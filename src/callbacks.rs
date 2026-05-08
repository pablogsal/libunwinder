//! `extern "C"` callbacks libunwind invokes through the address space's
//! accessor table. All callbacks recover the per-call `UnwindCtx` from the
//! `arg: *mut c_void` parameter.

use std::ffi::c_void;
use std::os::raw::c_int;
use std::sync::Arc;

use crate::dwarf;
use crate::error::{DwarfParseError, UnwindInfoError};
use crate::ffi::{
    DwarfCieInfo, UnwAddrSpace, UnwProcInfo, UnwWord, UNW_EBADREG, UNW_EINVAL, UNW_ENOINFO,
    UNW_ESUCCESS, UNW_INFO_FORMAT_REMOTE_TABLE,
};
use crate::module::{FunctionDetails, ModuleData};
use crate::unwind_ctx::UnwindCtx;

/// `find_proc_info`: tell libunwind what unwind info covers `ip`.
///
/// **The hot-path optimization (ported from atl's `RemoteBacktracer`):**
/// instead of asking libunwind to find + parse the FDE/CIE on every step
/// (~30+ access_mem calls per step), we do that work *once* per function
/// in our own DWARF parser and cache the result. Subsequent lookups are
/// O(log n) BTreeMap hits returning a pre-built `dwarf_cie_info_t`.
///
/// We hand back `pi.format = UNW_INFO_FORMAT_REMOTE_TABLE` and
/// `pi.unwind_info = &cached_dwarf_cie_info_t`. libunwind treats that
/// pointer as a parsed CIE and skips its own parser; it goes straight
/// to evaluating CFI rules.
pub(crate) unsafe extern "C" fn find_proc_info(
    _as: UnwAddrSpace,
    _ip: UnwWord,
    pi: *mut UnwProcInfo,
    _need_unwind_info: c_int,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: libunwind invokes this callback with `arg` set to the
    // `as_arg()` value we passed to `unw_init_remote`, and `pi` pointing
    // at a writable `UnwProcInfo` it owns for the call duration.
    unsafe {
        let ctx = UnwindCtx::from_arg(arg);
        let lookup_ip = ctx.lookup_ip;
        let module = match ctx.modules.find_module(lookup_ip) {
            Some(m) => m,
            None => {
                ctx.unwind_info_error = Some(UnwindInfoError::ModuleNotFound { ip: lookup_ip });
                return -UNW_ENOINFO;
            }
        };

        let details = match get_or_parse_function_details(module, lookup_ip) {
            Ok(d) => d,
            Err(err) => {
                ctx.unwind_info_error = Some(err);
                return -UNW_ENOINFO;
            }
        };

        // Populate pi to point at our cached DwarfCieInfo. Note: libunwind
        // treats `unwind_info` as a `dwarf_cie_info_t*` when format is
        // TABLE/REMOTE_TABLE, regardless of which variant. The C++ comment
        // in RemoteBacktracer.cc explains: "TABLE and REMOTE_TABLE are
        // treated identically -- except dwarf_cie_info."
        let info = &mut *pi;
        info.start_ip = details.start_ip;
        info.end_ip = details.end_ip;
        info.lsda = details.lsda;
        info.handler = details.handler;
        info.gp = 0;
        info.flags = 0;
        info.format = UNW_INFO_FORMAT_REMOTE_TABLE;
        info.unwind_info_size = std::mem::size_of::<DwarfCieInfo>() as c_int;
        // The Arc holding `details` is alive in the module's function_cache
        // for the entire lifetime of the module, so this pointer is valid
        // for as long as the cursor that consumes it.
        info.unwind_info = (&details.cie_info as *const DwarfCieInfo) as *mut c_void;
        UNW_ESUCCESS
    }
}

/// Look up or parse-and-cache the `FunctionDetails` for a tracee IP.
unsafe fn get_or_parse_function_details(
    module: &Arc<ModuleData>,
    ip: u64,
) -> Result<Arc<FunctionDetails>, UnwindInfoError> {
    {
        let cache =
            module
                .function_cache
                .lock()
                .map_err(|_| UnwindInfoError::FunctionCachePoisoned {
                    module: module.name.clone(),
                })?;
        if let Some((_, details)) = cache.range(..=ip).next_back() {
            if ip < details.end_ip {
                return Ok(Arc::clone(details));
            }
        }
    }
    // Cache miss: locate the FDE via .eh_frame_hdr binary search, parse
    // it, parse the CIE it points at, and cache the result.
    // SAFETY: caller upholds `parse_function_details` preconditions
    // (module's eh_frame{,_hdr} pointers reference live, readable bytes).
    let details = unsafe { parse_function_details(module, ip) }?;
    let mut cache =
        module
            .function_cache
            .lock()
            .map_err(|_| UnwindInfoError::FunctionCachePoisoned {
                module: module.name.clone(),
            })?;
    cache.insert(details.start_ip, Arc::clone(&details));
    Ok(details)
}

unsafe fn parse_function_details(
    module: &Arc<ModuleData>,
    ip: u64,
) -> Result<Arc<FunctionDetails>, UnwindInfoError> {
    let module_name = || module.name.clone();
    if module.eh_frame_local_ptr.is_null() || module.eh_frame_hdr_local_ptr.is_null() {
        return Err(UnwindInfoError::MissingLocalUnwindSections {
            module: module_name(),
            ip,
        });
    }
    // SAFETY: caller upholds that `eh_frame_hdr_local_ptr` references
    // `eh_frame_hdr_local_len` readable bytes for the module's lifetime.
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(module.eh_frame_hdr_local_ptr, module.eh_frame_hdr_local_len)
    };
    let (_initial_pc, fde_avma) = module.table.lookup(hdr_bytes, ip).ok_or_else(|| {
        UnwindInfoError::EhFrameHeaderLookupMiss {
            module: module_name(),
            ip,
        }
    })?;

    // SAFETY: caller upholds that `eh_frame_local_ptr` references
    // `eh_frame_local_len` readable bytes for the module's lifetime.
    let eh_frame_bytes =
        unsafe { std::slice::from_raw_parts(module.eh_frame_local_ptr, module.eh_frame_local_len) };
    let fde_offset = fde_avma.checked_sub(module.eh_frame_avma).ok_or_else(|| {
        UnwindInfoError::FdeOffsetBeforeEhFrame {
            module: module_name(),
            fde_avma,
            eh_frame_avma: module.eh_frame_avma,
        }
    })? as usize;
    if fde_offset >= eh_frame_bytes.len() {
        return Err(UnwindInfoError::FdeOffsetOutOfRange {
            module: module_name(),
            fde_offset,
            eh_frame_len: eh_frame_bytes.len(),
        });
    }

    // First pass: read the FDE's CIE pointer and find the CIE.
    // We need fde_encoding/lsda_encoding/has_z from the CIE before we
    // can finish parsing the FDE, so parse the CIE first.
    let cie_offset = {
        // Length + cie_ptr offset = 4 + 4 = 8, except for 64-bit length.
        let len_prefix = eh_frame_bytes
            .get(fde_offset..fde_offset + 4)
            .ok_or_else(|| UnwindInfoError::FdeLengthPrefixTruncated {
                module: module_name(),
                fde_offset,
                eh_frame_len: eh_frame_bytes.len(),
            })?;
        let len32 = u32::from_le_bytes(len_prefix.try_into().unwrap());
        let (cie_ptr_pos, cie_ptr_len) = if len32 == 0xffff_ffff {
            (fde_offset + 12, 8)
        } else {
            (fde_offset + 4, 4)
        };
        let cie_ptr_bytes = eh_frame_bytes
            .get(cie_ptr_pos..cie_ptr_pos + cie_ptr_len)
            .ok_or_else(|| UnwindInfoError::CiePointerTruncated {
                module: module_name(),
                cie_ptr_offset: cie_ptr_pos,
                eh_frame_len: eh_frame_bytes.len(),
            })?;
        let cie_ptr = if cie_ptr_len == 8 {
            u64::from_le_bytes(cie_ptr_bytes.try_into().unwrap())
        } else {
            u32::from_le_bytes(cie_ptr_bytes.try_into().unwrap()) as u64
        };
        let cie_ptr =
            usize::try_from(cie_ptr).map_err(|_| UnwindInfoError::CiePointerUnderflow {
                module: module_name(),
                cie_ptr_offset: cie_ptr_pos,
                cie_ptr,
            })?;
        cie_ptr_pos
            .checked_sub(cie_ptr)
            .ok_or_else(|| UnwindInfoError::CiePointerUnderflow {
                module: module_name(),
                cie_ptr_offset: cie_ptr_pos,
                cie_ptr: cie_ptr as u64,
            })?
    };

    let cie = dwarf::parse_cie(eh_frame_bytes, cie_offset, module.eh_frame_avma).map_err(
        |source: DwarfParseError| UnwindInfoError::CieParse {
            module: module_name(),
            cie_offset,
            source,
        },
    )?;
    let fde = dwarf::parse_fde(
        eh_frame_bytes,
        fde_offset,
        module.eh_frame_avma,
        dwarf::FdeParseConfig {
            fde_encoding: cie.fde_encoding,
            lsda_encoding: cie.lsda_encoding,
            has_z: cie.has_z,
            text_base: module.text_base,
            data_base: module.data_base,
        },
    )
    .map_err(|source: DwarfParseError| UnwindInfoError::FdeParse {
        module: module_name(),
        fde_offset,
        source,
    })?;

    let Some(end_ip) = fde.initial_pc.checked_add(fde.address_range) else {
        return Err(UnwindInfoError::EhFrameHeaderLookupMiss {
            module: module_name(),
            ip,
        });
    };
    if ip < fde.initial_pc || ip >= end_ip {
        return Err(UnwindInfoError::EhFrameHeaderLookupMiss {
            module: module_name(),
            ip,
        });
    }

    let cie_info = dwarf::build_dwarf_cie_info(&cie, &fde, module.eh_frame_avma);
    let details = Arc::new(FunctionDetails {
        start_ip: fde.initial_pc,
        end_ip,
        cie_info,
        lsda: fde.lsda,
        handler: cie.personality,
        signal_frame: cie.signal_frame,
    });
    Ok(details)
}

/// `put_unwind_info`: free per-call storage. We allocate from the ctx's
/// arena and free it implicitly on `unwind_frame` return, so this is a
/// no-op.
pub(crate) unsafe extern "C" fn put_unwind_info(
    _as: UnwAddrSpace,
    _pi: *mut UnwProcInfo,
    _arg: *mut c_void,
) {
}

/// `get_dyn_info_list_addr`: we don't expose dynamically-registered unwind
/// tables. Returning `-UNW_ENOINFO` tells libunwind there are none.
pub(crate) unsafe extern "C" fn get_dyn_info_list_addr(
    _as: UnwAddrSpace,
    _val: *mut UnwWord,
    _arg: *mut c_void,
) -> c_int {
    -UNW_ENOINFO
}

/// `access_mem`: read or write 8 bytes at `addr` in the tracee's address
/// space. Writes are rejected.
///
/// Read fast path: if `addr` falls inside any registered `.eh_frame` /
/// `.eh_frame_hdr` mirror, we copy from the local mmap and return. This
/// captures the dominant cost of remote unwinding (DWARF instruction
/// reads + binary search table reads).
///
/// Slow path: call the user's `read_fn`. If it errors, record the
/// address so the caller can build `Error::CouldNotReadStack(addr)`.
pub(crate) unsafe extern "C" fn access_mem(
    _as: UnwAddrSpace,
    addr: UnwWord,
    val: *mut UnwWord,
    write: c_int,
    arg: *mut c_void,
) -> c_int {
    if write != 0 {
        return -UNW_EINVAL;
    }
    // SAFETY: libunwind invokes this callback with our `as_arg()` value
    // and a writable `*mut UnwWord`; `lookup_local` only returns pointers
    // into mappings the user pinned to the module set.
    unsafe {
        let ctx = UnwindCtx::from_arg(arg);
        if let Some(local_ptr) = ctx.modules.lookup_local(addr) {
            let bytes = std::slice::from_raw_parts(local_ptr, 8);
            let mut word = [0u8; 8];
            word.copy_from_slice(bytes);
            let v = u64::from_le_bytes(word);
            *val = v;
            return UNW_ESUCCESS;
        }
        match (ctx.read_fn)(addr) {
            Ok(v) => {
                *val = v;
                UNW_ESUCCESS
            }
            Err(()) => {
                ctx.last_failed_read_addr = Some(addr);
                -UNW_EINVAL
            }
        }
    }
}

/// `access_reg`: read or write an integer register. We only carry the
/// minimum profiler snapshots usually supply (RIP/RSP/RBP on x86_64;
/// PC/SP/FP/LR on aarch64). Other regs return `-UNW_EBADREG`.
pub(crate) unsafe extern "C" fn access_reg(
    _as: UnwAddrSpace,
    reg: c_int,
    val: *mut UnwWord,
    write: c_int,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: libunwind invokes this callback with our `as_arg()` value
    // and a writable `*mut UnwWord`. `regs_ptr` was set by the per-arch
    // `unwind_frame` to a pointer of the matching `RawRegs` type.
    unsafe {
        let ctx = UnwindCtx::from_arg(arg);
        arch::access_reg(ctx.regs_ptr, reg, val, write)
    }
}

/// `access_fpreg`: floating-point regs. We don't support them.
pub(crate) unsafe extern "C" fn access_fpreg(
    _as: UnwAddrSpace,
    _reg: c_int,
    _val: *mut [u64; 2],
    _write: c_int,
    _arg: *mut c_void,
) -> c_int {
    -UNW_EBADREG
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::{DwarfModuleSections, Module};

    fn one_fde_module() -> Module<Vec<u8>> {
        let initial_pc = 0x1000u64;
        let address_range = 0x10u64;
        let eh_frame_avma = 0x3000u64;
        let eh_frame_hdr_avma = 0x4000u64;

        let mut eh_frame = Vec::new();
        eh_frame.extend_from_slice(&9u32.to_le_bytes()); // CIE length.
        eh_frame.extend_from_slice(&0u32.to_le_bytes()); // CIE id.
        eh_frame.push(1); // version.
        eh_frame.push(0); // empty augmentation string.
        eh_frame.push(1); // code alignment.
        eh_frame.push(0x78); // data alignment = -8.
        eh_frame.push(16); // return-address column.

        let fde_offset = eh_frame.len() as u64;
        let cie_ptr_pos = fde_offset + 4;
        eh_frame.extend_from_slice(&20u32.to_le_bytes()); // FDE length.
        eh_frame.extend_from_slice(&(cie_ptr_pos as u32).to_le_bytes());
        eh_frame.extend_from_slice(&initial_pc.to_le_bytes());
        eh_frame.extend_from_slice(&address_range.to_le_bytes());

        let mut eh_frame_hdr = vec![1, 0x03, 0x03, 0x3b];
        eh_frame_hdr.extend_from_slice(&(eh_frame_avma as u32).to_le_bytes());
        eh_frame_hdr.extend_from_slice(&1u32.to_le_bytes());
        eh_frame_hdr.extend_from_slice(
            &((initial_pc as i64 - eh_frame_hdr_avma as i64) as i32).to_le_bytes(),
        );
        eh_frame_hdr.extend_from_slice(
            &(((eh_frame_avma + fde_offset) as i64 - eh_frame_hdr_avma as i64) as i32)
                .to_le_bytes(),
        );

        let eh_frame_len = eh_frame.len() as u64;
        let eh_frame_hdr_len = eh_frame_hdr.len() as u64;
        Module::from_dwarf_sections(
            "one-fde".to_string(),
            0x1000..0x2000,
            0,
            DwarfModuleSections {
                base_svma: 0,
                text_svma: Some(0x1000..0x2000),
                text: None,
                eh_frame_svma: Some(eh_frame_avma..eh_frame_avma + eh_frame_len),
                eh_frame: Some(eh_frame),
                eh_frame_hdr_svma: Some(eh_frame_hdr_avma..eh_frame_hdr_avma + eh_frame_hdr_len),
                eh_frame_hdr: Some(eh_frame_hdr),
            },
        )
        .expect("valid DWARF sections")
    }

    fn one_dwarf64_fde_module() -> Module<Vec<u8>> {
        let initial_pc = 0x1100u64;
        let address_range = 0x20u64;
        let eh_frame_avma = 0x3000u64;
        let eh_frame_hdr_avma = 0x4000u64;

        let mut eh_frame = Vec::new();
        eh_frame.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        eh_frame.extend_from_slice(&13u64.to_le_bytes()); // CIE length.
        eh_frame.extend_from_slice(&0u64.to_le_bytes()); // 8-byte CIE id.
        eh_frame.push(1); // version.
        eh_frame.push(0); // empty augmentation string.
        eh_frame.push(1); // code alignment.
        eh_frame.push(0x78); // data alignment = -8.
        eh_frame.push(16); // return-address column.

        let fde_offset = eh_frame.len() as u64;
        let cie_ptr_pos = fde_offset + 12;
        eh_frame.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        eh_frame.extend_from_slice(&24u64.to_le_bytes()); // FDE length.
        eh_frame.extend_from_slice(&cie_ptr_pos.to_le_bytes());
        eh_frame.extend_from_slice(&initial_pc.to_le_bytes());
        eh_frame.extend_from_slice(&address_range.to_le_bytes());

        let mut eh_frame_hdr = vec![1, 0x03, 0x03, 0x3b];
        eh_frame_hdr.extend_from_slice(&(eh_frame_avma as u32).to_le_bytes());
        eh_frame_hdr.extend_from_slice(&1u32.to_le_bytes());
        eh_frame_hdr.extend_from_slice(
            &((initial_pc as i64 - eh_frame_hdr_avma as i64) as i32).to_le_bytes(),
        );
        eh_frame_hdr.extend_from_slice(
            &(((eh_frame_avma + fde_offset) as i64 - eh_frame_hdr_avma as i64) as i32)
                .to_le_bytes(),
        );

        let eh_frame_len = eh_frame.len() as u64;
        let eh_frame_hdr_len = eh_frame_hdr.len() as u64;
        Module::from_dwarf_sections(
            "one-dwarf64-fde".to_string(),
            0x1000..0x2000,
            0,
            DwarfModuleSections {
                base_svma: 0,
                text_svma: Some(0x1000..0x2000),
                text: None,
                eh_frame_svma: Some(eh_frame_avma..eh_frame_avma + eh_frame_len),
                eh_frame: Some(eh_frame),
                eh_frame_hdr_svma: Some(eh_frame_hdr_avma..eh_frame_hdr_avma + eh_frame_hdr_len),
                eh_frame_hdr: Some(eh_frame_hdr),
            },
        )
        .expect("valid DWARF64 sections")
    }

    #[test]
    fn accepts_ip_inside_parsed_fde_range() {
        let module = one_fde_module();

        // SAFETY: the test fixture's module owns its eh_frame{,_hdr} bytes
        // and outlives the call.
        let details =
            unsafe { parse_function_details(&module.data, 0x100f) }.expect("IP should be covered");

        assert_eq!(details.start_ip, 0x1000);
        assert_eq!(details.end_ip, 0x1010);
    }

    #[test]
    fn rejects_header_lookup_hit_outside_parsed_fde_range() {
        let module = one_fde_module();

        // SAFETY: same as above — fixture-owned section bytes outlive the call.
        let err = match unsafe { parse_function_details(&module.data, 0x1010) } {
            Ok(_) => panic!("IP at the FDE end must not be covered"),
            Err(err) => err,
        };

        assert_eq!(
            err,
            UnwindInfoError::EhFrameHeaderLookupMiss {
                module: "one-fde".to_string(),
                ip: 0x1010,
            }
        );
    }

    #[test]
    fn accepts_dwarf64_fde_cie_pointer() {
        let module = one_dwarf64_fde_module();

        // SAFETY: same as above — fixture-owned section bytes outlive the call.
        let details =
            unsafe { parse_function_details(&module.data, 0x111f) }.expect("IP should be covered");

        assert_eq!(details.start_ip, 0x1100);
        assert_eq!(details.end_ip, 0x1120);
    }
}

#[cfg(target_arch = "x86_64")]
mod arch {
    use std::os::raw::c_int;

    use crate::ffi::UnwWord;
    use crate::x86_64::RawRegsX86_64;

    pub(super) unsafe fn access_reg(
        regs_ptr: *mut (),
        reg: c_int,
        val: *mut UnwWord,
        write: c_int,
    ) -> c_int {
        // SAFETY: caller (the FFI access_reg dispatch) upholds that
        // `regs_ptr` is a valid `*mut RawRegsX86_64` for the cursor's
        // lifetime, and `val` is a writable `*mut UnwWord`.
        unsafe {
            let regs = &mut *(regs_ptr as *mut RawRegsX86_64);
            regs.access_reg(reg, val, write)
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use std::os::raw::c_int;

    use crate::aarch64::RawRegsAarch64;
    use crate::ffi::consts::aarch64_regs::{
        UNW_AARCH64_PC, UNW_AARCH64_SP, UNW_AARCH64_X29, UNW_AARCH64_X30,
    };
    use crate::ffi::{UnwWord, UNW_EBADREG, UNW_ESUCCESS};

    pub(super) unsafe fn access_reg(
        regs_ptr: *mut (),
        reg: c_int,
        val: *mut UnwWord,
        write: c_int,
    ) -> c_int {
        // SAFETY: caller (the FFI access_reg dispatch) upholds that
        // `regs_ptr` is a valid `*mut RawRegsAarch64` for the cursor's
        // lifetime, and `val` is a writable `*mut UnwWord`.
        unsafe {
            let regs = &mut *(regs_ptr as *mut RawRegsAarch64);
            let slot = match reg {
                UNW_AARCH64_PC => &mut regs.pc,
                UNW_AARCH64_SP => &mut regs.sp,
                UNW_AARCH64_X29 => &mut regs.fp,
                UNW_AARCH64_X30 => &mut regs.lr,
                _ => return -UNW_EBADREG,
            };
            if write != 0 {
                *slot = *val;
            } else {
                *val = *slot;
            }
            UNW_ESUCCESS
        }
    }
}
