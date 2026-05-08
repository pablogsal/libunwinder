//! Lazy-initialized process-global `unw_addr_space_t`.
//!
//! Binds our accessor table (function pointers) to libunwind. Carries no
//! per-tracee state - that lives in `UnwindCtx` reachable through the
//! cursor's `arg` pointer.
//!
//! libunwind documents `unw_init_remote` as MT-safe given a unique `arg`
//! per call, and the address space is read-only after construction.

use std::ffi::c_void;
use std::sync::OnceLock;

use crate::callbacks;
use crate::error::{LibunwindError, LibunwindPhase};
use crate::ffi::{self, UnwAccessors, UnwAddrSpace, UnwCursor, UnwWord, UNW_LITTLE_ENDIAN};
use std::os::raw::c_int;

static ADDR_SPACE: OnceLock<AddrSpaceHandle> = OnceLock::new();

struct AddrSpaceHandle(UnwAddrSpace);
// SAFETY: `unw_addr_space_t` is documented MT-safe for `init_remote`
// calls. Our accessors carry no shared state beyond the const-init
// function pointer table.
unsafe impl Send for AddrSpaceHandle {}
// SAFETY: see `Send` impl above; same justification applies.
unsafe impl Sync for AddrSpaceHandle {}

static ACCESSORS: UnwAccessors = UnwAccessors {
    find_proc_info: Some(callbacks::find_proc_info),
    put_unwind_info: Some(callbacks::put_unwind_info),
    get_dyn_info_list_addr: Some(callbacks::get_dyn_info_list_addr),
    access_mem: Some(callbacks::access_mem),
    access_reg: Some(callbacks::access_reg),
    access_fpreg: Some(callbacks::access_fpreg),
    resume: None,
    get_proc_name: None,
    get_elf_filename: None,
    get_proc_ip_range: None,
    ptrauth_insn_mask: None,
};

fn get() -> UnwAddrSpace {
    ADDR_SPACE
        .get_or_init(|| {
            // SAFETY: `&ACCESSORS` is `'static`. The byteorder arg is a
            // plain int.
            let raw = unsafe { ffi::unw_create_addr_space(&ACCESSORS, UNW_LITTLE_ENDIAN) };
            if raw.is_null() {
                panic!("unw_create_addr_space returned null");
            }
            AddrSpaceHandle(raw)
        })
        .0
}

/// Initialize a remote cursor and step it once. Returns the new register
/// state on success, `Ok(None)` at end of stack, or `Err(libunwind_code)`
/// for any libunwind error.
///
/// libunwind stores the post-step register state in the cursor's internal
/// fields, NOT by writing back through `access_reg`. We must read the new
/// IP/SP via `unw_get_reg` after `unw_step` returns - otherwise the
/// caller's register copy stays stale, the next unwind step sees the old
/// SP, and we infinite-loop on garbage.
///
/// `arg` is the user-data pointer (typically `&mut UnwindCtx`). The
/// caller owns its storage and keeps it alive across this call.
pub(crate) fn init_and_step(
    arg: *mut c_void,
    extra_regs: &[c_int],
) -> Result<StepOutcome, LibunwindError> {
    let addr_space = get();
    let mut cursor = UnwCursor::zeroed();
    // SAFETY: cursor is zeroed; libunwind populates it. `arg` is valid
    // for the duration of this function.
    let init_ret = unsafe { ffi::unw_init_remote(&mut cursor, addr_space, arg) };
    if init_ret < 0 {
        return Err(LibunwindError::new(LibunwindPhase::InitRemote, init_ret));
    }
    // SAFETY: cursor was initialized successfully above.
    let step_ret = unsafe { ffi::unw_step(&mut cursor) };
    if step_ret < 0 {
        return Err(LibunwindError::new(LibunwindPhase::Step, step_ret));
    }
    if step_ret == 0 {
        return Ok(StepOutcome::EndOfStack);
    }

    let mut new_ip: UnwWord = 0;
    // SAFETY: `&mut new_ip` is a valid out-pointer.
    let ret = unsafe { ffi::unw_get_reg(&mut cursor, ffi::reg_ip(), &mut new_ip as *mut UnwWord) };
    if ret < 0 {
        return Err(LibunwindError::new(
            LibunwindPhase::GetInstructionPointer,
            ret,
        ));
    }

    let mut extras = [0u64; 4];
    for (index, &reg) in extra_regs.iter().take(extra_regs.len().min(4)).enumerate() {
        let mut val: UnwWord = 0;
        // SAFETY: `&mut val` is a valid out-pointer.
        let ret = unsafe { ffi::unw_get_reg(&mut cursor, reg, &mut val as *mut UnwWord) };
        if ret < 0 {
            if index == 0 {
                return Err(LibunwindError::new(
                    LibunwindPhase::GetRegister { reg },
                    ret,
                ));
            }
            // Non-SP extras (BP/LR) may legitimately be unavailable in the
            // recovered state; treat as 0 rather than failing the step.
        } else {
            extras[index] = val;
        }
    }
    Ok(StepOutcome::Stepped { new_ip, extras })
}

pub(crate) enum StepOutcome {
    Stepped { new_ip: UnwWord, extras: [u64; 4] },
    EndOfStack,
}
