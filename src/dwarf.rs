//! Hand-rolled DWARF byte parser for `.eh_frame` CIE/FDE entries.
//!
//! Goal: parse a CIE+FDE pair into a `dwarf_cie_info_t` we can hand back
//! to libunwind via `unw_proc_info_t::unwind_info`, so libunwind skips
//! its own per-step CIE parser. This is the dominant performance win in
//! the C++ `RemoteBacktracer`.
//!
//! Scope: covers the CIE/FDE shapes glibc and the GNU toolchain emit on
//! Linux x86_64 + aarch64. Specifically:
//!   - Augmentation strings starting with `z` (sized) plus `R`/`P`/`L`/`S`
//!   - `DW_EH_PE_*` encodings: omit, absptr, udata2/4/8, sdata2/4/8,
//!     uleb128, sleb128, with `pcrel`/`datarel`/`textrel`/`funcrel` modifiers
//!   - Both 32-bit length and 64-bit extended length (`0xffffffff` prefix)
//!
//! Anything unusual (e.g. ARM-EHABI, signature-typed CIEs) returns a precise
//! parser error so callers can classify the unwind-info failure.

use crate::error::{DwarfParseError, DwarfParseErrorKind};
use crate::ffi::DwarfCieInfo;

type DwarfError = DwarfParseError;

// DW_EH_PE_* encoding constants (LSB chapter "Pointer Encodings").
pub(crate) const DW_EH_PE_OMIT: u8 = 0xff;
pub(crate) const DW_EH_PE_ABSPTR: u8 = 0x00;
pub(crate) const DW_EH_PE_FORMAT_MASK: u8 = 0x0f;
pub(crate) const DW_EH_PE_APP_MASK: u8 = 0x70;
pub(crate) const DW_EH_PE_INDIRECT: u8 = 0x80;

pub(crate) const DW_EH_PE_UDATA2: u8 = 0x02;
pub(crate) const DW_EH_PE_UDATA4: u8 = 0x03;
pub(crate) const DW_EH_PE_UDATA8: u8 = 0x04;
pub(crate) const DW_EH_PE_SDATA2: u8 = 0x0a;
pub(crate) const DW_EH_PE_SDATA4: u8 = 0x0b;
pub(crate) const DW_EH_PE_SDATA8: u8 = 0x0c;
pub(crate) const DW_EH_PE_ULEB128: u8 = 0x01;
pub(crate) const DW_EH_PE_SLEB128: u8 = 0x09;

pub(crate) const DW_EH_PE_PCREL: u8 = 0x10;
pub(crate) const DW_EH_PE_TEXTREL: u8 = 0x20;
pub(crate) const DW_EH_PE_DATAREL: u8 = 0x30;
pub(crate) const DW_EH_PE_FUNCREL: u8 = 0x40;
pub(crate) const DW_EH_PE_ALIGNED: u8 = 0x50;

/// Cursor into the local mmap of `.eh_frame`. Tracks the *local* read
/// pointer (within our mmap'd byte slice) and the corresponding *avma*
/// in the tracee, so callers can compute pcrel-relative addresses
/// against the right base.
pub(crate) struct Cursor<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
    /// Tracee virtual address of `bytes[0]`.
    pub avma_base: u64,
}

impl<'a> Cursor<'a> {
    pub fn current_avma(&self) -> u64 {
        self.avma_base.wrapping_add(self.pos as u64)
    }

    pub fn read_u8(&mut self) -> Result<u8, DwarfError> {
        let v = *self.bytes.get(self.pos).ok_or_else(|| {
            DwarfError::new(
                self.pos,
                DwarfParseErrorKind::Truncated {
                    needed: self.pos + 1,
                    len: self.bytes.len(),
                },
            )
        })?;
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> Result<u16, DwarfError> {
        let end = self.pos + 2;
        let slice = self.bytes.get(self.pos..end).ok_or_else(|| {
            DwarfError::new(
                self.pos,
                DwarfParseErrorKind::Truncated {
                    needed: end,
                    len: self.bytes.len(),
                },
            )
        })?;
        let v = u16::from_le_bytes(slice.try_into().unwrap());
        self.pos = end;
        Ok(v)
    }

    pub fn read_u32(&mut self) -> Result<u32, DwarfError> {
        let end = self.pos + 4;
        let slice = self.bytes.get(self.pos..end).ok_or_else(|| {
            DwarfError::new(
                self.pos,
                DwarfParseErrorKind::Truncated {
                    needed: end,
                    len: self.bytes.len(),
                },
            )
        })?;
        let v = u32::from_le_bytes(slice.try_into().unwrap());
        self.pos = end;
        Ok(v)
    }

    pub fn read_u64(&mut self) -> Result<u64, DwarfError> {
        let end = self.pos + 8;
        let slice = self.bytes.get(self.pos..end).ok_or_else(|| {
            DwarfError::new(
                self.pos,
                DwarfParseErrorKind::Truncated {
                    needed: end,
                    len: self.bytes.len(),
                },
            )
        })?;
        let v = u64::from_le_bytes(slice.try_into().unwrap());
        self.pos = end;
        Ok(v)
    }

    pub fn read_uleb128(&mut self) -> Result<u64, DwarfError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err(DwarfError::new(
                    self.pos,
                    DwarfParseErrorKind::Leb128Overflow,
                ));
            }
        }
    }

    pub fn read_sleb128(&mut self) -> Result<i64, DwarfError> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7f) as i64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && (byte & 0x40) != 0 {
                    result |= -1i64 << shift;
                }
                return Ok(result);
            }
            if shift >= 64 {
                return Err(DwarfError::new(
                    self.pos,
                    DwarfParseErrorKind::Leb128Overflow,
                ));
            }
        }
    }

    /// Read an encoded value per `DW_EH_PE_*` rules. Returns the
    /// resolved (post-application) target address. `func_base` is used
    /// for `DW_EH_PE_funcrel`, `data_base` for `DW_EH_PE_datarel`,
    /// `text_base` for `DW_EH_PE_textrel`.
    pub fn read_encoded(
        &mut self,
        enc: u8,
        text_base: u64,
        data_base: u64,
        func_base: u64,
    ) -> Result<u64, DwarfError> {
        self.read_encoded_impl(enc, text_base, data_base, func_base, false)
    }

    /// Read a CIE personality pointer. Indirect personality encodings are
    /// accepted by consuming the encoded pointer bytes without dereferencing
    /// tracee memory; libunwinder does not need the personality routine for CFI
    /// stack walking.
    pub fn read_encoded_personality(
        &mut self,
        enc: u8,
        text_base: u64,
        data_base: u64,
        func_base: u64,
    ) -> Result<u64, DwarfError> {
        self.read_encoded_impl(enc, text_base, data_base, func_base, true)
    }

    fn read_encoded_impl(
        &mut self,
        enc: u8,
        text_base: u64,
        data_base: u64,
        func_base: u64,
        allow_indirect_without_deref: bool,
    ) -> Result<u64, DwarfError> {
        if enc == DW_EH_PE_OMIT {
            return Err(DwarfError::new(
                self.pos,
                DwarfParseErrorKind::OmittedPointerEncoding,
            ));
        }
        let is_indirect = enc & DW_EH_PE_INDIRECT != 0;
        if is_indirect && !allow_indirect_without_deref {
            return Err(DwarfError::new(
                self.pos,
                DwarfParseErrorKind::IndirectPointerRequiresDereference { encoding: enc },
            ));
        }
        let direct_enc = enc & !DW_EH_PE_INDIRECT;

        // Capture the avma of the byte we're about to read for pcrel.
        let pcrel_base = self.current_avma();
        let raw = match direct_enc & DW_EH_PE_FORMAT_MASK {
            DW_EH_PE_ABSPTR => self.read_u64()?,
            DW_EH_PE_UDATA2 => self.read_u16()? as u64,
            DW_EH_PE_UDATA4 => self.read_u32()? as u64,
            DW_EH_PE_UDATA8 => self.read_u64()?,
            DW_EH_PE_SDATA2 => self.read_u16()? as i16 as i64 as u64,
            DW_EH_PE_SDATA4 => self.read_u32()? as i32 as i64 as u64,
            DW_EH_PE_SDATA8 => self.read_u64()? as i64 as u64,
            DW_EH_PE_ULEB128 => self.read_uleb128()?,
            DW_EH_PE_SLEB128 => self.read_sleb128()? as u64,
            _ => {
                return Err(DwarfError::new(
                    self.pos,
                    DwarfParseErrorKind::UnsupportedPointerEncoding { encoding: enc },
                ));
            }
        };

        if is_indirect {
            return Ok(0);
        }

        // Zero raw means "absent" (the encoded value is literally 0;
        // applying a base would give the wrong answer).
        if raw == 0 {
            return Ok(0);
        }

        let resolved = match direct_enc & DW_EH_PE_APP_MASK {
            0 => raw,
            DW_EH_PE_PCREL => raw.wrapping_add(pcrel_base),
            DW_EH_PE_TEXTREL => raw.wrapping_add(text_base),
            DW_EH_PE_DATAREL => raw.wrapping_add(data_base),
            DW_EH_PE_FUNCREL => raw.wrapping_add(func_base),
            DW_EH_PE_ALIGNED => {
                return Err(DwarfError::new(
                    self.pos,
                    DwarfParseErrorKind::UnsupportedPointerApplication { encoding: enc },
                ));
            }
            _ => {
                return Err(DwarfError::new(
                    self.pos,
                    DwarfParseErrorKind::UnsupportedPointerApplication { encoding: enc },
                ));
            }
        };
        Ok(resolved)
    }
}

/// Result of parsing a CIE. Filled into a `DwarfCieInfo` once the FDE
/// instruction range is known.
pub(crate) struct ParsedCie {
    pub code_align: u64,
    pub data_align: i64,
    pub ret_addr_column: u64,
    pub fde_encoding: u8,
    pub lsda_encoding: u8,
    pub personality: u64,
    pub has_z: bool,
    pub signal_frame: bool,
    /// Offset within `.eh_frame` of the first CIE initial-instruction byte.
    pub cie_instr_offset_in_eh_frame: usize,
    /// Length of CIE initial-instructions in bytes.
    pub cie_instr_len: usize,
}

/// Parse a CIE starting at `eh_frame_bytes[cie_offset]`. Returns the
/// parsed metadata; the caller combines it with the FDE to build the
/// final `DwarfCieInfo`.
pub(crate) fn parse_cie(
    eh_frame_bytes: &[u8],
    cie_offset: usize,
    eh_frame_avma_base: u64,
) -> Result<ParsedCie, DwarfError> {
    let mut c = Cursor {
        bytes: eh_frame_bytes,
        pos: cie_offset,
        avma_base: eh_frame_avma_base,
    };

    // Length (32-bit, with optional 64-bit extension).
    let len32 = c.read_u32()?;
    let is_dwarf64 = len32 == 0xffff_ffff;
    let entry_len = if is_dwarf64 {
        usize::try_from(c.read_u64()?)
            .map_err(|_| DwarfError::new(c.pos, DwarfParseErrorKind::EntryLengthOverflow))?
    } else {
        len32 as usize
    };
    let entry_end = c
        .pos
        .checked_add(entry_len)
        .ok_or_else(|| DwarfError::new(c.pos, DwarfParseErrorKind::EntryLengthOverflow))?;

    // CIE id must be 0.
    let cie_id_pos = c.pos;
    let cie_id = if is_dwarf64 {
        c.read_u64()?
    } else {
        c.read_u32()? as u64
    };
    if cie_id != 0 {
        return Err(DwarfError::new(
            cie_id_pos,
            DwarfParseErrorKind::BadCieId { cie_id },
        ));
    }

    let version = c.read_u8()?;
    if version != 1 && version != 3 && version != 4 {
        return Err(DwarfError::new(
            c.pos.saturating_sub(1),
            DwarfParseErrorKind::UnsupportedCieVersion { version },
        ));
    }

    // Augmentation string (NUL-terminated).
    let aug_start = c.pos;
    let aug_end = aug_start
        + c.bytes[aug_start..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| {
                DwarfError::new(
                    aug_start,
                    DwarfParseErrorKind::UnterminatedAugmentationString,
                )
            })?;
    let aug = &c.bytes[aug_start..aug_end];
    c.pos = aug_end + 1;

    if version == 4 {
        // address_size, segment_size - must be 8 / 0 on x86_64.
        let address_size = c.read_u8()?;
        let segment_size = c.read_u8()?;
        if address_size != 8 || segment_size != 0 {
            return Err(DwarfError::new(
                c.pos.saturating_sub(2),
                DwarfParseErrorKind::UnsupportedCieAddressSize {
                    address_size,
                    segment_size,
                },
            ));
        }
    }

    let code_align = c.read_uleb128()?;
    let data_align = c.read_sleb128()?;
    let ret_addr_column = if version == 1 {
        c.read_u8()? as u64
    } else {
        c.read_uleb128()?
    };

    // Augmentation parsing.
    let mut has_z = false;
    let mut fde_encoding: u8 = DW_EH_PE_ABSPTR;
    let mut lsda_encoding: u8 = DW_EH_PE_OMIT;
    let mut personality: u64 = 0;
    let mut signal_frame = false;

    if !aug.is_empty() && aug[0] == b'z' {
        has_z = true;
        let _aug_data_len = c.read_uleb128()?;
        for &ch in &aug[1..] {
            match ch {
                b'R' => fde_encoding = c.read_u8()?,
                b'L' => lsda_encoding = c.read_u8()?,
                b'P' => {
                    let personality_encoding = c.read_u8()?;
                    personality = c.read_encoded_personality(personality_encoding, 0, 0, 0)?;
                }
                b'S' => signal_frame = true,
                b'B' | b'G' => {
                    // GNU extensions we ignore (B = SPARC, G = sigaltstack)
                }
                _ => {
                    return Err(DwarfError::new(
                        c.pos,
                        DwarfParseErrorKind::UnsupportedAugmentation { byte: ch },
                    ));
                }
            }
        }
    } else if aug.is_empty() {
        // Bare CIE, no augmentation. fde_encoding defaults to absptr.
    } else {
        return Err(DwarfError::new(
            aug_start,
            DwarfParseErrorKind::UnsupportedNonZAugmentation,
        ));
    }

    let cie_instr_offset_in_eh_frame = c.pos;
    if entry_end > eh_frame_bytes.len() {
        return Err(DwarfError::new(
            c.pos,
            DwarfParseErrorKind::Truncated {
                needed: entry_end,
                len: eh_frame_bytes.len(),
            },
        ));
    }
    let cie_instr_len = entry_end - cie_instr_offset_in_eh_frame;

    Ok(ParsedCie {
        code_align,
        data_align,
        ret_addr_column,
        fde_encoding,
        lsda_encoding,
        personality,
        has_z,
        signal_frame,
        cie_instr_offset_in_eh_frame,
        cie_instr_len,
    })
}

/// Result of parsing an FDE.
pub(crate) struct ParsedFde {
    /// Function start address (tracee avma).
    pub initial_pc: u64,
    /// Function size in bytes.
    pub address_range: u64,
    /// Offset within `.eh_frame` of the first FDE-instruction byte.
    pub fde_instr_offset_in_eh_frame: usize,
    /// Length of FDE instructions in bytes.
    pub fde_instr_len: usize,
    /// LSDA address (tracee avma) if encoded.
    pub lsda: u64,
}

pub(crate) struct FdeParseConfig {
    pub fde_encoding: u8,
    pub lsda_encoding: u8,
    pub has_z: bool,
    pub text_base: u64,
    pub data_base: u64,
}

/// Parse an FDE starting at `eh_frame_bytes[fde_offset]`. Requires the
/// CIE's `fde_encoding` and `lsda_encoding` (which we get via
/// `parse_cie`).
pub(crate) fn parse_fde(
    eh_frame_bytes: &[u8],
    fde_offset: usize,
    eh_frame_avma_base: u64,
    config: FdeParseConfig,
) -> Result<ParsedFde, DwarfError> {
    let mut c = Cursor {
        bytes: eh_frame_bytes,
        pos: fde_offset,
        avma_base: eh_frame_avma_base,
    };

    // Length (32-bit, with optional 64-bit extension).
    let len32 = c.read_u32()?;
    let is_dwarf64 = len32 == 0xffff_ffff;
    let entry_len = if is_dwarf64 {
        usize::try_from(c.read_u64()?)
            .map_err(|_| DwarfError::new(c.pos, DwarfParseErrorKind::EntryLengthOverflow))?
    } else {
        len32 as usize
    };
    let entry_end = c
        .pos
        .checked_add(entry_len)
        .ok_or_else(|| DwarfError::new(c.pos, DwarfParseErrorKind::EntryLengthOverflow))?;

    // CIE pointer: positive offset back from THIS field's position.
    // Validated as non-zero (zero means "this is a CIE, not an FDE")
    // and points back into the `.eh_frame` bytes; the caller computed
    // `cie_offset` from the same field before calling us.
    let cie_ptr_pos = c.pos;
    let cie_ptr = if is_dwarf64 {
        c.read_u64()?
    } else {
        c.read_u32()? as u64
    };
    if cie_ptr == 0 {
        return Err(DwarfError::new(
            cie_ptr_pos,
            DwarfParseErrorKind::FdeCiePointerIsZero,
        ));
    }

    // initial_pc: encoded per CIE's fde_encoding.
    let initial_pc = c.read_encoded(config.fde_encoding, config.text_base, config.data_base, 0)?;

    // address_range: encoded per fde_encoding's format (no application).
    let range_enc = config.fde_encoding & DW_EH_PE_FORMAT_MASK;
    let address_range = c.read_encoded(range_enc, 0, 0, 0)?;

    // LSDA: only present if 'z' (sized augmentation) - we read aug_data_len then aug data.
    let mut lsda = 0u64;
    if config.has_z {
        let aug_data_len = usize::try_from(c.read_uleb128()?)
            .map_err(|_| DwarfError::new(c.pos, DwarfParseErrorKind::EntryLengthOverflow))?;
        let aug_data_start = c.pos;
        let aug_data_end = aug_data_start.checked_add(aug_data_len).ok_or_else(|| {
            DwarfError::new(aug_data_start, DwarfParseErrorKind::EntryLengthOverflow)
        })?;
        if aug_data_end > entry_end {
            return Err(DwarfError::new(
                aug_data_start,
                DwarfParseErrorKind::Truncated {
                    needed: aug_data_end,
                    len: entry_end,
                },
            ));
        }
        if config.lsda_encoding != DW_EH_PE_OMIT {
            lsda = c.read_encoded(
                config.lsda_encoding,
                config.text_base,
                config.data_base,
                initial_pc,
            )?;
        }
        if c.pos > aug_data_end {
            return Err(DwarfError::new(
                aug_data_start,
                DwarfParseErrorKind::Truncated {
                    needed: c.pos,
                    len: aug_data_end,
                },
            ));
        }
        c.pos = aug_data_end;
    }

    let fde_instr_offset_in_eh_frame = c.pos;
    if entry_end > eh_frame_bytes.len() {
        return Err(DwarfError::new(
            c.pos,
            DwarfParseErrorKind::Truncated {
                needed: entry_end,
                len: eh_frame_bytes.len(),
            },
        ));
    }
    let fde_instr_len = entry_end - fde_instr_offset_in_eh_frame;

    Ok(ParsedFde {
        initial_pc,
        address_range,
        fde_instr_offset_in_eh_frame,
        fde_instr_len,
        lsda,
    })
}

/// Combine a parsed CIE + FDE into the libunwind-internal
/// `dwarf_cie_info_t` libunwind expects when we set
/// `unw_proc_info_t::format = UNW_INFO_FORMAT_REMOTE_TABLE` and
/// `unwind_info` to point at this struct.
///
/// All `*_instr_start/end` fields hold tracee avmas in `.eh_frame`.
/// Our `access_mem` callback redirects those reads to the local mmap.
pub(crate) fn build_dwarf_cie_info(
    cie: &ParsedCie,
    fde: &ParsedFde,
    eh_frame_avma_base: u64,
) -> DwarfCieInfo {
    let cie_instr_start = eh_frame_avma_base.wrapping_add(cie.cie_instr_offset_in_eh_frame as u64);
    let cie_instr_end = cie_instr_start.wrapping_add(cie.cie_instr_len as u64);
    let fde_instr_start = eh_frame_avma_base.wrapping_add(fde.fde_instr_offset_in_eh_frame as u64);
    let fde_instr_end = fde_instr_start.wrapping_add(fde.fde_instr_len as u64);

    let mut flags = 0u32;
    if cie.has_z {
        flags |= DwarfCieInfo::FLAG_SIZED_AUGMENTATION;
    }
    if cie.signal_frame {
        flags |= DwarfCieInfo::FLAG_SIGNAL_FRAME;
    }

    DwarfCieInfo {
        cie_instr_start,
        cie_instr_end,
        fde_instr_start,
        fde_instr_end,
        code_align: cie.code_align,
        data_align: cie.data_align as u64,
        ret_addr_column: cie.ret_addr_column,
        handler: cie.personality,
        abi: 0,
        tag: 0,
        fde_encoding: cie.fde_encoding,
        lsda_encoding: cie.lsda_encoding,
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cie_zplr_accepts_indirect_pcrel_sdata4_personality_without_deref() {
        let cie = [
            0x15,
            0x00,
            0x00,
            0x00, // length
            0x00,
            0x00,
            0x00,
            0x00, // CIE id
            0x01, // version
            b'z',
            b'P',
            b'L',
            b'R',
            0x00, // augmentation
            0x01, // code align
            0x78, // data align = -8
            0x10, // return address column
            0x07, // augmentation data length
            0x9b, // P: indirect | pcrel | sdata4
            0x00,
            0x00,
            0x00,
            0x00,                             // personality pointer bytes
            DW_EH_PE_OMIT,                    // L
            DW_EH_PE_PCREL | DW_EH_PE_SDATA4, // R
        ];

        let parsed = parse_cie(&cie, 0, 0x1000).unwrap();

        assert_eq!(parsed.personality, 0);
        assert_eq!(parsed.lsda_encoding, DW_EH_PE_OMIT);
        assert_eq!(parsed.fde_encoding, DW_EH_PE_PCREL | DW_EH_PE_SDATA4);
        assert_eq!(parsed.cie_instr_len, 0);
    }

    #[test]
    fn normal_encoded_values_still_reject_indirect_without_deref() {
        let bytes = [0x00, 0x00, 0x00, 0x00];
        let mut cursor = Cursor {
            bytes: &bytes,
            pos: 0,
            avma_base: 0x1000,
        };

        let err = cursor
            .read_encoded(
                DW_EH_PE_INDIRECT | DW_EH_PE_PCREL | DW_EH_PE_SDATA4,
                0,
                0,
                0,
            )
            .unwrap_err();

        assert_eq!(
            err.kind,
            DwarfParseErrorKind::IndirectPointerRequiresDereference {
                encoding: DW_EH_PE_INDIRECT | DW_EH_PE_PCREL | DW_EH_PE_SDATA4
            }
        );
        assert_eq!(cursor.pos, 0);
    }

    #[test]
    fn dwarf64_cie_and_fde_use_8_byte_id_and_pointer() {
        let mut eh_frame = Vec::new();
        eh_frame.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        eh_frame.extend_from_slice(&13u64.to_le_bytes()); // CIE length.
        eh_frame.extend_from_slice(&0u64.to_le_bytes()); // 8-byte CIE id.
        eh_frame.push(1); // version.
        eh_frame.push(0); // empty augmentation string.
        eh_frame.push(1); // code alignment.
        eh_frame.push(0x78); // data alignment = -8.
        eh_frame.push(16); // return-address column.

        let fde_offset = eh_frame.len();
        let cie_ptr_pos = fde_offset + 12;
        eh_frame.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        eh_frame.extend_from_slice(&24u64.to_le_bytes()); // FDE length.
        eh_frame.extend_from_slice(&(cie_ptr_pos as u64).to_le_bytes());
        eh_frame.extend_from_slice(&0x1000u64.to_le_bytes());
        eh_frame.extend_from_slice(&0x10u64.to_le_bytes());

        let cie = parse_cie(&eh_frame, 0, 0x3000).unwrap();
        let fde = parse_fde(
            &eh_frame,
            fde_offset,
            0x3000,
            FdeParseConfig {
                fde_encoding: cie.fde_encoding,
                lsda_encoding: cie.lsda_encoding,
                has_z: cie.has_z,
                text_base: 0,
                data_base: 0,
            },
        )
        .unwrap();

        assert_eq!(cie.cie_instr_offset_in_eh_frame, fde_offset);
        assert_eq!(fde.initial_pc, 0x1000);
        assert_eq!(fde.address_range, 0x10);
        assert_eq!(fde.fde_instr_len, 0);
    }

    #[test]
    fn fde_z_augmentation_length_past_entry_returns_error() {
        let mut fde = Vec::new();
        fde.extend_from_slice(&21u32.to_le_bytes()); // FDE length.
        fde.extend_from_slice(&4u32.to_le_bytes()); // CIE pointer.
        fde.extend_from_slice(&0x1000u64.to_le_bytes());
        fde.extend_from_slice(&0x10u64.to_le_bytes());
        fde.push(1); // Augmentation data claims one byte past entry_end.

        let err = match parse_fde(
            &fde,
            0,
            0,
            FdeParseConfig {
                fde_encoding: DW_EH_PE_ABSPTR,
                lsda_encoding: DW_EH_PE_OMIT,
                has_z: true,
                text_base: 0,
                data_base: 0,
            },
        ) {
            Ok(_) => panic!("malformed FDE augmentation should be rejected"),
            Err(err) => err,
        };

        assert_eq!(
            err.kind,
            DwarfParseErrorKind::Truncated {
                needed: 26,
                len: 25
            }
        );
    }
}
