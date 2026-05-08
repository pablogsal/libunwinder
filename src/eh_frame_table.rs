//! `.eh_frame_hdr` parsing - just enough to hand libunwind a
//! `unw_dyn_remote_table_info_t`.
//!
//! Format (Linux Standard Base "Exception Frame Header"):
//!   u8  version             (must be 1)
//!   u8  eh_frame_ptr_enc    (encoding of the eh_frame pointer)
//!   u8  fde_count_enc       (encoding of the fde count)
//!   u8  table_enc           (encoding of binary-search-table entries)
//!   var eh_frame_ptr        (encoded per eh_frame_ptr_enc)
//!   var fde_count           (encoded per fde_count_enc)
//!   var binary_search_table (fde_count * sizeof(table entry))
//!
//! The fast path only needs to locate the binary search table: its file
//! offset within `.eh_frame_hdr` and its entry count.

// DW_EH_PE_* encoding constants. Just the ones we accept.
const DW_EH_PE_OMIT: u8 = 0xff;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_SDATA4: u8 = 0x0b;
const DW_EH_PE_DATAREL: u8 = 0x30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhFrameHdrError {
    FixedHeaderTruncated {
        len: usize,
    },
    UnsupportedVersion {
        version: u8,
    },
    UnsupportedEhFramePtrEncoding {
        encoding: u8,
    },
    EhFramePtrTruncated {
        offset: usize,
        size: usize,
        len: usize,
    },
    UnsupportedFdeCountEncoding {
        encoding: u8,
    },
    FdeCountTruncated {
        offset: usize,
        size: usize,
        len: usize,
    },
    UnsupportedTableEncoding {
        encoding: u8,
    },
    TableTruncated {
        offset: usize,
        entry_count: u64,
        len: usize,
    },
}

impl std::fmt::Display for EhFrameHdrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FixedHeaderTruncated { len } => {
                write!(f, ".eh_frame_hdr fixed header is truncated: len={len}, need 4")
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported .eh_frame_hdr version {version}")
            }
            Self::UnsupportedEhFramePtrEncoding { encoding } => write!(
                f,
                "unsupported .eh_frame_hdr eh_frame_ptr encoding 0x{encoding:02x}"
            ),
            Self::EhFramePtrTruncated { offset, size, len } => write!(
                f,
                ".eh_frame_hdr eh_frame_ptr at offset 0x{offset:x} needs {size} bytes but len is {len}"
            ),
            Self::UnsupportedFdeCountEncoding { encoding } => write!(
                f,
                "unsupported .eh_frame_hdr FDE count encoding 0x{encoding:02x}"
            ),
            Self::FdeCountTruncated { offset, size, len } => write!(
                f,
                ".eh_frame_hdr FDE count at offset 0x{offset:x} needs {size} bytes but len is {len}"
            ),
            Self::UnsupportedTableEncoding { encoding } => write!(
                f,
                "unsupported .eh_frame_hdr table encoding 0x{encoding:02x}; expected DW_EH_PE_datarel|DW_EH_PE_sdata4"
            ),
            Self::TableTruncated {
                offset,
                entry_count,
                len,
            } => write!(
                f,
                ".eh_frame_hdr table at offset 0x{offset:x} has {entry_count} entries but len is {len}"
            ),
        }
    }
}

impl std::error::Error for EhFrameHdrError {}

/// Pre-parsed `.eh_frame_hdr` view. We don't keep the bytes here - the
/// owning `ModuleData` does. We only record the offsets libunwind needs
/// plus what we need for our own binary search of the table.
pub(crate) struct EhFrameTable {
    /// Offset within `.eh_frame_hdr` where the binary search table starts.
    pub table_data_offset: u64,
    /// Number of entries in the binary search table.
    pub entry_count: u64,
    /// Tracee avma of `.eh_frame_hdr` start (the segbase used for
    /// resolving DW_EH_PE_datarel offsets in table entries).
    pub eh_frame_hdr_avma: u64,
}

impl EhFrameTable {
    pub fn empty(eh_frame_hdr_avma: u64) -> Self {
        Self {
            table_data_offset: 0,
            entry_count: 0,
            eh_frame_hdr_avma,
        }
    }

    /// Parse the header. This parser intentionally accepts only the common
    /// Linux shape libunwinder's fast path understands.
    pub fn parse(
        eh_frame_hdr: &[u8],
        _eh_frame_hdr_svma: u64,
        _eh_frame_svma: Option<u64>,
        _base_avma: u64,
        _base_svma: u64,
        _text_avma: u64,
        eh_frame_hdr_avma: u64,
    ) -> Result<Self, EhFrameHdrError> {
        if eh_frame_hdr.len() < 4 {
            return Err(EhFrameHdrError::FixedHeaderTruncated {
                len: eh_frame_hdr.len(),
            });
        }
        if eh_frame_hdr[0] != 1 {
            return Err(EhFrameHdrError::UnsupportedVersion {
                version: eh_frame_hdr[0],
            });
        }

        let eh_frame_ptr_enc = eh_frame_hdr[1];
        let fde_count_enc = eh_frame_hdr[2];
        let table_enc = eh_frame_hdr[3];
        let mut cursor = 4usize;

        let eh_frame_ptr_size = match enc_size(eh_frame_ptr_enc) {
            Some(s) => s,
            None => {
                return Err(EhFrameHdrError::UnsupportedEhFramePtrEncoding {
                    encoding: eh_frame_ptr_enc,
                });
            }
        };
        if cursor.saturating_add(eh_frame_ptr_size) > eh_frame_hdr.len() {
            return Err(EhFrameHdrError::EhFramePtrTruncated {
                offset: cursor,
                size: eh_frame_ptr_size,
                len: eh_frame_hdr.len(),
            });
        }
        cursor += eh_frame_ptr_size;

        let fde_count = match read_unsigned(&eh_frame_hdr[cursor..], fde_count_enc) {
            Some((val, size)) => {
                cursor += size;
                val
            }
            None => match enc_size(fde_count_enc) {
                Some(size) => {
                    return Err(EhFrameHdrError::FdeCountTruncated {
                        offset: cursor,
                        size,
                        len: eh_frame_hdr.len(),
                    });
                }
                None => {
                    return Err(EhFrameHdrError::UnsupportedFdeCountEncoding {
                        encoding: fde_count_enc,
                    });
                }
            },
        };

        // Validate the table encoding is what libunwind expects.
        // DW_EH_PE_datarel|sdata4 (0x3B) is the canonical glibc choice.
        if table_enc != (DW_EH_PE_DATAREL | DW_EH_PE_SDATA4) {
            return Err(EhFrameHdrError::UnsupportedTableEncoding {
                encoding: table_enc,
            });
        }

        let entry_size = 8u64; // two int32s per entry
        let need = entry_size.saturating_mul(fde_count) as usize;
        if cursor.saturating_add(need) > eh_frame_hdr.len() {
            return Err(EhFrameHdrError::TableTruncated {
                offset: cursor,
                entry_count: fde_count,
                len: eh_frame_hdr.len(),
            });
        }

        Ok(Self {
            table_data_offset: cursor as u64,
            entry_count: fde_count,
            eh_frame_hdr_avma,
        })
    }

    /// Binary-search the `.eh_frame_hdr` table for the nearest FDE candidate
    /// whose start address is not greater than the given tracee IP. Returns
    /// `(initial_pc, fde_avma)` of that entry, or `None` if `ip` is below the
    /// lowest entry. Callers must parse the FDE and verify its address range
    /// before treating it as a match.
    ///
    /// Each table entry is two `int32` values (`DW_EH_PE_datarel|sdata4`):
    /// `(initial_pc_offset, fde_offset)` relative to `.eh_frame_hdr`'s
    /// avma.
    pub fn lookup(&self, eh_frame_hdr_bytes: &[u8], ip: u64) -> Option<(u64, u64)> {
        if self.entry_count == 0 {
            return None;
        }
        let table_off = self.table_data_offset as usize;
        let n = self.entry_count as usize;
        let entries = eh_frame_hdr_bytes.get(table_off..table_off + n * 8)?;
        let segbase = self.eh_frame_hdr_avma;

        // Decode helper.
        let entry_pc = |i: usize| -> u64 {
            let off = i * 8;
            let pc_off = i32::from_le_bytes([
                entries[off],
                entries[off + 1],
                entries[off + 2],
                entries[off + 3],
            ]);
            segbase.wrapping_add(pc_off as i64 as u64)
        };
        let entry_fde = |i: usize| -> u64 {
            let off = i * 8 + 4;
            let fde_off = i32::from_le_bytes([
                entries[off],
                entries[off + 1],
                entries[off + 2],
                entries[off + 3],
            ]);
            segbase.wrapping_add(fde_off as i64 as u64)
        };

        // Binary search for the largest entry with initial_pc <= ip.
        let mut lo = 0usize;
        let mut hi = n;
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            if entry_pc(mid) <= ip {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let pc = entry_pc(lo);
        if pc > ip {
            return None;
        }
        Some((pc, entry_fde(lo)))
    }
}

fn enc_size(enc: u8) -> Option<usize> {
    if enc == DW_EH_PE_OMIT {
        return None;
    }
    match enc & 0x0f {
        DW_EH_PE_UDATA4 | DW_EH_PE_SDATA4 => Some(4),
        0x04 | 0x0c => Some(8), // DW_EH_PE_udata8 / sdata8
        0x02 | 0x0a => Some(2), // udata2 / sdata2
        _ => None,
    }
}

fn read_unsigned(bytes: &[u8], enc: u8) -> Option<(u64, usize)> {
    if enc == DW_EH_PE_OMIT {
        return None;
    }
    match enc & 0x0f {
        DW_EH_PE_UDATA4 => {
            if bytes.len() < 4 {
                return None;
            }
            let v = u32::from_le_bytes(bytes[..4].try_into().ok()?);
            Some((v as u64, 4))
        }
        DW_EH_PE_SDATA4 => {
            if bytes.len() < 4 {
                return None;
            }
            let v = i32::from_le_bytes(bytes[..4].try_into().ok()?);
            Some((v as u64, 4))
        }
        0x04 => {
            if bytes.len() < 8 {
                return None;
            }
            let v = u64::from_le_bytes(bytes[..8].try_into().ok()?);
            Some((v, 8))
        }
        _ => None,
    }
}
