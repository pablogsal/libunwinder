/// Error type returned from the unwinder.
///
/// libunwind status codes are decoded into structured variants and kept with
/// the raw status for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Could not read a stack word at the given address. Returned when the
    /// user's `read_fn` returned `Err(())`, typically because the address
    /// fell outside the captured stack snapshot or the tracee read failed.
    CouldNotReadStack(u64),

    /// Frame-pointer based unwinding produced a frame whose FP did not
    /// strictly increase. Indicates a bogus stack.
    FramepointerUnwindingMovedBackwards,

    /// `unw_step` returned the same IP as the previous frame.
    DidNotAdvance,

    /// Arithmetic overflow during unwind state evaluation.
    IntegerOverflow,

    /// Compatibility variant for callers that classify null return addresses
    /// as errors. libunwinder treats a null return address as end-of-stack and
    /// does not emit this variant.
    ReturnAddressIsNull,

    /// libunwind returned an error while initializing, stepping, or reading
    /// recovered registers.
    Libunwind(LibunwindError),

    /// libunwinder could not produce proc-info for an IP in a registered
    /// module.
    UnwindInfo(UnwindInfoError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CouldNotReadStack(addr) => write!(f, "could not read stack memory at 0x{addr:x}"),
            Self::FramepointerUnwindingMovedBackwards => {
                f.write_str("frame pointer unwinding moved backwards")
            }
            Self::DidNotAdvance => {
                f.write_str("neither the code address nor the stack pointer changed")
            }
            Self::IntegerOverflow => f.write_str("unwinding caused integer overflow"),
            Self::ReturnAddressIsNull => f.write_str("return address was null"),
            Self::Libunwind(err) => write!(f, "{err}"),
            Self::UnwindInfo(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Libunwind(err) => Some(err),
            Self::UnwindInfo(err) => Some(err),
            _ => None,
        }
    }
}

/// The libunwind operation that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibunwindPhase {
    InitRemote,
    Step,
    GetInstructionPointer,
    GetRegister { reg: i32 },
}

impl std::fmt::Display for LibunwindPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitRemote => f.write_str("unw_init_remote"),
            Self::Step => f.write_str("unw_step"),
            Self::GetInstructionPointer => f.write_str("unw_get_reg(IP)"),
            Self::GetRegister { reg } => write!(f, "unw_get_reg({reg})"),
        }
    }
}

/// Decoded libunwind status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibunwindErrorCode {
    Unspecified,
    NoMemory,
    BadRegister,
    ReadOnlyRegister,
    StopUnwind,
    InvalidInstructionPointer,
    BadFrame,
    InvalidOperation,
    BadVersion,
    NoInfo,
    Unknown(i32),
}

impl LibunwindErrorCode {
    #[must_use]
    pub fn from_status(status: i32) -> Self {
        match status.abs() {
            crate::ffi::UNW_EUNSPEC => Self::Unspecified,
            crate::ffi::UNW_ENOMEM => Self::NoMemory,
            crate::ffi::UNW_EBADREG => Self::BadRegister,
            crate::ffi::UNW_EREADONLYREG => Self::ReadOnlyRegister,
            crate::ffi::UNW_ESTOPUNWIND => Self::StopUnwind,
            crate::ffi::UNW_EINVALIDIP => Self::InvalidInstructionPointer,
            crate::ffi::UNW_EBADFRAME => Self::BadFrame,
            crate::ffi::UNW_EINVAL => Self::InvalidOperation,
            crate::ffi::UNW_EBADVERSION => Self::BadVersion,
            crate::ffi::UNW_ENOINFO => Self::NoInfo,
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for LibunwindErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => f.write_str("unspecified error"),
            Self::NoMemory => f.write_str("out of memory"),
            Self::BadRegister => f.write_str("bad register"),
            Self::ReadOnlyRegister => f.write_str("read-only register"),
            Self::StopUnwind => f.write_str("forced stop"),
            Self::InvalidInstructionPointer => f.write_str("invalid instruction pointer"),
            Self::BadFrame => f.write_str("bad frame"),
            Self::InvalidOperation => f.write_str("invalid operation"),
            Self::BadVersion => f.write_str("bad version"),
            Self::NoInfo => f.write_str("no unwind info"),
            Self::Unknown(code) => write!(f, "unknown libunwind error code {code}"),
        }
    }
}

/// A libunwind failure with the raw status retained for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibunwindError {
    pub phase: LibunwindPhase,
    pub code: LibunwindErrorCode,
    pub raw_status: i32,
}

impl LibunwindError {
    #[must_use]
    pub fn new(phase: LibunwindPhase, raw_status: i32) -> Self {
        Self {
            phase,
            code: LibunwindErrorCode::from_status(raw_status),
            raw_status,
        }
    }
}

impl std::fmt::Display for LibunwindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} failed: {} (raw status {})",
            self.phase, self.code, self.raw_status
        )
    }
}

impl std::error::Error for LibunwindError {}

/// Precise DWARF parser error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DwarfParseError {
    pub offset: usize,
    pub kind: DwarfParseErrorKind,
}

impl DwarfParseError {
    #[must_use]
    pub fn new(offset: usize, kind: DwarfParseErrorKind) -> Self {
        Self { offset, kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfParseErrorKind {
    Truncated { needed: usize, len: usize },
    Leb128Overflow,
    EntryLengthOverflow,
    OmittedPointerEncoding,
    UnsupportedPointerEncoding { encoding: u8 },
    IndirectPointerRequiresDereference { encoding: u8 },
    UnsupportedPointerApplication { encoding: u8 },
    BadCieId { cie_id: u64 },
    UnsupportedCieVersion { version: u8 },
    UnsupportedCieAddressSize { address_size: u8, segment_size: u8 },
    UnterminatedAugmentationString,
    UnsupportedAugmentation { byte: u8 },
    UnsupportedNonZAugmentation,
    FdeCiePointerIsZero,
}

impl std::fmt::Display for DwarfParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DWARF parse error at .eh_frame offset 0x{:x}: ",
            self.offset
        )?;
        match self.kind {
            DwarfParseErrorKind::Truncated { needed, len } => {
                write!(
                    f,
                    "truncated read, needed byte offset {needed} but buffer length is {len}"
                )
            }
            DwarfParseErrorKind::Leb128Overflow => f.write_str("LEB128 value overflowed u64/i64"),
            DwarfParseErrorKind::EntryLengthOverflow => {
                f.write_str("entry length overflows the .eh_frame buffer")
            }
            DwarfParseErrorKind::OmittedPointerEncoding => {
                f.write_str("DW_EH_PE_omit cannot be decoded as a value")
            }
            DwarfParseErrorKind::UnsupportedPointerEncoding { encoding } => {
                write!(f, "unsupported pointer encoding 0x{encoding:02x}")
            }
            DwarfParseErrorKind::IndirectPointerRequiresDereference { encoding } => {
                write!(
                    f,
                    "pointer encoding 0x{encoding:02x} is indirect and would require tracee memory dereference"
                )
            }
            DwarfParseErrorKind::UnsupportedPointerApplication { encoding } => {
                write!(
                    f,
                    "unsupported pointer application in encoding 0x{encoding:02x}"
                )
            }
            DwarfParseErrorKind::BadCieId { cie_id } => {
                write!(f, "expected CIE id 0, found {cie_id}")
            }
            DwarfParseErrorKind::UnsupportedCieVersion { version } => {
                write!(f, "unsupported CIE version {version}")
            }
            DwarfParseErrorKind::UnsupportedCieAddressSize {
                address_size,
                segment_size,
            } => write!(
                f,
                "unsupported CIE address_size={address_size}, segment_size={segment_size}"
            ),
            DwarfParseErrorKind::UnterminatedAugmentationString => {
                f.write_str("unterminated CIE augmentation string")
            }
            DwarfParseErrorKind::UnsupportedAugmentation { byte } => {
                write!(f, "unsupported CIE augmentation byte 0x{byte:02x}")
            }
            DwarfParseErrorKind::UnsupportedNonZAugmentation => {
                f.write_str("unsupported non-z CIE augmentation string")
            }
            DwarfParseErrorKind::FdeCiePointerIsZero => {
                f.write_str("FDE CIE pointer is zero, so entry is not an FDE")
            }
        }
    }
}

impl std::error::Error for DwarfParseError {}

/// Why libunwinder could not provide libunwind proc-info for a module IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindInfoError {
    ModuleNotFound {
        ip: u64,
    },
    MissingLocalUnwindSections {
        module: String,
        ip: u64,
    },
    FunctionCachePoisoned {
        module: String,
    },
    EhFrameHeaderLookupMiss {
        module: String,
        ip: u64,
    },
    InvalidEhFrameHdr {
        module: String,
        source: crate::eh_frame_table::EhFrameHdrError,
    },
    FdeOffsetBeforeEhFrame {
        module: String,
        fde_avma: u64,
        eh_frame_avma: u64,
    },
    FdeOffsetOutOfRange {
        module: String,
        fde_offset: usize,
        eh_frame_len: usize,
    },
    FdeLengthPrefixTruncated {
        module: String,
        fde_offset: usize,
        eh_frame_len: usize,
    },
    CiePointerTruncated {
        module: String,
        cie_ptr_offset: usize,
        eh_frame_len: usize,
    },
    CiePointerUnderflow {
        module: String,
        cie_ptr_offset: usize,
        cie_ptr: u64,
    },
    CieParse {
        module: String,
        cie_offset: usize,
        source: DwarfParseError,
    },
    FdeParse {
        module: String,
        fde_offset: usize,
        source: DwarfParseError,
    },
}

impl std::fmt::Display for UnwindInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleNotFound { ip } => {
                write!(f, "no registered module contains IP 0x{ip:x}")
            }
            Self::MissingLocalUnwindSections { module, ip } => write!(
                f,
                "module {module} has no local .eh_frame/.eh_frame_hdr data for IP 0x{ip:x}"
            ),
            Self::FunctionCachePoisoned { module } => {
                write!(f, "function-details cache for module {module} is poisoned")
            }
            Self::EhFrameHeaderLookupMiss { module, ip } => {
                write!(f, ".eh_frame_hdr in module {module} has no FDE for IP 0x{ip:x}")
            }
            Self::InvalidEhFrameHdr { module, source } => {
                write!(f, "module {module} has malformed .eh_frame_hdr: {source}")
            }
            Self::FdeOffsetBeforeEhFrame {
                module,
                fde_avma,
                eh_frame_avma,
            } => write!(
                f,
                "module {module} FDE address 0x{fde_avma:x} is before .eh_frame at 0x{eh_frame_avma:x}"
            ),
            Self::FdeOffsetOutOfRange {
                module,
                fde_offset,
                eh_frame_len,
            } => write!(
                f,
                "module {module} FDE offset 0x{fde_offset:x} is outside .eh_frame length 0x{eh_frame_len:x}"
            ),
            Self::FdeLengthPrefixTruncated {
                module,
                fde_offset,
                eh_frame_len,
            } => write!(
                f,
                "module {module} FDE length prefix at 0x{fde_offset:x} exceeds .eh_frame length 0x{eh_frame_len:x}"
            ),
            Self::CiePointerTruncated {
                module,
                cie_ptr_offset,
                eh_frame_len,
            } => write!(
                f,
                "module {module} CIE pointer at 0x{cie_ptr_offset:x} exceeds .eh_frame length 0x{eh_frame_len:x}"
            ),
            Self::CiePointerUnderflow {
                module,
                cie_ptr_offset,
                cie_ptr,
            } => write!(
                f,
                "module {module} CIE pointer 0x{cie_ptr:x} at 0x{cie_ptr_offset:x} points before .eh_frame"
            ),
            Self::CieParse {
                module,
                cie_offset,
                source,
            } => write!(
                f,
                "failed to parse CIE at .eh_frame offset 0x{cie_offset:x} in module {module}: {source}"
            ),
            Self::FdeParse {
                module,
                fde_offset,
                source,
            } => write!(
                f,
                "failed to parse FDE at .eh_frame offset 0x{fde_offset:x} in module {module}: {source}"
            ),
        }
    }
}

impl std::error::Error for UnwindInfoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEhFrameHdr { source, .. } => Some(source),
            Self::CieParse { source, .. } | Self::FdeParse { source, .. } => Some(source),
            _ => None,
        }
    }
}
