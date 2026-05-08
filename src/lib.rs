//! libunwind-backed native unwinder for profilers.
//!
//! This crate targets native Linux x86_64/aarch64 unwinding through vendored
//! libunwind. The public surface is intentionally small and Rust-oriented:
//! callers provide module unwind sections, register state, and a stack-read
//! callback, and receive one recovered caller frame at a time.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

mod address_space;
mod callbacks;
mod dwarf;
mod eh_frame_table;
mod error;
mod ffi;
mod frame_address;
mod module;
mod module_set;
mod unwind_ctx;

pub use eh_frame_table::EhFrameHdrError;
pub use error::{
    DwarfParseError, DwarfParseErrorKind, Error, LibunwindError, LibunwindErrorCode,
    LibunwindPhase, UnwindInfoError,
};
pub use frame_address::FrameAddress;
pub use module::{
    DwarfModuleSections, ExplicitModuleSectionInfo, MmapBytes, MmapModuleError, Module,
    ModuleError, ModuleSectionInfo, UnwindIterator, Unwinder,
};

#[cfg(target_arch = "aarch64")]
pub type CacheNative = aarch64::CacheAarch64;
#[cfg(target_arch = "aarch64")]
pub type UnwindRegsNative = aarch64::UnwindRegsAarch64;
#[cfg(target_arch = "aarch64")]
pub type UnwinderNative<D> = aarch64::UnwinderAarch64<D>;

#[cfg(target_arch = "x86_64")]
pub type CacheNative = x86_64::CacheX86_64;
#[cfg(target_arch = "x86_64")]
pub type UnwindRegsNative = x86_64::UnwindRegsX86_64;
#[cfg(target_arch = "x86_64")]
pub type UnwinderNative<D> = x86_64::UnwinderX86_64<D>;

/// Internal entry points exposed for fuzzing only. Enabled by the
/// `__fuzz` feature; not part of the public API and may change at any
/// time. Do not use from regular code.
#[cfg(feature = "__fuzz")]
#[doc(hidden)]
pub mod __fuzz {
    use crate::dwarf;

    /// Drive the DWARF CIE/FDE parsers from a fuzzer input. The first
    /// byte selects which parser and how to derive the FDE config; the
    /// remainder is the payload offered to the parser at offset 0.
    pub fn parse_dwarf(data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mode = data[0];
        if mode & 1 == 0 {
            let payload = &data[1..];
            let _ = dwarf::parse_cie(payload, 0, 0);
        } else {
            let fde_encoding = data.get(1).copied().unwrap_or(0);
            let lsda_encoding = data.get(2).copied().unwrap_or(0);
            let payload = if data.len() > 3 { &data[3..] } else { &[] };
            let cfg = dwarf::FdeParseConfig {
                fde_encoding,
                lsda_encoding,
                has_z: (mode & 2) != 0,
                text_base: 0,
                data_base: 0,
            };
            let _ = dwarf::parse_fde(payload, 0, 0, cfg);
        }
    }
}
