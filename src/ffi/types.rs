use std::os::raw::{c_char, c_int, c_void};

/// `unw_word_t` from libunwind. 64-bit on the platforms we target.
pub type UnwWord = u64;

/// Opaque handle to an `unw_addr_space_t`. libunwind documents it as a
/// pointer-typedef; we match that shape.
pub type UnwAddrSpace = *mut c_void;

/// Opaque cursor. The real type is `unw_word_t opaque[UNW_TDEP_CURSOR_LEN]`,
/// which has historically grown across libunwind versions:
///   - x86_64 1.3+ : 127 words = 1016 bytes
///   - aarch64 1.5+: 350 words = 2800 bytes (and may grow further)
///
/// We pin a generous 4 KB upper bound so we don't break against future
/// libunwind upgrades; wasting a few KB of stack per unwind is harmless.
/// Aligned to `UnwWord`.
#[repr(C, align(8))]
pub struct UnwCursor {
    _opaque: [u64; 512],
}

impl UnwCursor {
    pub const fn zeroed() -> Self {
        Self { _opaque: [0; 512] }
    }
}

/// `unw_proc_info_t` (libunwind-common.h). Layout matches libunwind's
/// declaration; `extra` is target-dependent. For x86_64 the tdep struct is
/// `{ char unused; }` (1 byte); for aarch64 it's also a single-field padding
/// struct. We declare a 16-byte buffer so any reasonable padding fits.
#[repr(C)]
pub struct UnwProcInfo {
    pub start_ip: UnwWord,
    pub end_ip: UnwWord,
    pub lsda: UnwWord,
    pub handler: UnwWord,
    pub gp: UnwWord,
    pub flags: UnwWord,
    pub format: c_int,
    pub unwind_info_size: c_int,
    pub unwind_info: *mut c_void,
    pub extra: [u8; 16],
}

/// `dwarf_cie_info_t` (libunwind internal header `dwarf.h`).
///
/// **NOT a public libunwind type.** This is the internal DWARF
/// per-function unwind descriptor that libunwind builds up from CIE +
/// FDE bytes. By pre-parsing CIE/FDE in our own code and handing
/// libunwind a populated `dwarf_cie_info_t` directly via
/// `unw_proc_info_t::unwind_info`, libunwind skips its own CIE parser on
/// every step - the dominant cost of remote unwinding.
///
/// The layout below matches libunwind 1.5+ / 1.8 (with `abi` and `tag`
/// fields). **libunwind 1.3 lacks these fields**, so on old systems
/// you'll read garbage for `fde_encoding` and below. If targeting 1.3,
/// remove the `abi` and `tag` fields.
///
/// Field ordering must match libunwind exactly. The trailing bitfields
/// in C (`sized_augmentation : 1`, `have_abi_marker : 1`,
/// `signal_frame : 1`) are packed into one `unsigned int` container -
/// we represent that as a `u32` with bit-mask helpers.
#[repr(C)]
#[derive(Clone)]
pub struct DwarfCieInfo {
    pub cie_instr_start: UnwWord,
    pub cie_instr_end: UnwWord,
    pub fde_instr_start: UnwWord,
    pub fde_instr_end: UnwWord,
    pub code_align: UnwWord,
    pub data_align: UnwWord,
    pub ret_addr_column: UnwWord,
    pub handler: UnwWord,
    pub abi: u16,
    pub tag: u16,
    pub fde_encoding: u8,
    pub lsda_encoding: u8,
    pub flags: u32,
}

impl DwarfCieInfo {
    pub const FLAG_SIZED_AUGMENTATION: u32 = 1 << 0;
    pub const FLAG_SIGNAL_FRAME: u32 = 1 << 2;
}

/// `unw_accessors_t` (libunwind-common.h). The callback table libunwind
/// uses for remote unwinding.
#[repr(C)]
pub struct UnwAccessors {
    pub find_proc_info: Option<
        unsafe extern "C" fn(UnwAddrSpace, UnwWord, *mut UnwProcInfo, c_int, *mut c_void) -> c_int,
    >,
    pub put_unwind_info: Option<unsafe extern "C" fn(UnwAddrSpace, *mut UnwProcInfo, *mut c_void)>,
    pub get_dyn_info_list_addr:
        Option<unsafe extern "C" fn(UnwAddrSpace, *mut UnwWord, *mut c_void) -> c_int>,
    pub access_mem: Option<
        unsafe extern "C" fn(UnwAddrSpace, UnwWord, *mut UnwWord, c_int, *mut c_void) -> c_int,
    >,
    pub access_reg: Option<
        unsafe extern "C" fn(UnwAddrSpace, c_int, *mut UnwWord, c_int, *mut c_void) -> c_int,
    >,
    pub access_fpreg: Option<
        unsafe extern "C" fn(UnwAddrSpace, c_int, *mut [u64; 2], c_int, *mut c_void) -> c_int,
    >,
    pub resume: Option<unsafe extern "C" fn(UnwAddrSpace, *mut UnwCursor, *mut c_void) -> c_int>,
    pub get_proc_name: Option<
        unsafe extern "C" fn(
            UnwAddrSpace,
            UnwWord,
            *mut c_char,
            usize,
            *mut UnwWord,
            *mut c_void,
        ) -> c_int,
    >,
    pub get_elf_filename: Option<
        unsafe extern "C" fn(
            UnwAddrSpace,
            UnwWord,
            *mut c_char,
            usize,
            *mut UnwWord,
            *mut c_void,
        ) -> c_int,
    >,
    pub get_proc_ip_range: Option<
        unsafe extern "C" fn(
            UnwAddrSpace,
            UnwWord,
            *mut UnwWord,
            *mut UnwWord,
            *mut c_void,
        ) -> c_int,
    >,
    pub ptrauth_insn_mask: Option<unsafe extern "C" fn(UnwAddrSpace, *mut c_void) -> UnwWord>,
}
