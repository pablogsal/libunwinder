//! Hand-written FFI bindings to libunwind. We bind only what we use:
//! address space construction, remote-cursor stepping, and the accessors
//! struct that lets us plug in our own memory/register read callbacks.
//!
//! libunwind's `unw_*` symbols are macros that expand to per-arch mangled
//! names (`_Ux86_64_*`, `_Uaarch64_*`); we use `#[link_name]` to bind the
//! mangled symbols directly.

pub mod consts;
pub mod types;

pub use consts::*;
pub use types::*;

use std::os::raw::c_int;

/// `UNW_REG_IP` for the host architecture.
#[inline]
#[must_use]
pub fn reg_ip() -> c_int {
    #[cfg(target_arch = "x86_64")]
    {
        consts::x86_64_regs::UNW_REG_IP
    }
    #[cfg(target_arch = "aarch64")]
    {
        consts::aarch64_regs::UNW_REG_IP
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" {
    #[link_name = "_Ux86_64_create_addr_space"]
    pub fn unw_create_addr_space(a: *const UnwAccessors, byteorder: c_int) -> UnwAddrSpace;

    #[link_name = "_Ux86_64_init_remote"]
    pub fn unw_init_remote(c: *mut UnwCursor, a: UnwAddrSpace, arg: *mut std::ffi::c_void)
        -> c_int;

    #[link_name = "_Ux86_64_step"]
    pub fn unw_step(c: *mut UnwCursor) -> c_int;

    #[link_name = "_Ux86_64_get_reg"]
    pub fn unw_get_reg(c: *mut UnwCursor, reg: c_int, val: *mut UnwWord) -> c_int;
}

#[cfg(target_arch = "aarch64")]
extern "C" {
    #[link_name = "_Uaarch64_create_addr_space"]
    pub fn unw_create_addr_space(a: *const UnwAccessors, byteorder: c_int) -> UnwAddrSpace;

    #[link_name = "_Uaarch64_init_remote"]
    pub fn unw_init_remote(c: *mut UnwCursor, a: UnwAddrSpace, arg: *mut std::ffi::c_void)
        -> c_int;

    #[link_name = "_Uaarch64_step"]
    pub fn unw_step(c: *mut UnwCursor) -> c_int;

    #[link_name = "_Uaarch64_get_reg"]
    pub fn unw_get_reg(c: *mut UnwCursor, reg: c_int, val: *mut UnwWord) -> c_int;
}
