//! The per-`unwind_frame` context that's threaded through libunwind's
//! `arg: *mut c_void` parameter into our callbacks.
//!
//! Lifetime: ctx is allocated on the stack of `unwind_frame`, passed into
//! `unw_init_remote`, used during `unw_step` and `unw_get_reg`, and
//! deallocated on return. libunwind never retains the pointer past the
//! cursor's lifetime, and the cursor lives in the `unwind_frame` stack
//! frame.

use std::ffi::c_void;

use crate::error::UnwindInfoError;
use crate::module_set::ModuleSet;

/// Per-call context, type-erased over the user's `read_fn` and the
/// architecture's `RawRegs` so the FFI callbacks can be non-generic.
///
/// `regs_ptr` is `*mut RawRegsX86_64` or `*mut RawRegsAarch64` depending
/// on which arch's `unwind_frame` built it; the per-arch callbacks know
/// which type to cast back to via `cfg(target_arch)`.
pub(crate) struct UnwindCtx<'a> {
    pub modules: &'a ModuleSet,
    pub regs_ptr: *mut (),
    pub lookup_ip: u64,
    pub read_fn: &'a mut dyn FnMut(u64) -> Result<u64, ()>,
    /// Set when a tracee read fails so the caller can recover the address.
    pub last_failed_read_addr: Option<u64>,
    /// Set when `find_proc_info` cannot build unwind info for the lookup IP.
    pub unwind_info_error: Option<UnwindInfoError>,
}

impl<'a> UnwindCtx<'a> {
    pub fn as_arg(&mut self) -> *mut c_void {
        self as *mut Self as *mut c_void
    }

    /// Reinterpret the opaque `arg` libunwind passes to a callback as
    /// `&mut UnwindCtx`. SAFETY: caller guarantees `arg` was produced by
    /// `as_arg()` on a live `UnwindCtx`.
    pub unsafe fn from_arg<'b>(arg: *mut c_void) -> &'b mut UnwindCtx<'b> {
        // SAFETY: by this fn's contract, `arg` came from `as_arg()` on a
        // live `UnwindCtx<'b>` and outlives the returned reference.
        unsafe { &mut *(arg as *mut UnwindCtx<'b>) }
    }
}
