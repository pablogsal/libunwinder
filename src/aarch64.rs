//! aarch64 backend.

use std::marker::PhantomData;

use crate::address_space::{init_and_step, StepOutcome};
use crate::error::Error;
use crate::ffi::consts::aarch64_regs::{UNW_AARCH64_X29, UNW_AARCH64_X30, UNW_REG_SP};
use crate::frame_address::FrameAddress;
use crate::module::{Module, Unwinder};
use crate::module_set::ModuleSet;
use crate::unwind_ctx::UnwindCtx;

#[repr(C)]
pub(crate) struct RawRegsAarch64 {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
}

/// Mask for stripping pointer authentication bits from return addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PtrAuthMask(pub u64);

impl PtrAuthMask {
    #[must_use]
    pub fn new_no_strip() -> Self {
        Self(u64::MAX)
    }

    #[must_use]
    pub fn new_24_40() -> Self {
        Self(u64::MAX >> 24)
    }

    #[must_use]
    pub fn from_max_known_address(address: u64) -> Self {
        if address == 0 {
            Self::new_no_strip()
        } else {
            Self(u64::MAX >> address.leading_zeros())
        }
    }

    #[must_use]
    pub fn strip_ptr_auth(&self, addr: u64) -> u64 {
        addr & self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnwindRegsAarch64 {
    lr_mask: PtrAuthMask,
    lr: u64,
    sp: u64,
    fp: u64,
}

impl UnwindRegsAarch64 {
    #[must_use]
    pub fn new(lr: u64, sp: u64, fp: u64) -> Self {
        Self::new_with_ptr_auth_mask(PtrAuthMask::new_no_strip(), lr, sp, fp)
    }

    #[must_use]
    pub fn new_with_ptr_auth_mask(mask: PtrAuthMask, lr: u64, sp: u64, fp: u64) -> Self {
        Self {
            lr_mask: mask,
            lr: mask.strip_ptr_auth(lr),
            sp,
            fp,
        }
    }

    #[must_use]
    pub fn lr_mask(&self) -> PtrAuthMask {
        self.lr_mask
    }

    #[must_use]
    pub fn ptr_auth_mask(&self) -> PtrAuthMask {
        self.lr_mask()
    }

    #[must_use]
    pub fn lr(&self) -> u64 {
        self.lr
    }

    pub fn set_lr(&mut self, lr: u64) {
        self.lr = self.lr_mask.strip_ptr_auth(lr);
    }

    #[must_use]
    pub fn sp(&self) -> u64 {
        self.sp
    }

    pub fn set_sp(&mut self, sp: u64) {
        self.sp = sp;
    }

    #[must_use]
    pub fn fp(&self) -> u64 {
        self.fp
    }

    pub fn set_fp(&mut self, fp: u64) {
        self.fp = fp;
    }
}

#[derive(Debug, Default, Clone)]
pub struct CacheAarch64;

impl CacheAarch64 {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

pub struct UnwinderAarch64<S> {
    modules: ModuleSet,
    _phantom: PhantomData<fn() -> S>,
}

impl<S> Clone for UnwinderAarch64<S> {
    fn clone(&self) -> Self {
        Self {
            modules: self.modules.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S> Default for UnwinderAarch64<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> UnwinderAarch64<S> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            modules: ModuleSet::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S> Unwinder for UnwinderAarch64<S>
where
    S: std::ops::Deref<Target = [u8]> + Send + Sync + 'static,
{
    type UnwindRegs = UnwindRegsAarch64;
    type Cache = CacheAarch64;
    type Module = Module<S>;

    fn add_module(&mut self, module: Self::Module) {
        self.modules.add(module.data);
    }

    fn remove_module(&mut self, avma_start: u64) {
        self.modules.remove(avma_start);
    }

    fn max_known_code_address(&self) -> u64 {
        self.modules.max_known_code_address()
    }

    fn is_signal_frame(&self, frame: FrameAddress, regs: &Self::UnwindRegs) -> bool {
        self.modules
            .is_signal_frame(regs.lr_mask.strip_ptr_auth(frame.address_for_lookup()))
    }

    fn unwind_frame<F>(
        &self,
        frame: FrameAddress,
        regs: &mut Self::UnwindRegs,
        _cache: &mut Self::Cache,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let current_ip = regs.lr_mask.strip_ptr_auth(frame.address());
        let lookup_ip = regs.lr_mask.strip_ptr_auth(frame.address_for_lookup());
        if let Some(err) = self.modules.unwind_info_error(lookup_ip) {
            return Err(Error::UnwindInfo(err));
        }
        if !self.modules.has_unwind_info(lookup_ip) {
            return fallback_unwind_frame(current_ip, regs, read_stack);
        }

        let mut raw = RawRegsAarch64 {
            pc: lookup_ip,
            sp: regs.sp,
            fp: regs.fp,
            lr: regs.lr,
        };

        let step = {
            let mut ctx = UnwindCtx {
                modules: &self.modules,
                regs_ptr: &mut raw as *mut RawRegsAarch64 as *mut (),
                lookup_ip,
                read_fn: read_stack,
                last_failed_read_addr: None,
                unwind_info_error: None,
            };
            let step = init_and_step(
                ctx.as_arg(),
                &[UNW_REG_SP, UNW_AARCH64_X29, UNW_AARCH64_X30],
            );
            let failed_read = ctx.last_failed_read_addr;
            let unwind_info_error = ctx.unwind_info_error;
            (step, failed_read, unwind_info_error)
        };

        match step {
            (Ok(StepOutcome::EndOfStack), _, _) => Ok(None),
            (Ok(StepOutcome::Stepped { new_ip, extras }), _, _) => {
                let new_sp = extras[0];
                let new_fp = extras[1];
                let new_lr = extras[2];
                let mut return_address = regs.lr_mask.strip_ptr_auth(new_ip);
                if return_address == 0 {
                    return Ok(None);
                }
                let signal_frame = self.modules.is_signal_frame(lookup_ip);
                if frame.is_return_address()
                    && !signal_frame
                    && self.modules.contains_address(return_address)
                {
                    return_address = return_address
                        .checked_add(1)
                        .ok_or(Error::IntegerOverflow)?;
                }
                if return_address == current_ip && new_sp == regs.sp {
                    return Err(Error::DidNotAdvance);
                }
                regs.set_sp(new_sp);
                regs.set_fp(new_fp);
                regs.set_lr(new_lr);
                Ok(Some(return_address))
            }
            (Err(_), Some(addr), _) => Err(Error::CouldNotReadStack(addr)),
            (Err(_), None, Some(err)) => Err(Error::UnwindInfo(err)),
            (Err(err), None, None) => Err(Error::Libunwind(err)),
        }
    }
}

fn fallback_unwind_frame<F>(
    current_ip: u64,
    regs: &mut UnwindRegsAarch64,
    read_stack: &mut F,
) -> Result<Option<u64>, Error>
where
    F: FnMut(u64) -> Result<u64, ()>,
{
    let sp = regs.sp();
    let fp = regs.fp();
    if fp == 0 {
        return Ok(None);
    }

    let return_address_location = fp.checked_add(8).ok_or(Error::IntegerOverflow)?;
    let new_sp = fp.checked_add(16).ok_or(Error::IntegerOverflow)?;
    if new_sp <= sp {
        return Err(Error::FramepointerUnwindingMovedBackwards);
    }

    let new_fp = read_stack(fp).map_err(|_| Error::CouldNotReadStack(fp))?;
    if new_fp != 0 && new_fp <= fp {
        return Err(Error::FramepointerUnwindingMovedBackwards);
    }

    let new_lr = read_stack(return_address_location)
        .map_err(|_| Error::CouldNotReadStack(return_address_location))?;
    let return_address = regs.lr_mask().strip_ptr_auth(new_lr);
    if return_address == 0 {
        return Ok(None);
    }
    if return_address == current_ip && new_sp == sp {
        return Err(Error::DidNotAdvance);
    }

    regs.set_lr(new_lr);
    regs.set_sp(new_sp);
    regs.set_fp(new_fp);
    Ok(Some(return_address))
}
