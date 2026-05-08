//! x86_64 backend.

use std::marker::PhantomData;

use crate::address_space::{init_and_step, StepOutcome};
use crate::error::Error;
use crate::ffi::consts::x86_64_regs::{UNW_REG_SP, UNW_X86_64_RBP, UNW_X86_64_RIP};
use crate::ffi::{UnwWord, UNW_EBADREG, UNW_ESUCCESS};
use crate::frame_address::FrameAddress;
use crate::module::{Module, Unwinder};
use crate::module_set::ModuleSet;
use crate::unwind_ctx::UnwindCtx;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Reg {
    RAX,
    RDX,
    RCX,
    RBX,
    RSI,
    RDI,
    RBP,
    RSP,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

#[repr(C)]
pub(crate) struct RawRegsX86_64 {
    ip: u64,
    regs: [u64; 16],
    valid_regs: u16,
}

impl RawRegsX86_64 {
    fn from_public(ip: u64, regs: &UnwindRegsX86_64) -> Self {
        Self {
            ip,
            regs: regs.regs,
            valid_regs: regs.valid_regs,
        }
    }

    pub(crate) unsafe fn access_reg(&mut self, reg: i32, val: *mut UnwWord, write: i32) -> i32 {
        // SAFETY: libunwind invokes the access_reg accessor with a valid
        // `*mut UnwWord` aligned for `UnwWord`; reads honor `write == 0`,
        // writes honor `write != 0`. The pointer is owned by libunwind for
        // the duration of the call.
        unsafe {
            if reg == UNW_X86_64_RIP {
                if write != 0 {
                    self.ip = *val;
                } else {
                    *val = self.ip;
                }
                return UNW_ESUCCESS;
            }

            let Some(index) = (0..16).contains(&reg).then_some(reg as usize) else {
                return -UNW_EBADREG;
            };

            if write != 0 {
                self.regs[index] = *val;
                self.valid_regs |= 1u16 << index;
                UNW_ESUCCESS
            } else if self.valid_regs & (1u16 << index) != 0 {
                *val = self.regs[index];
                UNW_ESUCCESS
            } else {
                -UNW_EBADREG
            }
        }
    }
}

/// Register state used for x86_64 unwinding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnwindRegsX86_64 {
    ip: u64,
    regs: [u64; 16],
    valid_regs: u16,
}

impl std::fmt::Debug for UnwindRegsX86_64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnwindRegsX86_64")
            .field("ip", &self.ip)
            .field("rsp", &self.get_if_set(Reg::RSP))
            .field("rbp", &self.get_if_set(Reg::RBP))
            .finish_non_exhaustive()
    }
}

impl UnwindRegsX86_64 {
    #[must_use]
    pub fn new(ip: u64, sp: u64, bp: u64) -> Self {
        let mut regs = Self {
            ip,
            regs: [0; 16],
            valid_regs: 0,
        };
        regs.set_sp(sp);
        regs.set_bp(bp);
        regs
    }

    #[inline]
    fn valid_reg_bit(reg: Reg) -> u16 {
        1u16 << (reg as u8)
    }

    #[must_use]
    pub fn get(&self, reg: Reg) -> u64 {
        self.regs[reg as usize]
    }

    #[must_use]
    pub fn get_if_set(&self, reg: Reg) -> Option<u64> {
        (self.valid_regs & Self::valid_reg_bit(reg) != 0).then(|| self.get(reg))
    }

    pub fn set(&mut self, reg: Reg, value: u64) {
        self.regs[reg as usize] = value;
        self.valid_regs |= Self::valid_reg_bit(reg);
    }

    fn clear_unrestored_caller_registers(&mut self) {
        self.valid_regs = Self::valid_reg_bit(Reg::RSP) | Self::valid_reg_bit(Reg::RBP);
    }

    #[must_use]
    pub fn ip(&self) -> u64 {
        self.ip
    }

    pub fn set_ip(&mut self, ip: u64) {
        self.ip = ip;
    }

    #[must_use]
    pub fn sp(&self) -> u64 {
        self.get(Reg::RSP)
    }

    pub fn set_sp(&mut self, sp: u64) {
        self.set(Reg::RSP, sp);
    }

    #[must_use]
    pub fn bp(&self) -> u64 {
        self.get(Reg::RBP)
    }

    pub fn set_bp(&mut self, bp: u64) {
        self.set(Reg::RBP, bp);
    }

    #[must_use]
    pub fn rip(&self) -> u64 {
        self.ip()
    }

    #[must_use]
    pub fn rsp(&self) -> u64 {
        self.sp()
    }

    #[must_use]
    pub fn rbp(&self) -> u64 {
        self.bp()
    }

    pub fn set_rip(&mut self, v: u64) {
        self.set_ip(v);
    }

    pub fn set_rsp(&mut self, v: u64) {
        self.set_sp(v);
    }

    pub fn set_rbp(&mut self, v: u64) {
        self.set_bp(v);
    }
}

#[derive(Debug, Default, Clone)]
pub struct CacheX86_64;

impl CacheX86_64 {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

pub struct UnwinderX86_64<S> {
    modules: ModuleSet,
    _phantom: PhantomData<fn() -> S>,
}

impl<S> Clone for UnwinderX86_64<S> {
    fn clone(&self) -> Self {
        Self {
            modules: self.modules.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<S> Default for UnwinderX86_64<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> UnwinderX86_64<S> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            modules: ModuleSet::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S> Unwinder for UnwinderX86_64<S>
where
    S: std::ops::Deref<Target = [u8]> + Send + Sync + 'static,
{
    type UnwindRegs = UnwindRegsX86_64;
    type Cache = CacheX86_64;
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

    fn is_signal_frame(&self, frame: FrameAddress, _regs: &Self::UnwindRegs) -> bool {
        self.modules.is_signal_frame(frame.address_for_lookup())
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
        let current_ip = frame.address();
        let lookup_ip = frame.address_for_lookup();
        if let Some(err) = self.modules.unwind_info_error(lookup_ip) {
            return Err(Error::UnwindInfo(err));
        }
        if !self.modules.has_unwind_info(lookup_ip) {
            return fallback_unwind_frame(current_ip, regs, read_stack);
        }

        let mut raw = RawRegsX86_64::from_public(lookup_ip, regs);
        let step = {
            let mut ctx = UnwindCtx {
                modules: &self.modules,
                regs_ptr: &mut raw as *mut RawRegsX86_64 as *mut (),
                lookup_ip,
                read_fn: read_stack,
                last_failed_read_addr: None,
                unwind_info_error: None,
            };
            let step = init_and_step(ctx.as_arg(), &[UNW_REG_SP, UNW_X86_64_RBP]);
            let failed_read = ctx.last_failed_read_addr;
            let unwind_info_error = ctx.unwind_info_error;
            (step, failed_read, unwind_info_error)
        };

        match step {
            (Ok(StepOutcome::EndOfStack), _, _) => Ok(None),
            (Ok(StepOutcome::Stepped { new_ip, extras }), _, _) => {
                let new_sp = extras[0];
                let new_bp = extras[1];
                if new_ip == 0 {
                    return Ok(None);
                }
                let signal_frame = self.modules.is_signal_frame(lookup_ip);
                let new_ip = if frame.is_return_address()
                    && !signal_frame
                    && self.modules.contains_address(new_ip)
                {
                    new_ip.checked_add(1).ok_or(Error::IntegerOverflow)?
                } else {
                    new_ip
                };
                if new_ip == current_ip && new_sp == regs.sp() {
                    return Err(Error::DidNotAdvance);
                }
                regs.clear_unrestored_caller_registers();
                regs.set_ip(new_ip);
                regs.set_sp(new_sp);
                regs.set_bp(new_bp);
                Ok(Some(new_ip))
            }
            (Err(_), Some(addr), _) => Err(Error::CouldNotReadStack(addr)),
            (Err(_), None, Some(err)) => Err(Error::UnwindInfo(err)),
            (Err(err), None, None) => Err(Error::Libunwind(err)),
        }
    }
}

fn fallback_unwind_frame<F>(
    current_ip: u64,
    regs: &mut UnwindRegsX86_64,
    read_stack: &mut F,
) -> Result<Option<u64>, Error>
where
    F: FnMut(u64) -> Result<u64, ()>,
{
    let sp = regs.sp();
    let bp = regs.bp();
    if bp == 0 {
        return Ok(None);
    }

    let return_address_location = bp.checked_add(8).ok_or(Error::IntegerOverflow)?;
    let new_sp = bp.checked_add(16).ok_or(Error::IntegerOverflow)?;
    if new_sp <= sp {
        return Err(Error::FramepointerUnwindingMovedBackwards);
    }

    let new_bp = read_stack(bp).map_err(|_| Error::CouldNotReadStack(bp))?;
    if new_bp != 0 && new_bp <= bp {
        return Err(Error::FramepointerUnwindingMovedBackwards);
    }
    let return_address = read_stack(return_address_location)
        .map_err(|_| Error::CouldNotReadStack(return_address_location))?;
    if return_address == 0 {
        return Ok(None);
    }
    if new_sp == sp && return_address == current_ip {
        return Err(Error::DidNotAdvance);
    }

    regs.clear_unrestored_caller_registers();
    regs.set_ip(return_address);
    regs.set_sp(new_sp);
    regs.set_bp(new_bp);
    Ok(Some(return_address))
}
