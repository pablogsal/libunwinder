use libunwinder::{FrameAddress, Unwinder};

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_64_no_module_uses_frame_pointer_fallback() {
    use libunwinder::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};

    let unwinder: UnwinderX86_64<Vec<u8>> = UnwinderX86_64::new();
    let mut cache = CacheX86_64::new();
    let mut regs = UnwindRegsX86_64::new(0x1000, 0x10, 0x20);
    let stack = [0, 0, 0, 0, 0x40, 0x1234];

    let result = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x1000),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).copied().ok_or(()),
    );

    assert_eq!(result, Ok(Some(0x1234)));
    assert_eq!(regs.ip(), 0x1234);
    assert_eq!(regs.sp(), 0x30);
    assert_eq!(regs.bp(), 0x40);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn aarch64_no_module_uses_frame_pointer_fallback() {
    use libunwinder::aarch64::{CacheAarch64, UnwindRegsAarch64, UnwinderAarch64};

    let unwinder: UnwinderAarch64<Vec<u8>> = UnwinderAarch64::new();
    let mut cache = CacheAarch64::new();
    let mut regs = UnwindRegsAarch64::new(0x1000, 0x10, 0x20);
    let stack = [0, 0, 0, 0, 0x40, 0x1234];

    let result = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x1000),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).copied().ok_or(()),
    );

    assert_eq!(result, Ok(Some(0x1234)));
    assert_eq!(regs.lr(), 0x1234);
    assert_eq!(regs.sp(), 0x30);
    assert_eq!(regs.fp(), 0x40);
}
