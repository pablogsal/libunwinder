use libunwinder::{FrameAddress, Unwinder};

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use super::*;
    use libunwinder::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};
    use libunwinder::Error;

    fn unwind_with_stack(
        sp: u64,
        bp: u64,
        stack: &[u64],
    ) -> (Result<Option<u64>, Error>, UnwindRegsX86_64) {
        let unwinder: UnwinderX86_64<Vec<u8>> = UnwinderX86_64::new();
        let mut cache = CacheX86_64::new();
        let mut regs = UnwindRegsX86_64::new(0x1000, sp, bp);
        let result = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x1000),
            &mut regs,
            &mut cache,
            &mut |addr| stack.get((addr / 8) as usize).copied().ok_or(()),
        );
        (result, regs)
    }

    #[test]
    fn unwinds_with_frame_pointer() {
        let stack = [0, 0, 0, 0, 0x40, 0x1234];
        let (result, regs) = unwind_with_stack(0x10, 0x20, &stack);
        assert_eq!(result, Ok(Some(0x1234)));
        assert_eq!((regs.ip(), regs.sp(), regs.bp()), (0x1234, 0x30, 0x40));
    }

    #[test]
    fn zero_frame_pointer_ends_stack() {
        let (result, _) = unwind_with_stack(0x10, 0, &[]);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn backwards_frame_pointer_is_error() {
        let stack = [0, 0, 0x40, 0x1234];
        let (result, _) = unwind_with_stack(0x30, 0x10, &stack);
        assert_eq!(result, Err(Error::FramepointerUnwindingMovedBackwards));
    }

    #[test]
    fn non_increasing_saved_frame_pointer_is_error() {
        let stack = [0, 0, 0, 0, 0x20, 0x1234];
        let (result, _) = unwind_with_stack(0x10, 0x20, &stack);
        assert_eq!(result, Err(Error::FramepointerUnwindingMovedBackwards));

        let stack = [0, 0, 0, 0, 0x18, 0x1234];
        let (result, _) = unwind_with_stack(0x10, 0x20, &stack);
        assert_eq!(result, Err(Error::FramepointerUnwindingMovedBackwards));
    }

    #[test]
    fn final_saved_frame_pointer_returns_address_before_zero_bp_ends_stack() {
        let stack = [0, 0, 0, 0, 0, 0x1234];
        let (result, regs) = unwind_with_stack(0x10, 0x20, &stack);
        assert_eq!(result, Ok(Some(0x1234)));
        assert_eq!((regs.ip(), regs.sp(), regs.bp()), (0x1234, 0x30, 0));

        let unwinder: UnwinderX86_64<Vec<u8>> = UnwinderX86_64::new();
        let mut cache = CacheX86_64::new();
        let mut regs = regs;
        let result = unwinder.unwind_frame(
            FrameAddress::from_return_address(0x1234).unwrap(),
            &mut regs,
            &mut cache,
            &mut |_| Err(()),
        );
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn failed_stack_read_reports_address() {
        let (result, _) = unwind_with_stack(0x10, 0x20, &[]);
        assert_eq!(result, Err(Error::CouldNotReadStack(0x20)));
    }

    #[test]
    fn null_return_address_ends_stack() {
        let stack = [0, 0, 0, 0, 0x40, 0];
        let (result, _) = unwind_with_stack(0x10, 0x20, &stack);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn iterator_yields_initial_ip_then_return_address() {
        let unwinder: UnwinderX86_64<Vec<u8>> = UnwinderX86_64::new();
        let mut cache = CacheX86_64::new();
        let regs = UnwindRegsX86_64::new(0x1000, 0x10, 0x20);
        let stack = [0, 0, 0, 0, 0x40, 0x1234];
        let mut read_stack = |addr| stack.get((addr / 8) as usize).copied().ok_or(());
        let mut iter = unwinder.iter_frames(0x1000, regs, &mut cache, &mut read_stack);

        assert_eq!(
            iter.next(),
            Ok(Some(FrameAddress::InstructionPointer(0x1000)))
        );
        assert_eq!(
            iter.next(),
            Ok(Some(FrameAddress::from_return_address(0x1234).unwrap()))
        );
    }

    #[test]
    fn malformed_eh_frame_hdr_reports_structured_error() {
        use libunwinder::{DwarfModuleSections, EhFrameHdrError, Module, UnwindInfoError};

        let mut unwinder = UnwinderX86_64::new();
        unwinder.add_module(Module::new(
            "bad".to_string(),
            0x1000..0x2000,
            0x1000,
            DwarfModuleSections {
                base_svma: 0x1000,
                text_svma: Some(0x1000..0x1001),
                text: Some(vec![0]),
                eh_frame_svma: Some(0x1100..0x1101),
                eh_frame: Some(vec![0]),
                eh_frame_hdr_svma: Some(0x1200..0x1203),
                eh_frame_hdr: Some(vec![1, 0, 0]),
            },
        ));

        let mut cache = CacheX86_64::new();
        let mut regs = UnwindRegsX86_64::new(0x1000, 0x10, 0x20);
        let result = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x1000),
            &mut regs,
            &mut cache,
            &mut |_| Err(()),
        );

        assert_eq!(
            result,
            Err(Error::UnwindInfo(UnwindInfoError::InvalidEhFrameHdr {
                module: "bad".to_string(),
                source: EhFrameHdrError::FixedHeaderTruncated { len: 3 },
            }))
        );
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use super::*;
    use libunwinder::aarch64::{CacheAarch64, UnwindRegsAarch64, UnwinderAarch64};

    #[test]
    fn unwinds_with_frame_pointer() {
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
        assert_eq!((regs.lr(), regs.sp(), regs.fp()), (0x1234, 0x30, 0x40));
    }

    #[test]
    fn final_saved_lr_is_returned_before_zero_fp_ends_stack() {
        let unwinder: UnwinderAarch64<Vec<u8>> = UnwinderAarch64::new();
        let mut cache = CacheAarch64::new();
        let mut regs = UnwindRegsAarch64::new(0x1000, 0x10, 0x20);
        let stack = [0, 0, 0, 0, 0, 0x1234];

        let result = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x1000),
            &mut regs,
            &mut cache,
            &mut |addr| stack.get((addr / 8) as usize).copied().ok_or(()),
        );

        assert_eq!(result, Ok(Some(0x1234)));
        assert_eq!((regs.lr(), regs.sp(), regs.fp()), (0x1234, 0x30, 0));

        let result = unwinder.unwind_frame(
            FrameAddress::from_return_address(0x1234).unwrap(),
            &mut regs,
            &mut cache,
            &mut |_| Err(()),
        );
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn backwards_frame_pointer_is_error_without_stack_read() {
        let unwinder: UnwinderAarch64<Vec<u8>> = UnwinderAarch64::new();
        let mut cache = CacheAarch64::new();
        let mut regs = UnwindRegsAarch64::new(0x1000, 0x30, 0x10);
        let mut read_count = 0;

        let result = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x1000),
            &mut regs,
            &mut cache,
            &mut |_| {
                read_count += 1;
                Err(())
            },
        );

        assert_eq!(
            result,
            Err(libunwinder::Error::FramepointerUnwindingMovedBackwards)
        );
        assert_eq!(read_count, 0);
    }

    #[test]
    fn non_increasing_saved_frame_pointer_is_error_before_lr_read() {
        let unwinder: UnwinderAarch64<Vec<u8>> = UnwinderAarch64::new();
        let mut cache = CacheAarch64::new();
        let mut regs = UnwindRegsAarch64::new(0x1000, 0x10, 0x20);
        let mut read_count = 0;

        let result = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x1000),
            &mut regs,
            &mut cache,
            &mut |addr| {
                read_count += 1;
                match addr {
                    0x20 => Ok(0x20),
                    _ => Err(()),
                }
            },
        );

        assert_eq!(
            result,
            Err(libunwinder::Error::FramepointerUnwindingMovedBackwards)
        );
        assert_eq!(read_count, 1);
    }
}
