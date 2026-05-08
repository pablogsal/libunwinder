#![cfg(target_os = "linux")]

use std::path::Path;

use libunwinder::{FrameAddress, MmapBytes, Module, Unwinder};

fn add_object<U>(unwinder: &mut U, objpath: &Path, base_avma: u64)
where
    U: Unwinder<Module = Module<MmapBytes>>,
{
    let file_len = std::fs::metadata(objpath).unwrap().len();
    let module =
        Module::from_mmap_file(objpath, base_avma..base_avma + file_len, base_avma).unwrap();
    unwinder.add_module(module);
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use super::*;
    use libunwinder::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};

    fn fixture(path: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/linux")
            .join(path)
    }

    #[test]
    fn plt_cfa_expr() {
        let mut cache = CacheX86_64::new();
        let mut unwinder = UnwinderX86_64::new();
        add_object(
            &mut unwinder,
            &fixture("x86_64/fp/nightly-firefox-bin"),
            0x1000000,
        );

        let stack = [1, 2, 3, 4, 5, 0xa, 0x123456, 6, 7, 8, 9];
        let mut read_stack = |addr| stack.get((addr / 8) as usize).copied().ok_or(());

        for (sp, rel_pc) in [
            (0x28, 0xc0db),
            (0x30, 0xc0e0),
            (0x30, 0xc0e6),
            (0x28, 0xc0eb),
        ] {
            let mut regs = UnwindRegsX86_64::new(0x1000000 + rel_pc, sp, 0x345);
            let result = unwinder.unwind_frame(
                FrameAddress::from_instruction_pointer(0x1000000 + rel_pc),
                &mut regs,
                &mut cache,
                &mut read_stack,
            );
            assert_eq!(result, Ok(Some(0x123456)));
            assert_eq!(regs.sp(), 0x38);
            assert_eq!(regs.bp(), 0x345);
        }
    }

    #[test]
    fn pthread_cfa_expr() {
        let mut cache = CacheX86_64::new();
        let mut unwinder = UnwinderX86_64::new();
        add_object(
            &mut unwinder,
            &fixture("x86_64/nofp/libpthread-2.19.so"),
            0x7f54b14fc000,
        );

        let mut stack = vec![0u64; 0x200 / 8];
        stack[0x120 / 8] = 0x1234;
        stack[0x128 / 8] = 0xbe7042;
        let mut read_stack = |addr| stack.get((addr / 8) as usize).copied().ok_or(());
        let mut regs = UnwindRegsX86_64::new(0x7f54b14fc000 + 0x9431, 0x10, 0x120);

        let result = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x7f54b14fc000 + 0x9431),
            &mut regs,
            &mut cache,
            &mut read_stack,
        );
        assert_eq!(result, Ok(Some(0x7f54b14fc000 + 0x9436)));
        assert_eq!(regs.sp(), 0x10);
        assert_eq!(regs.bp(), 0x120);

        let result = unwinder.unwind_frame(
            FrameAddress::from_return_address(0x7f54b14fc000 + 0x9436).unwrap(),
            &mut regs,
            &mut cache,
            &mut read_stack,
        );
        assert_eq!(result, Ok(Some(0x7f54b14fc000 + 0x8c2c)));
        assert_eq!(regs.sp(), 0x90);
        assert_eq!(regs.bp(), 0x120);

        let result = unwinder.unwind_frame(
            FrameAddress::from_return_address(0x7f54b14fc000 + 0x8c2c).unwrap(),
            &mut regs,
            &mut cache,
            &mut read_stack,
        );
        assert_eq!(result, Ok(Some(0xbe7042)));
        assert_eq!(regs.sp(), 0x130);
        assert_eq!(regs.bp(), 0x1234);
    }

    #[test]
    fn signal_trampoline_cfa_expr_with_memory_deref() {
        let mut cache = CacheX86_64::new();
        let mut unwinder = UnwinderX86_64::new();
        add_object(&mut unwinder, &fixture("x86_64/nofp/libc.so.6"), 0);

        let mut stack = vec![0u64; 0x200 / 8];
        stack[0x0f8 / 8] = 0x4567;
        stack[0x120 / 8] = 0x188;
        stack[0x128 / 8] = 0x123456;
        let mut read_stack = |addr| stack.get((addr / 8) as usize).copied().ok_or(());

        let mut regs = UnwindRegsX86_64::new(0x46527, 0x80, 0x9999);
        let result = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x46527),
            &mut regs,
            &mut cache,
            &mut read_stack,
        );
        assert_eq!(result, Ok(Some(0x123456)));
        assert_eq!(regs.sp(), 0x188);
        assert_eq!(regs.bp(), 0x4567);
    }

    #[test]
    fn root_func_x64() {
        let mut cache = CacheX86_64::new();
        let mut unwinder = UnwinderX86_64::new();
        add_object(
            &mut unwinder,
            &fixture("x86_64/nofp/release-firefox-bin"),
            0,
        );

        let mut read_stack = |addr| {
            if addr >= 0x1000 {
                Ok(0x123456)
            } else {
                Err(())
            }
        };

        let mut regs = UnwindRegsX86_64::new(0x88cf2, 0x1000, 0xbeef);
        let result = unwinder.unwind_frame(
            FrameAddress::from_return_address(0x88cf2).unwrap(),
            &mut regs,
            &mut cache,
            &mut read_stack,
        );
        assert_eq!(result, Ok(None));
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64 {
    use super::*;
    use libunwinder::aarch64::{CacheAarch64, UnwindRegsAarch64, UnwinderAarch64};

    #[test]
    fn vdso_without_eh_frame_hdr_uses_frame_pointer_fallback() {
        let mut cache = CacheAarch64::new();
        let mut unwinder = UnwinderAarch64::new();
        add_object(
            &mut unwinder,
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/aarch64/vdso.so"),
            0,
        );

        let stack = [0, 1, 2, 3, 40000, 50000, 6, 7, 80000, 90000];
        let mut regs = UnwindRegsAarch64::new(0x1234, 0x10, 0x20);
        let result = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x5a8),
            &mut regs,
            &mut cache,
            &mut |addr| stack.get((addr / 8) as usize).copied().ok_or(()),
        );

        assert_eq!(result, Ok(Some(50000)));
        assert_eq!(regs.sp(), 0x30);
        assert_eq!(regs.fp(), 40000);
    }
}
