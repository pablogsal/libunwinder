#[cfg(target_arch = "x86_64")]
use std::{hint::black_box, time::Instant};

#[cfg(target_arch = "x86_64")]
use libunwinder::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};
#[cfg(target_arch = "x86_64")]
use libunwinder::{FrameAddress, MmapBytes, Module, Unwinder};

fn main() {
    #[cfg(target_arch = "x86_64")]
    x86_64::run();

    #[cfg(not(target_arch = "x86_64"))]
    println!("no benchmarks configured for this architecture");
}

#[cfg(target_arch = "x86_64")]
fn bench(name: &str, iterations: u64, mut f: impl FnMut()) {
    for _ in 0..10_000.min(iterations) {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    let ns_per_iter = elapsed.as_nanos() as f64 / iterations as f64;
    let iters_per_sec = 1_000_000_000.0 / ns_per_iter;

    println!(
        "{name:<34} {:>10} iters  {:>10.2} ns/iter  {:>10.2} frames/s",
        iterations, ns_per_iter, iters_per_sec
    );
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use super::*;
    use std::path::Path;

    pub fn run() {
        fallback_frame_pointer();
        linux_eh_frame_fixture();
    }

    fn fallback_frame_pointer() {
        let unwinder: UnwinderX86_64<Vec<u8>> = UnwinderX86_64::new();
        let mut cache = CacheX86_64::new();
        let stack = [0, 0, 0, 0, 0x40, 0x1234];
        let mut read_stack = |addr| black_box(stack.get((addr / 8) as usize).copied().ok_or(()));

        bench("x86_64 frame-pointer fallback", 1_000_000, || {
            let mut regs = UnwindRegsX86_64::new(0x1000, 0x10, 0x20);
            let result = unwinder
                .unwind_frame(
                    FrameAddress::from_instruction_pointer(0x1000),
                    &mut regs,
                    &mut cache,
                    &mut read_stack,
                )
                .unwrap();
            assert_eq!(black_box(result), Some(0x1234));
            black_box(regs);
        });
    }

    fn linux_eh_frame_fixture() {
        let mut unwinder = UnwinderX86_64::new();
        add_object(
            &mut unwinder,
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/linux/x86_64/nofp/libpthread-2.19.so"),
            0x7f54b14fc000,
        );

        let mut cache = CacheX86_64::new();
        let mut stack = vec![0u64; 0x200 / 8];
        stack[0x120 / 8] = 0x1234;
        stack[0x128 / 8] = 0xbe7042;
        let mut read_stack = |addr| black_box(stack.get((addr / 8) as usize).copied().ok_or(()));

        bench("x86_64 libunwind .eh_frame", 250_000, || {
            let mut regs = UnwindRegsX86_64::new(0x7f54b14fc000 + 0x9431, 0x10, 0x120);
            let result = unwinder
                .unwind_frame(
                    FrameAddress::from_instruction_pointer(0x7f54b14fc000 + 0x9431),
                    &mut regs,
                    &mut cache,
                    &mut read_stack,
                )
                .unwrap();
            assert_eq!(black_box(result), Some(0x7f54b14fc000 + 0x9436));
            black_box(regs);
        });
    }

    fn add_object<U>(unwinder: &mut U, objpath: &Path, base_avma: u64)
    where
        U: Unwinder<Module = Module<MmapBytes>>,
    {
        let file_len = std::fs::metadata(objpath).unwrap().len();
        let module =
            Module::from_mmap_file(objpath, base_avma..base_avma + file_len, base_avma).unwrap();
        unwinder.add_module(module);
    }
}
