# libunwinder

`libunwinder` is a native Linux stack unwinding crate backed by vendored
`libunwind`. Its job is to answer "who called me?" without making your profiler
drag a whole crash dump filing cabinet around.

The API is intentionally small and Rust-oriented, because the stack is already
dramatic enough. Callers register loaded modules with their unwind sections,
provide register state plus a stack-read callback, and recover one caller frame
at a time. It targets the profiler use case and does not claim Mach-O/PE
support, cross-architecture unwinding, no-std operation, or no-allocation
unwinding.

By default the build script compiles the prepared `vendor/libunwind-dist`
snapshot statically. The vendored snapshot is pinned to libunwind `v1.8.1`
because the Rust FFI mirrors an internal libunwind C struct whose layout is
version-sensitive.

The default build needs only a C compiler, `sh`, and `make`; it does not run
`autoreconf`, download sources, or require a checked-out Git submodule. For ABI
experiments or distro builds, link system libunwind instead:

```sh
cargo build --no-default-features --features system-libunwind
```

The legacy `LIBUNWIND_NO_VENDOR=1` environment variable does the same thing.

Maintainers bumping the vendored libunwind version should follow
[docs/bumping-libunwind.md](docs/bumping-libunwind.md).

## API example

The low-friction path is intentionally adapter-friendly:

```rust
use libunwinder::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};
use libunwinder::{ExplicitModuleSectionInfo, FrameAddress, Module, Unwinder};

let module = Module::new(name, avma_range, base_avma, ExplicitModuleSectionInfo {
    base_svma,
    text_svma,
    text,
    eh_frame_svma,
    eh_frame,
    eh_frame_hdr_svma,
    eh_frame_hdr,
    ..Default::default()
});

let mut unwinder = UnwinderX86_64::new();
let mut cache = CacheX86_64::new();
unwinder.add_module(module);

let mut regs = UnwindRegsX86_64::new(rip, rsp, rbp);
let next = unwinder.unwind_frame(
    FrameAddress::from_instruction_pointer(rip),
    &mut regs,
    &mut cache,
    &mut read_stack,
)?;
```

`Module::new` is forgiving: missing or unsupported unwind sections produce a
module that can still use frame-pointer fallback. For strict loading,
`Module::from_dwarf_sections(DwarfModuleSections<_>)` and
`Module::try_from_section_info(...)` return `ModuleError` with exact missing or
malformed-section causes.

For ELF files on disk, prefer `Module::from_mmap_file(...)` or
`Module::try_from_mmap_file(...)`. These map the object read-only and keep
`.eh_frame` / `.eh_frame_hdr` as mmap-backed byte ranges instead of copying
large unwind sections into heap buffers.

Unwind failures are structured. `Error::CouldNotReadStack(addr)` carries the
failing stack address, `Error::Libunwind(err)` includes the libunwind phase and
decoded status code, and `Error::UnwindInfo(err)` reports the exact fast-path
`.eh_frame` / `.eh_frame_hdr` parse or lookup failure.

## Benchmarks

For the small in-tree microbenchmark, run:

```sh
cargo bench --bench unwind
```

Reference run environment for the numbers below:

| item | value |
| --- | --- |
| CPU | Intel Core i9-14900KS |
| OS/kernel | Linux 7.0.3-1-cachyos x86_64 |
| Rust | rustc 1.94.0 |
| C++ compiler | GCC 16.1.1 |

On that host, the in-tree benchmark reports about 11.07 ns/frame for
frame-pointer fallback and 272.50 ns/frame for the Linux `.eh_frame` fixture
path. Treat these as reference measurements for this setup, not portable
throughput guarantees.

For a less toy-shaped benchmark, run:

```sh
LIBUNWINDER_CPP_BENCH_ITERS=100000 cargo run --release --example cpp_unwind_bench
```

That driver writes three C++20 programs into `target/cpp-unwind-bench`, compiles
them with GCC 16.1.1 using `-O2 -fomit-frame-pointer -fasynchronous-unwind-tables`
and friends, captures real register/stack snapshots from inside the running
programs, then repeatedly unwinds those captured stacks.

Measured on the reference host above:

| workload | in-module frames | iterations | ns/full unwind | ns/frame | frames/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| template recursion | 17 | 100000 | 3828.20 | 225.19 | 4440731 |
| STL sort comparator | 3 | 100000 | 1357.13 | 452.38 | 2210547 |
| virtual dispatch | 13 | 100000 | 6472.30 | 497.87 | 2008561 |

Rerun the driver on the machine you care about before comparing absolute
throughput numbers.
