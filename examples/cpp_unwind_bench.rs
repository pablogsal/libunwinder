#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod linux_x86_64 {
    use std::error::Error;
    use std::fs;
    use std::hint::black_box;
    use std::ops::Range;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Instant;

    use libunwinder::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};
    use libunwinder::{FrameAddress, MmapBytes, Module, Unwinder};
    use memmap2::MmapOptions;
    use object::{Object, ObjectSegment};

    const SNAPSHOT_MAGIC: u64 = 0x4c55_5742_454e_4348;
    const DEFAULT_ITERS: u64 = 20_000;

    pub fn main() -> Result<(), Box<dyn Error>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("cpp-unwind-bench");
        fs::create_dir_all(&root)?;

        let cxx = std::env::var("CXX").unwrap_or_else(|_| "c++".to_string());
        let iterations = std::env::var("LIBUNWINDER_CPP_BENCH_ITERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_ITERS);

        let workloads = [
            Workload {
                name: "template recursion",
                source_name: "template_recursion.cc",
                body: TEMPLATE_RECURSION,
            },
            Workload {
                name: "STL sort comparator",
                source_name: "stl_sort.cc",
                body: STL_SORT,
            },
            Workload {
                name: "virtual dispatch",
                source_name: "virtual_dispatch.cc",
                body: VIRTUAL_DISPATCH,
            },
        ];

        let mut results = Vec::new();
        for workload in workloads {
            let binary = compile_workload(&root, &cxx, workload)?;
            let snapshot_path = root.join(format!("{}.snapshot", binary_name(workload.name)));
            run_workload(&binary, &snapshot_path)?;
            let snapshot = Snapshot::read(&snapshot_path)?;
            let module = load_module(&binary)?;
            let frames = unwind_stack(&module, &snapshot)?;
            let timing = time_unwind(&module, &snapshot, frames, iterations)?;
            results.push(BenchResult {
                workload: workload.name,
                frames,
                iterations,
                ns_per_unwind: timing.ns_per_unwind,
                ns_per_frame: timing.ns_per_frame,
                frames_per_second: timing.frames_per_second,
            });
        }

        print_markdown(&cxx, iterations, &results);
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct Workload {
        name: &'static str,
        source_name: &'static str,
        body: &'static str,
    }

    struct BenchResult {
        workload: &'static str,
        frames: usize,
        iterations: u64,
        ns_per_unwind: f64,
        ns_per_frame: f64,
        frames_per_second: f64,
    }

    struct Timing {
        ns_per_unwind: f64,
        ns_per_frame: f64,
        frames_per_second: f64,
    }

    struct Snapshot {
        ip: u64,
        sp: u64,
        bp: u64,
        stack_start: u64,
        stack: Vec<u8>,
    }

    impl Snapshot {
        fn read(path: &Path) -> Result<Self, Box<dyn Error>> {
            let bytes = fs::read(path)?;
            if bytes.len() < 48 {
                return Err(format!("snapshot {} is truncated", path.display()).into());
            }
            let magic = read_u64(&bytes, 0)?;
            if magic != SNAPSHOT_MAGIC {
                return Err(format!("snapshot {} has bad magic", path.display()).into());
            }
            let ip = read_u64(&bytes, 8)?;
            let sp = read_u64(&bytes, 16)?;
            let bp = read_u64(&bytes, 24)?;
            let stack_start = read_u64(&bytes, 32)?;
            let stack_len = read_u64(&bytes, 40)? as usize;
            let stack_end = 48usize
                .checked_add(stack_len)
                .ok_or("snapshot length overflow")?;
            if bytes.len() < stack_end {
                return Err(format!("snapshot {} is missing stack bytes", path.display()).into());
            }
            Ok(Self {
                ip,
                sp,
                bp,
                stack_start,
                stack: bytes[48..stack_end].to_vec(),
            })
        }

        fn read_stack(&self, addr: u64) -> Result<u64, ()> {
            let offset = addr.checked_sub(self.stack_start).ok_or(())? as usize;
            let bytes = self
                .stack
                .get(offset..offset.checked_add(8).ok_or(())?)
                .ok_or(())?;
            Ok(u64::from_ne_bytes(bytes.try_into().map_err(|_| ())?))
        }
    }

    struct LoadedModule {
        unwinder: UnwinderX86_64<MmapBytes>,
        avma_range: Range<u64>,
    }

    fn compile_workload(
        root: &Path,
        cxx: &str,
        workload: Workload,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let source = root.join(workload.source_name);
        let binary = root.join(binary_name(workload.name));
        fs::write(&source, format!("{}{}", SNAPSHOT_SUPPORT, workload.body))?;

        let status = Command::new(cxx)
            .args([
                "-std=c++20",
                "-O2",
                "-g",
                "-fomit-frame-pointer",
                "-fno-pie",
                "-no-pie",
                "-fasynchronous-unwind-tables",
                "-fno-optimize-sibling-calls",
                "-pthread",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()?;
        if !status.success() {
            return Err(format!("failed to compile {}", workload.source_name).into());
        }
        Ok(binary)
    }

    fn run_workload(binary: &Path, snapshot_path: &Path) -> Result<(), Box<dyn Error>> {
        let status = Command::new(binary).arg(snapshot_path).status()?;
        if !status.success() {
            return Err(format!("{} exited with {status}", binary.display()).into());
        }
        Ok(())
    }

    fn load_module(binary: &Path) -> Result<LoadedModule, Box<dyn Error>> {
        let file_for_range = fs::File::open(binary)?;
        // SAFETY: this temporary map is read-only and only used to inspect ELF
        // load segments before the module creates its own mmap-backed section views.
        let mmap_for_range = unsafe { MmapOptions::new().map(&file_for_range)? };
        let file = object::File::parse(&mmap_for_range[..])?;
        let avma_range = load_range(&file).ok_or("binary has no loadable segments")?;
        let mut unwinder = UnwinderX86_64::new();
        let module = Module::try_from_mmap_file(binary, avma_range.clone(), 0)?;
        unwinder.add_module(module);
        Ok(LoadedModule {
            unwinder,
            avma_range,
        })
    }

    fn load_range<'data>(file: &impl Object<'data>) -> Option<Range<u64>> {
        let mut start = u64::MAX;
        let mut end = 0u64;
        for segment in file.segments() {
            if segment.size() == 0 {
                continue;
            }
            start = start.min(segment.address());
            end = end.max(segment.address().saturating_add(segment.size()));
        }
        (start < end).then_some(start..end)
    }

    fn unwind_stack(module: &LoadedModule, snapshot: &Snapshot) -> Result<usize, Box<dyn Error>> {
        let mut regs = UnwindRegsX86_64::new(snapshot.ip, snapshot.sp, snapshot.bp);
        let mut cache = CacheX86_64::new();
        let mut frame = FrameAddress::from_instruction_pointer(snapshot.ip);
        let mut frames = 1usize;

        loop {
            let next = {
                let mut read_stack = |addr| snapshot.read_stack(addr);
                module
                    .unwinder
                    .unwind_frame(frame, &mut regs, &mut cache, &mut read_stack)?
            };
            let Some(next_ip) = next else {
                break;
            };
            if !module.avma_range.contains(&next_ip) {
                break;
            }
            frames += 1;
            frame = FrameAddress::from_return_address(next_ip)
                .unwrap_or(FrameAddress::InstructionPointer(next_ip));
            if frames > 256 {
                return Err("unwind produced more than 256 in-module frames".into());
            }
        }

        Ok(frames)
    }

    fn time_unwind(
        module: &LoadedModule,
        snapshot: &Snapshot,
        frames: usize,
        iterations: u64,
    ) -> Result<Timing, Box<dyn Error>> {
        for _ in 0..1000.min(iterations) {
            black_box(unwind_stack(module, snapshot)?);
        }

        let start = Instant::now();
        for _ in 0..iterations {
            black_box(unwind_stack(module, snapshot)?);
        }
        let elapsed = start.elapsed();
        let ns_per_unwind = elapsed.as_nanos() as f64 / iterations as f64;
        let ns_per_frame = ns_per_unwind / frames as f64;
        let frames_per_second = 1_000_000_000.0 / ns_per_frame;

        Ok(Timing {
            ns_per_unwind,
            ns_per_frame,
            frames_per_second,
        })
    }

    fn print_markdown(cxx: &str, iterations: u64, results: &[BenchResult]) {
        println!(
            "Generated with `{cxx}` and {iterations} measured full-stack unwinds per workload.\n"
        );
        println!(
            "| workload | in-module frames | iterations | ns/full unwind | ns/frame | frames/s |"
        );
        println!("| --- | ---: | ---: | ---: | ---: | ---: |");
        for result in results {
            println!(
                "| {} | {} | {} | {:.2} | {:.2} | {:.0} |",
                result.workload,
                result.frames,
                result.iterations,
                result.ns_per_unwind,
                result.ns_per_frame,
                result.frames_per_second
            );
        }
    }

    fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Box<dyn Error>> {
        Ok(u64::from_ne_bytes(
            bytes
                .get(offset..offset + 8)
                .ok_or("missing u64")?
                .try_into()?,
        ))
    }

    fn binary_name(name: &str) -> String {
        name.replace(' ', "-").to_ascii_lowercase()
    }

    const SNAPSHOT_SUPPORT: &str = r#"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <numeric>
#include <pthread.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

static const std::uint64_t SNAPSHOT_MAGIC = 0x4c555742454e4348ULL;
static const char* g_snapshot_path = nullptr;
static volatile std::uint64_t g_sink = 0;

struct SnapshotHeader {
    std::uint64_t magic;
    std::uint64_t ip;
    std::uint64_t sp;
    std::uint64_t bp;
    std::uint64_t stack_start;
    std::uint64_t stack_len;
};

__attribute__((noinline, used))
static void libunwinder_take_snapshot(std::uint64_t checksum) {
    std::uintptr_t ip = 0;
    std::uintptr_t sp = 0;
    std::uintptr_t bp = 0;
    asm volatile(
        "leaq (%%rip), %0\n\t"
        "movq %%rsp, %1\n\t"
        "movq %%rbp, %2\n\t"
        : "=r"(ip), "=r"(sp), "=r"(bp)
        :
        : "memory");

    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) {
        std::abort();
    }

    void* stack_addr = nullptr;
    std::size_t stack_size = 0;
    if (pthread_attr_getstack(&attr, &stack_addr, &stack_size) != 0) {
        std::abort();
    }
    pthread_attr_destroy(&attr);

    std::uintptr_t stack_high =
        reinterpret_cast<std::uintptr_t>(stack_addr) + stack_size;
    sp &= ~static_cast<std::uintptr_t>(7);
    if (sp >= stack_high) {
        std::abort();
    }

    SnapshotHeader header{
        SNAPSHOT_MAGIC,
        static_cast<std::uint64_t>(ip),
        static_cast<std::uint64_t>(sp),
        static_cast<std::uint64_t>(bp),
        static_cast<std::uint64_t>(sp),
        static_cast<std::uint64_t>(stack_high - sp),
    };

    std::FILE* file = std::fopen(g_snapshot_path, "wb");
    if (file == nullptr) {
        std::abort();
    }
    if (std::fwrite(&header, sizeof(header), 1, file) != 1) {
        std::abort();
    }
    if (std::fwrite(reinterpret_cast<void*>(sp), header.stack_len, 1, file) != 1) {
        std::abort();
    }
    std::fclose(file);
    g_sink ^= checksum;
}
"#;

    const TEMPLATE_RECURSION: &str = r#"
template <int N>
__attribute__((noinline))
static std::uint64_t template_chain(std::uint64_t value) {
    if constexpr (N == 0) {
        libunwinder_take_snapshot(value);
        return value + 1;
    } else {
        auto next = template_chain<N - 1>(value + N);
        g_sink += next;
        return next ^ static_cast<std::uint64_t>(N);
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        return 2;
    }
    g_snapshot_path = argv[1];
    auto result = template_chain<14>(7);
    g_sink += result;
    return g_sink == 0 ? 1 : 0;
}
"#;

    const STL_SORT: &str = r#"
struct Record {
    std::string name;
    int key;
    std::vector<int> payload;
};

static bool g_captured = false;

int main(int argc, char** argv) {
    if (argc != 2) {
        return 2;
    }
    g_snapshot_path = argv[1];

    std::vector<Record> records;
    records.reserve(96);
    for (int i = 0; i < 96; ++i) {
        std::vector<int> payload(12);
        std::iota(payload.begin(), payload.end(), i);
        records.push_back({"row-" + std::to_string(i), (i * 37) % 101, std::move(payload)});
    }

    std::sort(records.begin(), records.end(), [](const Record& left, const Record& right) {
        if (!g_captured && ((left.key ^ right.key) & 1) != 0) {
            g_captured = true;
            libunwinder_take_snapshot(static_cast<std::uint64_t>(left.key + right.key));
        }
        if (left.key != right.key) {
            return left.key < right.key;
        }
        return left.name < right.name;
    });

    g_sink += static_cast<std::uint64_t>(records.front().key);
    return g_captured ? 0 : 1;
}
"#;

    const VIRTUAL_DISPATCH: &str = r#"
struct Node {
    virtual ~Node() = default;
    virtual std::uint64_t visit(std::uint64_t seed) = 0;
};

struct Leaf final : Node {
    explicit Leaf(std::uint64_t value) : value(value) {}

    __attribute__((noinline))
    std::uint64_t visit(std::uint64_t seed) override {
        auto checksum = value ^ (seed * 1315423911ULL);
        libunwinder_take_snapshot(checksum);
        g_sink += checksum;
        return checksum;
    }

    std::uint64_t value;
};

struct Branch final : Node {
    Branch(std::unique_ptr<Node> child, std::uint64_t salt)
        : child(std::move(child)), salt(salt) {}

    __attribute__((noinline))
    std::uint64_t visit(std::uint64_t seed) override {
        auto next = child->visit(seed + salt);
        g_sink += next ^ salt;
        return next + salt;
    }

    std::unique_ptr<Node> child;
    std::uint64_t salt;
};

int main(int argc, char** argv) {
    if (argc != 2) {
        return 2;
    }
    g_snapshot_path = argv[1];

    std::unique_ptr<Node> node = std::make_unique<Leaf>(0x51f15eULL);
    for (std::uint64_t i = 1; i <= 10; ++i) {
        node = std::make_unique<Branch>(std::move(node), i * 17);
    }

    auto result = node->visit(11);
    g_sink += result;
    return g_sink == 0 ? 1 : 0;
}
"#;
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux_x86_64::main()
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn main() {
    eprintln!("cpp_unwind_bench currently needs Linux x86_64");
}
