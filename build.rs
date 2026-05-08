use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const BUILD_TOOLS_HELP: &str = "\
libunwinder builds its vendored libunwind with a prepared configure script.
Install a C compiler and make, or build with `--no-default-features --features system-libunwind`
to link against system libunwind instead.";

/// Build vendored libunwind 1.8.1 statically and link it.
///
/// Why vendor: libunwinder feeds libunwind a pre-parsed
/// `dwarf_cie_info_t` (a libunwind-internal type whose layout has
/// changed across versions). Vendoring pins the layout so our Rust
/// `DwarfCieInfo` struct matches exactly.
fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor_src = manifest_dir.join("vendor").join("libunwind-dist");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build_dir = out_dir.join("libunwind-build");
    let install_dir = out_dir.join("libunwind-install");

    println!("cargo:rerun-if-changed={}", vendor_src.display());
    println!("cargo:rerun-if-env-changed=LIBUNWIND_NO_VENDOR");
    println!("cargo:rerun-if-env-changed=CC");

    // Allow opting out of the vendored build (e.g., to link the system
    // libunwind for ABI testing). Off by default.
    if use_system_libunwind() {
        println!("cargo:warning=linking system libunwind");
        println!("cargo:rustc-link-lib=unwind-generic");
        println!("cargo:rustc-link-lib=unwind");
        return;
    }

    if !vendor_src.join("configure").is_file() {
        panic!(
            "prepared vendored libunwind source missing at {}. \
             The crate package must include vendor/libunwind-dist with generated configure files.",
            vendor_src.display()
        );
    }

    require_program("make");
    require_c_compiler();

    std::fs::create_dir_all(&build_dir).expect("create build dir");
    std::fs::create_dir_all(&install_dir).expect("create install dir");

    if !build_dir.join("Makefile").exists() {
        let configure = vendor_src.join("configure");
        run_in(
            &build_dir,
            "sh",
            &[
                configure.to_str().unwrap(),
                "--enable-static",
                "--disable-shared",
                "--disable-documentation",
                "--disable-coredump",
                "--disable-ptrace",
                "--disable-setjmp",
                "--disable-tests",
                "--disable-minidebuginfo",
                "--disable-zlibdebuginfo",
                &format!("--prefix={}", install_dir.display()),
                "CFLAGS=-fPIC -O2 -g",
            ],
        );
    }

    run_in(&build_dir, "make", &["-j", &num_jobs()]);
    run_in(&build_dir, "make", &["install"]);

    let lib_dir = install_dir.join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // Order matters: arch-specific lib references symbols in the generic
    // lib and in libunwind-dwarf-*.
    #[cfg(target_arch = "x86_64")]
    println!("cargo:rustc-link-lib=static=unwind-x86_64");
    #[cfg(target_arch = "aarch64")]
    println!("cargo:rustc-link-lib=static=unwind-aarch64");
    println!("cargo:rustc-link-lib=static=unwind");
}

fn use_system_libunwind() -> bool {
    env::var_os("CARGO_FEATURE_SYSTEM_LIBUNWIND").is_some()
        || env::var_os("CARGO_FEATURE_VENDORED").is_none()
        || env::var_os("LIBUNWIND_NO_VENDOR").is_some()
}

fn require_program(program: &str) {
    if command_succeeds(program) {
        return;
    }

    panic!("required build tool `{program}` was not found. {BUILD_TOOLS_HELP}");
}

fn require_c_compiler() {
    if let Some(cc) = env::var_os("CC") {
        let cc = cc.to_string_lossy();
        let program = cc.split_whitespace().next().unwrap_or("");
        if !program.is_empty() && command_succeeds(program) {
            return;
        }
        panic!("C compiler from CC={cc:?} was not found. {BUILD_TOOLS_HELP}");
    }

    if ["cc", "gcc", "clang"]
        .iter()
        .any(|candidate| command_succeeds(candidate))
    {
        return;
    }

    panic!("no C compiler found. {BUILD_TOOLS_HELP}");
}

fn command_succeeds(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn run_in(dir: &Path, program: &str, args: &[&str]) {
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {program}: {e}. {BUILD_TOOLS_HELP}"));
    if !status.success() {
        panic!(
            "{} {} failed with {}. {}",
            program,
            args.join(" "),
            status,
            BUILD_TOOLS_HELP
        );
    }
}

fn num_jobs() -> String {
    env::var("NUM_JOBS").unwrap_or_else(|_| "4".to_string())
}
