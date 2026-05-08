# Bumping Vendored libunwind

This document is for maintainers updating the libunwind version bundled with
`libunwinder`.

Consumer builds must not run `autoreconf`. The published crate ships a prepared
`vendor/libunwind-dist` tree with generated `configure` files, and `build.rs`
only runs that prepared `configure` script plus `make`.

## Directory Roles

- `vendor/libunwind`: upstream Git submodule, used as the source of truth for
  the selected libunwind tag.
- `vendor/libunwind-dist`: prepared release tree included in the crate package.
  This contains generated autotools files such as `configure`, `Makefile.in`,
  `aclocal.m4`, `config/`, and `m4/`.

Run `autoreconf` only while preparing `vendor/libunwind-dist`; never add it back
to `build.rs`.

## Prerequisites

Install the maintainer-only autotools stack:

```sh
autoconf --version
automake --version
libtoolize --version
make --version
cc --version
```

The exact package names vary by distro. On Debian/Ubuntu, the rough set is
`autoconf automake libtool make build-essential`.

## Update Procedure

Replace `vX.Y.Z` with the target upstream libunwind tag.

```sh
# 1. Update the upstream submodule.
git -C vendor/libunwind fetch --tags
git -C vendor/libunwind checkout vX.Y.Z

# 2. Rebuild the prepared dist tree from the submodule contents.
rm -rf vendor/libunwind-dist
mkdir -p vendor/libunwind-dist
tar \
  --exclude='./.git' \
  --exclude='./.github' \
  --exclude='./autom4te.cache' \
  -cf - -C vendor/libunwind . \
  | tar -xf - -C vendor/libunwind-dist

# 3. Generate autotools outputs in the dist tree only.
cd vendor/libunwind-dist
autoreconf -fi
cd ../..

# 4. Stage both the submodule pointer and the prepared dist tree.
git add vendor/libunwind
git add -A vendor/libunwind-dist
git add -f vendor/libunwind-dist
```

The final `git add -f` is intentional. libunwind's own `.gitignore` ignores
generated files like `configure` and `Makefile.in`, but those files are required
for consumer builds.

## Required Checks

First confirm the generated files are present:

```sh
test -x vendor/libunwind-dist/configure
test -f vendor/libunwind-dist/Makefile.in
test -f vendor/libunwind-dist/src/Makefile.in
test -d vendor/libunwind-dist/config
test -d vendor/libunwind-dist/m4
```

Then check the package contents:

```sh
cargo package --allow-dirty --list \
  | rg 'vendor/libunwind-dist/(configure$|Makefile\.in$|config/ltmain\.sh|m4/libtool\.m4)'

cargo package --allow-dirty --list \
  | rg '^vendor/libunwind/' && false || true
```

The first command should print generated files from `vendor/libunwind-dist`.
The second command should print nothing; the crate package should not include
the upstream submodule path `vendor/libunwind/`.

## ABI Compatibility Check

`libunwinder` passes a Rust-built copy of libunwind's internal
`dwarf_cie_info_t` to libunwind. This is intentionally not a public libunwind
ABI, so every bump must compare these two definitions:

- `vendor/libunwind-dist/include/dwarf.h`: `typedef struct dwarf_cie_info`
- `src/ffi/types.rs`: `pub struct DwarfCieInfo`

The field order, integer widths, and bitfield packing must match. If upstream
adds, removes, or reorders fields, update `DwarfCieInfo` and the code that
builds it before publishing.

Use this quick locator:

```sh
rg -n 'typedef struct dwarf_cie_info|dwarf_cie_info_t|pub struct DwarfCieInfo' \
  vendor/libunwind-dist/include/dwarf.h src/ffi/types.rs
```

## Build Verification

Run the normal test and package matrix:

```sh
cargo fmt --check
cargo test
cargo check --no-default-features --features system-libunwind
cargo package --allow-dirty
cargo publish --dry-run --allow-dirty
```

The package verification step builds from the `.crate` archive, so it is the
best local simulation of a consumer install.

## Release Notes

When committing the bump, include:

- old and new libunwind tags;
- whether `DwarfCieInfo` changed;
- the packaged crate size from `cargo package`;
- the verification commands that passed.

