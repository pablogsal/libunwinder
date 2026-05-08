# libunwinder fuzz targets

Fuzz harnesses for the DWARF parser. Driven by `cargo-fuzz` + libFuzzer.

## Setup

```sh
cargo install cargo-fuzz
rustup toolchain install nightly
```

## Run the `dwarf` target

From the repository root:

```sh
cargo +nightly fuzz run dwarf
```

The harness exercises `parse_cie` and `parse_fde` with attacker-controlled
bytes via the `__fuzz` feature gate (internal API, no stability guarantees).

To replay a crash artifact:

```sh
cargo +nightly fuzz run dwarf fuzz/artifacts/dwarf/<id>
```

Coverage:

```sh
cargo +nightly fuzz coverage dwarf
```
