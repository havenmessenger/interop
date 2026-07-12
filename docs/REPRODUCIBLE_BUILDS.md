# Reproducible Builds - Haven Interop

## Approach
This crate builds a native library and binaries; there is no WASM or web target in this
repo. Reproducibility rests on two pins:
- **Toolchain**, via `rust-toolchain.toml` (`rustc 1.96.0`, `rustfmt` + `clippy`).
- **Dependencies**, via the committed `Cargo.lock`.

## How to verify
```sh
cargo build --release
sha256sum target/release/libmimi_core.rlib target/release/mimi-content

rm -rf target
cargo build --release
sha256sum target/release/libmimi_core.rlib target/release/mimi-content
```
The two `sha256sum` outputs must match. `mimi-hub`'s daemon binary builds the same way from
`mimi-hub/`.

## Status
Verified on `rustc 1.96.0`. A rebuild-and-diff in a clean container (rather than the same
machine's `target/` cache) is the stronger form of this check and is not yet automated in CI.
