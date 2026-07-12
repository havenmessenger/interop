# vc-vectors-xcheck

Cross-implementation vector generator for `draft-ietf-mls-virtual-clients-01` §5.2 (five-secret
derivation), §5.6.1 (Small-Space PRP), §5.6.2 (reuse_guard compute/recover), and §5.6.3
(generation_id).

Why this is not a normal workspace member: it depends on `openmls-main`, git-pinned to an exact
commit, unreleased `virtual-clients-draft` cargo feature. The repo root's
`scripts/check_manifest_purity.py` guard forbids any non-crates.io dependency in `mimi-core`'s
own `Cargo.lock`; the audited library must resolve entirely from crates.io from a bare checkout.
This tool lives in its own subdirectory with its own `Cargo.toml`/`Cargo.lock`, so
`cargo build`/`cargo test` at the repo root never touches it and the manifest-purity guard stays
green.

## What it does

1. Computes every vector value via this crate's own `mimi_core::virtual_clients` functions.
2. Cross-checks the Small-Space PRP (§5.6.1) live, by calling openmls-main's own
   `OpenMlsCrypto::ff1_aes128_encrypt`/`ff1_aes128_decrypt`. That function is a public trait
   method, unlike the rest of openmls's VC surface (`pub(crate)`), so no patching is needed.
3. Cross-checks everything else (the five §5.2 secrets, the reuse-guard PRP-key derivation,
   generation_id) against values embedded from a one-time, local-only extraction run; see
   `openmls-extraction.patch` below. Every embedded value is asserted (`assert_eq!`) against this
   generator's own live computation at build time, so a future `cargo run` here fails loudly if
   either side's construction drifts.
4. Writes the final vector set to `../../tests/vectors/vc-01-vectors.json`.

Full method, the pinned commit SHA, and the agreement table are in
`../../docs/vc-01-vector-report.md`.

## Reproducing the extraction (the `pub(crate)`-blocked values)

Most of openmls's VC-01 surface (`EmulatorEpochSecret`, `ReuseGuardSecret`, `GenerationIdSecret`,
and `ciphersuite::Secret` itself) is `pub(crate)` or module-private, unreachable from an external
crate regardless of how it is imported. The only way to observe those values is to add temporary,
same-file test code that prints them, run it inside a local clone of openmls, and never push it
upstream. `openmls-extraction.patch` is that code, preserved here so the embedded values can be
re-verified independently:

```bash
git clone https://github.com/openmls/openmls.git /tmp/openmls-main
cd /tmp/openmls-main
git checkout f3040aaac59b8c72a9d4e0b7970eefcde9c1dd11
git apply /path/to/this/openmls-extraction.patch
cargo test -p openmls \
  --features test-utils,virtual-clients-draft,virtual-clients-draft-test-dependencies \
  --lib components::vc_derivation_info::vc_vector_dump -- --nocapture
# compare the printed hex values against tests/vectors/vc-01-vectors.json's
# openmls_extracted_* / openmls_prp_key_hex / openmls_reuse_guard_hex fields.
git checkout -- .   # revert; do not commit or push the patched clone
```

## Regenerating the committed vectors

```bash
cd tools/vc-vectors-xcheck
cargo run
# writes ../../tests/vectors/vc-01-vectors.json; every openmls_extracted_* comparison is an
# assert_eq! against the constants embedded in src/main.rs, so a silent divergence panics
# instead of writing a stale file.
```
