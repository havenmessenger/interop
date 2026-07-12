# VC-01 cross-implementation test vectors - report

`draft-ietf-mls-virtual-clients-01` §5.2 (five-secret derivation), §5.6.1 (Small-Space PRP),
§5.6.2 (reuse_guard compute/recover), §5.6.3 (generation_id), cross-verified between two
independent implementations of the `-01` mechanism.

- Implementation A: this repository, `src/virtual_clients.rs`.
- Implementation B: `openmls/openmls`, commit `f3040aaac59b8c72a9d4e0b7970eefcde9c1dd11`
  (2026-07-07, unreleased; 0.8.1 predates the `virtual-clients-draft` feature).
- Draft anchor: `draft-ietf-mls-virtual-clients-01`, re-verified §-by-§ against the live text the
  same day this vector set was built. No `-02` exists as of this writing.
- Vectors: `tests/vectors/vc-01-vectors.json`, 12 cases across the four categories below.
  Generator: `tools/vc-vectors-xcheck/` (see its README for why it lives outside `mimi-core`'s own
  manifest). CI replay: `tests/vc_vectors_replay.rs`, runs on every `cargo test` at the repo root
  and does not depend on openmls-main.

## Method

Most of the VC-01 surface on openmls's side is `pub(crate)` or module-private
(`EmulatorEpochSecret`, `ReuseGuardSecret`, `GenerationIdSecret`, and `ciphersuite::Secret`
itself; the module `ciphersuite::secret` is not even `pub mod`). Two extraction paths were used.

1. Small-Space PRP (§5.6.1), a direct external call, no patching.
   `openmls_traits::crypto::OpenMlsCrypto::ff1_aes128_encrypt`/`ff1_aes128_decrypt`
   (`traits/src/crypto.rs:206-223`) are trait methods on the public `OpenMlsCrypto` trait,
   implemented by the public `openmls_rust_crypto::OpenMlsRustCrypto` provider
   (`openmls_rust_crypto/src/provider.rs:615-623`, which delegates to `openmls_rust_crypto::ff1::
   encrypt`/`decrypt`). `tools/vc-vectors-xcheck` depends on `openmls_rust_crypto` git-pinned to
   the SHA above (aliased via Cargo's `package =` rename so it coexists with the crates.io
   `openmls_rust_crypto` `mimi-core` already depends on) and calls this live on every run: a
   two-implementation comparison with no source access needed.

2. Everything else (the five §5.2 secrets, the reuse-guard PRP-key derivation, generation_id): a
   temporary, local-only extraction harness. To avoid pushing test scaffolding to another
   project's repository, the extraction code was never pushed anywhere. It is a
   `#[cfg(test)] mod vc_vector_dump { ... }` appended to the end of
   `openmls/src/components/vc_derivation_info.rs` in a throwaway local clone
   (not any tracked repo path). Same-file test code has compiler-level access to
   private and `pub(crate)` items defined in that file, so it can construct
   `EmulatorEpochSecret`/`ReuseGuardSecret`/`GenerationIdSecret` directly from known-plaintext
   secret bytes and print the derived values as hex. Run via:
   ```
   cargo test -p openmls --features test-utils,virtual-clients-draft,virtual-clients-draft-test-dependencies \
     --lib components::vc_derivation_info::vc_vector_dump -- --nocapture
   ```
   The patch is preserved as `tools/vc-vectors-xcheck/openmls-extraction.patch`. Anyone can
   `git apply` it to a fresh clone at the pinned SHA and reproduce the output (see that
   directory's README for the exact command sequence). The local clone was reverted
   (`git checkout -- .`) immediately after the extraction run; nothing from it was committed or
   pushed to openmls/openmls or any fork.

Every extracted value was diffed programmatically against this generator's own live computation
before being embedded as a constant in `tools/vc-vectors-xcheck/src/main.rs`, each guarded by an
`assert_eq!`, so `cargo run` in that directory re-proves every cross-check on every invocation,
not only once at authoring time.

## Results

| Category | Cases | Result | Notes |
|---|---|---|---|
| §5.2 five-secret derivation (`epoch_id`, `epoch_base_secret`, `epoch_encryption_key`, `generation_id_secret`, `reuse_guard_secret`) | 2 (baseline + all-zero-input edge case) | Agree, byte-identical, all 10 values | Confirms that our `expand_with_label`/`derive_secret` (written independently from RFC 9420 §8.1 and the draft's label strings) matches openmls's `Secret::kdf_expand_label`/`derive_secret`, which is openmls's core RFC 9420 key-schedule primitive, used throughout the crate rather than written for VC-01. Two independently written implementations of the KDFLabel/ExpandWithLabel construction agree. |
| §5.6.2 reuse-guard PRP-key derivation (`ExpandWithLabel(reuse_guard_secret, "reuse guard", key_schedule_nonce, 16)`) | 3 (leaf 0, leaf max for a small group, a large power-of-two `N_e` boundary) | Agree, byte-identical, all 3 keys | Same KDFLabel construction, this time with a non-empty (16-33 byte) context. Rules out the empty-context agreement being a coincidence. |
| §5.6.3 `generation_id` (`ExpandWithLabel(generation_id_secret, "generation id", PrivateMessageContext, 32)`) | 2 (generation 0, a skipped generation jumping to 1000) | Agree, byte-identical, both cases | The `PrivateMessageContext` TLS serialization was also compared before the KDF step; both sides produced the same 47-byte `ctx_bytes` for the generation-0 case, confirming the struct field order and types agree independently of the KDF result. |
| §5.6.1 Small-Space PRP (`SmallSpacePRP.Encrypt`/`Decrypt`, FF1-AES128 radix-2) | 5 (0, 1, `u32::MAX`, `2^31-1`, `2^31`) | Diverge, every case, both directions | See below. The only divergence found. |

## The Small-Space PRP divergence

For the same (key, plaintext) pair, our encryption output and openmls's differ on every tested
input, including `plaintext = 0` and `plaintext = 1`. Each side's own `decrypt(encrypt(x)) == x`
round trip holds within itself, which is why neither side's existing unit tests catch the
divergence: both only self-consistency-test, and the draft has no published test-vectors
appendix to check either side against an independent reference. This is the reason for this
vector set.

The two constructions, side by side:

- Ours (`src/virtual_clients.rs`) maps a `u32` to a 32-element bit array by listing bits
  most-significant-first (`(0..32).rev().map(|i| (value >> i) & 1)`), wraps it in `fpe`'s
  `FlexibleNumeralString`, and runs `fpe::ff1::FF1::<Aes128>` with radix 2.
  `FlexibleNumeralString`'s own `num_radix()` is a Horner-method MSB-first reduction
  (`res = res*radix + digit`), which reconstructs the original integer value: the numeral string
  represents `plaintext` per the draft's instruction ("bits from most significant to least
  significant").
- openmls-main (`openmls_rust_crypto/src/ff1.rs`) uses
  `BinaryNumeralString::from_bytes_le(&plaintext.to_be_bytes())`: it feeds the big-endian byte
  representation of `plaintext` into a constructor whose doc comment states it expects
  little-endian byte order, and whose `num_radix()` implementation (`BigUint::from_bytes_le`)
  confirms that contract (byte 0 is the least significant byte).

We confirmed, by running both constructions rather than by reading the doc comments alone, that
they represent different underlying integers for the FF1 core to permute. This is a real,
reproducible divergence, not a test-harness artifact. We tried to identify the transformation
relating the two (a byte-swap of the input, or a full bit-reversal) by testing both against the
`fpe` crate's own `FF1` type; neither hypothesis reproduced openmls's output. The actual
relationship is more intricate than a simple byte or bit reorder, most likely arising from
`BinaryNumeralString::split()`'s half-byte-boundary bit-shuffling (that function carries an
extensive comment on the care needed to keep binary NumeralStrings "big-endian-bit-pattern"
consistent through FF1's Feistel rounds; see `fpe-0.6.1/src/ff1/alloc.rs` lines 200-238). We are
not asserting openmls has a bug: we traced the construction as far as this vector set's scope
allowed and stopped short of a proven root cause rather than publish an unverified claim about
someone else's code.

Classification: spec ambiguity, an interop risk not confidently attributable to either side. The
draft text ("A 32-bit unsigned integer is mapped to a numeral string by listing its bits from
most significant to least significant") is unambiguous about the target semantics, but neither
implementation's test suite, including this one until now, verified against it independently.
Recommendation for the working group or the editor: add an FF1-radix-2 test vector to the draft
(there is currently no official NIST/CAVP radix-2 FF1 vector to check against either), so the two
running implementations that now exist, and any future ones, have a ground truth to converge on
rather than each trusting its own round-trip test. The `fpe`/FF1 MSB-first bit mapping was the
site we expected a divergence to be most likely, before generating any vectors, and it is where
one turned up.

## Reproducing this report

```bash
cd tools/vc-vectors-xcheck
cargo run    # regenerates tests/vectors/vc-01-vectors.json; every openmls_extracted_*
             # comparison is an assert_eq! against constants in src/main.rs, so a silent
             # divergence panics instead of writing a stale file.
cd ../..
cargo test --test vc_vectors_replay   # replays the committed vectors against our own
                                       # implementation only, no openmls-main dependency
```

To independently re-derive the `openmls_extracted_*` constants rather than trust the values
embedded in `main.rs`, see `tools/vc-vectors-xcheck/README.md`, "Reproducing the extraction".
