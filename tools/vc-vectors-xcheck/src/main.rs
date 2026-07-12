//! Cross-implementation vector generator for draft-ietf-mls-virtual-clients-01 §5.2/§5.6.1-.3.
//! Not part of the interop repo's own manifest; see the crate's README for why.
//!
//! Computes each vector via this crate's own `mimi_core::virtual_clients` functions, plus a
//! direct cross-implementation check of the Small-Space PRP (§5.6.1) by calling openmls-main's
//! `OpenMlsCrypto::ff1_aes128_encrypt`/`ff1_aes128_decrypt` (pinned commit, `virtual-clients-draft`
//! feature). That function is externally callable, a public trait method, unlike the rest of
//! openmls's VC surface (`pub(crate)`). See `docs/vc-01-vector-report.md` in the interop repo for
//! the extraction method used for the `pub(crate)`-blocked values: the five §5.2 secrets, the
//! reuse-guard PRP-key derivation, and generation_id.

use mimi_core::virtual_clients::{
    compute_generation_id, derive_epoch_secrets, expand_with_label, small_space_prp_decrypt,
    small_space_prp_encrypt, RatchetType,
};
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use openmls_traits_vc::{
    crypto::OpenMlsCrypto as OpenMlsCryptoVc, OpenMlsProvider as OpenMlsProviderVc,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Deterministic seed bytes: SHA-256 of a fixed ASCII string plus a case index, so re-running this
/// generator gets byte-identical inputs with no RNG state to transport.
fn seed(case_index: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"vc-01-vector-seed");
    hasher.update([case_index]);
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[derive(Serialize)]
struct EpochSecretsVector {
    case: &'static str,
    emulator_epoch_secret_hex: String,
    epoch_id_hex: String,
    epoch_base_secret_hex: String,
    epoch_encryption_key_hex: String,
    generation_id_secret_hex: String,
    reuse_guard_secret_hex: String,
    openmls_extracted_epoch_id_hex: String,
    openmls_extracted_epoch_base_secret_hex: String,
    openmls_extracted_epoch_encryption_key_hex: String,
    openmls_extracted_generation_id_secret_hex: String,
    openmls_extracted_reuse_guard_secret_hex: String,
}

#[derive(Serialize)]
struct PrpVector {
    case: &'static str,
    key_hex: String,
    plaintext: u32,
    ours_ciphertext: u32,
    openmls_ciphertext: u32,
    ours_decrypt_roundtrip: u32,
    openmls_decrypt_roundtrip: u32,
}

#[derive(Serialize)]
struct ReuseGuardVector {
    case: &'static str,
    reuse_guard_secret_hex: String,
    key_schedule_nonce_hex: String,
    n_e: u32,
    leaf_index_e: u32,
    /// x = high_bits | leaf_index_e - the pre-PRP value; fixed here (not OS-random) for
    /// reproducibility, matching what `compute_reuse_guard` would construct internally.
    x: u32,
    ours_prp_key_hex: String,
    openmls_prp_key_hex: String,
    ours_reuse_guard_hex: String,
    openmls_reuse_guard_hex: String,
    ours_recovered_leaf_index: u32,
    openmls_recovered_leaf_index: u32,
}

#[derive(Serialize)]
struct GenerationIdVector {
    case: &'static str,
    generation_id_secret_hex: String,
    group_id_hex: String,
    epoch: u64,
    generation: u32,
    ratchet_type: &'static str,
    ours_generation_id_hex: String,
    openmls_extracted_generation_id_hex: String,
}

#[derive(Serialize)]
struct VectorFile {
    format_version: u32,
    ciphersuite: &'static str,
    openmls_main_pinned_sha: &'static str,
    epoch_secrets: Vec<EpochSecretsVector>,
    small_space_prp: Vec<PrpVector>,
    reuse_guard: Vec<ReuseGuardVector>,
    generation_id: Vec<GenerationIdVector>,
}

fn main() {
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let crypto = provider.crypto();

    // ---- §5.2: five-secret derivation, 2 cases ----
    // openmls_extracted_* values were produced by the ONE-TIME local extraction harness
    // (`openmls-extraction.patch`, applied to openmls-main at the pinned SHA, run via
    // `cargo test -p openmls --features test-utils,virtual-clients-draft,virtual-clients-draft-test-dependencies
    //  --lib components::vc_derivation_info::vc_vector_dump -- --nocapture`) - see
    // docs/vc-01-vector-report.md for the full method and the raw run transcript. Every value below
    // was verified byte-for-byte against this generator's own `ours_*` output before being embedded.
    let mut epoch_secrets = Vec::new();
    for (case, idx, extracted) in [
        (
            "case_a_baseline",
            1u8,
            [
                "30c26fe937485f2ee1d6f8f8277a54583a9b309dd8f3f9a8d94639f8cacb7e2c",
                "b03c9f660a4f3d4465f461c8dd54dc89efa81fbdd773a8bf65a7b23c088e74f0",
                "7c42e064ded5eec211eed343670f214590968906f78e7c30976953d65f73caad",
                "c1b453f2ed99a4732036f8cb3dcb1b4a4f3511b17fd699f597940b7ed3dffba8",
                "3b5b6592cffcb1df2f80f3046290aa3d1c0934cd39c01d53e7cdc07b26c46164",
            ],
        ),
        (
            "case_b_all_zero_secret",
            2u8,
            [
                "1a9ab89a4c150c72b11a5dbe58c67e3a4cededd0cdf4494b9fda3e715e0f2785",
                "55225e87343f5de990eae88049ebe252c6d0c895cafefac7d71f6be3f3d9c058",
                "7f604f18e1adcb574706a314e504fbe0315bbe541085fd828232fa23f3c308b8",
                "7714916d5d933ffb63a7b7ed7533731d43019317944f7ac5095431b749dd57c2",
                "2d3e55fae17893df3329a8a296a308335dcb741f9cc2c4c44a0833e9aab5b1a7",
            ],
        ),
    ] {
        let emulator_epoch_secret = if idx == 2 {
            [0u8; 32] // all-zero edge input, distinct from the SHA-derived "random-looking" baseline
        } else {
            seed(idx)
        };
        let secrets = derive_epoch_secrets(crypto, SUITE, &emulator_epoch_secret)
            .expect("derive_epoch_secrets");
        assert_eq!(
            hex(&secrets.epoch_id),
            extracted[0],
            "{case}: epoch_id cross-check"
        );
        assert_eq!(
            hex(&secrets.epoch_base_secret),
            extracted[1],
            "{case}: epoch_base_secret cross-check"
        );
        assert_eq!(
            hex(&secrets.epoch_encryption_key),
            extracted[2],
            "{case}: epoch_encryption_key cross-check"
        );
        assert_eq!(
            hex(&secrets.generation_id_secret),
            extracted[3],
            "{case}: generation_id_secret cross-check"
        );
        assert_eq!(
            hex(&secrets.reuse_guard_secret),
            extracted[4],
            "{case}: reuse_guard_secret cross-check"
        );
        epoch_secrets.push(EpochSecretsVector {
            case,
            emulator_epoch_secret_hex: hex(&emulator_epoch_secret),
            epoch_id_hex: hex(&secrets.epoch_id),
            epoch_base_secret_hex: hex(&secrets.epoch_base_secret),
            epoch_encryption_key_hex: hex(&secrets.epoch_encryption_key),
            generation_id_secret_hex: hex(&secrets.generation_id_secret),
            reuse_guard_secret_hex: hex(&secrets.reuse_guard_secret),
            openmls_extracted_epoch_id_hex: extracted[0].to_string(),
            openmls_extracted_epoch_base_secret_hex: extracted[1].to_string(),
            openmls_extracted_epoch_encryption_key_hex: extracted[2].to_string(),
            openmls_extracted_generation_id_secret_hex: extracted[3].to_string(),
            openmls_extracted_reuse_guard_secret_hex: extracted[4].to_string(),
        });
    }

    // ---- §5.6.1: Small-Space PRP domain-boundary round trips, 5 cases ----
    let prp_key: [u8; 16] = seed(10)[..16].try_into().unwrap();
    let mut small_space_prp = Vec::new();
    for (case, plaintext) in [
        ("input_zero", 0u32),
        ("input_one", 1u32),
        ("input_max", u32::MAX),
        ("input_2pow31_minus_1", (1u32 << 31) - 1),
        ("input_2pow31", 1u32 << 31),
    ] {
        let ours_ct = small_space_prp_encrypt(&prp_key, plaintext).expect("ours encrypt");
        let ours_rt = small_space_prp_decrypt(&prp_key, ours_ct).expect("ours decrypt");
        let openmls_ct = crypto_vc()
            .ff1_aes128_encrypt(&prp_key, plaintext)
            .expect("openmls ff1 encrypt");
        let openmls_rt = crypto_vc()
            .ff1_aes128_decrypt(&prp_key, openmls_ct)
            .expect("openmls ff1 decrypt");
        small_space_prp.push(PrpVector {
            case,
            key_hex: hex(&prp_key),
            plaintext,
            ours_ciphertext: ours_ct,
            openmls_ciphertext: openmls_ct,
            ours_decrypt_roundtrip: ours_rt,
            openmls_decrypt_roundtrip: openmls_rt,
        });
    }

    // ---- §5.6.2: reuse_guard compute/recover, 2 cases (leaf_index=0 / leaf_index=max for small N_e,
    //      plus one large power-of-two N_e boundary) ----
    let mut reuse_guard = Vec::new();
    // (case, n_e, leaf_index_e, secret_idx, nonce_idx, openmls_extracted_prp_key, openmls_extracted_reuse_guard)
    // openmls_extracted_* from the same one-time extraction run (see docs/vc-01-vector-report.md).
    for (case, n_e, leaf_index_e, secret_idx, nonce_idx, ext_prp_key, ext_guard) in [
        (
            "leaf_index_zero_small_group",
            4u32,
            0u32,
            20u8,
            40u8,
            "e7a96240c558a9e9b3c73cdc2db5504f",
            "6ec8e615",
        ),
        (
            "leaf_index_max_small_group",
            4u32,
            3u32,
            21u8,
            41u8,
            "718ed2c5de6c38fb1a8c2871ea2d05b2",
            "e3dcf271",
        ),
        (
            "large_power_of_two_boundary",
            1u32 << 16,
            (1u32 << 16) - 1,
            22u8,
            42u8,
            "aacc5caa7c94b894836a09edd9ac01c7",
            "aa497bdb",
        ),
    ] {
        let reuse_guard_secret = seed(secret_idx);
        let key_schedule_nonce = seed(nonce_idx);
        let log2_n_e = n_e.trailing_zeros();
        // x construction mirrors compute_reuse_guard's internal logic but with a FIXED (not
        // OS-random) high-bits pattern for reproducibility: high_bits = 0xA5A5_A5A5 truncated/shifted.
        let high_bits = if log2_n_e >= 32 {
            0
        } else {
            0xA5A5_A5A5u32 << log2_n_e
        };
        let x = high_bits | leaf_index_e;

        let ours_prp_key = expand_with_label(
            crypto,
            SUITE,
            &reuse_guard_secret,
            "reuse guard",
            &key_schedule_nonce,
            16,
        )
        .expect("ours prp key");
        let ours_guard =
            small_space_prp_encrypt(&ours_prp_key, x).expect("ours reuse guard encrypt");
        let ours_recovered =
            small_space_prp_decrypt(&ours_prp_key, ours_guard).expect("ours decrypt") % n_e;

        // openmls's PRP-key derivation for reuse_guard is pub(crate) (ReuseGuardSecret::derive_prp_key).
        // The prp_key cross-check below is a two-implementation match: both KDFLabel/ExpandWithLabel
        // constructions were extracted separately and agree. The reuse_guard value does not match;
        // see docs/vc-01-vector-report.md for the Small-Space PRP divergence this generator found.
        assert_eq!(
            hex(&ours_prp_key),
            ext_prp_key,
            "{case}: prp_key cross-check"
        );
        reuse_guard.push(ReuseGuardVector {
            case,
            reuse_guard_secret_hex: hex(&reuse_guard_secret),
            key_schedule_nonce_hex: hex(&key_schedule_nonce),
            n_e,
            leaf_index_e,
            x,
            ours_prp_key_hex: hex(&ours_prp_key),
            openmls_prp_key_hex: ext_prp_key.to_string(),
            ours_reuse_guard_hex: hex(&ours_guard.to_be_bytes()),
            openmls_reuse_guard_hex: ext_guard.to_string(),
            ours_recovered_leaf_index: ours_recovered,
            openmls_recovered_leaf_index: leaf_index_e, // by construction; extraction confirms openmls side
        });
    }

    // ---- §5.6.3: generation_id, generation-0 + skipped-generation cases ----
    let mut generation_id = Vec::new();
    // openmls_extracted_generation_id from the same one-time extraction run (report has the
    // ctx_bytes-level cross-check confirming both TLS serializations of PrivateMessageContext
    // agree byte-for-byte before the KDF step even runs).
    for (case, generation, secret_idx, group_idx, ext_gid) in [
        (
            "generation_zero",
            0u32,
            30u8,
            50u8,
            "2f64b25e65fb0350d2318bf82664b432ab0bb9b5e455aafebc44e1101a5d5bc1",
        ),
        (
            "generation_skipped_to_1000",
            1000u32,
            31u8,
            51u8,
            "0e60973cf7a33d9a7db6e34852d6c8e0e6bc008eaf3f9aafbe19eeb9b7885b67",
        ),
    ] {
        let generation_id_secret = seed(secret_idx);
        let group_id = seed(group_idx);
        let epoch = 7u64;
        let gid = compute_generation_id(
            crypto,
            SUITE,
            &generation_id_secret,
            &group_id,
            epoch,
            generation,
            RatchetType::Application,
        )
        .expect("ours generation_id");
        assert_eq!(hex(&gid), ext_gid, "{case}: generation_id cross-check");
        generation_id.push(GenerationIdVector {
            case,
            generation_id_secret_hex: hex(&generation_id_secret),
            group_id_hex: hex(&group_id),
            epoch,
            generation,
            ratchet_type: "application",
            ours_generation_id_hex: hex(&gid),
            openmls_extracted_generation_id_hex: ext_gid.to_string(),
        });
    }

    let out = VectorFile {
        format_version: 1,
        ciphersuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        openmls_main_pinned_sha: "f3040aaac59b8c72a9d4e0b7970eefcde9c1dd11",
        epoch_secrets,
        small_space_prp,
        reuse_guard,
        generation_id,
    };

    let json = serde_json::to_string_pretty(&out).unwrap();
    // Run from this crate's own directory (`tools/vc-vectors-xcheck/`); writes to the committed
    // vector location at the repo root.
    fs::write("../../tests/vectors/vc-01-vectors.json", &json).expect("write output");
    println!(
        "wrote ../../tests/vectors/vc-01-vectors.json ({} bytes)",
        json.len()
    );
}

/// Small helper: returns the crypto backend (openmls-main pinned `OpenMlsRustCrypto`, aliased crate
/// `openmls_rust_crypto_vc`) implementing `openmls_traits_vc`'s `OpenMlsCrypto` trait.
fn crypto_vc() -> &'static (impl OpenMlsCryptoVc + 'static) {
    use std::sync::OnceLock;
    static P: OnceLock<openmls_rust_crypto_vc::OpenMlsRustCrypto> = OnceLock::new();
    let provider = P.get_or_init(openmls_rust_crypto_vc::OpenMlsRustCrypto::default);
    OpenMlsProviderVc::crypto(provider)
}
