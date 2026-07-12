//! CI replay test for the committed vector set at `tests/vectors/vc-01-vectors.json`
//! (draft-ietf-mls-virtual-clients-01 §5.2/§5.6.1-.3), produced by `tools/vc-vectors-xcheck` and
//! cross-verified against openmls-main. See `docs/vc-01-vector-report.md` for the pinned commit
//! and the method. This test has no dependency on openmls-main: it replays every vector through
//! this crate's own `mimi_core::virtual_clients` functions and asserts the recorded `ours_*`
//! values still match, catching a regression without the git-pinned cross-check dependency in
//! this crate's manifest (`scripts/check_manifest_purity.py`).

use mimi_core::virtual_clients::{
    compute_generation_id, derive_epoch_secrets, expand_with_label, small_space_prp_decrypt,
    small_space_prp_encrypt, RatchetType,
};
use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
use serde::Deserialize;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

const VECTORS_JSON: &str = include_str!("vectors/vc-01-vectors.json");

#[derive(Deserialize)]
struct EpochSecretsVector {
    case: String,
    emulator_epoch_secret_hex: String,
    epoch_id_hex: String,
    epoch_base_secret_hex: String,
    epoch_encryption_key_hex: String,
    generation_id_secret_hex: String,
    reuse_guard_secret_hex: String,
}

#[derive(Deserialize)]
struct PrpVector {
    case: String,
    key_hex: String,
    plaintext: u32,
    ours_ciphertext: u32,
    ours_decrypt_roundtrip: u32,
}

#[derive(Deserialize)]
struct ReuseGuardVector {
    case: String,
    reuse_guard_secret_hex: String,
    key_schedule_nonce_hex: String,
    n_e: u32,
    x: u32,
    ours_prp_key_hex: String,
    ours_reuse_guard_hex: String,
    ours_recovered_leaf_index: u32,
}

#[derive(Deserialize)]
struct GenerationIdVector {
    case: String,
    generation_id_secret_hex: String,
    group_id_hex: String,
    epoch: u64,
    generation: u32,
    ours_generation_id_hex: String,
}

#[derive(Deserialize)]
struct VectorFile {
    ciphersuite: String,
    epoch_secrets: Vec<EpochSecretsVector>,
    small_space_prp: Vec<PrpVector>,
    reuse_guard: Vec<ReuseGuardVector>,
    generation_id: Vec<GenerationIdVector>,
}

fn decode(s: &str) -> Vec<u8> {
    hex::decode(s).expect("vector field is not valid hex")
}

#[test]
fn vc01_vectors_replay_against_our_own_implementation() {
    let file: VectorFile = serde_json::from_str(VECTORS_JSON).expect("parse vc-01-vectors.json");
    assert_eq!(
        file.ciphersuite, "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "vector file pinned to an unexpected ciphersuite"
    );

    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let crypto = provider.crypto();

    for v in &file.epoch_secrets {
        let secret = decode(&v.emulator_epoch_secret_hex);
        let derived = derive_epoch_secrets(crypto, SUITE, &secret)
            .unwrap_or_else(|e| panic!("{}: derive_epoch_secrets failed: {e}", v.case));
        assert_eq!(
            hex::encode(&derived.epoch_id),
            v.epoch_id_hex,
            "{}: epoch_id",
            v.case
        );
        assert_eq!(
            hex::encode(&derived.epoch_base_secret),
            v.epoch_base_secret_hex,
            "{}: epoch_base_secret",
            v.case
        );
        assert_eq!(
            hex::encode(&derived.epoch_encryption_key),
            v.epoch_encryption_key_hex,
            "{}: epoch_encryption_key",
            v.case
        );
        assert_eq!(
            hex::encode(&derived.generation_id_secret),
            v.generation_id_secret_hex,
            "{}: generation_id_secret",
            v.case
        );
        assert_eq!(
            hex::encode(&derived.reuse_guard_secret),
            v.reuse_guard_secret_hex,
            "{}: reuse_guard_secret",
            v.case
        );
    }

    for v in &file.small_space_prp {
        let key: [u8; 16] = decode(&v.key_hex)
            .try_into()
            .expect("prp key must be 16 bytes");
        let ct = small_space_prp_encrypt(&key, v.plaintext)
            .unwrap_or_else(|e| panic!("{}: encrypt failed: {e}", v.case));
        assert_eq!(ct, v.ours_ciphertext, "{}: ciphertext", v.case);
        let pt = small_space_prp_decrypt(&key, ct)
            .unwrap_or_else(|e| panic!("{}: decrypt failed: {e}", v.case));
        assert_eq!(pt, v.plaintext, "{}: round-trip", v.case);
        assert_eq!(
            pt, v.ours_decrypt_roundtrip,
            "{}: recorded round-trip",
            v.case
        );
    }

    for v in &file.reuse_guard {
        let secret = decode(&v.reuse_guard_secret_hex);
        let nonce = decode(&v.key_schedule_nonce_hex);
        let prp_key = expand_with_label(crypto, SUITE, &secret, "reuse guard", &nonce, 16)
            .unwrap_or_else(|e| panic!("{}: prp key derivation failed: {e}", v.case));
        assert_eq!(
            hex::encode(&prp_key),
            v.ours_prp_key_hex,
            "{}: prp_key",
            v.case
        );
        let key: [u8; 16] = prp_key.try_into().expect("prp key must be 16 bytes");
        let guard = small_space_prp_encrypt(&key, v.x)
            .unwrap_or_else(|e| panic!("{}: reuse guard encrypt failed: {e}", v.case));
        assert_eq!(
            hex::encode(guard.to_be_bytes()),
            v.ours_reuse_guard_hex,
            "{}: reuse_guard",
            v.case
        );
        let recovered = small_space_prp_decrypt(&key, guard)
            .unwrap_or_else(|e| panic!("{}: reuse guard decrypt failed: {e}", v.case))
            % v.n_e;
        assert_eq!(
            recovered, v.ours_recovered_leaf_index,
            "{}: recovered leaf index",
            v.case
        );
    }

    for v in &file.generation_id {
        let secret = decode(&v.generation_id_secret_hex);
        let group_id = decode(&v.group_id_hex);
        let gid = compute_generation_id(
            crypto,
            SUITE,
            &secret,
            &group_id,
            v.epoch,
            v.generation,
            RatchetType::Application,
        )
        .unwrap_or_else(|e| panic!("{}: compute_generation_id failed: {e}", v.case));
        assert_eq!(
            hex::encode(&gid),
            v.ours_generation_id_hex,
            "{}: generation_id",
            v.case
        );
    }
}
