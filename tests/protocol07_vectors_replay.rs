//! Replays the committed protocol-07 wire vectors at `tests/vectors/protocol07-vectors.json` (§5.2 `KeyMaterialResponse`,
//! §5.3 `HandshakeBundle`) through the public codec: every `ok` vector decodes, names the variant recorded for it and encodes
//! back to the same bytes; every `refused` vector is refused. The vectors are laid out field by field by
//! `examples/gen_protocol07_vectors.rs` and not by this crate's encoders, so they also serve as the input a second
//! implementation decodes.

use mimi_core::gate::{mimi_gate_keypackage, MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519};
use mimi_core::protocol_wire::{HandshakeBundle, KeyMaterialResponse, UpdateRoomResponse};
use serde::Deserialize;

/// The vectors' KeyPackages are checked against a gate that accepts 0x0001 only.
const ONLY_AES: &[u16] = &[MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519];

const VECTORS_JSON: &str = include_str!("vectors/protocol07-vectors.json");

#[derive(Deserialize)]
struct Vectors {
    format_version: u32,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    kind: String,
    hex: String,
    decode: String,
    variant: Option<String>,
}

fn key_material_variant(response: &KeyMaterialResponse) -> &'static str {
    match response {
        KeyMaterialResponse::Success { .. } => "Success",
        KeyMaterialResponse::Exhausted { .. } => "Exhausted",
        KeyMaterialResponse::Denied { .. } => "Denied",
        KeyMaterialResponse::Clients { .. } => "Clients",
    }
}

fn bundle_variant(bundle: &HandshakeBundle) -> &'static str {
    match bundle {
        HandshakeBundle::Commit { .. } => "Commit",
        HandshakeBundle::Proposal { .. } => "Proposal",
    }
}

fn vectors() -> Vec<Vector> {
    let parsed: Vectors = serde_json::from_str(VECTORS_JSON).unwrap();
    assert_eq!(parsed.format_version, 1);
    parsed.vectors
}

#[test]
fn every_vector_is_decoded_or_refused_as_recorded() {
    let vectors = vectors();
    assert!(vectors.len() >= 27, "the vector set is not empty");
    for vector in vectors {
        let bytes = hex::decode(&vector.hex).unwrap();
        let id = &vector.id;
        let (accepted, variant, re_encoded) = match vector.kind.as_str() {
            "KeyMaterialResponse" => match KeyMaterialResponse::decode(&bytes, ONLY_AES) {
                Ok(response) => (
                    true,
                    Some(key_material_variant(&response)),
                    Some(response.encode().unwrap()),
                ),
                Err(_) => (false, None, None),
            },
            "UpdateRoomResponse" => match UpdateRoomResponse::decode(&bytes) {
                Ok(response) => (true, None, Some(response.encode().unwrap())),
                Err(_) => (false, None, None),
            },
            // An UpdateRequest is a HandshakeBundle; what the hub answers is replayed in mimi-hubd's own tests.
            "HandshakeBundle" | "UpdateRequest" => {
                match HandshakeBundle::decode(&bytes, ONLY_AES) {
                    Ok(bundle) => (
                        true,
                        Some(bundle_variant(&bundle)),
                        Some(bundle.encode().unwrap()),
                    ),
                    Err(_) => (false, None, None),
                }
            }
            // The gate reads a KeyPackage and writes nothing back, so there is no re-encoding to compare.
            "KeyPackage" => {
                let passed = mimi_gate_keypackage(&bytes, ONLY_AES).is_ok();
                (passed, None, passed.then(|| bytes.clone()))
            }
            other => panic!("{id}: unknown vector kind {other}"),
        };
        match vector.decode.as_str() {
            "ok" => {
                assert!(accepted, "{id}: must decode");
                assert_eq!(variant, vector.variant.as_deref(), "{id}: variant");
                assert_eq!(
                    re_encoded.as_deref(),
                    Some(bytes.as_slice()),
                    "{id}: decode then encode must be the identity"
                );
            }
            "refused" => assert!(!accepted, "{id}: must be refused"),
            other => panic!("{id}: unknown expectation {other}"),
        }
    }
}

#[test]
fn the_set_covers_each_shape_the_draft_defines() {
    let ids: Vec<String> = vectors().into_iter().map(|vector| vector.id).collect();
    for wanted in [
        "km-01-two-clients-success",
        "km-02-partial-success-one-exhausted",
        "km-03-nothing-compatible-with-capabilities",
        "km-05-user-unknown",
        "hb-01-commit-bare-welcome-full-group-info",
        "hb-03-partial-group-info",
        "hb-x1-welcome-in-mls-message",
        "kp-x1-grease-key-package",
        "up-02-participant-list-app-data-update",
        "up-x1-bare-commit",
        "ur-01-success",
        "ur-04-invalid-proposal",
    ] {
        assert!(ids.iter().any(|id| id == wanted), "missing vector {wanted}");
    }
}

/// hb-03 carries the PartialGroupInfo of hb-01's GroupInfo, raw: decoded from both vectors, the one is the other split.
#[test]
fn the_partial_vector_is_the_full_vectors_group_info_split() {
    let group_info = |id: &str| {
        let vector = vectors()
            .into_iter()
            .find(|vector| vector.id == id)
            .unwrap();
        match HandshakeBundle::decode(&hex::decode(&vector.hex).unwrap(), ONLY_AES).unwrap() {
            HandshakeBundle::Commit {
                group_info_option, ..
            } => group_info_option.payload,
            HandshakeBundle::Proposal { .. } => panic!("{id}: not a Commit"),
        }
    };
    let full = group_info("hb-01-commit-bare-welcome-full-group-info");
    let partial = group_info("hb-03-partial-group-info");
    assert_eq!(
        partial,
        mimi_core::partial_group_info::PartialGroupInfo::split(&full, false)
            .unwrap()
            .encode()
            .unwrap()
    );
}
