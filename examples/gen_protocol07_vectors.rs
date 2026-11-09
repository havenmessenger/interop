//! Writes `tests/vectors/protocol07-vectors.json`: byte-exact `KeyMaterialResponse` and `HandshakeBundle` messages of
//! draft-ietf-mimi-protocol-07 §5.2 and §5.3, laid out field by field here and not through this crate's encoders, so a
//! second implementation can decode them and a regression in the codec shows up as a diff.
//!
//! `cargo run --example gen_protocol07_vectors --features test-helpers > tests/vectors/protocol07-vectors.json`
//!
//! The KeyPackages, Welcome and GroupInfo inside are produced by openmls operations under the pinned ciphersuite. They
//! are random, so regenerating changes every vector; the committed file is the reference, and the replay test
//! (`tests/protocol07_vectors_replay.rs`) checks it without regenerating anything.
//!
//! `unwrap` is fine here: this is a generator, not the library.

use mimi_core::participant_list::{
    encode_participant_list_update, ParticipantListUpdate, UserRolePair,
    MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use mimi_core::protocol_wire::{
    GroupInfoOption, GroupInfoRepresentation, HandshakeBundle, UpdateRoomResponse,
};
use mimi_core::room_policy::{BaseRoomPolicy, Capability, Role};
use mimi_core::room_policy_wire::{encode_base_room_policy, encode_role_data};
use mimi_core::test_helpers::key_package;
use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use serde_json::json;
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

const PROTOCOL_MLS10: u8 = 1;
const USER: &str = "mimi://example.org/u/alice";
const CLIENT_A: &str = "mimi://example.org/d/alice-a";
const CLIENT_B: &str = "mimi://example.org/d/alice-b";
const ROOM: &str = "mimi://havenmessenger.com/r/x";
const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const CAROL: &str = "mimi://havenmessenger.com/u/carol";
const ZOE: &str = "mimi://havenmessenger.com/u/zoe";
const ROLES_LIST_COMPONENT: u16 = 0x0025;
const BASE_ROOM_POLICY_COMPONENT: u16 = 0x0027;
const PARTICIPANT_LIST_COMPONENT: u16 = 0x0022;
const SUITE_PINNED: u16 = 0x0001;
// The ChaCha20-Poly1305 suite, used only to build the foreign-suite refusals.
const SUITE_FOREIGN: u16 = 0x0003;

struct Signer25519 {
    key: Vec<u8>,
}

impl Signer for Signer25519 {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        OpenMlsRustCrypto::default()
            .crypto()
            .sign(SignatureScheme::ED25519, payload, &self.key)
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

fn uri(value: &str) -> Vec<u8> {
    VLBytes::new(value.as_bytes().to_vec())
        .tls_serialize_detached()
        .unwrap()
}

fn success(client: &str, key_package: &[u8]) -> Vec<u8> {
    [vec![0], uri(client), key_package.to_vec()].concat()
}

fn exhausted(client: &str) -> Vec<u8> {
    [vec![1], uri(client)].concat()
}

fn nothing_compatible(client: &str, capabilities: Option<&[u8]>) -> Vec<u8> {
    let tail = match capabilities {
        Some(bytes) => [vec![1], bytes.to_vec()].concat(),
        None => vec![0],
    };
    [vec![2], uri(client), tail].concat()
}

fn key_material(user_status: u8, user: &str, clients: &[Vec<u8>]) -> Vec<u8> {
    let window = VLBytes::new(clients.concat())
        .tls_serialize_detached()
        .unwrap();
    [vec![PROTOCOL_MLS10, user_status], uri(user), window].concat()
}

fn bundle(
    commit: &[u8],
    welcome: Option<&[u8]>,
    representation: u8,
    group_info: &[u8],
    tree: &[u8],
) -> Vec<u8> {
    let welcome = match welcome {
        Some(bytes) => [vec![1], bytes.to_vec()].concat(),
        None => vec![0],
    };
    [
        commit.to_vec(),
        welcome,
        vec![representation],
        group_info.to_vec(),
        tree.to_vec(),
    ]
    .concat()
}

/// The PublicMessage Commit, the bare Welcome and the GroupInfo of a pinned-suite group adding one member.
fn add_commit() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let provider = OpenMlsRustCrypto::default();
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let signer = Signer25519 { key: private_key };
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    let bob = key_package(b"bob", SUITE_PINNED);
    let mut slice = bob.as_slice();
    let bob = KeyPackageIn::tls_deserialize(&mut slice)
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let (commit, welcome, group_info) = group.add_members(&provider, &signer, &[bob]).unwrap();
    let wrapped = welcome.tls_serialize_detached().unwrap();
    // `version` (mls10) and `wire_format` (mls_welcome) precede the Welcome in an MLSMessage.
    assert_eq!(wrapped[..4], [0x00, 0x01, 0x00, 0x03]);
    (
        commit.tls_serialize_detached().unwrap(),
        wrapped[4..].to_vec(),
        group_info.unwrap().tls_serialize_detached().unwrap(),
    )
}

/// The by-value proposal message and the Commit over it: a group of one proposes and commits one custom proposal of
/// `proposal_type` carrying `payload`.
fn custom_proposal_and_commit(proposal_type: u16, payload: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let provider = OpenMlsRustCrypto::default();
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let signer = Signer25519 { key: private_key };
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let capabilities = Capabilities::new(
        None,
        Some(&[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]),
        None,
        Some(&[ProposalType::Custom(proposal_type)]),
        None,
    );
    let config = MlsGroupCreateConfig::builder()
        .capabilities(capabilities)
        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let mut group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    let (proposal, _reference) = group
        .propose_custom_proposal_by_value(
            &provider,
            &signer,
            CustomProposal::new(proposal_type, payload),
        )
        .unwrap();
    let (commit, _welcome, _group_info) = group
        .commit_to_pending_proposals(&provider, &signer)
        .unwrap();
    (
        proposal.tls_serialize_detached().unwrap(),
        commit.tls_serialize_detached().unwrap(),
    )
}

/// The Commit with its one custom proposal rewritten as an AppDataUpdate of `component` (mls-extensions-10 §4.7: type
/// 0x0008, a two-byte component id, the operation `update`, `update<V>`), with the proposals window's prefix adjusted.
fn as_app_data_update(commit: &[u8], payload: &[u8], component: u16) -> Vec<u8> {
    let prefix = |len: usize| {
        let whole = vl(&vec![0u8; len]);
        whole[..whole.len() - len].to_vec()
    };
    let entry = [vec![0x01, 0xF7, 0xA0], vl(payload)].concat();
    let found = [prefix(entry.len()), entry].concat();
    let at = commit
        .windows(found.len())
        .position(|w| w == found.as_slice())
        .unwrap();
    let entry = [
        vec![0x01, 0x00, 0x08],
        component.to_be_bytes().to_vec(),
        vec![0x01],
        vl(payload),
    ]
    .concat();
    let replacement = [prefix(entry.len()), entry].concat();
    [&commit[..at], &replacement, &commit[at + found.len()..]].concat()
}

fn vl(bytes: &[u8]) -> Vec<u8> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

/// An `UpdateRequest`: a Commit bundle with no Welcome, a Partial group info and no ratchet tree.
fn update_request(commit: &[u8]) -> Vec<u8> {
    HandshakeBundle::Commit {
        proposal_or_commit: commit.to_vec(),
        welcome: None,
        group_info_option: GroupInfoOption {
            representation: GroupInfoRepresentation::Partial,
            payload: Vec::new(),
        },
        ratchet_tree_option: Vec::new(),
    }
    .encode()
    .unwrap()
}

fn capabilities() -> Vec<u8> {
    Capabilities::new(
        None,
        Some(&[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]),
        None,
        None,
        None,
    )
    .tls_serialize_detached()
    .unwrap()
}

fn vector(
    id: &str,
    kind: &str,
    description: &str,
    bytes: &[u8],
    decode: &str,
    variant: Option<&str>,
) -> serde_json::Value {
    json!({
        "id": id,
        "kind": kind,
        "description": description,
        "hex": hex::encode(bytes),
        "decode": decode,
        "variant": variant,
    })
}

/// An `UpdateRequest` vector: the room it is posted to, the participants the room holds first, the participants it holds
/// after an accepted update, and the `UpdateRoomResponse` kind the hub answers with.
fn update_vector(
    id: &str,
    description: &str,
    body: &[u8],
    decode: &str,
    variant: Option<&str>,
    outcome: &str,
    after: &[&str],
) -> serde_json::Value {
    update_vector_from(
        id,
        description,
        body,
        decode,
        variant,
        outcome,
        &[ALICE, BOB],
        after,
    )
}

/// An `UpdateRequest` vector for a room that lists `before`, in that order (protocol-07 §7.5: an index is a position in
/// the list, and added participants are appended), and ends listing `after`, in order.
#[allow(clippy::too_many_arguments)]
fn update_vector_from(
    id: &str,
    description: &str,
    body: &[u8],
    decode: &str,
    variant: Option<&str>,
    outcome: &str,
    before: &[&str],
    after: &[&str],
) -> serde_json::Value {
    let mut v = vector(id, "UpdateRequest", description, body, decode, variant);
    v["room"] = json!(ROOM);
    v["participants_before"] = json!(before);
    v["participants_after"] = json!(after);
    v["answer"] = json!(outcome);
    v
}

fn main() {
    let (a, b) = (
        key_package(b"alice-a", SUITE_PINNED),
        key_package(b"alice-b", SUITE_PINNED),
    );
    let foreign = key_package(b"alice-f", SUITE_FOREIGN);
    let caps = capabilities();
    let km = "KeyMaterialResponse";
    let hb = "HandshakeBundle";
    let (commit, welcome, group_info) = add_commit();
    let wrapped_welcome = [vec![0x00, 0x01, 0x00, 0x03], welcome.clone()].concat();
    let foreign_welcome = [vec![0x00, 0x03], vec![0xFF; 16]].concat();
    let partial = VLBytes::new(vec![0xAB; 40])
        .tls_serialize_detached()
        .unwrap();

    let add_carol = encode_participant_list_update(&ParticipantListUpdate {
        added_participants: vec![UserRolePair {
            user_uri: CAROL.into(),
            role_index: 2,
        }],
        ..Default::default()
    })
    .unwrap();
    let (proposal_message, commit_message) =
        custom_proposal_and_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, add_carol.clone());
    let app_data_commit =
        as_app_data_update(&commit_message, &add_carol, PARTICIPANT_LIST_COMPONENT);
    let other_component_commit = as_app_data_update(&commit_message, &add_carol, 0x0023);
    // protocol-07 section 7.5: an index is a position in the list as it stood before the update, and added participants are
    // appended. A user already listed cannot be added.
    let as_commit = |payload: &[u8]| {
        custom_proposal_and_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, payload.to_vec()).1
    };
    let remove_position_1 = encode_participant_list_update(&ParticipantListUpdate {
        removed_indices: vec![1],
        ..Default::default()
    })
    .unwrap();
    let add_alice_again = encode_participant_list_update(&ParticipantListUpdate {
        added_participants: vec![UserRolePair {
            user_uri: ALICE.into(),
            role_index: 2,
        }],
        ..Default::default()
    })
    .unwrap();
    let remove_and_add_zoe = encode_participant_list_update(&ParticipantListUpdate {
        removed_indices: vec![1],
        added_participants: vec![UserRolePair {
            user_uri: ZOE.into(),
            role_index: 2,
        }],
        ..Default::default()
    })
    .unwrap();
    let roles = encode_role_data(&[Role {
        role_index: 2,
        role_name: "member".into(),
        capabilities: vec![Capability::SendMessage],
        authorized_role_changes: Vec::new(),
    }]);
    let base = encode_base_room_policy(&BaseRoomPolicy::default(), None);
    let remove_commit = as_commit(&remove_position_1);
    let again_commit = as_commit(&add_alice_again);
    let zoe_commit = as_commit(&remove_and_add_zoe);
    let roles_commit = as_app_data_update(&as_commit(&roles), &roles, ROLES_LIST_COMPONENT);
    let base_commit = as_app_data_update(&as_commit(&base), &base, BASE_ROOM_POLICY_COMPONENT);
    let cut_roles = &roles[..roles.len() - 1];
    let cut_roles_commit =
        as_app_data_update(&as_commit(cut_roles), cut_roles, ROLES_LIST_COMPONENT);
    let proposals_bundle = HandshakeBundle::Proposal {
        proposal_or_commit: proposal_message,
        more_proposals: Vec::new(),
    }
    .encode()
    .unwrap();
    let responses = [
        (
            "ur-01-success",
            "UpdateRoomResponse success with the hub's acceptance time in milliseconds",
            UpdateRoomResponse::Success {
                error_description: String::new(),
                accepted_timestamp: 1_762_100_000_123,
            },
        ),
        (
            "ur-02-wrong-epoch",
            "UpdateRoomResponse wrongEpoch with the current epoch",
            UpdateRoomResponse::WrongEpoch {
                error_description: "stale epoch".into(),
                current_epoch: 7,
            },
        ),
        (
            "ur-03-not-allowed",
            "UpdateRoomResponse notAllowed",
            UpdateRoomResponse::NotAllowed {
                error_description: "the hub did not accept this update".into(),
            },
        ),
        (
            "ur-04-invalid-proposal",
            "UpdateRoomResponse invalidProposal listing one proposal reference",
            UpdateRoomResponse::InvalidProposal {
                error_description: "invalid".into(),
                invalid_proposals: vec![vec![0x11; 32]],
            },
        ),
    ];

    let mut vectors = vec![
        vector("km-01-two-clients-success", km, "userStatus success, two clients each with a KeyPackage",
            &key_material(0, USER, &[success(CLIENT_A, &a), success(CLIENT_B, &b)]), "ok", Some("Clients")),
        vector("km-02-partial-success-one-exhausted", km, "userStatus partialSuccess: one client with a KeyPackage, one keyMaterialExhausted",
            &key_material(1, USER, &[success(CLIENT_A, &a), exhausted(CLIENT_B)]), "ok", Some("Clients")),
        vector("km-03-nothing-compatible-with-capabilities", km, "partialSuccess with a nothingCompatible client that includes its capabilities",
            &key_material(1, USER, &[success(CLIENT_A, &a), nothing_compatible(CLIENT_B, Some(&caps))]), "ok", Some("Clients")),
        vector("km-04-nothing-compatible-without-capabilities", km, "partialSuccess with a nothingCompatible client that omits its capabilities",
            &key_material(1, USER, &[success(CLIENT_A, &a), nothing_compatible(CLIENT_B, None)]), "ok", Some("Clients")),
        vector("km-05-user-unknown", km, "userStatus userUnknown carries no client", &key_material(4, USER, &[]), "ok", Some("Clients")),
        vector("km-06-no-compatible-material", km, "userStatus noCompatibleMaterial with no clients listed", &key_material(3, USER, &[]), "ok", Some("Clients")),
        vector("km-07-no-consent", km, "userStatus noConsent carries no client", &key_material(5, USER, &[]), "ok", Some("Denied")),
        vector("km-08-single-success", km, "one client, under the user's own URI, with a KeyPackage",
            &key_material(0, USER, &[success(USER, &a)]), "ok", Some("Success")),
        vector("km-09-single-exhausted", km, "partialSuccess with one keyMaterialExhausted client under the user's own URI",
            &key_material(1, USER, &[exhausted(USER)]), "ok", Some("Exhausted")),
        vector("km-x1-foreign-suite-second-client", km, "the second client's KeyPackage names another ciphersuite",
            &key_material(0, USER, &[success(CLIENT_A, &a), success(CLIENT_B, &foreign)]), "refused", None),
        vector("km-x2-success-with-exhausted-client", km, "userStatus success whose second client is keyMaterialExhausted",
            &key_material(0, USER, &[success(CLIENT_A, &a), exhausted(CLIENT_B)]), "refused", None),
        vector("km-x3-user-unknown-with-client", km, "userStatus userUnknown must not carry a client",
            &key_material(4, USER, &[exhausted(CLIENT_A)]), "refused", None),
        vector("hb-01-commit-bare-welcome-full-group-info", hb, "a Commit, a bare Welcome, a raw Full GroupInfo and a ratchet tree",
            &bundle(&commit, Some(&welcome), 1, &group_info, &[0xCC, 0xDD]), "ok", Some("Commit")),
        vector("hb-02-commit-without-welcome", hb, "a Commit with no Welcome and a raw Full GroupInfo",
            &bundle(&commit, None, 1, &group_info, &[]), "ok", Some("Commit")),
        vector("hb-03-partial-group-info", hb, "a Partial GroupInfoOption, written with a length prefix",
            &bundle(&commit, Some(&welcome), 2, &partial, &[0xEE]), "ok", Some("Commit")),
        vector("hb-x1-welcome-in-mls-message", hb, "the Welcome wrapped in an MLSMessage instead of bare",
            &bundle(&commit, Some(&wrapped_welcome), 1, &group_info, &[]), "refused", None),
        vector("hb-x2-foreign-suite-welcome", hb, "a Welcome whose leading cipher suite is not the pinned one",
            &bundle(&commit, Some(&foreign_welcome), 1, &group_info, &[]), "refused", None),
        vector("kp-x1-grease-key-package", "KeyPackage",
            "a pinned-suite KeyPackage that lists a GREASE value in its capabilities and carries it in its extensions",
            &grease_key_package(), "ok", None),
        update_vector("up-01-participant-list-private-type", "an UpdateRequest whose Commit carries the participant-list update as the 0xF7A0 custom proposal",
            &update_request(&commit_message), "ok", Some("Commit"), "success", &[ALICE, BOB, CAROL]),
        update_vector("up-02-participant-list-app-data-update", "the same update carried as an AppDataUpdate for component 0x0022 (mls-extensions-10 section 4.7)",
            &update_request(&app_data_commit), "ok", Some("Commit"), "success", &[ALICE, BOB, CAROL]),
        update_vector_from("up-03-index-is-a-position", "removedIndices [1] on the list [alice, zoe, bob] removes the second entry, zoe, and the others keep their order (section 7.5)",
            &update_request(&remove_commit), "ok", Some("Commit"), "success", &[ALICE, ZOE, BOB], &[ALICE, BOB]),
        update_vector_from("up-04-added-participants-are-appended", "an added participant goes to the end of the list (section 7.5)",
            &update_request(&app_data_commit), "ok", Some("Commit"), "success", &[BOB, ALICE], &[BOB, ALICE, CAROL]),
        update_vector_from("up-05-roles-list-app-data-update", "an AppDataUpdate for roles_list (component 0x0025, room-policy-04 section 3) sets the room's roles and leaves the participants as they were",
            &update_request(&roles_commit), "ok", Some("Commit"), "success", &[ALICE, BOB], &[ALICE, BOB]),
        update_vector_from("up-x4-added-participant-already-listed", "an added participant who is already in the list is invalid (section 7.5)",
            &update_request(&again_commit), "ok", Some("Commit"), "invalidProposal", &[ALICE, BOB], &[ALICE, BOB]),
        update_vector_from("up-x5-removed-and-added-in-one-update", "a user removed and added back in one update is invalid: the update is checked against the list as it stood before it (this hub's reading of section 7.5)",
            &update_request(&zoe_commit), "ok", Some("Commit"), "invalidProposal", &[ALICE, ZOE, BOB], &[ALICE, ZOE, BOB]),
        update_vector_from("up-x6-base-room-policy-before-roles", "an AppDataUpdate for base_room_policy (component 0x0027) for a room that has no roles yet is invalid",
            &update_request(&base_commit), "ok", Some("Commit"), "invalidProposal", &[ALICE, BOB], &[ALICE, BOB]),
        update_vector_from("up-x7-roles-list-cut-short", "an AppDataUpdate for roles_list whose RoleData ends before its length says is invalid",
            &update_request(&cut_roles_commit), "ok", Some("Commit"), "invalidProposal", &[ALICE, BOB], &[ALICE, BOB]),
        update_vector("up-x1-bare-commit", "the Commit alone, without the HandshakeBundle around it",
            &commit_message, "refused", None, "invalidProposal", &[ALICE, BOB]),
        update_vector("up-x2-bundle-of-proposals", "a HandshakeBundle of proposals instead of a Commit",
            &proposals_bundle, "ok", Some("Proposal"), "invalidProposal", &[ALICE, BOB]),
        update_vector("up-x3-app-data-update-other-component", "an AppDataUpdate for component 0x0023 (room_metadata), which the hub does not read",
            &update_request(&other_component_commit), "ok", Some("Commit"), "invalidProposal", &[ALICE, BOB]),
    ];
    for (id, description, response) in responses {
        let mut v = vector(
            id,
            "UpdateRoomResponse",
            description,
            &response.encode().unwrap(),
            "ok",
            None,
        );
        v["answer"] = json!(null);
        vectors.push(v);
    }
    let out = json!({
        "format_version": 1,
        "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "spec": "draft-ietf-mimi-protocol-07 section 5.2 and 5.3",
        "generator": "examples/gen_protocol07_vectors.rs",
        "vectors": vectors,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn grease_key_package() -> Vec<u8> {
    let provider = OpenMlsRustCrypto::default();
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"grease".to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let capabilities = Capabilities::new(
        None,
        Some(&[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]),
        Some(&[ExtensionType::Grease(0x0A0A)]),
        None,
        None,
    );
    KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .key_package_extensions(
            Extensions::single(Extension::Unknown(0x0A0A, UnknownExtension(Vec::new()))).unwrap(),
        )
        .key_package_lifetime(Lifetime::init(0, u64::MAX))
        .build(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            &provider,
            &Signer25519 { key: private_key },
            credential,
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}
