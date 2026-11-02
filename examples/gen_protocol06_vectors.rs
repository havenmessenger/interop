//! Writes `tests/vectors/protocol06-vectors.json`: byte-exact `KeyMaterialResponse` and `HandshakeBundle` messages of
//! draft-ietf-mimi-protocol-06 §5.2 and §5.3, laid out field by field here and not through this crate's encoders, so a
//! second implementation can decode them and a regression in the codec shows up as a diff.
//!
//! `cargo run --example gen_protocol06_vectors --features test-helpers > tests/vectors/protocol06-vectors.json`
//!
//! The KeyPackages, Welcome and GroupInfo inside are produced by real openmls operations under the pinned ciphersuite. They
//! are random, so regenerating changes every vector; the committed file is the reference, and the replay test
//! (`tests/protocol06_vectors_replay.rs`) checks it without regenerating anything.
//!
//! `unwrap` is fine here: this is a generator, not the library.

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

    let vectors = vec![
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
            "a pinned-suite KeyPackage that lists a GREASE value in its capabilities and carries it in its extensions; refused by the pinned openmls release (DIVERGENCES.md DIV-14)",
            &grease_key_package(), "refused", None),
    ];
    let out = json!({
        "format_version": 1,
        "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "spec": "draft-ietf-mimi-protocol-06 section 5.2 and 5.3",
        "generator": "examples/gen_protocol06_vectors.rs",
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
