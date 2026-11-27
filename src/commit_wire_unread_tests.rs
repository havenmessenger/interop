//! What the Commit decoder hands back instead of refusing: an Add whose KeyPackage carries a credential of a type other
//! than Basic, with no identity and its KeyPackage kept for the caller to read; and an AppDataUpdate for a component this
//! crate does not read, as its component and operation. Commits are built by splicing a proposals window into a captured
//! openmls Commit (`app_data_tests`).

use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};

use super::app_data_tests::{app_data_update, commit_with};
use super::*;

struct Ed25519(Vec<u8>);

impl Signer for Ed25519 {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        OpenMlsRustCrypto::default()
            .crypto()
            .sign(SignatureScheme::ED25519, payload, &self.0)
            .map_err(|_| SignerError::SigningError)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// A KeyPackage whose leaf carries `credential`, its type listed in the leaf's capabilities.
fn key_package(credential: Credential) -> Vec<u8> {
    let provider = OpenMlsRustCrypto::default();
    let (private, public) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let credential_type = credential.credential_type();
    KeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[suite]),
            None,
            None,
            Some(&[CredentialType::Basic, credential_type]),
        ))
        .build(
            suite,
            &provider,
            &Ed25519(private),
            CredentialWithKey {
                credential,
                signature_key: SignaturePublicKey::from(public),
            },
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}

/// One by-value `Add` entry carrying `key_package`.
fn add(key_package: &[u8]) -> Vec<u8> {
    [&[1u8, 0x00, 0x01][..], key_package].concat()
}

/// An Add of any credential type decodes; a Basic one carries its identity, any other none, and each its KeyPackage as
/// sent. Revert check: refuse a credential that is not Basic, and the Commit does not decode.
#[test]
fn an_add_of_any_credential_type_decodes() {
    let basic = key_package(BasicCredential::new(b"mimi://a.example/u/alice".to_vec()).into());
    let other = key_package(Credential::new(
        CredentialType::Other(0x0008),
        b"a log".to_vec(),
    ));
    let decoded = decode_commit_proposals(&commit_with(&[add(&basic), add(&other)]))
        .expect("PLANT-CORE-ADD-ANY-CREDENTIAL: an Add whose credential is not Basic was refused");
    assert_eq!(decoded.adds.len(), 2);
    assert_eq!(
        decoded.adds[0].identity.as_deref(),
        Some(&b"mimi://a.example/u/alice"[..])
    );
    assert_eq!(decoded.adds[0].key_package, basic);
    assert_eq!(
        decoded.adds[1].identity, None,
        "a credential of another type has no identity here"
    );
    assert_eq!(decoded.adds[1].key_package, other);
}

/// An AppDataUpdate for a component this crate does not read is handed back, with its operation, beside the changes it
/// does read; a removal of a component it reads is handed back too, as it is not a change this crate reads. Revert
/// check: refuse such an update, and the Commit does not decode.
#[test]
fn an_unread_app_data_update_is_handed_back() {
    let participant_list = crate::app_data::PARTICIPANT_LIST_COMPONENT;
    let decoded = decode_commit_proposals(&commit_with(&[
        app_data_update(0xF013, APP_DATA_UPDATE_OP_UPDATE, Some(b"record")),
        app_data_update(0xF0F0, APP_DATA_UPDATE_OP_REMOVE, None),
    ]))
    .expect("PLANT-CORE-UNREAD: an unread AppDataUpdate was refused");
    assert_eq!(
        decoded.unread_app_data,
        vec![
            UnreadAppData {
                component: 0xF013,
                remove: false
            },
            UnreadAppData {
                component: 0xF0F0,
                remove: true
            },
        ]
    );
    assert!(decoded.updates.is_empty());
    let removal = decode_commit_proposals(&commit_with(&[app_data_update(
        participant_list,
        APP_DATA_UPDATE_OP_REMOVE,
        None,
    )]))
    .unwrap();
    assert_eq!(
        removal.unread_app_data,
        vec![UnreadAppData {
            component: participant_list,
            remove: true
        }]
    );
}
