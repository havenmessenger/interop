//! A Welcome that reaches this provider in a notify, from the hub of a room it does not host, is queued for the local
//! user whose published KeyPackage it names, and for no one else.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Extension,
};
use mimi_core::protocol_wire::FanoutMessage;
use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as _, Serialize as _};
use tower::ServiceExt;

use super::now_unix;
use super::tests::{app, real_keypackage_for};
use crate::peer::{PeerCert, PeerIdentity};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const ROOM: &str = "mimi://other.example/r/lounge";

struct MemorySigner(Vec<u8>);

impl Signer for MemorySigner {
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

/// The Welcome another provider's member makes when adding the holder of `key_package` to its group.
pub(super) fn welcome_adding(key_package: &[u8]) -> Vec<u8> {
    let provider = OpenMlsRustCrypto::default();
    let (private, public) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let signer = MemorySigner(private);
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"mimi://other.example/u/alice".to_vec()).into(),
        signature_key: SignaturePublicKey::from(public),
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    let key_package = KeyPackageIn::tls_deserialize_exact(key_package)
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let (_commit, welcome, _group_info) = group
        .add_members(&provider, &signer, &[key_package])
        .unwrap();
    welcome.tls_serialize_detached().unwrap()
}

fn hub_of_the_room() -> PeerCert {
    let (ca, _ca_pem) = make_ca();
    let (cert_pem, _key) = issue(&ca, vec!["other.example".to_string()], "other");
    let chain = certs_from_pem(cert_pem.as_bytes()).unwrap();
    PeerCert(Some(PeerIdentity::new(chain[0].clone().into_owned())))
}

#[tokio::test]
async fn a_notified_welcome_is_queued_for_the_local_user_whose_key_package_it_names() {
    let (router, p) = app();
    let bobs = real_keypackage_for(b"mimi://havenmessenger.com/u/bob");
    p.lock()
        .unwrap()
        .publish_key_package("bob", &bobs, now_unix())
        .unwrap();
    let welcome = welcome_adding(&bobs);
    let body = FanoutMessage {
        protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
        timestamp: 1,
        message_and_tail: welcome.clone(),
    }
    .encode()
    .unwrap();
    let room = ROOM.replace(':', "%3A").replace('/', "%2F");
    let status = router
        .layer(Extension(hub_of_the_room()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mimi/pl/notify/{room}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::CREATED);
    let queued = p.lock().unwrap().fetch_welcome("bob").unwrap();
    assert_eq!(queued.as_deref(), Some(welcome.as_slice()));
    assert!(p.lock().unwrap().fetch_welcome("carol").unwrap().is_none());
}
