//! In-crate MLS fixtures for the sibling test files: genuine KeyPackages under a chosen wire suite, signed with Ed25519.
//! Unlike `test_helpers`, this module is always available to `cargo test`, so tests that run without the
//! `test-helpers` feature can use it.

use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize as TlsSerialize;

struct Ed25519Signer {
    key: Vec<u8>,
}

impl Signer for Ed25519Signer {
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

/// A genuine KeyPackage under the wire ciphersuite `suite`, signed with Ed25519.
pub(crate) fn key_package(credential: &[u8], suite: u16) -> Vec<u8> {
    let provider = OpenMlsRustCrypto::default();
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(credential.to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .key_package_lifetime(Lifetime::init(0, u64::MAX))
        .build(
            Ciphersuite::try_from(suite).expect("known fixture ciphersuite"),
            &provider,
            &Ed25519Signer { key: private_key },
            credential,
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}

/// A serialized `Capabilities` as a client of the pinned suite would advertise.
pub(crate) fn capabilities() -> Vec<u8> {
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
