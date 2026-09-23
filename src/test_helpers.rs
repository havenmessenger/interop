//! Test-only MLS fixtures for downstream protocol and store boundary tests.
//! This module is opt-in so production consumers do not acquire fixture APIs.

use openmls::{
    ciphersuite::signature::SignaturePublicKey,
    credentials::{BasicCredential, CredentialWithKey},
    prelude::*,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    signatures::{Signer, SignerError},
    OpenMlsProvider,
};
use tls_codec::Serialize as TlsSerialize;

struct FixtureSigner {
    key: Vec<u8>,
    scheme: SignatureScheme,
}

impl Signer for FixtureSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        OpenMlsRustCrypto::default()
            .crypto()
            .sign(self.scheme, payload, &self.key)
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Build a genuine MLS KeyPackage in the requested wire ciphersuite.
pub fn key_package(credential: &[u8], suite: u16) -> Vec<u8> {
    let provider = OpenMlsRustCrypto::default();
    let scheme = SignatureScheme::ED25519;
    let (private_key, public_key) = provider.crypto().signature_key_gen(scheme).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(credential.to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let lifetime = Lifetime::init(0, u64::MAX);
    let suite = Ciphersuite::try_from(suite).expect("known fixture ciphersuite");
    KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .key_package_lifetime(lifetime)
        .build(
            suite,
            &provider,
            &FixtureSigner {
                key: private_key,
                scheme,
            },
            credential,
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}
