//! A KeyMaterialRequest signed with its requester's key verifies; any change to a signed field, or a signature by
//! another key, does not.

use openmls::prelude::{BasicCredential, SignatureScheme};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto as _;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider as _;

use crate::protocol_wire::{IdentifierUri, KeyMaterialRequest};

/// An Ed25519 key that signs as a requester would.
struct SignatureKeyPair {
    private: Vec<u8>,
    public: Vec<u8>,
}

impl SignatureKeyPair {
    fn new(scheme: SignatureScheme) -> Result<Self, ()> {
        let (private, public) = OpenMlsRustCrypto::default()
            .crypto()
            .signature_key_gen(scheme)
            .map_err(|_| ())?;
        Ok(Self { private, public })
    }

    fn public(&self) -> &[u8] {
        &self.public
    }
}

impl Signer for SignatureKeyPair {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        OpenMlsRustCrypto::default()
            .crypto()
            .sign(SignatureScheme::ED25519, payload, &self.private)
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

fn signed(key: &SignatureKeyPair) -> KeyMaterialRequest {
    let mut request =
        KeyMaterialRequest::minimal("mimi://a.example/u/alice", "mimi://b.example/u/bob").unwrap();
    request.room_id = IdentifierUri("mimi://a.example/r/room".into());
    request.requester_signature_key = key.public().to_vec().into();
    request.requester_credential =
        BasicCredential::new(b"mimi://a.example/u/alice".to_vec()).into();
    request.sign(key).unwrap();
    request
}

#[test]
fn a_request_signed_by_its_key_verifies_and_survives_encoding() {
    let key = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let request = signed(&key);
    assert!(
        request.signature_verifies(),
        "PLANT-KM-SIGNATURE-VERIFIES: the requester's own signature verifies"
    );
    let decoded = KeyMaterialRequest::decode(&request.encode().unwrap()).unwrap();
    assert!(decoded.signature_verifies());
}

#[test]
fn a_changed_field_or_another_key_does_not_verify() {
    let key = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let mut changed = signed(&key);
    changed.target_user = IdentifierUri("mimi://b.example/u/carol".into());
    assert!(
        !changed.signature_verifies(),
        "PLANT-KM-SIGNATURE-COVERS-FIELDS: a changed target fails"
    );

    let other = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let mut swapped = signed(&key);
    swapped.requester_signature_key = other.public().to_vec().into();
    assert!(!swapped.signature_verifies());

    let unsigned =
        KeyMaterialRequest::minimal("mimi://a.example/u/alice", "mimi://b.example/u/bob").unwrap();
    assert!(!unsigned.signature_verifies());
}
