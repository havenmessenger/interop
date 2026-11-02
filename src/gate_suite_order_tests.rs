//! The suite refusal comes first: a KeyPackage that names another suite is refused as foreign before it is decoded or its
//! signature is verified, so no other suite's arithmetic runs on a peer's bytes.

use super::*;
use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls_traits::signatures::{Signer, SignerError};

const PINNED: u16 = HAVEN_MLS_CIPHERSUITE_U16;

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

/// A genuine KeyPackage under `suite`, signed with Ed25519.
fn key_package(credential: &[u8], suite: u16) -> Vec<u8> {
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

/// A genuine pinned-suite KeyPackage whose suite field is rewritten to `suite`. Everything after the field is a valid
/// 0x0001 KeyPackage, so any later stage (decode, signature check) would fail on it; only the order of the stages decides
/// which error comes back.
fn renamed(suite: u16) -> Vec<u8> {
    let mut bytes = key_package(b"suite-order", PINNED);
    bytes[2..4].copy_from_slice(&suite.to_be_bytes());
    bytes
}

fn is_foreign(error: &GateError, suite: u16) -> bool {
    matches!(error, GateError::ForeignCiphersuite(ForeignCiphersuite { got }) if *got == suite)
}

#[test]
fn the_suite_is_read_from_the_wire_position_the_rfc_fixes() {
    for suite in [0x0001u16, 0x0003] {
        let bytes = key_package(b"wire-layout", suite);
        assert_eq!(keypackage_wire_suite(&bytes).unwrap(), suite);
    }
}

#[test]
fn a_foreign_suite_is_refused_before_any_signature_is_verified() {
    for suite in [0x0002u16, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007] {
        let error = mimi_gate_keypackage(&renamed(suite)).unwrap_err();
        assert!(is_foreign(&error, suite), "suite {suite:#06x}: {error}");
    }
}

#[test]
fn a_suite_openmls_does_not_know_is_still_a_foreign_refusal() {
    let error = mimi_gate_keypackage(&renamed(0xFFFF)).unwrap_err();
    assert!(is_foreign(&error, 0xFFFF), "{error}");
}

#[test]
fn the_ref_derivation_refuses_a_foreign_suite_too() {
    let error = keypackage_ref(&renamed(0x0002)).unwrap_err();
    assert!(is_foreign(&error, 0x0002), "{error}");
}

#[test]
fn bytes_too_short_to_name_a_suite_are_undecodable() {
    for length in 0..4 {
        let bytes = vec![0u8; length];
        assert!(matches!(
            mimi_gate_keypackage(&bytes),
            Err(GateError::UndecodableKeyPackage(_))
        ));
    }
}

#[test]
fn the_pinned_suite_still_passes_and_yields_a_ref() {
    let bytes = key_package(b"pinned", PINNED);
    mimi_gate_keypackage(&bytes).unwrap();
    assert!(!keypackage_ref(&bytes).unwrap().is_empty());
}

#[test]
fn a_pinned_suite_keypackage_with_a_bad_signature_is_a_validation_failure_not_a_suite_refusal() {
    let mut bytes = key_package(b"tampered", PINNED);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert!(matches!(
        mimi_gate_keypackage(&bytes),
        Err(GateError::KeyPackageValidation(_))
    ));
}
