//! Test-only MLS fixtures for downstream protocol and store boundary tests.
//! This module is opt-in so production consumers do not acquire fixture APIs.

use openmls::{
    ciphersuite::signature::SignaturePublicKey,
    credentials::{BasicCredential, CredentialWithKey},
    prelude::*,
    schedule::psk::{ExternalPsk, PreSharedKeyId, Psk},
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

struct MlsTestSigner {
    key: Vec<u8>,
    scheme: SignatureScheme,
}

impl Signer for MlsTestSigner {
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

/// A genuine OpenMLS PublicMessage Commit carrying an ordinary standard `Update` proposal.
/// The stub does not verify MLS crypto, but it must still fully classify and route the standard
/// proposal rather than rejecting an otherwise valid group-evolution Commit.
pub fn public_proposal_and_commit_with_standard_update() -> (String, String) {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let scheme = SignatureScheme::ED25519;
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(scheme)
        .expect("generates test signing key");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"standard-update".to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let signer = MlsTestSigner {
        key: private_key,
        scheme,
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let mut group =
        MlsGroup::new(&provider, &signer, &config, credential).expect("creates a real MLS group");
    let (proposal, _) = group
        .propose_self_update(
            &provider,
            &signer,
            openmls::treesync::LeafNodeParameters::default(),
        )
        .expect("creates a standard Update proposal");
    let (commit, _, _) = group
        .commit_to_pending_proposals(&provider, &signer)
        .expect("commits the standard Update proposal");
    (
        hex::encode(
            proposal
                .tls_serialize_detached()
                .expect("serializes the public MLS Proposal"),
        ),
        hex::encode(
            commit
                .tls_serialize_detached()
                .expect("serializes the public MLS Commit"),
        ),
    )
}

pub fn public_commit_with_standard_update() -> String {
    public_proposal_and_commit_with_standard_update().1
}

/// A genuine OpenMLS public SelfRemove proposal for the §5.3 exception path.
pub fn public_self_remove_proposal() -> String {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let scheme = SignatureScheme::ED25519;
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(scheme)
        .expect("generates test signing key");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"self-remove".to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let signer = MlsTestSigner {
        key: private_key,
        scheme,
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .capabilities(
            Capabilities::builder()
                .proposals(vec![ProposalType::SelfRemove])
                .build(),
        )
        .build();
    let mut group =
        MlsGroup::new(&provider, &signer, &config, credential).expect("creates a real MLS group");
    hex::encode(
        group
            .leave_group_via_self_remove(&provider, &signer)
            .expect("creates a SelfRemove proposal")
            .tls_serialize_detached()
            .expect("serializes the public MLS SelfRemove"),
    )
}

/// A genuine OpenMLS public Remove proposal for the §5.3 exception path.
pub fn public_remove_proposal() -> String {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let scheme = SignatureScheme::ED25519;
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(scheme)
        .expect("generates test signing key");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"remove".to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let signer = MlsTestSigner {
        key: private_key,
        scheme,
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let mut group =
        MlsGroup::new(&provider, &signer, &config, credential).expect("creates a real MLS group");
    hex::encode(
        group
            .propose_remove_member(&provider, &signer, LeafNodeIndex::new(0))
            .expect("creates a Remove proposal")
            .0
            .tls_serialize_detached()
            .expect("serializes the public MLS Remove"),
    )
}

/// OpenMLS's received-proposal path for a standard proposal that is committed by reference.
/// Unlike the test-only MIMI-extension fixture below, these bytes are emitted unchanged by
/// OpenMLS: the PSK proposal is first sent as a public Proposal, then the pending Commit cites
/// its library-computed ProposalRef.
pub fn public_proposal_and_commit_with_referenced_psk() -> (String, String) {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let scheme = SignatureScheme::ED25519;
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(scheme)
        .expect("generates test signing key");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"referenced-psk".to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let signer = MlsTestSigner {
        key: private_key,
        scheme,
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let mut group =
        MlsGroup::new(&provider, &signer, &config, credential).expect("creates a real MLS group");
    let psk = PreSharedKeyId::new(
        suite,
        provider.rand(),
        Psk::External(ExternalPsk::new(b"referenced-standard-psk".to_vec())),
    )
    .expect("creates an external PSK identifier");
    psk.store(&provider, &[0x42; 32])
        .expect("stores external PSK for the pending Commit");
    let (proposal, _) = group
        .propose_external_psk(&provider, &signer, psk)
        .expect("creates a reference-form PSK proposal");
    let (commit, _, _) = group
        .commit_to_pending_proposals(&provider, &signer)
        .expect("commits the referenced PSK proposal");
    (
        hex::encode(
            proposal
                .tls_serialize_detached()
                .expect("serializes the public MLS Proposal"),
        ),
        hex::encode(
            commit
                .tls_serialize_detached()
                .expect("serializes the public MLS Commit"),
        ),
    )
}
