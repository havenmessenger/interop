//! In-crate MLS fixtures for the sibling test files: KeyPackages built by openmls under a chosen wire suite, signed with Ed25519.
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

/// A KeyPackage built by openmls under the wire ciphersuite `suite`, signed with Ed25519.
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
        Some(&[CredentialType::Basic]),
    )
    .tls_serialize_detached()
    .unwrap()
}

/// What a commit that adds one member produces on the wire: the PublicMessage Commit, the bare `Welcome`, and the `GroupInfo`.
pub(crate) struct AddCommit {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub group_info: Vec<u8>,
}

/// A pinned-suite group of one adds a second member, with the ratchet tree extension on so a GroupInfo is produced.
pub(crate) fn add_commit() -> AddCommit {
    use openmls::prelude::tls_codec::Deserialize as _;
    let provider = OpenMlsRustCrypto::default();
    let (private_key, public_key) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let signer = Ed25519Signer { key: private_key };
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
    let bob = key_package(b"bob", 1);
    let mut slice = bob.as_slice();
    let bob = KeyPackageIn::tls_deserialize(&mut slice)
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let (commit, welcome, group_info) = group.add_members(&provider, &signer, &[bob]).unwrap();
    // An MLSMessage carrying a Welcome is `version` (mls10) and `wire_format` (mls_welcome), four bytes, then the Welcome.
    let wrapped = welcome.tls_serialize_detached().unwrap();
    assert_eq!(wrapped[..4], [0x00, 0x01, 0x00, 0x03]);
    AddCommit {
        commit: commit.tls_serialize_detached().unwrap(),
        welcome: wrapped[4..].to_vec(),
        group_info: group_info
            .expect("the ratchet tree extension yields a GroupInfo")
            .tls_serialize_detached()
            .unwrap(),
    }
}

/// A pinned-suite KeyPackage the way an RFC 9420 §13.5 client builds one: GREASE value `0x0A0A` listed in its capabilities and
/// present in its KeyPackage extensions.
pub(crate) fn grease_key_package() -> Vec<u8> {
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
        Some(&[CredentialType::Basic]),
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
            &Ed25519Signer { key: private_key },
            credential,
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}
