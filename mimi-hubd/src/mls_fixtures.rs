//! Real openmls groups for the hub's tests: members with their own keys, the Commits they make, and the GroupInfo and
//! ratchet tree a Commit's bundle carries.

use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;

pub(crate) const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub(crate) struct MemorySigner(Vec<u8>);

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

/// One client: its crypto provider, its signing key and the credential naming its user's URI.
pub(crate) struct Member {
    pub(crate) provider: OpenMlsRustCrypto,
    pub(crate) signer: MemorySigner,
    pub(crate) credential: CredentialWithKey,
}

impl Member {
    pub(crate) fn new(uri: &str) -> Self {
        let provider = OpenMlsRustCrypto::default();
        let (private, public) = provider
            .crypto()
            .signature_key_gen(SignatureScheme::ED25519)
            .unwrap();
        Self {
            provider,
            signer: MemorySigner(private),
            credential: CredentialWithKey {
                credential: BasicCredential::new(uri.as_bytes().to_vec()).into(),
                signature_key: SignaturePublicKey::from(public),
            },
        }
    }

    /// A KeyPackage for this member to be added with.
    pub(crate) fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .build(SUITE, &self.provider, &self.signer, self.credential.clone())
            .unwrap()
            .key_package()
            .clone()
    }

    /// A new group with this member alone, under `group_id`, as a PublicMessage-sending creator.
    pub(crate) fn create_group(&self, group_id: &[u8]) -> MlsGroup {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .unwrap()
    }
}

/// A Commit `by` makes in `group` adding `joiners`, merged on its side: the Commit as serialized MLSMessage bytes, and
/// the group's GroupInfo and ratchet tree after it, serialized as a Commit bundle carries them.
pub(crate) fn add_commit(
    group: &mut MlsGroup,
    by: &Member,
    joiners: &[&Member],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let key_packages: Vec<KeyPackage> = joiners.iter().map(|member| member.key_package()).collect();
    let (commit, _welcome, _group_info) = group
        .add_members(&by.provider, &by.signer, &key_packages)
        .unwrap();
    group.merge_pending_commit(&by.provider).unwrap();
    (
        commit.tls_serialize_detached().unwrap(),
        group_info_after(group, by),
        group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .unwrap(),
    )
}

/// The group's current GroupInfo, signed by `by`, without the ratchet tree in it, as the bare `GroupInfo` a bundle's
/// `GroupInfoOption` carries (not wrapped in an MLSMessage).
pub(crate) fn group_info_after(group: &MlsGroup, by: &Member) -> Vec<u8> {
    let message: MlsMessageIn = group
        .export_group_info(by.provider.crypto(), &by.signer, false)
        .unwrap()
        .into();
    match message.extract() {
        MlsMessageBodyIn::GroupInfo(info) => info.tls_serialize_detached().unwrap(),
        other => panic!("not a GroupInfo: {other:?}"),
    }
}
