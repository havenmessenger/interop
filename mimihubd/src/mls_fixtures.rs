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
    /// Whether its leaves list the did_webvh credential type although its credential is Basic.
    pub(crate) lists_did_webvh: bool,
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
            lists_did_webvh: false,
        }
    }

    /// A client whose credential is a `did_webvh` credential: a one-entry log at `example.com/<path>` authorizing this
    /// client's key and naming `uri` in `alsoKnownAs`.
    pub(crate) fn did_webvh(uri: &str, path: &str) -> Self {
        let mut member = Self::new(uri);
        let key: mls_didwebvh::PublicKey = member
            .credential
            .signature_key
            .as_slice()
            .try_into()
            .unwrap();
        let seed = path
            .bytes()
            .fold(0x5a_u8, |acc, b| acc.wrapping_mul(31).wrapping_add(b));
        let log = crate::didwebvh_fixtures::log(path, seed, &[key], &[uri]);
        member.credential.credential =
            crate::didwebvh_fixtures::mls_credential(&log.credential().unwrap());
        member
    }

    /// The capabilities this client's leaves advertise: [`capabilities`], with the `did_webvh` credential type too when
    /// its credential is one.
    pub(crate) fn leaf_capabilities(&self) -> Capabilities {
        let did_webvh = CredentialType::Other(crate::credential::DID_WEBVH.credential_type());
        match self.credential.credential.credential_type() {
            CredentialType::Basic if !self.lists_did_webvh => capabilities(),
            _ => Capabilities::new(
                None,
                Some(&[SUITE]),
                Some(&[ExtensionType::AppDataDictionary]),
                Some(&[ProposalType::AppDataUpdate]),
                Some(&[CredentialType::Basic, did_webvh]),
            ),
        }
    }

    /// A client with a Basic credential whose leaves list the did_webvh credential type as well, so it can be a member
    /// of a group with did_webvh members (RFC 9420 §7.2: every member supports every credential type in use).
    pub(crate) fn basic_listing_did_webvh(uri: &str) -> Self {
        let mut member = Self::new(uri);
        member.lists_did_webvh = true;
        member
    }

    /// The same client on a fresh store: its signing key and credential with a new provider, as a client that lost its
    /// group state and rejoins with the key its leaf holds (a resync, RFC 9420 §12.4.3.2).
    pub(crate) fn on_a_fresh_store(&self) -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
            signer: MemorySigner(self.signer.0.clone()),
            credential: self.credential.clone(),
            lists_did_webvh: self.lists_did_webvh,
        }
    }

    /// A KeyPackage for this member to be added with, advertising the app data dictionary and AppDataUpdate.
    pub(crate) fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(self.leaf_capabilities())
            .build(SUITE, &self.provider, &self.signer, self.credential.clone())
            .unwrap()
            .key_package()
            .clone()
    }

    /// A KeyPackage bundle (with its private keys in this member's provider), for a join that processes the Welcome.
    pub(crate) fn key_package_bundle(&self) -> KeyPackageBundle {
        KeyPackage::builder()
            .leaf_node_capabilities(self.leaf_capabilities())
            .build(SUITE, &self.provider, &self.signer, self.credential.clone())
            .unwrap()
    }

    /// A new group with this member alone, under `group_id`, as a PublicMessage-sending creator.
    pub(crate) fn create_group(&self, group_id: &[u8]) -> MlsGroup {
        self.create_group_with(group_id, &[])
    }

    /// As [`Self::create_group`], with `components` (id, value) in the GroupContext's app data dictionary.
    pub(crate) fn create_group_with(
        &self,
        group_id: &[u8],
        components: &[(u16, Vec<u8>)],
    ) -> MlsGroup {
        let mut builder = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .capabilities(self.leaf_capabilities());
        if !components.is_empty() {
            let mut dictionary = AppDataDictionary::new();
            for (id, value) in components {
                let _ = dictionary.insert(*id, value.clone());
            }
            builder = builder.with_group_context_extensions(
                Extensions::single(Extension::AppDataDictionary(
                    AppDataDictionaryExtension::new(dictionary),
                ))
                .unwrap(),
            );
        }
        let config = builder.build();
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

/// The capabilities every fixture leaf advertises: the suite, the app data dictionary, AppDataUpdate, basic credentials.
pub(crate) fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[SUITE]),
        Some(&[ExtensionType::AppDataDictionary]),
        Some(&[ProposalType::AppDataUpdate]),
        Some(&[CredentialType::Basic]),
    )
}

/// `by` adds `joiner` to `group` and merges; `joiner` processes the Welcome and has its own copy of the group.
pub(crate) fn add_and_join(group: &mut MlsGroup, by: &Member, joiner: &Member) -> MlsGroup {
    let key_package = joiner.key_package_bundle();
    let (_commit, welcome, _group_info) = group
        .add_members(
            &by.provider,
            &by.signer,
            &[key_package.key_package().clone()],
        )
        .unwrap();
    group.merge_pending_commit(&by.provider).unwrap();
    let welcome: MlsMessageIn = welcome.into();
    let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("not a Welcome");
    };
    StagedWelcome::new_from_welcome(
        &joiner.provider,
        &MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build(),
        welcome,
        Some(group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(&joiner.provider)
    .unwrap()
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

/// A Commit `by` makes in `group` carrying AppDataUpdates by value, each (component, the update, the component's value
/// after it), as MLSMessage bytes. It is left pending on `by`'s side: the caller merges it once the hub accepts it, or
/// clears it after a refusal.
pub(crate) fn app_data_commit(
    group: &mut MlsGroup,
    by: &Member,
    updates: &[(u16, Vec<u8>, Vec<u8>)],
) -> Vec<u8> {
    let proposals: Vec<Proposal> = updates
        .iter()
        .map(|(component, update, _)| {
            Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
                *component,
                update.clone(),
            )))
        })
        .collect();
    let mut stage = group
        .commit_builder()
        .add_proposals(proposals)
        .load_psks(by.provider.storage())
        .unwrap();
    let mut updater = stage.app_data_dictionary_updater();
    for (component, _, value) in updates {
        updater.set(openmls::component::ComponentData::from_parts(
            *component,
            value.clone().into(),
        ));
    }
    stage.with_app_data_dictionary_updates(updater.changes());
    let (commit, _welcome, _group_info) = stage
        .build(by.provider.rand(), by.provider.crypto(), &by.signer, |_| {
            true
        })
        .unwrap()
        .stage_commit(&by.provider)
        .unwrap()
        .into_contents();
    commit.tls_serialize_detached().unwrap()
}

/// An external Commit `joiner` makes to join the group described by `group_info` (bare, as a bundle carries it) and
/// `tree`: the Commit as MLSMessage bytes, and the joiner's group after it.
pub(crate) fn external_commit(
    group_info: &[u8],
    tree: RatchetTreeIn,
    joiner: &Member,
) -> (Vec<u8>, MlsGroup) {
    use openmls::prelude::tls_codec::Deserialize as _;
    let info =
        openmls::messages::group_info::VerifiableGroupInfo::tls_deserialize_exact(group_info)
            .unwrap();
    let (group, bundle) = MlsGroup::external_commit_builder()
        .with_ratchet_tree(tree)
        .with_config(
            MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build(),
        )
        .build_group(&joiner.provider, info, joiner.credential.clone())
        .unwrap()
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(capabilities())
                .build(),
        )
        .load_psks(joiner.provider.storage())
        .unwrap()
        .build(
            joiner.provider.rand(),
            joiner.provider.crypto(),
            &joiner.signer,
            |_| true,
        )
        .unwrap()
        .finalize(&joiner.provider)
        .unwrap();
    (
        bundle.into_commit().tls_serialize_detached().unwrap(),
        group,
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

/// One member's own group, for tests that need real application messages (PrivateMessages) and no particular room.
pub(crate) struct Sender {
    member: Member,
    group: MlsGroup,
}

impl Sender {
    pub(crate) fn new() -> Self {
        let member = Member::new("mimi://example.com/u/sender");
        let group = member.create_group(b"mimi://example.com/g/sender");
        Self { member, group }
    }

    /// An application message carrying `text`, as an MLSMessage: a PrivateMessage, as RFC 9420 §6 has one.
    pub(crate) fn message(&mut self, text: &[u8]) -> Vec<u8> {
        self.group
            .create_message(&self.member.provider, &self.member.signer, text)
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }
}

/// An MLSMessage carrying a PublicMessage with application content, built by hand: openmls makes application messages
/// only as PrivateMessages. Its signature and membership tag are zeros; it is well-formed, not valid.
pub(crate) fn public_application_message(group_id: &[u8], epoch: u64) -> Vec<u8> {
    fn opaque(out: &mut Vec<u8>, bytes: &[u8]) {
        // RFC 9420 §2.1.2 variable-size length: one byte below 64, two (0b01 prefix) below 16384.
        if bytes.len() < 64 {
            out.push(u8::try_from(bytes.len()).unwrap());
        } else {
            out.extend_from_slice(&(0x4000u16 | u16::try_from(bytes.len()).unwrap()).to_be_bytes());
        }
        out.extend_from_slice(bytes);
    }
    let mut out = vec![0, 1, 0, 1]; // mls10, public_message
    opaque(&mut out, group_id);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(1); // sender_type member
    out.extend_from_slice(&0u32.to_be_bytes()); // leaf_index
    opaque(&mut out, b""); // authenticated_data
    out.push(1); // content_type application
    opaque(&mut out, b"in the clear");
    opaque(&mut out, &[0u8; 64]); // signature
    opaque(&mut out, &[0u8; 32]); // membership_tag
    out
}

/// A KeyPackage, as bytes, whose leaf carries `credential`, of whatever type, under a fresh key, with capabilities that
/// list that credential type as well as Basic.
pub(crate) fn key_package_carrying(credential: Credential) -> Vec<u8> {
    let member = Member::new("mimi://example.com/u/unused");
    let credential_type = credential.credential_type();
    KeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[SUITE]),
            Some(&[ExtensionType::AppDataDictionary]),
            Some(&[ProposalType::AppDataUpdate]),
            Some(&[CredentialType::Basic, credential_type]),
        ))
        .build(
            SUITE,
            &member.provider,
            &member.signer,
            CredentialWithKey {
                credential,
                signature_key: member.credential.signature_key.clone(),
            },
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}
