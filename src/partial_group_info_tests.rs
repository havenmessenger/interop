//! A real openmls GroupInfo, split into a PartialGroupInfo and the fields a tracking receiver holds, is rebuilt byte for
//! byte; a PartialGroupInfo that carries a ratchet_tree, or a tree its presence does not call for, is refused.

use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

use super::{PartialGroupInfo, RatchetTreePresence, TreeAt, RATCHET_TREE_EXTENSION};

/// A GroupInfo's parts: the encoded GroupContext, its extensions as (type, data), the encoded confirmation tag, the
/// signer and the signature.
struct Parts {
    group_context: Vec<u8>,
    extensions: Vec<(u16, Vec<u8>)>,
    confirmation_tag: Vec<u8>,
    signer: u32,
    signature: Vec<u8>,
}

fn parts(group_info: &[u8]) -> Parts {
    let info = VerifiableGroupInfo::tls_deserialize_exact(group_info).unwrap();
    let group_context = info.group_context().tls_serialize_detached().unwrap();
    let rest = &group_info[group_context.len()..];
    let (list, rest) = VLBytes::tls_deserialize_bytes(rest).unwrap();
    let mut extensions = Vec::new();
    let mut list = list.as_slice();
    while !list.is_empty() {
        let (extension_type, after) = u16::tls_deserialize_bytes(list).unwrap();
        let (data, after) = VLBytes::tls_deserialize_bytes(after).unwrap();
        extensions.push((extension_type, data.as_slice().to_vec()));
        list = after;
    }
    let (tag, after_tag) = VLBytes::tls_deserialize_bytes(rest).unwrap();
    let confirmation_tag = rest[..rest.len() - after_tag.len()].to_vec();
    assert!(!tag.as_slice().is_empty());
    let (signer, rest) = u32::tls_deserialize_bytes(after_tag).unwrap();
    let signature = VLBytes::tls_deserialize_exact(rest).unwrap();
    Parts {
        group_context,
        extensions,
        confirmation_tag,
        signer,
        signature: signature.as_slice().to_vec(),
    }
}

/// The PartialGroupInfo a committer sends for `parts`: its extensions without the ratchet_tree, and the signature.
fn partial(parts: &Parts, presence: RatchetTreePresence) -> PartialGroupInfo {
    let mut extensions = Vec::new();
    for (extension_type, data) in &parts.extensions {
        if *extension_type != RATCHET_TREE_EXTENSION {
            extension_type.tls_serialize(&mut extensions).unwrap();
            VLBytes::new(data.clone())
                .tls_serialize(&mut extensions)
                .unwrap();
        }
    }
    PartialGroupInfo {
        ratchet_tree_presence: presence,
        extensions,
        signature: parts.signature.clone(),
    }
}

fn tree(parts: &Parts) -> Option<&[u8]> {
    parts
        .extensions
        .iter()
        .find(|(extension_type, _)| *extension_type == RATCHET_TREE_EXTENSION)
        .map(|(_, data)| data.as_slice())
}

/// An Ed25519 signing key.
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

/// A group of one's own GroupInfo with only `external_pub` in it, as openmls exports one without the tree.
fn group_info_without_tree() -> Vec<u8> {
    let provider = OpenMlsRustCrypto::default();
    let (key, public) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let signer = Ed25519(key);
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: public.into(),
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        .build();
    let group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    let message: MlsMessageIn = group
        .export_group_info(provider.crypto(), &signer, false)
        .unwrap()
        .into();
    match message.extract() {
        MlsMessageBodyIn::GroupInfo(info) => info.tls_serialize_detached().unwrap(),
        other => panic!("not a GroupInfo: {other:?}"),
    }
}

/// The GroupInfo `parts` stands for with its extensions in `order` (indices into `parts.extensions`).
fn reordered(parts: &Parts, order: &[usize]) -> Vec<u8> {
    let mut extensions = Vec::new();
    for &at in order {
        let (extension_type, data) = &parts.extensions[at];
        extension_type.tls_serialize(&mut extensions).unwrap();
        VLBytes::new(data.clone())
            .tls_serialize(&mut extensions)
            .unwrap();
    }
    let mut out = parts.group_context.clone();
    VLBytes::new(extensions).tls_serialize(&mut out).unwrap();
    out.extend_from_slice(&parts.confirmation_tag);
    out.extend_from_slice(&parts.signer.to_be_bytes());
    VLBytes::new(parts.signature.clone())
        .tls_serialize(&mut out)
        .unwrap();
    out
}

/// An add Commit's GroupInfo as openmls writes it, ratchet_tree then external_pub, is rebuilt from its Partial with the
/// tree first, and with the tree last it is the same list in the draft's order. Revert check: ignore where the tree is
/// asked for, and one of the two differs.
#[test]
fn a_group_info_with_the_tree_is_rebuilt_from_its_partial_at_either_end() {
    let group_info = crate::test_fixtures::add_commit().group_info;
    let parts = parts(&group_info);
    let types: Vec<u16> = parts.extensions.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        types,
        [RATCHET_TREE_EXTENSION, 0x0004],
        "openmls writes the tree first"
    );
    let partial = partial(&parts, RatchetTreePresence::Present);
    let decoded = PartialGroupInfo::decode(&partial.encode().unwrap()).unwrap();
    assert_eq!(decoded, partial);
    assert_eq!(PartialGroupInfo::split(&group_info, true).unwrap(), partial);
    assert_eq!(
        PartialGroupInfo::split(&group_info, false)
            .unwrap()
            .ratchet_tree_presence,
        RatchetTreePresence::Added
    );
    let rebuild = |at| {
        decoded
            .group_info(
                &parts.group_context,
                Some((tree(&parts).unwrap(), at)),
                &parts.confirmation_tag,
                parts.signer,
            )
            .unwrap()
    };
    assert!(
        rebuild(TreeAt::First) == group_info,
        "PLANT-PARTIAL-GI-REBUILT: the GroupInfo rebuilt from its Partial is the one signed"
    );
    assert!(rebuild(TreeAt::Last) == reordered(&parts, &[1, 0]));
}

/// The tree can be put back before any extension of the Partial's list: with external_pub and two GREASE extensions
/// (mls-rs's shape has one after the tree), each place gives the list with the tree there, the two ends are
/// `TreeAt::First` and `TreeAt::Last`, and a place past the end is refused. Revert check: ignore the index and put the
/// tree last, and the middle places differ.
#[test]
fn the_tree_is_put_back_at_any_place_in_the_list() {
    let group_info = crate::test_fixtures::add_commit().group_info;
    let mut parts = parts(&group_info);
    parts.extensions.push((0x0a0a, Vec::new()));
    parts.extensions.push((0x1a1a, Vec::new()));
    let partial = partial(&parts, RatchetTreePresence::Present);
    assert_eq!(partial.extension_count().unwrap(), 3);
    let rebuild = |at| {
        partial.group_info(
            &parts.group_context,
            Some((tree(&parts).unwrap(), at)),
            &parts.confirmation_tag,
            parts.signer,
        )
    };
    // parts.extensions is [tree, external_pub, grease, grease]: the tree is index 0, the others 1 to 3 in order.
    for place in 0..=3 {
        let mut order = vec![1, 2, 3];
        order.insert(place, 0);
        assert!(
            rebuild(TreeAt::Before(place)).unwrap() == reordered(&parts, &order),
            "PLANT-PARTIAL-GI-TREE-ANY-PLACE: the tree put back at place {place} is not there"
        );
    }
    assert_eq!(
        rebuild(TreeAt::First).unwrap(),
        rebuild(TreeAt::Before(0)).unwrap()
    );
    assert_eq!(
        rebuild(TreeAt::Last).unwrap(),
        rebuild(TreeAt::Before(3)).unwrap()
    );
    assert!(rebuild(TreeAt::Before(4)).is_err());
}

/// A GroupInfo without the tree (external_pub only) is rebuilt from its Partial with nothing appended.
#[test]
fn a_group_info_without_the_tree_is_rebuilt_from_its_partial() {
    let group_info = group_info_without_tree();
    let parts = parts(&group_info);
    assert!(tree(&parts).is_none());
    let partial = partial(&parts, RatchetTreePresence::NoRatchetTree);
    assert_eq!(
        PartialGroupInfo::split(&group_info, false).unwrap(),
        partial
    );
    let rebuilt = PartialGroupInfo::decode(&partial.encode().unwrap())
        .unwrap()
        .group_info(
            &parts.group_context,
            None,
            &parts.confirmation_tag,
            parts.signer,
        )
        .unwrap();
    assert_eq!(rebuilt, group_info);
}

/// A tree the presence does not call for, or none where it does, is refused rather than rebuilt into another GroupInfo.
#[test]
fn a_tree_must_agree_with_the_presence() {
    let group_info = crate::test_fixtures::add_commit().group_info;
    let parts = parts(&group_info);
    let rebuild = |presence, tree| {
        partial(&parts, presence).group_info(
            &parts.group_context,
            tree,
            &parts.confirmation_tag,
            parts.signer,
        )
    };
    assert!(rebuild(RatchetTreePresence::Added, None).is_err());
    let tree = tree(&parts).map(|tree| (tree, TreeAt::Last));
    assert!(rebuild(RatchetTreePresence::Removed, tree).is_err());
    assert!(rebuild(RatchetTreePresence::Added, tree).is_ok());
    assert!(rebuild(RatchetTreePresence::Removed, None).is_ok());
}

/// A PartialGroupInfo carrying a ratchet_tree extension is rejected (ratchet-tree-options §4), as are an unknown
/// presence and bytes after the signature. Revert check: skip the extension check, and the first decodes.
#[test]
fn a_partial_with_a_ratchet_tree_or_extra_bytes_is_refused() {
    let group_info = crate::test_fixtures::add_commit().group_info;
    let parts = parts(&group_info);
    let mut with_tree = partial(&parts, RatchetTreePresence::Present);
    RATCHET_TREE_EXTENSION
        .tls_serialize(&mut with_tree.extensions)
        .unwrap();
    VLBytes::new(tree(&parts).unwrap().to_vec())
        .tls_serialize(&mut with_tree.extensions)
        .unwrap();
    assert!(
        PartialGroupInfo::decode(&with_tree.encode().unwrap()).is_err(),
        "PLANT-PARTIAL-GI-NO-TREE: a Partial carrying the ratchet_tree is rejected"
    );
    let good = partial(&parts, RatchetTreePresence::Present)
        .encode()
        .unwrap();
    let mut unknown = good.clone();
    unknown[0] = 4;
    assert!(PartialGroupInfo::decode(&unknown).is_err());
    let mut longer = good.clone();
    longer.push(0);
    assert!(PartialGroupInfo::decode(&longer).is_err());
    assert!(PartialGroupInfo::decode(&good).is_ok());
}
