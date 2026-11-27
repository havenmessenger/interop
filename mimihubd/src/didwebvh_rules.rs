//! The `did_webvh` credential's group rules at the hub (draft-atwood-mls-didwebvh-credential §The Heads Component and
//! §Group Consistency Rules), so a tracked room takes no Commit and no seed its `did_webvh` members would refuse.
//!
//! The record of the newest head the group has accepted for each SCID is the `did_webvh_heads` component of the
//! GroupContext's `app_data_dictionary`. A Commit's AppDataUpdates set it ([`resolve_heads`]); every tracked Commit where
//! the record exists or the resulting tree holds a `did_webvh` leaf is checked against the draft's rules
//! ([`check_commit`]), and a seed against the rules a joiner checks ([`check_join`]). The rules themselves (Expected
//! Heads, Record matches, Consistency with the reference entry, Authorization) are the `mls-didwebvh` crate's, over the
//! tree's leaves as this hub reads them (`crate::credential`). The draft's other requirements on the GroupContext are
//! checked here too: a group whose tree holds a `did_webvh` credential names the record in its `app_components`, and no
//! `did_webvh` credential is an external sender.

use std::sync::Arc;

use mimi_core::app_data::ComponentChange;
use mls_didwebvh::rules::{self, Leaf, RuleError};
use mls_didwebvh::{DidWebvhHeads, VerifiedLog};
use openmls::prelude::{Credential, GroupContext};

use crate::credential;

/// The `app_components` component of mls-extensions (its §7.5: 0x0001), the list of components a group's members
/// implement.
const APP_COMPONENTS: u16 = 0x0001;

/// The record's component ID, `None` when the hub reads no `did_webvh` credential (then the record is a component it has
/// no rule for).
pub(crate) fn heads_component() -> Option<u16> {
    credential::did_webvh().map(|points| points.heads_component())
}

/// The record's value after a Commit's AppDataUpdates to it, in the Commit's order, given its value before: "each entry
/// replaces the entry with the same `scid`, or is inserted at its place in the sort order. An update that does not
/// decode, or whose entries are not sorted, is invalid", and "an AppDataUpdate proposal for `did_webvh_heads` whose
/// `op` is `remove` is invalid".
pub(crate) fn resolve_heads(
    before: Option<&[u8]>,
    changes: &[ComponentChange<'_>],
) -> Result<Vec<u8>, &'static str> {
    let mut record = match before {
        Some(bytes) => DidWebvhHeads::decode(bytes)
            .map_err(|_| "the room's did_webvh_heads record does not decode")?,
        None => DidWebvhHeads::new(),
    };
    for change in changes {
        match change {
            ComponentChange::Remove => return Err("the did_webvh_heads record is never removed"),
            ComponentChange::Update(update) => {
                let update = DidWebvhHeads::decode(update)
                    .map_err(|_| "a did_webvh_heads update does not decode, or is not sorted")?;
                for head in update.heads() {
                    record.insert(head.clone());
                }
            }
        }
    }
    record
        .encode()
        .map_err(|_| "the did_webvh_heads record does not encode")
}

/// Whether a Commit staged on `group` may be one the rules apply to: the room has a record before or after it, or a leaf
/// before the Commit or one it brings (an Add, an Update, the committer's new leaf) is a `did_webvh` credential. Only
/// then is the tree after it built to check. A Commit that creates the record in a room with no `did_webvh` leaf is
/// checked too, and refused: with no leaf to record, the expected record is empty.
pub(crate) fn may_apply(
    group: &openmls::group::PublicGroup,
    staged: &openmls::group::StagedCommit,
) -> bool {
    record_present(group.group_context())
        || record_present(staged.group_context())
        || group
            .members()
            .any(|member| credential::is_did_webvh(&member.credential))
        || staged.add_proposals().any(|add| {
            credential::is_did_webvh(add.add_proposal().key_package().leaf_node().credential())
        })
        || staged.update_proposals().any(|update| {
            credential::is_did_webvh(update.update_proposal().leaf_node().credential())
        })
        || staged
            .update_path_leaf_node()
            .is_some_and(|leaf| credential::is_did_webvh(leaf.credential()))
}

fn record_present(context: &GroupContext) -> bool {
    heads_component().is_some_and(|heads| crate::room_tree::app_data(context, heads).is_some())
}

/// A Commit's checks, given the GroupContext before it and after it and the members of the tree after it (each leaf's
/// credential and signature key). Nothing is checked in a room with no record before the Commit and no `did_webvh` leaf
/// after it.
pub(crate) fn check_commit(
    before: &GroupContext,
    after: &GroupContext,
    members_after: impl Iterator<Item = (Credential, Vec<u8>)>,
) -> Result<(), &'static str> {
    let leaves = did_webvh_leaves(members_after)?;
    let previous = record(before)?;
    // Nothing to check in a room that had no record, has no did_webvh leaf and is not given a record; one that is
    // given a record with no leaf to record fails Record matches below, as the expected record is empty.
    if previous.is_none() && leaves.is_empty() && !record_present(after) {
        return check_external_senders(after);
    }
    check_context(after, !leaves.is_empty())?;
    let resulting = record(after)?.unwrap_or_default();
    let refs: Vec<Leaf<'_>> = leaves
        .iter()
        .map(|(key, log)| Leaf {
            signature_key: key,
            log,
        })
        .collect();
    rules::check_commit(&previous.unwrap_or_default(), &resulting, &refs).map_err(rule)
}

/// A seed's checks: the tree and GroupContext a joiner receives ("A member joining by Welcome has no previous epoch ...
/// It instead checks that `did_webvh_heads` has an entry for each SCID in the tree ... and the consistency and
/// authorization rules, taking R for each SCID from the GroupContext it receives").
pub(crate) fn check_join(
    context: &GroupContext,
    members: impl Iterator<Item = (Credential, Vec<u8>)>,
) -> Result<(), &'static str> {
    let leaves = did_webvh_leaves(members)?;
    let heads = record(context)?;
    if heads.is_none() && leaves.is_empty() {
        return check_external_senders(context);
    }
    check_context(context, !leaves.is_empty())?;
    let refs: Vec<Leaf<'_>> = leaves
        .iter()
        .map(|(key, log)| Leaf {
            signature_key: key,
            log,
        })
        .collect();
    rules::check_join(&heads.unwrap_or_default(), &refs).map_err(rule)
}

/// A `did_webvh` leaf as the rules read it: its signature key and its verified log.
type VerifiedLeaf = (Vec<u8>, Arc<VerifiedLog>);

/// The tree's `did_webvh` leaves, each with its verified log; a `did_webvh` leaf whose log does not verify or authorize
/// its key fails the Commit.
fn did_webvh_leaves(
    members: impl Iterator<Item = (Credential, Vec<u8>)>,
) -> Result<Vec<VerifiedLeaf>, &'static str> {
    members
        .filter(|(credential, _)| credential::is_did_webvh(credential))
        .map(|(credential, key)| {
            credential::verified_log(&credential, &key)
                .map(|log| (key, log))
                .ok_or("a did_webvh leaf's log does not verify or authorize its key")
        })
        .collect()
}

/// The record in `context`, if it carries one.
fn record(context: &GroupContext) -> Result<Option<DidWebvhHeads>, &'static str> {
    heads_component()
        .and_then(|heads| crate::room_tree::app_data(context, heads))
        .map(DidWebvhHeads::decode)
        .transpose()
        .map_err(|_| "the did_webvh_heads record does not decode")
}

/// The draft's requirements on a GroupContext the rules apply to: with a `did_webvh` leaf in the tree, "its GroupContext
/// `app_components` list MUST name" the record; and no `did_webvh` credential among the external senders.
fn check_context(context: &GroupContext, has_did_webvh_leaf: bool) -> Result<(), &'static str> {
    if has_did_webvh_leaf
        && !crate::room_tree::app_data(context, APP_COMPONENTS)
            .and_then(component_ids)
            .is_some_and(|ids| heads_component().is_some_and(|heads| ids.contains(&heads)))
    {
        return Err(
            "a group with did_webvh members does not name did_webvh_heads in its app_components",
        );
    }
    check_external_senders(context)
}

/// "A `did_webvh` credential MUST NOT appear in the `external_senders` GroupContext extension." Checked on every
/// tracked Commit's resulting GroupContext and every seed, in any room.
pub(crate) fn check_external_senders(context: &GroupContext) -> Result<(), &'static str> {
    let senders = context.extensions().external_senders();
    // openmls has validated the extension; only a did_webvh credential among its senders is refused here.
    if senders.into_iter().flatten().any(|sender| {
        credential::external_sender_credential(sender).is_some_and(|c| credential::is_did_webvh(&c))
    }) {
        return Err("a did_webvh credential is an external sender");
    }
    Ok(())
}

/// Whether a KeyPackage meets a keyMaterial request's `required` capabilities as the draft reads them for `did_webvh`
/// ("a provider answering a request that requires the `did_webvh` credential type MAY treat it as also requiring the
/// component, and SHOULD return only KeyPackages whose LeafNode lists both"): when `required` names the `did_webvh`
/// credential type, the leaf's `app_components` names `did_webvh_heads`. Any other request is not narrowed. The rest of
/// what a request requires is `mimi_core::gate::keypackage_meets`'s.
pub(crate) fn key_package_meets(
    key_package: &[u8],
    required: &openmls::prelude::RequiredCapabilitiesExtension,
) -> bool {
    use openmls::prelude::tls_codec::Deserialize as _;
    let Some(points) = credential::did_webvh() else {
        return true;
    };
    let did_webvh = openmls::prelude::CredentialType::Other(points.credential_type());
    if !required.credential_types().contains(&did_webvh) {
        return true;
    }
    let Ok(Ok(key_package)) = std::panic::catch_unwind(|| {
        openmls::prelude::KeyPackageIn::tls_deserialize_exact(key_package)
    }) else {
        return false;
    };
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let Ok(key_package) = key_package.validate(
        openmls_traits::OpenMlsProvider::crypto(&provider),
        openmls::prelude::ProtocolVersion::Mls10,
    ) else {
        return false;
    };
    key_package
        .leaf_node()
        .extensions()
        .app_data_dictionary()
        .and_then(|dictionary| dictionary.dictionary().get(&APP_COMPONENTS))
        .and_then(component_ids)
        .is_some_and(|ids| ids.contains(&points.heads_component()))
}

/// The component IDs of an `app_components` value: `ComponentID component_ids<V>` (mls-extensions §5), a vector of
/// two-byte IDs behind an RFC 9420 §2.1.2 length.
fn component_ids(value: &[u8]) -> Option<Vec<u16>> {
    let (&first, rest) = value.split_first()?;
    let (length, rest) = match first >> 6 {
        0 => (usize::from(first), rest),
        1 => {
            let (&second, rest) = rest.split_first()?;
            (usize::from(first & 0x3f) << 8 | usize::from(second), rest)
        }
        2 => {
            let (bytes, rest) = rest.split_at_checked(3)?;
            let mut length = usize::from(first & 0x3f);
            for &byte in bytes {
                length = length << 8 | usize::from(byte);
            }
            (length, rest)
        }
        _ => return None,
    };
    if rest.len() != length || length % 2 != 0 {
        return None;
    }
    Some(
        rest.chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect(),
    )
}

/// What a broken rule is answered with, by the draft's name for it.
fn rule(error: RuleError) -> &'static str {
    match error {
        RuleError::KeyNotInHead => "a did_webvh leaf's key is not authorized by its own log (§Binding to the LeafNode)",
        RuleError::NewestLogLacksReference { .. } => {
            "the newest did_webvh log for an SCID does not contain the recorded head (§Expected Heads)"
        }
        RuleError::ExtensionMismatch { .. } => {
            "did_webvh_heads does not hold exactly the expected entries (§Rules, Record matches)"
        }
        RuleError::MissingReference { .. } | RuleError::Fork { .. } => {
            "a did_webvh credential is not consistent with the recorded head (§Rules, Consistency)"
        }
        RuleError::Unauthorized { .. } => {
            "a did_webvh leaf's key is not authorized by its SCID's recorded head (§Rules, Authorization)"
        }
        RuleError::MissingEntry { .. } => "did_webvh_heads has no entry for an SCID in the tree",
        RuleError::NewerThanRecorded { .. } => {
            "a did_webvh leaf carries a log newer than its SCID's recorded head"
        }
        RuleError::KeysMismatch { .. } => {
            "a recorded head's authorized_keys do not match the DID document a leaf carries"
        }
        _ => "the Commit breaks a did_webvh group rule",
    }
}

#[cfg(test)]
#[path = "didwebvh_rules_tests.rs"]
mod tests;
