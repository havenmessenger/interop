//! Each room's ratchet tree: the delivery service's view of the room's MLS group.
//!
//! A tracked room has an openmls `PublicGroup` in the store (the ratchet tree and GroupContext, no secrets), and every
//! Commit the hub accepts for it is verified against that group and merged into it: its sender must be a member whose
//! signature verifies, and it must apply to the tree as it stands. A Commit that does not apply is refused and changes
//! nothing, so one bad Commit cannot drop the room's checks.
//!
//! A room is tracked from the first Commit whose bundle carries a Full GroupInfo and a full ratchet tree
//! (ratchet-tree-options `full`), after that Commit is otherwise accepted. Protocol-07 §5.3 lets the client choose what
//! the bundle carries, so a room stays untracked until such a bundle arrives, and behaves as before meanwhile. Seeding is
//! trust on first use, narrowed: the GroupInfo must be for the epoch after the Commit, signed by a member of the tree it
//! comes with, that member's provider must be the peer that sent the bundle, and every participant the hub lists for the
//! room must be a member of the tree. The hub records the group's id and which provider seeded the room.

use openmls::framing::{MlsMessageIn, ProcessedMessageContent, ProtocolMessage, Sender};
use openmls::group::{PublicGroup, StagedCommit};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    AppDataUpdateOperation, Credential, GroupId, LeafNodeIndex, ProposalStore, RatchetTreeIn,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use mimi_core::participant_list::{
    apply_update, decode_participant_list_data, decode_participant_list_update,
    encode_participant_list_data, ParticipantListData,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};

use crate::{Provider, UpdateRefusal};

/// `participant_list`'s component id in a GroupContext's app data dictionary (protocol-07 §10.3).
pub const PARTICIPANT_LIST_COMPONENT: u16 = 0x0022;

/// ratchet-tree-options `RatchetTreeRepresentation.full`.
const RATCHET_TREE_FULL: u8 = 1;

/// The full ratchet tree a bundle's `RatchetTreeOption` carries (`full`: `optional<Node> ratchet_tree<V>`, the RFC 9420
/// ratchet_tree extension's content), or `None` for any other representation or bytes that do not decode as one.
pub fn full_ratchet_tree(option: &[u8]) -> Option<RatchetTreeIn> {
    let (&representation, tree) = option.split_first()?;
    if representation != RATCHET_TREE_FULL {
        return None;
    }
    std::panic::catch_unwind(|| RatchetTreeIn::tls_deserialize_exact(tree))
        .ok()?
        .ok()
}

/// What the hub keeps about a tracked room besides its group state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomTracking {
    /// The MLS group id the room was seeded with; a Commit for another group is refused.
    pub group_id: Vec<u8>,
    /// The provider whose peer sent the bundle the room was seeded from.
    pub seeded_by: String,
}

/// A Commit verified against a tracked room's group, ready to be merged once the hub has applied it to its own tables.
pub struct StagedRoomCommit {
    group: PublicGroup,
    staged: StagedCommit,
}

/// The user URI a member's credential names: a BasicCredential whose identity is the URI (the reading this hub takes;
/// how a credential binds a user is still open in the working group).
fn credential_uri(credential: &Credential) -> Option<String> {
    let identity = credential.serialized_content();
    std::str::from_utf8(identity)
        .ok()
        .map(mimi_core::uri::canonical)
}

/// The provider a user URI belongs to: its authority.
fn provider_of(uri: &str) -> Option<String> {
    mimi_core::uri::MimiUri::parse(uri)
        .ok()
        .map(|parsed| parsed.authority.to_ascii_lowercase())
}

fn member_uri(group: &PublicGroup, leaf: LeafNodeIndex) -> Option<String> {
    group
        .leaf(leaf)
        .and_then(|node| credential_uri(node.credential()))
}

impl Provider {
    /// The room's tracking record, when the hub keeps its tree.
    pub fn room_tracking(&self, room_uri: &str) -> anyhow::Result<Option<RoomTracking>> {
        self.store.room_tree(room_uri)
    }

    /// Stop keeping the room's tree: its group state and tracking record go, and its next bundle with a Full GroupInfo
    /// and a full tree seeds it again. The operator's way out of a room stuck on a tree the hub cannot apply Commits to.
    pub fn untrack_room(&self, room_uri: &str) -> anyhow::Result<bool> {
        let Some(tracking) = self.store.room_tree(room_uri)? else {
            return Ok(false);
        };
        PublicGroup::delete(
            &self.store.groups(),
            &GroupId::from_slice(&tracking.group_id),
        )?;
        self.store.drop_room_tree(room_uri)?;
        Ok(true)
    }

    /// Verify `commit` against the tracked room's group and stage it, without changing anything yet. `group_info` is the
    /// bundle's: a Full one must describe the group as it is after the Commit. Every refusal is logged with the room and
    /// the sender's provider, so a room that keeps refusing is seen.
    pub(crate) fn stage_tracked_commit(
        &self,
        room_uri: &str,
        tracking: &RoomTracking,
        commit: &[u8],
        group_info: Option<&GroupInfoOption>,
    ) -> Result<StagedRoomCommit, UpdateRefusal> {
        let refused = |why: &'static str, sender: Option<String>, refusal: UpdateRefusal| {
            eprintln!(
                "[mimi-hubd] refused a Commit for {room_uri} (tracked, seeded by {}) from {}: {why}",
                tracking.seeded_by,
                sender.as_deref().unwrap_or("an unknown sender")
            );
            refusal
        };
        let crypto = OpenMlsRustCrypto::default();
        let groups = self.store.groups();
        let group = PublicGroup::load(&groups, &GroupId::from_slice(&tracking.group_id))
            .map_err(|_| UpdateRefusal::Store)?
            .ok_or(UpdateRefusal::Store)?;
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .ok()
            .and_then(|message| message.try_into_protocol_message().ok())
            .ok_or_else(|| {
                refused(
                    "not an MLS handshake message",
                    None,
                    UpdateRefusal::Invalid("the commit is not one this hub can read"),
                )
            })?;
        if let ProtocolMessage::PublicMessage(public) = &message {
            if public.group_id().as_slice() != tracking.group_id.as_slice() {
                return Err(refused(
                    "another group's Commit",
                    None,
                    UpdateRefusal::NotAllowed,
                ));
            }
            if public.epoch() != group.group_context().epoch() {
                return Err(refused(
                    "another epoch",
                    None,
                    UpdateRefusal::WrongEpoch(group.group_context().epoch().as_u64()),
                ));
            }
        }
        let processed = group
            .process_message(crypto.crypto(), message)
            .map_err(|_| {
                refused(
                    "it does not verify or apply to the room's tree",
                    None,
                    UpdateRefusal::NotAllowed,
                )
            })?;
        let sender = match processed.sender() {
            Sender::Member(leaf) => member_uri(&group, *leaf),
            _ => {
                return Err(refused(
                    "the sender is not a member",
                    None,
                    UpdateRefusal::NotAllowed,
                ))
            }
        };
        let sender_provider = sender.as_deref().and_then(provider_of);
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => *staged,
            ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) => {
                let mut updater = group.app_data_dictionary_updater();
                for proposal in unresolved.app_data_update_proposals() {
                    let component = proposal.component_id();
                    match proposal.operation() {
                        AppDataUpdateOperation::Remove => updater.remove(&component),
                        AppDataUpdateOperation::Update(data) => {
                            let value = if component == PARTICIPANT_LIST_COMPONENT {
                                let current = match updater.old_value(component) {
                                    Some(bytes) => decode_participant_list_data(bytes)
                                        .map_err(|_| UpdateRefusal::Store)?,
                                    None => ParticipantListData::default(),
                                };
                                let update = decode_participant_list_update(data.as_slice())
                                    .map_err(|_| {
                                        UpdateRefusal::Invalid(
                                            "the participant list update is malformed",
                                        )
                                    })?;
                                let next = apply_update(&current, &update).map_err(|_| {
                                    UpdateRefusal::Invalid(
                                        "the participant list update does not apply to the room's list",
                                    )
                                })?;
                                encode_participant_list_data(&next)
                                    .map_err(|_| UpdateRefusal::Store)?
                            } else {
                                data.as_slice().to_vec()
                            };
                            updater.set(openmls::component::ComponentData::from_parts(
                                component,
                                value.into(),
                            ));
                        }
                    }
                }
                let changes = updater.changes();
                group
                    .stage_app_data_commit(crypto.crypto(), *unresolved, changes)
                    .map_err(|_| {
                        refused(
                            "its AppDataUpdates do not apply",
                            sender_provider.clone(),
                            UpdateRefusal::NotAllowed,
                        )
                    })?
            }
            _ => {
                return Err(refused(
                    "not a Commit",
                    sender_provider,
                    UpdateRefusal::Invalid("the commit is not one this hub can read"),
                ))
            }
        };
        if let Some(group_info) =
            group_info.filter(|info| info.representation == GroupInfoRepresentation::Full)
        {
            let matches = VerifiableGroupInfo::tls_deserialize_exact(group_info.payload.as_slice())
                .ok()
                .is_some_and(|info| {
                    info.group_context().tls_serialize_detached().ok()
                        == staged.group_context().tls_serialize_detached().ok()
                });
            if !matches {
                return Err(refused(
                    "its GroupInfo does not describe the group after it",
                    sender_provider,
                    UpdateRefusal::Invalid(
                        "the GroupInfo does not match the group after this Commit",
                    ),
                ));
            }
        }
        Ok(StagedRoomCommit { group, staged })
    }

    /// Merge a staged Commit into the room's group, once the hub has applied it to its own tables.
    pub(crate) fn merge_tracked_commit(
        &self,
        staged: StagedRoomCommit,
    ) -> Result<(), UpdateRefusal> {
        let StagedRoomCommit { mut group, staged } = staged;
        group
            .merge_commit(&self.store.groups(), staged)
            .map_err(|_| UpdateRefusal::Store)
    }

    /// Seed an untracked room's tree from an accepted Commit's bundle, when it carries a Full GroupInfo and a full tree
    /// and they pass every check in the module doc. `commit_epoch` is the epoch the Commit was sent in. Anything short of
    /// that leaves the room untracked; the Commit itself is already accepted either way.
    pub(crate) fn seed_room_tree(
        &self,
        room_uri: &str,
        commit_epoch: u64,
        peer: Option<&crate::peer::PeerIdentity>,
        group_info: &GroupInfoOption,
        ratchet_tree_option: &[u8],
    ) {
        if let Err(Some(why)) = self.try_seed_room_tree(
            room_uri,
            commit_epoch,
            peer,
            group_info,
            ratchet_tree_option,
        ) {
            eprintln!("[mimi-hubd] {room_uri} stays untracked: {why}");
        }
    }

    /// `Err(None)`: the bundle does not carry what seeding needs (nothing to say); `Err(Some)`: it does, and a check
    /// refused it.
    fn try_seed_room_tree(
        &self,
        room_uri: &str,
        commit_epoch: u64,
        peer: Option<&crate::peer::PeerIdentity>,
        group_info: &GroupInfoOption,
        ratchet_tree_option: &[u8],
    ) -> Result<(), Option<&'static str>> {
        if group_info.representation != GroupInfoRepresentation::Full {
            return Err(None);
        }
        let tree = full_ratchet_tree(ratchet_tree_option).ok_or(None)?;
        let info = VerifiableGroupInfo::tls_deserialize_exact(group_info.payload.as_slice())
            .map_err(|_| Some("its GroupInfo does not decode"))?;
        if info.group_context().epoch().as_u64() != commit_epoch + 1 {
            return Err(Some("its GroupInfo is not for the epoch after the Commit"));
        }
        // Checked in a scratch store first, so a group that fails a check is never written to the hub's.
        let scratch = OpenMlsRustCrypto::default();
        let (candidate, _) = PublicGroup::from_external(
            scratch.crypto(),
            scratch.storage(),
            tree.clone(),
            info.clone(),
            ProposalStore::new(),
        )
        .map_err(|_| Some("its GroupInfo and tree are not a valid group"))?;
        let signer = member_uri(&candidate, info.signer())
            .ok_or(Some("its GroupInfo's signer names no user"))?;
        let provider =
            provider_of(&signer).ok_or(Some("its GroupInfo's signer names no provider"))?;
        if !peer.is_some_and(|peer| peer.authenticates(&provider)) {
            return Err(Some(
                "its GroupInfo's signer is not of the provider that sent it",
            ));
        }
        let members: Vec<String> = candidate
            .members()
            .filter_map(|member| credential_uri(&member.credential))
            .collect();
        let listed = self
            .store
            .list_participant_rows(room_uri)
            .map_err(|_| Some("the room's participants could not be read"))?;
        if listed.iter().any(|row| !members.contains(&row.member_uri)) {
            return Err(Some("a participant the hub lists is not in its tree"));
        }
        let group_id = candidate.group_id().as_slice().to_vec();
        let crypto = OpenMlsRustCrypto::default();
        PublicGroup::from_external(
            crypto.crypto(),
            &self.store.groups(),
            tree,
            info,
            ProposalStore::new(),
        )
        .map_err(|_| Some("its group could not be stored"))?;
        self.store
            .set_room_tree(room_uri, &group_id, &provider, commit_epoch + 1)
            .map_err(|_| Some("its tracking record could not be stored"))?;
        eprintln!(
            "[mimi-hubd] {room_uri} is tracked from epoch {}, seeded by {provider}",
            commit_epoch + 1
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "room_tree_tests.rs"]
mod tests;
