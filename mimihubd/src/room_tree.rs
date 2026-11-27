//! Each room's ratchet tree: the delivery service's view of the room's MLS group.
//!
//! A tracked room has an openmls `PublicGroup` in the store (the ratchet tree and GroupContext, no secrets), and every
//! Commit the hub accepts for it is verified against that group and merged into it: its sender must be a member whose
//! signature verifies, and it must apply to the tree as it stands. A Commit that does not apply is refused and changes
//! nothing, so one bad Commit cannot drop the room's checks.
//!
//! A room is tracked from the first Commit whose bundle carries a Full GroupInfo and a full ratchet tree
//! (ratchet-tree-options `full`), after that Commit is otherwise accepted. Protocol-07 §5.3 lets the client choose what
//! the bundle carries; what a room hosted here meets until such a bundle arrives is `hosted_untracked.rs`. Seeding is
//! trust on first use, narrowed: the GroupInfo must be for the epoch after the Commit, signed by a member of the tree it
//! comes with, that member's provider must be the peer that sent the bundle, and every participant the hub lists for the
//! room must be a member of the tree. The hub records the group's id and which provider seeded the room.
//!
//! A tracked room's Commit with a GroupInfo is checked against the group after it: the GroupInfo must be signed by the
//! committer with the key it holds after the Commit, name the committer's leaf, and carry the hub's GroupContext. A
//! Partial GroupInfo (ratchet-tree-options §4) is first rebuilt from the group after the Commit: its GroupContext, the
//! Commit's confirmation tag, the committer's leaf, and the tree when the Partial says the GroupInfo carries one, tried
//! last (as the draft has it) and first (as openmls writes it). A Commit with no GroupInfo is not checked so, and a
//! drift of the hub's group from the members' is refused one epoch late, when the next member PublicMessage's signature
//! over the GroupContext fails to verify.

use openmls::framing::{MlsMessageIn, ProcessedMessageContent, ProtocolMessage, Sender};
use openmls::group::{PublicGroup, StagedCommit};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    AppDataUpdateOperation, GroupId, LeafNodeIndex, OpenMlsSignaturePublicKey, Proposal,
    ProposalStore, RatchetTreeIn, Verifiable as _,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use mimi_core::app_data::{resolve_component, AppDataError, ComponentChange};
use mimi_core::partial_group_info::{PartialGroupInfo, TreeAt};
use mimi_core::participant_list::{decode_participant_list_data, ParticipantListData};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};

use crate::credential::user_uri;
use crate::list_leaves::{ListAndLeaves, RemovedLeaf, Renewal};
use crate::{Provider, UpdateRefusal};

/// `participant_list`'s component id in a GroupContext's app data dictionary (protocol-07 §10.3).
pub const PARTICIPANT_LIST_COMPONENT: u16 = mimi_core::app_data::PARTICIPANT_LIST_COMPONENT;

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

/// `roles_list`'s component id in a GroupContext's app data dictionary (room-policy-04).
pub const ROLES_LIST_COMPONENT: u16 = 0x0025;
/// `base_room_policy`'s component id.
pub const BASE_ROOM_POLICY_COMPONENT: u16 = 0x0027;

/// A Commit verified against a tracked room's group, ready to be merged once the hub has applied it to its own tables.
pub struct StagedRoomCommit {
    group: PublicGroup,
    staged: StagedCommit,
    /// The committer's user, by its credential.
    pub(crate) sender: Option<String>,
    /// Whether the group had a `roles_list` before this Commit.
    pub(crate) had_roles_list: bool,
    /// For an external Commit, the joiner's user, by the credential of the leaf its update path adds.
    pub(crate) joiner: Option<String>,
    /// The committer's leaf, for a Commit a member sent.
    committer_leaf: Option<LeafNodeIndex>,
}

impl StagedRoomCommit {
    /// The room's list and clients around this Commit, for [`crate::list_leaves::require_paired`]: the participant list
    /// before it (the group's GroupContext) and after it (the GroupContext as staged, its AppDataUpdates resolved), the
    /// clients it adds and removes, held proposals included, and the user of each client after it. A group that carries
    /// no participant list in its GroupContext is read with the hub's own list, `hub_before` and `hub_after` (its
    /// participants before the Commit and after its change).
    ///
    /// An external Commit that removes a client of its joiner's own user (a resync, RFC 9420 §12.4.3.2) replaces that
    /// client with the joiner, so that client is not counted as removed by another member.
    pub(crate) fn list_and_leaves(
        &self,
        hub_before: Vec<(String, u32)>,
        hub_after: Vec<String>,
    ) -> Result<ListAndLeaves, UpdateRefusal> {
        let decode = |bytes: Option<&[u8]>| {
            bytes
                .map(decode_participant_list_data)
                .transpose()
                .map_err(|_| UpdateRefusal::Invalid("the participant list does not decode"))
        };
        let before = decode(app_data(
            self.group.group_context(),
            PARTICIPANT_LIST_COMPONENT,
        ))?;
        let after = decode(app_data(
            self.staged.group_context(),
            PARTICIPANT_LIST_COMPONENT,
        ))?;
        let mut removed_at = Vec::new();
        let mut removed = Vec::new();
        for queued in self.staged.queued_proposals() {
            let proposer_leaf = match queued.sender() {
                Sender::Member(leaf) => Some(*leaf),
                _ => None,
            };
            let leaf = match queued.proposal() {
                Proposal::Remove(remove) => remove.removed(),
                Proposal::SelfRemove => match proposer_leaf {
                    Some(leaf) => leaf,
                    None => continue,
                },
                _ => continue,
            };
            removed_at.push(leaf);
            let user = member_uri(&self.group, leaf);
            let proposer = match queued.sender() {
                Sender::NewMemberCommit => self.joiner.clone(),
                _ => proposer_leaf.and_then(|leaf| member_uri(&self.group, leaf)),
            };
            if matches!(queued.sender(), Sender::NewMemberCommit)
                && user.is_some()
                && user == proposer
            {
                continue;
            }
            removed.push(RemovedLeaf { user, proposer });
        }
        let mut added: Vec<Option<String>> = self
            .staged
            .add_proposals()
            .map(|add| {
                let leaf = add.add_proposal().key_package().leaf_node();
                user_uri(leaf.credential(), leaf.signature_key().as_slice())
            })
            .collect();
        if let Some(joiner) = &self.joiner {
            added.push(Some(joiner.clone()));
        }
        let mut leaves_after: Vec<Option<String>> = self
            .group
            .members()
            .filter(|member| !removed_at.contains(&member.index))
            .map(|member| user_uri(&member.credential, &member.signature_key))
            .collect();
        leaves_after.extend(added.iter().cloned());
        // A client's new leaf must name the user its old one did: each Update by its sender, and a member committer's
        // leaf in its update path (an external Commit's joiner is a new client, counted among the added).
        let credential_before = |leaf: LeafNodeIndex| {
            self.group.leaf(leaf).map(|node| {
                (
                    node.credential().clone(),
                    node.signature_key().as_slice().to_vec(),
                )
            })
        };
        let mut renewed: Vec<Renewal> = self
            .staged
            .update_proposals()
            .filter_map(|update| match update.sender() {
                Sender::Member(leaf) => {
                    let new = update.update_proposal().leaf_node();
                    Some((
                        credential_before(*leaf),
                        (
                            new.credential().clone(),
                            new.signature_key().as_slice().to_vec(),
                        ),
                    ))
                }
                _ => None,
            })
            .collect();
        if self.joiner.is_none() {
            if let Some(leaf) = self.staged.update_path_leaf_node() {
                renewed.push((
                    self.committer_leaf.and_then(credential_before),
                    (
                        leaf.credential().clone(),
                        leaf.signature_key().as_slice().to_vec(),
                    ),
                ));
            }
        }
        let users = |list: Option<ParticipantListData>| -> Vec<(String, u32)> {
            list.map(|list| {
                list.participants
                    .into_iter()
                    .map(|pair| (mimi_core::uri::canonical(&pair.user_uri), pair.role_index))
                    .collect()
            })
            .unwrap_or_default()
        };
        Ok(ListAndLeaves {
            before: match before {
                Some(_) => users(before),
                None => hub_before,
            },
            after: match after {
                Some(_) => users(after).into_iter().map(|(user, _)| user).collect(),
                None => hub_after,
            },
            added,
            removed,
            leaves_after,
            renewed,
        })
    }
}

/// A seeding bundle that passed every check, not written yet: what `write_seed` stores for the room.
pub(crate) struct SeedCandidate {
    tree: RatchetTreeIn,
    info: VerifiableGroupInfo,
    group_id: Vec<u8>,
    /// The provider of the GroupInfo's signer: the peer that sent the bundle.
    provider: String,
    /// The GroupInfo's signer's user, and its leaf.
    pub(crate) signer: String,
    pub(crate) signer_leaf: u32,
    /// The room policy, participant list, operational policy and room metadata of the group's GroupContext.
    pub(crate) policy: Option<mimi_core::room_policy::RoomPolicy>,
    pub(crate) list: Option<mimi_core::participant_list::ParticipantListData>,
    operational: Option<Vec<u8>>,
    metadata: Option<Vec<u8>>,
}

/// What `write_seed` stores, handed to the writes it runs as one group.
struct SeedParts<'p> {
    tree: RatchetTreeIn,
    info: VerifiableGroupInfo,
    group_id: Vec<u8>,
    provider: &'p str,
    policy: Option<mimi_core::room_policy::RoomPolicy>,
    list: Option<mimi_core::participant_list::ParticipantListData>,
    operational: Option<Vec<u8>>,
    metadata: Option<Vec<u8>>,
}

/// The leaf a member-sent Commit's `PublicMessage` names as its sender, read without a group.
pub(crate) fn commit_sender_leaf(commit: &[u8]) -> Option<u32> {
    let message = MlsMessageIn::tls_deserialize_exact(commit)
        .ok()?
        .try_into_protocol_message()
        .ok()?;
    match message {
        ProtocolMessage::PublicMessage(public) => match public.sender() {
            Sender::Member(leaf) => Some(leaf.u32()),
            _ => None,
        },
        _ => None,
    }
}

/// The committer's leaf after `staged`: a member's own leaf, which its Commit does not move, or the leaf an external
/// Commit's joiner is added at, the leftmost one no member holds once the Commit's removals are made (RFC 9420 §12.4.1:
/// "the leftmost blank leaf node in the new ratchet tree", the tree extended as §7.7 says when it has none; trimming
/// blank leaves off its right does not change which one that is).
fn committer_leaf_after(
    group: &PublicGroup,
    staged: &StagedCommit,
    committer: Option<LeafNodeIndex>,
) -> LeafNodeIndex {
    if let Some(leaf) = committer {
        return leaf;
    }
    let removed: Vec<LeafNodeIndex> = staged
        .remove_proposals()
        .map(|proposal| proposal.remove_proposal().removed())
        .collect();
    let held: std::collections::BTreeSet<u32> = group
        .members()
        .map(|member| member.index)
        .filter(|leaf| !removed.contains(leaf))
        .map(|leaf| leaf.u32())
        .collect();
    LeafNodeIndex::new((0..).find(|leaf| !held.contains(leaf)).unwrap_or(u32::MAX))
}

/// The key the committer of `staged` signs a GroupInfo with after it: its leaf in the Commit's update path when there is
/// one (an external Commit's joiner always has one), else its leaf in the tree. A GroupInfo is verified under this key, so
/// one another member signed does not verify, whatever leaf it names.
fn committer_key(
    group: &PublicGroup,
    staged: &StagedCommit,
    committer: Option<LeafNodeIndex>,
) -> Option<OpenMlsSignaturePublicKey> {
    let key = match staged.update_path_leaf_node() {
        Some(leaf) => leaf.signature_key().clone(),
        None => group.leaf(committer?)?.signature_key().clone(),
    };
    Some(OpenMlsSignaturePublicKey::from_signature_key(
        key,
        group.ciphersuite().signature_algorithm(),
    ))
}

/// Why a Commit could not be staged on a room's group.
enum StageError {
    /// It does not verify or does not apply to the group.
    DoesNotApply,
    /// The shared resolver refuses its AppDataUpdates.
    AppData(AppDataError),
    /// Its AppDataUpdates, resolved, do not apply.
    AppDataDoesNotApply(Sender),
    /// It is not a Commit.
    NotACommit(Sender),
}

/// Verify `message` against `group` and stage it, without changing the group: its sender and the staged Commit. Each
/// component's AppDataUpdates go to the one resolver this hub and its clients share, together and in the Commit's order
/// (draft-ietf-mls-extensions §4.7); the participant list's all index the list before the Commit (protocol-07 §7.5).
fn stage_commit(
    group: &PublicGroup,
    crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
    message: ProtocolMessage,
) -> Result<(Sender, StagedCommit), StageError> {
    let processed = group
        .process_message(crypto, message)
        .map_err(|_| StageError::DoesNotApply)?;
    let sender = processed.sender().clone();
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => *staged,
        ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) => {
            let mut by_component: Vec<(u16, Vec<ComponentChange<'_>>)> = Vec::new();
            for proposal in unresolved.app_data_update_proposals() {
                let component = proposal.component_id();
                let change = match proposal.operation() {
                    AppDataUpdateOperation::Remove => ComponentChange::Remove,
                    AppDataUpdateOperation::Update(data) => {
                        ComponentChange::Update(data.as_slice())
                    }
                };
                match by_component.last_mut() {
                    Some((last, changes)) if *last == component => changes.push(change),
                    _ => by_component.push((component, vec![change])),
                }
            }
            let mut updater = group.app_data_dictionary_updater();
            for (component, changes) in &by_component {
                let before = updater.old_value(*component);
                let value =
                    resolve_component(*component, before, changes).map_err(StageError::AppData)?;
                match value {
                    Some(value) => updater.set(openmls::component::ComponentData::from_parts(
                        *component,
                        value.into(),
                    )),
                    None => updater.remove(component),
                }
            }
            let changes = updater.changes();
            group
                .stage_app_data_commit(crypto, *unresolved, changes)
                .map_err(|_| StageError::AppDataDoesNotApply(sender.clone()))?
        }
        _ => return Err(StageError::NotACommit(sender)),
    };
    Ok((sender, staged))
}

/// The most extensions a Partial GroupInfo may hold for the hub to try its tree at every place among them; past this,
/// only at the two ends. Each place tried is one GroupInfo built and one signature checked.
// LIMIT-REASON: input: implementations put a handful of extensions in a GroupInfo; this bounds the tries one Commit costs
pub const MAX_TREE_PLACES_EXTENSIONS: usize = 16;

/// The places a Partial GroupInfo's tree is tried at, for a list of `count` extensions, in order: last (the draft's),
/// first (openmls's), then each place between them, those only up to [`MAX_TREE_PLACES_EXTENSIONS`].
fn tree_places(count: usize) -> Vec<TreeAt> {
    let mut places = vec![TreeAt::Last];
    if count > 0 {
        places.push(TreeAt::First);
    }
    if count <= MAX_TREE_PLACES_EXTENSIONS {
        places.extend((1..count).map(TreeAt::Before));
    }
    places
}

/// The GroupInfos a Partial GroupInfo stands for, each built only when asked for, in the order [`tree_places`] gives.
pub(crate) struct Rebuilds {
    partial: PartialGroupInfo,
    group_context: Vec<u8>,
    tree: Option<Vec<u8>>,
    confirmation_tag: Vec<u8>,
    signer: u32,
    places: std::vec::IntoIter<Option<TreeAt>>,
}

impl Iterator for Rebuilds {
    type Item = Result<Vec<u8>, RebuildError>;

    fn next(&mut self) -> Option<Self::Item> {
        let at = self.places.next()?;
        let tree = self.tree.as_deref().zip(at);
        // The tree is given exactly when the presence calls for one, so a rebuild fails only in encoding.
        Some(
            self.partial
                .group_info(
                    &self.group_context,
                    tree,
                    &self.confirmation_tag,
                    self.signer,
                )
                .map_err(|_| RebuildError::Hub),
        )
    }
}

/// Why a Partial GroupInfo could not be rebuilt: on the sender's side, or on the hub's.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RebuildError {
    /// The Partial GroupInfo does not decode.
    DoesNotDecode,
    /// The Commit has no confirmation tag.
    NoConfirmationTag,
    /// The hub could not rebuild the tree after the Commit, or encode what it rebuilt.
    Hub,
}

/// The user a Commit's sender is, when it is a member named by its credential.
fn sender_uri(group: &PublicGroup, sender: &Sender) -> Option<String> {
    match sender {
        Sender::Member(leaf) => member_uri(group, *leaf),
        _ => None,
    }
}

/// The refusal for a Commit whose AppDataUpdates the shared resolver refuses.
fn app_data_refusal(error: AppDataError) -> UpdateRefusal {
    const DOES_NOT_APPLY: &str = "the participant list update does not apply to the room's list";
    const NOT_READ: &str = "the Commit changes an app data component this hub does not read";
    match error {
        AppDataError::Malformed(_) => {
            UpdateRefusal::Invalid("the participant list update is malformed")
        }
        AppDataError::StoredList(_) => UpdateRefusal::Store,
        AppDataError::DoesNotApply(_) | AppDataError::ListRemoved | AppDataError::Shape(_) => {
            UpdateRefusal::Invalid(DOES_NOT_APPLY)
        }
        AppDataError::Unknown(_) => UpdateRefusal::Invalid(NOT_READ),
    }
}

/// Why a `RoomMetaData` was refused for a room.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MetadataRefusal {
    /// It does not decode within its bounds.
    Malformed,
    /// It names another room.
    AnotherRoom,
}

/// Check a `RoomMetaData` (protocol-07 §10.4) for `room_uri`: it decodes within its bounds and names that room, compared
/// canonically. Display data the hub enforces nothing from, but it names its own room, in an update and at seeding.
pub(crate) fn check_room_metadata(bytes: &[u8], room_uri: &str) -> Result<(), MetadataRefusal> {
    let read = mimi_core::room_metadata::decode_room_metadata(bytes)
        .map_err(|_| MetadataRefusal::Malformed)?;
    if mimi_core::uri::canonical(&read.room_uri) != mimi_core::uri::canonical(room_uri) {
        return Err(MetadataRefusal::AnotherRoom);
    }
    Ok(())
}

/// One component of a GroupContext's app data dictionary.
pub(crate) fn app_data(context: &openmls::group::GroupContext, component: u16) -> Option<&[u8]> {
    context
        .extensions()
        .app_data_dictionary()
        .and_then(|extension| extension.dictionary().get(&component))
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
        .and_then(|node| user_uri(node.credential(), node.signature_key().as_slice()))
}

/// A tracked room's proposals, verified against its tree and not queued yet.
pub struct VerifiedProposals {
    group: PublicGroup,
    queued: Vec<openmls::prelude::QueuedProposal>,
    /// Each proposal's sender's user, in the order given.
    pub(crate) senders: Vec<Option<String>>,
}

impl VerifiedProposals {
    /// Queue every proposal in the room's group.
    pub(crate) fn queue(
        self,
        groups: &crate::group_store::GroupStore<'_>,
    ) -> Result<(), UpdateRefusal> {
        let Self {
            mut group, queued, ..
        } = self;
        for proposal in queued {
            group
                .add_proposal(groups, proposal)
                .map_err(|_| UpdateRefusal::Store)?;
        }
        Ok(())
    }
}

impl Provider {
    /// The tracked room's ratchet tree, as a `full` RatchetTreeOption.
    pub(crate) fn tree_option(&self, tracking: &RoomTracking) -> Option<Vec<u8>> {
        let group = PublicGroup::load(
            &self.store.groups(),
            &GroupId::from_slice(&tracking.group_id),
        )
        .ok()
        .flatten()?;
        let tree = group.export_ratchet_tree().tls_serialize_detached().ok()?;
        Some([&[RATCHET_TREE_FULL][..], &tree].concat())
    }

    /// The room's tracking record, when the hub keeps its tree.
    pub fn room_tracking(&self, room_uri: &str) -> anyhow::Result<Option<RoomTracking>> {
        self.store.room_tree(room_uri)
    }

    /// Stop keeping the room's tree: its group state and tracking record go, and its next bundle with a Full GroupInfo
    /// and a full tree seeds it again. The operator's way out of a room stuck on a tree the hub cannot apply Commits to.
    pub fn untrack_room(&self, room_uri: &str) -> anyhow::Result<bool> {
        self.assert_hub_of_record(room_uri)?;
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
                "[mimihubd] refused a Commit for {room_uri} (tracked, seeded by {}) from {}: {why}",
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
        // The Commit's confirmation tag, which a Partial GroupInfo leaves for the hub to fill in.
        let confirmation_tag = match &message {
            ProtocolMessage::PublicMessage(public) => public
                .confirmation_tag()
                .and_then(|tag| tag.tls_serialize_detached().ok()),
            _ => None,
        };
        let (processed_sender, staged) =
            stage_commit(&group, crypto.crypto(), message).map_err(|error| match error {
                StageError::DoesNotApply => refused(
                    "it does not verify or apply to the room's tree",
                    None,
                    UpdateRefusal::NotAllowed,
                ),
                StageError::AppData(error) => app_data_refusal(error),
                StageError::AppDataDoesNotApply(sender) => refused(
                    "its AppDataUpdates do not apply",
                    sender_uri(&group, &sender).as_deref().and_then(provider_of),
                    UpdateRefusal::NotAllowed,
                ),
                StageError::NotACommit(sender) => refused(
                    "not a Commit",
                    sender_uri(&group, &sender).as_deref().and_then(provider_of),
                    UpdateRefusal::Invalid("the commit is not one this hub can read"),
                ),
            })?;
        let committer_leaf = match &processed_sender {
            Sender::Member(leaf) => Some(*leaf),
            _ => None,
        };
        let (sender, external) = match &processed_sender {
            Sender::Member(leaf) => (member_uri(&group, *leaf), false),
            // An external Commit: its joiner is named by the leaf its update path adds, once staged.
            Sender::NewMemberCommit => (None, true),
            _ => {
                return Err(refused(
                    "the sender is not a member",
                    None,
                    UpdateRefusal::NotAllowed,
                ))
            }
        };
        let sender_provider = sender.as_deref().and_then(provider_of);
        if let Some(group_info) = group_info {
            let signer = committer_leaf_after(&group, &staged, committer_leaf);
            // A Full GroupInfo as sent; a Partial one rebuilt from the group after the Commit, in each place its tree
            // may stand (ratchet-tree-options §4), one at a time, and taken if one of them is signed.
            let candidates: Box<dyn Iterator<Item = Result<Vec<u8>, RebuildError>>> = match group_info
                .representation
            {
                GroupInfoRepresentation::Full => Box::new(std::iter::once(Ok(group_info.payload.clone()))),
                GroupInfoRepresentation::Partial => Box::new(self
                    .rebuilt_group_infos(
                        tracking,
                        commit,
                        &group_info.payload,
                        &staged,
                        confirmation_tag.as_deref(),
                        signer,
                    )
                    .map_err(|error| match error {
                        RebuildError::DoesNotDecode => refused(
                            "its Partial GroupInfo does not decode",
                            sender_provider.clone(),
                            UpdateRefusal::Invalid("the Partial GroupInfo does not decode"),
                        ),
                        RebuildError::NoConfirmationTag => refused(
                            "its Commit has no confirmation tag to rebuild its Partial GroupInfo with",
                            sender_provider.clone(),
                            UpdateRefusal::Invalid("the Commit carries no confirmation tag"),
                        ),
                        RebuildError::Hub => refused(
                            "the hub could not rebuild the room's tree after it for its Partial GroupInfo",
                            sender_provider.clone(),
                            UpdateRefusal::Store,
                        ),
                    })?),
            };
            // Signed by the committer, with the key it holds after the Commit, before its GroupContext is compared: a
            // GroupInfo rewritten on its way here cannot make a hub whose group has drifted match it. It must also name
            // the committer's leaf as its signer, or every joiner, which verifies it under the key of the leaf it names,
            // would fail to.
            let key = committer_key(&group, &staged, committer_leaf);
            let mut info = None;
            for candidate in candidates {
                let bytes = candidate.map_err(|_| {
                    refused(
                        "the hub could not encode a GroupInfo rebuilt from its Partial GroupInfo",
                        sender_provider.clone(),
                        UpdateRefusal::Store,
                    )
                })?;
                info = VerifiableGroupInfo::tls_deserialize_exact(bytes.as_slice())
                    .ok()
                    .filter(|info| {
                        info.signer() == signer
                            && key
                                .as_ref()
                                .is_some_and(|key| info.verify_no_out(crypto.crypto(), key).is_ok())
                    });
                if info.is_some() {
                    break;
                }
            }
            let Some(info) = info else {
                return Err(refused(
                    "its GroupInfo is not signed by the committer",
                    sender_provider,
                    UpdateRefusal::Invalid("the GroupInfo is not signed by the Commit's sender"),
                ));
            };
            if info.group_context().tls_serialize_detached().ok()
                != staged.group_context().tls_serialize_detached().ok()
            {
                return Err(refused(
                    "its GroupInfo does not describe the group after it",
                    sender_provider,
                    UpdateRefusal::Invalid(
                        "the GroupInfo does not match the group after this Commit",
                    ),
                ));
            }
        }
        let joiner = external
            .then(|| staged.update_path_leaf_node())
            .flatten()
            .and_then(|leaf| user_uri(leaf.credential(), leaf.signature_key().as_slice()));
        if external && joiner.is_none() {
            return Err(refused(
                "an external Commit whose joiner names no user",
                None,
                UpdateRefusal::NotAllowed,
            ));
        }
        let had_roles_list = app_data(group.group_context(), ROLES_LIST_COMPONENT).is_some();
        Ok(StagedRoomCommit {
            group,
            staged,
            sender,
            had_roles_list,
            joiner,
            committer_leaf,
        })
    }

    /// The GroupInfos a Partial GroupInfo (ratchet-tree-options §4) stands for after `staged`: the GroupContext after the
    /// Commit, its extensions, the Commit's `confirmation_tag`, `signer` and its signature, with the tree after the
    /// Commit, when its presence says the GroupInfo carries one, at each place it may have stood ([`tree_places`]). They
    /// are built one at a time as the caller asks, so a GroupInfo whose tree is last or first costs what it did before.
    /// Fails on the sender's side when it does not decode (a ratchet_tree in it included) or the Commit has no
    /// confirmation tag, and on the hub's when the hub cannot rebuild the tree after the Commit.
    fn rebuilt_group_infos(
        &self,
        tracking: &RoomTracking,
        commit: &[u8],
        partial: &[u8],
        staged: &StagedCommit,
        confirmation_tag: Option<&[u8]>,
        signer: LeafNodeIndex,
    ) -> Result<Rebuilds, RebuildError> {
        let partial = PartialGroupInfo::decode(partial).map_err(|_| RebuildError::DoesNotDecode)?;
        let confirmation_tag = confirmation_tag.ok_or(RebuildError::NoConfirmationTag)?;
        let group_context = staged
            .group_context()
            .tls_serialize_detached()
            .map_err(|_| RebuildError::Hub)?;
        let (tree, places) = if partial.ratchet_tree_presence.in_current_epoch() {
            let tree = self.tree_after(tracking, commit).ok_or(RebuildError::Hub)?;
            // The list decoded once already, so it counts.
            let count = partial
                .extension_count()
                .map_err(|_| RebuildError::DoesNotDecode)?;
            (
                Some(tree),
                tree_places(count).into_iter().map(Some).collect(),
            )
        } else {
            (None, vec![None])
        };
        Ok(Rebuilds {
            partial,
            group_context,
            tree,
            confirmation_tag: confirmation_tag.to_vec(),
            signer: signer.u32(),
            places: Vec::into_iter(places),
        })
    }

    /// The room's ratchet tree after `commit`, encoded. A PublicGroup's staged Commit exports no tree, so the Commit is
    /// staged again on a second copy of the group, which is merged in memory; the room's stored group is not touched.
    fn tree_after(&self, tracking: &RoomTracking, commit: &[u8]) -> Option<Vec<u8>> {
        let scratch = OpenMlsRustCrypto::default();
        let groups = self.store.groups();
        let mut group =
            PublicGroup::load(&groups, &GroupId::from_slice(&tracking.group_id)).ok()??;
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .ok()?
            .try_into_protocol_message()
            .ok()?;
        let (_, staged) = stage_commit(&group, scratch.crypto(), message).ok()?;
        group.merge_commit(scratch.storage(), staged).ok()?;
        group.export_ratchet_tree().tls_serialize_detached().ok()
    }

    /// Verify a tracked room's proposals against its tree and queue them in its group for the Commit that will name them.
    /// All are verified before any is queued, so a refused one leaves the group as it was.
    #[cfg(test)]
    pub(crate) fn queue_tracked_proposals(
        &self,
        room_uri: &str,
        tracking: &RoomTracking,
        messages: &[&[u8]],
    ) -> Result<(), UpdateRefusal> {
        self.verify_tracked_proposals(room_uri, tracking, messages)?
            .queue(&self.store.groups())
    }

    /// Verify a tracked room's proposals against its tree, without queueing them: each one's sender, in order, for the
    /// caller to authorize before [`VerifiedProposals::queue`].
    pub(crate) fn verify_tracked_proposals(
        &self,
        room_uri: &str,
        tracking: &RoomTracking,
        messages: &[&[u8]],
    ) -> Result<VerifiedProposals, UpdateRefusal> {
        let crypto = OpenMlsRustCrypto::default();
        let group = PublicGroup::load(
            &self.store.groups(),
            &GroupId::from_slice(&tracking.group_id),
        )
        .map_err(|_| UpdateRefusal::Store)?
        .ok_or(UpdateRefusal::Store)?;
        let mut queued = Vec::with_capacity(messages.len());
        let mut senders = Vec::with_capacity(messages.len());
        for message in messages {
            let processed = MlsMessageIn::tls_deserialize_exact(*message)
                .ok()
                .and_then(|message| message.try_into_protocol_message().ok())
                .and_then(|message| group.process_message(crypto.crypto(), message).ok());
            let sender = processed
                .as_ref()
                .and_then(|processed| match processed.sender() {
                    Sender::Member(leaf) => member_uri(&group, *leaf),
                    _ => None,
                });
            match processed.map(|processed| processed.into_content()) {
                Some(ProcessedMessageContent::ProposalMessage(proposal)) => {
                    queued.push(*proposal);
                    senders.push(sender);
                }
                _ => {
                    eprintln!(
                        "[mimihubd] refused a proposal for {room_uri} (tracked, seeded by {}): it does not verify against the room's tree",
                        tracking.seeded_by
                    );
                    return Err(UpdateRefusal::NotAllowed);
                }
            }
        }
        Ok(VerifiedProposals {
            group,
            queued,
            senders,
        })
    }

    /// Merge a staged Commit into the room's group, once the hub has applied it to its own tables.
    pub(crate) fn merge_tracked_commit(
        &self,
        staged: StagedRoomCommit,
    ) -> Result<(), UpdateRefusal> {
        let StagedRoomCommit {
            mut group, staged, ..
        } = staged;
        group
            .merge_commit(&self.store.groups(), staged)
            .map_err(|_| UpdateRefusal::Store)
    }

    /// Seed an untracked room's tree from an accepted Commit's bundle, when it carries a Full GroupInfo and a full tree
    /// and they pass every check in the module doc. `commit_epoch` is the epoch the Commit was sent in. Anything short of
    /// that leaves the room untracked; the Commit itself is already accepted either way.
    pub(crate) fn seed_room_tree<'r>(
        &self,
        room_uri: &str,
        commit_epoch: u64,
        requester: impl Into<crate::requester::Requester<'r>>,
        group_info: &GroupInfoOption,
        ratchet_tree_option: &[u8],
    ) {
        if let Err(Some(why)) = self.try_seed_room_tree(
            room_uri,
            commit_epoch,
            requester.into(),
            group_info,
            ratchet_tree_option,
        ) {
            eprintln!("[mimihubd] {room_uri} stays untracked: {why}");
        }
    }

    /// `Err(None)`: the bundle does not carry what seeding needs (nothing to say); `Err(Some)`: it does, and a check
    /// refused it.
    fn try_seed_room_tree(
        &self,
        room_uri: &str,
        commit_epoch: u64,
        requester: crate::requester::Requester<'_>,
        group_info: &GroupInfoOption,
        ratchet_tree_option: &[u8],
    ) -> Result<(), Option<&'static str>> {
        let listed: Vec<String> = self
            .store
            .list_participant_rows(room_uri)
            .map_err(|_| Some("the room's participants could not be read"))?
            .into_iter()
            .map(|row| row.member_uri)
            .collect();
        let seed = self.verify_seed(
            room_uri,
            commit_epoch,
            requester,
            group_info,
            ratchet_tree_option,
            &listed,
        )?;
        self.write_seed(room_uri, commit_epoch, seed, group_info)
            .map_err(Some)
    }

    /// Check a seeding bundle for `room_uri` against every rule in the module doc without writing anything. `listed` is
    /// the room's participants as the hub will list them after the Commit; each must be a member of the tree.
    /// `Err(None)`: the bundle does not carry what seeding needs; `Err(Some)`: it does, and a check refused it.
    pub(crate) fn verify_seed(
        &self,
        room_uri: &str,
        commit_epoch: u64,
        requester: crate::requester::Requester<'_>,
        group_info: &GroupInfoOption,
        ratchet_tree_option: &[u8],
        listed: &[String],
    ) -> Result<SeedCandidate, Option<&'static str>> {
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
        if !requester.may_speak_for(&signer, &provider, &self.domain) {
            return Err(Some(
                "its GroupInfo's signer is not of the provider that sent it",
            ));
        }
        let members: Vec<String> = candidate
            .members()
            .filter_map(|member| user_uri(&member.credential, &member.signature_key))
            .collect();
        if listed
            .iter()
            .any(|user| !members.contains(&mimi_core::uri::canonical(user)))
        {
            return Err(Some("a participant the hub lists is not in its tree"));
        }
        // The room's policy and list are its GroupContext's from here (room-policy PR #52: a roles_list is set when the
        // group is created). Read and checked before anything is written.
        let context = candidate.group_context();
        let roles = app_data(context, ROLES_LIST_COMPONENT)
            .map(mimi_core::room_policy_wire::decode_role_data)
            .transpose()
            .map_err(|_| Some("its GroupContext's roles_list does not decode"))?;
        let base = app_data(context, BASE_ROOM_POLICY_COMPONENT)
            .map(mimi_core::room_policy_wire::decode_base_room_policy)
            .transpose()
            .map_err(|_| Some("its GroupContext's base_room_policy does not decode"))?;
        let policy = match roles {
            Some(roles) => {
                let policy = mimi_core::room_policy::RoomPolicy {
                    base: base.unwrap_or_default(),
                    roles,
                };
                policy
                    .validate()
                    .map_err(|_| Some("its GroupContext's room policy is not valid"))?;
                Some(policy)
            }
            None => None,
        };
        let operational = app_data(
            context,
            mimi_core::operational_parameters::OPERATIONAL_POLICY_COMPONENT_ID,
        )
        .map(|bytes| {
            mimi_core::operational_parameters::decode_operational_parameters(bytes)
                .map(|_| bytes.to_vec())
        })
        .transpose()
        .map_err(|_| Some("its GroupContext's operational policy does not decode"))?;
        // Display data the hub enforces nothing from, but it names its own room (protocol-07 §10.4), and the hub
        // refuses one naming another room at seeding as it does in an update.
        let metadata = app_data(
            context,
            mimi_core::room_metadata::ROOM_METADATA_COMPONENT_ID,
        );
        if let Some(bytes) = metadata {
            check_room_metadata(bytes, room_uri).map_err(|refusal| {
                Some(match refusal {
                    MetadataRefusal::Malformed => {
                        "its GroupContext's room metadata does not decode"
                    }
                    MetadataRefusal::AnotherRoom => {
                        "its GroupContext's room metadata names another room"
                    }
                })
            })?;
        }
        let metadata = metadata.map(<[u8]>::to_vec);
        let list = app_data(context, PARTICIPANT_LIST_COMPONENT)
            .map(decode_participant_list_data)
            .transpose()
            .map_err(|_| Some("its GroupContext's participant list does not decode"))?;
        if let Some(list) = &list {
            if list.participants.iter().any(|pair| {
                provider_of(&pair.user_uri).is_none()
                    || !members.contains(&mimi_core::uri::canonical(&pair.user_uri))
            }) {
                return Err(Some(
                    "a participant its GroupContext lists is not in its tree or names no provider",
                ));
            }
        }
        // Every client in the tree is a client of a listed user (room-policy-04 §8.1.2). The list after the Commit is the
        // GroupContext's when it carries one, else the hub's own with the Commit's change applied (`listed`).
        let listed_after: Vec<String> = match &list {
            Some(list) => list
                .participants
                .iter()
                .map(|pair| mimi_core::uri::canonical(&pair.user_uri))
                .collect(),
            None => listed
                .iter()
                .map(|user| mimi_core::uri::canonical(user))
                .collect(),
        };
        if candidate.members().any(|member| {
            user_uri(&member.credential, &member.signature_key)
                .is_none_or(|user| !listed_after.contains(&user))
        }) {
            return Err(Some(
                "a client in its tree is not a client of a participant it lists",
            ));
        }
        let signer_leaf = info.signer().u32();
        Ok(SeedCandidate {
            group_id: candidate.group_id().as_slice().to_vec(),
            tree,
            info,
            provider,
            signer,
            signer_leaf,
            policy,
            list,
            operational,
            metadata,
        })
    }

    /// Store a verified seed: the room is tracked from the epoch after the Commit, and its policy, participant list,
    /// operational policy and room metadata are its group's from here.
    pub(crate) fn write_seed(
        &self,
        room_uri: &str,
        commit_epoch: u64,
        seed: SeedCandidate,
        group_info: &GroupInfoOption,
    ) -> Result<(), &'static str> {
        let SeedCandidate {
            tree,
            info,
            group_id,
            provider,
            policy,
            list,
            operational,
            metadata,
            ..
        } = seed;
        // One group of writes: a failure at any step leaves nothing of the seed behind, not a tracked room missing its
        // policy or list.
        self.store
            .atomically(|| {
                self.write_seed_parts(
                    room_uri,
                    commit_epoch,
                    SeedParts {
                        tree,
                        info,
                        group_id,
                        provider: &provider,
                        policy,
                        list,
                        operational,
                        metadata,
                    },
                    group_info,
                )
            })
            .map_err(|_| "its seed could not be stored")??;
        eprintln!(
            "[mimihubd] {room_uri} is tracked from epoch {}, seeded by {provider}",
            commit_epoch + 1
        );
        Ok(())
    }

    /// The writes of [`Provider::write_seed`], in order; the caller runs them as one group.
    fn write_seed_parts(
        &self,
        room_uri: &str,
        commit_epoch: u64,
        parts: SeedParts<'_>,
        group_info: &GroupInfoOption,
    ) -> Result<(), &'static str> {
        let SeedParts {
            tree,
            info,
            group_id,
            provider,
            policy,
            list,
            operational,
            metadata,
        } = parts;
        let crypto = OpenMlsRustCrypto::default();
        PublicGroup::from_external(
            crypto.crypto(),
            &self.store.groups(),
            tree,
            info,
            ProposalStore::new(),
        )
        .map_err(|_| "its group could not be stored")?;
        self.store
            .set_room_tree(room_uri, &group_id, provider, commit_epoch + 1)
            .map_err(|_| "its tracking record could not be stored")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        match &policy {
            Some(policy) => self
                .set_room_policy(room_uri, policy, now)
                .map_err(|_| "its room policy could not be stored")?,
            None => self
                .store
                .clear_room_policy(room_uri)
                .map_err(|_| "its room policy could not be cleared")?,
        }
        if let Some(list) = list {
            let rows: Vec<crate::store::ParticipantRow> = list
                .participants
                .iter()
                .map(|pair| crate::store::ParticipantRow {
                    member_uri: mimi_core::uri::canonical(&pair.user_uri),
                    authority: provider_of(&pair.user_uri).unwrap_or_default(), // checked above
                    role_index: Some(pair.role_index),
                })
                .collect();
            self.store
                .replace_participants(room_uri, &rows, now)
                .map_err(|_| "its participant list could not be stored")?;
        }
        match &operational {
            Some(data) => self.store.set_operational_policy(room_uri, data),
            None => self.store.clear_operational_policy(room_uri),
        }
        .map_err(|_| "its operational policy could not be stored")?;
        // Kept as the GroupContext carries it, as an update's is kept as sent; none there, none here.
        match &metadata {
            Some(data) => self.store.set_room_metadata(room_uri, data, now),
            None => self.store.clear_room_metadata(room_uri),
        }
        .map_err(|_| "its room metadata could not be stored")?;
        self.keep_group_info_after(room_uri, commit_epoch + 1, Some(group_info));
        Ok(())
    }
}

#[cfg(test)]
#[path = "room_tree_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "room_tree_partial_tests.rs"]
mod partial_tests;

#[cfg(test)]
#[path = "room_tree_list_merge_tests.rs"]
mod list_merge_tests;

#[cfg(test)]
#[path = "room_tree_seed_metadata_tests.rs"]
mod seed_metadata_tests;

#[cfg(test)]
#[path = "room_tree_seed_atomic_tests.rs"]
mod seed_atomic_tests;

#[cfg(test)]
#[path = "room_tree_didwebvh_tests.rs"]
mod didwebvh_tests;
