//! A room hosted here whose ratchet tree the hub does not keep.
//!
//! The hub enforces the room's policy (protocol-07 §9), and it can tell who proposed a change only against the room's
//! tree: a PublicMessage's sender is a leaf, and its signature verifies only under that leaf's key. Protocol-07 §5.3
//! lets the client choose what a Commit's bundle carries, so a room can reach the hub without its tree. Such a room is
//! not left unchecked:
//!
//! - **Its first Commit must give the hub the tree.** A room the hub has accepted no Commit for takes one only when its
//!   bundle carries a Full GroupInfo and the full ratchet tree (ratchet-tree-options `full`) and they seed the room
//!   (`room_tree.rs`); otherwise it is refused (`notAllowed`), saying so. From then on any `RatchetTreeOption` will do:
//!   the hub moves the tree on from each Commit it accepts.
//! - **Without the tree it takes no change that needs the proposer.** A room that has Commits but no tree (one from
//!   before the hub kept trees, or after the operator's `untrackRoom`) takes a Commit carrying a participant-list or
//!   room-policy change by value only when the bundle seeds it. Without the GroupContext the hub cannot tell whether the
//!   group has a `roles_list`, so every such change is treated as needing it. A Commit that only commits held leaves
//!   (bound to the requester when they were held) or changes room metadata is taken as before.
//! - **A seed this needs is checked before anything changes.** A bundle that fails a seed check refuses the Commit.
//! - **The seeding Commit's changes are authorized for its committer**, as a tracked room's are (room-policy-04 §8.1):
//!   the GroupInfo's signer, which must be the leaf that sent the Commit, against the room's policy before the Commit
//!   (the hub's, or for a room it holds none for, the group's) and the room's list before it. A room's creator is in its
//!   group's list from its creation, which no Commit carries, so for a room the hub has seen no Commit or participant
//!   for, the list before its first Commit is the creator alone.

use mimi_core::commit_wire::{DecodedCommit, DecodedCustomProposal};
use mimi_core::participant_list::{
    apply_updates, decode_participant_list_update, ParticipantListData, UserRolePair,
    MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
use mimi_core::room_policy::{MIMI_BASE_ROOM_POLICY_PROPOSAL_TYPE, MIMI_ROLES_LIST_PROPOSAL_TYPE};

use crate::room_tree::{commit_sender_leaf, full_ratchet_tree, SeedCandidate};
use crate::store::ParticipantRow;
use crate::{Provider, UpdateRefusal};

const NEEDS_TREE: UpdateRefusal = UpdateRefusal::Policy(
    "this hub needs a Full GroupInfo and the full ratchet tree (ratchet-tree-options `full`) with a room's first \
     Commit, and with any participant-list or room-policy change to a room whose tree it does not keep",
);
const NOT_THE_SENDER: UpdateRefusal = UpdateRefusal::Policy(
    "the GroupInfo seeding the room's tree is not signed by the member that sent the Commit",
);
const POLICY_UNKNOWN: UpdateRefusal = UpdateRefusal::Policy(
    "a room-policy change in the Commit that gives the hub the room's tree, for a room it holds no policy for",
);

/// Whether a change carried by value needs its proposer: a participant-list or room-policy change.
fn needs_proposer(change: &DecodedCustomProposal) -> bool {
    matches!(
        change.proposal_type,
        MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE
            | MIMI_ROLES_LIST_PROPOSAL_TYPE
            | MIMI_BASE_ROOM_POLICY_PROPOSAL_TYPE
            | mimi_core::operational_parameters::MIMI_OPERATIONAL_POLICY_PROPOSAL_TYPE
    )
}

fn is_policy_change(change: &DecodedCustomProposal) -> bool {
    needs_proposer(change) && change.proposal_type != MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE
}

/// The participant-list updates among `changes`, users in one form.
fn list_updates(
    changes: &[DecodedCustomProposal],
) -> Result<Vec<mimi_core::participant_list::ParticipantListUpdate>, UpdateRefusal> {
    changes
        .iter()
        .filter(|change| change.proposal_type == MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE)
        .map(|change| {
            decode_participant_list_update(&change.payload).map(|mut update| {
                for added in &mut update.added_participants {
                    added.user_uri = mimi_core::uri::canonical(&added.user_uri);
                }
                update
            })
        })
        .collect::<Result<_, _>>()
        .map_err(|_| UpdateRefusal::Invalid("the participant list update is malformed"))
}

impl Provider {
    /// The creator of a room whose first Commit this is and that the hub lists no one for, when the bundle's group
    /// names it (its GroupInfo's signer, in a group with a participant list): the list before the Commit is the creator
    /// alone (`seed_check.rs`). `None` for any other room, or a bundle that would not seed.
    pub(crate) fn new_room_creator<'r>(
        &self,
        room_uri: &str,
        commit_epoch: u64,
        group_info: &GroupInfoOption,
        ratchet_tree: &[u8],
        requester: crate::requester::Requester<'r>,
    ) -> Result<Option<String>, UpdateRefusal> {
        let first = self
            .store
            .room_epoch(room_uri)
            .map_err(|_| UpdateRefusal::Store)?
            .is_none();
        let listed = self
            .store
            .list_participant_rows(room_uri)
            .map_err(|_| UpdateRefusal::Store)?;
        if !first || !listed.is_empty() {
            return Ok(None);
        }
        Ok(self
            .verify_seed(commit_epoch, requester, group_info, ratchet_tree, &[])
            .ok()
            .filter(|seed| seed.list.is_some())
            .map(|seed| seed.signer))
    }

    /// Whether an untracked room hosted here takes `commit` (its changes by value, before held ones are read in) only
    /// with a seeding bundle: its first Commit, or one carrying a change that needs its proposer.
    pub(crate) fn untracked_needs_seed(
        &self,
        room_uri: &str,
        commit: &DecodedCommit,
    ) -> Result<bool, UpdateRefusal> {
        let first = self
            .store
            .room_epoch(room_uri)
            .map_err(|_| UpdateRefusal::Store)?
            .is_none();
        Ok(first || commit.updates.iter().any(needs_proposer))
    }

    /// The seed an untracked room's Commit needs, verified, with the Commit's changes by value (`by_value`) authorized
    /// for its committer. `commit` has its held proposals read in, so the list it leaves is the one checked against the
    /// tree. Returns the seed and, for a room whose first Commit this is and that lists no one yet, its creator.
    pub(crate) fn required_seed<'r>(
        &self,
        room_uri: &str,
        commit_bytes: &[u8],
        commit: &DecodedCommit,
        by_value: &[DecodedCustomProposal],
        bundle: Option<(&GroupInfoOption, &Vec<u8>)>,
        requester: crate::requester::Requester<'r>,
    ) -> Result<(SeedCandidate, Option<String>), UpdateRefusal> {
        let Some((group_info, ratchet_tree)) = bundle else {
            return Err(NEEDS_TREE);
        };
        if group_info.representation != GroupInfoRepresentation::Full
            || full_ratchet_tree(ratchet_tree).is_none()
        {
            return Err(NEEDS_TREE);
        }
        let rows = self
            .store
            .list_participant_rows(room_uri)
            .map_err(|_| UpdateRefusal::Store)?;
        let first = self
            .store
            .room_epoch(room_uri)
            .map_err(|_| UpdateRefusal::Store)?
            .is_none();
        let before = ParticipantListData {
            participants: rows
                .iter()
                .map(|row| UserRolePair {
                    user_uri: row.member_uri.clone(),
                    role_index: row.role_index.unwrap_or(0),
                })
                .collect(),
        };
        let listed: Vec<String> = apply_updates(&before, &list_updates(&commit.updates)?)
            .map_err(|_| {
                UpdateRefusal::Invalid(
                    "the participant list update does not apply to the room's list",
                )
            })?
            .participants
            .into_iter()
            .map(|pair| pair.user_uri)
            .collect();
        let seed = self
            .verify_seed(commit.epoch, requester, group_info, ratchet_tree, &listed)
            .map_err(|why| why.map_or(NEEDS_TREE, UpdateRefusal::Policy))?;
        if commit_sender_leaf(commit_bytes) != Some(seed.signer_leaf) {
            return Err(NOT_THE_SENDER);
        }
        let creator =
            (first && rows.is_empty() && seed.list.is_some()).then(|| seed.signer.clone());
        let policy = match self
            .room_policy(room_uri)
            .map_err(|_| UpdateRefusal::Store)?
        {
            Some(policy) => Some(policy),
            None if by_value.iter().any(is_policy_change) => return Err(POLICY_UNKNOWN),
            None => seed.policy.clone(),
        };
        let rows_before = match &creator {
            Some(creator) => vec![ParticipantRow {
                member_uri: creator.clone(),
                authority: mimi_core::uri::MimiUri::parse(creator)
                    .map(|uri| uri.authority.to_ascii_lowercase())
                    .unwrap_or_default(),
                role_index: seed.list.as_ref().and_then(|list| {
                    list.participants
                        .iter()
                        .find(|pair| mimi_core::uri::canonical(&pair.user_uri) == *creator)
                        .map(|pair| pair.role_index)
                }),
            }],
            None => rows,
        };
        crate::role_checks::authorize_by_value(
            policy.as_ref(),
            &rows_before,
            Some(&seed.signer),
            by_value,
        )?;
        Ok((seed, creator))
    }
}
