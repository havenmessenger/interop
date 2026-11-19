//! A Commit that would seed a room's tree may not change what the hub holds for the room.
//!
//! The first Commit of an untracked room that carries a Full GroupInfo and a full ratchet tree seeds the room's tree, and
//! from then on the group's own components are the room's state (`room_tree.rs`). The room already has a state before
//! that: a lane room the deployment's profile (`client_lane_rooms.rs`), any other room what its operator or earlier
//! Commits set. A seed that carried another policy, operational policy or participant list would replace it with the
//! creator's choice; a group with no roles_list would drop the room's role checks, and one with no operational policy
//! its refusal of external Commits.
//!
//! So before such a Commit is accepted, the GroupInfo's GroupContext must hold exactly what the hub will hold after
//! the Commit: the room policy (roles_list and base policy) and the operational policy, as the hub holds them or as
//! this Commit changes them by value, and the participant list as the hub's list after this Commit's own
//! participant-list updates. Anything else is refused and nothing changes. A room the hub holds no policy for seeds as
//! before. The GroupInfo's signature is checked when the seed is made; this check only refuses.

use mimi_core::commit_wire::DecodedCommit;
use mimi_core::participant_list::{
    apply_updates, decode_participant_list_data, decode_participant_list_update,
    ParticipantListData, UserRolePair, MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
use mimi_core::room_policy::{
    RoomPolicy, MIMI_BASE_ROOM_POLICY_PROPOSAL_TYPE, MIMI_ROLES_LIST_PROPOSAL_TYPE,
};
use mimi_core::room_policy_wire::{decode_base_room_policy, decode_role_data};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::Deserialize as _;

use crate::room_tree::{
    app_data, full_ratchet_tree, BASE_ROOM_POLICY_COMPONENT, ROLES_LIST_COMPONENT,
};
use crate::{Provider, UpdateRefusal};

const POLICY_DIFFERS: UpdateRefusal = UpdateRefusal::Policy(
    "the GroupInfo seeding the room's tree does not carry the room's policy (its roles_list and base room policy)",
);
const OPERATIONAL_DIFFERS: UpdateRefusal = UpdateRefusal::Policy(
    "the GroupInfo seeding the room's tree does not carry the room's operational policy",
);
const LIST_DIFFERS: UpdateRefusal = UpdateRefusal::Policy(
    "the GroupInfo seeding the room's tree lists other participants or roles than the room has after this Commit",
);

impl Provider {
    /// Refuse a seeding Commit whose GroupInfo's GroupContext differs from what the hub holds for the room after it.
    /// `group_info` and `ratchet_tree` are the Commit's bundle; a bundle that would not seed is not checked.
    pub(crate) fn check_seed_keeps_room_state(
        &self,
        room_uri: &str,
        commit: &DecodedCommit,
        group_info: &GroupInfoOption,
        ratchet_tree: &[u8],
    ) -> Result<(), UpdateRefusal> {
        if group_info.representation != GroupInfoRepresentation::Full
            || full_ratchet_tree(ratchet_tree).is_none()
        {
            return Ok(());
        }
        let Ok(info) = VerifiableGroupInfo::tls_deserialize_exact(group_info.payload.as_slice())
        else {
            // Not a GroupInfo: the seed refuses it in its turn, and the room stays as it is.
            return Ok(());
        };
        let context = info.group_context();

        // What the Commit sets by value; the table path checks these are the committer's to set.
        let mut roles = None;
        let mut base = None;
        let mut operational = None;
        let mut list_updates = Vec::new();
        for change in &commit.updates {
            match change.proposal_type {
                MIMI_ROLES_LIST_PROPOSAL_TYPE => roles = decode_role_data(&change.payload).ok(),
                MIMI_BASE_ROOM_POLICY_PROPOSAL_TYPE => {
                    base = decode_base_room_policy(&change.payload).ok()
                }
                mimi_core::operational_parameters::MIMI_OPERATIONAL_POLICY_PROPOSAL_TYPE => {
                    operational = Some(change.payload.clone());
                }
                MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE => {
                    let mut update =
                        decode_participant_list_update(&change.payload).map_err(|_| {
                            UpdateRefusal::Invalid("the participant list update is malformed")
                        })?;
                    for added in &mut update.added_participants {
                        added.user_uri = mimi_core::uri::canonical(&added.user_uri);
                    }
                    list_updates.push(update);
                }
                _ => {}
            }
        }

        if let Some(held) = self
            .room_policy(room_uri)
            .map_err(|_| UpdateRefusal::Store)?
        {
            let want = RoomPolicy {
                base: base.unwrap_or(held.base),
                roles: roles.unwrap_or(held.roles),
            };
            let got_roles = app_data(context, ROLES_LIST_COMPONENT)
                .map(decode_role_data)
                .transpose()
                .map_err(|_| POLICY_DIFFERS)?
                .ok_or(POLICY_DIFFERS)?;
            let got_base = app_data(context, BASE_ROOM_POLICY_COMPONENT)
                .map(decode_base_room_policy)
                .transpose()
                .map_err(|_| POLICY_DIFFERS)?
                .unwrap_or_default();
            if got_roles != want.roles || got_base != want.base {
                return Err(POLICY_DIFFERS);
            }
        }

        let held_operational = self
            .store
            .operational_policy(room_uri)
            .map_err(|_| UpdateRefusal::Store)?;
        if let Some(want) = operational.or(held_operational) {
            let got = app_data(
                context,
                mimi_core::operational_parameters::OPERATIONAL_POLICY_COMPONENT_ID,
            );
            if got != Some(want.as_slice()) {
                return Err(OPERATIONAL_DIFFERS);
            }
        }

        if let Some(list) = app_data(context, crate::room_tree::PARTICIPANT_LIST_COMPONENT) {
            let got = decode_participant_list_data(list).map_err(|_| LIST_DIFFERS)?;
            let rows = self
                .store
                .list_participant_rows(room_uri)
                .map_err(|_| UpdateRefusal::Store)?;
            let before = ParticipantListData {
                participants: rows
                    .iter()
                    .map(|row| UserRolePair {
                        user_uri: row.member_uri.clone(),
                        role_index: row.role_index.unwrap_or(0),
                    })
                    .collect(),
            };
            let want = apply_updates(&before, &list_updates).map_err(|_| LIST_DIFFERS)?;
            // A member the hub holds no role for may take any role in the group; every other one keeps its role.
            let unroled: Vec<&str> = rows
                .iter()
                .filter(|row| row.role_index.is_none())
                .map(|row| row.member_uri.as_str())
                .collect();
            let mut want: Vec<(String, Option<u32>)> = want
                .participants
                .into_iter()
                .map(|pair| {
                    let role =
                        (!unroled.contains(&pair.user_uri.as_str())).then_some(pair.role_index);
                    (mimi_core::uri::canonical(&pair.user_uri), role)
                })
                .collect();
            let mut got: Vec<(String, Option<u32>)> = got
                .participants
                .into_iter()
                .map(|pair| {
                    let uri = mimi_core::uri::canonical(&pair.user_uri);
                    let role = (!unroled.contains(&uri.as_str())).then_some(pair.role_index);
                    (uri, role)
                })
                .collect();
            want.sort();
            got.sort();
            if got != want {
                return Err(LIST_DIFFERS);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "seed_check_tests.rs"]
mod tests;
