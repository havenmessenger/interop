//! External joins to a room this hub hosts (protocol-07 §5.6, room-policy-04 §7.1 and §8.1): whether the room allows
//! them, and who may join that way.
//!
//! A room allows external Commits when its `mls_operational_policy` component says `external_commit_allowed`; a room
//! with no such component follows MLS, where an external join is possible, unless the deployment's policy sets
//! `external_commit_when_unset = "deny"`. Who may join: a listed participant whose role holds `canAddOwnClient` (a new
//! client of its user), or an unlisted user when role 0 holds `canOpenJoin`, whose external Commit then adds that user,
//! and only that user, to the participant list. A room with no roles has no role checks (room-policy PR #52).
//! Preauthorized users and joining codes are not read (DIVERGENCES).

use mimi_core::operational_parameters::{decode_operational_parameters, OperationalParameters};
use mimi_core::participant_list::ParticipantListUpdate;
use mimi_core::room_policy::Capability;

use crate::policy::ExternalCommitWhenUnset;
use crate::{Provider, UpdateRefusal};

const NOT_ALLOWED_HERE: UpdateRefusal =
    UpdateRefusal::Policy("the room's policy does not allow external Commits");
const MAY_NOT_JOIN: UpdateRefusal =
    UpdateRefusal::Policy("the joiner may not join this room by an external Commit");
const ONLY_ITSELF: UpdateRefusal = UpdateRefusal::Policy(
    "an external Commit may change the participant list only to add its joiner",
);

impl Provider {
    /// The room's operational policy, if it has one.
    pub fn operational_parameters(
        &self,
        room_uri: &str,
    ) -> anyhow::Result<Option<OperationalParameters>> {
        match self.store.operational_policy(room_uri)? {
            Some(bytes) => Ok(Some(decode_operational_parameters(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Whether the room allows external Commits at all.
    pub fn external_commits_allowed(&self, room_uri: &str) -> anyhow::Result<bool> {
        Ok(match self.operational_parameters(room_uri)? {
            Some(parameters) => parameters.external_commit_allowed,
            None => self.policy().external_commit_when_unset == ExternalCommitWhenUnset::Allow,
        })
    }

    /// Whether `user` (a canonical URI) may join the room by an external Commit, with `change` the participant-list
    /// change the Commit carries, if any.
    pub(crate) fn authorize_external_join(
        &self,
        room_uri: &str,
        user: &str,
        change: Option<&ParticipantListUpdate>,
    ) -> Result<(), UpdateRefusal> {
        if !self
            .external_commits_allowed(room_uri)
            .map_err(|_| UpdateRefusal::Store)?
        {
            return Err(NOT_ALLOWED_HERE);
        }
        let adds_itself = match change {
            None => false,
            Some(change) => {
                if !change.removed_indices.is_empty()
                    || !change.changed_role_participants.is_empty()
                    || change.added_participants.len() != 1
                    || change.added_participants[0].user_uri != user
                {
                    return Err(ONLY_ITSELF);
                }
                true
            }
        };
        let listed = self
            .store
            .list_participant_rows(room_uri)
            .map_err(|_| UpdateRefusal::Store)?
            .into_iter()
            .find(|row| row.member_uri == user);
        if listed.is_some() && adds_itself {
            return Err(ONLY_ITSELF);
        }
        let policy = self
            .room_policy(room_uri)
            .map_err(|_| UpdateRefusal::Store)?
            .filter(|policy| !policy.roles.is_empty());
        let Some(policy) = policy else {
            return if listed.is_some() || adds_itself {
                Ok(())
            } else {
                Err(MAY_NOT_JOIN)
            };
        };
        let allowed = match listed {
            Some(row) => row
                .role_index
                .and_then(|role| policy.role(role))
                .is_some_and(|role| role.has(Capability::AddOwnClient)),
            None => {
                adds_itself
                    && policy
                        .role(0)
                        .is_some_and(|role| role.has(Capability::OpenJoin))
            }
        };
        if allowed {
            Ok(())
        } else {
            Err(MAY_NOT_JOIN)
        }
    }

    /// Keep `data` (an `OperationalParameters` already read) as the room's operational policy; a room that no longer
    /// allows external Commits keeps no GroupInfo.
    pub(crate) fn set_operational_policy(
        &self,
        room_uri: &str,
        data: &[u8],
    ) -> Result<(), UpdateRefusal> {
        self.store
            .set_operational_policy(room_uri, data)
            .map_err(|_| UpdateRefusal::Store)?;
        if !self.external_commits_allowed(room_uri).unwrap_or(false) {
            self.store
                .keep_group_info(room_uri, 0, None)
                .map_err(|_| UpdateRefusal::Store)?;
        }
        Ok(())
    }

    /// After a tracked room's Commit: keep the bundle's GroupInfo for `epoch` when it is Full and the room allows external
    /// Commits; otherwise keep none, so an older one is never served for a newer epoch.
    pub(crate) fn keep_group_info_after(
        &self,
        room_uri: &str,
        epoch: u64,
        group_info: Option<&mimi_core::protocol_wire::GroupInfoOption>,
    ) {
        let full = group_info
            .filter(|info| {
                info.representation == mimi_core::protocol_wire::GroupInfoRepresentation::Full
            })
            .map(|info| info.payload.as_slice());
        let keep = full.filter(|_| self.external_commits_allowed(room_uri).unwrap_or(false));
        if let Err(error) = self.store.keep_group_info(room_uri, epoch, keep) {
            eprintln!("[mimi-hubd] external join: the room's GroupInfo could not be kept: {error}");
        }
    }

    /// Whether `user` may fetch the room's GroupInfo: the room allows external Commits, and the user may join it that way
    /// (a listed user by `canAddOwnClient`, an unlisted one by `canOpenJoin`, which its Commit will then use).
    pub(crate) fn may_fetch_group_info(&self, room_uri: &str, user: &str) -> bool {
        let listed = self
            .store
            .list_participant_rows(room_uri)
            .ok()
            .is_some_and(|rows| rows.iter().any(|row| row.member_uri == user));
        let as_if = (!listed).then(|| ParticipantListUpdate {
            added_participants: vec![mimi_core::participant_list::UserRolePair {
                user_uri: user.to_string(),
                role_index: 0,
            }],
            ..Default::default()
        });
        self.authorize_external_join(room_uri, user, as_if.as_ref())
            .is_ok()
    }
}

#[cfg(test)]
#[path = "external_join_tests.rs"]
mod tests;
