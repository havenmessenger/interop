//! Who may make a participant-list change, for a room whose ratchet tree the hub keeps (room-policy-04 §8.1).
//!
//! Each change is authorized for its **proposer**: the committer for a change the Commit carries by value, the
//! proposal's own sender for one it names by reference (a held leave). The proposer is a member of the tree, mapped to a
//! user by its credential, and its role is the one the room's participant list gives that user.
//!
//! For a change to another user, the proposer's role must hold the capability the transition needs and an
//! `authorized_role_changes` entry for it (`RoomPolicy::authorize_role_change`). The capabilities that grant those
//! (`canAddParticipant`, `canRemoveParticipant`, `canChangeUserRole`) exclude the holder itself, so a change to the
//! proposer's own user is its own case: leaving needs `canRemoveSelf` (`RoomPolicy::authorize_self_removal`); any other
//! change to one's own role is `canChangeOwnRole`, which works through the Preauthorized users component this hub does not
//! read, so it is not built yet and such a change is refused.
//!
//! A room with no `roles_list` has no role checks (room-policy PR #52). The participant-count constraints are not
//! checked here (DIVERGENCES, DIV-15).

use mimi_core::participant_list::ParticipantListUpdate;
use mimi_core::room_policy::RoomPolicy;

use crate::store::ParticipantRow;
use crate::UpdateRefusal;

const NOT_A_PARTICIPANT: UpdateRefusal =
    UpdateRefusal::Policy("the proposer of the change is not a participant of the room");
const NOT_AUTHORIZED: UpdateRefusal =
    UpdateRefusal::Policy("the proposer's role does not authorize the change");
const OWN_ROLE: UpdateRefusal = UpdateRefusal::Policy(
    "a participant changing its own role other than by leaving is not supported (canChangeOwnRole)",
);

/// Authorize every transition `update` makes, for `proposer` (a canonical user URI), against `policy` and the room's
/// list as it stands before the change (`rows`, in list order). `policy` is `None` for a room with no `roles_list`,
/// which has no role checks.
pub fn authorize_change(
    policy: Option<&RoomPolicy>,
    rows: &[ParticipantRow],
    proposer: &str,
    update: &ParticipantListUpdate,
) -> Result<(), UpdateRefusal> {
    let Some(policy) = policy.filter(|policy| !policy.roles.is_empty()) else {
        return Ok(());
    };
    let proposer_role = rows
        .iter()
        .find(|row| row.member_uri == proposer)
        .and_then(|row| row.role_index)
        .ok_or(NOT_A_PARTICIPANT)?;
    let at = |index: u32| rows.get(index as usize).ok_or(NOT_AUTHORIZED);
    for changed in &update.changed_role_participants {
        let target = at(changed.user_index)?;
        if target.member_uri == proposer {
            return Err(OWN_ROLE);
        }
        policy
            .authorize_role_change(
                proposer_role,
                target.role_index.unwrap_or(0),
                changed.role_index,
            )
            .map_err(|_| NOT_AUTHORIZED)?;
    }
    for removed in &update.removed_indices {
        let target = at(*removed)?;
        if target.member_uri == proposer {
            policy
                .authorize_self_removal(proposer_role)
                .map_err(|_| NOT_AUTHORIZED)?;
        } else {
            policy
                .authorize_role_change(proposer_role, target.role_index.unwrap_or(0), 0)
                .map_err(|_| NOT_AUTHORIZED)?;
        }
    }
    for added in &update.added_participants {
        policy
            .authorize_role_change(proposer_role, 0, added.role_index)
            .map_err(|_| NOT_AUTHORIZED)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "role_checks_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "role_checks_tracked_tests.rs"]
mod tracked_tests;
