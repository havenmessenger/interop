//! A tracked room's clients and its participant list stay paired (room-policy-04 §8.1.2, protocol-07 §7.5).
//!
//! MIMI lists users, and a user may have several clients (leaves). After every Commit a tracked room accepts:
//! - each client the Commit adds is a client of a user listed after it;
//! - a user the Commit takes off the list keeps no client in the group ("There MUST NOT be any clients of the removed
//!   user in the MLS group after the corresponding commit");
//! - a client of a user who stays listed is removed only by that user, as its own client (`canRemoveOwnClient`), by a
//!   Remove it commits or a Remove or SelfRemove it proposed. Another member removes a user's clients only by taking
//!   the user off the list.
//!
//! A listed user with no client is valid (an inactive participant). Users are compared in canonical form.
//!
//! The check reads plain data, which [`crate::room_tree::StagedRoomCommit::list_and_leaves`] takes from the room's
//! group before the Commit and the Commit as staged on it. An untracked room has no tree to read, and keeps the
//! hub's Add and Remove checks alone.

use mimi_core::room_policy::{Capability, RoomPolicy};

/// A client a Commit removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemovedLeaf {
    /// The client's user, by its credential; `None` when the credential names no user.
    pub user: Option<String>,
    /// The user of the member who proposed the removal: the committer for a Remove it carries, the proposer for a held
    /// Remove, the client itself for a SelfRemove.
    pub proposer: Option<String>,
}

/// A tracked room's participant list and clients around one Commit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ListAndLeaves {
    /// The list before the Commit: each user and its role.
    pub before: Vec<(String, u32)>,
    /// The users listed after it.
    pub after: Vec<String>,
    /// The user of each client the Commit adds (an external Commit's joiner included).
    pub added: Vec<Option<String>>,
    /// Each client the Commit removes.
    pub removed: Vec<RemovedLeaf>,
    /// The user of each client in the group after the Commit.
    pub leaves_after: Vec<Option<String>>,
}

pub(crate) const ADDED_NOT_LISTED: &str =
    "a client the Commit adds is not a client of a participant listed after it";
pub(crate) const DELISTED_KEEPS_CLIENT: &str =
    "a participant the Commit takes off the list keeps a client in the group";
pub(crate) const CLIENT_OF_ANOTHER: &str =
    "the Commit removes a listed participant's client that the participant did not remove as its own";

/// Refuses a Commit after which the room's clients and its list are not paired, by the rules in the module doc.
/// `policy` is the room's policy, when it has roles: removing one's own client then needs `canRemoveOwnClient` in the
/// user's role. A room without roles has no capability to check.
pub(crate) fn require_paired(
    view: &ListAndLeaves,
    policy: Option<&RoomPolicy>,
) -> Result<(), &'static str> {
    let listed_after = |user: &str| view.after.iter().any(|listed| listed == user);
    if view
        .added
        .iter()
        .any(|user| !user.as_deref().is_some_and(listed_after))
    {
        return Err(ADDED_NOT_LISTED);
    }
    for (user, _) in &view.before {
        if !listed_after(user)
            && view
                .leaves_after
                .iter()
                .any(|leaf| leaf.as_deref() == Some(user.as_str()))
        {
            return Err(DELISTED_KEEPS_CLIENT);
        }
    }
    for removed in &view.removed {
        // A client of a user listed neither before nor after (one that names no user, or was never listed) may go:
        // removing it only brings the room back to the rule.
        let Some(user) = removed.user.as_deref() else {
            continue;
        };
        let listed_before = view.before.iter().find(|(listed, _)| listed == user);
        let (Some((_, role)), true) = (listed_before, listed_after(user)) else {
            continue;
        };
        let own = removed.proposer.as_deref() == Some(user);
        let may = policy.is_none_or(|policy| {
            policy
                .role(*role)
                .is_some_and(|role| role.has(Capability::RemoveOwnClient))
        });
        if !(own && may) {
            return Err(CLIENT_OF_ANOTHER);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "list_leaves_tests.rs"]
mod tests;
