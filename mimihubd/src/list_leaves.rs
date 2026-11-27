//! A tracked room's clients and its participant list stay paired (room-policy-04 §8.1.2, protocol-07 §7.5).
//!
//! MIMI lists users, and a user may have several clients (leaves). After every Commit a tracked room accepts:
//! - each client the Commit adds is a client of a user listed after it;
//! - a user the Commit takes off the list keeps no client in the group ("There MUST NOT be any clients of the removed
//!   user in the MLS group after the corresponding commit");
//! - a client of a user who stays listed is removed by that user, as its own client (`canRemoveOwnClient`), by a Remove
//!   it commits or a Remove or SelfRemove it proposed; or by a member whose role holds `canKick`, which removes another
//!   participant's clients without changing the list. Otherwise a member removes a user's clients only by taking the
//!   user off the list;
//! - a client keeps its credential: an Update, or the committer's new leaf, carries a valid successor of the credential
//!   of the leaf it replaces (RFC 9420 §5.3.1, [`crate::credential::is_successor`]), so no client becomes another
//!   user's, listed or not. For a Basic credential that is byte equality of the identity, not the canonical form the
//!   list is matched in: it is the comparison the room's clients make, so every renewal a client refuses is refused
//!   here first.
//!
//! A listed user with no client is valid (an inactive participant). Users are compared in canonical form.
//!
//! The check reads plain data, which [`crate::room_tree::StagedRoomCommit::list_and_leaves`] takes from the room's
//! group before the Commit and the Commit as staged on it. An untracked room has no tree to read, and keeps the
//! hub's Add and Remove checks alone.

use mimi_core::room_policy::{Capability, RoomPolicy};
use openmls::prelude::Credential;

/// A client a Commit removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemovedLeaf {
    /// The client's user, by its credential; `None` when the credential names no user.
    pub user: Option<String>,
    /// The user of the member who proposed the removal: the committer for a Remove it carries, the proposer for a held
    /// Remove, the client itself for a SelfRemove.
    pub proposer: Option<String>,
}

/// A client the Commit gives a new leaf: the credential of its leaf before (`None` if the tree had no leaf there), and
/// of its new leaf.
pub(crate) type Renewal = (Option<Credential>, Credential);

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
    /// Each client the Commit gives a new leaf (an Update, or the committer's leaf in its update path): its credential
    /// before and its new leaf's.
    pub renewed: Vec<Renewal>,
}

pub(crate) const ADDED_NOT_LISTED: &str =
    "a client the Commit adds is not a client of a participant listed after it";
pub(crate) const DELISTED_KEEPS_CLIENT: &str =
    "a participant the Commit takes off the list keeps a client in the group";
pub(crate) const CLIENT_OF_ANOTHER: &str =
    "the Commit removes a listed participant's client that the participant did \
     not remove as its own and no member who may kick removed";
pub(crate) const CLIENT_CHANGES_USER: &str =
    "a client's new leaf names another user than the client's";

/// Refuses a Commit after which the room's clients and its list are not paired, by the rules in the module doc.
/// `policy` is the room's policy, when it has roles: removing one's own client then needs `canRemoveOwnClient` in the
/// user's role, and removing another's needs `canKick` in the proposer's. A room without roles has no capability to
/// check: a user may remove its own client there, and no one may remove another's without taking it off the list.
pub(crate) fn require_paired(
    view: &ListAndLeaves,
    policy: Option<&RoomPolicy>,
) -> Result<(), &'static str> {
    let listed_after = |user: &str| view.after.iter().any(|listed| listed == user);
    if view.renewed.iter().any(|(before, after)| {
        !before
            .as_ref()
            .is_some_and(|before| crate::credential::is_successor(before, after))
    }) {
        return Err(CLIENT_CHANGES_USER);
    }
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
        let holds = |role: Option<u32>, capability: Capability| {
            policy.is_some_and(|policy| {
                role.and_then(|role| policy.role(role))
                    .is_some_and(|role| role.has(capability))
            })
        };
        let own = removed.proposer.as_deref() == Some(user);
        let as_own = own && (policy.is_none() || holds(Some(*role), Capability::RemoveOwnClient));
        let by_kick = !own
            && removed.proposer.as_deref().is_some_and(|proposer| {
                let proposer_role = view
                    .before
                    .iter()
                    .find(|(listed, _)| listed == proposer)
                    .map(|(_, role)| *role);
                holds(proposer_role, Capability::Kick)
            });
        if !(as_own || by_kick) {
            return Err(CLIENT_OF_ANOTHER);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "list_leaves_tests.rs"]
mod tests;
