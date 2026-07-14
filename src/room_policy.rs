//! MIMI room policy / RBAC (room-policy-04, conformance P1–P6).
//!
//! The role model + authorization logic. Roles live in the participant list (AppSync, see
//! [`crate::participant_list`]) - not in the MLS credential (credentials are opaque). So a role is a
//! `role_index` attached to a member; this module defines what a role *is* and what it *authorizes*.
//!
//! This module implements roles, capabilities, authorized role changes, membership constraints, and
//! reserved roles. The hub enforces `canSendMessage` (§8.3) at runtime; clients enforce the
//! remaining capabilities.

use serde::{Deserialize, Serialize};

/// The sibling custom proposal type to mimiParticipantList (0xF7A0): a room-policy (Role-definition)
/// change rides as `mimiRoomPolicy`. Haven-chosen pending WG guidance. P2 forbids it from
/// sharing a commit with a participant-list change.
pub const MIMI_ROOM_POLICY_PROPOSAL_TYPE: u16 = 0xF7A1;

/// Reserved role indices (room-policy-04 §3). 0 = non-participant, 1 = banned. Ordinary roles are >= 2.
pub const ROLE_NON_PARTICIPANT: u32 = 0;
pub const ROLE_BANNED: u32 = 1;

/// Typed errors for room-policy validation/authorization (`thiserror` per-module
/// enum - the library convention). Each variant is a distinct P1–P6 rule violation.
#[derive(Debug, thiserror::Error)]
pub enum RoomPolicyError {
    /// A P1/structural role-definition rule was violated (duplicate index; reserved-role naming; a
    /// reserved role carrying capabilities; a fixed-membership role holding AddParticipant).
    #[error("{0}")]
    RoleDefinition(String),
    /// The actor role referenced in a P4 authorization check is not defined in the policy.
    #[error("actor role {0} not defined")]
    ActorRoleUndefined(u32),
    /// A P4 role-change was denied (actor lacks the capability, or no `authorized_role_changes` entry
    /// permits the transition).
    #[error("{0}")]
    RoleChangeDenied(String),
    /// A P3 membership-count constraint was violated (fixed_membership growth; max_clients/max_users).
    #[error("{0}")]
    MembershipConstraint(String),
    /// P2 (§8.6): a room-policy change shared a commit with a participant-list change.
    #[error(
        "P2: a room-policy change MUST NOT share a commit with a participant-list change (§8.6)"
    )]
    PolicyRosterCoCommit,
}

/// Room-policy-03 capabilities (the subset we model). A `Role` holds a set of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    SendMessage,
    AddParticipant,
    RemoveParticipant,
    ChangeRole,
    Kick,
    Ban,
}

/// room-policy-04 §8.1 `SingleSourceRoleChangeTargets` - from one role, which target roles a change may
/// move a user to. (Add = an entry with `from == 0`; Remove = targets include 0; Ban = targets include 1.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleSourceRoleChangeTargets {
    pub from_role_index: u32,
    pub target_role_indexes: Vec<u32>,
}

/// A role definition (the load-bearing subset of the room-policy-04 `Role` struct).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub role_index: u32,
    pub role_name: String,
    pub capabilities: Vec<Capability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_role_changes: Vec<SingleSourceRoleChangeTargets>,
}

impl Role {
    pub fn has(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }
}

/// room-policy-04 §5 `BaseRoomPolicy` (load-bearing subset).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BaseRoomPolicy {
    pub fixed_membership: bool,
    pub parent_dependant: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_clients: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_users: Option<u32>,
    pub discoverable: bool,
}

/// A complete room policy: the base policy + the role definitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomPolicy {
    pub base: BaseRoomPolicy,
    pub roles: Vec<Role>,
}

impl RoomPolicy {
    pub fn role(&self, role_index: u32) -> Option<&Role> {
        self.roles.iter().find(|r| r.role_index == role_index)
    }

    /// P5: does the member's role allow sending a message? Reserved roles (non-participant/banned) never
    /// can. An unknown role index cannot send (fail-closed).
    pub fn can_send_message(&self, role_index: u32) -> bool {
        if role_index == ROLE_NON_PARTICIPANT || role_index == ROLE_BANNED {
            return false;
        }
        self.role(role_index)
            .map(|r| r.has(Capability::SendMessage))
            .unwrap_or(false)
    }

    /// P1 + structural validation: role indices unique; the reserved indices, if present, are well-formed
    /// (1 = "banned"); a non-participant/banned role must not carry capabilities.
    pub fn validate(&self) -> Result<(), RoomPolicyError> {
        let mut seen = std::collections::HashSet::new();
        for r in &self.roles {
            if !seen.insert(r.role_index) {
                return Err(RoomPolicyError::RoleDefinition(format!(
                    "duplicate role_index {} (P1: roles must be uniquely indexed)",
                    r.role_index
                )));
            }
            if r.role_index == ROLE_BANNED && r.role_name != "banned" {
                return Err(RoomPolicyError::RoleDefinition(
                    "role_index 1 is reserved and MUST be named \"banned\"".to_string(),
                ));
            }
            if (r.role_index == ROLE_NON_PARTICIPANT || r.role_index == ROLE_BANNED)
                && !r.capabilities.is_empty()
            {
                return Err(RoomPolicyError::RoleDefinition(format!(
                    "reserved role {} must hold no capabilities",
                    r.role_index
                )));
            }
            // P3: fixed_membership ⇒ no ordinary role may add participants.
            if self.base.fixed_membership && r.has(Capability::AddParticipant) {
                return Err(RoomPolicyError::RoleDefinition(format!(
                    "fixed_membership room: role {} must not hold AddParticipant (P3)",
                    r.role_index
                )));
            }
        }
        Ok(())
    }

    /// P4: may `actor_role_index` move a user `from_role` → `to_role`? The actor's role must hold the
    /// capability the change implies, AND the ACTOR's own role must have an `authorized_role_changes`
    /// entry (keyed by `from_role`) whose targets include `to_role` (room-policy-04 §8.1.3:
    /// `canChangeUserRole` is authorized "according to the holder's `authorized_role_changes` list" -
    /// the holder is the actor, not the target's current role). Add = from 0 (needs AddParticipant);
    /// Remove = to 0 (needs RemoveParticipant); Ban = to 1 (needs Ban); any other transition needs
    /// ChangeRole.
    pub fn authorize_role_change(
        &self,
        actor_role_index: u32,
        from_role: u32,
        to_role: u32,
    ) -> Result<(), RoomPolicyError> {
        let actor = self
            .role(actor_role_index)
            .ok_or(RoomPolicyError::ActorRoleUndefined(actor_role_index))?;
        // the capability the transition requires
        let needed = if from_role == ROLE_NON_PARTICIPANT {
            Capability::AddParticipant
        } else if to_role == ROLE_NON_PARTICIPANT {
            Capability::RemoveParticipant
        } else if to_role == ROLE_BANNED {
            Capability::Ban
        } else {
            Capability::ChangeRole
        };
        if !actor.has(needed) {
            return Err(RoomPolicyError::RoleChangeDenied(format!(
                "role {actor_role_index} lacks {needed:?} for the {from_role}->{to_role} change (P4)"
            )));
        }
        // the ACTOR's own role must authorize this transition - not the target's current role. Room-
        // policy-03 §8.1.3 grants canChangeUserRole "according to the holder's authorized_role_changes
        // list"; the holder is the actor identified by actor_role_index, already resolved above as
        // `actor`. Looking up the target's from_role instead would let anyone holding the right
        // capability perform any transition that ANY role's list happens to permit for that from_role,
        // regardless of what the acting role is actually authorized for.
        let allowed = actor
            .authorized_role_changes
            .iter()
            .any(|t| t.from_role_index == from_role && t.target_role_indexes.contains(&to_role));
        if !allowed {
            return Err(RoomPolicyError::RoleChangeDenied(format!(
                "role {actor_role_index} has no authorized_role_changes entry permitting {from_role}->{to_role} (P4)"
            )));
        }
        Ok(())
    }

    /// P3: membership-count constraints. fixed_membership rooms reject any growth; max_clients/max_users
    /// bound the group. `next_clients`/`next_users` are the counts AFTER the proposed change.
    pub fn check_membership_constraints(
        &self,
        next_clients: u32,
        next_users: u32,
        is_growth: bool,
    ) -> Result<(), RoomPolicyError> {
        if self.base.fixed_membership && is_growth {
            return Err(RoomPolicyError::MembershipConstraint(
                "fixed_membership room: cannot add members (P3)".to_string(),
            ));
        }
        if let Some(maxc) = self.base.max_clients {
            if next_clients > maxc {
                return Err(RoomPolicyError::MembershipConstraint(format!(
                    "max_clients {maxc} exceeded ({next_clients}) (P3)"
                )));
            }
        }
        if let Some(maxu) = self.base.max_users {
            if next_users > maxu {
                return Err(RoomPolicyError::MembershipConstraint(format!(
                    "max_users {maxu} exceeded ({next_users}) (P3)"
                )));
            }
        }
        Ok(())
    }
}

/// P2 (room-policy-04 §8.6 EXACT): a Role-definition (mimiRoomPolicy) change is NOT valid in the same
/// commit as any participant-list (mimiParticipantList) change. Given the custom proposal types carried
/// in one commit, reject the forbidden co-occurrence. Fail-closed.
pub fn validate_commit_component_exclusivity(
    custom_proposal_types: &[u16],
) -> Result<(), RoomPolicyError> {
    let has_policy = custom_proposal_types.contains(&MIMI_ROOM_POLICY_PROPOSAL_TYPE);
    let has_roster = custom_proposal_types
        .contains(&crate::participant_list::MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE);
    if has_policy && has_roster {
        return Err(RoomPolicyError::PolicyRosterCoCommit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_role(idx: u32, name: &str, caps: Vec<Capability>) -> Role {
        Role {
            role_index: idx,
            role_name: name.into(),
            capabilities: caps,
            authorized_role_changes: vec![],
        }
    }

    /// admin(2) can add (from 0->2 or 0->3), remove (3->0), ban (3->1), and demote (2->3); member(3) can
    /// only send. The role-change graph lives on the ACTOR's (admin's) own `authorized_role_changes` -
    /// per room-policy-04 §8.1.3, that's whose list governs, not the target's current role.
    fn sample_policy() -> RoomPolicy {
        let admin = Role {
            role_index: 2,
            role_name: "admin".into(),
            capabilities: vec![
                Capability::SendMessage,
                Capability::AddParticipant,
                Capability::RemoveParticipant,
                Capability::Ban,
                Capability::ChangeRole,
            ],
            authorized_role_changes: vec![
                SingleSourceRoleChangeTargets {
                    from_role_index: 0,
                    target_role_indexes: vec![2, 3],
                },
                SingleSourceRoleChangeTargets {
                    from_role_index: 3,
                    target_role_indexes: vec![0, 1],
                },
                SingleSourceRoleChangeTargets {
                    from_role_index: 2,
                    target_role_indexes: vec![3],
                },
            ],
        };
        let member = member_role(3, "member", vec![Capability::SendMessage]);
        let banned = member_role(ROLE_BANNED, "banned", vec![]);
        let nonp = member_role(ROLE_NON_PARTICIPANT, "non-participant", vec![]);
        RoomPolicy {
            base: BaseRoomPolicy::default(),
            roles: vec![nonp, banned, admin, member],
        }
    }

    #[test]
    fn p1_validate_roles_and_reserved_indices() {
        assert!(sample_policy().validate().is_ok());
        // duplicate index
        let mut p = sample_policy();
        p.roles.push(member_role(2, "dup", vec![]));
        assert!(p.validate().is_err(), "duplicate role_index rejected");
        // reserved role 1 must be named "banned"
        let mut p2 = sample_policy();
        p2.roles.retain(|r| r.role_index != ROLE_BANNED);
        p2.roles.push(member_role(ROLE_BANNED, "blocked", vec![]));
        assert!(p2.validate().is_err(), "role 1 must be named banned");
        // reserved role with caps
        let mut p3 = sample_policy();
        p3.roles.retain(|r| r.role_index != ROLE_BANNED);
        p3.roles.push(member_role(
            ROLE_BANNED,
            "banned",
            vec![Capability::SendMessage],
        ));
        assert!(p3.validate().is_err(), "banned role must hold no caps");
    }

    #[test]
    fn p5_can_send_message_only_for_capable_active_roles() {
        let p = sample_policy();
        assert!(p.can_send_message(2), "admin can send");
        assert!(p.can_send_message(3), "member can send");
        assert!(!p.can_send_message(ROLE_BANNED), "banned cannot send");
        assert!(
            !p.can_send_message(ROLE_NON_PARTICIPANT),
            "non-participant cannot send"
        );
        assert!(
            !p.can_send_message(99),
            "unknown role cannot send (fail-closed)"
        );
        // a role without SendMessage can't send
        let mut p2 = sample_policy();
        p2.roles.push(member_role(4, "muted", vec![]));
        assert!(
            !p2.can_send_message(4),
            "role without SendMessage cap cannot send"
        );
    }

    #[test]
    fn p4_authorize_role_change_add_remove_ban() {
        let p = sample_policy();
        // admin adds a member (0->3)
        assert!(
            p.authorize_role_change(2, 0, 3).is_ok(),
            "admin may add (0->3)"
        );
        // admin removes a member (3->0)
        assert!(
            p.authorize_role_change(2, 3, 0).is_ok(),
            "admin may remove (3->0)"
        );
        // admin bans a member (3->1)
        assert!(
            p.authorize_role_change(2, 3, 1).is_ok(),
            "admin may ban (3->1)"
        );
        // a member (only SendMessage) may NOT add
        assert!(
            p.authorize_role_change(3, 0, 3).is_err(),
            "member lacks AddParticipant"
        );
        // even admin can't do a transition its own authorized_role_changes doesn't list (2->1 not in graph)
        assert!(
            p.authorize_role_change(2, 2, 1).is_err(),
            "no authorized_role_changes entry 2->1"
        );
    }

    /// `authorize_role_change` must consult the ACTOR's own `authorized_role_changes`,
    /// not the list belonging to whatever role happens to have `role_index == from_role`. Role 6 here
    /// has its own (irrelevant) authorized_role_changes entry for the exact from/to pair under test -
    /// the old buggy code looked up `self.role(from_role)` and would have granted the transition on
    /// role 6's say-so, even though the actual actor (role 5) never authorized it.
    #[test]
    fn p4_authorize_role_change_is_keyed_on_actor_not_target_role() {
        let junior_mod = Role {
            role_index: 5,
            role_name: "junior_mod".into(),
            capabilities: vec![Capability::ChangeRole],
            authorized_role_changes: vec![SingleSourceRoleChangeTargets {
                from_role_index: 3,
                target_role_indexes: vec![6],
            }],
        };
        let member = member_role(3, "member", vec![Capability::SendMessage]);
        // role 6's own graph permits 3->7 - a decoy the actor (junior_mod) never authorized.
        let decoy = Role {
            role_index: 6,
            role_name: "decoy".into(),
            capabilities: vec![],
            authorized_role_changes: vec![SingleSourceRoleChangeTargets {
                from_role_index: 3,
                target_role_indexes: vec![7],
            }],
        };
        let target_role = member_role(7, "target_role", vec![]);
        let p = RoomPolicy {
            base: BaseRoomPolicy::default(),
            roles: vec![junior_mod, member, decoy, target_role],
        };
        assert!(
            p.authorize_role_change(5, 3, 6).is_ok(),
            "junior_mod's own list permits 3->6"
        );
        assert!(
            p.authorize_role_change(5, 3, 7).is_err(),
            "junior_mod's own list does NOT permit 3->7, regardless of what role 6's list says"
        );
    }

    #[test]
    fn p3_membership_constraints() {
        // fixed_membership blocks growth + forbids AddParticipant at validate-time
        let mut p = sample_policy();
        p.base.fixed_membership = true;
        assert!(
            p.validate().is_err(),
            "admin has AddParticipant in a fixed_membership room (P3)"
        );
        // remove the add cap so validate passes, then growth is still blocked
        let mut p2 = sample_policy();
        p2.base.fixed_membership = true;
        for r in &mut p2.roles {
            r.capabilities.retain(|c| *c != Capability::AddParticipant);
        }
        assert!(p2.validate().is_ok());
        assert!(
            p2.check_membership_constraints(5, 5, true).is_err(),
            "fixed_membership blocks growth"
        );
        assert!(
            p2.check_membership_constraints(5, 5, false).is_ok(),
            "non-growth ops allowed"
        );
        // max_clients / max_users
        let mut p3 = sample_policy();
        p3.base.max_clients = Some(10);
        p3.base.max_users = Some(8);
        assert!(
            p3.check_membership_constraints(10, 8, true).is_ok(),
            "at the cap is OK"
        );
        assert!(
            p3.check_membership_constraints(11, 8, true).is_err(),
            "over max_clients rejected"
        );
        assert!(
            p3.check_membership_constraints(10, 9, true).is_err(),
            "over max_users rejected"
        );
    }

    #[test]
    fn p2_policy_and_roster_cannot_share_a_commit() {
        use crate::participant_list::MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE;
        // both present → rejected
        assert!(validate_commit_component_exclusivity(&[
            MIMI_ROOM_POLICY_PROPOSAL_TYPE,
            MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE
        ])
        .is_err());
        // either alone → fine
        assert!(validate_commit_component_exclusivity(&[MIMI_ROOM_POLICY_PROPOSAL_TYPE]).is_ok());
        assert!(
            validate_commit_component_exclusivity(&[MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE]).is_ok()
        );
        assert!(validate_commit_component_exclusivity(&[]).is_ok());
    }
}
