//! One test per path of `authorize_change`: another user's role change, a removal of another, an add, one's own removal
//! with and without `canRemoveSelf`, one's own other change, and a room with no roles.

use mimi_core::participant_list::{ParticipantListUpdate, UserRolePair, UserindexRolePair};
use mimi_core::room_policy::{
    BaseRoomPolicy, Capability, Role, RoomPolicy, SingleSourceRoleChangeTargets,
};

use super::*;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const ADMIN: u32 = 2;
const MEMBER: u32 = 3;

fn role(index: u32, capabilities: Vec<Capability>, changes: &[(u32, &[u32])]) -> Role {
    Role {
        role_index: index,
        role_name: format!("role {index}"),
        capabilities,
        authorized_role_changes: changes
            .iter()
            .map(|(from, to)| SingleSourceRoleChangeTargets {
                from_role_index: *from,
                target_role_indexes: to.to_vec(),
            })
            .collect(),
    }
}

/// An admin that may add members, remove them and make them admins; a member that may only leave.
fn policy() -> RoomPolicy {
    RoomPolicy {
        base: BaseRoomPolicy::default(),
        roles: vec![
            role(
                ADMIN,
                vec![
                    Capability::AddParticipant,
                    Capability::RemoveParticipant,
                    Capability::ChangeRole,
                    Capability::RemoveSelf,
                ],
                &[(0, &[MEMBER]), (MEMBER, &[0, ADMIN]), (ADMIN, &[0])],
            ),
            role(MEMBER, vec![Capability::RemoveSelf], &[(MEMBER, &[0])]),
        ],
    }
}

/// Alice an admin, Bob a member, in that order.
fn rows() -> Vec<ParticipantRow> {
    vec![
        ParticipantRow {
            member_uri: ALICE.into(),
            authority: "a.example".into(),
            role_index: Some(ADMIN),
        },
        ParticipantRow {
            member_uri: BOB.into(),
            authority: "b.example".into(),
            role_index: Some(MEMBER),
        },
    ]
}

fn change_role(index: u32, to: u32) -> ParticipantListUpdate {
    ParticipantListUpdate {
        changed_role_participants: vec![UserindexRolePair {
            user_index: index,
            role_index: to,
        }],
        ..Default::default()
    }
}

fn remove(index: u32) -> ParticipantListUpdate {
    ParticipantListUpdate {
        removed_indices: vec![index],
        ..Default::default()
    }
}

/// Another user's role change is allowed for a proposer whose role authorizes it, and refused for one whose role does
/// not. Revert check: skip the check, and Bob makes Alice a member.
#[test]
fn another_users_role_change_follows_the_proposers_role() {
    let policy = policy();
    assert!(authorize_change(Some(&policy), &rows(), ALICE, &change_role(1, ADMIN)).is_ok());
    assert!(
        authorize_change(Some(&policy), &rows(), BOB, &change_role(0, MEMBER)).is_err(),
        "PLANT-ROLE-OTHER: a member changed an admin's role"
    );
}

/// Removing another user, and adding one, follow the proposer's role too.
#[test]
fn removing_and_adding_another_user_follow_the_proposers_role() {
    let policy = policy();
    assert!(authorize_change(Some(&policy), &rows(), ALICE, &remove(1)).is_ok());
    assert!(authorize_change(Some(&policy), &rows(), BOB, &remove(0)).is_err());
    let add = |role_index| ParticipantListUpdate {
        added_participants: vec![UserRolePair {
            user_uri: "mimi://c.example/u/carol".into(),
            role_index,
        }],
        ..Default::default()
    };
    assert!(authorize_change(Some(&policy), &rows(), ALICE, &add(MEMBER)).is_ok());
    assert!(
        authorize_change(Some(&policy), &rows(), ALICE, &add(ADMIN)).is_err(),
        "an admin cannot add a user straight into a role its entries do not name"
    );
    assert!(authorize_change(Some(&policy), &rows(), BOB, &add(MEMBER)).is_err());
}

/// Leaving needs `canRemoveSelf`: Bob may leave, and without the capability he may not; an admin's
/// `canRemoveParticipant` is for others and does not let it leave. Revert check: drop the self case, and the admin leaves
/// on `canRemoveParticipant`.
#[test]
fn ones_own_removal_needs_remove_self() {
    let policy = policy();
    assert!(authorize_change(Some(&policy), &rows(), BOB, &remove(1)).is_ok());
    let mut without = policy.clone();
    without.roles[1].capabilities.clear();
    assert!(
        authorize_change(Some(&without), &rows(), BOB, &remove(1)).is_err(),
        "PLANT-ROLE-SELF-REMOVE: a member without canRemoveSelf left"
    );
    // An admin's canRemoveParticipant is for others: with canRemoveSelf taken away, the admin cannot leave by it.
    let mut admin_without = policy;
    admin_without.roles[0]
        .capabilities
        .retain(|capability| *capability != Capability::RemoveSelf);
    assert!(authorize_change(Some(&admin_without), &rows(), ALICE, &remove(0)).is_err());
}

/// Any other change to one's own role is refused: it is canChangeOwnRole, not built yet. Revert check: send it through
/// `authorize_role_change`, and the admin demotes itself on its own entry.
#[test]
fn ones_own_other_role_change_is_refused() {
    assert!(
        authorize_change(Some(&policy()), &rows(), ALICE, &change_role(0, MEMBER)).is_err(),
        "PLANT-ROLE-OWN: a participant changed its own role"
    );
}

/// A proposer who is not listed is refused, and a room with no roles has no role checks.
#[test]
fn an_unlisted_proposer_is_refused_and_a_room_without_roles_is_not_checked() {
    let policy = policy();
    assert!(authorize_change(
        Some(&policy),
        &rows(),
        "mimi://x.example/u/mallory",
        &remove(1)
    )
    .is_err());
    assert!(authorize_change(None, &rows(), BOB, &change_role(0, MEMBER)).is_ok());
    let no_roles = RoomPolicy {
        base: BaseRoomPolicy::default(),
        roles: Vec::new(),
    };
    assert!(authorize_change(Some(&no_roles), &rows(), BOB, &change_role(0, MEMBER)).is_ok());
}
