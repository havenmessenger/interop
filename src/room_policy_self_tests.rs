//! `authorize_self_removal`: leaving needs `canRemoveSelf` and an entry from the leaver's own role to 0.

use super::*;

fn role(index: u32, capabilities: Vec<Capability>, changes: Vec<(u32, Vec<u32>)>) -> Role {
    Role {
        role_index: index,
        role_name: format!("role {index}"),
        capabilities,
        authorized_role_changes: changes
            .into_iter()
            .map(
                |(from_role_index, target_role_indexes)| SingleSourceRoleChangeTargets {
                    from_role_index,
                    target_role_indexes,
                },
            )
            .collect(),
    }
}

fn policy(member: Role) -> RoomPolicy {
    RoomPolicy {
        base: BaseRoomPolicy::default(),
        roles: vec![member],
    }
}

/// A role with `canRemoveSelf` and an entry from itself to 0 may leave. Revert check: drop the capability check, and the
/// role without it leaves too.
#[test]
fn a_role_with_remove_self_and_an_entry_to_zero_may_leave() {
    let may = policy(role(3, vec![Capability::RemoveSelf], vec![(3, vec![0])]));
    assert!(may.authorize_self_removal(3).is_ok());

    let without_capability = policy(role(
        3,
        vec![Capability::RemoveParticipant],
        vec![(3, vec![0])],
    ));
    assert!(
        without_capability.authorize_self_removal(3).is_err(),
        "PLANT-REMOVE-SELF-CAPABILITY: a role without canRemoveSelf left"
    );

    let without_entry = policy(role(3, vec![Capability::RemoveSelf], vec![(3, vec![4])]));
    assert!(without_entry.authorize_self_removal(3).is_err());

    assert!(
        may.authorize_self_removal(9).is_err(),
        "an undefined role cannot leave by its policy"
    );
}

/// `canRemoveSelf` reads and writes as registry value 0x0006.
#[test]
fn remove_self_is_registry_value_6() {
    assert_eq!(
        crate::room_policy_wire::capability_from_wire(0x0006),
        Some(Capability::RemoveSelf)
    );
    assert_eq!(
        crate::room_policy_wire::capability_to_wire(Capability::RemoveSelf),
        0x0006
    );
}
