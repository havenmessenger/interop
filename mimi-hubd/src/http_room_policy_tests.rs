//! A room's roles and base policy change through an AppDataUpdate for `roles_list` (0x0025) and `base_room_policy`
//! (0x0027), carrying room-policy-04's `RoleData` and `BaseRoomPolicy`. A refused update leaves the stored policy as it was.

use mimi_core::participant_list::MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE;
use mimi_core::protocol_wire::UpdateRoomResponse;
use mimi_core::room_policy::{BaseRoomPolicy, Capability, Role, RoomPolicy};
use mimi_core::room_policy_wire::{
    encode_base_room_policy, encode_role_data, BASE_ROOM_POLICY_COMPONENT_ID,
    ROLES_LIST_COMPONENT_ID,
};

use super::tests::{app, bundle_of, real_single_custom_proposal_commit, update_answer};
use super::update_tests::{as_app_data_update, post, ROOM};
use crate::http::SharedProvider;

fn role(index: u32, name: &str, capabilities: Vec<Capability>) -> Role {
    Role {
        role_index: index,
        role_name: name.into(),
        capabilities,
        authorized_role_changes: vec![],
    }
}

pub(super) fn roles() -> Vec<Role> {
    vec![
        role(
            2,
            "admin",
            vec![Capability::SendMessage, Capability::AddParticipant],
        ),
        role(3, "member", vec![Capability::SendMessage]),
    ]
}

/// Post `update` as an AppDataUpdate for `component` and return the hub's answer.
async fn send(router: axum::Router, component: u16, update: &[u8]) -> UpdateRoomResponse {
    // The Commit is built with the participant-list type, which the group negotiates, and rewritten to the component.
    let commit =
        real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, update.to_vec());
    let sent = as_app_data_update(&commit, update, component);
    update_answer(post(router, ROOM, bundle_of(sent)).await).await
}

fn stored(p: &SharedProvider) -> Option<RoomPolicy> {
    p.lock().unwrap().room_policy(ROOM).unwrap()
}

fn hosted(p: &SharedProvider) {
    p.lock()
        .unwrap()
        .add_participant(ROOM, "mimi://havenmessenger.com/u/alice", 1)
        .unwrap();
}

fn assert_invalid(answer: &UpdateRoomResponse) {
    assert!(
        matches!(answer, UpdateRoomResponse::InvalidProposal { .. }),
        "{answer:?}"
    );
}

#[tokio::test]
async fn a_roles_list_update_sets_the_roles() {
    let (router, p) = app();
    hosted(&p);
    let answer = send(router, ROLES_LIST_COMPONENT_ID, &encode_role_data(&roles())).await;
    assert!(
        matches!(answer, UpdateRoomResponse::Success { .. }),
        "{answer:?}"
    );
    let policy = stored(&p).expect("a policy is stored");
    assert_eq!(policy.roles, roles());
    assert_eq!(policy.base, BaseRoomPolicy::default());
    assert!(policy.can_send_message(3));
    assert!(!policy.can_send_message(4));
}

#[tokio::test]
async fn a_base_update_replaces_the_base_and_keeps_the_roles() {
    let (router, p) = app();
    hosted(&p);
    p.lock()
        .unwrap()
        .set_room_policy(
            ROOM,
            &RoomPolicy {
                base: BaseRoomPolicy::default(),
                roles: roles(),
            },
            1,
        )
        .unwrap();
    let base = BaseRoomPolicy {
        fixed_membership: false,
        parent_dependant: false,
        max_clients: Some(8),
        max_users: Some(4),
        discoverable: true,
    };
    let answer = send(
        router,
        BASE_ROOM_POLICY_COMPONENT_ID,
        &encode_base_room_policy(&base, None),
    )
    .await;
    assert!(
        matches!(answer, UpdateRoomResponse::Success { .. }),
        "{answer:?}"
    );
    let policy = stored(&p).unwrap();
    assert_eq!(policy.base, base);
    assert_eq!(policy.roles, roles());
}

#[tokio::test]
async fn a_roles_update_keeps_the_stored_base() {
    let (router, p) = app();
    hosted(&p);
    let base = BaseRoomPolicy {
        max_users: Some(9),
        ..BaseRoomPolicy::default()
    };
    p.lock()
        .unwrap()
        .set_room_policy(
            ROOM,
            &RoomPolicy {
                base: base.clone(),
                roles: roles(),
            },
            1,
        )
        .unwrap();
    let replacement = vec![role(5, "guest", vec![])];
    let answer = send(
        router,
        ROLES_LIST_COMPONENT_ID,
        &encode_role_data(&replacement),
    )
    .await;
    assert!(
        matches!(answer, UpdateRoomResponse::Success { .. }),
        "{answer:?}"
    );
    let policy = stored(&p).unwrap();
    assert_eq!(policy.base, base);
    assert_eq!(policy.roles, replacement);
}

#[tokio::test]
async fn a_base_update_for_a_room_with_no_roles_is_invalid_and_stores_nothing() {
    let (router, p) = app();
    hosted(&p);
    let answer = send(
        router,
        BASE_ROOM_POLICY_COMPONENT_ID,
        &encode_base_room_policy(&BaseRoomPolicy::default(), None),
    )
    .await;
    assert_invalid(&answer);
    assert_eq!(stored(&p), None);
}

#[tokio::test]
async fn an_update_that_does_not_parse_is_invalid_and_changes_nothing() {
    let good = encode_role_data(&roles());
    let cases: Vec<(&str, u16, Vec<u8>)> = vec![
        (
            "roles cut short",
            ROLES_LIST_COMPONENT_ID,
            good[..good.len() - 1].to_vec(),
        ),
        (
            "roles with a trailing byte",
            ROLES_LIST_COMPONENT_ID,
            [good.clone(), vec![0]].concat(),
        ),
        ("roles, empty", ROLES_LIST_COMPONENT_ID, vec![]),
        ("base, empty", BASE_ROOM_POLICY_COMPONENT_ID, vec![]),
        (
            "base, garbage",
            BASE_ROOM_POLICY_COMPONENT_ID,
            vec![0xFF; 5],
        ),
    ];
    for (name, component, update) in cases {
        let (router, p) = app();
        hosted(&p);
        let kept = RoomPolicy {
            base: BaseRoomPolicy::default(),
            roles: roles(),
        };
        p.lock().unwrap().set_room_policy(ROOM, &kept, 1).unwrap();
        let answer = send(router, component, &update).await;
        assert_invalid(&answer);
        assert_eq!(stored(&p), Some(kept), "{name}");
    }
}

#[tokio::test]
async fn a_policy_that_does_not_validate_is_invalid_and_changes_nothing() {
    // Role 1 is reserved for "banned".
    let (router, p) = app();
    hosted(&p);
    let kept = RoomPolicy {
        base: BaseRoomPolicy::default(),
        roles: roles(),
    };
    p.lock().unwrap().set_room_policy(ROOM, &kept, 1).unwrap();
    let bad = vec![role(1, "gone", vec![])];
    let answer = send(router, ROLES_LIST_COMPONENT_ID, &encode_role_data(&bad)).await;
    assert_invalid(&answer);
    assert_eq!(stored(&p), Some(kept.clone()));

    // A fixed-membership base is refused while a stored role may add participants.
    let (router, p) = app();
    hosted(&p);
    p.lock().unwrap().set_room_policy(ROOM, &kept, 1).unwrap();
    let fixed = BaseRoomPolicy {
        fixed_membership: true,
        ..BaseRoomPolicy::default()
    };
    let answer = send(
        router,
        BASE_ROOM_POLICY_COMPONENT_ID,
        &encode_base_room_policy(&fixed, None),
    )
    .await;
    assert_invalid(&answer);
    assert_eq!(stored(&p), Some(kept));
}
