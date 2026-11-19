//! A Commit's participant-list change puts users only into roles the room's policy defines, sent through `update` the
//! way a peer sends it. A ban into role 1 needs role 1 defined (room-policy PR #51); a refused change writes nothing.

use mimi_core::participant_list::{
    encode_participant_list_update, ParticipantListUpdate, UserRolePair, UserindexRolePair,
    MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use mimi_core::protocol_wire::UpdateRoomResponse;
use mimi_core::room_policy::{BaseRoomPolicy, Role, RoomPolicy};

use super::room_policy_tests::roles;
use super::tests::{
    app_accepting_untracked_rooms as app, bundle_of, real_single_custom_proposal_commit,
    update_answer,
};
use super::update_tests::{post, ROOM};
use crate::http::SharedProvider;

const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";

/// A hosted room with alice and bob, alice in role 2 and bob in role 3, under `roles`.
fn room_with(p: &SharedProvider, roles: Vec<Role>) {
    let g = p.lock().unwrap();
    for user in [ALICE, BOB] {
        g.add_participant(ROOM, user, 1).unwrap();
    }
    g.set_room_policy(
        ROOM,
        &RoomPolicy {
            base: BaseRoomPolicy::default(),
            roles,
        },
        1,
    )
    .unwrap();
}

fn with_role_1() -> Vec<Role> {
    let mut roles = roles();
    roles.push(Role {
        role_index: 1,
        role_name: "banned".into(),
        capabilities: vec![],
        authorized_role_changes: vec![],
    });
    roles
}

async fn send(router: axum::Router, update: ParticipantListUpdate) -> UpdateRoomResponse {
    let commit = real_single_custom_proposal_commit(
        MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
        encode_participant_list_update(&update).unwrap(),
    );
    update_answer(post(router, ROOM, bundle_of(commit)).await).await
}

/// Move the participant at `user_index` into `role_index`.
fn change(user_index: u32, role_index: u32) -> ParticipantListUpdate {
    ParticipantListUpdate {
        changed_role_participants: vec![UserindexRolePair {
            user_index,
            role_index,
        }],
        ..Default::default()
    }
}

/// The role the hub holds for `user`, if it holds one.
fn role_of(p: &SharedProvider, user: &str) -> Option<u32> {
    p.lock()
        .unwrap()
        .store
        .list_participant_rows(ROOM)
        .unwrap()
        .into_iter()
        .find(|row| row.member_uri == user)
        .and_then(|row| row.role_index)
}

/// Refused by the room's policy: protocol-07 §5.3 `notAllowed`, with the words that say why.
fn is_refused(answer: &UpdateRoomResponse) -> bool {
    matches!(
        answer,
        UpdateRoomResponse::NotAllowed { error_description }
            if error_description.contains("the room's policy does not define")
    )
}

#[tokio::test]
async fn a_ban_into_an_undefined_role_1_is_refused_and_writes_nothing() {
    let (router, p) = app();
    room_with(&p, roles());
    let before = role_of(&p, BOB);
    let answer = send(router, change(1, 1)).await;
    assert!(is_refused(&answer), "{answer:?}");
    assert_eq!(role_of(&p, BOB), before);
}

#[tokio::test]
async fn a_ban_into_a_defined_role_1_is_applied() {
    let (router, p) = app();
    room_with(&p, with_role_1());
    let answer = send(router, change(1, 1)).await;
    assert!(
        matches!(answer, UpdateRoomResponse::Success { .. }),
        "{answer:?}"
    );
    assert_eq!(role_of(&p, BOB), Some(1));
}

#[tokio::test]
async fn a_change_into_a_role_the_policy_does_not_define_is_refused() {
    let (router, p) = app();
    room_with(&p, roles());
    let answer = send(router, change(1, 7)).await;
    assert!(is_refused(&answer), "{answer:?}");
}

#[tokio::test]
async fn an_added_participant_in_an_undefined_role_is_refused() {
    let (router, p) = app();
    room_with(&p, roles());
    let update = ParticipantListUpdate {
        added_participants: vec![UserRolePair {
            user_uri: "mimi://havenmessenger.com/u/carol".into(),
            role_index: 9,
        }],
        ..Default::default()
    };
    let answer = send(router, update).await;
    assert!(is_refused(&answer), "{answer:?}");
    assert_eq!(role_of(&p, "mimi://havenmessenger.com/u/carol"), None);
}

#[tokio::test]
async fn a_change_into_a_defined_role_is_applied() {
    let (router, p) = app();
    room_with(&p, roles());
    let answer = send(router, change(1, 2)).await;
    assert!(
        matches!(answer, UpdateRoomResponse::Success { .. }),
        "{answer:?}"
    );
    assert_eq!(role_of(&p, BOB), Some(2));
}
