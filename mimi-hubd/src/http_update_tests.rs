//! `update` against §5.3: the request is an `UpdateRequest` (a `HandshakeBundle`) and the answer an `UpdateRoomResponse`.
//! Every refusal leaves the room's participants and policy as they were, and the answers for a room this hub does not
//! host and for one it refuses are the same bytes.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
    Router,
};
use mimi_core::participant_list::{
    encode_participant_list_update, ParticipantListUpdate, UserRolePair,
    MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use mimi_core::protocol_wire::{
    GroupInfoOption, GroupInfoRepresentation, HandshakeBundle, UpdateRoomResponse,
};
use tower::ServiceExt;

use super::tests::{
    app, bundle_of, real_custom_proposal_and_commit, real_single_custom_proposal_commit,
    update_answer,
};
use crate::http::SharedProvider;

const ROOM: &str = "mimi://havenmessenger.com/r/x";

fn path_of(room: &str) -> String {
    format!(
        "/mimi/pl/update/{}",
        room.replace(':', "%3A").replace('/', "%2F")
    )
}

async fn post(router: Router, room: &str, body: Vec<u8>) -> Response {
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path_of(room))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn add_carol() -> Vec<u8> {
    let update = ParticipantListUpdate {
        added_participants: vec![UserRolePair {
            user_uri: "mimi://havenmessenger.com/u/carol".into(),
            role_index: 2,
        }],
        ..Default::default()
    };
    encode_participant_list_update(&update).unwrap()
}

fn hosted_room_with_alice_and_bob(p: &SharedProvider) {
    for user in ["alice", "bob"] {
        p.lock()
            .unwrap()
            .add_participant(ROOM, &format!("mimi://havenmessenger.com/u/{user}"), 1)
            .unwrap();
    }
}

fn participants(p: &SharedProvider) -> Vec<String> {
    p.lock()
        .unwrap()
        .list_participants(ROOM)
        .unwrap()
        .into_iter()
        .map(|(uri, _)| uri)
        .collect()
}

#[tokio::test]
async fn success_carries_the_hub_time_in_milliseconds() {
    let (router, p) = app();
    hosted_room_with_alice_and_bob(&p);
    let before = super::now_unix_millis();
    let commit =
        real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, add_carol());
    let answer = update_answer(post(router, ROOM, bundle_of(commit)).await).await;
    let after = super::now_unix_millis();
    let UpdateRoomResponse::Success {
        accepted_timestamp, ..
    } = answer
    else {
        panic!("expected success, got {answer:?}");
    };
    assert!(
        (before..=after).contains(&accepted_timestamp),
        "{accepted_timestamp} is not a time in milliseconds between {before} and {after}"
    );
    assert!(participants(&p).contains(&"mimi://havenmessenger.com/u/carol".to_string()));
}

#[tokio::test]
async fn a_room_this_hub_does_not_host_and_a_refused_one_are_answered_with_the_same_bytes() {
    let commit =
        || real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, add_carol());

    // A room under another provider's domain.
    let (router, _p) = app();
    let not_hosted = post(router, "mimi://other.example/r/x", bundle_of(commit())).await;
    // A path segment that is not a room URI at all.
    let (router, _p) = app();
    let not_a_room = post(router, "room1", bundle_of(commit())).await;
    // A hosted room already at the store's participant cap.
    let (router, p) = app();
    for n in 0..crate::store::MAX_PARTICIPANTS_PER_ROOM {
        p.lock()
            .unwrap()
            .add_participant(ROOM, &format!("mimi://havenmessenger.com/u/member{n}"), 1)
            .unwrap();
    }
    let at_cap = post(router, ROOM, bundle_of(commit())).await;

    let mut bodies = Vec::new();
    for response in [not_hosted, not_a_room, at_cap] {
        assert_eq!(response.status(), StatusCode::OK);
        bodies.push(
            axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap(),
        );
    }
    assert_eq!(
        bodies[0], bodies[1],
        "not hosted and not a room answer differently"
    );
    assert_eq!(
        bodies[0], bodies[2],
        "not hosted and refused at the cap answer differently"
    );
    assert!(matches!(
        UpdateRoomResponse::decode(&bodies[0]).unwrap(),
        UpdateRoomResponse::NotAllowed { .. }
    ));
}

#[tokio::test]
async fn a_bundle_of_proposals_is_refused_with_no_state_change() {
    let (router, p) = app();
    hosted_room_with_alice_and_bob(&p);
    let before = participants(&p);
    let (proposal, _commit) =
        real_custom_proposal_and_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, add_carol());
    let body = HandshakeBundle::Proposal {
        proposal_or_commit: proposal,
        more_proposals: Vec::new(),
    }
    .encode()
    .unwrap();
    let answer = update_answer(post(router, ROOM, body).await).await;
    assert!(
        matches!(answer, UpdateRoomResponse::InvalidProposal { .. }),
        "{answer:?}"
    );
    assert_eq!(participants(&p), before);
}

#[tokio::test]
async fn a_welcome_under_another_ciphersuite_is_refused_with_no_state_change() {
    let (router, p) = app();
    hosted_room_with_alice_and_bob(&p);
    let before = participants(&p);
    let commit =
        real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, add_carol());
    // A Welcome whose leading cipher suite is not the pinned one; the suite refusal comes before anything is decoded.
    let foreign_welcome = [vec![0x00, 0x03], vec![0xFF; 16]].concat();
    let body = HandshakeBundle::Commit {
        proposal_or_commit: commit,
        welcome: Some(foreign_welcome),
        group_info_option: GroupInfoOption {
            representation: GroupInfoRepresentation::Partial,
            payload: Vec::new(),
        },
        ratchet_tree_option: Vec::new(),
    }
    .encode()
    .unwrap();
    let answer = update_answer(post(router, ROOM, body).await).await;
    assert!(
        matches!(answer, UpdateRoomResponse::NotAllowed { .. }),
        "{answer:?}"
    );
    assert_eq!(participants(&p), before);
}

#[tokio::test]
async fn a_bare_commit_is_not_an_update_request() {
    let (router, p) = app();
    hosted_room_with_alice_and_bob(&p);
    let before = participants(&p);
    let commit =
        real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, add_carol());
    let answer = update_answer(post(router, ROOM, commit).await).await;
    assert!(
        matches!(answer, UpdateRoomResponse::InvalidProposal { .. }),
        "{answer:?}"
    );
    assert_eq!(participants(&p), before);
}

#[tokio::test]
async fn an_update_that_does_not_fit_the_room_is_invalid_and_changes_nothing() {
    let (router, p) = app();
    hosted_room_with_alice_and_bob(&p);
    let before = participants(&p);
    let update = ParticipantListUpdate {
        removed_indices: vec![99],
        ..Default::default()
    };
    let commit = real_single_custom_proposal_commit(
        MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
        encode_participant_list_update(&update).unwrap(),
    );
    let answer = update_answer(post(router, ROOM, bundle_of(commit)).await).await;
    assert!(
        matches!(answer, UpdateRoomResponse::InvalidProposal { .. }),
        "{answer:?}"
    );
    assert_eq!(participants(&p), before);
}

#[tokio::test]
async fn an_added_participant_that_is_not_a_user_uri_is_invalid_and_changes_nothing() {
    let (router, p) = app();
    hosted_room_with_alice_and_bob(&p);
    let before = participants(&p);
    let update = ParticipantListUpdate {
        added_participants: vec![UserRolePair {
            user_uri: ROOM.into(),
            role_index: 2,
        }],
        ..Default::default()
    };
    let commit = real_single_custom_proposal_commit(
        MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
        encode_participant_list_update(&update).unwrap(),
    );
    let answer = update_answer(post(router, ROOM, bundle_of(commit)).await).await;
    assert!(
        matches!(answer, UpdateRoomResponse::InvalidProposal { .. }),
        "{answer:?}"
    );
    assert_eq!(participants(&p), before);
}

#[test]
fn a_sqlite_failure_is_the_hubs_own_and_any_other_store_error_is_a_refusal() {
    assert_eq!(
        crate::store_refusal(&anyhow::Error::new(rusqlite::Error::InvalidQuery)),
        crate::UpdateRefusal::Store
    );
    assert_eq!(
        crate::store_refusal(&anyhow::anyhow!("participant cap reached for room (256)")),
        crate::UpdateRefusal::NotAllowed
    );
}
