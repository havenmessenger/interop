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
use tls_codec::Serialize as _;
use tower::ServiceExt;

use super::tests::{
    app, bundle_of, real_custom_proposal_and_commit, real_single_custom_proposal_commit,
    update_answer,
};
use crate::http::SharedProvider;

pub(super) const ROOM: &str = "mimi://havenmessenger.com/r/x";

fn path_of(room: &str) -> String {
    format!(
        "/mimi/pl/update/{}",
        room.replace(':', "%3A").replace('/', "%2F")
    )
}

pub(super) async fn post(router: Router, room: &str, body: Vec<u8>) -> Response {
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

fn vl(bytes: &[u8]) -> Vec<u8> {
    tls_codec::VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

/// The length prefix a `<V>` field of `len` bytes carries.
fn length_prefix(len: usize) -> Vec<u8> {
    let whole = vl(&vec![0u8; len]);
    whole[..whole.len() - len].to_vec()
}

/// The Commit with its one custom proposal rewritten as an AppDataUpdate (mls-extensions-10 §4.7: type 0x0008, a two-byte
/// component id, the operation, `update<V>`), with the proposals window's length prefix adjusted to match.
pub(super) fn as_app_data_update(commit: &[u8], payload: &[u8], component: u16) -> Vec<u8> {
    let entry = [vec![0x01, 0xF7, 0xA0], vl(payload)].concat();
    let found = [length_prefix(entry.len()), entry].concat();
    let at = commit
        .windows(found.len())
        .position(|w| w == found.as_slice())
        .expect("the commit's one custom proposal");
    let entry = [
        vec![0x01, 0x00, 0x08],
        component.to_be_bytes().to_vec(),
        vec![0x01],
        vl(payload),
    ]
    .concat();
    let replacement = [length_prefix(entry.len()), entry].concat();
    [&commit[..at], &replacement, &commit[at + found.len()..]].concat()
}

#[tokio::test]
async fn an_app_data_update_for_the_participant_list_is_applied_like_the_private_form() {
    let (router, p) = app();
    hosted_room_with_alice_and_bob(&p);
    let payload = add_carol();
    let commit =
        real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, payload.clone());
    let sent = as_app_data_update(&commit, &payload, 0x0022);
    assert_ne!(sent, commit);
    let answer = update_answer(post(router, ROOM, bundle_of(sent)).await).await;
    assert!(
        matches!(answer, UpdateRoomResponse::Success { .. }),
        "{answer:?}"
    );
    assert!(participants(&p).contains(&"mimi://havenmessenger.com/u/carol".to_string()));
}

#[tokio::test]
async fn an_app_data_update_for_another_component_is_invalid_and_changes_nothing() {
    for component in [0x0020u16, 0x0021, 0x0023] {
        let (router, p) = app();
        hosted_room_with_alice_and_bob(&p);
        let before = participants(&p);
        let payload = add_carol();
        let commit = real_single_custom_proposal_commit(
            MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
            payload.clone(),
        );
        let sent = as_app_data_update(&commit, &payload, component);
        let answer = update_answer(post(router, ROOM, bundle_of(sent)).await).await;
        assert!(
            matches!(answer, UpdateRoomResponse::InvalidProposal { .. }),
            "{component:#06x}: {answer:?}"
        );
        assert_eq!(participants(&p), before, "{component:#06x}");
    }
}

#[tokio::test]
async fn an_app_data_update_that_is_not_a_participant_list_update_is_invalid_and_changes_nothing() {
    let (router, p) = app();
    hosted_room_with_alice_and_bob(&p);
    let before = participants(&p);
    let garbage = vec![0xFF; 5];
    let commit =
        real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, garbage.clone());
    let sent = as_app_data_update(&commit, &garbage, 0x0022);
    let answer = update_answer(post(router, ROOM, bundle_of(sent)).await).await;
    assert!(
        matches!(answer, UpdateRoomResponse::InvalidProposal { .. }),
        "{answer:?}"
    );
    assert_eq!(participants(&p), before);
}

fn from_hex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// Every `UpdateRequest` in the committed protocol-07 vectors is posted to a room that holds the participants the vector
/// names, and the hub answers as the vector records and leaves the room as the vector records.
#[tokio::test]
async fn every_update_request_vector_gets_its_recorded_answer() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/vectors/protocol07-vectors.json")).unwrap();
    let mut checked = 0;
    for vector in vectors["vectors"].as_array().unwrap() {
        if vector["kind"] != "UpdateRequest" {
            continue;
        }
        let id = vector["id"].as_str().unwrap();
        let room = vector["room"].as_str().unwrap();
        let (router, p) = app();
        for user in vector["participants_before"].as_array().unwrap() {
            p.lock()
                .unwrap()
                .add_participant(room, user.as_str().unwrap(), 1)
                .unwrap();
        }
        let body = from_hex(vector["hex"].as_str().unwrap());
        let answer = update_answer(post(router, room, body).await).await;
        let kind = match answer {
            UpdateRoomResponse::Success { .. } => "success",
            UpdateRoomResponse::NotAllowed { .. } => "notAllowed",
            UpdateRoomResponse::InvalidProposal { .. } => "invalidProposal",
            UpdateRoomResponse::WrongEpoch { .. } => "wrongEpoch",
        };
        assert_eq!(kind, vector["answer"].as_str().unwrap(), "{id}: answer");
        // In list order: protocol-07 section 7.5 makes an index a position, and an added participant goes to the end.
        let after: Vec<String> = participants_of(&p, room);
        let want: Vec<String> = vector["participants_after"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u.as_str().unwrap().to_string())
            .collect();
        assert_eq!(after, want, "{id}: participants after");
        checked += 1;
    }
    assert!(checked >= 12, "the vector set carries update requests");
}

fn participants_of(p: &SharedProvider, room: &str) -> Vec<String> {
    p.lock()
        .unwrap()
        .list_participants(room)
        .unwrap()
        .into_iter()
        .map(|(uri, _)| uri)
        .collect()
}
