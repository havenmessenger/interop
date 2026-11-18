//! The client lane's room routes: createRoom, submitMessage and update, each acting as the verified user.

use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use super::client_lane_tests::{call, lane, signed};
use super::tests::bundle_of;
use super::update_leave_tests::{bobs_leave, bundle, by_value_change, commit_of, list_change};
use crate::client_lane_rooms::{ROLE_ADMIN, ROLE_MEMBER};

const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const DAVE: &str = "mimi://havenmessenger.com/u/dave";

const CREATE: &str = r#"{"policy":"haven-default"}"#;

/// Alice's new room, through the lane.
async fn alices_room(l: &super::client_lane_tests::Lane) -> String {
    let (status, body) = call(&l.router, signed(&l.key, "createRoom", ALICE, CREATE)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["room"].as_str().expect("room").to_string()
}

/// A room made through the lane is hosted here, under a fresh URI, with its creator as the only participant and its
/// admin, and refuses external Commits. Revert check: leave external Commits allowed, and the room takes them.
#[tokio::test]
async fn create_room_makes_the_user_its_admin_with_external_commits_refused() {
    let l = lane("create-room");
    let room = alices_room(&l).await;
    let id = room
        .strip_prefix("mimi://havenmessenger.com/r/")
        .expect("a room hosted here");
    assert!(
        id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit()),
        "{room}"
    );
    let p = l.provider.lock().unwrap();
    assert_eq!(
        p.list_participants(&room).unwrap(),
        vec![(ALICE.to_string(), "havenmessenger.com".to_string())]
    );
    assert_eq!(p.store.member_role(&room, ALICE).unwrap(), Some(ROLE_ADMIN));
    assert!(
        !p.external_commits_allowed(&room).unwrap(),
        "PLANT-LANE-ROOM-EXTERNAL: a lane room allows external Commits"
    );
    drop(p);
    assert_ne!(alices_room(&l).await, room, "each room is new");
}

/// createRoom names one policy; anything else is refused and makes no room.
#[tokio::test]
async fn create_room_takes_only_the_one_policy() {
    let l = lane("create-room-policy");
    for body in [r#"{"policy":"open"}"#, r#"{}"#] {
        let (status, _) = call(&l.router, signed(&l.key, "createRoom", ALICE, body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
}

/// A participant's message reaches the room's other local member, and not its sender; a user who is not a participant
/// is refused and nothing is queued. Revert check: skip the sender's authorization, and Dave's message reaches Bob.
#[tokio::test]
async fn a_participant_sends_and_a_non_participant_is_refused() {
    let l = lane("submit");
    let room = alices_room(&l).await;
    {
        let p = l.provider.lock().unwrap();
        p.add_participant(&room, BOB, 1).unwrap();
        p.set_member_role(&room, BOB, ROLE_MEMBER).unwrap();
    }
    let send = |message: &[u8]| {
        format!(
            r#"{{"room":"{room}","message":"{}"}}"#,
            STANDARD.encode(message)
        )
    };
    let (status, body) = call(
        &l.router,
        signed(&l.key, "submitMessage", ALICE, &send(b"one")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(
        &l.router,
        signed(&l.key, "submitMessage", DAVE, &send(b"two")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let p = l.provider.lock().unwrap();
    let bobs = p.lane_inbox(BOB, 0, 0, 10).unwrap().messages;
    let bobs: Vec<Vec<u8>> = bobs.into_iter().map(|item| item.bytes).collect();
    assert_eq!(
        bobs,
        vec![b"one".to_vec()],
        "PLANT-LANE-SUBMIT: a non-participant's message was delivered"
    );
    assert!(p.lane_inbox(ALICE, 0, 0, 10).unwrap().messages.is_empty());
}

/// An update sent on the lane goes through the same checks as on the wire and answers with the wire's answers: a Commit
/// at the room's epoch is applied, the same Commit again is of a past epoch, and bytes that are no UpdateRequest are an
/// invalid proposal.
#[tokio::test]
async fn an_update_from_the_lane_applies_and_answers_like_the_wire() {
    let l = lane("update");
    let room = alices_room(&l).await;
    let commit = bundle_of(commit_of(0, &[by_value_change(&list_change(&[BOB], &[]))]));
    let update = |bytes: &[u8]| {
        format!(
            r#"{{"room":"{room}","update":"{}"}}"#,
            STANDARD.encode(bytes)
        )
    };
    let (status, body) = call(&l.router, signed(&l.key, "update", ALICE, &update(&commit))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"answer": "success", "epoch": 1}));
    assert_eq!(
        l.provider
            .lock()
            .unwrap()
            .list_participants(&room)
            .unwrap()
            .len(),
        2
    );
    let (_, body) = call(&l.router, signed(&l.key, "update", ALICE, &update(&commit))).await;
    assert_eq!(
        body,
        serde_json::json!({"answer": "wrongEpoch", "current_epoch": 1})
    );
    let (_, body) = call(
        &l.router,
        signed(&l.key, "update", ALICE, &update(b"not one")),
    )
    .await;
    assert_eq!(body["answer"], "invalidProposal", "{body}");
}

/// The lane's update acts as its user: Bob's leave, carried in Alice's request, is refused; in Bob's own, it is held.
/// Revert check: send lane updates as an anonymous peer, and Bob's own leave is refused too.
#[tokio::test]
async fn a_leave_on_the_lane_is_its_senders_own() {
    let l = lane("leave");
    let room = alices_room(&l).await;
    let update = |bytes: &[u8]| {
        format!(
            r#"{{"room":"{room}","update":"{}"}}"#,
            STANDARD.encode(bytes)
        )
    };
    let add_bob = bundle_of(commit_of(0, &[by_value_change(&list_change(&[BOB], &[]))]));
    let (_, body) = call(
        &l.router,
        signed(&l.key, "update", ALICE, &update(&add_bob)),
    )
    .await;
    assert_eq!(body["answer"], "success", "{body}");
    let (messages, _, _) = bobs_leave();
    let leave = bundle(&messages);
    let (_, body) = call(&l.router, signed(&l.key, "update", ALICE, &update(&leave))).await;
    assert_eq!(body["answer"], "notAllowed", "{body}");
    let (_, body) = call(&l.router, signed(&l.key, "update", BOB, &update(&leave))).await;
    assert_eq!(
        body["answer"], "success",
        "PLANT-LANE-UPDATE-REQUESTER: Bob's own leave on the lane was refused: {body}"
    );
}
