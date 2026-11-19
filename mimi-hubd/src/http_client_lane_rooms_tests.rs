//! The client lane's room routes: createRoom, submitMessage and update, each acting as the verified user.

use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use super::client_lane_tests::{call, lane, lane_with, signed};
use super::tests::bundle_of;
use super::update_leave_tests::{bobs_leave, bundle, by_value_change, commit_of, list_change};
use crate::client_lane_rooms::{LaneRoomProfile, ROLE_ADMIN, ROLE_MEMBER};

const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const DAVE: &str = "mimi://havenmessenger.com/u/dave";

const CREATE: &str = "{}";

/// Alice's new room, through the lane.
async fn alices_room(l: &super::client_lane_tests::Lane) -> String {
    let (status, body) = call(&l.router, signed(&l.key, "createRoom", ALICE, CREATE)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["room"].as_str().expect("room").to_string()
}

/// A room made through the lane with the neutral profile is hosted here, under a fresh URI, with its creator as the only
/// participant and its admin, and refuses external Commits. Revert check: leave external Commits allowed, and the room
/// takes them.
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

/// createRoom takes nothing from the client: a request naming a policy is refused.
#[tokio::test]
async fn create_room_takes_no_policy_from_the_client() {
    let l = lane("create-room-policy");
    for body in [
        r#"{"policy":"haven-default"}"#,
        r#"{"policy":"open"}"#,
        "not json",
    ] {
        let (status, _) = call(&l.router, signed(&l.key, "createRoom", ALICE, body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
}

/// The deployment's profile decides what a lane room starts with: under a profile whose creator is a member and whose
/// rooms allow external Commits, the room is so. Revert check: create every room from the neutral profile, and this
/// room refuses external Commits.
#[tokio::test]
async fn the_deployments_profile_decides_the_room() {
    let mut profile = LaneRoomProfile::neutral();
    profile.creator_role = ROLE_MEMBER;
    profile.external_commit_allowed = true;
    let l = lane_with("create-room-profile", profile);
    let room = alices_room(&l).await;
    let p = l.provider.lock().unwrap();
    assert_eq!(
        p.store.member_role(&room, ALICE).unwrap(),
        Some(ROLE_MEMBER)
    );
    assert!(
        p.external_commits_allowed(&room).unwrap(),
        "PLANT-LANE-PROFILE: the room ignored the deployment's profile"
    );
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
    let mut chatter = crate::mls_fixtures::Chatter::new();
    let (one, two) = (chatter.say(b"one"), chatter.say(b"two"));
    let (status, body) = call(
        &l.router,
        signed(&l.key, "submitMessage", ALICE, &send(&one)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(
        &l.router,
        signed(&l.key, "submitMessage", DAVE, &send(&two)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let p = l.provider.lock().unwrap();
    let bobs = p.lane_inbox(BOB, 0, 0, 10).unwrap().messages;
    let bobs: Vec<Vec<u8>> = bobs.into_iter().map(|item| item.bytes).collect();
    assert_eq!(
        bobs,
        vec![one],
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
    // Alice's Commits here are hand-built: no tree could take them.
    l.provider.lock().unwrap().policy.untracked_rooms = crate::policy::UntrackedRooms::Accept;
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
    // Alice's Commits here are hand-built: no tree could take them.
    l.provider.lock().unwrap().policy.untracked_rooms = crate::policy::UntrackedRooms::Accept;
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

/// A lane message for an earlier epoch of a room whose tree the hub keeps is answered `epoch-too-old`, and the body says
/// which epoch the room is at, so the client knows what to catch up to. Revert check: answer the bare problem, and the
/// body has no `current_epoch`.
#[tokio::test]
async fn an_old_epochs_message_is_told_the_rooms_epoch() {
    use crate::mls_fixtures::{add_commit, application_message, Member};
    use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};

    let l = lane("submit-old-epoch");
    let room = alices_room(&l).await;
    let alice = Member::new(ALICE);
    let mut group = alice.create_group(b"lane-old-epoch");
    add_commit(&mut group, &alice, &[&Member::new(BOB)]);
    let at_one = application_message(&mut group, &alice, b"at epoch 1");
    let (_, group_info, tree) = add_commit(&mut group, &alice, &[&Member::new(DAVE)]);
    {
        let p = l.provider.lock().unwrap();
        p.store.commit_accepted_at(&room, 1).unwrap();
        p.seed_room_tree(
            &room,
            1,
            crate::requester::Requester::LaneUser(ALICE),
            &GroupInfoOption {
                representation: GroupInfoRepresentation::Full,
                payload: group_info,
            },
            &[&[1u8][..], &tree].concat(),
        );
        assert!(
            p.room_tracking(&room).unwrap().is_some(),
            "the room is tracked"
        );
    }
    let request = format!(
        r#"{{"room":"{room}","message":"{}"}}"#,
        STANDARD.encode(&at_one)
    );
    let (status, body) = call(&l.router, signed(&l.key, "submitMessage", ALICE, &request)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        body["current_epoch"], 2,
        "PLANT-LANE-EPOCH-TOO-OLD: the lane's answer does not say the room's epoch: {body}"
    );
}
