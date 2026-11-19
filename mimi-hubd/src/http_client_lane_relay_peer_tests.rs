//! The lane relaying to a room's hub on another provider, against a local peer that records what it is sent: what each
//! route posts, where, and what it answers with.

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mimi_core::protocol_wire::{
    IdentifierUri, KeyMaterialRequest, KeyMaterialResponse, SubmitMessageRequest,
    SubmitMessageResponse, UpdateRoomResponse, PROTOCOL_MLS10,
};
use openmls::prelude::tls_codec::Serialize as _;

use super::client_lane_tests::{call, lane_reaching, signed, Lane};
use crate::client_lane_rooms::LaneRoomProfile;
use crate::mls_fixtures::Member;
use crate::outbound::tests::{answer, loopback_allowed, resolver, server_with, Pki, Seen, PEER};
use crate::peer_directory::{Directories, PeerAccess, PeerBases};

const ALICE: &str = "mimi://havenmessenger.com/u/alice";
/// A room hosted by the peer.
const ROOM: &str = "mimi://peer.example/r/room";
/// A room on the peer whose group has moved past the epoch the client sends in.
const ROOM_BEHIND: &str = "mimi://peer.example/r/behind";
/// A user of a third provider, which this hub cannot reach: a keyMaterial request for them goes to the room's hub.
const CAROL: &str = "mimi://third.example/u/carol";

/// A peer at `PEER` serving its directory, and answering submitMessage accepted (epochTooOld at 9 for `ROOM_BEHIND`),
/// update wrongEpoch 7, keyMaterial with a KeyPackage; and the lane of a hub that reaches it, and only it.
async fn lane_and_peer(test: &str) -> (Lane, Arc<Mutex<Vec<Seen>>>) {
    let pki = Pki::new();
    let key_package = Member::new(CAROL)
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let port = Arc::new(Mutex::new(0u16));
    let port_in = port.clone();
    let (addr, seen) = server_with(&pki, PEER, move |seen| {
        let port = *port_in.lock().unwrap();
        let head = seen.head.as_str();
        if head.starts_with("GET /.well-known/mimi-protocol-directory ") {
            let body = format!(
                r#"{{"submitMessage": "https://{PEER}:{port}/v1/submitMessage/{{roomId}}",
                    "update": "https://{PEER}:{port}/v1/update/{{roomId}}",
                    "keyMaterial": "https://{PEER}:{port}/v1/keyMaterial/{{targetUser}}"}}"#
            );
            return answer("200 OK", "", body.as_bytes());
        }
        if head.starts_with("POST /v1/submitMessage/") && head.contains("behind") {
            let behind = SubmitMessageResponse::EpochTooOld { current_epoch: 9 };
            return answer("200 OK", "", &behind.encode());
        }
        if head.starts_with("POST /v1/submitMessage/") {
            return answer(
                "200 OK",
                "",
                &SubmitMessageResponse::Accepted {
                    accepted_timestamp: 1,
                }
                .encode(),
            );
        }
        if head.starts_with("POST /v1/update/") {
            let wrong = UpdateRoomResponse::WrongEpoch {
                error_description: "the room is at epoch 7".into(),
                current_epoch: 7,
            };
            return answer("200 OK", "", &wrong.encode().unwrap());
        }
        if head.starts_with("POST /v1/keyMaterial/") && head.contains("garbled") {
            return answer("200 OK", "", b"not a KeyMaterialResponse");
        }
        if head.starts_with("POST /v1/keyMaterial/") {
            let success = KeyMaterialResponse::Success {
                user_uri: IdentifierUri(CAROL.into()),
                key_package: key_package.clone(),
            };
            return answer("200 OK", "", &success.encode().unwrap());
        }
        answer("404 Not Found", "", b"")
    })
    .await;
    *port.lock().unwrap() = addr.port();
    let access = PeerAccess {
        client: Arc::new(pki.client(loopback_allowed(), None, resolver(PEER, &[addr]))),
        directories: Arc::new(Directories::new(
            PeerBases::parse(&format!(r#""{PEER}" = "https://{PEER}:{}""#, addr.port())).unwrap(),
        )),
    };
    let lane = lane_reaching(
        test,
        "havenmessenger.com",
        LaneRoomProfile::neutral(),
        Some(Arc::new(access)),
    );
    (lane, seen)
}

fn posted<'a>(seen: &'a [Seen], route: &str) -> Vec<&'a Seen> {
    seen.iter()
        .filter(|seen| seen.head.starts_with(&format!("POST /v1/{route}/")))
        .collect()
}

/// A message into a room on the peer is posted to the peer's submitMessage for that room, as a SubmitMessageRequest
/// naming the lane user as its sender, and the peer's acceptance is the lane's answer.
#[tokio::test]
async fn a_message_for_a_room_on_another_hub_is_posted_there_as_the_user() {
    let (l, seen) = lane_and_peer("relay-peer-submit").await;
    let message = b"opaque PrivateMessage bytes".to_vec();
    let body =
        serde_json::json!({ "room": ROOM, "message": STANDARD.encode(&message) }).to_string();
    let (status, answer) = call(&l.router, signed(&l.key, "submitMessage", ALICE, &body)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let seen = seen.lock().unwrap();
    let posts = posted(&seen, "submitMessage");
    assert_eq!(posts.len(), 1, "one post to the room's hub");
    assert!(posts[0]
        .head
        .contains("mimi%3A%2F%2Fpeer.example%2Fr%2Froom"));
    let expected = SubmitMessageRequest {
        protocol: PROTOCOL_MLS10,
        app_message: message,
        sending_uri: IdentifierUri(ALICE.into()),
    }
    .encode()
    .unwrap();
    assert_eq!(
        posts[0].body, expected,
        "PLANT-LANE-RELAY-SUBMIT: the request names the lane user as its sender"
    );
}

/// A message into a room on the peer whose group has moved on is answered as a room hosted here would be: the client
/// lane's `epoch-too-old`, naming the epoch the room's hub is at, so the user can catch up and resend. Revert check:
/// answer every refusal from the room's hub `not-permitted`, and the user is told nothing about the epoch.
#[tokio::test]
async fn a_room_hubs_epoch_too_old_reaches_the_user_with_its_epoch() {
    let (l, seen) = lane_and_peer("relay-peer-submit-behind").await;
    let body = serde_json::json!({ "room": ROOM_BEHIND, "message": STANDARD.encode(b"old epoch") })
        .to_string();
    let (status, answer) = call(&l.router, signed(&l.key, "submitMessage", ALICE, &body)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "PLANT-LANE-RELAY-EPOCH-TOO-OLD: the room's hub's epochTooOld did not reach the user: {answer}"
    );
    assert!(
        answer["type"]
            .as_str()
            .is_some_and(|kind| kind.ends_with("#epoch-too-old")),
        "{answer}"
    );
    assert_eq!(answer["current_epoch"], 9);
    assert_eq!(posted(&seen.lock().unwrap(), "submitMessage").len(), 1);
}

/// An update for a room on the peer is posted there as the bundle the client sent, and the peer's answer is passed on
/// unchanged.
#[tokio::test]
async fn an_update_for_a_room_on_another_hub_is_answered_as_that_hub_answers() {
    let (l, seen) = lane_and_peer("relay-peer-update").await;
    let update = b"an UpdateRequest as the wire carries it".to_vec();
    let body = serde_json::json!({ "room": ROOM, "update": STANDARD.encode(&update) }).to_string();
    let (status, answer) = call(&l.router, signed(&l.key, "update", ALICE, &body)).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer["answer"], "wrongEpoch",
        "PLANT-LANE-RELAY-UPDATE: the room's hub's answer is the lane's"
    );
    assert_eq!(answer["current_epoch"], 7);
    let seen = seen.lock().unwrap();
    let posts = posted(&seen, "update");
    assert_eq!(posts.len(), 1);
    assert_eq!(
        posts[0].body, update,
        "the bundle is sent as the client sent it"
    );
}

/// keyMaterial for a room on the peer goes to the peer, the room's hub (protocol-07 §5.2), not to the provider of the
/// user asked for, which this hub cannot even reach; its answer is passed on. Revert check: send it to the target's
/// provider and the lane answers 502.
#[tokio::test]
async fn key_material_for_a_room_on_another_hub_goes_to_that_hub() {
    let (l, seen) = lane_and_peer("relay-peer-km").await;
    let alice = Member::new(ALICE);
    let mut request = KeyMaterialRequest::minimal(ALICE, CAROL).unwrap();
    request.room_id = IdentifierUri(ROOM.into());
    request.requester_signature_key = alice.credential.signature_key.clone();
    request.requester_credential = alice.credential.credential.clone();
    request.sign(&alice.signer).unwrap();
    let body =
        serde_json::json!({ "request": STANDARD.encode(request.encode().unwrap()) }).to_string();
    let (status, answer) = call(&l.router, signed(&l.key, "keyMaterial", ALICE, &body)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PLANT-LANE-RELAY-KM-HUB: the request goes to the room's hub: {answer}"
    );
    let bytes = STANDARD
        .decode(answer["response"].as_str().unwrap())
        .unwrap();
    assert!(matches!(
        KeyMaterialResponse::decode(&bytes, &[0x0001]).unwrap(),
        KeyMaterialResponse::Success { .. }
    ));
    let seen = seen.lock().unwrap();
    let posts = posted(&seen, "keyMaterial");
    assert_eq!(posts.len(), 1);
    assert!(posts[0]
        .head
        .contains("mimi%3A%2F%2Fthird.example%2Fu%2Fcarol"));
}

/// An answer from the room's hub that does not decode as a KeyMaterialResponse is not passed on: 502. Revert check:
/// pass the bytes through undecoded and the lane answers 200.
#[tokio::test]
async fn an_undecodable_key_material_answer_is_not_passed_on() {
    let (l, _seen) = lane_and_peer("relay-peer-km-garbled").await;
    let alice = Member::new(ALICE);
    let mut request = KeyMaterialRequest::minimal(ALICE, "mimi://third.example/u/garbled").unwrap();
    request.room_id = IdentifierUri(ROOM.into());
    request.requester_signature_key = alice.credential.signature_key.clone();
    request.requester_credential = alice.credential.credential.clone();
    request.sign(&alice.signer).unwrap();
    let body =
        serde_json::json!({ "request": STANDARD.encode(request.encode().unwrap()) }).to_string();
    let (status, _) = call(&l.router, signed(&l.key, "keyMaterial", ALICE, &body)).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "PLANT-LANE-RELAY-KM-DECODE: a garbled answer is a 502"
    );
}
