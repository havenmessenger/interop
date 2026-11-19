//! The lane's keyMaterial for a room hosted here, and what the lane does with a room on another hub when this hub has
//! no outbound client. Relaying to a real second hub runs against two hubs in a test client.

use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mimi_core::consent::{ConsentEntry, ConsentOperation};
use mimi_core::protocol_wire::{IdentifierUri, KeyMaterialRequest, KeyMaterialResponse};

use super::client_lane_tests::{call, lane, signed};
use super::tests::real_keypackage_for;
use crate::mls_fixtures::Member;

const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";

fn key_material_body(by: &Member, requesting: &str, target: &str, room: &str) -> String {
    let mut request = KeyMaterialRequest::minimal(requesting, target).unwrap();
    request.room_id = IdentifierUri(room.into());
    request.requester_signature_key = by.credential.signature_key.clone();
    request.requester_credential = by.credential.credential.clone();
    request.sign(&by.signer).unwrap();
    serde_json::json!({ "request": STANDARD.encode(request.encode().unwrap()) }).to_string()
}

/// Alice fetches Bob's KeyPackage for her room through the lane: the hub answers it from its store. A request naming
/// someone else is refused. Revert check: skip the lane's request check and the request naming Bob is answered.
#[tokio::test]
async fn key_material_for_a_room_here_is_answered_and_must_be_the_users_own() {
    let l = lane("relay-km-here");
    let (status, body) = call(&l.router, signed(&l.key, "createRoom", ALICE, "{}")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let room = body["room"].as_str().unwrap().to_string();
    let key_package = real_keypackage_for(BOB.as_bytes());
    l.provider
        .lock()
        .unwrap()
        .publish_key_package("bob", &key_package, super::now_unix())
        .unwrap();
    // Bob has let Alice add him; without it the answer is noConsent, as on the peer route.
    l.provider
        .lock()
        .unwrap()
        .record_consent_decision(
            &ConsentEntry {
                operation: ConsentOperation::Grant,
                requester_uri: ALICE.into(),
                target_uri: BOB.into(),
                room_uri: None,
                client_key_packages: Vec::new(),
                consent_extensions: Vec::new(),
            },
            super::now_unix(),
        )
        .unwrap();

    let alice = Member::new(ALICE);
    let (status, body) = call(
        &l.router,
        signed(
            &l.key,
            "keyMaterial",
            ALICE,
            &key_material_body(&alice, ALICE, BOB, &room),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let bytes = STANDARD.decode(body["response"].as_str().unwrap()).unwrap();
    let accepted = l.provider.lock().unwrap().accepted_suites().to_vec();
    assert!(
        matches!(
            KeyMaterialResponse::decode(&bytes, &accepted).unwrap(),
            KeyMaterialResponse::Success { ref user_uri, .. } if user_uri.0 == BOB
        ),
        "Bob's KeyPackage is served: {:?}",
        KeyMaterialResponse::decode(&bytes, &accepted)
    );

    let bob = Member::new(BOB);
    let (status, _) = call(
        &l.router,
        signed(
            &l.key,
            "keyMaterial",
            ALICE,
            &key_material_body(&bob, BOB, ALICE, &room),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "PLANT-LANE-KM-OWN: a request naming another user is refused"
    );
}

/// A hub with no outbound client answers 502 for a room on another hub, for each relayed route, and changes nothing.
/// Revert check: take the local path for a remote room and submitMessage answers 403 instead.
#[tokio::test]
async fn a_room_on_another_hub_without_an_outbound_client_is_502() {
    let l = lane("relay-no-outbound");
    let remote = "mimi://a.example/r/room";
    let message =
        serde_json::json!({ "room": remote, "message": STANDARD.encode(b"x") }).to_string();
    let (status, _) = call(&l.router, signed(&l.key, "submitMessage", ALICE, &message)).await;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "PLANT-LANE-RELAY-REMOTE: a room on another hub is sent there"
    );
    let update = serde_json::json!({ "room": remote, "update": STANDARD.encode(b"x") }).to_string();
    let (status, _) = call(&l.router, signed(&l.key, "update", ALICE, &update)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let alice = Member::new(ALICE);
    let (status, _) = call(
        &l.router,
        signed(
            &l.key,
            "keyMaterial",
            ALICE,
            &key_material_body(&alice, ALICE, BOB, remote),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}
