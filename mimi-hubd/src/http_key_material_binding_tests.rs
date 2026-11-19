//! keyMaterial on the provider path is taken only from a peer that speaks for its requester (the requester's provider, or
//! the hub of the room the request names), and only for the one user both its path and its body name.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use mimi_core::consent::{ConsentEntry, ConsentOperation};
use mimi_core::protocol_wire::{IdentifierUri, KeyMaterialRequest, KeyMaterialResponse};
use tower::ServiceExt;

use super::now_unix;
use super::tests::{app, real_keypackage};
use crate::http::SharedProvider;
use crate::peer::{PeerCert, PeerIdentity};

const BOB: &str = "mimi://havenmessenger.com/u/bob";
const CAROL: &str = "mimi://havenmessenger.com/u/carol";
/// A user of a provider that is neither this one nor the peer asking.
const ZED: &str = "mimi://third.example/u/zed";
/// A user of this provider.
const ALICE: &str = "mimi://havenmessenger.com/u/alice";
/// A room hosted by `hub.example`.
const HUB_ROOM: &str = "mimi://hub.example/r/room";

fn grant(p: &SharedProvider, requester: &str, target: &str) {
    p.lock()
        .unwrap()
        .record_consent_decision(
            &ConsentEntry {
                operation: ConsentOperation::Grant,
                requester_uri: requester.into(),
                target_uri: target.into(),
                room_uri: None,
                client_key_packages: Vec::new(),
                consent_extensions: Vec::new(),
            },
            now_unix(),
        )
        .unwrap();
}

fn stock(p: &SharedProvider, name: &str) {
    p.lock()
        .unwrap()
        .add_key_package(name, &real_keypackage(), now_unix() + 100)
        .unwrap();
}

/// POST a keyMaterial request by `requester` for `target`, in `room` when not empty, to the path naming `path_user`,
/// from a peer whose proof authenticates `peer_domain`.
async fn ask(
    router: &Router,
    peer_domain: &str,
    path_user: &str,
    requester: &str,
    target: &str,
    room: &str,
) -> (StatusCode, Vec<u8>) {
    let mut request = KeyMaterialRequest::minimal(requester, target).unwrap();
    request.room_id = IdentifierUri(room.into());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .extension(PeerCert(Some(PeerIdentity::signed(peer_domain))))
                .uri(format!("/mimi/pl/keyMaterial/{path_user}"))
                .body(Body::from(request.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

fn served(body: &[u8]) -> bool {
    matches!(
        KeyMaterialResponse::decode(body, &[0x0001]),
        Ok(KeyMaterialResponse::Success { .. })
    )
}

fn still_stocked(p: &SharedProvider, name: &str) -> bool {
    p.lock()
        .unwrap()
        .serve_key_material(name, now_unix())
        .unwrap()
        .is_some()
}

/// A peer naming a requester of another provider, with no room it hosts, is refused (403 `not-permitted`), and the
/// target's KeyPackage is not taken, although the requester was granted consent. Revert check: drop the binding, and
/// the KeyPackage is served to whoever names a consented requester.
#[tokio::test]
async fn a_peer_that_speaks_for_neither_the_requester_nor_the_room_is_refused() {
    let (router, p) = app();
    grant(&p, ZED, BOB);
    stock(&p, "bob");
    let (status, _) = ask(&router, "mallory.example", "bob", ZED, BOB, "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "PLANT-KM-PEER-BINDING: a peer that does not speak for the requester was served"
    );
    let (status, _) = ask(&router, "mallory.example", "bob", ZED, BOB, HUB_ROOM).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a room on yet another provider"
    );
    assert!(
        still_stocked(&p, "bob"),
        "a refused request took the KeyPackage"
    );
}

/// The requester's own provider is served.
#[tokio::test]
async fn the_requesters_provider_is_served() {
    let (router, p) = app();
    grant(&p, ZED, BOB);
    stock(&p, "bob");
    let (status, body) = ask(&router, "third.example", "bob", ZED, BOB, "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(served(&body));
}

/// The hub of the room the request names is served for a requester of a third provider, and for a user of this one:
/// protocol-07 §5.2 sends every keyMaterial request through the room's hub. Revert check: bind to the requester's
/// provider alone, and both are refused.
#[tokio::test]
async fn the_rooms_hub_is_served_for_any_requester() {
    let (router, p) = app();
    grant(&p, ZED, BOB);
    grant(&p, ALICE, CAROL);
    stock(&p, "bob");
    stock(&p, "carol");
    let (status, body) = ask(&router, "hub.example", "bob", ZED, BOB, HUB_ROOM).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PLANT-KM-HUB-FORWARD: the room's hub was refused"
    );
    assert!(served(&body));
    let (status, body) = ask(&router, "hub.example", "carol", ALICE, CAROL, HUB_ROOM).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a user of this provider, through the room's hub"
    );
    assert!(served(&body));
}

/// A peer never speaks for a user of this provider on its own, nor as the hub of a room this provider hosts.
#[tokio::test]
async fn a_peer_does_not_speak_for_this_providers_users() {
    let (router, p) = app();
    grant(&p, ALICE, BOB);
    stock(&p, "bob");
    let (status, _) = ask(&router, "havenmessenger.com", "bob", ALICE, BOB, "").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no room");
    let local_room = "mimi://havenmessenger.com/r/room";
    let (status, _) = ask(&router, "hub.example", "bob", ALICE, BOB, local_room).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a room hosted here");
    assert!(still_stocked(&p, "bob"));
}

/// The path names the user whose KeyPackage is taken and the body the user whose consent is read: a request where they
/// differ is refused (400 `malformed-request`) and takes nothing. Revert check: drop the comparison, and Zed, granted
/// consent by Carol, is served Bob's KeyPackage.
#[tokio::test]
async fn a_path_and_body_naming_different_users_is_refused() {
    let (router, p) = app();
    grant(&p, ZED, CAROL);
    stock(&p, "bob");
    let (status, _) = ask(&router, "third.example", "bob", ZED, CAROL, "").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PLANT-KM-ONE-TARGET: the path's user was served on the body's user's consent"
    );
    assert!(still_stocked(&p, "bob"), "Bob's KeyPackage was taken");
    // Another spelling of the same user is the same user.
    stock(&p, "carol");
    let (status, body) = ask(&router, "third.example", "carol", ZED, CAROL, "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(served(&body));
}

/// A refused request spends no requester's budget: after more refusals than the limit, the requester's provider is
/// still served up to it. Revert check: count before the binding, and the requester's own provider gets a 429.
#[tokio::test]
async fn a_refused_request_spends_no_budget() {
    let (router, p) = app();
    grant(&p, ZED, BOB);
    for _ in 0..crate::client_lane_relay::KEY_MATERIAL_PER_TARGET_PER_HOUR + 1 {
        let (status, _) = ask(&router, "mallory.example", "bob", ZED, BOB, "").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, _) = ask(&router, "third.example", "bob", ZED, BOB, "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PLANT-KM-COUNT-AFTER-BINDING: refused requests spent the requester's budget"
    );
}
