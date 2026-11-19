//! Two hubs, each with its client lane: a user of hub A makes a room there and adds a user of hub B, whose KeyPackage
//! B took through its lane; B's user gets the Welcome and then the room's message in their lane inbox, and acknowledges
//! them. Delivery from A to B is A's outbox handed to B's `notify` as A's outbox worker would post it, with A's
//! certificate, and each answer handled as the worker does (`201` delivered, a refusal for good dropped).
//!
//! A claims Bob's KeyPackage from B here by recording the claim, as A's keyMaterial client does when it fetches one from
//! another provider (`associate_claimed_keypackage`); the lane's own keyMaterial for a remote user is not built yet.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{Extension, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation, HandshakeBundle};
use tower::ServiceExt;

use super::client_lane_tests::{call, lane_at, signed, Lane};
use super::notify_welcome_tests::welcome_adding;
use super::tests::{real_keypackage_for, real_mls_envelope_bytes};
use super::update_leave_tests::{by_value_change, commit_of, list_change};
use crate::client_lane_rooms::LaneRoomProfile;
use crate::peer::{PeerCert, PeerIdentity};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};

const HUB_A: &str = "a.example";
const HUB_B: &str = "havenmessenger.com";
const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";

/// Hub A's certificate, as B's peer listener sees it.
fn hub_a() -> PeerCert {
    let (ca, _) = make_ca();
    let (cert_pem, _) = issue(&ca, vec![HUB_A.to_string()], "a");
    let chain = certs_from_pem(cert_pem.as_bytes()).unwrap();
    PeerCert(Some(PeerIdentity::new(chain[0].clone().into_owned())))
}

/// Post every row in A's outbox to B's `notify` for its room, as A, oldest first, as the outbox worker does: a `201`
/// is delivered and a refusal for good (`outbox::refused_for_good`) dropped, either way removing the row. Returns
/// (delivered, refused).
async fn deliver_outbox(a: &Lane, b_peer: &Router) -> (usize, usize) {
    let (mut delivered, mut refused) = (0, 0);
    // Only a queue's head is due, so the next row of a queue comes due once the head before it is removed.
    loop {
        let heads = a
            .provider
            .lock()
            .unwrap()
            .store
            .due_outbox_heads(u64::MAX, &[])
            .unwrap();
        let Some(row) = heads.into_iter().next() else {
            break;
        };
        assert_eq!(row.domain, HUB_B, "A sends only to B");
        let status = b_peer
            .clone()
            .layer(Extension(hub_a()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/mimi/pl/notify/{}",
                        row.room_uri.replace(':', "%3A").replace('/', "%2F")
                    ))
                    .body(Body::from(row.body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        match status.as_u16() {
            201 => delivered += 1,
            code if crate::outbox::refused_for_good(code) => refused += 1,
            code => panic!("B answered {code}, which the worker would retry"),
        }
        a.provider
            .lock()
            .unwrap()
            .store
            .remove_outbox_row(row.id)
            .unwrap();
    }
    (delivered, refused)
}

/// Alice on hub A adds Bob of hub B to a room she made through her lane; Bob, through his, finds the Welcome and then
/// Alice's message, oldest first, and acknowledging them leaves his inbox empty. Revert check: let A's lane update drop
/// the Commit bundle's Welcome, and no Welcome reaches B.
#[tokio::test]
async fn a_user_of_another_hub_is_welcomed_and_reads_the_room_through_their_lane() {
    let a = lane_at("two-hubs-a", HUB_A, LaneRoomProfile::neutral());
    let b = lane_at("two-hubs-b", HUB_B, LaneRoomProfile::neutral());
    let b_peer = crate::http::build_router(b.provider.clone());

    // Bob publishes a KeyPackage through B's lane.
    let bobs = real_keypackage_for(BOB.as_bytes());
    let publish = format!(r#"{{"key_packages":["{}"]}}"#, STANDARD.encode(&bobs));
    let (status, body) = call(
        &b.router,
        signed(&b.key, "publishKeyPackages", BOB, &publish),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A claims it from B, as its keyMaterial client would.
    a.provider
        .lock()
        .unwrap()
        .associate_claimed_keypackage(&bobs, HUB_B, u64::MAX / 2)
        .unwrap();

    // Alice makes a room on A through A's lane.
    let (status, body) = call(&a.router, signed(&a.key, "createRoom", ALICE, "{}")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let room = body["room"].as_str().unwrap().to_string();

    // Alice's Commit adds Bob to the room's list, with the Welcome for Bob's KeyPackage. A bundle carries the Welcome
    // bare, without its MLSMessage header; the hub wraps it again to send it on, so Bob gets the MLSMessage.
    let welcome = welcome_adding(&bobs);
    let bare = welcome
        .strip_prefix(&[0x00, 0x01, 0x00, 0x03][..])
        .expect("an mls_welcome MLSMessage")
        .to_vec();
    let update = HandshakeBundle::Commit {
        proposal_or_commit: commit_of(0, &[by_value_change(&list_change(&[BOB], &[]))]),
        welcome: Some(bare),
        group_info_option: GroupInfoOption {
            representation: GroupInfoRepresentation::Partial,
            // The least PartialGroupInfo: no tree, no extensions, an empty signature.
            payload: vec![0, 0, 0],
        },
        ratchet_tree_option: Vec::new(),
    }
    .encode()
    .unwrap();
    let request = format!(
        r#"{{"room":"{room}","update":"{}"}}"#,
        STANDARD.encode(&update)
    );
    let (_, body) = call(&a.router, signed(&a.key, "update", ALICE, &request)).await;
    assert_eq!(body["answer"], "success", "{body}");
    // To B the Commit goes first and is refused for good (B has no member of the room until the Welcome), then the
    // Welcome is delivered.
    assert_eq!(
        deliver_outbox(&a, &b_peer).await,
        (1, 1),
        "the Welcome reached B"
    );

    // Alice sends a message; it reaches B the same way.
    let message = real_mls_envelope_bytes();
    let send = format!(
        r#"{{"room":"{room}","message":"{}"}}"#,
        STANDARD.encode(&message)
    );
    let (status, body) = call(&a.router, signed(&a.key, "submitMessage", ALICE, &send)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        deliver_outbox(&a, &b_peer).await,
        (1, 0),
        "the message reached B"
    );

    // Bob reads both through B's lane, and acknowledges them.
    let (status, page) = call(&b.router, signed(&b.key, "inboxFetch", BOB, "{}")).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let bytes = |items: &serde_json::Value| -> Vec<Vec<u8>> {
        items
            .as_array()
            .unwrap()
            .iter()
            .map(|item| STANDARD.decode(item["bytes"].as_str().unwrap()).unwrap())
            .collect()
    };
    assert_eq!(
        bytes(&page["welcomes"]),
        vec![welcome],
        "PLANT-TWO-HUBS: Bob's lane inbox does not hold the Welcome"
    );
    assert_eq!(bytes(&page["messages"]), vec![message.clone()]);
    let ack = format!(
        r#"{{"welcomes_up_to":{},"messages_up_to":{}}}"#,
        page["welcomes"][0]["seq"], page["messages"][0]["seq"]
    );
    let (status, _) = call(&b.router, signed(&b.key, "inboxAck", BOB, &ack)).await;
    assert_eq!(status, StatusCode::OK);
    let (_, page) = call(&b.router, signed(&b.key, "inboxFetch", BOB, "{}")).await;
    assert_eq!(
        page,
        serde_json::json!({"welcomes": [], "messages": [], "more": false})
    );
    // Alice's inbox at A holds the Commit, as every local member's does, and not her own message.
    let (_, page) = call(&a.router, signed(&a.key, "inboxFetch", ALICE, "{}")).await;
    assert_eq!(bytes(&page["messages"]).len(), 1, "{page}");
    assert!(!bytes(&page["messages"]).contains(&message), "{page}");
}
