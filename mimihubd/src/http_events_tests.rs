//! The provider event stream's lane routes: the version and mode `info` states, which calls each mode takes, the
//! provider-level signature kept apart from a user's, the acknowledgement bound, and switching transport mid-stream.

use std::sync::Arc;
use std::time::SystemTime;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ring::signature::Ed25519KeyPair;

use super::client_lane_tests::{call, lane, lane_over, signed, Lane};
use crate::client_lane_events::EventBatch;
use crate::client_lane_rooms::LaneRoomProfile;
use crate::event_push::{EventPusher, PushAttempt};
use crate::outbound::tests::{answer, server_with, Pki};
use crate::Provider;

const DOMAIN: &str = "havenmessenger.com";
const HOST: &str = "hub.example:8450";
const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const ROOM: &str = "mimi://havenmessenger.com/r/room";

/// A lane request to `route` signed by `mimihubd_api` (the library a provider's server links), acting as `acting`, with
/// the lane fixture's key: the hub's own verifier checks the library's signature.
pub(super) fn api_signed(
    lane_key: &Ed25519KeyPair,
    route: &str,
    acting: &mimihubd_api::sign::Acting,
    body: &str,
) -> Request<Body> {
    let key = mimihubd_api::sign::SigningKey::from_seed(&[7u8; 32], "lane1").unwrap();
    assert_eq!(
        key.public_key().as_slice(),
        ring::signature::KeyPair::public_key(lane_key).as_ref(),
        "the lane fixture's key"
    );
    let path = format!("{}{route}", mimihubd_api::LANE_PATH_PREFIX);
    let created = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let headers = key.sign_lane(
        &format!("https://{HOST}{path}"),
        body.as_bytes(),
        acting,
        created,
        &mimihubd_api::sign::fresh_nonce().unwrap(),
    );
    let mut request = Request::builder()
        .method("POST")
        .uri(&path)
        .header("host", HOST);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request.body(Body::from(body.to_string())).expect("request")
}

/// A provider-level request to `route`, as the provider's server signs one for itself.
pub(super) fn provider_signed(lane_key: &Ed25519KeyPair, route: &str, body: &str) -> Request<Body> {
    api_signed(lane_key, route, &mimihubd_api::sign::Acting::Provider, body)
}

fn events_lane(test: &str) -> Lane {
    lane_over(
        test,
        Provider::in_memory(DOMAIN).unwrap().with_event_delivery(),
        LaneRoomProfile::neutral(),
    )
}

fn write(l: &Lane, items: &[&[u8]]) {
    l.provider
        .lock()
        .unwrap()
        .store
        .enqueue_messages(ALICE, Some(ROOM), items, 0)
        .unwrap();
}

async fn fetch(l: &Lane, after: i64) -> EventBatch {
    let (status, body) = call(
        &l.router,
        provider_signed(
            &l.key,
            "events/fetch",
            &format!(r#"{{"after_seq":{after}}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body).unwrap()
}

async fn ack(l: &Lane, up_to: i64) -> (StatusCode, serde_json::Value) {
    call(
        &l.router,
        provider_signed(&l.key, "events/ack", &format!(r#"{{"up_to_seq":{up_to}}}"#)),
    )
    .await
}

/// `info` states the lane's version and how the hub delivers.
#[tokio::test]
async fn info_states_the_version_and_the_delivery_mode() {
    let inbox = lane("events-info-inbox");
    let (status, body) = call(&inbox.router, provider_signed(&inbox.key, "info", "{}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        serde_json::json!({"lane_version": 1, "delivery": "inbox", "push": false})
    );
    let events = events_lane("events-info-events");
    write(&events, &[b"1", b"2"]);
    let (_, body) = call(&events.router, provider_signed(&events.key, "info", "{}")).await;
    assert_eq!(
        body,
        serde_json::json!({
            "lane_version": 1,
            "delivery": "events",
            "push": false,
            "stream": {"last_seq": 2, "acked_through": 0}
        })
    );
    // A hub that pushes says how the push stands; one that has not tried yet has failed nothing.
    events
        .provider
        .lock()
        .unwrap()
        .store
        .set_event_push()
        .unwrap();
    let (_, body) = call(&events.router, provider_signed(&events.key, "info", "{}")).await;
    assert_eq!(body["push"], true);
    assert_eq!(
        body["push_status"],
        serde_json::json!({"acked_through": 0, "failures": 0})
    );
}

/// Each mode answers the other mode's calls with the delivery-mode problem, and a hub that delivers per user writes no
/// events.
#[tokio::test]
async fn each_mode_refuses_the_other_modes_calls() {
    let events = events_lane("events-mode-events");
    for route in ["inboxFetch", "inboxAck"] {
        let (status, body) = call(&events.router, signed(&events.key, route, ALICE, "{}")).await;
        assert_eq!(status, StatusCode::CONFLICT, "{route}: {body}");
        assert!(body["type"].as_str().unwrap().ends_with("#delivery-mode"));
    }
    let inbox = lane("events-mode-inbox");
    for (route, body) in [
        ("events/fetch", "{}"),
        ("events/ack", r#"{"up_to_seq":0}"#),
        ("events/wait", r#"{"timeout_ms":0}"#),
    ] {
        let (status, answer) = call(&inbox.router, provider_signed(&inbox.key, route, body)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{route}: {answer}");
    }
    write(&inbox, &[b"m"]);
    let p = inbox.provider.lock().unwrap();
    assert_eq!(p.events_cursor().unwrap().last_seq, 0);
    assert_eq!(p.lane_inbox(ALICE, 0, 0, 10).unwrap().messages.len(), 1);
}

/// A request signed for a user is not one signed for the provider, and the other way round.
#[tokio::test]
async fn a_users_signature_and_the_providers_are_not_interchangeable() {
    let l = events_lane("events-signatures");
    let (status, _) = call(&l.router, signed(&l.key, "events/fetch", ALICE, "{}")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&l.router, provider_signed(&l.key, "keyPackageCount", "{}")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let mut unsigned = provider_signed(&l.key, "events/fetch", "{}");
    unsigned.headers_mut().remove("signature");
    let (status, _) = call(&l.router, unsigned).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// An acknowledgement past the last event is refused and changes nothing; fetch answers after the cursor in order.
#[tokio::test]
async fn ack_past_the_end_is_refused() {
    let l = events_lane("events-ack");
    write(&l, &[b"1", b"2"]);
    let (status, body) = ack(&l, 3).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["type"].as_str().unwrap().ends_with("#ack-past-end"));
    assert_eq!(fetch(&l, 0).await.events.len(), 2);
    let (status, body) = ack(&l, 1).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({"acked_through": 1}));
    let batch = fetch(&l, 0).await;
    assert_eq!(
        batch.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![2]
    );
    assert_eq!(
        batch.events[0].bytes.as_deref(),
        Some(STANDARD.encode(b"2").as_str())
    );
}

/// Pull, then push, then pull again over one stream: every event is delivered once, nothing past an acknowledgement is
/// lost or repeated.
#[tokio::test]
async fn switching_transport_mid_stream_loses_and_repeats_nothing() {
    let l = events_lane("events-switch");
    write(&l, &[b"1", b"2", b"3"]);
    let mut delivered = Vec::new();
    // Pull takes 1 and 2.
    let batch = fetch(&l, 0).await;
    delivered.extend(batch.events.iter().take(2).map(|e| e.seq));
    assert_eq!(ack(&l, 2).await.0, StatusCode::OK);
    // The operator turns push on: it starts after the acknowledged cursor.
    let pki = Pki::new();
    let (addr, seen) = server_with(&pki, "app.havenmessenger.com", |_| {
        answer("200 OK", "", b"")
    })
    .await;
    l.provider.lock().unwrap().store.set_event_push().unwrap();
    let pusher = EventPusher::new(
        l.provider.clone(),
        Arc::new(crate::event_push::tests::push_client(
            &pki,
            "app.havenmessenger.com",
            addr,
            None,
        )),
        &format!("https://app.havenmessenger.com:{}/events", addr.port()),
    )
    .unwrap();
    write(&l, &[b"4"]);
    assert_eq!(
        pusher.push_once().await,
        PushAttempt::Delivered {
            through: 4,
            more: false
        }
    );
    for body in seen
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.head.starts_with("POST "))
    {
        let batch: EventBatch = serde_json::from_slice(&body.body).unwrap();
        delivered.extend(batch.events.iter().map(|e| e.seq));
    }
    // And back to pull: the reader starts from the hub's cursor.
    write(&l, &[b"5"]);
    let cursor = l
        .provider
        .lock()
        .unwrap()
        .events_cursor()
        .unwrap()
        .acked_through;
    let batch = fetch(&l, cursor).await;
    delivered.extend(batch.events.iter().map(|e| e.seq));
    assert_eq!(delivered, vec![1, 2, 3, 4, 5]);
}

/// The inbox lane still behaves as before for a hub that delivers per user: its stream stays empty.
#[tokio::test]
async fn an_inbox_hub_is_unchanged() {
    let l = lane("events-inbox-unchanged");
    let (status, body) = call(&l.router, signed(&l.key, "inboxFetch", ALICE, "{}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        serde_json::json!({"welcomes": [], "messages": [], "more": false})
    );
    write(&l, &[b"m"]);
    assert_eq!(
        l.provider.lock().unwrap().events_cursor().unwrap().last_seq,
        0
    );
}

/// A user's request signed by the library is taken on a user route, as the hub's own fixture's is.
#[tokio::test]
async fn the_librarys_user_signature_is_taken_on_a_user_route() {
    let l = lane("events-api-user");
    let acting = mimihubd_api::sign::Acting::User {
        user: ALICE.into(),
        device: "dev-1".into(),
    };
    let (status, body) = call(
        &l.router,
        api_signed(&l.key, "keyPackageCount", &acting, "{}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(&l.router, api_signed(&l.key, "events/fetch", &acting, "{}")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a user's signature on a provider route"
    );
}
