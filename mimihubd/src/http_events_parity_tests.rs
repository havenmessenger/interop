//! Push and pull deliver the same provider event stream.
//!
//! One scenario (two rooms, a Welcome, application messages in both rooms, a Commit, a consent request) is played twice,
//! with identical MLS bytes, against two fresh hubs that deliver through the event stream: one pushes it to a local
//! provider server, the other is drained by `events/wait`, `events/fetch` and `events/ack` on its lane. Both must yield
//! the same events (seq, kind, user, room, payload hash, consent change), in seq order, each once, and leave the cursor
//! at the last event.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openmls::prelude::tls_codec::Serialize as _;
use sha2::{Digest, Sha256};

use super::client_lane_tests::{call, lane_over, signed, Lane};
use super::events_tests::provider_signed;
use super::tests::bundle_of;
use super::update_leave_tests::{by_value_change, commit_of, list_change};
use crate::client_lane_events::{EventBatch, WireEvent};
use crate::client_lane_rooms::{LaneRoomProfile, ROLE_MEMBER};
use crate::event_push::{EventPusher, PushAttempt};
use crate::outbound::tests::{answer, loopback_allowed, resolver, server_with, Pki};
use crate::Provider;

const DOMAIN: &str = "havenmessenger.com";
const SERVER: &str = "app.havenmessenger.com";
const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const DAVE: &str = "mimi://havenmessenger.com/u/dave";

/// The scenario's MLS bytes, made once and played to both hubs.
struct Inputs {
    welcome: Vec<u8>,
    commit: Vec<u8>,
}

fn inputs() -> Inputs {
    let alice = crate::mls_fixtures::Member::new(ALICE);
    let bob = crate::mls_fixtures::Member::new(BOB);
    let mut group = alice.create_group(b"parity-room");
    let (_commit, welcome, _group_info) = group
        .add_members(
            &alice.provider,
            &alice.signer,
            &[bob.key_package_bundle().key_package().clone()],
        )
        .unwrap();
    Inputs {
        welcome: welcome.tls_serialize_detached().unwrap(),
        commit: bundle_of(commit_of(0, &[by_value_change(&list_change(&[DAVE], &[]))])),
    }
}

/// A hub delivering through the event stream, pushing it when `push`.
fn events_hub(test: &str, push: bool) -> Lane {
    let mut hub = Provider::in_memory(DOMAIN).unwrap().with_event_delivery();
    if push {
        hub = hub.with_event_push().unwrap();
    }
    // The scenario's Commit is hand-built: no tree could take it.
    hub.policy.untracked_rooms = crate::policy::UntrackedRooms::Accept;
    lane_over(test, hub, LaneRoomProfile::neutral())
}

/// Play the scenario on `l`. Returns the rooms it made, in order, so their URIs (fresh on each hub) compare by position.
async fn scenario(l: &Lane, inputs: &Inputs) -> Vec<String> {
    let mut rooms = Vec::new();
    for _ in 0..2 {
        let (status, body) = call(&l.router, signed(&l.key, "createRoom", ALICE, "{}")).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        rooms.push(body["room"].as_str().unwrap().to_string());
    }
    {
        let p = l.provider.lock().unwrap();
        for room in &rooms {
            p.add_participant(room, BOB, 1).unwrap();
            p.set_member_role(room, BOB, ROLE_MEMBER).unwrap();
        }
        p.relay_welcome(BOB, Some(&rooms[0]), &inputs.welcome, 0)
            .unwrap();
    }
    let send = |user: &str, room: &str, message: &[u8]| {
        signed(
            &l.key,
            "submitMessage",
            user,
            &format!(
                r#"{{"room":"{room}","message":"{}"}}"#,
                STANDARD.encode(message)
            ),
        )
    };
    for (user, room, message) in [
        (ALICE, &rooms[0], &b"a1"[..]),
        (ALICE, &rooms[1], b"b1"),
        (ALICE, &rooms[0], b"a2"),
    ] {
        let (status, body) = call(&l.router, send(user, room, message)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let update = format!(
        r#"{{"room":"{}","update":"{}"}}"#,
        rooms[0],
        STANDARD.encode(&inputs.commit)
    );
    let (status, body) = call(&l.router, signed(&l.key, "update", ALICE, &update)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["answer"], "success", "{body}");
    let ask = format!(r#"{{"target":"{ALICE}"}}"#);
    let (status, body) = call(&l.router, signed(&l.key, "requestConsent", BOB, &ask)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = call(&l.router, send(BOB, &rooms[1], b"b2")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    rooms
}

/// An event as the comparison sees it: the room by its position in the scenario, the payload by its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    seq: i64,
    kind: String,
    user: String,
    room: Option<String>,
    payload: Option<String>,
    consent: Option<(String, String, Option<String>, String)>,
}

fn normalized(events: &[WireEvent], rooms: &[String]) -> Vec<Seen> {
    let label: HashMap<&str, String> = rooms
        .iter()
        .enumerate()
        .map(|(at, room)| (room.as_str(), format!("room{at}")))
        .collect();
    let room = |uri: &Option<String>| {
        uri.as_deref()
            .map(|uri| label.get(uri).cloned().unwrap_or_else(|| uri.to_string()))
    };
    events
        .iter()
        .map(|event| Seen {
            seq: event.seq,
            kind: serde_json::to_value(event.kind)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string(),
            user: event.user.clone(),
            room: room(&event.room),
            payload: event
                .bytes
                .as_ref()
                .map(|bytes| STANDARD.encode(Sha256::digest(STANDARD.decode(bytes).unwrap()))),
            consent: event.consent.as_ref().map(|change| {
                (
                    change.requester.clone(),
                    change.target.clone(),
                    room(&change.room),
                    change.state.clone(),
                )
            }),
        })
        .collect()
}

/// Drain `l`'s stream by pull: wait, fetch a small page, acknowledge it, until a wait times out with nothing new.
async fn pull(l: &Lane) -> Vec<WireEvent> {
    let mut got = Vec::new();
    let mut cursor = 0i64;
    loop {
        let (status, waited) = call(
            &l.router,
            provider_signed(
                &l.key,
                "events/wait",
                &format!(r#"{{"after_seq":{cursor},"timeout_ms":200}}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{waited}");
        if waited["latest_seq"].as_i64().unwrap() <= cursor {
            return got;
        }
        let (status, page) = call(
            &l.router,
            provider_signed(
                &l.key,
                "events/fetch",
                &format!(r#"{{"after_seq":{cursor},"limit":3}}"#),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let page: EventBatch = serde_json::from_value(page).unwrap();
        let Some(last) = page.events.last().map(|event| event.seq) else {
            return got;
        };
        got.extend(page.events);
        let (status, acked) = call(
            &l.router,
            provider_signed(&l.key, "events/ack", &format!(r#"{{"up_to_seq":{last}}}"#)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{acked}");
        cursor = last;
    }
}

/// A provider server that takes every push with `200`, recording each batch's events.
async fn receiver(pki: &Pki) -> (SocketAddr, Arc<Mutex<Vec<crate::outbound::tests::Seen>>>) {
    server_with(pki, SERVER, |_| answer("200 OK", "", b"")).await
}

/// Push `l`'s stream to a receiver until the cursor reaches the last event; every event the receiver was sent.
async fn push(l: &Lane) -> Vec<WireEvent> {
    let pki = Pki::new();
    let (addr, seen) = receiver(&pki).await;
    let signer =
        Arc::new(crate::request_signing::RequestSigner::from_seed(&[9u8; 32], "hub1").unwrap());
    let client = pki.client_with(
        loopback_allowed(),
        None,
        resolver(SERVER, &[addr]),
        true,
        Some(signer),
    );
    let pusher = EventPusher::new(
        l.provider.clone(),
        Arc::new(client),
        &format!("https://{SERVER}:{}/events", addr.port()),
    )
    .unwrap();
    let last = l.provider.lock().unwrap().events_cursor().unwrap().last_seq;
    let task = pusher.spawn();
    for _ in 0..200 {
        if l.provider
            .lock()
            .unwrap()
            .events_cursor()
            .unwrap()
            .acked_through
            >= last
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    task.abort();
    assert_eq!(
        pusher.push_once().await,
        PushAttempt::Idle,
        "PLANT-EVENTS-ORDER/PLANT-EVENTS-ACK: push left events past the cursor"
    );
    let bodies: Vec<Vec<u8>> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|seen| seen.head.starts_with("POST "))
        .map(|seen| seen.body.clone())
        .collect();
    bodies
        .iter()
        .flat_map(|body| serde_json::from_slice::<EventBatch>(body).unwrap().events)
        .collect()
}

/// Each seq once, in order, from 1 with no gap.
fn assert_in_order_once(what: &str, events: &[Seen]) {
    let seqs: Vec<i64> = events.iter().map(|event| event.seq).collect();
    let expected: Vec<i64> = (1..=i64::try_from(seqs.len()).unwrap()).collect();
    assert_eq!(
        seqs, expected,
        "PLANT-EVENTS-ORDER/PLANT-EVENTS-ACK: {what} did not deliver each seq once, in order"
    );
}

/// The stream's cursor is at its last event and nothing is left in it.
fn assert_drained(what: &str, l: &Lane) {
    let p = l.provider.lock().unwrap();
    let cursor = p.events_cursor().unwrap();
    assert_eq!(
        cursor.acked_through, cursor.last_seq,
        "PLANT-EVENTS-ACK: {what} left the cursor behind"
    );
    assert!(
        p.events_page(0, 10).unwrap().unwrap().events.is_empty(),
        "PLANT-EVENTS-ACK: {what} left acknowledged events in the stream"
    );
}

#[tokio::test]
async fn push_and_pull_deliver_the_same_events() {
    let inputs = inputs();

    let pulled_hub = events_hub("parity-pull", false);
    let pulled_rooms = scenario(&pulled_hub, &inputs).await;
    let pulled = normalized(&pull(&pulled_hub).await, &pulled_rooms);

    let pushed_hub = events_hub("parity-push", true);
    let pushed_rooms = scenario(&pushed_hub, &inputs).await;
    let pushed = normalized(&push(&pushed_hub).await, &pushed_rooms);

    assert!(
        !pushed.is_empty(),
        "PLANT-EVENTS-PUSH-OFF: push delivered nothing"
    );
    assert_eq!(
        pulled, pushed,
        "PLANT-EVENTS-PULL-DIFFERS: pull and push delivered different events"
    );
    assert_in_order_once("pull", &pulled);
    assert_in_order_once("push", &pushed);
    assert_drained("pull", &pulled_hub);
    assert_drained("push", &pushed_hub);
    // The scenario's every kind came through: the Welcome, the messages in both rooms, the Commit, the consent request.
    let kinds: Vec<(&str, &str, Option<&str>)> = pulled
        .iter()
        .map(|event| {
            (
                event.kind.as_str(),
                event.user.as_str(),
                event.room.as_deref(),
            )
        })
        .collect();
    assert!(
        kinds.contains(&("welcome", BOB, Some("room0"))),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&("message", BOB, Some("room1"))),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&("message", ALICE, Some("room1"))),
        "{kinds:?}"
    );
    assert!(kinds.contains(&("consent", ALICE, None)), "{kinds:?}");
    assert!(
        pulled
            .iter()
            .filter(|event| event.kind == "message"
                && event.user == BOB
                && event.room.as_deref() == Some("room0"))
            .count()
            >= 3,
        "two messages and the Commit in room0 reach Bob: {kinds:?}"
    );
}
