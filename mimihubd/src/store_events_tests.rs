//! The provider event stream in the store: numbering, bounds, acknowledgement, and what writes reach it.

use std::sync::Arc;

use super::*;
use crate::store::{QueueKind, QueueRefused, SqliteStore, MAX_QUEUE_MESSAGES};

const DOMAIN: &str = "hub.example";
const ALICE: &str = "mimi://hub.example/u/alice";
const BOB: &str = "mimi://hub.example/u/bob";
const ROOM: &str = "mimi://hub.example/r/room";

fn stream() -> SqliteStore {
    let mut store = SqliteStore::in_memory().unwrap();
    store.deliver_as_events(DOMAIN, Arc::new(tokio::sync::Notify::new()));
    store
}

fn seqs(store: &SqliteStore, after: i64) -> Vec<(i64, EventKind, String)> {
    store
        .fetch_events(after, 1000, usize::MAX)
        .unwrap()
        .0
        .into_iter()
        .map(|e| (e.seq, e.kind, e.user))
        .collect()
}

/// Welcomes, messages and consent for several users take one gap-free sequence, in the order they were written, and the
/// per-user queues stay empty.
#[test]
fn every_kind_and_user_shares_one_gap_free_sequence() {
    let store = stream();
    store
        .enqueue_room_welcome(ALICE, Some(ROOM), b"w1", 1)
        .unwrap();
    store
        .enqueue_messages(BOB, Some(ROOM), &[b"m1", b"m2"], 2)
        .unwrap();
    store.set_consent(BOB, ALICE, "", "requested", 3).unwrap();
    // A Welcome found by KeyPackageRef is queued under the stored name; the stream names the user's URI.
    store
        .enqueue_room_welcome("bob", Some(ROOM), b"w2", 4)
        .unwrap();
    assert_eq!(
        seqs(&store, 0),
        vec![
            (1, EventKind::Welcome, ALICE.to_string()),
            (2, EventKind::Message, BOB.to_string()),
            (3, EventKind::Message, BOB.to_string()),
            (4, EventKind::Consent, ALICE.to_string()),
            (5, EventKind::Welcome, BOB.to_string()),
        ]
    );
    let events = store.fetch_events(0, 10, usize::MAX).unwrap().0;
    assert_eq!(events[1].room.as_deref(), Some(ROOM));
    assert_eq!(events[1].bytes.as_deref(), Some(&b"m1"[..]));
    assert_eq!(
        events[3].consent,
        Some(ConsentChange {
            requester: BOB.into(),
            target: ALICE.into(),
            room: None,
            state: "requested".into(),
        })
    );
    assert!(store
        .peek_queue(QueueKind::Welcomes, &[ALICE, "alice"], 0, 10)
        .unwrap()
        .is_empty());
    assert!(store
        .peek_queue(QueueKind::Messages, &[BOB, "bob"], 0, 10)
        .unwrap()
        .is_empty());
    assert_eq!(store.event_cursor().unwrap().last_seq, 5);
}

/// A decision reaches the requester; a request reaches the target; a withdrawn request tells the target. Only local
/// users get events.
#[test]
fn consent_events_reach_the_local_party_the_change_concerns() {
    let store = stream();
    let remote = "mimi://other.example/u/carol";
    store
        .set_consent(remote, ALICE, ROOM, "requested", 1)
        .unwrap();
    store.set_consent(ALICE, remote, "", "granted", 2).unwrap();
    store.set_consent(BOB, remote, "", "requested", 3).unwrap();
    assert!(store.withdraw_consent_request(remote, ALICE, ROOM).unwrap());
    let events = store.fetch_events(0, 10, usize::MAX).unwrap().0;
    let got: Vec<(String, String)> = events
        .iter()
        .map(|e| (e.user.clone(), e.consent.as_ref().unwrap().state.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            (ALICE.to_string(), "requested".to_string()),
            (ALICE.to_string(), "granted".to_string()),
            (ALICE.to_string(), "withdrawn".to_string()),
        ]
    );
    assert_eq!(events[0].room.as_deref(), Some(ROOM));
}

/// An acknowledgement removes what it covers and only moves forward; one past the last seq changes nothing.
#[test]
fn ack_moves_forward_only_and_never_past_the_end() {
    let store = stream();
    store
        .enqueue_messages(ALICE, Some(ROOM), &[b"1", b"2", b"3"], 0)
        .unwrap();
    assert_eq!(
        store.ack_events(4).unwrap(),
        EventAck::PastEnd { last_seq: 3 }
    );
    assert_eq!(seqs(&store, 0).len(), 3);
    assert_eq!(store.ack_events(2).unwrap(), EventAck::AckedThrough(2));
    assert_eq!(store.ack_events(1).unwrap(), EventAck::AckedThrough(2));
    assert_eq!(
        seqs(&store, 0)
            .into_iter()
            .map(|(seq, ..)| seq)
            .collect::<Vec<_>>(),
        vec![3]
    );
    // A seq is never reused after its event is acknowledged.
    store
        .enqueue_messages(ALICE, Some(ROOM), &[b"4"], 0)
        .unwrap();
    assert_eq!(seqs(&store, 2)[1].0, 4);
}

/// The per-user bound refuses at enqueue, all or none, and a refused item takes no seq.
#[test]
fn a_full_backlog_refuses_without_taking_a_seq() {
    let store = stream();
    let items: Vec<Vec<u8>> = (0..MAX_QUEUE_MESSAGES)
        .map(|i| i.to_be_bytes().to_vec())
        .collect();
    let refs: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
    store.enqueue_messages(ALICE, Some(ROOM), &refs, 0).unwrap();
    let error = store
        .enqueue_messages(ALICE, Some(ROOM), &[b"over"], 0)
        .unwrap_err();
    assert!(error.downcast_ref::<QueueRefused>().is_some());
    store
        .enqueue_messages(BOB, Some(ROOM), &[b"bob"], 0)
        .unwrap();
    assert_eq!(
        store.event_cursor().unwrap().last_seq,
        MAX_QUEUE_MESSAGES + 1
    );
}

/// A page stops at its byte bound (one event always fits) and says more are waiting.
#[test]
fn a_page_keeps_to_its_bounds() {
    let store = stream();
    store
        .enqueue_messages(
            ALICE,
            Some(ROOM),
            &[&[1u8; 100], &[2u8; 100], &[3u8; 100]],
            0,
        )
        .unwrap();
    let (page, more) = store.fetch_events(0, 10, 150).unwrap();
    assert_eq!(page.len(), 1);
    assert!(more);
    let (page, more) = store.fetch_events(0, 2, usize::MAX).unwrap();
    assert_eq!(page.len(), 2);
    assert!(more);
    let (page, more) = store.fetch_events(0, 3, usize::MAX).unwrap();
    assert_eq!(page.len(), 3);
    assert!(!more);
}

/// With the stream off, nothing is written to it: per-user queues work as they did.
#[test]
fn inbox_delivery_writes_no_events() {
    let store = SqliteStore::in_memory().unwrap();
    store
        .enqueue_room_welcome(ALICE, Some(ROOM), b"w", 0)
        .unwrap();
    store
        .enqueue_messages(ALICE, Some(ROOM), &[b"m"], 0)
        .unwrap();
    store.set_consent(BOB, ALICE, "", "requested", 0).unwrap();
    assert_eq!(store.event_cursor().unwrap().last_seq, 0);
    assert!(seqs(&store, 0).is_empty());
    assert_eq!(
        store
            .peek_queue(QueueKind::Messages, &[ALICE, "alice"], 0, 10)
            .unwrap()
            .len(),
        1
    );
}

/// A recipient that is not a user of this provider is refused, not written under a name no reader expects.
#[test]
fn a_foreign_recipient_is_refused() {
    let store = stream();
    let error = store
        .enqueue_messages("mimi://other.example/u/x", Some(ROOM), &[b"m"], 0)
        .unwrap_err();
    assert!(error.downcast_ref::<QueueRefused>().is_some());
    assert_eq!(store.event_cursor().unwrap().last_seq, 0);
}

/// The cursor survives reopening the store file.
#[test]
fn the_cursor_survives_a_reopen() {
    let dir = std::env::temp_dir().join(format!("mimihubd-events-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.db");
    let path = path.to_str().unwrap();
    {
        let mut store = SqliteStore::open(path).unwrap();
        store.deliver_as_events(DOMAIN, Arc::new(tokio::sync::Notify::new()));
        store
            .enqueue_messages(ALICE, Some(ROOM), &[b"1", b"2"], 0)
            .unwrap();
        store.ack_events(1).unwrap();
    }
    let store = SqliteStore::open(path).unwrap();
    assert_eq!(
        store.event_cursor().unwrap(),
        EventCursor {
            last_seq: 2,
            acked_through: 1
        }
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
