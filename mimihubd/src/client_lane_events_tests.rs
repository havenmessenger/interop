//! Waiting on the provider event stream: an event wakes a held wait at once, a quiet stream times out empty, and a hub
//! that delivers per user refuses.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;

const ALICE: &str = "mimi://hub.example/u/alice";
const ROOM: &str = "mimi://hub.example/r/room";

fn hub(events: bool) -> SharedProvider {
    let provider = Provider::in_memory("hub.example").unwrap();
    let provider = if events {
        provider.with_event_delivery()
    } else {
        provider
    };
    Arc::new(Mutex::new(provider))
}

fn write_message(provider: &SharedProvider) {
    crate::http::lock(provider)
        .store
        .enqueue_messages(ALICE, Some(ROOM), &[b"m"], 0)
        .unwrap();
}

/// A wait held on a quiet stream answers within a second of an event being written, naming its user.
#[tokio::test]
async fn an_event_wakes_a_held_wait_at_once() {
    let provider = hub(true);
    let writer = provider.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        write_message(&writer);
    });
    let started = Instant::now();
    let answer = wait_for_events(&provider, 0, Duration::from_secs(20))
        .await
        .unwrap()
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(1300),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(
        answer,
        WaitAnswer {
            latest_seq: 1,
            users: vec![ALICE.to_string()]
        }
    );
}

/// An event already past the cursor answers without waiting.
#[tokio::test]
async fn a_waiting_event_answers_at_once() {
    let provider = hub(true);
    write_message(&provider);
    let started = Instant::now();
    let answer = wait_for_events(&provider, 0, Duration::from_secs(20))
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(answer.latest_seq, 1);
}

/// A quiet stream answers at the timeout with no users and the cursor where it was.
#[tokio::test]
async fn a_quiet_stream_times_out_empty() {
    let provider = hub(true);
    write_message(&provider);
    let started = Instant::now();
    let answer = wait_for_events(&provider, 1, Duration::from_millis(400))
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(400));
    assert_eq!(
        answer,
        WaitAnswer {
            latest_seq: 1,
            users: Vec::new()
        }
    );
}

/// A hub that delivers per user refuses every events call.
#[tokio::test]
async fn an_inbox_hub_refuses_the_stream() {
    let provider = hub(false);
    assert_eq!(
        wait_for_events(&provider, 0, Duration::from_millis(10))
            .await
            .unwrap(),
        Err(EventsRefusal::NotEventDelivery)
    );
    let locked = crate::http::lock(&provider);
    assert_eq!(
        locked.events_page(0, 10).unwrap(),
        Err(EventsRefusal::NotEventDelivery)
    );
    assert_eq!(
        locked.events_ack(0).unwrap(),
        Err(EventsRefusal::NotEventDelivery)
    );
}
