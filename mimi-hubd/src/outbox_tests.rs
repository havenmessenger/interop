//! The worker against a local provider: order, what each answer does to the row, the backoff, and a provider the
//! outbound gate refuses.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use super::*;
use crate::outbound::tests::{answer, loopback_allowed, resolver, server_with, Pki, Seen, PEER};
use crate::outbound::AddressPolicy;
use crate::peer_directory::{Directories, PeerBases};

const ROOM: &str = "mimi://hub.example/r/room";

fn hub() -> SharedProvider {
    Arc::new(Mutex::new(
        crate::Provider::in_memory("hub.example").unwrap(),
    ))
}

/// A provider at `PEER` serving a directory whose `notify` is on it, and answering each `notify` with the next of
/// `statuses` (the last one repeating).
async fn peer(
    pki: &Pki,
    statuses: Vec<(&'static str, &'static str)>,
) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let port = Arc::new(Mutex::new(0u16));
    let count = Arc::new(Mutex::new(0usize));
    let port_for_server = port.clone();
    let (addr, seen) = server_with(pki, PEER, move |seen| {
        if seen
            .head
            .starts_with("GET /.well-known/mimi-protocol-directory ")
        {
            let port = *port_for_server.lock().unwrap();
            let body = format!(r#"{{"notify": "https://{PEER}:{port}/v1/notify/{{roomId}}"}}"#);
            return answer(
                "200 OK",
                "content-type: application/json\r\n",
                body.as_bytes(),
            );
        }
        let mut count = count.lock().unwrap();
        let (status, headers) = statuses[(*count).min(statuses.len() - 1)];
        *count += 1;
        answer(status, headers, b"")
    })
    .await;
    *port.lock().unwrap() = addr.port();
    (addr, seen)
}

fn worker(
    provider: SharedProvider,
    pki: &Pki,
    addr: SocketAddr,
    addresses: AddressPolicy,
) -> Arc<OutboxWorker> {
    let bases =
        PeerBases::parse(&format!(r#""{PEER}" = "https://{PEER}:{}""#, addr.port())).unwrap();
    OutboxWorker::new(
        provider,
        Arc::new(pki.client(addresses, None, resolver(PEER, &[addr]))),
        Arc::new(Directories::new(bases)),
        Arc::new(tokio::sync::Notify::new()),
    )
}

fn notified_bodies(seen: &Mutex<Vec<Seen>>) -> Vec<Vec<u8>> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|seen| seen.head.starts_with("POST "))
        .map(|seen| seen.body.clone())
        .collect()
}

fn head(provider: &SharedProvider) -> Option<OutboxRow> {
    provider
        .lock()
        .unwrap()
        .store
        .due_outbox_heads(u64::MAX, &[])
        .unwrap()
        .into_iter()
        .next()
}

/// The running worker delivers a room's queue in order, to the directory's `notify` with the room in the path, and a
/// delivered row leaves the outbox.
#[tokio::test]
async fn a_queue_is_delivered_in_order() {
    let pki = Pki::new();
    let (addr, seen) = peer(&pki, vec![("201 Created", "")]).await;
    let provider = hub();
    for body in [b"one", b"two"] {
        provider
            .lock()
            .unwrap()
            .store
            .enqueue_fanout(ROOM, PEER, body, 0)
            .unwrap();
    }
    let worker = worker(provider.clone(), &pki, addr, loopback_allowed());
    let task = worker.spawn();
    for _ in 0..100 {
        if head(&provider).is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    task.abort();
    assert!(head(&provider).is_none(), "the queue was not delivered");
    assert_eq!(notified_bodies(&seen), [b"one".to_vec(), b"two".to_vec()]);
    let first = seen
        .lock()
        .unwrap()
        .iter()
        .find(|s| s.head.starts_with("POST "))
        .unwrap()
        .head
        .clone();
    assert!(
        first.starts_with("POST /v1/notify/mimi%3A%2F%2Fhub.example%2Fr%2Froom HTTP/1.1\r\n"),
        "{first}"
    );
}

/// A `503` keeps the head, counts the attempt and waits out `Retry-After`; the next attempt sends the same bytes and
/// is delivered, and only then is the row behind it due. Revert check: remove the row on any answer, and the `503`
/// loses it.
#[tokio::test]
async fn a_5xx_keeps_the_head_and_the_retry_sends_the_same_bytes() {
    let pki = Pki::new();
    let (addr, seen) = peer(
        &pki,
        vec![
            ("503 Service Unavailable", "retry-after: 120\r\n"),
            ("201 Created", ""),
        ],
    )
    .await;
    let provider = hub();
    provider
        .lock()
        .unwrap()
        .store
        .enqueue_fanout(ROOM, PEER, b"one", 0)
        .unwrap();
    provider
        .lock()
        .unwrap()
        .store
        .enqueue_fanout(ROOM, PEER, b"two", 0)
        .unwrap();
    let worker = worker(provider.clone(), &pki, addr, loopback_allowed());

    let row = head(&provider).unwrap();
    let attempt = worker.attempt(&row).await;
    assert_eq!(
        attempt,
        Attempt::Failed {
            why: "answered 503".into(),
            retry_after_ms: Some(120_000)
        }
    );
    worker.settle(&row, &attempt, 1_000);
    {
        let store = &provider.lock().unwrap().store;
        let waiting = store.due_outbox_heads(u64::MAX, &[]).unwrap();
        assert_eq!(
            waiting[0].id, row.id,
            "PLANT-OUTBOX-RETRY: the failed head left the queue"
        );
        assert_eq!(
            (waiting[0].attempts, waiting[0].next_attempt_ms),
            (1, 121_000)
        );
        assert!(
            store.due_outbox_heads(120_999, &[]).unwrap().is_empty(),
            "the row behind the head became due"
        );
    }

    let row = head(&provider).unwrap();
    assert_eq!(worker.attempt_and_settle(&row).await, Attempt::Delivered);
    assert_eq!(notified_bodies(&seen), [b"one".to_vec(), b"one".to_vec()]);
    assert_eq!(head(&provider).unwrap().body, b"two");
}

/// A `4xx` other than `408` and `429` drops the row, and the next is the head. Revert check: retry it, and the room's
/// queue is stuck on it.
#[tokio::test]
async fn a_4xx_drops_the_row() {
    let pki = Pki::new();
    let (addr, _) = peer(&pki, vec![("422 Unprocessable Content", "")]).await;
    let provider = hub();
    provider
        .lock()
        .unwrap()
        .store
        .enqueue_fanout(ROOM, PEER, b"one", 0)
        .unwrap();
    provider
        .lock()
        .unwrap()
        .store
        .enqueue_fanout(ROOM, PEER, b"two", 0)
        .unwrap();
    let worker = worker(provider.clone(), &pki, addr, loopback_allowed());
    let row = head(&provider).unwrap();
    assert_eq!(worker.attempt_and_settle(&row).await, Attempt::Refused(422));
    assert_eq!(
        head(&provider).unwrap().body,
        b"two",
        "PLANT-OUTBOX-DROP: a refused row stayed at the head"
    );
}

/// A provider the outbound gate refuses (here: on loopback, with no allowlist) is a failed attempt, kept and counted,
/// and nothing connects.
#[tokio::test]
async fn a_refused_destination_is_kept_and_retried() {
    let pki = Pki::new();
    let (addr, seen) = peer(&pki, vec![("201 Created", "")]).await;
    let provider = hub();
    provider
        .lock()
        .unwrap()
        .store
        .enqueue_fanout(ROOM, PEER, b"one", 0)
        .unwrap();
    let worker = worker(provider.clone(), &pki, addr, AddressPolicy::default());
    let row = head(&provider).unwrap();
    let attempt = worker.attempt_and_settle(&row).await;
    assert!(
        matches!(&attempt, Attempt::Failed { why, .. } if why.contains("loopback")),
        "{attempt:?}"
    );
    let row = head(&provider).unwrap();
    assert_eq!(row.attempts, 1);
    assert!(seen.lock().unwrap().is_empty());
    let queues = provider.lock().unwrap().store.outbox_queues().unwrap();
    assert!(queues[0]
        .head_last_outcome
        .as_deref()
        .unwrap()
        .contains("loopback"));
}

#[test]
fn the_backoff_doubles_to_five_minutes_and_retry_after_only_lengthens_it() {
    assert_eq!(retry_delay_ms(0, None), 1_000);
    assert_eq!(retry_delay_ms(1, None), 2_000);
    assert_eq!(retry_delay_ms(8, None), 256_000);
    assert_eq!(retry_delay_ms(9, None), MAX_BACKOFF_MS);
    assert_eq!(retry_delay_ms(60, None), MAX_BACKOFF_MS);
    assert_eq!(retry_delay_ms(3, Some(10)), 8_000);
    assert_eq!(retry_delay_ms(0, Some(120_000)), 120_000);
    assert_eq!(retry_delay_ms(0, Some(u64::MAX)), MAX_RETRY_AFTER_MS);
}

#[test]
fn retry_after_is_seconds_or_a_date() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    assert_eq!(retry_after_ms("120", now), Some(120_000));
    let later = httpdate::fmt_http_date(now + Duration::from_secs(90));
    assert_eq!(retry_after_ms(&later, now), Some(90_000));
    let earlier = httpdate::fmt_http_date(now - Duration::from_secs(90));
    assert_eq!(retry_after_ms(&earlier, now), Some(0));
    assert_eq!(retry_after_ms("soon", now), None);
    assert!(refused_for_good(400) && refused_for_good(404) && refused_for_good(422));
    assert!(
        !refused_for_good(408)
            && !refused_for_good(429)
            && !refused_for_good(503)
            && !refused_for_good(302)
    );
}
