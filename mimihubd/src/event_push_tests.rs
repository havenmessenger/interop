//! Pushing the event stream to a local provider server: order, signing, retry without loss, and resuming after a
//! restart from the acknowledged cursor.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::*;
use crate::client_lane_events::EventBatch;
use crate::outbound::tests::{answer, resolver, server_with, Pki, Seen};
use crate::outbound::{AddressPolicy, PeerClient, PeerUrl};

const DOMAIN: &str = "hub.example";
/// The provider's own server, on a subdomain of the provider's domain.
const SERVER: &str = "app.hub.example";
const ALICE: &str = "mimi://hub.example/u/alice";
const ROOM: &str = "mimi://hub.example/r/room";

fn hub() -> SharedProvider {
    Arc::new(Mutex::new(
        crate::Provider::in_memory(DOMAIN)
            .unwrap()
            .with_event_delivery()
            .with_event_push()
            .unwrap(),
    ))
}

/// The client a hub pushes with, made as the daemon makes it: from the peers' settings, whose address policy admits no
/// special range, with the push destination's own allowlist (loopback, where the test server is) in its place.
pub(crate) fn push_client(
    pki: &Pki,
    host: &str,
    addr: SocketAddr,
    signer: Option<Arc<crate::request_signing::RequestSigner>>,
) -> PeerClient {
    let mut peers = pki.settings(AddressPolicy::default(), None, true, signer);
    // As the daemon builds it: requests name the provider's own domain (`From: mimi@<domain>`); the server is on a
    // subdomain of it.
    peers.own_domain = host
        .split_once('.')
        .map(|(_, domain)| domain.to_string())
        .unwrap();
    PeerClient::new(
        peers.for_event_push(AddressPolicy::parse_allowlist("127.0.0.0/8").unwrap()),
        resolver(host, &[addr]),
    )
    .unwrap()
}

fn write(provider: &SharedProvider, items: &[&[u8]]) {
    crate::http::lock(provider)
        .store
        .enqueue_messages(ALICE, Some(ROOM), items, 0)
        .unwrap();
}

/// A server answering each push with the next of `statuses` (the last one repeating).
async fn server(pki: &Pki, statuses: Vec<&'static str>) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let count = Arc::new(Mutex::new(0usize));
    server_with(pki, SERVER, move |_| {
        let mut count = count.lock().unwrap();
        let status = statuses[(*count).min(statuses.len() - 1)];
        *count += 1;
        answer(status, "", b"")
    })
    .await
}

fn pusher(provider: SharedProvider, pki: &Pki, addr: SocketAddr) -> Arc<EventPusher> {
    let signer =
        Arc::new(crate::request_signing::RequestSigner::from_seed(&[7u8; 32], "hub1").unwrap());
    let client = push_client(pki, SERVER, addr, Some(signer));
    EventPusher::new(
        provider,
        Arc::new(client),
        &format!("https://{SERVER}:{}/mimi-events", addr.port()),
    )
    .unwrap()
}

fn batches(seen: &Mutex<Vec<Seen>>) -> Vec<EventBatch> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|seen| seen.head.starts_with("POST "))
        .map(|seen| serde_json::from_slice(&seen.body).unwrap())
        .collect()
}

fn seqs(batch: &EventBatch) -> Vec<i64> {
    batch.events.iter().map(|event| event.seq).collect()
}

fn acked(provider: &SharedProvider) -> i64 {
    crate::http::lock(provider)
        .events_cursor()
        .unwrap()
        .acked_through
}

/// The running pusher posts the stream in seq order to the configured URL, signed by the hub, and a 2xx acknowledges
/// it.
#[tokio::test]
async fn the_stream_is_pushed_in_order_signed_and_acknowledged() {
    let pki = Pki::new();
    let (addr, seen) = server(&pki, vec!["204 No Content"]).await;
    let provider = hub();
    write(&provider, &[b"one", b"two", b"three"]);
    let task = pusher(provider.clone(), &pki, addr).spawn();
    for _ in 0..100 {
        if acked(&provider) == 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    task.abort();
    assert_eq!(acked(&provider), 3);
    let batches = batches(&seen);
    assert_eq!(batches.len(), 1);
    assert_eq!(seqs(&batches[0]), vec![1, 2, 3]);
    let head = seen.lock().unwrap()[0].head.to_ascii_lowercase();
    assert!(head.starts_with("post /mimi-events "), "{head}");
    assert!(
        head.contains("\r\nsignature-input: "),
        "the push is not signed: {head}"
    );
    assert!(head.contains("content-type: application/json"), "{head}");
}

/// A failed push keeps the cursor; the same events are posted again and acknowledged once taken. A 4xx is retried like
/// any failure: nothing is dropped.
#[tokio::test]
async fn a_failed_push_is_retried_without_loss() {
    let pki = Pki::new();
    let (addr, seen) = server(
        &pki,
        vec!["500 Internal Server Error", "400 Bad Request", "200 OK"],
    )
    .await;
    let provider = hub();
    write(&provider, &[b"one", b"two"]);
    let pusher = pusher(provider.clone(), &pki, addr);
    assert!(matches!(
        pusher.push_once().await,
        PushAttempt::Failed { .. }
    ));
    assert_eq!(acked(&provider), 0);
    assert!(matches!(
        pusher.push_once().await,
        PushAttempt::Failed { .. }
    ));
    assert_eq!(acked(&provider), 0);
    assert_eq!(
        pusher.push_once().await,
        PushAttempt::Delivered {
            through: 2,
            more: false
        }
    );
    assert_eq!(pusher.push_once().await, PushAttempt::Idle);
    let batches = batches(&seen);
    assert_eq!(batches.len(), 3);
    for batch in &batches {
        assert_eq!(seqs(batch), vec![1, 2]);
    }
    // A receiver that keeps the highest seq it handled takes each event once, in order.
    let mut handled = 0;
    let mut taken = Vec::new();
    for batch in &batches {
        for event in &batch.events {
            if event.seq > handled {
                handled = event.seq;
                taken.push(event.seq);
            }
        }
    }
    assert_eq!(taken, vec![1, 2]);
}

/// After a restart, pushing resumes from the acknowledged cursor: what was acknowledged is not posted again.
#[tokio::test]
async fn a_restarted_hub_resumes_from_the_acknowledged_cursor() {
    let pki = Pki::new();
    let (addr, seen) = server(&pki, vec!["200 OK"]).await;
    let dir = std::env::temp_dir().join(format!("mimihubd-push-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.db");
    let open = || {
        Arc::new(Mutex::new(
            crate::Provider::open(DOMAIN, path.to_str().unwrap())
                .unwrap()
                .with_event_delivery()
                .with_event_push()
                .unwrap(),
        ))
    };
    {
        let provider: SharedProvider = open();
        write(&provider, &[b"one", b"two"]);
        let pusher = pusher(provider.clone(), &pki, addr);
        assert!(matches!(
            pusher.push_once().await,
            PushAttempt::Delivered { through: 2, .. }
        ));
        write(&provider, &[b"three"]);
    }
    let provider: SharedProvider = open();
    let pusher = pusher(provider.clone(), &pki, addr);
    assert!(matches!(
        pusher.push_once().await,
        PushAttempt::Delivered { through: 3, .. }
    ));
    let batches = batches(&seen);
    assert_eq!(seqs(&batches[0]), vec![1, 2]);
    assert_eq!(seqs(&batches[1]), vec![3]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A push URL off the provider's domain, a hub that delivers per user, or one not configured to push, is refused when
/// the pusher is made.
#[tokio::test]
async fn a_pusher_needs_the_stream_and_a_url_on_the_providers_domain() {
    let pki = Pki::new();
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let client = Arc::new(push_client(&pki, SERVER, addr, None));
    assert!(EventPusher::new(hub(), client.clone(), "https://elsewhere.example/events").is_err());
    assert!(EventPusher::new(hub(), client.clone(), "http://app.hub.example/events").is_err());
    let inbox = Arc::new(Mutex::new(crate::Provider::in_memory(DOMAIN).unwrap()));
    assert!(EventPusher::new(inbox, client.clone(), "https://app.hub.example/events").is_err());
    let not_pushing = Arc::new(Mutex::new(
        crate::Provider::in_memory(DOMAIN)
            .unwrap()
            .with_event_delivery(),
    ));
    assert!(EventPusher::new(not_pushing, client, "https://app.hub.example/events").is_err());
}

/// The push destination's allowlist admits the operator's own server on loopback, while a client made from the same
/// peers' settings, the one every request to a peer goes through, still refuses that address: the push's allowlist
/// widens nothing for a peer-supplied destination. Revert check: build the push client from the peers' settings
/// unchanged, and the push to loopback is refused; widen the peers' settings instead, and the peer request goes through.
#[tokio::test]
async fn the_push_allowlist_does_not_widen_the_peer_gate() {
    let pki = Pki::new();
    let (addr, seen) = server(&pki, vec!["200 OK"]).await;
    let url = PeerUrl::parse(&format!("https://{SERVER}:{}/x", addr.port()), DOMAIN).unwrap();
    let peers = pki.settings(AddressPolicy::default(), None, true, None);
    let push = PeerClient::new(
        peers.for_event_push(AddressPolicy::parse_allowlist("127.0.0.0/8").unwrap()),
        resolver(SERVER, &[addr]),
    )
    .unwrap();
    let peer = PeerClient::new(peers.clone(), resolver(SERVER, &[addr])).unwrap();
    assert_eq!(
        push.post(&url, "application/json", b"{}".to_vec())
            .await
            .expect("the push reaches the configured destination")
            .status,
        200
    );
    let refused = peer
        .post(&url, "application/json", b"{}".to_vec())
        .await
        .expect_err("PLANT-PUSH-WIDENS-PEERS: a peer request reached a loopback address");
    assert!(
        matches!(refused, crate::outbound::OutboundError::Refused { .. }),
        "{refused}"
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "only the push reached the server"
    );
}

/// A push the server keeps refusing is visible: failures counted, the last error kept, the acknowledged seq where it
/// was; one that goes through again clears them.
#[tokio::test]
async fn a_stuck_push_is_visible_in_its_status() {
    let pki = Pki::new();
    let (addr, _seen) = server(
        &pki,
        vec![
            "500 Internal Server Error",
            "503 Service Unavailable",
            "200 OK",
        ],
    )
    .await;
    let provider = hub();
    write(&provider, &[b"one"]);
    let pusher = pusher(provider.clone(), &pki, addr);
    pusher.push_once().await;
    pusher.push_once().await;
    let status = pusher.status();
    assert_eq!(status.failures, 2);
    assert_eq!(status.last_error.as_deref(), Some("answered 503"));
    assert_eq!(status.acked_through, 0);
    let shared = crate::http::lock(&provider).push_status().unwrap();
    assert_eq!(
        *shared.lock().unwrap(),
        status,
        "the provider reports the pusher's own status"
    );
    pusher.push_once().await;
    let status = pusher.status();
    assert_eq!(
        (status.failures, status.last_error, status.acked_through),
        (0, None, 1)
    );
}
