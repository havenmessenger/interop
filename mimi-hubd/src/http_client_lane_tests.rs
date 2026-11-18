//! The client lane end to end through its router: requests signed as the client-facing service signs them, for one user
//! of this provider, and what the lane lets that user do.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::now_unix;
use super::tests::real_keypackage_for;
use crate::client_http::{build_client_router, UserCap, REQUESTS_PER_USER_PER_MINUTE};
use crate::client_lane::ClientLaneAuth;
use crate::http::SharedProvider;
use crate::signature::{NonceLedger, PeerKeys};
use crate::Provider;

const DOMAIN: &str = "havenmessenger.com";
const HOST: &str = "hub.example:8450";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const ALICE: &str = "mimi://havenmessenger.com/u/alice";

static NONCES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The client-facing service's key, and a lane whose key file holds its public half.
pub(super) struct Lane {
    pub(super) key: Ed25519KeyPair,
    pub(super) router: Router,
    pub(super) provider: SharedProvider,
    dir: std::path::PathBuf,
}

impl Drop for Lane {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

pub(super) fn lane(test: &str) -> Lane {
    lane_with(test, crate::client_lane_rooms::LaneRoomProfile::neutral())
}

/// [`lane`], with `rooms` as the deployment's lane room profile.
pub(super) fn lane_with(test: &str, rooms: crate::client_lane_rooms::LaneRoomProfile) -> Lane {
    lane_at(test, DOMAIN, rooms)
}

/// [`lane_with`], for a hub of `domain`.
pub(super) fn lane_at(
    test: &str,
    domain: &str,
    rooms: crate::client_lane_rooms::LaneRoomProfile,
) -> Lane {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).expect("seed");
    let dir = std::env::temp_dir().join(format!("mimi-lane-http-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("lane_keys.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"lane1._mimi.client-lane": "{}"}}"#,
            STANDARD.encode(key.public_key().as_ref())
        ),
    )
    .expect("key file");
    let provider: SharedProvider =
        Arc::new(Mutex::new(Provider::in_memory(domain).expect("provider")));
    let auth = Arc::new(ClientLaneAuth {
        keys: PeerKeys::from_file(Some(path)),
        nonces: NonceLedger::default(),
        started_unix: i64::try_from(seconds()).unwrap_or(0) - 10,
        domain: domain.into(),
    });
    Lane {
        key,
        router: build_client_router(provider.clone(), auth, rooms),
        provider,
        dir,
    }
}

/// A request to `route` for `user`, signed with `key` as the client-facing service signs it.
pub(super) fn signed(key: &Ed25519KeyPair, route: &str, user: &str, body: &str) -> Request<Body> {
    let path = format!("/mimi/client/v1/{route}");
    let digest = format!(
        "sha-256=:{}:",
        STANDARD.encode(Sha256::digest(body.as_bytes()))
    );
    // A fresh nonce for every request, as the service makes them: the lane refuses one it has seen.
    let count = NONCES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nonce = URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!("{route}{user}{body}{count}").as_bytes(),
    ))[..22]
        .to_string();
    let params = format!(
        r#"("@method" "@target-uri" "content-digest" "mimi-client-user" "mimi-client-device");created={};nonce="{nonce}";keyid="lane1";tag="haven-client-lane""#,
        seconds()
    );
    let base = format!(
        "\"@method\": POST\n\"@target-uri\": https://{HOST}{path}\n\"content-digest\": {digest}\n\"mimi-client-user\": {user}\n\"mimi-client-device\": dev-1\n\"@signature-params\": {params}"
    );
    let signature = STANDARD.encode(key.sign(base.as_bytes()).as_ref());
    Request::builder()
        .method("POST")
        .uri(&path)
        .header("host", HOST)
        .header("content-digest", digest)
        .header("mimi-client-user", user)
        .header("mimi-client-device", "dev-1")
        .header("signature-input", format!("haven={params}"))
        .header("signature", format!("haven=:{signature}:"))
        .body(Body::from(body.to_string()))
        .expect("request")
}

pub(super) async fn call(
    router: &Router,
    request: Request<Body>,
) -> (StatusCode, serde_json::Value) {
    let response = router.clone().oneshot(request).await.expect("answer");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// The user publishes their own KeyPackage, and it is stored under their name here, where a peer's keyMaterial claim
/// looks for it. Revert check: skip the credential check, and Alice's KeyPackage is stored for Bob.
#[tokio::test]
async fn a_user_publishes_only_their_own_key_packages() {
    let lane = lane("publish");
    let bobs = STANDARD.encode(real_keypackage_for(BOB.as_bytes()));
    let alices = STANDARD.encode(real_keypackage_for(ALICE.as_bytes()));
    let (status, answer) = call(
        &lane.router,
        signed(
            &lane.key,
            "publishKeyPackages",
            BOB,
            &format!(r#"{{"key_packages":["{bobs}"]}}"#),
        ),
    )
    .await;
    assert_eq!(
        (status, answer["count"].as_u64()),
        (StatusCode::OK, Some(1))
    );
    let (status, _) = call(
        &lane.router,
        signed(
            &lane.key,
            "publishKeyPackages",
            BOB,
            &format!(r#"{{"key_packages":["{alices}"]}}"#),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "PLANT-LANE-CREDENTIAL: a KeyPackage naming another user was accepted"
    );
    let claimed = lane
        .provider
        .lock()
        .expect("lock")
        .serve_key_material("bob", now_unix())
        .expect("claim");
    assert!(
        claimed.is_some(),
        "Bob's KeyPackage is claimable under his name"
    );
    let (status, answer) = call(
        &lane.router,
        signed(&lane.key, "withdrawKeyPackages", BOB, "{}"),
    )
    .await;
    assert_eq!(
        (status, answer["count"].as_u64()),
        (StatusCode::OK, Some(0))
    );
}

/// Withdrawing removes what is published, so no one can add the user any more.
#[tokio::test]
async fn withdrawing_leaves_nothing_to_claim() {
    let lane = lane("withdraw");
    let bobs = STANDARD.encode(real_keypackage_for(BOB.as_bytes()));
    call(
        &lane.router,
        signed(
            &lane.key,
            "publishKeyPackages",
            BOB,
            &format!(r#"{{"key_packages":["{bobs}","{bobs}"]}}"#),
        ),
    )
    .await;
    let (status, answer) = call(
        &lane.router,
        signed(&lane.key, "withdrawKeyPackages", BOB, "{}"),
    )
    .await;
    assert_eq!(
        (status, answer["count"].as_u64()),
        (StatusCode::OK, Some(2))
    );
    let left = lane
        .provider
        .lock()
        .expect("lock")
        .serve_key_material("bob", now_unix())
        .expect("claim");
    assert!(left.is_none());
}

/// The inbox reads both forms a user's items are queued under, leaves them in place, and an ack removes only what it
/// names; another user's items are never in the page. Revert check: delete on fetch, and the second fetch is empty.
#[tokio::test]
async fn the_inbox_is_read_then_acknowledged() {
    let lane = lane("inbox");
    {
        let p = lane.provider.lock().expect("lock");
        // Alice's item first, so an ack that ignored whose items it removes would take it with Bob's.
        p.store
            .enqueue_message("alice", b"not-bobs", now_unix())
            .expect("queue");
        p.store
            .enqueue_welcome("bob", b"welcome-1", now_unix())
            .expect("queue");
        p.store
            .enqueue_message(BOB, b"commit-1", now_unix())
            .expect("queue");
        p.store
            .enqueue_message("bob", b"message-2", now_unix())
            .expect("queue");
    }
    let fetch = || {
        signed(
            &lane.key,
            "inboxFetch",
            BOB,
            r#"{"after_welcome":0,"after_message":0,"limit":10}"#,
        )
    };
    let (status, page) = call(&lane.router, fetch()).await;
    assert_eq!(status, StatusCode::OK);
    let bytes = |items: &serde_json::Value| -> Vec<Vec<u8>> {
        items
            .as_array()
            .expect("items")
            .iter()
            .map(|item| {
                STANDARD
                    .decode(item["bytes"].as_str().expect("bytes"))
                    .expect("b64")
            })
            .collect()
    };
    assert_eq!(bytes(&page["welcomes"]), vec![b"welcome-1".to_vec()]);
    assert_eq!(
        bytes(&page["messages"]),
        vec![b"commit-1".to_vec(), b"message-2".to_vec()],
        "both forms, in order, and none of Alice's"
    );
    let (_, again) = call(&lane.router, fetch()).await;
    assert_eq!(
        bytes(&again["messages"]).len(),
        2,
        "PLANT-LANE-PEEK: a fetch removed what it read"
    );
    let first_message = page["messages"][0]["seq"].as_i64().expect("seq");
    let welcome = page["welcomes"][0]["seq"].as_i64().expect("seq");
    let (status, acked) = call(
        &lane.router,
        signed(
            &lane.key,
            "inboxAck",
            BOB,
            &format!(r#"{{"welcomes_up_to":{welcome},"messages_up_to":{first_message}}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (acked["welcomes"].as_u64(), acked["messages"].as_u64()),
        (Some(1), Some(1))
    );
    let (_, after) = call(&lane.router, fetch()).await;
    assert_eq!(bytes(&after["messages"]), vec![b"message-2".to_vec()]);
    assert!(bytes(&after["welcomes"]).is_empty());
    let alices = lane
        .provider
        .lock()
        .expect("lock")
        .lane_inbox(ALICE, 0, 0, 10)
        .expect("alice");
    assert_eq!(
        alices.messages.len(),
        1,
        "PLANT-LANE-ACK-USER: Bob's ack removed Alice's item"
    );
}

/// No lane signature, or one for a user of another provider, reaches nothing.
#[tokio::test]
async fn an_unsigned_or_foreign_request_is_refused() {
    let lane = lane("refused");
    let unsigned = Request::builder()
        .method("POST")
        .uri("/mimi/client/v1/inboxFetch")
        .header("host", HOST)
        .header("mimi-client-user", BOB)
        .body(Body::from("{}"))
        .expect("request");
    assert_eq!(
        call(&lane.router, unsigned).await.0,
        StatusCode::UNAUTHORIZED
    );
    let foreign = signed(&lane.key, "inboxFetch", "mimi://other.example/u/bob", "{}");
    assert_eq!(
        call(&lane.router, foreign).await.0,
        StatusCode::UNAUTHORIZED
    );
    let other_key = Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).expect("seed");
    let wrong_key = signed(&other_key, "inboxFetch", BOB, "{}");
    assert_eq!(
        call(&lane.router, wrong_key).await.0,
        StatusCode::UNAUTHORIZED
    );
}

/// The per-user cap counts each user on their own and starts again each minute.
#[test]
fn the_per_user_cap_is_per_user_and_per_minute() {
    let cap = UserCap::default();
    for _ in 0..REQUESTS_PER_USER_PER_MINUTE {
        assert!(cap.admit(BOB, 600));
    }
    assert!(!cap.admit(BOB, 600), "PLANT-LANE-CAP: past the cap");
    assert!(cap.admit(ALICE, 600), "another user is counted apart");
    assert!(cap.admit(BOB, 660), "a new minute starts again");
}
