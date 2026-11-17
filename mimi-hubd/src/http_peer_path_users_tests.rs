//! The provider path serves a peer only for that peer's own users. A peer can neither read nor take what is queued for
//! a user of this provider, nor publish KeyPackages under one's name; the hub's operator still can, on its loopback
//! listener, for demos and tests.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use tower::ServiceExt;

use super::now_unix;
use super::tests::{app, real_keypackage_for};
use crate::peer::{PeerCert, PeerIdentity};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};

const BOB: &str = "mimi://havenmessenger.com/u/bob";

fn peer(name: &str) -> PeerCert {
    let (ca, _) = make_ca();
    let (cert_pem, _) = issue(&ca, vec![name.to_string()], "peer");
    let chain = certs_from_pem(cert_pem.as_bytes()).expect("chain");
    PeerCert(Some(PeerIdentity::new(chain[0].clone().into_owned())))
}

fn encoded(user: &str) -> String {
    user.replace(':', "%3A").replace('/', "%2F")
}

async fn as_peer(router: &Router, request: Request<Body>, from: &str) -> StatusCode {
    let mut request = request;
    request.extensions_mut().insert(peer(from));
    router
        .clone()
        .oneshot(request)
        .await
        .expect("answer")
        .status()
}

fn pull(kind: &str, user: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/mimi/v1/{kind}?user={}", encoded(user)))
        .body(Body::empty())
        .expect("request")
}

fn publish(user: &str, identity: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!(
            "/mimi/v1/keyMaterial/ingest?user={}",
            encoded(user)
        ))
        .body(Body::from(real_keypackage_for(identity.as_bytes())))
        .expect("request")
}

/// A peer asking for what is queued for one of this provider's users gets nothing and takes nothing: the item is still
/// there afterwards, under the bare name and under the URI.
#[tokio::test]
async fn a_peer_cannot_read_or_take_a_local_users_queue() {
    let (router, p) = app();
    {
        let g = p.lock().expect("lock");
        g.store
            .enqueue_message("bob", b"for-bob", now_unix())
            .expect("queue");
        g.store
            .enqueue_message(BOB, b"for-bob-uri", now_unix())
            .expect("queue");
        g.store
            .enqueue_welcome("bob", b"welcome-bob", now_unix())
            .expect("queue");
    }
    for (kind, user) in [("message", "bob"), ("message", BOB), ("welcome", "bob")] {
        assert_eq!(
            as_peer(&router, pull(kind, user), "other.example").await,
            StatusCode::FORBIDDEN,
            "PLANT-PEER-PULL: a peer read {kind} for {user}"
        );
    }
    let g = p.lock().expect("lock");
    assert_eq!(
        g.fetch_message("bob").expect("fetch"),
        Some(b"for-bob".to_vec())
    );
    assert_eq!(
        g.fetch_message(BOB).expect("fetch"),
        Some(b"for-bob-uri".to_vec())
    );
    assert_eq!(
        g.fetch_welcome("bob").expect("fetch"),
        Some(b"welcome-bob".to_vec())
    );
}

/// A peer cannot publish KeyPackages under the name of a user of this provider, as a bare name or as a URI.
#[tokio::test]
async fn a_peer_cannot_publish_for_a_local_user() {
    let (router, p) = app();
    for user in ["bob", BOB] {
        assert_eq!(
            as_peer(&router, publish(user, BOB), "other.example").await,
            StatusCode::FORBIDDEN,
            "PLANT-PEER-PUBLISH: a peer published for {user}"
        );
    }
    assert!(p
        .lock()
        .expect("lock")
        .serve_key_material("bob", now_unix())
        .expect("claim")
        .is_none());
}

/// A peer still publishes for its own domain's users, and not for a third provider's.
#[tokio::test]
async fn a_peer_publishes_for_its_own_users_only() {
    let (router, _p) = app();
    let carol = "mimi://other.example/u/carol";
    assert_eq!(
        as_peer(&router, publish(carol, carol), "other.example").await,
        StatusCode::NO_CONTENT
    );
    let dave = "mimi://third.example/u/dave";
    assert_eq!(
        as_peer(&router, publish(dave, dave), "other.example").await,
        StatusCode::FORBIDDEN
    );
}

/// The operator's loopback listener publishes and pulls for a local user.
#[tokio::test]
async fn the_operator_publishes_and_pulls_for_local_users() {
    let (_router, p) = app();
    let admin = crate::admin::build_admin_router(p.clone());
    let operator_publish = Request::builder()
        .method("POST")
        .uri("/mimi/v1/operator/keyMaterial?user=bob")
        .body(Body::from(real_keypackage_for(BOB.as_bytes())))
        .expect("request");
    let status = admin
        .clone()
        .oneshot(operator_publish)
        .await
        .expect("answer")
        .status();
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(p
        .lock()
        .expect("lock")
        .serve_key_material("bob", now_unix())
        .expect("claim")
        .is_some());
    p.lock()
        .expect("lock")
        .store
        .enqueue_message("bob", b"for-bob", now_unix())
        .expect("queue");
    let answer = admin
        .oneshot(pull("operator/message", "bob"))
        .await
        .expect("answer");
    assert_eq!(answer.status(), StatusCode::OK);
    let body = axum::body::to_bytes(answer.into_body(), 1 << 16)
        .await
        .expect("body");
    assert_eq!(&body[..], b"for-bob");
}
