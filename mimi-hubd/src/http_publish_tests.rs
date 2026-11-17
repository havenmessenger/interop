//! `/mimi/v1/keyMaterial/ingest?user=`: a peer publishes a KeyPackage only for a user of its own provider, the one its
//! certificate names. A user of this provider takes KeyPackages from no peer; its operator publishes for it
//! (`admin.rs`).

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Extension, Router,
};
use tower::ServiceExt;

use super::tests::{app, real_keypackage_for};
use crate::peer::{PeerCert, PeerIdentity};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};

fn peer(names: &[&str]) -> PeerCert {
    let (ca, _ca_pem) = make_ca();
    let (cert_pem, _key) = issue(&ca, names.iter().map(|n| n.to_string()).collect(), "peer");
    let chain = certs_from_pem(cert_pem.as_bytes()).unwrap();
    PeerCert(Some(PeerIdentity::new(chain[0].clone().into_owned())))
}

async fn publish(router: Router, user: &str, from: Option<PeerCert>) -> StatusCode {
    let user = user.replace(':', "%3A").replace('/', "%2F");
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/mimi/v1/keyMaterial/ingest?user={user}"))
        .body(Body::from(real_keypackage_for(
            b"mimi://havenmessenger.com/u/alice",
        )))
        .unwrap();
    if let Some(peer) = from {
        request.extensions_mut().insert(Extension(peer).0);
    }
    router.oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn our_users_take_keypackages_from_no_peer() {
    let (router, _p) = app();
    for from in [
        None,
        Some(peer(&["other.example"])),
        Some(peer(&["havenmessenger.com"])),
    ] {
        assert_eq!(
            publish(router.clone(), "alice", from.clone()).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            publish(router.clone(), "mimi://havenmessenger.com/u/alice", from).await,
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn another_providers_user_needs_that_providers_certificate() {
    let (router, p) = app();
    let theirs = "mimi://other.example/u/carol";
    assert_eq!(
        publish(router.clone(), theirs, None).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        publish(router.clone(), theirs, Some(peer(&["third.example"]))).await,
        StatusCode::FORBIDDEN
    );
    assert!(p
        .lock()
        .unwrap()
        .serve_key_material(theirs, 1)
        .unwrap()
        .is_none());
    assert_eq!(
        publish(router, theirs, Some(peer(&["other.example"]))).await,
        StatusCode::NO_CONTENT
    );
}
