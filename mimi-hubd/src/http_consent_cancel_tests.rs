//! A `requestConsent` cancel on the wire lane (protocol-07 §5.7): it withdraws the pending request of the same
//! ConsentScope, only when the peer's certificate authenticates the requester URI's domain, and never a grant or a
//! revoke the target made. Every answer is the same 202, so a cancel says nothing about what exists.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{Extension, Router};
use mimi_core::consent::{ConsentEntry, ConsentOperation};
use mimi_core::protocol_wire::encode_consent_entry;
use tower::ServiceExt;

use super::tests::app;
use crate::http::SharedProvider;
use crate::peer::{PeerCert, PeerIdentity};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};

const REQUESTER_DOMAIN: &str = "mimi-b.havenmessenger.com";
const REQUESTER: &str = "mimi://mimi-b.havenmessenger.com/u/bob";
const TARGET: &str = "mimi://havenmessenger.com/u/alice";
const ROUTE: &str = "/mimi/pl/requestConsent/havenmessenger.com";

fn identity_for(domain: &str) -> PeerIdentity {
    let (ca, _ca_pem) = make_ca();
    let (cert_pem, _key) = issue(&ca, vec![domain.to_string()], domain);
    let chain = certs_from_pem(cert_pem.as_bytes()).unwrap();
    PeerIdentity::new(chain[0].clone().into_owned())
}

fn entry(operation: ConsentOperation) -> ConsentEntry {
    ConsentEntry {
        operation,
        requester_uri: REQUESTER.into(),
        target_uri: TARGET.into(),
        room_uri: None,
        client_key_packages: Vec::new(),
        consent_extensions: Vec::new(),
    }
}

async fn cancel_from(router: Router, peer: Option<&str>) -> StatusCode {
    let router = match peer {
        Some(domain) => router.layer(Extension(PeerCert(Some(identity_for(domain))))),
        None => router,
    };
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(ROUTE)
                .body(Body::from(
                    encode_consent_entry(&entry(ConsentOperation::Cancel)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

fn state(p: &SharedProvider) -> Option<String> {
    p.lock()
        .unwrap()
        .store
        .consent_state(REQUESTER, TARGET, "")
        .unwrap()
}

fn requested(p: &SharedProvider) {
    p.lock()
        .unwrap()
        .process_request_consent(&entry(ConsentOperation::Request), None, 1)
        .unwrap();
}

/// The requester's provider withdraws its pending request with a wire cancel. Revert check: hand the cancel to the
/// request path as before and the request stays.
#[tokio::test]
async fn the_requesters_provider_cancels_its_pending_request() {
    let (router, p) = app();
    requested(&p);
    assert_eq!(state(&p).as_deref(), Some("requested"));
    assert_eq!(
        cancel_from(router, Some(REQUESTER_DOMAIN)).await,
        StatusCode::ACCEPTED
    );
    assert_eq!(state(&p), None);
}

/// A cancel from any other provider, or from a connection with no certificate, withdraws nothing, and is answered as
/// the requester's own is. Revert check: drop the provider check and another provider withdraws the request.
#[tokio::test]
async fn a_cancel_from_another_provider_withdraws_nothing() {
    for peer in [Some("havenmessenger.com"), Some("other.example"), None] {
        let (router, p) = app();
        requested(&p);
        assert_eq!(
            cancel_from(router, peer).await,
            StatusCode::ACCEPTED,
            "{peer:?}"
        );
        assert_eq!(state(&p).as_deref(), Some("requested"), "{peer:?}");
    }
}

/// A cancel withdraws a pending request and nothing else: a grant or a revoke (a preemptive denial among them) the
/// target made stays, whoever sends the cancel. Revert check: delete the scope's record whatever its state and the
/// target's decision is gone.
#[tokio::test]
async fn a_cancel_leaves_the_targets_decision_in_place() {
    for decision in [ConsentOperation::Grant, ConsentOperation::Revoke] {
        let (router, p) = app();
        requested(&p);
        p.lock()
            .unwrap()
            .process_update_consent(&entry(decision), 2)
            .unwrap();
        let before = state(&p);
        assert!(before.is_some());
        assert_eq!(
            cancel_from(router, Some(REQUESTER_DOMAIN)).await,
            StatusCode::ACCEPTED
        );
        assert_eq!(state(&p), before, "{decision:?}");
    }
}

/// A cancel with no request of its ConsentScope changes nothing and is answered the same.
#[tokio::test]
async fn a_cancel_with_no_request_is_answered_the_same() {
    let (router, p) = app();
    assert_eq!(
        cancel_from(router, Some(REQUESTER_DOMAIN)).await,
        StatusCode::ACCEPTED
    );
    assert_eq!(state(&p), None);
}

/// A cancel is the requester's: an updateConsent cancel, which the target's provider would send, changes nothing.
#[test]
fn an_update_consent_cancel_changes_nothing() {
    let (_router, p) = app();
    requested(&p);
    assert!(p
        .lock()
        .unwrap()
        .process_update_consent(&entry(ConsentOperation::Cancel), 2)
        .is_err());
    assert_eq!(state(&p).as_deref(), Some("requested"));
}
