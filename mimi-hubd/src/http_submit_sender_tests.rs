//! `POST /mimi/pl/submitMessage/{room}`: a peer submits only as a user of a domain its proof authenticates. It never
//! submits as a user of this provider, and not as a user of a third provider; a refused message is neither stored nor
//! fanned out.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use mimi_core::protocol_wire::{
    IdentifierUri, SubmitMessageRequest, SubmitMessageResponse, PROTOCOL_MLS10,
};
use tower::ServiceExt;

use super::now_unix;
use super::tests::{app, real_mls_envelope_bytes};
use crate::http::SharedProvider;
use crate::peer::{PeerCert, PeerIdentity};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};

const ROOM: &str = "mimi://havenmessenger.com/r/lounge";
const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const CAROL: &str = "mimi://other.example/u/carol";

fn peer(name: &str) -> PeerCert {
    let (ca, _) = make_ca();
    let (cert_pem, _) = issue(&ca, vec![name.to_string()], "peer");
    let chain = certs_from_pem(cert_pem.as_bytes()).expect("chain");
    PeerCert(Some(PeerIdentity::new(chain[0].clone().into_owned())))
}

/// A room this hub hosts with two local members and one of other.example.
fn room() -> (Router, SharedProvider) {
    let (router, p) = app();
    {
        let g = p.lock().expect("lock");
        for member in [ALICE, BOB, CAROL] {
            g.add_participant(ROOM, member, now_unix())
                .expect("participant");
        }
    }
    (router, p)
}

/// What the hub answers when `from` (a peer's name, or none) submits a message as `sender`.
async fn submit(router: &Router, sender: &str, from: Option<&str>) -> SubmitMessageResponse {
    let body = SubmitMessageRequest {
        protocol: PROTOCOL_MLS10,
        app_message: real_mls_envelope_bytes(),
        sending_uri: IdentifierUri(sender.into()),
    }
    .encode()
    .expect("encode");
    let mut request = Request::builder()
        .method("POST")
        .uri(format!(
            "/mimi/pl/submitMessage/{}",
            ROOM.replace(':', "%3A").replace('/', "%2F")
        ))
        .body(Body::from(body))
        .expect("request");
    if let Some(name) = from {
        request.extensions_mut().insert(peer(name));
    }
    let response = router.clone().oneshot(request).await.expect("answer");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("body");
    SubmitMessageResponse::decode(&bytes).expect("decode")
}

fn queued_for(p: &SharedProvider, user: &str) -> usize {
    let g = p.lock().expect("lock");
    let mut n = 0;
    while g.fetch_message(user).expect("fetch").is_some() {
        n += 1;
    }
    n
}

/// A peer submits as its own user: accepted and fanned out to the local members.
#[tokio::test]
async fn a_peer_submits_as_its_own_user() {
    let (router, p) = room();
    assert!(matches!(
        submit(&router, CAROL, Some("other.example")).await,
        SubmitMessageResponse::Accepted { .. }
    ));
    assert_eq!(queued_for(&p, ALICE), 1, "fanned out to a local member");
}

/// A peer cannot submit as a user of this provider, whichever name its certificate carries, and the message reaches
/// no one. Revert check: authorize the sender without asking who the peer is, and Alice's message is accepted.
#[tokio::test]
async fn a_peer_cannot_submit_as_a_local_user() {
    let (router, p) = room();
    for from in [Some("other.example"), Some("havenmessenger.com"), None] {
        assert_eq!(
            submit(&router, ALICE, from).await,
            SubmitMessageResponse::NotAllowed,
            "PLANT-SUBMIT-LOCAL: a peer ({from:?}) submitted as Alice"
        );
    }
    assert_eq!(queued_for(&p, BOB), 0, "nothing was fanned out");
}

/// A peer cannot submit as another provider's user.
#[tokio::test]
async fn a_peer_cannot_submit_as_a_third_providers_user() {
    let (router, p) = room();
    assert_eq!(
        submit(&router, CAROL, Some("third.example")).await,
        SubmitMessageResponse::NotAllowed,
        "PLANT-SUBMIT-THIRD: third.example submitted as other.example's user"
    );
    assert_eq!(queued_for(&p, ALICE), 0, "nothing was fanned out");
}
