//! The JSON lane's deposits (`POST /mimi/v1/submitMessage?recipient=` and `POST /mimi/v1/welcome/ingest?recipient=`)
//! take an item only for a user of a domain the peer's proof authenticates. A user of this provider's queues are filled
//! only by this hub's own fan-out and its operator, so a peer cannot fill them with items of its own.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use tower::ServiceExt;

use super::now_unix;
use super::tests::{app, real_mls_envelope_bytes};
use crate::http::SharedProvider;
use crate::peer::{PeerCert, PeerIdentity};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};

const BOB: &str = "mimi://havenmessenger.com/u/bob";
const CAROL: &str = "mimi://other.example/u/carol";

fn peer(name: &str) -> PeerCert {
    let (ca, _) = make_ca();
    let (cert_pem, _) = issue(&ca, vec![name.to_string()], "peer");
    let chain = certs_from_pem(cert_pem.as_bytes()).expect("chain");
    PeerCert(Some(PeerIdentity::new(chain[0].clone().into_owned())))
}

async fn deposit(
    router: &Router,
    route: &str,
    recipient: &str,
    body: Vec<u8>,
    from: &str,
) -> StatusCode {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!(
            "/mimi/v1/{route}?recipient={}",
            recipient.replace(':', "%3A").replace('/', "%2F")
        ))
        .body(Body::from(body))
        .expect("request");
    request.extensions_mut().insert(peer(from));
    router
        .clone()
        .oneshot(request)
        .await
        .expect("answer")
        .status()
}

/// How many messages and Welcomes are queued for `user` (and taken, so the count is exact).
fn queued(p: &SharedProvider, user: &str) -> (usize, usize) {
    let g = p.lock().expect("lock");
    let (mut messages, mut welcomes) = (0, 0);
    while g.fetch_message(user).expect("fetch").is_some() {
        messages += 1;
    }
    while g.fetch_welcome(user).expect("fetch").is_some() {
        welcomes += 1;
    }
    (messages, welcomes)
}

/// A peer cannot deposit a message or relay a Welcome into the queue of a user of this provider, by bare name or URI,
/// whatever name its certificate carries; the queue holds exactly what it held. Revert check: drop the check, and the
/// queue grows by the peer's items.
#[tokio::test]
async fn a_peer_cannot_fill_a_local_users_queue() {
    let (router, p) = app();
    p.lock()
        .expect("lock")
        .store
        .enqueue_message("bob", b"ours", now_unix())
        .expect("queue");
    for from in ["other.example", "havenmessenger.com"] {
        for user in ["bob", BOB] {
            assert_eq!(
                deposit(
                    &router,
                    "submitMessage",
                    user,
                    real_mls_envelope_bytes(),
                    from
                )
                .await,
                StatusCode::FORBIDDEN,
                "PLANT-PEER-DEPOSIT: {from} deposited a message for {user}"
            );
            assert_eq!(
                deposit(
                    &router,
                    "welcome/ingest",
                    user,
                    b"not a welcome".to_vec(),
                    from
                )
                .await,
                StatusCode::FORBIDDEN,
                "PLANT-PEER-WELCOME-RELAY: {from} relayed a Welcome for {user}"
            );
        }
    }
    assert_eq!(queued(&p, "bob"), (1, 0), "only this hub's own item");
    assert_eq!(queued(&p, BOB), (0, 0));
}

/// A peer still deposits for its own provider's users.
#[tokio::test]
async fn a_peer_deposits_for_its_own_users() {
    let (router, p) = app();
    assert_eq!(
        deposit(
            &router,
            "submitMessage",
            CAROL,
            real_mls_envelope_bytes(),
            "other.example"
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(queued(&p, CAROL), (1, 0));
    assert_eq!(
        deposit(
            &router,
            "submitMessage",
            CAROL,
            real_mls_envelope_bytes(),
            "third.example"
        )
        .await,
        StatusCode::FORBIDDEN
    );
}
