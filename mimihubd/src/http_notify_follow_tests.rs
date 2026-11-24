//! A room on another hub, as this provider's users see it: a Welcome from its hub makes the user it names a member, and
//! what the hub fans out after that reaches the member, once, without the FanoutMessage's tail.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Extension, Router,
};
use mimi_core::protocol_wire::FanoutMessage;
use tower::ServiceExt;

use super::notify_welcome_tests::welcome_adding;
use super::now_unix;
use super::tests::{app, real_keypackage_for, real_mls_envelope_bytes};
use crate::http::SharedProvider;
use crate::peer::{PeerCert, PeerIdentity};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};

const ROOM: &str = "mimi://other.example/r/lounge";

fn the_rooms_hub() -> PeerCert {
    let (ca, _) = make_ca();
    let (cert_pem, _) = issue(&ca, vec!["other.example".to_string()], "other");
    let chain = certs_from_pem(cert_pem.as_bytes()).unwrap();
    PeerCert(Some(PeerIdentity::new(chain[0].clone().into_owned())))
}

async fn notify(router: &Router, fanout: &FanoutMessage) -> StatusCode {
    router
        .clone()
        .layer(Extension(the_rooms_hub()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/mimi/pl/notify/{}",
                    ROOM.replace(':', "%3A").replace('/', "%2F")
                ))
                .body(Body::from(fanout.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// Bob publishes a KeyPackage here, and the room's hub sends the Welcome adding him.
async fn bob_is_welcomed(router: &Router, p: &SharedProvider) {
    let bobs = real_keypackage_for(b"mimi://havenmessenger.com/u/bob");
    p.lock()
        .unwrap()
        .publish_key_package("bob", &bobs, now_unix())
        .unwrap();
    let welcome = FanoutMessage {
        protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
        timestamp: 1,
        message_and_tail: welcome_adding(&bobs),
    };
    assert_eq!(notify(router, &welcome).await, StatusCode::CREATED);
}

fn messages(p: &SharedProvider, user: &str) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    while let Some(message) = p.lock().unwrap().fetch_message(user).unwrap() {
        all.push(message);
    }
    all
}

/// After the Welcome, a message for the room reaches Bob as its MLSMessage, the tail left off; a second one follows it.
/// Revert check: do not make Bob a member on his Welcome, and the message is refused as for a room with nobody here.
#[tokio::test]
async fn a_welcomed_user_gets_the_rooms_messages_in_order() {
    let (router, p) = app();
    bob_is_welcomed(&router, &p).await;
    let first = real_mls_envelope_bytes();
    let second = real_mls_envelope_bytes();
    assert_eq!(
        notify(&router, &FanoutMessage::application(2, &first)).await,
        StatusCode::CREATED,
        "PLANT-FOLLOW-MEMBER: the welcomed user is not a member"
    );
    assert_eq!(
        notify(&router, &FanoutMessage::commit(3, &second)).await,
        StatusCode::CREATED
    );
    assert_eq!(
        messages(&p, "bob"),
        [first, second],
        "PLANT-FOLLOW-MESSAGE: not the MLSMessages, in order"
    );
}

/// The same message sent again, in another body (another timestamp), is answered 201 and delivered once; the same body
/// again is 201 too. Revert check: drop the per-room check, and Bob gets the message twice.
#[tokio::test]
async fn the_same_message_in_another_body_is_delivered_once() {
    let (router, p) = app();
    bob_is_welcomed(&router, &p).await;
    let message = real_mls_envelope_bytes();
    let once = FanoutMessage::application(2, &message);
    assert_eq!(notify(&router, &once).await, StatusCode::CREATED);
    assert_eq!(notify(&router, &once).await, StatusCode::CREATED);
    assert_eq!(
        notify(&router, &FanoutMessage::application(9, &message)).await,
        StatusCode::CREATED
    );
    assert_eq!(
        messages(&p, "bob").len(),
        1,
        "PLANT-FOLLOW-DEDUP: the message was delivered twice"
    );
}

/// A Welcome naming no user here makes no member: the next message for the room is refused.
#[tokio::test]
async fn a_welcome_for_nobody_here_makes_no_member() {
    let (router, _p) = app();
    let someone_elses = real_keypackage_for(b"mimi://elsewhere.example/u/dana");
    let welcome = FanoutMessage {
        protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
        timestamp: 1,
        message_and_tail: welcome_adding(&someone_elses),
    };
    assert_eq!(notify(&router, &welcome).await, StatusCode::CREATED);
    assert_eq!(
        notify(
            &router,
            &FanoutMessage::application(2, &real_mls_envelope_bytes())
        )
        .await,
        StatusCode::NOT_FOUND
    );
}
