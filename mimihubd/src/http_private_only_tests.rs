//! submitMessage takes only an application message as RFC 9420 §6 has one, a PrivateMessage carrying application
//! content, on both paths: a peer's wire `submitMessage` and the client lane's.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use mimi_core::protocol_wire::{
    IdentifierUri, SubmitMessageRequest, SubmitMessageResponse, PROTOCOL_MLS10,
};
use tower::ServiceExt;

use super::client_lane_tests::{call, lane, signed};
use super::tests::app;
use crate::mls_fixtures::{public_application_message, Sender};

const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const DAVE: &str = "mimi://havenmessenger.com/u/dave";
/// A member of another provider, which submits on the wire for its own users only.
const CAROL: &str = "mimi://other.example/u/carol";

/// On the wire, a PublicMessage carrying application content is answered notAllowed and reaches no one; a
/// PrivateMessage is accepted. Revert check: skip the check, and the PublicMessage is accepted.
#[tokio::test]
async fn the_wire_refuses_a_public_application_message() {
    let (router, p) = app();
    let room = "mimi://havenmessenger.com/r/wire";
    {
        let p = p.lock().unwrap();
        p.add_participant(room, CAROL, 0).unwrap();
        p.add_participant(room, DAVE, 0).unwrap();
    }
    // The request comes from other.example, proven by its certificate, for its own user Carol.
    let (ca, _) = crate::tls::tests::make_ca();
    let (cert_pem, _) = crate::tls::tests::issue(&ca, vec!["other.example".into()], "other");
    let chain = crate::tls::certs_from_pem(cert_pem.as_bytes()).unwrap();
    let submit = |message: Vec<u8>| {
        let request = SubmitMessageRequest {
            protocol: PROTOCOL_MLS10,
            app_message: message,
            sending_uri: IdentifierUri(CAROL.to_string()),
        };
        let mut request = Request::builder()
            .method("POST")
            .uri(format!(
                "/mimi/pl/submitMessage/{}",
                room.replace(':', "%3A").replace('/', "%2F")
            ))
            .body(Body::from(request.encode().unwrap()))
            .unwrap();
        request.extensions_mut().insert(crate::peer::PeerCert(Some(
            crate::peer::PeerIdentity::new(chain[0].clone().into_owned()),
        )));
        request
    };
    let answer = |body: axum::body::Bytes| SubmitMessageResponse::decode(&body).unwrap();
    let response = router
        .clone()
        .oneshot(submit(public_application_message(b"g", 0)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        answer(body),
        SubmitMessageResponse::NotAllowed,
        "PLANT-PRIVATE-ONLY-WIRE: a PublicMessage was taken on the wire"
    );
    assert!(p.lock().unwrap().fetch_message(DAVE).unwrap().is_none());
    let response = router
        .oneshot(submit(Sender::new().message(b"hello")))
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        matches!(answer(body), SubmitMessageResponse::Accepted { .. }),
        "the same sender's PrivateMessage is accepted, so the refusal above is the check's"
    );
}

/// On the client lane, a PublicMessage carrying application content is answered 400 not-an-application-message and
/// reaches no one.
#[tokio::test]
async fn the_lane_refuses_a_public_application_message() {
    let l = lane("private-only");
    let (status, body) = call(&l.router, signed(&l.key, "createRoom", ALICE, "{}")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let room = body["room"].as_str().unwrap().to_string();
    l.provider
        .lock()
        .unwrap()
        .add_participant(&room, DAVE, 0)
        .unwrap();
    let send = |message: &[u8]| {
        format!(
            r#"{{"room":"{room}","message":"{}"}}"#,
            STANDARD.encode(message)
        )
    };
    let (status, body) = call(
        &l.router,
        signed(
            &l.key,
            "submitMessage",
            ALICE,
            &send(&public_application_message(b"g", 0)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["type"]
            .as_str()
            .unwrap()
            .ends_with("#not-an-application-message"),
        "PLANT-PRIVATE-ONLY-LANE: {body}"
    );
    assert!(l
        .provider
        .lock()
        .unwrap()
        .lane_inbox(DAVE, 0, 0, 10)
        .unwrap()
        .messages
        .is_empty());
    let (status, body) = call(
        &l.router,
        signed(
            &l.key,
            "submitMessage",
            ALICE,
            &send(&Sender::new().message(b"hello")),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same sender's PrivateMessage is taken, so the refusal above is the check's: {body}"
    );
}
