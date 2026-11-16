//! Every refusal carries an RFC 9457 problem body: the type for its condition, a `status` that matches the answer's,
//! and nothing the request named (mimi-protocol PR #211). Refusals axum answers itself (an unmatched route, a wrong
//! method, an unreadable JSON body) get one from the fallback layer, on every listener.

use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::Response,
    Router,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::tests::app;
use crate::problem::PROBLEM_JSON;

const HUB: &str = "havenmessenger.com";
const FOREIGN_ROOM: &str = "mimi%3A%2F%2Fother.example%2Fr%2Fsecret-room";

fn post(uri: &str, body: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::from(body.to_vec()))
        .unwrap()
}

/// The answer's problem type anchor, after checking its media type, that its `status` is the HTTP status, and that it
/// names nothing the request did.
async fn problem_of(response: Response) -> (StatusCode, String, Vec<u8>) {
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| value.as_bytes().to_vec()),
        Some(PROBLEM_JSON.as_bytes().to_vec()),
        "a {status} without a problem body"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], status.as_u16());
    let text = String::from_utf8_lossy(&bytes);
    for named in ["secret-room", "other.example", "nobody", "u/carol"] {
        assert!(!text.contains(named), "a problem body names {named}");
    }
    let anchor = body["type"]
        .as_str()
        .unwrap()
        .rsplit_once('#')
        .unwrap()
        .1
        .to_owned();
    (status, anchor, bytes.to_vec())
}

async fn send(router: &Router, request: Request<Body>) -> (StatusCode, String, Vec<u8>) {
    problem_of(router.clone().oneshot(request).await.unwrap()).await
}

/// Each refusal of the peer listener, with the type it names. Revert check: drop the fallback layer, and the unmatched
/// route, the wrong method and the unreadable JSON body go out without a problem body.
#[tokio::test]
async fn each_refusal_names_its_problem_type() {
    let (router, _p) = app();
    let cases: Vec<(Request<Body>, StatusCode, &str)> = vec![
        (
            post("/mimi/pl/keyMaterial/carol", b"\x01"),
            StatusCode::BAD_REQUEST,
            "malformed-request",
        ),
        (
            post(
                "/mimi/v1/keyMaterial/ingest?user=carol",
                b"not a key package",
            ),
            StatusCode::BAD_REQUEST,
            "material-not-accepted",
        ),
        (
            post(&format!("/mimi/pl/notify/{FOREIGN_ROOM}"), b""),
            StatusCode::FORBIDDEN,
            "not-the-rooms-hub",
        ),
        (
            post("/mimi/pl/requestConsent/other.example", &[9]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "wrong-operation",
        ),
        (
            post(&format!("/mimi/pl/groupInfo/{FOREIGN_ROOM}"), b""),
            StatusCode::NOT_FOUND,
            "room-not-hosted",
        ),
        (
            Request::builder()
                .method("POST")
                .uri("/mimi/pl/reportAbuse/r")
                .header(header::FROM, "mimi@other.example")
                .body(Body::empty())
                .unwrap(),
            StatusCode::FORBIDDEN,
            "not-authenticated",
        ),
        (
            Request::builder()
                .uri("/mimi/v1/nothing-here")
                .body(Body::empty())
                .unwrap(),
            StatusCode::NOT_FOUND,
            "not-found",
        ),
        (
            Request::builder()
                .uri("/mimi/pl/update/r")
                .body(Body::empty())
                .unwrap(),
            StatusCode::METHOD_NOT_ALLOWED,
            "method-not-allowed",
        ),
        (
            Request::builder()
                .method("POST")
                .uri("/mimi/v1/identifierQuery")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "malformed-request",
        ),
        (
            post("/mimi/v1/identifierQuery", br#"{"username":"nobody"}"#),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "http-error",
        ),
    ];
    for (request, status, anchor) in cases {
        let what = format!("{} {}", request.method(), request.uri());
        let (got_status, got_anchor, _) = send(&router, request).await;
        assert_eq!(
            (got_status, got_anchor.as_str()),
            (status, anchor),
            "PLANT-PROBLEM-TYPE: {what}"
        );
    }
}

/// A user not found and a route not found give the same bytes, so the problem body is no existence oracle (DIV-4).
#[tokio::test]
async fn a_user_not_found_reads_as_any_not_found() {
    let (router, _p) = app();
    let user = Request::builder()
        .method("POST")
        .uri("/mimi/v1/identifierQuery")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"username":"nobody"}"#))
        .unwrap();
    let (_, anchor, user_bytes) = send(&router, user).await;
    assert_eq!(anchor, "not-found");
    let route = Request::builder()
        .uri("/mimi/v1/nothing-here")
        .body(Body::empty())
        .unwrap();
    let (_, _, route_bytes) = send(&router, route).await;
    assert_eq!(user_bytes, route_bytes);
}

/// The other listeners: the provider-auth gate's refusal, the directory listener's 404, and the operator's.
#[tokio::test]
async fn the_gate_and_the_other_listeners_answer_problems_too() {
    let provider = Arc::new(Mutex::new(crate::Provider::in_memory(HUB).unwrap()));
    let gated = crate::provider_auth::with_provider_auth(
        crate::http::build_router(provider.clone()),
        Arc::new(crate::signature::PeerKeys::from_file(None)),
    );
    let (status, anchor, _) = send(&gated, post("/mimi/pl/update/r", b"")).await;
    assert_eq!(
        (status, anchor.as_str()),
        (StatusCode::FORBIDDEN, "not-authenticated")
    );

    let directory = crate::http::build_directory_router(provider.clone());
    let (status, anchor, _) = send(&directory, post("/mimi/pl/update/r", b"")).await;
    assert_eq!(
        (status, anchor.as_str()),
        (StatusCode::NOT_FOUND, "not-found")
    );

    let admin = crate::admin::build_admin_router(provider);
    let untrack = post(
        "/mimi/v1/untrackRoom?room=mimi://havenmessenger.com/r/secret-room",
        b"",
    );
    let (status, anchor, _) = send(&admin, untrack).await;
    assert_eq!(
        (status, anchor.as_str()),
        (StatusCode::NOT_FOUND, "not-found")
    );
}
