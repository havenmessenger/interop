//! The activity line holds the method, the route template and the status, and nothing a peer chose.

use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{Method, Request},
};
use tower::ServiceExt;

use super::*;
use crate::{http::build_router, Provider};

fn app() -> (Router, Arc<Mutex<Provider>>) {
    let provider = Arc::new(Mutex::new(
        Provider::in_memory("havenmessenger.com").unwrap(),
    ));
    (build_router(provider.clone()), provider)
}

fn collecting() -> (ActivitySink, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let lines = lines.clone();
        Arc::new(move |line: String| lines.lock().unwrap().push(line)) as ActivitySink
    };
    (sink, lines)
}

async fn send(router: Router, method: &str, uri: &str) -> u16 {
    router
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(&b"body bytes the log must not carry"[..]))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn a_request_leaves_one_line_with_the_route_template_and_no_path() {
    let (router, _provider) = app();
    let (sink, lines) = collecting();
    let router = with_activity_log(router, true, sink);
    let status = send(router, "POST", "/mimi/pl/update/room-chosen-by-the-peer").await;
    let lines = lines.lock().unwrap();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(
        lines[0],
        format!("[mimi-activity] method=POST route=/mimi/pl/update/:room_id status={status}")
    );
    assert!(!lines[0].contains("room-chosen-by-the-peer"));
}

#[tokio::test]
async fn a_request_no_route_matched_reads_unmatched_and_keeps_its_path_out() {
    let (router, _provider) = app();
    let (sink, lines) = collecting();
    let router = with_activity_log(router, true, sink);
    let status = send(router, "GET", "/nothing/secret-looking-segment").await;
    assert_eq!(status, 404);
    let lines = lines.lock().unwrap();
    assert_eq!(
        lines.as_slice(),
        ["[mimi-activity] method=GET route=unmatched status=404"]
    );
}

#[tokio::test]
async fn a_query_string_does_not_reach_the_line() {
    let (router, _provider) = app();
    let (sink, lines) = collecting();
    let router = with_activity_log(router, true, sink);
    send(
        router,
        "GET",
        "/.well-known/mimi-protocol-directory?user=alice&token=abc123",
    )
    .await;
    let lines = lines.lock().unwrap();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("route=/.well-known/mimi-protocol-directory "));
    for leaked in ["alice", "abc123", "token", "?"] {
        assert!(!lines[0].contains(leaked), "{} leaked {leaked}", lines[0]);
    }
}

#[tokio::test]
async fn nothing_is_logged_unless_the_setting_is_one() {
    for setting in [
        None,
        Some(""),
        Some("0"),
        Some("true"),
        Some("yes"),
        Some(" 1"),
    ] {
        let (router, _provider) = app();
        let (sink, lines) = collecting();
        let router = with_activity_log(router, enabled(setting), sink);
        send(router, "GET", "/.well-known/mimi-protocol-directory").await;
        assert!(lines.lock().unwrap().is_empty(), "{setting:?}");
    }
    let (router, _provider) = app();
    let (sink, lines) = collecting();
    let router = with_activity_log(router, enabled(Some("1")), sink);
    send(router, "GET", "/.well-known/mimi-protocol-directory").await;
    assert_eq!(lines.lock().unwrap().len(), 1);
}

#[test]
fn a_method_outside_the_usual_set_reads_other() {
    let strange = Method::from_bytes(b"EVIL-METHOD").unwrap();
    assert_eq!(
        activity_line(&strange, Some("/x"), 200),
        "[mimi-activity] method=OTHER route=/x status=200"
    );
    assert_eq!(
        activity_line(&Method::DELETE, None, 405),
        "[mimi-activity] method=DELETE route=unmatched status=405"
    );
}
