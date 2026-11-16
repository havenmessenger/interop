//! The operator's routes: served on their own loopback listener, and not by the router peers reach.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

use super::*;
use crate::http::build_router;
use crate::Provider;

const ROOM: &str = "mimi://mimi.havenmessenger.com/r/x";
const ALICE: &str = "mimi://mimi.havenmessenger.com/u/alice";

const POLICY: &str = r#"{
    "base": {"fixed_membership": false, "parent_dependant": false, "discoverable": false},
    "roles": [{"role_index": 3, "role_name": "member", "capabilities": ["SendMessage"]}]
}"#;

fn provider() -> SharedProvider {
    Arc::new(Mutex::new(
        Provider::in_memory("mimi.havenmessenger.com").unwrap(),
    ))
}

async fn send(router: Router, method: Method, uri: &str, body: Option<&str>) -> StatusCode {
    let mut request = Request::builder().method(method).uri(uri);
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    router
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_owned())))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// The operator's three routes, each with a request that would change something.
fn operator_requests() -> [(String, Option<&'static str>); 3] {
    [
        (format!("/mimi/v1/roomPolicy?room={ROOM}"), Some(POLICY)),
        (
            format!("/mimi/v1/memberRole?room={ROOM}&member={ALICE}&role=3"),
            None,
        ),
        (
            format!("/mimi/v1/addParticipant?room={ROOM}&member={ALICE}"),
            None,
        ),
    ]
}

/// The router peers reach does not have the operator's routes: each is a 404, and the room is left as it was. Revert
/// check: mount `roomPolicy` on `build_router` again, and it answers 201.
#[tokio::test]
async fn the_peer_router_does_not_mount_the_operator_routes() {
    let shared = provider();
    for (uri, body) in operator_requests() {
        assert_eq!(
            send(build_router(shared.clone()), Method::POST, &uri, body).await,
            StatusCode::NOT_FOUND,
            "PLANT-ADMIN-PEER-ROUTE: a peer reached {uri}"
        );
    }
    assert!(
        shared.lock().unwrap().room_policy(ROOM).unwrap().is_none(),
        "no policy was stored"
    );
}

/// The operator's listener sets a policy, a role and a participant in a room this hub hosts.
#[tokio::test]
async fn the_operator_router_changes_a_hosted_room() {
    let shared = provider();
    for (uri, body) in operator_requests() {
        assert_eq!(
            send(build_admin_router(shared.clone()), Method::POST, &uri, body).await,
            StatusCode::CREATED,
            "{uri}"
        );
    }
    assert!(shared.lock().unwrap().room_policy(ROOM).unwrap().is_some());
}

/// A room another hub hosts is still refused on the operator's listener.
#[tokio::test]
async fn the_operator_router_refuses_a_room_this_hub_does_not_host() {
    let foreign = "mimi://other.example/r/x";
    assert_eq!(
        send(
            build_admin_router(provider()),
            Method::POST,
            &format!("/mimi/v1/roomPolicy?room={foreign}"),
            Some(POLICY),
        )
        .await,
        StatusCode::BAD_REQUEST
    );
}

/// The operator's listener serves its three routes and nothing a peer asks for.
#[tokio::test]
async fn the_operator_router_mounts_nothing_else() {
    for (method, uri) in [
        (Method::GET, "/.well-known/mimi-protocol-directory"),
        (Method::GET, "/mimi/v1/keyMaterial?user=alice"),
        (Method::POST, "/mimi/v1/authorizeSender?room=x&sender=y"),
        (Method::POST, "/mimi/pl/update/x"),
        (Method::POST, "/mimi/pl/notify/x"),
    ] {
        assert_eq!(
            send(build_admin_router(provider()), method.clone(), uri, None).await,
            StatusCode::NOT_FOUND,
            "{method} {uri} reached something"
        );
    }
}

/// Loopback addresses, IPv4 and IPv6, are taken.
#[test]
fn a_loopback_address_is_taken() {
    for value in ["127.0.0.1:8445", "127.8.9.10:8445", "[::1]:8445"] {
        assert_eq!(
            admin_bind_addr(value).unwrap(),
            value.parse::<SocketAddr>().unwrap()
        );
    }
}

/// Anything that is not a loopback ip:port is refused: every interface, a LAN or public address, a hostname, and a
/// value that is not an address. Revert check: take any address that parses, and `0.0.0.0` is accepted.
#[test]
fn an_address_other_hosts_can_reach_is_refused() {
    for value in [
        "0.0.0.0:8445",
        "[::]:8445",
        "198.51.100.5:8445",
        "192.168.1.20:8445",
        "203.0.113.7:8445",
        "[fe80::1]:8445",
        "localhost:8445",
        "127.0.0.1",
        "",
    ] {
        assert!(
            admin_bind_addr(value).is_err(),
            "PLANT-ADMIN-LOOPBACK: {value:?} was taken"
        );
    }
}
