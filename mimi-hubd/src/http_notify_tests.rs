//! `notify` against protocol-07 §5.5: a provider that receives `/notify/{roomId}` verifies that the source provider the
//! transport authenticated is the hub of that room, and otherwise rejects the request without processing or storing
//! anything it carries. The same holds on the JSON lane, and `From` (§4.1) is checked where a request sends one.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Extension, Router,
};
use mimi_core::protocol_wire::FanoutMessage;
use tower::ServiceExt;

use super::tests::{app, real_mls_envelope_bytes};
use crate::http::SharedProvider;
use crate::peer::{PeerCert, PeerIdentity};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};

const ROOM: &str = "mimi://hub.example/r/clubhouse";

fn encoded(room: &str) -> String {
    room.replace(':', "%3A").replace('/', "%2F")
}

/// A peer whose certificate carries these DNS names (none: a certificate with only a common name).
fn peer(names: &[&str], common_name: &str) -> PeerCert {
    let (ca, _ca_pem) = make_ca();
    let (cert_pem, _key) = issue(
        &ca,
        names.iter().map(|n| n.to_string()).collect(),
        common_name,
    );
    let chain = certs_from_pem(cert_pem.as_bytes()).unwrap();
    PeerCert(Some(PeerIdentity::new(chain[0].clone().into_owned())))
}

/// One fanout body for the whole run: a fresh MLS message each call would differ in every byte, and these rows ask
/// whether a particular body reached the store.
fn body() -> Vec<u8> {
    static BODY: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BODY.get_or_init(|| {
        FanoutMessage {
            protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
            timestamp: 1,
            message_and_tail: real_mls_envelope_bytes(),
        }
        .encode()
        .unwrap()
    })
    .clone()
}

async fn notify(
    router: Router,
    room: &str,
    peer: Option<PeerCert>,
    from: Option<&str>,
) -> StatusCode {
    let router = match peer {
        Some(peer) => router.layer(Extension(peer)),
        None => router,
    };
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/mimi/pl/notify/{}", encoded(room)));
    if let Some(from) = from {
        request = request.header("from", from);
    }
    router
        .oneshot(request.body(Body::from(body())).unwrap())
        .await
        .unwrap()
        .status()
}

/// True when no fanout body has reached the store.
fn nothing_was_stored(p: &SharedProvider) -> bool {
    p.lock().unwrap().store.notify_seen_count() == 0
}

#[tokio::test]
async fn the_hub_of_the_room_is_accepted_and_a_duplicate_is_still_201() {
    let (router, p) = app();
    let hub = peer(&["hub.example"], "hub");
    assert_eq!(
        notify(router.clone(), ROOM, Some(hub.clone()), None).await,
        StatusCode::CREATED
    );
    assert_eq!(
        notify(router, ROOM, Some(hub), None).await,
        StatusCode::CREATED
    );
    assert!(!nothing_was_stored(&p));
}

#[tokio::test]
async fn another_provider_is_refused_and_nothing_is_stored() {
    let (router, p) = app();
    let other = peer(&["other.example"], "other");
    assert_eq!(
        notify(router, ROOM, Some(other), None).await,
        StatusCode::FORBIDDEN
    );
    assert!(nothing_was_stored(&p));
}

#[tokio::test]
async fn a_connection_with_no_certificate_is_refused() {
    let (router, p) = app();
    assert_eq!(
        notify(router.clone(), ROOM, None, None).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        notify(router, ROOM, Some(PeerCert(None)), None).await,
        StatusCode::FORBIDDEN
    );
    assert!(nothing_was_stored(&p));
}

#[tokio::test]
async fn the_common_name_does_not_name_a_provider() {
    let (router, p) = app();
    let cn_only = peer(&[], "hub.example");
    assert_eq!(
        notify(router, ROOM, Some(cn_only), None).await,
        StatusCode::FORBIDDEN
    );
    assert!(nothing_was_stored(&p));
}

#[tokio::test]
async fn a_wildcard_name_covers_one_label_only() {
    let wildcard = peer(&["*.provider.example"], "wild");
    let (router, _p) = app();
    assert_eq!(
        notify(
            router.clone(),
            "mimi://mimi.provider.example/r/x",
            Some(wildcard.clone()),
            None
        )
        .await,
        StatusCode::CREATED
    );
    for room in [
        "mimi://a.mimi.provider.example/r/x",
        "mimi://provider.example/r/x",
    ] {
        assert_eq!(
            notify(router.clone(), room, Some(wildcard.clone()), None).await,
            StatusCode::FORBIDDEN,
            "{room}"
        );
    }
}

#[tokio::test]
async fn the_room_authority_is_compared_without_case_or_port() {
    let hub = peer(&["hub.example"], "hub");
    for room in ["mimi://HUB.example/r/x", "mimi://hub.example:8443/r/x"] {
        let (router, _p) = app();
        assert_eq!(
            notify(router, room, Some(hub.clone()), None).await,
            StatusCode::CREATED,
            "{room}"
        );
    }
}

#[tokio::test]
async fn a_path_that_is_not_a_room_is_a_bad_request() {
    let hub = peer(&["hub.example"], "hub");
    for not_a_room in [
        "mimi://hub.example/u/alice",
        "mimi://hub.example",
        "mimi://user@hub.example/r/x",
        "https://hub.example/r/x",
        "x",
    ] {
        let (router, p) = app();
        assert_eq!(
            notify(router, not_a_room, Some(hub.clone()), None).await,
            StatusCode::BAD_REQUEST,
            "{not_a_room}"
        );
        assert!(nothing_was_stored(&p));
    }
}

#[tokio::test]
async fn no_route_lets_a_peer_that_is_not_the_hub_record_a_notify() {
    // Every route the router has that could end in `submit_notify`: the wire route, the JSON route with a room, the
    // JSON route without one, and the room-less wire path this hub used to serve.
    let other = peer(&["other.example"], "other");
    let room = encoded(ROOM);
    let attempts = [
        format!("/mimi/pl/notify/{room}"),
        format!("/mimi/v1/notify?room={room}"),
        "/mimi/v1/notify".to_string(),
        "/mimi/pl/notify".to_string(),
    ];
    for uri in attempts {
        let (router, p) = app();
        let status = router
            .layer(Extension(other.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .body(Body::from(body()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert!(
            matches!(
                status,
                StatusCode::FORBIDDEN
                    | StatusCode::BAD_REQUEST
                    | StatusCode::NOT_FOUND
                    | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{uri} answered {status}"
        );
        assert!(nothing_was_stored(&p), "{uri} stored the body");
    }
}

#[tokio::test]
async fn the_json_lane_asks_the_same_question() {
    let hub = peer(&["hub.example"], "hub");
    let other = peer(&["other.example"], "other");
    let room = encoded(ROOM);
    let post = |router: Router, peer: PeerCert, uri: String| async move {
        router
            .layer(Extension(peer))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::from("fanout-body"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    };
    let (router, _p) = app();
    assert_eq!(
        post(
            router.clone(),
            hub.clone(),
            format!("/mimi/v1/notify?room={room}")
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(
        post(
            router.clone(),
            other,
            format!("/mimi/v1/notify?room={room}")
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(router, hub, "/mimi/v1/notify".to_string()).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn an_undecodable_body_from_the_hub_is_a_bad_request_and_from_anyone_else_a_refusal() {
    let hub = peer(&["hub.example"], "hub");
    let other = peer(&["other.example"], "other");
    let send = |peer: PeerCert| {
        let (router, _p) = app();
        async move {
            router
                .layer(Extension(peer))
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/mimi/pl/notify/{}", encoded(ROOM)))
                        .body(Body::from(&b"not a FanoutMessage"[..]))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(send(hub).await, StatusCode::BAD_REQUEST);
    assert_eq!(send(other).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn from_is_checked_where_it_is_sent_and_never_required() {
    let hub = peer(&["hub.example"], "hub");
    let (router, _p) = app();
    let status = |from: Option<&'static str>, peer: Option<PeerCert>| {
        notify(router.clone(), ROOM, peer, from)
    };
    assert_eq!(
        status(None, Some(hub.clone())).await,
        StatusCode::CREATED,
        "From is not required"
    );
    assert_eq!(
        status(Some("mimi@hub.example"), Some(hub.clone())).await,
        StatusCode::CREATED
    );
    assert_eq!(
        status(Some("mimi@HUB.example"), Some(hub.clone())).await,
        StatusCode::CREATED
    );
    for refused in [
        "mimi@other.example",
        "alice@hub.example",
        "Hub <mimi@hub.example>",
        "hub.example",
        "mimi@",
    ] {
        assert_eq!(
            status(Some(refused), Some(hub.clone())).await,
            StatusCode::FORBIDDEN,
            "{refused}"
        );
    }
    assert_eq!(
        status(Some("mimi@hub.example"), None).await,
        StatusCode::FORBIDDEN,
        "a From with no certificate to check it against"
    );
}

#[tokio::test]
async fn from_is_checked_on_every_wire_route() {
    let hub = peer(&["hub.example"], "hub");
    for uri in [
        "/mimi/pl/update/x",
        "/mimi/pl/submitMessage/x",
        "/mimi/pl/keyMaterial/x",
        "/mimi/pl/requestConsent/x",
        "/mimi/pl/updateConsent/x",
        "/mimi/pl/identifierQuery",
        "/mimi/pl/identifierQuery/x",
        "/mimi/pl/reportAbuse/x",
    ] {
        let (router, _p) = app();
        let status = router
            .layer(Extension(hub.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("from", "mimi@other.example")
                    .body(Body::from(vec![1u8]))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
    }
}

/// The whole path: a real mutually authenticated connection, the acceptor handing the certificate to the handler.
#[tokio::test]
async fn over_a_real_connection_the_certificate_the_peer_presented_decides() {
    use crate::peer::PeerIdentityAcceptor;
    use crate::tls::{build_mtls_server_config, certs_from_pem, key_from_pem};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (ca, ca_pem) = make_ca();
    let (server_cert, server_key) = issue(&ca, vec!["localhost".into()], "server");
    let server_config = build_mtls_server_config(
        server_cert.as_bytes(),
        server_key.as_bytes(),
        ca_pem.as_bytes(),
    )
    .unwrap();
    let (router, p) = app();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls)
            .map(PeerIdentityAcceptor::new)
            .serve(router.into_make_service())
            .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let post = |names: Vec<String>, from: Option<&'static str>| {
        let (cert, key) = issue(&ca, names, "peer");
        let ca_pem = ca_pem.clone();
        async move {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut roots = rustls::RootCertStore::empty();
            for root in certs_from_pem(ca_pem.as_bytes()).unwrap() {
                roots.add(root).unwrap();
            }
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    certs_from_pem(cert.as_bytes()).unwrap(),
                    key_from_pem(key.as_bytes()).unwrap(),
                )
                .unwrap();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let mut stream = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    tcp,
                )
                .await
                .unwrap();
            let body = body();
            let from_line = from.map(|f| format!("From: {f}\r\n")).unwrap_or_default();
            let head = format!(
                "POST /mimi/pl/notify/{} HTTP/1.1\r\nHost: localhost\r\n{from_line}Content-Length: {}\r\nConnection: close\r\n\r\n",
                encoded(ROOM),
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            let mut answer = Vec::new();
            let _ = stream.read_to_end(&mut answer).await;
            String::from_utf8_lossy(&answer)
                .lines()
                .next()
                .unwrap_or("")
                .to_string()
        }
    };

    let refused = post(vec!["other.example".into()], None).await;
    assert!(refused.contains("403"), "{refused}");
    assert!(nothing_was_stored(&p));
    let mislabeled = post(vec!["hub.example".into()], Some("mimi@other.example")).await;
    assert!(mislabeled.contains("403"), "{mislabeled}");
    assert!(nothing_was_stored(&p));
    let accepted = post(vec!["hub.example".into()], Some("mimi@hub.example")).await;
    assert!(accepted.contains("201"), "{accepted}");
    assert!(!nothing_was_stored(&p));
}
