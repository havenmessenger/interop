//! The gate: no route but the directory answers a request with neither a client certificate nor a valid signature, and a
//! signed request reaches its route as the signed provider.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::*;
use crate::http::build_router;
use crate::Provider;

/// The RFC 9421 B.1.4 Ed25519 test key: private seed and public key.
const SEED: &str = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU";
const PUBLIC: &str = "JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";

fn gated(keys: PeerKeys) -> Router {
    let provider = Arc::new(Mutex::new(
        Provider::in_memory("havenmessenger.com").unwrap(),
    ));
    with_provider_auth(build_router(provider), Arc::new(keys))
}

/// A key file of its own for each test (`test`), so tests running at once never share or remove another's file.
fn key_file(test: &str) -> (PeerKeys, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("mimi-gate-keys-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("peer_keys.json");
    std::fs::write(&path, format!(r#"{{"s1._mimi.a.example": "{PUBLIC}"}}"#)).unwrap();
    (PeerKeys::from_file(Some(path)), dir)
}

/// Every route this hub serves, with a concrete path and its method.
const ROUTES: &[(&str, &str)] = &[
    ("GET", "/mimi/v1/keyMaterial"),
    ("POST", "/mimi/v1/keyMaterial/ingest"),
    ("POST", "/mimi/v1/notify"),
    ("POST", "/mimi/v1/welcome/ingest"),
    ("GET", "/mimi/v1/welcome"),
    ("POST", "/mimi/v1/submitMessage"),
    ("GET", "/mimi/v1/message"),
    ("POST", "/mimi/v1/identifierQuery"),
    ("POST", "/mimi/v1/requestConsent"),
    ("POST", "/mimi/v1/updateConsent"),
    ("POST", "/mimi/v1/authorizeSender"),
    ("POST", "/mimi/pl/submitMessage/room"),
    ("POST", "/mimi/pl/requestConsent/a.example"),
    ("POST", "/mimi/pl/updateConsent/a.example"),
    ("POST", "/mimi/pl/keyMaterial/user"),
    ("POST", "/mimi/pl/notify/room"),
    ("POST", "/mimi/pl/identifierQuery"),
    ("POST", "/mimi/pl/identifierQuery/havenmessenger.com"),
    ("POST", "/mimi/pl/reportAbuse/room"),
    ("POST", "/mimi/pl/update/room"),
];

#[tokio::test]
async fn every_route_but_the_directory_refuses_a_request_with_no_proof() {
    let (keys, dir) = key_file("routes");
    let router = gated(keys);
    for (method, path) in ROUTES {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(*method)
                    .uri(format!("https://mimi.havenmessenger.com{path}"))
                    .header("from", "mimi@a.example")
                    .body(Body::from(vec![1, 0, 0, 0]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(
            response.headers().get(axum::http::header::SERVER).unwrap(),
            crate::http::SERVER,
            "{method} {path}"
        );
    }
    let directory = router
        .oneshot(
            Request::builder()
                .uri("https://mimi.havenmessenger.com/.well-known/mimi-protocol-directory")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(directory.status(), StatusCode::OK);
    std::fs::remove_dir_all(dir).ok();
}

fn signed_request(path: &str, body: Vec<u8>, from: &str) -> Request<Body> {
    let uri = format!("https://mimi.havenmessenger.com{path}");
    let created = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body)));
    let params = format!(
        r#"("@method" "@target-uri" "content-digest" "from");created={created};keyid="s1";tag="mimi""#
    );
    let base = format!(
        "\"@method\": POST\n\"@target-uri\": {uri}\n\"content-digest\": {digest}\n\"from\": {from}\n\"@signature-params\": {params}"
    );
    let seed = URL_SAFE_NO_PAD.decode(SEED).unwrap();
    let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let signature = STANDARD.encode(key.sign(base.as_bytes()).as_ref());
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("from", from)
        .header("content-digest", digest)
        .header("signature-input", format!("mimi={params}"))
        .header("signature", format!("mimi=:{signature}:"))
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn a_signed_request_reaches_its_route() {
    use mimi_core::protocol_wire::{IdentifierRequest, QueryElement, SearchIdentifierType};
    let query = IdentifierRequest {
        query_elements: vec![QueryElement {
            search_type: SearchIdentifierType::Nick,
            qualifier: Vec::new(),
            search_value: b"nobody".to_vec(),
        }],
    }
    .encode()
    .unwrap();
    let (keys, dir) = key_file("signed");
    let router = gated(keys);
    let reached = router
        .clone()
        .oneshot(signed_request(
            "/mimi/pl/identifierQuery",
            query.clone(),
            "mimi@a.example",
        ))
        .await
        .unwrap();
    assert_eq!(reached.status(), StatusCode::OK);
    // The same signature claiming another provider is refused: no key is published for it here.
    let other = router
        .oneshot(signed_request(
            "/mimi/pl/identifierQuery",
            query,
            "mimi@c.example",
        ))
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::FORBIDDEN);
    std::fs::remove_dir_all(dir).ok();
}
