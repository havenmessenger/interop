//! The `/mimi/pl/*` routes against protocol-07: the media type of a body (§10.6), the consent answers (§5.7) and the
//! `identifierQuery/{domain}` path (§5.8).

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Request, StatusCode},
    response::Response,
    Router,
};
use mimi_core::consent::{ConsentEntry, ConsentOperation};
use mimi_core::protocol_wire::encode_consent_entry;
use tower::ServiceExt;

use super::tests::{app, real_mls_envelope_bytes};

const REQUESTER: &str = "mimi://mimi-b.havenmessenger.com/u/bob";
const TARGET: &str = "mimi://havenmessenger.com/u/alice";

async fn post(router: Router, uri: &str, body: Vec<u8>) -> Response {
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn entry(operation: ConsentOperation) -> Vec<u8> {
    encode_consent_entry(&ConsentEntry {
        operation,
        requester_uri: REQUESTER.into(),
        target_uri: TARGET.into(),
        room_uri: None,
        client_key_packages: Vec::new(),
        consent_extensions: Vec::new(),
    })
    .unwrap()
}

fn content_type(response: &Response) -> Option<String> {
    response
        .headers()
        .get(CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string())
}

#[tokio::test]
async fn a_wire_answer_with_a_body_is_labeled_with_the_protocol_media_type() {
    // submitMessage to a room nobody may send to still answers with a SubmitMessageResponse body.
    let (router, _p) = app();
    let request = mimi_core::protocol_wire::SubmitMessageRequest {
        protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
        app_message: real_mls_envelope_bytes(),
        sending_uri: mimi_core::protocol_wire::IdentifierUri(REQUESTER.into()),
    };
    let response = post(
        router,
        "/mimi/pl/submitMessage/mimi%3A%2F%2Fhavenmessenger.com%2Fr%2Fx",
        request.encode().unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        content_type(&response).as_deref(),
        Some("application/mimi-protocol")
    );
}

#[tokio::test]
async fn an_update_answer_is_labeled_with_the_protocol_media_type() {
    let (router, _p) = app();
    let response = post(
        router,
        "/mimi/pl/update/mimi%3A%2F%2Fhavenmessenger.com%2Fr%2Fx",
        vec![0],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        content_type(&response).as_deref(),
        Some("application/mimi-protocol")
    );
}

#[tokio::test]
async fn an_answer_with_no_body_or_an_error_description_is_not_labeled() {
    let (router, _p) = app();
    let bare = post(
        router.clone(),
        "/mimi/pl/requestConsent/a.example",
        entry(ConsentOperation::Request),
    )
    .await;
    assert_eq!(bare.status(), StatusCode::ACCEPTED);
    assert_eq!(content_type(&bare), None, "a bare status carries no type");
    let refused = post(router, "/mimi/pl/keyMaterial/x", vec![0xff]).await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_ne!(
        content_type(&refused).as_deref(),
        Some("application/mimi-protocol")
    );
}

#[tokio::test]
async fn the_directory_stays_json() {
    let (router, _p) = app();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/mimi-protocol-directory")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(content_type(&response).as_deref(), Some("application/json"));
}

#[tokio::test]
async fn request_consent_takes_request_and_cancel_and_answers_202() {
    for operation in [ConsentOperation::Request, ConsentOperation::Cancel] {
        let (router, _p) = app();
        let response = post(
            router,
            "/mimi/pl/requestConsent/havenmessenger.com",
            entry(operation),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
}

#[tokio::test]
async fn request_consent_refuses_grant_and_revoke_with_422() {
    for operation in [ConsentOperation::Grant, ConsentOperation::Revoke] {
        let (router, _p) = app();
        let response = post(
            router,
            "/mimi/pl/requestConsent/havenmessenger.com",
            entry(operation),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[tokio::test]
async fn update_consent_takes_grant_and_revoke_and_answers_202() {
    for operation in [ConsentOperation::Grant, ConsentOperation::Revoke] {
        let (router, _p) = app();
        let response = post(
            router,
            "/mimi/pl/updateConsent/mimi-b.havenmessenger.com",
            entry(operation),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
}

#[tokio::test]
async fn update_consent_refuses_request_and_cancel_with_422() {
    for operation in [ConsentOperation::Request, ConsentOperation::Cancel] {
        let (router, _p) = app();
        let response = post(
            router,
            "/mimi/pl/updateConsent/mimi-b.havenmessenger.com",
            entry(operation),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[tokio::test]
async fn the_422_depends_on_the_operation_byte_alone() {
    // Whether the users exist, whether the rest of the body decodes, and which route is asked do not change it.
    for body in [
        vec![2u8],
        vec![3, 0xff, 0xff],
        vec![7],
        entry(ConsentOperation::Grant),
    ] {
        let (router, _p) = app();
        let response = post(router, "/mimi/pl/requestConsent/a.example", body).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
    // An empty body names no operation: it is an entry that does not decode, answered as any other is.
    let (router, _p) = app();
    let response = post(router, "/mimi/pl/requestConsent/a.example", Vec::new()).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn identifier_query_answers_on_the_domain_path_and_on_the_older_one() {
    use mimi_core::protocol_wire::{IdentifierRequest, QueryElement, SearchIdentifierType};
    let query = |value: &str| {
        IdentifierRequest {
            query_elements: vec![QueryElement {
                search_type: SearchIdentifierType::Handle,
                qualifier: Vec::new(),
                search_value: value.as_bytes().to_vec(),
            }],
        }
        .encode()
        .unwrap()
    };
    for uri in [
        "/mimi/pl/identifierQuery/havenmessenger.com",
        "/mimi/pl/identifierQuery",
    ] {
        let (router, p) = app();
        p.lock().unwrap().enroll("alice").unwrap();
        // An enrolled handle is found (200) and anything else is the bare 404: a missing route would be 404 for both.
        assert_eq!(
            post(router.clone(), uri, query("alice")).await.status(),
            StatusCode::OK,
            "{uri}"
        );
        assert_eq!(
            post(router, uri, query("nobody")).await.status(),
            StatusCode::NOT_FOUND,
            "{uri}"
        );
    }
}
