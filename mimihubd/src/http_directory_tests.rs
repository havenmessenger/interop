//! The directory-only router: one GET, and nothing else mounted.

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

use crate::http::build_directory_router;
use crate::Provider;

fn router() -> Router {
    build_directory_router(Arc::new(Mutex::new(
        Provider::in_memory("mimi.havenmessenger.com").unwrap(),
    )))
}

async fn send(method: Method, uri: &str) -> axum::response::Response {
    router()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(vec![1u8]))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn the_directory_is_served_as_json_without_a_client_certificate() {
    let response = send(Method::GET, "/.well-known/mimi-protocol-directory").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(document["provider"], "mimi.havenmessenger.com");
}

#[tokio::test]
async fn nothing_but_the_directory_is_mounted() {
    for uri in [
        "/",
        "/mimi/v1/keyMaterial?user=alice",
        "/mimi/v1/notify?room=x",
        "/mimi/v1/roomPolicy?room=x",
        "/mimi/pl/notify/x",
        "/mimi/pl/update/x",
        "/mimi/pl/keyMaterial/x",
        "/.well-known/other",
    ] {
        for method in [Method::GET, Method::POST] {
            let response = send(method.clone(), uri).await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{method} {uri} reached something"
            );
        }
    }
}

#[tokio::test]
async fn the_directory_answers_a_get_and_no_other_method() {
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
        let response = send(method.clone(), "/.well-known/mimi-protocol-directory").await;
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}"
        );
    }
}
