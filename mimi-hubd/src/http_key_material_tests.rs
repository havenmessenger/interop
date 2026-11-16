//! keyMaterial on the wire lane serves a KeyPackage that meets the request's required capabilities, and answers
//! noCompatibleMaterial (taking nothing) when the user has KeyPackages and none meets it.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use mimi_core::consent::{ConsentEntry, ConsentOperation};
use mimi_core::protocol_wire::{KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode};
use openmls::prelude::{ExtensionType, RequiredCapabilitiesExtension};
use tower::ServiceExt;

use super::now_unix;
use super::tests::{app, real_keypackage};
use crate::http::SharedProvider;

const REQUESTER: &str = "mimi://a.example/u/alice";
const TARGET: &str = "mimi://havenmessenger.com/u/bob";

fn granted(p: &SharedProvider) {
    p.lock()
        .unwrap()
        .process_update_consent(
            &ConsentEntry {
                operation: ConsentOperation::Grant,
                requester_uri: REQUESTER.into(),
                target_uri: TARGET.into(),
                room_uri: None,
                client_key_packages: Vec::new(),
                consent_extensions: Vec::new(),
            },
            now_unix(),
        )
        .unwrap();
}

async fn ask(router: Router, required: RequiredCapabilitiesExtension) -> KeyMaterialResponse {
    let mut request = KeyMaterialRequest::minimal(REQUESTER, TARGET).unwrap();
    request.required_capabilities = required;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mimi/pl/keyMaterial/bob")
                .body(Body::from(request.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    KeyMaterialResponse::decode(&bytes, &[0x0001]).unwrap()
}

#[tokio::test]
async fn a_requirement_no_key_package_meets_is_no_compatible_material_and_takes_nothing() {
    let (router, p) = app();
    granted(&p);
    p.lock()
        .unwrap()
        .add_key_package("bob", &real_keypackage(), now_unix() + 100)
        .unwrap();
    let unmet = RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0x0006)], &[], &[]);
    let answer = ask(router.clone(), unmet).await;
    // On the wire: userStatus noCompatibleMaterial, no clients (the decoder reads that shape as `Clients`).
    assert!(
        matches!(
            &answer,
            KeyMaterialResponse::Clients {
                user_status: KeyMaterialUserCode::NoCompatibleMaterial,
                clients,
                ..
            } if clients.is_empty()
        ),
        "{answer:?}"
    );
    // Nothing was taken: a request with no requirement still gets the KeyPackage.
    let answer = ask(router, RequiredCapabilitiesExtension::default()).await;
    assert!(
        matches!(answer, KeyMaterialResponse::Success { .. }),
        "{answer:?}"
    );
}

#[tokio::test]
async fn a_user_with_no_key_packages_is_still_exhausted() {
    let (router, p) = app();
    granted(&p);
    let unmet = RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(0x0006)], &[], &[]);
    let answer = ask(router, unmet).await;
    assert!(
        matches!(answer, KeyMaterialResponse::Exhausted { .. }),
        "{answer:?}"
    );
}

/// A request that spells the target another way (scheme and host case, a percent-encoded letter) is the same user:
/// the consent grant is found and the KeyPackage served.
#[tokio::test]
async fn another_spelling_of_the_target_finds_its_consent() {
    let (router, p) = app();
    granted(&p);
    p.lock()
        .unwrap()
        .add_key_package("bob", &real_keypackage(), now_unix() + 100)
        .unwrap();
    let request =
        KeyMaterialRequest::minimal(REQUESTER, "MIMI://HavenMessenger.com/u/%62ob").unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mimi/pl/keyMaterial/bob")
                .body(Body::from(request.encode().unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let answer = KeyMaterialResponse::decode(&bytes, &[0x0001]).unwrap();
    assert!(
        matches!(answer, KeyMaterialResponse::Success { .. }),
        "{answer:?}"
    );
}
