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
        .record_consent_decision(
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
                .extension(crate::peer::PeerCert(Some(
                    crate::peer::PeerIdentity::signed("a.example"),
                )))
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
    let unmet = RequiredCapabilitiesExtension::new(&[ExtensionType::from(0x0006)], &[], &[]);
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
    let unmet = RequiredCapabilitiesExtension::new(&[ExtensionType::from(0x0006)], &[], &[]);
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
                .extension(crate::peer::PeerCert(Some(
                    crate::peer::PeerIdentity::signed("a.example"),
                )))
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

/// One requester may ask for one target's KeyPackages only so often in an hour on the provider path, as on the client
/// lane: past it, 429 `key-material-rate-limited`, and another target is still answered. Revert check: skip the count,
/// and the request past the limit is answered.
#[tokio::test]
async fn a_requester_past_the_per_target_limit_is_told_to_wait() {
    let (router, p) = app();
    granted(&p);
    let status_for = |target: &'static str, path: &'static str| {
        let router = router.clone();
        async move {
            let request = KeyMaterialRequest::minimal(REQUESTER, target).unwrap();
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .extension(crate::peer::PeerCert(Some(
                            crate::peer::PeerIdentity::signed("a.example"),
                        )))
                        .uri(format!("/mimi/pl/keyMaterial/{path}"))
                        .body(Body::from(request.encode().unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&body).to_string())
        }
    };
    for _ in 0..crate::client_lane_relay::KEY_MATERIAL_PER_TARGET_PER_HOUR {
        assert_eq!(status_for(TARGET, "bob").await.0, StatusCode::OK);
    }
    let (status, body) = status_for(TARGET, "bob").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "PLANT-KM-PROVIDER-RATE: a request past the per-target limit was answered"
    );
    assert!(body.contains("key-material-rate-limited"), "{body}");
    assert_eq!(
        status_for("mimi://havenmessenger.com/u/carol", "carol")
            .await
            .0,
        StatusCode::OK
    );
}
