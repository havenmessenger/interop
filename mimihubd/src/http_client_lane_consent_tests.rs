//! The client lane's consent routes, end to end through the lane's gate: a user decides, asks, lists the requests made
//! of them and the grants they hold, and opts out.

use axum::http::StatusCode;
use mimi_core::consent::KeyPackageAccess;

use super::client_lane_tests::{call, lane, signed};

const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const ZED: &str = "mimi://other.example/u/zed";

/// Bob grants Alice through his lane, and her KeyPackage access opens; Alice asks Bob, and Bob lists her request; Alice
/// lists the grant she holds; Bob opts out, and the grant is gone. Revert check: leave the routes off the lane, and
/// the first call is not found.
#[tokio::test]
async fn a_user_decides_asks_lists_and_opts_out_through_the_lane() {
    let l = lane("consent-routes");
    let grant = format!(r#"{{"requester":"{ALICE}","decision":"grant"}}"#);
    let (status, body) = call(&l.router, signed(&l.key, "consent", BOB, &grant)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PLANT-LANE-CONSENT-ROUTES: the consent route is not on the lane: {body}"
    );
    assert_eq!(body["notified"], false, "Alice is here: nothing is sent");
    let access = |requester: &str| {
        l.provider
            .lock()
            .unwrap()
            .keypackage_access(requester, BOB, None)
            .unwrap()
    };
    assert_eq!(access(ALICE), KeyPackageAccess::Allowed);

    // A grant to a user of another provider stands though this hub has no outbound client to tell it.
    let grant_zed = format!(r#"{{"requester":"{ZED}","decision":"grant"}}"#);
    let (status, body) = call(&l.router, signed(&l.key, "consent", BOB, &grant_zed)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["notified"], false);
    assert_eq!(access(ZED), KeyPackageAccess::Allowed);

    let provider = r#"{"provider":"other.example","decision":"grant"}"#;
    let (status, _) = call(&l.router, signed(&l.key, "consent", BOB, provider)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no provider grants by default"
    );
    for bad in [
        format!(r#"{{"requester":"{ALICE}","decision":"maybe"}}"#),
        format!(r#"{{"requester":"{ALICE}","provider":"other.example","decision":"grant"}}"#),
        r#"{"decision":"grant"}"#.to_string(),
    ] {
        let (status, _) = call(&l.router, signed(&l.key, "consent", BOB, &bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }

    let ask = format!(r#"{{"target":"{BOB}"}}"#);
    let (status, body) = call(&l.router, signed(&l.key, "requestConsent", ALICE, &ask)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["delivered"], true, "Bob is here: it is recorded");
    // Bob already granted Alice, so her request does not reopen it as pending.
    let (status, body) = call(&l.router, signed(&l.key, "consentRequests", BOB, "{}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["requests"].as_array().unwrap().len(), 0, "{body}");

    let ask_alice = format!(r#"{{"target":"{ALICE}"}}"#);
    let (status, _) = call(&l.router, signed(&l.key, "requestConsent", BOB, &ask_alice)).await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = call(&l.router, signed(&l.key, "consentRequests", ALICE, "{}")).await;
    let requests = body["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1, "{body}");
    assert_eq!(requests[0]["requester"], BOB);
    let after = format!(r#"{{"after":{}}}"#, requests[0]["seq"]);
    let (_, body) = call(&l.router, signed(&l.key, "consentRequests", ALICE, &after)).await;
    assert_eq!(
        body["requests"].as_array().unwrap().len(),
        0,
        "paged past it"
    );

    let (status, body) = call(&l.router, signed(&l.key, "consentReceived", ALICE, "{}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["grants"][0]["target"], BOB, "{body}");

    let (status, body) = call(&l.router, signed(&l.key, "optOut", BOB, "{}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["count"], 0, "Bob published no KeyPackage");
    assert_eq!(body["cleared"], 2, "the grants to Alice and Zed");
    assert_eq!(access(ALICE), KeyPackageAccess::NoConsent);
}
