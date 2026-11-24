//! The attributes a record carries, the collector address rule and the startup line. These hold in every build;
//! the export itself is tested in `otlp_tests.rs`.

use std::time::{Duration, SystemTime};

use axum::http::Method;

use super::*;

/// Every key an inbound or outbound record may carry.
pub(crate) const ALLOWED_KEYS: [&str; 8] = [
    "http.request.method",
    "http.route",
    "http.response.status_code",
    "mimi.peer.provider",
    "mimi.problem",
    "mimi.endpoint",
    "error.type",
    "mimi.attempt",
];

#[test]
fn a_record_carries_only_the_listed_attributes() {
    let inbound = Inbound {
        method: &Method::from_bytes(b"SECRETVERB").unwrap(),
        route: Some("/mimi/pl/notify/:room_id"),
        status: 403,
        peer: Some("peer.example"),
        problem: Some("not-the-rooms-hub"),
        started: SystemTime::now(),
        duration: Duration::from_millis(3),
    };
    let attributes = inbound_attributes(&inbound);
    assert!(attributes.iter().all(|(key, _)| ALLOWED_KEYS.contains(key)));
    assert_eq!(
        attributes,
        vec![
            ("http.request.method", "OTHER".to_owned()),
            ("http.route", "/mimi/pl/notify/:room_id".to_owned()),
            ("http.response.status_code", "403".to_owned()),
            ("mimi.peer.provider", "peer.example".to_owned()),
            ("mimi.problem", "not-the-rooms-hub".to_owned()),
        ]
    );
    let unmatched = Inbound {
        route: None,
        peer: None,
        problem: None,
        ..inbound
    };
    assert_eq!(
        inbound_attributes(&unmatched)[1..],
        [
            ("http.route", "unmatched".to_owned()),
            ("http.response.status_code", "403".to_owned()),
            ("mimi.peer.provider", UNAUTHENTICATED.to_owned()),
        ]
    );

    let outbound = Outbound {
        peer: "other.example",
        endpoint: "notify",
        outcome: Err("timeout"),
        attempt: Some(3),
        started: SystemTime::now(),
        duration: Duration::from_millis(9),
    };
    let attributes = outbound_attributes(&outbound);
    assert!(attributes.iter().all(|(key, _)| ALLOWED_KEYS.contains(key)));
    assert!(attributes.contains(&("error.type", "timeout".to_owned())));
    assert!(attributes.contains(&("mimi.attempt", "3".to_owned())));
}

/// The collector is https, or http only to a loopback address. Revert check: accept any http host, and the
/// non-loopback http endpoints pass.
#[test]
fn the_collector_is_https_or_loopback_http() {
    for ok in [
        "https://otel.example:4318",
        "https://otel.example",
        "http://127.0.0.1:4318",
        "http://127.8.9.10:4318/",
        "http://[::1]:4318",
        "http://localhost:4318",
    ] {
        assert_eq!(check_endpoint(ok), Ok(()), "{ok}");
    }
    for refused in [
        "http://otel.example:4318",
        "http://203.0.113.5:4318",
        "http://[::ffff:7f00:1]:4318",
        "ftp://127.0.0.1",
        "127.0.0.1:4318",
        "https://user:pass@otel.example",
        "http://",
    ] {
        assert!(check_endpoint(refused).is_err(), "{refused}");
    }
}

#[cfg(not(feature = "otlp"))]
#[test]
fn a_build_without_otlp_says_so() {
    let (telemetry, line) = start(None).unwrap();
    assert!(!telemetry.is_on());
    assert_eq!(line, "otlp: off (not built)");
    let (telemetry, line) = start(Some("https://otel.example")).unwrap();
    assert!(!telemetry.is_on());
    assert!(line.starts_with("otlp: off (not built"));
}

#[cfg(feature = "otlp")]
#[tokio::test]
async fn a_build_with_otlp_is_off_until_a_collector_is_named() {
    let (telemetry, line) = start(None).unwrap();
    assert!(!telemetry.is_on());
    assert_eq!(line, "otlp: off");
    assert!(start(Some("http://otel.example:4318")).is_err());
    let (telemetry, line) = start(Some("http://127.0.0.1:9")).unwrap();
    assert!(telemetry.is_on());
    assert_eq!(line, "otlp: http://127.0.0.1:9");
}
