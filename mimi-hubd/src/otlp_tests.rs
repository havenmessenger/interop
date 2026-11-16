//! Export against an in-process collector: requests that name rooms, users and queries reach the hub through the
//! provider-auth gate, and what arrives at the collector is per peer, with only the listed attributes, and holds none of
//! what the requests named.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, Request, StatusCode, Uri},
    routing::post,
    Router,
};
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value::Value, KeyValue};
use opentelemetry_proto::tonic::metrics::v1::{metric::Data, number_data_point};
use prost::Message;
use tower::ServiceExt;

use crate::peer::{PeerCert, PeerIdentity};
use crate::telemetry::{with_telemetry, Outbound, Telemetry};

type Received = Arc<Mutex<Vec<(String, Bytes)>>>;

/// A collector on a loopback port that keeps every body it is sent.
async fn collector() -> (String, Received) {
    let received: Received = Arc::default();
    async fn take(State(received): State<Received>, uri: Uri, body: Bytes) -> StatusCode {
        received.lock().unwrap().push((uri.path().to_owned(), body));
        StatusCode::OK
    }
    let app = Router::new()
        .route("/v1/traces", post(take))
        .route("/v1/metrics", post(take))
        .with_state(received.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), received)
}

fn string_of(attributes: &[KeyValue], key: &str) -> Option<String> {
    attributes.iter().find(|kv| kv.key == key).and_then(|kv| {
        match kv.value.as_ref()?.value.as_ref()? {
            Value::StringValue(text) => Some(text.clone()),
            _ => None,
        }
    })
}

/// Revert checks: put the request's path in the route attribute, and the room in the path reaches the collector; leave
/// the authenticated peer off the gate's answer, and the counts per peer are wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_are_exported_per_peer_with_nothing_they_named() {
    let (endpoint, received) = collector().await;
    let telemetry = Telemetry::for_test(&endpoint).unwrap();
    let provider = Arc::new(Mutex::new(
        crate::Provider::in_memory("hub.example").unwrap(),
    ));
    let router = with_telemetry(
        crate::provider_auth::with_provider_auth(
            crate::http::build_router(provider),
            Arc::new(crate::signature::PeerKeys::from_file(None)),
        ),
        telemetry.clone(),
    );
    let from_peer = |method: &str, uri: &str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::FROM, "mimi@peer.example")
            .extension(PeerCert(Some(PeerIdentity::signed("peer.example"))))
            .body(Body::empty())
            .unwrap()
    };
    let answers = [
        from_peer(
            "POST",
            "/mimi/pl/notify/mimi%3A%2F%2Fother.example%2Fr%2Fsecret-room",
        ),
        from_peer("GET", "/mimi/v1/keyMaterial?user=secret-user"),
        Request::builder()
            .method("POST")
            .uri("/mimi/pl/update/secret-room-two")
            .body(Body::empty())
            .unwrap(),
    ];
    let mut statuses = Vec::new();
    for request in answers {
        statuses.push(router.clone().oneshot(request).await.unwrap().status());
    }
    assert_eq!(
        statuses,
        [
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::FORBIDDEN
        ]
    );
    telemetry.record_outbound(&Outbound {
        peer: "other.example",
        endpoint: "notify",
        outcome: Err("timeout"),
        attempt: Some(2),
        started: std::time::SystemTime::now(),
        duration: Duration::from_millis(5),
    });
    let flushing = telemetry.clone();
    tokio::task::spawn_blocking(move || flushing.flush())
        .await
        .unwrap();

    let mut spans = Vec::new();
    let mut server_counts: Vec<(Option<String>, i64)> = Vec::new();
    let received = received.lock().unwrap().clone();
    for (path, body) in &received {
        let text = String::from_utf8_lossy(body);
        for named in ["secret-room", "secret-user", "other.example%2Fr"] {
            assert!(!text.contains(named), "the export to {path} holds {named}");
        }
        if path == "/v1/traces" {
            let request = ExportTraceServiceRequest::decode(body.as_ref()).unwrap();
            for resource in request.resource_spans {
                for scope in resource.scope_spans {
                    spans.extend(scope.spans);
                }
            }
        } else {
            let request = ExportMetricsServiceRequest::decode(body.as_ref()).unwrap();
            for metric in request
                .resource_metrics
                .into_iter()
                .flat_map(|resource| resource.scope_metrics)
                .flat_map(|scope| scope.metrics)
                .filter(|metric| metric.name == "mimi.server.requests")
            {
                let Some(Data::Sum(sum)) = metric.data else {
                    continue;
                };
                for point in sum.data_points {
                    let Some(number_data_point::Value::AsInt(count)) = point.value else {
                        continue;
                    };
                    server_counts.push((string_of(&point.attributes, "mimi.peer.provider"), count));
                }
            }
        }
    }
    assert_eq!(spans.len(), 4, "three requests and one outbound attempt");
    for span in &spans {
        for attribute in &span.attributes {
            assert!(
                crate::telemetry::tests::ALLOWED_KEYS.contains(&attribute.key.as_str()),
                "unlisted attribute {}",
                attribute.key
            );
        }
    }
    let routes: Vec<Option<String>> = spans
        .iter()
        .map(|span| string_of(&span.attributes, "http.route"))
        .collect();
    assert!(
        routes.contains(&Some("/mimi/pl/notify/:room_id".to_owned())),
        "PLANT-OTLP-ROUTE: {routes:?}"
    );
    let notify = spans
        .iter()
        .find(|span| span.name == "POST /mimi/pl/notify/:room_id")
        .unwrap();
    assert_eq!(
        string_of(&notify.attributes, "mimi.problem").as_deref(),
        Some("not-the-rooms-hub")
    );
    let mut per_peer: std::collections::BTreeMap<Option<String>, i64> = Default::default();
    for (peer, count) in server_counts {
        *per_peer.entry(peer).or_default() += count;
    }
    assert_eq!(
        per_peer.into_iter().collect::<Vec<_>>(),
        vec![
            (Some("peer.example".to_owned()), 2),
            (Some("unauthenticated".to_owned()), 1),
        ],
        "PLANT-OTLP-PEER: per-peer counts"
    );
    let outbound = spans.iter().find(|span| span.name == "notify").unwrap();
    assert_eq!(
        string_of(&outbound.attributes, "mimi.peer.provider").as_deref(),
        Some("other.example")
    );
    assert_eq!(
        string_of(&outbound.attributes, "error.type").as_deref(),
        Some("timeout")
    );
}
