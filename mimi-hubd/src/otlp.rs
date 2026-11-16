//! Export over OTLP/HTTP with protobuf bodies (feature `otlp`): a span per request and two metrics per direction,
//! `mimi.server.requests` and `mimi.server.duration` for requests peers make, `mimi.client.requests` and
//! `mimi.client.duration` for requests this hub makes. The attributes are the ones `crate::telemetry` lists.
//!
//! Spans are batched and metrics read every 30 s, each by the SDK on a thread of its own; a request only adds to the
//! batch or a counter, so a collector that is slow or down never slows or fails one. What the collector does not take
//! is dropped. The HTTP client sends from the hub's own tokio runtime, over rustls with the ring provider and the
//! system's root certificates.

use std::time::Duration;

use opentelemetry::metrics::{Counter, Histogram, MeterProvider as _};
use opentelemetry::trace::{Span as _, SpanKind, Status, Tracer as _, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use opentelemetry_sdk::Resource;

use crate::telemetry::{inbound_attributes, outbound_attributes, Inbound, Outbound};

/// How long one export to the collector may take.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the metrics are read and sent.
const METRIC_INTERVAL: Duration = Duration::from_secs(30);

pub struct Export {
    tracer: SdkTracer,
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    server_requests: Counter<u64>,
    server_duration: Histogram<f64>,
    client_requests: Counter<u64>,
    client_duration: Histogram<f64>,
}

/// The HTTP client the exporters use: hyper over rustls, each request run on the hub's runtime. The SDK exports from
/// threads of its own, where no runtime is current.
#[derive(Debug, Clone)]
struct OnRuntime {
    runtime: tokio::runtime::Handle,
    client: opentelemetry_http::hyper::HyperClient<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    >,
}

#[async_trait::async_trait]
impl opentelemetry_http::HttpClient for OnRuntime {
    async fn send_bytes(
        &self,
        request: opentelemetry_http::Request<opentelemetry_http::Bytes>,
    ) -> Result<
        opentelemetry_http::Response<opentelemetry_http::Bytes>,
        opentelemetry_http::HttpError,
    > {
        let client = self.client.clone();
        self.runtime
            .spawn(async move { client.send_bytes(request).await })
            .await?
    }
}

fn http_client() -> anyhow::Result<OnRuntime> {
    let mut roots = rustls::RootCertStore::empty();
    let (added, _ignored) =
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if added == 0 {
        eprintln!("[mimi-hubd] otlp: no system root certificate could be loaded");
    }
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    // `https_or_http`: the endpoint was already held to https, or http to a loopback address.
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    Ok(OnRuntime {
        runtime: tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow::anyhow!("otlp: export starts inside the hub's runtime"))?,
        client: opentelemetry_http::hyper::HyperClient::new(connector, EXPORT_TIMEOUT, None),
    })
}

fn key_values(attributes: Vec<(&'static str, String)>) -> Vec<KeyValue> {
    attributes
        .into_iter()
        .map(|(key, value)| KeyValue::new(key, value))
        .collect()
}

impl Export {
    /// Start exporting to the collector at `endpoint` (its base URL; `/v1/traces` and `/v1/metrics` are added).
    pub fn start(endpoint: &str) -> anyhow::Result<Self> {
        let base = endpoint.trim_end_matches('/');
        let client = http_client()?;
        let resource = Resource::builder_empty()
            .with_service_name("mimi-hubd")
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build();
        let spans = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_http_client(client.clone())
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(format!("{base}/v1/traces"))
            .with_timeout(EXPORT_TIMEOUT)
            .build()?;
        let metrics = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_http_client(client)
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(format!("{base}/v1/metrics"))
            .with_timeout(EXPORT_TIMEOUT)
            .build()?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(spans)
            .with_resource(resource.clone())
            .build();
        let meter_provider = SdkMeterProvider::builder()
            .with_reader(
                PeriodicReader::builder(metrics)
                    .with_interval(METRIC_INTERVAL)
                    .build(),
            )
            .with_resource(resource)
            .build();
        let tracer = tracer_provider.tracer("mimi-hubd");
        let meter = meter_provider.meter("mimi-hubd");
        Ok(Self {
            tracer,
            tracer_provider,
            server_requests: meter
                .u64_counter("mimi.server.requests")
                .with_description("Requests peers made to this hub")
                .build(),
            server_duration: meter
                .f64_histogram("mimi.server.duration")
                .with_unit("ms")
                .with_description("Time to answer a peer's request")
                .build(),
            client_requests: meter
                .u64_counter("mimi.client.requests")
                .with_description("Requests this hub made to other providers")
                .build(),
            client_duration: meter
                .f64_histogram("mimi.client.duration")
                .with_unit("ms")
                .with_description("Time for another provider to answer, or for the attempt to fail")
                .build(),
            meter_provider,
        })
    }

    pub fn inbound(&self, record: &Inbound<'_>) {
        let attributes = key_values(inbound_attributes(record));
        self.server_requests.add(1, &attributes);
        self.server_duration
            .record(record.duration.as_secs_f64() * 1000.0, &attributes);
        let name = format!(
            "{} {}",
            record.method.as_str(),
            record.route.unwrap_or("unmatched")
        );
        let mut span = self
            .tracer
            .span_builder(name)
            .with_kind(SpanKind::Server)
            .with_start_time(record.started)
            .with_attributes(attributes)
            .start(&self.tracer);
        if record.status >= 500 {
            span.set_status(Status::error("server error"));
        }
        span.end_with_timestamp(record.started + record.duration);
    }

    pub fn outbound(&self, record: &Outbound<'_>) {
        let attributes = key_values(outbound_attributes(record));
        self.client_requests.add(1, &attributes);
        self.client_duration
            .record(record.duration.as_secs_f64() * 1000.0, &attributes);
        let mut span = self
            .tracer
            .span_builder(record.endpoint)
            .with_kind(SpanKind::Client)
            .with_start_time(record.started)
            .with_attributes(attributes)
            .start(&self.tracer);
        if !matches!(record.outcome, Ok(status) if status < 500) {
            span.set_status(Status::error("failed"));
        }
        span.end_with_timestamp(record.started + record.duration);
    }

    pub fn flush(&self) {
        if let Err(error) = self.tracer_provider.force_flush() {
            eprintln!("[mimi-hubd] otlp: spans not sent: {error}");
        }
        if let Err(error) = self.meter_provider.force_flush() {
            eprintln!("[mimi-hubd] otlp: metrics not sent: {error}");
        }
    }
}

#[cfg(test)]
#[path = "otlp_tests.rs"]
mod tests;
