//! What the hub reports about its traffic to an operator's OpenTelemetry collector: per peer provider, how many requests,
//! with what status, and how long they took, in both directions.
//!
//! Export is built only with the `otlp` feature and runs only when `MIMI_OTLP_ENDPOINT` names a collector
//! ([`start`]). Without either, [`Telemetry`] is a handle that records nothing. The record of a request carries only
//! the attributes [`inbound_attributes`] and [`outbound_attributes`] list: the method, the route as this crate's router
//! names it, the status or the failure's class, the provider domain the request was authenticated as (or sent to), and
//! a refusal's problem type. Never a path value, a query, a header, a certificate, a body, a user or a room.
//!
//! The collector is the operator's own setting, so requests to it do not go through the outbound gate that checks
//! peers' addresses; [`check_endpoint`] holds it to `https`, or plain `http` to a loopback address only.

use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use axum::{
    extract::{MatchedPath, Request, State},
    http::Method,
    middleware::Next,
    response::Response,
    Router,
};

/// What the provider-auth gate puts on the answer to a request it admitted: the provider domain the request was
/// authenticated as, by its signature or by its certificate and `From` header.
#[derive(Clone, Debug)]
pub struct AuthenticatedPeer(pub String);

/// The peer attribute for a request no provider authenticated.
pub const UNAUTHENTICATED: &str = "unauthenticated";

/// One request a peer made to this hub.
pub struct Inbound<'a> {
    pub method: &'a Method,
    /// The route template this crate's router matched, or `None` for a request no route matched.
    pub route: Option<&'a str>,
    pub status: u16,
    /// The provider domain the request was authenticated as.
    pub peer: Option<&'a str>,
    /// The problem type of a refusal (`docs/problems.md`).
    pub problem: Option<&'static str>,
    pub started: SystemTime,
    pub duration: Duration,
}

/// One request this hub made to another provider.
pub struct Outbound<'a> {
    /// The provider domain the request went to.
    pub peer: &'a str,
    /// Which of the hub's requests it was, by name (`notify`, `keyMaterial`, `directory`).
    pub endpoint: &'static str,
    /// The answer's status, or the class of the failure that left no answer.
    pub outcome: Result<u16, &'static str>,
    /// For a queued delivery, which attempt this was (1 for the first).
    pub attempt: Option<u32>,
    pub started: SystemTime,
    pub duration: Duration,
}

/// The attributes of an inbound request: these keys and no others.
pub fn inbound_attributes(record: &Inbound<'_>) -> Vec<(&'static str, String)> {
    let mut attributes = vec![
        ("http.request.method", method_name(record.method).to_owned()),
        ("http.route", record.route.unwrap_or("unmatched").to_owned()),
        ("http.response.status_code", record.status.to_string()),
        (
            "mimi.peer.provider",
            record.peer.unwrap_or(UNAUTHENTICATED).to_owned(),
        ),
    ];
    if let Some(problem) = record.problem {
        attributes.push(("mimi.problem", problem.to_owned()));
    }
    attributes
}

/// The attributes of an outbound request: these keys and no others.
pub fn outbound_attributes(record: &Outbound<'_>) -> Vec<(&'static str, String)> {
    let mut attributes = vec![
        ("mimi.peer.provider", record.peer.to_owned()),
        ("mimi.endpoint", record.endpoint.to_owned()),
    ];
    match record.outcome {
        Ok(status) => attributes.push(("http.response.status_code", status.to_string())),
        Err(class) => attributes.push(("error.type", class.to_owned())),
    }
    if let Some(attempt) = record.attempt {
        attributes.push(("mimi.attempt", attempt.to_string()));
    }
    attributes
}

/// A method as the attribute names it; anything outside the usual set reads `OTHER`, so a peer's method token does not
/// become an attribute value.
fn method_name(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::PATCH => "PATCH",
        _ => "OTHER",
    }
}

/// The class of an outbound failure that left no answer.
pub fn failure_class(error: &crate::outbound::OutboundError) -> &'static str {
    use crate::outbound::OutboundError as E;
    match error {
        E::NotHttps | E::BadUrl(_) | E::HostNotPeer { .. } | E::Refused { .. } => "refused",
        E::NoAddress(_) | E::Resolve { .. } => "resolve",
        E::Connect(_) | E::Proxy(_) => "connect",
        E::Tls(_) => "tls",
        E::Http(_) | E::TooLarge => "http",
        E::Timeout(_) => "timeout",
    }
}

/// Where telemetry goes, or nowhere. Cloning shares it.
#[derive(Clone, Default)]
pub struct Telemetry {
    #[cfg(feature = "otlp")]
    export: Option<std::sync::Arc<crate::otlp::Export>>,
}

impl Telemetry {
    /// A handle that records nothing.
    pub fn off() -> Self {
        Self::default()
    }

    /// Whether anything is recorded.
    pub fn is_on(&self) -> bool {
        #[cfg(feature = "otlp")]
        {
            self.export.is_some()
        }
        #[cfg(not(feature = "otlp"))]
        {
            false
        }
    }

    pub fn record_inbound(&self, record: &Inbound<'_>) {
        #[cfg(feature = "otlp")]
        if let Some(export) = &self.export {
            export.inbound(record);
        }
        #[cfg(not(feature = "otlp"))]
        let _ = record;
    }

    pub fn record_outbound(&self, record: &Outbound<'_>) {
        #[cfg(feature = "otlp")]
        if let Some(export) = &self.export {
            export.outbound(record);
        }
        #[cfg(not(feature = "otlp"))]
        let _ = record;
    }

    /// Send what is buffered now; for shutdown and tests.
    pub fn flush(&self) {
        #[cfg(feature = "otlp")]
        if let Some(export) = &self.export {
            export.flush();
        }
    }

    /// Record an outbound request that started at `started`, from the client's result.
    pub fn record_peer_request<T>(
        &self,
        peer: &str,
        endpoint: &'static str,
        attempt: Option<u32>,
        started: (SystemTime, Instant),
        result: &Result<T, crate::outbound::OutboundError>,
        status_of: impl Fn(&T) -> u16,
    ) {
        if !self.is_on() {
            return;
        }
        self.record_outbound(&Outbound {
            peer,
            endpoint,
            outcome: result.as_ref().map(&status_of).map_err(failure_class),
            attempt,
            started: started.0,
            duration: started.1.elapsed(),
        });
    }
}

/// The start of a request, for [`Telemetry::record_peer_request`].
pub fn now() -> (SystemTime, Instant) {
    (SystemTime::now(), Instant::now())
}

/// Check the collector's URL: `https`, or `http` only to a loopback address (`localhost`, 127.0.0.0/8 or `::1`). Its
/// requests skip the outbound gate, so this is the gate's stance applied to the one address the operator names.
pub fn check_endpoint(url: &str) -> Result<(), &'static str> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or("the OTLP endpoint is not a URL")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err("the OTLP endpoint names no host, or carries credentials in its URL");
    }
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(());
    }
    if !scheme.eq_ignore_ascii_case("http") {
        return Err("the OTLP endpoint is not http or https");
    }
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host),
    };
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if loopback {
        Ok(())
    } else {
        Err("an http OTLP endpoint must be a loopback address; use https for any other")
    }
}

/// Start export to the collector `setting` names, if this build can and the setting names one. Returns the handle and
/// the startup line: `otlp: off (not built)`, `otlp: off`, or `otlp: <endpoint>`.
pub fn start(setting: Option<&str>) -> anyhow::Result<(Telemetry, String)> {
    let setting = setting.map(str::trim).filter(|value| !value.is_empty());
    #[cfg(not(feature = "otlp"))]
    {
        let line = match setting {
            Some(_) => "otlp: off (not built; MIMI_OTLP_ENDPOINT is ignored)",
            None => "otlp: off (not built)",
        };
        Ok((Telemetry::off(), line.to_owned()))
    }
    #[cfg(feature = "otlp")]
    {
        let Some(endpoint) = setting else {
            return Ok((Telemetry::off(), "otlp: off".to_owned()));
        };
        check_endpoint(endpoint).map_err(|why| anyhow::anyhow!("MIMI_OTLP_ENDPOINT: {why}"))?;
        let export = crate::otlp::Export::start(endpoint)?;
        Ok((
            Telemetry {
                export: Some(std::sync::Arc::new(export)),
            },
            format!("otlp: {endpoint}"),
        ))
    }
}

#[cfg(feature = "otlp")]
impl Telemetry {
    /// A handle exporting to `endpoint` with a short export interval, for tests.
    pub fn for_test(endpoint: &str) -> anyhow::Result<Self> {
        Ok(Telemetry {
            export: Some(std::sync::Arc::new(crate::otlp::Export::start(endpoint)?)),
        })
    }
}

/// The router with each request recorded, when `telemetry` records anything; as it was otherwise. Placed outside the
/// provider-auth gate, so a request the gate refuses is recorded too, as `unauthenticated`.
pub fn with_telemetry(router: Router, telemetry: Telemetry) -> Router {
    if telemetry.is_on() {
        router.layer(axum::middleware::from_fn_with_state(telemetry, record))
    } else {
        router
    }
}

async fn record(State(telemetry): State<Telemetry>, request: Request, next: Next) -> Response {
    let started = now();
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_owned());
    let response = next.run(request).await;
    let peer = response
        .extensions()
        .get::<AuthenticatedPeer>()
        .map(|AuthenticatedPeer(domain)| domain.clone());
    let problem = response
        .extensions()
        .get::<crate::problem::ProblemAnchor>()
        .map(|crate::problem::ProblemAnchor(anchor)| *anchor);
    telemetry.record_inbound(&Inbound {
        method: &method,
        route: route.as_deref(),
        status: response.status().as_u16(),
        peer: peer.as_deref(),
        problem,
        started: started.0,
        duration: started.1.elapsed(),
    });
    response
}

#[cfg(test)]
#[path = "telemetry_tests.rs"]
pub(crate) mod tests;
