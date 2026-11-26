//! The client lane's provider-level routes: the provider event stream by pull (`events/wait`, `events/fetch`,
//! `events/ack`) and `info`. Each request is signed by the provider's server for itself ([`LANE_PROVIDER`]), not for a
//! user; a request signed for a user is refused here, as one signed for the provider is refused on the user routes.
//!
//! [`LANE_PROVIDER`]: crate::client_lane::LANE_PROVIDER

use std::time::{Duration, SystemTime};

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use super::{internal, parse, with_signed_request, LaneState, MAX_LANE_BODY};
use crate::client_lane_events::{
    wait_for_events, EventsRefusal, LANE_VERSION, MAX_EVENTS_PAGE, MAX_WAIT_MS,
};
use crate::store::EventAck;

/// The provider-level routes, with their own gate in front.
pub(super) fn router(state: LaneState) -> Router<LaneState> {
    Router::new()
        .route("/mimi/client/v1/info", post(info))
        .route("/mimi/client/v1/events/wait", post(wait))
        .route("/mimi/client/v1/events/fetch", post(fetch))
        .route("/mimi/client/v1/events/ack", post(ack))
        .layer(middleware::from_fn_with_state(state, provider_gate))
}

/// Authenticate the request as the provider's own server, or answer 401.
async fn provider_gate(State(state): State<LaneState>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_LANE_BODY).await else {
        return crate::problem::BODY_TOO_LARGE.response();
    };
    let verdict = with_signed_request(&parts, &body, |request| {
        state.auth.verify_provider(request, SystemTime::now())
    });
    if let Err(refusal) = verdict {
        eprintln!(
            "[mimihubd] client lane refused {} {}: {refusal:?}",
            parts.method,
            parts.uri.path()
        );
        return crate::problem::CLIENT_NOT_AUTHENTICATED.response();
    }
    next.run(Request::from_parts(parts, Body::from(body))).await
}

fn refused(refusal: EventsRefusal) -> Response {
    match refusal {
        EventsRefusal::NotEventDelivery => crate::problem::DELIVERY_MODE.response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InfoRequest {}

#[derive(Serialize)]
struct InfoAnswer {
    lane_version: u32,
    /// `inbox` (per-user queues: `inboxFetch`/`inboxAck`) or `events` (the provider event stream).
    delivery: &'static str,
    /// Whether the hub pushes the event stream to the provider's server.
    push: bool,
    /// Where the stream stands, for a hub delivering through it.
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<crate::store::EventCursor>,
    /// How the push stands, for a hub that pushes: what a stuck push looks like from outside. No payload appears in it.
    #[serde(skip_serializing_if = "Option::is_none")]
    push_status: Option<crate::event_push::PushStatus>,
}

/// The lane's version and how this hub delivers.
async fn info(State(state): State<LaneState>, body: Bytes) -> Response {
    if parse::<InfoRequest>(&body).is_none() {
        return crate::problem::MALFORMED_REQUEST.response();
    }
    let provider = crate::http::lock(&state.provider);
    let stream = if provider.delivers_events() {
        match provider.events_cursor() {
            Ok(cursor) => Some(cursor),
            Err(error) => return internal("info", error),
        }
    } else {
        None
    };
    let push_status = provider.push_status().map(|status| {
        status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    });
    Json(InfoAnswer {
        lane_version: LANE_VERSION,
        delivery: if provider.delivers_events() {
            "events"
        } else {
            "inbox"
        },
        push: provider.pushes_events(),
        stream,
        push_status,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitRequest {
    #[serde(default)]
    after_seq: i64,
    #[serde(default = "default_wait_ms")]
    timeout_ms: u64,
}

fn default_wait_ms() -> u64 {
    MAX_WAIT_MS
}

/// Answer as soon as an event past `after_seq` exists, or at the timeout with no users.
async fn wait(State(state): State<LaneState>, body: Bytes) -> Response {
    let Some(request) = parse::<WaitRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let timeout = Duration::from_millis(request.timeout_ms.min(MAX_WAIT_MS));
    match wait_for_events(&state.provider, request.after_seq, timeout).await {
        Ok(Ok(answer)) => Json(answer).into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(error) => internal("events/wait", error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchRequest {
    #[serde(default)]
    after_seq: i64,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    MAX_EVENTS_PAGE
}

/// The events after `after_seq`, in `seq` order, left in place until acknowledged.
async fn fetch(State(state): State<LaneState>, body: Bytes) -> Response {
    let Some(request) = parse::<FetchRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    match crate::http::lock(&state.provider).events_page(request.after_seq, request.limit) {
        Ok(Ok(batch)) => Json(batch).into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(error) => internal("events/fetch", error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRequest {
    up_to_seq: i64,
}

#[derive(Serialize)]
struct AckAnswer {
    acked_through: i64,
}

/// Acknowledge every event up to `up_to_seq`. Past the last `seq` written, nothing changes and the answer is a problem.
async fn ack(State(state): State<LaneState>, body: Bytes) -> Response {
    let Some(request) = parse::<AckRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    match crate::http::lock(&state.provider).events_ack(request.up_to_seq) {
        Ok(Ok(EventAck::AckedThrough(acked_through))) => {
            Json(AckAnswer { acked_through }).into_response()
        }
        Ok(Ok(EventAck::PastEnd { .. })) => crate::problem::ACK_PAST_END.response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(error) => internal("events/ack", error),
    }
}
