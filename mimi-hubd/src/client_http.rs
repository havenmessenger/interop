//! The client lane's listener: `/mimi/client/v1/*`, and nothing else.
//!
//! Every request passes [`ClientLaneAuth`] first (see `client_lane.rs`): the handlers act for the user it names and
//! never take a user from a request body. Bodies are JSON; MLS objects in them are base64 (standard alphabet).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::client_lane::{ClientLaneAuth, LaneUser};
use crate::client_lane_ops::PublishRefusal;
use crate::http::SharedProvider;
use crate::signature::SignedRequest;

/// The largest lane request body read.
// LIMIT-REASON: wire-cost: a publish of the most KeyPackages, or one Commit with its Welcome and GroupInfo
const MAX_LANE_BODY: usize = 4 * 1024 * 1024;

/// How many lane requests one user may make in a minute.
// LIMIT-REASON: quota: a coarse backstop behind the client-facing service's own per-route limits
pub const REQUESTS_PER_USER_PER_MINUTE: u32 = 600;

/// Requests per user in the current minute, kept in memory.
#[derive(Default)]
pub struct UserCap {
    counts: Mutex<HashMap<String, (i64, u32)>>,
}

impl UserCap {
    /// Count one request for `user` at `now` (seconds); false when the user is over the cap this minute.
    pub fn admit(&self, user: &str, now: i64) -> bool {
        let minute = now / 60;
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counts.retain(|_, (at, _)| *at == minute);
        let entry = counts.entry(user.to_string()).or_insert((minute, 0));
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= REQUESTS_PER_USER_PER_MINUTE
    }
}

#[derive(Clone)]
struct LaneState {
    provider: SharedProvider,
    auth: Arc<ClientLaneAuth>,
    cap: Arc<UserCap>,
}

/// The lane's router, with its gate in front of every route.
pub fn build_client_router(provider: SharedProvider, auth: Arc<ClientLaneAuth>) -> Router {
    let state = LaneState {
        provider: provider.clone(),
        auth,
        cap: Arc::new(UserCap::default()),
    };
    Router::new()
        .route("/mimi/client/v1/publishKeyPackages", post(publish))
        .route("/mimi/client/v1/withdrawKeyPackages", post(withdraw))
        .route("/mimi/client/v1/inboxFetch", post(inbox_fetch))
        .route("/mimi/client/v1/inboxAck", post(inbox_ack))
        .route("/mimi/client/v1/createRoom", post(create_room))
        .route("/mimi/client/v1/submitMessage", post(submit_message))
        .route("/mimi/client/v1/update", post(update))
        .layer(middleware::from_fn_with_state(state.clone(), gate))
        .with_state(state)
}

/// Authenticate the request for one user, or answer 401; then hold the user to the per-user cap.
async fn gate(State(state): State<LaneState>, request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_LANE_BODY).await else {
        return crate::problem::BODY_TOO_LARGE.response();
    };
    let verdict = {
        let host = parts
            .uri
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                parts
                    .headers
                    .get(axum::http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let target_uri = format!("https://{host}{path_and_query}");
        let headers = parts.headers.clone();
        let header = move |name: &str| -> Option<String> {
            let values: Vec<&str> = headers
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(str::trim)
                .collect();
            (!values.is_empty()).then(|| values.join(", "))
        };
        state.auth.verify(
            &SignedRequest {
                method: parts.method.as_str(),
                target_uri: &target_uri,
                authority: &host,
                path: parts.uri.path(),
                query: parts.uri.query(),
                header: &header,
                body: &body,
            },
            SystemTime::now(),
        )
    };
    let user = match verdict {
        Ok(user) => user,
        Err(refusal) => {
            eprintln!(
                "[mimi-hubd] client lane refused {} {}: {refusal:?}",
                parts.method,
                parts.uri.path()
            );
            return crate::problem::CLIENT_NOT_AUTHENTICATED.response();
        }
    };
    if !state.cap.admit(&user.user, now_seconds()) {
        return crate::problem::CLIENT_RATE_LIMITED.response();
    }
    parts.extensions.insert(user);
    next.run(Request::from_parts(parts, Body::from(body))).await
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

fn now_unix() -> u64 {
    u64::try_from(now_seconds()).unwrap_or(0)
}

/// The JSON body, when it is one of the expected shape.
fn parse<T: for<'de> Deserialize<'de>>(body: &Bytes) -> Option<T> {
    serde_json::from_slice(body).ok()
}

fn internal(what: &str, error: anyhow::Error) -> Response {
    eprintln!("[mimi-hubd] client lane {what}: {error}");
    crate::problem::INTERNAL_ERROR.response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishRequest {
    key_packages: Vec<String>,
}

#[derive(Serialize)]
struct Count {
    count: usize,
}

/// Publish KeyPackages for the user: each names the user in its basic credential and passes the suite gate.
async fn publish(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    let Some(request) = parse::<PublishRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let Ok(key_packages) = request
        .key_packages
        .iter()
        .map(|kp| STANDARD.decode(kp))
        .collect::<Result<Vec<_>, _>>()
    else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let provider = crate::http::lock(&state.provider);
    match provider.lane_publish(&user.user, &key_packages, now_unix()) {
        Ok(Ok(count)) => Json(Count { count }).into_response(),
        Ok(Err(PublishRefusal::TooMany)) => crate::problem::MALFORMED_REQUEST.response(),
        Ok(Err(PublishRefusal::NotAccepted(_) | PublishRefusal::NotTheUser(_))) => {
            crate::problem::MATERIAL_NOT_ACCEPTED.response()
        }
        Err(error) => internal("publish", error),
    }
}

/// Withdraw every KeyPackage of the user's: from now on no one can add them.
async fn withdraw(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
) -> Response {
    match crate::http::lock(&state.provider).lane_withdraw(&user.user) {
        Ok(count) => Json(Count { count }).into_response(),
        Err(error) => internal("withdraw", error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchRequest {
    #[serde(default)]
    after_welcome: i64,
    #[serde(default)]
    after_message: i64,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    crate::client_lane_ops::MAX_INBOX_PAGE
}

#[derive(Serialize)]
struct Item {
    seq: i64,
    bytes: String,
    received_at: i64,
}

#[derive(Serialize)]
struct FetchAnswer {
    welcomes: Vec<Item>,
    messages: Vec<Item>,
    more: bool,
}

/// The user's queued Welcomes and messages after the cursors, oldest first, left in place until acknowledged. A client
/// handles the Welcomes of a page before its messages.
async fn inbox_fetch(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    let Some(request) = parse::<FetchRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let page = match crate::http::lock(&state.provider).lane_inbox(
        &user.user,
        request.after_welcome,
        request.after_message,
        request.limit,
    ) {
        Ok(page) => page,
        Err(error) => return internal("inboxFetch", error),
    };
    let items = |queued: Vec<crate::store::QueuedItem>| {
        queued
            .into_iter()
            .map(|item| Item {
                seq: item.id,
                bytes: STANDARD.encode(item.bytes),
                received_at: item.received_at,
            })
            .collect()
    };
    Json(FetchAnswer {
        welcomes: items(page.welcomes),
        messages: items(page.messages),
        more: page.more,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckRequest {
    #[serde(default)]
    welcomes_up_to: i64,
    #[serde(default)]
    messages_up_to: i64,
}

#[derive(Serialize)]
struct AckAnswer {
    welcomes: usize,
    messages: usize,
}

/// Remove the user's queued items up to the cursors.
async fn inbox_ack(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    let Some(request) = parse::<AckRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    match crate::http::lock(&state.provider).lane_ack(
        &user.user,
        request.welcomes_up_to,
        request.messages_up_to,
    ) {
        Ok((welcomes, messages)) => Json(AckAnswer { welcomes, messages }).into_response(),
        Err(error) => internal("inboxAck", error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRoomRequest {
    policy: String,
}

#[derive(Serialize)]
struct CreatedRoom {
    room: String,
}

/// The one room policy a lane request may name.
const DEFAULT_POLICY: &str = "haven-default";

/// Create a room hosted here with the user as its first participant and admin, under the lane's one policy.
async fn create_room(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    let Some(request) = parse::<CreateRoomRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    if request.policy != DEFAULT_POLICY {
        return crate::problem::MALFORMED_REQUEST.response();
    }
    match crate::http::lock(&state.provider).lane_create_room(&user.user, now_unix()) {
        Ok(room) => (axum::http::StatusCode::CREATED, Json(CreatedRoom { room })).into_response(),
        Err(error) => internal("createRoom", error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitRequest {
    room: String,
    message: String,
}

#[derive(Serialize)]
struct Empty {}

/// Send an application message into a room hosted here, as the user: the user must be an active participant whose
/// role may send.
async fn submit_message(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    let Some(request) = parse::<SubmitRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let Ok(message) = STANDARD.decode(&request.message) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    if crate::http::lock(&state.provider).accept_application_message(
        &request.room,
        &user.user,
        &message,
        now_unix(),
    ) {
        Json(Empty {}).into_response()
    } else {
        crate::problem::NOT_PERMITTED.response()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRequest {
    room: String,
    /// The `UpdateRequest` as the wire lane carries it: a Commit bundle, or a leave's proposals.
    update: String,
}

/// The `update` answer as JSON, one of the wire's four answers.
#[derive(Serialize)]
#[serde(tag = "answer", rename_all = "camelCase")]
enum UpdateAnswer {
    /// `epoch`: the room's epoch as this hub holds it after the update, when it holds one.
    Success {
        epoch: Option<u64>,
    },
    WrongEpoch {
        current_epoch: u64,
    },
    NotAllowed {
        description: String,
    },
    InvalidProposal {
        description: String,
    },
}

/// Apply a room update as the user, for a room hosted here: the same checks as the wire lane's `update`, with the
/// user as the requester (see `requester.rs`).
async fn update(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    use mimi_core::protocol_wire::UpdateRoomResponse;

    let Some(request) = parse::<UpdateRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let Ok(update) = STANDARD.decode(&request.update) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let provider = crate::http::lock(&state.provider);
    let result = provider.apply_update_request(
        &request.room,
        &update,
        crate::requester::Requester::LaneUser(&user.user),
        now_unix(),
    );
    let Some(answer) = crate::http::update_room_response(result, 0) else {
        return crate::problem::INTERNAL_ERROR.response();
    };
    let epoch = || provider.store.room_epoch(&request.room).ok().flatten();
    crate::http::log_update_answer(&answer, epoch);
    Json(match answer {
        UpdateRoomResponse::Success { .. } => UpdateAnswer::Success { epoch: epoch() },
        UpdateRoomResponse::WrongEpoch { current_epoch, .. } => {
            UpdateAnswer::WrongEpoch { current_epoch }
        }
        UpdateRoomResponse::NotAllowed { error_description } => UpdateAnswer::NotAllowed {
            description: error_description,
        },
        UpdateRoomResponse::InvalidProposal {
            error_description, ..
        } => UpdateAnswer::InvalidProposal {
            description: error_description,
        },
    })
    .into_response()
}
