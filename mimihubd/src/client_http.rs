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
use crate::client_lane_rooms::LaneRoomProfile;
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

#[path = "client_http_consent.rs"]
mod consent;
#[path = "client_http_events.rs"]
mod events;

#[derive(Clone)]
struct LaneState {
    provider: SharedProvider,
    auth: Arc<ClientLaneAuth>,
    cap: Arc<UserCap>,
    rooms: Arc<LaneRoomProfile>,
    key_material: Arc<crate::client_lane_relay::KeyMaterialCap>,
}

/// The lane's router, with its gate in front of every route. `rooms` is what a room the lane creates starts with.
pub fn build_client_router(
    provider: SharedProvider,
    auth: Arc<ClientLaneAuth>,
    rooms: LaneRoomProfile,
) -> Router {
    let state = LaneState {
        provider: provider.clone(),
        auth,
        cap: Arc::new(UserCap::default()),
        rooms: Arc::new(rooms),
        key_material: Arc::new(crate::client_lane_relay::KeyMaterialCap::default()),
    };
    Router::new()
        .route("/mimi/client/v1/publishKeyPackages", post(publish))
        .route("/mimi/client/v1/withdrawKeyPackages", post(withdraw))
        .route("/mimi/client/v1/keyPackageCount", post(key_package_count))
        .route("/mimi/client/v1/inboxFetch", post(inbox_fetch))
        .route("/mimi/client/v1/inboxAck", post(inbox_ack))
        .route("/mimi/client/v1/createRoom", post(create_room))
        .route("/mimi/client/v1/submitMessage", post(submit_message))
        .route("/mimi/client/v1/update", post(update))
        .route("/mimi/client/v1/keyMaterial", post(key_material))
        .route("/mimi/client/v1/consent", post(consent::consent))
        .route(
            "/mimi/client/v1/requestConsent",
            post(consent::request_consent),
        )
        .route(
            "/mimi/client/v1/consentRequests",
            post(consent::consent_requests),
        )
        .route(
            "/mimi/client/v1/consentReceived",
            post(consent::consent_received),
        )
        .route("/mimi/client/v1/optOut", post(consent::opt_out))
        .layer(middleware::from_fn_with_state(state.clone(), gate))
        .merge(events::router(state.clone()))
        .with_state(state)
}

/// Run `check` on the request as its signature sees it: the method, the target URI, the headers and the body.
fn with_signed_request<R>(
    parts: &axum::http::request::Parts,
    body: &Bytes,
    check: impl FnOnce(&SignedRequest<'_>) -> R,
) -> R {
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
    check(&SignedRequest {
        method: parts.method.as_str(),
        target_uri: &target_uri,
        authority: &host,
        path: parts.uri.path(),
        query: parts.uri.query(),
        header: &header,
        body,
    })
}

/// Authenticate the request for one user, or answer 401; then hold the user to the per-user cap.
async fn gate(State(state): State<LaneState>, request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_LANE_BODY).await else {
        return crate::problem::BODY_TOO_LARGE.response();
    };
    let verdict = with_signed_request(&parts, &body, |request| {
        state.auth.verify(request, SystemTime::now())
    });
    let user = match verdict {
        Ok(user) => user,
        Err(refusal) => {
            eprintln!(
                "[mimihubd] client lane refused {} {}: {refusal:?}",
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
    eprintln!("[mimihubd] client lane {what}: {error}");
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

/// The user's published KeyPackages: how many one-time ones are left unexpired, and whether a last-resort one is.
#[derive(Serialize)]
struct KeyPackageCount {
    one_time: u64,
    last_resort: bool,
}

async fn key_package_count(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
) -> Response {
    match crate::http::lock(&state.provider).lane_key_package_count(&user.user, now_unix()) {
        Ok((one_time, last_resort)) => Json(KeyPackageCount {
            one_time,
            last_resort,
        })
        .into_response(),
        Err(error) => internal("keyPackageCount", error),
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
    /// For a Welcome, the room it joins, as the hub queued it (left out when the hub had none to give).
    #[serde(skip_serializing_if = "Option::is_none")]
    room: Option<String>,
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
    if crate::http::lock(&state.provider).delivers_events() {
        return crate::problem::DELIVERY_MODE.response();
    }
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
                room: item.room,
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
    if crate::http::lock(&state.provider).delivers_events() {
        return crate::problem::DELIVERY_MODE.response();
    }
    match crate::http::lock(&state.provider).lane_ack(
        &user.user,
        request.welcomes_up_to,
        request.messages_up_to,
    ) {
        Ok((welcomes, messages)) => Json(AckAnswer { welcomes, messages }).into_response(),
        Err(error) => internal("inboxAck", error),
    }
}

/// createRoom takes nothing from the client: what the room starts with is the deployment's profile.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRoomRequest {}

#[derive(Serialize)]
struct CreatedRoom {
    room: String,
    /// The role the room's creator holds: the role the client lists itself in.
    creator_role: u32,
    /// The app data components the client's group starts with besides its participant list.
    components: Vec<Component>,
}

#[derive(Serialize)]
struct Component {
    id: u16,
    data: String,
}

/// Create a room hosted here with the user as its first participant, as the deployment's lane room profile says. The
/// answer gives the role the user holds and the components its group must start with.
async fn create_room(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    if parse::<CreateRoomRequest>(&body).is_none() {
        return crate::problem::MALFORMED_REQUEST.response();
    }
    match crate::http::lock(&state.provider).lane_create_room(&user.user, &state.rooms, now_unix())
    {
        Ok(room) => (
            axum::http::StatusCode::CREATED,
            Json(CreatedRoom {
                room,
                creator_role: state.rooms.creator_role,
                components: state
                    .rooms
                    .components()
                    .into_iter()
                    .map(|(id, data)| Component {
                        id,
                        data: STANDARD.encode(data),
                    })
                    .collect(),
            }),
        )
            .into_response(),
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

/// Send an application message into a room as the user. In a room hosted here the user must be an active participant
/// whose role may send; a room on another hub has it sent there (`client_lane_relay.rs`).
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
    if let Some(hub) = state.other_hub(&request.room) {
        return relay_submit(&state, &hub, &request.room, &user.user, message).await;
    }
    match crate::http::lock(&state.provider).accept_application_message(
        &request.room,
        &user.user,
        &message,
        now_unix(),
    ) {
        crate::submit::Acceptance::Accepted => Json(Empty {}).into_response(),
        crate::submit::Acceptance::Refused => crate::problem::NOT_PERMITTED.response(),
        crate::submit::Acceptance::WrongGroup => crate::problem::GROUP_MISMATCH.response(),
        crate::submit::Acceptance::Failed => crate::problem::INTERNAL_ERROR.response(),
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

/// Apply a room update as the user. For a room hosted here: the same checks as the wire lane's `update`, with the user
/// as the requester (see `requester.rs`); a room on another hub has it sent there (`client_lane_relay.rs`).
async fn update(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    let Some(request) = parse::<UpdateRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let Ok(update) = STANDARD.decode(&request.update) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    if let Some(hub) = state.other_hub(&request.room) {
        return relay_update(&state, &hub, &request.room, update).await;
    }
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
    let held = epoch();
    update_answer_json(answer, held)
}

/// The lane's JSON for a wire `update` answer; `epoch` is the room's epoch as this hub holds it, when it does.
fn update_answer_json(
    answer: mimi_core::protocol_wire::UpdateRoomResponse,
    epoch: Option<u64>,
) -> Response {
    use mimi_core::protocol_wire::UpdateRoomResponse;
    Json(match answer {
        UpdateRoomResponse::Success { .. } => UpdateAnswer::Success { epoch },
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

impl LaneState {
    /// The domain of the room's hub when it is another provider's.
    fn other_hub(&self, room: &str) -> Option<String> {
        let provider = crate::http::lock(&self.provider);
        crate::client_lane_relay::other_hub(room, provider.domain())
    }

    fn peer_access(&self) -> Option<Arc<crate::peer_directory::PeerAccess>> {
        crate::http::lock(&self.provider).peer_access()
    }
}

/// Send the user's application message into a room on `hub`, as this provider, naming the user as its sender.
async fn relay_submit(
    state: &LaneState,
    hub: &str,
    room: &str,
    user: &str,
    message: Vec<u8>,
) -> Response {
    use mimi_core::protocol_wire::{
        IdentifierUri, SubmitMessageRequest, SubmitMessageResponse, PROTOCOL_MLS10,
    };
    let Some(access) = state.peer_access() else {
        return crate::problem::UPSTREAM_FAILED.response();
    };
    let Ok(body) = (SubmitMessageRequest {
        protocol: PROTOCOL_MLS10,
        app_message: message,
        sending_uri: IdentifierUri(user.to_string()),
    })
    .encode() else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let answer =
        crate::client_lane_relay::post_to_peer(&access, hub, "submitMessage", "roomId", room, body)
            .await;
    match answer {
        Ok((200, bytes)) => match SubmitMessageResponse::decode(&bytes) {
            Ok(SubmitMessageResponse::Accepted { .. }) => Json(Empty {}).into_response(),
            Ok(_) => crate::problem::NOT_PERMITTED.response(),
            Err(_) => crate::problem::UPSTREAM_FAILED.response(),
        },
        Ok((status, _)) => {
            eprintln!("[mimihubd] client lane submitMessage: the room's hub answered {status}");
            crate::problem::UPSTREAM_FAILED.response()
        }
        Err(why) => {
            eprintln!(
                "[mimihubd] client lane submitMessage: the room's hub was not reached ({why})"
            );
            crate::problem::UPSTREAM_FAILED.response()
        }
    }
}

/// Send the user's update for a room on `hub` there, as this provider, and answer what it answers.
async fn relay_update(state: &LaneState, hub: &str, room: &str, update: Vec<u8>) -> Response {
    use mimi_core::protocol_wire::UpdateRoomResponse;
    let Some(access) = state.peer_access() else {
        return crate::problem::UPSTREAM_FAILED.response();
    };
    let answer =
        crate::client_lane_relay::post_to_peer(&access, hub, "update", "roomId", room, update)
            .await;
    match answer {
        Ok((200, bytes)) => match UpdateRoomResponse::decode(&bytes) {
            Ok(answer) => update_answer_json(answer, None),
            Err(_) => crate::problem::UPSTREAM_FAILED.response(),
        },
        Ok((status, _)) => {
            eprintln!("[mimihubd] client lane update: the room's hub answered {status}");
            crate::problem::UPSTREAM_FAILED.response()
        }
        Err(why) => {
            eprintln!("[mimihubd] client lane update: the room's hub was not reached ({why})");
            crate::problem::UPSTREAM_FAILED.response()
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyMaterialLaneRequest {
    /// The client's `KeyMaterialRequest`, signed with its MLS key.
    request: String,
}

#[derive(Serialize)]
struct KeyMaterialLaneAnswer {
    /// The `KeyMaterialResponse`, as the room's hub answered it.
    response: String,
}

/// KeyPackages for the user to add someone to a room, fetched through the room's hub (protocol-07 §5.2): answered
/// here for a room hosted here, sent to the room's hub otherwise (`client_lane_relay.rs`).
async fn key_material(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    use crate::client_lane_relay::{check_key_material_request, KeyMaterialRefusal};
    let Some(request) = parse::<KeyMaterialLaneRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let Ok(bytes) = STANDARD.decode(&request.request) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let Ok(decoded) = mimi_core::protocol_wire::KeyMaterialRequest::decode(&bytes) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    match check_key_material_request(&decoded, &user.user) {
        Ok(()) => {}
        Err(KeyMaterialRefusal::NotTheUser) => return crate::problem::NOT_PERMITTED.response(),
        Err(KeyMaterialRefusal::NoRoom) => return crate::problem::MALFORMED_REQUEST.response(),
    }
    if !state
        .key_material
        .admit(&user.user, &decoded.target_user.0, now_seconds())
    {
        return crate::problem::CLIENT_RATE_LIMITED.response();
    }
    let room = decoded.room_id.0.clone();
    let target = decoded.target_user.0.clone();
    let answer = match state.other_hub(&room) {
        None => crate::http::key_material_answer(&state.provider, target, &decoded, bytes).await,
        Some(hub) => {
            let Some(access) = state.peer_access() else {
                return crate::problem::UPSTREAM_FAILED.response();
            };
            let accepted = crate::http::lock(&state.provider)
                .accepted_suites()
                .to_vec();
            match crate::key_material_proxy::forward_key_material(&access, &hub, &target, bytes)
                .await
            {
                // An answer that does not decode as a KeyMaterialResponse, its KeyPackages suite-gated, is not passed on.
                Ok(bytes) => {
                    match mimi_core::protocol_wire::KeyMaterialResponse::decode(&bytes, &accepted) {
                        Ok(_) => Ok(bytes),
                        Err(error) => {
                            eprintln!("[mimihubd] client lane keyMaterial: the room's hub answered something that does not decode ({error})");
                            Err(crate::problem::UPSTREAM_FAILED.response())
                        }
                    }
                }
                Err(why) => {
                    eprintln!("[mimihubd] client lane keyMaterial: the room's hub was not reached ({why})");
                    Err(crate::problem::UPSTREAM_FAILED.response())
                }
            }
        }
    };
    match answer {
        Ok(bytes) => Json(KeyMaterialLaneAnswer {
            response: STANDARD.encode(bytes),
        })
        .into_response(),
        Err(response) => response,
    }
}
