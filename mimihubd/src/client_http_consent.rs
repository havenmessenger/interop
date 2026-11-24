//! The client lane's consent routes (`client_lane_consent.rs` has what each decides). Every one acts for the lane user
//! alone.

use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use super::{internal, now_unix, parse, LaneState};
use crate::client_lane::LaneUser;
use crate::client_lane_consent::{ConsentMessage, ConsentRequester, LaneConsentRefusal};

/// The most requests one `consentRequests` answer lists.
// LIMIT-REASON: page: one answer stays small; the client pages on with `after`
const MAX_REQUESTS_PAGE: usize = 100;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideRequest {
    #[serde(default)]
    requester: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    room: Option<String>,
    decision: String,
}

#[derive(Serialize)]
struct Notified {
    /// Whether the requester's provider took the decision; false when nothing was sent.
    notified: bool,
}

fn refused(refusal: LaneConsentRefusal) -> Response {
    match refusal {
        LaneConsentRefusal::Malformed(why) => {
            eprintln!("[mimihubd] client lane consent: {why}");
            crate::problem::MALFORMED_REQUEST.response()
        }
        LaneConsentRefusal::NotPermitted(why) => {
            eprintln!("[mimihubd] client lane consent: {why}");
            crate::problem::NOT_PERMITTED.response()
        }
    }
}

/// Send `message` to its provider as this provider; true when it took it. A peer's consent routes answer `202
/// Accepted` whatever they did with it (protocol-07 §5.7 says nothing back), so any 2xx is taken, and anything else not.
async fn send(state: &LaneState, message: ConsentMessage) -> bool {
    let Some(access) = state.peer_access() else {
        eprintln!(
            "[mimihubd] client lane consent: no outbound client, so {} was not sent to {}",
            message.endpoint, message.domain
        );
        return false;
    };
    match crate::client_lane_relay::post_to_peer(
        &access,
        &message.domain,
        message.endpoint,
        message.variable,
        &message.domain,
        message.body,
    )
    .await
    {
        Ok((200..=299, _)) => true,
        Ok((status, _)) => {
            eprintln!(
                "[mimihubd] client lane consent: {} answered {status} to {}",
                message.domain, message.endpoint
            );
            false
        }
        Err(why) => {
            eprintln!(
                "[mimihubd] client lane consent: {} was not reached for {} ({why})",
                message.domain, message.endpoint
            );
            false
        }
    }
}

/// `consent`: the user grants or revokes a requester's access to their KeyPackages.
pub(super) async fn consent(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    let Some(request) = parse::<DecideRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let grant = match request.decision.as_str() {
        "grant" => true,
        "revoke" => false,
        _ => return crate::problem::MALFORMED_REQUEST.response(),
    };
    let requester = match (request.requester, request.provider) {
        (Some(user), None) => ConsentRequester::User(user),
        (None, Some(domain)) => ConsentRequester::Provider(domain),
        _ => return crate::problem::MALFORMED_REQUEST.response(),
    };
    let decided = crate::http::lock(&state.provider).lane_decide_consent(
        &user.user,
        &requester,
        request.room.as_deref(),
        grant,
        now_unix(),
    );
    let message = match decided {
        Ok(Ok(message)) => message,
        Ok(Err(refusal)) => return refused(refusal),
        Err(error) => return internal("consent", error),
    };
    let notified = match message {
        Some(message) => send(&state, message).await,
        None => false,
    };
    Json(Notified { notified }).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AskRequest {
    target: String,
    #[serde(default)]
    room: Option<String>,
    #[serde(default)]
    cancel: bool,
}

#[derive(Serialize)]
struct Delivered {
    /// Whether the target's provider took the request: true for a target of this provider, where it is recorded.
    delivered: bool,
}

/// `requestConsent`: the user asks a user for consent, or cancels that request.
pub(super) async fn request_consent(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    let Some(request) = parse::<AskRequest>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let asked = crate::http::lock(&state.provider).lane_request_consent(
        &user.user,
        &request.target,
        request.room.as_deref(),
        request.cancel,
        now_unix(),
    );
    let delivered = match asked {
        Ok(Ok(None)) => true,
        Ok(Ok(Some(message))) => send(&state, message).await,
        Ok(Err(refusal)) => return refused(refusal),
        Err(error) => return internal("requestConsent", error),
    };
    Json(Delivered { delivered }).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestsQuery {
    #[serde(default)]
    after: i64,
    #[serde(default = "default_page")]
    limit: usize,
}

fn default_page() -> usize {
    MAX_REQUESTS_PAGE
}

#[derive(Serialize)]
struct Requests {
    requests: Vec<RequestItem>,
}

#[derive(Serialize)]
struct RequestItem {
    seq: i64,
    requester: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    room: Option<String>,
    at: u64,
}

/// `consentRequests`: the requests made of the user and still pending, oldest first.
pub(super) async fn consent_requests(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    let Some(query) = parse::<RequestsQuery>(&body) else {
        return crate::problem::MALFORMED_REQUEST.response();
    };
    let listed = crate::http::lock(&state.provider).lane_consent_requests(
        &user.user,
        query.after,
        query.limit.min(MAX_REQUESTS_PAGE),
        now_unix(),
    );
    match listed {
        Ok(requests) => Json(Requests {
            requests: requests
                .into_iter()
                .map(|request| RequestItem {
                    seq: request.seq,
                    requester: request.requester,
                    room: request.room,
                    at: request.at,
                })
                .collect(),
        })
        .into_response(),
        Err(error) => internal("consentRequests", error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Serialize)]
struct Grants {
    grants: Vec<GrantItem>,
}

#[derive(Serialize)]
struct GrantItem {
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    room: Option<String>,
    at: u64,
}

/// `consentReceived`: the grants the user holds from other users.
pub(super) async fn consent_received(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    if parse::<Empty>(&body).is_none() {
        return crate::problem::MALFORMED_REQUEST.response();
    }
    match crate::http::lock(&state.provider).lane_consent_received(&user.user) {
        Ok(grants) => Json(Grants {
            grants: grants
                .into_iter()
                .map(|grant| GrantItem {
                    target: grant.target,
                    room: grant.room,
                    at: grant.at,
                })
                .collect(),
        })
        .into_response(),
        Err(error) => internal("consentReceived", error),
    }
}

#[derive(Serialize)]
struct OptedOut {
    /// KeyPackages withdrawn.
    count: usize,
    /// Consent decisions and requests cleared.
    cleared: usize,
}

/// `optOut`: the user leaves MIMI here: their KeyPackages are withdrawn and their consent cleared, as the policy says.
pub(super) async fn opt_out(
    State(state): State<LaneState>,
    Extension(user): Extension<LaneUser>,
    body: Bytes,
) -> Response {
    if parse::<Empty>(&body).is_none() {
        return crate::problem::MALFORMED_REQUEST.response();
    }
    match crate::http::lock(&state.provider).lane_opt_out(&user.user) {
        Ok((count, cleared)) => Json(OptedOut { count, cleared }).into_response(),
        Err(error) => internal("optOut", error),
    }
}
