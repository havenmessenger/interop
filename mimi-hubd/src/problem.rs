//! RFC 9457 problem details for the refusals that carry one. Each problem type is named by a URI into
//! `docs/problems.md`, the page that says what it means. A problem body names the condition only: never a user, a
//! client or a room.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// The media type of a problem body (RFC 9457 §3).
pub const PROBLEM_JSON: &str = "application/problem+json";

/// The page each problem type's URI points into.
const PROBLEMS_PAGE: &str = "https://github.com/havenmessenger/interop/blob/main/docs/problems.md";

/// The problem type an answer carries, as a response extension, for the telemetry record (`crate::telemetry`).
#[derive(Clone, Copy, Debug)]
pub struct ProblemAnchor(pub &'static str);

/// A problem type: its anchor on the problems page, its title and the status it is answered with.
pub struct ProblemType {
    pub anchor: &'static str,
    pub title: &'static str,
    pub status: StatusCode,
    pub detail: &'static str,
}

/// A `notify` (protocol-07 §5.5) carrying a Commit, proposals or an application message for a room hosted on another hub
/// that no user of this provider is a member of: refused, rather than accepted and delivered to nobody.
pub const NO_LOCAL_MEMBER: ProblemType = ProblemType {
    anchor: "no-local-member",
    title: "Not delivered: no member of the room here",
    status: StatusCode::NOT_FOUND,
    detail: "No user of this provider is a member of the room: no Welcome for it has named one.",
};

/// A request this hub cannot read: its body, path or query does not decode, or names something it does not take.
pub const MALFORMED_REQUEST: ProblemType = ProblemType {
    anchor: "malformed-request",
    title: "The request could not be read",
    status: StatusCode::BAD_REQUEST,
    detail: "The body, path or query does not decode as this endpoint's request, or names a room this hub does not host.",
};

/// A KeyPackage or Welcome the gate refuses.
pub const MATERIAL_NOT_ACCEPTED: ProblemType = ProblemType {
    anchor: "material-not-accepted",
    title: "The KeyPackage or Welcome is not accepted",
    status: StatusCode::BAD_REQUEST,
    detail: "It does not decode, its ciphersuite is not one this hub accepts, or it fails the hub's checks.",
};

/// A message for the JSON lane's queue that the queue's bounds refuse.
pub const MESSAGE_NOT_QUEUED: ProblemType = ProblemType {
    anchor: "message-not-queued",
    title: "The message was not queued",
    status: StatusCode::BAD_REQUEST,
    detail: "It is empty or too large, or its recipient's queue is full or not one this hub keeps.",
};

/// No provider proof, one that does not verify, or a `From` header naming another provider.
pub const NOT_AUTHENTICATED: ProblemType = ProblemType {
    anchor: "not-authenticated",
    title: "The requesting provider is not authenticated",
    status: StatusCode::FORBIDDEN,
    detail: "The request carries no proof of its provider that this hub accepts, or names a provider its proof does not authenticate.",
};

/// An authenticated provider asking for something only another provider may do.
pub const NOT_PERMITTED: ProblemType = ProblemType {
    anchor: "not-permitted",
    title: "The requesting provider may not do this",
    status: StatusCode::FORBIDDEN,
    detail: "The request is for a user of another provider, and only that provider may make it.",
};

/// A `notify` from a provider that is not the room's hub.
pub const NOT_THE_ROOMS_HUB: ProblemType = ProblemType {
    anchor: "not-the-rooms-hub",
    title: "Not from the room's hub",
    status: StatusCode::FORBIDDEN,
    detail: "Only the hub that hosts a room sends a notify for it, and the request's provider is not that hub.",
};

/// `authorizeSender`'s refusal: the sender may not send in the room.
pub const SENDER_NOT_ALLOWED: ProblemType = ProblemType {
    anchor: "sender-not-allowed",
    title: "The sender may not send in this room",
    status: StatusCode::FORBIDDEN,
    detail: "The sender is not an active participant of the room, was removed, or its role does not hold canSendMessage.",
};

/// Nothing answers the request: no such route, nothing queued, no KeyPackage, or an identifier not found. One answer
/// for all of them, so it says nothing about which.
pub const NOT_FOUND: ProblemType = ProblemType {
    anchor: "not-found",
    title: "Not found",
    status: StatusCode::NOT_FOUND,
    detail: "Nothing here answers this request.",
};

/// `groupInfo` for a room this hub does not host.
pub const ROOM_NOT_HOSTED: ProblemType = ProblemType {
    anchor: "room-not-hosted",
    title: "The room is not hosted here",
    status: StatusCode::NOT_FOUND,
    detail: "This hub is not the hub of the room the request names.",
};

/// A request with a method the route does not take.
pub const METHOD_NOT_ALLOWED: ProblemType = ProblemType {
    anchor: "method-not-allowed",
    title: "Method not allowed",
    status: StatusCode::METHOD_NOT_ALLOWED,
    detail: "The route does not take this method; the Allow header names the ones it takes.",
};

/// An operator's change to a room whose ratchet tree the hub keeps: its list and policy are changed by Commit.
pub const ROOM_IS_TRACKED: ProblemType = ProblemType {
    anchor: "room-is-tracked",
    title: "The room is changed by Commit",
    status: StatusCode::CONFLICT,
    detail: "The hub keeps this room's ratchet tree, so its participant list and policy change only by a Commit.",
};

/// A body larger than the endpoint takes.
pub const BODY_TOO_LARGE: ProblemType = ProblemType {
    anchor: "body-too-large",
    title: "The request is too large",
    status: StatusCode::PAYLOAD_TOO_LARGE,
    detail: "The body is larger than this endpoint takes.",
};

/// A consent entry whose operation the endpoint does not take (protocol-07 §5.7).
pub const WRONG_OPERATION: ProblemType = ProblemType {
    anchor: "wrong-operation",
    title: "Wrong consent operation",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    detail: "requestConsent takes request and cancel; updateConsent takes grant and revoke.",
};

/// The hub's own failure.
pub const INTERNAL_ERROR: ProblemType = ProblemType {
    anchor: "internal-error",
    title: "The hub failed",
    status: StatusCode::INTERNAL_SERVER_ERROR,
    detail: "The hub could not complete the request; the fault is the hub's own.",
};

/// Another provider this request had to reach did not answer usably.
pub const UPSTREAM_FAILED: ProblemType = ProblemType {
    anchor: "upstream-failed",
    title: "Another provider did not answer",
    status: StatusCode::BAD_GATEWAY,
    detail: "The request had to be forwarded to another provider, which could not be reached or answered with something this hub cannot read.",
};

/// A client-lane request that the lane did not authenticate.
pub const CLIENT_NOT_AUTHENTICATED: ProblemType = ProblemType {
    anchor: "client-not-authenticated",
    title: "The client lane request is not authenticated",
    status: StatusCode::UNAUTHORIZED,
    detail: "The request carries no lane signature this hub accepts, or acts for no user of this provider.",
};

/// A client-lane caller sent more requests for one user than the lane takes in a minute.
pub const CLIENT_RATE_LIMITED: ProblemType = ProblemType {
    anchor: "client-rate-limited",
    title: "Too many client lane requests for this user",
    status: StatusCode::TOO_MANY_REQUESTS,
    detail:
        "The lane takes a bounded number of requests per user per minute. Retry after a minute.",
};

/// A requesting provider, or a requester, asked for one target's KeyPackages more often than the hub takes in an hour.
pub const KEY_MATERIAL_RATE_LIMITED: ProblemType = ProblemType {
    anchor: "key-material-rate-limited",
    title: "Too many keyMaterial requests for this target",
    status: StatusCode::TOO_MANY_REQUESTS,
    detail: "The hub takes a bounded number of keyMaterial requests from one requesting provider, and from one requester, for one target user in an hour. Retry after an hour.",
};

/// Every problem type, for the page check and the fallback.
pub const ALL: [&ProblemType; 19] = [
    &CLIENT_NOT_AUTHENTICATED,
    &CLIENT_RATE_LIMITED,
    &KEY_MATERIAL_RATE_LIMITED,
    &NO_LOCAL_MEMBER,
    &MALFORMED_REQUEST,
    &MATERIAL_NOT_ACCEPTED,
    &MESSAGE_NOT_QUEUED,
    &NOT_AUTHENTICATED,
    &NOT_PERMITTED,
    &NOT_THE_ROOMS_HUB,
    &SENDER_NOT_ALLOWED,
    &NOT_FOUND,
    &ROOM_NOT_HOSTED,
    &METHOD_NOT_ALLOWED,
    &ROOM_IS_TRACKED,
    &BODY_TOO_LARGE,
    &WRONG_OPERATION,
    &INTERNAL_ERROR,
    &UPSTREAM_FAILED,
];

/// The answer for an error status no handler gave a problem body (one axum answers itself, such as an unmatched route,
/// a wrong method or an extractor's rejection): the type for that status, or `http-error` for any other.
fn for_status(status: StatusCode) -> (&'static str, Body) {
    let known = match status {
        StatusCode::BAD_REQUEST => Some(&MALFORMED_REQUEST),
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => Some(&NOT_AUTHENTICATED),
        StatusCode::NOT_FOUND => Some(&NOT_FOUND),
        StatusCode::METHOD_NOT_ALLOWED => Some(&METHOD_NOT_ALLOWED),
        StatusCode::CONFLICT => Some(&ROOM_IS_TRACKED),
        StatusCode::PAYLOAD_TOO_LARGE => Some(&BODY_TOO_LARGE),
        StatusCode::UNPROCESSABLE_ENTITY => Some(&WRONG_OPERATION),
        StatusCode::INTERNAL_SERVER_ERROR => Some(&INTERNAL_ERROR),
        StatusCode::BAD_GATEWAY => Some(&UPSTREAM_FAILED),
        _ => None,
    };
    match known.filter(|problem| problem.status == status) {
        Some(problem) => (problem.anchor, problem.body()),
        None => (
            "http-error",
            Body {
                kind: format!("{PROBLEMS_PAGE}#http-error"),
                title: "The request was refused",
                status: status.as_u16(),
                detail: "The HTTP status says why; no more specific type applies.",
            },
        ),
    }
}

/// A layer for every listener: an error answer (4xx or 5xx) that carries no problem body gets one, the type its status
/// maps to, so no refusal goes out as an empty body or as text written for a log. Headers the answer set, such as
/// `Allow` or `Retry-After`, are kept.
pub async fn fallback(response: Response) -> Response {
    let status = response.status();
    let is_problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes() == PROBLEM_JSON.as_bytes());
    if !(status.is_client_error() || status.is_server_error()) || is_problem {
        return response;
    }
    let (mut parts, _) = response.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    parts
        .headers
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
    let (anchor, body) = for_status(status);
    parts.extensions.insert(ProblemAnchor(anchor));
    let json = serde_json::to_vec(&body).unwrap_or_default();
    Response::from_parts(parts, axum::body::Body::from(json))
}

#[derive(Serialize)]
struct Body {
    #[serde(rename = "type")]
    kind: String,
    title: &'static str,
    status: u16,
    detail: &'static str,
}

impl ProblemType {
    /// The problem type's URI.
    pub fn uri(&self) -> String {
        format!("{PROBLEMS_PAGE}#{}", self.anchor)
    }

    fn body(&self) -> Body {
        Body {
            kind: self.uri(),
            title: self.title,
            status: self.status.as_u16(),
            detail: self.detail,
        }
    }

    /// The answer: the problem's status, `Content-Type: application/problem+json`, and the body.
    pub fn response(&self) -> Response {
        let json = serde_json::to_vec(&self.body()).unwrap_or_default();
        let mut response = (self.status, json).into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
        response.extensions_mut().insert(ProblemAnchor(self.anchor));
        response
    }
}

#[cfg(test)]
#[path = "problem_tests.rs"]
mod tests;
