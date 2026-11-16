//! The hub operator's own routes: setting a room's policy, a member's role and its participants on this hub.
//!
//! These are not MIMI routes; protocol-07 has no endpoint for them, and a peer changes a room's roster or policy through
//! `update`. They are served only on a listener of their own, bound to a loopback address, with no client certificate:
//! the operator is whoever can reach that address on the hub's host, the same person who can run `mimi-hubd enroll` or
//! open the hub's store. The peer-facing listener does not mount them, so a peer gets a 404.
//!
//!   POST /mimi/v1/roomPolicy?room=                  (P1-P6, set a room's RBAC policy)
//!   POST /mimi/v1/memberRole?room=&member=&role=    (P1, assign a member's role)
//!   POST /mimi/v1/addParticipant?room=&member=      (R1, register a room participant)
//!   POST /mimi/v1/untrackRoom?room=                 (drop a room's ratchet tree; its next full bundle seeds it again)
//!   GET  /mimi/v1/outbox                            (each queue of fan-out waiting for another provider)
//!   POST /mimi/v1/dropOutbox?room=&domain=          (drop one such queue, every row of it)
//!
//! The listener is safe without credentials only while nothing a peer sends can make the hub connect to it. The hub's
//! one outbound client (`outbound.rs`) refuses loopback unless the operator allowlists it, and speaks only TLS, which
//! this plain-HTTP listener does not answer.

use std::net::SocketAddr;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::http::{
    add_participant, server_header, set_member_role, set_room_policy, untrack_room, SharedProvider,
};

/// The operator's routes and nothing else, for the loopback listener [`admin_bind_addr`] accepts.
pub fn build_admin_router(provider: SharedProvider) -> Router {
    Router::new()
        .route("/mimi/v1/roomPolicy", post(set_room_policy))
        .route("/mimi/v1/memberRole", post(set_member_role))
        .route("/mimi/v1/addParticipant", post(add_participant))
        .route("/mimi/v1/untrackRoom", post(untrack_room))
        .route("/mimi/v1/outbox", get(outbox))
        .route("/mimi/v1/dropOutbox", post(drop_outbox))
        .with_state(provider)
        .layer(axum::middleware::map_response(server_header))
}

fn lock(provider: &SharedProvider) -> std::sync::MutexGuard<'_, crate::Provider> {
    provider
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Every outbox queue: room, domain, depth, oldest row, and its head's attempts and last outcome.
async fn outbox(State(provider): State<SharedProvider>) -> Response {
    match lock(&provider).store.outbox_queues() {
        Ok(queues) => Json(queues).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
struct DropOutboxQuery {
    room: String,
    domain: String,
}

/// Drop the queue for one room and domain; answers how many rows it held.
async fn drop_outbox(
    State(provider): State<SharedProvider>,
    Query(query): Query<DropOutboxQuery>,
) -> Response {
    match lock(&provider)
        .store
        .drop_outbox_queue(&query.room, &query.domain)
    {
        Ok(dropped) => {
            eprintln!(
                "[mimi-hubd] outbox: the operator dropped {dropped} row(s) for {} to {}",
                query.room, query.domain
            );
            Json(serde_json::json!({ "dropped": dropped })).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The address the operator's listener binds, from its setting: an `ip:port` whose address is loopback (127.0.0.0/8 or
/// `::1`). Anything else is refused, a hostname included, because the listener asks for no credential and must not be
/// reachable from another machine.
pub fn admin_bind_addr(value: &str) -> anyhow::Result<SocketAddr> {
    let addr: SocketAddr = value.parse().map_err(|_| {
        anyhow::anyhow!(
            "MIMI_ADMIN_BIND_ADDR={value} is not an ip:port; the operator listener takes a loopback address, such as 127.0.0.1:8445"
        )
    })?;
    if !addr.ip().is_loopback() {
        anyhow::bail!(
            "MIMI_ADMIN_BIND_ADDR={value} is not a loopback address; the operator listener asks for no credential, so it binds 127.0.0.1 or ::1 only"
        );
    }
    Ok(addr)
}

#[cfg(test)]
#[path = "admin_tests.rs"]
mod tests;
