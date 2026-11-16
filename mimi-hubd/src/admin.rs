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
//!
//! The listener is safe without credentials only while nothing a peer sends can make the hub connect to it. The hub
//! makes no requests to other hubs; see DIVERGENCES.md for what an outbound request will have to refuse.

use std::net::SocketAddr;

use axum::{routing::post, Router};

use crate::http::{
    add_participant, server_header, set_member_role, set_room_policy, SharedProvider,
};

/// The operator's routes and nothing else, for the loopback listener [`admin_bind_addr`] accepts.
pub fn build_admin_router(provider: SharedProvider) -> Router {
    Router::new()
        .route("/mimi/v1/roomPolicy", post(set_room_policy))
        .route("/mimi/v1/memberRole", post(set_member_role))
        .route("/mimi/v1/addParticipant", post(add_participant))
        .with_state(provider)
        .layer(axum::middleware::map_response(server_header))
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
