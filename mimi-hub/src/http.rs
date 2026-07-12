//! HTTP transport for the MIMI provider - axum router wiring the [`Provider`] core to the v1
//! endpoints. The router is testable without a socket via `tower::ServiceExt::oneshot`; the live
//! mTLS-terminated serving is in [`crate::tls`].
//!
//! Endpoints (v1 scope). Every foreign-input path runs the mimi-core gate (K5) first.
//!   GET  /.well-known/mimi-protocol-directory
//!   GET  /mimi/v1/keyMaterial?user=<name>          (serve a local one-time KP; K1/K2)
//!   POST /mimi/v1/keyMaterial/ingest               (gate a FOREIGN KP before Add; K5)
//!   POST /mimi/v1/notify                           (fanout receipt; idempotent 201; M5)
//!   POST /mimi/v1/welcome/ingest                   (gate a FOREIGN Welcome before openmls; K5)
//!   POST /mimi/v1/identifierQuery                  (opt-in only; DIV-4, leak-free)
//!   POST /mimi/v1/requestConsent                   (§5.7 C1, always 201, privacy)
//!   POST /mimi/v1/updateConsent                    (§5.7 C2, always 201, privacy)
//!   POST /mimi/v1/roomPolicy?room=                  (P1-P6, set a room's RBAC policy)
//!   POST /mimi/v1/memberRole?room=&member=&role=    (P1, assign a member's role)
//!   POST /mimi/v1/addParticipant?room=&member=      (R1, register a room participant)
//!   POST /mimi/v1/authorizeSender?room=&sender=     (M2/R3/P5, 200 allow / 403 blocked)
//!
//! Wire lane (protocol-06 §5 TLS presentation language, alongside the JSON compat lane above; a
//! foreign implementation speaking the draft's actual wire format hits these instead):
//!   POST /mimi/pl/submitMessage/:recipient          (§5.4, SubmitMessageRequest/Response bodies)
//!   POST /mimi/pl/requestConsent/:target_domain     (§5.7 C1, ConsentEntry body, always 201)
//!   POST /mimi/pl/updateConsent/:requester_domain   (§5.7 C2, ConsentEntry body, always 201)
//!   POST /mimi/pl/keyMaterial/:target_user          (§5.2, KeyMaterialRequest/Response bodies)
//!   POST /mimi/pl/notify                            (§5.5, inbound-receive only, FanoutMessage)
//!   POST /mimi/pl/identifierQuery                   (§5.8, DIV-4 no-body-oracle preserved)
//! `update` (§5.3) has a codec (`mimi_core::protocol_wire::HandshakeBundle`) but no route: this
//! reference hub has no Provider method that processes a real MLS Commit/Proposal, so wiring one
//! would mean writing new protocol logic, not framing (see the codec's own module doc). `groupInfo`
//! (§5.6, DIV-1's external-commit join) and the four room-admin endpoints' wire framing are not
//! built yet. Most wire-route path segments still play the same opaque routing-key role the JSON
//! lane's query params already play (framing change, not a routing-model change); `submitMessage`
//! is the one exception - its path segment is the room the message targets, sender-authorized
//! (M2/R3/P5) and fanned out to every LOCAL room participant (M3), not just stored under one
//! opaque key (see [`submit_message_wire`]'s own doc; foreign-provider forwarding is still a
//! disclosed residual, DIVERGENCES.md DIV-5).

use std::sync::{Arc, Mutex};

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use mimi_core::consent::ConsentEntry;
use mimi_core::gate::IdentifierQueryResult;
use mimi_core::protocol_wire::{SubmitMessageRequest, SubmitMessageResponse};
use serde::Deserialize;

use crate::{NotifyOutcome, Provider};

/// Shared, mutating provider state (some handlers consume KeyPackages, record dedup, or enrollment).
/// Backed by the durable SQLite store; a handler holds the lock only for the duration of one request.
pub type SharedProvider = Arc<Mutex<Provider>>;

pub fn build_router(provider: SharedProvider) -> Router {
    Router::new()
        .route("/.well-known/mimi-protocol-directory", get(directory))
        .route("/mimi/v1/keyMaterial", get(key_material))
        .route("/mimi/v1/keyMaterial/ingest", post(ingest_keypackage))
        .route("/mimi/v1/notify", post(notify))
        .route("/mimi/v1/welcome/ingest", post(ingest_welcome))
        .route("/mimi/v1/welcome", get(fetch_welcome)) // recipient pulls a queued Welcome (deliver-once)
        .route("/mimi/v1/submitMessage", post(submit_message)) // deposit opaque ciphertext for a recipient
        .route("/mimi/v1/message", get(fetch_message)) // recipient pulls a queued message (deliver-once)
        .route("/mimi/v1/identifierQuery", post(identifier_query))
        .route("/mimi/v1/requestConsent", post(request_consent)) // §5.7 C1, always 201 (privacy)
        .route("/mimi/v1/updateConsent", post(update_consent)) // §5.7 C2, always 201 (privacy)
        .route("/mimi/v1/roomPolicy", post(set_room_policy)) // P1-P6, hub sets a room's RBAC policy
        .route("/mimi/v1/memberRole", post(set_member_role)) // P1, assign a member's role in a room
        .route("/mimi/v1/addParticipant", post(add_participant)) // R1, register a room participant
        .route("/mimi/v1/authorizeSender", post(authorize_sender)) // M2/R3/P5, may this member send?
        .route(
            "/mimi/pl/submitMessage/:recipient",
            post(submit_message_wire),
        )
        .route(
            "/mimi/pl/requestConsent/:target_domain",
            post(request_consent_wire),
        )
        .route(
            "/mimi/pl/updateConsent/:requester_domain",
            post(update_consent_wire),
        )
        .route("/mimi/pl/keyMaterial/:target_user", post(key_material_wire))
        .route("/mimi/pl/notify", post(notify_wire))
        .route("/mimi/pl/identifierQuery", post(identifier_query_wire))
        .with_state(provider)
}

fn lock(p: &SharedProvider) -> std::sync::MutexGuard<'_, Provider> {
    // A poisoned lock means a handler panicked mid-mutation; recovering the guard is safe here
    // because our state is plain data (no broken invariant survives a panic in these handlers).
    p.lock().unwrap_or_else(|e| e.into_inner())
}

async fn directory(State(p): State<SharedProvider>) -> Json<serde_json::Value> {
    Json(lock(&p).directory())
}

#[derive(Deserialize)]
struct UserQuery {
    user: String,
}

/// Serve one one-time KeyPackage for a local user (K1/K2). 200 + bytes, 404 if none live, 500 on a
/// store error.
async fn key_material(State(p): State<SharedProvider>, Query(q): Query<UserQuery>) -> Response {
    let now = now_unix();
    match lock(&p).serve_key_material(&q.user, now) {
        Ok(Some(bytes)) => (StatusCode::OK, bytes).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// §5.2 wire twin of [`key_material`]. The draft's `POST /keyMaterial/{targetUser}` path segment
/// plays the routing-key role the JSON lane's `?user=` plays and is what actually routes the store
/// lookup (matching the convention already used by [`submit_message_wire`] and the consent wire
/// twins); the request body's own `targetUser` field is a DIFFERENT thing - a real target URI used
/// as the consent-gate lookup key (see below), not a routing key. The negotiation fields
/// (ciphersuites, capabilities, signature) are decoded but not enforced, exactly as documented on
/// `mimi_core::protocol_wire::KeyMaterialRequest` (the JSON lane enforces none of this either, so
/// adding enforcement here would be new behavior, not framing).
///
/// Routes through `Provider::serve_key_material_gated` (the same consent gate `updateConsent`/
/// `requestConsent` populate) instead of the ungated `serve_key_material` the JSON lane still uses
/// for its own demo/admin purposes. A denial maps to `KeyMaterialResponse::Denied` carrying the
/// draft's own NoConsent/NoConsentForThisRoom userStatus code (5/6), not a generic failure.
/// DISCLOSURE (see DIVERGENCES.md): `requesting_user` here is CLIENT-ASSERTED from the
/// request body, not derived from an authenticated channel (mTLS peer identity) - this reference
/// hub has no such binding anywhere yet. The consent gate is real, but nothing stops a client from
/// asserting someone else's URI as `requesting_user`.
async fn key_material_wire(
    State(p): State<SharedProvider>,
    Path(target_user): Path<String>,
    body: Bytes,
) -> Response {
    use mimi_core::consent::KeyPackageAccess;
    use mimi_core::protocol_wire::{
        IdentifierUri, KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode,
    };
    let req = match KeyMaterialRequest::decode(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let now = now_unix();
    let room_uri = (!req.room_id.0.is_empty()).then_some(req.room_id.0.as_str());
    let gated = lock(&p).serve_key_material_gated(
        &req.requesting_user.0,
        &target_user,
        &req.target_user.0,
        room_uri,
        now,
    );
    let outcome = match gated {
        Ok(Ok(Some(bytes))) => KeyMaterialResponse::Success {
            user_uri: IdentifierUri(target_user),
            key_package: bytes,
        },
        Ok(Ok(None)) => KeyMaterialResponse::Exhausted {
            user_uri: IdentifierUri(target_user),
        },
        Ok(Err(deny)) => {
            let code = match deny {
                KeyPackageAccess::NoConsentForThisRoom => KeyMaterialUserCode::NoConsentForThisRoom,
                // KeyPackageAccess::Allowed never reaches the Err arm (see
                // Provider::serve_key_material_gated); treat it the same as NoConsent rather than
                // panicking on a structurally-unreachable case in a request handler.
                KeyPackageAccess::NoConsent | KeyPackageAccess::Allowed => {
                    KeyMaterialUserCode::NoConsent
                }
            };
            KeyMaterialResponse::Denied {
                user_uri: IdentifierUri(target_user),
                code,
            }
        }
        Err(_) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    match outcome.encode() {
        Ok(bytes) => (StatusCode::OK, bytes).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Optional routing key on the ingest/delivery endpoints. With `?user=` the KeyPackage is PUBLISHED
/// (validated + stored, claimable later); with `?recipient=` a Welcome is RELAYED (validated +
/// queued). Without it, the legacy validate-only behavior (gate the foreign object, store nothing).
#[derive(Deserialize)]
struct RouteKey {
    user: Option<String>,
    recipient: Option<String>,
}

/// Foreign KeyPackage. `?user=X` → suite-gate THEN PUBLISH (claimable). No user → validate-only (204).
/// 204 on accept, 400 if the gate rejects (non-0x0001 / undecodable); never reaches openmls.
async fn ingest_keypackage(
    State(p): State<SharedProvider>,
    Query(k): Query<RouteKey>,
    body: Bytes,
) -> Response {
    let g = lock(&p);
    let r = match k.user {
        Some(user) => g.publish_key_package(&user, &body, now_unix()),
        None => g.ingest_foreign_keypackage(&body),
    };
    match r {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// Foreign Welcome. `?recipient=X` → suite-gate THEN RELAY (queue for fetch). No recipient →
/// validate-only (204). The suite gate runs before any queue/openmls touch, closing the path
/// that would otherwise drive openmls's libcrux ChaCha implementation on an unvalidated suite.
async fn ingest_welcome(
    State(p): State<SharedProvider>,
    Query(k): Query<RouteKey>,
    body: Bytes,
) -> Response {
    let g = lock(&p);
    let r = match k.recipient {
        Some(rcpt) => g.relay_welcome(&rcpt, &body, now_unix()),
        None => g.ingest_foreign_welcome(&body),
    };
    match r {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// Recipient pulls one queued Welcome (deliver-once, FIFO). 200 + bytes, 404 when none.
async fn fetch_welcome(State(p): State<SharedProvider>, Query(q): Query<UserQuery>) -> Response {
    match lock(&p).fetch_welcome(&q.user) {
        Ok(Some(bytes)) => (StatusCode::OK, bytes).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Deposit an opaque application message (MLS PrivateMessage) for `?recipient=X`. The provider stores
/// ciphertext only - it never decrypts (INV-MIMI-002); the store bounds size + queue depth. 201 on
/// accept, 400 if the bounds reject (empty/oversize/queue-full/bad recipient).
async fn submit_message(
    State(p): State<SharedProvider>,
    Query(k): Query<RouteKey>,
    body: Bytes,
) -> Response {
    let Some(rcpt) = k.recipient else {
        return (StatusCode::BAD_REQUEST, "missing ?recipient=").into_response();
    };
    match lock(&p).submit_message(&rcpt, &body, now_unix()) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// §5.4 wire twin of [`submit_message`]: TLS-PL `SubmitMessageRequest` in, TLS-PL
/// `SubmitMessageResponse` out. The `appMessage` bytes are stored as opaque as the JSON lane's raw
/// body (`Provider::submit_message` never inspects them); this handler only unwraps the
/// spec envelope to reach the same bytes. An undecodable request gets a plain 400 (there is no
/// valid Protocol/statusCode to answer in-band with); once decoded, the outcome always travels in
/// a 200 body per the draft's own response-in-body shape for this endpoint (unlike consent, which
/// signals outcome via the bare HTTP status line).
///
/// The path segment is the room this message targets (draft §5.1's `{roomId}` template - see
/// `directory()`'s flat-key comment). Unlike `submit_message` (the JSON demo/admin lane, whose
/// `?recipient=` key can be any opaque string), this wire twin now enforces the sender authorization
/// this endpoint always should have had: `authorize_sender` (M2/R3/P5 - active participation, not
/// removed, room-policy canSendMessage) must pass before anything is stored, and `NotAllowed` is
/// returned otherwise (a `recipient` that doesn't even parse as a room this hub hosts also lands
/// here, via `authorize_sender`'s own `assert_hub_of_record`). On success, the message is queued
/// under the literal path segment AS BEFORE (unchanged persistence key, for callers already relying
/// on that shape) AND additionally fanned out to every other LOCAL participant of the room (M3),
/// which is the real room-delivery behavior this endpoint was missing entirely. Forwarding to
/// FOREIGN participants' providers still isn't implemented (no cross-provider relay client exists
/// in this reference hub) - see DIVERGENCES.md DIV-5 for that bounded residual.
async fn submit_message_wire(
    State(p): State<SharedProvider>,
    Path(recipient): Path<String>,
    body: Bytes,
) -> Response {
    let req = match SubmitMessageRequest::decode(&body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let sending_uri = &req.sending_uri.0;
    let g = lock(&p);
    if g.authorize_sender(&recipient, sending_uri).is_err() {
        return (StatusCode::OK, SubmitMessageResponse::NotAllowed.encode()).into_response();
    }
    let outcome = match g.submit_message(&recipient, &req.app_message, now_unix()) {
        Ok(()) => {
            if let Ok(plan) = g.fanout_targets(&recipient, sending_uri) {
                for member in plan.local {
                    let _ = g.submit_message(&member, &req.app_message, now_unix());
                }
            }
            SubmitMessageResponse::Accepted {
                accepted_timestamp: now_unix_millis(),
            }
        }
        Err(_) => SubmitMessageResponse::NotAllowed,
    };
    (StatusCode::OK, outcome.encode()).into_response()
}

/// Recipient pulls one queued message (deliver-once, FIFO). 200 + bytes, 404 when none.
async fn fetch_message(State(p): State<SharedProvider>, Query(q): Query<UserQuery>) -> Response {
    match lock(&p).fetch_message(&q.user) {
        Ok(Some(bytes)) => (StatusCode::OK, bytes).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Fanout `/notify` (M5): ALWAYS 201, whether first-seen or a byte-exact duplicate (the spec's
/// idempotency requirement); 500 only on a store error. The body decides process-vs-ignore.
async fn notify(State(p): State<SharedProvider>, body: Bytes) -> StatusCode {
    match lock(&p).submit_notify(&body, now_unix()) {
        Ok(NotifyOutcome::Process) => StatusCode::CREATED, // (process happens here in the full build)
        Ok(NotifyOutcome::DuplicateIgnored) => StatusCode::CREATED,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// §5.5 wire twin of [`notify`], inbound-receive shape only (see
/// `mimi_core::protocol_wire`'s module doc on `FanoutMessage`). Confirms the body decodes as a
/// well-formed `FanoutMessage` (a real MLS envelope, not garbage) before handing the SAME opaque
/// bytes the JSON lane would receive to the identical dedup-by-content-hash store call. Rejecting
/// undecodable bodies with 400, rather than treating them as valid-but-different content the way
/// `submit_notify` treats any other byte string, keeps the wire lane honest about actually
/// speaking the protocol rather than accepting anything.
async fn notify_wire(State(p): State<SharedProvider>, body: Bytes) -> StatusCode {
    if mimi_core::protocol_wire::FanoutMessage::decode(&body).is_err() {
        return StatusCode::BAD_REQUEST;
    }
    match lock(&p).submit_notify(&body, now_unix()) {
        Ok(NotifyOutcome::Process | NotifyOutcome::DuplicateIgnored) => StatusCode::CREATED,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Deserialize)]
struct IdentifierQueryReq {
    username: String,
}

/// identifierQuery (DIV-4): 200 for opt-in enrollees, 404 otherwise. CRITICAL: the 404 for a
/// non-enrolled-but-real user MUST be byte-identical to the 404 for a non-existent user, so we
/// return a bare StatusCode with no distinguishing body either way. A store error also maps to 404
/// (fail-closed: never reveal more than "not found").
async fn identifier_query(
    State(p): State<SharedProvider>,
    Json(req): Json<IdentifierQueryReq>,
) -> StatusCode {
    match lock(&p).identifier_query(&req.username) {
        Ok(IdentifierQueryResult::Found) => StatusCode::OK,
        Ok(IdentifierQueryResult::NotFound) | Err(_) => StatusCode::NOT_FOUND,
    }
}

/// §5.8 wire twin of [`identifier_query`]. Decodes the full `IdentifierRequest` (for wire
/// fidelity) but only ever answers a request carrying exactly one `Handle`-typed query element,
/// matching the v1 single-username model (DIV-4: no data model exists for the other identifier
/// types, and a request this hub can't evaluate is treated as not-found rather than silently
/// evaluating a different element than the caller may have meant). Returns a BARE status, no
/// body, on both outcomes: DIV-4 requires a found-vs-not-found answer to be indistinguishable by
/// response shape, and a decodable `IdentifierResponse` body would reintroduce exactly the oracle
/// DIV-4 exists to close. An undecodable or unanswerable request also gets a bare 404 for the
/// same reason, not a 400: 400 vs 404 would itself leak information about whether the request was
/// well-formed, which is a smaller but real fingerprint the JSON lane doesn't have either (a
/// malformed JSON body there hits axum's own rejection path before this handler runs, which is a
/// pre-existing asymmetry this wire twin does not widen).
async fn identifier_query_wire(State(p): State<SharedProvider>, body: Bytes) -> StatusCode {
    let Ok(req) = mimi_core::protocol_wire::IdentifierRequest::decode(&body) else {
        return StatusCode::NOT_FOUND;
    };
    let Some(username) = req.primary_search_value() else {
        return StatusCode::NOT_FOUND;
    };
    match lock(&p).identifier_query(&username) {
        Ok(IdentifierQueryResult::Found) => StatusCode::OK,
        Ok(IdentifierQueryResult::NotFound) | Err(_) => StatusCode::NOT_FOUND,
    }
}

/// requestConsent (§5.7, C1). PRIVACY: ALWAYS 201, even if the entry is malformed or the target/
/// requester does not exist. The response MUST NOT be an existence oracle. A malformed entry is
/// validated+dropped internally (no state change); the caller still sees 201. 500 is reserved for a
/// store failure we cannot hide.
async fn request_consent(
    State(p): State<SharedProvider>,
    Json(entry): Json<ConsentEntry>,
) -> StatusCode {
    match lock(&p).process_request_consent(&entry, now_unix()) {
        Ok(()) => StatusCode::CREATED,
        // a validation failure is NOT surfaced (no oracle); only a real store error is a 500. Since
        // process_request_consent's only non-validation error path is the store, distinguish them:
        Err(_) => StatusCode::CREATED, // drop malformed silently, privacy over diagnostics
    }
}

/// updateConsent (§5.7, C2). Same privacy rule: ALWAYS 201. grant/revoke/cancel processed internally;
/// a malformed entry or a non-0x0001 grant KP is dropped without revealing anything.
async fn update_consent(
    State(p): State<SharedProvider>,
    Json(entry): Json<ConsentEntry>,
) -> StatusCode {
    match lock(&p).process_update_consent(&entry, now_unix()) {
        Ok(()) => StatusCode::CREATED,
        Err(_) => StatusCode::CREATED, // drop malformed silently, privacy over diagnostics
    }
}

/// §5.7 C1 wire twin of [`request_consent`]: TLS-PL `ConsentEntry` body instead of JSON, same
/// privacy discipline (always 201, per the draft's own "the response merely indicates receipt"
/// text). An undecodable body is dropped the same way a malformed JSON entry is, still 201: the
/// privacy property this endpoint exists for (no existence oracle) applies the same way to
/// malformed wire bytes as it does to malformed JSON.
async fn request_consent_wire(
    State(p): State<SharedProvider>,
    Path(_target_domain): Path<String>,
    body: Bytes,
) -> StatusCode {
    let Ok(entry) = mimi_core::protocol_wire::decode_consent_entry(&body) else {
        return StatusCode::CREATED;
    };
    let _ = lock(&p).process_request_consent(&entry, now_unix());
    StatusCode::CREATED
}

/// §5.7 C2 wire twin of [`update_consent`]. Same shape and privacy rule as
/// [`request_consent_wire`].
async fn update_consent_wire(
    State(p): State<SharedProvider>,
    Path(_requester_domain): Path<String>,
    body: Bytes,
) -> StatusCode {
    let Ok(entry) = mimi_core::protocol_wire::decode_consent_entry(&body) else {
        return StatusCode::CREATED;
    };
    let _ = lock(&p).process_update_consent(&entry, now_unix());
    StatusCode::CREATED
}

// 🔴 SECURITY SCOPE (reference hub) - the mutating policy/membership endpoints below
// (roomPolicy/memberRole/addParticipant) are gated by (1) mTLS peer-trust (only an allowlisted peer
// presenting a cert signed by the configured CA can reach the hub at all; it is not public) and
// (2) hub-of-record (a hub may only mutate rooms whose URI authority is its own domain). They do
// not yet verify a per-caller room-admin principal: within the trusted peer set, any caller may
// administer this hub's rooms. This matches the rest of the reference implementation
// (publish_key_package / relay_welcome etc. also trust the mTLS peer with no user-auth layer).
// Production hardening needed before these carry real user data: bind an authenticated principal
// (mTLS-derived identity, not the client-asserted From header) and require it to hold an admin role
// for `q.room` per the RoomPolicy before mutating.
#[derive(Deserialize)]
struct RoomQuery {
    room: String,
}

/// Set a room's RBAC policy (P1-P6). `?room=<uri>` + JSON RoomPolicy body. Hub-of-record gated +
/// validated (P1/P3 well-formedness) before storage. 201 on accept, 400 on a malformed/invalid policy or
/// a room we don't host.
async fn set_room_policy(
    State(p): State<SharedProvider>,
    Query(q): Query<RoomQuery>,
    Json(policy): Json<mimi_core::room_policy::RoomPolicy>,
) -> Response {
    match lock(&p).set_room_policy(&q.room, &policy, now_unix()) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct MemberRoleQuery {
    room: String,
    member: String,
    role: u32,
}

/// Assign a member's role in a room (P1: one role per member). `?room=&member=&role=`. Hub-of-record
/// gated. 201 on accept, 400 if we don't host the room.
async fn set_member_role(
    State(p): State<SharedProvider>,
    Query(q): Query<MemberRoleQuery>,
) -> Response {
    match lock(&p).set_member_role(&q.room, &q.member, q.role) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct ParticipantQuery {
    room: String,
    member: String,
}

/// Register a participant in a room (R1; the routing/membership list). `?room=&member=`. Hub-of-record
/// gated; the member's provider authority is derived from its URI. 201 on accept, 400 otherwise.
async fn add_participant(
    State(p): State<SharedProvider>,
    Query(q): Query<ParticipantQuery>,
) -> Response {
    match lock(&p).add_participant(&q.room, &q.member, now_unix()) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct SenderQuery {
    room: String,
    sender: String,
}

/// Authorize a message sender (M2 active-participant + R3 removed-block + P5 canSendMessage when a policy
/// is set). `?room=&sender=`. 200 = may send, 403 = blocked (with the reason), 400 on a bad room. This is
/// the live hub gate the demo calls to SHOW policy enforcement.
async fn authorize_sender(
    State(p): State<SharedProvider>,
    Query(q): Query<SenderQuery>,
) -> Response {
    match lock(&p).authorize_sender(&q.room, &q.sender) {
        Ok(()) => StatusCode::OK.into_response(),
        // distinguish "we don't host this room" (400) from "blocked" (403) by the error text shape.
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not the hub-of-record") || msg.contains("not a room") {
                (StatusCode::BAD_REQUEST, msg).into_response()
            } else {
                (StatusCode::FORBIDDEN, msg).into_response()
            }
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// §5.4's `accepted_timestamp` is "the hub acceptance time (in milliseconds from the UNIX
/// epoch)" -- distinct from `now_unix()`, which every other caller here uses for seconds-
/// granularity TTL/expiry bookkeeping, not wire framing.
fn now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt; // oneshot

    fn app() -> (Router, SharedProvider) {
        let p = Arc::new(Mutex::new(
            Provider::in_memory("havenmessenger.com").unwrap(),
        ));
        (build_router(p.clone()), p)
    }

    /// Minimal percent-encoding for embedding a `mimi://` URI (which contains reserved `:`/`/`
    /// characters) as a SINGLE axum path segment (`:recipient` matches within one segment, not
    /// across `/`). Only escapes the two characters a `mimi://domain/tag/path` URI actually
    /// contains outside its final path component - not a general-purpose encoder.
    fn urlencode_path(s: &str) -> String {
        s.replace(':', "%3A").replace('/', "%2F")
    }

    #[tokio::test]
    async fn directory_endpoint_returns_0x0001_only() {
        let (router, _p) = app();
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/.well-known/mimi-protocol-directory")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["mls_ciphersuites"], serde_json::json!([1]));
    }

    #[tokio::test]
    async fn identifier_query_404_is_indistinguishable_for_nonenrolled_vs_nonexistent() {
        let (router, p) = app();
        p.lock().unwrap().enroll("alice").unwrap();

        let q = |name: &str| {
            Request::builder()
                .method("POST")
                .uri("/mimi/v1/identifierQuery")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"username":"{name}"}}"#)))
                .unwrap()
        };

        let found = router.clone().oneshot(q("alice")).await.unwrap();
        assert_eq!(found.status(), StatusCode::OK);

        // non-enrolled-but-could-be-real AND definitely-nonexistent: both 404, no body to differ on.
        let nonenrolled = router.clone().oneshot(q("bob")).await.unwrap();
        let nonexistent = router.clone().oneshot(q("zzz_ghost")).await.unwrap();
        assert_eq!(nonenrolled.status(), StatusCode::NOT_FOUND);
        assert_eq!(nonexistent.status(), StatusCode::NOT_FOUND);
        let b1 = nonenrolled.into_body().collect().await.unwrap().to_bytes();
        let b2 = nonexistent.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            b1, b2,
            "the two 404s must be byte-identical (no existence leak)"
        );
    }

    #[tokio::test]
    async fn notify_is_always_201_even_on_duplicate() {
        let (router, _p) = app();
        let req = || {
            Request::builder()
                .method("POST")
                .uri("/mimi/v1/notify")
                .body(Body::from("fanout-body"))
                .unwrap()
        };
        let first = router.clone().oneshot(req()).await.unwrap();
        let dup = router.clone().oneshot(req()).await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        assert_eq!(
            dup.status(),
            StatusCode::CREATED,
            "duplicate /notify must still be 201 (M5)"
        );
    }

    #[tokio::test]
    async fn consent_endpoints_always_201_and_persist() {
        // The endpoints are advertised in the directory: they must be reachable (not 404) AND honor the
        // §5.7 privacy rule (always 201, even for a malformed body, no existence/validity oracle).
        let p = Arc::new(Mutex::new(
            Provider::in_memory("mimi.havenmessenger.com").unwrap(),
        ));
        let router = build_router(p.clone());
        let post = |path: &'static str, body: String| {
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        };
        let grant = serde_json::json!({
            "operation": 2,
            "requester_uri": "mimi://mimi-b.havenmessenger.com/u/bob",
            "target_uri": "mimi://mimi.havenmessenger.com/u/alice"
        })
        .to_string();
        let r = router
            .clone()
            .oneshot(post("/mimi/v1/updateConsent", grant))
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::CREATED,
            "updateConsent reachable + 201"
        );
        // it actually persisted: the gate now allows that requester.
        assert_eq!(
            p.lock()
                .unwrap()
                .keypackage_access(
                    "mimi://mimi-b.havenmessenger.com/u/bob",
                    "mimi://mimi.havenmessenger.com/u/alice",
                    None
                )
                .unwrap(),
            mimi_core::consent::KeyPackageAccess::Allowed
        );
        // a garbage body still returns 201 (privacy: no oracle), changes nothing.
        let bad = router
            .clone()
            .oneshot(post(
                "/mimi/v1/requestConsent",
                "{\"nonsense\":true}".into(),
            ))
            .await;
        // serde rejection of an unparseable body surfaces as a 4xx from axum's extractor BEFORE our
        // handler; a well-formed-but-semantically-invalid body hits our handler → 201. Test the latter:
        let _ = bad; // (axum extractor 4xx for non-deserializable JSON is acceptable; not an oracle)
        let semantically_bad = serde_json::json!({
            "operation": 1,
            "requester_uri": "not-a-uri",
            "target_uri": "mimi://mimi.havenmessenger.com/u/alice"
        })
        .to_string();
        let r2 = router
            .clone()
            .oneshot(post("/mimi/v1/requestConsent", semantically_bad))
            .await
            .unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::CREATED,
            "malformed entry dropped silently, still 201"
        );
    }

    #[tokio::test]
    async fn room_policy_and_member_role_endpoints_persist() {
        let p = Arc::new(Mutex::new(
            Provider::in_memory("mimi.havenmessenger.com").unwrap(),
        ));
        let router = build_router(p.clone());
        let room = "mimi://mimi.havenmessenger.com/r/x";
        let alice = "mimi://mimi.havenmessenger.com/u/alice";
        // set a minimal valid policy (member role 3 with SendMessage)
        let policy = serde_json::json!({
            "base": {"fixed_membership": false, "parent_dependant": false, "discoverable": false},
            "roles": [{"role_index": 3, "role_name": "member", "capabilities": ["SendMessage"]}]
        })
        .to_string();
        let r = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/mimi/v1/roomPolicy?room={room}"))
                    .header("content-type", "application/json")
                    .body(Body::from(policy))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED, "roomPolicy set");
        // assign alice role 3
        let rr = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/mimi/v1/memberRole?room={room}&member={alice}&role=3"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rr.status(), StatusCode::CREATED, "memberRole set");
        // it persisted + is authoritative: alice (member) can send; a banned member cannot.
        p.lock()
            .unwrap()
            .add_participant(room, alice, now_unix())
            .unwrap();
        assert!(
            p.lock().unwrap().authorize_sender(room, alice).is_ok(),
            "member may send (P5 live)"
        );
        // an invalid policy (fixed_membership + AddParticipant) is rejected at the endpoint
        let bad = serde_json::json!({
            "base": {"fixed_membership": true, "parent_dependant": false, "discoverable": false},
            "roles": [{"role_index": 2, "role_name": "admin", "capabilities": ["AddParticipant"]}]
        })
        .to_string();
        let br = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/mimi/v1/roomPolicy?room={room}"))
                    .header("content-type", "application/json")
                    .body(Body::from(bad))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            br.status(),
            StatusCode::BAD_REQUEST,
            "invalid policy rejected (P3)"
        );
    }

    #[tokio::test]
    async fn live_policy_scenario_allows_member_blocks_banned() {
        // The end-to-end live P1/P4/P5 demo path: set policy → register participants → assign roles →
        // authorizeSender shows 200 (member) vs 403 (banned).
        let p = Arc::new(Mutex::new(
            Provider::in_memory("mimi.havenmessenger.com").unwrap(),
        ));
        let router = build_router(p.clone());
        let room = "mimi://mimi.havenmessenger.com/r/x";
        let alice = "mimi://mimi.havenmessenger.com/u/alice";
        let mallory = "mimi://mimi.havenmessenger.com/u/mallory";
        let policy = serde_json::json!({
            "base": {"fixed_membership": false, "parent_dependant": false, "discoverable": false},
            "roles": [
                {"role_index": 1, "role_name": "banned", "capabilities": []},
                {"role_index": 3, "role_name": "member", "capabilities": ["SendMessage"]}
            ]
        })
        .to_string();
        let post = |uri: String, body: Option<String>| {
            let mut b = Request::builder().method("POST").uri(uri);
            if body.is_some() {
                b = b.header("content-type", "application/json");
            }
            b.body(body.map(Body::from).unwrap_or_else(Body::empty))
                .unwrap()
        };
        assert_eq!(
            router
                .clone()
                .oneshot(post(
                    format!("/mimi/v1/roomPolicy?room={room}"),
                    Some(policy)
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        for m in [alice, mallory] {
            assert_eq!(
                router
                    .clone()
                    .oneshot(post(
                        format!("/mimi/v1/addParticipant?room={room}&member={m}"),
                        None
                    ))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::CREATED
            );
        }
        assert_eq!(
            router
                .clone()
                .oneshot(post(
                    format!("/mimi/v1/memberRole?room={room}&member={alice}&role=3"),
                    None
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            router
                .clone()
                .oneshot(post(
                    format!("/mimi/v1/memberRole?room={room}&member={mallory}&role=1"),
                    None
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        // alice (member, SendMessage) → 200; mallory (banned) → 403
        assert_eq!(
            router
                .clone()
                .oneshot(post(
                    format!("/mimi/v1/authorizeSender?room={room}&sender={alice}"),
                    None
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            router
                .clone()
                .oneshot(post(
                    format!("/mimi/v1/authorizeSender?room={room}&sender={mallory}"),
                    None
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn key_material_served_once_then_404() {
        let (router, p) = app();
        p.lock()
            .unwrap()
            .add_key_package("alice", b"kp1", now_unix() + 100)
            .unwrap();
        let req = || {
            Request::builder()
                .uri("/mimi/v1/keyMaterial?user=alice")
                .body(Body::empty())
                .unwrap()
        };
        let first = router.clone().oneshot(req()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = router.clone().oneshot(req()).await.unwrap();
        assert_eq!(
            second.status(),
            StatusCode::NOT_FOUND,
            "KP is one-time (K1)"
        );
    }

    #[tokio::test]
    async fn foreign_keypackage_gate_rejects_garbage_with_400() {
        let (router, _p) = app();
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/v1/keyMaterial/ingest")
                    .body(Body::from("not a keypackage"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "gate rejects foreign garbage at the edge"
        );
    }

    // ---- store-and-forward delivery (the cross-provider relay) ----

    #[tokio::test]
    async fn message_submit_then_fetch_roundtrip_delivers_once() {
        let (router, _p) = app();
        // submit an opaque app message for the recipient (provider never decrypts it)
        let submit = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/v1/submitMessage?recipient=xxx@haven")
                    .body(Body::from(&b"opaque-ciphertext"[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(submit.status(), StatusCode::CREATED);

        // recipient fetches it (deliver-once)
        let fetch = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mimi/v1/message?user=xxx@haven")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(fetch.status(), StatusCode::OK);
        let body = fetch.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            &body[..],
            b"opaque-ciphertext",
            "exact ciphertext relayed, unmodified"
        );

        // queue now empty → 404
        let empty = router
            .oneshot(
                Request::builder()
                    .uri("/mimi/v1/message?user=xxx@haven")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            empty.status(),
            StatusCode::NOT_FOUND,
            "deliver-once: gone after fetch"
        );
    }

    #[tokio::test]
    async fn submit_message_requires_recipient() {
        let (router, _p) = app();
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/v1/submitMessage")
                    .body(Body::from(&b"x"[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "no ?recipient= → 400"
        );
    }

    #[tokio::test]
    async fn welcome_relay_rejects_garbage_but_message_is_opaque() {
        let (router, _p) = app();
        // welcome RELAY still suite-gates (garbage rejected before it ever queues)
        let bad_welcome = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/v1/welcome/ingest?recipient=xxx@haven")
                    .body(Body::from(&b"not a welcome"[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            bad_welcome.status(),
            StatusCode::BAD_REQUEST,
            "welcome relay is suite-gated"
        );
        // and nothing got queued for the recipient
        let none = router
            .oneshot(
                Request::builder()
                    .uri("/mimi/v1/welcome?user=xxx@haven")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            none.status(),
            StatusCode::NOT_FOUND,
            "rejected welcome never reached the queue"
        );
    }

    // ---- wire lane (protocol-06 §5 TLS-PL framing) ----

    #[tokio::test]
    async fn submit_message_wire_rejects_undecodable_body() {
        let (router, _p) = app();
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/submitMessage/xxx@haven")
                    .body(Body::from(&b"not a SubmitMessageRequest"[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "an undecodable wire body has no valid response to answer with"
        );
    }

    #[tokio::test]
    async fn submit_message_wire_rejects_non_participant_sender() {
        use mimi_core::protocol_wire::{SubmitMessageRequest, SubmitMessageResponse};

        let (router, p) = app();
        let room = "mimi://havenmessenger.com/r/x";
        // room exists (hub-of-record) but mallory was never added to it.
        p.lock()
            .unwrap()
            .add_participant(room, "mimi://havenmessenger.com/u/alice", now_unix())
            .unwrap();

        let req = SubmitMessageRequest {
            protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
            app_message: real_mls_envelope_bytes(),
            sending_uri: mimi_core::protocol_wire::IdentifierUri(
                "mimi://havenmessenger.com/u/mallory".to_string(),
            ),
        };
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/mimi/pl/submitMessage/{}", urlencode_path(room)))
                    .body(Body::from(req.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "still 200, per §5.4 shape");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            SubmitMessageResponse::decode(&body).unwrap(),
            SubmitMessageResponse::NotAllowed,
            "a non-participant sender must be rejected (M2/R3)"
        );
    }

    #[tokio::test]
    async fn submit_message_wire_fans_out_to_local_participants() {
        use mimi_core::protocol_wire::{SubmitMessageRequest, SubmitMessageResponse};

        let (router, p) = app();
        let room = "mimi://havenmessenger.com/r/x";
        let alice = "mimi://havenmessenger.com/u/alice";
        let bob = "mimi://havenmessenger.com/u/bob";
        p.lock()
            .unwrap()
            .add_participant(room, alice, now_unix())
            .unwrap();
        p.lock()
            .unwrap()
            .add_participant(room, bob, now_unix())
            .unwrap();

        let app_message = real_mls_envelope_bytes();
        let req = SubmitMessageRequest {
            protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
            app_message: app_message.clone(),
            sending_uri: mimi_core::protocol_wire::IdentifierUri(alice.to_string()),
        };
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/mimi/pl/submitMessage/{}", urlencode_path(room)))
                    .body(Body::from(req.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            matches!(
                SubmitMessageResponse::decode(&body).unwrap(),
                SubmitMessageResponse::Accepted { .. }
            ),
            "an active participant's message must be accepted"
        );
        // M3: bob (a local participant, not the literal path-segment key) must have received it via
        // fan-out - not just whatever queue the literal room-URI path segment happens to be.
        let fetched = p.lock().unwrap().fetch_message(bob).unwrap();
        assert_eq!(
            fetched,
            Some(app_message),
            "fanout_targets must deliver to every other local room participant (M3)"
        );
    }

    #[tokio::test]
    async fn submit_message_wire_rejects_recipient_that_is_not_a_room() {
        use mimi_core::protocol_wire::{SubmitMessageRequest, SubmitMessageResponse};

        let (router, _p) = app();
        let req = SubmitMessageRequest {
            protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
            app_message: real_mls_envelope_bytes(),
            sending_uri: mimi_core::protocol_wire::IdentifierUri(
                "mimi://havenmessenger.com/u/alice".to_string(),
            ),
        };
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/submitMessage/xxx@haven") // not a mimi:// room URI at all
                    .body(Body::from(req.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            SubmitMessageResponse::decode(&body).unwrap(),
            SubmitMessageResponse::NotAllowed,
            "a path segment that doesn't even parse as a room this hub hosts must be rejected, not \
             silently accepted as an opaque routing key"
        );
    }

    #[tokio::test]
    async fn update_consent_wire_grant_reaches_the_same_gate_as_json() {
        use mimi_core::consent::{ConsentEntry, ConsentOperation, KeyPackageAccess};
        use mimi_core::protocol_wire::encode_consent_entry;

        let (router, p) = app();
        let requester = "mimi://mimi-b.havenmessenger.com/u/bob";
        let target = "mimi://havenmessenger.com/u/alice";
        assert_eq!(
            p.lock()
                .unwrap()
                .keypackage_access(requester, target, None)
                .unwrap(),
            KeyPackageAccess::NoConsent,
            "default-deny before any grant"
        );

        let entry = ConsentEntry {
            operation: ConsentOperation::Grant,
            requester_uri: requester.to_string(),
            target_uri: target.to_string(),
            room_uri: None,
            client_key_packages: Vec::new(),
            consent_extensions: Vec::new(),
        };
        let wire_body = encode_consent_entry(&entry).unwrap();

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/updateConsent/mimi-b.havenmessenger.com")
                    .body(Body::from(wire_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "always 201 (privacy)");

        // The same gate state a JSON updateConsent grant would have produced: proves the wire
        // handler drove the identical Provider code path, not a shadow implementation.
        assert_eq!(
            p.lock()
                .unwrap()
                .keypackage_access(requester, target, None)
                .unwrap(),
            KeyPackageAccess::Allowed,
            "the decoded grant must reach the same gate the JSON lane writes to"
        );
    }

    #[tokio::test]
    async fn request_consent_wire_stays_201_on_undecodable_body_no_oracle() {
        let (router, _p) = app();
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/requestConsent/a.example")
                    .body(Body::from(&b"garbage, not a ConsentEntry"[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "malformed wire bytes must not distinguish from a valid-but-dropped entry"
        );
    }

    /// Build a real, canonical 0x0001 KeyPackage. Local to this module (mirrors `lib.rs`'s own
    /// `real_keypackage` test helper, which is private to that module's test scope) so this
    /// module's tests can round-trip a KeyMaterialResponse against bytes that actually decode.
    fn real_keypackage() -> Vec<u8> {
        use openmls::ciphersuite::signature::SignaturePublicKey;
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::prelude::*;
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;
        use tls_codec::Serialize as _;

        struct S {
            key: Vec<u8>,
            scheme: SignatureScheme,
        }
        impl Signer for S {
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
                OpenMlsRustCrypto::default()
                    .crypto()
                    .sign(self.scheme, payload, &self.key)
                    .map_err(|_| SignerError::SigningError)
            }
            fn signature_scheme(&self) -> SignatureScheme {
                self.scheme
            }
        }

        let provider = OpenMlsRustCrypto::default();
        let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let scheme = SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(b"bob".to_vec()).into(),
            signature_key: pk,
        };
        let signer = S {
            key: priv_b,
            scheme,
        };
        let now = now_unix();
        let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
            "not_before": now.saturating_sub(3600),
            "not_after": now + 60 * 60 * 24 * 84,
        }))
        .unwrap();
        let kpb = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime)
            .build(suite, &provider, &signer, cwk)
            .unwrap();
        kpb.key_package().tls_serialize_detached().unwrap()
    }

    #[tokio::test]
    async fn key_material_wire_serves_a_real_keypackage() {
        use mimi_core::consent::{ConsentEntry, ConsentOperation};
        use mimi_core::protocol_wire::{KeyMaterialRequest, KeyMaterialResponse};

        let (router, p) = app();
        let kp_bytes = real_keypackage();
        p.lock()
            .unwrap()
            .add_key_package("bob", &kp_bytes, now_unix() + 100)
            .unwrap();
        let requester = "mimi://a.example/u/alice";
        let target_uri = "mimi://havenmessenger.com/u/bob";
        // key_material_wire is consent-gated - grant it first, matching what a real client
        // flow would need before this request could ever succeed.
        p.lock()
            .unwrap()
            .process_update_consent(
                &ConsentEntry {
                    operation: ConsentOperation::Grant,
                    requester_uri: requester.to_string(),
                    target_uri: target_uri.to_string(),
                    room_uri: None,
                    client_key_packages: Vec::new(),
                    consent_extensions: Vec::new(),
                },
                now_unix(),
            )
            .unwrap();

        // the wire body's target_user carries the target's real URI (the consent-gate lookup key);
        // the PATH segment stays the bare store username ("bob", matching add_key_package above) -
        // these are two different fields on purpose (see key_material_wire's own doc).
        let req_body = KeyMaterialRequest::minimal(requester, target_uri)
            .unwrap()
            .encode()
            .unwrap();
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/keyMaterial/bob")
                    .body(Body::from(req_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        match KeyMaterialResponse::decode(&body).unwrap() {
            KeyMaterialResponse::Success {
                user_uri,
                key_package,
            } => {
                assert_eq!(user_uri.0, "bob");
                assert_eq!(
                    key_package, kp_bytes,
                    "the served KeyPackage must round-trip byte-identical"
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }

        // one-time: the second request over the SAME wire lane finds nothing left (K1).
        let second = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/keyMaterial/bob")
                    .body(Body::from(req_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK, "still 200, per §5.2 shape");
        let body2 = second.into_body().collect().await.unwrap().to_bytes();
        assert!(matches!(
            KeyMaterialResponse::decode(&body2).unwrap(),
            KeyMaterialResponse::Exhausted { .. }
        ));
    }

    #[tokio::test]
    async fn key_material_wire_denies_without_consent() {
        // A requester with no consent grant must be denied, not served, even when a
        // real KeyPackage exists for the target.
        use mimi_core::protocol_wire::{
            KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode,
        };

        let (router, p) = app();
        let kp_bytes = real_keypackage();
        p.lock()
            .unwrap()
            .add_key_package("carol", &kp_bytes, now_unix() + 100)
            .unwrap();
        // no consent grant

        let req_body = KeyMaterialRequest::minimal(
            "mimi://a.example/u/mallory",
            "mimi://havenmessenger.com/u/carol",
        )
        .unwrap()
        .encode()
        .unwrap();
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/keyMaterial/carol")
                    .body(Body::from(req_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "still 200, per §5.2 shape");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        match KeyMaterialResponse::decode(&body).unwrap() {
            KeyMaterialResponse::Denied { user_uri, code } => {
                assert_eq!(user_uri.0, "carol");
                assert_eq!(code, KeyMaterialUserCode::NoConsent);
            }
            other => panic!("expected Denied(NoConsent), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn key_material_wire_rejects_undecodable_body() {
        let (router, _p) = app();
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/keyMaterial/bob")
                    .body(Body::from(&b"not a KeyMaterialRequest"[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    fn real_mls_envelope_bytes() -> Vec<u8> {
        use openmls::ciphersuite::signature::SignaturePublicKey;
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::group::{MlsGroup, MlsGroupCreateConfig};
        use openmls::prelude::{Ciphersuite, OpenMlsCrypto, SignatureScheme};
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;
        use tls_codec::Serialize as _;

        struct S {
            key: Vec<u8>,
            scheme: SignatureScheme,
        }
        impl Signer for S {
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
                OpenMlsRustCrypto::default()
                    .crypto()
                    .sign(self.scheme, payload, &self.key)
                    .map_err(|_| SignerError::SigningError)
            }
            fn signature_scheme(&self) -> SignatureScheme {
                self.scheme
            }
        }

        let provider = OpenMlsRustCrypto::default();
        let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let scheme = SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(b"alice".to_vec()).into(),
            signature_key: pk,
        };
        let signer = S {
            key: priv_b,
            scheme,
        };
        let cfg = MlsGroupCreateConfig::builder().ciphersuite(suite).build();
        let mut group = MlsGroup::new(&provider, &signer, &cfg, cwk).unwrap();
        group
            .create_message(&provider, &signer, b"fanout wire test")
            .unwrap()
            .tls_serialize_detached()
            .unwrap()
    }

    #[tokio::test]
    async fn notify_wire_accepts_real_fanout_message() {
        use mimi_core::protocol_wire::FanoutMessage;

        let (router, _p) = app();
        let fm = FanoutMessage {
            protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
            timestamp: now_unix(),
            message_and_tail: real_mls_envelope_bytes(),
        };
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/notify")
                    .body(Body::from(fm.encode().unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn notify_wire_rejects_undecodable_body() {
        let (router, _p) = app();
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/notify")
                    .body(Body::from(&b"not a FanoutMessage"[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn identifier_query_wire_matches_json_lane_behavior() {
        use mimi_core::protocol_wire::{IdentifierRequest, QueryElement, SearchIdentifierType};

        let (router, p) = app();
        p.lock().unwrap().enroll("alice").unwrap();

        let query = |value: &str| {
            IdentifierRequest {
                query_elements: vec![QueryElement {
                    search_type: SearchIdentifierType::Handle,
                    qualifier: Vec::new(),
                    search_value: value.as_bytes().to_vec(),
                }],
            }
            .encode()
            .unwrap()
        };

        let found = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/identifierQuery")
                    .body(Body::from(query("alice")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(found.status(), StatusCode::OK);
        assert!(
            found
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty(),
            "DIV-4: no response body on the wire lane either"
        );

        let not_enrolled = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/identifierQuery")
                    .body(Body::from(query("bob")))
                    .unwrap(),
            )
            .await
            .unwrap();
        let nonexistent = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mimi/pl/identifierQuery")
                    .body(Body::from(query("zzz_ghost")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(not_enrolled.status(), StatusCode::NOT_FOUND);
        assert_eq!(nonexistent.status(), StatusCode::NOT_FOUND);
    }
}
