//! mimi-hubd - a reference MIMI hub daemon (native, server-side).
//!
//! v1 hub semantics: add-driven membership, text-only content, suite 0x0001 only. The stateful
//! request-handling core is [`Provider`] (backed by the durable [`store::SqliteStore`]); the async
//! HTTP transport is [`http`]; mTLS termination is [`tls`]. Every foreign-input path runs the
//! `mimi-core` gate before openmls.
//!
//! Core [`Provider`] methods (conformance rows in parens, see `mimi-core`'s own conformance tracking):
//!   [`Provider::directory`]                (T5)     [`Provider::serve_key_material`]      (K1,K2)
//!   [`Provider::ingest_foreign_keypackage`] (K5)     [`Provider::submit_notify`]           (M5)
//!   [`Provider::ingest_foreign_welcome`]    (K5)     [`Provider::identifier_query`]        (DIV-4/C3)
//!
//! The full HTTP route table (14 `/mimi/v1/*` JSON routes plus the directory endpoint) lives in
//! [`http`], not duplicated here - see that module for the current list rather than risking a
//! second copy going stale. 6 of those routes (`keyMaterial`, `submitMessage`, `notify`,
//! `identifierQuery`, `requestConsent`, `updateConsent`) also have a live `/mimi/pl/*` route
//! speaking draft-ietf-mimi-protocol's TLS presentation-language (TLS-PL) wire framing directly,
//! reading and writing the same underlying store as the JSON lane. A seventh, `reportAbuse`, has a
//! wire route only (§5.9, DIV-8: metadata-only, no JSON-lane twin exists).
//!
//! Out of v1 scope (see DIVERGENCES.md at the repo root for the full list): §5.6
//! GroupInfo/external-commit join (DIV-1), non-0x0001 suites (DIV-2, enforced by the gate),
//! assets+OHTTP §5.10 (DIV-3).

pub mod activity;
pub mod enroll;
pub mod http;
pub mod notify_source;
pub mod peer;
pub mod store;
pub mod tls;

use mimi_core::commit_wire::{
    changes_refusal, check_changes, decode_commit_proposals, decode_proposal_message,
    DecodedCommit, ReadProposal,
};
use mimi_core::consent::{
    validate_consent_entry, ConsentEntry, ConsentOperation, KeyPackageAccess,
};
use mimi_core::gate::{
    identifier_query, keypackage_ref, mimi_gate_keypackage, mimi_gate_welcome,
    IdentifierQueryResult, HAVEN_MLS_CIPHERSUITE_U16,
};
use mimi_core::participant_list::{
    apply_update, decode_participant_list_update, ParticipantListData, ParticipantListUpdate,
    UserRolePair, MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use mimi_core::protocol_wire::{HandshakeBundle, WireError};
use mimi_core::room_policy::{
    RoomPolicy, MIMI_BASE_ROOM_POLICY_PROPOSAL_TYPE, MIMI_ROLES_LIST_PROPOSAL_TYPE,
};
use mimi_core::room_policy_wire::{decode_base_room_policy, decode_role_data};
use mimi_core::uri::{MimiKind, MimiUri};

/// The provider domain of a user URI: its authority, lowercased, with a port taken off. `None` for a URI that is not a
/// user URI.
fn user_domain(user_uri: &str) -> Option<String> {
    let uri = MimiUri::parse(user_uri).ok()?;
    if uri.kind != Some(MimiKind::User) {
        return None;
    }
    let host = match uri.authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => uri.authority.as_str(),
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Upper bound on a member/room URI we will store (anti-DoS on the routing key; a real mimi:// URI is
/// far shorter). Parsed URIs longer than this are rejected before any work.
const MAX_URI_LEN: usize = 512;

use crate::store::{ParticipantRow, SqliteStore};

/// Published KeyPackages live this long before K2 expiry prunes them from claims.
const KEYPACKAGE_TTL_SECS: u64 = 30 * 24 * 3600; // 30 days
/// Queued welcomes/messages older than this are swept (ephemeral delivery state, not storage).
const DELIVERY_TTL_SECS: u64 = 24 * 3600; // 24 hours

/// Why `update` did not apply a request, in the terms §5.3's `UpdateRoomResponse` answers with.
#[derive(Debug, PartialEq, Eq)]
pub enum UpdateRefusal {
    /// The hub did not accept the update: the room is not one this hub hosts, the bundle carries material under another
    /// ciphersuite, or a store limit (the participant cap) would be exceeded. One answer covers all of them, so a refusal
    /// does not say which applied.
    NotAllowed,
    /// The request, or the proposal it carries, is not one this hub can read or apply. The text is fixed wording, never
    /// the peer's bytes.
    Invalid(&'static str),
    /// As [`Self::Invalid`], naming the proposals at fault by their `ProposalRef`: a reference this hub holds nothing
    /// for, or a held proposal the Commit leaves out.
    InvalidProposals(&'static str, Vec<Vec<u8>>),
    /// The proposals are not of the room's current epoch, which is this one.
    WrongEpoch(u64),
    /// A peer that may leave the room asked for more than the hub holds for one room's next Commit. Answered
    /// `notAllowed` with these words; only a provider of the room's participants reaches it, so it says nothing about
    /// whether a room exists.
    Limit(&'static str),
    /// The store failed. This is the hub's own fault, not a verdict on the request.
    Store,
}

impl std::fmt::Display for UpdateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed => f.write_str("the hub did not accept this update"),
            Self::Invalid(why) | Self::InvalidProposals(why, _) | Self::Limit(why) => {
                f.write_str(why)
            }
            Self::WrongEpoch(_) => {
                f.write_str("the proposals are not for the room's current epoch")
            }
            Self::Store => f.write_str("the hub could not store this update"),
        }
    }
}

impl std::error::Error for UpdateRefusal {}

/// A store error is the hub's own failure when it comes from SQLite; any other error the store raises is a limit it
/// enforces on the request (the participant cap).
pub(crate) fn store_refusal(error: &anyhow::Error) -> UpdateRefusal {
    if error.downcast_ref::<rusqlite::Error>().is_some() {
        UpdateRefusal::Store
    } else {
        UpdateRefusal::NotAllowed
    }
}

/// Outcome of a `/notify` fanout submission (MIMI §5.5, conformance M5). Both arms map to HTTP 201;
/// the distinction is whether the caller should PROCESS the body or treat it as an already-handled
/// duplicate. (Returning 201 for duplicates is the spec's idempotency requirement.)
#[derive(Debug, PartialEq, Eq)]
pub enum NotifyOutcome {
    /// First time we've seen this exact body: process it, then 201.
    Process,
    /// Byte-exact duplicate: do NOT re-process, still 201.
    DuplicateIgnored,
}

/// The hub fan-out plan for one room (M3): which members get LOCAL delivery (enqueue here) vs FOREIGN
/// (forward the ciphertext to that provider's authority). Pure routing metadata; no plaintext.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FanoutPlan {
    /// member URIs whose provider is THIS provider → local enqueue.
    pub local: Vec<String>,
    /// (provider_authority, member_uri) for members on OTHER providers → forward to that provider.
    pub foreign: Vec<(String, String)>,
}

/// The provider's state, backed by the durable SQLite store (no in-memory residue).
pub struct Provider {
    /// This hub's own domain, e.g. "example.com", used in the directory response and From handling.
    domain: String,
    /// Where this hub's endpoints are reachable, e.g. "https://mimi.example.com:8443", when that is
    /// not `https://{domain}`. Only the directory's endpoint URLs use it; identifiers keep `domain`.
    public_base_url: Option<String>,
    store: SqliteStore,
}

impl Provider {
    /// Open a provider backed by a SQLite file (production).
    pub fn open(domain: impl Into<String>, db_path: &str) -> anyhow::Result<Self> {
        Ok(Self {
            domain: domain.into(),
            public_base_url: None,
            store: SqliteStore::open(db_path)?,
        })
    }

    /// Open a provider backed by an in-memory SQLite db (tests).
    pub fn in_memory(domain: impl Into<String>) -> anyhow::Result<Self> {
        Ok(Self {
            domain: domain.into(),
            public_base_url: None,
            store: SqliteStore::in_memory()?,
        })
    }

    /// Serve the directory's endpoint URLs from `url` instead of `https://{domain}` - for a hub
    /// behind a reverse proxy, on a port other than 443, or on a dedicated host (protocol-07 §5.1:
    /// the directory conveys the endpoint URLs rather than hard-coding them). `url` must be an
    /// `https://` URL with a host and no query or fragment; one trailing `/` is dropped.
    pub fn with_public_base_url(mut self, url: &str) -> anyhow::Result<Self> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| anyhow::anyhow!("public base URL must start with https://: {url:?}"))?;
        let host_len = rest.find('/').unwrap_or(rest.len());
        if host_len == 0 || rest.contains(['?', '#']) || rest.contains(char::is_whitespace) {
            anyhow::bail!("public base URL needs a host and no query, fragment or spaces: {url:?}");
        }
        self.public_base_url = Some(url.strip_suffix('/').unwrap_or(url).to_string());
        Ok(self)
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    // ---- enrollment (the Standards Testing Page opt-in: discoverability + send-gate + portal) ----

    pub fn enroll(&self, username: &str) -> anyhow::Result<()> {
        self.store.enroll(username)
    }

    pub fn is_enrolled(&self, username: &str) -> anyhow::Result<bool> {
        self.store.is_enrolled(username)
    }

    pub fn add_key_package(
        &self,
        username: &str,
        kp_bytes: &[u8],
        not_after: u64,
    ) -> anyhow::Result<()> {
        self.store.add_key_package(username, kp_bytes, not_after)
    }

    // ---- T5: directory ----

    /// The `/.well-known/mimi-protocol-directory` document. Advertises our endpoints + the SINGLE
    /// supported MLS ciphersuite (0x0001, DIV-2) + the conformant draft revisions, AND discloses the
    /// unsupported set: it advertises only what v1 actually serves.
    ///
    /// protocol-07 §5.1's own example is a FLAT object: top-level keys are the ten endpoint names,
    /// values are absolute HTTPS URLs (e.g. `"keyMaterial": "https://mimi.example.com/v1/keyMaterial/
    /// {targetUser}"`). This document publishes those flat, draft-shaped keys for the eight
    /// endpoints this hub actually wire-routes (`keyMaterial`/`submitMessage`/`notify`/
    /// `identifierQuery`/`requestConsent`/`updateConsent`/`reportAbuse`/`update`) - the other two
    /// draft keys (`groupInfo`/`proxyDownload`) are omitted since nothing here serves them, per the
    /// same "advertise only what's served" discipline as `unsupported` below. `endpoints` (relative paths,
    /// JSON compat lane) and `wireEndpoints` (relative paths, mirrors the flat keys) are additive
    /// non-standard keys kept for existing consumers - a strict §5.1 client ignores unknown keys.
    /// The flat URLs start at `https://{domain}`, or at the public base URL when one is set
    /// ([`Provider::with_public_base_url`]).
    pub fn directory(&self) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "provider": self.domain,
            "mls_ciphersuites": [HAVEN_MLS_CIPHERSUITE_U16],   // 0x0001 only
            "protocol_drafts": { "protocol": "07", "content": "10", "room-policy": "04" },
            "endpoints": {
                "keyMaterial": "/mimi/v1/keyMaterial",
                "notify": "/mimi/v1/notify",
                "welcome": "/mimi/v1/welcome",
                "submitMessage": "/mimi/v1/submitMessage",
                "message": "/mimi/v1/message",
                "identifierQuery": "/mimi/v1/identifierQuery",
                "updateConsent": "/mimi/v1/updateConsent",
                "requestConsent": "/mimi/v1/requestConsent"
            },
            "wireEndpoints": {
                "keyMaterial": "/mimi/pl/keyMaterial/{targetUser}",
                "submitMessage": "/mimi/pl/submitMessage/{roomId}",
                "notify": "/mimi/pl/notify/{roomId}",
                "identifierQuery": "/mimi/pl/identifierQuery/{domain}",
                "requestConsent": "/mimi/pl/requestConsent/{targetDomain}",
                "updateConsent": "/mimi/pl/updateConsent/{requesterDomain}",
                "reportAbuse": "/mimi/pl/reportAbuse/{roomId}",
                "update": "/mimi/pl/update/{roomId}"
            },
            "unsupported": {
                "groupInfo_external_commit_join": "DIV-1: add-driven join only (ETK security)",
                "assets_ohttp": "DIV-3: v1 is messaging-only",
                "non_0x0001_ciphersuites": "DIV-2: rejected at ingest",
                "update_wire_endpoint_mixed_commits": "DIV-10: a Commit is applied when it carries a participant-list change, a room-policy change, or one of each (a role list never beside a participant-list change, room-policy-04 §3), alone or with Add and Remove proposals beside it; proposals by reference are accepted only when they are the ones this hub holds for a member's leave. A second change of one kind, a role list beside a participant-list change, a Commit with no change, any other proposal type and any other proposal by reference are refused",
                "reportAbuse_with_abusive_messages": "DIV-9: a report attaching an AbusiveMessage is refused (its Frank cannot yet be verified) - metadata-only reports are accepted"
            }
        });
        let base = self
            .public_base_url
            .clone()
            .unwrap_or_else(|| format!("https://{}", self.domain));
        for (key, path) in [
            ("keyMaterial", "/mimi/pl/keyMaterial/{targetUser}"),
            ("submitMessage", "/mimi/pl/submitMessage/{roomId}"),
            ("notify", "/mimi/pl/notify/{roomId}"),
            ("identifierQuery", "/mimi/pl/identifierQuery/{domain}"),
            ("requestConsent", "/mimi/pl/requestConsent/{targetDomain}"),
            ("updateConsent", "/mimi/pl/updateConsent/{requesterDomain}"),
            ("reportAbuse", "/mimi/pl/reportAbuse/{roomId}"),
            ("update", "/mimi/pl/update/{roomId}"),
        ] {
            doc[key] = serde_json::Value::String(format!("{base}{path}"));
        }
        doc
    }

    // ---- K1/K2: serve a local user's one-time KeyPackage ----

    pub fn serve_key_material(
        &self,
        username: &str,
        now_unix: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.store.claim_key_package(username, now_unix)
    }

    // ---- K5: gate every foreign object BEFORE openmls ----

    pub fn ingest_foreign_keypackage(&self, kp_bytes: &[u8]) -> anyhow::Result<()> {
        Ok(mimi_gate_keypackage(kp_bytes)?)
    }

    pub fn ingest_foreign_welcome(&self, mls_message_bytes: &[u8]) -> anyhow::Result<()> {
        Ok(mimi_gate_welcome(mls_message_bytes)?)
    }

    // ---- store-and-forward delivery (the cross-provider relay) ----
    // The provider stores OPAQUE ciphertext keyed by a caller-supplied recipient (routing metadata).
    // It never decrypts (INV-MIMI-002). KeyPackages + Welcomes are suite-gated at ingest (INV-MLS-002);
    // application messages are opaque PrivateMessages (size-bounded only, their suite is not in clear).

    /// Publish a local user's one-time KeyPackage so cross-provider peers can claim it. Suite-gated,
    /// THEN stored with a TTL. (Distinct from `ingest_foreign_keypackage`, which only validates.)
    pub fn publish_key_package(
        &self,
        username: &str,
        kp_bytes: &[u8],
        now_unix: u64,
    ) -> anyhow::Result<()> {
        mimi_gate_keypackage(kp_bytes)?; // K5 / INV-MLS-002, reject non-0x0001 before storing
        let not_after = now_unix + KEYPACKAGE_TTL_SECS;
        // K4: the follower associates this served KeyPackageRef -> its local client, so an inbound
        // Welcome carrying that ref can be delivered to the right user. Computed over the SAME bytes we
        // gated/store, so it is byte-identical to the ref a Welcome's secrets carry.
        let kpref = keypackage_ref(kp_bytes)?;
        self.store
            .associate_kpref_client(&kpref, username, not_after)?;
        self.store.add_key_package(username, kp_bytes, not_after)
    }

    // ---- K3/K4: KeyPackageRef routing associations ----

    /// K3 (hub side): on claiming a remote user's KeyPackage to add them, associate the canonical
    /// KeyPackageRef with the target provider, so the resulting Welcome can be forwarded there.
    /// `kp_bytes` is the claimed (already suite-gated by the serving provider) KeyPackage; the ref is
    /// computed locally so it matches the Welcome's secrets. `not_after` should track the KP lifetime.
    pub fn associate_claimed_keypackage(
        &self,
        kp_bytes: &[u8],
        provider_authority: &str,
        not_after: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let kpref = keypackage_ref(kp_bytes)?;
        self.store
            .associate_kpref_provider(&kpref, provider_authority, not_after)?;
        Ok(kpref)
    }

    /// Resolve a KeyPackageRef to the local client it was served for (K4). None if unknown.
    pub fn client_for_kpref(&self, kpref: &[u8]) -> anyhow::Result<Option<String>> {
        self.store.client_for_kpref(kpref)
    }

    /// Resolve a KeyPackageRef to the provider that owns it (K3). None if unknown.
    pub fn provider_for_kpref(&self, kpref: &[u8]) -> anyhow::Result<Option<String>> {
        self.store.provider_for_kpref(kpref)
    }

    /// Forget both associations once a Welcome has been forwarded/delivered for this ref.
    pub fn forget_kpref(&self, kpref: &[u8]) -> anyhow::Result<()> {
        self.store.forget_kpref(kpref)
    }

    /// Relay a Welcome to `recipient`. Suite-gated, THEN enqueued as opaque bytes (deliver-once).
    pub fn relay_welcome(
        &self,
        recipient: &str,
        welcome_bytes: &[u8],
        now_unix: u64,
    ) -> anyhow::Result<()> {
        mimi_gate_welcome(welcome_bytes)?; // K5 / INV-MLS-002 before it touches a queue
        self.store
            .enqueue_welcome(recipient, welcome_bytes, now_unix)
    }

    pub fn fetch_welcome(&self, recipient: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.store.fetch_welcome(recipient)
    }

    /// Submit an application message (opaque MLS PrivateMessage) for `recipient`. NOT suite-gated - it
    /// is end-to-end ciphertext the provider must never inspect (INV-MIMI-002); the store bounds size.
    pub fn submit_message(
        &self,
        recipient: &str,
        msg_bytes: &[u8],
        now_unix: u64,
    ) -> anyhow::Result<()> {
        self.store.enqueue_message(recipient, msg_bytes, now_unix)
    }

    pub fn fetch_message(&self, recipient: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.store.fetch_message(recipient)
    }

    /// Opportunistic TTL sweep of the delivery queues, the notify dedup ledger (both ephemeral relay
    /// state, TTL-bounded), and never-claimed expired KeyPackages (L1: bounded on their own absolute
    /// `not_after`, not the delivery TTL - a published-but-never-claimed KeyPackage has nothing to do
    /// with how long a delivered message stays queued).
    pub fn sweep_expired(&self, now_unix: u64) -> anyhow::Result<usize> {
        let ttl_cutoff = now_unix.saturating_sub(DELIVERY_TTL_SECS);
        let delivery = self.store.sweep_expired(ttl_cutoff)?;
        let notify = self.store.sweep_expired_notify_seen(ttl_cutoff)?;
        let keypackages = self.store.sweep_expired_keypackages(now_unix)?;
        Ok(delivery + notify + keypackages)
    }

    // ---- M5: /notify idempotency ----

    /// Record a `/notify` body for dedup. The proof says the request came from the hub of the room it names
    /// (`notify_source`); there is no way to call this without one, so a request from anyone else is never stored.
    pub fn submit_notify(
        &self,
        _source: &notify_source::VerifiedNotifySource,
        body: &[u8],
        now_unix: u64,
    ) -> anyhow::Result<NotifyOutcome> {
        if self.store.notify_seen(body, now_unix)? {
            Ok(NotifyOutcome::DuplicateIgnored)
        } else {
            Ok(NotifyOutcome::Process)
        }
    }

    // ---- R1-R3 / M3: room participant list + hub fan-out ----
    //
    // SECURITY (routing integrity): a member's provider authority is the fan-out routing key - it decides
    // where that member's ciphertext is sent. It MUST be derived from the member's own URI, never supplied
    // as a decoupled parameter (a mismatch would misroute/exfiltrate ciphertext). Membership mutation is
    // also gated on the room's owning authority (the hub-of-record): only this provider may mutate rooms
    // it hosts. Re-adds cannot silently flip a member's authority (store enforces same-authority on
    // conflict). These three together close the decoupled-authority + IDOR + key-flip findings.

    /// Assert this provider is the hub-of-record for `room_uri` (the room URI's authority is our domain).
    /// Mutating/serving membership for a room we don't host is rejected (no cross-room IDOR).
    fn assert_hub_of_record(&self, room_uri: &str) -> anyhow::Result<MimiUri> {
        if room_uri.len() > MAX_URI_LEN {
            anyhow::bail!("room URI too long");
        }
        let u = MimiUri::parse(room_uri)?;
        if u.kind != Some(MimiKind::Room) {
            anyhow::bail!("not a room URI: {room_uri}");
        }
        if !u.is_local_to(&self.domain) {
            anyhow::bail!(
                "not the hub-of-record for {room_uri} (this provider is {})",
                self.domain
            );
        }
        Ok(u)
    }

    /// Add a participant to a room. The provider authority is DERIVED from `member_uri` (parsed), never
    /// supplied separately, so the stored routing key always matches the member's real provider. Caller
    /// must be the hub-of-record for the room. R1.
    pub fn add_participant(
        &self,
        room_uri: &str,
        member_uri: &str,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        self.assert_hub_of_record(room_uri)?;
        if member_uri.len() > MAX_URI_LEN {
            anyhow::bail!("member URI too long");
        }
        let m = MimiUri::parse(member_uri)?;
        if m.kind != Some(MimiKind::User) {
            anyhow::bail!("member must be a user URI: {member_uri}");
        }
        // authority is the member's OWN URI host, normalized (parser lowercases via is_local_to; store
        // the canonical lowercase form so fan-out comparison is exact). NOT a caller-supplied value.
        let authority = m.authority.to_ascii_lowercase();
        self.store
            .add_participant(room_uri, member_uri, &authority, now_unix)
    }

    /// Remove a participant: they no longer receive fan-out (R2/R3). Hub-of-record gated.
    pub fn remove_participant(&self, room_uri: &str, member_uri: &str) -> anyhow::Result<bool> {
        self.assert_hub_of_record(room_uri)?;
        self.store.remove_participant(room_uri, member_uri)
    }

    pub fn list_participants(&self, room_uri: &str) -> anyhow::Result<Vec<(String, String)>> {
        self.assert_hub_of_record(room_uri)?;
        self.store.list_participants(room_uri)
    }

    /// THE HUB FAN-OUT ROUTING DECISION (M3). Given a room WE HOST, partition its participants into those
    /// LOCAL to this provider (deliver via the local queue) and those on FOREIGN providers (the ciphertext
    /// must be forwarded to that provider). Pure metadata routing; the hub never sees plaintext
    /// (INV-MIMI-002). `exclude` (typically the sender) is omitted. The stored authority was derived from
    /// each member's own URI at add-time, so it cannot have been spoofed to misroute.
    pub fn fanout_targets(&self, room_uri: &str, exclude: &str) -> anyhow::Result<FanoutPlan> {
        self.assert_hub_of_record(room_uri)?;
        let mut plan = FanoutPlan::default();
        for (member, authority) in self.store.list_participants(room_uri)? {
            if member == exclude {
                continue;
            }
            if authority.eq_ignore_ascii_case(&self.domain) {
                plan.local.push(member);
            } else {
                plan.foreign.push((authority, member));
            }
        }
        Ok(plan)
    }

    // ---- DIV-4 / C3: opt-in-only identifierQuery ----

    /// Found ONLY for opt-in enrollees; otherwise NotFound, indistinguishable from non-existent.
    /// Structurally leak-free: the answer depends only on enrollment.
    pub fn identifier_query(&self, username: &str) -> anyhow::Result<IdentifierQueryResult> {
        Ok(identifier_query(self.is_enrolled(username)?))
    }

    // ---- C1/C2/C3: consent (protocol §5.7) ----
    //
    // A directional (requester -> target) authorization the TARGET's provider holds. Requests/updates
    // arrive from a peer provider; they are VALIDATED (mimi-core) then recorded. Privacy (§5.7): the
    // caller (http) answers the same whether or not the user or requester exists (201 on the JSON lane, 202 on the
    // wire lane): no oracle.
    // room_key '' = global scope; a room-specific record overrides global.

    fn room_key(room_uri: &Option<String>) -> &str {
        room_uri.as_deref().unwrap_or("")
    }

    /// C1: accept + process a `requestConsent` from another provider: a `request` or a `cancel` (§5.7).
    ///
    /// A `request` records a pending request UNLESS a terminal decision (grant/revoke) already exists for the scope (a
    /// request must not clobber a decision). A `cancel` withdraws the pending request of the same ConsentScope, and only
    /// when `peer`, the certificate the connection presented, authenticates the domain of the requester URI (§5.7: the
    /// requesterUri is in one of the domains of the sending provider): only the requester's own provider can withdraw
    /// its request. A cancel withdraws a pending request and nothing else, so a grant, a revoke or a preemptive denial
    /// the target made stays. A cancel with no matching request, or from another provider, changes nothing; the caller
    /// answers it as any other, so it says nothing about what exists. Validates well-formedness first (fail-closed).
    pub fn process_request_consent(
        &self,
        entry: &ConsentEntry,
        peer: Option<&crate::peer::PeerIdentity>,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        validate_consent_entry(entry)?;
        let rk = Self::room_key(&entry.room_uri);
        match entry.operation {
            ConsentOperation::Request => {
                if self
                    .store
                    .consent_state(&entry.requester_uri, &entry.target_uri, rk)?
                    .is_none()
                {
                    self.store.set_consent(
                        &entry.requester_uri,
                        &entry.target_uri,
                        rk,
                        "requested",
                        now_unix,
                    )?;
                }
            }
            ConsentOperation::Cancel => {
                let requester = user_domain(&entry.requester_uri)
                    .ok_or_else(|| anyhow::anyhow!("the requester URI names no provider domain"))?;
                if !peer.is_some_and(|peer| peer.authenticates(&requester)) {
                    anyhow::bail!("a cancel is taken only from the requester's provider");
                }
                self.store
                    .withdraw_consent_request(&entry.requester_uri, &entry.target_uri, rk)?;
            }
            ConsentOperation::Grant | ConsentOperation::Revoke => {
                anyhow::bail!("requestConsent takes request or cancel");
            }
        }
        Ok(())
    }

    /// C2: accept + process an `updateConsent` (grant / revoke). `grant`→granted, `revoke`→revoked (valid
    /// PREEMPTIVELY, no prior request needed). A cancel is the requester's and goes through `requestConsent`
    /// ([`Self::process_request_consent`]). Any grant-carried client_key_packages are suite-gated (INV-MLS-002) before
    /// they could be stored/used.
    pub fn process_update_consent(
        &self,
        entry: &ConsentEntry,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        validate_consent_entry(entry)?;
        let rk = Self::room_key(&entry.room_uri);
        match entry.operation {
            ConsentOperation::Grant => {
                for kp in &entry.client_key_packages {
                    mimi_gate_keypackage(kp)?; // reject non-0x0001 grant KPs before honoring the grant
                }
                self.store.set_consent(
                    &entry.requester_uri,
                    &entry.target_uri,
                    rk,
                    "granted",
                    now_unix,
                )?;
            }
            ConsentOperation::Revoke => {
                self.store.set_consent(
                    &entry.requester_uri,
                    &entry.target_uri,
                    rk,
                    "revoked",
                    now_unix,
                )?;
            }
            ConsentOperation::Request | ConsentOperation::Cancel => {
                anyhow::bail!("a request or a cancel is a requestConsent, not an updateConsent");
            }
        }
        Ok(())
    }

    /// C3: the KeyPackage-access consent gate (protocol §5.2). Resolves whether `requester` may access
    /// `target`'s keying material (optionally for a specific room). A room-specific revoke →
    /// `NoConsentForThisRoom(6)`; a global revoke or no consent at all → `NoConsent(5)`; a grant (room or
    /// global) → `Allowed`. This is the enforcement PRIMITIVE; `serve_key_material_gated` applies it.
    pub fn keypackage_access(
        &self,
        requester_uri: &str,
        target_uri: &str,
        room_uri: Option<&str>,
    ) -> anyhow::Result<KeyPackageAccess> {
        // room-specific decision wins.
        if let Some(room) = room_uri {
            match self
                .store
                .consent_state(requester_uri, target_uri, room)?
                .as_deref()
            {
                Some("granted") => return Ok(KeyPackageAccess::Allowed),
                Some("revoked") => return Ok(KeyPackageAccess::NoConsentForThisRoom),
                _ => {} // fall through to the global scope
            }
        }
        match self
            .store
            .consent_state(requester_uri, target_uri, "")?
            .as_deref()
        {
            Some("granted") => Ok(KeyPackageAccess::Allowed),
            Some("revoked") => Ok(KeyPackageAccess::NoConsent),
            _ => Ok(KeyPackageAccess::NoConsent), // default-deny: no consent on record ⇒ no access
        }
    }

    /// C3: consent-enforced KeyPackage serve. Returns `Ok(Some(kp))` only when `requester` is consented
    /// to reach `target`; otherwise `Ok(None)` carrying WHY via the [`KeyPackageAccess`] gate code (the
    /// caller maps 5/6 to the wire). NOTE: this implementation's plain `serve_key_material` stays UNGATED by
    /// design (the inviter-driven add flow has no consent handshake yet); this is the consent-aware path.
    pub fn serve_key_material_gated(
        &self,
        requester_uri: &str,
        target_username: &str,
        target_uri: &str,
        room_uri: Option<&str>,
        now_unix: u64,
    ) -> anyhow::Result<Result<Option<Vec<u8>>, KeyPackageAccess>> {
        match self.keypackage_access(requester_uri, target_uri, room_uri)? {
            KeyPackageAccess::Allowed => {
                Ok(Ok(self.serve_key_material(target_username, now_unix)?))
            }
            deny => Ok(Err(deny)),
        }
    }

    // ---- report abuse (§5.9, DIV-8) ----

    /// §5.9: persist a metadata-only abuse report. `alleged_abuser_uri` MUST parse as a MIMI user
    /// URI (fail-closed: a report naming a malformed or non-user target is rejected rather than
    /// recorded against garbage); `reporting_user` may be empty (the draft's "optionally" reporter
    /// identity - see `AbuseReport`'s own doc comment). The draft: "There is no response body. The
    /// response code only indicates if the abuse report was accepted, not if any specific automated
    /// or human action was taken." The schema has no message-body field. The caller-supplied note
    /// is stored verbatim, and no automated action is taken.
    pub fn process_report_abuse(
        &self,
        room_uri: &str,
        report: &mimi_core::protocol_wire::AbuseReport,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        let abuser = MimiUri::parse(&report.alleged_abuser_uri.0)?;
        if abuser.kind != Some(MimiKind::User) {
            anyhow::bail!(
                "allegedAbuserUri must be a user URI: {}",
                report.alleged_abuser_uri.0
            );
        }
        self.store.record_abuse_report(
            room_uri,
            &report.reporting_user.0,
            &report.alleged_abuser_uri.0,
            report.reason_code,
            &report.note,
            now_unix,
        )
    }

    /// Count of persisted abuse reports for a room (test/inspection helper).
    pub fn abuse_report_count(&self, room_uri: &str) -> anyhow::Result<i64> {
        self.store.abuse_report_count(room_uri)
    }

    // ---- M2 / R3: sender authorization (protocol §5.4 / §5.3) ----

    /// M2 + R3: authorize a message sender in a room this hub hosts. The `sending_uri` MUST be a
    /// valid MIMI user URI and an active participant (M2). This same check enforces R3: a
    /// removed/banned participant is no longer in `room_participants`, so their traffic is rejected.
    /// Ok(()) = may send.
    ///
    /// Deviation from the draft: §5.3 says block a removed member's messages/commits/proposals except
    /// a Remove/SelfRemove proposal. This hub relays opaque ciphertext (INV-MIMI-002) and cannot see
    /// MLS handshake types inside it, so it blocks at participant-list granularity: once removed, a
    /// member can send nothing. This is stricter and correct for a ciphertext relay; there is nothing
    /// legitimate left for a removed member to send (a live member's own SelfRemove is sent while
    /// still in the list, so it passes this check before removal takes effect).
    pub fn authorize_sender(&self, room_uri: &str, sending_uri: &str) -> anyhow::Result<()> {
        self.assert_hub_of_record(room_uri)?;
        if sending_uri.len() > MAX_URI_LEN {
            anyhow::bail!("sendingUri too long");
        }
        let s = MimiUri::parse(sending_uri)?;
        if s.kind != Some(MimiKind::User) {
            anyhow::bail!("sendingUri must be a user URI: {sending_uri}");
        }
        let is_active = self
            .store
            .list_participants(room_uri)?
            .iter()
            .any(|(member, _authority)| member == sending_uri);
        if !is_active {
            anyhow::bail!(
                "sendingUri {sending_uri} is not an active participant of {room_uri} (M2/R3 reject)"
            );
        }
        // P5: if the room has a policy, the hub ALSO enforces canSendMessage (the ONE capability the hub
        // enforces per room-policy-04 §8.3; all other caps are client-enforced BY DESIGN). No policy set
        // ⇒ active-participation alone governs (backward-compatible with pre-C5 rooms).
        if let Some(policy) = self.room_policy(room_uri)? {
            let role = self.store.member_role(room_uri, sending_uri)?.unwrap_or(0);
            if !policy.can_send_message(role) {
                anyhow::bail!(
                    "sendingUri {sending_uri} (role {role}) lacks canSendMessage in {room_uri} (P5)"
                );
            }
        }
        Ok(())
    }

    // ---- P1-P6: room policy / RBAC (room-policy-04) ----

    /// Set a room's policy (validated before storage). Hub-of-record gated. Rejects a malformed
    /// policy before storage (`RoomPolicy::validate`). The hub enforces canSendMessage at runtime;
    /// the policy is also the authoritative source for role-change authorization checks.
    pub fn set_room_policy(
        &self,
        room_uri: &str,
        policy: &RoomPolicy,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        self.assert_hub_of_record(room_uri)?;
        policy.validate()?;
        let json = serde_json::to_string(policy)?;
        self.store.set_room_policy(room_uri, &json, now_unix)
    }

    /// The room's policy (None = default-permissive, no policy set). Hub-of-record gated.
    pub fn room_policy(&self, room_uri: &str) -> anyhow::Result<Option<RoomPolicy>> {
        self.assert_hub_of_record(room_uri)?;
        match self.store.room_policy_json(room_uri)? {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    /// Assign a member's role in a room (P1: one role per member). Hub-of-record gated.
    pub fn set_member_role(
        &self,
        room_uri: &str,
        member_uri: &str,
        role_index: u32,
    ) -> anyhow::Result<()> {
        self.assert_hub_of_record(room_uri)?;
        self.store.set_member_role(room_uri, member_uri, role_index)
    }

    /// P4 (+P6): authorize a role change in a room, using the room's authoritative policy. The actor's
    /// current role (from member_role) must be permitted to move `target` from→to per the policy's
    /// authorized_role_changes. Errors if no policy is set (a role change needs a policy to authorize it).
    pub fn authorize_role_change(
        &self,
        room_uri: &str,
        actor_uri: &str,
        from_role: u32,
        to_role: u32,
    ) -> anyhow::Result<()> {
        let policy = self.room_policy(room_uri)?.ok_or_else(|| {
            anyhow::anyhow!("no room policy set for {room_uri}; cannot authorize a role change")
        })?;
        let actor_role = self
            .store
            .member_role(room_uri, actor_uri)?
            .ok_or_else(|| anyhow::anyhow!("actor {actor_uri} has no role in {room_uri}"))?;
        Ok(policy.authorize_role_change(actor_role, from_role, to_role)?)
    }

    // ---- DIV-10: applying a participant-list or room-policy change from a Commit ----

    /// Decode a `PublicMessage`-wrapped Commit (`mimi_core::commit_wire`) and apply its single
    /// custom proposal to this room's stored state. Dispatches on `proposal_type`; a value that
    /// matches neither registered Haven proposal type is refused. Hub-of-record gated (via the
    /// individual `add_participant`/`remove_participant`/`set_member_role`/`set_room_policy` calls
    /// this delegates to, each of which already enforces it).
    pub fn apply_update_commit(
        &self,
        room_uri: &str,
        commit_bytes: &[u8],
        now_unix: u64,
    ) -> Result<(), UpdateRefusal> {
        // A Commit refused for the changes it carries together says which rule refused it; any other is unreadable.
        let mut commit = decode_commit_proposals(commit_bytes).map_err(|error| {
            UpdateRefusal::Invalid(
                changes_refusal(&error).unwrap_or("the commit is not one this hub can read"),
            )
        })?;
        // A KeyPackage the gate refuses (a foreign suite, a bad signature) refuses the whole Commit before anything changes.
        for added in &commit.adds {
            mimi_core::gate::mimi_gate_keypackage(&added.key_package)
                .map_err(|_| UpdateRefusal::NotAllowed)?;
        }
        self.assert_hub_of_record(room_uri)
            .map_err(|_| UpdateRefusal::NotAllowed)?;
        self.include_held_proposals(room_uri, &mut commit, now_unix)?;
        let epoch = commit.epoch;
        self.apply_decoded_commit(room_uri, &commit, now_unix)?;
        self.store
            .commit_accepted_at(room_uri, epoch)
            .map_err(|_| UpdateRefusal::Store)
    }

    /// Read the proposals `commit` names by reference into it, from what this hub holds for the room at the Commit's
    /// epoch (protocol-07 §3.5, RFC 9420 §12.4). Every reference must name a proposal held for that epoch, and every
    /// proposal held for it must be named: the hub requires the next Commit to include them. A held Remove joins the
    /// Commit's Removes and a held change becomes its change; a held change beside one sent by value is a second change.
    fn include_held_proposals(
        &self,
        room_uri: &str,
        commit: &mut DecodedCommit,
        now_unix: u64,
    ) -> Result<(), UpdateRefusal> {
        let held = self
            .store
            .held_proposals(room_uri, commit.epoch, now_unix)
            .map_err(|_| UpdateRefusal::Store)?;
        let unknown: Vec<Vec<u8>> = commit
            .references
            .iter()
            .enumerate()
            .filter(|(at, reference)| {
                commit.references[..*at].contains(reference)
                    || !held.iter().any(|(name, _)| name == *reference)
            })
            .map(|(_, reference)| reference.clone())
            .collect();
        if !unknown.is_empty() {
            return Err(UpdateRefusal::InvalidProposals(
                "the Commit names a proposal this hub does not hold for its epoch, or names one twice",
                unknown,
            ));
        }
        let left_out: Vec<Vec<u8>> = held
            .iter()
            .filter(|(name, _)| !commit.references.contains(name))
            .map(|(name, _)| name.clone())
            .collect();
        if !left_out.is_empty() {
            return Err(UpdateRefusal::InvalidProposals(
                "the Commit leaves out proposals this hub holds for its epoch",
                left_out,
            ));
        }
        for reference in &commit.references {
            let (_, message) = held
                .iter()
                .find(|(name, _)| name == reference)
                .ok_or(UpdateRefusal::Store)?;
            match decode_proposal_message(message)
                .map_err(|_| UpdateRefusal::Store)?
                .proposal
            {
                ReadProposal::Remove(leaf) => commit.removes.push(leaf),
                ReadProposal::Change(change) => commit.updates.push(change),
            }
        }
        check_changes(&commit.updates).map_err(UpdateRefusal::Invalid)
    }

    /// Apply a Commit whose references are already read in: its participant-list change, its room-policy change, or one
    /// of each ([`check_changes`] has already refused any other combination). Everything is decoded and checked before
    /// anything is written; the participant change is written first and the room policy second, so only a store failure
    /// between the two writes could leave one without the other.
    fn apply_decoded_commit(
        &self,
        room_uri: &str,
        commit: &DecodedCommit,
        now_unix: u64,
    ) -> Result<(), UpdateRefusal> {
        if commit.updates.is_empty() {
            return Err(UpdateRefusal::Invalid(
                "the Commit carries no participant-list or room-policy change",
            ));
        }
        let mut participants = None;
        let mut roles = None;
        let mut base = None;
        for change in &commit.updates {
            match change.proposal_type {
                MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE => {
                    participants = Some(decode_participant_list_update(&change.payload).map_err(
                        |_| UpdateRefusal::Invalid("the participant list update is malformed"),
                    )?);
                }
                MIMI_ROLES_LIST_PROPOSAL_TYPE => {
                    roles = Some(
                        decode_role_data(&change.payload)
                            .map_err(|_| UpdateRefusal::Invalid("the role list is malformed"))?,
                    );
                }
                MIMI_BASE_ROOM_POLICY_PROPOSAL_TYPE => {
                    base = Some(decode_base_room_policy(&change.payload).map_err(|_| {
                        UpdateRefusal::Invalid("the base room policy is malformed")
                    })?);
                }
                _ => {
                    return Err(UpdateRefusal::Invalid(
                        "the proposal type is not recognized",
                    ))
                }
            }
        }
        self.assert_hub_of_record(room_uri)
            .map_err(|_| UpdateRefusal::NotAllowed)?;
        self.check_commit_against_list(
            room_uri,
            commit,
            participants
                .as_ref()
                .unwrap_or(&ParticipantListUpdate::default()),
        )?;
        // The policy the room ends with: a new role list keeps the base policy (or the draft's default while the room
        // has none); a new base policy keeps the roles, and a room with no roles stored takes the roles first.
        let policy = if roles.is_some() || base.is_some() {
            let stored = self
                .room_policy(room_uri)
                .map_err(|_| UpdateRefusal::Store)?;
            let roles = match (roles, &stored) {
                (Some(roles), _) => roles,
                (None, Some(stored)) => stored.roles.clone(),
                (None, None) => {
                    return Err(UpdateRefusal::Invalid(
                        "the room has no roles yet; send the role list first",
                    ))
                }
            };
            let base = base
                .or_else(|| stored.map(|policy| policy.base))
                .unwrap_or_default();
            let policy = RoomPolicy { base, roles };
            policy
                .validate()
                .map_err(|_| UpdateRefusal::Invalid("the room policy is not valid"))?;
            Some(policy)
        } else {
            None
        };
        if let Some(update) = &participants {
            self.apply_participant_list_update(room_uri, update, now_unix)?;
        }
        match policy {
            Some(policy) => self.store_room_policy(room_uri, policy, now_unix),
            None => Ok(()),
        }
    }

    /// What a Commit's `Add` and `Remove` proposals must say beside its change (when it has any), checked against the list the room holds now
    /// and the update (§7.5): every user the update adds has an `Add` for one of its clients, no `Add` is for a user who is
    /// neither listed nor added by the update, and an update that removes users has a `Remove` to go with them. A `Remove`
    /// is a leaf index and the hub holds no ratchet tree, so which user it is cannot be checked; a `Remove` without a
    /// removed user (one device of a listed user) is allowed, and an `Add` for a listed user (a second device) too.
    fn check_commit_against_list(
        &self,
        room_uri: &str,
        commit: &DecodedCommit,
        update: &ParticipantListUpdate,
    ) -> Result<(), UpdateRefusal> {
        const MISMATCH: UpdateRefusal =
            UpdateRefusal::Invalid("the Commit's Add and Remove proposals do not match its change");
        self.assert_hub_of_record(room_uri)
            .map_err(|_| UpdateRefusal::NotAllowed)?;
        // A Commit with the change alone is read as it always was: a participant can be listed before any client is added.
        if commit.adds.is_empty() && commit.removes.is_empty() {
            return Ok(());
        }
        let rows = self
            .store
            .list_participant_rows(room_uri)
            .map_err(|_| UpdateRefusal::Store)?;
        let named = |identity: &[u8]| -> bool {
            std::str::from_utf8(identity).is_ok_and(|uri| {
                rows.iter().any(|row| row.member_uri == uri)
                    || update
                        .added_participants
                        .iter()
                        .any(|added| added.user_uri == uri)
            })
        };
        if commit.adds.iter().any(|added| !named(&added.identity)) {
            return Err(MISMATCH);
        }
        for added in &update.added_participants {
            if !commit
                .adds
                .iter()
                .any(|add| add.identity == added.user_uri.as_bytes())
            {
                return Err(MISMATCH);
            }
        }
        if !update.removed_indices.is_empty() && commit.removes.is_empty() {
            return Err(MISMATCH);
        }
        Ok(())
    }

    /// Validate and store a room policy that arrived in an update.
    fn store_room_policy(
        &self,
        room_uri: &str,
        policy: RoomPolicy,
        now_unix: u64,
    ) -> Result<(), UpdateRefusal> {
        policy
            .validate()
            .map_err(|_| UpdateRefusal::Invalid("the room policy is not valid"))?;
        self.set_room_policy(room_uri, &policy, now_unix)
            .map_err(|e| store_refusal(&e))
    }

    /// `update` (§5.3): the request body is an `UpdateRequest`, which for MLS is a `HandshakeBundle`. A Commit bundle's
    /// commit goes through [`Self::apply_update_commit`]; a bundle of proposals is a member leaving (protocol-07 §3.5)
    /// and goes through [`Self::hold_leave_proposals`]. The Welcome, `GroupInfoOption` and `RatchetTreeOption` of a Commit
    /// bundle are read and suite-gated by the codec and are neither stored nor relayed. Nothing changes unless the whole
    /// request is accepted.
    pub fn apply_update_request(
        &self,
        room_uri: &str,
        body: &[u8],
        peer: Option<&crate::peer::PeerIdentity>,
        now_unix: u64,
    ) -> Result<(), UpdateRefusal> {
        let bundle = HandshakeBundle::decode(body).map_err(|error| match error {
            WireError::CiphersuiteGate(_) => UpdateRefusal::NotAllowed,
            _ => UpdateRefusal::Invalid("the body is not an UpdateRequest this hub can read"),
        })?;
        match bundle {
            HandshakeBundle::Commit {
                proposal_or_commit, ..
            } => self.apply_update_commit(room_uri, &proposal_or_commit, now_unix),
            HandshakeBundle::Proposal {
                proposal_or_commit,
                more_proposals,
            } => self.hold_leave_proposals(
                room_uri,
                peer,
                std::iter::once(&proposal_or_commit).chain(&more_proposals),
                now_unix,
            ),
        }
    }

    /// Hold a leaving member's proposals for the room's next Commit (protocol-07 §3.5): one participant-list change that
    /// only removes participants, and `Remove`s for the devices of the user leaving, all of one epoch. They are held by
    /// `ProposalRef`, and the next Commit at that epoch must include every one by reference.
    ///
    /// The hub verifies no proposal's signature (it holds no group state), so what it requires a Commit to include is
    /// bounded by who asked: every user the change removes is one whose provider the peer's certificate authenticates. A
    /// `Remove` is a leaf index the hub cannot map to a user (it holds no ratchet tree), so it is not bound to a provider;
    /// the room's bounds on what it holds (`store::MAX_PENDING_PROPOSALS_PER_ROOM`, the byte bounds) and their expiry
    /// (`store::PROPOSAL_TTL_SECS`) bound what a leave can make the next Commit carry. Members verify each proposal before
    /// committing it, so one they cannot verify holds the room's Commits at that epoch until it expires.
    ///
    /// The epoch is the one the hub learned from the room's latest accepted Commit (persisted with the room); a room the
    /// hub has not seen a Commit for takes a leave at the leave's own epoch.
    ///
    /// Refused, in this order: what is not a leave, read from the messages alone (`invalidProposal`: a change that adds
    /// or changes a role, a room-policy change, two changes, proposals of more than one epoch, or `Remove`s with no
    /// change, since a Commit of `Remove`s alone is not one this hub reads and holding them would hold the room); no peer
    /// certificate (`notAllowed`); another epoch than the room's (`wrongEpoch` naming it, so a leave replayed after its
    /// Commit says so whatever its indices name now); a removed index past the room's list (`invalidProposal`) or a
    /// removed user of another provider (`notAllowed`, as a room this hub does not host); a message or a room's held
    /// proposals past their bounds (`notAllowed` saying so).
    pub fn hold_leave_proposals<'a>(
        &self,
        room_uri: &str,
        peer: Option<&crate::peer::PeerIdentity>,
        messages: impl Iterator<Item = &'a Vec<u8>>,
        now_unix: u64,
    ) -> Result<(), UpdateRefusal> {
        const NOT_A_LEAVE: UpdateRefusal = UpdateRefusal::Invalid(
            "proposals are taken only as a leave: Removes and one participant-list change that only removes",
        );
        self.assert_hub_of_record(room_uri)
            .map_err(|_| UpdateRefusal::NotAllowed)?;
        // What the messages are is read first, from their bytes alone; then that the peer presented a certificate, the
        // room's epoch, whose provider the removed users are, and the bounds. Only the provider of a participant a leave
        // removes learns what the room holds.
        let mut epoch = None;
        let mut change = None;
        let mut oversized = false;
        let mut held = Vec::new();
        for message in messages {
            oversized |= message.len() > crate::store::MAX_PROPOSAL_BYTES;
            let proposal = decode_proposal_message(message)
                .map_err(|_| UpdateRefusal::Invalid("a proposal is not one this hub can read"))?;
            if *epoch.get_or_insert(proposal.epoch) != proposal.epoch {
                return Err(UpdateRefusal::Invalid(
                    "the proposals are not all of one epoch",
                ));
            }
            match &proposal.proposal {
                // -07 §3.5: the leaving client proposes the removal of every device of its user, itself included.
                ReadProposal::Remove(_) => {}
                ReadProposal::Change(decoded) => {
                    if change.is_some()
                        || decoded.proposal_type != MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE
                    {
                        return Err(NOT_A_LEAVE);
                    }
                    let update =
                        decode_participant_list_update(&decoded.payload).map_err(|_| {
                            UpdateRefusal::Invalid("the participant list update is malformed")
                        })?;
                    if update.removed_indices.is_empty()
                        || !update.added_participants.is_empty()
                        || !update.changed_role_participants.is_empty()
                    {
                        return Err(NOT_A_LEAVE);
                    }
                    change = Some(update);
                }
            }
            held.push((proposal.reference, message.clone()));
        }
        let (Some(epoch), Some(change)) = (epoch, change) else {
            return Err(NOT_A_LEAVE);
        };
        let peer = peer.ok_or(UpdateRefusal::NotAllowed)?;
        // A room the hub has not seen a Commit for has no epoch here to hold the leave to: it is held at its own epoch,
        // and binds only a Commit at that epoch. The epoch is read before the indices, so a leave replayed after its
        // Commit is answered as of a past epoch, whatever its indices name in the room now.
        if let Some(room_epoch) = self
            .store
            .room_epoch(room_uri)
            .map_err(|_| UpdateRefusal::Store)?
        {
            if epoch != room_epoch {
                return Err(UpdateRefusal::WrongEpoch(room_epoch));
            }
        }
        let rows = self
            .store
            .list_participant_rows(room_uri)
            .map_err(|_| UpdateRefusal::Store)?;
        for index in &change.removed_indices {
            let row = rows.get(*index as usize).ok_or(UpdateRefusal::Invalid(
                "the participant list update does not fit the room",
            ))?;
            if !peer.authenticates(&row.authority) {
                return Err(UpdateRefusal::NotAllowed);
            }
        }
        if oversized {
            return Err(UpdateRefusal::Limit(
                "a proposal is larger than a leave needs",
            ));
        }
        self.store
            .hold_proposals(room_uri, epoch, &held, now_unix)
            .map_err(|e| match store_refusal(&e) {
                UpdateRefusal::NotAllowed => UpdateRefusal::Limit(
                    "the room holds as many proposals as it can for its next Commit",
                ),
                other => other,
            })
    }

    /// Enact a `ParticipantListUpdate` on this room's participants vector, as ONE atomic transition: a failure
    /// (the participant cap, a refused update) leaves the room as it was.
    ///
    /// What an update does to a list is decided in one place, `mimi_core::participant_list::apply_update`, the
    /// draft's own rules (§7.5): indices count the vector as it stood before the update, a removal does not shift
    /// the other indices, added participants are appended, and a user who is already listed cannot be added (so a
    /// user removed and added in the same update is refused too: the list an update is checked against is the one
    /// before it). The room is then written from that result; there is no second resolver here.
    fn apply_participant_list_update(
        &self,
        room_uri: &str,
        update: &ParticipantListUpdate,
        now_unix: u64,
    ) -> Result<(), UpdateRefusal> {
        self.assert_hub_of_record(room_uri)
            .map_err(|_| UpdateRefusal::NotAllowed)?;
        let rows = self
            .store
            .list_participant_rows(room_uri)
            .map_err(|_| UpdateRefusal::Store)?;
        let current = ParticipantListData {
            participants: rows
                .iter()
                .map(|row| UserRolePair {
                    user_uri: row.member_uri.clone(),
                    // A member the hub holds no role for reads as role 0 here; `role_index` of the stored row
                    // stays `None` unless the update names the member.
                    role_index: row.role_index.unwrap_or(0),
                })
                .collect(),
        };
        let next = apply_update(&current, update).map_err(|_| {
            UpdateRefusal::Invalid("the participant list update does not fit the room")
        })?;

        // authority is DERIVED from each added member's own URI (parsed), never supplied separately.
        let mut written = Vec::with_capacity(next.participants.len());
        for member in &next.participants {
            let kept = rows.iter().find(|row| row.member_uri == member.user_uri);
            let named = update
                .changed_role_participants
                .iter()
                .any(|c| current.participants[c.user_index as usize].user_uri == member.user_uri);
            written.push(match kept {
                Some(row) => ParticipantRow {
                    member_uri: row.member_uri.clone(),
                    authority: row.authority.clone(),
                    role_index: if named {
                        Some(member.role_index)
                    } else {
                        row.role_index
                    },
                },
                None => {
                    const BAD_MEMBER: UpdateRefusal =
                        UpdateRefusal::Invalid("an added participant is not a user URI");
                    if member.user_uri.len() > MAX_URI_LEN {
                        return Err(BAD_MEMBER);
                    }
                    let parsed = MimiUri::parse(&member.user_uri).map_err(|_| BAD_MEMBER)?;
                    if parsed.kind != Some(MimiKind::User) {
                        return Err(BAD_MEMBER);
                    }
                    ParticipantRow {
                        member_uri: member.user_uri.clone(),
                        authority: parsed.authority.to_ascii_lowercase(),
                        role_index: Some(member.role_index),
                    }
                }
            });
        }
        self.store
            .replace_participants(room_uri, &written, now_unix)
            .map_err(|e| store_refusal(&e))
    }
}

#[cfg(test)]
mod participant_order_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a real, canonical 0x0001 KeyPackage (the same serialization openmls hashes for its ref).
    /// Mirrors mimi-core's gate-test builder; used to prove the K3/K4 wiring end-to-end.
    fn real_keypackage(user: &str) -> Vec<u8> {
        use openmls::ciphersuite::signature::SignaturePublicKey;
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::prelude::*;
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;
        use tls_codec::Serialize as _;

        struct TestSigner {
            key: Vec<u8>,
            scheme: SignatureScheme,
        }
        impl Signer for TestSigner {
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
        let scheme = SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(user.as_bytes().to_vec()).into(),
            signature_key: pk,
        };
        let signer = TestSigner {
            key: priv_b,
            scheme,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
            "not_before": now.saturating_sub(3600),
            "not_after": now + 60 * 60 * 24 * 84,
        }))
        .unwrap();
        let kpb = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime)
            .build(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                &provider,
                &signer,
                cwk,
            )
            .unwrap();
        kpb.key_package().tls_serialize_detached().unwrap()
    }

    #[test]
    fn publish_associates_kpref_to_local_client_k4() {
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        let kp = real_keypackage("alice");
        p.publish_key_package("alice", &kp, 1000).unwrap();
        // the ref is the canonical openmls ref over the same bytes → resolves to the served client.
        let kpref = keypackage_ref(&kp).unwrap();
        assert_eq!(
            p.client_for_kpref(&kpref).unwrap(),
            Some("alice".into()),
            "K4: ref -> local client"
        );
        assert_eq!(p.client_for_kpref(b"unknown").unwrap(), None);
        // and the KP itself is still claimable (publish stored both the KP and the association).
        assert_eq!(
            p.serve_key_material("alice", 1000).unwrap(),
            Some(kp),
            "KP still claimable"
        );
    }

    #[test]
    fn hub_associates_kpref_to_provider_k3_and_forgets() {
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let kp = real_keypackage("bob");
        // K3: hub claims bob's KP from provider B → records ref -> B.
        let kpref = hub
            .associate_claimed_keypackage(&kp, "mimi-b.havenmessenger.com", 9_999)
            .unwrap();
        assert_eq!(
            kpref,
            keypackage_ref(&kp).unwrap(),
            "returns the canonical ref"
        );
        assert_eq!(
            hub.provider_for_kpref(&kpref).unwrap(),
            Some("mimi-b.havenmessenger.com".into()),
            "K3: ref -> target provider"
        );
        // forget on consume (after the Welcome is forwarded).
        hub.forget_kpref(&kpref).unwrap();
        assert_eq!(
            hub.provider_for_kpref(&kpref).unwrap(),
            None,
            "consumed -> forgotten"
        );
    }

    #[test]
    fn publish_rejects_foreign_suite_before_associating() {
        // a non-KeyPackage (or foreign suite) must error at the gate; nothing gets associated/stored.
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        assert!(p
            .publish_key_package("alice", b"not a keypackage", 1000)
            .is_err());
        assert_eq!(
            p.client_for_kpref(b"anything").unwrap(),
            None,
            "no association on a rejected publish"
        );
    }

    // ---- C3: consent (process + gate) ----

    fn consent_entry(op: ConsentOperation, room: Option<&str>) -> ConsentEntry {
        ConsentEntry {
            operation: op,
            requester_uri: "mimi://mimi-b.havenmessenger.com/u/bob".into(),
            target_uri: "mimi://mimi.havenmessenger.com/u/alice".into(),
            room_uri: room.map(|s| s.to_string()),
            client_key_packages: vec![],
            consent_extensions: vec![],
        }
    }

    #[test]
    fn consent_request_then_grant_then_gate_allows() {
        let p = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let req = "mimi://mimi-b.havenmessenger.com/u/bob";
        let tgt = "mimi://mimi.havenmessenger.com/u/alice";
        // before any consent: default-deny → NoConsent(5)
        assert_eq!(
            p.keypackage_access(req, tgt, None).unwrap(),
            KeyPackageAccess::NoConsent
        );
        // a request is recorded but does NOT grant access
        p.process_request_consent(&consent_entry(ConsentOperation::Request, None), None, 1)
            .unwrap();
        assert_eq!(
            p.keypackage_access(req, tgt, None).unwrap(),
            KeyPackageAccess::NoConsent
        );
        // a grant opens it
        p.process_update_consent(&consent_entry(ConsentOperation::Grant, None), 2)
            .unwrap();
        assert_eq!(
            p.keypackage_access(req, tgt, None).unwrap(),
            KeyPackageAccess::Allowed
        );
    }

    #[test]
    fn consent_preemptive_revoke_and_room_override() {
        let p = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let req = "mimi://mimi-b.havenmessenger.com/u/bob";
        let tgt = "mimi://mimi.havenmessenger.com/u/alice";
        let room = "mimi://mimi.havenmessenger.com/r/x";
        // preemptive revoke (no prior request) → NoConsent
        p.process_update_consent(&consent_entry(ConsentOperation::Revoke, None), 1)
            .unwrap();
        assert_eq!(
            p.keypackage_access(req, tgt, None).unwrap(),
            KeyPackageAccess::NoConsent
        );
        // global grant, but a room-specific revoke overrides for that room
        p.process_update_consent(&consent_entry(ConsentOperation::Grant, None), 2)
            .unwrap();
        p.process_update_consent(&consent_entry(ConsentOperation::Revoke, Some(room)), 3)
            .unwrap();
        assert_eq!(
            p.keypackage_access(req, tgt, Some(room)).unwrap(),
            KeyPackageAccess::NoConsentForThisRoom
        );
        // a DIFFERENT room still rides the global grant
        let other = "mimi://mimi.havenmessenger.com/r/y";
        assert_eq!(
            p.keypackage_access(req, tgt, Some(other)).unwrap(),
            KeyPackageAccess::Allowed
        );
    }

    #[test]
    fn gated_serve_returns_kp_only_when_consented() {
        let p = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let req = "mimi://mimi-b.havenmessenger.com/u/bob";
        let tgt = "mimi://mimi.havenmessenger.com/u/alice";
        let kp = real_keypackage("alice");
        p.publish_key_package("alice", &kp, 1000).unwrap();
        // no consent → Err(NoConsent), KP NOT served (and still claimable later)
        match p
            .serve_key_material_gated(req, "alice", tgt, None, 1000)
            .unwrap()
        {
            Err(KeyPackageAccess::NoConsent) => {}
            other => panic!("expected NoConsent deny, got {other:?}"),
        }
        // grant → KP served
        p.process_update_consent(&consent_entry(ConsentOperation::Grant, None), 1)
            .unwrap();
        let served = p
            .serve_key_material_gated(req, "alice", tgt, None, 1000)
            .unwrap()
            .unwrap();
        assert_eq!(served, Some(kp), "consented requester gets the KP");
    }

    #[test]
    fn consent_rejects_malformed_and_wrong_op() {
        let p = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        // request with a grant op → rejected by process_request_consent
        assert!(p
            .process_request_consent(&consent_entry(ConsentOperation::Grant, None), None, 1)
            .is_err());
        // grant carrying a garbage (non-0x0001) KeyPackage → gated out
        let mut bad = consent_entry(ConsentOperation::Grant, None);
        bad.client_key_packages = vec![b"not a keypackage".to_vec()];
        assert!(
            p.process_update_consent(&bad, 1).is_err(),
            "grant KP suite-gated"
        );
    }

    // ---- M2 / R3: sender authorization ----

    #[test]
    fn authorize_sender_enforces_active_participation_m2_r3() {
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/x";
        let alice = "mimi://mimi.havenmessenger.com/u/alice";
        let bob = "mimi://mimi-b.havenmessenger.com/u/bob";
        hub.add_participant(room, alice, 1).unwrap();
        hub.add_participant(room, bob, 1).unwrap();
        // active participants may send (M2)
        assert!(hub.authorize_sender(room, alice).is_ok());
        assert!(hub.authorize_sender(room, bob).is_ok());
        // a non-participant may not (M2)
        assert!(hub
            .authorize_sender(room, "mimi://mimi.havenmessenger.com/u/eve")
            .is_err());
        // R3: once removed, the (formerly active) member is rejected
        hub.remove_participant(room, bob).unwrap();
        assert!(
            hub.authorize_sender(room, bob).is_err(),
            "removed participant blocked (R3)"
        );
        // malformed / non-user sendingUri rejected
        assert!(hub.authorize_sender(room, "https://evil/u/x").is_err());
        assert!(hub
            .authorize_sender(room, "mimi://mimi.havenmessenger.com/r/notauser")
            .is_err());
        // a room we don't host → rejected (no cross-room IDOR)
        assert!(hub
            .authorize_sender("mimi://mimi-b.havenmessenger.com/r/foreign", alice)
            .is_err());
    }

    // ---- P1-P6: room policy / RBAC ----

    // Role-change graph lives on the ACTOR's (admin's) own authorized_role_changes - room-policy-04
    // §8.1.3 grants canChangeUserRole "according to the holder's authorized_role_changes list", and the
    // holder is the actor, not whatever role happens to equal the target's from_role.
    fn rbac_policy() -> RoomPolicy {
        use mimi_core::room_policy::{
            BaseRoomPolicy, Capability, Role, SingleSourceRoleChangeTargets,
        };
        RoomPolicy {
            base: BaseRoomPolicy::default(),
            roles: vec![
                Role {
                    role_index: 0,
                    role_name: "non-participant".into(),
                    capabilities: vec![],
                    authorized_role_changes: vec![],
                },
                Role {
                    role_index: 1,
                    role_name: "banned".into(),
                    capabilities: vec![],
                    authorized_role_changes: vec![],
                },
                Role {
                    role_index: 2,
                    role_name: "admin".into(),
                    capabilities: vec![
                        Capability::SendMessage,
                        Capability::AddParticipant,
                        Capability::RemoveParticipant,
                        Capability::Ban,
                    ],
                    authorized_role_changes: vec![
                        SingleSourceRoleChangeTargets {
                            from_role_index: 0,
                            target_role_indexes: vec![2, 3],
                        },
                        SingleSourceRoleChangeTargets {
                            from_role_index: 3,
                            target_role_indexes: vec![0, 1],
                        },
                    ],
                },
                Role {
                    role_index: 3,
                    role_name: "member".into(),
                    capabilities: vec![Capability::SendMessage],
                    authorized_role_changes: vec![],
                },
            ],
        }
    }

    #[test]
    fn p5_hub_enforces_can_send_message_when_policy_set() {
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/x";
        let alice = "mimi://mimi.havenmessenger.com/u/alice"; // will be a member (can send)
        let mallory = "mimi://mimi.havenmessenger.com/u/mallory"; // will be banned (cannot send)
        hub.add_participant(room, alice, 1).unwrap();
        hub.add_participant(room, mallory, 1).unwrap();
        // BEFORE a policy: active participation alone governs (backward-compatible) - both may send.
        assert!(hub.authorize_sender(room, alice).is_ok());
        assert!(hub.authorize_sender(room, mallory).is_ok());
        // set a policy + roles
        hub.set_room_policy(room, &rbac_policy(), 1).unwrap();
        hub.set_member_role(room, alice, 3).unwrap(); // member
        hub.set_member_role(room, mallory, 1).unwrap(); // banned
                                                        // P5 now ALSO applies: member sends, banned cannot.
        assert!(
            hub.authorize_sender(room, alice).is_ok(),
            "member with SendMessage may send"
        );
        assert!(
            hub.authorize_sender(room, mallory).is_err(),
            "banned role cannot send (P5)"
        );
        // a member still in the participant list but with no role assigned defaults to role 0 → cannot send
        let ghost = "mimi://mimi.havenmessenger.com/u/ghost";
        hub.add_participant(room, ghost, 1).unwrap();
        assert!(
            hub.authorize_sender(room, ghost).is_err(),
            "unassigned role (0) cannot send under a policy"
        );
    }

    #[test]
    fn p4_p6_role_change_uses_room_authoritative_policy() {
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/x";
        let admin = "mimi://mimi.havenmessenger.com/u/admin";
        let member = "mimi://mimi.havenmessenger.com/u/member";
        hub.set_room_policy(room, &rbac_policy(), 1).unwrap();
        hub.set_member_role(room, admin, 2).unwrap();
        hub.set_member_role(room, member, 3).unwrap();
        // admin may add (0->3) and ban (3->1)
        assert!(hub.authorize_role_change(room, admin, 0, 3).is_ok());
        assert!(hub.authorize_role_change(room, admin, 3, 1).is_ok());
        // the member (only SendMessage) may NOT add
        assert!(
            hub.authorize_role_change(room, member, 0, 3).is_err(),
            "member lacks AddParticipant (P4)"
        );
        // a role change with no policy set is refused (needs an authoritative policy, P6)
        let other = "mimi://mimi.havenmessenger.com/r/nopolicy";
        assert!(hub.authorize_role_change(other, admin, 0, 3).is_err());
    }

    #[test]
    fn room_policy_validate_rejects_malformed_before_store() {
        use mimi_core::room_policy::{BaseRoomPolicy, Capability, Role};
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/x";
        // a fixed_membership policy whose role holds AddParticipant is invalid (P3) → set rejected.
        let bad = RoomPolicy {
            base: BaseRoomPolicy {
                fixed_membership: true,
                ..BaseRoomPolicy::default()
            },
            roles: vec![Role {
                role_index: 2,
                role_name: "admin".into(),
                capabilities: vec![Capability::AddParticipant],
                authorized_role_changes: vec![],
            }],
        };
        assert!(
            hub.set_room_policy(room, &bad, 1).is_err(),
            "invalid policy rejected before storage"
        );
        assert!(
            hub.room_policy(room).unwrap().is_none(),
            "nothing stored on a rejected policy"
        );
    }

    #[test]
    fn directory_advertises_only_0x0001_and_discloses_unsupported() {
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        let dir = p.directory();
        assert_eq!(dir["provider"], "havenmessenger.com");
        assert_eq!(dir["mls_ciphersuites"], serde_json::json!([1]));
        assert!(dir["unsupported"]["groupInfo_external_commit_join"].is_string());
        assert!(dir["unsupported"]["assets_ohttp"].is_string());
    }

    #[test]
    fn directory_advertises_the_wire_lane_with_real_path_templates() {
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        let dir = p.directory();
        let wire = &dir["wireEndpoints"];
        assert_eq!(wire["submitMessage"], "/mimi/pl/submitMessage/{roomId}");
        assert_eq!(wire["keyMaterial"], "/mimi/pl/keyMaterial/{targetUser}");
        assert_eq!(wire["notify"], "/mimi/pl/notify/{roomId}");
        assert_eq!(wire["identifierQuery"], "/mimi/pl/identifierQuery/{domain}");
        assert_eq!(
            wire["requestConsent"],
            "/mimi/pl/requestConsent/{targetDomain}"
        );
        assert_eq!(
            wire["updateConsent"],
            "/mimi/pl/updateConsent/{requesterDomain}"
        );
        assert_eq!(wire["reportAbuse"], "/mimi/pl/reportAbuse/{roomId}");
        assert_eq!(wire["update"], "/mimi/pl/update/{roomId}");
        // groupInfo/download and the 4 admin endpoints have no wire route yet: the
        // directory must not claim one exists.
        assert!(wire.get("groupInfo").is_none());
        assert!(wire.get("roomPolicy").is_none());
        assert!(dir["unsupported"]["update_wire_endpoint_mixed_commits"].is_string());
        assert!(dir["unsupported"]["reportAbuse_with_abusive_messages"].is_string());
    }

    #[test]
    fn the_directory_names_the_drafts_it_follows() {
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        let drafts = &p.directory()["protocol_drafts"];
        assert_eq!(drafts["protocol"], "07");
        assert_eq!(drafts["content"], "10");
        assert_eq!(drafts["room-policy"], "04");
    }

    /// What the directory says of a Commit sent to `update` is what the route does: Add and Remove beside its changes
    /// are applied, proposals by reference are taken only for a held leave, and a second change of one kind is refused.
    #[test]
    fn the_directory_says_which_commits_update_applies_and_which_it_refuses() {
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        let said = p.directory()["unsupported"]["update_wire_endpoint_mixed_commits"]
            .as_str()
            .expect("a statement")
            .to_owned();
        let (applied, refused) = said
            .split_once(" A second change of one kind")
            .expect("what is applied, then what is refused");
        assert!(applied.starts_with("DIV-10: "), "{said}");
        assert!(
            applied.contains("a participant-list change, a room-policy change, or one of each"),
            "{said}"
        );
        assert!(applied.contains("Add and Remove"), "{said}");
        assert!(applied.contains("by reference"), "{said}");
        assert!(refused.ends_with("are refused"), "{said}");
    }

    #[test]
    fn directory_advertises_flat_draft_shaped_keys_for_wire_routed_endpoints() {
        // protocol-07 §5.1's own example directory is a FLAT object - top-level keys are the
        // endpoint names, values are absolute HTTPS URLs. `endpoints`/`wireEndpoints` are Haven's
        // additive non-standard nesting; a strict §5.1 client looks at the top level directly.
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        let dir = p.directory();
        assert_eq!(
            dir["keyMaterial"],
            "https://havenmessenger.com/mimi/pl/keyMaterial/{targetUser}"
        );
        assert_eq!(
            dir["submitMessage"],
            "https://havenmessenger.com/mimi/pl/submitMessage/{roomId}"
        );
        assert_eq!(
            dir["notify"],
            "https://havenmessenger.com/mimi/pl/notify/{roomId}"
        );
        assert_eq!(
            dir["identifierQuery"],
            "https://havenmessenger.com/mimi/pl/identifierQuery/{domain}"
        );
        assert_eq!(
            dir["requestConsent"],
            "https://havenmessenger.com/mimi/pl/requestConsent/{targetDomain}"
        );
        assert_eq!(
            dir["updateConsent"],
            "https://havenmessenger.com/mimi/pl/updateConsent/{requesterDomain}"
        );
        assert_eq!(
            dir["reportAbuse"],
            "https://havenmessenger.com/mimi/pl/reportAbuse/{roomId}"
        );
        assert_eq!(
            dir["update"],
            "https://havenmessenger.com/mimi/pl/update/{roomId}"
        );
        // the two draft keys nothing here serves must NOT appear at the top level - advertise
        // only what's actually wire-routed.
        assert!(dir.get("groupInfo").is_none());
        assert!(dir.get("proxyDownload").is_none());
    }

    #[test]
    fn directory_flat_keys_use_the_public_base_url() {
        let p = Provider::in_memory("havenmessenger.com")
            .unwrap()
            .with_public_base_url("https://mimi.havenmessenger.com:8443/")
            .unwrap();
        let dir = p.directory();
        assert_eq!(
            dir["keyMaterial"],
            "https://mimi.havenmessenger.com:8443/mimi/pl/keyMaterial/{targetUser}"
        );
        assert_eq!(
            dir["update"],
            "https://mimi.havenmessenger.com:8443/mimi/pl/update/{roomId}"
        );
        // Identifiers and the relative-path nestings are unaffected.
        assert_eq!(dir["provider"], "havenmessenger.com");
        assert_eq!(
            dir["wireEndpoints"]["keyMaterial"],
            "/mimi/pl/keyMaterial/{targetUser}"
        );
    }

    #[test]
    fn public_base_url_must_be_https_with_a_host() {
        for bad in [
            "http://mimi.example.com",
            "https://",
            "https:///mimi",
            "https://mimi.example.com?x=1",
            "https://mimi.example.com/#top",
            "https://mimi example.com",
            "mimi.example.com",
        ] {
            assert!(
                Provider::in_memory("example.com")
                    .unwrap()
                    .with_public_base_url(bad)
                    .is_err(),
                "{bad}"
            );
        }
        let p = Provider::in_memory("example.com")
            .unwrap()
            .with_public_base_url("https://proxy.example.com/hub")
            .unwrap();
        assert_eq!(
            p.directory()["notify"],
            "https://proxy.example.com/hub/mimi/pl/notify/{roomId}"
        );
    }

    #[test]
    fn identifier_query_is_optin_only() {
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        assert_eq!(
            p.identifier_query("alice").unwrap(),
            IdentifierQueryResult::NotFound
        );
        p.enroll("alice").unwrap();
        assert_eq!(
            p.identifier_query("alice").unwrap(),
            IdentifierQueryResult::Found
        );
        assert_eq!(
            p.identifier_query("bob").unwrap(),
            IdentifierQueryResult::NotFound
        );
    }

    #[test]
    fn key_material_serves_once_then_empty() {
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        let now = 1000;
        p.add_key_package("alice", b"kp1", now + 100).unwrap();
        assert_eq!(
            p.serve_key_material("alice", now).unwrap(),
            Some(b"kp1".to_vec())
        );
        assert_eq!(
            p.serve_key_material("alice", now).unwrap(),
            None,
            "KP is one-time (K1)"
        );
        assert_eq!(p.serve_key_material("nobody", now).unwrap(), None);
    }

    #[test]
    fn notify_is_idempotent() {
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        let source = notify_source::VerifiedNotifySource::for_tests();
        assert_eq!(
            p.submit_notify(&source, b"fanout-1", 1_000).unwrap(),
            NotifyOutcome::Process
        );
        assert_eq!(
            p.submit_notify(&source, b"fanout-1", 1_000).unwrap(),
            NotifyOutcome::DuplicateIgnored
        );
        assert_eq!(
            p.submit_notify(&source, b"fanout-2", 1_000).unwrap(),
            NotifyOutcome::Process
        );
    }

    #[test]
    fn foreign_garbage_is_gated_not_panicked() {
        let p = Provider::in_memory("havenmessenger.com").unwrap();
        assert!(p.ingest_foreign_keypackage(b"not a keypackage").is_err());
        assert!(p.ingest_foreign_welcome(b"\xff\xff\xff").is_err());
    }

    #[test]
    fn hub_fanout_partitions_local_vs_foreign_and_excludes_sender() {
        // Hub A hosts the room; members are an A-user (local), a B-user (foreign), and the sender.
        // Authority is DERIVED from each member URI - not passed in.
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/demo";
        let now = 1000;
        hub.add_participant(room, "mimi://mimi.havenmessenger.com/u/alice", now)
            .unwrap();
        hub.add_participant(room, "mimi://mimi-b.havenmessenger.com/u/bob", now)
            .unwrap();
        hub.add_participant(room, "mimi://mimi.havenmessenger.com/u/sender", now)
            .unwrap();

        let plan = hub
            .fanout_targets(room, "mimi://mimi.havenmessenger.com/u/sender")
            .unwrap();
        assert_eq!(
            plan.local,
            vec!["mimi://mimi.havenmessenger.com/u/alice"],
            "A-user is local"
        );
        assert_eq!(
            plan.foreign,
            vec![(
                "mimi-b.havenmessenger.com".to_string(),
                "mimi://mimi-b.havenmessenger.com/u/bob".to_string()
            )],
            "B-user is forwarded to its OWN provider (derived from its URI)"
        );
        assert!(
            !plan
                .local
                .contains(&"mimi://mimi.havenmessenger.com/u/sender".to_string()),
            "sender excluded"
        );
    }

    #[test]
    fn hub_fanout_is_n_way_across_multiple_foreign_providers() {
        // M3 routing decision for the N-way case: a room with members on TWO distinct foreign providers
        // plus two locals. The plan must forward to BOTH foreign providers (each to its OWN authority,
        // derived from the member URI) and enqueue both locals - sender excluded. (The forward TRANSPORT
        // is live-proven single-foreign; this proves the partition is correct for N>1 foreign targets.)
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/multi";
        let now = 1000;
        hub.add_participant(room, "mimi://mimi.havenmessenger.com/u/alice", now)
            .unwrap();
        hub.add_participant(room, "mimi://mimi.havenmessenger.com/u/carol", now)
            .unwrap();
        hub.add_participant(room, "mimi://mimi-b.havenmessenger.com/u/bob", now)
            .unwrap();
        hub.add_participant(room, "mimi://mimi-c.example.org/u/dave", now)
            .unwrap();
        hub.add_participant(room, "mimi://mimi.havenmessenger.com/u/sender", now)
            .unwrap();

        let mut plan = hub
            .fanout_targets(room, "mimi://mimi.havenmessenger.com/u/sender")
            .unwrap();
        plan.local.sort();
        plan.foreign.sort();
        assert_eq!(
            plan.local,
            vec![
                "mimi://mimi.havenmessenger.com/u/alice".to_string(),
                "mimi://mimi.havenmessenger.com/u/carol".to_string(),
            ],
            "both locals enqueued"
        );
        assert_eq!(
            plan.foreign,
            vec![
                (
                    "mimi-b.havenmessenger.com".to_string(),
                    "mimi://mimi-b.havenmessenger.com/u/bob".to_string()
                ),
                (
                    "mimi-c.example.org".to_string(),
                    "mimi://mimi-c.example.org/u/dave".to_string()
                ),
            ],
            "each foreign member forwarded to ITS OWN provider authority (N-way)"
        );
    }

    #[test]
    fn participant_remove_drops_from_fanout() {
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/x";
        hub.add_participant(room, "mimi://mimi-b.havenmessenger.com/u/bob", 1)
            .unwrap();
        assert_eq!(hub.fanout_targets(room, "").unwrap().foreign.len(), 1);
        assert!(hub
            .remove_participant(room, "mimi://mimi-b.havenmessenger.com/u/bob")
            .unwrap());
        assert!(
            hub.fanout_targets(room, "").unwrap().foreign.is_empty(),
            "removed member gets no fan-out"
        );
    }

    #[test]
    fn participant_cap_is_enforced() {
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/big";
        for i in 0..crate::store::MAX_PARTICIPANTS_PER_ROOM {
            hub.add_participant(room, &format!("mimi://mimi.havenmessenger.com/u/u{i}"), 1)
                .unwrap();
        }
        assert!(
            hub.add_participant(room, "mimi://mimi.havenmessenger.com/u/overflow", 1)
                .is_err(),
            "cap enforced"
        );
        // an EXISTING member can still refresh past the cap.
        assert!(hub
            .add_participant(room, "mimi://mimi.havenmessenger.com/u/u0", 2)
            .is_ok());
    }

    #[test]
    fn participant_list_update_batch_is_all_or_nothing_on_a_mid_sequence_cap_failure() {
        // A batch that adds TWO new participants where the room is one below capacity: the first
        // addition succeeds (brings the room to exactly the cap), the second fails (now over the
        // cap). The whole batch is one transaction, so a failure on the second addition must
        // leave the room at its PRE-batch participant count, not one-more-than-that - a partial
        // application (one added, one rejected) would mean the room's real state and the caller's
        // understanding of it have silently diverged.
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/batch-cap";
        for i in 0..crate::store::MAX_PARTICIPANTS_PER_ROOM - 1 {
            hub.add_participant(
                room,
                &format!("mimi://mimi.havenmessenger.com/u/seed{i}"),
                1,
            )
            .unwrap();
        }
        let pre_batch_count = hub.list_participants(room).unwrap().len();
        assert_eq!(
            pre_batch_count,
            (crate::store::MAX_PARTICIPANTS_PER_ROOM - 1) as usize
        );

        let update = ParticipantListUpdate {
            added_participants: vec![
                UserRolePair {
                    user_uri: "mimi://mimi.havenmessenger.com/u/batch-a".into(),
                    role_index: 1,
                },
                UserRolePair {
                    user_uri: "mimi://mimi.havenmessenger.com/u/batch-b".into(),
                    role_index: 1,
                },
            ],
            ..Default::default()
        };
        let result = hub.apply_participant_list_update(room, &update, 1);
        assert!(
            result.is_err(),
            "the batch must fail once the 2nd addition exceeds the cap"
        );

        let post_batch_count = hub.list_participants(room).unwrap().len();
        assert_eq!(
            post_batch_count, pre_batch_count,
            "a failed batch must leave the room's participant count UNCHANGED - a partial \
             application (one added, one rejected) is exactly the bug this fix closes"
        );
    }

    // ---- SECURITY regression tests ----

    #[test]
    fn authority_is_derived_from_uri_not_spoofable() {
        // The routing key for a B-user is mimi-b... derived from its URI - there is no way to make the
        // hub route a B-user's ciphertext to an attacker-chosen provider, because authority isn't an input.
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/x";
        hub.add_participant(room, "mimi://mimi-b.havenmessenger.com/u/bob", 1)
            .unwrap();
        let (_member, authority) = hub
            .list_participants(room)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(
            authority, "mimi-b.havenmessenger.com",
            "authority is the member URI host, derived"
        );
    }

    #[test]
    fn re_add_cannot_flip_authority() {
        // A member exists as a B-user; a re-add with the SAME member URI but it now parses to a different
        // host would be a different member URI entirely - so the real attack is impossible by construction.
        // Guard the store-level invariant directly: same (room, member) cannot change authority.
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/x";
        let member = "mimi://mimi-b.havenmessenger.com/u/bob";
        hub.add_participant(room, member, 1).unwrap();
        // direct store call simulating a key-flip attempt → must be rejected.
        assert!(
            hub.store
                .add_participant(room, member, "evil.example", 2)
                .is_err(),
            "re-add must not silently flip the routing authority"
        );
        assert_eq!(
            hub.list_participants(room).unwrap()[0].1,
            "mimi-b.havenmessenger.com"
        );
    }

    #[test]
    fn membership_ops_gated_on_hub_of_record() {
        // A provider may NOT mutate/serve membership for a room it does not host (no cross-room IDOR).
        let p = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let foreign_room = "mimi://mimi-b.havenmessenger.com/r/notours";
        assert!(p
            .add_participant(foreign_room, "mimi://mimi.havenmessenger.com/u/a", 1)
            .is_err());
        assert!(p.remove_participant(foreign_room, "mimi://x/u/a").is_err());
        assert!(p.fanout_targets(foreign_room, "").is_err());
        assert!(p.list_participants(foreign_room).is_err());
    }

    #[test]
    fn malformed_room_or_member_uri_rejected() {
        let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
        let room = "mimi://mimi.havenmessenger.com/r/x";
        // room must be a room URI
        assert!(hub
            .add_participant(
                "mimi://mimi.havenmessenger.com/u/notaroom",
                "mimi://mimi.havenmessenger.com/u/a",
                1
            )
            .is_err());
        // member must be a user URI, well-formed
        assert!(hub.add_participant(room, "https://evil/u/a", 1).is_err());
        assert!(hub
            .add_participant(room, "mimi://mimi.havenmessenger.com/r/room", 1)
            .is_err());
        // over-long URI rejected
        let long = format!("mimi://mimi.havenmessenger.com/u/{}", "a".repeat(600));
        assert!(hub.add_participant(room, &long, 1).is_err());
    }
}
