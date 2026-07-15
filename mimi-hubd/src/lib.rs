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

pub mod http;
pub mod store;
pub mod tls;

use mimi_core::commit_wire::decode_single_custom_proposal_commit;
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
use mimi_core::room_policy::{RoomPolicy, MIMI_ROOM_POLICY_PROPOSAL_TYPE};
use mimi_core::uri::{MimiKind, MimiUri};

/// Upper bound on a member/room URI we will store (anti-DoS on the routing key; a real mimi:// URI is
/// far shorter). Parsed URIs longer than this are rejected before any work.
const MAX_URI_LEN: usize = 512;

use crate::store::SqliteStore;

/// Published KeyPackages live this long before K2 expiry prunes them from claims.
const KEYPACKAGE_TTL_SECS: u64 = 30 * 24 * 3600; // 30 days
/// Queued welcomes/messages older than this are swept (ephemeral delivery state, not storage).
const DELIVERY_TTL_SECS: u64 = 24 * 3600; // 24 hours

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
    store: SqliteStore,
}

impl Provider {
    /// Open a provider backed by a SQLite file (production).
    pub fn open(domain: impl Into<String>, db_path: &str) -> anyhow::Result<Self> {
        Ok(Self {
            domain: domain.into(),
            store: SqliteStore::open(db_path)?,
        })
    }

    /// Open a provider backed by an in-memory SQLite db (tests).
    pub fn in_memory(domain: impl Into<String>) -> anyhow::Result<Self> {
        Ok(Self {
            domain: domain.into(),
            store: SqliteStore::in_memory()?,
        })
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
    /// protocol-06 §5.1's own example is a FLAT object: top-level keys are the ten endpoint names,
    /// values are absolute HTTPS URLs (e.g. `"keyMaterial": "https://mimi.example.com/v1/keyMaterial/
    /// {targetUser}"`). This document publishes those flat, draft-shaped keys for the eight
    /// endpoints this hub actually wire-routes (`keyMaterial`/`submitMessage`/`notify`/
    /// `identifierQuery`/`requestConsent`/`updateConsent`/`reportAbuse`/`update`) - the other two
    /// draft keys (`groupInfo`/`proxyDownload`) are omitted since nothing here serves them, per the
    /// same "advertise only what's served" discipline as `unsupported` below. `endpoints` (relative paths,
    /// JSON compat lane) and `wireEndpoints` (relative paths, mirrors the flat keys) are additive
    /// non-standard keys kept for existing consumers - a strict §5.1 client ignores unknown keys.
    pub fn directory(&self) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "provider": self.domain,
            "mls_ciphersuites": [HAVEN_MLS_CIPHERSUITE_U16],   // 0x0001 only
            "protocol_drafts": { "protocol": "06", "content": "09", "room-policy": "04" },
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
                "submitMessage": "/mimi/pl/submitMessage/{recipient}",
                "notify": "/mimi/pl/notify",
                "identifierQuery": "/mimi/pl/identifierQuery",
                "requestConsent": "/mimi/pl/requestConsent/{targetDomain}",
                "updateConsent": "/mimi/pl/updateConsent/{requesterDomain}",
                "reportAbuse": "/mimi/pl/reportAbuse/{roomId}",
                "update": "/mimi/pl/update/{roomId}"
            },
            "unsupported": {
                "groupInfo_external_commit_join": "DIV-1: add-driven join only (ETK security)",
                "assets_ohttp": "DIV-3: v1 is messaging-only",
                "non_0x0001_ciphersuites": "DIV-2: rejected at ingest",
                "update_wire_endpoint_mixed_commits": "DIV-10: a Commit combining a custom proposal with a standard MLS proposal (Add, Remove, ...) in the same proposal list is refused - only a Commit whose list holds exactly one custom proposal is applied",
                "reportAbuse_with_abusive_messages": "DIV-9: a report attaching an AbusiveMessage is refused (its Frank cannot yet be verified) - metadata-only reports are accepted"
            }
        });
        let domain = &self.domain;
        for (key, path) in [
            ("keyMaterial", "/mimi/pl/keyMaterial/{targetUser}"),
            ("submitMessage", "/mimi/pl/submitMessage/{recipient}"),
            ("notify", "/mimi/pl/notify"),
            ("identifierQuery", "/mimi/pl/identifierQuery"),
            ("requestConsent", "/mimi/pl/requestConsent/{targetDomain}"),
            ("updateConsent", "/mimi/pl/updateConsent/{requesterDomain}"),
            ("reportAbuse", "/mimi/pl/reportAbuse/{roomId}"),
            ("update", "/mimi/pl/update/{roomId}"),
        ] {
            doc[key] = serde_json::Value::String(format!("https://{domain}{path}"));
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

    pub fn submit_notify(&self, body: &[u8], now_unix: u64) -> anyhow::Result<NotifyOutcome> {
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
    // caller (http) always returns 201 regardless of whether the user/requester exists: no oracle.
    // room_key '' = global scope; a room-specific record overrides global.

    fn room_key(room_uri: &Option<String>) -> &str {
        room_uri.as_deref().unwrap_or("")
    }

    /// C1: accept + process a `requestConsent` from another provider. Records a pending request UNLESS a
    /// terminal decision (grant/revoke) already exists for the scope (a request must not clobber a
    /// decision). Validates well-formedness first (fail-closed).
    pub fn process_request_consent(
        &self,
        entry: &ConsentEntry,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        validate_consent_entry(entry)?;
        if entry.operation != ConsentOperation::Request {
            anyhow::bail!("process_request_consent expects operation=request");
        }
        let rk = Self::room_key(&entry.room_uri);
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
        Ok(())
    }

    /// C2: accept + process an `updateConsent` (grant / revoke / cancel). `grant`→granted, `revoke`→
    /// revoked (valid PREEMPTIVELY, no prior request needed), `cancel`→delete a pending request. Any
    /// grant-carried client_key_packages are suite-gated (INV-MLS-002) before they could be stored/used.
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
            ConsentOperation::Cancel => {
                self.store
                    .delete_consent(&entry.requester_uri, &entry.target_uri, rk)?;
            }
            ConsentOperation::Request => {
                anyhow::bail!("requestConsent must use process_request_consent, not updateConsent");
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

    // ---- DIV-10: applying a mimiParticipantList/mimiRoomPolicy custom proposal from a real Commit ----

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
    ) -> anyhow::Result<()> {
        let decoded = decode_single_custom_proposal_commit(commit_bytes)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        match decoded.proposal_type {
            MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE => {
                let update = decode_participant_list_update(&decoded.payload)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                self.apply_participant_list_update(room_uri, &update, now_unix)
            }
            MIMI_ROOM_POLICY_PROPOSAL_TYPE => {
                let policy: RoomPolicy = serde_json::from_slice(&decoded.payload)
                    .map_err(|e| anyhow::anyhow!("malformed RoomPolicy payload: {e}"))?;
                self.set_room_policy(room_uri, &policy, now_unix)
            }
            other => anyhow::bail!("unrecognized custom proposal_type {other:#06x}"),
        }
    }

    /// Enact a `ParticipantListUpdate` against this room's `room_participants`/`member_role`
    /// tables. Indices in `update` resolve against [`Self::list_participants`]'s own ordering
    /// (alphabetical by URI) - the same canonical order this hub uses everywhere else it needs a
    /// stable participant ordering. A peer whose index computation used a different ordering
    /// convention will not apply correctly; this reference hub does not attempt to reconcile that
    /// (see DIVERGENCES.md).
    fn apply_participant_list_update(
        &self,
        room_uri: &str,
        update: &ParticipantListUpdate,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        self.assert_hub_of_record(room_uri)?;
        let rows = self.store.list_participants(room_uri)?;
        // apply_update needs only a length + index-bounds check here (this method resolves the
        // actual mutations from `update` directly against `rows`, not against apply_update's own
        // returned list) - reusing it keeps the bounds-checking logic in one place rather than
        // duplicating `validate_participant_list_update` plus a manual length check.
        let current = ParticipantListData {
            participants: rows
                .iter()
                .map(|(uri, _authority)| UserRolePair {
                    user_uri: uri.clone(),
                    role_index: 0, // placeholder: only positions are read below, never this value
                })
                .collect(),
        };
        apply_update(&current, update).map_err(|e| anyhow::anyhow!("{e}"))?;

        for c in &update.changed_role_participants {
            let uri = &current.participants[c.user_index as usize].user_uri;
            self.set_member_role(room_uri, uri, c.role_index)?;
        }
        for &idx in &update.removed_indices {
            let uri = &current.participants[idx as usize].user_uri;
            self.remove_participant(room_uri, uri)?;
        }
        for a in &update.added_participants {
            self.add_participant(room_uri, &a.user_uri, now_unix)?;
            self.set_member_role(room_uri, &a.user_uri, a.role_index)?;
        }
        Ok(())
    }
}

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
        p.process_request_consent(&consent_entry(ConsentOperation::Request, None), 1)
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
            .process_request_consent(&consent_entry(ConsentOperation::Grant, None), 1)
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
        assert_eq!(wire["submitMessage"], "/mimi/pl/submitMessage/{recipient}");
        assert_eq!(wire["keyMaterial"], "/mimi/pl/keyMaterial/{targetUser}");
        assert_eq!(wire["notify"], "/mimi/pl/notify");
        assert_eq!(wire["identifierQuery"], "/mimi/pl/identifierQuery");
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
    fn directory_advertises_flat_draft_shaped_keys_for_wire_routed_endpoints() {
        // protocol-06 §5.1's own example directory is a FLAT object - top-level keys are the
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
            "https://havenmessenger.com/mimi/pl/submitMessage/{recipient}"
        );
        assert_eq!(dir["notify"], "https://havenmessenger.com/mimi/pl/notify");
        assert_eq!(
            dir["identifierQuery"],
            "https://havenmessenger.com/mimi/pl/identifierQuery"
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
        assert_eq!(
            p.submit_notify(b"fanout-1", 1_000).unwrap(),
            NotifyOutcome::Process
        );
        assert_eq!(
            p.submit_notify(b"fanout-1", 1_000).unwrap(),
            NotifyOutcome::DuplicateIgnored
        );
        assert_eq!(
            p.submit_notify(b"fanout-2", 1_000).unwrap(),
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
