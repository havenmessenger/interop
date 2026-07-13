//! Durable provider state - the ONE store (SQLite). No in-memory residue: prod opens a file, tests
//! open `:memory:`, same code path. Holds the three pieces of provider state:
//!   - one-time KeyPackages per local user (K1 once-only + K2 expiry),
//!   - the `/notify` byte-exact dedup ledger (M5),
//!   - MIMI enrollment (the Standards-Testing-Page opt-in; DIV-4 + INV-MIMI-001 send-gate).
//!
//! K1 atomicity is load-bearing: a race that serves one KeyPackage twice breaks the one-time
//! guarantee. `claim_one` is therefore a SINGLE `DELETE ... RETURNING` statement (atomic in SQLite),
//! never a read-then-write.

use rusqlite::{params, Connection, OptionalExtension};

pub struct SqliteStore {
    conn: Connection,
}

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS keypackages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT NOT NULL,
    kp_bytes  BLOB NOT NULL,
    not_after INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kp_user ON keypackages(username, not_after);

CREATE TABLE IF NOT EXISTS notify_seen (
    hash    BLOB PRIMARY KEY,
    seen_at INTEGER NOT NULL DEFAULT 0
);

-- KeyPackageRef routing associations (protocol §5.2 para 16; conformance K3/K4). Keyed by the canonical
-- MLS KeyPackageRef (the same ref a Welcome's secrets[].new_member carries). K4: the TARGET provider maps
-- a served KeyPackageRef -> its local client (so an inbound Welcome can be delivered to the right user).
-- K3: the HUB maps a claimed KeyPackageRef -> the target provider (so it forwards the Welcome there).
-- `not_after` lets the sweep drop stale associations (spec: deletable after the Welcome is forwarded OR
-- not_after passes). Pure routing METADATA: a ref is a hash, not plaintext (INV-MIMI-002 holds).
CREATE TABLE IF NOT EXISTS kpref_client (
    kpref     BLOB PRIMARY KEY,
    username  TEXT NOT NULL,
    not_after INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kpref_provider (
    kpref     BLOB PRIMARY KEY,
    provider  TEXT NOT NULL,
    not_after INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS enrolled (
    username TEXT PRIMARY KEY
);

-- Cross-provider consent (protocol §5.7; conformance C1/C2/C3). A directional (requester -> target)
-- authorization the TARGET's provider holds, scoping whether the requester may reach the target. `room_key`
-- is the room URI for a room-scoped record or '' for a global one (room-specific overrides global). `state`
-- is requested|granted|revoked. Pure authz METADATA (URIs), no plaintext (INV-MIMI-002).
CREATE TABLE IF NOT EXISTS consent (
    requester TEXT NOT NULL,
    target    TEXT NOT NULL,
    room_key  TEXT NOT NULL,          -- '' = global scope
    state     TEXT NOT NULL,          -- 'requested' | 'granted' | 'revoked'
    ts        INTEGER NOT NULL,
    PRIMARY KEY (requester, target, room_key)
);
CREATE INDEX IF NOT EXISTS idx_consent_pair ON consent(requester, target);

-- Per-room policy (room-policy-04; conformance P1-P6). The RoomPolicy (roles + base policy) as a JSON
-- blob keyed by the room URI, plus each member's assigned role_index. Absent policy = default-permissive
-- (backward-compatible: rooms without a policy enforce only active-participant, as before). The hub
-- enforces ONLY canSendMessage (P5); the role assignment is the per-member role for that check.
CREATE TABLE IF NOT EXISTS room_policy (
    room_uri    TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL,
    ts          INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS member_role (
    room_uri   TEXT NOT NULL,
    member_uri TEXT NOT NULL,
    role_index INTEGER NOT NULL,
    PRIMARY KEY (room_uri, member_uri)
);

-- Store-and-forward delivery (the cross-provider relay). The provider stores OPAQUE ciphertext keyed
-- by a caller-supplied RECIPIENT string (routing METADATA only, it never decrypts; INV-MIMI-002).
CREATE TABLE IF NOT EXISTS welcomes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    bytes     BLOB NOT NULL,
    ts        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_welcome_rcpt ON welcomes(recipient, id);

CREATE TABLE IF NOT EXISTS messages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient TEXT NOT NULL,
    bytes     BLOB NOT NULL,
    ts        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_msg_rcpt ON messages(recipient, id);

-- Room participant list (the HUB's per-room membership; protocol §5.3, conformance R1-R3). The hub for a
-- room is the provider whose authority owns the room URI. `authority` is each member's provider - the
-- routing key that decides, on fan-out (M3), whether a member is LOCAL (enqueue here) or FOREIGN (forward
-- to that provider). This is metadata routing only; the provider never sees plaintext (INV-MIMI-002).
CREATE TABLE IF NOT EXISTS room_participants (
    room_uri   TEXT NOT NULL,
    member_uri TEXT NOT NULL,
    authority  TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    PRIMARY KEY (room_uri, member_uri)
);
CREATE INDEX IF NOT EXISTS idx_room ON room_participants(room_uri);

-- Abuse reports (protocol §5.9; DIV-8, the bounded v1 case: metadata-only, no attached
-- AbusiveMessage - a report carrying one requires verifying its Frank, which this reference hub
-- does not build (see DIVERGENCES.md DIV-9). reason_code is the raw AbuseType wire value (the draft
-- defines only reserved(0) - no taxonomy is registered yet). note is a UTF8 human-readable string,
-- may be empty. Pure metadata (INV-MIMI-002); this hub takes no automated action on a report.
CREATE TABLE IF NOT EXISTS abuse_reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    room_uri            TEXT NOT NULL,
    reporting_user      TEXT NOT NULL,
    alleged_abuser_uri  TEXT NOT NULL,
    reason_code         INTEGER NOT NULL,
    note                TEXT NOT NULL,
    ts                  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_abuse_room ON abuse_reports(room_uri);
";

// Store-and-forward bounds (anti-DoS; ephemeral relay state). A recipient cannot queue more than
// these, and items expire - the provider is a delivery service, not durable storage.
pub const MAX_ITEM_BYTES: usize = 64 * 1024; // per welcome/message
pub const MAX_QUEUE_WELCOMES: i64 = 32; // pending welcomes per recipient
pub const MAX_QUEUE_MESSAGES: i64 = 256; // pending messages per recipient
pub const RECIPIENT_MAX_LEN: usize = 256; // routing-key length bound
                                          // Room/participant bounds (the hub's membership state; anti-DoS, bounded like the queues).
pub const MAX_ROOMS: i64 = 1024;
pub const MAX_PARTICIPANTS_PER_ROOM: i64 = 256;
// Consent records (anti-flood; a hostile peer must not be able to grow the table without bound).
pub const MAX_CONSENT_RECORDS: i64 = 65536;
// KeyPackages (anti-flood; L1). A never-claimed backlog for one user must not grow unbounded -
// oldest are evicted past this cap on every insert.
pub const MAX_KEYPACKAGES_PER_USER: i64 = 64;
// Abuse reports (anti-flood; a hostile or malfunctioning peer must not be able to grow the table
// without bound). note<V> is bounded independently at decode time (MAX_RUN_AGGREGATE_BYTES).
pub const MAX_ABUSE_REPORTS: i64 = 65536;

impl SqliteStore {
    /// Open (or create) the store at `path`, running migrations. Use for production.
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// In-memory store (tests). Same schema + code path as `open`.
    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> anyhow::Result<Self> {
        // A busy_timeout lets concurrent writers (e.g. parallel KeyPackage claims from separate
        // connections to a file-backed db) WAIT for the write lock instead of failing SQLITE_BUSY.
        // The atomic single-statement claim (K1) is still the correctness primitive; this just makes
        // contention graceful rather than erroring.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // WAL + foreign-keys are good hygiene; the schema is idempotent (IF NOT EXISTS).
        conn.execute_batch(SCHEMA)?;
        // Migration (L1): notify_seen gained `seen_at` after its initial release, needed to sweep
        // an otherwise permanently-growing dedup ledger. `CREATE TABLE IF NOT EXISTS` above is a
        // no-op against a pre-existing DB missing the column, so add it explicitly; ignore only the
        // "already has this column" case (a DB created after this migration shipped), propagate
        // anything else.
        if let Err(e) = conn.execute(
            "ALTER TABLE notify_seen ADD COLUMN seen_at INTEGER NOT NULL DEFAULT 0",
            [],
        ) {
            if !e.to_string().contains("duplicate column name") {
                return Err(e.into());
            }
        }
        Ok(Self { conn })
    }

    // ---- KeyPackages (K1/K2) ----

    pub fn add_key_package(
        &self,
        username: &str,
        kp_bytes: &[u8],
        not_after: u64,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO keypackages (username, kp_bytes, not_after) VALUES (?1, ?2, ?3)",
            params![username, kp_bytes, not_after as i64],
        )?;
        // L1: cap the per-user backlog - a user who publishes KeyPackages that are never claimed
        // (or a hostile caller flooding one username) must not grow this table without bound. Evict
        // the oldest rows past MAX_KEYPACKAGES_PER_USER, keeping the newest (claim order is oldest-
        // first via claim_key_package's own ORDER BY id, so this doesn't starve live claims).
        self.conn.execute(
            "DELETE FROM keypackages WHERE username = ?1 AND id NOT IN (
                 SELECT id FROM keypackages WHERE username = ?1 ORDER BY id DESC LIMIT ?2
             )",
            params![username, MAX_KEYPACKAGES_PER_USER],
        )?;
        Ok(())
    }

    /// Drop KeyPackages whose `not_after` has passed without ever being claimed (K2 cleanup, L1).
    /// `claim_key_package`'s own `not_after` filter already refuses to SERVE an expired row, but
    /// never claiming it left the row in place forever; this reclaims it. Keyed on the KeyPackage's
    /// own expiry (an absolute timestamp set at publish time), not the delivery TTL.
    pub fn sweep_expired_keypackages(&self, now_unix: u64) -> anyhow::Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM keypackages WHERE not_after < ?1",
            params![now_unix as i64],
        )?;
        Ok(n)
    }

    /// Atomically claim ONE unserved, unexpired KeyPackage for `username` (K1 once-only + K2 expiry).
    /// Single DELETE..RETURNING = atomic: two concurrent callers cannot get the same row.
    pub fn claim_key_package(
        &self,
        username: &str,
        now_unix: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let row = self
            .conn
            .query_row(
                "DELETE FROM keypackages \
                 WHERE id = (SELECT id FROM keypackages \
                             WHERE username = ?1 AND not_after > ?2 \
                             ORDER BY id LIMIT 1) \
                 RETURNING kp_bytes",
                params![username, now_unix as i64],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(row)
    }

    // ---- /notify dedup (M5) ----

    /// Record a `/notify` body by its SHA-256. Returns true if it was ALREADY seen (duplicate →
    /// caller returns 201, does not re-process), false if first time. `INSERT OR IGNORE` + the
    /// rows-affected count is the atomic dedup primitive.
    pub fn notify_seen(&self, body: &[u8], now_unix: u64) -> anyhow::Result<bool> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(body);
        let digest: [u8; 32] = h.finalize().into();
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO notify_seen (hash, seen_at) VALUES (?1, ?2)",
            params![&digest[..], now_unix as i64],
        )?;
        Ok(inserted == 0) // 0 rows inserted = the hash was already present = duplicate
    }

    /// L1: drop dedup entries older than `older_than_unix` - without this the ledger grows forever
    /// (every distinct `/notify` body seen, ever). Ephemeral relay state, not durable storage, same
    /// as `sweep_expired`'s welcomes/messages.
    pub fn sweep_expired_notify_seen(&self, older_than_unix: u64) -> anyhow::Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM notify_seen WHERE seen_at < ?1",
            params![older_than_unix as i64],
        )?;
        Ok(n)
    }

    // ---- KeyPackageRef routing associations (K3/K4) ----
    // Two index tables keyed by the canonical MLS KeyPackageRef. Associate is INSERT-OR-REPLACE
    // (idempotent; refreshes not_after). Lookup returns None for an unknown ref. `forget_*` deletes a
    // consumed association (after the Welcome is forwarded). The sweep drops expired rows.

    /// K4 (target/follower side): associate a served KeyPackageRef -> the local client it belongs to.
    pub fn associate_kpref_client(
        &self,
        kpref: &[u8],
        username: &str,
        not_after: u64,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO kpref_client (kpref, username, not_after) VALUES (?1, ?2, ?3)",
            params![kpref, username, not_after as i64],
        )?;
        Ok(())
    }

    /// Resolve a KeyPackageRef to the local client it was served for (K4). None if unknown.
    pub fn client_for_kpref(&self, kpref: &[u8]) -> anyhow::Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT username FROM kpref_client WHERE kpref = ?1",
                params![kpref],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    /// K3 (hub side): associate a claimed KeyPackageRef -> the target provider that owns it.
    pub fn associate_kpref_provider(
        &self,
        kpref: &[u8],
        provider: &str,
        not_after: u64,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO kpref_provider (kpref, provider, not_after) VALUES (?1, ?2, ?3)",
            params![kpref, provider, not_after as i64],
        )?;
        Ok(())
    }

    /// Resolve a KeyPackageRef to the provider that owns it (K3). None if unknown.
    pub fn provider_for_kpref(&self, kpref: &[u8]) -> anyhow::Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT provider FROM kpref_provider WHERE kpref = ?1",
                params![kpref],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    /// Forget both associations for a consumed KeyPackageRef (after its Welcome is forwarded/delivered).
    pub fn forget_kpref(&self, kpref: &[u8]) -> anyhow::Result<()> {
        self.conn
            .execute("DELETE FROM kpref_client WHERE kpref = ?1", params![kpref])?;
        self.conn.execute(
            "DELETE FROM kpref_provider WHERE kpref = ?1",
            params![kpref],
        )?;
        Ok(())
    }

    // ---- consent (C1/C2/C3; protocol §5.7) ----
    // Directional (requester -> target) authz the target's provider holds. room_key '' = global.

    /// Set (or replace) a consent record's state. Idempotent on (requester, target, room_key). Bounded
    /// against unbounded growth from a hostile peer flooding requests.
    pub fn set_consent(
        &self,
        requester: &str,
        target: &str,
        room_key: &str,
        state: &str,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        // Only bound on a NEW (requester,target,room_key) row; updates to existing rows are free.
        let exists: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM consent WHERE requester=?1 AND target=?2 AND room_key=?3",
                params![requester, target, room_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            let n: i64 = self
                .conn
                .query_row("SELECT COUNT(*) FROM consent", [], |r| r.get(0))?;
            if n >= MAX_CONSENT_RECORDS {
                anyhow::bail!("consent table cap reached ({MAX_CONSENT_RECORDS})");
            }
        }
        self.conn.execute(
            "INSERT INTO consent (requester, target, room_key, state, ts) VALUES (?1,?2,?3,?4,?5) \
             ON CONFLICT(requester, target, room_key) DO UPDATE SET state=excluded.state, ts=excluded.ts",
            params![requester, target, room_key, state, now_unix as i64],
        )?;
        Ok(())
    }

    /// Delete a consent record (used by `cancel` of a pending request). True if a row was removed.
    pub fn delete_consent(
        &self,
        requester: &str,
        target: &str,
        room_key: &str,
    ) -> anyhow::Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM consent WHERE requester=?1 AND target=?2 AND room_key=?3",
            params![requester, target, room_key],
        )?;
        Ok(n > 0)
    }

    /// The raw consent state for an EXACT scope (requester, target, room_key). None if no record.
    pub fn consent_state(
        &self,
        requester: &str,
        target: &str,
        room_key: &str,
    ) -> anyhow::Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT state FROM consent WHERE requester=?1 AND target=?2 AND room_key=?3",
                params![requester, target, room_key],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    // ---- abuse reports (§5.9; DIV-8 bounded v1) ----

    /// Persist a metadata-only abuse report. Bounded by [`MAX_ABUSE_REPORTS`] (anti-flood) -
    /// there is no eviction policy for this table (unlike the KeyPackage/queue tables): a report is
    /// an incident record, not ephemeral relay state, so once the cap is reached new reports are
    /// refused (fail-closed) rather than silently dropping the oldest one.
    pub fn record_abuse_report(
        &self,
        room_uri: &str,
        reporting_user: &str,
        alleged_abuser_uri: &str,
        reason_code: u8,
        note: &str,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM abuse_reports", [], |r| r.get(0))?;
        if n >= MAX_ABUSE_REPORTS {
            anyhow::bail!("abuse_reports table cap reached ({MAX_ABUSE_REPORTS})");
        }
        self.conn.execute(
            "INSERT INTO abuse_reports (room_uri, reporting_user, alleged_abuser_uri, reason_code, note, ts) \
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                room_uri,
                reporting_user,
                alleged_abuser_uri,
                reason_code as i64,
                note,
                now_unix as i64
            ],
        )?;
        Ok(())
    }

    /// Count of persisted abuse reports for a room (test/inspection helper).
    pub fn abuse_report_count(&self, room_uri: &str) -> anyhow::Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM abuse_reports WHERE room_uri=?1",
            params![room_uri],
            |r| r.get(0),
        )?)
    }

    // ---- room policy + member roles (P1-P6; room-policy-04) ----

    /// Store a room's policy (JSON-encoded RoomPolicy). Idempotent on room_uri.
    pub fn set_room_policy(
        &self,
        room_uri: &str,
        policy_json: &str,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO room_policy (room_uri, policy_json, ts) VALUES (?1,?2,?3) \
             ON CONFLICT(room_uri) DO UPDATE SET policy_json=excluded.policy_json, ts=excluded.ts",
            params![room_uri, policy_json, now_unix as i64],
        )?;
        Ok(())
    }

    /// The room's policy JSON, or None (default-permissive, no policy set).
    pub fn room_policy_json(&self, room_uri: &str) -> anyhow::Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT policy_json FROM room_policy WHERE room_uri = ?1",
                params![room_uri],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    /// Assign a member's role within a room (P1: exactly one role per member, PK enforces it).
    pub fn set_member_role(
        &self,
        room_uri: &str,
        member_uri: &str,
        role_index: u32,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO member_role (room_uri, member_uri, role_index) VALUES (?1,?2,?3) \
             ON CONFLICT(room_uri, member_uri) DO UPDATE SET role_index=excluded.role_index",
            params![room_uri, member_uri, role_index as i64],
        )?;
        Ok(())
    }

    /// A member's role_index in a room, or None if unassigned.
    pub fn member_role(&self, room_uri: &str, member_uri: &str) -> anyhow::Result<Option<u32>> {
        Ok(self
            .conn
            .query_row(
                "SELECT role_index FROM member_role WHERE room_uri = ?1 AND member_uri = ?2",
                params![room_uri, member_uri],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|n| n as u32))
    }

    // ---- enrollment (the opt-in) ----

    pub fn enroll(&self, username: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO enrolled (username) VALUES (?1)",
            params![username],
        )?;
        Ok(())
    }

    pub fn is_enrolled(&self, username: &str) -> anyhow::Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM enrolled WHERE username = ?1",
                params![username],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    // ---- store-and-forward delivery (welcomes + messages) ----
    // Both store OPAQUE bytes keyed by `recipient` (routing metadata; never decrypted). Enqueue enforces
    // the per-recipient queue cap; fetch is FIFO and DELETES what it returns (deliver-once).

    fn enqueue(
        &self,
        table: &str,
        recipient: &str,
        bytes: &[u8],
        cap: i64,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        if recipient.is_empty() || recipient.len() > RECIPIENT_MAX_LEN {
            anyhow::bail!("recipient must be 1..={RECIPIENT_MAX_LEN} bytes");
        }
        if bytes.is_empty() || bytes.len() > MAX_ITEM_BYTES {
            anyhow::bail!("item must be 1..={MAX_ITEM_BYTES} bytes");
        }
        let depth: i64 = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE recipient = ?1"),
            params![recipient],
            |r| r.get(0),
        )?;
        if depth >= cap {
            anyhow::bail!("queue full for recipient (cap {cap})");
        }
        self.conn.execute(
            &format!("INSERT INTO {table} (recipient, bytes, ts) VALUES (?1, ?2, ?3)"),
            params![recipient, bytes, now_unix as i64],
        )?;
        Ok(())
    }

    /// Fetch+delete the oldest queued item for `recipient` (deliver-once, FIFO). None when empty.
    fn dequeue(&self, table: &str, recipient: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let row = self
            .conn
            .query_row(
                &format!(
                    "DELETE FROM {table} \
                     WHERE id = (SELECT id FROM {table} WHERE recipient = ?1 ORDER BY id LIMIT 1) \
                     RETURNING bytes"
                ),
                params![recipient],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(row)
    }

    pub fn enqueue_welcome(
        &self,
        recipient: &str,
        bytes: &[u8],
        now_unix: u64,
    ) -> anyhow::Result<()> {
        self.enqueue("welcomes", recipient, bytes, MAX_QUEUE_WELCOMES, now_unix)
    }
    pub fn fetch_welcome(&self, recipient: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.dequeue("welcomes", recipient)
    }
    pub fn enqueue_message(
        &self,
        recipient: &str,
        bytes: &[u8],
        now_unix: u64,
    ) -> anyhow::Result<()> {
        self.enqueue("messages", recipient, bytes, MAX_QUEUE_MESSAGES, now_unix)
    }
    pub fn fetch_message(&self, recipient: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.dequeue("messages", recipient)
    }

    // ---- room participant list (R1-R3; the hub's membership state) ----

    /// Add (or refresh) a participant in a room, recording their provider authority (the fan-out routing
    /// key). Idempotent on (room, member). Bounded: rejects new rooms past MAX_ROOMS and new members past
    /// MAX_PARTICIPANTS_PER_ROOM (existing members refresh freely).
    pub fn add_participant(
        &self,
        room_uri: &str,
        member_uri: &str,
        authority: &str,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT 1 FROM room_participants WHERE room_uri = ?1 AND member_uri = ?2",
                params![room_uri, member_uri],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            let room_known: bool = self
                .conn
                .query_row(
                    "SELECT 1 FROM room_participants WHERE room_uri = ?1 LIMIT 1",
                    params![room_uri],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !room_known {
                let rooms: i64 = self.conn.query_row(
                    "SELECT COUNT(DISTINCT room_uri) FROM room_participants",
                    [],
                    |r| r.get(0),
                )?;
                if rooms >= MAX_ROOMS {
                    anyhow::bail!("room cap reached ({MAX_ROOMS})");
                }
            }
            let members: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM room_participants WHERE room_uri = ?1",
                params![room_uri],
                |r| r.get(0),
            )?;
            if members >= MAX_PARTICIPANTS_PER_ROOM {
                anyhow::bail!("participant cap reached for room ({MAX_PARTICIPANTS_PER_ROOM})");
            }
        }
        // SECURITY: a re-add may refresh `ts` but MUST NOT silently flip `authority` (the routing key).
        // The WHERE guard makes the UPDATE a no-op if the authority differs; we then detect that and
        // reject, so a member's provider can only change via an explicit remove + fresh add.
        let changed = self.conn.execute(
            "INSERT INTO room_participants (room_uri, member_uri, authority, ts) VALUES (?1,?2,?3,?4) \
             ON CONFLICT(room_uri, member_uri) DO UPDATE SET ts=excluded.ts \
             WHERE room_participants.authority = excluded.authority",
            params![room_uri, member_uri, authority, now_unix as i64],
        )?;
        if changed == 0 && exists {
            anyhow::bail!(
                "refusing to change a participant's authority on re-add (remove + re-add to move providers)"
            );
        }
        Ok(())
    }

    /// Remove a participant (R2/R3: a removed member no longer receives fan-out). Returns true if a row
    /// was removed.
    pub fn remove_participant(&self, room_uri: &str, member_uri: &str) -> anyhow::Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM room_participants WHERE room_uri = ?1 AND member_uri = ?2",
            params![room_uri, member_uri],
        )?;
        Ok(n > 0)
    }

    /// All participants of a room as (member_uri, authority), ordered for determinism.
    pub fn list_participants(&self, room_uri: &str) -> anyhow::Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_uri, authority FROM room_participants WHERE room_uri = ?1 ORDER BY member_uri",
        )?;
        let rows = stmt
            .query_map(params![room_uri], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// TTL sweep: drop welcomes/messages older than `older_than_unix`. Returns rows removed. Called
    /// opportunistically (the queues are ephemeral delivery state, not durable storage).
    pub fn sweep_expired(&self, older_than_unix: u64) -> anyhow::Result<usize> {
        let w = self.conn.execute(
            "DELETE FROM welcomes WHERE ts < ?1",
            params![older_than_unix as i64],
        )?;
        let m = self.conn.execute(
            "DELETE FROM messages WHERE ts < ?1",
            params![older_than_unix as i64],
        )?;
        Ok(w + m)
    }

    /// Drop KeyPackageRef associations whose `not_after` has passed (K3/K4 cleanup). Returns rows
    /// removed. Keyed on the association's own expiry, NOT the delivery TTL: these track the KeyPackage
    /// lifetime, so the caller passes `now` (not `now - DELIVERY_TTL`).
    pub fn sweep_expired_kprefs(&self, now_unix: u64) -> anyhow::Result<usize> {
        let c = self.conn.execute(
            "DELETE FROM kpref_client WHERE not_after < ?1",
            params![now_unix as i64],
        )?;
        let p = self.conn.execute(
            "DELETE FROM kpref_provider WHERE not_after < ?1",
            params![now_unix as i64],
        )?;
        Ok(c + p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypackage_served_once_and_skips_expired() {
        let s = SqliteStore::in_memory().unwrap();
        let now = 1_000u64;
        s.add_key_package("alice", b"kp1", now + 100).unwrap();
        s.add_key_package("alice", b"kp2", now + 100).unwrap();
        s.add_key_package("alice", b"expired", now - 1).unwrap();

        let a = s.claim_key_package("alice", now).unwrap().unwrap();
        let b = s.claim_key_package("alice", now).unwrap().unwrap();
        assert_ne!(
            a, b,
            "two claims return two DIFFERENT KeyPackages (K1 once-only)"
        );
        assert!([b"kp1".to_vec(), b"kp2".to_vec()].contains(&a));
        assert!([b"kp1".to_vec(), b"kp2".to_vec()].contains(&b));
        // expired (K2) never served; live ones now exhausted.
        assert!(
            s.claim_key_package("alice", now).unwrap().is_none(),
            "expired KP must not be served"
        );
        assert!(s.claim_key_package("nobody", now).unwrap().is_none());
    }

    #[test]
    fn notify_dedup_byte_exact() {
        let s = SqliteStore::in_memory().unwrap();
        assert!(
            !s.notify_seen(b"body-1", 1_000).unwrap(),
            "first sight = not a duplicate"
        );
        assert!(
            s.notify_seen(b"body-1", 1_000).unwrap(),
            "exact same body = duplicate"
        );
        assert!(!s.notify_seen(b"body-2", 1_000).unwrap());
        assert!(
            !s.notify_seen(b"body-1X", 1_000).unwrap(),
            "one byte different = not a duplicate"
        );
    }

    #[test]
    fn notify_seen_sweep_drops_old_only() {
        let s = SqliteStore::in_memory().unwrap();
        s.notify_seen(b"old", 100).unwrap();
        s.notify_seen(b"new", 1_000).unwrap();
        let removed = s.sweep_expired_notify_seen(500).unwrap();
        assert_eq!(removed, 1, "only the old entry swept");
        // the surviving ("new") hash is still recognized as seen; the swept one is forgotten (would
        // be treated as first-sight again if resubmitted).
        assert!(s.notify_seen(b"new", 1_000).unwrap(), "new still deduped");
        assert!(
            !s.notify_seen(b"old", 1_000).unwrap(),
            "swept entry is forgotten, so it reads as first-sight again"
        );
    }

    #[test]
    fn keypackage_backlog_capped_per_user_evicts_oldest() {
        let s = SqliteStore::in_memory().unwrap();
        let now = 1_000u64;
        for i in 0..MAX_KEYPACKAGES_PER_USER + 5 {
            s.add_key_package("alice", format!("kp{i}").as_bytes(), now + 100)
                .unwrap();
        }
        // exactly the cap survives, and it's the NEWEST ones (oldest 5 evicted).
        let mut served = Vec::new();
        while let Some(kp) = s.claim_key_package("alice", now).unwrap() {
            served.push(kp);
        }
        assert_eq!(
            served.len(),
            MAX_KEYPACKAGES_PER_USER as usize,
            "backlog capped at MAX_KEYPACKAGES_PER_USER, not unbounded"
        );
        assert!(
            !served.contains(&b"kp0".to_vec()),
            "the oldest (first-published) entries were evicted, not the newest"
        );
    }

    #[test]
    fn enrollment_roundtrip() {
        let s = SqliteStore::in_memory().unwrap();
        assert!(!s.is_enrolled("alice").unwrap());
        s.enroll("alice").unwrap();
        assert!(s.is_enrolled("alice").unwrap());
        assert!(!s.is_enrolled("bob").unwrap());
        s.enroll("alice").unwrap(); // idempotent
        assert!(s.is_enrolled("alice").unwrap());
    }

    #[test]
    fn delivery_queue_fifo_deliver_once() {
        let s = SqliteStore::in_memory().unwrap();
        s.enqueue_message("xxx@haven", b"m1", 100).unwrap();
        s.enqueue_message("xxx@haven", b"m2", 101).unwrap();
        assert_eq!(
            s.fetch_message("xxx@haven").unwrap(),
            Some(b"m1".to_vec()),
            "FIFO"
        );
        assert_eq!(s.fetch_message("xxx@haven").unwrap(), Some(b"m2".to_vec()));
        assert_eq!(
            s.fetch_message("xxx@haven").unwrap(),
            None,
            "deliver-once: queue now empty"
        );
        assert_eq!(
            s.fetch_message("other").unwrap(),
            None,
            "isolated per recipient"
        );
    }

    #[test]
    fn welcome_queue_roundtrip() {
        let s = SqliteStore::in_memory().unwrap();
        s.enqueue_welcome("rcpt", b"welcome-bytes", 5).unwrap();
        assert_eq!(
            s.fetch_welcome("rcpt").unwrap(),
            Some(b"welcome-bytes".to_vec())
        );
        assert_eq!(s.fetch_welcome("rcpt").unwrap(), None);
    }

    #[test]
    fn enqueue_enforces_bounds() {
        let s = SqliteStore::in_memory().unwrap();
        assert!(
            s.enqueue_message("", b"x", 1).is_err(),
            "empty recipient rejected"
        );
        assert!(
            s.enqueue_message("r", b"", 1).is_err(),
            "empty item rejected"
        );
        assert!(
            s.enqueue_message("r", &vec![0u8; MAX_ITEM_BYTES + 1], 1)
                .is_err(),
            "oversize rejected"
        );
        assert!(s.enqueue_message("r", &vec![0u8; 8], 1).is_ok());
        // queue cap
        for _ in 0..MAX_QUEUE_WELCOMES {
            s.enqueue_welcome("cap", b"w", 1).unwrap();
        }
        assert!(
            s.enqueue_welcome("cap", b"w", 1).is_err(),
            "welcome queue cap enforced"
        );
    }

    #[test]
    fn sweep_drops_old_only() {
        let s = SqliteStore::in_memory().unwrap();
        s.enqueue_message("r", b"old", 100).unwrap();
        s.enqueue_message("r", b"new", 1_000).unwrap();
        let removed = s.sweep_expired(500).unwrap();
        assert_eq!(removed, 1, "only the old item swept");
        assert_eq!(
            s.fetch_message("r").unwrap(),
            Some(b"new".to_vec()),
            "new survives"
        );
    }

    #[test]
    fn sweep_expired_keypackages_drops_unclaimed_past_not_after() {
        let s = SqliteStore::in_memory().unwrap();
        let now = 1_000u64;
        s.add_key_package("alice", b"live", now + 100).unwrap();
        s.add_key_package("alice", b"stale", now - 1).unwrap();
        let removed = s.sweep_expired_keypackages(now).unwrap();
        assert_eq!(removed, 1, "only the past-expiry, never-claimed row swept");
        assert_eq!(
            s.claim_key_package("alice", now).unwrap(),
            Some(b"live".to_vec()),
            "the live one is still claimable"
        );
    }

    #[test]
    fn kpref_associations_roundtrip_consume_and_sweep() {
        let s = SqliteStore::in_memory().unwrap();
        let ref1 = b"\x01\x02\x03\x04".as_slice();
        let ref2 = b"\xaa\xbb\xcc\xdd".as_slice();
        // K4: ref -> local client; K3: ref -> provider.
        s.associate_kpref_client(ref1, "alice", 9_999).unwrap();
        s.associate_kpref_provider(ref1, "mimi-b.havenmessenger.com", 9_999)
            .unwrap();
        assert_eq!(s.client_for_kpref(ref1).unwrap(), Some("alice".into()));
        assert_eq!(
            s.provider_for_kpref(ref1).unwrap(),
            Some("mimi-b.havenmessenger.com".into())
        );
        assert_eq!(
            s.client_for_kpref(ref2).unwrap(),
            None,
            "unknown ref -> None"
        );
        assert_eq!(s.provider_for_kpref(ref2).unwrap(), None);
        // associate is idempotent / refreshes (no duplicate-key error).
        s.associate_kpref_client(ref1, "alice", 12_345).unwrap();
        assert_eq!(s.client_for_kpref(ref1).unwrap(), Some("alice".into()));
        // forget on consume drops both sides.
        s.forget_kpref(ref1).unwrap();
        assert_eq!(
            s.client_for_kpref(ref1).unwrap(),
            None,
            "consumed -> forgotten"
        );
        assert_eq!(s.provider_for_kpref(ref1).unwrap(), None);
        // sweep drops expired-only.
        s.associate_kpref_client(ref1, "old", 100).unwrap();
        s.associate_kpref_provider(ref2, "p", 1_000).unwrap();
        let removed = s.sweep_expired_kprefs(500).unwrap();
        assert_eq!(
            removed, 1,
            "only the expired (not_after<500) association swept"
        );
        assert_eq!(
            s.provider_for_kpref(ref2).unwrap(),
            Some("p".into()),
            "unexpired survives"
        );
    }

    #[test]
    fn keypackage_claim_is_atomic_under_concurrency() {
        // K1 contention proof: N threads, EACH with its own Connection to a shared file db, all racing
        // to claim from a fixed pool. The atomic DELETE..RETURNING + busy_timeout must guarantee every
        // claimed KeyPackage is served EXACTLY once - no double-serve, no loss.
        use std::collections::HashSet;
        use std::sync::Arc;
        use std::thread;

        let dir = std::env::temp_dir().join(format!("mimi_claim_race_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("race.db");
        let p = Arc::new(path.to_str().unwrap().to_string());

        // Must stay <= MAX_KEYPACKAGES_PER_USER (L1's per-user backlog cap) or the cap's own oldest-
        // eviction would race this test's own inserts and make "every one served exactly once" false
        // for reasons unrelated to what this test is actually proving (K1 claim atomicity).
        const POOL: usize = 60;
        {
            let s = SqliteStore::open(&p).unwrap();
            for i in 0..POOL {
                s.add_key_package("alice", format!("kp-{i:04}").as_bytes(), 9_999_999_999)
                    .unwrap();
            }
        }

        const THREADS: usize = 8;
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let p = Arc::clone(&p);
                thread::spawn(move || {
                    let s = SqliteStore::open(&p).unwrap();
                    let mut got = Vec::new();
                    // each thread claims until the pool is drained
                    while let Some(kp) = s.claim_key_package("alice", 1000).unwrap() {
                        got.push(kp);
                    }
                    got
                })
            })
            .collect();

        let mut all = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }
        let unique: HashSet<_> = all.iter().cloned().collect();
        assert_eq!(
            all.len(),
            POOL,
            "every KeyPackage served exactly once (no loss)"
        );
        assert_eq!(
            unique.len(),
            POOL,
            "no KeyPackage served twice across racing claimers (K1)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn consent_set_lookup_override_and_delete() {
        let s = SqliteStore::in_memory().unwrap();
        let req = "mimi://b/u/bob";
        let tgt = "mimi://a/u/alice";
        // global grant
        s.set_consent(req, tgt, "", "granted", 1).unwrap();
        assert_eq!(
            s.consent_state(req, tgt, "").unwrap(),
            Some("granted".into())
        );
        // room-specific revoke (override)
        s.set_consent(req, tgt, "mimi://a/r/x", "revoked", 2)
            .unwrap();
        assert_eq!(
            s.consent_state(req, tgt, "mimi://a/r/x").unwrap(),
            Some("revoked".into())
        );
        assert_eq!(
            s.consent_state(req, tgt, "").unwrap(),
            Some("granted".into()),
            "global untouched"
        );
        // unknown scope -> None
        assert_eq!(s.consent_state(req, tgt, "mimi://a/r/other").unwrap(), None);
        // update in place (idempotent key)
        s.set_consent(req, tgt, "", "revoked", 3).unwrap();
        assert_eq!(
            s.consent_state(req, tgt, "").unwrap(),
            Some("revoked".into())
        );
        // delete (cancel)
        assert!(s.delete_consent(req, tgt, "mimi://a/r/x").unwrap());
        assert_eq!(s.consent_state(req, tgt, "mimi://a/r/x").unwrap(), None);
        assert!(!s.delete_consent(req, tgt, "nope").unwrap());
    }

    #[test]
    fn persists_to_file() {
        let dir = std::env::temp_dir().join(format!("mimi_store_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.db");
        let p = path.to_str().unwrap();
        {
            let s = SqliteStore::open(p).unwrap();
            s.enroll("alice").unwrap();
            s.add_key_package("alice", b"kp1", 9_999_999_999).unwrap();
        }
        {
            let s = SqliteStore::open(p).unwrap(); // reopen, durability check
            assert!(
                s.is_enrolled("alice").unwrap(),
                "enrollment must survive reopen"
            );
            assert_eq!(
                s.claim_key_package("alice", 1000).unwrap(),
                Some(b"kp1".to_vec())
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
