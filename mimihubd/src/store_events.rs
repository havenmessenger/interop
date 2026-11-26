//! The provider event stream: everything the hub holds for this provider's own users, in one sequence.
//!
//! A hub whose operator chose `events` delivery (`lane_delivery = "events"`) writes what it would otherwise queue per
//! user (Welcomes, room messages, consent changes) as rows of one table, each numbered by `seq`. The provider's own
//! server reads that sequence by pull (`events/wait`, `events/fetch`, `events/ack` on the client lane) or has it pushed
//! (`event_push.rs`); both read the same rows and move the same cursor.
//!
//! - `seq` is the previous `seq` plus one, taken in the transaction that writes the row: gap-free, monotonic per
//!   provider, never reused, across every user and room.
//! - A row leaves only when an acknowledgement covers it. Nothing expires, so no `seq` past the cursor disappears
//!   unseen; the per-user bounds refuse new items at enqueue instead, before they get a `seq`.
//! - `user` is always the user's canonical URI. MLS bytes are kept as they arrived and never read.

use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use super::{QueueRefused, SqliteStore};

pub(super) const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS events (
    seq          INTEGER PRIMARY KEY,
    kind         TEXT NOT NULL,
    user_uri     TEXT NOT NULL,
    room         TEXT,
    bytes        BLOB,
    consent_json TEXT,
    ts           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_uri, kind);
CREATE TABLE IF NOT EXISTS event_cursor (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    last_seq      INTEGER NOT NULL,
    acked_through INTEGER NOT NULL
);
INSERT OR IGNORE INTO event_cursor (id, last_seq, acked_through) VALUES (1, 0, 0);
";

/// The most Welcomes one user may have waiting in the stream, as the per-user Welcome queue allows.
pub const MAX_PENDING_WELCOMES: i64 = super::MAX_QUEUE_WELCOMES;
/// The most room messages one user may have waiting in the stream, as the per-user message queue allows.
pub const MAX_PENDING_MESSAGES: i64 = super::MAX_QUEUE_MESSAGES;
/// The most consent changes one user may have waiting in the stream.
// LIMIT-REASON: input: consent changes come from peers; a user's backlog of them is bounded like their messages
pub const MAX_PENDING_CONSENT: i64 = super::MAX_QUEUE_MESSAGES;

pub use mimihubd_api::wire::{ConsentChange, EventKind};

/// How a kind is stored.
fn kind_str(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Welcome => "welcome",
        EventKind::Message => "message",
        EventKind::Consent => "consent",
    }
}

/// A stored kind, read back.
fn kind_parse(text: &str) -> Option<EventKind> {
    match text {
        "welcome" => Some(EventKind::Welcome),
        "message" => Some(EventKind::Message),
        "consent" => Some(EventKind::Consent),
        _ => None,
    }
}

/// The most events of a kind one user may have waiting.
fn kind_cap(kind: EventKind) -> i64 {
    match kind {
        EventKind::Welcome => MAX_PENDING_WELCOMES,
        EventKind::Message => MAX_PENDING_MESSAGES,
        EventKind::Consent => MAX_PENDING_CONSENT,
    }
}

/// One event as a reader sees it.
#[derive(Clone, PartialEq, Eq)]
pub struct EventRow {
    pub seq: i64,
    pub kind: EventKind,
    pub user: String,
    pub room: Option<String>,
    pub bytes: Option<Vec<u8>>,
    pub consent: Option<ConsentChange>,
    pub received_at: i64,
}

/// The bytes are left out: they are MLS ciphertext and handshake data, and do not belong in a log.
impl std::fmt::Debug for EventRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventRow")
            .field("seq", &self.seq)
            .field("kind", &self.kind)
            .field("user", &self.user)
            .field("room", &self.room)
            .field("bytes_len", &self.bytes.as_ref().map(Vec::len))
            .field("consent", &self.consent)
            .finish()
    }
}

/// Where the stream stands: the last `seq` written, and the last one acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EventCursor {
    pub last_seq: i64,
    pub acked_through: i64,
}

/// What an acknowledgement did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventAck {
    /// The cursor is now at this `seq` (unchanged when the acknowledgement was at or below it).
    AckedThrough(i64),
    /// The acknowledgement named a `seq` past the last one written; nothing changed.
    PastEnd { last_seq: i64 },
}

impl SqliteStore {
    /// Append one event per item in `items` for `user`, in order, all or none. Refused ([`QueueRefused`]) when an item
    /// is out of bounds or the user's backlog of this kind has no room for all of them; a refused item takes no `seq`.
    pub(super) fn append_events(
        &self,
        kind: EventKind,
        user: &str,
        room: Option<&str>,
        items: &[&[u8]],
        now_unix: u64,
    ) -> anyhow::Result<()> {
        if items
            .iter()
            .any(|bytes| bytes.is_empty() || bytes.len() > super::MAX_ITEM_BYTES)
        {
            return Err(
                QueueRefused(format!("item must be 1..={} bytes", super::MAX_ITEM_BYTES)).into(),
            );
        }
        let rows: Vec<(Option<&[u8]>, Option<String>)> =
            items.iter().map(|bytes| (Some(*bytes), None)).collect();
        self.atomically(|| append_in(&self.conn, kind, user, room, &rows, now_unix))??;
        self.wake_event_readers();
        Ok(())
    }

    /// Append a consent event for `user` inside the caller's atomic group: refused, without failing the caller, when
    /// the user's consent backlog is full (the record itself is still written and readable).
    pub(super) fn append_consent_event_in(
        tx: &rusqlite::Connection,
        user: &str,
        change: &ConsentChange,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        let json = serde_json::to_string(change)?;
        match append_in(
            tx,
            EventKind::Consent,
            user,
            change.room.as_deref(),
            &[(None, Some(json))],
            now_unix,
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.downcast_ref::<QueueRefused>().is_some() => {
                eprintln!(
                    "[mimihubd] events: a consent change was not added to the stream: {error}"
                );
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// The events after `after_seq`, oldest first: at most `limit`, and no more than `max_bytes` of payload beyond the
    /// first (one event is always returned when one is waiting). The bool says whether more are waiting.
    pub fn fetch_events(
        &self,
        after_seq: i64,
        limit: usize,
        max_bytes: usize,
    ) -> anyhow::Result<(Vec<EventRow>, bool)> {
        let limit = i64::try_from(limit.max(1)).unwrap_or(i64::MAX);
        let mut statement = self.conn.prepare(
            "SELECT seq, kind, user_uri, room, bytes, consent_json, ts FROM events \
             WHERE seq > ?1 ORDER BY seq LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after_seq, limit.saturating_add(1)], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<Vec<u8>>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        let mut size = 0usize;
        let mut more = false;
        for row in rows {
            let (seq, kind, user, room, bytes, consent_json, ts) = row?;
            let len =
                bytes.as_ref().map_or(0, Vec::len) + consent_json.as_ref().map_or(0, String::len);
            if i64::try_from(out.len()).unwrap_or(i64::MAX) >= limit
                || (!out.is_empty() && size.saturating_add(len) > max_bytes)
            {
                more = true;
                break;
            }
            size = size.saturating_add(len);
            let kind = kind_parse(&kind)
                .ok_or_else(|| anyhow::anyhow!("event {seq} has an unknown kind"))?;
            let consent = consent_json
                .map(|json| serde_json::from_str::<ConsentChange>(&json))
                .transpose()?;
            out.push(EventRow {
                seq,
                kind,
                user,
                room,
                bytes,
                consent,
                received_at: ts,
            });
        }
        Ok((out, more))
    }

    /// The users with an event after `after_seq`, each once.
    pub fn users_with_events_after(&self, after_seq: i64) -> anyhow::Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare("SELECT DISTINCT user_uri FROM events WHERE seq > ?1 ORDER BY user_uri")?;
        let rows = statement.query_map(params![after_seq], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Where the stream stands.
    pub fn event_cursor(&self) -> anyhow::Result<EventCursor> {
        Ok(self.conn.query_row(
            "SELECT last_seq, acked_through FROM event_cursor WHERE id = 1",
            [],
            |r| {
                Ok(EventCursor {
                    last_seq: r.get(0)?,
                    acked_through: r.get(1)?,
                })
            },
        )?)
    }

    /// Acknowledge every event up to `up_to_seq`: they are removed and the cursor moves there. The cursor only moves
    /// forward, and never past the last `seq` written, so an acknowledgement cannot skip an event not yet written.
    pub fn ack_events(&self, up_to_seq: i64) -> anyhow::Result<EventAck> {
        let tx = self.conn.unchecked_transaction()?;
        let (last_seq, acked_through): (i64, i64) = tx.query_row(
            "SELECT last_seq, acked_through FROM event_cursor WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if up_to_seq > last_seq {
            return Ok(EventAck::PastEnd { last_seq });
        }
        if up_to_seq <= acked_through {
            return Ok(EventAck::AckedThrough(acked_through));
        }
        tx.execute("DELETE FROM events WHERE seq <= ?1", params![up_to_seq])?;
        tx.execute(
            "UPDATE event_cursor SET acked_through = ?1 WHERE id = 1",
            params![up_to_seq],
        )?;
        tx.commit()?;
        Ok(EventAck::AckedThrough(up_to_seq))
    }

    /// How many events are waiting for `user`, of every kind.
    pub fn pending_events_for(&self, user: &str) -> anyhow::Result<i64> {
        let user = mimi_core::uri::canonical(user);
        Ok(self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE user_uri = ?1",
                params![user],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }
}

/// Append `rows` (each a payload or a consent JSON) for `user` inside `tx`, numbering them from the cursor.
fn append_in(
    tx: &rusqlite::Connection,
    kind: EventKind,
    user: &str,
    room: Option<&str>,
    rows: &[(Option<&[u8]>, Option<String>)],
    now_unix: u64,
) -> anyhow::Result<()> {
    let user = mimi_core::uri::canonical(user);
    if user.is_empty() || user.len() > super::RECIPIENT_MAX_LEN {
        return Err(QueueRefused(format!(
            "recipient must be 1..={} bytes",
            super::RECIPIENT_MAX_LEN
        ))
        .into());
    }
    let room = room.map(mimi_core::uri::canonical);
    let depth: i64 = tx.query_row(
        "SELECT COUNT(*) FROM events WHERE user_uri = ?1 AND kind = ?2",
        params![user, kind_str(kind)],
        |r| r.get(0),
    )?;
    let wanted = i64::try_from(rows.len()).unwrap_or(i64::MAX);
    if depth.saturating_add(wanted) > kind_cap(kind) {
        return Err(QueueRefused(format!(
            "events full for recipient (cap {} {})",
            kind_cap(kind),
            kind_str(kind)
        ))
        .into());
    }
    let mut seq: i64 = tx.query_row("SELECT last_seq FROM event_cursor WHERE id = 1", [], |r| {
        r.get(0)
    })?;
    for (bytes, consent_json) in rows {
        seq = seq
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("event sequence exhausted"))?;
        tx.execute(
            "INSERT INTO events (seq, kind, user_uri, room, bytes, consent_json, ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                seq,
                kind_str(kind),
                user,
                room,
                bytes,
                consent_json,
                i64::try_from(now_unix).unwrap_or(i64::MAX)
            ],
        )?;
    }
    tx.execute(
        "UPDATE event_cursor SET last_seq = ?1 WHERE id = 1",
        params![seq],
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "store_events_tests.rs"]
mod tests;
