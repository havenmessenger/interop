//! The outbox: `/notify` bodies for other providers not delivered yet, one FIFO queue per (room, destination domain).
//!
//! Rows keep the order they were enqueued in, and only the head of a queue is ever attempted, so a provider receives a
//! room's fan-out in the order the hub accepted it. A row's body is fixed when it is enqueued: a retry sends the same
//! bytes, which is what the receiver's duplicate check (protocol-07 §5.5) compares. Nothing expires: a queue for a
//! provider that is down keeps its rows, in order, until they are delivered, refused for good, or the operator drops the
//! queue. The worker that delivers them is `outbox.rs`.

use rusqlite::params;

use super::SqliteStore;

pub(super) const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    room_uri        TEXT NOT NULL,
    domain          TEXT NOT NULL,
    body            BLOB NOT NULL,
    enqueued_at_ms  INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_ms INTEGER NOT NULL,
    last_outcome    TEXT
);
CREATE INDEX IF NOT EXISTS outbox_queue ON outbox (room_uri, domain, id);
";

/// The head of one queue: the only row of it that may be attempted.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboxRow {
    pub id: i64,
    pub room_uri: String,
    pub domain: String,
    pub body: Vec<u8>,
    pub attempts: u32,
    pub next_attempt_ms: u64,
}

/// The body is left out: it is MLS ciphertext and handshake data, and does not belong in a log.
impl std::fmt::Debug for OutboxRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxRow")
            .field("id", &self.id)
            .field("room_uri", &self.room_uri)
            .field("domain", &self.domain)
            .field("body_len", &self.body.len())
            .field("attempts", &self.attempts)
            .field("next_attempt_ms", &self.next_attempt_ms)
            .finish()
    }
}

/// One queue as the operator sees it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OutboxQueue {
    pub room_uri: String,
    pub domain: String,
    pub depth: u64,
    pub oldest_enqueued_at_ms: u64,
    pub head_attempts: u32,
    pub head_next_attempt_ms: u64,
    pub head_last_outcome: Option<String>,
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

impl SqliteStore {
    /// Append `body` to the queue for (`room_uri`, `domain`), due now. Returns its id.
    pub fn enqueue_fanout(
        &self,
        room_uri: &str,
        domain: &str,
        body: &[u8],
        now_ms: u64,
    ) -> anyhow::Result<i64> {
        let room_uri = mimi_core::uri::canonical(room_uri);
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.conn.execute(
            "INSERT INTO outbox (room_uri, domain, body, enqueued_at_ms, next_attempt_ms) VALUES (?1, ?2, ?3, ?4, ?4)",
            params![room_uri, domain, body, to_i64(now_ms)],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// The head of every queue whose head is due at `now_ms`, oldest first, leaving out the queues in `busy`.
    pub fn due_outbox_heads(
        &self,
        now_ms: u64,
        busy: &[(String, String)],
    ) -> anyhow::Result<Vec<OutboxRow>> {
        let mut statement = self.conn.prepare(
            "SELECT id, room_uri, domain, body, attempts, next_attempt_ms FROM outbox \
             WHERE id IN (SELECT MIN(id) FROM outbox GROUP BY room_uri, domain) AND next_attempt_ms <= ?1 \
             ORDER BY id",
        )?;
        let rows = statement
            .query_map(params![to_i64(now_ms)], |row| {
                Ok(OutboxRow {
                    id: row.get(0)?,
                    room_uri: row.get(1)?,
                    domain: row.get(2)?,
                    body: row.get(3)?,
                    attempts: u32::try_from(row.get::<_, i64>(4)?).unwrap_or(u32::MAX),
                    next_attempt_ms: to_u64(row.get(5)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter(|row| {
                !busy
                    .iter()
                    .any(|(room, domain)| *room == row.room_uri && *domain == row.domain)
            })
            .collect())
    }

    /// The earliest time any queue's head is due, if there is a row at all.
    pub fn next_outbox_due_ms(&self) -> anyhow::Result<Option<u64>> {
        let due: Option<i64> = self.conn.query_row(
            "SELECT MIN(next_attempt_ms) FROM outbox \
             WHERE id IN (SELECT MIN(id) FROM outbox GROUP BY room_uri, domain)",
            [],
            |row| row.get(0),
        )?;
        Ok(due.map(to_u64))
    }

    /// Remove row `id`: delivered, or refused for good. Removing a row that is gone is not an error.
    pub fn remove_outbox_row(&self, id: i64) -> anyhow::Result<()> {
        self.conn
            .execute("DELETE FROM outbox WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Count a failed attempt on row `id`, say what happened, and set when it is next due.
    pub fn record_outbox_attempt(
        &self,
        id: i64,
        next_attempt_ms: u64,
        outcome: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE outbox SET attempts = attempts + 1, next_attempt_ms = ?1, last_outcome = ?2 WHERE id = ?3",
            params![to_i64(next_attempt_ms), outcome, id],
        )?;
        Ok(())
    }

    /// Every queue, for the operator: its depth, its oldest row, and its head's attempts and last outcome.
    pub fn outbox_queues(&self) -> anyhow::Result<Vec<OutboxQueue>> {
        let mut statement = self.conn.prepare(
            "SELECT q.room_uri, q.domain, q.depth, q.oldest, h.attempts, h.next_attempt_ms, h.last_outcome FROM \
             (SELECT room_uri, domain, COUNT(*) AS depth, MIN(enqueued_at_ms) AS oldest, MIN(id) AS head \
              FROM outbox GROUP BY room_uri, domain) q JOIN outbox h ON h.id = q.head ORDER BY q.head",
        )?;
        let queues = statement
            .query_map([], |row| {
                Ok(OutboxQueue {
                    room_uri: row.get(0)?,
                    domain: row.get(1)?,
                    depth: to_u64(row.get(2)?),
                    oldest_enqueued_at_ms: to_u64(row.get(3)?),
                    head_attempts: u32::try_from(row.get::<_, i64>(4)?).unwrap_or(u32::MAX),
                    head_next_attempt_ms: to_u64(row.get(5)?),
                    head_last_outcome: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(queues)
    }

    /// Drop the whole queue for (`room_uri`, `domain`), on the operator's word. Returns how many rows it held.
    pub fn drop_outbox_queue(&self, room_uri: &str, domain: &str) -> anyhow::Result<usize> {
        let room_uri = mimi_core::uri::canonical(room_uri);
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        Ok(self.conn.execute(
            "DELETE FROM outbox WHERE room_uri = ?1 AND domain = ?2",
            params![room_uri, domain],
        )?)
    }
}

#[cfg(test)]
#[path = "store_outbox_tests.rs"]
mod tests;
