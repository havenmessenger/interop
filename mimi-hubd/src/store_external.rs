//! What the hub keeps for external joins to a room it hosts: the room's `mls_operational_policy` component as last set,
//! and the last Full GroupInfo a Commit's bundle carried, with the epoch it is for.

use rusqlite::{params, OptionalExtension};

use super::SqliteStore;

pub(super) const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS room_operational_policy (
    room_uri TEXT PRIMARY KEY,
    data     BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS room_group_info (
    room_uri   TEXT PRIMARY KEY,
    epoch      INTEGER NOT NULL,
    group_info BLOB NOT NULL
);
";

impl SqliteStore {
    /// Keep `data` (an `OperationalParameters`, already checked) as the room's operational policy.
    pub fn set_operational_policy(&self, room_uri: &str, data: &[u8]) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO room_operational_policy (room_uri, data) VALUES (?1, ?2) \
             ON CONFLICT(room_uri) DO UPDATE SET data = excluded.data",
            params![mimi_core::uri::canonical(room_uri), data],
        )?;
        Ok(())
    }

    /// Forget the room's operational policy.
    pub fn clear_operational_policy(&self, room_uri: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM room_operational_policy WHERE room_uri = ?1",
            params![mimi_core::uri::canonical(room_uri)],
        )?;
        Ok(())
    }

    /// The room's operational policy as kept, if it has one.
    pub fn operational_policy(&self, room_uri: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT data FROM room_operational_policy WHERE room_uri = ?1",
                params![mimi_core::uri::canonical(room_uri)],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Keep `group_info` (a bare GroupInfo) for the room at `epoch`, or, with `None`, keep none.
    pub fn keep_group_info(
        &self,
        room_uri: &str,
        epoch: u64,
        group_info: Option<&[u8]>,
    ) -> anyhow::Result<()> {
        let room_uri = mimi_core::uri::canonical(room_uri);
        match group_info {
            Some(group_info) => self.conn.execute(
                "INSERT INTO room_group_info (room_uri, epoch, group_info) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(room_uri) DO UPDATE SET epoch = excluded.epoch, group_info = excluded.group_info",
                params![room_uri, i64::try_from(epoch).unwrap_or(i64::MAX), group_info],
            )?,
            None => self.conn.execute(
                "DELETE FROM room_group_info WHERE room_uri = ?1",
                params![room_uri],
            )?,
        };
        Ok(())
    }

    /// The room's kept GroupInfo and its epoch.
    pub fn kept_group_info(&self, room_uri: &str) -> anyhow::Result<Option<(u64, Vec<u8>)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT epoch, group_info FROM room_group_info WHERE room_uri = ?1",
                params![mimi_core::uri::canonical(room_uri)],
                |row| {
                    Ok((
                        u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                        row.get(1)?,
                    ))
                },
            )
            .optional()?)
    }

    /// The proposals held for the room at `epoch`, in the order they were held, each with the second it was held at.
    pub fn held_proposals_timed(
        &self,
        room_uri: &str,
        epoch: u64,
        now_unix: u64,
    ) -> anyhow::Result<Vec<(Vec<u8>, u64)>> {
        let mut statement = self.conn.prepare(
            "SELECT message, ts FROM pending_proposals \
             WHERE room_uri = ?1 AND epoch = ?2 AND ts >= ?3 ORDER BY ts, rowid",
        )?;
        let rows = statement
            .query_map(
                params![
                    mimi_core::uri::canonical(room_uri),
                    i64::try_from(epoch).unwrap_or(i64::MAX),
                    super::expired_before(now_unix)
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}
