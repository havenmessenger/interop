//! What this provider keeps about rooms hosted on other hubs that its users are members of: who is a member (from the
//! Welcomes that made them one), and which FanoutMessages it already delivered, without their timestamp, so a message
//! the hub sends again in another body is delivered once.

use rusqlite::params;

use super::SqliteStore;

pub(super) const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS followed_member (
    room_uri   TEXT NOT NULL,
    member_uri TEXT NOT NULL,
    since      INTEGER NOT NULL,
    PRIMARY KEY (room_uri, member_uri)
);
CREATE TABLE IF NOT EXISTS followed_seen (
    room_uri TEXT NOT NULL,
    digest   BLOB NOT NULL,
    seen_at  INTEGER NOT NULL,
    PRIMARY KEY (room_uri, digest)
);
";

impl SqliteStore {
    /// `member_uri` is a member of the room `room_uri`, hosted elsewhere, from `now_unix`.
    pub fn add_followed_member(
        &self,
        room_uri: &str,
        member_uri: &str,
        now_unix: u64,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO followed_member (room_uri, member_uri, since) VALUES (?1, ?2, ?3)",
            params![
                mimi_core::uri::canonical(room_uri),
                mimi_core::uri::canonical(member_uri),
                i64::try_from(now_unix).unwrap_or(i64::MAX)
            ],
        )?;
        Ok(())
    }

    /// This provider's members of the room `room_uri`, hosted elsewhere, in the order they joined.
    pub fn followed_members(&self, room_uri: &str) -> anyhow::Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            "SELECT member_uri FROM followed_member WHERE room_uri = ?1 ORDER BY since, rowid",
        )?;
        let members = statement
            .query_map(params![mimi_core::uri::canonical(room_uri)], |row| {
                row.get(0)
            })?
            .collect::<Result<Vec<String>, _>>()?;
        Ok(members)
    }

    /// Record `digest` as delivered for `room_uri`. `true` the first time, `false` when it already was.
    pub fn first_followed_delivery(
        &self,
        room_uri: &str,
        digest: &[u8],
        now_unix: u64,
    ) -> anyhow::Result<bool> {
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO followed_seen (room_uri, digest, seen_at) VALUES (?1, ?2, ?3)",
            params![
                mimi_core::uri::canonical(room_uri),
                digest,
                i64::try_from(now_unix).unwrap_or(i64::MAX)
            ],
        )?;
        Ok(inserted == 1)
    }

    /// Forget delivered digests older than `cutoff_unix`.
    pub fn sweep_followed_seen(&self, cutoff_unix: u64) -> anyhow::Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM followed_seen WHERE seen_at < ?1",
            params![i64::try_from(cutoff_unix).unwrap_or(i64::MAX)],
        )?)
    }
}
