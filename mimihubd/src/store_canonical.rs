//! A one-time pass that rewrites every stored `mimi://` URI to its canonical form (`mimi_core::uri::canonical`), so
//! rows written before the store canonicalized its keys are found by the same keys as rows written after.

use rusqlite::{params, Connection};

/// Every column that holds a user or room URI (or a bare user name, which `canonical` leaves as it is).
const URI_COLUMNS: &[(&str, &str)] = &[
    ("keypackages", "username"),
    ("kpref_client", "username"),
    ("consent", "requester"),
    ("consent", "target"),
    ("consent", "room_key"),
    ("enrolled", "username"),
    ("room_policy", "room_uri"),
    ("member_role", "room_uri"),
    ("member_role", "member_uri"),
    ("welcomes", "recipient"),
    ("messages", "recipient"),
    ("room_participants", "room_uri"),
    ("room_participants", "member_uri"),
    ("abuse_reports", "room_uri"),
    ("abuse_reports", "reporting_user"),
    ("abuse_reports", "alleged_abuser_uri"),
    ("pending_proposals", "room_uri"),
    ("room_epoch", "room_uri"),
];

/// The store's version after this pass; a store at it or later is not rewritten again. Version 2 is the canonical form
/// that also maps a path written as an IRI to its URI, so a store written at version 1 is rewritten once more.
pub const CANONICAL_URIS_VERSION: i64 = 2;

/// What the pass did: rows rewritten, and rows left as they were because their canonical form was already stored
/// under a key the table holds once (they are named so an operator can look; nothing is merged or dropped).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CanonicalReport {
    pub rewritten: usize,
    pub left: Vec<String>,
}

/// Rewrite every URI column once, in one transaction, and record the version.
pub fn canonicalize_stored_uris(conn: &Connection) -> anyhow::Result<CanonicalReport> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let mut report = CanonicalReport::default();
    if version >= CANONICAL_URIS_VERSION {
        return Ok(report);
    }
    let tx = conn.unchecked_transaction()?;
    for (table, column) in URI_COLUMNS {
        let rows: Vec<(i64, String)> = {
            let mut stmt = tx.prepare(&format!("SELECT rowid, {column} FROM {table}"))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            rows
        };
        for (rowid, value) in rows {
            let canonical = mimi_core::uri::canonical(&value);
            if canonical == value {
                continue;
            }
            let changed = tx.execute(
                &format!("UPDATE OR IGNORE {table} SET {column} = ?1 WHERE rowid = ?2"),
                params![canonical, rowid],
            )?;
            if changed == 1 {
                report.rewritten += 1;
            } else {
                report.left.push(format!("{table}.{column} rowid {rowid}"));
            }
        }
    }
    tx.execute_batch(&format!("PRAGMA user_version = {CANONICAL_URIS_VERSION}"))?;
    tx.commit()?;
    Ok(report)
}

#[cfg(test)]
#[path = "store_canonical_tests.rs"]
mod tests;
