//! Enrolling a handle for `identifierQuery`, from the hub's own host.
//!
//! `identifierQuery` answers only for handles that opted in (DIVERGENCES.md, DIV-4), and no route enrolls one: a peer
//! must not be able to make a user discoverable. Enrollment is an operator's act, `mimi-hubd enroll <handle>`, which
//! writes the handle into the hub's store. A running hub reads the store at each query, so it answers for the handle
//! from its next request on.

use std::path::Path;

use crate::store::SqliteStore;

/// Enroll `handle` in the hub's store at `db_path`. Enrolling a handle that is already there changes nothing.
///
/// Refused when `handle` is empty, and when no database file is at `db_path`: opening the store creates one, and a
/// path that is not the hub's would get a new, empty database with the handle in it while the hub's own store stayed
/// as it was.
pub fn enroll_handle(db_path: &str, handle: &str) -> anyhow::Result<()> {
    if handle.is_empty() {
        anyhow::bail!("the handle to enroll is empty");
    }
    if !Path::new(db_path).is_file() {
        anyhow::bail!(
            "no hub database at {db_path}: give the hub's own settings (--config, or MIMI_DB_PATH); nothing was written"
        );
    }
    SqliteStore::open(db_path)?.enroll(handle)
}

#[cfg(test)]
#[path = "enroll_tests.rs"]
mod tests;
