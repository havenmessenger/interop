//! The one-time pass rewrites stored URIs to their canonical form once, leaves a row whose canonical form is already
//! stored, and is not run again.

use rusqlite::Connection;

use super::*;
use crate::store::SqliteStore;

/// A store written before keys were canonical: rows inserted directly, as an older hub would have stored them.
fn older_store(path: &std::path::Path) {
    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();
    drop(store);
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 0;
         INSERT INTO consent (requester, target, room_key, state, ts)
             VALUES ('MIMI://B.Example/u/%61lice', 'mimi://a.example/u/erin', '', 'granted', 1);
         INSERT INTO room_participants (room_uri, member_uri, authority, ts, seq)
             VALUES ('mimi://A.example/r/table', 'mimi://b.example/u/alice', 'b.example', 1, 1);
         INSERT INTO keypackages (username, kp_bytes, not_after) VALUES ('erin', x'00', 99);
         INSERT INTO consent (requester, target, room_key, state, ts)
             VALUES ('mimi://c.example/u/bob', 'mimi://a.example/u/erin', '', 'granted', 1);
         INSERT INTO consent (requester, target, room_key, state, ts)
             VALUES ('MIMI://C.example/u/bob', 'mimi://a.example/u/erin', '', 'revoked', 2);",
    )
    .unwrap();
}

#[test]
fn stored_uris_are_rewritten_once_and_a_clash_is_left_and_named() {
    let dir = std::env::temp_dir().join(format!("mimi-canon-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    let _ = std::fs::remove_file(&path);
    older_store(&path);

    let conn = Connection::open(&path).unwrap();
    let report = canonicalize_stored_uris(&conn).unwrap();
    // alice's consent requester and the room's URI were rewritten; bob's second spelling clashes with the first.
    assert_eq!(report.rewritten, 2, "{report:?}");
    assert_eq!(report.left.len(), 1, "{report:?}");
    let requesters: Vec<String> = conn
        .prepare("SELECT requester FROM consent ORDER BY rowid")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        requesters,
        [
            "mimi://b.example/u/alice",
            "mimi://c.example/u/bob",
            "MIMI://C.example/u/bob"
        ]
    );
    let room: String = conn
        .query_row("SELECT room_uri FROM room_participants", [], |r| r.get(0))
        .unwrap();
    assert_eq!(room, "mimi://a.example/r/table");

    // The version is recorded, so a second open changes nothing.
    assert_eq!(
        canonicalize_stored_uris(&conn).unwrap(),
        CanonicalReport::default()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_lookup_in_another_spelling_finds_the_canonical_row() {
    let store = SqliteStore::in_memory().unwrap();
    store
        .set_consent(
            "mimi://b.example/u/alice",
            "mimi://a.example/u/erin",
            "",
            "granted",
            1,
        )
        .unwrap();
    assert_eq!(
        store
            .consent_state("MIMI://B.Example/u/%61lice", "mimi://A.example/u/erin", "")
            .unwrap()
            .as_deref(),
        Some("granted")
    );
}

#[test]
fn a_store_at_version_1_has_its_iri_paths_mapped_to_uris_once() {
    let dir = std::env::temp_dir().join(format!("mimi-canon-v1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    let _ = std::fs::remove_file(&path);
    drop(SqliteStore::open(path.to_str().unwrap()).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "PRAGMA user_version = 1;
         INSERT INTO consent (requester, target, room_key, state, ts)
             VALUES ('mimi://b.example/u/zoë', 'mimi://a.example/u/erin', '', 'granted', 1);",
    )
    .unwrap();
    let report = canonicalize_stored_uris(&conn).unwrap();
    assert_eq!(report.rewritten, 1, "{report:?}");
    let requester: String = conn
        .query_row("SELECT requester FROM consent", [], |r| r.get(0))
        .unwrap();
    assert_eq!(requester, "mimi://b.example/u/zo%C3%AB");
    let again = canonicalize_stored_uris(&conn).unwrap();
    assert_eq!(again.rewritten, 0, "{again:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
