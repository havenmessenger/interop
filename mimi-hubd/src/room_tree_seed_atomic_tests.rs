//! A room's seed is stored all or nothing: a store failure at its last write leaves every table as it was, so the hub
//! never tracks a room whose policy, list or metadata did not make it.

use std::collections::BTreeMap;

use super::seed_metadata_tests::{metadata_naming, seed_into, ROOM};
use crate::Provider;

/// Every table's row count: the whole store, not a list of the tables a seed is expected to touch.
fn counts(db: &rusqlite::Connection) -> BTreeMap<String, i64> {
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let count = db
                .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
                    row.get(0)
                })
                .unwrap();
            (table, count)
        })
        .collect()
}

/// The seed fails at its last write (the room metadata, refused by a trigger) and leaves nothing: the room is not
/// tracked and no table gained a row. With the trigger gone the same seed is taken, so the failure was the trigger.
/// Revert check: run the seed's writes outside one group, and the group and tracking record stay behind.
#[test]
fn a_seed_that_fails_at_its_last_write_leaves_nothing() {
    let dir = std::env::temp_dir().join(format!("mimi-hubd-seed-atomic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.sqlite");
    let _ = std::fs::remove_file(&path);
    let p = Provider::open("hub.example", path.to_str().unwrap()).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER refuse_metadata BEFORE INSERT ON room_metadata
         BEGIN SELECT RAISE(ABORT, 'the disk is full'); END;",
    )
    .unwrap();
    let before = counts(&db);

    assert!(
        !seed_into(&p, Some(metadata_naming(ROOM))),
        "PLANT-SEED-ATOMIC: a seed that failed at its last write left the room tracked"
    );
    assert_eq!(
        counts(&db),
        before,
        "PLANT-SEED-ATOMIC: a seed that failed at its last write left rows behind"
    );
    assert!(p.room_metadata(ROOM).unwrap().is_none());

    db.execute_batch("DROP TRIGGER refuse_metadata;").unwrap();
    assert!(
        seed_into(&p, Some(metadata_naming(ROOM))),
        "the same seed is taken once the store takes the write"
    );
    assert_ne!(counts(&db), before);
    drop(p);
    let _ = std::fs::remove_dir_all(&dir);
}
