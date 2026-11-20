//! [`SqliteStore::atomically`]: what a group keeps, what it rolls back, nested groups, and a panic inside one.

use std::panic::{catch_unwind, AssertUnwindSafe};

use super::SqliteStore;

fn store() -> SqliteStore {
    let store = SqliteStore::in_memory().unwrap();
    store
        .conn
        .execute_batch("CREATE TABLE marks (name TEXT NOT NULL);")
        .unwrap();
    store
}

fn mark(store: &SqliteStore, name: &str) -> rusqlite::Result<usize> {
    store
        .conn
        .execute("INSERT INTO marks (name) VALUES (?1)", [name])
}

fn marks(store: &SqliteStore) -> Vec<String> {
    let mut stmt = store
        .conn
        .prepare("SELECT name FROM marks ORDER BY rowid")
        .unwrap();
    stmt.query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn a_group_that_succeeds_is_kept_and_one_that_fails_leaves_nothing() {
    let s = store();
    let kept = s.atomically(|| -> rusqlite::Result<()> {
        mark(&s, "a")?;
        mark(&s, "b")?;
        Ok(())
    });
    assert!(matches!(kept, Ok(Ok(()))));
    let failed = s.atomically(|| -> Result<(), &'static str> {
        mark(&s, "c").unwrap();
        Err("the second write failed")
    });
    assert!(matches!(failed, Ok(Err("the second write failed"))));
    assert_eq!(
        marks(&s),
        ["a", "b"],
        "PLANT-ATOMIC-ROLLBACK: a failed group kept its writes"
    );
    assert!(s.conn.is_autocommit(), "no transaction is left open");
}

#[test]
fn a_nested_group_that_fails_rolls_back_only_itself() {
    let s = store();
    let outer = s.atomically(|| -> rusqlite::Result<()> {
        mark(&s, "outer")?;
        let inner = s.atomically(|| -> Result<(), &'static str> {
            mark(&s, "inner").unwrap();
            Err("no")
        });
        assert!(matches!(inner, Ok(Err("no"))));
        assert!(!s.conn.is_autocommit(), "the outer group is still open");
        mark(&s, "after")?;
        Ok(())
    });
    assert!(matches!(outer, Ok(Ok(()))));
    assert_eq!(marks(&s), ["outer", "after"]);

    // And an outer failure undoes an inner group that succeeded.
    let s = store();
    let outer = s.atomically(|| -> Result<(), &'static str> {
        let inner = s.atomically(|| mark(&s, "inner"));
        assert!(matches!(inner, Ok(Ok(1))));
        Err("the outer group failed")
    });
    assert!(matches!(outer, Ok(Err(_))));
    assert!(marks(&s).is_empty());
    assert!(s.conn.is_autocommit());
}

#[test]
fn a_panic_inside_a_group_rolls_it_back_and_the_store_stays_usable() {
    let s = store();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        let _ = s.atomically(|| -> rusqlite::Result<()> {
            mark(&s, "before the panic")?;
            panic!("a handler panicked mid-write");
        });
    }));
    assert!(unwound.is_err());
    assert!(marks(&s).is_empty());
    assert!(s.conn.is_autocommit(), "the panic left no transaction open");
    mark(&s, "later").unwrap();
    assert_eq!(marks(&s), ["later"]);
}
