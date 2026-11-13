//! `enroll_handle` writes into the hub's store, and only into a store that is already there.

use mimi_core::gate::IdentifierQueryResult;

use super::enroll_handle;
use crate::Provider;

/// A directory of this test's own, and the path of a database inside it that does not exist yet.
fn fresh_db_path(test: &str) -> (std::path::PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("mimi_hubd_enroll_{test}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db").to_str().unwrap().to_owned();
    (dir, path)
}

#[test]
fn an_enrolled_handle_is_found_by_a_hub_on_the_same_store_and_no_other_is() {
    let (dir, path) = fresh_db_path("found");
    let hub = Provider::open("example.com", &path).unwrap();
    assert_eq!(
        hub.identifier_query("erin").unwrap(),
        IdentifierQueryResult::NotFound
    );

    enroll_handle(&path, "erin").unwrap();

    // The hub was open before the handle was enrolled: it reads the store at each query.
    assert_eq!(
        hub.identifier_query("erin").unwrap(),
        IdentifierQueryResult::Found
    );
    assert_eq!(
        hub.identifier_query("grace").unwrap(),
        IdentifierQueryResult::NotFound
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn enrolling_a_handle_twice_is_not_an_error() {
    let (dir, path) = fresh_db_path("twice");
    let hub = Provider::open("example.com", &path).unwrap();
    enroll_handle(&path, "erin").unwrap();
    enroll_handle(&path, "erin").unwrap();
    assert_eq!(
        hub.identifier_query("erin").unwrap(),
        IdentifierQueryResult::Found
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_path_with_no_database_is_refused_and_none_is_created_there() {
    let (dir, path) = fresh_db_path("missing");

    let refused = enroll_handle(&path, "erin").unwrap_err().to_string();

    assert!(refused.contains("no hub database at"), "{refused}");
    assert!(
        !std::path::Path::new(&path).exists(),
        "a refused enroll left a database behind"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_empty_handle_is_refused_and_nothing_is_enrolled() {
    let (dir, path) = fresh_db_path("empty");
    let hub = Provider::open("example.com", &path).unwrap();

    let refused = enroll_handle(&path, "").unwrap_err().to_string();

    assert!(refused.contains("empty"), "{refused}");
    assert_eq!(
        hub.identifier_query("").unwrap(),
        IdentifierQueryResult::NotFound
    );
    std::fs::remove_dir_all(dir).unwrap();
}
