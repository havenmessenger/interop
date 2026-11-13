//! `mimi-hubd enroll <HANDLE>`, run as the built binary: it writes the handle into the store the settings name and
//! needs nothing else from them, and it leaves a path that holds no database alone.

use std::path::PathBuf;
use std::process::Command;

use mimi_core::gate::IdentifierQueryResult;
use mimi_hubd::Provider;

fn fresh_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mimi_hubd_enroll_cli_{test}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The binary with an environment that holds one setting, the database path: no certificate, no provider domain.
fn enroll(db_path: &str, handle: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mimi-hubd"))
        .env_clear()
        .env("MIMI_DB_PATH", db_path)
        .args(["enroll", handle])
        .output()
        .unwrap()
}

#[test]
fn enroll_writes_the_handle_into_the_hubs_store_with_no_certificate_configured() {
    let dir = fresh_dir("writes");
    let path = dir.join("hub.db").to_str().unwrap().to_owned();
    let hub = Provider::open("example.com", &path).unwrap();
    assert_eq!(
        hub.identifier_query("erin").unwrap(),
        IdentifierQueryResult::NotFound
    );

    let ran = enroll(&path, "erin");

    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    let said = String::from_utf8_lossy(&ran.stdout);
    assert!(said.contains("erin") && said.contains(&path), "{said}");
    assert_eq!(
        hub.identifier_query("erin").unwrap(),
        IdentifierQueryResult::Found
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn enroll_at_a_path_with_no_database_fails_and_creates_none() {
    let dir = fresh_dir("missing");
    let path = dir.join("hub.db").to_str().unwrap().to_owned();

    let ran = enroll(&path, "erin");

    assert!(
        !ran.status.success(),
        "enroll reported success with no database to write"
    );
    assert!(
        String::from_utf8_lossy(&ran.stderr).contains("no hub database at"),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        !std::path::Path::new(&path).exists(),
        "a failed enroll left a database behind"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
