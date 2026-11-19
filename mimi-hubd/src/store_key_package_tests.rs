//! One-time and last-resort KeyPackages in the store: one-time ones are handed out first and once each, the last-resort
//! one only when none is left and kept for the next claim, never evicted for the per-user cap, and replaced by a newer
//! one.

use super::*;

const NOW: u64 = 1_000;
const LATER: u64 = NOW + 100;

/// Bob's last-resort KeyPackage and two one-time ones: the one-time ones are claimed first, oldest first, and then the
/// last-resort one, as often as asked. Revert checks: hand out the oldest row whatever it is, and the last-resort one
/// comes first; delete it when claimed, and the second claim of it finds nothing.
#[test]
fn one_time_key_packages_go_first_and_the_last_resort_one_stays() {
    let s = SqliteStore::in_memory().unwrap();
    s.add_key_package_marked("bob", b"last", LATER, true)
        .unwrap();
    s.add_key_package_marked("bob", b"one", LATER, false)
        .unwrap();
    s.add_key_package_marked("bob", b"two", LATER, false)
        .unwrap();
    assert_eq!(s.key_package_count("bob", NOW).unwrap(), (2, true));
    assert_eq!(
        s.claim_key_package("bob", NOW).unwrap().as_deref(),
        Some(&b"one"[..]),
        "PLANT-HUB-KP-ONE-TIME-FIRST: a one-time KeyPackage is handed out before the last-resort one"
    );
    assert_eq!(
        s.claim_key_package("bob", NOW).unwrap().as_deref(),
        Some(&b"two"[..])
    );
    assert_eq!(
        s.claim_key_package("bob", NOW).unwrap().as_deref(),
        Some(&b"last"[..])
    );
    assert_eq!(
        s.claim_key_package("bob", NOW).unwrap().as_deref(),
        Some(&b"last"[..]),
        "PLANT-HUB-KP-KEPT: the last-resort KeyPackage is handed out again"
    );
    assert_eq!(s.key_package_count("bob", NOW).unwrap(), (0, true));
}

/// A claim that names what it needs passes over a one-time KeyPackage that does not meet it to the last-resort one,
/// and keeps that.
#[test]
fn a_claim_that_meets_only_the_last_resort_one_keeps_it() {
    let s = SqliteStore::in_memory().unwrap();
    s.add_key_package_marked("bob", b"old-suite", LATER, false)
        .unwrap();
    s.add_key_package_marked("bob", b"last", LATER, true)
        .unwrap();
    for _ in 0..2 {
        assert!(matches!(
            s.claim_key_package_meeting("bob", NOW, |kp| kp == b"last").unwrap(),
            KeyClaim::Claimed(kp) if kp == b"last"
        ));
    }
    assert_eq!(s.key_package_count("bob", NOW).unwrap(), (1, true));
}

/// Past the per-user cap the oldest one-time KeyPackages go, and the last-resort one, though the oldest of all, stays.
/// Revert check: evict the oldest rows of any kind, and it goes.
#[test]
fn the_cap_never_evicts_the_last_resort_key_package() {
    let s = SqliteStore::in_memory().unwrap();
    s.add_key_package_marked("bob", b"last", LATER, true)
        .unwrap();
    for i in 0..MAX_KEYPACKAGES_PER_USER + 1 {
        s.add_key_package_marked("bob", &i.to_be_bytes(), LATER, false)
            .unwrap();
    }
    let (one_time, last_resort) = s.key_package_count("bob", NOW).unwrap();
    assert!(
        last_resort,
        "PLANT-HUB-KP-NOT-EVICTED: the last-resort KeyPackage survives the cap"
    );
    assert_eq!(
        one_time + 1,
        u64::try_from(MAX_KEYPACKAGES_PER_USER).unwrap(),
        "the cap counts the last-resort one"
    );
}

/// A new last-resort KeyPackage replaces the one before. Revert check: keep both, and the older one is handed out.
#[test]
fn a_new_last_resort_key_package_replaces_the_old() {
    let s = SqliteStore::in_memory().unwrap();
    s.add_key_package_marked("bob", b"first", LATER, true)
        .unwrap();
    s.add_key_package_marked("bob", b"second", LATER, true)
        .unwrap();
    assert_eq!(
        s.claim_key_package("bob", NOW).unwrap().as_deref(),
        Some(&b"second"[..]),
        "PLANT-HUB-KP-REPLACED: the newer last-resort KeyPackage is the one handed out"
    );
    assert_eq!(s.key_package_count("bob", NOW).unwrap(), (0, true));
}

/// A store written before KeyPackages were marked opens with the column added, and its rows are one-time KeyPackages.
#[test]
fn a_store_from_before_the_mark_reads_its_key_packages_as_one_time() {
    let path = std::env::temp_dir().join(format!("mimi-kp-mark-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE keypackages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL,
                 kp_bytes BLOB NOT NULL,
                 not_after INTEGER NOT NULL
             );
             INSERT INTO keypackages (username, kp_bytes, not_after) VALUES ('bob', x'01', 2000);",
        )
        .unwrap();
    }
    let s = SqliteStore::open(path.to_str().unwrap()).unwrap();
    assert_eq!(s.key_package_count("bob", NOW).unwrap(), (1, false));
    assert_eq!(s.claim_key_package("bob", NOW).unwrap(), Some(vec![1]));
    assert_eq!(s.claim_key_package("bob", NOW).unwrap(), None);
    drop(s);
    let _ = std::fs::remove_file(&path);
}
