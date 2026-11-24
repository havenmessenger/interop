//! Who `identifierQuery` finds under each discovery setting, and the suites the directory advertises.

use super::*;
use crate::policy::{Discovery, HubPolicy};

const NOW: u64 = 1_000;

fn hub(discovery: Discovery) -> Provider {
    Provider::in_memory("example.com")
        .unwrap()
        .with_policy(HubPolicy {
            identifier_discovery: discovery,
            ..HubPolicy::default()
        })
}

/// With `all`, a user the hub holds an unexpired KeyPackage for is found, under its name or its URI here; one whose
/// KeyPackages have all expired, or who has none, is not. Revert check: answer from enrollment alone, and alice is
/// not found.
#[test]
fn all_finds_a_user_the_hub_holds_key_material_for() {
    let p = hub(Discovery::All);
    p.store.add_key_package("alice", b"kp", NOW + 10).unwrap();
    p.store
        .add_key_package("mimi://example.com/u/bob", b"kp", NOW + 10)
        .unwrap();
    p.store.add_key_package("carol", b"kp", NOW - 1).unwrap();
    assert_eq!(
        p.identifier_query("alice", NOW).unwrap(),
        IdentifierQueryResult::Found,
        "PLANT-DISCOVERY-ALL: a user with key material is found"
    );
    assert_eq!(
        p.identifier_query("bob", NOW).unwrap(),
        IdentifierQueryResult::Found
    );
    assert_eq!(
        p.identifier_query("carol", NOW).unwrap(),
        IdentifierQueryResult::NotFound
    );
    assert_eq!(
        p.identifier_query("dave", NOW).unwrap(),
        IdentifierQueryResult::NotFound
    );
}

/// With `enrolled`, only an enrolled user is found, whatever key material the hub holds. Revert check: ignore the
/// setting, and alice is found.
#[test]
fn enrolled_finds_only_an_enrolled_user() {
    let p = hub(Discovery::Enrolled);
    p.store.add_key_package("alice", b"kp", NOW + 10).unwrap();
    p.enroll("erin").unwrap();
    assert_eq!(
        p.identifier_query("alice", NOW).unwrap(),
        IdentifierQueryResult::NotFound,
        "PLANT-DISCOVERY-ENROLLED: key material alone does not find a user"
    );
    assert_eq!(
        p.identifier_query("erin", NOW).unwrap(),
        IdentifierQueryResult::Found
    );
}

/// The directory advertises the suites the policy accepts: every implemented suite by default, exactly the list when
/// the policy names one. Revert check: advertise a fixed 0x0001, and the default's list differs.
#[test]
fn the_directory_advertises_the_accepted_suites() {
    let default = Provider::in_memory("example.com").unwrap();
    assert_eq!(
        default.directory()["mls_ciphersuites"],
        serde_json::json!(mimi_core::gate::default_mls_ciphersuites()),
        "PLANT-DIRECTORY-SUITES: the directory follows the policy"
    );
    let narrowed = Provider::in_memory("example.com")
        .unwrap()
        .with_policy(HubPolicy {
            mls_ciphersuites: vec![0x0001],
            ..HubPolicy::default()
        });
    assert_eq!(
        narrowed.directory()["mls_ciphersuites"],
        serde_json::json!([1])
    );
}
