//! A user of this provider has one KeyPackage pool, whether it is published for by name or by URI, and a store that kept
//! some under the URI has them joined to the name when it opens.

use openmls::prelude::tls_codec::Serialize as _;

use crate::mls_fixtures::Member;
use crate::store::SqliteStore;
use crate::Provider;

const DOMAIN: &str = "hub.example";
const ERIN: &str = "mimi://hub.example/u/erin";
const NOW: u64 = 1_700_000_000;

fn key_package() -> Vec<u8> {
    Member::new(ERIN)
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}

/// Published by URI, claimed by name, and the other way round: one pool. Revert check: store under the key as given
/// and the claim by the other spelling finds nothing.
#[test]
fn a_user_named_either_way_has_one_pool() {
    let p = Provider::in_memory(DOMAIN).unwrap();
    p.publish_key_package(ERIN, &key_package(), NOW).unwrap();
    assert!(
        p.serve_key_material("erin", NOW).unwrap().is_some(),
        "PLANT-KP-ONE-KEY: a KeyPackage published by URI is claimed by name"
    );
    p.publish_key_package("erin", &key_package(), NOW).unwrap();
    assert!(p.serve_key_material(ERIN, NOW).unwrap().is_some());
    assert!(p.serve_key_material("erin", NOW).unwrap().is_none());
}

/// Another provider's user stays under its URI: it is not a name here.
#[test]
fn another_providers_user_stays_under_its_uri() {
    let p = Provider::in_memory(DOMAIN).unwrap();
    assert_eq!(
        p.key_package_user("mimi://other.example/u/erin"),
        "mimi://other.example/u/erin"
    );
    assert_eq!(p.key_package_user(ERIN), "erin");
    assert_eq!(p.key_package_user("erin"), "erin");
}

/// A store with KeyPackages and a ref association kept under the user's URI has them under the name once opened; a
/// longer path and another domain are left. Revert check: skip the fold and the claim by name finds nothing.
#[test]
fn opening_joins_a_uri_pool_to_the_name() {
    let dir = std::env::temp_dir().join(format!("mimi-kp-fold-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    let path = path.to_str().unwrap();
    {
        let store = SqliteStore::open(path).unwrap();
        store
            .add_key_package(ERIN, b"kp-by-uri", NOW + 100)
            .unwrap();
        store
            .add_key_package("mimi://hub.example/u/erin/x", b"kp-path", NOW + 100)
            .unwrap();
        store
            .add_key_package("mimi://other.example/u/erin", b"kp-other", NOW + 100)
            .unwrap();
        store
            .associate_kpref_client(b"ref", ERIN, NOW + 100)
            .unwrap();
    }
    let p = Provider::open(DOMAIN, path).unwrap();
    assert_eq!(
        p.serve_key_material("erin", NOW).unwrap().as_deref(),
        Some(&b"kp-by-uri"[..]),
        "PLANT-KP-FOLD: a URI pool is joined to the name at open"
    );
    assert_eq!(p.client_for_kpref(b"ref").unwrap().as_deref(), Some("erin"));
    assert!(p
        .serve_key_material("mimi://hub.example/u/erin/x", NOW)
        .unwrap()
        .is_some());
    assert!(p
        .serve_key_material("mimi://other.example/u/erin", NOW)
        .unwrap()
        .is_some());
    std::fs::remove_dir_all(&dir).ok();
}
