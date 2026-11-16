//! A KeyPackage that carries a GREASE value (RFC 9420 §13.5) passes the gate: GREASE keeps peers tolerant of values they
//! don't know, so a client that sends one must not lose its key material for it.

use super::*;
use crate::test_fixtures::{grease_key_package, key_package};

/// The gates asked to accept 0x0001 only.
const ONLY_AES: &[u16] = &[crate::gate::MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519];

#[test]
fn a_grease_bearing_key_package_of_the_pinned_suite_passes_the_gate() {
    mimi_gate_keypackage(&grease_key_package(), ONLY_AES).unwrap();
}

#[test]
fn the_same_key_package_without_grease_passes() {
    mimi_gate_keypackage(&key_package(b"plain", 1), ONLY_AES).unwrap();
}
