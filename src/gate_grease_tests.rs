//! A KeyPackage that carries a GREASE value (RFC 9420 §13.5) is refused by the pinned openmls release: it reads the same
//! value as a GREASE extension type in a client's capabilities and as an unknown extension type in the KeyPackage's own
//! extensions, so the check that every extension is listed in the capabilities fails with `UnsupportedExtension`.
//! DIVERGENCES.md DIV-14 records the refusal.

use super::*;
use crate::test_fixtures::{grease_key_package, key_package};

/// The refusal as it stands. When the pinned openmls release classifies GREASE consistently this test fails: invert it, so
/// that a GREASE-bearing KeyPackage of the pinned suite passes the gate, and remove DIV-14.
#[test]
fn a_grease_bearing_key_package_is_refused_until_the_pinned_openmls_classifies_grease_consistently()
{
    let error = mimi_gate_keypackage(&grease_key_package()).unwrap_err();
    assert!(
        matches!(&error, GateError::KeyPackageValidation(detail) if detail.contains("UnsupportedExtension")),
        "{error}"
    );
}

/// The refusal is about the GREASE value and nothing else: the same builder without it passes.
#[test]
fn the_same_key_package_without_grease_passes() {
    mimi_gate_keypackage(&key_package(b"plain", 1)).unwrap();
}
