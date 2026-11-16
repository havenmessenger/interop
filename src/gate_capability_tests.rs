//! `keypackage_meets`: a KeyPackage meets a KeyMaterialRequest's ciphersuites and required capabilities.

use super::*;
use crate::test_fixtures::{key_package, key_package_with_capabilities};

const PINNED: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// A leaf that lists the app_data_dictionary extension and the AppDataUpdate proposal, with the basic credential.
fn room_capable() -> Vec<u8> {
    key_package_with_capabilities(Capabilities::new(
        None,
        Some(&[PINNED]),
        Some(&[ExtensionType::from(0x0006)]),
        Some(&[ProposalType::from(0x0008)]),
        Some(&[CredentialType::Basic]),
    ))
}

fn requiring(
    extensions: &[ExtensionType],
    proposals: &[ProposalType],
    credentials: &[CredentialType],
) -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(extensions, proposals, credentials)
}

#[test]
fn a_leaf_that_lists_what_is_required_meets_it() {
    let required = requiring(
        &[ExtensionType::from(0x0006)],
        &[ProposalType::from(0x0008)],
        &[CredentialType::Basic],
    );
    assert!(keypackage_meets(&room_capable(), &[PINNED], &required));
    assert!(keypackage_meets(&room_capable(), &[], &required));
}

#[test]
fn a_leaf_that_lacks_a_required_extension_or_proposal_does_not() {
    let plain = key_package(b"plain", 1);
    assert!(!keypackage_meets(
        &plain,
        &[],
        &requiring(&[ExtensionType::from(0x0006)], &[], &[])
    ));
    assert!(!keypackage_meets(
        &plain,
        &[],
        &requiring(&[], &[ProposalType::from(0x0008)], &[])
    ));
}

#[test]
fn default_types_need_not_be_listed_and_nothing_required_is_met_by_any() {
    let plain = key_package(b"plain", 1);
    assert!(keypackage_meets(&plain, &[], &requiring(&[], &[], &[])));
    assert!(keypackage_meets(
        &plain,
        &[],
        &requiring(&[ExtensionType::RatchetTree], &[ProposalType::Add], &[])
    ));
}

#[test]
fn a_suite_outside_the_acceptable_list_is_not_met() {
    let other = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    assert!(!keypackage_meets(
        &room_capable(),
        &[other],
        &requiring(&[], &[], &[])
    ));
}

#[test]
fn bytes_that_are_not_a_key_package_meet_nothing() {
    assert!(!keypackage_meets(
        &[0x00, 0x01, 0x02],
        &[],
        &requiring(&[], &[], &[])
    ));
}
