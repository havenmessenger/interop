//! The policy file: the drafts' behaviour by default, each field read, and a file that is not what was meant refused.

use super::*;

/// No file, or an empty one, is the drafts' behaviour: every implemented suite, and discovery of every user the hub
/// can answer for.
#[test]
fn the_default_is_the_drafts_behaviour() {
    let empty = HubPolicy::parse("").unwrap();
    assert_eq!(empty, HubPolicy::default());
    assert_eq!(
        empty.mls_ciphersuites,
        mimi_core::gate::default_mls_ciphersuites()
    );
    assert!(empty.mls_ciphersuites.contains(&0x0001));
    assert_eq!(empty.identifier_discovery, Discovery::All);
}

#[test]
fn each_field_is_read() {
    let policy = HubPolicy::parse(
        r#"
        mls_ciphersuites = [0x0001]
        identifier_discovery = "enrolled"
        require_nonce_on_key_material = true
        external_commit_when_unset = "deny"
        untracked_rooms = "accept"
        consent_provider_grants = true
        consent_revoke_notifies = true
        consent_kept_at_opt_out = true
        consent_request_days = 7
        "#,
    )
    .unwrap();
    assert!(policy.require_nonce_on_key_material);
    assert!(!HubPolicy::default().require_nonce_on_key_material);
    assert_eq!(policy.mls_ciphersuites, vec![0x0001]);
    assert_eq!(policy.identifier_discovery, Discovery::Enrolled);
    assert!(policy.consent_provider_grants && policy.consent_revoke_notifies);
    assert!(policy.consent_kept_at_opt_out);
    assert_eq!(policy.consent_request_days, 7);
    let drafts = HubPolicy::default();
    assert!(!drafts.consent_provider_grants && !drafts.consent_revoke_notifies);
    assert!(!drafts.consent_kept_at_opt_out);
    assert_eq!(drafts.consent_request_days, 30);
    assert_eq!(
        policy.untracked_rooms,
        crate::policy::UntrackedRooms::Accept
    );
    assert_eq!(
        HubPolicy::default().untracked_rooms,
        crate::policy::UntrackedRooms::Refuse
    );
    assert_eq!(
        policy.describe(),
        "mls_ciphersuites=0x0001 identifier_discovery=enrolled require_nonce_on_key_material=true external_commit_when_unset=deny untracked_rooms=accept consent_provider_grants=true consent_revoke_notifies=true consent_kept_at_opt_out=true consent_request_days=7 did_webvh=0x0008/0xf013"
    );
}

/// The `[did_webvh]` table: the reference implementation's code points by default; other values, or off, as written.
/// Revert check: read the code points from the defaults whatever the table says, and the written ones are not used.
#[test]
fn the_did_webvh_table_is_read() {
    let drafts = HubPolicy::default().did_webvh;
    assert_eq!(
        drafts.code_points().unwrap(),
        Some(mls_didwebvh::CodePoints::DEFAULT)
    );
    let written = HubPolicy::parse(
        r#"
        [did_webvh]
        credential_type = 0xF013
        heads_component = 0xF014
        "#,
    )
    .unwrap();
    let points = written.did_webvh.code_points().unwrap().unwrap();
    assert_eq!(
        (points.credential_type(), points.heads_component()),
        (0xF013, 0xF014),
        "PLANT-POLICY-DIDWEBVH-POINTS: the table's code points were not read"
    );
    assert!(written.describe().ends_with("did_webvh=0xf013/0xf014"));
    let off = HubPolicy::parse("[did_webvh]\nenabled = false\n").unwrap();
    assert_eq!(
        off.did_webvh.code_points().unwrap(),
        None,
        "PLANT-POLICY-DIDWEBVH-OFF: did_webvh was read though the policy turns it off"
    );
    assert!(off.describe().ends_with("did_webvh=off"));
}

/// A file that does not say what was meant stops the start: a misspelt key, an unknown value, an empty suite list, a
/// suite the crypto provider does not implement.
#[test]
fn a_policy_that_is_not_what_was_meant_is_refused() {
    for raw in [
        "mls_ciphersuite = [1]",
        "identifier_discovery = \"some\"",
        "environment = \"development\"",
        "mls_ciphersuites = []",
        "consent_request_days = 0",
        "mls_ciphersuites = [0x0001, 0xbeef]",
        "mls_ciphersuites = \"0x0001\"",
        // A credential type RFC 9420 assigns (x509), a GREASE component, and a key the table does not have.
        "[did_webvh]\ncredential_type = 0x0002",
        "[did_webvh]\nheads_component = 0x0A0A",
        "[did_webvh]\ncredential = 0x0008",
    ] {
        assert!(HubPolicy::parse(raw).is_err(), "{raw:?} was taken");
    }
}

#[test]
fn a_named_file_that_cannot_be_read_is_refused() {
    let missing =
        std::env::temp_dir().join(format!("mimi-policy-missing-{}.toml", std::process::id()));
    let error = HubPolicy::load(&missing).unwrap_err().to_string();
    assert!(error.contains("cannot read the policy file"), "{error}");
}
