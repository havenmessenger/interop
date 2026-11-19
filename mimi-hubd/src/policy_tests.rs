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
        "mls_ciphersuites=0x0001 identifier_discovery=enrolled require_nonce_on_key_material=true external_commit_when_unset=deny untracked_rooms=accept consent_provider_grants=true consent_revoke_notifies=true consent_kept_at_opt_out=true consent_request_days=7"
    );
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
