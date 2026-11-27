//! The reference implementation's interop vectors and a DIF did:webvh test-suite subset (`tests/vectors/didwebvh/`, see
//! its PROVENANCE), read through this hub's own code: a log through `credential::verify_log`, a leaf's binding through
//! `credential::verified_log`, and a Commit or a join through the tree's leaves as `did_webvh_leaves` reads them and the
//! records-level rules (`commit_on_records`, `join_on_records`) the GroupContext checks call. The vectors' expected
//! outcomes are the generator's, written from the draft's text; none is produced by this hub or by mls-didwebvh.

use mls_didwebvh::{DidWebvhCredential, DidWebvhHeads};
use openmls::prelude::{Credential, CredentialType};
use serde_json::Value;

use super::{commit_on_records, did_webvh_leaves, join_on_records, VerifiedLeaf};
use crate::credential::{is_successor, mimi_user_uri, verified_log, verify_log, DID_WEBVH};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../tests/vectors/didwebvh/vectors.json")).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn text<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} in {v}"))
}

/// The MLS credential carrying a vector log's `credential_tls`, under the did_webvh type this hub reads.
fn credential_of(vectors: &Value, log: &str) -> Credential {
    let entry = vectors["logs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == log)
        .unwrap_or_else(|| panic!("no log {log}"));
    Credential::new(
        CredentialType::Other(DID_WEBVH.credential_type()),
        hex(text(entry, "credential_tls")),
    )
}

/// A vector's leaves as the hub reads a tree's: each `(credential, signature key)` through `did_webvh_leaves`.
fn leaves(vectors: &Value, v: &Value) -> Result<Vec<VerifiedLeaf>, &'static str> {
    did_webvh_leaves(v["leaves"].as_array().unwrap().iter().map(|leaf| {
        (
            credential_of(vectors, text(leaf, "log")),
            hex(text(leaf, "signature_key")),
        )
    }))
}

fn record(v: &Value) -> DidWebvhHeads {
    DidWebvhHeads::decode(&hex(text(v, "tls"))).unwrap()
}

/// The words of the hub's refusal for a rule the vectors name.
fn says(reason: &str) -> &'static str {
    match reason {
        "key-not-in-head" => "authorize its key",
        "newest-lacks-reference" => "Expected Heads",
        "extension-mismatch" => "Record matches",
        "missing-reference" | "fork" => "Consistency",
        "unauthorized" => "Authorization",
        "missing-entry" => "has no entry",
        "newer-than-recorded" => "newer than",
        "keys-mismatch" => "authorized_keys do not match",
        other => panic!("a reason the vectors did not have: {other}"),
    }
}

/// Every log vector: a valid one verifies with its SCID, versions and authorized keys; an invalid one does not.
#[test]
fn the_log_vectors_verify_as_the_draft_says() {
    let vectors = vectors();
    let mut checked = 0;
    for entry in vectors["logs"].as_array().unwrap() {
        let name = text(entry, "name");
        let credential = Credential::new(
            CredentialType::Other(DID_WEBVH.credential_type()),
            hex(text(entry, "credential_tls")),
        );
        let log = verify_log(&credential);
        if entry["valid"] == true {
            let log = log.unwrap_or_else(|| panic!("{name}: a valid log did not verify"));
            assert_eq!(log.scid(), text(entry, "scid"), "{name}");
            let versions: Vec<&str> = entry["version_ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(log.version_ids(), versions.as_slice(), "{name}");
            let keys: Vec<Vec<u8>> = log.authorized_keys().iter().map(|k| k.to_vec()).collect();
            let expected: Vec<Vec<u8>> = entry["authorized_keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| hex(k.as_str().unwrap()))
                .collect();
            assert_eq!(keys, expected, "{name}");
        } else {
            assert!(log.is_none(), "{name}: an invalid log verified");
        }
        checked += 1;
    }
    assert!(checked >= 30, "only {checked} log vectors");
}

/// Every binding vector through the hub's `verified_log`; every successor vector the hub refuses when the vector does
/// (the hub's rule is stricter: it also keeps the `mimi:` URI).
#[test]
fn the_binding_and_successor_vectors_hold() {
    let vectors = vectors();
    for v in vectors["binding"].as_array().unwrap() {
        let leaf = &v["leaf"];
        let bound = verified_log(
            &credential_of(&vectors, text(leaf, "log")),
            &hex(text(leaf, "signature_key")),
        )
        .is_some();
        assert_eq!(
            bound,
            v["valid"] == true,
            "PLANT-VECTORS-BINDING: {}",
            v["note"]
        );
    }
    for v in vectors["successor"].as_array().unwrap() {
        let note = &v["note"];
        let (old, new) = (
            credential_of(&vectors, text(v, "old")),
            credential_of(&vectors, text(v, "new")),
        );
        let key = |credential: &Credential| {
            verify_log(credential)
                .and_then(|log| log.authorized_keys().iter().next().copied())
                .map(|key| key.to_vec())
                .unwrap_or_default()
        };
        let draft = v["valid"] == true;
        let hub = is_successor((&old, &key(&old)), (&new, &key(&new)));
        let (old_log, new_log) = (verify_log(&old).unwrap(), verify_log(&new).unwrap());
        // The draft's rule (§Successor Credentials) decides the vector; the hub adds protocol-07 §7.5's: the same
        // mimi: URI.
        assert_eq!(
            mls_didwebvh::rules::is_valid_successor(&old_log, &new_log),
            draft,
            "{note}: the draft's successor rule"
        );
        if hub {
            assert!(
                draft,
                "PLANT-VECTORS-SUCCESSOR: {note}: the hub took a successor the draft's rule refuses"
            );
        }
        if draft && !hub {
            let (before, after) = (mimi_user_uri(&old_log), mimi_user_uri(&new_log));
            assert!(
                before.is_none() || before != after,
                "{note}: the hub refused a successor the draft takes, and not by the §7.5 URI rule"
            );
        }
    }
}

/// Every Commit vector through the hub's leaves and rules: a valid one passes; an invalid one is refused for the rule
/// the vector names. Revert check: skip Record matches, and an extension-mismatch vector passes.
#[test]
fn the_commit_vectors_get_the_drafts_answers() {
    let vectors = vectors();
    let mut checked = 0;
    for v in vectors["commits"].as_array().unwrap() {
        let name = text(v, "name");
        let answer = leaves(&vectors, v).and_then(|leaves| {
            commit_on_records(
                Some(&record(&v["previous"])),
                Some(&record(&v["resulting"])),
                &leaves,
            )
        });
        if v["valid"] == true {
            assert_eq!(answer, Ok(()), "{name}");
        } else {
            let reason = says(text(v, "reason"));
            assert!(
                answer.is_err_and(|why| why.contains(reason)),
                "PLANT-VECTORS-COMMIT: {name}: answered {answer:?}, the vector says {}",
                text(v, "reason")
            );
        }
        checked += 1;
    }
    assert!(checked >= 15, "only {checked} commit vectors");
}

/// Every join vector through the hub's leaves and the rules a joiner checks.
#[test]
fn the_join_vectors_get_the_drafts_answers() {
    let vectors = vectors();
    for v in vectors["joins"].as_array().unwrap() {
        let name = text(v, "name");
        let answer = leaves(&vectors, v)
            .and_then(|leaves| join_on_records(Some(&record(&v["heads"])), &leaves));
        if v["valid"] == true {
            assert_eq!(answer, Ok(()), "{name}");
        } else {
            let why = answer.expect_err(name);
            if let Some(reason) = v["reason"].as_str() {
                assert!(
                    why.contains(says(reason)),
                    "{name}: refused for {why:?}, the vector says {reason}"
                );
            }
        }
    }
}

/// The DIF test-suite subset through the hub's `verify_log`. Every positive scenario verifies, but one: `deactivate`,
/// a valid did:webvh v1.0 log that ends deactivated, which the draft refuses on purpose (§Log Verification, change 5:
/// "After every entry has been processed, the active value of the `deactivated` parameter MUST be false"), and
/// mls-didwebvh names that rule. Every negative scenario is refused; `negative-versiontime-future` at its third entry,
/// as the draft keeps the strict increase of `versionTime` but compares it with no clock (change 3).
#[test]
fn the_dif_logs_verify_as_the_draft_says() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/didwebvh/dif");
    let mut positive = 0;
    let mut negative = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let scenario = entry.unwrap().path();
        let name = scenario.file_name().unwrap().to_string_lossy().into_owned();
        let log = std::fs::read(scenario.join("did.jsonl")).unwrap();
        let witness = std::fs::read(scenario.join("did-witness.json")).unwrap_or_default();
        let did_webvh = DidWebvhCredential::new(log, witness).unwrap();
        let credential = Credential::new(
            CredentialType::Other(DID_WEBVH.credential_type()),
            did_webvh.encode().unwrap(),
        );
        let verified = verify_log(&credential).is_some();
        let why = mls_didwebvh::verify_credential(&did_webvh).err();
        if name == "deactivate" {
            assert!(!verified, "deactivate: a deactivated log verified");
            assert_eq!(
                why,
                Some(mls_didwebvh::LogError::Deactivated),
                "deactivate: refused by §Log Verification change 5"
            );
        } else if name.starts_with("negative-") {
            assert!(!verified, "{name}: refused by the draft, verified here");
            if name == "negative-versiontime-future" {
                assert!(
                    matches!(why, Some(mls_didwebvh::LogError::Webvh { entry: 3, .. })),
                    "{name}: refused at its third entry, the one that goes back in time: {why:?}"
                );
            }
            negative += 1;
        } else {
            assert!(verified, "{name}: a valid log did not verify: {why:?}");
            positive += 1;
        }
    }
    assert!(
        positive >= 12 && negative >= 15,
        "{positive} positive, {negative} negative"
    );
}
