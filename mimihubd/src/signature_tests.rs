//! The verifier against the draft's own example (Appendix A, the RFC 9421 B.1.4 Ed25519 test key), and each way a
//! request can fail to be authenticated by it.

use std::time::{Duration, SystemTime};

use super::*;

const CREATED: u64 = 1_794_700_800;
const BODY: &[u8] = b"example MIMI notify body";
const DIGEST: &str = "sha-256=:ltvFi/ijqMH79/ThrwZ/JykItjIYFA06v8rfqBdj7dY=:";
const INPUT: &str = r#"mimi=("@method" "@target-uri" "content-digest" "from");created=1794700800;keyid="s1";tag="mimi""#;
const SIGNATURE: &str =
    "mimi=:OBXnNmTPY+Gcxbn+BKcfqCpK7GrkCGO+Ab0/PS956byMzzcArSVEeJWA95WiYjfLJ9vMsEaCRab3geIFr5FpCw==:";
const URI: &str = "https://b.example/v1/notify/a.example/r/clubhouse";

/// A key file of its own for each test (`test`), so tests running at once never share or remove another's file.
fn keys(test: &str, value: &str) -> (PeerKeys, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("mimi-peer-keys-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("peer_keys.json");
    std::fs::write(&path, format!(r#"{{"s1._mimi.a.example": "{value}"}}"#)).unwrap();
    (PeerKeys::from_file(Some(path.clone())), dir)
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn check(
    method: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    now: SystemTime,
    keys: &PeerKeys,
) -> Result<String, Refusal> {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let header = move |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    verify(
        &SignedRequest {
            method,
            target_uri: URI,
            authority: "b.example",
            path: "/v1/notify/a.example/r/clubhouse",
            query: None,
            header: &header,
            body,
        },
        now,
        keys,
    )
}

fn appendix_a<'a>() -> Vec<(&'a str, &'a str)> {
    vec![
        ("from", "mimi@a.example"),
        ("content-digest", DIGEST),
        ("signature-input", INPUT),
        ("signature", SIGNATURE),
    ]
}

const PUBLIC: &str = "JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";

#[test]
fn the_drafts_example_authenticates_its_source_domain() {
    let (keys, dir) = keys("example", PUBLIC);
    assert_eq!(
        check("POST", &appendix_a(), BODY, at(CREATED), &keys),
        Ok("a.example".to_string())
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_changed_request_authenticates_nobody() {
    let (keys, dir) = keys("changed", PUBLIC);
    let now = at(CREATED);
    assert_eq!(
        check("PUT", &appendix_a(), BODY, now, &keys),
        Err(Refusal::BadSignature)
    );
    assert_eq!(
        check("POST", &appendix_a(), b"another body", now, &keys),
        Err(Refusal::DigestMismatch)
    );
    let mut other_from = appendix_a();
    other_from[0] = ("from", "mimi@c.example");
    assert_eq!(
        check("POST", &other_from, BODY, now, &keys),
        Err(Refusal::UnknownKey("s1._mimi.c.example".into()))
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn created_must_be_recent_and_not_ahead() {
    let (keys, dir) = keys("created", PUBLIC);
    assert!(check("POST", &appendix_a(), BODY, at(CREATED + 300), &keys).is_ok());
    assert_eq!(
        check("POST", &appendix_a(), BODY, at(CREATED + 301), &keys),
        Err(Refusal::Expired)
    );
    assert!(check("POST", &appendix_a(), BODY, at(CREATED - 60), &keys).is_ok());
    assert_eq!(
        check("POST", &appendix_a(), BODY, at(CREATED - 61), &keys),
        Err(Refusal::NotYetValid)
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_revoked_or_unknown_key_verifies_nothing() {
    let (revoked, dir) = keys("revoked", "");
    assert_eq!(
        check("POST", &appendix_a(), BODY, at(CREATED), &revoked),
        Err(Refusal::UnknownKey("s1._mimi.a.example".into()))
    );
    std::fs::remove_dir_all(dir).ok();
    let none = PeerKeys::from_file(None);
    assert!(check("POST", &appendix_a(), BODY, at(CREATED), &none).is_err());
}

#[test]
fn the_required_components_must_be_covered() {
    let (keys, dir) = keys("required", PUBLIC);
    let mut no_digest = appendix_a();
    no_digest[2] = (
        "signature-input",
        r#"mimi=("@method" "@target-uri" "from");created=1794700800;keyid="s1";tag="mimi""#,
    );
    assert_eq!(
        check("POST", &no_digest, BODY, at(CREATED), &keys),
        Err(Refusal::MissingComponent("content-digest"))
    );
    let unsigned: Vec<(&str, &str)> = appendix_a().into_iter().take(2).collect();
    assert_eq!(
        check("POST", &unsigned, BODY, at(CREATED), &keys),
        Err(Refusal::NoSignature)
    );
    std::fs::remove_dir_all(dir).ok();
}
