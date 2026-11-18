//! The lane verifier against the client-facing service's known-answer vector (the same seed, time, nonce and body
//! its own signer is tested with), and each way a lane request is refused.

use std::time::{Duration, SystemTime};

use super::*;

const PUBLIC: &str = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
const CREATED: u64 = 1_700_000_000;
const URI: &str = "https://hub.example:8450/mimi/client/v1/inboxFetch";
const USER: &str = "mimi://mimi.example.org/u/ana";
const DEVICE: &str = "dev-handle-0123456789a";
const BODY: &[u8] = br#"{"after":0,"limit":50}"#;
const DIGEST: &str = "sha-256=:3Ecv0of+AaZz8QdLHHa5NMuBdzjiu4LNhMowvznk93o=:";
const INPUT: &str = r#"haven=("@method" "@target-uri" "content-digest" "mimi-client-user" "mimi-client-device");created=1700000000;nonce="AAECAwQFBgcICQoLDA0ODw";keyid="lane1";tag="mimi-client-lane""#;
const SIGNATURE: &str = "haven=:Ny/e/mZfTf6TzMvewSi81IVmjdbbNJNPxiwU2knYMNZck888gI62TSa8YfePMhNgef9tzaSkN8BDpJFmxfG5Dw==:";

/// A lane key file of its own for each test, so tests running at once never share one.
fn lane_auth(test: &str, started: u64) -> (ClientLaneAuth, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("mimi-lane-keys-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("lane_keys.json");
    std::fs::write(
        &path,
        format!(r#"{{"lane1._mimi.client-lane": "{PUBLIC}"}}"#),
    )
    .unwrap();
    (
        ClientLaneAuth {
            keys: PeerKeys::from_file(Some(path)),
            nonces: NonceLedger::default(),
            started_unix: started as i64,
            domain: "mimi.example.org".into(),
        },
        dir,
    )
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn vector() -> Vec<(&'static str, String)> {
    vec![
        ("content-digest", DIGEST.into()),
        ("mimi-client-user", USER.into()),
        ("mimi-client-device", DEVICE.into()),
        ("signature-input", INPUT.into()),
        ("signature", SIGNATURE.into()),
    ]
}

fn check(
    auth: &ClientLaneAuth,
    method: &str,
    headers: &[(&'static str, String)],
    body: &[u8],
    now: SystemTime,
) -> Result<LaneUser, LaneRefusal> {
    let headers = headers.to_vec();
    let header = move |name: &str| {
        let values: Vec<String> = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    };
    auth.verify(
        &SignedRequest {
            method,
            target_uri: URI,
            authority: "hub.example:8450",
            path: "/mimi/client/v1/inboxFetch",
            query: None,
            header: &header,
            body,
        },
        now,
    )
}

fn with(
    headers: &[(&'static str, String)],
    name: &str,
    value: &str,
) -> Vec<(&'static str, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                *k,
                if *k == name {
                    value.to_string()
                } else {
                    v.clone()
                },
            )
        })
        .collect()
}

#[test]
fn the_services_vector_names_its_user() {
    let (auth, dir) = lane_auth("vector", CREATED - 60);
    let got = check(&auth, "POST", &vector(), BODY, at(CREATED + 5));
    std::fs::remove_dir_all(dir).ok();
    assert_eq!(
        got,
        Ok(LaneUser {
            user: USER.into(),
            device: DEVICE.into()
        })
    );
}

#[test]
fn every_covered_part_is_bound() {
    let (auth, dir) = lane_auth("bound", CREATED - 60);
    let now = at(CREATED + 5);
    let refused = |r: Result<LaneUser, LaneRefusal>| r.is_err();
    assert!(refused(check(&auth, "GET", &vector(), BODY, now)), "method");
    assert!(
        refused(check(
            &auth,
            "POST",
            &vector(),
            b"{\"after\":1,\"limit\":50}",
            now
        )),
        "body"
    );
    assert!(
        refused(check(
            &auth,
            "POST",
            &with(
                &vector(),
                "mimi-client-user",
                "mimi://mimi.example.org/u/bob"
            ),
            BODY,
            now
        )),
        "user"
    );
    assert!(
        refused(check(
            &auth,
            "POST",
            &with(&vector(), "mimi-client-device", "dev-handle-0123456789b"),
            BODY,
            now
        )),
        "device"
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_peer_signature_is_not_a_lane_signature() {
    let (auth, dir) = lane_auth("peer-tag", CREATED - 60);
    let input = INPUT.replace(r#"tag="mimi-client-lane""#, r#"tag="mimi""#);
    let got = check(
        &auth,
        "POST",
        &with(&vector(), "signature-input", &input),
        BODY,
        at(CREATED + 5),
    );
    std::fs::remove_dir_all(dir).ok();
    assert!(matches!(
        got,
        Err(LaneRefusal::Signature(Refusal::MissingComponent(_)))
    ));
}

#[test]
fn a_nonce_is_used_once() {
    let (auth, dir) = lane_auth("replay", CREATED - 60);
    let now = at(CREATED + 5);
    assert!(check(&auth, "POST", &vector(), BODY, now).is_ok());
    let again = check(&auth, "POST", &vector(), BODY, now);
    std::fs::remove_dir_all(dir).ok();
    assert_eq!(again, Err(LaneRefusal::Signature(Refusal::Replayed)));
}

#[test]
fn a_request_without_a_nonce_is_refused() {
    let (auth, dir) = lane_auth("no-nonce", CREATED - 60);
    let input = INPUT.replace(r#";nonce="AAECAwQFBgcICQoLDA0ODw""#, "");
    let got = check(
        &auth,
        "POST",
        &with(&vector(), "signature-input", &input),
        BODY,
        at(CREATED + 5),
    );
    std::fs::remove_dir_all(dir).ok();
    assert_eq!(got, Err(LaneRefusal::Signature(Refusal::NoNonce)));
}

#[test]
fn the_window_is_thirty_seconds_and_starts_with_the_process() {
    let (auth, dir) = lane_auth("window", CREATED - 60);
    assert_eq!(
        check(&auth, "POST", &vector(), BODY, at(CREATED + 31)),
        Err(LaneRefusal::Signature(Refusal::Expired))
    );
    assert_eq!(
        check(&auth, "POST", &vector(), BODY, at(CREATED - 31)),
        Err(LaneRefusal::Signature(Refusal::NotYetValid))
    );
    let (restarted, dir2) = lane_auth("window-restart", CREATED + 1);
    assert_eq!(
        check(&restarted, "POST", &vector(), BODY, at(CREATED + 5)),
        Err(LaneRefusal::BeforeStart)
    );
    std::fs::remove_dir_all(dir).ok();
    std::fs::remove_dir_all(dir2).ok();
}

#[test]
fn the_lane_acts_only_for_this_providers_users() {
    let (mut auth, dir) = lane_auth("foreign", CREATED - 60);
    auth.domain = "other.example".into();
    let got = check(&auth, "POST", &vector(), BODY, at(CREATED + 5));
    std::fs::remove_dir_all(dir).ok();
    assert_eq!(got, Err(LaneRefusal::NotLocalUser));
}

#[test]
fn an_unknown_or_revoked_key_verifies_nothing() {
    let (auth, dir) = lane_auth("revoked", CREATED - 60);
    std::fs::write(
        dir.join("lane_keys.json"),
        r#"{"lane1._mimi.client-lane": ""}"#,
    )
    .unwrap();
    let got = check(&auth, "POST", &vector(), BODY, at(CREATED + 5));
    std::fs::remove_dir_all(dir).ok();
    assert!(matches!(
        got,
        Err(LaneRefusal::Signature(Refusal::UnknownKey(_)))
    ));
}

#[test]
fn a_user_header_sent_twice_is_refused() {
    let (auth, dir) = lane_auth("twice", CREATED - 60);
    let mut headers = vector();
    headers.push(("mimi-client-user", USER.into()));
    let got = check(&auth, "POST", &headers, BODY, at(CREATED + 5));
    std::fs::remove_dir_all(dir).ok();
    assert!(got.is_err());
}
