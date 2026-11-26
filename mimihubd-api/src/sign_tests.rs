//! The signatures, against the base strings RFC 9421 builds from them.

use ring::signature::{UnparsedPublicKey, ED25519};

use super::*;

const TARGET: &str = "https://hub.example:8450/mimi/client/v1/events/fetch";

fn get<'a>(headers: &'a Headers, name: &str) -> &'a str {
    headers
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.as_str())
        .unwrap()
}

fn verifies(key: &SigningKey, base: &str, signature_header: &str, label: &str) -> bool {
    let signature = signature_header
        .strip_prefix(&format!("{label}=:"))
        .and_then(|s| s.strip_suffix(':'))
        .and_then(|s| STANDARD.decode(s).ok())
        .unwrap();
    UnparsedPublicKey::new(&ED25519, key.public_key())
        .verify(base.as_bytes(), &signature)
        .is_ok()
}

/// The provider server's own request: three components, its own tag, no user header; it verifies over the base string
/// the hub rebuilds.
#[test]
fn a_provider_lane_request_signs_its_three_components() {
    let key = SigningKey::from_seed(&[7u8; 32], "lane1").unwrap();
    let body = br#"{"after_seq":0}"#;
    let headers = key.sign_lane(TARGET, body, &Acting::Provider, 1_700_000_000, "n1");
    let params = get(&headers, "signature-input")
        .strip_prefix("lane=")
        .unwrap();
    assert_eq!(
        params,
        r#"("@method" "@target-uri" "content-digest");created=1700000000;nonce="n1";keyid="lane1";tag="mimi-client-lane-provider""#
    );
    assert!(headers.iter().all(|(n, _)| *n != "mimi-client-user"));
    let base = format!(
        "\"@method\": POST\n\"@target-uri\": {TARGET}\n\"content-digest\": {}\n\"@signature-params\": {params}",
        content_digest(body)
    );
    assert!(verifies(&key, &base, get(&headers, "signature"), "lane"));
}

/// A user's request covers the user and device headers under the user tag.
#[test]
fn a_user_lane_request_names_the_user_and_device() {
    let key = SigningKey::from_seed(&[7u8; 32], "lane1").unwrap();
    let acting = Acting::User {
        user: "mimi://example.com/u/a".into(),
        device: "server".into(),
    };
    let headers = key.sign_lane(TARGET, b"{}", &acting, 5, "n2");
    assert_eq!(get(&headers, "mimi-client-user"), "mimi://example.com/u/a");
    let params = get(&headers, "signature-input")
        .strip_prefix("lane=")
        .unwrap();
    assert!(params.starts_with(
        r#"("@method" "@target-uri" "content-digest" "mimi-client-user" "mimi-client-device");"#
    ));
    assert!(params.ends_with(r#"tag="mimi-client-lane""#));
    let base = format!(
        "\"@method\": POST\n\"@target-uri\": {TARGET}\n\"content-digest\": {}\n\"mimi-client-user\": mimi://example.com/u/a\n\"mimi-client-device\": server\n\"@signature-params\": {params}",
        content_digest(b"{}")
    );
    assert!(verifies(&key, &base, get(&headers, "signature"), "lane"));
}

/// A provider's request, without a nonce, is the published example's shape: method upper-cased, `from` covered.
#[test]
fn a_provider_request_covers_from() {
    let key = SigningKey::from_seed(&[1u8; 32], "sel").unwrap();
    let headers = key.sign_provider(
        "post",
        "https://b.example/notify",
        "mimi@a.example",
        b"x",
        9,
        None,
    );
    let params = get(&headers, "signature-input")
        .strip_prefix("mimi=")
        .unwrap();
    assert_eq!(
        params,
        r#"("@method" "@target-uri" "content-digest" "from");created=9;keyid="sel";tag="mimi""#
    );
    let base = format!(
        "\"@method\": POST\n\"@target-uri\": https://b.example/notify\n\"content-digest\": {}\n\"from\": mimi@a.example\n\"@signature-params\": {params}",
        content_digest(b"x")
    );
    assert!(verifies(&key, &base, get(&headers, "signature"), "mimi"));
}

/// A key needs 32 seed bytes and a plain key id; a nonce is fresh each time.
#[test]
fn keys_and_nonces() {
    assert_eq!(
        SigningKey::from_seed(&[1u8; 31], "a").unwrap_err(),
        KeyError::Seed
    );
    assert_eq!(
        SigningKey::from_seed(&[1u8; 32], "a.b").unwrap_err(),
        KeyError::KeyId
    );
    assert_ne!(fresh_nonce().unwrap(), fresh_nonce().unwrap());
}
