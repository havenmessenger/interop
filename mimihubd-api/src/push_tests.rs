//! A pushed batch is taken only as the hub signs it, once.

use std::collections::HashMap;

use super::*;
use crate::sign::SigningKey;

const TARGET: &str = "https://app.example.com/mimi-events";

fn pushed(seed: u8, body: &[u8], created: u64, nonce: &str) -> HashMap<String, String> {
    let key = SigningKey::from_seed(&[seed; 32], "hub1").unwrap();
    let mut headers: HashMap<String, String> = key
        .sign_provider(
            "POST",
            TARGET,
            "mimi@example.com",
            body,
            created,
            Some(nonce),
        )
        .into_iter()
        .map(|(n, v)| (n.to_string(), v))
        .collect();
    headers.insert("from".into(), "mimi@example.com".into());
    headers
}

fn verifier() -> PushVerifier {
    let public = SigningKey::from_seed(&[3u8; 32], "hub1")
        .unwrap()
        .public_key();
    PushVerifier::new(public, "hub1", "example.com")
}

fn check(
    v: &PushVerifier,
    target: &str,
    h: &HashMap<String, String>,
    body: &[u8],
    now: i64,
) -> Result<(), PushRefusal> {
    v.verify(target, |name| h.get(name).cloned(), body, now)
}

/// The hub's own signature verifies once; a replay, another key, another body, another target, another sender, a
/// stale one and a lane tag are each refused.
#[test]
fn a_push_is_taken_only_as_the_hub_signs_it() {
    let v = verifier();
    let body = br#"{"events":[],"more":false}"#;
    assert_eq!(
        check(&v, TARGET, &pushed(3, body, 1000, "a"), body, 1000),
        Ok(())
    );
    assert_eq!(
        check(&v, TARGET, &pushed(3, body, 1000, "a"), body, 1001),
        Err(PushRefusal::Replayed)
    );
    assert_eq!(
        check(&v, TARGET, &pushed(4, body, 1000, "b"), body, 1000),
        Err(PushRefusal::Signature)
    );
    assert_eq!(
        check(&v, TARGET, &pushed(3, body, 1000, "c"), b"{}", 1000),
        Err(PushRefusal::Digest)
    );
    assert_eq!(
        check(
            &v,
            "https://other.example.com/x",
            &pushed(3, body, 1000, "d"),
            body,
            1000
        ),
        Err(PushRefusal::Signature)
    );
    let mut peer = pushed(3, body, 1000, "e");
    peer.insert("from".into(), "mimi@peer.example".into());
    assert_eq!(
        check(&v, TARGET, &peer, body, 1000),
        Err(PushRefusal::Profile("from"))
    );
    assert_eq!(
        check(&v, TARGET, &pushed(3, body, 1000, "f"), body, 1100),
        Err(PushRefusal::Stale)
    );
    let mut lane = pushed(3, body, 1000, "g");
    let input = lane["signature-input"].replace(r#"tag="mimi""#, r#"tag="mimi-client-lane""#);
    lane.insert("signature-input".into(), input);
    assert_eq!(
        check(&v, TARGET, &lane, body, 1000),
        Err(PushRefusal::Profile("tag"))
    );
}
