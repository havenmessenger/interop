//! Checking an event batch the hub pushed: signed with the hub provider's key (the provider profile, tag `mimi`, over
//! `@method`, `@target-uri`, `content-digest` and `from`), `From: mimi@<the provider's domain>`, made within the
//! window, and with a nonce not seen before. A receiver checks this before it reads the body as a batch.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ring::signature::{UnparsedPublicKey, ED25519};

use crate::sign::{content_digest, PROVIDER_COMPONENTS, PROVIDER_TAG};

/// How far `created` may be from the receiver's clock, either way.
pub const MAX_AGE_SECS: i64 = 30;

/// Why a pushed request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushRefusal {
    /// A header is missing or does not parse.
    Malformed(&'static str),
    /// `Content-Digest` is not the body's.
    Digest,
    /// Not the components, tag, key id or sender a hub's push is signed with.
    Profile(&'static str),
    /// `created` is outside the window.
    Stale,
    /// The nonce was seen before.
    Replayed,
    /// The signature does not verify.
    Signature,
}

impl std::fmt::Display for PushRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PushRefusal {}

/// The receiver's check, for the hub key published under `keyid` for `domain`. It keeps the nonces of the window.
pub struct PushVerifier {
    key: [u8; 32],
    keyid: String,
    from: String,
    seen: Mutex<HashMap<String, i64>>,
}

impl PushVerifier {
    pub fn new(public_key: [u8; 32], keyid: &str, domain: &str) -> Self {
        Self {
            key: public_key,
            keyid: keyid.to_string(),
            from: format!("mimi@{}", domain.to_ascii_lowercase()),
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Accept a `POST` of `body` to `target_uri` (the full `https://host[:port]/path` the hub addressed), whose headers
    /// `header` reads by lowercase name, at `now` (Unix seconds); or say why not. A nonce that verifies is remembered.
    pub fn verify(
        &self,
        target_uri: &str,
        header: impl Fn(&str) -> Option<String>,
        body: &[u8],
        now: i64,
    ) -> Result<(), PushRefusal> {
        let get = |name: &'static str| header(name).ok_or(PushRefusal::Malformed(name));
        let digest = get("content-digest")?;
        if digest != content_digest(body) {
            return Err(PushRefusal::Digest);
        }
        let from = get("from")?;
        if !from.eq_ignore_ascii_case(&self.from) {
            return Err(PushRefusal::Profile("from"));
        }
        let input = get("signature-input")?;
        let (label, params) = input
            .split_once('=')
            .ok_or(PushRefusal::Malformed("signature-input"))?;
        let signature = get("signature")?;
        let signature = signature
            .strip_prefix(label)
            .and_then(|rest| rest.strip_prefix("=:"))
            .and_then(|rest| rest.strip_suffix(':'))
            .and_then(|value| STANDARD.decode(value).ok())
            .ok_or(PushRefusal::Malformed("signature"))?;
        let (components, rest) = params
            .strip_prefix('(')
            .and_then(|p| p.split_once(')'))
            .ok_or(PushRefusal::Malformed("signature-input"))?;
        let expected = PROVIDER_COMPONENTS
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(" ");
        if components != expected {
            return Err(PushRefusal::Profile("components"));
        }
        let (mut created, mut nonce, mut keyid, mut tag) = (None, None, None, None);
        for param in rest.split(';').filter(|p| !p.is_empty()) {
            let (name, value) = param
                .split_once('=')
                .ok_or(PushRefusal::Malformed("signature-input"))?;
            let unquoted = value.trim_matches('"').to_string();
            match name {
                "created" => created = value.parse::<i64>().ok(),
                "nonce" => nonce = Some(unquoted),
                "keyid" => keyid = Some(unquoted),
                "tag" => tag = Some(unquoted),
                "alg" | "expires" => {}
                _ => return Err(PushRefusal::Malformed("signature-input")),
            }
        }
        if tag.as_deref() != Some(PROVIDER_TAG) {
            return Err(PushRefusal::Profile("tag"));
        }
        if keyid.as_deref() != Some(self.keyid.as_str()) {
            return Err(PushRefusal::Profile("keyid"));
        }
        let created = created.ok_or(PushRefusal::Malformed("created"))?;
        if (now - created).abs() > MAX_AGE_SECS {
            return Err(PushRefusal::Stale);
        }
        let nonce = nonce.ok_or(PushRefusal::Malformed("nonce"))?;
        let base = format!(
            "\"@method\": POST\n\"@target-uri\": {target_uri}\n\"content-digest\": {digest}\n\"from\": {from}\n\"@signature-params\": {params}"
        );
        UnparsedPublicKey::new(&ED25519, &self.key)
            .verify(base.as_bytes(), &signature)
            .map_err(|_| PushRefusal::Signature)?;
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, at| (now - *at).abs() <= MAX_AGE_SECS * 2);
        if seen.insert(nonce, now).is_some() {
            return Err(PushRefusal::Replayed);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "push_tests.rs"]
mod tests;
