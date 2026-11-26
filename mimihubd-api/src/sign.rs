//! The signatures the lane takes and makes (RFC 9421, Ed25519, with `Content-Digest` per RFC 9530 on every request,
//! an empty body included).
//!
//! | Profile | Tag | Covers | Signed by |
//! |---|---|---|---|
//! | A user's lane request | `mimi-client-lane` | `@method` `@target-uri` `content-digest` `mimi-client-user` `mimi-client-device` | the provider's server, with a lane key |
//! | The provider server's own lane request | `mimi-client-lane-provider` | `@method` `@target-uri` `content-digest` | the provider's server, with a lane key |
//! | A provider's request | `mimi` | `@method` `@target-uri` `content-digest` `from` | the provider, with its DNS-published key (draft-atwood-mimi-provider-auth §5); a hub signs a push this way |
//!
//! Each carries `created`, a `nonce` and the `keyid`. The two lane profiles have tags of their own, so a signature for
//! a user is never taken for one the server made for itself, nor the other way round.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

/// A user's lane request: its tag and the components it covers, in order.
pub const LANE_USER_TAG: &str = "mimi-client-lane";
pub const LANE_USER_COMPONENTS: &[&str] = &[
    "@method",
    "@target-uri",
    "content-digest",
    "mimi-client-user",
    "mimi-client-device",
];

/// The provider server's own lane request: its tag and the components it covers, in order.
pub const LANE_PROVIDER_TAG: &str = "mimi-client-lane-provider";
pub const LANE_PROVIDER_COMPONENTS: &[&str] = &["@method", "@target-uri", "content-digest"];

/// A provider's own request (and a hub's push): its tag and the components it covers, in order.
pub const PROVIDER_TAG: &str = "mimi";
pub const PROVIDER_COMPONENTS: &[&str] = &["@method", "@target-uri", "content-digest", "from"];

/// The `Content-Digest` value for `body`.
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

/// A fresh nonce: 16 random bytes, base64url.
pub fn fresh_nonce() -> Result<String, KeyError> {
    let mut nonce = [0u8; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| KeyError::NoRandomness)?;
    Ok(URL_SAFE_NO_PAD.encode(nonce))
}

/// Why a key could not be made or used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The seed is not 32 bytes, or not a usable Ed25519 seed.
    Seed,
    /// The key id is empty, or not letters, digits, `-` and `_`.
    KeyId,
    /// The system gave no random bytes for a nonce.
    NoRandomness,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Seed => "a signing key seed is 32 usable bytes",
            Self::KeyId => "a key id is letters, digits, '-' and '_'",
            Self::NoRandomness => "no random bytes for a signature nonce",
        })
    }
}

impl std::error::Error for KeyError {}

/// Who a lane request acts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acting {
    /// One of the provider's users (a user URI on its domain), from the device it names.
    User { user: String, device: String },
    /// The provider's server itself.
    Provider,
}

/// The headers a signed request carries, as (lowercase name, value), `content-digest` first.
pub type Headers = Vec<(&'static str, String)>;

/// An Ed25519 signing key and the key id its signatures name.
pub struct SigningKey {
    key: Ed25519KeyPair,
    keyid: String,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("keyid", &self.keyid)
            .field("public_key", &STANDARD.encode(self.public_key()))
            .finish()
    }
}

impl SigningKey {
    /// A key from a 32-byte Ed25519 seed, whose signatures name `keyid`.
    pub fn from_seed(seed: &[u8], keyid: &str) -> Result<Self, KeyError> {
        if seed.len() != 32 {
            return Err(KeyError::Seed);
        }
        if keyid.is_empty()
            || !keyid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(KeyError::KeyId);
        }
        let key = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| KeyError::Seed)?;
        Ok(Self {
            key,
            keyid: keyid.to_string(),
        })
    }

    pub fn keyid(&self) -> &str {
        &self.keyid
    }

    /// The public key, raw.
    pub fn public_key(&self) -> [u8; 32] {
        let mut public = [0u8; 32];
        public.copy_from_slice(self.key.public_key().as_ref());
        public
    }

    /// Sign one request: `components` (the derived ones and header names, in order) with their `values`, under
    /// `label` and `tag`.
    fn sign_components(
        &self,
        label: &str,
        tag: &str,
        components: &[&str],
        values: &[&str],
        created: u64,
        nonce: Option<&str>,
    ) -> (String, String) {
        let list = components
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(" ");
        let mut params = format!("({list});created={created}");
        if let Some(nonce) = nonce {
            params.push_str(&format!(";nonce=\"{nonce}\""));
        }
        params.push_str(&format!(";keyid=\"{}\";tag=\"{tag}\"", self.keyid));
        let mut base = String::new();
        for (component, value) in components.iter().zip(values) {
            base.push_str(&format!("\"{component}\": {value}\n"));
        }
        base.push_str(&format!("\"@signature-params\": {params}"));
        let signature = STANDARD.encode(self.key.sign(base.as_bytes()).as_ref());
        (
            format!("{label}={params}"),
            format!("{label}=:{signature}:"),
        )
    }

    /// The headers for a lane `POST` of `body` to `target_uri` (`https://host[:port]/mimi/client/v1/<route>`, as the
    /// hub sees it addressed), acting as `acting`, signed at `created` with `nonce`.
    pub fn sign_lane(
        &self,
        target_uri: &str,
        body: &[u8],
        acting: &Acting,
        created: u64,
        nonce: &str,
    ) -> Headers {
        let digest = content_digest(body);
        let (input, signature) = match acting {
            Acting::User { user, device } => self.sign_components(
                "lane",
                LANE_USER_TAG,
                LANE_USER_COMPONENTS,
                &["POST", target_uri, &digest, user, device],
                created,
                Some(nonce),
            ),
            Acting::Provider => self.sign_components(
                "lane",
                LANE_PROVIDER_TAG,
                LANE_PROVIDER_COMPONENTS,
                &["POST", target_uri, &digest],
                created,
                Some(nonce),
            ),
        };
        let mut headers: Headers = vec![("content-digest", digest)];
        if let Acting::User { user, device } = acting {
            headers.push(("mimi-client-user", user.clone()));
            headers.push(("mimi-client-device", device.clone()));
        }
        headers.push(("signature-input", input));
        headers.push(("signature", signature));
        headers
    }

    /// The headers for a provider's request (`method` to `target_uri`, `From: from`, `body`), signed at `created`, with
    /// `nonce` or none: how a provider signs its requests to peers, and how a hub signs a push.
    pub fn sign_provider(
        &self,
        method: &str,
        target_uri: &str,
        from: &str,
        body: &[u8],
        created: u64,
        nonce: Option<&str>,
    ) -> Headers {
        let digest = content_digest(body);
        let method = method.to_ascii_uppercase();
        let (input, signature) = self.sign_components(
            "mimi",
            PROVIDER_TAG,
            PROVIDER_COMPONENTS,
            &[&method, target_uri, &digest, from],
            created,
            nonce,
        );
        vec![
            ("content-digest", digest),
            ("signature-input", input),
            ("signature", signature),
        ]
    }
}

#[cfg(test)]
#[path = "sign_tests.rs"]
mod tests;
