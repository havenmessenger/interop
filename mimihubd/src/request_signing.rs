//! Signing the hub's own requests with the key its provider publishes in DNS (draft-atwood-mimi-provider-auth §5), the
//! way the receiving side (`signature.rs`) and mimid check them.
//!
//! The signature (RFC 9421, label `mimi`, `tag="mimi"`) covers `@method`, `@target-uri`, `content-digest` and `from`,
//! with `Content-Digest` (RFC 9530, `sha-256`) sent on every request, an empty body included. Its parameters are
//! `created`, a `nonce` of 16 random bytes (base64url) so a replayed request is refused by a receiver that keeps them
//! (§13.2: a keyMaterial answer hands out a KeyPackage), `keyid` (the selector) and `tag`. The key is Ed25519, from a
//! 32-byte seed in a file the operator names (base64); its public half is the
//! `v=MIMI1; k=ed25519; p=...` TXT record at `<selector>._mimi.<provider domain>`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// The components a signature covers, in order.
pub const SIGNED_COMPONENTS: &[&str] = mimihubd_api::sign::PROVIDER_COMPONENTS;

/// The headers a signature adds to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHeaders {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
}

/// The hub's request signer: the provider profile of `mimihubd_api::sign`, with the key read from the operator's file.
pub struct RequestSigner {
    key: mimihubd_api::sign::SigningKey,
}

impl std::fmt::Debug for RequestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSigner")
            .field("keyid", &self.keyid())
            .field("public_key", &self.public_key_b64())
            .finish()
    }
}

impl RequestSigner {
    /// A signer from a 32-byte Ed25519 seed, whose signatures name `keyid`.
    pub fn from_seed(seed: &[u8], keyid: &str) -> anyhow::Result<Self> {
        if seed.len() != 32 {
            anyhow::bail!("a signing key seed is 32 bytes, not {}", seed.len());
        }
        let key =
            mimihubd_api::sign::SigningKey::from_seed(seed, keyid).map_err(
                |error| match error {
                    mimihubd_api::sign::KeyError::KeyId => {
                        anyhow::anyhow!("the signing selector {keyid:?} is not a DNS label")
                    }
                    other => anyhow::anyhow!("the signing key seed is not usable: {other}"),
                },
            )?;
        Ok(Self { key })
    }

    /// A signer from the file at `path`, which holds the seed in base64.
    pub fn from_file(path: &std::path::Path, keyid: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", path.display()))?;
        let seed = STANDARD
            .decode(text.trim())
            .map_err(|_| anyhow::anyhow!("{} does not hold a base64 seed", path.display()))?;
        Self::from_seed(&seed, keyid)
    }

    pub fn keyid(&self) -> &str {
        self.key.keyid()
    }

    /// The public key, base64, as the TXT record carries it.
    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.key.public_key())
    }

    /// The TXT record value for `<keyid>._mimi.<provider domain>`.
    pub fn dns_record(&self) -> String {
        format!("v=MIMI1; k=ed25519; p={}", self.public_key_b64())
    }

    /// Sign a request now, with a fresh nonce.
    pub fn sign(
        &self,
        method: &str,
        target_uri: &str,
        from: &str,
        body: &[u8],
    ) -> anyhow::Result<SignatureHeaders> {
        let nonce = mimihubd_api::sign::fresh_nonce()
            .map_err(|_| anyhow::anyhow!("no random bytes for the signature nonce"))?;
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        Ok(self.sign_with(method, target_uri, from, body, created, Some(&nonce)))
    }

    /// Sign a request at `created`, with `nonce` or none (a published example has none).
    pub fn sign_with(
        &self,
        method: &str,
        target_uri: &str,
        from: &str,
        body: &[u8],
        created: u64,
        nonce: Option<&str>,
    ) -> SignatureHeaders {
        let headers = self
            .key
            .sign_provider(method, target_uri, from, body, created, nonce);
        let get = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        SignatureHeaders {
            content_digest: get("content-digest"),
            signature_input: get("signature-input"),
            signature: get("signature"),
        }
    }
}

#[cfg(test)]
#[path = "request_signing_tests.rs"]
mod tests;
