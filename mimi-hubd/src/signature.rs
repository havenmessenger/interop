//! Requests authenticated by a DNS-published key (draft-atwood-mimi-provider-auth §5).
//!
//! A source provider signs a request with HTTP Message Signatures (RFC 9421). The signature covers `@method`,
//! `@target-uri` and `from`, and `content-digest` when the request has content (RFC 9530, `sha-256`); it carries
//! `created` and `keyid`, and `tag="mimi"` names it among others. Its key is the Ed25519 key published in a TXT record at
//! `<keyid>._mimi.<source domain>`, the source domain being the one the `From` header names (§5.3).
//!
//! The hub does not query DNS itself: the keys come from a file ([`PeerKeys`]) that a job on the hub's host keeps current
//! from a DNSSEC-validating resolver, the record's TTL being the cache bound §5.3 allows. A key the file does not hold,
//! or holds empty (revoked), verifies nothing.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::peer::provider_of_from_header;

/// How far in the past and the future `created` may be (§5.3 step 4).
pub const MAX_AGE_SECS: i64 = 300;
pub const MAX_SKEW_SECS: i64 = 60;

/// Why a signature did not authenticate a request. Read in the hub's log only; the peer is told no more than 403.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    NoSignature,
    Malformed(&'static str),
    MissingComponent(&'static str),
    UnsupportedComponent(String),
    Expired,
    NotYetValid,
    NoFrom,
    DigestMismatch,
    UnknownKey(String),
    BadSignature,
    /// The same key already used this nonce within the window.
    Replayed,
    /// A keyMaterial request with no nonce, where the hub's policy requires one.
    NoNonce,
}

/// The request facts a signature is checked against.
pub struct SignedRequest<'a> {
    pub method: &'a str,
    pub target_uri: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub header: &'a dyn Fn(&str) -> Option<String>,
    pub body: &'a [u8],
}

/// The keys this hub accepts signatures from, by `<keyid>._mimi.<domain>`, as the host job last wrote them.
pub struct PeerKeys {
    path: Option<PathBuf>,
    cache: Mutex<Option<(SystemTime, HashMap<String, String>)>>,
}

impl PeerKeys {
    /// Keys from the JSON file at `path` (an object of record name to base64 public key, empty for revoked), re-read
    /// whenever the file changes. With no path, no key is known and no signature verifies.
    pub fn from_file(path: Option<PathBuf>) -> Self {
        Self {
            path,
            cache: Mutex::new(None),
        }
    }

    /// The 32-byte Ed25519 public key published for `keyid` under `domain`, if the file holds a usable one.
    pub fn key(&self, keyid: &str, domain: &str) -> Option<Vec<u8>> {
        let path = self.path.as_ref()?;
        let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
        let mut cache = self.cache.lock().ok()?;
        if cache.as_ref().map(|(at, _)| *at) != Some(modified) {
            let text = std::fs::read_to_string(path).ok()?;
            let keys: HashMap<String, String> = serde_json::from_str(&text).ok()?;
            *cache = Some((modified, keys));
        }
        let name = format!("{keyid}._mimi.{}", domain.to_ascii_lowercase());
        let value = cache.as_ref()?.1.get(&name)?;
        let key = STANDARD.decode(value.trim()).ok()?;
        (key.len() == 32).then_some(key)
    }
}

/// What a valid signature says: the provider domain it authenticates, and the key, nonce and time it was made with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub domain: String,
    pub keyid: String,
    pub nonce: Option<String>,
    pub created: i64,
}

/// The provider domain a valid signature on `request` authenticates, or why it authenticates none.
pub fn verify(
    request: &SignedRequest<'_>,
    now: SystemTime,
    keys: &PeerKeys,
) -> Result<String, Refusal> {
    verify_signed(request, now, keys).map(|verified| verified.domain)
}

/// As [`verify`], with the signature's key, nonce and time.
pub fn verify_signed(
    request: &SignedRequest<'_>,
    now: SystemTime,
    keys: &PeerKeys,
) -> Result<Verified, Refusal> {
    let input = (request.header)("signature-input").ok_or(Refusal::NoSignature)?;
    let signatures = (request.header)("signature").ok_or(Refusal::NoSignature)?;
    let members = parse_signature_input(&input)?;
    let has_body = !request.body.is_empty();
    let required: &[&str] = if has_body {
        &["@method", "@target-uri", "from", "content-digest"]
    } else {
        &["@method", "@target-uri", "from"]
    };
    let covers = |m: &InputMember| required.iter().all(|c| m.components.iter().any(|x| x == c));
    let member = members
        .iter()
        .find(|m| m.param("tag").as_deref() == Some("mimi"))
        .or_else(|| members.iter().find(|m| covers(m)))
        .ok_or(Refusal::MissingComponent("a signature tagged mimi"))?;
    for component in required {
        if !member.components.iter().any(|c| c == component) {
            return Err(Refusal::MissingComponent(component));
        }
    }
    if let Some(alg) = member.param("alg") {
        if alg != "ed25519" {
            return Err(Refusal::Malformed("alg is not ed25519"));
        }
    }
    let keyid = member
        .param("keyid")
        .ok_or(Refusal::Malformed("no keyid"))?;
    let created: i64 = member
        .param("created")
        .and_then(|c| c.parse().ok())
        .ok_or(Refusal::Malformed("no created"))?;
    let now = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if created < now - MAX_AGE_SECS {
        return Err(Refusal::Expired);
    }
    if created > now + MAX_SKEW_SECS {
        return Err(Refusal::NotYetValid);
    }
    if let Some(expires) = member.param("expires").and_then(|e| e.parse::<i64>().ok()) {
        if now > expires {
            return Err(Refusal::Expired);
        }
    }
    let from = (request.header)("from").ok_or(Refusal::NoFrom)?;
    let domain = provider_of_from_header(from.trim()).ok_or(Refusal::NoFrom)?;
    if has_body || member.components.iter().any(|c| c == "content-digest") {
        let digest = (request.header)("content-digest").ok_or(Refusal::DigestMismatch)?;
        if !digest_matches(&digest, request.body) {
            return Err(Refusal::DigestMismatch);
        }
    }
    let signature = signature_for(&signatures, &member.label)?;
    let base = signature_base(request, member)?;
    let key = keys
        .key(&keyid, &domain)
        .ok_or_else(|| Refusal::UnknownKey(format!("{keyid}._mimi.{domain}")))?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key)
        .verify(base.as_bytes(), &signature)
        .map_err(|_| Refusal::BadSignature)?;
    Ok(Verified {
        domain,
        keyid,
        nonce: member.param("nonce"),
        created,
    })
}

/// The longest nonce kept; a longer one is refused rather than stored.
pub const MAX_NONCE_LEN: usize = 128;

/// The nonces of signatures that verified, each until its `created` time leaves the window ([`MAX_AGE_SECS`]): a second
/// use by the same key within the window is a replay (draft-atwood-mimi-provider-auth §13.2; a keyMaterial answer hands
/// out a KeyPackage). Kept in memory, so a restart forgets at most one window. Entries leave by time, not by count.
#[derive(Default)]
pub struct NonceLedger {
    seen: Mutex<HashMap<(String, String, String), i64>>,
}

impl NonceLedger {
    /// Record `verified`'s nonce at `now` (seconds). `Err` when the same key already used it within the window, or it is
    /// too long. A signature with no nonce records nothing.
    pub fn record(&self, verified: &Verified, now: i64) -> Result<(), Refusal> {
        let Some(nonce) = &verified.nonce else {
            return Ok(());
        };
        if nonce.len() > MAX_NONCE_LEN {
            return Err(Refusal::Malformed("nonce too long"));
        }
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        seen.retain(|_, expires| *expires >= now);
        let key = (
            verified.domain.clone(),
            verified.keyid.clone(),
            nonce.clone(),
        );
        if seen.contains_key(&key) {
            return Err(Refusal::Replayed);
        }
        seen.insert(key, verified.created.saturating_add(MAX_AGE_SECS));
        Ok(())
    }
}

/// One member of a `Signature-Input` dictionary: its label, covered components, parameters, and its serialized value
/// (what `@signature-params` signs).
#[derive(Debug)]
struct InputMember {
    label: String,
    components: Vec<String>,
    params: Vec<(String, String)>,
    serialized: String,
}

impl InputMember {
    fn param(&self, name: &str) -> Option<String> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

/// Splits a structured-field dictionary into its members, at commas outside parentheses and quoted strings.
fn split_members(value: &str) -> Vec<&str> {
    let (mut out, mut depth, mut quoted, mut escaped, mut start) =
        (Vec::new(), 0i32, false, false, 0);
    for (i, ch) in value.char_indices() {
        match ch {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth -= 1,
            ',' if !quoted && depth == 0 => {
                out.push(value[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(value[start..].trim());
    out.into_iter().filter(|m| !m.is_empty()).collect()
}

fn unquote(text: &str) -> Option<String> {
    let inner = text.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => out.push(chars.next()?),
            '"' => return None,
            _ => out.push(ch),
        }
    }
    Some(out)
}

fn parse_signature_input(value: &str) -> Result<Vec<InputMember>, Refusal> {
    let mut members = Vec::new();
    for member in split_members(value) {
        let (label, rest) = member
            .split_once('=')
            .ok_or(Refusal::Malformed("signature-input member"))?;
        let rest = rest.trim();
        let close = rest
            .strip_prefix('(')
            .and_then(|r| r.find(')'))
            .ok_or(Refusal::Malformed("signature-input inner list"))?;
        let inner = &rest[1..=close];
        let components = inner
            .split_whitespace()
            .map(|c| unquote(c).ok_or(Refusal::Malformed("component identifier")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut params = Vec::new();
        for param in rest[close + 2..]
            .split(';')
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            let (key, raw) = param.split_once('=').unwrap_or((param, "?1"));
            let value = if raw.starts_with('"') {
                unquote(raw).ok_or(Refusal::Malformed("parameter string"))?
            } else {
                raw.to_string()
            };
            params.push((key.trim().to_string(), value));
        }
        members.push(InputMember {
            label: label.trim().to_string(),
            components,
            params,
            serialized: rest.to_string(),
        });
    }
    Ok(members)
}

/// The signature bytes the `Signature` dictionary holds under `label` (`label=:base64:`).
fn signature_for(value: &str, label: &str) -> Result<Vec<u8>, Refusal> {
    for member in split_members(value) {
        if let Some((l, v)) = member.split_once('=') {
            if l.trim() == label {
                let b64 = v
                    .trim()
                    .strip_prefix(':')
                    .and_then(|v| v.strip_suffix(':'))
                    .ok_or(Refusal::Malformed("signature byte sequence"))?;
                return STANDARD
                    .decode(b64)
                    .map_err(|_| Refusal::Malformed("signature base64"));
            }
        }
    }
    Err(Refusal::NoSignature)
}

/// True when a `Content-Digest` dictionary has a `sha-256` member equal to the body's digest.
fn digest_matches(value: &str, body: &[u8]) -> bool {
    let want = STANDARD.encode(Sha256::digest(body));
    split_members(value).into_iter().any(|member| {
        member
            .split_once('=')
            .filter(|(alg, _)| alg.trim() == "sha-256")
            .and_then(|(_, v)| v.trim().strip_prefix(':').and_then(|v| v.strip_suffix(':')))
            == Some(want.as_str())
    })
}

/// The RFC 9421 §2.5 signature base for `member` over `request`.
fn signature_base(request: &SignedRequest<'_>, member: &InputMember) -> Result<String, Refusal> {
    let mut lines = Vec::with_capacity(member.components.len() + 1);
    for component in &member.components {
        let value = match component.as_str() {
            "@method" => request.method.to_ascii_uppercase(),
            "@target-uri" => request.target_uri.to_string(),
            "@authority" => request.authority.to_ascii_lowercase(),
            "@path" => request.path.to_string(),
            "@query" => format!("?{}", request.query.unwrap_or("")),
            name if name.starts_with('@') => {
                return Err(Refusal::UnsupportedComponent(name.to_string()))
            }
            name => {
                (request.header)(name).ok_or(Refusal::MissingComponent("a covered header field"))?
            }
        };
        lines.push(format!("\"{component}\": {}", value.trim()));
    }
    lines.push(format!("\"@signature-params\": {}", member.serialized));
    Ok(lines.join("\n"))
}

#[cfg(test)]
#[path = "signature_tests.rs"]
mod tests;
