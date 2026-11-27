//! The one place the hub reads a user from an MLS credential.
//!
//! The hub binds each member's leaf to a user URI, to check a Commit's participant-list change against the clients it
//! adds and removes (protocol-07 §7.5) and to know which provider a member's client belongs to. RFC 9420 leaves how a
//! credential names a user to the application, so this module decides it, credential type by credential type, and no
//! other module reads a credential's content. A credential type this hub cannot read names no user: it is refused
//! wherever the hub must know the user, and it is never read as if it were another type.
//!
//! Read today:
//!
//! - a Basic credential, whose identity is the user's URI;
//! - a `did_webvh` credential (draft-atwood-mls-didwebvh-credential), whose log is verified and bound to the leaf's
//!   signature key (§Binding to the LeafNode) by the `mls-didwebvh` crate, and whose user URI is the one `mimi:` entry
//!   of its head DID document's `alsoKnownAs`, as the reference implementation reads it (DIV-24). The draft makes the
//!   log's SCID the credential's identity and says nothing of a MIMI URI; and it lets the DID move to another domain
//!   ("The DID string can change if the controller moves the DID, but the SCID cannot"), so the DID's domain is not
//!   compared with the URI's provider.
//!
//! A credential is read together with the signature key of the leaf that carries it, because a `did_webvh` credential
//! names its user only for a key its log authorizes.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use mls_didwebvh::{CodePoints, DidWebvhCredential, VerifiedLog};
use openmls::prelude::{Credential, CredentialType, ExternalSender};
use sha2::{Digest, Sha256};

/// The `did_webvh` credential type and record component this hub reads: the `mls-didwebvh` crate's defaults, the values
/// the reference implementation uses (DIV-24).
pub(crate) const DID_WEBVH: CodePoints = CodePoints::DEFAULT;

/// Whether this hub reads credentials of `credential`'s type at all: one it does not read names no user, whatever it
/// carries.
pub(crate) fn is_read(credential: &Credential) -> bool {
    kind(credential).is_some()
}

/// The credential types this hub reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Basic,
    DidWebvh,
}

fn kind(credential: &Credential) -> Option<Kind> {
    match credential.credential_type() {
        CredentialType::Basic => Some(Kind::Basic),
        CredentialType::Other(code) if code == DID_WEBVH.credential_type() => Some(Kind::DidWebvh),
        _ => None,
    }
}

/// The user URI `credential` names for the leaf whose signature key is `signature_key`, as it states it: a Basic
/// credential's identity, when it is UTF-8; a `did_webvh` credential's one `mimi:` `alsoKnownAs` entry, when its log
/// verifies and authorizes `signature_key`. `None` for every other credential type, so the bytes of a credential of
/// another type are never read as a URI.
pub(crate) fn stated_uri(credential: &Credential, signature_key: &[u8]) -> Option<String> {
    match kind(credential)? {
        Kind::Basic => std::str::from_utf8(credential.serialized_content())
            .ok()
            .map(str::to_owned),
        Kind::DidWebvh => {
            let log = verified_log(credential, signature_key)?;
            mimi_user_uri(&log).map(str::to_owned)
        }
    }
}

/// The user `credential` names, in canonical form (`mimi_core::uri::canonical`): [`stated_uri`], canonicalized.
pub(crate) fn user_uri(credential: &Credential, signature_key: &[u8]) -> Option<String> {
    stated_uri(credential, signature_key).map(|uri| mimi_core::uri::canonical(&uri))
}

/// Whether a client's leaf may carry `new` in place of `old` (RFC 9420 §5.3.1, "valid as a successor ... according to
/// the application's policy"), each with its leaf's signature key: both are of the same type this hub reads, and name
/// the same user.
///
/// - Basic: the same identity bytes, exactly, as the group's clients require.
/// - `did_webvh`: the same SCID with the old log a prefix of the new (§Successor Credentials), the new log authorizing
///   the new key, and the same `mimi:` URI, so a renewed leaf cannot rebind its client to another user.
///
/// The `mimi:` URI condition is stricter than the credential's own successor rule, on purpose, and it is a MIMI rule,
/// not a credential rule. The participant list is keyed by user URI, and protocol-07 §7.5 has every client of a user
/// carry that user's identifier: "In a room that has multiple MLS clients per "user", the identifier for each user in
/// participants.user is the same across all that user's clients in the room." A leaf whose URI changes while its list
/// entry stays breaks that for every member of the room, whatever its credential library says. So a renamed user
/// (same SCID, new URI) is not a successor here: it leaves the room and joins again under its new URI. Do not relax
/// this to `mls_didwebvh::rules::is_valid_successor` alone.
pub(crate) fn is_successor(old: (&Credential, &[u8]), new: (&Credential, &[u8])) -> bool {
    match (kind(old.0), kind(new.0)) {
        (Some(Kind::Basic), Some(Kind::Basic)) => {
            old.0.serialized_content() == new.0.serialized_content()
        }
        (Some(Kind::DidWebvh), Some(Kind::DidWebvh)) => {
            let (Some(before), Some(after)) =
                (verified_log(old.0, old.1), verified_log(new.0, new.1))
            else {
                return false;
            };
            mls_didwebvh::rules::is_valid_successor(&before, &after)
                && mimi_user_uri(&before).is_some()
                && mimi_user_uri(&before) == mimi_user_uri(&after)
        }
        _ => false,
    }
}

/// Whether `credential` is of the `did_webvh` type this hub reads.
pub(crate) fn is_did_webvh(credential: &Credential) -> bool {
    kind(credential) == Some(Kind::DidWebvh)
}

/// The credential of an `external_senders` entry (RFC 9420 §12.1.8.1: `SignaturePublicKey signature_key; Credential
/// credential;`), read from its encoding, since the MLS library does not expose it.
pub(crate) fn external_sender_credential(sender: &ExternalSender) -> Option<Credential> {
    use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _, VLBytes};
    let bytes = sender.tls_serialize_detached().ok()?;
    let mut rest = bytes.as_slice();
    VLBytes::tls_deserialize(&mut rest).ok()?;
    Credential::tls_deserialize_exact(rest).ok()
}

/// A `did_webvh` credential's verified log, when its log verifies (§Log Verification) and authorizes `signature_key`
/// (§Binding to the LeafNode). Binding is checked on every call; the verification itself is remembered (see
/// [`VerifiedLogs`]).
pub(crate) fn verified_log(
    credential: &Credential,
    signature_key: &[u8],
) -> Option<Arc<VerifiedLog>> {
    if kind(credential)? != Kind::DidWebvh {
        return None;
    }
    let log = VerifiedLogs::global().verify(credential.serialized_content())?;
    mls_didwebvh::rules::check_binding(signature_key, &log).ok()?;
    Some(log)
}

/// The MIMI user URI a verified log names: the one entry of its head DID document's `alsoKnownAs` whose scheme is
/// `mimi` (ASCII case-insensitive), or `None` if there is none or more than one. This is the reference implementation's
/// reading (mimid's `mimi_user_uri`), kept exactly, so the hub and the members using that implementation bind the same
/// leaf to the same user.
pub(crate) fn mimi_user_uri(log: &VerifiedLog) -> Option<&str> {
    let is_mimi = |entry: &&str| {
        entry
            .get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("mimi:"))
    };
    let mut entries = log.head_also_known_as().into_iter();
    let first = entries.by_ref().find(is_mimi)?;
    entries.find(is_mimi).is_none().then_some(first)
}

/// The most credential bytes whose verified logs are remembered at once. A log is at most 1 MiB (the draft's limit),
/// and its verified form holds at most its head DID document.
// LIMIT-REASON: memory: bounds what the verification memo holds; a log past it is verified again when next read
const MAX_REMEMBERED_BYTES: usize = 64 * 1024 * 1024;

/// The most verified logs remembered at once, whatever their size.
// LIMIT-REASON: memory: bounds the memo's entry count for many small logs
const MAX_REMEMBERED_LOGS: usize = 4096;

/// Verified `did_webvh` logs by the SHA-256 of the credential that carried them, oldest first out. Verifying a log means
/// parsing every entry and checking a signature on each, and the hub reads every member's credential on every Commit,
/// so a credential is verified once and its outcome reused. The outcome depends on the credential's bytes alone (the
/// draft's verification reads no clock and fetches nothing), so remembering it changes no answer.
pub(crate) struct VerifiedLogs {
    inner: Mutex<Remembered>,
    max_bytes: usize,
    max_logs: usize,
}

#[derive(Default)]
struct Remembered {
    logs: HashMap<[u8; 32], (Option<Arc<VerifiedLog>>, usize)>,
    order: VecDeque<[u8; 32]>,
    bytes: usize,
}

impl VerifiedLogs {
    fn global() -> &'static Self {
        static LOGS: OnceLock<VerifiedLogs> = OnceLock::new();
        LOGS.get_or_init(|| Self::with_limits(MAX_REMEMBERED_BYTES, MAX_REMEMBERED_LOGS))
    }

    fn with_limits(max_bytes: usize, max_logs: usize) -> Self {
        Self {
            inner: Mutex::new(Remembered::default()),
            max_bytes,
            max_logs,
        }
    }

    /// How many outcomes are remembered.
    #[cfg(test)]
    fn remembered(&self) -> usize {
        self.lock().order.len()
    }

    /// The verified log of the `did_webvh` credential whose content (the TLS-encoded `DIDWebVHCredential`) is
    /// `content`, or `None` when it does not decode or verify.
    fn verify(&self, content: &[u8]) -> Option<Arc<VerifiedLog>> {
        let digest: [u8; 32] = Sha256::digest(content).into();
        if let Some((outcome, _)) = self.lock().logs.get(&digest) {
            return outcome.clone();
        }
        let outcome = DidWebvhCredential::decode(content)
            .ok()
            .and_then(|credential| mls_didwebvh::verify_credential(&credential).ok())
            .map(Arc::new);
        let mut remembered = self.lock();
        if !remembered.logs.contains_key(&digest) {
            remembered.bytes += content.len();
            remembered.order.push_back(digest);
            remembered
                .logs
                .insert(digest, (outcome.clone(), content.len()));
            while remembered.bytes > self.max_bytes || remembered.order.len() > self.max_logs {
                let Some(oldest) = remembered.order.pop_front() else {
                    break;
                };
                if let Some((_, size)) = remembered.logs.remove(&oldest) {
                    remembered.bytes -= size;
                }
            }
        }
        outcome
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Remembered> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod tests;
