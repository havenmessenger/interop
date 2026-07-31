//! content-09 §4.4 ExternalPart: constructing and consuming out-of-band attachment references.
//!
//! An ExternalPart is a *reference*, not content. The bytes live somewhere the recipient can fetch;
//! the message carries `url`, the AEAD parameters, an integrity hash and a size. The codec for the
//! reference lives in [`crate::content`]; this module is the layer that MAKES a valid reference from
//! a blob and READS one back.
//!
//! The design content-09 gets right, and the reason this layer is small: the blob is encrypted
//! out-of-band under its OWN key, and that key travels inside the end-to-end encrypted message as
//! part of the reference. Whatever stores the bytes is therefore blind by construction, the payload
//! never enters the messaging path, and any member holding the message can fetch and decrypt.
//!
//! # No cryptography lives here
//!
//! The caller supplies the AEAD ([`Aead`]) and the hash ([`Digest`]). This crate performs neither,
//! depends on no cryptographic crate, and never mints a key. Two consequences an implementor owes:
//!
//! - **The traits cannot force authenticated encryption.** An [`Aead`] implementation that does not
//!   authenticate silently voids the confidentiality and integrity this module's callers assume. The
//!   guarantee is the implementor's, not this crate's.
//! - **Algorithm selection is the caller's.** `enc_alg` and `hash_alg` are parameters and are never
//!   chosen here. Choosing an AEAD is a ciphersuite decision and belongs in whatever seam a consumer
//!   centralises ciphersuite choice in.
//!
//! # Two orderings this module enforces structurally rather than by documenting them
//!
//! **Store before you reference.** [`seal_attachment`] yields the ciphertext to upload;
//! [`build_external_reference`] needs a `url`, which does not exist until the upload succeeded. A
//! reference to bytes that are not yet stored is therefore unreachable, not merely discouraged. It
//! matters because a dangling reference is indistinguishable, at the recipient, from content that
//! expired or content the store lost.
//!
//! **Verify before you decrypt.** [`verify_fetched`] returns a [`VerifiedCiphertext`], and
//! [`open_verified`] accepts nothing else. The token's constructor is private to this module and the
//! token borrows the buffer it verified, so a consumer cannot decrypt bytes it has not checked, and
//! cannot check one buffer and decrypt another. A consumer that decrypts first has already fed
//! attacker-chosen input to its AEAD.
//!
//! # What the hash covers
//!
//! content-09 §4.4 specifies `contentHash` as the "hash of the content at the target url", and
//! §4.5 states that private external content is encrypted before it is uploaded. What is at the url
//! is therefore the sealed object, and that is what this module hashes and what a consumer verifies.
//!
//! Stating the rule as "the bytes at the url" rather than "the ciphertext" is deliberate and is the
//! total form: the two coincide only while `enc_alg` is non-zero. The draft permits an unencrypted
//! external part (`enc_alg = 0`), which this module refuses to emit, but which a consumer can still
//! receive from a peer.

use core::fmt;

use crate::content::PartBody;

/// The AEAD a caller supplies. Key, nonce and additional authenticated data are parameters on every
/// call rather than state bound at construction.
///
/// That shape is a deliberate departure from the ecosystem convention of binding the key when the
/// cipher is built. It exists so that the parameters used to seal an object and the parameters
/// written into its reference are the SAME values: this module receives them once and both uses flow
/// from that one source. A key held inside the implementation could differ from the key placed in
/// the reference, producing a reference nothing can open, and no test here could detect it.
///
/// Method names follow the ecosystem's `encrypt`/`decrypt` vocabulary so an existing implementation
/// is a thin adapter rather than a rewrite.
pub trait Aead {
    /// What the implementation reports on failure. Displayed, never inspected.
    type Error: fmt::Display;

    /// Seal `plaintext`, returning the object to be stored: ciphertext with its authentication tag,
    /// and nothing else. The nonce is NOT prepended - it travels in the reference's own field.
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Open a sealed object. Must fail on any authentication-tag mismatch.
    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// The hash a caller supplies, used for `contentHash`. Separate from [`Aead`] so an implementor can
/// reuse an existing AEAD unchanged and supply a hash independently.
pub trait Digest {
    /// What the implementation reports on failure. Displayed, never inspected.
    type Error: fmt::Display;

    /// Hash `bytes` with the algorithm the caller declared in `hash_alg`.
    fn digest(&self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// The largest `url` this module will emit or accept. A reference is carried inside a message, so an
/// unbounded url is an unbounded message field; the bound is generous for an identifier and far below
/// anything a message should carry.
pub const MAX_URL_LEN: usize = 2048;

/// The AEAD algorithm value the draft reserves for unencrypted external content. Never emitted.
const ENC_ALG_UNENCRYPTED: u16 = 0;

/// Failures while sealing a blob or building its reference.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// `enc_alg` was zero, which the draft defines as unencrypted external content. Emitting it
    /// would place readable bytes in a store this design treats as untrusted.
    #[error("refusing to build an unencrypted external part (encAlg is zero)")]
    UnencryptedRefused,
    /// The caller supplied an empty key or nonce.
    #[error("{field} must not be empty")]
    EmptyParameter {
        /// Which parameter was empty.
        field: &'static str,
    },
    /// The `url` was empty, over [`MAX_URL_LEN`], not shaped like a URI, or carried a control
    /// character or whitespace.
    #[error("url is not a usable URI: {reason}")]
    MalformedUrl {
        /// Why the url was rejected.
        reason: &'static str,
    },
    /// A text field carried a control character. Such a value is a hazard to whatever renders or
    /// stores it and cannot be a legitimate media type, description or filename.
    #[error("{field} contains a control character")]
    ControlCharacter {
        /// Which field carried it.
        field: &'static str,
    },
    /// The caller's AEAD failed.
    #[error("aead encrypt failed: {0}")]
    Aead(String),
    /// The caller's hash failed.
    #[error("digest failed: {0}")]
    Digest(String),
}

/// Failures while validating a reference or the bytes fetched from its url.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The part was not an ExternalPart.
    #[error("part is not an external part")]
    NotExternal,
    /// The reference declared `encAlg = 0`. The draft permits this; whether to accept readable
    /// external content is a policy question, so it is reported separately from a malformed
    /// reference rather than folded into one.
    #[error("reference declares unencrypted content (encAlg is zero)")]
    UnencryptedRejected,
    /// The reference was internally inconsistent: an empty key, nonce or content hash.
    #[error("reference is incomplete: {field} is empty")]
    IncompleteReference {
        /// Which field was empty.
        field: &'static str,
    },
    /// The fetched object's length did not match the reference's `size`.
    #[error("size mismatch: reference declares {declared}, fetched {fetched}")]
    SizeMismatch {
        /// What the reference said.
        declared: u64,
        /// What arrived.
        fetched: u64,
    },
    /// The hash of the fetched object did not match `contentHash`.
    #[error("content hash mismatch")]
    ContentHashMismatch,
    /// The caller's hash failed.
    #[error("digest failed: {0}")]
    Digest(String),
}

/// Failures while decrypting an object that has already been verified.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The part was not an ExternalPart.
    #[error("part is not an external part")]
    NotExternal,
    /// The caller's AEAD failed, which includes an authentication-tag mismatch.
    #[error("aead decrypt failed: {0}")]
    Aead(String),
}

/// The AEAD parameters for one blob. Supplied once and used both to seal the object and to fill the
/// reference, so the two cannot disagree.
#[derive(Clone, Copy, Debug)]
pub struct SealParams<'a> {
    /// The AEAD key for this object. Fresh per blob; never derived from a group secret, never reused.
    pub key: &'a [u8],
    /// The AEAD nonce for this object.
    pub nonce: &'a [u8],
    /// Additional authenticated data. The draft's default is empty.
    pub aad: &'a [u8],
    /// An IANA AEAD algorithm number. Must not be zero.
    pub enc_alg: u16,
    /// An IANA Named Information hash algorithm number, describing what [`Digest`] computes.
    pub hash_alg: u8,
}

/// A sealed blob, its integrity hash, and the parameters that produced it.
///
/// Fields are private: everything a caller needs is exposed by accessor, and the parameters carried
/// here are the ones [`build_external_reference`] writes into the reference. Constructing this by
/// hand would allow the sealing parameters and the referenced parameters to diverge.
#[derive(Clone, Debug)]
pub struct SealedAttachment {
    ciphertext: Vec<u8>,
    content_hash: Vec<u8>,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    enc_alg: u16,
    hash_alg: u8,
}

impl SealedAttachment {
    /// The object to store. This is exactly what `contentHash` covers and what `size` counts.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The hash of [`Self::ciphertext`].
    #[must_use]
    pub fn content_hash(&self) -> &[u8] {
        &self.content_hash
    }

    /// The length of [`Self::ciphertext`], the value that becomes the reference's `size`.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.ciphertext.len() as u64
    }
}

/// The descriptive fields of a reference. Separate from [`SealParams`] because these are only
/// knowable after the object has been stored: `url` in particular does not exist until then.
#[derive(Clone, Copy, Debug)]
pub struct ReferenceMeta<'a> {
    /// Where the object can be fetched. Validated for URI shape, not dereferenced.
    pub url: &'a str,
    /// An IANA media type for the PLAINTEXT, since that is what a recipient ends up rendering.
    pub content_type: &'a str,
    /// Seconds since the UNIX epoch after which the content is invalid, or zero for no expiry.
    ///
    /// This is a field, not a mechanism. Nothing in this crate or in the format enforces it; whether
    /// an expired object is still served is entirely a property of the store.
    pub expires: u32,
    /// An optional human-readable description. May be empty.
    pub description: &'a str,
    /// An optional suggested filename. May be empty.
    ///
    /// A consumer that writes this to disk owns the path safety of doing so: the value is chosen by
    /// the sender and this module does not reduce it to a basename or otherwise constrain its shape
    /// beyond rejecting control characters.
    pub filename: &'a str,
}

/// Seal a blob and hash the sealed bytes, yielding the object to store.
///
/// This is the first of two steps. The second, [`build_external_reference`], cannot run until the
/// returned ciphertext has been stored and a url obtained for it.
///
/// # Errors
///
/// Returns [`BuildError::UnencryptedRefused`] if `enc_alg` is zero,
/// [`BuildError::EmptyParameter`] for an empty key or nonce, and [`BuildError::Aead`] or
/// [`BuildError::Digest`] if the caller's implementation fails.
pub fn seal_attachment<A: Aead, D: Digest>(
    aead: &A,
    digest: &D,
    params: &SealParams<'_>,
    plaintext: &[u8],
) -> Result<SealedAttachment, BuildError> {
    if params.enc_alg == ENC_ALG_UNENCRYPTED {
        return Err(BuildError::UnencryptedRefused);
    }
    if params.key.is_empty() {
        return Err(BuildError::EmptyParameter { field: "key" });
    }
    if params.nonce.is_empty() {
        return Err(BuildError::EmptyParameter { field: "nonce" });
    }

    let ciphertext = aead
        .encrypt(params.key, params.nonce, params.aad, plaintext)
        .map_err(|e| BuildError::Aead(e.to_string()))?;
    let content_hash = digest
        .digest(&ciphertext)
        .map_err(|e| BuildError::Digest(e.to_string()))?;

    Ok(SealedAttachment {
        ciphertext,
        content_hash,
        key: params.key.to_vec(),
        nonce: params.nonce.to_vec(),
        aad: params.aad.to_vec(),
        enc_alg: params.enc_alg,
        hash_alg: params.hash_alg,
    })
}

/// Build the reference for an object that has already been stored.
///
/// # Errors
///
/// Returns [`BuildError::MalformedUrl`] if `url` is empty, too long, not shaped like a URI, or
/// carries a control character or whitespace, and [`BuildError::ControlCharacter`] if a text field
/// carries a control character.
pub fn build_external_reference(
    sealed: &SealedAttachment,
    meta: &ReferenceMeta<'_>,
) -> Result<PartBody, BuildError> {
    validate_url(meta.url)?;
    reject_control_characters(meta.content_type, "content_type")?;
    reject_control_characters(meta.description, "description")?;
    reject_control_characters(meta.filename, "filename")?;

    Ok(PartBody::External {
        content_type: meta.content_type.to_string(),
        url: meta.url.to_string(),
        expires: meta.expires,
        size: sealed.size(),
        enc_alg: sealed.enc_alg,
        key: sealed.key.clone(),
        nonce: sealed.nonce.clone(),
        aad: sealed.aad.clone(),
        hash_alg: sealed.hash_alg,
        content_hash: sealed.content_hash.clone(),
        description: meta.description.to_string(),
        filename: meta.filename.to_string(),
    })
}

/// Bytes that have been checked against a reference's `size` and `contentHash`.
///
/// The only way to obtain one is [`verify_fetched`], and it borrows the buffer it verified, so the
/// bytes handed to [`open_verified`] are necessarily the bytes that were checked.
///
/// A token whose mere PRESENCE is required is satisfied by minting one at the call site, which is the
/// cheapest thing a caller can do and defeats the ordering entirely. The field below is therefore
/// private to this module, and the two examples that follow are the sensor for that: the first must
/// fail to compile, and the second must compile, so that a failure caused by a stale name or import
/// cannot be mistaken for the property holding.
///
/// Constructing one directly is rejected because the field is private:
///
/// ```compile_fail,E0451
/// use mimi_core::external::VerifiedCiphertext;
///
/// let bytes: &[u8] = b"never checked against any reference";
/// let forged = VerifiedCiphertext { bytes };
/// ```
///
/// Positive control - the legitimate route compiles, so the example above is known to fail for the
/// privacy of the field rather than for a name that no longer resolves:
///
/// ```
/// use mimi_core::content::PartBody;
/// use mimi_core::external::{verify_fetched, Digest, VerifiedCiphertext};
///
/// struct D;
/// impl Digest for D {
///     type Error = String;
///     fn digest(&self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
///         Ok(vec![bytes.len() as u8])
///     }
/// }
///
/// let reference = PartBody::External {
///     content_type: "application/octet-stream".to_string(),
///     url: "detente://fleet/blob/1".to_string(),
///     expires: 0,
///     size: 3,
///     enc_alg: 1,
///     key: vec![1],
///     nonce: vec![2],
///     aad: Vec::new(),
///     hash_alg: 1,
///     content_hash: vec![3],
///     description: String::new(),
///     filename: String::new(),
/// };
///
/// let verified: VerifiedCiphertext<'_> = verify_fetched(&D, &reference, b"abc").unwrap();
/// assert_eq!(verified.as_bytes(), b"abc");
/// ```
#[derive(Debug)]
pub struct VerifiedCiphertext<'a> {
    bytes: &'a [u8],
}

impl VerifiedCiphertext<'_> {
    /// The verified bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
}

/// The `size` a reference declares, readable without fetching anything.
///
/// A consumer bounds its fetch and its buffer against this BEFORE requesting the object, which is
/// the only point at which the bound can prevent an allocation rather than merely detect one.
///
/// # Errors
///
/// Returns [`VerifyError::NotExternal`] if the part is not an ExternalPart.
pub const fn declared_size(reference: &PartBody) -> Result<u64, VerifyError> {
    match reference {
        PartBody::External { size, .. } => Ok(*size),
        _ => Err(VerifyError::NotExternal),
    }
}

/// Check fetched bytes against their reference: policy, completeness, `size`, then `contentHash`.
///
/// # Errors
///
/// Returns [`VerifyError::NotExternal`], [`VerifyError::UnencryptedRejected`],
/// [`VerifyError::IncompleteReference`], [`VerifyError::SizeMismatch`],
/// [`VerifyError::ContentHashMismatch`], or [`VerifyError::Digest`].
pub fn verify_fetched<'a, D: Digest>(
    digest: &D,
    reference: &PartBody,
    fetched: &'a [u8],
) -> Result<VerifiedCiphertext<'a>, VerifyError> {
    let PartBody::External {
        size,
        enc_alg,
        key,
        nonce,
        content_hash,
        ..
    } = reference
    else {
        return Err(VerifyError::NotExternal);
    };

    if *enc_alg == ENC_ALG_UNENCRYPTED {
        return Err(VerifyError::UnencryptedRejected);
    }
    if key.is_empty() {
        return Err(VerifyError::IncompleteReference { field: "key" });
    }
    if nonce.is_empty() {
        return Err(VerifyError::IncompleteReference { field: "nonce" });
    }
    if content_hash.is_empty() {
        return Err(VerifyError::IncompleteReference {
            field: "content_hash",
        });
    }

    let fetched_len = fetched.len() as u64;
    if fetched_len != *size {
        return Err(VerifyError::SizeMismatch {
            declared: *size,
            fetched: fetched_len,
        });
    }

    let computed = digest
        .digest(fetched)
        .map_err(|e| VerifyError::Digest(e.to_string()))?;
    if !constant_time_eq(&computed, content_hash) {
        return Err(VerifyError::ContentHashMismatch);
    }

    Ok(VerifiedCiphertext { bytes: fetched })
}

/// Decrypt bytes that [`verify_fetched`] has already checked.
///
/// # Errors
///
/// Returns [`OpenError::NotExternal`] if the part is not an ExternalPart, or [`OpenError::Aead`] if
/// the caller's implementation fails, which includes an authentication-tag mismatch.
pub fn open_verified<A: Aead>(
    aead: &A,
    reference: &PartBody,
    verified: &VerifiedCiphertext<'_>,
) -> Result<Vec<u8>, OpenError> {
    let PartBody::External {
        key, nonce, aad, ..
    } = reference
    else {
        return Err(OpenError::NotExternal);
    };

    aead.decrypt(key, nonce, aad, verified.as_bytes())
        .map_err(|e| OpenError::Aead(e.to_string()))
}

/// Compare two byte strings without an early exit on the first differing byte.
///
/// One operand is attacker-supplied, so a comparison that returns as soon as it finds a difference
/// reports through its timing how many leading bytes matched. Lengths are compared directly: a hash
/// length is public.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        difference |= x ^ y;
    }
    core::hint::black_box(difference) == 0
}

/// Accept only a value shaped like a URI: a scheme, `://`, and a non-empty remainder, with no
/// control characters or whitespace anywhere.
///
/// The url is an identifier this crate never dereferences, so this checks shape and rejects
/// characters that let one value be read as two. It is deliberately not a full parser.
fn validate_url(url: &str) -> Result<(), BuildError> {
    if url.is_empty() {
        return Err(BuildError::MalformedUrl { reason: "empty" });
    }
    if url.len() > MAX_URL_LEN {
        return Err(BuildError::MalformedUrl {
            reason: "longer than the permitted maximum",
        });
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(BuildError::MalformedUrl {
            reason: "contains a control character or whitespace",
        });
    }

    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(BuildError::MalformedUrl {
            reason: "has no scheme",
        });
    };
    if rest.is_empty() {
        return Err(BuildError::MalformedUrl {
            reason: "has a scheme but nothing after it",
        });
    }
    let mut scheme_chars = scheme.chars();
    let starts_with_letter = scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    let tail_is_legal =
        scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !starts_with_letter || !tail_is_legal {
        return Err(BuildError::MalformedUrl {
            reason: "scheme is not a legal URI scheme",
        });
    }
    Ok(())
}

/// Reject a text field carrying a control character.
///
/// A control character in a value that is later rendered, logged or written to a filesystem lets one
/// value be presented as another, and no legitimate media type, description or filename needs one.
fn reject_control_characters(value: &str, field: &'static str) -> Result<(), BuildError> {
    if value.chars().any(char::is_control) {
        return Err(BuildError::ControlCharacter { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{Disposition, NestedPart};

    /// A stand-in AEAD: reversible, tagged, and dependent on every parameter, so a test that changes
    /// a key, nonce or aad observes a different result. It is NOT encryption and exists only to
    /// exercise this module's ordering and validation.
    struct XorAead;

    /// The tag this stand-in appends, so that a truncated or altered object fails to open the way a
    /// real authentication tag would.
    const STUB_TAG: &[u8] = b"tag";

    impl XorAead {
        fn mask(key: &[u8], nonce: &[u8], aad: &[u8], index: usize) -> u8 {
            let k = key[index % key.len()];
            let n = nonce[index % nonce.len()];
            let a = if aad.is_empty() {
                0
            } else {
                aad[index % aad.len()]
            };
            k ^ n ^ a
        }
    }

    impl Aead for XorAead {
        type Error = String;

        fn encrypt(
            &self,
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, Self::Error> {
            let mut out: Vec<u8> = plaintext
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ Self::mask(key, nonce, aad, i))
                .collect();
            out.extend_from_slice(STUB_TAG);
            Ok(out)
        }

        fn decrypt(
            &self,
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, Self::Error> {
            let split = ciphertext
                .len()
                .checked_sub(STUB_TAG.len())
                .ok_or_else(|| "ciphertext shorter than the tag".to_string())?;
            let (body, tag) = ciphertext.split_at(split);
            if tag != STUB_TAG {
                return Err("tag mismatch".to_string());
            }
            Ok(body
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ Self::mask(key, nonce, aad, i))
                .collect())
        }
    }

    /// A stand-in hash: order-dependent and length-fixed. Not a cryptographic hash.
    struct StubDigest;

    impl Digest for StubDigest {
        type Error = String;

        fn digest(&self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
            let mut acc: [u8; 4] = [0x9e, 0x37, 0x79, 0xb9];
            for (i, b) in bytes.iter().enumerate() {
                let slot = i % acc.len();
                acc[slot] = acc[slot].wrapping_mul(31).wrapping_add(*b);
            }
            Ok(acc.to_vec())
        }
    }

    /// A hash that always fails, for the error-propagation cases.
    struct FailingDigest;

    impl Digest for FailingDigest {
        type Error = String;

        fn digest(&self, _bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Err("digest unavailable".to_string())
        }
    }

    /// An AEAD that always fails, for the error-propagation cases.
    struct FailingAead;

    impl Aead for FailingAead {
        type Error = String;

        fn encrypt(
            &self,
            _key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            _plaintext: &[u8],
        ) -> Result<Vec<u8>, Self::Error> {
            Err("aead unavailable".to_string())
        }

        fn decrypt(
            &self,
            _key: &[u8],
            _nonce: &[u8],
            _aad: &[u8],
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>, Self::Error> {
            Err("aead unavailable".to_string())
        }
    }

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const NONCE: &[u8] = b"123456789012";

    fn params() -> SealParams<'static> {
        SealParams {
            key: KEY,
            nonce: NONCE,
            aad: b"",
            enc_alg: 1,
            hash_alg: 1,
        }
    }

    fn meta() -> ReferenceMeta<'static> {
        ReferenceMeta {
            url: "detente://fleet/blob/abc",
            content_type: "text/plain",
            expires: 0,
            description: "",
            filename: "note.txt",
        }
    }

    fn seal(plaintext: &[u8]) -> SealedAttachment {
        seal_attachment(&XorAead, &StubDigest, &params(), plaintext).expect("seal succeeds")
    }

    fn reference(plaintext: &[u8]) -> (SealedAttachment, PartBody) {
        let sealed = seal(plaintext);
        let part = build_external_reference(&sealed, &meta()).expect("reference builds");
        (sealed, part)
    }

    #[test]
    fn round_trip_recovers_the_plaintext() {
        let plaintext = b"the quick brown fox";
        let (sealed, part) = reference(plaintext);

        let verified =
            verify_fetched(&StubDigest, &part, sealed.ciphertext()).expect("verification succeeds");
        let opened = open_verified(&XorAead, &part, &verified).expect("decryption succeeds");

        assert_eq!(opened, plaintext, "a sealed blob must round-trip exactly");
    }

    #[test]
    fn the_reference_carries_the_sealing_parameters() {
        let (sealed, part) = reference(b"payload");
        let PartBody::External {
            key,
            nonce,
            aad,
            enc_alg,
            hash_alg,
            size,
            content_hash,
            ..
        } = &part
        else {
            panic!("builder must produce an external part");
        };

        assert_eq!(key.as_slice(), KEY, "the reference must carry the seal key");
        assert_eq!(
            nonce.as_slice(),
            NONCE,
            "the reference must carry the seal nonce"
        );
        assert!(aad.is_empty(), "an empty aad must stay empty");
        assert_eq!(*enc_alg, 1, "encAlg must be the caller's value");
        assert_eq!(*hash_alg, 1, "hashAlg must be the caller's value");
        assert_eq!(
            *size,
            sealed.ciphertext().len() as u64,
            "size must count the sealed object, not the plaintext"
        );
        assert_eq!(
            content_hash.as_slice(),
            sealed.content_hash(),
            "contentHash must cover the sealed object"
        );
    }

    #[test]
    fn size_counts_ciphertext_not_plaintext() {
        let plaintext = b"exactly sixteen!";
        let (sealed, _) = reference(plaintext);
        assert_ne!(
            sealed.size(),
            plaintext.len() as u64,
            "the stand-in appends a tag, so a size equal to the plaintext length would mean size \
             was measured before sealing"
        );
        assert_eq!(
            sealed.size(),
            (plaintext.len() + STUB_TAG.len()) as u64,
            "size must be the sealed length"
        );
    }

    #[test]
    fn the_hash_covers_the_sealed_object_not_the_plaintext() {
        let plaintext = b"attachment body";
        let sealed = seal(plaintext);
        let over_plaintext = StubDigest.digest(plaintext).expect("digest succeeds");
        assert_ne!(
            sealed.content_hash(),
            over_plaintext.as_slice(),
            "hashing the plaintext would make verification impossible before decryption"
        );
    }

    #[test]
    fn unencrypted_is_refused_at_build() {
        let mut p = params();
        p.enc_alg = 0;
        let result = seal_attachment(&XorAead, &StubDigest, &p, b"body");
        assert!(
            matches!(result, Err(BuildError::UnencryptedRefused)),
            "encAlg zero must be refused rather than emitted"
        );
    }

    #[test]
    fn unencrypted_is_rejected_on_receipt_with_its_own_error() {
        let (sealed, mut part) = reference(b"body");
        if let PartBody::External { enc_alg, .. } = &mut part {
            *enc_alg = 0;
        }
        let result = verify_fetched(&StubDigest, &part, sealed.ciphertext());
        assert!(
            matches!(result, Err(VerifyError::UnencryptedRejected)),
            "receiving encAlg zero is a policy decision and must not be reported as a malformed \
             reference or as a hash failure"
        );
    }

    #[test]
    fn a_truncated_object_fails_on_size_before_the_hash_is_consulted() {
        let (sealed, part) = reference(b"a longer attachment body");
        let truncated = &sealed.ciphertext()[..sealed.ciphertext().len() - 1];

        let result = verify_fetched(&FailingDigest, &part, truncated);
        assert!(
            matches!(result, Err(VerifyError::SizeMismatch { .. })),
            "a length mismatch must be caught by the size check; a failing digest here proves the \
             size check ran first"
        );
    }

    #[test]
    fn an_oversized_object_is_refused() {
        let (sealed, part) = reference(b"body");
        let mut oversized = sealed.ciphertext().to_vec();
        oversized.push(0);

        let result = verify_fetched(&StubDigest, &part, &oversized);
        assert!(
            matches!(
                result,
                Err(VerifyError::SizeMismatch {
                    declared: _,
                    fetched: _
                })
            ),
            "an object longer than the reference declares must be refused"
        );
    }

    #[test]
    fn altered_bytes_of_the_declared_length_fail_the_hash() {
        let (sealed, part) = reference(b"body");
        let mut altered = sealed.ciphertext().to_vec();
        altered[0] ^= 0xff;

        let result = verify_fetched(&StubDigest, &part, &altered);
        assert!(
            matches!(result, Err(VerifyError::ContentHashMismatch)),
            "bytes of the right length but the wrong content must fail the hash"
        );
    }

    #[test]
    fn a_reference_with_a_foreign_hash_does_not_verify() {
        let (sealed, mut part) = reference(b"body");
        if let PartBody::External { content_hash, .. } = &mut part {
            content_hash[0] ^= 0xff;
        }
        let result = verify_fetched(&StubDigest, &part, sealed.ciphertext());
        assert!(
            matches!(result, Err(VerifyError::ContentHashMismatch)),
            "a reference whose hash does not cover the object must be refused"
        );
    }

    #[test]
    fn an_incomplete_reference_is_refused_before_hashing() {
        for (field, wipe) in [("key", 0_u8), ("nonce", 1), ("content_hash", 2)] {
            let (sealed, mut part) = reference(b"body");
            if let PartBody::External {
                key,
                nonce,
                content_hash,
                ..
            } = &mut part
            {
                match wipe {
                    0 => key.clear(),
                    1 => nonce.clear(),
                    _ => content_hash.clear(),
                }
            }
            let result = verify_fetched(&FailingDigest, &part, sealed.ciphertext());
            assert!(
                matches!(
                    result,
                    Err(VerifyError::IncompleteReference { field: f }) if f == field
                ),
                "an empty {field} must be reported as an incomplete reference, and the failing \
                 digest proves the completeness check ran before any hashing"
            );
        }
    }

    #[test]
    fn declared_size_is_readable_without_the_object() {
        let (sealed, part) = reference(b"body");
        assert_eq!(
            declared_size(&part).expect("an external part declares a size"),
            sealed.size(),
            "a consumer must be able to bound its fetch before requesting anything"
        );
    }

    #[test]
    fn non_external_parts_are_refused_by_every_entry_point() {
        let null = PartBody::Null;
        assert!(matches!(
            declared_size(&null),
            Err(VerifyError::NotExternal)
        ));
        assert!(matches!(
            verify_fetched(&StubDigest, &null, b""),
            Err(VerifyError::NotExternal)
        ));

        let (sealed, part) = reference(b"body");
        let verified =
            verify_fetched(&StubDigest, &part, sealed.ciphertext()).expect("verification succeeds");
        assert!(
            matches!(
                open_verified(&XorAead, &null, &verified),
                Err(OpenError::NotExternal)
            ),
            "a verified object must not be openable against a part that is not a reference"
        );
    }

    #[test]
    fn empty_key_or_nonce_is_refused_at_seal() {
        let mut empty_key = params();
        empty_key.key = b"";
        assert!(matches!(
            seal_attachment(&XorAead, &StubDigest, &empty_key, b"body"),
            Err(BuildError::EmptyParameter { field: "key" })
        ));

        let mut empty_nonce = params();
        empty_nonce.nonce = b"";
        assert!(matches!(
            seal_attachment(&XorAead, &StubDigest, &empty_nonce, b"body"),
            Err(BuildError::EmptyParameter { field: "nonce" })
        ));
    }

    #[test]
    fn a_malformed_url_is_refused() {
        for (url, why) in [
            ("", "empty"),
            ("no-scheme/blob/1", "no scheme delimiter"),
            ("://blob/1", "empty scheme"),
            ("9scheme://blob/1", "scheme starting with a digit"),
            ("sch eme://blob/1", "whitespace in the scheme"),
            ("detente://", "nothing after the scheme"),
            ("detente://blob/\u{0}1", "an embedded control character"),
            ("detente://blob/1\n", "a trailing newline"),
        ] {
            let sealed = seal(b"body");
            let mut m = meta();
            m.url = url;
            assert!(
                matches!(
                    build_external_reference(&sealed, &m),
                    Err(BuildError::MalformedUrl { .. })
                ),
                "a url with {why} must be refused"
            );
        }
    }

    #[test]
    fn a_well_formed_url_is_accepted() {
        for url in [
            "detente://fleet/blob/abc",
            "https://example.com/o/1",
            "mimi://example.com/r/room",
            "x+y-z.1://host/path",
        ] {
            let sealed = seal(b"body");
            let mut m = meta();
            m.url = url;
            assert!(
                build_external_reference(&sealed, &m).is_ok(),
                "{url} is a legal URI shape and must be accepted"
            );
        }
    }

    #[test]
    fn a_control_character_in_a_text_field_is_refused() {
        for (field, apply) in [("content_type", 0_u8), ("description", 1), ("filename", 2)] {
            let sealed = seal(b"body");
            let mut m = meta();
            let hostile = "a\u{0}b";
            match apply {
                0 => m.content_type = hostile,
                1 => m.description = hostile,
                _ => m.filename = hostile,
            }
            assert!(
                matches!(
                    build_external_reference(&sealed, &m),
                    Err(BuildError::ControlCharacter { field: f }) if f == field
                ),
                "a control character in {field} must be refused"
            );
        }
    }

    #[test]
    fn an_empty_payload_still_seals_and_round_trips() {
        let (sealed, part) = reference(b"");
        let verified =
            verify_fetched(&StubDigest, &part, sealed.ciphertext()).expect("verification succeeds");
        let opened = open_verified(&XorAead, &part, &verified).expect("decryption succeeds");
        assert!(opened.is_empty(), "an empty payload must round-trip empty");
    }

    #[test]
    fn a_differing_aad_produces_a_differing_object() {
        let plain = b"body";
        let bound = SealParams {
            aad: b"room-context",
            ..params()
        };
        let with_aad =
            seal_attachment(&XorAead, &StubDigest, &bound, plain).expect("seal succeeds");
        let without_aad = seal(plain);
        assert_ne!(
            with_aad.ciphertext(),
            without_aad.ciphertext(),
            "aad must reach the caller's aead rather than being dropped on the way"
        );

        let part = build_external_reference(&with_aad, &meta()).expect("reference builds");
        let PartBody::External { aad, .. } = &part else {
            panic!("builder must produce an external part");
        };
        assert_eq!(
            aad.as_slice(),
            b"room-context",
            "the aad used to seal must be the aad written into the reference"
        );
    }

    #[test]
    fn aead_and_digest_failures_are_reported_not_swallowed() {
        assert!(matches!(
            seal_attachment(&FailingAead, &StubDigest, &params(), b"body"),
            Err(BuildError::Aead(_))
        ));
        assert!(matches!(
            seal_attachment(&XorAead, &FailingDigest, &params(), b"body"),
            Err(BuildError::Digest(_))
        ));

        let (sealed, part) = reference(b"body");
        let verified =
            verify_fetched(&StubDigest, &part, sealed.ciphertext()).expect("verification succeeds");
        assert!(matches!(
            open_verified(&FailingAead, &part, &verified),
            Err(OpenError::Aead(_))
        ));
    }

    #[test]
    fn the_reference_round_trips_through_the_content_codec() {
        use crate::content::{from_content08_cbor, to_content08_cbor, MimiContent};

        let (_, part) = reference(b"an attachment that survives the codec");
        let mut message = MimiContent {
            salt: [7_u8; 16],
            replaces: None,
            topic_id: Vec::new(),
            expires: None,
            in_reply_to: None,
            mimi_extensions: Vec::new(),
            nested_part: NestedPart {
                disposition: Disposition::Attachment,
                language: String::new(),
                body: PartBody::Null,
            },
        };
        message.nested_part.body = part.clone();

        let wire = to_content08_cbor(&message).expect("a built reference must encode");
        let decoded = from_content08_cbor(&wire).expect("and decode");

        assert_eq!(
            decoded.nested_part.body, part,
            "a reference this module builds must survive the codec byte for byte"
        );
        assert_eq!(
            decoded.nested_part.disposition,
            Disposition::Attachment,
            "an attachment reference carries the attachment disposition"
        );
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abcd", b"bbcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
