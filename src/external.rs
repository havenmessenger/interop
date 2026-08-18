//! content-09 ExternalPart construction and consumption.
//!
//! The content codec owns the wire shape. This module supplies the deliberately separate glue for
//! a private external object: seal the blob, hash the ciphertext stored at the URL, then build the
//! existing [`PartBody::External`] value. It has no dependency on a particular crypto crate; callers
//! supply their AEAD implementation through [`Aead`].
//!
//! `contentHash` and `size` cover the ciphertext, not the plaintext. A consumer checks both before
//! calling [`Aead::open`], so corrupt or substituted store bytes never reach the AEAD implementation.

use std::fmt;

use crate::{content::PartBody, message_id::HashAlgorithm};

/// The authenticated-encryption operation used for a content-09 external object.
///
/// This trait deliberately does not select an algorithm or provide key/nonce generation. Those are
/// caller-side ciphersuite and randomness decisions; `interop` only carries their wire-visible
/// results. Implementors must provide an AEAD construction, not encryption without authentication.
pub trait Aead {
    /// The implementation's sealing/opening failure type.
    type Error: fmt::Display;

    /// Seal plaintext with the supplied key, nonce, and additional authenticated data.
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Open ciphertext with the supplied key, nonce, and additional authenticated data.
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Caller-chosen metadata and AEAD material for a content-09 ExternalPart.
///
/// `enc_alg` remains an explicit IANA AEAD algorithm number because this generic library must not
/// choose a ciphersuite on a caller's behalf. Zero is rejected: it represents unencrypted external
/// content in content-09, which cannot be produced through this sealed-object API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalPartMetadata {
    pub content_type: String,
    pub url: String,
    pub expires: u32,
    pub enc_alg: u16,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub hash_algorithm: HashAlgorithm,
    pub description: String,
    pub filename: String,
}

/// A sealed external object and the content-09 reference which names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltExternalPart {
    /// The existing content-09 wire value to put into a [`crate::content::NestedPart`].
    pub part: PartBody,
    /// The ciphertext to upload to the URL named by `part` before sending its reference.
    pub ciphertext: Vec<u8>,
}

/// Fail-closed errors from building or consuming an external object.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExternalPartError {
    /// The URL is not an absolute URI and therefore cannot name an external object.
    #[error("external object URL is not an absolute URI: {0:?}")]
    InvalidUrl(String),
    /// content-09's zero algorithm means plaintext external content, outside this sealed API.
    #[error("external object enc_alg must name an AEAD, not zero")]
    UnencryptedAlgorithm,
    /// An in-memory ciphertext length did not fit the content-09 `u64` field.
    #[error("ciphertext length does not fit content-09 size field")]
    SizeOverflow,
    /// The supplied part was not an ExternalPart.
    #[error("expected a content-09 ExternalPart")]
    NotExternalPart,
    /// The claimed content size differs from the bytes fetched from the object store.
    #[error("external object size mismatch: reference says {expected}, fetched {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    /// The external object is no longer valid at the supplied Unix timestamp.
    #[error("external object expired at {expires}; current time is {now}")]
    Expired { expires: u32, now: u32 },
    /// The named information hash is unknown to this version of the library.
    #[error("unsupported content hash algorithm {0}")]
    UnknownHashAlgorithm(u8),
    /// The fetched ciphertext does not match the authenticated reference's content hash.
    #[error("external object content hash does not match fetched ciphertext")]
    ContentHashMismatch,
    /// The caller-provided AEAD rejected sealing or opening the object.
    #[error("external object AEAD operation failed: {0}")]
    Aead(String),
}

/// Seal a blob and create its content-09 ExternalPart reference.
///
/// The returned ciphertext is for the caller to upload before it sends the returned reference. The
/// `url` must already name that eventual object-store slot; this function does no network I/O.
/// `contentHash` and `size` describe the ciphertext that is returned.
pub fn build_external_part<A: Aead>(
    aead: &A,
    blob: &[u8],
    metadata: ExternalPartMetadata,
) -> Result<BuiltExternalPart, ExternalPartError> {
    validate_absolute_uri(&metadata.url)?;
    if metadata.enc_alg == 0 {
        return Err(ExternalPartError::UnencryptedAlgorithm);
    }

    let ciphertext = aead
        .seal(&metadata.key, &metadata.nonce, &metadata.aad, blob)
        .map_err(|error| ExternalPartError::Aead(error.to_string()))?;
    let size = u64::try_from(ciphertext.len()).map_err(|_| ExternalPartError::SizeOverflow)?;
    let content_hash = metadata.hash_algorithm.digest(&ciphertext).to_vec();

    Ok(BuiltExternalPart {
        part: PartBody::External {
            content_type: metadata.content_type,
            url: metadata.url,
            expires: metadata.expires,
            size,
            enc_alg: metadata.enc_alg,
            key: metadata.key,
            nonce: metadata.nonce,
            aad: metadata.aad,
            hash_alg: metadata.hash_algorithm.id(),
            content_hash,
            description: metadata.description,
            filename: metadata.filename,
        },
        ciphertext,
    })
}

/// Verify and open a fetched content-09 external object.
///
/// `now` is an absolute Unix timestamp. The function checks expiry and byte length, then verifies
/// the ciphertext hash before invoking [`Aead::open`].
pub fn consume_external_part<A: Aead>(
    aead: &A,
    part: &PartBody,
    ciphertext: &[u8],
    now: u32,
) -> Result<Vec<u8>, ExternalPartError> {
    let PartBody::External {
        url,
        expires,
        size,
        enc_alg,
        key,
        nonce,
        aad,
        hash_alg,
        content_hash,
        ..
    } = part
    else {
        return Err(ExternalPartError::NotExternalPart);
    };

    validate_absolute_uri(url)?;
    if *enc_alg == 0 {
        return Err(ExternalPartError::UnencryptedAlgorithm);
    }
    if *expires <= now {
        return Err(ExternalPartError::Expired {
            expires: *expires,
            now,
        });
    }
    let actual = u64::try_from(ciphertext.len()).map_err(|_| ExternalPartError::SizeOverflow)?;
    if *size != actual {
        return Err(ExternalPartError::SizeMismatch {
            expected: *size,
            actual,
        });
    }
    let algorithm = HashAlgorithm::from_id(*hash_alg)
        .map_err(|_| ExternalPartError::UnknownHashAlgorithm(*hash_alg))?;
    if algorithm.digest(ciphertext).as_slice() != content_hash {
        return Err(ExternalPartError::ContentHashMismatch);
    }

    aead.open(key, nonce, aad, ciphertext)
        .map_err(|error| ExternalPartError::Aead(error.to_string()))
}

fn validate_absolute_uri(value: &str) -> Result<(), ExternalPartError> {
    let Some((scheme, rest)) = value.split_once(':') else {
        return Err(ExternalPartError::InvalidUrl(value.to_string()));
    };
    let valid_scheme = !scheme.is_empty()
        && scheme.as_bytes()[0].is_ascii_alphabetic()
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
    if !valid_scheme || rest.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(ExternalPartError::InvalidUrl(value.to_string()));
    }
    Ok(())
}
