//! content-09 §3.3 message ID derivation.
//!
//! A message ID is one octet naming the hash algorithm, followed by the first 31 octets of a hash
//! over the sender URI, the room URI, the encoded message, and the message salt.
//!
//! The salt is hashed **twice**. §3.3 concatenates "the entire MIMI message content (including the
//! salt), and the salt (again)", so the encoded document contributes the salt once as its own first
//! field and the same value is appended as the final term. An implementation that supplies the
//! document without its salt, or appends nothing after it, derives identifiers that no conformant
//! implementation reproduces. [`MimiMessage`] exists so that the two copies cannot come from
//! different places.
//!
//! Two further properties of the construction bind what a consumer may conclude from an identifier
//! it holds.
//!
//! Truncation to 31 octets makes the identifier collision resistant, and not collision free. A
//! stored message ID equal to a newly derived one is not proof that the two messages are equal.
//! Code that treats a match as identity has an integrity bug: compare the messages themselves where
//! equality is the question being asked.
//!
//! The derivation covers URI octets, and content-09 §3.2 permits schemes other than `mimi:`. Two
//! devices agree on an identifier only when they hash the same octets. A device that hashes an alias
//! for the sender, or a URI it decoded and then re-encoded, derives a different identifier for the
//! same message, and deduplication against that identifier fails without any error. Hash the octets
//! as received. This module accepts URIs and messages as byte slices for that reason, and accepts no
//! decoded form that would have to be serialized again before hashing.

use crate::content::MessageId;
use sha2::{Digest as _, Sha256};

/// Octets in a content-09 message ID: one algorithm identifier and 31 octets of hash output.
///
/// The §4.1 CDDL states this as `MessageId = bstr .size 32`.
pub const MESSAGE_ID_LEN: usize = 32;

/// Octets in the per-message salt carried by `MimiContent`.
pub const SALT_LEN: usize = 16;

/// Octets of hash output carried after the algorithm identifier.
const HASH_PREFIX_LEN: usize = MESSAGE_ID_LEN - 1;

/// Failures while deriving a message ID.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MessageIdError {
    /// A URI longer than the `u16` length prefix that precedes it in the preimage. Emitting a
    /// truncated length would produce a well-formed identifier over the wrong preimage, so this is
    /// an error rather than a narrowing cast.
    #[error("{field} URI is {len} octets and the length prefix is a u16")]
    UriTooLong {
        /// Which of the two URIs exceeded the prefix range.
        field: &'static str,
        /// The offending length in octets.
        len: usize,
    },
    /// An algorithm identifier this build cannot derive with.
    #[error("unrecognized hash algorithm identifier {0}")]
    UnknownAlgorithm(u8),
    /// Octets that do not decode as a MIMI content document, so the salt they carry cannot be read.
    #[error("not a decodable MIMI content document: {0}")]
    Undecodable(String),
}

/// An encoded MIMI content document paired with the salt it carries.
///
/// §3.3 hashes the salt twice: once within the encoded document, and once appended as the final
/// term. Supplying the document and the salt as two arguments would let them disagree, and a
/// mismatch yields an identifier no other implementation derives, with nothing to signal it. This
/// type removes that: the only way to obtain one is [`MimiMessage::from_encoded`], which reads the
/// salt out of the document itself.
///
/// The original octets are retained and hashed as given. Decoding here reads the salt; it never
/// replaces the octets with a re-encoded form.
#[derive(Clone, Copy, Debug)]
pub struct MimiMessage<'a> {
    encoded: &'a [u8],
    salt: [u8; SALT_LEN],
}

impl<'a> MimiMessage<'a> {
    /// Read an encoded MIMI content document and the salt it carries.
    ///
    /// # Errors
    /// [`MessageIdError::Undecodable`] if the octets are not a MIMI content document.
    pub fn from_encoded(encoded: &'a [u8]) -> Result<Self, MessageIdError> {
        let content = crate::content::from_content08_cbor(encoded)
            .map_err(|e| MessageIdError::Undecodable(e.to_string()))?;
        Ok(Self {
            encoded,
            salt: content.salt,
        })
    }

    /// The document's octets, as supplied.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.encoded
    }

    /// The salt the document carries.
    #[must_use]
    pub const fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}

/// Hash algorithms available for a message ID.
///
/// The value written as an identifier's first octet is the algorithm's number in the IANA Named
/// Information hash algorithm registry. Carrying it on the wire is what lets an algorithm be
/// retired later: a further algorithm arrives as a variant here with its own registry number and
/// its own test vectors, and identifiers already emitted keep resolving.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256, registry number 1.
    Sha256,
}

impl HashAlgorithm {
    /// The registry number written as a message ID's first octet.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Sha256 => 1,
        }
    }

    /// Recover the algorithm from the first octet of a message ID.
    ///
    /// # Errors
    /// [`MessageIdError::UnknownAlgorithm`] if this build cannot derive with that number.
    pub const fn from_id(id: u8) -> Result<Self, MessageIdError> {
        match id {
            1 => Ok(Self::Sha256),
            other => Err(MessageIdError::UnknownAlgorithm(other)),
        }
    }

    fn hash(self, input: &[u8]) -> [u8; 32] {
        match self {
            Self::Sha256 => Sha256::digest(input).into(),
        }
    }
}

/// Build the §3.3 hash preimage.
///
/// The concatenation is `senderUriLength || senderUri || roomUriLength || roomUri || message ||
/// salt`. Both lengths are big-endian `u16` octet counts. `message` is the whole encoded MIMI
/// content, whose own first field is the salt, and the salt is then repeated as the final term.
///
/// This is public so that a consumer deriving with an algorithm this build does not carry can hash
/// the same octets and still agree with implementations that do. It is the lower-level entry point:
/// `salt` is passed separately here, so the caller carries the obligation that it is the same salt
/// `message` already contains. A `salt` that differs from the one inside `message` produces an
/// identifier no other implementation derives. [`derive_message_id`] takes a [`MimiMessage`] instead
/// and removes that obligation; prefer it unless the document's framing is one this crate cannot
/// decode.
///
/// # Errors
/// [`MessageIdError::UriTooLong`] if either URI exceeds the range of its length prefix.
pub fn message_id_preimage(
    sender_uri: &[u8],
    room_uri: &[u8],
    message: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, MessageIdError> {
    let sender_len = u16::try_from(sender_uri.len()).map_err(|_| MessageIdError::UriTooLong {
        field: "sender",
        len: sender_uri.len(),
    })?;
    let room_len = u16::try_from(room_uri.len()).map_err(|_| MessageIdError::UriTooLong {
        field: "room",
        len: room_uri.len(),
    })?;

    let mut preimage = Vec::with_capacity(
        (2 * size_of::<u16>()) + sender_uri.len() + room_uri.len() + message.len() + SALT_LEN,
    );
    preimage.extend_from_slice(&sender_len.to_be_bytes());
    preimage.extend_from_slice(sender_uri);
    preimage.extend_from_slice(&room_len.to_be_bytes());
    preimage.extend_from_slice(room_uri);
    preimage.extend_from_slice(message);
    preimage.extend_from_slice(salt);
    Ok(preimage)
}

/// Derive the §3.3 message ID for an encoded message.
///
/// `sender_uri` and `room_uri` are hashed as supplied. Where the message was received rather than
/// composed here, build the [`MimiMessage`] from the octets as received: see this module's note on
/// why a re-encoded form yields a different identifier.
///
/// The salt is taken from the message rather than passed alongside it, so the copy hashed inside the
/// document and the copy appended after it are the same value by construction.
///
/// # Errors
/// [`MessageIdError::UriTooLong`] if either URI exceeds the range of its length prefix.
pub fn derive_message_id(
    algorithm: HashAlgorithm,
    sender_uri: &[u8],
    room_uri: &[u8],
    message: &MimiMessage<'_>,
) -> Result<MessageId, MessageIdError> {
    let preimage = message_id_preimage(sender_uri, room_uri, message.as_bytes(), message.salt())?;
    let digest = algorithm.hash(&preimage);

    let mut id = Vec::with_capacity(MESSAGE_ID_LEN);
    id.push(algorithm.id());
    id.extend_from_slice(&digest[..HASH_PREFIX_LEN]);
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::{
        derive_message_id, message_id_preimage, HashAlgorithm, MessageIdError, MimiMessage,
        MESSAGE_ID_LEN, SALT_LEN,
    };
    use crate::test_vectors::{decode_hex, official_vector, PUBLISHED_MESSAGE_IDS};

    fn hex_of(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    /// The first published example, as the fixed case the shape tests below work from.
    fn reference_case() -> (&'static str, &'static str, Vec<u8>, &'static str) {
        let (name, sender, room, expected) = PUBLISHED_MESSAGE_IDS[0];
        (sender, room, decode_hex(official_vector(name)), expected)
    }

    /// Every message ID published alongside the content-09 examples is reproduced from the example
    /// document. Agreement with values the specification publishes, rather than with arithmetic
    /// restated here, is what makes these evidence of interoperability.
    #[test]
    fn published_message_ids_are_reproduced() {
        assert_eq!(
            PUBLISHED_MESSAGE_IDS.len(),
            13,
            "vector count changed; the published set is 13"
        );

        for (name, sender, room, expected) in PUBLISHED_MESSAGE_IDS {
            let encoded = decode_hex(official_vector(name));
            let message = MimiMessage::from_encoded(&encoded).expect("an example document decodes");
            let derived = derive_message_id(
                HashAlgorithm::Sha256,
                sender.as_bytes(),
                room.as_bytes(),
                &message,
            )
            .expect("the example URIs are within the length prefix");

            assert_eq!(
                hex_of(&derived),
                *expected,
                "message ID for the {name} example"
            );
            assert_eq!(derived.len(), MESSAGE_ID_LEN);
            assert_eq!(derived[0], HashAlgorithm::Sha256.id());
        }
    }

    /// §3.3 hashes the salt twice. The document contributes it once, and the same value is appended
    /// as the final term.
    #[test]
    fn the_salt_is_hashed_twice() {
        let (sender, room, encoded, _) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");
        let salt = *message.salt();

        let preimage = message_id_preimage(sender.as_bytes(), room.as_bytes(), &encoded, &salt)
            .expect("within range");

        assert!(preimage.ends_with(&salt), "the salt is the final term");
        assert_eq!(
            &encoded[2..2 + SALT_LEN],
            salt.as_slice(),
            "the document carries the same salt within it"
        );
        let occurrences = preimage
            .windows(SALT_LEN)
            .filter(|w| *w == salt.as_slice())
            .count();
        assert_eq!(occurrences, 2, "the salt appears twice in the preimage");
    }

    /// Omitting the appended salt is the reading of the §3.3 pseudocode that treats the message term
    /// as excluding it. It yields a different identifier, so the repetition is load bearing.
    #[test]
    fn preimage_without_the_repeated_salt_differs() {
        let (sender, room, encoded, _) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");
        let full =
            message_id_preimage(sender.as_bytes(), room.as_bytes(), &encoded, message.salt())
                .expect("within range");

        let without_trailing_salt = &full[..full.len() - SALT_LEN];
        assert_ne!(full.as_slice(), without_trailing_salt);
        assert_eq!(&full[full.len() - SALT_LEN..], message.salt().as_slice());
    }

    /// The salt cannot be supplied separately from the document it belongs to, so the two copies
    /// hashed by §3.3 cannot disagree.
    #[test]
    fn the_salt_comes_from_the_document_it_belongs_to() {
        let (_, _, encoded, _) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");

        let decoded = crate::content::from_content08_cbor(&encoded).expect("decodes");
        assert_eq!(message.salt(), &decoded.salt);
        assert_eq!(
            message.as_bytes(),
            encoded.as_slice(),
            "octets are unchanged"
        );
    }

    /// Octets that are not a MIMI content document carry no salt to read, so no identifier can be
    /// derived from them by this path.
    #[test]
    fn octets_that_are_not_a_content_document_are_rejected() {
        let err = MimiMessage::from_encoded(b"not cbor at all")
            .expect_err("arbitrary octets are not a content document");
        assert!(matches!(err, MessageIdError::Undecodable(_)));

        let (_, _, encoded, _) = reference_case();
        let truncated = &encoded[..encoded.len() / 2];
        assert!(matches!(
            MimiMessage::from_encoded(truncated),
            Err(MessageIdError::Undecodable(_))
        ));
    }

    /// The length prefixes are big-endian.
    #[test]
    fn length_prefixes_are_big_endian() {
        let (sender, room, encoded, _) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");
        let full =
            message_id_preimage(sender.as_bytes(), room.as_bytes(), &encoded, message.salt())
                .expect("within range");

        let sender_len = u16::try_from(sender.len()).expect("short");
        assert_eq!(&full[..2], &sender_len.to_be_bytes());
        assert_ne!(&full[..2], &sender_len.to_le_bytes());
    }

    /// The sender URI is hashed before the room URI, so field order carries meaning beyond the set
    /// of octets present.
    #[test]
    fn sender_and_room_are_not_interchangeable() {
        let (sender, room, encoded, expected) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");
        let swapped = derive_message_id(
            HashAlgorithm::Sha256,
            room.as_bytes(),
            sender.as_bytes(),
            &message,
        )
        .expect("within range");
        assert_ne!(hex_of(&swapped), *expected);
    }

    /// Each URI sits behind its own length prefix, so two URIs that concatenate to the same octets
    /// still produce different preimages.
    #[test]
    fn length_prefixes_separate_ambiguous_splits() {
        let salt = [7u8; SALT_LEN];
        let body = b"document".as_slice();

        let left = message_id_preimage(b"aab", b"c", body, &salt).expect("within range");
        let right = message_id_preimage(b"aa", b"bc", body, &salt).expect("within range");
        assert_ne!(left, right);
    }

    /// Dropping the prefixes entirely is the construction that allows that ambiguity.
    #[test]
    fn dropping_the_length_prefixes_changes_the_preimage() {
        let (sender, room, encoded, _) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");
        let full =
            message_id_preimage(sender.as_bytes(), room.as_bytes(), &encoded, message.salt())
                .expect("within range");

        let mut unprefixed = Vec::new();
        unprefixed.extend_from_slice(sender.as_bytes());
        unprefixed.extend_from_slice(room.as_bytes());
        unprefixed.extend_from_slice(&encoded);
        unprefixed.extend_from_slice(message.salt());
        assert_ne!(full, unprefixed);
    }

    #[test]
    fn sender_uri_beyond_the_length_prefix_is_rejected() {
        let (_, room, encoded, _) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");
        let long = vec![b'a'; usize::from(u16::MAX) + 1];

        let err = derive_message_id(HashAlgorithm::Sha256, &long, room.as_bytes(), &message)
            .expect_err("a URI beyond the prefix range is not representable");
        assert_eq!(
            err,
            MessageIdError::UriTooLong {
                field: "sender",
                len: usize::from(u16::MAX) + 1,
            }
        );
    }

    #[test]
    fn room_uri_beyond_the_length_prefix_is_rejected() {
        let (sender, _, encoded, _) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");
        let long = vec![b'a'; usize::from(u16::MAX) + 1];

        let err = derive_message_id(HashAlgorithm::Sha256, sender.as_bytes(), &long, &message)
            .expect_err("a URI beyond the prefix range is not representable");
        assert_eq!(
            err,
            MessageIdError::UriTooLong {
                field: "room",
                len: usize::from(u16::MAX) + 1,
            }
        );
    }

    /// A URI at the maximum representable length is accepted, so the bound rejects only what it
    /// cannot encode.
    #[test]
    fn sender_uri_at_the_length_prefix_maximum_is_accepted() {
        let (_, room, encoded, _) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");
        let at_max = vec![b'a'; usize::from(u16::MAX)];

        let id = derive_message_id(HashAlgorithm::Sha256, &at_max, room.as_bytes(), &message)
            .expect("the maximum length is representable");
        assert_eq!(id.len(), MESSAGE_ID_LEN);
    }

    #[test]
    fn algorithm_identifier_round_trips() {
        assert_eq!(HashAlgorithm::Sha256.id(), 1);
        assert_eq!(HashAlgorithm::from_id(1), Ok(HashAlgorithm::Sha256));
    }

    #[test]
    fn unrecognized_algorithm_identifier_is_rejected() {
        assert_eq!(
            HashAlgorithm::from_id(2),
            Err(MessageIdError::UnknownAlgorithm(2))
        );
        assert_eq!(
            HashAlgorithm::from_id(0),
            Err(MessageIdError::UnknownAlgorithm(0))
        );
    }

    /// The identifier's first octet is the algorithm, and the remaining 31 are hash output.
    #[test]
    fn identifier_layout_is_algorithm_then_truncated_hash() {
        let (sender, room, encoded, _) = reference_case();
        let message = MimiMessage::from_encoded(&encoded).expect("decodes");
        let id = derive_message_id(
            HashAlgorithm::Sha256,
            sender.as_bytes(),
            room.as_bytes(),
            &message,
        )
        .expect("within range");

        let preimage =
            message_id_preimage(sender.as_bytes(), room.as_bytes(), &encoded, message.salt())
                .expect("within range");
        let digest: [u8; 32] = {
            use sha2::{Digest as _, Sha256};
            Sha256::digest(&preimage).into()
        };

        assert_eq!(id[0], 1);
        assert_eq!(&id[1..], &digest[..MESSAGE_ID_LEN - 1]);
        assert_ne!(&id[1..], &digest[1..MESSAGE_ID_LEN]);
    }
}
