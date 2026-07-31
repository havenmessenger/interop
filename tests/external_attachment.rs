//! End-to-end use of the content-09 ExternalPart glue from OUTSIDE the crate.
//!
//! These exercise the surface an adopter actually compiles against: only public items, only the
//! documented route. The in-module tests can reach private state and so cannot demonstrate that the
//! public API alone is sufficient to build and consume a reference, nor that it is insufficient to
//! bypass the ordering.

use mimi_core::content::{
    from_content08_cbor, to_content08_cbor, Disposition, MimiContent, NestedPart, PartBody,
};
use mimi_core::external::{
    build_external_reference, declared_size, open_verified, seal_attachment, verify_fetched, Aead,
    Digest, ReferenceMeta, SealParams,
};

/// A reversible stand-in that depends on every parameter and carries a tag, so an altered object
/// fails to open the way a real authentication tag would. Not encryption.
struct StubAead;

const STUB_TAG: &[u8] = b"..tag..";

impl StubAead {
    fn mask(key: &[u8], nonce: &[u8], aad: &[u8], index: usize) -> u8 {
        let a = if aad.is_empty() {
            0
        } else {
            aad[index % aad.len()]
        };
        key[index % key.len()] ^ nonce[index % nonce.len()] ^ a
    }
}

impl Aead for StubAead {
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
            .ok_or_else(|| "shorter than the tag".to_string())?;
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

/// An order-dependent stand-in hash. Not a cryptographic hash.
struct StubDigest;

impl Digest for StubDigest {
    type Error = String;

    fn digest(&self, bytes: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut acc: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        for (i, b) in bytes.iter().enumerate() {
            let slot = i % acc.len();
            acc[slot] = acc[slot].wrapping_mul(131).wrapping_add(*b);
        }
        Ok(acc.to_vec())
    }
}

const KEY: &[u8] = b"an-attachment-key-of-some-length";
const NONCE: &[u8] = b"nonce-bytes!";

fn seal_params() -> SealParams<'static> {
    SealParams {
        key: KEY,
        nonce: NONCE,
        aad: b"",
        enc_alg: 1,
        hash_alg: 1,
    }
}

/// The whole documented sequence, using nothing but public items: seal, then store (represented
/// here by the caller holding the bytes and choosing a url), then reference, then send, then at the
/// far end bound the fetch, verify, and only then decrypt.
#[test]
fn the_public_api_carries_an_attachment_end_to_end() {
    let plaintext = b"a report the coordinator will collect later";

    let sealed = seal_attachment(&StubAead, &StubDigest, &seal_params(), plaintext)
        .expect("sealing succeeds");

    // The store is represented by nothing more than "the caller now has an identifier for the bytes".
    let stored: Vec<u8> = sealed.ciphertext().to_vec();
    let url = "detente://fleet-0/blob/report-1";

    let reference = build_external_reference(
        &sealed,
        &ReferenceMeta {
            url,
            content_type: "text/plain",
            expires: 0,
            description: "run output",
            filename: "report.txt",
        },
    )
    .expect("the reference builds once a url exists");

    let wire = to_content08_cbor(&message_carrying(reference.clone())).expect("encodes");
    let received = from_content08_cbor(&wire).expect("decodes");
    let received_reference = received.nested_part.body;

    let bound = declared_size(&received_reference).expect("a reference declares its size");
    assert_eq!(
        bound,
        stored.len() as u64,
        "a consumer bounds its fetch from the reference alone, before requesting anything"
    );

    let verified =
        verify_fetched(&StubDigest, &received_reference, &stored).expect("the object verifies");
    let opened = open_verified(&StubAead, &received_reference, &verified).expect("and opens");

    assert_eq!(
        opened, plaintext,
        "the attachment must survive sealing, the codec and opening unchanged"
    );
}

/// The bytes handed to the opener are necessarily the bytes that were checked, because the token
/// borrows them. This is the property that makes verify-before-decrypt structural: there is no way
/// to verify one buffer and then open a different one.
#[test]
fn the_token_is_tied_to_the_buffer_it_verified() {
    let sealed = seal_attachment(&StubAead, &StubDigest, &seal_params(), b"body").expect("seals");
    let reference = build_external_reference(&sealed, &meta()).expect("builds");

    let honest = sealed.ciphertext().to_vec();
    let verified = verify_fetched(&StubDigest, &reference, &honest).expect("verifies");

    assert_eq!(
        verified.as_bytes(),
        honest.as_slice(),
        "the token must expose exactly the buffer it verified"
    );

    let mut hostile = honest.clone();
    hostile[0] ^= 0xff;
    assert!(
        verify_fetched(&StubDigest, &reference, &hostile).is_err(),
        "the hostile buffer must not be able to obtain a token of its own"
    );
}

/// The refusal to emit unencrypted external content is reachable from outside the crate, and a
/// received one is reported as its own case rather than as a malformed reference.
#[test]
fn unencrypted_external_content_is_refused_in_both_directions() {
    let mut params = seal_params();
    params.enc_alg = 0;
    assert!(
        seal_attachment(&StubAead, &StubDigest, &params, b"body").is_err(),
        "an adopter must not be able to build an unencrypted external part"
    );

    let sealed = seal_attachment(&StubAead, &StubDigest, &seal_params(), b"body").expect("seals");
    let mut reference = build_external_reference(&sealed, &meta()).expect("builds");
    if let PartBody::External { enc_alg, .. } = &mut reference {
        *enc_alg = 0;
    }
    assert!(
        verify_fetched(&StubDigest, &reference, sealed.ciphertext()).is_err(),
        "a received unencrypted reference must not verify"
    );
}

/// A reference this module builds is accepted by the codec unchanged, including through a message
/// carrying the attachment disposition.
#[test]
fn a_built_reference_survives_the_codec() {
    let sealed = seal_attachment(&StubAead, &StubDigest, &seal_params(), b"attachment bytes")
        .expect("seals");
    let reference = build_external_reference(&sealed, &meta()).expect("builds");

    let wire = to_content08_cbor(&message_carrying(reference.clone())).expect("encodes");
    let decoded = from_content08_cbor(&wire).expect("decodes");

    assert_eq!(
        decoded.nested_part.body, reference,
        "the reference must round-trip through the codec unchanged"
    );
    assert_eq!(decoded.nested_part.disposition, Disposition::Attachment);
}

fn meta() -> ReferenceMeta<'static> {
    ReferenceMeta {
        url: "detente://fleet-0/blob/1",
        content_type: "application/octet-stream",
        expires: 0,
        description: "",
        filename: "",
    }
}

fn message_carrying(body: PartBody) -> MimiContent {
    MimiContent {
        salt: [3_u8; 16],
        replaces: None,
        topic_id: Vec::new(),
        expires: None,
        in_reply_to: None,
        mimi_extensions: Vec::new(),
        nested_part: NestedPart {
            disposition: Disposition::Attachment,
            language: String::new(),
            body,
        },
    }
}
