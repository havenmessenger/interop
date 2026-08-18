//! The ExternalPart builder and consumer as an independent `interop` adopter uses them.

use std::cell::Cell;

use mimi_core::{
    content::PartBody,
    external::{
        build_external_part, consume_external_part, Aead, ExternalPartError, ExternalPartMetadata,
    },
    message_id::HashAlgorithm,
};

#[derive(Default)]
struct TestAead {
    opens: Cell<u8>,
}

impl Aead for TestAead {
    type Error = &'static str;

    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        if key.is_empty() || nonce.is_empty() || aad != b"attachment-aad" {
            return Err("invalid test inputs");
        }
        Ok(plaintext.iter().map(|byte| byte ^ key[0]).collect())
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.opens.set(self.opens.get() + 1);
        self.seal(key, nonce, aad, ciphertext)
    }
}

fn metadata() -> ExternalPartMetadata {
    ExternalPartMetadata {
        content_type: "application/octet-stream".into(),
        url: "detente://fleet-1/blob/attachment-1".into(),
        expires: 1_900_000_000,
        enc_alg: 1,
        key: vec![0x5a; 32],
        nonce: vec![0x23; 12],
        aad: b"attachment-aad".to_vec(),
        hash_algorithm: HashAlgorithm::Sha256,
        description: "test attachment".into(),
        filename: "attachment.bin".into(),
    }
}

#[test]
fn builds_ciphertext_reference_and_recovers_the_original_blob() {
    let aead = TestAead::default();
    let blob = b"a private attachment";
    let built = build_external_part(&aead, blob, metadata()).expect("build external part");

    let PartBody::External {
        size,
        hash_alg,
        content_hash,
        ..
    } = &built.part
    else {
        panic!("builder must return ExternalPart");
    };
    assert_eq!(*size, u64::try_from(built.ciphertext.len()).unwrap());
    assert_eq!(*hash_alg, HashAlgorithm::Sha256.id());
    assert_eq!(
        content_hash,
        &HashAlgorithm::Sha256.digest(&built.ciphertext)
    );
    assert_eq!(
        consume_external_part(&aead, &built.part, &built.ciphertext, 1_800_000_000)
            .expect("consumer verifies then opens"),
        blob
    );
    assert_eq!(
        aead.opens.get(),
        1,
        "only the valid object reaches AEAD open"
    );
}

#[test]
fn tampered_ciphertext_is_rejected_before_the_aead_open_call() {
    let aead = TestAead::default();
    let built = build_external_part(&aead, b"a private attachment", metadata()).unwrap();
    let mut tampered = built.ciphertext.clone();
    tampered[0] ^= 1;

    assert_eq!(
        consume_external_part(&aead, &built.part, &tampered, 1_800_000_000),
        Err(ExternalPartError::ContentHashMismatch),
        "ciphertext hash is checked before an attacker-controlled blob reaches AEAD"
    );
    assert_eq!(
        aead.opens.get(),
        0,
        "mutation reddens if hash verification is moved after open"
    );
}

#[test]
fn rejects_expired_or_unencrypted_external_parts() {
    let aead = TestAead::default();
    let built = build_external_part(&aead, b"a private attachment", metadata()).unwrap();
    assert!(matches!(
        consume_external_part(&aead, &built.part, &built.ciphertext, 1_900_000_000),
        Err(ExternalPartError::Expired { .. })
    ));
    assert_eq!(aead.opens.get(), 0, "expired objects must not be opened");

    let mut unencrypted = metadata();
    unencrypted.enc_alg = 0;
    assert_eq!(
        build_external_part(&aead, b"a private attachment", unencrypted),
        Err(ExternalPartError::UnencryptedAlgorithm)
    );
}

#[test]
fn claimed_size_is_checked_before_the_aead_open_call() {
    let aead = TestAead::default();
    let mut built = build_external_part(&aead, b"a private attachment", metadata()).unwrap();
    let PartBody::External { size, .. } = &mut built.part else {
        panic!("builder must return ExternalPart");
    };
    *size -= 1;

    assert!(matches!(
        consume_external_part(&aead, &built.part, &built.ciphertext, 1_800_000_000),
        Err(ExternalPartError::SizeMismatch { .. })
    ));
    assert_eq!(
        aead.opens.get(),
        0,
        "size mismatch must not reach AEAD open"
    );
}
