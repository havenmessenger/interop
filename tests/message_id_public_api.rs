//! The content-09 §3.3 derivation as a consumer reaches it: through the crate's public API only,
//! with no access to the internal vector tables.

use mimi_core::message_id::{
    derive_message_id, message_id_preimage, HashAlgorithm, MimiMessage, MESSAGE_ID_LEN, SALT_LEN,
};

/// The content-09 "original" instance document, encoded.
const ORIGINAL_MESSAGE_HEX: &str = "87505eed9406c2545547ab6f09f20a18b003f640f6f6a20178206d696d693a\
2f2f6578616d706c652e636f6d2f752f616c6963652d736d6974680278256d696d693a2f2f6578616d706c652e636f6d2f\
722f656e67696e656572696e675f7465616d85016001781e746578742f6d61726b646f776e3b76617269616e743d47464d\
2d4d494d49583948692065766572796f6e652c207765206a75737420736869707065642072656c6561736520322e302e20\
5f5f476f6f642020776f726b5f5f21";

const ORIGINAL_SENDER: &str = "mimi://example.com/u/alice-smith";
const ORIGINAL_ROOM: &str = "mimi://example.com/r/engineering_team";
const ORIGINAL_SALT: [u8; SALT_LEN] = [
    0x5e, 0xed, 0x94, 0x06, 0xc2, 0x54, 0x55, 0x47, 0xab, 0x6f, 0x09, 0xf2, 0x0a, 0x18, 0xb0, 0x03,
];

/// The message ID published with the example.
const ORIGINAL_MESSAGE_ID: &str =
    "017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4";

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[test]
fn derives_the_published_identifier_through_the_public_api() {
    let message = decode_hex(ORIGINAL_MESSAGE_HEX);

    let document = MimiMessage::from_encoded(&message).expect("the example document decodes");
    assert_eq!(
        document.salt(),
        &ORIGINAL_SALT,
        "the salt is read from the document"
    );

    let id = derive_message_id(
        HashAlgorithm::Sha256,
        ORIGINAL_SENDER.as_bytes(),
        ORIGINAL_ROOM.as_bytes(),
        &document,
    )
    .expect("the example URIs are within the length prefix");

    assert_eq!(encode_hex(&id), ORIGINAL_MESSAGE_ID);
    assert_eq!(id.len(), MESSAGE_ID_LEN);
}

/// A consumer deriving with an algorithm this build does not carry can still reach the octets that
/// have to agree.
#[test]
fn preimage_is_reachable_for_a_consumer_supplying_its_own_hash() {
    let message = decode_hex(ORIGINAL_MESSAGE_HEX);

    let preimage = message_id_preimage(
        ORIGINAL_SENDER.as_bytes(),
        ORIGINAL_ROOM.as_bytes(),
        &message,
        &ORIGINAL_SALT,
    )
    .expect("the example URIs are within the length prefix");

    let expected_len =
        4 + ORIGINAL_SENDER.len() + ORIGINAL_ROOM.len() + message.len() + ORIGINAL_SALT.len();
    assert_eq!(preimage.len(), expected_len);
    assert!(preimage.starts_with(&u16::try_from(ORIGINAL_SENDER.len()).unwrap().to_be_bytes()));
    assert!(preimage.ends_with(&ORIGINAL_SALT));
}

/// The salt carried at the head of the encoded message is the same salt supplied as the final term.
#[test]
fn the_salt_appears_both_inside_the_message_and_as_the_final_term() {
    let message = decode_hex(ORIGINAL_MESSAGE_HEX);
    assert_eq!(&message[2..2 + SALT_LEN], &ORIGINAL_SALT);
}
