//! MIMI content documents for another implementation to decode, beyond a single text part.
//!
//! ```text
//! cargo run --example content_fixtures -- <dir>
//! ```
//!
//! Writes three documents to `<dir>`, each as deterministic CBOR (`*.cbor`), and `fixtures.txt` saying what each one
//! holds and the message ID each has as sent by `SENDER` in `ROOM`:
//!
//! - `alternative.cbor`: a multipart/alternative, `chooseOne` over a text/plain and a text/markdown part.
//! - `attachment.cbor`: `processAll` over a text/plain part and an external part for an image, its disposition
//!   `attachment`, with no encryption (`encAlg` 0) and the SHA-256 of the bytes named in `fixtures.txt`.
//! - `reply.cbor`: a text/plain reply whose `inReplyTo` is the message ID of `alternative.cbor`.
//!
//! The salts are fixed so a run always writes the same bytes; a real sender draws each salt at random. Every document
//! is decoded again and re-encoded before it is written, and the run stops if either step does not give it back.

use std::fmt::Write as _;
use std::path::Path;

use mimi_core::content::{
    from_content08_cbor, to_content08_cbor, Disposition, MimiContent, NestedPart, PartBody,
    PartSemantics,
};
use mimi_core::message_id::{derive_message_id, HashAlgorithm, MimiMessage};
use sha2::{Digest, Sha256};

type Failure = Box<dyn std::error::Error>;

const SENDER: &str = "mimi://mimi.havenmessenger.com/u/erin";
const ROOM: &str = "mimi://mimi.havenmessenger.com/r/table";
/// The bytes the attachment's `contentHash` is the SHA-256 of; nothing is stored at its URL.
const ATTACHMENT_BYTES: &[u8] = b"an example attachment for a MIMI content test";

fn text(content_type: &str, body: &str) -> NestedPart {
    NestedPart {
        disposition: Disposition::Render,
        language: "en".into(),
        body: PartBody::Single {
            content_type: content_type.into(),
            content: body.as_bytes().to_vec(),
        },
    }
}

const fn document(salt: u8, in_reply_to: Option<Vec<u8>>, nested_part: NestedPart) -> MimiContent {
    MimiContent {
        salt: [salt; 16],
        replaces: None,
        topic_id: Vec::new(),
        expires: None,
        in_reply_to,
        mimi_extensions: Vec::new(),
        nested_part,
    }
}

fn alternative() -> MimiContent {
    document(
        1,
        None,
        NestedPart {
            disposition: Disposition::Render,
            language: "en".into(),
            body: PartBody::Multi {
                semantics: PartSemantics::ChooseOne,
                parts: vec![
                    text("text/plain;charset=utf-8", "Hello from Haven."),
                    text("text/markdown;charset=utf-8", "Hello from **Haven**."),
                ],
            },
        },
    )
}

fn attachment() -> MimiContent {
    let image = NestedPart {
        disposition: Disposition::Attachment,
        language: String::new(),
        body: PartBody::External {
            content_type: "image/png".into(),
            url: "https://mimi.havenmessenger.com/files/example.png".into(),
            expires: 0,
            size: ATTACHMENT_BYTES.len() as u64,
            enc_alg: 0,
            key: Vec::new(),
            nonce: Vec::new(),
            aad: Vec::new(),
            hash_alg: 1,
            content_hash: Sha256::digest(ATTACHMENT_BYTES).to_vec(),
            description: "An example image".into(),
            filename: "example.png".into(),
        },
    };
    document(
        2,
        None,
        NestedPart {
            disposition: Disposition::Render,
            language: "en".into(),
            body: PartBody::Multi {
                semantics: PartSemantics::ProcessAll,
                parts: vec![
                    text("text/plain;charset=utf-8", "The file is attached."),
                    image,
                ],
            },
        },
    )
}

fn reply(to: Vec<u8>) -> MimiContent {
    document(
        3,
        Some(to),
        text("text/plain;charset=utf-8", "Thanks, got it."),
    )
}

/// Encode `content`, check it decodes to itself and re-encodes to the same bytes, and return the bytes.
fn encoded(content: &MimiContent) -> Result<Vec<u8>, Failure> {
    let bytes = to_content08_cbor(content)?;
    let back = from_content08_cbor(&bytes)?;
    if &back != content || to_content08_cbor(&back)? != bytes {
        return Err("a document did not decode to itself".into());
    }
    Ok(bytes)
}

fn message_id(bytes: &[u8]) -> Result<Vec<u8>, Failure> {
    Ok(derive_message_id(
        HashAlgorithm::Sha256,
        SENDER.as_bytes(),
        ROOM.as_bytes(),
        &MimiMessage::from_encoded(bytes)?,
    )?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<(), Failure> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir] = args.as_slice() else {
        return Err("usage: content_fixtures <dir>".into());
    };
    std::fs::create_dir_all(dir)?;
    let alternative = encoded(&alternative())?;
    let alternative_id = message_id(&alternative)?;
    let attachment = encoded(&attachment())?;
    let reply = encoded(&reply(alternative_id))?;
    let mut notes = format!(
        "sender {SENDER}\nroom {ROOM}\nmessage IDs: SHA-256, as sent by the sender in the room\n\n"
    );
    for (name, bytes, says) in [
        (
            "alternative.cbor",
            &alternative,
            "chooseOne: text/plain \"Hello from Haven.\" | text/markdown \"Hello from **Haven**.\"",
        ),
        (
            "attachment.cbor",
            &attachment,
            "processAll: text/plain \"The file is attached.\" + external image/png, disposition attachment, encAlg 0, \
             hashAlg 1",
        ),
        (
            "reply.cbor",
            &reply,
            "text/plain \"Thanks, got it.\", inReplyTo = the message ID of alternative.cbor",
        ),
    ] {
        std::fs::write(Path::new(dir).join(name), bytes)?;
        writeln!(
            notes,
            "{name}: {} bytes, message ID {}\n  {says}",
            bytes.len(),
            hex(&message_id(bytes)?)
        )?;
    }
    writeln!(
        notes,
        "\nattachment contentHash = SHA-256 of the {} bytes \"{}\": {}",
        ATTACHMENT_BYTES.len(),
        String::from_utf8_lossy(ATTACHMENT_BYTES),
        hex(&Sha256::digest(ATTACHMENT_BYTES))
    )?;
    std::fs::write(Path::new(dir).join("fixtures.txt"), notes)?;
    Ok(())
}
