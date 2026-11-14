//! Decode MIMI content documents from another implementation and say whether each re-encodes to the same bytes.
//!
//! ```text
//! cargo run --example content_check -- [--sender <uri> --room <uri>] <file>...
//! ```
//!
//! With `--sender` and `--room`, each document's message ID is derived as sent by that sender in that room, and its
//! `senderUri` and `roomUri` extensions, when it has them, are checked against the two.
//!
//! For each file: what the document holds (its parts, their content types and dispositions, `inReplyTo`), then
//! `same bytes` when encoding the decoded document gives the file back exactly, or where the two first differ. A file
//! that does not decode says why. The exit status is 1 when any file did not decode or did not re-encode the same.

use mimi_core::content::{
    from_content08_cbor, to_content08_cbor, validate_extension_uris, NestedPart, PartBody,
};
use mimi_core::message_id::{derive_message_id, HashAlgorithm, MimiMessage};

type Failure = Box<dyn std::error::Error>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn describe(part: &NestedPart, depth: usize, out: &mut String) {
    let pad = "  ".repeat(depth);
    let head = format!("{pad}{:?}", part.disposition);
    match &part.body {
        PartBody::Null => out.push_str(&format!("{head} null part\n")),
        PartBody::Single {
            content_type,
            content,
        } => out.push_str(&format!(
            "{head} {content_type}: {:?}\n",
            String::from_utf8_lossy(content)
        )),
        PartBody::External {
            content_type,
            url,
            size,
            enc_alg,
            hash_alg,
            content_hash,
            filename,
            ..
        } => out.push_str(&format!(
            "{head} external {content_type} {url} size {size} encAlg {enc_alg} hashAlg {hash_alg} filename {filename:?}\n\
             {pad}  contentHash {}\n",
            hex(content_hash)
        )),
        PartBody::Multi { semantics, parts } => {
            out.push_str(&format!("{head} multipart {semantics:?}, {} parts\n", parts.len()));
            for part in parts {
                describe(part, depth + 1, out);
            }
        }
    }
}

fn check(path: &str, enclosing: Option<(&str, &str)>) -> Result<bool, Failure> {
    let bytes = std::fs::read(path)?;
    let content = match from_content08_cbor(&bytes) {
        Ok(content) => content,
        Err(error) => {
            println!("{path}: {} bytes, does not decode: {error}", bytes.len());
            return Ok(false);
        }
    };
    let mut said = String::new();
    let mut ok = true;
    for (key, value) in &content.mimi_extensions {
        said.push_str(&format!(
            "  extension {}: {:?}\n",
            hex(key),
            String::from_utf8_lossy(value)
        ));
    }
    if let Some((sender, room)) = enclosing {
        let id = derive_message_id(
            HashAlgorithm::Sha256,
            sender.as_bytes(),
            room.as_bytes(),
            &MimiMessage::from_encoded(&bytes)?,
        )?;
        said.push_str(&format!("  message ID {}\n", hex(&id)));
        if let Err(error) = validate_extension_uris(&content.mimi_extensions, sender, room) {
            said.push_str(&format!(
                "  extensions do NOT match the sender and room: {error}\n"
            ));
            ok = false;
        }
    }
    if let Some(to) = &content.in_reply_to {
        said.push_str(&format!("  inReplyTo {}\n", hex(to)));
    }
    describe(&content.nested_part, 1, &mut said);
    let again = to_content08_cbor(&content)?;
    let same = again == bytes;
    let verdict = if same {
        "same bytes".to_owned()
    } else {
        let at = again
            .iter()
            .zip(&bytes)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| again.len().min(bytes.len()));
        format!(
            "DIFFERENT bytes: {} re-encoded against {} read, first difference at offset {at}",
            again.len(),
            bytes.len()
        )
    };
    print!("{path}: {} bytes, decodes, {verdict}\n{said}", bytes.len());
    Ok(same && ok)
}

fn main() -> Result<(), Failure> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut sender = None;
    let mut room = None;
    while args.len() >= 2 && args[0].starts_with("--") {
        let value = args.remove(1);
        match args.remove(0).as_str() {
            "--sender" => sender = Some(value),
            "--room" => room = Some(value),
            other => return Err(format!("unknown option {other}").into()),
        }
    }
    if args.is_empty() || sender.is_some() != room.is_some() {
        return Err("usage: content_check [--sender <uri> --room <uri>] <file>...".into());
    }
    let enclosing = sender.as_deref().zip(room.as_deref());
    let mut all = true;
    for path in &args {
        all &= check(path, enclosing)?;
    }
    if !all {
        std::process::exit(1);
    }
    Ok(())
}
