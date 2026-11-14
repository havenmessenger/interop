//! Decode MIMI content documents from another implementation and say whether each re-encodes to the same bytes.
//!
//! ```text
//! cargo run --example content_check -- <file>...
//! ```
//!
//! For each file: what the document holds (its parts, their content types and dispositions, `inReplyTo`), then
//! `same bytes` when encoding the decoded document gives the file back exactly, or where the two first differ. A file
//! that does not decode says why. The exit status is 1 when any file did not decode or did not re-encode the same.

use mimi_core::content::{from_content08_cbor, to_content08_cbor, NestedPart, PartBody};

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
            filename,
            ..
        } => out.push_str(&format!(
            "{head} external {content_type} {url} size {size} encAlg {enc_alg} hashAlg {hash_alg} filename {filename:?}\n"
        )),
        PartBody::Multi { semantics, parts } => {
            out.push_str(&format!("{head} multipart {semantics:?}, {} parts\n", parts.len()));
            for part in parts {
                describe(part, depth + 1, out);
            }
        }
    }
}

fn check(path: &str) -> Result<bool, Failure> {
    let bytes = std::fs::read(path)?;
    let content = match from_content08_cbor(&bytes) {
        Ok(content) => content,
        Err(error) => {
            println!("{path}: {} bytes, does not decode: {error}", bytes.len());
            return Ok(false);
        }
    };
    let mut said = String::new();
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
    Ok(same)
}

fn main() -> Result<(), Failure> {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        return Err("usage: content_check <file>...".into());
    }
    let mut all = true;
    for path in &paths {
        all &= check(path)?;
    }
    if !all {
        std::process::exit(1);
    }
    Ok(())
}
