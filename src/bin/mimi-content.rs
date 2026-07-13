//! mimi-content - a tiny CLI that wraps the REAL mimi-core content-09 codec for the interop CLI.
//!
//! A caller can shell out to this so the content-09 CBOR frame it shows a researcher is
//! produced by the EXACT same KAT-proven codec as `mimi-core::content` (canonical bytes a researcher can
//! diff against the spec) - NOT a separate reimplementation, and without linking mimi-core into
//! any other binary.
//!
//!   mimi-content encode   stdin = plaintext UTF-8        → stdout = deterministic content-09 CBOR
//!   mimi-content decode   stdin = content-09 CBOR        → stdout = the plaintext UTF-8
//!
//! encode wraps the plaintext as a SinglePart (text/plain;charset=utf-8) with a per-message random
//! 16-byte salt (content-09 §4.1 - salt MUST be cryptographically random; read from /dev/urandom to
//! avoid a rand dependency). decode validates nesting + returns the SinglePart body.

use std::io::{Read, Write};

use mimi_core::content::{
    from_content08_cbor, to_content08_cbor, validate_nesting, Disposition, MimiContent, NestedPart,
    PartBody,
};

fn read_stdin() -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

/// 16 cryptographically-random bytes from the OS CSPRNG (content-09 §4.1 salt). No rand crate dep.
fn random_salt() -> anyhow::Result<[u8; 16]> {
    let mut f = std::fs::File::open("/dev/urandom")?;
    let mut salt = [0u8; 16];
    f.read_exact(&mut salt)?;
    Ok(salt)
}

fn encode(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let part = NestedPart {
        disposition: Disposition::Render,
        language: String::new(),
        body: PartBody::Single {
            content_type: "text/plain;charset=utf-8".to_string(),
            content: plaintext.to_vec(),
        },
    };
    validate_nesting(&part)?;
    let content = MimiContent {
        salt: random_salt()?,
        replaces: None,
        topic_id: Vec::new(),
        expires: None,
        in_reply_to: None,
        mimi_extensions: Vec::new(),
        nested_part: part,
    };
    Ok(to_content08_cbor(&content)?)
}

fn decode(cbor: &[u8]) -> anyhow::Result<Vec<u8>> {
    let content: MimiContent = from_content08_cbor(cbor)?;
    validate_nesting(&content.nested_part)?;
    match content.nested_part.body {
        PartBody::Single { content, .. } => Ok(content),
        PartBody::Null => Ok(Vec::new()),
        _ => Err(anyhow::anyhow!(
            "unsupported content body (this CLI handles SinglePart)"
        )),
    }
}

fn main() -> anyhow::Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let input = read_stdin()?;
    let out = match mode.as_str() {
        "encode" => encode(&input)?,
        "decode" => decode(&input)?,
        other => {
            return Err(anyhow::anyhow!(
                "usage: mimi-content <encode|decode>  (got '{other}')"
            ))
        }
    };
    std::io::stdout().write_all(&out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F1 (content-09 §4.1): the per-message salt MUST be cryptographically random. Evidence: encoding
    /// the SAME plaintext twice yields DIFFERENT 16-byte salts (and the resulting frames differ), and a
    /// salt is not the all-zero value. This is the behavioral proof behind the conformance F1 row.
    #[test]
    fn f1_per_message_salt_is_random() {
        let pt = b"identical plaintext";
        let a = encode(pt).unwrap();
        let b = encode(pt).unwrap();
        assert_ne!(
            a, b,
            "same plaintext must not produce identical frames (salt must differ)"
        );

        let ca = from_content08_cbor(&a).unwrap();
        let cb = from_content08_cbor(&b).unwrap();
        assert_ne!(
            ca.salt, cb.salt,
            "two encodes must carry different 16-byte salts"
        );
        assert_ne!(ca.salt, [0u8; 16], "salt must not be the all-zero value");

        // Sanity: despite different salts, the application payload round-trips identically.
        assert_eq!(decode(&a).unwrap(), pt.to_vec());
        assert_eq!(decode(&b).unwrap(), pt.to_vec());
    }
}
