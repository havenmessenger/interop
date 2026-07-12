//! MIMI content codec (content-09 §4-6).
//!
//! Encodes/decodes the MIMI **content container** (the message body that travels INSIDE the
//! MLS-encrypted application message). This is a client concern: a MIMI *provider* only routes
//! MLS ciphertext and never sees content, so this module does not gate the provider (that lives
//! in `gate`). This is a plain module with no binding-layer integration.
//!
//! ## Determinism - the load-bearing decision
//! content-09 §6.1 mandates **RFC 8949 §4.2.1 core deterministic** encoding - shortest int/length,
//! NO indefinite-length, **bytewise-lexicographic** map-key order - AND explicitly states
//! *"Implementations MUST NOT send MIMI content in RFC7094 'canonical' order"* (the length-first
//! order). 🔴 `ciborium::value::CanonicalValue` implements exactly that FORBIDDEN length-first order,
//! so we never use it. Instead:
//!   - The container is **array-based** (`mimiContent`, `NestedPart` are CBOR arrays - position
//!     ordered, no key-sort question). ciborium's serde path encodes arrays definite-length +
//!     integers/lengths shortest-form (verified in ciborium 0.2.2 source), satisfying those rules.
//!   - The ONLY map is `mimiExtensions`. We sort it ourselves by **§4.2.1 bytewise order**: encode
//!     each key to its deterministic CBOR bytes, then order entries by that byte sequence
//!     lexicographically (NOT length-first). See `encode_extensions_deterministic`.
//!
//! ## Wire conformance
//! `to_content08_cbor`/`from_content08_cbor` build/read the exact §4.1 structure (7-element
//! array, integer enums, FLAT NestedPart per the group-choice splice, null for absent fields) as
//! an explicit ciborium Value tree - `#[derive(Serialize)]` would silently emit a CBOR *map*
//! (0xa7) with field-name keys and string enums, which is not conformant. Structural KATs assert
//! the shape (top byte 0x87, int disposition/cardinality, flat NestedPart, null absents, reject a
//! map-imposter). CDDL Appendix A and Appendix B (examples) are byte-identical between
//! draft-ietf-mimi-content-08 and -09 (diffed both drafts' raw text directly), and the official
//! `examples/*.cbor` vectors carry identical git blob hashes at both drafts' tags in
//! `github.com/ietf-wg-mimi/draft-ietf-mimi-content` - the 08→09 bump is editorial only (Appendix
//! C.11: reference fixes, a `franking_base_secret`→`salt_base_secret` prose rename in §9.2, typo
//! fixes; zero CDDL/wire change). The derive-based `to_deterministic_cbor`/`from_cbor` remain as
//! generic utilities but are NOT the content-09 wire path.
//! CROSS-IMPLEMENTATION CONFORMANT: decode→re-encode of ALL 14 official examples/*.cbor vectors
//! is byte-identical (test `official_ietf_vectors_roundtrip_byte_identical`); the non-mimiContent
//! `implied-original` is asserted-rejected. This official-vector test is what surfaces a
//! non-conformant CBOR *map* encoding or an incorrectly-typed field (e.g. an `expires: u64`
//! where the spec requires `Expiration = [relative, time]`) - a self-tested-only codec would not
//! catch either. The reply-loop guard (§4.1) and the edit/delete authorization check are both
//! proven against this reference data, not merely self-tested.
//!
//! ## Coverage
//! The `MimiContent` container + `NestedPart` (SinglePart/NullPart/MultiPart/ExternalPart) +
//! the §4.2.1 extension-map encoder + determinism KATs (incl. the discriminating
//! §4.2.1-vs-§4.2.3 test), the ≤4 nesting-depth guard (§6.3), the `nohtml`/no-Autolink
//! GFM-MIMI rule (§7.1.1), and the reply-loop guard (§4.1) are all implemented and tested.

use serde::{Deserialize, Serialize};

/// content-09 §5 disposition values (baseDispos). 9–255 reserved/unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Disposition {
    Unspecified = 0,
    Render = 1,
    Reaction = 2,
    Profile = 3,
    Inline = 4,
    Icon = 5,
    Attachment = 6,
    Session = 7,
    Preview = 8,
}

/// content-09 §4.4 MultiPart part-semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PartSemantics {
    ChooseOne = 0,
    SingleUnit = 1,
    ProcessAll = 2,
}

/// content-09 §4.1 Expiration = `[relative: bool, time: uint]`. `relative=false` → `time` is an absolute
/// timestamp; `relative=true` → seconds after receipt. Absent expiry is `null` at the mimiContent level
/// (modeled as `Option<Expiration>`). Verified against `examples/expiring.cbor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expiration {
    pub relative: bool,
    pub time: u64,
}

/// content-09 §6.3: NestedParts MUST NOT nest more than 4 levels deep.
pub const MAX_NEST_DEPTH: usize = 4;

/// Coarse stack-safety bound enforced DURING CBOR deserialize on the untrusted inbound parse path
/// (`from_content08_cbor`). This is NOT the spec depth bound - that is [`MAX_NEST_DEPTH`], enforced
/// precisely in `value_to_nested_part`. This is the defense-in-depth cap that gates `ciborium`'s
/// tree-materialize step at a Haven-owned value instead of leaning on ciborium's incidental default
/// (256). A legal max-depth-4 message nests ~8 CBOR array levels (2·`MAX_NEST_DEPTH` + outer), so 64
/// is 8× headroom (never rejects a conformant message) while being 4× tighter than ciborium's default.
/// WHY at-our-boundary: a dependency default can change on a bump and is invisible to our trust
/// boundary; bounding the recursion here makes parse-time stack-safety explicit and Haven-controlled.
pub const MAX_CBOR_RECURSION_DEPTH: usize = 64;

/// A 16-byte message ID (sender-uri + room-uri + content + salt hash). Opaque here.
pub type MessageId = Vec<u8>;

/// The MIMI content body part. content-09 §4.4 cardinalities (full set).
/// Field names + types are exact per the §4.4 CDDL, verified verbatim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartBody {
    /// NullPart (cardinality 0) - empty content, used for deletions.
    Null,
    /// SinglePart (cardinality 1) - contentType + bytes.
    Single {
        content_type: String,
        content: Vec<u8>,
    },
    /// ExternalPart (cardinality 2) - out-of-band content reference + its AEAD params.
    /// CDDL types are size-bounded: expires u32, size u64, encAlg u16, hashAlg u8, rest bstr/tstr.
    External {
        content_type: String,
        url: String,
        expires: u32,
        size: u64,
        enc_alg: u16,
        key: Vec<u8>,
        nonce: Vec<u8>,
        aad: Vec<u8>,
        hash_alg: u8,
        content_hash: Vec<u8>,
        description: String,
        filename: String,
    },
    /// MultiPart (cardinality 3) - semantics + `[2* NestedPart]` (CDDL requires ≥2 children).
    Multi {
        semantics: PartSemantics,
        parts: Vec<NestedPart>,
    },
}

/// content-09 §4.1 NestedPart = [disposition, language, body].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedPart {
    pub disposition: Disposition,
    pub language: String,
    pub body: PartBody,
}

/// content-09 §4.1 top-level container.
/// `mimiContent = [salt(16), replaces, topicId, expires, inReplyTo, mimiExtensions, nestedPart]`.
/// NOTE: `mimi_extensions` is carried as already-sorted §4.2.1 entries (see
/// `encode_extensions_deterministic`); we keep it as an ordered Vec to control the wire order
/// ourselves rather than relying on a serde map (which would NOT sort per §4.2.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MimiContent {
    pub salt: [u8; 16],
    pub replaces: Option<MessageId>,
    pub topic_id: Vec<u8>,
    pub expires: Option<Expiration>,
    pub in_reply_to: Option<MessageId>,
    /// Extension entries (key-bytes, value-bytes). MUST be §4.2.1-sorted before encoding -
    /// use `sorted_extensions` to enforce it; never push raw + encode.
    pub mimi_extensions: Vec<(Vec<u8>, Vec<u8>)>,
    pub nested_part: NestedPart,
}

/// Encode a value to deterministic CBOR via ciborium's serde path (shortest-int + definite-length;
/// the §4.2.1 rules ciborium gives for free). Does NOT itself sort maps - callers must pre-sort the
/// one map (extensions) via `sorted_extensions`. Returns the CBOR bytes.
pub fn to_deterministic_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, ContentError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| ContentError::Encode(e.to_string()))?;
    Ok(buf)
}

pub fn from_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ContentError> {
    ciborium::de::from_reader(bytes).map_err(|e| ContentError::Decode(e.to_string()))
}

// ── content-09 §4.1 WIRE-CONFORMANT codec ───────────────────────────────────────────────────────────
// The derive(Serialize) on these structs produces CBOR *maps* (field-name keys) and *string* enums,
// which is NOT content-09 (§4.1 mandates a 7-element ARRAY, integer enums, and a FLAT NestedPart where
// the cardinality group is spliced in - CDDL group choice). We therefore build the exact structure as an
// explicit `ciborium::value::Value` tree (ciborium's writer still gives shortest-int + definite-length
// per §6.1/RFC 8949 §4.2.1; map order is ours via sorted_extensions). CDDL fetched verbatim from
// draft-ietf-mimi-content-09.

use ciborium::value::Value;

/// Typed errors for the content-09 codec + validators (`thiserror` per-module enum -
/// the library convention, vs `anyhow` which is app-idiom). Variants are matchable failure CLASSES; the
/// security/conformance-meaningful ones (nesting depth, nohtml) are structured, the bulk type/structure
/// errors carry the precise message as detail.
#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    /// ciborium CBOR encoding failed.
    #[error("CBOR encode failed: {0}")]
    Encode(String),
    /// ciborium CBOR decoding failed (or the recursion bound was exceeded).
    #[error("CBOR decode failed: {0}")]
    Decode(String),
    /// A field/value had the wrong CBOR type (bstr/tstr/array/map/int/bool mismatch).
    #[error("{0}")]
    WrongType(String),
    /// A structural constraint was violated (wrong element count, bad byte length, out-of-range integer).
    #[error("{0}")]
    Structure(String),
    /// An enum/cardinality/semantics discriminant was not recognized.
    #[error("{0}")]
    UnknownDiscriminant(String),
    /// content-09 §6.3: the NestedPart tree nests deeper than the allowed maximum.
    #[error("NestedPart nests deeper than content-09 §6.3 max {0} levels")]
    NestingTooDeep(usize),
    /// content-09 §4.4: a MultiPart must carry ≥2 children.
    #[error("{0}")]
    MultiPartArity(String),
    /// A mimiExtensions constraint (§4.4 unique keys / §6.2 key type+length) was violated.
    #[error("{0}")]
    Extension(String),
    /// content-09 §7.1.1: GFM-MIMI content carried a raw HTML tag (nohtml is MANDATORY).
    #[error("GFM-MIMI content contains a raw HTML tag; content-09 §7.1.1 nohtml is MANDATORY")]
    RawHtmlInGfm,
    /// content-09 §4.1 (F1): an inReplyTo edge would create a reply loop.
    #[error("{0}")]
    ReplyLoop(String),
    /// An inbound application message carried an unsupported content type.
    #[error("{0}")]
    UnsupportedContentType(String),
    /// Body bytes were not valid UTF-8 where the content type requires text.
    #[error("{0}")]
    NotUtf8(String),
    /// content-09 §9.3 (F8): a `replaces` (edit/delete) was attempted by a party other than the original
    /// sender with no authorizing policy.
    #[error("{0}")]
    UnauthorizedReplacement(String),
}

fn opt_id_to_value(id: &Option<MessageId>) -> Value {
    // absent = CBOR null (0xf6), NOT a 0-sentinel
    id.as_ref().map_or(Value::Null, |b| Value::Bytes(b.clone()))
}

fn value_to_opt_id(v: &Value) -> Result<Option<MessageId>, ContentError> {
    match v {
        Value::Null => Ok(None),
        Value::Bytes(b) => {
            // Note: content-09's CDDL is `MessageId = bstr .size 32` -- any other
            // length was silently accepted before this check.
            if b.len() != 32 {
                return Err(ContentError::Structure(format!(
                    "MessageId must be 32 bytes, got {}",
                    b.len()
                )));
            }
            Ok(Some(b.clone()))
        }
        _ => Err(ContentError::WrongType(
            "messageId field must be bstr or null".to_string(),
        )),
    }
}

fn nested_part_to_value(p: &NestedPart) -> Value {
    // NestedPart = [disposition, language, <cardinality + its fields, spliced flat>]
    let mut a = vec![
        Value::Integer((p.disposition as u8).into()),
        Value::Text(p.language.clone()),
    ];
    match &p.body {
        PartBody::Null => a.push(Value::Integer(0u8.into())),
        PartBody::Single {
            content_type,
            content,
        } => {
            a.push(Value::Integer(1u8.into()));
            a.push(Value::Text(content_type.clone()));
            a.push(Value::Bytes(content.clone()));
        }
        PartBody::External {
            content_type,
            url,
            expires,
            size,
            enc_alg,
            key,
            nonce,
            aad,
            hash_alg,
            content_hash,
            description,
            filename,
        } => {
            a.push(Value::Integer(2u8.into()));
            a.push(Value::Text(content_type.clone()));
            a.push(Value::Text(url.clone()));
            a.push(Value::Integer((*expires).into()));
            a.push(Value::Integer((*size).into()));
            a.push(Value::Integer((*enc_alg).into()));
            a.push(Value::Bytes(key.clone()));
            a.push(Value::Bytes(nonce.clone()));
            a.push(Value::Bytes(aad.clone()));
            a.push(Value::Integer((*hash_alg).into()));
            a.push(Value::Bytes(content_hash.clone()));
            a.push(Value::Text(description.clone()));
            a.push(Value::Text(filename.clone()));
        }
        PartBody::Multi { semantics, parts } => {
            a.push(Value::Integer(3u8.into()));
            a.push(Value::Integer((*semantics as u8).into()));
            a.push(Value::Array(
                parts.iter().map(nested_part_to_value).collect(),
            ));
        }
    }
    Value::Array(a)
}

fn mimi_content_to_value(c: &MimiContent) -> Result<Value, ContentError> {
    // extensions: stored entries are pre-encoded deterministic-CBOR key/value bytes (already §4.2.1
    // sorted); decode each back to a Value to place in a real CBOR map, preserving order.
    let mut ext: Vec<(Value, Value)> = Vec::new();
    for (k, v) in &c.mimi_extensions {
        ext.push((
            ciborium::de::from_reader(k.as_slice())
                .map_err(|e| ContentError::Decode(format!("ext key: {e}")))?,
            ciborium::de::from_reader(v.as_slice())
                .map_err(|e| ContentError::Decode(format!("ext val: {e}")))?,
        ));
    }
    Ok(Value::Array(vec![
        Value::Bytes(c.salt.to_vec()),
        opt_id_to_value(&c.replaces),
        Value::Bytes(c.topic_id.clone()),
        // Expiration = [relative: bool, time: uint]
        c.expires.map_or(Value::Null, |e| {
            Value::Array(vec![Value::Bool(e.relative), Value::Integer(e.time.into())])
        }),
        opt_id_to_value(&c.in_reply_to),
        Value::Map(ext),
        nested_part_to_value(&c.nested_part),
    ]))
}

/// Encode `MimiContent` to content-09 §4.1 **wire-conformant** deterministic CBOR (7-element array,
/// integer enums, flat NestedPart, null for absent fields). This is the function the wire/demo uses.
///
/// Defensive on the way out, not just the way in: enforces §6.3/§4.4 nesting (`validate_nesting`) and
/// §4.2.1 extension ordering (`sorted_extensions`) itself rather than trusting the caller already did -
/// `mimi_content_to_value` places `mimi_extensions` on the wire in whatever order it's given.
pub fn to_content08_cbor(c: &MimiContent) -> Result<Vec<u8>, ContentError> {
    validate_nesting(&c.nested_part)?;
    let mut c = c.clone();
    c.mimi_extensions = sorted_extensions(c.mimi_extensions);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&mimi_content_to_value(&c)?, &mut buf)
        .map_err(|e| ContentError::Encode(format!("content-09 encode failed: {e}")))?;
    Ok(buf)
}

fn reencode(v: &Value) -> Result<Vec<u8>, ContentError> {
    let mut b = Vec::new();
    ciborium::ser::into_writer(v, &mut b)
        .map_err(|e| ContentError::Encode(format!("ext re-encode: {e}")))?;
    Ok(b)
}

const fn disposition_from_u8(n: u8) -> Disposition {
    match n {
        1 => Disposition::Render,
        2 => Disposition::Reaction,
        3 => Disposition::Profile,
        4 => Disposition::Inline,
        5 => Disposition::Icon,
        6 => Disposition::Attachment,
        7 => Disposition::Session,
        8 => Disposition::Preview,
        _ => Disposition::Unspecified, // 0 + 9..255 reserved/unknown → Unspecified (lossy for unknown)
    }
}

fn as_u64(v: &Value) -> Result<u64, ContentError> {
    match v {
        Value::Integer(i) => u64::try_from(*i)
            .map_err(|_| ContentError::Structure("integer out of u64 range".to_string())),
        _ => Err(ContentError::WrongType("expected integer".to_string())),
    }
}

fn value_to_nested_part(v: &Value, depth: usize) -> Result<NestedPart, ContentError> {
    // content-09 §6.3 enforced DURING the descent (fail-closed): bail before doing any work at a level
    // past MAX_NEST_DEPTH, so an over-deep tree is rejected as we recurse rather than only by the
    // post-parse validate_nesting walk. `depth` is the level of THIS part (top call passes 1).
    if depth > MAX_NEST_DEPTH {
        return Err(ContentError::NestingTooDeep(MAX_NEST_DEPTH));
    }
    let wrong = |what: &str| ContentError::WrongType(what.to_string());
    let a = v
        .as_array()
        .ok_or_else(|| wrong("NestedPart must be an array"))?;
    if a.len() < 3 {
        return Err(ContentError::Structure(format!(
            "NestedPart needs >=3 elements, got {}",
            a.len()
        )));
    }
    let disposition = disposition_from_u8(as_u64(&a[0])? as u8);
    let language = a[1]
        .as_text()
        .ok_or_else(|| wrong("language must be tstr"))?
        .to_string();
    let card = as_u64(&a[2])?;
    let body = match card {
        0 => PartBody::Null,
        1 => {
            if a.len() != 5 {
                return Err(ContentError::Structure(format!(
                    "SinglePart NestedPart needs 5 elements, got {}",
                    a.len()
                )));
            }
            PartBody::Single {
                content_type: a[3]
                    .as_text()
                    .ok_or_else(|| wrong("contentType tstr"))?
                    .to_string(),
                content: a[4]
                    .as_bytes()
                    .ok_or_else(|| wrong("content bstr"))?
                    .clone(),
            }
        }
        2 => {
            if a.len() != 15 {
                return Err(ContentError::Structure(format!(
                    "ExternalPart NestedPart needs 15 elements, got {}",
                    a.len()
                )));
            }
            PartBody::External {
                content_type: a[3]
                    .as_text()
                    .ok_or_else(|| wrong("contentType"))?
                    .to_string(),
                url: a[4].as_text().ok_or_else(|| wrong("url"))?.to_string(),
                // Note: the CDDL bounds these to `.size 4`/`.size 2`/`.size 1`
                // respectively (u32/u16/u8 range); `as` truncated silently on an out-of-range
                // CBOR integer instead of rejecting it (e.g. expires=4294967296 became 0).
                expires: u32::try_from(as_u64(&a[5])?)
                    .map_err(|_| ContentError::Structure("expires exceeds u32 range".into()))?,
                size: as_u64(&a[6])?,
                enc_alg: u16::try_from(as_u64(&a[7])?)
                    .map_err(|_| ContentError::Structure("encAlg exceeds u16 range".into()))?,
                key: a[8].as_bytes().ok_or_else(|| wrong("key"))?.clone(),
                nonce: a[9].as_bytes().ok_or_else(|| wrong("nonce"))?.clone(),
                aad: a[10].as_bytes().ok_or_else(|| wrong("aad"))?.clone(),
                hash_alg: u8::try_from(as_u64(&a[11])?)
                    .map_err(|_| ContentError::Structure("hashAlg exceeds u8 range".into()))?,
                content_hash: a[12]
                    .as_bytes()
                    .ok_or_else(|| wrong("contentHash"))?
                    .clone(),
                description: a[13]
                    .as_text()
                    .ok_or_else(|| wrong("description"))?
                    .to_string(),
                filename: a[14]
                    .as_text()
                    .ok_or_else(|| wrong("filename"))?
                    .to_string(),
            }
        }
        3 => {
            if a.len() != 5 {
                return Err(ContentError::Structure(format!(
                    "MultiPart NestedPart needs 5 elements, got {}",
                    a.len()
                )));
            }
            let semantics = match as_u64(&a[3])? {
                0 => PartSemantics::ChooseOne,
                1 => PartSemantics::SingleUnit,
                2 => PartSemantics::ProcessAll,
                n => {
                    return Err(ContentError::UnknownDiscriminant(format!(
                        "unknown partSemantics {n}"
                    )))
                }
            };
            let parts_v = a[4]
                .as_array()
                .ok_or_else(|| wrong("MultiPart parts array"))?;
            let mut parts = Vec::with_capacity(parts_v.len());
            for p in parts_v {
                parts.push(value_to_nested_part(p, depth + 1)?);
            }
            PartBody::Multi { semantics, parts }
        }
        n => {
            return Err(ContentError::UnknownDiscriminant(format!(
                "unknown NestedPart cardinality {n}"
            )))
        }
    };
    Ok(NestedPart {
        disposition,
        language,
        body,
    })
}

/// Decode content-09 §4.1 wire-conformant CBOR back to `MimiContent` (inverse of `to_content08_cbor`).
pub fn from_content08_cbor(bytes: &[u8]) -> Result<MimiContent, ContentError> {
    // Bound recursion DURING materialize at a Haven-owned limit (defense-in-depth vs. ciborium's
    // incidental 256 default): an over-deep hostile blob fails closed with a typed error here, before
    // any unbounded tree is built. ciborium returns Err(RecursionLimitExceeded) - not a panic/abort.
    //
    // Note: `from_reader` stops after ONE complete CBOR value and never checks whether
    // the reader has bytes left -- a `Cursor` lets us check the position afterward, so a second
    // (trailing) CBOR item appended to an otherwise-valid vector is rejected rather than silently
    // ignored.
    let mut cursor = std::io::Cursor::new(bytes);
    let v: Value =
        ciborium::de::from_reader_with_recursion_limit(&mut cursor, MAX_CBOR_RECURSION_DEPTH)
            .map_err(|e| {
                ContentError::Decode(format!(
                    "content-09 decode failed (or recursion bound exceeded): {e}"
                ))
            })?;
    if (cursor.position() as usize) != bytes.len() {
        return Err(ContentError::Structure(format!(
            "{} trailing byte(s) after the mimiContent CBOR value",
            bytes.len() - cursor.position() as usize
        )));
    }
    let wrong = |what: &str| ContentError::WrongType(what.to_string());
    let a = v
        .as_array()
        .ok_or_else(|| wrong("mimiContent must be an array"))?;
    if a.len() != 7 {
        return Err(ContentError::Structure(format!(
            "mimiContent must have 7 elements, got {}",
            a.len()
        )));
    }
    let salt_v = a[0].as_bytes().ok_or_else(|| wrong("salt must be bstr"))?;
    if salt_v.len() != 16 {
        return Err(ContentError::Structure(format!(
            "salt must be 16 bytes, got {}",
            salt_v.len()
        )));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(salt_v);
    let mut ext: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    match &a[5] {
        Value::Map(m) => {
            for (k, val) in m {
                ext.push((reencode(k)?, reencode(val)?));
            }
        }
        _ => return Err(wrong("mimiExtensions must be a map")),
    }
    // F3 (§6.2): reject malformed/over-long/duplicate extension keys on receive (fail-closed).
    validate_extensions(&ext)?;
    let nested_part = value_to_nested_part(&a[6], 1)?;
    // F4 (§6.3/§4.4): reject an over-deep or under-filled MultiPart tree on receive.
    validate_nesting(&nested_part)?;
    Ok(MimiContent {
        salt,
        replaces: value_to_opt_id(&a[1])?,
        topic_id: a[2]
            .as_bytes()
            .ok_or_else(|| wrong("topicId must be bstr"))?
            .clone(),
        expires: match &a[3] {
            Value::Null => None,
            Value::Array(ev) => {
                if ev.len() != 2 {
                    return Err(ContentError::Structure(format!(
                        "Expiration must be [relative, time], got {} elems",
                        ev.len()
                    )));
                }
                let relative = match ev[0] {
                    Value::Bool(b) => b,
                    _ => return Err(wrong("Expiration.relative must be a bool")),
                };
                Some(Expiration {
                    relative,
                    time: as_u64(&ev[1])?,
                })
            }
            _ => return Err(wrong("expires must be null or an Expiration array")),
        },
        in_reply_to: value_to_opt_id(&a[4])?,
        mimi_extensions: ext,
        nested_part,
    })
}

/// Sort `mimiExtensions` entries by **RFC 8949 §4.2.1 bytewise-lexicographic order of the encoded
/// key** - NOT the length-first (§4.2.3/RFC7049) order content-09 §6.1 forbids. The key bytes are
/// already the deterministic CBOR encoding of the key, so a plain lexicographic `sort_by` on those
/// byte slices IS §4.2.1. (Contrast: length-first would compare `key.len()` first.)
pub fn sorted_extensions(mut entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
    entries.sort_by(|(k1, _), (k2, _)| k1.as_slice().cmp(k2.as_slice()));
    // dedup-by-key would go here if the spec required unique keys (it does, §4.4: MUST NOT have
    // two extension entries with the same map key) - left to the validator layer (TODO).
    entries
}

/// The GFM-MIMI markdown content-type whose nohtml rule (content-09 §7.1.1) applies.
pub const GFM_MIMI_CONTENT_TYPE: &str = "text/markdown;variant=GFM-MIMI";

// ---- validation (content-09 MUSTs) -----------------------------------------

/// Depth of a NestedPart tree (this part = 1; a Multi adds its deepest child's depth).
fn nested_depth(part: &NestedPart) -> usize {
    match &part.body {
        PartBody::Multi { parts, .. } => 1 + parts.iter().map(nested_depth).max().unwrap_or(0),
        _ => 1,
    }
}

/// content-09 §6.3: NestedParts MUST NOT nest more than [`MAX_NEST_DEPTH`] (4) levels, AND
/// §4.4: a MultiPart MUST carry `[2* NestedPart]` (≥2 children). Validate both, recursively.
///
/// PARSE-TIME stack-safety on the untrusted decode path is NOT provided by this walk (it runs only
/// after the tree is fully materialized). It is provided by `from_content08_cbor` bounding ciborium's
/// materialize with [`MAX_CBOR_RECURSION_DEPTH`] AND `value_to_nested_part` carrying a depth budget
/// that bails past [`MAX_NEST_DEPTH`] during the descent - both fail closed with a typed error before
/// any unbounded recursion. This function is the precise §6.3 (depth) + §4.4 (≥2 children) SPEC
/// assertion on the already-bounded tree: cheap belt-and-suspenders, and the sole carrier of the §4.4
/// child-count check. (Also run on encode to refuse building a non-conformant tree.)
pub fn validate_nesting(part: &NestedPart) -> Result<(), ContentError> {
    let d = nested_depth(part);
    if d > MAX_NEST_DEPTH {
        return Err(ContentError::NestingTooDeep(MAX_NEST_DEPTH));
    }
    fn walk(p: &NestedPart) -> Result<(), ContentError> {
        if let PartBody::Multi { parts, .. } = &p.body {
            if parts.len() < 2 {
                return Err(ContentError::MultiPartArity(format!(
                    "MultiPart has {} child(ren); content-09 §4.4 requires >= 2",
                    parts.len()
                )));
            }
            for c in parts {
                walk(c)?;
            }
        }
        Ok(())
    }
    walk(part)
}

/// content-09 §7.1.1 (F7): for GFM-MIMI markdown, raw HTML tags MUST be rejected (the `nohtml`
/// extension is MANDATORY) and the Autolink extension MUST NOT be supported. We apply this as a
/// receive-side validation on any SinglePart whose contentType is the GFM-MIMI variant. This aligns
/// with Haven's existing CSP/sanitizer posture (INV-CSP-003: HTML is sanitized before any render).
/// Conservative heuristic: reject if a raw HTML tag (`<tag ...>`/`</tag>`) appears. A full markdown
/// parser is the eventual home; this fails-closed in the meantime (over-reject > under-reject).
pub fn validate_gfm_mimi_nohtml(part: &NestedPart) -> Result<(), ContentError> {
    if let PartBody::Single {
        content_type,
        content,
    } = &part.body
    {
        if content_type.eq_ignore_ascii_case(GFM_MIMI_CONTENT_TYPE) {
            let text = String::from_utf8_lossy(content);
            if contains_raw_html_tag(&text) {
                return Err(ContentError::RawHtmlInGfm);
            }
        }
    }
    // recurse into Multi children
    if let PartBody::Multi { parts, .. } = &part.body {
        for c in parts {
            validate_gfm_mimi_nohtml(c)?;
        }
    }
    Ok(())
}

/// Conservative raw-HTML-tag detector: matches `<` followed by an optional `/` and an ASCII letter
/// (tag-name start), up to a closing `>`. Catches `<script>`, `</div>`, `<img ...>`. Does NOT try to
/// be a markdown-aware parser (that's the eventual home) - it fails closed.
fn contains_raw_html_tag(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'/' {
                j += 1;
            }
            if j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                // scan for a closing '>'
                if bytes[j..].contains(&b'>') {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// content-09 §4.1 (F1): a client MUST NOT knowingly create reply sequences that form loops via
/// `inReplyTo`. Given the known `inReplyTo` edges (message_id -> its parent), detect whether adding
/// `new_id -> new_parent` would create a cycle. Returns Err if it would. The codec can't see the
/// whole room graph, so the caller supplies the edges it knows; this is the loop-check unit.
pub fn would_create_reply_loop(
    edges: &std::collections::HashMap<Vec<u8>, Vec<u8>>,
    new_id: &[u8],
    new_parent: &[u8],
) -> Result<(), ContentError> {
    // Walk up from new_parent via existing edges; if we reach new_id, the new edge closes a loop.
    if new_id == new_parent {
        return Err(ContentError::ReplyLoop(
            "inReplyTo loop: a message cannot reply to itself".to_string(),
        ));
    }
    let mut cur = new_parent.to_vec();
    let mut seen = std::collections::HashSet::new();
    while let Some(parent) = edges.get(&cur) {
        if parent.as_slice() == new_id {
            return Err(ContentError::ReplyLoop(
                "inReplyTo loop: new reply would close a cycle".to_string(),
            ));
        }
        if !seen.insert(parent.clone()) {
            // pre-existing cycle in the supplied edges - stop walking (don't hang)
            break;
        }
        cur = parent.clone();
    }
    Ok(())
}

/// content-09 §6.2 (F3): validate the `mimiExtensions` map. Each KEY MUST be either an integer or a
/// text string ≤255 octets, and every text string MUST be valid UTF-8 (§6.2). §4.4: keys MUST be
/// unique. Input is the decoded-but-reencoded entry list (key bytes = the deterministic CBOR encoding
/// of the key Value), so we re-parse each key Value to classify it. Run on receive (a hostile peer can
/// send an over-long / dup / non-UTF-8 key); fail-closed.
pub fn validate_extensions(entries: &[(Vec<u8>, Vec<u8>)]) -> Result<(), ContentError> {
    let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    for (k, _v) in entries {
        // §4.4 unique keys (compare the canonical encoded key bytes).
        if !seen.insert(k.as_slice()) {
            return Err(ContentError::Extension(
                "mimiExtensions has a duplicate key (content-09 §4.4 requires unique keys)"
                    .to_string(),
            ));
        }
        let key_val: Value = ciborium::de::from_reader(k.as_slice()).map_err(|e| {
            ContentError::Extension(format!("extension key is not valid CBOR: {e}"))
        })?;
        match key_val {
            Value::Integer(_) => {} // integer key - always allowed
            Value::Text(s) => {
                // ciborium only yields Value::Text for valid UTF-8, so UTF-8 is guaranteed here; the
                // load-bearing check is the §6.2 octet bound (octets, NOT chars).
                if s.len() > 255 {
                    return Err(ContentError::Extension(format!(
                        "extension text key is {} octets; content-09 §6.2 max is 255",
                        s.len()
                    )));
                }
            }
            other => {
                return Err(ContentError::Extension(format!(
                "extension key must be an integer or text string (content-09 §6.2), got {other:?}"
            )))
            }
        }
    }
    Ok(())
}

/// content-09 §7.1 (F5): the set of content types a receiver MUST be able to receive.
pub const RECEIVABLE_CONTENT_TYPES: [&str; 3] = [
    "application/mimi-content",
    "text/plain;charset=utf-8",
    GFM_MIMI_CONTENT_TYPE, // text/markdown;variant=GFM-MIMI
];

/// The normalized result of receiving a content-typed body (F5). Carries enough to render/store without
/// re-dispatching on the type string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedContent {
    /// A full `application/mimi-content` container (parsed + validated).
    MimiContent(Box<MimiContent>),
    /// `text/plain;charset=utf-8` - validated UTF-8 text.
    PlainText(String),
    /// `text/markdown;variant=GFM-MIMI` - nohtml-validated markdown source.
    GfmMimiMarkdown(String),
}

/// content-09 §7.1 (F5): receive a content-typed body. A conformant receiver MUST accept all three of
/// [`RECEIVABLE_CONTENT_TYPES`]; we parse+validate each and REJECT any other type (fail-closed). The
/// content-type match is case-insensitive on the type/subtype but exact on the required parameters
/// (`charset=utf-8`, `variant=GFM-MIMI`) per the draft's literal strings.
pub fn receive_content(content_type: &str, body: &[u8]) -> Result<ReceivedContent, ContentError> {
    let ct = content_type.trim();
    if ct.eq_ignore_ascii_case("application/mimi-content") {
        let c = from_content08_cbor(body)?; // already validates structure + extensions + nesting
                                            // §7.1.1 nohtml is content-TYPE-scoped, not envelope-scoped: a GFM-MIMI SinglePart can appear
                                            // anywhere inside the decoded tree (e.g. nested under a MultiPart) even though the outer
                                            // content-type here is application/mimi-content, not GFM-MIMI directly. The validator already
                                            // recurses through PartBody::Multi, so one top-level call covers the whole tree.
        validate_gfm_mimi_nohtml(&c.nested_part)?;
        Ok(ReceivedContent::MimiContent(Box::new(c)))
    } else if ct.eq_ignore_ascii_case("text/plain;charset=utf-8") {
        let s = std::str::from_utf8(body).map_err(|e| {
            ContentError::NotUtf8(format!("text/plain body is not valid UTF-8: {e}"))
        })?;
        Ok(ReceivedContent::PlainText(s.to_string()))
    } else if ct.eq_ignore_ascii_case(GFM_MIMI_CONTENT_TYPE) {
        let s = std::str::from_utf8(body)
            .map_err(|e| ContentError::NotUtf8(format!("GFM-MIMI body is not valid UTF-8: {e}")))?;
        // §7.1.1 nohtml applies to GFM-MIMI: reject raw HTML (reuse the F7 validator via a SinglePart).
        let part = NestedPart {
            disposition: Disposition::Render,
            language: String::new(),
            body: PartBody::Single {
                content_type: GFM_MIMI_CONTENT_TYPE.to_string(),
                content: body.to_vec(),
            },
        };
        validate_gfm_mimi_nohtml(&part)?;
        Ok(ReceivedContent::GfmMimiMarkdown(s.to_string()))
    } else {
        Err(ContentError::UnsupportedContentType(format!(
            "unsupported content type {ct:?}; content-09 §7.1 receivable set is {RECEIVABLE_CONTENT_TYPES:?}"
        )))
    }
}

/// What a `replaces` message does to its target (content-09 §9.3): an EDIT (new content) or a
/// RETRACTION (deletion - empty/NullPart body). Used to surface the "edited/retracted" indication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementKind {
    Edit,
    Retraction,
}

/// content-09 §9.3 (F8): authorize a message that `replaces` (edits/deletes) an earlier one. A receiving
/// client MUST NOT allow any party other than the ORIGINAL sender to edit or delete a message, unless a
/// concrete authorization policy permits it. This is the pure authz unit: the replacement's sender URI
/// MUST equal the original message's sender URI (`policy_allows` is the explicit escape for a concrete
/// room policy - default false). Returns the [`ReplacementKind`] so the caller can show the required
/// "edited"/"retracted" indication (the SHOULD in §9.3).
pub fn authorize_replacement(
    original_sender_uri: &str,
    replacement_sender_uri: &str,
    replacement_part: &NestedPart,
    policy_allows: bool,
) -> Result<ReplacementKind, ContentError> {
    if original_sender_uri != replacement_sender_uri && !policy_allows {
        return Err(ContentError::UnauthorizedReplacement(format!(
            "content-09 §9.3: {replacement_sender_uri} may not edit/delete a message from \
             {original_sender_uri} (no authorizing policy)"
        )));
    }
    // A retraction is signalled by an empty/Null body; anything else is an edit.
    let kind = match &replacement_part.body {
        PartBody::Null => ReplacementKind::Retraction,
        PartBody::Single { content, .. } if content.is_empty() => ReplacementKind::Retraction,
        _ => ReplacementKind::Edit,
    };
    Ok(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode WITHOUT `to_content08_cbor`'s defensive nesting/extension-order checks - for tests that
    /// specifically prove the DECODE path enforces §6.3/§4.4 independently of any encode-side guard
    /// (the real encoder has its own `validate_nesting` check, so those tests can no longer produce
    /// an over-deep wire blob through it).
    fn encode_unchecked(c: &MimiContent) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&mimi_content_to_value(c).unwrap(), &mut buf).unwrap();
        buf
    }

    fn sample() -> MimiContent {
        MimiContent {
            salt: [7u8; 16],
            replaces: None,
            topic_id: b"topic".to_vec(),
            expires: Some(Expiration {
                relative: false,
                time: 1_900_000_000,
            }),
            in_reply_to: None,
            mimi_extensions: vec![],
            nested_part: NestedPart {
                disposition: Disposition::Render,
                language: "en".to_string(),
                body: PartBody::Single {
                    content_type: "text/plain;charset=utf-8".to_string(),
                    content: b"hello mimi".to_vec(),
                },
            },
        }
    }

    #[test]
    fn determinism_same_struct_identical_bytes() {
        // Property KAT: the same content MUST encode to byte-identical CBOR every time
        // (no map iteration nondeterminism, no indefinite-length variance).
        let c = sample();
        let a = to_deterministic_cbor(&c).unwrap();
        let b = to_deterministic_cbor(&c).unwrap();
        assert_eq!(a, b, "same MimiContent must encode to identical bytes");
        assert!(!a.is_empty());
    }

    #[test]
    fn roundtrip_preserves_value() {
        let c = sample();
        let bytes = to_deterministic_cbor(&c).unwrap();
        let back: MimiContent = from_cbor(&bytes).unwrap();
        assert_eq!(c, back, "encode→decode must roundtrip");
    }

    // ── content-09 §4.1 WIRE-STRUCTURE KATs (the conformance the determinism tests above DON'T cover) ──

    #[test]
    fn content08_toplevel_is_array_of_7_not_a_map() {
        // §4.1: mimiContent is a 7-element ARRAY → first byte 0x87. The old derive emitted 0xa7 (map).
        let bytes = to_content08_cbor(&sample()).unwrap();
        assert_eq!(
            bytes[0], 0x87,
            "mimiContent MUST be a 7-element CBOR array (0x87), got {:#04x}",
            bytes[0]
        );
    }

    #[test]
    fn content08_no_field_name_strings_on_the_wire() {
        // A map-based encoding would carry the English field names; an array-based one MUST NOT.
        let bytes = to_content08_cbor(&sample()).unwrap();
        for needle in [&b"salt"[..], b"nestedPart", b"topicId", b"disposition"] {
            assert!(
                bytes.windows(needle.len()).all(|w| w != needle),
                "wire bytes must not contain the field name {:?}",
                std::str::from_utf8(needle).unwrap()
            );
        }
    }

    #[test]
    fn content08_nestedpart_is_flat_with_integer_cardinality_and_disposition() {
        // NestedPart = [disposition:int, language:tstr, 1, contentType:tstr, content:bstr] - 5 flat
        // elements, disposition + cardinality are INTEGERS (not "Render"/"Single" strings).
        let bytes = to_content08_cbor(&sample()).unwrap();
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let top = v.as_array().unwrap();
        let np = top[6].as_array().expect("nestedPart is an array");
        assert_eq!(np.len(), 5, "SinglePart NestedPart is flat with 5 elements");
        assert!(
            matches!(np[0], Value::Integer(_)),
            "disposition is an integer"
        );
        assert_eq!(as_u64(&np[0]).unwrap(), 1, "Render == 1");
        assert!(matches!(np[1], Value::Text(_)), "language is tstr");
        assert_eq!(as_u64(&np[2]).unwrap(), 1, "cardinality single == 1");
        assert!(matches!(np[4], Value::Bytes(_)), "content is bstr");
    }

    #[test]
    fn content08_absent_fields_are_cbor_null() {
        // replaces/expires/inReplyTo absent → CBOR null (0xf6), not 0 and not omitted.
        let mut c = sample();
        c.expires = None;
        let bytes = to_content08_cbor(&c).unwrap();
        let v: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        let top = v.as_array().unwrap();
        assert!(matches!(top[1], Value::Null), "replaces absent → null");
        assert!(matches!(top[3], Value::Null), "expires absent → null");
        assert!(matches!(top[4], Value::Null), "inReplyTo absent → null");
    }

    #[test]
    fn content08_roundtrip_identity() {
        let c = sample();
        let bytes = to_content08_cbor(&c).unwrap();
        let back = from_content08_cbor(&bytes).unwrap();
        assert_eq!(c, back, "content-09 encode→decode must roundtrip");
        // and re-encode is byte-identical (determinism on the conformant path)
        assert_eq!(
            bytes,
            to_content08_cbor(&back).unwrap(),
            "re-encode must be byte-identical"
        );
    }

    #[test]
    fn content08_rejects_a_map_encoded_imposter() {
        // A map-shaped "content-09" (the old bug's output) MUST be rejected by the conformant decoder.
        let bytes = to_deterministic_cbor(&sample()).unwrap(); // derive path → map
        assert_eq!(
            bytes[0], 0xa7,
            "sanity: derive path is the non-conformant map"
        );
        assert!(
            from_content08_cbor(&bytes).is_err(),
            "conformant decoder must reject a map"
        );
    }

    // ── CROSS-IMPLEMENTATION VERIFICATION against the OFFICIAL IETF test vectors ─────────────────────
    // These are the verbatim bytes from the draft-ietf-mimi-content examples/ directory
    // (github.com/ietf-wg-mimi/draft-ietf-mimi-content). Every file in examples/ carries an
    // identical git blob hash at both the draft-ietf-mimi-content-08 and -09 tags, so these bytes
    // are the vectors for either draft revision. Round-tripping them through our codec - decode
    // the official bytes, then re-encode - and asserting BYTE-IDENTICAL output proves our codec
    // is canonical-compatible with the reference implementation, not just self-consistent.

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// All 14 mimiContent vectors from examples/ (the 15th, implied-original, is a DIFFERENT structure -
    /// asserted-rejected below). Coverage: SinglePart (text/markdown, text/plain, html), NullPart
    /// (delete/unlike), ExternalPart 13-field (attachment, conferencing), recursive MultiPart
    /// (multipart-1/2/3), every disposition seen in the suite, extensions {1,2}, set/null replaces &
    /// expires & inReplyTo, emoji + unicode content.
    const OFFICIAL_VECTORS: &[(&str, &str)] = &[
        ("attachment", "875018fac6371e4e53f1aeaf8a013155c166f640f6f6a201781e6d696d693a2f2f6578616d706c652e636f6d2f752f626f622d6a6f6e65730278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d8f0662656e0269766964656f2f6d7034782b68747470733a2f2f6578616d706c652e636f6d2f73746f726167652f386b7342346253727252452e6d7034001a2a36ced1015021399320958a6f4c745dde670d95e0d84cc86cf2c33f21527d1dd76f5b400158209ab17a8cf0890baaae7ee016c7312fcc080ba46498389458ee44f0276e783163781c3220686f757273206f66206b6579207369676e696e6720766964656f6b62696766696c652e6d7034"),
        ("conferencing", "8750678ac6cd54de049c3e9665cd212470faf647466f6f20313138f6f6a20178206d696d693a2f2f6578616d706c652e636f6d2f752f616c6963652d736d6974680278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d8f07600260781e68747470733a2f2f6578616d706c652e636f6d2f6a6f696e2f31323334350000004040400040781b4a6f696e2074686520466f6f2031313820636f6e666572656e636560"),
        ("delete", "87500a590d73b2c7761c39168be5ebf7f2e65820015354973c2b65ca937bf1e035ae53a5ab80e947afa43d46920d4202e5cc0b2740f65820017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4a201781e6d696d693a2f2f6578616d706c652e636f6d2f752f626f622d6a6f6e65730278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d83016000"),
        ("edit", "8750b8c2e6d8800ecf45df39be6c45f4c0425820015354973c2b65ca937bf1e035ae53a5ab80e947afa43d46920d4202e5cc0b2740f65820017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4a201781e6d696d693a2f2f6578616d706c652e636f6d2f752f626f622d6a6f6e65730278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d85016001781e746578742f6d61726b646f776e3b76617269616e743d47464d2d4d494d4958225269676874206f6e21205f436f6e67726174756c6174696f6e735f207927616c6c21"),
        ("expiring", "875033be993eb39f418f9295afc2ae160d2df64082f41a62036674f6a20178206d696d693a2f2f6578616d706c652e636f6d2f752f616c6963652d736d6974680278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d85016001781e746578742f6d61726b646f776e3b76617269616e743d47464d2d4d494d4958505f5f2a56504e20474f494e4720444f574e2a5f5f2049276d207265626f6f74696e67207468652056504e20696e2074656e206d696e7574657320756e6c65737320616e796f6e65206f626a656374732e"),
        ("mention", "875004f290e215d0f82d1750bfa8b7dc089df640f65820017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4a20178256d696d693a2f2f6578616d706c652e636f6d2f752f63617468792d77617368696e67746f6e0278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d85016001781e746578742f6d61726b646f776e3b76617269616e743d47464d2d4d494d4958584b75646f7320746f205b40416c69636520536d6974685d286d696d693a2f2f6578616d706c652e636f6d2f752f616c6963652d736d6974682920666f72206d616b696e67207468652072656c656173652068617070656e21"),
        ("mention-html", "875015d9705fd5bf5e02b0af47c85f8b98fef640f65820017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4a20178256d696d693a2f2f6578616d706c652e636f6d2f752f63617468792d77617368696e67746f6e0278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d8501600177746578742f68746d6c3b636861727365743d7574662d38586a3c703e4b75646f7320746f203c6120687265663d226d696d693a2f2f6578616d706c652e636f6d2f752f616c6963652d736d697468223e40416c69636520536d6974683c2f613e20666f72206d616b696e67207468652072656c656173652068617070656e213c2f703e"),
        ("multipart-1", "8750261c953e178af653fe3d42641b91d814f640f6f6a20178206d696d693a2f2f6578616d706c652e636f6d2f752f616c6963652d736d6974680278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d85016003008285016001781e746578742f6d61726b646f776e3b76617269616e743d47464d2d4d494d494a232057656c636f6d652185016001782e6170706c69636174696f6e2f766e642e6578616d706c6576656e646f722d66616e63792d696d2d6d6573736167654fdc861ebaa718fd7c3ca159f71a2001"),
        ("multipart-2", "87508528dc2d92e4f1944d62042907ab94d0f640f6f6a20178206d696d693a2f2f6578616d706c652e636f6d2f752f616c6963652d736d6974680278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d850260030283850260017818746578742f706c61696e3b636861727365743d7574662d3843e29da4850260017818746578742f706c61696e3b636861727365743d7574662d3844f09fa5b3850260017818746578742f706c61696e3b636861727365743d7574662d3844f09fa49e"),
        ("multipart-3", "8750b8362793168d18c049b882d4642a2274f640f6f6a20178206d696d693a2f2f6578616d706c652e636f6d2f752f616c6963652d736d6974680278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d850160030082850160030282850160030082850162656e0177746578742f68746d6c3b636861727365743d7574662d3858613c68746d6c3e3c626f64793e3c68313e57656c636f6d65213c2f68313e0a3c696d67207372633d226369643a35406c6f63616c2e696e76616c69642220616c743d2257656c636f6d6520696d616765222f3e0a3c2f626f64793e3c2f68746d6c3e85016266720177746578742f68746d6c3b636861727365743d7574662d3858653c68746d6c3e3c626f64793e3c68313e4269656e76656e7565213c2f68313e0a3c696d67207372633d226369643a35406c6f63616c2e696e76616c69642220616c743d22496d616765206269656e76656e7565222f3e0a3c2f626f64793e3c2f68746d6c3e8504600169696d6167652f67696650dc861ebaa718fd7c3ca159f71a2001a7850160030282850160030082850162656e0177746578742f68746d6c3b636861727365743d7574662d3858623c68746d6c3e3c626f64793e3c68313e57656c636f6d65213c2f68313e0a3c696d67207372633d226369643a3130406c6f63616c2e696e76616c69642220616c743d2257656c636f6d6520696d616765222f3e0a3c2f626f64793e3c2f68746d6c3e85016266720177746578742f68746d6c3b636861727365743d7574662d3858663c68746d6c3e3c626f64793e3c68313e4269656e76656e7565213c2f68313e0a3c696d67207372633d226369643a3130406c6f63616c2e696e76616c69642220616c743d22496d616765206269656e76656e7565222f3e0a3c2f626f64793e3c2f68746d6c3e8504600169696d6167652f706e6750fa444237451a05a72bb0f67037cc1669"),
        ("original", "87505eed9406c2545547ab6f09f20a18b003f640f6f6a20178206d696d693a2f2f6578616d706c652e636f6d2f752f616c6963652d736d6974680278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d85016001781e746578742f6d61726b646f776e3b76617269616e743d47464d2d4d494d49583948692065766572796f6e652c207765206a75737420736869707065642072656c6561736520322e302e205f5f476f6f642020776f726b5f5f21"),
        ("reaction", "8750d37bc0e6a8b4f04e9e6382375f587bf6f640f65820017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4a20178256d696d693a2f2f6578616d706c652e636f6d2f752f63617468792d77617368696e67746f6e0278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d850260017818746578742f706c61696e3b636861727365743d7574662d3843e29da4"),
        ("reply", "875011a458c73b8dd2cf404db4b378b8fe4df640f65820017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4a201781e6d696d693a2f2f6578616d706c652e636f6d2f752f626f622d6a6f6e65730278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d85016001781e746578742f6d61726b646f776e3b76617269616e743d47464d2d4d494d4958215269676874206f6e21205f436f6e67726174756c6174696f6e735f2027616c6c21"),
        ("unlike", "8750c5ba86dc9fd272e58ca52ec805b7919958200158c4288911e50a8f6be3f47746b6682f10fd91bc8c05557aa589a3157aff6840f65820017ce54837404c3696e0c747b985cb172716d0ed0a3d249ca63ace7d82a096f4a20178256d696d693a2f2f6578616d706c652e636f6d2f752f63617468792d77617368696e67746f6e0278256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d83026000"),
    ];

    #[test]
    fn official_ietf_vectors_roundtrip_byte_identical() {
        // CROSS-IMPL PROOF: decode each official reference vector, re-encode, demand byte-identical.
        for (name, hex) in OFFICIAL_VECTORS {
            let official = unhex(hex);
            assert_eq!(
                official[0], 0x87,
                "{name}: official vector is a 7-element array"
            );
            let decoded = from_content08_cbor(&official)
                .unwrap_or_else(|e| panic!("{name}: failed to DECODE the official vector: {e}"));
            let reencoded = to_content08_cbor(&decoded)
                .unwrap_or_else(|e| panic!("{name}: failed to RE-ENCODE: {e}"));
            assert_eq!(
                official, reencoded,
                "{name}: re-encoded bytes MUST equal the official IETF vector byte-for-byte"
            );
        }
    }

    #[test]
    fn content08_decode_rejects_trailing_cbor_byte() {
        // Note: from_reader stops after one CBOR value; a second (trailing) item
        // appended to an otherwise-valid vector must now be rejected, not silently ignored.
        let mut bytes = to_content08_cbor(&sample()).unwrap();
        assert!(from_content08_cbor(&bytes).is_ok(), "sanity: valid alone");
        bytes.push(0x00);
        assert!(
            from_content08_cbor(&bytes).is_err(),
            "a trailing CBOR item must be rejected"
        );
    }

    #[test]
    fn content08_decode_rejects_wrong_length_message_id() {
        // Note: content-09's CDDL is `MessageId = bstr .size 32`.
        let mut v: Value =
            ciborium::de::from_reader(to_content08_cbor(&sample()).unwrap().as_slice()).unwrap();
        let top = v.as_array_mut().unwrap();
        top[1] = Value::Bytes(vec![0u8; 31]); // replaces: one byte short
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&v, &mut bytes).unwrap();
        assert!(
            from_content08_cbor(&bytes).is_err(),
            "a 31-byte MessageId must be rejected"
        );
    }

    #[test]
    fn content08_decode_rejects_external_part_expires_out_of_u32_range() {
        // Note: `expires: uint .size 4` (u32 range); a CBOR integer wider than that
        // must be rejected, not silently truncated: under the old `as u32` cast,
        // 4294967296 == 2**32 silently became 0.
        let ext = NestedPart {
            disposition: Disposition::Attachment,
            language: "en".to_string(),
            body: PartBody::External {
                content_type: "image/png".to_string(),
                url: "https://assets.example/x".to_string(),
                expires: 1_000, // placeholder; overwritten below via raw CBOR
                size: 4096,
                enc_alg: 1,
                key: vec![1; 16],
                nonce: vec![2; 12],
                aad: vec![],
                hash_alg: 1,
                content_hash: vec![3; 32],
                description: "a picture".to_string(),
                filename: "x.png".to_string(),
            },
        };
        let mut c = sample();
        c.nested_part = ext;
        let mut v: Value =
            ciborium::de::from_reader(to_content08_cbor(&c).unwrap().as_slice()).unwrap();
        let top = v.as_array_mut().unwrap();
        let np = top[6].as_array_mut().expect("nestedPart is an array");
        // NestedPart(External) = [disposition, language, cardinality, contentType, url, expires, ...]
        assert_eq!(np[5], Value::Integer(1_000.into()), "sanity: expires slot");
        np[5] = Value::Integer(4_294_967_296i64.into()); // 2**32, one past u32::MAX
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&v, &mut bytes).unwrap();
        assert!(
            from_content08_cbor(&bytes).is_err(),
            "an expires value exceeding u32::MAX must be rejected, not truncated"
        );
    }

    #[test]
    fn implied_original_is_not_a_mimicontent_and_is_rejected() {
        // examples/implied-original.cbor is a DIFFERENT structure (messageId, timestamp, mlsGroupId,
        // senderLeafIndex, urls) - first element is a 32-byte bstr, not the 16-byte salt. Our decoder
        // MUST reject it (proves salt-size validation isn't just decorative).
        let implied = unhex("87582001b0084467273cc43d6f0ebeac13eb84229c4fffe8f6c3594c905f47779e5a791b0000017edd1dcdbb5820eeee0d12a7b5b5b78115ad1a1ddb13811c83fd7387c43e66799a594beeda26bf04783e6d696d693a2f2f6578616d706c652e636f6d2f642f33623532323439642d363866392d343563652d386266352d6337393966336361643765632f3030303378206d696d693a2f2f6578616d706c652e636f6d2f752f616c6963652d736d69746878256d696d693a2f2f6578616d706c652e636f6d2f722f656e67696e656572696e675f7465616d");
        assert!(
            from_content08_cbor(&implied).is_err(),
            "implied-original is not a mimiContent (32-byte first element) - must be rejected"
        );
    }

    #[test]
    fn shortest_int_and_definite_length() {
        // content-09 §6.1: shortest int + definite length. A small int (expires fits in fewer
        // bytes when small) and no 0x9f/0xbf (indefinite array/map start markers) anywhere.
        let mut c = sample();
        c.expires = Some(Expiration {
            relative: false,
            time: 10,
        }); // time 10 → single byte 0x0a
        let bytes = to_deterministic_cbor(&c).unwrap();
        assert!(
            bytes.contains(&0x0a),
            "small int must use shortest (1-byte) form"
        );
        assert!(
            !bytes.contains(&0x9f) && !bytes.contains(&0xbf),
            "no indefinite-length array (0x9f) or map (0xbf) markers allowed"
        );
    }

    #[test]
    fn extensions_sort_is_4_2_1_bytewise_not_4_2_3_length_first() {
        // THE DISCRIMINATING TEST. Pick two keys that sort DIFFERENTLY under the two orders:
        //   key A = [0x00, 0x00]  (2 bytes)
        //   key B = [0x01]        (1 byte)
        // §4.2.1 bytewise: compare byte-by-byte → A(0x00..) < B(0x01) → order [A, B].
        // §4.2.3 length-first (FORBIDDEN): shorter first → B(len1) < A(len2) → order [B, A].
        // We MUST produce [A, B].
        let key_a = vec![0x00u8, 0x00];
        let key_b = vec![0x01u8];
        let unsorted = vec![
            (key_b.clone(), b"vb".to_vec()),
            (key_a.clone(), b"va".to_vec()),
        ];
        let sorted = sorted_extensions(unsorted);
        assert_eq!(
            sorted[0].0, key_a,
            "§4.2.1 bytewise: [0x00,0x00] must sort BEFORE [0x01] (we must NOT use the forbidden \
             length-first order, which would put the 1-byte key first)"
        );
        assert_eq!(sorted[1].0, key_b);
    }

    fn single(ct: &str, body: &[u8]) -> NestedPart {
        NestedPart {
            disposition: Disposition::Render,
            language: "en".to_string(),
            body: PartBody::Single {
                content_type: ct.to_string(),
                content: body.to_vec(),
            },
        }
    }

    fn multi(children: Vec<NestedPart>) -> NestedPart {
        NestedPart {
            disposition: Disposition::Unspecified,
            language: "en".to_string(),
            body: PartBody::Multi {
                semantics: PartSemantics::ProcessAll,
                parts: children,
            },
        }
    }

    #[test]
    fn external_part_roundtrips() {
        let ext = NestedPart {
            disposition: Disposition::Attachment,
            language: "en".to_string(),
            body: PartBody::External {
                content_type: "image/png".to_string(),
                url: "https://assets.example/x".to_string(),
                expires: 1_900_000_000,
                size: 4096,
                enc_alg: 1,
                key: vec![1; 16],
                nonce: vec![2; 12],
                aad: vec![],
                hash_alg: 1,
                content_hash: vec![3; 32],
                description: "a picture".to_string(),
                filename: "x.png".to_string(),
            },
        };
        let mut c = sample();
        c.nested_part = ext.clone();
        let back: MimiContent = from_cbor(&to_deterministic_cbor(&c).unwrap()).unwrap();
        assert_eq!(
            back.nested_part, ext,
            "ExternalPart (13 fields) must roundtrip exactly"
        );
    }

    #[test]
    fn nesting_depth_guard() {
        // depth 1 (single) ok; build progressively deeper Multi trees.
        assert!(validate_nesting(&single("text/plain", b"x")).is_ok());
        // depth 4: multi(multi(multi(single,single),..),..) - exactly at the limit, OK.
        let d2 = multi(vec![single("text/plain", b"a"), single("text/plain", b"b")]);
        let d3 = multi(vec![d2.clone(), single("text/plain", b"c")]);
        let d4 = multi(vec![d3.clone(), single("text/plain", b"d")]);
        assert_eq!(nested_depth(&d4), 4);
        assert!(
            validate_nesting(&d4).is_ok(),
            "depth 4 is the max, must pass"
        );
        // depth 5: one deeper - must be rejected (§6.3).
        let d5 = multi(vec![d4.clone(), single("text/plain", b"e")]);
        assert!(
            validate_nesting(&d5).is_err(),
            "depth 5 must be rejected (§6.3 max 4)"
        );
    }

    #[test]
    fn multipart_requires_two_children() {
        let one_child = multi(vec![single("text/plain", b"only")]);
        assert!(
            validate_nesting(&one_child).is_err(),
            "MultiPart with <2 children must be rejected (§4.4 [2* NestedPart])"
        );
    }

    #[test]
    fn content08_decode_rejects_overdeep_nestedpart_during_parse() {
        // §6.3 depth must be enforced DURING the decode descent, not only by
        // the post-parse validate_nesting walk. Build a depth-5 tree, encode it (the encoder has no
        // depth guard), and prove the WIRE DECODE path rejects it - fail-closed, no panic.
        let d2 = multi(vec![single("text/plain", b"a"), single("text/plain", b"b")]);
        let d3 = multi(vec![d2, single("text/plain", b"c")]);
        let d4 = multi(vec![d3, single("text/plain", b"d")]);
        let d5 = multi(vec![d4.clone(), single("text/plain", b"e")]);

        let mut overdeep = sample();
        overdeep.nested_part = d5;
        // to_content08_cbor now validates nesting itself (M4) and would refuse this - bypass it to
        // still prove the DECODE path enforces §6.3 independently, per this test's own purpose.
        let bytes = encode_unchecked(&overdeep);
        assert!(
            from_content08_cbor(&bytes).is_err(),
            "a depth-5 NestedPart must be rejected by the decoder (§6.3 max 4)"
        );

        // Conformance boundary: depth-4 (the legal max) MUST still decode - don't reject valid input.
        let mut legal = sample();
        legal.nested_part = d4;
        let ok_bytes = to_content08_cbor(&legal).unwrap();
        assert!(
            from_content08_cbor(&ok_bytes).is_ok(),
            "a depth-4 NestedPart (the legal max) must still decode"
        );
    }

    #[test]
    fn content08_decode_rejects_overdeep_raw_cbor_without_abort() {
        // A hostile blob of deeply-nested raw CBOR arrays must fail closed
        // at the recursion bound DURING materialize (not exhaust the stack). 200 nested 1-element
        // arrays exceed MAX_CBOR_RECURSION_DEPTH; the call must RETURN an Err (ciborium yields a typed
        // RecursionLimitExceeded), never panic/abort.
        let mut hostile = vec![0x81u8; MAX_CBOR_RECURSION_DEPTH * 2]; // nested array-of-1 headers, 2× the bound
        hostile.push(0x00); // innermost scalar
        assert!(
            from_content08_cbor(&hostile).is_err(),
            "an over-deep raw-CBOR blob must fail closed at the recursion bound, not exhaust the stack"
        );
    }

    #[test]
    fn gfm_mimi_rejects_raw_html() {
        let bad = single(GFM_MIMI_CONTENT_TYPE, b"hello <script>alert(1)</script>");
        assert!(
            validate_gfm_mimi_nohtml(&bad).is_err(),
            "raw HTML in GFM-MIMI must be rejected"
        );
        let bad2 = single(GFM_MIMI_CONTENT_TYPE, b"text with <img src=x> embedded");
        assert!(
            validate_gfm_mimi_nohtml(&bad2).is_err(),
            "raw img tag must be rejected"
        );
        // clean markdown passes
        let ok = single(
            GFM_MIMI_CONTENT_TYPE,
            b"# Heading\n\n**bold** and a < b comparison",
        );
        assert!(
            validate_gfm_mimi_nohtml(&ok).is_ok(),
            "'< b' (not a tag) must pass; clean md ok"
        );
        // plain text is not subject to the nohtml rule
        let plain = single("text/plain;charset=utf-8", b"<not checked here>");
        assert!(
            validate_gfm_mimi_nohtml(&plain).is_ok(),
            "non-GFM-MIMI is not nohtml-checked"
        );
    }

    #[test]
    fn receive_content_mimi_content_rejects_nested_gfm_raw_html() {
        // M4: application/mimi-content's receive branch must apply the nohtml rule to whatever's
        // INSIDE the decoded tree, not just top-level GFM-MIMI bodies received directly. Build a
        // MimiContent whose nested_part is a MultiPart containing a GFM-MIMI child with raw HTML.
        let mut c = sample();
        c.nested_part = multi(vec![
            single("text/plain;charset=utf-8", b"plain sibling"),
            single(GFM_MIMI_CONTENT_TYPE, b"hello <script>alert(1)</script>"),
        ]);
        let bytes = to_content08_cbor(&c).unwrap();
        let err = receive_content("application/mimi-content", &bytes).unwrap_err();
        assert!(
            matches!(err, ContentError::RawHtmlInGfm),
            "a GFM-MIMI child nested under application/mimi-content must still be nohtml-checked, got {err:?}"
        );
    }

    #[test]
    fn receive_content_mimi_content_accepts_clean_nested_gfm() {
        let mut c = sample();
        c.nested_part = multi(vec![
            single("text/plain;charset=utf-8", b"plain sibling"),
            single(GFM_MIMI_CONTENT_TYPE, b"clean **markdown**"),
        ]);
        let bytes = to_content08_cbor(&c).unwrap();
        assert!(receive_content("application/mimi-content", &bytes).is_ok());
    }

    #[test]
    fn to_content08_cbor_rejects_overdeep_nesting_defensively() {
        // M4: to_content08_cbor must not trust the caller pre-validated nesting - build a tree past
        // MAX_NEST_DEPTH directly (bypassing any builder-side check) and confirm encode itself refuses.
        let mut deepest = single("text/plain;charset=utf-8", b"leaf");
        for _ in 0..MAX_NEST_DEPTH + 2 {
            deepest = multi(vec![
                deepest,
                single("text/plain;charset=utf-8", b"sibling"),
            ]);
        }
        let mut c = sample();
        c.nested_part = deepest;
        assert!(
            to_content08_cbor(&c).is_err(),
            "encode must refuse a tree deeper than MAX_NEST_DEPTH, not trust the caller"
        );
    }

    #[test]
    fn to_content08_cbor_sorts_extensions_defensively() {
        // M4: to_content08_cbor must not trust mimi_extensions arrived pre-sorted - pass entries in
        // deliberately wrong order and confirm the encoded bytes match the sorted-first encoding.
        let key_a = to_deterministic_cbor(&Value::Integer(1.into())).unwrap();
        let key_b = to_deterministic_cbor(&Value::Integer(2.into())).unwrap();
        let val = to_deterministic_cbor(&Value::Bool(true)).unwrap();
        let mut unsorted = sample();
        unsorted.mimi_extensions = vec![(key_b.clone(), val.clone()), (key_a.clone(), val.clone())];
        let mut presorted = sample();
        presorted.mimi_extensions = vec![(key_a, val.clone()), (key_b, val)];
        assert_eq!(
            to_content08_cbor(&unsorted).unwrap(),
            to_content08_cbor(&presorted).unwrap(),
            "encode must sort extensions itself regardless of input order"
        );
    }

    #[test]
    fn reply_loop_guard() {
        use std::collections::HashMap;
        // Existing chain: B -> A (B replies to A).
        let mut edges: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        edges.insert(b"B".to_vec(), b"A".to_vec());
        // New C -> B is fine (no loop).
        assert!(would_create_reply_loop(&edges, b"C", b"B").is_ok());
        // New A -> B would close A->B->A : loop.
        assert!(
            would_create_reply_loop(&edges, b"A", b"B").is_err(),
            "A replying to B when B->A exists closes a cycle"
        );
        // Self-reply is a loop.
        assert!(would_create_reply_loop(&edges, b"X", b"X").is_err());
        // Pre-existing cycle in supplied edges must not hang (terminates).
        edges.insert(b"P".to_vec(), b"Q".to_vec());
        edges.insert(b"Q".to_vec(), b"P".to_vec());
        let _ = would_create_reply_loop(&edges, b"Z", b"P"); // must return, not loop forever
    }

    #[test]
    fn extension_order_is_stable_in_the_container() {
        // Two containers whose extensions were inserted in opposite orders must encode identically
        // once both go through sorted_extensions - the determinism guarantee for the one map.
        let a_first = sorted_extensions(vec![
            (vec![0x00, 0x00], b"x".to_vec()),
            (vec![0x01], b"y".to_vec()),
        ]);
        let b_first = sorted_extensions(vec![
            (vec![0x01], b"y".to_vec()),
            (vec![0x00, 0x00], b"x".to_vec()),
        ]);
        let mut c1 = sample();
        c1.mimi_extensions = a_first;
        let mut c2 = sample();
        c2.mimi_extensions = b_first;
        assert_eq!(
            to_deterministic_cbor(&c1).unwrap(),
            to_deterministic_cbor(&c2).unwrap(),
            "insertion order must not affect encoded bytes after sorted_extensions"
        );
    }

    // ---- C2: content-format completeness (F3/F5/F8) ----

    /// Encode a CBOR `Value` to its bytes (to build well-formed extension keys in tests).
    fn cbor(v: Value) -> Vec<u8> {
        let mut b = Vec::new();
        ciborium::ser::into_writer(&v, &mut b).unwrap();
        b
    }

    #[test]
    fn f3_extension_keys_int_or_short_text_unique() {
        // integer key + short text key = OK.
        let ok = vec![
            (cbor(Value::Integer(1.into())), b"v1".to_vec()),
            (cbor(Value::Text("k".into())), b"v2".to_vec()),
        ];
        assert!(
            validate_extensions(&ok).is_ok(),
            "int + short text keys accepted"
        );

        // text key > 255 octets = rejected.
        let long = vec![(cbor(Value::Text("a".repeat(256))), b"v".to_vec())];
        assert!(
            validate_extensions(&long).is_err(),
            "256-octet text key rejected (§6.2 max 255)"
        );
        let edge = vec![(cbor(Value::Text("a".repeat(255))), b"v".to_vec())];
        assert!(
            validate_extensions(&edge).is_ok(),
            "exactly 255 octets is allowed"
        );

        // non-int/non-text key (e.g. a byte string) = rejected.
        let bstr_key = vec![(cbor(Value::Bytes(vec![1, 2, 3])), b"v".to_vec())];
        assert!(
            validate_extensions(&bstr_key).is_err(),
            "bstr key rejected (§6.2 int|text only)"
        );

        // duplicate key = rejected (§4.4).
        let dup = vec![
            (cbor(Value::Integer(7.into())), b"a".to_vec()),
            (cbor(Value::Integer(7.into())), b"b".to_vec()),
        ];
        assert!(
            validate_extensions(&dup).is_err(),
            "duplicate key rejected (§4.4)"
        );
    }

    #[test]
    fn f3_f4_enforced_on_decode() {
        // A container with a too-deep nesting must be REJECTED by from_content08_cbor (not just by the
        // standalone validator) - proving the receive path enforces it.
        fn wrap(inner: NestedPart) -> NestedPart {
            NestedPart {
                disposition: Disposition::Render,
                language: "en".into(),
                body: PartBody::Multi {
                    semantics: PartSemantics::ChooseOne,
                    parts: vec![
                        inner,
                        NestedPart {
                            disposition: Disposition::Render,
                            language: "en".into(),
                            body: PartBody::Null,
                        },
                    ],
                },
            }
        }
        let mut deep = NestedPart {
            disposition: Disposition::Render,
            language: "en".into(),
            body: PartBody::Single {
                content_type: "text/plain;charset=utf-8".into(),
                content: b"x".to_vec(),
            },
        };
        for _ in 0..5 {
            deep = wrap(deep); // 5 Multi layers > the 4-deep max
        }
        let mut c = sample();
        c.nested_part = deep;
        // encode WITHOUT to_content08_cbor's own nesting guard (M4), then prove decode independently
        // rejects an over-deep tree.
        let bytes = encode_unchecked(&c);
        assert!(
            from_content08_cbor(&bytes).is_err(),
            "decode must reject an over-deep NestedPart tree (F4 enforced on receive)"
        );
    }

    #[test]
    fn f5_receive_all_three_mandatory_types_and_reject_others() {
        // application/mimi-content
        let c = sample();
        let bytes = to_content08_cbor(&c).unwrap();
        match receive_content("application/mimi-content", &bytes).unwrap() {
            ReceivedContent::MimiContent(_) => {}
            other => panic!("expected MimiContent, got {other:?}"),
        }
        // text/plain;charset=utf-8
        assert_eq!(
            receive_content("text/plain;charset=utf-8", "héllo".as_bytes()).unwrap(),
            ReceivedContent::PlainText("héllo".into())
        );
        // text/markdown;variant=GFM-MIMI (clean markdown)
        assert_eq!(
            receive_content(GFM_MIMI_CONTENT_TYPE, b"# hello *world*").unwrap(),
            ReceivedContent::GfmMimiMarkdown("# hello *world*".into())
        );
        // GFM-MIMI with raw HTML → rejected (F7 nohtml on the receive path)
        assert!(
            receive_content(GFM_MIMI_CONTENT_TYPE, b"hi <script>evil</script>").is_err(),
            "raw HTML in GFM-MIMI rejected on receive"
        );
        // invalid UTF-8 text/plain → rejected
        assert!(receive_content("text/plain;charset=utf-8", &[0xff, 0xfe]).is_err());
        // unknown content type → rejected (fail-closed)
        assert!(
            receive_content("application/json", b"{}").is_err(),
            "unknown type rejected"
        );
        // case-insensitive type/subtype match still works
        assert!(receive_content("Text/Plain;charset=utf-8", b"hi").is_ok());
    }

    #[test]
    fn f8_only_original_sender_may_edit_or_delete() {
        let edit = NestedPart {
            disposition: Disposition::Render,
            language: "en".into(),
            body: PartBody::Single {
                content_type: "text/plain;charset=utf-8".into(),
                content: b"edited".to_vec(),
            },
        };
        let retract = NestedPart {
            disposition: Disposition::Render,
            language: "en".into(),
            body: PartBody::Null,
        };
        // original sender edits → OK, classified Edit
        assert_eq!(
            authorize_replacement("mimi://h/u/alice", "mimi://h/u/alice", &edit, false).unwrap(),
            ReplacementKind::Edit
        );
        // original sender retracts (NullPart) → OK, classified Retraction
        assert_eq!(
            authorize_replacement("mimi://h/u/alice", "mimi://h/u/alice", &retract, false).unwrap(),
            ReplacementKind::Retraction
        );
        // a DIFFERENT sender editing → rejected (§9.3)
        assert!(
            authorize_replacement("mimi://h/u/alice", "mimi://h/u/mallory", &edit, false).is_err(),
            "non-original sender may not edit (§9.3)"
        );
        // ...unless a concrete policy authorizes it (the explicit escape)
        assert!(
            authorize_replacement("mimi://h/u/alice", "mimi://h/u/mod", &edit, true).is_ok(),
            "a concrete authorization policy permits a non-original editor"
        );
        // empty SinglePart also counts as a retraction
        let empty = NestedPart {
            disposition: Disposition::Render,
            language: "en".into(),
            body: PartBody::Single {
                content_type: "text/plain;charset=utf-8".into(),
                content: vec![],
            },
        };
        assert_eq!(
            authorize_replacement("mimi://h/u/a", "mimi://h/u/a", &empty, false).unwrap(),
            ReplacementKind::Retraction
        );
    }
}
