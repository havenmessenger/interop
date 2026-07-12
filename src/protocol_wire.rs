//! MIMI protocol-06 §5 wire framing (TLS presentation language), the spec wire lane, alongside the
//! existing JSON `/mimi/v1/*` compat lane a foreign implementation does not speak.
//!
//! Scope: `submitMessage` (§5.4, routed), consent (§5.7, routed), `keyMaterial` (§5.2, routed),
//! `update` (§5.3, codec only, see its own section doc), `notify` inbound-receive (§5.5, routed),
//! `identifierQuery` (§5.8, routed). `groupInfo` (§5.6) is out of scope: it is the external-commit
//! join endpoint DIV-1 disallows in Haven's own product build, and framing it without the
//! accept-path behind it would wire-format half of a security-relevant endpoint. `reportAbuse`
//! (§5.9) and asset download (§5.10) are out of scope because this reference hub has no v1 handler
//! for either.
//!
//! The four v1 room-admin endpoints (`roomPolicy`/`memberRole`/`addParticipant`/
//! `authorizeSender`) are NOT framed here: protocol-06 §5 has ten named endpoints (directory,
//! keyMaterial, update, submitMessage, fanout, groupInfo, consent, identifierQuery, reportAbuse,
//! download) and the admin four are not among them. They are Haven's own RBAC management
//! surface, expressing (out
//! of band, via direct RPC) what the draft models as AppSync proposals carried inside a real
//! `update` transaction (§4.3.2). Since `update` itself has no live accept-path (see its section
//! doc), there is no spec wire form to frame the admin four AGAINST; inventing one would be a
//! private encoding wearing the TLS-PL label, not protocol conformance. Their v1 authorization
//! (query-param-based) is unchanged, which is the only thing to confirm about them.
//!
//! `<V>` maps to `tls_codec::VLBytes`/`Vec<T>` (QUIC varint length prefix, RFC 9000); `uint32`/`uint64`
//! are big-endian fixed-width. This mirrors `participant_list.rs`'s already-shipped TLS-PL codec, which
//! is the correct reuse target for this draft (`content.rs` is CBOR, not TLS-PL, a separate format for a
//! separate spec).
//!
//! `IdentifierUri` wraps a `String` via `VLBytes` (`opaque uri<V>`, §5 preamble). `MLSMessage` fields
//! delegate to openmls's own `MlsMessageIn`/`MlsMessageOut` (`Deserialize`/`Serialize`, Read-based).
//! Composing an embedded, non-`<V>`-prefixed struct with a following `<V>`-prefixed field works because
//! `&[u8]` implements `Read`, consuming from the front (the same pattern `gate.rs`'s `mimi_gate_welcome`
//! uses); the remaining slice after the MLS read is where the next field starts. Reading the outer MLS
//! envelope (wire_format, group_id, epoch) this way is the same operation `gate.rs`'s suite check already
//! performs on every inbound object. It does not touch `PrivateMessage` ciphertext content, consistent
//! with the store-and-forward opacity `Provider::submit_message` documents (INV-MIMI-002: the provider
//! never gains message-decryption capability).

use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::prelude::{
    Ciphersuite, Credential, KeyPackageIn, MlsMessageIn, MlsMessageOut,
    RequiredCapabilitiesExtension,
};
use tls_codec::{
    Deserialize as TlsDeserialize, DeserializeBytes, Error as TlsError, Serialize as TlsSerialize,
    VLBytes,
};

use crate::consent::{ConsentEntry, ConsentOperation};

/// protocol-06 §5 preamble `enum { reserved(0), mls10(1), (255) } Protocol;`. Modeled as a raw `u8`
/// (not a Rust enum), so an unknown or future value still round-trips instead of erroring on decode.
/// This is the same GREASE-tolerant choice `role_index`/`user_index` make in `participant_list.rs` for
/// fields with an explicit `(255)` extensible range. Haven only ever emits or accepts `MLS10`.
pub type Protocol = u8;
pub const PROTOCOL_RESERVED: Protocol = 0;
pub const PROTOCOL_MLS10: Protocol = 1;

/// Wire error for this module. Fail-closed: every decode path either produces a valid value or an
/// error, never a partially-populated struct.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("unsupported Protocol value {0} (Haven only speaks mls10)")]
    UnsupportedProtocol(u8),
    #[error("malformed MLSMessage: {0}")]
    MlsMessage(String),
    #[error("malformed {what}: {detail}")]
    Codec { what: &'static str, detail: String },
    #[error("{what}: {n} trailing byte(s)")]
    Trailing { what: &'static str, n: usize },
    #[error("sendingUri is not valid UTF-8")]
    NonUtf8Uri,
    #[error("invalid SubmitResponseCode {0}")]
    InvalidSubmitResponseCode(u8),
    /// A `KeyMaterialResponse` carried a KeyPackage that failed the ciphersuite
    /// accept-gate (`crate::gate::mimi_gate_keypackage`) - refused before the bytes can reach
    /// any caller that hands them to openmls.
    #[error("KeyPackage rejected by the ciphersuite accept-gate: {0}")]
    CiphersuiteGate(#[from] crate::gate::GateError),
    /// A `ConsentEntry` parsed as valid bytes but failed its semantic well-formedness
    /// check (`crate::consent::validate_consent_entry`) - a non-user requester/target, a room URI
    /// that isn't a room URI, or KeyPackages carried on a non-grant operation.
    #[error("ConsentEntry failed semantic validation: {0}")]
    ConsentValidation(#[from] crate::consent::ConsentError),
    /// A peer-controlled run of sub-objects (KeyPackages, proposals, query elements,
    /// consent extension entries) exceeded the shared element-count or aggregate-byte budget
    /// (`RunBudget`) before this decoder finished parsing it.
    #[error("{what}: {detail}")]
    RunBudgetExceeded { what: &'static str, detail: String },
}

fn codec_err(what: &'static str, e: TlsError) -> WireError {
    WireError::Codec {
        what,
        detail: e.to_string(),
    }
}

/// Defensive ceiling on the number of elements a single peer-controlled run decode
/// (KeyPackages, proposals, consent extension entries) will parse into memory. Each element
/// individually parses cleanly - a hostile peer packs the maximum count of minimal-size elements
/// into one length-bounded window to force allocation proportional to the count, not to any
/// single element's size. This is the shared default for runs with no derivable protocol bound
/// (a consent grant's KeyPackage count, an MLS Commit's batched proposal count) - a policy
/// choice, generous above realistic legitimate use, not a spec-derived limit. Sites with an
/// actual per-site bound use `RunBudget::with_limits` instead (see `MAX_QUERY_ELEMENTS` for
/// `IdentifierRequest`, whose wire format is generic but whose real usage here is single-element).
pub const MAX_RUN_ELEMENTS: usize = 1024;

/// Aggregate byte ceiling for the shared-default run class, independent of
/// `MAX_RUN_ELEMENTS` - bounds a run of few-but-huge elements the count cap alone would not
/// catch. 1 MiB is generous above the largest legitimate run in this crate (a KeyPackage is a
/// few hundred bytes to a few KiB; even `MAX_RUN_ELEMENTS` KeyPackages at 1 KiB each is 1 MiB, so
/// the two caps compose rather than one dominating the other).
pub const MAX_RUN_AGGREGATE_BYTES: usize = 1024 * 1024;

/// Per-site budget for `IdentifierRequest::query_elements`. The wire format itself (§5.8)
/// does not restrict a request to one element, but this hub's own `primary_search_value` only
/// ever reads the first - a real request never legitimately carries more than a handful of search
/// criteria. Documented as this site's own bound, not the shared default, since the draft's wire
/// format is more permissive than this hub's usage.
pub const MAX_QUERY_ELEMENTS: usize = 16;
pub const MAX_QUERY_AGGREGATE_BYTES: usize = 16 * 1024;

/// `tls_codec::vlen::read_length` accumulates a declared length into a `usize`
/// (`quic_vec.rs`: `length = (length << 8) + byte`, repeated per length-prefix byte). The QUIC
/// RFC 9000 wire format's largest form encodes a 62-bit value; a 62-bit accumulation into a
/// 32-bit `usize` could wrap before this crate ever sees the (corrupted) result, and no
/// downstream comparison can detect a wrap that already happened.
///
/// `read_declared_length` below closes this from this crate's own code, not by relying on a
/// dependency's feature flag: it rejects the 8-byte/62-bit wire form outright, before calling
/// into `tls_codec` at all, so the largest declared length this crate ever accumulates is the
/// 4-byte form's 30-bit maximum - comfortably inside even a 32-bit `usize`. (`tls_codec`'s own
/// `mls` feature, active in this build because `openmls`'s `Cargo.toml` requests it and Cargo's
/// feature unification applies that crate-wide, already imposes the same 30-bit cap - confirmed
/// by direct probe - but that is a transitive dependency's choice this crate does not control and
/// could silently lose on a future dependency bump; the check below does not depend on it.) The
/// compile-time assertion is additional, independent insurance: it makes it impossible to build
/// this crate at all on a target where a 30-bit value could wrap.
const _: () = assert!(
    usize::BITS >= 32,
    "mimi-core's declared-length arithmetic assumes a usize wide enough for a 30-bit value; see the run-decode bounding note on read_declared_length below"
);

/// Shared first step for every windowed run-decode below: read the QUIC-varint length prefix
/// and reject it against `budget_limit` before any real decode runs. Returns the declared payload
/// length and how many bytes the prefix itself occupied, so a caller can locate where the payload
/// starts without re-parsing the prefix.
fn read_declared_length(
    bytes: &[u8],
    what: &'static str,
    budget_limit: usize,
) -> Result<(usize, usize), WireError> {
    // Reject the 8-byte/62-bit varint length-of-length form ourselves, before
    // `tls_codec::vlen::read_length` ever runs. `tls_codec` 0.4.2's own rejection of this form
    // (`quic_vec.rs`'s `calculate_length`, when `mls` is active) sits behind a
    // `debug_assert_eq!` that fires immediately before the correct `Err` return - the same
    // fail-before-erroring bug class as the short-read panic `bounded_run_input` closes, just on
    // the length-of-length selector byte instead of the payload. Verified directly: a real public
    // decode function (`decode_consent_entry`) panics under `cargo test` on a length-prefix byte
    // selecting this form, through this exact call path. This crate's wire format never needs
    // more than the 4-byte/30-bit form (the largest real budget, `MAX_RUN_AGGREGATE_BYTES`, is
    // 1 MiB), so rejecting the 8-byte form here is not a functional restriction on anything this
    // crate legitimately decodes.
    if let Some(&first_byte) = bytes.first() {
        if first_byte >> 6 == 0b11 {
            return Err(WireError::Codec {
                what,
                detail: "declared length uses the unsupported 8-byte varint form".into(),
            });
        }
    }
    let mut cursor = bytes;
    let (length, _len_len) =
        tls_codec::vlen::read_length(&mut cursor).map_err(|e| codec_err(what, e))?;
    if length > budget_limit {
        return Err(WireError::RunBudgetExceeded {
            what,
            detail: format!(
                "declared length {length} exceeds the {budget_limit}-byte budget (rejected before allocation)"
            ),
        });
    }
    let len_len = bytes.len() - cursor.len();
    Ok((length, len_len))
}

/// The general codec-level chokepoint every peer-controlled variable-length run
/// in this crate routes through. Reads the QUIC-varint length prefix of an upcoming `<V>`-length
/// TLS vector, rejects the declared length against `budget_limit` before the real decode call
/// runs, and returns a self-contained slice covering only the length-prefix bytes plus the
/// declared payload - nothing past the declared window - alongside the correctly-advanced
/// remainder for continued top-level parsing.
///
/// This exists because `VLBytes::tls_deserialize_bytes` and the blanket `Vec<T>:
/// DeserializeBytes` both clone or collect up to the declared length as soon as it parses -
/// `RunBudget::record`, called per element after each one deserializes, only rejects a run after
/// that allocation already happened. Peeking the outer declared length and rejecting it
/// before the outer clone is not sufficient on its own for a run
/// whose element type carries its own nested variable-length field (e.g. `VLBytes` inside a
/// struct decoded via the blanket `Vec<T>` impl): `tls_codec` 0.4.2's blanket impl hands each
/// element the whole remaining slice, not a slice bounded to this window's declared length, and
/// only stops once the running consumed total reaches the declared length - it does not reject
/// an element that overshoots it. Handing the real decode call this function's bounded slice
/// (instead of the raw, unbounded remainder) closes that: an inner element that tries to read
/// past the declared window runs out of bytes inside the bounded slice and the decode fails
/// closed (`EndOfStream`/`DecodingError`) instead of silently reading past the boundary.
///
/// The returned `remainder` is authoritative regardless of what the caller's decode call does
/// inside the bounded slice (whether it returns a non-empty internal tail is the caller's own
/// concern, not this function's).
pub(crate) fn bounded_run_input<'a>(
    bytes: &'a [u8],
    what: &'static str,
    budget_limit: usize,
) -> Result<(&'a [u8], &'a [u8]), WireError> {
    let (length, len_len) = read_declared_length(bytes, what, budget_limit)?;
    let total = len_len
        .checked_add(length)
        .ok_or_else(|| WireError::Codec {
            what,
            detail: format!("declared length {length} overflows"),
        })?;
    let bounded = bytes.get(..total).ok_or_else(|| WireError::Codec {
        what,
        detail: format!(
            "declared length {length} exceeds the {} byte(s) actually available",
            bytes.len().saturating_sub(len_len)
        ),
    })?;
    Ok((bounded, &bytes[total..]))
}

/// Shared accumulator every peer-controlled run-decoder in this module records against, so a
/// new variable-length decoder gets both budgets by construction instead of an ad-hoc check
/// someone has to remember to add. Call `record` once per parsed element, with that element's
/// own consumed byte length, before pushing it into the caller's result collection. Pair with
/// [`bounded_run_input`] on the outer window before the loop starts - `record` alone only
/// bounds work done AFTER the outer clone/collect has already happened.
struct RunBudget {
    max_elements: usize,
    max_aggregate_bytes: usize,
    elements: usize,
    aggregate_bytes: usize,
}

impl RunBudget {
    const fn new() -> Self {
        Self::with_limits(MAX_RUN_ELEMENTS, MAX_RUN_AGGREGATE_BYTES)
    }

    const fn with_limits(max_elements: usize, max_aggregate_bytes: usize) -> Self {
        Self {
            max_elements,
            max_aggregate_bytes,
            elements: 0,
            aggregate_bytes: 0,
        }
    }

    fn record(&mut self, what: &'static str, element_bytes: usize) -> Result<(), WireError> {
        self.elements += 1;
        if self.elements > self.max_elements {
            return Err(WireError::RunBudgetExceeded {
                what,
                detail: format!("run exceeds the {}-element budget", self.max_elements),
            });
        }
        self.aggregate_bytes += element_bytes;
        if self.aggregate_bytes > self.max_aggregate_bytes {
            return Err(WireError::RunBudgetExceeded {
                what,
                detail: format!(
                    "run exceeds the {}-byte aggregate budget",
                    self.max_aggregate_bytes
                ),
            });
        }
        Ok(())
    }
}

/// `opaque uri<V>` (§5 preamble; used as `IdentifierUri` throughout §5). Wraps a UTF-8 `String`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierUri(pub String);

impl IdentifierUri {
    fn to_vlbytes(&self) -> VLBytes {
        VLBytes::new(self.0.clone().into_bytes())
    }

    fn from_vlbytes(v: VLBytes) -> Result<Self, WireError> {
        String::from_utf8(v.as_slice().to_vec())
            .map(Self)
            .map_err(|_| WireError::NonUtf8Uri)
    }
}

// ============================ submitMessage (§5.4) ============================

/// §5.4 `SubmitMessageRequest` - `{ Protocol protocol; select(protocol){ case mls10: MLSMessage
/// appMessage; IdentifierUri sendingUri; }; }`. `app_message` carries the raw MLS wire bytes
/// (`MlsMessageOut::tls_serialize_detached()` on encode, kept opaque past the envelope on decode).
#[derive(Debug, Clone)]
pub struct SubmitMessageRequest {
    pub protocol: Protocol,
    pub app_message: Vec<u8>,
    pub sending_uri: IdentifierUri,
}

impl SubmitMessageRequest {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.protocol != PROTOCOL_MLS10 {
            return Err(WireError::UnsupportedProtocol(self.protocol));
        }
        let mut out = vec![self.protocol];
        // The MLS message is embedded, not <V>-prefixed (RFC 9420 framing is self-delimiting);
        // write it as-is and let the caller have provided already-serialized MLS wire bytes.
        out.extend_from_slice(&self.app_message);
        self.sending_uri
            .to_vlbytes()
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("sendingUri", e))?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (protocol, rest) = bytes
            .split_first()
            .ok_or(WireError::UnsupportedProtocol(0))?;
        if *protocol != PROTOCOL_MLS10 {
            return Err(WireError::UnsupportedProtocol(*protocol));
        }
        // Bound the embedded MLSMessage by actually parsing it (same technique gate.rs uses for the
        // inbound Welcome suite check). This is how a length-implicit TLS-PL field finds its own end;
        // it reads the envelope only, never the PrivateMessage ciphertext body.
        // `MlsMessageIn::tls_deserialize` can PANIC (not just Err) on certain malformed
        // nested-length-prefix input -- the same tls_codec-internal panic risk as the other
        // peer-controlled MLSMessage sites in this file (this is the live submitMessage endpoint,
        // the most peer-exposed of them). catch_unwind turns a hostile/malformed app_message into
        // a decode error instead of an unhandled panic in the request task.
        let before = rest.len();
        let consumed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut c: &[u8] = rest;
            MlsMessageIn::tls_deserialize(&mut c).map(|_| before - c.len())
        }))
        .map_err(|_| WireError::Codec {
            what: "app_message",
            detail: "malformed MLSMessage (decoder panicked)".into(),
        })?
        .map_err(|e| WireError::MlsMessage(format!("{e:?}")))?;
        let cursor: &[u8] = &rest[consumed..];
        // MlsMessageIn (parse-only type) has no serializer; the already-consumed slice is the wire
        // bytes for the envelope, since decoding it already fixed its length.
        let app_message = rest[..consumed].to_vec();
        // Bound before decoding, not just for elements nested inside an outer
        // window - any VLBytes decode call on a slice an attacker can make shorter than its own
        // declared length hits the same tls_codec short-read panic, scalar leaf fields included.
        let (uri_bounded, tail) = bounded_run_input(cursor, "sendingUri", MAX_RUN_AGGREGATE_BYTES)?;
        let (uri_bytes, _uri_tail) =
            VLBytes::tls_deserialize_bytes(uri_bounded).map_err(|e| codec_err("sendingUri", e))?;
        if !tail.is_empty() {
            return Err(WireError::Trailing {
                what: "SubmitMessageRequest",
                n: tail.len(),
            });
        }
        Ok(Self {
            protocol: *protocol,
            app_message,
            sending_uri: IdentifierUri::from_vlbytes(uri_bytes)?,
        })
    }

    /// Convenience constructor from an already-built `MlsMessageOut`, matching how a real sender
    /// would call this: the message is built once, then framed for the wire.
    pub fn from_mls_message(
        msg: &MlsMessageOut,
        sending_uri: impl Into<String>,
    ) -> Result<Self, WireError> {
        let app_message = msg
            .tls_serialize_detached()
            .map_err(|e| WireError::MlsMessage(e.to_string()))?;
        Ok(Self {
            protocol: PROTOCOL_MLS10,
            app_message,
            sending_uri: IdentifierUri(sending_uri.into()),
        })
    }
}

/// §5.4 `SubmitResponseCode` (line 1568-1573 of the draft): `accepted(0), notAllowed(1),
/// epochTooOld(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitResponseCode {
    Accepted,
    NotAllowed,
    EpochTooOld,
}

impl SubmitResponseCode {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Accepted => 0,
            Self::NotAllowed => 1,
            Self::EpochTooOld => 2,
        }
    }

    const fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::NotAllowed),
            2 => Ok(Self::EpochTooOld),
            other => Err(WireError::InvalidSubmitResponseCode(other)),
        }
    }
}

/// §5.4 `SubmitMessageResponse`. `frank` (server_frank framing, §5.4.1) is deferred: it is not yet
/// built in mimi-hub's v1 store-and-forward. The struct still requires the `optional Frank frank`
/// presence tag after `accepted_timestamp` even when absent -- TLS presentation-language
/// `optional<T>` is a 1-byte tag (0/1) followed by the value only if present; omitting the tag
/// entirely is not additive framing, it desyncs a strict decoder. Building the real frank value is
/// additive (encode 1 then the `Frank` bytes) once §5.4.1 lands; the tag itself is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitMessageResponse {
    Accepted { accepted_timestamp: u64 },
    NotAllowed,
    EpochTooOld { current_epoch: u64 },
}

impl SubmitMessageResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![PROTOCOL_MLS10];
        match self {
            Self::Accepted { accepted_timestamp } => {
                out.push(SubmitResponseCode::Accepted.to_u8());
                out.extend_from_slice(&accepted_timestamp.to_be_bytes());
                out.push(0); // optional Frank frank: absent (see the type doc)
            }
            Self::NotAllowed => {
                out.push(SubmitResponseCode::NotAllowed.to_u8());
            }
            Self::EpochTooOld { current_epoch } => {
                out.push(SubmitResponseCode::EpochTooOld.to_u8());
                out.extend_from_slice(&current_epoch.to_be_bytes());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (&protocol, rest) = bytes
            .split_first()
            .ok_or(WireError::UnsupportedProtocol(0))?;
        if protocol != PROTOCOL_MLS10 {
            return Err(WireError::UnsupportedProtocol(protocol));
        }
        let (&code_byte, rest) = rest
            .split_first()
            .ok_or(WireError::InvalidSubmitResponseCode(0))?;
        let code = SubmitResponseCode::from_u8(code_byte)?;
        match code {
            SubmitResponseCode::Accepted => {
                let ts_bytes = rest.get(..8).ok_or_else(|| WireError::Codec {
                    what: "accepted_timestamp",
                    detail: format!("need 8 bytes, got {}", rest.len()),
                })?;
                let ts = read_u64(ts_bytes, "accepted_timestamp")?;
                let tail = &rest[8..];
                let (&frank_tag, tail) = tail.split_first().ok_or_else(|| WireError::Codec {
                    what: "frank presence tag",
                    detail: "truncated".into(),
                })?;
                match frank_tag {
                    0 => {
                        if !tail.is_empty() {
                            return Err(WireError::Trailing {
                                what: "SubmitMessageResponse(accepted)",
                                n: tail.len(),
                            });
                        }
                    }
                    1 => {
                        // Frank decode isn't built (see the type doc) -- a peer that actually
                        // franks a response is a real case we can't yet parse, not garbage.
                        return Err(WireError::Codec {
                            what: "frank",
                            detail: "server_frank framing (§5.4.1) is not yet decodable".into(),
                        });
                    }
                    other => {
                        return Err(WireError::Codec {
                            what: "frank presence tag",
                            detail: format!("expected 0 or 1, got {other}"),
                        })
                    }
                }
                Ok(Self::Accepted {
                    accepted_timestamp: ts,
                })
            }
            SubmitResponseCode::NotAllowed => {
                if !rest.is_empty() {
                    return Err(WireError::Trailing {
                        what: "SubmitMessageResponse(notAllowed)",
                        n: rest.len(),
                    });
                }
                Ok(Self::NotAllowed)
            }
            SubmitResponseCode::EpochTooOld => {
                let epoch = read_u64(rest, "currentEpoch")?;
                Ok(Self::EpochTooOld {
                    current_epoch: epoch,
                })
            }
        }
    }
}

fn read_u64(bytes: &[u8], what: &'static str) -> Result<u64, WireError> {
    let arr: [u8; 8] = bytes
        .get(..8)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| WireError::Codec {
            what,
            detail: format!("need 8 bytes, got {}", bytes.len()),
        })?;
    if bytes.len() != 8 {
        return Err(WireError::Trailing {
            what,
            n: bytes.len() - 8,
        });
    }
    Ok(u64::from_be_bytes(arr))
}

// ============================ consent (§5.7) ============================

/// §5.7 `ConsentEntry` wire form: `{ ConsentOperation consentOperation; IdentifierUri requesterUri;
/// IdentifierUri targetUri; optional<RoomId> roomId; select(consentOperation){ case grant: KeyPackage
/// clientKeyPackages<V>; }; AppDataDictionary consent_extensions; }`.
///
/// `consent_extensions` is NOT decoded into the real MLS-extensions-10 `AppDataDictionary`
/// CBOR/TLS structure - that structure is a separate, unimplemented draft feature (the same
/// reasoning `update`'s `RatchetTreeOption`/`GroupInfoOption` fields use for staying out of an
/// unrelated draft's codec). `consent.rs`'s own domain type already commits to `Vec<(String,
/// Vec<u8>)>`, though, so this module encodes/decodes that shape directly - see
/// [`encode_consent_extensions`]/[`decode_consent_extensions`] - rather than treating a real,
/// populatable field as an opaque blob that silently loses its contents.
pub fn encode_consent_entry(e: &ConsentEntry) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    out.push(u8::from(e.operation));
    IdentifierUri(e.requester_uri.clone())
        .to_vlbytes()
        .tls_serialize(&mut out)
        .map_err(|err| codec_err("requesterUri", err))?;
    IdentifierUri(e.target_uri.clone())
        .to_vlbytes()
        .tls_serialize(&mut out)
        .map_err(|err| codec_err("targetUri", err))?;
    // optional<RoomId>: a 1-byte presence tag (0/1), matching openmls's own `optional<T>` convention
    // for a TLS-PL Option (see e.g. `Welcome`'s optional fields in the RFC 9420 grammar).
    match &e.room_uri {
        Some(room) => {
            out.push(1);
            IdentifierUri(room.clone())
                .to_vlbytes()
                .tls_serialize(&mut out)
                .map_err(|err| codec_err("roomId", err))?;
        }
        None => out.push(0),
    }
    if e.operation == ConsentOperation::Grant {
        // `KeyPackage clientKeyPackages<V>` is ONE outer length wrapping concatenated
        // self-delimiting KeyPackage objects -- NOT a vector of individually length-prefixed
        // blobs. Each `client_key_packages` element is already exactly one KeyPackage's own
        // serialized bytes, so concatenate them raw under a single VLBytes.
        let mut concatenated = Vec::new();
        for kp in &e.client_key_packages {
            concatenated.extend_from_slice(kp);
        }
        VLBytes::new(concatenated)
            .tls_serialize(&mut out)
            .map_err(|err| codec_err("clientKeyPackages", err))?;
    }
    let ext_bytes = encode_consent_extensions(&e.consent_extensions)?;
    VLBytes::new(ext_bytes)
        .tls_serialize(&mut out)
        .map_err(|err| codec_err("consent_extensions", err))?;
    Ok(out)
}

pub fn decode_consent_entry(bytes: &[u8]) -> Result<ConsentEntry, WireError> {
    let (&op_byte, rest) = bytes.split_first().ok_or_else(|| WireError::Codec {
        what: "consentOperation",
        detail: "empty input".into(),
    })?;
    let operation = ConsentOperation::try_from(op_byte).map_err(|e| WireError::Codec {
        what: "consentOperation",
        detail: e,
    })?;
    // Bound every scalar VLBytes decode too, not just outer run windows - the
    // same short-read tls_codec panic applies regardless of nesting.
    let (requester_bounded, rest) =
        bounded_run_input(rest, "requesterUri", MAX_RUN_AGGREGATE_BYTES)?;
    let (requester_bytes, _requester_tail) = VLBytes::tls_deserialize_bytes(requester_bounded)
        .map_err(|e| codec_err("requesterUri", e))?;
    let requester_uri = IdentifierUri::from_vlbytes(requester_bytes)?.0;
    let (target_bounded, rest) = bounded_run_input(rest, "targetUri", MAX_RUN_AGGREGATE_BYTES)?;
    let (target_bytes, _target_tail) =
        VLBytes::tls_deserialize_bytes(target_bounded).map_err(|e| codec_err("targetUri", e))?;
    let target_uri = IdentifierUri::from_vlbytes(target_bytes)?.0;
    let (&room_tag, rest) = rest.split_first().ok_or_else(|| WireError::Codec {
        what: "roomId presence tag",
        detail: "truncated".into(),
    })?;
    let (room_uri, rest) = match room_tag {
        0 => (None, rest),
        1 => {
            let (room_bounded, rest) = bounded_run_input(rest, "roomId", MAX_RUN_AGGREGATE_BYTES)?;
            let (room_bytes, _room_tail) =
                VLBytes::tls_deserialize_bytes(room_bounded).map_err(|e| codec_err("roomId", e))?;
            (Some(IdentifierUri::from_vlbytes(room_bytes)?.0), rest)
        }
        other => {
            return Err(WireError::Codec {
                what: "roomId presence tag",
                detail: format!("expected 0 or 1, got {other}"),
            })
        }
    };
    let (client_key_packages, rest) = if operation == ConsentOperation::Grant {
        // Bound the input to the declared window before decoding it, not just peek
        // the declared length - closes the class even for a window whose own decode step turns
        // out to be a manual per-element loop (below), consistent with every other run-decoder in
        // this module.
        let (bounded, next_rest) =
            bounded_run_input(rest, "clientKeyPackages", MAX_RUN_AGGREGATE_BYTES)?;
        let rest = next_rest;
        // Mirror of the encode side: one outer VLBytes window bounds a run of
        // self-delimiting KeyPackage objects, not individually length-prefixed blobs. Decode
        // each KeyPackage in turn (same consumed-byte-count technique as
        // `KeyMaterialResponse::decode` above) until the window is exactly exhausted.
        let (window, _tail) = VLBytes::tls_deserialize_bytes(bounded)
            .map_err(|e| codec_err("clientKeyPackages", e))?;
        let window = window.as_slice();
        // `KeyPackageIn::tls_deserialize_bytes` can PANIC (not just Err) on certain malformed
        // nested-length-prefix inputs -- an internal tls_codec 0.4.2 assertion, observed directly
        // while testing this fix. `clientKeyPackages` is peer-controlled; catch_unwind turns a
        // hostile/malformed KeyPackage into a decode error instead of an unhandled panic in the
        // request task, matching this crate's own "hostile input must never panic" rule
        // (content.rs's module doc states the same discipline for the content codec).
        let mut offset = 0usize;
        let mut kps = Vec::new();
        let mut budget = RunBudget::new();
        while offset < window.len() {
            let slice = &window[offset..];
            let (_kp, consumed) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                KeyPackageIn::tls_deserialize_bytes(slice)
                    .map(|(kp, tail)| (kp, slice.len() - tail.len()))
            }))
            .map_err(|_| WireError::Codec {
                what: "clientKeyPackages[]",
                detail: "malformed KeyPackage (decoder panicked)".into(),
            })?
            .map_err(|e| codec_err("clientKeyPackages[]", e))?;
            let kp_bytes = window[offset..offset + consumed].to_vec();
            budget.record("clientKeyPackages[]", kp_bytes.len())?;
            // A consent grant's carried KeyPackages are join material a requester
            // may add to a group directly - gate each one at decode, same as `/keyMaterial`.
            crate::gate::mimi_gate_keypackage(&kp_bytes)?;
            kps.push(kp_bytes);
            offset += consumed;
        }
        (kps, rest)
    } else {
        (Vec::new(), rest)
    };
    // This outer window needs its own pre-check independent of the inner one - the
    // name/value pairs inside it (`decode_consent_extensions`) are budgeted separately, so an
    // over-budget declared length here would otherwise be cloned in full before that inner
    // budget gets a chance to run.
    let (ext_bounded, rest) =
        bounded_run_input(rest, "consent_extensions", MAX_RUN_AGGREGATE_BYTES)?;
    let (ext_window, _tail) = VLBytes::tls_deserialize_bytes(ext_bounded)
        .map_err(|e| codec_err("consent_extensions", e))?;
    if !rest.is_empty() {
        return Err(WireError::Trailing {
            what: "ConsentEntry",
            n: rest.len(),
        });
    }
    let consent_extensions = decode_consent_extensions(ext_window.as_slice())?;
    let entry = ConsentEntry {
        operation,
        requester_uri,
        target_uri,
        room_uri,
        client_key_packages,
        consent_extensions,
    };
    // No publicly-reachable path returns an unvalidated ConsentEntry - the
    // clientKeyPackages suite gate above runs on each element as it is parsed;
    // this checks the entry's own semantic invariants once it is fully assembled.
    crate::consent::validate_consent_entry(&entry)?;
    Ok(entry)
}

/// `consent_extensions` (the AppDataDictionary, §5.7) as a run of `(name, value)` pairs -
/// `crate::consent::ConsentEntry`'s own domain type already commits to `Vec<(String, Vec<u8>)>`,
/// not an opaque byte blob, so a real codec for that shape is needed (not the actual
/// MLS-extensions-10 `AppDataDictionary` CBOR/TLS structure, which is a separate, unimplemented
/// draft feature - the same reasoning `GroupInfoOption`'s own doc gives for staying out of an
/// unrelated draft's codec). Each entry is `VLBytes(name) || VLBytes(value)`, concatenated
/// entries wrapped in one outer window - the same "one window, self-delimiting elements"
/// convention this module already uses for `clientKeyPackages<V>` and `moreProposals<V>`.
fn encode_consent_extensions(entries: &[(String, Vec<u8>)]) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::new();
    for (name, value) in entries {
        VLBytes::new(name.clone().into_bytes())
            .tls_serialize(&mut buf)
            .map_err(|e| codec_err("consent_extensions[].name", e))?;
        VLBytes::new(value.clone())
            .tls_serialize(&mut buf)
            .map_err(|e| codec_err("consent_extensions[].value", e))?;
    }
    Ok(buf)
}

/// Decode side of [`encode_consent_extensions`]. Budgeted from the start - a peer-
/// controlled run of pairs is exactly the class `RunBudget` exists for.
fn decode_consent_extensions(window: &[u8]) -> Result<Vec<(String, Vec<u8>)>, WireError> {
    let mut entries = Vec::new();
    let mut budget = RunBudget::new();
    let mut cursor = window;
    while !cursor.is_empty() {
        // Uniform with every other run-decoder in this module - bound then decode.
        let (name_bounded, rest) =
            bounded_run_input(cursor, "consent_extensions[].name", MAX_RUN_AGGREGATE_BYTES)?;
        let (name_bytes, _tail) = VLBytes::tls_deserialize_bytes(name_bounded)
            .map_err(|e| codec_err("consent_extensions[].name", e))?;
        let name =
            String::from_utf8(name_bytes.as_slice().to_vec()).map_err(|_| WireError::Codec {
                what: "consent_extensions[].name",
                detail: "not valid UTF-8".into(),
            })?;
        let (value_bounded, rest) =
            bounded_run_input(rest, "consent_extensions[].value", MAX_RUN_AGGREGATE_BYTES)?;
        let (value_bytes, _tail) = VLBytes::tls_deserialize_bytes(value_bounded)
            .map_err(|e| codec_err("consent_extensions[].value", e))?;
        let value = value_bytes.as_slice().to_vec();
        // Use the actual on-wire consumed length (name+value bytes plus both VLBytes
        // length prefixes), not name.len()+value.len() alone, which undercounts by omitting the
        // prefix bytes.
        let consumed = cursor.len() - rest.len();
        budget.record("consent_extensions[]", consumed)?;
        entries.push((name, value));
        cursor = rest;
    }
    Ok(entries)
}

// ============================ keyMaterial (§5.2) ============================

/// §5.2 `KeyMaterialRequest`. The negotiation fields (`acceptable_ciphersuites`,
/// `required_capabilities`, `requester_signature_key`, `requester_credential`,
/// `key_material_request_signature`) are decoded for wire fidelity (each is a self-delimiting
/// TLS-PL struct that must be parsed correctly to find the following field's boundary) but not
/// acted on: the v1 `serve_key_material` this maps onto has no capability negotiation or
/// signature verification of any kind, on the JSON lane either, so adding enforcement here would
/// be new behavior, not framing. `room_id` is an empty `IdentifierUri` when the request is not
/// room-scoped (the draft's struct has no `optional<>` wrapper on this field).
#[derive(Debug, Clone)]
pub struct KeyMaterialRequest {
    pub protocol: Protocol,
    pub requesting_user: IdentifierUri,
    pub target_user: IdentifierUri,
    pub room_id: IdentifierUri,
    pub acceptable_ciphersuites: Vec<Ciphersuite>,
    pub required_capabilities: RequiredCapabilitiesExtension,
    pub requester_signature_key: SignaturePublicKey,
    pub requester_credential: Credential,
    pub key_material_request_signature: Vec<u8>,
}

impl KeyMaterialRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (&protocol, rest) = bytes
            .split_first()
            .ok_or(WireError::UnsupportedProtocol(0))?;
        if protocol != PROTOCOL_MLS10 {
            return Err(WireError::UnsupportedProtocol(protocol));
        }
        // Bound every scalar VLBytes decode too - live from mimi-hub's
        // keyMaterial HTTP handler, the most peer-exposed decode in this crate.
        let (requesting_user_bounded, rest) =
            bounded_run_input(rest, "requestingUser", MAX_RUN_AGGREGATE_BYTES)?;
        let (requesting_user, _requesting_user_tail) =
            VLBytes::tls_deserialize_bytes(requesting_user_bounded)
                .map_err(|e| codec_err("requestingUser", e))?;
        let (target_user_bounded, rest) =
            bounded_run_input(rest, "targetUser", MAX_RUN_AGGREGATE_BYTES)?;
        let (target_user, _target_user_tail) = VLBytes::tls_deserialize_bytes(target_user_bounded)
            .map_err(|e| codec_err("targetUser", e))?;
        let (room_id_bounded, rest) = bounded_run_input(rest, "roomId", MAX_RUN_AGGREGATE_BYTES)?;
        let (room_id, _room_id_tail) =
            VLBytes::tls_deserialize_bytes(room_id_bounded).map_err(|e| codec_err("roomId", e))?;
        // `Vec<Ciphersuite>::tls_deserialize_bytes` is tls_codec's own blanket impl - a
        // single opaque call, not a loop this module writes, so a per-element RunBudget can't be
        // interjected here. `Ciphersuite` is a fixed-size element (no nested variable-length
        // field), so it is not independently exposed to the nested-overshoot class, but routes
        // through the same bounding helper as every other run in this module for uniformity.
        let (bounded, rest) =
            bounded_run_input(rest, "acceptableCiphersuites", MAX_RUN_AGGREGATE_BYTES)?;
        let (acceptable_ciphersuites, _tail) =
            Vec::<Ciphersuite>::tls_deserialize_bytes(bounded)
                .map_err(|e| codec_err("acceptableCiphersuites", e))?;
        // `RequiredCapabilitiesExtension` and `Credential` are multi-field openmls
        // types, not a single `<V>`-prefixed blob this crate can bound externally the way a
        // scalar `VLBytes` field is bounded - their own internal length-prefixed sub-fields are
        // opaque to this crate. Probed directly: `RequiredCapabilitiesExtension` panics on a
        // length-prefix byte selecting the 8-byte varint form (the same
        // `debug_assert_eq!`-before-`Err` bug `read_declared_length` closes for this crate's own
        // reads, reached here through openmls's own internal call into tls_codec);
        // `Credential` was not observed to panic on the one byte layout tried, but its own
        // `serialized_credential_content` field is the identical shape and not proven safe.
        // `catch_unwind` is this crate's established mitigation for this class of opaque
        // external-type decode (`KeyPackageIn`/`MlsMessageIn` elsewhere in this file, `gate.rs`).
        // `SignaturePublicKey` does NOT need this: it wraps a single `VLBytes` directly, so
        // bounding it externally via `bounded_run_input` (below) closes both the short-read and
        // the 8-byte-form class the same way a scalar field does, verified.
        let (required_capabilities, rest) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                RequiredCapabilitiesExtension::tls_deserialize_bytes(rest)
            }))
            .map_err(|_| WireError::Codec {
                what: "requiredCapabilities",
                detail: "malformed RequiredCapabilitiesExtension (decoder panicked)".into(),
            })?
            .map_err(|e| codec_err("requiredCapabilities", e))?;
        let (sig_key_bounded, rest) =
            bounded_run_input(rest, "requesterSignatureKey", MAX_RUN_AGGREGATE_BYTES)?;
        let (requester_signature_key, _sig_key_tail) =
            SignaturePublicKey::tls_deserialize_bytes(sig_key_bounded)
                .map_err(|e| codec_err("requesterSignatureKey", e))?;
        let (requester_credential, rest) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Credential::tls_deserialize_bytes(rest)
            }))
            .map_err(|_| WireError::Codec {
                what: "requesterCredential",
                detail: "malformed Credential (decoder panicked)".into(),
            })?
            .map_err(|e| codec_err("requesterCredential", e))?;
        let (sig_bounded, rest) = bounded_run_input(
            rest,
            "key_material_request_signature",
            MAX_RUN_AGGREGATE_BYTES,
        )?;
        let (sig, _sig_tail) = VLBytes::tls_deserialize_bytes(sig_bounded)
            .map_err(|e| codec_err("key_material_request_signature", e))?;
        if !rest.is_empty() {
            return Err(WireError::Trailing {
                what: "KeyMaterialRequest",
                n: rest.len(),
            });
        }
        Ok(Self {
            protocol,
            requesting_user: IdentifierUri::from_vlbytes(requesting_user)?,
            target_user: IdentifierUri::from_vlbytes(target_user)?,
            room_id: IdentifierUri::from_vlbytes(room_id)?,
            acceptable_ciphersuites,
            required_capabilities,
            requester_signature_key,
            requester_credential,
            key_material_request_signature: sig.as_slice().to_vec(),
        })
    }

    /// Test/client-side convenience constructor for a minimal request naming only the fields this
    /// reference hub's serve path actually reads (`target_user`). The negotiation fields are given
    /// permissive-but-valid defaults so the encoded bytes are a real, decodable request.
    pub fn minimal(
        requesting_user: impl Into<String>,
        target_user: impl Into<String>,
    ) -> Result<Self, WireError> {
        Ok(Self {
            protocol: PROTOCOL_MLS10,
            requesting_user: IdentifierUri(requesting_user.into()),
            target_user: IdentifierUri(target_user.into()),
            room_id: IdentifierUri(String::new()),
            acceptable_ciphersuites: vec![
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            ],
            required_capabilities: RequiredCapabilitiesExtension::default(),
            requester_signature_key: SignaturePublicKey::from(Vec::<u8>::new()),
            requester_credential: openmls::credentials::BasicCredential::new(
                requesting_user_bytes(),
            )
            .into(),
            key_material_request_signature: Vec::new(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.protocol != PROTOCOL_MLS10 {
            return Err(WireError::UnsupportedProtocol(self.protocol));
        }
        let mut out = vec![self.protocol];
        self.requesting_user
            .to_vlbytes()
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("requestingUser", e))?;
        self.target_user
            .to_vlbytes()
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("targetUser", e))?;
        self.room_id
            .to_vlbytes()
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("roomId", e))?;
        self.acceptable_ciphersuites
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("acceptableCiphersuites", e))?;
        self.required_capabilities
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("requiredCapabilities", e))?;
        self.requester_signature_key
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("requesterSignatureKey", e))?;
        self.requester_credential
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("requesterCredential", e))?;
        VLBytes::new(self.key_material_request_signature.clone())
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("key_material_request_signature", e))?;
        Ok(out)
    }
}

fn requesting_user_bytes() -> Vec<u8> {
    b"wire-proof-requester".to_vec()
}

/// §5.2 `KeyMaterialUserCode` (0-7, per the draft's own enum). `NoConsent`/`NoConsentForThisRoom`
/// are live (`key_material_wire` routes through `serve_key_material_gated`, whose
/// `KeyPackageAccess` denial maps directly to these two). `UserUnknown`/`UserDeleted` are modeled
/// for completeness; this reference hub's v1 store never distinguishes them, so encoding them is
/// dead-but-correct until a caller produces them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMaterialUserCode {
    Success,
    PartialSuccess,
    IncompatibleProtocol,
    NoCompatibleMaterial,
    UserUnknown,
    NoConsent,
    NoConsentForThisRoom,
    UserDeleted,
}

impl KeyMaterialUserCode {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::PartialSuccess => 1,
            Self::IncompatibleProtocol => 2,
            Self::NoCompatibleMaterial => 3,
            Self::UserUnknown => 4,
            Self::NoConsent => 5,
            Self::NoConsentForThisRoom => 6,
            Self::UserDeleted => 7,
        }
    }

    fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(Self::Success),
            1 => Ok(Self::PartialSuccess),
            2 => Ok(Self::IncompatibleProtocol),
            3 => Ok(Self::NoCompatibleMaterial),
            4 => Ok(Self::UserUnknown),
            5 => Ok(Self::NoConsent),
            6 => Ok(Self::NoConsentForThisRoom),
            7 => Ok(Self::UserDeleted),
            other => Err(WireError::Codec {
                what: "KeyMaterialUserCode",
                detail: format!("invalid value {other}"),
            }),
        }
    }
}

/// §5.2 `KeyMaterialClientCode` (0-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMaterialClientCode {
    Success,
    KeyMaterialExhausted,
    NothingCompatible,
}

impl KeyMaterialClientCode {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::KeyMaterialExhausted => 1,
            Self::NothingCompatible => 2,
        }
    }

    fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(Self::Success),
            1 => Ok(Self::KeyMaterialExhausted),
            2 => Ok(Self::NothingCompatible),
            other => Err(WireError::Codec {
                what: "KeyMaterialClientCode",
                detail: format!("invalid value {other}"),
            }),
        }
    }
}

/// §5.2 `KeyMaterialResponse` shaped for this reference hub's single-KeyPackage-per-user v1 model:
/// at most one `ClientKeyMaterial` entry, since v1 has no per-client enumeration. `Success` carries
/// the already-gate-validated KeyPackage bytes as stored (embedding, not re-parsing, since they
/// were proven well-formed at publish time); `Exhausted` covers the no-material-available case.
/// The draft does not specify which `KeyMaterialUserCode` wraps a single `keyMaterialExhausted`
/// client (the aggregation rule across `clients<V>` is unstated): `PartialSuccess` is used rather
/// than `UserUnknown`, on the reasoning that the target user is known (one client was enumerated
/// for them, it just has nothing to offer). Flagged as a named judgment call, not treated as
/// settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterialResponse {
    Success {
        user_uri: IdentifierUri,
        key_package: crate::gate::GatedKeyPackage,
    },
    Exhausted {
        user_uri: IdentifierUri,
    },
    /// The consent-aware gate (`Provider::serve_key_material_gated`) denied the request. `code`
    /// is `NoConsent` or `NoConsentForThisRoom` (§5.2's own userStatus codes 5/6). Carries NO client
    /// entries (`clients<V>` is empty) - there is no key material to describe, unlike Success/
    /// Exhausted which always carry exactly one.
    Denied {
        user_uri: IdentifierUri,
        code: KeyMaterialUserCode,
    },
}

impl KeyMaterialResponse {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut out = vec![PROTOCOL_MLS10];
        match self {
            Self::Success {
                user_uri,
                key_package,
            } => {
                out.push(KeyMaterialUserCode::Success.to_u8());
                user_uri
                    .to_vlbytes()
                    .tls_serialize(&mut out)
                    .map_err(|e| codec_err("userUri", e))?;
                // clients<V>: a <V> vector of ClientKeyMaterial is (byte-length-of-concatenated-
                // elements, then the elements). With exactly one element that is the same wire
                // shape as VLBytes(the element's own serialized bytes), so build the one element
                // then wrap it in VLBytes rather than hand-writing a second varint primitive.
                let mut client_buf = Vec::new();
                client_buf.push(KeyMaterialClientCode::Success.to_u8());
                user_uri
                    .to_vlbytes()
                    .tls_serialize(&mut client_buf)
                    .map_err(|e| codec_err("clientUri", e))?;
                client_buf.extend_from_slice(key_package.as_slice());
                VLBytes::new(client_buf)
                    .tls_serialize(&mut out)
                    .map_err(|e| codec_err("clients", e))?;
            }
            Self::Exhausted { user_uri } => {
                out.push(KeyMaterialUserCode::PartialSuccess.to_u8());
                user_uri
                    .to_vlbytes()
                    .tls_serialize(&mut out)
                    .map_err(|e| codec_err("userUri", e))?;
                let mut client_buf = Vec::new();
                client_buf.push(KeyMaterialClientCode::KeyMaterialExhausted.to_u8());
                user_uri
                    .to_vlbytes()
                    .tls_serialize(&mut client_buf)
                    .map_err(|e| codec_err("clientUri", e))?;
                VLBytes::new(client_buf)
                    .tls_serialize(&mut out)
                    .map_err(|e| codec_err("clients", e))?;
            }
            Self::Denied { user_uri, code } => {
                out.push(code.to_u8());
                user_uri
                    .to_vlbytes()
                    .tls_serialize(&mut out)
                    .map_err(|e| codec_err("userUri", e))?;
                // no client material to describe - clients<V> is empty.
                VLBytes::new(Vec::new())
                    .tls_serialize(&mut out)
                    .map_err(|e| codec_err("clients", e))?;
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (&protocol, rest) = bytes
            .split_first()
            .ok_or(WireError::UnsupportedProtocol(0))?;
        if protocol != PROTOCOL_MLS10 {
            return Err(WireError::UnsupportedProtocol(protocol));
        }
        let (&user_status_byte, rest) = rest.split_first().ok_or_else(|| WireError::Codec {
            what: "userStatus",
            detail: "truncated".into(),
        })?;
        let user_status = KeyMaterialUserCode::from_u8(user_status_byte)?;
        // Bound the scalar userUri too, same short-read panic class as any nested
        // element.
        let (user_uri_bounded, rest) = bounded_run_input(rest, "userUri", MAX_RUN_AGGREGATE_BYTES)?;
        let (user_uri_bytes, _user_uri_tail) = VLBytes::tls_deserialize_bytes(user_uri_bounded)
            .map_err(|e| codec_err("userUri", e))?;
        let user_uri = IdentifierUri::from_vlbytes(user_uri_bytes)?;
        // This window needs the same bounding as every other peer-controlled run: no peek, no
        // budget, means an unbounded declared length gets cloned in full. Semantically this
        // window carries at most one client entry (checked below), but that check runs after
        // this clone, so the clone itself must be bounded first.
        let (bounded, rest) = bounded_run_input(rest, "clients", MAX_RUN_AGGREGATE_BYTES)?;
        let (clients_blob, _tail) =
            VLBytes::tls_deserialize_bytes(bounded).map_err(|e| codec_err("clients", e))?;
        if !rest.is_empty() {
            return Err(WireError::Trailing {
                what: "KeyMaterialResponse",
                n: rest.len(),
            });
        }
        let client_bytes = clients_blob.as_slice();
        if matches!(
            user_status,
            KeyMaterialUserCode::NoConsent | KeyMaterialUserCode::NoConsentForThisRoom
        ) {
            if !client_bytes.is_empty() {
                return Err(WireError::Codec {
                    what: "KeyMaterialResponse.clients",
                    detail:
                        "a denial (NoConsent/NoConsentForThisRoom) must carry zero client entries"
                            .into(),
                });
            }
            return Ok(Self::Denied {
                user_uri,
                code: user_status,
            });
        }
        if client_bytes.is_empty() {
            return Err(WireError::Codec {
                what: "KeyMaterialResponse.clients",
                detail: "expected exactly one client entry, got zero".into(),
            });
        }
        let (&client_status_byte, client_rest) =
            client_bytes.split_first().ok_or_else(|| WireError::Codec {
                what: "clientStatus",
                detail: "truncated".into(),
            })?;
        let client_status = KeyMaterialClientCode::from_u8(client_status_byte)?;
        // `client_rest` sits inside the already-bounded `clients` window, but its
        // own content is attacker-chosen, so `clientUri`'s declared length can still exceed what
        // is actually left in `client_rest` - the same short-read panic class as an element
        // nested inside an outer Vec<T> run, just one field of a hand-parsed struct instead.
        let (client_uri_bounded, client_rest) =
            bounded_run_input(client_rest, "clientUri", MAX_RUN_AGGREGATE_BYTES)?;
        let (_client_uri_bytes, _client_uri_tail) =
            VLBytes::tls_deserialize_bytes(client_uri_bounded)
                .map_err(|e| codec_err("clientUri", e))?;
        match (user_status, client_status) {
            (KeyMaterialUserCode::Success, KeyMaterialClientCode::Success) => {
                // `KeyPackageIn::tls_deserialize_bytes` can PANIC (not just Err) on certain
                // malformed nested-length-prefix input -- the same tls_codec-internal panic risk
                // as the other peer-controlled KeyPackage sites in this file (clientKeyPackages[]
                // above, gate.rs's gates). catch_unwind turns a hostile/malformed KeyPackage into
                // a decode error instead of an unhandled panic in the request task.
                let (_kp, consumed) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    KeyPackageIn::tls_deserialize_bytes(client_rest)
                        .map(|(kp, tail)| (kp, client_rest.len() - tail.len()))
                }))
                .map_err(|_| WireError::Codec {
                    what: "keyPackage",
                    detail: "malformed KeyPackage (decoder panicked)".into(),
                })?
                .map_err(|e| codec_err("keyPackage", e))?;
                let key_package_bytes = &client_rest[..consumed];
                let cursor = &client_rest[consumed..];
                if !cursor.is_empty() {
                    return Err(WireError::Trailing {
                        what: "KeyMaterialResponse.clients[0]",
                        n: cursor.len(),
                    });
                }
                // The accept-gate runs here, not left to whichever caller eventually
                // hands `key_package` to openmls. A remote hub's claim that a KeyPackage is
                // well-formed is not a claim that it carries the pinned ciphersuite - a foreign
                // suite must never leave `decode()` wrapped in `Success`. Constructing the
                // `GatedKeyPackage` IS running the gate - there is no way to reach `Success`
                // with an ungated `key_package` field.
                let key_package = crate::gate::GatedKeyPackage::from_gated_bytes(key_package_bytes)?;
                Ok(Self::Success {
                    user_uri,
                    key_package,
                })
            }
            (KeyMaterialUserCode::PartialSuccess, KeyMaterialClientCode::KeyMaterialExhausted) => {
                if !client_rest.is_empty() {
                    return Err(WireError::Trailing {
                        what: "KeyMaterialResponse.clients[0]",
                        n: client_rest.len(),
                    });
                }
                Ok(Self::Exhausted { user_uri })
            }
            _ => Err(WireError::Codec {
                what: "KeyMaterialResponse",
                detail: format!(
                    "unsupported (userStatus, clientStatus) combination: ({user_status:?}, {client_status:?})"
                ),
            }),
        }
    }
}

// ============================ update (§5.3) - codec only, not wired ============================
//
// This section builds the §5.3 `HandshakeBundle`/`UpdateRequest`/`UpdateResponseCode`/
// `UpdateRoomResponse` codec and tests it against real openmls Commit/Proposal messages. It is not
// wired to an HTTP route. The draft's `update` transaction is how a client submits an MLS Commit
// or Proposal (carrying an AppSync CustomProposal for participant-list/room-policy changes, per
// §4.3.2) for the hub to validate and fan out. This reference hub's v1 `roomPolicy`/`memberRole`/
// `addParticipant` endpoints implement the policy outcome of that flow through ad-hoc JSON RPCs;
// they do not parse or process a real MLS Commit/Proposal at all, and there is no Provider method
// that does. Building one would mean writing the AppSync CustomProposal dispatch logic (0xF7A0,
// `participant_list.rs`) into a live accept-path - new protocol processing, which is out of
// scope for this module (wire framing only). Framing the wire shape without a real handler
// behind it would be a route that always answers success without doing anything, which is
// worse than no route.

/// §5.3 `GroupInfoRepresentation` (0-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupInfoRepresentation {
    Full,
    Partial,
}

impl GroupInfoRepresentation {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Full => 1,
            Self::Partial => 2,
        }
    }

    fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            1 => Ok(Self::Full),
            2 => Ok(Self::Partial),
            other => Err(WireError::Codec {
                what: "GroupInfoRepresentation",
                detail: format!("invalid value {other}"),
            }),
        }
    }
}

/// §5.3 `GroupInfoOption`. The `full`/`partial` payloads (`GroupInfo`/`PartialGroupInfo`) are
/// carried as opaque bytes (a disclosed residual -- see DIVERGENCES.md): the draft's
/// literal struct carries `payload` RAW, self-delimited by its own internal TLS structure, not
/// `<V>`-length-prefixed -- and `PartialGroupInfo` belongs to the unimplemented sibling draft, so
/// this codec cannot itself determine where a `Partial` payload ends without a decoder for that
/// type. (`openmls::messages::group_info::VerifiableGroupInfo` IS reachable and decodable for the
/// `Full` case -- absent from `openmls::prelude` but not `pub(crate)`-scoped.
/// `Full`-representation payloads are suite-gated at decode via
/// `crate::gate::mimi_gate_group_info`, `Partial` is not, since no decoder exists for it here or
/// in openmls's public surface.) `encode`/`decode` keep a length-prefix wrap here as the only way
/// to keep `ratchetTreeOption` (which follows it) findable at all; this is a known, disclosed
/// departure from the literal wire shape for this one field, not a silent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfoOption {
    pub representation: GroupInfoRepresentation,
    pub payload: Vec<u8>,
}

/// §5.3 `HandshakeBundle`. `proposal_or_commit` is the real MLS wire envelope (bounded the same
/// way `SubmitMessageRequest.app_message` is: parsed via `MlsMessageIn` to find the boundary, then
/// the already-consumed bytes are kept verbatim). `welcome` is `optional<Welcome>` -- a presence
/// tag then the RAW `Welcome` bytes (Note: `Welcome` is TLS-self-delimiting and
/// openmls's own type, so this codec decodes it exactly like `MlsMessageIn` elsewhere in this
/// module, no length wrap). `ratchet_tree_option` is the trailing field of the `commit` case, so
/// it needs no length prefix either -- it is simply everything left after `groupInfoOption`. See
/// `GroupInfoOption`'s own doc for why THAT field still carries a wrap.
///
/// `decode` requires `proposal_or_commit` to be `PublicMessage`-framed (matches §4.2's "the
/// PublicMessage encapsulation provides sender authentication, including the ability for actors
/// outside the group... to originate AppSync proposals", the reason the hub needs to read this
/// content at all) and rejects `PrivateMessage`. openmls's `MlsGroupCreateConfig::builder()`
/// without an explicit `wire_format_policy` produces `PrivateMessage`-framed Commits and
/// Proposals by default, discovered while writing this module's own tests: a caller building a
/// MIMI-conformant client needs `wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)` (or an
/// equivalent policy admitting `PublicMessage` handshake traffic) on the group, or every commit
/// and proposal it sends will be silently unreadable by a spec-conformant hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeBundle {
    Commit {
        proposal_or_commit: Vec<u8>,
        welcome: Option<crate::gate::GatedWelcome>,
        group_info_option: GroupInfoOption,
        ratchet_tree_option: Vec<u8>,
    },
    Proposal {
        proposal_or_commit: Vec<u8>,
        more_proposals: Vec<Vec<u8>>,
    },
}

impl HandshakeBundle {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        match self {
            Self::Commit {
                proposal_or_commit,
                welcome,
                group_info_option,
                ratchet_tree_option,
            } => {
                out.extend_from_slice(proposal_or_commit);
                match welcome {
                    // Note: Welcome is self-delimiting TLS -- no length wrap, matching
                    // the draft's literal `optional<Welcome>` (a presence tag then the value).
                    Some(w) => {
                        out.push(1);
                        out.extend_from_slice(w.as_slice());
                    }
                    None => out.push(0),
                }
                out.push(group_info_option.representation.to_u8());
                // GroupInfoOption.payload keeps a length wrap: see the type's own doc for why
                // (no self-delimiting decoder available for either GroupInfo or PartialGroupInfo).
                VLBytes::new(group_info_option.payload.clone())
                    .tls_serialize(&mut out)
                    .map_err(|e| codec_err("groupInfoOption.payload", e))?;
                // ratchetTreeOption is the trailing field of the commit case -- no length prefix
                // needed at all, raw bytes to the end.
                out.extend_from_slice(ratchet_tree_option);
            }
            Self::Proposal {
                proposal_or_commit,
                more_proposals,
            } => {
                out.extend_from_slice(proposal_or_commit);
                // Same class of bug as elsewhere in this module: `MLSMessage moreProposals<V>` is ONE outer
                // length wrapping concatenated self-delimiting MLSMessage objects, not a vector of
                // individually length-prefixed blobs.
                let mut concatenated = Vec::new();
                for p in more_proposals {
                    concatenated.extend_from_slice(p);
                }
                VLBytes::new(concatenated)
                    .tls_serialize(&mut out)
                    .map_err(|e| codec_err("moreProposals", e))?;
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        // `MlsMessageIn::tls_deserialize` can PANIC (not just Err) on certain malformed
        // nested-length-prefix input -- the same tls_codec-internal panic risk as the welcome/
        // moreProposals parses below in this same function (peer-controlled bytes). catch_unwind
        // turns a hostile/malformed proposalOrCommit into a decode error instead of an unhandled
        // panic in the request task.
        let (msg, consumed) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut c: &[u8] = bytes;
            MlsMessageIn::tls_deserialize(&mut c).map(|m| (m, bytes.len() - c.len()))
        }))
        .map_err(|_| WireError::Codec {
            what: "proposalOrCommit",
            detail: "malformed MLSMessage (decoder panicked)".into(),
        })?
        .map_err(|e| WireError::MlsMessage(format!("{e:?}")))?;
        let cursor: &[u8] = &bytes[consumed..];
        let proposal_or_commit = bytes[..consumed].to_vec();
        let content_type = match msg.extract() {
            openmls::prelude::MlsMessageBodyIn::PublicMessage(pm) => pm.content_type(),
            other => {
                return Err(WireError::MlsMessage(format!(
                    "expected a PublicMessage-framed Commit or Proposal, got {other:?}"
                )))
            }
        };
        match content_type {
            openmls::prelude::ContentType::Commit => {
                let (&welcome_tag, rest) =
                    cursor.split_first().ok_or_else(|| WireError::Codec {
                        what: "welcome presence tag",
                        detail: "truncated".into(),
                    })?;
                // Note: welcome is RAW self-delimiting bytes, no length wrap. Decoded
                // via MlsMessageIn (not a bare Welcome): openmls's own add_members returns the
                // Welcome wrapped in the general MlsMessage envelope (protocol_version +
                // wire_format + body), which is what any real openmls-based client actually
                // serializes onto the wire -- confirmed empirically (a bare-Welcome decode
                // misaligned the fields that follow, against a real openmls-produced Welcome).
                // catch_unwind for the same tls_codec-internal-panic reason as the KeyPackage
                // gates -- Welcome is peer-controlled.
                let (welcome, rest) = match welcome_tag {
                    0 => (None, rest),
                    1 => {
                        let (_w, consumed_len) =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                let mut c: &[u8] = rest;
                                MlsMessageIn::tls_deserialize(&mut c)
                                    .map(|w| (w, rest.len() - c.len()))
                            }))
                            .map_err(|_| WireError::Codec {
                                what: "welcome",
                                detail: "malformed Welcome (decoder panicked)".into(),
                            })?
                            .map_err(|e| codec_err("welcome", e))?;
                        // This is the same MlsMessage-wrapped Welcome shape
                        // `mimi_gate_welcome` gates on the `/keyMaterial` receive path - a hub
                        // forwarding a Commit's welcome is exactly the "decode -> join" path the
                        // accept-gate exists for. Constructing the `GatedWelcome` IS running the
                        // gate - there is no way to reach `Commit` with an ungated `welcome` field.
                        let w = crate::gate::GatedWelcome::from_gated_bytes(&rest[..consumed_len])?;
                        (Some(w), &rest[consumed_len..])
                    }
                    other => {
                        return Err(WireError::Codec {
                            what: "welcome presence tag",
                            detail: format!("expected 0 or 1, got {other}"),
                        })
                    }
                };
                let (&repr_byte, rest) = rest.split_first().ok_or_else(|| WireError::Codec {
                    what: "GroupInfoRepresentation",
                    detail: "truncated".into(),
                })?;
                let representation = GroupInfoRepresentation::from_u8(repr_byte)?;
                // groupInfoOption.payload keeps its length wrap (see the type's own doc); this is
                // what lets ratchetTreeOption below be found without needing to parse it.
                // Bound before decoding, same short-read panic class as any other
                // scalar VLBytes field.
                let (gi_payload_bounded, rest) =
                    bounded_run_input(rest, "groupInfoOption.payload", MAX_RUN_AGGREGATE_BYTES)?;
                let (gi_payload, _gi_payload_tail) =
                    VLBytes::tls_deserialize_bytes(gi_payload_bounded)
                        .map_err(|e| codec_err("groupInfoOption.payload", e))?;
                // `Full` representation is decodable as a `VerifiableGroupInfo` (see the
                // type's own doc for the correction on that point) and is join material a caller
                // could feed to `join_by_external_commit` - gate it. `Partial`
                // (`PartialGroupInfo`) has no decoder anywhere in this crate or in openmls's
                // public surface, so it cannot be suite-checked here; this is a disclosed
                // residual, not an oversight - see the type's own doc.
                if representation == GroupInfoRepresentation::Full {
                    crate::gate::mimi_gate_group_info(gi_payload.as_slice())?;
                }
                // ratchetTreeOption is the trailing field -- everything left, raw, no wrap.
                let rt_option = rest;
                Ok(Self::Commit {
                    proposal_or_commit,
                    welcome,
                    group_info_option: GroupInfoOption {
                        representation,
                        payload: gi_payload.as_slice().to_vec(),
                    },
                    ratchet_tree_option: rt_option.to_vec(),
                })
            }
            openmls::prelude::ContentType::Proposal => {
                // Same class of bug as elsewhere in this module: one outer window bounds a run of
                // self-delimiting MLSMessage objects, not individually length-prefixed blobs.
                // Bound the input to the declared window before decoding it.
                let (bounded, rest) =
                    bounded_run_input(cursor, "moreProposals", MAX_RUN_AGGREGATE_BYTES)?;
                let (window, _tail) = VLBytes::tls_deserialize_bytes(bounded)
                    .map_err(|e| codec_err("moreProposals", e))?;
                if !rest.is_empty() {
                    return Err(WireError::Trailing {
                        what: "HandshakeBundle(proposal)",
                        n: rest.len(),
                    });
                }
                let window = window.as_slice();
                let mut offset = 0usize;
                let mut wrapped = Vec::new();
                let mut budget = RunBudget::new();
                while offset < window.len() {
                    let slice = &window[offset..];
                    let consumed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let mut c: &[u8] = slice;
                        MlsMessageIn::tls_deserialize(&mut c).map(|_| slice.len() - c.len())
                    }))
                    .map_err(|_| WireError::Codec {
                        what: "moreProposals[]",
                        detail: "malformed MLSMessage (decoder panicked)".into(),
                    })?
                    .map_err(|e| WireError::MlsMessage(format!("{e:?}")))?;
                    budget.record("moreProposals[]", consumed)?;
                    wrapped.push(window[offset..offset + consumed].to_vec());
                    offset += consumed;
                }
                Ok(Self::Proposal {
                    proposal_or_commit,
                    more_proposals: wrapped,
                })
            }
            other => Err(WireError::MlsMessage(format!(
                "HandshakeBundle's proposalOrCommit must be a Commit or Proposal, got {other:?}"
            ))),
        }
    }
}

/// §5.3 `UpdateResponseCode` (0-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateResponseCode {
    Success,
    WrongEpoch,
    NotAllowed,
    InvalidProposal,
}

impl UpdateResponseCode {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::WrongEpoch => 1,
            Self::NotAllowed => 2,
            Self::InvalidProposal => 3,
        }
    }

    fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            0 => Ok(Self::Success),
            1 => Ok(Self::WrongEpoch),
            2 => Ok(Self::NotAllowed),
            3 => Ok(Self::InvalidProposal),
            other => Err(WireError::Codec {
                what: "UpdateResponseCode",
                detail: format!("invalid value {other}"),
            }),
        }
    }
}

/// §5.3 `UpdateRoomResponse`. `invalid_proposals` (the `invalidProposal` case's `ProposalRef
/// invalidProposals<V>`) is carried as a list of opaque refs (`ProposalRef` is a plain hash
/// value elsewhere in openmls; a `Vec<VLBytes>` of its raw bytes is wire-equivalent without
/// pulling in the type solely for this one field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateRoomResponse {
    Success {
        error_description: String,
        accepted_timestamp: u64,
    },
    WrongEpoch {
        error_description: String,
        current_epoch: u64,
    },
    NotAllowed {
        error_description: String,
    },
    InvalidProposal {
        error_description: String,
        invalid_proposals: Vec<Vec<u8>>,
    },
}

impl UpdateRoomResponse {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        let (code, desc) = match self {
            Self::Success {
                error_description, ..
            } => (UpdateResponseCode::Success, error_description),
            Self::WrongEpoch {
                error_description, ..
            } => (UpdateResponseCode::WrongEpoch, error_description),
            Self::NotAllowed { error_description } => {
                (UpdateResponseCode::NotAllowed, error_description)
            }
            Self::InvalidProposal {
                error_description, ..
            } => (UpdateResponseCode::InvalidProposal, error_description),
        };
        out.push(code.to_u8());
        VLBytes::new(desc.clone().into_bytes())
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("errorDescription", e))?;
        match self {
            Self::Success {
                accepted_timestamp, ..
            } => out.extend_from_slice(&accepted_timestamp.to_be_bytes()),
            Self::WrongEpoch { current_epoch, .. } => {
                out.extend_from_slice(&current_epoch.to_be_bytes())
            }
            Self::NotAllowed { .. } => {}
            Self::InvalidProposal {
                invalid_proposals, ..
            } => {
                let wrapped: Vec<VLBytes> = invalid_proposals
                    .iter()
                    .map(|r| VLBytes::new(r.clone()))
                    .collect();
                wrapped
                    .tls_serialize(&mut out)
                    .map_err(|e| codec_err("invalidProposals", e))?;
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (&code_byte, rest) = bytes.split_first().ok_or_else(|| WireError::Codec {
            what: "UpdateResponseCode",
            detail: "empty input".into(),
        })?;
        let code = UpdateResponseCode::from_u8(code_byte)?;
        // Bound before decoding, same short-read panic class as any other scalar
        // VLBytes field.
        let (desc_bounded, rest) =
            bounded_run_input(rest, "errorDescription", MAX_RUN_AGGREGATE_BYTES)?;
        let (desc_bytes, _desc_tail) = VLBytes::tls_deserialize_bytes(desc_bounded)
            .map_err(|e| codec_err("errorDescription", e))?;
        let error_description =
            String::from_utf8(desc_bytes.as_slice().to_vec()).map_err(|_| WireError::Codec {
                what: "errorDescription",
                detail: "not valid UTF-8".into(),
            })?;
        match code {
            UpdateResponseCode::Success => {
                let ts = read_u64(rest, "accepted_timestamp")?;
                Ok(Self::Success {
                    error_description,
                    accepted_timestamp: ts,
                })
            }
            UpdateResponseCode::WrongEpoch => {
                let epoch = read_u64(rest, "currentEpoch")?;
                Ok(Self::WrongEpoch {
                    error_description,
                    current_epoch: epoch,
                })
            }
            UpdateResponseCode::NotAllowed => {
                if !rest.is_empty() {
                    return Err(WireError::Trailing {
                        what: "UpdateRoomResponse(notAllowed)",
                        n: rest.len(),
                    });
                }
                Ok(Self::NotAllowed { error_description })
            }
            UpdateResponseCode::InvalidProposal => {
                // `Vec<VLBytes>::tls_deserialize_bytes` is tls_codec's own blanket
                // impl, and it does not bound an element's own declared length to what remains of
                // the outer window - it hands each element whatever slice it is given, so an
                // inner `VLBytes` that declares more than the outer window has left is still
                // handed to tls_codec's decode, which hits its short-read `debug_assert_eq!` and
                // panics under `cargo test` (compiled out under `--release`, so outer-only
                // bounding alone masks this under `--release` while still panicking in
                // debug/CI). Fix: decode this run one element at a time, bounding each element to
                // its own declared length before the real decode runs, so an overshooting element
                // fails closed (`WireError`) instead of ever reaching tls_codec's short-read path.
                // Not live in this hub's own HTTP handlers (no accept-path for `update`, per this
                // module's own doc), but public API any consumer decodes an `UpdateRoomResponse`
                // with.
                let (bounded, tail) =
                    bounded_run_input(rest, "invalidProposals", MAX_RUN_AGGREGATE_BYTES)?;
                let (window_vlbytes, _outer_tail) = VLBytes::tls_deserialize_bytes(bounded)
                    .map_err(|e| codec_err("invalidProposals", e))?;
                let mut cursor = window_vlbytes.as_slice();
                let mut invalid_proposals = Vec::new();
                let mut budget = RunBudget::new();
                while !cursor.is_empty() {
                    let (elem_bounded, next_cursor) =
                        bounded_run_input(cursor, "invalidProposals[]", MAX_RUN_AGGREGATE_BYTES)?;
                    let (elem, _elem_tail) = VLBytes::tls_deserialize_bytes(elem_bounded)
                        .map_err(|e| codec_err("invalidProposals[]", e))?;
                    budget.record("invalidProposals[]", cursor.len() - next_cursor.len())?;
                    // VLBytes -> Vec<u8> is an owned move (`impl From<VLBytes> for Vec<u8>`),
                    // not a second clone of already-owned bytes.
                    invalid_proposals.push(Vec::from(elem));
                    cursor = next_cursor;
                }
                if !tail.is_empty() {
                    return Err(WireError::Trailing {
                        what: "UpdateRoomResponse(invalidProposal)",
                        n: tail.len(),
                    });
                }
                Ok(Self::InvalidProposal {
                    error_description,
                    invalid_proposals,
                })
            }
        }
    }
}

// ============================ notify inbound-receive (§5.5) ============================
//
// The draft's literal §5.5 struct starts DIRECTLY with `uint64 timestamp` -- no leading
// `Protocol` field at all (confirmed against the published protocol-06 text, not assumed) - this
// is the draft's actual shape, not a draft gap needing a workaround. `protocol` stays as a
// Rust-level field (every sibling type in this module keys its `select(protocol)` branch on
// one; mls10 is the only value this hub speaks) but is no longer written to or read from the
// wire.
//
// The four `select (message.wire_format)` tail shapes (application/welcome/proposal/commit)
// are not modeled separately; this reference hub's own `submit_notify` treats the whole body as
// opaque bytes for dedup-by-content-hash, so decoding only needs to find `message`'s boundary
// (via `MlsMessageIn`, the same technique used throughout this module), not interpret its
// contents. This is the inbound-receive shape only (what a real MIMI hub would send US); the
// outbound-calling side (this hub acting as a hub, pushing fanout to foreign followers), support
// for concatenated FanoutMessage objects in one body, and per-wire-format tail parsing are all
// materially different, not-yet-built features -- see DIVERGENCES.md.

/// §5.5 `FanoutMessage`, inbound-receive framing only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutMessage {
    pub protocol: Protocol,
    pub timestamp: u64,
    /// The MLS message envelope plus everything the `select (message.wire_format)` tail carries,
    /// kept as one opaque blob (see the section doc for why: nothing downstream interprets it).
    pub message_and_tail: Vec<u8>,
}

impl FanoutMessage {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.protocol != PROTOCOL_MLS10 {
            return Err(WireError::UnsupportedProtocol(self.protocol));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.message_and_tail);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let timestamp = read_u64(&bytes[..bytes.len().min(8)], "timestamp")?;
        let rest = bytes.get(8..).ok_or_else(|| WireError::Codec {
            what: "timestamp",
            detail: "truncated".into(),
        })?;
        let protocol = PROTOCOL_MLS10;
        // Confirm `message` at least parses as a real MLS envelope (a garbage body must not be
        // silently accepted as opaque bytes), then keep everything from here on as one blob.
        // `MlsMessageIn::tls_deserialize` can PANIC (not just Err) on certain malformed
        // nested-length-prefix input -- the same tls_codec-internal panic risk as the other
        // peer-controlled MLSMessage sites in this file. catch_unwind turns a hostile/malformed
        // `message` into a decode error instead of an unhandled panic in the request task.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut c: &[u8] = rest;
            MlsMessageIn::tls_deserialize(&mut c)
        }))
        .map_err(|_| WireError::Codec {
            what: "message",
            detail: "malformed MLSMessage (decoder panicked)".into(),
        })?
        .map_err(|e| WireError::MlsMessage(format!("{e:?}")))?;
        Ok(Self {
            protocol,
            timestamp,
            message_and_tail: rest.to_vec(),
        })
    }
}

// ============================ identifierQuery (§5.8) ============================
//
// Request framed fully (`IdentifierRequest`/`QueryElement`), matching wire fidelity for a real
// client's query. This reference hub's own `identifier_query` handler is DIV-4 (a documented
// PRIVACY-UPGRADE divergence, stronger than the spec default): it answers a single opt-in-enrolled
// username lookup and returns NO response body over JSON, by design, so a found-vs-not-found
// answer can never be distinguished by response shape (only by status). The wire lane preserves
// this: only the first query element's search value is used (matching the v1 single-username
// model), and `IdentifierResponse` is built for wire completeness/testing but the actual mimi-hub
// route (like the JSON one) never sends a response body, keeping the DIV-4 property intact rather
// than reintroducing a body-shaped oracle the JSON lane is built specifically to avoid.

/// §5.8 `SearchIdentifierType` (0-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchIdentifierType {
    Handle,
    Nick,
    Email,
    Phone,
    PartialName,
    WholeProfile,
    OidcStdClaim,
    VcardField,
}

impl SearchIdentifierType {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Handle => 1,
            Self::Nick => 2,
            Self::Email => 3,
            Self::Phone => 4,
            Self::PartialName => 5,
            Self::WholeProfile => 6,
            Self::OidcStdClaim => 7,
            Self::VcardField => 8,
        }
    }

    fn from_u8(v: u8) -> Result<Self, WireError> {
        match v {
            1 => Ok(Self::Handle),
            2 => Ok(Self::Nick),
            3 => Ok(Self::Email),
            4 => Ok(Self::Phone),
            5 => Ok(Self::PartialName),
            6 => Ok(Self::WholeProfile),
            7 => Ok(Self::OidcStdClaim),
            8 => Ok(Self::VcardField),
            other => Err(WireError::Codec {
                what: "SearchIdentifierType",
                detail: format!("invalid or reserved(0) value {other}"),
            }),
        }
    }
}

/// §5.8 `QueryElement`. `qualifier` carries `claimName`/`propertyName` for the two search types
/// that need one (empty otherwise); `search_value` is always present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryElement {
    pub search_type: SearchIdentifierType,
    pub qualifier: Vec<u8>,
    pub search_value: Vec<u8>,
}

impl QueryElement {
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.push(self.search_type.to_u8());
        if matches!(
            self.search_type,
            SearchIdentifierType::OidcStdClaim | SearchIdentifierType::VcardField
        ) {
            VLBytes::new(self.qualifier.clone())
                .tls_serialize(out)
                .map_err(|e| codec_err("QueryElement qualifier", e))?;
        }
        VLBytes::new(self.search_value.clone())
            .tls_serialize(out)
            .map_err(|e| codec_err("searchValue", e))?;
        Ok(())
    }

    fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), WireError> {
        let (&type_byte, rest) = bytes.split_first().ok_or_else(|| WireError::Codec {
            what: "QueryElement.searchType",
            detail: "truncated".into(),
        })?;
        let search_type = SearchIdentifierType::from_u8(type_byte)?;
        // `qualifier`/`searchValue` sit inside `elems_blob`'s already-bounded
        // window, but their own declared lengths (attacker content within that window) can still
        // exceed what is left in it - bound each before decoding, same class as any other scalar.
        let (qualifier, rest) = if matches!(
            search_type,
            SearchIdentifierType::OidcStdClaim | SearchIdentifierType::VcardField
        ) {
            let (q_bounded, rest) = bounded_run_input(rest, "qualifier", MAX_RUN_AGGREGATE_BYTES)?;
            let (q, _q_tail) =
                VLBytes::tls_deserialize_bytes(q_bounded).map_err(|e| codec_err("qualifier", e))?;
            (q.as_slice().to_vec(), rest)
        } else {
            (Vec::new(), rest)
        };
        let (value_bounded, rest) =
            bounded_run_input(rest, "searchValue", MAX_RUN_AGGREGATE_BYTES)?;
        let (value, _value_tail) = VLBytes::tls_deserialize_bytes(value_bounded)
            .map_err(|e| codec_err("searchValue", e))?;
        Ok((
            Self {
                search_type,
                qualifier,
                search_value: value.as_slice().to_vec(),
            },
            rest,
        ))
    }
}

/// §5.8 `IdentifierRequest`. `id_request_extensions` (`AppDataDictionary`) is carried as an opaque
/// `<V>` blob, the same treatment used for every other `AppDataDictionary`/sibling-draft field in
/// this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierRequest {
    pub query_elements: Vec<QueryElement>,
}

impl IdentifierRequest {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut elems_buf = Vec::new();
        for e in &self.query_elements {
            e.encode_into(&mut elems_buf)?;
        }
        let mut out = Vec::new();
        VLBytes::new(elems_buf)
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("query_elements", e))?;
        VLBytes::new(Vec::new())
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("id_request_extensions", e))?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        // The identifier-query wire format allows more than one query element, but this
        // hub's own `primary_search_value` only ever reads the first (see its doc below) - a
        // per-site budget tighter than the shared run default reflects that real usage, not a
        // spec-derived limit. Bound the input to the declared window before decoding it.
        let (bounded, rest) =
            bounded_run_input(bytes, "query_elements", MAX_QUERY_AGGREGATE_BYTES)?;
        let (elems_blob, _tail) =
            VLBytes::tls_deserialize_bytes(bounded).map_err(|e| codec_err("query_elements", e))?;
        // This run has no pre-check before this clone; the same bounding this module
        // applies to every other peer-controlled run applies here too.
        let (ext_bounded, rest) =
            bounded_run_input(rest, "id_request_extensions", MAX_RUN_AGGREGATE_BYTES)?;
        let (_ext_blob, _ext_tail) = VLBytes::tls_deserialize_bytes(ext_bounded)
            .map_err(|e| codec_err("id_request_extensions", e))?;
        if !rest.is_empty() {
            return Err(WireError::Trailing {
                what: "IdentifierRequest",
                n: rest.len(),
            });
        }
        let mut elems = Vec::new();
        let mut cursor = elems_blob.as_slice();
        let mut budget = RunBudget::with_limits(MAX_QUERY_ELEMENTS, MAX_QUERY_AGGREGATE_BYTES);
        while !cursor.is_empty() {
            let (e, tail) = QueryElement::decode_from(cursor)?;
            budget.record("query_elements[]", cursor.len() - tail.len())?;
            elems.push(e);
            cursor = tail;
        }
        Ok(Self {
            query_elements: elems,
        })
    }

    /// The effective username this reference hub's v1 `identifier_query` looks up. Requires EXACTLY
    /// ONE query element, of type `Handle` (Haven's v1 model has no other identifier type - no
    /// email/phone/OIDC/vcard search backing store exists), decoded as UTF-8; returns `None`
    /// otherwise (zero elements, more than one element, or a non-Handle element - a decoder that
    /// silently ignored these and only ever looked at the first element regardless of type or count
    /// would have the wrong AND-across-elements semantics the draft implies for a multi-element
    /// query). This hub still can't honor true AND-semantics across heterogeneous identifier types -
    /// see DIVERGENCES.md DIV-4 - but it never pretends a query it can't evaluate matched.
    pub fn primary_search_value(&self) -> Option<String> {
        let [element] = self.query_elements.as_slice() else {
            return None;
        };
        if element.search_type != SearchIdentifierType::Handle {
            return None;
        }
        String::from_utf8(element.search_value.clone()).ok()
    }
}

/// §5.8 `IdentifierQueryCode` (0-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierQueryCode {
    Success,
    NotFound,
    Ambiguous,
    Forbidden,
    UnsupportedField,
}

impl IdentifierQueryCode {
    const fn to_u8(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::NotFound => 1,
            Self::Ambiguous => 2,
            Self::Forbidden => 3,
            Self::UnsupportedField => 4,
        }
    }
}

/// §5.8 `IdentifierResponse`, built for wire completeness/testing. `foundProfiles<V>` and
/// `id_response_extensions` are always empty in this reference hub's usage (DIV-4: it never
/// discloses profile data, only an opt-in-enrolled/not existence signal) so this only encodes the
/// zero-profile shape rather than the general `ProfileField` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierResponse {
    pub response_code: IdentifierQueryCode,
    pub uri: IdentifierUri,
}

impl IdentifierResponse {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut out = vec![self.response_code.to_u8()];
        self.uri
            .to_vlbytes()
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("uri", e))?;
        VLBytes::new(Vec::new()) // foundProfiles<V>: always empty here
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("foundProfiles", e))?;
        VLBytes::new(Vec::new()) // id_response_extensions
            .tls_serialize(&mut out)
            .map_err(|e| codec_err("id_response_extensions", e))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::ConsentEntry;

    fn tohex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A real, `KeyPackageIn`-decodable KeyPackage's serialized bytes -- shared by every test that
    /// needs a genuine self-delimiting KeyPackage rather than a placeholder blob (a placeholder
    /// silently passes a decoder that never actually parses the field, hiding exactly the class
    /// of bug this file's KATs need to catch).
    fn real_key_package_bytes(credential_name: &[u8]) -> Vec<u8> {
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::prelude::{Extensions, KeyPackage, Lifetime, OpenMlsCrypto, SignatureScheme};
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;

        struct S {
            key: Vec<u8>,
            scheme: SignatureScheme,
        }
        impl Signer for S {
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
                OpenMlsRustCrypto::default()
                    .crypto()
                    .sign(self.scheme, payload, &self.key)
                    .map_err(|_| SignerError::SigningError)
            }
            fn signature_scheme(&self) -> SignatureScheme {
                self.scheme
            }
        }

        let provider = OpenMlsRustCrypto::default();
        let suite = openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let scheme = SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(credential_name.to_vec()).into(),
            signature_key: pk,
        };
        let signer = S {
            key: priv_b,
            scheme,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
            "not_before": now.saturating_sub(3600),
            "not_after": now + 60 * 60 * 24 * 84,
        }))
        .unwrap();
        let kpb = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime)
            .build(suite, &provider, &signer, cwk)
            .unwrap();
        kpb.key_package().tls_serialize_detached().unwrap()
    }

    // ---- ConsentEntry: hand-constructed byte-level KAT. A self-round-trip alone proves nothing
    // cross-implementation, so the expected bytes below are computed independently from the struct
    // layout, not derived from the encoder itself. ----
    #[test]
    fn consent_entry_kat_request_no_room() {
        // operation=request(1) requesterUri="mimi://a.example/u/alice" (24B) targetUri="mimi://b.example/u/bob" (22B)
        // roomId tag=0 (absent) [grant-only field skipped] consent_extensions=<V> empty(00)
        let e = ConsentEntry {
            operation: ConsentOperation::Request,
            requester_uri: "mimi://a.example/u/alice".to_string(),
            target_uri: "mimi://b.example/u/bob".to_string(),
            room_uri: None,
            client_key_packages: Vec::new(),
            consent_extensions: Vec::new(),
        };
        let encoded = encode_consent_entry(&e).unwrap();
        // 1 (op) + [varint-len(24)=18 + 24B requester] + [varint-len(22)=16 + 22B target] + 1 (room tag=0) + 1 (ext len=00)
        let mut want = vec![0x01u8];
        want.push(24); // requester uri length (single-byte QUIC varint, <64)
        want.extend_from_slice(b"mimi://a.example/u/alice");
        want.push(22);
        want.extend_from_slice(b"mimi://b.example/u/bob");
        want.push(0x00); // roomId absent
        want.push(0x00); // consent_extensions empty
        assert_eq!(tohex(&encoded), tohex(&want), "hand-computed KAT mismatch");
        assert_eq!(decode_consent_entry(&encoded).unwrap(), e, "round-trip");
    }

    #[test]
    fn consent_entry_kat_grant_with_room_and_kp() {
        // Note: a real, KeyPackageIn-decodable KeyPackage, not a placeholder blob --
        // the old placeholder silently passed the (broken) per-element-length-prefixed decoder,
        // a textbook case of a hand-written KAT locking in the divergence it should catch.
        let kp_bytes = real_key_package_bytes(b"bob");
        let e = ConsentEntry {
            operation: ConsentOperation::Grant,
            requester_uri: "mimi://a.example/u/alice".to_string(),
            target_uri: "mimi://b.example/u/bob".to_string(),
            room_uri: Some("mimi://a.example/r/team".to_string()),
            client_key_packages: vec![kp_bytes.clone()],
            consent_extensions: Vec::new(),
        };
        let encoded = encode_consent_entry(&e).unwrap();
        let mut want = vec![0x02u8]; // grant
        want.push(24);
        want.extend_from_slice(b"mimi://a.example/u/alice");
        want.push(22);
        want.extend_from_slice(b"mimi://b.example/u/bob");
        want.push(0x01); // roomId present
        want.push(23);
        want.extend_from_slice(b"mimi://a.example/r/team");
        // clientKeyPackages<V>: ONE outer length wrapping the KeyPackage bytes directly --
        // NOT a per-element length-prefixed blob. The wrap-width itself is QUIC-varint (VLBytes's
        // own encoding, tls_codec's quic_vec module) and not what this KAT is proving; VLBytes is
        // used here as a trusted primitive to compute the expected wrap, the way the existing
        // key_material_response tests already treat it. What this KAT proves is the STRUCTURE: one
        // wrap of the raw bytes, not a wrap-of-wraps.
        let mut wrapped_kp = Vec::new();
        VLBytes::new(kp_bytes.clone())
            .tls_serialize(&mut wrapped_kp)
            .unwrap();
        want.extend_from_slice(&wrapped_kp);
        want.push(0x00); // consent_extensions empty
        assert_eq!(tohex(&encoded), tohex(&want), "hand-computed KAT mismatch");
        assert_eq!(decode_consent_entry(&encoded).unwrap(), e, "round-trip");
    }

    #[test]
    fn consent_entry_decode_rejects_old_double_length_prefixed_shape() {
        // Regression guard: the OLD (buggy) encoding -- outer_len || (kp_len || kp_bytes), i.e.
        // literally `Vec<VLBytes>` -- must now be REJECTED, not silently accepted as if it were
        // the correct outer_len || kp_bytes shape.
        let kp_bytes = real_key_package_bytes(b"bob");
        let mut bad = vec![0x02u8]; // grant
        bad.push(24);
        bad.extend_from_slice(b"mimi://a.example/u/alice");
        bad.push(22);
        bad.extend_from_slice(b"mimi://b.example/u/bob");
        bad.push(0x00); // no room
                        // the exact old buggy encoder: Vec<VLBytes> serialization (double-wrapped).
        let old_buggy: Vec<VLBytes> = vec![VLBytes::new(kp_bytes.clone())];
        old_buggy.tls_serialize(&mut bad).unwrap();
        bad.push(0x00); // consent_extensions empty
        assert!(decode_consent_entry(&bad).is_err());
    }

    #[test]
    fn consent_entry_decode_rejects_trailing_bytes() {
        let e = ConsentEntry {
            operation: ConsentOperation::Cancel,
            requester_uri: "mimi://a.example/u/a".to_string(),
            target_uri: "mimi://b.example/u/b".to_string(),
            room_uri: None,
            client_key_packages: Vec::new(),
            consent_extensions: Vec::new(),
        };
        let mut bytes = encode_consent_entry(&e).unwrap();
        bytes.push(0xFF);
        assert!(matches!(
            decode_consent_entry(&bytes),
            Err(WireError::Trailing { .. })
        ));
    }

    #[test]
    fn consent_entry_decode_rejects_bad_operation_byte() {
        let bytes = unhex("ff00");
        assert!(decode_consent_entry(&bytes).is_err());
    }

    /// A consent grant's `clientKeyPackages` are join material a requester may
    /// add to a group directly, mirroring `real_key_package_bytes` but under a non-pinned suite
    /// (INV-MLS-002-ALLOW: test-only, never a production path). The accept-gate must reject the
    /// whole entry before the foreign-suite KeyPackage can leave `decode_consent_entry` at all.
    fn foreign_suite_key_package_bytes(credential_name: &[u8]) -> Vec<u8> {
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::prelude::{Extensions, KeyPackage, Lifetime, OpenMlsCrypto, SignatureScheme};
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;

        struct S {
            key: Vec<u8>,
            scheme: SignatureScheme,
        }
        impl Signer for S {
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
                OpenMlsRustCrypto::default()
                    .crypto()
                    .sign(self.scheme, payload, &self.key)
                    .map_err(|_| SignerError::SigningError)
            }
            fn signature_scheme(&self) -> SignatureScheme {
                self.scheme
            }
        }

        let provider = OpenMlsRustCrypto::default();
        // INV-MLS-002-ALLOW (test-only): the foreign suite the gate must reject.
        let suite =
            openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let scheme = SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(credential_name.to_vec()).into(),
            signature_key: pk,
        };
        let signer = S {
            key: priv_b,
            scheme,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
            "not_before": now.saturating_sub(3600),
            "not_after": now + 60 * 60 * 24 * 84,
        }))
        .unwrap();
        let kpb = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime)
            .build(suite, &provider, &signer, cwk)
            .unwrap();
        kpb.key_package().tls_serialize_detached().unwrap()
    }

    #[test]
    fn consent_entry_decode_rejects_foreign_suite_keypackage() {
        let kp_bytes = foreign_suite_key_package_bytes(b"eve");
        let e = ConsentEntry {
            operation: ConsentOperation::Grant,
            requester_uri: "mimi://a.example/u/alice".to_string(),
            target_uri: "mimi://b.example/u/eve".to_string(),
            room_uri: None,
            client_key_packages: vec![kp_bytes],
            consent_extensions: Vec::new(),
        };
        let encoded = encode_consent_entry(&e).unwrap();
        let err = decode_consent_entry(&encoded)
            .expect_err("a 0x0003 KeyPackage must never leave decode_consent_entry");
        assert!(
            matches!(err, WireError::CiphersuiteGate(_)),
            "expected the ciphersuite accept-gate to reject it, got: {err:?}"
        );
    }

    /// `decode_consent_entry` must call `validate_consent_entry` and never return an
    /// entry that fails semantic validation - a room URI as the requester parses fine (any
    /// well-formed `IdentifierUri` bytes decode) but is semantically invalid (§5.7 requires a
    /// user URI there). Fail-before/pass-after: this exact payload decoded successfully before
    /// the validation call was wired in.
    #[test]
    fn consent_entry_decode_rejects_semantically_invalid_requester() {
        let e = ConsentEntry {
            operation: ConsentOperation::Request,
            requester_uri: "mimi://a.example/r/notauser".to_string(),
            target_uri: "mimi://b.example/u/bob".to_string(),
            room_uri: None,
            client_key_packages: Vec::new(),
            consent_extensions: Vec::new(),
        };
        let encoded = encode_consent_entry(&e).unwrap();
        let err = decode_consent_entry(&encoded)
            .expect_err("a room URI as requesterUri must fail semantic validation");
        assert!(
            matches!(err, WireError::ConsentValidation(_)),
            "expected the semantic-validation error variant, got: {err:?}"
        );
    }

    /// A non-empty `consent_extensions` (the AppDataDictionary bag) must survive
    /// encode->decode intact, never silently zeroed on either side. Covers an empty
    /// value (a name-only marker entry) and a multi-byte value in the same run.
    #[test]
    fn consent_entry_extensions_round_trip_non_empty() {
        let e = ConsentEntry {
            operation: ConsentOperation::Request,
            requester_uri: "mimi://a.example/u/alice".to_string(),
            target_uri: "mimi://b.example/u/bob".to_string(),
            room_uri: None,
            client_key_packages: Vec::new(),
            consent_extensions: vec![
                ("marker".to_string(), Vec::new()),
                ("note".to_string(), b"hello consent extensions".to_vec()),
            ],
        };
        let encoded = encode_consent_entry(&e).unwrap();
        let decoded = decode_consent_entry(&encoded).unwrap();
        assert_eq!(
            decoded.consent_extensions, e.consent_extensions,
            "consent_extensions must round-trip byte-identical, not silently empty"
        );
    }

    /// The `consent_extensions` outer window needs its own pre-check independent of the
    /// name/value pairs budgeted inside it, otherwise an over-budget declared
    /// length on the window itself would be cloned in full before that inner budget got a chance
    /// to run. Strips the real (empty, single-byte) trailing window off a legitimately-encoded
    /// entry and replaces it with an over-budget declared length and no body.
    #[test]
    fn consent_entry_decode_rejects_over_budget_consent_extensions_outer_window_before_allocation()
    {
        let e = ConsentEntry {
            operation: ConsentOperation::Request,
            requester_uri: "mimi://a.example/u/alice".to_string(),
            target_uri: "mimi://b.example/u/bob".to_string(),
            room_uri: None,
            client_key_packages: Vec::new(),
            consent_extensions: Vec::new(),
        };
        let mut bytes = encode_consent_entry(&e).unwrap();
        bytes.pop(); // the real (empty) consent_extensions window is one 0x00 length byte
        tls_codec::vlen::write_length(&mut bytes, MAX_RUN_AGGREGATE_BYTES + 1).unwrap();
        let err = decode_consent_entry(&bytes).expect_err(
            "an over-budget consent_extensions declared length must be rejected before allocation",
        );
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    /// The test above only proves the outer `consent_extensions` window is
    /// rejected when its own declared length exceeds the budget - it says nothing about an outer
    /// window that is within budget but contains one inner name/value pair whose own declared
    /// length overshoots what is left of that outer window. `decode_consent_extensions` already
    /// bounds each name/value pair individually, so this proves that per-element
    /// bounding actually closes the class here too, the same shape as the nested-overshoot proofs
    /// for `invalidProposals`/`added`/`participants` elsewhere in this crate.
    #[test]
    fn consent_entry_decode_rejects_consent_extensions_inner_name_that_overshoots_an_in_budget_outer_window(
    ) {
        let e = ConsentEntry {
            operation: ConsentOperation::Request,
            requester_uri: "mimi://a.example/u/alice".to_string(),
            target_uri: "mimi://b.example/u/bob".to_string(),
            room_uri: None,
            client_key_packages: Vec::new(),
            consent_extensions: Vec::new(),
        };
        let mut bytes = encode_consent_entry(&e).unwrap();
        bytes.pop(); // the real (empty) consent_extensions window is one 0x00 length byte

        let mut name_prefix = Vec::new();
        tls_codec::vlen::write_length(&mut name_prefix, 4096).unwrap();
        assert_eq!(name_prefix.len(), 2, "this proof needs a full 2-byte inner prefix, not a 1-byte one the outer window would truncate before it can be read");

        // Outer window: exactly 2 bytes, well within MAX_RUN_AGGREGATE_BYTES.
        tls_codec::vlen::write_length(&mut bytes, name_prefix.len()).unwrap();
        bytes.extend_from_slice(&name_prefix); // the full inner name prefix, zero payload bytes for it

        let err = decode_consent_entry(&bytes).expect_err(
            "an inner name prefix overshooting an in-budget outer window must be rejected, not panic",
        );
        assert!(matches!(err, WireError::Codec { .. }));
    }

    // ---- RunBudget - the shared element-count + aggregate-byte guard ----

    #[test]
    fn run_budget_rejects_element_count_overflow() {
        let mut budget = RunBudget::new();
        for _ in 0..MAX_RUN_ELEMENTS {
            budget.record("test", 1).expect("within the element budget");
        }
        let err = budget
            .record("test", 1)
            .expect_err("the element after the budget must be rejected");
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    #[test]
    fn run_budget_rejects_aggregate_byte_overflow() {
        // Two elements, each under the count cap, whose combined size exceeds the aggregate cap -
        // proves the byte budget fires independently of the element-count budget.
        let mut budget = RunBudget::new();
        budget
            .record("test", MAX_RUN_AGGREGATE_BYTES)
            .expect("exactly at the aggregate budget");
        let err = budget
            .record("test", 1)
            .expect_err("one more byte must exceed the aggregate budget");
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    /// The decisive proof that `bounded_run_input` rejects an over-budget
    /// declared length before any body allocation - a length prefix declaring more than the
    /// budget allows, with zero body bytes following it at all. `bounded_run_input` rejects on
    /// the declared value during the prefix read itself, before it ever tries to slice out a
    /// body.
    ///
    /// `VLBytes::tls_deserialize_bytes` on the same bytes also fails on this path, with
    /// `DecodingError`, not `EndOfStream` (verified directly against the vendored source,
    /// `quic_vec.rs`: the crate's own `remainder.get(..length).ok_or(Error::EndOfStream)` result
    /// is discarded on the short-read path and replaced with a `DecodingError`). That call is not
    /// exercised here: on a zero-body short read, `quic_vec.rs`'s short-read branch runs a
    /// `debug_assert_eq!` before constructing that `DecodingError`, which panics under
    /// `cargo test` (debug_assertions on, matching CI) though not under `--release`. Asserting the
    /// raw call's return value would couple this test's pass/fail to tls_codec's own debug-vs-
    /// release behavior on a path this test isn't about.
    #[test]
    fn bounded_run_input_rejects_before_any_body_bytes_exist() {
        let declared = MAX_RUN_AGGREGATE_BYTES + 1;
        let mut prefix_only = Vec::new();
        tls_codec::vlen::write_length(&mut prefix_only, declared).unwrap();
        // No body bytes appended - proves the reject comes from the prefix alone.
        let err = bounded_run_input(&prefix_only, "test", MAX_RUN_AGGREGATE_BYTES)
            .expect_err("a declared length past the budget must be rejected from the prefix alone");
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    /// `bounded_run_input` must fail closed, never panic, when a declared length
    /// is under the budget but larger than the bytes actually available - the truncation itself
    /// (`bytes.get(..total)`) has to be a checked bound, not a panicking index. This is the
    /// non-budget short-read case `bounded_run_input_rejects_before_any_body_bytes_exist` above
    /// does not cover.
    #[test]
    fn bounded_run_input_rejects_declared_length_larger_than_available_bytes() {
        let mut input = Vec::new();
        tls_codec::vlen::write_length(&mut input, 100).unwrap();
        input.extend_from_slice(&[0u8; 10]); // far fewer than the declared 100 bytes
        let err = bounded_run_input(&input, "test", MAX_RUN_AGGREGATE_BYTES)
            .expect_err("a declared length past the available bytes must be rejected, not panic");
        assert!(matches!(err, WireError::Codec { .. }));
    }

    /// `read_declared_length` rejects the QUIC varint's 8-byte/62-bit wire form
    /// (top two bits `11`) itself, before calling into `tls_codec` at all. `budget_limit` here is
    /// `usize::MAX` specifically to prove the rejection is this crate's own upfront check, not the
    /// ordinary budget comparison (which `tls_codec::vlen::read_length` would need to run first,
    /// and - unpatched - panics under `cargo test` on this exact byte via a `debug_assert_eq!`
    /// immediately before its own correct `Err` return, `quic_vec.rs`'s `calculate_length`).
    #[test]
    fn bounded_run_input_rejects_the_8_byte_varint_form_before_calling_tls_codec() {
        let mut input = vec![0xC0u8]; // top bits 11 -> declares the 8-byte/62-bit form
        input.extend_from_slice(&[0u8; 7]); // the rest of that form's length field, value irrelevant
        let err = bounded_run_input(&input, "test", usize::MAX)
            .expect_err("the 8-byte varint form must be rejected outright");
        assert!(matches!(err, WireError::Codec { .. }));
    }

    /// The same rejection, exercised through a real public decode function rather
    /// than `bounded_run_input` in isolation - `decode_consent_entry`'s `requesterUri` is the
    /// first length-prefixed field any peer-supplied `ConsentEntry` reaches. Before this
    /// fix, this panicked under `cargo test` (silently passed under `--release`, the same
    /// release-masks-debug-panics gap closed for the short-read case).
    #[test]
    fn consent_entry_decode_rejects_the_8_byte_varint_form_on_requester_uri() {
        let mut bytes = vec![u8::from(ConsentOperation::Request)];
        bytes.push(0xC0);
        bytes.extend_from_slice(&[0u8; 20]);
        let err = decode_consent_entry(&bytes)
            .expect_err("the 8-byte varint form on requesterUri must be rejected, not panic");
        assert!(matches!(err, WireError::Codec { .. }));
    }

    /// The decisive proof of the truncation itself, not just the budget check -
    /// a declared length at the budget boundary is accepted, the returned bounded slice covers
    /// the prefix plus that many payload bytes (nothing more), and the returned remainder is
    /// only what follows the declared window, not the whole untruncated input.
    #[test]
    fn bounded_run_input_bounds_the_slice_to_exactly_the_declared_window() {
        let mut input = Vec::new();
        tls_codec::vlen::write_length(&mut input, MAX_RUN_AGGREGATE_BYTES).unwrap();
        let prefix_len = input.len();
        input.extend(std::iter::repeat_n(0u8, MAX_RUN_AGGREGATE_BYTES));
        input.extend_from_slice(b"trailing-not-in-window");
        let (bounded, remainder) = bounded_run_input(&input, "test", MAX_RUN_AGGREGATE_BYTES)
            .expect("a declared length exactly at budget must be accepted");
        assert_eq!(bounded.len(), prefix_len + MAX_RUN_AGGREGATE_BYTES);
        assert_eq!(remainder, b"trailing-not-in-window");
    }

    #[test]
    fn consent_extensions_decode_rejects_element_count_overflow() {
        // MAX_RUN_ELEMENTS + 1 name-only (zero-value) entries - cheap to construct (no crypto),
        // exercises the budget through the real decode path, not just the RunBudget unit itself.
        let entries: Vec<(String, Vec<u8>)> = (0..=MAX_RUN_ELEMENTS)
            .map(|i| (format!("k{i}"), Vec::new()))
            .collect();
        let window = encode_consent_extensions(&entries).unwrap();
        let err = decode_consent_extensions(&window)
            .expect_err("a run past the element-count budget must be rejected");
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    #[test]
    fn consent_extensions_decode_rejects_aggregate_byte_overflow() {
        // Two entries, EACH individually under the aggregate-byte budget, whose combined size
        // exceeds it - the "few huge elements" attack shape the element-count cap alone misses.
        let entries: Vec<(String, Vec<u8>)> = vec![
            ("a".to_string(), vec![0u8; MAX_RUN_AGGREGATE_BYTES - 2]),
            ("b".to_string(), vec![0u8; 10]),
        ];
        let window = encode_consent_extensions(&entries).unwrap();
        let err = decode_consent_extensions(&window)
            .expect_err("a run past the aggregate-byte budget must be rejected");
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    // ---- SubmitMessageResponse: hand-constructed byte-level KAT ----
    #[test]
    fn submit_response_kat_accepted() {
        let r = SubmitMessageResponse::Accepted {
            accepted_timestamp: 0x0102030405060708,
        };
        let encoded = r.encode();
        // mls10(01) accepted(00) u64 BE(0102030405060708) optional-Frank-absent(00)
        let want = unhex("0100010203040506070800");
        assert_eq!(tohex(&encoded), tohex(&want));
        assert_eq!(SubmitMessageResponse::decode(&encoded).unwrap(), r);
    }

    #[test]
    fn submit_response_kat_accepted_rejects_missing_frank_tag() {
        // Note: the draft's optional<T> presence tag is mandatory even when the
        // value is absent -- a decoder MUST NOT accept a response that omits it.
        let short = unhex("01000102030405060708"); // no trailing frank tag
        assert!(SubmitMessageResponse::decode(&short).is_err());
    }

    #[test]
    fn submit_response_kat_accepted_rejects_trailing_after_frank_tag() {
        let with_trailing = unhex("0100010203040506070800ff");
        assert!(SubmitMessageResponse::decode(&with_trailing).is_err());
    }

    #[test]
    fn submit_response_kat_not_allowed() {
        let r = SubmitMessageResponse::NotAllowed;
        let encoded = r.encode();
        assert_eq!(tohex(&encoded), "0101");
        assert_eq!(SubmitMessageResponse::decode(&encoded).unwrap(), r);
    }

    #[test]
    fn submit_response_kat_epoch_too_old() {
        let r = SubmitMessageResponse::EpochTooOld { current_epoch: 42 };
        let encoded = r.encode();
        let want = unhex("0102000000000000002a"); // mls10(01) epochTooOld(02) u64 BE 42
        assert_eq!(tohex(&encoded), tohex(&want));
        assert_eq!(SubmitMessageResponse::decode(&encoded).unwrap(), r);
    }

    #[test]
    fn submit_response_decode_rejects_unsupported_protocol() {
        let bytes = unhex("02000000000000000000");
        assert!(matches!(
            SubmitMessageResponse::decode(&bytes),
            Err(WireError::UnsupportedProtocol(2))
        ));
    }

    // ---- SubmitMessageRequest: round-trip against a real openmls application message. Builds a
    // single-member group and a real PrivateMessage via `create_message`, the same construction
    // gate.rs's own tests use for Welcome, applied here to prove the framing finds the MLS message's
    // self-described end boundary before the following IdentifierUri. ----
    use openmls::group::{MlsGroup, MlsGroupCreateConfig};
    use openmls::prelude::OpenMlsCrypto;
    use openmls::prelude::{Ciphersuite, CredentialWithKey, KeyPackage, Lifetime};
    use openmls::{
        ciphersuite::signature::SignaturePublicKey, credentials::BasicCredential,
        prelude::Extensions,
    };
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::signatures::{Signer, SignerError};
    use openmls_traits::OpenMlsProvider;

    struct TestSigner {
        key: Vec<u8>,
        scheme: openmls::prelude::SignatureScheme,
    }
    impl Signer for TestSigner {
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
            OpenMlsRustCrypto::default()
                .crypto()
                .sign(self.scheme, payload, &self.key)
                .map_err(|_| SignerError::SigningError)
        }
        fn signature_scheme(&self) -> openmls::prelude::SignatureScheme {
            self.scheme
        }
    }

    fn real_application_message() -> MlsMessageOut {
        let provider = OpenMlsRustCrypto::default();
        let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let scheme = openmls::prelude::SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(b"alice".to_vec()).into(),
            signature_key: pk,
        };
        let signer = TestSigner {
            key: priv_b,
            scheme,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
            "not_before": now.saturating_sub(3600),
            "not_after": now + 60 * 60 * 24 * 84,
        }))
        .unwrap();
        // group creator's own KeyPackage isn't needed to found a group (MlsGroup::new self-founds).
        let _ = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime)
            .build(suite, &provider, &signer, cwk.clone());
        let cfg = MlsGroupCreateConfig::builder().ciphersuite(suite).build();
        let mut group = MlsGroup::new(&provider, &signer, &cfg, cwk).unwrap();
        group
            .create_message(&provider, &signer, b"hello mimi wire test")
            .unwrap()
    }

    #[test]
    fn submit_message_request_round_trip_with_real_mls_message() {
        let msg = real_application_message();
        let req = SubmitMessageRequest::from_mls_message(&msg, "mimi://a.example/u/alice").unwrap();
        let encoded = req.encode().unwrap();
        let decoded = SubmitMessageRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol, PROTOCOL_MLS10);
        assert_eq!(
            decoded.sending_uri,
            IdentifierUri("mimi://a.example/u/alice".to_string())
        );
        assert_eq!(
            decoded.app_message,
            msg.tls_serialize_detached().unwrap(),
            "the MLS envelope must round-trip byte-identical"
        );
    }

    #[test]
    fn submit_message_request_decode_rejects_trailing_bytes_after_uri() {
        let msg = real_application_message();
        let req = SubmitMessageRequest::from_mls_message(&msg, "mimi://a.example/u/alice").unwrap();
        let mut encoded = req.encode().unwrap();
        encoded.push(0xEE);
        assert!(matches!(
            SubmitMessageRequest::decode(&encoded),
            Err(WireError::Trailing { .. })
        ));
    }

    #[test]
    fn submit_message_request_decode_rejects_garbage_mls_bytes() {
        let bytes = [&[PROTOCOL_MLS10][..], &[0xFF; 32]].concat();
        assert!(matches!(
            SubmitMessageRequest::decode(&bytes),
            Err(WireError::MlsMessage(_))
        ));
    }

    #[test]
    fn submit_message_request_decode_does_not_panic_on_malformed_app_message() {
        // submitMessage is the live, peer-facing endpoint (§5.4) -- the most exposed of this
        // file's MLSMessage parse sites. Reaches the catch_unwind-guarded
        // MlsMessageIn::tls_deserialize call over a wider set of malformed payloads than
        // `_rejects_garbage_mls_bytes` above. Proves fail-closed: every payload returns Err, the
        // test process doesn't crash even if one happens to trip tls_codec's internal panic.
        let garbage_bodies: [&[u8]; 4] = [
            b"",
            b"\x00",
            b"not an mls object at all",
            &[0x00, 0x01, 0x02, 0x03, 0x04],
        ];
        for body in garbage_bodies {
            let bytes = [&[PROTOCOL_MLS10][..], body].concat();
            assert!(
                SubmitMessageRequest::decode(&bytes).is_err(),
                "malformed app_message bytes must be rejected, not panic: {body:?}"
            );
        }
    }

    // ---- KeyMaterialRequest/Response ----

    #[test]
    fn key_material_request_round_trip() {
        let req = KeyMaterialRequest::minimal("mimi://a.example/u/alice", "mimi://b.example/u/bob")
            .unwrap();
        let encoded = req.encode().unwrap();
        let decoded = KeyMaterialRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol, PROTOCOL_MLS10);
        assert_eq!(
            decoded.requesting_user,
            IdentifierUri("mimi://a.example/u/alice".to_string())
        );
        assert_eq!(
            decoded.target_user,
            IdentifierUri("mimi://b.example/u/bob".to_string())
        );
        assert_eq!(decoded.room_id, IdentifierUri(String::new()));
        assert_eq!(
            decoded.acceptable_ciphersuites,
            vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]
        );
    }

    /// `RequiredCapabilitiesExtension::tls_deserialize_bytes` panics on a
    /// length-prefix byte selecting the QUIC varint's 8-byte form (probed directly against this
    /// crate's own vendored openmls/tls_codec) - the identical `debug_assert_eq!`-before-`Err` bug
    /// `read_declared_length` closes for this crate's own reads, reached here through an opaque
    /// openmls type this crate does not control the internals of. `catch_unwind` closes it the
    /// same way this file already closes it for `KeyPackageIn`/`MlsMessageIn`.
    #[test]
    fn key_material_request_decode_rejects_the_8_byte_varint_form_in_required_capabilities() {
        let mut bytes = vec![PROTOCOL_MLS10];
        for uri in ["mimi://a.example/u/alice", "mimi://b.example/u/bob", ""] {
            VLBytes::new(uri.as_bytes().to_vec())
                .tls_serialize(&mut bytes)
                .unwrap();
        }
        Vec::<Ciphersuite>::new().tls_serialize(&mut bytes).unwrap(); // empty acceptableCiphersuites
        bytes.push(0xC0); // requiredCapabilities: 8-byte varint form selector
        bytes.extend_from_slice(&[0u8; 7]);

        let err = KeyMaterialRequest::decode(&bytes).expect_err(
            "the 8-byte varint form in requiredCapabilities must be rejected, not panic",
        );
        assert!(matches!(err, WireError::Codec { .. }));
    }

    #[test]
    fn key_material_request_decode_rejects_trailing_bytes() {
        let req = KeyMaterialRequest::minimal("mimi://a.example/u/alice", "mimi://b.example/u/bob")
            .unwrap();
        let mut encoded = req.encode().unwrap();
        encoded.push(0xEE);
        assert!(matches!(
            KeyMaterialRequest::decode(&encoded),
            Err(WireError::Trailing { .. })
        ));
    }

    /// Same class as the `requiredCapabilities` test above, for
    /// `requesterCredential` (`Credential`) - a second opaque openmls type this crate wraps in
    /// `catch_unwind` for the same reason.
    #[test]
    fn key_material_request_decode_rejects_the_8_byte_varint_form_in_requester_credential() {
        let mut bytes = vec![PROTOCOL_MLS10];
        for uri in ["mimi://a.example/u/alice", "mimi://b.example/u/bob", ""] {
            VLBytes::new(uri.as_bytes().to_vec())
                .tls_serialize(&mut bytes)
                .unwrap();
        }
        Vec::<Ciphersuite>::new().tls_serialize(&mut bytes).unwrap();
        RequiredCapabilitiesExtension::default()
            .tls_serialize(&mut bytes)
            .unwrap();
        VLBytes::new(Vec::new())
            .tls_serialize(&mut bytes) // requesterSignatureKey: empty, valid
            .unwrap();
        // Credential { credential_type: u16; serialized_credential_content: VLBytes }: the u16
        // leads, so the varint form selector has to sit in serialized_credential_content's own
        // length prefix, not the first byte of the field.
        bytes.extend_from_slice(&0u16.to_be_bytes()); // credential_type, value irrelevant
        bytes.push(0xC0); // serialized_credential_content: 8-byte varint form selector
        bytes.extend_from_slice(&[0u8; 7]);

        let err = KeyMaterialRequest::decode(&bytes).expect_err(
            "the 8-byte varint form in requesterCredential must be rejected, not panic",
        );
        assert!(matches!(err, WireError::Codec { .. }));
    }

    /// Proves `requesterSignatureKey` (`SignaturePublicKey`) is closed by
    /// `bounded_run_input` the same way a scalar `VLBytes` field is - no `catch_unwind` needed
    /// here, unlike `requiredCapabilities`/`requesterCredential` above, because
    /// `SignaturePublicKey` wraps a single `VLBytes` and this crate bounds the input externally
    /// before ever calling its decode.
    #[test]
    fn key_material_request_decode_rejects_the_8_byte_varint_form_in_signature_key() {
        let mut bytes = vec![PROTOCOL_MLS10];
        for uri in ["mimi://a.example/u/alice", "mimi://b.example/u/bob", ""] {
            VLBytes::new(uri.as_bytes().to_vec())
                .tls_serialize(&mut bytes)
                .unwrap();
        }
        Vec::<Ciphersuite>::new().tls_serialize(&mut bytes).unwrap();
        RequiredCapabilitiesExtension::default()
            .tls_serialize(&mut bytes)
            .unwrap();
        bytes.push(0xC0); // requesterSignatureKey: 8-byte varint form selector
        bytes.extend_from_slice(&[0u8; 7]);

        let err = KeyMaterialRequest::decode(&bytes).expect_err(
            "the 8-byte varint form in requesterSignatureKey must be rejected, not panic",
        );
        assert!(matches!(err, WireError::Codec { .. }));
    }

    /// `KeyMaterialRequest::decode` is live from `mimi-hub`'s `/keyMaterial` HTTP
    /// handler - proves the pre-check is actually wired into the real decoder, not just tested in
    /// isolation on `bounded_run_input`. Hand-built prefix (protocol + 3 URIs, matching what
    /// `decode` expects) plus an over-budget acceptableCiphersuites declared length with NO body
    /// following - the reject must happen before `decode` would need that body at all.
    #[test]
    fn key_material_request_decode_rejects_over_budget_ciphersuites_declared_length() {
        let mut bytes = vec![PROTOCOL_MLS10];
        IdentifierUri("mimi://a.example/u/alice".to_string())
            .to_vlbytes()
            .tls_serialize(&mut bytes)
            .unwrap();
        IdentifierUri("mimi://b.example/u/bob".to_string())
            .to_vlbytes()
            .tls_serialize(&mut bytes)
            .unwrap();
        IdentifierUri(String::new())
            .to_vlbytes()
            .tls_serialize(&mut bytes)
            .unwrap();
        tls_codec::vlen::write_length(&mut bytes, MAX_RUN_AGGREGATE_BYTES + 1).unwrap();
        let err = KeyMaterialRequest::decode(&bytes)
            .expect_err("an over-budget declared ciphersuites length must be rejected");
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    #[test]
    fn key_material_response_exhausted_kat() {
        let r = KeyMaterialResponse::Exhausted {
            user_uri: IdentifierUri("mimi://b.example/u/bob".to_string()),
        };
        let encoded = r.encode().unwrap();
        // protocol(01) userStatus=partialSuccess(01) userUri(<V> len=22 + 22B)
        // clients<V>: outer len = 1(clientStatus)+1(clientUri len)+22(clientUri bytes) = 24
        let mut want = vec![0x01u8, 0x01];
        want.push(22);
        want.extend_from_slice(b"mimi://b.example/u/bob");
        want.push(24); // clients<V> byte length
        want.push(0x01); // clientStatus = keyMaterialExhausted
        want.push(22);
        want.extend_from_slice(b"mimi://b.example/u/bob");
        assert_eq!(tohex(&encoded), tohex(&want), "hand-computed KAT mismatch");
        assert_eq!(KeyMaterialResponse::decode(&encoded).unwrap(), r);
    }

    #[test]
    fn key_material_response_success_round_trip_with_real_keypackage() {
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::prelude::{Extensions, KeyPackage, Lifetime, OpenMlsCrypto, SignatureScheme};
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;

        struct S {
            key: Vec<u8>,
            scheme: SignatureScheme,
        }
        impl Signer for S {
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
                OpenMlsRustCrypto::default()
                    .crypto()
                    .sign(self.scheme, payload, &self.key)
                    .map_err(|_| SignerError::SigningError)
            }
            fn signature_scheme(&self) -> SignatureScheme {
                self.scheme
            }
        }

        let provider = OpenMlsRustCrypto::default();
        let suite = openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let scheme = SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(b"bob".to_vec()).into(),
            signature_key: pk,
        };
        let signer = S {
            key: priv_b,
            scheme,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
            "not_before": now.saturating_sub(3600),
            "not_after": now + 60 * 60 * 24 * 84,
        }))
        .unwrap();
        let kpb = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime)
            .build(suite, &provider, &signer, cwk)
            .unwrap();
        let kp_bytes = kpb.key_package().tls_serialize_detached().unwrap();

        let r = KeyMaterialResponse::Success {
            user_uri: IdentifierUri("mimi://b.example/u/bob".to_string()),
            key_package: crate::gate::GatedKeyPackage::trusted(kp_bytes.clone()),
        };
        let encoded = r.encode().unwrap();
        let decoded = KeyMaterialResponse::decode(&encoded).unwrap();
        match decoded {
            KeyMaterialResponse::Success {
                user_uri,
                key_package,
            } => {
                assert_eq!(
                    user_uri,
                    IdentifierUri("mimi://b.example/u/bob".to_string())
                );
                assert_eq!(
                    key_package.as_slice(),
                    kp_bytes.as_slice(),
                    "the KeyPackage must round-trip byte-identical"
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// A wire-valid `KeyMaterialResponse::Success` carrying a foreign-suite (non-0x0001)
    /// KeyPackage must be rejected by `decode()` itself - the accept-gate runs on the receive
    /// path, not left to whichever caller eventually calls `add_member` on the returned bytes.
    /// INV-MLS-002-ALLOW: the foreign suite here is test-only, constructed to prove the gate
    /// fires, never a production path.
    #[test]
    fn key_material_response_decode_rejects_foreign_suite_keypackage() {
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::prelude::{Extensions, KeyPackage, Lifetime, OpenMlsCrypto, SignatureScheme};
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;

        struct S {
            key: Vec<u8>,
            scheme: SignatureScheme,
        }
        impl Signer for S {
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
                OpenMlsRustCrypto::default()
                    .crypto()
                    .sign(self.scheme, payload, &self.key)
                    .map_err(|_| SignerError::SigningError)
            }
            fn signature_scheme(&self) -> SignatureScheme {
                self.scheme
            }
        }

        let provider = OpenMlsRustCrypto::default();
        // INV-MLS-002-ALLOW (test-only): the foreign suite the gate must reject.
        let suite =
            openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let scheme = SignatureScheme::ED25519;
        let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
        let pk = SignaturePublicKey::try_from(pub_b).unwrap();
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(b"eve".to_vec()).into(),
            signature_key: pk,
        };
        let signer = S {
            key: priv_b,
            scheme,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
            "not_before": now.saturating_sub(3600),
            "not_after": now + 60 * 60 * 24 * 84,
        }))
        .unwrap();
        let kpb = KeyPackage::builder()
            .key_package_extensions(Extensions::empty())
            .key_package_lifetime(lifetime)
            .build(suite, &provider, &signer, cwk)
            .unwrap();
        let kp_bytes = kpb.key_package().tls_serialize_detached().unwrap();

        let r = KeyMaterialResponse::Success {
            user_uri: IdentifierUri("mimi://b.example/u/eve".to_string()),
            // `trusted`, not `from_gated_bytes`: this test deliberately builds a wire-level
            // Success carrying a foreign-suite KeyPackage to prove `decode()` rejects it -
            // `from_gated_bytes` would itself refuse to construct this fixture.
            key_package: crate::gate::GatedKeyPackage::trusted(kp_bytes),
        };
        let encoded = r.encode().unwrap();
        let err = KeyMaterialResponse::decode(&encoded)
            .expect_err("a 0x0003 KeyPackage must never decode as Success");
        assert!(
            matches!(err, WireError::CiphersuiteGate(_)),
            "expected the ciphersuite accept-gate to reject it, got: {err:?}"
        );
    }

    #[test]
    fn key_material_response_decode_rejects_garbage() {
        let bytes = unhex("01ff0000");
        assert!(KeyMaterialResponse::decode(&bytes).is_err());
    }

    #[test]
    fn key_material_response_decode_does_not_panic_on_malformed_keypackage() {
        // Reaches the catch_unwind-guarded KeyPackageIn::tls_deserialize_bytes call in the
        // Success branch (past the earlier enum/VLBytes framing `_rejects_garbage` above
        // exercises) by building well-formed wire framing around a malformed `keyPackage` field.
        // Proves fail-closed: every payload returns Err, the test process doesn't crash even if
        // one happens to trip tls_codec's internal panic.
        let garbage_payloads: [&[u8]; 4] = [
            b"",
            b"\x00",
            &[0xff; 64],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
        ];
        for bad in garbage_payloads {
            let r = KeyMaterialResponse::Success {
                user_uri: IdentifierUri("mimi://b.example/u/bob".to_string()),
                key_package: crate::gate::GatedKeyPackage::trusted(bad.to_vec()),
            };
            let encoded = r.encode().unwrap();
            assert!(
                KeyMaterialResponse::decode(&encoded).is_err(),
                "malformed keyPackage bytes must be rejected, not panic: {bad:?}"
            );
        }
    }

    /// `clients<V>` needs its own pre-check like every other peer-controlled run in this
    /// module - not the nested-overshoot class (it is a single `VLBytes`
    /// clone, not a `Vec<T>` blanket-impl run of elements, so its own declared length already
    /// bounds its own clone), but without a dedicated check on this site: an
    /// over-budget declared length here would be cloned in full before the "exactly one client"
    /// check downstream ever ran. Proves the fix the same way the original
    /// `bounded_run_input_rejects_before_any_body_bytes_exist` proof does - reject on the
    /// declared value alone, with no body bytes present to clone.
    #[test]
    fn key_material_response_decode_rejects_over_budget_clients_declared_length_before_allocation()
    {
        let mut bytes = vec![PROTOCOL_MLS10, KeyMaterialUserCode::Success.to_u8()];
        IdentifierUri("mimi://b.example/u/bob".to_string())
            .to_vlbytes()
            .tls_serialize(&mut bytes)
            .unwrap();
        // clients<V> declares a length over the shared budget, with NO body bytes following.
        tls_codec::vlen::write_length(&mut bytes, MAX_RUN_AGGREGATE_BYTES + 1).unwrap();
        let err = KeyMaterialResponse::decode(&bytes).expect_err(
            "an over-budget clients declared length must be rejected before allocation",
        );
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    // ---- HandshakeBundle / UpdateRoomResponse ----

    mod handshake_bundle_tests {
        use super::super::*;
        use openmls::ciphersuite::signature::SignaturePublicKey;
        use openmls::credentials::{BasicCredential, CredentialWithKey};
        use openmls::group::{MlsGroup, MlsGroupCreateConfig};
        use openmls::prelude::{
            Extensions, KeyPackage, KeyPackageIn, Lifetime, OpenMlsCrypto, ProtocolVersion,
            SignatureScheme,
        };
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;

        struct S {
            key: Vec<u8>,
            scheme: SignatureScheme,
        }
        impl Signer for S {
            fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
                OpenMlsRustCrypto::default()
                    .crypto()
                    .sign(self.scheme, payload, &self.key)
                    .map_err(|_| SignerError::SigningError)
            }
            fn signature_scheme(&self) -> SignatureScheme {
                self.scheme
            }
        }

        fn ident(user: &str, provider: &OpenMlsRustCrypto) -> (Vec<u8>, S, CredentialWithKey) {
            let scheme = SignatureScheme::ED25519;
            let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
            let pk = SignaturePublicKey::try_from(pub_b).unwrap();
            let cwk = CredentialWithKey {
                credential: BasicCredential::new(user.as_bytes().to_vec()).into(),
                signature_key: pk,
            };
            let signer = S {
                key: priv_b,
                scheme,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
                "not_before": now.saturating_sub(3600),
                "not_after": now + 60 * 60 * 24 * 84,
            }))
            .unwrap();
            let suite = openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
            let kpb = KeyPackage::builder()
                .key_package_extensions(Extensions::empty())
                .key_package_lifetime(lifetime)
                .build(suite, provider, &signer, cwk.clone())
                .unwrap();
            (
                kpb.key_package().tls_serialize_detached().unwrap(),
                signer,
                cwk,
            )
        }

        #[test]
        fn decode_does_not_panic_on_malformed_proposal_or_commit() {
            // Reaches the catch_unwind-guarded MlsMessageIn::tls_deserialize call that parses
            // `proposalOrCommit` -- the very first thing HandshakeBundle::decode does, unlike the
            // already-guarded welcome/moreProposals parses further down. Proves fail-closed: every
            // payload returns Err, the test process doesn't crash even if one happens to trip
            // tls_codec's internal panic.
            let garbage_payloads: [&[u8]; 5] = [
                b"",
                b"\x00",
                b"not an mls object at all",
                &[0xff; 64],
                &[0x00, 0x01, 0x02, 0x03, 0x04],
            ];
            for bad in garbage_payloads {
                assert!(
                    HandshakeBundle::decode(bad).is_err(),
                    "malformed proposalOrCommit bytes must be rejected, not panic: {bad:?}"
                );
            }
        }

        #[test]
        fn commit_round_trip_with_real_welcome_and_group_info() {
            let provider = OpenMlsRustCrypto::default();
            let suite = openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
            let (_akp, asigner, acwk) = ident("alice", &provider);
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(suite)
                .wire_format_policy(openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                // `Full`-representation groupInfoOption payloads are suite-gated at
                // decode (`mimi_gate_group_info`), which requires a payload that decodes as a
                // `VerifiableGroupInfo` - a placeholder byte sequence like `[0xAA, 0xBB]` is
                // indistinguishable from garbage to that gate. `use_ratchet_tree_extension`
                // is what makes `add_members` actually export one.
                .use_ratchet_tree_extension(true)
                .build();
            let mut group = MlsGroup::new(&provider, &asigner, &cfg, acwk).unwrap();
            let (bob_kp_bytes, _bsigner, _bcwk) = ident("bob", &provider);
            let mut s = bob_kp_bytes.as_slice();
            let bob_kp = KeyPackageIn::tls_deserialize(&mut s)
                .unwrap()
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
            let (commit, welcome, gi) = group.add_members(&provider, &asigner, &[bob_kp]).unwrap();
            let commit_bytes = commit.tls_serialize_detached().unwrap();
            let welcome_bytes = welcome.tls_serialize_detached().unwrap();
            let gi_bytes = gi
                .expect("use_ratchet_tree_extension(true) must produce a GroupInfo")
                .tls_serialize_detached()
                .unwrap();

            let bundle = HandshakeBundle::Commit {
                proposal_or_commit: commit_bytes.clone(),
                welcome: Some(crate::gate::GatedWelcome::trusted(welcome_bytes.clone())),
                group_info_option: GroupInfoOption {
                    representation: GroupInfoRepresentation::Full,
                    payload: gi_bytes.clone(),
                },
                ratchet_tree_option: vec![0xCC],
            };
            let encoded = bundle.encode().unwrap();
            let decoded = HandshakeBundle::decode(&encoded).unwrap();
            match decoded {
                HandshakeBundle::Commit {
                    proposal_or_commit,
                    welcome,
                    group_info_option,
                    ratchet_tree_option,
                } => {
                    assert_eq!(
                        proposal_or_commit, commit_bytes,
                        "commit envelope round-trip"
                    );
                    assert_eq!(
                        welcome.map(|w| w.into_bytes()),
                        Some(welcome_bytes),
                        "welcome round-trip"
                    );
                    assert_eq!(
                        group_info_option.representation,
                        GroupInfoRepresentation::Full
                    );
                    assert_eq!(group_info_option.payload, gi_bytes, "GroupInfo round-trip");
                    assert_eq!(ratchet_tree_option, vec![0xCC]);
                }
                HandshakeBundle::Proposal { .. } => panic!("expected Commit"),
            }
        }

        #[test]
        fn commit_decode_rejects_bad_welcome_tag() {
            let provider = OpenMlsRustCrypto::default();
            let suite = openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
            let (_akp, asigner, acwk) = ident("alice", &provider);
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(suite)
                .wire_format_policy(openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build();
            let mut group = MlsGroup::new(&provider, &asigner, &cfg, acwk).unwrap();
            let (bob_kp_bytes, _bsigner, _bcwk) = ident("bob", &provider);
            let mut s = bob_kp_bytes.as_slice();
            let bob_kp = KeyPackageIn::tls_deserialize(&mut s)
                .unwrap()
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
            let (commit, _welcome, _gi) =
                group.add_members(&provider, &asigner, &[bob_kp]).unwrap();
            let mut bytes = commit.tls_serialize_detached().unwrap();
            bytes.push(0xFF); // bad welcome-presence tag right after the commit envelope
            assert!(HandshakeBundle::decode(&bytes).is_err());
        }

        /// Same shape as `ident`, but lets the caller pick the ciphersuite - needed to build a
        /// self-consistent foreign-suite KeyPackage that can actually be added to a
        /// foreign-suite group (openmls requires the KeyPackage's suite to match the group's).
        fn ident_under(
            user: &str,
            provider: &OpenMlsRustCrypto,
            suite: openmls::prelude::Ciphersuite,
        ) -> (Vec<u8>, S, CredentialWithKey) {
            let scheme = SignatureScheme::ED25519;
            let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
            let pk = SignaturePublicKey::try_from(pub_b).unwrap();
            let cwk = CredentialWithKey {
                credential: BasicCredential::new(user.as_bytes().to_vec()).into(),
                signature_key: pk,
            };
            let signer = S {
                key: priv_b,
                scheme,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let lifetime: Lifetime = serde_json::from_value(serde_json::json!({
                "not_before": now.saturating_sub(3600),
                "not_after": now + 60 * 60 * 24 * 84,
            }))
            .unwrap();
            let kpb = KeyPackage::builder()
                .key_package_extensions(Extensions::empty())
                .key_package_lifetime(lifetime)
                .build(suite, provider, &signer, cwk.clone())
                .unwrap();
            (
                kpb.key_package().tls_serialize_detached().unwrap(),
                signer,
                cwk,
            )
        }

        /// `HandshakeBundle::decode`'s welcome field is the same MlsMessage-wrapped
        /// Welcome shape `mimi_gate_welcome` gates on the `/keyMaterial` path - proves the gate
        /// fires here too, not just there.
        #[test]
        fn commit_decode_rejects_foreign_suite_welcome() {
            let provider = OpenMlsRustCrypto::default();
            // INV-MLS-002-ALLOW (test-only): the foreign suite the gate must reject.
            let suite =
                openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
            let (_akp, asigner, acwk) = ident("alice", &provider);
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(suite)
                .wire_format_policy(openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build();
            let mut group = MlsGroup::new(&provider, &asigner, &cfg, acwk).unwrap();
            let (bob_kp_bytes, _bsigner, _bcwk) = ident_under("bob", &provider, suite);
            let mut s = bob_kp_bytes.as_slice();
            let bob_kp = KeyPackageIn::tls_deserialize(&mut s)
                .unwrap()
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
            let (commit, welcome, _gi) = group.add_members(&provider, &asigner, &[bob_kp]).unwrap();
            let commit_bytes = commit.tls_serialize_detached().unwrap();
            let welcome_bytes = welcome.tls_serialize_detached().unwrap();

            let bundle = HandshakeBundle::Commit {
                proposal_or_commit: commit_bytes,
                // `trusted`, not `from_gated_bytes`: this test deliberately builds a wire-level
                // Commit carrying a foreign-suite Welcome to prove `decode()` rejects it -
                // `from_gated_bytes` would itself refuse to construct this fixture.
                welcome: Some(crate::gate::GatedWelcome::trusted(welcome_bytes)),
                // Never reached: the welcome gate errors and `decode()` returns via `?` before
                // parsing these fields, so their contents don't matter for this test.
                group_info_option: GroupInfoOption {
                    representation: GroupInfoRepresentation::Partial,
                    payload: vec![],
                },
                ratchet_tree_option: vec![],
            };
            let encoded = bundle.encode().unwrap();
            let err = HandshakeBundle::decode(&encoded)
                .expect_err("a 0x0003 Welcome must never leave HandshakeBundle::decode as Ok");
            assert!(
                matches!(err, WireError::CiphersuiteGate(_)),
                "expected the ciphersuite accept-gate to reject it, got: {err:?}"
            );
        }

        /// `HandshakeBundle::decode`'s `Full`-representation `groupInfoOption`
        /// payload must be suite-gated too. Isolated from the welcome gate: the outer commit and
        /// welcome stay pinned-suite (0x0001) and only the groupInfoOption payload is swapped for
        /// one minted under a foreign suite from an unrelated group, so a failure here can only
        /// be attributed to the group_info gate specifically.
        #[test]
        fn commit_decode_rejects_foreign_suite_group_info() {
            let provider = OpenMlsRustCrypto::default();
            let suite = openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
            let (_akp, asigner, acwk) = ident("alice", &provider);
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(suite)
                .wire_format_policy(openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build();
            let mut group = MlsGroup::new(&provider, &asigner, &cfg, acwk).unwrap();
            let (bob_kp_bytes, _bsigner, _bcwk) = ident("bob", &provider);
            let mut s = bob_kp_bytes.as_slice();
            let bob_kp = KeyPackageIn::tls_deserialize(&mut s)
                .unwrap()
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
            let (commit, welcome, _gi) = group.add_members(&provider, &asigner, &[bob_kp]).unwrap();
            let commit_bytes = commit.tls_serialize_detached().unwrap();
            let welcome_bytes = welcome.tls_serialize_detached().unwrap();

            // A separate foreign-suite group, only to mint a decodable but wrong-suite
            // GroupInfo. INV-MLS-002-ALLOW (test-only): never a production path.
            let foreign_suite =
                openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
            let (_fakp, fasigner, facwk) = ident_under("mallory", &provider, foreign_suite);
            let foreign_cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(foreign_suite)
                .use_ratchet_tree_extension(true)
                .build();
            let mut foreign_group =
                MlsGroup::new(&provider, &fasigner, &foreign_cfg, facwk).unwrap();
            let (foreign_member_kp_bytes, _fmsigner, _fmcwk) =
                ident_under("trudy", &provider, foreign_suite);
            let mut fs = foreign_member_kp_bytes.as_slice();
            let foreign_member_kp = KeyPackageIn::tls_deserialize(&mut fs)
                .unwrap()
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
            let (_fcommit, _fwelcome, foreign_gi) = foreign_group
                .add_members(&provider, &fasigner, &[foreign_member_kp])
                .unwrap();
            let foreign_gi_bytes = foreign_gi
                .expect("use_ratchet_tree_extension(true) must produce a GroupInfo")
                .tls_serialize_detached()
                .unwrap();

            let bundle = HandshakeBundle::Commit {
                proposal_or_commit: commit_bytes,
                welcome: Some(crate::gate::GatedWelcome::trusted(welcome_bytes)),
                group_info_option: GroupInfoOption {
                    representation: GroupInfoRepresentation::Full,
                    payload: foreign_gi_bytes,
                },
                ratchet_tree_option: vec![],
            };
            let encoded = bundle.encode().unwrap();
            let err = HandshakeBundle::decode(&encoded)
                .expect_err("a 0x0003 GroupInfo must never leave HandshakeBundle::decode as Ok");
            assert!(
                matches!(err, WireError::CiphersuiteGate(_)),
                "expected the ciphersuite accept-gate to reject it, got: {err:?}"
            );
        }

        #[test]
        fn proposal_round_trip() {
            let provider = OpenMlsRustCrypto::default();
            let suite = openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
            let (_akp, asigner, acwk) = ident("alice", &provider);
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(suite)
                .wire_format_policy(openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build();
            let mut group = MlsGroup::new(&provider, &asigner, &cfg, acwk).unwrap();
            let (proposal_msg, _proposal_ref) = group
                .propose_self_update(
                    &provider,
                    &asigner,
                    openmls::treesync::LeafNodeParameters::default(),
                )
                .unwrap();
            let proposal_bytes = proposal_msg.tls_serialize_detached().unwrap();
            // Note: `moreProposals<V>` requires each element to be a real,
            // self-delimiting MLSMessage -- two more real self-update proposals, not placeholder
            // bytes (a placeholder silently passed the old per-element-length-prefixed decoder).
            let (more_1, _) = group
                .propose_self_update(
                    &provider,
                    &asigner,
                    openmls::treesync::LeafNodeParameters::default(),
                )
                .unwrap();
            let (more_2, _) = group
                .propose_self_update(
                    &provider,
                    &asigner,
                    openmls::treesync::LeafNodeParameters::default(),
                )
                .unwrap();
            let more_proposals_expected = vec![
                more_1.tls_serialize_detached().unwrap(),
                more_2.tls_serialize_detached().unwrap(),
            ];

            let bundle = HandshakeBundle::Proposal {
                proposal_or_commit: proposal_bytes.clone(),
                more_proposals: more_proposals_expected.clone(),
            };
            let encoded = bundle.encode().unwrap();
            let decoded = HandshakeBundle::decode(&encoded).unwrap();
            match decoded {
                HandshakeBundle::Proposal {
                    proposal_or_commit,
                    more_proposals,
                } => {
                    assert_eq!(proposal_or_commit, proposal_bytes);
                    assert_eq!(more_proposals, more_proposals_expected);
                }
                HandshakeBundle::Commit { .. } => panic!("expected Proposal"),
            }
        }

        #[test]
        fn decode_rejects_non_handshake_mls_message() {
            let provider = OpenMlsRustCrypto::default();
            let suite = openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
            let (_akp, asigner, acwk) = ident("alice", &provider);
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(suite)
                .wire_format_policy(openmls::prelude::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build();
            let mut group = MlsGroup::new(&provider, &asigner, &cfg, acwk).unwrap();
            let app_msg = group
                .create_message(&provider, &asigner, b"not a handshake message")
                .unwrap();
            let bytes = app_msg.tls_serialize_detached().unwrap();
            let err = HandshakeBundle::decode(&bytes).unwrap_err();
            assert!(matches!(err, WireError::MlsMessage(_)));
        }
    }

    #[test]
    fn update_room_response_kat_success() {
        let r = UpdateRoomResponse::Success {
            error_description: String::new(),
            accepted_timestamp: 0x0102030405060708,
        };
        let encoded = r.encode().unwrap();
        let want = unhex("00000102030405060708"); // code(00) desc<V>=empty(00) u64 BE
        assert_eq!(tohex(&encoded), tohex(&want));
        assert_eq!(UpdateRoomResponse::decode(&encoded).unwrap(), r);
    }

    #[test]
    fn update_room_response_round_trip_wrong_epoch_with_description() {
        let r = UpdateRoomResponse::WrongEpoch {
            error_description: "stale epoch".to_string(),
            current_epoch: 7,
        };
        let encoded = r.encode().unwrap();
        assert_eq!(UpdateRoomResponse::decode(&encoded).unwrap(), r);
    }

    #[test]
    fn update_room_response_round_trip_invalid_proposal() {
        let r = UpdateRoomResponse::InvalidProposal {
            error_description: "bad proposal ref".to_string(),
            invalid_proposals: vec![vec![0xDE, 0xAD], vec![0xBE, 0xEF, 0x00]],
        };
        let encoded = r.encode().unwrap();
        assert_eq!(UpdateRoomResponse::decode(&encoded).unwrap(), r);
    }

    #[test]
    fn update_room_response_decode_rejects_bad_code() {
        let bytes = unhex("ff00");
        assert!(UpdateRoomResponse::decode(&bytes).is_err());
    }

    /// A nested-overshoot shape: an outer run declaring length
    /// 1 (far too small for any real element), immediately followed by one real, well-formed
    /// `VLBytes` element whose own declared length is large. A pre-check that only peeks the
    /// outer "1" against the budget (trivially within it) and then hands the untruncated
    /// remainder to `Vec::<VLBytes>::tls_deserialize_bytes` is not sufficient - per `tls_codec`
    /// 0.4.2's blanket impl, that call decodes each element against whatever slice
    /// it is given, not against the outer window, so it would clone the big element anyway
    /// and return `Ok`. `bounded_run_input` truncates the input to the declared 1 byte first,
    /// so the inner element's own length prefix cannot even be fully read inside that window and
    /// the whole decode fails closed.
    #[test]
    fn update_room_response_invalid_proposal_rejects_nested_oversized_element_before_the_big_clone()
    {
        let mut real_element = Vec::new();
        VLBytes::new(vec![0xAAu8; 4096])
            .tls_serialize(&mut real_element)
            .unwrap();

        let mut bytes = vec![UpdateResponseCode::InvalidProposal.to_u8()];
        VLBytes::new(Vec::new())
            .tls_serialize(&mut bytes) // empty errorDescription
            .unwrap();
        tls_codec::vlen::write_length(&mut bytes, 1).unwrap(); // outer declares "1 byte" - a lie
        bytes.extend_from_slice(&real_element); // the real element is much bigger than that

        let err = UpdateRoomResponse::decode(&bytes).expect_err(
            "an outer declared length of 1 must not let a 4096-byte inner element through",
        );
        assert!(
            matches!(err, WireError::Codec { .. }),
            "expected the inner decode to fail closed inside the truncated window, got {err:?}"
        );
    }

    /// A distinct shape from the test above: an outer declared length
    /// of 1 truncates the inner element's own length prefix before it can even be read in full.
    /// This test uses an outer declared length that exactly fits a real, complete inner length
    /// prefix (2 bytes for a QUIC varint declaring 4096) but leaves zero payload bytes for that
    /// inner element - the inner prefix reads successfully, then tls_codec tries to clone 4096
    /// payload bytes it does not have. Before per-element bounded decode, this reached
    /// `tls_codec`'s short-read `debug_assert_eq!` and panicked under `cargo test` (compiled out,
    /// so silent, under `--release`).
    #[test]
    fn update_room_response_invalid_proposal_rejects_inner_prefix_that_reads_but_overshoots_its_own_payload(
    ) {
        let mut inner_prefix = Vec::new();
        tls_codec::vlen::write_length(&mut inner_prefix, 4096).unwrap();
        assert_eq!(inner_prefix.len(), 2, "this proof needs a full 2-byte inner prefix, not a 1-byte one the outer window would truncate before it can be read");

        let mut bytes = vec![UpdateResponseCode::InvalidProposal.to_u8()];
        VLBytes::new(Vec::new())
            .tls_serialize(&mut bytes) // empty errorDescription
            .unwrap();
        tls_codec::vlen::write_length(&mut bytes, inner_prefix.len()).unwrap(); // outer declares exactly 2 bytes
        bytes.extend_from_slice(&inner_prefix); // the full inner prefix, zero payload bytes for it

        let err = UpdateRoomResponse::decode(&bytes).expect_err(
            "an inner prefix declaring more payload than the outer window has left must be rejected, not panic",
        );
        assert!(matches!(err, WireError::Codec { .. }));
    }

    // ---- FanoutMessage ----

    #[test]
    fn fanout_message_kat_no_leading_protocol_byte() {
        // Note: the draft's literal §5.5 struct starts directly with `uint64
        // timestamp` -- hand-construct the expected bytes independently of `.encode()` to prove
        // there is no leading Protocol byte, not just that encode/decode agree with each other.
        let msg = real_application_message();
        let mls_bytes = msg.tls_serialize_detached().unwrap();
        let fm = FanoutMessage {
            protocol: PROTOCOL_MLS10,
            timestamp: 0x0102030405060708,
            message_and_tail: mls_bytes.clone(),
        };
        let encoded = fm.encode().unwrap();
        let mut want = 0x0102030405060708u64.to_be_bytes().to_vec();
        want.extend_from_slice(&mls_bytes);
        assert_eq!(tohex(&encoded), tohex(&want), "hand-computed KAT mismatch");
        let decoded = FanoutMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, fm);
    }

    #[test]
    fn fanout_message_decode_rejects_garbage_message() {
        let mut bytes = 99u64.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0xFF; 16]);
        assert!(matches!(
            FanoutMessage::decode(&bytes),
            Err(WireError::MlsMessage(_))
        ));
    }

    #[test]
    fn fanout_message_decode_does_not_panic_on_malformed_message() {
        // Reaches the catch_unwind-guarded MlsMessageIn::tls_deserialize call over a wider set of
        // malformed payloads than `_rejects_garbage_message` above. Proves fail-closed: every
        // payload returns Err, the test process doesn't crash even if one happens to trip
        // tls_codec's internal panic.
        let garbage_bodies: [&[u8]; 4] = [
            b"",
            b"\x00",
            b"not an mls object at all",
            &[0x00, 0x01, 0x02, 0x03, 0x04],
        ];
        for body in garbage_bodies {
            let mut bytes = 99u64.to_be_bytes().to_vec();
            bytes.extend_from_slice(body);
            assert!(
                FanoutMessage::decode(&bytes).is_err(),
                "malformed message bytes must be rejected, not panic: {body:?}"
            );
        }
    }

    #[test]
    fn fanout_message_decode_rejects_truncated_timestamp() {
        let bytes = vec![0x00, 0x01];
        assert!(FanoutMessage::decode(&bytes).is_err());
    }

    // ---- identifierQuery ----

    #[test]
    fn identifier_request_round_trip_handle_query() {
        let req = IdentifierRequest {
            query_elements: vec![QueryElement {
                search_type: SearchIdentifierType::Handle,
                qualifier: Vec::new(),
                search_value: b"alice".to_vec(),
            }],
        };
        let encoded = req.encode().unwrap();
        let decoded = IdentifierRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded.primary_search_value(), Some("alice".to_string()));
    }

    #[test]
    fn identifier_request_round_trip_oidc_claim_with_qualifier() {
        let req = IdentifierRequest {
            query_elements: vec![QueryElement {
                search_type: SearchIdentifierType::OidcStdClaim,
                qualifier: b"given_name".to_vec(),
                search_value: b"Alice".to_vec(),
            }],
        };
        let encoded = req.encode().unwrap();
        assert_eq!(IdentifierRequest::decode(&encoded).unwrap(), req);
    }

    #[test]
    fn identifier_request_round_trip_multiple_elements_and_semantics() {
        let req = IdentifierRequest {
            query_elements: vec![
                QueryElement {
                    search_type: SearchIdentifierType::Handle,
                    qualifier: Vec::new(),
                    search_value: b"alice".to_vec(),
                },
                QueryElement {
                    search_type: SearchIdentifierType::Email,
                    qualifier: Vec::new(),
                    search_value: b"alice@example.com".to_vec(),
                },
            ],
        };
        let encoded = req.encode().unwrap();
        let decoded = IdentifierRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.query_elements.len(), 2);
        assert_eq!(decoded, req);
        // This hub can't evaluate a multi-element query (no data model for Email etc.) - it must
        // not silently answer using only the first element, ignoring the rest.
        assert_eq!(
            decoded.primary_search_value(),
            None,
            "a 2-element request (even Handle-first) is unanswerable, not silently truncated to element 0"
        );
    }

    /// `IdentifierRequest`'s per-site budget (`MAX_QUERY_ELEMENTS=16`) is tighter
    /// than the shared run default (`MAX_RUN_ELEMENTS=1024`) - a run that would pass the generic
    /// default must still be rejected here, proving the tightened per-site limit is what's
    /// actually enforced, not just the shared one.
    #[test]
    fn identifier_request_decode_rejects_run_past_the_tightened_per_site_budget() {
        let req = IdentifierRequest {
            query_elements: (0..=MAX_QUERY_ELEMENTS)
                .map(|_| QueryElement {
                    search_type: SearchIdentifierType::Handle,
                    qualifier: Vec::new(),
                    search_value: b"x".to_vec(),
                })
                .collect(),
        };
        let encoded = req.encode().unwrap();
        let err = IdentifierRequest::decode(&encoded)
            .expect_err("a run past MAX_QUERY_ELEMENTS must be rejected");
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    /// `id_request_extensions` needs the same pre-check as every other peer-controlled run
    /// in this crate - no check at all before this clone would leave it unguarded. Mirrors
    /// the proof for `KeyMaterialResponse.clients`: an over-budget
    /// declared length with no body must be rejected before allocation.
    #[test]
    fn identifier_request_decode_rejects_over_budget_id_request_extensions_before_allocation() {
        let req = IdentifierRequest {
            query_elements: Vec::new(),
        };
        let mut bytes = req.encode().unwrap();
        bytes.pop(); // the real (empty) id_request_extensions window is one 0x00 length byte
        tls_codec::vlen::write_length(&mut bytes, MAX_RUN_AGGREGATE_BYTES + 1).unwrap();
        let err = IdentifierRequest::decode(&bytes).expect_err(
            "an over-budget id_request_extensions declared length must be rejected before allocation",
        );
        assert!(matches!(err, WireError::RunBudgetExceeded { .. }));
    }

    #[test]
    fn identifier_request_primary_search_value_rejects_zero_elements() {
        let req = IdentifierRequest {
            query_elements: vec![],
        };
        assert_eq!(req.primary_search_value(), None);
    }

    #[test]
    fn identifier_request_primary_search_value_rejects_non_handle_type() {
        let req = IdentifierRequest {
            query_elements: vec![QueryElement {
                search_type: SearchIdentifierType::Email,
                qualifier: Vec::new(),
                search_value: b"alice@example.com".to_vec(),
            }],
        };
        assert_eq!(
            req.primary_search_value(),
            None,
            "a single Email-typed element is unanswerable (v1 has no email lookup), not \
             quietly treated as a username"
        );
    }

    #[test]
    fn identifier_request_decode_rejects_bad_search_type() {
        let bytes = unhex("00000000");
        assert!(IdentifierRequest::decode(&bytes).is_err());
    }

    #[test]
    fn identifier_response_encode_kat() {
        let r = IdentifierResponse {
            response_code: IdentifierQueryCode::NotFound,
            uri: IdentifierUri(String::new()),
        };
        let encoded = r.encode().unwrap();
        // code(01) uri<V>=empty(00) foundProfiles<V>=empty(00) id_response_extensions<V>=empty(00)
        assert_eq!(tohex(&encoded), "01000000");
    }
}
