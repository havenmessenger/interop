//! The room's MLS operational policy: the `mls_operational_policy` component (room-policy-04 §7.1, `OperationalParameters`).
//!
//! Every field is read and kept. Where -04 leaves a type undefined it is read as MLS defines the name: `WireFormats` as
//! a `WireFormat` (`uint16`), `ContentType` as MLS's `ContentType` (`uint8`), `ComponentID` as mls-extensions-10 has
//! it (`uint16`), `MediaType` as its §6.2.2 struct, and `unit64` as `uint64`. `PendingProposalPolicy`'s `extension`
//! arm names no enum value, so only `unspecified`, `immediate_commit` and `random_delay` are read. A value is refused
//! when it does not end where its length says, a count or a length passes a bound, a flag is neither 0 nor 1, a
//! minimum is above its maximum, or a default lies outside them.

use serde::{Deserialize, Serialize};

use crate::room_policy::RoomPolicyError;
use crate::room_policy_wire::{put_run, refuse, Reader};

/// The most entries in one capability list.
const MAX_LIST: usize = 256;
/// The most media types in one list, and parameters on one media type.
const MAX_MEDIA_TYPES: usize = 64;
const MAX_PARAMETERS: usize = 16;
/// The longest media type or parameter text.
const MAX_TEXT: usize = 256;

/// A media type (mls-extensions §6.2.2): `type/subtype` and its parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaType {
    pub media_type: String,
    pub parameters: Vec<(String, String)>,
}

/// `ExtendedCapabilities`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedCapabilities {
    pub versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub proposals: Vec<u16>,
    pub credentials: Vec<u16>,
    pub wire_formats: Vec<u16>,
    pub component_ids: Vec<u16>,
    pub safe_aad_types: Vec<u16>,
    pub media_types: Vec<MediaType>,
    pub content_types: Vec<u8>,
}

/// `PendingProposalPolicy`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingProposalPolicy {
    #[default]
    Unspecified,
    ImmediateCommit,
    RandomDelay {
        minimum_delay_ms: u64,
        maximum_delay_ms: u64,
    },
}

/// `MinDefaultMaxTime`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinDefaultMaxTime {
    pub minimum: u64,
    pub default: u64,
    pub maximum: u64,
}

/// `AppMessagePolicy`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppMessagePolicy {
    pub epoch_tolerance: u8,
    pub pad_to_size: u16,
    pub max_generations_skipahead: u32,
}

/// `OperationalParameters`: the room's MLS operational policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalParameters {
    pub mandatory_capabilities: ExtendedCapabilities,
    pub default_capabilities: ExtendedCapabilities,
    pub forbidden_capabilities: ExtendedCapabilities,
    pub handshake_formats: Vec<u16>,
    pub external_proposal_allowed: bool,
    pub external_commit_allowed: bool,
    pub pending_proposal_policy: PendingProposalPolicy,
    pub leaf_node_update_time: MinDefaultMaxTime,
    pub app_message_policy: AppMessagePolicy,
    pub max_kp_lifetime: u64,
    pub max_credential_lifetime: u64,
    pub resumption_psk_lifetime: u64,
    pub sender_nonce_keypair_lifetime: MinDefaultMaxTime,
    pub max_keypairs: u32,
    pub buffer_incoming_message_time: MinDefaultMaxTime,
    pub max_buffered_messages: u32,
}

fn list<T>(
    r: &mut Reader<'_>,
    what: &'static str,
    width: usize,
    read: impl Fn(&mut Reader<'_>) -> Result<T, RoomPolicyError>,
) -> Result<Vec<T>, RoomPolicyError> {
    let mut run = r.run(what, MAX_LIST * width)?;
    let mut out = Vec::new();
    while !run.is_empty() {
        if out.len() == MAX_LIST {
            return Err(refuse(what, format!("more than {MAX_LIST} entries")));
        }
        out.push(read(&mut run)?);
    }
    Ok(out)
}

fn u16_list(r: &mut Reader<'_>, what: &'static str) -> Result<Vec<u16>, RoomPolicyError> {
    list(r, what, 2, |r| r.u16(what))
}

fn text(r: &mut Reader<'_>, what: &'static str) -> Result<String, RoomPolicyError> {
    let bytes = r.opaque(what, MAX_TEXT)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| refuse(what, "not valid UTF-8"))
}

fn media_type(r: &mut Reader<'_>) -> Result<MediaType, RoomPolicyError> {
    let media_type = text(r, "MediaType.type")?;
    let mut run = r.run("MediaType.parameters", MAX_PARAMETERS * (2 * MAX_TEXT + 8))?;
    let mut parameters = Vec::new();
    while !run.is_empty() {
        if parameters.len() == MAX_PARAMETERS {
            return Err(refuse("MediaType.parameters", "too many parameters"));
        }
        parameters.push((
            text(&mut run, "Parameter.parameter_name")?,
            text(&mut run, "Parameter.parameter_value")?,
        ));
    }
    Ok(MediaType {
        media_type,
        parameters,
    })
}

fn capabilities(
    r: &mut Reader<'_>,
    what: &'static str,
) -> Result<ExtendedCapabilities, RoomPolicyError> {
    let mut c = r.run(what, 64 * 1024)?;
    let capabilities = ExtendedCapabilities {
        versions: u16_list(&mut c, "ExtendedCapabilities.versions")?,
        cipher_suites: u16_list(&mut c, "ExtendedCapabilities.cipher_suites")?,
        extensions: u16_list(&mut c, "ExtendedCapabilities.extensions")?,
        proposals: u16_list(&mut c, "ExtendedCapabilities.proposals")?,
        credentials: u16_list(&mut c, "ExtendedCapabilities.credentials")?,
        wire_formats: u16_list(&mut c, "ExtendedCapabilities.wire_formats")?,
        component_ids: u16_list(&mut c, "ExtendedCapabilities.component_ids")?,
        safe_aad_types: u16_list(&mut c, "ExtendedCapabilities.safe_aad_types")?,
        media_types: {
            let mut run = c.run("ExtendedCapabilities.media_types", 64 * 1024)?;
            let mut out = Vec::new();
            while !run.is_empty() {
                if out.len() == MAX_MEDIA_TYPES {
                    return Err(refuse(
                        "ExtendedCapabilities.media_types",
                        "too many media types",
                    ));
                }
                out.push(media_type(&mut run)?);
            }
            out
        },
        content_types: list(&mut c, "ExtendedCapabilities.content_types", 1, |r| {
            r.u8("ExtendedCapabilities.content_types")
        })?,
    };
    c.done(what)?;
    Ok(capabilities)
}

fn min_default_max(
    r: &mut Reader<'_>,
    what: &'static str,
) -> Result<MinDefaultMaxTime, RoomPolicyError> {
    let time = MinDefaultMaxTime {
        minimum: r.u64(what)?,
        default: r.u64(what)?,
        maximum: r.u64(what)?,
    };
    if time.minimum > time.maximum || time.default < time.minimum || time.default > time.maximum {
        return Err(refuse(
            what,
            "the default is not between the minimum and the maximum",
        ));
    }
    Ok(time)
}

/// Read an `OperationalParameters` (the component's data, and its update, which has the same shape).
///
/// The struct is length-implicit in -04 (no outer `<V>`), as the other components' data are: it is the whole of the
/// component's `data`, and a value with octets left over is refused.
pub fn decode_operational_parameters(
    bytes: &[u8],
) -> Result<OperationalParameters, RoomPolicyError> {
    let mut r = Reader::new(bytes);
    let parameters = OperationalParameters {
        mandatory_capabilities: capabilities(&mut r, "mandatory_capabilities")?,
        default_capabilities: capabilities(&mut r, "default_capabilities")?,
        forbidden_capabilities: capabilities(&mut r, "forbidden_capabilities")?,
        handshake_formats: u16_list(&mut r, "handshake_formats")?,
        external_proposal_allowed: r.flag("external_proposal_allowed")?,
        external_commit_allowed: r.flag("external_commit_allowed")?,
        pending_proposal_policy: match r.u8("pending_proposal_strategy")? {
            0 => PendingProposalPolicy::Unspecified,
            1 => PendingProposalPolicy::ImmediateCommit,
            2 => {
                let minimum_delay_ms = r.u64("minimum_delay_ms")?;
                let maximum_delay_ms = r.u64("maximum_delay_ms")?;
                if minimum_delay_ms > maximum_delay_ms {
                    return Err(refuse("random_delay", "the minimum is above the maximum"));
                }
                PendingProposalPolicy::RandomDelay {
                    minimum_delay_ms,
                    maximum_delay_ms,
                }
            }
            other => {
                return Err(refuse(
                    "pending_proposal_strategy",
                    format!("{other} is not a strategy -04 defines"),
                ))
            }
        },
        leaf_node_update_time: min_default_max(&mut r, "LeafNode_update_time")?,
        app_message_policy: AppMessagePolicy {
            epoch_tolerance: r.u8("epoch_tolerance")?,
            pad_to_size: r.u16("pad_to_size")?,
            max_generations_skipahead: r.u32("max_generations_skipahead")?,
        },
        max_kp_lifetime: r.u64("max_kp_lifetime")?,
        max_credential_lifetime: r.u64("max_credential_lifetime")?,
        resumption_psk_lifetime: r.u64("resumption_psk_lifetime")?,
        sender_nonce_keypair_lifetime: min_default_max(&mut r, "sender_nonce_keypair_lifetime")?,
        max_keypairs: r.u32("max_keypairs")?,
        buffer_incoming_message_time: min_default_max(&mut r, "buffer_incoming_message_time")?,
        max_buffered_messages: r.u32("max_buffered_messages")?,
    };
    r.done("OperationalParameters")?;
    Ok(parameters)
}

fn put_u16_list(out: &mut Vec<u8>, values: &[u16]) {
    let content: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
    put_run(out, &content);
}

fn put_text(out: &mut Vec<u8>, text: &str) {
    put_run(out, text.as_bytes());
}

fn put_capabilities(out: &mut Vec<u8>, c: &ExtendedCapabilities) {
    let mut inner = Vec::new();
    for list in [
        &c.versions,
        &c.cipher_suites,
        &c.extensions,
        &c.proposals,
        &c.credentials,
        &c.wire_formats,
        &c.component_ids,
        &c.safe_aad_types,
    ] {
        put_u16_list(&mut inner, list);
    }
    let mut media = Vec::new();
    for m in &c.media_types {
        put_text(&mut media, &m.media_type);
        let mut parameters = Vec::new();
        for (name, value) in &m.parameters {
            put_text(&mut parameters, name);
            put_text(&mut parameters, value);
        }
        put_run(&mut media, &parameters);
    }
    put_run(&mut inner, &media);
    put_run(&mut inner, &c.content_types);
    put_run(out, &inner);
}

fn put_time(out: &mut Vec<u8>, t: &MinDefaultMaxTime) {
    for v in [t.minimum, t.default, t.maximum] {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Write an `OperationalParameters`.
pub fn encode_operational_parameters(p: &OperationalParameters) -> Vec<u8> {
    let mut out = Vec::new();
    put_capabilities(&mut out, &p.mandatory_capabilities);
    put_capabilities(&mut out, &p.default_capabilities);
    put_capabilities(&mut out, &p.forbidden_capabilities);
    put_u16_list(&mut out, &p.handshake_formats);
    out.push(u8::from(p.external_proposal_allowed));
    out.push(u8::from(p.external_commit_allowed));
    match &p.pending_proposal_policy {
        PendingProposalPolicy::Unspecified => out.push(0),
        PendingProposalPolicy::ImmediateCommit => out.push(1),
        PendingProposalPolicy::RandomDelay {
            minimum_delay_ms,
            maximum_delay_ms,
        } => {
            out.push(2);
            out.extend_from_slice(&minimum_delay_ms.to_be_bytes());
            out.extend_from_slice(&maximum_delay_ms.to_be_bytes());
        }
    }
    put_time(&mut out, &p.leaf_node_update_time);
    out.push(p.app_message_policy.epoch_tolerance);
    out.extend_from_slice(&p.app_message_policy.pad_to_size.to_be_bytes());
    out.extend_from_slice(&p.app_message_policy.max_generations_skipahead.to_be_bytes());
    for v in [
        p.max_kp_lifetime,
        p.max_credential_lifetime,
        p.resumption_psk_lifetime,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    put_time(&mut out, &p.sender_nonce_keypair_lifetime);
    out.extend_from_slice(&p.max_keypairs.to_be_bytes());
    put_time(&mut out, &p.buffer_incoming_message_time);
    out.extend_from_slice(&p.max_buffered_messages.to_be_bytes());
    out
}

#[cfg(test)]
#[path = "operational_parameters_tests.rs"]
mod tests;
