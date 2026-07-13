//! MIMI consent - pure protocol types + validation (protocol-06 §5.7, conformance C1/C2/C3).
//!
//! Consent is the cross-provider anti-spam/privacy gate: before a requester can reach a target
//! (claim their KeyPackage, add them to a room), the target's provider must hold a `grant`. This
//! module is the PURE, portable layer - the structs, the operation enum, and well-formedness
//! validation. The STATE (who consented to whom) and the enforcement live in the consuming service.
//!
//! Wire note: this module is the pure JSON-facing domain type (derives serde for the JSON compat
//! lane). The draft's exact ConsentEntry is a TLS presentation-language struct (§5.7, NOT CBOR) -
//! the binary wire codec lives in `protocol_wire::{encode,decode}_consent_entry` and is draft-exact,
//! including the routed `consent_extensions` field (see that module for the AppDataDictionary shape).
//!
//! Per MIMI content-08/protocol-06: a grant implies NO action by the receiver, and
//! `client_key_packages` is genuinely optional on a grant - send KPs to cut round-trips OR omit
//! them to save space; BE PREPARED FOR BOTH. KPs carried in a grant MAY EXPIRE before
//! the human acts, so the requester's use-site (claim/add) MUST tolerate a stale grant-KP and fall back to
//! `/keyMaterial`. Our model already matches: `client_key_packages: Vec<Vec<u8>>`, empty ⇒ fetch via
//! /keyMaterial. (This validates the consent "out-v1" stance - it's an application choice, not a gap.)

use crate::uri::MimiUri;
use serde::{Deserialize, Serialize};

/// protocol-06 §5.7 ConsentOperation (EXACT wire values). `grant`/`revoke` need not follow a `request`
/// (revoke is a valid PREEMPTIVE deny). Serializes as its integer on the JSON wire (no extra dep).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum ConsentOperation {
    Cancel = 0,
    Request = 1,
    Grant = 2,
    Revoke = 3,
}

impl From<ConsentOperation> for u8 {
    fn from(op: ConsentOperation) -> Self {
        op as Self
    }
}

impl TryFrom<u8> for ConsentOperation {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Cancel),
            1 => Ok(Self::Request),
            2 => Ok(Self::Grant),
            3 => Ok(Self::Revoke),
            other => Err(format!("invalid ConsentOperation {other} (valid: 0..=3)")),
        }
    }
}

/// protocol-06 §5.7 ConsentScope - the directional relationship a consent op applies to. `room_uri`
/// absent = global (applies to every room); present = scoped to that one room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentScope {
    pub requester_uri: String,
    pub target_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_uri: Option<String>,
}

/// protocol-06 §5.7 ConsentEntry - a single consent operation crossing providers. `client_key_packages`
/// is carried ONLY on `grant` (may be empty: the requester then fetches via /keyMaterial - this is the
/// privacy-preserving path). `consent_extensions` is the app-data dictionary (opaque here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentEntry {
    pub operation: ConsentOperation,
    pub requester_uri: String,
    pub target_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_uri: Option<String>,
    /// grant-only: the target's client KeyPackages (public key material). Empty ⇒ fetch via /keyMaterial.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_key_packages: Vec<Vec<u8>>,
    /// AppDataDictionary (§5.7) - `(component_id, data)` pairs, matching
    /// `draft-ietf-mls-extensions` §4.6's `ComponentData { uint16 component_id; opaque data<V>; }`.
    /// MUST be sorted by `component_id` with at most one entry per id (enforced by the wire codec
    /// in `protocol_wire`, not here - this type has no wire-invariant enforcement of its own).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_extensions: Vec<(u16, Vec<u8>)>,
}

impl ConsentEntry {
    /// The (requester, target, room) scope this entry acts on.
    pub fn scope(&self) -> ConsentScope {
        ConsentScope {
            requester_uri: self.requester_uri.clone(),
            target_uri: self.target_uri.clone(),
            room_uri: self.room_uri.clone(),
        }
    }
}

/// protocol-06 §5.2 KeyPackage-access gate result. The integer codes are the draft's enum: a provider
/// that refuses KeyPackage access for lack of consent returns `noConsent(5)` (global) or
/// `noConsentForThisRoom(6)` (the requester is consented generally but not for this room).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPackageAccess {
    Allowed,
    NoConsent,
    NoConsentForThisRoom,
}

impl KeyPackageAccess {
    /// The draft §5.2 numeric gate code (None when access is allowed - there is no "ok" code, the KP is
    /// simply returned).
    pub const fn gate_code(&self) -> Option<u8> {
        match self {
            Self::Allowed => None,
            Self::NoConsent => Some(5),
            Self::NoConsentForThisRoom => Some(6),
        }
    }
}

/// Typed validation errors for [`validate_consent_entry`] (`thiserror` per-module
/// enum - the library convention). A malformed URI surfaces transparently via [`crate::uri::UriError`].
#[derive(Debug, thiserror::Error)]
pub enum ConsentError {
    /// A requester/target/room URI did not parse as a MIMI URI.
    #[error(transparent)]
    Uri(#[from] crate::uri::UriError),
    /// The requester URI parsed but is not a `/u/` (user) URI.
    #[error("consent requesterUri must be a user URI: {0}")]
    RequesterNotUser(String),
    /// The target URI parsed but is not a `/u/` (user) URI.
    #[error("consent targetUri must be a user URI: {0}")]
    TargetNotUser(String),
    /// A room URI was present but is not a `/r/` (room) URI.
    #[error("consent roomUri must be a room URI: {0}")]
    RoomUriNotRoom(String),
    /// `client_key_packages` were attached to a non-`grant` operation (§5.2: only a grant may carry them).
    #[error("only a grant ConsentEntry may carry client_key_packages")]
    KeyPackagesOnNonGrant,
}

/// Validate a ConsentEntry's well-formedness (§5.7): the requester + target URIs MUST parse as MIMI
/// user URIs; a present room_uri MUST parse as a room URI; only `grant` may carry client_key_packages.
/// Fail-closed - a malformed consent op from a foreign provider is dropped before it touches state.
pub fn validate_consent_entry(e: &ConsentEntry) -> Result<(), ConsentError> {
    use crate::uri::MimiKind;
    let req = MimiUri::parse(&e.requester_uri)?;
    if req.kind != Some(MimiKind::User) {
        return Err(ConsentError::RequesterNotUser(e.requester_uri.clone()));
    }
    let tgt = MimiUri::parse(&e.target_uri)?;
    if tgt.kind != Some(MimiKind::User) {
        return Err(ConsentError::TargetNotUser(e.target_uri.clone()));
    }
    if let Some(r) = &e.room_uri {
        let ru = MimiUri::parse(r)?;
        if ru.kind != Some(MimiKind::Room) {
            return Err(ConsentError::RoomUriNotRoom(r.clone()));
        }
    }
    if !e.client_key_packages.is_empty() && e.operation != ConsentOperation::Grant {
        return Err(ConsentError::KeyPackagesOnNonGrant);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(op: ConsentOperation) -> ConsentEntry {
        ConsentEntry {
            operation: op,
            requester_uri: "mimi://mimi-b.havenmessenger.com/u/bob".into(),
            target_uri: "mimi://mimi.havenmessenger.com/u/alice".into(),
            room_uri: None,
            client_key_packages: vec![],
            consent_extensions: vec![],
        }
    }

    #[test]
    fn operation_wire_values_are_exact() {
        assert_eq!(u8::from(ConsentOperation::Cancel), 0);
        assert_eq!(u8::from(ConsentOperation::Request), 1);
        assert_eq!(u8::from(ConsentOperation::Grant), 2);
        assert_eq!(u8::from(ConsentOperation::Revoke), 3);
        assert_eq!(
            ConsentOperation::try_from(2u8).unwrap(),
            ConsentOperation::Grant
        );
        assert!(ConsentOperation::try_from(9u8).is_err());
    }

    #[test]
    fn operation_json_roundtrips_as_integer() {
        let j = serde_json::to_string(&ConsentOperation::Revoke).unwrap();
        assert_eq!(j, "3", "operation serializes as its integer wire value");
        let back: ConsentOperation = serde_json::from_str("2").unwrap();
        assert_eq!(back, ConsentOperation::Grant);
    }

    #[test]
    fn entry_json_roundtrips() {
        let mut e = entry(ConsentOperation::Grant);
        e.client_key_packages = vec![b"kp".to_vec()];
        e.room_uri = Some("mimi://mimi.havenmessenger.com/r/x".into());
        let j = serde_json::to_string(&e).unwrap();
        let back: ConsentEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn validate_rejects_malformed() {
        assert!(validate_consent_entry(&entry(ConsentOperation::Request)).is_ok());
        // non-user requester
        let mut bad = entry(ConsentOperation::Request);
        bad.requester_uri = "mimi://mimi-b.havenmessenger.com/r/room".into();
        assert!(
            validate_consent_entry(&bad).is_err(),
            "room URI as requester rejected"
        );
        // room_uri that isn't a room
        let mut bad2 = entry(ConsentOperation::Request);
        bad2.room_uri = Some("mimi://h/u/notaroom".into());
        assert!(validate_consent_entry(&bad2).is_err());
        // KPs on a non-grant
        let mut bad3 = entry(ConsentOperation::Request);
        bad3.client_key_packages = vec![b"kp".to_vec()];
        assert!(
            validate_consent_entry(&bad3).is_err(),
            "only grant may carry KeyPackages"
        );
    }

    #[test]
    fn grant_with_empty_key_packages_is_valid() {
        // Per MIMI protocol-06: client_key_packages is genuinely OPTIONAL on a grant -
        // "be prepared for both". A grant that OMITS KPs
        // (the requester then fetches via /keyMaterial) MUST validate, exactly like a grant
        // that carries them; grant-KPs may also expire, so the omit-path is the steady state.
        let mut g_omitted = entry(ConsentOperation::Grant);
        g_omitted.client_key_packages = vec![]; // omitted ⇒ fetch via /keyMaterial
        assert!(
            validate_consent_entry(&g_omitted).is_ok(),
            "a grant without client_key_packages is valid (be prepared for both)"
        );
        // And the carry-KPs form is equally valid (the round-trip-saving variant).
        let mut g_carried = entry(ConsentOperation::Grant);
        g_carried.client_key_packages = vec![b"kp".to_vec()];
        assert!(
            validate_consent_entry(&g_carried).is_ok(),
            "a grant carrying client_key_packages is also valid"
        );
    }

    #[test]
    fn gate_codes_match_draft() {
        assert_eq!(KeyPackageAccess::Allowed.gate_code(), None);
        assert_eq!(KeyPackageAccess::NoConsent.gate_code(), Some(5));
        assert_eq!(KeyPackageAccess::NoConsentForThisRoom.gate_code(), Some(6));
    }
}
