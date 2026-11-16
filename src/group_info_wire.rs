//! The groupInfo endpoint (protocol-07 §5.6): the request a client signs to fetch what it needs for an external join,
//! and the hub's answer, encrypted to the client and signed by the hub.
//!
//! The request is checked over its TBS bytes exactly as received: `GroupInfoRequestTBS` is the request without its
//! signature, `joiningCode` being optional in both, as mimid reads it. Signatures are RFC 9420 §5.1.2 `SignWithLabel`
//! (`SignContent { "MLS 1.0 " + label, content }`), and the answer's payload is RFC 9420 §5.1.3 `EncryptWithLabel` to the
//! request's `groupInfoPublicKey`, with the room ID's bytes as the context. Ciphersuite `0x0001` only (Ed25519 signatures,
//! HPKE over Curve25519), as mimid.

use openmls::prelude::{BasicCredential, Credential};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, HpkeCiphertext, SignatureScheme};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

use crate::protocol_wire::{WireError, PROTOCOL_MLS10};

/// The one ciphersuite the request and answer are signed and encrypted with.
pub const GROUP_INFO_SUITE: u16 = 0x0001;
const SIGN_REQUEST_LABEL: &str = "GroupInfoRequestTBS";
const SIGN_RESPONSE_LABEL: &str = "GroupInfoResponseTBS";
const ENCRYPT_LABEL: &str = "GroupInfo and ratchet_tree encryption";

fn wire(what: &'static str, detail: impl std::fmt::Display) -> WireError {
    WireError::Codec {
        what,
        detail: detail.to_string(),
    }
}

/// `SignContent`: the label with "MLS 1.0 " before it, and the content, each `opaque <V>`.
fn sign_content(label: &str, content: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    VLBytes::new(format!("MLS 1.0 {label}").into_bytes())
        .tls_serialize(&mut out)
        .map_err(|e| wire("SignContent", e))?;
    VLBytes::new(content.to_vec())
        .tls_serialize(&mut out)
        .map_err(|e| wire("SignContent", e))?;
    Ok(out)
}

/// `SignWithLabel` with an Ed25519 private key.
pub fn sign_with_label(
    private_key: &[u8],
    label: &str,
    content: &[u8],
) -> Result<Vec<u8>, WireError> {
    OpenMlsRustCrypto::default()
        .crypto()
        .sign(
            SignatureScheme::ED25519,
            &sign_content(label, content)?,
            private_key,
        )
        .map_err(|e| wire("SignWithLabel", format!("{e:?}")))
}

/// `VerifyWithLabel` with an Ed25519 public key.
pub fn verify_with_label(
    public_key: &[u8],
    label: &str,
    content: &[u8],
    signature: &[u8],
) -> Result<(), WireError> {
    OpenMlsRustCrypto::default()
        .crypto()
        .verify_signature(
            SignatureScheme::ED25519,
            &sign_content(label, content)?,
            public_key,
            signature,
        )
        .map_err(|_| wire("VerifyWithLabel", "the signature does not verify"))
}

/// Reads a TLS value, turning a decoder panic on hostile input into an error.
fn guarded<T>(
    what: &'static str,
    read: impl FnOnce() -> Result<T, tls_codec::Error>,
) -> Result<T, WireError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(read))
        .map_err(|_| wire(what, "the decoder panicked"))?
        .map_err(|e| wire(what, e))
}

/// `GroupInfoRequest`: the fields, the TBS bytes as received, and the signature.
#[derive(Debug, Clone)]
pub struct GroupInfoRequest {
    pub cipher_suite: u16,
    pub requesting_signature_key: Vec<u8>,
    pub requesting_credential: Credential,
    pub group_info_public_key: Vec<u8>,
    pub joining_code: Option<Vec<u8>>,
    tbs_bytes: Vec<u8>,
    signature: Vec<u8>,
}

impl GroupInfoRequest {
    /// Read a request; nothing may follow its signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let mut rest = bytes;
        let protocol = guarded("protocol", || u8::tls_deserialize(&mut rest))?;
        if protocol != PROTOCOL_MLS10 {
            return Err(WireError::UnsupportedProtocol(protocol));
        }
        let cipher_suite = guarded("cipher_suite", || u16::tls_deserialize(&mut rest))?;
        let requesting_signature_key = guarded("requestingSignatureKey", || {
            VLBytes::tls_deserialize(&mut rest)
        })?;
        let requesting_credential = guarded("requestingCredential", || {
            Credential::tls_deserialize(&mut rest)
        })?;
        let group_info_public_key =
            guarded("groupInfoPublicKey", || VLBytes::tls_deserialize(&mut rest))?;
        let joining_code = match guarded("joiningCode", || u8::tls_deserialize(&mut rest))? {
            0 => None,
            1 => Some(guarded("joiningCode", || {
                VLBytes::tls_deserialize(&mut rest)
            })?),
            other => return Err(wire("joiningCode", format!("presence octet {other}"))),
        };
        let tbs_bytes = bytes[..bytes.len() - rest.len()].to_vec();
        let signature = guarded("signature", || VLBytes::tls_deserialize(&mut rest))?;
        if !rest.is_empty() {
            return Err(WireError::Trailing {
                what: "GroupInfoRequest",
                n: rest.len(),
            });
        }
        Ok(Self {
            cipher_suite,
            requesting_signature_key: requesting_signature_key.as_slice().to_vec(),
            requesting_credential,
            group_info_public_key: group_info_public_key.as_slice().to_vec(),
            joining_code: joining_code.map(|code| code.as_slice().to_vec()),
            tbs_bytes,
            signature: signature.as_slice().to_vec(),
        })
    }

    /// The signature verifies with `requestingSignatureKey` over the TBS bytes as received. This shows only that the
    /// requester holds that key; tying the key to the credential and authorizing the request are the caller's.
    pub fn verify(&self) -> Result<(), WireError> {
        if self.cipher_suite != GROUP_INFO_SUITE {
            return Err(wire(
                "cipher_suite",
                format!("0x{:04x} is not 0x0001", self.cipher_suite),
            ));
        }
        verify_with_label(
            &self.requesting_signature_key,
            SIGN_REQUEST_LABEL,
            &self.tbs_bytes,
            &self.signature,
        )
    }

    /// The user URI a BasicCredential names, if the credential is one and its identity is UTF-8.
    pub fn requester_uri(&self) -> Option<String> {
        let basic = BasicCredential::try_from(self.requesting_credential.clone()).ok()?;
        String::from_utf8(basic.identity().to_vec()).ok()
    }

    /// Build and sign a request (a client's side, and tests).
    pub fn sign(
        signature_private_key: &[u8],
        signature_public_key: &[u8],
        credential: Credential,
        group_info_public_key: &[u8],
        joining_code: Option<&[u8]>,
    ) -> Result<Vec<u8>, WireError> {
        let mut tbs = vec![PROTOCOL_MLS10];
        tbs.extend_from_slice(&GROUP_INFO_SUITE.to_be_bytes());
        VLBytes::new(signature_public_key.to_vec())
            .tls_serialize(&mut tbs)
            .map_err(|e| wire("requestingSignatureKey", e))?;
        credential
            .tls_serialize(&mut tbs)
            .map_err(|e| wire("requestingCredential", e))?;
        VLBytes::new(group_info_public_key.to_vec())
            .tls_serialize(&mut tbs)
            .map_err(|e| wire("groupInfoPublicKey", e))?;
        match joining_code {
            Some(code) => {
                tbs.push(1);
                VLBytes::new(code.to_vec())
                    .tls_serialize(&mut tbs)
                    .map_err(|e| wire("joiningCode", e))?;
            }
            None => tbs.push(0),
        }
        let signature = sign_with_label(signature_private_key, SIGN_REQUEST_LABEL, &tbs)?;
        VLBytes::new(signature)
            .tls_serialize(&mut tbs)
            .map_err(|e| wire("signature", e))?;
        Ok(tbs)
    }
}

/// `GroupInfoCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupInfoCode {
    Success = 1,
    NotAuthorized = 2,
    NoSuchRoom = 3,
}

/// `PendingProposal`: a proposal the hub holds for the epoch (an MLSMessage), and when it accepted it (ms).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingProposal {
    pub proposal: Vec<u8>,
    pub hub_accepted_time: u64,
}

/// `EncryptWithLabel(groupInfoPublicKey, "GroupInfo and ratchet_tree encryption", room_id, GroupInfoRatchetTreeTBE)`:
/// the GroupInfo (bare, without an embedded tree), the `RatchetTreeOption` as given, and the pending proposals.
pub fn encrypt_group_info(
    group_info_public_key: &[u8],
    room_id: &[u8],
    group_info: &[u8],
    ratchet_tree_option: &[u8],
    pending: &[PendingProposal],
) -> Result<HpkeCiphertext, WireError> {
    let mut plaintext = group_info.to_vec();
    plaintext.extend_from_slice(ratchet_tree_option);
    let mut proposals = Vec::new();
    for p in pending {
        proposals.extend_from_slice(&p.proposal);
        proposals.extend_from_slice(&p.hub_accepted_time.to_be_bytes());
    }
    VLBytes::new(proposals)
        .tls_serialize(&mut plaintext)
        .map_err(|e| wire("pending_proposals", e))?;
    let mut info = Vec::new();
    VLBytes::new(format!("MLS 1.0 {ENCRYPT_LABEL}").into_bytes())
        .tls_serialize(&mut info)
        .map_err(|e| wire("EncryptContext", e))?;
    VLBytes::new(room_id.to_vec())
        .tls_serialize(&mut info)
        .map_err(|e| wire("EncryptContext", e))?;
    OpenMlsRustCrypto::default()
        .crypto()
        .hpke_seal(
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.hpke_config(),
            group_info_public_key,
            &info,
            &[],
            &plaintext,
        )
        .map_err(|e| wire("EncryptWithLabel", format!("{e:?}")))
}

/// The hub as the answer's signer: its Ed25519 key pair and its credential (`mimi://<hub domain>`), which together
/// are the `hub_sender` ExternalSender.
pub struct HubSigner {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub credential: Credential,
}

/// A `GroupInfoResponse`: `success` with the encrypted payload, signed by `hub`; any other code with nothing after it.
pub fn group_info_response(
    room_id: &[u8],
    status: GroupInfoCode,
    success: Option<(&HubSigner, &HpkeCiphertext)>,
) -> Result<Vec<u8>, WireError> {
    let mut out = vec![PROTOCOL_MLS10];
    VLBytes::new(room_id.to_vec())
        .tls_serialize(&mut out)
        .map_err(|e| wire("room_id", e))?;
    out.push(status as u8);
    let (Some((hub, encrypted)), GroupInfoCode::Success) = (success, status) else {
        return Ok(out);
    };
    out.extend_from_slice(&GROUP_INFO_SUITE.to_be_bytes());
    VLBytes::new(hub.public_key.clone())
        .tls_serialize(&mut out)
        .map_err(|e| wire("hub_sender", e))?;
    hub.credential
        .tls_serialize(&mut out)
        .map_err(|e| wire("hub_sender", e))?;
    encrypted
        .tls_serialize(&mut out)
        .map_err(|e| wire("encrypted_groupinfo_and_tree", e))?;
    let signature = sign_with_label(&hub.private_key, SIGN_RESPONSE_LABEL, &out)?;
    VLBytes::new(signature)
        .tls_serialize(&mut out)
        .map_err(|e| wire("signature", e))?;
    Ok(out)
}

/// Check a `success` answer's signature with the `hub_sender` key it carries, and return the encrypted payload (a
/// client's side, and tests). The caller still checks that `hub_sender` is the room's hub.
pub fn verify_group_info_response(bytes: &[u8]) -> Result<(Vec<u8>, HpkeCiphertext), WireError> {
    let mut rest = bytes;
    let _protocol = guarded("protocol", || u8::tls_deserialize(&mut rest))?;
    let _room = guarded("room_id", || VLBytes::tls_deserialize(&mut rest))?;
    let status = guarded("status", || u8::tls_deserialize(&mut rest))?;
    if status != GroupInfoCode::Success as u8 {
        return Err(wire("status", format!("{status} is not success")));
    }
    let _suite = guarded("cipher_suite", || u16::tls_deserialize(&mut rest))?;
    let key = guarded("hub_sender", || VLBytes::tls_deserialize(&mut rest))?;
    let _credential = guarded("hub_sender", || Credential::tls_deserialize(&mut rest))?;
    let encrypted = guarded("encrypted", || HpkeCiphertext::tls_deserialize(&mut rest))?;
    let tbs = &bytes[..bytes.len() - rest.len()];
    let signature = guarded("signature", || VLBytes::tls_deserialize(&mut rest))?;
    verify_with_label(
        key.as_slice(),
        SIGN_RESPONSE_LABEL,
        tbs,
        signature.as_slice(),
    )?;
    Ok((key.as_slice().to_vec(), encrypted))
}

#[cfg(test)]
#[path = "group_info_wire_tests.rs"]
mod tests;
