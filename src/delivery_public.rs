//! Bounded public MLS observations for a content-blind delivery service.

use openmls::{
    ciphersuite::hash_ref::{make_proposal_ref, ProposalRef},
    prelude::{Ciphersuite, ContentType, KeyPackageIn, MlsMessageBodyIn, MlsMessageIn, ProposalIn},
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserialize, DeserializeBytes, Serialize as TlsSerialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Welcome,
    Application,
    Proposal,
    Commit,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProposalFacts {
    pub custom: Option<(u16, Vec<u8>)>,
    pub added_signature_key: Option<Vec<u8>>,
    pub removed_leaf_index: Option<u32>,
}

/// Observe the content type of a complete MLS envelope without retaining its group state.
pub fn message_kind(bytes: &[u8]) -> Result<Option<MessageKind>, String> {
    guarded(|| {
        let mut rest = bytes;
        let message = MlsMessageIn::tls_deserialize(&mut rest).map_err(|e| e.to_string())?;
        if !rest.is_empty() {
            return Err("MLS framing has trailing bytes".into());
        }
        if matches!(message.clone().extract(), MlsMessageBodyIn::Welcome(_)) {
            return Ok(Some(MessageKind::Welcome));
        }
        let protocol = match message.try_into_protocol_message() {
            Ok(protocol) => protocol,
            Err(_) => return Ok(None),
        };
        Ok(Some(match protocol.content_type() {
            ContentType::Application => MessageKind::Application,
            ContentType::Proposal => MessageKind::Proposal,
            ContentType::Commit => MessageKind::Commit,
        }))
    })
}

/// Require an entire public MLS message of one content type before inspecting its fields.
pub fn require_public_message(bytes: &[u8], kind: MessageKind) -> Result<(), String> {
    guarded(|| {
        let mut rest = bytes;
        let message = MlsMessageIn::tls_deserialize(&mut rest).map_err(|e| e.to_string())?;
        if !rest.is_empty() {
            return Err("public MLS message has trailing bytes".into());
        }
        let MlsMessageBodyIn::PublicMessage(public) = message.extract() else {
            return Err("not a public MLS message".into());
        };
        let expected = match kind {
            MessageKind::Application => ContentType::Application,
            MessageKind::Proposal => ContentType::Proposal,
            MessageKind::Commit => ContentType::Commit,
            MessageKind::Welcome => return Err("Welcome is not a public message".into()),
        };
        if public.content_type() != expected {
            return Err("public MLS content type differs from the expected kind".into());
        }
        Ok(())
    })
}

/// Decode one complete MLS proposal field from the start of a larger proposal vector.
pub fn proposal_prefix(bytes: &[u8]) -> Result<(ProposalFacts, usize), String> {
    guarded(|| {
        let (proposal, rest) =
            ProposalIn::tls_deserialize_bytes(bytes).map_err(|e| e.to_string())?;
        let consumed = bytes.len() - rest.len();
        let mut facts = ProposalFacts::default();
        match proposal {
            ProposalIn::Custom(custom) => {
                facts.custom = Some((custom.proposal_type(), custom.payload().to_vec()));
            }
            ProposalIn::Add(add) => {
                let encoded = ProposalIn::Add(add)
                    .tls_serialize_detached()
                    .map_err(|e| e.to_string())?;
                let key_package = KeyPackageIn::tls_deserialize_exact(
                    encoded.get(2..).ok_or("truncated Add proposal")?,
                )
                .map_err(|e| e.to_string())?;
                facts.added_signature_key = Some(
                    key_package
                        .unverified_credential()
                        .signature_key
                        .as_slice()
                        .to_vec(),
                );
            }
            ProposalIn::Remove(remove) => {
                facts.removed_leaf_index = Some(remove.removed().u32());
            }
            _ => {}
        }
        Ok((facts, consumed))
    })
}

pub fn proposal_exact(bytes: &[u8]) -> Result<ProposalFacts, String> {
    let (facts, consumed) = proposal_prefix(bytes)?;
    if consumed != bytes.len() {
        return Err("MLS proposal has trailing bytes".into());
    }
    Ok(facts)
}

pub fn proposal_ref_prefix(bytes: &[u8]) -> Result<(Vec<u8>, usize), String> {
    guarded(|| {
        let (reference, rest) =
            ProposalRef::tls_deserialize_bytes(bytes).map_err(|e| e.to_string())?;
        Ok((reference.as_slice().to_vec(), bytes.len() - rest.len()))
    })
}

/// Compute the RFC 9420 proposal reference for the exact authenticated content bytes.
pub fn proposal_reference(
    authenticated_content: &[u8],
    ciphersuite: u16,
) -> Result<Vec<u8>, String> {
    if ciphersuite != 0x0001 {
        return Err(format!("unsupported MLS ciphersuite {ciphersuite:#06x}"));
    }
    guarded(|| {
        make_proposal_ref(
            authenticated_content,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            OpenMlsRustCrypto::default().crypto(),
        )
        .map(|reference| reference.as_slice().to_vec())
        .map_err(|e| e.to_string())
    })
}

fn guarded<T>(body: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
        .map_err(|_| "MLS public parser panicked on malformed input".to_string())?
}

#[cfg(test)]
#[path = "delivery_public_tests.rs"]
mod tests;
