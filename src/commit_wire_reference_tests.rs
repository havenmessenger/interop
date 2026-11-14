//! A standalone proposal is named by its `ProposalRef`, and a Commit that includes it by reference carries that name. The
//! name is checked against openmls's own: a real group proposes by reference and commits, and both sides must agree.

use super::*;
use crate::participant_list::MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE;
use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct TestSigner {
    key: Vec<u8>,
    scheme: SignatureScheme,
}

impl Signer for TestSigner {
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

/// A one-member group proposes a participant-list change by reference and commits it: the proposal message, the
/// reference openmls gave it, and the Commit.
fn proposed_by_reference_then_committed(payload: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let provider = OpenMlsRustCrypto::default();
    let scheme = SignatureScheme::ED25519;
    let (private_key, public_key) = provider.crypto().signature_key_gen(scheme).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"mimi://example.com/u/alice".to_vec()).into(),
        signature_key: SignaturePublicKey::from(public_key),
    };
    let signer = TestSigner {
        key: private_key,
        scheme,
    };
    let capabilities = Capabilities::new(
        None,
        Some(&[SUITE]),
        None,
        Some(&[ProposalType::Custom(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE)]),
        Some(&[CredentialType::Basic]),
    );
    let config = MlsGroupCreateConfig::builder()
        .capabilities(capabilities)
        .ciphersuite(SUITE)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let mut group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    let (proposal, reference) = group
        .propose_custom_proposal_by_reference(
            &provider,
            &signer,
            CustomProposal::new(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, payload.to_vec()),
        )
        .unwrap();
    let (commit, _welcome, _group_info) = group
        .commit_to_pending_proposals(&provider, &signer)
        .unwrap();
    (
        proposal.tls_serialize_detached().unwrap(),
        reference.as_slice().to_vec(),
        commit.tls_serialize_detached().unwrap(),
    )
}

/// The reference this crate computes for a proposal is the one openmls gives it, and the one the Commit includes it by.
/// Revert check: hash the message with its version, or with its membership tag, and the first assertion fails.
#[test]
fn a_proposal_is_named_as_openmls_names_it_and_a_commit_includes_it_by_that_name() {
    let payload = b"a participant-list update".to_vec();
    let (proposal, openmls_reference, commit) = proposed_by_reference_then_committed(&payload);
    let decoded = decode_proposal_message(&proposal).unwrap();
    assert_eq!(decoded.reference, openmls_reference);
    assert_eq!(decoded.reference.len(), PROPOSAL_REF_LEN);
    assert_eq!(
        decoded.proposal,
        ReadProposal::Change(DecodedCustomProposal {
            proposal_type: MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
            payload,
        })
    );
    let committed = decode_commit_proposals(&commit).unwrap();
    assert_eq!(committed.references, vec![openmls_reference]);
    assert_eq!(committed.epoch, decoded.epoch);
    assert!(committed.updates.is_empty());
    assert!(committed.removes.is_empty() && committed.adds.is_empty());
}

fn vl(bytes: &[u8]) -> Vec<u8> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

/// A member-sent PublicMessage proposal at `epoch` from leaf `sender`, with `proposal` as its body.
pub(crate) fn proposal_message(epoch: u64, sender: u32, proposal: &[u8]) -> Vec<u8> {
    [
        MLS_PROTOCOL_VERSION_MLS10.to_be_bytes().to_vec(),
        MLS_WIRE_FORMAT_PUBLIC_MESSAGE.to_be_bytes().to_vec(),
        vl(b"group"),
        epoch.to_be_bytes().to_vec(),
        vec![MLS_SENDER_TYPE_MEMBER],
        sender.to_be_bytes().to_vec(),
        vl(b""),
        vec![MLS_CONTENT_TYPE_PROPOSAL],
        proposal.to_vec(),
        vl(&[9; 64]),
        vl(&[8; 32]),
    ]
    .concat()
}

pub(crate) fn remove_body(leaf: u32) -> Vec<u8> {
    [
        MLS_PROPOSAL_TYPE_REMOVE.to_be_bytes().to_vec(),
        leaf.to_be_bytes().to_vec(),
    ]
    .concat()
}

pub(crate) fn participant_list_body(update: &[u8]) -> Vec<u8> {
    [
        APP_DATA_UPDATE_PROPOSAL_TYPE.to_be_bytes().to_vec(),
        PARTICIPANT_LIST_COMPONENT_ID.to_be_bytes().to_vec(),
        vec![APP_DATA_UPDATE_OP_UPDATE],
        vl(update),
    ]
    .concat()
}

/// A Remove is a leaf index and an AppDataUpdate to the participant list is the participant-list change, each with its
/// epoch and sender; the membership tag is not part of the name, so two messages that differ only there share it.
#[test]
fn a_remove_and_a_participant_list_update_are_read_with_their_epoch_sender_and_name() {
    let remove = decode_proposal_message(&proposal_message(7, 2, &remove_body(2))).unwrap();
    assert_eq!(
        (remove.epoch, remove.sender, &remove.proposal),
        (7, 2, &ReadProposal::Remove(2))
    );
    let change =
        decode_proposal_message(&proposal_message(7, 2, &participant_list_body(b"u"))).unwrap();
    assert_eq!(
        change.proposal,
        ReadProposal::Change(DecodedCustomProposal {
            proposal_type: MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
            payload: b"u".to_vec(),
        })
    );
    assert_ne!(remove.reference, change.reference);
    let mut other_tag = proposal_message(7, 2, &remove_body(2));
    let at = other_tag.len() - 1;
    other_tag[at] ^= 1;
    assert_eq!(
        decode_proposal_message(&other_tag).unwrap().reference,
        remove.reference
    );
}

/// Only a member's Remove or list or policy change is read as a proposal, and only the whole message. Revert check: drop the
/// trailing-bytes check and the last assertion fails.
#[test]
fn a_proposal_this_crate_has_no_rule_for_is_refused() {
    let update = [7u16.to_be_bytes().to_vec(), vec![0]].concat();
    assert!(decode_proposal_message(&proposal_message(1, 0, &update)).is_err());
    let other_component = [
        APP_DATA_UPDATE_PROPOSAL_TYPE.to_be_bytes().to_vec(),
        0x0099u16.to_be_bytes().to_vec(),
        vec![APP_DATA_UPDATE_OP_UPDATE],
        vl(b"x"),
    ]
    .concat();
    assert!(decode_proposal_message(&proposal_message(1, 0, &other_component)).is_err());
    let removes_the_component = [
        APP_DATA_UPDATE_PROPOSAL_TYPE.to_be_bytes().to_vec(),
        PARTICIPANT_LIST_COMPONENT_ID.to_be_bytes().to_vec(),
        vec![APP_DATA_UPDATE_OP_REMOVE],
    ]
    .concat();
    assert!(decode_proposal_message(&proposal_message(1, 0, &removes_the_component)).is_err());
    let mut commit_typed = proposal_message(1, 0, &remove_body(0));
    let content_type_at =
        commit_typed.len() - remove_body(0).len() - vl(&[9; 64]).len() - vl(&[8; 32]).len() - 1;
    commit_typed[content_type_at] = MLS_CONTENT_TYPE_COMMIT;
    assert!(decode_proposal_message(&commit_typed).is_err());
    let mut trailing = proposal_message(1, 0, &remove_body(0));
    trailing.push(0);
    assert!(decode_proposal_message(&trailing).is_err());
}

/// A reference in a Commit is a ProposalRef of the suite's hash length; any other length is refused.
#[test]
fn a_reference_of_another_length_is_refused() {
    use super::app_data_tests::commit_with;
    let good = [
        vec![MLS_PROPOSAL_OR_REF_REFERENCE],
        vl(&[7; PROPOSAL_REF_LEN]),
    ]
    .concat();
    let decoded = decode_commit_proposals(&commit_with(&[good])).unwrap();
    assert_eq!(decoded.references, vec![vec![7; PROPOSAL_REF_LEN]]);
    let short = [vec![MLS_PROPOSAL_OR_REF_REFERENCE], vl(&[7; 16])].concat();
    assert!(decode_commit_proposals(&commit_with(&[short])).is_err());
}
