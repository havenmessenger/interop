//! The FanoutMessage a hub builds for each `select` arm: the message, then that arm's tail, decoding back to itself.

use super::*;
use crate::test_helpers::{
    public_proposal_and_commit_with_standard_update, public_remove_proposal,
};

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

/// A Commit's tail is an empty `externalProposals`, an application message's an absent `frank`: one zero byte each.
#[test]
fn a_commit_and_an_application_message_end_in_one_zero_byte() {
    let (_, commit) = public_proposal_and_commit_with_standard_update();
    let commit = unhex(&commit);
    let fanout = FanoutMessage::commit(1_700_000_000_123, &commit);
    let bytes = fanout.encode().unwrap();
    assert_eq!(&bytes[..8], &1_700_000_000_123u64.to_be_bytes());
    assert_eq!(&bytes[8..], [&commit[..], &[0]].concat().as_slice());
    assert_eq!(FanoutMessage::decode(&bytes).unwrap(), fanout);

    let application = FanoutMessage::application(7, b"opaque");
    assert_eq!(application.message_and_tail, b"opaque\0");
}

/// A proposal's tail is its bundle's `moreProposals`: one length prefix over the concatenated MLSMessages.
#[test]
fn a_proposal_carries_more_proposals_under_one_length() {
    let (proposal, _) = public_proposal_and_commit_with_standard_update();
    let proposal = unhex(&proposal);
    let more = unhex(&public_remove_proposal());
    let fanout = FanoutMessage::proposal(9, &proposal, std::slice::from_ref(&more)).unwrap();
    let tail = &fanout.message_and_tail[proposal.len()..];
    let mut expected = Vec::new();
    VLBytes::new(more.clone())
        .tls_serialize(&mut expected)
        .unwrap();
    assert_eq!(tail, expected.as_slice());
    let encoded = fanout.encode().unwrap();
    assert_eq!(FanoutMessage::decode(&encoded).unwrap(), fanout);

    let alone = FanoutMessage::proposal(9, &proposal, &[]).unwrap();
    assert_eq!(&alone.message_and_tail[proposal.len()..], &[0]);
}

/// A Welcome is wrapped as an `mls_welcome` MLSMessage and followed by the ratchet tree option as given.
#[test]
fn a_welcome_is_wrapped_and_followed_by_its_tree_option() {
    let fanout = FanoutMessage::welcome(3, b"WELCOME", b"\x01TREE");
    assert_eq!(fanout.message_and_tail, b"\x00\x01\x00\x03WELCOME\x01TREE");
}
