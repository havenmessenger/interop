//! A submitted message is a PrivateMessage carrying an application message (draft-ietf-mimi-protocol-07 §5.4), and in
//! a room whose tree the hub keeps it is for the room's group at the room's current epoch.

use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};

use super::Acceptance;
use crate::mls_fixtures::{add_commit, application_message, Chatter, Member};
use crate::peer::PeerIdentity;
use crate::Provider;

const ROOM: &str = "mimi://hub.example/r/room";
const GROUP: &[u8] = b"mimi://example.com/g/room";
const ALICE: &str = "mimi://example.com/u/alice";
const BOB: &str = "mimi://example.com/u/bob";
const CAROL: &str = "mimi://example.com/u/carol";

fn hub_with(participants: &[&str]) -> Provider {
    let p = Provider::in_memory("hub.example").unwrap();
    for participant in participants {
        p.add_participant(ROOM, participant, 1).unwrap();
    }
    p
}

/// Seed the hub's tree for the room from the bundle after the Commit made at `commit_epoch`, accepting the Commit first
/// as the hub does before it seeds.
fn seed(p: &Provider, commit_epoch: u64, group_info: &[u8], tree: &[u8]) {
    p.store.commit_accepted_at(ROOM, commit_epoch).unwrap();
    p.seed_room_tree(
        ROOM,
        commit_epoch,
        Some(&PeerIdentity::signed("example.com")),
        &GroupInfoOption {
            representation: GroupInfoRepresentation::Full,
            payload: group_info.to_vec(),
        },
        &[&[1u8][..], tree].concat(),
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_some(),
        "the room is tracked"
    );
}

/// In a room whose tree the hub does not keep, only real application messages are taken: bytes that are no MLS
/// message, and a Commit, are refused. Revert check: drop the framing check and the Commit is fanned out.
#[test]
fn an_untracked_room_takes_only_private_application_messages() {
    let p = hub_with(&[ALICE, BOB]);
    let alice = Member::new(ALICE);
    let bob = Member::new(BOB);
    let mut group = alice.create_group(GROUP);
    let (commit, _, _) = add_commit(&mut group, &alice, &[&bob]);
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, &commit, 10),
        Acceptance::Refused,
        "PLANT-SUBMIT-FRAMING: a Commit was taken as an application message"
    );
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, b"not an MLS message", 11),
        Acceptance::Refused
    );
    assert!(
        p.fetch_message(BOB).unwrap().is_none(),
        "nothing reached Bob"
    );
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, &Chatter::new().say(b"hi"), 12),
        Acceptance::Accepted
    );
}

/// In a room whose tree the hub keeps: the room's group at its epoch is taken; another group, or an epoch after the
/// room's, is refused; an epoch before it is answered with the room's epoch. Revert check: skip the epoch comparison
/// and the earlier epoch's message is accepted.
#[test]
fn a_tracked_room_takes_its_own_group_at_its_own_epoch() {
    let p = hub_with(&[ALICE, BOB, CAROL]);
    let alice = Member::new(ALICE);
    let mut group = alice.create_group(GROUP);
    add_commit(&mut group, &alice, &[&Member::new(BOB)]);
    let at_one = application_message(&mut group, &alice, b"at epoch 1");
    let (_, group_info, tree) = add_commit(&mut group, &alice, &[&Member::new(CAROL)]);
    seed(&p, 1, &group_info, &tree);
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, &at_one, 10),
        Acceptance::EpochTooOld { current_epoch: 2 },
        "PLANT-SUBMIT-EPOCH: a message for an earlier epoch was taken"
    );
    let at_two = application_message(&mut group, &alice, b"at epoch 2");
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, &at_two, 11),
        Acceptance::Accepted
    );
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, &Chatter::new().say(b"elsewhere"), 12),
        Acceptance::Refused,
        "another group's message"
    );
    add_commit(
        &mut group,
        &alice,
        &[&Member::new("mimi://example.com/u/dan")],
    );
    let at_three = application_message(&mut group, &alice, b"at epoch 3");
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, &at_three, 13),
        Acceptance::Refused,
        "an epoch after the room's"
    );
}
