//! A room takes every message its members may send, however many: nothing collects under the room itself, so its
//! members' own queues are what bound delivery.

use super::Acceptance;
use crate::Provider;

const ROOM: &str = "mimi://hub.example/r/room";
const ALICE: &str = "mimi://hub.example/u/alice";
const DAVE: &str = "mimi://hub.example/u/dave";

fn room_of(members: &[&str]) -> Provider {
    let p = Provider::in_memory("hub.example").unwrap();
    for member in members {
        p.add_participant(ROOM, member, 1).unwrap();
    }
    p
}

/// More messages than a queue holds, within one delivery lifetime, are all accepted while the member reads them, and
/// nothing is left under the room. Revert check: queue each accepted message under the room again, and message 257 is
/// refused.
#[test]
fn a_room_takes_more_messages_than_a_queue_holds_while_its_members_read_them() {
    let p = room_of(&[ALICE, DAVE]);
    let count = u64::try_from(crate::store::MAX_QUEUE_MESSAGES).unwrap() + 44;
    for n in 0..count {
        let body = format!("m{n}");
        assert_eq!(
            p.accept_application_message(ROOM, ALICE, body.as_bytes(), 10 + n),
            Acceptance::Accepted,
            "PLANT-ROOM-QUEUE: message {n} of {count} was refused"
        );
        assert_eq!(p.fetch_message(DAVE).unwrap(), Some(body.into_bytes()));
    }
    assert!(
        p.fetch_message(ROOM).unwrap().is_none(),
        "nothing is queued under the room"
    );
}

/// An empty message, and one larger than a queued item, are refused and reach no one.
#[test]
fn an_empty_or_oversize_message_is_refused_and_reaches_no_one() {
    let p = room_of(&[ALICE, DAVE]);
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, b"", 10),
        Acceptance::Refused
    );
    let oversize = vec![7u8; crate::store::MAX_ITEM_BYTES + 1];
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, &oversize, 11),
        Acceptance::Refused
    );
    assert!(p.fetch_message(DAVE).unwrap().is_none());
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, &vec![7u8; crate::store::MAX_ITEM_BYTES], 12),
        Acceptance::Accepted
    );
}

/// A sender who is not a participant is refused before anything is queued.
#[test]
fn a_non_participant_is_refused_and_nothing_is_queued() {
    let p = room_of(&[DAVE]);
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, b"hello", 10),
        Acceptance::Refused
    );
    assert!(p.fetch_message(DAVE).unwrap().is_none());
}

/// A fan-out that fails on a store error (here, the message table is gone) is the hub's own failure, never an
/// acceptance, so the sender is not told the message was taken. Revert check: answer accepted whatever the fan-out
/// did, and this message "is accepted".
#[test]
fn a_fan_out_store_error_is_a_failure_not_an_acceptance() {
    let p = room_of(&[ALICE, DAVE]);
    p.store.break_message_queue_for_test();
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, b"hello", 10),
        Acceptance::Failed,
        "PLANT-ROOM-FANOUT-ERROR: a message nothing queued was not reported as the hub's failure"
    );
}

/// Alice and Dave of a peer provider, members of a room here whose tree the hub keeps.
const PEER_ALICE: &str = "mimi://example.com/u/alice";
const PEER_DAVE: &str = "mimi://example.com/u/dave";

/// A hub tracking `ROOM` (Alice and Dave of `example.com`, seeded at epoch 1), and Alice's group with Alice.
fn tracked_room() -> (
    Provider,
    openmls::prelude::MlsGroup,
    crate::mls_fixtures::Member,
) {
    use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
    let p = room_of(&[PEER_ALICE, PEER_DAVE]);
    let alice = crate::mls_fixtures::Member::new(PEER_ALICE);
    let dave = crate::mls_fixtures::Member::new(PEER_DAVE);
    let mut group = alice.create_group(b"mimi://example.com/g/room");
    let (_commit, group_info, tree) = crate::mls_fixtures::add_commit(&mut group, &alice, &[&dave]);
    p.seed_room_tree(
        ROOM,
        0,
        Some(&crate::peer::PeerIdentity::signed("example.com")),
        &GroupInfoOption {
            representation: GroupInfoRepresentation::Full,
            payload: group_info,
        },
        &[&[1u8][..], &tree].concat(),
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_some(),
        "the room is tracked"
    );
    (p, group, alice)
}

fn application(
    group: &mut openmls::prelude::MlsGroup,
    by: &crate::mls_fixtures::Member,
    text: &[u8],
) -> Vec<u8> {
    use openmls::prelude::tls_codec::Serialize as _;
    group
        .create_message(&by.provider, &by.signer, text)
        .unwrap()
        .tls_serialize_detached()
        .unwrap()
}

/// In a tracked room, a message framed for the room's group at its epoch is delivered; one framed for another group,
/// or for an epoch the room has not reached, or that is no MLS message, reaches no one. Revert check: skip the framing
/// check, and the other group's message goes out to the members' provider.
#[test]
fn a_tracked_room_takes_only_messages_framed_for_its_group() {
    let (p, mut group, alice) = tracked_room();
    let fits = application(&mut group, &alice, b"hello");
    assert_eq!(
        p.accept_application_message(ROOM, PEER_ALICE, &fits, 10),
        Acceptance::Accepted
    );
    assert_eq!(
        fanned_out(&p),
        1,
        "the fitting message went out to the members' provider"
    );

    let mut other = alice.create_group(b"mimi://example.com/g/other");
    let elsewhere = application(&mut other, &alice, b"framed for another group");
    assert_eq!(
        p.accept_application_message(ROOM, PEER_ALICE, &elsewhere, 11),
        Acceptance::WrongGroup,
        "PLANT-FRAMING-GROUP: a message framed for another group was taken"
    );

    // Alice moves her group on without the hub: her next message is from an epoch the room has not reached.
    group
        .self_update(&alice.provider, &alice.signer, Default::default())
        .unwrap();
    group.merge_pending_commit(&alice.provider).unwrap();
    let ahead = application(&mut group, &alice, b"from a later epoch");
    assert_eq!(
        p.accept_application_message(ROOM, PEER_ALICE, &ahead, 12),
        Acceptance::WrongGroup,
        "PLANT-FRAMING-EPOCH: a message from a later epoch was taken"
    );
    assert_eq!(
        p.accept_application_message(ROOM, PEER_ALICE, b"not an MLS message", 13),
        Acceptance::WrongGroup
    );
    assert_eq!(fanned_out(&p), 1, "nothing more went out");
}

/// A room whose tree the hub does not keep has no group to compare with: its messages are taken as before.
#[test]
fn an_untracked_room_is_not_framing_checked() {
    let p = room_of(&[ALICE, DAVE]);
    assert_eq!(
        p.accept_application_message(ROOM, ALICE, b"opaque", 10),
        Acceptance::Accepted
    );
}

/// How many fan-outs wait in the outbox for other providers.
fn fanned_out(p: &Provider) -> usize {
    p.store
        .outbox_queues()
        .unwrap()
        .iter()
        .map(|queue| usize::try_from(queue.depth).unwrap())
        .sum()
}
