//! A room takes every message its members may send, however many: nothing collects under the room itself, so its
//! members' own queues are what bound delivery.

use super::Acceptance;
use crate::mls_fixtures::Chatter;
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
    let mut chatter = Chatter::new();
    let count = u64::try_from(crate::store::MAX_QUEUE_MESSAGES).unwrap() + 44;
    for n in 0..count {
        let body = chatter.say(format!("m{n}").as_bytes());
        assert_eq!(
            p.accept_application_message(ROOM, ALICE, &body, 10 + n),
            Acceptance::Accepted,
            "PLANT-ROOM-QUEUE: message {n} of {count} was refused"
        );
        assert_eq!(p.fetch_message(DAVE).unwrap(), Some(body));
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
        p.accept_application_message(
            ROOM,
            ALICE,
            &message_of_length(crate::store::MAX_ITEM_BYTES),
            12
        ),
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
        p.accept_application_message(ROOM, ALICE, &Chatter::new().say(b"hello"), 10),
        Acceptance::Failed,
        "PLANT-ROOM-FANOUT-ERROR: a message nothing queued was not reported as the hub's failure"
    );
}

/// A real application message whose serialized length is exactly `length`.
fn message_of_length(length: usize) -> Vec<u8> {
    let mut chatter = Chatter::new();
    let overhead = chatter.say(b"").len();
    for text in (length.saturating_sub(overhead + 16)..=length.saturating_sub(overhead)).rev() {
        let message = chatter.say(&vec![b'x'; text]);
        if message.len() == length {
            return message;
        }
    }
    panic!("no application message of exactly {length} bytes");
}
