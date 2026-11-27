//! A tracked room whose members carry did_webvh credentials: the hub reads each member's user from its credential and
//! leaf key, through the seed and a Commit, as it does for Basic credentials.

use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};

use super::*;
use crate::mls_fixtures::{add_commit, Member};
use crate::peer::PeerIdentity;

const ROOM: &str = "mimi://hub.example/r/room";
const GROUP: &[u8] = b"mimi://example.com/g/didwebvh";
const ALICE: &str = "mimi://example.com/u/alice";
const BOB: &str = "mimi://example.com/u/bob";
const CAROL: &str = "mimi://example.com/u/carol";

fn full(group_info: &[u8]) -> GroupInfoOption {
    GroupInfoOption {
        representation: GroupInfoRepresentation::Full,
        payload: group_info.to_vec(),
    }
}

struct Room {
    alice: Member,
    group: openmls::prelude::MlsGroup,
    group_info: Vec<u8>,
    tree: Vec<u8>,
}

/// Alice's group with Bob added in its first Commit, both with did_webvh credentials naming their URIs.
fn room() -> Room {
    let alice = Member::did_webvh(ALICE, "alice");
    let bob = Member::did_webvh(BOB, "bob");
    let mut group = alice.create_group(GROUP);
    let (_commit, group_info, tree) = add_commit(&mut group, &alice, &[&bob]);
    Room {
        alice,
        group,
        group_info,
        tree,
    }
}

fn seed(p: &Provider, room: &Room) {
    p.seed_room_tree(
        ROOM,
        0,
        Some(&PeerIdentity::signed("example.com")),
        &full(&room.group_info),
        &[&[1u8][..], &room.tree].concat(),
    );
}

/// A tree of did_webvh members seeds the room when the users their credentials name are the ones it lists. Revert
/// check: read no user from a did_webvh credential, and the room is not tracked.
#[test]
fn a_room_of_did_webvh_members_seeds_by_the_users_their_logs_name() {
    let p = Provider::in_memory("hub.example").unwrap();
    let room = room();
    p.add_participant(ROOM, ALICE, 1).unwrap();
    p.add_participant(ROOM, BOB, 1).unwrap();
    seed(&p, &room);
    assert!(
        p.room_tracking(ROOM).unwrap().is_some(),
        "PLANT-DIDWEBVH-ROOM: a tree of did_webvh members naming the listed users did not seed"
    );
}

/// A did_webvh member whose log names a user the room does not list keeps the room from seeding, as a Basic one would.
#[test]
fn a_did_webvh_member_of_an_unlisted_user_does_not_seed() {
    let p = Provider::in_memory("hub.example").unwrap();
    let room = room();
    p.add_participant(ROOM, ALICE, 1).unwrap();
    p.add_participant(ROOM, "mimi://example.com/u/robert", 1)
        .unwrap();
    seed(&p, &room);
    assert!(p.room_tracking(ROOM).unwrap().is_none());
}

/// A Commit adding a did_webvh member stages on the tracked room, and the hub reads the added client's user from its
/// KeyPackage's credential and key.
#[test]
fn a_commit_adding_a_did_webvh_member_names_its_user() {
    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = room();
    p.add_participant(ROOM, ALICE, 1).unwrap();
    p.add_participant(ROOM, BOB, 1).unwrap();
    seed(&p, &room);
    let carol = Member::did_webvh(CAROL, "carol");
    let (commit, group_info, _tree) = add_commit(&mut room.group, &room.alice, &[&carol]);
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let staged = p
        .stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&group_info)))
        .unwrap();
    let view = staged
        .list_and_leaves(
            vec![(ALICE.to_string(), 1), (BOB.to_string(), 1)],
            vec![ALICE.to_string(), BOB.to_string(), CAROL.to_string()],
        )
        .unwrap();
    assert_eq!(view.added, vec![Some(CAROL.to_string())]);
}
