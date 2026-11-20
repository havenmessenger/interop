//! A room's seed checks the `room_metadata` its GroupContext carries as an update's is checked: it must decode within
//! bounds and name the room being seeded (protocol-07 §10.4).

use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
use mimi_core::room_metadata::{encode_room_metadata, RoomMetadata, ROOM_METADATA_COMPONENT_ID};
use openmls::prelude::tls_codec::Serialize as _;

use crate::mls_fixtures::{add_and_join, group_info_after, Member};
use crate::peer::PeerIdentity;
use crate::Provider;

const ROOM: &str = "mimi://hub.example/r/room";
const GROUP: &[u8] = b"mimi://example.com/g/room";

fn metadata_naming(room: &str) -> Vec<u8> {
    encode_room_metadata(&RoomMetadata {
        room_uri: room.to_string(),
        room_name: "Table".to_string(),
        descriptions: Vec::new(),
        avatar: String::new(),
        subject: String::new(),
        mood: String::new(),
    })
}

/// The hub given Alice's group, created with `room_metadata` in its GroupContext and Bob added, seeded from the bundle
/// after that Commit; whether the room is tracked.
fn seeds_with(room_metadata: Vec<u8>) -> bool {
    let p = Provider::in_memory("hub.example").unwrap();
    let alice = Member::new("mimi://example.com/u/alice");
    let bob = Member::new("mimi://example.com/u/bob");
    let mut group = alice.create_group_with(GROUP, &[(ROOM_METADATA_COMPONENT_ID, room_metadata)]);
    let _bob_group = add_and_join(&mut group, &alice, &bob);
    let tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();
    p.seed_room_tree(
        ROOM,
        0,
        Some(&PeerIdentity::signed("example.com")),
        &GroupInfoOption {
            representation: GroupInfoRepresentation::Full,
            payload: group_info_after(&group, &alice),
        },
        &[&[1u8][..], &tree].concat(),
    );
    p.room_tracking(ROOM).unwrap().is_some()
}

/// A GroupContext whose room metadata names this room seeds it (its URI compared canonically); one naming another room,
/// or one that does not decode, leaves the room untracked. Revert check: skip the comparison, and the room naming
/// another room seeds.
#[test]
fn a_seed_whose_room_metadata_names_another_room_is_refused() {
    assert!(
        seeds_with(metadata_naming(ROOM)),
        "the room's own name seeds"
    );
    assert!(
        seeds_with(metadata_naming("mimi://HUB.example/r/room")),
        "a host compared canonically"
    );
    assert!(
        !seeds_with(metadata_naming("mimi://hub.example/r/another")),
        "PLANT-SEED-METADATA-ROOM: a seed whose room metadata names another room was taken"
    );
    assert!(
        !seeds_with(b"not a RoomMetaData".to_vec()),
        "a room metadata that does not decode"
    );
}
