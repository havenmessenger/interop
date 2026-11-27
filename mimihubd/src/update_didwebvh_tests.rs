//! A room of did_webvh members through `update`, the route every Commit takes (`apply_update_request`): from a peer, as
//! the wire's `update` sends it, and from a lane user, as the client lane's does. The Commit decoder in front of it
//! hands back what it does not read, and the hub decides by whether it keeps the room's tree: a tracked room takes a
//! did_webvh client and the did_webvh_heads record, held to the draft's group rules; an untracked one takes neither.

use mimi_core::participant_list::{
    encode_participant_list_data, encode_participant_list_update, ParticipantListData,
    ParticipantListUpdate, UserRolePair,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation, HandshakeBundle};
use openmls::prelude::MlsGroup;

use crate::client_lane_rooms::{LaneRoomProfile, ROLE_ADMIN, ROLE_MEMBER};
use crate::didwebvh_fixtures::{
    app_components, commit, group_with, head_of, heads, record, Change, APP_COMPONENTS,
};
use crate::mls_fixtures::Member;
use crate::peer::PeerIdentity;
use crate::policy::UntrackedRooms;
use crate::requester::Requester;
use crate::room_tree::PARTICIPANT_LIST_COMPONENT;
use crate::{Provider, UpdateRefusal};

const DOMAIN: &str = "hub.example";
const ROOM: &str = "mimi://hub.example/r/peer-room";
const ALICE: &str = "mimi://member.example/u/alice";
const BOB: &str = "mimi://member.example/u/bob";
const CAROL: &str = "mimi://member.example/u/carol";
const NOW: u64 = 1_700_000_000;

fn list(pairs: &[(&str, u32)]) -> Vec<u8> {
    encode_participant_list_data(&ParticipantListData {
        participants: pairs
            .iter()
            .map(|(user, role)| UserRolePair {
                user_uri: (*user).to_string(),
                role_index: *role,
            })
            .collect(),
    })
    .unwrap()
}

/// The participant-list AppDataUpdate adding `user` in `role`, with the list's value after it.
fn listing(user: &str, role: u32, after: &[(&str, u32)]) -> (u16, Vec<u8>, Vec<u8>) {
    let update = ParticipantListUpdate {
        added_participants: vec![UserRolePair {
            user_uri: user.to_string(),
            role_index: role,
        }],
        ..ParticipantListUpdate::default()
    };
    (
        PARTICIPANT_LIST_COMPONENT,
        encode_participant_list_update(&update).unwrap(),
        list(after),
    )
}

/// An UpdateRequest of `commit` with its bundle's Full GroupInfo and full tree, as both routes carry it.
fn request(commit: Vec<u8>, group_info: Vec<u8>, tree: Vec<u8>) -> Vec<u8> {
    HandshakeBundle::Commit {
        proposal_or_commit: commit,
        welcome: None,
        group_info_option: GroupInfoOption {
            representation: GroupInfoRepresentation::Full,
            payload: group_info,
        },
        ratchet_tree_option: [&[1u8][..], &tree].concat(),
    }
    .encode()
    .unwrap()
}

/// The same Commit with no tree, as a room that does not seed sends it.
fn request_without_tree(commit: Vec<u8>) -> Vec<u8> {
    HandshakeBundle::Commit {
        proposal_or_commit: commit,
        welcome: None,
        group_info_option: GroupInfoOption {
            representation: GroupInfoRepresentation::Partial,
            payload: vec![0, 0, 0],
        },
        ratchet_tree_option: vec![4],
    }
    .encode()
    .unwrap()
}

fn peer() -> PeerIdentity {
    PeerIdentity::signed("member.example")
}

struct Room {
    p: Provider,
    alice: Member,
    bob: Member,
    group: MlsGroup,
}

/// Alice's group for the room, did_webvh, listing her, its record holding her head and naming it in `app_components`;
/// her first Commit adds Bob, his head and his listing, sent from her provider through `update`: the room seeds.
fn seeded() -> Room {
    let p = Provider::in_memory(DOMAIN).unwrap();
    let alice = Member::did_webvh(ALICE, "alice");
    let bob = Member::did_webvh(BOB, "bob");
    let mut group = group_with(
        &alice,
        ROOM.as_bytes(),
        &[
            (APP_COMPONENTS, app_components(&[heads()])),
            (heads(), record([head_of(&alice)])),
            (PARTICIPANT_LIST_COMPONENT, list(&[(ALICE, 1)])),
        ],
    );
    let (commit, group_info, tree) = commit(
        &mut group,
        &alice,
        Change {
            adds: vec![&bob],
            record: Some(record([head_of(&alice), head_of(&bob)])),
            updates: vec![listing(BOB, 1, &[(ALICE, 1), (BOB, 1)])],
            ..Change::default()
        },
    );
    let answer =
        p.apply_update_request(ROOM, &request(commit, group_info, tree), Some(&peer()), NOW);
    assert_eq!(
        answer,
        Ok(()),
        "PLANT-UPDATE-DIDWEBVH-SEED: a did_webvh room's first Commit through update was refused"
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_some(),
        "the room is tracked"
    );
    Room {
        p,
        alice,
        bob,
        group,
    }
}

/// Alice adds Carol through `update`, listing her, with `record` (when given) the record after it.
fn add_carol(room: &mut Room, record_after: Option<Vec<u8>>) -> Result<(), UpdateRefusal> {
    let carol = Member::did_webvh(CAROL, "carol");
    let (commit, group_info, tree) = commit(
        &mut room.group,
        &room.alice,
        Change {
            adds: vec![&carol],
            record: record_after,
            updates: vec![listing(CAROL, 1, &[(ALICE, 1), (BOB, 1), (CAROL, 1)])],
            ..Change::default()
        },
    );
    room.p
        .apply_update_request(ROOM, &request(commit, group_info, tree), Some(&peer()), NOW)
}

/// A did_webvh room seeds through `update`, and a did_webvh member joins it through `update` with its head added to the
/// record and its user added to the list: the decoder reads the Add whatever its credential, the hub reads its user from
/// its credential, and the room's rules take the record. Revert check: let the decoder refuse a non-Basic Add, and the
/// room never seeds.
#[test]
fn a_did_webvh_member_is_added_through_update() {
    let mut room = seeded();
    let carol = Member::did_webvh(CAROL, "carol");
    let raised = record([head_of(&room.alice), head_of(&room.bob), head_of(&carol)]);
    // A fresh Carol per Commit: the one whose head is recorded is the one added.
    let (commit, group_info, tree) = commit(
        &mut room.group,
        &room.alice,
        Change {
            adds: vec![&carol],
            record: Some(raised),
            updates: vec![listing(CAROL, 1, &[(ALICE, 1), (BOB, 1), (CAROL, 1)])],
            ..Change::default()
        },
    );
    let answer =
        room.p
            .apply_update_request(ROOM, &request(commit, group_info, tree), Some(&peer()), NOW);
    assert_eq!(answer, Ok(()), "PLANT-UPDATE-DIDWEBVH-ADD: {answer:?}");
    assert_eq!(room.p.list_participants(ROOM).unwrap().len(), 3);
}

/// The same Add through `update` without its record update is refused by the room's rules, and changes nothing.
#[test]
fn a_did_webvh_add_without_its_record_update_is_refused_through_update() {
    let mut room = seeded();
    let answer = add_carol(&mut room, None);
    assert!(
        matches!(answer, Err(UpdateRefusal::Invalid(why)) if why.contains("Record matches")),
        "{answer:?}"
    );
    assert_eq!(room.p.list_participants(ROOM).unwrap().len(), 2);
}

/// An AppDataUpdate for a component this hub has no rule for is refused through `update`, in a tracked room too, as it
/// was before the decoder handed such updates back. Revert check: take every unread component, and it is accepted.
#[test]
fn an_unknown_component_is_refused_through_update() {
    let mut room = seeded();
    let (commit, group_info, tree) = commit(
        &mut room.group,
        &room.alice,
        Change {
            updates: vec![(0xF0F0, b"anything".to_vec(), b"anything".to_vec())],
            ..Change::default()
        },
    );
    let answer =
        room.p
            .apply_update_request(ROOM, &request(commit, group_info, tree), Some(&peer()), NOW);
    assert_eq!(
        answer,
        Err(UpdateRefusal::Invalid(
            "the commit is not one this hub can read"
        )),
        "PLANT-UPDATE-UNKNOWN-COMPONENT"
    );
}

/// A room whose tree the hub does not keep takes no did_webvh client and no record: it has no tree to hold them to the
/// rules. The same Commit with a Basic client is taken. Revert check: let an untracked room take a non-Basic Add, and
/// the did_webvh one is accepted.
#[test]
fn an_untracked_room_takes_no_did_webvh_client_and_no_record() {
    let answer_for = |did_webvh: bool, with_record: bool| {
        let mut p = Provider::in_memory(DOMAIN).unwrap();
        p.policy.untracked_rooms = UntrackedRooms::Accept;
        let alice = if did_webvh {
            Member::did_webvh(ALICE, "alice")
        } else {
            Member::new(ALICE)
        };
        let bob = if did_webvh {
            Member::did_webvh(BOB, "bob")
        } else {
            Member::basic_listing_did_webvh(BOB)
        };
        let mut components = vec![(PARTICIPANT_LIST_COMPONENT, list(&[(ALICE, 1)]))];
        if did_webvh || with_record {
            components.push((APP_COMPONENTS, app_components(&[heads()])));
        }
        if did_webvh {
            components.push((heads(), record([head_of(&alice)])));
        }
        let mut group = group_with(&alice, ROOM.as_bytes(), &components);
        let record_after = if did_webvh {
            Some(record([head_of(&alice), head_of(&bob)]))
        } else if with_record {
            Some(record([]))
        } else {
            None
        };
        let (commit, _info, _tree) = commit(
            &mut group,
            &alice,
            Change {
                adds: vec![&bob],
                record: record_after,
                updates: vec![listing(BOB, 1, &[(ALICE, 1), (BOB, 1)])],
                ..Change::default()
            },
        );
        p.apply_update_request(ROOM, &request_without_tree(commit), Some(&peer()), NOW)
    };
    assert_eq!(
        answer_for(false, false),
        Ok(()),
        "a Basic client is taken untracked"
    );
    assert!(
        matches!(answer_for(true, false), Err(UpdateRefusal::Policy(why)) if why.contains("not Basic")),
        "PLANT-UPDATE-UNTRACKED-DIDWEBVH: {:?}",
        answer_for(true, false)
    );
    assert!(
        matches!(answer_for(false, true), Err(UpdateRefusal::Policy(why)) if why.contains("did_webvh_heads")),
        "PLANT-UPDATE-UNTRACKED-RECORD: {:?}",
        answer_for(false, true)
    );
}

/// From a lane user, as the client lane's `update` sends it: a lane room under the deployment's profile, Alice's
/// did_webvh group carrying the profile, the list, the record and `app_components`, and her first Commit adding Bob with
/// his head and listing seeds it.
#[test]
fn a_lane_users_did_webvh_room_seeds_and_takes_a_member_through_update() {
    const LANE_ALICE: &str = "mimi://hub.example/u/alice";
    const LANE_BOB: &str = "mimi://hub.example/u/bob";
    let p = Provider::in_memory(DOMAIN).unwrap();
    let profile = LaneRoomProfile::neutral();
    let room = p.lane_create_room(LANE_ALICE, &profile, NOW).unwrap();
    let alice = Member::did_webvh(LANE_ALICE, "alice");
    let bob = Member::did_webvh(LANE_BOB, "bob");
    let mut components = profile.components();
    components.push((
        PARTICIPANT_LIST_COMPONENT,
        list(&[(LANE_ALICE, ROLE_ADMIN)]),
    ));
    components.push((APP_COMPONENTS, app_components(&[heads()])));
    components.push((heads(), record([head_of(&alice)])));
    let mut group = group_with(&alice, room.as_bytes(), &components);
    let (commit, group_info, tree) = commit(
        &mut group,
        &alice,
        Change {
            adds: vec![&bob],
            record: Some(record([head_of(&alice), head_of(&bob)])),
            updates: vec![listing(
                LANE_BOB,
                ROLE_MEMBER,
                &[(LANE_ALICE, ROLE_ADMIN), (LANE_BOB, ROLE_MEMBER)],
            )],
            ..Change::default()
        },
    );
    let answer = p.apply_update_request(
        &room,
        &request(commit, group_info, tree),
        Requester::LaneUser(LANE_ALICE),
        NOW,
    );
    assert_eq!(answer, Ok(()), "PLANT-LANE-DIDWEBVH-UPDATE: {answer:?}");
    assert!(
        p.room_tracking(&room).unwrap().is_some(),
        "the room is tracked"
    );
    assert_eq!(p.list_participants(&room).unwrap().len(), 2);
}

/// In a deployment that accepts untracked rooms, a did_webvh Commit to one still seeds it with its seed verified first:
/// a first Commit whose record leaves out the member it adds is refused, and nothing changes, where an untracked Basic
/// Commit would be applied and its seed tried after. Revert check: seed a did_webvh Commit only when the policy asks,
/// and the Commit is applied with the room left untracked.
#[test]
fn a_did_webvh_seed_is_verified_even_where_untracked_rooms_are_accepted() {
    let mut p = Provider::in_memory(DOMAIN).unwrap();
    p.policy.untracked_rooms = UntrackedRooms::Accept;
    // The room lists Alice already, so the seed's list matches the room's and only the did_webvh rules can refuse it.
    p.add_participant(ROOM, ALICE, 1).unwrap();
    let alice = Member::did_webvh(ALICE, "alice");
    let bob = Member::did_webvh(BOB, "bob");
    let mut group = group_with(
        &alice,
        ROOM.as_bytes(),
        &[
            (APP_COMPONENTS, app_components(&[heads()])),
            (heads(), record([head_of(&alice)])),
            (PARTICIPANT_LIST_COMPONENT, list(&[(ALICE, 1)])),
        ],
    );
    let (commit, group_info, tree) = commit(
        &mut group,
        &alice,
        Change {
            adds: vec![&bob],
            // Bob's head is left out of the record.
            record: Some(record([head_of(&alice)])),
            updates: vec![listing(BOB, 1, &[(ALICE, 1), (BOB, 1)])],
            ..Change::default()
        },
    );
    let answer =
        p.apply_update_request(ROOM, &request(commit, group_info, tree), Some(&peer()), NOW);
    assert!(
        matches!(&answer, Err(UpdateRefusal::Policy(why)) if why.contains("did_webvh")),
        "PLANT-UPDATE-DIDWEBVH-FORCED-SEED: a did_webvh seed whose record misses a member was not refused for it: {answer:?}"
    );
    assert!(p.room_tracking(ROOM).unwrap().is_none());
    assert_eq!(
        p.list_participants(ROOM).unwrap().len(),
        1,
        "Bob is not listed"
    );
}

/// A room whose `required_capabilities` lists the did_webvh credential type requires every member to support it, not to
/// use it (draft §Negotiation: a room "can require this credential type for every member by listing it in the
/// `required_capabilities` GroupContext extension and rejecting other credential types"; RFC 9420 §7.2). The hub adds
/// no rule of its own: a Basic member whose leaf lists did_webvh is taken through `update`, and openmls refuses to make
/// the Commit that adds one whose leaf does not.
#[test]
fn a_room_listing_did_webvh_takes_a_basic_member_that_supports_it() {
    use openmls::prelude::CredentialType;
    let p = Provider::in_memory(DOMAIN).unwrap();
    let alice = Member::did_webvh(ALICE, "alice");
    let did_webvh = CredentialType::Other(crate::credential::DID_WEBVH.credential_type());
    let mut group = crate::didwebvh_fixtures::group_requiring(
        &alice,
        ROOM.as_bytes(),
        &[
            (APP_COMPONENTS, app_components(&[heads()])),
            (heads(), record([head_of(&alice)])),
            (PARTICIPANT_LIST_COMPONENT, list(&[(ALICE, 1)])),
        ],
        &[did_webvh],
    );
    let dave = Member::basic_listing_did_webvh(BOB);
    let (commit, group_info, tree) = commit(
        &mut group,
        &alice,
        Change {
            adds: vec![&dave],
            updates: vec![listing(BOB, 1, &[(ALICE, 1), (BOB, 1)])],
            ..Change::default()
        },
    );
    let answer =
        p.apply_update_request(ROOM, &request(commit, group_info, tree), Some(&peer()), NOW);
    assert_eq!(
        answer,
        Ok(()),
        "a Basic member that supports did_webvh is taken: {answer:?}"
    );
    let erin = Member::new(CAROL);
    let refused = group
        .commit_builder()
        .propose_adds([erin.key_package()])
        .load_psks(openmls_traits::OpenMlsProvider::storage(&alice.provider))
        .unwrap()
        .build(
            openmls_traits::OpenMlsProvider::rand(&alice.provider),
            openmls_traits::OpenMlsProvider::crypto(&alice.provider),
            &alice.signer,
            |_| true,
        );
    assert!(
        refused.is_err(),
        "openmls made a Commit adding a member that does not support a required credential type"
    );
}
