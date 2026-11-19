//! A seeding Commit may not change a room's policy, operational policy or participant list: each comparison on its own,
//! then end to end through the lane's `update`.

use mimi_core::commit_wire::DecodedCommit;
use mimi_core::participant_list::{
    encode_participant_list_data, encode_participant_list_update, ParticipantListData,
    ParticipantListUpdate, UserRolePair,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation, HandshakeBundle};
use openmls::prelude::tls_codec::Serialize as _;

use crate::client_lane_rooms::{LaneRoomProfile, ROLE_ADMIN, ROLE_MEMBER};
use crate::mls_fixtures::{app_data_commit, group_info_after, Member};
use crate::room_tree::PARTICIPANT_LIST_COMPONENT;
use crate::{Provider, UpdateRefusal};

const DOMAIN: &str = "hub.example";
const ALICE: &str = "mimi://hub.example/u/alice";
const BOB: &str = "mimi://hub.example/u/bob";
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

/// A lane room of Alice's under `profile`, and Alice's group for it with `components` in its GroupContext.
fn lane_room(
    profile: &LaneRoomProfile,
    components: &[(u16, Vec<u8>)],
) -> (Provider, String, Member, openmls::prelude::MlsGroup) {
    let p = Provider::in_memory(DOMAIN).unwrap();
    p.add_participant("mimi://hub.example/r/seed", ALICE, NOW)
        .unwrap();
    let room = p.lane_create_room(ALICE, profile, NOW).unwrap();
    let alice = Member::new(ALICE);
    let group = alice.create_group_with(room.as_bytes(), components);
    (p, room, alice, group)
}

fn full(group: &openmls::prelude::MlsGroup, by: &Member) -> (GroupInfoOption, Vec<u8>) {
    let tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();
    (
        GroupInfoOption {
            representation: GroupInfoRepresentation::Full,
            payload: group_info_after(group, by),
        },
        [&[1u8][..], &tree].concat(),
    )
}

fn no_changes() -> DecodedCommit {
    DecodedCommit {
        epoch: 0,
        updates: Vec::new(),
        adds: Vec::new(),
        removes: Vec::new(),
        references: Vec::new(),
        external: false,
    }
}

fn with_profile(profile: &LaneRoomProfile, alice_role: u32) -> Vec<(u16, Vec<u8>)> {
    let mut components = profile.components();
    components.push((PARTICIPANT_LIST_COMPONENT, list(&[(ALICE, alice_role)])));
    components
}

fn check(profile: &LaneRoomProfile, components: &[(u16, Vec<u8>)]) -> Result<(), UpdateRefusal> {
    let (p, room, alice, group) = lane_room(profile, components);
    let (info, tree) = full(&group, &alice);
    p.check_seed_keeps_room_state(&room, &no_changes(), &info, &tree)
}

/// A group that starts with the profile's components and lists its creator in the creator role seeds the room.
#[test]
fn a_group_carrying_the_profile_seeds() {
    let profile = LaneRoomProfile::neutral();
    assert_eq!(check(&profile, &with_profile(&profile, ROLE_ADMIN)), Ok(()));
}

/// A group with no roles_list would drop the room's role checks. Revert check: skip the policy comparison and it seeds.
#[test]
fn a_group_without_the_roles_list_is_refused() {
    let profile = LaneRoomProfile::neutral();
    let components = vec![(PARTICIPANT_LIST_COMPONENT, list(&[(ALICE, ROLE_ADMIN)]))];
    assert!(
        matches!(check(&profile, &components), Err(UpdateRefusal::Policy(why)) if why.contains("room's policy")),
        "PLANT-SEED-KEEPS-POLICY: a seed without the room's roles_list is refused"
    );
}

/// A group whose operational policy allows external Commits, in a room whose profile refuses them. Revert check: skip
/// the operational comparison and it seeds.
#[test]
fn a_group_allowing_external_commits_is_refused() {
    let profile = LaneRoomProfile::neutral();
    let allowing = LaneRoomProfile {
        external_commit_allowed: true,
        ..LaneRoomProfile::neutral()
    };
    let mut components = with_profile(&profile, ROLE_ADMIN);
    let operational = mimi_core::operational_parameters::OPERATIONAL_POLICY_COMPONENT_ID;
    components.retain(|(id, _)| *id != operational);
    components.extend(
        allowing
            .components()
            .into_iter()
            .filter(|(id, _)| *id == operational),
    );
    assert!(
        matches!(check(&profile, &components), Err(UpdateRefusal::Policy(why)) if why.contains("operational")),
        "PLANT-SEED-KEEPS-OPERATIONAL: a seed allowing external Commits the room refuses is refused"
    );
}

/// A creator the profile makes a member lists itself as an admin. Revert check: skip the list comparison and it seeds.
#[test]
fn a_creator_raising_its_own_role_is_refused() {
    let profile = LaneRoomProfile {
        creator_role: ROLE_MEMBER,
        ..LaneRoomProfile::neutral()
    };
    assert!(
        matches!(check(&profile, &with_profile(&profile, ROLE_ADMIN)), Err(UpdateRefusal::Policy(why)) if why.contains("participants or roles")),
        "PLANT-SEED-KEEPS-LIST: a seed raising the creator's role is refused"
    );
    assert_eq!(
        check(&profile, &with_profile(&profile, ROLE_MEMBER)),
        Ok(())
    );
}

/// createRoom's components are the profile's: they decode back to its room policy and its external-Commit setting.
#[test]
fn the_profiles_components_decode_to_the_profile() {
    let profile = LaneRoomProfile::neutral();
    let components = profile.components();
    let get = |id: u16| {
        components
            .iter()
            .find(|(c, _)| *c == id)
            .map(|(_, data)| data.clone())
            .unwrap()
    };
    assert_eq!(
        mimi_core::room_policy_wire::decode_role_data(&get(crate::room_tree::ROLES_LIST_COMPONENT))
            .unwrap(),
        profile.room_policy.roles
    );
    assert_eq!(
        mimi_core::room_policy_wire::decode_base_room_policy(&get(
            crate::room_tree::BASE_ROOM_POLICY_COMPONENT
        ))
        .unwrap(),
        profile.room_policy.base
    );
    let operational = mimi_core::operational_parameters::decode_operational_parameters(&get(
        mimi_core::operational_parameters::OPERATIONAL_POLICY_COMPONENT_ID,
    ))
    .unwrap();
    assert!(!operational.external_commit_allowed);
}

/// Through the lane: Alice's first Commit, listing Bob, with a GroupInfo whose group carries no roles_list, is refused,
/// and the room keeps its policy and its list; the same Commit from a group carrying the profile is accepted.
#[test]
fn a_seed_dropping_the_profile_is_refused_through_the_lane() {
    let profile = LaneRoomProfile::neutral();
    for carries_profile in [false, true] {
        let components = if carries_profile {
            with_profile(&profile, ROLE_ADMIN)
        } else {
            vec![(PARTICIPANT_LIST_COMPONENT, list(&[(ALICE, ROLE_ADMIN)]))]
        };
        let (p, room, alice, mut group) = lane_room(&profile, &components);
        let update = ParticipantListUpdate {
            added_participants: vec![UserRolePair {
                user_uri: BOB.to_string(),
                role_index: ROLE_MEMBER,
            }],
            ..ParticipantListUpdate::default()
        };
        let commit = app_data_commit(
            &mut group,
            &alice,
            &[(
                PARTICIPANT_LIST_COMPONENT,
                encode_participant_list_update(&update).unwrap(),
                list(&[(ALICE, ROLE_ADMIN), (BOB, ROLE_MEMBER)]),
            )],
        );
        group.merge_pending_commit(&alice.provider).unwrap();
        let (info, tree) = full(&group, &alice);
        let bundle = HandshakeBundle::Commit {
            proposal_or_commit: commit,
            welcome: None,
            group_info_option: info,
            ratchet_tree_option: tree,
        }
        .encode()
        .unwrap();
        let result = p.apply_update_request(
            &room,
            &bundle,
            crate::requester::Requester::LaneUser(ALICE),
            NOW,
        );
        assert_eq!(
            p.room_policy(&room).unwrap(),
            Some(profile.room_policy.clone()),
            "the room keeps the profile's policy either way"
        );
        if carries_profile {
            // Bob is listed before any client of his is added, so the tree does not seed here; that the hub then keeps
            // the room's state is what this test is about. A seed with real adds runs in the test client against a hub.
            assert_eq!(result, Ok(()), "a Commit carrying the profile is accepted");
            assert_eq!(
                p.list_participants(&room).unwrap().len(),
                2,
                "Bob is listed"
            );
        } else {
            assert!(
                matches!(result, Err(UpdateRefusal::Policy(_))),
                "a seed without the profile is refused: {result:?}"
            );
            assert_eq!(
                p.list_participants(&room).unwrap().len(),
                1,
                "Bob is not listed"
            );
            assert!(p.room_tracking(&room).unwrap().is_none());
        }
    }
}
