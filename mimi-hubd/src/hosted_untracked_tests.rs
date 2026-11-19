//! A room hosted here whose ratchet tree the hub does not keep: its first Commit must give the hub the tree, and while it
//! has none it takes no participant-list or room-policy change (`untracked_rooms = "refuse"`, the default).

use mimi_core::participant_list::{
    encode_participant_list_data, encode_participant_list_update, ParticipantListData,
    ParticipantListUpdate, UserRolePair,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation, HandshakeBundle};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    AppDataUpdateProposal, MlsGroup, MlsMessageIn, ProcessedMessageContent, Proposal,
};
use openmls_traits::OpenMlsProvider as _;

use crate::client_lane_rooms::{LaneRoomProfile, ROLE_ADMIN, ROLE_MEMBER};
use crate::mls_fixtures::{add_and_join, app_data_commit, group_info_after, Member};
use crate::peer::PeerIdentity;
use crate::policy::UntrackedRooms;
use crate::room_tree::PARTICIPANT_LIST_COMPONENT;
use crate::{Provider, UpdateRefusal};

const DOMAIN: &str = "hub.example";
/// A room hosted here that a client of another provider created: the hub has no row for it before its first Commit.
const ROOM: &str = "mimi://hub.example/r/peer-room";
const ALICE: &str = "mimi://member.example/u/alice";
const BOB: &str = "mimi://member.example/u/bob";
const CAROL: &str = "mimi://member.example/u/carol";
const NOW: u64 = 1_700_000_000;
/// ratchet-tree-options `distributionService`: the hub is to rebuild the tree itself.
const DISTRIBUTION_SERVICE: &[u8] = &[4];

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

fn member_example() -> PeerIdentity {
    PeerIdentity::signed("member.example")
}

/// `by`'s Commit in `group` adding `joiner`'s client and `joiner` to the participant list in `role`, in the same Commit,
/// merged on `by`'s side: the Commit as MLSMessage bytes. `list_after` is the group's participant list after it.
fn add(
    group: &mut MlsGroup,
    by: &Member,
    joiner: &Member,
    joiner_uri: &str,
    role: u32,
    list_after: &[(&str, u32)],
) -> Vec<u8> {
    let update = ParticipantListUpdate {
        added_participants: vec![UserRolePair {
            user_uri: joiner_uri.to_string(),
            role_index: role,
        }],
        ..ParticipantListUpdate::default()
    };
    let mut stage = group
        .commit_builder()
        .propose_adds([joiner.key_package()])
        .add_proposals([Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(
                PARTICIPANT_LIST_COMPONENT,
                encode_participant_list_update(&update).unwrap(),
            ),
        ))])
        .load_psks(by.provider.storage())
        .unwrap();
    let mut updater = stage.app_data_dictionary_updater();
    updater.set(openmls::component::ComponentData::from_parts(
        PARTICIPANT_LIST_COMPONENT,
        list(list_after).into(),
    ));
    stage.with_app_data_dictionary_updates(updater.changes());
    let (commit, _welcome, _group_info) = stage
        .build(by.provider.rand(), by.provider.crypto(), &by.signer, |_| {
            true
        })
        .unwrap()
        .stage_commit(&by.provider)
        .unwrap()
        .into_contents();
    group.merge_pending_commit(&by.provider).unwrap();
    commit.tls_serialize_detached().unwrap()
}

/// The Commit with a Full GroupInfo of `group` after it signed by `signer`, and the full tree, or with `tree_option`
/// in its place when given, as an UpdateRequest body.
fn bundle(commit: &[u8], group: &MlsGroup, signer: &Member, tree_option: Option<&[u8]>) -> Vec<u8> {
    let tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();
    HandshakeBundle::Commit {
        proposal_or_commit: commit.to_vec(),
        welcome: None,
        group_info_option: GroupInfoOption {
            representation: GroupInfoRepresentation::Full,
            payload: group_info_after(group, signer),
        },
        ratchet_tree_option: tree_option
            .map_or_else(|| [&[1u8][..], &tree].concat(), <[u8]>::to_vec),
    }
    .encode()
    .unwrap()
}

fn listed(p: &Provider) -> Vec<String> {
    p.list_participants(ROOM)
        .unwrap()
        .into_iter()
        .map(|participant| participant.0)
        .collect()
}

/// Alice's new group for the room, listing her in `role`, with `components` besides the list.
fn alices_group(alice: &Member, role: u32, components: Vec<(u16, Vec<u8>)>) -> MlsGroup {
    let mut components = components;
    components.push((PARTICIPANT_LIST_COMPONENT, list(&[(ALICE, role)])));
    alice.create_group_with(ROOM.as_bytes(), &components)
}

/// `by`'s Commit in `group` naming the room, merged on `by`'s side: the Commit as MLSMessage bytes.
fn name_room(group: &mut MlsGroup, by: &Member) -> Vec<u8> {
    let metadata =
        mimi_core::room_metadata::encode_room_metadata(&mimi_core::room_metadata::RoomMetadata {
            room_uri: ROOM.to_string(),
            room_name: "Table".to_string(),
            descriptions: Vec::new(),
            avatar: String::new(),
            subject: String::new(),
            mood: String::new(),
        });
    let commit = app_data_commit(
        group,
        by,
        &[(
            mimi_core::room_metadata::ROOM_METADATA_COMPONENT_ID,
            metadata.clone(),
            metadata,
        )],
    );
    group.merge_pending_commit(&by.provider).unwrap();
    commit
}

/// A room another provider's client created here seeds from its first Commit: the group lists its creator from its
/// creation, which no Commit carries, so the list before that Commit is the creator alone. Revert check: compare the
/// group's list with the hub's empty one, and the Commit is refused for a list that differs.
#[test]
fn a_room_another_providers_client_created_seeds_from_its_first_commit() {
    let p = Provider::in_memory(DOMAIN).unwrap();
    let alice = Member::new(ALICE);
    let bob = Member::new(BOB);
    let mut group = alices_group(&alice, 1, Vec::new());
    let commit = add(&mut group, &alice, &bob, BOB, 1, &[(ALICE, 1), (BOB, 1)]);
    let peer = member_example();
    let result = p.apply_update_request(
        ROOM,
        &bundle(&commit, &group, &alice, None),
        Some(&peer),
        NOW,
    );
    assert_eq!(
        result,
        Ok(()),
        "PLANT-NEW-ROOM-CREATOR: a new room's first Commit with a Full GroupInfo and tree was refused"
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_some(),
        "the room is tracked"
    );
    assert_eq!(listed(&p).len(), 2, "both are listed");
}

/// A room's first Commit without the tree is refused and changes nothing; on `accept` it is taken, untracked. Revert
/// check: drop the first-Commit rule, and the room takes Bob without the hub ever having its tree.
#[test]
fn a_rooms_first_commit_without_the_tree_is_refused() {
    for policy in [UntrackedRooms::Refuse, UntrackedRooms::Accept] {
        let mut p = Provider::in_memory(DOMAIN).unwrap();
        p.policy.untracked_rooms = policy;
        let alice = Member::new(ALICE);
        let bob = Member::new(BOB);
        let mut group = alices_group(&alice, 1, Vec::new());
        let commit = add(&mut group, &alice, &bob, BOB, 1, &[(ALICE, 1), (BOB, 1)]);
        let result = p.apply_update_request(
            ROOM,
            &bundle(&commit, &group, &alice, Some(DISTRIBUTION_SERVICE)),
            Some(&member_example()),
            NOW,
        );
        if policy == UntrackedRooms::Refuse {
            assert!(
                matches!(result, Err(UpdateRefusal::Policy(why)) if why.contains("full ratchet tree")),
                "PLANT-UNTRACKED-FIRST-SEED: a first Commit without the tree was taken: {result:?}"
            );
            assert!(listed(&p).is_empty(), "nothing is listed");
            assert_eq!(
                p.store.room_epoch(ROOM).unwrap(),
                None,
                "no Commit is recorded"
            );
        } else {
            assert_eq!(result, Ok(()), "accept takes it");
            assert!(p.room_tracking(ROOM).unwrap().is_none());
        }
    }
}

/// A first Commit whose seed fails a check is refused, not taken untracked: here the GroupInfo's signer is not of the
/// provider that sent it. The group has no participant list and the Commit only names the room, so nothing else would
/// refuse it. Revert check: take the Commit first and seed after it, as for a room that needs no seed, and it is taken
/// with the room left untracked.
#[test]
fn a_first_commit_whose_seed_fails_a_check_is_refused() {
    let p = Provider::in_memory(DOMAIN).unwrap();
    let alice = Member::new(ALICE);
    let mut group = alice.create_group(ROOM.as_bytes());
    let commit = name_room(&mut group, &alice);
    let result = p.apply_update_request(
        ROOM,
        &bundle(&commit, &group, &alice, None),
        Some(&PeerIdentity::signed("other.example")),
        NOW,
    );
    assert!(
        matches!(result, Err(UpdateRefusal::Policy(_))),
        "PLANT-SEED-BEFORE-WRITE: a Commit whose seed failed was taken: {result:?}"
    );
    assert_eq!(p.room_metadata(ROOM).unwrap(), None, "the room has no name");
    assert!(p.room_tracking(ROOM).unwrap().is_none());
}

/// A room with Commits but no tree takes a participant-list change only with a bundle that seeds it, and then it is
/// tracked. Revert check: drop the rule for rooms with Commits, and the change is taken without the tree.
#[test]
fn a_room_with_commits_and_no_tree_takes_a_change_only_with_the_tree() {
    let p = Provider::in_memory(DOMAIN).unwrap();
    p.add_participant(ROOM, ALICE, NOW).unwrap();
    p.store.commit_accepted_at(ROOM, 0).unwrap();
    let alice = Member::new(ALICE);
    let bob = Member::new(BOB);
    let carol = Member::new(CAROL);
    let mut group = alices_group(&alice, 1, Vec::new());
    let _bobs = add_and_join(&mut group, &alice, &bob);
    let commit = add(
        &mut group,
        &alice,
        &carol,
        CAROL,
        1,
        &[(ALICE, 1), (CAROL, 1)],
    );
    let peer = member_example();
    let result = p.apply_update_request(
        ROOM,
        &bundle(&commit, &group, &alice, Some(DISTRIBUTION_SERVICE)),
        Some(&peer),
        NOW,
    );
    assert!(
        matches!(result, Err(UpdateRefusal::Policy(_))),
        "PLANT-UNTRACKED-ROLE-GATED: a participant change was taken without the tree: {result:?}"
    );
    assert_eq!(listed(&p), vec![ALICE.to_string()], "Carol is not listed");
    let result = p.apply_update_request(
        ROOM,
        &bundle(&commit, &group, &alice, None),
        Some(&peer),
        NOW,
    );
    assert_eq!(result, Ok(()), "with the tree it is taken");
    assert!(
        p.room_tracking(ROOM).unwrap().is_some(),
        "and the room is tracked"
    );
    assert_eq!(listed(&p).len(), 2);
}

/// The Commit that gives the hub the tree is authorized for its committer like any other: a creator whose role may not
/// add participants cannot add Bob. Revert check: skip the seeding Commit's authorization, and Bob is added.
#[test]
fn the_seeding_commits_changes_are_authorized_for_its_committer() {
    for (role, allowed) in [(ROLE_MEMBER, false), (ROLE_ADMIN, true)] {
        let p = Provider::in_memory(DOMAIN).unwrap();
        let alice = Member::new(ALICE);
        let bob = Member::new(BOB);
        let mut group = alices_group(&alice, role, LaneRoomProfile::neutral().components());
        let commit = add(
            &mut group,
            &alice,
            &bob,
            BOB,
            ROLE_MEMBER,
            &[(ALICE, role), (BOB, ROLE_MEMBER)],
        );
        let result = p.apply_update_request(
            ROOM,
            &bundle(&commit, &group, &alice, None),
            Some(&member_example()),
            NOW,
        );
        if allowed {
            assert_eq!(result, Ok(()), "an admin adds Bob");
        } else {
            assert!(
                matches!(result, Err(UpdateRefusal::Policy(_))),
                "PLANT-SEED-AUTHORIZED: a member added Bob: {result:?}"
            );
            assert!(listed(&p).is_empty());
        }
    }
}

/// The GroupInfo that seeds the room must be signed by the member that sent the Commit: the committer is the one its
/// changes are authorized for. Bob's GroupInfo for Alice's Commit is refused; Alice's is taken. Revert check: drop the
/// sender check, and Bob's is taken.
#[test]
fn a_seed_signed_by_another_member_than_the_committer_is_refused() {
    let p = Provider::in_memory(DOMAIN).unwrap();
    p.add_participant(ROOM, ALICE, NOW).unwrap();
    p.store.commit_accepted_at(ROOM, 0).unwrap();
    let alice = Member::new(ALICE);
    let bob = Member::new(BOB);
    let carol = Member::new(CAROL);
    let mut group = alices_group(&alice, 1, Vec::new());
    let mut bobs = add_and_join(&mut group, &alice, &bob);
    let commit = add(
        &mut group,
        &alice,
        &carol,
        CAROL,
        1,
        &[(ALICE, 1), (CAROL, 1)],
    );
    let message = MlsMessageIn::tls_deserialize_exact(&commit)
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let processed = bobs.process_message(&bob.provider, message).unwrap();
    // The Commit changes the participant list, so Bob resolves it with the list it leaves.
    let mut updater = bobs.app_data_dictionary_updater();
    updater.set(openmls::component::ComponentData::from_parts(
        PARTICIPANT_LIST_COMPONENT,
        list(&[(ALICE, 1), (CAROL, 1)]).into(),
    ));
    let changes = updater.changes();
    let processed = bobs
        .resolve_app_data_commit(&bob.provider, processed, changes)
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("not a Commit");
    };
    bobs.merge_staged_commit(&bob.provider, *staged).unwrap();
    let peer = member_example();
    let result =
        p.apply_update_request(ROOM, &bundle(&commit, &bobs, &bob, None), Some(&peer), NOW);
    assert!(
        matches!(result, Err(UpdateRefusal::Policy(why)) if why.contains("member that sent the Commit")),
        "PLANT-SIGNER-IS-SENDER: a seed another member signed was taken: {result:?}"
    );
    assert!(p.room_tracking(ROOM).unwrap().is_none());
    let result = p.apply_update_request(
        ROOM,
        &bundle(&commit, &group, &alice, None),
        Some(&peer),
        NOW,
    );
    assert_eq!(result, Ok(()), "the committer's own GroupInfo is taken");
}

/// A room's first Commit needs the tree even when it changes nothing that needs its proposer: here it only names the
/// room. With the tree it is taken, and the room is tracked from it. Revert check: let a first Commit through on what it
/// changes alone, and the room takes its name and stays untracked.
#[test]
fn a_rooms_first_commit_that_only_names_it_needs_the_tree_too() {
    let p = Provider::in_memory(DOMAIN).unwrap();
    let alice = Member::new(ALICE);
    let mut group = alices_group(&alice, 1, Vec::new());
    let commit = name_room(&mut group, &alice);
    let peer = member_example();
    let result = p.apply_update_request(
        ROOM,
        &bundle(&commit, &group, &alice, Some(DISTRIBUTION_SERVICE)),
        Some(&peer),
        NOW,
    );
    assert!(
        matches!(result, Err(UpdateRefusal::Policy(_))),
        "PLANT-UNTRACKED-FIRST-SEED: a first Commit without the tree was taken: {result:?}"
    );
    assert_eq!(p.room_metadata(ROOM).unwrap(), None, "the room has no name");
    let result = p.apply_update_request(
        ROOM,
        &bundle(&commit, &group, &alice, None),
        Some(&peer),
        NOW,
    );
    assert_eq!(result, Ok(()), "with the tree it is taken");
    assert!(p.room_tracking(ROOM).unwrap().is_some());
    assert_eq!(listed(&p), vec![ALICE.to_string()], "its creator is listed");
}
