//! Seeding a room's tree from a bundle, verifying a tracked room's Commits against it, and what is refused.

use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;

use super::*;
use crate::mls_fixtures::{add_commit, group_info_after, Member};
use crate::peer::PeerIdentity;

const ROOM: &str = "mimi://hub.example/r/room";
const GROUP: &[u8] = b"mimi://example.com/g/room";

fn hub() -> Provider {
    Provider::in_memory("hub.example").unwrap()
}

fn full(group_info: &[u8]) -> GroupInfoOption {
    GroupInfoOption {
        representation: GroupInfoRepresentation::Full,
        payload: group_info.to_vec(),
    }
}

/// A `RatchetTreeOption` of representation `full` around a serialized tree.
fn tree_option(tree: &[u8]) -> Vec<u8> {
    [&[1u8][..], tree].concat()
}

struct Room {
    alice: Member,
    bob: Member,
    group: MlsGroup,
    group_info: Vec<u8>,
    tree: Vec<u8>,
}

/// Alice's group with Bob added in its first Commit (epoch 0 to 1), and the hub listing both as participants.
fn room(p: &Provider) -> Room {
    let alice = Member::new("mimi://example.com/u/alice");
    let bob = Member::new("mimi://example.com/u/bob");
    let mut group = alice.create_group(GROUP);
    let (_commit, group_info, tree) = add_commit(&mut group, &alice, &[&bob]);
    p.add_participant(ROOM, "mimi://example.com/u/alice", 1)
        .unwrap();
    p.add_participant(ROOM, "mimi://example.com/u/bob", 1)
        .unwrap();
    Room {
        alice,
        bob,
        group,
        group_info,
        tree,
    }
}

fn example_peer() -> PeerIdentity {
    PeerIdentity::signed("example.com")
}

fn seed(p: &Provider, room: &Room, peer: &PeerIdentity) {
    p.seed_room_tree(
        ROOM,
        0,
        Some(peer),
        &full(&room.group_info),
        &tree_option(&room.tree),
    );
}

/// A Full GroupInfo and a full tree for the epoch after the Commit, signed by a member of the sending provider, with
/// every listed participant in the tree, seed the room: it is tracked, by that provider, from that epoch.
#[test]
fn a_bundle_that_passes_every_check_seeds_the_room() {
    let p = hub();
    let room = room(&p);
    seed(&p, &room, &example_peer());
    let tracking = p.room_tracking(ROOM).unwrap().expect("the room is tracked");
    assert_eq!(tracking.group_id, GROUP);
    assert_eq!(tracking.seeded_by, "example.com");
    let group = PublicGroup::load(&p.store.groups(), &GroupId::from_slice(GROUP))
        .unwrap()
        .unwrap();
    assert_eq!(group.group_context().epoch().as_u64(), 1);
    assert_eq!(group.members().count(), 2);
}

/// A tree that leaves out a participant the hub lists does not seed the room. Revert check: drop the participant
/// check, and the room is tracked.
#[test]
fn a_tree_without_a_listed_participant_does_not_seed() {
    let p = hub();
    let room = room(&p);
    p.add_participant(ROOM, "mimi://example.com/u/carol", 1)
        .unwrap();
    seed(&p, &room, &example_peer());
    assert!(
        p.room_tracking(ROOM).unwrap().is_none(),
        "PLANT-SEED-PARTICIPANTS: a tree without a listed participant seeded the room"
    );
}

/// A tree with a client of a user the hub does not list does not seed the room: every client in the group is a client
/// of a listed participant (room-policy-04 §8.1.2). Revert check: drop that check, and the room is tracked.
#[test]
fn a_tree_with_a_client_of_an_unlisted_user_does_not_seed() {
    let p = hub();
    let alice = Member::new("mimi://example.com/u/alice");
    let bob = Member::new("mimi://example.com/u/bob");
    let mut group = alice.create_group(GROUP);
    let (_commit, group_info, tree) = add_commit(&mut group, &alice, &[&bob]);
    p.add_participant(ROOM, "mimi://example.com/u/alice", 1)
        .unwrap();
    p.seed_room_tree(
        ROOM,
        0,
        Some(&example_peer()),
        &full(&group_info),
        &tree_option(&tree),
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_none(),
        "PLANT-HUB-SEED-UNLISTED: a tree with a client of an unlisted user seeded the room"
    );
}

/// A bundle sent by a provider other than its GroupInfo's signer's, or for another epoch, or with no peer, does not seed.
/// Revert check: drop the provider check, and the other provider's bundle seeds the room.
#[test]
fn a_bundle_from_another_provider_or_epoch_does_not_seed() {
    let p = hub();
    let room = room(&p);
    seed(&p, &room, &PeerIdentity::signed("other.example"));
    assert!(
        p.room_tracking(ROOM).unwrap().is_none(),
        "PLANT-SEED-PROVIDER: another provider's bundle seeded the room"
    );
    p.seed_room_tree(
        ROOM,
        4,
        Some(&example_peer()),
        &full(&room.group_info),
        &tree_option(&room.tree),
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_none(),
        "another epoch seeded the room"
    );
    p.seed_room_tree(
        ROOM,
        0,
        None,
        &full(&room.group_info),
        &tree_option(&room.tree),
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_none(),
        "no peer seeded the room"
    );
}

/// A Partial GroupInfo, or a tree option that is not `full`, leaves the room untracked.
#[test]
fn a_bundle_without_a_full_group_info_and_tree_does_not_seed() {
    let p = hub();
    let room = room(&p);
    let partial = GroupInfoOption {
        representation: GroupInfoRepresentation::Partial,
        payload: Vec::new(),
    };
    p.seed_room_tree(
        ROOM,
        0,
        Some(&example_peer()),
        &partial,
        &tree_option(&room.tree),
    );
    p.seed_room_tree(
        ROOM,
        0,
        Some(&example_peer()),
        &full(&room.group_info),
        &[4u8],
    );
    assert!(p.room_tracking(ROOM).unwrap().is_none());
}

/// A tracked room's next Commit verifies against its tree and, merged, moves the tree on: Carol is a member at epoch 2.
#[test]
fn a_tracked_rooms_commit_is_staged_and_merged() {
    let p = hub();
    let mut room = room(&p);
    seed(&p, &room, &example_peer());
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, group_info, _tree) = add_commit(&mut room.group, &room.alice, &[&carol]);
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let staged = p
        .stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&group_info)))
        .unwrap();
    p.merge_tracked_commit(staged).unwrap();
    let group = PublicGroup::load(&p.store.groups(), &GroupId::from_slice(GROUP))
        .unwrap()
        .unwrap();
    assert_eq!(group.group_context().epoch().as_u64(), 2);
    assert_eq!(group.members().count(), 3);
}

/// A Commit the tree cannot take is refused and the tree does not move: one for an epoch already passed is
/// `wrongEpoch` naming the room's, and one whose signature does not verify is `notAllowed`. Revert check: accept a
/// Commit whose processing fails, and the tampered one stages.
#[test]
fn a_commit_the_tree_cannot_take_is_refused() {
    let p = hub();
    let mut room = room(&p);
    seed(&p, &room, &example_peer());
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, _group_info, _tree) = add_commit(&mut room.group, &room.alice, &[&carol]);

    // A byte inside the signed content: the trailing membership tag is one a delivery service cannot check (it holds no
    // epoch secret), so tampering with it would prove nothing here.
    let mut tampered = commit.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;
    assert!(
        matches!(
            p.stage_tracked_commit(ROOM, &tracking, &tampered, None),
            Err(UpdateRefusal::NotAllowed)
        ),
        "PLANT-TRACKED-REFUSE: a Commit whose signature does not verify was staged"
    );

    let staged = p
        .stage_tracked_commit(ROOM, &tracking, &commit, None)
        .unwrap();
    p.merge_tracked_commit(staged).unwrap();
    assert!(matches!(
        p.stage_tracked_commit(ROOM, &tracking, &commit, None),
        Err(UpdateRefusal::WrongEpoch(2))
    ));
}

/// A Full GroupInfo in the bundle must describe the group after the Commit: an earlier one is refused. Revert check:
/// skip the comparison, and the stale GroupInfo passes.
#[test]
fn a_group_info_that_does_not_match_the_group_after_the_commit_is_refused() {
    let p = hub();
    let mut room = room(&p);
    seed(&p, &room, &example_peer());
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let stale = group_info_after(&room.group, &room.alice);
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, _group_info, _tree) = add_commit(&mut room.group, &room.alice, &[&carol]);
    assert!(
        matches!(
            p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&stale))),
            Err(UpdateRefusal::Invalid(_))
        ),
        "PLANT-GROUP-INFO-MATCH: a GroupInfo for the epoch before passed"
    );
}

/// A Full GroupInfo in the bundle must be signed by the Commit's sender with the key it holds after the Commit: Alice's
/// own GroupInfo stages, and the same GroupInfo with one byte of its signature changed is refused, though its
/// GroupContext is the group after the Commit. Revert check: compare the GroupContext without the signature, and the
/// altered GroupInfo stages.
#[test]
fn a_group_info_not_signed_by_the_committer_is_refused() {
    let p = hub();
    let mut room = room(&p);
    seed(&p, &room, &example_peer());
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, group_info, _tree) = add_commit(&mut room.group, &room.alice, &[&carol]);
    assert!(p
        .stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&group_info)))
        .is_ok());
    let mut altered = group_info;
    let last = altered.len() - 1;
    altered[last] ^= 0x01;
    assert!(
        matches!(
            p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&altered))),
            Err(UpdateRefusal::Invalid(_))
        ),
        "PLANT-GROUP-INFO-SIGNED: a GroupInfo with a broken signature passed"
    );
}

/// A GroupInfo for the group after Alice's Commit, correctly signed by Bob, another member, is refused with her Commit:
/// it names Bob's leaf, not the committer's, and it is verified under the committer's key, so a relayer cannot pass off
/// another member's GroupInfo as the committer's. Alice's own is taken. Revert check: drop the rule that it name the
/// committer's leaf and verify under the key of the leaf it names, and Bob's passes.
#[test]
fn a_group_info_another_member_signed_is_refused() {
    let p = hub();
    let alice = Member::new("mimi://example.com/u/alice");
    let bob = Member::new("mimi://example.com/u/bob");
    let mut group = alice.create_group(GROUP);
    let mut bob_group = crate::mls_fixtures::add_and_join(&mut group, &alice, &bob);
    p.add_participant(ROOM, "mimi://example.com/u/alice", 1)
        .unwrap();
    p.add_participant(ROOM, "mimi://example.com/u/bob", 1)
        .unwrap();
    let tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();
    p.seed_room_tree(
        ROOM,
        0,
        Some(&example_peer()),
        &full(&group_info_after(&group, &alice)),
        &tree_option(&tree),
    );
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, alices, _tree) = add_commit(&mut group, &alice, &[&carol]);
    let message = MlsMessageIn::tls_deserialize_exact(commit.as_slice())
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged) = bob_group
        .process_message(&bob.provider, message)
        .unwrap()
        .into_content()
    else {
        panic!("a Commit");
    };
    bob_group
        .merge_staged_commit(&bob.provider, *staged)
        .unwrap();
    let bobs = group_info_after(&bob_group, &bob);
    assert!(
        matches!(
            p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&bobs))),
            Err(UpdateRefusal::Invalid(_))
        ),
        "PLANT-GROUP-INFO-COMMITTER: a GroupInfo Bob signed passed for Alice's Commit"
    );
    assert!(p
        .stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&alices)))
        .is_ok());
}

/// A GroupInfo the committer signed correctly, but that names another member's leaf as its signer, is refused: every
/// joiner verifies a GroupInfo under the key of the leaf it names, so the hub would be keeping one nobody can join by.
/// Built raw, since openmls signs only for its own leaf. Revert check: drop the rule that the named leaf is the
/// committer's, and it stages.
#[test]
fn a_group_info_naming_another_leaf_as_its_signer_is_refused() {
    use openmls::prelude::tls_codec::VLBytes;
    use openmls_traits::signatures::Signer as _;
    let p = hub();
    let mut room = room(&p);
    seed(&p, &room, &example_peer());
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, group_info, _tree) = add_commit(&mut room.group, &room.alice, &[&carol]);
    // An Ed25519 signature: 64 bytes after a two-byte length. Before it, the signed GroupInfoTBS ends in the signer's
    // leaf index, a u32; Alice's is 0, Bob's 1.
    let (signed, signature) = group_info.split_at(group_info.len() - 66);
    assert_eq!(&signature[..2], &[0x40, 0x40]);
    let mut renamed = signed.to_vec();
    let at = renamed.len() - 4;
    assert_eq!(&renamed[at..], &0u32.to_be_bytes());
    renamed[at..].copy_from_slice(&1u32.to_be_bytes());
    let content = SignContent::new("GroupInfoTBS", renamed.clone().into())
        .tls_serialize_detached()
        .unwrap();
    let signature = room.alice.signer.sign(&content).unwrap();
    let forged = [
        renamed,
        VLBytes::new(signature).tls_serialize_detached().unwrap(),
    ]
    .concat();
    assert!(
        matches!(
            p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&forged))),
            Err(UpdateRefusal::Invalid(_))
        ),
        "PLANT-GROUP-INFO-SIGNER-LEAF: a GroupInfo naming Bob's leaf passed for Alice's Commit"
    );
    assert!(p
        .stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&group_info)))
        .is_ok());
}

/// Alice commits an update path that replaces her signature key, and signs the GroupInfo after it with the new one: it
/// is verified under the key her leaf holds after the Commit, and stages. Revert check: verify under her leaf's key
/// from before the Commit, and her valid GroupInfo is refused.
#[test]
fn a_group_info_signed_with_the_committers_new_key_stages() {
    let p = hub();
    let mut room = room(&p);
    seed(&p, &room, &example_peer());
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let renewed = Member::new("mimi://example.com/u/alice");
    let bundle = room
        .group
        .self_update_with_new_signer(
            &room.alice.provider,
            &room.alice.signer,
            NewSignerBundle {
                signer: &renewed.signer,
                credential_with_key: renewed.credential.clone(),
            },
            LeafNodeParameters::builder()
                .with_credential_with_key(renewed.credential.clone())
                .build(),
        )
        .unwrap();
    let commit = bundle.commit().tls_serialize_detached().unwrap();
    room.group
        .merge_pending_commit(&room.alice.provider)
        .unwrap();
    let group_info = group_info_after(&room.group, &renewed);
    assert!(
        p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&group_info)))
            .is_ok(),
        "PLANT-GROUP-INFO-NEW-KEY: a GroupInfo signed with the committer's new key was refused"
    );
}

/// Bob, at leaf 1, rejoins by an external Commit with his own key, so openmls removes his old leaf in it, and puts him
/// back at that freed leaf: the leftmost blank once the Commit's removals are made, not the next leaf after the tree.
/// His GroupInfo names that leaf, and it stages. Revert check: compute the joiner's leaf before the removals, and his
/// GroupInfo is refused.
#[test]
fn a_rejoining_members_group_info_names_the_leaf_it_freed() {
    let p = hub();
    let room = room(&p);
    seed(&p, &room, &example_peer());
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let tree: RatchetTreeIn = RatchetTreeIn::tls_deserialize_exact(room.tree.as_slice()).unwrap();
    let (commit, bob_group) =
        crate::mls_fixtures::external_commit(&room.group_info, tree, &room.bob);
    assert_eq!(
        bob_group.own_leaf_index(),
        LeafNodeIndex::new(1),
        "openmls puts the rejoining member at the leaf its Commit freed"
    );
    let group_info = group_info_after(&bob_group, &room.bob);
    assert!(
        p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&group_info)))
            .is_ok(),
        "PLANT-GROUP-INFO-REJOIN-LEAF: a rejoining member's GroupInfo, naming the leaf it freed, was refused"
    );
}

/// Untracking drops the group and the record, so the next bundle can seed again.
#[test]
fn untracking_drops_the_tree() {
    let p = hub();
    let room = room(&p);
    seed(&p, &room, &example_peer());
    assert!(p.untrack_room(ROOM).unwrap());
    assert!(p.room_tracking(ROOM).unwrap().is_none());
    assert!(
        PublicGroup::load(&p.store.groups(), &GroupId::from_slice(GROUP))
            .unwrap()
            .is_none()
    );
    assert!(!p.untrack_room(ROOM).unwrap());
    let _ = (&room.bob, room.tree.tls_serialize_detached());
}

/// A proposal held for a tracked room is verified against its tree and queued in its group, so the Commit that names it
/// by reference stages; a proposal that does not verify is refused and nothing is queued. Revert check: queue nothing,
/// and the referencing Commit does not stage.
#[test]
fn a_tracked_rooms_proposal_is_queued_so_the_commit_naming_it_stages() {
    let p = hub();
    let mut room = room(&p);
    seed(&p, &room, &example_peer());
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let bob_leaf = room
        .group
        .members()
        .find(|member| member.credential == room.bob.credential.credential)
        .unwrap()
        .index;
    let (proposal, _reference) = room
        .group
        .propose_remove_member(&room.alice.provider, &room.alice.signer, bob_leaf)
        .unwrap();
    let proposal = proposal.tls_serialize_detached().unwrap();

    let mut tampered = proposal.clone();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;
    assert!(matches!(
        p.queue_tracked_proposals(ROOM, &tracking, &[&tampered]),
        Err(UpdateRefusal::NotAllowed)
    ));

    p.queue_tracked_proposals(ROOM, &tracking, &[&proposal])
        .unwrap();
    let (commit, _welcome, _info) = room
        .group
        .commit_to_pending_proposals(&room.alice.provider, &room.alice.signer)
        .unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let staged = p.stage_tracked_commit(ROOM, &tracking, &commit, None);
    assert!(
        staged.is_ok(),
        "PLANT-TRACKED-QUEUE: the Commit naming a queued proposal stages"
    );
    p.merge_tracked_commit(staged.ok().unwrap()).unwrap();
    let group = PublicGroup::load(&p.store.groups(), &GroupId::from_slice(GROUP))
        .unwrap()
        .unwrap();
    assert_eq!(group.members().count(), 1);
}

/// On the client lane a GroupInfo seeds the room only when the lane user signed it: Bob's request with Alice's GroupInfo
/// leaves the room untracked, and Alice's own seeds it. Revert check: let a lane user speak for any user, and Bob's
/// request seeds the room.
#[test]
fn on_the_client_lane_only_the_group_info_signer_seeds_the_room() {
    use crate::requester::Requester;
    let p = hub();
    let room = room(&p);
    p.seed_room_tree(
        ROOM,
        0,
        Requester::LaneUser("mimi://example.com/u/bob"),
        &full(&room.group_info),
        &tree_option(&room.tree),
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_none(),
        "PLANT-LANE-SEED: a lane user seeded the room with another user's GroupInfo"
    );
    p.seed_room_tree(
        ROOM,
        0,
        Requester::LaneUser("mimi://example.com/u/alice"),
        &full(&room.group_info),
        &tree_option(&room.tree),
    );
    assert!(p.room_tracking(ROOM).unwrap().is_some());
}

/// A peer never seeds a room's tree for a user of this hub, even one whose proof names this hub's domain; the same
/// GroupInfo from the lane, as its signer, seeds it. Revert check: let a peer speak for this provider's users, and the
/// peer seeds the room.
#[test]
fn a_peer_never_seeds_a_tree_for_a_user_of_this_hub() {
    use crate::requester::Requester;
    let room = room(&hub());
    let p = Provider::in_memory("example.com").unwrap();
    let local = "mimi://example.com/r/room";
    for user in ["mimi://example.com/u/alice", "mimi://example.com/u/bob"] {
        p.add_participant(local, user, 1).unwrap();
    }
    p.seed_room_tree(
        local,
        0,
        Some(&example_peer()),
        &full(&room.group_info),
        &tree_option(&room.tree),
    );
    assert!(
        p.room_tracking(local).unwrap().is_none(),
        "PLANT-PEER-LOCAL-SEED: a peer seeded a tree for a user of this hub"
    );
    p.seed_room_tree(
        local,
        0,
        Requester::LaneUser("mimi://example.com/u/alice"),
        &full(&room.group_info),
        &tree_option(&room.tree),
    );
    assert!(p.room_tracking(local).unwrap().is_some());
}
