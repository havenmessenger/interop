//! A tracked room's Commit that carries a Partial GroupInfo (ratchet-tree-options §4): the hub rebuilds the GroupInfo
//! from its group after the Commit and checks it as it checks a Full one.

use mimi_core::partial_group_info::{PartialGroupInfo, RatchetTreePresence};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _, VLBytes};
use openmls::prelude::*;
use openmls_traits::signatures::Signer as _;

use super::*;
use crate::mls_fixtures::{add_commit, Member};
use crate::peer::PeerIdentity;

const ROOM: &str = "mimi://hub.example/r/room";
const GROUP: &[u8] = b"mimi://example.com/g/room";

fn full(group_info: &[u8]) -> GroupInfoOption {
    GroupInfoOption {
        representation: GroupInfoRepresentation::Full,
        payload: group_info.to_vec(),
    }
}

fn partial(partial: &PartialGroupInfo) -> GroupInfoOption {
    GroupInfoOption {
        representation: GroupInfoRepresentation::Partial,
        payload: partial.encode().unwrap(),
    }
}

/// A hub tracking Alice's room (Alice and Bob, seeded at epoch 1), Alice's group, and Alice.
fn tracked() -> (Provider, RoomTracking, MlsGroup, Member) {
    let p = Provider::in_memory("hub.example").unwrap();
    let alice = Member::new("mimi://example.com/u/alice");
    let bob = Member::new("mimi://example.com/u/bob");
    let mut group = alice.create_group(GROUP);
    let (_commit, group_info, tree) = add_commit(&mut group, &alice, &[&bob]);
    for user in ["mimi://example.com/u/alice", "mimi://example.com/u/bob"] {
        p.add_participant(ROOM, user, 1).unwrap();
    }
    p.seed_room_tree(
        ROOM,
        0,
        Some(&PeerIdentity::signed("example.com")),
        &full(&group_info),
        &[&[1u8][..], &tree].concat(),
    );
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    (p, tracking, group, alice)
}

/// `group`'s GroupInfo signed by `by`, with the ratchet tree in it, as openmls exports one: ratchet_tree, then
/// external_pub.
fn group_info_with_tree(group: &MlsGroup, by: &Member) -> Vec<u8> {
    let message: MlsMessageIn = group
        .export_group_info(by.provider.crypto(), &by.signer, true)
        .unwrap()
        .into();
    match message.extract() {
        MlsMessageBodyIn::GroupInfo(info) => info.tls_serialize_detached().unwrap(),
        other => panic!("not a GroupInfo: {other:?}"),
    }
}

/// `group_info` with its two extensions swapped and signed again by `by`: the tree last, as ratchet-tree-options §4 has
/// a GroupInfo sent as a Partial one put it.
fn with_the_tree_last(group_info: &[u8], by: &Member) -> Vec<u8> {
    use openmls::messages::group_info::VerifiableGroupInfo;
    let info = VerifiableGroupInfo::tls_deserialize_exact(group_info).unwrap();
    let context = info.group_context().tls_serialize_detached().unwrap();
    let rest = &group_info[context.len()..];
    let list = VLBytes::tls_deserialize(&mut &rest[..]).unwrap();
    let after_list = &rest[list.tls_serialized_len()..];
    let mut extensions = Vec::new();
    let mut remaining = list.as_slice();
    while !remaining.is_empty() {
        let extension_type = u16::tls_deserialize(&mut &remaining[..]).unwrap();
        let data = VLBytes::tls_deserialize(&mut &remaining[2..]).unwrap();
        let length = 2 + data.tls_serialized_len();
        extensions.push((extension_type, remaining[..length].to_vec()));
        remaining = &remaining[length..];
    }
    assert_eq!(
        extensions.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        [0x0002, 0x0004]
    );
    let swapped = [extensions[1].1.clone(), extensions[0].1.clone()].concat();
    // After the list: the confirmation tag, the u32 signer, then the 64-byte signature with its two-byte length.
    let tail = &after_list[..after_list.len() - 66];
    let tbs = [
        context,
        VLBytes::new(swapped).tls_serialize_detached().unwrap(),
        tail.to_vec(),
    ]
    .concat();
    let content = SignContent::new("GroupInfoTBS", tbs.clone().into())
        .tls_serialize_detached()
        .unwrap();
    let signature = by.signer.sign(&content).unwrap();
    [
        tbs,
        VLBytes::new(signature).tls_serialize_detached().unwrap(),
    ]
    .concat()
}

/// Alice's Partial GroupInfo for her Commit, the tree not in it, is rebuilt and stages; the same with one byte of its
/// signature changed is refused. Revert check: take a Partial GroupInfo unchecked, and the broken one stages.
#[test]
fn a_partial_group_info_is_rebuilt_and_its_signature_checked() {
    let (p, tracking, mut group, alice) = tracked();
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, group_info, _tree) = add_commit(&mut group, &alice, &[&carol]);
    let good = PartialGroupInfo::split(&group_info, false).unwrap();
    assert_eq!(
        good.ratchet_tree_presence,
        RatchetTreePresence::NoRatchetTree
    );
    let mut broken = good.clone();
    *broken.signature.last_mut().unwrap() ^= 0x01;
    assert!(
        matches!(
            p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&partial(&broken))),
            Err(UpdateRefusal::Invalid(_))
        ),
        "PLANT-PARTIAL-GI-SIGNED: a Partial GroupInfo with a broken signature passed"
    );
    let staged = p
        .stage_tracked_commit(ROOM, &tracking, &commit, Some(&partial(&good)))
        .unwrap();
    p.merge_tracked_commit(staged).unwrap();
}

/// A Partial GroupInfo whose GroupInfo carried the tree, as openmls writes it (first), is rebuilt with the hub's tree
/// after the Commit and stages. Revert check: rebuild without the tree, and it is refused.
#[test]
fn a_partial_group_info_with_the_tree_first_is_rebuilt_with_the_hubs_tree() {
    let (p, tracking, mut group, alice) = tracked();
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, _group_info, _tree) = add_commit(&mut group, &alice, &[&carol]);
    let with_tree = PartialGroupInfo::split(&group_info_with_tree(&group, &alice), true).unwrap();
    assert!(
        p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&partial(&with_tree)))
            .is_ok(),
        "PLANT-PARTIAL-GI-TREE: a Partial GroupInfo carrying the tree was not rebuilt with it"
    );
    // The same Partial claiming no tree is a GroupInfo nobody signed.
    let mut no_tree = with_tree;
    no_tree.ratchet_tree_presence = RatchetTreePresence::NoRatchetTree;
    assert!(matches!(
        p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&partial(&no_tree))),
        Err(UpdateRefusal::Invalid(_))
    ));
}

/// A Partial GroupInfo whose GroupInfo put the tree last, as ratchet-tree-options §4 requires, stages too. Revert check:
/// rebuild with the tree first only, and it is refused.
#[test]
fn a_partial_group_info_with_the_tree_last_stages() {
    let (p, tracking, mut group, alice) = tracked();
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, _group_info, _tree) = add_commit(&mut group, &alice, &[&carol]);
    let last = with_the_tree_last(&group_info_with_tree(&group, &alice), &alice);
    assert!(p
        .stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&last)))
        .is_ok());
    let partial_last = PartialGroupInfo::split(&last, true).unwrap();
    assert!(
        p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&partial(&partial_last)))
            .is_ok(),
        "PLANT-PARTIAL-GI-TREE-LAST: a Partial GroupInfo with the tree last was refused"
    );
}

/// A Partial GroupInfo that does not decode is refused, and the group does not move.
#[test]
fn a_partial_group_info_that_does_not_decode_is_refused() {
    let (p, tracking, mut group, alice) = tracked();
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, group_info, _tree) = add_commit(&mut group, &alice, &[&carol]);
    let garbage = GroupInfoOption {
        representation: GroupInfoRepresentation::Partial,
        payload: vec![9, 0, 0],
    };
    assert!(matches!(
        p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&garbage)),
        Err(UpdateRefusal::Invalid(_))
    ));
    // The group did not move: the same Commit, with its Full GroupInfo, still stages.
    assert!(p
        .stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&group_info)))
        .is_ok());
}

/// What fails a rebuild is told apart: a Partial that does not decode and a Commit without a confirmation tag are the
/// sender's, a tree the hub cannot rebuild (here, a group it does not hold) is the hub's. Revert check: answer every
/// failure as the sender's, and the hub's own is blamed on the Partial.
#[test]
fn a_rebuild_the_hub_cannot_make_is_the_hubs_failure() {
    let (p, tracking, mut group, alice) = tracked();
    let carol = Member::new("mimi://example.com/u/carol");
    let (commit, _group_info, _tree) = add_commit(&mut group, &alice, &[&carol]);
    let with_tree = PartialGroupInfo::split(&group_info_with_tree(&group, &alice), true)
        .unwrap()
        .encode()
        .unwrap();
    let staged = p
        .stage_tracked_commit(ROOM, &tracking, &commit, None)
        .unwrap();
    let elsewhere = RoomTracking {
        group_id: b"a group the hub does not hold".to_vec(),
        seeded_by: tracking.seeded_by.clone(),
    };
    let tag = [0u8; 33];
    let rebuild = |tracking: &RoomTracking, partial: &[u8], tag: Option<&[u8]>| {
        p.rebuilt_group_infos(
            tracking,
            &commit,
            partial,
            &staged.staged,
            tag,
            LeafNodeIndex::new(0),
        )
    };
    assert_eq!(
        rebuild(&elsewhere, &with_tree, Some(&tag)),
        Err(RebuildError::Hub),
        "PLANT-PARTIAL-GI-HUB-FAILURE: the hub's failure to rebuild the tree was blamed on the sender"
    );
    assert_eq!(
        rebuild(&tracking, &[9, 0, 0], Some(&tag)),
        Err(RebuildError::DoesNotDecode)
    );
    assert_eq!(
        rebuild(&tracking, &with_tree, None),
        Err(RebuildError::NoConfirmationTag)
    );
    assert_eq!(
        rebuild(&tracking, &with_tree, Some(&tag)).map(|v| v.len()),
        Ok(2)
    );
}
