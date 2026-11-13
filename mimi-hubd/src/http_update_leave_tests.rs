//! `update` with a member leaving (-07 §3.5, "Bob Leaves the Room"): the leaving client sends its Remove and a
//! participant-list change removing its user as proposals; the hub holds them, and the next Commit at that epoch must
//! include them by reference (RFC 9420 §12.4: proposals from another member go in by reference). Every refusal leaves
//! the room as it was.

use mimi_core::commit_wire::decode_proposal_message;
use mimi_core::participant_list::{
    encode_participant_list_update, ParticipantListUpdate, UserRolePair,
    MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use mimi_core::protocol_wire::{HandshakeBundle, UpdateRoomResponse};

use super::tests::{app, bundle_of, real_single_custom_proposal_commit, update_answer};
use super::update_tests::{as_app_data_update, post, ROOM};
use crate::http::SharedProvider;

const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const CAROL: &str = "mimi://havenmessenger.com/u/carol";

fn vl(bytes: &[u8]) -> Vec<u8> {
    use tls_codec::Serialize as _;
    tls_codec::VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

fn length_prefix(len: usize) -> Vec<u8> {
    let whole = vl(&vec![0u8; len]);
    whole[..whole.len() - len].to_vec()
}

fn room(p: &SharedProvider) {
    for user in [ALICE, BOB, CAROL] {
        p.lock().unwrap().add_participant(ROOM, user, 1).unwrap();
    }
}

fn listed(p: &SharedProvider) -> Vec<String> {
    p.lock()
        .unwrap()
        .list_participants(ROOM)
        .unwrap()
        .into_iter()
        .map(|(uri, _)| uri)
        .collect()
}

fn list_change(added: &[&str], removed: &[u32]) -> Vec<u8> {
    encode_participant_list_update(&ParticipantListUpdate {
        added_participants: added
            .iter()
            .map(|user| UserRolePair {
                user_uri: (*user).into(),
                role_index: 2,
            })
            .collect(),
        removed_indices: removed.to_vec(),
        ..Default::default()
    })
    .unwrap()
}

/// A member-sent PublicMessage proposal at epoch 0, the epoch of the Commits these tests send, from leaf `sender`.
fn proposal(sender: u32, body: &[u8]) -> Vec<u8> {
    [
        1u16.to_be_bytes().to_vec(),
        1u16.to_be_bytes().to_vec(),
        vl(b"group"),
        0u64.to_be_bytes().to_vec(),
        vec![1],
        sender.to_be_bytes().to_vec(),
        vl(b""),
        vec![2],
        body.to_vec(),
        vl(&[9; 64]),
        vl(&[8; 32]),
    ]
    .concat()
}

fn remove_of(leaf: u32) -> Vec<u8> {
    proposal(
        leaf,
        &[
            0x0003u16.to_be_bytes().to_vec(),
            leaf.to_be_bytes().to_vec(),
        ]
        .concat(),
    )
}

/// The participant-list change as an AppDataUpdate proposal for component 0x0022, sent by `sender`.
fn change_of(sender: u32, update: &[u8]) -> Vec<u8> {
    proposal(
        sender,
        &[
            0x0008u16.to_be_bytes().to_vec(),
            0x0022u16.to_be_bytes().to_vec(),
            vec![1],
            vl(update),
        ]
        .concat(),
    )
}

fn reference_of(message: &[u8]) -> Vec<u8> {
    decode_proposal_message(message).unwrap().reference
}

fn bundle_of_proposals(first: Vec<u8>, more: Vec<Vec<u8>>) -> Vec<u8> {
    HandshakeBundle::Proposal {
        proposal_or_commit: first,
        more_proposals: more,
    }
    .encode()
    .unwrap()
}

fn by_reference(reference: &[u8]) -> Vec<u8> {
    [vec![2], vl(reference)].concat()
}

/// A real Commit at epoch 0 whose proposals window is `entries`.
fn commit_of(entries: &[Vec<u8>]) -> Vec<u8> {
    let payload = list_change(&[], &[]);
    let real =
        real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, payload.clone());
    let sent = as_app_data_update(&real, &payload, 0x0022);
    let entry = [
        vec![0x01, 0x00, 0x08],
        0x0022u16.to_be_bytes().to_vec(),
        vec![0x01],
        vl(&payload),
    ]
    .concat();
    let found = [length_prefix(entry.len()), entry].concat();
    let at = sent
        .windows(found.len())
        .position(|w| w == found.as_slice())
        .expect("the window of the one AppDataUpdate");
    let window = entries.concat();
    [
        &sent[..at],
        &length_prefix(window.len()),
        &window,
        &sent[at + found.len()..],
    ]
    .concat()
}

/// A change sent by value in a Commit.
fn by_value_change(update: &[u8]) -> Vec<u8> {
    [
        vec![0x01, 0x00, 0x08],
        0x0022u16.to_be_bytes().to_vec(),
        vec![0x01],
        vl(update),
    ]
    .concat()
}

async fn send(p: &SharedProvider, router: axum::Router, body: Vec<u8>) -> UpdateRoomResponse {
    let _ = p;
    update_answer(post(router, ROOM, body).await).await
}

/// Bob's leave: his Remove and the change removing him (index 1), as one bundle.
fn bobs_leave() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let remove = remove_of(1);
    let change = change_of(1, &list_change(&[], &[1]));
    let bundle = bundle_of_proposals(remove.clone(), vec![change.clone()]);
    (bundle, reference_of(&remove), reference_of(&change))
}

fn is_success(answer: &UpdateRoomResponse) -> bool {
    matches!(answer, UpdateRoomResponse::Success { .. })
}

fn invalid_refs(answer: &UpdateRoomResponse) -> Option<Vec<Vec<u8>>> {
    match answer {
        UpdateRoomResponse::InvalidProposal {
            invalid_proposals, ..
        } => Some(invalid_proposals.clone()),
        _ => None,
    }
}

/// -07 §3.5: Bob's proposals are held, not applied; Alice's next Commit includes them by reference and Bob leaves. Revert
/// check: refuse a bundle of proposals, or a proposal by reference, and Bob stays listed.
#[tokio::test]
async fn a_member_leaves_through_proposals_the_next_commit_includes_by_reference() {
    let (router, p) = app();
    room(&p);
    let (bundle, remove, change) = bobs_leave();
    let held = send(&p, router.clone(), bundle).await;
    assert!(is_success(&held), "{held:?}");
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
    let commit = commit_of(&[by_reference(&remove), by_reference(&change)]);
    let answer = send(&p, router.clone(), bundle_of(commit)).await;
    assert!(is_success(&answer), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE, CAROL]);
    // What was held is gone with the Commit that included it: a later Commit at that epoch need not name it.
    let later = commit_of(&[by_value_change(&list_change(&[BOB], &[]))]);
    let answer = send(&p, router, bundle_of(later)).await;
    assert!(is_success(&answer), "{answer:?}");
}

/// The hub requires the next Commit to include what it holds: one that leaves a held proposal out is refused, naming
/// it, and nothing changes. Revert check: skip the left-out check and Carol is removed while Bob stays.
#[tokio::test]
async fn a_commit_that_leaves_out_a_held_proposal_is_refused_naming_it() {
    let (router, p) = app();
    room(&p);
    let (bundle, remove, change) = bobs_leave();
    assert!(is_success(&send(&p, router.clone(), bundle).await));
    let other = commit_of(&[by_value_change(&list_change(&[], &[2]))]);
    let answer = send(&p, router.clone(), bundle_of(other)).await;
    assert_eq!(invalid_refs(&answer), Some(vec![remove.clone(), change]));
    let half = commit_of(&[by_reference(&remove)]);
    let answer = send(&p, router, bundle_of(half)).await;
    assert!(
        invalid_refs(&answer).is_some_and(|refs| refs.len() == 1),
        "{answer:?}"
    );
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}

/// A reference to nothing the hub holds for the Commit's epoch is refused, naming it; so is one named twice.
#[tokio::test]
async fn a_reference_the_hub_holds_nothing_for_is_refused_naming_it() {
    let (router, p) = app();
    room(&p);
    let unknown = vec![7u8; 32];
    let commit = commit_of(&[
        by_value_change(&list_change(&[], &[2])),
        by_reference(&unknown),
    ]);
    let answer = send(&p, router.clone(), bundle_of(commit)).await;
    assert_eq!(invalid_refs(&answer), Some(vec![unknown]));
    let (bundle, remove, change) = bobs_leave();
    assert!(is_success(&send(&p, router.clone(), bundle).await));
    let twice = commit_of(&[
        by_reference(&remove),
        by_reference(&change),
        by_reference(&remove),
    ]);
    let answer = send(&p, router, bundle_of(twice)).await;
    assert_eq!(invalid_refs(&answer), Some(vec![remove]));
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}

/// Proposals are taken only as a leave: a change that adds, Removes with no change, two changes, or proposals of two
/// epochs are refused and nothing is held. A held change beside a change sent by value is a second change.
#[tokio::test]
async fn proposals_that_are_not_a_leave_are_refused() {
    let (router, p) = app();
    room(&p);
    let adds = bundle_of_proposals(change_of(1, &list_change(&[BOB], &[])), vec![]);
    let removes_alone = bundle_of_proposals(remove_of(1), vec![]);
    let two_changes = bundle_of_proposals(
        change_of(1, &list_change(&[], &[1])),
        vec![change_of(1, &list_change(&[], &[1]))],
    );
    let mut later = remove_of(1);
    later[2 + 2 + vl(b"group").len() + 7] = 1;
    let two_epochs = bundle_of_proposals(change_of(1, &list_change(&[], &[1])), vec![later]);
    for refused in [adds, removes_alone, two_changes, two_epochs] {
        let answer = send(&p, router.clone(), refused).await;
        assert!(invalid_refs(&answer).is_some(), "{answer:?}");
    }
    // A real leave is held, and a Commit that includes it beside a change of its own carries two changes.
    let (bundle, remove, change) = bobs_leave();
    assert!(is_success(&send(&p, router.clone(), bundle).await));
    let beside = commit_of(&[
        by_value_change(&list_change(&[], &[2])),
        by_reference(&remove),
        by_reference(&change),
    ]);
    let answer = send(&p, router, bundle_of(beside)).await;
    assert!(invalid_refs(&answer).is_some(), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}
