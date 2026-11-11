//! `update` with a Commit that proposes the participant-list change beside `Add` and `Remove` proposals (-07 §3.2, "Alice
//! adds Bob to the Room"). The hub reads each `Add` with openmls's KeyPackage decoder, gates its KeyPackage, and checks what
//! the Adds and Removes say against the change (DIV-10). Every refusal leaves the room as it was.

use mimi_core::participant_list::{
    encode_participant_list_update, ParticipantListUpdate, UserRolePair,
    MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use mimi_core::protocol_wire::UpdateRoomResponse;

use super::tests::{
    app, bundle_of, real_keypackage_for, real_single_custom_proposal_commit, update_answer,
};
use super::update_tests::{as_app_data_update, post, ROOM};
use crate::http::SharedProvider;

const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const CAROL: &str = "mimi://havenmessenger.com/u/carol";
const DAVE: &str = "mimi://havenmessenger.com/u/dave";

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
    for user in [ALICE, BOB] {
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

/// One by-value `Add` entry for a client of `user`.
fn add_of(user: &str) -> Vec<u8> {
    [vec![1, 0, 1], real_keypackage_for(user.as_bytes())].concat()
}

/// One by-value `Remove` entry of leaf `leaf`.
fn remove_of(leaf: u32) -> Vec<u8> {
    [vec![1, 0, 3], leaf.to_be_bytes().to_vec()].concat()
}

/// One by-value `GroupContextExtensions` entry with no extensions.
fn group_context_extensions() -> Vec<u8> {
    vec![1, 0, 7, 0]
}

fn update(added: &[&str], removed: &[u32]) -> Vec<u8> {
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

/// A real Commit whose proposals window is `before`, then the participant-list change as an AppDataUpdate, then `after`.
fn commit_around(payload: &[u8], before: &[Vec<u8>], after: &[Vec<u8>]) -> Vec<u8> {
    let real =
        real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, payload.to_vec());
    let sent = as_app_data_update(&real, payload, 0x0022);
    let entry = [
        vec![0x01, 0x00, 0x08],
        0x0022u16.to_be_bytes().to_vec(),
        vec![0x01],
        vl(payload),
    ]
    .concat();
    let found = [length_prefix(entry.len()), entry.clone()].concat();
    let at = sent
        .windows(found.len())
        .position(|w| w == found.as_slice())
        .expect("the window of the one AppDataUpdate");
    let window = [before.concat(), entry, after.concat()].concat();
    [
        &sent[..at],
        &length_prefix(window.len()),
        &window,
        &sent[at + found.len()..],
    ]
    .concat()
}

async fn answer_of(commit: Vec<u8>) -> (UpdateRoomResponse, SharedProvider) {
    let (router, p) = app();
    room(&p);
    let answer = update_answer(post(router, ROOM, bundle_of(commit)).await).await;
    (answer, p)
}

fn is_success(answer: &UpdateRoomResponse) -> bool {
    matches!(answer, UpdateRoomResponse::Success { .. })
}

fn is_invalid(answer: &UpdateRoomResponse) -> bool {
    matches!(answer, UpdateRoomResponse::InvalidProposal { .. })
}

/// -07 §3.2: the Add of the user's client and the list change that names the user, in either order.
#[tokio::test]
async fn an_add_and_the_list_change_that_names_its_user_are_applied_in_either_order() {
    for (before, after) in [(vec![add_of(CAROL)], vec![]), (vec![], vec![add_of(CAROL)])] {
        let commit = commit_around(&update(&[CAROL], &[]), &before, &after);
        let (answer, p) = answer_of(commit).await;
        assert!(is_success(&answer), "{answer:?}");
        assert!(listed(&p).contains(&CAROL.to_string()));
    }
}

#[tokio::test]
async fn a_second_device_of_a_listed_user_and_a_new_user_come_in_one_commit() {
    let commit = commit_around(&update(&[CAROL], &[]), &[add_of(BOB), add_of(CAROL)], &[]);
    let (answer, p) = answer_of(commit).await;
    assert!(is_success(&answer), "{answer:?}");
    assert!(listed(&p).contains(&CAROL.to_string()));
}

#[tokio::test]
async fn an_add_for_a_user_who_is_neither_listed_nor_added_is_refused_and_changes_nothing() {
    let commit = commit_around(&update(&[CAROL], &[]), &[add_of(CAROL), add_of(DAVE)], &[]);
    let (answer, p) = answer_of(commit).await;
    assert!(is_invalid(&answer), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE.to_string(), BOB.to_string()]);
}

#[tokio::test]
async fn an_added_user_with_no_add_beside_other_adds_is_refused_and_changes_nothing() {
    let commit = commit_around(&update(&[CAROL], &[]), &[add_of(BOB)], &[]);
    let (answer, p) = answer_of(commit).await;
    assert!(is_invalid(&answer), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE.to_string(), BOB.to_string()]);
}

/// The list change alone, as before: a participant can be listed before any client is added.
#[tokio::test]
async fn the_change_alone_is_read_as_it_always_was() {
    let (answer, p) = answer_of(commit_around(&update(&[CAROL], &[]), &[], &[])).await;
    assert!(is_success(&answer), "{answer:?}");
    assert!(listed(&p).contains(&CAROL.to_string()));
}

/// A removed user needs a Remove beside it; which leaf is that user's is not checkable here (no ratchet tree).
#[tokio::test]
async fn a_removed_user_needs_a_remove_and_a_remove_alone_is_a_device() {
    let with_remove = commit_around(&update(&[], &[1]), &[], &[remove_of(1)]);
    let (answer, p) = answer_of(with_remove).await;
    assert!(is_success(&answer), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE.to_string()]);
    // The list removes a user, and the Commit removes no leaf beside an Add: not the same Commit.
    let without = commit_around(&update(&[], &[1]), &[add_of(ALICE)], &[]);
    let (answer, p) = answer_of(without).await;
    assert!(is_invalid(&answer), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE.to_string(), BOB.to_string()]);
    // A Remove with no removed user: one device of a listed user leaves.
    let device = commit_around(&update(&[CAROL], &[]), &[add_of(CAROL)], &[remove_of(3)]);
    let (answer, _) = answer_of(device).await;
    assert!(is_success(&answer), "{answer:?}");
}

/// A proposal this hub has no rule for stays refused, whichever side of the change it is on.
#[tokio::test]
async fn any_other_standard_proposal_beside_the_change_is_still_refused() {
    for (before, after) in [
        (vec![group_context_extensions()], vec![]),
        (vec![], vec![group_context_extensions()]),
        (vec![add_of(CAROL)], vec![group_context_extensions()]),
    ] {
        let commit = commit_around(&update(&[CAROL], &[]), &before, &after);
        let (answer, p) = answer_of(commit).await;
        assert!(is_invalid(&answer), "{answer:?}");
        assert_eq!(listed(&p), vec![ALICE.to_string(), BOB.to_string()]);
    }
}

#[tokio::test]
async fn a_second_change_in_one_commit_is_refused() {
    let second = [vec![1, 0xF7, 0xA0], vl(&update(&[DAVE], &[]))].concat();
    let commit = commit_around(&update(&[CAROL], &[]), &[add_of(CAROL)], &[second]);
    let (answer, p) = answer_of(commit).await;
    assert!(is_invalid(&answer), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE.to_string(), BOB.to_string()]);
}

/// An Add whose KeyPackage the gate refuses (here: under another ciphersuite) refuses the whole Commit.
#[tokio::test]
async fn an_add_the_gate_refuses_refuses_the_commit_and_changes_nothing() {
    let mut key_package = real_keypackage_for(CAROL.as_bytes());
    key_package[2..4].copy_from_slice(&[0x00, 0x02]);
    let foreign = [vec![1, 0, 1], key_package].concat();
    let commit = commit_around(&update(&[CAROL], &[]), &[foreign], &[]);
    let (answer, p) = answer_of(commit).await;
    assert!(
        matches!(answer, UpdateRoomResponse::NotAllowed { .. }),
        "{answer:?}"
    );
    assert_eq!(listed(&p), vec![ALICE.to_string(), BOB.to_string()]);
}
