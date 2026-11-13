//! `update` with a member leaving (-07 §3.5, "Bob Leaves the Room"): the leaving client sends its Remove and a
//! participant-list change removing its user as proposals; the hub holds them, and the next Commit at that epoch must
//! include them by reference (RFC 9420 §12.4: proposals from another member go in by reference). The hub verifies no
//! proposal's signature, so what it holds is bounded by who sent it: the peer's certificate must authenticate the provider
//! of every user removed, and proposals are of the room's current epoch, bounded in count, size and time. Every refusal
//! leaves the room as it was.

use axum::body::Body;
use axum::http::Request;
use axum::{Extension, Router};
use mimi_core::commit_wire::decode_proposal_message;
use mimi_core::participant_list::{
    encode_participant_list_update, ParticipantListUpdate, UserRolePair,
    MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
};
use mimi_core::protocol_wire::{HandshakeBundle, UpdateRoomResponse};
use tower::ServiceExt;

use super::tests::{app, bundle_of, real_single_custom_proposal_commit, update_answer};
use super::update_tests::{as_app_data_update, ROOM};
use crate::http::SharedProvider;
use crate::peer::{PeerCert, PeerIdentity};
use crate::store::{MAX_PENDING_PROPOSALS_PER_ROOM, PROPOSAL_TTL_SECS};
use crate::tls::certs_from_pem;
use crate::tls::tests::{issue, make_ca};
use crate::UpdateRefusal;

const HOME: &str = "havenmessenger.com";
const OTHER: &str = "other.example";
const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const CAROL: &str = "mimi://other.example/u/carol";
/// Bob's index in the participants vector, and his device's leaf.
const BOB_AT: u32 = 1;
const CAROL_AT: u32 = 2;

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

/// A peer whose certificate is valid for `domain`.
fn identity_for(domain: &str) -> PeerIdentity {
    let (ca, _ca_pem) = make_ca();
    let (cert_pem, _key) = issue(&ca, vec![domain.to_string()], domain);
    let chain = certs_from_pem(cert_pem.as_bytes()).unwrap();
    PeerIdentity::new(chain[0].clone().into_owned())
}

async fn post_from(router: Router, peer: Option<&str>, body: Vec<u8>) -> UpdateRoomResponse {
    let router = match peer {
        Some(domain) => router.layer(Extension(PeerCert(Some(identity_for(domain))))),
        None => router,
    };
    let path = format!(
        "/mimi/pl/update/{}",
        ROOM.replace(':', "%3A").replace('/', "%2F")
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    update_answer(response).await
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

/// A member-sent PublicMessage proposal at `epoch` from leaf `sender`, signed with `signature` bytes.
fn proposal_with(epoch: u64, sender: u32, body: &[u8], signature: &[u8]) -> Vec<u8> {
    [
        1u16.to_be_bytes().to_vec(),
        1u16.to_be_bytes().to_vec(),
        vl(b"group"),
        epoch.to_be_bytes().to_vec(),
        vec![1],
        sender.to_be_bytes().to_vec(),
        vl(b""),
        vec![2],
        body.to_vec(),
        vl(signature),
        vl(&[8; 32]),
    ]
    .concat()
}

fn remove_body(leaf: u32) -> Vec<u8> {
    [
        0x0003u16.to_be_bytes().to_vec(),
        leaf.to_be_bytes().to_vec(),
    ]
    .concat()
}

/// A Remove of `leaf` sent by `sender`.
fn remove(epoch: u64, sender: u32, leaf: u32) -> Vec<u8> {
    proposal_with(epoch, sender, &remove_body(leaf), &[9; 64])
}

/// The participant-list change as an AppDataUpdate proposal for component 0x0022, sent by `sender`.
fn change(epoch: u64, sender: u32, update: &[u8]) -> Vec<u8> {
    proposal_with(
        epoch,
        sender,
        &[
            0x0008u16.to_be_bytes().to_vec(),
            0x0022u16.to_be_bytes().to_vec(),
            vec![1],
            vl(update),
        ]
        .concat(),
        &[9; 64],
    )
}

fn reference_of(message: &[u8]) -> Vec<u8> {
    decode_proposal_message(message).unwrap().reference
}

fn bundle(messages: &[Vec<u8>]) -> Vec<u8> {
    HandshakeBundle::Proposal {
        proposal_or_commit: messages[0].clone(),
        more_proposals: messages[1..].to_vec(),
    }
    .encode()
    .unwrap()
}

fn by_reference(reference: &[u8]) -> Vec<u8> {
    [vec![2], vl(reference)].concat()
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

/// A real Commit at `epoch` whose proposals window is `entries`. The epoch is written into a real openmls Commit; the
/// hub verifies no signature, so the Commit is read as sent.
fn commit_of(epoch: u64, entries: &[Vec<u8>]) -> Vec<u8> {
    let payload = list_change(&[], &[]);
    let real =
        real_single_custom_proposal_commit(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, payload.clone());
    let sent = as_app_data_update(&real, &payload, 0x0022);
    let entry = by_value_change(&payload);
    let found = [length_prefix(entry.len()), entry].concat();
    let at = sent
        .windows(found.len())
        .position(|w| w == found.as_slice())
        .expect("the window of the one AppDataUpdate");
    let window = entries.concat();
    let mut commit = [
        &sent[..at],
        &length_prefix(window.len()),
        &window,
        &sent[at + found.len()..],
    ]
    .concat();
    // version, wire format, then the group id<V>: a varint whose top two bits give its own length.
    let prefix = 1usize << (commit[4] >> 6);
    let mut length = usize::from(commit[4] & 0x3f);
    for byte in &commit[5..4 + prefix] {
        length = (length << 8) | usize::from(*byte);
    }
    let epoch_at = 4 + prefix + length;
    commit[epoch_at..epoch_at + 8].copy_from_slice(&epoch.to_be_bytes());
    commit
}

fn participants(p: &SharedProvider) {
    for user in [ALICE, BOB, CAROL] {
        p.lock().unwrap().add_participant(ROOM, user, 1).unwrap();
    }
}

/// A room of Alice and Bob here and Carol at another provider, whose latest accepted Commit was at epoch 0: the next
/// Commit, and any leave, is at epoch 1.
async fn room() -> (Router, SharedProvider) {
    let (router, p) = app();
    participants(&p);
    let first = commit_of(0, &[by_value_change(&list_change(&[], &[]))]);
    let answer = post_from(router.clone(), None, bundle_of(first)).await;
    assert!(is_success(&answer), "{answer:?}");
    (router, p)
}

/// Bob's leave at epoch 1: his device's Remove of itself and the change removing him.
fn bobs_leave() -> (Vec<Vec<u8>>, Vec<u8>, Vec<u8>) {
    let own_remove = remove(1, BOB_AT, BOB_AT);
    let own_change = change(1, BOB_AT, &list_change(&[], &[BOB_AT]));
    let refs = (reference_of(&own_remove), reference_of(&own_change));
    (vec![own_remove, own_change], refs.0, refs.1)
}

fn is_success(answer: &UpdateRoomResponse) -> bool {
    matches!(answer, UpdateRoomResponse::Success { .. })
}

fn is_not_allowed(answer: &UpdateRoomResponse) -> bool {
    matches!(answer, UpdateRoomResponse::NotAllowed { .. })
}

fn invalid_refs(answer: &UpdateRoomResponse) -> Option<Vec<Vec<u8>>> {
    match answer {
        UpdateRoomResponse::InvalidProposal {
            invalid_proposals, ..
        } => Some(invalid_proposals.clone()),
        _ => None,
    }
}

/// -07 §3.5: Bob's proposals are held, not applied; Alice's next Commit includes them by reference and Bob leaves. The
/// same proposals sent again after that Commit are refused. Revert check: refuse a bundle of proposals, or a proposal by
/// reference, and Bob stays listed.
#[tokio::test]
async fn a_member_leaves_through_proposals_the_next_commit_includes_by_reference() {
    let (router, p) = room().await;
    let (messages, own_remove, own_change) = bobs_leave();
    let held = post_from(router.clone(), Some(HOME), bundle(&messages)).await;
    assert!(is_success(&held), "{held:?}");
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
    let commit = commit_of(1, &[by_reference(&own_remove), by_reference(&own_change)]);
    let answer = post_from(router.clone(), None, bundle_of(commit)).await;
    assert!(is_success(&answer), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE, CAROL]);
    // Replayed after the Commit, the same bytes are refused: index 1 is Carol's now, another provider's user, and the
    // room is at epoch 2. Nothing changes.
    let replay = post_from(router.clone(), Some(HOME), bundle(&messages)).await;
    assert!(is_not_allowed(&replay), "{replay:?}");
    assert_eq!(listed(&p), vec![ALICE, CAROL]);
    // What was held went with the Commit that included it: a later Commit names nothing and goes.
    let later = commit_of(2, &[by_value_change(&list_change(&[BOB], &[]))]);
    assert!(is_success(&post_from(router, None, bundle_of(later)).await));
}

/// -07 §3.5 step 1: the leaving client proposes the removal of all its user's devices, itself included. One client of
/// Bob's, at leaf 1, sends Removes for leaves 1 and 3 with the list change; the next Commit includes all three and Bob
/// leaves. Revert check: hold only a Remove of its own sender and the leave is refused.
#[tokio::test]
async fn one_client_leaves_for_every_device_of_its_user() {
    let (router, p) = room().await;
    let messages = vec![
        remove(1, BOB_AT, BOB_AT),
        remove(1, BOB_AT, 3),
        change(1, BOB_AT, &list_change(&[], &[BOB_AT])),
    ];
    let held = post_from(router.clone(), Some(HOME), bundle(&messages)).await;
    assert!(is_success(&held), "{held:?}");
    let refs: Vec<Vec<u8>> = messages
        .iter()
        .map(|m| by_reference(&reference_of(m)))
        .collect();
    let answer = post_from(router, None, bundle_of(commit_of(1, &refs))).await;
    assert!(is_success(&answer), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE, CAROL]);
}

/// A room the hub has not yet seen a Commit for (one founded before the hub learned its epoch) takes a leave at the
/// leave's own epoch, and the next Commit at that epoch must include it. Revert check: refuse a leave until the hub knows
/// the room's epoch and the leave is refused.
#[tokio::test]
async fn a_room_the_hub_saw_no_commit_for_takes_a_leave_at_its_own_epoch() {
    let (router, p) = app();
    participants(&p);
    let (messages, own_remove, own_change) = bobs_leave();
    let held = post_from(router.clone(), Some(HOME), bundle(&messages)).await;
    assert!(is_success(&held), "{held:?}");
    let leaves_it_out = commit_of(1, &[by_value_change(&list_change(&[], &[CAROL_AT]))]);
    let answer = post_from(router.clone(), None, bundle_of(leaves_it_out)).await;
    assert!(invalid_refs(&answer).is_some(), "{answer:?}");
    let includes_it = commit_of(1, &[by_reference(&own_remove), by_reference(&own_change)]);
    let answer = post_from(router, None, bundle_of(includes_it)).await;
    assert!(is_success(&answer), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE, CAROL]);
}

/// The epoch the hub learned for a room lives in the store with the room, so it survives a restart: a leave after one is
/// held to the same epoch. Revert check: keep the epoch in memory and the reopened store knows none.
#[test]
fn the_learned_epoch_survives_reopening_the_store() {
    let dir = std::env::temp_dir().join(format!("mimi-hubd-epoch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    let path = path.to_str().unwrap();
    {
        let store = crate::store::SqliteStore::open(path).unwrap();
        store.commit_accepted_at(ROOM, 4).unwrap();
    }
    let reopened = crate::store::SqliteStore::open(path).unwrap();
    assert_eq!(reopened.room_epoch(ROOM).unwrap(), Some(5));
    drop(reopened);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A leave sent again after the Commit that included it, by the provider that may send it, is of an epoch the room has
/// moved past: `wrongEpoch`, naming the room's epoch, and nothing is held. Revert check: drop the epoch check and the
/// replay is held for the room's next Commit.
#[tokio::test]
async fn a_leave_replayed_after_its_commit_is_of_a_past_epoch() {
    let (router, p) = room().await;
    let carol_leaves = vec![
        remove(1, CAROL_AT, CAROL_AT),
        change(1, CAROL_AT, &list_change(&[], &[CAROL_AT])),
    ];
    let refs: Vec<Vec<u8>> = carol_leaves.iter().map(|m| reference_of(m)).collect();
    assert!(is_success(
        &post_from(router.clone(), Some(OTHER), bundle(&carol_leaves)).await
    ));
    let commit = commit_of(1, &refs.iter().map(|r| by_reference(r)).collect::<Vec<_>>());
    assert!(is_success(
        &post_from(router.clone(), None, bundle_of(commit)).await
    ));
    assert_eq!(listed(&p), vec![ALICE, BOB]);
    // Carol is listed again, at index 2, and her old leave comes back.
    let back = commit_of(2, &[by_value_change(&list_change(&[CAROL], &[]))]);
    assert!(is_success(
        &post_from(router.clone(), None, bundle_of(back)).await
    ));
    let replay = post_from(router.clone(), Some(OTHER), bundle(&carol_leaves)).await;
    assert!(
        matches!(
            replay,
            UpdateRoomResponse::WrongEpoch {
                current_epoch: 3,
                ..
            }
        ),
        "{replay:?}"
    );
    let next = commit_of(3, &[by_value_change(&list_change(&[], &[]))]);
    assert!(is_success(&post_from(router, None, bundle_of(next)).await));
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}

/// The hub requires the next Commit to include what it holds: one that leaves a held proposal out is refused, naming
/// it, and nothing changes. Revert check: skip the left-out check and Carol is removed while Bob stays.
#[tokio::test]
async fn a_commit_that_leaves_out_a_held_proposal_is_refused_naming_it() {
    let (router, p) = room().await;
    let (messages, own_remove, own_change) = bobs_leave();
    assert!(is_success(
        &post_from(router.clone(), Some(HOME), bundle(&messages)).await
    ));
    let other = commit_of(1, &[by_value_change(&list_change(&[], &[CAROL_AT]))]);
    let answer = post_from(router.clone(), None, bundle_of(other)).await;
    assert_eq!(
        invalid_refs(&answer),
        Some(vec![own_remove.clone(), own_change])
    );
    let half = commit_of(1, &[by_reference(&own_remove)]);
    let answer = post_from(router, None, bundle_of(half)).await;
    assert!(
        invalid_refs(&answer).is_some_and(|refs| refs.len() == 1),
        "{answer:?}"
    );
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}

/// A reference to nothing the hub holds for the Commit's epoch is refused, naming it; so is one named twice.
#[tokio::test]
async fn a_reference_the_hub_holds_nothing_for_is_refused_naming_it() {
    let (router, p) = room().await;
    let unknown = vec![7u8; 32];
    let commit = commit_of(
        1,
        &[
            by_value_change(&list_change(&[], &[CAROL_AT])),
            by_reference(&unknown),
        ],
    );
    let answer = post_from(router.clone(), None, bundle_of(commit)).await;
    assert_eq!(invalid_refs(&answer), Some(vec![unknown]));
    let (messages, own_remove, own_change) = bobs_leave();
    assert!(is_success(
        &post_from(router.clone(), Some(HOME), bundle(&messages)).await
    ));
    let twice = commit_of(
        1,
        &[
            by_reference(&own_remove),
            by_reference(&own_change),
            by_reference(&own_remove),
        ],
    );
    let answer = post_from(router, None, bundle_of(twice)).await;
    assert_eq!(invalid_refs(&answer), Some(vec![own_remove]));
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}

/// A provider can have the hub hold the removal only of its own users: removing another provider's user is refused as
/// notAllowed, from either side, and so is a leave with no certificate. Revert check: drop the provider check and Carol's
/// removal is held for her room's next Commit by a peer that is not her provider.
#[tokio::test]
async fn a_provider_cannot_have_the_hub_hold_the_removal_of_another_providers_member() {
    let (router, p) = room().await;
    let carol_leaves = vec![
        remove(1, CAROL_AT, CAROL_AT),
        change(1, CAROL_AT, &list_change(&[], &[CAROL_AT])),
    ];
    let bob_leaves = bobs_leave().0;
    for (peer, messages) in [
        (Some(HOME), carol_leaves.clone()),
        (Some(OTHER), bob_leaves.clone()),
        (None, bob_leaves),
    ] {
        let answer = post_from(router.clone(), peer, bundle(&messages)).await;
        assert!(is_not_allowed(&answer), "{peer:?}: {answer:?}");
    }
    // Nothing was held: a Commit at that epoch names nothing and goes.
    let commit = commit_of(1, &[by_value_change(&list_change(&[], &[]))]);
    assert!(is_success(
        &post_from(router.clone(), None, bundle_of(commit)).await
    ));
    // Carol's own provider may hold her leave.
    let carol_leaves = vec![
        remove(2, CAROL_AT, CAROL_AT),
        change(2, CAROL_AT, &list_change(&[], &[CAROL_AT])),
    ];
    let from_there = post_from(router, Some(OTHER), bundle(&carol_leaves)).await;
    assert!(is_success(&from_there), "{from_there:?}");
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}

/// Proposals are taken only of the room's current epoch, and only as a leave: a change that adds, Removes with no change,
/// or two changes are refused. A held change beside a change sent by value is a second change.
#[tokio::test]
async fn proposals_of_another_epoch_or_that_are_not_a_leave_are_refused() {
    let (router, p) = room().await;
    let stale = [
        remove(0, BOB_AT, BOB_AT),
        change(0, BOB_AT, &list_change(&[], &[BOB_AT])),
    ];
    let answer = post_from(router.clone(), Some(HOME), bundle(&stale)).await;
    assert!(
        matches!(
            answer,
            UpdateRoomResponse::WrongEpoch {
                current_epoch: 1,
                ..
            }
        ),
        "{answer:?}"
    );
    let adds = vec![change(1, BOB_AT, &list_change(&[BOB], &[]))];
    let removes_alone = vec![remove(1, BOB_AT, BOB_AT)];
    let two_changes = vec![
        change(1, BOB_AT, &list_change(&[], &[BOB_AT])),
        change(1, BOB_AT, &list_change(&[], &[BOB_AT])),
    ];
    for refused in [adds, removes_alone, two_changes] {
        let answer = post_from(router.clone(), Some(HOME), bundle(&refused)).await;
        assert!(invalid_refs(&answer).is_some(), "{answer:?}");
    }
    let (messages, own_remove, own_change) = bobs_leave();
    assert!(is_success(
        &post_from(router.clone(), Some(HOME), bundle(&messages)).await
    ));
    let beside = commit_of(
        1,
        &[
            by_value_change(&list_change(&[], &[CAROL_AT])),
            by_reference(&own_remove),
            by_reference(&own_change),
        ],
    );
    let answer = post_from(router, None, bundle_of(beside)).await;
    assert!(invalid_refs(&answer).is_some(), "{answer:?}");
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}

/// A room holds at most a bounded count and size of proposals, and one message past what a leave needs is refused:
/// each is notAllowed saying so, and nothing more is held. Revert check: drop the room's byte bound and the large
/// leaves are held.
#[tokio::test]
async fn a_flood_of_proposals_is_refused_saying_so() {
    let (router, p) = room().await;
    let limit = |answer: &UpdateRoomResponse| {
        matches!(answer, UpdateRoomResponse::NotAllowed { error_description }
            if error_description != &UpdateRefusal::NotAllowed.to_string())
    };
    // One message past a leave's size.
    let big = vec![
        proposal_with(1, BOB_AT, &remove_body(BOB_AT), &[9; 5000]),
        change(1, BOB_AT, &list_change(&[], &[BOB_AT])),
    ];
    let answer = post_from(router.clone(), Some(HOME), bundle(&big)).await;
    assert!(limit(&answer), "{answer:?}");
    // More Removes than a room can hold.
    let count = u32::try_from(MAX_PENDING_PROPOSALS_PER_ROOM).unwrap() + 1;
    let mut many: Vec<Vec<u8>> = (0..count).map(|leaf| remove(1, leaf, leaf)).collect();
    many.push(change(1, BOB_AT, &list_change(&[], &[BOB_AT])));
    let answer = post_from(router.clone(), Some(HOME), bundle(&many)).await;
    assert!(limit(&answer), "{answer:?}");
    // Messages that fit one by one but not together in the room's bytes.
    let mut large: Vec<Vec<u8>> = (0..20)
        .map(|leaf| proposal_with(1, leaf, &remove_body(leaf), &[9; 3900]))
        .collect();
    large.push(change(1, BOB_AT, &list_change(&[], &[BOB_AT])));
    let answer = post_from(router.clone(), Some(HOME), bundle(&large)).await;
    assert!(limit(&answer), "{answer:?}");
    // Nothing was held: a Commit at that epoch names nothing and goes.
    let commit = commit_of(1, &[by_value_change(&list_change(&[], &[]))]);
    assert!(is_success(
        &post_from(router, None, bundle_of(commit)).await
    ));
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}

/// A held proposal binds the room's next Commit only for a while: once it expires, a Commit need not include it and
/// cannot name it. Revert check: read held proposals without their age and the Commit that leaves it out is refused.
#[tokio::test]
async fn a_held_proposal_expires() {
    let (_router, p) = room().await;
    let (messages, own_remove, _own_change) = bobs_leave();
    let identity = identity_for(HOME);
    let now = 4_000_000_000;
    p.lock()
        .unwrap()
        .apply_update_request(ROOM, &bundle(&messages), Some(&identity), now)
        .unwrap();
    let later = now + PROPOSAL_TTL_SECS + 1;
    let names_it = commit_of(1, &[by_reference(&own_remove)]);
    assert!(matches!(
        p.lock()
            .unwrap()
            .apply_update_request(ROOM, &bundle_of(names_it), None, later),
        Err(UpdateRefusal::InvalidProposals(_, _))
    ));
    let leaves_it_out = commit_of(1, &[by_value_change(&list_change(&[], &[]))]);
    p.lock()
        .unwrap()
        .apply_update_request(ROOM, &bundle_of(leaves_it_out), None, later)
        .unwrap();
    assert_eq!(listed(&p), vec![ALICE, BOB, CAROL]);
}
