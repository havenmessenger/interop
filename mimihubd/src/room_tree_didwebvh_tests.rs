//! A tracked room whose members carry did_webvh credentials: the hub reads each member's user from its credential and
//! leaf key, through the seed and a Commit, and holds the room to the draft's group rules
//! (draft-atwood-mls-didwebvh-credential §Group Consistency Rules).

use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
use openmls::prelude::{Extension, Extensions, ExternalSender, MlsGroup, SignaturePublicKey};

use super::*;
use crate::didwebvh_fixtures::{
    app_components, commit, commit_welcoming, dictionary, group, head_of, heads, join, log,
    mls_credential, record, required, Change, APP_COMPONENTS,
};
use crate::mls_fixtures::Member;
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
    bob: Member,
    group: MlsGroup,
    group_info: Vec<u8>,
    tree: Vec<u8>,
}

/// Alice's group with Bob added in its first Commit, both with did_webvh credentials naming their URIs, the record
/// holding both heads.
fn room() -> Room {
    let alice = Member::did_webvh(ALICE, "alice");
    let bob = Member::did_webvh(BOB, "bob");
    let mut group = group(&alice, GROUP);
    let (_commit, group_info, tree) = commit(
        &mut group,
        &alice,
        Change {
            adds: vec![&bob],
            record: Some(record([head_of(&alice), head_of(&bob)])),
            ..Change::default()
        },
    );
    Room {
        alice,
        bob,
        group,
        group_info,
        tree,
    }
}

fn hub_listing(users: &[&str]) -> Provider {
    let p = Provider::in_memory("hub.example").unwrap();
    for user in users {
        p.add_participant(ROOM, user, 1).unwrap();
    }
    p
}

fn seed(p: &Provider, group_info: &[u8], tree: &[u8]) {
    p.seed_room_tree(
        ROOM,
        0,
        Some(&PeerIdentity::signed("example.com")),
        &full(group_info),
        &[&[1u8][..], tree].concat(),
    );
}

/// Seed a hub listing `listed` with `group_info` and `tree`, and stage on it the Commit `by` makes in `group` with
/// `change`: the hub's answer.
fn stage_on(
    listed: &[&str],
    (group_info, tree): (&[u8], &[u8]),
    group: &mut MlsGroup,
    by: &Member,
    change: Change<'_>,
) -> Result<StagedRoomCommit, UpdateRefusal> {
    let p = hub_listing(listed);
    seed(&p, group_info, tree);
    assert!(p.room_tracking(ROOM).unwrap().is_some(), "the room seeds");
    let (commit, group_info, _tree) = commit(group, by, change);
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    p.stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&group_info)))
}

/// Alice's next Commit in `room`, with `change`, staged on a hub that seeded the room.
fn stage(room: &mut Room, change: Change<'_>) -> Result<StagedRoomCommit, UpdateRefusal> {
    let Room {
        alice,
        group,
        group_info,
        tree,
        ..
    } = room;
    stage_on(&[ALICE, BOB], (group_info, tree), group, alice, change)
}

/// The refusal's reason, when the answer is one.
fn refused_for(answer: &Result<StagedRoomCommit, UpdateRefusal>) -> Option<&'static str> {
    match answer {
        Err(UpdateRefusal::Invalid(why)) => Some(why),
        _ => None,
    }
}

/// A tree of did_webvh members seeds the room when the users their credentials name are the ones it lists and the
/// record holds their heads. Revert check: read no user from a did_webvh credential, and the room is not tracked.
#[test]
fn a_room_of_did_webvh_members_seeds_by_the_users_their_logs_name() {
    let p = hub_listing(&[ALICE, BOB]);
    let room = room();
    seed(&p, &room.group_info, &room.tree);
    assert!(
        p.room_tracking(ROOM).unwrap().is_some(),
        "PLANT-DIDWEBVH-ROOM: a tree of did_webvh members naming the listed users did not seed"
    );
}

/// A did_webvh member whose log names a user the room does not list keeps the room from seeding, as a Basic one would.
#[test]
fn a_did_webvh_member_of_an_unlisted_user_does_not_seed() {
    let p = hub_listing(&[ALICE, "mimi://example.com/u/robert"]);
    let room = room();
    seed(&p, &room.group_info, &room.tree);
    assert!(p.room_tracking(ROOM).unwrap().is_none());
}

/// A seed whose record has no entry for an SCID in its tree does not seed ("`did_webvh_heads` has an entry for each SCID
/// in the tree"). Revert check: skip the seed's rules, and it seeds.
#[test]
fn a_seed_whose_record_misses_a_member_does_not_seed() {
    let alice = Member::did_webvh(ALICE, "alice");
    let bob = Member::did_webvh(BOB, "bob");
    let mut group = group(&alice, GROUP);
    let (_commit, group_info, tree) = commit(
        &mut group,
        &alice,
        Change {
            adds: vec![&bob],
            ..Change::default()
        },
    );
    let p = hub_listing(&[ALICE, BOB]);
    seed(&p, &group_info, &tree);
    assert!(
        p.room_tracking(ROOM).unwrap().is_none(),
        "PLANT-DIDWEBVH-SEED: a seed whose record lacks a member's SCID seeded"
    );
}

/// A Commit adding a did_webvh member with the record raised to its head stages, and the hub reads the added client's
/// user from its KeyPackage's credential and key.
#[test]
fn a_commit_adding_a_did_webvh_member_with_its_head_is_taken() {
    let mut room = room();
    let carol = Member::did_webvh(CAROL, "carol");
    let raised = record([head_of(&room.alice), head_of(&room.bob), head_of(&carol)]);
    let staged = stage(
        &mut room,
        Change {
            adds: vec![&carol],
            record: Some(raised),
            ..Change::default()
        },
    )
    .expect("an Add with its record update is taken");
    let view = staged
        .list_and_leaves(
            vec![(ALICE.to_string(), 1), (BOB.to_string(), 1)],
            vec![ALICE.to_string(), BOB.to_string(), CAROL.to_string()],
        )
        .unwrap();
    assert_eq!(view.added, vec![Some(CAROL.to_string())]);
}

/// An Add of a did_webvh member that leaves the record as it was is refused: the record must hold exactly the expected
/// entries (§Rules, Record matches). openmls takes the Commit; the rule is the hub's to check. Revert check: skip the
/// rules, and it stages.
#[test]
fn an_add_without_its_record_update_is_refused() {
    let mut room = room();
    let carol = Member::did_webvh(CAROL, "carol");
    let answer = stage(
        &mut room,
        Change {
            adds: vec![&carol],
            ..Change::default()
        },
    );
    assert!(
        refused_for(&answer).is_some_and(|why| why.contains("Record matches")),
        "PLANT-DIDWEBVH-RECORD: {:?}",
        answer.err()
    );
}

/// An AppDataUpdate removing the record is refused: "an AppDataUpdate proposal for `did_webvh_heads` whose `op` is
/// `remove` is invalid". Revert check: let the resolver take a removal, and it is not refused for it.
#[test]
fn removing_the_record_is_refused() {
    let mut room = room();
    let answer = stage(
        &mut room,
        Change {
            remove_record: true,
            ..Change::default()
        },
    );
    assert!(
        refused_for(&answer).is_some_and(|why| why.contains("never removed")),
        "PLANT-DIDWEBVH-REMOVE: {:?}",
        answer.err()
    );
}

/// A group whose members implement the record but whose GroupContext `app_components` does not name it does not seed:
/// "A group whose tree contains a `did_webvh` credential MUST carry the component, and its GroupContext `app_components`
/// list MUST name it". (After the seed the list cannot lose it: the hub resolves no update to `app_components`, and
/// openmls refuses a GroupContextExtensions proposal that changes the dictionary.) Revert check: skip the check, and
/// the room seeds.
#[test]
fn a_seed_whose_app_components_do_not_name_the_record_does_not_seed() {
    let alice = Member::did_webvh(ALICE, "alice");
    let bob = Member::did_webvh(BOB, "bob");
    let mut group = crate::didwebvh_fixtures::group_with(
        &alice,
        GROUP,
        &[
            (APP_COMPONENTS, app_components(&[])),
            (heads(), record([head_of(&alice)])),
        ],
    );
    let (_commit, group_info, tree) = commit(
        &mut group,
        &alice,
        Change {
            adds: vec![&bob],
            record: Some(record([head_of(&alice), head_of(&bob)])),
            ..Change::default()
        },
    );
    let p = hub_listing(&[ALICE, BOB]);
    seed(&p, &group_info, &tree);
    assert!(
        p.room_tracking(ROOM).unwrap().is_none(),
        "PLANT-DIDWEBVH-APP-COMPONENTS: a seed whose app_components lack the record seeded"
    );
}

/// The record cannot be dropped or changed by a GroupContextExtensions proposal: openmls refuses one that changes the
/// app data dictionary (the dictionary changes by AppDataUpdate alone, mls-extensions §4.7), which is why the record's
/// removal is refused at the resolver instead.
#[test]
fn the_dictionary_is_not_changed_by_group_context_extensions() {
    use openmls_traits::OpenMlsProvider as _;
    let room = room();
    let mut group = room.group;
    let built = group
        .commit_builder()
        .propose_group_context_extensions(
            Extensions::from_vec(vec![
                required(),
                dictionary(&[(APP_COMPONENTS, app_components(&[heads()]))]),
            ])
            .unwrap(),
        )
        .unwrap()
        .load_psks(room.alice.provider.storage())
        .unwrap()
        .build(
            room.alice.provider.rand(),
            room.alice.provider.crypto(),
            &room.alice.signer,
            |_| true,
        );
    assert!(
        built.is_err(),
        "openmls built a Commit changing the dictionary by GroupContextExtensions"
    );
}

/// A did_webvh credential among the external senders is refused ("A `did_webvh` credential MUST NOT appear in the
/// `external_senders` GroupContext extension"). Revert check: skip the check, and the Commit stages.
#[test]
fn a_did_webvh_external_sender_is_refused() {
    let mut room = room();
    let outsider = log(
        "outsider",
        9,
        &[[0x33; 32]],
        &["mimi://example.com/u/outsider"],
    );
    let sender = ExternalSender::new(
        SignaturePublicKey::from(vec![0x33; 32]),
        mls_credential(&outsider.credential().unwrap()),
    );
    let mut extensions = room.group.extensions().clone();
    extensions
        .add_or_replace(Extension::ExternalSenders(vec![sender]))
        .unwrap();
    let answer = stage(
        &mut room,
        Change {
            extensions: Some(extensions),
            ..Change::default()
        },
    );
    assert!(
        refused_for(&answer).is_some_and(|why| why.contains("external sender")),
        "PLANT-DIDWEBVH-EXTERNAL-SENDER: {:?}",
        answer.err()
    );
}

/// Bob's two devices, one log listing both, in Alice's group with Alice; the record holds their heads.
struct TwoDevices {
    alice: Member,
    bob1: Member,
    /// Bob's first device's own group, joined from the Welcome.
    group: MlsGroup,
    group_info: Vec<u8>,
    tree: Vec<u8>,
    bob_log: mls_didwebvh::controller::DidLog,
}

fn two_devices() -> TwoDevices {
    let alice = Member::did_webvh(ALICE, "alice");
    let mut bob1 = Member::new(BOB);
    let mut bob2 = Member::new(BOB);
    let key = |m: &Member| -> mls_didwebvh::PublicKey {
        m.credential.signature_key.as_slice().try_into().unwrap()
    };
    let bob_log = log("bob", 0x0b, &[key(&bob1), key(&bob2)], &[BOB]);
    let credential = mls_credential(&bob_log.credential().unwrap());
    bob1.credential.credential = credential.clone();
    bob2.credential.credential = credential;
    let mut alices = group(&alice, GROUP);
    let (_commit, group_info, tree, welcome) = commit_welcoming(
        &mut alices,
        &alice,
        Change {
            adds: vec![&bob1, &bob2],
            record: Some(record([head_of(&alice), head_of(&bob1)])),
            ..Change::default()
        },
    );
    let group = join(&bob1, welcome.unwrap(), &tree);
    TwoDevices {
        alice,
        bob1,
        group,
        group_info,
        tree,
        bob_log,
    }
}

/// Bob's second device revoked in a fresh room: his log drops its key, and his first device commits the new log in its
/// update path with the record raised to its head (§Revoking a Device), with or without the revoked device's Remove.
/// The hub's answer.
fn revoke(remove: bool) -> Result<StagedRoomCommit, UpdateRefusal> {
    let TwoDevices {
        alice,
        bob1,
        mut group,
        group_info,
        tree,
        mut bob_log,
    } = two_devices();
    let bob1_key: mls_didwebvh::PublicKey =
        bob1.credential.signature_key.as_slice().try_into().unwrap();
    bob_log
        .append(
            "2026-11-26T10:00:02Z",
            &mls_didwebvh::controller::Parameters::default(),
            &mls_didwebvh::controller::UpdateKey::from_seed(&[0x0b; 32]),
            &[bob1_key],
        )
        .unwrap();
    let raised = record([
        head_of(&alice),
        mls_didwebvh::DidWebvhHead::from_log(bob_log.verified()),
    ]);
    let new_log = mls_credential(&bob_log.credential().unwrap());
    // Alice is leaf 0, Bob's devices leaves 1 and 2, in the order the Add named them.
    stage_on(
        &[ALICE, BOB],
        (&group_info, &tree),
        &mut group,
        &bob1,
        Change {
            removes: if remove { vec![2] } else { vec![] },
            record: Some(raised),
            credential: Some(new_log),
            ..Change::default()
        },
    )
}

/// A revocation (§Revoking a Device) with the revoked device's Remove in the same Commit is taken; without it the
/// revoked leaf stays and is refused, as the recorded head no longer authorizes its key (§Rules, Authorization: "A
/// Commit that raises the recorded head of S to a version that no longer authorizes some of S's leaves therefore has to
/// remove those leaves in the same Commit"). Revert check: skip the rules, and the Commit that keeps the revoked leaf
/// stages.
#[test]
fn a_revocation_must_remove_the_revoked_device() {
    let taken = revoke(true);
    assert!(taken.is_ok(), "{:?}", taken.err());
    let refused = revoke(false);
    assert!(
        refused_for(&refused).is_some_and(|why| why.contains("Authorization")),
        "PLANT-DIDWEBVH-AUTHORIZATION: {:?}",
        refused.err()
    );
}

/// A room of Basic and did_webvh members side by side: the record holds the did_webvh members' heads only, and a Commit
/// adding a Basic member leaves it as it is.
#[test]
fn basic_and_did_webvh_members_share_a_room() {
    let mut room = room();
    let dave = Member::basic_listing_did_webvh("mimi://example.com/u/dave");
    let answer = stage(
        &mut room,
        Change {
            adds: vec![&dave],
            ..Change::default()
        },
    );
    assert!(answer.is_ok(), "{:?}", answer.err());
}

/// A room of Basic members never enters the did_webvh checks, and the hub's tree after each of its Commits is byte for
/// byte the members' own: an Add and a Remove each stage as before, with nothing to build or check for did_webvh.
#[test]
fn a_basic_room_is_not_touched_by_the_did_webvh_rules() {
    use crate::mls_fixtures::add_commit;
    let alice = Member::new(ALICE);
    let bob = Member::new(BOB);
    let carol = Member::new(CAROL);
    let mut group = alice.create_group(GROUP);
    let (_commit, group_info, tree) = add_commit(&mut group, &alice, &[&bob]);
    let p = hub_listing(&[ALICE, BOB]);
    seed(&p, &group_info, &tree);
    let step = |p: &Provider, group: &mut MlsGroup, commit: Vec<u8>, group_info: Vec<u8>| {
        let tracking = p.room_tracking(ROOM).unwrap().unwrap();
        let stored = openmls::group::PublicGroup::load(
            &p.store.groups(),
            &openmls::prelude::GroupId::from_slice(GROUP),
        )
        .unwrap()
        .unwrap();
        let staged = p
            .stage_tracked_commit(ROOM, &tracking, &commit, Some(&full(&group_info)))
            .unwrap();
        assert!(
            !crate::didwebvh_rules::may_apply(&stored, &staged.staged),
            "a Basic room's Commit is not one the did_webvh rules apply to"
        );
        p.merge_tracked_commit(staged).unwrap();
        let hub_tree = openmls::group::PublicGroup::load(
            &p.store.groups(),
            &openmls::prelude::GroupId::from_slice(GROUP),
        )
        .unwrap()
        .unwrap()
        .export_ratchet_tree();
        assert_eq!(
            hub_tree.tls_serialize_detached().unwrap(),
            group
                .export_ratchet_tree()
                .tls_serialize_detached()
                .unwrap(),
            "the hub's tree is the members' tree"
        );
    };
    let (commit, group_info, _tree) = add_commit(&mut group, &alice, &[&carol]);
    step(&p, &mut group, commit, group_info);
    let (commit, _welcome, _info) = group
        .remove_members(
            &alice.provider,
            &alice.signer,
            &[openmls::prelude::LeafNodeIndex::new(2)],
        )
        .unwrap();
    group.merge_pending_commit(&alice.provider).unwrap();
    let group_info = crate::mls_fixtures::group_info_after(&group, &alice);
    step(
        &p,
        &mut group,
        commit.tls_serialize_detached().unwrap(),
        group_info,
    );
}

/// A Commit that creates a did_webvh_heads record in a room with no did_webvh member is refused: with no leaf to
/// record, the expected record is empty (§Rules, Record matches). Revert check: look for the record before the Commit
/// only, and the record is created unchecked.
#[test]
fn a_record_created_in_a_basic_room_is_refused() {
    use crate::mls_fixtures::{add_commit, app_data_commit};
    let alice = Member::new(ALICE);
    let bob = Member::new(BOB);
    let mut group = alice.create_group(GROUP);
    let (_commit, group_info, tree) = add_commit(&mut group, &alice, &[&bob]);
    let p = hub_listing(&[ALICE, BOB]);
    seed(&p, &group_info, &tree);
    let invented =
        crate::didwebvh_fixtures::log("ghost", 7, &[[0x44; 32]], &["mimi://example.com/u/ghost"]);
    let value = record([mls_didwebvh::DidWebvhHead::from_log(invented.verified())]);
    let commit = app_data_commit(&mut group, &alice, &[(heads(), value.clone(), value)]);
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let answer = p.stage_tracked_commit(ROOM, &tracking, &commit, None);
    assert!(
        refused_for(&answer).is_some_and(|why| why.contains("Record matches")),
        "PLANT-DIDWEBVH-RECORD-CREATED: {:?}",
        answer.err()
    );
}
