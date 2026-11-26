//! What each accepted message fans out to: which providers' queues get a FanoutMessage, and which local members get the
//! message itself.

use mimi_core::protocol_wire::FanoutMessage;
use openmls::prelude::tls_codec::Serialize as _;

use crate::mls_fixtures::Member;
use crate::store::ParticipantRow;
use crate::Provider;

const ROOM: &str = "mimi://hub.example/r/room";
const ALICE: &str = "mimi://hub.example/u/alice";
const DAVE: &str = "mimi://hub.example/u/dave";
const BOB: &str = "mimi://b.example/u/bob";
const CAROL: &str = "mimi://c.example/u/carol";

fn hub_with(members: &[&str]) -> Provider {
    let p = Provider::in_memory("hub.example").unwrap();
    for member in members {
        p.add_participant(ROOM, member, 1).unwrap();
    }
    p
}

/// Each outbox row as (domain, the FanoutMessage it holds). The message is read after the 8-byte timestamp, not
/// decoded, since some tests fan out placeholder bytes.
fn queued(p: &Provider) -> Vec<(String, FanoutMessage)> {
    p.store
        .due_outbox_heads(u64::MAX, &[])
        .unwrap()
        .into_iter()
        .map(|row| {
            let fanout = FanoutMessage {
                protocol: mimi_core::protocol_wire::PROTOCOL_MLS10,
                timestamp: u64::from_be_bytes(row.body[..8].try_into().unwrap()),
                message_and_tail: row.body[8..].to_vec(),
            };
            (row.domain, fanout)
        })
        .collect()
}

fn domains(p: &Provider) -> Vec<String> {
    queued(p).into_iter().map(|(domain, _)| domain).collect()
}

/// A Commit goes to the provider of every participant before it, so the provider of a member it removed is told, and
/// to every local member's queue; its tail is an empty `externalProposals`. Revert check: fan out to the list after the
/// Commit only, and the removed member's provider is not told.
#[test]
fn a_commit_reaches_the_providers_before_it_and_the_local_members() {
    let p = hub_with(&[ALICE, BOB, CAROL]);
    let before = p.store.list_participant_rows(ROOM).unwrap();
    p.remove_participant(ROOM, CAROL).unwrap();
    let report = p
        .fan_out_commit(ROOM, b"COMMIT", None, &before, 10)
        .unwrap();
    assert_eq!(
        domains(&p),
        ["b.example", "c.example"],
        "PLANT-FANOUT-REMOVED: the removed member's provider was not told"
    );
    assert_eq!(report.providers, ["b.example", "c.example"]);
    let (_, fanout) = &queued(&p)[0];
    assert_eq!(fanout.message_and_tail, b"COMMIT\0");
    assert_eq!(
        p.fetch_message(ALICE).unwrap().as_deref(),
        Some(&b"COMMIT"[..])
    );
}

/// Held proposals go out as the first with the rest as `moreProposals`, and each reaches the local members.
#[test]
fn held_proposals_carry_their_more_proposals() {
    let p = hub_with(&[ALICE, BOB]);
    p.fan_out_proposals(ROOM, b"P1", &[b"P2".to_vec(), b"P3".to_vec()], 10)
        .unwrap();
    let (domain, fanout) = &queued(&p)[0];
    assert_eq!(domain, "b.example");
    assert_eq!(fanout.message_and_tail, b"P1\x04P2P3");
    assert_eq!(p.fetch_message(ALICE).unwrap().as_deref(), Some(&b"P1"[..]));
    assert_eq!(p.fetch_message(ALICE).unwrap().as_deref(), Some(&b"P2"[..]));
}

/// An application message reaches every participant but its sender: the local ones' queues and the other providers.
#[test]
fn an_application_message_reaches_everyone_but_its_sender() {
    let p = hub_with(&[ALICE, DAVE, BOB]);
    let report = p.fan_out_application(ROOM, ALICE, b"HELLO", 10).unwrap();
    assert_eq!(
        (report.providers.as_slice(), report.local),
        (&["b.example".to_string()][..], 1)
    );
    assert_eq!(queued(&p)[0].1.message_and_tail, b"HELLO\0");
    assert_eq!(
        p.fetch_message(DAVE).unwrap().as_deref(),
        Some(&b"HELLO"[..])
    );
    assert!(p.fetch_message(ALICE).unwrap().is_none());
}

/// A Commit adding Bob, and its Welcome as a bundle carries it (bare), with Bob's KeyPackage as the joiner's.
fn commit_adding_bob() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let alice = Member::new(ALICE);
    let bob = Member::new(BOB);
    let mut group = alice.create_group(b"room");
    let key_package = bob.key_package();
    let (commit, welcome, _) = group
        .add_members(
            &alice.provider,
            &alice.signer,
            std::slice::from_ref(&key_package),
        )
        .unwrap();
    let welcome = welcome.tls_serialize_detached().unwrap();
    (
        commit.tls_serialize_detached().unwrap(),
        welcome[4..].to_vec(),
        key_package.tls_serialize_detached().unwrap(),
    )
}

/// A Welcome goes to the provider the hub recorded for the KeyPackage it names (here not the user's own domain, so the
/// record is what decides), wrapped as an MLSMessage and followed by
/// the bundle's tree option. Revert check: skip the recorded provider, and Bob's provider gets no Welcome.
#[test]
fn a_welcome_goes_to_the_provider_recorded_for_its_key_package() {
    let (commit, welcome, key_package) = commit_adding_bob();
    let p = hub_with(&[ALICE]);
    p.associate_claimed_keypackage(&key_package, "keys.b.example", u64::MAX)
        .unwrap();
    let before = p.store.list_participant_rows(ROOM).unwrap();
    p.fan_out_commit(ROOM, &commit, Some((&welcome, b"\x01TREE")), &before, 10)
        .unwrap();
    let welcomes: Vec<_> = queued(&p)
        .into_iter()
        .filter(|(_, fanout)| fanout.message_and_tail.starts_with(&[0, 1, 0, 3]))
        .collect();
    assert_eq!(
        welcomes.len(),
        1,
        "PLANT-FANOUT-WELCOME-K3: no Welcome for Bob's provider"
    );
    assert_eq!(
        welcomes[0].0, "keys.b.example",
        "the Welcome went by the added user's domain, not the recorded provider"
    );
    assert!(welcomes[0].1.message_and_tail.ends_with(b"\x01TREE"));
}

/// With no record of the KeyPackage, the Welcome goes to the providers of the users the Commit adds.
#[test]
fn an_unrecorded_welcome_goes_to_the_added_users_providers() {
    let (commit, welcome, _) = commit_adding_bob();
    let p = hub_with(&[ALICE]);
    let before: Vec<ParticipantRow> = p.store.list_participant_rows(ROOM).unwrap();
    p.fan_out_commit(ROOM, &commit, Some((&welcome, b"\x01TREE")), &before, 10)
        .unwrap();
    let welcome_domains: Vec<String> = queued(&p)
        .into_iter()
        .filter(|(_, fanout)| fanout.message_and_tail.starts_with(&[0, 1, 0, 3]))
        .map(|(domain, _)| domain)
        .collect();
    assert_eq!(welcome_domains, ["b.example"]);
}

/// Every outbox row, oldest first in each queue, as (domain, the FanoutMessage's message and tail): each queue's head
/// is taken and removed until none is left.
fn drained(p: &Provider) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    loop {
        let heads = p.store.due_outbox_heads(u64::MAX, &[]).unwrap();
        if heads.is_empty() {
            return rows;
        }
        for row in heads {
            p.store.remove_outbox_row(row.id).unwrap();
            rows.push((row.domain, row.body[8..].to_vec()));
        }
    }
}

/// An MLSMessage carrying a Welcome (wire format 3), as a FanoutMessage holds one.
fn is_welcome(message_and_tail: &[u8]) -> bool {
    message_and_tail.starts_with(&[0, 1, 0, 3])
}

/// A provider whose only users in the room are the ones a Commit adds gets their Welcome and not the Commit, and a
/// local user the Commit adds gets no Commit in its queue: they join from the Welcome, at the epoch after it
/// (protocol-07 §5.5, Figures 3 and 5). Revert check: fan the Commit out to the list after it too, and Bob's provider
/// gets the Commit first, which it would refuse, having no member of the room yet.
#[test]
fn the_joiners_provider_gets_only_the_welcome() {
    let (commit, welcome, _) = commit_adding_bob();
    let p = hub_with(&[ALICE]);
    let before = p.store.list_participant_rows(ROOM).unwrap();
    // The Commit lists Bob, of b.example, and Dave, of this hub, after it.
    p.add_participant(ROOM, BOB, 2).unwrap();
    p.add_participant(ROOM, DAVE, 2).unwrap();
    p.fan_out_commit(ROOM, &commit, Some((&welcome, b"\x01TREE")), &before, 10)
        .unwrap();
    let to_b: Vec<bool> = drained(&p)
        .into_iter()
        .filter(|(domain, _)| domain == "b.example")
        .map(|(_, body)| is_welcome(&body))
        .collect();
    assert_eq!(
        to_b,
        vec![true],
        "PLANT-FANOUT-JOINER: the joiner's provider got the Commit too"
    );
    assert!(
        p.fetch_message(DAVE).unwrap().is_none(),
        "a local joiner gets no Commit"
    );
    assert_eq!(
        p.fetch_message(ALICE).unwrap().as_deref(),
        Some(commit.as_slice()),
        "a member before the Commit gets it"
    );
}

/// A provider with a member in the room before a Commit that also adds one of its users gets both, the Commit first and
/// then the Welcome, in its one queue for the room.
#[test]
fn a_provider_with_a_member_gets_the_commit_then_the_welcome() {
    let (commit, welcome, _) = commit_adding_bob();
    let p = hub_with(&[ALICE, "mimi://b.example/u/beth"]);
    let before = p.store.list_participant_rows(ROOM).unwrap();
    p.add_participant(ROOM, BOB, 2).unwrap();
    p.fan_out_commit(ROOM, &commit, Some((&welcome, b"\x01TREE")), &before, 10)
        .unwrap();
    let to_b: Vec<bool> = drained(&p)
        .into_iter()
        .filter(|(domain, _)| domain == "b.example")
        .map(|(_, body)| is_welcome(&body))
        .collect();
    assert_eq!(to_b, vec![false, true], "the Commit, then the Welcome");
}

/// One local member whose queue is full does not stop the message reaching the members after it: they get it, the
/// full member is reported as skipped and its queue is left as it was. Revert check: let a refused enqueue end the
/// loop, and Erin gets nothing.
#[test]
fn a_full_local_queue_does_not_stop_the_others() {
    let erin = "mimi://hub.example/u/erin";
    let p = hub_with(&[ALICE, DAVE, erin]);
    for n in 0..crate::store::MAX_QUEUE_MESSAGES {
        p.store
            .enqueue_message(DAVE, format!("old-{n}").as_bytes(), 1)
            .unwrap();
    }
    let report = p.fan_out_application(ROOM, ALICE, b"hello", 2).unwrap();
    assert_eq!(report.local, 1, "only Erin was queued");
    assert_eq!(report.skipped, vec![DAVE.to_string()]);
    assert_eq!(
        p.fetch_message(erin).unwrap(),
        Some(b"hello".to_vec()),
        "PLANT-FANOUT-FULL: a full queue before Erin's stopped her delivery"
    );
    let mut daves = 0;
    while p.fetch_message(DAVE).unwrap().is_some() {
        daves += 1;
    }
    assert_eq!(i64::from(daves), crate::store::MAX_QUEUE_MESSAGES);
}

/// A member's bundle is queued whole or not at all: Dave, one slot short of a proposal and the one held beside it,
/// keeps exactly what he had, and Erin gets both. Revert check: queue the bundle item by item, and Dave's queue reaches
/// the cap holding half of it.
#[test]
fn a_member_gets_a_whole_bundle_or_none_of_it() {
    let erin = "mimi://hub.example/u/erin";
    let p = hub_with(&[ALICE, DAVE, erin]);
    for n in 0..crate::store::MAX_QUEUE_MESSAGES - 1 {
        p.store
            .enqueue_message(DAVE, format!("old-{n}").as_bytes(), 1)
            .unwrap();
    }
    let report = p
        .fan_out_proposals(ROOM, b"proposal", &[b"more".to_vec()], 2)
        .unwrap();
    assert_eq!(report.skipped, vec![DAVE.to_string()]);
    let mut daves = Vec::new();
    while let Some(item) = p.fetch_message(DAVE).unwrap() {
        daves.push(item);
    }
    assert_eq!(
        i64::try_from(daves.len()).unwrap(),
        crate::store::MAX_QUEUE_MESSAGES - 1,
        "PLANT-FANOUT-BUNDLE: Dave holds part of the bundle"
    );
    assert!(daves.iter().all(|item| item.starts_with(b"old-")));
    assert_eq!(p.fetch_message(erin).unwrap(), Some(b"proposal".to_vec()));
    assert_eq!(p.fetch_message(erin).unwrap(), Some(b"more".to_vec()));
}

/// A Welcome naming two local users' KeyPackages reaches the one whose Welcome queue has room, although the other's is
/// full; the full queue is left as it was. Revert check: let the refusal end delivery, and Erin gets no Welcome.
#[test]
fn a_full_welcome_queue_does_not_stop_the_other_welcomed_user() {
    let p = Provider::in_memory("hub.example").unwrap();
    let (dave, erin) = (Member::new(DAVE), Member::new("mimi://hub.example/u/erin"));
    let (daves, erins) = (dave.key_package(), erin.key_package());
    p.publish_key_package("dave", &daves.tls_serialize_detached().unwrap(), 1)
        .unwrap();
    p.publish_key_package("erin", &erins.tls_serialize_detached().unwrap(), 1)
        .unwrap();
    for n in 0..crate::store::MAX_QUEUE_WELCOMES {
        p.store
            .enqueue_welcome("dave", format!("old-{n}").as_bytes(), 1)
            .unwrap();
    }
    let alice = Member::new("mimi://other.example/u/alice");
    let mut group = alice.create_group(b"room");
    let (_commit, welcome, _info) = group
        .add_members(&alice.provider, &alice.signer, &[daves, erins])
        .unwrap();
    let users = p
        .deliver_notified_welcome_to(
            "mimi://other.example/r/room",
            &welcome.tls_serialize_detached().unwrap(),
            2,
        )
        .unwrap();
    assert_eq!(
        users,
        vec!["erin".to_string()],
        "PLANT-FANOUT-WELCOME: the full queue stopped Erin's Welcome"
    );
    assert!(p.fetch_welcome("erin").unwrap().is_some());
    let mut daves_queue = 0;
    while p.fetch_welcome("dave").unwrap().is_some() {
        daves_queue += 1;
    }
    assert_eq!(i64::from(daves_queue), crate::store::MAX_QUEUE_WELCOMES);
}

/// A store error that is not a queue's refusal (here, the message table is gone) fails the fan-out instead of being
/// skipped member by member, so a broken store is loud. Revert check: skip every error, and this fan-out "succeeds".
#[test]
fn a_store_error_fails_the_fan_out() {
    let erin = "mimi://hub.example/u/erin";
    let p = hub_with(&[ALICE, DAVE, erin]);
    p.store.break_message_queue_for_test();
    assert!(
        p.fan_out_application(ROOM, ALICE, b"hello", 2).is_err(),
        "PLANT-FANOUT-STORE-ERROR: a store error was skipped as a refusal"
    );
}

/// With reuse on, Erin's only KeyPackage is a last-resort one, so two rooms on other providers claim the same one and each sends a
/// Welcome for it in a notify: both reach Erin, the KeyPackageRef still naming her after the first. Revert check: forget
/// the ref once its first Welcome is delivered, and the second room's Welcome is dropped.
#[test]
fn two_welcomes_on_one_last_resort_key_package_both_reach_the_user() {
    use openmls::prelude::KeyPackage;
    let p = Provider::in_memory("hub.example")
        .unwrap()
        .with_last_resort_reuse(true);
    let erin = Member::new("mimi://hub.example/u/erin");
    let last = KeyPackage::builder()
        .leaf_node_capabilities(crate::mls_fixtures::capabilities())
        .mark_as_last_resort()
        .build(
            crate::mls_fixtures::SUITE,
            &erin.provider,
            &erin.signer,
            erin.credential.clone(),
        )
        .unwrap()
        .key_package()
        .clone();
    let bytes = last.tls_serialize_detached().unwrap();
    p.publish_key_package("erin", &bytes, 1).unwrap();
    let mut delivered = Vec::new();
    for (inviter, room) in [
        ("mimi://other.example/u/alice", &b"room-a"[..]),
        ("mimi://c.example/u/carol", &b"room-c"[..]),
    ] {
        assert_eq!(
            p.serve_key_material("erin", 2).unwrap().as_deref(),
            Some(bytes.as_slice())
        );
        let inviter = Member::new(inviter);
        let mut group = inviter.create_group(room);
        let (_commit, welcome, _info) = group
            .add_members(&inviter.provider, &inviter.signer, &[last.clone()])
            .unwrap();
        delivered.push(
            p.deliver_notified_welcome_to(
                "mimi://other.example/r/room",
                &welcome.tls_serialize_detached().unwrap(),
                3,
            )
            .unwrap(),
        );
    }
    assert_eq!(
        delivered,
        vec![vec!["erin".to_string()], vec!["erin".to_string()]],
        "PLANT-FANOUT-LAST-RESORT-WELCOMES: the second room's Welcome did not reach Erin"
    );
    assert!(p.fetch_welcome("erin").unwrap().is_some());
    assert!(p.fetch_welcome("erin").unwrap().is_some());
    assert!(p.fetch_welcome("erin").unwrap().is_none());
}

/// By default (reuse off) Erin's last-resort KeyPackage is handed out once: the first room gets it, the second room's
/// claim finds nothing, and Erin's client is told none is left. Revert check: keep the last-resort KeyPackage whatever
/// the setting, and the second claim gets it again.
#[test]
fn by_default_a_last_resort_key_package_goes_to_one_room() {
    use openmls::prelude::KeyPackage;
    let p = Provider::in_memory("hub.example").unwrap();
    let erin = Member::new("mimi://hub.example/u/erin");
    let last = KeyPackage::builder()
        .leaf_node_capabilities(crate::mls_fixtures::capabilities())
        .mark_as_last_resort()
        .build(
            crate::mls_fixtures::SUITE,
            &erin.provider,
            &erin.signer,
            erin.credential.clone(),
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    p.publish_key_package("erin", &last, 1).unwrap();
    assert_eq!(
        p.serve_key_material("erin", 2).unwrap().as_deref(),
        Some(last.as_slice())
    );
    assert_eq!(
        p.serve_key_material("erin", 2).unwrap(),
        None,
        "PLANT-HUB-KP-ONCE-DEFAULT: by default a last-resort KeyPackage is handed out once"
    );
    assert_eq!(p.store.key_package_count("erin", 2).unwrap(), (0, false));
}
