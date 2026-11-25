//! A queued Welcome names the room it joins when the hub knows it: the room this hub fans it out for, or the room a
//! hub's notify names. The client lane passes the room on, since a Welcome alone does not say which room it is for.

use openmls::prelude::tls_codec::Serialize as _;

use crate::mls_fixtures::Member;
use crate::store::{QueueKind, SqliteStore};
use crate::Provider;

const ROOM: &str = "mimi://hub.example/r/room";
const ALICE: &str = "mimi://hub.example/u/alice";
const ERIN: &str = "mimi://hub.example/u/erin";

fn welcomes(store: &SqliteStore, user: &str) -> Vec<Option<String>> {
    store
        .peek_queue(QueueKind::Welcomes, &[user, user], 0, 50)
        .unwrap()
        .into_iter()
        .map(|item| item.room)
        .collect()
}

/// A Welcome queued with a room keeps it, in canonical form; one queued without names none; a message never does.
#[test]
fn a_welcome_keeps_its_room_and_a_message_has_none() {
    let store = SqliteStore::in_memory().unwrap();
    store
        .enqueue_room_welcome("bob", Some("MIMI://HUB.example/r/room"), b"w1", 1)
        .unwrap();
    store.enqueue_welcome("bob", b"w2", 1).unwrap();
    store.enqueue_message("bob", b"m", 1).unwrap();
    assert_eq!(
        welcomes(&store, "bob"),
        vec![Some(ROOM.to_string()), None],
        "PLANT-WELCOME-ROOM-STORE: the room was not kept, or not in canonical form"
    );
    let messages = store
        .peek_queue(QueueKind::Messages, &["bob", "bob"], 0, 50)
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].room, None);
}

/// A store opened over a welcomes table from before the room column gains it, and what was queued then names no room.
#[test]
fn an_older_welcome_queue_migrates_and_its_welcomes_name_no_room() {
    let path = std::env::temp_dir().join(format!("mimi-welcome-room-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let old = rusqlite::Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE welcomes (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, bytes BLOB NOT NULL,
             ts INTEGER NOT NULL);
             INSERT INTO welcomes (recipient, bytes, ts) VALUES ('bob', x'01', 1);",
        )
        .unwrap();
    }
    let store = SqliteStore::open(path.to_str().unwrap()).unwrap();
    store
        .enqueue_room_welcome("bob", Some(ROOM), b"w", 2)
        .unwrap();
    let rooms = welcomes(&store, "bob");
    drop(store);
    let _ = std::fs::remove_file(&path);
    assert_eq!(rooms, vec![None, Some(ROOM.to_string())]);
}

/// A room this hub hosts: the Welcome its fan-out queues for a local new member names that room.
#[test]
fn a_hosted_rooms_fan_out_names_the_room() {
    let p = Provider::in_memory("hub.example").unwrap();
    p.add_participant(ROOM, ALICE, 1).unwrap();
    let alice = Member::new(ALICE);
    let erin = Member::new(ERIN);
    let key_package = erin.key_package();
    let bytes = key_package.tls_serialize_detached().unwrap();
    p.publish_key_package("erin", &bytes, 1).unwrap();
    assert_eq!(
        p.serve_key_material("erin", 1).unwrap().as_deref(),
        Some(bytes.as_slice()),
        "the hub serves Erin's KeyPackage, recording whose it is"
    );
    let mut group = alice.create_group(b"room");
    let (commit, welcome, _) = group
        .add_members(&alice.provider, &alice.signer, &[key_package])
        .unwrap();
    let welcome = welcome.tls_serialize_detached().unwrap();
    let before = p.store.list_participant_rows(ROOM).unwrap();
    let report = p
        .fan_out_commit(
            ROOM,
            &commit.tls_serialize_detached().unwrap(),
            Some((&welcome[4..], b"\x01TREE")),
            &before,
            2,
        )
        .unwrap();
    assert_eq!(report.local, 1, "Erin's Welcome was queued here");
    assert_eq!(
        welcomes(&p.store, "erin"),
        vec![Some(ROOM.to_string())],
        "PLANT-WELCOME-ROOM-FANOUT: the fan-out queued the Welcome without its room"
    );
}

/// A room on another hub: the Welcome its hub sends in a notify is queued with the room the notify named.
#[test]
fn a_notified_welcome_names_the_room_its_hub_named() {
    let p = Provider::in_memory("hub.example").unwrap();
    let erin = Member::new(ERIN);
    let key_package = erin.key_package();
    let bytes = key_package.tls_serialize_detached().unwrap();
    p.publish_key_package("erin", &bytes, 1).unwrap();
    p.serve_key_material("erin", 1).unwrap();
    let alice = Member::new("mimi://other.example/u/alice");
    let mut group = alice.create_group(b"room");
    let (_commit, welcome, _) = group
        .add_members(&alice.provider, &alice.signer, &[key_package])
        .unwrap();
    let users = p
        .deliver_notified_welcome_to(
            "mimi://other.example/r/theirs",
            &welcome.tls_serialize_detached().unwrap(),
            2,
        )
        .unwrap();
    assert_eq!(users, vec!["erin".to_string()]);
    assert_eq!(
        welcomes(&p.store, "erin"),
        vec![Some("mimi://other.example/r/theirs".to_string())],
        "PLANT-WELCOME-ROOM-NOTIFY: the notified Welcome was queued without its room"
    );
}
