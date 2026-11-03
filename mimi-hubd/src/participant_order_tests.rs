//! A `ParticipantListUpdate` names participants by position (protocol-07 §7.5): the indices refer to the room's
//! participants vector as it stood before the update, and added participants are appended to its end. These rows hold the
//! hub to that order, so an index lands on the participant the sender counted.

use mimi_core::participant_list::{ParticipantListUpdate, UserRolePair, UserindexRolePair};

use super::{Provider, UpdateRefusal};

const ROOM: &str = "mimi://mimi.havenmessenger.com/r/order";

fn user(name: &str) -> String {
    format!("mimi://mimi.havenmessenger.com/u/{name}")
}

fn hub_with(names: &[&str]) -> Provider {
    let hub = Provider::in_memory("mimi.havenmessenger.com").unwrap();
    for name in names {
        hub.add_participant(ROOM, &user(name), 1).unwrap();
    }
    hub
}

fn members(hub: &Provider) -> Vec<String> {
    hub.list_participants(ROOM)
        .unwrap()
        .into_iter()
        .map(|(uri, _authority)| uri)
        .collect()
}

fn named(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| user(name)).collect()
}

fn added(name: &str, role_index: u32) -> UserRolePair {
    UserRolePair {
        user_uri: user(name),
        role_index,
    }
}

fn role_of(hub: &Provider, name: &str) -> Option<u32> {
    hub.store.member_role(ROOM, &user(name)).unwrap()
}

#[test]
fn the_list_is_in_the_order_participants_were_added() {
    // Alphabetical order would put bob before zoe.
    let hub = hub_with(&["alice", "zoe", "bob"]);
    assert_eq!(members(&hub), named(&["alice", "zoe", "bob"]));
}

#[test]
fn a_removal_by_index_removes_the_participant_at_that_position_in_the_room_s_order() {
    // alice, zoe, bob: a sender counting the room's order removes zoe with index 1.
    let hub = hub_with(&["alice", "zoe", "bob"]);
    let update = ParticipantListUpdate {
        removed_indices: vec![1],
        ..Default::default()
    };
    hub.apply_participant_list_update(ROOM, &update, 2).unwrap();
    assert_eq!(members(&hub), named(&["alice", "bob"]));
}

#[test]
fn a_role_change_by_index_lands_on_the_participant_at_that_position() {
    let hub = hub_with(&["alice", "zoe", "bob"]);
    hub.set_member_role(ROOM, &user("zoe"), 2).unwrap();
    hub.set_member_role(ROOM, &user("bob"), 2).unwrap();
    let update = ParticipantListUpdate {
        changed_role_participants: vec![UserindexRolePair {
            user_index: 1,
            role_index: 5,
        }],
        ..Default::default()
    };
    hub.apply_participant_list_update(ROOM, &update, 2).unwrap();
    assert_eq!(role_of(&hub, "zoe"), Some(5));
    assert_eq!(role_of(&hub, "bob"), Some(2), "bob is at index 2, not 1");
}

#[test]
fn a_removal_and_an_addition_in_one_update_keep_the_order_and_append() {
    let hub = hub_with(&["alice", "zoe", "bob"]);
    let update = ParticipantListUpdate {
        removed_indices: vec![0],
        added_participants: vec![added("carol", 2), added("amy", 2)],
        ..Default::default()
    };
    hub.apply_participant_list_update(ROOM, &update, 2).unwrap();
    assert_eq!(members(&hub), named(&["zoe", "bob", "carol", "amy"]));
}

#[test]
fn a_participant_removed_and_added_again_joins_at_the_end() {
    let hub = hub_with(&["alice", "zoe", "bob"]);
    hub.remove_participant(ROOM, &user("zoe")).unwrap();
    hub.add_participant(ROOM, &user("zoe"), 3).unwrap();
    assert_eq!(members(&hub), named(&["alice", "bob", "zoe"]));
}

#[test]
fn indices_after_an_earlier_update_count_the_new_order() {
    let hub = hub_with(&["alice", "zoe", "bob"]);
    let first = ParticipantListUpdate {
        removed_indices: vec![0],
        added_participants: vec![added("carol", 2)],
        ..Default::default()
    };
    hub.apply_participant_list_update(ROOM, &first, 2).unwrap();
    // zoe, bob, carol: index 2 is carol.
    let second = ParticipantListUpdate {
        removed_indices: vec![2],
        ..Default::default()
    };
    hub.apply_participant_list_update(ROOM, &second, 3).unwrap();
    assert_eq!(members(&hub), named(&["zoe", "bob"]));
}

#[test]
fn removing_two_entries_does_not_shift_the_second_index() {
    // §7.5: removing one entry does not shift the indices of the other removals.
    let hub = hub_with(&["alice", "zoe", "bob", "dan"]);
    let update = ParticipantListUpdate {
        removed_indices: vec![1, 2],
        ..Default::default()
    };
    hub.apply_participant_list_update(ROOM, &update, 2).unwrap();
    assert_eq!(members(&hub), named(&["alice", "dan"]));
}

#[test]
fn a_participant_who_is_already_listed_cannot_be_added_again() {
    // §7.5: an update is invalid if a user in addedParticipants is already in the participant list.
    let hub = hub_with(&["alice", "zoe", "bob"]);
    hub.set_member_role(ROOM, &user("zoe"), 2).unwrap();
    let update = ParticipantListUpdate {
        added_participants: vec![added("zoe", 3)],
        ..Default::default()
    };
    assert!(matches!(
        hub.apply_participant_list_update(ROOM, &update, 2),
        Err(UpdateRefusal::Invalid(_))
    ));
    assert_eq!(members(&hub), named(&["alice", "zoe", "bob"]));
    assert_eq!(
        role_of(&hub, "zoe"),
        Some(2),
        "the refused update changed a role"
    );
}

#[test]
fn a_participant_removed_and_added_in_the_same_update_is_refused() {
    // The list an update is checked against is the one before it, so the user is still listed.
    let hub = hub_with(&["alice", "zoe", "bob"]);
    let update = ParticipantListUpdate {
        removed_indices: vec![1],
        added_participants: vec![added("zoe", 2)],
        ..Default::default()
    };
    assert!(matches!(
        hub.apply_participant_list_update(ROOM, &update, 2),
        Err(UpdateRefusal::Invalid(_))
    ));
    assert_eq!(members(&hub), named(&["alice", "zoe", "bob"]));
}

#[test]
fn an_index_past_the_end_is_refused_and_changes_nothing() {
    let hub = hub_with(&["alice", "zoe", "bob"]);
    for update in [
        ParticipantListUpdate {
            removed_indices: vec![3],
            ..Default::default()
        },
        ParticipantListUpdate {
            changed_role_participants: vec![UserindexRolePair {
                user_index: 3,
                role_index: 2,
            }],
            ..Default::default()
        },
    ] {
        assert!(matches!(
            hub.apply_participant_list_update(ROOM, &update, 2),
            Err(UpdateRefusal::Invalid(_))
        ));
    }
    assert_eq!(members(&hub), named(&["alice", "zoe", "bob"]));
}

#[test]
fn an_index_named_twice_or_in_both_lists_is_refused_and_changes_nothing() {
    let hub = hub_with(&["alice", "zoe", "bob"]);
    for update in [
        ParticipantListUpdate {
            removed_indices: vec![1, 1],
            ..Default::default()
        },
        ParticipantListUpdate {
            changed_role_participants: vec![
                UserindexRolePair {
                    user_index: 1,
                    role_index: 2,
                },
                UserindexRolePair {
                    user_index: 1,
                    role_index: 3,
                },
            ],
            ..Default::default()
        },
        ParticipantListUpdate {
            changed_role_participants: vec![UserindexRolePair {
                user_index: 1,
                role_index: 2,
            }],
            removed_indices: vec![1],
            ..Default::default()
        },
    ] {
        assert!(matches!(
            hub.apply_participant_list_update(ROOM, &update, 2),
            Err(UpdateRefusal::Invalid(_))
        ));
    }
    assert_eq!(members(&hub), named(&["alice", "zoe", "bob"]));
}

#[test]
fn a_store_opened_on_the_older_table_keeps_the_order_it_was_written_in() {
    // The first release ordered nothing and had no position column; its rows keep their insertion order.
    let dir = std::env::temp_dir().join(format!("mimi-hubd-order-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("old.sqlite");
    let _ = std::fs::remove_file(&path);
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE room_participants (
                 room_uri TEXT NOT NULL, member_uri TEXT NOT NULL, authority TEXT NOT NULL, ts INTEGER NOT NULL,
                 PRIMARY KEY (room_uri, member_uri)
             );",
        )
        .unwrap();
        for name in ["alice", "zoe", "bob"] {
            conn.execute(
                "INSERT INTO room_participants (room_uri, member_uri, authority, ts) VALUES (?1, ?2, 'mimi.havenmessenger.com', 1)",
                rusqlite::params![ROOM, user(name)],
            )
            .unwrap();
        }
    }
    let hub = Provider::open("mimi.havenmessenger.com", path.to_str().unwrap()).unwrap();
    assert_eq!(members(&hub), named(&["alice", "zoe", "bob"]));
    hub.add_participant(ROOM, &user("amy"), 2).unwrap();
    assert_eq!(members(&hub), named(&["alice", "zoe", "bob", "amy"]));
    let _ = std::fs::remove_dir_all(&dir);
}
