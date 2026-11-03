//! `apply_update` against protocol-07 §7.5: indices count the vector as it stood before the update, and an update that
//! adds a user who is already listed is invalid.

use super::*;

fn list(names: &[&str]) -> ParticipantListData {
    ParticipantListData {
        participants: names
            .iter()
            .map(|name| UserRolePair {
                user_uri: format!("mimi://a.example/u/{name}"),
                role_index: 2,
            })
            .collect(),
    }
}

fn user(name: &str) -> String {
    format!("mimi://a.example/u/{name}")
}

fn add(name: &str) -> UserRolePair {
    UserRolePair {
        user_uri: user(name),
        role_index: 2,
    }
}

#[test]
fn an_update_adding_a_listed_user_is_invalid() {
    let update = ParticipantListUpdate {
        added_participants: vec![add("zoe")],
        ..Default::default()
    };
    assert!(apply_update(&list(&["alice", "zoe", "bob"]), &update).is_err());
}

#[test]
fn a_user_removed_and_added_again_in_one_update_is_invalid() {
    let update = ParticipantListUpdate {
        removed_indices: vec![1],
        added_participants: vec![add("zoe")],
        ..Default::default()
    };
    assert!(apply_update(&list(&["alice", "zoe", "bob"]), &update).is_err());
}

#[test]
fn removals_count_the_vector_before_the_update_and_adds_append() {
    let update = ParticipantListUpdate {
        removed_indices: vec![0, 2],
        added_participants: vec![add("dan")],
        ..Default::default()
    };
    let next = apply_update(&list(&["alice", "zoe", "bob"]), &update).unwrap();
    let names: Vec<_> = next
        .participants
        .iter()
        .map(|p| p.user_uri.clone())
        .collect();
    assert_eq!(names, vec![user("zoe"), user("dan")]);
}

#[test]
fn an_index_in_both_lists_or_named_twice_is_invalid() {
    let both = ParticipantListUpdate {
        changed_role_participants: vec![UserindexRolePair {
            user_index: 1,
            role_index: 3,
        }],
        removed_indices: vec![1],
        ..Default::default()
    };
    let twice = ParticipantListUpdate {
        removed_indices: vec![1, 1],
        ..Default::default()
    };
    for update in [both, twice] {
        assert!(apply_update(&list(&["alice", "zoe", "bob"]), &update).is_err());
    }
}
