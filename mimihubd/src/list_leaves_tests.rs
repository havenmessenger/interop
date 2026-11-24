use super::*;
use mimi_core::room_policy::{BaseRoomPolicy, Role};

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const CAROL: &str = "mimi://c.example/u/carol";
const MEMBER: u32 = 3;

fn policy(capabilities: Vec<Capability>) -> RoomPolicy {
    RoomPolicy {
        base: BaseRoomPolicy::default(),
        roles: vec![Role {
            role_index: MEMBER,
            role_name: "member".into(),
            capabilities,
            authorized_role_changes: Vec::new(),
        }],
    }
}

fn may_remove_own() -> RoomPolicy {
    policy(vec![Capability::SendMessage, Capability::RemoveOwnClient])
}

fn users(list: &[&str]) -> Vec<String> {
    list.iter().map(|user| user.to_string()).collect()
}

fn leaves(list: &[&str]) -> Vec<Option<String>> {
    list.iter().map(|user| Some(user.to_string())).collect()
}

fn removed(user: &str, proposer: &str) -> RemovedLeaf {
    RemovedLeaf {
        user: Some(user.into()),
        proposer: Some(proposer.into()),
    }
}

/// Alice, Bob and Carol listed as members; Bob has two clients.
fn room() -> ListAndLeaves {
    ListAndLeaves {
        before: vec![
            (ALICE.into(), MEMBER),
            (BOB.into(), MEMBER),
            (CAROL.into(), MEMBER),
        ],
        after: users(&[ALICE, BOB, CAROL]),
        added: Vec::new(),
        removed: Vec::new(),
        leaves_after: leaves(&[ALICE, BOB, BOB, CAROL]),
        renewed: Vec::new(),
    }
}

#[test]
fn a_delisted_user_whose_clients_stay_is_refused() {
    // The list drops Carol, and the Commit removes one of Bob's clients instead of Carol's.
    let view = ListAndLeaves {
        after: users(&[ALICE, BOB]),
        removed: vec![removed(BOB, ALICE)],
        leaves_after: leaves(&[ALICE, BOB, CAROL]),
        ..room()
    };
    assert_eq!(
        require_paired(&view, Some(&may_remove_own())),
        Err(DELISTED_KEEPS_CLIENT),
        "PLANT-HUB-LIST-REMOVE: a delisted user keeps no client"
    );
}

#[test]
fn a_delisted_user_whose_clients_all_go_is_accepted() {
    let view = ListAndLeaves {
        after: users(&[ALICE, CAROL]),
        removed: vec![removed(BOB, ALICE), removed(BOB, ALICE)],
        leaves_after: leaves(&[ALICE, CAROL]),
        ..room()
    };
    assert_eq!(require_paired(&view, Some(&may_remove_own())), Ok(()));
}

#[test]
fn a_delisted_user_with_one_of_two_clients_left_is_refused() {
    let view = ListAndLeaves {
        after: users(&[ALICE, CAROL]),
        removed: vec![removed(BOB, ALICE)],
        leaves_after: leaves(&[ALICE, BOB, CAROL]),
        ..room()
    };
    assert_eq!(
        require_paired(&view, Some(&may_remove_own())),
        Err(DELISTED_KEEPS_CLIENT)
    );
}

#[test]
fn removing_another_listed_users_client_is_refused() {
    // Alice removes one of Bob's clients and leaves the list as it was.
    let view = ListAndLeaves {
        removed: vec![removed(BOB, ALICE)],
        leaves_after: leaves(&[ALICE, BOB, CAROL]),
        ..room()
    };
    assert_eq!(
        require_paired(&view, Some(&may_remove_own())),
        Err(CLIENT_OF_ANOTHER),
        "PLANT-HUB-OWN-CLIENT: only a user removes its own client from a list it stays on"
    );
}

#[test]
fn removing_ones_own_second_client_is_accepted() {
    let view = ListAndLeaves {
        removed: vec![removed(BOB, BOB)],
        leaves_after: leaves(&[ALICE, BOB, CAROL]),
        ..room()
    };
    assert_eq!(require_paired(&view, Some(&may_remove_own())), Ok(()));
}

#[test]
fn removing_ones_own_client_needs_the_capability() {
    let view = ListAndLeaves {
        removed: vec![removed(BOB, BOB)],
        leaves_after: leaves(&[ALICE, BOB, CAROL]),
        ..room()
    };
    assert_eq!(
        require_paired(&view, Some(&policy(vec![Capability::SendMessage]))),
        Err(CLIENT_OF_ANOTHER)
    );
}

#[test]
fn a_held_self_remove_another_member_commits_is_accepted() {
    // Bob proposed the removal of one of his clients (a SelfRemove or a Remove of his own), and Alice commits it.
    let view = ListAndLeaves {
        removed: vec![removed(BOB, BOB)],
        leaves_after: leaves(&[ALICE, BOB, CAROL]),
        ..room()
    };
    assert_eq!(require_paired(&view, Some(&may_remove_own())), Ok(()));
}

#[test]
fn a_room_without_roles_checks_whose_client_it_is_but_no_capability() {
    let own = ListAndLeaves {
        removed: vec![removed(BOB, BOB)],
        leaves_after: leaves(&[ALICE, BOB, CAROL]),
        ..room()
    };
    assert_eq!(require_paired(&own, None), Ok(()));
    let another = ListAndLeaves {
        removed: vec![removed(BOB, CAROL)],
        ..own
    };
    assert_eq!(require_paired(&another, None), Err(CLIENT_OF_ANOTHER));
}

#[test]
fn an_added_client_must_be_of_a_user_listed_after_the_commit() {
    let dave = "mimi://d.example/u/dave";
    let unlisted = ListAndLeaves {
        added: leaves(&[dave]),
        leaves_after: leaves(&[ALICE, BOB, BOB, CAROL, dave]),
        ..room()
    };
    assert_eq!(
        require_paired(&unlisted, Some(&may_remove_own())),
        Err(ADDED_NOT_LISTED),
        "PLANT-HUB-ADD-LISTED: an added client's user is listed after the Commit"
    );
    let listed = ListAndLeaves {
        after: users(&[ALICE, BOB, CAROL, dave]),
        ..unlisted
    };
    assert_eq!(require_paired(&listed, Some(&may_remove_own())), Ok(()));
}

#[test]
fn an_added_client_that_names_no_user_is_refused() {
    let view = ListAndLeaves {
        added: vec![None],
        ..room()
    };
    assert_eq!(
        require_paired(&view, Some(&may_remove_own())),
        Err(ADDED_NOT_LISTED)
    );
}

#[test]
fn a_client_of_no_listed_user_may_be_removed_by_anyone() {
    let stray = "mimi://e.example/u/erin";
    let view = ListAndLeaves {
        removed: vec![
            removed(stray, ALICE),
            RemovedLeaf {
                user: None,
                proposer: Some(ALICE.into()),
            },
        ],
        ..room()
    };
    assert_eq!(require_paired(&view, Some(&may_remove_own())), Ok(()));
}

#[test]
fn a_listed_user_with_no_client_left_is_valid() {
    // Bob removes both of his clients and stays listed: an inactive participant.
    let view = ListAndLeaves {
        removed: vec![removed(BOB, BOB), removed(BOB, BOB)],
        leaves_after: leaves(&[ALICE, CAROL]),
        ..room()
    };
    assert_eq!(require_paired(&view, Some(&may_remove_own())), Ok(()));
}

#[test]
fn a_client_whose_new_leaf_names_another_user_is_refused() {
    let dave = "mimi://d.example/u/dave";
    let bytes = |user: &str| Some(user.as_bytes().to_vec());
    // Another listed user, an unlisted one, and Bob's own URI with its host in another case: each is another
    // credential, though the last names the same user in canonical form.
    for other in [CAROL, dave, "mimi://B.EXAMPLE/u/bob"] {
        let view = ListAndLeaves {
            renewed: vec![(bytes(BOB), bytes(other))],
            ..room()
        };
        assert_eq!(
            require_paired(&view, Some(&may_remove_own())),
            Err(CLIENT_CHANGES_USER),
            "PLANT-HUB-SAME-USER: a client's new leaf named another user ({other})"
        );
    }
    let same = ListAndLeaves {
        renewed: vec![(bytes(BOB), bytes(BOB))],
        ..room()
    };
    assert_eq!(require_paired(&same, Some(&may_remove_own())), Ok(()));
    let not_basic = ListAndLeaves {
        renewed: vec![(None, bytes(BOB))],
        ..room()
    };
    assert_eq!(
        require_paired(&not_basic, Some(&may_remove_own())),
        Err(CLIENT_CHANGES_USER)
    );
}

#[test]
fn a_member_who_may_kick_removes_another_listed_users_client() {
    let view = ListAndLeaves {
        removed: vec![removed(BOB, ALICE)],
        leaves_after: leaves(&[ALICE, BOB, CAROL]),
        ..room()
    };
    assert_eq!(
        require_paired(&view, Some(&policy(vec![Capability::Kick]))),
        Ok(()),
        "PLANT-HUB-KICK: canKick removes another participant's client without changing the list"
    );
    assert_eq!(require_paired(&view, None), Err(CLIENT_OF_ANOTHER));
}
