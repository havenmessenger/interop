use super::*;
use crate::participant_list::{
    encode_participant_list_update, ParticipantListUpdate, UserRolePair, UserindexRolePair,
};

fn user(name: &str) -> String {
    format!("mimi://hub.example/u/{name}")
}

fn list(names: &[&str]) -> Vec<u8> {
    encode_participant_list_data(&ParticipantListData {
        participants: names
            .iter()
            .map(|name| UserRolePair {
                user_uri: user(name),
                role_index: 2,
            })
            .collect(),
    })
    .unwrap()
}

fn names(value: &[u8]) -> Vec<String> {
    decode_participant_list_data(value)
        .unwrap()
        .participants
        .into_iter()
        .map(|participant| participant.user_uri)
        .collect()
}

fn removing(indices: &[u32]) -> Vec<u8> {
    encode_participant_list_update(&ParticipantListUpdate {
        removed_indices: indices.to_vec(),
        ..ParticipantListUpdate::default()
    })
    .unwrap()
}

fn adding(name: &str) -> Vec<u8> {
    encode_participant_list_update(&ParticipantListUpdate {
        added_participants: vec![UserRolePair {
            user_uri: user(name),
            role_index: 2,
        }],
        ..ParticipantListUpdate::default()
    })
    .unwrap()
}

/// protocol-07 §7.5's case: Bob (1) and Carol (2) leave in one Commit, each update indexing the list before it, and Dave
/// stays. Revert check: apply the updates one after another, and Carol's removal takes Dave instead.
#[test]
fn two_leaves_in_one_commit_both_index_the_list_before_it() {
    let before = list(&["alice", "bob", "carol", "dave"]);
    let (bob, carol) = (removing(&[1]), removing(&[2]));
    let after = resolve_component(
        PARTICIPANT_LIST_COMPONENT,
        Some(&before),
        &[
            ComponentChange::Update(&bob),
            ComponentChange::Update(&carol),
        ],
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        names(&after),
        [user("alice"), user("dave")],
        "PLANT-MIMI-LIST-PRE-COMMIT: Dave stays listed"
    );
}

/// Additions from two updates are appended in the Commit's order, after the removals.
#[test]
fn additions_from_several_updates_are_appended_in_order() {
    let before = list(&["alice", "bob"]);
    let (leave, carol, dan) = (removing(&[1]), adding("carol"), adding("dan"));
    let after = resolve_component(
        PARTICIPANT_LIST_COMPONENT,
        Some(&before),
        &[
            ComponentChange::Update(&carol),
            ComponentChange::Update(&leave),
            ComponentChange::Update(&dan),
        ],
    )
    .unwrap()
    .unwrap();
    assert_eq!(names(&after), [user("alice"), user("carol"), user("dan")]);
}

/// §7.5: a Commit whose updates touch one user twice is not valid, by index or by URI. Revert check: let a later
/// update's index repeat an earlier one's, and the Commit is taken.
#[test]
fn a_user_touched_by_two_updates_is_refused() {
    let before = list(&["alice", "bob", "carol"]);
    let role = encode_participant_list_update(&ParticipantListUpdate {
        changed_role_participants: vec![UserindexRolePair {
            user_index: 1,
            role_index: 3,
        }],
        ..ParticipantListUpdate::default()
    })
    .unwrap();
    let (leave, dan) = (removing(&[1]), adding("dan"));
    for changes in [
        vec![
            ComponentChange::Update(&leave),
            ComponentChange::Update(&leave),
        ],
        vec![
            ComponentChange::Update(&role),
            ComponentChange::Update(&leave),
        ],
        vec![ComponentChange::Update(&dan), ComponentChange::Update(&dan)],
    ] {
        assert!(
            matches!(
                resolve_component(PARTICIPANT_LIST_COMPONENT, Some(&before), &changes),
                Err(AppDataError::DoesNotApply(_))
            ),
            "PLANT-MIMI-LIST-TOUCHED-TWICE: {changes:?}"
        );
    }
}

#[test]
fn a_list_update_that_does_not_fit_or_decode_is_refused() {
    let before = list(&["alice", "bob"]);
    let out_of_range = removing(&[5]);
    let already = adding("bob");
    for change in [&out_of_range, &already] {
        assert!(matches!(
            resolve_component(
                PARTICIPANT_LIST_COMPONENT,
                Some(&before),
                &[ComponentChange::Update(change)]
            ),
            Err(AppDataError::DoesNotApply(_))
        ));
    }
    assert!(matches!(
        resolve_component(
            PARTICIPANT_LIST_COMPONENT,
            Some(&before),
            &[ComponentChange::Update(b"\xff")]
        ),
        Err(AppDataError::Malformed(_))
    ));
}

#[test]
fn the_participant_list_is_never_removed() {
    assert!(matches!(
        resolve_component(
            PARTICIPANT_LIST_COMPONENT,
            Some(&list(&["alice"])),
            &[ComponentChange::Remove]
        ),
        Err(AppDataError::ListRemoved)
    ));
}

/// Another component's update is its new value, so the last one is the value; a removal removes it, and a removal
/// beside a change is refused.
#[test]
fn another_components_last_update_is_its_value() {
    const OTHER: u16 = 0x0023;
    assert_eq!(
        resolve_component(
            OTHER,
            Some(b"old"),
            &[
                ComponentChange::Update(b"one"),
                ComponentChange::Update(b"two")
            ]
        )
        .unwrap(),
        Some(b"two".to_vec())
    );
    assert_eq!(
        resolve_component(OTHER, Some(b"old"), &[ComponentChange::Remove]).unwrap(),
        None
    );
    assert!(matches!(
        resolve_component(
            OTHER,
            Some(b"old"),
            &[ComponentChange::Remove, ComponentChange::Update(b"x")]
        ),
        Err(AppDataError::Shape(OTHER))
    ));
}

/// room-policy-04's join_links component (suggested 0x002A) takes a `JoinLinksUpdate` of removals and additions, not
/// its new value, and this crate does not read it: an update to it, or to any component this crate does not know, is
/// refused rather than stored as the value. Revert check: take any component's last update as its value, and the
/// join-links update is stored.
#[test]
fn a_component_this_crate_does_not_read_is_refused() {
    const JOIN_LINKS: u16 = 0x002A;
    for component in [JOIN_LINKS, 0x0026, 0xF000] {
        assert!(
            matches!(
                resolve_component(component, None, &[ComponentChange::Update(b"diff")]),
                Err(AppDataError::Unknown(refused)) if refused == component
            ),
            "PLANT-MIMI-UNKNOWN-COMPONENT: component {component:#06x}"
        );
        assert!(matches!(
            resolve_component(component, Some(b"old"), &[ComponentChange::Remove]),
            Err(AppDataError::Unknown(_))
        ));
    }
}
