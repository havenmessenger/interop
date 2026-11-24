//! The role checks on a tracked room, through the hub's own paths: the room's policy and list taken from its
//! GroupContext at seeding, a Commit's changes authorized for its committer, a first `roles_list` by Commit refused, and
//! a held leave authorized for the leaver.

use mimi_core::participant_list::{
    apply_update, encode_participant_list_data, encode_participant_list_update,
    ParticipantListData, ParticipantListUpdate, UserRolePair, UserindexRolePair,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
use mimi_core::room_policy::{
    BaseRoomPolicy, Capability, Role, RoomPolicy, SingleSourceRoleChangeTargets,
};
use mimi_core::room_policy_wire::encode_role_data;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;

use crate::mls_fixtures::{add_and_join, app_data_commit, group_info_after, Member};
use crate::peer::PeerIdentity;
use crate::room_tree::{PARTICIPANT_LIST_COMPONENT, ROLES_LIST_COMPONENT};
use crate::{Provider, UpdateRefusal};

const ROOM: &str = "mimi://hub.example/r/room";
const GROUP: &[u8] = b"mimi://example.com/g/room";
const ALICE: &str = "mimi://example.com/u/alice";
const BOB: &str = "mimi://example.com/u/bob";
const ADMIN: u32 = 2;
const MEMBER: u32 = 3;
const NOW: u64 = 1_700_000_000;

fn role(index: u32, capabilities: Vec<Capability>, changes: &[(u32, &[u32])]) -> Role {
    Role {
        role_index: index,
        role_name: format!("role {index}"),
        capabilities,
        authorized_role_changes: changes
            .iter()
            .map(|(from, to)| SingleSourceRoleChangeTargets {
                from_role_index: *from,
                target_role_indexes: to.to_vec(),
            })
            .collect(),
    }
}

/// An admin that may add, remove and promote members and leave; a member that may leave (`member_may_leave`) and
/// nothing else.
fn roles(member_may_leave: bool) -> Vec<Role> {
    let member_capabilities = if member_may_leave {
        vec![Capability::RemoveSelf]
    } else {
        Vec::new()
    };
    vec![
        role(
            ADMIN,
            vec![
                Capability::AddParticipant,
                Capability::RemoveParticipant,
                Capability::ChangeRole,
                Capability::RemoveSelf,
                Capability::ChangeRoleDefinitions,
                Capability::ChangeRoomMembershipStyle,
            ],
            &[(0, &[MEMBER]), (MEMBER, &[0, ADMIN]), (ADMIN, &[0])],
        ),
        role(MEMBER, member_capabilities, &[(MEMBER, &[0])]),
    ]
}

/// Alice an admin and Bob a member.
fn list() -> ParticipantListData {
    ParticipantListData {
        participants: vec![
            UserRolePair {
                user_uri: ALICE.into(),
                role_index: ADMIN,
            },
            UserRolePair {
                user_uri: BOB.into(),
                role_index: MEMBER,
            },
        ],
    }
}

struct Room {
    alice: Member,
    bob: Member,
    group: MlsGroup,
    bob_group: MlsGroup,
}

/// Alice's group, created with `roles` (or no `roles_list`) and the list in its GroupContext, Bob added and joined, and
/// the hub seeded from the bundle after that Commit.
fn tracked_room(p: &Provider, roles: Option<&[Role]>) -> Room {
    let alice = Member::new(ALICE);
    let bob = Member::new(BOB);
    let mut components = vec![(
        PARTICIPANT_LIST_COMPONENT,
        encode_participant_list_data(&list()).unwrap(),
    )];
    if let Some(roles) = roles {
        components.push((ROLES_LIST_COMPONENT, encode_role_data(roles)));
    }
    let mut group = alice.create_group_with(GROUP, &components);
    let bob_group = add_and_join(&mut group, &alice, &bob);
    let tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();
    p.seed_room_tree(
        ROOM,
        0,
        Some(&PeerIdentity::signed("example.com")),
        &GroupInfoOption {
            representation: GroupInfoRepresentation::Full,
            payload: group_info_after(&group, &alice),
        },
        &[&[1u8][..], &tree].concat(),
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_some(),
        "the room is tracked"
    );
    Room {
        alice,
        bob,
        group,
        bob_group,
    }
}

/// The AppDataUpdate for a participant-list change, and the list's value after it, from the list as it is now.
fn list_update(p: &Provider, update: &ParticipantListUpdate) -> (u16, Vec<u8>, Vec<u8>) {
    let now = ParticipantListData {
        participants: p
            .store
            .list_participant_rows(ROOM)
            .unwrap()
            .into_iter()
            .map(|row| UserRolePair {
                user_uri: row.member_uri,
                role_index: row.role_index.unwrap_or(0),
            })
            .collect(),
    };
    let after = apply_update(&now, update).unwrap();
    (
        PARTICIPANT_LIST_COMPONENT,
        encode_participant_list_update(update).unwrap(),
        encode_participant_list_data(&after).unwrap(),
    )
}

fn change_role(index: u32, to: u32) -> ParticipantListUpdate {
    ParticipantListUpdate {
        changed_role_participants: vec![UserindexRolePair {
            user_index: index,
            role_index: to,
        }],
        ..Default::default()
    }
}

fn apply(p: &Provider, commit: &[u8]) -> Result<(), UpdateRefusal> {
    p.apply_commit_bundle(
        ROOM,
        commit,
        None,
        Some(&PeerIdentity::signed("example.com")),
        NOW,
    )
}

fn role_of(p: &Provider, uri: &str) -> Option<u32> {
    p.store
        .list_participant_rows(ROOM)
        .unwrap()
        .into_iter()
        .find(|row| row.member_uri == uri)
        .and_then(|row| row.role_index)
}

/// Seeding takes the room's policy and list from its GroupContext, over a policy the operator stored before, and a
/// GroupContext with no `roles_list` leaves the room with none. Revert check: keep the stored policy at seeding, and the
/// operator's roles stay.
#[test]
fn seeding_takes_the_policy_and_list_from_the_group_context() {
    let p = Provider::in_memory("hub.example").unwrap();
    let stored = RoomPolicy {
        base: BaseRoomPolicy::default(),
        roles: vec![role(5, vec![Capability::SendMessage], &[])],
    };
    p.set_room_policy(ROOM, &stored, NOW).unwrap();
    let _room = tracked_room(&p, Some(&roles(true)));
    assert_eq!(
        p.room_policy(ROOM).unwrap().map(|policy| policy.roles),
        Some(roles(true)),
        "PLANT-SEED-POLICY: the room kept the operator's policy over its GroupContext's"
    );
    assert_eq!(role_of(&p, ALICE), Some(ADMIN));
    assert_eq!(role_of(&p, BOB), Some(MEMBER));

    let p = Provider::in_memory("hub.example").unwrap();
    p.set_room_policy(ROOM, &stored, NOW).unwrap();
    let _room = tracked_room(&p, None);
    assert!(p.room_policy(ROOM).unwrap().is_none());
}

/// A change a Commit carries by value is the committer's: Bob, a member, cannot make Alice a member, and Alice cannot
/// change her own role; Alice, an admin, makes Bob an admin. Revert check: skip the committer check, and Bob's Commit is
/// accepted.
#[test]
fn a_commits_changes_are_authorized_for_its_committer() {
    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p, Some(&roles(true)));
    let bobs = app_data_commit(
        &mut room.bob_group,
        &room.bob,
        &[list_update(&p, &change_role(0, MEMBER))],
    );
    assert!(
        matches!(apply(&p, &bobs), Err(UpdateRefusal::Policy(_))),
        "PLANT-ROLE-COMMITTER: a member's Commit changed an admin's role"
    );
    assert_eq!(role_of(&p, ALICE), Some(ADMIN));

    let own = app_data_commit(
        &mut room.group,
        &room.alice,
        &[list_update(&p, &change_role(0, MEMBER))],
    );
    assert!(matches!(apply(&p, &own), Err(UpdateRefusal::Policy(_))));
    room.group
        .clear_pending_commit(room.alice.provider.storage())
        .unwrap();

    let promote = app_data_commit(
        &mut room.group,
        &room.alice,
        &[list_update(&p, &change_role(1, ADMIN))],
    );
    apply(&p, &promote).unwrap();
    room.group
        .merge_pending_commit(&room.alice.provider)
        .unwrap();
    assert_eq!(role_of(&p, BOB), Some(ADMIN));
}

/// A `roles_list` is set when the group is created (room-policy PR #52): a Commit adding one to a tracked room whose
/// group has none is refused, and one replacing a group's `roles_list` is not. Revert check: drop the refusal, and the
/// first `roles_list` is accepted.
#[test]
fn a_first_roles_list_by_commit_is_refused() {
    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p, None);
    let roles_list = encode_role_data(&roles(true));
    let first = app_data_commit(
        &mut room.group,
        &room.alice,
        &[(ROLES_LIST_COMPONENT, roles_list.clone(), roles_list.clone())],
    );
    assert!(
        matches!(apply(&p, &first), Err(UpdateRefusal::Policy(_))),
        "PLANT-FIRST-ROLES-LIST: a Commit added a roles_list to a group that had none"
    );
    assert!(p.room_policy(ROOM).unwrap().is_none());

    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p, Some(&roles(true)));
    let narrower = encode_role_data(&roles(false));
    let replace = app_data_commit(
        &mut room.group,
        &room.alice,
        &[(ROLES_LIST_COMPONENT, narrower.clone(), narrower)],
    );
    apply(&p, &replace).unwrap();
    assert_eq!(
        p.room_policy(ROOM).unwrap().map(|policy| policy.roles),
        Some(roles(false))
    );
}

/// Bob's leave and its participant-list change, as the MLSMessage proposals his client sends.
fn bobs_leave(room: &mut Room) -> Vec<Vec<u8>> {
    let remove = room
        .bob_group
        .leave_group(&room.bob.provider, &room.bob.signer)
        .unwrap();
    let update = encode_participant_list_update(&ParticipantListUpdate {
        removed_indices: vec![1],
        ..Default::default()
    })
    .unwrap();
    let (change, _reference) = room
        .bob_group
        .propose_app_data_update(
            &room.bob.provider,
            &room.bob.signer,
            PARTICIPANT_LIST_COMPONENT,
            AppDataUpdateOperation::Update(update.into()),
        )
        .unwrap();
    vec![
        remove.tls_serialize_detached().unwrap(),
        change.tls_serialize_detached().unwrap(),
    ]
}

/// A held leave is authorized for its proposer, the leaver: Bob leaves while his role holds `canRemoveSelf`, and not
/// once it does not, though Alice, who will commit it, could remove him. Revert check: drop the check where the leave is
/// held, and Bob's leave without the capability is held.
#[test]
fn a_held_leave_is_authorized_for_the_leaver() {
    let peer = PeerIdentity::signed("example.com");
    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p, Some(&roles(true)));
    let leave = bobs_leave(&mut room);
    p.hold_leave_proposals(ROOM, Some(&peer), leave.iter(), NOW)
        .unwrap();

    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p, Some(&roles(false)));
    let leave = bobs_leave(&mut room);
    assert!(
        p.hold_leave_proposals(ROOM, Some(&peer), leave.iter(), NOW)
            .is_err(),
        "PLANT-HELD-LEAVE: a leave was held for a member without canRemoveSelf"
    );
}

/// A member's Commit that removes another listed user's client, with no change to the list, is refused: only the user
/// removes its own client from a list it stays on (room-policy-04 §8.1.2). Revert check: drop the hub's pairing check,
/// and Alice's Remove of Bob's client is accepted.
#[test]
fn removing_another_listed_users_client_is_refused() {
    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p, Some(&roles(true)));
    let (commit, _, _) = room
        .group
        .remove_members(
            &room.alice.provider,
            &room.alice.signer,
            &[LeafNodeIndex::new(1)],
        )
        .unwrap();
    let refused = apply(&p, &commit.tls_serialize_detached().unwrap());
    assert!(
        matches!(
            refused,
            Err(UpdateRefusal::Invalid(why)) if why == crate::list_leaves::CLIENT_OF_ANOTHER
        ),
        "PLANT-HUB-OWN-CLIENT-E2E: another user's client was removed while the user stays listed: {refused:?}"
    );
    assert_eq!(role_of(&p, BOB), Some(MEMBER));
}

/// A client's new leaf must name its own user: Bob commits a self-update whose update-path leaf carries Carol's
/// credential, signed with her key as a renamed leaf must be, and the hub refuses it with the room at its epoch.
/// Revert check: stop collecting renewed leaves in `list_and_leaves`, and the renamed leaf is accepted.
#[test]
fn a_self_update_that_names_another_user_is_refused() {
    use openmls_traits::OpenMlsProvider as _;
    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p, Some(&roles(true)));
    let carol = Member::new("mimi://example.com/u/carol");
    let epoch = || {
        let tracking = p.room_tracking(ROOM).unwrap().unwrap();
        PublicGroup::load(&p.store.groups(), &GroupId::from_slice(&tracking.group_id))
            .unwrap()
            .unwrap()
            .group_context()
            .epoch()
            .as_u64()
    };
    let before = epoch();
    let (commit, _, _) = room
        .bob_group
        .commit_builder()
        .force_self_update(true)
        .load_psks(room.bob.provider.storage())
        .unwrap()
        .build_with_new_signer(
            room.bob.provider.rand(),
            room.bob.provider.crypto(),
            &room.bob.signer,
            NewSignerBundle {
                signer: &carol.signer,
                credential_with_key: carol.credential.clone(),
            },
            |_| true,
        )
        .unwrap()
        .stage_commit(&room.bob.provider)
        .unwrap()
        .into_contents();
    let refused = apply(&p, &commit.tls_serialize_detached().unwrap());
    assert!(
        matches!(
            refused,
            Err(UpdateRefusal::Invalid(why)) if why == crate::list_leaves::CLIENT_CHANGES_USER
        ),
        "PLANT-HUB-SAME-USER-E2E: a self-update naming another user was taken: {refused:?}"
    );
    assert_eq!(epoch(), before);
}

/// The operator's routes answer 409 for a tracked room: its policy and list are its group's, changed by a Commit. An
/// untracked room's are still the operator's to set. Revert check: drop the tracked check, and `addParticipant` lists
/// Carol in the tracked room.
#[tokio::test]
async fn the_operators_routes_refuse_a_tracked_room() {
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    let p = Provider::in_memory("hub.example").unwrap();
    let _room = tracked_room(&p, Some(&roles(true)));
    let shared = std::sync::Arc::new(std::sync::Mutex::new(p));
    let router = crate::admin::build_admin_router(shared.clone());
    let carol = "mimi://example.com/u/carol";
    let send = |uri: String| {
        let router = router.clone();
        async move {
            router
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(
        send(format!(
            "/mimi/v1/addParticipant?room={ROOM}&member={carol}"
        ))
        .await,
        StatusCode::CONFLICT,
        "PLANT-OPERATOR-TRACKED: the operator changed a tracked room's list"
    );
    assert_eq!(
        send(format!(
            "/mimi/v1/memberRole?room={ROOM}&member={BOB}&role={ADMIN}"
        ))
        .await,
        StatusCode::CONFLICT
    );
    assert!(role_of(&shared.lock().unwrap(), carol).is_none());
    assert_eq!(role_of(&shared.lock().unwrap(), BOB), Some(MEMBER));

    let untracked = "mimi://hub.example/r/other";
    assert_eq!(
        send(format!(
            "/mimi/v1/addParticipant?room={untracked}&member={carol}"
        ))
        .await,
        StatusCode::CREATED
    );
}

/// Replacing the roles needs canChangeRoleDefinitions, and the base policy canChangeRoomMembershipStyle, in the
/// committer's role: Bob (a member, holding neither) is refused both, and Alice (an admin, holding both) makes both.
/// Revert check: skip the capability check, and Bob replaces the room's roles.
#[test]
fn a_policy_change_needs_its_capability() {
    use mimi_core::room_policy::BaseRoomPolicy;
    use mimi_core::room_policy_wire::encode_base_room_policy;
    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p, Some(&roles(true)));
    let narrower = encode_role_data(&roles(false));
    let bobs = app_data_commit(
        &mut room.bob_group,
        &room.bob,
        &[(ROLES_LIST_COMPONENT, narrower.clone(), narrower.clone())],
    );
    assert!(
        matches!(apply(&p, &bobs), Err(UpdateRefusal::Policy(_))),
        "PLANT-ROLES-CAPABILITY: a member replaced the room's roles"
    );
    assert_eq!(
        p.room_policy(ROOM).unwrap().map(|policy| policy.roles),
        Some(roles(true))
    );
    room.bob_group
        .clear_pending_commit(room.bob.provider.storage())
        .unwrap();

    let base = encode_base_room_policy(
        &BaseRoomPolicy {
            discoverable: true,
            ..BaseRoomPolicy::default()
        },
        None,
    );
    let bobs_base = app_data_commit(
        &mut room.bob_group,
        &room.bob,
        &[(
            crate::room_tree::BASE_ROOM_POLICY_COMPONENT,
            base.clone(),
            base.clone(),
        )],
    );
    assert!(
        matches!(apply(&p, &bobs_base), Err(UpdateRefusal::Policy(_))),
        "PLANT-BASE-CAPABILITY: a member changed the room's base policy"
    );

    let alices = app_data_commit(
        &mut room.group,
        &room.alice,
        &[(
            crate::room_tree::BASE_ROOM_POLICY_COMPONENT,
            base.clone(),
            base,
        )],
    );
    apply(&p, &alices).unwrap();
    assert!(p.room_policy(ROOM).unwrap().unwrap().base.discoverable);
}
