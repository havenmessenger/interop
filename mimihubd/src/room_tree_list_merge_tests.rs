//! Several participant-list updates in one Commit to a room whose tree the hub keeps, end to end through openmls: the hub
//! and the members resolve them with `mimi_core::app_data::resolve_component`, every update indexing the list before the
//! Commit (protocol-07 §7.5), and a Commit whose updates touch one user twice is refused.

use mimi_core::app_data::{resolve_component, ComponentChange};
use mimi_core::participant_list::{
    decode_participant_list_data, encode_participant_list_data, encode_participant_list_update,
    ParticipantListData, ParticipantListUpdate, UserRolePair,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
use mimi_core::room_policy::{Capability, Role, SingleSourceRoleChangeTargets};
use mimi_core::room_policy_wire::encode_role_data;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;

use crate::mls_fixtures::{group_info_after, Member};
use crate::peer::PeerIdentity;
use crate::room_tree::{PARTICIPANT_LIST_COMPONENT, ROLES_LIST_COMPONENT};
use crate::{Provider, UpdateRefusal};

const ROOM: &str = "mimi://hub.example/r/room";
const GROUP: &[u8] = b"mimi://example.com/g/room";
const ADMIN: u32 = 2;
const MEMBER: u32 = 3;
const NOW: u64 = 1_700_000_000;
const NAMES: [&str; 4] = ["alice", "bob", "carol", "dave"];

fn uri(name: &str) -> String {
    format!("mimi://example.com/u/{name}")
}

fn peer() -> PeerIdentity {
    PeerIdentity::signed("example.com")
}

/// An admin that may remove participants, and a member that may leave.
fn roles() -> Vec<Role> {
    let role = |index: u32, capabilities: Vec<Capability>, changes: &[(u32, &[u32])]| Role {
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
    };
    vec![
        role(
            ADMIN,
            vec![
                Capability::AddParticipant,
                Capability::RemoveParticipant,
                Capability::RemoveSelf,
            ],
            &[(0, &[MEMBER]), (MEMBER, &[0]), (ADMIN, &[0])],
        ),
        role(MEMBER, vec![Capability::RemoveSelf], &[(MEMBER, &[0])]),
    ]
}

struct Room {
    members: Vec<Member>,
    groups: Vec<MlsGroup>,
}

/// Alice's room with Bob, Carol and Dave added in one Commit and joined, listed in that order, and the hub seeded after
/// that Commit.
fn tracked_room(p: &Provider) -> Room {
    let members: Vec<Member> = NAMES.iter().map(|name| Member::new(&uri(name))).collect();
    let list = ParticipantListData {
        participants: NAMES
            .iter()
            .enumerate()
            .map(|(at, name)| UserRolePair {
                user_uri: uri(name),
                role_index: if at == 0 { ADMIN } else { MEMBER },
            })
            .collect(),
    };
    let mut alice = members[0].create_group_with(
        GROUP,
        &[
            (
                PARTICIPANT_LIST_COMPONENT,
                encode_participant_list_data(&list).unwrap(),
            ),
            (ROLES_LIST_COMPONENT, encode_role_data(&roles())),
        ],
    );
    let bundles: Vec<KeyPackageBundle> = members[1..]
        .iter()
        .map(Member::key_package_bundle)
        .collect();
    let key_packages: Vec<KeyPackage> = bundles
        .iter()
        .map(|bundle| bundle.key_package().clone())
        .collect();
    let (_commit, welcome, _group_info) = alice
        .add_members(&members[0].provider, &members[0].signer, &key_packages)
        .unwrap();
    alice.merge_pending_commit(&members[0].provider).unwrap();
    let welcome: MlsMessageIn = welcome.into();
    let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("not a Welcome");
    };
    let tree = alice.export_ratchet_tree();
    let mut groups = vec![];
    for member in &members[1..] {
        groups.push(
            StagedWelcome::new_from_welcome(
                &member.provider,
                &MlsGroupJoinConfig::builder()
                    .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .build(),
                welcome.clone(),
                Some(tree.clone().into()),
            )
            .unwrap()
            .into_group(&member.provider)
            .unwrap(),
        );
    }
    groups.insert(0, alice);
    let tree = groups[0]
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();
    p.seed_room_tree(
        ROOM,
        0,
        Some(&peer()),
        &GroupInfoOption {
            representation: GroupInfoRepresentation::Full,
            payload: group_info_after(&groups[0], &members[0]),
        },
        &[&[1u8][..], &tree].concat(),
    );
    assert!(
        p.room_tracking(ROOM).unwrap().is_some(),
        "the room is tracked"
    );
    Room { members, groups }
}

fn removing(index: u32) -> Vec<u8> {
    encode_participant_list_update(&ParticipantListUpdate {
        removed_indices: vec![index],
        ..Default::default()
    })
    .unwrap()
}

/// The leave of the member at `at`, also its index in the list: its Remove of itself and its list update.
fn leave(room: &mut Room, at: usize) -> Vec<Vec<u8>> {
    let (member, group) = (&room.members[at], &mut room.groups[at]);
    let remove = group.leave_group(&member.provider, &member.signer).unwrap();
    let (change, _) = group
        .propose_app_data_update(
            &member.provider,
            &member.signer,
            PARTICIPANT_LIST_COMPONENT,
            AppDataUpdateOperation::Update(removing(u32::try_from(at).unwrap()).into()),
        )
        .unwrap();
    vec![
        remove.tls_serialize_detached().unwrap(),
        change.tls_serialize_detached().unwrap(),
    ]
}

/// The member at `at` keeps another member's proposals for its next commit, or processes a commit.
fn deliver(room: &mut Room, at: usize, message: &[u8]) -> ProcessedMessageContent {
    let (member, group) = (&room.members[at], &mut room.groups[at]);
    let message =
        ProtocolMessage::try_from(MlsMessageIn::tls_deserialize_exact(message).unwrap()).unwrap();
    group
        .process_message(&member.provider, message)
        .unwrap()
        .into_content()
}

fn keep(room: &mut Room, at: usize, proposals: &[Vec<u8>]) {
    for proposal in proposals {
        let ProcessedMessageContent::ProposalMessage(queued) = deliver(room, at, proposal) else {
            panic!("a proposal");
        };
        let (member, group) = (&room.members[at], &mut room.groups[at]);
        group
            .store_pending_proposal(member.provider.storage(), *queued)
            .unwrap();
    }
}

/// Each component's changes, grouped in the order openmls hands them over, resolved together.
fn resolved<'a>(
    updater: &mut AppDataDictionaryUpdater<'_>,
    proposals: impl Iterator<Item = &'a AppDataUpdateProposal>,
) {
    let mut by_component: Vec<(u16, Vec<ComponentChange<'a>>)> = Vec::new();
    for proposal in proposals {
        let change = match proposal.operation() {
            AppDataUpdateOperation::Update(data) => ComponentChange::Update(data.as_slice()),
            AppDataUpdateOperation::Remove => ComponentChange::Remove,
        };
        match by_component.last_mut() {
            Some((component, changes)) if *component == proposal.component_id() => {
                changes.push(change);
            }
            _ => by_component.push((proposal.component_id(), vec![change])),
        }
    }
    for (component, changes) in by_component {
        let value = resolve_component(component, updater.old_value(component), &changes)
            .unwrap()
            .unwrap();
        updater.set(openmls::component::ComponentData::from_parts(
            component,
            value.into(),
        ));
    }
}

/// Alice's Commit of what she holds, with `own` updates of hers by value, resolved as every member resolves it; left
/// pending on her side.
fn alices_commit(room: &mut Room, own: &[Vec<u8>]) -> Vec<u8> {
    let (alice, group) = (&room.members[0], &mut room.groups[0]);
    let proposals = own.iter().map(|update| {
        Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
            PARTICIPANT_LIST_COMPONENT,
            update.clone(),
        )))
    });
    let mut stage = group
        .commit_builder()
        .add_proposals(proposals)
        .load_psks(alice.provider.storage())
        .unwrap();
    let proposals: Vec<AppDataUpdateProposal> =
        stage.app_data_update_proposals().cloned().collect();
    let mut updater = stage.app_data_dictionary_updater();
    resolved(&mut updater, proposals.iter());
    let changes = updater.changes();
    stage.with_app_data_dictionary_updates(changes);
    let (commit, _welcome, _group_info) = stage
        .build(
            alice.provider.rand(),
            alice.provider.crypto(),
            &alice.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&alice.provider)
        .unwrap()
        .into_contents();
    commit.tls_serialize_detached().unwrap()
}

fn group_list(group: &MlsGroup) -> Vec<String> {
    let value = group
        .extensions()
        .app_data_dictionary()
        .and_then(|extension| extension.dictionary().get(&PARTICIPANT_LIST_COMPONENT))
        .unwrap()
        .to_vec();
    decode_participant_list_data(&value)
        .unwrap()
        .participants
        .into_iter()
        .map(|participant| participant.user_uri)
        .collect()
}

/// The list in the GroupContext of the group the hub keeps for the room.
fn tracked_list(p: &Provider) -> Vec<String> {
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let group = openmls::group::PublicGroup::load(
        &p.store.groups(),
        &GroupId::from_slice(&tracking.group_id),
    )
    .unwrap()
    .unwrap();
    let value = group
        .group_context()
        .extensions()
        .app_data_dictionary()
        .and_then(|extension| extension.dictionary().get(&PARTICIPANT_LIST_COMPONENT))
        .unwrap()
        .to_vec();
    decode_participant_list_data(&value)
        .unwrap()
        .participants
        .into_iter()
        .map(|participant| participant.user_uri)
        .collect()
}

/// The hub's own participant table for the room.
fn hub_list(p: &Provider) -> Vec<String> {
    p.store
        .list_participant_rows(ROOM)
        .unwrap()
        .into_iter()
        .map(|row| row.member_uri)
        .collect()
}

fn apply(p: &Provider, commit: &[u8]) -> Result<(), UpdateRefusal> {
    p.apply_commit_bundle(ROOM, commit, None, Some(&peer()), NOW)
}

/// Bob (1) and Carol (2) leave at one epoch, and Alice's next Commit carries both leaves by reference. The hub resolves
/// it to Alice and Dave, in its table and in the GroupContext of the group it keeps; Alice and Dave, who stored the leaves
/// in the other order, hold the same list in theirs. Revert check: have the hub's group resolve a component's first update
/// only, and Carol stays listed there.
#[test]
fn two_leaves_in_one_commit_leave_alice_and_dave_at_the_hub_and_the_members() {
    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p);
    let bobs = leave(&mut room, 1);
    let carols = leave(&mut room, 2);
    for messages in [&bobs, &carols] {
        p.hold_leave_proposals(ROOM, Some(&peer()), messages.iter(), NOW)
            .unwrap();
    }
    keep(&mut room, 0, &[bobs.clone(), carols.clone()].concat());
    keep(&mut room, 3, &[carols, bobs].concat());
    let commit = alices_commit(&mut room, &[]);
    apply(&p, &commit).expect("the hub takes both leaves in one Commit");
    let both = vec![uri("alice"), uri("dave")];
    assert_eq!(hub_list(&p), both, "the hub's table lists Alice and Dave");
    assert_eq!(
        tracked_list(&p),
        both,
        "PLANT-HUB-TRACKED-TWO-LEAVES: the hub's group lists Alice and Dave"
    );

    room.groups[0]
        .merge_pending_commit(&room.members[0].provider)
        .unwrap();
    let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved) =
        deliver(&mut room, 3, &commit)
    else {
        panic!("a Commit with AppDataUpdates");
    };
    let (dave, group) = (&room.members[3], &mut room.groups[3]);
    let mut updater = group.app_data_dictionary_updater();
    resolved(&mut updater, unresolved.app_data_update_proposals());
    let changes = updater.changes();
    let staged = group
        .stage_app_data_commit(&dave.provider, *unresolved, changes)
        .unwrap();
    group.merge_staged_commit(&dave.provider, staged).unwrap();
    assert_eq!(group_list(&room.groups[0]), both);
    assert_eq!(group_list(&room.groups[3]), both);
}

/// Bob's held leave and an update of Alice's removing Bob again touch Bob twice in one Commit, which protocol-07 §7.5
/// says is not valid: the hub refuses it and its list stays as it was.
#[test]
fn a_commit_touching_one_user_twice_is_refused_at_the_hub() {
    let p = Provider::in_memory("hub.example").unwrap();
    let mut room = tracked_room(&p);
    let bobs = leave(&mut room, 1);
    p.hold_leave_proposals(ROOM, Some(&peer()), bobs.iter(), NOW)
        .unwrap();
    keep(&mut room, 0, &bobs);
    // Alice's own resolution would refuse it too, so her Commit carries what the hub must refuse by itself: a value
    // computed as if the second removal were not there.
    let (alice, group) = (&room.members[0], &mut room.groups[0]);
    let mut stage = group
        .commit_builder()
        .add_proposals([Proposal::AppDataUpdate(Box::new(
            AppDataUpdateProposal::update(PARTICIPANT_LIST_COMPONENT, removing(1)),
        ))])
        .load_psks(alice.provider.storage())
        .unwrap();
    let after = ParticipantListData {
        participants: [0, 2, 3]
            .iter()
            .map(|at| UserRolePair {
                user_uri: uri(NAMES[*at]),
                role_index: if *at == 0 { ADMIN } else { MEMBER },
            })
            .collect(),
    };
    let mut updater = stage.app_data_dictionary_updater();
    updater.set(openmls::component::ComponentData::from_parts(
        PARTICIPANT_LIST_COMPONENT,
        encode_participant_list_data(&after).unwrap().into(),
    ));
    let changes = updater.changes();
    stage.with_app_data_dictionary_updates(changes);
    let (commit, _welcome, _group_info) = stage
        .build(
            alice.provider.rand(),
            alice.provider.crypto(),
            &alice.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&alice.provider)
        .unwrap()
        .into_contents();
    let commit = commit.tls_serialize_detached().unwrap();
    assert!(
        apply(&p, &commit).is_err(),
        "PLANT-HUB-TRACKED-TOUCHED-TWICE: the hub refuses a Commit touching Bob twice"
    );
    let everyone: Vec<String> = NAMES.iter().map(|name| uri(name)).collect();
    assert_eq!(hub_list(&p), everyone);
    assert_eq!(tracked_list(&p), everyone);
}
