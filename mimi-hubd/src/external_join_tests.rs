//! External Commits to a tracked room, made by openmls: who may join, what the room's operational policy and the hub's
//! policy decide, and the refusals (proposals held, a room whose tree is not kept). A change to the operational policy
//! needs its capability.

use mimi_core::operational_parameters::{
    encode_operational_parameters, OperationalParameters, OPERATIONAL_POLICY_COMPONENT_ID,
};
use mimi_core::participant_list::{
    encode_participant_list_data, ParticipantListData, UserRolePair,
};
use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation};
use mimi_core::room_policy::{Capability, Role, SingleSourceRoleChangeTargets};
use mimi_core::room_policy_wire::encode_role_data;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;

use crate::mls_fixtures::{
    add_and_join, app_data_commit, external_commit, group_info_after, Member,
};
use crate::peer::PeerIdentity;
use crate::policy::{ExternalCommitWhenUnset, HubPolicy};
use crate::room_tree::{PARTICIPANT_LIST_COMPONENT, ROLES_LIST_COMPONENT};
use crate::{Provider, UpdateRefusal};

const ROOM: &str = "mimi://example.com/r/room";
const GROUP: &[u8] = b"mimi://example.com/g/room";
const ALICE: &str = "mimi://example.com/u/alice";
const BOB: &str = "mimi://example.com/u/bob";
const NOW: u64 = 1_700_000_000;

fn roles(member_adds_own_client: bool) -> Vec<Role> {
    let role = |index: u32, capabilities: Vec<Capability>| Role {
        role_index: index,
        role_name: format!("role {index}"),
        capabilities,
        authorized_role_changes: vec![
            SingleSourceRoleChangeTargets {
                from_role_index: 0,
                target_role_indexes: vec![3],
            },
            SingleSourceRoleChangeTargets {
                from_role_index: 3,
                target_role_indexes: vec![0],
            },
        ],
    };
    let mut member = vec![Capability::SendMessage, Capability::RemoveSelf];
    if member_adds_own_client {
        member.push(Capability::AddOwnClient);
    }
    vec![
        role(
            2,
            vec![
                Capability::AddParticipant,
                Capability::AddOwnClient,
                Capability::ChangeMlsOperationalPolicies,
            ],
        ),
        role(3, member),
    ]
}

fn operational(external_commit_allowed: bool) -> OperationalParameters {
    OperationalParameters {
        external_commit_allowed,
        ..Default::default()
    }
}

struct Room {
    alice: Member,
    bob: Member,
    group: MlsGroup,
    bob_group: MlsGroup,
}

/// Alice's room with Bob added, its GroupContext carrying the list, `roles` and `ops` if given; the hub seeded from it
/// (or not, with `track` false: the hub then only lists the two).
fn room(p: &Provider, roles: &[Role], ops: Option<&OperationalParameters>, track: bool) -> Room {
    let alice = Member::new(ALICE);
    let bob = Member::new(BOB);
    let list = ParticipantListData {
        participants: vec![
            UserRolePair {
                user_uri: ALICE.into(),
                role_index: 2,
            },
            UserRolePair {
                user_uri: BOB.into(),
                role_index: 3,
            },
        ],
    };
    let mut components = vec![
        (
            PARTICIPANT_LIST_COMPONENT,
            encode_participant_list_data(&list).unwrap(),
        ),
        (ROLES_LIST_COMPONENT, encode_role_data(roles)),
    ];
    if let Some(ops) = ops {
        components.push((
            OPERATIONAL_POLICY_COMPONENT_ID,
            encode_operational_parameters(ops),
        ));
    }
    let mut group = alice.create_group_with(GROUP, &components);
    let bob_group = add_and_join(&mut group, &alice, &bob);
    if track {
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
        assert!(p.room_tracking(ROOM).unwrap().is_some());
    } else {
        p.add_participant(ROOM, ALICE, NOW).unwrap();
        p.add_participant(ROOM, BOB, NOW).unwrap();
    }
    Room {
        alice,
        bob,
        group,
        bob_group,
    }
}

/// Bob's second client joins the room by external Commit, from the GroupInfo and tree the room publishes.
fn bobs_new_client(room: &Room) -> Vec<u8> {
    let second = Member::new(BOB);
    let info = group_info_after(&room.group, &room.alice);
    external_commit(&info, room.group.export_ratchet_tree().into(), &second).0
}

fn apply(p: &Provider, commit: &[u8]) -> Result<(), UpdateRefusal> {
    apply_from(p, commit, Some("example.com"))
}

fn apply_from(p: &Provider, commit: &[u8], peer: Option<&str>) -> Result<(), UpdateRefusal> {
    let peer = peer.map(PeerIdentity::signed);
    p.apply_commit_bundle(ROOM, commit, None, peer.as_ref(), NOW)
}

/// A listed user whose role holds canAddOwnClient adds a client by external Commit; the room's tree has it. Revert
/// check: refuse every external Commit, and this one is refused.
#[test]
fn a_listed_users_new_client_joins_by_external_commit() {
    let p = Provider::in_memory("example.com").unwrap();
    let room = room(&p, &roles(true), None, true);
    assert!(
        apply(&p, &bobs_new_client(&room)).is_ok(),
        "PLANT-EXTERNAL-ACCEPT"
    );
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let group = PublicGroup::load(&p.store.groups(), &GroupId::from_slice(&tracking.group_id))
        .unwrap()
        .unwrap();
    assert_eq!(group.members().count(), 3);
}

/// The user an external Commit's new leaf names must belong to the provider that sent it: another provider, or a
/// request with no provider's proof, cannot add a client in that user's name. Revert check: skip the provider check,
/// and other.example adds a client as Bob.
#[test]
fn only_the_joiners_own_provider_sends_its_external_commit() {
    let p = Provider::in_memory("example.com").unwrap();
    let room = room(&p, &roles(true), None, true);
    let commit = bobs_new_client(&room);
    for peer in [Some("other.example"), None] {
        assert!(
            matches!(apply_from(&p, &commit, peer), Err(UpdateRefusal::Policy(_))),
            "PLANT-EXTERNAL-PROVIDER: {peer:?} added a client as a user of example.com"
        );
    }
    let tracking = p.room_tracking(ROOM).unwrap().unwrap();
    let group = PublicGroup::load(&p.store.groups(), &GroupId::from_slice(&tracking.group_id))
        .unwrap()
        .unwrap();
    assert_eq!(group.members().count(), 2);
    apply_from(&p, &commit, Some("example.com")).unwrap();
}

/// Without canAddOwnClient, with the room's policy saying no, or with the hub's policy denying a room that says
/// nothing, the external Commit is refused and the tree does not move. Revert check: skip the role check, and Bob's
/// second client joins without the capability.
#[test]
fn the_role_and_the_policies_decide() {
    let p = Provider::in_memory("example.com").unwrap();
    let room_ = room(&p, &roles(false), None, true);
    assert!(
        matches!(
            apply(&p, &bobs_new_client(&room_)),
            Err(UpdateRefusal::Policy(_))
        ),
        "PLANT-EXTERNAL-ROLE: a client joined without canAddOwnClient"
    );

    let p = Provider::in_memory("example.com").unwrap();
    let room_ = room(&p, &roles(true), Some(&operational(false)), true);
    assert!(
        matches!(
            apply(&p, &bobs_new_client(&room_)),
            Err(UpdateRefusal::Policy(_))
        ),
        "PLANT-EXTERNAL-FLAG: the room's policy said no"
    );
    assert!(
        p.store.kept_group_info(ROOM).unwrap().is_none(),
        "a GroupInfo was kept for a closed room"
    );

    let deny = HubPolicy {
        external_commit_when_unset: ExternalCommitWhenUnset::Deny,
        ..HubPolicy::default()
    };
    let p = Provider::in_memory("example.com")
        .unwrap()
        .with_policy(deny);
    let room_ = room(&p, &roles(true), None, true);
    assert!(matches!(
        apply(&p, &bobs_new_client(&room_)),
        Err(UpdateRefusal::Policy(_))
    ));

    // An open room keeps the seeding bundle's GroupInfo; after a Commit with no Full GroupInfo it keeps none.
    let p = Provider::in_memory("example.com").unwrap();
    let room_ = room(&p, &roles(true), Some(&operational(true)), true);
    assert!(p.store.kept_group_info(ROOM).unwrap().is_some());
    assert!(apply(&p, &bobs_new_client(&room_)).is_ok());
    assert!(p.store.kept_group_info(ROOM).unwrap().is_none());
}

/// An external Commit is refused while proposals are held for the epoch (this hub staples none), and to a room whose
/// tree the hub does not keep.
#[test]
fn held_proposals_and_an_untracked_room_refuse_it() {
    let p = Provider::in_memory("example.com").unwrap();
    let mut room_ = room(&p, &roles(true), None, true);
    let remove = room_
        .bob_group
        .leave_group(&room_.bob.provider, &room_.bob.signer)
        .unwrap();
    let update = mimi_core::participant_list::encode_participant_list_update(
        &mimi_core::participant_list::ParticipantListUpdate {
            removed_indices: vec![1],
            ..Default::default()
        },
    )
    .unwrap();
    let (change, _) = room_
        .bob_group
        .propose_app_data_update(
            &room_.bob.provider,
            &room_.bob.signer,
            PARTICIPANT_LIST_COMPONENT,
            AppDataUpdateOperation::Update(update.into()),
        )
        .unwrap();
    let held = [
        remove.tls_serialize_detached().unwrap(),
        change.tls_serialize_detached().unwrap(),
    ];
    p.hold_leave_proposals(
        ROOM,
        Some(&PeerIdentity::signed("example.com")),
        held.iter(),
        NOW,
    )
    .unwrap();
    assert!(
        matches!(
            apply(&p, &bobs_new_client(&room_)),
            Err(UpdateRefusal::Policy(_))
        ),
        "PLANT-EXTERNAL-HELD: an external Commit passed held proposals"
    );

    let p = Provider::in_memory("example.com").unwrap();
    let room_ = room(&p, &roles(true), None, false);
    assert!(matches!(
        apply(&p, &bobs_new_client(&room_)),
        Err(UpdateRefusal::Policy(_))
    ));
}

/// A change to the room's operational policy needs canChangeMlsOperationalPolicies: Bob (without it) is refused,
/// Alice (with it) sets it. Revert check: skip the capability check, and Bob's change is applied.
#[test]
fn an_operational_policy_change_needs_its_capability() {
    let p = Provider::in_memory("example.com").unwrap();
    let mut room_ = room(&p, &roles(true), Some(&operational(true)), true);
    let closed = encode_operational_parameters(&operational(false));
    let bobs = app_data_commit(
        &mut room_.bob_group,
        &room_.bob,
        &[(
            OPERATIONAL_POLICY_COMPONENT_ID,
            closed.clone(),
            closed.clone(),
        )],
    );
    assert!(
        matches!(apply(&p, &bobs), Err(UpdateRefusal::Policy(_))),
        "PLANT-OPS-CAPABILITY: a member changed the operational policy"
    );
    let alices = app_data_commit(
        &mut room_.group,
        &room_.alice,
        &[(OPERATIONAL_POLICY_COMPONENT_ID, closed.clone(), closed)],
    );
    apply(&p, &alices).unwrap();
    assert!(
        !p.operational_parameters(ROOM)
            .unwrap()
            .unwrap()
            .external_commit_allowed
    );
    assert!(!p.external_commits_allowed(ROOM).unwrap());
}

// ---------------------------------------------------------------- the groupInfo route

mod group_info_route {
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Extension;
    use http_body_util::BodyExt;
    use mimi_core::group_info_wire::{verify_group_info_response, GroupInfoRequest};
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::crypto::OpenMlsCrypto;
    use openmls_traits::types::{Ciphersuite, SignatureScheme};
    use openmls_traits::OpenMlsProvider;
    use tower::ServiceExt;

    use super::*;
    use crate::peer::PeerCert;

    /// A signed GroupInfoRequest from a client of `user`, with its HPKE key pair.
    fn request(
        user: &str,
        joining_code: Option<&[u8]>,
    ) -> (Vec<u8>, openmls_traits::types::HpkeKeyPair) {
        let crypto = OpenMlsRustCrypto::default();
        let (private, public) = crypto
            .crypto()
            .signature_key_gen(SignatureScheme::ED25519)
            .unwrap();
        let hpke = crypto
            .crypto()
            .derive_hpke_keypair(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.hpke_config(),
                &[3u8; 32],
            )
            .unwrap();
        let bytes = GroupInfoRequest::sign(
            &private,
            &public,
            BasicCredential::new(user.as_bytes().to_vec()).into(),
            &hpke.public,
            joining_code,
        )
        .unwrap();
        (bytes, hpke)
    }

    async fn ask(p: Provider, room: &str, peer: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let response = crate::http::build_router(Arc::new(Mutex::new(p)))
            .layer(Extension(PeerCert(Some(PeerIdentity::signed(peer)))))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/mimi/pl/groupInfo/{}",
                        room.replace(':', "%3A").replace('/', "%2F")
                    ))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        (
            status,
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
    }

    fn signed_hub(p: Provider) -> Provider {
        p.with_hub_signer(Arc::new(
            crate::group_info_endpoint::hub_signer_from_seed(&[5u8; 32], "example.com").unwrap(),
        ))
    }

    /// A listed user who may add a client of its own gets the room's GroupInfo, its tree and the held proposals,
    /// encrypted to its key, in an answer signed by the hub's key; the payload starts with the kept GroupInfo. Revert
    /// check: answer without signing, and the answer does not verify.
    #[tokio::test]
    async fn a_listed_user_gets_the_groupinfo_signed_and_encrypted() {
        let p = Provider::in_memory("example.com").unwrap();
        let _room = room(&p, &roles(true), None, true);
        let (epoch, kept) = p.store.kept_group_info(ROOM).unwrap().unwrap();
        assert_eq!(epoch, 1);
        let p = signed_hub(p);
        let hub_key = p.hub_signer.as_ref().unwrap().public_key.clone();
        let (body, hpke) = request(BOB, None);
        let (status, answer) = ask(p, ROOM, "example.com", body).await;
        assert_eq!(status, StatusCode::OK);
        let (key, encrypted) = verify_group_info_response(&answer).expect("PLANT-GROUPINFO-SIGNED");
        assert_eq!(key, hub_key);
        let mut info = Vec::new();
        tls_codec::Serialize::tls_serialize(
            &tls_codec::VLBytes::new(b"MLS 1.0 GroupInfo and ratchet_tree encryption".to_vec()),
            &mut info,
        )
        .unwrap();
        tls_codec::Serialize::tls_serialize(
            &tls_codec::VLBytes::new(ROOM.as_bytes().to_vec()),
            &mut info,
        )
        .unwrap();
        let opened = OpenMlsRustCrypto::default()
            .crypto()
            .hpke_open(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.hpke_config(),
                &encrypted,
                hpke.private.as_ref(),
                &info,
                &[],
            )
            .unwrap();
        assert!(opened.starts_with(&kept));
        assert_eq!(
            opened[kept.len()],
            1,
            "the tree follows as a full RatchetTreeOption"
        );
    }

    /// Refused as notAuthorized: a role without canAddOwnClient, a joining code, a requester of another provider than
    /// the one asking, and a hub with no MLS key; a room this hub does not host is 404. Revert check: skip the role
    /// check, and the member without the capability gets the GroupInfo.
    #[tokio::test]
    async fn what_may_not_fetch_it_is_not_authorized() {
        let not_authorized = |answer: &[u8]| answer.last() == Some(&2) && answer.len() < 64;
        let p = Provider::in_memory("example.com").unwrap();
        let _room = room(&p, &roles(false), None, true);
        let (status, answer) = ask(signed_hub(p), ROOM, "example.com", request(BOB, None).0).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            not_authorized(&answer),
            "PLANT-GROUPINFO-ROLE: a member without canAddOwnClient got it"
        );

        for (peer, code, signer) in [
            ("example.com", Some(&b"code"[..]), true),
            ("other.example", None, true),
            ("example.com", None, false),
        ] {
            let p = Provider::in_memory("example.com").unwrap();
            let _room = room(&p, &roles(true), None, true);
            let p = if signer { signed_hub(p) } else { p };
            let (status, answer) = ask(p, ROOM, peer, request(BOB, code).0).await;
            assert_eq!(status, StatusCode::OK);
            assert!(not_authorized(&answer), "{peer} {code:?} {signer}");
        }

        let p = signed_hub(Provider::in_memory("example.com").unwrap());
        let (status, _) = ask(
            p,
            "mimi://other.example/r/room",
            "example.com",
            request(BOB, None).0,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
