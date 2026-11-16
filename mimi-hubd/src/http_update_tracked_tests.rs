//! The joint IETF 127 UpdateRequest vectors (from mimid) replayed against a hub that keeps the room's ratchet tree: the
//! room is seeded from the setup's GroupInfo and tree, so every Commit the hub accepts is verified against the tree and
//! moves it on. A tree modelled wrong shows here as a refused Commit.

use mimi_core::protocol_wire::{GroupInfoOption, GroupInfoRepresentation, UpdateRoomResponse};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{GroupId, MlsMessageBodyIn, MlsMessageIn, PublicGroup};

use super::tests::update_answer;
use super::update_tests::post;
use crate::http::SharedProvider;
use crate::peer::PeerIdentity;

fn from_hex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// The setup's GroupInfo is an MLSMessage; a bundle's `GroupInfoOption` carries it bare.
fn bare_group_info(message: &[u8]) -> Vec<u8> {
    match MlsMessageIn::tls_deserialize_exact(message)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::GroupInfo(info) => info.tls_serialize_detached().unwrap(),
        other => panic!("the setup's group_info is not a GroupInfo: {other:?}"),
    }
}

fn tracked_epoch(p: &SharedProvider, room: &str) -> Option<u64> {
    let p = p.lock().unwrap();
    let tracking = p.room_tracking(room).unwrap()?;
    PublicGroup::load(&p.store.groups(), &GroupId::from_slice(&tracking.group_id))
        .unwrap()
        .map(|group| group.group_context().epoch().as_u64())
}

/// Every joint vector gets Haven's recorded answer with the room's tree tracked, and each Commit the hub accepts moves
/// the tree to the next epoch: jt-mls-02's Commit, and jt-mls-03's earlier one before its stale Commit is refused.
/// Revert check: stop merging accepted Commits into the tree, and the epochs after stay at the setup's.
#[tokio::test]
async fn the_joint_vectors_get_their_answers_with_the_tree_tracked() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/joint-ietf127-mls-vectors.json"
    ))
    .unwrap();
    let setup = &vectors["setup"];
    let setup_epoch = setup["epoch"].as_u64().unwrap();
    let mut checked = 0;
    for vector in vectors["vectors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let room = vector["room"].as_str().unwrap();
        let p: SharedProvider = std::sync::Arc::new(std::sync::Mutex::new(
            crate::Provider::in_memory(setup["hub_domain"].as_str().unwrap()).unwrap(),
        ));
        let router = crate::http::build_router(p.clone());
        let policy = mimi_core::room_policy::RoomPolicy {
            base: mimi_core::room_policy_wire::decode_base_room_policy(&from_hex(
                setup["base_room_policy"].as_str().unwrap(),
            ))
            .unwrap(),
            roles: mimi_core::room_policy_wire::decode_role_data(&from_hex(
                setup["roles_list"].as_str().unwrap(),
            ))
            .unwrap(),
        };
        let role = setup["participant_role_index"].as_u64().unwrap();
        {
            let hub = p.lock().unwrap();
            for user in vector["participants_before"].as_array().unwrap() {
                hub.add_participant(room, user.as_str().unwrap(), role)
                    .unwrap();
            }
            hub.set_room_policy(room, &policy, 1_700_000_000).unwrap();
            let tree = [
                &[1u8][..],
                &from_hex(setup["ratchet_tree"].as_str().unwrap()),
            ]
            .concat();
            let group_info = GroupInfoOption {
                representation: GroupInfoRepresentation::Full,
                payload: bare_group_info(&from_hex(setup["group_info"].as_str().unwrap())),
            };
            hub.seed_room_tree(
                room,
                setup_epoch - 1,
                Some(&PeerIdentity::signed(setup["hub_domain"].as_str().unwrap())),
                &group_info,
                &tree,
            );
        }
        assert_eq!(
            tracked_epoch(&p, room),
            Some(setup_epoch),
            "{id}: seeded from the setup"
        );
        // The room's policy and list are now the setup GroupContext's, so the role checks run on these vectors with the
        // policy the joint setup publishes.
        {
            let hub = p.lock().unwrap();
            assert_eq!(
                hub.room_policy(room).unwrap(),
                Some(policy.clone()),
                "{id}: the policy is the GroupContext's"
            );
            let listed: Vec<String> = hub
                .store
                .list_participant_rows(room)
                .unwrap()
                .into_iter()
                .map(|row| row.member_uri)
                .collect();
            let before: Vec<String> = vector["participants_before"]
                .as_array()
                .unwrap()
                .iter()
                .map(|user| mimi_core::uri::canonical(user.as_str().unwrap()))
                .collect();
            assert_eq!(listed, before, "{id}: the list is the GroupContext's");
        }
        let mut accepted = 0;
        for earlier in vector["earlier"].as_array().unwrap() {
            let answer = update_answer(
                post(router.clone(), room, from_hex(earlier.as_str().unwrap())).await,
            )
            .await;
            assert!(
                matches!(answer, UpdateRoomResponse::Success { .. }),
                "{id}: earlier: {answer:?}"
            );
            accepted += 1;
        }
        let answer =
            update_answer(post(router, room, from_hex(vector["hex"].as_str().unwrap())).await)
                .await;
        let kind = match answer {
            UpdateRoomResponse::Success { .. } => {
                accepted += 1;
                "success"
            }
            UpdateRoomResponse::NotAllowed { .. } => "notAllowed",
            UpdateRoomResponse::InvalidProposal { .. } => "invalidProposal",
            UpdateRoomResponse::WrongEpoch { .. } => "wrongEpoch",
        };
        let want = vector.get("answer_haven").unwrap_or(&vector["answer"]);
        assert_eq!(kind, want.as_str().unwrap(), "{id}: answer, tracked");
        assert_eq!(
            tracked_epoch(&p, room),
            Some(setup_epoch + accepted),
            "PLANT-TRACKED-VECTORS: {id}: the tree is at the epoch after every accepted Commit"
        );
        // Each accepted Commit is queued once for the provider of the room's participant elsewhere; a refused one is
        // not queued.
        let queues = p.lock().unwrap().store.outbox_queues().unwrap();
        let queued: u64 = queues
            .iter()
            .filter(|queue| {
                queue.domain == "b.example" && queue.room_uri == mimi_core::uri::canonical(room)
            })
            .map(|queue| queue.depth)
            .sum();
        assert_eq!(
            queued,
            u64::from(accepted),
            "PLANT-FANOUT-VECTORS: {id}: fan-out queued"
        );
        checked += 1;
    }
    assert_eq!(checked, 3);
}
