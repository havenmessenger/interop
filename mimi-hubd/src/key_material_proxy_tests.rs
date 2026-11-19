//! keyMaterial for another provider's user, through the wire route against a local peer: what is forwarded, what the
//! hub records, and what it refuses without forwarding.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mimi_core::protocol_wire::{
    IdentifierUri, KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode,
};
use mimi_core::room_policy::{
    BaseRoomPolicy, Capability, Role, RoomPolicy, SingleSourceRoleChangeTargets,
};
use openmls::prelude::tls_codec::Serialize as _;
use tower::ServiceExt;

use crate::http::SharedProvider;
use crate::mls_fixtures::Member;
use crate::outbound::tests::{answer, loopback_allowed, resolver, server_with, Pki, Seen, PEER};
use crate::peer_directory::{Directories, PeerAccess, PeerBases};
use crate::Provider;

const ROOM: &str = "mimi://hub.example/r/room";
const ALICE: &str = "mimi://member.example/u/alice";
const DAVE: &str = "mimi://member.example/u/dave";
const CAROL: &str = "mimi://peer.example/u/carol";

fn role(index: u32, capabilities: Vec<Capability>) -> Role {
    Role {
        role_index: index,
        role_name: format!("role {index}"),
        capabilities,
        authorized_role_changes: vec![SingleSourceRoleChangeTargets {
            from_role_index: 0,
            target_role_indexes: vec![3],
        }],
    }
}

/// Carol's KeyPackage, and a peer at `PEER` that answers keyMaterial with it, or with `status` when that is not 200.
async fn peer(
    pki: &Pki,
    status: &'static str,
) -> (Vec<u8>, std::net::SocketAddr, Arc<Mutex<Vec<Seen>>>) {
    let key_package = Member::new(CAROL)
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let success = KeyMaterialResponse::Success {
        user_uri: IdentifierUri(CAROL.into()),
        key_package: key_package.clone(),
    }
    .encode()
    .unwrap();
    let port = Arc::new(Mutex::new(0u16));
    let port_in = port.clone();
    let (addr, seen) = server_with(pki, PEER, move |seen| {
        if seen
            .head
            .starts_with("GET /.well-known/mimi-protocol-directory ")
        {
            let port = *port_in.lock().unwrap();
            let body = format!(
                r#"{{"keyMaterial": "https://{PEER}:{port}/v1/keyMaterial/{{targetUser}}"}}"#
            );
            return answer("200 OK", "", body.as_bytes());
        }
        if status == "200 OK" {
            answer(status, "", &success)
        } else {
            answer(status, "", b"")
        }
    })
    .await;
    *port.lock().unwrap() = addr.port();
    (key_package, addr, seen)
}

/// A hub hosting `ROOM` with Alice (a role that may add participants) and Dave (one that may not), both users of
/// `member.example`, whose requests come through it, reaching `PEER` at `addr`.
fn hub(pki: &Pki, addr: std::net::SocketAddr) -> SharedProvider {
    let access = PeerAccess {
        client: Arc::new(pki.client(loopback_allowed(), None, resolver(PEER, &[addr]))),
        directories: Arc::new(Directories::new(
            PeerBases::parse(&format!(r#""{PEER}" = "https://{PEER}:{}""#, addr.port())).unwrap(),
        )),
    };
    let p = Provider::in_memory("hub.example")
        .unwrap()
        .with_peer_access(Arc::new(access));
    for member in [ALICE, DAVE] {
        p.add_participant(ROOM, member, 1).unwrap();
    }
    p.set_room_policy(
        ROOM,
        &RoomPolicy {
            base: BaseRoomPolicy::default(),
            roles: vec![
                role(2, vec![Capability::AddParticipant]),
                role(3, vec![Capability::SendMessage]),
            ],
        },
        1,
    )
    .unwrap();
    p.set_member_role(ROOM, ALICE, 2).unwrap();
    p.set_member_role(ROOM, DAVE, 3).unwrap();
    Arc::new(Mutex::new(p))
}

fn request(requester: &str, room: &str) -> Vec<u8> {
    let mut request = KeyMaterialRequest::minimal(requester, CAROL).unwrap();
    request.room_id = IdentifierUri(room.into());
    request.encode().unwrap()
}

async fn ask(p: &SharedProvider, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let response = crate::http::build_router(p.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .extension(crate::peer::PeerCert(Some(
                    crate::peer::PeerIdentity::signed("member.example"),
                )))
                .uri("/mimi/pl/keyMaterial/mimi%3A%2F%2Fpeer.example%2Fu%2Fcarol")
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

fn posts(seen: &Mutex<Vec<Seen>>) -> Vec<Seen> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|seen| seen.head.starts_with("POST "))
        .cloned()
        .collect()
}

/// A participant who may add participants asks for another provider's user: the request goes to that provider as
/// received, its answer comes back as sent, and the KeyPackage in it is recorded against that provider for the Welcome.
/// Revert check: do not record it, and the Welcome has no provider to go to.
#[tokio::test]
async fn a_request_for_another_providers_user_is_forwarded_and_its_key_package_recorded() {
    let pki = Pki::new();
    let (key_package, addr, seen) = peer(&pki, "200 OK").await;
    let p = hub(&pki, addr);
    let body = request(ALICE, ROOM);
    let (status, answer) = ask(&p, body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let decoded = KeyMaterialResponse::decode(&answer, &[0x0001]).unwrap();
    assert!(
        matches!(decoded, KeyMaterialResponse::Success { key_package: ref kp, .. } if *kp == key_package)
    );
    let forwarded = posts(&seen);
    assert_eq!(forwarded.len(), 1);
    assert!(forwarded[0]
        .head
        .starts_with("POST /v1/keyMaterial/mimi%3A%2F%2Fpeer.example%2Fu%2Fcarol HTTP/1.1"));
    assert_eq!(
        forwarded[0].body, body,
        "the request was not forwarded as received"
    );
    let kpref = crate::keypackage_ref(&key_package, &[0x0001]).unwrap();
    assert_eq!(
        p.lock()
            .unwrap()
            .provider_for_kpref(&kpref)
            .unwrap()
            .as_deref(),
        Some(PEER),
        "PLANT-PROXY-RECORD: the KeyPackage's provider was not recorded"
    );
}

/// A request without a hosted room, from a non-participant, or from a role that may not add participants is answered
/// `noConsent` and not forwarded. Revert check: skip the role check, and Dave's request reaches the peer.
#[tokio::test]
async fn a_request_the_hub_does_not_forward_is_no_consent() {
    let pki = Pki::new();
    let (_, addr, seen) = peer(&pki, "200 OK").await;
    let p = hub(&pki, addr);
    for (who, body) in [
        ("no room", request(ALICE, "")),
        (
            "another hub's room",
            request(ALICE, "mimi://other.example/r/room"),
        ),
        (
            "a non-participant",
            request("mimi://member.example/u/eve", ROOM),
        ),
        ("a role without canAddParticipant", request(DAVE, ROOM)),
    ] {
        let (status, answer) = ask(&p, body).await;
        assert!(
            posts(&seen).is_empty(),
            "PLANT-PROXY-REFUSE: {who} was forwarded"
        );
        assert_eq!(status, StatusCode::OK, "{who}");
        assert!(
            matches!(
                KeyMaterialResponse::decode(&answer, &[0x0001]).unwrap(),
                KeyMaterialResponse::Denied {
                    code: KeyMaterialUserCode::NoConsent,
                    ..
                }
            ),
            "{who}"
        );
    }
}

/// A peer that fails is a 502, and nothing is recorded.
#[tokio::test]
async fn a_peer_failure_is_a_bad_gateway() {
    let pki = Pki::new();
    let (_, addr, _) = peer(&pki, "500 Internal Server Error").await;
    let p = hub(&pki, addr);
    let (status, _) = ask(&p, request(ALICE, ROOM)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}
