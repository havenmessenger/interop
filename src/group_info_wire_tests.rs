//! A signed GroupInfoRequest is read back and verified; a changed one is not. An answer is signed by the hub and its
//! payload opens, with the requester's key, to the GroupInfo, the tree option and the pending proposals as given.

use openmls::prelude::BasicCredential;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

use super::*;

const ALICE: &str = "mimi://a.example/u/alice";

fn keys() -> (Vec<u8>, Vec<u8>) {
    OpenMlsRustCrypto::default()
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap()
}

fn credential(uri: &str) -> Credential {
    BasicCredential::new(uri.as_bytes().to_vec()).into()
}

/// A request signed with the requester's key decodes to its fields, verifies, and names its user; a request whose
/// signed part was changed does not verify. Revert check: skip the signature check, and the changed one passes.
#[test]
fn a_signed_request_reads_back_and_verifies() {
    let (private, public) = keys();
    for code in [None, Some(&b"join-123"[..])] {
        let bytes =
            GroupInfoRequest::sign(&private, &public, credential(ALICE), b"hpke-public", code)
                .unwrap();
        let request = GroupInfoRequest::decode(&bytes).unwrap();
        request.verify().unwrap();
        assert_eq!(request.requester_uri().as_deref(), Some(ALICE));
        assert_eq!(request.group_info_public_key, b"hpke-public");
        assert_eq!(request.joining_code.as_deref(), code);

        let mut changed = bytes.clone();
        let at = 4;
        changed[at] ^= 1;
        let tampered = GroupInfoRequest::decode(&changed).map(|r| r.verify());
        assert!(
            !matches!(tampered, Ok(Ok(()))),
            "PLANT-GROUPINFO-VERIFY: a changed request verified"
        );
        assert!(GroupInfoRequest::decode(&[&bytes[..], &[0][..]].concat()).is_err());
    }
}

/// The answer's signature verifies with the `hub_sender` key it carries, and its payload opens with the requester's
/// HPKE key and the room ID to the GroupInfo, the tree option and the pending proposals, in that order.
#[test]
fn an_answer_is_signed_and_opens_to_what_was_put_in() {
    let crypto = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let requester = crypto
        .crypto()
        .derive_hpke_keypair(suite.hpke_config(), &[7u8; 32])
        .unwrap();
    let (hub_private, hub_public) = keys();
    let hub = HubSigner {
        private_key: hub_private,
        public_key: hub_public.clone(),
        credential: credential("mimi://hub.example"),
    };
    let room = b"mimi://hub.example/r/room";
    let pending = vec![PendingProposal {
        proposal: b"PROPOSAL".to_vec(),
        hub_accepted_time: 42,
    }];
    let sealed =
        encrypt_group_info(&requester.public, room, b"GROUPINFO", b"\x01TREE", &pending).unwrap();
    let answer = group_info_response(room, GroupInfoCode::Success, Some((&hub, &sealed))).unwrap();
    let (key, encrypted) = verify_group_info_response(&answer).unwrap();
    assert_eq!(key, hub_public);

    let mut info = Vec::new();
    VLBytes::new(b"MLS 1.0 GroupInfo and ratchet_tree encryption".to_vec())
        .tls_serialize(&mut info)
        .unwrap();
    VLBytes::new(room.to_vec())
        .tls_serialize(&mut info)
        .unwrap();
    let opened = crypto
        .crypto()
        .hpke_open(
            suite.hpke_config(),
            &encrypted,
            requester.private.as_ref(),
            &info,
            &[],
        )
        .unwrap();
    let mut proposals = b"PROPOSAL".to_vec();
    proposals.extend_from_slice(&42u64.to_be_bytes());
    let mut expected = b"GROUPINFO\x01TREE".to_vec();
    VLBytes::new(proposals)
        .tls_serialize(&mut expected)
        .unwrap();
    assert_eq!(opened, expected);

    let mut forged = answer.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert!(verify_group_info_response(&forged).is_err());

    let refused = group_info_response(room, GroupInfoCode::NotAuthorized, None).unwrap();
    assert_eq!(refused.last(), Some(&2));
    let _ = HpkeCiphertext::tls_deserialize_exact(&encrypted.tls_serialize_detached().unwrap())
        .unwrap();
}
