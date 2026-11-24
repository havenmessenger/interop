//! A lane keyMaterial request must be the lane user's own and name a room; the caps hold per user and per target; a
//! room on another domain is another hub's.

use mimi_core::protocol_wire::{IdentifierUri, KeyMaterialRequest};

use super::*;
use crate::mls_fixtures::Member;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const ROOM: &str = "mimi://c.example/r/room";

/// `by`'s request for Bob's KeyPackage for the room, signed with `by`'s key and naming `requesting`.
fn request(by: &Member, requesting: &str, room: &str) -> KeyMaterialRequest {
    let mut request = KeyMaterialRequest::minimal(requesting, BOB).unwrap();
    request.room_id = IdentifierUri(room.into());
    request.requester_signature_key = by.credential.signature_key.clone();
    request.requester_credential = by.credential.credential.clone();
    request.sign(&by.signer).unwrap();
    request
}

#[test]
fn the_users_own_signed_request_for_a_room_is_taken() {
    let alice = Member::new(ALICE);
    assert_eq!(
        check_key_material_request(&request(&alice, ALICE, ROOM), ALICE),
        Ok(())
    );
}

/// Revert check: skip the signature and the tampered request is taken.
#[test]
fn a_request_for_someone_else_or_unsigned_is_refused() {
    let alice = Member::new(ALICE);
    let carol = Member::new("mimi://a.example/u/carol");
    // Names Alice but is Carol's key and credential.
    assert_eq!(
        check_key_material_request(&request(&carol, ALICE, ROOM), ALICE),
        Err(KeyMaterialRefusal::NotTheUser)
    );
    // Alice's key and credential, naming Carol as the requester: KeyPackages would be reserved under Carol's name.
    assert_eq!(
        check_key_material_request(&request(&alice, "mimi://a.example/u/carol", ROOM), ALICE),
        Err(KeyMaterialRefusal::NotTheUser),
        "PLANT-LANE-KM-REQUESTER: a request naming another requester is refused"
    );
    // Alice's own, for another lane user.
    assert_eq!(
        check_key_material_request(&request(&alice, ALICE, ROOM), "mimi://a.example/u/carol"),
        Err(KeyMaterialRefusal::NotTheUser)
    );
    let mut tampered = request(&alice, ALICE, ROOM);
    tampered.target_user = IdentifierUri("mimi://b.example/u/dave".into());
    assert_eq!(
        check_key_material_request(&tampered, ALICE),
        Err(KeyMaterialRefusal::NotTheUser),
        "PLANT-LANE-KM-SIGNATURE: a request changed after signing is refused"
    );
    assert_eq!(
        check_key_material_request(&request(&alice, ALICE, ""), ALICE),
        Err(KeyMaterialRefusal::NoRoom)
    );
}

/// Revert check: drop the per-target count and the sixth request for one target is admitted.
#[test]
fn the_caps_hold_per_user_and_per_target() {
    let cap = KeyMaterialCap::default();
    let now = 1_700_000_000;
    for _ in 0..KEY_MATERIAL_PER_TARGET_PER_HOUR {
        assert!(cap.admit(ALICE, BOB, now));
    }
    assert!(
        !cap.admit(ALICE, BOB, now),
        "PLANT-LANE-KM-PER-TARGET: one user cannot spend another's KeyPackages past the cap"
    );
    assert!(
        cap.admit("mimi://a.example/u/carol", BOB, now),
        "another requester has its own count"
    );
    let cap = KeyMaterialCap::default();
    let admitted = (0..100)
        .filter(|at| cap.admit(ALICE, &format!("mimi://b.example/u/user{at}"), now))
        .count();
    assert_eq!(admitted, KEY_MATERIAL_PER_MINUTE as usize);
}

#[test]
fn a_room_on_another_domain_is_another_hubs() {
    assert_eq!(
        other_hub("mimi://B.example/r/room", "a.example"),
        Some("b.example".into())
    );
    assert_eq!(other_hub("mimi://a.example/r/room", "a.example"), None);
}
