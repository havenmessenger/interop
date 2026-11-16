//! A room's public group state written through the store and read back, as openmls's PublicGroup does it.

use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::mls_fixtures::{add_commit, Member};
use crate::store::SqliteStore;

fn public_group_of(store: &SqliteStore, group_info: &[u8], tree: &[u8]) -> PublicGroup {
    let crypto = OpenMlsRustCrypto::default();
    let info = VerifiableGroupInfo::tls_deserialize_exact(group_info).unwrap();
    let tree = RatchetTreeIn::tls_deserialize_exact(tree).unwrap();
    PublicGroup::from_external(
        crypto.crypto(),
        &store.groups(),
        tree,
        info,
        ProposalStore::new(),
    )
    .unwrap()
    .0
}

/// A PublicGroup made from a GroupInfo and tree is stored, and loads back with the same epoch, members and tree. Revert
/// check: let `tree` read nothing back, and the load finds no group.
#[test]
fn a_public_group_is_stored_and_loads_back() {
    let store = SqliteStore::in_memory().unwrap();
    let alice = Member::new("mimi://example.com/u/alice");
    let bob = Member::new("mimi://example.com/u/bob");
    let mut group = alice.create_group(b"mimi://example.com/g/room");
    let (_commit, group_info, tree) = add_commit(&mut group, &alice, &[&bob]);
    let stored = public_group_of(&store, &group_info, &tree);

    let loaded = PublicGroup::load(&store.groups(), group.group_id())
        .unwrap()
        .expect("PLANT-GROUP-STORE-LOAD: the stored group loads");
    assert_eq!(loaded.group_context().epoch(), group.epoch());
    assert_eq!(loaded.members().count(), 2);
    assert_eq!(loaded.export_ratchet_tree(), stored.export_ratchet_tree());
}

/// Another group's state is its own: deleting one leaves the other.
#[test]
fn groups_are_kept_apart() {
    let store = SqliteStore::in_memory().unwrap();
    let alice = Member::new("mimi://example.com/u/alice");
    let bob = Member::new("mimi://example.com/u/bob");
    let mut first = alice.create_group(b"first");
    let mut second = alice.create_group(b"second");
    let (_c1, info1, tree1) = add_commit(&mut first, &alice, &[&bob]);
    let (_c2, info2, tree2) = add_commit(&mut second, &alice, &[&bob]);
    public_group_of(&store, &info1, &tree1);
    public_group_of(&store, &info2, &tree2);
    PublicGroup::delete(&store.groups(), second.group_id()).unwrap();
    assert!(PublicGroup::load(&store.groups(), second.group_id())
        .unwrap()
        .is_none());
    assert!(PublicGroup::load(&store.groups(), first.group_id())
        .unwrap()
        .is_some());
}
