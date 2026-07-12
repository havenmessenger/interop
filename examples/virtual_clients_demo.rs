//! A runnable, narrated proof of the `mimi_core::virtual_clients` mechanism
//! (draft-ietf-mls-virtual-clients-01 §5-§6): `cargo run --example virtual_clients_demo`.
//!
//! This is NOT a mock - every step below is a real openmls `MlsGroup` operation. The narration prints
//! what the spec requires at each step and what this demo just proved about it. See
//! `src/virtual_clients.rs`'s module doc for the full "what's implemented / what's deliberately not"
//! scope statement, and `src/virtual_clients.rs`'s own test suite for the same proofs as `cargo test`.
//!
//! Scenario: "alice" owns two devices - a phone and a laptop - that jointly emulate ONE virtual
//! client (§5.1) under a single leaf of a higher-level MLS group. A third device (a tablet) later
//! onboards by joining the emulation group externally (§6.2). The laptop is then lost and removed
//! (§6.3).
//!
//! `unwrap`/`panic` are fine here (narrative demo code, not the library) - the crate's own
//! `unwrap_used`/`panic` clippy lints apply to the `--lib --bins` surface only (see Cargo.toml), which
//! examples are outside of by that same convention.
#![allow(clippy::unwrap_used, clippy::panic)]

use mimi_core::virtual_clients::{
    compute_reuse_guard, derive_epoch_secrets, recover_sender_leaf_index,
};

use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as _, Serialize as _};

const AES: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const EMULATOR_EPOCH_SECRET_LABEL: &str = "virtual clients emulator epoch secret (v1 stand-in)";

struct DemoSigner {
    key: Vec<u8>,
    scheme: SignatureScheme,
}
impl Signer for DemoSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        OpenMlsRustCrypto::default()
            .crypto()
            .sign(self.scheme, payload, &self.key)
            .map_err(|_| SignerError::SigningError)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

fn ident(device: &str) -> (DemoSigner, CredentialWithKey, OpenMlsRustCrypto) {
    let provider = OpenMlsRustCrypto::default();
    let scheme = SignatureScheme::ED25519;
    let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
    let pk = SignaturePublicKey::from(pub_b);
    let cwk = CredentialWithKey {
        credential: BasicCredential::new(device.as_bytes().to_vec()).into(),
        signature_key: pk,
    };
    (
        DemoSigner {
            key: priv_b,
            scheme,
        },
        cwk,
        provider,
    )
}

fn keypackage(
    signer: &DemoSigner,
    cwk: &CredentialWithKey,
    provider: &OpenMlsRustCrypto,
) -> KeyPackage {
    KeyPackage::builder()
        .build(AES, provider, signer, cwk.clone())
        .unwrap()
        .key_package()
        .clone()
}

fn welcome_in(out: MlsMessageOut) -> Welcome {
    let bytes = out.tls_serialize_detached().unwrap();
    match MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::Welcome(w) => w,
        other => panic!("expected a Welcome, got {other:?}"),
    }
}

fn protocol_in(out: MlsMessageOut) -> ProtocolMessage {
    let bytes = out.tls_serialize_detached().unwrap();
    let msg_in = MlsMessageIn::tls_deserialize(&mut bytes.as_slice()).unwrap();
    ProtocolMessage::try_from(msg_in).unwrap()
}

fn group_info_in(out: MlsMessageOut) -> VerifiableGroupInfo {
    let bytes = out.tls_serialize_detached().unwrap();
    match MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::GroupInfo(gi) => gi,
        other => panic!("expected a GroupInfo, got {other:?}"),
    }
}

/// v1 stand-in for `emulator_epoch_secret = SafeExportSecret(virtual_clients_component_id)` - see
/// `src/virtual_clients.rs`'s module doc for the divergence this stands in for.
fn emulator_epoch_secret(group: &MlsGroup, crypto: &impl OpenMlsCrypto) -> Vec<u8> {
    group
        .export_secret(crypto, EMULATOR_EPOCH_SECRET_LABEL, &[], 32)
        .unwrap()
}

fn section(title: &str) {
    println!("\n=== {title} ===");
}

fn main() {
    println!("mimi-core virtual_clients demo - draft-ietf-mls-virtual-clients-01 §5-§6");
    println!("(every step below is a real openmls MlsGroup operation, not a mock)");

    section("§5.1/§5.2 - alice's phone + laptop form the emulation group");
    let (phone_sig, phone_cwk, phone_prov) = ident("alice-phone");
    let (laptop_sig, laptop_cwk, laptop_prov) = ident("alice-laptop");
    let cfg = MlsGroupCreateConfig::builder()
        .ciphersuite(AES)
        .use_ratchet_tree_extension(true)
        .build();
    let mut phone = MlsGroup::new(&phone_prov, &phone_sig, &cfg, phone_cwk).unwrap();
    let laptop_kp = keypackage(&laptop_sig, &laptop_cwk, &laptop_prov);
    let (_c, welcome, _gi) = phone
        .add_members(&phone_prov, &phone_sig, &[laptop_kp])
        .unwrap();
    phone.merge_pending_commit(&phone_prov).unwrap();
    let welcome = welcome_in(welcome);
    let laptop = StagedWelcome::new_from_welcome(&laptop_prov, cfg.join_config(), welcome, None)
        .unwrap()
        .into_group(&laptop_prov)
        .unwrap();
    println!("phone + laptop: 2-member emulation group formed via ordinary MLS Add + Welcome.");

    section("§5.2 - both devices derive the SAME five virtual-client secrets");
    let phone_input = emulator_epoch_secret(&phone, phone_prov.crypto());
    let laptop_input = emulator_epoch_secret(&laptop, laptop_prov.crypto());
    assert_eq!(phone_input, laptop_input, "epoch secret export must agree");
    let phone_secrets = derive_epoch_secrets(phone_prov.crypto(), AES, &phone_input).unwrap();
    let laptop_secrets = derive_epoch_secrets(laptop_prov.crypto(), AES, &laptop_input).unwrap();
    assert_eq!(phone_secrets.epoch_id, laptop_secrets.epoch_id);
    assert_eq!(
        phone_secrets.reuse_guard_secret,
        laptop_secrets.reuse_guard_secret
    );
    println!(
        "epoch_id (first 8 bytes): {:02x?}",
        &phone_secrets.epoch_id[..8]
    );
    println!("phone and laptop derived byte-identical epoch_id / reuse_guard_secret / etc.");

    section("§5.6.1/§5.6.2 - reuse_guard: no key/nonce collision between phone and laptop");
    let nonce = [0x01, 0x02, 0x03, 0x04];
    let n_e = 2u32; // 2 leaves in the emulation group right now
    let phone_leaf = 0u32;
    let laptop_leaf = 1u32;
    let phone_guard = compute_reuse_guard(
        phone_prov.crypto(),
        AES,
        &phone_secrets.reuse_guard_secret,
        &nonce,
        phone_leaf,
        n_e,
    )
    .unwrap();
    let laptop_guard = compute_reuse_guard(
        laptop_prov.crypto(),
        AES,
        &laptop_secrets.reuse_guard_secret,
        &nonce,
        laptop_leaf,
        n_e,
    )
    .unwrap();
    assert_ne!(phone_guard, laptop_guard);
    let recovered_phone = recover_sender_leaf_index(
        laptop_prov.crypto(),
        AES,
        &laptop_secrets.reuse_guard_secret,
        &nonce,
        &phone_guard,
        n_e,
    )
    .unwrap();
    assert_eq!(recovered_phone, phone_leaf);
    println!(
        "phone's reuse_guard = {phone_guard:02x?}, laptop's = {laptop_guard:02x?} - different, as required."
    );
    println!(
        "laptop recovers phone's true leaf index ({recovered_phone}) from phone's reuse_guard alone."
    );

    section("§6.2 - a tablet onboards by joining the emulation group externally");
    let (tablet_sig, tablet_cwk, tablet_prov) = ident("alice-tablet");
    let group_info = group_info_in(
        phone
            .export_group_info(phone_prov.crypto(), &phone_sig, true)
            .unwrap(),
    );
    let (mut tablet, commit_bundle) = ExternalCommitBuilder::new()
        .with_config(cfg.join_config().clone())
        .build_group(&tablet_prov, group_info, tablet_cwk)
        .unwrap()
        .leaf_node_parameters(LeafNodeParameters::default())
        .load_psks(tablet_prov.storage())
        .unwrap()
        .build(
            tablet_prov.rand(),
            tablet_prov.crypto(),
            &tablet_sig,
            |_| true,
        )
        .unwrap()
        .finalize(&tablet_prov)
        .unwrap();
    let (commit_out, _welcome, _gi) = commit_bundle.into_contents();
    tablet.merge_pending_commit(&tablet_prov).unwrap();
    let commit_in = protocol_in(commit_out);
    let processed = phone.process_message(&phone_prov, commit_in).unwrap();
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            phone.merge_staged_commit(&phone_prov, *staged).unwrap();
        }
        other => panic!("expected a staged commit, got {other:?}"),
    }
    let tablet_secrets = derive_epoch_secrets(
        tablet_prov.crypto(),
        AES,
        &emulator_epoch_secret(&tablet, tablet_prov.crypto()),
    )
    .unwrap();
    let phone_secrets_post_join = derive_epoch_secrets(
        phone_prov.crypto(),
        AES,
        &emulator_epoch_secret(&phone, phone_prov.crypto()),
    )
    .unwrap();
    assert_eq!(tablet_secrets.epoch_id, phone_secrets_post_join.epoch_id);
    println!("tablet joined via external commit and now shares the emulation group's epoch state.");
    println!(
        "(NOTE: laptop's local MlsGroup is now stale post-join in this demo - a real emulator client \
         would process the same commit message to stay in sync, exactly as phone just did.)"
    );

    section("§6.3 - the laptop is lost; phone removes it and the epoch advances");
    let pre_removal_epoch_id = phone_secrets_post_join.epoch_id;
    let laptop_leaf_index = phone
        .members()
        .find(|m| m.credential.serialized_content() == b"alice-laptop")
        .expect("laptop must still be a member")
        .index;
    let (commit, _w, _gi) = phone
        .remove_members(&phone_prov, &phone_sig, &[laptop_leaf_index])
        .unwrap();
    phone.merge_pending_commit(&phone_prov).unwrap();
    let commit_in = protocol_in(commit);
    let processed = tablet.process_message(&tablet_prov, commit_in).unwrap();
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            tablet.merge_staged_commit(&tablet_prov, *staged).unwrap();
        }
        other => panic!("expected a staged commit, got {other:?}"),
    }
    let phone_secrets_post_removal = derive_epoch_secrets(
        phone_prov.crypto(),
        AES,
        &emulator_epoch_secret(&phone, phone_prov.crypto()),
    )
    .unwrap();
    let tablet_secrets_post_removal = derive_epoch_secrets(
        tablet_prov.crypto(),
        AES,
        &emulator_epoch_secret(&tablet, tablet_prov.crypto()),
    )
    .unwrap();
    assert_eq!(
        phone_secrets_post_removal.epoch_id,
        tablet_secrets_post_removal.epoch_id
    );
    assert_ne!(phone_secrets_post_removal.epoch_id, pre_removal_epoch_id);
    println!(
        "laptop removed via an ordinary in-group MLS Remove (no external operation involved)."
    );
    println!("phone and tablet still agree on the new epoch's secrets, which differ from before removal.");

    println!(
        "\nAll assertions passed - the mechanism this demo narrates is the same one proven in"
    );
    println!(
        "`cargo test --lib virtual_clients` (12 unit tests + 3 group-level conformance tests)."
    );
}
