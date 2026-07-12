//! Proof that openmls's own external-commit and external-proposal mechanisms are real and
//! testable - gated behind the default-off `external-ops` Cargo feature (compiled ONLY when the
//! feature is enabled AND under `cfg(test)`, so it never ships in any build, feature-gated or not).
//!
//! **This module is NOT Haven's acceptance mechanism.** It calls openmls's APIs directly - no
//! `crate::gate` function, no `crypto-core::profile` policy check, no allowlist, no room-policy
//! hub-of-record check. Its only job is to prove the underlying capability a full-fidelity
//! ("SpecProfile") consumer would rely on genuinely exists and is exercised by a real test, not
//! merely declared. Building Haven's own narrow mimi-lane acceptance path against
//! `crypto-core::profile::allows_external_proposal`'s `AllowlistedRemoveOnly` policy - the
//! sender-verification, the room-policy check, the explicit-inclusion-only commit mechanic - is
//! separate work, out of scope for this module.
//!
//! Structural-exclusion proof: with `external-ops` off (Haven's product build), this module - and
//! therefore these test symbols - is entirely absent from the compiled artifact, provable by a
//! `cargo tree`/symbol-table check against a `--no-default-features` build (see the CI job that
//! asserts this). With the feature on, both tests below run against real openmls and pass.

use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::extensions::{ExternalSender, ExternalSendersExtension};
use openmls::messages::external_proposals::ExternalProposal;
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

const AES: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct TestSigner {
    key: Vec<u8>,
    scheme: SignatureScheme,
}
impl Signer for TestSigner {
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

fn ident(
    user: &str,
) -> (
    TestSigner,
    CredentialWithKey,
    SignaturePublicKey,
    OpenMlsRustCrypto,
) {
    let provider = OpenMlsRustCrypto::default();
    let scheme = SignatureScheme::ED25519;
    let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
    let pk = SignaturePublicKey::try_from(pub_b).unwrap();
    let cwk = CredentialWithKey {
        credential: BasicCredential::new(user.as_bytes().to_vec()).into(),
        signature_key: pk.clone(),
    };
    (
        TestSigner {
            key: priv_b,
            scheme,
        },
        cwk,
        pk,
        provider,
    )
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

/// A SpecProfile consumer can construct a `GroupInfo` and use it to join via external commit -
/// the RFC 9420 §12.4.3.1 mechanism `INV-MLS-001a` permanently refuses in `Profile::Haven`, both
/// lanes. This is `openmls`'s own capability, exercised directly, with no Haven wrapper involved.
#[test]
fn spec_profile_external_commit_join_works_against_real_openmls() {
    let (asig, acwk, _apk, aprov) = ident("alice");
    let cfg = MlsGroupCreateConfig::builder()
        .ciphersuite(AES)
        .use_ratchet_tree_extension(true)
        .build();
    let alice = MlsGroup::new(&aprov, &asig, &cfg, acwk).unwrap();

    let (bsig, bcwk, _bpk, bprov) = ident("bob-joining-externally");
    let group_info = group_info_in(
        alice
            .export_group_info(aprov.crypto(), &asig, true)
            .unwrap(),
    );

    let (mut bob, commit_bundle) = ExternalCommitBuilder::new()
        .with_config(cfg.join_config().clone())
        .build_group(&bprov, group_info, bcwk)
        .unwrap()
        .leaf_node_parameters(LeafNodeParameters::default())
        .load_psks(bprov.storage())
        .unwrap()
        .build(bprov.rand(), bprov.crypto(), &bsig, |_| true)
        .unwrap()
        .finalize(&bprov)
        .unwrap();
    bob.merge_pending_commit(&bprov).unwrap();

    // alice processes bob's external-commit message and ends up in sync - proving the join is a
    // real, two-sided MLS state transition, not merely a message that was accepted syntactically.
    let mut alice = alice;
    let (commit_out, _welcome, _group_info) = commit_bundle.into_contents();
    let processed = alice
        .process_message(&aprov, protocol_in(commit_out))
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            alice.merge_staged_commit(&aprov, *staged).unwrap();
        }
        other => panic!("expected a staged commit, got {other:?}"),
    }
    assert_eq!(
        alice.members().count(),
        2,
        "alice must now see bob as a member after processing the external commit"
    );
}

/// A SpecProfile consumer can pre-configure an `ExternalSendersExtension` and have that sender
/// construct a valid `Sender::External` Remove proposal openmls accepts (stages as a
/// `ProposalMessage`) - the narrow mechanism `INV-MLS-001b` describes, not yet wired to any live
/// acceptance path. A proposal from a signer NOT in the extension is rejected
/// by openmls before ever reaching that stage. This test only proves openmls's OWN validation; it
/// does not select, commit, or otherwise "process" the proposal the way a real acceptance
/// mechanism would.
#[test]
fn spec_profile_external_remove_proposal_is_validated_and_staged_by_real_openmls() {
    let (asig, acwk, _apk, aprov) = ident("alice");
    let (hub_sig, _hub_cwk, hub_pk, _hub_prov) = ident("hub");
    let external_senders: ExternalSendersExtension =
        vec![ExternalSender::new(hub_pk, acwk.credential.clone())];
    let cfg = MlsGroupCreateConfig::builder()
        .ciphersuite(AES)
        .with_group_context_extensions(
            Extensions::single(Extension::ExternalSenders(external_senders)).unwrap(),
        )
        .build();
    let mut alice = MlsGroup::new(&aprov, &asig, &cfg, acwk.clone()).unwrap();

    let (bsig, bcwk, _bpk, bprov) = ident("bob");
    let bob_kp = KeyPackage::builder()
        .build(AES, &bprov, &bsig, bcwk.clone())
        .unwrap()
        .key_package()
        .clone();
    let (_commit, welcome, _gi) = alice.add_members(&aprov, &asig, &[bob_kp]).unwrap();
    alice.merge_pending_commit(&aprov).unwrap();
    let _ = welcome; // only alice is needed for this proof; bob's join isn't exercised here.

    // The pre-configured hub sender constructs a valid external Remove proposal for bob (leaf 1).
    let remove_out = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
        LeafNodeIndex::new(1),
        alice.group_id().clone(),
        alice.epoch(),
        &hub_sig,
        SenderExtensionIndex::new(0),
    )
    .unwrap();
    let processed = alice
        .process_message(&aprov, protocol_in(remove_out))
        .unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ProposalMessage(_queued) => {
            // openmls validated the sender against ExternalSendersExtension[0] and staged it -
            // proof the mechanism works. Selecting/committing it is out of scope for this module.
        }
        other => panic!("expected a staged external proposal, got {other:?}"),
    }

    // A signer NOT in the extension must be rejected before ever reaching that stage.
    let (rogue_sig, _rogue_cwk, _rogue_pk, _rogue_prov) = ident("rogue-non-hub-sender");
    let rogue_remove_out = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
        LeafNodeIndex::new(1),
        alice.group_id().clone(),
        alice.epoch(),
        &rogue_sig,
        SenderExtensionIndex::new(0),
    )
    .unwrap();
    let rogue_result = alice.process_message(&aprov, protocol_in(rogue_remove_out));
    assert!(
        rogue_result.is_err(),
        "openmls must reject an external proposal signed by a key not in ExternalSendersExtension"
    );
}
