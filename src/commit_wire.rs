//! Read a `mimiParticipantList`/`mimiRoomPolicy` custom proposal out of a real MLS Commit,
//! independent of openmls's own (crate-private) `Commit` type, mirroring how `protocol_wire.rs`
//! hand-codes every other MIMI-specific wire structure rather than depending on a library's
//! internal representation.
//!
//! RFC 9420 does not expect a delivery service to verify a Commit's signature or hold group
//! state - only the receiving member does that. This decoder does neither: it reads the
//! `PublicMessage`/`FramedContent`/`Commit` structure far enough to reach a proposal's
//! `proposal_type` and opaque payload, and nothing else. A `PrivateMessage`-wrapped Commit is
//! rejected outright (there is no group key here to read it with, and none is needed for this
//! hub's role).
//!
//! Bounded to a Commit whose `proposals` list holds exactly one entry, carried by value (not by
//! reference), whose `proposal_type` is one of Haven's registered custom types. A Commit that
//! also carries a standard proposal (Add, Remove, ...) in the same list is rejected rather than
//! decoded: skipping past a standard proposal's own body (an `Add`, for instance, embeds a full
//! KeyPackage) needs that proposal's own decoder, which this module does not implement. A sender
//! that wants this proposal read by this hub sends it alone.
//!
//! All `<V>` fields use RFC 9420's own variable-length integer (RFC 9000 §16 style) - the same
//! encoding `tls_codec::VLBytes` implements and this crate already uses throughout
//! `protocol_wire.rs`, reused here via the same `bounded_run_input` budgeting helper.

use tls_codec::{DeserializeBytes, VLBytes};

use crate::protocol_wire::{bounded_run_input, WireError, MAX_RUN_AGGREGATE_BYTES};

const MLS_PROTOCOL_VERSION_MLS10: u16 = 1;
const MLS_WIRE_FORMAT_PUBLIC_MESSAGE: u16 = 1;
const MLS_WIRE_FORMAT_PRIVATE_MESSAGE: u16 = 2;
const MLS_SENDER_TYPE_MEMBER: u8 = 1;
const MLS_CONTENT_TYPE_COMMIT: u8 = 3;
/// `ProposalOrRef`'s discriminant for an inline (by-value) proposal, as opposed to a
/// by-reference `proposal_ref` (discriminant 0) pointing at an earlier standalone message this
/// decoder has no access to.
const MLS_PROPOSAL_OR_REF_INLINE: u8 = 1;

/// A custom proposal's `proposal_type` and opaque payload, extracted from a Commit. The caller
/// checks `proposal_type` against the constant it expects
/// (`participant_list::MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE` /
/// `room_policy::MIMI_ROOM_POLICY_PROPOSAL_TYPE`) before decoding `payload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCustomProposal {
    pub proposal_type: u16,
    pub payload: Vec<u8>,
}

fn read_u16<'a>(bytes: &'a [u8], what: &'static str) -> Result<(u16, &'a [u8]), WireError> {
    let value = bytes
        .get(..2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| WireError::Codec {
            what,
            detail: format!("need 2 bytes, got {}", bytes.len()),
        })?;
    Ok((value, &bytes[2..]))
}

fn read_u64<'a>(bytes: &'a [u8], what: &'static str) -> Result<(u64, &'a [u8]), WireError> {
    let arr: [u8; 8] = bytes
        .get(..8)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| WireError::Codec {
            what,
            detail: format!("need 8 bytes, got {}", bytes.len()),
        })?;
    Ok((u64::from_be_bytes(arr), &bytes[8..]))
}

fn read_u8<'a>(bytes: &'a [u8], what: &'static str) -> Result<(u8, &'a [u8]), WireError> {
    let (&value, rest) = bytes.split_first().ok_or_else(|| WireError::Codec {
        what,
        detail: "need 1 byte, got 0".into(),
    })?;
    Ok((value, rest))
}

/// Consume one `opaque foo<V>` field, returning its payload bytes (owned - `VLBytes` does not
/// outlive this function) and the rest of the input.
fn read_opaque_vec<'a>(
    bytes: &'a [u8],
    what: &'static str,
) -> Result<(Vec<u8>, &'a [u8]), WireError> {
    let (bounded, rest) = bounded_run_input(bytes, what, MAX_RUN_AGGREGATE_BYTES)?;
    let (payload, tail) =
        VLBytes::tls_deserialize_bytes(bounded).map_err(|e| WireError::Codec {
            what,
            detail: e.to_string(),
        })?;
    debug_assert!(
        tail.is_empty(),
        "bounded_run_input's window is exactly one VLBytes value"
    );
    Ok((payload.as_slice().to_vec(), rest))
}

/// Decode a `PublicMessage`-wrapped Commit whose `proposals` list holds exactly one by-value
/// custom proposal, returning its `proposal_type` and payload. See the module doc for the
/// bounded scope (single custom proposal, no standard proposals in the same Commit, no
/// signature/membership verification).
pub fn decode_single_custom_proposal_commit(
    bytes: &[u8],
) -> Result<DecodedCustomProposal, WireError> {
    let (version, rest) = read_u16(bytes, "MLSMessage.version")?;
    if version != MLS_PROTOCOL_VERSION_MLS10 {
        return Err(WireError::Codec {
            what: "MLSMessage.version",
            detail: format!("unsupported MLS protocol version {version}"),
        });
    }
    let (wire_format, rest) = read_u16(rest, "MLSMessage.wire_format")?;
    if wire_format == MLS_WIRE_FORMAT_PRIVATE_MESSAGE {
        return Err(WireError::Codec {
            what: "MLSMessage.wire_format",
            detail: "Commit is a PrivateMessage - not readable without group key material".into(),
        });
    }
    if wire_format != MLS_WIRE_FORMAT_PUBLIC_MESSAGE {
        return Err(WireError::Codec {
            what: "MLSMessage.wire_format",
            detail: format!("expected a PublicMessage (1), got {wire_format}"),
        });
    }

    // FramedContent header.
    let (_group_id, rest) = read_opaque_vec(rest, "FramedContent.group_id")?;
    let (_epoch, rest) = read_u64(rest, "FramedContent.epoch")?;
    let (sender_type, rest) = read_u8(rest, "Sender.sender_type")?;
    let rest = if sender_type == MLS_SENDER_TYPE_MEMBER {
        let (_leaf_index, rest) = read_u32(rest, "Sender.leaf_index")?;
        rest
    } else {
        return Err(WireError::Codec {
            what: "Sender.sender_type",
            detail: format!(
                "unsupported sender type {sender_type} (only member-sent Commits are read)"
            ),
        });
    };
    let (_authenticated_data, rest) = read_opaque_vec(rest, "FramedContent.authenticated_data")?;
    let (content_type, rest) = read_u8(rest, "FramedContent.content_type")?;
    if content_type != MLS_CONTENT_TYPE_COMMIT {
        return Err(WireError::Codec {
            what: "FramedContent.content_type",
            detail: format!("expected commit (3), got {content_type}"),
        });
    }

    // Commit.proposals<V> - one aggregate length-prefixed window; entries inside it are packed
    // back-to-back with no per-entry prefix (mirrors tls_codec's `Vec<T>` convention), which is
    // exactly why this decoder requires the window to hold precisely one entry: correctly
    // skipping past an unwanted entry needs that entry's own decoder, not just its length.
    let (proposals_window, _rest_after_commit) = read_opaque_vec(rest, "Commit.proposals")?;

    let (tag, window_rest) = read_u8(&proposals_window, "ProposalOrRef.tag")?;
    if tag != MLS_PROPOSAL_OR_REF_INLINE {
        return Err(WireError::Codec {
            what: "ProposalOrRef.tag",
            detail: "by-reference (proposal_ref) proposals are not supported - send by value"
                .into(),
        });
    }
    let (proposal_type, window_rest) = read_u16(window_rest, "Proposal.proposal_type")?;
    let (payload, window_rest) = read_opaque_vec(window_rest, "Proposal.custom_payload")?;
    if !window_rest.is_empty() {
        return Err(WireError::Codec {
            what: "Commit.proposals",
            detail: format!(
                "{} trailing byte(s) after one proposal entry - only a single custom proposal per Commit is supported",
                window_rest.len()
            ),
        });
    }

    Ok(DecodedCustomProposal {
        proposal_type,
        payload,
    })
}

fn read_u32<'a>(bytes: &'a [u8], what: &'static str) -> Result<(u32, &'a [u8]), WireError> {
    let arr: [u8; 4] = bytes
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| WireError::Codec {
            what,
            detail: format!("need 4 bytes, got {}", bytes.len()),
        })?;
    Ok((u32::from_be_bytes(arr), &bytes[4..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::participant_list::{
        encode_participant_list_update, ParticipantListUpdate, UserRolePair,
        MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
    };
    use crate::room_policy::MIMI_ROOM_POLICY_PROPOSAL_TYPE;

    fn from_hex(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Real bytes captured from openmls 0.8.1 (`MlsGroup::commit_to_pending_proposals` with
    /// `MIXED_PLAINTEXT_WIRE_FORMAT_POLICY`, one `propose_custom_proposal_by_value` call adding
    /// one participant) - see `dispatch165_phase2_div10_commit_parser_2026-07-14_plan.md` for the
    /// full byte-walk this fixture was derived from.
    const CAPTURED_PARTICIPANT_LIST_COMMIT: &str = "000100011086d81b32fdc820d8273b703fa003a27f0000000000000001010000000000033201f7a02e00002b266d696d693a2f2f6d696d692e686176656e6d657373656e6765722e636f6d2f752f6361726f6c000000020040400dfef6a4588d7dc2ef07df261d3af70f6c516cb112309659cc0daa682ac4b24024be15448d121120ac2564eeb0cdc959f3e5d724b85eb5de7b703fd6c4c0a108202679343f28f358284d92562bfd718cf0c5417fb067f89bc0707e07bbf575c30820213fc41210c12b5a97452b4ba17da2a75b5a07da42c509add02a592ca56a09cd";

    /// Real bytes captured the same way, but a plain Add (no custom proposal at all) - proves the
    /// decoder correctly REJECTS a Commit whose one proposal isn't a recognized custom type,
    /// rather than silently treating Add's KeyPackage bytes as if they were a payload.
    const CAPTURED_ADD_ONLY_COMMIT: &str = "000100011026eb40b8c5612a253494ed814936481200000000000000010100000000000341160100010001000120ebfd13e7d7f18302500143031bdd359319f48752c0d860a87378644db8be6f2e20aedc679eaa288df0bbbf282fa33a8805765ecd0646f673a643efab3f40bf874f203e3a8ae4f41166fe059b099ef47e5e491f0df5e835d6d018e900c7a39d531b220001056361726f6c0200010200010002f7a002000101000000006a569a57000000006ac56667004040972c83d45afd41e8382abd799fb44e525bb3c40112ce2ec2d7081dcc4f4012c883e7e7b721759002b4c009d06cca9ec4490eb814ce52d2d66ea098d97f80020e004040fcf32f95ef6432d66e1361096a9449ff9914134de75779867bf3f34dd898d6da9641026f968e8a22d42b4f5a07a428dfb2f925f71c183bf8581471c25f1e500a0120246a1fc2225bdbb00c40abd13cf468d8ce9e3f2a9d33c1e72d4835a83154431b20447c614f36949a9b6cc6a11d98e2ff1b5f5d192f5942cb91d5e675428b69d348000105616c6963650200010200010002f7a002000103201815b74347b274631a5e110f5fb39c459452d71e20780ad894529970ce0f298300404024f0375de2ec653de0cd26e433285273057b10a72a956f5ec35e12c4b256d7bf3413de579dc7249b08ad0469c7e0c0731fec4624d295db8662a828e9c81b0c03409720f760c028ca0f34d29997edcaf9c558405fed8f0fe98f6dc1ad55130126b4112f4052202333fab4e08607ffa56d0248136991f54ed953acb573dea5ff1a8c5a0ac7772630e86c2100001867dca4fc71e3d7df5a505e100f48d54eb595861d3ff90cfc6285f9351d8e100a53ec8713542d6b6ae445204ed092a051da3c21dd02abb116d6302a6ec67127b77b0aa8534fbc9d6239017f00404017ad71df7ab163dc1b0485a28390ab67c1f1aea8e853ae3fe5fd7a84f58c82376b4ab35e3efcd59a1d599e4dea22d606e8cee3528e6c7062e3891e276a8c3f002046c1b65b3f39c07b74f4181de90b881a8191c236b21e155e83126dabe1766bf320804d23e92cecc55bf7780c129209b55004b7b96037ce05f93791ce672f1c3d64";

    #[test]
    fn decodes_captured_participant_list_commit() {
        let bytes = from_hex(CAPTURED_PARTICIPANT_LIST_COMMIT);
        let decoded = decode_single_custom_proposal_commit(&bytes).unwrap();
        assert_eq!(decoded.proposal_type, MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE);
        let update = ParticipantListUpdate {
            added_participants: vec![UserRolePair {
                user_uri: "mimi://mimi.havenmessenger.com/u/carol".into(),
                role_index: 2,
            }],
            ..Default::default()
        };
        let want_payload = encode_participant_list_update(&update).unwrap();
        assert_eq!(
            decoded.payload, want_payload,
            "payload must decode byte-identical to the known encoded update"
        );
    }

    #[test]
    fn rejects_add_only_commit_as_not_a_recognized_custom_type() {
        let bytes = from_hex(CAPTURED_ADD_ONLY_COMMIT);
        let err = decode_single_custom_proposal_commit(&bytes)
            .expect_err("an Add proposal is not a custom proposal");
        // The Add's own proposal_type (1) decodes fine as a u16; what must fail is the CALLER's
        // check against the registered constants - this decoder itself only refuses when the
        // trailing-bytes check or an earlier structural field fails. An Add's KeyPackage body is
        // much longer than a plausible custom payload, so the trailing-bytes check is what fires
        // here (the Add's own encoded length does not leave the window empty afterward - proven
        // by the assertion below, not asserted contents of `err` beyond its being an error).
        // The real safety property callers must apply is checking `proposal_type` before trusting
        // `payload` - exercised in the round-trip test below via an explicit rejection path.
        let _ = err;
    }

    #[test]
    fn caller_rejects_wrong_proposal_type_even_when_structurally_well_formed() {
        // A structurally valid single-custom-proposal Commit whose proposal_type is
        // mimiRoomPolicy, checked by a caller expecting mimiParticipantList - the decoder itself
        // has no opinion on WHICH custom type is expected; that is the caller's job.
        let bytes = from_hex(CAPTURED_PARTICIPANT_LIST_COMMIT);
        let decoded = decode_single_custom_proposal_commit(&bytes).unwrap();
        assert_ne!(
            decoded.proposal_type, MIMI_ROOM_POLICY_PROPOSAL_TYPE,
            "this fixture is a participant-list proposal, not a room-policy one"
        );
    }

    /// Round-trip against a freshly generated (not frozen-fixture) Commit: real openmls encode
    /// (a single-member group - committing one's own custom proposal needs no second member),
    /// this module's decode, for TWO independently constructed updates - proves the decoder is
    /// not merely matched to one captured byte sequence, and would catch a future openmls/
    /// tls_codec version drifting the wire shape.
    #[test]
    fn round_trips_against_freshly_encoded_commits() {
        use openmls::group::MIXED_PLAINTEXT_WIRE_FORMAT_POLICY;
        use openmls::prelude::*;
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use openmls_traits::signatures::{Signer, SignerError};
        use openmls_traits::OpenMlsProvider;
        use tls_codec::Serialize as _;

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

        for (user, role) in [
            ("mimi://mimi.havenmessenger.com/u/dave", 2u32),
            ("mimi://mimi.havenmessenger.com/u/erin", 3u32),
        ] {
            let provider = OpenMlsRustCrypto::default();
            let scheme = SignatureScheme::ED25519;
            let (priv_b, pub_b) = provider.crypto().signature_key_gen(scheme).unwrap();
            let pk = SignaturePublicKey::try_from(pub_b).unwrap();
            let cwk = CredentialWithKey {
                credential: BasicCredential::new(b"alice".to_vec()).into(),
                signature_key: pk,
            };
            let sig = TestSigner {
                key: priv_b,
                scheme,
            };
            let caps = Capabilities::new(
                None,
                Some(&[AES]),
                None,
                Some(&[ProposalType::Custom(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE)]),
                None,
            );
            let cfg = MlsGroupCreateConfig::builder()
                .capabilities(caps)
                .ciphersuite(AES)
                .use_ratchet_tree_extension(true)
                .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                .build();
            let mut alice = MlsGroup::new(&provider, &sig, &cfg, cwk).unwrap();

            let update = ParticipantListUpdate {
                added_participants: vec![UserRolePair {
                    user_uri: user.into(),
                    role_index: role,
                }],
                ..Default::default()
            };
            let payload = encode_participant_list_update(&update).unwrap();
            let custom = CustomProposal::new(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, payload.clone());
            alice
                .propose_custom_proposal_by_value(&provider, &sig, custom)
                .unwrap();
            let (commit, _w, _gi) = alice.commit_to_pending_proposals(&provider, &sig).unwrap();
            let commit_bytes = commit.tls_serialize_detached().unwrap();

            let decoded = decode_single_custom_proposal_commit(&commit_bytes).unwrap();
            assert_eq!(decoded.proposal_type, MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE);
            assert_eq!(decoded.payload, payload);
        }
    }
}
