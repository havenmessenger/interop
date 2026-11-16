//! The operational policy component: every field round-trips, and what does not say what it means is refused.

use super::*;

fn full() -> OperationalParameters {
    let capabilities = ExtendedCapabilities {
        versions: vec![1],
        cipher_suites: vec![1, 3],
        extensions: vec![0x0005],
        proposals: vec![0x0008],
        credentials: vec![1],
        wire_formats: vec![1, 2],
        component_ids: vec![0x0022, 0x0025],
        safe_aad_types: vec![],
        media_types: vec![MediaType {
            media_type: "text/markdown".into(),
            parameters: vec![("charset".into(), "utf-8".into())],
        }],
        content_types: vec![1, 2, 3],
    };
    OperationalParameters {
        mandatory_capabilities: capabilities.clone(),
        default_capabilities: ExtendedCapabilities::default(),
        forbidden_capabilities: capabilities,
        handshake_formats: vec![1],
        external_proposal_allowed: false,
        external_commit_allowed: true,
        pending_proposal_policy: PendingProposalPolicy::RandomDelay {
            minimum_delay_ms: 10,
            maximum_delay_ms: 500,
        },
        leaf_node_update_time: MinDefaultMaxTime {
            minimum: 1,
            default: 2,
            maximum: 3,
        },
        app_message_policy: AppMessagePolicy {
            epoch_tolerance: 2,
            pad_to_size: 256,
            max_generations_skipahead: 1000,
        },
        max_kp_lifetime: 7_776_000,
        max_credential_lifetime: 31_536_000,
        resumption_psk_lifetime: 86_400,
        sender_nonce_keypair_lifetime: MinDefaultMaxTime {
            minimum: 0,
            default: 5,
            maximum: 9,
        },
        max_keypairs: 64,
        buffer_incoming_message_time: MinDefaultMaxTime {
            minimum: 0,
            default: 0,
            maximum: 0,
        },
        max_buffered_messages: 100,
    }
}

/// Every field written is read back as written, the two flags included. Revert check: swap the order the two flags
/// are read in, and `external_commit_allowed` comes back false.
#[test]
fn every_field_round_trips() {
    let parameters = full();
    let bytes = encode_operational_parameters(&parameters);
    let read = decode_operational_parameters(&bytes).unwrap();
    assert!(
        read.external_commit_allowed && !read.external_proposal_allowed,
        "PLANT-OPS-FLAGS"
    );
    assert_eq!(read, parameters);
    let empty = OperationalParameters::default();
    assert_eq!(
        decode_operational_parameters(&encode_operational_parameters(&empty)).unwrap(),
        empty
    );
}

/// A truncated value, octets left over, a flag that is not 0 or 1, an unknown strategy, and a default outside its
/// bounds are each refused.
#[test]
fn what_does_not_say_what_it_means_is_refused() {
    let bytes = encode_operational_parameters(&full());
    assert!(decode_operational_parameters(&bytes[..bytes.len() - 1]).is_err());
    assert!(decode_operational_parameters(&[&bytes[..], &[0][..]].concat()).is_err());

    let mut parameters = full();
    parameters.pending_proposal_policy = PendingProposalPolicy::Unspecified;
    let plain = encode_operational_parameters(&parameters);
    let flags_at = plain.len() - (1 + 24 + 7 + 24 + 24 + 4 + 24 + 4) - 2;
    let mut bad_flag = plain.clone();
    bad_flag[flags_at + 1] = 2;
    assert!(
        decode_operational_parameters(&bad_flag).is_err(),
        "a flag of 2 was read"
    );
    let mut bad_strategy = plain.clone();
    bad_strategy[flags_at + 2] = 3;
    assert!(
        decode_operational_parameters(&bad_strategy).is_err(),
        "strategy 3 was read"
    );

    let mut outside = full();
    outside.leaf_node_update_time = MinDefaultMaxTime {
        minimum: 5,
        default: 1,
        maximum: 9,
    };
    assert!(decode_operational_parameters(&encode_operational_parameters(&outside)).is_err());
    let mut delay = full();
    delay.pending_proposal_policy = PendingProposalPolicy::RandomDelay {
        minimum_delay_ms: 9,
        maximum_delay_ms: 1,
    };
    assert!(decode_operational_parameters(&encode_operational_parameters(&delay)).is_err());
}
