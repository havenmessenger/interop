//! A Commit that carries an AppDataUpdate for the participant list is read as the `0xF7A0` participant-list proposal it is
//! equivalent to. Commits are built here by splicing a new proposals window into a captured openmls Commit, so every length
//! prefix around the window is exact, and the layouts are mls-extensions-10 §4.7 and protocol-06 §9/§10.3.

use super::*;
use crate::participant_list::MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE;
use tests::CAPTURED_PARTICIPANT_LIST_COMMIT;

const PARTICIPANT_LIST: u16 = PARTICIPANT_LIST_COMPONENT_ID;

fn from_hex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn vl(bytes: &[u8]) -> Vec<u8> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

/// The captured Commit cut at its proposals window: the bytes before the window's length prefix and the bytes after it.
fn around_the_window() -> (Vec<u8>, Vec<u8>) {
    let bytes = from_hex(CAPTURED_PARTICIPANT_LIST_COMMIT);
    let (_v, rest) = read_u16(&bytes, "v").unwrap();
    let (_w, rest) = read_u16(rest, "w").unwrap();
    let (_g, rest) = read_opaque_vec(rest, "g").unwrap();
    let (_e, rest) = read_u64(rest, "e").unwrap();
    let (_s, rest) = read_u8(rest, "s").unwrap();
    let (_l, rest) = read_u32(rest, "l").unwrap();
    let (_a, rest) = read_opaque_vec(rest, "a").unwrap();
    let (_c, window_at) = read_u8(rest, "c").unwrap();
    let (_window, after) = read_opaque_vec(window_at, "p").unwrap();
    (
        bytes[..bytes.len() - window_at.len()].to_vec(),
        after.to_vec(),
    )
}

/// A Commit whose proposals window is `entries`, concatenated.
pub(crate) fn commit_with(entries: &[Vec<u8>]) -> Vec<u8> {
    let (before, after) = around_the_window();
    [before, vl(&entries.concat()), after].concat()
}

/// One by-value `ProposalOrRef` entry for a custom proposal of type `proposal_type`.
pub(crate) fn custom(proposal_type: u16, payload: &[u8]) -> Vec<u8> {
    [vec![1], proposal_type.to_be_bytes().to_vec(), vl(payload)].concat()
}

/// One by-value AppDataUpdate entry.
pub(crate) fn app_data_update(component: u16, op: u8, update: Option<&[u8]>) -> Vec<u8> {
    let tail = update.map(vl).unwrap_or_default();
    [
        vec![1],
        APP_DATA_UPDATE_PROPOSAL_TYPE.to_be_bytes().to_vec(),
        component.to_be_bytes().to_vec(),
        vec![op],
        tail,
    ]
    .concat()
}

fn update_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn an_update_to_the_participant_list_component_is_the_participant_list_proposal() {
    let update = update_of(40);
    let decoded = decode_single_custom_proposal_commit(&commit_with(&[app_data_update(
        PARTICIPANT_LIST,
        APP_DATA_UPDATE_OP_UPDATE,
        Some(&update),
    )]))
    .unwrap();
    assert_eq!(decoded.proposal_type, MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE);
    assert_eq!(decoded.payload, update);
}

/// room-policy-04 §10.1: an update to `roles_list` (0x0025) or `base_room_policy` (0x0027) is read as the private proposal
/// type that carries that component's bytes, and no other component takes either type.
#[test]
fn an_update_to_a_room_policy_component_is_that_components_proposal() {
    use crate::room_policy::{MIMI_BASE_ROOM_POLICY_PROPOSAL_TYPE, MIMI_ROLES_LIST_PROPOSAL_TYPE};
    let update = update_of(40);
    for (component, expected) in [
        (0x0025u16, MIMI_ROLES_LIST_PROPOSAL_TYPE),
        (0x0027u16, MIMI_BASE_ROOM_POLICY_PROPOSAL_TYPE),
    ] {
        let decoded = decode_single_custom_proposal_commit(&commit_with(&[app_data_update(
            component,
            APP_DATA_UPDATE_OP_UPDATE,
            Some(&update),
        )]))
        .unwrap();
        assert_eq!(decoded.proposal_type, expected, "{component:#06x}");
        assert_eq!(decoded.payload, update, "{component:#06x}");
    }
    // Their neighbours in the component numbering are not read.
    for component in [0x0024u16, 0x0026, 0x0028, 0x0029] {
        let sent = commit_with(&[app_data_update(
            component,
            APP_DATA_UPDATE_OP_UPDATE,
            Some(&update),
        )]);
        assert!(
            decode_single_custom_proposal_commit(&sent).is_err(),
            "{component:#06x}"
        );
    }
    // Removing either component is not read.
    for component in [0x0025u16, 0x0027] {
        let sent = commit_with(&[app_data_update(component, APP_DATA_UPDATE_OP_REMOVE, None)]);
        assert!(decode_single_custom_proposal_commit(&sent).is_err());
    }
}

#[test]
fn the_private_form_is_still_read_beside_it() {
    let update = update_of(40);
    let decoded = decode_single_custom_proposal_commit(&commit_with(&[custom(
        MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE,
        &update,
    )]))
    .unwrap();
    assert_eq!(decoded.payload, update);
}

/// Update sizes on both sides of the length-prefix boundaries (63/64 and 16383/16384), so the update, the entry and the
/// proposals window each cross a prefix size, in the rewritten form (which drops the component and operation bytes) and in
/// the original.
#[test]
fn lengths_that_cross_a_prefix_boundary_are_read_exactly() {
    for size in (0..=2).chain(55..=70).chain(16376..=16392) {
        let update = update_of(size);
        let sent = commit_with(&[app_data_update(
            PARTICIPANT_LIST,
            APP_DATA_UPDATE_OP_UPDATE,
            Some(&update),
        )]);
        let decoded = decode_single_custom_proposal_commit(&sent)
            .unwrap_or_else(|e| panic!("update of {size} bytes: {e:?}"));
        assert_eq!(decoded.payload, update, "update of {size} bytes");

        let private = commit_with(&[custom(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, &update)]);
        let normalized = normalize_app_data_updates(&sent).unwrap().unwrap();
        // The rewritten message is the private form, byte for byte, whatever the sizes did to the prefixes.
        assert_eq!(normalized.bytes, private, "update of {size} bytes");
        assert_eq!(
            normalized.delta,
            private.len() as isize - sent.len() as isize,
            "update of {size} bytes"
        );
    }
}

#[test]
fn only_the_proposals_window_is_rewritten() {
    let (before, after) = around_the_window();
    let sent = commit_with(&[app_data_update(
        PARTICIPANT_LIST,
        APP_DATA_UPDATE_OP_UPDATE,
        Some(&update_of(30)),
    )]);
    let normalized = normalize_app_data_updates(&sent).unwrap().unwrap();
    assert!(normalized.bytes.starts_with(&before));
    assert!(normalized.bytes.ends_with(&after));
    assert!(sent.starts_with(&before) && sent.ends_with(&after));
}

#[test]
fn a_message_with_no_app_data_update_is_not_rewritten() {
    let captured = from_hex(CAPTURED_PARTICIPANT_LIST_COMMIT);
    assert!(normalize_app_data_updates(&captured).unwrap().is_none());
}

#[test]
fn another_component_is_refused() {
    for component in [0x0020u16, 0x0021, 0x0023, 0x0000, 0xFFFF] {
        let sent = commit_with(&[app_data_update(
            component,
            APP_DATA_UPDATE_OP_UPDATE,
            Some(&update_of(8)),
        )]);
        assert!(
            decode_single_custom_proposal_commit(&sent).is_err(),
            "component {component:#06x}"
        );
    }
}

#[test]
fn removing_the_component_and_an_invalid_operation_are_refused() {
    let remove = commit_with(&[app_data_update(
        PARTICIPANT_LIST,
        APP_DATA_UPDATE_OP_REMOVE,
        None,
    )]);
    assert!(decode_single_custom_proposal_commit(&remove).is_err());
    for op in [0u8, 3, 255] {
        let sent = commit_with(&[app_data_update(PARTICIPANT_LIST, op, Some(&update_of(8)))]);
        assert!(
            decode_single_custom_proposal_commit(&sent).is_err(),
            "operation {op}"
        );
    }
}

#[test]
fn a_second_proposal_beside_it_is_refused() {
    let update = app_data_update(
        PARTICIPANT_LIST,
        APP_DATA_UPDATE_OP_UPDATE,
        Some(&update_of(8)),
    );
    for second in [
        custom(MIMI_PARTICIPANT_LIST_PROPOSAL_TYPE, &update_of(8)),
        update.clone(),
    ] {
        let sent = commit_with(&[update.clone(), second.clone()]);
        assert!(decode_single_custom_proposal_commit(&sent).is_err());
        let sent = commit_with(&[second, update.clone()]);
        assert!(decode_single_custom_proposal_commit(&sent).is_err());
    }
}

#[test]
fn a_proposal_by_reference_beside_it_is_refused() {
    let reference = [vec![MLS_PROPOSAL_OR_REF_REFERENCE], vl(&[7; 32])].concat();
    let update = app_data_update(
        PARTICIPANT_LIST,
        APP_DATA_UPDATE_OP_UPDATE,
        Some(&update_of(8)),
    );
    assert!(decode_single_custom_proposal_commit(&commit_with(&[
        update.clone(),
        reference.clone()
    ]))
    .is_err());
    assert!(decode_single_custom_proposal_commit(&commit_with(&[reference, update])).is_err());
}

#[test]
fn bytes_after_the_update_inside_the_window_are_refused() {
    let mut entry = app_data_update(
        PARTICIPANT_LIST,
        APP_DATA_UPDATE_OP_UPDATE,
        Some(&update_of(8)),
    );
    entry.push(0x00);
    assert!(decode_single_custom_proposal_commit(&commit_with(&[entry])).is_err());
}

#[test]
fn an_update_cut_short_inside_the_window_is_refused() {
    let mut entry = app_data_update(
        PARTICIPANT_LIST,
        APP_DATA_UPDATE_OP_UPDATE,
        Some(&update_of(8)),
    );
    entry.truncate(entry.len() - 3);
    assert!(decode_single_custom_proposal_commit(&commit_with(&[entry])).is_err());
}

/// A Commit a peer that proposes the participant-list change beside the standard proposals the same Commit needs, in either
/// order: `GroupContextExtensions` (proposal type 7, an empty extension list) or `Remove` (type 3, a leaf index). This hub
/// reads a Commit with exactly one proposal (DIV-10), so each is refused: never read as the update, never partly applied.
/// openmls is not involved in the refusal: the hub reads a Commit with its own decoder and holds no group state, so the
/// ordering of AppDataUpdate against GroupContextExtensions that openmls's own processing has to settle is never reached here.
#[test]
fn an_update_beside_a_standard_proposal_is_refused_in_either_order() {
    let update = app_data_update(
        PARTICIPANT_LIST,
        APP_DATA_UPDATE_OP_UPDATE,
        Some(&update_of(8)),
    );
    let group_context_extensions = [vec![1], 7u16.to_be_bytes().to_vec(), vec![0]].concat();
    let remove = [
        vec![1],
        3u16.to_be_bytes().to_vec(),
        1u32.to_be_bytes().to_vec(),
    ]
    .concat();
    for standard in [group_context_extensions, remove] {
        for entries in [
            [update.clone(), standard.clone()],
            [standard.clone(), update.clone()],
        ] {
            let sent = commit_with(&entries);
            assert!(
                decode_single_custom_proposal_commit(&sent).is_err(),
                "a Commit of two proposals is not read as one"
            );
            // The rewrite for reading does not change what is refused or stored: the bytes the hub forwards are the original.
            assert!(
                normalize_app_data_updates(&sent).is_ok(),
                "the standard proposal is sized by openmls's own decoder, and is not mistaken for part of the update"
            );
        }
    }
}
