//! `HandshakeBundle` against the §5.3 wire, laid out here byte by byte so the layout under test is the draft's and not this
//! crate's own: a commit bundle is the commit, a presence tag and a bare `Welcome`, the representation of the group info and
//! a raw `GroupInfo`, then the ratchet tree.

use super::*;
use crate::commit_wire::app_data_tests::{app_data_update, commit_with, custom};
use crate::test_fixtures::{add_commit, AddCommit};

const FULL: u8 = 1;
const PARTIAL: u8 = 2;

/// The bytes of a commit bundle, assembled from its parts without the encoder.
fn bundle(
    commit: &[u8],
    welcome: Option<&[u8]>,
    representation: u8,
    group_info: &[u8],
    tree: &[u8],
) -> Vec<u8> {
    let welcome = match welcome {
        Some(bytes) => [vec![1], bytes.to_vec()].concat(),
        None => vec![0],
    };
    [
        commit.to_vec(),
        welcome,
        vec![representation],
        group_info.to_vec(),
        tree.to_vec(),
    ]
    .concat()
}

fn length_prefixed(bytes: &[u8]) -> Vec<u8> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

#[test]
fn a_commit_bundle_carries_a_bare_welcome_and_a_raw_group_info() {
    let AddCommit {
        commit,
        welcome,
        group_info,
    } = add_commit();
    let wire = bundle(&commit, Some(&welcome), FULL, &group_info, &[0xCC, 0xDD]);
    let decoded = HandshakeBundle::decode(&wire).unwrap();
    let HandshakeBundle::Commit {
        proposal_or_commit,
        welcome: read_welcome,
        group_info_option,
        ratchet_tree_option,
    } = &decoded
    else {
        panic!("a commit bundle decodes to Commit");
    };
    assert_eq!(proposal_or_commit, &commit);
    assert_eq!(read_welcome.as_deref(), Some(welcome.as_slice()));
    assert_eq!(
        group_info_option.representation,
        GroupInfoRepresentation::Full
    );
    assert_eq!(group_info_option.payload, group_info);
    assert_eq!(ratchet_tree_option, &[0xCC, 0xDD]);
    assert_eq!(
        decoded.encode().unwrap(),
        wire,
        "decode then encode is the identity"
    );
}

#[test]
fn a_commit_bundle_without_a_welcome_round_trips() {
    let AddCommit {
        commit, group_info, ..
    } = add_commit();
    let wire = bundle(&commit, None, FULL, &group_info, &[]);
    let decoded = HandshakeBundle::decode(&wire).unwrap();
    assert_eq!(decoded.encode().unwrap(), wire);
}

#[test]
fn a_welcome_wrapped_in_an_mls_message_is_not_a_welcome() {
    let AddCommit {
        commit,
        welcome,
        group_info,
    } = add_commit();
    let wrapped = [vec![0x00, 0x01, 0x00, 0x03], welcome].concat();
    let wire = bundle(&commit, Some(&wrapped), FULL, &group_info, &[]);
    assert!(HandshakeBundle::decode(&wire).is_err());
}

#[test]
fn a_full_group_info_is_never_read_through_a_length_prefix() {
    let AddCommit {
        commit,
        welcome,
        group_info,
    } = add_commit();
    let wire = bundle(
        &commit,
        Some(&welcome),
        FULL,
        &length_prefixed(&group_info),
        &[],
    );
    // The trailing ratchet tree is "everything left", so a misframed group info can still decode as something; what must hold is
    // that the bytes read as the group info are not the GroupInfo that was sent.
    if let Ok(HandshakeBundle::Commit {
        group_info_option, ..
    }) = HandshakeBundle::decode(&wire)
    {
        assert_ne!(group_info_option.payload, group_info);
    }
}

#[test]
fn a_partial_group_info_keeps_its_length_prefix() {
    let AddCommit {
        commit, welcome, ..
    } = add_commit();
    let payload = [0xAB; 40];
    let wire = bundle(
        &commit,
        Some(&welcome),
        PARTIAL,
        &length_prefixed(&payload),
        &[0xEE],
    );
    let decoded = HandshakeBundle::decode(&wire).unwrap();
    let HandshakeBundle::Commit {
        group_info_option,
        ratchet_tree_option,
        ..
    } = &decoded
    else {
        panic!("Commit");
    };
    assert_eq!(
        group_info_option.representation,
        GroupInfoRepresentation::Partial
    );
    assert_eq!(group_info_option.payload, payload);
    assert_eq!(ratchet_tree_option, &[0xEE]);
    assert_eq!(decoded.encode().unwrap(), wire);
}

#[test]
fn a_foreign_suite_welcome_is_refused_before_it_is_decoded() {
    let AddCommit {
        commit, group_info, ..
    } = add_commit();
    // A cipher suite other than the pinned one, then bytes that are not a Welcome at all: only a refusal that reads the
    // suite first can name the suite; a decoder would report garbage.
    let foreign = [vec![0x00, 0x03], vec![0xFF; 16]].concat();
    let wire = bundle(&commit, Some(&foreign), FULL, &group_info, &[]);
    let error = HandshakeBundle::decode(&wire).unwrap_err();
    assert!(matches!(error, WireError::CiphersuiteGate(_)), "{error:?}");
}

#[test]
fn a_foreign_suite_group_info_is_refused() {
    let AddCommit {
        commit,
        welcome,
        mut group_info,
    } = add_commit();
    // The GroupInfoTBS opens with the group context, whose second field is the cipher suite (version u16, then suite u16).
    group_info[2..4].copy_from_slice(&[0x00, 0x03]);
    let wire = bundle(&commit, Some(&welcome), FULL, &group_info, &[]);
    assert!(HandshakeBundle::decode(&wire).is_err());
}

#[test]
fn a_truncated_bundle_is_refused_at_every_cut() {
    let AddCommit {
        commit,
        welcome,
        group_info,
    } = add_commit();
    let wire = bundle(&commit, Some(&welcome), FULL, &group_info, &[]);
    for cut in (0..wire.len()).step_by(37) {
        assert!(
            HandshakeBundle::decode(&wire[..cut]).is_err(),
            "cut at {cut}"
        );
    }
}

#[test]
fn the_bare_welcome_gate_refuses_a_foreign_suite_and_a_trailer() {
    let AddCommit { welcome, .. } = add_commit();
    crate::gate::mimi_gate_welcome_bare(&welcome).unwrap();
    let mut foreign = welcome.clone();
    foreign[..2].copy_from_slice(&[0x00, 0x03]);
    assert!(crate::gate::mimi_gate_welcome_bare(&foreign).is_err());
    let mut trailing = welcome;
    trailing.push(0);
    assert!(crate::gate::mimi_gate_welcome_bare(&trailing).is_err());
    assert!(crate::gate::mimi_gate_welcome_bare(&[0x00]).is_err());
}

/// A Commit that carries an AppDataUpdate for the participant list: openmls built without `extensions-draft-08` cannot find
/// where it ends, so the bundle is read through a rewritten form while the bytes kept are the ones that were sent.
mod app_data_update {
    use super::*;

    const UPDATE_OP: u8 = 1;
    const PARTICIPANT_LIST: u16 = 0x0022;

    fn commit(update_len: usize) -> Vec<u8> {
        commit_with(&[app_data_update(
            PARTICIPANT_LIST,
            UPDATE_OP,
            Some(&vec![0x5A; update_len]),
        )])
    }

    #[test]
    fn a_whole_bundle_around_the_commit_decodes_and_keeps_the_original_bytes() {
        let AddCommit {
            welcome,
            group_info,
            ..
        } = add_commit();
        // Sizes on both sides of the prefix boundaries, so the bytes after the Commit sit at shifted offsets.
        for update_len in [0usize, 20, 58, 59, 60, 63, 64, 70, 16380, 16384, 16390] {
            let sent = commit(update_len);
            let wire = bundle(&sent, Some(&welcome), FULL, &group_info, &[0xCC, 0xDD]);
            let decoded = HandshakeBundle::decode(&wire)
                .unwrap_or_else(|e| panic!("update of {update_len} bytes: {e:?}"));
            let HandshakeBundle::Commit {
                proposal_or_commit,
                welcome: read_welcome,
                group_info_option,
                ratchet_tree_option,
            } = &decoded
            else {
                panic!("a commit bundle decodes to Commit");
            };
            assert_eq!(
                proposal_or_commit, &sent,
                "the bytes kept are the ones sent ({update_len})"
            );
            assert_eq!(
                read_welcome.as_deref(),
                Some(welcome.as_slice()),
                "{update_len}"
            );
            assert_eq!(group_info_option.payload, group_info, "{update_len}");
            assert_eq!(ratchet_tree_option, &[0xCC, 0xDD], "{update_len}");
            assert_eq!(decoded.encode().unwrap(), wire, "{update_len}");
        }
    }

    #[test]
    fn the_private_form_decodes_to_the_same_bundle_shape() {
        let AddCommit {
            welcome,
            group_info,
            ..
        } = add_commit();
        let sent = commit_with(&[custom(0xF7A0, &[0x5A; 20])]);
        let wire = bundle(&sent, Some(&welcome), FULL, &group_info, &[]);
        let HandshakeBundle::Commit {
            proposal_or_commit, ..
        } = HandshakeBundle::decode(&wire).unwrap()
        else {
            panic!("Commit");
        };
        assert_eq!(proposal_or_commit, sent);
    }

    #[test]
    fn a_bundle_whose_commit_carries_a_malformed_app_data_update_is_refused() {
        let AddCommit {
            welcome,
            group_info,
            ..
        } = add_commit();
        let mut entry = app_data_update(PARTICIPANT_LIST, UPDATE_OP, Some(&[1, 2, 3]));
        entry.truncate(entry.len() - 2);
        let wire = bundle(
            &commit_with(&[entry]),
            Some(&welcome),
            FULL,
            &group_info,
            &[],
        );
        assert!(HandshakeBundle::decode(&wire).is_err());
    }
}
