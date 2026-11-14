//! A FanoutMessage whose Commit carries AppDataUpdates, the way a protocol-07 room changes its participant list and
//! policy, is read as one. The Commits are those of the protocol-07 vectors.

use mimi_core::protocol_wire::{FanoutMessage, HandshakeBundle};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("vectors/protocol07-vectors.json");

#[derive(Deserialize)]
struct Vectors {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    hex: String,
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_commit_with_app_data_updates_is_read_as_a_fanout_message_and_kept_as_sent() {
    let vectors: Vectors = serde_json::from_str(VECTORS_JSON).unwrap();
    let mut read = 0;
    for id in [
        "up-01-participant-list-private-type",
        "up-02-participant-list-app-data-update",
        "up-04-added-participants-are-appended",
        "up-05-roles-list-app-data-update",
    ] {
        let vector = vectors.vectors.iter().find(|v| v.id == id).unwrap();
        let HandshakeBundle::Commit {
            proposal_or_commit, ..
        } = HandshakeBundle::decode(&bytes(&vector.hex)).unwrap()
        else {
            panic!("{id} is not a Commit bundle");
        };
        let body = [
            1_700_000_000_000u64.to_be_bytes().to_vec(),
            proposal_or_commit.clone(),
        ]
        .concat();
        let fanout = FanoutMessage::decode(&body).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(fanout.message_and_tail, proposal_or_commit, "{id}");
        read += 1;
    }
    assert_eq!(read, 4);
}
