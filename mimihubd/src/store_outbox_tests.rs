//! The outbox's order, its heads, and what the operator sees and drops.

use super::super::SqliteStore;

const ROOM: &str = "mimi://hub.example/r/room";
const OTHER: &str = "mimi://hub.example/r/other";

/// Only each queue's head is due, in enqueue order, and a busy queue is left out; a failed attempt moves the head's due
/// time and the next row stays behind it. Revert check: take every due row instead of each queue's head, and the second
/// row of a queue is attempted beside the first.
#[test]
fn only_each_queues_head_is_due_in_order() {
    let store = SqliteStore::in_memory().unwrap();
    let a1 = store.enqueue_fanout(ROOM, "a.example", b"a1", 10).unwrap();
    let _a2 = store.enqueue_fanout(ROOM, "a.example", b"a2", 11).unwrap();
    let b1 = store.enqueue_fanout(ROOM, "B.example.", b"b1", 12).unwrap();
    let o1 = store.enqueue_fanout(OTHER, "a.example", b"o1", 13).unwrap();

    let heads: Vec<i64> = store
        .due_outbox_heads(100, &[])
        .unwrap()
        .iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(
        heads,
        [a1, b1, o1],
        "PLANT-OUTBOX-HEADS: not one head per queue, in order"
    );
    let busy = [(ROOM.to_string(), "a.example".to_string())];
    let heads: Vec<i64> = store
        .due_outbox_heads(100, &busy)
        .unwrap()
        .iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(heads, [b1, o1]);

    store.record_outbox_attempt(a1, 500, "503").unwrap();
    let heads: Vec<i64> = store
        .due_outbox_heads(100, &[])
        .unwrap()
        .iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(
        heads,
        [b1, o1],
        "the next row overtook a head waiting to be retried"
    );
    assert_eq!(store.next_outbox_due_ms().unwrap(), Some(12));

    store.remove_outbox_row(a1).unwrap();
    let head = &store.due_outbox_heads(100, &[]).unwrap()[0];
    assert_eq!(
        (head.body.as_slice(), head.domain.as_str()),
        (&b"a2"[..], "a.example")
    );
}

/// The operator sees each queue's depth, oldest row and head's last outcome, and can drop one queue.
#[test]
fn the_operator_sees_and_drops_a_queue() {
    let store = SqliteStore::in_memory().unwrap();
    let a1 = store.enqueue_fanout(ROOM, "a.example", b"a1", 10).unwrap();
    store.enqueue_fanout(ROOM, "a.example", b"a2", 20).unwrap();
    store.enqueue_fanout(ROOM, "b.example", b"b1", 30).unwrap();
    store
        .record_outbox_attempt(a1, 99, "connecting: refused")
        .unwrap();
    let queues = store.outbox_queues().unwrap();
    assert_eq!(queues.len(), 2);
    assert_eq!(
        (
            queues[0].domain.as_str(),
            queues[0].depth,
            queues[0].oldest_enqueued_at_ms,
            queues[0].head_attempts
        ),
        ("a.example", 2, 10, 1)
    );
    assert_eq!(
        queues[0].head_last_outcome.as_deref(),
        Some("connecting: refused")
    );
    assert_eq!(store.drop_outbox_queue(ROOM, "a.example").unwrap(), 2);
    assert_eq!(store.outbox_queues().unwrap().len(), 1);
    assert_eq!(store.next_outbox_due_ms().unwrap(), Some(30));
}
