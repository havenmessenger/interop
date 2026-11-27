//! The bodies as the lane writes and reads them.

use super::*;

/// An event batch as the hub documents it reads, and writes back the same.
#[test]
fn an_event_batch_reads_and_writes_as_documented() {
    let json = r#"{"events":[{"seq":41,"kind":"welcome","user":"mimi://example.com/u/bob","room":"mimi://example.com/r/1f","bytes":"AAEA","received_at":1767225600},{"seq":42,"kind":"consent","user":"mimi://example.com/u/bob","consent":{"requester":"mimi://other.example/u/c","target":"mimi://example.com/u/bob","state":"requested"},"received_at":1767225601}],"more":false}"#;
    let batch: EventBatch = serde_json::from_str(json).unwrap();
    assert_eq!(batch.events[0].kind, EventKind::Welcome);
    assert_eq!(batch.events[0].mls_bytes(), Some(vec![0, 1, 0]));
    assert_eq!(batch.events[1].consent.as_ref().unwrap().state, "requested");
    assert_eq!(serde_json::to_string(&batch).unwrap(), json);
}

/// An event of a kind this version does not know reads as `Unrecognised`, with the rest of the event, and the batch
/// it comes in still reads: a newer hub's kind is handed on, never dropped or read as another kind.
#[test]
fn an_unknown_event_kind_reads_as_unrecognised_and_keeps_the_batch() {
    let json = r#"{"events":[{"seq":7,"kind":"welcome","user":"mimi://example.com/u/bob","received_at":1},{"seq":8,"kind":"roomnotice","user":"mimi://example.com/u/bob","room":"mimi://example.com/r/1f","bytes":"AAEA","received_at":2}],"more":false}"#;
    let batch: EventBatch =
        serde_json::from_str(json).expect("PLANT-EVENTKIND-OTHER: the batch reads");
    assert_eq!(batch.events.len(), 2);
    assert_eq!(batch.events[0].kind, EventKind::Welcome);
    assert_eq!(batch.events[1].kind, EventKind::Unrecognised);
    assert_eq!(
        batch.events[1].room.as_deref(),
        Some("mimi://example.com/r/1f")
    );
    assert_eq!(batch.events[1].mls_bytes(), Some(vec![0, 1, 0]));
}

/// A request refuses a field it does not know; an answer takes one, so a newer hub does not break an older client.
#[test]
fn requests_are_strict_and_answers_are_not() {
    assert!(serde_json::from_str::<AckRequest>(r#"{"up_to_seq":1,"extra":true}"#).is_err());
    assert_eq!(
        serde_json::from_str::<FetchRequest>("{}").unwrap(),
        FetchRequest {
            after_seq: 0,
            limit: FetchRequest::MAX_LIMIT
        }
    );
    let info: Info = serde_json::from_str(
        r#"{"lane_version":1,"delivery":"events","push":false,"stream":{"last_seq":2,"acked_through":0},"later":1}"#,
    )
    .unwrap();
    assert_eq!(info.delivery, Delivery::Events);
    assert_eq!(info.stream.unwrap().last_seq, 2);
}
