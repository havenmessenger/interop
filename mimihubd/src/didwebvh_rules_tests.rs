use mimi_core::app_data::ComponentChange;
use mls_didwebvh::{DidWebvhHead, DidWebvhHeads};

use super::{component_ids, resolve_heads};
use crate::didwebvh_fixtures::log;

fn head(path: &str, seed: u8) -> DidWebvhHead {
    DidWebvhHead::from_log(
        log(
            path,
            seed,
            &[[seed; 32]],
            &[&format!("mimi://example.com/u/{path}")],
        )
        .verified(),
    )
}

fn encoded(heads: &[DidWebvhHead]) -> Vec<u8> {
    let mut record = DidWebvhHeads::new();
    for head in heads {
        record.insert(head.clone());
    }
    record.encode().unwrap()
}

/// An update's entries replace the entries of the same SCID or are inserted in order; updates apply in the Commit's
/// order; with no record before, the first update starts it.
#[test]
fn updates_replace_by_scid_and_insert_in_order() {
    let (a, b, c) = (head("a", 1), head("b", 2), head("c", 3));
    let from_none =
        resolve_heads(None, &[ComponentChange::Update(&encoded(&[a.clone()]))]).unwrap();
    assert_eq!(from_none, encoded(&[a.clone()]));
    let before = encoded(&[a.clone(), b.clone()]);
    let after = resolve_heads(
        Some(&before),
        &[
            ComponentChange::Update(&encoded(&[c.clone()])),
            ComponentChange::Update(&encoded(&[b.clone()])),
        ],
    )
    .unwrap();
    let after = DidWebvhHeads::decode(&after).unwrap();
    assert_eq!(after.heads().len(), 3);
    assert!(
        after.get(a.scid()).is_some()
            && after.get(b.scid()).is_some()
            && after.get(c.scid()).is_some()
    );
}

/// A removal, an update that does not decode or is not sorted, and a stored record that does not decode are refused.
#[test]
fn a_removal_or_a_bad_update_is_refused() {
    let before = encoded(&[head("a", 1)]);
    assert_eq!(
        resolve_heads(Some(&before), &[ComponentChange::Remove]),
        Err("the did_webvh_heads record is never removed")
    );
    assert!(resolve_heads(Some(&before), &[ComponentChange::Update(b"not a record")]).is_err());
    let (x, y) = (head("x", 4), head("y", 5));
    let (first, second) = if x.scid() < y.scid() { (x, y) } else { (y, x) };
    // The same two entries in ascending order are taken, and in descending order refused for their order alone.
    let ascending = vector(
        &[
            body(&encoded(&[first.clone()])),
            body(&encoded(&[second.clone()])),
        ]
        .concat(),
    );
    assert_eq!(ascending, encoded(&[first.clone(), second.clone()]));
    assert!(resolve_heads(None, &[ComponentChange::Update(&ascending)]).is_ok());
    let descending = vector(&[body(&encoded(&[second])), body(&encoded(&[first]))].concat());
    assert!(
        resolve_heads(None, &[ComponentChange::Update(&descending)]).is_err(),
        "an update whose entries are not sorted is invalid"
    );
    assert!(resolve_heads(Some(b"\\x05junk"), &[ComponentChange::Update(&before)]).is_err());
}

/// The bytes of an `opaque<V>` after its RFC 9420 §2.1.2 length.
fn body(vector: &[u8]) -> &[u8] {
    match vector[0] >> 6 {
        0 => &vector[1..],
        1 => &vector[2..],
        _ => &vector[4..],
    }
}

/// `bytes` as an `opaque<V>`, its length in one or two bytes.
fn vector(bytes: &[u8]) -> Vec<u8> {
    let mut out = if bytes.len() < 64 {
        vec![u8::try_from(bytes.len()).unwrap()]
    } else {
        let length = u16::try_from(bytes.len()).unwrap() | 0x4000;
        length.to_be_bytes().to_vec()
    };
    out.extend_from_slice(bytes);
    out
}

#[test]
fn app_components_decode_as_a_vector_of_ids() {
    assert_eq!(
        component_ids(&[0x04, 0x00, 0x01, 0xf0, 0x13]),
        Some(vec![0x0001, 0xf013])
    );
    assert_eq!(component_ids(&[0x00]), Some(vec![]));
    assert_eq!(
        component_ids(&[0x03, 0x00, 0x01, 0xf0]),
        None,
        "an odd length"
    );
    assert_eq!(
        component_ids(&[0x02, 0x00, 0x01, 0xf0]),
        None,
        "trailing bytes"
    );
    let mut two_byte = vec![0x40, 0x40];
    two_byte.extend(std::iter::repeat_n([0xf0, 0x13], 32).flatten());
    assert_eq!(component_ids(&two_byte).map(|ids| ids.len()), Some(32));
}
