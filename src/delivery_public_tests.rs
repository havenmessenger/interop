use super::*;

const PUBLIC_COMMIT: &str = "000100011086d81b32fdc820d8273b703fa003a27f0000000000000001010000000000033201f7a02e00002b266d696d693a2f2f6d696d692e686176656e6d657373656e6765722e636f6d2f752f6361726f6c000000030040400dfef6a4588d7dc2ef07df261d3af70f6c516cb112309659cc0daa682ac4b24024be15448d121120ac2564eeb0cdc959f3e5d724b85eb5de7b703fd6c4c0a108202679343f28f358284d92562bfd718cf0c5417fb067f89bc0707e07bbf575c30820213fc41210c12b5a97452b4ba17da2a75b5a07da42c509add02a592ca56a09cd";

#[test]
fn a_complete_public_commit_has_one_well_formed_custom_proposal() {
    let bytes = hex::decode(PUBLIC_COMMIT).expect("fixture is hex");
    assert_eq!(message_kind(&bytes).unwrap(), Some(MessageKind::Commit));
    require_public_message(&bytes, MessageKind::Commit).expect("complete public Commit");
    assert!(require_public_message(&bytes, MessageKind::Proposal).is_err());
    assert!(require_public_message(&bytes[..bytes.len() - 1], MessageKind::Commit).is_err());
}

#[test]
fn a_custom_proposal_reports_its_consumed_boundary_and_exact_payload() {
    let mut bytes = vec![0xf7, 0xa0, 0x01, 0xff];
    let (facts, consumed) = proposal_prefix(&bytes).expect("complete custom proposal");
    assert_eq!(consumed, bytes.len());
    assert_eq!(facts.custom, Some((0xf7a0, vec![0xff])));
    bytes.push(0);
    assert_eq!(proposal_prefix(&bytes).unwrap().1, consumed);
    assert!(proposal_exact(&bytes).is_err());
}

#[test]
fn proposal_references_refuse_an_unbound_suite_and_malformed_input() {
    assert!(proposal_reference(b"authenticated", 0x0003).is_err());
    assert!(proposal_ref_prefix(&[0xff]).is_err());
    assert!(proposal_prefix(&[0]).is_err());
}
