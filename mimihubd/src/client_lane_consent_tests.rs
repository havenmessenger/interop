use mimi_core::consent::{ConsentEntry, ConsentOperation, KeyPackageAccess};
use mimi_core::protocol_wire::decode_consent_entry;
use openmls::prelude::tls_codec::Serialize as _;

use super::{ConsentRequester, LaneConsentRefusal};
use crate::mls_fixtures::Member;
use crate::peer::PeerIdentity;
use crate::Provider;

const DOMAIN: &str = "havenmessenger.com";
const ALICE: &str = "mimi://havenmessenger.com/u/alice";
const BOB: &str = "mimi://havenmessenger.com/u/bob";
const ZED: &str = "mimi://other.example/u/zed";
const YURI: &str = "mimi://other.example/u/yuri";
const ROOM: &str = "mimi://havenmessenger.com/r/room";
const OTHER_ROOM: &str = "mimi://havenmessenger.com/r/other";
const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn hub() -> Provider {
    Provider::in_memory(DOMAIN).unwrap()
}

fn access(p: &Provider, requester: &str, room: Option<&str>) -> KeyPackageAccess {
    p.keypackage_access(requester, BOB, room).unwrap()
}

fn decide(
    p: &Provider,
    requester: &str,
    room: Option<&str>,
    grant: bool,
) -> Result<Option<super::ConsentMessage>, LaneConsentRefusal> {
    p.lane_decide_consent(
        BOB,
        &ConsentRequester::User(requester.into()),
        room,
        grant,
        NOW,
    )
    .unwrap()
}

fn entry(message: &super::ConsentMessage) -> ConsentEntry {
    decode_consent_entry(&message.body, &[0x0001]).unwrap()
}

/// A request a peer brings, as `requestConsent` from `requester`'s provider.
fn peer_request(p: &Provider, requester: &str, at: u64) {
    let domain = requester.split('/').nth(2).unwrap();
    p.process_request_consent(
        &ConsentEntry {
            operation: ConsentOperation::Request,
            requester_uri: requester.into(),
            target_uri: BOB.into(),
            room_uri: None,
            client_key_packages: Vec::new(),
            consent_extensions: Vec::new(),
        },
        Some(&PeerIdentity::signed(domain)),
        at,
    )
    .unwrap();
}

fn listed(p: &Provider, now: u64) -> Vec<String> {
    p.lane_consent_requests(BOB, 0, 100, now)
        .unwrap()
        .into_iter()
        .map(|request| request.requester)
        .collect()
}

/// A grant opens the user's KeyPackages to the requester, for any room; a revoke closes them. Revert check: skip
/// recording the decision, and the requester is still refused after the grant.
#[test]
fn a_grant_opens_the_gate_and_a_revoke_closes_it() {
    let p = hub();
    assert_eq!(access(&p, ZED, None), KeyPackageAccess::NoConsent);
    decide(&p, ZED, None, true).unwrap();
    assert_eq!(
        access(&p, ZED, Some(ROOM)),
        KeyPackageAccess::Allowed,
        "PLANT-CONSENT-GRANT-RECORDED: a grant did not open the gate"
    );
    decide(&p, ZED, None, false).unwrap();
    assert_eq!(access(&p, ZED, None), KeyPackageAccess::NoConsent);
}

/// A grant for one room covers that room only.
#[test]
fn a_room_grant_covers_that_room_only() {
    let p = hub();
    decide(&p, ZED, Some(ROOM), true).unwrap();
    assert_eq!(access(&p, ZED, Some(ROOM)), KeyPackageAccess::Allowed);
    assert_eq!(
        access(&p, ZED, Some(OTHER_ROOM)),
        KeyPackageAccess::NoConsent
    );
    assert_eq!(access(&p, ZED, None), KeyPackageAccess::NoConsent);
}

/// A grant to a user of another provider goes to that provider as `updateConsent`; a revoke does not, unless the policy
/// says so; a decision for a user of this provider goes nowhere. Revert check: send every decision, and the revoke is
/// sent by default.
#[test]
fn a_grant_is_sent_to_the_requesters_provider_and_a_revoke_is_not_by_default() {
    let p = hub();
    let grant = decide(&p, ZED, Some(ROOM), true)
        .unwrap()
        .expect("a grant is sent");
    assert_eq!(
        (grant.domain.as_str(), grant.endpoint, grant.variable),
        ("other.example", "updateConsent", "requesterDomain")
    );
    let sent = entry(&grant);
    assert_eq!(sent.operation, ConsentOperation::Grant);
    assert_eq!(
        (sent.requester_uri.as_str(), sent.target_uri.as_str()),
        (ZED, BOB)
    );
    assert_eq!(sent.room_uri.as_deref(), Some(ROOM));
    assert_eq!(
        decide(&p, ZED, Some(ROOM), false).unwrap(),
        None,
        "PLANT-CONSENT-REVOKE-QUIET: a revoke was sent by default"
    );
    assert_eq!(
        decide(&p, ALICE, None, true).unwrap(),
        None,
        "Alice is here"
    );

    let mut p = hub();
    p.policy.consent_revoke_notifies = true;
    let revoke = decide(&p, ZED, None, false)
        .unwrap()
        .expect("sent on the setting");
    assert_eq!(entry(&revoke).operation, ConsentOperation::Revoke);
}

/// A request made of the user is listed until the user decides, the requester cancels, or it expires; asking again
/// after it expired renews it. Revert check: list requests whatever their age, and the expired one is still listed.
#[test]
fn a_request_is_listed_until_decided_cancelled_or_expired() {
    let p = hub();
    peer_request(&p, ZED, NOW);
    p.lane_request_consent(ALICE, BOB, None, false, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(listed(&p, NOW), vec![ZED.to_string(), ALICE.to_string()]);
    decide(&p, ZED, None, true).unwrap();
    assert_eq!(listed(&p, NOW), vec![ALICE.to_string()], "decided");
    p.lane_request_consent(ALICE, BOB, None, true, NOW)
        .unwrap()
        .unwrap();
    assert!(listed(&p, NOW).is_empty(), "cancelled");

    peer_request(&p, YURI, NOW);
    let later = NOW + 31 * DAY;
    assert!(
        listed(&p, later).is_empty(),
        "PLANT-CONSENT-REQUEST-EXPIRY: a request past consent_request_days was listed"
    );
    peer_request(&p, YURI, later);
    assert_eq!(
        listed(&p, later),
        vec![YURI.to_string()],
        "asking again renews it"
    );
}

/// A request to a user of another provider goes to that provider as `requestConsent`, and a cancel the same way.
#[test]
fn a_request_to_a_user_of_another_provider_is_sent_there() {
    let p = hub();
    let ask = p
        .lane_request_consent(BOB, ZED, Some(ROOM), false, NOW)
        .unwrap()
        .unwrap()
        .expect("sent");
    assert_eq!(
        (ask.domain.as_str(), ask.endpoint, ask.variable),
        ("other.example", "requestConsent", "targetDomain")
    );
    let sent = entry(&ask);
    assert_eq!(sent.operation, ConsentOperation::Request);
    assert_eq!(
        (sent.requester_uri.as_str(), sent.target_uri.as_str()),
        (BOB, ZED)
    );
    let cancel = p
        .lane_request_consent(BOB, ZED, Some(ROOM), true, NOW)
        .unwrap()
        .unwrap()
        .expect("sent");
    assert_eq!(entry(&cancel).operation, ConsentOperation::Cancel);
}

/// A requester lists the grants it holds, a remote target's included, and never a revoke. Revert check: list every
/// decision, and the revoked one is listed.
#[test]
fn the_requester_lists_the_grants_it_holds_and_never_a_revoke() {
    let p = hub();
    let from_zed = |operation| ConsentEntry {
        operation,
        requester_uri: ALICE.into(),
        target_uri: ZED.into(),
        room_uri: None,
        client_key_packages: Vec::new(),
        consent_extensions: Vec::new(),
    };
    let zeds_provider = PeerIdentity::signed("other.example");
    p.process_update_consent(
        &from_zed(ConsentOperation::Grant),
        Some(&zeds_provider),
        NOW,
    )
    .unwrap();
    p.lane_decide_consent(BOB, &ConsentRequester::User(ALICE.into()), None, true, NOW)
        .unwrap()
        .unwrap();
    let held = |p: &Provider| -> Vec<String> {
        p.lane_consent_received(ALICE)
            .unwrap()
            .into_iter()
            .map(|grant| grant.target)
            .collect()
    };
    assert_eq!(held(&p), vec![ZED.to_string(), BOB.to_string()]);
    p.process_update_consent(
        &from_zed(ConsentOperation::Revoke),
        Some(&zeds_provider),
        NOW,
    )
    .unwrap();
    assert_eq!(
        held(&p),
        vec![BOB.to_string()],
        "PLANT-CONSENT-NO-REVOKE-LISTED: a revoke was listed"
    );
}

/// Opting out withdraws the user's KeyPackages and clears their decisions and the requests made of them, so a grant
/// from before does not open the gate once they publish again; on the setting the decisions stay. Revert check: keep
/// the decisions by default, and the old grant still opens the gate.
#[test]
fn opting_out_withdraws_key_packages_and_clears_consent() {
    for kept in [false, true] {
        let mut p = hub();
        p.policy.consent_kept_at_opt_out = kept;
        let key_package = Member::new(BOB)
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        p.add_key_package("bob", &key_package, NOW + 1000).unwrap();
        decide(&p, ZED, None, true).unwrap();
        peer_request(&p, YURI, NOW);
        let (withdrawn, cleared) = p.lane_opt_out(BOB).unwrap();
        assert_eq!(withdrawn, 1);
        if kept {
            assert_eq!(cleared, 0);
            assert_eq!(access(&p, ZED, None), KeyPackageAccess::Allowed);
        } else {
            assert_eq!(
                access(&p, ZED, None),
                KeyPackageAccess::NoConsent,
                "PLANT-CONSENT-CLEARED-AT-OPT-OUT: a grant from before opting out still opens the gate"
            );
            assert_eq!(cleared, 2, "the grant and the request");
            assert!(listed(&p, NOW).is_empty());
        }
    }
}

/// A decision for every user of a provider needs the setting. On it, any user of that provider is let in, and a user's
/// own revoke still keeps that user out. Revert check: skip the setting, and the provider grant is taken by default.
#[test]
fn provider_grants_need_the_setting_and_a_users_own_revoke_wins() {
    let p = hub();
    let provider = ConsentRequester::Provider("other.example".into());
    assert!(
        matches!(
            p.lane_decide_consent(BOB, &provider, None, true, NOW)
                .unwrap(),
            Err(LaneConsentRefusal::NotPermitted(_))
        ),
        "PLANT-CONSENT-PROVIDER-GATED: a provider grant was taken without the setting"
    );
    assert_eq!(access(&p, ZED, None), KeyPackageAccess::NoConsent);

    let mut p = hub();
    p.policy.consent_provider_grants = true;
    p.lane_decide_consent(BOB, &provider, None, true, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(access(&p, ZED, None), KeyPackageAccess::Allowed);
    assert_eq!(access(&p, YURI, Some(ROOM)), KeyPackageAccess::Allowed);
    assert_eq!(
        access(&p, ALICE, None),
        KeyPackageAccess::NoConsent,
        "another provider"
    );
    decide(&p, ZED, None, false).unwrap();
    assert_eq!(
        access(&p, ZED, None),
        KeyPackageAccess::NoConsent,
        "PLANT-CONSENT-USER-REVOKE-WINS: a provider grant outranked the user's own revoke"
    );
    assert_eq!(access(&p, YURI, None), KeyPackageAccess::Allowed);
}

/// What a decision or request names must be what it should be: another user, a room, a domain.
#[test]
fn malformed_scopes_are_refused() {
    let mut p = hub();
    p.policy.consent_provider_grants = true;
    assert!(matches!(
        decide(&p, BOB, None, true),
        Err(LaneConsentRefusal::Malformed(_))
    ));
    assert!(matches!(
        decide(&p, ZED, Some(ALICE), true),
        Err(LaneConsentRefusal::Malformed(_))
    ));
    assert!(matches!(
        p.lane_decide_consent(
            BOB,
            &ConsentRequester::Provider("other.example/u/zed".into()),
            None,
            true,
            NOW
        )
        .unwrap(),
        Err(LaneConsentRefusal::Malformed(_))
    ));
    assert!(matches!(
        p.lane_request_consent(BOB, "not a uri", None, false, NOW)
            .unwrap(),
        Err(LaneConsentRefusal::Malformed(_))
    ));
}
