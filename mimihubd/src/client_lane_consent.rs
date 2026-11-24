//! Consent on the client lane (protocol-07 §8, §5.7): a user of this provider decides who may fetch their KeyPackages,
//! asks a user of another provider, and sees the requests made of them and the grants they hold.
//!
//! Only the user decides. The decision is recorded at this hub, the target's, where it gates the user's KeyPackages
//! ([`Provider::keypackage_access`]); a peer never writes it (`process_update_consent` takes a decision only for a
//! requester of this provider). A decision's scope is the draft's `ConsentScope`: one requesting user, optionally one
//! room. With the policy's `consent_provider_grants` a user may also decide for every user of a provider, read after
//! the user's own decisions. It is read against the requester URI's domain, which any peer naming a room on its own
//! domain can choose (DIVERGENCES DIV-6), so on it admits any authenticated peer. A grant to a user of another provider
//! is sent to that provider as `updateConsent`, so the requester's client knows it may add the user; a revoke is not,
//! unless `consent_revoke_notifies` (§8: "a consent revocation/rejection is typically not communicated"). Either way
//! the decision stands: it is the gate.
//!
//! A request made of a user stays pending for `consent_request_days`, then is dropped; ignoring one leaves it pending,
//! and a revoke with no request is a preemptive one ("block"). Opting out withdraws the user's KeyPackages and, unless
//! `consent_kept_at_opt_out`, clears the user's decisions and the requests made of them, so opting in again starts
//! over.

use mimi_core::consent::{validate_consent_entry, ConsentEntry, ConsentOperation};
use mimi_core::protocol_wire::encode_consent_entry;
use mimi_core::uri::{MimiKind, MimiUri};

use crate::Provider;

const SECONDS_PER_DAY: u64 = 86_400;

/// Why a lane consent call is not taken.
#[derive(Debug, PartialEq, Eq)]
pub enum LaneConsentRefusal {
    /// The call names something that is not what it should be: a user URI, a room URI, a domain.
    Malformed(&'static str),
    /// The hub's policy does not take it: a decision for a whole provider without `consent_provider_grants`.
    NotPermitted(&'static str),
}

/// Whom a decision is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentRequester {
    /// One requesting user, by URI.
    User(String),
    /// Every user of a provider, by domain (`consent_provider_grants`).
    Provider(String),
}

/// A consent message to send to another provider, as this provider: its peer route and body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentMessage {
    /// The provider it goes to.
    pub domain: String,
    /// Its directory endpoint (`requestConsent` or `updateConsent`) and that endpoint's variable.
    pub endpoint: &'static str,
    pub variable: &'static str,
    /// The `ConsentEntry`, encoded.
    pub body: Vec<u8>,
}

/// A request made of a user, as the lane lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub seq: i64,
    pub requester: String,
    pub room: Option<String>,
    pub at: u64,
}

/// A grant a user holds from another user, as the lane lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldGrant {
    pub target: String,
    pub room: Option<String>,
    pub at: u64,
}

/// The requester column's value for a decision covering every user of `domain`. A user URI always has a path, so this
/// never names a user.
pub(crate) fn provider_scope(domain: &str) -> String {
    format!("mimi://{}", domain.to_ascii_lowercase())
}

/// The provider domain a user URI belongs to.
fn domain_of(user: &str) -> Option<String> {
    MimiUri::parse(user)
        .ok()
        .filter(|uri| uri.kind == Some(MimiKind::User))
        .map(|uri| uri.authority.to_ascii_lowercase())
}

fn room_key(room: Option<&str>) -> Option<String> {
    room.map(mimi_core::uri::canonical)
}

fn check_room(room: Option<&str>) -> Result<(), LaneConsentRefusal> {
    match room {
        Some(room)
            if MimiUri::parse(room)
                .ok()
                .is_none_or(|uri| uri.kind != Some(MimiKind::Room)) =>
        {
            Err(LaneConsentRefusal::Malformed("room is not a room URI"))
        }
        _ => Ok(()),
    }
}

impl Provider {
    /// The lane user `user` grants (`grant`) or revokes a requester's access to their KeyPackages, optionally for one
    /// room. Returns the `updateConsent` to send to the requester's provider, when there is one to send.
    pub fn lane_decide_consent(
        &self,
        user: &str,
        requester: &ConsentRequester,
        room: Option<&str>,
        grant: bool,
        now_unix: u64,
    ) -> anyhow::Result<Result<Option<ConsentMessage>, LaneConsentRefusal>> {
        if let Err(refusal) = check_room(room) {
            return Ok(Err(refusal));
        }
        let requester = match requester {
            ConsentRequester::Provider(domain) => {
                if !self.policy.consent_provider_grants {
                    return Ok(Err(LaneConsentRefusal::NotPermitted(
                        "this hub takes consent for one requesting user, not a provider",
                    )));
                }
                if room.is_some() {
                    return Ok(Err(LaneConsentRefusal::Malformed(
                        "a decision for a provider is for any room",
                    )));
                }
                if domain_of(&format!("mimi://{domain}/u/x")).as_deref()
                    != Some(domain.to_ascii_lowercase().as_str())
                {
                    return Ok(Err(LaneConsentRefusal::Malformed(
                        "provider is not a domain",
                    )));
                }
                self.store.set_consent(
                    &provider_scope(domain),
                    user,
                    "",
                    if grant { "granted" } else { "revoked" },
                    now_unix,
                )?;
                return Ok(Ok(None));
            }
            ConsentRequester::User(requester) => requester,
        };
        let entry = ConsentEntry {
            operation: if grant {
                ConsentOperation::Grant
            } else {
                ConsentOperation::Revoke
            },
            requester_uri: mimi_core::uri::canonical(requester),
            target_uri: user.to_string(),
            room_uri: room_key(room),
            client_key_packages: Vec::new(),
            consent_extensions: Vec::new(),
        };
        if validate_consent_entry(&entry).is_err() || entry.requester_uri == entry.target_uri {
            return Ok(Err(LaneConsentRefusal::Malformed(
                "requester is not another user's URI",
            )));
        }
        self.record_consent_decision(&entry, now_unix)?;
        let send = !self.is_local_user(&entry.requester_uri)
            && (grant || self.policy.consent_revoke_notifies);
        if !send {
            return Ok(Ok(None));
        }
        let domain = domain_of(&entry.requester_uri)
            .ok_or_else(|| anyhow::anyhow!("a checked user URI names no provider"))?;
        Ok(Ok(Some(ConsentMessage {
            domain,
            endpoint: "updateConsent",
            variable: "requesterDomain",
            body: encode_consent_entry(&entry)?,
        })))
    }

    /// The lane user `user` asks `target` for consent to fetch their KeyPackages, optionally for one room, or cancels
    /// that request (`cancel`). A target of this provider has it recorded here, as `requestConsent` from a peer would;
    /// for any other, returns the `requestConsent` to send to the target's provider.
    pub fn lane_request_consent(
        &self,
        user: &str,
        target: &str,
        room: Option<&str>,
        cancel: bool,
        now_unix: u64,
    ) -> anyhow::Result<Result<Option<ConsentMessage>, LaneConsentRefusal>> {
        if let Err(refusal) = check_room(room) {
            return Ok(Err(refusal));
        }
        let entry = ConsentEntry {
            operation: if cancel {
                ConsentOperation::Cancel
            } else {
                ConsentOperation::Request
            },
            requester_uri: user.to_string(),
            target_uri: mimi_core::uri::canonical(target),
            room_uri: room_key(room),
            client_key_packages: Vec::new(),
            consent_extensions: Vec::new(),
        };
        if validate_consent_entry(&entry).is_err() || entry.requester_uri == entry.target_uri {
            return Ok(Err(LaneConsentRefusal::Malformed(
                "target is not another user's URI",
            )));
        }
        if self.is_local_user(&entry.target_uri) {
            self.record_local_request(&entry, now_unix)?;
            return Ok(Ok(None));
        }
        let domain = domain_of(&entry.target_uri)
            .ok_or_else(|| anyhow::anyhow!("a checked user URI names no provider"))?;
        Ok(Ok(Some(ConsentMessage {
            domain,
            endpoint: "requestConsent",
            variable: "targetDomain",
            body: encode_consent_entry(&entry)?,
        })))
    }

    /// A request or cancel between two users of this provider, recorded as one from a peer would be: a request is kept
    /// unless the target already decided for the scope, and a cancel withdraws a pending request and nothing else.
    fn record_local_request(&self, entry: &ConsentEntry, now_unix: u64) -> anyhow::Result<()> {
        self.expire_consent_requests(now_unix)?;
        let room = entry.room_uri.as_deref().unwrap_or("");
        match entry.operation {
            ConsentOperation::Request => {
                if self
                    .store
                    .consent_state(&entry.requester_uri, &entry.target_uri, room)?
                    .is_none()
                {
                    self.store.set_consent(
                        &entry.requester_uri,
                        &entry.target_uri,
                        room,
                        "requested",
                        now_unix,
                    )?;
                }
            }
            _ => {
                self.store.withdraw_consent_request(
                    &entry.requester_uri,
                    &entry.target_uri,
                    room,
                )?;
            }
        }
        Ok(())
    }

    /// The time before which a pending request has expired: `consent_request_days` before `now_unix`.
    fn request_cutoff(&self, now_unix: u64) -> u64 {
        let days = u64::from(self.policy.consent_request_days);
        now_unix.saturating_sub(days.saturating_mul(SECONDS_PER_DAY))
    }

    /// Drop the requests older than `consent_request_days`.
    pub(crate) fn expire_consent_requests(&self, now_unix: u64) -> anyhow::Result<()> {
        self.store
            .expire_consent_requests(self.request_cutoff(now_unix))?;
        Ok(())
    }

    /// The pending requests made of `user`, after `after`, oldest first, at most `limit`.
    pub fn lane_consent_requests(
        &self,
        user: &str,
        after: i64,
        limit: usize,
        now_unix: u64,
    ) -> anyhow::Result<Vec<PendingRequest>> {
        self.expire_consent_requests(now_unix)?;
        Ok(self
            .store
            .consent_requests_for(user, after, self.request_cutoff(now_unix), limit)?
            .into_iter()
            .map(|(seq, requester, room, at)| PendingRequest {
                seq,
                requester,
                room: (!room.is_empty()).then_some(room),
                at,
            })
            .collect())
    }

    /// The grants `user` holds from other users. A revoke is never listed.
    pub fn lane_consent_received(&self, user: &str) -> anyhow::Result<Vec<HeldGrant>> {
        Ok(self
            .store
            .consent_grants_held_by(user)?
            .into_iter()
            .map(|(target, room, at)| HeldGrant {
                target,
                room: (!room.is_empty()).then_some(room),
                at,
            })
            .collect())
    }

    /// `user` opts out: their KeyPackages are withdrawn, and, unless the policy keeps them, their consent decisions and
    /// the requests made of them are cleared. Returns (KeyPackages withdrawn, consent rows cleared).
    pub fn lane_opt_out(&self, user: &str) -> anyhow::Result<(usize, usize)> {
        let withdrawn = self.lane_withdraw(user)?;
        let cleared = if self.policy.consent_kept_at_opt_out {
            0
        } else {
            self.store.clear_consent_as_target(user)?
        };
        Ok((withdrawn, cleared))
    }
}

#[cfg(test)]
#[path = "client_lane_consent_tests.rs"]
mod tests;
