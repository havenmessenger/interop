//! The client lane: requests from this provider's own client-facing service, each acting for one of its users.
//!
//! MIMI leaves the client-to-provider interface to each provider. Here the provider's client-facing service (the one
//! that authenticates its users' sessions) signs every request it forwards with HTTP Message Signatures (RFC 9421,
//! Ed25519), covering the user it acts for. The signature (`tag="mimi-client-lane"`) covers, in order:
//!
//! ```text
//! "@method" "@target-uri" "content-digest" "mimi-client-user" "mimi-client-device"
//! ```
//!
//! with `created`, a `nonce` and `keyid`. `Content-Digest` (RFC 9530, `sha-256`) is sent on every request, an empty
//! body included. A request is accepted only when the signature verifies with a key in the lane's key file, its nonce is
//! fresh, it was made within the last 30 seconds and not before this process started, and `mimi-client-user` is a user
//! URI on this provider's own domain: the lane can act only for this provider's users.
//!
//! The lane trusts the service for who the user is and nothing else. Policy, consent, roles and the suite gate are
//! applied to the user exactly as they are to a peer provider's member.

use std::time::SystemTime;

use mimi_core::uri::{MimiKind, MimiUri};

use crate::signature::{
    verify_with, NonceLedger, PeerKeys, Refusal, SignedDomain, SignedRequest, VerifyProfile,
};

/// The name the lane's keys are filed under: `<keyid>._mimi.client-lane` in the lane's key file.
pub const KEY_DOMAIN: &str = "client-lane";

/// The longest a `mimi-client-user` or `mimi-client-device` value may be.
// LIMIT-REASON: input: a user URI and a device handle are single short header values
pub const MAX_HEADER_VALUE_LEN: usize = 512;

/// What a lane request's signature must cover and how old it may be.
pub const LANE: VerifyProfile = VerifyProfile {
    tag: "mimi-client-lane",
    strict_tag: true,
    required_with_body: &[
        "@method",
        "@target-uri",
        "content-digest",
        "mimi-client-user",
        "mimi-client-device",
    ],
    required_without_body: &[
        "@method",
        "@target-uri",
        "content-digest",
        "mimi-client-user",
        "mimi-client-device",
    ],
    digest_always: true,
    nonce_required: true,
    max_age_secs: 30,
    max_skew_secs: 30,
    domain: SignedDomain::Fixed(KEY_DOMAIN),
};

/// What a provider-level lane request's signature must cover: the provider's server acting for itself, not for one of
/// its users (the event stream's `events/*` and `info`). Its own tag, so a signature made for a user's request is never
/// accepted as one made for the provider, or the other way round.
pub const LANE_PROVIDER: VerifyProfile = VerifyProfile {
    tag: "mimi-client-lane-provider",
    strict_tag: true,
    required_with_body: &["@method", "@target-uri", "content-digest"],
    required_without_body: &["@method", "@target-uri", "content-digest"],
    digest_always: true,
    nonce_required: true,
    max_age_secs: 30,
    max_skew_secs: 30,
    domain: SignedDomain::Fixed(KEY_DOMAIN),
};

/// Why a lane request was not accepted, beyond the signature's own refusals.
#[derive(Debug, PartialEq, Eq)]
pub enum LaneRefusal {
    Signature(Refusal),
    /// Signed before this process started: its nonce could have been used in a run whose ledger is gone.
    BeforeStart,
    /// `mimi-client-user` is missing, not a user URI, or not on this provider's domain.
    NotLocalUser,
    /// `mimi-client-device` is missing or malformed.
    NoDevice,
}

/// A lane request that was accepted: the user it acts for, and the device handle it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneUser {
    /// The user's URI in canonical form.
    pub user: String,
    pub device: String,
}

/// The lane's verifier: its keys, its nonces, and the time this process started.
pub struct ClientLaneAuth {
    pub keys: PeerKeys,
    pub nonces: NonceLedger,
    pub started_unix: i64,
    /// This provider's domain; a user on any other is refused.
    pub domain: String,
}

impl ClientLaneAuth {
    /// The user a lane request acts for, or why it is refused. Records the nonce of a request that verifies.
    pub fn verify(
        &self,
        request: &SignedRequest<'_>,
        now: SystemTime,
    ) -> Result<LaneUser, LaneRefusal> {
        let verified =
            verify_with(request, now, &self.keys, &LANE).map_err(LaneRefusal::Signature)?;
        if verified.created < self.started_unix {
            return Err(LaneRefusal::BeforeStart);
        }
        let user = header_value(request, "mimi-client-user").ok_or(LaneRefusal::NotLocalUser)?;
        let uri = MimiUri::parse(&user).map_err(|_| LaneRefusal::NotLocalUser)?;
        if uri.kind != Some(MimiKind::User) || !uri.is_local_to(&self.domain) {
            return Err(LaneRefusal::NotLocalUser);
        }
        let device = header_value(request, "mimi-client-device").ok_or(LaneRefusal::NoDevice)?;
        let seconds = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
            });
        self.nonces
            .record(&verified, seconds)
            .map_err(LaneRefusal::Signature)?;
        Ok(LaneUser {
            user: mimi_core::uri::canonical(&user),
            device,
        })
    }
}

impl ClientLaneAuth {
    /// Accept a provider-level lane request ([`LANE_PROVIDER`]), or say why not. Records the nonce of one that verifies.
    pub fn verify_provider(
        &self,
        request: &SignedRequest<'_>,
        now: SystemTime,
    ) -> Result<(), LaneRefusal> {
        let verified = verify_with(request, now, &self.keys, &LANE_PROVIDER)
            .map_err(LaneRefusal::Signature)?;
        if verified.created < self.started_unix {
            return Err(LaneRefusal::BeforeStart);
        }
        let seconds = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
            });
        self.nonces
            .record(&verified, seconds)
            .map_err(LaneRefusal::Signature)
    }
}

/// One header's value: present once, printable ASCII, and short.
fn header_value(request: &SignedRequest<'_>, name: &str) -> Option<String> {
    let value = (request.header)(name)?;
    let value = value.trim();
    (!value.is_empty()
        && value.len() <= MAX_HEADER_VALUE_LEN
        && !value.contains(',')
        && value.bytes().all(|b| b.is_ascii_graphic()))
    .then(|| value.to_string())
}

#[cfg(test)]
#[path = "client_lane_tests.rs"]
mod tests;
