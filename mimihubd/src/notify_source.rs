//! Who may `/notify` a room (protocol-07 §5.5).
//!
//! The hub of a room is the provider named by the authority of the room's MIMI URI. A provider that receives
//! `/notify/{roomId}` MUST verify that the source provider authenticated by the transport corresponds to that hub;
//! otherwise it MUST reject the request and MUST NOT process, store or forward anything the request carries.
//!
//! [`VerifiedNotifySource`] is that verification as a value. `Provider::submit_notify` takes one, and the only way to
//! make one outside a test is [`VerifiedNotifySource::verify`], so no route can reach the store without having asked the
//! question, whichever lane it arrived on.

use crate::peer::PeerIdentity;
use mimi_core::uri::{MimiKind, MimiUri};

/// Why a `/notify` was refused. The two are told apart for the log and the status line only; neither names the peer's
/// bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum NotifyRefusal {
    /// The path does not name a room under a provider domain.
    NotARoom,
    /// The peer's certificate does not authenticate the room's hub, or the connection presented none.
    NotFromTheHub,
}

/// Proof that the peer of this request authenticated as the hub of the room it names.
#[derive(Debug)]
pub struct VerifiedNotifySource {
    _verified: (),
}

impl VerifiedNotifySource {
    /// `room_uri` is the room the request names; `peer` is the certificate the connection presented, `None` for a
    /// connection that did not come through the mutually authenticated listener.
    pub fn verify(room_uri: &str, peer: Option<&PeerIdentity>) -> Result<Self, NotifyRefusal> {
        let hub = hub_domain(room_uri).ok_or(NotifyRefusal::NotARoom)?;
        match peer {
            Some(peer) if peer.authenticates(&hub) => Ok(Self { _verified: () }),
            _ => Err(NotifyRefusal::NotFromTheHub),
        }
    }

    /// A proof for a test that exercises the store behind the check and not the check.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self { _verified: () }
    }
}

/// The provider domain in the authority of a room URI: lowercased, with a port taken off.
fn hub_domain(room_uri: &str) -> Option<String> {
    let uri = MimiUri::parse(room_uri).ok()?;
    if uri.kind != Some(MimiKind::Room) {
        return None;
    }
    let host = match uri.authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => uri.authority.as_str(),
    };
    if host.is_empty() || host.contains(['@', '[', ']', ':']) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}
