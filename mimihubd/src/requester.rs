//! Who asked for a room change: a peer provider on the provider path, or a user of this hub on the client lane.
//!
//! The room-change paths ask one question of the requester at every point where authority matters: may it speak for
//! a given user? A peer speaks for every user of a domain its proof authenticates, except this provider's own: what a
//! user of this provider does reaches the hub through the client lane, never through a peer. A lane user speaks only
//! for itself,
//! so on the lane a leave removes only its sender, an external Commit joins only its sender, and a GroupInfo that seeds
//! a room's tree is signed by its sender.

use crate::peer::PeerIdentity;

/// The party a room-change request came from.
#[derive(Clone, Copy, Debug)]
pub enum Requester<'a> {
    /// A provider, by the proof its request carried; `None` when it carried none.
    Peer(Option<&'a PeerIdentity>),
    /// A user of this hub, by the client lane's verified `mimi-client-user` (a canonical user URI).
    LaneUser(&'a str),
}

impl<'a> From<Option<&'a PeerIdentity>> for Requester<'a> {
    fn from(peer: Option<&'a PeerIdentity>) -> Self {
        Requester::Peer(peer)
    }
}

impl Requester<'_> {
    /// Whether this requester may act for `user`, whose provider is `authority`, at the hub of `local_domain`.
    ///
    /// `authority` must be the host of `user`'s own parsed URI, never a value from the request: a peer is trusted for
    /// exactly the users its proof authenticates, so an authority the requester could choose would let it speak for
    /// anyone. Every caller passes one read from a parsed URI: a joiner's (`MimiUri::parse`), a stored participant
    /// row's (set from the member's URI when the row was written), or a GroupInfo signer's (`provider_of`).
    pub fn may_speak_for(&self, user: &str, authority: &str, local_domain: &str) -> bool {
        match self {
            Requester::Peer(peer) => {
                !authority.eq_ignore_ascii_case(local_domain)
                    && peer.is_some_and(|peer| peer.authenticates(authority))
            }
            Requester::LaneUser(lane_user) => {
                mimi_core::uri::canonical(user) == mimi_core::uri::canonical(lane_user)
            }
        }
    }

    /// Whether the request named anyone at all: a peer that presented no proof did not.
    pub fn is_named(&self) -> bool {
        !matches!(self, Requester::Peer(None))
    }
}
