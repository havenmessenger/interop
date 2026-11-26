//! Delivering what another hub fans out for a room it hosts to this provider's users in that room (protocol-07 §5.5).
//!
//! A `notify` is taken only from the room's hub (`notify_source`). Then:
//!
//! - **A Welcome** is queued for each user of this provider whose published KeyPackage it names (found by the
//!   `KeyPackageRef` recorded when it was published), and makes that user a member of the room here.
//! - **Anything else** (a Commit, proposals, an application message) is queued, as its MLSMessage, for every member of the
//!   room here, in the order it arrives. When the room has none, the `notify` is refused (`no-local-member`) before
//!   anything is recorded, so it is never accepted and delivered to nobody.
//!
//! A `notify` whose body was already accepted from the hub is answered 201 and changes nothing (§5.5). So is one whose
//! FanoutMessage, timestamp aside, was already delivered for the room, as the same message sent again in another body
//! would be. A membership does not end when a Commit removes the user: this provider keeps neither the room's
//! participant list nor its tree, so it cannot tell which user a list index or a leaf is (DIVERGENCES, DIV-5).

use mimi_core::protocol_wire::FanoutMessage;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::MlsMessageIn;
use sha2::{Digest, Sha256};

use crate::notify_source::VerifiedNotifySource;
use crate::{NotifyOutcome, Provider};

/// What a `notify` for a room on another hub came to.
#[derive(Debug, PartialEq, Eq)]
pub enum FollowedDelivery {
    /// Queued for this many users of this provider.
    Delivered(usize),
    /// Already delivered: nothing changes.
    Duplicate,
    /// No user of this provider is a member of the room: refused, nothing recorded.
    NoLocalMember,
}

/// The MLSMessage at the start of a FanoutMessage's `message_and_tail`, without the tail. `None` when its end cannot be
/// found, which the decoder that accepted the FanoutMessage already rules out.
fn message_of(message_and_tail: &[u8]) -> Option<&[u8]> {
    std::panic::catch_unwind(|| {
        let mut rest = message_and_tail;
        MlsMessageIn::tls_deserialize(&mut rest)
            .ok()
            .map(|_| message_and_tail.len() - rest.len())
    })
    .ok()
    .flatten()
    .map(|end| &message_and_tail[..end])
}

impl Provider {
    /// Deliver a `notify` from the hub of `room_uri`, a room on another hub, to this provider's members of it.
    pub fn deliver_followed(
        &self,
        source: &VerifiedNotifySource,
        room_uri: &str,
        body: &[u8],
        fanout: &FanoutMessage,
        now_unix: u64,
    ) -> anyhow::Result<FollowedDelivery> {
        // A Welcome that fails its gate is still a Welcome: it is accepted and queued for nobody, as before.
        let is_welcome = !matches!(
            mimi_core::gate::welcome_new_members(&fanout.message_and_tail),
            Err(mimi_core::gate::GateError::NotAWelcome)
        );
        let members = if is_welcome {
            Vec::new()
        } else {
            let members = self.store.followed_members(room_uri)?;
            if members.is_empty() {
                return Ok(FollowedDelivery::NoLocalMember);
            }
            members
        };
        if self.submit_notify(source, body, now_unix)? == NotifyOutcome::DuplicateIgnored {
            return Ok(FollowedDelivery::Duplicate);
        }
        let digest = Sha256::digest(&fanout.message_and_tail);
        if !self
            .store
            .first_followed_delivery(room_uri, &digest, now_unix)?
        {
            return Ok(FollowedDelivery::Duplicate);
        }
        if is_welcome {
            let users =
                self.deliver_notified_welcome_to(room_uri, &fanout.message_and_tail, now_unix)?;
            for user in &users {
                self.store.add_followed_member(room_uri, user, now_unix)?;
            }
            return Ok(FollowedDelivery::Delivered(users.len()));
        }
        let message = message_of(&fanout.message_and_tail).unwrap_or(&fanout.message_and_tail);
        // A member whose queue refuses the message is skipped (and logged); the others still get it.
        let (queued, _skipped) =
            self.queue_for_members(&members, room_uri, &[message], now_unix)?;
        Ok(FollowedDelivery::Delivered(queued))
    }
}
