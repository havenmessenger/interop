//! Accepting an application message for a room this hub hosts, from either path: a peer's `submitMessage` for one of
//! its users, or the client lane's for its verified user. The caller has already bound `sender` to whoever asked.

use openmls::framing::{MlsMessageIn, WireFormat};
use openmls::group::PublicGroup;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{ContentType, GroupId};

use crate::Provider;

/// What became of a submitted application message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// Fanned out to every other local member and every other provider with a participant.
    Accepted,
    /// Not taken: the sender may not send here, or the message is empty or larger than one queued item. Nothing is
    /// queued.
    Refused,
    /// Not taken: the room's tree is kept here, and the message's framing names another group, or an epoch past the
    /// room's. Nothing is queued.
    WrongGroup,
    /// Not taken: the message is not an application message as RFC 9420 §6 has one, a PrivateMessage carrying
    /// application content (a PublicMessage, a Commit or a proposal, or bytes that are no MLS message). Nothing is
    /// queued.
    NotApplication,
    /// The fan-out failed on a store error, the hub's own fault: never reported as accepted.
    Failed,
}

impl Provider {
    /// Accept `message` from `sender` into `room_uri` and fan it out. [`Acceptance::Refused`] (nothing queued) when the
    /// sender is not an active participant whose role may send, or the message is empty or larger than one queued item;
    /// [`Acceptance::Failed`] when the fan-out fails on a store error, so a sender is never told a message was taken
    /// that was not queued.
    ///
    /// A store error can come part-way through the fan-out (other providers' outbox rows are queued before local members'
    /// queues), so a failed message may already have reached some members; a resent copy reaches them again, and MLS drops
    /// it as a replay.
    ///
    /// Nothing is kept under the room itself: fan-out queues the message for each other local member and for each other
    /// provider with a participant, and those queues alone bound delivery. A room-keyed copy would have no reader, and
    /// a room's own queue, filled to its cap within the delivery lifetime, would refuse every sender.
    pub fn accept_application_message(
        &self,
        room_uri: &str,
        sender: &str,
        message: &[u8],
        now_unix: u64,
    ) -> Acceptance {
        if self.authorize_sender(room_uri, sender).is_err() {
            eprintln!("[mimihubd] submitMessage: notAllowed (the sender is not an active participant, or lacks canSendMessage)");
            return Acceptance::Refused;
        }
        if message.is_empty() || message.len() > crate::store::MAX_ITEM_BYTES {
            eprintln!("[mimihubd] submitMessage: notAllowed (the message is empty or larger than a queued item)");
            return Acceptance::Refused;
        }
        if !is_application_message(message) {
            eprintln!("[mimihubd] submitMessage: notAllowed (not a PrivateMessage carrying application content)");
            return Acceptance::NotApplication;
        }
        match self.framing_fits(room_uri, message) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("[mimihubd] submitMessage: notAllowed (the framing names another group, or an epoch past the room's)");
                return Acceptance::WrongGroup;
            }
            Err(error) => {
                eprintln!("[mimihubd] submitMessage: cannot read the room's tree: {error}");
                return Acceptance::Failed;
            }
        }
        let fanout = self.fan_out_application(room_uri, sender, message, now_unix);
        let outcome = if fanout.is_ok() {
            Acceptance::Accepted
        } else {
            Acceptance::Failed
        };
        crate::log_fanout("application message", room_uri, fanout);
        outcome
    }
}

/// Whether `message` is an application message as RFC 9420 §6 has one: an MLSMessage carrying a PrivateMessage whose
/// content type, which its framing carries in the clear, is `application`. "Applications MUST use PrivateMessage to
/// encrypt application messages"; a handshake message (a Commit, a proposal) goes to `update`, not here. Nothing is
/// decrypted.
pub fn is_application_message(message: &[u8]) -> bool {
    MlsMessageIn::tls_deserialize_exact(message)
        .ok()
        .and_then(|message| message.try_into_protocol_message().ok())
        .is_some_and(|framing| {
            framing.wire_format() == WireFormat::PrivateMessage
                && framing.content_type() == ContentType::Application
        })
}

impl Provider {
    /// Whether `message`'s cleartext framing fits `room_uri`. In a room whose tree the hub keeps, it must be an MLS
    /// message naming the room's group, at an epoch no later than the room's: a member routes an incoming message to a
    /// chat by its group id, and treats one from a later epoch as a sign it missed a Commit, so a message framed for
    /// another group, or for an epoch the room has not reached, must not reach any member. An earlier epoch is let
    /// through: a message sent just before a Commit the hub took first is still one its members can read. No message is
    /// decrypted; a room whose tree the hub does not keep has no group to compare with, and is not checked.
    pub fn framing_fits(&self, room_uri: &str, message: &[u8]) -> anyhow::Result<bool> {
        let Some(tracking) = self.store.room_tree(room_uri)? else {
            return Ok(true);
        };
        let Some(framing) = MlsMessageIn::tls_deserialize_exact(message)
            .ok()
            .and_then(|message| message.try_into_protocol_message().ok())
        else {
            return Ok(false);
        };
        if framing.group_id().as_slice() != tracking.group_id.as_slice() {
            return Ok(false);
        }
        let groups = self.store.groups();
        let Some(group) = PublicGroup::load(&groups, &GroupId::from_slice(&tracking.group_id))
            .map_err(|error| anyhow::anyhow!("the room's group: {error:?}"))?
        else {
            anyhow::bail!("a tracked room with no stored group");
        };
        Ok(framing.epoch() <= group.group_context().epoch())
    }
}

#[cfg(test)]
#[path = "submit_tests.rs"]
mod tests;
