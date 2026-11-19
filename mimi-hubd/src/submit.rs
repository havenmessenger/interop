//! Accepting an application message for a room this hub hosts, from either path: a peer's `submitMessage` for one of
//! its users, or the client lane's for its verified user. The caller has already bound `sender` to whoever asked.

use mimi_core::protocol_wire::{inspect_mls_outer_header, MlsContentType, MlsWireFormat};

use crate::Provider;

/// What became of a submitted application message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// Fanned out to every other local member and every other provider with a participant.
    Accepted,
    /// Not taken: the sender may not send here; the message is empty or larger than one queued item; it is not an MLS
    /// PrivateMessage carrying an application message; or, in a room whose tree this hub keeps, it is for another group
    /// or for an epoch after the room's. Nothing is queued.
    Refused,
    /// Not taken: the room's group has moved on to `current_epoch`, and the message is for an earlier one (draft-ietf-
    /// mimi-protocol-07 §5.4 `epochTooOld`). Nothing is queued; the sender resends in the current epoch.
    EpochTooOld { current_epoch: u64 },
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
            eprintln!("[mimi-hubd] submitMessage: notAllowed (the sender is not an active participant, or lacks canSendMessage)");
            return Acceptance::Refused;
        }
        if message.is_empty() || message.len() > crate::store::MAX_ITEM_BYTES {
            eprintln!("[mimi-hubd] submitMessage: notAllowed (the message is empty or larger than a queued item)");
            return Acceptance::Refused;
        }
        match self.framing(room_uri, message) {
            Ok(Framing::Fits) => {}
            Ok(Framing::Refused(why)) => {
                eprintln!("[mimi-hubd] submitMessage: notAllowed ({why})");
                return Acceptance::Refused;
            }
            Ok(Framing::Behind(current_epoch)) => {
                eprintln!("[mimi-hubd] submitMessage: epochTooOld (the room's group is at epoch {current_epoch})");
                return Acceptance::EpochTooOld { current_epoch };
            }
            Err(error) => {
                eprintln!("[mimi-hubd] submitMessage: the room's group could not be read: {error}");
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

/// Whether a message's MLS framing fits the room it is submitted to.
enum Framing {
    Fits,
    Refused(&'static str),
    /// The message is for an epoch before the room's, which is this one.
    Behind(u64),
}

impl Provider {
    /// Read the message's outer header, with no key (RFC 9420 §6.3): a submitted message is a PrivateMessage carrying
    /// an application message (draft-ietf-mimi-protocol-07 §5.4). For a room whose tree this hub keeps, its group must
    /// be the room's and its epoch the room's current one. A room whose tree the hub does not keep has its framing
    /// checked only: its epoch comes from Commits the hub could not verify (DIVERGENCES DIV-20).
    fn framing(&self, room_uri: &str, message: &[u8]) -> anyhow::Result<Framing> {
        let Ok(header) = inspect_mls_outer_header(message) else {
            return Ok(Framing::Refused("the message is not an MLS message"));
        };
        if header.wire_format != MlsWireFormat::PrivateMessage
            || header.content_type != MlsContentType::Application
        {
            return Ok(Framing::Refused(
                "the message is not a PrivateMessage carrying an application message",
            ));
        }
        let Some(tracking) = self.room_tracking(room_uri)? else {
            return Ok(Framing::Fits);
        };
        if header.group_id != tracking.group_id {
            return Ok(Framing::Refused("the message is for another group"));
        }
        // The room's epoch as the hub keeps it, which is its tracked group's: a Commit is accepted only at it and moves
        // it to the next, and a seed's GroupInfo is for the epoch after the Commit that brought it. Read without loading
        // the tree.
        let current = self
            .store
            .room_epoch(room_uri)?
            .ok_or_else(|| anyhow::anyhow!("a tracked room has no epoch on record"))?;
        Ok(match header.epoch.cmp(&current) {
            std::cmp::Ordering::Equal => Framing::Fits,
            std::cmp::Ordering::Less => Framing::Behind(current),
            std::cmp::Ordering::Greater => {
                Framing::Refused("the message is for an epoch after the room's")
            }
        })
    }
}

#[cfg(test)]
#[path = "submit_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "submit_framing_tests.rs"]
mod framing_tests;
