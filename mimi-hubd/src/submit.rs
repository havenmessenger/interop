//! Accepting an application message for a room this hub hosts, from either path: a peer's `submitMessage` for one of
//! its users, or the client lane's for its verified user. The caller has already bound `sender` to whoever asked.

use crate::Provider;

/// What became of a submitted application message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// Fanned out to every other local member and every other provider with a participant.
    Accepted,
    /// Not taken: the sender may not send here, or the message is empty or larger than one queued item. Nothing is
    /// queued.
    Refused,
    /// The fan-out failed on a store error, the hub's own fault: never reported as accepted.
    Failed,
}

impl Provider {
    /// Accept `message` from `sender` into `room_uri` and fan it out. [`Acceptance::Refused`] (nothing queued) when the
    /// sender is not an active participant whose role may send, or the message is empty or larger than one queued item;
    /// [`Acceptance::Failed`] when the fan-out fails on a store error, so a sender is never told a message was taken
    /// that was not queued.
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

#[cfg(test)]
#[path = "submit_tests.rs"]
mod tests;
