//! Accepting an application message for a room this hub hosts, from either path: a peer's `submitMessage` for one of
//! its users, or the client lane's for its verified user. The caller has already bound `sender` to whoever asked.

use crate::Provider;

impl Provider {
    /// Accept `message` from `sender` into `room_uri` and fan it out. Refused (false, nothing queued) when the sender is
    /// not an active participant whose role may send, or the message is empty or larger than one queued item; and
    /// refused when the fan-out fails on a store error, so a sender is never told a message was taken that was not
    /// queued.
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
    ) -> bool {
        if self.authorize_sender(room_uri, sender).is_err() {
            eprintln!("[mimi-hubd] submitMessage: notAllowed (the sender is not an active participant, or lacks canSendMessage)");
            return false;
        }
        if message.is_empty() || message.len() > crate::store::MAX_ITEM_BYTES {
            eprintln!("[mimi-hubd] submitMessage: notAllowed (the message is empty or larger than a queued item)");
            return false;
        }
        let fanout = self.fan_out_application(room_uri, sender, message, now_unix);
        let queued = fanout.is_ok();
        crate::log_fanout("application message", room_uri, fanout);
        queued
    }
}

#[cfg(test)]
#[path = "submit_tests.rs"]
mod tests;
