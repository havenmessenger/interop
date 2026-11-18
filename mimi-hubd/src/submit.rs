//! Accepting an application message for a room this hub hosts, from either path: a peer's `submitMessage` for one of
//! its users, or the client lane's for its verified user. The caller has already bound `sender` to whoever asked.

use crate::Provider;

impl Provider {
    /// Accept `message` from `sender` into `room_uri` and fan it out. Refused (false, nothing queued) when the sender is
    /// not an active participant whose role may send, or the room does not take the message.
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
        if self.submit_message(room_uri, message, now_unix).is_err() {
            return false;
        }
        crate::log_fanout(
            "application message",
            room_uri,
            self.fan_out_application(room_uri, sender, message, now_unix),
        );
        true
    }
}
