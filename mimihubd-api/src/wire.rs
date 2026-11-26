//! The lane's bodies. A request type refuses a field it does not know, as the hub does; an answer type ignores one, so
//! a client keeps working when the hub adds a field.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// What an event of the provider stream carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    /// A Welcome, with the room it joins when the hub knew it.
    Welcome,
    /// An MLSMessage for a room: a Commit, a proposal or an application message, as the hub took it.
    Message,
    /// A change to a consent record that concerns the user.
    Consent,
}

/// A consent change: the directional record and its new state. `room` is the room of a room-scoped record. `state` is
/// `requested` (for the target), `granted` or `revoked` (for the requester), or `withdrawn` (a pending request its
/// requester took back, for the target).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentChange {
    pub requester: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    pub state: String,
}

/// One event of the provider stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Its place in the stream: one more than the event before it, across every user and room.
    pub seq: i64,
    pub kind: EventKind,
    /// The user it is for, as a URI on the provider's domain.
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// The MLS object, base64 (standard alphabet), for a Welcome or a message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent: Option<ConsentChange>,
    /// When the hub took it, in Unix seconds.
    pub received_at: i64,
}

impl Event {
    /// The MLS object it carries, decoded; `None` when it carries none or it does not decode.
    pub fn mls_bytes(&self) -> Option<Vec<u8>> {
        self.bytes.as_deref().and_then(|b| STANDARD.decode(b).ok())
    }
}

/// A page of the stream: what `events/fetch` answers and what a push posts. `more` says further events were waiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventBatch {
    pub events: Vec<Event>,
    pub more: bool,
}

/// `events/wait`: held until an event past `after_seq` exists, or `timeout_ms` (at most 25000).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitRequest {
    #[serde(default)]
    pub after_seq: i64,
    #[serde(default = "WaitRequest::default_timeout_ms")]
    pub timeout_ms: u64,
}

impl WaitRequest {
    /// The longest the hub holds a wait.
    pub const MAX_TIMEOUT_MS: u64 = 25_000;

    fn default_timeout_ms() -> u64 {
        Self::MAX_TIMEOUT_MS
    }
}

/// What `events/wait` answers: the last `seq` written, and the users with events past the caller's cursor (empty when
/// the wait timed out).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitAnswer {
    pub latest_seq: i64,
    pub users: Vec<String>,
}

/// `events/fetch`: the events past `after_seq`, at most `limit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchRequest {
    #[serde(default)]
    pub after_seq: i64,
    #[serde(default = "FetchRequest::default_limit")]
    pub limit: usize,
}

impl FetchRequest {
    /// The most events one page carries.
    pub const MAX_LIMIT: usize = 256;

    fn default_limit() -> usize {
        Self::MAX_LIMIT
    }
}

/// `events/ack`: every event up to `up_to_seq` was handled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRequest {
    pub up_to_seq: i64,
}

/// What `events/ack` answers: the hub's cursor afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckAnswer {
    pub acked_through: i64,
}

/// Where the stream stands: the last `seq` written and the last acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCursor {
    pub last_seq: i64,
    pub acked_through: i64,
}

/// How a push stands: enough to see one that is stuck, and why, without any event's content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushStatus {
    /// The last `seq` the provider's server acknowledged by push.
    pub acked_through: i64,
    /// Failed attempts since the last one that went through.
    pub failures: u32,
    /// Why the last attempt failed, while the push is failing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// When the last attempt was made, in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<i64>,
}

/// How the hub hands the provider's users what it holds for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Delivery {
    /// Per-user, legacy: a queue per user, read with `inboxFetch` and `inboxAck`.
    Inbox,
    /// The provider stream.
    Events,
}

/// What `info` answers (its request is `{}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    pub lane_version: u32,
    pub delivery: Delivery,
    /// Whether the hub pushes the event stream to the provider's server.
    pub push: bool,
    /// Where the stream stands, for a hub delivering through it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<StreamCursor>,
    /// How the push stands, for a hub that pushes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_status: Option<PushStatus>,
}

/// What `createRoom` answers (its request is `{}`): the room, the role its creator holds, and the app data components
/// the creator's group starts with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedRoom {
    pub room: String,
    pub creator_role: u32,
    #[serde(default)]
    pub components: Vec<Component>,
}

/// One app data component: its id and its data, base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub id: u16,
    pub data: String,
}

/// `submitMessage`: an application message into a room, base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitMessageRequest {
    pub room: String,
    pub message: String,
}

/// `update`: an UpdateRequest as the wire carries it (a Commit bundle, or a leave's proposals), base64. Its answer is
/// the wire's (`success` with `epoch`, `wrongEpoch` with `current_epoch`, `notAllowed`, `invalidProposal` with a
/// `description`), read as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRequest {
    pub room: String,
    pub update: String,
}

/// `publishKeyPackages`: KeyPackages for the user, base64. Its answer is a [`Count`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    pub key_packages: Vec<String>,
}

/// A count of what a call took or removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Count {
    pub count: usize,
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
