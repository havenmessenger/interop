//! The provider event stream as the provider's own server reads it: one sequence of everything the hub holds for the
//! provider's users (`store_events.rs`), delivered by pull or by push, with one contract.
//!
//! - **Pull.** The server calls `events/wait` (held until an event past its cursor exists, or the timeout), then
//!   `events/fetch` and `events/ack`. These are provider-level calls on the client lane, not calls for one user.
//! - **Push.** With a push URL configured, the hub posts the same batches to the server (`event_push.rs`): a `2xx`
//!   acknowledges through the batch's last `seq`.
//!
//! Both read the same events in `seq` order and move the same cursor, so an operator can change transport without
//! losing or repeating anything past the acknowledged `seq`. Delivery is at least once: a receiver keeps the highest
//! `seq` it has handled and skips any event at or below it.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::http::SharedProvider;
use crate::store::{ConsentChange, EventAck, EventCursor, EventKind, EventRow};
use crate::Provider;

/// The version of the client lane's contract this hub serves.
pub const LANE_VERSION: u32 = 1;

/// The most events one fetch or one pushed batch carries.
// LIMIT-REASON: wire-cost: one answer stays bounded; the stream itself is not capped, a reader takes it in pages
pub const MAX_EVENTS_PAGE: usize = 256;

/// The most payload bytes one fetch or one pushed batch carries beyond its first event.
// LIMIT-REASON: wire-cost: a page of base64 MLS objects stays a few megabytes
pub const MAX_EVENTS_PAGE_BYTES: usize = 4 * 1024 * 1024;

/// The longest an `events/wait` is held.
// LIMIT-REASON: wire-cost: under common proxy and load-balancer idle timeouts (30 s and up)
pub const MAX_WAIT_MS: u64 = 25_000;

/// One event on the wire. `bytes` is the MLS object, base64 (standard alphabet), for `welcome` and `message`;
/// `consent` is the change, for `consent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEvent {
    pub seq: i64,
    pub kind: EventKind,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent: Option<ConsentChange>,
    pub received_at: i64,
}

impl From<EventRow> for WireEvent {
    fn from(row: EventRow) -> Self {
        Self {
            seq: row.seq,
            kind: row.kind,
            user: row.user,
            room: row.room,
            bytes: row.bytes.map(|bytes| STANDARD.encode(bytes)),
            consent: row.consent,
            received_at: row.received_at,
        }
    }
}

/// A page of events: what `events/fetch` answers and what a push posts. `more` says further events were waiting when
/// the page was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventBatch {
    pub events: Vec<WireEvent>,
    pub more: bool,
}

/// What `events/wait` answers: the last `seq` written and the users with events past the caller's cursor. Empty
/// `users` and the caller's own cursor mean the wait timed out with nothing new.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitAnswer {
    pub latest_seq: i64,
    pub users: Vec<String>,
}

/// Why an events call was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum EventsRefusal {
    /// The hub delivers through per-user queues; the provider stream is off.
    NotEventDelivery,
}

impl Provider {
    /// Deliver through the provider event stream instead of per-user queues (`lane_delivery = "events"`).
    pub fn with_event_delivery(mut self) -> Self {
        let domain = self.domain.clone();
        self.store
            .deliver_as_events(&domain, Arc::new(Notify::new()));
        self
    }

    /// Push the event stream to the provider's server (`event_push.rs` does the pushing). Refused when the stream is off.
    pub fn with_event_push(mut self) -> anyhow::Result<Self> {
        self.store.set_event_push()?;
        Ok(self)
    }

    /// Whether the hub pushes the event stream to the provider's server.
    pub fn pushes_events(&self) -> bool {
        self.store.pushes_events()
    }

    /// Whether this hub delivers through the provider event stream.
    pub fn delivers_events(&self) -> bool {
        self.store.delivers_events()
    }

    /// What is notified after each event is written, when the stream is on.
    pub fn event_waker(&self) -> Option<Arc<Notify>> {
        self.store.event_waker()
    }

    /// One page of events after `after_seq`.
    pub fn events_page(
        &self,
        after_seq: i64,
        limit: usize,
    ) -> anyhow::Result<Result<EventBatch, EventsRefusal>> {
        if !self.delivers_events() {
            return Ok(Err(EventsRefusal::NotEventDelivery));
        }
        let (rows, more) = self.store.fetch_events(
            after_seq,
            limit.clamp(1, MAX_EVENTS_PAGE),
            MAX_EVENTS_PAGE_BYTES,
        )?;
        Ok(Ok(EventBatch {
            events: rows.into_iter().map(WireEvent::from).collect(),
            more,
        }))
    }

    /// Acknowledge the events up to `up_to_seq`.
    pub fn events_ack(&self, up_to_seq: i64) -> anyhow::Result<Result<EventAck, EventsRefusal>> {
        if !self.delivers_events() {
            return Ok(Err(EventsRefusal::NotEventDelivery));
        }
        Ok(Ok(self.store.ack_events(up_to_seq)?))
    }

    /// Where the stream stands.
    pub fn events_cursor(&self) -> anyhow::Result<EventCursor> {
        self.store.event_cursor()
    }

    /// The users with events after `after_seq`.
    pub fn users_with_events_after(&self, after_seq: i64) -> anyhow::Result<Vec<String>> {
        self.store.users_with_events_after(after_seq)
    }
}

/// Wait until an event past `after_seq` exists, or `timeout` passes; then answer where the stream stands. The provider
/// is locked only to read, never across the wait.
pub async fn wait_for_events(
    provider: &SharedProvider,
    after_seq: i64,
    timeout: Duration,
) -> anyhow::Result<Result<WaitAnswer, EventsRefusal>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let (wake, cursor) = {
            let provider = crate::http::lock(provider);
            let Some(wake) = provider.event_waker() else {
                return Ok(Err(EventsRefusal::NotEventDelivery));
            };
            (wake, provider.events_cursor()?)
        };
        // Registered before the stream is read again, so an event written in between still wakes this wait.
        let notified = wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let cursor = if cursor.last_seq > after_seq {
            cursor
        } else {
            crate::http::lock(provider).events_cursor()?
        };
        if cursor.last_seq > after_seq {
            let users = crate::http::lock(provider).users_with_events_after(after_seq)?;
            return Ok(Ok(WaitAnswer {
                latest_seq: cursor.last_seq,
                users,
            }));
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            return Ok(Ok(WaitAnswer {
                latest_seq: cursor.last_seq,
                users: Vec::new(),
            }));
        }
    }
}

#[cfg(test)]
#[path = "client_lane_events_tests.rs"]
mod tests;
