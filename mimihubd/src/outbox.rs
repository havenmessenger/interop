//! Delivers the outbox (`store_outbox.rs`) to other providers' `/notify` (protocol-07 §5.5).
//!
//! Each (room, domain) pair is a FIFO queue, and only its head is attempted. What an attempt's answer does to the row:
//!
//! - `201`: delivered, removed.
//! - A `4xx` other than `408` and `429`: refused for good, removed and logged, so one message a peer will not take does
//!   not hold back every later one of the room.
//! - Anything else (another status, a network or TLS error, a directory that cannot be fetched or read, a request the
//!   outbound gate refuses): a failed attempt. The head waits `min(1 s * 2^attempts, 5 min)`, or longer when the peer's
//!   `Retry-After` asks for it (honoured up to a day), and is tried again with the same bytes.
//!
//! Nothing expires: a queue for a provider that is down keeps its order until it is delivered, or until the operator
//! drops it. Delivery is at least once (a crash between a `201` and the row's removal sends it again), which the
//! receiver's duplicate rule covers. Queues for different providers run side by side, at most [`MAX_IN_FLIGHT`]
//! attempts at a time and never two for one queue, so a slow provider holds up only its own queues.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;

use crate::http::SharedProvider;
use crate::outbound::PeerClient;
use crate::peer_directory::Directories;
use crate::store::OutboxRow;

/// The wait after a first failed attempt; each further failure doubles it.
pub const BASE_BACKOFF_MS: u64 = 1_000;
/// The longest wait the backoff reaches.
pub const MAX_BACKOFF_MS: u64 = 300_000;
/// The longest `Retry-After` honoured.
pub const MAX_RETRY_AFTER_MS: u64 = 86_400_000;
/// The most attempts in flight at once.
pub const MAX_IN_FLIGHT: usize = 8;
/// How often the worker looks for due rows when nothing wakes it.
const IDLE_WAKE: Duration = Duration::from_secs(1);

/// What one attempt came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Attempt {
    Delivered,
    /// Refused for good with this status.
    Refused(u16),
    Failed {
        why: String,
        retry_after_ms: Option<u64>,
    },
}

/// The worker. [`OutboxWorker::spawn`] runs it; [`OutboxWorker::waker`] is what an enqueue notifies.
pub struct OutboxWorker {
    provider: SharedProvider,
    client: Arc<PeerClient>,
    directories: Arc<Directories>,
    wake: Arc<Notify>,
    in_flight: Mutex<HashSet<(String, String)>>,
}

impl OutboxWorker {
    /// `wake` is the one the provider notifies after queueing fan-out (`Provider::with_outbox_waker`).
    pub fn new(
        provider: SharedProvider,
        client: Arc<PeerClient>,
        directories: Arc<Directories>,
        wake: Arc<Notify>,
    ) -> Arc<Self> {
        Arc::new(Self {
            provider,
            client,
            directories,
            wake,
            in_flight: Mutex::new(HashSet::new()),
        })
    }

    pub fn waker(&self) -> Arc<Notify> {
        self.wake.clone()
    }

    pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let worker = self.clone();
        tokio::spawn(async move { worker.run().await })
    }

    async fn run(self: Arc<Self>) {
        loop {
            self.start_due(now_ms());
            tokio::select! {
                () = self.wake.notified() => {}
                () = tokio::time::sleep(IDLE_WAKE) => {}
            }
        }
    }

    /// Start an attempt on the due head of every queue not already in flight, up to [`MAX_IN_FLIGHT`].
    fn start_due(self: &Arc<Self>, now_ms: u64) {
        let busy: Vec<(String, String)> = self.in_flight().iter().cloned().collect();
        if busy.len() >= MAX_IN_FLIGHT {
            return;
        }
        let heads = match self.lock().store.due_outbox_heads(now_ms, &busy) {
            Ok(heads) => heads,
            Err(error) => {
                eprintln!("[mimihubd] outbox: cannot read the queue: {error}");
                return;
            }
        };
        for row in heads.into_iter().take(MAX_IN_FLIGHT - busy.len()) {
            let queue = (row.room_uri.clone(), row.domain.clone());
            self.in_flight().insert(queue.clone());
            let worker = self.clone();
            tokio::spawn(async move {
                worker.attempt_and_settle(&row).await;
                worker.in_flight().remove(&queue);
                worker.wake.notify_one();
            });
        }
    }

    /// One attempt at `row`, and its outcome written to the store.
    pub async fn attempt_and_settle(&self, row: &OutboxRow) -> Attempt {
        let attempt = self.attempt(row).await;
        self.settle(row, &attempt, now_ms());
        attempt
    }

    /// One attempt at `row`: find the provider's `notify` endpoint and post the row's body to it.
    pub async fn attempt(&self, row: &OutboxRow) -> Attempt {
        let failed = |why: String| Attempt::Failed {
            why,
            retry_after_ms: None,
        };
        let directory = match self.directories.get(&self.client, &row.domain).await {
            Ok(directory) => directory,
            Err(error) => return failed(error.to_string()),
        };
        let url = match directory.endpoint("notify", "roomId", &row.room_uri, &row.domain) {
            Ok(url) => url,
            Err(error) => {
                self.directories.forget(&row.domain);
                return failed(error.to_string());
            }
        };
        let started = crate::telemetry::now();
        let result = self
            .client
            .post(&url, "application/mimi-protocol", row.body.clone())
            .await;
        self.client.telemetry().record_peer_request(
            &row.domain,
            "notify",
            Some(row.attempts.saturating_add(1)),
            started,
            &result,
            |response| response.status,
        );
        match result {
            Ok(response) if response.status == 201 => Attempt::Delivered,
            Ok(response) if refused_for_good(response.status) => Attempt::Refused(response.status),
            Ok(response) => {
                self.directories.forget(&row.domain);
                Attempt::Failed {
                    why: format!("answered {}", response.status),
                    retry_after_ms: response
                        .retry_after
                        .as_deref()
                        .and_then(|value| retry_after_ms(value, SystemTime::now())),
                }
            }
            Err(error) => {
                self.directories.forget(&row.domain);
                failed(error.to_string())
            }
        }
    }

    /// Write `attempt`'s outcome for `row`, at `now_ms`.
    pub fn settle(&self, row: &OutboxRow, attempt: &Attempt, now_ms: u64) {
        let provider = self.lock();
        let result = match attempt {
            Attempt::Delivered => {
                eprintln!(
                    "[mimihubd] outbox: delivered a fan-out for {} to {} (attempt {})",
                    row.room_uri,
                    row.domain,
                    row.attempts.saturating_add(1)
                );
                provider.store.remove_outbox_row(row.id)
            }
            Attempt::Refused(status) => {
                eprintln!(
                    "[mimihubd] outbox: {} refused a fan-out for {} with {status}; dropped",
                    row.domain, row.room_uri
                );
                provider.store.remove_outbox_row(row.id)
            }
            Attempt::Failed {
                why,
                retry_after_ms,
            } => {
                let delay = retry_delay_ms(row.attempts, *retry_after_ms);
                eprintln!(
                    "[mimihubd] outbox: a fan-out for {} to {} failed ({why}); attempt {}, next in {} s",
                    row.room_uri,
                    row.domain,
                    row.attempts.saturating_add(1),
                    delay / 1000
                );
                provider
                    .store
                    .record_outbox_attempt(row.id, now_ms.saturating_add(delay), why)
            }
        };
        if let Err(error) = result {
            eprintln!("[mimihubd] outbox: cannot record an attempt: {error}");
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, crate::Provider> {
        self.provider
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn in_flight(&self) -> std::sync::MutexGuard<'_, HashSet<(String, String)>> {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A status that refuses the row for good: any `4xx` but `408 Request Timeout` and `429 Too Many Requests`.
pub fn refused_for_good(status: u16) -> bool {
    (400..500).contains(&status) && status != 408 && status != 429
}

/// The wait before the next attempt, after `failures_before` earlier failures and this one: the backoff, or the
/// peer's `Retry-After` when that is longer.
pub fn retry_delay_ms(failures_before: u32, retry_after_ms: Option<u64>) -> u64 {
    let backoff = BASE_BACKOFF_MS
        .checked_shl(failures_before.min(32))
        .unwrap_or(MAX_BACKOFF_MS)
        .min(MAX_BACKOFF_MS);
    backoff.max(retry_after_ms.unwrap_or(0).min(MAX_RETRY_AFTER_MS))
}

/// A `Retry-After` value in milliseconds from `now`: delay-seconds or an HTTP-date (RFC 9110 §10.2.3). A date in the
/// past is 0; a value that is neither is `None`.
pub fn retry_after_ms(value: &str, now: SystemTime) -> Option<u64> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds.saturating_mul(1000));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(at.duration_since(now).map_or(0, |wait| {
        u64::try_from(wait.as_millis()).unwrap_or(u64::MAX)
    }))
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
#[path = "outbox_tests.rs"]
mod tests;
