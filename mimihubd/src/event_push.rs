//! Pushing the provider event stream (`client_lane_events.rs`) to the provider's own server.
//!
//! With `events_push_url` set, the hub posts the stream to that URL in batches, in `seq` order, one batch in flight:
//!
//! - The body is an [`EventBatch`], `application/json`, the same shape `events/fetch` answers.
//! - A `2xx` acknowledges through the batch's last `seq`, exactly as `events/ack` would, and the next batch follows.
//! - Any other answer, or no answer, is a failed attempt: the same batch (and anything written since, up to the batch
//!   bounds) is posted again after `min(1 s * 2^failures, 5 min)`, or later when the server's `Retry-After` asks for it.
//!   No answer drops a batch, a `4xx` included, since that would lose events.
//! - The cursor is the store's: after a restart pushing resumes from the last acknowledged `seq`, and pull and push move
//!   the same one, so switching transport loses and repeats nothing past it.
//!
//! Delivery is at least once (a `2xx` whose acknowledgement is lost to a crash is posted again), so the server skips any
//! event at or below the highest `seq` it has handled. Every request goes through the hub's one outbound client
//! (`outbound.rs`): the URL's host is the provider's own domain or a subdomain of it, its addresses pass the outbound
//! policy, and the request is signed with the provider's key (`request_signing.rs`), with the client certificate when one
//! is configured. The server checks that signature to know the batch came from its hub.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Notify;

use crate::client_lane_events::MAX_EVENTS_PAGE;
use crate::http::SharedProvider;
use crate::outbound::{PeerClient, PeerUrl};
use crate::outbox::{retry_after_ms, retry_delay_ms};
use crate::store::EventAck;

/// How often the pusher looks for events when nothing wakes it.
const IDLE_WAKE: Duration = Duration::from_secs(1);

/// What one push attempt came to.
#[derive(Debug, PartialEq, Eq)]
pub enum PushAttempt {
    /// Nothing was waiting.
    Idle,
    /// The batch was accepted, and the cursor is now at `through`; `more` says further events were waiting.
    Delivered { through: i64, more: bool },
    Failed {
        why: String,
        retry_after_ms: Option<u64>,
    },
}

/// The pusher. [`EventPusher::spawn`] runs it.
pub struct EventPusher {
    provider: SharedProvider,
    client: Arc<PeerClient>,
    url: PeerUrl,
    wake: Arc<Notify>,
}

impl EventPusher {
    /// A pusher for `provider`'s stream to `url`, which must be on the provider's own domain or a subdomain of it. Refused
    /// when the provider does not deliver through the event stream.
    pub fn new(
        provider: SharedProvider,
        client: Arc<PeerClient>,
        url: &str,
    ) -> anyhow::Result<Arc<Self>> {
        let (domain, wake) = {
            let provider = crate::http::lock(&provider);
            let wake = provider.event_waker().ok_or_else(|| {
                anyhow::anyhow!("event push needs event delivery (lane_delivery = \"events\")")
            })?;
            (provider.domain().to_string(), wake)
        };
        let url = PeerUrl::parse(url, &domain)
            .map_err(|error| anyhow::anyhow!("events_push_url: {error}"))?;
        Ok(Arc::new(Self {
            provider,
            client,
            url,
            wake,
        }))
    }

    pub fn spawn(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let pusher = self.clone();
        tokio::spawn(async move { pusher.run().await })
    }

    async fn run(self: Arc<Self>) {
        let mut failures: u32 = 0;
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.push_once().await {
                PushAttempt::Delivered { more: true, .. } => {
                    failures = 0;
                    continue;
                }
                PushAttempt::Delivered { more: false, .. } => {
                    failures = 0;
                }
                PushAttempt::Idle => {}
                PushAttempt::Failed {
                    why,
                    retry_after_ms,
                } => {
                    let delay = retry_delay_ms(failures, retry_after_ms);
                    failures = failures.saturating_add(1);
                    eprintln!(
                        "[mimihubd] events: push failed ({why}); attempt {failures}, next in {} s",
                        delay / 1000
                    );
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    continue;
                }
            }
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep(IDLE_WAKE) => {}
            }
        }
    }

    /// Post the batch after the cursor, and acknowledge it when the server takes it.
    pub async fn push_once(&self) -> PushAttempt {
        let failed = |why: String| PushAttempt::Failed {
            why,
            retry_after_ms: None,
        };
        let batch = {
            let provider = crate::http::lock(&self.provider);
            let read = provider.events_cursor().and_then(|cursor| {
                provider
                    .events_page(cursor.acked_through, MAX_EVENTS_PAGE)
                    .map(|page| page.map_err(|refusal| anyhow::anyhow!("{refusal:?}")))
            });
            match read {
                Ok(Ok(batch)) => batch,
                Ok(Err(error)) | Err(error) => {
                    return failed(format!("cannot read the stream: {error}"))
                }
            }
        };
        let Some(last) = batch.events.last().map(|event| event.seq) else {
            return PushAttempt::Idle;
        };
        let more = batch.more;
        let body = match serde_json::to_vec(&batch) {
            Ok(body) => body,
            Err(error) => return failed(format!("cannot encode the batch: {error}")),
        };
        match self.client.post(&self.url, "application/json", body).await {
            Ok(response) if (200..300).contains(&response.status) => {
                match crate::http::lock(&self.provider).events_ack(last) {
                    Ok(Ok(EventAck::AckedThrough(through))) => {
                        PushAttempt::Delivered { through, more }
                    }
                    Ok(Ok(EventAck::PastEnd { .. })) | Ok(Err(_)) => {
                        failed("the stream refused the acknowledgement".into())
                    }
                    Err(error) => failed(format!("cannot acknowledge: {error}")),
                }
            }
            Ok(response) => PushAttempt::Failed {
                why: format!("answered {}", response.status),
                retry_after_ms: response
                    .retry_after
                    .as_deref()
                    .and_then(|value| retry_after_ms(value, SystemTime::now())),
            },
            Err(error) => failed(error.to_string()),
        }
    }
}

#[cfg(test)]
#[path = "event_push_tests.rs"]
mod tests;
