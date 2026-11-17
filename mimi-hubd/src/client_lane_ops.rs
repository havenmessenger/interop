//! What the client lane does for one of this provider's users: publish and withdraw their KeyPackages, and read and
//! clear their queues. The lane's caller has already been authenticated for `user` (`client_lane`); nothing here takes
//! a user from a request body.

use mimi_core::uri::{MimiKind, MimiUri};

use crate::store::{QueueKind, QueuedItem};
use crate::Provider;

/// The most items one inbox read returns from each queue.
// LIMIT-REASON: wire-cost: one answer stays a few megabytes at most (256 items at the store's per-item bound)
pub const MAX_INBOX_PAGE: usize = 256;

/// The most KeyPackages one publish may carry.
// LIMIT-REASON: quota: the store keeps a bounded set per user; a larger publish would only evict its own rows
pub const MAX_PUBLISH: usize = 32;

/// Why a publish was refused. Nothing from a refused publish is stored.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishRefusal {
    /// Too many KeyPackages in one request.
    TooMany,
    /// The KeyPackage at this index does not pass the suite gate or does not decode and validate.
    NotAccepted(usize),
    /// The KeyPackage at this index names someone other than the user in its basic credential.
    NotTheUser(usize),
}

/// One inbox read: the queued items after the given cursors, oldest first, and whether more are waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxPage {
    pub welcomes: Vec<QueuedItem>,
    pub messages: Vec<QueuedItem>,
    pub more: bool,
}

impl Provider {
    /// The name `user` (a URI on this provider's domain) is stored under: the part after `/u/`.
    pub fn local_name(&self, user: &str) -> Option<String> {
        let uri = MimiUri::parse(user).ok()?;
        if uri.kind != Some(MimiKind::User) || !uri.is_local_to(&self.domain) {
            return None;
        }
        let canonical = mimi_core::uri::canonical(user);
        let name = canonical.rsplit_once("/u/")?.1;
        (!name.is_empty() && !name.contains('/')).then(|| name.to_string())
    }

    /// Publish `key_packages` for `user`: each must pass the suite gate and carry `user`, exactly, as its basic
    /// credential's identity. All are checked before any is stored.
    pub fn lane_publish(
        &self,
        user: &str,
        key_packages: &[Vec<u8>],
        now_unix: u64,
    ) -> anyhow::Result<Result<usize, PublishRefusal>> {
        let Some(name) = self.local_name(user) else {
            anyhow::bail!("not a user of this provider");
        };
        if key_packages.len() > MAX_PUBLISH {
            return Ok(Err(PublishRefusal::TooMany));
        }
        let user = mimi_core::uri::canonical(user);
        for (at, kp) in key_packages.iter().enumerate() {
            match mimi_core::gate::keypackage_basic_identity(kp, self.accepted_suites()) {
                Ok(identity) if identity == user.as_bytes() => {}
                Ok(_) => return Ok(Err(PublishRefusal::NotTheUser(at))),
                Err(_) => return Ok(Err(PublishRefusal::NotAccepted(at))),
            }
        }
        for kp in key_packages {
            self.publish_key_package(&name, kp, now_unix)?;
        }
        Ok(Ok(key_packages.len()))
    }

    /// Withdraw every KeyPackage published for `user`, so no one can add them from now on.
    pub fn lane_withdraw(&self, user: &str) -> anyhow::Result<usize> {
        let Some(name) = self.local_name(user) else {
            anyhow::bail!("not a user of this provider");
        };
        self.store.remove_key_packages(&name)
    }

    /// The names `user`'s queued items may be stored under: local fan-out queues under the member's URI, delivery
    /// from another provider's room under the stored name.
    fn queue_names(&self, user: &str) -> anyhow::Result<[String; 2]> {
        let Some(name) = self.local_name(user) else {
            anyhow::bail!("not a user of this provider");
        };
        Ok([mimi_core::uri::canonical(user), name])
    }

    /// Read `user`'s queues after the cursors, leaving the items in place.
    pub fn lane_inbox(
        &self,
        user: &str,
        after_welcome: i64,
        after_message: i64,
        limit: usize,
    ) -> anyhow::Result<InboxPage> {
        let names = self.queue_names(user)?;
        let names = [names[0].as_str(), names[1].as_str()];
        let limit = limit.clamp(1, MAX_INBOX_PAGE);
        let mut welcomes =
            self.store
                .peek_queue(QueueKind::Welcomes, &names, after_welcome, limit + 1)?;
        let mut messages =
            self.store
                .peek_queue(QueueKind::Messages, &names, after_message, limit + 1)?;
        let more = welcomes.len() > limit || messages.len() > limit;
        welcomes.truncate(limit);
        messages.truncate(limit);
        Ok(InboxPage {
            welcomes,
            messages,
            more,
        })
    }

    /// Remove `user`'s queued items up to the cursors; returns how many went from each queue.
    pub fn lane_ack(
        &self,
        user: &str,
        welcomes_up_to: i64,
        messages_up_to: i64,
    ) -> anyhow::Result<(usize, usize)> {
        let names = self.queue_names(user)?;
        let names = [names[0].as_str(), names[1].as_str()];
        Ok((
            self.store
                .ack_queue(QueueKind::Welcomes, &names, welcomes_up_to)?,
            self.store
                .ack_queue(QueueKind::Messages, &names, messages_up_to)?,
        ))
    }
}
