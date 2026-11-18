//! Fanning out what the hub accepted for a room it hosts (protocol-07 §5.5).
//!
//! For every provider other than this one with a participant in the room, the accepted message goes into the outbox
//! (`store_outbox.rs`) as one FanoutMessage, which the outbox worker posts to that provider's `notify`. Local members get
//! the message itself in their queue. What goes out:
//!
//! - **A Commit**, to the providers and local members of the room's participants before and after it, so a member the
//!   Commit removes is told (§5.5 SHOULD). Its `externalProposals` is empty.
//! - **A Welcome** in the Commit's bundle, with the bundle's `RatchetTreeOption`: to the provider recorded for each
//!   `KeyPackageRef` in its secrets when the hub served that KeyPackage, and, for a ref with no record, to the providers
//!   of the users the Commit adds. A local new member gets it in its own queue. The submitter's provider is not skipped.
//! - **Held leave proposals**, when they are held: the first proposal with the others as `moreProposals`, exactly as
//!   the bundle carried them.
//! - **An application message**, to every other participant's provider, with no `frank`.
//!
//! The sender's provider is not left out: §5.5 does not require the hub to send a client its own message back, and asks
//! the client and its provider to be ready for one. Fan-out runs after the change is stored and does not undo it: a
//! failure to queue is logged, and the message was accepted.

use std::collections::BTreeSet;
use std::sync::Arc;

use mimi_core::protocol_wire::FanoutMessage;
use tokio::sync::Notify;

use crate::store::ParticipantRow;
use crate::Provider;

/// What one fan-out queued: the providers it went to, the local members it was queued for, and the local members whose
/// queue refused it (full, or the item out of bounds), who were skipped so the others still got it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FanoutReport {
    pub providers: Vec<String>,
    pub local: usize,
    pub skipped: Vec<String>,
}

impl Provider {
    /// Queue `messages`, in order, for each of `members`. A member whose queue refuses one of them is skipped and logged,
    /// and the others are still queued: one full queue never stops delivery to the rest. Returns how many members got
    /// every message, and the members skipped.
    pub(crate) fn queue_for_members<'a>(
        &self,
        members: impl IntoIterator<Item = &'a String>,
        messages: &[&[u8]],
        now_unix: u64,
    ) -> (usize, Vec<String>) {
        let mut queued = 0;
        let mut skipped = Vec::new();
        for member in members {
            match messages
                .iter()
                .try_for_each(|message| self.store.enqueue_message(member, message, now_unix))
            {
                Ok(()) => queued += 1,
                Err(error) => {
                    eprintln!("[mimi-hubd] fan-out: skipped a local member, its queue refused the item: {error}");
                    skipped.push(member.clone());
                }
            }
        }
        (queued, skipped)
    }

    /// Wake `wake` after queueing fan-out, so the outbox worker does not wait for its next tick.
    pub fn with_outbox_waker(mut self, wake: Arc<Notify>) -> Self {
        self.outbox_waker = Some(wake);
        self
    }

    /// The other providers with a participant among `rows`, and this provider's own participants.
    fn split_rows<'a>(
        &self,
        rows: impl IntoIterator<Item = &'a ParticipantRow>,
    ) -> (BTreeSet<String>, BTreeSet<String>) {
        let mut providers = BTreeSet::new();
        let mut local = BTreeSet::new();
        for row in rows {
            if row.authority.eq_ignore_ascii_case(&self.domain) {
                local.insert(row.member_uri.clone());
            } else {
                providers.insert(row.authority.to_ascii_lowercase());
            }
        }
        (providers, local)
    }

    /// Queue `fanout` for each of `providers` and wake the worker.
    fn enqueue_fanout(
        &self,
        room_uri: &str,
        providers: &BTreeSet<String>,
        fanout: &FanoutMessage,
    ) -> anyhow::Result<()> {
        if providers.is_empty() {
            return Ok(());
        }
        let body = fanout.encode()?;
        let now = crate::outbox::now_ms();
        for provider in providers {
            self.store.enqueue_fanout(room_uri, provider, &body, now)?;
        }
        if let Some(wake) = &self.outbox_waker {
            wake.notify_one();
        }
        Ok(())
    }

    /// A Commit the hub accepted, and the Welcome its bundle carried. `before` is the room's list before the Commit.
    pub(crate) fn fan_out_commit(
        &self,
        room_uri: &str,
        commit: &[u8],
        welcome: Option<(&[u8], &[u8])>,
        before: &[ParticipantRow],
        now_unix: u64,
    ) -> anyhow::Result<FanoutReport> {
        let after = self.store.list_participant_rows(room_uri)?;
        let (providers, local) = self.split_rows(before.iter().chain(&after));
        let timestamp = crate::outbox::now_ms();
        self.enqueue_fanout(
            room_uri,
            &providers,
            &FanoutMessage::commit(timestamp, commit),
        )?;
        let (queued, skipped) = self.queue_for_members(&local, &[commit], now_unix);
        let mut report = FanoutReport {
            providers: providers.into_iter().collect(),
            local: queued,
            skipped,
        };
        if let Some((bare_welcome, ratchet_tree_option)) = welcome {
            self.fan_out_welcome(
                room_uri,
                commit,
                bare_welcome,
                ratchet_tree_option,
                timestamp,
                now_unix,
                &mut report,
            )?;
        }
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    fn fan_out_welcome(
        &self,
        room_uri: &str,
        commit: &[u8],
        bare_welcome: &[u8],
        ratchet_tree_option: &[u8],
        timestamp: u64,
        now_unix: u64,
        report: &mut FanoutReport,
    ) -> anyhow::Result<()> {
        let fanout = FanoutMessage::welcome(timestamp, bare_welcome, ratchet_tree_option);
        let Ok((welcome, refs)) = mimi_core::gate::welcome_new_members(&fanout.message_and_tail)
        else {
            anyhow::bail!("the bundle's Welcome does not decode");
        };
        let mut providers = BTreeSet::new();
        let mut unrecorded = false;
        for kpref in &refs {
            if let Some(user) = self.store.client_for_kpref(kpref)? {
                // A local member whose Welcome queue refuses it is skipped; the others still get theirs.
                match self.relay_welcome(&user, &welcome, now_unix) {
                    Ok(()) => report.local += 1,
                    Err(error) => {
                        eprintln!("[mimi-hubd] fan-out: skipped a local member, its queue refused the Welcome: {error}");
                        report.skipped.push(user.clone());
                    }
                }
            } else if let Some(provider) = self.store.provider_for_kpref(kpref)? {
                providers.insert(provider.to_ascii_lowercase());
            } else {
                unrecorded = true;
            }
        }
        if unrecorded {
            let added = mimi_core::commit_wire::decode_commit_proposals(commit)
                .map(|decoded| decoded.adds)
                .unwrap_or_default();
            for client in added {
                let user = String::from_utf8_lossy(&client.identity).to_string();
                if let Ok(uri) = mimi_core::uri::MimiUri::parse(&user) {
                    if !uri.is_local_to(&self.domain) {
                        providers.insert(uri.authority.to_ascii_lowercase());
                    }
                }
            }
        }
        self.enqueue_fanout(room_uri, &providers, &fanout)?;
        for provider in providers {
            if !report.providers.contains(&provider) {
                report.providers.push(provider);
            }
        }
        Ok(())
    }

    /// Held leave proposals, as their bundle carried them, to every provider and local member of the room.
    pub(crate) fn fan_out_proposals(
        &self,
        room_uri: &str,
        proposal: &[u8],
        more_proposals: &[Vec<u8>],
        now_unix: u64,
    ) -> anyhow::Result<FanoutReport> {
        let rows = self.store.list_participant_rows(room_uri)?;
        let (providers, local) = self.split_rows(&rows);
        let fanout = FanoutMessage::proposal(crate::outbox::now_ms(), proposal, more_proposals)?;
        self.enqueue_fanout(room_uri, &providers, &fanout)?;
        let messages: Vec<&[u8]> = std::iter::once(proposal)
            .chain(more_proposals.iter().map(Vec::as_slice))
            .collect();
        let (queued, skipped) = self.queue_for_members(&local, &messages, now_unix);
        Ok(FanoutReport {
            providers: providers.into_iter().collect(),
            local: queued,
            skipped,
        })
    }

    /// An application message the hub accepted from `sender`: to every other local participant's queue and to the
    /// provider of every participant elsewhere.
    pub fn fan_out_application(
        &self,
        room_uri: &str,
        sender: &str,
        message: &[u8],
        now_unix: u64,
    ) -> anyhow::Result<FanoutReport> {
        let sender = mimi_core::uri::canonical(sender);
        let rows: Vec<ParticipantRow> = self
            .store
            .list_participant_rows(room_uri)?
            .into_iter()
            .filter(|row| row.member_uri != sender)
            .collect();
        let (providers, local) = self.split_rows(&rows);
        let fanout = FanoutMessage::application(crate::outbox::now_ms(), message);
        self.enqueue_fanout(room_uri, &providers, &fanout)?;
        let (queued, skipped) = self.queue_for_members(&local, &[message], now_unix);
        Ok(FanoutReport {
            providers: providers.into_iter().collect(),
            local: queued,
            skipped,
        })
    }
}

#[cfg(test)]
#[path = "fanout_tests.rs"]
mod tests;
