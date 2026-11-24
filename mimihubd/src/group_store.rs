//! openmls's public-group storage over the hub's own SQLite store.
//!
//! A room's `PublicGroup` (the delivery service's view of an MLS group: its ratchet tree and GroupContext, no secrets)
//! reads and writes its state through [`PublicStorageProvider`]. openmls's own SQLite backend links another rusqlite,
//! and two bundled SQLite libraries cannot share one binary, so the hub implements the trait over its own connection.
//! Keys and values are serialized as JSON, as openmls's in-memory store does.

use openmls_traits::public_storage::PublicStorageProvider;
use openmls_traits::storage::{traits, CURRENT_VERSION};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};

const TREE: &str = "tree";
const CONTEXT: &str = "context";
const INTERIM_TRANSCRIPT_HASH: &str = "interim_transcript_hash";
const CONFIRMATION_TAG: &str = "confirmation_tag";

/// A failure reading or writing group state: the store's, or a value that does not encode or decode.
#[derive(Debug, thiserror::Error)]
pub enum GroupStoreError {
    #[error("group store: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("group store: {0}")]
    Encoding(#[from] serde_json::Error),
}

/// The public group state in the hub's store, borrowed for one request.
pub struct GroupStore<'a> {
    conn: &'a Connection,
}

impl<'a> GroupStore<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    fn write_value(
        &self,
        group_id: &impl Serialize,
        label: &str,
        value: &impl Serialize,
    ) -> Result<(), GroupStoreError> {
        self.conn.execute(
            "INSERT INTO mls_public_group (group_id, label, value) VALUES (?1, ?2, ?3)
             ON CONFLICT (group_id, label) DO UPDATE SET value = excluded.value",
            params![
                serde_json::to_vec(group_id)?,
                label,
                serde_json::to_vec(value)?
            ],
        )?;
        Ok(())
    }

    fn read_value<V: DeserializeOwned>(
        &self,
        group_id: &impl Serialize,
        label: &str,
    ) -> Result<Option<V>, GroupStoreError> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM mls_public_group WHERE group_id = ?1 AND label = ?2",
                params![serde_json::to_vec(group_id)?, label],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()
            .map_err(Into::into)
    }

    fn delete_value(&self, group_id: &impl Serialize, label: &str) -> Result<(), GroupStoreError> {
        self.conn.execute(
            "DELETE FROM mls_public_group WHERE group_id = ?1 AND label = ?2",
            params![serde_json::to_vec(group_id)?, label],
        )?;
        Ok(())
    }
}

impl PublicStorageProvider<CURRENT_VERSION> for GroupStore<'_> {
    type PublicError = GroupStoreError;

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::PublicError> {
        self.write_value(group_id, TREE, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::PublicError> {
        self.write_value(group_id, INTERIM_TRANSCRIPT_HASH, interim_transcript_hash)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::PublicError> {
        self.write_value(group_id, CONTEXT, group_context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::PublicError> {
        self.write_value(group_id, CONFIRMATION_TAG, confirmation_tag)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::PublicError> {
        let group = serde_json::to_vec(group_id)?;
        self.conn.execute(
            "INSERT INTO mls_public_proposal (group_id, proposal_ref, proposal, seq)
             VALUES (?1, ?2, ?3, (SELECT COALESCE(MAX(seq), 0) + 1 FROM mls_public_proposal WHERE group_id = ?1))
             ON CONFLICT (group_id, proposal_ref) DO UPDATE SET proposal = excluded.proposal",
            params![group, serde_json::to_vec(proposal_ref)?, serde_json::to_vec(proposal)?],
        )?;
        Ok(())
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::PublicError> {
        let mut statement = self.conn.prepare(
            "SELECT proposal_ref, proposal FROM mls_public_proposal WHERE group_id = ?1 ORDER BY seq",
        )?;
        let rows = statement
            .query_map(params![serde_json::to_vec(group_id)?], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(reference, proposal)| {
                Ok((
                    serde_json::from_slice(&reference)?,
                    serde_json::from_slice(&proposal)?,
                ))
            })
            .collect()
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::PublicError> {
        self.read_value(group_id, TREE)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::PublicError> {
        self.read_value(group_id, CONTEXT)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::PublicError> {
        self.read_value(group_id, INTERIM_TRANSCRIPT_HASH)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::PublicError> {
        self.read_value(group_id, CONFIRMATION_TAG)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_value(group_id, TREE)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_value(group_id, CONFIRMATION_TAG)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_value(group_id, CONTEXT)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.delete_value(group_id, INTERIM_TRANSCRIPT_HASH)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::PublicError> {
        self.conn.execute(
            "DELETE FROM mls_public_proposal WHERE group_id = ?1 AND proposal_ref = ?2",
            params![
                serde_json::to_vec(group_id)?,
                serde_json::to_vec(proposal_ref)?
            ],
        )?;
        Ok(())
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        self.conn.execute(
            "DELETE FROM mls_public_proposal WHERE group_id = ?1",
            params![serde_json::to_vec(group_id)?],
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "group_store_tests.rs"]
mod tests;
