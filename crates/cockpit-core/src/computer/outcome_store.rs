//! Durable sanitized computer-action outcome receipts.

use super::coordinator::{ActionIdentity, ActionPayloadDigest, CoordinatedOutcome, DelegationId};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Mutex};

#[derive(Debug, Clone)]
pub struct StoredOutcome {
    pub outcome: CoordinatedOutcome,
    pub digest: ActionPayloadDigest,
}

#[derive(Debug, thiserror::Error)]
pub enum OutcomeStoreError {
    #[error("computer outcome store lock is poisoned")]
    LockPoisoned,
    #[error("computer outcome database failed: {0}")]
    Database(String),
    #[error("computer outcome encoding failed: {0}")]
    Encoding(String),
    #[error("computer outcome receipt is corrupt: {0}")]
    Corrupt(String),
}

#[async_trait]
pub trait ComputerOutcomeStore: Send + Sync {
    fn is_durable(&self) -> bool {
        false
    }
    async fn store(
        &self,
        identity: &ActionIdentity,
        outcome: &CoordinatedOutcome,
        digest: &ActionPayloadDigest,
    ) -> Result<(), OutcomeStoreError>;
    async fn lookup(
        &self,
        identity: &ActionIdentity,
    ) -> Result<Option<StoredOutcome>, OutcomeStoreError>;
    async fn rehydrate(
        &self,
        session_id: &str,
        delegation_id: &DelegationId,
    ) -> Result<Vec<(ActionIdentity, StoredOutcome)>, OutcomeStoreError>;
}

#[derive(Debug, Default)]
pub struct MemoryOutcomeStore {
    entries: Mutex<HashMap<ActionIdentity, StoredOutcome>>,
}
impl MemoryOutcomeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ComputerOutcomeStore for MemoryOutcomeStore {
    async fn store(
        &self,
        identity: &ActionIdentity,
        outcome: &CoordinatedOutcome,
        digest: &ActionPayloadDigest,
    ) -> Result<(), OutcomeStoreError> {
        self.entries
            .lock()
            .map_err(|_| OutcomeStoreError::LockPoisoned)?
            .insert(
                identity.clone(),
                StoredOutcome {
                    outcome: outcome.clone(),
                    digest: digest.clone(),
                },
            );
        Ok(())
    }
    async fn lookup(
        &self,
        identity: &ActionIdentity,
    ) -> Result<Option<StoredOutcome>, OutcomeStoreError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| OutcomeStoreError::LockPoisoned)?
            .get(identity)
            .cloned())
    }
    async fn rehydrate(
        &self,
        session_id: &str,
        delegation_id: &DelegationId,
    ) -> Result<Vec<(ActionIdentity, StoredOutcome)>, OutcomeStoreError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| OutcomeStoreError::LockPoisoned)?
            .iter()
            .filter(|(id, _)| id.session_id == session_id && id.delegation_id == *delegation_id)
            .map(|(id, stored)| (id.clone(), stored.clone()))
            .collect())
    }
}

pub struct SqliteOutcomeStore {
    db: crate::db::Db,
}
impl SqliteOutcomeStore {
    pub fn new(db: crate::db::Db) -> Self {
        Self { db }
    }
    fn decode(
        row: crate::db::computer_outcomes::ComputerOutcomeRow,
    ) -> Result<(ActionIdentity, StoredOutcome), OutcomeStoreError> {
        let digest = ActionPayloadDigest::from_hex(&row.payload_digest)
            .map_err(OutcomeStoreError::Corrupt)?;
        let outcome = serde_json::from_str(&row.outcome_json)
            .map_err(|error| OutcomeStoreError::Corrupt(error.to_string()))?;
        Ok((
            ActionIdentity {
                session_id: row.session_id,
                delegation_id: DelegationId(row.delegation_id),
                provider_call_id: row.provider_call_id,
                batch_index: row.batch_index,
            },
            StoredOutcome { outcome, digest },
        ))
    }
}

#[async_trait]
impl ComputerOutcomeStore for SqliteOutcomeStore {
    fn is_durable(&self) -> bool {
        true
    }
    async fn store(
        &self,
        identity: &ActionIdentity,
        outcome: &CoordinatedOutcome,
        digest: &ActionPayloadDigest,
    ) -> Result<(), OutcomeStoreError> {
        let outcome_json = serde_json::to_string(outcome)
            .map_err(|error| OutcomeStoreError::Encoding(error.to_string()))?;
        self.db
            .put_computer_outcome(crate::db::computer_outcomes::ComputerOutcomeRow {
                session_id: identity.session_id.clone(),
                delegation_id: identity.delegation_id.0.clone(),
                provider_call_id: identity.provider_call_id.clone(),
                batch_index: identity.batch_index,
                payload_digest: digest.to_hex(),
                outcome_json,
            })
            .await
            .map_err(|error| OutcomeStoreError::Database(format!("{error:#}")))
    }
    async fn lookup(
        &self,
        identity: &ActionIdentity,
    ) -> Result<Option<StoredOutcome>, OutcomeStoreError> {
        self.db
            .computer_outcome(
                identity.session_id.clone(),
                identity.delegation_id.0.clone(),
                identity.provider_call_id.clone(),
                identity.batch_index,
            )
            .await
            .map_err(|error| OutcomeStoreError::Database(format!("{error:#}")))?
            .map(Self::decode)
            .transpose()
            .map(|entry| entry.map(|(_, stored)| stored))
    }
    async fn rehydrate(
        &self,
        session_id: &str,
        delegation_id: &DelegationId,
    ) -> Result<Vec<(ActionIdentity, StoredOutcome)>, OutcomeStoreError> {
        self.db
            .computer_outcomes_for_delegation(session_id.to_string(), delegation_id.0.clone())
            .await
            .map_err(|error| OutcomeStoreError::Database(format!("{error:#}")))?
            .into_iter()
            .map(Self::decode)
            .collect()
    }
}
