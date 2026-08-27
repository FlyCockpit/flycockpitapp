//! Durable sanitized computer-action outcome receipts.

use super::coordinator::{ActionIdentity, ActionPayloadDigest, CoordinatedOutcome, DelegationId};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Mutex};

#[derive(Debug, Clone)]
pub struct StoredOutcome {
    pub outcome: CoordinatedOutcome,
    pub digest: ActionPayloadDigest,
}

#[derive(Debug, Clone)]
pub enum OutcomeReservation {
    Acquired,
    Existing {
        identity: ActionIdentity,
        stored: StoredOutcome,
    },
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
    /// Reserve every identity in one indivisible operation.  A competing
    /// receipt leaves *none* of this batch claimed, so a retry cannot inherit
    /// a synthetic `DispatchUnknown` from an earlier item in the batch.
    async fn reserve_batch(
        &self,
        receipts: &[(ActionIdentity, ActionPayloadDigest)],
        action_label: &str,
    ) -> Result<OutcomeReservation, OutcomeStoreError>;
    /// Directly store a known zero-input terminal result for every identity.
    /// Unlike completion, this never takes over a pre-existing claim.
    async fn store_terminal_batch(
        &self,
        receipts: &[(ActionIdentity, ActionPayloadDigest)],
        outcome: &CoordinatedOutcome,
    ) -> Result<OutcomeReservation, OutcomeStoreError>;
    /// Complete the exact batch that this coordinator already reserved before
    /// physical dispatch. This may transition matching `claimed` receipts,
    /// but never overwrites an existing terminal outcome.
    async fn complete_reserved_batch(
        &self,
        receipts: &[(ActionIdentity, ActionPayloadDigest)],
        outcome: &CoordinatedOutcome,
    ) -> Result<OutcomeReservation, OutcomeStoreError>;
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
    entries: Mutex<HashMap<ActionIdentity, MemoryOutcomeEntry>>,
}

#[derive(Debug, Clone)]
struct MemoryOutcomeEntry {
    stored: StoredOutcome,
    claimed: bool,
}
impl MemoryOutcomeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ComputerOutcomeStore for MemoryOutcomeStore {
    async fn reserve_batch(
        &self,
        receipts: &[(ActionIdentity, ActionPayloadDigest)],
        action_label: &str,
    ) -> Result<OutcomeReservation, OutcomeStoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| OutcomeStoreError::LockPoisoned)?;
        if let Some((identity, entry)) = receipts
            .iter()
            .find_map(|(identity, _)| entries.get(identity).map(|entry| (identity, entry)))
        {
            return Ok(OutcomeReservation::Existing {
                identity: identity.clone(),
                stored: entry.stored.clone(),
            });
        }
        for (identity, digest) in receipts {
            entries.insert(
                identity.clone(),
                MemoryOutcomeEntry {
                    stored: StoredOutcome {
                        digest: digest.clone(),
                        outcome: CoordinatedOutcome::DispatchUnknown {
                            action_label: action_label.to_string(),
                        },
                    },
                    claimed: true,
                },
            );
        }
        Ok(OutcomeReservation::Acquired)
    }
    async fn store_terminal_batch(
        &self,
        receipts: &[(ActionIdentity, ActionPayloadDigest)],
        outcome: &CoordinatedOutcome,
    ) -> Result<OutcomeReservation, OutcomeStoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| OutcomeStoreError::LockPoisoned)?;
        if let Some((identity, entry)) = receipts
            .iter()
            .find_map(|(identity, _)| entries.get(identity).map(|entry| (identity, entry)))
        {
            return Ok(OutcomeReservation::Existing {
                identity: identity.clone(),
                stored: entry.stored.clone(),
            });
        }
        for (identity, digest) in receipts {
            entries.insert(
                identity.clone(),
                MemoryOutcomeEntry {
                    stored: StoredOutcome {
                        outcome: outcome.clone(),
                        digest: digest.clone(),
                    },
                    claimed: false,
                },
            );
        }
        Ok(OutcomeReservation::Acquired)
    }
    async fn complete_reserved_batch(
        &self,
        receipts: &[(ActionIdentity, ActionPayloadDigest)],
        outcome: &CoordinatedOutcome,
    ) -> Result<OutcomeReservation, OutcomeStoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| OutcomeStoreError::LockPoisoned)?;
        for (identity, digest) in receipts {
            let Some(entry) = entries.get(identity) else {
                return Err(OutcomeStoreError::Database(
                    "computer outcome batch is missing its reservation".to_string(),
                ));
            };
            if entry.stored.digest != *digest || !entry.claimed {
                return Ok(OutcomeReservation::Existing {
                    identity: identity.clone(),
                    stored: entry.stored.clone(),
                });
            }
        }
        for (identity, digest) in receipts {
            entries.insert(
                identity.clone(),
                MemoryOutcomeEntry {
                    stored: StoredOutcome {
                        outcome: outcome.clone(),
                        digest: digest.clone(),
                    },
                    claimed: false,
                },
            );
        }
        Ok(OutcomeReservation::Acquired)
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
            .map(|entry| entry.stored.clone()))
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
            .map(|(id, entry)| (id.clone(), entry.stored.clone()))
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
    async fn reserve_batch(
        &self,
        receipts: &[(ActionIdentity, ActionPayloadDigest)],
        action_label: &str,
    ) -> Result<OutcomeReservation, OutcomeStoreError> {
        let unknown = serde_json::to_string(&CoordinatedOutcome::DispatchUnknown {
            action_label: action_label.to_string(),
        })
        .map_err(|error| OutcomeStoreError::Encoding(error.to_string()))?;
        let rows = receipts
            .iter()
            .map(
                |(identity, digest)| crate::db::computer_outcomes::ComputerOutcomeRow {
                    session_id: identity.session_id.clone(),
                    delegation_id: identity.delegation_id.0.clone(),
                    provider_call_id: identity.provider_call_id.clone(),
                    batch_index: identity.batch_index,
                    payload_digest: digest.to_hex(),
                    outcome_json: unknown.clone(),
                },
            )
            .collect();
        let reservation = self
            .db
            .reserve_computer_outcomes(rows)
            .await
            .map_err(|error| OutcomeStoreError::Database(format!("{error:#}")))?;
        match reservation {
            None => Ok(OutcomeReservation::Acquired),
            Some(row) => Self::decode(row)
                .map(|(identity, stored)| OutcomeReservation::Existing { identity, stored }),
        }
    }
    async fn store_terminal_batch(
        &self,
        receipts: &[(ActionIdentity, ActionPayloadDigest)],
        outcome: &CoordinatedOutcome,
    ) -> Result<OutcomeReservation, OutcomeStoreError> {
        let outcome_json = serde_json::to_string(outcome)
            .map_err(|error| OutcomeStoreError::Encoding(error.to_string()))?;
        let rows = receipts
            .iter()
            .map(
                |(identity, digest)| crate::db::computer_outcomes::ComputerOutcomeRow {
                    session_id: identity.session_id.clone(),
                    delegation_id: identity.delegation_id.0.clone(),
                    provider_call_id: identity.provider_call_id.clone(),
                    batch_index: identity.batch_index,
                    payload_digest: digest.to_hex(),
                    outcome_json: outcome_json.clone(),
                },
            )
            .collect();
        match self
            .db
            .store_terminal_computer_outcomes(rows)
            .await
            .map_err(|error| OutcomeStoreError::Database(format!("{error:#}")))?
        {
            None => Ok(OutcomeReservation::Acquired),
            Some(row) => Self::decode(row)
                .map(|(identity, stored)| OutcomeReservation::Existing { identity, stored }),
        }
    }
    async fn complete_reserved_batch(
        &self,
        receipts: &[(ActionIdentity, ActionPayloadDigest)],
        outcome: &CoordinatedOutcome,
    ) -> Result<OutcomeReservation, OutcomeStoreError> {
        let outcome_json = serde_json::to_string(outcome)
            .map_err(|error| OutcomeStoreError::Encoding(error.to_string()))?;
        let rows = receipts
            .iter()
            .map(
                |(identity, digest)| crate::db::computer_outcomes::ComputerOutcomeRow {
                    session_id: identity.session_id.clone(),
                    delegation_id: identity.delegation_id.0.clone(),
                    provider_call_id: identity.provider_call_id.clone(),
                    batch_index: identity.batch_index,
                    payload_digest: digest.to_hex(),
                    outcome_json: outcome_json.clone(),
                },
            )
            .collect();
        match self
            .db
            .commit_computer_outcomes(rows)
            .await
            .map_err(|error| OutcomeStoreError::Database(format!("{error:#}")))?
        {
            None => Ok(OutcomeReservation::Acquired),
            Some(row) => Self::decode(row)
                .map(|(identity, stored)| OutcomeReservation::Existing { identity, stored }),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(batch_index: u32) -> ActionIdentity {
        ActionIdentity {
            session_id: "session".to_string(),
            delegation_id: DelegationId("delegation".to_string()),
            provider_call_id: "provider-call".to_string(),
            batch_index,
        }
    }

    fn digest() -> ActionPayloadDigest {
        ActionPayloadDigest::from_actions(&[super::super::ComputerAction::CaptureFull])
    }

    #[tokio::test]
    async fn computer_dedup_batch_reservation_is_atomic_in_memory() {
        let store = MemoryOutcomeStore::new();
        let receipt_one = (identity(1), digest());
        assert!(matches!(
            store
                .reserve_batch(std::slice::from_ref(&receipt_one), "first")
                .await,
            Ok(OutcomeReservation::Acquired)
        ));

        let receipt_zero = (identity(0), digest());
        let batch = vec![receipt_zero.clone(), receipt_one.clone()];
        assert!(matches!(
            store.reserve_batch(&batch, "batch").await,
            Ok(OutcomeReservation::Existing { identity, .. }) if identity == receipt_one.0
        ));
        assert!(
            store.lookup(&receipt_zero.0).await.unwrap().is_none(),
            "a competing later identity must not strand an earlier claimed receipt"
        );
    }

    #[tokio::test]
    async fn computer_dedup_terminal_zero_input_is_stored_without_claim_placeholder() {
        let store = MemoryOutcomeStore::new();
        let receipt = (identity(0), digest());
        let terminal = CoordinatedOutcome::Denied {
            reason: "approval denied".to_string(),
        };
        assert!(matches!(
            store
                .store_terminal_batch(std::slice::from_ref(&receipt), &terminal)
                .await,
            Ok(OutcomeReservation::Acquired)
        ));
        assert!(matches!(
            store
                .reserve_batch(std::slice::from_ref(&receipt), "must not replace terminal")
                .await,
            Ok(OutcomeReservation::Existing { stored, .. }) if stored.outcome == terminal
        ));
    }
}
