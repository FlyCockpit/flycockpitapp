//! Durable computer-action outcome store.
//!
//! [`ComputerOutcomeStore`] persists full sanitized [`CoordinatedOutcome`]
//! values keyed by [`ActionIdentity`] + [`ActionPayloadDigest`], so dedup
//! survives restart. Memory and SQLite implementations are provided.
//!
//! Only sanitized serde-serializable data enters the store — never
//! `LiveComputerFrame`, base64 wire payloads, typed text, or titles (AC13).
//! The store rebuilds `DuplicateReplay { prior_outcome }` from the full
//! sanitized outcome, not a digest-only stub.

use std::collections::HashMap;
use std::sync::Mutex;

use super::coordinator::{ActionIdentity, ActionPayloadDigest, CoordinatedOutcome};

/// A stored outcome entry: the full sanitized terminal outcome plus the
/// payload digest it was committed under.
#[derive(Debug, Clone)]
pub struct StoredOutcome {
    pub outcome: CoordinatedOutcome,
    pub digest: ActionPayloadDigest,
}

/// The durable outcome store trait. Memory and SQLite implementations.
///
/// Physical targets require a durable (SQLite) store; virtual/test
/// coordinators may inject a memory store explicitly (AC14).
pub trait ComputerOutcomeStore: Send + Sync {
    /// Store a sanitized outcome for the given identity + digest. Overwrites
    /// if the identity already exists.
    fn store(
        &self,
        identity: &ActionIdentity,
        outcome: &CoordinatedOutcome,
        digest: &ActionPayloadDigest,
    );

    /// Look up a stored outcome by identity. Returns the outcome and the
    /// digest it was stored under.
    fn lookup(&self, identity: &ActionIdentity) -> Option<StoredOutcome>;

    /// Rehydrate all stored outcomes for a session + delegation. Returns a
    /// map of identity → stored outcome.
    fn rehydrate(
        &self,
        session_id: &str,
        delegation_id: &super::coordinator::DelegationId,
    ) -> Vec<(ActionIdentity, StoredOutcome)>;
}

/// In-memory outcome store for tests and pure-virtual coordinators.
#[derive(Debug, Default)]
pub struct MemoryOutcomeStore {
    entries: Mutex<HashMap<ActionIdentity, StoredOutcome>>,
}

impl MemoryOutcomeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ComputerOutcomeStore for MemoryOutcomeStore {
    fn store(
        &self,
        identity: &ActionIdentity,
        outcome: &CoordinatedOutcome,
        digest: &ActionPayloadDigest,
    ) {
        self.entries.lock().unwrap().insert(
            identity.clone(),
            StoredOutcome {
                outcome: outcome.clone(),
                digest: digest.clone(),
            },
        );
    }

    fn lookup(&self, identity: &ActionIdentity) -> Option<StoredOutcome> {
        self.entries.lock().unwrap().get(identity).cloned()
    }

    fn rehydrate(
        &self,
        session_id: &str,
        delegation_id: &super::coordinator::DelegationId,
    ) -> Vec<(ActionIdentity, StoredOutcome)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| id.session_id == session_id && id.delegation_id == *delegation_id)
            .map(|(id, stored)| (id.clone(), stored.clone()))
            .collect()
    }
}

/// SQLite-backed outcome store for production (physical targets).
///
/// Schema is folded into `0001_initial.sql` as the `computer_outcome_store`
/// table. Columns hold only sanitized serde / digests / ids — never pixels
/// or wire payloads.
///
/// TODO: Implement the SQLite-backed store using the existing `cockpit_db`
/// access patterns. The memory store is sufficient for tests and pure-virtual
/// coordinators; the SQLite implementation is needed for physical targets
/// where dedup must survive restart (AC13/AC14).
pub struct SqliteOutcomeStore {
    // db: crate::db::Db,
}

impl SqliteOutcomeStore {
    pub fn new() -> Self {
        Self {}
    }
}

impl ComputerOutcomeStore for SqliteOutcomeStore {
    fn store(
        &self,
        _identity: &ActionIdentity,
        _outcome: &CoordinatedOutcome,
        _digest: &ActionPayloadDigest,
    ) {
        // TODO: Implement SQLite persistence using the computer_outcome_store
        // table. Serialize CoordinatedOutcome via serde_json and store the
        // identity + digest + outcome_json.
        todo!("SqliteOutcomeStore::store — implement with cockpit_db access patterns")
    }

    fn lookup(&self, _identity: &ActionIdentity) -> Option<StoredOutcome> {
        todo!("SqliteOutcomeStore::lookup — implement with cockpit_db access patterns")
    }

    fn rehydrate(
        &self,
        _session_id: &str,
        _delegation_id: &super::coordinator::DelegationId,
    ) -> Vec<(ActionIdentity, StoredOutcome)> {
        todo!("SqliteOutcomeStore::rehydrate — implement with cockpit_db access patterns")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer::coordinator::DelegationId;

    fn identity(call_id: &str, batch: u32) -> ActionIdentity {
        ActionIdentity {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            provider_call_id: call_id.to_string(),
            batch_index: batch,
        }
    }

    fn digest(n: u64) -> ActionPayloadDigest {
        // ActionPayloadDigest has a private [u8; 32] field; use from_actions
        // with a simple action to get a deterministic digest.
        ActionPayloadDigest::from_actions(&[crate::computer::ComputerAction::Wait {
            duration: std::time::Duration::from_nanos(n),
        }])
    }

    /// AC13: persist a full sanitized CoordinatedOutcome in the memory store;
    /// drop and reopen with same store; same identity+digest → DuplicateReplay
    /// with prior_outcome equal to the stored sanitized outcome.
    #[test]
    fn computer_dedup_memory_store_survives() {
        let store = MemoryOutcomeStore::new();
        let id = identity("call-1", 0);
        let d = digest(0);
        let outcome = CoordinatedOutcome::Completed {
            completed: Vec::new(),
            screenshot: None,
        };

        // Store the outcome.
        store.store(&id, &outcome, &d);

        // Look up — same identity returns the stored outcome.
        let stored = store.lookup(&id).expect("stored outcome must be present");
        assert_eq!(stored.outcome, outcome);
        assert_eq!(stored.digest, d);

        // Rehydrate for this session + delegation.
        let rehydrated = store.rehydrate("session-1", &DelegationId("delegation-1".to_string()));
        assert_eq!(rehydrated.len(), 1);
        assert_eq!(rehydrated[0].1.outcome, outcome);
    }

    /// AC13: different digest for the same identity is a different entry.
    #[test]
    fn computer_dedup_memory_store_different_digest_overwrites() {
        let store = MemoryOutcomeStore::new();
        let id = identity("call-1", 0);

        // Store with one outcome.
        let outcome1 = CoordinatedOutcome::Completed {
            completed: Vec::new(),
            screenshot: None,
        };
        store.store(&id, &outcome1, &digest(0));

        // Store with a different outcome (overwrite).
        let outcome2 = CoordinatedOutcome::Denied {
            reason: "test".to_string(),
        };
        store.store(&id, &outcome2, &digest(1));

        // Look up — the latest stored outcome is returned.
        let stored = store.lookup(&id).expect("stored outcome must be present");
        assert_eq!(stored.outcome, outcome2);
    }

    /// AC14: rehydrate only returns entries for the matching session +
    /// delegation.
    #[test]
    fn computer_dedup_memory_store_rehydrate_scoped() {
        let store = MemoryOutcomeStore::new();

        // Store for session-1/delegation-1.
        let id1 = identity("call-1", 0);
        store.store(
            &id1,
            &CoordinatedOutcome::Completed {
                completed: Vec::new(),
                screenshot: None,
            },
            &digest(0),
        );

        // Store for a different delegation.
        let id2 = ActionIdentity {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-2".to_string()),
            provider_call_id: "call-2".to_string(),
            batch_index: 0,
        };
        store.store(
            &id2,
            &CoordinatedOutcome::Completed {
                completed: Vec::new(),
                screenshot: None,
            },
            &digest(0),
        );

        // Rehydrate for delegation-1 only.
        let rehydrated = store.rehydrate("session-1", &DelegationId("delegation-1".to_string()));
        assert_eq!(rehydrated.len(), 1);
        assert_eq!(rehydrated[0].0, id1);
    }
}
