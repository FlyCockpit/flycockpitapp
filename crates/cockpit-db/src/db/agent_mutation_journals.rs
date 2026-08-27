use anyhow::{Result, bail};
use rusqlite::params;

use super::Db;

/// Owned recovery fence inserted while the caller holds the cross-process
/// agent publication lock. This type deliberately contains metadata only;
/// agent document bytes remain filesystem-owned.
pub struct AgentMutationJournalFence {
    pub owner_digest: String,
    pub client_operation_id: String,
    pub request_hash: [u8; 32],
    pub keyed_request_identity: [u8; 32],
    pub fencing_generation: i64,
    pub project_root: String,
    pub request_project_root: String,
    pub agent_name: Option<String>,
    pub action: String,
    pub consumed_revision: Option<String>,
    pub affected_hint: i64,
    pub changed_hint: bool,
    pub consumed_config_generation: i64,
    pub mutation_intent_hash: String,
    pub consumed_projection_identity: String,
    pub intended_projection_identity: String,
    pub created_at_unix_ms: i64,
}

impl Db {
    /// Insert the exact recovery fence without moving the caller's `!Send`
    /// publication guard to the database writer thread.
    pub fn insert_agent_mutation_journal_under_publication_lock(
        &self,
        fence: AgentMutationJournalFence,
    ) -> Result<()> {
        self.insert_agent_mutation_journal_under_publication_lock_with(fence, |_| {
            Ok(((), "{}".to_string()))
        })
    }

    pub fn insert_agent_mutation_journal_under_publication_lock_with<F, T>(
        &self,
        fence: AgentMutationJournalFence,
        stage: F,
    ) -> Result<T>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<(T, String)> + Send + 'static,
        T: Send + 'static,
    {
        self.write_blocking_unguarded(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let (staged, compensation_json) = stage(&tx)?;
            let changed = tx.execute(
                "INSERT OR IGNORE INTO agent_mutation_journals
                 (owner_digest,client_operation_id,request_hash,keyed_request_identity,fencing_generation,
                  project_root,request_project_root,agent_name,action,consumed_revision,affected_hint,changed_hint,consumed_config_generation,
                  mutation_intent_hash,consumed_projection_identity,intended_projection_identity,
                  terminal_response_json,credential_compensation_json,created_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,NULL,?17,?18)",
                params![
                    fence.owner_digest,
                    fence.client_operation_id,
                    fence.request_hash.as_slice(),
                    fence.keyed_request_identity.as_slice(),
                    fence.fencing_generation,
                    fence.project_root,
                    fence.request_project_root,
                    fence.agent_name,
                    fence.action,
                    fence.consumed_revision,
                    fence.affected_hint,
                    i64::from(fence.changed_hint),
                    fence.consumed_config_generation,
                    fence.mutation_intent_hash,
                    fence.consumed_projection_identity,
                    fence.intended_projection_identity,
                    compensation_json,
                    fence.created_at_unix_ms,
                ],
            )?;
            if changed != 1 {
                bail!("agent mutation operation already has unresolved recovery authority");
            }
            tx.commit()?;
            Ok(staged)
        })
    }
}
