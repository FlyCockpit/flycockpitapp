//! Bounded retention for append-only ledgers that otherwise grow without
//! limit (issue #308).
//!
//! Each table below documents a **retention class** consumed by the daemon
//! retention pass. Windows align with [`super::retention::RetentionConfig`]:
//! terminal evidence uses `terminal_evidence_window_days`; workspace intel
//! index rows use the same horizon as stale derived content.
//!
//! | Table / family | Class | Policy |
//! | --- | --- | --- |
//! | `external_journal_operations` (+ cascaded events/queue) | terminal_evidence | Terminal operations past the evidence window, when no live media reservation still references the operation |
//! | `external_journal_queue_entries` | terminal_evidence | Terminal queue rows past the evidence window |
//! | `decision_receipts`, `agent_transition_receipts` | terminal_evidence | Terminal audit receipts for closed sessions past the evidence window |
//! | `guidance_proposal_receipts` | terminal_evidence | Terminal proposal receipts past the evidence window (`created` rows are never age-deleted) |
//! | `intel_files` (+ cascaded symbol graph) | intel_index | Stale workspace index snapshots past the evidence window |
//!
//! `computer_audit_entries` remains append-only with SQL-enforced immutability;
//! chain truncation is owned by the machine-local audit writer, not this sweep.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

/// Rows deleted per batched ledger sweep statement.
pub const LEDGER_RETENTION_BATCH: usize = 256;

const EXTERNAL_JOURNAL_TERMINAL_STATES: &[&str] = &[
    "rejected",
    "cancelled",
    "expired",
    "completed_after_cancel",
    "succeeded",
    "failed",
];

const TERMINAL_QUEUE_STATES: &[&str] = &["cancelled", "expired"];

const GUIDANCE_TERMINAL_STATES: &[&str] =
    &["accepted", "rejected", "expired", "expired_on_restart"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LedgerRetentionOutcome {
    pub external_journal_operations_deleted: u64,
    pub external_journal_queue_entries_deleted: u64,
    pub decision_receipts_deleted: u64,
    pub agent_transition_receipts_deleted: u64,
    pub guidance_proposal_receipts_deleted: u64,
    pub intel_files_deleted: u64,
}

impl LedgerRetentionOutcome {
    pub fn rows_deleted(self) -> u64 {
        self.external_journal_operations_deleted
            .saturating_add(self.external_journal_queue_entries_deleted)
            .saturating_add(self.decision_receipts_deleted)
            .saturating_add(self.agent_transition_receipts_deleted)
            .saturating_add(self.guidance_proposal_receipts_deleted)
            .saturating_add(self.intel_files_deleted)
    }
}

pub(crate) fn prune_append_only_ledgers_conn(
    conn: &Connection,
    cutoff_unix_ms: i64,
) -> Result<LedgerRetentionOutcome> {
    if cutoff_unix_ms <= 0 {
        return Ok(LedgerRetentionOutcome::default());
    }
    let batch = i64::try_from(LEDGER_RETENTION_BATCH).context("ledger retention batch overflow")?;
    let journal_states = sql_in_list(EXTERNAL_JOURNAL_TERMINAL_STATES);
    let queue_states = sql_in_list(TERMINAL_QUEUE_STATES);
    let guidance_states = sql_in_list(GUIDANCE_TERMINAL_STATES);

    let external_journal_operations_deleted =
        conn.execute(
            &format!(
                "DELETE FROM external_journal_operations
                  WHERE operation_id IN (
                      SELECT operation_id
                        FROM external_journal_operations
                       WHERE state IN ({journal_states})
                         AND COALESCE(terminal_at_wall_ms, updated_at_wall_ms) < ?1
                         AND NOT EXISTS (
                             SELECT 1 FROM media_reservations reservation
                              WHERE reservation.external_operation_id =
                                    external_journal_operations.operation_id
                         )
                       ORDER BY COALESCE(terminal_at_wall_ms, updated_at_wall_ms) ASC
                       LIMIT ?2
                  )"
            ),
            params![cutoff_unix_ms, batch],
        )
        .context("pruning terminal external journal operations")? as u64;

    let external_journal_queue_entries_deleted =
        conn.execute(
            &format!(
                "DELETE FROM external_journal_queue_entries
                  WHERE queue_entry_id IN (
                      SELECT queue_entry_id
                        FROM external_journal_queue_entries
                       WHERE state IN ({queue_states})
                         AND updated_at_wall_ms < ?1
                       ORDER BY updated_at_wall_ms ASC
                       LIMIT ?2
                  )"
            ),
            params![cutoff_unix_ms, batch],
        )
        .context("pruning terminal external journal queue entries")? as u64;

    let closed_sessions = "session_id IN (
        SELECT session_id FROM sessions
         WHERE ended_at_unix_ms IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM pins WHERE pins.session_id = sessions.session_id)
    )";

    let decision_receipts_deleted = conn
        .execute(
            &format!(
                "DELETE FROM decision_receipts
                  WHERE decision_request_id IN (
                      SELECT decision_request_id
                        FROM decision_receipts
                       WHERE created_at_unix_ms < ?1
                         AND {closed_sessions}
                       ORDER BY created_at_unix_ms ASC
                       LIMIT ?2
                  )"
            ),
            params![cutoff_unix_ms, batch],
        )
        .context("pruning decision receipts")? as u64;

    let agent_transition_receipts_deleted =
        conn.execute(
            &format!(
                "DELETE FROM agent_transition_receipts
                  WHERE (agent_instance_id, terminal_state) IN (
                      SELECT agent_instance_id, terminal_state
                        FROM agent_transition_receipts
                       WHERE created_at_unix_ms < ?1
                         AND {closed_sessions}
                       ORDER BY created_at_unix_ms ASC
                       LIMIT ?2
                  )"
            ),
            params![cutoff_unix_ms, batch],
        )
        .context("pruning agent transition receipts")? as u64;

    let guidance_proposal_receipts_deleted =
        conn.execute(
            &format!(
                "DELETE FROM guidance_proposal_receipts
                  WHERE proposal_id IN (
                      SELECT proposal_id
                        FROM guidance_proposal_receipts
                       WHERE state IN ({guidance_states})
                         AND COALESCE(transitioned_at_unix_ms, created_at_unix_ms) < ?1
                       ORDER BY COALESCE(transitioned_at_unix_ms, created_at_unix_ms) ASC
                       LIMIT ?2
                  )"
            ),
            params![cutoff_unix_ms, batch],
        )
        .context("pruning guidance proposal receipts")? as u64;

    let intel_files_deleted = conn
        .execute(
            "DELETE FROM intel_files
              WHERE (root, path) IN (
                  SELECT root, path
                    FROM intel_files
                   WHERE indexed_at < ?1
                   ORDER BY indexed_at ASC
                   LIMIT ?2
              )",
            params![cutoff_unix_ms, batch],
        )
        .context("pruning stale intel index files")? as u64;

    Ok(LedgerRetentionOutcome {
        external_journal_operations_deleted,
        external_journal_queue_entries_deleted,
        decision_receipts_deleted,
        agent_transition_receipts_deleted,
        guidance_proposal_receipts_deleted,
        intel_files_deleted,
    })
}

fn sql_in_list(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("'{value}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use uuid::Uuid;

    #[tokio::test]
    async fn terminal_external_journal_operation_is_pruned_after_window() {
        let db = Db::open_in_memory().unwrap();
        let operation_id = Uuid::new_v4();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO external_journal_operations(
                    operation_id, operation_kind, owner_session_id, idempotency_key,
                    payload_digest, payload_len, state, version,
                    created_at_wall_ms, updated_at_wall_ms, terminal_at_wall_ms
                 ) VALUES (?1, 'image_generation', 'owner', 'idem', ?2, 1, 'succeeded', 1, 1, 1, 1)",
                params![operation_id.to_string(), "a".repeat(64)],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let outcome = db
            .write(move |conn| prune_append_only_ledgers_conn(conn, 2_000))
            .await
            .unwrap();
        assert_eq!(outcome.external_journal_operations_deleted, 1);
    }
}
