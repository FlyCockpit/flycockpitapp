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
//! | `external_journal_queue_entries` | terminal_evidence | Terminal queue rows past the evidence window (`journaled` rows cascade when their operation is pruned) |
//! | `decision_receipts`, `agent_transition_receipts` | terminal_evidence | Terminal audit receipts for closed sessions past the evidence window |
//! | `guidance_proposal_receipts` | terminal_evidence | Terminal proposal receipts past the evidence window (`created` rows are never age-deleted) |
//! | `intel_files` (+ cascaded symbol graph) | intel_index | Stale workspace index snapshots past the evidence window |
//! | `sealed_value_acquisition_audit`, `sealed_action_invocation_audit`, `sealed_recovery_audit` | terminal_evidence | Terminal sealed audit metadata past the evidence window (`pending` acquisition rows are never age-deleted) |
//! | `media_retained_https_audit`, `media_local_path_registration_audit`, `local_media_operation_audit` | terminal_evidence | Terminal media-operation audit rows past the evidence window |
//! | `remote_principal_audit` | terminal_evidence | Remote principal request audit rows past the evidence window (remote profile only) |
//! | `image_generation_artifact_security_recovery_audits` (+ cascaded components) | terminal_evidence | Terminal security-recovery audit rows past the evidence window (`recorded` rows are never age-deleted; extended profile only) |
//! | `image_generation_artifact_security_recovery_attempts` | terminal_evidence | Terminal security-recovery attempt rows past the evidence window (`received` rows are never age-deleted; extended profile only) |
//!
//! `computer_audit_entries` remains append-only with SQL-enforced immutability;
//! chain truncation is owned by the machine-local audit writer, not this sweep.

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, params};
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::AppendOnlyDeleteFenceViolation;

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

const TERMINAL_QUEUE_STATES: &[&str] = &["cancelled", "expired", "journaled"];

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
    pub sealed_value_acquisition_audit_deleted: u64,
    pub sealed_action_invocation_audit_deleted: u64,
    pub sealed_recovery_audit_deleted: u64,
    pub media_retained_https_audit_deleted: u64,
    pub media_local_path_registration_audit_deleted: u64,
    pub local_media_operation_audit_deleted: u64,
    pub remote_principal_audit_deleted: u64,
    pub image_security_recovery_components_deleted: u64,
    pub image_security_recovery_audits_deleted: u64,
    pub image_security_recovery_attempts_deleted: u64,
}

impl LedgerRetentionOutcome {
    pub fn rows_deleted(self) -> u64 {
        self.external_journal_operations_deleted
            .saturating_add(self.external_journal_queue_entries_deleted)
            .saturating_add(self.decision_receipts_deleted)
            .saturating_add(self.agent_transition_receipts_deleted)
            .saturating_add(self.guidance_proposal_receipts_deleted)
            .saturating_add(self.intel_files_deleted)
            .saturating_add(self.sealed_value_acquisition_audit_deleted)
            .saturating_add(self.sealed_action_invocation_audit_deleted)
            .saturating_add(self.sealed_recovery_audit_deleted)
            .saturating_add(self.media_retained_https_audit_deleted)
            .saturating_add(self.media_local_path_registration_audit_deleted)
            .saturating_add(self.local_media_operation_audit_deleted)
            .saturating_add(self.remote_principal_audit_deleted)
            .saturating_add(self.image_security_recovery_components_deleted)
            .saturating_add(self.image_security_recovery_audits_deleted)
            .saturating_add(self.image_security_recovery_attempts_deleted)
    }
}

pub(crate) fn prune_append_only_ledgers_conn(
    conn: &Connection,
    cutoff_unix_ms: i64,
    cutoff_unix_secs: i64,
) -> Result<LedgerRetentionOutcome> {
    if cutoff_unix_ms <= 0 || cutoff_unix_secs <= 0 {
        return Ok(LedgerRetentionOutcome::default());
    }
    let batch = i64::try_from(LEDGER_RETENTION_BATCH).context("ledger retention batch overflow")?;
    let journal_states = sql_in_list(EXTERNAL_JOURNAL_TERMINAL_STATES);
    let queue_states = sql_in_list(TERMINAL_QUEUE_STATES);
    let guidance_states = sql_in_list(GUIDANCE_TERMINAL_STATES);

    let external_journal_operations_deleted = delete_in_batches(batch, || {
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
        .context("pruning terminal external journal operations")
    })?;

    let external_journal_queue_entries_deleted = delete_in_batches(batch, || {
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
        .context("pruning terminal external journal queue entries")
    })?;

    let closed_sessions = "session_id IN (
        SELECT session_id FROM sessions
         WHERE ended_at_unix_ms IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM pins WHERE pins.session_id = sessions.session_id)
    )";

    let decision_receipts_deleted = delete_in_batches(batch, || {
        conn.execute(
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
        .context("pruning decision receipts")
    })?;

    let agent_transition_receipts_deleted = delete_in_batches(batch, || {
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
        .context("pruning agent transition receipts")
    })?;

    let guidance_proposal_receipts_deleted = delete_in_batches(batch, || {
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
        .context("pruning guidance proposal receipts")
    })?;

    let intel_files_deleted = delete_in_batches(batch, || {
        conn.execute(
            "DELETE FROM intel_files
              WHERE (root, path) IN (
                  SELECT root, path
                    FROM intel_files
                   WHERE indexed_at < ?1
                   ORDER BY indexed_at ASC
                   LIMIT ?2
              )",
            params![cutoff_unix_secs, batch],
        )
        .context("pruning stale intel index files")
    })?;

    let sealed_value_acquisition_audit_deleted = delete_in_batches(batch, || {
        conn.execute(
            "DELETE FROM sealed_value_acquisition_audit
              WHERE acquisition_id IN (
                  SELECT acquisition_id
                    FROM sealed_value_acquisition_audit
                   WHERE outcome <> 'pending'
                     AND COALESCE(completed_at_ms, created_at_ms) < ?1
                   ORDER BY COALESCE(completed_at_ms, created_at_ms) ASC
                   LIMIT ?2
              )",
            params![cutoff_unix_ms, batch],
        )
        .context("pruning terminal sealed value acquisition audit rows")
    })?;

    let sealed_action_invocation_audit_deleted = delete_in_batches(batch, || {
        conn.execute(
            "DELETE FROM sealed_action_invocation_audit
              WHERE audit_id IN (
                  SELECT audit_id
                    FROM sealed_action_invocation_audit
                   WHERE created_at_ms < ?1
                   ORDER BY created_at_ms ASC
                   LIMIT ?2
              )",
            params![cutoff_unix_ms, batch],
        )
        .context("pruning sealed action invocation audit rows")
    })?;

    let sealed_recovery_audit_deleted = delete_in_batches(batch, || {
        conn.execute(
            "DELETE FROM sealed_recovery_audit
              WHERE audit_id IN (
                  SELECT audit_id
                    FROM sealed_recovery_audit
                   WHERE created_at_ms < ?1
                   ORDER BY created_at_ms ASC
                   LIMIT ?2
              )",
            params![cutoff_unix_ms, batch],
        )
        .context("pruning sealed recovery audit rows")
    })?;

    let media_retained_https_audit_deleted = delete_in_batches(batch, || {
        conn.execute(
            "DELETE FROM media_retained_https_audit
              WHERE local_operation_id IN (
                  SELECT local_operation_id
                    FROM media_retained_https_audit
                   WHERE committed_at_unix_ms < ?1
                   ORDER BY committed_at_unix_ms ASC
                   LIMIT ?2
              )",
            params![cutoff_unix_ms, batch],
        )
        .context("pruning media retained https audit rows")
    })?;

    let media_local_path_registration_audit_deleted = delete_in_batches(batch, || {
        conn.execute(
            "DELETE FROM media_local_path_registration_audit
              WHERE local_operation_id IN (
                  SELECT local_operation_id
                    FROM media_local_path_registration_audit
                   WHERE committed_at_unix_ms < ?1
                   ORDER BY committed_at_unix_ms ASC
                   LIMIT ?2
              )",
            params![cutoff_unix_ms, batch],
        )
        .context("pruning media local path registration audit rows")
    })?;

    let local_media_operation_audit_deleted = delete_in_batches(batch, || {
        conn.execute(
            "DELETE FROM local_media_operation_audit
              WHERE local_operation_id IN (
                  SELECT local_operation_id
                    FROM local_media_operation_audit
                   WHERE committed_at_unix_ms < ?1
                   ORDER BY committed_at_unix_ms ASC
                   LIMIT ?2
              )",
            params![cutoff_unix_ms, batch],
        )
        .context("pruning local media operation audit rows")
    })?;

    let remote_principal_audit_deleted = if table_exists(conn, "remote_principal_audit")? {
        delete_in_batches(batch, || {
            conn.execute(
                "DELETE FROM remote_principal_audit
                  WHERE audit_id IN (
                      SELECT audit_id
                        FROM remote_principal_audit
                       WHERE ts_ms < ?1
                       ORDER BY ts_ms ASC
                       LIMIT ?2
                  )",
                params![cutoff_unix_ms, batch],
            )
            .context("pruning remote principal audit rows")
        })?
    } else {
        0
    };

    let (
        image_security_recovery_components_deleted,
        image_security_recovery_audits_deleted,
        image_security_recovery_attempts_deleted,
    ) = if table_exists(conn, "image_generation_artifact_security_recovery_audits")? {
        prune_image_security_recovery_ledgers_conn(conn, cutoff_unix_ms, batch)?
    } else {
        (0, 0, 0)
    };

    Ok(LedgerRetentionOutcome {
        external_journal_operations_deleted,
        external_journal_queue_entries_deleted,
        decision_receipts_deleted,
        agent_transition_receipts_deleted,
        guidance_proposal_receipts_deleted,
        intel_files_deleted,
        sealed_value_acquisition_audit_deleted,
        sealed_action_invocation_audit_deleted,
        sealed_recovery_audit_deleted,
        media_retained_https_audit_deleted,
        media_local_path_registration_audit_deleted,
        local_media_operation_audit_deleted,
        remote_principal_audit_deleted,
        image_security_recovery_components_deleted,
        image_security_recovery_audits_deleted,
        image_security_recovery_attempts_deleted,
    })
}

const IMAGE_SECURITY_RECOVERY_COMPONENT_DELETE_TRIGGER_SQL: &str = "
CREATE TRIGGER image_generation_security_recovery_component_delete_forbidden
BEFORE DELETE ON image_generation_artifact_security_recovery_components
BEGIN
    SELECT RAISE(ABORT,'security recovery component identity is durable');
END;
";

const IMAGE_SECURITY_RECOVERY_ATTEMPT_DELETE_TRIGGER_SQL: &str = "
CREATE TRIGGER image_generation_security_recovery_attempt_delete_forbidden
BEFORE DELETE ON image_generation_artifact_security_recovery_attempts
BEGIN
    SELECT RAISE(ABORT,'security recovery attempt audit is durable');
END;
";

const IMAGE_SECURITY_RECOVERY_AUDIT_DELETE_TRIGGER_SQL: &str = "
CREATE TRIGGER image_generation_security_recovery_audit_delete_forbidden
BEFORE DELETE ON image_generation_artifact_security_recovery_audits
BEGIN
    SELECT RAISE(ABORT,'security recovery audit is durable');
END;
";

const IMAGE_SECURITY_RECOVERY_DELETE_TRIGGERS: [(&str, &str); 3] = [
    (
        "image_generation_security_recovery_component_delete_forbidden",
        IMAGE_SECURITY_RECOVERY_COMPONENT_DELETE_TRIGGER_SQL,
    ),
    (
        "image_generation_security_recovery_attempt_delete_forbidden",
        IMAGE_SECURITY_RECOVERY_ATTEMPT_DELETE_TRIGGER_SQL,
    ),
    (
        "image_generation_security_recovery_audit_delete_forbidden",
        IMAGE_SECURITY_RECOVERY_AUDIT_DELETE_TRIGGER_SQL,
    ),
];

fn restore_security_recovery_delete_triggers(conn: &Connection, count: usize) -> Result<()> {
    for (_, sql) in IMAGE_SECURITY_RECOVERY_DELETE_TRIGGERS.iter().take(count) {
        conn.execute_batch(sql)
            .context("restoring image security recovery delete trigger")?;
    }
    Ok(())
}

struct ImageSecurityRecoveryDeleteTriggerGuard<'a> {
    conn: &'a Connection,
    restored: bool,
    quarantined: bool,
}

impl ImageSecurityRecoveryDeleteTriggerGuard<'_> {
    fn acquire(conn: &Connection) -> Result<Self> {
        let mut dropped = 0usize;
        for (trigger_name, _) in IMAGE_SECURITY_RECOVERY_DELETE_TRIGGERS {
            match conn
                .execute(&format!("DROP TRIGGER IF EXISTS {trigger_name}"), [])
                .with_context(|| format!("dropping {trigger_name}"))
            {
                Ok(_) => dropped += 1,
                Err(drop_error) => {
                    if dropped == 0 {
                        return Err(drop_error);
                    }
                    return match restore_security_recovery_delete_triggers(conn, dropped) {
                        Ok(()) => Err(drop_error),
                        Err(restore_error) => Err(AppendOnlyDeleteFenceViolation {
                            restore: restore_error,
                            truncation: Some(drop_error),
                        }
                        .into()),
                    };
                }
            }
        }
        Ok(Self {
            conn,
            restored: false,
            quarantined: false,
        })
    }

    fn restore(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        restore_security_recovery_delete_triggers(
            self.conn,
            IMAGE_SECURITY_RECOVERY_DELETE_TRIGGERS.len(),
        )?;
        self.restored = true;
        Ok(())
    }

    fn acknowledge_quarantine(&mut self) {
        self.quarantined = true;
    }
}

impl Drop for ImageSecurityRecoveryDeleteTriggerGuard<'_> {
    fn drop(&mut self) {
        if self.restored || self.quarantined {
            return;
        }
        if self.restore().is_err() {
            tracing::error!(
                "image security recovery delete fences left unrestored without writer quarantine"
            );
            self.quarantined = true;
        }
    }
}

fn prune_image_security_recovery_ledgers_conn(
    conn: &Connection,
    cutoff_unix_ms: i64,
    batch: i64,
) -> Result<(u64, u64, u64)> {
    let mut trigger_guard = ImageSecurityRecoveryDeleteTriggerGuard::acquire(conn)?;
    let pruning = catch_unwind(AssertUnwindSafe(|| -> Result<(u64, u64, u64)> {
        let image_security_recovery_components_deleted = delete_in_batches(batch, || {
            conn.execute(
                "DELETE FROM image_generation_artifact_security_recovery_components
                  WHERE (recovery_operation_id, component_id) IN (
                      SELECT recovery_operation_id, component_id
                        FROM image_generation_artifact_security_recovery_components
                       WHERE recovery_operation_id IN (
                           SELECT recovery_operation_id
                             FROM image_generation_artifact_security_recovery_audits
                            WHERE state IN ('applied', 'denied', 'proof_failed', 'stale')
                              AND COALESCE(decided_at_unix_ms, created_at_unix_ms) < ?1
                       )
                       ORDER BY recovery_operation_id ASC, component_id ASC
                       LIMIT ?2
                  )",
                params![cutoff_unix_ms, batch],
            )
            .context("pruning image security recovery components")
        })?;

        let image_security_recovery_audits_deleted = delete_in_batches(batch, || {
            conn.execute(
                "DELETE FROM image_generation_artifact_security_recovery_audits
                  WHERE recovery_operation_id IN (
                      SELECT recovery_operation_id
                        FROM image_generation_artifact_security_recovery_audits
                       WHERE state IN ('applied', 'denied', 'proof_failed', 'stale')
                         AND COALESCE(decided_at_unix_ms, created_at_unix_ms) < ?1
                       ORDER BY COALESCE(decided_at_unix_ms, created_at_unix_ms) ASC
                       LIMIT ?2
                  )",
                params![cutoff_unix_ms, batch],
            )
            .context("pruning image security recovery audits")
        })?;

        let image_security_recovery_attempts_deleted = delete_in_batches(batch, || {
            conn.execute(
                "DELETE FROM image_generation_artifact_security_recovery_attempts
                  WHERE recovery_operation_id IN (
                      SELECT recovery_operation_id
                        FROM image_generation_artifact_security_recovery_attempts
                       WHERE state IN ('validated', 'denied')
                         AND COALESCE(decided_at_unix_ms, created_at_unix_ms) < ?1
                       ORDER BY COALESCE(decided_at_unix_ms, created_at_unix_ms) ASC
                       LIMIT ?2
                  )",
                params![cutoff_unix_ms, batch],
            )
            .context("pruning image security recovery attempts")
        })?;

        Ok((
            image_security_recovery_components_deleted,
            image_security_recovery_audits_deleted,
            image_security_recovery_attempts_deleted,
        ))
    }));
    let pruning = match pruning {
        Ok(result) => result,
        Err(_panic) => Err(anyhow::anyhow!(
            "pruning image security recovery ledgers panicked"
        )),
    };
    let restore = trigger_guard.restore();
    let restore_failed = restore.is_err();
    let result = match (pruning, restore) {
        (Ok(counts), Ok(())) => Ok(counts),
        (Err(pruning), Ok(())) => Err(pruning),
        (pruning, Err(restore)) => Err(AppendOnlyDeleteFenceViolation {
            restore,
            truncation: pruning.err(),
        }
        .into()),
    };
    if restore_failed {
        trigger_guard.acknowledge_quarantine();
    }
    result
}

fn delete_in_batches(batch: i64, mut delete_batch: impl FnMut() -> Result<usize>) -> Result<u64> {
    let mut total = 0_u64;
    loop {
        let deleted = u64::try_from(delete_batch()?).context("ledger retention delete overflow")?;
        total = total.saturating_add(deleted);
        if deleted < batch as u64 {
            break;
        }
    }
    Ok(total)
}

fn sql_in_list(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("'{value}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let mut exists = false;
    let mut stmt = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1")
        .context("preparing table existence probe")?;
    let mut rows = stmt
        .query([table])
        .context("querying table existence probe")?;
    if rows.next()?.is_some() {
        exists = true;
    }
    Ok(exists)
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
            .write(move |conn| prune_append_only_ledgers_conn(conn, 2_000, 2))
            .await
            .unwrap();
        assert_eq!(outcome.external_journal_operations_deleted, 1);
    }
}
