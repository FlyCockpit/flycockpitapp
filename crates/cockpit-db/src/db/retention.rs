//! Retention pass for payload-heavy session tables.

use anyhow::{Context, Result};
use rusqlite::{Connection, ErrorCode, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Closed-session transcript retention. Zero means unlimited.
    #[serde(default = "default_transcript_window_days")]
    pub transcript_window_days: u32,
    /// Raw provider requests and tool wire/input/output retention. Zero means unlimited.
    #[serde(default = "default_raw_wire_window_days")]
    pub raw_wire_window_days: u32,
    /// Terminal operational evidence and usage metadata retention. Zero means unlimited.
    #[serde(default = "default_terminal_evidence_window_days")]
    pub terminal_evidence_window_days: u32,
    /// Whole-session retention window in days.
    #[serde(default = "default_session_window_days")]
    pub session_window_days: u32,
    /// Periodic retention sweep interval in hours.
    #[serde(default = "default_retention_sweep_interval_hours")]
    pub sweep_interval_hours: u32,
    /// Deleted-row threshold for vacuum.
    #[serde(default = "default_retention_vacuum_min_deletions")]
    pub vacuum_min_deletions: u64,
    /// Vacuum interval in days.
    #[serde(default = "default_retention_vacuum_interval_days")]
    pub vacuum_interval_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            transcript_window_days: default_transcript_window_days(),
            raw_wire_window_days: default_raw_wire_window_days(),
            terminal_evidence_window_days: default_terminal_evidence_window_days(),
            session_window_days: default_session_window_days(),
            sweep_interval_hours: default_retention_sweep_interval_hours(),
            vacuum_min_deletions: default_retention_vacuum_min_deletions(),
            vacuum_interval_days: default_retention_vacuum_interval_days(),
        }
    }
}

fn default_transcript_window_days() -> u32 {
    90
}

fn default_raw_wire_window_days() -> u32 {
    30
}

fn default_terminal_evidence_window_days() -> u32 {
    90
}

fn default_session_window_days() -> u32 {
    365
}

fn default_retention_sweep_interval_hours() -> u32 {
    6
}

fn default_retention_vacuum_min_deletions() -> u64 {
    1000
}

fn default_retention_vacuum_interval_days() -> u32 {
    7
}

/// `retention_meta` key for the last expiry pass's media-barrier skip count.
/// Doctor reads this exact name.
pub const SESSIONS_EXPIRY_SKIPPED_MEDIA_BARRIER_KEY: &str = "sessions_expiry_skipped_media_barrier";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionOutcome {
    pub sessions_expired: u64,
    /// All rows changed by whole-session cascades, including dependent rows.
    pub session_cascade_rows_deleted: u64,
    /// Closed sessions that were due but skipped because media is not terminal.
    pub sessions_expiry_skipped_media_barrier: u64,
    pub payload_rows_deleted: u64,
    pub transcript_rows_deleted: u64,
    pub raw_wire_rows_deleted_or_redacted: u64,
    pub terminal_evidence_rows_deleted: u64,
    pub goal_tombstones_purged: u64,
    pub local_authority_rows_purged: u64,
    pub vacuumed: bool,
}

/// Read-only accounting for session rows protected from whole-session expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionProtectionReport {
    pub total_session_rows: u64,
    pub directly_pinned_sessions: u64,
    pub pin_protected_root_sessions: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SessionExpiryOutcome {
    sessions_expired: u64,
    cascade_rows_deleted: u64,
    sessions_expiry_skipped_media_barrier: u64,
}

impl Db {
    /// Report how pins affect whole-session retention without mutating state.
    pub async fn retention_protection_report(&self) -> Result<RetentionProtectionReport> {
        self.read(|conn| {
            conn.query_row(
                "WITH RECURSIVE ancestry(session_id, root_session_id) AS (
                     SELECT session_id, session_id FROM sessions WHERE parent_session_id IS NULL
                     UNION ALL
                     SELECT child.session_id, ancestry.root_session_id
                       FROM sessions child
                       JOIN ancestry ON child.parent_session_id=ancestry.session_id
                 )
                 SELECT
                     (SELECT COUNT(*) FROM sessions),
                     (SELECT COUNT(DISTINCT session_id) FROM pins),
                     (SELECT COUNT(DISTINCT ancestry.root_session_id)
                        FROM ancestry JOIN pins USING (session_id))",
                [],
                |row| {
                    Ok(RetentionProtectionReport {
                        total_session_rows: row.get::<_, i64>(0)? as u64,
                        directly_pinned_sessions: row.get::<_, i64>(1)? as u64,
                        pin_protected_root_sessions: row.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .context("reading retention pin protection accounting")
        })
        .await
    }

    /// Bound secret-free local authority receipts while retaining a generous
    /// replay/reconciliation window. Executing operations and completing
    /// editor leases are deliberately excluded: ambiguous side effects remain
    /// inspectable until their owning recovery path reaches a terminal state.
    pub async fn prune_local_authority_receipts(&self, cutoff_unix_ms: i64) -> Result<u64> {
        self.transaction(move |conn| {
            let editor = conn.execute(
                "DELETE FROM agent_editor_leases
                 WHERE state = 'terminal' AND updated_at_unix_ms < ?1",
                params![cutoff_unix_ms],
            )? as u64;
            // Recovery-owned ambiguous intents stay inspectable. Only dead or
            // already-terminal marker residue is eligible for bounded cleanup.
            let patch_journals = conn.execute(
                "DELETE FROM extended_config_patch_journals
                  WHERE created_at_unix_ms < ?1
                    AND NOT EXISTS (
                        SELECT 1 FROM local_operation_receipts receipt
                         WHERE receipt.owner_digest=extended_config_patch_journals.owner_digest
                           AND receipt.client_operation_id=extended_config_patch_journals.client_operation_id
                           AND receipt.state IN ('prepared','executing')
                    )",
                params![cutoff_unix_ms],
            )? as u64;
            let agent_journals = conn.execute(
                "DELETE FROM agent_mutation_journals
                  WHERE created_at_unix_ms < ?1
                    AND NOT EXISTS (
                        SELECT 1 FROM local_operation_receipts receipt
                         WHERE receipt.owner_digest=agent_mutation_journals.owner_digest
                           AND receipt.client_operation_id=agent_mutation_journals.client_operation_id
                           AND receipt.state IN ('prepared','executing')
                    )",
                params![cutoff_unix_ms],
            )? as u64;
            let image_journals = conn.execute(
                "DELETE FROM image_config_mutation_journals
                  WHERE created_at_unix_ms < ?1
                    AND NOT EXISTS (
                        SELECT 1 FROM local_operation_receipts receipt
                         WHERE receipt.owner_digest=image_config_mutation_journals.owner_digest
                           AND receipt.client_operation_id=image_config_mutation_journals.client_operation_id
                           AND receipt.state IN ('prepared','executing')
                    )",
                params![cutoff_unix_ms],
            )? as u64;
            let assistant_journals = conn.execute(
                "DELETE FROM assistant_mutation_journals
                  WHERE created_at_unix_ms < ?1
                    AND NOT EXISTS (
                        SELECT 1 FROM local_operation_receipts receipt
                         WHERE receipt.owner_digest=assistant_mutation_journals.owner_digest
                           AND receipt.client_operation_id=assistant_mutation_journals.client_operation_id
                           AND receipt.state IN ('prepared','executing')
                    )",
                params![cutoff_unix_ms],
            )? as u64;
            // Delete journal children before terminal receipts so SQLite's
            // cascade does not hide deleted-row accounting from `changes()`.
            // Prepared/executing receipts continue to protect every journal.
            let receipts = conn.execute(
                "DELETE FROM local_operation_receipts
                 WHERE state LIKE 'terminal_%' AND updated_at_unix_ms < ?1",
                params![cutoff_unix_ms],
            )? as u64;
            Ok(receipts
                .saturating_add(editor)
                .saturating_add(patch_journals)
                .saturating_add(agent_journals)
                .saturating_add(image_journals)
                .saturating_add(assistant_journals))
        })
        .await
    }

    /// Delete old payload rows for closed sessions, preserving session rows.
    pub async fn prune_session_payloads(
        &self,
        transcript_cutoff_secs: i64,
        raw_wire_cutoff_secs: i64,
        terminal_evidence_cutoff_secs: i64,
    ) -> Result<(u64, u64, u64)> {
        if transcript_cutoff_secs <= 0
            && raw_wire_cutoff_secs <= 0
            && terminal_evidence_cutoff_secs <= 0
        {
            return Ok((0, 0, 0));
        }
        self.write(move |conn| {
            prune_session_payloads_conn(
                conn,
                transcript_cutoff_secs,
                raw_wire_cutoff_secs,
                terminal_evidence_cutoff_secs,
            )
        })
        .await
    }

    /// Delete old closed, non-ephemeral root sessions whose entire subtrees are
    /// closed and older than the cutoff.
    pub async fn expire_old_sessions(&self, session_cutoff_secs: i64) -> Result<u64> {
        Ok(self
            .expire_old_sessions_with_accounting(session_cutoff_secs)
            .await?
            .sessions_expired)
    }

    async fn expire_old_sessions_with_accounting(
        &self,
        session_cutoff_secs: i64,
    ) -> Result<SessionExpiryOutcome> {
        if session_cutoff_secs <= 0 {
            return Ok(SessionExpiryOutcome::default());
        }
        // `transaction`: each `delete_session_conn` writes an external
        // side-effect tombstone before deleting, and the pair must commit or
        // roll back together. One transaction for the pass also means a
        // failure part-way cannot leave the sweep half-applied.
        let removed = self
            .transaction(move |conn| expire_old_sessions_conn(conn, session_cutoff_secs))
            .await?;
        if removed.sessions_expiry_skipped_media_barrier > 0 {
            self.record_sessions_expiry_skipped_media_barrier(
                removed.sessions_expiry_skipped_media_barrier,
            )
            .await?;
        }
        if removed.sessions_expired > 0
            && let Err(error) = self.reconcile_delegation_sidecar_cleanup_intents().await
        {
            tracing::warn!(%error, "retention sidecar cleanup remains durably pending");
        }
        Ok(removed)
    }

    /// Last whole-session expiry pass's media-barrier skip count. Missing key
    /// is zero (no pass has run yet). Doctor surfaces this name as-is.
    pub async fn sessions_expiry_skipped_media_barrier(&self) -> Result<u64> {
        let value = self
            .read(|conn| {
                conn.query_row(
                    "SELECT value FROM retention_meta WHERE key = ?1",
                    [SESSIONS_EXPIRY_SKIPPED_MEDIA_BARRIER_KEY],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .context("querying sessions_expiry_skipped_media_barrier")
            })
            .await?
            .unwrap_or(0);
        u64::try_from(value.max(0)).context("sessions_expiry_skipped_media_barrier overflow")
    }

    async fn record_sessions_expiry_skipped_media_barrier(&self, skipped: u64) -> Result<()> {
        let value = i64::try_from(skipped).unwrap_or(i64::MAX);
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO retention_meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![SESSIONS_EXPIRY_SKIPPED_MEDIA_BARRIER_KEY, value],
            )
            .context("recording sessions_expiry_skipped_media_barrier")?;
            Ok(())
        })
        .await
    }

    /// Decide whether retention should vacuum after a pass.
    pub async fn should_vacuum(&self, deleted: u64, now_secs: i64, cfg: &RetentionConfig) -> bool {
        if deleted >= cfg.vacuum_min_deletions {
            return true;
        }
        if cfg.vacuum_interval_days == 0 {
            return false;
        }
        let last = self.last_vacuum_secs().await.ok().flatten().unwrap_or(0);
        now_secs.saturating_sub(last) >= (cfg.vacuum_interval_days as i64) * 86_400
    }

    /// Record a successful retention vacuum timestamp.
    pub async fn record_vacuum(&self, now_secs: i64) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO retention_meta (key, value) VALUES ('last_vacuum_secs', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![now_secs],
            )
            .context("recording retention vacuum timestamp")?;
            Ok(())
        })
        .await
    }

    /// Run the two-tier retention pass and optional on-disk vacuum.
    pub async fn run_retention_pass(
        &self,
        cfg: &RetentionConfig,
        now_secs: i64,
    ) -> Result<RetentionOutcome> {
        let mut outcome = RetentionOutcome::default();

        if cfg.session_window_days > 0 {
            let cutoff = now_secs - (cfg.session_window_days as i64) * 86_400;
            let expired = self.expire_old_sessions_with_accounting(cutoff).await?;
            outcome.sessions_expired = expired.sessions_expired;
            outcome.session_cascade_rows_deleted = expired.cascade_rows_deleted;
            outcome.sessions_expiry_skipped_media_barrier =
                expired.sessions_expiry_skipped_media_barrier;
        }
        let transcript_cutoff = retention_cutoff(now_secs, cfg.transcript_window_days);
        let raw_wire_cutoff = retention_cutoff(now_secs, cfg.raw_wire_window_days);
        let terminal_evidence_cutoff =
            retention_cutoff(now_secs, cfg.terminal_evidence_window_days);
        let (transcripts, raw_wire, terminal_evidence) = self
            .prune_session_payloads(transcript_cutoff, raw_wire_cutoff, terminal_evidence_cutoff)
            .await?;
        outcome.transcript_rows_deleted = transcripts;
        outcome.raw_wire_rows_deleted_or_redacted = raw_wire;
        outcome.terminal_evidence_rows_deleted = terminal_evidence;
        outcome.payload_rows_deleted = transcripts
            .saturating_add(raw_wire)
            .saturating_add(terminal_evidence);
        outcome.goal_tombstones_purged = self
            .purge_cleared_goal_tombstones(now_secs)
            .await?
            .try_into()
            .unwrap_or(u64::MAX);
        // Local mutation receipts contain no request bodies or secret values,
        // but they still disclose operation metadata and workspace targets.
        // Use the configurable terminal-evidence window for lost-response
        // replay, pruning only terminal receipts and long-expired,
        // never-consumed editor capabilities. Zero means unlimited.
        if terminal_evidence_cutoff > 0 {
            outcome.local_authority_rows_purged = self
                .prune_local_authority_receipts(terminal_evidence_cutoff.saturating_mul(1000))
                .await?;
        }

        // Verification ledger envelopes currently have no GC path
        // (`retention_state` never becomes `cleaned`). This hook is wired to
        // the existing retention tick so a later media-retention-style sweep
        // can mark cleaned envelopes without a new scheduler.
        // TODO(media-retention): implement verification envelope cleaning
        // (digest-only rows, same window as terminal evidence).
        let _ = self.sweep_verification_retention_stub().await?;

        let deleted = outcome
            .session_cascade_rows_deleted
            .saturating_add(outcome.payload_rows_deleted)
            .saturating_add(outcome.goal_tombstones_purged);
        let deleted = deleted.saturating_add(outcome.local_authority_rows_purged);
        if self.path.is_some()
            && self.should_vacuum(deleted, now_secs, cfg).await
            && self.vacuum_retention_database().await?
        {
            self.record_vacuum(now_secs).await?;
            outcome.vacuumed = true;
        }

        Ok(outcome)
    }

    async fn vacuum_retention_database(&self) -> Result<bool> {
        if self.path.is_none() {
            return Ok(false);
        }
        // VACUUM under WAL still needs exclusive access to rewrite the DB. Keep it on
        // the writer connection so retention does not bypass writer serialization.
        self.write(|conn| match conn.execute_batch("VACUUM") {
            Ok(()) => Ok(true),
            Err(err) if sqlite_busy(&err) => {
                tracing::debug!(error = %err, "retention vacuum skipped because sqlite is busy");
                Ok(false)
            }
            Err(err) => Err(err).context("vacuuming after retention pass"),
        })
        .await
    }

    async fn last_vacuum_secs(&self) -> Result<Option<i64>> {
        self.read(|conn| {
            conn.query_row(
                "SELECT value FROM retention_meta WHERE key = 'last_vacuum_secs'",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("querying retention vacuum timestamp")
        })
        .await
    }
}

fn sqlite_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(code.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn retention_cutoff(now_secs: i64, window_days: u32) -> i64 {
    if window_days == 0 {
        0
    } else {
        now_secs.saturating_sub(i64::from(window_days).saturating_mul(86_400))
    }
}

fn prune_session_payloads_conn(
    conn: &Connection,
    transcript_cutoff_secs: i64,
    raw_wire_cutoff_secs: i64,
    terminal_evidence_cutoff_secs: i64,
) -> Result<(u64, u64, u64)> {
    let tx = conn
        .unchecked_transaction()
        .context("begin prune_session_payloads tx")?;
    // A pin is a whole-session preservation hold. Several raw/wire/evidence
    // ledgers intentionally have no turn sequence, so preserving only the
    // pinned event would silently delete evidence that cannot be mapped back
    // to that turn. Release the hold by removing all session pins first.
    let closed = "session_id IN (
        SELECT session_id FROM sessions
         WHERE ended_at_unix_ms IS NOT NULL
           AND NOT EXISTS (
               SELECT 1 FROM pins
                WHERE pins.session_id=sessions.session_id
           )
    )";
    let mut transcripts = 0_u64;
    if transcript_cutoff_secs > 0 {
        let predicate = format!(
            "ts_ms < ?1 AND {closed}
             AND NOT EXISTS (
                 SELECT 1 FROM sessions child
                  WHERE child.parent_session_id=session_events.session_id
                    AND child.fork_point_turn_id=session_events.seq
             )"
        );
        transcripts = count_delete_candidates(
            &tx,
            "session_events",
            &predicate,
            transcript_cutoff_secs.saturating_mul(1000),
        )?;
        tx.execute(
            &format!("DELETE FROM session_events WHERE {predicate}"),
            params![transcript_cutoff_secs.saturating_mul(1000)],
        )?;
    }
    let mut raw_wire = 0_u64;
    if raw_wire_cutoff_secs > 0 {
        let inference_request_predicate = format!("ts_ms < ?1 AND {closed}");
        raw_wire = raw_wire.saturating_add(count_delete_candidates(
            &tx,
            "inference_requests",
            &inference_request_predicate,
            raw_wire_cutoff_secs.saturating_mul(1000),
        )?);
        tx.execute(
            &format!("DELETE FROM inference_requests WHERE {inference_request_predicate}"),
            params![raw_wire_cutoff_secs.saturating_mul(1000)],
        )?;
        // A parent deletion cascades its call subtree. Delete it only when no
        // descendant is newer than the cutoff; otherwise retain the complete
        // structural chain until the youngest descendant becomes eligible.
        // Count the complete target set before DELETE: SQLite's `changes()`
        // excludes rows removed by FK cascades, so counting only the parent
        // statements would under-report the retained tree and vacuum signal.
        let tool_call_predicate = format!(
            "timestamp < ?1 AND {closed}
             AND NOT EXISTS (
                 WITH RECURSIVE descendants(call_id, timestamp) AS (
                     SELECT child.call_id, child.timestamp
                       FROM tool_call_events child
                      WHERE child.session_id=tool_call_events.session_id
                        AND child.parent_call_id=tool_call_events.call_id
                     UNION ALL
                     SELECT child.call_id, child.timestamp
                       FROM tool_call_events child
                       JOIN descendants parent ON child.parent_call_id=parent.call_id
                      WHERE child.session_id=tool_call_events.session_id
                 )
                 SELECT 1 FROM descendants WHERE timestamp >= ?1
             )"
        );
        raw_wire = raw_wire.saturating_add(count_delete_candidates(
            &tx,
            "tool_call_events",
            &tool_call_predicate,
            raw_wire_cutoff_secs,
        )?);
        tx.execute(
            &format!("DELETE FROM tool_call_events WHERE {tool_call_predicate}"),
            params![raw_wire_cutoff_secs],
        )?;
    }
    let mut terminal_evidence = 0_u64;
    if terminal_evidence_cutoff_secs > 0 {
        let predicate = format!("timestamp < ?1 AND {closed}");
        terminal_evidence = count_delete_candidates(
            &tx,
            "inference_calls",
            &predicate,
            terminal_evidence_cutoff_secs,
        )?;
        tx.execute(
            &format!("DELETE FROM inference_calls WHERE {predicate}"),
            params![terminal_evidence_cutoff_secs],
        )?;
    }
    tx.commit().context("commit prune_session_payloads tx")?;
    Ok((transcripts, raw_wire, terminal_evidence))
}

fn count_delete_candidates(
    conn: &Connection,
    table: &str,
    predicate: &str,
    cutoff: i64,
) -> Result<u64> {
    let count: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"),
            params![cutoff],
            |row| row.get(0),
        )
        .with_context(|| format!("counting {table} retention delete candidates"))?;
    u64::try_from(count).with_context(|| format!("negative {table} retention candidate count"))
}

fn old_session_roots(conn: &Connection, cutoff_secs: i64) -> Result<Vec<Uuid>> {
    let cutoff_unix_ms = cutoff_secs.saturating_mul(1000);
    let mut stmt = conn
        .prepare(
            "SELECT root.session_id
               FROM sessions root
              WHERE root.parent_session_id IS NULL
                AND root.ended_at_unix_ms IS NOT NULL
                AND root.ephemeral = 0
                AND root.last_active_at_unix_ms < ?1
                AND NOT EXISTS (
                    WITH RECURSIVE subtree(session_id, ended_at_unix_ms, last_active_at_unix_ms) AS (
                        SELECT session_id, ended_at_unix_ms, last_active_at_unix_ms
                          FROM sessions WHERE session_id = root.session_id
                        UNION ALL
                        SELECT child.session_id, child.ended_at_unix_ms, child.last_active_at_unix_ms
                          FROM sessions child
                          JOIN subtree parent ON child.parent_session_id = parent.session_id
                    )
                    SELECT 1 FROM subtree
                     WHERE ended_at_unix_ms IS NULL OR last_active_at_unix_ms >= ?1
                )
                AND NOT EXISTS (
                    WITH RECURSIVE subtree(session_id) AS (
                        SELECT session_id FROM sessions WHERE session_id = root.session_id
                        UNION ALL
                        SELECT child.session_id
                          FROM sessions child
                          JOIN subtree parent ON child.parent_session_id = parent.session_id
                    )
                    SELECT 1 FROM pins JOIN subtree USING (session_id)
                )",
        )
        .context("preparing old session roots")?;
    let rows = stmt
        .query_map(params![cutoff_unix_ms], |row| {
            let raw: String = row.get(0)?;
            parse_uuid_sql(raw)
        })
        .context("querying old session roots")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.context("decoding old session root")?);
    }
    Ok(out)
}

fn expire_old_sessions_conn(conn: &Connection, cutoff_secs: i64) -> Result<SessionExpiryOutcome> {
    let roots = old_session_roots(conn, cutoff_secs)?;
    let mut removed = 0_u64;
    let mut cascade_rows_deleted = 0_u64;
    let mut sessions_expiry_skipped_media_barrier = 0_u64;
    for root in roots {
        // Count the complete logical session cascade before deleting its root.
        // `DELETE FROM sessions` reports only the root through `changes()`;
        // descendant forks are removed by the self-FK cascade.
        let subtree_rows: i64 = conn.query_row(
            "WITH RECURSIVE subtree(session_id) AS (
                 SELECT session_id FROM sessions WHERE session_id=?1
                 UNION ALL
                 SELECT child.session_id
                   FROM sessions child
                   JOIN subtree parent ON child.parent_session_id=parent.session_id
             )
             SELECT COUNT(*) FROM subtree",
            [root.to_string()],
            |row| row.get(0),
        )?;
        let subtree_rows =
            u64::try_from(subtree_rows).context("negative session retention subtree row count")?;
        match crate::db::sessions::delete_session_conn(conn, root) {
            Ok(cascade_rows) => {
                removed = removed.saturating_add(subtree_rows);
                cascade_rows_deleted = cascade_rows_deleted.saturating_add(cascade_rows);
            }
            Err(error) if crate::db::sessions::is_session_media_cleanup_barrier(&error) => {
                sessions_expiry_skipped_media_barrier =
                    sessions_expiry_skipped_media_barrier.saturating_add(1);
                tracing::info!(
                    session_id = %root,
                    reason = SESSIONS_EXPIRY_SKIPPED_MEDIA_BARRIER_KEY,
                    "session expiry skipped because media cleanup is not terminal"
                );
            }
            Err(error) => {
                return Err(error).with_context(|| format!("expiring old session {root}"));
            }
        }
    }
    Ok(SessionExpiryOutcome {
        sessions_expired: removed,
        cascade_rows_deleted,
        sessions_expiry_skipped_media_barrier,
    })
}

fn parse_uuid_sql(raw: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn close_session(db: &Db, id: Uuid, ts_secs: i64) {
        let ts_ms = ts_secs.saturating_mul(1000);
        db.write(move |conn| {
            conn.execute(
                "UPDATE sessions
                    SET started_at_unix_ms = MIN(started_at_unix_ms, ?2),
                        ended_at_unix_ms = ?2,
                        last_active_at_unix_ms = ?2
                  WHERE session_id = ?1",
                params![id.to_string(), ts_ms],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    async fn insert_payload_rows(db: &Db, session_id: Uuid, call_id: &str, ts_secs: i64) {
        let call_id = call_id.to_owned();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO inference_requests (call_id, session_id, ts_ms, payload_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![call_id, session_id.to_string(), ts_secs * 1000, "{}"],
            )?;
            conn.execute(
                "INSERT INTO session_events (session_id, ts_ms, type, data_json)
                 VALUES (?1, ?2, 'user_message', '{}')",
                params![session_id.to_string(), ts_secs * 1000],
            )?;
            conn.execute(
                "INSERT INTO tool_call_events (
                    event_id, session_id, call_id, timestamp, model, provider, project_id,
                    project_root, agent, tool, original_input_json, wire_input_json, output
                 ) VALUES (?1, ?2, ?3, ?4, 'm', 'p', 'proj', '/x', 'a', 'read', '{}', '{}', '')",
                params![
                    Uuid::new_v4().to_string(),
                    session_id.to_string(),
                    call_id,
                    ts_secs
                ],
            )?;
            conn.execute(
                "INSERT INTO inference_calls (
                    call_id, session_id, project_id, project_root, model, provider, timestamp,
                    input_tokens, output_tokens, cached_input_tokens, cache_creation_input_tokens
                 ) VALUES (?1, ?2, 'proj', '/x', 'm', 'p', ?3, 1, 1, 0, 0)",
                params![call_id, session_id.to_string(), ts_secs],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    async fn payload_count(db: &Db, table: &str, session_id: Uuid) -> i64 {
        let table = table.to_owned();
        db.read(move |conn| {
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE session_id = ?1"),
                params![session_id.to_string()],
                |row| row.get(0),
            )
            .context("counting payload rows")
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn payload_age_out_keeps_open_session_rows() {
        let db = Db::open_in_memory().unwrap();
        let closed = db.create_session("p", "/x", "Build").await.unwrap();
        let open = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, closed.session_id, 10).await;
        insert_payload_rows(&db, closed.session_id, "closed", 10).await;
        insert_payload_rows(&db, open.session_id, "open", 10).await;

        assert_eq!(
            db.prune_session_payloads(20, 20, 20).await.unwrap(),
            (1, 2, 1)
        );

        for table in [
            "inference_requests",
            "session_events",
            "tool_call_events",
            "inference_calls",
        ] {
            assert_eq!(
                payload_count(&db, table, closed.session_id).await,
                0,
                "{table}"
            );
            assert_eq!(
                payload_count(&db, table, open.session_id).await,
                1,
                "{table}"
            );
        }
    }

    #[tokio::test]
    async fn payload_prune_failure_rolls_back_prior_table_deletes() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, s.session_id, 10).await;
        insert_payload_rows(&db, s.session_id, "closed", 10).await;
        db.write(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_session_event_prune
                 BEFORE DELETE ON session_events
                 BEGIN
                     SELECT RAISE(FAIL, 'injected payload prune failure');
                 END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let err = db.prune_session_payloads(20, 20, 20).await.unwrap_err();

        assert!(
            format!("{err:#}").contains("injected payload prune failure"),
            "unexpected error: {err:#}"
        );
        for table in [
            "inference_requests",
            "session_events",
            "tool_call_events",
            "inference_calls",
        ] {
            assert_eq!(payload_count(&db, table, s.session_id).await, 1, "{table}");
        }
    }

    #[tokio::test]
    async fn payload_age_out_respects_half_open_boundary() {
        let db = Db::open_in_memory().unwrap();
        let at = db.create_session("p", "/x", "Build").await.unwrap();
        let old = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, at.session_id, 100).await;
        close_session(&db, old.session_id, 99).await;
        insert_payload_rows(&db, at.session_id, "at", 100).await;
        insert_payload_rows(&db, old.session_id, "old", 99).await;

        assert_eq!(
            db.prune_session_payloads(100, 100, 100).await.unwrap(),
            (1, 2, 1)
        );

        for table in [
            "inference_requests",
            "session_events",
            "tool_call_events",
            "inference_calls",
        ] {
            assert_eq!(payload_count(&db, table, at.session_id).await, 1, "{table}");
            assert_eq!(
                payload_count(&db, table, old.session_id).await,
                0,
                "{table}"
            );
        }
    }

    #[tokio::test]
    async fn payload_age_out_preserves_session_metadata_row() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, s.session_id, 10).await;
        insert_payload_rows(&db, s.session_id, "closed", 10).await;

        db.prune_session_payloads(20, 20, 20).await.unwrap();

        assert!(db.get_session(s.session_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn raw_wire_accounting_counts_every_cascaded_tool_descendant() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, session.session_id, 10).await;
        for call_id in ["root", "child", "grandchild"] {
            insert_payload_rows(&db, session.session_id, call_id, 10).await;
        }
        let session_id = session.session_id;
        db.write(move |conn| {
            conn.execute(
                "UPDATE tool_call_events SET parent_call_id='root'
                  WHERE session_id=?1 AND call_id='child'",
                [session_id.to_string()],
            )?;
            conn.execute(
                "UPDATE tool_call_events SET parent_call_id='child'
                  WHERE session_id=?1 AND call_id='grandchild'",
                [session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        assert_eq!(
            db.prune_session_payloads(0, 20, 0).await.unwrap(),
            (0, 6, 0)
        );
        assert_eq!(
            payload_count(&db, "tool_call_events", session.session_id).await,
            0
        );
        assert_eq!(
            payload_count(&db, "inference_requests", session.session_id).await,
            0
        );
    }

    #[tokio::test]
    async fn session_age_out_skips_open_subtree() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "Build").await.unwrap();
        let _child = db.create_fork(root.session_id, None).await.unwrap();
        close_session(&db, root.session_id, 10).await;

        assert_eq!(db.expire_old_sessions(20).await.unwrap(), 0);
        assert!(db.get_session(root.session_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn session_age_out_skips_recently_active_closed_descendant() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "Build").await.unwrap();
        let child = db.create_fork(root.session_id, None).await.unwrap();
        close_session(&db, root.session_id, 10).await;
        close_session(&db, child.session_id, 20).await;

        assert_eq!(db.expire_old_sessions(20).await.unwrap(), 0);
        assert!(db.get_session(root.session_id).await.unwrap().is_some());
        assert!(db.get_session(child.session_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn session_age_out_accounts_for_every_cascaded_session_row() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "Build").await.unwrap();
        let child = db.create_fork(root.session_id, None).await.unwrap();
        let grandchild = db.create_fork(child.session_id, None).await.unwrap();
        close_session(&db, root.session_id, 10).await;
        close_session(&db, child.session_id, 10).await;
        close_session(&db, grandchild.session_id, 10).await;

        assert_eq!(db.expire_old_sessions(20).await.unwrap(), 3);
        assert!(db.get_session(root.session_id).await.unwrap().is_none());
        assert!(db.get_session(child.session_id).await.unwrap().is_none());
        assert!(
            db.get_session(grandchild.session_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn retention_report_counts_descendant_pin_as_root_protection() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "Build").await.unwrap();
        let child = db.create_fork(root.session_id, None).await.unwrap();
        let child_id = child.session_id;
        let seq = db
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO session_events (session_id, ts_ms, type, data_json)
                     VALUES (?1, 1, 'user_message', '{}')",
                    params![child_id.to_string()],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
            .unwrap();
        assert!(db.pin_message(child.session_id, seq).await.unwrap());

        assert_eq!(
            db.retention_protection_report().await.unwrap(),
            RetentionProtectionReport {
                total_session_rows: 2,
                directly_pinned_sessions: 1,
                pin_protected_root_sessions: 1,
            }
        );
    }

    #[tokio::test]
    async fn session_age_out_skips_ephemeral() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, s.session_id, 10).await;
        db.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET ephemeral = 1 WHERE session_id = ?1",
                params![s.session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        assert_eq!(db.expire_old_sessions(20).await.unwrap(), 0);
        assert!(db.get_session(s.session_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn session_age_out_zero_window_is_noop() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, s.session_id, 10).await;

        assert_eq!(db.expire_old_sessions(0).await.unwrap(), 0);
        assert!(db.get_session(s.session_id).await.unwrap().is_some());
    }

    fn quarantined_media(session_id: Uuid) -> crate::db::media_attachments::MediaAttachmentRecord {
        use crate::db::media_attachments::{
            MediaAttachmentRecord, MediaAvailability, MediaKind, MediaSourceKind,
        };
        MediaAttachmentRecord {
            attachment_id: Uuid::now_v7(),
            session_id,
            canonical_project_digest: "11".repeat(32),
            media_kind: MediaKind::Image,
            source_kind: MediaSourceKind::RetainedHttps,
            canonical_container: "png".into(),
            canonical_mime: "image/png".into(),
            availability: MediaAvailability::Quarantined,
            attachment_version: 1,
            availability_generation: 1,
            reference_generation: 1,
            captured_capability_generation: 1,
            source_identity_digest: "22".repeat(32),
            source_byte_length: 1,
            source_sha256: "33".repeat(32),
            selected_video_stream: None,
            selected_audio_stream: None,
            created_at_unix_ms: 1,
            updated_at_unix_ms: 1,
            draft_expires_at_unix_ms: None,
            first_referenced_at_unix_ms: None,
        }
    }

    #[tokio::test]
    async fn session_expiry_skips_blocked_media() {
        let db = Db::open_in_memory().unwrap();
        let blocked = db.create_session("p", "/x", "Build").await.unwrap();
        let clean = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, blocked.session_id, 10).await;
        close_session(&db, clean.session_id, 10).await;
        let media = quarantined_media(blocked.session_id);
        db.transaction(move |conn| crate::db::Db::insert_media_attachment_conn(conn, &media))
            .await
            .unwrap();

        let expired = db.expire_old_sessions(20).await.unwrap();

        assert_eq!(expired, 1);
        assert!(db.get_session(blocked.session_id).await.unwrap().is_some());
        assert!(db.get_session(clean.session_id).await.unwrap().is_none());
        assert_eq!(db.sessions_expiry_skipped_media_barrier().await.unwrap(), 1);
        let outcome = db
            .run_retention_pass(
                &RetentionConfig {
                    transcript_window_days: 0,
                    raw_wire_window_days: 0,
                    terminal_evidence_window_days: 0,
                    session_window_days: 1,
                    vacuum_interval_days: 0,
                    ..RetentionConfig::default()
                },
                100_000,
            )
            .await
            .unwrap();
        assert_eq!(outcome.sessions_expired, 0);
        assert_eq!(outcome.sessions_expiry_skipped_media_barrier, 1);
    }

    #[tokio::test]
    async fn vacuum_triggers_on_deletion_threshold() {
        let db = Db::open_in_memory().unwrap();
        let cfg = RetentionConfig::default();
        assert!(db.should_vacuum(cfg.vacuum_min_deletions, 100, &cfg).await);
    }

    #[tokio::test]
    async fn vacuum_triggers_on_interval() {
        let db = Db::open_in_memory().unwrap();
        let cfg = RetentionConfig::default();
        db.record_vacuum(100).await.unwrap();
        assert!(!db.should_vacuum(0, 100 + 6 * 86_400, &cfg).await);
        assert!(db.should_vacuum(0, 100 + 7 * 86_400, &cfg).await);
    }

    #[tokio::test]
    async fn record_vacuum_round_trips() {
        let db = Db::open_in_memory().unwrap();
        let cfg = RetentionConfig::default();
        db.record_vacuum(100).await.unwrap();
        assert!(!db.should_vacuum(0, 100, &cfg).await);
    }

    #[tokio::test]
    async fn vacuum_uses_writer_connection() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("retention.db")).unwrap();
        assert!(db.vacuum_retention_database().await.unwrap());
    }

    #[tokio::test]
    async fn cascaded_session_rows_satisfy_the_vacuum_threshold() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("retention-threshold.db")).unwrap();
        let root = db.create_session("p", "/x", "Build").await.unwrap();
        let child = db.create_fork(root.session_id, None).await.unwrap();
        close_session(&db, root.session_id, 10).await;
        close_session(&db, child.session_id, 10).await;
        insert_payload_rows(&db, root.session_id, "root-evidence", 10).await;
        let cfg = RetentionConfig {
            transcript_window_days: 0,
            raw_wire_window_days: 0,
            terminal_evidence_window_days: 0,
            session_window_days: 1,
            // The two session rows alone are below threshold. Their dependent
            // evidence cascade must participate in the vacuum decision.
            vacuum_min_deletions: 3,
            vacuum_interval_days: 0,
            ..RetentionConfig::default()
        };

        let outcome = db.run_retention_pass(&cfg, 100_000).await.unwrap();

        assert_eq!(outcome.sessions_expired, 2);
        assert!(outcome.session_cascade_rows_deleted > outcome.sessions_expired);
        assert!(outcome.vacuumed);
    }

    #[test]
    fn launch_retention_defaults_bound_payloads_and_whole_sessions() {
        let cfg = RetentionConfig::default();
        assert_eq!(cfg.transcript_window_days, 90);
        assert_eq!(cfg.raw_wire_window_days, 30);
        assert_eq!(cfg.terminal_evidence_window_days, 90);
        assert_eq!(cfg.session_window_days, 365);
    }

    #[tokio::test]
    async fn disabled_windows_delete_nothing() {
        let db = Db::open_in_memory().unwrap();
        let cfg = RetentionConfig {
            transcript_window_days: 0,
            raw_wire_window_days: 0,
            terminal_evidence_window_days: 0,
            session_window_days: 0,
            vacuum_interval_days: 0,
            ..RetentionConfig::default()
        };

        assert_eq!(
            db.run_retention_pass(&cfg, 100).await.unwrap(),
            RetentionOutcome::default()
        );
    }

    #[tokio::test]
    async fn db_async_ops_retention_pass_runs_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, s.session_id, 10).await;
        insert_payload_rows(&db, s.session_id, "closed", 10).await;
        let cfg = RetentionConfig {
            transcript_window_days: 1,
            raw_wire_window_days: 1,
            terminal_evidence_window_days: 1,
            vacuum_interval_days: 0,
            ..RetentionConfig::default()
        };

        let outcome = db.run_retention_pass(&cfg, 100_000).await.unwrap();

        assert_eq!(outcome.payload_rows_deleted, 4);
        assert_eq!(outcome.sessions_expired, 0);
        assert!(!outcome.vacuumed);
    }

    #[tokio::test]
    async fn pinned_session_is_exempt_from_every_payload_window() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, session.session_id, 10).await;
        insert_payload_rows(&db, session.session_id, "preserved", 10).await;
        assert!(db.pin_message(session.session_id, 1).await.unwrap());
        let cfg = RetentionConfig {
            transcript_window_days: 1,
            raw_wire_window_days: 1,
            terminal_evidence_window_days: 1,
            vacuum_interval_days: 0,
            ..RetentionConfig::default()
        };

        let outcome = db.run_retention_pass(&cfg, 100_000).await.unwrap();

        assert_eq!(outcome.payload_rows_deleted, 0);
        for table in [
            "session_events",
            "inference_requests",
            "tool_call_events",
            "inference_calls",
        ] {
            assert_eq!(payload_count(&db, table, session.session_id).await, 1);
        }
    }

    #[tokio::test]
    async fn retention_pass_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        close_session(&db, s.session_id, 10).await;
        insert_payload_rows(&db, s.session_id, "closed", 10).await;
        let cfg = RetentionConfig {
            transcript_window_days: 1,
            raw_wire_window_days: 1,
            terminal_evidence_window_days: 1,
            vacuum_interval_days: 0,
            ..RetentionConfig::default()
        };

        let first = db.run_retention_pass(&cfg, 100_000).await.unwrap();
        let second = db.run_retention_pass(&cfg, 100_000).await.unwrap();

        assert_eq!(first.payload_rows_deleted, 4);
        assert_eq!(first.sessions_expired, 0);
        assert_eq!(second.payload_rows_deleted, 0);
        assert_eq!(second.sessions_expired, 0);
    }
}
