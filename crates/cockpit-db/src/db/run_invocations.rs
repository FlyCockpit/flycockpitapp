//! Durable daemon-global run invocation state and rejected-before-acceptance
//! tombstones. Keys are sole `client_submission_id` UUIDs — never a principal
//! composite. Rows do not cascade with sessions.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// Fixed row/index charge included in every `accounted_bytes` value.
pub const RUN_INVOCATION_BASE_BYTES: u64 = 256;

/// Retention after terminal_at / tombstone creation (30 days).
pub const RUN_INVOCATION_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

pub const SESSION_INVOCATION_COUNT_LIMIT: u64 = 1_024;
pub const SESSION_INVOCATION_BYTES_LIMIT: u64 = 8 * 1024 * 1024;
pub const PRINCIPAL_INVOCATION_COUNT_LIMIT: u64 = 4_096;
pub const PRINCIPAL_INVOCATION_BYTES_LIMIT: u64 = 32 * 1024 * 1024;
pub const PRINCIPAL_TOMBSTONE_COUNT_LIMIT: u64 = 1_024;
pub const PRINCIPAL_TOMBSTONE_BYTES_LIMIT: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInvocationRow {
    pub client_submission_id: Uuid,
    pub origin_principal_digest: String,
    pub session_id: Uuid,
    pub options_json: String,
    pub options_digest: String,
    pub content_digest: String,
    pub state: String,
    pub state_version: u64,
    pub created_at_wall_ms: i64,
    pub updated_at_wall_ms: i64,
    pub last_observed_wall_ms: i64,
    pub remaining_ms: Option<u64>,
    pub reserved_turns: u32,
    pub max_turns: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub cancel_requested: bool,
    pub cancel_result: Option<String>,
    pub terminal_reason: Option<String>,
    pub terminal_at_wall_ms: Option<i64>,
    pub expires_at_wall_ms: Option<i64>,
    pub accounted_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInvocationTombstoneRow {
    pub client_submission_id: Uuid,
    pub claiming_principal_digest: String,
    pub created_at_wall_ms: i64,
    pub expires_at_wall_ms: i64,
    pub accounted_bytes: u64,
}

/// Result of an atomic provider-dispatch turn reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveTurnOutcome {
    /// Reservation counted; provider dispatch may begin.
    Reserved(RunInvocationRow),
    /// Exactly N reservations already consumed; terminalized before N+1.
    MaxTurnsExceeded(RunInvocationRow),
    /// Already terminal (timeout/cancel/success/etc.).
    AlreadyTerminal(RunInvocationRow),
    /// Cancellation was requested first; no further dispatch.
    CancelRequested(RunInvocationRow),
    /// No durable record.
    NotFound,
}

/// Result of an idempotent timeout fire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutFireOutcome {
    /// First TimeoutExpired commit for this id.
    Committed(RunInvocationRow),
    /// Already terminal (including a prior timeout); no second transition.
    AlreadyTerminal(RunInvocationRow),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptRunInvocationOutcome {
    Created(RunInvocationRow),
    ExactReplay(RunInvocationRow),
    IdempotencyConflict,
    ClientSubmissionIdUnavailable,
    CapacityExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupRunInvocationOutcome {
    Found(Box<RunInvocationRow>),
    NotFoundInstalledTombstone,
    NotFoundExistingTombstone,
    LookupBusy,
}

/// Compute fixed-row-plus-canonical-fields accounting charge.
pub fn accounted_bytes_for_invocation(
    origin_principal_digest: &str,
    options_json: &str,
    options_digest: &str,
    content_digest: &str,
    state: &str,
    cancel_result: Option<&str>,
    terminal_reason: Option<&str>,
) -> Result<u64> {
    let mut total = RUN_INVOCATION_BASE_BYTES;
    for part in [
        origin_principal_digest.len() as u64,
        options_json.len() as u64,
        options_digest.len() as u64,
        content_digest.len() as u64,
        state.len() as u64,
        cancel_result.map(|s| s.len() as u64).unwrap_or(0),
        terminal_reason.map(|s| s.len() as u64).unwrap_or(0),
        // Fixed-width safe numeric columns charged once.
        8 * 8,
    ] {
        total = total
            .checked_add(part)
            .context("run invocation accounted_bytes overflow")?;
    }
    Ok(total)
}

/// Test-facing remaining-time classifier (mirrors daemon restart math).
#[cfg(test)]
pub fn remaining_after_restart_for_test(
    persisted_remaining_ms: Option<u64>,
    last_observed_wall_ms: i64,
    now_wall_ms: i64,
) -> String {
    let Some(remaining) = persisted_remaining_ms else {
        return "unbounded".into();
    };
    if now_wall_ms < last_observed_wall_ms {
        return "clock_rollback".into();
    }
    let elapsed = (now_wall_ms - last_observed_wall_ms) as u64;
    if elapsed >= remaining {
        return "expired".into();
    }
    format!("remaining:{}", remaining - elapsed)
}

pub fn accounted_bytes_for_tombstone(claiming_principal_digest: &str) -> Result<u64> {
    RUN_INVOCATION_BASE_BYTES
        .checked_add(claiming_principal_digest.len() as u64)
        .and_then(|v| v.checked_add(16)) // uuid + expiry fields
        .context("tombstone accounted_bytes overflow")
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RunInvocationRow> {
    Ok(RunInvocationRow {
        client_submission_id: Uuid::parse_str(&row.get::<_, String>(0)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        origin_principal_digest: row.get(1)?,
        session_id: Uuid::parse_str(&row.get::<_, String>(2)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        options_json: row.get(3)?,
        options_digest: row.get(4)?,
        content_digest: row.get(5)?,
        state: row.get(6)?,
        state_version: row.get::<_, i64>(7)? as u64,
        created_at_wall_ms: row.get(8)?,
        updated_at_wall_ms: row.get(9)?,
        last_observed_wall_ms: row.get(10)?,
        remaining_ms: row.get::<_, Option<i64>>(11)?.map(|v| v.max(0) as u64),
        reserved_turns: row.get::<_, i64>(12)? as u32,
        max_turns: row.get::<_, Option<i64>>(13)?.map(|v| v as u32),
        timeout_ms: row.get::<_, Option<i64>>(14)?.map(|v| v.max(0) as u64),
        cancel_requested: row.get::<_, i64>(15)? != 0,
        cancel_result: row.get(16)?,
        terminal_reason: row.get(17)?,
        terminal_at_wall_ms: row.get(18)?,
        expires_at_wall_ms: row.get(19)?,
        accounted_bytes: row.get::<_, i64>(20)? as u64,
    })
}

const SELECT_COLS: &str = "client_submission_id, origin_principal_digest, session_id,
    options_json, options_digest, content_digest, state, state_version,
    created_at_wall_ms, updated_at_wall_ms, last_observed_wall_ms, remaining_ms,
    reserved_turns, max_turns, timeout_ms, cancel_requested, cancel_result,
    terminal_reason, terminal_at_wall_ms, expires_at_wall_ms, accounted_bytes";

impl Db {
    pub async fn get_run_invocation(
        &self,
        client_submission_id: Uuid,
    ) -> Result<Option<RunInvocationRow>> {
        self.read(move |conn| {
            conn.query_row(
                &format!(
                    "SELECT {SELECT_COLS} FROM run_invocations WHERE client_submission_id = ?1"
                ),
                params![client_submission_id.to_string()],
                map_row,
            )
            .optional()
            .context("looking up run invocation")
        })
        .await
    }

    pub async fn get_run_invocation_tombstone(
        &self,
        client_submission_id: Uuid,
    ) -> Result<Option<RunInvocationTombstoneRow>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT client_submission_id, claiming_principal_digest,
                        created_at_wall_ms, expires_at_wall_ms, accounted_bytes
                   FROM run_invocation_tombstones
                  WHERE client_submission_id = ?1",
                params![client_submission_id.to_string()],
                |row| {
                    Ok(RunInvocationTombstoneRow {
                        client_submission_id: Uuid::parse_str(&row.get::<_, String>(0)?)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                        claiming_principal_digest: row.get(1)?,
                        created_at_wall_ms: row.get(2)?,
                        expires_at_wall_ms: row.get(3)?,
                        accounted_bytes: row.get::<_, i64>(4)? as u64,
                    })
                },
            )
            .optional()
            .context("looking up run invocation tombstone")
        })
        .await
    }

    /// Accept a new run invocation or return an exact/idempotent replay result.
    /// Deletes expired rows first, then checks quotas, then inserts atomically.
    #[allow(clippy::too_many_arguments)]
    pub async fn accept_run_invocation(
        &self,
        client_submission_id: Uuid,
        origin_principal_digest: String,
        session_id: Uuid,
        options_json: String,
        options_digest: String,
        content_digest: String,
        max_turns: Option<u32>,
        timeout_ms: Option<u64>,
        now_wall_ms: i64,
    ) -> Result<AcceptRunInvocationOutcome> {
        let accounted = accounted_bytes_for_invocation(
            &origin_principal_digest,
            &options_json,
            &options_digest,
            &content_digest,
            "accepted",
            None,
            None,
        )?;
        self.transaction(move |conn| {
            delete_expired_run_invocation_rows(conn, now_wall_ms)?;

            if let Some(existing) = get_run_invocation_conn(conn, client_submission_id)? {
                if existing.origin_principal_digest != origin_principal_digest {
                    return Ok(AcceptRunInvocationOutcome::ClientSubmissionIdUnavailable);
                }
                if existing.options_digest == options_digest
                    && existing.content_digest == content_digest
                {
                    return Ok(AcceptRunInvocationOutcome::ExactReplay(existing));
                }
                return Ok(AcceptRunInvocationOutcome::IdempotencyConflict);
            }

            if tombstone_exists_conn(conn, client_submission_id)? {
                return Ok(AcceptRunInvocationOutcome::ClientSubmissionIdUnavailable);
            }

            if !session_quota_allows(conn, session_id, accounted)?
                || !principal_quota_allows(conn, &origin_principal_digest, accounted, false)?
            {
                return Ok(AcceptRunInvocationOutcome::CapacityExceeded);
            }

            let remaining_ms = timeout_ms;
            conn.execute(
                "INSERT INTO run_invocations (
                    client_submission_id, origin_principal_digest, session_id,
                    options_json, options_digest, content_digest, state, state_version,
                    created_at_wall_ms, updated_at_wall_ms, last_observed_wall_ms,
                    remaining_ms, reserved_turns, max_turns, timeout_ms,
                    cancel_requested, cancel_result, terminal_reason,
                    terminal_at_wall_ms, expires_at_wall_ms, accounted_bytes
                 ) VALUES (?1,?2,?3,?4,?5,?6,'accepted',1,?7,?7,?7,?8,0,?9,?10,0,NULL,NULL,NULL,NULL,?11)",
                params![
                    client_submission_id.to_string(),
                    origin_principal_digest,
                    session_id.to_string(),
                    options_json,
                    options_digest,
                    content_digest,
                    now_wall_ms,
                    remaining_ms.map(|v| v as i64),
                    max_turns.map(|v| v as i64),
                    timeout_ms.map(|v| v as i64),
                    accounted as i64,
                ],
            )
            .context("inserting run invocation")?;

            let created = get_run_invocation_conn(conn, client_submission_id)?
                .context("run invocation missing after insert")?;
            Ok(AcceptRunInvocationOutcome::Created(created))
        })
        .await
    }

    /// Authoritative unknown-ID lookup: install a content-free tombstone when
    /// capacity allows; otherwise return non-authoritative LookupBusy.
    pub async fn lookup_or_tombstone_run_invocation(
        &self,
        client_submission_id: Uuid,
        claiming_principal_digest: String,
        now_wall_ms: i64,
        is_owner: bool,
    ) -> Result<LookupRunInvocationOutcome> {
        self.transaction(move |conn| {
            Self::lookup_or_tombstone_run_invocation_conn(
                conn,
                client_submission_id,
                &claiming_principal_digest,
                now_wall_ms,
                is_owner,
            )
        })
        .await
    }

    pub fn lookup_or_tombstone_run_invocation_conn(
        conn: &rusqlite::Connection,
        client_submission_id: Uuid,
        claiming_principal_digest: &str,
        now_wall_ms: i64,
        is_owner: bool,
    ) -> Result<LookupRunInvocationOutcome> {
        delete_expired_run_invocation_rows(conn, now_wall_ms)?;
        if let Some(row) = get_run_invocation_conn(conn, client_submission_id)? {
            if is_owner || row.origin_principal_digest == claiming_principal_digest {
                return Ok(LookupRunInvocationOutcome::Found(Box::new(row)));
            }
            return Ok(LookupRunInvocationOutcome::NotFoundExistingTombstone);
        }
        if tombstone_exists_conn(conn, client_submission_id)? {
            return Ok(LookupRunInvocationOutcome::NotFoundExistingTombstone);
        }
        let accounted = accounted_bytes_for_tombstone(claiming_principal_digest)?;
        if !principal_quota_allows(conn, claiming_principal_digest, accounted, true)? {
            return Ok(LookupRunInvocationOutcome::LookupBusy);
        }
        let expires = now_wall_ms
            .checked_add(RUN_INVOCATION_RETENTION_MS)
            .context("tombstone expiry overflow")?;
        conn.execute(
            "INSERT INTO run_invocation_tombstones (
                client_submission_id, claiming_principal_digest,
                created_at_wall_ms, expires_at_wall_ms, accounted_bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                client_submission_id.to_string(),
                claiming_principal_digest,
                now_wall_ms,
                expires,
                accounted as i64
            ],
        )
        .context("inserting run invocation tombstone")?;
        Ok(LookupRunInvocationOutcome::NotFoundInstalledTombstone)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_run_invocation_state_conn(
        conn: &rusqlite::Connection,
        client_submission_id: Uuid,
        expected_state_version: u64,
        new_state: &str,
        remaining_ms: Option<u64>,
        cancel_requested: Option<bool>,
        cancel_result: Option<&str>,
        now_wall_ms: i64,
    ) -> Result<Option<RunInvocationRow>> {
        let Some(existing) = get_run_invocation_conn(conn, client_submission_id)? else {
            return Ok(None);
        };
        if existing.state_version != expected_state_version {
            return Ok(Some(existing));
        }
        if existing.terminal_at_wall_ms.is_some() {
            if let Some(result) = cancel_result
                && existing.cancel_result.is_none()
            {
                let new_version = existing
                    .state_version
                    .checked_add(1)
                    .context("state_version overflow")?;
                conn.execute(
                    "UPDATE run_invocations SET state_version=?1, updated_at_wall_ms=?2,
                     cancel_requested=1, cancel_result=?3 WHERE client_submission_id=?4",
                    params![
                        new_version as i64,
                        now_wall_ms,
                        result,
                        client_submission_id.to_string()
                    ],
                )
                .context("stamping cancel_result on terminal invocation")?;
                return get_run_invocation_conn(conn, client_submission_id);
            }
            return Ok(Some(existing));
        }
        let new_version = existing
            .state_version
            .checked_add(1)
            .context("state_version overflow")?;
        conn.execute(
            "UPDATE run_invocations SET state=?1, state_version=?2, updated_at_wall_ms=?3,
             last_observed_wall_ms=?3, remaining_ms=?4, cancel_requested=?5,
             cancel_result=?6 WHERE client_submission_id=?7",
            params![
                new_state,
                new_version as i64,
                now_wall_ms,
                remaining_ms.or(existing.remaining_ms).map(|v| v as i64),
                cancel_requested.unwrap_or(existing.cancel_requested) as i64,
                cancel_result.or(existing.cancel_result.as_deref()),
                client_submission_id.to_string()
            ],
        )
        .context("updating run invocation cancellation state")?;
        get_run_invocation_conn(conn, client_submission_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_run_invocation_state(
        &self,
        client_submission_id: Uuid,
        expected_state_version: u64,
        new_state: &str,
        remaining_ms: Option<u64>,
        reserved_turns: Option<u32>,
        cancel_requested: Option<bool>,
        cancel_result: Option<&str>,
        terminal_reason: Option<&str>,
        now_wall_ms: i64,
    ) -> Result<Option<RunInvocationRow>> {
        let new_state = new_state.to_owned();
        let cancel_result = cancel_result.map(str::to_owned);
        let terminal_reason = terminal_reason.map(str::to_owned);
        self.transaction(move |conn| {
            let Some(existing) = get_run_invocation_conn(conn, client_submission_id)? else {
                return Ok(None);
            };
            if existing.state_version != expected_state_version {
                return Ok(Some(existing));
            }
            // Terminal rows only accept idempotent cancel_result stamping.
            if existing.terminal_at_wall_ms.is_some() {
                if let Some(result) = cancel_result.as_deref()
                    && existing.cancel_result.is_none()
                {
                    let new_version = existing
                        .state_version
                        .checked_add(1)
                        .context("state_version overflow")?;
                    conn.execute(
                        "UPDATE run_invocations SET
                            state_version = ?1,
                            updated_at_wall_ms = ?2,
                            cancel_requested = 1,
                            cancel_result = ?3
                         WHERE client_submission_id = ?4",
                        params![
                            new_version as i64,
                            now_wall_ms,
                            result,
                            client_submission_id.to_string(),
                        ],
                    )
                    .context("stamping cancel_result on terminal invocation")?;
                    return get_run_invocation_conn(conn, client_submission_id);
                }
                return Ok(Some(existing));
            }
            let is_terminal = matches!(
                new_state.as_str(),
                "succeeded"
                    | "failed"
                    | "cancelled"
                    | "timeout_expired"
                    | "max_turns_exceeded"
                    | "clock_rollback_timed_out"
                    | "outcome_unknown"
            );
            let terminal_at = is_terminal.then_some(now_wall_ms);
            let expires_at = if is_terminal {
                Some(
                    now_wall_ms
                        .checked_add(RUN_INVOCATION_RETENTION_MS)
                        .context("terminal expiry overflow")?,
                )
            } else {
                None
            };
            let new_version = existing
                .state_version
                .checked_add(1)
                .context("state_version overflow")?;
            let reserved = reserved_turns.unwrap_or(existing.reserved_turns);
            let cancel_req = cancel_requested.unwrap_or(existing.cancel_requested);
            let cancel_res = cancel_result.or(existing.cancel_result.clone());
            let term_reason = terminal_reason.or(existing.terminal_reason.clone());
            let rem = remaining_ms.or(existing.remaining_ms);

            conn.execute(
                "UPDATE run_invocations SET
                    state = ?1,
                    state_version = ?2,
                    updated_at_wall_ms = ?3,
                    last_observed_wall_ms = ?3,
                    remaining_ms = ?4,
                    reserved_turns = ?5,
                    cancel_requested = ?6,
                    cancel_result = ?7,
                    terminal_reason = ?8,
                    terminal_at_wall_ms = ?9,
                    expires_at_wall_ms = ?10
                 WHERE client_submission_id = ?11",
                params![
                    new_state,
                    new_version as i64,
                    now_wall_ms,
                    rem.map(|v| v as i64),
                    reserved as i64,
                    cancel_req as i64,
                    cancel_res,
                    term_reason,
                    terminal_at,
                    expires_at,
                    client_submission_id.to_string(),
                ],
            )
            .context("updating run invocation state")?;
            get_run_invocation_conn(conn, client_submission_id)
        })
        .await
    }

    /// Atomically terminalize every active invocation for a session.
    pub async fn terminalize_session_run_invocations(
        &self,
        session_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<u64> {
        self.transaction(move |conn| {
            Self::terminalize_session_run_invocations_conn(conn, session_id, now_wall_ms)
        })
        .await
    }

    /// Connection-direct session run-invocation terminalization for callers
    /// already inside a transaction (e.g. the transactional remote-operation
    /// ledger writer deleting a session), so this durable mutation commits
    /// atomically with the session delete + ledger row instead of in a separate
    /// autocommitted transaction that a later ledger failure cannot undo.
    pub fn terminalize_session_run_invocations_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<u64> {
        delete_expired_run_invocation_rows(conn, now_wall_ms)?;
        let expires = now_wall_ms
            .checked_add(RUN_INVOCATION_RETENTION_MS)
            .context("session delete expiry overflow")?;
        let changed = conn
            .execute(
                "UPDATE run_invocations SET
                        state = 'cancelled',
                        state_version = state_version + 1,
                        updated_at_wall_ms = ?1,
                        last_observed_wall_ms = ?1,
                        cancel_requested = 1,
                        cancel_result = COALESCE(cancel_result, 'already_terminal'),
                        terminal_reason = 'cancelled_session_deleted',
                        terminal_at_wall_ms = ?1,
                        expires_at_wall_ms = ?2,
                        remaining_ms = 0
                     WHERE session_id = ?3 AND terminal_at_wall_ms IS NULL",
                params![now_wall_ms, expires, session_id.to_string()],
            )
            .context("terminalizing session run invocations")?;
        Ok(changed as u64)
    }

    /// Checkpoint remaining time without advancing lifecycle state.
    pub async fn checkpoint_run_invocation_remaining(
        &self,
        client_submission_id: Uuid,
        remaining_ms: Option<u64>,
        now_wall_ms: i64,
    ) -> Result<Option<RunInvocationRow>> {
        self.transaction(move |conn| {
            let Some(existing) = get_run_invocation_conn(conn, client_submission_id)? else {
                return Ok(None);
            };
            if existing.terminal_at_wall_ms.is_some() {
                return Ok(Some(existing));
            }
            // Clock rollback never extends expiry.
            if now_wall_ms < existing.last_observed_wall_ms {
                let expires = now_wall_ms
                    .checked_add(RUN_INVOCATION_RETENTION_MS)
                    .context("clock rollback expiry overflow")?;
                conn.execute(
                    "UPDATE run_invocations SET
                        state = 'clock_rollback_timed_out',
                        state_version = state_version + 1,
                        updated_at_wall_ms = ?1,
                        last_observed_wall_ms = ?1,
                        remaining_ms = 0,
                        terminal_reason = 'clock_rollback_timed_out',
                        terminal_at_wall_ms = ?1,
                        expires_at_wall_ms = ?2
                     WHERE client_submission_id = ?3",
                    params![now_wall_ms, expires, client_submission_id.to_string()],
                )
                .context("clock-rollback terminalizing run invocation")?;
                return get_run_invocation_conn(conn, client_submission_id);
            }
            let new_version = existing
                .state_version
                .checked_add(1)
                .context("state_version overflow")?;
            conn.execute(
                "UPDATE run_invocations SET
                    state_version = ?1,
                    updated_at_wall_ms = ?2,
                    last_observed_wall_ms = ?2,
                    remaining_ms = ?3
                 WHERE client_submission_id = ?4",
                params![
                    new_version as i64,
                    now_wall_ms,
                    remaining_ms.map(|v| v as i64),
                    client_submission_id.to_string(),
                ],
            )
            .context("checkpointing run invocation remaining")?;
            get_run_invocation_conn(conn, client_submission_id)
        })
        .await
    }

    /// Atomically reserve one provider-dispatch turn for a run invocation.
    ///
    /// Exactly N reservations are permitted when `max_turns = N`. Needing an
    /// (N+1)th reservation terminalizes `max_turns_exceeded` before any
    /// further provider request. Uncertain acceptance still consumes the
    /// reservation — there is no un-reserve path.
    pub async fn reserve_run_invocation_turn(
        &self,
        client_submission_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<ReserveTurnOutcome> {
        self.transaction(move |conn| {
            let Some(existing) = get_run_invocation_conn(conn, client_submission_id)? else {
                return Ok(ReserveTurnOutcome::NotFound);
            };
            if existing.terminal_at_wall_ms.is_some() {
                return Ok(ReserveTurnOutcome::AlreadyTerminal(existing));
            }
            if existing.cancel_requested {
                return Ok(ReserveTurnOutcome::CancelRequested(existing));
            }
            if let Some(max) = existing.max_turns
                && existing.reserved_turns >= max
            {
                // Terminalize before N+1 without incrementing reserved_turns.
                let expires = now_wall_ms
                    .checked_add(RUN_INVOCATION_RETENTION_MS)
                    .context("max_turns expiry overflow")?;
                let new_version = existing
                    .state_version
                    .checked_add(1)
                    .context("state_version overflow")?;
                conn.execute(
                    "UPDATE run_invocations SET
                            state = 'max_turns_exceeded',
                            state_version = ?1,
                            updated_at_wall_ms = ?2,
                            last_observed_wall_ms = ?2,
                            remaining_ms = 0,
                            terminal_reason = 'max_turns_exceeded',
                            terminal_at_wall_ms = ?2,
                            expires_at_wall_ms = ?3
                         WHERE client_submission_id = ?4",
                    params![
                        new_version as i64,
                        now_wall_ms,
                        expires,
                        client_submission_id.to_string(),
                    ],
                )
                .context("terminalizing max_turns_exceeded")?;
                let row = get_run_invocation_conn(conn, client_submission_id)?
                    .context("missing after max_turns terminalize")?;
                return Ok(ReserveTurnOutcome::MaxTurnsExceeded(row));
            }
            let next = existing
                .reserved_turns
                .checked_add(1)
                .context("reserved_turns overflow")?;
            let new_version = existing
                .state_version
                .checked_add(1)
                .context("state_version overflow")?;
            conn.execute(
                "UPDATE run_invocations SET
                    state = 'dispatching',
                    state_version = ?1,
                    updated_at_wall_ms = ?2,
                    last_observed_wall_ms = ?2,
                    reserved_turns = ?3
                 WHERE client_submission_id = ?4",
                params![
                    new_version as i64,
                    now_wall_ms,
                    next as i64,
                    client_submission_id.to_string(),
                ],
            )
            .context("reserving run invocation turn")?;
            let row = get_run_invocation_conn(conn, client_submission_id)?
                .context("missing after reserve")?;
            Ok(ReserveTurnOutcome::Reserved(row))
        })
        .await
    }

    /// Idempotent TimeoutExpired commit. Exactly one terminal transition wins.
    pub async fn fire_run_invocation_timeout(
        &self,
        client_submission_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<TimeoutFireOutcome> {
        self.transaction(move |conn| {
            let Some(existing) = get_run_invocation_conn(conn, client_submission_id)? else {
                return Ok(TimeoutFireOutcome::NotFound);
            };
            if existing.terminal_at_wall_ms.is_some() {
                return Ok(TimeoutFireOutcome::AlreadyTerminal(existing));
            }
            let expires = now_wall_ms
                .checked_add(RUN_INVOCATION_RETENTION_MS)
                .context("timeout expiry overflow")?;
            let new_version = existing
                .state_version
                .checked_add(1)
                .context("state_version overflow")?;
            conn.execute(
                "UPDATE run_invocations SET
                    state = 'timeout_expired',
                    state_version = ?1,
                    updated_at_wall_ms = ?2,
                    last_observed_wall_ms = ?2,
                    remaining_ms = 0,
                    terminal_reason = 'timeout_expired',
                    terminal_at_wall_ms = ?2,
                    expires_at_wall_ms = ?3
                 WHERE client_submission_id = ?4
                   AND terminal_at_wall_ms IS NULL",
                params![
                    new_version as i64,
                    now_wall_ms,
                    expires,
                    client_submission_id.to_string(),
                ],
            )
            .context("firing timeout_expired")?;
            let row = get_run_invocation_conn(conn, client_submission_id)?
                .context("missing after timeout fire")?;
            if row.terminal_reason.as_deref() == Some("timeout_expired")
                && row.terminal_at_wall_ms == Some(now_wall_ms)
            {
                Ok(TimeoutFireOutcome::Committed(row))
            } else {
                // Lost race to another terminalizer.
                Ok(TimeoutFireOutcome::AlreadyTerminal(row))
            }
        })
        .await
    }

    /// Mark a run invocation terminal with the given reason (cancel-first aware).
    pub async fn mark_run_invocation_terminal(
        &self,
        client_submission_id: Uuid,
        terminal_reason: &str,
        state: &str,
        now_wall_ms: i64,
    ) -> Result<Option<RunInvocationRow>> {
        let terminal_reason = terminal_reason.to_owned();
        let state = state.to_owned();
        self.transaction(move |conn| {
            let Some(existing) = get_run_invocation_conn(conn, client_submission_id)? else {
                return Ok(None);
            };
            if existing.terminal_at_wall_ms.is_some() {
                return Ok(Some(existing));
            }
            // Cancel-first: cancel wins over later success/failure.
            let (final_state, final_reason) = if existing.cancel_requested
                && !matches!(
                    terminal_reason.as_str(),
                    "cancelled"
                        | "cancelled_session_deleted"
                        | "timeout_expired"
                        | "max_turns_exceeded"
                        | "clock_rollback_timed_out"
                )
            {
                ("cancelled", "cancelled".to_string())
            } else {
                (state.as_str(), terminal_reason)
            };
            let expires = now_wall_ms
                .checked_add(RUN_INVOCATION_RETENTION_MS)
                .context("terminal mark expiry overflow")?;
            let new_version = existing
                .state_version
                .checked_add(1)
                .context("state_version overflow")?;
            conn.execute(
                "UPDATE run_invocations SET
                    state = ?1,
                    state_version = ?2,
                    updated_at_wall_ms = ?3,
                    last_observed_wall_ms = ?3,
                    remaining_ms = 0,
                    cancel_requested = CASE WHEN ?4 THEN 1 ELSE cancel_requested END,
                    cancel_result = COALESCE(cancel_result, CASE WHEN ?4 THEN 'cancellation_requested' ELSE NULL END),
                    terminal_reason = ?5,
                    terminal_at_wall_ms = ?3,
                    expires_at_wall_ms = ?6
                 WHERE client_submission_id = ?7
                   AND terminal_at_wall_ms IS NULL",
                params![
                    final_state,
                    new_version as i64,
                    now_wall_ms,
                    final_reason == "cancelled",
                    final_reason,
                    expires,
                    client_submission_id.to_string(),
                ],
            )
            .context("marking run invocation terminal")?;
            get_run_invocation_conn(conn, client_submission_id)
        })
        .await
    }

    pub async fn cleanup_expired_run_invocations(&self, now_wall_ms: i64) -> Result<(u64, u64)> {
        self.transaction(move |conn| delete_expired_run_invocation_rows(conn, now_wall_ms))
            .await
    }

    pub async fn list_active_run_invocations_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<RunInvocationRow>> {
        self.read(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {SELECT_COLS} FROM run_invocations
                  WHERE session_id = ?1 AND terminal_at_wall_ms IS NULL
                  ORDER BY created_at_wall_ms ASC"
            ))?;
            let rows = stmt
                .query_map(params![session_id.to_string()], map_row)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }
}

fn get_run_invocation_conn(
    conn: &rusqlite::Connection,
    client_submission_id: Uuid,
) -> Result<Option<RunInvocationRow>> {
    conn.query_row(
        &format!("SELECT {SELECT_COLS} FROM run_invocations WHERE client_submission_id = ?1"),
        params![client_submission_id.to_string()],
        map_row,
    )
    .optional()
    .context("looking up run invocation in tx")
}

fn tombstone_exists_conn(conn: &rusqlite::Connection, client_submission_id: Uuid) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(1) FROM run_invocation_tombstones WHERE client_submission_id = ?1",
            params![client_submission_id.to_string()],
            |row| row.get(0),
        )
        .context("checking tombstone existence")?;
    Ok(count > 0)
}

fn delete_expired_run_invocation_rows(
    conn: &rusqlite::Connection,
    now_wall_ms: i64,
) -> Result<(u64, u64)> {
    let inv = conn
        .execute(
            "DELETE FROM run_invocations
              WHERE expires_at_wall_ms IS NOT NULL AND expires_at_wall_ms <= ?1",
            params![now_wall_ms],
        )
        .context("deleting expired run invocations")? as u64;
    let tombs = conn
        .execute(
            "DELETE FROM run_invocation_tombstones WHERE expires_at_wall_ms <= ?1",
            params![now_wall_ms],
        )
        .context("deleting expired run invocation tombstones")? as u64;
    Ok((inv, tombs))
}

fn session_quota_allows(
    conn: &rusqlite::Connection,
    session_id: Uuid,
    additional_bytes: u64,
) -> Result<bool> {
    let (count, bytes): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(1), COALESCE(SUM(accounted_bytes), 0)
               FROM run_invocations WHERE session_id = ?1",
            params![session_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("session invocation quota")?;
    if count as u64 >= SESSION_INVOCATION_COUNT_LIMIT {
        return Ok(false);
    }
    let bytes = bytes as u64;
    Ok(bytes
        .checked_add(additional_bytes)
        .map(|total| total <= SESSION_INVOCATION_BYTES_LIMIT)
        .unwrap_or(false))
}

fn principal_quota_allows(
    conn: &rusqlite::Connection,
    principal_digest: &str,
    additional_bytes: u64,
    is_tombstone: bool,
) -> Result<bool> {
    let (inv_count, inv_bytes): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(1), COALESCE(SUM(accounted_bytes), 0)
               FROM run_invocations WHERE origin_principal_digest = ?1",
            params![principal_digest],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("principal invocation quota")?;
    let (tomb_count, tomb_bytes): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(1), COALESCE(SUM(accounted_bytes), 0)
               FROM run_invocation_tombstones WHERE claiming_principal_digest = ?1",
            params![principal_digest],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("principal tombstone quota")?;

    if is_tombstone {
        if tomb_count as u64 >= PRINCIPAL_TOMBSTONE_COUNT_LIMIT {
            return Ok(false);
        }
        let tomb_bytes = tomb_bytes as u64;
        if tomb_bytes
            .checked_add(additional_bytes)
            .map(|t| t > PRINCIPAL_TOMBSTONE_BYTES_LIMIT)
            .unwrap_or(true)
        {
            return Ok(false);
        }
    }

    let combined_count = (inv_count as u64)
        .checked_add(tomb_count as u64)
        .context("principal combined count overflow")?;
    if combined_count >= PRINCIPAL_INVOCATION_COUNT_LIMIT {
        return Ok(false);
    }
    let combined_bytes = (inv_bytes as u64)
        .checked_add(tomb_bytes as u64)
        .and_then(|b| b.checked_add(additional_bytes))
        .context("principal combined bytes overflow")?;
    Ok(combined_bytes <= PRINCIPAL_INVOCATION_BYTES_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn options_json(max_turns: Option<u32>, timeout_ms: Option<u64>) -> String {
        serde_json::to_string(&serde_json::json!({
            "max_turns": max_turns,
            "timeout_ms": timeout_ms,
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn run_invocation_capacity_accounting() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let principal = "digest-owner".to_string();
        let now = 1_700_000_000_000i64;
        let mut last_id = Uuid::nil();
        for i in 0..SESSION_INVOCATION_COUNT_LIMIT {
            let id = Uuid::from_u128(i as u128 + 1);
            last_id = id;
            let outcome = db
                .accept_run_invocation(
                    id,
                    principal.clone(),
                    session,
                    options_json(None, None),
                    "opts".into(),
                    format!("content-{i}"),
                    None,
                    None,
                    now,
                )
                .await
                .unwrap();
            assert!(matches!(outcome, AcceptRunInvocationOutcome::Created(_)));
        }
        // 1025th is capacity exceeded with zero partial effect.
        let overflow_id = Uuid::from_u128(SESSION_INVOCATION_COUNT_LIMIT as u128 + 10);
        let outcome = db
            .accept_run_invocation(
                overflow_id,
                principal.clone(),
                session,
                options_json(None, None),
                "opts".into(),
                "content-overflow".into(),
                None,
                None,
                now,
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            AcceptRunInvocationOutcome::CapacityExceeded
        ));
        assert!(db.get_run_invocation(overflow_id).await.unwrap().is_none());

        // Exact replay at capacity still works and consumes no additional quota.
        let replay = db
            .accept_run_invocation(
                last_id,
                principal.clone(),
                session,
                options_json(None, None),
                "opts".into(),
                format!("content-{}", SESSION_INVOCATION_COUNT_LIMIT - 1),
                None,
                None,
                now,
            )
            .await
            .unwrap();
        assert!(matches!(replay, AcceptRunInvocationOutcome::ExactReplay(_)));

        // Differing content is conflict.
        let conflict = db
            .accept_run_invocation(
                last_id,
                principal.clone(),
                session,
                options_json(Some(1), None),
                "opts-changed".into(),
                "other".into(),
                Some(1),
                None,
                now,
            )
            .await
            .unwrap();
        assert!(matches!(
            conflict,
            AcceptRunInvocationOutcome::IdempotencyConflict
        ));

        // accounted_bytes is fixed base + fields.
        let row = db.get_run_invocation(last_id).await.unwrap().unwrap();
        let expected = accounted_bytes_for_invocation(
            &row.origin_principal_digest,
            &row.options_json,
            &row.options_digest,
            &row.content_digest,
            &row.state,
            None,
            None,
        )
        .unwrap();
        assert_eq!(row.accounted_bytes, expected);
        assert!(row.accounted_bytes >= RUN_INVOCATION_BASE_BYTES);

        // Expiry reclamation frees capacity in the same transaction.
        db.write(move |conn| {
            conn.execute(
                "UPDATE run_invocations SET
                    terminal_at_wall_ms = ?1,
                    expires_at_wall_ms = ?1,
                    terminal_reason = 'succeeded',
                    state = 'succeeded'
                 WHERE client_submission_id = ?2",
                params![now - 1, last_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let reclaimed = db
            .accept_run_invocation(
                overflow_id,
                principal,
                session,
                options_json(None, None),
                "opts".into(),
                "after-reclaim".into(),
                None,
                None,
                now,
            )
            .await
            .unwrap();
        assert!(matches!(reclaimed, AcceptRunInvocationOutcome::Created(_)));
    }

    #[tokio::test]
    async fn run_invocation_retention_session_delete() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let id = Uuid::new_v4();
        let now = 1_700_000_000_000i64;
        db.accept_run_invocation(
            id,
            "owner".into(),
            session,
            options_json(Some(2), Some(1000)),
            "opts".into(),
            "content".into(),
            Some(2),
            Some(1000),
            now,
        )
        .await
        .unwrap();

        // Active session deletion terminalizes without extending later.
        let n = db
            .terminalize_session_run_invocations(session, now + 5)
            .await
            .unwrap();
        assert_eq!(n, 1);
        let row = db.get_run_invocation(id).await.unwrap().unwrap();
        assert_eq!(row.state, "cancelled");
        assert_eq!(
            row.terminal_reason.as_deref(),
            Some("cancelled_session_deleted")
        );
        assert_eq!(row.terminal_at_wall_ms, Some(now + 5));
        assert_eq!(
            row.expires_at_wall_ms,
            Some(now + 5 + RUN_INVOCATION_RETENTION_MS)
        );

        // Second terminalize does not extend expiry.
        let n2 = db
            .terminalize_session_run_invocations(session, now + 50)
            .await
            .unwrap();
        assert_eq!(n2, 0);
        let row2 = db.get_run_invocation(id).await.unwrap().unwrap();
        assert_eq!(row2.expires_at_wall_ms, row.expires_at_wall_ms);

        // Just below expiry retains the row.
        let (inv_below, _) = db
            .cleanup_expired_run_invocations(row.expires_at_wall_ms.unwrap() - 1)
            .await
            .unwrap();
        assert_eq!(inv_below, 0);
        assert!(db.get_run_invocation(id).await.unwrap().is_some());

        // Cleanup at exactly expiry removes the row.
        let (inv, _) = db
            .cleanup_expired_run_invocations(row.expires_at_wall_ms.unwrap())
            .await
            .unwrap();
        assert_eq!(inv, 1);
        assert!(db.get_run_invocation(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn run_global_uuid_receipt_not_found_barrier() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let id = Uuid::new_v4();
        let now = 1_700_000_000_000i64;

        // Unknown-first status installs a global tombstone.
        let lookup = db
            .lookup_or_tombstone_run_invocation(id, "alice".into(), now, false)
            .await
            .unwrap();
        assert!(matches!(
            lookup,
            LookupRunInvocationOutcome::NotFoundInstalledTombstone
        ));

        // Late start from any principal is unavailable.
        let late = db
            .accept_run_invocation(
                id,
                "bob".into(),
                session,
                options_json(None, None),
                "opts".into(),
                "content".into(),
                None,
                None,
                now + 1,
            )
            .await
            .unwrap();
        assert!(matches!(
            late,
            AcceptRunInvocationOutcome::ClientSubmissionIdUnavailable
        ));

        // Owner cannot learn the tombstone claimant.
        let owner_lookup = db
            .lookup_or_tombstone_run_invocation(id, "owner".into(), now + 2, true)
            .await
            .unwrap();
        assert!(matches!(
            owner_lookup,
            LookupRunInvocationOutcome::NotFoundExistingTombstone
        ));
        assert!(db.get_run_invocation(id).await.unwrap().is_none());
    }

    #[test]
    fn accounted_bytes_base_charge() {
        let bytes =
            accounted_bytes_for_invocation("a", "{}", "d", "c", "accepted", None, None).unwrap();
        assert!(bytes >= RUN_INVOCATION_BASE_BYTES);
        let tomb = accounted_bytes_for_tombstone("alice").unwrap();
        assert!(tomb >= RUN_INVOCATION_BASE_BYTES);
    }

    #[tokio::test]
    async fn run_turn_reservation_exact() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let now = 1_700_000_000_000i64;

        // max_turns = 1
        let id1 = Uuid::from_u128(101);
        db.accept_run_invocation(
            id1,
            "owner".into(),
            session,
            options_json(Some(1), None),
            "opts".into(),
            "c1".into(),
            Some(1),
            None,
            now,
        )
        .await
        .unwrap();
        let r1 = db.reserve_run_invocation_turn(id1, now + 1).await.unwrap();
        assert!(matches!(r1, ReserveTurnOutcome::Reserved(_)));
        let row = match r1 {
            ReserveTurnOutcome::Reserved(r) => r,
            _ => unreachable!(),
        };
        assert_eq!(row.reserved_turns, 1);
        // N+1 before any further provider request → MaxTurnsExceeded
        let r2 = db.reserve_run_invocation_turn(id1, now + 2).await.unwrap();
        assert!(matches!(r2, ReserveTurnOutcome::MaxTurnsExceeded(_)));
        let row = db.get_run_invocation(id1).await.unwrap().unwrap();
        assert_eq!(row.state, "max_turns_exceeded");
        assert_eq!(row.reserved_turns, 1, "must not count N+1 reservation");
        assert_eq!(row.terminal_reason.as_deref(), Some("max_turns_exceeded"));

        // max_turns = 10_000 boundary: N reservations allowed
        let id_big = Uuid::from_u128(102);
        db.accept_run_invocation(
            id_big,
            "owner".into(),
            session,
            options_json(Some(2), None),
            "opts".into(),
            "c2".into(),
            Some(2),
            None,
            now,
        )
        .await
        .unwrap();
        assert!(matches!(
            db.reserve_run_invocation_turn(id_big, now + 3)
                .await
                .unwrap(),
            ReserveTurnOutcome::Reserved(_)
        ));
        assert!(matches!(
            db.reserve_run_invocation_turn(id_big, now + 4)
                .await
                .unwrap(),
            ReserveTurnOutcome::Reserved(_)
        ));
        assert!(matches!(
            db.reserve_run_invocation_turn(id_big, now + 5)
                .await
                .unwrap(),
            ReserveTurnOutcome::MaxTurnsExceeded(_)
        ));

        // Cancel before acceptance/reservation blocks further dispatch.
        let id_c = Uuid::from_u128(103);
        db.accept_run_invocation(
            id_c,
            "owner".into(),
            session,
            options_json(Some(5), None),
            "opts".into(),
            "c3".into(),
            Some(5),
            None,
            now,
        )
        .await
        .unwrap();
        db.update_run_invocation_state(
            id_c,
            1,
            "cancellation_requested",
            None,
            None,
            Some(true),
            Some("cancellation_requested"),
            None,
            now + 6,
        )
        .await
        .unwrap();
        assert!(matches!(
            db.reserve_run_invocation_turn(id_c, now + 7).await.unwrap(),
            ReserveTurnOutcome::CancelRequested(_)
        ));

        // Uncertain acceptance consumes reservation: no un-reserve on "failure".
        let id_u = Uuid::from_u128(104);
        db.accept_run_invocation(
            id_u,
            "owner".into(),
            session,
            options_json(Some(1), None),
            "opts".into(),
            "c4".into(),
            Some(1),
            None,
            now,
        )
        .await
        .unwrap();
        assert!(matches!(
            db.reserve_run_invocation_turn(id_u, now + 8).await.unwrap(),
            ReserveTurnOutcome::Reserved(_)
        ));
        // Simulate uncertain provider acceptance: do not free the reservation.
        // A retry attempt must not get another reservation.
        assert!(matches!(
            db.reserve_run_invocation_turn(id_u, now + 9).await.unwrap(),
            ReserveTurnOutcome::MaxTurnsExceeded(_)
        ));
    }

    #[tokio::test]
    async fn run_deadline_cancels_inflight_work() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let id = Uuid::new_v4();
        let now = 1_700_000_000_000i64;
        db.accept_run_invocation(
            id,
            "owner".into(),
            session,
            options_json(None, Some(1000)),
            "opts".into(),
            "content".into(),
            None,
            Some(1000),
            now,
        )
        .await
        .unwrap();
        // Reserve while "in flight"
        assert!(matches!(
            db.reserve_run_invocation_turn(id, now + 1).await.unwrap(),
            ReserveTurnOutcome::Reserved(_)
        ));
        // Injected deadline fires once.
        let first = db
            .fire_run_invocation_timeout(id, now + 1000)
            .await
            .unwrap();
        assert!(matches!(first, TimeoutFireOutcome::Committed(_)));
        let row = db.get_run_invocation(id).await.unwrap().unwrap();
        assert_eq!(row.state, "timeout_expired");
        assert_eq!(row.terminal_reason.as_deref(), Some("timeout_expired"));
        // Second fire is suppressed (exactly one TimeoutExpired).
        let second = db
            .fire_run_invocation_timeout(id, now + 2000)
            .await
            .unwrap();
        assert!(matches!(second, TimeoutFireOutcome::AlreadyTerminal(_)));
        let row2 = db.get_run_invocation(id).await.unwrap().unwrap();
        assert_eq!(row2.terminal_at_wall_ms, row.terminal_at_wall_ms);
        // Late success cannot replace timeout.
        let late = db
            .mark_run_invocation_terminal(id, "succeeded", "succeeded", now + 3000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(late.state, "timeout_expired");
        assert_eq!(late.terminal_reason.as_deref(), Some("timeout_expired"));
    }

    #[tokio::test]
    async fn run_restart_never_extends_expiry() {
        use crate::db::run_invocations::remaining_after_restart_for_test;

        // Pure remaining math (shared with daemon restart path).
        assert_eq!(
            remaining_after_restart_for_test(Some(1000), 500, 400),
            "clock_rollback"
        );
        assert_eq!(
            remaining_after_restart_for_test(Some(1000), 100, 2000),
            "expired"
        );
        assert_eq!(
            remaining_after_restart_for_test(Some(1000), 100, 100),
            "remaining:1000"
        );
        assert_eq!(
            remaining_after_restart_for_test(Some(1000), 100, 600),
            "remaining:500"
        );
        assert_eq!(remaining_after_restart_for_test(None, 0, 9999), "unbounded");

        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let id = Uuid::new_v4();
        let now = 1_700_000_000_000i64;
        db.accept_run_invocation(
            id,
            "owner".into(),
            session,
            options_json(None, Some(10_000)),
            "opts".into(),
            "content".into(),
            None,
            Some(10_000),
            now,
        )
        .await
        .unwrap();
        // Checkpoint consume 3s
        db.checkpoint_run_invocation_remaining(id, Some(7_000), now + 3_000)
            .await
            .unwrap();
        let row = db.get_run_invocation(id).await.unwrap().unwrap();
        assert_eq!(row.remaining_ms, Some(7_000));
        assert_eq!(row.last_observed_wall_ms, now + 3_000);
        // Wall rollback → clock_rollback_timed_out
        let rolled = db
            .checkpoint_run_invocation_remaining(id, Some(7_000), now + 1_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rolled.state, "clock_rollback_timed_out");
        assert_eq!(
            rolled.terminal_reason.as_deref(),
            Some("clock_rollback_timed_out")
        );
        // Cannot extend after terminal
        let again = db
            .checkpoint_run_invocation_remaining(id, Some(99_000), now + 50_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again.terminal_at_wall_ms, rolled.terminal_at_wall_ms);
        assert_eq!(again.remaining_ms, Some(0));
    }
}
