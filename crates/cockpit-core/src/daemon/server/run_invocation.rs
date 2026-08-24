//! Durable run-invocation acceptance barrier, status, cancel, and helpers.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::sessions::*;
use super::*;
use crate::db::run_invocations::{
    AcceptRunInvocationOutcome, LookupRunInvocationOutcome, RunInvocationRow,
};

/// Current wall time in epoch milliseconds (production path).
pub fn wall_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Stable content-free principal digest for invocation ownership.
pub fn principal_digest(principal: &ClientPrincipal) -> String {
    let tag = match principal {
        ClientPrincipal::Owner => "owner".to_string(),
        ClientPrincipal::Remote(remote) => format!("flycockpit:{}", remote.user_id),
    };
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    crate::intel::hex_lower(&hasher.finalize())
}

pub fn options_digest(options: &proto::RunInvocationOptions) -> String {
    let mut hasher = Sha256::new();
    match options.max_turns {
        None => hasher.update(b"max:none"),
        Some(n) => {
            hasher.update(b"max:some");
            hasher.update(n.to_le_bytes());
        }
    }
    match options.timeout_ms {
        None => hasher.update(b"to:none"),
        Some(n) => {
            hasher.update(b"to:some");
            hasher.update(n.to_le_bytes());
        }
    }
    match options.approval_mode {
        None => hasher.update(b"am:none"),
        Some(mode) => {
            hasher.update(b"am:some");
            hasher.update(mode.as_str().as_bytes());
        }
    }
    crate::intel::hex_lower(&hasher.finalize())
}

pub fn options_json(options: &proto::RunInvocationOptions) -> Result<String, ErrorPayload> {
    // Canonicalize through the shared serde shape so approval_mode is
    // immutable client input in options_json only (no daemon state field).
    serde_json::to_string(options).map_err(internal)
}

pub fn content_digest(wire_fingerprint: &str, options_digest: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(wire_fingerprint.as_bytes());
    hasher.update(b"|");
    hasher.update(options_digest.as_bytes());
    crate::intel::hex_lower(&hasher.finalize())
}

fn invocation_not_found() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::InvocationNotFound,
        message: "invocation not found".into(),
    }
}

fn row_to_status_v1(row: &RunInvocationRow) -> Result<proto::RunInvocationStatusV1, ErrorPayload> {
    let state = parse_lifecycle_state(&row.state)?;
    let terminal_reason = row
        .terminal_reason
        .as_deref()
        .map(parse_terminal_reason)
        .transpose()?;
    Ok(proto::RunInvocationStatusV1 {
        schema_version: proto::RunInvocationStatusV1::SCHEMA_VERSION,
        client_submission_id: row.client_submission_id,
        state,
        state_version: row.state_version,
        created_at_wall_ms: row.created_at_wall_ms,
        updated_at_wall_ms: row.updated_at_wall_ms,
        max_turns: row.max_turns,
        timeout_ms: row.timeout_ms,
        remaining_ms: row.remaining_ms,
        reserved_turns: row.reserved_turns,
        terminal_at_wall_ms: row.terminal_at_wall_ms,
        terminal_reason,
    })
}

pub(super) fn parse_lifecycle_state(
    raw: &str,
) -> Result<proto::RunInvocationLifecycleState, ErrorPayload> {
    use proto::RunInvocationLifecycleState::*;
    Ok(match raw {
        "accepted" => Accepted,
        "queued" => Queued,
        "dispatching" => Dispatching,
        "submission_unknown" => SubmissionUnknown,
        "running" => Running,
        "cancellation_requested" => CancellationRequested,
        "succeeded" => Succeeded,
        "failed" => Failed,
        "cancelled" => Cancelled,
        "timeout_expired" => TimeoutExpired,
        "max_turns_exceeded" => MaxTurnsExceeded,
        "clock_rollback_timed_out" => ClockRollbackTimedOut,
        "outcome_unknown" => OutcomeUnknown,
        other => {
            return Err(ErrorPayload {
                code: ErrorCode::Internal,
                message: format!("unknown run invocation state {other}"),
            });
        }
    })
}

fn parse_terminal_reason(raw: &str) -> Result<proto::RunInvocationTerminalReason, ErrorPayload> {
    use proto::RunInvocationTerminalReason::*;
    Ok(match raw {
        "succeeded" => Succeeded,
        "failed" => Failed,
        "cancelled" => Cancelled,
        "cancelled_session_deleted" => CancelledSessionDeleted,
        "timeout_expired" => TimeoutExpired,
        "max_turns_exceeded" => MaxTurnsExceeded,
        "clock_rollback_timed_out" => ClockRollbackTimedOut,
        "outcome_unknown" => OutcomeUnknown,
        other => {
            return Err(ErrorPayload {
                code: ErrorCode::Internal,
                message: format!("unknown run invocation terminal reason {other}"),
            });
        }
    })
}

/// Compute remaining budget after a restart using wall evidence.
/// Never extends expiry; rollback and forward jumps beyond remainder expire.
pub fn remaining_after_restart(
    persisted_remaining_ms: Option<u64>,
    last_observed_wall_ms: i64,
    now_wall_ms: i64,
) -> RemainingRestart {
    let Some(remaining) = persisted_remaining_ms else {
        return RemainingRestart::Unbounded;
    };
    if now_wall_ms < last_observed_wall_ms {
        return RemainingRestart::ClockRollback;
    }
    let elapsed = (now_wall_ms - last_observed_wall_ms) as u64;
    if elapsed >= remaining {
        return RemainingRestart::Expired;
    }
    RemainingRestart::Remaining(remaining - elapsed)
}

/// Row-aware restart reconciliation. A bounded oversized FCM2 invocation is
/// persisted in phase one with no remaining budget until phase two atomically
/// materializes its source/event/artifacts; treating that durable shape as the
/// ordinary `None = unbounded` case would hide the queued-clock distinction.
pub fn remaining_after_restart_for_row(
    row: &RunInvocationRow,
    now_wall_ms: i64,
) -> RemainingRestart {
    if crate::db::run_invocations::timeout_clock_is_deferred(row) {
        RemainingRestart::ClockNotStarted
    } else {
        remaining_after_restart(row.remaining_ms, row.last_observed_wall_ms, now_wall_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemainingRestart {
    /// Phase-one accepted oversized FCM2 invocation with a configured timeout
    /// whose countdown has not begun. This is neither unbounded nor expired.
    ClockNotStarted,
    Unbounded,
    Remaining(u64),
    Expired,
    ClockRollback,
}

pub(super) async fn accept_run_if_marked(
    ctx: &Arc<DaemonContext>,
    principal: &ClientPrincipal,
    session_id: Uuid,
    client_submission_id: Uuid,
    wire_fingerprint: &str,
    options: &proto::RunInvocationOptions,
    now_wall_ms: i64,
) -> std::result::Result<RunInvocationRow, ErrorPayload> {
    let origin = principal_digest(principal);
    let opts_digest = options_digest(options);
    let content = content_digest(wire_fingerprint, &opts_digest);
    let options_json = options_json(options)?;
    let outcome = ctx
        .db
        .accept_run_invocation(
            client_submission_id,
            origin,
            session_id,
            options_json,
            opts_digest,
            content,
            options.max_turns,
            options.timeout_ms,
            now_wall_ms,
        )
        .await
        .map_err(internal)?;
    match outcome {
        AcceptRunInvocationOutcome::Created(row) | AcceptRunInvocationOutcome::ExactReplay(row) => {
            Ok(row)
        }
        AcceptRunInvocationOutcome::IdempotencyConflict => Err(ErrorPayload {
            code: ErrorCode::IdempotencyConflict,
            message: "client_submission_id was already used with different content".into(),
        }),
        AcceptRunInvocationOutcome::ClientSubmissionIdUnavailable => Err(ErrorPayload {
            code: ErrorCode::ClientSubmissionIdUnavailable,
            message: "client_submission_id is unavailable".into(),
        }),
        AcceptRunInvocationOutcome::CapacityExceeded => Err(ErrorPayload {
            code: ErrorCode::InvocationCapacityExceeded,
            message: "invocation capacity exceeded".into(),
        }),
    }
}

pub(super) async fn handle_get_run_invocation_status(
    state: &MutableClientState,
    ctx: &Arc<DaemonContext>,
    client_submission_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    handle_get_run_invocation_status_for(&state.principal, ctx, client_submission_id, wall_ms_now())
        .await
}

pub(super) async fn handle_get_run_invocation_status_shared(
    shared: &SharedClientState,
    ctx: &Arc<DaemonContext>,
    client_submission_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    handle_get_run_invocation_status_for(
        &shared.principal,
        ctx,
        client_submission_id,
        wall_ms_now(),
    )
    .await
}

async fn handle_get_run_invocation_status_for(
    principal: &ClientPrincipal,
    ctx: &Arc<DaemonContext>,
    client_submission_id: Uuid,
    now_wall_ms: i64,
) -> std::result::Result<Response, ErrorPayload> {
    let digest = principal_digest(principal);
    let is_owner = principal.is_owner();
    let outcome = ctx
        .db
        .lookup_or_tombstone_run_invocation(client_submission_id, digest, now_wall_ms, is_owner)
        .await
        .map_err(internal)?;
    match outcome {
        LookupRunInvocationOutcome::Found(row) => {
            // Refresh remaining budget view on read for active timed runs.
            let row = reconcile_remaining_on_lookup(ctx, *row, now_wall_ms).await?;
            Ok(Response::RunInvocationStatus {
                status: row_to_status_v1(&row)?,
            })
        }
        LookupRunInvocationOutcome::NotFoundInstalledTombstone
        | LookupRunInvocationOutcome::NotFoundExistingTombstone => Err(invocation_not_found()),
        LookupRunInvocationOutcome::LookupBusy => Err(ErrorPayload {
            code: ErrorCode::InvocationLookupBusy,
            message: "invocation lookup busy".into(),
        }),
    }
}

async fn reconcile_remaining_on_lookup(
    ctx: &Arc<DaemonContext>,
    row: RunInvocationRow,
    now_wall_ms: i64,
) -> std::result::Result<RunInvocationRow, ErrorPayload> {
    if row.terminal_at_wall_ms.is_some() || row.timeout_ms.is_none() {
        return Ok(row);
    }
    match remaining_after_restart_for_row(&row, now_wall_ms) {
        RemainingRestart::ClockNotStarted => Ok(row),
        RemainingRestart::Unbounded => Ok(row),
        RemainingRestart::Remaining(rem) => {
            if Some(rem) == row.remaining_ms && now_wall_ms == row.last_observed_wall_ms {
                return Ok(row);
            }
            ctx.db
                .checkpoint_run_invocation_remaining(
                    row.client_submission_id,
                    Some(rem),
                    now_wall_ms,
                )
                .await
                .map_err(internal)?
                .ok_or_else(invocation_not_found)
        }
        RemainingRestart::Expired => ctx
            .db
            .update_run_invocation_state(
                row.client_submission_id,
                row.state_version,
                "timeout_expired",
                Some(0),
                None,
                None,
                None,
                Some("timeout_expired"),
                now_wall_ms,
            )
            .await
            .map_err(internal)?
            .ok_or_else(invocation_not_found),
        RemainingRestart::ClockRollback => ctx
            .db
            .update_run_invocation_state(
                row.client_submission_id,
                row.state_version,
                "clock_rollback_timed_out",
                Some(0),
                None,
                None,
                None,
                Some("clock_rollback_timed_out"),
                now_wall_ms,
            )
            .await
            .map_err(internal)?
            .ok_or_else(invocation_not_found),
    }
}

pub(super) async fn handle_cancel_run_invocation(
    state: &MutableClientState,
    ctx: &Arc<DaemonContext>,
    client_submission_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    let now = wall_ms_now();
    let digest = principal_digest(&state.principal);
    let is_owner = state.principal.is_owner();
    let outcome = ctx
        .db
        .lookup_or_tombstone_run_invocation(client_submission_id, digest, now, is_owner)
        .await
        .map_err(internal)?;
    let row = match outcome {
        LookupRunInvocationOutcome::Found(row) => *row,
        LookupRunInvocationOutcome::NotFoundInstalledTombstone
        | LookupRunInvocationOutcome::NotFoundExistingTombstone => {
            return Err(invocation_not_found());
        }
        LookupRunInvocationOutcome::LookupBusy => {
            return Err(ErrorPayload {
                code: ErrorCode::InvocationLookupBusy,
                message: "invocation lookup busy".into(),
            });
        }
    };

    // Idempotent stored cancel results.
    if let Some(stored) = row.cancel_result.as_deref() {
        let outcome = match stored {
            "cancellation_requested" => proto::RunInvocationCancelOutcome::CancellationRequested,
            "already_cancelled" => proto::RunInvocationCancelOutcome::AlreadyCancelled,
            "already_terminal" => proto::RunInvocationCancelOutcome::AlreadyTerminal,
            other => {
                return Err(ErrorPayload {
                    code: ErrorCode::Internal,
                    message: format!("unknown cancel_result {other}"),
                });
            }
        };
        return Ok(Response::RunInvocationCancelResult {
            result: proto::RunInvocationCancelResultV1 {
                schema_version: proto::RunInvocationCancelResultV1::SCHEMA_VERSION,
                client_submission_id,
                outcome,
                state: parse_lifecycle_state(&row.state)?,
                state_version: row.state_version,
            },
        });
    }

    if row.terminal_at_wall_ms.is_some() {
        let updated = ctx
            .db
            .update_run_invocation_state(
                client_submission_id,
                row.state_version,
                &row.state,
                row.remaining_ms,
                None,
                Some(true),
                Some("already_terminal"),
                row.terminal_reason.as_deref(),
                now,
            )
            .await
            .map_err(internal)?
            .ok_or_else(invocation_not_found)?;
        return Ok(Response::RunInvocationCancelResult {
            result: proto::RunInvocationCancelResultV1 {
                schema_version: proto::RunInvocationCancelResultV1::SCHEMA_VERSION,
                client_submission_id,
                outcome: proto::RunInvocationCancelOutcome::AlreadyTerminal,
                state: parse_lifecycle_state(&updated.state)?,
                state_version: updated.state_version,
            },
        });
    }

    // First cancel: request cancellation cutoff.
    let updated = ctx
        .db
        .update_run_invocation_state(
            client_submission_id,
            row.state_version,
            "cancellation_requested",
            row.remaining_ms,
            None,
            Some(true),
            Some("cancellation_requested"),
            None,
            now,
        )
        .await
        .map_err(internal)?
        .ok_or_else(invocation_not_found)?;

    // Best-effort live cancel of the owning session worker.
    if let Some(handle) = ctx.registry.live_handle(updated.session_id) {
        let _ = handle.send_work(SessionWork::Cancel).await;
    }

    Ok(Response::RunInvocationCancelResult {
        result: proto::RunInvocationCancelResultV1 {
            schema_version: proto::RunInvocationCancelResultV1::SCHEMA_VERSION,
            client_submission_id,
            outcome: proto::RunInvocationCancelOutcome::CancellationRequested,
            state: parse_lifecycle_state(&updated.state)?,
            state_version: updated.state_version,
        },
    })
}

pub use crate::db::run_invocations::{ReserveTurnOutcome, TimeoutFireOutcome};

/// Atomically reserve one provider-dispatch turn.
#[allow(dead_code)]
pub async fn reserve_turn(
    db: &crate::db::Db,
    client_submission_id: Uuid,
    now_wall_ms: i64,
) -> std::result::Result<ReserveTurnOutcome, ErrorPayload> {
    db.reserve_run_invocation_turn(client_submission_id, now_wall_ms)
        .await
        .map_err(internal)
}

/// Mark a run invocation terminal (cancel-first aware).
#[allow(dead_code)]
pub async fn mark_run_terminal(
    db: &crate::db::Db,
    client_submission_id: Uuid,
    reason: proto::RunInvocationTerminalReason,
    now_wall_ms: i64,
) -> std::result::Result<Option<RunInvocationRow>, ErrorPayload> {
    db.mark_run_invocation_terminal(
        client_submission_id,
        reason.as_str(),
        reason.to_lifecycle_state().as_str(),
        now_wall_ms,
    )
    .await
    .map_err(internal)
}

/// Commit exactly one TimeoutExpired and cancel the live deadline token.
/// Late completions after this call observe an already-terminal record.
#[allow(dead_code)]
pub async fn fire_timeout_and_cancel(
    db: &crate::db::Db,
    client_submission_id: Uuid,
    cancel: &tokio_util::sync::CancellationToken,
    now_wall_ms: i64,
) -> std::result::Result<TimeoutFireOutcome, ErrorPayload> {
    // Cancel first so in-flight work begins reaping immediately; the durable
    // TimeoutExpired transition is still exactly-once via the DB CAS.
    cancel.cancel();
    db.fire_run_invocation_timeout(client_submission_id, now_wall_ms)
        .await
        .map_err(internal)
}

/// Spawn a deadline watcher. Uses `sleep` only for production remaining budget;
/// tests call [`fire_timeout_and_cancel`] directly with an injected wall clock.
#[allow(dead_code)]
pub fn spawn_deadline_watcher(
    db: crate::db::Db,
    client_submission_id: Uuid,
    remaining_ms: u64,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let sleep = tokio::time::sleep(std::time::Duration::from_millis(remaining_ms));
        tokio::pin!(sleep);
        tokio::select! {
            _ = cancel.cancelled() => {
                // External cancel (user/session) owns terminalization.
            }
            _ = &mut sleep => {
                let now = wall_ms_now();
                let _ = fire_timeout_and_cancel(&db, client_submission_id, &cancel, now).await;
            }
        }
    })
}

/// Checkpoint remaining budget before a side effect (queue/dispatch/terminal).
#[allow(dead_code)]
pub async fn checkpoint_before_side_effect(
    db: &crate::db::Db,
    client_submission_id: Uuid,
    now_wall_ms: i64,
) -> std::result::Result<Option<RunInvocationRow>, ErrorPayload> {
    let Some(row) = db
        .get_run_invocation(client_submission_id)
        .await
        .map_err(internal)?
    else {
        return Ok(None);
    };
    if row.terminal_at_wall_ms.is_some() || row.timeout_ms.is_none() {
        return Ok(Some(row));
    }
    match remaining_after_restart_for_row(&row, now_wall_ms) {
        RemainingRestart::ClockNotStarted => Ok(Some(row)),
        RemainingRestart::Unbounded => Ok(Some(row)),
        RemainingRestart::Remaining(rem) => db
            .checkpoint_run_invocation_remaining(client_submission_id, Some(rem), now_wall_ms)
            .await
            .map_err(internal),
        RemainingRestart::Expired => {
            let _ = db
                .fire_run_invocation_timeout(client_submission_id, now_wall_ms)
                .await
                .map_err(internal)?;
            db.get_run_invocation(client_submission_id)
                .await
                .map_err(internal)
        }
        RemainingRestart::ClockRollback => {
            let _ = db
                .update_run_invocation_state(
                    client_submission_id,
                    row.state_version,
                    "clock_rollback_timed_out",
                    Some(0),
                    None,
                    None,
                    None,
                    Some("clock_rollback_timed_out"),
                    now_wall_ms,
                )
                .await
                .map_err(internal)?;
            db.get_run_invocation(client_submission_id)
                .await
                .map_err(internal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::db::run_invocations::{ReserveTurnOutcome, TimeoutFireOutcome};

    #[test]
    fn run_remaining_time_checkpoint() {
        // Same wall time preserves remainder.
        assert_eq!(
            remaining_after_restart(Some(1000), 100, 100),
            RemainingRestart::Remaining(1000)
        );
        // Monotonic consumption.
        assert_eq!(
            remaining_after_restart(Some(1000), 100, 400),
            RemainingRestart::Remaining(700)
        );
        // Forward jump beyond remainder expires.
        assert_eq!(
            remaining_after_restart(Some(1000), 100, 2000),
            RemainingRestart::Expired
        );
        // Exact remainder boundary expires.
        assert_eq!(
            remaining_after_restart(Some(1000), 100, 1100),
            RemainingRestart::Expired
        );
        // Rollback never extends.
        assert_eq!(
            remaining_after_restart(Some(1000), 500, 400),
            RemainingRestart::ClockRollback
        );
        // Unbounded.
        assert_eq!(
            remaining_after_restart(None, 100, 999_999),
            RemainingRestart::Unbounded
        );
        // Multiple restarts: recompute from last checkpoint.
        let first = remaining_after_restart(Some(10_000), 0, 2_000);
        assert_eq!(first, RemainingRestart::Remaining(8_000));
        let RemainingRestart::Remaining(after_first) = first else {
            panic!();
        };
        assert_eq!(
            remaining_after_restart(Some(after_first), 2_000, 5_000),
            RemainingRestart::Remaining(5_000)
        );
    }

    #[test]
    fn options_digest_is_stable_and_content_sensitive() {
        let a = proto::RunInvocationOptions {
            max_turns: None,
            timeout_ms: None,
            approval_mode: None,
        };
        let b = proto::RunInvocationOptions {
            max_turns: Some(1),
            timeout_ms: None,
            approval_mode: None,
        };
        assert_eq!(options_digest(&a), options_digest(&a));
        assert_ne!(options_digest(&a), options_digest(&b));
        // Zero is distinct from None (unbounded).
        let zero = proto::RunInvocationOptions {
            max_turns: Some(0),
            timeout_ms: None,
            approval_mode: None,
        };
        assert_ne!(options_digest(&a), options_digest(&zero));
        // approval_mode is part of the immutable client digest.
        let yolo = proto::RunInvocationOptions {
            max_turns: None,
            timeout_ms: None,
            approval_mode: Some(proto::ApprovalMode::Yolo),
        };
        let manual = proto::RunInvocationOptions {
            max_turns: None,
            timeout_ms: None,
            approval_mode: Some(proto::ApprovalMode::Manual),
        };
        assert_ne!(options_digest(&a), options_digest(&yolo));
        assert_ne!(options_digest(&yolo), options_digest(&manual));
        assert!(options_json(&yolo).unwrap().contains("yolo"));
    }

    #[tokio::test]
    async fn concurrent_run_modes_are_isolated() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let manual_id = Uuid::from_u128(0x11);
        let yolo_id = Uuid::from_u128(0x22);
        let now = 1_700_000_000_000i64;
        let origin = principal_digest(&ClientPrincipal::Owner);

        let manual_opts = proto::RunInvocationOptions {
            max_turns: None,
            timeout_ms: None,
            approval_mode: Some(proto::ApprovalMode::Manual),
        };
        let yolo_opts = proto::RunInvocationOptions {
            max_turns: None,
            timeout_ms: None,
            approval_mode: Some(proto::ApprovalMode::Yolo),
        };
        for (id, opts) in [(manual_id, &manual_opts), (yolo_id, &yolo_opts)] {
            let oj = options_json(opts).unwrap();
            let od = options_digest(opts);
            let content = content_digest(&format!("text:{id}"), &od);
            let outcome = db
                .accept_run_invocation(
                    id,
                    origin.clone(),
                    session,
                    oj,
                    od,
                    content,
                    None,
                    None,
                    now,
                )
                .await
                .unwrap();
            assert!(matches!(outcome, AcceptRunInvocationOutcome::Created(_)));
        }

        // Parked side by side: each durable record retains its own mode.
        let manual_row = db.get_run_invocation(manual_id).await.unwrap().unwrap();
        let yolo_row = db.get_run_invocation(yolo_id).await.unwrap().unwrap();
        let manual_parsed: proto::RunInvocationOptions =
            serde_json::from_str(&manual_row.options_json).unwrap();
        let yolo_parsed: proto::RunInvocationOptions =
            serde_json::from_str(&yolo_row.options_json).unwrap();
        assert_eq!(
            manual_parsed.approval_mode,
            Some(proto::ApprovalMode::Manual)
        );
        assert_eq!(yolo_parsed.approval_mode, Some(proto::ApprovalMode::Yolo));
        assert_ne!(manual_row.options_digest, yolo_row.options_digest);
        // Status exposes bounds columns only — no duplicate approval_mode state field.
        assert!(manual_row.max_turns.is_none());
        assert!(!manual_row.options_json.is_empty());
    }

    #[tokio::test]
    async fn queued_mode_survives_restart() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let id = Uuid::from_u128(0x33);
        let now = 1_700_000_000_000i64;
        let opts = proto::RunInvocationOptions {
            max_turns: Some(2),
            timeout_ms: Some(60_000),
            approval_mode: Some(proto::ApprovalMode::Auto),
        };
        let oj = options_json(&opts).unwrap();
        let od = options_digest(&opts);
        db.accept_run_invocation(
            id,
            principal_digest(&ClientPrincipal::Owner),
            session,
            oj.clone(),
            od.clone(),
            content_digest("wire", &od),
            opts.max_turns,
            opts.timeout_ms,
            now,
        )
        .await
        .unwrap();

        // Simulate restart: re-read durable options; they must be unchanged.
        let row = db.get_run_invocation(id).await.unwrap().unwrap();
        assert_eq!(row.options_json, oj);
        assert_eq!(row.options_digest, od);
        let parsed: proto::RunInvocationOptions = serde_json::from_str(&row.options_json).unwrap();
        assert_eq!(parsed.approval_mode, Some(proto::ApprovalMode::Auto));
        assert_eq!(parsed.max_turns, Some(2));
        // Restart remaining math does not touch options.
        let rem = remaining_after_restart(row.remaining_ms, row.last_observed_wall_ms, now + 1_000);
        assert_eq!(rem, RemainingRestart::Remaining(59_000));
        let after = db.get_run_invocation(id).await.unwrap().unwrap();
        let after_parsed: proto::RunInvocationOptions =
            serde_json::from_str(&after.options_json).unwrap();
        assert_eq!(after_parsed.approval_mode, Some(proto::ApprovalMode::Auto));
    }

    #[tokio::test]
    async fn cancelled_mode_does_not_leak() {
        let db = Db::open_in_memory().unwrap();
        let session_id = Uuid::new_v4();
        let id = Uuid::from_u128(0x44);
        let now = 1_700_000_000_000i64;
        let opts = proto::RunInvocationOptions {
            max_turns: None,
            timeout_ms: None,
            approval_mode: Some(proto::ApprovalMode::Yolo),
        };
        let od = options_digest(&opts);
        db.accept_run_invocation(
            id,
            principal_digest(&ClientPrincipal::Owner),
            session_id,
            options_json(&opts).unwrap(),
            od.clone(),
            content_digest("cancel-me", &od),
            None,
            None,
            now,
        )
        .await
        .unwrap();

        // Cancel terminalizes only this invocation; options stay with the record
        // and do not migrate to a later unbounded message (no run marker).
        db.mark_run_invocation_terminal(id, "cancelled", "cancelled", now + 10)
            .await
            .unwrap();
        let row = db.get_run_invocation(id).await.unwrap().unwrap();
        assert_eq!(row.state, "cancelled");
        let parsed: proto::RunInvocationOptions = serde_json::from_str(&row.options_json).unwrap();
        assert_eq!(parsed.approval_mode, Some(proto::ApprovalMode::Yolo));

        // A fresh invocation without override is independent.
        let next = Uuid::from_u128(0x45);
        let none_opts = proto::RunInvocationOptions::default();
        let nod = options_digest(&none_opts);
        db.accept_run_invocation(
            next,
            principal_digest(&ClientPrincipal::Owner),
            session_id,
            options_json(&none_opts).unwrap(),
            nod.clone(),
            content_digest("next", &nod),
            None,
            None,
            now + 20,
        )
        .await
        .unwrap();
        let next_row = db.get_run_invocation(next).await.unwrap().unwrap();
        let next_parsed: proto::RunInvocationOptions =
            serde_json::from_str(&next_row.options_json).unwrap();
        assert_eq!(next_parsed.approval_mode, None);
        assert_ne!(next_row.options_digest, row.options_digest);
    }

    #[tokio::test]
    async fn run_turn_reservation_exact() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let id = Uuid::from_u128(1);
        let now = 1_700_000_000_000i64;
        db.accept_run_invocation(
            id,
            principal_digest(&ClientPrincipal::Owner),
            session,
            serde_json::to_string(&serde_json::json!({"max_turns":1,"timeout_ms":null})).unwrap(),
            "opts".into(),
            "content".into(),
            Some(1),
            None,
            now,
        )
        .await
        .unwrap();
        let first = reserve_turn(&db, id, now + 1).await.unwrap();
        assert!(matches!(first, ReserveTurnOutcome::Reserved(_)));
        // Uncertain acceptance consumed the only reservation; no retry.
        let second = reserve_turn(&db, id, now + 2).await.unwrap();
        assert!(matches!(second, ReserveTurnOutcome::MaxTurnsExceeded(_)));
        let row = db.get_run_invocation(id).await.unwrap().unwrap();
        assert_eq!(row.reserved_turns, 1);
        assert_eq!(row.state, "max_turns_exceeded");
    }

    #[tokio::test]
    async fn run_deadline_cancels_inflight_work() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let id = Uuid::new_v4();
        let now = 1_700_000_000_000i64;
        db.accept_run_invocation(
            id,
            principal_digest(&ClientPrincipal::Owner),
            session,
            serde_json::to_string(&serde_json::json!({"max_turns":null,"timeout_ms":50})).unwrap(),
            "opts".into(),
            "content".into(),
            None,
            Some(50),
            now,
        )
        .await
        .unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        // Simulate hung provider: cancel token not yet cancelled.
        assert!(!cancel.is_cancelled());
        let outcome = fire_timeout_and_cancel(&db, id, &cancel, now + 50)
            .await
            .unwrap();
        assert!(matches!(outcome, TimeoutFireOutcome::Committed(_)));
        assert!(cancel.is_cancelled(), "deadline owns cancel token");
        // Exactly one TimeoutExpired
        let again = fire_timeout_and_cancel(&db, id, &cancel, now + 100)
            .await
            .unwrap();
        assert!(matches!(again, TimeoutFireOutcome::AlreadyTerminal(_)));
        // Late success suppressed
        let late = mark_run_terminal(
            &db,
            id,
            proto::RunInvocationTerminalReason::Succeeded,
            now + 200,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(late.state, "timeout_expired");
    }

    #[tokio::test]
    async fn run_timeout_starts_at_durable_acceptance() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let id = Uuid::new_v4();
        let now = 1_700_000_000_000i64;
        let seven_days_ms = 7 * 24 * 60 * 60 * 1000u64;
        db.accept_run_invocation(
            id,
            principal_digest(&ClientPrincipal::Owner),
            session,
            serde_json::to_string(
                &serde_json::json!({"max_turns":null,"timeout_ms":seven_days_ms}),
            )
            .unwrap(),
            "opts".into(),
            "content".into(),
            None,
            Some(seven_days_ms),
            now,
        )
        .await
        .unwrap();
        // Queued time alone (no provider request) consumes budget via checkpoint.
        let queued_wait = 60_000u64;
        let after = checkpoint_before_side_effect(&db, id, now + queued_wait as i64)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.remaining_ms, Some(seven_days_ms - queued_wait));
        assert_eq!(after.state, "accepted"); // still no provider dispatch
        // Expire entirely while still queued.
        let expired = checkpoint_before_side_effect(&db, id, now + seven_days_ms as i64 + 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expired.state, "timeout_expired");
        assert_eq!(
            expired.reserved_turns, 0,
            "no provider reservation occurred"
        );
    }
}
