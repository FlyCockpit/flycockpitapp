//! The single DB opener for the offline `cockpit doctor` diagnostic. When no
//! daemon is running (or one failed to boot), doctor opens the existing session
//! DB read-only to report SQLite and migration-ledger health. A running daemon's
//! doctor RPC does not use this — it passes its already-open `ctx.db` handle.
use crate::db::Db;

/// Open the default-path session DB for the offline doctor diagnostic. Returns
/// the open `Result` so the caller can render `openability: FAILED (<reason>)`
/// (or a schema-rejection line) when the open fails, which is exactly what
/// `reports_unopenable_database` / `reports_amended_migration` assert.
pub(crate) fn open_diagnostic_db() -> anyhow::Result<Db> {
    Db::open_default_read_only_diagnostic()
}

/// Read-only failed-call projection for the hidden diagnostic worker.
/// Uses the same default-path opener as offline `doctor`; never starts a daemon.
pub async fn failed_tool_calls_json(
    filter: crate::db::tool_calls::FailedCallsFilter,
) -> anyhow::Result<String> {
    let db = open_diagnostic_db()?;
    let rows = db.list_failed_tool_calls(filter).await?;
    let calls: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let (kind, stage) = row.recovery.raw_db_fields();
            serde_json::json!({
                "event_id": row.event_id,
                "session_id": row.session_id,
                "timestamp": row.timestamp,
                "model": row.model,
                "provider": row.provider,
                "project_id": row.project_id,
                "agent": row.agent,
                "tool": row.tool,
                "path": row.path,
                "hard_fail": row.hard_fail,
                "shape_fingerprint": row.shape_fingerprint,
                "recovery_kind": kind,
                "recovery_stage": stage,
                "recovery_unknown": row.recovery.is_unknown(),
                "original_input": row.original_input_json,
                "wire_input": row.wire_input_json,
                "output": row.output,
                "truncated": row.truncated,
                "duration_ms": row.duration_ms,
            })
        })
        .collect();
    Ok(serde_json::to_string(&calls)?)
}
