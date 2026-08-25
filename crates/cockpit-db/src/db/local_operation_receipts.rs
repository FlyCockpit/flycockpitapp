//! Durable owner/idempotency-key bindings for local daemon mutations.

use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};

use super::Db;

const EXECUTION_LEASE_MS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalOperationBegin {
    Dispatch { fencing_generation: i64 },
    Pending,
    TerminalSuccess(String),
    TerminalError(String),
    TerminalCancelled(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalOperationSettlement {
    Pending,
    TerminalSuccess(String),
    TerminalError(String),
    TerminalCancelled(String),
}

impl Db {
    pub async fn local_operation_settlement(
        &self,
        owner_digest: String,
        client_operation_id: String,
    ) -> Result<Option<LocalOperationSettlement>> {
        self.read(move |conn| {
            let result: Option<(String, Option<String>)> = conn.query_row(
                "SELECT state,terminal_outcome_json FROM local_operation_receipts WHERE owner_digest=?1 AND client_operation_id=?2",
                params![owner_digest, client_operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            Ok(result.map(|(state, outcome)| match (state.as_str(), outcome) {
                ("terminal_success", Some(json)) => LocalOperationSettlement::TerminalSuccess(json),
                ("terminal_error", Some(json)) => LocalOperationSettlement::TerminalError(json),
                ("terminal_cancelled", Some(json)) => LocalOperationSettlement::TerminalCancelled(json),
                _ => LocalOperationSettlement::Pending,
            }))
        }).await
    }

    pub async fn begin_local_operation(
        &self,
        owner_digest: String,
        client_operation_id: String,
        operation_kind: String,
        request_hash: [u8; 32],
    ) -> Result<LocalOperationBegin> {
        self.transaction(move |conn| {
            let now = chrono::Utc::now().timestamp_millis();
            let existing: Option<(String, Vec<u8>, String, Option<String>, i64, Option<i64>)> = conn.query_row(
                "SELECT operation_kind,request_hash,state,terminal_outcome_json,fencing_generation,execution_expires_at_unix_ms FROM local_operation_receipts WHERE owner_digest=?1 AND client_operation_id=?2",
                params![owner_digest, client_operation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            ).optional()?;
            if let Some((kind, hash, state, outcome, generation, _expires_at)) = existing {
                if kind != operation_kind || hash.as_slice() != request_hash { bail!("client operation id was reused for a different request"); }
                return match (state.as_str(), outcome) {
                    ("terminal_success", Some(json)) => Ok(LocalOperationBegin::TerminalSuccess(json)),
                    ("terminal_error", Some(json)) => Ok(LocalOperationBegin::TerminalError(json)),
                    ("terminal_cancelled", Some(json)) => Ok(LocalOperationBegin::TerminalCancelled(json)),
                    // Never time-take over an executing external operation.
                    // Its process may still be alive after a slow provider,
                    // keyring, or filesystem call. Only daemon startup, after
                    // singleton ownership is established, may settle work
                    // interrupted by the previous process.
                    ("executing", _) => Ok(LocalOperationBegin::Pending),
                    ("prepared", _) => {
                        let next = generation.checked_add(1).ok_or_else(|| anyhow::anyhow!("local operation fencing generation exhausted"))?;
                        let changed = conn.execute(
                            "UPDATE local_operation_receipts SET state='executing',fencing_generation=?3,execution_started_at_unix_ms=?4,execution_expires_at_unix_ms=?5,updated_at_unix_ms=?4 WHERE owner_digest=?1 AND client_operation_id=?2 AND fencing_generation=?6 AND state IN ('prepared','executing')",
                            params![owner_digest, client_operation_id, next, now, now.saturating_add(EXECUTION_LEASE_MS), generation],
                        )?;
                        if changed != 1 { return Ok(LocalOperationBegin::Pending); }
                        Ok(LocalOperationBegin::Dispatch { fencing_generation: next })
                    }
                    _ => bail!("local operation receipt has an invalid state/outcome"),
                };
            }
            conn.execute(
                "INSERT INTO local_operation_receipts (owner_digest,client_operation_id,operation_kind,request_hash,state,fencing_generation,execution_started_at_unix_ms,execution_expires_at_unix_ms,terminal_outcome_json,created_at_unix_ms,updated_at_unix_ms) VALUES (?1,?2,?3,?4,'executing',1,?5,?6,NULL,?5,?5)",
                params![owner_digest, client_operation_id, operation_kind, request_hash.as_slice(), now, now.saturating_add(EXECUTION_LEASE_MS)],
            )?;
            Ok(LocalOperationBegin::Dispatch { fencing_generation: 1 })
        }).await
    }

    /// Fail closed operations interrupted by a previous daemon process. This
    /// is called exactly once during startup recovery, before accepting a
    /// client, so it cannot fence live work in the current process. Domain
    /// journals that can prove a commit must reconcile before this call.
    pub async fn settle_interrupted_local_operations(&self) -> Result<u64> {
        self.write(|conn| {
            let now = chrono::Utc::now().timestamp_millis();
            let outcome = serde_json::json!({
                "code": "internal",
                "message": "the daemon restarted before this local operation produced a durable terminal receipt; the operation was not re-executed"
            })
            .to_string();
            Ok(conn.execute(
                "UPDATE local_operation_receipts
                 SET state='terminal_error',terminal_outcome_json=?1,
                     execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?2
                 WHERE state IN ('prepared','executing')",
                params![outcome, now],
            )? as u64)
        })
        .await
    }

    pub async fn finish_local_operation(
        &self,
        owner_digest: String,
        client_operation_id: String,
        request_hash: [u8; 32],
        fencing_generation: i64,
        terminal_state: String,
        terminal_outcome_json: String,
    ) -> Result<()> {
        self.transaction(move |conn| {
            if !matches!(terminal_state.as_str(), "terminal_success" | "terminal_error" | "terminal_cancelled") { bail!("invalid local operation terminal state"); }
            let existing: Option<(String, Option<String>, i64)> = conn.query_row(
                "SELECT state,terminal_outcome_json,fencing_generation FROM local_operation_receipts WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3",
                params![owner_digest, client_operation_id, request_hash.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;
            if let Some((state, outcome, _)) = &existing && state == &terminal_state && outcome.as_deref() == Some(&terminal_outcome_json) { return Ok(()); }
            if existing.as_ref().is_some_and(|(_, _, generation)| *generation != fencing_generation) { bail!("local operation execution lease was fenced by recovery"); }
            let changed = conn.execute(
                "UPDATE local_operation_receipts SET state=?5,terminal_outcome_json=?6,execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?7 WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3 AND fencing_generation=?4 AND state='executing'",
                params![owner_digest, client_operation_id, request_hash.as_slice(), fencing_generation, terminal_state, terminal_outcome_json, chrono::Utc::now().timestamp_millis()],
            )?;
            if changed != 1 { bail!("local operation lost its durable execution claim"); }
            Ok(())
        }).await
    }
}
