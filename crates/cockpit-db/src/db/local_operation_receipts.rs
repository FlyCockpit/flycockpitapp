//! Durable owner/idempotency-key bindings for local daemon mutations.

use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};

use super::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalOperationBegin {
    Dispatch,
    Prepared,
    Terminal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalOperationSettlement {
    Pending,
    Terminal(String),
}

impl Db {
    pub async fn local_operation_settlement(
        &self,
        owner_digest: String,
        client_operation_id: String,
    ) -> Result<Option<LocalOperationSettlement>> {
        self.read(move |conn| {
            let result: Option<Option<String>> = conn
                .query_row(
                    "SELECT terminal_response_json FROM local_operation_receipts
                 WHERE owner_digest=?1 AND client_operation_id=?2",
                    params![owner_digest, client_operation_id],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(result.map(|response| match response {
                Some(response) => LocalOperationSettlement::Terminal(response),
                None => LocalOperationSettlement::Pending,
            }))
        })
        .await
    }

    pub async fn begin_local_operation(
        &self,
        owner_digest: String,
        client_operation_id: String,
        operation_kind: String,
        request_hash: [u8; 32],
    ) -> Result<LocalOperationBegin> {
        self.transaction(move |conn| {
            let existing: Option<(String, Vec<u8>, String, Option<String>)> = conn
                .query_row(
                    "SELECT operation_kind,request_hash,state,terminal_response_json
                     FROM local_operation_receipts
                     WHERE owner_digest=?1 AND client_operation_id=?2",
                    params![owner_digest, client_operation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            if let Some((kind, hash, state, response)) = existing {
                if kind != operation_kind || hash.as_slice() != request_hash {
                    bail!("client operation id was reused for a different request");
                }
                return Ok(match (state.as_str(), response) {
                    ("terminal", Some(response)) => LocalOperationBegin::Terminal(response),
                    _ => LocalOperationBegin::Prepared,
                });
            }
            let now = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "INSERT INTO local_operation_receipts
                 (owner_digest,client_operation_id,operation_kind,request_hash,state,
                  terminal_response_json,created_at_unix_ms,updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,'prepared',NULL,?5,?5)",
                params![
                    owner_digest,
                    client_operation_id,
                    operation_kind,
                    request_hash.as_slice(),
                    now
                ],
            )?;
            Ok(LocalOperationBegin::Dispatch)
        })
        .await
    }

    pub async fn finish_local_operation(
        &self,
        owner_digest: String,
        client_operation_id: String,
        request_hash: [u8; 32],
        terminal_response_json: String,
    ) -> Result<()> {
        self.write(move |conn| {
            let changed = conn.execute(
                "UPDATE local_operation_receipts
                 SET state='terminal',terminal_response_json=?4,updated_at_unix_ms=?5
                 WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3
                   AND state='prepared'",
                params![
                    owner_digest,
                    client_operation_id,
                    request_hash.as_slice(),
                    terminal_response_json,
                    chrono::Utc::now().timestamp_millis()
                ],
            )?;
            if changed != 1 {
                bail!("local operation lost its durable prepared intent");
            }
            Ok(())
        })
        .await
    }
}
