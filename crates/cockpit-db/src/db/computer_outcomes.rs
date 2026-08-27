//! Durable, provider-identity-keyed computer outcome receipts.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use super::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerOutcomeRow {
    pub session_id: String,
    pub delegation_id: String,
    pub provider_call_id: String,
    pub batch_index: u32,
    pub payload_digest: String,
    pub outcome_json: String,
}

impl Db {
    /// Atomically reserve an immutable action identity. `None` means this
    /// caller inserted the claim; `Some` is the pre-existing claim/outcome.
    pub async fn reserve_computer_outcome(
        &self,
        row: ComputerOutcomeRow,
    ) -> Result<Option<ComputerOutcomeRow>> {
        self.write(move |conn| {
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO computer_outcome_store (
                    session_id, delegation_id, provider_call_id, batch_index,
                    payload_digest, outcome_json, state, committed_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'claimed',
                    CAST(unixepoch('subsec') * 1000 AS INTEGER))",
                params![row.session_id, row.delegation_id, row.provider_call_id,
                    i64::from(row.batch_index), row.payload_digest, row.outcome_json],
            ).context("reserving durable computer outcome identity")?;
            if inserted == 1 { return Ok(None); }
            conn.query_row(
                "SELECT session_id, delegation_id, provider_call_id, batch_index,
                        payload_digest, outcome_json FROM computer_outcome_store
                 WHERE session_id=?1 AND delegation_id=?2 AND provider_call_id=?3 AND batch_index=?4",
                params![row.session_id, row.delegation_id, row.provider_call_id, i64::from(row.batch_index)],
                |r| Ok(ComputerOutcomeRow { session_id:r.get(0)?, delegation_id:r.get(1)?,
                    provider_call_id:r.get(2)?, batch_index:r.get(3)?, payload_digest:r.get(4)?, outcome_json:r.get(5)? })
            ).optional().context("loading competing computer outcome claim")
        }).await
    }

    pub async fn put_computer_outcome(&self, row: ComputerOutcomeRow) -> Result<()> {
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "INSERT INTO computer_outcome_store (
                    session_id, delegation_id, provider_call_id, batch_index,
                    payload_digest, outcome_json, state, committed_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'completed',
                    CAST(unixepoch('subsec') * 1000 AS INTEGER))
                 ON CONFLICT(session_id, delegation_id, provider_call_id, batch_index)
                 DO UPDATE SET outcome_json = excluded.outcome_json,
                               state = 'completed',
                               committed_at_unix_ms = excluded.committed_at_unix_ms
                 WHERE computer_outcome_store.payload_digest = excluded.payload_digest
                   AND computer_outcome_store.state = 'claimed'",
                    params![
                        row.session_id,
                        row.delegation_id,
                        row.provider_call_id,
                        i64::from(row.batch_index),
                        row.payload_digest,
                        row.outcome_json,
                    ],
                )
                .context("storing durable computer outcome")?;
            anyhow::ensure!(
                changed == 1,
                "computer outcome did not match its immutable identity claim"
            );
            Ok(())
        })
        .await
    }

    pub async fn computer_outcome(
        &self,
        session_id: String,
        delegation_id: String,
        provider_call_id: String,
        batch_index: u32,
    ) -> Result<Option<ComputerOutcomeRow>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT session_id, delegation_id, provider_call_id, batch_index,
                        payload_digest, outcome_json
                 FROM computer_outcome_store
                 WHERE session_id = ?1 AND delegation_id = ?2
                   AND provider_call_id = ?3 AND batch_index = ?4",
                params![
                    session_id,
                    delegation_id,
                    provider_call_id,
                    i64::from(batch_index)
                ],
                |row| {
                    Ok(ComputerOutcomeRow {
                        session_id: row.get(0)?,
                        delegation_id: row.get(1)?,
                        provider_call_id: row.get(2)?,
                        batch_index: row.get(3)?,
                        payload_digest: row.get(4)?,
                        outcome_json: row.get(5)?,
                    })
                },
            )
            .optional()
            .context("loading durable computer outcome")
        })
        .await
    }

    pub async fn computer_outcomes_for_delegation(
        &self,
        session_id: String,
        delegation_id: String,
    ) -> Result<Vec<ComputerOutcomeRow>> {
        self.read(move |conn| {
            let mut statement = conn
                .prepare(
                    "SELECT session_id, delegation_id, provider_call_id, batch_index,
                            payload_digest, outcome_json
                     FROM computer_outcome_store
                     WHERE session_id = ?1 AND delegation_id = ?2
                     ORDER BY provider_call_id, batch_index",
                )
                .context("preparing durable computer outcome scan")?;
            let rows = statement
                .query_map(params![session_id, delegation_id], |row| {
                    Ok(ComputerOutcomeRow {
                        session_id: row.get(0)?,
                        delegation_id: row.get(1)?,
                        provider_call_id: row.get(2)?,
                        batch_index: row.get(3)?,
                        payload_digest: row.get(4)?,
                        outcome_json: row.get(5)?,
                    })
                })
                .context("querying durable computer outcomes")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("decoding durable computer outcomes")
        })
        .await
    }
}
