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
    /// Atomically store terminal zero-input receipts. Any existing identity,
    /// including an in-flight claim, wins and leaves this entire batch
    /// untouched. That prevents a local denial from falsely completing a
    /// physical dispatch owned by another coordinator.
    pub async fn store_terminal_computer_outcomes(
        &self,
        rows: Vec<ComputerOutcomeRow>,
    ) -> Result<Option<ComputerOutcomeRow>> {
        self.write(move |conn| {
            let transaction = conn
                .unchecked_transaction()
                .context("opening terminal computer-outcome transaction")?;
            for row in &rows {
                let existing = transaction
                    .query_row(
                        "SELECT session_id, delegation_id, provider_call_id, batch_index,
                                payload_digest, outcome_json FROM computer_outcome_store
                         WHERE session_id=?1 AND delegation_id=?2 AND provider_call_id=?3 AND batch_index=?4",
                        params![&row.session_id, &row.delegation_id, &row.provider_call_id, i64::from(row.batch_index)],
                        |r| Ok(ComputerOutcomeRow { session_id:r.get(0)?, delegation_id:r.get(1)?,
                            provider_call_id:r.get(2)?, batch_index:r.get(3)?, payload_digest:r.get(4)?, outcome_json:r.get(5)? }),
                    )
                    .optional()
                    .context("loading competing terminal computer outcome")?;
                if let Some(existing) = existing {
                    return Ok(Some(existing));
                }
            }
            for row in &rows {
                transaction.execute(
                    "INSERT INTO computer_outcome_store (
                        session_id, delegation_id, provider_call_id, batch_index,
                        payload_digest, outcome_json, state, committed_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'completed',
                        CAST(unixepoch('subsec') * 1000 AS INTEGER))",
                    params![&row.session_id, &row.delegation_id, &row.provider_call_id,
                        i64::from(row.batch_index), &row.payload_digest, &row.outcome_json],
                ).context("storing terminal computer outcome")?;
            }
            transaction
                .commit()
                .context("committing terminal computer outcomes")?;
            Ok(None)
        }).await
    }

    /// Atomically reserve a complete computer-action batch. `None` means this
    /// caller inserted every claim; `Some` is the pre-existing competing
    /// claim/outcome and leaves no partial claims from this batch behind.
    pub async fn reserve_computer_outcomes(
        &self,
        rows: Vec<ComputerOutcomeRow>,
    ) -> Result<Option<ComputerOutcomeRow>> {
        self.write(move |conn| {
            let transaction = conn
                .unchecked_transaction()
                .context("opening durable computer-outcome reservation transaction")?;
            for row in &rows {
                let existing = transaction
                    .query_row(
                "SELECT session_id, delegation_id, provider_call_id, batch_index,
                        payload_digest, outcome_json FROM computer_outcome_store
                 WHERE session_id=?1 AND delegation_id=?2 AND provider_call_id=?3 AND batch_index=?4",
                params![&row.session_id, &row.delegation_id, &row.provider_call_id, i64::from(row.batch_index)],
                |r| Ok(ComputerOutcomeRow { session_id:r.get(0)?, delegation_id:r.get(1)?,
                    provider_call_id:r.get(2)?, batch_index:r.get(3)?, payload_digest:r.get(4)?, outcome_json:r.get(5)? })
                    )
                    .optional()
                    .context("loading competing computer outcome claim")?;
                if let Some(existing) = existing {
                    return Ok(Some(existing));
                }
            }
            for row in &rows {
                let inserted = transaction.execute(
                    "INSERT OR IGNORE INTO computer_outcome_store (
                        session_id, delegation_id, provider_call_id, batch_index,
                        payload_digest, outcome_json, state, committed_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'claimed',
                        CAST(unixepoch('subsec') * 1000 AS INTEGER))",
                    params![&row.session_id, &row.delegation_id, &row.provider_call_id,
                        i64::from(row.batch_index), &row.payload_digest, &row.outcome_json],
                ).context("reserving durable computer outcome identity")?;
                if inserted != 1 {
                    let existing = transaction.query_row(
                        "SELECT session_id, delegation_id, provider_call_id, batch_index,
                                payload_digest, outcome_json FROM computer_outcome_store
                         WHERE session_id=?1 AND delegation_id=?2 AND provider_call_id=?3 AND batch_index=?4",
                        params![&row.session_id, &row.delegation_id, &row.provider_call_id, i64::from(row.batch_index)],
                        |r| Ok(ComputerOutcomeRow { session_id:r.get(0)?, delegation_id:r.get(1)?,
                            provider_call_id:r.get(2)?, batch_index:r.get(3)?, payload_digest:r.get(4)?, outcome_json:r.get(5)? })
                    ).optional().context("loading competing computer outcome claim")?;
                    return Ok(existing);
                }
            }
            transaction
                .commit()
                .context("committing durable computer-outcome batch reservation")?;
            Ok(None)
        }).await
    }

    /// Atomically complete a matching batch of prior `claimed` receipts after
    /// physical dispatch. A missing or competing receipt aborts the
    /// transaction before this batch is changed.
    pub async fn commit_computer_outcomes(
        &self,
        rows: Vec<ComputerOutcomeRow>,
    ) -> Result<Option<ComputerOutcomeRow>> {
        self.write(move |conn| {
            let transaction = conn
                .unchecked_transaction()
                .context("opening durable computer-outcome commit transaction")?;
            for row in &rows {
                let existing = transaction.query_row(
                    "SELECT session_id, delegation_id, provider_call_id, batch_index,
                            payload_digest, outcome_json, state FROM computer_outcome_store
                     WHERE session_id=?1 AND delegation_id=?2 AND provider_call_id=?3 AND batch_index=?4",
                    params![&row.session_id, &row.delegation_id, &row.provider_call_id, i64::from(row.batch_index)],
                    |r| Ok((ComputerOutcomeRow { session_id:r.get(0)?, delegation_id:r.get(1)?,
                        provider_call_id:r.get(2)?, batch_index:r.get(3)?, payload_digest:r.get(4)?, outcome_json:r.get(5)? }, r.get::<_, String>(6)?)),
                ).optional().context("loading computer outcome before terminal commit")?;
                let Some((existing, state)) = existing else {
                    anyhow::bail!("computer outcome batch is missing its reservation");
                };
                if existing.payload_digest != row.payload_digest || state != "claimed" {
                    return Ok(Some(existing));
                }
            }
            for row in &rows {
                let changed = transaction.execute(
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
                        &row.session_id,
                        &row.delegation_id,
                        &row.provider_call_id,
                        i64::from(row.batch_index),
                        &row.payload_digest,
                        &row.outcome_json,
                    ],
                )
                .context("storing durable computer outcome")?;
            anyhow::ensure!(
                changed == 1,
                "computer outcome did not match its immutable identity claim"
            );
            }
            transaction
                .commit()
                .context("committing durable computer-outcome batch result")?;
            Ok(None)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn row(batch_index: u32, digest: &str, outcome: &str) -> ComputerOutcomeRow {
        ComputerOutcomeRow {
            session_id: "session".to_string(),
            delegation_id: "delegation".to_string(),
            provider_call_id: "call".to_string(),
            batch_index,
            payload_digest: digest.to_string(),
            outcome_json: outcome.to_string(),
        }
    }

    #[tokio::test]
    async fn computer_outcome_batch_reservation_rolls_back_earlier_claims_on_conflict() {
        let db = Db::open_in_memory().expect("open in-memory database");
        let digest = "11".repeat(32);
        assert!(
            db.reserve_computer_outcomes(vec![row(1, &digest, "claimed-one")])
                .await
                .expect("reserve first identity")
                .is_none()
        );

        let competing = db
            .reserve_computer_outcomes(vec![
                row(0, &digest, "would-be-earlier-claim"),
                row(1, &digest, "competing-claim"),
            ])
            .await
            .expect("atomically inspect competing batch")
            .expect("batch must see existing index one");
        assert_eq!(competing.batch_index, 1);
        assert!(
            db.computer_outcome(
                "session".to_string(),
                "delegation".to_string(),
                "call".to_string(),
                0,
            )
            .await
            .expect("read earlier identity")
            .is_none()
        );
    }
}
