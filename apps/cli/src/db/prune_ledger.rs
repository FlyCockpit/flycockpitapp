//! `prune_ledger` reads/writes — session resume prune-ledger
//! (implementation note).
//!
//! One row per session holding the JSON-serialized
//! [`crate::engine::prune::PruneLedger`] — the durable twin of the
//! in-memory prune state (`current_elided_ids` + the driver's
//! `prune_watermark`). Persisted at every inference boundary and on every
//! `/prune` (migration `0026`) so a resumed session can rebuild its
//! transcript and re-prune it to the form the model last saw, surviving
//! even an unclean daemon kill. `session_events` + `tool_call_events`
//! remain the single source of truth for the conversation *content*; this
//! is only the small delta that reproduces the *pruned* form.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;
use crate::engine::prune::PruneLedger;

impl Db {
    /// Persist (upsert) the prune ledger for `session_id`. Idempotent on
    /// the session id, so persisting again at the next inference boundary
    /// replaces the prior ledger with the current pruned state.
    pub fn save_prune_ledger(&self, session_id: Uuid, ledger: &PruneLedger) -> Result<()> {
        let ledger_json = serde_json::to_string(ledger).context("serializing prune ledger")?;
        let now = chrono::Utc::now().timestamp();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO prune_ledger (session_id, ledger_json, updated_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (session_id) DO UPDATE SET
                     ledger_json = excluded.ledger_json,
                     updated_at = excluded.updated_at",
                params![session_id.to_string(), ledger_json, now],
            )
            .context("inserting prune_ledger")?;
            Ok(())
        })
    }

    /// Load the prune ledger for `session_id`. Returns `None` when no
    /// ledger has been persisted (a session that never pruned, or a
    /// pre-`0026` session) — the rehydration path then rebuilds the full
    /// (unpruned) transcript, which is correct (nothing was elided).
    /// Returns an `Err` only when a stored ledger fails to deserialize
    /// (corrupt row) so the caller can treat it as a missing ledger and
    /// fall back to the full unpruned form with a warning.
    pub fn load_prune_ledger(&self, session_id: Uuid) -> Result<Option<PruneLedger>> {
        self.write_blocking(move |conn| {
            let row: Option<String> = conn
                .query_row(
                    "SELECT ledger_json FROM prune_ledger WHERE session_id = ?1",
                    params![session_id.to_string()],
                    |r| r.get(0),
                )
                .optional()
                .context("querying prune_ledger")?;
            match row {
                Some(json) => {
                    let ledger: PruneLedger =
                        serde_json::from_str(&json).context("deserializing prune ledger")?;
                    Ok(Some(ledger))
                }
                None => Ok(None),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::prune::{LedgerEntry, PruneLedger};

    #[test]
    fn save_load_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        let ledger = PruneLedger {
            elided: vec![
                LedgerEntry {
                    original_event_id: "c1".into(),
                    reason: "snapshot superseded".into(),
                    partial_body: None,
                },
                LedgerEntry {
                    original_event_id: "c2".into(),
                    reason: "snapshot superseded".into(),
                    partial_body: None,
                },
            ],
            watermark: 7,
        };
        db.save_prune_ledger(s.session_id, &ledger).unwrap();
        let got = db.load_prune_ledger(s.session_id).unwrap().unwrap();
        assert_eq!(got, ledger);
    }

    #[test]
    fn save_upserts() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        let l1 = PruneLedger {
            elided: vec![LedgerEntry {
                original_event_id: "c1".into(),
                reason: "snapshot superseded".into(),
                partial_body: None,
            }],
            watermark: 2,
        };
        db.save_prune_ledger(s.session_id, &l1).unwrap();
        let l2 = PruneLedger {
            elided: vec![
                LedgerEntry {
                    original_event_id: "c1".into(),
                    reason: "snapshot superseded".into(),
                    partial_body: None,
                },
                LedgerEntry {
                    original_event_id: "c3".into(),
                    reason: "snapshot superseded".into(),
                    partial_body: None,
                },
            ],
            watermark: 5,
        };
        db.save_prune_ledger(s.session_id, &l2).unwrap();
        let got = db.load_prune_ledger(s.session_id).unwrap().unwrap();
        assert_eq!(got, l2);
    }

    #[test]
    fn unknown_session_is_none() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.load_prune_ledger(Uuid::new_v4()).unwrap().is_none());
    }
}
