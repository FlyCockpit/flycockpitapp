//! `inference_calls` writes.
//!
//! One row per LLM round-trip. Tool calls in [`tool_calls`] join here
//! on `call_id` when /stats needs to attribute tokens.

use anyhow::{Context, Result};
use rusqlite::params;
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone)]
pub struct InferenceCallRow {
    pub call_id: Uuid,
    pub session_id: Uuid,
    pub project_id: String,
    pub project_root: String,
    pub model: String,
    pub provider: String,
    pub timestamp: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_input_tokens: i64,
    /// Input tokens written *into* the prompt cache on a miss (Anthropic
    /// `cache_creation`), distinct from `cached_input_tokens` (the cache
    /// read). Lets the pruning policy's cache-hit expectation be validated
    /// against measured reality (GOALS §10).
    pub cache_creation_input_tokens: i64,
    pub cost_usd_micros: Option<i64>,
    /// `true` when this call was made by the utility model / background
    /// machinery (auto-titling, auto-router, prompt-injection guard,
    /// next-message prediction, the `/compact` handoff brief, …) rather than
    /// a foreground user turn. Persisted so the `/export debug` bundle can
    /// route the call's request body into the sibling
    /// `inference_requests_utility/` folder. Defaults to `false`.
    pub is_utility: bool,
}

impl Db {
    pub fn insert_inference_call(&self, row: &InferenceCallRow) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO inference_calls (
                    call_id, session_id, project_id, project_root,
                    model, provider, timestamp,
                    input_tokens, output_tokens, cached_input_tokens,
                    cache_creation_input_tokens,
                    cost_usd_micros, is_utility
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    row.call_id.to_string(),
                    row.session_id.to_string(),
                    row.project_id,
                    row.project_root,
                    row.model,
                    row.provider,
                    row.timestamp,
                    row.input_tokens,
                    row.output_tokens,
                    row.cached_input_tokens,
                    row.cache_creation_input_tokens,
                    row.cost_usd_micros,
                    row.is_utility,
                ],
            )
            .context("inserting inference_call")?;
            Ok(())
        })
    }

    /// The set of `call_id`s among `call_ids` whose `inference_calls` row has
    /// `is_utility = 1`. The `/export debug` bundle joins this onto the
    /// `inference_request` events it iterates to route each captured request
    /// body into `inference_requests/` (regular) or
    /// `inference_requests_utility/` (utility). A `call_id` with no
    /// `inference_calls` row (e.g. a pre-flag call, or a captured request
    /// without a usage row) is simply absent from the result → treated as
    /// non-utility.
    pub fn utility_call_ids(
        &self,
        call_ids: &[String],
    ) -> Result<std::collections::HashSet<String>> {
        let mut out = std::collections::HashSet::new();
        if call_ids.is_empty() {
            return Ok(out);
        }
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT is_utility FROM inference_calls WHERE call_id = ?1")
                .context("preparing utility_call_ids")?;
            for id in call_ids {
                let flag: rusqlite::Result<i64> = stmt.query_row(params![id], |row| row.get(0));
                match flag {
                    Ok(v) if v != 0 => {
                        out.insert(id.clone());
                    }
                    Ok(_) => {}
                    Err(rusqlite::Error::QueryReturnedNoRows) => {}
                    Err(e) => return Err(e).context("querying is_utility"),
                }
            }
            Ok(())
        })?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let row = InferenceCallRow {
            call_id: Uuid::new_v4(),
            session_id: s.session_id,
            project_id: "p".into(),
            project_root: "/x".into(),
            model: "claude-opus-4-7".into(),
            provider: "anthropic".into(),
            timestamp: 1700000000,
            input_tokens: 1234,
            output_tokens: 567,
            cached_input_tokens: 8910,
            cache_creation_input_tokens: 1112,
            cost_usd_micros: Some(420),
            is_utility: false,
        };
        db.insert_inference_call(&row).unwrap();
        let count: i64 = db
            .with_conn(|c| {
                Ok(c.query_row("SELECT COUNT(*) FROM inference_calls", [], |r| r.get(0))?)
            })
            .unwrap();
        assert_eq!(count, 1);
        // The cache-creation column round-trips
        // (prompt `prompt-caching-strategy.md`).
        let creation: i64 = db
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT cache_creation_input_tokens FROM inference_calls WHERE call_id = ?1",
                    params![row.call_id.to_string()],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(creation, 1112);
    }

    /// The `is_utility` flag round-trips on `inference_calls`, and
    /// `utility_call_ids` returns exactly the utility-flagged calls — the join
    /// the `/export debug` bundle uses to split the request folders.
    #[test]
    fn is_utility_flag_round_trips_and_filters() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let regular = Uuid::new_v4();
        let utility = Uuid::new_v4();
        let base = |call_id: Uuid, is_utility: bool| InferenceCallRow {
            call_id,
            session_id: s.session_id,
            project_id: "p".into(),
            project_root: "/x".into(),
            model: "m".into(),
            provider: "anthropic".into(),
            timestamp: 1,
            input_tokens: 1,
            output_tokens: 1,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
            cost_usd_micros: None,
            is_utility,
        };
        db.insert_inference_call(&base(regular, false)).unwrap();
        db.insert_inference_call(&base(utility, true)).unwrap();

        let unknown = Uuid::new_v4().to_string();
        let flagged = db
            .utility_call_ids(&[regular.to_string(), utility.to_string(), unknown.clone()])
            .unwrap();
        assert!(flagged.contains(&utility.to_string()));
        assert!(!flagged.contains(&regular.to_string()));
        // Unknown call_id (no row) is treated as non-utility.
        assert!(!flagged.contains(&unknown));
        // Empty input is a clean no-op.
        assert!(db.utility_call_ids(&[]).unwrap().is_empty());
    }
}
