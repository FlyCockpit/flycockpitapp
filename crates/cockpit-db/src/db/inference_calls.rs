//! `inference_calls` writes.
//!
//! One row per LLM round-trip. Tool calls in [`tool_calls`] join here
//! on `call_id` when /stats needs to attribute tokens.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
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
    pub async fn insert_inference_call(&self, row: &InferenceCallRow) -> Result<()> {
        let row = row.clone();
        self.transaction(move |conn| Self::insert_inference_call_conn(conn, &row))
            .await
    }

    pub fn insert_inference_call_conn(conn: &Connection, row: &InferenceCallRow) -> Result<()> {
        conn.execute(
            "INSERT INTO inference_calls (call_id, session_id, project_id, project_root, model, provider, timestamp, input_tokens, output_tokens, cached_input_tokens, cache_creation_input_tokens, cost_usd_micros, is_utility) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![row.call_id.to_string(), row.session_id.to_string(), row.project_id, row.project_root, row.model, row.provider, row.timestamp, row.input_tokens, row.output_tokens, row.cached_input_tokens, row.cache_creation_input_tokens, row.cost_usd_micros, row.is_utility],
        ).context("inserting inference_call")?;
        // Account usage at the immutable append boundary, in the same DB
        // transaction as the call row. Aggregate snapshots can later shrink
        // under retention and grow past an old baseline before anyone polls;
        // charging each uniquely keyed call exactly once avoids that ambiguity.
        conn.execute(
            // `inference_requests` is now keyed `(call_id, ordinal)`; every
            // ordinal of a call carries the same goal provenance, so select the
            // primary attempt (`MIN(ordinal)`) to keep the scalar subquery
            // single-valued and deterministic under multi-attempt rows.
            "UPDATE session_goals
                SET tokens_used = tokens_used + MAX(0, ?1 + ?2)
              WHERE id = (SELECT goal_id FROM inference_requests WHERE call_id = ?3 ORDER BY ordinal ASC LIMIT 1)
                AND attempt_generation = (SELECT goal_attempt_generation FROM inference_requests WHERE call_id = ?3 ORDER BY ordinal ASC LIMIT 1)
                AND token_budget IS NOT NULL
                AND ?4 = 0",
            params![
                row.input_tokens,
                row.output_tokens,
                row.call_id.to_string(),
                row.is_utility,
            ],
        )
        .context("accounting inference call against open session goal")?;
        Ok(())
    }

    pub fn list_inference_calls_for_session_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Vec<InferenceCallRow>> {
        let mut stmt = conn.prepare("SELECT call_id, session_id, project_id, project_root, model, provider, timestamp, input_tokens, output_tokens, cached_input_tokens, cache_creation_input_tokens, cost_usd_micros, is_utility FROM inference_calls WHERE session_id = ?1 ORDER BY timestamp ASC, rowid ASC").context("preparing list_inference_calls")?;
        let rows = stmt.query_map([session_id.to_string()], |row| {
            Ok(InferenceCallRow {
                call_id: Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                session_id: Uuid::parse_str(&row.get::<_, String>(1)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                project_id: row.get(2)?,
                project_root: row.get(3)?,
                model: row.get(4)?,
                provider: row.get(5)?,
                timestamp: row.get(6)?,
                input_tokens: row.get(7)?,
                output_tokens: row.get(8)?,
                cached_input_tokens: row.get(9)?,
                cache_creation_input_tokens: row.get(10)?,
                cost_usd_micros: row.get(11)?,
                is_utility: row.get::<_, i64>(12)? != 0,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("querying inference_calls")
    }

    /// The set of `call_id`s among `call_ids` whose `inference_calls` row has
    /// `is_utility = 1`. The `/export debug` bundle joins this onto the
    /// `inference_request` events it iterates to route each captured request
    /// body into `inference_requests/` (regular) or
    /// `inference_requests_utility/` (utility). A `call_id` with no
    /// `inference_calls` row (e.g. a pre-flag call, or a captured request
    /// without a usage row) is simply absent from the result → treated as
    /// non-utility.
    pub async fn utility_call_ids(
        &self,
        call_ids: &[String],
    ) -> Result<std::collections::HashSet<String>> {
        if call_ids.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let call_ids = call_ids.to_vec();
        self.read(move |conn| Self::utility_call_ids_conn(conn, &call_ids))
            .await
    }

    pub fn utility_call_ids_conn(
        conn: &Connection,
        call_ids: &[String],
    ) -> Result<std::collections::HashSet<String>> {
        let mut out = std::collections::HashSet::new();
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
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_goals::GoalDisposition;

    #[tokio::test]
    async fn insert_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
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
        db.insert_inference_call(&row).await.unwrap();
        let count: i64 = db
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM inference_calls", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(count, 1);
        // The cache-creation column round-trips
        // (prompt `prompt-caching-strategy.md`).
        let call_id = row.call_id.to_string();
        let creation: i64 = db
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT cache_creation_input_tokens FROM inference_calls WHERE call_id = ?1",
                    params![call_id],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(creation, 1112);
    }

    /// The `is_utility` flag round-trips on `inference_calls`, and
    /// `utility_call_ids` returns exactly the utility-flagged calls — the join
    /// the `/export debug` bundle uses to split the request folders.
    #[tokio::test]
    async fn is_utility_flag_round_trips_and_filters() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").await.unwrap();
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
        db.insert_inference_call(&base(regular, false))
            .await
            .unwrap();
        db.insert_inference_call(&base(utility, true))
            .await
            .unwrap();

        let unknown = Uuid::new_v4().to_string();
        let flagged = db
            .utility_call_ids(&[regular.to_string(), utility.to_string(), unknown.clone()])
            .await
            .unwrap();
        assert!(flagged.contains(&utility.to_string()));
        assert!(!flagged.contains(&regular.to_string()));
        // Unknown call_id (no row) is treated as non-utility.
        assert!(!flagged.contains(&unknown));
        // Empty input is a clean no-op.
        assert!(db.utility_call_ids(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn goal_accounting_requires_matching_dispatch_provenance() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "a").await.unwrap();
        let goal = db
            .create_session_goal(session.session_id, "p", "ship it", None, Some(1_000))
            .await
            .unwrap();
        let inference = |call_id, input_tokens, output_tokens, is_utility| InferenceCallRow {
            call_id,
            session_id: session.session_id,
            project_id: "p".into(),
            project_root: "/x".into(),
            model: "m".into(),
            provider: "provider".into(),
            timestamp: 1,
            input_tokens,
            output_tokens,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
            cost_usd_micros: None,
            is_utility,
        };

        // An ordinary foreground call in the same Running session has no
        // supervised dispatch provenance and must not consume the goal budget.
        db.insert_inference_call(&inference(Uuid::new_v4(), 20, 10, false))
            .await
            .unwrap();
        let running = db
            .current_session_goal(session.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(running.tokens_used, 0);

        let utility_call = Uuid::new_v4();
        db.insert_inference_request(
            &utility_call.to_string(),
            0,
            session.session_id,
            &serde_json::json!({}),
            crate::db::session_log::InferenceAttemptMeta::default(),
            Some((goal.id, goal.attempt_generation)),
        )
        .await
        .unwrap();
        db.insert_inference_call(&inference(utility_call, 40, 30, true))
            .await
            .unwrap();

        let matching_call = Uuid::new_v4();
        db.insert_inference_request(
            &matching_call.to_string(),
            0,
            session.session_id,
            &serde_json::json!({}),
            crate::db::session_log::InferenceAttemptMeta::default(),
            Some((goal.id, goal.attempt_generation)),
        )
        .await
        .unwrap();
        db.insert_inference_call(&inference(matching_call, 20, 10, false))
            .await
            .unwrap();

        db.set_session_goal_status(session.session_id, GoalDisposition::UserPaused)
            .await
            .unwrap();
        let paused_call = Uuid::new_v4();
        db.insert_inference_request(
            &paused_call.to_string(),
            0,
            session.session_id,
            &serde_json::json!({}),
            crate::db::session_log::InferenceAttemptMeta::default(),
            Some((goal.id, goal.attempt_generation)),
        )
        .await
        .unwrap();
        db.insert_inference_call(&inference(paused_call, 7, 4, false))
            .await
            .unwrap();
        let paused = db
            .current_session_goal(session.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            paused.tokens_used, 41,
            "a matching call dispatched before pause remains append-once usage"
        );

        let resumed = db
            .set_session_goal_status(session.session_id, GoalDisposition::Running)
            .await
            .unwrap();
        assert_eq!(resumed.id, goal.id);
        assert_eq!(resumed.tokens_used, 41);
        assert!(resumed.attempt_generation > goal.attempt_generation);

        let stale_call = Uuid::new_v4();
        db.insert_inference_request(
            &stale_call.to_string(),
            0,
            session.session_id,
            &serde_json::json!({}),
            crate::db::session_log::InferenceAttemptMeta::default(),
            Some((goal.id, goal.attempt_generation)),
        )
        .await
        .unwrap();
        db.insert_inference_call(&inference(stale_call, 100, 100, false))
            .await
            .unwrap();

        let resumed_call = Uuid::new_v4();
        db.insert_inference_request(
            &resumed_call.to_string(),
            0,
            session.session_id,
            &serde_json::json!({}),
            crate::db::session_log::InferenceAttemptMeta::default(),
            Some((resumed.id, resumed.attempt_generation)),
        )
        .await
        .unwrap();
        db.insert_inference_call(&inference(resumed_call, 5, 6, false))
            .await
            .unwrap();
        let charged_after_resume = db
            .current_session_goal(session.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(charged_after_resume.tokens_used, 52);
    }
}
