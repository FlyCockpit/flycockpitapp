//! `tandem_inference` writes — model-comparison shadow inference
//! (implementation note).
//!
//! One row per `(shadowed main call, tandem model)`. Unlike
//! [`crate::db::session_log`]'s `inference_requests` (request body only), a
//! tandem record additionally stores the FULL raw completion
//! (`response_json`) and token usage (`usage_json`) — the comparison needs
//! what the tandem model actually emitted on the identical input. Linked to
//! the main call it shadows via `parent_call_id` (+ `parent_seq` / `agent`
//! for timeline alignment). Written at dispatch with status `pending` and
//! updated to its terminal value on settle (`INSERT OR REPLACE` keyed by the
//! per-row `id`) so an in-flight tandem request unsettled at export time
//! still exports a `pending` record.

use anyhow::{Context, Result};
use rusqlite::params;
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;
use crate::db::session_log::{InferenceRequestStatus, now_ms};

/// One captured tandem (shadow) inference record, read back for `/export
/// debug`'s `inference_requests_tandem/` sibling directory.
#[derive(Debug, Clone)]
pub struct TandemRecord {
    pub session_id: Uuid,
    /// The main inference call this tandem shadows (== `inference_calls` /
    /// `inference_requests` `call_id`).
    pub parent_call_id: String,
    /// The main call's timeline `seq`, when known at dispatch.
    pub parent_seq: Option<i64>,
    /// The agent whose turn was shadowed (primary or `builder`/`explore`/`docs`).
    pub agent: Option<String>,
    pub provider: String,
    pub model: String,
    pub ts_ms: i64,
    /// The exact post-redaction request body sent to the tandem model.
    pub request: Value,
    /// The full raw completion (assistant text and/or tool calls), or `None`
    /// for an unsettled / errored record with no completion.
    pub response: Option<Value>,
    /// Provider-reported token usage, or `None`.
    pub usage: Option<Value>,
    /// Lifecycle status string (`pending`/`completed`/`errored`/
    /// `timed_out`/`cancelled`).
    pub status: String,
}

impl Db {
    /// Insert (or update) a tandem inference record. Keyed by the per-row
    /// `id`, so the dispatch-time `pending` write and the terminal update for
    /// the same row land on one row (`INSERT OR REPLACE`); the dispatch
    /// `ts_ms` is preserved across the update via `COALESCE`.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_tandem_inference(
        &self,
        id: &str,
        session_id: Uuid,
        parent_call_id: &str,
        parent_seq: Option<i64>,
        agent: Option<&str>,
        provider: &str,
        model: &str,
        request: &Value,
        response: Option<&Value>,
        usage: Option<&Value>,
        status: InferenceRequestStatus,
    ) -> Result<()> {
        let request_json = serde_json::to_string(request).context("serializing tandem request")?;
        let response_json = response
            .map(serde_json::to_string)
            .transpose()
            .context("serializing tandem response")?;
        let usage_json = usage
            .map(serde_json::to_string)
            .transpose()
            .context("serializing tandem usage")?;
        let ts_ms = now_ms();
        let id = id.to_owned();
        let parent_call_id = parent_call_id.to_owned();
        let agent = agent.map(str::to_owned);
        let provider = provider.to_owned();
        let model = model.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO tandem_inference
                   (id, session_id, parent_call_id, parent_seq, agent,
                    provider, model, ts_ms, request_json, response_json,
                    usage_json, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(id) DO UPDATE SET
                   parent_seq    = excluded.parent_seq,
                   agent         = excluded.agent,
                   request_json  = excluded.request_json,
                   response_json = excluded.response_json,
                   usage_json    = excluded.usage_json,
                   status        = excluded.status,
                   ts_ms         = COALESCE(tandem_inference.ts_ms, excluded.ts_ms)",
                params![
                    id,
                    session_id.to_string(),
                    parent_call_id,
                    parent_seq,
                    agent,
                    provider,
                    model,
                    ts_ms,
                    request_json,
                    response_json,
                    usage_json,
                    status.as_str(),
                ],
            )
            .context("inserting tandem_inference")?;
            Ok(())
        })
    }

    /// All tandem records for a session, ordered by `(parent_seq, model)` so
    /// the export lists shadows grouped under the main call they shadow. Used
    /// by `/export debug` to emit the `inference_requests_tandem/` files and
    /// the `tandem_inference` events.
    pub fn list_tandem_inference(&self, session_id: Uuid) -> Result<Vec<TandemRecord>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT session_id, parent_call_id, parent_seq, agent,
                            provider, model, ts_ms, request_json, response_json,
                            usage_json, status
                       FROM tandem_inference
                      WHERE session_id = ?1
                      ORDER BY parent_seq ASC, model ASC, id ASC",
                )
                .context("preparing list_tandem_inference")?;
            let rows = stmt
                .query_map([session_id.to_string()], decode_tandem_row)
                .context("querying tandem_inference")?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.context("decoding tandem_inference row")??);
            }
            Ok(out)
        })
    }
}

type DecodeResult<T> = rusqlite::Result<Result<T>>;

fn decode_tandem_row(row: &rusqlite::Row<'_>) -> DecodeResult<TandemRecord> {
    let sid: String = row.get("session_id")?;
    let request_json: String = row.get("request_json")?;
    let response_json: Option<String> = row.get("response_json")?;
    let usage_json: Option<String> = row.get("usage_json")?;
    Ok((|| {
        let session_id = Uuid::parse_str(&sid).with_context(|| format!("session_id `{sid}`"))?;
        let request: Value =
            serde_json::from_str(&request_json).context("deserializing request_json")?;
        let response = response_json
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .context("deserializing response_json")?;
        let usage = usage_json
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .context("deserializing usage_json")?;
        Ok(TandemRecord {
            session_id,
            parent_call_id: row.get("parent_call_id").map_err(anyhow::Error::from)?,
            parent_seq: row.get("parent_seq").map_err(anyhow::Error::from)?,
            agent: row.get("agent").map_err(anyhow::Error::from)?,
            provider: row.get("provider").map_err(anyhow::Error::from)?,
            model: row.get("model").map_err(anyhow::Error::from)?,
            ts_ms: row.get("ts_ms").map_err(anyhow::Error::from)?,
            request,
            response,
            usage,
            status: row.get("status").map_err(anyhow::Error::from)?,
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tandem_record_round_trips_request_response_usage() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let parent = Uuid::new_v4().to_string();

        // Dispatch-time write: pending, no response yet.
        db.upsert_tandem_inference(
            "tan-1",
            s.session_id,
            &parent,
            Some(42),
            Some("builder"),
            "openrouter",
            "glm-4.6",
            &json!({ "model": "glm-4.6", "messages": [] }),
            None,
            None,
            InferenceRequestStatus::Pending,
        )
        .unwrap();

        // Settle: completed, with response + usage.
        db.upsert_tandem_inference(
            "tan-1",
            s.session_id,
            &parent,
            Some(42),
            Some("builder"),
            "openrouter",
            "glm-4.6",
            &json!({ "model": "glm-4.6", "messages": [] }),
            Some(&json!([{ "text": "hi" }])),
            Some(&json!({ "input_tokens": 10, "output_tokens": 3 })),
            InferenceRequestStatus::Completed,
        )
        .unwrap();

        let rows = db.list_tandem_inference(s.session_id).unwrap();
        assert_eq!(rows.len(), 1, "upsert keyed by id keeps one row");
        let r = &rows[0];
        assert_eq!(r.parent_call_id, parent);
        assert_eq!(r.parent_seq, Some(42));
        assert_eq!(r.agent.as_deref(), Some("builder"));
        assert_eq!(r.provider, "openrouter");
        assert_eq!(r.model, "glm-4.6");
        assert_eq!(r.status, "completed");
        assert_eq!(r.response.as_ref().unwrap()[0]["text"], "hi");
        assert_eq!(r.usage.as_ref().unwrap()["input_tokens"], 10);
    }

    #[test]
    fn pending_tandem_record_survives_with_no_response() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        db.upsert_tandem_inference(
            "tan-pending",
            s.session_id,
            "call-x",
            None,
            Some("Build"),
            "anthropic",
            "claude",
            &json!({ "model": "claude" }),
            None,
            None,
            InferenceRequestStatus::Pending,
        )
        .unwrap();
        let rows = db.list_tandem_inference(s.session_id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "pending");
        assert!(rows[0].response.is_none());
        assert!(rows[0].usage.is_none());
    }
}
