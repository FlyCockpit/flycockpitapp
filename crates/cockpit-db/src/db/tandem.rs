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
use rusqlite::{Connection, params};
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;
use crate::db::session_log::{InferenceRequestStatus, now_ms, redacted_json_debug};

/// One captured tandem (shadow) inference record, read back for `/export
/// debug`'s `inference_requests_tandem/` sibling directory.
#[derive(Clone)]
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

impl std::fmt::Debug for TandemRecord {
    /// `request` / `response` (and `usage`) are the raw trusted tandem bodies;
    /// never print them verbatim. Show each field's structural descriptor plus
    /// the (non-body) routing/lifecycle metadata.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TandemRecord")
            .field("session_id", &self.session_id)
            .field("parent_call_id", &self.parent_call_id)
            .field("parent_seq", &self.parent_seq)
            .field("agent", &self.agent)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("ts_ms", &self.ts_ms)
            .field("request", &format_args!("{}", redacted_json_debug(&self.request)))
            .field(
                "response",
                &format_args!(
                    "{}",
                    self.response
                        .as_ref()
                        .map_or_else(|| "None".to_string(), redacted_json_debug)
                ),
            )
            .field(
                "usage",
                &format_args!(
                    "{}",
                    self.usage
                        .as_ref()
                        .map_or_else(|| "None".to_string(), redacted_json_debug)
                ),
            )
            .field("status", &self.status)
            .finish()
    }
}

impl Db {
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_tandem_inference_conn(
        conn: &Connection,
        id: &str,
        session_id: Uuid,
        parent_call_id: &str,
        parent_seq: Option<i64>,
        agent: Option<&str>,
        provider: &str,
        model: &str,
        ts_ms: i64,
        request: &Value,
        response: Option<&Value>,
        usage: Option<&Value>,
        status: &str,
    ) -> Result<()> {
        if !matches!(
            status,
            "pending" | "completed" | "errored" | "timed_out" | "cancelled"
        ) {
            anyhow::bail!("invalid imported tandem inference status `{status}`");
        }
        let request_json = serde_json::to_string(request).context("serializing tandem request")?;
        let response_json = response
            .map(serde_json::to_string)
            .transpose()
            .context("serializing tandem response")?;
        let usage_json = usage
            .map(serde_json::to_string)
            .transpose()
            .context("serializing tandem usage")?;
        conn.execute(
            "INSERT INTO tandem_inference
               (id, session_id, parent_call_id, parent_seq, agent, provider, model, ts_ms,
                request_json, response_json, usage_json, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(id) DO UPDATE SET
               session_id=excluded.session_id, parent_call_id=excluded.parent_call_id,
               parent_seq=excluded.parent_seq, agent=excluded.agent, provider=excluded.provider,
               model=excluded.model, ts_ms=excluded.ts_ms, request_json=excluded.request_json,
               response_json=excluded.response_json, usage_json=excluded.usage_json, status=excluded.status",
            params![id, session_id.to_string(), parent_call_id, parent_seq, agent, provider, model,
                ts_ms, request_json, response_json, usage_json, status],
        ).context("restoring tandem_inference")?;
        Ok(())
    }

    /// Insert (or update) a tandem inference record. Keyed by the per-row
    /// `id`, so the dispatch-time `pending` write and the terminal update for
    /// the same row land on one row (`INSERT OR REPLACE`); the dispatch
    /// `ts_ms` is preserved across the update via `COALESCE`.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_tandem_inference(
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
        self.write(move |conn| {
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
        .await
    }

    /// All tandem records for a session, ordered by `(parent_seq, model)` so
    /// the export lists shadows grouped under the main call they shadow. Used
    /// by `/export debug` to emit the `inference_requests_tandem/` files and
    /// the `tandem_inference` events.
    pub async fn list_tandem_inference(&self, session_id: Uuid) -> Result<Vec<TandemRecord>> {
        self.read(move |conn| Self::list_tandem_inference_conn(conn, session_id))
            .await
    }

    pub fn list_tandem_inference_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Vec<TandemRecord>> {
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

    #[tokio::test]
    async fn tandem_record_round_trips_request_response_usage() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
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
        .await
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
        .await
        .unwrap();

        let rows = db.list_tandem_inference(s.session_id).await.unwrap();
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

    #[tokio::test]
    async fn pending_tandem_record_survives_with_no_response() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
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
        .await
        .unwrap();
        let rows = db.list_tandem_inference(s.session_id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "pending");
        assert!(rows[0].response.is_none());
        assert!(rows[0].usage.is_none());
    }

    #[test]
    fn tandem_record_debug_redacts_request_and_response() {
        let req_secret = "TRUSTED-TANDEM-REQUEST-SECRET-111";
        let resp_secret = "TRUSTED-TANDEM-RESPONSE-SECRET-222";
        let record = TandemRecord {
            session_id: Uuid::nil(),
            parent_call_id: "parent-call".to_string(),
            parent_seq: Some(3),
            agent: Some("builder".to_string()),
            provider: "openrouter".to_string(),
            model: "glm-4.6".to_string(),
            ts_ms: 555,
            request: json!({ "prompt": req_secret }),
            response: Some(json!({ "text": resp_secret })),
            usage: Some(json!({ "input_tokens": 10 })),
            status: "completed".to_string(),
        };
        let rendered = format!("{record:?}");
        assert!(!rendered.contains(req_secret), "leaked request: {rendered}");
        assert!(
            !rendered.contains(resp_secret),
            "leaked response: {rendered}"
        );
        assert!(rendered.contains("REDACTED"), "missing marker: {rendered}");
        // Non-body routing metadata stays visible.
        assert!(
            rendered.contains("parent-call"),
            "dropped parent_call_id: {rendered}"
        );
        assert!(rendered.contains("openrouter"), "dropped provider: {rendered}");
    }
}
