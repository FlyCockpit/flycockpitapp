//! Retrieve durable delegation payloads by sha256 hash.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};
use crate::tools::common::OUTPUT_BYTE_CAP;
use crate::tools::tool_result_retrieve::{optional_line, render_capped_line_range};

pub struct DelegationPayloadRetrieveTool;

#[async_trait]
impl Tool for DelegationPayloadRetrieveTool {
    fn name(&self) -> &str {
        "delegation_payload_retrieve"
    }

    fn description(&self) -> &str {
        "Retrieve this subagent's exact delegation payload by 64-hex hash; use start_line/end_line to page long bodies"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Retrieve the exact redacted delegation brief stored for this session. \
             Use the 64-character lowercase sha256 hash from the delegation-payload marker; \
             do not guess or shorten the hash, and do not use this for unrelated tool results. \
             Output is capped; page large payloads with `start_line` and `end_line`."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "hash": { "type": "string", "description": "64 lowercase hex chars" },
                "start_line": { "type": "integer", "description": "First 1-indexed line" },
                "end_line": { "type": "integer", "description": "Last 1-indexed line, inclusive" }
            },
            "required": ["hash"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "hash": { "type": "string", "description": "Required 64-character lowercase sha256 hash from a delegation-payload marker" },
                "start_line": { "type": "integer", "description": "Optional first 1-indexed line to return when you only need a slice" },
                "end_line": { "type": "integer", "description": "Optional last 1-indexed line to return, inclusive; requires `start_line`" }
            },
            "required": ["hash"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let hash = args
            .get("hash")
            .and_then(Value::as_str)
            .map(str::trim)
            .ok_or_else(|| invalid_input("`hash` is required"))?;
        if !valid_full_hash(hash) {
            return Err(invalid_input(
                "`hash` must be exactly 64 lowercase hexadecimal characters",
            ));
        }

        let Some(payload) = ctx
            .session
            .db
            .load_task_delegation_payload_by_hash(ctx.session.id, hash)?
        else {
            return Ok(ToolOutput::text(format!(
                "No delegation payload with hash `{hash}` is available in this session."
            )));
        };

        let start = optional_line(args.get("start_line"), "start_line")?;
        let end = optional_line(args.get("end_line"), "end_line")?;
        if end.is_some() && start.is_none() {
            return Err(invalid_input("`end_line` requires `start_line`"));
        }
        if let (Some(s), Some(e)) = (start, end)
            && e < s
        {
            return Err(invalid_input(
                "`end_line` must be greater than or equal to `start_line`",
            ));
        }

        Ok(render_capped_line_range(
            &payload.body,
            start.unwrap_or(1),
            end.unwrap_or(usize::MAX),
            OUTPUT_BYTE_CAP,
            self.name(),
            hash,
        ))
    }
}

pub(crate) fn valid_full_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::task_delegation_payloads::{NewTaskDelegationPayload, delegation_payload_hash};
    use serde_json::json;

    fn stored_body(line_count: usize, line_width: usize) -> String {
        (1..=line_count)
            .map(|line| format!("{line:04}:{}\n", "d".repeat(line_width)))
            .collect()
    }

    async fn store_payload(ctx: &ToolCtx, content: &str) -> String {
        ctx.session
            .db
            .upsert_task_delegation_job(
                ctx.session.id,
                "task-1",
                Some("call-1"),
                "Build",
                None,
                &[crate::db::task_delegations::DelegationChildInit {
                    label: "default",
                    child_agent: "Explore",
                    model: None,
                    output_dir: None,
                    requested_cwd: None,
                    resolved_cwd: None,
                    todo_ids_json: None,
                }],
            )
            .unwrap();
        let row = ctx
            .session
            .db
            .insert_task_delegation_payload(NewTaskDelegationPayload {
                task_call_id: "task-1",
                function_call_id: Some("call-1"),
                parent_session_id: ctx.session.id,
                parent_agent: "Build",
                label: "default",
                child_agent: "Explore",
                prompt: content,
            })
            .unwrap();
        assert_eq!(row.payload_hash, delegation_payload_hash(content));
        row.payload_hash
    }

    async fn retrieve(content: &str, args_for: impl FnOnce(&str) -> Value) -> ToolOutput {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let hash = store_payload(&ctx, content).await;
        DelegationPayloadRetrieveTool
            .call(args_for(&hash), &ctx)
            .await
            .unwrap()
    }

    #[test]
    fn validates_lowercase_sha256() {
        assert!(valid_full_hash(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!valid_full_hash("abc"));
        assert!(!valid_full_hash(
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }

    #[tokio::test]
    async fn delegation_payload_retrieve_caps_and_pages() {
        let content = stored_body(80, OUTPUT_BYTE_CAP / 20);

        let output = retrieve(&content, |hash| json!({ "hash": hash })).await;

        assert!(output.truncated);
        assert!(output.content.len() <= OUTPUT_BYTE_CAP);
        assert!(output.content.starts_with("0001:"));
        assert!(output.content.contains("delegation_payload_retrieve"));
        assert!(output.content.contains("hash="));
        assert!(output.content.contains("start_line="));
    }

    #[tokio::test]
    async fn delegation_payload_retrieve_continuation_resumes_exactly() {
        let content = stored_body(80, OUTPUT_BYTE_CAP / 20);
        let first = retrieve(&content, |hash| json!({ "hash": hash })).await;
        let next = first
            .content
            .split("start_line=")
            .nth(1)
            .and_then(|tail| tail.split_whitespace().next())
            .and_then(|n| n.parse::<usize>().ok())
            .expect("continuation start_line");

        let second = retrieve(&content, |hash| json!({ "hash": hash, "start_line": next })).await;

        assert!(second.content.starts_with(&format!("{next:04}:")));
        assert!(!first.content.contains(&format!("{next:04}:")));
    }

    #[tokio::test]
    async fn delegation_payload_retrieve_small_payload_has_no_marker() {
        let content = "brief\nbody\n";

        let output = retrieve(content, |hash| json!({ "hash": hash })).await;

        assert_eq!(output.content, content);
        assert!(!output.truncated);
        assert!(!output.content.contains("delegation_payload_retrieve"));
    }

    #[tokio::test]
    async fn delegation_payload_retrieve_output_is_not_restored() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let retained = crate::engine::tool::RetainedTruncatedOutput {
            content: "hidden delegation payload page".to_string(),
            original_byte_len: "hidden delegation payload page".len(),
            partial: false,
        };
        let mut delivered = "visible delegation payload page".to_string();

        let stored = crate::engine::agent::maybe_store_retrievable_truncated_tool_result(
            &ctx.session,
            "Build",
            "delegation_payload_retrieve",
            "call-1",
            &mut delivered,
            Some(&retained),
            false,
        )
        .await
        .unwrap();

        assert!(stored.is_none());
        assert!(
            ctx.session
                .db
                .list_compressed_tool_results(ctx.session.id)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
