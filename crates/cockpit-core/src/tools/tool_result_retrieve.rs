//! Retrieve durable stored tool results by short sha256 hash.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};
use crate::tools::common::OUTPUT_BYTE_CAP;

pub struct ToolResultRetrieveTool;

#[async_trait]
impl Tool for ToolResultRetrieveTool {
    fn name(&self) -> &str {
        "tool_result_retrieve"
    }

    fn description(&self) -> &str {
        "Retrieve a stored tool result by its 24-hex hash from a \"... hash=<h> retrieve with tool_result_retrieve\" marker; use start_line/end_line to page long bodies"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Retrieve stored text for a previous tool result in this session as the tool originally \
             produced it, minus truncation. Pass the 24-character lowercase hex hash from a \
             `... hash=<h> retrieve with tool_result_retrieve` marker. Output is capped; page large \
             bodies with `start_line` and the marker's `lines=` count instead of fetching them whole. \
             This tool does not work for `[elided:` markers because that content is not stored under \
             a hash; it appears in a later message or transcript event."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "hash": { "type": "string", "description": "24 lowercase hex chars" },
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
                "hash": { "type": "string", "description": "Required 24-character lowercase hexadecimal hash from a tool-result marker" },
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
        if !valid_short_hash(hash) {
            return Err(invalid_input(
                "`hash` must be exactly 24 lowercase hexadecimal characters",
            ));
        }

        let Some(entry) = ctx
            .session
            .db
            .compressed_tool_result(ctx.session.id, hash)?
        else {
            return Ok(ToolOutput::text(format!(
                "No stored tool result with hash `{hash}` is available in this session."
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
            &entry.content,
            start.unwrap_or(1),
            end.unwrap_or(usize::MAX),
            OUTPUT_BYTE_CAP,
            hash,
        ))
    }
}

pub(crate) fn valid_short_hash(hash: &str) -> bool {
    hash.len() == 24
        && hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn optional_line(value: Option<&Value>, name: &str) -> Result<Option<usize>> {
    match value.and_then(Value::as_u64) {
        Some(0) => Err(invalid_input(format!("`{name}` must be >= 1"))),
        Some(n) => Ok(Some(n as usize)),
        None if value.is_some() => Err(invalid_input(format!("`{name}` must be an integer"))),
        None => Ok(None),
    }
}

fn render_capped_line_range(
    content: &str,
    start: usize,
    end: usize,
    cap: usize,
    hash: &str,
) -> ToolOutput {
    let selected: Vec<(usize, &str)> = content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let line_no = idx + 1;
            (line_no >= start && line_no <= end).then_some((line_no, line))
        })
        .collect();
    if selected.is_empty() {
        return ToolOutput::text(format!("No lines in range {start}-{end}."));
    }

    let mut out = String::new();
    let mut truncated = false;
    for (idx, (line_no, line)) in selected.iter().copied().enumerate() {
        let line_len = line.len() + 1;
        let has_more = idx + 1 < selected.len();
        let marker = has_more.then(|| continuation_marker(line_no, line_no + 1, hash));
        let required = out
            .len()
            .saturating_add(line_len)
            .saturating_add(marker.as_ref().map_or(0, String::len));
        if !out.is_empty() && required > cap {
            let last = selected[idx - 1].0;
            out.push_str(&continuation_marker(last, line_no, hash));
            truncated = true;
            break;
        }
        out.push_str(line);
        out.push('\n');
        if has_more && required > cap {
            out.push_str(marker.expect("marker for remaining lines").as_str());
            truncated = true;
            break;
        }
    }
    if truncated {
        ToolOutput::truncated_text(out)
    } else {
        ToolOutput::text(out)
    }
}

fn continuation_marker(last: usize, next: usize, hash: &str) -> String {
    format!(
        "... [truncated at line {last}; ask tool_result_retrieve with hash={hash} start_line={next} to see more]\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::compressed_results::NewCompressedToolResult;
    use serde_json::json;

    const HASH: &str = "0123456789abcdefabcdef12";

    fn stored_body(line_count: usize, line_width: usize) -> String {
        (1..=line_count)
            .map(|line| format!("{line:04}:{}\n", "x".repeat(line_width)))
            .collect()
    }

    fn store_body(ctx: &ToolCtx, content: &str) {
        ctx.session
            .db
            .insert_compressed_tool_result(
                HASH,
                NewCompressedToolResult {
                    session_id: ctx.session.id,
                    agent_id: "builder",
                    tool: "bash",
                    call_id: "call-1",
                    original_byte_len: content.len(),
                    compressed_byte_len: None,
                    created_at: 1,
                    kind: "truncated",
                    content,
                },
            )
            .unwrap();
    }

    async fn retrieve(content: &str, args: Value) -> ToolOutput {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        store_body(&ctx, content);
        ToolResultRetrieveTool.call(args, &ctx).await.unwrap()
    }

    #[test]
    fn validates_short_hash() {
        assert!(valid_short_hash("0123456789abcdefabcdef12"));
        assert!(!valid_short_hash("0123456789ABCDEFabcdef"));
        assert!(!valid_short_hash("0123456789abcdefabcdef1"));
        assert!(!valid_short_hash("0123456789abcdefabcdeg"));
    }

    #[test]
    fn renders_line_range() {
        let output = render_capped_line_range("a\nb\nc\n", 2, 3, OUTPUT_BYTE_CAP, "h");
        assert_eq!(output.content, "b\nc\n");
        assert!(!output.truncated);
    }

    #[tokio::test]
    async fn tool_result_retrieve_caps_whole_body_output() {
        let content = stored_body(80, OUTPUT_BYTE_CAP / 20);

        let output = retrieve(&content, json!({ "hash": HASH })).await;

        assert!(output.truncated);
        assert!(output.content.len() <= OUTPUT_BYTE_CAP);
        assert!(output.content.starts_with("0001:"));
        assert!(output.content.contains("ask tool_result_retrieve"));
    }

    #[tokio::test]
    async fn tool_result_retrieve_emits_continuation_marker() {
        let content = stored_body(80, OUTPUT_BYTE_CAP / 20);

        let output = retrieve(&content, json!({ "hash": HASH })).await;

        assert!(output.truncated);
        assert!(output.content.ends_with("to see more]\n"));
        assert!(output.content.contains("start_line="));
        assert!(output.content.contains(HASH));
    }

    #[tokio::test]
    async fn tool_result_retrieve_continuation_resumes_exactly() {
        let content = stored_body(80, OUTPUT_BYTE_CAP / 20);
        let first = retrieve(&content, json!({ "hash": HASH })).await;
        let next = first
            .content
            .split("start_line=")
            .nth(1)
            .and_then(|tail| tail.split_whitespace().next())
            .and_then(|n| n.parse::<usize>().ok())
            .expect("continuation start_line");

        let second = retrieve(&content, json!({ "hash": HASH, "start_line": next })).await;

        assert!(second.content.starts_with(&format!("{next:04}:")));
        assert!(!first.content.contains(&format!("{next:04}:")));
    }

    #[tokio::test]
    async fn tool_result_retrieve_small_body_has_no_marker() {
        let content = "alpha\nbeta\n";

        let output = retrieve(content, json!({ "hash": HASH })).await;

        assert_eq!(output.content, content);
        assert!(!output.truncated);
        assert!(!output.content.contains("ask tool_result_retrieve"));
    }

    #[tokio::test]
    async fn tool_result_retrieve_line_range_is_also_capped() {
        let content = stored_body(80, OUTPUT_BYTE_CAP / 20);

        let output = retrieve(
            &content,
            json!({ "hash": HASH, "start_line": 10, "end_line": 70 }),
        )
        .await;

        assert!(output.truncated);
        assert!(output.content.starts_with("0010:"));
        assert!(output.content.contains("start_line="));
        let next = output
            .content
            .split("start_line=")
            .nth(1)
            .and_then(|tail| tail.split_whitespace().next())
            .and_then(|n| n.parse::<usize>().ok())
            .expect("continuation start_line");
        assert!(next <= 70);
    }

    #[tokio::test]
    async fn tool_result_retrieve_oversized_single_line_makes_progress() {
        let content = format!("{}\nsmall\n", "x".repeat(OUTPUT_BYTE_CAP + 32));

        let output = retrieve(&content, json!({ "hash": HASH })).await;

        assert!(output.truncated);
        assert!(output.content.starts_with("xxx"));
        assert!(output.content.contains("start_line=2"));
    }

    #[tokio::test]
    async fn tool_result_retrieve_never_splits_a_line() {
        let content = stored_body(80, OUTPUT_BYTE_CAP / 20);

        let output = retrieve(&content, json!({ "hash": HASH })).await;

        for line in output.content.lines() {
            if line.starts_with("... [truncated") {
                continue;
            }
            assert!(line.starts_with(char::is_numeric));
            assert!(line.ends_with('x'), "line was split: {line:?}");
        }
    }

    #[test]
    fn tool_result_retrieve_description_drops_redacted_claim() {
        let tool = ToolResultRetrieveTool;

        assert!(!tool.description().contains("redacted"));
        assert!(
            !tool
                .defensive_description()
                .expect("defensive description")
                .contains("redacted")
        );
    }

    #[test]
    fn tool_result_retrieve_description_shows_marker_shape_and_elided_caveat() {
        let description = ToolResultRetrieveTool
            .defensive_description()
            .expect("defensive description");

        assert!(description.contains("retrieve with tool_result_retrieve"));
        assert!(description.contains("start_line"));
        assert!(description.contains("[elided:"));
        assert!(description.contains("does not work"));
    }

    #[test]
    fn tool_result_retrieve_terse_description_names_hash_and_range() {
        let description = ToolResultRetrieveTool.description();

        assert_eq!(description.lines().count(), 1);
        assert!(description.contains("24-hex hash"));
        assert!(description.contains("start_line"));
        assert!(description.contains("end_line"));
    }
}
