//! Retrieve durable stored tool results by short sha256 hash.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct ToolResultRetrieveTool;

#[async_trait]
impl Tool for ToolResultRetrieveTool {
    fn name(&self) -> &str {
        "tool_result_retrieve"
    }

    fn description(&self) -> &str {
        "Retrieve a stored tool result by 24-hex hash; optional line range"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Retrieve the exact redacted text for a previous stored tool result in this session. \
             Pass the 24-character lowercase hex hash from the tool-result marker; optionally \
             pass `start_line` and `end_line` to read only part of a long text result."
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

        let body = match start {
            Some(s) => render_line_range(&entry.content, s, end.unwrap_or(usize::MAX)),
            None => entry.content,
        };
        Ok(ToolOutput::text(body))
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

fn render_line_range(content: &str, start: usize, end: usize) -> String {
    let mut out = String::new();
    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        if line_no < start {
            continue;
        }
        if line_no > end {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    if out.is_empty() {
        format!("No lines in range {start}-{end}.")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_short_hash() {
        assert!(valid_short_hash("0123456789abcdefabcdef12"));
        assert!(!valid_short_hash("0123456789ABCDEFabcdef"));
        assert!(!valid_short_hash("0123456789abcdefabcdef1"));
        assert!(!valid_short_hash("0123456789abcdefabcdeg"));
    }

    #[test]
    fn renders_line_range() {
        assert_eq!(render_line_range("a\nb\nc\n", 2, 3), "b\nc\n");
    }
}
