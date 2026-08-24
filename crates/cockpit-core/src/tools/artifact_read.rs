//! Read a bounded, session-owned page from an immutable text artifact.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::tools::common::OUTPUT_BYTE_CAP;

pub struct ArtifactReadTool;

#[async_trait]
impl Tool for ArtifactReadTool {
    fn name(&self) -> &str {
        "artifact_read"
    }
    fn description(&self) -> &str {
        "Read a bounded line or byte page from an immutable session text artifact."
    }
    fn defensive_description(&self) -> Option<String> {
        Some(
            "Read only the requested bounded page of one current-session text artifact. Use the \
             artifact_id from a cockpit_artifact_v1 frame; page a large result with the returned \
             continuation instead of guessing another artifact or reading host files. This tool \
             cannot modify the artifact or access another session."
                .to_owned(),
        )
    }
    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }
    fn parameters(&self) -> Value {
        serde_json::json!({"type":"object","properties":{
            "artifact_id":{"type":"string","description":"Artifact UUID from a cockpit_artifact_v1 frame"},
            "start_line":{"type":"integer","description":"1-indexed first line"},
            "end_line":{"type":"integer","description":"inclusive final line"},
            "start_byte":{"type":"integer","description":"byte offset only for a single-line page"}
        },"required":["artifact_id"]})
    }
    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let artifact_id = parse_id(&args)?;
        let Some(artifact) = ctx
            .session
            .db
            .text_artifact(ctx.session.id, artifact_id)
            .await?
        else {
            return Ok(ToolOutput::text(
                "No text artifact with that ID is available in this session.",
            ));
        };
        // Archive imports validate structure, not the importing workspace's
        // current sensitive-literal inventory. Re-run the normal outbound
        // redaction boundary for every read, including live raw artifacts.
        let outbound_content = ctx.redact.scrub(&artifact.content);
        let (start, end, start_byte) = artifact_page_bounds(&args)?;
        if start_byte != 0 {
            let Some(line) = outbound_content.lines().nth(start.saturating_sub(1)) else {
                return Err(invalid_input(
                    "`start_byte` names a line outside the artifact",
                ));
            };
            if start_byte > line.len() || !line.is_char_boundary(start_byte) {
                return Err(invalid_input(
                    "`start_byte` must be a UTF-8 boundary within the requested line",
                ));
            }
        }
        Ok(render_capped_artifact_lines(
            &outbound_content,
            artifact_id,
            start,
            end,
            start_byte,
        ))
    }
}

pub(crate) fn artifact_page_bounds(args: &Value) -> Result<(usize, usize, usize)> {
    let start_byte = args
        .get("start_byte")
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| invalid_input("`start_byte` must be a non-negative integer"))
                .and_then(|value| {
                    usize::try_from(value).map_err(|_| {
                        invalid_input("`start_byte` exceeds this platform's byte range")
                    })
                })
        })
        .transpose()?;
    let start = positive(args, "start_line")?.unwrap_or(1);
    let end = positive(args, "end_line")?.unwrap_or_else(|| {
        if start_byte.is_some() {
            start
        } else {
            usize::MAX
        }
    });
    if end < start {
        return Err(invalid_input(
            "`end_line` must be greater than or equal to `start_line`",
        ));
    }
    if start_byte.is_some() && start != end {
        return Err(invalid_input(
            "`start_byte` requires matching `start_line` and `end_line`",
        ));
    }
    Ok((start, end, start_byte.unwrap_or(0)))
}

pub(crate) fn parse_id(args: &Value) -> Result<Uuid> {
    let value = args
        .get("artifact_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("`artifact_id` is required"))?;
    Uuid::parse_str(value).map_err(|_| invalid_input("`artifact_id` must be a UUID"))
}

pub(crate) fn positive(args: &Value, name: &str) -> Result<Option<usize>> {
    match args.get(name) {
        None => Ok(None),
        Some(value) => match value.as_u64() {
            Some(0) => Err(invalid_input(format!("`{name}` must be >= 1"))),
            Some(n) => usize::try_from(n)
                .map(Some)
                .map_err(|_| invalid_input(format!("`{name}` exceeds this platform's line range"))),
            None => Err(invalid_input(format!("`{name}` must be an integer"))),
        },
    }
}

pub(crate) fn utf8_prefix(value: &str, budget: usize) -> &str {
    if value.len() <= budget {
        return value;
    }
    let mut end = budget;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

pub(crate) fn render_capped_artifact_lines(
    content: &str,
    artifact_id: Uuid,
    start: usize,
    end: usize,
    start_byte: usize,
) -> ToolOutput {
    // Keep a fixed amount of room while emitting content.  The exact cursor is
    // added only after a page actually ends, but this bound makes that final
    // append independent of line-number digit widths and therefore guarantees
    // that no response can exceed the common tool-output cap.
    const CONTINUATION_RESERVE_BYTES: usize = 192;
    let mut out = String::new();
    let mut continuation = None;
    for (index, line) in content.lines().enumerate() {
        let number = index + 1;
        if number < start || number > end {
            continue;
        }
        let line_offset = if number == start {
            start_byte.min(line.len())
        } else {
            0
        };
        debug_assert!(line.is_char_boundary(line_offset));
        let slice = &line[line_offset..];
        let remaining = OUTPUT_BYTE_CAP.saturating_sub(out.len());
        if remaining <= CONTINUATION_RESERVE_BYTES {
            continuation = Some((number, line_offset));
            break;
        }
        let budget = remaining
            .saturating_sub(CONTINUATION_RESERVE_BYTES)
            .saturating_sub(1);
        let clipped = utf8_prefix(slice, budget);
        out.push_str(clipped);
        out.push('\n');
        if clipped.len() != slice.len() {
            continuation = Some((number, line_offset.saturating_add(clipped.len())));
            break;
        }
        // If a later selected line exists but cannot fit, the next iteration
        // emits a line-based continuation. Keeping this check here avoids
        // emitting a continuation merely because the caller intentionally set
        // a finite end_line.
        if out.len() >= OUTPUT_BYTE_CAP {
            continuation = Some((number.saturating_add(1), 0));
            break;
        }
    }
    if let Some((next_line, next_byte)) = continuation {
        let continuation = if next_byte == 0 {
            format!(
                "... [artifact continuation artifact_id={artifact_id} start_line={next_line}]\n"
            )
        } else {
            format!(
                "... [artifact continuation artifact_id={artifact_id} start_line={next_line} start_byte={next_byte}]\n"
            )
        };
        debug_assert!(continuation.len() <= CONTINUATION_RESERVE_BYTES);
        while out.len().saturating_add(continuation.len()) > OUTPUT_BYTE_CAP {
            out.pop();
        }
        out.push_str(&continuation);
        ToolOutput::truncated_text(out)
    } else {
        ToolOutput::text(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn byte_cursor_defaults_to_one_physical_line() {
        assert_eq!(
            artifact_page_bounds(&json!({"artifact_id":"ignored", "start_line":7, "start_byte":3}))
                .unwrap(),
            (7, 7, 3)
        );
    }
}
