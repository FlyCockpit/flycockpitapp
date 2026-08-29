//! Search one immutable, session-owned text artifact without broadening the
//! database search surface.

use anyhow::Result;
use async_trait::async_trait;
use regex::RegexBuilder;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::tools::artifact_read::{parse_id, utf8_prefix};
use crate::tools::common::OUTPUT_BYTE_CAP;

pub struct ArtifactSearchTool;

#[async_trait]
impl Tool for ArtifactSearchTool {
    fn name(&self) -> &str {
        "artifact_search"
    }
    fn description(&self) -> &str {
        "Search one immutable session text artifact by literal text or regular expression."
    }
    fn verbose_description(&self) -> Option<String> {
        Some(
            "Search one current-session text artifact only. Use the artifact_id from its frame, \
             choose literal search unless regular-expression behavior is necessary, and page or \
             narrow the query when matches are omitted. This is read-only and never searches host \
             files, the transcript, or another session."
                .to_owned(),
        )
    }
    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }
    fn parameters(&self) -> Value {
        serde_json::json!({"type":"object","properties":{
        "artifact_id":{"type":"string"},"pattern":{"type":"string","maxLength":4096},
        "mode":{"enum":["literal","regex"]},"case_sensitive":{"type":"boolean"},"max_matches":{"type":"integer","minimum":1,"maximum":100}
    },"required":["artifact_id","pattern"]})
    }
    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let artifact_id = parse_id(&args)?;
        let pattern = args
            .get("pattern")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`pattern` is required"))?;
        if pattern.is_empty() || pattern.len() > 4096 {
            return Err(invalid_input(
                "`pattern` must contain at most 4096 UTF-8 bytes",
            ));
        }
        let mode = args
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("literal");
        if !matches!(mode, "literal" | "regex") {
            return Err(invalid_input("`mode` must be `literal` or `regex`"));
        }
        let case_sensitive = match args.get("case_sensitive") {
            None => true,
            Some(value) => value
                .as_bool()
                .ok_or_else(|| invalid_input("`case_sensitive` must be a boolean"))?,
        };
        let max_matches = match args.get("max_matches") {
            None => 20,
            Some(value) => value
                .as_u64()
                .ok_or_else(|| invalid_input("`max_matches` must be an integer"))?,
        };
        if !(1..=100).contains(&max_matches) {
            return Err(invalid_input("`max_matches` must be between 1 and 100"));
        }
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
        // Imported representation metadata never grants outbound trust. Search
        // the current redacted view so both matched lines and the existence of
        // a literal obey the same local egress policy as ordinary tool output.
        let outbound_content = ctx.redact.scrub(&artifact.content);
        let expression = if mode == "literal" {
            regex::escape(pattern)
        } else {
            pattern.to_owned()
        };
        let matcher = RegexBuilder::new(&expression)
            .case_insensitive(!case_sensitive)
            .build()
            .map_err(|error| invalid_input(format!("invalid regex: {error}")))?;
        let mut out = String::new();
        let mut count = 0_u64;
        let mut output_truncated = false;
        let mut max_matches_reached = false;
        for (index, line) in outbound_content.lines().enumerate() {
            if !matcher.is_match(line) {
                continue;
            }
            if count == max_matches {
                max_matches_reached = true;
                break;
            }
            let prefix = format!("{}:", index + 1);
            let required_prefix = prefix.len().saturating_add(1);
            if OUTPUT_BYTE_CAP.saturating_sub(out.len()) < required_prefix {
                output_truncated = true;
                break;
            }
            let remaining = OUTPUT_BYTE_CAP - out.len() - required_prefix;
            let rendered = utf8_prefix(line, remaining);
            out.push_str(&prefix);
            out.push_str(rendered);
            out.push('\n');
            count += 1;
            if rendered.len() != line.len() {
                output_truncated = true;
                break;
            }
        }
        if count == 0 {
            return Ok(ToolOutput::text("No matches."));
        }
        if output_truncated {
            let suffix = "[search output truncated]\n";
            while out.len().saturating_add(suffix.len()) > OUTPUT_BYTE_CAP {
                out.pop();
            }
            out.push_str(suffix);
        } else if max_matches_reached {
            let suffix = "[additional matches omitted by max_matches]\n";
            while out.len().saturating_add(suffix.len()) > OUTPUT_BYTE_CAP {
                out.pop();
            }
            out.push_str(suffix);
        }
        Ok(if output_truncated {
            ToolOutput::truncated_text(out)
        } else {
            ToolOutput::text(out)
        })
    }
}
