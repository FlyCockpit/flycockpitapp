//! Read-only LSP navigation tool for semantic lookups.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::daemon::lsp::{LspNavigationRequest, LspOperation};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};
use crate::tools::common::resolve;

pub struct LspTool;

#[async_trait]
impl Tool for LspTool {
    fn name(&self) -> &str {
        "lsp"
    }

    fn description(&self) -> &str {
        "Semantic hover, definition, or references when intel tools need type precision"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Use LSP only for type-aware hover, definition, or references after cheaper intel/search tools are insufficient; it is read-only and may be unavailable."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "operation": { "type": "string", "enum": ["hover", "definition", "references"], "description": "Semantic lookup operation" },
                "file": { "type": "string", "x-cockpit-kind": "path", "description": "Source file path" },
                "line": { "type": "integer", "minimum": 1, "description": "1-based line" },
                "character": { "type": "integer", "minimum": 1, "description": "1-based character" }
            },
            "required": ["operation", "file"]
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let operation = args
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`operation` is required"))?;
        let operation = match operation {
            "hover" => LspOperation::Hover,
            "definition" => LspOperation::Definition,
            "references" => LspOperation::References,
            other => {
                return Err(invalid_input(format!(
                    "unsupported LSP operation `{other}`; expected hover, definition, or references"
                )));
            }
        };
        let file = args
            .get("file")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`file` is required"))?;
        let line = optional_u32(&args, "line")?;
        let character = optional_u32(&args, "character")?;
        let file = resolve(file, &ctx.cwd);
        crate::tools::sandbox::check_native_access(ctx, &file).await?;
        let Some(lsp) = &ctx.lsp else {
            return Ok(ToolOutput::text("LSP is unavailable in this context."));
        };
        let config = crate::config::extended::load_for_cwd(&ctx.cwd);
        let out = lsp
            .navigate(
                &ctx.cwd,
                LspNavigationRequest {
                    operation,
                    file,
                    line,
                    character,
                },
                &config,
            )
            .await;
        Ok(ToolOutput::text(out))
    }
}

fn optional_u32(args: &Value, key: &str) -> Result<Option<u32>> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    let Some(n) = value.as_u64() else {
        return Err(invalid_input(format!("`{key}` must be an integer")));
    };
    if n == 0 || n > u32::MAX as u64 {
        return Err(invalid_input(format!(
            "`{key}` must be between 1 and {}",
            u32::MAX
        )));
    }
    Ok(Some(n as u32))
}
