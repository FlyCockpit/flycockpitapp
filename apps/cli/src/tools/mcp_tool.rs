//! The `mcp` tool — executes a model-authored Python script in the Monty
//! sandbox (GOALS §18a, monty mode).
//!
//! The script reaches enabled MCP servers through host functions
//! exposed inside the sandbox: `mcp.search(query)`,
//! `mcp.describe(server, tool)`, and `mcp.invoke(server, tool, args)`.
//! The script's final value is returned as JSON. If the script returns
//! `None`, captured `print(...)` output is returned as a fallback. The sandbox
//! has no filesystem, network, or env access.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct McpTool;

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &str {
        "mcp"
    }

    fn description(&self) -> &str {
        "Run Python in a sandbox exposing mcp.search, mcp.describe, and mcp.invoke."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Execute a Python script in an isolated sandbox to reach MCP tools. Inside the \
             script call `mcp.search(query)` for cheap discovery (returns dicts with server, tool, \
             and description), `mcp.describe(server, tool)` when you need one tool's full input \
             schema, and `mcp.invoke(server, tool, args)` to call one. Process intermediate results \
             in Python and use a final expression for the value you want back, for example \
             `hits = mcp.search(\"calendar\")` then `hits`. If the script returns `None`, \
             printed output is captured and returned as a fallback. The sandbox has no filesystem, \
             network, or environment access."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "script": { "type": "string", "description": "Python script" }
            },
            "required": ["script"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "script": {
                    "type": "string",
                    "description": "Python source using mcp.search, mcp.describe, and mcp.invoke; prefer a final expression as the returned value, with print(...) output returned only as a fallback when the script returns None"
                }
            },
            "required": ["script"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let script = args
            .get("script")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`script` (a Python string) is required"))?;

        let cfg = crate::mcp::config::McpConfig::discover(&ctx.cwd);
        match crate::mcp::sandbox::run(script, &cfg).await {
            Ok(out) => Ok(ToolOutput::text(out)),
            // A sandbox error (compile error, denied OS access, mcp.invoke
            // failure surfaced as a Python exception, etc.) is an execution
            // outcome the model should see and react to, not an invocation
            // shape error — return it as content.
            Err(e) => Ok(ToolOutput::text(format!("[mcp sandbox error] {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_is_one_sentence_terse() {
        let t = McpTool;
        assert!(t.description().len() <= 200, "terse budget");
        assert!(t.description().contains("mcp.search"));
        assert!(t.description().contains("mcp.describe"));
        assert!(t.description().contains("mcp.invoke"));
        assert!(t.description().contains("Python"));
    }

    #[test]
    fn parameters_require_script_string() {
        let p = McpTool.parameters();
        assert_eq!(p["required"], serde_json::json!(["script"]));
        assert_eq!(p["properties"]["script"]["type"], "string");
    }

    #[test]
    fn defensive_text_mentions_final_expression_and_print_fallback() {
        let t = McpTool;
        let desc = t.defensive_description().unwrap();
        assert!(desc.contains("final expression"), "{desc}");
        assert!(desc.contains("printed output"), "{desc}");
        assert!(desc.contains("fallback"), "{desc}");

        let p = t.defensive_parameters().unwrap();
        let script_desc = p["properties"]["script"]["description"].as_str().unwrap();
        assert!(script_desc.contains("final expression"), "{script_desc}");
        assert!(script_desc.contains("print"), "{script_desc}");
        assert!(script_desc.contains("fallback"), "{script_desc}");
    }
}
