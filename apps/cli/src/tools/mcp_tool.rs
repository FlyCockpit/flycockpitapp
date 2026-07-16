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

use crate::engine::agent::TurnEvent;
use crate::engine::tool::{Tool, ToolBox, ToolCtx, ToolDescOverride, ToolOutput, invalid_input};

pub struct McpTool;

const NORMAL_DESCRIPTION: &str =
    "Run Python in a sandbox exposing mcp.search, mcp.describe, and mcp.invoke.";
const DEFENSIVE_DESCRIPTION: &str = "Execute a Python script in an isolated sandbox to reach MCP tools. Inside the \
     script call `mcp.search(query)` for cheap discovery (returns dicts with server, tool, \
     and description), `mcp.describe(server, tool)` when you need one tool's full input \
     schema, and `mcp.invoke(server, tool, args)` to call one. Process intermediate results \
     in Python and use a final expression for the value you want back, for example \
     `hits = mcp.search(\"calendar\")` then `hits`. If the script returns `None`, \
     printed output is captured and returned as a fallback. The sandbox has no filesystem, \
     network, or environment access.";

pub(crate) fn mcp_description_override_for_adverts(adverts: &[String]) -> Option<ToolDescOverride> {
    if adverts.is_empty() {
        return None;
    }
    let advert_text = adverts
        .iter()
        .map(|line| format!("- {}", line.trim()))
        .collect::<Vec<_>>()
        .join("\n");
    let suffix = format!("\n\nAvailable built-in cockpit functions:\n{advert_text}");
    Some(ToolDescOverride {
        normal: Some(format!("{NORMAL_DESCRIPTION}{suffix}")),
        frontier: Some(format!("{NORMAL_DESCRIPTION}{suffix}")),
        defensive: Some(format!("{DEFENSIVE_DESCRIPTION}{suffix}")),
    })
}

pub(crate) fn apply_mcp_description_adverts(toolbox: &mut ToolBox, adverts: &[String]) -> bool {
    let override_text = mcp_description_override_for_adverts(adverts).unwrap_or_default();
    toolbox.set_override_if_changed("mcp", override_text)
}

pub(crate) fn current_mcp_description_adverts() -> Vec<String> {
    Vec::new()
}

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &str {
        "mcp"
    }

    fn description(&self) -> &str {
        NORMAL_DESCRIPTION
    }

    fn defensive_description(&self) -> Option<String> {
        Some(DEFENSIVE_DESCRIPTION.to_string())
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
        if cfg.has_reserved_builtin_server_config()
            && let Some(text) = ctx.session.mcp_reserved_cockpit_server_notice()
            && let Some(events) = &ctx.events
        {
            let _ = events.send(TurnEvent::Notice { text }).await;
        }
        let host = crate::mcp::builtin::HostContext::from_tool_ctx(ctx);
        match crate::mcp::sandbox::run_with_host(script, &cfg, &host).await {
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
    use crate::config::extended::LlmMode;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingMcpTool {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Tool for CountingMcpTool {
        fn name(&self) -> &str {
            "mcp"
        }

        fn description(&self) -> &str {
            NORMAL_DESCRIPTION
        }

        fn parameters(&self) -> Value {
            self.calls.fetch_add(1, Ordering::SeqCst);
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text("ok"))
        }
    }

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

    #[test]
    fn mcp_description_unchanged_when_no_adverts() {
        let mut toolbox = ToolBox::new().with(Arc::new(McpTool));
        let before = serde_json::to_string(&toolbox.definitions(LlmMode::Normal)).unwrap();

        assert!(!apply_mcp_description_adverts(&mut toolbox, &[]));

        let after = serde_json::to_string(&toolbox.definitions(LlmMode::Normal)).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn mcp_description_includes_adverts() {
        let mut toolbox = ToolBox::new().with(Arc::new(McpTool));
        let adverts = vec!["`cockpit.test_count` - Count test values".to_string()];

        assert!(apply_mcp_description_adverts(&mut toolbox, &adverts));

        let definition = toolbox
            .definitions(LlmMode::Normal)
            .into_iter()
            .find(|definition| definition.name == "mcp")
            .unwrap();
        assert!(
            definition
                .description
                .contains("Available built-in cockpit functions"),
            "{}",
            definition.description
        );
        assert!(
            definition.description.contains("cockpit.test_count"),
            "{}",
            definition.description
        );
    }

    #[test]
    fn advert_flip_invalidates_definition_cache_only_on_change() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut toolbox = ToolBox::new().with(Arc::new(CountingMcpTool {
            calls: calls.clone(),
        }));

        let _ = toolbox.definitions(LlmMode::Normal);
        let _ = toolbox.definitions(LlmMode::Normal);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        assert!(!apply_mcp_description_adverts(&mut toolbox, &[]));
        let _ = toolbox.definitions(LlmMode::Normal);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let first = vec!["`cockpit.test_count` - Count test values".to_string()];
        assert!(apply_mcp_description_adverts(&mut toolbox, &first));
        let _ = toolbox.definitions(LlmMode::Normal);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        assert!(!apply_mcp_description_adverts(&mut toolbox, &first));
        let _ = toolbox.definitions(LlmMode::Normal);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let second = vec!["`cockpit.other` - Other test values".to_string()];
        assert!(apply_mcp_description_adverts(&mut toolbox, &second));
        let _ = toolbox.definitions(LlmMode::Normal);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn config_cockpit_server_id_is_reserved() {
        let tmp = tempfile::tempdir().unwrap();
        let mcp_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&mcp_dir).unwrap();
        std::fs::write(
            mcp_dir.join("mcp.json"),
            r#"{
              "servers": {
                "cockpit": {
                  "transport": "streamable",
                  "endpoint": "https://example.invalid/mcp"
                }
              }
            }"#,
        )
        .unwrap();

        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        ctx.events = Some(tx);

        let tool = McpTool;
        let output = tool
            .call(serde_json::json!({ "script": "mcp.search('')" }), &ctx)
            .await
            .unwrap();
        let hits: Value = serde_json::from_str(&output.content).unwrap();
        assert!(
            hits.as_array()
                .unwrap()
                .iter()
                .all(|hit| hit["server"] != "cockpit"),
            "{}",
            output.content
        );
        let notice = rx.try_recv().expect("expected reserved-id notice");
        assert!(
            matches!(notice, TurnEvent::Notice { ref text } if text.contains("reserved")),
            "unexpected notice: {notice:?}"
        );

        let output = tool
            .call(serde_json::json!({ "script": "mcp.search('')" }), &ctx)
            .await
            .unwrap();
        let hits: Value = serde_json::from_str(&output.content).unwrap();
        assert!(
            hits.as_array()
                .unwrap()
                .iter()
                .all(|hit| hit["server"] != "cockpit"),
            "{}",
            output.content
        );
        assert!(rx.try_recv().is_err(), "notice should be once per session");
    }
}
