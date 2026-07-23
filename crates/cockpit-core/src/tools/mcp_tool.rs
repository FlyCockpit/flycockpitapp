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
use crate::engine::tool::{Tool, ToolBox, ToolCtx, ToolOutput, invalid_input};

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

pub(crate) fn discoverable_tool_adverts(toolbox: &ToolBox) -> Vec<String> {
    let names = toolbox.discoverable_mcp_tool_names();
    let mut adverts = Vec::new();
    push_family_advert(
        &names,
        &mut adverts,
        "intel tail",
        &["word", "hot", "circular", "impact", "change_impact"],
    );
    push_family_advert(
        &names,
        &mut adverts,
        "harness delegation",
        &["harness_list", "harness_invoke"],
    );
    push_family_advert(
        &names,
        &mut adverts,
        "prior sessions",
        &["session_search", "session_read"],
    );
    push_family_advert(
        &names,
        &mut adverts,
        "goal state",
        &["create_goal", "get_goal", "update_goal"],
    );
    push_family_advert(&names, &mut adverts, "code navigation", &["lsp"]);
    push_family_advert(&names, &mut adverts, "skill management", &["skill_manage"]);
    adverts
}

pub(crate) fn turn_start_advert_message(
    toolbox: &ToolBox,
    session: &crate::session::Session,
) -> Option<String> {
    let mut adverts = discoverable_tool_adverts(toolbox);
    if session
        .db
        .current_session_goal(session.id, false)
        .ok()
        .flatten()
        .is_some()
    {
        adverts.push(
            "A goal is active; if context pressure builds (check mcp.invoke(\"cockpit\", \"context_usage\", {})), you may schedule compaction via mcp.invoke(\"cockpit\", \"request_compact\", {})."
                .to_string(),
        );
    }
    advert_message_from_lines(&adverts)
}

pub(crate) fn advert_message_from_lines(adverts: &[String]) -> Option<String> {
    if adverts.is_empty() {
        return None;
    }
    let advert_text = adverts
        .iter()
        .map(|line| format!("- {}", line.trim()))
        .collect::<Vec<_>>()
        .join("\n");
    Some(format!(
        "Available built-in cockpit functions:\n{advert_text}"
    ))
}

fn push_family_advert(
    names: &[String],
    adverts: &mut Vec<String>,
    family: &str,
    family_tools: &[&str],
) {
    let present = family_tools
        .iter()
        .copied()
        .filter(|tool| names.iter().any(|name| name == tool))
        .collect::<Vec<_>>();
    if present.is_empty() {
        return;
    }
    adverts.push(format!(
        "{family}: {} via mcp.invoke(\"cockpit\", ...).",
        present.join("/")
    ));
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

    fn mcp_description(toolbox: &ToolBox, mode: LlmMode) -> String {
        toolbox
            .definitions(mode)
            .into_iter()
            .find(|definition| definition.name == "mcp")
            .unwrap()
            .description
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
    fn mcp_description_is_static_across_catalog_change() {
        let disabled = ToolBox::new().with(Arc::new(McpTool));
        let discoverable = ToolBox::new()
            .with(Arc::new(McpTool))
            .with_discoverable_mcp(Arc::new(crate::tools::intel::WordTool));

        assert_eq!(
            mcp_description(&disabled, LlmMode::Normal),
            mcp_description(&discoverable, LlmMode::Normal)
        );
        assert_eq!(
            mcp_description(&disabled, LlmMode::Defensive),
            mcp_description(&discoverable, LlmMode::Defensive)
        );
    }

    #[test]
    fn mcp_description_has_no_advert_suffix() {
        let toolbox = ToolBox::new()
            .with(Arc::new(McpTool))
            .with_discoverable_mcp(Arc::new(crate::tools::intel::WordTool));

        let normal = mcp_description(&toolbox, LlmMode::Normal);
        let defensive = mcp_description(&toolbox, LlmMode::Defensive);

        assert_eq!(normal, NORMAL_DESCRIPTION);
        assert_eq!(defensive, DEFENSIVE_DESCRIPTION);
        assert!(!normal.contains("Available built-in cockpit functions"));
        assert!(!defensive.contains("Available built-in cockpit functions"));
    }

    #[test]
    fn advert_grouping_keeps_one_line_per_discoverable_family() {
        let toolbox = ToolBox::new()
            .with(Arc::new(McpTool))
            .with_discoverable_mcp(Arc::new(crate::tools::intel::WordTool))
            .with_discoverable_mcp(Arc::new(crate::tools::intel::HotTool))
            .with_discoverable_mcp(Arc::new(crate::tools::harness::HarnessListTool))
            .with_discoverable_mcp(Arc::new(crate::tools::harness::HarnessInvokeTool))
            .with_discoverable_mcp(Arc::new(crate::tools::session_search::SessionSearchTool))
            .with_discoverable_mcp(Arc::new(crate::tools::session_read::SessionReadTool))
            .with_discoverable_mcp(Arc::new(crate::tools::goal::CreateGoalTool))
            .with_discoverable_mcp(Arc::new(crate::tools::goal::GetGoalTool))
            .with_discoverable_mcp(Arc::new(crate::tools::goal::UpdateGoalTool))
            .with_discoverable_mcp(Arc::new(crate::tools::lsp::LspTool))
            .with_discoverable_mcp(Arc::new(crate::tools::skill_manage::SkillManageTool));

        let adverts = discoverable_tool_adverts(&toolbox);

        assert_eq!(adverts.len(), 6, "{adverts:?}");
        for family in [
            "intel tail",
            "harness delegation",
            "prior sessions",
            "goal state",
            "code navigation",
            "skill management",
        ] {
            assert_eq!(
                adverts
                    .iter()
                    .filter(|line| line.starts_with(family))
                    .count(),
                1,
                "{family}: {adverts:?}"
            );
        }
    }

    #[tokio::test]
    async fn model_context_invariance_with_child_events() {
        let tmp = tempfile::tempdir().unwrap();
        let tool = McpTool;
        let args = serde_json::json!({ "script": "mcp.search('context_usage')" });
        let plain_ctx = crate::tools::common::test_ctx(tmp.path());
        let mut child_ctx = crate::tools::common::test_ctx(tmp.path());
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        child_ctx.current_tool_call_id = Some("outer-mcp".to_string());
        child_ctx.events = Some(tx);

        let plain = tool.call(args.clone(), &plain_ctx).await.unwrap();
        let with_children = tool.call(args, &child_ctx).await.unwrap();

        assert_eq!(tool.description(), NORMAL_DESCRIPTION);
        assert_eq!(
            tool.defensive_description().as_deref(),
            Some(DEFENSIVE_DESCRIPTION)
        );
        assert_eq!(plain.content, with_children.content);
        assert_eq!(plain.truncated, with_children.truncated);
    }

    #[test]
    fn advert_compact_follows_goal_state() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let toolbox = ToolBox::new().with(Arc::new(McpTool));

        ctx.session
            .db
            .create_session_goal(
                ctx.session.id,
                &ctx.session.project_id,
                "ship feature",
                None,
                None,
            )
            .unwrap();
        let message = turn_start_advert_message(&toolbox, &ctx.session).unwrap();
        assert!(message.contains("request_compact"), "{message}");
        assert!(message.contains("context_usage"), "{message}");

        ctx.session.db.clear_session_goal(ctx.session.id).unwrap();
        assert!(turn_start_advert_message(&toolbox, &ctx.session).is_none());
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
        assert_no_configured_cockpit_hits(&hits, &output.content);
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
        assert_no_configured_cockpit_hits(&hits, &output.content);
        assert!(rx.try_recv().is_err(), "notice should be once per session");
    }

    fn assert_no_configured_cockpit_hits(hits: &Value, output: &str) {
        let configured_cockpit_hits = hits
            .as_array()
            .unwrap()
            .iter()
            .filter(|hit| hit["server"] == "cockpit")
            .filter(|hit| {
                !matches!(
                    hit["tool"].as_str(),
                    Some("rename_session" | "request_compact" | "context_usage")
                )
            })
            .count();
        assert_eq!(configured_cockpit_hits, 0, "{output}");
    }
}
