//! Read-only tool calls selected by an explore warm-cache fork.
//!
//! Seeds contain calls, never results. The implementation child executes them
//! through ordinary tool dispatch before its first inference, so authorization,
//! sandboxing, schema repair, and freshness remain owned by that child.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex};

use crate::engine::message::{Message, collect_tool_calls};

/// The complete launch allowlist. Keep this closed and name-based: accepting a
/// newly read-only effect classification here by accident would widen the
/// cross-agent capability without an explicit product decision.
pub const ALLOWED_SEED_READ_TOOLS: &[&str] = &["read", "grep", "code", "graph", "search"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedRead {
    pub tool: String,
    #[serde(default)]
    pub args: Value,
}

impl SeedRead {
    pub fn validate(self) -> Result<Self, String> {
        if !ALLOWED_SEED_READ_TOOLS.contains(&self.tool.as_str()) {
            return Err(format!(
                "seed_reads rejects non-read-only tool `{}`; allowed tools: {}",
                self.tool,
                ALLOWED_SEED_READ_TOOLS.join(", ")
            ));
        }
        if !self.args.is_object() {
            return Err(format!(
                "seed_reads tool `{}` requires `args` to be an object",
                self.tool
            ));
        }
        Ok(self)
    }
}

pub fn parse_seed_reads(value: Option<&Value>) -> Result<Vec<SeedRead>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let calls = value
        .as_array()
        .ok_or_else(|| "seed_reads must be an array".to_string())?;
    if calls.len() > 32 {
        return Err("seed_reads accepts at most 32 calls".to_string());
    }
    calls
        .iter()
        .map(|call| {
            serde_json::from_value::<SeedRead>(call.clone())
                .map_err(|error| format!("invalid seed_reads entry: {error}"))?
                .validate()
        })
        .collect()
}

/// Ask a same-model ephemeral fork of the completed explore transcript which
/// discoveries the implementation child should refresh. The fork receives the
/// exact base native tool block; `seed_reads` exists only in its Monty host
/// catalog. Prose and non-Monty calls are ignored.
#[allow(clippy::too_many_arguments)]
pub async fn select_from_explore_fork(
    session: Arc<crate::session::Session>,
    model: Arc<crate::engine::model::Model>,
    system: &str,
    agent_name: &str,
    params: crate::engine::model::ModelParams,
    history: &[Message],
    tools: Vec<crate::engine::message::ToolDefinition>,
    cwd: std::path::PathBuf,
    config: crate::daemon::session_worker::SessionConfigHandle,
    cancel: tokio_util::sync::CancellationToken,
    sealed_egress: Option<Arc<crate::redact::RedactionTable>>,
) -> Vec<SeedRead> {
    if agent_name != "explore" || cancel.is_cancelled() {
        return Vec::new();
    }
    let slot = Arc::new(Mutex::new(None));
    let host = crate::mcp::builtin::HostContext::seed_reads_fork(
        session,
        cwd,
        config,
        slot.clone(),
    );
    let prompt = Message::user(
        "Select only the read-only calls an implementation subagent should rerun before its first inference to avoid rediscovery while keeping results fresh. Call Monty exactly once with a script that invokes mcp.invoke('cockpit', 'seed_reads', {'calls': [...]}); each call is {'tool': one of read/grep/code/graph/search, 'args': {...}}. The script may compute the list programmatically. Do not execute the calls and do not explain.",
    );
    let completion = model
        .complete_captured_with_sealed_egress(
            system,
            history,
            prompt,
            &tools,
            params,
            agent_name,
            false,
            &cancel,
            sealed_egress.as_deref(),
        )
        .await;
    let Ok(((_, content, _), _, _)) = completion else {
        return Vec::new();
    };
    let Some(script) = collect_tool_calls(&content)
        .into_iter()
        .find(|call| call.function.name == "mcp")
        .and_then(|call| {
            call.function
                .arguments
                .get("script")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
    else {
        return Vec::new();
    };
    if crate::mcp::sandbox::run_with_host(
        &script,
        &crate::mcp::config::McpConfig::default(),
        &host,
    )
    .await
    .is_err()
    {
        return Vec::new();
    }
    slot.lock()
        .ok()
        .and_then(|mut selected| selected.take())
        .unwrap_or_default()
}

pub fn append_to_report(mut report: String, seed_reads: &[SeedRead]) -> String {
    if seed_reads.is_empty() {
        return report;
    }
    let payload = serde_json::json!({"seed_reads": seed_reads});
    report.push_str("\n\n## Seed reads\n");
    report.push_str(&payload.to_string());
    report.push('\n');
    report
}

pub fn history_contains_seed_reads(history: &[Message]) -> bool {
    history.iter().any(|message| {
        let Message::Assistant { content, .. } = message else {
            return false;
        };
        content.iter().any(|part| {
            matches!(
                part,
                crate::engine::message::AssistantContent::ToolCall(call)
                    if call.id.as_ref().starts_with("seed-read-")
            )
        })
    })
}

/// Execute seeds through the same ordinary-call boundary used for model-authored
/// calls. The caller supplies the implementation child's full `ToolCtx`; this
/// deliberately preserves its permission, sandbox, lease, hook, and timeout
/// checks instead of treating seeds as trusted host reads.
#[allow(clippy::too_many_arguments)]
pub async fn execute_before_first_inference(
    agent: &crate::engine::agent::Agent,
    active_tools: &crate::engine::tool::ToolBox,
    ctx: &crate::engine::tool::ToolCtx,
    tx: &tokio::sync::mpsc::Sender<crate::engine::agent::TurnEvent>,
    history: &mut Vec<Message>,
    seed_reads: &[SeedRead],
    session: &Arc<crate::session::Session>,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    cwd: &std::path::Path,
    loop_guard_threshold: u32,
) -> anyhow::Result<()> {
    use rig::message::{ToolCall, ToolFunction};

    if seed_reads.is_empty() {
        return Ok(());
    }
    let calls = seed_reads
        .iter()
        .cloned()
        .map(SeedRead::validate)
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .map(|seed| ToolCall {
            id: rig::message::ToolCallId::new_or_mint(format!(
                "seed-read-{}",
                uuid::Uuid::now_v7()
            )),
            provider: None,
            function: ToolFunction {
                name: seed.tool,
                arguments: seed.args,
            },
            signature: None,
            additional_params: None,
        })
        .collect::<Vec<_>>();
    history.push(Message::Assistant {
        id: None,
        content: calls
            .iter()
            .cloned()
            .map(crate::engine::message::AssistantContent::ToolCall)
            .collect(),
    });
    let snapshot = config.snapshot();
    let env = crate::engine::agent::tool_dispatch::DispatchEnv {
        agent,
        session,
        model: &agent.model,
        active_tools,
        ctx,
        tx,
        hint_corrections: crate::engine::agent::hint_tool_call_corrections_enabled(session, config),
        loop_guard_threshold,
        cwd,
        hooks: snapshot.hooks(),
    };
    for call in calls {
        let name = call.function.name.clone();
        crate::engine::agent::tool_dispatch::execute_ordinary_call(
            &env,
            history,
            &call,
            &name,
            crate::db::tool_calls::Recovery::Clean,
            None,
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_mutating_seed_call() {
        let error = parse_seed_reads(Some(&serde_json::json!([
            {"tool": "write", "args": {"path": "src/lib.rs", "content": "bad"}}
        ])))
        .unwrap_err();
        assert!(error.contains("non-read-only tool `write`"), "{error}");
    }

    #[test]
    fn accepts_closed_read_allowlist() {
        for tool in ALLOWED_SEED_READ_TOOLS {
            let calls = parse_seed_reads(Some(&serde_json::json!([
                {"tool": tool, "args": {}}
            ])))
            .unwrap();
            assert_eq!(calls[0].tool, *tool);
        }
    }
}
