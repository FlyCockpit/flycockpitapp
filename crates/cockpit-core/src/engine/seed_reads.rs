//! Read-only tool calls selected by an explore warm-cache fork.
//!
//! Seeds contain calls, never results. The implementation child executes them
//! through ordinary tool dispatch before its first inference, so authorization,
//! sandboxing, schema repair, and freshness remain owned by that child.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex};

use crate::engine::message::{AssistantContent, Message, collect_tool_calls};

/// The complete launch allowlist. Keep this closed and name-based: accepting a
/// newly read-only effect classification here by accident would widen the
/// cross-agent capability without an explicit product decision.
pub const ALLOWED_SEED_READ_TOOLS: &[&str] = &["read", "grep", "code", "graph", "search"];
const COMPLETION_NOTICE: &str = "The host executed the explore-selected read-only seed calls above. Use their fresh results and continue with the delegated implementation brief without rediscovering them.";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedRead {
    pub tool: String,
    #[serde(default)]
    pub args: Value,
}

/// Host-authored output of an ephemeral explore selection. The opaque receipt
/// proves the calls crossed the Monty-only fork boundary; the parent must pass
/// it with the unchanged list to the single allowed implementation handoff.
#[derive(Debug, Clone, PartialEq)]
pub struct SeedReadSelection {
    pub calls: Vec<SeedRead>,
    pub receipt: Option<String>,
}

impl SeedReadSelection {
    fn empty() -> Self {
        Self {
            calls: Vec::new(),
            receipt: None,
        }
    }
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
    sealed_egress: Arc<crate::redact::RedactionTable>,
) -> SeedReadSelection {
    if agent_name != "explore" || cancel.is_cancelled() {
        return SeedReadSelection::empty();
    }
    let slot = Arc::new(Mutex::new(None));
    let host = crate::mcp::builtin::HostContext::seed_reads_fork(
        session.clone(),
        cwd,
        config,
        slot.clone(),
    );
    let prompt = Message::user(
        "Select only the read-only calls an implementation subagent should rerun before its first inference to avoid rediscovery while keeping results fresh. Call Monty exactly once with a script that invokes mcp.invoke('cockpit', 'seed_reads', {'calls': [...]}); each call is {'tool': one of read/grep/code/graph/search, 'args': {...}}. The script may compute the list programmatically. Do not execute the calls and do not explain.",
    );
    let call_id = uuid::Uuid::new_v4();
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
            Some(sealed_egress.as_ref()),
        )
        .await;
    let Ok(((_, content, usage), captured, _)) = completion else {
        return SeedReadSelection::empty();
    };
    // This is a real provider inference even though its output is consumed
    // only by the host. Keep the captured request, token cost, and timeline
    // metadata joined by one call id so `/stats`, context usage, and export do
    // not under-report the explore → implementation handoff.
    let session_table = model.session_redact_table();
    if let Err(error) = session
        .record_inference_request(
            call_id,
            &captured,
            crate::db::session_log::InferenceRequestStatus::Completed,
            session_table.as_ref(),
            model.is_trusted(),
        )
        .await
    {
        tracing::warn!(%error, "recording seed-read selection request failed");
    }
    if let Some(usage) = usage
        && let Err(error) = session.record_usage_utility(call_id, usage).await
    {
        tracing::warn!(%error, "recording seed-read selection usage failed");
    }
    if let Err(error) = session
        .record_event(
            crate::db::session_log::SessionEventKind::InferenceRequest,
            Some(agent_name),
            Some(&call_id.to_string()),
            &serde_json::json!({
                "purpose": "seed_read_selection",
                "usage": usage.map(|usage| serde_json::json!({
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "cached_input_tokens": usage.cached_input_tokens,
                    "cache_creation_input_tokens": usage.cache_creation_input_tokens,
                })),
            }),
        )
        .await
    {
        tracing::warn!(%error, "recording seed-read selection completion failed");
    }
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
        return SeedReadSelection::empty();
    };
    if crate::mcp::sandbox::run_with_host(&script, &crate::mcp::config::McpConfig::default(), &host)
        .await
        .is_err()
    {
        return SeedReadSelection::empty();
    }
    let calls = slot
        .lock()
        .ok()
        .and_then(|mut selected| selected.take())
        .unwrap_or_default();
    let receipt = (!calls.is_empty() && session.parent_session_id.is_none())
        .then(|| session.issue_seed_read_receipt(&calls));
    SeedReadSelection { calls, receipt }
}

pub fn append_to_report(mut report: String, selection: &SeedReadSelection) -> String {
    let payload = serde_json::json!({
        "seed_reads": selection.calls,
        "seed_reads_receipt": selection.receipt,
    });
    report.push_str("\n\n## Seed reads\n");
    report.push_str(&payload.to_string());
    report.push('\n');
    report
}

/// Enforce the cross-agent ownership boundary before a structural `task`
/// outcome exists. Only the root `Build` agent may redeem the one-use receipt,
/// and only to the implementation `builder` role.
pub fn authorize_handoff(
    session: &crate::session::Session,
    parent_agent: &crate::engine::agent::Agent,
    child_agent: &str,
    seed_reads: &[SeedRead],
    receipt: Option<&str>,
) -> Result<(), String> {
    if seed_reads.is_empty() {
        return if receipt.is_some() {
            Err("seed_reads_receipt requires a non-empty seed_reads list".to_string())
        } else {
            Ok(())
        };
    }
    if parent_agent.delegated || parent_agent.name != "Build" {
        return Err("seed_reads may be redeemed only by the root Build agent".to_string());
    }
    if child_agent != "builder" {
        return Err("seed_reads may target only the builder implementation agent".to_string());
    }
    let receipt = receipt
        .filter(|receipt| !receipt.trim().is_empty())
        .ok_or_else(|| "seed_reads require the host-issued explore receipt".to_string())?;
    session.consume_seed_read_receipt(receipt, seed_reads)
}

/// Synthetic seed calls already declared in history but lacking a paired tool
/// result. This is the replay continuation source: it preserves the original
/// call IDs so a parked seed can be resumed without dropping later seeds.
pub fn pending_declared_seed_calls(history: &[Message]) -> Vec<crate::engine::message::ToolCall> {
    let completed_call_ids = history
        .iter()
        .filter_map(|message| match message {
            Message::User { content } => Some(content),
            _ => None,
        })
        .flatten()
        .filter_map(|part| match part {
            rig::message::UserContent::ToolResult(result) => Some(result.call.as_str()),
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();
    history
        .iter()
        .filter_map(|message| match message {
            Message::Assistant { content, .. } => Some(content),
            _ => None,
        })
        .flatten()
        .filter_map(|part| match part {
            AssistantContent::ToolCall(call)
                if call.id.as_str().starts_with("seed-read-")
                    && !completed_call_ids.contains(call.id.as_str()) =>
            {
                SeedRead {
                    tool: call.function.name.clone(),
                    args: call.function.arguments.clone(),
                }
                .validate()
                .ok()
                .map(|_| call.clone())
            }
            _ => None,
        })
        .collect()
}

pub fn completion_prompt() -> Message {
    Message::user(COMPLETION_NOTICE)
}

/// Return only seeds whose synthetic call does not yet have its paired tool
/// result in recovered history. A declaration is deliberately insufficient:
/// crashes, cancellation, and dispatch errors can occur after the host writes
/// the batch declaration but before every call crosses the child's ordinary
/// dispatch boundary.
pub fn remaining_seed_reads(history: &[Message], seed_reads: Vec<SeedRead>) -> Vec<SeedRead> {
    let completed_call_ids = history
        .iter()
        .filter_map(|message| match message {
            Message::User { content } => Some(content),
            _ => None,
        })
        .flatten()
        .filter_map(|part| match part {
            rig::message::UserContent::ToolResult(result) => Some(result.call.as_str()),
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();
    let mut completed = history
        .iter()
        .filter_map(|message| match message {
            Message::Assistant { content, .. } => Some(content),
            _ => None,
        })
        .flatten()
        .filter_map(|part| match part {
            AssistantContent::ToolCall(call)
                if call.id.as_str().starts_with("seed-read-")
                    && completed_call_ids.contains(call.id.as_str()) =>
            {
                SeedRead {
                    tool: call.function.name.clone(),
                    args: call.function.arguments.clone(),
                }
                .validate()
                .ok()
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    seed_reads
        .into_iter()
        .filter(|seed| {
            if let Some(index) = completed.iter().position(|completed| completed == seed) {
                completed.remove(index);
                false
            } else {
                true
            }
        })
        .collect()
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
    execute_declared_seed_calls(&env, history, calls).await
}

pub async fn execute_declared_seed_calls(
    env: &crate::engine::agent::tool_dispatch::DispatchEnv<'_>,
    history: &mut Vec<Message>,
    calls: Vec<crate::engine::message::ToolCall>,
) -> anyhow::Result<()> {
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

    fn synthetic_seed_call(id: &str, seed: &SeedRead) -> crate::engine::message::ToolCall {
        use rig::message::{ToolCallId, ToolFunction};

        crate::engine::message::ToolCall {
            id: ToolCallId::new_or_mint(id),
            provider: None,
            function: ToolFunction {
                name: seed.tool.clone(),
                arguments: seed.args.clone(),
            },
            signature: None,
            additional_params: None,
        }
    }

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

    #[test]
    fn recovery_retries_only_seed_reads_without_a_paired_result() {
        let first = SeedRead {
            tool: "read".to_string(),
            args: serde_json::json!({"path": "already-read.rs"}),
        };
        let second = SeedRead {
            tool: "grep".to_string(),
            args: serde_json::json!({"pattern": "still-needed", "path": "src"}),
        };
        let first_call = synthetic_seed_call("seed-read-first", &first);
        let second_call = synthetic_seed_call("seed-read-second", &second);
        let history = vec![
            Message::Assistant {
                id: None,
                content: vec![
                    AssistantContent::ToolCall(first_call.clone()),
                    AssistantContent::ToolCall(second_call),
                ],
            },
            crate::engine::message::tool_result_message(&first_call, "fresh result".to_string()),
        ];

        assert_eq!(
            remaining_seed_reads(&history, vec![first, second.clone()]),
            vec![second],
            "a seed declaration is not completion; only its paired tool result suppresses replay"
        );
    }

    #[test]
    fn parked_seed_replay_retains_declared_suffix_by_original_call_id() {
        let first = SeedRead {
            tool: "read".to_string(),
            args: serde_json::json!({"path": "first.rs"}),
        };
        let second = SeedRead {
            tool: "grep".to_string(),
            args: serde_json::json!({"pattern": "second", "path": "src"}),
        };
        let first_call = synthetic_seed_call("seed-read-first", &first);
        let second_call = synthetic_seed_call("seed-read-second", &second);
        let history = vec![
            Message::Assistant {
                id: None,
                content: vec![
                    AssistantContent::ToolCall(first_call.clone()),
                    AssistantContent::ToolCall(second_call.clone()),
                ],
            },
            crate::engine::message::tool_result_message(&first_call, "approved".to_string()),
        ];

        assert_eq!(
            pending_declared_seed_calls(&history),
            vec![second_call],
            "after a parked seed replays, the driver must retain every later declared seed for ordinary dispatch"
        );
    }
}
