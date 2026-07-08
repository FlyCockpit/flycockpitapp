//! Utility-model command-safety gate (implementation note).
//!
//! The engine behind the `auto` *approval mode*
//! ([`crate::config::extended::ApprovalMode::Auto`]). Each gated tool call
//! (`bash`, `webfetch`, `mcp`) is sent — **with no conversation
//! history** — to the utility model for a structured safety verdict before
//! it runs: a `safe` verdict runs without prompting, an `unsafe` one
//! escalates to the user through the existing approval prompt. The verdict
//! also carries whether the call's *result* must be re-checked for prompt
//! injection (set true for calls that pull in external/untrusted content,
//! e.g. fetching a tweet).
//!
//! This is the safety twin of [`crate::engine::injection_check`]: same
//! one-shot, history-free [`crate::engine::model::Model::tool_completion`]
//! pattern (forced structured tool call), a `safety` tool instead of
//! `risk`. The result re-check itself reuses `injection_check` directly —
//! we do not reimplement the nonce/`risk` mechanism here.
//!
//! ## Fail CLOSED (the opposite of the inbound injection scan)
//!
//! The inbound prompt-injection scan fails *open* — a missing/broken
//! utility model proceeds unscanned. The command-safety gate fails
//! **closed**: when the verdict can't be obtained
//! ([`SafetyOutcome::Unavailable`]), the gated call is treated as
//! requiring user approval rather than silently running. Running a command
//! the gate couldn't vet would defeat `auto` mode's whole purpose, so the
//! safe default is "ask the user".

use std::time::Duration;

use serde_json::json;

use crate::config::providers::ProvidersConfig;
use crate::engine::message::ToolDefinition;

/// Timeout for the utility-model safety call. The verdict gates a tool
/// call, so a stalled provider resolves to [`SafetyOutcome::Unavailable`]
/// (fail closed → ask the user) rather than holding the call open.
pub const SAFETY_TIMEOUT: Duration = Duration::from_secs(20);

/// The structured tool name the utility model answers the safety verdict
/// through.
pub const SAFETY_TOOL_NAME: &str = "safety";

/// The structured safety verdict the gate read back from the utility
/// model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyVerdict {
    /// Whether the call is safe to run without prompting the user.
    pub safe: bool,
    /// Whether the call's result must be re-checked for prompt injection
    /// after it runs (external/untrusted content was pulled in).
    pub recheck_result: bool,
}

/// Outcome of one safety-gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyOutcome {
    /// The model returned a usable verdict.
    Rated(SafetyVerdict),
    /// The verdict could not be obtained (no utility model, unbuildable
    /// model, the call errored / timed out, or the model returned no usable
    /// verdict). Callers **fail closed** — escalate to the user.
    Unavailable,
}

/// The `safety` tool definition advertised to the utility model. Two
/// required booleans. Terse per the token-economy rule (GOALS §10).
fn safety_tool() -> ToolDefinition {
    ToolDefinition {
        name: SAFETY_TOOL_NAME.to_string(),
        description: "Report whether the single command/call is safe to run and whether its result needs an injection re-check."
            .to_string(),
        parameters: json!({
            "type": "object",
            "properties": {
                "safe": {
                    "type": "boolean",
                    "description": "safe to run unprompted",
                },
                "recheck_result": {
                    "type": "boolean",
                    "description": "result pulls external content and needs an injection re-check",
                }
            },
            "required": ["safe", "recheck_result"],
        }),
    }
}

/// Fixed system instruction for the safety call. Kept minimal; reinforces
/// the no-history, judge-on-its-own-merits, answer-through-the-tool
/// contract.
const SAFETY_SYSTEM: &str = "You are a command-safety classifier for an AI coding agent. You are shown a \
     SINGLE shell command or network tool call, with no conversation context. Judge it on its own \
     merits: is it safe to run without asking the user (no destructive, exfiltrating, or \
     system-compromising effect)? Also decide whether its result will pull in external/untrusted \
     content (a fetched web page, an API response, a tweet) that should be re-checked for prompt \
     injection. Report your verdict only by calling the `safety` tool.";

/// Build the single-call evaluation message: the tool name plus the
/// command/call payload, fenced as data. History-free — this is the only
/// content the model sees.
fn build_eval_message(tool: &str, payload: &str) -> String {
    format!("Tool: `{tool}`\nCall to evaluate:\n{payload}")
}

/// Run one history-free safety evaluation on a single gated call.
///
/// `provider_model` is the `"provider:model-id"` selector (the utility
/// model). `tool` is the gated tool's name (`bash`/`webfetch`/`mcp`)
/// and `payload` is the single command/call to judge — the model sees ONLY
/// this, never conversation history. Returns [`SafetyOutcome::Unavailable`]
/// for every failure path (unset/unparseable/unbuildable model, send error,
/// timeout, no usable verdict) so callers fail **closed**.
pub async fn evaluate(
    provider_model: Option<&str>,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
    tool: &str,
    payload: &str,
) -> SafetyOutcome {
    match evaluate_inner(
        provider_model,
        providers,
        redact,
        trusted_only,
        tool,
        payload,
    )
    .await
    {
        Some(verdict) => SafetyOutcome::Rated(verdict),
        None => SafetyOutcome::Unavailable,
    }
}

async fn evaluate_inner(
    provider_model: Option<&str>,
    providers: &ProvidersConfig,
    redact: std::sync::Arc<crate::redact::RedactionTable>,
    trusted_only: std::sync::Arc<std::sync::atomic::AtomicBool>,
    tool: &str,
    payload: &str,
) -> Option<SafetyVerdict> {
    let model_ref = provider_model?;
    let model = match crate::engine::model::Model::from_ref_trusted_only(
        providers,
        model_ref,
        redact,
        trusted_only,
    ) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(error = %e, "safety_gate: model build failed; failing closed");
            return None;
        }
    };

    let message = build_eval_message(tool, payload);
    let safety = safety_tool();

    let calls = match tokio::time::timeout(
        SAFETY_TIMEOUT,
        model.tool_completion(SAFETY_SYSTEM, &message, &safety),
    )
    .await
    {
        Ok(Ok(calls)) => calls,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "safety_gate: call failed; failing closed");
            return None;
        }
        Err(_) => {
            tracing::debug!("safety_gate: call timed out; failing closed");
            return None;
        }
    };

    parse_verdict(&calls)
}

/// Pull the `safety` verdict out of the model's tool call. The first
/// `safety` call's `safe` + `recheck_result` booleans are read; a missing
/// `safe` (or no `safety` call at all) reads as no usable verdict (`None` →
/// fail closed). A missing `recheck_result` defaults to `false` (don't
/// re-check) — the conservative side for the re-check flag specifically.
fn parse_verdict(calls: &[crate::engine::message::ToolCall]) -> Option<SafetyVerdict> {
    let call = calls.iter().find(|c| c.function.name == SAFETY_TOOL_NAME)?;
    let safe = call.function.arguments.get("safe")?.as_bool()?;
    let recheck_result = call
        .function
        .arguments
        .get("recheck_result")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Some(SafetyVerdict {
        safe,
        recheck_result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(name: &str, args: serde_json::Value) -> crate::engine::message::ToolCall {
        crate::engine::message::ToolCall {
            id: "1".into(),
            call_id: None,
            function: rig::message::ToolFunction {
                name: name.into(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        }
    }

    #[test]
    fn parse_verdict_reads_safe_and_recheck() {
        // safe + needs re-check.
        assert_eq!(
            parse_verdict(&[mk(
                "safety",
                json!({ "safe": true, "recheck_result": true })
            )]),
            Some(SafetyVerdict {
                safe: true,
                recheck_result: true
            })
        );
        // unsafe + no re-check.
        assert_eq!(
            parse_verdict(&[mk(
                "safety",
                json!({ "safe": false, "recheck_result": false })
            )]),
            Some(SafetyVerdict {
                safe: false,
                recheck_result: false
            })
        );
        // Missing `recheck_result` defaults to false (don't re-check).
        assert_eq!(
            parse_verdict(&[mk("safety", json!({ "safe": true }))]),
            Some(SafetyVerdict {
                safe: true,
                recheck_result: false
            })
        );
    }

    #[test]
    fn parse_verdict_unknown_or_missing_fails_safe() {
        // No `safety` call at all → no verdict (caller fails closed).
        assert_eq!(parse_verdict(&[mk("other", json!({ "safe": true }))]), None);
        // Missing the required `safe` field → no verdict.
        assert_eq!(
            parse_verdict(&[mk("safety", json!({ "recheck_result": true }))]),
            None
        );
        // Wrong type for `safe` → no verdict.
        assert_eq!(
            parse_verdict(&[mk("safety", json!({ "safe": "yes" }))]),
            None
        );
        // No tool calls → no verdict.
        assert_eq!(parse_verdict(&[]), None);
    }

    #[tokio::test]
    async fn evaluate_unavailable_when_utility_model_unset() {
        let providers = ProvidersConfig::default();
        let outcome = evaluate(
            None,
            &providers,
            std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            "bash",
            "rm -rf /",
        )
        .await;
        assert_eq!(
            outcome,
            SafetyOutcome::Unavailable,
            "an unset utility model must be Unavailable (caller fails closed)"
        );
    }

    #[tokio::test]
    async fn evaluate_unavailable_when_model_ref_malformed() {
        let providers = ProvidersConfig::default();
        let outcome = evaluate(
            Some("no-colon-here"),
            &providers,
            std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            "bash",
            "ls",
        )
        .await;
        assert_eq!(outcome, SafetyOutcome::Unavailable);
    }

    #[test]
    fn eval_message_carries_tool_and_payload_without_history() {
        let msg = build_eval_message("webfetch", "{\"url\":\"https://x.com/foo\"}");
        assert!(msg.contains("webfetch"));
        assert!(msg.contains("https://x.com/foo"));
    }
}
