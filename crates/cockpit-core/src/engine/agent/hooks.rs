//! Fail-open local command hooks across the agent lifecycle.
//!
//! This module owns the core-private hook dispatcher and command runner. It
//! consumes the typed resolver ([`crate::config::extended::hooks::HookRegistry`])
//! and the durable ledger ([`crate::db::session_log::HookRunAudit`]) foundations;
//! it does not create an independent configuration parser or a second tool-policy
//! engine.
//!
//! ## Enforcement model
//!
//! Pre hooks are **fail-open**: a hook can deny only by printing valid JSON
//! `{"decision":"deny","reason":"..."}` to stdout. Exit status alone never
//! denies. A pre-hook crash, timeout, spawn failure, malformed output, oversized
//! output, or nonzero exit other than an explicit parseable deny are recorded
//! as failed hook runs and allow existing agent execution to continue.
//!
//! Post and observe-only hooks never block; they run sequentially even if an
//! earlier observer fails.
//!
//! ## Environment
//!
//! The runner resolves a bare executable before `env_clear` using Cockpit's
//! parent-process executable lookup, then spawns the resolved absolute path.
//! The child receives configured hook env only; it never receives a host
//! `PATH`. Reserved keys are overwritten after configured env.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::config::extended::hooks::{HookEvent, HookRegistry, ResolvedHook};
use crate::db::session_log::{HookRunAudit, HookRunStatus};

/// Maximum size for serialized `toolInput` / `toolResult` envelope values
/// (128 KiB). Excess is replaced with a UTF-8-safe prefix and the
/// corresponding `toolInputTruncated` / `toolResultTruncated` boolean is set.
pub(crate) const ENVELOPE_VALUE_MAX_BYTES: usize = 128 * 1024;

/// Independent cap for stdout and stderr (64 KiB each).
pub(crate) const OUTPUT_CAP_BYTES: usize = 64 * 1024;

/// Maximum UTF-8-safe character length for a denial reason (1,024 chars).
pub(crate) const REASON_MAX_CHARS: usize = 1_024;

/// Default reason when a deny has a missing/blank reason.
pub(crate) const DEFAULT_DENY_REASON: &str = "blocked by preToolUse hook";

/// Closed, durable failure-reason vocabulary for hook execution.  Keep these
/// human-readable: the exact values are written to `hook_run.reason`, exposed
/// by the documentation contract, and asserted by import/rehydration tests.
pub(crate) const REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED: &str =
    "descendant_containment_unsupported";
pub(crate) const REASON_HOOK_TIMED_OUT: &str = "hook timed out";
pub(crate) const REASON_SPAWN_FAILED: &str = "spawn failed";
pub(crate) const REASON_EXECUTABLE_NOT_FOUND: &str = "executable not found";
pub(crate) const REASON_MALFORMED_JSON_OUTPUT: &str = "malformed JSON output";
pub(crate) const REASON_OUTPUT_LIMIT_EXCEEDED: &str = "hook output exceeded limit";
pub(crate) const REASON_NONZERO_EXIT_PREFIX: &str = "hook exited with non-zero status";
pub(crate) const REASON_NO_EXIT_STATUS: &str = "hook exited without status";
pub(crate) const REASON_PIPE_IO_FAILED: &str = "hook pipe I/O failed";
pub(crate) const REASON_HOOK_CANCELLED: &str = "hook cancelled";
pub(crate) const REASON_CONTAINMENT_ACTOR_UNAVAILABLE: &str =
    "containment cleanup authority unavailable";
pub(crate) const REASON_OUTPUT_NOT_JSON_OBJECT: &str = "output is not a JSON object";
pub(crate) const REASON_MALFORMED_HOOK_OUTPUT: &str = "malformed hook output";
pub(crate) const REASON_UNEXPECTED_PRE_TOOL_BLOCK: &str =
    "unexpected decision 'block' for pre-tool event";
pub(crate) const REASON_UNEXPECTED_STOP_DENY: &str =
    "unexpected decision 'deny' for stop event";
pub(crate) const REASON_UNKNOWN_OR_MISSING_DECISION: &str = "unknown or missing decision";
pub(crate) const STOP_HOOK_FORCED_END_SOURCE: &str = "stop_hook_continuation_cap";

/// Typed ownership map for native lifecycle boundaries. This is kept beside
/// dispatch—not in README prose—so documentation tests can prove exhaustive
/// classification without brittle source-text searches. Boundary tests still
/// drive the named production seams; this table makes a newly-added event fail
/// exhaustiveness review until it has an owner.
pub(crate) const PRODUCTION_HOOK_BOUNDARIES: &[(HookEvent, &str)] = &[
    (HookEvent::SessionStart, "session_worker.rehydrated"),
    (HookEvent::UserPromptSubmit, "driver.accepted_submission"),
    (HookEvent::PreToolUse, "tool_dispatch.pre_execution"),
    (HookEvent::PostToolUse, "tool_dispatch.success"),
    (HookEvent::PostToolUseFailure, "tool_dispatch.failure"),
    (HookEvent::PermissionDenied, "tool_dispatch.permission_denied"),
    (HookEvent::Stop, "driver.root_normal_done"),
    (HookEvent::StopFailure, "driver.inference_failure"),
    (HookEvent::SubagentStart, "driver.child_started"),
    (HookEvent::SubagentStop, "child.normal_or_abnormal_terminal"),
    (HookEvent::PreCompact, "driver.compaction_apply"),
    (HookEvent::PostCompact, "driver.compaction_durable"),
    (HookEvent::SessionEnd, "session_worker.teardown"),
];

/// Reserved environment keys overwritten after configured env.
pub(crate) const RESERVED_ENV_KEYS: &[&str] = &[
    "COCKPIT_HOOK_EVENT",
    "COCKPIT_HOOK_NAME",
    "COCKPIT_SESSION_ID",
    "COCKPIT_WORKSPACE_ROOT",
    "COCKPIT_TOOL_NAME",
    "COCKPIT_TOOL_CALL_ID",
];

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// Cockpit-native JSON envelope sent to a hook command on stdin.
///
/// camelCase JSON containing `hookEventName`, `sessionId`, `workspaceRoot`,
/// `timestamp`, `toolName`, `toolCallId`, `toolInput`, and event-specific
/// `toolResult` or `toolError`. Input/result values are serialized to a maximum
/// 128 KiB each; excess is replaced with a UTF-8-safe prefix and the
/// corresponding truncated boolean is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HookEnvelope {
    pub hook_event_name: String,
    pub session_id: String,
    pub workspace_root: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_input: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_input_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_result_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `sessionStart` discriminator: `fresh` | `resume`. First-class typed
    /// field (Decision 8) — not overloaded onto generic `source`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_source: Option<String>,
    /// `userPromptSubmit` discriminator: `user` | `queued`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_source: Option<String>,
    /// `permissionDenied` discriminator: the existing deny status string
    /// already produced at the ordinary-tool deny site.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_kind: Option<String>,
    /// `stopFailure` discriminator: the stable inference error-class token
    /// from [`error_class_match_value`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// `preCompact` / `postCompact` discriminator: `manual` | `auto`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compact_source: Option<String>,
    /// Stable idempotency identity shared by the pre/post compact pair.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_id: Option<String>,
    /// End-reason discriminator (Decision 8) — a first-class typed field, not
    /// overloaded onto the generic `reason` key. Carries the `subagentStop`
    /// child-stop reason (e.g. `completed`, `aborted`) and, for `sessionEnd`,
    /// the same closed `WorkerStop`-derived token used as the matcher
    /// (`completed` | `interrupted` | `cancelled` | `shutdown` | `error`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<String>,
    /// `stop` discriminator (Decision 8): the reason the root turn is stopping
    /// — the same closed matcher token (`end_turn`). A first-class typed field,
    /// deliberately NOT overloaded onto the generic `source`/`reason` keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    /// `stop` re-entrancy flag (Decision 8): `true` while the turn is already
    /// inside a stop-hook continuation loop for this `(session, root frame,
    /// originating user turn)`, so a stop hook can detect and avoid looping
    /// forever. `false`/absent on the first consultation of a turn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_hook_active: Option<bool>,
}

/// Typed, camelCase observe-envelope discriminators (Decision 8 / F1).
///
/// Each observe event populates exactly the field(s) meaningful to it; the
/// rest stay `None` and are omitted from the serialized JSON. These are
/// first-class typed fields, deliberately NOT overloaded onto the generic
/// `source` / `reason` keys.
#[derive(Debug, Clone, Default)]
pub(crate) struct ObserveFields<'a> {
    pub start_source: Option<&'a str>,
    pub prompt_source: Option<&'a str>,
    pub permission_kind: Option<&'a str>,
    pub error_class: Option<&'a str>,
    pub compact_source: Option<&'a str>,
    pub compaction_id: Option<&'a str>,
    /// `subagentStop` child-stop reason (envelope `endReason`).
    pub end_reason: Option<&'a str>,
    /// `stop` reason (envelope `stopReason`) — the closed matcher token
    /// (`end_turn`).
    pub stop_reason: Option<&'a str>,
    /// `stop` re-entrancy flag (envelope `stopHookActive`) — `true` while
    /// inside an ongoing stop-hook continuation loop for this turn.
    pub stop_hook_active: Option<bool>,
}

impl HookEnvelope {
    /// Build a pre-tool envelope.
    pub(crate) fn for_pre_tool_use(
        event: HookEvent,
        session_id: Uuid,
        workspace_root: &Path,
        timestamp: &str,
        tool_name: &str,
        tool_call_id: &str,
        tool_input: &Value,
    ) -> Self {
        let (input, truncated) = clip_json_value(tool_input, ENVELOPE_VALUE_MAX_BYTES);
        Self {
            hook_event_name: event.key().to_string(),
            session_id: session_id.to_string(),
            workspace_root: workspace_root.to_string_lossy().to_string(),
            timestamp: timestamp.to_string(),
            tool_name: Some(tool_name.to_string()),
            tool_call_id: Some(tool_call_id.to_string()),
            tool_input: input,
            tool_input_truncated: truncated.then_some(true),
            tool_result: None,
            tool_result_truncated: None,
            tool_error: None,
            subagent_id: None,
            subagent_type: None,
            source: None,
            reason: None,
            start_source: None,
            prompt_source: None,
            permission_kind: None,
            error_class: None,
            compact_source: None,
            compaction_id: None,
            end_reason: None,
            stop_reason: None,
            stop_hook_active: None,
        }
    }

    /// Build a post-tool envelope (success or failure).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_post_tool_use(
        event: HookEvent,
        session_id: Uuid,
        workspace_root: &Path,
        timestamp: &str,
        tool_name: &str,
        tool_call_id: &str,
        tool_input: &Value,
        tool_result: Option<&Value>,
        tool_error: Option<&str>,
    ) -> Self {
        let (input, input_truncated) = clip_json_value(tool_input, ENVELOPE_VALUE_MAX_BYTES);
        let (result, result_truncated) = tool_result
            .map(|r| clip_json_value(r, ENVELOPE_VALUE_MAX_BYTES))
            .unwrap_or((None, false));
        Self {
            hook_event_name: event.key().to_string(),
            session_id: session_id.to_string(),
            workspace_root: workspace_root.to_string_lossy().to_string(),
            timestamp: timestamp.to_string(),
            tool_name: Some(tool_name.to_string()),
            tool_call_id: Some(tool_call_id.to_string()),
            tool_input: input,
            tool_input_truncated: input_truncated.then_some(true),
            tool_result: result,
            tool_result_truncated: result_truncated.then_some(true),
            tool_error: tool_error.map(str::to_string),
            subagent_id: None,
            subagent_type: None,
            source: None,
            reason: None,
            start_source: None,
            prompt_source: None,
            permission_kind: None,
            error_class: None,
            compact_source: None,
            compaction_id: None,
            end_reason: None,
            stop_reason: None,
            stop_hook_active: None,
        }
    }

    /// Build an observe-only lifecycle envelope.
    ///
    /// `fields` carries the first-class typed discriminators (Decision 8);
    /// generic `source` / `reason` remain for the stop-gate `end_turn` path.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_observe(
        event: HookEvent,
        session_id: Uuid,
        workspace_root: &Path,
        timestamp: &str,
        tool_name: Option<&str>,
        tool_call_id: Option<&str>,
        source: Option<&str>,
        reason: Option<&str>,
        subagent_type: Option<&str>,
        subagent_id: Option<&str>,
        fields: ObserveFields<'_>,
    ) -> Self {
        Self {
            hook_event_name: event.key().to_string(),
            session_id: session_id.to_string(),
            workspace_root: workspace_root.to_string_lossy().to_string(),
            timestamp: timestamp.to_string(),
            tool_name: tool_name.map(str::to_string),
            tool_call_id: tool_call_id.map(str::to_string),
            tool_input: None,
            tool_input_truncated: None,
            tool_result: None,
            tool_result_truncated: None,
            tool_error: None,
            subagent_id: subagent_id.map(str::to_string),
            subagent_type: subagent_type.map(str::to_string),
            source: source.map(str::to_string),
            reason: reason.map(str::to_string),
            start_source: fields.start_source.map(str::to_string),
            prompt_source: fields.prompt_source.map(str::to_string),
            permission_kind: fields.permission_kind.map(str::to_string),
            error_class: fields.error_class.map(str::to_string),
            compact_source: fields.compact_source.map(str::to_string),
            compaction_id: fields.compaction_id.map(str::to_string),
            end_reason: fields.end_reason.map(str::to_string),
            stop_reason: fields.stop_reason.map(str::to_string),
            stop_hook_active: fields.stop_hook_active,
        }
    }

    /// Serialize to a JSON string for stdin.
    pub(crate) fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

// ---------------------------------------------------------------------------
// Decision / Run Result
// ---------------------------------------------------------------------------

/// The outcome of a single hook handler run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookDecision {
    /// The hook allowed the action (or is an observer that ran successfully).
    Allow,
    /// The hook explicitly denied (pre-tool only). The reason is the
    /// model-visible rejected-tool diagnostic.
    Deny { reason: String },
    /// The hook produced a stop-gate block with aggregated feedback for
    /// another model round.
    Block {
        reason: String,
        additional_context: Option<String>,
    },
    /// The hook produced a stop-gate continue that ends the turn.
    Continue { stop_reason: String },
    /// The hook run failed (fail-open). The reason is recorded in the ledger.
    Failed { reason: String },
}

impl HookDecision {
    pub(crate) fn status(&self) -> HookRunStatus {
        match self {
            Self::Allow => HookRunStatus::Success,
            Self::Deny { .. } => HookRunStatus::Denied,
            Self::Block { .. } => HookRunStatus::Blocked,
            Self::Continue { .. } => HookRunStatus::Success,
            Self::Failed { .. } => HookRunStatus::Failed,
        }
    }

    pub(crate) fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Deny { reason } | Self::Block { reason, .. } | Self::Failed { reason } => {
                Some(reason)
            }
            Self::Continue { stop_reason } => Some(stop_reason),
        }
    }
}

/// Parsed stdout JSON from a hook command.
#[derive(Debug, Deserialize)]
struct HookOutput {
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default, rename = "hookSpecificOutput")]
    hook_specific_output: Option<HookSpecificOutput>,
    #[serde(default)]
    r#continue: Option<bool>,
    #[serde(default, rename = "stopReason")]
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HookSpecificOutput {
    #[serde(default, rename = "additionalContext")]
    additional_context: Option<String>,
}

/// Parse stdout as a hook decision for a pre-tool event.
///
/// Invalid JSON, JSON that is not an object, an unknown `decision`, or JSON
/// with a non-string reason is a failed run, not a deny. Valid JSON wins over
/// an exit code only for the explicit pre-tool deny vocabulary.
fn parse_pre_tool_decision(stdout: &str, exit_code: Option<i32>) -> HookDecision {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        // No stdout output — exit code alone never denies.
        if let Some(code) = exit_code
            && code != 0
        {
            return HookDecision::Failed {
                reason: format!("{REASON_NONZERO_EXIT_PREFIX}: {code}"),
            };
        }
        return HookDecision::Allow;
    }
    let parsed: Result<Value, _> = serde_json::from_str(trimmed);
    let Ok(value) = parsed else {
        return HookDecision::Failed {
            reason: REASON_MALFORMED_JSON_OUTPUT.to_string(),
        };
    };
    if !value.is_object() {
        return HookDecision::Failed {
            reason: REASON_OUTPUT_NOT_JSON_OBJECT.to_string(),
        };
    }
    let output: HookOutput = match serde_json::from_value(value) {
        Ok(output) => output,
        Err(_) => {
            return HookDecision::Failed {
                reason: REASON_MALFORMED_HOOK_OUTPUT.to_string(),
            };
        }
    };
    match output.decision.as_deref() {
        Some("allow") => HookDecision::Allow,
        Some("deny") => {
            let reason = output
                .reason
                .filter(|r| !r.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_DENY_REASON.to_string());
            HookDecision::Deny {
                reason: clip_reason(&reason),
            }
        }
        Some("block") => {
            // block is a stop-gate vocabulary, not valid for pre-tool.
            HookDecision::Failed {
                reason: REASON_UNEXPECTED_PRE_TOOL_BLOCK.to_string(),
            }
        }
        _ => HookDecision::Failed {
            reason: REASON_UNKNOWN_OR_MISSING_DECISION.to_string(),
        },
    }
}

/// Parse stdout as a hook decision for a stop-gate event.
fn parse_stop_decision(stdout: &str, exit_code: Option<i32>) -> HookDecision {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        if let Some(code) = exit_code
            && code != 0
        {
            return HookDecision::Failed {
                reason: format!("{REASON_NONZERO_EXIT_PREFIX}: {code}"),
            };
        }
        return HookDecision::Allow;
    }
    let parsed: Result<Value, _> = serde_json::from_str(trimmed);
    let Ok(value) = parsed else {
        return HookDecision::Failed {
            reason: REASON_MALFORMED_JSON_OUTPUT.to_string(),
        };
    };
    if !value.is_object() {
        return HookDecision::Failed {
            reason: REASON_OUTPUT_NOT_JSON_OBJECT.to_string(),
        };
    }
    let output: HookOutput = match serde_json::from_value(value) {
        Ok(output) => output,
        Err(_) => {
            return HookDecision::Failed {
                reason: REASON_MALFORMED_HOOK_OUTPUT.to_string(),
            };
        }
    };

    // continue:false wins and ends the turn.
    if let Some(false) = output.r#continue {
        let reason = output
            .stop_reason
            .filter(|r| !r.trim().is_empty())
            .unwrap_or_else(|| "stop hook requested end".to_string());
        return HookDecision::Continue {
            stop_reason: clip_reason(&reason),
        };
    }

    match output.decision.as_deref() {
        Some("allow") => HookDecision::Allow,
        Some("deny") => {
            // deny is not a stop-gate vocabulary; treat as fail.
            HookDecision::Failed {
                reason: REASON_UNEXPECTED_STOP_DENY.to_string(),
            }
        }
        Some("block") => {
            let reason = output
                .reason
                .filter(|r| !r.trim().is_empty())
                .unwrap_or_else(|| "blocked by stop hook".to_string());
            let additional_context = output
                .hook_specific_output
                .and_then(|h| h.additional_context)
                .filter(|c| !c.trim().is_empty())
                .map(|c| clip_reason(&c));
            HookDecision::Block {
                reason: clip_reason(&reason),
                additional_context,
            }
        }
        _ => HookDecision::Allow, // Unknown decision in stop-gate is observe (fail-open).
    }
}

/// Parse stdout for an observe-only event. Always `Allow` or `Failed`.
fn parse_observe_decision(stdout: &str, exit_code: Option<i32>) -> HookDecision {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        if let Some(code) = exit_code
            && code != 0
        {
            return HookDecision::Failed {
                reason: format!("{REASON_NONZERO_EXIT_PREFIX}: {code}"),
            };
        }
        return HookDecision::Allow;
    }
    // Observe-only hooks: we don't parse decisions, just check for non-object
    // or malformed output as a failure signal.
    if serde_json::from_str::<Value>(trimmed).is_ok() {
        HookDecision::Allow
    } else {
        HookDecision::Failed {
            reason: REASON_MALFORMED_JSON_OUTPUT.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Process environment seam
// ---------------------------------------------------------------------------

/// A process-environment seam for resolving bare executables and constructing
/// clean child environments without mutating `std::env`.
///
/// Production code uses [`DefaultProcessEnv`]; tests inject a fake that
/// returns deterministic paths and captures the env without touching the host.
pub trait ProcessEnv: Send + Sync {
    /// Resolve a bare executable name to an absolute path using the
    /// parent-process executable lookup (PATH, PATHEXT on Windows).
    /// Returns `None` if not found.
    fn resolve_executable(&self, name: &str) -> Option<PathBuf>;

    /// Return the parent-process `SystemRoot` value (Windows only).
    /// Returns `None` if absent. Only called under `#[cfg(windows)]` in
    /// [`build_child_env`]; `#[allow(dead_code)]` avoids a non-Windows
    /// warning for this required cross-platform seam.
    #[allow(dead_code)]
    fn system_root(&self) -> Option<String>;
}

/// Production process environment that reads `std::env` for PATH lookup.
#[derive(Debug, Clone, Default)]
pub struct DefaultProcessEnv;

impl ProcessEnv for DefaultProcessEnv {
    fn resolve_executable(&self, name: &str) -> Option<PathBuf> {
        crate::harness::preflight::which_on_path(name)
    }

    fn system_root(&self) -> Option<String> {
        std::env::var("SystemRoot").ok()
    }
}

/// Construct the clean child environment for a hook command.
///
/// The child receives configured hook env only. On Windows only, the runner
/// additionally supplies `SystemRoot` and `WINDIR`, both copied from the
/// parent `SystemRoot` value (or returns an error fail-open if absent).
/// `ComSpec`, `PATHEXT`, and every other host variable remain absent. On Unix
/// no ambient variable is added. Reserved keys are overwritten after
/// configured env so configured env cannot spoof them.
pub(crate) fn build_child_env(
    hook: &ResolvedHook,
    #[allow(unused_variables)] process_env: &dyn ProcessEnv,
    event: HookEvent,
    session_id: Uuid,
    workspace_root: &Path,
    tool_name: Option<&str>,
    tool_call_id: Option<&str>,
) -> Result<BTreeMap<String, String>, String> {
    let mut env = hook.env.clone();

    #[cfg(windows)]
    {
        let system_root = process_env.system_root().ok_or_else(|| {
            "missing SystemRoot: cannot construct clean Windows environment".to_string()
        })?;
        env.insert("SystemRoot".to_string(), system_root.clone());
        env.insert("WINDIR".to_string(), system_root);
        // Deliberately do NOT add ComSpec, PATHEXT, or any other host variable.
    }

    // Overwrite reserved keys after configured env.
    env.insert(RESERVED_ENV_KEYS[0].to_string(), event.key().to_string());
    env.insert(
        RESERVED_ENV_KEYS[1].to_string(),
        hook.origin.as_str().to_string(),
    );
    env.insert(RESERVED_ENV_KEYS[2].to_string(), session_id.to_string());
    env.insert(
        RESERVED_ENV_KEYS[3].to_string(),
        workspace_root.to_string_lossy().to_string(),
    );
    if let Some(name) = tool_name {
        env.insert(RESERVED_ENV_KEYS[4].to_string(), name.to_string());
    }
    if let Some(id) = tool_call_id {
        env.insert(RESERVED_ENV_KEYS[5].to_string(), id.to_string());
    }

    Ok(env)
}

/// Resolve the hook command's executable to an absolute path.
///
/// The config foundation already resolved source-relative paths to absolute or
/// bare names. A bare name is resolved here before `env_clear` using the
/// process-environment seam.
pub(crate) fn resolve_hook_executable(
    hook: &ResolvedHook,
    process_env: &dyn ProcessEnv,
) -> Option<PathBuf> {
    let exe = hook.command.first()?;
    let path = Path::new(exe);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    // Bare executable: resolve via parent-process lookup.
    process_env.resolve_executable(exe)
}

// ---------------------------------------------------------------------------
// Command runner trait (test seam)
// ---------------------------------------------------------------------------

/// The raw result of running one hook command (before decision parsing).
#[derive(Debug, Clone)]
pub struct HookRawOutput {
    pub stdout: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub spawn_failed: bool,
    pub timeout: bool,
    /// Closed runner-level failure reason that must survive decision parsing.
    pub failure_reason: Option<&'static str>,
    pub output_truncated: bool,
}

/// A command runner trait for deterministic tests.
///
/// Production uses [`TokioCommandRunner`]; tests inject a fake that captures
/// the command, env, stdin, cwd, and timeout without spawning a real process.
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run a hook command with the given executable, args, env, cwd, stdin
    /// envelope, and timeout. Returns the raw output (stdout, exit code,
    /// duration, failure flags).
    async fn run(
        &self,
        executable: &Path,
        args: &[String],
        env: &BTreeMap<String, String>,
        cwd: &Path,
        stdin: &str,
        timeout: Duration,
        session_id: Uuid,
    ) -> HookRawOutput;

    /// Stop-gate variant with an explicit caller cancellation boundary. Test
    /// runners own no descendant process, so the default may race the fake.
    /// The production runner overrides this and proves containment empty
    /// before cancellation is reported.
    #[allow(clippy::too_many_arguments)]
    async fn run_cancellable(
        &self,
        executable: &Path,
        args: &[String],
        env: &BTreeMap<String, String>,
        cwd: &Path,
        stdin: &str,
        timeout: Duration,
        session_id: Uuid,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> HookRawOutput {
        tokio::select! {
            output = self.run(executable, args, env, cwd, stdin, timeout, session_id) => output,
            _ = cancel.cancelled() => HookRawOutput {
                stdout: String::new(), exit_code: None, duration_ms: 0,
                spawn_failed: false, timeout: false,
                failure_reason: Some(REASON_HOOK_CANCELLED), output_truncated: false,
            },
        }
    }
}

/// Production command runner using tokio::process.
#[derive(Clone)]
pub struct TokioCommandRunner {
    containment: Option<crate::process_containment::ProcessContainmentHandle>,
    cancellation: Option<tokio_util::sync::CancellationToken>,
}

impl TokioCommandRunner {
    pub fn new() -> Self {
        Self {
            containment: None,
            cancellation: None,
        }
    }

    pub fn with_containment(
        containment: crate::process_containment::ProcessContainmentHandle,
    ) -> Self {
        Self {
            containment: Some(containment),
            cancellation: None,
        }
    }

    fn with_cancellation(mut self, cancellation: tokio_util::sync::CancellationToken) -> Self {
        self.cancellation = Some(cancellation);
        self
    }
}

impl Default for TokioCommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

struct HookContainmentDropGuard {
    handle: crate::process_containment::ProcessContainmentHandle,
    lease: Option<crate::process_containment::ContainmentLease>,
}

impl HookContainmentDropGuard {
    fn disarm(&mut self) {
        self.lease = None;
    }
}

async fn terminate_and_prove_empty(
    handle: &crate::process_containment::ProcessContainmentHandle,
    lease: &crate::process_containment::ContainmentLease,
) -> Result<(), crate::process_containment::ContainmentError> {
    // A hook execution is not settled while the containment oracle can still
    // see descendants. `Uncertain` is deliberately not converted into a hook
    // failure: doing so would return control while an untrusted descendant may
    // still be alive. Ownership transfers to the actor's reconciliation queue;
    // its completion ticket resolves only after the same generation is proven
    // empty, while retries remain interleaved with ordinary actor commands.
    handle.reconcile_and_await_empty(lease.clone()).await
}

impl Drop for HookContainmentDropGuard {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        // This synchronous unbounded ownership channel is consumed only by
        // the containment actor. Drop never starts a detached task and never
        // loses a lease merely because the ordinary bounded command queue is
        // full. A closed channel honestly means the actor has already stopped.
        let _ = self.handle.enqueue_reconciliation(lease);
    }
}

#[async_trait::async_trait]
impl CommandRunner for TokioCommandRunner {
    async fn run(
        &self,
        executable: &Path,
        args: &[String],
        env: &BTreeMap<String, String>,
        cwd: &Path,
        stdin: &str,
        timeout: Duration,
        session_id: Uuid,
    ) -> HookRawOutput {
        let start = std::time::Instant::now();
        if timeout.is_zero()
            || self
                .cancellation
                .as_ref()
                .is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
        {
            return HookRawOutput {
                stdout: String::new(),
                exit_code: None,
                duration_ms: 0,
                spawn_failed: false,
                timeout: timeout.is_zero(),
                failure_reason: (!timeout.is_zero()).then_some(REASON_HOOK_CANCELLED),
                output_truncated: false,
            };
        }
        let Some(containment) = self.containment.as_ref() else {
            return HookRawOutput {
                stdout: String::new(),
                exit_code: None,
                duration_ms: 0,
                spawn_failed: true,
                timeout: false,
                failure_reason: Some(REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED),
                output_truncated: false,
            };
        };
        let operation_id = format!("hook-{}", Uuid::new_v4());
        let allocation_cancel = match crate::process_containment::AllocationCancellation::new() {
            Ok(ticket) => ticket,
            Err(_) => {
                return HookRawOutput {
                    stdout: String::new(),
                    exit_code: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    spawn_failed: true,
                    timeout: false,
                    failure_reason: Some(REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED),
                    output_truncated: false,
                };
            }
        };
        let allocation = containment.create_and_spawn_with_io_cancellable(
                session_id,
                operation_id,
                executable,
                args.to_vec(),
                env.clone(),
                cwd,
                true,
                allocation_cancel.clone(),
            );
        let cancellation = self
            .cancellation
            .clone()
            .unwrap_or_else(tokio_util::sync::CancellationToken::new);
        let cancellation_enabled = self.cancellation.is_some();
        // Allocation is part of the hook deadline. Once the bounded actor
        // accepts this request, `allocation_cancel` is its cleanup ticket:
        // timeout/cancellation transfers the request-specific cleanup ticket
        // to the actor. The hook then awaits that ticket: completion means the
        // exact generation either never crossed release or reached ProvenEmpty.
        let mut allocation = Box::pin(allocation);
        let allocation_deadline = tokio::time::sleep(timeout);
        tokio::pin!(allocation_deadline);
        enum AllocationBoundary {
            Ready(Result<(crate::process_containment::ContainmentLease, crate::process_containment::NativeChildIo), crate::process_containment::ContainmentError>),
            Cancelled,
            TimedOut,
        }
        let allocation_boundary = tokio::select! {
            biased;
            _ = cancellation.cancelled(), if cancellation_enabled => {
                AllocationBoundary::Cancelled
            }
            _ = &mut allocation_deadline => AllocationBoundary::TimedOut,
            result = &mut allocation => AllocationBoundary::Ready(result),
        };
        let allocation_result = match allocation_boundary {
            AllocationBoundary::Ready(result) => result,
            boundary @ (AllocationBoundary::Cancelled | AllocationBoundary::TimedOut) => {
                let (timed_out, failure_reason) = match boundary {
                    AllocationBoundary::Cancelled => (false, Some(REASON_HOOK_CANCELLED)),
                    AllocationBoundary::TimedOut => (true, None),
                    AllocationBoundary::Ready(_) => unreachable!("matched terminal allocation boundary"),
                };
                let cancellation_recorded = allocation_cancel.cancel().await.is_ok();
                // The actor reply is the explicit cleanup-completion ticket.
                // It resolves only after a losing broker prepare is cancelled
                // or a winning commit reaches same-generation ProvenEmpty.
                let completion = allocation.await;
                if !cancellation_recorded
                    && let Ok((lease, _)) = completion
                {
                    let _ = containment.reconcile_and_await_empty(lease).await;
                }
                return HookRawOutput {
                    stdout: String::new(),
                    exit_code: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    spawn_failed: false,
                    timeout: timed_out,
                    failure_reason,
                    output_truncated: false,
                };
            }
        };
        let (lease, mut io) = match allocation_result {
            Ok(created) => created,
            Err(crate::process_containment::ContainmentError::DescendantContainmentUnavailable {
                ..
            }) => {
                return HookRawOutput {
                    stdout: String::new(),
                    exit_code: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    spawn_failed: true,
                    timeout: false,
                    failure_reason: Some(REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED),
                    output_truncated: false,
                };
            }
            Err(_) => {
                return HookRawOutput {
                    stdout: String::new(),
                    exit_code: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    spawn_failed: true,
                    timeout: false,
                    failure_reason: Some(REASON_SPAWN_FAILED),
                    output_truncated: false,
                };
            }
        };
        let mut drop_guard = HookContainmentDropGuard {
            handle: containment.clone(),
            lease: Some(lease.clone()),
        };
        if lease.guarantee() != crate::process_containment::ContainmentGuarantee::Proven {
            let cleanup_owned = terminate_and_prove_empty(containment, &lease).await.is_ok();
            if cleanup_owned {
                drop_guard.disarm();
            }
            return HookRawOutput {
                stdout: String::new(),
                exit_code: None,
                duration_ms: start.elapsed().as_millis() as u64,
                spawn_failed: true,
                timeout: false,
                failure_reason: Some(if cleanup_owned {
                    REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED
                } else {
                    REASON_CONTAINMENT_ACTOR_UNAVAILABLE
                }),
                output_truncated: false,
            };
        }

        let mut child_stdin = io.stdin.take();
        let mut child_stdout = io.stdout.take();
        let mut child_stderr = io.stderr.take();
        let (overflow_tx, mut overflow_rx) = tokio::sync::mpsc::channel::<()>(1);

        let stdin_fut = async {
            if let Some(mut input) = child_stdin.take() {
                input.write_all(stdin.as_bytes()).await?;
            }
            Ok::<(), std::io::Error>(())
        };

        // Read stdout with independent cap.
        let stdout_overflow = overflow_tx.clone();
        let stdout_fut = async move {
            if let Some(mut out) = child_stdout.take() {
                let mut temp = vec![0u8; OUTPUT_CAP_BYTES + 1];
                let mut total = Vec::new();
                loop {
                    let n = match out.read(&mut temp).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => return (Some((total, false)), true),
                    };
                    total.extend_from_slice(&temp[..n]);
                    if total.len() > OUTPUT_CAP_BYTES {
                        total.truncate(OUTPUT_CAP_BYTES);
                        let _ = stdout_overflow.try_send(());
                        return (Some((total, true)), false);
                    }
                }
                (Some((total, false)), false)
            } else {
                (None, false)
            }
        };

        let stderr_fut = async move {
            if let Some(mut err) = child_stderr.take() {
                let mut buffer = vec![0_u8; OUTPUT_CAP_BYTES + 1];
                let mut total = 0_usize;
                loop {
                    match err.read(&mut buffer).await {
                        Ok(0) => break,
                        Err(_) => return (false, true),
                        Ok(read) => {
                            total = total.saturating_add(read);
                            if total > OUTPUT_CAP_BYTES {
                                let _ = overflow_tx.try_send(());
                                return (true, false);
                            }
                        }
                    }
                }
            }
            (false, false)
        };

        // The deadline covers stdin delivery, both pipe drains, and process
        // exit as one operation. Timing only `wait` can deadlock forever when
        // a descendant inherits a pipe, and writing stdin outside the deadline
        // can block before timeout enforcement even begins.
        let operation = async {
            let (stdin_result, stdout_result, stderr_result, wait_result) =
                tokio::join!(stdin_fut, stdout_fut, stderr_fut, io.wait.as_mut());
            (stdin_result, stdout_result, stderr_result, wait_result)
        };
        let (stdin_failed, stdout_result, stdout_pipe_failed, stderr_truncated, stderr_pipe_failed, exit_code, timed_out, overflowed, cancelled) =
            tokio::select! {
                biased;
                _ = cancellation.cancelled(), if cancellation_enabled => (false, None, false, false, false, None, false, false, true),
                Some(()) = overflow_rx.recv() => (false, None, false, false, false, None, false, true, false),
                completed = tokio::time::timeout(timeout.saturating_sub(start.elapsed()), operation) => match completed {
                Ok((stdin_result, (stdout_result, stdout_pipe_failed), (stderr_truncated, stderr_pipe_failed), wait_result)) => (
                    stdin_result.is_err(),
                    stdout_result,
                    stdout_pipe_failed,
                    stderr_truncated,
                    stderr_pipe_failed,
                    wait_result.unwrap_or(None),
                    false,
                    false,
                    false,
                ),
                Err(_) => (false, None, false, false, false, None, true, false, false),
                }
            };

        let cleanup_owned = terminate_and_prove_empty(containment, &lease).await.is_ok();
        if cleanup_owned {
            drop_guard.disarm();
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let (stdout_bytes, stdout_truncated) = stdout_result.unwrap_or_default();
        let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();

        HookRawOutput {
            stdout,
            exit_code,
            duration_ms,
            spawn_failed: stdin_failed,
            timeout: timed_out,
            failure_reason: if !cleanup_owned {
                Some(REASON_CONTAINMENT_ACTOR_UNAVAILABLE)
            } else if cancelled {
                Some(REASON_HOOK_CANCELLED)
            } else if timed_out {
                Some(REASON_HOOK_TIMED_OUT)
            } else if stdin_failed {
                Some(REASON_PIPE_IO_FAILED)
            } else if stdout_pipe_failed || stderr_pipe_failed {
                Some(REASON_PIPE_IO_FAILED)
            } else if overflowed || stdout_truncated || stderr_truncated {
                Some(REASON_OUTPUT_LIMIT_EXCEEDED)
            } else if exit_code.is_none() && !timed_out {
                Some(REASON_NO_EXIT_STATUS)
            } else {
                None
            },
            output_truncated: overflowed || stdout_truncated || stderr_truncated,
        }
    }

    async fn run_cancellable(
        &self,
        executable: &Path,
        args: &[String],
        env: &BTreeMap<String, String>,
        cwd: &Path,
        stdin: &str,
        timeout: Duration,
        session_id: Uuid,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> HookRawOutput {
        self.clone()
            .with_cancellation(cancel.clone())
            .run(executable, args, env, cwd, stdin, timeout, session_id)
            .await
    }
}

// ---------------------------------------------------------------------------
// Matcher and dispatch
// ---------------------------------------------------------------------------

/// Select matching hooks for an event and canonical match value.
///
/// Exact matchers only: the hook's matcher set (if present) must contain the
/// canonical match value. A hook with no matcher matches all values for its
/// event.
pub(crate) fn matching_hooks<'a>(
    registry: &'a HookRegistry,
    event: HookEvent,
    match_value: &str,
) -> Vec<&'a ResolvedHook> {
    registry
        .hooks
        .iter()
        .filter(|hook| {
            hook.event == event
                && hook
                    .matcher
                    .as_ref()
                    .as_ref()
                    .is_none_or(|set| set.contains(match_value))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Recording (audit ledger)
// ---------------------------------------------------------------------------

/// Build a `HookRunAudit` for a single hook run.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_hook_run_audit(
    event: HookEvent,
    hook: &ResolvedHook,
    decision: &HookDecision,
    duration_ms: u64,
    turn_id: Option<&str>,
    tool_name: Option<&str>,
    tool_call_id: Option<&str>,
    subagent_id: Option<&str>,
) -> HookRunAudit {
    HookRunAudit {
        event: event.key().to_string(),
        hook: hook.origin.as_str().to_string(),
        origin: hook.origin.as_str().to_string(),
        status: decision.status(),
        duration_ms,
        reason: decision.reason().map(|r| r.to_string()),
        turn_id: turn_id.map(|t| t.to_string()),
        tool_name: tool_name.map(|t| t.to_string()),
        tool_call_id: tool_call_id.map(|t| t.to_string()),
        subagent_id: subagent_id.map(|t| t.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Clip a reason to `REASON_MAX_CHARS` UTF-8-safe characters.
fn clip_reason(reason: &str) -> String {
    if reason.chars().count() <= REASON_MAX_CHARS {
        return reason.to_string();
    }
    let clipped: String = reason.chars().take(REASON_MAX_CHARS).collect();
    clipped
}

/// Truncation marker appended to clipped envelope values.
const TRUNCATION_MARKER: &str = "…[truncated]";

/// Clip a JSON value's serialized form to `max_bytes`. Returns `(Some(clipped),
/// true)` if the value was truncated, `(Some(original), false)` if it fit, and
/// `(None, false)` if the value was `None`-ish.
///
/// When the value is too large it is replaced with a `Value::String` whose
/// JSON-serialized form (including surrounding quotes and the truncation
/// marker) fits within `max_bytes`. This guarantees the envelope field's
/// serialized size never exceeds the configured bound.
fn clip_json_value(value: &Value, max_bytes: usize) -> (Option<Value>, bool) {
    let serialized = serde_json::to_string(value).unwrap_or_default();
    if serialized.len() <= max_bytes {
        return (Some(value.clone()), false);
    }
    // The replacement is a JSON string value: `"<prefix>…[truncated]"`. Its
    // serialized length includes surrounding quotes and JSON escaping of any
    // special characters in the prefix. We iteratively trim the prefix until
    // the serialized replacement fits within `max_bytes`.
    let marker = TRUNCATION_MARKER;
    // Start with a conservative budget that leaves room for quotes + marker.
    let mut prefix_budget = max_bytes.saturating_sub(2 + marker.len());
    loop {
        let prefix = clip_utf8_bytes(&serialized, prefix_budget);
        let replacement = Value::String(format!("{prefix}{marker}"));
        let repl_serialized = serde_json::to_string(&replacement).unwrap_or_default();
        if repl_serialized.len() <= max_bytes || prefix_budget == 0 {
            return (Some(replacement), true);
        }
        // Escaping pushed it over; shrink the budget and retry.
        let over = repl_serialized.len() - max_bytes;
        prefix_budget = prefix_budget.saturating_sub(over.max(1));
    }
}

/// Clip a string to `max_bytes` at a UTF-8 char boundary.
fn clip_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Dispatch functions (pre/post tool hooks)
// ---------------------------------------------------------------------------

/// The outcome of running all matching pre-tool hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreHookOutcome {
    /// All matching pre hooks allowed (or no matching hooks, or all failed
    /// fail-open).
    Allow,
    /// The first explicit deny. The tool is not executed.
    Deny { reason: String },
}

/// Run all matching pre-tool hooks sequentially until the first explicit deny.
///
/// Pre hooks are fail-open: a hook can deny only by printing valid JSON
/// `{"decision":"deny","reason":"..."}` to stdout. A hook crash, timeout,
/// spawn failure, malformed output, oversized output, or nonzero exit other
/// than an explicit parseable deny are recorded as failed hook runs and allow
/// existing agent execution to continue. The first explicit deny
/// short-circuits later pre hooks.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_pre_tool_hooks(
    runner: &dyn CommandRunner,
    process_env: &dyn ProcessEnv,
    registry: &HookRegistry,
    tool_name: &str,
    tool_input: &Value,
    tool_call_id: &str,
    session_id: Uuid,
    workspace_root: &Path,
    db: &crate::db::Db,
) -> PreHookOutcome {
    let event = HookEvent::PreToolUse;
    let hooks = matching_hooks(registry, event, tool_name);
    if hooks.is_empty() {
        return PreHookOutcome::Allow;
    }

    let timestamp = chrono::Utc::now().to_rfc3339();
    let envelope = HookEnvelope::for_pre_tool_use(
        event,
        session_id,
        workspace_root,
        &timestamp,
        tool_name,
        tool_call_id,
        tool_input,
    );
    let stdin = envelope.to_json_string();

    for hook in hooks {
        let executable = match resolve_hook_executable(hook, process_env) {
            Some(path) => path,
            None => {
                // Spawn failure: fail-open, record failed run.
                record_hook_run(
                    db,
                    session_id,
                    event,
                    hook,
                    &HookDecision::Failed {
                        reason: REASON_EXECUTABLE_NOT_FOUND.to_string(),
                    },
                    0,
                    None,
                    Some(tool_name),
                    Some(tool_call_id),
                    None,
                )
                .await;
                continue;
            }
        };
        let env_result = build_child_env(
            hook,
            process_env,
            event,
            session_id,
            workspace_root,
            Some(tool_name),
            Some(tool_call_id),
        );
        let child_env = match env_result {
            Ok(env) => env,
            Err(reason) => {
                record_hook_run(
                    db,
                    session_id,
                    event,
                    hook,
                    &HookDecision::Failed { reason },
                    0,
                    None,
                    Some(tool_name),
                    Some(tool_call_id),
                    None,
                )
                .await;
                continue;
            }
        };
        let timeout = Duration::from_secs(hook.timeout_secs as u64);
        let args = &hook.command[1..];
        let raw = runner
            .run(
                &executable,
                args,
                &child_env,
                workspace_root,
                &stdin,
                timeout,
                session_id,
            )
            .await;

        let decision = if let Some(reason) = raw.failure_reason {
            HookDecision::Failed {
                reason: reason.to_string(),
            }
        } else if raw.spawn_failed {
            HookDecision::Failed {
                reason: REASON_SPAWN_FAILED.to_string(),
            }
        } else if raw.timeout {
            HookDecision::Failed {
                reason: REASON_HOOK_TIMED_OUT.to_string(),
            }
        } else {
            parse_pre_tool_decision(&raw.stdout, raw.exit_code)
        };

        record_hook_run(
            db,
            session_id,
            event,
            hook,
            &decision,
            raw.duration_ms,
            None,
            Some(tool_name),
            Some(tool_call_id),
            None,
        )
        .await;

        if let HookDecision::Deny { reason } = &decision {
            return PreHookOutcome::Deny {
                reason: reason.clone(),
            };
        }
    }
    PreHookOutcome::Allow
}

/// Run all matching post-tool hooks sequentially.
///
/// `postToolUse` runs once after a successful real tool execution;
/// `postToolUseFailure` runs once after a real tool execution that returns an
/// error. All matching post hooks run sequentially even if an earlier
/// observer fails. Post hooks are observe-only (fail-open).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_post_tool_hooks(
    runner: &dyn CommandRunner,
    process_env: &dyn ProcessEnv,
    registry: &HookRegistry,
    event: HookEvent,
    tool_name: &str,
    tool_input: &Value,
    tool_call_id: &str,
    result: &anyhow::Result<crate::engine::tool::ToolOutput>,
    session_id: Uuid,
    workspace_root: &Path,
    db: &crate::db::Db,
) {
    let hooks = matching_hooks(registry, event, tool_name);
    if hooks.is_empty() {
        return;
    }

    let timestamp = chrono::Utc::now().to_rfc3339();

    let (tool_result, tool_error) = match result {
        Ok(output) => (
            Some(serde_json::Value::String(output.content.clone())),
            None,
        ),
        Err(e) => (None, Some(format!("{e}"))),
    };
    let envelope = HookEnvelope::for_post_tool_use(
        event,
        session_id,
        workspace_root,
        &timestamp,
        tool_name,
        tool_call_id,
        tool_input,
        tool_result.as_ref(),
        tool_error.as_deref(),
    );
    let stdin = envelope.to_json_string();

    for hook in hooks {
        let executable = match resolve_hook_executable(hook, process_env) {
            Some(path) => path,
            None => {
                record_hook_run(
                    db,
                    session_id,
                    event,
                    hook,
                    &HookDecision::Failed {
                        reason: REASON_EXECUTABLE_NOT_FOUND.to_string(),
                    },
                    0,
                    None,
                    Some(tool_name),
                    Some(tool_call_id),
                    None,
                )
                .await;
                continue;
            }
        };
        let env_result = build_child_env(
            hook,
            process_env,
            event,
            session_id,
            workspace_root,
            Some(tool_name),
            Some(tool_call_id),
        );
        let child_env = match env_result {
            Ok(env) => env,
            Err(reason) => {
                record_hook_run(
                    db,
                    session_id,
                    event,
                    hook,
                    &HookDecision::Failed { reason },
                    0,
                    None,
                    Some(tool_name),
                    Some(tool_call_id),
                    None,
                )
                .await;
                continue;
            }
        };
        let timeout = Duration::from_secs(hook.timeout_secs as u64);
        let args = &hook.command[1..];
        let raw = runner
            .run(
                &executable,
                args,
                &child_env,
                workspace_root,
                &stdin,
                timeout,
                session_id,
            )
            .await;

        let decision = if let Some(reason) = raw.failure_reason {
            HookDecision::Failed {
                reason: reason.to_string(),
            }
        } else if raw.spawn_failed {
            HookDecision::Failed {
                reason: REASON_SPAWN_FAILED.to_string(),
            }
        } else if raw.timeout {
            HookDecision::Failed {
                reason: REASON_HOOK_TIMED_OUT.to_string(),
            }
        } else {
            parse_observe_decision(&raw.stdout, raw.exit_code)
        };

        record_hook_run(
            db,
            session_id,
            event,
            hook,
            &decision,
            raw.duration_ms,
            None,
            Some(tool_name),
            Some(tool_call_id),
            None,
        )
        .await;
    }
}

/// Record a single hook run in the durable ledger (best-effort).
///
/// Recording failure cannot alter a live turn: if the `insert_hook_run` call
/// fails, only the hook display label/event/status is logged and the turn
/// continues. The hook's result is never re-run during audit persistence or
/// replay.
#[allow(clippy::too_many_arguments)]
async fn record_hook_run(
    db: &crate::db::Db,
    session_id: Uuid,
    event: HookEvent,
    hook: &ResolvedHook,
    decision: &HookDecision,
    duration_ms: u64,
    turn_id: Option<&str>,
    tool_name: Option<&str>,
    tool_call_id: Option<&str>,
    subagent_id: Option<&str>,
) {
    let audit = build_hook_run_audit(
        event,
        hook,
        decision,
        duration_ms,
        turn_id,
        tool_name,
        tool_call_id,
        subagent_id,
    );
    // Best-effort: recording failure cannot alter a live turn.
    if let Err(error) = db.insert_hook_run(session_id, audit).await {
        tracing::warn!(
            event = event.key(),
            hook = %hook.origin,
            status = ?decision.status(),
            %error,
            "failed to record hook run in durable ledger"
        );
    }
}

// ---------------------------------------------------------------------------
// Stop-gate state machine
// ---------------------------------------------------------------------------

/// Maximum number of stop-hook continuations per `(session, frame-or-job,
/// originating user turn)`.
pub(crate) const STOP_HOOK_MAX_CONTINUATIONS: u8 = 8;

/// Per-frame/job stop-gate latch tracking continuation count.
#[derive(Debug, Clone, Default)]
pub struct StopGateState {
    pub stop_hook_active: bool,
    pub continuation_count: u8,
    /// At least one configured handler was entered for this lifecycle gate.
    /// Child teardown uses this to avoid emitting a second observe-only
    /// `subagentStop` when cancellation races an in-flight consultation.
    pub lifecycle_event_emitted: bool,
    /// Shared child-lifecycle latch owned by the scheduler/driver.  Publishing
    /// through this pointer at handler entry closes the race where teardown
    /// could otherwise emit an observe-only duplicate while a stop handler was
    /// still awaiting its process result.
    pub lifecycle_event_latch: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl StopGateState {
    pub fn capped(&self) -> bool {
        self.continuation_count >= STOP_HOOK_MAX_CONTINUATIONS
    }
}

/// Aggregated stop-gate feedback from all matching stop hooks.
#[derive(Debug, Clone, Default)]
pub struct StopGateFeedback {
    pub blocks: Vec<String>,
    pub additional_contexts: Vec<String>,
    pub forced_end: bool,
}

impl StopGateFeedback {
    pub fn should_continue_round(&self) -> bool {
        !self.forced_end && (!self.blocks.is_empty() || !self.additional_contexts.is_empty())
    }

    pub fn combined_reason(&self) -> String {
        self.blocks.join("\n")
    }

    pub fn combined_additional_context(&self) -> Option<String> {
        if self.additional_contexts.is_empty() {
            None
        } else {
            Some(self.additional_contexts.join("\n"))
        }
    }
}

/// The outcome of running all matching stop hooks for one completion event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopHookOutcome {
    /// No matching stop hooks, or all hooks allowed/failed fail-open. The
    /// turn ends normally.
    End,
    /// At least one stop hook produced a block with aggregated feedback for
    /// another model round. The turn continues with the combined reason and
    /// optional additional context.
    Continue {
        reason: String,
        additional_context: Option<String>,
    },
    /// A stop hook produced `{"continue":false,"stopReason":"..."}` which wins
    /// and ends the turn, or the continuation cap was reached (forced end).
    ForcedEnd(ForcedEndCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedEndCause {
    ContinuationCap,
    HookRequested,
}

/// Run all matching stop hooks and aggregate their feedback.
///
/// On genuine normal `end_turn` only, all matching `stop` hooks run;
/// `{"decision":"block","reason":"..."}` and
/// `hookSpecificOutput.additionalContext` aggregate bounded feedback for
/// another model round, while `{"continue":false,"stopReason":"..."}` wins and
/// ends the turn. All matching stop hooks run sequentially despite earlier
/// failures. The per-frame/job continuation cap is enforced at the SINGLE entry
/// check below: once the latch has already granted [`STOP_HOOK_MAX_CONTINUATIONS`]
/// continuations for its `(session, frame-or-job, originating user turn)`, the
/// next consultation force-ends the turn WITHOUT reconsulting (or recording) any
/// stop hook. The rows for the hooks already run on prior rounds remain the
/// audit trail of the forced end.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_stop_hooks(
    runner: &dyn CommandRunner,
    process_env: &dyn ProcessEnv,
    registry: &HookRegistry,
    event: HookEvent,
    match_value: &str,
    session_id: Uuid,
    workspace_root: &Path,
    db: &crate::db::Db,
    subagent_type: Option<&str>,
    subagent_id: Option<&str>,
    end_reason: Option<&str>,
    state: &mut StopGateState,
) -> StopHookOutcome {
    run_stop_hooks_cancellable(
        runner,
        process_env,
        registry,
        event,
        match_value,
        session_id,
        workspace_root,
        db,
        subagent_type,
        subagent_id,
        end_reason,
        state,
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_stop_hooks_cancellable(
    runner: &dyn CommandRunner,
    process_env: &dyn ProcessEnv,
    registry: &HookRegistry,
    event: HookEvent,
    match_value: &str,
    session_id: Uuid,
    workspace_root: &Path,
    db: &crate::db::Db,
    subagent_type: Option<&str>,
    subagent_id: Option<&str>,
    end_reason: Option<&str>,
    state: &mut StopGateState,
    cancel: &tokio_util::sync::CancellationToken,
) -> StopHookOutcome {
    // A stop consultation cancelled before entry is not a lifecycle boundary:
    // do not resolve commands, spawn handlers, or write misleading hook rows.
    if cancel.is_cancelled() {
        return StopHookOutcome::End;
    }
    // If already at the continuation cap, force end without reconsulting hooks.
    if state.capped() {
        if let Err(error) = db
            .insert_session_event(
                session_id,
                crate::db::session_log::SessionEventKind::Notice,
                None,
                None,
                &serde_json::json!({
                    "text": "Stop-hook continuation cap reached; ending without reconsulting hooks.",
                    "severity": "warning",
                    "source": STOP_HOOK_FORCED_END_SOURCE,
                    "hookEvent": event.key(),
                    "forcedEndCause": "continuation_cap",
                    "continuationsGranted": state.continuation_count,
                    "subagentId": subagent_id,
                }),
            )
            .await
        {
            tracing::warn!(%error, event = event.key(), "failed to record stop-hook forced end");
        }
        return StopHookOutcome::ForcedEnd(ForcedEndCause::ContinuationCap);
    }

    // Claim the lifecycle boundary before matcher resolution. Exactly-once is
    // about dispatching the native boundary, not about whether configuration
    // happened to contain a matching handler. Parent/drain reconciliation uses
    // this bit to avoid redispatching a completed child as a terminal stop when
    // the first dispatch legitimately matched zero hooks.
    state.lifecycle_event_emitted = true;
    if let Some(latch) = &state.lifecycle_event_latch {
        latch.store(true, std::sync::atomic::Ordering::Release);
    }

    let hooks = matching_hooks(registry, event, match_value);
    if hooks.is_empty() {
        return StopHookOutcome::End;
    }

    let timestamp = chrono::Utc::now().to_rfc3339();
    // First-class typed `stop` envelope fields (Decision 8): `stopReason`
    // carries the closed matcher token, and `stopHookActive` reflects whether
    // this consultation is already inside a continuation loop (set by a prior
    // round of THIS turn). Neither is overloaded onto the generic `source` /
    // `reason` keys, and neither carries any secret.
    let envelope = HookEnvelope::for_observe(
        event,
        session_id,
        workspace_root,
        &timestamp,
        None,
        None,
        None,
        None,
        subagent_type,
        subagent_id,
        ObserveFields {
            stop_reason: (event == HookEvent::Stop).then_some(match_value),
            end_reason,
            stop_hook_active: Some(state.stop_hook_active),
            ..ObserveFields::default()
        },
    );
    let stdin = envelope.to_json_string();

    let mut feedback = StopGateFeedback::default();

    for hook in hooks {
        // Cancellation ends the consultation between handlers. A handler that
        // was already running is cancelled by `run_cancellable`; later
        // handlers must never be spawned for an ended turn.
        if cancel.is_cancelled() {
            break;
        }
        // From this point the configured lifecycle handler owns the event,
        // even when executable resolution or process launch subsequently
        // fails (those failures are durably recorded below).
        let executable = match resolve_hook_executable(hook, process_env) {
            Some(path) => path,
            None => {
                record_hook_run(
                    db,
                    session_id,
                    event,
                    hook,
                    &HookDecision::Failed {
                        reason: REASON_EXECUTABLE_NOT_FOUND.to_string(),
                    },
                    0,
                    None,
                    None,
                    None,
                    subagent_id,
                )
                .await;
                continue;
            }
        };
        let env_result = build_child_env(
            hook,
            process_env,
            event,
            session_id,
            workspace_root,
            None,
            None,
        );
        let child_env = match env_result {
            Ok(env) => env,
            Err(reason) => {
                record_hook_run(
                    db,
                    session_id,
                    event,
                    hook,
                    &HookDecision::Failed { reason },
                    0,
                    None,
                    None,
                    None,
                    subagent_id,
                )
                .await;
                continue;
            }
        };
        let timeout = Duration::from_secs(hook.timeout_secs as u64);
        let args = &hook.command[1..];
        let raw = runner
            .run_cancellable(
                &executable,
                args,
                &child_env,
                workspace_root,
                &stdin,
                timeout,
                session_id,
                cancel,
            )
            .await;

        let decision = if let Some(reason) = raw.failure_reason {
            HookDecision::Failed {
                reason: reason.to_string(),
            }
        } else if raw.spawn_failed {
            HookDecision::Failed {
                reason: REASON_SPAWN_FAILED.to_string(),
            }
        } else if raw.timeout {
            HookDecision::Failed {
                reason: REASON_HOOK_TIMED_OUT.to_string(),
            }
        } else {
            parse_stop_decision(&raw.stdout, raw.exit_code)
        };

        record_hook_run(
            db,
            session_id,
            event,
            hook,
            &decision,
            raw.duration_ms,
            None,
            None,
            None,
            subagent_id,
        )
        .await;

        if cancel.is_cancelled() {
            break;
        }

        match decision {
            HookDecision::Continue { .. } => {
                // continue:false wins and ends the turn.
                feedback.forced_end = true;
            }
            HookDecision::Block {
                reason,
                additional_context,
            } => {
                feedback.blocks.push(reason);
                if let Some(ctx) = additional_context {
                    feedback.additional_contexts.push(ctx);
                }
            }
            // Allow and Failed are fail-open: no effect on aggregation.
            _ => {}
        }
    }

    if feedback.forced_end {
        if let Err(error) = db
            .insert_session_event(
                session_id,
                crate::db::session_log::SessionEventKind::Notice,
                None,
                None,
                &serde_json::json!({
                    "text": "A stop hook explicitly ended the turn.",
                    "severity": "info",
                    "source": STOP_HOOK_FORCED_END_SOURCE,
                    "hookEvent": event.key(),
                    "forcedEndCause": "hook_requested",
                    "continuationsGranted": state.continuation_count,
                    "subagentId": subagent_id,
                }),
            )
            .await
        {
            tracing::warn!(%error, event = event.key(), "failed to record hook-requested forced end");
        }
        return StopHookOutcome::ForcedEnd(ForcedEndCause::HookRequested);
    }

    if feedback.should_continue_round() {
        // Grant a continuation and count it against this frame/job's latch.
        // The cap is enforced solely at the entry check above: once the count
        // reaches STOP_HOOK_MAX_CONTINUATIONS, the NEXT consultation force-ends
        // without reconsulting hooks. That gives exactly `STOP_HOOK_MAX_
        // CONTINUATIONS` granted rounds before the forced end (rather than one
        // fewer), and keeps the "force-end WITHOUT reconsulting" semantics in a
        // single place.
        state.continuation_count = state.continuation_count.saturating_add(1);
        state.stop_hook_active = true;
        return StopHookOutcome::Continue {
            reason: feedback.combined_reason(),
            additional_context: feedback.combined_additional_context(),
        };
    }

    StopHookOutcome::End
}

/// Run all matching observe-only lifecycle hooks sequentially.
///
/// Observe-only hooks (`sessionStart`, `userPromptSubmit`, `permissionDenied`,
/// `subagentStart`, `preCompact`, `postCompact`, `stopFailure`, and
/// `sessionEnd`) never block. `subagentStop` is deliberately excluded: it is a
/// `G::Stop` event and every child-stop boundary routes through
/// [`run_stop_hooks`] exactly once. All matching observers run sequentially
/// even if an earlier observer fails. Each failed run is recorded; a
/// nonmatching handler produces no row.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_observe_hooks(
    runner: &dyn CommandRunner,
    process_env: &dyn ProcessEnv,
    registry: &HookRegistry,
    event: HookEvent,
    match_value: &str,
    session_id: Uuid,
    workspace_root: &Path,
    db: &crate::db::Db,
    tool_name: Option<&str>,
    tool_call_id: Option<&str>,
    subagent_type: Option<&str>,
    subagent_id: Option<&str>,
    fields: ObserveFields<'_>,
) {
    let hooks = matching_hooks(registry, event, match_value);
    if hooks.is_empty() {
        return;
    }

    let timestamp = chrono::Utc::now().to_rfc3339();
    let envelope = HookEnvelope::for_observe(
        event,
        session_id,
        workspace_root,
        &timestamp,
        tool_name,
        tool_call_id,
        None,
        None,
        subagent_type,
        subagent_id,
        fields,
    );
    let stdin = envelope.to_json_string();

    for hook in hooks {
        let executable = match resolve_hook_executable(hook, process_env) {
            Some(path) => path,
            None => {
                record_hook_run(
                    db,
                    session_id,
                    event,
                    hook,
                    &HookDecision::Failed {
                        reason: REASON_EXECUTABLE_NOT_FOUND.to_string(),
                    },
                    0,
                    None,
                    tool_name,
                    tool_call_id,
                    subagent_id,
                )
                .await;
                continue;
            }
        };
        let env_result = build_child_env(
            hook,
            process_env,
            event,
            session_id,
            workspace_root,
            tool_name,
            tool_call_id,
        );
        let child_env = match env_result {
            Ok(env) => env,
            Err(reason) => {
                record_hook_run(
                    db,
                    session_id,
                    event,
                    hook,
                    &HookDecision::Failed { reason },
                    0,
                    None,
                    tool_name,
                    tool_call_id,
                    subagent_id,
                )
                .await;
                continue;
            }
        };
        let timeout = Duration::from_secs(hook.timeout_secs as u64);
        let args = &hook.command[1..];
        let raw = runner
            .run(
                &executable,
                args,
                &child_env,
                workspace_root,
                &stdin,
                timeout,
                session_id,
            )
            .await;

        let decision = if let Some(reason) = raw.failure_reason {
            HookDecision::Failed {
                reason: reason.to_string(),
            }
        } else if raw.spawn_failed {
            HookDecision::Failed {
                reason: REASON_SPAWN_FAILED.to_string(),
            }
        } else if raw.timeout {
            HookDecision::Failed {
                reason: REASON_HOOK_TIMED_OUT.to_string(),
            }
        } else {
            parse_observe_decision(&raw.stdout, raw.exit_code)
        };

        record_hook_run(
            db,
            session_id,
            event,
            hook,
            &decision,
            raw.duration_ms,
            None,
            tool_name,
            tool_call_id,
            subagent_id,
        )
        .await;
    }
}

/// Stable, per-variant `&'static str` match value for a `stopFailure` hook.
///
/// Maps the runtime enum onto the constants owned by hook configuration, so
/// config validation, runtime dispatch, docs, and tests share one closed token
/// vocabulary. The two data-bearing variants (`Http`, `Other`) collapse to
/// stable coarse tokens rather than exposing volatile diagnostics.
pub(crate) fn error_class_match_value(
    class: &crate::engine::model::InferenceErrorClass,
) -> &'static str {
    use crate::config::extended::hooks as vocabulary;
    use crate::engine::model::InferenceErrorClass as C;
    match class {
        C::TimeoutTtft => vocabulary::ERROR_CLASS_TIMEOUT_TTFT,
        C::TimeoutIdle => vocabulary::ERROR_CLASS_TIMEOUT_IDLE,
        C::Network => vocabulary::ERROR_CLASS_NETWORK,
        C::Http(_) => vocabulary::ERROR_CLASS_HTTP,
        C::UtilityTimeout => vocabulary::ERROR_CLASS_UTILITY_TIMEOUT,
        C::MissingToolEntitlement { .. } => vocabulary::ERROR_CLASS_MISSING_TOOL_ENTITLEMENT,
        C::ClientSideToolsUnsupported => vocabulary::ERROR_CLASS_CLIENT_SIDE_TOOLS_UNSUPPORTED,
        C::ResponsesToolIdentity => vocabulary::ERROR_CLASS_RESPONSES_TOOL_IDENTITY,
        C::ProviderNotConfigured => vocabulary::ERROR_CLASS_PROVIDER_NOT_CONFIGURED,
        C::ProviderRateLimit => vocabulary::ERROR_CLASS_PROVIDER_RATE_LIMIT,
        C::BillingOrQuotaExhausted => vocabulary::ERROR_CLASS_BILLING_OR_QUOTA_EXHAUSTED,
        C::UnrenderableWireField => vocabulary::ERROR_CLASS_UNRENDERABLE_WIRE_FIELD,
        C::Other(_) => vocabulary::ERROR_CLASS_OTHER,
    }
}

#[cfg(test)]
mod tests;
