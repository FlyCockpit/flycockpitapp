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
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::config::extended::hooks::{HookEvent, HookRegistry, ResolvedHook};
use crate::db::session_log::{HookRunAudit, HookRunStatus};
use crate::process_containment::{
    ContainmentError, ContainmentGuarantee, ContainmentLease, EmptyOutcome,
    ProcessContainmentHandle,
};

/// Maximum size for serialized `toolInput` / `toolResult` envelope values
/// (128 KiB). Excess is replaced with a UTF-8-safe prefix and the
/// corresponding `toolInputTruncated` / `toolResultTruncated` boolean is set.
pub(crate) const ENVELOPE_VALUE_MAX_BYTES: usize = 128 * 1024;

/// Independent cap for stdout and stderr (64 KiB each).
pub(crate) const OUTPUT_CAP_BYTES: usize = 64 * 1024;

/// Grace window for reaping a deadline-killed hook child before giving up and
/// deferring to the lease's containment teardown. Bounds the post-`start_kill`
/// wait so an uninterruptible (D-state) child cannot stall the caller.
const HOOK_CHILD_REAP_GRACE: Duration = Duration::from_secs(2);

/// Maximum UTF-8-safe character length for a denial reason (1,024 chars).
pub(crate) const REASON_MAX_CHARS: usize = 1_024;

/// Default reason when a deny has a missing/blank reason.
pub(crate) const DEFAULT_DENY_REASON: &str = "blocked by preToolUse hook";

/// Single-sourced, closed failure-reason constants for the process-containment
/// path of hook execution (Decision #6). These exact strings are written to
/// `hook_run.reason` and asserted by containment tests; do not spell them
/// inline elsewhere.
///
/// Emitted when the platform cannot prove descendant containment *before* the
/// hook child would run (`ContainmentError::DescendantContainmentUnavailable`
/// or a non-Proven lease). The handler body never runs; the hook fails open.
pub(crate) const REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED: &str =
    "descendant_containment_unsupported";
/// Emitted when, after the child ran, the same-generation empty oracle could
/// not prove the descendant group empty (`EmptyOutcome::Uncertain` /
/// `Unsupported`, or a bounded barrier deadline). The hook fails open, the
/// durable containment recovery row is retained, and we do NOT claim the child
/// is gone.
pub(crate) const REASON_DESCENDANT_CONTAINMENT_UNCERTAIN: &str = "descendant_containment_uncertain";
/// Emitted when the containment actor itself errored while terminating or
/// awaiting empty (actor stopped, terminate error). The hook fails open.
pub(crate) const REASON_DESCENDANT_CONTAINMENT_FAILED: &str = "descendant_containment_failed";

/// Single-sourced, closed failure-reason constants for the ordinary execution
/// and stdout-parse paths of hook execution (Decision #6). These exact strings
/// are written to `hook_run.reason`, cited by the README hooks-contract block,
/// and asserted by `hooks_documentation_matches_typed_contract`; do not spell
/// them inline elsewhere.
///
/// The bare executable could not be resolved before the clean environment was
/// built (the handler body never runs; fail open).
pub(crate) const REASON_EXECUTABLE_NOT_FOUND: &str = "executable not found";
/// The child process could not be launched.
pub(crate) const REASON_SPAWN_FAILED: &str = "spawn failed";
/// The child did not finish within `timeoutSecs`.
pub(crate) const REASON_HOOK_TIMED_OUT: &str = "hook timed out";
/// stdout was not valid JSON.
pub(crate) const REASON_MALFORMED_JSON_OUTPUT: &str = "malformed JSON output";
/// stdout parsed but was not a JSON object.
pub(crate) const REASON_OUTPUT_NOT_JSON_OBJECT: &str = "output is not a JSON object";
/// stdout was a JSON object but did not match the closed hook-output shape.
pub(crate) const REASON_MALFORMED_HOOK_OUTPUT: &str = "malformed hook output";
/// Prefix for a non-zero exit with no parseable deny; the numeric status is
/// appended (`hook exited with non-zero status: <code>`).
pub(crate) const REASON_NONZERO_EXIT_PREFIX: &str = "hook exited with non-zero status";
/// A pre-tool hook used the stop-gate `block` vocabulary.
pub(crate) const REASON_UNEXPECTED_PRE_TOOL_BLOCK: &str =
    "unexpected decision 'block' for pre-tool event";
/// A stop-gate hook used the pre-tool `deny` vocabulary.
pub(crate) const REASON_UNEXPECTED_STOP_DENY: &str = "unexpected decision 'deny' for stop event";
/// A pre-tool hook produced an unknown or missing `decision`.
pub(crate) const REASON_UNKNOWN_OR_MISSING_DECISION: &str = "unknown or missing decision";

/// Bounded deadline for the post-run empty barrier. A single `terminate` +
/// single `await_empty` actor round-trip already bounds the common case; this
/// deadline guarantees that even a stuck platform oracle can never hang the
/// turn — on elapse the outcome is treated as uncertain (recovery row kept),
/// never as proven-empty settlement.
pub(crate) const CONTAINMENT_EMPTY_BARRIER_TIMEOUT: Duration = Duration::from_secs(10);

/// Reserved environment keys overwritten after configured env. Consumed by
/// [`build_child_env`] (the single source for these key names) and cited by the
/// documentation contract.
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
    /// `preCompact` / `postCompact` discriminator: `agent_requested` | `auto`
    /// | `manual`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compact_source: Option<String>,
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
        // Deliberately do NOT add ComSpec, PATHEXT, or any other host variable.
        for (key, value) in windows_clean_env_additions(process_env.system_root())? {
            env.insert(key.to_string(), value);
        }
    }

    // Overwrite reserved keys after configured env. The key names are the
    // single-sourced `RESERVED_ENV_KEYS` (Decision #6) so the runner, the
    // documentation contract, and tests cannot drift.
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

/// Windows-only clean-environment additions (`SystemRoot` + `WINDIR`), both
/// derived from the parent `SystemRoot` value obtained through the
/// [`ProcessEnv`] seam. Returns the missing-`SystemRoot` fail-open error when
/// the parent process has no `SystemRoot`, so a hook is never launched into an
/// unbootable Windows environment. `ComSpec`, `PATHEXT`, and every other host
/// variable are deliberately excluded.
///
/// This is a cross-platform pure function — compiled on all hosts, consumed
/// only under `#[cfg(windows)]` in [`build_child_env`] — so the construction
/// and its fail-open branch are unit-testable without a Windows host. On
/// non-Windows builds it is genuinely unused by production; the allow mirrors
/// the cross-platform [`ProcessEnv::system_root`] seam.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn windows_clean_env_additions(
    system_root: Option<String>,
) -> Result<Vec<(&'static str, String)>, String> {
    let root = system_root.ok_or_else(|| {
        "missing SystemRoot: cannot construct clean Windows environment".to_string()
    })?;
    Ok(vec![("SystemRoot", root.clone()), ("WINDIR", root)])
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
///
/// Secret-safety: this type intentionally carries only the hook's own stdout
/// (bounded, later clipped), coarse status flags, and a CLOSED `&'static str`
/// failure reason. It never carries argv, env, stdin, or a raw platform error
/// string, so nothing sensitive can reach the durable ledger or a log through
/// it.
#[derive(Debug, Clone)]
pub struct HookRawOutput {
    pub stdout: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub spawn_failed: bool,
    pub timeout: bool,
    /// Closed containment failure reason that overrides decision parsing. When
    /// `Some`, the hook fails open with exactly this reason (one of the
    /// `REASON_DESCENDANT_CONTAINMENT_*` constants). When `None`, the ordinary
    /// `spawn_failed` / `timeout` / stdout-parse decision applies.
    pub failure_reason: Option<&'static str>,
}

impl HookRawOutput {
    /// Fail-open output carrying a closed containment reason. Used before the
    /// hook body runs (unsupported) or after a non-proven-empty barrier.
    fn containment_failure(reason: &'static str, start: Instant) -> Self {
        Self {
            stdout: String::new(),
            exit_code: None,
            duration_ms: start.elapsed().as_millis() as u64,
            spawn_failed: false,
            timeout: false,
            failure_reason: Some(reason),
        }
    }
}

/// Outcome of running the actual hook child, independent of containment
/// bookkeeping. Produced by the injected spawner inside
/// [`run_hook_child_contained`] so the containment orchestration can be tested
/// with a fake adapter and without a real external executable.
struct ChildRunOutcome {
    stdout: String,
    exit_code: Option<i32>,
    spawn_failed: bool,
    timed_out: bool,
}

/// A command runner trait for deterministic tests.
///
/// Production uses [`TokioCommandRunner`]; tests inject a fake that captures
/// the command, env, stdin, cwd, and timeout without spawning a real process.
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run a hook command with the given executable, args, env, cwd, stdin
    /// envelope, and timeout. `session_id` is threaded so the production runner
    /// can acquire a per-session containment lease. Returns the raw output
    /// (stdout, exit code, duration, failure flags).
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
}

/// Terminate the lease and await the same-generation empty oracle, bounded so a
/// stuck platform oracle can never hang the turn. Only `ProvenEmpty` is
/// accepted as settlement (same contract as `process_containment/adapter.rs`).
enum EmptyBarrier {
    /// Same-generation oracle proved the group empty. Safe to settle.
    ProvenEmpty,
    /// Ambiguous (`Uncertain` / `Unsupported` after spawn, or barrier deadline).
    /// Keep the durable recovery row; do not claim the child is gone.
    Uncertain,
    /// The containment actor itself errored on terminate or await.
    ActorError,
}

async fn terminate_and_await_empty(
    handle: &ProcessContainmentHandle,
    lease: ContainmentLease,
) -> EmptyBarrier {
    // A single terminate + single await_empty actor round-trip — NOT a busy
    // loop. The WHOLE sequence (both `terminate` and `await_empty`) is under one
    // deadline so a stuck actor/platform on EITHER call can never hang the turn.
    let sequence = async {
        handle.terminate(lease.clone()).await?;
        handle.await_empty(lease).await
    };
    match tokio::time::timeout(CONTAINMENT_EMPTY_BARRIER_TIMEOUT, sequence).await {
        Ok(Ok(EmptyOutcome::ProvenEmpty { .. })) => EmptyBarrier::ProvenEmpty,
        Ok(Ok(EmptyOutcome::Uncertain { .. })) | Ok(Ok(EmptyOutcome::Unsupported { .. })) => {
            EmptyBarrier::Uncertain
        }
        // A terminate or await_empty actor error.
        Ok(Err(_)) => EmptyBarrier::ActorError,
        // Deadline on either call: we could not prove empty in time. Keep the
        // recovery row and fail open as uncertain; never proven-empty settlement.
        Err(_elapsed) => EmptyBarrier::Uncertain,
    }
}

/// Drop-safety for the hook lease while the child is running: if the run future
/// is dropped during `spawn_child`, the lease is still terminated + awaited via
/// a detached task, so a running hook child is never orphaned. The orchestrator
/// disarms the guard the instant the child exits (before the inline barrier), so
/// cleanup runs exactly once — either this detached terminate or the inline
/// barrier, never both.
struct HookLeaseGuard {
    handle: ProcessContainmentHandle,
    lease: Option<ContainmentLease>,
}

impl HookLeaseGuard {
    fn new(handle: ProcessContainmentHandle, lease: ContainmentLease) -> Self {
        Self {
            handle,
            lease: Some(lease),
        }
    }

    fn disarm(&mut self) {
        self.lease = None;
    }
}

impl Drop for HookLeaseGuard {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        // A dropped future cannot await; hand the SAME bounded terminate +
        // await_empty to a detached task if a runtime is available. This is a
        // single terminate + single await — never a busy loop.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let handle = self.handle.clone();
            rt.spawn(async move {
                let _ = terminate_and_await_empty(&handle, lease).await;
            });
        }
    }
}

/// Run one hook child under a proven containment lease (write-scope posture).
///
/// 1. Acquire a `ContainmentLease` via `create_and_spawn` with
///    `require_proven: true`. On `DescendantContainmentUnavailable` /
///    Unsupported-before-spawn, fail open with
///    [`REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED`] WITHOUT running the child.
/// 2. Run the real child (`spawn_child`) under the lease, guarded so a dropped
///    future still terminates it.
/// 3. Bounded `terminate` + `await_empty`. Only `EmptyOutcome::ProvenEmpty`
///    settles the real outcome; `Uncertain`/`Unsupported`-after-spawn yields
///    [`REASON_DESCENDANT_CONTAINMENT_UNCERTAIN`] (recovery row kept) and an
///    actor error yields [`REASON_DESCENDANT_CONTAINMENT_FAILED`].
///
/// The child spawn is injected so this orchestration is exercised by tests with
/// a `FakeProvenAdapter` / `FakeUnsupportedAdapter` and no real executable,
/// while production passes the real `tokio::process` spawner.
async fn run_hook_child_contained<F, Fut>(
    handle: &ProcessContainmentHandle,
    session_id: Uuid,
    program: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    start: Instant,
    spawn_child: F,
) -> HookRawOutput
where
    F: FnOnce(ContainmentLease) -> Fut,
    Fut: Future<Output = ChildRunOutcome>,
{
    // Transient program/args/cwd for the lease. They are NOT persisted: the
    // actor records only `operation_id` + content-free `SafeLocator`; env and
    // stdin never reach the lease at all.
    let operation_id = format!("hook-{}", Uuid::new_v4());
    let lease = match handle
        .create_and_spawn(session_id, operation_id, program, args, cwd, true)
        .await
    {
        Ok(lease) => lease,
        Err(ContainmentError::DescendantContainmentUnavailable { .. }) => {
            return HookRawOutput::containment_failure(
                REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED,
                start,
            );
        }
        // Any other actor error before spawn (actor stopped, queue saturated,
        // session deleting): fail open. No lease exists, so no child ran.
        Err(_) => {
            return HookRawOutput::containment_failure(REASON_DESCENDANT_CONTAINMENT_FAILED, start);
        }
    };

    // `require_proven: true` means the actor already rejected Unsupported, but
    // never run a hook child under a non-proven lease.
    if lease.guarantee() != ContainmentGuarantee::Proven {
        let _ = terminate_and_await_empty(handle, lease).await;
        return HookRawOutput::containment_failure(
            REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED,
            start,
        );
    }

    // The guard covers the window where the hook CHILD is running: if the run
    // future is dropped during `spawn_child`, the guard terminates the lease so
    // the child is never orphaned. Once the child has exited we DISARM before
    // the barrier, so cleanup runs exactly once: either the guard's detached
    // terminate (dropped while the child ran) or this inline barrier (child
    // already exited). A drop during the barrier itself leaves a non-proven
    // outcome on the actor's existing containment recovery path — no orphaned
    // child, since the child has already exited.
    let mut guard = HookLeaseGuard::new(handle.clone(), lease.clone());
    let outcome = spawn_child(lease.clone()).await;
    guard.disarm();
    let barrier = terminate_and_await_empty(handle, lease).await;

    match barrier {
        EmptyBarrier::ProvenEmpty => HookRawOutput {
            stdout: outcome.stdout,
            exit_code: outcome.exit_code,
            duration_ms: start.elapsed().as_millis() as u64,
            spawn_failed: outcome.spawn_failed,
            timeout: outcome.timed_out,
            failure_reason: None,
        },
        EmptyBarrier::Uncertain => {
            HookRawOutput::containment_failure(REASON_DESCENDANT_CONTAINMENT_UNCERTAIN, start)
        }
        EmptyBarrier::ActorError => {
            HookRawOutput::containment_failure(REASON_DESCENDANT_CONTAINMENT_FAILED, start)
        }
    }
}

/// Spawn the real hook child via `tokio::process` and capture bounded output.
///
/// This is the production execution seam — a plain cross-platform
/// `tokio::process::Command` with `env_clear`, piped stdio, an independent
/// stdout cap, and `kill_on_drop(true)` (in addition to the lease terminate +
/// empty barrier that owns cancellation). It is invoked from inside
/// [`run_hook_child_contained`] only after a proven lease exists.
async fn spawn_real_hook_child(
    executable: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
    cwd: &Path,
    stdin: &str,
    timeout: Duration,
) -> ChildRunOutcome {
    let mut cmd = tokio::process::Command::new(executable);
    cmd.args(args);
    cmd.current_dir(cwd);
    cmd.env_clear();
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    // Drop-safety for the local child handle, IN ADDITION TO the lease
    // terminate + empty barrier (never the sole authority).
    cmd.kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => {
            return ChildRunOutcome {
                stdout: String::new(),
                exit_code: None,
                spawn_failed: true,
                timed_out: false,
            };
        }
    };

    // Take all three pipes so stdin write, stdout capture, and stderr drain run
    // CONCURRENTLY. Writing the whole stdin before reading (or never reading
    // stderr) deadlocks whenever the child fills a kernel pipe buffer — a hook
    // that emits >64KiB on stderr, or that never consumes its stdin, would wedge.
    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    // Best-effort stdin writer. A child that exits or is killed mid-write yields
    // a broken pipe, which is not a hook failure — the deadline path owns the
    // outcome. Dropping the handle closes stdin so the child observes EOF.
    let stdin_bytes = stdin.as_bytes().to_vec();
    let stdin_fut = async move {
        if let Some(mut sin) = child_stdin {
            let _ = sin.write_all(&stdin_bytes).await;
        }
    };

    // Read stdout with independent cap.
    let stdout_fut = async move {
        if let Some(mut out) = child_stdout {
            let mut temp = vec![0u8; OUTPUT_CAP_BYTES + 1];
            let mut total = Vec::new();
            loop {
                let n = match out.read(&mut temp).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                total.extend_from_slice(&temp[..n]);
                if total.len() >= OUTPUT_CAP_BYTES {
                    total.truncate(OUTPUT_CAP_BYTES);
                    break;
                }
            }
            Some(total)
        } else {
            None
        }
    };

    // Drain stderr to EOF and discard it — only stdout carries the hook
    // decision. The drain exists solely so a chatty child never blocks on a full
    // stderr pipe.
    let stderr_fut = async move {
        if let Some(mut err) = child_stderr {
            let mut temp = vec![0u8; 8192];
            loop {
                match err.read(&mut temp).await {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        }
    };

    // Bound the ENTIRE interaction — stdin write, both drains, AND wait — under a
    // single deadline. Bounding only `child.wait()` is not enough: a hook can
    // fork a background descendant that inherits the pipe fds, so after the
    // direct child exits or is killed the drains never observe EOF and the join
    // would hang forever, starving the caller's lease teardown. On elapse we kill
    // the direct child and return; the caller's `terminate_and_await_empty` then
    // kills the whole containment group (descendants included), which is the real
    // authority for closing inherited pipes.
    let interaction = async {
        let (_stdin_done, stdout_result, _stderr_drained, wait_res) =
            tokio::join!(stdin_fut, stdout_fut, stderr_fut, child.wait());
        (stdout_result, wait_res)
    };

    match tokio::time::timeout(timeout, interaction).await {
        Ok((stdout_result, wait_res)) => {
            let exit_code = match wait_res {
                Ok(status) => status.code(),
                Err(_) => None,
            };
            let stdout_bytes = stdout_result.unwrap_or_default();
            let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
            // A missing exit status (wait error) is reported as a non-completion;
            // the caller maps both timeout and no-status to a Failed decision.
            let timed_out = exit_code.is_none();
            ChildRunOutcome {
                stdout,
                exit_code,
                spawn_failed: false,
                timed_out,
            }
        }
        Err(_elapsed) => {
            // Deadline hit. Kill+reap the direct child, but keep the reap itself
            // BOUNDED: an uninterruptible (D-state) child, or a `start_kill` that
            // does not immediately take, must not turn this into another
            // unbounded await that stalls the caller's lease teardown. The
            // `kill_on_drop(true)` handle plus the caller's
            // `terminate_and_await_empty` (which kills the whole containment
            // group) are the ultimate authority. Partial stdout is intentionally
            // dropped: the caller maps `timeout` to Failed and never parses it.
            let _ = child.start_kill();
            let _ = tokio::time::timeout(HOOK_CHILD_REAP_GRACE, child.wait()).await;
            ChildRunOutcome {
                stdout: String::new(),
                exit_code: None,
                spawn_failed: false,
                timed_out: true,
            }
        }
    }
}

/// Production command runner using tokio::process under a containment lease.
#[derive(Clone)]
pub struct TokioCommandRunner {
    /// The daemon's process-containment handle. Production always attaches it;
    /// when absent (some unit tests) every spawn fails open as
    /// [`REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED`].
    containment: Option<ProcessContainmentHandle>,
}

impl TokioCommandRunner {
    /// Construct a runner with no containment handle. Every hook spawn fails
    /// open as unsupported; only for unit tests that do not exercise the spawn
    /// path. Production must use [`TokioCommandRunner::with_optional_containment`].
    pub fn new() -> Self {
        Self { containment: None }
    }

    /// Construct a runner from a session's optional containment handle. When the
    /// handle is present (production daemon) hooks run under a proven lease; when
    /// absent (isolated/non-daemon sessions) hooks fail open as unsupported. This
    /// is the single constructor every production hook-spawn site uses so none
    /// can accidentally spawn without going through the containment path.
    pub fn with_optional_containment(handle: Option<ProcessContainmentHandle>) -> Self {
        Self {
            containment: handle,
        }
    }
}

impl Default for TokioCommandRunner {
    fn default() -> Self {
        Self::new()
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
        let start = Instant::now();
        // Production never spawns a hook without a containment handle. A missing
        // handle is fail-open unsupported, not a raw spawn.
        let Some(handle) = self.containment.clone() else {
            return HookRawOutput::containment_failure(
                REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED,
                start,
            );
        };
        // Clones for the injected spawner (the child spawn borrows nothing from
        // the orchestration's owned copies).
        let program = executable.to_path_buf();
        let args_owned = args.to_vec();
        let cwd_owned = cwd.to_path_buf();
        let env_owned = env.clone();
        let stdin_owned = stdin.to_string();
        run_hook_child_contained(
            &handle,
            session_id,
            program.clone(),
            args_owned.clone(),
            cwd_owned.clone(),
            start,
            move |_lease| async move {
                spawn_real_hook_child(
                    &program,
                    &args_owned,
                    &env_owned,
                    &cwd_owned,
                    &stdin_owned,
                    timeout,
                )
                .await
            },
        )
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
    ForcedEnd,
}

/// Run all matching stop-gate hooks and aggregate their feedback.
///
/// This is the SINGLE G::Stop dispatcher for both the root `stop` event and the
/// unified `subagentStop` event (all three child modes — interactive stack,
/// noninteractive job, detached Swarm — route their child stop through here, so
/// there is no separate `subagentStop` observe fire). A genuine completion the
/// caller can re-run passes `end_reason = Some("completed")` and honors a
/// returned [`StopHookOutcome::Continue`]; a terminal child stop (abort / fail /
/// cancel) passes the terminal `end_reason`, a fresh `state`, and ignores the
/// outcome (a dead child cannot continue).
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
    // Child-stop identity for the unified `subagentStop` dispatch (all three
    // modes route through this ONE G::Stop dispatcher). Root `stop` passes all
    // three `None`. `end_reason` populates the camelCase `endReason` envelope
    // field (`completed` for a genuine child completion the gate can re-run,
    // `aborted` / `failed` / `cancelled` for a terminal fire the caller runs
    // with a fresh discarded `state` and ignores the outcome of).
    subagent_type: Option<&str>,
    subagent_id: Option<&str>,
    end_reason: Option<&str>,
    state: &mut StopGateState,
) -> StopHookOutcome {
    // If already at the continuation cap, force end without reconsulting hooks.
    if state.capped() {
        return StopHookOutcome::ForcedEnd;
    }

    let hooks = matching_hooks(registry, event, match_value);
    if hooks.is_empty() {
        return StopHookOutcome::End;
    }

    let timestamp = chrono::Utc::now().to_rfc3339();
    // First-class typed stop-gate envelope fields (Decision 8): `stopHookActive`
    // reflects whether this consultation is already inside a continuation loop
    // (set by a prior round of THIS turn/frame/job). For the root `stop` event
    // `stopReason` carries the closed matcher token (`end_turn`); for
    // `subagentStop` the closed matcher token IS the child agent type, which is
    // already carried by `subagentType`, so `stopReason` stays `None` there and
    // the child fields (`subagentType` / `subagentId` / `endReason`) describe
    // the stop instead. Nothing is overloaded onto the generic `source` /
    // `reason` keys, and nothing carries a secret.
    let stop_reason = matches!(event, HookEvent::Stop).then_some(match_value);
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
            stop_reason,
            stop_hook_active: Some(state.stop_hook_active),
            end_reason,
            ..ObserveFields::default()
        },
    );
    let stdin = envelope.to_json_string();

    let mut feedback = StopGateFeedback::default();

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
        return StopHookOutcome::ForcedEnd;
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
/// `sessionEnd`) never block. `subagentStop` is NOT emitted through here — it is
/// a G::Stop event dispatched (in every mode) through [`run_stop_hooks`]. All
/// matching hooks run sequentially even if an earlier observer fails. Each
/// failed run is recorded; a nonmatching handler produces no row.
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
/// Reuses the inference error-class vocabulary
/// ([`InferenceErrorClass::as_str`]) so config matchers and tests share ONE
/// token set rather than a second parallel enum (F3). The two data-bearing
/// variants (`Http`, `Other`) collapse to a stable coarse token because the
/// helper must return `&'static str`.
pub(crate) fn error_class_match_value(
    class: &crate::engine::model::InferenceErrorClass,
) -> &'static str {
    use crate::engine::model::InferenceErrorClass as C;
    match class {
        C::TimeoutTtft => "timeout_ttft",
        C::TimeoutIdle => "timeout_idle",
        C::Network => "network",
        C::Http(_) => "http",
        C::UtilityTimeout => "utility_timeout",
        C::MissingToolEntitlement { .. } => "missing_tool_entitlement",
        C::ClientSideToolsUnsupported => "client_side_tools_unsupported",
        C::ResponsesToolIdentity => "responses_tool_identity",
        C::ProviderNotConfigured => "provider_not_configured",
        C::ProviderRateLimit => "provider_rate_limit",
        C::BillingOrQuotaExhausted => "billing_or_quota_exhausted",
        C::UnrenderableWireField => "unrenderable_wire_field",
        C::Other(_) => "other",
    }
}

#[cfg(test)]
mod tests;
