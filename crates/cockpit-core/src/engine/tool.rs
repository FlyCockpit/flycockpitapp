//! Tool abstraction for cockpit.
//!
//! Why we wrap rig's `Tool`/`ToolDyn` rather than using them directly:
//! the §12 repair layer needs a seam between rig's JSON-deserialized
//! arguments and the typed dispatcher. We pin `type Args = Value` on
//! every tool — rig's `ToolDyn` just `serde_json::from_str`s into
//! `Args`, which is infallible for `Value` — so by the time `call()`
//! runs we have a `serde_json::Value` we can mutate in place via
//! [`crate::engine::repair`].
//!
//! Concrete tools implement [`Tool`]; the dispatcher holds a
//! `BTreeMap<String, Arc<dyn Tool>>`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::engine::message::ToolDefinition;

pub use crate::daemon::proto::ToolFailKind;

/// Marker error a tool returns when the *arguments* were the problem
/// (see [`ToolFailKind::Invocation`]). The dispatcher downcasts to this
/// to classify the failure; build it with [`invalid_input`].
#[derive(Debug)]
pub struct InvalidToolInput(pub String);

impl std::fmt::Display for InvalidToolInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidToolInput {}

/// Build an [`InvalidToolInput`] error. Tools use this for missing /
/// wrong-type required args and for argument values that can't be
/// satisfied — anything that's the model's fault rather than the
/// environment's.
pub fn invalid_input(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(InvalidToolInput(msg.into()))
}

/// Deserialize already-repaired tool arguments into a tool-local args type.
///
/// This deliberately sits below the repair layer: [`Tool::call`] still receives
/// raw [`serde_json::Value`], then individual tools call this helper inside
/// `call` after validation/repair/path-normalization has mutated that value.
pub fn typed_args<A: DeserializeOwned>(args: Value) -> Result<A> {
    serde_json::from_value(args)
        .map_err(|err| invalid_input(format!("invalid tool arguments: {err}")))
}

/// Classify a dispatch error: an [`InvalidToolInput`] anywhere in the
/// chain means the model built the call badly; everything else is an
/// execution failure.
pub fn classify_failure(err: &anyhow::Error) -> ToolFailKind {
    if err.downcast_ref::<InvalidToolInput>().is_some() {
        ToolFailKind::Invocation
    } else {
        ToolFailKind::Execution
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolEffect {
    ReadOnly,
    Mutating,
    Dynamic,
}

/// Shared permission predicate for Cockpit-owned tools. Transport-specific
/// callers must use this instead of reinterpreting [`ToolEffect`] locally so a
/// native call and a Monty `mcp.invoke('cockpit', ...)` call agree.
pub fn tool_requires_permission(tool: &dyn Tool) -> bool {
    !matches!(tool.effect(), ToolEffect::ReadOnly)
}

pub const TOOL_PRESENTATION_SUMMARY_CHARS: usize = 240;
pub const TOOL_PRESENTATION_FULL_CHARS: usize = 2_000;

/// Display-neutral tool-call presentation.
///
/// Core owns the semantic choice of label, glyph key, and argument summary.
/// TUI code maps these plain strings onto terminal spans, colors, widths, and
/// glyph padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPresentation {
    pub glyph: Option<&'static str>,
    pub label: String,
    pub summary: String,
    pub full_input: String,
}

impl ToolPresentation {
    pub fn default_for(tool: &str, args: &Value) -> Self {
        let (summary, full_input) = readable_args(args);
        Self {
            glyph: None,
            label: tool.to_string(),
            summary,
            full_input,
        }
    }

    pub fn with_parts(
        glyph: Option<&'static str>,
        label: impl Into<String>,
        summary: impl Into<String>,
        full_input: impl Into<String>,
    ) -> Self {
        Self {
            glyph,
            label: label.into(),
            summary: summary.into(),
            full_input: full_input.into(),
        }
    }
}

pub fn readable_args(args: &Value) -> (String, String) {
    (
        crate::text::format_args(
            args,
            crate::text::ArgFormatOptions::history(TOOL_PRESENTATION_SUMMARY_CHARS, false),
        ),
        crate::text::format_args(
            args,
            crate::text::ArgFormatOptions::history(TOOL_PRESENTATION_FULL_CHARS, true),
        ),
    )
}

pub fn path_or_readable_args(args: &Value) -> (String, String) {
    string_field(args, "path")
        .map(|path| (path.clone(), path))
        .unwrap_or_else(|| readable_args(args))
}

pub fn string_field(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_string)
}

pub fn single_line_preview(s: &str, limit: usize) -> String {
    let mut first = s.lines().next().unwrap_or("").to_string();
    if s.contains('\n') {
        first.push_str(" …");
    }
    bounded_preview(&first, limit)
}

pub fn bounded_preview(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    let take = limit.saturating_sub(1);
    let mut out: String = s.chars().take(take).collect();
    out.push('…');
    out
}

pub fn known_tool_presentation(tool: &str, args: &Value) -> ToolPresentation {
    use crate::tools;
    match tool {
        "bash" => tools::bash::BashTool::new().presentation(args),
        "read" => tools::read::ReadTool.presentation(args),
        "readlock" => tools::readlock::ReadlockTool.presentation(args),
        "unlock" => tools::unlock::UnlockTool.presentation(args),
        "writeunlock" => tools::writeunlock::WriteunlockTool.presentation(args),
        "editunlock" => tools::editunlock::EditunlockTool.presentation(args),
        "websearch" => tools::web::WebSearchTool.presentation(args),
        "webfetch" => tools::web::WebFetchTool.presentation(args),
        // Legacy restored rows may carry the pre-unlock display names. They
        // are not current Tool implementors, so keep their old presentation
        // through the same display-neutral data path.
        "write" | "edit" => {
            let (summary, full_input) = path_or_readable_args(args);
            ToolPresentation::with_parts(Some("📝"), tool, summary, full_input)
        }
        _ => ToolPresentation::default_for(tool, args),
    }
}

#[derive(Debug, Clone)]
pub struct ReviewCage {
    state: Arc<Mutex<ReviewCageState>>,
}

#[derive(Debug)]
struct ReviewCageState {
    allowed_tools: HashSet<String>,
    viewed_skills: HashSet<String>,
    auto_deny_approvals: bool,
    max_dispatches: u32,
    dispatches: u32,
}

impl ReviewCage {
    pub fn skills_review() -> Self {
        Self {
            state: Arc::new(Mutex::new(ReviewCageState {
                allowed_tools: ["skill", "skill_manage"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                viewed_skills: HashSet::new(),
                auto_deny_approvals: true,
                max_dispatches: 16,
                dispatches: 0,
            })),
        }
    }

    pub fn allow_dispatch(&self, tool: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if !state.allowed_tools.contains(tool) {
            return Err(invalid_input(format!(
                "background skill review cannot call `{tool}`; allowed tools: {}",
                sorted_csv(&state.allowed_tools)
            )));
        }
        if state.dispatches >= state.max_dispatches {
            return Err(invalid_input(format!(
                "background skill review stopped after {} tool dispatches",
                state.max_dispatches
            )));
        }
        state.dispatches = state.dispatches.saturating_add(1);
        Ok(())
    }

    pub fn auto_deny_approvals(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .auto_deny_approvals
    }

    pub fn record_skill_view(&self, name: &str) {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .viewed_skills
            .insert(name.to_string());
    }

    pub fn skill_was_viewed(&self, name: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .viewed_skills
            .contains(name)
    }
}

fn sorted_csv(values: &HashSet<String>) -> String {
    let mut values: Vec<&str> = values.iter().map(String::as_str).collect();
    values.sort_unstable();
    values.join(", ")
}

#[cfg(test)]
mod typed_args_tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Deserialize)]
    struct GlobArgs {
        pattern: String,
    }

    #[test]
    fn typed_args_deserializes_after_repair_normalizes_aliases() {
        let schema = json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "x-cockpit-aliases": ["query"]
                }
            },
            "required": ["pattern"]
        });
        let mut args = json!({ "query": "**/*.rs" });

        let outcome = crate::engine::repair::repair(&mut args, &schema, "glob");
        assert!(outcome.valid, "{outcome:?}");

        let parsed: GlobArgs = typed_args(args).unwrap();
        assert_eq!(parsed.pattern, "**/*.rs");
    }

    #[test]
    fn typed_args_failures_are_invocation_errors() {
        let err = typed_args::<GlobArgs>(json!({})).unwrap_err();

        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
    }
}

/// A locked-down tool whose argument type is always `serde_json::Value`.
///
/// Implementors get the args **after** §12 repair has run; the caller's
/// `ctx` is opaque and threaded for cross-cutting state (lock manager,
/// session reference, redaction table, etc.). The output is rendered to
/// a string for the model — JSON, markdown, raw text, whatever fits.
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;

    /// One-sentence description per GOALS §10. Keep this terse enough for the
    /// normal/frontier tool array; the invariant test treats ~200 chars as the
    /// hard ceiling for built-ins.
    /// This is the **normal** `llm_mode` form (terse, the token-economy
    /// budget the CI check enforces).
    fn description(&self) -> &str;

    /// The **defensive** `llm_mode` description: explicit, steering prose
    /// for the weak-model target (implementation note).
    /// `None` (the default) means "no defensive variant — fall back to the
    /// terse [`Self::description`]." Registry-driven tests enforce defensive
    /// coverage for built-ins that reach the normal agent surface; dynamic or
    /// user-authored tools may rely on the terse fallback where that is the
    /// correct wording.
    fn defensive_description(&self) -> Option<String> {
        None
    }

    /// Authoritative side-effect classification for approval policy. Dynamic
    /// tools must conservatively require approval unless the concrete call is
    /// proven read-only by that tool's own policy.
    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    fn binary_requirements(&self) -> Vec<crate::capabilities::BinaryRequirement> {
        Vec::new()
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        ToolPresentation::default_for(self.name(), args)
    }

    /// JSON Schema for the arguments. Returning `Value::Null` means "no
    /// arguments." See plan.md §12 for the conventions the schema must
    /// follow for the repair catalog to fire. This is the **normal**
    /// `llm_mode` form (noun-phrase parameter descriptions).
    fn parameters(&self) -> Value;

    /// The **defensive** `llm_mode` parameter schema: same structure +
    /// required set as [`Self::parameters`], with explicit steering
    /// parameter descriptions. `None` (the default) reuses
    /// [`Self::parameters`]. Tool *grants* never vary by mode — only how
    /// the schema's descriptions read — so the shape here must match.
    fn defensive_parameters(&self) -> Option<Value> {
        None
    }

    /// Run the tool. The args have already passed through §12 repair (or
    /// validate-clean) before this call; the implementor only needs to
    /// look up the fields it cares about.
    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput>;

    /// True for tools whose `call` future actively observes [`ToolCtx::cancel`]
    /// and performs its own cleanup before returning from cancellation.
    fn honors_dispatch_cancel(&self) -> bool {
        false
    }

    /// Cleanup hook invoked by the dispatcher after abandoning an in-flight
    /// call due to timeout or turn cancellation. Most tools are abandon-safe
    /// and keep the default no-op; transport-backed tools can override this to
    /// tear down poisoned protocol state before the next call.
    async fn on_abandon(&self, _ctx: &ToolCtx) -> Result<()> {
        Ok(())
    }
}

/// Tool output shape.
///
/// `content` is what the model sees on the next turn. `truncated` tells
/// the §10 spillover path whether to write a full version to disk.
///
/// `recovery` and `canonical_args` let a tool communicate that the call
/// it received was *recoverable* — it ran successfully, but only after
/// the tool normalized the args in a way the model should learn from.
/// The edit cascade (GOALS §13c) is the only v0 user: when an edit
/// matches at stage > 1, the tool sets `recovery = EditCascade { stage,
/// path: "old_string" }` and `canonical_args = <original args with
/// old_string replaced by the matched bytes>`. The dispatcher uses
/// these to persist the canonical form to the audit row's
/// `wire_input_json` and to rewrite the in-memory assistant message so
/// the next inference call carries canonical bytes.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub content: String,
    /// Optional short-circuit guidance for an immediately repeated call with
    /// the same final semantic input. A tool sets this when its *result* was a
    /// recoverable dead-end the model should not repeat verbatim. The
    /// dispatcher records it in session-local memory and, on the next identical
    /// call, returns the guidance without re-running the tool.
    pub repeat_guard: Option<RepeatGuard>,
    /// True when [`content`] is capped (per the §10 truncation marker).
    pub truncated: bool,
    /// Optional retained source body for a truncated result. This is present
    /// only when the tool can supply bytes that were not delivered in
    /// [`content`], so retrieval is useful rather than a no-op.
    pub truncated_retention: Option<RetainedTruncatedOutput>,
    /// Optional recovery annotation. `None` means the tool ran without
    /// any normalization. The dispatcher prefers this over any
    /// shape-repair recovery that fired earlier in the same call.
    pub recovery: Option<crate::db::tool_calls::Recovery>,
    /// Optional canonical args. When `Some`, the dispatcher uses this
    /// as `wire_input_json` for the audit row and as the rewritten
    /// arguments in the assistant message's `ToolCall` in history.
    pub canonical_args: Option<serde_json::Value>,
    /// Optional sandbox-state metadata for the `tool_call` event (Part B).
    /// **Only `bash` populates it**; every other tool leaves it `None`, so
    /// the event omits the `sandbox` sub-object. It never enters the
    /// model's context (token economy, GOALS §10) — the dispatcher reads it
    /// solely to emit the timeline/export event.
    pub sandbox: Option<SandboxMeta>,
    /// Optional runtime resource-scheduler metadata for the `tool_call` event.
    /// Only `bash` populates it; it never enters model-facing content.
    pub resource: Option<ResourceMeta>,
    /// The structured process exit code for a `bash` call that ran a shell
    /// (export-audit fidelity). The authoritative source the exporter writes
    /// onto the `tool_call` event's `exit_code` field — distinct from the
    /// human-readable `exit: N` line kept in `content` for backward
    /// compatibility. `None` (key omitted) for every non-`bash` tool and on
    /// `bash`'s spawn/timeout/cancel paths (no shell exit to report). Never
    /// enters the model's context — the dispatcher reads it solely for the
    /// timeline/export event.
    pub exit_code: Option<i32>,
    /// Optional post-run artifact payload for audit export. Tools must not put
    /// this in model-facing content; the dispatcher scrubs string fields before
    /// persisting it onto the durable event, and the exporter writes it as a
    /// sidecar file.
    pub output_sidecar: Option<ToolOutputSidecar>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedTruncatedOutput {
    /// Retained pre-truncation bytes, capped by the producing tool.
    pub content: String,
    /// Full byte length of the pre-truncation body observed by the producer.
    /// This may exceed `content.len()` when [`partial`] is true.
    pub original_byte_len: usize,
    /// True when [`content`] is only a capped prefix of the original body.
    pub partial: bool,
}

#[derive(Debug, Clone)]
pub struct ToolOutputSidecar {
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct RepeatGuard {
    pub message: String,
}

/// `bash`-only sandbox-state record for the `tool_call` event (Part B,
/// data/export — never model-facing). Captures which of the four sandbox
/// states a `bash` call took so an exported `events.json` is diagnosable:
/// sandbox-off-granted, sandbox-off-approved, confined-success, and
/// confined-fail-to-escalate (prompted or preauthorized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMeta {
    /// Sandboxing was on for this session + platform supports it.
    pub enabled: bool,
    /// The first run actually ran confined.
    pub confined: bool,
    /// A confined non-zero exit triggered the permission re-run path.
    pub escalated: bool,
    /// Every simple command had a qualifying stored grant, so a trusted
    /// confined failure may rerun unconfined without raising a prompt.
    pub escalation_preauthorized: bool,
    /// The scope chosen on the escalation approval (`once`/`session`/
    /// `project`/`global`), or `None` when not escalated / denied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_scope_recorded: Option<String>,
    /// Set **only** on the sandbox-unavailable refuse path: the diagnosed
    /// reason (the same `SandboxGate::Refuse { reason }` text, including the
    /// `sudo sysctl …=0` command when diagnosed). Carries the user-facing
    /// remedy out-of-band so the engine can raise a deterministic persistent
    /// indicator (`implementation notes` §6.5). Never model-facing (token economy
    /// §10); `None` on every non-refuse path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    /// Optional command resource profiles applied to this bash invocation.
    /// This is export/event metadata only; it explains extra allowlisted
    /// roots such as Rust toolchain homes without entering model context.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_profiles: Vec<SandboxResourceProfileMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxResourceProfileMeta {
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configured_wrappers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub introspection: Vec<SandboxResourceIntrospectionMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<SandboxResourceRootMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_roots: Vec<SandboxResourceRootMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxResourceRootMeta {
    pub kind: String,
    pub path: String,
    pub access: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributing_profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxResourceIntrospectionMeta {
    pub tool: String,
    pub command: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMeta {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub declared: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub policy: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reviewer: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub effective: BTreeMap<String, u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler_display_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquired_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    pub acquired: bool,
    pub released_on_drop: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ContextUsageSnapshot {
    pub ctx_pct: Option<f64>,
    pub used_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub compact_nudge_pct: u8,
    pub auto_compact_pct: u8,
}

impl ContextUsageSnapshot {
    pub fn unavailable() -> Self {
        Self {
            ctx_pct: None,
            used_tokens: None,
            total_tokens: None,
            compact_nudge_pct: crate::config::providers::ContextConfig::default().compact_nudge_pct,
            auto_compact_pct: 60,
        }
    }
}

impl ToolOutput {
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            repeat_guard: None,
            truncated: false,
            truncated_retention: None,
            recovery: None,
            canonical_args: None,
            sandbox: None,
            resource: None,
            exit_code: None,
            output_sidecar: None,
        }
    }

    pub fn truncated_text(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            repeat_guard: None,
            truncated: true,
            truncated_retention: None,
            recovery: None,
            canonical_args: None,
            sandbox: None,
            resource: None,
            exit_code: None,
            output_sidecar: None,
        }
    }

    pub fn with_truncated_retention(mut self, retention: RetainedTruncatedOutput) -> Self {
        self.truncated_retention = Some(retention);
        self
    }

    /// Attach `bash` sandbox-state metadata for the `tool_call` event
    /// (Part B). Only `bash` calls this; the content is unchanged.
    pub fn with_sandbox(mut self, sandbox: SandboxMeta) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    pub fn with_resource(mut self, resource: ResourceMeta) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn with_bash_meta(self, sandbox: SandboxMeta, resource: &Option<ResourceMeta>) -> Self {
        let out = self.with_sandbox(sandbox);
        match resource {
            Some(resource) => out.with_resource(resource.clone()),
            None => out,
        }
    }

    /// Attach the `bash` process exit code for the `tool_call` event's
    /// authoritative `exit_code` field (export-audit fidelity). Only `bash`
    /// calls this, and only on a run that produced a shell exit; the content
    /// is unchanged.
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    pub fn with_output_sidecar(mut self, sidecar: ToolOutputSidecar) -> Self {
        self.output_sidecar = Some(sidecar);
        self
    }

    pub fn with_repeat_guard(mut self, message: impl Into<String>) -> Self {
        self.repeat_guard = Some(RepeatGuard {
            message: message.into(),
        });
        self
    }

    /// Attach a recovery annotation and the canonical arg form. See the
    /// struct docs for the contract.
    pub fn with_recovery(
        mut self,
        recovery: crate::db::tool_calls::Recovery,
        canonical_args: serde_json::Value,
    ) -> Self {
        self.recovery = Some(recovery);
        self.canonical_args = Some(canonical_args);
        self
    }
}

/// State threaded into every tool call.
///
/// Holding `Arc`s here means the dispatcher can clone-and-stash this
/// without copying the lock manager / session contents. Tools must not
/// hold references across `.await` points past the borrow this gives
/// them.
#[derive(Clone)]
pub struct ToolCtx {
    pub agent_id: String,
    /// Current outer model tool-call id, when this context was built for a
    /// live model-issued tool dispatch. Host-side tools can use it to parent
    /// synthetic UI/telemetry events without exposing the id to tool schemas or
    /// model-visible arguments. `bash` may echo it in sandbox failure text so
    /// the model can call `escalate` with the required id.
    pub current_tool_call_id: Option<String>,
    /// The active LLM-mode of the calling agent. Read by tools that vary
    /// *behavior* (not just description prose) on the defensive/normal axis —
    /// today only `bash`, which appends a defensive-mode-only file/search
    /// routing nudge to its result body
    /// (implementation note). Mirrors
    /// `agent.llm_mode` at the dispatch site; `Normal` in test/seed-tool
    /// contexts so the nudge is silent there.
    pub llm_mode: crate::config::extended::LlmMode,
    pub locks: Arc<crate::locks::LockManager>,
    pub session: Arc<crate::session::Session>,
    pub cwd: std::path::PathBuf,
    /// Session-scoped, turn-pinned config reader. The single access path to
    /// resolved config for turn-scoped tools — tools read `config.extended()`
    /// / `config.providers()` instead of re-loading config from disk, so they
    /// observe the same generationed snapshot (and turn-boundary semantics) as
    /// the rest of the turn (`engine-config-snapshot-adoption`).
    pub config: crate::daemon::session_worker::SessionConfigHandle,
    /// The redaction chokepoint (GOALS §7). Tools that return strings
    /// destined for the model context don't have to call this
    /// themselves — `engine::agent::turn` scrubs every tool result
    /// before it lands in history. Threaded here too for tools that
    /// want to scrub *before* a long output is even allocated (e.g.
    /// `bash` capping output and only scrubbing what fits).
    pub redact: Arc<crate::redact::RedactionTable>,
    /// Per-session environment overlay from attached clients. Spawned tools
    /// merge this explicitly instead of mutating process-global env.
    pub env_overlay: Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>,
    /// Interrupt wakeup hub (GOALS §3b). Structural tools that block on
    /// a human answer — today only `question` — raise an interrupt
    /// through this and await the resolution that arrives, out of band,
    /// on the daemon worker's `ResolveInterrupt` path. Threaded as an
    /// `Arc` so the same hub instance is shared with the worker.
    pub interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    /// Per-turn cancellation token (user ctrl+c → `CancelTurn`). Long-
    /// running tools — today `bash` — race their subprocess against
    /// `cancel.cancelled()` and kill it (process group on Unix) when the
    /// user aborts the turn, so a runaway test run dies promptly instead
    /// of holding the turn open. Fresh per turn; cancelling it never
    /// affects a later turn.
    pub cancel: tokio_util::sync::CancellationToken,
    /// Daemon shutdown gate shared by the active model for this turn. Utility
    /// models built inside tools (for example harness-result summarization)
    /// install it so background utility calls are abandoned during drain.
    pub shutdown_gate: crate::daemon::shutdown::ShutdownSignal,
    /// Command/path approval driver (sandboxing part 2). The `bash` tool
    /// consults it for the run-fail-escalate flow (broadened re-run on a
    /// non-zero sandboxed exit), and the native file/intel tools consult
    /// it via [`crate::tools::sandbox::check_native_access`] to escalate
    /// an out-of-boundary path access. `None` on paths with no client
    /// fan-out (seed-tool re-execution, tool tests): a missing approver
    /// skips the prompt — it never silently denies. Shared `Arc` so one
    /// approver instance backs the whole delegation tree.
    pub approver: Option<Arc<crate::approval::Approver>>,
    /// The current frame's deferred-log buffer (`plan.md §3d`). A subagent's
    /// `defer_to_orchestrator` tool appends out-of-scope asks here; the
    /// driver drains it when the frame pops and folds it into the report the
    /// parent ingests. `Default` (empty) for the root frame and for contexts
    /// with no subagent (tests, seed-tool re-exec) — defer there is a no-op
    /// drain nobody reads.
    pub deferred_log: crate::engine::deferred::DeferredLog,
    /// The current frame's seed collector (GOALS §3c). A re-queryable
    /// read-only noninteractive subagent's `seed` tool appends `{tool, args}`
    /// entries here; the driver drains them on return and injects them into
    /// the caller's transcript. `Default` (empty) for the root frame, the
    /// interactive path, and contexts with no subagent (tests, seed-tool
    /// re-exec) — `seed` there is a no-op drain nobody reads.
    pub seeds: crate::engine::seed_collector::SeedCollector,
    /// Whether this tool call belongs to the foreground root frame. Driver-level
    /// controls such as agent-requested compaction are only valid there.
    pub root_agent_frame: bool,
    /// Trusted provenance for skill mutations. Ordinary foreground and test
    /// calls default to `Foreground`; the isolated self-improvement reviewer
    /// overrides this on its frame without exposing the field to model args.
    pub skill_write_origin: crate::skills::manage::SkillWriteOrigin,
    /// Optional dispatch/read-before-write cage for background self-improvement
    /// review. Foreground turns leave this unset.
    pub review_cage: Option<ReviewCage>,
    /// Turn-start context-pressure snapshot for model-facing introspection.
    pub context_usage: Option<ContextUsageSnapshot>,
    /// Exact tool names advertised to the calling agent for this turn. Skill
    /// package activation uses this session-local surface for Hermes
    /// `requires_tools` / `fallback_for_tools` gates.
    pub available_tools: Arc<std::collections::HashSet<String>>,
    /// Frozen Monty builtin registry for this agent/tool context. It contains
    /// the host control functions plus native tools made scriptable for the
    /// session's tool tier placement.
    pub mcp_builtin_registry: Arc<crate::mcp::builtin::BuiltinRegistry>,
    /// Whether the calling agent holds the `tree` tool. Lets a tool steer a
    /// recovery hint to the caller's actual surface (e.g. `read` on a
    /// directory suggests `tree` only when the agent can use it) rather than
    /// name-guessing capabilities. Populated from the agent's `ToolBox` at the
    /// live dispatch site; `false` in test/seed-tool contexts with no toolbox.
    pub has_tree: bool,
    /// Whether the calling agent holds the `bash` tool. The `bash` fallback for
    /// the same surface-aware recovery hints (used when `tree` is absent).
    pub has_bash: bool,
    /// The per-turn event stream (`engine::agent::TurnEvent`), so a tool that
    /// blocks can surface a transient client indicator without inventing a
    /// second broadcast authority — it routes through the same seam the turn
    /// loop uses (implementation note). Today only
    /// `readlock` uses it, to emit the `WaitingForLock` start/clear pair while
    /// blocked on a contended lock. `None` in test / seed-tool / headless
    /// contexts with no client fan-out — emitting is then a silent no-op.
    pub events: Option<tokio::sync::mpsc::Sender<crate::engine::agent::TurnEvent>>,
    /// Daemon-owned LSP manager. `None` in tests/replay contexts; LSP is
    /// advisory, so tools skip diagnostics/navigation when absent.
    pub lsp: Option<Arc<crate::daemon::lsp::LspManager>>,
    /// Daemon-owned resource scheduler for runtime permit acquisition. `None`
    /// for tests/replay paths and ephemeral daemons that opt out of the shared
    /// machine/user queue.
    #[allow(dead_code)]
    pub resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
}

/// A per-agent description override for a single tool, carried on the
/// [`ToolBox`] alongside the tool itself. The **same tool ID and the same
/// SCHEMA** are shared across every agent — only the *description text* is
/// selected per agent + per [`LlmMode`]. This is the per-agent axis that
/// composes onto the existing per-mode axis applied in [`definition_of`]:
/// the override's text, when present for the active mode, *replaces* the
/// description the per-mode logic would otherwise render; the parameters are
/// never touched (schema variation would change validation/repair behavior —
/// project guidance design rule). Authored both by the built-in factories (via
/// [`ToolBox::with_override`]) and by markdown agent defs (their
/// `tool_descriptions:` frontmatter).
///
/// Each field is `None` by default → fall through to the tool's own base
/// (per-mode) description, so an agent with no override behaves
/// byte-identically to today. Per the token-economy budget (§10) each
/// override stays one terse sentence.
///
/// [`LlmMode`]: crate::config::extended::LlmMode
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolDescOverride {
    /// The `Normal`-mode description text. `None` → keep the tool's terse
    /// [`Tool::description`].
    pub normal: Option<String>,
    /// The `Frontier`-mode description text. `None` → keep the tool's terse
    /// [`Tool::description`].
    pub frontier: Option<String>,
    /// The `Defensive`-mode description text. `None` → keep the tool's
    /// [`Tool::defensive_description`] (or its terse fallback).
    pub defensive: Option<String>,
}

impl ToolDescOverride {
    /// The override text selected for `mode`, if this override supplies one.
    fn text_for(&self, mode: crate::config::extended::LlmMode) -> Option<&str> {
        use crate::config::extended::LlmMode;
        match mode {
            LlmMode::Normal => self.normal.as_deref(),
            LlmMode::Frontier => self.frontier.as_deref(),
            LlmMode::Defensive => self.defensive.as_deref(),
        }
    }

    /// True when neither mode carries an override — a no-op override that the
    /// builder can drop so the `ToolBox`'s serialized form stays byte-stable
    /// (an empty override is indistinguishable from no override).
    fn is_empty(&self) -> bool {
        self.normal.is_none() && self.frontier.is_none() && self.defensive.is_none()
    }
}

/// Project the `Tool` trait into a `ToolDefinition` rig understands.
///
/// This is the **single** place both description axes are applied. First the
/// `llm_mode` description-verbosity axis
/// (implementation note): in [`LlmMode::Defensive`] we
/// render each tool's [`Tool::defensive_description`] /
/// [`Tool::defensive_parameters`] when present, falling back to the terse
/// [`Tool::description`] / [`Tool::parameters`] otherwise; in
/// [`LlmMode::Normal`] and [`LlmMode::Frontier`] we always render the terse
/// form. Then the **per-agent**
/// axis composes on top: when `desc_override` supplies text for the active
/// mode, it *replaces* the description chosen above — the parameters (schema)
/// are never overridden, so the tool's ID and SCHEMA stay uniform across every
/// agent. Both switches live here and nowhere else — no per-tool conditionals
/// at call sites.
pub fn definition_of(
    tool: &dyn Tool,
    mode: crate::config::extended::LlmMode,
    desc_override: Option<&ToolDescOverride>,
) -> ToolDefinition {
    use crate::config::extended::LlmMode;
    let (base_description, parameters) = match mode {
        LlmMode::Defensive => (
            tool.defensive_description()
                .unwrap_or_else(|| tool.description().to_string()),
            tool.defensive_parameters()
                .unwrap_or_else(|| tool.parameters()),
        ),
        LlmMode::Normal | LlmMode::Frontier => (tool.description().to_string(), tool.parameters()),
    };
    // Per-agent axis: an override for the active mode wins over the base
    // description. Schema is intentionally untouched.
    let description = desc_override
        .and_then(|o| o.text_for(mode))
        .map(str::to_string)
        .unwrap_or(base_description);
    ToolDefinition {
        name: tool.name().to_string(),
        description,
        parameters,
    }
}

/// Behavioral capabilities gated on the [`LlmMode`] axis.
///
/// [`definition_of`] above is the *description-verbosity* seam — it changes
/// how a tool's schema reads, never what the engine will accept. This is the
/// separate **behavioral** seam: a real capability check the engine consults
/// before *acting*, so a mode can disable a feature outright rather than just
/// rewording its prose. [`Capability::enabled`] is the single predicate; the
/// engine calls it at the point of action (e.g. before minting a re-query
/// handle or honoring a `resume_handle`/`seed`), so a disabled capability is
/// rejected/inert regardless of what the model asked for.
///
/// [`LlmMode`]: crate::config::extended::LlmMode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Re-queryable read-only noninteractive subagents + seeded tool calls
    /// (GOALS §3c): the follow-up handle, `resume_handle` rehydration, and
    /// `seed` injection. Available outside defensive mode.
    FollowupSeed,
    /// Explicit sandbox escalation reruns. Available only to stronger modes;
    /// defensive mode gets the separate human-offer path instead.
    SandboxEscalate,
}

impl Capability {
    /// Whether this capability is available under `mode`. Disabled
    /// capabilities are gated at the engine's point of action, not merely
    /// hidden in description text.
    pub fn enabled(self, mode: crate::config::extended::LlmMode) -> bool {
        use crate::config::extended::LlmMode;
        match self {
            // Follow-up/seed is a stronger-model affordance: the weak-model
            // (defensive) target re-spawns cold instead (GOALS §3c).
            Capability::FollowupSeed | Capability::SandboxEscalate => {
                matches!(mode, LlmMode::Normal | LlmMode::Frontier)
            }
        }
    }
}

/// Registry of tools available to an agent. Keyed by name for O(log n)
/// dispatch. Use [`ToolBox::with`] to add tools.
///
/// Alongside the tools, the box carries an optional **per-agent description
/// override** per tool name ([`ToolDescOverride`]), applied at
/// [`Self::definitions`] time. The override changes only the rendered
/// *description text* — never the tool's ID or SCHEMA — so the same tool can
/// encode different per-agent intent (e.g. `Build` "delegate-eager" vs a
/// "do-it-yourself" agent) while validation/repair stay uniform. Overrides are
/// fixed at agent-construction time, so the serialized tools array stays
/// byte-stable for a given `(agent, mode)` → prompt-cache hit preserved; this
/// adds **no** new mid-session mutation.
#[derive(Default, Clone)]
pub struct ToolBox {
    tools: BTreeMap<String, Arc<dyn Tool>>,
    mcp_builtin_tools: BTreeMap<String, McpBuiltinToolEntry>,
    /// Per-tool-name description overrides. Empty (the default) means every
    /// tool renders its own base/per-mode description — byte-identical to the
    /// pre-override behavior.
    overrides: BTreeMap<String, ToolDescOverride>,
    /// Rendered tool schemas for this finalized toolbox, keyed by LLM mode.
    /// Builder-style mutations clear it so per-agent overrides stay exact.
    definition_cache: Arc<Mutex<HashMap<crate::config::extended::LlmMode, Vec<ToolDefinition>>>>,
    capability_unavailable: BTreeMap<String, Vec<crate::capabilities::ToolCapabilityIssue>>,
    capability_description_suffixes: BTreeMap<String, Vec<String>>,
}

#[derive(Clone)]
struct McpBuiltinToolEntry {
    tool: Arc<dyn Tool>,
    directly_callable: bool,
}

pub(crate) fn is_monty_builtin_adaptable(name: &str) -> bool {
    !matches!(
        name,
        "question"
            | "handoff"
            | "return"
            | "schedule"
            | "task"
            | "spawn"
            | "defer_to_orchestrator"
            | "start_build"
            | "mcp"
    )
}

impl ToolBox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, tool: Arc<dyn Tool>) -> Self {
        let name = tool.name().to_string();
        if is_monty_builtin_adaptable(&name) {
            self.mcp_builtin_tools.insert(
                name.clone(),
                McpBuiltinToolEntry {
                    tool: tool.clone(),
                    directly_callable: true,
                },
            );
        }
        self.tools.insert(name.clone(), tool);
        self.capability_unavailable.remove(&name);
        self.capability_description_suffixes.remove(&name);
        self.definition_cache.lock().unwrap().clear();
        self
    }

    pub fn without(mut self, name: &str) -> Self {
        self.tools.remove(name);
        self.mcp_builtin_tools.remove(name);
        self.overrides.remove(name);
        self.capability_unavailable.remove(name);
        self.capability_description_suffixes.remove(name);
        self.definition_cache.lock().unwrap().clear();
        self
    }

    pub fn with_discoverable_mcp(mut self, tool: Arc<dyn Tool>) -> Self {
        let name = tool.name().to_string();
        if is_monty_builtin_adaptable(&name) {
            self.mcp_builtin_tools.insert(
                name,
                McpBuiltinToolEntry {
                    tool,
                    directly_callable: false,
                },
            );
        }
        self.definition_cache.lock().unwrap().clear();
        self
    }

    pub fn mcp_builtin_registry(&self) -> Arc<crate::mcp::builtin::BuiltinRegistry> {
        let funcs = self
            .mcp_builtin_tools
            .iter()
            .filter(|(name, _entry)| !self.capability_unavailable.contains_key(*name))
            .filter_map(|(_name, entry)| {
                let adapter =
                    crate::mcp::builtin::ToolOutputBuiltinAdapter::new(entry.tool.clone())
                        .with_direct_call_marker(entry.directly_callable);
                adapter.into_function().ok()
            })
            .collect();
        Arc::new(crate::mcp::builtin::BuiltinRegistry::default_with(funcs))
    }

    pub(crate) fn discoverable_mcp_tool_names(&self) -> Vec<String> {
        self.mcp_builtin_tools
            .iter()
            .filter(|(name, entry)| {
                !entry.directly_callable && !self.capability_unavailable.contains_key(*name)
            })
            .map(|(name, _entry)| name.clone())
            .collect()
    }

    /// Register a per-agent description override for the tool named `name`.
    /// The override only takes effect once a tool with that name is present
    /// (registering for an absent name is inert — the tools array is what the
    /// model sees). An empty override (no text for either mode) is dropped so
    /// the box's serialized form is unaffected. Called by the built-in agent
    /// factories and by the markdown-agent builder to author per-agent intent.
    pub fn with_override(mut self, name: &str, ov: ToolDescOverride) -> Self {
        self.set_override_if_changed(name, ov);
        self
    }

    pub fn set_override_if_changed(&mut self, name: &str, ov: ToolDescOverride) -> bool {
        let changed = if ov.is_empty() {
            self.overrides.remove(name).is_some()
        } else if self.overrides.get(name) == Some(&ov) {
            false
        } else {
            self.overrides.insert(name.to_string(), ov);
            true
        };
        if changed {
            self.definition_cache.lock().unwrap().clear();
        }
        changed
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        if self.capability_unavailable.contains_key(name) {
            return None;
        }
        self.tools.get(name)
    }

    pub fn get_cloned(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.get(name).cloned()
    }

    pub fn apply_capabilities(
        mut self,
        env: &std::collections::HashMap<String, String>,
        cwd: &std::path::Path,
        target: crate::capabilities::ExecutionTarget,
    ) -> Self {
        let cache = crate::capabilities::default_probe_cache();
        self.apply_capabilities_with_cache(env, cwd, target, &cache);
        self
    }

    pub fn apply_capabilities_with_cache(
        &mut self,
        env: &std::collections::HashMap<String, String>,
        cwd: &std::path::Path,
        target: crate::capabilities::ExecutionTarget,
        cache: &crate::capabilities::CapabilityProbeCache,
    ) {
        self.capability_unavailable.clear();
        self.capability_description_suffixes.clear();
        for (name, tool) in &self.tools {
            let requirements = tool.binary_requirements();
            let evaluation = crate::capabilities::evaluate_tool_requirements(
                name,
                &requirements,
                env,
                cwd,
                target,
                cache,
            );
            if !evaluation.unavailable.is_empty() {
                self.capability_unavailable
                    .insert(name.clone(), evaluation.unavailable);
            }
            if !evaluation.optional_missing.is_empty() {
                self.capability_description_suffixes.insert(
                    name.clone(),
                    evaluation
                        .optional_missing
                        .into_iter()
                        .map(|issue| {
                            format!(
                                " Optional `{}` missing: {}",
                                issue.requirement.name,
                                issue.render_remedy(crate::capabilities::RemedyPlatform::current())
                            )
                        })
                        .collect(),
                );
            }
        }
        self.definition_cache.lock().unwrap().clear();
    }

    pub fn capability_unavailable(
        &self,
    ) -> impl Iterator<Item = &crate::capabilities::ToolCapabilityIssue> {
        self.capability_unavailable
            .values()
            .flat_map(|issues| issues.iter())
    }

    pub fn capability_notice_text(&self) -> Option<String> {
        crate::capabilities::missing_required_notice(
            self.capability_unavailable().cloned(),
            crate::capabilities::RemedyPlatform::current(),
        )
    }

    pub fn capability_notice_fix_command(&self) -> Option<String> {
        crate::capabilities::first_copyable_install_command(
            self.capability_unavailable().cloned(),
            crate::capabilities::RemedyPlatform::current(),
        )
    }

    /// Project every tool to a `ToolDefinition`, rendering descriptions in
    /// the given `llm_mode` and applying any per-agent override. The `mode`
    /// flows from the active [`crate::config::extended::LlmMode`] through the
    /// agent spawn; the overrides are the ones registered via
    /// [`Self::with_override`] at construction time.
    pub fn definitions(&self, mode: crate::config::extended::LlmMode) -> Vec<ToolDefinition> {
        if let Some(cached) = self.definition_cache.lock().unwrap().get(&mode).cloned() {
            return cached;
        }
        let definitions: Vec<ToolDefinition> = self
            .tools
            .values()
            .filter(|t| !self.capability_unavailable.contains_key(t.name()))
            .map(|t| {
                let mut definition = definition_of(&**t, mode, self.overrides.get(t.name()));
                if let Some(suffixes) = self.capability_description_suffixes.get(t.name()) {
                    definition.description.push_str(&suffixes.join(""));
                }
                definition
            })
            .collect();
        self.definition_cache
            .lock()
            .unwrap()
            .insert(mode, definitions.clone());
        definitions
    }

    pub fn names(&self) -> Vec<&str> {
        self.tools
            .keys()
            .filter(|name| !self.capability_unavailable.contains_key(*name))
            .map(String::as_str)
            .collect()
    }

    // Registry-emptiness query; retained for the tool-registry API surface.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use crate::config::extended::LlmMode;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// The follow-up/seed capability is disabled only for defensive mode.
    #[test]
    fn followup_seed_is_enabled_outside_defensive_mode() {
        assert!(Capability::FollowupSeed.enabled(LlmMode::Normal));
        assert!(Capability::FollowupSeed.enabled(LlmMode::Frontier));
        assert!(!Capability::FollowupSeed.enabled(LlmMode::Defensive));
    }

    struct RequirementTool {
        name: &'static str,
        requirements: Vec<crate::capabilities::BinaryRequirement>,
    }

    #[async_trait]
    impl Tool for RequirementTool {
        fn name(&self) -> &str {
            self.name
        }

        fn description(&self) -> &str {
            "require external binary"
        }

        fn binary_requirements(&self) -> Vec<crate::capabilities::BinaryRequirement> {
            self.requirements.clone()
        }

        fn parameters(&self) -> Value {
            serde_json::json!({"type": "object", "properties": {}})
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text("ok"))
        }
    }

    struct ToolTestProbe {
        present: BTreeSet<String>,
        calls: AtomicUsize,
    }

    impl ToolTestProbe {
        fn new(present: &[&str]) -> Self {
            Self {
                present: present.iter().map(|name| (*name).to_string()).collect(),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl crate::capabilities::BinaryProbe for ToolTestProbe {
        fn resolve(
            &self,
            name: &str,
            _path: Option<&str>,
            _cwd: &Path,
            _budget: Duration,
        ) -> crate::capabilities::BinaryProbeStatus {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.present.contains(name) {
                crate::capabilities::BinaryProbeStatus::Present(PathBuf::from(format!(
                    "/bin/{name}"
                )))
            } else {
                crate::capabilities::BinaryProbeStatus::Missing
            }
        }
    }

    #[test]
    fn capability_tool_trait_defaults_empty_and_declared_requirement_round_trips() {
        struct NoRequirementTool;
        #[async_trait]
        impl Tool for NoRequirementTool {
            fn name(&self) -> &str {
                "none"
            }
            fn description(&self) -> &str {
                "none"
            }
            fn parameters(&self) -> Value {
                serde_json::json!({"type": "object", "properties": {}})
            }
            async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text("ok"))
            }
        }

        assert!(NoRequirementTool.binary_requirements().is_empty());

        let tool = RequirementTool {
            name: "declared",
            requirements: vec![crate::capabilities::BinaryRequirement::required(
                "demo-bin",
                crate::capabilities::CapabilityRemedy::prose("Install demo-bin."),
            )],
        };
        let requirements = tool.binary_requirements();
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].name, "demo-bin");
        assert_eq!(
            requirements[0].kind,
            crate::capabilities::BinaryRequirementKind::Required
        );
    }

    #[test]
    fn capability_required_binary_controls_callable_set_and_notice_dedupes() {
        let probe = std::sync::Arc::new(ToolTestProbe::new(&["present-bin"]));
        let cache = crate::capabilities::CapabilityProbeCache::new(probe, Duration::from_millis(1));
        let mut toolbox = ToolBox::new()
            .with(std::sync::Arc::new(RequirementTool {
                name: "present_tool",
                requirements: vec![crate::capabilities::BinaryRequirement::required(
                    "present-bin",
                    crate::capabilities::common_remedy("present-bin"),
                )],
            }))
            .with(std::sync::Arc::new(RequirementTool {
                name: "missing_a",
                requirements: vec![crate::capabilities::BinaryRequirement::required(
                    "missing-bin",
                    crate::capabilities::common_remedy("missing-bin"),
                )],
            }))
            .with(std::sync::Arc::new(RequirementTool {
                name: "missing_b",
                requirements: vec![crate::capabilities::BinaryRequirement::required(
                    "missing-bin",
                    crate::capabilities::common_remedy("missing-bin"),
                )],
            }));

        toolbox.apply_capabilities_with_cache(
            &std::collections::HashMap::from([("PATH".to_string(), "/bin".to_string())]),
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );

        assert!(toolbox.get("present_tool").is_some());
        assert!(toolbox.get("missing_a").is_none());
        assert!(toolbox.get("missing_b").is_none());
        let definitions = toolbox.definitions(LlmMode::Normal);
        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].name, "present_tool");
        let notice = toolbox.capability_notice_text().unwrap();
        assert_eq!(notice.matches("`missing-bin` missing").count(), 1);
    }

    #[test]
    fn capability_notice_ignores_missing_binary_for_ungranted_tool() {
        let probe = std::sync::Arc::new(ToolTestProbe::new(&[]));
        let cache =
            crate::capabilities::CapabilityProbeCache::new(probe.clone(), Duration::from_millis(1));
        let mut toolbox = ToolBox::new().with(std::sync::Arc::new(RequirementTool {
            name: "granted_tool",
            requirements: Vec::new(),
        }));

        toolbox.apply_capabilities_with_cache(
            &std::collections::HashMap::new(),
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );

        assert!(toolbox.capability_notice_text().is_none());
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            0,
            "only granted toolbox tools are probed"
        );
    }

    #[test]
    fn capability_optional_binary_keeps_tool_callable_and_updates_description() {
        let cache = crate::capabilities::CapabilityProbeCache::new(
            std::sync::Arc::new(ToolTestProbe::new(&[])),
            Duration::from_millis(1),
        );
        let mut toolbox = ToolBox::new().with(std::sync::Arc::new(RequirementTool {
            name: "optional_tool",
            requirements: vec![crate::capabilities::BinaryRequirement::optional(
                "optional-bin",
                crate::capabilities::CapabilityRemedy::prose("Install optional-bin."),
            )],
        }));

        toolbox.apply_capabilities_with_cache(
            &std::collections::HashMap::new(),
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );

        assert!(toolbox.get("optional_tool").is_some());
        let definitions = toolbox.definitions(LlmMode::Normal);
        assert_eq!(definitions.len(), 1);
        assert!(
            definitions[0]
                .description
                .contains("Optional `optional-bin` missing")
        );
    }

    #[test]
    fn capability_toolbox_rebuild_cache_is_keyed_by_path() {
        let probe = std::sync::Arc::new(ToolTestProbe::new(&[]));
        let cache =
            crate::capabilities::CapabilityProbeCache::new(probe.clone(), Duration::from_millis(1));
        let mut toolbox = ToolBox::new().with(std::sync::Arc::new(RequirementTool {
            name: "missing_tool",
            requirements: vec![crate::capabilities::BinaryRequirement::required(
                "missing-bin",
                crate::capabilities::common_remedy("missing-bin"),
            )],
        }));
        let env_a = std::collections::HashMap::from([("PATH".to_string(), "/a".to_string())]);
        let env_b = std::collections::HashMap::from([("PATH".to_string(), "/b".to_string())]);

        toolbox.apply_capabilities_with_cache(
            &env_a,
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );
        toolbox.apply_capabilities_with_cache(
            &env_a,
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        toolbox.apply_capabilities_with_cache(
            &env_b,
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    }
}

#[cfg(test)]
mod definition_cache_tests {
    use super::*;
    use crate::config::extended::LlmMode;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingTool {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Tool for CountingTool {
        fn name(&self) -> &str {
            "counting"
        }

        fn description(&self) -> &str {
            "count calls"
        }

        fn parameters(&self) -> Value {
            self.calls.fetch_add(1, Ordering::SeqCst);
            json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text("ok"))
        }
    }

    #[test]
    fn definitions_build_schema_once_per_mode() {
        let calls = Arc::new(AtomicUsize::new(0));
        let toolbox = ToolBox::new().with(Arc::new(CountingTool {
            calls: calls.clone(),
        }));

        let first = toolbox.definitions(LlmMode::Normal);
        let second = toolbox.definitions(LlmMode::Normal);
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let _ = toolbox.definitions(LlmMode::Frontier);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

#[cfg(test)]
mod sandbox_meta_tests {
    use super::*;

    /// §6.5 separation of channels: on the refuse path `bash` attaches the
    /// diagnosed remedy ONLY out-of-band on `SandboxMeta.unavailable_reason`.
    /// The model-facing `ToolOutput.content` (what enters history / the
    /// outbound prompt) is the addressed-to-the-model error and is the only
    /// thing the model ever sees — `with_sandbox` does not splice the meta into
    /// `content`. This is what keeps the user-facing surfacing out of the LLM
    /// context: the remedy rides the meta → engine event → broadcast bus only.
    #[test]
    fn unavailable_reason_rides_meta_not_model_content() {
        let reason = "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); \
             `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` re-enables confinement";
        let model_facing = "Error: the shell sandbox cannot start here (some reason); `bash` will \
             fail for the rest of the session until the user types `/sandbox off`";
        let meta = SandboxMeta {
            enabled: true,
            confined: false,
            escalated: false,
            escalation_preauthorized: false,
            approval_scope_recorded: None,
            unavailable_reason: Some(reason.to_string()),
            resource_profiles: Vec::new(),
        };
        let out = ToolOutput::text(model_facing).with_sandbox(meta);
        // The remedy lives on the meta…
        assert_eq!(
            out.sandbox.as_ref().unwrap().unavailable_reason.as_deref(),
            Some(reason)
        );
        // …and never in the model-facing body. The sysctl command in
        // particular must not leak into what the model sees.
        assert!(!out.content.contains("sudo sysctl"));
        assert!(!out.content.contains(reason));
    }

    /// The export sub-object omits `unavailable_reason` on every non-refuse
    /// path (token economy — the events.json `sandbox` key stays minimal).
    #[test]
    fn unavailable_reason_omitted_when_none() {
        let meta = SandboxMeta {
            enabled: true,
            confined: true,
            escalated: false,
            escalation_preauthorized: false,
            approval_scope_recorded: None,
            unavailable_reason: None,
            resource_profiles: Vec::new(),
        };
        let v = serde_json::to_value(&meta).unwrap();
        assert!(v.get("unavailable_reason").is_none());
    }

    #[test]
    fn resource_profiles_serialize_only_when_present() {
        let meta = SandboxMeta {
            enabled: true,
            confined: true,
            escalated: false,
            escalation_preauthorized: false,
            approval_scope_recorded: None,
            unavailable_reason: None,
            resource_profiles: vec![SandboxResourceProfileMeta {
                profile: "rust_toolchain".to_string(),
                definition_source: Some("builtin".to_string()),
                matched_commands: vec!["cargo test".to_string()],
                configured_wrappers: vec!["just test".to_string()],
                introspection: vec![SandboxResourceIntrospectionMeta {
                    tool: "go".to_string(),
                    command: "go env GOMODCACHE GOCACHE".to_string(),
                    status: "used".to_string(),
                    detail: None,
                }],
                roots: vec![SandboxResourceRootMeta {
                    kind: "cargo_home".to_string(),
                    path: "/home/me/.cargo".to_string(),
                    access: "read_write".to_string(),
                    source: Some("session_env".to_string()),
                    reason: None,
                    contributing_profiles: vec!["rust_toolchain".to_string()],
                }],
                denied_roots: Vec::new(),
            }],
        };

        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(v["resource_profiles"][0]["profile"], "rust_toolchain");
        assert_eq!(
            v["resource_profiles"][0]["matched_commands"][0],
            "cargo test"
        );
        assert_eq!(v["resource_profiles"][0]["roots"][0]["kind"], "cargo_home");
        assert_eq!(v["resource_profiles"][0]["definition_source"], "builtin");
        assert_eq!(
            v["resource_profiles"][0]["configured_wrappers"][0],
            "just test"
        );
        assert_eq!(
            v["resource_profiles"][0]["roots"][0]["source"],
            "session_env"
        );
        assert_eq!(
            v["resource_profiles"][0]["roots"][0]["contributing_profiles"][0],
            "rust_toolchain"
        );
        assert_eq!(
            v["resource_profiles"][0]["introspection"][0]["status"],
            "used"
        );
    }
}

#[cfg(test)]
mod llm_mode_tests {
    use super::*;
    use crate::config::extended::LlmMode;
    use crate::tools;

    fn all_builtin_tools() -> Vec<Arc<dyn Tool>> {
        crate::engine::builtin::invariant_builtin_tools()
    }

    fn tool_by_name(name: &str) -> Arc<dyn Tool> {
        all_builtin_tools()
            .into_iter()
            .find(|tool| tool.name() == name)
            .unwrap_or_else(|| panic!("built-in tool `{name}` missing from invariant registry"))
    }

    fn words(text: &str) -> std::collections::BTreeSet<String> {
        text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .filter(|word| !word.is_empty())
            .map(|word| word.to_ascii_lowercase())
            .collect()
    }

    fn has_description_steering_shape(normal: &str, defensive: &str) -> bool {
        let normal_words = words(normal);
        let defensive_words = words(defensive);
        let added_distinct_words = defensive_words.difference(&normal_words).count();
        let defensive_lower = defensive.to_ascii_lowercase();
        let when_to_use_markers = [
            "use ",
            "call ",
            "read ",
            "write ",
            "replace ",
            "search ",
            "find ",
            "get ",
            "show ",
            "list ",
            "send ",
            "create ",
            "update ",
            "run ",
            "schedule ",
            "ask ",
            "spawn ",
            "emit ",
            "request ",
            "return ",
            "surface ",
        ];
        let when_not_to_use_markers = [
            " do not ",
            " don't ",
            " not ",
            " never ",
            " instead",
            " rather than",
            " avoid",
            " prefer",
            " without",
            " only ",
            " cannot",
            " can't",
            " must not",
            " must ",
            " fails",
            " rejected",
            " requires",
            " required",
            " takes no arguments",
            " no arguments",
            " no filesystem",
            " no network",
            " no environment",
            " scope with",
            " confined",
            " budget",
            " capped",
            " bounded",
            " limit",
            " reserve",
            " path-confined",
            " preview",
            " omit",
        ];
        added_distinct_words >= 8
            && when_to_use_markers
                .iter()
                .any(|marker| defensive_lower.contains(marker))
            && when_not_to_use_markers
                .iter()
                .any(|marker| defensive_lower.contains(marker))
    }

    /// CONFLICT-AVOIDANCE INVARIANT (implementation note):
    /// for every built-in tool, in BOTH its terse and defensive schema, no
    /// `x-cockpit-aliases` entry may (a) shadow a canonical property name or
    /// (b) be double-claimed by two properties — within that same schema.
    /// Cross-tool collisions are harmless (resolution is per-tool-schema).
    /// Registry-driven, so a future tool that adds a shadowing/double-claimed
    /// alias trips here (and CI), not at runtime.
    #[test]
    fn no_tool_schema_has_a_shadowing_or_double_claimed_alias() {
        use crate::engine::repair::alias_invariants;
        for tool in all_builtin_tools() {
            let mut schemas = vec![tool.parameters()];
            if let Some(d) = tool.defensive_parameters() {
                schemas.push(d);
            }
            for schema in &schemas {
                let violations = alias_invariants(schema);
                assert!(
                    violations.is_empty(),
                    "tool `{}` schema has alias-invariant violations: {:?}",
                    tool.name(),
                    violations
                );
            }
        }
    }

    /// PRIMARY-FIELD INVARIANT (implementation note): for
    /// every built-in tool, in BOTH its terse and defensive schema, an
    /// `x-cockpit-primary-field` annotation (when present) must name a real
    /// property of that same schema — otherwise the root-string wrap would
    /// produce an object that can never validate. Registry-driven, so a future
    /// tool that annotates a nonexistent field trips here (and CI), not at
    /// runtime.
    #[test]
    fn primary_field_annotation_names_a_real_property() {
        use crate::engine::repair::PRIMARY_FIELD_KEY;
        for tool in all_builtin_tools() {
            let mut schemas = vec![tool.parameters()];
            if let Some(d) = tool.defensive_parameters() {
                schemas.push(d);
            }
            for schema in &schemas {
                let Some(field) = schema.get(PRIMARY_FIELD_KEY) else {
                    continue;
                };
                let field = field.as_str().unwrap_or_else(|| {
                    panic!(
                        "tool `{}` has a non-string `{PRIMARY_FIELD_KEY}`",
                        tool.name()
                    )
                });
                let props = schema.get("properties").and_then(|p| p.as_object());
                assert!(
                    props.is_some_and(|p| p.contains_key(field)),
                    "tool `{}` declares primary field `{field}` which is not a property of its schema",
                    tool.name()
                );
            }
        }
    }

    /// FULL-SURFACE COVERAGE: every built-in tool must supply a non-empty
    /// defensive description that is meaningfully more explicit than its
    /// terse one — no terse-fallback gaps, no TODO tools. Registry-driven,
    /// so a future built-in tool can't silently skip.
    #[test]
    fn every_builtin_tool_has_a_defensive_description() {
        for tool in all_builtin_tools() {
            if tool.name() == "escalate" {
                // `escalate` is removed from Defensive toolboxes by
                // Capability::SandboxEscalate, so a defensive variant is
                // unrenderable by construction. Keep this a named exemption so
                // other built-ins cannot silently lose Defensive coverage.
                continue;
            }
            let terse = tool.description().to_string();
            let defensive = tool.defensive_description().unwrap_or_else(|| {
                panic!(
                    "built-in tool `{}` has no defensive_description — full-surface coverage requires one",
                    tool.name()
                )
            });
            assert!(
                !defensive.trim().is_empty(),
                "tool `{}` has an empty defensive description",
                tool.name()
            );
            // Defensive is the *verbose* form: it must be longer than the
            // terse one, not byte-identical, and add real use/avoid steering
            // rather than padding.
            assert!(
                defensive.len() > terse.len(),
                "tool `{}` defensive description is not more explicit than terse ({} <= {})",
                tool.name(),
                defensive.len(),
                terse.len()
            );
            assert!(
                has_description_steering_shape(&terse, &defensive),
                "tool `{}` defensive description lacks structural use/avoid steering or meaningful new vocabulary: {defensive}",
                tool.name()
            );
        }
    }

    #[test]
    fn padded_description_without_steering_fails_structural_check() {
        let normal = "Read a file.";
        let padded = "Read a file. padding padding padding padding padding padding padding padding padding padding padding padding padding padding.";
        assert!(padded.len() >= 80);
        assert!(!has_description_steering_shape(normal, padded));
    }

    #[test]
    fn description_quality_rewrites_pin_load_bearing_clauses() {
        let writeunlock = tool_by_name("writeunlock")
            .description()
            .to_ascii_lowercase();
        assert!(writeunlock.contains("complete new contents"));
        assert!(writeunlock.contains("omitted lines are deleted"));
        assert!(writeunlock.contains("editunlock"));

        let impact = tool_by_name("impact").description().to_ascii_lowercase();
        let change_impact = tool_by_name("change_impact")
            .description()
            .to_ascii_lowercase();
        assert!(impact.contains("change_impact"));
        assert!(change_impact.contains("impact"));

        let context_pack = tool_by_name("context_pack")
            .description()
            .to_ascii_lowercase();
        assert!(context_pack.contains("first move"));
        assert!(context_pack.contains("never prints file contents"));
        assert!(context_pack.contains("read"));

        let goal = tool_by_name("goal").description().to_ascii_lowercase();
        assert!(goal.contains("goal"));
        assert!(goal.contains("control-plane"));
        assert!(goal.contains("driver"));

        let note = tool_by_name("note").description().to_ascii_lowercase();
        assert!(note.contains("live progress note"));
        assert!(!note.contains("now; it reaches"));

        let todo = tool_by_name("todo").description().to_ascii_lowercase();
        assert!(todo.contains("long-horizon"));
        assert!(todo.contains("task"));

        let names: std::collections::BTreeSet<_> = all_builtin_tools()
            .into_iter()
            .map(|tool| tool.name().to_string())
            .collect();
        assert!(names.contains("websearch"), "{names:?}");
        assert!(names.contains("webfetch"), "{names:?}");
        for name in ["websearch", "webfetch"] {
            let tool = tool_by_name(name);
            let normal = tool.description().to_string();
            let defensive = tool.defensive_description().unwrap();
            assert!(has_description_steering_shape(&normal, &defensive));
        }
    }

    #[test]
    fn sibling_disambiguation_normal_descriptions_name_siblings() {
        let cases: &[(&str, &[&str])] = &[
            ("search", &["grep", "word", "symbol_find"]),
            ("grep", &["search", "word", "symbol_find"]),
            ("word", &["search", "grep", "symbol_find"]),
            ("symbol_find", &["search", "grep", "word"]),
            ("outline", &["tree", "context_pack", "read"]),
            ("tree", &["outline", "context_pack"]),
            ("deps", &["impact", "change_impact"]),
            ("context_pack", &["read"]),
            ("impact", &["change_impact"]),
            ("change_impact", &["impact"]),
            ("read", &["readlock", "writeunlock", "editunlock"]),
            ("readlock", &["writeunlock", "editunlock", "unlock"]),
            ("writeunlock", &["readlock", "editunlock"]),
            ("editunlock", &["writeunlock", "unlock"]),
            ("unlock", &["readlock", "writeunlock", "editunlock"]),
            ("plan_read", &["plan_edit", "plan_write", "todo", "goal"]),
            ("plan_write", &["plan_edit", "todo", "goal"]),
            ("plan_edit", &["plan_read", "plan_write"]),
            ("todo", &["task"]),
            ("goal", &["todo"]),
        ];
        for (name, siblings) in cases {
            let description = tool_by_name(name).description().to_ascii_lowercase();
            for sibling in *siblings {
                assert!(
                    description.contains(sibling),
                    "`{name}` normal description must name sibling `{sibling}`; got: {description}"
                );
            }
        }
    }

    /// Defensive parameters, when supplied, keep the SAME shape + required
    /// set as the terse parameters — tool grants never vary by mode, only
    /// how descriptions render. We compare the structural skeleton
    /// (property names + `required` + `enum`s), ignoring `description`.
    #[test]
    fn defensive_parameters_preserve_shape() {
        for tool in all_builtin_tools() {
            let Some(defensive) = tool.defensive_parameters() else {
                continue;
            };
            let terse = tool.parameters();
            assert_eq!(
                skeleton(&terse),
                skeleton(&defensive),
                "tool `{}` defensive parameters changed the schema shape",
                tool.name()
            );
        }
    }

    /// Strip every `description` field from a JSON schema, leaving the
    /// structural skeleton (types, property names, `required`, `enum`s).
    fn skeleton(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, val) in map {
                    if k == "description" {
                        continue;
                    }
                    out.insert(k.clone(), skeleton(val));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(skeleton).collect())
            }
            other => other.clone(),
        }
    }

    /// The centralized rendering seam: in `Normal` and `Frontier` the
    /// definition carries the terse description; in `Defensive` it carries
    /// the verbose one. The switch lives in `definition_of` and nowhere else.
    #[test]
    fn definition_of_switches_description_on_mode() {
        let tool = tools::read::ReadTool;
        let normal = definition_of(&tool, LlmMode::Normal, None);
        let frontier = definition_of(&tool, LlmMode::Frontier, None);
        let defensive = definition_of(&tool, LlmMode::Defensive, None);
        assert_eq!(normal.description, tool.description());
        assert_eq!(frontier.description, tool.description());
        assert_eq!(defensive.description, tool.defensive_description().unwrap());
        assert_ne!(normal.description, defensive.description);
        assert_ne!(frontier.description, defensive.description);
    }

    /// DEFENSIVE-ROUTING STEER (`defensive-tool-descriptions-weak-
    /// model-routing.md`): the six search/navigation intel tools each render a
    /// verbose, bash-redirecting defensive description in `Defensive` (never
    /// the terse fallback), and the terse `description()` in `Normal`. Anchored
    /// on a distinctive phrase from each tool's spec'd prose so a regression
    /// that drops back to the terse one-liner fails here.
    #[test]
    fn definition_of_intel_tools_steer_in_defensive_mode() {
        // (tool, distinctive defensive-only substring from its spec'd prose).
        let cases: Vec<(Arc<dyn Tool>, &str)> = vec![
            (Arc::new(tools::intel::TreeTool), "Prefer it early"),
            (
                Arc::new(tools::intel::SearchTool),
                "When you would reach for `rg`/`grep`",
            ),
            (
                Arc::new(tools::intel::SymbolFindTool),
                "is DEFINED — function",
            ),
            (Arc::new(tools::intel::WordTool), "identifier TOKEN"),
            (Arc::new(tools::intel::OutlineTool), "structural outline"),
            (Arc::new(tools::intel::DepsTool), "files that depend on it"),
        ];
        for (tool, needle) in cases {
            let normal = definition_of(&*tool, LlmMode::Normal, None);
            let defensive = definition_of(&*tool, LlmMode::Defensive, None);
            // Normal renders the terse one-liner.
            assert_eq!(
                normal.description,
                tool.description(),
                "tool `{}` normal-mode must be the terse description",
                tool.name()
            );
            // Defensive renders the tool's own (verbose) defensive form, not
            // the terse fallback, and carries the spec'd steering phrase.
            assert_eq!(
                defensive.description,
                tool.defensive_description().unwrap(),
                "tool `{}` defensive-mode must be the defensive description",
                tool.name()
            );
            assert_ne!(
                defensive.description,
                normal.description,
                "tool `{}` defensive must differ from terse",
                tool.name()
            );
            assert!(
                defensive.description.contains(needle),
                "tool `{}` defensive text missing steer `{needle}`: {}",
                tool.name(),
                defensive.description
            );
        }
    }

    /// The shared `bash` search-hint no longer implies searches should happen
    /// in bash: it is a pure `grep`/`find` → `rg`/`fd` substitution, with no
    /// `for searches` tail, in BOTH the terse and defensive descriptions.
    #[test]
    fn bash_search_hint_drops_for_searches_in_both_modes() {
        let tool = tools::bash::BashTool::new();
        let normal = definition_of(&tool, LlmMode::Normal, None);
        let defensive = definition_of(&tool, LlmMode::Defensive, None);
        assert!(
            !normal.description.contains("for searches"),
            "terse bash description still says `for searches`: {}",
            normal.description
        );
        assert!(
            !defensive.description.contains("for searches"),
            "defensive bash description still says `for searches`: {}",
            defensive.description
        );
    }

    /// A tool with no defensive override falls back to the terse form in every
    /// mode (the `None`-keeper path — custom-bash tools rely on this).
    #[test]
    fn definition_of_falls_back_when_no_defensive_variant() {
        struct Terse;
        #[async_trait]
        impl Tool for Terse {
            fn name(&self) -> &str {
                "terse"
            }
            fn description(&self) -> &str {
                "terse one-liner"
            }
            fn parameters(&self) -> Value {
                serde_json::json!({"type": "object", "properties": {}})
            }
            async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text(""))
            }
        }
        let t = Terse;
        assert_eq!(
            definition_of(&t, LlmMode::Normal, None).description,
            definition_of(&t, LlmMode::Defensive, None).description,
            "a tool with no defensive variant renders identically in defensive and normal"
        );
        assert_eq!(
            definition_of(&t, LlmMode::Normal, None).description,
            definition_of(&t, LlmMode::Frontier, None).description,
            "a tool with no defensive variant renders identically in normal and frontier"
        );
    }

    /// TERSE-MODE BUDGET GUARD: rendered in `Normal` and `Frontier`, every
    /// built-in tool's description stays terse (the token-economy budget the
    /// CI check enforces). Defensive growth is the intended tradeoff and is
    /// exempt. One sentence ≈ under ~200 chars is the terse bar; `bash` gets
    /// a larger budget because it is high-frequency and must steer models
    /// away from routing around the dedicated file/search tools.
    #[test]
    fn terse_mode_descriptions_stay_within_budget() {
        for tool in all_builtin_tools() {
            for mode in [LlmMode::Normal, LlmMode::Frontier] {
                let def = definition_of(&*tool, mode, None);
                let budget = match tool.name() {
                    "bash" => 400,
                    "schedule" => 280,
                    "writeunlock" => 240,
                    _ => 200,
                };
                assert!(
                    def.description.len() <= budget,
                    "tool `{}` {mode:?} description exceeds the terse budget ({} chars): {}",
                    tool.name(),
                    def.description.len(),
                    def.description
                );
            }
        }
    }

    /// PER-AGENT AXIS: an override replaces the rendered description text for
    /// the active mode while leaving the SCHEMA untouched, and composes with
    /// the per-mode axis (each mode can carry its own override text). A mode
    /// with no override text falls back to the tool's own per-mode form.
    #[test]
    fn definition_of_applies_per_agent_override_and_composes_with_mode() {
        let tool = tools::read::ReadTool;
        let ov = ToolDescOverride {
            normal: Some("agent-specific terse intent".to_string()),
            frontier: Some("agent-specific frontier intent".to_string()),
            defensive: Some("agent-specific explicit steering intent".to_string()),
        };
        let normal = definition_of(&tool, LlmMode::Normal, Some(&ov));
        let frontier = definition_of(&tool, LlmMode::Frontier, Some(&ov));
        let defensive = definition_of(&tool, LlmMode::Defensive, Some(&ov));
        // Per-agent text wins over the tool's own description in each mode.
        assert_eq!(normal.description, "agent-specific terse intent");
        assert_eq!(frontier.description, "agent-specific frontier intent");
        assert_eq!(
            defensive.description,
            "agent-specific explicit steering intent"
        );
        // Per-mode strings still select different text.
        assert_ne!(normal.description, defensive.description);
        // SCHEMA is identical to the no-override form — only the description
        // changed. The tool's own (mode-specific) parameters are untouched.
        assert_eq!(
            normal.parameters,
            definition_of(&tool, LlmMode::Normal, None).parameters
        );
        assert_eq!(
            defensive.parameters,
            definition_of(&tool, LlmMode::Defensive, None).parameters
        );
    }

    /// A partial override (text for only one mode) leaves the other mode on
    /// the tool's own base description — the fallback contract.
    #[test]
    fn definition_of_partial_override_falls_back_per_mode() {
        let tool = tools::read::ReadTool;
        let ov = ToolDescOverride {
            normal: Some("only normal is overridden".to_string()),
            frontier: None,
            defensive: None,
        };
        assert_eq!(
            definition_of(&tool, LlmMode::Normal, Some(&ov)).description,
            "only normal is overridden"
        );
        // Defensive falls through to the tool's own defensive description.
        assert_eq!(
            definition_of(&tool, LlmMode::Defensive, Some(&ov)).description,
            tool.defensive_description().unwrap()
        );
    }

    #[test]
    fn override_cannot_silently_clobber_defensive_description() {
        struct FakeTool;

        #[async_trait]
        impl Tool for FakeTool {
            fn name(&self) -> &str {
                "fake"
            }

            fn description(&self) -> &str {
                "fake terse"
            }

            fn defensive_description(&self) -> Option<String> {
                Some("fake defensive".to_string())
            }

            fn parameters(&self) -> Value {
                serde_json::json!({"type": "object", "properties": {}})
            }

            async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text(""))
            }
        }

        let tool = FakeTool;
        let ov = ToolDescOverride {
            normal: Some("normal override only".to_string()),
            frontier: None,
            defensive: None,
        };

        assert_eq!(
            definition_of(&tool, LlmMode::Normal, Some(&ov)).description,
            "normal override only"
        );
        assert_eq!(
            definition_of(&tool, LlmMode::Frontier, Some(&ov)).description,
            tool.description()
        );
        assert_eq!(
            definition_of(&tool, LlmMode::Defensive, Some(&ov)).description,
            tool.defensive_description().unwrap()
        );
    }

    /// SAME ID + SAME SCHEMA, DIFFERENT DESCRIPTION: two toolboxes holding the
    /// same tool but different per-agent overrides advertise the same tool ID
    /// and identical parameters, with different description text encoding
    /// different intent.
    #[test]
    fn two_agents_same_tool_differ_only_in_description() {
        let build_box = ToolBox::new()
            .with(Arc::new(tools::read::ReadTool))
            .with_override(
                "read",
                ToolDescOverride {
                    normal: Some("Build: skim before delegating".to_string()),
                    frontier: None,
                    defensive: None,
                },
            );
        let builder_box = ToolBox::new()
            .with(Arc::new(tools::read::ReadTool))
            .with_override(
                "read",
                ToolDescOverride {
                    normal: Some("builder: read the file you will edit yourself".to_string()),
                    frontier: None,
                    defensive: None,
                },
            );
        let a = &build_box.definitions(LlmMode::Normal)[0];
        let b = &builder_box.definitions(LlmMode::Normal)[0];
        // Same ID.
        assert_eq!(a.name, "read");
        assert_eq!(a.name, b.name);
        // Same SCHEMA.
        assert_eq!(a.parameters, b.parameters);
        // Different description text.
        assert_ne!(a.description, b.description);
    }

    /// CACHE-SAFETY: the serialized tools array is byte-stable across repeated
    /// renders for a given `(agent, mode)`. An empty override is dropped, so a
    /// box with a no-op override serializes identically to one without any.
    #[test]
    fn toolbox_definitions_are_byte_stable_with_overrides() {
        let tb = ToolBox::new()
            .with(Arc::new(tools::read::ReadTool))
            .with(Arc::new(tools::bash::BashTool::new()))
            .with_override(
                "read",
                ToolDescOverride {
                    normal: Some("agent intent".to_string()),
                    frontier: None,
                    defensive: Some("agent intent, explicit".to_string()),
                },
            );
        let first = serde_json::to_string(&tb.definitions(LlmMode::Normal)).unwrap();
        let second = serde_json::to_string(&tb.definitions(LlmMode::Normal)).unwrap();
        assert_eq!(first, second, "tools array must be byte-stable per render");

        // An all-`None` override is a no-op: the box serializes identically to
        // one that never registered it.
        let no_override = ToolBox::new()
            .with(Arc::new(tools::read::ReadTool))
            .with(Arc::new(tools::bash::BashTool::new()));
        let empty_override = no_override.clone().with_override(
            "read",
            ToolDescOverride {
                normal: None,
                frontier: None,
                defensive: None,
            },
        );
        assert_eq!(
            serde_json::to_string(&no_override.definitions(LlmMode::Normal)).unwrap(),
            serde_json::to_string(&empty_override.definitions(LlmMode::Normal)).unwrap(),
            "an empty override must not change the serialized tools array"
        );
    }

    #[test]
    fn btw_tool_effect_metadata_complete() {
        let expected = [
            ("bash", ToolEffect::Dynamic),
            ("add-package", ToolEffect::Dynamic),
            ("change_impact", ToolEffect::ReadOnly),
            ("circular", ToolEffect::ReadOnly),
            ("context_pack", ToolEffect::Dynamic),
            ("defer_to_orchestrator", ToolEffect::Dynamic),
            ("delegation_payload_retrieve", ToolEffect::Dynamic),
            ("deps", ToolEffect::Dynamic),
            ("editunlock", ToolEffect::Dynamic),
            ("escalate", ToolEffect::Dynamic),
            ("goal", ToolEffect::Dynamic),
            ("glob", ToolEffect::ReadOnly),
            ("grep", ToolEffect::ReadOnly),
            ("handoff", ToolEffect::Dynamic),
            ("harness_invoke", ToolEffect::Dynamic),
            ("harness_list", ToolEffect::Dynamic),
            ("hot", ToolEffect::ReadOnly),
            ("impact", ToolEffect::ReadOnly),
            ("list-packages", ToolEffect::Dynamic),
            ("lsp", ToolEffect::ReadOnly),
            ("mcp", ToolEffect::Dynamic),
            ("note", ToolEffect::Dynamic),
            ("outline", ToolEffect::Dynamic),
            ("plan_edit", ToolEffect::Dynamic),
            ("plan_read", ToolEffect::Dynamic),
            ("plan_write", ToolEffect::Dynamic),
            ("question", ToolEffect::Dynamic),
            ("read", ToolEffect::ReadOnly),
            ("readlock", ToolEffect::Dynamic),
            ("return", ToolEffect::Dynamic),
            ("schedule", ToolEffect::Dynamic),
            ("search", ToolEffect::Dynamic),
            ("seed", ToolEffect::Dynamic),
            ("session_read", ToolEffect::ReadOnly),
            ("session_search", ToolEffect::ReadOnly),
            ("skill", ToolEffect::Dynamic),
            ("skill_manage", ToolEffect::Dynamic),
            ("spawn", ToolEffect::Dynamic),
            ("start_build", ToolEffect::Dynamic),
            ("symbol_find", ToolEffect::Dynamic),
            ("task", ToolEffect::Dynamic),
            ("todo", ToolEffect::Dynamic),
            ("tool_result_retrieve", ToolEffect::Dynamic),
            ("tree", ToolEffect::Dynamic),
            ("unlock", ToolEffect::Dynamic),
            ("webfetch", ToolEffect::Dynamic),
            ("websearch", ToolEffect::Dynamic),
            ("word", ToolEffect::ReadOnly),
            ("writeunlock", ToolEffect::Dynamic),
        ];
        let expected: BTreeMap<String, _> = expected
            .into_iter()
            .map(|(name, effect)| (name.to_string(), effect))
            .collect();
        let actual: BTreeMap<_, _> = crate::engine::builtin::invariant_builtin_tools()
            .into_iter()
            .map(|tool| (tool.name().to_string(), tool.effect()))
            .collect();

        assert_eq!(actual, expected);

        struct Unknown;
        #[async_trait]
        impl Tool for Unknown {
            fn name(&self) -> &str {
                "unknown"
            }

            fn description(&self) -> &str {
                "unknown dynamic tool"
            }

            fn parameters(&self) -> serde_json::Value {
                serde_json::Value::Null
            }

            async fn call(&self, _args: serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text("ok"))
            }
        }

        assert_eq!(Unknown.effect(), ToolEffect::Dynamic);
    }

    #[test]
    fn presentation_seam_has_a_default() {
        struct DefaultPresentationTool;
        #[async_trait]
        impl Tool for DefaultPresentationTool {
            fn name(&self) -> &str {
                "plain"
            }

            fn description(&self) -> &str {
                "plain test tool"
            }

            fn parameters(&self) -> serde_json::Value {
                serde_json::Value::Null
            }

            async fn call(&self, _args: serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text("ok"))
            }
        }

        struct CustomPresentationTool;
        #[async_trait]
        impl Tool for CustomPresentationTool {
            fn name(&self) -> &str {
                "custom"
            }

            fn description(&self) -> &str {
                "custom test tool"
            }

            fn parameters(&self) -> serde_json::Value {
                serde_json::Value::Null
            }

            fn presentation(&self, args: &serde_json::Value) -> ToolPresentation {
                let (summary, full_input) = readable_args(args);
                ToolPresentation::with_parts(Some("★"), "custom_label", summary, full_input)
            }

            async fn call(&self, _args: serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text("ok"))
            }
        }

        let args = serde_json::json!({ "path": "src/lib.rs" });
        let default = DefaultPresentationTool.presentation(&args);
        assert_eq!(default.glyph, None);
        assert_eq!(default.label, "plain");
        assert_eq!(default.summary, "path=\"src/lib.rs\"");

        let custom = CustomPresentationTool.presentation(&args);
        assert_eq!(custom.glyph, Some("★"));
        assert_eq!(custom.label, "custom_label");
        assert_eq!(custom.summary, "path=\"src/lib.rs\"");
    }
}
