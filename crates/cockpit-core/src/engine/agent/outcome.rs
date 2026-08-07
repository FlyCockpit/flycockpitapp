use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskContext {
    Fresh,
    Fork,
}

impl TaskContext {
    pub fn from_value(value: Option<&Value>) -> Self {
        match value.and_then(Value::as_str).map(str::trim) {
            Some("fork") => Self::Fork,
            _ => Self::Fresh,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Fork => "fork",
        }
    }
}

/// Outcome of one [`turn`] call. The driver loops on the result.
#[derive(Debug)]
pub enum TurnOutcome {
    /// Agent produced text and no tool calls — its turn is done.
    Done,
    /// Agent produced one or more tool calls; the loop must run another
    /// turn so the model can react to the results.
    Continue,
    /// Agent invoked `task` for an *interactive* subagent (e.g.
    /// `builder` from `Build`). The driver pushes a fresh
    /// session onto the stack and the subagent takes over the
    /// conversation until it produces final text.
    SpawnSubagent {
        child_agent: String,
        prompt: String,
        model: Option<crate::engine::model_roles::DelegationModelSelector>,
        remaining_depth: Option<u32>,
        /// Per-delegation tool grants (`task.grant_tools`, prompt
        /// `parent-granted-tools.md`): extra tools the parent attached to this
        /// one delegation. The driver validates them against the target's role
        /// invariants, then builds the child with base + grants for this run
        /// only. Empty when the parent granted nothing.
        granted_tools: Vec<String>,
        todo_ids: Vec<uuid::Uuid>,
        repair_notes: Vec<String>,
        /// Outstanding tool-call id the driver must answer when the
        /// subagent finishes. `ToolCall.id` is `String`; `ToolCall.call_id`
        /// is `Option<String>` because some providers don't surface a
        /// distinct id and rig's `tool_result_with_call_id` accepts the
        /// pair shape.
        task_call_id: String,
        task_function_call_id: Option<String>,
    },
    /// Agent invoked `task` for a *noninteractive* subagent (e.g.
    /// `explore` from `Build`). The driver runs the
    /// child's full conversation loop to completion synchronously
    /// and delivers its final text back as the parent's tool result —
    /// the user sees the spawn rendered like a single tool call,
    /// not a primary handoff.
    SpawnNoninteractive {
        child_agent: String,
        prompt: String,
        model: Option<crate::engine::model_roles::DelegationModelSelector>,
        remaining_depth: Option<u32>,
        /// The caller's motivation (`task.why`, GOALS §3c), threaded into the
        /// subagent's context so it can tailor what it surfaces/seeds. Empty
        /// when omitted.
        why: String,
        /// A follow-up against a prior read-only subagent (`task.resume_handle`,
        /// GOALS §3c): the driver rehydrates that subagent's transcript and
        /// re-runs it. `None` for a fresh spawn. Honored only in normal mode.
        resume_handle: Option<String>,
        /// Optional working directory for a noninteractive child. Parsed here
        /// and resolved/validated by the driver before spawn.
        cwd: Option<String>,
        /// Optional hard write-confined subtree for this child.
        write_scope: Option<String>,
        /// Whether the child starts with a fresh context or a forked copy of
        /// the delegating parent's transcript.
        context: TaskContext,
        /// Per-delegation tool grants (`task.grant_tools`, prompt
        /// `parent-granted-tools.md`): extra tools the parent attached to this
        /// one delegation. The driver validates them against the target's role
        /// invariants, then builds the child with base + grants for this run
        /// only. Empty when the parent granted nothing.
        granted_tools: Vec<String>,
        todo_ids: Vec<uuid::Uuid>,
        repair_notes: Vec<String>,
        task_call_id: String,
        task_function_call_id: Option<String>,
    },
    SpawnNoninteractiveBatch {
        entries: Vec<BatchTaskEntry>,
        why: String,
        repair_notes: Vec<String>,
        task_call_id: String,
        task_function_call_id: Option<String>,
    },
    TaskControl {
        action: TaskControlAction,
        target_task_call_id: Option<String>,
        label: Option<String>,
        message: Option<String>,
        task_call_id: String,
        task_function_call_id: Option<String>,
    },
    ToolResult {
        task_call_id: String,
        task_function_call_id: Option<String>,
        body: String,
    },
    /// Agent invoked `spawn` — the recursive `Swarm` fan-out
    /// (GOALS §24). Structural like `task`/`schedule`: intercepted by the engine
    /// and routed to the driver's single async-job authority, which enforces
    /// the depth ceiling + global concurrency cap, schedules the child
    /// `Swarm` subagent as a background job (queued when at capacity), and
    /// delivers an accepted/refused pointer back as this call's tool_result.
    /// Only a `Swarm` agent holds this tool — the sole exception to
    /// leaf-termination.
    Spawn {
        /// The child's self-contained brief.
        prompt: String,
        /// The dedicated write scope/DB the caller assigned the child so
        /// concurrent branches don't collide on a file. Empty when omitted.
        write_scope: String,
        model: Option<String>,
        task_call_id: String,
        task_function_call_id: Option<String>,
    },
    /// Agent invoked the `schedule` meta-tool (GOALS §22). Like `task`, this
    /// is intercepted by the engine and routed to the driver, which owns
    /// the single async-job authority. The driver dispatches the action,
    /// builds the tool result, and delivers it back as this call's
    /// tool_result — same shape as a noninteractive tool call.
    ScheduleAction {
        /// What the model emitted before outer `{action,args}` repair.
        original_args: Value,
        /// Repaired `{action, args}` payload.
        args: Value,
        recovery: Recovery,
        task_call_id: String,
        task_function_call_id: Option<String>,
    },
    /// A delegated subagent invoked the structural `return` tool to finish with
    /// a structured summary (implementation note).
    /// The model-authored fields are carried up so the driver assembles the
    /// envelope (model fields + host-derived `files_changed`) and injects it as
    /// this delegation's tool result. Held only by delegated subagents
    /// (`builder`/`explore` + custom); the `docs` pipeline is
    /// exempt and never holds it.
    Return {
        /// The repaired `return` argument object (model-authored fields). The
        /// driver builds [`crate::engine::envelope::Envelope`] from it and
        /// attaches the host-derived `files_changed` from the child's frame.
        fields: Value,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskControlAction {
    Models,
    List,
    Status,
    Cancel,
    Query,
    Steer,
}

#[derive(Debug, Clone)]
pub struct BatchTaskEntry {
    pub label: String,
    pub child_agent: String,
    pub prompt: String,
    pub model: Option<crate::engine::model_roles::DelegationModelSelector>,
    pub remaining_depth: Option<u32>,
    pub resume_handle: Option<String>,
    pub cwd: Option<String>,
    pub context: TaskContext,
    pub granted_tools: Vec<String>,
    pub todo_ids: Vec<uuid::Uuid>,
    pub write_scope: Option<String>,
}

/// Resolve whether a `task` delegation runs **noninteractively** (synchronous
/// leaf, result reported up) or as an **interactive** primary handoff.
///
/// A follow-up (`has_resume_handle`) is ALWAYS noninteractive — a
/// question/instruction answered and reported back, not a resumed interactive
/// handoff (implementation note). So a `builder` re-query routes through the
/// noninteractive arm (which
/// re-acquires a write-capable subagent's locks hash-matched), never a fresh
/// conversation handoff — even though those agents are interactive when spawned
/// fresh. Absent a resume handle, an explicit `mode` override wins
/// (`subagent` → noninteractive, `subagent_interactive` → interactive — the
/// seam the future LLM-strategy axis switches on), then the agent's own default
/// ([`crate::engine::builtin::is_noninteractive`]).
pub(super) fn resolve_interactivity(
    mode: Option<&str>,
    child: &str,
    has_resume_handle: bool,
) -> bool {
    if has_resume_handle {
        return true;
    }
    match mode {
        Some("subagent_interactive") => false,
        Some("subagent") => true,
        _ => crate::engine::builtin::is_noninteractive(child),
    }
}

pub(super) fn task_string_array(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            let mut out = Vec::new();
            for v in a {
                if let Some(s) = v.as_str().map(str::trim)
                    && !s.is_empty()
                    && !out.iter().any(|x: &String| x == s)
                {
                    out.push(s.to_string());
                }
            }
            out
        })
        .unwrap_or_default()
}

pub(super) fn task_todo_ids(args: &Value) -> Vec<uuid::Uuid> {
    args.get("todo_ids")
        .and_then(Value::as_array)
        .map(|a| {
            let mut out = Vec::new();
            for v in a {
                if let Some(s) = v.as_str().map(str::trim)
                    && let Ok(id) = uuid::Uuid::parse_str(s)
                    && !out.contains(&id)
                {
                    out.push(id);
                }
            }
            out
        })
        .unwrap_or_default()
}

pub(super) fn task_remaining_depth(args: &Value) -> Result<Option<u32>, String> {
    let Some(value) = args.get("remaining_depth") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(raw) = value.as_u64() else {
        return Err("`remaining_depth` must be a nonnegative integer".to_string());
    };
    u32::try_from(raw)
        .map(Some)
        .map_err(|_| "`remaining_depth` is too large".to_string())
}

pub(super) fn task_refusal(
    id: &str,
    call_id: Option<String>,
    body: impl Into<String>,
) -> TurnOutcome {
    TurnOutcome::ToolResult {
        task_call_id: id.to_string(),
        task_function_call_id: call_id,
        body: format!("Error: {}", body.into()),
    }
}

#[cfg(test)]
mod handoff_outcome_removal_tests {
    /// The dead native handoff tool's structural outcome and helper must not
    /// reappear. Source-level so this fails first while the variant/helper
    /// remain, then passes after deletion. Banned tokens are assembled at
    /// runtime so this test body does not self-match via `include_str!`.
    #[test]
    fn turn_outcome_has_no_handoff_variant() {
        let src = include_str!("outcome.rs");
        // Strip this test module before scanning so assert messages cannot
        // self-match.
        let production = src
            .split("mod handoff_outcome_removal_tests")
            .next()
            .unwrap_or(src);
        let variant = format!("{} {{", "Handoff");
        let helper = format!("fn hand{}target", "off_");
        let path = format!("TurnOutcome::{}", "Handoff");
        assert!(
            !production.contains(&variant),
            "TurnOutcome must not declare a Handoff variant"
        );
        assert!(
            !production.contains(&helper),
            "handoff_target helper must be removed with the dead tool"
        );
        assert!(
            !production.contains(&path),
            "no TurnOutcome::Handoff references may remain in outcome production code"
        );
    }
}

#[cfg(test)]
mod interactivity_tests {
    use super::resolve_interactivity;

    /// A fresh delegation uses the agent's default: `builder` is
    /// the interactive handoff; everything else (`explore`, custom) is a
    /// noninteractive leaf.
    #[test]
    fn fresh_delegation_uses_agent_default() {
        assert!(!resolve_interactivity(None, "builder", false));
        assert!(resolve_interactivity(None, "explore", false));
        assert!(resolve_interactivity(None, "my-custom-subagent", false));
    }

    /// An explicit `mode` overrides the default for a fresh delegation.
    #[test]
    fn explicit_mode_overrides_for_fresh_delegation() {
        assert!(resolve_interactivity(Some("subagent"), "builder", false));
        assert!(!resolve_interactivity(
            Some("subagent_interactive"),
            "explore",
            false
        ));
    }

    /// A follow-up (`resume_handle` present) is ALWAYS noninteractive — even for
    /// an interactive-by-default `builder`, and even if `mode`
    /// asked for interactive — so a re-query routes through the noninteractive
    /// arm that re-acquires write-capable locks hash-matched
    /// (implementation note).
    #[test]
    fn followup_is_always_noninteractive() {
        assert!(resolve_interactivity(None, "builder", true));
        assert!(resolve_interactivity(None, "explore", true));
        // An interactive `mode` request cannot un-noninteractive a follow-up.
        assert!(resolve_interactivity(
            Some("subagent_interactive"),
            "builder",
            true
        ));
    }
}
