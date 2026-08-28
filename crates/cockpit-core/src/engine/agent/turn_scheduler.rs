//! Capability-aware turn scheduler (issue #57).
//!
//! Replaces phase-10's first-structural-return with a first-class turn
//! scheduler that never drops a parallel tool call. The scheduler builds a
//! source-order plan over every original call ID, classifies each call as
//! parallel-lane-eligible or a serial barrier at plan time, and dispatches
//! results in source order (never completion order).
//!
//! ## Parallel lane admission
//!
//! A parallel lane may contain only:
//! - Registered `ToolEffect::ReadOnly` ordinary tools.
//! - Noninteractive `task(intent=delegate)` calls whose final
//!   `ResolvedChildExecutionSurface.parallel_read_only_eligible` is true.
//!
//! Everything else (mutating, `Dynamic`, unknown, approval-gated, interactive
//! task, write-authority, `schedule`/`handoff`/`spawn`/`return`/`done`, task
//! control) is a serial barrier. A serial barrier waits for all earlier lane
//! members; later calls wait for that barrier.
//!
//! ## FIFO lane bounding
//!
//! Both an ordinary parallel lane and explicit `task(intent=batch)` use the
//! existing `delegation.max_parallel` limit (at least one). In an ordinary
//! lane, calls start FIFO in source order up to that limit; as a member
//! settles, the next queued eligible member starts. The lane drains before
//! the next serial barrier.

use serde::Serialize;
use serde_json::Value;

use crate::engine::tool::{ToolBox, ToolEffect};

/// Classification of a single tool call in the scheduler plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallClassification {
    /// May run in a parallel lane: a registered `ReadOnly` ordinary tool, or
    /// a noninteractive delegate whose `ResolvedChildExecutionSurface` proves
    /// `parallel_read_only_eligible`.
    ParallelLane { reason: ParallelLaneReason },
    /// A syntactically noninteractive delegate.  Its real child surface is
    /// deliberately unresolved here: the Driver resolves and pins it only
    /// when this source position is ready to start.
    DelegateCandidate,
    /// Must run serially, draining any in-flight lane first.
    SerialBarrier { reason: SerialBarrierReason },
}

impl CallClassification {
    pub fn is_parallel_lane(&self) -> bool {
        matches!(self, Self::ParallelLane { .. })
    }

    pub fn is_serial_barrier(&self) -> bool {
        matches!(self, Self::SerialBarrier { .. })
    }

    pub fn reason_str(&self) -> &'static str {
        match self {
            Self::ParallelLane { reason } => reason.as_str(),
            Self::DelegateCandidate => "delegate_attempt_resolution",
            Self::SerialBarrier { reason } => reason.as_str(),
        }
    }
}

/// Why a call was admitted to a parallel lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParallelLaneReason {
    /// A registered ordinary tool with `ToolEffect::ReadOnly`.
    ReadOnlyOrdinary,
}

impl ParallelLaneReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnlyOrdinary => "read_only_ordinary",
        }
    }
}

/// Why a call was classified as a serial barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SerialBarrierReason {
    MutatingTool,
    DynamicTool,
    UnknownTool,
    ApprovalGated,
    InteractiveDelegate,
    DelegateNotEligible,
    TaskControl,
    TaskBatch,
    Schedule,
    Spawn,
    Return,
    Done,
    StructuralControl,
}

impl SerialBarrierReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::MutatingTool => "mutating_tool",
            Self::DynamicTool => "dynamic_tool",
            Self::UnknownTool => "unknown_tool",
            Self::ApprovalGated => "approval_gated",
            Self::InteractiveDelegate => "interactive_delegate",
            Self::DelegateNotEligible => "delegate_not_eligible",
            Self::TaskControl => "task_control",
            Self::TaskBatch => "task_batch",
            Self::Schedule => "schedule",
            Self::Spawn => "spawn",
            Self::Return => "return",
            Self::Done => "done",
            Self::StructuralControl => "structural_control",
        }
    }
}

/// One entry in the scheduler plan, in source order.
#[derive(Debug, Clone)]
pub(crate) struct ScheduledCall {
    /// Source-order index (0-based) in the original tool-call list.
    pub source_index: usize,
    /// The call's wire ID.
    pub call_id: String,
    /// The resolved tool name (after name repair).
    pub resolved_name: String,
    /// The classification.
    pub classification: CallClassification,
}

impl ScheduledCall {
    pub fn is_parallel_lane(&self) -> bool {
        self.classification.is_parallel_lane()
    }

    pub fn is_serial_barrier(&self) -> bool {
        self.classification.is_serial_barrier()
    }

    pub fn is_delegate_candidate(&self) -> bool {
        matches!(self.classification, CallClassification::DelegateCandidate)
    }

    pub fn classification_str(&self) -> &'static str {
        if self.is_parallel_lane() {
            "parallel_lane"
        } else if self.is_delegate_candidate() {
            "deferred_delegate"
        } else {
            "serial_barrier"
        }
    }
}

/// The complete turn scheduler plan.
#[derive(Debug, Clone)]
pub(crate) struct TurnSchedulerPlan {
    pub calls: Vec<ScheduledCall>,
    /// The `delegation.max_parallel` limit used for FIFO lane bounding.
    pub max_parallel: usize,
}

impl TurnSchedulerPlan {
    /// Iterate calls in source order.
    pub fn iter(&self) -> impl Iterator<Item = &ScheduledCall> {
        self.calls.iter()
    }

    /// Serialize the plan to a JSON payload for the `tool_call_scheduling`
    /// session event. Contains only original call IDs, lane/barrier
    /// classification, and the max_parallel bound — never tool arguments,
    /// title candidates, or provider bodies.
    pub fn to_event_payload(&self) -> Value {
        serde_json::json!({
            "max_parallel": self.max_parallel,
            "calls": self.calls
                .iter()
                .map(|call| {
                    Value::Object({
                        let mut map = serde_json::Map::new();
                        map.insert("call_id".to_string(), Value::String(call.call_id.clone()));
                        map.insert(
                            "tool".to_string(),
                            Value::String(call.resolved_name.clone()),
                        );
                        let (lane, reason) = match &call.classification {
                            CallClassification::ParallelLane { reason } => {
                                ("parallel_lane", reason.as_str())
                            }
                            CallClassification::DelegateCandidate => {
                                ("deferred_delegate", "delegate_attempt_resolution")
                            }
                            CallClassification::SerialBarrier { reason } => {
                                ("serial_barrier", reason.as_str())
                            }
                        };
                        map.insert("lane".to_string(), Value::String(lane.to_string()));
                        map.insert("reason".to_string(), Value::String(reason.to_string()));
                        map
                    })
                })
                .collect::<Vec<_>>(),
        })
    }
}

pub(crate) const SCHEDULER_INTERRUPTED_BODY: &str =
    "Tool call interrupted before the turn scheduler could durably settle it.";

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum SchedulerTerminalOutcome {
    Completed,
    Refused,
    Transitioned,
    Cancelled,
}

impl SchedulerTerminalOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Refused => "refused",
            Self::Transitioned => "transitioned",
            Self::Cancelled => "cancelled",
        }
    }
}

pub(crate) fn terminal_event_payload(
    call: &ScheduledCall,
    outcome: SchedulerTerminalOutcome,
) -> Value {
    serde_json::json!({
        "call_id": call.call_id,
        "lane": if call.is_parallel_lane() {
            "parallel_lane"
        } else if call.is_delegate_candidate() {
            "deferred_delegate"
        } else {
            "serial_barrier"
        },
        "reason": call.classification.reason_str(),
        "terminal_outcome": outcome,
    })
}

/// Build the scheduler plan from a list of resolved tool calls.
///
/// `resolved_names` is parallel to `calls` — each entry is the name-repaired
/// tool name for the corresponding call. `active_tools` is the turn's toolbox.
/// `max_parallel` is `delegation.max_parallel.max(1)`.
///
/// Delegate calls are only syntax-classified here.  Real child resolution and
/// admission belong to the Driver at the attempt boundary.
pub(crate) fn build_plan(
    calls: &[crate::engine::message::ToolCall],
    resolved_names: &[String],
    active_tools: &ToolBox,
    max_parallel: usize,
) -> TurnSchedulerPlan {
    build_plan_with_delegate_context(calls, resolved_names, active_tools, max_parallel, false)
}

pub(crate) fn build_plan_with_delegate_context(
    calls: &[crate::engine::message::ToolCall],
    resolved_names: &[String],
    active_tools: &ToolBox,
    max_parallel: usize,
    force_noninteractive_delegates: bool,
) -> TurnSchedulerPlan {
    let scheduled = calls
        .iter()
        .enumerate()
        .map(|(idx, tc)| {
            let resolved_name = resolved_names
                .get(idx)
                .map(String::as_str)
                .unwrap_or(&tc.function.name);
            let classification = classify_call(
                tc,
                resolved_name,
                active_tools,
                force_noninteractive_delegates,
            );
            ScheduledCall {
                source_index: idx,
                call_id: tc.id.to_string(),
                resolved_name: resolved_name.to_string(),
                classification,
            }
        })
        .collect();
    TurnSchedulerPlan {
        calls: scheduled,
        max_parallel,
    }
}

/// Classify a single tool call as parallel-lane-eligible or a serial barrier.
fn classify_call(
    tc: &crate::engine::message::ToolCall,
    resolved_name: &str,
    active_tools: &ToolBox,
    force_noninteractive_delegates: bool,
) -> CallClassification {
    // Structural tools are always serial barriers unless they are a
    // noninteractive delegate that proves parallel_read_only_eligible.
    match resolved_name {
        "task" => classify_task_call(tc, active_tools, force_noninteractive_delegates),
        "schedule" => {
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Schedule,
            };
        }
        "spawn" => {
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Spawn,
            };
        }
        "return" => {
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Return,
            };
        }
        "done" => {
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Done,
            };
        }
        _ => {}
    }

    // Ordinary tool: classify by static ToolEffect.
    if let Some(tool) = active_tools.get(resolved_name) {
        // Parallel admission is a positive capability proof, not merely an
        // effect label. Custom tools can deliberately report `ReadOnly` while
        // still wrapping arbitrary shell commands; those stay unknown. Effect
        // is the primary serial reason so `tool_call_scheduling` can distinguish
        // mutating vs dynamic vs unknown. Approval is an independent overlay
        // that only applies to a tool that would otherwise join the lane.
        if !tool.is_registered_ordinary_operation() {
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::UnknownTool,
            };
        }
        match tool.effect() {
            ToolEffect::ReadOnly => {
                if crate::engine::tool::tool_requires_permission(tool.as_ref()) {
                    CallClassification::SerialBarrier {
                        reason: SerialBarrierReason::ApprovalGated,
                    }
                } else {
                    CallClassification::ParallelLane {
                        reason: ParallelLaneReason::ReadOnlyOrdinary,
                    }
                }
            }
            ToolEffect::Mutating => CallClassification::SerialBarrier {
                reason: SerialBarrierReason::MutatingTool,
            },
            ToolEffect::Dynamic => CallClassification::SerialBarrier {
                reason: SerialBarrierReason::DynamicTool,
            },
        }
    } else {
        // Unknown/unregistered tool: serial barrier (fail-closed).
        CallClassification::SerialBarrier {
            reason: SerialBarrierReason::UnknownTool,
        }
    }
}

/// Classify a `task` call by parsing its intent and, for delegates, probing
/// the child execution surface.
fn classify_task_call(
    tc: &crate::engine::message::ToolCall,
    _active_tools: &ToolBox,
    force_noninteractive_delegates: bool,
) -> CallClassification {
    let known_task_call_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let parsed = match crate::tools::task_repair::parse_task_args(
        &tc.function.arguments,
        &known_task_call_ids,
    ) {
        Ok(parsed) => parsed,
        Err(_) => {
            // Unparseable task args: serial barrier (the dispatch will surface
            // the parse error as a refusal).
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::StructuralControl,
            };
        }
    };

    match parsed {
        crate::tools::task_repair::ParsedTaskArgs::Control { .. } => {
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::TaskControl,
            }
        }
        crate::tools::task_repair::ParsedTaskArgs::Batch { .. } => {
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::TaskBatch,
            }
        }
        crate::tools::task_repair::ParsedTaskArgs::Delegate { args, .. } => {
            classify_delegate_call(&args, force_noninteractive_delegates)
        }
    }
}

/// Classify only the syntax-owned delegate barriers.  A remaining candidate
/// is resolved by the Driver from its live cwd/config/grants at attempt start.
fn classify_delegate_call(delegate_args: &Value, force_noninteractive: bool) -> CallClassification {
    let child_agent = delegate_args
        .get("agent")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    if child_agent.is_empty() {
        return CallClassification::SerialBarrier {
            reason: SerialBarrierReason::DelegateNotEligible,
        };
    }

    // `write_scope` is an authority request, not a syntax-owned barrier.
    // vNext carries it through the noninteractive path and the Driver binds
    // the live grant at attempt start (`phase_10` / mixed-lane pin). A
    // write-capable surface drains earlier lane members and runs exclusively
    // there; classifying it here would skip that attempt-time pin/rebind.

    // Determine interactivity from the parsed args. A resume_handle always
    // makes a delegate noninteractive. An explicit mode override wins;
    // otherwise the agent's default applies.
    let mode = delegate_args
        .get("mode")
        .and_then(Value::as_str)
        .map(str::trim);
    let has_resume_handle = delegate_args
        .get("resume_handle")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some();

    let interactive = if force_noninteractive || has_resume_handle {
        false // follow-up is always noninteractive
    } else {
        match mode {
            Some("subagent_interactive") => true,
            Some("subagent") => false,
            _ => !crate::engine::builtin::is_noninteractive(child_agent),
        }
    };

    if interactive {
        return CallClassification::SerialBarrier {
            reason: SerialBarrierReason::InteractiveDelegate,
        };
    }

    CallClassification::DelegateCandidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MutatingStub;

    #[async_trait::async_trait]
    impl crate::engine::tool::Tool for MutatingStub {
        fn name(&self) -> &str {
            "mutating_stub"
        }

        fn description(&self) -> &str {
            "registered ordinary mutating fixture"
        }

        fn effect(&self) -> ToolEffect {
            ToolEffect::Mutating
        }

        fn parameters(&self) -> Value {
            serde_json::json!({ "type": "object", "properties": {} })
        }

        async fn call(
            &self,
            _args: Value,
            _ctx: &crate::engine::tool::ToolCtx,
        ) -> anyhow::Result<crate::engine::tool::ToolOutput> {
            Ok(crate::engine::tool::ToolOutput::text("mutating"))
        }
    }

    fn tool_call(name: &str, args: Value) -> crate::engine::message::ToolCall {
        crate::engine::message::ToolCall {
            id: rig::message::ToolCallId::new_or_mint(name.to_string()),
            provider: None,
            function: rig::message::ToolFunction {
                name: name.to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        }
    }

    fn resolved_names(calls: &[crate::engine::message::ToolCall]) -> Vec<String> {
        calls.iter().map(|tc| tc.function.name.clone()).collect()
    }

    /// AC1: A read-only ordinary tool is classified as parallel-lane. A
    /// dynamic tool and an unknown tool are each classified as serial
    /// barriers. Source-order IDs are preserved.
    #[test]
    fn capability_aware_turn_scheduler_preserves_ids_and_serial_barriers() {
        let toolbox = ToolBox::new()
            .with(Arc::new(crate::tools::read::ReadTool))
            .with(Arc::new(crate::tools::bash::BashTool::new()))
            .with(Arc::new(crate::tools::glob::GlobTool))
            .with(Arc::new(crate::tools::grep::GrepTool))
            .with(Arc::new(MutatingStub));

        let calls = vec![
            tool_call("read", serde_json::json!({ "path": "a.txt" })),
            tool_call("glob", serde_json::json!({ "pattern": "*.rs" })),
            tool_call("mutating_stub", serde_json::json!({})),
            tool_call("bash", serde_json::json!({ "command": "ls" })),
            tool_call("unknown_tool", serde_json::json!({})),
        ];
        let names = resolved_names(&calls);
        let plan = build_plan(&calls, &names, &toolbox, 4);

        // Source order preserved: every original call ID is in the plan.
        assert_eq!(plan.calls.len(), 5);
        assert_eq!(plan.calls[0].call_id, "read");
        assert_eq!(plan.calls[1].call_id, "glob");
        assert_eq!(plan.calls[2].call_id, "mutating_stub");
        assert_eq!(plan.calls[3].call_id, "bash");
        assert_eq!(plan.calls[4].call_id, "unknown_tool");

        // read is ReadOnly → parallel lane.
        assert!(plan.calls[0].is_parallel_lane());
        assert_eq!(
            plan.calls[0].classification,
            CallClassification::ParallelLane {
                reason: ParallelLaneReason::ReadOnlyOrdinary,
            }
        );

        // glob is ReadOnly → parallel lane.
        assert!(plan.calls[1].is_parallel_lane());
        assert_eq!(
            plan.calls[1].classification,
            CallClassification::ParallelLane {
                reason: ParallelLaneReason::ReadOnlyOrdinary,
            }
        );

        // mutating_stub is Mutating → serial barrier with that reason, not
        // approval_gated. `tool_requires_permission` is !ReadOnly, so matching
        // it first would collapse this arm (and bash) into ApprovalGated.
        assert!(plan.calls[2].is_serial_barrier());
        assert_eq!(
            plan.calls[2].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::MutatingTool,
            }
        );

        // bash is Dynamic (default) → serial barrier.
        assert!(plan.calls[3].is_serial_barrier());
        assert_eq!(
            plan.calls[3].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::DynamicTool,
            }
        );

        // unknown_tool is not registered → serial barrier.
        assert!(plan.calls[4].is_serial_barrier());
        assert_eq!(
            plan.calls[4].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::UnknownTool,
            }
        );

        // Event payload contains only call IDs, lane, and reason — no args.
        let payload = plan.to_event_payload();
        let arr = payload["calls"].as_array().expect("calls is an array");
        assert_eq!(arr.len(), 5);
        assert_eq!(arr[0]["call_id"], "read");
        assert_eq!(arr[0]["lane"], "parallel_lane");
        assert_eq!(arr[2]["reason"], "mutating_tool");
        assert_eq!(arr[3]["reason"], "dynamic_tool");
        assert!(arr[0].get("arguments").is_none());
    }

    /// AC1: Structural tools are serial barriers.
    #[test]
    fn structural_tools_are_serial_barriers() {
        let toolbox = ToolBox::new();

        let calls = vec![
            tool_call("schedule", serde_json::json!({})),
            tool_call(
                "spawn",
                serde_json::json!({ "prompt": "x", "write_scope": "s" }),
            ),
            tool_call("return", serde_json::json!({ "summary": "done" })),
            tool_call("done", serde_json::json!({})),
        ];
        let names = resolved_names(&calls);
        let plan = build_plan(&calls, &names, &toolbox, 4);

        assert!(plan.calls.iter().all(ScheduledCall::is_serial_barrier));
        assert_eq!(
            plan.calls[0].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Schedule,
            }
        );
        assert_eq!(
            plan.calls[1].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Spawn,
            }
        );
        assert_eq!(
            plan.calls[2].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Return,
            }
        );
        assert_eq!(
            plan.calls[3].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Done,
            }
        );
    }

    /// AC1: Task control and task batch are serial barriers.
    #[test]
    fn task_control_and_batch_are_serial_barriers() {
        let toolbox = ToolBox::new();

        let calls = vec![
            tool_call(
                "task",
                serde_json::json!({ "intent": "control", "action": "list" }),
            ),
            tool_call(
                "task",
                serde_json::json!({
                    "intent": "batch",
                    "payload": [
                        { "agent": "explore", "prompt": "a" },
                        { "agent": "explore", "prompt": "b" }
                    ]
                }),
            ),
        ];
        let names = resolved_names(&calls);
        let plan = build_plan(&calls, &names, &toolbox, 4);

        assert!(plan.calls[0].is_serial_barrier());
        assert_eq!(
            plan.calls[0].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::TaskControl,
            }
        );
        assert!(plan.calls[1].is_serial_barrier());
        assert_eq!(
            plan.calls[1].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::TaskBatch,
            }
        );
    }

    /// AC1: An interactive delegate is a syntax-owned serial barrier. A
    /// write-scope request stays an attempt-resolved candidate so the Driver
    /// can pin the live grant after the preceding barrier.
    #[test]
    fn interactive_delegates_are_serial_barriers_and_write_scope_stays_a_candidate() {
        let toolbox = ToolBox::new();

        // Interactive delegate (builder is interactive by default).
        let calls = vec![
            tool_call(
                "task",
                serde_json::json!({ "intent": "delegate", "payload": { "agent": "builder", "prompt": "build it" } }),
            ),
            // Write-scope is an authority request, not a plan-time barrier.
            tool_call(
                "task",
                serde_json::json!({ "intent": "delegate", "payload": { "agent": "explore", "prompt": "look", "write_scope": "src/" } }),
            ),
        ];
        let names = resolved_names(&calls);
        let plan = build_plan(&calls, &names, &toolbox, 4);

        // builder is interactive → serial barrier.
        assert!(plan.calls[0].is_serial_barrier());
        assert_eq!(
            plan.calls[0].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::InteractiveDelegate,
            }
        );

        // explore with write_scope remains a candidate. The mixed lane binds
        // write_authority from the live surface at attempt start.
        assert!(plan.calls[1].is_delegate_candidate());
    }

    /// AC3 (plan-level): `plan_keeps_batch_and_distinct_delegates_separate` —
    /// the scheduler plan classifies explicit `intent=batch` as a serial
    /// barrier (TaskBatch) while separately emitted delegates are distinct
    /// plan entries (not coalesced).
    #[test]
    fn plan_keeps_batch_and_distinct_delegates_separate() {
        let toolbox = ToolBox::new();

        // An explicit batch followed by two distinct delegates.
        let calls = vec![
            tool_call(
                "task",
                serde_json::json!({
                    "intent": "batch",
                    "payload": [
                        { "agent": "explore", "prompt": "a" },
                        { "agent": "explore", "prompt": "b" }
                    ]
                }),
            ),
            tool_call(
                "task",
                serde_json::json!({ "intent": "delegate", "payload": { "agent": "explore", "prompt": "c" } }),
            ),
            tool_call(
                "task",
                serde_json::json!({ "intent": "delegate", "payload": { "agent": "explore", "prompt": "d" } }),
            ),
        ];
        let names = resolved_names(&calls);
        let plan = build_plan(&calls, &names, &toolbox, 4);

        // Batch is a serial barrier with TaskBatch reason.
        assert!(plan.calls[0].is_serial_barrier());
        assert_eq!(
            plan.calls[0].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::TaskBatch,
            }
        );

        // Distinct delegates keep separate IDs (not rewritten into batch).
        assert_eq!(plan.calls[1].call_id, "task");
        assert_eq!(plan.calls[2].call_id, "task");
        // They are separate entries in the plan — not coalesced.
        assert_ne!(plan.calls[1].source_index, plan.calls[2].source_index);

        // Each delegate remains its own attempt-resolved lifecycle.
        assert!(plan.calls[1].is_delegate_candidate());
        assert!(plan.calls[2].is_delegate_candidate());
    }

    /// Regression for the production mixed-lane shape: an ordinary read and
    /// two separately authored noninteractive delegates stay three distinct,
    /// FIFO scheduler identities under one bound.  In particular, the two task
    /// calls are not rewritten into the explicit-batch lifecycle.
    #[test]
    fn ordinary_plus_two_distinct_delegates_form_one_bounded_candidate_run() {
        let toolbox = ToolBox::new().with(Arc::new(crate::tools::read::ReadTool));
        let calls = vec![
            tool_call("read", serde_json::json!({ "path": "Cargo.toml" })),
            tool_call(
                "task",
                serde_json::json!({
                    "intent": "delegate",
                    "payload": { "agent": "probe-a", "prompt": "first" }
                }),
            ),
            tool_call(
                "task",
                serde_json::json!({
                    "intent": "delegate",
                    "payload": { "agent": "probe-b", "prompt": "second" }
                }),
            ),
        ];
        let plan =
            build_plan_with_delegate_context(&calls, &resolved_names(&calls), &toolbox, 2, true);

        assert_eq!(plan.max_parallel, 2);
        assert_eq!(
            plan.calls
                .iter()
                .map(|call| call.source_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(plan.calls[0].is_parallel_lane());
        assert!(plan.calls[1].is_delegate_candidate());
        assert!(plan.calls[2].is_delegate_candidate());
        assert_ne!(plan.calls[1].source_index, plan.calls[2].source_index);
    }

    /// Architecture acceptance: every resumable nested turn loop must enter
    /// the same Driver-owned mixed-lane funnel.  This ratchet prevents a future
    /// call site from restoring the former ordinary-only `plan.advance` path,
    /// which silently serialized distinct eligible delegates.
    #[test]
    fn nested_resumable_runners_are_wired_to_driver_mixed_lane_authority() {
        for source in [
            include_str!("../driver/noninteractive.rs"),
            include_str!("../schedule/loop_runner.rs"),
            include_str!("../schedule/swarm.rs"),
        ] {
            assert!(
                source.contains("advance_driver_owned_turn_plan_in_history"),
                "nested runner must use the Driver mixed-lane authority"
            );
            assert!(
                !source.contains("plan.advance("),
                "nested runner must not bypass delegate lane admission"
            );
        }
    }

    /// The event payload never contains tool arguments or provider bodies.
    #[test]
    fn event_payload_omits_args_and_bodies() {
        let toolbox = ToolBox::new();
        let calls = vec![
            tool_call("read", serde_json::json!({ "path": "/secret/key" })),
            tool_call("bash", serde_json::json!({ "command": "cat /etc/passwd" })),
        ];
        let names = resolved_names(&calls);
        let plan = build_plan(&calls, &names, &toolbox, 4);
        let payload = plan.to_event_payload();
        let json = serde_json::to_string(&payload).unwrap();
        // No tool arguments leak into the event payload.
        assert!(!json.contains("/secret/key"));
        assert!(!json.contains("cat /etc/passwd"));
        assert!(!json.contains("arguments"));
    }
}
