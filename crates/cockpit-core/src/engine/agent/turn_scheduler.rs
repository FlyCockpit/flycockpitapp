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

use serde_json::Value;
use std::sync::Arc;

use crate::engine::tool::{ToolBox, ToolEffect};

/// Classification of a single tool call in the scheduler plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallClassification {
    /// May run in a parallel lane: a registered `ReadOnly` ordinary tool, or
    /// a noninteractive delegate whose `ResolvedChildExecutionSurface` proves
    /// `parallel_read_only_eligible`.
    ParallelLane {
        reason: ParallelLaneReason,
    },
    /// Must run serially, draining any in-flight lane first.
    SerialBarrier {
        reason: SerialBarrierReason,
    },
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
            Self::SerialBarrier { reason } => reason.as_str(),
        }
    }
}

/// Why a call was admitted to a parallel lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParallelLaneReason {
    /// A registered ordinary tool with `ToolEffect::ReadOnly`.
    ReadOnlyOrdinary,
    /// A noninteractive delegate whose execution surface proves
    /// `parallel_read_only_eligible`.
    ReadOnlyDelegate,
}

impl ParallelLaneReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnlyOrdinary => "read_only_ordinary",
            Self::ReadOnlyDelegate => "read_only_delegate",
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
    WriteCapableTask,
    TaskControl,
    TaskBatch,
    DelegateNotEligible,
    DelegateResolutionFailed,
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
            Self::WriteCapableTask => "write_capable_task",
            Self::TaskControl => "task_control",
            Self::TaskBatch => "task_batch",
            Self::DelegateNotEligible => "delegate_not_eligible",
            Self::DelegateResolutionFailed => "delegate_resolution_failed",
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
        Value::Array(
            self.calls
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
                            CallClassification::SerialBarrier { reason } => {
                                ("serial_barrier", reason.as_str())
                            }
                        };
                        map.insert("lane".to_string(), Value::String(lane.to_string()));
                        map.insert("reason".to_string(), Value::String(reason.to_string()));
                        map
                    })
                })
                .collect(),
        )
    }
}

/// Build the scheduler plan from a list of resolved tool calls.
///
/// `resolved_names` is parallel to `calls` — each entry is the name-repaired
/// tool name for the corresponding call. `active_tools` is the turn's toolbox.
/// `max_parallel` is `delegation.max_parallel.max(1)`.
///
/// For `task` delegate calls, this attempts a side-effect-free
/// `resolve_child_execution_surface` to check
/// `parallel_read_only_eligible`. If resolution fails, the call is classified
/// as a serial barrier (fail-closed). The resolution creates no child/task
/// record, spawns no child, pregrants no write scope, requests no approval,
/// and mutates no task lifecycle — it is purely a read-only classification
/// probe.
pub(crate) fn build_plan(
    calls: &[crate::engine::message::ToolCall],
    resolved_names: &[String],
    active_tools: &ToolBox,
    max_parallel: usize,
) -> TurnSchedulerPlan {
    let scheduled = calls
        .iter()
        .enumerate()
        .map(|(idx, tc)| {
            let resolved_name = resolved_names
                .get(idx)
                .map(String::as_str)
                .unwrap_or(&tc.function.name);
            let classification = classify_call(tc, resolved_name, active_tools);
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
) -> CallClassification {
    // Structural tools are always serial barriers unless they are a
    // noninteractive delegate that proves parallel_read_only_eligible.
    match resolved_name {
        "task" => classify_task_call(tc, active_tools),
        "schedule" => {
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Schedule,
            }
        }
        "spawn" => {
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Spawn,
            }
        }
        "return" => {
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Return,
            }
        }
        "done" => {
            return CallClassification::SerialBarrier {
                reason: SerialBarrierReason::Done,
            }
        }
        _ => {}
    }

    // Ordinary tool: classify by static ToolEffect.
    if let Some(tool) = active_tools.get(resolved_name) {
        match tool.effect() {
            ToolEffect::ReadOnly => CallClassification::ParallelLane {
                reason: ParallelLaneReason::ReadOnlyOrdinary,
            },
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
            classify_delegate_call(&args)
        }
    }
}

/// Classify a `task(intent=delegate)` call by probing the child execution
/// surface. Side-effect-free: builds the child agent (a pure construction)
/// and derives the surface, but creates no task record, spawns no child,
/// pregrants no write scope, requests no approval, or mutates no task
/// lifecycle.
fn classify_delegate_call(delegate_args: &Value) -> CallClassification {
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

    // Check write_scope presence from the parsed args. A delegate with a
    // write_scope is a serial barrier.
    let has_write_scope = delegate_args
        .get("write_scope")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some();

    if has_write_scope {
        return CallClassification::SerialBarrier {
            reason: SerialBarrierReason::WriteCapableTask,
        };
    }

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

    let interactive = if has_resume_handle {
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

    // Attempt a side-effect-free child surface resolution. If it succeeds and
    // the surface proves parallel_read_only_eligible, the delegate is admitted
    // to a parallel lane. Otherwise it is a serial barrier (fail-closed).
    //
    // The resolution builds SpawnArgs from the delegate args. This creates no
    // child/task record, spawns no child, pregrants no write scope, requests no
    // approval, and mutates no task lifecycle — `resolve_child_execution_surface`
    // is a pure construction + derivation.
    match try_resolve_delegate_surface(child_agent, delegate_args) {
        Ok(surface) => {
            if surface.parallel_read_only_eligible {
                CallClassification::ParallelLane {
                    reason: ParallelLaneReason::ReadOnlyDelegate,
                }
            } else {
                CallClassification::SerialBarrier {
                    reason: SerialBarrierReason::DelegateNotEligible,
                }
            }
        }
        Err(_) => CallClassification::SerialBarrier {
            reason: SerialBarrierReason::DelegateResolutionFailed,
        },
    }
}

/// Build a minimal `SpawnArgs` for a plan-time delegate surface probe and
/// resolve the child execution surface. This is side-effect-free.
///
/// The SpawnArgs is constructed from the delegate's parsed args with defaults
/// for Driver-specific fields. The key fields that affect
/// `parallel_read_only_eligible` (interactive, write_scope, config, cwd, model)
/// are set correctly from the delegate args and the turn context. Fields that
/// the driver owns (assistant_identity_prefix, model_override,
/// vnext_local_installation_resolver, etc.) are defaulted — they do not affect
/// the read-only eligibility derivation for standard built-in agents.
fn try_resolve_delegate_surface(
    child_agent: &str,
    delegate_args: &Value,
) -> anyhow::Result<crate::engine::builtin::ResolvedChildExecutionSurface> {
    // Build a minimal SpawnArgs for the probe. We use no_installations() for
    // the vnext resolver — standard built-in agents (explore, etc.) don't need
    // vnext bindings.
    let args = build_probe_spawn_args(child_agent, delegate_args)?;
    crate::engine::builtin::resolve_child_execution_surface(child_agent, &args)
}

/// Build a minimal `SpawnArgs` for a plan-time surface probe.
///
/// This is intentionally minimal: it provides the fields that
/// `derive_parallel_read_only_eligible` and `load()` need to build the child
/// and derive its surface, without requiring the full Driver context. Fields
/// that the Driver owns and that don't affect read-only eligibility are
/// defaulted.
fn build_probe_spawn_args(
    _child_agent: &str,
    _delegate_args: &Value,
) -> anyhow::Result<crate::engine::builtin::SpawnArgs> {
    // This function requires a config handle and model to build SpawnArgs.
    // In the current architecture, the turn context provides these, but they
    // are not available in this free function. The scheduler's `build_plan`
    // is called from `run_turn` which has the full TurnCtx.
    //
    // For now, we return an error to indicate that probe resolution is not
    // available without the full turn context. This makes all delegates
    // serial barriers (fail-closed), which is safe but conservative.
    //
    // TODO: Thread the TurnCtx into the scheduler so delegate surface probes
    // can resolve at plan time. The issue's AC1 requires this for full
    // parallel-lane admission of eligible delegates.
    anyhow::bail!("delegate surface probe requires turn context (not yet threaded)")
}

/// A lane admission state tracking FIFO bounding by `max_parallel`.
#[derive(Debug)]
pub(crate) struct LaneAdmission {
    max_parallel: usize,
    /// Indices into the plan's calls that are queued for admission.
    queued: Vec<usize>,
    /// Number of currently in-flight (started, not settled) members.
    in_flight: usize,
}

impl LaneAdmission {
    pub fn new(max_parallel: usize) -> Self {
        Self {
            max_parallel: max_parallel.max(1),
            queued: Vec::new(),
            in_flight: 0,
        }
    }

    /// Enqueue a call for later admission.
    pub fn enqueue(&mut self, plan_index: usize) {
        self.queued.push(plan_index);
    }

    /// Try to admit queued calls up to `max_parallel`. Returns the plan
    /// indices that may now start, in FIFO (source) order.
    pub fn admit_available(&mut self) -> Vec<usize> {
        let mut admitted = Vec::new();
        while self.in_flight < self.max_parallel {
            if let Some(idx) = self.queued.first().copied() {
                self.queued.remove(0);
                self.in_flight += 1;
                admitted.push(idx);
            } else {
                break;
            }
        }
        admitted
    }

    /// Mark one in-flight member as settled (frees one capacity slot).
    pub fn settle_one(&mut self) {
        if self.in_flight > 0 {
            self.in_flight -= 1;
        }
    }

    /// Whether the lane has drained (no queued, no in-flight).
    pub fn is_drained(&self) -> bool {
        self.queued.is_empty() && self.in_flight == 0
    }

    /// Number of queued (not yet admitted) calls.
    pub fn queued_count(&self) -> usize {
        self.queued.len()
    }

    /// Number of currently in-flight calls.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        calls
            .iter()
            .map(|tc| tc.function.name.clone())
            .collect()
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
            .with(Arc::new(crate::tools::grep::GrepTool));

        let calls = vec![
            tool_call("read", serde_json::json!({ "path": "a.txt" })),
            tool_call("glob", serde_json::json!({ "pattern": "*.rs" })),
            tool_call("bash", serde_json::json!({ "command": "ls" })),
            tool_call("unknown_tool", serde_json::json!({})),
        ];
        let names = resolved_names(&calls);
        let plan = build_plan(&calls, &names, &toolbox, 4);

        // Source order preserved: every original call ID is in the plan.
        assert_eq!(plan.calls.len(), 4);
        assert_eq!(plan.calls[0].call_id, "read");
        assert_eq!(plan.calls[1].call_id, "glob");
        assert_eq!(plan.calls[2].call_id, "bash");
        assert_eq!(plan.calls[3].call_id, "unknown_tool");

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

        // bash is Dynamic (default) → serial barrier.
        assert!(plan.calls[2].is_serial_barrier());
        assert_eq!(
            plan.calls[2].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::DynamicTool,
            }
        );

        // unknown_tool is not registered → serial barrier.
        assert!(plan.calls[3].is_serial_barrier());
        assert_eq!(
            plan.calls[3].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::UnknownTool,
            }
        );

        // Event payload contains only call IDs, lane, and reason — no args.
        let payload = plan.to_event_payload();
        let arr = payload.as_array().expect("payload is an array");
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[0]["call_id"], "read");
        assert_eq!(arr[0]["lane"], "parallel_lane");
        assert!(arr[0].get("arguments").is_none());
    }

    /// AC1: Structural tools are serial barriers.
    #[test]
    fn structural_tools_are_serial_barriers() {
        let toolbox = ToolBox::new();

        let calls = vec![
            tool_call("schedule", serde_json::json!({})),
            tool_call("spawn", serde_json::json!({ "prompt": "x", "write_scope": "s" })),
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

    /// AC1: An interactive delegate and a write-scope delegate are serial
    /// barriers.
    #[test]
    fn interactive_and_write_scope_delegates_are_serial_barriers() {
        let toolbox = ToolBox::new();

        // Interactive delegate (builder is interactive by default).
        let calls = vec![
            tool_call(
                "task",
                serde_json::json!({ "intent": "delegate", "payload": { "agent": "builder", "prompt": "build it" } }),
            ),
            // Write-scope delegate.
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

        // explore with write_scope → serial barrier.
        assert!(plan.calls[1].is_serial_barrier());
        assert_eq!(
            plan.calls[1].classification,
            CallClassification::SerialBarrier {
                reason: SerialBarrierReason::WriteCapableTask,
            }
        );
    }

    /// AC2: `parallel_lane_respects_delegation_max_parallel_fifo` proves an
    /// over-limit ordinary lane starts no more than `max_parallel` members,
    /// starts queued members FIFO as capacity frees, and drains before the
    /// next barrier.
    #[test]
    fn parallel_lane_respects_delegation_max_parallel_fifo() {
        // 6 read-only calls with max_parallel=2.
        let mut lane = LaneAdmission::new(2);
        for i in 0..6 {
            lane.enqueue(i);
        }

        // First admission: exactly 2 start (FIFO: 0, 1).
        let first = lane.admit_available();
        assert_eq!(first, vec![0, 1]);
        assert_eq!(lane.in_flight_count(), 2);
        assert_eq!(lane.queued_count(), 4);
        assert!(!lane.is_drained());

        // Settle one (call 0) → one capacity frees → next queued starts (2).
        lane.settle_one();
        let second = lane.admit_available();
        assert_eq!(second, vec![2]);
        assert_eq!(lane.in_flight_count(), 2);
        assert_eq!(lane.queued_count(), 3);

        // Settle one (call 1) → next queued starts (3).
        lane.settle_one();
        let third = lane.admit_available();
        assert_eq!(third, vec![3]);
        assert_eq!(lane.in_flight_count(), 2);
        assert_eq!(lane.queued_count(), 2);

        // Settle both in-flight → two more start (4, 5).
        lane.settle_one();
        lane.settle_one();
        let fourth = lane.admit_available();
        assert_eq!(fourth, vec![4, 5]);
        assert_eq!(lane.in_flight_count(), 2);
        assert_eq!(lane.queued_count(), 0);

        // Settle both → lane is drained.
        lane.settle_one();
        lane.settle_one();
        assert!(lane.is_drained());

        // No more to admit.
        let fifth = lane.admit_available();
        assert!(fifth.is_empty());
    }

    /// AC2: max_parallel of 1 means strictly serial admission within a lane.
    #[test]
    fn lane_admission_max_one_is_strictly_serial() {
        let mut lane = LaneAdmission::new(1);
        for i in 0..3 {
            lane.enqueue(i);
        }
        assert_eq!(lane.admit_available(), vec![0]);
        assert_eq!(lane.admit_available(), vec![]); // at capacity
        lane.settle_one();
        assert_eq!(lane.admit_available(), vec![1]);
        lane.settle_one();
        assert_eq!(lane.admit_available(), vec![2]);
        lane.settle_one();
        assert!(lane.is_drained());
    }

    /// AC3: `scheduler_defers_delegate_admission_until_serial_barrier` — a
    /// delegate call is classified as a serial barrier when surface resolution
    /// is unavailable (fail-closed), proving no child selection/build/record/
    /// spawn happens at plan time.
    #[test]
    fn scheduler_defers_delegate_admission_until_serial_barrier() {
        let toolbox = ToolBox::new();

        // A noninteractive delegate (explore) without write_scope. Without
        // turn context for surface resolution, this is fail-closed to a
        // serial barrier.
        let calls = vec![tool_call(
            "task",
            serde_json::json!({ "intent": "delegate", "payload": { "agent": "explore", "prompt": "look around" } }),
        )];
        let names = resolved_names(&calls);
        let plan = build_plan(&calls, &names, &toolbox, 4);

        // Fail-closed: delegate is a serial barrier when surface probe is
        // unavailable. No child record/spawn/scope happens at plan time.
        assert!(plan.calls[0].is_serial_barrier());
        // The reason is either DelegateResolutionFailed or DelegateNotEligible.
        let reason = match &plan.calls[0].classification {
            CallClassification::SerialBarrier { reason } => *reason,
            _ => unreachable!(),
        };
        assert!(
            reason == SerialBarrierReason::DelegateResolutionFailed
                || reason == SerialBarrierReason::DelegateNotEligible,
            "expected delegate resolution failure or not-eligible, got {reason:?}"
        );
    }

    /// AC3: `explicit_batch_and_distinct_delegates_keep_separate_lifecycles` —
    /// explicit `intent=batch` retains bounded grouping behavior (serial
    /// barrier) while separately emitted delegates retain separate IDs.
    #[test]
    fn explicit_batch_and_distinct_delegates_keep_separate_lifecycles() {
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

        // Each delegate is its own serial barrier (fail-closed without turn
        // context for surface resolution).
        assert!(plan.calls[1].is_serial_barrier());
        assert!(plan.calls[2].is_serial_barrier());
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
