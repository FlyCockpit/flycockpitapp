//! The agent loop — cockpit's conversation engine.
//!
//! Drives Cockpit's host-owned completion-request conversation loop: it builds
//! [`rig::completion::CompletionRequest`] values directly, dispatches tool calls
//! through the [`tool`] layer, and persists `original_input` / `wire_input` /
//! `recovery` on each tool-call row per GOALS §14. Rig supplies provider
//! transport and message types only; Cockpit owns turn control and never uses
//! Rig agent APIs.
//!
//! Layering:
//!
//! - [`message`] — type aliases over rig's `rig::message` so the rest
//!   of the codebase doesn't import rig directly.
//! - [`tool`] — our [`Tool`](tool::Tool) trait with `Args = Value`,
//!   giving §12 repair a place to live between deserialization and
//!   dispatch.
//! - [`model`] — provider enum (`OpenAi` v0; `Anthropic`, `OpenRouter`,
//!   `Ollama` queued).
//! - [`repair`] — the §12 catalog.
//! - [`agent`] — [`Agent`](agent::Agent) + [`turn`](agent::turn).
//! - [`driver`] — multi-agent stack with interactive primary handoff
//!   (GOALS §3b).
//! - [`builtin`] — embedded `builder.md` + `build.md`.

pub mod agent;
pub mod bash_hints;
pub mod builtin;
pub mod compact;
pub(crate) mod compact_draft;
pub mod deferred;
pub mod deleg_shrink;
pub mod delegation_prompt_prune;
pub mod docs_pipeline;
pub mod driver;
pub mod envelope;
pub mod guidance_diff;
pub mod injection_check;
pub mod interrupt;
pub mod message;
pub mod model;
pub mod model_roles;
pub mod predict;
pub mod preflight;
pub mod prune;
pub mod rehydrate;
pub mod repair;
pub mod resource_scheduler;
pub mod response_performance;
pub mod retry;
pub mod safety_gate;
pub mod schedule;
pub mod task_identity;
pub mod text_call;
pub mod think;
pub mod tool;
pub mod translate;
/// Closed acquisition-outcome type + fail-closed `RequiresUser` validator
/// (leak-report AC6, sub-increment 2c-3a). A pure module with no provider,
/// async, or I/O. The production coordinator that dispatches a trusted child
/// and classifies its output into an `AcquisitionOutcome` lands in the
/// follow-up sub-increment (2c-3b), so this type is `dead_code`-allowed until
/// then — mirroring the not-yet-wired `session::trusted_child_capture`
/// authority surface. The allow drops when 2c-3b consumes it.
#[allow(dead_code)]
pub(crate) mod trusted_child_acquisition;
/// Trusted-child sealed-value acquisition COORDINATOR (leak-report AC6,
/// sub-increment 2c-3b). Ties together 2c-1 (`resolve_trusted_child_model`),
/// 2c-2 (`session::trusted_child_capture`), and 2c-3a
/// (`trusted_child_acquisition`) into the single host function that performs one
/// acquisition over a trusted child and returns only an `AcquisitionOutcome`.
/// The child runs as a non-persisting utility completion (never the turn
/// runner), so its raw output never reaches a session event, `budget_result`,
/// parent context, or the stream. The thin live task-delegation trigger is a
/// follow-up (the swarm loop has no sealed-acquisition trigger yet, and the
/// computer-use caller is deferred), so this module is `dead_code`-allowed until
/// a live caller consumes it — mirroring 2c-1/2c-2/2c-3a's dormancy.
#[allow(dead_code)]
pub(crate) mod trusted_child_acquisition_coordinator;
pub mod validation_hint;

pub use agent::{
    ControlRequestId, ControlRequestNotDelivered, ControlRequestOutcome, IdleReason, ToolProgress,
    TurnEvent,
};
pub use driver::Driver;
pub use response_performance::{
    AssistantAttemptId, AssistantTextPayload, DisplayAttemptReset, DisplayClassifierConfig,
    DisplayComplete, DisplayError, DisplayErrorKind, DisplayEvent, DisplayReasoningDelta,
    DisplayStreamClassifier, DisplayTextDelta, InjectedDisplayClock, Instant, RealDisplayClock,
    ResponsePerformance,
};

/// Whether the conversation is at a point where context-reduction
/// (`/prune` auto-fire, auto-`/compact`) may run without corrupting the
/// wire/user transcript split (`plan.md` T6.e). The boundary is safe
/// when no tool call is mid-flight, no interactive subagent is active,
/// and no user interaction is pending:
///
/// ```text
/// tool_call_in_flight.is_none()
///     && active_subagents.is_empty()
///     && !pending_user_interaction
/// ```
///
/// The driver evaluates this at the inference boundary (between tool
/// loops). Mid-tool-call or mid-subagent state must defer the reduction
/// and re-evaluate after the next significant state change, never prune
/// in place. A `false` here means "queue and retry."
pub fn is_at_safe_compaction_boundary(
    tool_call_in_flight: bool,
    active_subagents: bool,
    pending_user_interaction: bool,
) -> bool {
    !tool_call_in_flight && !active_subagents && !pending_user_interaction
}
