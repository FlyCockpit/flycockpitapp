//! `schedule` meta-tool + the fork-only `note` channel (GOALS §22).
//!
//! ## Cache-safety
//!
//! The `schedule` meta-tool's schema is fixed for a build and advertises a
//! closed union of supported per-action `args`. It changes only when schedule
//! capabilities change, matching the cache-bust profile of any other tool
//! schema change.
//!
//! ## Two tool surfaces
//!
//! - [`ScheduleTool`] — the main-context meta-tool. Like `task`, it is a
//!   *structural* tool the engine intercepts by name: the driver owns the
//!   single [`crate::engine::schedule::ScheduleAuthority`], so the action is
//!   dispatched there, not here. The trait impl exists only to advertise
//!   the fixed schema in one place; calling it directly is a loud error.
//! - [`ForkScheduleTool`] + [`NoteTool`] — injected into ephemeral-fork loop
//!   iterations. `note` is the only fork→main channel; the fork-scoped
//!   `schedule` cancels *its own* loop and re-routes create-actions to
//!   requests (forks cannot spawn async work — anti-runaway).

use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::engine::agent::TurnEvent;
use crate::engine::schedule::schemas::schema_for;
use crate::engine::schedule::spec::{
    ScheduleAction, SpawnRequest, parse_action, parse_background_start, parse_loop_start,
};
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};

/// The fixed schema for the `schedule` meta-tool.
pub const SCHEDULE_DESCRIPTION: &str = "Schedule async loop/background work without blocking the conversation; choose `action` (`loop.start`, `loop.cancel`, `background.start`, `background.tail`, `background.cancel`, `list`) and put per-action details in `args`; use limit=1 for one-shot timers; set idle=true to reset a bounded timer after each user message";

/// The verbose-steering `schedule` description
/// (implementation note): explicit steering for the
/// weak-model target. Same schema shape — only the prose is richer. Call
/// `schedule` directly as a native tool with an `action` argument; do not
/// route it through MCP.
pub const SCHEDULE_DESCRIPTION_DEFENSIVE: &str = "Run work in the background or on a recurring schedule so the conversation isn't blocked waiting. Call `schedule` directly as a native tool (an `action` argument), not through MCP. Pick the kind of work with `action`: `loop.start` runs a prompt repeatedly on an interval (set `limit=1` for a single delayed/one-shot timer), `loop.cancel` stops a running loop, `background.start` launches a long task that runs detached, `background.tail` shows that task's latest output, `background.cancel` stops it, and `list` shows what is currently scheduled. Set `idle=true` on a bounded loop to reset its countdown after every accepted user message. Idle wakes always run in an ephemeral fork: do not invent work; report, mutate, or raise an inbox item only when there is a real change. With `watch_paths`, Cockpit checks project-local metadata before inference and backs off without model cost when nothing changed. Each ordinary `loop.start` iteration is a full model inference that costs tokens and may run while the user is away, so pick the smallest iteration count and the longest interval that still does the job. Put the per-action details in `args`. Use this for things like polling a build, watching for a condition, or kicking off something slow you'll check later — not for ordinary step-by-step work, which you should just do directly.";
const FORK_SCHEDULE_DESCRIPTION: &str = "Request scheduled work from the main agent or cancel this fork's own loop; forked schedule never launches detached work itself";
const FORK_SCHEDULE_DESCRIPTION_DEFENSIVE: &str = "Inside a scheduled fork, use `schedule` only to request that the main agent consider new loop/background work, or to cancel this fork's own loop. `loop.start` and `background.start` record requests for the main agent; they do not launch detached work from the fork. `loop.cancel` cancels this fork's loop. Other schedule actions are rejected here.";

/// Build the `schedule` meta-tool's JSON schema. Kept in a free function so
/// tests can assert on it directly; see [`schedule_parameters_defensive`] for
/// the verbose-description variant.
pub fn schedule_parameters() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ScheduleAction::ALL.map(ScheduleAction::as_str),
                "description": "Branch: loop.start/loop.cancel/background.start/background.tail/background.cancel/list"
            },
            "args": {
                "anyOf": schedule_args_any_of(),
                "description": "Per-action arguments"
            }
        },
        "required": ["action"],
        "additionalProperties": false
    })
}

/// The verbose-steering parameter schema for the `schedule`
/// meta-tool: identical shape + required set to [`schedule_parameters`], with
/// explicit parameter descriptions.
pub fn schedule_parameters_defensive() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ScheduleAction::ALL.map(ScheduleAction::as_str),
                "description": "Which scheduled-work operation to perform: `loop.start`, `loop.cancel`, `background.start`, `background.tail`, `background.cancel`, or `list`"
            },
            "args": {
                "anyOf": schedule_args_any_of(),
                "description": "The arguments for the chosen `action` (e.g. the prompt + interval for `loop.start`, the job id for a cancel/tail); omit for `list`"
            }
        },
        "required": ["action"],
        "additionalProperties": false
    })
}

fn schedule_args_any_of() -> Vec<Value> {
    ScheduleAction::ALL.into_iter().map(schema_for).collect()
}

/// The main-context `schedule` meta-tool. Structural: intercepted by the
/// engine dispatcher (see [`crate::engine::agent::turn`]), which routes
/// the action to the driver-owned authority.
pub struct ScheduleTool;

#[async_trait]
impl Tool for ScheduleTool {
    fn name(&self) -> &str {
        "schedule"
    }

    fn description(&self) -> &str {
        SCHEDULE_DESCRIPTION
    }

    fn verbose_description(&self) -> Option<String> {
        Some(SCHEDULE_DESCRIPTION_DEFENSIVE.to_string())
    }

    fn parameters(&self) -> Value {
        schedule_parameters()
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(schedule_parameters_defensive())
    }

    async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        Err(anyhow::anyhow!(
            "`schedule` is intercepted by the engine dispatcher; this code path should be unreachable"
        ))
    }
}

/// Pull the `action` string + the `args` object out of a repaired `schedule`
/// call. `args` defaults to an empty object when omitted.
pub fn split_action(call_args: &Value) -> Result<(ScheduleAction, Value)> {
    let action_str = call_args
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("`action` is required"))?;
    let action = parse_action(action_str)?;
    let args = call_args
        .get("args")
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    Ok((action, args))
}

// ---- Fork-only tools -------------------------------------------------------

/// Shared ephemeral-fork state. Ordinary loops retain it to terminal
/// promotion; the loop runner creates a fresh value for every idle wake so
/// one wake's effect accounting cannot make a later read-only wake durable.
pub struct ForkScheduleState {
    /// The job id this fork's loop owns — `loop.cancel` must match it.
    own_job_id: String,
    notes: Mutex<Vec<String>>,
    requests: Mutex<Vec<SpawnRequest>>,
    actions: Mutex<Vec<String>>,
    cancelled: std::sync::atomic::AtomicBool,
    sealed_for_cancellation: std::sync::atomic::AtomicBool,
}

impl ForkScheduleState {
    pub fn new(own_job_id: String) -> Self {
        Self {
            own_job_id,
            notes: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
            actions: Mutex::new(Vec::new()),
            cancelled: std::sync::atomic::AtomicBool::new(false),
            sealed_for_cancellation: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn push_note(&self, text: String) -> bool {
        if self
            .sealed_for_cancellation
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return false;
        }
        let mut notes = self.notes.lock().unwrap();
        if self
            .sealed_for_cancellation
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return false;
        }
        notes.push(text);
        true
    }

    fn push_request(&self, req: SpawnRequest) -> bool {
        if self
            .sealed_for_cancellation
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return false;
        }
        let mut requests = self.requests.lock().unwrap();
        if self
            .sealed_for_cancellation
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return false;
        }
        requests.push(req);
        true
    }

    fn push_action(&self, action: String) -> bool {
        if self
            .sealed_for_cancellation
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return false;
        }
        let mut actions = self.actions.lock().unwrap();
        if self
            .sealed_for_cancellation
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return false;
        }
        actions.push(action);
        true
    }

    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn seal_for_cancellation(&self) {
        self.sealed_for_cancellation
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.cancel();
    }

    pub fn has_persistent_action(&self) -> bool {
        if !self.notes.lock().unwrap().is_empty() {
            return true;
        }
        if !self.requests.lock().unwrap().is_empty() {
            return true;
        }
        !self.actions.lock().unwrap().is_empty()
    }

    /// Drain accumulated notes (called once at termination).
    pub fn take_notes(&self) -> Vec<String> {
        std::mem::take(&mut *self.notes.lock().unwrap())
    }

    /// Drain accumulated spawn-requests (called once at termination).
    pub fn take_requests(&self) -> Vec<SpawnRequest> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }

    /// Drain effectful ordinary-tool calls. These are intentionally recorded
    /// before dispatch: an external cancellation may abort the future after a
    /// tool has already changed local or remote state, and must not turn that
    /// wake into an apparent no-op.
    pub fn take_actions(&self) -> Vec<String> {
        std::mem::take(&mut *self.actions.lock().unwrap())
    }
}

/// Authority-owned handoff for the one idle wake that is currently executing.
/// Exactly one side may take the state: the runner after a normal iteration or
/// the authority when cancellation aborts that runner.
pub type ActiveIdleWake = Arc<Mutex<ActiveIdleWakeState>>;

#[derive(Default)]
pub struct ActiveIdleWakeState {
    cancelled: bool,
    phase: ActiveIdleWakePhase,
}

#[derive(Default)]
enum ActiveIdleWakePhase {
    #[default]
    Idle,
    Running(Arc<ForkScheduleState>),
    Publishing,
}

pub enum IdleWakeCancellationClaim {
    Idle,
    Running(Arc<ForkScheduleState>),
    Publishing,
}

pub fn new_active_idle_wake() -> ActiveIdleWake {
    Arc::new(Mutex::new(ActiveIdleWakeState::default()))
}

pub fn install_active_idle_wake(active: &ActiveIdleWake, state: Arc<ForkScheduleState>) -> bool {
    let mut guard = active.lock().unwrap();
    if guard.cancelled {
        state.seal_for_cancellation();
        return false;
    }
    debug_assert!(matches!(guard.phase, ActiveIdleWakePhase::Idle));
    guard.phase = ActiveIdleWakePhase::Running(state);
    true
}

pub fn take_active_idle_wake_for_cancellation(
    active: &ActiveIdleWake,
) -> IdleWakeCancellationClaim {
    let mut guard = active.lock().unwrap();
    guard.cancelled = true;
    match std::mem::take(&mut guard.phase) {
        ActiveIdleWakePhase::Idle => IdleWakeCancellationClaim::Idle,
        ActiveIdleWakePhase::Running(state) => {
            state.seal_for_cancellation();
            IdleWakeCancellationClaim::Running(state)
        }
        ActiveIdleWakePhase::Publishing => {
            guard.phase = ActiveIdleWakePhase::Publishing;
            IdleWakeCancellationClaim::Publishing
        }
    }
}

pub fn begin_active_idle_wake_publication(
    active: &ActiveIdleWake,
    expected: &Arc<ForkScheduleState>,
) -> bool {
    let mut guard = active.lock().unwrap();
    match &guard.phase {
        ActiveIdleWakePhase::Running(current) if Arc::ptr_eq(current, expected) => {
            guard.phase = ActiveIdleWakePhase::Publishing;
            true
        }
        _ => false,
    }
}

/// Release a completed no-op wake without granting it ownership of a durable
/// event. A concurrent cancellation can still claim `Running` and publish its
/// own terminal marker.
pub fn finish_active_idle_wake_without_publication(
    active: &ActiveIdleWake,
    expected: &Arc<ForkScheduleState>,
) -> bool {
    let mut guard = active.lock().unwrap();
    match &guard.phase {
        ActiveIdleWakePhase::Running(current) if Arc::ptr_eq(current, expected) => {
            guard.phase = ActiveIdleWakePhase::Idle;
            true
        }
        _ => false,
    }
}

pub fn finish_active_idle_wake_publication(active: &ActiveIdleWake) -> bool {
    let mut guard = active.lock().unwrap();
    debug_assert!(matches!(guard.phase, ActiveIdleWakePhase::Publishing));
    guard.phase = ActiveIdleWakePhase::Idle;
    guard.cancelled
}

/// Track a possibly effectful parent operation in an idle fork. The wrapper
/// preserves the original tool contract while making the call visible to the
/// fork's authority-owned state before execution can be externally aborted.
pub struct IdleWakeActionTool {
    inner: Arc<dyn Tool>,
    state: Arc<ForkScheduleState>,
}

impl IdleWakeActionTool {
    pub fn new(inner: Arc<dyn Tool>, state: Arc<ForkScheduleState>) -> Self {
        Self { inner, state }
    }
}

#[async_trait]
impl Tool for IdleWakeActionTool {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn description(&self) -> &str {
        self.inner.description()
    }

    fn verbose_description(&self) -> Option<String> {
        self.inner.verbose_description()
    }

    fn effect(&self) -> ToolEffect {
        self.inner.effect()
    }

    fn authorizes_own_effects(&self) -> bool {
        self.inner.authorizes_own_effects()
    }

    fn is_registered_ordinary_operation(&self) -> bool {
        self.inner.is_registered_ordinary_operation()
    }

    fn binary_requirements(&self) -> Vec<crate::capabilities::BinaryRequirement> {
        self.inner.binary_requirements()
    }

    fn presentation(&self, args: &Value) -> crate::engine::tool::ToolPresentation {
        self.inner.presentation(args)
    }

    fn parameters(&self) -> Value {
        self.inner.parameters()
    }

    fn verbose_parameters(&self) -> Option<Value> {
        self.inner.verbose_parameters()
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        if !self
            .state
            .push_action(format!("invoked stateful tool `{}`", self.inner.name()))
        {
            return Err(anyhow::anyhow!(
                "idle wake was cancelled before the tool could run"
            ));
        }
        self.inner.call(args, ctx).await
    }

    fn ledger_args(&self, args: &Value) -> Value {
        self.inner.ledger_args(args)
    }

    fn honors_dispatch_cancel(&self) -> bool {
        self.inner.honors_dispatch_cancel()
    }

    async fn on_abandon(&self, ctx: &ToolCtx) -> Result<()> {
        self.inner.on_abandon(ctx).await
    }
}

/// `note(text)` — a fork→main channel. It is shown live in the UI via a
/// [`TurnEvent::ScheduleNote`]; ordinary loops bundle it at termination while
/// idle loops promote it with the acting wake.
pub struct NoteTool {
    state: Arc<ForkScheduleState>,
    turn_tx: mpsc::Sender<TurnEvent>,
}

impl NoteTool {
    pub fn new(state: Arc<ForkScheduleState>, turn_tx: mpsc::Sender<TurnEvent>) -> Self {
        Self { state, turn_tx }
    }
}

#[async_trait]
impl Tool for NoteTool {
    fn name(&self) -> &str {
        "note"
    }

    fn description(&self) -> &str {
        "Show the human a live progress note from this background loop; notes join the main conversation when the loop ends"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Send a short progress note to the human while you run inside a background loop. The \
             note is shown to the user live, but it does NOT enter the main conversation until \
             the loop finishes — at which point your notes are bundled with the final result. \
             Use it to report what each iteration found or did. Forked schedule requests are \
             recorded for the main agent rather than launched directly from here."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "text": { "type": "string", "description": "Progress note" }
            },
            "required": ["text"]
        })
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "text": { "type": "string", "description": "The progress note to surface to the human; keep it short and specific to this iteration" }
            },
            "required": ["text"]
        }))
    }

    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        let text = args
            .get("text")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| invalid_input("`text` is required"))?
            .to_string();
        // Record before signaling UI so cancellation can promote a note that
        // already became visible. A sealed wake cannot publish a new note.
        if !self.state.push_note(text.clone()) {
            return Err(anyhow::anyhow!(
                "idle wake was cancelled before the note could be sent"
            ));
        }
        // Live UI signal (never enters main context here — token economy).
        let _ = self.turn_tx.try_send(TurnEvent::ScheduleNote {
            job_id: self.state.own_job_id.clone(),
            text,
        });
        Ok(ToolOutput::text("noted"))
    }
}

/// The fork-scoped `schedule` meta-tool. Same fixed schema as [`ScheduleTool`] so
/// the fork's tools array is byte-stable too. Behaviour differs:
/// `loop.cancel` ends *this fork's own* loop; create-actions
/// (`loop.start`/`background.start`) do **not** execute — they record a
/// [`SpawnRequest`] routed to main (anti-runaway). Other actions are
/// rejected with a clear message.
pub struct ForkScheduleTool {
    state: Arc<ForkScheduleState>,
}

impl ForkScheduleTool {
    pub fn new(state: Arc<ForkScheduleState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl Tool for ForkScheduleTool {
    fn name(&self) -> &str {
        "schedule"
    }

    fn description(&self) -> &str {
        FORK_SCHEDULE_DESCRIPTION
    }

    fn verbose_description(&self) -> Option<String> {
        Some(FORK_SCHEDULE_DESCRIPTION_DEFENSIVE.to_string())
    }

    fn parameters(&self) -> Value {
        schedule_parameters()
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(schedule_parameters_defensive())
    }

    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        let (action, action_args) = split_action(&args)?;
        match action {
            ScheduleAction::LoopCancel => {
                // A fork may cancel its own loop. The job_id arg is
                // tolerated but the fork only owns one loop, so we don't
                // require a match — cancelling is always self-scoped here.
                self.state.cancel();
                Ok(ToolOutput::text(
                    "loop will end after this iteration completes",
                ))
            }
            ScheduleAction::LoopStart => {
                let parsed = parse_loop_start(&action_args)?;
                let summary = SpawnRequest::Loop(parsed.clone()).summary();
                if !self.state.push_request(SpawnRequest::Loop(parsed)) {
                    return Err(anyhow::anyhow!(
                        "idle wake was cancelled before the request could be recorded"
                    ));
                }
                Ok(ToolOutput::text(format!(
                    "request recorded — a fork cannot spawn scheduled work; the main agent will decide whether to start `{summary}`"
                )))
            }
            ScheduleAction::BackgroundStart => {
                let parsed = parse_background_start(&action_args)?;
                let summary = SpawnRequest::Background(parsed.clone()).summary();
                if !self.state.push_request(SpawnRequest::Background(parsed)) {
                    return Err(anyhow::anyhow!(
                        "idle wake was cancelled before the request could be recorded"
                    ));
                }
                Ok(ToolOutput::text(format!(
                    "request recorded — a fork cannot spawn scheduled work; the main agent will decide whether to start `{summary}`"
                )))
            }
            ScheduleAction::BackgroundTail
            | ScheduleAction::BackgroundCancel
            | ScheduleAction::List => Err(invalid_input(format!(
                "`{}` is only available in the main conversation, not inside a loop",
                action.as_str()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn remove_descriptions(value: &mut Value) {
        match value {
            Value::Object(object) => {
                object.remove("description");
                for child in object.values_mut() {
                    remove_descriptions(child);
                }
            }
            Value::Array(values) => {
                for value in values {
                    remove_descriptions(value);
                }
            }
            _ => {}
        }
    }

    /// The core caching invariant (GOALS §22): the serialized tools array
    /// containing the `schedule` meta-tool is **byte-identical** no matter
    /// which branches have been exercised. Branch-enabling is an appended
    /// hint message + dispatch acceptance — never a mutation of the tool's
    /// schema — so the cached prefix is never busted.
    #[test]
    fn tools_array_is_byte_stable_across_branch_enabling() {
        use crate::engine::tool::ToolBox;

        // The tools array a conversation carries (here: just `schedule`; the
        // real primary agent adds more, but they're equally immutable).
        let toolbox = ToolBox::new().with(Arc::new(ScheduleTool));
        let before =
            serde_json::to_string(&toolbox.definitions(crate::agents::ToolSteering::Terse))
                .unwrap();

        // Simulate "enabling every branch": the meta-tool's schema is the
        // same object regardless of action. Re-derive it for each branch
        // and confirm nothing about the advertised tool changes.
        for action in [
            "loop.start",
            "loop.cancel",
            "background.start",
            "background.tail",
            "background.cancel",
            "list",
        ] {
            // The action is accepted at dispatch (parses) — that's the
            // cache-safe acceptance half of enabling a branch.
            assert!(parse_action(action).is_ok());
            // The tool definition is unchanged after "enabling" it.
            let after =
                serde_json::to_string(&toolbox.definitions(crate::agents::ToolSteering::Terse))
                    .unwrap();
            assert_eq!(
                before, after,
                "tools array changed after enabling `{action}`"
            );
        }

        // And the schema itself is deterministic byte-for-byte.
        assert_eq!(
            serde_json::to_string(&schedule_parameters()).unwrap(),
            serde_json::to_string(&schedule_parameters()).unwrap()
        );
    }

    #[test]
    fn public_schema_is_a_closed_discriminated_union() {
        let schema = schedule_parameters();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"], json!(["action"]));
        assert_eq!(
            schema["properties"]["action"]["enum"],
            json!([
                "loop.start",
                "loop.cancel",
                "background.start",
                "background.tail",
                "background.cancel",
                "list"
            ])
        );

        let variants = schema["properties"]["args"]["anyOf"].as_array().unwrap();
        assert_eq!(variants.len(), ScheduleAction::ALL.len());
        for (action, variant) in ScheduleAction::ALL.into_iter().zip(variants) {
            assert_eq!(
                variant["type"],
                "object",
                "{} args schema is an object",
                action.as_str()
            );
            assert_eq!(
                variant["additionalProperties"],
                false,
                "{} args schema is closed",
                action.as_str()
            );
            assert!(
                variant.get("properties").is_some(),
                "{} args schema declares properties",
                action.as_str()
            );
        }
    }

    #[test]
    fn defensive_and_terse_schemas_agree_on_shape() {
        let mut terse = schedule_parameters();
        let mut defensive = schedule_parameters_defensive();
        remove_descriptions(&mut terse);
        remove_descriptions(&mut defensive);
        assert_eq!(terse, defensive);
    }

    /// The `schedule` description names the action surface but leaves
    /// per-action field shapes to the machine-readable schema. Keeping field
    /// names out of the prose prevents a second, drifting schema.
    #[test]
    fn description_names_actions_without_parameter_shapes() {
        for action in [
            "loop.start",
            "loop.cancel",
            "background.start",
            "background.tail",
            "background.cancel",
            "list",
        ] {
            assert!(
                SCHEDULE_DESCRIPTION.contains(action),
                "`schedule` description must name action `{action}`"
            );
        }
        for field in ["prompt", "interval", "job_id", "command", "cwd", "lines"] {
            assert!(
                !SCHEDULE_DESCRIPTION.contains(field),
                "`schedule` description should not duplicate schema field `{field}`"
            );
        }
    }

    #[test]
    fn schedule_verbose_description_states_iteration_cost() {
        let description = ScheduleTool.verbose_description().unwrap();

        assert!(description.contains("full model inference"));
        assert!(description.contains("costs tokens"));
        assert!(description.contains("while the user is away"));
        assert!(description.contains("smallest iteration count"));
        assert!(description.contains("longest interval"));
    }

    #[test]
    fn split_action_parses() {
        let (a, args) = split_action(&json!({
            "action": "loop.start",
            "args": { "interval": 30, "prompt": "p" }
        }))
        .unwrap();
        assert_eq!(a, ScheduleAction::LoopStart);
        assert_eq!(args["interval"], 30);
    }

    #[test]
    fn split_action_defaults_args_to_empty_object() {
        let (a, args) = split_action(&json!({ "action": "list" })).unwrap();
        assert_eq!(a, ScheduleAction::List);
        assert!(args.as_object().unwrap().is_empty());
    }

    #[test]
    fn split_action_unknown_errors() {
        assert!(split_action(&json!({ "action": "bogus" })).is_err());
        assert!(split_action(&json!({})).is_err());
    }

    #[tokio::test]
    async fn fork_schedule_routes_create_to_request() {
        let state = Arc::new(ForkScheduleState::new("sched-abc".into()));
        let tool = ForkScheduleTool::new(state.clone());
        let (_dir, ctx) = test_ctx();
        let out = tool
            .call(
                json!({ "action": "background.start", "args": { "command": "cargo test" } }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(out.content.contains("request recorded"));
        let reqs = state.take_requests();
        assert_eq!(reqs.len(), 1);
        assert!(matches!(reqs[0], SpawnRequest::Background(_)));
    }

    #[test]
    fn fork_schedule_description_differs_but_schema_matches_main_schedule() {
        let state = Arc::new(ForkScheduleState::new("sched-abc".into()));
        let fork = ForkScheduleTool::new(state);
        let main = ScheduleTool;

        assert_ne!(fork.description(), main.description());
        assert!(
            !fork
                .verbose_description()
                .unwrap()
                .contains("launches a long task that runs detached")
        );
        assert_eq!(fork.parameters(), main.parameters());
        assert_eq!(fork.verbose_parameters(), main.verbose_parameters());
    }

    #[tokio::test]
    async fn fork_schedule_cancel_sets_flag() {
        let state = Arc::new(ForkScheduleState::new("sched-abc".into()));
        let tool = ForkScheduleTool::new(state.clone());
        let (_dir, ctx) = test_ctx();
        assert!(!state.is_cancelled());
        tool.call(json!({ "action": "loop.cancel" }), &ctx)
            .await
            .unwrap();
        assert!(state.is_cancelled());
    }

    #[tokio::test]
    async fn fork_schedule_rejects_main_only_actions() {
        let state = Arc::new(ForkScheduleState::new("sched-abc".into()));
        let tool = ForkScheduleTool::new(state);
        let (_dir, ctx) = test_ctx();
        assert!(tool.call(json!({ "action": "list" }), &ctx).await.is_err());
        assert!(
            tool.call(
                json!({ "action": "background.tail", "args": {"job_id":"x"} }),
                &ctx
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn note_records_and_signals() {
        let state = Arc::new(ForkScheduleState::new("sched-abc".into()));
        let (tx, mut rx) = mpsc::channel(8);
        let tool = NoteTool::new(state.clone(), tx);
        let (_dir, ctx) = test_ctx();
        tool.call(json!({ "text": "halfway there" }), &ctx)
            .await
            .unwrap();
        let notes = state.take_notes();
        assert_eq!(notes, vec!["halfway there".to_string()]);
        match rx.try_recv().unwrap() {
            TurnEvent::ScheduleNote { text, .. } => assert_eq!(text, "halfway there"),
            other => panic!("expected ScheduleNote, got {other:?}"),
        }
    }

    #[test]
    fn cancellation_claim_seals_and_preserves_the_active_wake() {
        let active = new_active_idle_wake();
        let state = Arc::new(ForkScheduleState::new("sched-abc".into()));
        assert!(state.push_note("already acted".into()));
        assert!(install_active_idle_wake(&active, state.clone()));

        let IdleWakeCancellationClaim::Running(claimed) =
            take_active_idle_wake_for_cancellation(&active)
        else {
            panic!("cancellation must claim the running wake");
        };
        assert!(Arc::ptr_eq(&claimed, &state));
        assert_eq!(claimed.take_notes(), vec!["already acted".to_string()]);
        assert!(!claimed.push_note("must not be lost after cancellation".into()));
        assert!(!install_active_idle_wake(
            &active,
            Arc::new(ForkScheduleState::new("late".into()))
        ));
    }

    #[test]
    fn cancellation_during_publication_leaves_the_event_with_the_runner() {
        let active = new_active_idle_wake();
        let state = Arc::new(ForkScheduleState::new("sched-abc".into()));
        assert!(install_active_idle_wake(&active, state.clone()));
        assert!(begin_active_idle_wake_publication(&active, &state));
        assert!(matches!(
            take_active_idle_wake_for_cancellation(&active),
            IdleWakeCancellationClaim::Publishing
        ));
        assert!(finish_active_idle_wake_publication(&active));
    }

    #[test]
    fn no_op_release_does_not_claim_publication_or_block_the_next_wake() {
        let active = new_active_idle_wake();
        let no_op = Arc::new(ForkScheduleState::new("sched-abc".into()));
        assert!(install_active_idle_wake(&active, no_op.clone()));
        assert!(finish_active_idle_wake_without_publication(&active, &no_op));

        let next = Arc::new(ForkScheduleState::new("sched-abc".into()));
        assert!(install_active_idle_wake(&active, next.clone()));
        assert!(matches!(
            take_active_idle_wake_for_cancellation(&active),
            IdleWakeCancellationClaim::Running(claimed) if Arc::ptr_eq(&claimed, &next)
        ));
    }

    /// Minimal `ToolCtx` for unit-testing fork tools (they don't touch the
    /// session / locks / cwd).
    fn test_ctx() -> (tempfile::TempDir, ToolCtx) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(dir.path());
        (dir, ctx)
    }
}
