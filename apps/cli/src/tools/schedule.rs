//! `schedule` meta-tool + the fork-only `note` channel (GOALS §22).
//!
//! ## Cache-safety
//!
//! The `schedule` meta-tool's schema is **fixed and minimal** (`action` +
//! `args`). It never changes across a conversation, so the serialized
//! tools array is byte-stable and capability growth never busts the
//! prompt cache. Branches are enabled by two cache-safe moves elsewhere:
//! the dispatcher (driver) starts accepting the action, and an appended
//! **hint message** tells the model the action is available (appended
//! messages extend the cached prefix; they don't reserialize the tools
//! block).
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
use crate::engine::schedule::spec::{
    ScheduleAction, SpawnRequest, parse_action, parse_background_start, parse_loop_start,
};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

/// The fixed minimal schema for the `schedule` meta-tool. **Byte-stable** for
/// the conversation's lifetime — see the module docs and the
/// `tools_array_is_byte_stable` test in [`crate::engine::driver`].
pub const SCHEDULE_DESCRIPTION: &str = "Schedule async work: loop.start{prompt,interval,limit?,...}, loop.cancel{job_id}, background.start{command,cwd?}, background.tail{job_id,lines?}, background.cancel{job_id}, list{} (limit=1=timer)";

/// The defensive (`LlmMode::Defensive`) `schedule` description
/// (implementation note): explicit steering for the
/// weak-model target. Same fixed `action`+`args` schema — only the prose
/// is richer. Call `schedule` directly as a native tool with an `action`
/// argument; do not route it through MCP.
pub const SCHEDULE_DESCRIPTION_DEFENSIVE: &str = "Run work in the background or on a recurring schedule so the conversation isn't blocked waiting. Call `schedule` directly as a native tool (an `action` argument), not through MCP. Pick the kind of work with `action`: `loop.start` runs a prompt repeatedly on an interval (set `limit=1` for a single delayed/one-shot timer), `loop.cancel` stops a running loop, `background.start` launches a long task that runs detached, `background.tail` shows that task's latest output, `background.cancel` stops it, and `list` shows what is currently scheduled. Put the per-action details in `args`. Use this for things like polling a build, watching for a condition, or kicking off something slow you'll check later — not for ordinary step-by-step work, which you should just do directly.";

/// Build the `schedule` meta-tool's JSON schema. Kept in a free function so
/// the byte-stability test can assert on it directly. The schema is
/// byte-stable for cache safety regardless of `llm_mode`; see
/// [`schedule_parameters_defensive`] for the verbose-description variant.
pub fn schedule_parameters() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "description": "Branch: loop.start/loop.cancel/background.start/background.tail/background.cancel/list"
            },
            "args": {
                "type": "object",
                "description": "Per-action arguments"
            }
        },
        "required": ["action"]
    })
}

/// The defensive (`LlmMode::Defensive`) parameter schema for the `schedule`
/// meta-tool: identical shape + required set to [`schedule_parameters`], with
/// explicit parameter descriptions.
pub fn schedule_parameters_defensive() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "description": "Which scheduled-work operation to perform: `loop.start`, `loop.cancel`, `background.start`, `background.tail`, `background.cancel`, or `list`"
            },
            "args": {
                "type": "object",
                "description": "The arguments for the chosen `action` (e.g. the prompt + interval for `loop.start`, the job id for a cancel/tail); omit for `list`"
            }
        },
        "required": ["action"]
    })
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

    fn defensive_description(&self) -> Option<String> {
        Some(SCHEDULE_DESCRIPTION_DEFENSIVE.to_string())
    }

    fn parameters(&self) -> Value {
        schedule_parameters()
    }

    fn defensive_parameters(&self) -> Option<Value> {
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

/// Shared state the ephemeral-fork loop's tools write into and the
/// loop runner reads at termination. Notes and re-routed create-requests
/// accumulate here; `cancelled` flips when the fork cancels its own loop.
pub struct ForkScheduleState {
    /// The job id this fork's loop owns — `loop.cancel` must match it.
    own_job_id: String,
    notes: Mutex<Vec<String>>,
    requests: Mutex<Vec<SpawnRequest>>,
    cancelled: std::sync::atomic::AtomicBool,
}

impl ForkScheduleState {
    pub fn new(own_job_id: String) -> Self {
        Self {
            own_job_id,
            notes: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
            cancelled: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn push_note(&self, text: String) {
        self.notes.lock().unwrap().push(text);
    }

    fn push_request(&self, req: SpawnRequest) {
        self.requests.lock().unwrap().push(req);
    }

    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Drain accumulated notes (called once at termination).
    pub fn take_notes(&self) -> Vec<String> {
        std::mem::take(&mut *self.notes.lock().unwrap())
    }

    /// Drain accumulated spawn-requests (called once at termination).
    pub fn take_requests(&self) -> Vec<SpawnRequest> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

/// `note(text)` — the only fork→main channel. Shown live in the UI (via a
/// [`TurnEvent::ScheduleNote`]); enters main context only at loop termination,
/// bundled with the terminal result.
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
        "Surface a progress note to the human now; it reaches the main conversation only at loop end"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Send a short progress note to the human while you run inside a background loop. The \
             note is shown to the user live, but it does NOT enter the main conversation until \
             the loop finishes — at which point your notes are bundled with the final result. \
             Use it to report what each iteration found or did. This is your only channel back \
             to the main conversation from inside a fork; you cannot start new scheduled work from here."
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

    fn defensive_parameters(&self) -> Option<Value> {
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
        // Live UI signal (never enters main context here — token economy).
        let _ = self.turn_tx.try_send(TurnEvent::ScheduleNote {
            job_id: self.state.own_job_id.clone(),
            text: text.clone(),
        });
        self.state.push_note(text);
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
        SCHEDULE_DESCRIPTION
    }

    fn defensive_description(&self) -> Option<String> {
        Some(SCHEDULE_DESCRIPTION_DEFENSIVE.to_string())
    }

    fn parameters(&self) -> Value {
        schedule_parameters()
    }

    fn defensive_parameters(&self) -> Option<Value> {
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
                self.state.push_request(SpawnRequest::Loop(parsed));
                Ok(ToolOutput::text(format!(
                    "request recorded — a fork cannot spawn scheduled work; the main agent will decide whether to start `{summary}`"
                )))
            }
            ScheduleAction::BackgroundStart => {
                let parsed = parse_background_start(&action_args)?;
                let summary = SpawnRequest::Background(parsed.clone()).summary();
                self.state.push_request(SpawnRequest::Background(parsed));
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
            serde_json::to_string(&toolbox.definitions(crate::config::extended::LlmMode::Normal))
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
            let after = serde_json::to_string(
                &toolbox.definitions(crate::config::extended::LlmMode::Normal),
            )
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

    /// The `schedule` description must name every action plus that action's
    /// required `args` field(s), so the model is never pointed at a field
    /// `spec.rs`'s parser rejects. This catches drift between the
    /// description hints and the parser at `cargo test` time. The
    /// `(action, &[required fields])` table mirrors the required-vs-optional
    /// contract in `crate::engine::schedule::spec`.
    #[test]
    fn description_documents_each_action_and_required_fields() {
        // Required fields per action, matching `spec.rs` exactly:
        //   loop.start       → prompt, interval
        //   loop.cancel      → job_id
        //   background.start → command
        //   background.tail  → job_id
        //   background.cancel→ job_id
        //   list             → (none)
        let contract: &[(&str, &[&str])] = &[
            ("loop.start", &["prompt", "interval"]),
            ("loop.cancel", &["job_id"]),
            ("background.start", &["command"]),
            ("background.tail", &["job_id"]),
            ("background.cancel", &["job_id"]),
            ("list", &[]),
        ];
        for (action, required) in contract {
            assert!(
                SCHEDULE_DESCRIPTION.contains(action),
                "`schedule` description must name action `{action}`"
            );
            for field in *required {
                assert!(
                    SCHEDULE_DESCRIPTION.contains(field),
                    "`schedule` description must name `{action}`'s required field `{field}`"
                );
            }
        }
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
        let ctx = test_ctx();
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

    #[tokio::test]
    async fn fork_schedule_cancel_sets_flag() {
        let state = Arc::new(ForkScheduleState::new("sched-abc".into()));
        let tool = ForkScheduleTool::new(state.clone());
        let ctx = test_ctx();
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
        let ctx = test_ctx();
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
        let ctx = test_ctx();
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

    /// Minimal `ToolCtx` for unit-testing fork tools (they don't touch the
    /// session / locks / cwd).
    fn test_ctx() -> ToolCtx {
        crate::tools::common::test_ctx(std::path::Path::new("/"))
    }
}
