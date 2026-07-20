//! TUI ↔ daemon glue.
//!
//! Phase 4 of the daemon migration: the TUI no longer owns the
//! engine. Instead [`try_spawn`] probes (or auto-promotes) the daemon
//! via [`cockpit_core::daemon::client`], attaches a session at the cwd, and
//! pipes the per-tick event stream from the daemon's broadcast back
//! to the TUI in the same `Arc<Mutex<Vec<TurnEvent>>>` shape the rest
//! of `app.rs` already consumes. The wire-shape of events is
//! [`cockpit_core::daemon::proto::Event`]; we translate to [`TurnEvent`] at
//! the boundary so the TUI rendering paths don't need to know they
//! talk to a daemon.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, RwLock, mpsc, oneshot};
use tokio::task::JoinHandle;
use uuid::Uuid;

use cockpit_core::daemon::client::{DaemonClient, LifecycleMode, probe_or_spawn};
use cockpit_core::daemon::image_upload::upload_submission_images;
use cockpit_core::daemon::proto::{self, ErrorCode, Request, Response};
use cockpit_core::engine::{
    ControlRequestId, ControlRequestNotDelivered, ControlRequestOutcome, TurnEvent,
};

/// The three 30-day autocomplete count maps fetched at session start.
/// `models` and `slash` are global; `tags` is scoped to this session's
/// project. Empty when the daemon predates `GetUsageCounts`.
#[derive(Default, Clone)]
pub struct UsageCounts {
    pub models: HashMap<String, u64>,
    pub slash: HashMap<String, u64>,
    pub tags: HashMap<String, u64>,
}

/// Handle the TUI keeps to talk to the engine (now via the daemon).
pub struct AttachedRequest {
    pub request: Request,
    pub response_tx: oneshot::Sender<Result<Response, String>>,
}

pub struct ControlRequest {
    pub request: Request,
    pub response_tx: oneshot::Sender<Result<Response, String>>,
}

pub struct AgentRunner {
    /// Send user submissions here (text + any pasted image parts). Each
    /// becomes one `SendUserMessage` request; the daemon's queue-folding
    /// (GOALS §1c) is performed inside the worker, not here.
    pub input_tx: mpsc::Sender<cockpit_core::engine::message::UserSubmission>,
    /// Fire-and-forget `RecordUsage` requests (autocomplete tally).
    pub record_tx: mpsc::Sender<Request>,
    /// Response-bearing control requests from TUI commands. Kept separate
    /// from telemetry so a full usage queue cannot block control-plane state.
    pub control_tx: mpsc::Sender<ControlRequest>,
    /// Response-bearing requests sent over the already-attached daemon client.
    pub attached_request_tx: mpsc::Sender<AttachedRequest>,
    /// Drained per tick into [`crate::tui::app::App::history`].
    pub events: Arc<Mutex<Vec<TurnEvent>>>,
    pub(crate) event_notify: Arc<Notify>,
    /// Name of whoever's currently on top of the agent stack. The
    /// chrome reads this for the active-agent slot (GOALS §1a).
    pub active_agent: Arc<Mutex<String>>,
    /// Root primary plus any active interactive subagent path. Depth one is
    /// the current runtime behavior, but a vector avoids baking that into
    /// the footer model.
    pub active_agent_path: Arc<Mutex<Vec<String>>>,
    /// Names in the daemon's conditionally filtered skill inventory for the
    /// exact foreground toolbox. `None` until the first attached refresh.
    pub skill_inventory_names: Arc<Mutex<Option<std::collections::HashSet<String>>>>,
    /// Queue-edit foreground target from the attach snapshot. Live updates
    /// arrive as `TurnEvent::ForegroundInputTarget`.
    pub foreground_target: Option<cockpit_core::engine::message::QueueTarget>,
    /// Authoritative active-model snapshot from `Attach`, used to seed chrome
    /// before any later live active-model event arrives.
    pub active_model_state: Option<proto::ActiveModelState>,
    /// This session's full id. Shown in the startup graphic and printed on
    /// exit (session-id-display-and-lazy-persist). Assigned by the daemon at
    /// attach, before the `sessions` row is persisted.
    pub(crate) session_id_state: Arc<Mutex<uuid::Uuid>>,
    /// This session's 6-char display id (GOALS §17b). The TUI captures
    /// it as the predecessor short-id when this session spawns a
    /// `/compact` handoff, so the fresh session can draw a "compacted
    /// from <short-id>" boundary marker.
    pub short_id: String,
    /// This session's project id — the scope for `tag` usage records.
    pub project_id: String,
    /// Frequency counts fetched at attach; the TUI seeds its in-memory
    /// maps from these once.
    pub usage: UsageCounts,
    /// `true` when this TUI *spawned* the daemon it's attached to (the
    /// daemonless `AlwaysEphemeral` path) and therefore owns its teardown
    /// — the app builds an [`cockpit_core::daemon::ephemeral_guard::EphemeralDaemonGuard`]
    /// from this. `false` when it attached to a pre-existing (canonical or
    /// auto-promoted persistent) daemon, which it must never stop.
    pub owns_daemon: bool,
    /// The socket of the daemon this runner is attached to. Carried so an
    /// owned ephemeral daemon can be reaped on exit via the guard.
    pub socket: PathBuf,
    /// The daemon's chronological history snapshot for the attached session
    /// (implementation note). On a `/sessions` resume the
    /// app converts these wire entries into TUI `HistoryEntry` rows so the
    /// full prior transcript renders; empty for a freshly-created session.
    pub history: Vec<proto::HistoryEntry>,
    /// Durable work paused during daemon shutdown for this session. Non-empty
    /// only after reattaching to a session that needs an explicit resume/cancel
    /// decision.
    pub paused_work: Vec<proto::PausedWorkSummary>,
    /// Responses resume repair state, when the daemon opened the session
    /// read-only because provider replay cannot be rebuilt safely.
    pub repair_required: Option<proto::ResumeRepairState>,
    /// Live `/btw` fork advertised by the daemon when attaching to a parent
    /// session. The TUI may attach a second runner to this session id for the
    /// side pane; the main runner remains bound to the parent.
    pub btw_fork: Option<proto::BtwForkInfo>,
    /// Version advertised by the daemon at attach.
    pub daemon_version: String,
    /// Whether this client is compatible with the daemon protocol/version.
    pub daemon_compatible: bool,
    pub(crate) current_client: Option<Arc<RwLock<DaemonClient>>>,
    pub(crate) attach_context: Option<Arc<RwLock<AttachRequestContext>>>,
    pub(crate) last_applied_seq: Option<Arc<Mutex<Option<i64>>>>,
    /// Client-side forwarding/event tasks owned by this runner. Dropping a TUI
    /// runner must only tear down this socket-side plumbing; daemon-side
    /// session work keeps running until an explicit daemon request stops it.
    pub(crate) client_tasks: ClientTasks,
}

#[derive(Default)]
pub(crate) struct ClientTasks {
    handles: Vec<JoinHandle<()>>,
}

impl ClientTasks {
    fn push(&mut self, handle: JoinHandle<()>) {
        self.handles.push(handle);
    }

    fn shutdown(&mut self) {
        for handle in self.handles.drain(..) {
            handle.abort();
        }
    }
}

impl Drop for ClientTasks {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl AgentRunner {
    /// Stop this runner's socket-side client tasks. This intentionally sends no
    /// daemon request: abandoning a TUI handle must not cancel or discard the
    /// daemon-owned session.
    pub fn shutdown(&mut self) {
        self.client_tasks.shutdown();
    }

    pub fn event_notifier(&self) -> Arc<Notify> {
        Arc::clone(&self.event_notify)
    }

    pub fn session_id(&self) -> uuid::Uuid {
        *self
            .session_id_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set_session_id(&self, session_id: uuid::Uuid) {
        *self
            .session_id_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = session_id;
    }

    pub fn can_switch_session(&self) -> bool {
        self.current_client.is_some()
            && self.attach_context.is_some()
            && self.last_applied_seq.is_some()
    }

    pub fn switch_session_task(
        &self,
        target: SessionTarget,
    ) -> impl std::future::Future<Output = Result<SessionSwitchOutcome, String>> + Send + 'static
    {
        let current_client = self.current_client.clone();
        let attach_context = self.attach_context.clone();
        let last_applied_seq = self.last_applied_seq.clone();
        let session_id_state = Arc::clone(&self.session_id_state);
        let active_agent = Arc::clone(&self.active_agent);
        let active_agent_path = Arc::clone(&self.active_agent_path);
        async move {
            let Some(current_client) = current_client else {
                return Err("runner has no attached daemon client".to_string());
            };
            let Some(attach_context) = attach_context else {
                return Err("runner has no attach context".to_string());
            };
            let Some(last_applied_seq) = last_applied_seq else {
                return Err("runner has no session sequence state".to_string());
            };
            switch_session_inner(
                current_client,
                attach_context,
                last_applied_seq,
                session_id_state,
                active_agent,
                active_agent_path,
                target,
            )
            .await
        }
    }
}

fn push_turn_event(events: &Arc<Mutex<Vec<TurnEvent>>>, notify: &Arc<Notify>, event: TurnEvent) {
    let mut guard = events
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.push(event);
    notify.notify_one();
}

pub(crate) fn drain_turn_events(events: &Arc<Mutex<Vec<TurnEvent>>>) -> Vec<TurnEvent> {
    let mut guard = events
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::mem::take(&mut *guard)
}

#[derive(Clone)]
pub(crate) struct AttachRequestContext {
    project_root: String,
    no_sandbox: bool,
    env_snapshot: cockpit_core::env_snapshot::EnvSnapshotWire,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTarget {
    New,
    Resume {
        session_id: Uuid,
        since_seq: Option<i64>,
    },
}

#[derive(Debug, Clone)]
pub struct SessionSwitchOutcome {
    pub session_id: Uuid,
    pub short_id: String,
    pub foreground_target: Option<cockpit_core::engine::message::QueueTarget>,
    pub active_model_state: Option<proto::ActiveModelState>,
    pub project_id: String,
    pub history: Vec<proto::HistoryEntry>,
    pub paused_work: Vec<proto::PausedWorkSummary>,
    pub repair_required: Option<proto::ResumeRepairState>,
    pub btw_fork: Option<proto::BtwForkInfo>,
}

#[derive(Clone)]
struct LocalReconnectDriver {
    socket: PathBuf,
}

impl LocalReconnectDriver {
    async fn connect(&self) -> Result<DaemonClient, anyhow::Error> {
        DaemonClient::connect(&self.socket).await
    }
}

struct IncomingEventContext<'a> {
    session_id: Uuid,
    events: &'a Arc<Mutex<Vec<TurnEvent>>>,
    event_notify: &'a Arc<Notify>,
    active_agent: &'a Arc<Mutex<String>>,
    active_agent_path: &'a Arc<Mutex<Vec<String>>>,
    primary_agent: &'a Arc<Mutex<String>>,
    last_applied_seq: &'a Arc<Mutex<Option<i64>>>,
}

trait JitterSource {
    fn next_millis(&mut self, inclusive_upper: u64) -> u64;
}

struct RandomJitter;

impl JitterSource for RandomJitter {
    fn next_millis(&mut self, inclusive_upper: u64) -> u64 {
        rand::random_range(0..=inclusive_upper)
    }
}

struct ReconnectBackoff<J = RandomJitter> {
    base: Duration,
    cap: Duration,
    current: Duration,
    jitter: J,
}

struct ReconnectAttach {
    client: DaemonClient,
    history: Vec<proto::HistoryEntry>,
    paused_work: Vec<proto::PausedWorkSummary>,
    repair_required: Option<proto::ResumeRepairState>,
}

enum ReconnectAttachError {
    Retriable(anyhow::Error),
    Terminal(String),
}

impl ReconnectBackoff<RandomJitter> {
    fn new() -> Self {
        Self::with_jitter(RandomJitter)
    }
}

impl<J: JitterSource> ReconnectBackoff<J> {
    fn with_jitter(jitter: J) -> Self {
        let base = Duration::from_millis(500);
        Self {
            base,
            cap: Duration::from_secs(30),
            current: base,
            jitter,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let max_millis = self.current.as_millis().min(u128::from(u64::MAX)) as u64;
        let jitter = Duration::from_millis(self.jitter.next_millis(max_millis));
        let delay = self.base.saturating_add(jitter).min(self.cap);
        self.current = self.current.saturating_mul(2).min(self.cap);
        delay
    }
}

fn history_entry_seq(entry: &proto::HistoryEntry) -> Option<i64> {
    match entry {
        proto::HistoryEntry::InterruptDecision { seq, .. }
        | proto::HistoryEntry::User { seq, .. }
        | proto::HistoryEntry::Assistant { seq, .. }
        | proto::HistoryEntry::ToolCall { seq, .. }
        | proto::HistoryEntry::InferenceError { seq, .. }
        | proto::HistoryEntry::CompactBoundary { seq, .. }
        | proto::HistoryEntry::Subagent { seq, .. } => (*seq > 0).then_some(*seq),
    }
}

fn event_persisted_seq(event: &proto::Event) -> Option<i64> {
    match event {
        proto::Event::AssistantText { seq, .. }
        | proto::Event::QueuedUserMessagesFolded { seq, .. }
        | proto::Event::InterruptResolved { seq, .. }
        | proto::Event::ToolEnd { seq, .. }
        | proto::Event::ToolError { seq, .. } => *seq,
        proto::Event::UserMessageRecorded { seq, .. } => Some(*seq),
        proto::Event::HistoryReplay { max_seq, .. } => Some(*max_seq),
        _ => None,
    }
}

fn update_last_applied_seq(last_applied_seq: &Arc<Mutex<Option<i64>>>, seq: i64) {
    let mut guard = last_applied_seq
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none_or(|last| seq > last) {
        *guard = Some(seq);
    }
}

fn current_last_applied_seq(last_applied_seq: &Arc<Mutex<Option<i64>>>) -> Option<i64> {
    *last_applied_seq
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn switch_session_inner(
    current_client: Arc<RwLock<DaemonClient>>,
    attach_context: Arc<RwLock<AttachRequestContext>>,
    last_applied_seq: Arc<Mutex<Option<i64>>>,
    session_id_state: Arc<Mutex<Uuid>>,
    active_agent: Arc<Mutex<String>>,
    active_agent_path: Arc<Mutex<Vec<String>>>,
    target: SessionTarget,
) -> Result<SessionSwitchOutcome, String> {
    let ctx = attach_context.read().await.clone();
    let (target_session_id, since_seq) = match target {
        SessionTarget::New => (None, None),
        SessionTarget::Resume {
            session_id,
            since_seq,
        } => (Some(session_id), since_seq),
    };
    let response = current_client
        .read()
        .await
        .clone()
        .request(Request::Attach {
            session_id: target_session_id,
            since_seq,
            project_root: Some(ctx.project_root.clone()),
            no_sandbox: ctx.no_sandbox,
            interactive: true,
            model_override: None,
            client_protocol_version: cockpit_core::daemon::proto::PROTOCOL_VERSION,
            env_snapshot: Some(ctx.env_snapshot.clone()),
            env_policy: cockpit_core::env_snapshot::EnvDriftPolicy::Client,
        })
        .await
        .map_err(|e| format!("attach: {e}"))?;
    match response {
        Ok(Response::Attached {
            session_id,
            short_id,
            active_agent: new_active_agent,
            active_agent_path: new_active_agent_path,
            foreground_target,
            active_model_state,
            project_id,
            history,
            paused_work,
            repair_required,
            btw_fork,
            ..
        }) => Ok(apply_session_switch_attached(
            SessionSwitchAttached {
                session_id,
                short_id,
                active_agent: new_active_agent,
                active_agent_path: new_active_agent_path,
                foreground_target,
                active_model_state,
                project_id,
                history,
                paused_work,
                repair_required: repair_required.map(|repair| *repair),
                btw_fork,
            },
            &session_id_state,
            &last_applied_seq,
            &active_agent,
            &active_agent_path,
        )),
        Ok(other) => Err(format!("unexpected attach response: {other:?}")),
        Err(error) if error.code == ErrorCode::ProtocolVersion => {
            Err(incompatible_protocol_chip().to_string())
        }
        Err(error) => Err(format!("attach: daemon error: {error}")),
    }
}

struct SessionSwitchAttached {
    session_id: Uuid,
    short_id: String,
    active_agent: String,
    active_agent_path: Vec<String>,
    foreground_target: Option<proto::QueueTarget>,
    active_model_state: Option<proto::ActiveModelState>,
    project_id: String,
    history: Vec<proto::HistoryEntry>,
    paused_work: Vec<proto::PausedWorkSummary>,
    repair_required: Option<proto::ResumeRepairState>,
    btw_fork: Option<proto::BtwForkInfo>,
}

fn apply_session_switch_attached(
    attached: SessionSwitchAttached,
    session_id_state: &Arc<Mutex<Uuid>>,
    last_applied_seq: &Arc<Mutex<Option<i64>>>,
    active_agent: &Arc<Mutex<String>>,
    active_agent_path: &Arc<Mutex<Vec<String>>>,
) -> SessionSwitchOutcome {
    *active_agent
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = attached.active_agent.clone();
    *active_agent_path
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = if attached.active_agent_path.is_empty()
    {
        vec![attached.active_agent]
    } else {
        attached.active_agent_path
    };
    *last_applied_seq
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        attached.history.iter().filter_map(history_entry_seq).max();
    *session_id_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = attached.session_id;
    SessionSwitchOutcome {
        session_id: attached.session_id,
        short_id: attached.short_id,
        foreground_target: attached.foreground_target.map(queue_target_from_proto),
        active_model_state: attached.active_model_state,
        project_id: attached.project_id,
        history: attached.history,
        paused_work: attached.paused_work,
        repair_required: attached.repair_required,
        btw_fork: attached.btw_fork,
    }
}

fn is_global_event(event: &proto::Event) -> bool {
    matches!(
        event,
        proto::Event::CaffeinateState { .. }
            | proto::Event::DaemonDraining { .. }
            | proto::Event::ConnectorStatus { .. }
            | proto::Event::LspNotice { .. }
            | proto::Event::EnvDriftWarning { .. }
            | proto::Event::InterruptRaised { .. }
            | proto::Event::InterruptResolved { .. }
            | proto::Event::InterruptQueueChanged { .. }
    )
}

impl Drop for AgentRunner {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Probe for the daemon (auto-promoting one if needed), attach a
/// fresh session at `cwd`, and return the runner handle.
///
/// Returns `Err(String)` instead of `anyhow::Error` so `app.rs` can
/// render the message in its fallback "input captured" stub without
/// having to format an anyhow chain.
pub fn try_spawn(cwd: &Path, no_sandbox: bool, mode: LifecycleMode) -> Result<AgentRunner, String> {
    try_spawn_inner(cwd, None, no_sandbox, mode)
}

/// Re-attach to an existing session by id (the `/compact` commit path,
/// T6.e). Same as [`try_spawn`] but resumes `session_id` instead of
/// creating a fresh one, so the TUI switches its event stream + input
/// channel onto the new compaction-handoff session. `no_sandbox` is
/// ignored by the daemon on resume (the session keeps its own state),
/// passed only to keep the attach shape uniform.
pub fn attach_to_session(
    cwd: &Path,
    session_id: uuid::Uuid,
    no_sandbox: bool,
    mode: LifecycleMode,
) -> Result<AgentRunner, String> {
    try_spawn_inner(cwd, Some(session_id), no_sandbox, mode)
}

fn try_spawn_inner(
    cwd: &Path,
    session_id: Option<uuid::Uuid>,
    no_sandbox: bool,
    mode: LifecycleMode,
) -> Result<AgentRunner, String> {
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| "no tokio runtime — cockpit must be invoked from main".to_string())?;

    // probe_or_spawn is async; we block the (async) caller on it so
    // try_spawn returns a fully-attached handle to the TUI. We're
    // already in a tokio context (`main` is `#[tokio::main]`), so we
    // use `block_in_place` to run a `block_on` without panicking.
    let attached = tokio::task::block_in_place(|| {
        runtime.block_on(async {
            let mut timer = cockpit_core::startup::PhaseTimer::start("agent_runner::try_spawn");
            let daemon = probe_or_spawn(mode)
                .await
                .map_err(|e| format!("daemon probe: {e}"))?;
            timer.phase("probe_or_spawn");
            let owns_daemon = daemon.owns_daemon;
            let socket = daemon.socket.clone();
            let project_root = cwd.to_string_lossy().into_owned();
            let (env_snapshot, _env_diagnostic) =
                cockpit_core::env_snapshot::capture_tui_shell_env();
            let attached = match daemon
                .client
                .request(Request::Attach {
                    session_id,
                    since_seq: None,
                    project_root: Some(project_root),
                    no_sandbox,
                    // The TUI can answer interrupts (approval / loop-guard /
                    // `question` prompts) — mark this attach interactive so
                    // the loop guard prompts here instead of auto-rejecting.
                    interactive: true,
                    // The interactive TUI uses the session's active model; the
                    // plan-level override is only for the headless plan-run
                    // path (`cockpit run --model`).
                    model_override: None,
                    client_protocol_version: cockpit_core::daemon::proto::PROTOCOL_VERSION,
                    env_snapshot: Some(env_snapshot.to_wire()),
                    env_policy: cockpit_core::env_snapshot::EnvDriftPolicy::Client,
                })
                .await
            {
                Ok(Ok(response)) => response,
                Ok(Err(error)) if error.code == ErrorCode::ProtocolVersion => {
                    return Err(incompatible_protocol_chip().to_string());
                }
                Ok(Err(error)) => return Err(format!("attach: daemon error: {error}")),
                Err(e) => return Err(format!("attach: {e}")),
            };
            let (
                session_id,
                short_id,
                active_agent_name,
                active_agent_path,
                foreground_target,
                active_model_state,
                project_id,
                history,
                paused_work,
                repair_required,
                btw_fork,
                daemon_version,
                daemon_compatible,
            ) = match attached {
                Response::Attached {
                    session_id,
                    short_id,
                    active_agent,
                    active_agent_path,
                    foreground_target,
                    active_model_state,
                    project_id,
                    history,
                    paused_work,
                    repair_required,
                    btw_fork,
                    daemon_version,
                    compatible,
                    ..
                } => (
                    session_id,
                    short_id,
                    active_agent,
                    active_agent_path,
                    foreground_target,
                    active_model_state,
                    project_id,
                    history,
                    paused_work,
                    repair_required.map(|repair| *repair),
                    btw_fork,
                    daemon_version,
                    compatible,
                ),
                other => return Err(format!("unexpected attach response: {other:?}")),
            };
            // Fetch the autocomplete frequency maps for this session's
            // project. Best-effort: a daemon that doesn't speak
            // `GetUsageCounts` just leaves the maps empty (no ranking).
            let usage = match daemon
                .client
                .request_ok(Request::GetUsageCounts {
                    project_id: Some(project_id.clone()),
                })
                .await
            {
                Ok(Response::UsageCounts {
                    models,
                    slash,
                    tags,
                }) => UsageCounts {
                    models,
                    slash,
                    tags,
                },
                _ => UsageCounts::default(),
            };
            let skill_inventory_names = match daemon
                .client
                .request_ok(Request::ListSkills {
                    project_root: cwd.to_string_lossy().into_owned(),
                })
                .await
            {
                Ok(Response::Skills { skills }) => Some(
                    skills
                        .into_iter()
                        .map(|skill| skill.name)
                        .collect::<std::collections::HashSet<_>>(),
                ),
                _ => None,
            };
            timer.phase("attach_and_usage");
            timer.done();
            Ok::<_, String>((
                daemon.client,
                session_id,
                short_id,
                active_agent_name,
                active_agent_path,
                foreground_target,
                active_model_state,
                project_id,
                usage,
                skill_inventory_names,
                owns_daemon,
                socket,
                history,
                paused_work,
                repair_required,
                btw_fork,
                daemon_version,
                daemon_compatible,
            ))
        })
    })?;
    let (
        client,
        session_id,
        short_id,
        initial_active_agent,
        active_agent_path,
        foreground_target,
        active_model_state,
        project_id,
        usage,
        initial_skill_names,
        owns_daemon,
        socket,
        history,
        paused_work,
        repair_required,
        btw_fork,
        daemon_version,
        daemon_compatible,
    ) = attached;

    let (input_tx, mut input_rx) =
        mpsc::channel::<cockpit_core::engine::message::UserSubmission>(32);
    let (record_tx, mut record_rx) = mpsc::channel::<Request>(32);
    let (control_tx, mut control_rx) = mpsc::channel::<ControlRequest>(32);
    let (attached_request_tx, mut attached_request_rx) = mpsc::channel::<AttachedRequest>(32);
    let events = Arc::new(Mutex::new(Vec::new()));
    let event_notify = Arc::new(Notify::new());
    let initial_active_agent_path = if active_agent_path.is_empty() {
        vec![initial_active_agent.clone()]
    } else {
        active_agent_path
    };
    let active_agent = Arc::new(Mutex::new(initial_active_agent));
    let active_agent_path = Arc::new(Mutex::new(initial_active_agent_path));
    let skill_inventory_names = Arc::new(Mutex::new(initial_skill_names));
    let last_applied_seq = Arc::new(Mutex::new(
        history.iter().filter_map(history_entry_seq).max(),
    ));
    let session_id_state = Arc::new(Mutex::new(session_id));
    let current_client = Arc::new(RwLock::new(client));
    let attach_context = Arc::new(RwLock::new(AttachRequestContext {
        project_root: cwd.to_string_lossy().into_owned(),
        no_sandbox,
        env_snapshot: cockpit_core::env_snapshot::capture_tui_shell_env()
            .0
            .to_wire(),
    }));
    let mut client_tasks = ClientTasks::default();

    // Outbound: TUI sends a submission (text + any image parts) → upload image
    // attachments first, then forward refs in SendUserMessage.
    {
        let current_client = current_client.clone();
        let events = events.clone();
        let event_notify = event_notify.clone();
        client_tasks.push(tokio::spawn(async move {
            while let Some(sub) = input_rx.recv().await {
                let client = current_client.read().await.clone();
                let refs = match upload_submission_images(&client, &sub.images).await {
                    Ok(refs) => refs,
                    Err(error) => {
                        push_turn_event(
                            &events,
                            &event_notify,
                            TurnEvent::UserMessageDispatchFailed {
                                error: error.to_string(),
                            },
                        );
                        continue;
                    }
                };
                match client
                    .request(Request::SendUserMessage {
                        text: sub.text,
                        display_text: sub.display_text,
                        tag_expansions: sub.tag_expansions,
                        image_refs: refs,
                        forced_skill: sub.forced_skill,
                    })
                    .await
                {
                    Ok(Ok(Response::UserMessageQueued { queue, .. })) => {
                        push_turn_event(
                            &events,
                            &event_notify,
                            TurnEvent::QueueUpdated {
                                queue: queue.into_iter().map(queue_item_from_proto).collect(),
                            },
                        );
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        push_turn_event(
                            &events,
                            &event_notify,
                            TurnEvent::UserMessageDispatchFailed { error: e.message },
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = ?e, "send_user_message transport failed");
                        push_turn_event(
                            &events,
                            &event_notify,
                            TurnEvent::UserMessageDispatchFailed {
                                error: e.to_string(),
                            },
                        );
                    }
                }
            }
        }));
    }

    // Outbound: fire-and-forget autocomplete usage records.
    {
        let current_client = current_client.clone();
        client_tasks.push(tokio::spawn(async move {
            while let Some(req) = record_rx.recv().await {
                let client = current_client.read().await.clone();
                if let Err(e) = client.request(req).await {
                    tracing::warn!(error = ?e, "record_usage transport failed");
                }
            }
        }));
    }

    // Outbound: response-bearing TUI control requests. They are isolated from
    // telemetry, so a saturated usage channel cannot drop operator commands.
    {
        let current_client = current_client.clone();
        client_tasks.push(tokio::spawn(async move {
            while let Some(control_request) = control_rx.recv().await {
                let client = current_client.read().await.clone();
                let response = client
                    .request_ok(control_request.request)
                    .await
                    .map_err(|e| format!("daemon request: {e}"));
                let _ = control_request.response_tx.send(response);
            }
        }));
    }

    // Outbound: response-bearing attached-session RPCs. These must use the
    // same daemon client that completed Attach because attachment is stored in
    // per-client daemon state, not in the socket path.
    {
        let current_client = current_client.clone();
        client_tasks.push(tokio::spawn(async move {
            while let Some(attached_request) = attached_request_rx.recv().await {
                let client = current_client.read().await.clone();
                let response = client
                    .request_ok(attached_request.request)
                    .await
                    .map_err(|e| format!("daemon request: {e}"));
                let _ = attached_request.response_tx.send(response);
            }
        }));
    }

    // Inbound: daemon events → translate → push into the shared
    // buffer and update active-agent tracker.
    {
        let events = events.clone();
        let event_notify = event_notify.clone();
        let active_agent = active_agent.clone();
        let active_agent_path = active_agent_path.clone();
        let skill_inventory_names = skill_inventory_names.clone();
        let current_client = current_client.clone();
        let last_applied_seq = last_applied_seq.clone();
        let attach_context = attach_context.clone();
        let session_id_state = session_id_state.clone();
        let driver = LocalReconnectDriver {
            socket: socket.clone(),
        };
        // The current primary (root-frame) agent, tracked so a subagent pop
        // returns the active-agent slot to the right primary after a `/plan`
        // or `/build` swap (not a hardcoded `Build`). Seeded from the
        // attach-time active agent.
        let primary_agent = Arc::new(Mutex::new(
            active_agent_path
                .lock()
                .unwrap()
                .first()
                .cloned()
                .unwrap_or_else(|| active_agent.lock().unwrap().clone()),
        ));
        client_tasks.push(tokio::spawn(async move {
            let mut saw_draining = false;
            loop {
                let client = current_client.read().await.clone();
                while let Some(event) = client.next_event().await {
                    let refresh_skill_inventory = matches!(
                        &event,
                        proto::Event::PrimarySwapped { .. }
                            | proto::Event::ForegroundInputTarget { .. }
                            | proto::Event::AgentIdle { .. }
                    );
                    if matches!(event, proto::Event::DaemonDraining { .. }) {
                        saw_draining = true;
                    } else if saw_draining {
                        saw_draining = false;
                    }
                    let session_id = *session_id_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let incoming = IncomingEventContext {
                        session_id,
                        events: &events,
                        event_notify: &event_notify,
                        active_agent: &active_agent,
                        active_agent_path: &active_agent_path,
                        primary_agent: &primary_agent,
                        last_applied_seq: &last_applied_seq,
                    };
                    let project_root = attach_context.read().await.project_root.clone();
                    if refresh_skill_inventory
                        && let Ok(Response::Skills { skills }) = client
                            .request_ok(Request::ListSkills { project_root })
                            .await
                    {
                        *skill_inventory_names.lock().unwrap() = Some(
                            skills
                                .into_iter()
                                .map(|skill| skill.name)
                                .collect::<std::collections::HashSet<_>>(),
                        );
                    }
                    apply_incoming_event(event, &incoming);
                }
                if !client.is_socket_backed() {
                    return;
                }

                let mut attempt = 1;
                push_turn_event(
                    &events,
                    &event_notify,
                    TurnEvent::DaemonLinkReconnecting {
                        restarting: saw_draining,
                        attempt,
                    },
                );
                let mut backoff = ReconnectBackoff::new();
                loop {
                    tokio::time::sleep(backoff.next_delay()).await;
                    let attach_snapshot = attach_context.read().await.clone();
                    let session_id = *session_id_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    match reconnect_and_attach(
                        &driver,
                        session_id,
                        &attach_snapshot,
                        &last_applied_seq,
                    )
                    .await
                    {
                        Ok(attached) => {
                            let incoming = IncomingEventContext {
                                session_id,
                                events: &events,
                                event_notify: &event_notify,
                                active_agent: &active_agent,
                                active_agent_path: &active_agent_path,
                                primary_agent: &primary_agent,
                                last_applied_seq: &last_applied_seq,
                            };
                            let new_client = apply_reconnect_attached(attached, &incoming);
                            *current_client.write().await = new_client;
                            saw_draining = false;
                            push_turn_event(
                                &events,
                                &event_notify,
                                TurnEvent::DaemonLinkReconnected,
                            );
                            break;
                        }
                        Err(ReconnectAttachError::Retriable(error)) => {
                            tracing::debug!(error = ?error, attempt, "daemon reconnect failed");
                            attempt = attempt.saturating_add(1);
                            push_turn_event(
                                &events,
                                &event_notify,
                                TurnEvent::DaemonLinkReconnecting {
                                    restarting: saw_draining,
                                    attempt,
                                },
                            );
                        }
                        Err(ReconnectAttachError::Terminal(error)) => {
                            tracing::warn!(%error, "daemon reconnect attach stopped");
                            push_turn_event(
                                &events,
                                &event_notify,
                                TurnEvent::DaemonLinkTerminal { error },
                            );
                            return;
                        }
                    }
                }
            }
        }));
    }

    Ok(AgentRunner {
        input_tx,
        record_tx,
        control_tx,
        attached_request_tx,
        events,
        event_notify,
        active_agent,
        active_agent_path,
        skill_inventory_names,
        foreground_target: foreground_target.map(queue_target_from_proto),
        active_model_state,
        session_id_state,
        short_id,
        project_id,
        usage,
        owns_daemon,
        socket,
        history,
        paused_work,
        repair_required,
        btw_fork,
        daemon_version,
        daemon_compatible,
        current_client: Some(current_client),
        attach_context: Some(attach_context),
        last_applied_seq: Some(last_applied_seq),
        client_tasks,
    })
}

pub(crate) fn incompatible_protocol_chip() -> &'static str {
    "daemon speaks an incompatible protocol; relaunch / upgrade cockpit"
}

pub fn send_control_request(
    control_tx: &mpsc::Sender<ControlRequest>,
    events: &Arc<Mutex<Vec<TurnEvent>>>,
    event_notify: &Arc<Notify>,
    request_id: ControlRequestId,
    req: Request,
) -> Result<(), ControlRequestNotDelivered> {
    let (response_tx, response_rx) = oneshot::channel();
    match control_tx.try_send(ControlRequest {
        request: req,
        response_tx,
    }) {
        Ok(()) => {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let events = events.clone();
                let event_notify = event_notify.clone();
                handle.spawn(async move {
                    let outcome = match response_rx.await {
                        Ok(Ok(Response::Ack)) => ControlRequestOutcome::Applied,
                        Ok(Ok(other)) => ControlRequestOutcome::Rejected(format!(
                            "unexpected daemon response: {other:?}"
                        )),
                        Ok(Err(error)) => ControlRequestOutcome::Rejected(error),
                        Err(_) => ControlRequestOutcome::NotDelivered(
                            ControlRequestNotDelivered::RunnerTeardown,
                        ),
                    };
                    push_turn_event(
                        &events,
                        &event_notify,
                        TurnEvent::ControlRequestFinished {
                            request_id,
                            outcome,
                        },
                    );
                });
            }
            Ok(())
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            Err(ControlRequestNotDelivered::ChannelFull)
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            Err(ControlRequestNotDelivered::ChannelClosed)
        }
    }
}

/// Pre-flight sizing for the fresh-chat context indicator (Feature 1).
/// `file` is the basename of the matched guidance file (`None` when the
/// project has none); `guidance_tokens` is its body size (the `… in
/// <file>` label); `system_tokens` is the composed system prompt
/// (role prompt + OS + session).
#[derive(Debug, Clone)]
pub struct GuidanceEstimate {
    pub file: Option<String>,
    pub guidance_tokens: u64,
    pub system_tokens: u64,
    pub model_instruction_tokens: u64,
}

/// Resolve the fresh-chat sizing for `cwd` and the active model. Prefers
/// an already-running daemon's calibrated estimate (no attach, no spawn —
/// calling it at launch never creates a session); on any miss (no daemon,
/// connect/request error, or the daemon couldn't answer) it falls back to
/// a local raw-cl100k computation via [`cockpit_core::engine::builtin`]. The two
/// modes may differ by the calibration factor; each is the best available
/// for its mode. Best-effort and non-blocking for launch.
pub async fn fetch_guidance_estimate_with_socket(
    cwd: &Path,
    provider: Option<String>,
    model: Option<String>,
    socket: Option<std::path::PathBuf>,
) -> GuidanceEstimate {
    if let Some(socket) = socket
        && let Some(est) =
            daemon_guidance_estimate_at_socket(cwd, provider.clone(), model.clone(), &socket).await
    {
        return est;
    }
    local_guidance_estimate(cwd, provider.as_deref(), model.as_deref())
}

/// Ask an already-running daemon for the calibrated estimate. Returns
/// `None` on any failure (no daemon, transport error, or a malformed
/// response) so the caller can fall back to the local computation.
async fn daemon_guidance_estimate_at_socket(
    cwd: &Path,
    provider: Option<String>,
    model: Option<String>,
    socket: &Path,
) -> Option<GuidanceEstimate> {
    let client = cockpit_core::daemon::client::DaemonClient::connect(socket)
        .await
        .ok()?;
    let resp = client
        .request_ok(Request::GuidanceEstimate {
            project_root: cwd.to_string_lossy().into_owned(),
            provider,
            model,
        })
        .await
        .ok()?;
    match resp {
        Response::GuidanceEstimate {
            file,
            tokens,
            system_tokens,
            model_instruction_tokens,
        } => Some(GuidanceEstimate {
            file,
            guidance_tokens: tokens,
            system_tokens,
            model_instruction_tokens,
        }),
        _ => None,
    }
}

/// Daemonless fallback: size the guidance file body and the full composed
/// system prompt in-process with raw cl100k (`cockpit_core::tokens::count`).
/// Cheap and synchronous — `load_agent_guidance` only stats/reads one
/// small file along the cwd→git-root walk — so it never blocks launch.
fn local_guidance_estimate(
    cwd: &Path,
    provider: Option<&str>,
    model: Option<&str>,
) -> GuidanceEstimate {
    let file = cockpit_core::engine::builtin::load_agent_guidance(cwd).map(|(path, body)| {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        (name, cockpit_core::tokens::count(&body) as u64)
    });
    // No session exists yet at the fresh-chat indicator, so the system
    // prompt omits the `Session:` line — matching what the engine sends.
    let system_prompt = cockpit_core::engine::builtin::default_chat_system_prompt(cwd, "");
    let system_tokens = cockpit_core::tokens::count(&system_prompt) as u64;
    let model_instruction_tokens = provider
        .zip(model)
        .and_then(|(provider, model)| {
            let cfg = cockpit_core::secret_ref::load_effective(cwd);
            cfg.resolve_model_system_prompt(provider, model)
                .map(|prompt| cockpit_core::tokens::count(prompt) as u64)
        })
        .unwrap_or(0);
    match file {
        Some((name, guidance_tokens)) => GuidanceEstimate {
            file: Some(name),
            guidance_tokens,
            system_tokens,
            model_instruction_tokens,
        },
        None => GuidanceEstimate {
            file: None,
            guidance_tokens: 0,
            system_tokens,
            model_instruction_tokens,
        },
    }
}

/// Run one request-response RPC over the runner's already-attached daemon
/// client. Unlike socket helpers, this preserves daemon-side per-client
/// attached session state.
pub fn attached_request_tx_blocking(
    attached_request_tx: mpsc::Sender<AttachedRequest>,
    req: Request,
) -> Result<Response, String> {
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| "no tokio runtime".to_string())?;
    tokio::task::block_in_place(|| {
        runtime.block_on(async move {
            let (response_tx, response_rx) = oneshot::channel();
            attached_request_tx
                .send(AttachedRequest {
                    request: req,
                    response_tx,
                })
                .await
                .map_err(|_| "daemon client task has stopped".to_string())?;
            response_rx
                .await
                .map_err(|_| "daemon client dropped reply channel".to_string())?
        })
    })
}

/// Run one blocking daemon request against an already-running daemon and
/// return the typed response. Connects only — never spawns — so the
/// `/sessions` browser degrades gracefully (no live data, no DB writes,
/// no crash) when the daemon isn't up. Mirrors `try_spawn_inner`'s
/// `block_in_place` pattern so it's callable from the synchronous TUI
/// key handlers. `Err(String)` for any transport/typed failure.
pub fn daemon_request_blocking(req: Request) -> Result<Response, String> {
    use cockpit_core::daemon::{DaemonStatus, discover};
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| "no tokio runtime".to_string())?;
    tokio::task::block_in_place(|| {
        runtime.block_on(async {
            let probe = discover().await;
            if !matches!(probe.status, DaemonStatus::Running) {
                return Err("daemon not running".to_string());
            }
            let client = cockpit_core::daemon::client::DaemonClient::connect(&probe.paths.socket)
                .await
                .map_err(|e| format!("daemon connect: {e}"))?;
            client
                .request_ok(req)
                .await
                .map_err(|e| format!("daemon request: {e}"))
        })
    })
}

/// Run one blocking request against the daemon at a *known* `socket` —
/// the socket the attached [`AgentRunner`] is already bound to. Unlike
/// [`daemon_request_blocking`], this never re-resolves the canonical path,
/// so it reaches an owned pid+nonce ephemeral daemon (the daemonless and
/// auto-spawn paths) whose socket env is set only in the daemon child, not
/// in this client process. Connects only — never spawns. `Err(String)` on
/// any transport/typed failure.
pub fn daemon_request_at_blocking(socket: &Path, req: Request) -> Result<Response, String> {
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| "no tokio runtime".to_string())?;
    let socket = socket.to_path_buf();
    tokio::task::block_in_place(|| {
        runtime.block_on(async {
            let client = cockpit_core::daemon::client::DaemonClient::connect(&socket)
                .await
                .map_err(|e| format!("daemon connect: {e}"))?;
            client
                .request_ok(req)
                .await
                .map_err(|e| format!("daemon request: {e}"))
        })
    })
}

/// Run one request-response RPC against the daemon at `socket`. Unlike
/// [`daemon_request_blocking`] (which probes the *canonical* daemon paths),
/// this targets a specific socket — the one the live runner is attached to.
/// That matters in daemonless mode, where the runner owns a pid+nonce
/// ephemeral daemon the canonical paths don't point at.
fn request_on_socket(socket: &Path, req: Request) -> Result<Response, String> {
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| "no tokio runtime".to_string())?;
    let socket = socket.to_path_buf();
    tokio::task::block_in_place(|| {
        runtime.block_on(async {
            let client = cockpit_core::daemon::client::DaemonClient::connect(&socket)
                .await
                .map_err(|e| format!("daemon connect: {e}"))?;
            client
                .request_ok(req)
                .await
                .map_err(|e| format!("daemon request: {e}"))
        })
    })
}

/// Fork `parent_session_id` at its tail into a fresh session on the daemon
/// at `socket`, returning `(session_id, short_id)`. `ephemeral` marks it a
/// throwaway `/side` side-conversation fork (excluded from lists, never
/// auto-titled, discarded on end/exit).
pub fn fork_session_blocking(
    socket: &Path,
    parent_session_id: uuid::Uuid,
    fork_point_turn_id: Option<String>,
    ephemeral: bool,
) -> Result<(uuid::Uuid, String), String> {
    match request_on_socket(
        socket,
        Request::ForkSession {
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
        },
    )? {
        Response::Forked {
            session_id,
            short_id,
            ..
        } => Ok((session_id, short_id)),
        other => Err(format!("unexpected fork response: {other:?}")),
    }
}

/// Discard an ephemeral side-conversation (`/side`) on the daemon at
/// `socket`: stops its worker and deletes its row + descendant forks. A
/// non-ephemeral session is left untouched (daemon-side guard).
pub fn discard_session_blocking(socket: &Path, session_id: uuid::Uuid) -> Result<(), String> {
    match request_on_socket(socket, Request::DiscardSession { session_id })? {
        Response::Ack => Ok(()),
        other => Err(format!("unexpected discard response: {other:?}")),
    }
}

/// List sessions for the `/sessions` browser. `project_id = Some(p)` +
/// `parent = None` → root sessions in `p`; `parent = Some(s)` → direct
/// forks of `s`; both `None` → every open session (all-projects scope).
pub fn list_sessions_blocking(
    socket: &Path,
    project_id: Option<String>,
    parent_session_id: Option<uuid::Uuid>,
) -> Result<Vec<proto::SessionSummary>, String> {
    match daemon_request_at_blocking(
        socket,
        Request::ListSessions {
            project_id,
            parent_session_id,
        },
    )? {
        Response::Sessions { sessions } => Ok(sessions),
        other => Err(format!("unexpected list_sessions response: {other:?}")),
    }
}

pub fn read_session_messages_blocking(
    socket: &Path,
    session_id: uuid::Uuid,
    before_seq: Option<i64>,
    limit: u32,
) -> Result<(Vec<proto::SessionMessage>, bool), String> {
    match daemon_request_at_blocking(
        socket,
        Request::ReadSessionMessages {
            session_id,
            before_seq,
            limit,
        },
    )? {
        Response::SessionMessages {
            session_id: got,
            messages,
            has_more,
        } if got == session_id => Ok((messages, has_more)),
        other => Err(format!(
            "unexpected read_session_messages response: {other:?}"
        )),
    }
}

pub fn resource_snapshot_blocking() -> Result<proto::Response, String> {
    match daemon_request_blocking(Request::ResourceSnapshot)? {
        response @ Response::ResourceSnapshot { .. } => Ok(response),
        other => Err(format!("unexpected resource_snapshot response: {other:?}")),
    }
}

pub fn promote_resource_blocking(
    request_id: String,
    session_id: Option<uuid::Uuid>,
) -> Result<proto::Response, String> {
    match daemon_request_blocking(Request::PromoteResource {
        request_id,
        session_id,
    })? {
        response @ Response::PromoteResourceResult { .. } => Ok(response),
        other => Err(format!("unexpected promote_resource response: {other:?}")),
    }
}

/// Fetch live `(has_active_schedules, processing)` status for the candidate
/// session ids. Daemon down / no live worker → empty map; callers treat
/// absent ids as not-processing / no-jobs.
pub fn session_live_status_blocking(
    socket: &Path,
    session_ids: Vec<uuid::Uuid>,
) -> std::collections::HashMap<uuid::Uuid, (bool, bool)> {
    match daemon_request_at_blocking(socket, Request::SessionLiveStatus { session_ids }) {
        Ok(Response::SessionLiveStatus { statuses }) => statuses
            .into_iter()
            .map(|s| (s.session_id, (s.has_active_schedules, s.processing)))
            .collect(),
        _ => std::collections::HashMap::new(),
    }
}

fn update_active_agent(
    event: &proto::Event,
    slot: &Arc<Mutex<String>>,
    path: &Arc<Mutex<Vec<String>>>,
    primary: &Arc<Mutex<String>>,
) {
    match event {
        proto::Event::PrimarySwapped { name, .. } => {
            // The root-frame primary changed (`/plan` ↔ `/build`). Track it
            // and, since a swap only happens at idle (no subagent on top),
            // reflect it in the live slot immediately.
            *primary.lock().unwrap() = name.clone();
            *slot.lock().unwrap() = name.clone();
            *path.lock().unwrap() = vec![name.clone()];
        }
        proto::Event::SubagentSpawned { parent, child, .. } => {
            *slot.lock().unwrap() = child.clone();
            let mut path = path.lock().unwrap();
            if let Some(parent_idx) = path.iter().position(|name| name == parent) {
                path.truncate(parent_idx + 1);
            } else {
                path.clear();
                path.push(primary.lock().unwrap().clone());
            }
            path.push(child.clone());
        }
        proto::Event::SubagentReport { agent, .. } => {
            // Pop back to the current primary. v1 supports a depth-1 stack
            // (`Build`/`Plan` → one subagent); deeper trees need a proper
            // stack to track properly.
            *slot.lock().unwrap() = primary.lock().unwrap().clone();
            let mut path = path.lock().unwrap();
            if let Some(agent_idx) = path.iter().position(|name| name == agent) {
                path.truncate(agent_idx);
            } else {
                path.pop();
            }
            if path.is_empty() {
                path.push(primary.lock().unwrap().clone());
            }
        }
        proto::Event::AgentIdle { .. } => {
            let primary = primary.lock().unwrap().clone();
            *slot.lock().unwrap() = primary.clone();
            *path.lock().unwrap() = vec![primary];
        }
        _ => {}
    }
}

fn event_session(event: &proto::Event) -> Option<uuid::Uuid> {
    use proto::Event::*;
    Some(match event {
        ConfigSnapshot { snapshot } => snapshot.session_id,
        ThinkingStarted { session_id, .. }
        | QueueUpdated { session_id, .. }
        | ForegroundInputTarget { session_id, .. }
        | ActiveModelState { session_id, .. }
        | Reconnecting { session_id, .. }
        | AssistantTextDelta { session_id, .. }
        | ReasoningDelta { session_id, .. }
        | AssistantText { session_id, .. }
        | UserMessageRecorded { session_id, .. }
        | QueuedUserMessagesFolded { session_id, .. }
        | SessionPersistFailed { session_id, .. }
        | SessionDriverFailed { session_id, .. }
        | PreflightStarted { session_id, .. }
        | UserMessageRetracted { session_id, .. }
        | Notice { session_id, .. }
        | SkillAutoInjected { session_id, .. }
        | ToolStart { session_id, .. }
        | ToolEnd { session_id, .. }
        | ResourceWait { session_id, .. }
        | ResourceStart { session_id, .. }
        | ResourceClear { session_id, .. }
        | ToolError { session_id, .. }
        | InferenceFailed { session_id, .. }
        | InferenceSucceeded { session_id, .. }
        | InferenceWarning { session_id, .. }
        | BackupUsed { session_id, .. }
        | SubagentSpawned { session_id, .. }
        | SubagentRouting { session_id, .. }
        | SubagentReport { session_id, .. }
        | NestedTurn { session_id, .. }
        | Usage { session_id, .. }
        | InterruptRaised { session_id, .. }
        | InterruptResolved { session_id, .. }
        | HistoryReplay { session_id, .. }
        | InterruptQueueChanged { session_id, .. }
        | AgentIdle { session_id, .. }
        | PrimarySwapped { session_id, .. }
        | LlmModeChanged { session_id, .. }
        | SessionEnded { session_id, .. }
        | ScheduleStarted { session_id, .. }
        | ScheduleProgress { session_id, .. }
        | ScheduleNote { session_id, .. }
        | ScheduleCompleted { session_id, .. }
        | ContextProjection { session_id, .. }
        | Pruned { session_id, .. }
        | CompactReady { session_id, .. }
        | SandboxState { session_id, .. }
        | SandboxEscalationState { session_id, .. }
        | SandboxUnavailable { session_id, .. }
        | RedactionState { session_id, .. }
        | PreflightState { session_id, .. }
        | TrustedOnlyState { session_id, .. }
        | ApprovalModeState { session_id, .. }
        | DelegationRecursionState { session_id, .. }
        | TandemState { session_id, .. }
        | GitignoreAllow { session_id, .. }
        | PausedWorkAvailable { session_id, .. }
        | WaitingForLock { session_id, .. } => *session_id,
        // Daemon-global events carry no session_id: they reach every
        // client regardless of attachment.
        CaffeinateState { .. }
        | DaemonDraining { .. }
        | ConnectorStatus { .. }
        | TerminalOutput { .. }
        | TerminalClipboard { .. }
        | TerminalViewers { .. }
        | TerminalClosed { .. }
        | LspNotice { .. }
        | EnvDriftWarning { .. } => return None,
    })
}

async fn reconnect_and_attach(
    driver: &LocalReconnectDriver,
    session_id: uuid::Uuid,
    attach_context: &AttachRequestContext,
    last_applied_seq: &Arc<Mutex<Option<i64>>>,
) -> Result<ReconnectAttach, ReconnectAttachError> {
    let client = driver
        .connect()
        .await
        .map_err(ReconnectAttachError::Retriable)?;
    let response = client
        .request(Request::Attach {
            session_id: Some(session_id),
            since_seq: current_last_applied_seq(last_applied_seq),
            project_root: Some(attach_context.project_root.clone()),
            no_sandbox: attach_context.no_sandbox,
            interactive: true,
            model_override: None,
            client_protocol_version: cockpit_core::daemon::proto::PROTOCOL_VERSION,
            env_snapshot: Some(attach_context.env_snapshot.clone()),
            env_policy: cockpit_core::env_snapshot::EnvDriftPolicy::Client,
        })
        .await
        .map_err(ReconnectAttachError::Retriable)?;
    match response {
        Ok(Response::Attached {
            history,
            paused_work,
            repair_required,
            ..
        }) => Ok(ReconnectAttach {
            client,
            history,
            paused_work,
            repair_required: repair_required.map(|repair| *repair),
        }),
        Ok(other) => Err(ReconnectAttachError::Terminal(format!(
            "reconnect attach returned unexpected response: {other:?}"
        ))),
        Err(error) => {
            let prefix = if error.code == ErrorCode::UnknownSession {
                "session no longer exists"
            } else {
                "daemon rejected reconnect attach"
            };
            Err(ReconnectAttachError::Terminal(format!("{prefix}: {error}")))
        }
    }
}

fn apply_reconnect_attached(
    attached: ReconnectAttach,
    ctx: &IncomingEventContext<'_>,
) -> DaemonClient {
    if let Some(repair) = attached.repair_required {
        push_turn_event(
            ctx.events,
            ctx.event_notify,
            TurnEvent::ResumeRepairRequired { state: repair },
        );
    }
    if !attached.paused_work.is_empty() {
        push_turn_event(
            ctx.events,
            ctx.event_notify,
            TurnEvent::PausedWorkAvailable {
                session_id: ctx.session_id,
                items: attached.paused_work,
            },
        );
    }
    if !attached.history.is_empty() {
        let max_seq = attached.history.iter().filter_map(history_entry_seq).max();
        if let Some(max_seq) = max_seq {
            apply_incoming_event(
                proto::Event::HistoryReplay {
                    session_id: ctx.session_id,
                    entries: attached.history,
                    max_seq,
                },
                ctx,
            );
        } else {
            push_turn_event(
                ctx.events,
                ctx.event_notify,
                TurnEvent::HistoryReplay {
                    entries: attached.history,
                },
            );
        }
    }
    attached.client
}

fn apply_incoming_event(event: proto::Event, ctx: &IncomingEventContext<'_>) {
    // Daemon-global events carry no session_id and must reach this client
    // regardless of which session it's attached to.
    if !is_global_event(&event) && event_session(&event) != Some(ctx.session_id) {
        return;
    }
    let event_session_id = event_session(&event);

    if let proto::Event::HistoryReplay {
        entries, max_seq, ..
    } = event
    {
        let last = current_last_applied_seq(ctx.last_applied_seq);
        if last.is_some_and(|last| max_seq <= last) {
            return;
        }
        let entries: Vec<_> = entries
            .into_iter()
            .filter(|entry| {
                history_entry_seq(entry).is_none_or(|seq| last.is_none_or(|last| seq > last))
            })
            .collect();
        if entries.is_empty() {
            return;
        }
        let applied_max_seq = entries
            .iter()
            .filter_map(history_entry_seq)
            .max()
            .unwrap_or(max_seq);
        update_last_applied_seq(ctx.last_applied_seq, applied_max_seq);
        push_turn_event(
            ctx.events,
            ctx.event_notify,
            TurnEvent::HistoryReplay { entries },
        );
        return;
    }

    if event_session_id == Some(ctx.session_id)
        && let Some(seq) = event_persisted_seq(&event)
    {
        if current_last_applied_seq(ctx.last_applied_seq).is_some_and(|last| seq <= last) {
            return;
        }
        update_last_applied_seq(ctx.last_applied_seq, seq);
    }

    update_active_agent(
        &event,
        ctx.active_agent,
        ctx.active_agent_path,
        ctx.primary_agent,
    );
    if let Some(translated) = proto_event_to_turn_event(event) {
        push_turn_event(ctx.events, ctx.event_notify, translated);
    }
}

fn proto_event_to_turn_event(event: proto::Event) -> Option<TurnEvent> {
    use proto::Event::*;
    Some(match event {
        ThinkingStarted { agent, turn_id, .. } => TurnEvent::ThinkingStarted { agent, turn_id },
        Reconnecting {
            agent,
            attempt,
            provider,
            model,
            url,
            ..
        } => TurnEvent::Reconnecting {
            agent,
            attempt,
            provider,
            model,
            url,
        },
        HistoryReplay { entries, .. } => TurnEvent::HistoryReplay { entries },
        InferenceWarning {
            agent,
            provider,
            model,
            phase,
            waited_secs,
            ..
        } => TurnEvent::InferenceWarning {
            agent,
            provider,
            model,
            phase,
            waited_secs,
        },
        AssistantTextDelta { agent, delta, .. } => TurnEvent::AssistantTextDelta { agent, delta },
        ReasoningDelta { agent, delta, .. } => TurnEvent::ReasoningDelta { agent, delta },
        AssistantText {
            agent,
            text,
            reasoning,
            seq,
            ..
        } => TurnEvent::AssistantText {
            agent,
            text,
            reasoning,
            seq,
        },
        UserMessageRecorded {
            seq,
            preflight_cleaned,
            ..
        } => TurnEvent::UserMessageRecorded {
            seq,
            preflight_cleaned,
        },
        QueuedUserMessagesFolded {
            text,
            display_text,
            tag_expansions,
            queue_item_ids,
            target,
            seq,
            preflight_cleaned,
            ..
        } => TurnEvent::QueuedUserMessagesFolded {
            text,
            display_text,
            tag_expansions,
            queue_item_ids,
            target: queue_target_from_proto(target),
            seq,
            preflight_cleaned,
        },
        ForegroundInputTarget { target, .. } => TurnEvent::ForegroundInputTarget {
            target: queue_target_from_proto(target),
        },
        ActiveModelState {
            provider,
            model,
            config_provider,
            config_model,
            diverged,
            generation,
            ..
        } => TurnEvent::ActiveModelState {
            provider,
            model,
            config_provider,
            config_model,
            diverged,
            generation,
        },
        SessionPersistFailed { error, .. } => TurnEvent::SessionPersistFailed { error },
        SessionDriverFailed { error, .. } => TurnEvent::SessionDriverFailed { error },
        PreflightStarted { .. } => TurnEvent::PreflightStarted,
        UserMessageRetracted { .. } => TurnEvent::UserMessageRetracted,
        Notice { text, .. } | LspNotice { text } => TurnEvent::Notice { text },
        EnvDriftWarning { diff, policy, .. } => TurnEvent::Notice {
            text: format!(
                "environment differs from daemon baseline (policy: {policy:?}; {} added, {} removed, {} changed keys)",
                diff.added_keys, diff.removed_keys, diff.changed_keys
            ),
        },
        SkillAutoInjected { name, reason, .. } => TurnEvent::SkillAutoInjected { name, reason },
        ToolStart {
            agent,
            call_id,
            tool,
            args,
            ..
        } => TurnEvent::ToolStart {
            agent,
            call_id,
            tool,
            args,
        },
        ToolEnd {
            agent,
            call_id,
            tool,
            output,
            truncated,
            seq,
            hint,
            ..
        } => TurnEvent::ToolEnd {
            agent,
            call_id,
            tool,
            output,
            truncated,
            seq,
            hint,
        },
        ResourceWait {
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
            ..
        } => TurnEvent::ResourceWait {
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
        },
        ResourceStart {
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
            ..
        } => TurnEvent::ResourceStart {
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
        },
        ResourceClear {
            agent,
            request_id,
            display_id,
            resources,
            command_label,
            ..
        } => TurnEvent::ResourceClear {
            agent,
            request_id,
            display_id,
            resources,
            command_label,
        },
        ToolError {
            agent,
            call_id,
            tool,
            error,
            kind,
            seq,
            ..
        } => TurnEvent::ToolError {
            agent,
            call_id,
            tool,
            error,
            kind,
            seq,
        },
        InferenceFailed {
            agent,
            provider,
            model,
            error_class,
            detail,
            auth_failure,
            ..
        } => TurnEvent::InferenceFailed {
            agent,
            provider,
            model,
            error_class,
            detail,
            auth_failure,
        },
        InferenceSucceeded {
            provider, model, ..
        } => TurnEvent::InferenceSucceeded { provider, model },
        BackupUsed {
            agent,
            primary_model,
            error_class,
            backup_model,
            ..
        } => TurnEvent::BackupUsed {
            agent,
            primary_model,
            error_class,
            backup_model,
        },
        SubagentSpawned {
            parent,
            child,
            task_call_id,
            label,
            prompt,
            requested_cwd,
            resolved_cwd,
            trusted_only,
            model_trusted,
            routing,
            ..
        } => TurnEvent::SubagentSpawned {
            parent,
            child,
            task_call_id,
            label,
            prompt,
            requested_cwd,
            resolved_cwd,
            trusted_only,
            model_trusted,
            routing,
        },
        SubagentRouting {
            task_call_id,
            label,
            child,
            provider,
            model,
            trusted_only,
            model_trusted,
            routing,
            ..
        } => TurnEvent::SubagentRouting {
            task_call_id,
            label,
            child,
            provider,
            model,
            trusted_only,
            model_trusted,
            routing,
        },
        SubagentReport {
            agent,
            task_call_id,
            label,
            report,
            failed,
            trusted_only,
            model_trusted,
            routing,
            ..
        } => TurnEvent::SubagentReport {
            agent,
            task_call_id,
            label,
            report,
            failed,
            trusted_only,
            model_trusted,
            routing,
        },
        NestedTurn {
            task_call_id,
            label,
            parent_task_call_id,
            inner,
            ..
        } => {
            let inner = proto_event_to_turn_event(*inner)?;
            TurnEvent::NestedTurn {
                task_call_id,
                label,
                parent_task_call_id,
                inner: Box::new(inner),
            }
        }
        Usage {
            agent,
            input_tokens,
            output_tokens,
            cached_input_tokens,
            cache_creation_input_tokens,
            ..
        } => TurnEvent::Usage {
            agent,
            usage: cockpit_core::tokens::TokenUsage {
                input_tokens,
                output_tokens,
                cached_input_tokens,
                cache_creation_input_tokens,
            },
        },
        AgentIdle {
            turn_id, reason, ..
        } => TurnEvent::AgentIdle { turn_id, reason },
        PausedWorkAvailable {
            session_id, items, ..
        } => TurnEvent::PausedWorkAvailable { session_id, items },
        ScheduleStarted {
            session_id,
            job_id,
            label,
            kind,
        } => TurnEvent::ScheduleStarted {
            session_id,
            job_id,
            label,
            kind,
        },
        ScheduleProgress { job_id, .. } => TurnEvent::ScheduleProgress { job_id },
        ScheduleNote { job_id, text, .. } => TurnEvent::ScheduleNote { job_id, text },
        ScheduleCompleted {
            job_id,
            label,
            kind,
            failed,
            ..
        } => TurnEvent::ScheduleCompleted {
            job_id,
            label,
            kind,
            failed,
        },
        ContextProjection {
            prunable_tokens,
            cache_cold,
            ..
        } => TurnEvent::ContextProjection {
            prunable_tokens,
            cache_cold,
        },
        Pruned {
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
            ..
        } => TurnEvent::Pruned {
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
        },
        CompactReady {
            new_session_id,
            handoff,
            brief,
            source,
            trigger_ctx_pct,
            tokens_before,
            tokens_after,
            turns_summarized,
            tail_kept,
            tail_trimmed,
            seed_tool_count,
            seed_tool_tokens,
            ..
        } => TurnEvent::CompactReady {
            new_session_id,
            handoff,
            brief,
            source,
            trigger_ctx_pct,
            tokens_before,
            tokens_after,
            turns_summarized,
            tail_kept,
            tail_trimmed,
            seed_tool_count,
            seed_tool_tokens,
        },
        // A question-tool interrupt (GOALS §3b) carries a question batch;
        // surface it so the TUI opens the answering dialog. A bare
        // `InterruptRaised` with no batch (the `schedule` needs-attention
        // nudge) has no dialog and stays a no-op here. `InterruptResolved`
        // is translated below so attention surfaces can clear even for
        // background sessions.
        InterruptRaised {
            session_id,
            interrupt_id,
            description,
            questions: Some(questions),
            pending_count,
            reason,
            ..
        } => TurnEvent::InterruptRaised {
            session_id,
            interrupt_id,
            description,
            questions,
            pending_count,
            reason,
        },
        InterruptQueueChanged {
            session_id,
            active_interrupt_id,
            pending_count,
            ..
        } => TurnEvent::InterruptQueueChanged {
            session_id,
            active_interrupt_id,
            pending_count,
        },
        SandboxState {
            mode,
            container_network_enabled,
            container_availability,
            ..
        } => TurnEvent::SandboxState {
            mode,
            container_network_enabled,
            container_availability,
        },
        SandboxEscalationState { enabled, .. } => TurnEvent::SandboxEscalationState { enabled },
        SandboxUnavailable {
            remedy,
            fix_command,
            ..
        } => TurnEvent::SandboxUnavailable {
            remedy,
            fix_command,
        },
        RedactionState {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
            ..
        } => TurnEvent::RedactionState {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
        },
        PreflightState { enabled, .. } => TurnEvent::PreflightState { enabled },
        TrustedOnlyState { enabled, .. } => TurnEvent::TrustedOnlyState { enabled },
        ApprovalModeState { mode, .. } => TurnEvent::ApprovalModeState { mode },
        DelegationRecursionState {
            enabled,
            default_depth,
            ..
        } => TurnEvent::DelegationRecursionState {
            enabled,
            default_depth,
        },
        TandemState {
            models, warning, ..
        } => TurnEvent::TandemState { models, warning },
        GitignoreAllow { allow, .. } => TurnEvent::GitignoreAllow { allow },
        CaffeinateState {
            active,
            lid_close_guaranteed,
            message,
        } => TurnEvent::CaffeinateState {
            active,
            lid_close_guaranteed,
            message,
        },
        ConnectorStatus {
            enabled,
            status,
            relay_url,
            relay_id,
            relay_region,
            last_error,
        } => TurnEvent::ConnectorStatus {
            enabled,
            status,
            relay_url,
            relay_id,
            relay_region,
            last_error,
        },
        DaemonDraining { forced } => TurnEvent::DaemonDraining { forced },
        // The blocked-`readlock` waiting indicator
        // (`readlock-wait-and-lock-expiry.md`): surfaced so the app's chrome
        // shows/clears the transient "waiting for lock" indicator.
        WaitingForLock {
            path,
            holder_agent,
            waiting,
            ..
        } => TurnEvent::WaitingForLock {
            path,
            holder_agent,
            waiting,
        },
        QueueUpdated { queue, .. } => TurnEvent::QueueUpdated {
            queue: queue.into_iter().map(queue_item_from_proto).collect(),
        },
        InterruptResolved {
            session_id,
            interrupt_id,
            decision: Some(decision),
            seq,
            ..
        } => TurnEvent::InterruptDecision {
            session_id,
            interrupt_id,
            decision,
            seq,
        },
        InterruptResolved {
            session_id,
            interrupt_id,
            decision: None,
            ..
        } => TurnEvent::InterruptResolved {
            session_id,
            interrupt_id,
        },
        InterruptRaised { .. }
        | ConfigSnapshot { .. }
        | SessionEnded { .. }
        | TerminalOutput { .. }
        | TerminalClipboard { .. }
        | TerminalViewers { .. }
        | TerminalClosed { .. } => return None,
        // The chrome's active-agent slot is updated directly in
        // `update_active_agent`; the swap needs no history-stream entry.
        PrimarySwapped { .. } => return None,
        // The live `/llm-mode` switch: surfaced to the app so it tracks the
        // authoritative current mode (its `/llm-mode` toggle + cache-break
        // warning resolve against it).
        LlmModeChanged { mode, .. } => TurnEvent::LlmModeChanged { mode },
    })
}

fn queue_item_from_proto(
    item: proto::QueueItem,
) -> cockpit_core::engine::message::QueuedUserMessage {
    cockpit_core::engine::message::QueuedUserMessage {
        id: item.id,
        status: match item.status {
            proto::QueueItemStatus::Queued => {
                cockpit_core::engine::message::QueueItemStatus::Queued
            }
            proto::QueueItemStatus::Folding => {
                cockpit_core::engine::message::QueueItemStatus::Folding
            }
        },
        text: item.text,
        display_text: item.display_text,
        target: queue_target_from_proto(item.target),
    }
}

fn queue_target_from_proto(
    target: proto::QueueTarget,
) -> cockpit_core::engine::message::QueueTarget {
    cockpit_core::engine::message::QueueTarget {
        id: target.id,
        agent: target.agent,
        depth: target.depth,
        task_call_id: target.task_call_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[test]
    fn protocol_version_attach_error_uses_incompatible_chip() {
        let chip = incompatible_protocol_chip();
        assert_eq!(
            chip,
            "daemon speaks an incompatible protocol; relaunch / upgrade cockpit"
        );
        assert!(!chip.contains("unexpected attach response"));
    }

    /// Daemonless / pre-spawn resolution: the local fallback (the only
    /// source feeding the fresh-chat indicator before any daemon exists)
    /// must detect a guidance file sitting in `cwd` and report its basename
    /// plus a non-zero body size. `AGENTS.md` is in the shipped default
    /// `agent_guidance_files`, so this resolves regardless of any host
    /// override that only *adds* names (e.g. `project guidance`). Pins the
    /// no-daemon launch state against silent regression.
    #[test]
    fn local_guidance_estimate_detects_file_in_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "PROJECT RULES\nmore lines\n").unwrap();

        let est = local_guidance_estimate(tmp.path(), None, None);
        assert_eq!(
            est.file.as_deref(),
            Some("AGENTS.md"),
            "local fallback must detect the guidance file by basename"
        );
        assert!(
            est.guidance_tokens > 0,
            "a non-empty guidance body must size to a non-zero token count"
        );
        // The full composed system prompt is always non-empty (role prompt +
        // identity lines), so the baseline the running estimate folds in is
        // never zero — the refresh-on-connect adopt-guard relies on this.
        assert!(
            est.system_tokens > 0,
            "system prompt baseline must be non-zero"
        );
    }

    /// No guidance file present anywhere on the walk: the local fallback
    /// reports `file = None` (the indicator falls through to the usual
    /// context form) while still sizing the system-prompt baseline. Walks
    /// from a tempdir that has no `AGENTS.md`/`project guidance`.
    #[test]
    fn local_guidance_estimate_none_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("empty-project");
        std::fs::create_dir(&sub).unwrap();

        let est = local_guidance_estimate(&sub, None, None);
        assert!(
            est.file.is_none(),
            "no guidance file should resolve to None"
        );
        assert_eq!(est.guidance_tokens, 0);
        assert!(est.system_tokens > 0);
    }

    fn runner_with_client_task(handle: JoinHandle<()>) -> AgentRunner {
        runner_with_client_task_and_events(handle, Arc::new(Mutex::new(Vec::new())))
    }

    fn runner_with_client_task_and_events(
        handle: JoinHandle<()>,
        events: Arc<Mutex<Vec<TurnEvent>>>,
    ) -> AgentRunner {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let (record_tx, _record_rx) = mpsc::channel(1);
        let (control_tx, _control_rx) = mpsc::channel(1);
        let (attached_request_tx, _attached_request_rx) = mpsc::channel(1);
        let mut client_tasks = ClientTasks::default();
        client_tasks.push(handle);
        AgentRunner {
            input_tx,
            record_tx,
            control_tx,
            attached_request_tx,
            events,
            event_notify: Arc::new(Notify::new()),
            active_agent: Arc::new(Mutex::new("Build".to_string())),
            active_agent_path: Arc::new(Mutex::new(vec!["Build".to_string()])),
            skill_inventory_names: Arc::new(Mutex::new(None)),
            foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
            active_model_state: None,
            session_id_state: Arc::new(Mutex::new(uuid::Uuid::new_v4())),
            short_id: "abc123".to_string(),
            project_id: "project".to_string(),
            usage: UsageCounts::default(),
            owns_daemon: false,
            socket: PathBuf::from("/tmp/cockpit-test.sock"),
            history: Vec::new(),
            paused_work: Vec::new(),
            repair_required: None,
            btw_fork: None,
            daemon_version: "test".to_string(),
            daemon_compatible: true,
            current_client: None,
            attach_context: None,
            last_applied_seq: None,
            client_tasks,
        }
    }

    async fn assert_task_future_dropped(dropped: Arc<AtomicBool>) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("runner drop should abort and drop client task futures");
    }

    #[tokio::test]
    async fn dropping_agent_runner_aborts_client_tasks() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(dropped.clone());
        let handle = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });

        let runner = runner_with_client_task(handle);
        drop(runner);

        assert_task_future_dropped(dropped).await;
    }

    #[tokio::test]
    async fn dropping_agent_runner_stops_late_event_buffer_writes() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let task_events = events.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            task_events.lock().unwrap().push(TurnEvent::Notice {
                text: "late".into(),
            });
        });

        let runner = runner_with_client_task_and_events(handle, events.clone());
        drop(runner);
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(
            events.lock().unwrap().is_empty(),
            "aborted client task must not append late events after runner drop"
        );
    }

    #[test]
    fn agent_runner_switch_session_replaces_session_id_in_place() {
        let old_session_id = uuid::Uuid::new_v4();
        let new_session_id = uuid::Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(old_session_id));
        let last_applied_seq = Arc::new(Mutex::new(Some(2)));
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let history = vec![proto::HistoryEntry::Assistant {
            agent: "Plan".to_string(),
            text: "restored".to_string(),
            reasoning: String::new(),
            ts_ms: 0,
            seq: 7,
        }];

        let outcome = apply_session_switch_attached(
            SessionSwitchAttached {
                session_id: new_session_id,
                short_id: "def456".to_string(),
                active_agent: "Plan".to_string(),
                active_agent_path: Vec::new(),
                foreground_target: None,
                active_model_state: None,
                project_id: "new-project".to_string(),
                history,
                paused_work: Vec::new(),
                repair_required: None,
                btw_fork: None,
            },
            &session_id_state,
            &last_applied_seq,
            &active_agent,
            &active_agent_path,
        );

        assert_eq!(
            *session_id_state.lock().unwrap(),
            new_session_id,
            "switch must replace the live session id in place"
        );
        assert_eq!(outcome.session_id, new_session_id);
        assert_eq!(outcome.short_id, "def456");
        assert_eq!(outcome.project_id, "new-project");
        assert_eq!(&*active_agent.lock().unwrap(), "Plan");
        assert_eq!(
            &*active_agent_path.lock().unwrap(),
            &vec!["Plan".to_string()]
        );
        assert_eq!(*last_applied_seq.lock().unwrap(), Some(7));
    }

    #[test]
    fn proto_lifecycle_turn_id_maps_to_turn_events() {
        let session_id = uuid::Uuid::new_v4();

        let event = proto_event_to_turn_event(proto::Event::ThinkingStarted {
            session_id,
            agent: "Build".to_string(),
            turn_id: Some("turn-1".to_string()),
        })
        .expect("thinking event maps");
        assert!(matches!(
            event,
            TurnEvent::ThinkingStarted {
                agent,
                turn_id: Some(turn_id),
            } if agent == "Build" && turn_id == "turn-1"
        ));

        let event = proto_event_to_turn_event(proto::Event::AgentIdle {
            session_id,
            turn_id: Some("turn-1".to_string()),
            reason: cockpit_core::engine::IdleReason::Completed,
        })
        .expect("idle event maps");
        assert!(matches!(
            event,
            TurnEvent::AgentIdle {
                turn_id: Some(turn_id),
                reason: cockpit_core::engine::IdleReason::Completed,
            } if turn_id == "turn-1"
        ));
    }

    #[test]
    fn nested_turn_event_routes_and_decodes() {
        let sid = uuid::Uuid::new_v4();
        let event = proto::Event::NestedTurn {
            session_id: sid,
            task_call_id: "task-1".into(),
            label: "default".into(),
            parent_task_call_id: Some("parent-task".into()),
            inner: Box::new(proto::Event::ReasoningDelta {
                session_id: sid,
                agent: "Explore".into(),
                delta: "thinking".into(),
            }),
        };
        assert_eq!(event_session(&event), Some(sid));
        match proto_event_to_turn_event(event) {
            Some(TurnEvent::NestedTurn {
                task_call_id,
                label,
                parent_task_call_id,
                inner,
            }) => {
                assert_eq!(task_call_id, "task-1");
                assert_eq!(label, "default");
                assert_eq!(parent_task_call_id.as_deref(), Some("parent-task"));
                assert!(matches!(
                    inner.as_ref(),
                    TurnEvent::ReasoningDelta { agent, delta }
                        if agent == "Explore" && delta == "thinking"
                ));
            }
            other => panic!("expected nested turn event, got {other:?}"),
        }
    }

    #[test]
    fn subagent_routing_amend_roundtrips_through_agent_runner() {
        let sid = uuid::Uuid::new_v4();
        let routing = serde_json::json!({
            "provider": "test-provider",
            "resolved_model": "child-model",
            "fallback_decision": "backup",
        });
        let event = proto::Event::SubagentRouting {
            session_id: sid,
            task_call_id: "task-1".into(),
            label: "second".into(),
            child: "explore".into(),
            provider: "test-provider".into(),
            model: "child-model".into(),
            trusted_only: true,
            model_trusted: false,
            routing: routing.clone(),
        };

        assert_eq!(event_session(&event), Some(sid));
        match proto_event_to_turn_event(event) {
            Some(TurnEvent::SubagentRouting {
                task_call_id,
                label,
                child,
                provider,
                model,
                trusted_only,
                model_trusted,
                routing: actual_routing,
            }) => {
                assert_eq!(task_call_id, "task-1");
                assert_eq!(label, "second");
                assert_eq!(child, "explore");
                assert_eq!(provider, "test-provider");
                assert_eq!(model, "child-model");
                assert!(trusted_only);
                assert!(!model_trusted);
                assert_eq!(actual_routing, routing);
            }
            other => panic!("expected subagent routing amend, got {other:?}"),
        }
    }

    #[test]
    fn daemon_global_events_bypass_session_filter_and_translate() {
        let draining = proto::Event::DaemonDraining { forced: true };
        assert!(event_session(&draining).is_none());
        assert!(is_global_event(&draining));
        assert!(matches!(
            proto_event_to_turn_event(draining),
            Some(TurnEvent::DaemonDraining { forced: true })
        ));

        let meta = cockpit_core::env_snapshot::EnvSnapshotMeta {
            source: cockpit_core::env_snapshot::EnvSnapshotSource::DaemonStart,
            digest: "digest".into(),
            key_count: 3,
            path_entry_count: 1,
        };
        let drift = cockpit_core::env_snapshot::EnvDiffSummary {
            baseline_digest: "base".into(),
            candidate_digest: "candidate".into(),
            added_keys: 1,
            removed_keys: 2,
            changed_keys: 3,
            changed_secret_keys: vec!["TOKEN".into()],
            path_added: Vec::new(),
            path_removed: Vec::new(),
        };
        let warning = proto::Event::EnvDriftWarning {
            baseline: meta.clone(),
            candidate: meta,
            diff: drift,
            policy: cockpit_core::env_snapshot::EnvDriftPolicy::Daemon,
        };
        assert!(event_session(&warning).is_none());
        assert!(is_global_event(&warning));
        match proto_event_to_turn_event(warning) {
            Some(TurnEvent::Notice { text }) => {
                assert!(text.contains("environment differs"), "{text}");
                assert!(text.contains("1 added, 2 removed, 3 changed"), "{text}");
            }
            other => panic!("expected env drift notice, got {other:?}"),
        }
    }

    #[test]
    fn since_seq_replay_and_live_tool_events_are_seq_idempotent() {
        let sid = uuid::Uuid::new_v4();
        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let primary_agent = Arc::new(Mutex::new("Build".to_string()));
        let last = Arc::new(Mutex::new(Some(5)));
        let incoming = IncomingEventContext {
            session_id: sid,
            events: &events,
            event_notify: &notify,
            active_agent: &active_agent,
            active_agent_path: &active_agent_path,
            primary_agent: &primary_agent,
            last_applied_seq: &last,
        };

        apply_incoming_event(
            proto::Event::AssistantText {
                session_id: sid,
                agent: "Build".to_string(),
                text: "duplicate".to_string(),
                reasoning: String::new(),
                seq: Some(5),
            },
            &incoming,
        );
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(current_last_applied_seq(&last), Some(5));

        apply_incoming_event(
            proto::Event::HistoryReplay {
                session_id: sid,
                max_seq: 7,
                entries: vec![
                    proto::HistoryEntry::ToolCall {
                        seq: 6,
                        agent: "Build".to_string(),
                        call_id: "tool-1".to_string(),
                        parent_call_id: None,
                        parent_child_index: None,
                        tool: "read".to_string(),
                        mcp_server: None,
                        mcp_builtin: None,
                        mcp_kind: None,
                        original_input: serde_json::json!({"path": "src/lib.rs"}),
                        wire_input: serde_json::json!({"path": "src/lib.rs"}),
                        recovery_kind: None,
                        recovery_stage: None,
                        output: "body".to_string(),
                        hard_fail: false,
                        truncated: false,
                        hint: None,
                    },
                    proto::HistoryEntry::Assistant {
                        agent: "Build".to_string(),
                        text: "replayed".to_string(),
                        reasoning: String::new(),
                        ts_ms: 0,
                        seq: 7,
                    },
                ],
            },
            &incoming,
        );
        assert_eq!(current_last_applied_seq(&last), Some(7));

        apply_incoming_event(
            proto::Event::ToolEnd {
                session_id: sid,
                agent: "Build".to_string(),
                call_id: "tool-1".to_string(),
                tool: "read".to_string(),
                output: "overlap".to_string(),
                truncated: false,
                seq: Some(7),
                hint: None,
            },
            &incoming,
        );
        assert_eq!(events.lock().unwrap().len(), 1);

        apply_incoming_event(
            proto::Event::ToolEnd {
                session_id: sid,
                agent: "Build".to_string(),
                call_id: "tool-2".to_string(),
                tool: "bash".to_string(),
                output: "live".to_string(),
                truncated: false,
                seq: Some(8),
                hint: None,
            },
            &incoming,
        );

        let drained = drain_turn_events(&events);
        assert_eq!(drained.len(), 2);
        assert!(matches!(drained[0], TurnEvent::HistoryReplay { .. }));
        assert!(matches!(
            &drained[1],
            TurnEvent::ToolEnd {
                output,
                seq: Some(8),
                ..
            } if output == "live"
        ));
        assert_eq!(current_last_applied_seq(&last), Some(8));
    }

    struct FixedJitter {
        values: std::collections::VecDeque<u64>,
        seen_upper_bounds: Vec<u64>,
    }

    impl JitterSource for FixedJitter {
        fn next_millis(&mut self, inclusive_upper: u64) -> u64 {
            self.seen_upper_bounds.push(inclusive_upper);
            self.values.pop_front().unwrap_or(inclusive_upper)
        }
    }

    #[test]
    fn reconnect_backoff_uses_injected_jitter_rising_floor_and_cap() {
        let jitter = FixedJitter {
            values: [0, 500, 1_500, 60_000].into(),
            seen_upper_bounds: Vec::new(),
        };
        let mut backoff = ReconnectBackoff::with_jitter(jitter);

        assert_eq!(backoff.next_delay(), Duration::from_millis(500));
        assert_eq!(backoff.next_delay(), Duration::from_millis(1_000));
        assert_eq!(backoff.next_delay(), Duration::from_millis(2_000));
        assert_eq!(backoff.next_delay(), Duration::from_secs(30));
        assert_eq!(
            backoff.jitter.seen_upper_bounds,
            vec![500, 1_000, 2_000, 4_000]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn push_turn_event_notifies_waiter_without_timer() {
        use std::future::{Future, poll_fn};
        use std::pin::Pin;
        use std::task::Poll;

        async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
            poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let mut notified = Box::pin(notify.notified());

        assert!(matches!(poll_once(notified.as_mut()).await, Poll::Pending));
        push_turn_event(
            &events,
            &notify,
            TurnEvent::Notice {
                text: "wake now".into(),
            },
        );

        assert!(matches!(
            poll_once(notified.as_mut()).await,
            Poll::Ready(())
        ));
        assert_eq!(events.lock().unwrap().len(), 1);
    }

    #[test]
    fn turn_event_buffer_push_and_drain_recover_from_poison() {
        let events = Arc::new(Mutex::new(vec![TurnEvent::Notice {
            text: "before".into(),
        }]));
        let poison_events = events.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison_events.lock().unwrap();
            panic!("poison event buffer");
        })
        .join();

        push_turn_event(
            &events,
            &Arc::new(Notify::new()),
            TurnEvent::Notice {
                text: "after".into(),
            },
        );
        let drained = drain_turn_events(&events);

        assert_eq!(drained.len(), 2);
        assert!(matches!(&drained[0], TurnEvent::Notice { text } if text == "before"));
        assert!(matches!(&drained[1], TurnEvent::Notice { text } if text == "after"));
        assert!(drain_turn_events(&events).is_empty());
    }

    #[tokio::test]
    async fn explicit_agent_runner_shutdown_is_idempotent() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(dropped.clone());
        let handle = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });

        let mut runner = runner_with_client_task(handle);
        runner.shutdown();
        runner.shutdown();
        drop(runner);

        assert_task_future_dropped(dropped).await;
    }
}
