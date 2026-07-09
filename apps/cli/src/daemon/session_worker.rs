//! Per-session worker. One alive at a time per session_id.
//!
//! Owns the [`crate::engine::Driver`] for the session, the
//! per-session redaction table, and the model client. Accepts work
//! requests from any number of attached clients via an
//! `mpsc::Sender<SessionWork>` and fans events out to all attached
//! clients via `broadcast::Sender<proto::Event>`.
//!
//! Lifecycle:
//!
//! - **Spawned** lazily on the first `Attach` to a session_id.
//! - **Stays alive** across client disconnects — per GOALS §8b a
//!   session outlives its TUI client.
//! - **Exits** on explicit `Shutdown` (daemon teardown) or when the
//!   session ends (`Session::end`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::Result;
use rusqlite::Connection;
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot};
use uuid::Uuid;

use crate::daemon::proto;
use crate::engine::builtin::{self, SpawnArgs};
use crate::engine::model::{Model, ModelParams};
use crate::engine::{Driver, TurnEvent};
use crate::env_snapshot::EnvSnapshot;
use crate::locks::LockManager;
use crate::redact::RedactionTable;
use crate::session::Session;

/// Channel capacity for outbound events fanned to attached clients.
/// Lagging clients lose events (consistent with the fire-and-forget
/// event-stream contract); a client that lags has to reattach to
/// re-sync.
const EVENT_BROADCAST_CAPACITY: usize = 1024;
const LOCK_SNAPSHOT_WORK_LIMIT: usize = 4;
static LOCK_SNAPSHOT_WORK: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Inbound work-queue capacity. Generous — user messages, cancels,
/// and resolves are tiny.
const WORK_QUEUE_CAPACITY: usize = 64;

#[derive(Default)]
struct RedactionSourceOverrides {
    scan_environment: Option<bool>,
    scan_dotenv: Option<bool>,
    scan_ssh_keys: Option<bool>,
}

impl RedactionSourceOverrides {
    fn apply_to(&self, cfg: &mut crate::config::extended::RedactConfig) {
        if let Some(v) = self.scan_environment {
            cfg.scan_environment = v;
        }
        if let Some(v) = self.scan_dotenv {
            cfg.scan_dotenv = v;
        }
        if let Some(v) = self.scan_ssh_keys {
            cfg.scan_ssh_keys = v;
        }
    }
}

async fn refresh_redaction_for_turn(
    session_id: Uuid,
    project_root: &Path,
    overrides: &RedactionSourceOverrides,
    unsupported_notified: &mut HashSet<PathBuf>,
    event_tx: &broadcast::Sender<proto::Event>,
    driver_control_tx: &mpsc::Sender<crate::engine::driver::DriverControl>,
    env: &HashMap<String, String>,
) -> bool {
    let mut cfg = crate::config::extended::load_for_cwd(project_root).redact;
    overrides.apply_to(&mut cfg);
    match crate::redact::RedactionTable::build_with_env(&cfg, project_root, env) {
        Ok(table) => {
            let table = Arc::new(table);
            for path in table.unsupported_files() {
                if unsupported_notified.insert(path.clone()) {
                    let _ = event_tx.send(proto::Event::Notice {
                        session_id,
                        text: format!(
                            "`{}` is an unsupported format; redaction for this file will not work",
                            path.display()
                        ),
                    });
                }
            }
            if driver_control_tx
                .send(crate::engine::driver::DriverControl::SetRedaction {
                    table,
                    scan_environment: None,
                    scan_dotenv: None,
                    scan_ssh_keys: None,
                })
                .await
                .is_err()
            {
                tracing::warn!(session_id = %session_id, "driver control channel closed");
                return false;
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "refreshing redaction table failed");
        }
    }
    true
}

/// Live in-daemon status of a session, maintained by the event
/// forwarder (GOALS §17f / §22). The `ScheduleAuthority` and the driver turn
/// loop are the authorities for jobs and turn-state respectively; their
/// emissions all funnel through the worker's single forwarding seam, so
/// observing them there keeps the single-authority rule intact while
/// giving the browser a cheap, lock-free read for tiers 1-2.
#[derive(Default)]
pub struct LiveState {
    /// Count of live async jobs (loop/timer/background). `ScheduleStarted`
    /// increments, `ScheduleCompleted` decrements.
    active_schedules: AtomicUsize,
    /// Whether a turn is in flight: set on `ThinkingStarted`, cleared on
    /// `AgentIdle`.
    processing: AtomicBool,
}

impl LiveState {
    pub fn has_active_schedules(&self) -> bool {
        self.active_schedules.load(Ordering::Relaxed) > 0
    }

    pub fn processing(&self) -> bool {
        self.processing.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct ForegroundSnapshot {
    pub active_agent_path: Vec<String>,
    pub foreground_target: proto::QueueTarget,
    pub active_subagent: Option<proto::ActiveSubagent>,
}

#[derive(Debug, Clone)]
struct LiveForegroundState {
    root_agent: String,
    active_agent_path: Vec<String>,
    foreground_target: crate::engine::message::QueueTarget,
    active_subagents: Vec<proto::ActiveSubagent>,
}

impl LiveForegroundState {
    fn new(root_agent: String) -> Self {
        Self {
            foreground_target: crate::engine::message::QueueTarget::root(root_agent.clone()),
            active_agent_path: vec![root_agent.clone()],
            active_subagents: Vec::new(),
            root_agent,
        }
    }

    fn snapshot(&self) -> ForegroundSnapshot {
        ForegroundSnapshot {
            active_agent_path: self.active_agent_path.clone(),
            foreground_target: queue_target_to_proto(self.foreground_target.clone()),
            active_subagent: self.active_subagents.last().cloned(),
        }
    }
}

/// Handle one or more client tasks hold to drive a session. Cheap to
/// clone — both channels inside are reference-counted.
#[derive(Clone)]
pub struct SessionWorkerHandle {
    pub session_id: Uuid,
    pub project_root: PathBuf,
    pub active_agent_name: String,
    pub trust_policy: crate::config::trust::WorkspaceTrustPolicy,
    work_tx: mpsc::Sender<SessionWork>,
    event_tx: broadcast::Sender<proto::Event>,
    /// Live job/turn status for the `/sessions` browser (GOALS §17f).
    live: Arc<LiveState>,
    /// Count of attached *interactive* clients — ones that can answer an
    /// interrupt (the loop guard reads this to decide headless behavior,
    /// GOALS §1/§12). Shared with the worker's [`InterruptHub`]; the
    /// server bumps/decrements it as interactive clients attach/detach via
    /// [`Self::register_interactive_client`].
    interactive_clients: Arc<std::sync::atomic::AtomicUsize>,
    /// Shared session handle (sandboxing part 2): lets the server flip
    /// the per-session sandbox-enabled flag (`/sandbox`) directly and
    /// reply synchronously — the flag is an atomic on the `Arc<Session>`
    /// the worker's driver also reads per tool call.
    session: Arc<Session>,
    /// Per-session de-dupe latch for the sandbox-unavailable indicator
    /// (§6.5): `true` once the `SandboxUnavailable` broadcast has fired this
    /// session, so the forward seam drops the duplicates the recurring refuse
    /// path emits. `set_sandbox` clears it (a `/sandbox` toggle resolves the
    /// condition and the TUI notice), so a renewed unavailable condition can
    /// surface again. Shared with the worker's event-forward task.
    sandbox_notice_armed: Arc<AtomicBool>,
    /// The daemon-wide lock authority, so the last-detach-while-idle edge can
    /// release this session's locks (implementation note).
    /// The `InteractiveClientGuard`'s `Drop` consults it; the `AgentIdle` edge
    /// lives in the worker's forward seam, which holds its own clone.
    locks: Arc<LockManager>,
    env_overlay: Arc<RwLock<HashMap<String, String>>>,
    repair_required: Arc<RwLock<Option<proto::ResumeRepairState>>>,
    foreground: Arc<Mutex<LiveForegroundState>>,
}

struct WorkerCleanupGuard(Option<Box<dyn FnOnce() + Send + 'static>>);

impl Drop for WorkerCleanupGuard {
    fn drop(&mut self) {
        if let Some(cleanup) = self.0.take() {
            cleanup();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DriverOutcome {
    Ok,
    Err(String),
    Panicked(String),
}

impl DriverOutcome {
    fn failure_error(&self) -> Option<&str> {
        match self {
            DriverOutcome::Ok => None,
            DriverOutcome::Err(error) | DriverOutcome::Panicked(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkerStop {
    Shutdown {
        pause_for_resume: bool,
        active: bool,
    },
    DriverFailed,
    DriverExited,
    WorkerStopped,
}

impl WorkerStop {
    fn session_ended_reason(&self) -> &'static str {
        match self {
            WorkerStop::DriverFailed => "driver failed",
            WorkerStop::DriverExited => "driver exited",
            WorkerStop::Shutdown { .. } | WorkerStop::WorkerStopped => "worker stopped",
        }
    }
}

fn driver_join_outcome(
    result: std::result::Result<DriverOutcome, tokio::task::JoinError>,
) -> DriverOutcome {
    match result {
        Ok(outcome) => outcome,
        Err(join_error) => {
            let message = if join_error.is_panic() {
                let panic = join_error.into_panic();
                if let Some(message) = panic.downcast_ref::<&str>() {
                    (*message).to_string()
                } else if let Some(message) = panic.downcast_ref::<String>() {
                    message.clone()
                } else {
                    "driver task panicked".to_string()
                }
            } else {
                join_error.to_string()
            };
            tracing::error!(error = %message, "driver task panicked");
            DriverOutcome::Panicked(message)
        }
    }
}

fn emit_session_driver_failed_once(
    event_tx: &broadcast::Sender<proto::Event>,
    session_id: Uuid,
    driver_failed: &mut bool,
    error: String,
) {
    if *driver_failed {
        return;
    }
    *driver_failed = true;
    let _ = event_tx.send(proto::Event::SessionDriverFailed { session_id, error });
}

async fn send_driver_control_or_fail(
    driver_control_tx: &mpsc::Sender<crate::engine::driver::DriverControl>,
    control: crate::engine::driver::DriverControl,
    event_tx: &broadcast::Sender<proto::Event>,
    session_id: Uuid,
    driver_failed: &mut bool,
) -> bool {
    if driver_control_tx.send(control).await.is_ok() {
        return true;
    }
    tracing::warn!(session_id = %session_id, "driver control channel closed");
    emit_session_driver_failed_once(
        event_tx,
        session_id,
        driver_failed,
        "driver control channel closed".to_string(),
    );
    false
}

fn active_wire_api_for_session(
    session: &Session,
    project_root: &Path,
) -> (String, String, crate::config::providers::WireApi) {
    let provider = session.active_provider().unwrap_or_default();
    let model = session.active_model().unwrap_or_default();
    let providers = crate::config::providers::ConfigDoc::load_effective(project_root);
    let configured = providers.resolve_wire_api(&provider, &model);
    let resolved = if configured.is_auto() {
        crate::config::providers::WireApi::detect_for_provider(&provider, &model)
    } else {
        configured
    };
    (provider, model, resolved)
}

fn wire_api_label(wire_api: crate::config::providers::WireApi) -> &'static str {
    match wire_api {
        crate::config::providers::WireApi::Responses => "responses",
        crate::config::providers::WireApi::Completions => "completions",
        crate::config::providers::WireApi::Auto => "auto",
    }
}

fn build_resume_repair_state(
    session: &Session,
    project_root: &Path,
    repair: &crate::engine::rehydrate::RehydrateRepairRequired,
) -> proto::ResumeRepairState {
    let (provider, model, wire_api) = active_wire_api_for_session(session, project_root);
    proto::ResumeRepairState {
        session_id: session.id,
        short_id: session.short_id.clone(),
        provider,
        model,
        wire_api: wire_api_label(wire_api).to_string(),
        failure_kind: repair.failure_kind.clone(),
        failing_tool_call_ids: repair.failing_tool_call_ids.clone(),
        safe_last_turn_seq: repair.safe_last_turn_seq,
        suggested_actions: vec![
            proto::ResumeRepairAction::OpenReadOnly,
            proto::ResumeRepairAction::ForkFromLastProviderValidTurn,
            proto::ResumeRepairAction::RepairSyntheticToolResults,
            proto::ResumeRepairAction::ExportDebugBundle,
            proto::ResumeRepairAction::Cancel,
        ],
        detail: repair.detail.clone(),
    }
}

impl SessionWorkerHandle {
    #[cfg(test)]
    pub(crate) fn test_handle(session: Arc<Session>, locks: Arc<LockManager>) -> Self {
        Self::test_handle_with_receiver(session, locks).0
    }

    #[cfg(test)]
    pub(crate) fn test_handle_with_receiver(
        session: Arc<Session>,
        locks: Arc<LockManager>,
    ) -> (Self, mpsc::Receiver<SessionWork>) {
        let (work_tx, work_rx) = mpsc::channel(WORK_QUEUE_CAPACITY);
        let (event_tx, _event_rx) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        let handle = Self {
            session_id: session.id,
            project_root: session.project_root.clone(),
            active_agent_name: "Build".to_string(),
            trust_policy: crate::config::trust::WorkspaceTrustPolicy {
                root: crate::config::trust::resolve_trust_root(&session.project_root)
                    .unwrap_or_else(|_| crate::config::trust::TrustRoot {
                        opened_path: session.project_root.clone(),
                        root: session.project_root.clone(),
                        kind: crate::config::trust::TrustRootKind::Directory,
                    }),
                mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            },
            work_tx,
            event_tx,
            live: Arc::new(LiveState::default()),
            interactive_clients: Arc::new(AtomicUsize::new(0)),
            session,
            sandbox_notice_armed: Arc::new(AtomicBool::new(false)),
            locks,
            env_overlay: Arc::new(RwLock::new(HashMap::new())),
            repair_required: Arc::new(RwLock::new(None)),
            foreground: Arc::new(Mutex::new(LiveForegroundState::new("Build".to_string()))),
        };
        (handle, work_rx)
    }

    pub fn set_created_by_principal(&self, principal: Option<String>) -> anyhow::Result<()> {
        self.session.set_created_by_principal(principal)
    }

    pub fn set_env_overlay(&self, vars: HashMap<String, String>) {
        let mut overlay = self
            .env_overlay
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *overlay = vars;
    }

    #[cfg(test)]
    pub fn env_overlay(&self) -> Arc<RwLock<HashMap<String, String>>> {
        self.env_overlay.clone()
    }

    /// Set or toggle the session's sandbox mode. `None` toggles the legacy
    /// off/sandbox state; explicit container modes are validated before storing.
    pub fn set_sandbox(
        &self,
        mode: Option<crate::tools::sandbox_mode::SandboxMode>,
        container_network_enabled: Option<bool>,
    ) -> Result<crate::tools::sandbox_mode::SandboxMode, String> {
        if let Some(enabled) = container_network_enabled {
            self.session.set_container_network_enabled(enabled);
        }
        let requested = mode.unwrap_or_else(|| self.session.sandbox_mode().toggled_legacy());
        if requested.is_container() {
            let availability = crate::container::availability_snapshot();
            if !availability.available {
                return Err(availability
                    .unavailable_reason_text()
                    .unwrap_or_else(|| "container sandbox is unavailable".to_string()));
            }
        }
        let new = self.session.set_sandbox_mode(requested);
        self.sandbox_notice_armed.store(false, Ordering::SeqCst);
        let _ = self.event_tx.send(proto::Event::SandboxState {
            session_id: self.session_id,
            mode: new,
            enabled: new.enabled(),
            container_network_enabled: self.session.container_network_enabled(),
            container_availability: crate::container::availability_snapshot(),
        });
        Ok(new)
    }

    pub fn container_network_enabled(&self) -> bool {
        self.session.container_network_enabled()
    }

    /// Set the session's command-approval mode and broadcast the resulting
    /// state to every attached client. Effective immediately for subsequent
    /// gated tool calls because tools read the same session atomic.
    pub fn set_approval_mode(
        &self,
        mode: crate::config::extended::ApprovalMode,
    ) -> crate::config::extended::ApprovalMode {
        let mode = self.session.set_approval_mode(mode);
        let _ = self.event_tx.send(proto::Event::ApprovalModeState {
            session_id: self.session_id,
            mode,
        });
        mode
    }

    /// Register an interactive client (one that can answer interrupts —
    /// the TUI; later the remote dashboard) for the lifetime of the
    /// returned guard. The loop guard (GOALS §1/§12) reads the resulting
    /// count to tell an interactive session from a headless run: while at
    /// least one guard is alive, a back-to-back repeat prompts; with none,
    /// it auto-rejects without blocking. Dropping the guard (client
    /// detach / disconnect) decrements the count.
    pub fn register_interactive_client(&self) -> InteractiveClientGuard {
        self.interactive_clients
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        InteractiveClientGuard {
            counter: self.interactive_clients.clone(),
            session_id: self.session_id,
            locks: self.locks.clone(),
            live: self.live.clone(),
        }
    }
}

/// RAII guard for an attached interactive client. Decrements the worker's
/// interactive-client count on drop, so a disconnect (even an abrupt one)
/// correctly returns the session to headless behavior.
pub struct InteractiveClientGuard {
    counter: Arc<std::sync::atomic::AtomicUsize>,
    /// Session this guard belongs to — used by the last-detach-while-idle
    /// release edge (implementation note).
    session_id: Uuid,
    /// The daemon-wide lock authority, consulted on the last detach.
    locks: Arc<LockManager>,
    /// Live turn-state, so the detach edge releases only when idle (not
    /// mid-turn): a mid-turn detach keeps the worker (GOALS §8b) and its
    /// locks alive; the next `AgentIdle` with zero clients is the backstop.
    live: Arc<LiveState>,
}

impl Drop for InteractiveClientGuard {
    fn drop(&mut self) {
        // Saturating: never underflow even on a double-drop path. `prev` is
        // the count before this drop, so the count is now `prev - 1`.
        let prev = self
            .counter
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |n| Some(n.saturating_sub(1)),
            )
            .unwrap_or(0);
        // Last-detach-while-idle edge (implementation note):
        // when this was the last interactive client (count 1→0) AND the session
        // is awaiting input (not mid-turn), release the session's locks so an
        // unattended session doesn't block other agents/sessions. A mid-turn
        // detach is left alone — the worker keeps running and the next
        // `AgentIdle` with zero clients triggers the release.
        if detach_should_release(prev, self.live.processing()) {
            schedule_session_locks_unattended(
                self.locks.clone(),
                self.counter.clone(),
                self.live.clone(),
                self.session_id,
                "last detach while idle",
            );
            schedule_session_container_release(
                self.counter.clone(),
                self.live.clone(),
                self.session_id,
                "last detach while idle",
            );
        }
    }
}

impl SessionWorkerHandle {
    pub async fn send_work(&self, work: SessionWork) -> Result<()> {
        self.work_tx
            .send(work)
            .await
            .map_err(|_| anyhow::anyhow!("session worker {} has shut down", self.session_id))
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.work_tx.is_closed()
    }

    /// Subscribe to the event stream. Each attached client gets its
    /// own receiver; a lagging receiver drops events (per the design).
    pub fn subscribe(&self) -> broadcast::Receiver<proto::Event> {
        self.event_tx.subscribe()
    }

    pub fn broadcast_notice(&self, text: String) {
        let _ = self.event_tx.send(proto::Event::Notice {
            session_id: self.session_id,
            text,
        });
    }

    pub fn repair_required(&self) -> Option<proto::ResumeRepairState> {
        self.repair_required
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn mark_viewed(&self) -> Result<()> {
        self.session.mark_viewed()
    }

    /// Live job/turn status snapshot for the browser's tiers 1-2.
    pub fn live_status(&self) -> (bool, bool) {
        (self.live.has_active_schedules(), self.live.processing())
    }

    pub fn foreground_snapshot(&self) -> ForegroundSnapshot {
        self.foreground
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot()
    }

    /// The session's project id — read from the in-memory session so it is
    /// available before the `sessions` row is persisted
    /// (session-id-display-and-lazy-persist).
    pub fn project_id(&self) -> String {
        self.session.project_id.clone()
    }

    /// The session's 6-char display id — read from the in-memory session so
    /// it is available before the `sessions` row is persisted.
    pub fn short_id(&self) -> String {
        self.session.short_id.clone()
    }

    /// Broadcast the session's current gitignore read-allowlist over the
    /// per-session event bus (implementation note).
    /// Called on attach so a late/reconnecting client — and any second
    /// concurrent client — hydrates session-approved entries made before it
    /// connected, not only ones broadcast live afterward. Full-list replace;
    /// only the allow-set is ever sent. A send with no subscribers is a no-op.
    pub fn broadcast_gitignore_allow(&self) {
        let _ = self.event_tx.send(proto::Event::GitignoreAllow {
            session_id: self.session_id,
            allow: self.session.gitignore_session_allow(),
        });
    }
}

/// Work items a client can ask the worker to perform.
#[derive(Debug)]
pub enum SessionWork {
    UserMessage {
        submission: Box<crate::engine::message::UserSubmission>,
        respond_to: oneshot::Sender<(proto::QueueItem, Vec<proto::QueueItem>)>,
    },
    RemoveQueuedUserMessage {
        queue_item_id: Uuid,
        respond_to: oneshot::Sender<proto::RemoveQueuedUserMessageResult>,
    },
    RemoveNewestQueuedUserMessage {
        target_id: Option<String>,
        respond_to: oneshot::Sender<proto::RemoveQueuedUserMessageResult>,
    },
    RemoveEditableQueuedUserMessages {
        target_id: Option<String>,
        respond_to: oneshot::Sender<proto::RemoveQueuedUserMessagesResult>,
    },
    Cancel,
    ResolveInterrupt {
        interrupt_id: Uuid,
        response: proto::ResolveResponse,
    },
    RepairResume {
        respond_to: oneshot::Sender<std::result::Result<(), String>>,
    },
    SetActiveModel {
        provider: String,
        model: String,
    },
    SetAgent {
        name: String,
    },
    /// Switch the active `llm_mode` live (`/llm-mode`,
    /// implementation note). `mode = None` toggles.
    SetLlmMode {
        mode: Option<crate::config::extended::LlmMode>,
    },
    /// Switch LLM mode for this session only (`/quick`). Does not persist
    /// `llm_mode`.
    SetSessionLlmMode {
        mode: crate::config::extended::LlmMode,
    },
    /// Set the session's live delegation recursion override (`/quick`). Does
    /// not persist delegation config.
    SetDelegationRecursion {
        enabled: bool,
        default_depth: u32,
    },
    /// Toggle redaction sources for the running session (`/toggle-redaction`).
    /// Mutates the in-memory effective `RedactConfig`, rebuilds the table,
    /// and routes the new table to the driver. **Session-only** — no
    /// config-file write. `None` leaves a source unchanged.
    SetRedaction {
        scan_environment: Option<bool>,
        scan_dotenv: Option<bool>,
        scan_ssh_keys: Option<bool>,
    },
    /// Set (or toggle) request preflight for the running session
    /// (`/preflight`, implementation note). Routes the override to
    /// the driver (which holds it, precedence over config) and broadcasts the
    /// resulting state. **Session-only** — no config-file write. `None`
    /// toggles the driver's current effective state.
    SetPreflight {
        enabled: Option<bool>,
    },
    /// Set (or toggle) trusted-only inference mode for the running session.
    /// Session-only unless the caller also writes `trustedOnly` to config.
    SetTrustedOnly {
        enabled: Option<bool>,
    },
    /// Set the session's model-comparison tandem (shadow) set
    /// (`/model-comparison`, implementation note).
    /// Builds a completion model for each selected `(provider, model)` (the
    /// active model excluded) and routes them to the driver. **Empty = feature
    /// off.** Session-only — no config write; reverts on restart.
    SetTandemModels {
        models: Vec<(String, String)>,
    },
    /// Cancel a live async job (loop / timer / background, GOALS §22) by
    /// id, on behalf of the **human** ("stop checking the deploy" /
    /// `/schedule cancel <id>`). Routed to the driver's single async-job
    /// authority.
    CancelSchedule {
        job_id: String,
    },
    /// Run `/prune` (snapshot dedup) on the foreground agent now.
    Prune,
    /// Run `/compact` (fresh-thread handoff) on the foreground agent.
    Compact,
    /// Pin a user message verbatim for the next `/compact` (`/pin`).
    Pin {
        text: String,
    },
    Shutdown {
        pause_for_resume: bool,
    },
}

/// One-shot constructor: spawn the worker and return its handle.
///
/// `client_no_sandbox` is the attaching client's `--no-sandbox` flag
/// (sandboxing part 2): `Some(true)` means the client asked for new
/// sessions it creates to be unsandboxed. The session-spawn default is
/// resolved here by the precedence daemon-flag → client-flag → ON.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    session: Arc<Session>,
    locks: Arc<LockManager>,
    redact: Arc<RedactionTable>,
    model: Arc<Model>,
    model_override: Option<Arc<Model>>,
    thinking_params: Option<serde_json::Value>,
    project_root: PathBuf,
    client_no_sandbox: bool,
    extended_cfg: &crate::config::extended::ExtendedConfig,
    lsp: Arc<crate::daemon::lsp::LspManager>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    global_bus: Option<broadcast::Sender<proto::Event>>,
    trust_policy: crate::config::trust::WorkspaceTrustPolicy,
    cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
    env_snapshot: EnvSnapshot,
) -> (SessionWorkerHandle, tokio::task::JoinHandle<()>) {
    let session_id = session.id;
    // The primary the chrome's active-agent slot opens on: the stored agent
    // (resume) or the configured default (`Auto` unless pinned). The worker
    // re-derives the same value via `resolve_root_agent` and emits
    // `PrimarySwapped` on any later swap, so this is purely the start state.
    let initial_agent = resolve_root_agent(session_id, &session.db, extended_cfg);
    // Resolve the new-session sandbox default (highest wins):
    //   (a) daemon launched `--no-sandbox` → OFF for ALL sessions.
    //   (b) else this client passed `--no-sandbox` → OFF for the
    //       sessions it creates.
    //   (c) else ON.
    // A later `/sandbox` flip overrides this for the session.
    session.set_sandbox_mode(resolve_sandbox_default(
        client_no_sandbox,
        extended_cfg.sandbox.default_mode,
    ));
    // Command-approval mode (implementation note): new
    // sessions start in the configured default (`manual` unless overridden).
    // A later `/settings` change re-resolves on the next session.
    session.set_approval_mode(extended_cfg.default_approval_mode);
    // Native shell-output compression (implementation note):
    // new sessions start in the configured default (`enabled` unless
    // overridden). A later `/settings` change re-resolves on the next session.
    session.set_shell_compression(extended_cfg.shell_compression);
    let (work_tx, work_rx) = mpsc::channel::<SessionWork>(WORK_QUEUE_CAPACITY);
    let (event_tx, _initial_rx) = broadcast::channel::<proto::Event>(EVENT_BROADCAST_CAPACITY);
    let live = Arc::new(LiveState::default());
    // Shared interactive-client counter (GOALS §1/§12). Owned here, handed
    // to the worker's `InterruptHub` and stored on the handle so attach /
    // detach and the loop guard read the same cell.
    let interactive_clients = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Per-session de-dupe latch for the sandbox-unavailable indicator (§6.5).
    // Shared between the handle's `set_sandbox` (clears it) and the worker's
    // event-forward task (sets it on first broadcast, drops duplicates).
    let sandbox_notice_armed = Arc::new(AtomicBool::new(false));
    let env_overlay = Arc::new(RwLock::new(env_snapshot.into_vars()));
    let repair_required = Arc::new(RwLock::new(None));
    let foreground = Arc::new(Mutex::new(LiveForegroundState::new(initial_agent.clone())));

    let handle = SessionWorkerHandle {
        session_id,
        project_root: project_root.clone(),
        active_agent_name: initial_agent,
        trust_policy: trust_policy.clone(),
        work_tx,
        event_tx: event_tx.clone(),
        live: live.clone(),
        interactive_clients: interactive_clients.clone(),
        session: session.clone(),
        sandbox_notice_armed: sandbox_notice_armed.clone(),
        locks: locks.clone(),
        env_overlay: env_overlay.clone(),
        repair_required: repair_required.clone(),
        foreground: foreground.clone(),
    };

    // Return the worker's `JoinHandle` so the registry can *await* it on a
    // graceful drain (`daemon-graceful-drain-shutdown.md`) — today's
    // `shutdown_all` fires `Shutdown` and forgets, with no way to know the
    // in-flight turn finished. The handle also lets the force path
    // `abort()` a worker whose provider call hung past the grace deadline.
    let join = tokio::spawn(async move {
        let _cleanup = WorkerCleanupGuard(cleanup);
        crate::config::trust::scope_workspace_trust_policy(
            trust_policy,
            run_worker(
                session,
                locks,
                redact,
                model,
                model_override,
                thinking_params,
                project_root,
                work_rx,
                event_tx,
                live,
                interactive_clients,
                sandbox_notice_armed,
                env_overlay,
                repair_required,
                foreground,
                lsp,
                resource_scheduler,
                global_bus,
            ),
        )
        .await;
    });

    (handle, join)
}

#[allow(clippy::too_many_arguments)]
async fn run_worker(
    session: Arc<Session>,
    locks: Arc<LockManager>,
    redact: Arc<RedactionTable>,
    model: Arc<Model>,
    model_override: Option<Arc<Model>>,
    thinking_params: Option<serde_json::Value>,
    project_root: PathBuf,
    mut work_rx: mpsc::Receiver<SessionWork>,
    event_tx: broadcast::Sender<proto::Event>,
    live: Arc<LiveState>,
    interactive_clients: Arc<std::sync::atomic::AtomicUsize>,
    sandbox_notice_armed: Arc<AtomicBool>,
    env_overlay: Arc<RwLock<HashMap<String, String>>>,
    repair_required: Arc<RwLock<Option<proto::ResumeRepairState>>>,
    foreground: Arc<Mutex<LiveForegroundState>>,
    lsp: Arc<crate::daemon::lsp::LspManager>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    _global_bus: Option<broadcast::Sender<proto::Event>>,
) {
    let session_id = session.id;

    // The layered `config.json` resolved once at session start.
    // The active LLM mode (implementation note) and the
    // default primary agent (the auto-router feature) both read it; the live
    // `/llm-mode` switch overrides the mode in place via `DriverControl`.
    let extended_cfg = crate::config::extended::load_for_cwd(&project_root);
    // Effective LLM mode = active model `mode` override → active provider
    // `mode` override → the persisted global `llm_mode`
    // (implementation note). Re-resolved here so a
    // model/provider that pins a mode takes effect at session start (and on a
    // `/model` change, which restarts the worker on the new active model). A
    // live `/llm-mode` toggle still overrides this for the running session via
    // `DriverControl::SetLlmMode`.
    let llm_mode = resolve_effective_llm_mode(&session, &project_root, extended_cfg.llm_mode);
    // Root primary: the session's stored active agent (so a resume restarts
    // on `Plan` after a `/plan` swap or whichever primary `Auto` handed off
    // to, `plan.md §4.6.d`), falling back to the configured default
    // (`Auto` unless the user pinned another) when it's unset/unknown.
    let root_agent_name = resolve_root_agent(session_id, &session.db, &extended_cfg);
    // The daemon's shared shutdown gate, captured before `model` is moved into
    // `spawn_args`. Reused when building model-comparison tandem (shadow)
    // models so a tandem request — itself a new provider round-trip — refuses
    // to dispatch once a drain begins (`model-comparison-tandem-
    // inference.md`).
    let shutdown_gate = model.shutdown_gate();
    let spawn_args = SpawnArgs {
        model,
        env_overlay: env_overlay.clone(),
        // The active model's resolved extra-request-body fragment
        // (implementation note) rides on every outbound
        // request via `ModelParams`; the rest are defaults as before.
        params: ModelParams {
            additional_params: thinking_params,
            // Top-level `prompt_cache_key` = session id for OpenAI-compatible
            // backends (prompt `prompt-caching-strategy.md`, decision 3),
            // held constant across the session so per-key prefix caching keeps
            // hitting. Only the main session worker's foreground model sets
            // it; background/utility models leave it `None`. The native
            // Anthropic arm ignores it (it caches per-block instead).
            prompt_cache_key: Some(session_id.to_string()),
            ..ModelParams::default()
        },
        cwd: project_root.clone(),
        session_short_id: session.short_id.clone(),
        // The daemon root is always the user-facing interactive agent —
        // it gets the cross-session recall tools.
        interactive: true,
        llm_mode,
        // Plan-level model override (`plan-duplication-and-model-override.md`):
        // when set, the root and every spawned subagent run under it.
        model_override: model_override.clone(),
        delegation_model: None,
        delegated: false,
        delegation_recursion: builtin::configured_recursion_context(
            &extended_cfg.delegation,
            &root_agent_name,
            None,
        ),
        // Recursive-`Swarm` depth (GOALS §24): the `Swarm` root is depth 0;
        // each `bee` fan-out spawn advances it. The ceiling rides along so
        // the `spawn` description shows the remaining budget.
        swarm_depth: 0,
        swarm_max_depth: extended_cfg.swarm.max_depth,
        // The root primary carries no per-delegation grants — grants attach to
        // an individual `task` delegation, never to the root spawn.
        granted_tools: Vec::new(),
    };
    let root = Arc::new(
        builtin::load(&root_agent_name, &spawn_args)
            .unwrap_or_else(|_| builtin::build(&spawn_args)),
    );

    // Snapshot the resolved agent-guidance file body that just went into
    // the frozen system block (live instructions-file diff injection,
    // prompt `instructions-file-live-diff.md`). This is the start-of-
    // session baseline a later in-place edit is diffed against; the driver
    // checks it on every outbound request. Recomputed on each worker spawn
    // (fresh or resumed) because `builtin::build` re-composes the system
    // block from the current file each time.
    session.snapshot_guidance_baseline(&project_root);

    let (queue_update_tx, mut queue_update_rx) =
        mpsc::unbounded_channel::<Vec<crate::engine::message::QueuedUserMessage>>();
    let driver_input_queue = crate::engine::message::UserSubmissionQueue::new(queue_update_tx);
    let foreground_input_target = Arc::new(Mutex::new(crate::engine::message::QueueTarget::root(
        root.name.clone(),
    )));
    let (driver_control_tx, driver_control_rx) =
        mpsc::channel::<crate::engine::driver::DriverControl>(WORK_QUEUE_CAPACITY);
    let (engine_event_tx, mut engine_event_rx) = mpsc::channel::<TurnEvent>(WORK_QUEUE_CAPACITY);

    // Forward engine events → broadcast channel as proto::Event, and
    // maintain the live job/turn status (GOALS §17f) off the same
    // authoritative stream. These signals originate from the driver turn
    // loop (`ThinkingStarted` / `AgentIdle`) and the single `ScheduleAuthority`
    // (`ScheduleStarted` / `ScheduleCompleted`); the forwarder is the one seam they
    // all pass through, so updating here never duplicates the authority.
    let event_tx_for_forward = event_tx.clone();
    let event_tx_for_queue = event_tx.clone();
    let foreground_input_target_for_forward = foreground_input_target.clone();
    let foreground_for_forward = foreground.clone();
    let live_for_forward = live.clone();
    let sandbox_notice_armed_for_forward = sandbox_notice_armed.clone();
    // The lock authority + the interactive-client count, for the
    // `AgentIdle`-with-zero-clients release edge
    // (implementation note). When a turn finishes and no
    // interactive client is attached, the session's locks are released here —
    // the second of the two edges (the first is the last-detach drop above).
    let locks_for_forward = locks.clone();
    let interactive_clients_for_forward = interactive_clients.clone();
    let forward = tokio::spawn(async move {
        while let Some(event) = engine_event_rx.recv().await {
            update_live_foreground(
                &foreground_for_forward,
                &foreground_input_target_for_forward,
                &event,
            );
            for ev in turn_event_to_proto(event, session_id) {
                // Per-session de-dupe (§6.5): the engine emits `SandboxUnavailable`
                // on every refused `bash` (the verdict is process-lifetime-cached,
                // so it recurs), but the user needs only one persistent notice.
                // Forward the first; drop the recurring duplicates. `set_sandbox`
                // re-arms the latch when the user toggles `/sandbox`.
                if matches!(ev, proto::Event::SandboxUnavailable { .. })
                    && !forward_sandbox_unavailable(&sandbox_notice_armed_for_forward)
                {
                    continue;
                }
                match &ev {
                    proto::Event::ThinkingStarted { .. } => {
                        live_for_forward.processing.store(true, Ordering::Relaxed);
                    }
                    proto::Event::AgentIdle { .. } => {
                        live_for_forward.processing.store(false, Ordering::Relaxed);
                        // Last-detach-while-idle edge, idle side
                        // (implementation note): the turn
                        // just finished, so if no interactive client is
                        // attached, release this session's locks now. Covers the
                        // case where clients hit zero mid-turn (the detach edge
                        // declined to release because the agent was still
                        // running) and this idle boundary is the backstop.
                        if interactive_clients_for_forward.load(Ordering::SeqCst) == 0 {
                            schedule_session_locks_unattended(
                                locks_for_forward.clone(),
                                interactive_clients_for_forward.clone(),
                                live_for_forward.clone(),
                                session_id,
                                "idle with no attached clients",
                            );
                            schedule_session_container_release(
                                interactive_clients_for_forward.clone(),
                                live_for_forward.clone(),
                                session_id,
                                "idle with no attached clients",
                            );
                        }
                    }
                    proto::Event::ScheduleStarted { .. } => {
                        live_for_forward
                            .active_schedules
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    proto::Event::ScheduleCompleted { .. } => {
                        // Saturating: never underflow if a completion is
                        // ever seen without its start (defensive).
                        let _ = live_for_forward.active_schedules.fetch_update(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |n| Some(n.saturating_sub(1)),
                        );
                    }
                    _ => {}
                }
                // `send` returns `Err` only when there are no
                // subscribers — that's fine, nobody is listening.
                let _ = event_tx_for_forward.send(ev);
            }
        }
    });
    let queue_forward = tokio::spawn(async move {
        while let Some(queue) = queue_update_rx.recv().await {
            let _ = event_tx_for_queue.send(proto::Event::QueueUpdated {
                session_id,
                queue: queue.into_iter().map(queue_item_to_proto).collect(),
            });
        }
    });

    // Build the driver, then capture its async-job command sender (GOALS
    // §22) so a human-initiated `/schedule cancel` reaches the single
    // authority before moving the driver into its task.
    let max_concurrent_schedules = max_concurrent_schedules_for(&project_root);
    let mut driver = Driver::with_max_schedules(
        session.clone(),
        locks.clone(),
        redact.clone(),
        project_root.clone(),
        root,
        max_concurrent_schedules,
    );
    // Propagate any plan-level model override to the whole delegation tree
    // (`plan-duplication-and-model-override.md`): the root already runs under
    // it (loaded with the override `SpawnArgs`); this carries it down to
    // delegated subagents whose frontmatter would otherwise win.
    driver.set_model_override(model_override);
    // Recursive-`Swarm` knobs (GOALS §24): the depth ceiling + the global
    // concurrency cap on simultaneously-running `bee` workers, enforced
    // centrally by the single async-job authority.
    driver.set_swarm_config(
        extended_cfg.swarm.max_depth,
        extended_cfg.swarm.max_concurrency,
    );
    driver.set_lsp_manager(lsp);
    if let Some(scheduler) = resource_scheduler {
        driver.set_resource_scheduler(scheduler);
    }
    let job_cmd_tx = driver.job_command_sender();
    // Capture the driver's cancel handle (GOALS §3a) before moving it into
    // its task, so a user ctrl+c (`SessionWork::Cancel`) can abort the
    // in-flight user-message run — aborting the streaming inference and
    // killing any running `bash` subprocess.
    let cancel_handle = driver.cancel_handle();

    // Interrupt wakeup hub (GOALS §3b): wire the driver's tool calls to
    // the client event fan-out so the `question` tool can raise an
    // interrupt and block on the answer. We keep the same `Arc` so the
    // `ResolveInterrupt` handler below can wake the blocked tool. The
    // hub must be installed before the driver loop starts.
    let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::new(
        event_tx.clone(),
        interactive_clients,
    ));
    driver.set_interrupt_hub(interrupts.clone());

    // Command/path approval driver (sandboxing part 2). Built on the
    // session's grant store + the client-wired interrupt hub above, so a
    // `bash` run-fail-escalate or a native out-of-boundary path access
    // raises a prompt that fans out to the attached client exactly like a
    // `question`. The driver threads it into every `ToolCtx`. Installed
    // after the hub (the approver captures the same `Arc`). The active
    // agent for the prompt is the foreground primary agent at spawn time;
    // a delegated builder shares the same approver via the `ToolCtx`
    // `Arc`, so grants persist across the delegation tree.
    let grant_store = crate::approval::store::GrantStore::new(
        session.db.clone(),
        session_id,
        project_root.clone(),
    );
    let approver = Arc::new(crate::approval::Approver::new(
        grant_store,
        session.db.clone(),
        session_id,
        initial_active_agent(&extended_cfg),
        interrupts.clone(),
    ));
    driver.set_approver(approver);

    // Loop-guard threshold (GOALS §1/§12) from the layered config, same
    // discovery the jobs cap uses. Clamped to ≥ 2 by the setter.
    driver.set_loop_guard_threshold(loop_guard_threshold_for(&project_root));
    driver.set_max_primary_rounds(max_primary_rounds_for(&project_root));
    driver.set_allow_unbounded_schedule_loops(extended_cfg.schedule.allow_unbounded_loops);

    // Resume rehydration (implementation note): on a
    // fresh worker for a session that has prior recorded turns (a daemon
    // restart, an `/exit` + `/resume`, or resuming a `/compact` successor
    // that already had turns), rebuild the root agent's model-bound history
    // from the durable transcript + prune ledger so the next message
    // continues the conversation in its PRUNED form rather than starting
    // fresh. Automatic — only when the root frame has no live in-memory
    // history (which a freshly-built driver never does). A hard rebuild
    // failure (corrupt/unpairable rows) is surfaced as a clear error rather
    // than sending a malformed or silently-fresh context (priority #1).
    let (_, _, active_wire_api) = active_wire_api_for_session(&session, &project_root);
    let responses_strict_replay = matches!(
        active_wire_api,
        crate::config::providers::WireApi::Responses
    );
    let rehydrate_policy = if responses_strict_replay {
        crate::engine::rehydrate::RehydratePolicy::strict()
    } else {
        crate::engine::rehydrate::RehydratePolicy::heal()
    };
    let rehydrated = match driver
        .rehydrate_root_if_empty_with_policy(&root_agent_name, rehydrate_policy)
    {
        Ok(r) => r,
        Err(e) => {
            if responses_strict_replay
                && let Some(repair) =
                    e.downcast_ref::<crate::engine::rehydrate::RehydrateRepairRequired>()
            {
                let state = build_resume_repair_state(&session, &project_root, repair);
                tracing::error!(
                    session_id = %session_id,
                    failure_kind = %state.failure_kind,
                    failing_tool_call_ids = ?state.failing_tool_call_ids,
                    "resume rehydration requires explicit Responses repair before provider replay"
                );
                {
                    let mut slot = repair_required
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *slot = Some(state.clone());
                }
                let label = if state.short_id.is_empty() {
                    state.session_id.to_string()
                } else {
                    state.short_id.clone()
                };
                let _ = event_tx.send(proto::Event::Notice {
                    session_id,
                    text: format!(
                        "Resume repair required for {label}: {}. The transcript is open read-only; fork from the last valid turn, export a debug bundle, or explicitly repair before continuing.",
                        state.detail
                    ),
                });
            } else {
                tracing::error!(error = %e, session_id = %session_id,
                    "resume rehydration failed; the transcript could not be rebuilt into a \
                     provider-valid conversation");
                let _ = event_tx.send(proto::Event::Notice {
                    session_id,
                    text: format!(
                        "Resume failed: the prior conversation could not be rebuilt ({e}). \
                         Start a new session to continue."
                    ),
                });
            }
            None
        }
    };
    if let Some(r) = &rehydrated
        && r.ledger_fallback
    {
        // Continuity preserved, just less pruned — surface a non-fatal
        // warning (never a silent drop to a fresh context).
        let _ = event_tx.send(proto::Event::Notice {
            session_id,
            text: "Resume: the prune ledger was inconsistent; restored the full \
                   (unpruned) prior context instead."
                .to_string(),
        });
    }
    if let Some(r) = &rehydrated
        && !r.heals.is_empty()
    {
        // The heal pass stubbed/dropped unpairable rows so the prior
        // conversation could be rebuilt instead of dead-ending — degrade
        // visibly (alongside any ledger-fallback notice above), never a
        // silent alteration of the resumed context.
        let n = r.heals.len();
        let _ = event_tx.send(proto::Event::Notice {
            session_id,
            text: format!(
                "Resume: {n} incomplete tool call(s) were stubbed to rebuild the conversation."
            ),
        });
    }

    // Seed-tool re-execution (`/compact` handoff, T6.e): if this session
    // was created by `/compact`, its derived seed-tool plan was persisted
    // keyed by this session id. Drain it and dispatch the calls (read-only
    // / idempotent only) into the fresh agent's initial context *before*
    // the first inference — re-executed, never replayed from a stale
    // transcript. Done synchronously before the driver loop starts so it
    // can never race the first user message. Best-effort.
    //
    // MUTUALLY EXCLUSIVE with rehydration: seed re-execution is for a
    // *fresh* successor's first inference. When this worker rehydrated a
    // successor that has ALREADY had turns, the full pruned context is
    // rebuilt from its transcript — re-running seed tools too would
    // double-seed. So skip seeds when rehydration produced a history; the
    // seed rows are taken (drained) regardless so they never re-fire on a
    // later resume (idempotent).
    match session.db.take_seed_tools(session_id) {
        Ok(seeds)
            if !seeds.is_empty()
                && rehydrated.is_none()
                && repair_required
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_none() =>
        {
            driver.run_seed_tools(&seeds, &engine_event_tx).await;
        }
        Ok(_) => {}
        Err(error) => {
            log_seed_tool_drain_failed(session_id, &error);
        }
    }

    // Session-only redaction source overrides (`/toggle-redaction`). The
    // base config is reloaded at every turn boundary so dotenv/settings/SSH
    // changes made after session start are picked up before the next provider
    // request; these overrides preserve any live toggles without writing them
    // to disk.
    let mut redaction_overrides = RedactionSourceOverrides::default();
    let mut unsupported_redaction_notified: HashSet<PathBuf> = HashSet::new();

    // Spawn the driver loop.
    let driver_queue_for_loop = driver_input_queue.clone();
    let mut driver_handle = tokio::spawn(async move {
        match driver
            .run_main_loop(driver_queue_for_loop, driver_control_rx, &engine_event_tx)
            .await
        {
            Ok(()) => DriverOutcome::Ok,
            Err(e) => {
                let error = format!("{e:#}");
                tracing::error!(error = %error, "driver loop terminated with error");
                DriverOutcome::Err(error)
            }
        }
    });

    // Main work loop.
    let mut driver_failed = false;
    let mut driver_joined = false;
    let stop = loop {
        let work = tokio::select! {
            biased;
            work = work_rx.recv() => work,
            outcome = &mut driver_handle => {
                driver_joined = true;
                let outcome = driver_join_outcome(outcome);
                if let Some(error) = outcome.failure_error() {
                    emit_session_driver_failed_once(
                        &event_tx,
                        session_id,
                        &mut driver_failed,
                        error.to_string(),
                    );
                    break WorkerStop::DriverFailed;
                }
                break WorkerStop::DriverExited;
            }
        };
        let Some(work) = work else {
            break WorkerStop::WorkerStopped;
        };
        match work {
            SessionWork::UserMessage {
                submission,
                respond_to,
            } => {
                if let Some(state) = repair_required
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
                {
                    let ids = if state.failing_tool_call_ids.is_empty() {
                        "unknown tool id".to_string()
                    } else {
                        state.failing_tool_call_ids.join(", ")
                    };
                    let _ = event_tx.send(proto::Event::Notice {
                        session_id,
                        text: format!(
                            "Read-only resume: refusing to send model context until Responses repair is resolved ({}: {}). Use the resume repair dialog, fork, or export a debug bundle.",
                            state.failure_kind, ids
                        ),
                    });
                    let _ = respond_to.send((
                        proto::QueueItem {
                            id: Uuid::nil(),
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        },
                        Vec::new(),
                    ));
                    continue;
                }
                // Lazy persistence (session-id-display-and-lazy-persist): the
                // first user message is what commits the `sessions` row.
                // Flush it *before* `touch()` and before the driver runs, so
                // the row exists ahead of any dependent write (tool_calls,
                // inference_calls, locks). A persist failure aborts the
                // message rather than letting dependents reference a missing
                // row.
                match session.persist_if_needed() {
                    Ok(_) => {}
                    Err(e) => {
                        let error = format!("{e:#}");
                        tracing::error!(error = %error, session_id = %session_id,
                            "persisting session on first message failed; dropping message");
                        let _ =
                            event_tx.send(proto::Event::SessionPersistFailed { session_id, error });
                        let _ = respond_to.send((
                            proto::QueueItem {
                                id: Uuid::nil(),
                                status: proto::QueueItemStatus::Folding,
                                text: String::new(),
                                target: proto::QueueTarget::default(),
                            },
                            Vec::new(),
                        ));
                        continue;
                    }
                }
                if let Err(e) = session.touch() {
                    tracing::warn!(error = %e, "session touch failed");
                }
                let session_env = env_overlay
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                if !refresh_redaction_for_turn(
                    session_id,
                    &project_root,
                    &redaction_overrides,
                    &mut unsupported_redaction_notified,
                    &event_tx,
                    &driver_control_tx,
                    &session_env,
                )
                .await
                {
                    emit_session_driver_failed_once(
                        &event_tx,
                        session_id,
                        &mut driver_failed,
                        "driver control channel closed".to_string(),
                    );
                    let _ = respond_to.send((
                        proto::QueueItem {
                            id: Uuid::nil(),
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        },
                        Vec::new(),
                    ));
                    break WorkerStop::DriverFailed;
                }
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::RefreshActiveModel,
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    let _ = respond_to.send((
                        proto::QueueItem {
                            id: Uuid::nil(),
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        },
                        Vec::new(),
                    ));
                    break WorkerStop::DriverFailed;
                }
                let max_rounds = max_primary_rounds_for(&project_root);
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetMaxPrimaryRounds { max_rounds },
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    let _ = respond_to.send((
                        proto::QueueItem {
                            id: Uuid::nil(),
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        },
                        Vec::new(),
                    ));
                    break WorkerStop::DriverFailed;
                }
                let target = foreground_input_target
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                let (id, snapshot) = driver_input_queue.push(*submission, target).await;
                let queue: Vec<proto::QueueItem> =
                    snapshot.into_iter().map(queue_item_to_proto).collect();
                let item =
                    queue
                        .iter()
                        .find(|item| item.id == id)
                        .cloned()
                        .unwrap_or(proto::QueueItem {
                            id,
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        });
                let _ = respond_to.send((item, queue));
            }
            SessionWork::RemoveQueuedUserMessage {
                queue_item_id,
                respond_to,
            } => {
                let (result, snapshot) = driver_input_queue.remove(queue_item_id).await;
                let reason = remove_reason_to_proto(result);
                let _ = respond_to.send(proto::RemoveQueuedUserMessageResult {
                    applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
                    reason,
                    removed_item: None,
                    queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                });
            }
            SessionWork::RemoveNewestQueuedUserMessage {
                target_id,
                respond_to,
            } => {
                let target_id = target_id.unwrap_or_else(|| {
                    foreground_input_target
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .id
                        .clone()
                });
                let (result, removed_item, snapshot) =
                    driver_input_queue.remove_newest_for(&target_id).await;
                let reason = remove_reason_to_proto(result);
                let _ = respond_to.send(proto::RemoveQueuedUserMessageResult {
                    applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
                    reason,
                    removed_item: removed_item.map(queue_item_to_proto),
                    queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                });
            }
            SessionWork::RemoveEditableQueuedUserMessages {
                target_id,
                respond_to,
            } => {
                let target_id = target_id.unwrap_or_else(|| {
                    foreground_input_target
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .id
                        .clone()
                });
                let (result, removed_items, snapshot) =
                    driver_input_queue.remove_editable_for(&target_id).await;
                let reason = remove_reason_to_proto(result);
                let _ = respond_to.send(proto::RemoveQueuedUserMessagesResult {
                    applied: !removed_items.is_empty(),
                    reason,
                    removed_items: removed_items.into_iter().map(queue_item_to_proto).collect(),
                    queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                });
            }
            SessionWork::Cancel => {
                // User ctrl+c (`CancelTurn`). Fire the in-flight run's
                // cancellation token: the driver's `turn` aborts the
                // streaming inference (returning an `InferenceCancelled`
                // sentinel that unwinds the run cleanly), and any running
                // `bash` subprocess is killed via its process group. Safe
                // and idempotent at idle / mid-cancel — `CancelHandle::cancel`
                // is a no-op when no run is in flight. The driver then emits
                // `AgentIdle`, clearing the TUI's busy state.
                tracing::info!(session_id = %session_id, "cancel requested");
                cancel_handle.cancel();
            }
            SessionWork::ResolveInterrupt {
                interrupt_id,
                response,
            } => {
                if let Err(e) = session.db.resolve_interrupt(interrupt_id, &response) {
                    tracing::warn!(error = %e, %interrupt_id, "resolve_interrupt failed");
                }
                let _ = event_tx.send(proto::Event::InterruptResolved {
                    session_id,
                    interrupt_id,
                });
                // Engine-side wakeup (GOALS §3b): hand the resolution to
                // whatever tool call is blocked on this interrupt id (the
                // `question` tool). `false` just means nobody was blocked
                // locally — e.g. a `schedule` needs-attention nudge — and the
                // DB row update above is the only effect.
                interrupts.resolve(interrupt_id, response);
            }
            SessionWork::RepairResume { respond_to } => {
                let Some(state) = repair_required
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
                else {
                    let _ = respond_to.send(Err(
                        "no Responses resume repair is pending for this session".to_string(),
                    ));
                    continue;
                };
                let (driver_respond_to, driver_response_rx) = oneshot::channel();
                if driver_control_tx
                    .send(crate::engine::driver::DriverControl::RepairResume {
                        root_agent: root_agent_name.clone(),
                        respond_to: driver_respond_to,
                    })
                    .await
                    .is_err()
                {
                    let message = "driver control channel closed".to_string();
                    emit_session_driver_failed_once(
                        &event_tx,
                        session_id,
                        &mut driver_failed,
                        message.clone(),
                    );
                    let _ = respond_to.send(Err(message));
                    break WorkerStop::DriverFailed;
                }
                match driver_response_rx.await {
                    Ok(Ok(heal_count)) => {
                        {
                            let mut slot = repair_required
                                .write()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            *slot = None;
                        }
                        let text = format!(
                            "Responses resume repair approved: synthetic resume heal applied to {heal_count} tool call(s)."
                        );
                        if let Err(error) = session.record_event(
                            crate::db::session_log::SessionEventKind::UserNote,
                            Some(&root_agent_name),
                            None,
                            &serde_json::json!({
                                "text": text,
                                "resume_repair": {
                                    "approved": true,
                                    "failure_kind": state.failure_kind,
                                    "failing_tool_call_ids": state.failing_tool_call_ids,
                                    "provider": state.provider,
                                    "model": state.model,
                                    "wire_api": state.wire_api,
                                    "synthetic_heal_count": heal_count,
                                    "detail": state.detail,
                                }
                            }),
                        ) {
                            tracing::warn!(%error, %session_id, "record resume repair provenance failed");
                        }
                        let _ = event_tx.send(proto::Event::Notice { session_id, text });
                        let _ = respond_to.send(Ok(()));
                    }
                    Ok(Err(message)) => {
                        let _ = respond_to
                            .send(Err(format!("explicit Responses repair failed: {message}")));
                    }
                    Err(error) => {
                        let _ = respond_to
                            .send(Err(format!("explicit Responses repair failed: {error}")));
                    }
                }
            }
            SessionWork::SetActiveModel { provider, model } => {
                // Mid-session model switch (implementation note):
                // route the new `(provider, model)` to the running driver, which
                // rebuilds the active primary under the new model at the idle
                // boundary so the next request routes there. The driver persists
                // the session's active-model row only on a successful build (and
                // surfaces a loud `Notice` on an unconfigured/bad target, keeping
                // the current model active), so config + live routing never
                // diverge — the worker no longer pre-commits it here.
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetActiveModel { provider, model },
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetAgent { name } => {
                // Persist the active-agent choice so a resume restarts on it,
                // then swap the live primary in place at the idle boundary
                // (`/plan` → `Plan`, `/build` → `Build`, `plan.md §4.6.d`).
                if let Err(e) = session.set_active_agent(&name) {
                    tracing::warn!(error = %e, "set_active_agent failed");
                }
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SwapPrimary { name },
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetLlmMode { mode } => {
                // Resolve toggle against the current config value (the
                // single source of truth shared with `/settings` + the
                // config file), persist the resolved value so a resume keeps
                // it, then route the explicit mode to the driver to rebuild
                // the root agent in place.
                let current = crate::config::extended::load_for_cwd(&project_root).llm_mode;
                let resolved = mode.unwrap_or_else(|| current.cycled());
                if let Err(e) = persist_llm_mode(&project_root, resolved) {
                    tracing::warn!(error = %e, "persisting llm_mode failed");
                }
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetLlmMode {
                        mode: Some(resolved),
                    },
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetSessionLlmMode { mode } => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetLlmMode { mode: Some(mode) },
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetDelegationRecursion {
                enabled,
                default_depth,
            } => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetDelegationRecursion {
                        enabled,
                        default_depth,
                    },
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetRedaction {
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            } => {
                // `/toggle-redaction`: mutate the session's in-memory
                // effective `RedactConfig`, rebuild the redaction table, and
                // route the new table to the driver so subsequent outbound
                // prompts use it. Session-only — never persisted. `scrub()`
                // stays non-bypassable; this only changes the table contents.
                //
                // Prompt-cache note (`prompt-caching-strategy.md`): changing
                // what's redacted can change the scrubbed bytes of the cached
                // prefix, so the *next* outbound request after a toggle is a
                // one-time cache re-warm. This is accepted — the toggle is a
                // deliberate, rare user action; `scrub()` output is otherwise
                // deterministic/byte-stable turn-to-turn (see
                // `redact::tests::scrub_is_deterministic_within_a_session`),
                // so it never silently varies the prefix between turns.
                let mut effective_redact =
                    crate::config::extended::load_for_cwd(&project_root).redact;
                redaction_overrides.apply_to(&mut effective_redact);
                if let Some(v) = scan_environment {
                    redaction_overrides.scan_environment = Some(v);
                    effective_redact.scan_environment = v;
                }
                if let Some(v) = scan_dotenv {
                    redaction_overrides.scan_dotenv = Some(v);
                    effective_redact.scan_dotenv = v;
                }
                if let Some(v) = scan_ssh_keys {
                    redaction_overrides.scan_ssh_keys = Some(v);
                    effective_redact.scan_ssh_keys = v;
                }
                let session_env = env_overlay
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                match crate::redact::RedactionTable::build_with_env(
                    &effective_redact,
                    &project_root,
                    &session_env,
                ) {
                    Ok(table) => {
                        let table = Arc::new(table);
                        for path in table.unsupported_files() {
                            if unsupported_redaction_notified.insert(path.clone()) {
                                let _ = event_tx.send(proto::Event::Notice {
                                    session_id,
                                    text: format!(
                                        "`{}` is an unsupported format; redaction for this file will not work",
                                        path.display()
                                    ),
                                });
                            }
                        }
                        if !send_driver_control_or_fail(
                            &driver_control_tx,
                            crate::engine::driver::DriverControl::SetRedaction {
                                table,
                                scan_environment,
                                scan_dotenv,
                                scan_ssh_keys,
                            },
                            &event_tx,
                            session_id,
                            &mut driver_failed,
                        )
                        .await
                        {
                            break WorkerStop::DriverFailed;
                        }
                        let _ = event_tx.send(proto::Event::RedactionState {
                            session_id,
                            scan_environment: effective_redact.scan_environment,
                            scan_dotenv: effective_redact.scan_dotenv,
                            scan_ssh_keys: effective_redact.scan_ssh_keys,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "rebuilding redaction table failed");
                    }
                }
            }
            SessionWork::SetPreflight { enabled } => {
                // `/preflight`: route the override to the driver, which holds
                // it (precedence over config), resolves the toggle against its
                // authoritative current value, and broadcasts the resulting
                // state via `TurnEvent::PreflightState`. Session-only — never
                // persisted (mirrors `/toggle-redaction`).
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetPreflight { enabled },
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetTrustedOnly { enabled } => {
                let target = enabled.unwrap_or_else(|| session.toggle_trusted_only());
                if enabled.is_some() {
                    session.set_trusted_only(target);
                }
                let _ = event_tx.send(proto::Event::TrustedOnlyState {
                    session_id,
                    enabled: target,
                });
            }
            SessionWork::SetTandemModels { models } => {
                // `/model-comparison`: build a completion model for each
                // selected `(provider, model)` from the already-configured
                // providers, route them to the driver's in-memory tandem set,
                // and broadcast the resulting state (+ a one-line token-burn
                // warning when non-empty). Empty disables the feature.
                // Session-only — never persisted (mirrors `/toggle-redaction`).
                let (_, providers_cfg) = crate::auto_title::load_configs_for(&project_root);
                // Reuse the session redaction table the registry already
                // built successfully. Tandem models must never install an
                // empty fail-open table after a redaction rebuild error.
                let tandem_redact = redact.clone();
                let active = (session.active_provider(), session.active_model());
                let mut targets: Vec<crate::engine::schedule::TandemTarget> = Vec::new();
                for (provider, model_id) in &models {
                    // Defensive: never shadow the active model itself (the
                    // client already excludes it; no self-shadowing).
                    if active.0.as_deref() == Some(provider.as_str())
                        && active.1.as_deref() == Some(model_id.as_str())
                    {
                        continue;
                    }
                    let session_env = env_overlay
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    match crate::engine::model::Model::for_provider_with_env_trusted_only(
                        &providers_cfg,
                        provider,
                        model_id,
                        tandem_redact.clone(),
                        session.trusted_only_flag(),
                        |name| session_env.get(name).cloned(),
                    ) {
                        Ok(m) => {
                            let m = m.with_shutdown_gate(shutdown_gate.clone());
                            targets.push(crate::engine::schedule::TandemTarget {
                                provider: provider.clone(),
                                model: model_id.clone(),
                                handle: Arc::new(m),
                            });
                        }
                        Err(e) => {
                            // A misconfigured tandem provider/model is skipped
                            // with a notice rather than failing the toggle.
                            let _ = event_tx.send(proto::Event::Notice {
                                session_id,
                                text: format!(
                                    "model-comparison: skipping `{provider}/{model_id}` — {e:#}"
                                ),
                            });
                        }
                    }
                }
                let labels: Vec<String> = targets
                    .iter()
                    .map(crate::engine::schedule::TandemTarget::label)
                    .collect();
                // Token-burn warning on a non-empty set (warning only — no cap,
                // no meter), in the spirit of the `/swarm` entry warning.
                let warning = (!labels.is_empty()).then(|| {
                    format!(
                        "model-comparison ON: every substantive request is ALSO sent to {} tandem model(s) ({}). This multiplies token spend — it is off by default and reverts on restart.",
                        labels.len(),
                        labels.join(", ")
                    )
                });
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetTandemModels { targets },
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
                let _ = event_tx.send(proto::Event::TandemState {
                    session_id,
                    models: labels,
                    warning,
                });
            }
            SessionWork::CancelSchedule { job_id } => {
                if job_cmd_tx
                    .send(crate::engine::schedule::ScheduleCommand::Cancel { job_id })
                    .await
                    .is_err()
                {
                    tracing::warn!(session_id = %session_id, "job command channel closed");
                }
            }
            SessionWork::Prune => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::Prune,
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::Compact => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::Compact,
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::Pin { text } => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::Pin { text },
                    &event_tx,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::Shutdown { pause_for_resume } => {
                let active = {
                    let (has_schedules, processing) =
                        (live.has_active_schedules(), live.processing());
                    has_schedules || processing
                };
                break WorkerStop::Shutdown {
                    pause_for_resume,
                    active,
                };
            }
        }
    };

    // Drain: close the driver input → the driver finishes its current
    // turn (if any) and exits. Then the engine event channel closes
    // and the forwarder task exits.
    driver_input_queue.close().await;
    if !driver_joined {
        let outcome = driver_join_outcome(driver_handle.await);
        if let Some(error) = outcome.failure_error() {
            tracing::warn!(session_id = %session_id, error = %error, "driver ended during worker drain");
        }
    }
    drop(driver_input_queue);
    let _ = forward.await;
    let _ = queue_forward.await;

    if let WorkerStop::Shutdown {
        pause_for_resume: true,
        active,
    } = stop
    {
        if active
            && let Err(e) = session.db.upsert_paused_session_work(
                session_id,
                &root_agent_name,
                &project_root.display().to_string(),
                "daemon shutdown paused active work",
                0,
                proto::DAEMON_VERSION,
            )
        {
            tracing::warn!(error = %e, "persisting paused session work failed");
        }
    } else {
        // Mark session ended in DB for destructive/explicit worker stops. A
        // graceful daemon drain keeps the session resumable instead.
        if let Err(e) = locks.end_session(session_id) {
            tracing::warn!(error = %e, "lock cleanup failed during terminal session shutdown");
        }
        if let Err(e) = session.end() {
            tracing::warn!(error = %e, "session.end() failed during shutdown");
        }
    }
    let _ = event_tx.send(proto::Event::SessionEnded {
        session_id,
        reason: stop.session_ended_reason().into(),
    });
    tracing::info!(session_id = %session_id, "session worker exited");
}

/// Decide whether a just-landed user write/edit in this session earns the
/// one-time concurrent-write-during-plan warning, and word it mode-aware
/// (`plan-concurrent-build-and-merge.md`). Returns `Some(text)` to fire the
/// toast (and stamps `warned_plan` so the same plan episode warns only once),
/// or `None` when there's no active plan or this plan episode was already
/// warned. A *different* active plan re-arms the warning (the stamp differs).
fn forward_sandbox_unavailable(armed: &AtomicBool) -> bool {
    !armed.swap(true, Ordering::SeqCst)
}

/// Release every lock a session holds because it became unattended-while-idle
/// (implementation note). Both release edges — the
/// last-detach drop and the `AgentIdle`-with-zero-clients seam — funnel through
/// here so the snapshot/wake/persist behavior lives in exactly one place.
/// Errors are logged, never propagated: a failed release must not crash a
/// detach or a turn boundary (the idle-expiry sweep is the backstop).
fn schedule_session_locks_unattended(
    locks: Arc<LockManager>,
    counter: Arc<AtomicUsize>,
    live: Arc<LiveState>,
    session_id: Uuid,
    reason: &'static str,
) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(release_session_locks_unattended(
            locks, counter, live, session_id, reason,
        ));
    } else {
        std::thread::spawn(move || {
            if counter.load(Ordering::SeqCst) != 0 || live.processing() {
                return;
            }
            if let Err(e) = locks.suspend_session(session_id) {
                tracing::warn!(
                    error = %e,
                    %session_id,
                    reason,
                    "releasing session locks failed"
                );
            }
        });
    }
}

fn schedule_session_container_release(
    counter: Arc<AtomicUsize>,
    live: Arc<LiveState>,
    session_id: Uuid,
    reason: &'static str,
) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(release_session_container_unattended(
            counter, live, session_id, reason,
        ));
    }
}

async fn release_session_container_unattended(
    counter: Arc<AtomicUsize>,
    live: Arc<LiveState>,
    session_id: Uuid,
    reason: &'static str,
) {
    if counter.load(Ordering::SeqCst) != 0 || live.processing() || live.has_active_schedules() {
        return;
    }
    let Some(manager) = crate::container::container_manager().get() else {
        return;
    };
    if counter.load(Ordering::SeqCst) != 0 || live.processing() || live.has_active_schedules() {
        return;
    }
    if let Err(e) = manager.remove_container(session_id).await {
        tracing::warn!(error = %e, %session_id, reason, "removing idle session container failed");
    }
}

async fn release_session_locks_unattended(
    locks: Arc<LockManager>,
    counter: Arc<AtomicUsize>,
    live: Arc<LiveState>,
    session_id: Uuid,
    reason: &'static str,
) {
    if counter.load(Ordering::SeqCst) != 0 || live.processing() {
        return;
    }
    let semaphore = LOCK_SNAPSHOT_WORK
        .get_or_init(|| Arc::new(Semaphore::new(LOCK_SNAPSHOT_WORK_LIMIT)))
        .clone();
    let Ok(_permit) = semaphore.acquire_owned().await else {
        return;
    };
    if counter.load(Ordering::SeqCst) != 0 || live.processing() {
        return;
    }
    let result = tokio::task::spawn_blocking(move || locks.suspend_session(session_id)).await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            tracing::warn!(
                error = %e,
                %session_id,
                reason,
                "releasing session locks failed"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                %session_id,
                reason,
                "lock release blocking task failed"
            );
        }
    }
}

/// Whether the last-detach edge should release: this drop took the interactive
/// count to zero (it was `1` before) **and** the session is idle (not
/// mid-turn). A mid-turn detach is left alone — the worker keeps running and the
/// next `AgentIdle` with zero clients is the release backstop.
fn detach_should_release(prev_count: usize, processing: bool) -> bool {
    prev_count == 1 && !processing
}

fn update_live_foreground(
    foreground: &Arc<Mutex<LiveForegroundState>>,
    foreground_input_target: &Arc<Mutex<crate::engine::message::QueueTarget>>,
    event: &TurnEvent,
) {
    let mut state = foreground
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match event {
        TurnEvent::ForegroundInputTarget { target } => {
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = target.clone();
            state.foreground_target = target.clone();
            if !target.agent.is_empty() {
                if target.depth == 0 {
                    state.root_agent = target.agent.clone();
                    state.active_agent_path = vec![target.agent.clone()];
                    state.active_subagents.clear();
                } else if state
                    .active_agent_path
                    .last()
                    .map(|agent| agent != &target.agent)
                    .unwrap_or(true)
                {
                    state.active_agent_path.push(target.agent.clone());
                }
            }
        }
        TurnEvent::SubagentSpawned {
            parent,
            child,
            task_call_id,
            label,
            ..
        } => {
            if let Some(parent_idx) = state
                .active_agent_path
                .iter()
                .rposition(|agent| agent == parent)
            {
                state.active_agent_path.truncate(parent_idx + 1);
            } else {
                state.active_agent_path = vec![state.root_agent.clone()];
            }
            state.active_agent_path.push(child.clone());
            state.active_subagents.push(proto::ActiveSubagent {
                parent: parent.clone(),
                child: child.clone(),
                task_call_id: task_call_id.clone(),
                label: label.clone(),
            });
            state.foreground_target = crate::engine::message::QueueTarget::child(
                child.clone(),
                state.active_agent_path.len().saturating_sub(1),
                task_call_id.clone(),
                label.clone(),
            );
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = state.foreground_target.clone();
        }
        TurnEvent::SubagentReport {
            agent,
            task_call_id,
            label,
            ..
        } => {
            if let Some(idx) = state.active_subagents.iter().rposition(|sub| {
                sub.child == *agent && sub.task_call_id == *task_call_id && sub.label == *label
            }) {
                state.active_subagents.truncate(idx);
            } else {
                state.active_subagents.pop();
            }
            if let Some(agent_idx) = state
                .active_agent_path
                .iter()
                .rposition(|name| name == agent)
            {
                state.active_agent_path.truncate(agent_idx);
            } else {
                state.active_agent_path.pop();
            }
            if state.active_agent_path.is_empty() {
                let root_agent = state.root_agent.clone();
                state.active_agent_path.push(root_agent);
            }
            if let Some(active) = state.active_subagents.last() {
                state.foreground_target = crate::engine::message::QueueTarget::child(
                    active.child.clone(),
                    state.active_agent_path.len().saturating_sub(1),
                    active.task_call_id.clone(),
                    active.label.clone(),
                );
            } else {
                state.foreground_target =
                    crate::engine::message::QueueTarget::root(state.root_agent.clone());
            }
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = state.foreground_target.clone();
        }
        TurnEvent::PrimarySwapped { name } => {
            state.root_agent = name.clone();
            state.active_agent_path = vec![name.clone()];
            state.active_subagents.clear();
            state.foreground_target = crate::engine::message::QueueTarget::root(name.clone());
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = state.foreground_target.clone();
        }
        TurnEvent::AgentIdle { .. } if state.active_subagents.is_empty() => {
            state.active_agent_path = vec![state.root_agent.clone()];
            state.foreground_target =
                crate::engine::message::QueueTarget::root(state.root_agent.clone());
            *foreground_input_target
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = state.foreground_target.clone();
        }
        _ => {}
    }
}

/// Convert a single engine `TurnEvent` into one or more wire
/// `proto::Event`s. Some events (e.g. `ThinkingStarted`) map 1:1;
/// others (subagent spawn / report) are kept as the natural-enough
/// proto equivalents. Returning a `Vec` keeps the door open for a
/// 1:N expansion when, e.g., we attach a recovery chip alongside a
/// `ToolEnd` in the future.
fn turn_event_to_proto(event: TurnEvent, session_id: Uuid) -> Vec<proto::Event> {
    match event {
        TurnEvent::ThinkingStarted { agent, turn_id } => {
            vec![proto::Event::ThinkingStarted {
                session_id,
                agent,
                turn_id,
            }]
        }
        TurnEvent::Reconnecting {
            agent,
            attempt,
            provider,
            model,
            url,
        } => {
            vec![proto::Event::Reconnecting {
                session_id,
                agent,
                attempt,
                provider,
                model,
                url,
            }]
        }
        TurnEvent::AssistantTextDelta { agent, delta } => {
            vec![proto::Event::AssistantTextDelta {
                session_id,
                agent,
                delta,
            }]
        }
        TurnEvent::ReasoningDelta { agent, delta } => {
            vec![proto::Event::ReasoningDelta {
                session_id,
                agent,
                delta,
            }]
        }
        TurnEvent::AssistantText {
            agent,
            text,
            reasoning,
            seq,
        } => {
            vec![proto::Event::AssistantText {
                session_id,
                agent,
                text,
                reasoning,
                seq,
            }]
        }
        TurnEvent::UserMessageRecorded {
            seq,
            preflight_cleaned,
        } => {
            vec![proto::Event::UserMessageRecorded {
                session_id,
                seq,
                preflight_cleaned,
            }]
        }
        TurnEvent::QueuedUserMessagesFolded {
            text,
            queue_item_ids,
            target,
            seq,
            preflight_cleaned,
        } => {
            vec![proto::Event::QueuedUserMessagesFolded {
                session_id,
                text,
                queue_item_ids,
                target: queue_target_to_proto(target),
                seq,
                preflight_cleaned,
            }]
        }
        TurnEvent::SessionPersistFailed { error } => {
            vec![proto::Event::SessionPersistFailed { session_id, error }]
        }
        TurnEvent::SessionDriverFailed { error } => {
            vec![proto::Event::SessionDriverFailed { session_id, error }]
        }
        TurnEvent::UserMessageDispatchFailed { .. } => vec![],
        TurnEvent::PreflightStarted => {
            vec![proto::Event::PreflightStarted { session_id }]
        }
        TurnEvent::UserMessageRetracted => {
            vec![proto::Event::UserMessageRetracted { session_id }]
        }
        TurnEvent::Notice { text } => {
            vec![proto::Event::Notice { session_id, text }]
        }
        TurnEvent::SkillAutoInjected { name, reason } => {
            vec![proto::Event::SkillAutoInjected {
                session_id,
                name,
                reason,
            }]
        }
        TurnEvent::ToolStart {
            agent,
            call_id,
            tool,
            args,
        } => vec![proto::Event::ToolStart {
            session_id,
            agent,
            call_id,
            tool,
            args,
        }],
        TurnEvent::ToolEnd {
            agent,
            call_id,
            tool,
            output,
            truncated,
            hint,
        } => vec![proto::Event::ToolEnd {
            session_id,
            agent,
            call_id,
            tool,
            output,
            truncated,
            hint,
        }],
        TurnEvent::ResourceWait {
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
        } => vec![proto::Event::ResourceWait {
            session_id,
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
        }],
        TurnEvent::ResourceStart {
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
        } => vec![proto::Event::ResourceStart {
            session_id,
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
        }],
        TurnEvent::ResourceClear {
            agent,
            request_id,
            display_id,
            resources,
            command_label,
        } => vec![proto::Event::ResourceClear {
            session_id,
            agent,
            request_id,
            display_id,
            resources,
            command_label,
        }],
        TurnEvent::ToolError {
            agent,
            call_id,
            tool,
            error,
            kind,
        } => vec![proto::Event::ToolError {
            session_id,
            agent,
            call_id,
            tool,
            error,
            kind,
        }],
        TurnEvent::InferenceFailed {
            agent,
            provider,
            model,
            error_class,
            detail,
        } => vec![proto::Event::InferenceFailed {
            session_id,
            agent,
            provider,
            model,
            error_class,
            detail,
        }],
        TurnEvent::InferenceWarning {
            agent,
            provider,
            model,
            phase,
            waited_secs,
        } => vec![proto::Event::InferenceWarning {
            session_id,
            agent,
            provider,
            model,
            phase,
            waited_secs,
        }],
        TurnEvent::BackupUsed {
            agent,
            primary_model,
            error_class,
            backup_model,
        } => vec![proto::Event::BackupUsed {
            session_id,
            agent,
            primary_model,
            error_class,
            backup_model,
        }],
        TurnEvent::SubagentSpawned {
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
        } => vec![proto::Event::SubagentSpawned {
            session_id,
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
        }],
        TurnEvent::SubagentReport {
            agent,
            task_call_id,
            label,
            report,
            trusted_only,
            model_trusted,
            routing,
        } => {
            vec![proto::Event::SubagentReport {
                session_id,
                agent,
                task_call_id,
                label,
                report,
                trusted_only,
                model_trusted,
                routing,
            }]
        }
        TurnEvent::Usage { agent, usage } => {
            vec![proto::Event::Usage {
                session_id,
                agent,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cached_input_tokens: usage.cached_input_tokens,
                cache_creation_input_tokens: usage.cache_creation_input_tokens,
            }]
        }
        TurnEvent::AgentIdle { turn_id } => {
            vec![proto::Event::AgentIdle {
                session_id,
                turn_id,
            }]
        }
        TurnEvent::PrimarySwapped { name } => {
            vec![proto::Event::PrimarySwapped { session_id, name }]
        }
        TurnEvent::LlmModeChanged { mode } => {
            vec![proto::Event::LlmModeChanged { session_id, mode }]
        }
        // Engine→proto direction never produces this — the `question`
        // tool emits `proto::Event::InterruptRaised` directly through
        // the interrupt hub, and the TUI-client direction
        // (`proto_event_to_turn_event`) is the only place that
        // synthesizes the `TurnEvent` form. No wire event to forward.
        TurnEvent::InterruptRaised { .. } => vec![],
        TurnEvent::ScheduleStarted {
            // The engine stamps the originating session; the worker's own
            // `session_id` is authoritative for the wire event and equals it.
            session_id: _,
            job_id,
            label,
            kind,
        } => vec![proto::Event::ScheduleStarted {
            session_id,
            job_id,
            label,
            kind,
        }],
        TurnEvent::ScheduleProgress { job_id } => {
            vec![proto::Event::ScheduleProgress { session_id, job_id }]
        }
        TurnEvent::ScheduleNote { job_id, text } => {
            vec![proto::Event::ScheduleNote {
                session_id,
                job_id,
                text,
            }]
        }
        TurnEvent::ScheduleCompleted {
            job_id,
            label,
            kind,
            failed,
        } => vec![proto::Event::ScheduleCompleted {
            session_id,
            job_id,
            label,
            kind,
            failed,
        }],
        TurnEvent::ContextProjection {
            prunable_tokens,
            cache_cold,
        } => {
            vec![proto::Event::ContextProjection {
                session_id,
                prunable_tokens,
                cache_cold,
            }]
        }
        TurnEvent::Pruned {
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
        } => vec![proto::Event::Pruned {
            session_id,
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
        }],
        TurnEvent::CompactReady {
            new_session_id,
            handoff,
            brief,
            seed_tool_count,
            seed_tool_tokens,
        } => vec![proto::Event::CompactReady {
            session_id,
            new_session_id,
            handoff,
            brief,
            seed_tool_count,
            seed_tool_tokens,
        }],
        // The engine never emits `SandboxState` — the daemon's
        // `SetSandbox` handler broadcasts the wire event directly (it
        // carries `session_id`). This arm exists only for exhaustiveness.
        TurnEvent::SandboxState {
            mode,
            container_network_enabled,
            container_availability,
        } => {
            vec![proto::Event::SandboxState {
                session_id,
                mode,
                enabled: mode.enabled(),
                container_network_enabled,
                container_availability,
            }]
        }
        // Emitted by `engine::agent::turn` on the sandbox-unavailable refuse
        // path (§6.5). The mapping carries the remedy + session_id verbatim;
        // the per-session de-dupe (fire once per condition, not per failed
        // bash call) lives in the forward seam below, so a repeated failure
        // produces no second broadcast.
        TurnEvent::SandboxUnavailable { remedy } => {
            vec![proto::Event::SandboxUnavailable { session_id, remedy }]
        }
        // The engine never emits `RedactionState` — the daemon's
        // `SetRedaction` handler broadcasts the wire event directly. This
        // arm exists only for exhaustiveness.
        TurnEvent::RedactionState {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
        } => {
            vec![proto::Event::RedactionState {
                session_id,
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            }]
        }
        // Unlike redaction/sandbox, the DRIVER emits `PreflightState` — it
        // owns the session-only override + the toggle resolution (`/preflight`,
        // implementation note). Mapped to the broadcast event here.
        TurnEvent::PreflightState { enabled } => {
            vec![proto::Event::PreflightState {
                session_id,
                enabled,
            }]
        }
        TurnEvent::TrustedOnlyState { enabled } => {
            vec![proto::Event::TrustedOnlyState {
                session_id,
                enabled,
            }]
        }
        TurnEvent::ApprovalModeState { mode } => {
            vec![proto::Event::ApprovalModeState { session_id, mode }]
        }
        TurnEvent::DelegationRecursionState {
            enabled,
            default_depth,
        } => {
            vec![proto::Event::DelegationRecursionState {
                session_id,
                enabled,
                default_depth,
            }]
        }
        // The session gitignore-allowlist push is emitted directly over the
        // per-session bus — by the approval flow's `emit_gitignore_allow`
        // (`InterruptHub`) on change and by `broadcast_gitignore_allow` on
        // attach (implementation note). The engine
        // never routes it through the turn stream; this arm is for
        // exhaustiveness only.
        TurnEvent::GitignoreAllow { .. } => vec![],
        // The model-comparison tandem-set push is broadcast directly by the
        // `SetTandemModels` handler (`model-comparison-tandem-
        // inference.md`); the engine never routes it through the turn stream,
        // so this arm is for exhaustiveness only.
        TurnEvent::TandemState { .. } => vec![],
        // Caffeination is daemon-global, not a session event: the
        // `SetCaffeinate` handler / until-idle watcher broadcast
        // `proto::Event::CaffeinateState` over the global bus directly.
        // The engine never emits this; the arm is for exhaustiveness.
        TurnEvent::CaffeinateState { .. } => vec![],
        // The drain notice is daemon-global, broadcast by the daemon's
        // graceful-shutdown path directly (`server::request_shutdown`); the
        // engine never emits it. This arm is for exhaustiveness only.
        TurnEvent::DaemonDraining { .. } => vec![],
        // A blocked/unblocked `readlock` (`readlock-wait-and-lock-expiry.md`):
        // emitted by the `readlock` tool through the per-turn event stream;
        // forwarded verbatim, scoped to this session so only its attached
        // clients show the transient waiting indicator.
        TurnEvent::WaitingForLock {
            path,
            holder_agent,
            waiting,
        } => vec![proto::Event::WaitingForLock {
            session_id,
            path,
            holder_agent,
            waiting,
        }],
        TurnEvent::QueueUpdated { .. } => vec![],
        TurnEvent::ForegroundInputTarget { .. } => vec![],
        TurnEvent::ConnectorStatus { .. } => vec![],
    }
}

/// The primary agent a new session starts on: the user's configured
/// `defaultPrimaryAgent`, falling back to `Auto` (the conversational
/// front-door router) when unset. The registry uses this when it
/// constructs a fresh session row; the worker uses it for the approver's
/// prompt-attribution agent. Lives here so the constants and
/// event-translation helpers stay in one module.
pub(crate) fn initial_active_agent(cfg: &crate::config::extended::ExtendedConfig) -> &'static str {
    let configured = cfg.default_primary_agent.agent_name();
    // Experimental-mode gate (implementation note): with
    // the flag off, a configured default that points at a gated builtin
    // (`Auto`/`Plan`/…) silently falls back to `Build`. Returning `&'static
    // str` keeps the existing signature: both the configured names and the
    // fallback are statics, so resolve to the canonical static rather than a
    // heap string.
    if !cfg.experimental_mode && crate::agents::is_experimental_primary(configured) {
        crate::agents::FALLBACK_PRIMARY
    } else {
        configured
    }
}

fn queue_item_to_proto(item: crate::engine::message::QueuedUserMessage) -> proto::QueueItem {
    proto::QueueItem {
        id: item.id,
        status: match item.status {
            crate::engine::message::QueueItemStatus::Queued => proto::QueueItemStatus::Queued,
            crate::engine::message::QueueItemStatus::Folding => proto::QueueItemStatus::Folding,
        },
        text: item.text,
        target: queue_target_to_proto(item.target),
    }
}

fn remove_reason_to_proto(
    result: crate::engine::message::RemoveQueuedMessageResult,
) -> proto::RemoveQueuedUserMessageReason {
    match result {
        crate::engine::message::RemoveQueuedMessageResult::Removed => {
            proto::RemoveQueuedUserMessageReason::Removed
        }
        crate::engine::message::RemoveQueuedMessageResult::AlreadyStarted => {
            proto::RemoveQueuedUserMessageReason::AlreadyStarted
        }
        crate::engine::message::RemoveQueuedMessageResult::NotFound => {
            proto::RemoveQueuedUserMessageReason::NotFound
        }
    }
}

fn queue_target_to_proto(target: crate::engine::message::QueueTarget) -> proto::QueueTarget {
    proto::QueueTarget {
        id: target.id,
        agent: target.agent,
        depth: target.depth,
        task_call_id: target.task_call_id,
    }
}

fn log_seed_tool_drain_failed(session_id: Uuid, error: &anyhow::Error) {
    tracing::warn!(
        session_id = %session_id,
        error = %error,
        "seed-tool replay skipped because draining persisted seed tools failed"
    );
}

/// Resolve the root-frame primary for a session: its stored active agent
/// (so a resume restarts on whatever `Auto` handed off to, or a `/plan`
/// swap landed on), falling back to the configured default
/// ([`initial_active_agent`]) when unset/unknown. `Auto`, `Build`, and
/// `Plan` are the primary-mode agents; anything else degrades to the
/// default. Shared by [`spawn`] (the handle's initial chrome slot) and
/// [`run_worker`] (the agent it actually loads) so both agree.
pub(crate) fn resolve_root_agent(
    session_id: Uuid,
    db: &crate::db::Db,
    cfg: &crate::config::extended::ExtendedConfig,
) -> String {
    db.with_conn(|conn| Ok(resolve_root_agent_conn(conn, session_id, cfg)))
        .unwrap_or_else(|_| initial_active_agent(cfg).to_string())
}

pub(crate) fn resolve_root_agent_conn(
    conn: &Connection,
    session_id: Uuid,
    cfg: &crate::config::extended::ExtendedConfig,
) -> String {
    crate::db::Db::get_session_conn(conn, session_id)
        .ok()
        .flatten()
        .map(|row| row.active_agent)
        .filter(|name| {
            matches!(
                name.as_str(),
                "Auto" | "Plan" | "Build" | "Swarm" | "Multireview"
            )
        })
        // Experimental-mode gate (implementation note): a
        // session persisted on a now-gated primary (e.g. last on `Swarm`,
        // experimental since turned off) silently loads on `Build` instead —
        // no notice. With the flag on, the stored value is honored.
        .map(|name| crate::agents::resolve_primary_for_flag(&name, cfg.experimental_mode))
        .unwrap_or_else(|| initial_active_agent(cfg).to_string())
}

/// Resolve the effective LLM mode for the session's active (provider, model)
/// against the override chain (implementation note): model
/// `mode` → provider `mode` → the persisted global `llm_mode` (`global`). When
/// no model is active or the providers config can't be loaded, the global
/// value passes through unchanged. Same first-hit config-layer rule as the
/// rest of the worker.
fn resolve_effective_llm_mode(
    session: &Session,
    project_root: &std::path::Path,
    global: crate::config::extended::LlmMode,
) -> crate::config::extended::LlmMode {
    use crate::config::providers::ConfigDoc;
    let (Some(provider), Some(model)) = (session.active_provider(), session.active_model()) else {
        return global;
    };
    ConfigDoc::load_effective(project_root).resolve_mode(&provider, &model, global)
}

/// Persist a live `/llm-mode` switch to the layered config so a resume
/// keeps it (implementation note). Writes to the
/// highest-precedence existing `config.json` on the discovered
/// path (the layer `load_for_cwd` would read), or — when none exists yet —
/// scaffolds one in the project `.cockpit/` so `/settings` + the config
/// file + `/llm-mode` all resolve to the same value. Round-trips through
/// [`ExtendedConfigDoc`] so unknown keys (including sibling layer/provider
/// metadata) survive.
fn persist_llm_mode(
    project_root: &std::path::Path,
    mode: crate::config::extended::LlmMode,
) -> anyhow::Result<()> {
    use crate::config::dirs::{CONFIG_FILE, discover_config_dirs};
    use crate::config::extended::ExtendedConfigDoc;
    let target = discover_config_dirs(project_root)
        .into_iter()
        .map(|d| d.path.join(CONFIG_FILE))
        .find(|p| p.exists())
        .unwrap_or_else(|| project_root.join(".cockpit").join(CONFIG_FILE));
    let mut doc = ExtendedConfigDoc::load(&target)?;
    let mut cfg = doc.config();
    cfg.llm_mode = mode;
    doc.write(&cfg)?;
    Ok(())
}

/// Env var the daemon sets at boot when launched with `--no-sandbox`
/// (sandboxing part 2). Read per session-spawn to apply the
/// highest-precedence "OFF for ALL sessions" rule. Set internally only
/// (Layer B style); never a user-facing surface.
pub const DAEMON_NO_SANDBOX_ENV: &str = "COCKPIT_DAEMON_NO_SANDBOX";

/// Whether the running daemon was launched with `--no-sandbox`.
fn daemon_no_sandbox() -> bool {
    std::env::var_os(DAEMON_NO_SANDBOX_ENV).is_some()
}

/// Resolve the new-session sandbox default from the live daemon flag.
fn resolve_sandbox_default(
    client_no_sandbox: bool,
    configured_default: crate::tools::sandbox_mode::SandboxMode,
) -> crate::tools::sandbox_mode::SandboxMode {
    resolve_sandbox_default_with(daemon_no_sandbox(), client_no_sandbox, configured_default)
}

/// Pure precedence resolver (highest wins): daemon `--no-sandbox` ->
/// client `--no-sandbox` -> sandbox mode. Factored out from
/// [`resolve_sandbox_default`] so the precedence can be unit-tested without
/// touching process env.
fn resolve_sandbox_default_with(
    daemon_no_sandbox: bool,
    client_no_sandbox: bool,
    configured_default: crate::tools::sandbox_mode::SandboxMode,
) -> crate::tools::sandbox_mode::SandboxMode {
    if daemon_no_sandbox || client_no_sandbox {
        return crate::tools::sandbox_mode::SandboxMode::Off;
    }
    if configured_default.is_container() && !crate::container::availability_snapshot().available {
        crate::tools::sandbox_mode::SandboxMode::Sandbox
    } else {
        configured_default
    }
}

/// Resolve the per-session async-jobs concurrency cap (GOALS §22) from the
/// layered `config.json` rooted at `project_root`, falling back
/// to the default when none is configured.
fn max_concurrent_schedules_for(project_root: &std::path::Path) -> usize {
    crate::config::extended::load_for_cwd(project_root)
        .schedule
        .max_concurrent
}

/// Resolve the loop-guard threshold (GOALS §1/§12) from the layered
/// `config.json` rooted at `project_root`, falling back to the
/// default (2 = fire on the first exact repeat) when none is configured.
fn loop_guard_threshold_for(project_root: &std::path::Path) -> u32 {
    crate::config::extended::load_for_cwd(project_root)
        .loop_guard
        .effective_threshold()
}

fn max_primary_rounds_for(project_root: &std::path::Path) -> u32 {
    crate::config::extended::load_for_cwd(project_root).max_primary_rounds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use std::io;
    use std::sync::Mutex as StdMutex;
    use tracing::Level;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CaptureWriter(std::sync::Arc<StdMutex<Vec<u8>>>);

    struct CaptureGuard(std::sync::Arc<StdMutex<Vec<u8>>>);

    impl io::Write for CaptureGuard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CaptureGuard(self.0.clone())
        }
    }

    fn capture_warn_log(f: impl FnOnce()) -> String {
        let bytes = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_ansi(false)
            .with_writer(CaptureWriter(bytes.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
    }

    #[tokio::test]
    async fn turn_refresh_sends_rebuilt_redaction_table_to_driver() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join(".env"),
            "SESSION_REFRESH_SECRET=worker-secret\n",
        )
        .unwrap();
        let (event_tx, _event_rx) = broadcast::channel(8);
        let (driver_tx, mut driver_rx) = mpsc::channel(1);
        let mut notified = HashSet::new();

        refresh_redaction_for_turn(
            Uuid::new_v4(),
            tmp.path(),
            &RedactionSourceOverrides::default(),
            &mut notified,
            &event_tx,
            &driver_tx,
            &HashMap::new(),
        )
        .await;

        let crate::engine::driver::DriverControl::SetRedaction { table, .. } =
            driver_rx.recv().await.unwrap()
        else {
            panic!("unexpected driver control");
        };
        let scrubbed = table.scrub("worker-secret");
        assert!(!scrubbed.contains("worker-secret"));
        assert!(scrubbed.contains("REDACTED"));
    }

    #[test]
    fn session_driver_failed_event_is_latched() {
        let (event_tx, mut event_rx) = broadcast::channel(8);
        let session_id = Uuid::new_v4();
        let mut driver_failed = false;

        emit_session_driver_failed_once(
            &event_tx,
            session_id,
            &mut driver_failed,
            "first failure".to_string(),
        );
        emit_session_driver_failed_once(
            &event_tx,
            session_id,
            &mut driver_failed,
            "second failure".to_string(),
        );

        let event = event_rx.try_recv().unwrap();
        assert!(matches!(
            event,
            proto::Event::SessionDriverFailed { session_id: id, error }
                if id == session_id && error == "first failure"
        ));
        assert!(
            event_rx.try_recv().is_err(),
            "failure event is emitted once"
        );
    }

    #[tokio::test]
    async fn driver_join_outcome_observes_panics() {
        let handle = tokio::spawn(async {
            panic!("driver panic for test");
            #[allow(unreachable_code)]
            DriverOutcome::Ok
        });

        let outcome = driver_join_outcome(handle.await);

        assert!(
            matches!(outcome, DriverOutcome::Panicked(error) if error == "driver panic for test")
        );
    }

    /// An [`ExtendedConfig`] pinning `defaultPrimaryAgent` + the
    /// experimental flag, for the gate tests.
    fn cfg_with(
        default_primary: crate::config::extended::DefaultPrimaryAgent,
        experimental: bool,
    ) -> crate::config::extended::ExtendedConfig {
        crate::config::extended::ExtendedConfig {
            default_primary_agent: default_primary,
            experimental_mode: experimental,
            ..Default::default()
        }
    }

    #[test]
    fn initial_active_agent_gates_default_to_build_when_off() {
        use crate::config::extended::DefaultPrimaryAgent as D;
        // Off: a gated configured default (Auto/Plan) resolves to Build.
        assert_eq!(initial_active_agent(&cfg_with(D::Auto, false)), "Build");
        assert_eq!(initial_active_agent(&cfg_with(D::Plan, false)), "Build");
        // Off: Build is honored (not gated).
        assert_eq!(initial_active_agent(&cfg_with(D::Build, false)), "Build");
        // On: the configured default is honored.
        assert_eq!(initial_active_agent(&cfg_with(D::Auto, true)), "Auto");
        assert_eq!(initial_active_agent(&cfg_with(D::Plan, true)), "Plan");
    }

    #[test]
    fn seed_tool_drain_failure_warns_with_session_id_without_payload() {
        let session_id = Uuid::new_v4();
        let log = capture_warn_log(|| {
            let error = anyhow::anyhow!("db unavailable");
            log_seed_tool_drain_failed(session_id, &error);
        });

        assert!(log.contains(&session_id.to_string()));
        assert!(log.contains("seed-tool replay skipped"));
        assert!(log.contains("db unavailable"));
        assert!(!log.contains("prompt text"));
        assert!(!log.contains("tool output"));
    }

    #[test]
    fn resolve_root_agent_stale_gated_session_falls_back_to_build() {
        use crate::config::extended::DefaultPrimaryAgent as D;
        let db = crate::db::Db::open_in_memory().unwrap();
        // A session persisted on a gated primary (`Plan`), experimental off →
        // loads on `Build`. (`Swarm` is not resume-eligible per
        // the active-agent filter, so they degrade via the default path —
        // also `Build` when off.)
        let row = db.create_session("proj", "/proj", "Plan").unwrap();
        assert_eq!(
            resolve_root_agent(row.session_id, &db, &cfg_with(D::Auto, false)),
            "Build"
        );
        // Same persisted session, experimental on → the stored value stands.
        assert_eq!(
            resolve_root_agent(row.session_id, &db, &cfg_with(D::Auto, true)),
            "Plan"
        );
    }

    #[test]
    fn sandbox_default_precedence_daemon_wins() {
        use crate::tools::sandbox_mode::SandboxMode;

        // (a) daemon `--no-sandbox` -> OFF regardless of the client flag.
        assert_eq!(
            resolve_sandbox_default_with(true, false, SandboxMode::Sandbox),
            SandboxMode::Off
        );
        assert_eq!(
            resolve_sandbox_default_with(true, true, SandboxMode::Container),
            SandboxMode::Off
        );
    }

    #[test]
    fn sandbox_default_precedence_client_then_on() {
        use crate::tools::sandbox_mode::SandboxMode;

        // (b) no daemon flag, client `--no-sandbox` -> OFF.
        assert_eq!(
            resolve_sandbox_default_with(false, true, SandboxMode::Container),
            SandboxMode::Off
        );
        // (c) neither flag -> ON.
        assert_eq!(
            resolve_sandbox_default_with(false, false, SandboxMode::Sandbox),
            SandboxMode::Sandbox
        );
    }

    /// The concurrent-write-during-plan warning fires once per plan episode per
    /// session, re-arms on a different plan, and is mode-aware
    /// (`plan-concurrent-build-and-merge.md`).
    #[test]
    fn lifecycle_turn_id_maps_to_proto_events() {
        let sid = Uuid::new_v4();
        let out = turn_event_to_proto(
            TurnEvent::ThinkingStarted {
                agent: "Build".to_string(),
                turn_id: Some("turn-1".to_string()),
            },
            sid,
        );
        match out.as_slice() {
            [
                proto::Event::ThinkingStarted {
                    session_id,
                    agent,
                    turn_id,
                },
            ] => {
                assert_eq!(*session_id, sid);
                assert_eq!(agent, "Build");
                assert_eq!(turn_id.as_deref(), Some("turn-1"));
            }
            other => panic!("expected one ThinkingStarted, got {other:?}"),
        }

        let out = turn_event_to_proto(
            TurnEvent::AgentIdle {
                turn_id: Some("turn-1".to_string()),
            },
            sid,
        );
        match out.as_slice() {
            [
                proto::Event::AgentIdle {
                    session_id,
                    turn_id,
                },
            ] => {
                assert_eq!(*session_id, sid);
                assert_eq!(turn_id.as_deref(), Some("turn-1"));
            }
            other => panic!("expected one AgentIdle, got {other:?}"),
        }
    }

    #[test]
    fn live_foreground_snapshot_tracks_nested_active_subagent() {
        let foreground = Arc::new(Mutex::new(LiveForegroundState::new("Build".to_string())));
        let target = Arc::new(Mutex::new(crate::engine::message::QueueTarget::root(
            "Build",
        )));

        update_live_foreground(
            &foreground,
            &target,
            &TurnEvent::SubagentSpawned {
                parent: "Build".into(),
                child: "builder".into(),
                task_call_id: "task-1".into(),
                label: "default".into(),
                prompt: "build it".into(),
                requested_cwd: None,
                resolved_cwd: None,
                trusted_only: false,
                model_trusted: false,
                routing: serde_json::json!({}),
            },
        );
        update_live_foreground(
            &foreground,
            &target,
            &TurnEvent::ForegroundInputTarget {
                target: crate::engine::message::QueueTarget::child(
                    "builder", 1, "task-1", "default",
                ),
            },
        );
        update_live_foreground(
            &foreground,
            &target,
            &TurnEvent::SubagentSpawned {
                parent: "builder".into(),
                child: "bee".into(),
                task_call_id: "task-2".into(),
                label: "default".into(),
                prompt: "continue".into(),
                requested_cwd: None,
                resolved_cwd: None,
                trusted_only: false,
                model_trusted: false,
                routing: serde_json::json!({}),
            },
        );

        let snap = foreground.lock().unwrap().snapshot();
        assert_eq!(snap.active_agent_path, ["Build", "builder", "bee"]);
        assert_eq!(snap.foreground_target.agent, "bee");
        assert_eq!(snap.foreground_target.depth, 2);
        let active = snap.active_subagent.expect("active subagent descriptor");
        assert_eq!(active.parent, "builder");
        assert_eq!(active.child, "bee");
        assert_eq!(active.task_call_id, "task-2");

        update_live_foreground(
            &foreground,
            &target,
            &TurnEvent::SubagentReport {
                agent: "bee".into(),
                task_call_id: "task-2".into(),
                label: "default".into(),
                report: "done".into(),
                trusted_only: false,
                model_trusted: false,
                routing: serde_json::json!({}),
            },
        );
        let snap = foreground.lock().unwrap().snapshot();
        assert_eq!(snap.active_agent_path, ["Build", "builder"]);
        assert_eq!(snap.foreground_target.agent, "builder");
        assert_eq!(snap.foreground_target.depth, 1);
        assert_eq!(
            snap.active_subagent.as_ref().map(|sub| sub.child.as_str()),
            Some("builder")
        );
    }

    /// §6.5: the sandbox-unavailable `TurnEvent` maps to the wire broadcast
    /// carrying the session_id + the verbatim diagnosed remedy.
    #[test]
    fn sandbox_unavailable_maps_to_broadcast_with_remedy() {
        let sid = Uuid::new_v4();
        let remedy = "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); \
             `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` re-enables confinement"
            .to_string();
        let out = turn_event_to_proto(
            TurnEvent::SandboxUnavailable {
                remedy: remedy.clone(),
            },
            sid,
        );
        match out.as_slice() {
            [
                proto::Event::SandboxUnavailable {
                    session_id,
                    remedy: r,
                },
            ] => {
                assert_eq!(*session_id, sid);
                assert_eq!(r, &remedy);
                // The user-facing remedy names the exact host command.
                assert!(r.contains("sudo sysctl"));
            }
            other => panic!("expected one SandboxUnavailable, got {other:?}"),
        }
    }

    /// §6.5 de-dupe: the latch fires the broadcast exactly once per condition.
    /// Two failed `bash` calls (two `SandboxUnavailable` events) → one forward;
    /// `set_sandbox` re-arms it (clearing the latch) so a renewed condition
    /// after a `/sandbox` toggle can surface a fresh notice.
    #[test]
    fn sandbox_unavailable_dedupes_per_session() {
        let armed = AtomicBool::new(false);
        // First failed bash → forward.
        assert!(forward_sandbox_unavailable(&armed));
        // Second (and any further) failed bash in the same condition → drop.
        assert!(!forward_sandbox_unavailable(&armed));
        assert!(!forward_sandbox_unavailable(&armed));
        // `/sandbox` toggle re-arms (the latch the handle clears).
        armed.store(false, Ordering::SeqCst);
        // A renewed unavailable condition surfaces once more, then de-dupes.
        assert!(forward_sandbox_unavailable(&armed));
        assert!(!forward_sandbox_unavailable(&armed));
    }

    // ── Session-detach lock release edges (`session-detach-lock-release.md`) ──

    use std::sync::atomic::AtomicUsize;

    /// The detach edge fires only on the LAST detach (count 1→0) while idle.
    #[test]
    fn detach_should_release_only_on_last_detach_while_idle() {
        // Last detach (1→0), idle → release.
        assert!(detach_should_release(1, false));
        // Last detach but mid-turn → do NOT release.
        assert!(!detach_should_release(1, true));
        // Not the last client (2→1) → do NOT release, idle or not.
        assert!(!detach_should_release(2, false));
        assert!(!detach_should_release(2, true));
        // No clients to begin with → nothing.
        assert!(!detach_should_release(0, false));
    }

    /// Build a guard with injected state, bypassing the full worker `spawn`.
    fn test_guard(
        counter: Arc<AtomicUsize>,
        session_id: Uuid,
        locks: Arc<LockManager>,
        live: Arc<LiveState>,
    ) -> InteractiveClientGuard {
        counter.fetch_add(1, Ordering::SeqCst);
        InteractiveClientGuard {
            counter,
            session_id,
            locks,
            live,
        }
    }

    async fn wait_until<F>(mut predicate: F)
    where
        F: FnMut() -> bool,
    {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !predicate() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("condition became true");
    }

    /// Dropping the LAST interactive guard while the session is idle releases
    /// the session's locks (the detach edge), and a blocked cross-session
    /// waiter would be woken (the release calls `notify_waiters`).
    #[tokio::test]
    async fn last_detach_while_idle_releases_locks() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        std::fs::write(&p, "x").unwrap();
        let db = Db::open_in_memory().unwrap();
        let sid = db.create_session("p", "/x", "builder").unwrap().session_id;
        let locks = Arc::new(LockManager::in_memory(db));
        locks.acquire(&p, "builder", sid).unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(LiveState::default()); // not processing = idle
        let guard = test_guard(counter.clone(), sid, locks.clone(), live);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        drop(guard); // last detach, idle → release
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(
            locks.holder(&p).is_some(),
            "drop must only schedule cleanup, not hash/release inline"
        );
        wait_until(|| locks.holder(&p).is_none()).await;
        assert!(
            locks.holder(&p).is_none(),
            "scheduled idle last-detach cleanup must release the session's lock"
        );
    }

    #[tokio::test]
    async fn quick_reattach_skips_scheduled_unattended_release() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        std::fs::write(&p, "x").unwrap();
        let db = Db::open_in_memory().unwrap();
        let sid = db.create_session("p", "/x", "builder").unwrap().session_id;
        let locks = Arc::new(LockManager::in_memory(db));
        locks.acquire(&p, "builder", sid).unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(LiveState::default());
        let guard = test_guard(counter.clone(), sid, locks.clone(), live.clone());
        drop(guard);
        let _reattached = test_guard(counter.clone(), sid, locks.clone(), live);

        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            locks.holder(&p).map(|(_, a)| a).as_deref(),
            Some("builder"),
            "scheduled cleanup must skip when a client reattaches"
        );
    }

    /// A mid-turn detach (the agent is still processing) does NOT release; the
    /// idle backstop does the release once the turn ends.
    #[tokio::test]
    async fn mid_turn_detach_keeps_locks_then_idle_releases() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        std::fs::write(&p, "x").unwrap();
        let db = Db::open_in_memory().unwrap();
        let sid = db.create_session("p", "/x", "builder").unwrap().session_id;
        let locks = Arc::new(LockManager::in_memory(db));
        locks.acquire(&p, "builder", sid).unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(LiveState::default());
        live.processing.store(true, Ordering::SeqCst); // mid-turn
        let guard = test_guard(counter.clone(), sid, locks.clone(), live.clone());

        drop(guard); // last detach, but mid-turn → NO release
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(
            locks.holder(&p).is_some(),
            "mid-turn detach must NOT release the lock"
        );

        // Turn ends → the AgentIdle edge (count already zero) releases. The
        // forward seam runs this exact branch; assert its decision + effect.
        live.processing.store(false, Ordering::SeqCst);
        if counter.load(Ordering::SeqCst) == 0 {
            schedule_session_locks_unattended(
                locks.clone(),
                counter.clone(),
                live.clone(),
                sid,
                "test idle edge",
            );
        }
        wait_until(|| locks.holder(&p).is_none()).await;
        assert!(
            locks.holder(&p).is_none(),
            "the idle edge releases the lock the mid-turn detach left held"
        );
    }

    /// Multi-attach: a second guard means the first detach (2→1) releases
    /// nothing; only the last detach (1→0) does.
    #[tokio::test]
    async fn multi_attach_releases_only_on_last_detach() {
        let tmp = tempfile::TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        std::fs::write(&p, "x").unwrap();
        let db = Db::open_in_memory().unwrap();
        let sid = db.create_session("p", "/x", "builder").unwrap().session_id;
        let locks = Arc::new(LockManager::in_memory(db));
        locks.acquire(&p, "builder", sid).unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(LiveState::default());
        let g1 = test_guard(counter.clone(), sid, locks.clone(), live.clone());
        let g2 = test_guard(counter.clone(), sid, locks.clone(), live.clone());
        assert_eq!(counter.load(Ordering::SeqCst), 2);

        drop(g1); // 2→1: NOT the last detach → no release
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(
            locks.holder(&p).is_some(),
            "a non-last detach must not release"
        );

        drop(g2); // 1→0: last detach, idle → release
        wait_until(|| locks.holder(&p).is_none()).await;
        assert!(
            locks.holder(&p).is_none(),
            "the last detach releases the session's lock"
        );
    }
}
