use anyhow::Context;

use super::{helpers::*, lifecycle::*, run::run_worker, *};

/// Handle one or more client tasks hold to drive a session. Cheap to
/// clone — both channels inside are reference-counted.
#[derive(Clone)]
pub struct SessionWorkerHandle {
    pub session_id: Uuid,
    pub project_root: PathBuf,
    pub active_agent_name: String,
    /// Current daemon-authoritative workspace policy.  This is shared with
    /// the long-lived worker/driver task so a durable trust transition cannot
    /// leave a live session running under an attach-time copy of `Trust`.
    trust_policy: crate::config::trust::SharedWorkspaceTrustPolicy,
    /// Durable revision of `trust_policy`. This daemon-private tag lets a
    /// worker reject a refresh that was resolved before a later trust
    /// transition, without putting a database detail in task-local authority.
    trust_revision: Arc<std::sync::atomic::AtomicI64>,
    /// Set between a durable trust decision and publication of its matching
    /// provider projection. Setup snapshots fail closed while this is true.
    /// Revision currently being reconciled, or zero when the retained
    /// projection is current. Revision ownership prevents an older refresh
    /// from clearing a newer transition's admission gate.
    trust_transition_pending: Arc<std::sync::atomic::AtomicI64>,
    /// Attach-time directory authority for every workspace-local config
    /// refresh.  This is deliberately not a path-derived capability.
    pub(crate) workspace_root_authority:
        Arc<crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority>,
    work_tx: mpsc::Sender<SessionWork>,
    event_tx: EventSender,
    turn_completions: Arc<Mutex<TurnCompletions>>,
    redaction: SharedRedactionTable,
    /// Injection-only session values. Never exposed over proto or Debug.
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
    pub(super) sandbox_unavailable_notice: Arc<RwLock<Option<SandboxUnavailableNotice>>>,
    /// The daemon-wide lock authority, so the last-detach-while-idle edge can
    /// release this session's locks (implementation note).
    /// The `InteractiveClientGuard`'s `Drop` consults it; the `AgentIdle` edge
    /// lives in the worker's forward seam, which holds its own clone.
    locks: Arc<LockManager>,
    env_overlay: Arc<RwLock<HashMap<String, String>>>,
    repair_required: Arc<RwLock<Option<proto::ResumeRepairState>>>,
    foreground: Arc<Mutex<LiveForegroundState>>,
    pub(super) config_snapshot: Arc<RwLock<SessionConfigSnapshot>>,
    /// Async fence pairing a setup-snapshot read with worker config
    /// publication. Readers may hold it across database awaits without
    /// blocking a runtime thread; refresh publishers take the exclusive side.
    config_publication: Arc<tokio::sync::RwLock<()>>,
    /// Last daemon-authoritative model state emitted by this worker. Updated
    /// before the corresponding broadcast so a later attach cannot fall back
    /// to a config snapshot that still lags a successful default write.
    authoritative_active_model_state: Arc<RwLock<Option<proto::ActiveModelState>>>,
    /// Shared park-commit rendezvous
    /// (`daemon-lifecycle-replay-timing-robustness.md`). Created here, wired
    /// into the worker's `InterruptHub`, and read by the registry's drain path
    /// (to gate `metadata_guard.cleanup()` on every registered interrupt's park
    /// commit) and by the attach path (to wait for the worker's startup
    /// reconciliation pass before returning).
    park_commit: crate::engine::interrupt::ParkCommit,
    /// Identity the worker reserved for the session-root agent instance at
    /// spawn. Setup snapshots fall back to this before the durable
    /// `agent_instances` row exists; resume still prefers the DB root.
    reserved_root_agent_instance_id: Uuid,
}

const RECENT_TURN_COMPLETION_CAPACITY: usize = 64;

/// Terminal outcome of one dispatched turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnOutcome {
    Completed { reason: proto::IdleReason },
    Failed { error: String },
}

#[derive(Debug, Default)]
pub(super) struct TurnCompletions {
    pending: HashMap<String, Vec<oneshot::Sender<TurnOutcome>>>,
    recent: VecDeque<(String, TurnOutcome)>,
    closed: bool,
}

impl TurnCompletions {
    pub(super) fn watch(&mut self, turn_id: &str) -> oneshot::Receiver<TurnOutcome> {
        let (tx, rx) = oneshot::channel();
        if self.closed {
            drop(tx);
            return rx;
        }
        if let Some((_, outcome)) = self
            .recent
            .iter()
            .rev()
            .find(|(completed_turn_id, _)| completed_turn_id == turn_id)
        {
            let _ = tx.send(outcome.clone());
            return rx;
        }
        self.pending
            .entry(turn_id.to_string())
            .or_default()
            .push(tx);
        rx
    }

    fn resolve(&mut self, turn_id: String, outcome: TurnOutcome) {
        if self.closed {
            return;
        }
        if let Some(watchers) = self.pending.remove(&turn_id) {
            for watcher in watchers {
                let _ = watcher.send(outcome.clone());
            }
        }
        self.recent.push_back((turn_id, outcome));
        while self.recent.len() > RECENT_TURN_COMPLETION_CAPACITY {
            self.recent.pop_front();
        }
    }

    fn fail_all_pending(&mut self, error: String) {
        if self.closed {
            return;
        }
        let pending = std::mem::take(&mut self.pending);
        for watchers in pending.into_values() {
            for watcher in watchers {
                let _ = watcher.send(TurnOutcome::Failed {
                    error: error.clone(),
                });
            }
        }
    }

    fn close_all_pending(&mut self) {
        self.closed = true;
        self.pending.clear();
    }

    #[cfg(test)]
    fn has_pending(&self, turn_id: &str) -> bool {
        self.pending
            .get(turn_id)
            .is_some_and(|watchers| !watchers.is_empty())
    }
}

pub(super) fn resolve_turn_terminal_event(
    completions: &Arc<Mutex<TurnCompletions>>,
    event: &proto::Event,
) {
    let mut completions = completions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match event {
        proto::Event::AgentIdle {
            turn_id: Some(turn_id),
            reason,
            ..
        } => completions.resolve(
            turn_id.clone(),
            TurnOutcome::Completed {
                reason: reason.clone(),
            },
        ),
        proto::Event::SessionDriverFailed {
            turn_id: Some(turn_id),
            error,
            ..
        } => completions.resolve(
            turn_id.clone(),
            TurnOutcome::Failed {
                error: error.clone(),
            },
        ),
        proto::Event::SessionDriverFailed {
            turn_id: None,
            error,
            ..
        } => completions.fail_all_pending(error.clone()),
        proto::Event::AgentIdle { turn_id: None, .. } => {}
        _ => {}
    }
}

pub(super) fn close_pending_turn_completions(completions: &Arc<Mutex<TurnCompletions>>) {
    completions
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .close_all_pending();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SandboxUnavailableNotice {
    pub(super) remedy: String,
    pub(super) fix_command: Option<String>,
}

/// Ordinary work was refused because this worker's admission gate is closed
/// while a committed workspace-trust decision is projected onto it.
///
/// It is a distinct type rather than a message so the daemon's request layer
/// can downcast it and answer `ErrorCode::RetryLater`: re-sending the exact
/// same work is the documented recovery, unlike every other `send_work`
/// failure (a shut-down worker), which is terminal for that handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionWorkTrustReconciling {
    pub session_id: Uuid,
}

impl std::fmt::Display for SessionWorkTrustReconciling {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "session worker {} is reconciling workspace trust",
            self.session_id
        )
    }
}

impl std::error::Error for SessionWorkTrustReconciling {}

pub(super) struct WorkerCleanupGuard(Option<Box<dyn FnOnce() + Send + 'static>>);

impl Drop for WorkerCleanupGuard {
    fn drop(&mut self) {
        if let Some(cleanup) = self.0.take() {
            cleanup();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DriverOutcome {
    Ok,
    Err(String),
    Panicked(String),
}

impl DriverOutcome {
    pub(super) fn failure_error(&self) -> Option<&str> {
        match self {
            DriverOutcome::Ok => None,
            DriverOutcome::Err(error) | DriverOutcome::Panicked(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkerStop {
    Shutdown {
        pause_for_resume: bool,
        active: bool,
        pending_tool_count: i64,
    },
    DriverFailed,
    DriverExited,
    WorkerStopped,
}

impl WorkerStop {
    pub(super) fn session_ended_reason(&self) -> &'static str {
        match self {
            WorkerStop::DriverFailed => "driver failed",
            WorkerStop::DriverExited => "driver exited",
            WorkerStop::Shutdown { .. } | WorkerStop::WorkerStopped => "worker stopped",
        }
    }

    /// Closed, deterministic map from a worker-teardown cause onto the
    /// `sessionEnd` hook matcher (Decision 3). This is the ONLY authority for
    /// the matcher; callers must not re-derive it from the human-readable
    /// [`Self::session_ended_reason`] proto text. Exhaustive over every
    /// `WorkerStop` variant (no `_`) so a future teardown cause is a compile
    /// error here rather than a silent mis-map. The matcher token is one of the
    /// closed config set `completed | interrupted | cancelled | shutdown |
    /// error` (`config/extended/hooks.rs` `HookEvent::SessionEnd` policy):
    ///
    /// - a failed driver ⇒ `error`
    /// - a driver that exited on its own ⇒ `completed`
    /// - a resumable (`pause_for_resume: true`) daemon drain ⇒ `shutdown`
    ///   (the session stays resumable rather than ending)
    /// - a non-resumable shutdown or an explicit worker stop ⇒ `completed`
    ///
    /// `interrupted` / `cancelled` are reserved matcher tokens for future
    /// teardown causes; today no `WorkerStop` variant classifies them, so they
    /// are intentionally not produced (mapping to them would be a
    /// plausible-but-wrong value). When such a cause is added, extend
    /// `WorkerStop` and this match together.
    pub(super) fn session_end_matcher(&self) -> &'static str {
        match self {
            WorkerStop::DriverFailed => "error",
            WorkerStop::DriverExited => "completed",
            WorkerStop::Shutdown {
                pause_for_resume: true,
                ..
            } => "shutdown",
            WorkerStop::Shutdown {
                pause_for_resume: false,
                ..
            }
            | WorkerStop::WorkerStopped => "completed",
        }
    }
}

pub(super) fn driver_join_outcome(
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

pub(super) fn send_sandbox_unavailable_notice(
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
    notice: &SandboxUnavailableNotice,
) {
    send_current_event(
        event_tx,
        redaction,
        proto::Event::SandboxUnavailable {
            session_id,
            remedy: notice.remedy.clone(),
            fix_command: notice.fix_command.clone(),
        },
    );
}

#[derive(Clone)]
pub(crate) struct HostCapabilityRefreshRuntime {
    pub(crate) store: crate::host_capabilities::HostCapabilitySnapshotStore,
    pub(crate) probes: crate::host_capabilities::HostCapabilityProbeInputs,
    /// One daemon can own many sessions, but snapshots share one live store.
    /// The store-wide dispatcher serializes globally ordered durable outbox
    /// replay, probe → receipt → publication, so a later session cannot stage
    /// a generation before an earlier session's receipt is acknowledged.
    pub(crate) serial_execution: std::sync::Arc<tokio::sync::Mutex<()>>,
    /// A durable operation has at most one local dispatcher task. Other
    /// callers return promptly and the worker's bounded maintenance tick
    /// retries after the owner exits or a lease is reaped.
    pub(crate) in_flight_operations:
        std::sync::Arc<std::sync::Mutex<std::collections::HashSet<Uuid>>>,
}

#[derive(Debug, Clone)]
pub(crate) struct HostCapabilitiesRefreshCompletion {
    pub snapshot: cockpit_proto::HostCapabilitySnapshot,
    pub published: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostCapabilitiesRefreshError {
    Declined,
    Internal(String),
}

impl std::fmt::Debug for HostCapabilityRefreshRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostCapabilityRefreshRuntime")
            .finish_non_exhaustive()
    }
}

/// First published session-config generation. `0` is unpublished: no snapshot
/// has been installed on a live worker, and image-generation owner, plan, and
/// output-directory gates reject it. A quiet session therefore cannot remain
/// at `0` waiting for an unrelated file event.
pub const FIRST_PUBLISHED_CONFIG_GENERATION: u64 = 1;

#[derive(Debug, Clone)]
pub struct SessionConfigSnapshot {
    /// Published configuration generation. `0` is unpublished; the first live
    /// session snapshot uses [`FIRST_PUBLISHED_CONFIG_GENERATION`].
    pub generation: u64,
    /// Durable workspace-trust revision that produced this projection. It is
    /// only a worker-side CAS fence and is never exposed in the protocol.
    pub(crate) trust_revision: i64,
    pub providers: crate::config::providers::ProvidersConfig,
    /// Daemon-private source proofs for provider/model choices visible in
    /// this generation. They are derived from capability-captured layer bytes
    /// and deliberately never cross the protocol or diagnostic boundary.
    pub(crate) provider_model_sources:
        HashMap<(String, String), cockpit_config::config::providers::RetainedProviderModelSource>,
    pub extended: crate::config::extended::ExtendedConfig,
    pub guidance_global_layer: Option<bool>,
    pub guidance_project_layer: Option<bool>,
    /// Turn-pinned hook registry resolved under the same workspace-trust scope
    /// and generation as providers/extended config. A config reload affects
    /// later turns only; no hook set changes between `preToolUse` and its
    /// matching post event.
    pub hooks: crate::config::extended::hooks::HookRegistry,
    /// Injected host capabilities used to compute effective sandbox mode.
    /// Unpublished (empty features) leaves host Sandbox usable; Refuse is
    /// the fail-closed backstop.
    pub host_capabilities: cockpit_proto::HostCapabilitySnapshot,
    /// Daemon-composition-only host probe runtime.  It is not config and is
    /// intentionally retained when a config watcher replaces the surrounding
    /// snapshot, so a recovered allowed refresh always has the same host-owned
    /// execution seam available.
    pub(crate) host_capability_refresh_runtime: Option<HostCapabilityRefreshRuntime>,
    /// Daemon-owned installed-agent directory (`<pid-file-parent>/agents`).
    /// Workers must load prepared roots from this tree, not from process
    /// `COCKPIT_HOME`, which is a different directory in tests and can
    /// diverge from the installation service in production.
    pub(crate) daemon_agents_dir: Option<PathBuf>,
}

impl SessionConfigSnapshot {
    pub fn new(
        generation: u64,
        providers: crate::config::providers::ProvidersConfig,
        extended: crate::config::extended::ExtendedConfig,
    ) -> Self {
        Self {
            generation,
            trust_revision: 0,
            providers,
            provider_model_sources: HashMap::new(),
            guidance_global_layer: None,
            guidance_project_layer: extended.allow_computer_guidance_proposals,
            extended,
            hooks: crate::config::extended::hooks::HookRegistry::default(),
            host_capabilities: super::unpublished_host_capability_snapshot(),
            host_capability_refresh_runtime: None,
            daemon_agents_dir: None,
        }
    }

    /// Construct a snapshot with an explicit hook registry.
    pub fn with_hooks(
        generation: u64,
        providers: crate::config::providers::ProvidersConfig,
        extended: crate::config::extended::ExtendedConfig,
        hooks: crate::config::extended::hooks::HookRegistry,
    ) -> Self {
        Self {
            generation,
            trust_revision: 0,
            providers,
            provider_model_sources: HashMap::new(),
            guidance_global_layer: None,
            guidance_project_layer: extended.allow_computer_guidance_proposals,
            extended,
            hooks,
            host_capabilities: super::unpublished_host_capability_snapshot(),
            host_capability_refresh_runtime: None,
            daemon_agents_dir: None,
        }
    }

    pub fn with_daemon_agents_dir(mut self, dir: PathBuf) -> Self {
        self.daemon_agents_dir = Some(dir);
        self
    }

    pub fn with_guidance_doc_layers(
        mut self,
        layers: crate::config::extended::GuidanceProposalDocLayers,
    ) -> Self {
        self.guidance_global_layer = layers.global;
        self.guidance_project_layer = layers.project;
        self
    }

    pub fn with_host_capabilities(
        mut self,
        host_capabilities: cockpit_proto::HostCapabilitySnapshot,
    ) -> Self {
        self.host_capabilities = host_capabilities;
        self
    }

    pub(crate) fn with_host_capability_refresh_runtime(
        mut self,
        runtime: HostCapabilityRefreshRuntime,
    ) -> Self {
        self.host_capability_refresh_runtime = Some(runtime);
        self
    }

    /// Bind a resolved projection to its exact durable trust decision.
    pub(crate) fn with_trust_revision(mut self, trust_revision: i64) -> Self {
        self.trust_revision = trust_revision;
        self
    }

    /// Bind the visible provider/model catalog to the exact retained source
    /// bytes that supplied each choice. The supplied chain is the complete
    /// attach-time source selection (global, project, or explicit); its
    /// opaque proofs authorize only capability-relative writes to that exact
    /// source, never workspace access through a global layer.
    pub(crate) fn with_retained_provider_model_sources(
        mut self,
        workspace: &cockpit_config::config::WorkspaceConfigLayerSnapshotChain,
    ) -> anyhow::Result<Self> {
        let mut sources = HashMap::new();
        for (provider_id, provider) in &self.providers.providers {
            for model in &provider.models {
                if let Some(source) = cockpit_config::config::providers::retained_provider_model_source_from_workspace_layer_snapshots(
                    &workspace.layers,
                    provider_id,
                    &model.id,
                )? {
                    sources.insert((provider_id.clone(), model.id.clone()), source);
                }
            }
        }
        self.provider_model_sources = sources;
        Ok(self)
    }

    pub(crate) fn retained_provider_model_source(
        &self,
        provider_id: &str,
        model_id: &str,
    ) -> Option<&cockpit_config::config::providers::RetainedProviderModelSource> {
        self.provider_model_sources
            .get(&(provider_id.to_string(), model_id.to_string()))
    }

    /// The turn-pinned hook registry.
    pub fn hooks(&self) -> &crate::config::extended::hooks::HookRegistry {
        &self.hooks
    }

    pub fn to_proto(&self, session_id: Uuid) -> proto::ConfigSnapshot {
        proto::ConfigSnapshot {
            session_id,
            generation: self.generation,
            extended: redacted_extended_config(&self.extended),
            providers: redacted_provider_view(&self.providers),
        }
    }
}

/// Generation-aware reader over a session's [`SessionConfigSnapshot`].
///
/// This is the single, session-scoped access path to resolved config for
/// turn-scoped code. It is placed on the driver/agent environment
/// ([`crate::engine::Driver`]) and threaded to engine components and
/// built-in tools ([`crate::engine::tool::ToolCtx`]); nothing below the
/// worker re-reads config from disk. It is also the seam future consumers
/// (e.g. `approval-policy-live-reload`'s `GrantStore`) attach to.
///
/// **Turn isolation.** A handle carries an optional *pinned* view. The
/// driver re-pins at each turn boundary ([`Self::repin`]); the pinned handle
/// threaded into the turn reads a consistent snapshot for the whole turn even
/// if the worker re-resolves config (bumping the generation) mid-turn. A
/// re-resolution therefore takes effect at the next turn boundary — the
/// safe-live vs turn-boundary classification the foundation prompt
/// established. A handle with no pin (`None`) observes the live shared
/// snapshot; the worker holds such a live handle to answer between-turn reads.
#[derive(Clone)]
pub struct SessionConfigHandle {
    shared: Arc<RwLock<SessionConfigSnapshot>>,
    /// `Some` → reads return this fixed snapshot (turn-pinned). `None` →
    /// reads observe the live shared snapshot.
    pinned: Option<Arc<SessionConfigSnapshot>>,
}

impl SessionConfigHandle {
    /// A live handle over the worker's shared snapshot cell. Reads observe
    /// the current generation until [`Self::repin`] freezes a turn view.
    pub fn new(shared: Arc<RwLock<SessionConfigSnapshot>>) -> Self {
        Self {
            shared,
            pinned: None,
        }
    }

    /// A detached, pinned handle over a fixed snapshot — for standalone/
    /// tool contexts with no worker behind them and for tests.
    pub fn detached(snapshot: SessionConfigSnapshot) -> Self {
        Self {
            shared: Arc::new(RwLock::new(snapshot.clone())),
            pinned: Some(Arc::new(snapshot)),
        }
    }

    /// A detached handle over default config. Test/replay contexts that never
    /// exercise config-dependent behavior.
    pub fn detached_default() -> Self {
        Self::detached(SessionConfigSnapshot::new(
            0,
            crate::config::providers::ProvidersConfig::default(),
            crate::config::extended::ExtendedConfig::default(),
        ))
    }

    /// A pinned handle resolving the layered config on disk for `cwd`. Tests
    /// that write config into a tempdir and exercise config-dependent turn
    /// behavior use this to feed that config through the handle exactly as the
    /// production `ConfigSource` would — the same values the pre-adoption
    /// direct disk reads produced.
    #[cfg(test)]
    pub fn from_disk_for_tests(cwd: &std::path::Path) -> Self {
        Self::from_disk_for_tests_at_generation(cwd, 0)
    }

    /// Same as [`Self::from_disk_for_tests`], but the snapshot carries
    /// `generation` so a test refresh can advance the same counter a worker
    /// re-resolution would.
    #[cfg(test)]
    pub fn from_disk_for_tests_at_generation(cwd: &std::path::Path, generation: u64) -> Self {
        // Resolve the layered configs directly (no credential-migration side
        // effect, so widespread test use does not mutate the process-global
        // migration latch and cause cross-test interference), under an explicit
        // Trust policy for `cwd` so the tempdir's project layer is always
        // loaded regardless of any workspace-trust state leaked by a concurrent
        // test — the read is deterministic, matching what the production
        // ConfigSource resolves for a trusted session root.
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(cwd).unwrap_or_else(|_| {
                crate::config::trust::TrustRoot {
                    opened_path: cwd.to_path_buf(),
                    root: cwd.to_path_buf(),
                    kind: crate::config::trust::TrustRootKind::Directory,
                }
            }),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let saved_explicit = std::env::var_os(crate::config::dirs::COCKPIT_CONFIG_ENV);
        // This helper must load the tempdir's project layer even when a
        // process-wide COCKPIT_CONFIG points at an unrelated file.
        unsafe {
            std::env::remove_var(crate::config::dirs::COCKPIT_CONFIG_ENV);
        }
        let (providers, extended, hooks) =
            crate::config::trust::with_workspace_trust_policy(policy, || {
                (
                    crate::config::providers::ConfigDoc::load_effective(cwd),
                    crate::config::extended::load_for_cwd(cwd),
                    crate::config::extended::hooks::resolve_hooks_for_cwd(cwd),
                )
            });
        match saved_explicit {
            Some(value) => unsafe {
                std::env::set_var(crate::config::dirs::COCKPIT_CONFIG_ENV, value);
            },
            None => {}
        }
        // Test contexts sometimes replace this snapshot to exercise a
        // config-dependent tool decision. Keep their handle live over its
        // isolated cell; production turn handles remain pinned by `repin`.
        Self::new(Arc::new(RwLock::new(SessionConfigSnapshot::with_hooks(
            generation, providers, extended, hooks,
        ))))
    }

    fn read_shared(&self) -> SessionConfigSnapshot {
        self.shared
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replace the isolated live snapshot used by a tool/replay test.
    #[cfg(test)]
    pub(crate) fn set_full_config_snapshot_for_tests(&self, snapshot: SessionConfigSnapshot) {
        *self
            .shared
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = snapshot;
    }

    /// The snapshot this handle reads: the pinned view if pinned, else the
    /// current shared snapshot.
    pub fn snapshot(&self) -> Arc<SessionConfigSnapshot> {
        match &self.pinned {
            Some(pinned) => pinned.clone(),
            None => Arc::new(self.read_shared()),
        }
    }

    /// Re-pin to the current shared generation. The driver calls this at each
    /// turn boundary so the in-flight turn reads a consistent view while the
    /// next turn observes any re-resolution that landed in between.
    pub fn repin(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            pinned: Some(Arc::new(self.read_shared())),
        }
    }

    /// Keep an already-prepared pin. `repin()` always re-reads the shared
    /// cell, which would drop a prepare-time generation that the child runner
    /// still has to observe.
    pub fn ensure_pinned(&self) -> Self {
        if self.pinned.is_some() {
            self.clone()
        } else {
            self.repin()
        }
    }

    /// Generation of the snapshot this handle reads.
    pub fn generation(&self) -> u64 {
        self.snapshot().generation
    }

    /// The effective extended config this handle reads.
    pub fn extended(&self) -> crate::config::extended::ExtendedConfig {
        self.snapshot().extended.clone()
    }

    /// The effective provider config this handle reads.
    ///
    /// Stamps [`ProvidersConfig::resolution_generation`] from the snapshot
    /// generation so capability resolution is generation-keyed.
    pub fn providers(&self) -> crate::config::providers::ProvidersConfig {
        let snapshot = self.snapshot();
        snapshot
            .providers
            .clone()
            .with_resolution_generation(snapshot.generation)
    }

    /// Both resolved configs as one pair — mirrors the shape turn-scoped call
    /// sites previously got from [`crate::auto_title::load_configs_for`].
    pub fn configs(
        &self,
    ) -> (
        crate::config::extended::ExtendedConfig,
        crate::config::providers::ProvidersConfig,
    ) {
        let snapshot = self.snapshot();
        (
            snapshot.extended.clone(),
            snapshot
                .providers
                .clone()
                .with_resolution_generation(snapshot.generation),
        )
    }
}

pub(super) fn redacted_extended_config(
    extended: &crate::config::extended::ExtendedConfig,
) -> crate::config::extended::ExtendedConfig {
    let mut extended = extended.clone();
    extended.redact.denylist = extended
        .redact
        .denylist
        .iter()
        .map(|_| "[redacted]".to_string())
        .collect();
    // Image-generation config is secret-bearing and cannot be safely redacted
    // in place (see `ImageGenerationConfig::redacted_for_snapshot`); the policy
    // — omit its content from the snapshot by emitting the empty registry —
    // lives on the owned type.
    extended.image_generation = extended.image_generation.redacted_for_snapshot();
    extended
}

pub(super) fn redacted_provider_view(
    providers: &crate::config::providers::ProvidersConfig,
) -> proto::ProviderConfigView {
    crate::secret_ref::redact_provider_view(providers)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplaceConfigSnapshotResult {
    pub generation: u64,
    pub changed: bool,
    /// A refresh snapshot was resolved against an older worker generation.
    /// It was deliberately not published: callers must re-resolve from the
    /// retained authority rather than overwrite a newer mutation.
    pub stale: bool,
}

/// Two-stage receipt for one `ReplaceConfigSnapshot`.
///
/// Stage 1 (**published**) is this value: the worker performed the snapshot CAS
/// and the new projection is the session's live config. It is sent as soon as
/// the CAS lands, so the worker loop never blocks on the driver and a refresh
/// caller's deadline measures only worker-loop liveness.
///
/// Stage 2 (**applied**) is [`Self::applied`]: the driver serviced
/// `RefreshConfigDerivedState` and rebuilt its config-derived state. Driver
/// controls are only serviced at a turn boundary, so under a long turn this can
/// legitimately take minutes. It is therefore a *follow-up*, never a
/// precondition for acknowledging publication.
///
/// The receiver here is purely observational: the worker's own follow-up task
/// owns clearing `trust_transition_pending`, so dropping this receiver (a
/// caller that only needs publication, or one whose applied-deadline expired)
/// can never strand the admission gate.
#[derive(Debug)]
pub struct ReplaceConfigSnapshotAck {
    pub generation: u64,
    pub changed: bool,
    /// See [`ReplaceConfigSnapshotResult::stale`].
    pub stale: bool,
    /// Resolves once the driver has applied the published snapshot. `Some`
    /// only when a driver control was actually dispatched (`changed == true`
    /// and the control channel accepted it); `None` means there was nothing to
    /// apply. The sender is dropped without a value when the driver dies, so a
    /// `RecvError` means "not applied", not "applied".
    pub applied: Option<oneshot::Receiver<()>>,
}

impl ReplaceConfigSnapshotAck {
    /// A publication receipt with no driver follow-up: either the CAS changed
    /// nothing, it was refused as stale, or the caller is a test seam with no
    /// driver behind it.
    pub fn published(result: ReplaceConfigSnapshotResult) -> Self {
        Self {
            generation: result.generation,
            changed: result.changed,
            stale: result.stale,
            applied: None,
        }
    }
}

pub(super) fn replace_config_snapshot(
    config_snapshot: &Arc<RwLock<SessionConfigSnapshot>>,
    replacement: SessionConfigSnapshot,
) -> ReplaceConfigSnapshotResult {
    replace_config_snapshot_if_current(config_snapshot, replacement, None, None)
}

/// Replace a resolved snapshot only if the worker is still at the generation
/// observed before resolution began.  The worker lock is the final freshness
/// fence: a watcher may finish parsing an older file after a direct mutation
/// has already published generation N, but it can never publish its stale
/// view over N.
pub(super) fn replace_config_snapshot_if_current(
    config_snapshot: &Arc<RwLock<SessionConfigSnapshot>>,
    replacement: SessionConfigSnapshot,
    expected_generation: Option<u64>,
    expected_trust_revision: Option<i64>,
) -> ReplaceConfigSnapshotResult {
    let mut snapshot = config_snapshot
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if expected_generation.is_some_and(|expected| expected != snapshot.generation) {
        return ReplaceConfigSnapshotResult {
            generation: snapshot.generation,
            changed: false,
            stale: true,
        };
    }
    if expected_trust_revision.is_some_and(|expected| expected != snapshot.trust_revision) {
        return ReplaceConfigSnapshotResult {
            generation: snapshot.generation,
            changed: false,
            stale: true,
        };
    }
    if config_snapshots_equal(&snapshot, &replacement) {
        return ReplaceConfigSnapshotResult {
            generation: snapshot.generation,
            changed: false,
            stale: false,
        };
    }
    snapshot.generation = snapshot.generation.saturating_add(1);
    snapshot.providers = replacement.providers;
    snapshot.provider_model_sources = replacement.provider_model_sources;
    snapshot.extended = replacement.extended;
    snapshot.guidance_global_layer = replacement.guidance_global_layer;
    snapshot.guidance_project_layer = replacement.guidance_project_layer;
    snapshot.hooks = replacement.hooks;
    snapshot.trust_revision = replacement.trust_revision;
    ReplaceConfigSnapshotResult {
        generation: snapshot.generation,
        changed: true,
        stale: false,
    }
}

/// Own the driver's config-application receipt on behalf of a published
/// replacement, off the worker loop.
///
/// This task — never the worker loop, and never a refresh caller — is the sole
/// writer that clears `trust_transition_pending` for `pending_revision`. The
/// worker loop must not await the receipt (the driver only services controls at
/// a turn boundary, so it would block Cancel/Shutdown for a whole turn), and a
/// refresh caller must not own it (its deadline would then destroy a healthy
/// mid-turn worker). Splitting it here gives both a receipt they can observe and
/// drop freely.
///
/// Returns a second receiver that resolves after the gate has been cleared, so
/// an interested caller can wait for *application* rather than publication.
/// Dropping it is always safe.
///
/// Fail-closed on driver death: if the driver drops its sender without a
/// receipt, the gate stays set and the returned receiver resolves with an error.
/// A snapshot no driver applied must not start admitting work.
pub(super) fn spawn_config_application_follow_up(
    applied_rx: oneshot::Receiver<()>,
    trust_transition_pending: Arc<std::sync::atomic::AtomicI64>,
    pending_revision: Option<i64>,
    event_tx: EventSender,
    redaction: SharedRedactionTable,
    session_id: Uuid,
) -> oneshot::Receiver<()> {
    let (observed_tx, observed_rx) = oneshot::channel();
    tokio::spawn(async move {
        if applied_rx.await.is_err() {
            tracing::warn!(
                %session_id,
                revision = pending_revision.unwrap_or_default(),
                "driver dropped the config-derived-state receipt; workspace-trust admission stays fail-closed"
            );
            return;
        }
        clear_trust_transition_gate_on_application(
            &trust_transition_pending,
            pending_revision,
            &event_tx,
            &redaction,
            session_id,
        );
        let _ = observed_tx.send(());
    });
    observed_rx
}

/// Release the admission gate for exactly `revision` and announce it.
///
/// The compare-exchange is revision-owned on purpose: a newer transition that
/// won while this application was in flight installed its own revision, and its
/// gate must survive. A zero revision means no transition was riding on this
/// replacement, so there is nothing to release.
pub(super) fn clear_trust_transition_gate_on_application(
    trust_transition_pending: &Arc<std::sync::atomic::AtomicI64>,
    pending_revision: Option<i64>,
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
) {
    let Some(revision) = pending_revision.filter(|revision| *revision != 0) else {
        return;
    };
    if trust_transition_pending
        .compare_exchange(revision, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        broadcast_workspace_trust_reconciliation(
            event_tx,
            redaction,
            session_id,
            revision,
            proto::WorkspaceTrustReconciliationState::Applied,
        );
    }
}

/// Free-function form of [`SessionWorkerHandle::broadcast_workspace_trust_reconciliation`]
/// for the worker loop, which owns the raw event/redaction seams rather than a
/// handle clone.
pub(super) fn broadcast_workspace_trust_reconciliation(
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
    revision: i64,
    state: proto::WorkspaceTrustReconciliationState,
) {
    send_current_event(
        event_tx,
        redaction,
        proto::Event::WorkspaceTrustReconciliation {
            session_id,
            revision,
            state,
        },
    );
}

pub(super) fn send_config_snapshot_event_if_changed(
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    config_snapshot: &Arc<RwLock<SessionConfigSnapshot>>,
    session_id: Uuid,
    result: ReplaceConfigSnapshotResult,
) -> u64 {
    if result.changed {
        send_current_event(
            event_tx,
            redaction,
            proto::Event::ConfigSnapshot {
                snapshot: Box::new(
                    config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .to_proto(session_id),
                ),
            },
        );
    }
    result.generation
}

fn config_snapshots_equal(
    current: &SessionConfigSnapshot,
    replacement: &SessionConfigSnapshot,
) -> bool {
    serialize_equal(&current.providers, &replacement.providers)
        && current.provider_model_sources == replacement.provider_model_sources
        && serialize_equal(&current.extended, &replacement.extended)
        && current.guidance_global_layer == replacement.guidance_global_layer
        && current.guidance_project_layer == replacement.guidance_project_layer
        && current.hooks == replacement.hooks
        && current.trust_revision == replacement.trust_revision
}

fn serialize_equal<T: serde::Serialize>(left: &T, right: &T) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

pub(super) fn sandbox_unavailable_notice_from_availability(
    availability: &crate::tools::shell_sandbox::SandboxAvailability,
) -> Option<SandboxUnavailableNotice> {
    match availability {
        crate::tools::shell_sandbox::SandboxAvailability::Available => None,
        crate::tools::shell_sandbox::SandboxAvailability::Unavailable {
            reason,
            fix_command,
        } => Some(SandboxUnavailableNotice {
            remedy: reason.clone(),
            fix_command: fix_command
                .clone()
                .or_else(|| crate::tools::shell_sandbox::fix_command_for_reason(reason)),
        }),
        crate::tools::shell_sandbox::SandboxAvailability::UnsupportedPlatform { reason } => {
            Some(SandboxUnavailableNotice {
                remedy: reason.clone(),
                fix_command: None,
            })
        }
    }
}

pub(super) fn emit_session_driver_failed_once(
    event_tx: &EventSender,
    completions: &Arc<Mutex<TurnCompletions>>,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
    driver_failed: &mut bool,
    error: String,
) {
    if *driver_failed {
        return;
    }
    *driver_failed = true;
    let event = proto::Event::SessionDriverFailed {
        session_id,
        turn_id: None,
        error,
    };
    resolve_turn_terminal_event(completions, &event);
    send_current_event(event_tx, redaction, event);
}

pub(super) async fn send_driver_control_or_fail(
    driver_control_tx: &mpsc::Sender<crate::engine::driver::DriverControl>,
    control: crate::engine::driver::DriverControl,
    event_tx: &EventSender,
    completions: &Arc<Mutex<TurnCompletions>>,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
    driver_failed: &mut bool,
) -> bool {
    if driver_control_tx.send(control).await.is_ok() {
        return true;
    }
    tracing::warn!(session_id = %session_id, "driver control channel closed");
    emit_session_driver_failed_once(
        event_tx,
        completions,
        redaction,
        session_id,
        driver_failed,
        "driver control channel closed".to_string(),
    );
    false
}

pub(super) fn active_wire_api_for_session(
    session: &Session,
    providers: &crate::config::providers::ProvidersConfig,
) -> (String, String, crate::config::providers::WireApi) {
    let provider = session.active_provider().unwrap_or_default();
    let model = session.active_model().unwrap_or_default();
    let configured = providers.resolve_wire_api(&provider, &model);
    let resolved = if configured.is_auto() {
        crate::config::providers::WireApi::detect_for_provider(&provider, &model)
    } else {
        configured
    };
    (provider, model, resolved)
}

pub(super) fn wire_api_label(wire_api: crate::config::providers::WireApi) -> &'static str {
    match wire_api {
        crate::config::providers::WireApi::Responses => "responses",
        crate::config::providers::WireApi::Completions => "completions",
        crate::config::providers::WireApi::Auto => "auto",
    }
}

pub(super) fn build_resume_repair_state(
    session: &Session,
    providers: &crate::config::providers::ProvidersConfig,
    repair: &crate::engine::rehydrate::RehydrateRepairRequired,
) -> proto::ResumeRepairState {
    let (provider, model, wire_api) = active_wire_api_for_session(session, providers);
    proto::ResumeRepairState {
        session_id: session.id,
        short_id: session.short_id(),
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
    pub(crate) fn forwarded_mcp_slot(&self) -> Arc<crate::mcp::forwarded::ForwardedCatalogSlot> {
        self.session.forwarded_mcp_slot()
    }

    /// Exact live-worker identity, independent of the reusable session id.
    /// Registry transition fences use this to reject ABA replacement.
    pub(crate) fn same_worker_as(&self, other: &Self) -> bool {
        self.work_tx.same_channel(&other.work_tx)
    }

    #[cfg(test)]
    pub(crate) fn test_handle(session: Arc<Session>, locks: Arc<LockManager>) -> Self {
        Self::test_handle_with_receiver(session, locks).0
    }

    #[cfg(test)]
    fn test_workspace_capture_root(project_root: &std::path::Path) -> PathBuf {
        if project_root.is_dir() {
            return project_root.to_path_buf();
        }
        // Lifecycle tests still stamp synthetic session roots such as `/x`.
        // Capability capture needs a real directory; keep one process-wide
        // fallback so those handles can be constructed without changing the
        // stored session path.
        static FALLBACK: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        FALLBACK
            .get_or_init(|| {
                let dir = tempfile::TempDir::new().expect("test workspace fallback");
                let path = dir.path().to_path_buf();
                std::mem::forget(dir);
                path
            })
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn test_handle_with_receiver(
        session: Arc<Session>,
        locks: Arc<LockManager>,
    ) -> (Self, mpsc::Receiver<SessionWork>) {
        let (work_tx, work_rx) = mpsc::channel(WORK_QUEUE_CAPACITY);
        let (event_tx, _event_rx) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        let redaction: SharedRedactionTable =
            Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
        // Simulate a fully-started worker: a real `run_worker` reports its
        // startup crash-reconciliation pass complete early in its life, so a
        // resume-attach reconciliation gate resolves immediately
        // (`daemon-lifecycle-replay-timing-robustness.md`, finding 3). A bare
        // test handle has no `run_worker` to fire that signal, so mark it here —
        // otherwise every resume-attach to a test worker would block on the
        // per-resume reconciliation deadline. (Independent of the SHUTDOWN
        // park-commit signal, which tests still drive explicitly.)
        let park_commit = crate::engine::interrupt::ParkCommit::new();
        park_commit.report_startup_reconciled();
        let capture_root = Self::test_workspace_capture_root(&session.project_root);
        let trust_root =
            crate::config::trust::resolve_trust_root(&capture_root).unwrap_or_else(|_| {
                crate::config::trust::TrustRoot {
                    opened_path: capture_root.clone(),
                    root: capture_root.clone(),
                    kind: crate::config::trust::TrustRootKind::Directory,
                }
            });
        let handle = Self {
            session_id: session.id,
            project_root: session.project_root.clone(),
            active_agent_name: "Build".to_string(),
            trust_policy: crate::config::trust::shared_workspace_trust_policy(
                crate::config::trust::WorkspaceTrustPolicy {
                    root: trust_root.clone(),
                    mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                },
            ),
            trust_revision: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            trust_transition_pending: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            workspace_root_authority: Arc::new(
                crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority::capture(
                    &capture_root,
                    &crate::config::trust::WorkspaceTrustPolicy {
                        root: trust_root,
                        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                    },
                )
                .expect("test workspace authority"),
            ),
            work_tx,
            event_tx,
            turn_completions: Arc::new(Mutex::new(TurnCompletions::default())),
            redaction,
            live: Arc::new(LiveState::default()),
            interactive_clients: Arc::new(AtomicUsize::new(0)),
            session: session.clone(),
            sandbox_notice_armed: Arc::new(AtomicBool::new(false)),
            sandbox_unavailable_notice: Arc::new(RwLock::new(None)),
            locks,
            env_overlay: Arc::new(RwLock::new(HashMap::new())),
            repair_required: Arc::new(RwLock::new(None)),
            foreground: Arc::new(Mutex::new(LiveForegroundState::new("Build".to_string()))),
            config_snapshot: Arc::new(RwLock::new(SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                crate::config::extended::ExtendedConfig::default(),
            ))),
            config_publication: Arc::new(tokio::sync::RwLock::new(())),
            authoritative_active_model_state: Arc::new(RwLock::new(initial_active_model_state(
                &session,
                &crate::config::providers::ProvidersConfig::default(),
            ))),
            park_commit,
            reserved_root_agent_instance_id: Uuid::new_v4(),
        };
        (handle, work_rx)
    }

    /// Test receiver counterpart of the worker's atomic snapshot publication.
    /// Callers that model a real `ReplaceConfigSnapshot` acknowledgement must
    /// install that exact snapshot, including retained source proofs and the
    /// durable trust revision, then ack the same generation.
    #[cfg(test)]
    pub(crate) fn set_full_config_snapshot_for_tests(&self, snapshot: SessionConfigSnapshot) {
        *self
            .config_snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = snapshot;
    }

    pub fn set_created_by_principal(&self, principal: Option<String>) -> anyhow::Result<()> {
        self.session.set_created_by_principal(principal)
    }

    pub fn session_entry_mode(&self) -> crate::daemon::proto::SessionEntryMode {
        self.session.session_entry_mode()
    }

    /// Daemon-owned project identity for a live, not-yet-persisted session.
    /// This is intentionally available only on the in-process worker handle:
    /// callers must not substitute an Attach-supplied path while resolving a
    /// lazy session that has no durable row yet.
    pub fn project_root(&self) -> std::path::PathBuf {
        self.session.project_root.clone()
    }

    /// Commit a lazily-created session before an external process is told its
    /// id. Ephemeral daemon attaches use this so their session namespace is
    /// durable even if the client disconnects before sending a message.
    pub fn persist_if_needed(&self) -> anyhow::Result<bool> {
        self.session.persist_if_needed()
    }

    pub fn set_env_overlay(&self, vars: HashMap<String, String>) {
        let mut overlay = self
            .env_overlay
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *overlay = vars;
    }

    /// Snapshot the authenticated session environment for daemon-owned
    /// provider resolution. The values never cross the wire; callers use this
    /// only as an in-daemon lookup source.
    pub fn env_overlay_snapshot(&self) -> HashMap<String, String> {
        self.env_overlay
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    #[cfg(test)]
    pub fn env_overlay(&self) -> Arc<RwLock<HashMap<String, String>>> {
        self.env_overlay.clone()
    }

    #[cfg(test)]
    pub(crate) fn set_test_live_status(
        &self,
        has_active_schedules: bool,
        processing: bool,
        tool_running: bool,
    ) {
        self.live.active_schedules.store(
            usize::from(has_active_schedules),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.live
            .processing
            .store(processing, std::sync::atomic::Ordering::Relaxed);
        self.live.tool_running.store(
            usize::from(tool_running),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Set or toggle the session's sandbox mode. Available modes persist as
    /// intent and become this session's effective mode. Unavailable modes
    /// return [`super::SandboxCapabilityMissing`] and do not persist.
    pub fn set_sandbox(
        &self,
        mode: Option<crate::tools::sandbox_mode::SandboxMode>,
        container_network_enabled: Option<bool>,
        caps: &cockpit_proto::HostCapabilitySnapshot,
    ) -> Result<super::SetSandboxApplied, super::SetSandboxError> {
        if let Some(enabled) = container_network_enabled {
            self.session.set_container_network_enabled(enabled);
        }
        let requested = mode.unwrap_or_else(|| self.session.sandbox_mode().toggled_legacy());
        let persisted_intent = self
            .config_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extended
            .sandbox
            .default_mode;
        let applied = super::evaluate_set_sandbox(requested, persisted_intent, caps)
            .map_err(super::SetSandboxError::CapabilityMissing)?;
        persist_sandbox_intent(&self.project_root, applied.persisted_intent).map_err(|error| {
            super::SetSandboxError::Persist(format!("persisting sandbox intent: {error:#}"))
        })?;
        {
            let mut snapshot = self
                .config_snapshot
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            snapshot.extended.sandbox.default_mode = applied.persisted_intent;
            snapshot.host_capabilities = caps.clone();
        }
        let new = self.session.set_sandbox_mode(applied.effective);
        self.sandbox_notice_armed.store(false, Ordering::SeqCst);
        if !new.enabled() {
            *self
                .sandbox_unavailable_notice
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
        send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::SandboxState {
                session_id: self.session_id,
                mode: new,
                enabled: new.enabled(),
                container_network_enabled: self.session.container_network_enabled(),
                container_availability: crate::container::availability_snapshot(),
                persisted_intent: Some(applied.persisted_intent),
            },
        );
        if new.enabled() {
            self.probe_sandbox_unavailable();
        }
        Ok(applied)
    }

    pub fn container_network_enabled(&self) -> bool {
        self.session.container_network_enabled()
    }

    #[cfg(test)]
    pub fn sandbox_escalation_enabled(&self) -> bool {
        self.session.sandbox_escalation_enabled()
    }

    /// Set the session's sandbox-escalation availability and broadcast when
    /// the value changes. Idempotent writes are intentionally silent.
    pub fn set_sandbox_escalation(&self, enabled: bool) -> bool {
        let previous = self.session.sandbox_escalation_enabled();
        let enabled = self.session.set_sandbox_escalation_enabled(enabled);
        if previous != enabled {
            send_current_event(
                &self.event_tx,
                &self.redaction,
                proto::Event::SandboxEscalationState {
                    session_id: self.session_id,
                    enabled,
                },
            );
        }
        enabled
    }

    /// Set the session's command-approval mode and broadcast the resulting
    /// state to every attached client. Effective immediately for subsequent
    /// gated tool calls because tools read the same session atomic.
    pub fn set_approval_mode(
        &self,
        mode: crate::config::extended::ApprovalMode,
    ) -> crate::config::extended::ApprovalMode {
        let mode = self.session.set_approval_mode(mode);
        send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::ApprovalModeState {
                session_id: self.session_id,
                mode,
            },
        );
        mode
    }

    /// Effective approval mode for work owned by this attached session.
    pub fn approval_mode(&self) -> crate::config::extended::ApprovalMode {
        self.session.approval_mode()
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

    /// The worker's shared park-commit rendezvous
    /// (`daemon-lifecycle-replay-timing-robustness.md`). The registry drain
    /// path reads [`crate::engine::interrupt::ParkCommit::has_registered_waiters`]
    /// and awaits [`crate::engine::interrupt::ParkCommit::await_shutdown_commit`]
    /// before releasing pid/socket; the attach path awaits
    /// [`crate::engine::interrupt::ParkCommit::await_startup_reconciled`].
    pub fn park_commit(&self) -> crate::engine::interrupt::ParkCommit {
        self.park_commit.clone()
    }

    /// Spawn-time reserved root identity. Distinct from a resumed session's
    /// durable `session-root` row, which always wins when one exists.
    pub fn reserved_root_agent_instance_id(&self) -> Uuid {
        self.reserved_root_agent_instance_id
    }

    /// Live session agent, including a successful `SetAgent` swap. The
    /// spawn-time `active_agent_name` field is not updated in place.
    pub fn live_active_agent(&self) -> String {
        self.session.active_agent()
    }

    /// Test-only: mark this worker as mid-turn so drain treats it as owing a
    /// park-commit (finding 2 obligation extension), without a live driver.
    #[cfg(test)]
    pub(crate) fn set_processing_for_test(&self, processing: bool) {
        self.live.set_processing_for_test(processing);
    }
}

/// RAII guard for an attached interactive client. Decrements the worker's
/// interactive-client count on drop, so a disconnect (even an abrupt one)
/// correctly returns the session to headless behavior.
pub struct InteractiveClientGuard {
    pub(super) counter: Arc<std::sync::atomic::AtomicUsize>,
    /// Session this guard belongs to — used by the last-detach-while-idle
    /// release edge (implementation note).
    pub(super) session_id: Uuid,
    /// The daemon-wide lock authority, consulted on the last detach.
    pub(super) locks: Arc<LockManager>,
    /// Live turn-state, so the detach edge releases only when idle (not
    /// mid-turn): a mid-turn detach keeps the worker (GOALS §8b) and its
    /// locks alive; the next `AgentIdle` with zero clients is the backstop.
    pub(super) live: Arc<LiveState>,
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
    /// Snapshot the policy currently governing this live worker.  Do not use
    /// attach-time state for daemon decisions: trust can change while a
    /// session remains attached.
    pub(crate) fn current_trust_policy(&self) -> crate::config::trust::WorkspaceTrustPolicy {
        crate::config::trust::read_shared_workspace_trust_policy(&self.trust_policy)
    }

    pub(crate) fn current_trust_revision(&self) -> i64 {
        self.trust_revision
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn trust_transition_matches(
        &self,
        expected: &crate::config::trust::ResolvedWorkspaceTrustPolicy,
    ) -> bool {
        let revision = self.current_trust_revision();
        // Bare test handles have no async DB preflight, hence no durable
        // revision to seed. Production workers are constructed only after a
        // positive revision is resolved by the registry.
        (revision == expected.revision || (cfg!(test) && revision == 0))
            && self.current_trust_policy() == expected.policy
    }

    /// Advance the live policy cell and tag the existing projection before an
    /// unlocked replacement is sent to the worker.  Tagging the snapshot
    /// first invalidates any already-resolved older refresh at the worker CAS;
    /// publishing the policy immediately afterwards makes the durable DB
    /// decision authoritative even if the replacement later fails.
    #[cfg(test)]
    pub(crate) async fn begin_trust_transition(
        &self,
        resolved: &crate::config::trust::ResolvedWorkspaceTrustPolicy,
    ) -> tokio::sync::OwnedRwLockWriteGuard<()> {
        // Acquire the worker-local publication fence before exposing the new
        // trust revision. Setup readers take the shared side, so they either
        // finish entirely against the old policy/projection or wait until the
        // matching provider projection has been installed. The owned guard is
        // handed to the transition refresh and deliberately spans its awaits.
        let mut publication = self.config_publication.clone().write_owned().await;
        self.begin_trust_transition_with_publication(resolved, &mut publication);
        publication
    }

    /// Mark a committed transition while the caller already owns this
    /// worker's publication fence.  This is the lock-order-safe SetWorkspaceTrust
    /// path: worker-local authority is acquired before the daemon-global
    /// coordinator, and no worker-local await occurs under that coordinator.
    pub(crate) fn begin_trust_transition_with_publication(
        &self,
        resolved: &crate::config::trust::ResolvedWorkspaceTrustPolicy,
        _publication: &mut tokio::sync::OwnedRwLockWriteGuard<()>,
    ) {
        self.trust_transition_pending
            .store(resolved.revision, Ordering::Release);
        self.config_snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .trust_revision = resolved.revision;
        crate::config::trust::replace_shared_workspace_trust_policy(
            &self.trust_policy,
            resolved.policy.clone(),
        );
        self.trust_revision
            .store(resolved.revision, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn trust_transition_is_pending(&self) -> bool {
        self.trust_transition_pending.load(Ordering::Acquire) != 0
    }

    /// Test construction seam for handles that do not have a running worker
    /// to own the revision-bound replacement acknowledgement.
    #[cfg(test)]
    pub(crate) fn complete_trust_transition_for_test(&self, revision: i64) -> bool {
        self.trust_transition_pending
            .compare_exchange(revision, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Install a new policy only after the caller has published the matching
    /// retained config snapshot.  The shared task-local used by the driver
    /// observes this same cell on its next policy read.
    pub(crate) fn replace_trust_policy(&self, policy: crate::config::trust::WorkspaceTrustPolicy) {
        crate::config::trust::replace_shared_workspace_trust_policy(&self.trust_policy, policy);
    }

    pub async fn send_work(&self, work: SessionWork) -> Result<()> {
        let transition_bypass = matches!(
            &work,
            SessionWork::ReplaceConfigSnapshot { .. }
                | SessionWork::Cancel
                | SessionWork::CancelAll
                | SessionWork::Shutdown { .. }
        );
        // Reserve capacity before taking the publication read fence. Holding
        // that fence while a full queue drains would indefinitely postpone a
        // trust writer. Once capacity is owned, admission and permit
        // consumption are paired under the short read fence: if a transition
        // won while reserve was pending, its writer runs first and this work is
        // rejected without entering the worker queue.
        let permit = self
            .work_tx
            .reserve()
            .await
            .map_err(|_| anyhow::anyhow!("session worker {} has shut down", self.session_id))?;
        let _admission = if transition_bypass {
            None
        } else {
            Some(self.config_publication.read().await)
        };
        if self.trust_transition_is_pending() && !transition_bypass {
            // Typed, not prose: this rejection is transient by construction and
            // the request layer must be able to tag it `RetryLater` without
            // matching on a message. Every other `send_work` failure is a
            // genuine worker-lifetime error and stays `Internal`.
            return Err(anyhow::Error::new(SessionWorkTrustReconciling {
                session_id: self.session_id,
            }));
        }
        permit.send(work);
        Ok(())
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.work_tx.is_closed()
    }

    /// Complete the durable session half of generation-bound terminal cleanup.
    /// Kept on the exact worker handle so registry retry never reconstructs
    /// authority from a reusable session id.
    pub(crate) async fn end_session_for_terminal_cleanup(&self) -> Result<()> {
        let session = self.session.clone();
        tokio::task::spawn_blocking(move || session.end())
            .await
            .map_err(|error| anyhow::anyhow!("terminal session cleanup task failed: {error}"))?
    }

    /// Subscribe to the event stream. Each attached client gets its
    /// own receiver; a lagging receiver drops events (per the design).
    pub fn subscribe(&self) -> EventReceiver {
        self.event_tx.subscribe()
    }

    /// Await the terminal outcome of `turn_id` on a lossless point-to-point
    /// channel. Recently observed completions resolve immediately, closing the
    /// race between queue ack and watcher registration.
    pub fn watch_turn(&self, turn_id: &str) -> oneshot::Receiver<TurnOutcome> {
        self.turn_completions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .watch(turn_id)
    }

    #[cfg(test)]
    pub(crate) fn observe_turn_terminal_event_for_test(&self, event: &proto::Event) {
        resolve_turn_terminal_event(&self.turn_completions, event);
    }

    #[cfg(test)]
    pub(crate) fn close_turn_completions_for_test(&self) {
        close_pending_turn_completions(&self.turn_completions);
    }

    #[cfg(test)]
    pub(crate) fn has_pending_turn_for_test(&self, turn_id: &str) -> bool {
        self.turn_completions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .has_pending(turn_id)
    }

    #[cfg(test)]
    pub(crate) fn broadcast_notice_for_test(&self, text: String) {
        send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::Notice {
                session_id: self.session_id,
                text,
            },
        );
    }

    pub fn redaction_table(&self) -> Arc<RedactionTable> {
        current_redaction(&self.redaction)
    }

    /// Delete a sealed value. Reached only from the daemon's `owner_only`
    /// `DeleteSealedValue` request.
    ///
    /// The create and existence-probe siblings are gone: their only callers
    /// were the retired agent-facing Monty builtins and the retired
    /// `sealed_fetch` delegation mode, and leaving them would have kept an
    /// agent-reachable write and existence oracle alive.
    pub async fn delete_sealed_value(&self, value_id: &str) -> anyhow::Result<bool> {
        let deleted = self
            .session
            .delete_sealed_value(crate::sealed::OwnerAuthority::for_owner_request(), value_id)
            .await?;
        Ok(deleted)
    }

    pub fn session(&self) -> Arc<Session> {
        self.session.clone()
    }

    /// Announce where this session stands in a workspace-trust reconciliation.
    ///
    /// Emitted from the daemon-side transition owner (`Pending`, `StopRetrying`,
    /// `Failed`) and from the worker's applied follow-up task (`Applied`), so an
    /// attached client learns that its admission gate is closed — and later that
    /// it reopened — without polling or reading prose out of a rejection. It is
    /// deliberately state-free beyond the revision: the authoritative policy is
    /// still read through the normal RPCs.
    pub(crate) fn broadcast_workspace_trust_reconciliation(
        &self,
        revision: i64,
        state: proto::WorkspaceTrustReconciliationState,
    ) {
        broadcast_workspace_trust_reconciliation(
            &self.event_tx,
            &self.redaction,
            self.session_id,
            revision,
            state,
        );
    }

    pub fn broadcast_notice(&self, text: String) {
        send_current_session_event_with_agent(
            &self.session,
            Some(&self.active_agent_name),
            &self.event_tx,
            &self.redaction,
            proto::Event::Notice {
                session_id: self.session_id,
                text,
            },
            NoticeSource::DaemonDirect,
        );
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
    pub fn live_status(&self) -> (bool, bool, bool) {
        (
            self.live.has_active_schedules(),
            self.live.processing(),
            self.live.tool_running(),
        )
    }

    pub fn tool_surface_override_json(&self) -> Option<String> {
        self.session.tool_surface_override_json()
    }

    pub fn foreground_snapshot(&self) -> ForegroundSnapshot {
        self.foreground
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot()
    }

    pub fn config_snapshot(&self) -> SessionConfigSnapshot {
        self.config_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) async fn read_config_publication(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.config_publication.read().await
    }

    pub(crate) async fn write_config_publication(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.config_publication.write().await
    }

    pub(crate) async fn write_owned_config_publication(
        &self,
    ) -> tokio::sync::OwnedRwLockWriteGuard<()> {
        self.config_publication.clone().write_owned().await
    }

    /// Emit the correlated terminal result for a `/model` selection that a
    /// recovery pass finished on the driver's behalf.
    ///
    /// The originating call deliberately emitted nothing (its transaction was
    /// still pending recovery), so this is the one terminal result for that
    /// `selection_id`.
    pub fn broadcast_model_selection_result(
        &self,
        selection_id: uuid::Uuid,
        requested: &crate::config::providers::ActiveModelRef,
        outcome: proto::ModelSelectionOutcome,
    ) {
        crate::daemon::send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::ModelSelectionResult {
                session_id: self.session_id,
                selection_id,
                provider: requested.provider.clone(),
                model: requested.model.clone(),
                reasoning_effort: requested
                    .reasoning_effort
                    .as_ref()
                    .map(|effort| effort.value.clone()),
                thinking_mode: requested.thinking_mode,
                prompt_cache_retention: requested.prompt_cache_retention,
                outcome,
            },
        );
    }

    pub fn broadcast_default_model_update_result(
        &self,
        default_update_id: uuid::Uuid,
        outcome: proto::DefaultModelStandaloneOutcome,
    ) {
        crate::daemon::send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::DefaultModelUpdateResult {
                session_id: self.session_id,
                default_update_id,
                outcome,
            },
        );
    }

    pub fn broadcast_config_snapshot(&self) {
        let snapshot = self.config_snapshot().to_proto(self.session_id);
        send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::ConfigSnapshot {
                snapshot: Box::new(snapshot),
            },
        );
    }

    pub fn active_tool_names(&self) -> Vec<String> {
        self.session.active_tool_names()
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
        self.session.short_id()
    }

    /// The session's complete active selection. This is the daemon-owned
    /// resume source, not a projection reconstructed from config defaults.
    #[cfg(test)]
    pub(crate) fn active_model_selection(
        &self,
    ) -> Option<crate::config::providers::ActiveModelRef> {
        self.session.active_model_ref()
    }

    /// Latest worker-authoritative state for attach hydration. Callers must
    /// subscribe to events before reading this value; attach then restamps the
    /// returned state into its new generation epoch.
    pub(crate) fn authoritative_active_model_state(&self) -> Option<proto::ActiveModelState> {
        self.authoritative_active_model_state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn set_authoritative_active_model_state_for_tests(
        &self,
        state: proto::ActiveModelState,
    ) {
        *self
            .authoritative_active_model_state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(state);
    }

    /// Broadcast the session's current gitignore read-allowlist over the
    /// per-session event bus (implementation note).
    /// Called on attach so a late/reconnecting client — and any second
    /// concurrent client — hydrates session-approved entries made before it
    /// connected, not only ones broadcast live afterward. Full-list replace;
    /// only the allow-set is ever sent. A send with no subscribers is a no-op.
    pub fn broadcast_gitignore_allow(&self) {
        send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::GitignoreAllow {
                session_id: self.session_id,
                allow: self.session.gitignore_session_allow(),
            },
        );
    }

    /// Ask the authoritative worker queue to republish its full snapshot.
    /// The normal queue forwarder performs redaction and event broadcast.
    pub async fn broadcast_queue_snapshot(&self) -> Result<()> {
        self.send_work(SessionWork::RepublishQueue).await
    }

    pub async fn broadcast_active_interrupt(&self) {
        let Ok(open) = self.session.db.list_open_interrupts(self.session_id).await else {
            return;
        };
        let Some(active) = open.first() else {
            return;
        };
        let questions = active.questions.clone().or_else(|| {
            active
                .question
                .clone()
                .map(|question| proto::InterruptQuestionSet {
                    questions: vec![question],
                })
        });
        let Some(questions) = questions else {
            return;
        };
        send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::InterruptRaised {
                session_id: self.session_id,
                interrupt_id: active.interrupt_id,
                agent: active.agent_id.clone(),
                description: active.description.clone(),
                question: None,
                questions: Some(questions),
                pending_count: open.len().saturating_sub(1),
                reason: proto::InterruptRaiseReason::Rehydration,
            },
        );
    }

    /// Broadcast intent vs effective sandbox mode so attach/reconnect can
    /// show "intent Sandbox, effective Off (missing bwrap)".
    pub fn broadcast_sandbox_state(&self) {
        let snapshot = self.config_snapshot();
        let mode = self.session.sandbox_mode();
        send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::SandboxState {
                session_id: self.session_id,
                mode,
                enabled: mode.enabled(),
                container_network_enabled: self.session.container_network_enabled(),
                container_availability: crate::container::availability_snapshot(),
                persisted_intent: Some(snapshot.extended.sandbox.default_mode),
            },
        );
    }

    /// Broadcast the current sandbox-escalation availability so late or
    /// reconnecting clients hydrate the daemon-owned session flag.
    pub fn broadcast_sandbox_escalation(&self) {
        send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::SandboxEscalationState {
                session_id: self.session_id,
                enabled: self.session.sandbox_escalation_enabled(),
            },
        );
    }

    /// Hydrate a reconnecting client with the remembered sandbox-unavailable
    /// state, or start the eager probe if no state is known yet. This broadcasts
    /// over the shared session event stream like other attach hydration.
    pub fn broadcast_sandbox_unavailable_or_probe(&self) {
        self.schedule_sandbox_unavailable_probe(true);
    }

    /// Start the eager shell-sandbox availability probe for this session. The
    /// probe is non-blocking and process-cached by `shell_sandbox`.
    pub fn probe_sandbox_unavailable(&self) {
        self.schedule_sandbox_unavailable_probe(false);
    }

    fn schedule_sandbox_unavailable_probe(&self, hydrate_known: bool) {
        if !self.session.sandbox_mode().enabled() {
            *self
                .sandbox_unavailable_notice
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            return;
        }

        if hydrate_known
            && let Some(notice) = self
                .sandbox_unavailable_notice
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        {
            send_sandbox_unavailable_notice(
                &self.event_tx,
                &self.redaction,
                self.session_id,
                &notice,
            );
            return;
        }

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let session = self.session.clone();
        let project_root = self.project_root.clone();
        let event_tx = self.event_tx.clone();
        let redaction = self.redaction.clone();
        let session_id = self.session_id;
        let notice_store = self.sandbox_unavailable_notice.clone();
        let armed = self.sandbox_notice_armed.clone();
        handle.spawn(async move {
            let availability = crate::tools::shell_sandbox::sandbox_available(&project_root)
                .await
                .clone();
            let platform_unsupported = matches!(
                availability,
                crate::tools::shell_sandbox::SandboxAvailability::UnsupportedPlatform { .. }
            );
            if !session.sandbox_mode().enabled() && !platform_unsupported {
                *notice_store
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                return;
            }
            match sandbox_unavailable_notice_from_availability(&availability) {
                Some(notice) => {
                    *notice_store
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(notice.clone());
                    if (session.sandbox_mode().enabled() || platform_unsupported)
                        && forward_sandbox_unavailable(&armed)
                    {
                        send_sandbox_unavailable_notice(&event_tx, &redaction, session_id, &notice);
                    }
                }
                None => {
                    *notice_store
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                }
            }
        });
    }
}

/// Work items a client can ask the worker to perform.
#[derive(Debug)]
pub enum UserMessageProbeResult {
    Unknown,
    ContentCheckRequired,
    Duplicate {
        item: proto::QueueItem,
        queue: Vec<proto::QueueItem>,
    },
    Conflict,
}

/// FCM2 admission evidence for a text-only oversized user submission. The
/// worker validates these opaque bytes against the queued `UserSubmission`,
/// then asks the DB to create the receipt triple and quota lease atomically
/// before the driver can invoke any provider.
#[derive(Debug, Clone)]
pub struct OversizedTextArtifactAdmission {
    pub canonical_message: Vec<u8>,
    pub operation_id: [u8; 16],
    pub actor: crate::db::db::message_attachments::MessageActor,
    pub request_hash: [u8; 32],
    pub message_request_digest: [u8; 32],
    pub attachment_set_digest: [u8; 32],
    /// Durable outside-FCM2 fence; the canonical FCM2 v2 bytes remain frozen.
    pub model_fence: Option<(u64, cockpit_config::config::providers::ActiveModelRef)>,
    /// Optional run-invocation barrier carried as immutable client input. The
    /// worker creates it only after phase one has reserved the FCM2 source and
    /// before it makes the submission visible to the driver.
    pub run_invocation: Option<OversizedRunInvocationAdmission>,
}

#[derive(Debug, Clone)]
pub struct OversizedRunInvocationAdmission {
    pub origin_principal_digest: String,
    pub options_json: String,
    pub options_digest: String,
    pub content_digest: String,
    pub max_turns: Option<u32>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug)]
pub enum SessionWork {
    WakeGoal,
    /// A daemon-scheduled, observed-hit-gated cache refresh. It is never a
    /// user message and never advances away/resume activity.
    KeepWarm {
        cache_send_at_unix_millis: i64,
        cache_send_id: Uuid,
        after_secs: u64,
        idle_window_secs: u64,
        cancel: tokio_util::sync::CancellationToken,
        respond_to: oneshot::Sender<std::result::Result<String, String>>,
    },
    ProbeUserMessage {
        client_submission_id: Uuid,
        wire_fingerprint: String,
        origin_principal: Option<String>,
        respond_to:
            oneshot::Sender<std::result::Result<UserMessageProbeResult, proto::ErrorPayload>>,
    },
    UserMessage {
        submission: Box<crate::engine::message::UserSubmission>,
        /// Present when the message was admitted as an authenticated remote
        /// operation. The worker ACCEPT path commits the transactional
        /// remote-operation ledger (FCM2 identity) in the same step it accepts
        /// the submission, so a replayed operation is a durable no-op rather
        /// than a second accept. Owner/local sends pass `None` and take the
        /// unchanged in-memory accept path.
        #[cfg(feature = "remote")]
        remote_operation: Option<super::RemoteQueueOperation>,
        /// Present only for text-only sources above 64KiB. Unlike the legacy
        /// in-memory acceptance path, this branch has a durable FCM2 receipt
        /// and exact artifact lease before it reaches the driver.
        artifact_admission: Option<Box<OversizedTextArtifactAdmission>>,
        respond_to: oneshot::Sender<
            std::result::Result<(proto::QueueItem, Vec<proto::QueueItem>), proto::ErrorPayload>,
        >,
    },
    /// Terminal results for effective-default transactions a recovery pass
    /// converged for this session. Routed through the driver so each event
    /// carries the driver's own active-model-state generation.
    EmitRecoveredDefaultTerminals {
        transactions: Vec<crate::config::providers::RecoveredTransaction>,
        /// Resolves only after the driver's durable default-update receipt
        /// write. The retained config journal remains until that point.
        respond_to: oneshot::Sender<std::result::Result<(), String>>,
    },
    SteerDelegation {
        task_call_id: String,
        label: String,
        message: String,
        origin_principal: String,
        respond_to: oneshot::Sender<proto::DelegationSteerResult>,
    },
    RemoveQueuedUserMessage {
        queue_item_id: Uuid,
        #[cfg(feature = "remote")]
        remote_operation: Option<super::RemoteQueueOperation>,
        respond_to: oneshot::Sender<
            std::result::Result<proto::RemoveQueuedUserMessageResult, proto::ErrorPayload>,
        >,
    },
    RemoveNewestQueuedUserMessage {
        target_id: Option<String>,
        #[cfg(feature = "remote")]
        remote_operation: Option<super::RemoteQueueOperation>,
        respond_to: oneshot::Sender<
            std::result::Result<proto::RemoveQueuedUserMessageResult, proto::ErrorPayload>,
        >,
    },
    RemoveEditableQueuedUserMessages {
        target_id: Option<String>,
        #[cfg(feature = "remote")]
        remote_operation: Option<super::RemoteQueueOperation>,
        respond_to: oneshot::Sender<
            std::result::Result<proto::RemoveQueuedUserMessagesResult, proto::ErrorPayload>,
        >,
    },
    SetQueuedUserMessageClass {
        queue_item_id: Uuid,
        delivery_class: proto::QueueDeliveryClass,
        replacement: Option<proto::QueueItemReplacement>,
        respond_to: oneshot::Sender<
            std::result::Result<proto::SetQueuedUserMessageClassResult, proto::ErrorPayload>,
        >,
    },
    PromoteQueuedUserMessages {
        delivery_class: proto::QueueDeliveryClass,
        respond_to: oneshot::Sender<
            std::result::Result<proto::PromoteQueuedUserMessagesResult, proto::ErrorPayload>,
        >,
    },
    SendNowQueuedUserMessage {
        queue_item_id: Option<Uuid>,
        respond_to: oneshot::Sender<
            std::result::Result<proto::SendNowQueuedUserMessageResult, proto::ErrorPayload>,
        >,
    },
    RepublishQueue,
    Cancel,
    ResolveInterrupt {
        interrupt_id: Uuid,
        response: proto::ResolveResponse,
    },
    /// A typed durable decision answer. This is intentionally handled by the
    /// owning session worker so the continuation, session-scoped event, and
    /// any fresh recovery executor share one serialization point.
    ResolveAgentDecision {
        decision_request_id: Uuid,
        answer: crate::agent_tree::PublicDecisionAnswer,
        /// Present only for the ACP Code-root first-wins route. The worker
        /// writes it in the same SQLite transaction as a newly won decision.
        code_root_receipt: Option<crate::db::agent_tree_decisions::CodeRootInterruptReceiptWrite>,
        respond_to:
            oneshot::Sender<std::result::Result<crate::agent_tree::DecisionSettlement, String>>,
    },
    /// Request the one daemon-classified low-risk host effect through the
    /// same durable AgentTree decision/continuation path as a tool question.
    /// The worker owns the durable operation and executes the local probe only
    /// after the exact decision is terminally allowed; the server receives the
    /// persisted terminal snapshot for its original attached request.
    AuthorizeHostCapabilitiesRefresh {
        respond_to: oneshot::Sender<
            std::result::Result<HostCapabilitiesRefreshCompletion, HostCapabilitiesRefreshError>,
        >,
    },
    RepairResume {
        respond_to: oneshot::Sender<std::result::Result<(), String>>,
    },
    ReplaceConfigSnapshot {
        snapshot: Box<SessionConfigSnapshot>,
        /// Worker generation captured before the daemon began resolving this
        /// replacement. `None` is retained only for in-process test seams;
        /// production refreshes always provide a fence.
        expected_generation: Option<u64>,
        /// Durable trust revision captured with the same retained source
        /// chain. Production refreshes provide it so a worker cannot publish
        /// a projection from before a later trust transition.
        expected_trust_revision: Option<i64>,
        /// Publication receipt. It is sent as soon as the worker's snapshot CAS
        /// lands; the driver-applied follow-up rides along inside it.
        respond_to: oneshot::Sender<ReplaceConfigSnapshotAck>,
    },
    SetActiveModel {
        selection_id: Uuid,
        /// Fixed daemon-owned deadline assigned when dispatch accepts the
        /// request. It is intentionally not client configuration.
        selection_deadline: std::time::Instant,
        provider: String,
        model: String,
        persist_as_default: bool,
        trigger: crate::session::ModelSwitchTrigger,
        reasoning_effort: Option<String>,
        thinking_mode: Option<crate::config::providers::ThinkingMode>,
        prompt_cache_retention: Option<crate::config::providers::PromptCacheRetention>,
    },
    SetAgent {
        name: String,
        /// The remote adapter already committed this selection and its replay
        /// receipt before dispatch. A live-apply refusal must therefore close
        /// this worker for resumable recovery instead of returning an error
        /// that contradicts the durable receipt.
        durable_selection_committed: bool,
        respond_to: oneshot::Sender<std::result::Result<(), String>>,
    },
    SetToolSurfaceOverride {
        override_json: String,
        persist_session: bool,
        prune_after_switch: bool,
        monty_nudge: Option<String>,
        respond_to: oneshot::Sender<std::result::Result<(), String>>,
    },
    SetGoalSettingsOverride {
        override_json: Option<String>,
        persist_session: bool,
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
        respond_to: oneshot::Sender<std::result::Result<(bool, bool, bool), String>>,
    },
    /// Set (or toggle) request preflight for the running session
    /// (`/preflight`, implementation note). Routes the override to
    /// the driver (which holds it, precedence over config) and broadcasts the
    /// resulting state. **Session-only** — no config-file write. `None`
    /// toggles the driver's current effective state.
    SetPreflight {
        enabled: Option<bool>,
        respond_to: oneshot::Sender<std::result::Result<bool, String>>,
    },
    /// Set (or toggle) long prompt-cache retention intent for the running
    /// session. The driver owns the session-only override and capability
    /// resolution. **Session-only** — no config-file write.
    SetLongcache {
        enabled: Option<bool>,
        respond_to: oneshot::Sender<std::result::Result<bool, String>>,
    },
    /// Set the session's model-comparison tandem (shadow) set.
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
    /// Cancel the foreground turn and every scheduled/background job as one
    /// ordered worker command for the exit guard's "Stop all" choice.
    CancelAll,
    /// Run `/prune` (snapshot dedup) on the foreground agent now.
    Prune,
    /// Run `/compact` (fresh-thread handoff) on the foreground agent.
    Compact,
    /// Build a non-mutating away-resume offer from an exact rolling snapshot.
    PrepareResumeCompaction {
        idle_for_secs: u64,
        respond_to:
            oneshot::Sender<std::result::Result<Option<proto::ResumeCompactionOffer>, String>>,
    },
    /// Apply a previously offered exact rolling compaction without inference.
    ResumeFromCompaction {
        respond_to: oneshot::Sender<std::result::Result<(), String>>,
    },
    /// Pin a user message verbatim for the next `/compact` (`/pin`).
    Pin {
        text: String,
    },
    Shutdown {
        pause_for_resume: bool,
    },
}

/// One-shot constructor: persist its initial redaction boundary, then spawn the
/// worker and return its handle.
///
/// `client_no_sandbox` is the attaching client's `--no-sandbox` flag
/// (sandboxing part 2): `Some(true)` means the client asked for new
/// sessions it creates to be unsandboxed. The session-spawn default is
/// resolved here by the precedence daemon-flag → client-flag → ON.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    session: Arc<Session>,
    guidance_proposals: Arc<
        tokio::sync::Mutex<crate::computer::guidance::service::GuidanceProposalService>,
    >,
    locks: Arc<LockManager>,
    redact: Arc<RedactionTable>,
    model: Arc<Model>,
    model_override: Option<Arc<Model>>,
    thinking_params: Option<serde_json::Value>,
    endpoint_recovery_thinking_params: Option<
        crate::engine::model::EndpointRecoveryAdditionalParams,
    >,
    project_root: PathBuf,
    workspace_root_authority: Arc<
        crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority,
    >,
    client_no_sandbox: bool,
    daemon_no_sandbox: bool,
    extended_cfg: &crate::config::extended::ExtendedConfig,
    lsp: Arc<crate::daemon::lsp::LspManager>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    scheduler: Arc<std::sync::Mutex<Option<crate::daemon::scheduler::DaemonSchedulerHandle>>>,
    write_scope: crate::write_scope::WriteScopeSource,
    global_bus: Option<EventSender>,
    trust_policy: crate::config::trust::WorkspaceTrustPolicy,
    trust_revision: i64,
    cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
    terminal_lock_cleanup_gate: Arc<tokio::sync::Mutex<()>>,
    terminal_closing: Arc<std::sync::atomic::AtomicBool>,
    terminal_cleanup_complete: Arc<std::sync::atomic::AtomicBool>,
    env_snapshot: EnvSnapshot,
    image_generation_boot_id: Uuid,
    image_generation_started_at: std::time::Instant,
    media_storage_recovery: Option<Arc<crate::media_storage::MediaStorageRecovery>>,
    image_generation_dispatch_registry: crate::daemon::image_runtime::DaemonImageDispatchRegistry,
    config_snapshot: SessionConfigSnapshot,
) -> Result<(
    SessionWorkerHandle,
    tokio::task::JoinHandle<()>,
    WorkerStartPermit,
)> {
    let session_id = session.id;
    // The primary the chrome's active-agent slot opens on. Spawn is sync, so
    // it uses the session's in-memory active agent, which is hydrated from the
    // persisted row or the deferred row built on new-session creation. The
    // worker still re-resolves async at startup for stale removed primaries.
    let initial_agent = match session.assistant_name.clone() {
        Some(name) => name,
        None => {
            let active = session.active_agent();
            if crate::agents::is_builtin_primary(&active)
                || crate::agents::is_removed_primary(&active)
            {
                crate::agents::resolve_primary(Some(&active), initial_active_agent(extended_cfg))
            } else if !active.trim().is_empty() {
                active
            } else {
                initial_active_agent(extended_cfg).to_string()
            }
        }
    };
    // Resolve the new-session sandbox default (highest wins):
    //   (a) daemon launched `--no-sandbox` → OFF for ALL sessions.
    //   (b) else this client passed `--no-sandbox` → OFF for the
    //       sessions it creates.
    //   (c) else effective_sandbox_mode(persisted intent, host caps).
    // Unavailable container is Off, never a silent rewrite to host Sandbox.
    // A later `/sandbox` flip overrides this for the session.
    session.set_sandbox_mode(resolve_sandbox_default_with(
        daemon_no_sandbox,
        client_no_sandbox,
        extended_cfg.sandbox.default_mode,
        &config_snapshot.host_capabilities,
    ));
    session.set_sandbox_escalation_enabled(extended_cfg.sandbox_escalation_enabled);
    // Command-approval mode (implementation note): new
    // sessions start in the configured default (`manual` unless overridden).
    // A later `/settings` change re-resolves on the next session.
    session.set_approval_mode(extended_cfg.default_approval_mode);
    // Native shell-output compression (implementation note):
    // new sessions start in the configured default (`enabled` unless
    // overridden). A later `/settings` change re-resolves on the next session.
    session.set_shell_compression(extended_cfg.shell_compression);
    let (work_tx, work_rx) = mpsc::channel::<SessionWork>(WORK_QUEUE_CAPACITY);
    let (event_tx, _initial_rx) =
        broadcast::channel::<crate::daemon::EventEnvelope>(EVENT_BROADCAST_CAPACITY);
    let legacy_disk_origins = match session.persisted_disk_redaction_origins() {
        Ok(origins) => origins,
        Err(error) => {
            tracing::warn!(error = %error, %session_id, "loading persisted disk-derived redaction markers failed");
            Vec::new()
        }
    };
    let redact = match session.persisted_redaction_table() {
        Ok(Some(persisted)) => match persisted.union(&redact) {
            Ok(unioned) => Arc::new(unioned),
            Err(error) => {
                tracing::warn!(error = %error, %session_id, "unioning persisted redaction table failed");
                redact
            }
        },
        Ok(None) => redact,
        Err(error) => {
            tracing::warn!(error = %error, %session_id, "loading persisted redaction table failed");
            redact
        }
    };
    // H1: this initial persist needs no redaction-table write lock. It runs
    // during session-worker construction, strictly BEFORE the shared live table
    // (`redaction`, below) and the per-session `InterruptHub` that owns the write
    // lock exist and before the worker task is spawned — so no sealed adoption,
    // approved-secret-file registration, or per-turn refresh can be in flight.
    // It happens-before every locked writer, so it can neither read a stale table
    // nor be clobbered by one.
    session
        .persist_redaction_table(&redact)
        .context("persisting initial redaction table")?;
    for origin in legacy_disk_origins
        .iter()
        .filter(|origin| !redact.has_origin(origin))
    {
        tracing::warn!(%session_id, origin = %origin, "disk-derived redaction entry could not be re-derived; redaction coverage may be reduced");
    }
    let redaction: SharedRedactionTable = Arc::new(RwLock::new(redact.clone()));
    let turn_completions = Arc::new(Mutex::new(TurnCompletions::default()));
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
    let authoritative_active_model_state = Arc::new(RwLock::new(initial_active_model_state(
        &session,
        &config_snapshot.providers,
    )));
    // Park-commit rendezvous (`daemon-lifecycle-replay-timing-robustness.md`):
    // shared by the handle (read by the registry drain/attach paths) and the
    // worker task (wired into its `InterruptHub`, and signalled when its
    // startup reconciliation pass completes).
    let park_commit = crate::engine::interrupt::ParkCommit::new();
    let config_snapshot = Arc::new(RwLock::new(config_snapshot));
    let trust_transition_pending = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let config_publication = Arc::new(tokio::sync::RwLock::new(()));
    let reserved_root_agent_instance_id = Uuid::new_v4();

    let trust_policy = crate::config::trust::shared_workspace_trust_policy(trust_policy);
    let handle = SessionWorkerHandle {
        session_id,
        project_root: project_root.clone(),
        active_agent_name: initial_agent,
        trust_policy: trust_policy.clone(),
        trust_revision: Arc::new(std::sync::atomic::AtomicI64::new(trust_revision)),
        trust_transition_pending: trust_transition_pending.clone(),
        workspace_root_authority: workspace_root_authority.clone(),
        work_tx,
        event_tx: event_tx.clone(),
        turn_completions: turn_completions.clone(),
        redaction: redaction.clone(),
        live: live.clone(),
        interactive_clients: interactive_clients.clone(),
        session: session.clone(),
        sandbox_notice_armed: sandbox_notice_armed.clone(),
        sandbox_unavailable_notice: Arc::new(RwLock::new(None)),
        locks: locks.clone(),
        env_overlay: env_overlay.clone(),
        repair_required: repair_required.clone(),
        foreground: foreground.clone(),
        config_snapshot: config_snapshot.clone(),
        config_publication,
        authoritative_active_model_state: authoritative_active_model_state.clone(),
        park_commit: park_commit.clone(),
        reserved_root_agent_instance_id,
    };

    handle.probe_sandbox_unavailable();

    // Return the worker's `JoinHandle` so the registry can *await* it on a
    // graceful drain (`daemon-graceful-drain-shutdown.md`) — today's
    // `shutdown_all` fires `Shutdown` and forgets, with no way to know the
    // in-flight turn finished. The handle also lets the force path
    // `abort()` a worker whose provider call hung past the grace deadline.
    // The registry must publish both the handle and its join/watcher authority
    // before the worker can run. Otherwise an immediately-exiting task can run
    // its cleanup callback first and the registry can subsequently install
    // stale live/join entries for a worker that no longer exists.
    let (start_tx, start_rx) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(async move {
        if start_rx.await.is_err() {
            return;
        }
        let _cleanup = WorkerCleanupGuard(cleanup);
        let worker_trust_policy = trust_policy.clone();
        let worker = Box::pin(run_worker(
            session,
            guidance_proposals,
            locks,
            redact,
            model,
            model_override,
            thinking_params,
            endpoint_recovery_thinking_params,
            project_root,
            workspace_root_authority,
            worker_trust_policy,
            work_rx,
            event_tx,
            turn_completions,
            redaction,
            live,
            interactive_clients,
            sandbox_notice_armed,
            env_overlay,
            repair_required,
            foreground,
            config_snapshot,
            trust_transition_pending,
            authoritative_active_model_state,
            lsp,
            resource_scheduler,
            scheduler,
            write_scope,
            global_bus,
            park_commit,
            terminal_lock_cleanup_gate,
            terminal_closing,
            terminal_cleanup_complete,
            image_generation_boot_id,
            image_generation_started_at,
            media_storage_recovery,
            image_generation_dispatch_registry,
            reserved_root_agent_instance_id,
        ));
        crate::config::trust::scope_shared_workspace_trust_policy(trust_policy, worker).await;
    });

    Ok((handle, join, WorkerStartPermit(Some(start_tx))))
}

/// One-shot authority that makes a newly spawned worker runnable only after
/// its registry generation and join/watcher ownership are fully published.
pub struct WorkerStartPermit(Option<tokio::sync::oneshot::Sender<()>>);

impl WorkerStartPermit {
    pub fn release(mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

fn initial_active_model_state(
    session: &Session,
    providers: &crate::config::providers::ProvidersConfig,
) -> Option<proto::ActiveModelState> {
    session.active_model_ref().map(|selection| {
        let default_selection = providers.active_model.clone();
        let diverged = default_selection.as_ref() != Some(&selection);
        proto::ActiveModelState {
            selection,
            default_selection,
            diverged,
            generation: 0,
        }
    })
}
