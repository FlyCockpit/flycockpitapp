/// Handle one or more client tasks hold to drive a session. Cheap to
/// clone — both channels inside are reference-counted.
#[derive(Clone)]
pub struct SessionWorkerHandle {
    pub session_id: Uuid,
    pub project_root: PathBuf,
    pub active_agent_name: String,
    pub trust_policy: crate::config::trust::WorkspaceTrustPolicy,
    work_tx: mpsc::Sender<SessionWork>,
    event_tx: EventSender,
    redaction: SharedRedactionTable,
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
    sandbox_unavailable_notice: Arc<RwLock<Option<SandboxUnavailableNotice>>>,
    /// The daemon-wide lock authority, so the last-detach-while-idle edge can
    /// release this session's locks (implementation note).
    /// The `InteractiveClientGuard`'s `Drop` consults it; the `AgentIdle` edge
    /// lives in the worker's forward seam, which holds its own clone.
    locks: Arc<LockManager>,
    env_overlay: Arc<RwLock<HashMap<String, String>>>,
    repair_required: Arc<RwLock<Option<proto::ResumeRepairState>>>,
    foreground: Arc<Mutex<LiveForegroundState>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxUnavailableNotice {
    remedy: String,
    fix_command: Option<String>,
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
        pending_tool_count: i64,
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

fn send_sandbox_unavailable_notice(
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

fn sandbox_unavailable_notice_from_availability(
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
    }
}

fn emit_session_driver_failed_once(
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
    driver_failed: &mut bool,
    error: String,
) {
    if *driver_failed {
        return;
    }
    *driver_failed = true;
    send_current_event(
        event_tx,
        redaction,
        proto::Event::SessionDriverFailed { session_id, error },
    );
}

async fn send_driver_control_or_fail(
    driver_control_tx: &mpsc::Sender<crate::engine::driver::DriverControl>,
    control: crate::engine::driver::DriverControl,
    event_tx: &EventSender,
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
        redaction,
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
        let redaction: SharedRedactionTable =
            Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
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
            redaction,
            live: Arc::new(LiveState::default()),
            interactive_clients: Arc::new(AtomicUsize::new(0)),
            session,
            sandbox_notice_armed: Arc::new(AtomicBool::new(false)),
            sandbox_unavailable_notice: Arc::new(RwLock::new(None)),
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
            },
        );
        if new.enabled() {
            self.probe_sandbox_unavailable();
        }
        Ok(new)
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
    pub fn subscribe(&self) -> EventReceiver {
        self.event_tx.subscribe()
    }

    pub fn redaction_table(&self) -> Arc<RedactionTable> {
        current_redaction(&self.redaction)
    }

    pub fn broadcast_notice(&self, text: String) {
        send_current_event(
            &self.event_tx,
            &self.redaction,
            proto::Event::Notice {
                session_id: self.session_id,
                text,
            },
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

    pub fn broadcast_active_interrupt(&self) {
        let Ok(open) = self.session.db.list_open_interrupts(self.session_id) else {
            return;
        };
        let Some(active) = open.first() else {
            return;
        };
        let questions = active.questions.clone().or_else(|| {
            active.question.clone().map(|question| proto::InterruptQuestionSet {
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
            if !session.sandbox_mode().enabled() {
                *notice_store
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                return;
            }
            let availability = crate::tools::shell_sandbox::sandbox_available(&project_root)
                .await
                .clone();
            match sandbox_unavailable_notice_from_availability(&availability) {
                Some(notice) => {
                    *notice_store
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(notice.clone());
                    if session.sandbox_mode().enabled() && forward_sandbox_unavailable(&armed) {
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
pub enum SessionWork {
    UserMessage {
        submission: Box<crate::engine::message::UserSubmission>,
        respond_to: oneshot::Sender<(proto::QueueItem, Vec<proto::QueueItem>)>,
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
    RepublishQueue,
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
    global_bus: Option<EventSender>,
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
    if let Err(error) = session.persist_redaction_table(&redact) {
        tracing::warn!(error = %error, %session_id, "persisting initial redaction table failed");
    }
    let redaction: SharedRedactionTable = Arc::new(RwLock::new(redact.clone()));
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
    };

    handle.probe_sandbox_unavailable();

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
                redaction,
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
