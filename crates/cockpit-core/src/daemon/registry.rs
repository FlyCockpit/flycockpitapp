//! Session registry — owns the live [`SessionWorkerHandle`]s.
//!
//! One [`SessionRegistry`] per daemon process. Maps `session_id →
//! handle`; spawns a worker lazily on first `attach`, returns the
//! existing handle on subsequent attaches to the same id.
//!
//! Attach modes:
//!
//! - `attach(None, Some(project_root))` — create a fresh session in
//!   `project_root`.
//! - `attach(Some(id), _)` — resume the session with that id. Errors
//!   if no DB row exists.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::json;
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, watch};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::{ActiveModelRef, ProvidersConfig};
use crate::config::trust::{
    WorkspaceTrustError, WorkspaceTrustPolicy, resolve_workspace_trust_policy_with_revision_from_db,
};
use crate::daemon::EventSender;
use crate::daemon::server::CONFIG_PUBLICATION_RPC_LOCK;
use crate::daemon::session_worker::{self, SessionWorkerHandle};
use crate::daemon::shutdown::ShutdownSignal;
use crate::db::Db;
use crate::engine::model::Model;
use crate::env_snapshot::EnvSnapshot;
use crate::locks::LockManager;
use crate::redact::RedactionTable;
use crate::redact::protected_redaction_history::RedactionKeyResolver;
use crate::session::Session;

#[derive(Debug, Error)]
#[error("session entry mode conflict: session is {actual}, attach requested {requested}")]
pub(crate) struct SessionEntryModeConflict {
    pub actual: &'static str,
    pub requested: &'static str,
}

/// A generation observed during attach could not be activated without being
/// replaced or closed. Callers must retry the authoritative attach lookup;
/// they must never fall back to a bare session-id operation.
#[derive(Debug, Error)]
#[error("session changed while attaching; retry attach")]
pub(crate) struct SessionAttachRetry;

/// The prior worker generation reached terminal shutdown but its permanent
/// lock cleanup could not be committed. The registry retains that exact
/// generation so a later attach can retry cleanup without ever touching a
/// successor incarnation.
#[derive(Debug, Error)]
#[error("terminal session cleanup is incomplete; retry attach")]
pub(crate) struct SessionTerminalCleanupRetry;

#[cfg(not(test))]
pub const DESTRUCTIVE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub const DESTRUCTIVE_STOP_TIMEOUT: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const START_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const START_WAIT_TIMEOUT: Duration = Duration::from_millis(50);

/// Product-owned upper bound on how long shutdown/attach waits for every
/// registered interrupt's park to commit to SQLite
/// (`daemon-lifecycle-replay-timing-robustness.md`). This is **not** `--grace`:
/// `--grace` bounds genuinely in-flight tool/inference work (settled by
/// `daemon-drain-grace-and-activity-state`), whereas an interrupt park is the
/// "zero-grace instant park" that same prompt kept separate. The deadline only
/// caps a wedged worker so shutdown can still release pid/socket for a
/// successor; the normal path resolves the instant the park commits, so this is
/// a completion signal, not a widened timeout.
pub(crate) const INTERRUPT_PARK_COMMIT_DEADLINE: Duration = Duration::from_secs(5);

type WorkerGeneration = u64;

/// Compile-time proof that a worker start remains inside the daemon-wide
/// publication critical section. `start_worker` deliberately requires this
/// private capability so a future start path cannot bypass trust inventory
/// capture merely by calling the low-level constructor.
struct WorkerPublicationPermit<'a> {
    _guard: &'a tokio::sync::MutexGuard<'a, ()>,
}

/// Outcome of [`SessionRegistry::drain_all`]. Splits the two independent
/// shutdown guarantees the drain path now enforces
/// (`daemon-lifecycle-replay-timing-robustness.md`): the historical
/// grace-bounded drain of genuinely in-flight work, and the decoupled
/// interrupt-park commit that gates pid/socket release.
#[derive(Clone, Copy, Debug)]
pub struct DrainOutcome {
    /// Genuinely in-flight tool/inference work drained within `--grace`. This
    /// is the historical `drain_all` boolean: `false` when the grace deadline
    /// forced a worker abort.
    pub running_work_clean: bool,
    /// Terminal state of the interrupt-park commit wait — the new signal that
    /// keeps `metadata_guard.cleanup()`/`"daemon: restarted"` truthful.
    pub park_commit: crate::engine::interrupt::ParkCommitTerminal,
}

impl DrainOutcome {
    /// A fully clean shutdown: in-flight work drained AND every registered
    /// interrupt park committed. Only this may take the clean-success path.
    pub fn is_clean(self) -> bool {
        self.running_work_clean && self.park_commit.is_clean()
    }
}

/// Outcome of trying to hand a worker its graceful-shutdown `Shutdown` message
/// under a bounded deadline (`daemon-lifecycle-replay-timing-robustness.md`,
/// finding 1). Distinguishes a benign already-exited worker from a wedged one
/// whose full queue would otherwise block drain forever.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ShutdownDispatch {
    /// Accepted onto the worker's queue.
    Delivered,
    /// Send errored because the worker already exited (receiver dropped).
    WorkerGone,
    /// Send timed out — queue full and the worker not receiving; force-abort.
    Wedged,
}

/// Await the shutdown park-commit of every worker that owed one, each bounded
/// by `deadline`, and aggregate to a single terminal
/// (`daemon-lifecycle-replay-timing-robustness.md`). Mirrors `drain_all`'s
/// `join_all` fan-out: the signal aggregates across *every* live worker with a
/// registered waiter, not just the first. An empty obligation set resolves
/// immediately to `Committed` (proven none) so a no-waiter drain never waits.
async fn await_park_commits(
    obligations: &[crate::engine::interrupt::ParkCommit],
    deadline: Duration,
) -> crate::engine::interrupt::ParkCommitTerminal {
    use crate::engine::interrupt::ParkCommitTerminal;
    if obligations.is_empty() {
        return ParkCommitTerminal::Committed;
    }
    let results = futures::future::join_all(
        obligations
            .iter()
            .map(|park_commit| park_commit.await_shutdown_commit(deadline)),
    )
    .await;
    // A real failed write is the most informative non-clean terminal; an
    // unresolved deadline is the fallback. Either makes `is_clean()` false.
    let mut terminal = ParkCommitTerminal::Committed;
    for result in results {
        match result {
            ParkCommitTerminal::Committed => {}
            ParkCommitTerminal::KnownFailedWrite => return ParkCommitTerminal::KnownFailedWrite,
            ParkCommitTerminal::DeadlineUnresolved => {
                terminal = ParkCommitTerminal::DeadlineUnresolved;
            }
        }
    }
    terminal
}

/// Daemon-wide registry of active session workers.
#[derive(Clone)]
pub struct SessionRegistry {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    locks: Arc<LockManager>,
    lsp: Arc<crate::daemon::lsp::LspManager>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    scheduler: Arc<Mutex<Option<crate::daemon::scheduler::DaemonSchedulerHandle>>>,
    /// Durable write-scope authority. Late-installed like `scheduler`: the
    /// coordinator is built in `boot_with_db`, after this registry exists.
    write_scope: crate::write_scope::WriteScopeSource,
    external_journal: Arc<Mutex<Option<Arc<crate::external_journal::ExternalJournal>>>>,
    /// Daemon descendant process-containment handle. Late-installed like
    /// `external_journal` (the daemon builds the actor after this registry
    /// exists), then copied onto every worker `Session` so lifecycle hooks run
    /// their children under a proven containment lease.
    process_containment: Arc<Mutex<Option<crate::process_containment::ProcessContainmentHandle>>>,
    /// Required protected redaction-history key resolver installed on every
    /// `Session` this registry builds (decision 16). Late-installed at daemon
    /// boot after the secure-key actor attaches — the same seam that installs
    /// `external_journal` — but unlike the journal it is a **required**
    /// construction dependency: a session build fails closed if it is absent.
    redaction_key_resolver: Arc<Mutex<Option<Arc<dyn RedactionKeyResolver>>>>,
    /// Daemon-held wrap-key vault installed at construction. Session
    /// create/resume/fork use this handle instead of opening a second vault.
    secret_vault: Arc<Mutex<Option<Arc<crate::secure_key::SecretVault>>>>,
    /// Daemon-process cache of resolved command-backed named secrets
    /// (`command-backed-secret-refs-daemon`). One cache per daemon process,
    /// single-flight per name; sync lookups never execute. Created eagerly with
    /// the real subprocess executor so it is always present; tests swap in a
    /// counting-executor cache via [`SessionRegistry::set_command_secret_cache`]
    /// before any session starts.
    command_secret_cache: Mutex<Arc<crate::secret_command::CommandSecretCache>>,
    workers: Mutex<WorkerState>,
    /// Linearizes worker publication with authority transitions that must
    /// capture every worker for a durable root.  A start owner holds this from
    /// before trust/config resolution through insertion into `workers.live`;
    /// SetWorkspaceTrust holds it from exact inventory capture through the DB
    /// decision and live-policy transition.  Consequently a worker can be
    /// wholly before or wholly after a trust commit, never inserted between
    /// capture and publication with an attach-time policy snapshot.
    worker_publication: Arc<AsyncMutex<()>>,
    /// Live `JoinHandle` per worker, so a graceful drain can *await* the
    /// in-flight turn finishing (and `abort()` it past the deadline).
    /// Keyed by the same `session_id` as `workers`; populated on spawn,
    /// removed by [`Self::forget`] when the worker exits. Join entries carry
    /// the same generation as the live handle so stale cleanup cannot remove
    /// a successor for the same session id.
    worker_joins: Mutex<HashMap<Uuid, WorkerJoin>>,
    /// Daemon-wide graceful-shutdown gate
    /// (`daemon-graceful-drain-shutdown.md`). Installed into every worker's
    /// model so the inference-dispatch chokepoint refuses new provider
    /// requests once a drain begins. The drain state lives here, on the
    /// daemon's central authority — never scattered per call.
    shutdown: ShutdownSignal,
    /// Daemon-global event bus, installed once by [`DaemonContext`]. Workers
    /// use it for singular global recomputes derived from per-session events.
    global_bus: Mutex<Option<EventSender>>,
    /// Injectable config-resolution seam (`daemon-trust-test-isolation.md`).
    /// Production wires [`ConfigSource::production`] once at daemon startup;
    /// tests inject fixed configs so no attach/resume/worker path consults
    /// the machine's live layered config.
    config_source: crate::daemon::config_source::ConfigSource,
    /// Test-only seam for proving that the start boundary cannot replace the
    /// authority/configuration preflight selected. Production has no callback
    /// between those two phases.
    #[cfg(test)]
    pre_start_worker_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Shared host-capability snapshot. Late-installed after
    /// [`crate::daemon::server::DaemonContext`] owns the store.
    host_capabilities: Mutex<Option<crate::host_capabilities::HostCapabilitySnapshotStore>>,
    /// The probe sources paired with the daemon-owned snapshot.  They are not
    /// configuration: a recovered refresh operation must use the same
    /// composition-owned runtime that the original attached request used.
    host_capability_probes: Mutex<Option<crate::host_capabilities::HostCapabilityProbeInputs>>,
}

struct WorkerState {
    live: HashMap<Uuid, WorkerEntry>,
    starting: HashMap<Uuid, Arc<StartSlot>>,
    next_generation: WorkerGeneration,
}

struct WorkerEntry {
    generation: WorkerGeneration,
    handle: SessionWorkerHandle,
    /// An attach has accepted this exact worker generation and is still
    /// committing reconciliation/activation. A closed entry stays in place
    /// until the lease drops so a successor can never inherit that request's
    /// session-id-only lock resume.
    activation_leases: usize,
    /// Serializes a generation-bound reattach lock resume with this worker's
    /// terminal `LockManager::end_session` cleanup.  It is deliberately per
    /// generation: an old cleanup must never touch a successor's locks.
    terminal_lock_cleanup_gate: Arc<AsyncMutex<()>>,
    /// Set by the worker immediately before its terminal lock cleanup begins.
    terminal_closing: Arc<AtomicBool>,
    /// Set only after terminal lock cleanup completes.  Registry removal may
    /// proceed after this point, never before it.
    terminal_cleanup_complete: Arc<AtomicBool>,
}

struct WorkerJoin {
    generation: WorkerGeneration,
    join: JoinHandle<()>,
    _config_watcher: Option<ConfigWatcherJoin>,
}

struct ConfigWatcherJoin(JoinHandle<()>);

impl Drop for ConfigWatcherJoin {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct StartSlot {
    generation: WorkerGeneration,
    result: Mutex<Option<std::result::Result<SessionWorkerHandle, StartFailure>>>,
    ready: watch::Sender<()>,
}

#[derive(Clone)]
enum StartFailure {
    WorkspaceTrust(WorkspaceTrustError),
    Other(String),
}

impl StartFailure {
    fn from_error(error: &anyhow::Error) -> Self {
        error
            .downcast_ref::<WorkspaceTrustError>()
            .cloned()
            .map(Self::WorkspaceTrust)
            .unwrap_or_else(|| Self::Other(error.to_string()))
    }

    fn into_error(self) -> anyhow::Error {
        match self {
            Self::WorkspaceTrust(error) => anyhow::Error::new(error),
            Self::Other(message) => anyhow::Error::msg(message),
        }
    }
}

impl StartSlot {
    fn finish(&self, result: std::result::Result<SessionWorkerHandle, StartFailure>) {
        let mut slot_result = crate::sync::lock_or_recover(&self.result);
        if slot_result.is_none() {
            *slot_result = Some(result);
            let _ = self.ready.send(());
        }
    }
}

struct StartTicket {
    inner: Arc<Inner>,
    session_id: Uuid,
    slot: Arc<StartSlot>,
    completed: bool,
}

impl StartTicket {
    fn generation(&self) -> WorkerGeneration {
        self.slot.generation
    }

    fn finish(mut self, result: &Result<SessionWorkerHandle>) {
        remove_start_slot(&self.inner, self.session_id, &self.slot);
        self.slot.finish(match result {
            Ok(handle) => Ok(handle.clone()),
            Err(error) => Err(StartFailure::from_error(error)),
        });
        self.completed = true;
    }
}

impl Drop for StartTicket {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        remove_start_slot(&self.inner, self.session_id, &self.slot);
        self.slot.finish(Err(StartFailure::Other(format!(
            "session worker {} start abandoned before completion",
            self.session_id
        ))));
    }
}

enum AttachClaim {
    Live(LiveAttachClaim),
    CleanupRequired(LiveAttachClaim),
    Activating,
    Starting(Arc<StartSlot>),
    Start(StartTicket),
}

/// A generation-fenced observation of a live worker.
///
/// A lazy session has no durable row, so dispatch must read its root and mode
/// from the worker. Durable and lazy reattach both need the same protection:
/// facts are valid only while this exact registry generation remains live. The
/// opaque claim is intentionally consumed by
/// [`SessionRegistry::activate_claimed_live_session`], which rechecks the
/// generation before it can reactivate released locks.
pub(crate) struct LiveAttachClaim {
    inner: Weak<Inner>,
    session_id: Uuid,
    generation: WorkerGeneration,
    handle: SessionWorkerHandle,
    session_entry_mode: crate::daemon::proto::SessionEntryMode,
    project_root: PathBuf,
    terminal_lock_cleanup_gate: Arc<AsyncMutex<()>>,
    terminal_cleanup_complete: Arc<AtomicBool>,
}

impl Drop for LiveAttachClaim {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let should_forget = {
            let mut workers = crate::sync::lock_or_recover(&inner.workers);
            let Some(entry) = workers.live.get_mut(&self.session_id) else {
                return;
            };
            if entry.generation != self.generation {
                return;
            }
            entry.activation_leases = entry.activation_leases.saturating_sub(1);
            entry.activation_leases == 0
                && entry.handle.is_closed()
                && (!entry.terminal_closing.load(Ordering::Acquire)
                    || entry.terminal_cleanup_complete.load(Ordering::Acquire))
        };
        if should_forget {
            forget_generation_from_inner(&inner, self.session_id, self.generation);
        }
    }
}

impl LiveAttachClaim {
    pub(crate) fn session_entry_mode(&self) -> crate::daemon::proto::SessionEntryMode {
        self.session_entry_mode
    }

    pub(crate) fn project_root(&self) -> &PathBuf {
        &self.project_root
    }

    pub(crate) fn handle(&self) -> &SessionWorkerHandle {
        &self.handle
    }
}

async fn wait_for_start(slot: Arc<StartSlot>) -> Result<SessionWorkerHandle> {
    let mut ready = slot.ready.subscribe();
    loop {
        if let Some(result) = crate::sync::lock_or_recover(&slot.result).clone() {
            return result.clone().map_err(StartFailure::into_error);
        }
        match tokio::time::timeout(START_WAIT_TIMEOUT, ready.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => bail!(
                "session worker start waiter closed before generation {} completed",
                slot.generation
            ),
            Err(_) => bail!(
                "session worker start generation {} did not complete within {}ms",
                slot.generation,
                START_WAIT_TIMEOUT.as_millis()
            ),
        }
    }
}

fn with_worker_model_runtime(
    model: Model,
    shutdown: &ShutdownSignal,
    config_path: Option<PathBuf>,
) -> Arc<Model> {
    let model = model.with_shutdown_gate(shutdown.clone());
    let model = match config_path {
        Some(path) => model.with_config_path(path),
        None => model,
    };
    Arc::new(model)
}

fn resolve_session_active_model(
    providers_cfg: &ProvidersConfig,
    session: &Session,
) -> Result<ActiveModelRef> {
    // Resume keeps the session's persisted model. Fresh sessions with a
    // prepared vNext installation resolve the primary-slot default from the
    // agent factory (`resolve_vnext_slot_model`); this path remains the
    // no-installation / legacy `active_model` fallback.
    if let Some(active) = session.active_model_ref() {
        return Ok(active);
    }
    let active = providers_cfg
        .active_model
        .clone()
        .context("session has no active model selection and no default is configured")?;
    Ok(active)
}

fn resolve_session_worker_model(
    providers_cfg: &ProvidersConfig,
    extended_cfg: &ExtendedConfig,
    session: &Session,
    redact: Arc<RedactionTable>,
    env_snapshot: &EnvSnapshot,
    config_path: Option<PathBuf>,
    shutdown: &ShutdownSignal,
) -> Result<Arc<Model>> {
    let inherited_model = {
        let active = resolve_session_active_model(providers_cfg, session)?;
        let mut session_providers = providers_cfg.clone();
        session_providers.active_model = Some(active);
        let env_lookup = |name: &str| env_snapshot.vars().get(name).cloned();
        // Owner-scoped resolution: this provider request may only resolve
        // `$secret:` names owned by (provider, this workspace root). See
        // `named-secret-ownership-boundary`. `provider_credential_store` injects
        // any resolved command-backed outputs from the installed daemon cache (a
        // sync, execution-free lookup) so a `$secret:` command reference expands
        // to the cached value.
        let store = session.provider_credential_store(&session_providers)?;
        let model =
            Model::from_config_with_store(&session_providers, redact.clone(), env_lookup, store)?;
        with_worker_model_runtime(model, shutdown, config_path.clone())
    };

    if !session.is_btw_fork() {
        return Ok(inherited_model);
    }

    let Some(model_ref) = extended_cfg.btw_model_ref() else {
        return Ok(inherited_model);
    };
    let env_lookup = |name: &str| env_snapshot.vars().get(name).cloned();
    let store = session.provider_credential_store(providers_cfg)?;
    let secret_lookup = {
        let store = store.clone();
        move |name: &str| store.named_secret(name).map(str::to_string)
    };
    let model = split_btw_model_ref(model_ref)
        .context("model ref must be provider:model-id or provider/model")
        .and_then(|(provider, model_id)| {
            Model::for_provider_with_sources(
                providers_cfg,
                &provider,
                &model_id,
                redact,
                env_lookup,
                secret_lookup,
                Some(store),
            )
        });

    match model {
        Ok(model) => Ok(with_worker_model_runtime(model, shutdown, config_path)),
        Err(error) => {
            tracing::warn!(
                error = %error,
                model = %model_ref,
                session_id = %session.id,
                "btw_model failed to resolve; using parent session model"
            );
            Ok(inherited_model)
        }
    }
}

fn split_btw_model_ref(value: &str) -> Option<(String, String)> {
    value
        .split_once('/')
        .or_else(|| value.split_once(':'))
        .and_then(|(provider, model)| {
            let provider = provider.trim();
            let model = model.trim();
            (!provider.is_empty() && !model.is_empty())
                .then(|| (provider.to_string(), model.to_string()))
        })
}

fn remove_start_slot(inner: &Inner, session_id: Uuid, slot: &Arc<StartSlot>) {
    let mut workers = crate::sync::lock_or_recover(&inner.workers);
    if workers
        .starting
        .get(&session_id)
        .is_some_and(|current| Arc::ptr_eq(current, slot))
    {
        workers.starting.remove(&session_id);
    }
}

fn next_generation(state: &mut WorkerState) -> WorkerGeneration {
    state.next_generation = state.next_generation.saturating_add(1).max(1);
    state.next_generation
}

fn forget_generation_from_inner(inner: &Inner, session_id: Uuid, generation: WorkerGeneration) {
    let retained_by_activation = {
        let mut workers = crate::sync::lock_or_recover(&inner.workers);
        if workers.live.get(&session_id).is_some_and(|entry| {
            entry.generation == generation
                && entry.activation_leases == 0
                && (!entry.terminal_closing.load(Ordering::Acquire)
                    || entry.terminal_cleanup_complete.load(Ordering::Acquire))
        }) {
            workers.live.remove(&session_id);
            false
        } else {
            workers
                .live
                .get(&session_id)
                .is_some_and(|entry| entry.generation == generation)
        }
    };
    if retained_by_activation {
        return;
    }
    let mut joins = crate::sync::lock_or_recover(&inner.worker_joins);
    if joins
        .get(&session_id)
        .is_some_and(|entry| entry.generation == generation)
    {
        joins.remove(&session_id);
    }
}

fn cleanup_worker_on_exit(inner: Weak<Inner>, session_id: Uuid, generation: WorkerGeneration) {
    if let Some(inner) = inner.upgrade() {
        forget_generation_from_inner(&inner, session_id, generation);
    }
}

impl SessionRegistry {
    pub fn new(
        db: Db,
        locks: Arc<LockManager>,
        shutdown: ShutdownSignal,
        resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
        config_source: crate::daemon::config_source::ConfigSource,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                locks,
                lsp: Arc::new(crate::daemon::lsp::LspManager::new()),
                write_scope: Arc::new(Mutex::new(None)),
                external_journal: Arc::new(Mutex::new(None)),
                process_containment: Arc::new(Mutex::new(None)),
                redaction_key_resolver: Arc::new(Mutex::new(None)),
                secret_vault: Arc::new(Mutex::new(None)),
                command_secret_cache: Mutex::new(
                    crate::secret_command::CommandSecretCache::with_subprocess_executor(),
                ),
                resource_scheduler,
                scheduler: Arc::new(Mutex::new(None)),
                workers: Mutex::new(WorkerState {
                    live: HashMap::new(),
                    starting: HashMap::new(),
                    next_generation: 0,
                }),
                worker_publication: Arc::new(AsyncMutex::new(())),
                worker_joins: Mutex::new(HashMap::new()),
                shutdown,
                global_bus: Mutex::new(None),
                config_source,
                #[cfg(test)]
                pre_start_worker_hook: Mutex::new(None),
                host_capabilities: Mutex::new(None),
                host_capability_probes: Mutex::new(None),
            }),
        }
    }

    pub fn set_host_capabilities(
        &self,
        store: crate::host_capabilities::HostCapabilitySnapshotStore,
        probes: crate::host_capabilities::HostCapabilityProbeInputs,
    ) {
        *crate::sync::lock_or_recover(&self.inner.host_capabilities) = Some(store);
        *crate::sync::lock_or_recover(&self.inner.host_capability_probes) = Some(probes);
    }

    #[cfg(test)]
    fn set_pre_start_worker_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *crate::sync::lock_or_recover(&self.inner.pre_start_worker_hook) = hook;
    }

    #[cfg(test)]
    fn run_pre_start_worker_hook(&self) {
        if let Some(hook) = crate::sync::lock_or_recover(&self.inner.pre_start_worker_hook).clone()
        {
            hook();
        }
    }

    fn current_host_capabilities(&self) -> cockpit_proto::HostCapabilitySnapshot {
        crate::sync::lock_or_recover(&self.inner.host_capabilities)
            .as_ref()
            .and_then(|store| store.current().map(|snapshot| (*snapshot).clone()))
            .unwrap_or_else(session_worker::unpublished_host_capability_snapshot)
    }

    fn host_capability_refresh_runtime(
        &self,
    ) -> Option<session_worker::HostCapabilityRefreshRuntime> {
        let store = crate::sync::lock_or_recover(&self.inner.host_capabilities).clone()?;
        let probes = crate::sync::lock_or_recover(&self.inner.host_capability_probes).clone()?;
        Some(session_worker::HostCapabilityRefreshRuntime {
            serial_execution: store.refresh_serialization(),
            in_flight_operations: store.refresh_in_flight_operations(),
            store,
            probes,
        })
    }

    pub fn lsp_manager(&self) -> Arc<crate::daemon::lsp::LspManager> {
        self.inner.lsp.clone()
    }

    #[allow(dead_code)]
    pub fn resource_scheduler(
        &self,
    ) -> Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>> {
        self.inner.resource_scheduler.clone()
    }

    pub fn set_global_bus(&self, tx: EventSender) {
        *crate::sync::lock_or_recover(&self.inner.global_bus) = Some(tx);
    }

    pub fn set_scheduler(&self, handle: crate::daemon::scheduler::DaemonSchedulerHandle) {
        *crate::sync::lock_or_recover(&self.inner.scheduler) = Some(handle);
    }

    pub fn set_write_scope(
        &self,
        coordinator: std::sync::Arc<crate::write_scope::WriteScopeCoordinator>,
    ) {
        *crate::sync::lock_or_recover(&self.inner.write_scope) = Some(coordinator);
    }

    fn write_scope_source(&self) -> crate::write_scope::WriteScopeSource {
        self.inner.write_scope.clone()
    }

    pub fn set_external_journal(&self, journal: Arc<crate::external_journal::ExternalJournal>) {
        *crate::sync::lock_or_recover(&self.inner.external_journal) = Some(journal);
    }

    fn external_journal(&self) -> Option<Arc<crate::external_journal::ExternalJournal>> {
        crate::sync::lock_or_recover(&self.inner.external_journal).clone()
    }

    /// Install the daemon's descendant process-containment handle. Called once
    /// at boot after the containment actor attaches; every worker session built
    /// afterwards copies this handle so its lifecycle hooks are contained.
    pub fn set_process_containment(
        &self,
        handle: crate::process_containment::ProcessContainmentHandle,
    ) {
        *crate::sync::lock_or_recover(&self.inner.process_containment) = Some(handle);
    }

    fn process_containment(&self) -> Option<crate::process_containment::ProcessContainmentHandle> {
        crate::sync::lock_or_recover(&self.inner.process_containment).clone()
    }

    /// Install the daemon's shared protected redaction-history key resolver.
    /// Called once at boot after the secure-key actor attaches; every session
    /// built afterwards shares this one cache.
    pub fn set_redaction_key_resolver(&self, resolver: Arc<dyn RedactionKeyResolver>) {
        *crate::sync::lock_or_recover(&self.inner.redaction_key_resolver) = Some(resolver);
    }

    /// The installed resolver, or a fail-closed error. A session build must not
    /// proceed without a resolver (decision 16); production installs it at boot.
    fn redaction_key_resolver(&self) -> Result<Arc<dyn RedactionKeyResolver>> {
        crate::sync::lock_or_recover(&self.inner.redaction_key_resolver)
            .clone()
            .context("protected redaction-history key resolver not installed on registry")
    }

    pub fn set_secret_vault(&self, vault: Arc<crate::secure_key::SecretVault>) {
        *crate::sync::lock_or_recover(&self.inner.secret_vault) = Some(vault);
    }

    fn secret_vault(&self) -> Result<Arc<crate::secure_key::SecretVault>> {
        crate::sync::lock_or_recover(&self.inner.secret_vault)
            .clone()
            .context("secret vault not installed on registry")
    }

    /// Install a specific command-secret cache. Production uses the eager
    /// subprocess-backed cache from construction; this is the test seam that
    /// injects a counting-executor cache so exec-count assertions are possible.
    /// Must be called before any session start.
    pub fn set_command_secret_cache(&self, cache: Arc<crate::secret_command::CommandSecretCache>) {
        *crate::sync::lock_or_recover(&self.inner.command_secret_cache) = cache;
    }

    /// The daemon-process command-secret cache (single-flight per name; sync
    /// lookups never execute).
    pub(crate) fn command_secret_cache(&self) -> Arc<crate::secret_command::CommandSecretCache> {
        crate::sync::lock_or_recover(&self.inner.command_secret_cache).clone()
    }

    /// Pre-resolve (execute-once) every command-backed secret referenced by
    /// `providers_cfg`'s headers into the daemon cache, reading argv specs
    /// through the session's OWNER-SCOPED provider store — so only command names
    /// owned by `(provider, this workspace)` are ever executed; a foreign-owned
    /// name is dropped from the scoped view and never execed. Called on the ASYNC
    /// session create/resume path BEFORE the sync `start_worker`, so every
    /// subsequent sync redaction/model build (start, model-switch, tandem,
    /// redaction refresh) observes the CACHE and never triggers a subprocess exec
    /// (`async_resolve_precedes_redaction_and_model_build`).
    pub(crate) async fn preresolve_session_command_secrets(
        &self,
        session: &Session,
        providers_cfg: &ProvidersConfig,
    ) {
        let referenced = crate::secret_ref::provider_named_secret_references(providers_cfg);
        if referenced.is_empty() {
            return;
        }
        let store = match session.provider_credential_store(providers_cfg) {
            Ok(store) => store,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "command-secret pre-resolution skipped: owner-scoped store unavailable"
                );
                return;
            }
        };
        self.resolve_referenced_from_store(&store, &referenced, false)
            .await;
    }

    /// Resolve (optionally invalidating first) the command-backed secrets in
    /// `referenced` that are owned by `(provider, project_root)`. Reads argv
    /// specs through an OWNER-SCOPED store so a foreign-owned name is never
    /// executed. Used by daemon startup, provider-config update, and DocsAsk —
    /// all of which know the concrete `(provider, workspace root)` scope.
    pub(crate) async fn resolve_provider_command_secrets(
        &self,
        project_root: &str,
        referenced: &std::collections::BTreeSet<String>,
        invalidate: bool,
    ) {
        if referenced.is_empty() {
            return;
        }
        let Ok(vault) = self.secret_vault() else {
            return;
        };
        let store = match crate::credentials::CredentialStore::from_vault_owner_scoped(
            vault,
            crate::secret_ownership::OWNER_KIND_PROVIDER,
            &crate::secret_ownership::canonical_owner_root(project_root),
            referenced,
            // No cross-config scan here: never lazily claim an unclaimed name.
            // An already-provider-owned name (claimed on provider save) resolves;
            // a foreign / unclaimed name is dropped and never execed.
            None,
        ) {
            Ok(store) => store,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "command-secret resolution skipped: owner-scoped store unavailable"
                );
                return;
            }
        };
        self.resolve_referenced_from_store(&store, referenced, invalidate)
            .await;
    }

    /// Resolve each `referenced` command-backed name from an ALREADY OWNER-SCOPED
    /// `store`: a name the scoped store does not know as command-backed (foreign,
    /// unclaimed, or literal) is skipped and never executed. `store` is an owned
    /// snapshot, so no lock guard is held across the `.await`s below.
    async fn resolve_referenced_from_store(
        &self,
        store: &crate::credentials::CredentialStore,
        referenced: &std::collections::BTreeSet<String>,
        invalidate: bool,
    ) {
        let cache = self.command_secret_cache();
        for name in referenced {
            let Some(argv) = store.named_secret_command_spec(name) else {
                continue;
            };
            let argv = argv.to_vec();
            if invalidate {
                cache.invalidate(name);
            }
            // Single-flight, execute-once (or once-more after invalidate). The
            // resolved value stays in daemon memory; only a sanitized status is
            // observable outside the cache.
            cache.ensure_resolved(name, &argv).await;
        }
    }

    pub fn scheduler(&self) -> Option<crate::daemon::scheduler::DaemonSchedulerHandle> {
        crate::sync::lock_or_recover(&self.inner.scheduler).clone()
    }

    fn scheduler_source(
        &self,
    ) -> Arc<Mutex<Option<crate::daemon::scheduler::DaemonSchedulerHandle>>> {
        self.inner.scheduler.clone()
    }

    /// Spawn (or look up) the worker for a session. Live workers retain their
    /// immutable trust/config snapshot. Every path that actually starts a new
    /// worker resolves trust and config only after winning the atomic start
    /// claim, so a handle that closes during attach cannot turn a formerly-live
    /// policy snapshot into a newly-started worker.
    #[allow(clippy::too_many_arguments)]
    pub async fn attach(
        &self,
        session_id: Option<Uuid>,
        project_root: Option<PathBuf>,
        initial_model: Option<ActiveModelRef>,
        client_no_sandbox: bool,
        model_override: Option<&ActiveModelRef>,
        env_snapshot: EnvSnapshot,
        session_entry_mode: crate::daemon::proto::SessionEntryMode,
    ) -> Result<SessionWorkerHandle> {
        // This is deliberately daemon-wide rather than keyed by session id:
        // trust transitions select workers by durable workspace root, while a
        // cold attach does not know that root until it has resolved authority.
        // Holding the gate through insertion also makes the attach-time trust
        // sample the committed one when a transition wins first.
        let worker_publication = self.inner.worker_publication.lock().await;
        let worker_publication_permit = WorkerPublicationPermit {
            _guard: &worker_publication,
        };
        // Resume path.
        if let Some(id) = session_id {
            // Resolve the handle for whichever claim path this attach takes.
            // The reconciliation gate below is applied UNIFORMLY afterwards
            // (finding 3) so no claim path can slip a pre-reconciliation handle
            // back to a client.
            let mut cleanup_attempts = 0_u8;
            let claim = loop {
                let claim = match self.claim_attach(id) {
                    AttachClaim::Live(claim) => {
                        // Reattach to a still-alive worker (the worker outlives client
                        // disconnects, GOALS §8b). Re-acquire any locks released when
                        // the last client detached while idle
                        // (implementation note). A no-op when no
                        // release snapshot exists — so a second concurrent attach to an
                        // already-attached session triggers nothing.
                        claim
                    }
                    AttachClaim::CleanupRequired(claim) => {
                        cleanup_attempts = cleanup_attempts.saturating_add(1);
                        let result = self.complete_terminal_cleanup(&claim).await;
                        drop(claim);
                        match result {
                            Ok(()) if cleanup_attempts == 1 => continue,
                            Ok(()) | Err(_) => return Err(SessionTerminalCleanupRetry.into()),
                        }
                    }
                    AttachClaim::Activating => {
                        return Err(SessionAttachRetry.into());
                    }
                    AttachClaim::Starting(slot) => {
                        let generation = slot.generation;
                        Box::pin(wait_for_start(slot))
                            .await
                            .context("waiting for session worker start")?;
                        self.claim_live_generation(id, generation)
                            .ok_or(SessionAttachRetry)?
                    }
                    AttachClaim::Start(ticket) => {
                        let generation = ticket.generation();
                        self.inner.db.restore_supervised_goals(id).await?;
                        // Box the heavy resume sub-future: it synchronously calls
                        // `Session::resume` (a large stack frame) and threads config
                        // loading, so keeping its state on the heap rather than
                        // inlined into `attach`'s future is what keeps the enclosing
                        // future small enough to poll without overflowing the worker
                        // stack (`daemon-lifecycle-replay-timing-robustness.md`).
                        let result = Box::pin(self.start_resumed_worker(
                            id,
                            initial_model,
                            client_no_sandbox,
                            env_snapshot,
                            generation,
                            &worker_publication_permit,
                        ))
                        .await;
                        self.finish_attach_start(ticket, &result);
                        result?;
                        self.claim_live_generation(id, generation)
                            .ok_or(SessionAttachRetry)?
                    }
                };
                break claim;
            };
            let handle = claim.handle().clone();
            // Reconciliation gate (`daemon-lifecycle-replay-timing-robustness.md`,
            // §3 / finding 3): `start_worker` publishes the handle into
            // `workers.live` BEFORE the resumed worker's startup
            // crash-reconciliation pass (`Open → Parked` for an interrupt whose
            // graceful park did not land) completes. That pass runs
            // asynchronously inside the worker task, so a concurrent
            // `AttachClaim::Live` — or the `Start` owner itself — could return
            // while the row is still `Open`. Awaiting the shared park-commit
            // signal here for EVERY resume-claim path (not just `Start`) closes
            // that window: no attach observes the pre-reconciliation `Open` row.
            // Idempotent and immediate once reconciliation has landed; bounded
            // by the product-owned deadline, after which attach still proceeds
            // (the reconciliation is idempotent and re-runs on the next attach),
            // so it can never deadlock against a worker that is being torn down.
            // Box the reconciliation-gate await so its (handle-holding) state
            // does not inline into `attach`'s future.
            Box::pin(
                handle
                    .park_commit()
                    .await_startup_reconciled(INTERRUPT_PARK_COMMIT_DEADLINE),
            )
            .await;
            if handle.session_entry_mode() != session_entry_mode {
                return Err(SessionEntryModeConflict {
                    actual: handle.session_entry_mode().as_str(),
                    requested: session_entry_mode.as_str(),
                }
                .into());
            }
            // Every concrete generation — including Start/Starting after it
            // publishes — holds the same lease through lock resumption.
            let Some(handle) = self.activate_claimed_live_session(claim).await? else {
                return Err(SessionAttachRetry.into());
            };
            return Ok(handle);
        }

        // Create path — boxed (`daemon-lifecycle-replay-timing-robustness.md`):
        // this branch builds a session + config + worker and is the largest
        // await-point state in `attach`. Keeping it behind a `Box::pin` heap-
        // allocates that state instead of inflating the enclosing `attach`
        // future (which the resume path above already keeps small), so the whole
        // future stays comfortably within the worker stack.
        Box::pin(self.attach_create_session(
            project_root,
            initial_model,
            client_no_sandbox,
            model_override,
            env_snapshot,
            session_entry_mode,
            &worker_publication_permit,
        ))
        .await
    }

    /// Exclude worker start/publication while a caller captures and commits a
    /// daemon-wide authority transition.  The owned guard lets the transition
    /// hand post-submission reconciliation to its detached owner without
    /// weakening the exclusion boundary.
    pub(crate) async fn lock_worker_publication(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.inner.worker_publication.clone().lock_owned().await
    }

    /// Resume an existing durable session without accepting a caller-selected
    /// entry mode. This is the scheduler/automation boundary: the daemon reads
    /// immutable mode truth from its own row before it can start or join a
    /// worker.
    pub async fn attach_existing(
        &self,
        session_id: Uuid,
        initial_model: Option<ActiveModelRef>,
        client_no_sandbox: bool,
        model_override: Option<&ActiveModelRef>,
        env_snapshot: EnvSnapshot,
    ) -> Result<SessionWorkerHandle> {
        let row = self
            .inner
            .db
            .get_session(session_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("unknown session {session_id}"))?;
        let mode = match row.session_entry_mode.as_str() {
            "code" => crate::daemon::proto::SessionEntryMode::Code,
            "assistant" => crate::daemon::proto::SessionEntryMode::Assistant,
            "computer" => crate::daemon::proto::SessionEntryMode::Computer,
            invalid => anyhow::bail!("invalid persisted session entry mode {invalid:?}"),
        };
        self.attach(
            Some(session_id),
            None,
            initial_model,
            client_no_sandbox,
            model_override,
            env_snapshot,
            mode,
        )
        .await
    }

    /// Claim an already-live worker without ever starting a replacement.
    ///
    /// Lazy sessions deliberately have no `sessions` row until their first
    /// user message. A second local client must therefore reattach through the
    /// live daemon-owned handle, not manufacture a database-backed resume or
    /// accept caller-supplied setup metadata. `None` means there is no live
    /// claim and lets the normal durable attach path decide whether to resume
    /// or reject the id. The returned claim is generation-fenced: callers may
    /// await validation, but must successfully consume it before acting on
    /// the captured root or mode.
    pub(crate) async fn claim_live_attach_if_present(
        &self,
        session_id: Uuid,
    ) -> Result<Option<LiveAttachClaim>> {
        let claim = {
            let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
            let Some(entry) = workers.live.get_mut(&session_id) else {
                return Ok(None);
            };
            if entry.handle.is_closed() {
                return Ok(None);
            }
            entry.activation_leases = entry.activation_leases.saturating_add(1);
            LiveAttachClaim {
                inner: Arc::downgrade(&self.inner),
                session_id,
                generation: entry.generation,
                session_entry_mode: entry.handle.session_entry_mode(),
                project_root: entry.handle.project_root(),
                handle: entry.handle.clone(),
                terminal_lock_cleanup_gate: entry.terminal_lock_cleanup_gate.clone(),
                terminal_cleanup_complete: entry.terminal_cleanup_complete.clone(),
            }
        };
        Box::pin(
            claim
                .handle
                .park_commit()
                .await_startup_reconciled(INTERRUPT_PARK_COMMIT_DEADLINE),
        )
        .await;
        if !self.live_claim_is_current(&claim) {
            return Ok(None);
        }
        Ok(Some(claim))
    }

    /// Complete a validated live attach. Kept separate from
    /// [`Self::claim_live_attach_if_present`] so a caller-provided setup mismatch
    /// cannot reacquire locks or otherwise mutate a live worker before the
    /// daemon has rejected it.
    pub(crate) async fn activate_claimed_live_session(
        &self,
        claim: LiveAttachClaim,
    ) -> Result<Option<SessionWorkerHandle>> {
        if !self.live_claim_is_current(&claim) {
            return Ok(None);
        }
        // The RAII claim pins this generation through the awaited lock resume:
        // cleanup leaves a closed entry in place and `claim_attach` refuses a
        // successor until this operation returns or is cancelled. Thus this
        // session-id-only lock API cannot resume a replacement worker.
        let _terminal_cleanup = claim.terminal_lock_cleanup_gate.lock().await;
        if !self.live_claim_is_current(&claim) {
            return Ok(None);
        }
        self.inner
            .locks
            .resume_session(claim.session_id)
            .await
            .context("re-acquiring session locks on generation-bound reattach")?;
        if !self.live_claim_is_current(&claim) {
            return Ok(None);
        }
        Ok(Some(claim.handle().clone()))
    }

    /// Finish cleanup for exactly the terminal generation represented by
    /// `claim`. The generation lease and its gate prevent a concurrent attach
    /// or successor from changing which session lock state is being cleared.
    async fn complete_terminal_cleanup(&self, claim: &LiveAttachClaim) -> Result<()> {
        // Never timeout-drop this future. The generation-owned gate is the
        // single cleanup authority; abandoning it while its blocking session
        // end continues would permit a retry to overlap the same stores.
        let _gate = claim.terminal_lock_cleanup_gate.lock().await;
        let needs_cleanup = crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .get(&claim.session_id)
            .is_some_and(|entry| {
                entry.generation == claim.generation
                    && entry.terminal_closing.load(Ordering::Acquire)
                    && !entry.terminal_cleanup_complete.load(Ordering::Acquire)
            });
        if !needs_cleanup {
            return Err(SessionTerminalCleanupRetry.into());
        }
        self.inner
            .locks
            .end_session(claim.session_id)
            .await
            .context("retrying generation-bound terminal session lock cleanup")?;
        claim
            .handle
            .end_session_for_terminal_cleanup()
            .await
            .context("retrying generation-bound durable session cleanup")?;
        claim
            .terminal_cleanup_complete
            .store(true, Ordering::Release);
        Ok(())
    }

    /// Whether an id is currently backed by a live worker. This is used only
    /// by local-owner authorization to permit a lazy reattach; remote callers
    /// always require durable session ownership.
    pub fn has_live_session(&self, session_id: Uuid) -> bool {
        self.lookup_entry(session_id)
            .is_some_and(|(_, handle)| !handle.is_closed())
    }

    /// The create-a-new-session branch of [`Self::attach`], factored out and
    /// awaited behind a `Box::pin` so its (large) local state lives on the heap
    /// and does not inflate the `attach` future's on-stack size.
    async fn attach_create_session(
        &self,
        project_root: Option<PathBuf>,
        initial_model: Option<ActiveModelRef>,
        client_no_sandbox: bool,
        model_override: Option<&ActiveModelRef>,
        env_snapshot: EnvSnapshot,
        session_entry_mode: crate::daemon::proto::SessionEntryMode,
        worker_publication: &WorkerPublicationPermit<'_>,
    ) -> Result<SessionWorkerHandle> {
        // Linearize the full preflight/start handoff with trust decisions and
        // config publication. Command-secret preparation below awaits; without
        // this coordinator an IgnoreConfig decision could win during that
        // await and a project-derived snapshot would still be spawned.
        let _config_publication_guard = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
        let Some(project_root) = project_root else {
            bail!("attach requires either session_id or project_root");
        };
        let resolved_trust =
            resolve_workspace_trust_policy_with_revision_from_db(&self.inner.db, &project_root)
                .await?;
        let mut trust_policy = resolved_trust.policy;
        let mut trust_revision = resolved_trust.revision;
        self.inner
            .config_source
            .prepare_global_layers_before_retained_capture(&project_root, &trust_policy)?;
        let workspace_root_authority = Arc::new(
            crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority::capture(
                &project_root,
                &trust_policy,
            )?,
        );
        // Use the complete attach-time source chain. In addition to avoiding
        // a later ambient `COCKPIT_CONFIG` redirect, this preserves exact
        // provenance for global provider/model choices so an attached
        // SetModelFavorite can mutate only its observed retained source.
        let mut workspace_layer =
            workspace_root_authority.capture_retained_config_source_chain(&trust_policy)?;
        let (mut providers_cfg, mut extended_cfg) = self
            .inner
            .config_source
            .load_effective_for_daemon_with_retained_workspace_layer(
                &project_root,
                &trust_policy,
                &workspace_layer,
            )?;
        let mut hooks = workspace_root_authority.resolve_hooks_for_policy(&trust_policy)?;
        let config_watch_paths = workspace_root_authority.config_watch_paths();
        if let (Some(initial), Some(pinned)) = (&initial_model, model_override) {
            anyhow::ensure!(
                initial == pinned,
                "initial model and plan-level model pin must be the same complete selection"
            );
        }
        let active = initial_model
            .clone()
            .or_else(|| model_override.cloned())
            .or_else(|| providers_cfg.active_model.clone())
            .context("no model selected for the new session")?;
        let initial_agent = session_worker::initial_active_agent(&extended_cfg).to_string();
        // Lazy persistence (session-id-display-and-lazy-persist): hold the
        // new session in memory with its id assigned but its `sessions` row
        // un-written until `start_worker` flushes it, immediately before
        // durable lifecycle rows (agent-tree, write-scope) that foreign-key
        // to `sessions`.
        let mut session = Session::create_deferred(
            self.inner.db.clone(),
            project_root,
            &initial_agent,
            self.redaction_key_resolver()?,
            self.secret_vault()?,
        )
        .context("creating session")?;
        session.set_deferred_entry_mode(session_entry_mode)?;
        session
            .set_active_model_ref(active)
            .context("setting active model on new session")?;
        let generation = {
            let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
            next_generation(&mut workers)
        };
        // Async pre-resolve referenced command-backed secrets into the daemon
        // cache BEFORE the sync `start_worker` builds the redaction table and
        // model, so both observe the cache and never trigger a sync exec.
        self.preresolve_session_command_secrets(&session, &providers_cfg)
            .await;
        // Test-only interleaving seam. Keep it before the final durable trust
        // observation so a direct DB transition exercises the same reproject
        // path as a real concurrent writer; production has no hook here.
        #[cfg(test)]
        self.run_pre_start_worker_hook();
        // The coordinator prevents normal trust RPCs from changing policy in
        // this window, but retain a durable revision fence for DB writers and
        // future entry paths that do not share this task. Reproject only from
        // the authority captured above; never rediscover workspace paths.
        let current_trust = resolve_workspace_trust_policy_with_revision_from_db(
            &self.inner.db,
            &session.project_root,
        )
        .await?;
        if current_trust.revision != trust_revision || current_trust.policy != trust_policy {
            trust_policy = current_trust.policy;
            trust_revision = current_trust.revision;
            workspace_layer =
                workspace_root_authority.capture_retained_config_source_chain(&trust_policy)?;
            (providers_cfg, extended_cfg) = self
                .inner
                .config_source
                .load_effective_for_daemon_with_retained_workspace_layer(
                    &session.project_root,
                    &trust_policy,
                    &workspace_layer,
                )?;
            hooks = workspace_root_authority.resolve_hooks_for_policy(&trust_policy)?;
            if initial_model.is_none() && model_override.is_none() {
                session.set_active_model_ref(
                    providers_cfg
                        .active_model
                        .clone()
                        .context("no model selected after workspace trust changed")?,
                )?;
            }
        }
        debug_assert!(trust_revision > 0);
        self.start_worker(
            worker_publication,
            session,
            &providers_cfg,
            &extended_cfg,
            client_no_sandbox,
            model_override,
            None,
            trust_policy,
            trust_revision,
            workspace_root_authority,
            workspace_layer,
            hooks,
            config_watch_paths,
            env_snapshot,
            generation,
        )
    }

    /// Create a new assistant session through the normal daemon worker path,
    /// preserving deferred-persistence semantics until `start_worker` flushes
    /// the row, immediately before durable lifecycle setup.
    pub async fn create_assistant_session(
        &self,
        assistant_name: &str,
        project_root: PathBuf,
        initial_model: Option<ActiveModelRef>,
        client_no_sandbox: bool,
        env_snapshot: EnvSnapshot,
    ) -> Result<SessionWorkerHandle> {
        // Assistant creation is a worker-start path too. Acquire in the same
        // global order as attach (worker publication before config
        // publication), and retain it through the live/join insertion.
        let worker_publication_guard = self.inner.worker_publication.lock().await;
        let worker_publication = WorkerPublicationPermit {
            _guard: &worker_publication_guard,
        };
        let _config_publication_guard = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
        crate::assistants::validate_assistant_name(assistant_name)?;
        crate::assistants::load_verified(&self.inner.db, assistant_name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("assistant `{assistant_name}` not found"))?;

        let resolved_trust =
            resolve_workspace_trust_policy_with_revision_from_db(&self.inner.db, &project_root)
                .await?;
        let mut trust_policy = resolved_trust.policy;
        let mut trust_revision = resolved_trust.revision;
        self.inner
            .config_source
            .prepare_global_layers_before_retained_capture(&project_root, &trust_policy)?;
        let workspace_root_authority = Arc::new(
            crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority::capture(
                &project_root,
                &trust_policy,
            )?,
        );
        let mut workspace_layer =
            workspace_root_authority.capture_retained_config_source_chain(&trust_policy)?;
        let (mut providers_cfg, mut extended_cfg) = self
            .inner
            .config_source
            .load_effective_for_daemon_with_retained_workspace_layer(
                &project_root,
                &trust_policy,
                &workspace_layer,
            )?;
        let mut hooks = workspace_root_authority.resolve_hooks_for_policy(&trust_policy)?;
        let config_watch_paths = workspace_root_authority.config_watch_paths();
        let active = initial_model
            .clone()
            .or_else(|| providers_cfg.active_model.clone())
            .context("no model selected for the new assistant session")?;
        let mut session = Session::create_assistant_deferred(
            self.inner.db.clone(),
            project_root,
            assistant_name,
            assistant_name,
            self.redaction_key_resolver()?,
            self.secret_vault()?,
        )
        .context("creating assistant session")?;
        session.set_deferred_entry_mode(crate::daemon::proto::SessionEntryMode::Assistant)?;
        session
            .set_active_model_ref(active)
            .context("setting active model on new assistant session")?;
        let generation = {
            let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
            next_generation(&mut workers)
        };
        // Async pre-resolve referenced command-backed secrets before the sync
        // `start_worker` (see `attach_create_session`).
        self.preresolve_session_command_secrets(&session, &providers_cfg)
            .await;
        #[cfg(test)]
        self.run_pre_start_worker_hook();
        let current_trust = resolve_workspace_trust_policy_with_revision_from_db(
            &self.inner.db,
            &session.project_root,
        )
        .await?;
        if current_trust.revision != trust_revision || current_trust.policy != trust_policy {
            trust_policy = current_trust.policy;
            trust_revision = current_trust.revision;
            workspace_layer =
                workspace_root_authority.capture_retained_config_source_chain(&trust_policy)?;
            (providers_cfg, extended_cfg) = self
                .inner
                .config_source
                .load_effective_for_daemon_with_retained_workspace_layer(
                    &session.project_root,
                    &trust_policy,
                    &workspace_layer,
                )?;
            hooks = workspace_root_authority.resolve_hooks_for_policy(&trust_policy)?;
            if initial_model.is_none() {
                session.set_active_model_ref(
                    providers_cfg
                        .active_model
                        .clone()
                        .context("no model selected after workspace trust changed")?,
                )?;
            }
        }
        debug_assert!(trust_revision > 0);
        self.start_worker(
            &worker_publication,
            session,
            &providers_cfg,
            &extended_cfg,
            client_no_sandbox,
            None,
            None,
            trust_policy,
            trust_revision,
            workspace_root_authority,
            workspace_layer,
            hooks,
            config_watch_paths,
            env_snapshot,
            generation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_resumed_worker(
        &self,
        id: Uuid,
        initial_model: Option<ActiveModelRef>,
        client_no_sandbox: bool,
        env_snapshot: EnvSnapshot,
        generation: WorkerGeneration,
        worker_publication: &WorkerPublicationPermit<'_>,
    ) -> Result<SessionWorkerHandle> {
        let _config_publication_guard = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
        let mut session = Session::resume(
            self.inner.db.clone(),
            id,
            self.redaction_key_resolver()?,
            self.secret_vault()?,
        )
        .context("resuming session")?
        .ok_or_else(|| anyhow::anyhow!("unknown session {id}"))?;
        let resolved_trust = resolve_workspace_trust_policy_with_revision_from_db(
            &self.inner.db,
            &session.project_root,
        )
        .await?;
        let mut trust_policy = resolved_trust.policy;
        let mut trust_revision = resolved_trust.revision;
        self.inner
            .config_source
            .prepare_global_layers_before_retained_capture(&session.project_root, &trust_policy)?;
        let workspace_root_authority = Arc::new(
            crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority::capture(
                &session.project_root,
                &trust_policy,
            )?,
        );
        let mut workspace_layer =
            workspace_root_authority.capture_retained_config_source_chain(&trust_policy)?;
        let (mut providers_cfg, mut extended_cfg) = self
            .inner
            .config_source
            .load_effective_for_daemon_with_retained_workspace_layer(
                &session.project_root,
                &trust_policy,
                &workspace_layer,
            )?;
        let mut hooks = workspace_root_authority.resolve_hooks_for_policy(&trust_policy)?;
        let config_watch_paths = workspace_root_authority.config_watch_paths();
        // Async pre-resolve referenced command-backed secrets before the sync
        // `start_worker` (see `attach_create_session`).
        self.preresolve_session_command_secrets(&session, &providers_cfg)
            .await;
        #[cfg(test)]
        self.run_pre_start_worker_hook();
        let current_trust = resolve_workspace_trust_policy_with_revision_from_db(
            &self.inner.db,
            &session.project_root,
        )
        .await?;
        if current_trust.revision != trust_revision || current_trust.policy != trust_policy {
            trust_policy = current_trust.policy;
            trust_revision = current_trust.revision;
            workspace_layer =
                workspace_root_authority.capture_retained_config_source_chain(&trust_policy)?;
            (providers_cfg, extended_cfg) = self
                .inner
                .config_source
                .load_effective_for_daemon_with_retained_workspace_layer(
                    &session.project_root,
                    &trust_policy,
                    &workspace_layer,
                )?;
            hooks = workspace_root_authority.resolve_hooks_for_policy(&trust_policy)?;
        }
        debug_assert!(trust_revision > 0);
        self.start_worker(
            worker_publication,
            session,
            &providers_cfg,
            &extended_cfg,
            client_no_sandbox,
            None,
            initial_model,
            trust_policy,
            trust_revision,
            workspace_root_authority,
            workspace_layer,
            hooks,
            config_watch_paths,
            env_snapshot,
            generation,
        )
    }

    #[cfg(test)]
    fn lookup(&self, session_id: Uuid) -> Option<SessionWorkerHandle> {
        self.lookup_entry(session_id).map(|(_, handle)| handle)
    }

    fn lookup_entry(&self, session_id: Uuid) -> Option<(WorkerGeneration, SessionWorkerHandle)> {
        crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .get(&session_id)
            .map(|entry| (entry.generation, entry.handle.clone()))
    }

    fn live_claim_is_current(&self, claim: &LiveAttachClaim) -> bool {
        crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .get(&claim.session_id)
            .is_some_and(|entry| {
                entry.generation == claim.generation
                    && !entry.handle.is_closed()
                    && !entry.handle.trust_transition_is_pending()
                    && !entry.terminal_closing.load(Ordering::Acquire)
            })
    }

    /// Lease one exact already-published worker generation. This is used by
    /// Start/Starting after their asynchronous construction wait: the returned
    /// handle alone is not enough because it can close and be replaced before
    /// reconciliation or lock resumption completes.
    fn claim_live_generation(
        &self,
        session_id: Uuid,
        generation: WorkerGeneration,
    ) -> Option<LiveAttachClaim> {
        let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
        let entry = workers.live.get_mut(&session_id)?;
        if entry.generation != generation || entry.handle.is_closed() {
            return None;
        }
        entry.activation_leases = entry.activation_leases.saturating_add(1);
        Some(LiveAttachClaim {
            inner: Arc::downgrade(&self.inner),
            session_id,
            generation,
            session_entry_mode: entry.handle.session_entry_mode(),
            project_root: entry.handle.project_root(),
            handle: entry.handle.clone(),
            terminal_lock_cleanup_gate: entry.terminal_lock_cleanup_gate.clone(),
            terminal_cleanup_complete: entry.terminal_cleanup_complete.clone(),
        })
    }

    fn claim_attach(&self, session_id: Uuid) -> AttachClaim {
        let mut state = crate::sync::lock_or_recover(&self.inner.workers);
        let closed_generation = if let Some(entry) = state.live.get_mut(&session_id) {
            if !entry.handle.is_closed() {
                entry.activation_leases = entry.activation_leases.saturating_add(1);
                return AttachClaim::Live(LiveAttachClaim {
                    inner: Arc::downgrade(&self.inner),
                    session_id,
                    generation: entry.generation,
                    session_entry_mode: entry.handle.session_entry_mode(),
                    project_root: entry.handle.project_root(),
                    handle: entry.handle.clone(),
                    terminal_lock_cleanup_gate: entry.terminal_lock_cleanup_gate.clone(),
                    terminal_cleanup_complete: entry.terminal_cleanup_complete.clone(),
                });
            }
            if entry.terminal_closing.load(Ordering::Acquire)
                && !entry.terminal_cleanup_complete.load(Ordering::Acquire)
            {
                entry.activation_leases = entry.activation_leases.saturating_add(1);
                return AttachClaim::CleanupRequired(LiveAttachClaim {
                    inner: Arc::downgrade(&self.inner),
                    session_id,
                    generation: entry.generation,
                    session_entry_mode: entry.handle.session_entry_mode(),
                    project_root: entry.handle.project_root(),
                    handle: entry.handle.clone(),
                    terminal_lock_cleanup_gate: entry.terminal_lock_cleanup_gate.clone(),
                    terminal_cleanup_complete: entry.terminal_cleanup_complete.clone(),
                });
            }
            if entry.activation_leases > 0 {
                return AttachClaim::Activating;
            }
            Some(entry.generation)
        } else {
            None
        };
        if let Some(generation) = closed_generation {
            state.live.remove(&session_id);
            let mut joins = crate::sync::lock_or_recover(&self.inner.worker_joins);
            if joins
                .get(&session_id)
                .is_some_and(|join| join.generation == generation)
            {
                joins.remove(&session_id);
            }
        }
        if let Some(slot) = state.starting.get(&session_id) {
            return AttachClaim::Starting(slot.clone());
        }
        let generation = next_generation(&mut state);
        let slot = Arc::new(StartSlot {
            generation,
            result: Mutex::new(None),
            ready: watch::channel(()).0,
        });
        state.starting.insert(session_id, slot.clone());
        AttachClaim::Start(StartTicket {
            inner: self.inner.clone(),
            session_id,
            slot,
            completed: false,
        })
    }

    fn finish_attach_start(&self, ticket: StartTicket, result: &Result<SessionWorkerHandle>) {
        ticket.finish(result);
    }

    #[allow(clippy::too_many_arguments)]
    fn start_worker(
        &self,
        _worker_publication: &WorkerPublicationPermit<'_>,
        session: Session,
        providers_cfg: &ProvidersConfig,
        extended_cfg: &ExtendedConfig,
        client_no_sandbox: bool,
        model_override: Option<&ActiveModelRef>,
        recovery_model: Option<ActiveModelRef>,
        trust_policy: WorkspaceTrustPolicy,
        trust_revision: i64,
        workspace_root_authority: Arc<
            crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority,
        >,
        workspace_layer: cockpit_config::config::WorkspaceConfigLayerSnapshotChain,
        hooks: crate::config::extended::hooks::HookRegistry,
        config_watch_paths: crate::daemon::config_source::ConfigWatchPaths,
        env_snapshot: EnvSnapshot,
        generation: WorkerGeneration,
    ) -> Result<SessionWorkerHandle> {
        if self.inner.shutdown.is_draining() {
            bail!("daemon is shutting down; not starting session workers");
        }
        let session_id = session.id;
        let project_root = session.project_root.clone();
        // Preflight captured this exact authority and policy projection before
        // choosing the model. Reusing both here prevents a mutable
        // `COCKPIT_CONFIG` environment or path discovery from splitting model
        // selection from the worker/endpoint snapshot. A source hidden by the
        // current IgnoreConfig policy is intentionally not revalidated: it
        // remains retained only for a later Trust refresh.
        workspace_root_authority
            .verify_retained_config_source_chain_for_policy(&trust_policy)
            .context("validating preflight worker config authority")?;
        let providers_cfg = providers_cfg.clone();
        let extended_cfg = extended_cfg.clone();

        // Recovery of a pre-selection session is a two-phase operation. The
        // full selection is visible in memory while the worker is validated.
        // The deferred sessions row is flushed after that commit and immediately
        // precedes `session_worker::spawn`, which is synchronous and infallible;
        // attach always writes a durable parent row before agent-tree dependents.
        // Existing selections are never overwritten by Attach; intentional
        // changes go through SetActiveModel.
        let staged_recovery = if session.active_model_ref().is_none() {
            let active = recovery_model
                .or_else(|| providers_cfg.active_model.clone())
                .context("session has no active model selection and no default is configured")?;
            session.stage_active_model_ref_for_recovery(active.clone());
            Some(active)
        } else {
            None
        };

        session.set_sandbox_escalation_enabled(extended_cfg.sandbox_escalation_enabled);

        // Install the daemon command-secret cache on the session BEFORE any store
        // is built, so EVERY credential store this session builds for the whole
        // worker lifetime — the initial redaction table and model here, plus later
        // model-switch, tandem, and redaction-refresh builds — injects the
        // resolved command outputs the cache holds (a sync, execution-free
        // lookup). Pre-resolution has already run on the async caller path.
        session.set_command_secret_cache(Some(self.command_secret_cache()));

        // Build per-session redaction table from the immutable session env.
        // `credential_store` injects any resolved command-backed output into the
        // store, so the planted token joins the redaction table while the argv
        // spec never does (`command_secret_output_joins_redaction_table`).
        let redact = RedactionTable::build_with_env_and_credential_store(
            &extended_cfg.redact,
            &project_root,
            env_snapshot.vars(),
            &session.credential_store()?,
        )
        .context("building redaction table")?;
        let redact = Arc::new(redact);

        // Build the model from providers config. Errors out loud if
        // no provider is configured for the session's active model. Install
        // the daemon's shared shutdown gate so this worker's inference
        // dispatch refuses new provider requests once a drain begins
        // (`daemon-graceful-drain-shutdown.md`).
        // The endpoint-repair persistence target is selected from this same
        // preflight snapshot, never from a mutable `COCKPIT_CONFIG` or fresh
        // workspace discovery. Ambient-only providers deliberately have no
        // worker-local persistence target.
        let session_active = resolve_session_active_model(&providers_cfg, &session)?;
        let config_path = workspace_root_authority
            .provider_write_target(&workspace_layer, &session_active.provider);
        let model = resolve_session_worker_model(
            &providers_cfg,
            &extended_cfg,
            &session,
            redact.clone(),
            &env_snapshot,
            config_path.clone(),
            &self.inner.shutdown,
        )
        .context("resolving model")?;

        // Resolve the active model's extra-request-body fragment from rich
        // reasoning-effort capabilities first, falling back to legacy
        // thinking modes (implementation note). Threaded
        // onto the root spawn's `ModelParams` so every outbound request on the
        // session model carries the vendor reasoning controls.
        let mut session_providers = providers_cfg.clone();
        session_providers.active_model = Some(session_active.clone());
        let thinking_params = model.resolve_reasoning_params(&session_providers);
        let endpoint_recovery_thinking_params =
            model.endpoint_recovery_reasoning_params(&session_providers);

        // A plan-level pin is a second behavioral use of the authoritative
        // session model, not a parallel selection. Reuse the already-validated
        // model so provider failures cannot silently degrade to the configured
        // default and every preference remains aligned with durable state.
        if let Some(pinned) = model_override {
            anyhow::ensure!(
                pinned == &session_active,
                "plan-level model pin must match the session's complete active selection"
            );
        }
        let model_override = model_override.map(|_| model.clone());

        session.set_external_journal(self.external_journal());
        // Copy the daemon containment handle onto the worker session so every
        // lifecycle hook (driver, noninteractive, swarm — all share this
        // `Session`) spawns its child under a proven containment lease.
        session.set_process_containment(self.process_containment());
        let session = Arc::new(session);
        let cleanup_inner = Arc::downgrade(&self.inner);
        let cleanup =
            Box::new(move || cleanup_worker_on_exit(cleanup_inner, session_id, generation));
        let daemon_no_sandbox =
            session_worker::daemon_no_sandbox().context("reading COCKPIT_DAEMON_NO_SANDBOX")?;
        if let Some(staged_recovery) = staged_recovery {
            session
                .set_active_model_ref(staged_recovery)
                .context("committing recovered session model after worker validation")?;
        }
        let terminal_lock_cleanup_gate = Arc::new(AsyncMutex::new(()));
        let terminal_closing = Arc::new(AtomicBool::new(false));
        let terminal_cleanup_complete = Arc::new(AtomicBool::new(false));
        let (handle, join, start_permit) = session_worker::spawn(
            session,
            self.inner.locks.clone(),
            redact,
            model,
            model_override,
            thinking_params,
            endpoint_recovery_thinking_params,
            project_root.clone(),
            workspace_root_authority,
            client_no_sandbox,
            daemon_no_sandbox,
            &extended_cfg,
            self.inner.lsp.clone(),
            self.inner.resource_scheduler.clone(),
            self.scheduler_source(),
            self.write_scope_source(),
            crate::sync::lock_or_recover(&self.inner.global_bus).clone(),
            trust_policy.clone(),
            trust_revision,
            Some(cleanup),
            terminal_lock_cleanup_gate.clone(),
            terminal_closing.clone(),
            terminal_cleanup_complete.clone(),
            env_snapshot,
            {
                let snapshot = session_worker::SessionConfigSnapshot::with_hooks(
                    0,
                    providers_cfg.clone(),
                    extended_cfg.clone(),
                    hooks,
                )
                .with_trust_revision(trust_revision)
                .with_retained_provider_model_sources(&workspace_layer)?
                .with_host_capabilities(self.current_host_capabilities());
                match self.host_capability_refresh_runtime() {
                    Some(runtime) => snapshot.with_host_capability_refresh_runtime(runtime),
                    None => snapshot,
                }
            },
        );

        crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .insert(
                session_id,
                WorkerEntry {
                    generation,
                    handle: handle.clone(),
                    activation_leases: 0,
                    terminal_lock_cleanup_gate,
                    terminal_closing,
                    terminal_cleanup_complete,
                },
            );
        let config_watcher = crate::daemon::config_watch::spawn_config_watcher(
            self.inner.db.clone(),
            self.inner.config_source.clone(),
            handle.clone(),
            config_watch_paths,
        );
        crate::sync::lock_or_recover(&self.inner.worker_joins).insert(
            session_id,
            WorkerJoin {
                generation,
                join,
                _config_watcher: config_watcher.map(ConfigWatcherJoin),
            },
        );

        // Release only after every cleanup target exists. From this point an
        // immediate worker exit can atomically retire the exact generation.
        start_permit.release();

        Ok(handle)
    }

    /// Drop a session's worker handle from the registry. Called when
    /// the worker exits (session ended, daemon shutdown).
    #[allow(dead_code)]
    pub fn forget(&self, session_id: Uuid) {
        self.forget_many([session_id]);
    }

    #[allow(dead_code)]
    fn forget_many<I>(&self, session_ids: I)
    where
        I: IntoIterator<Item = Uuid>,
    {
        let ids: Vec<Uuid> = session_ids.into_iter().collect();
        if ids.is_empty() {
            return;
        }
        let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
        let mut joins = crate::sync::lock_or_recover(&self.inner.worker_joins);
        for id in ids {
            workers.live.remove(&id);
            joins.remove(&id);
        }
    }

    fn forget_generation(&self, session_id: Uuid, generation: WorkerGeneration) {
        forget_generation_from_inner(&self.inner, session_id, generation);
    }

    fn forget_generations<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (Uuid, WorkerGeneration)>,
    {
        for (session_id, generation) in entries {
            self.forget_generation(session_id, generation);
        }
    }

    /// Graceful drain (`daemon-graceful-drain-shutdown.md`). Sends
    /// `Shutdown` to every running worker — which closes its driver input
    /// so the in-flight turn finishes — then **awaits** all worker tasks up
    /// to `grace`. Any worker still running when the deadline fires (a hung
    /// provider call, a wedged tool) is `abort()`ed so the daemon can exit
    /// regardless. The new-request gate must already be set
    /// (`shutdown.begin_drain()`) before calling this, so no fresh provider
    /// dispatch slips out while we drain.
    ///
    /// Returns a [`DrainOutcome`] carrying both the historical grace-bounded
    /// running-work result (`running_work_clean`) and the decoupled
    /// interrupt-park commit terminal (`park_commit`)
    /// (`daemon-lifecycle-replay-timing-robustness.md`). The caller
    /// (`daemon/mod.rs`) must gate `metadata_guard.cleanup()` on
    /// [`DrainOutcome::is_clean`]-vs-forced so pid/socket release and
    /// `"daemon: restarted"` never falsely claim a clean park success.
    pub async fn drain_all(&self, grace: Duration) -> DrainOutcome {
        self.drain_all_inner(grace, INTERRUPT_PARK_COMMIT_DEADLINE)
            .await
    }

    /// [`Self::drain_all`] with an injectable park-commit deadline so tests can
    /// force the `DeadlineUnresolved` terminal without a real 5-second sleep
    /// (criterion 5b). Production always uses [`INTERRUPT_PARK_COMMIT_DEADLINE`].
    async fn drain_all_inner(
        &self,
        grace: Duration,
        park_commit_deadline: Duration,
    ) -> DrainOutcome {
        // Snapshot + take the join handles. Taking them out of the map means
        // a worker that exits on its own mid-drain (and calls `forget`)
        // can't race us for its handle.
        let joins: Vec<(Uuid, WorkerJoin)> = {
            let mut joins = crate::sync::lock_or_recover(&self.inner.worker_joins);
            joins.drain().collect()
        };
        let drained_generations: Vec<(Uuid, WorkerGeneration)> = joins
            .iter()
            .map(|(id, entry)| (*id, entry.generation))
            .collect();
        let handles: Vec<SessionWorkerHandle> = {
            let workers = crate::sync::lock_or_recover(&self.inner.workers);
            drained_generations
                .iter()
                .filter_map(|(id, generation)| {
                    workers
                        .live
                        .get(id)
                        .filter(|entry| entry.generation == *generation)
                        .map(|entry| entry.handle.clone())
                })
                .collect()
        };

        // Ask each worker to stop, with a BOUNDED, abort-aware dispatch
        // (finding 1). A worker's work queue is bounded; if it stopped
        // receiving (wedged) while its queue is full, an unbounded
        // `send(...).await` would block drain forever and never reach the
        // park-commit / grace / abort phases below — defeating every deadline.
        // So bound each send by the lifecycle deadline and force-abort any
        // worker we cannot even hand the Shutdown to. Sent concurrently so the
        // whole dispatch step is one deadline, not one per worker.
        let abort_handles_by_id: std::collections::HashMap<Uuid, tokio::task::AbortHandle> = joins
            .iter()
            .map(|(id, entry)| (*id, entry.join.abort_handle()))
            .collect();
        let send_deadline = park_commit_deadline.max(grace);
        let dispatch: Vec<ShutdownDispatch> = futures::future::join_all(handles.iter().map(|h| {
            let h = h.clone();
            async move {
                match tokio::time::timeout(
                    send_deadline,
                    h.send_work(crate::daemon::session_worker::SessionWork::Shutdown {
                        pause_for_resume: true,
                    }),
                )
                .await
                {
                    // Accepted onto the worker's queue.
                    Ok(Ok(())) => ShutdownDispatch::Delivered,
                    // Send errored (receiver dropped) — the worker task has
                    // already exited. Benign: its join completes immediately and
                    // it owes no park. NOT the finding-1 hang.
                    Ok(Err(_)) => ShutdownDispatch::WorkerGone,
                    // Timed out with the queue full and the worker not
                    // receiving: this is the wedged case finding 1 targets — an
                    // unbounded send here would block drain forever.
                    Err(_) => ShutdownDispatch::Wedged,
                }
            }
        }))
        .await;
        // Force-abort only the WEDGED workers (finding 1): a worker that never
        // accepted Shutdown because its queue is full and it stopped receiving
        // will neither drain nor park, so awaiting it would only burn the
        // deadline. Aborting now keeps the pre-abort path provably bounded. An
        // already-gone worker (send errored) needs no abort — it has exited.
        let mut any_wedged = false;
        for (h, d) in handles.iter().zip(dispatch.iter()) {
            if *d == ShutdownDispatch::Wedged {
                any_wedged = true;
                tracing::warn!(
                    session_id = %h.session_id,
                    "daemon drain: worker did not accept shutdown within deadline (wedged queue); forcing abort"
                );
                if let Some(ah) = abort_handles_by_id.get(&h.session_id) {
                    ah.abort();
                }
            }
        }
        if grace.is_zero() {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Interrupt-park obligations: EVERY worker we delivered a Shutdown to is
        // an obligation — drain awaits its ParkCommit terminal unconditionally
        // (`daemon-lifecycle-replay-timing-robustness.md`, finding 2 residual).
        // The obligation MUST be established at DISPATCH time, never inferred
        // from post-dispatch live `has_registered_waiters()`/`processing` state:
        // a worker whose INITIAL park write FAILS wakes/removes its waiter and
        // lets its driver exit, clearing BOTH bits before we could sample them —
        // yet it durably reports `FailedWrite`. Sampling live state would drop
        // that obligation and let drain aggregate `Committed`, releasing metadata
        // as if a failed durable park had succeeded. Every delivered worker's
        // park-drain loop reports a terminal for both pause paths, and a
        // no-waiter/idle worker reports `Committed` promptly (its driver exits as
        // soon as the input closes, so the loop's first poll observes exit), so
        // awaiting all of them stays bounded and adds no real latency. Only
        // `WorkerGone` (already exited) and `Wedged` (force-aborted) owe nothing.
        let park_obligations: Vec<crate::engine::interrupt::ParkCommit> = handles
            .iter()
            .zip(dispatch.iter())
            .filter(|(_, d)| **d == ShutdownDispatch::Delivered)
            .map(|(handle, _)| handle.park_commit())
            .collect();

        // Phase 1 — interrupt-park commit, on its OWN product-owned deadline,
        // BEFORE the grace-bounded abort below. Awaiting here (not sharing the
        // `--grace` deadline, and never abort-racing it) is the fix: the abort
        // arm would otherwise kill a worker's `park_interrupt` write before it
        // committed under a starved scheduler, leaving the row `Open` while the
        // restart reported success. A worker with no registered waiter resolves
        // immediately (see `await_park_commits`), so genuinely-running work is
        // never delayed by this phase.
        let park_commit = await_park_commits(&park_obligations, park_commit_deadline).await;

        // Phase 2 — grace-bounded drain + force-abort of genuinely in-flight
        // tool/inference work, UNCHANGED from `daemon-drain-grace-and-activity-
        // state`: wait for ALL worker tasks (never just the first — `join_all`
        // resolves only when every future has); on the deadline, force-abort
        // whatever's left so the daemon can exit regardless.
        let abort_handles: Vec<tokio::task::AbortHandle> = joins
            .iter()
            .map(|(_, entry)| entry.join.abort_handle())
            .collect();
        let drain = futures::future::join_all(joins.into_iter().map(|(_, entry)| entry.join));

        let phase2_clean = match tokio::time::timeout(grace, drain).await {
            Ok(_) => true,
            Err(_) => {
                // Grace exhausted with work still outstanding: force-abort
                // every (possibly already-finished — abort is then a no-op)
                // worker task so the daemon can exit. Aborting drops the
                // worker's driver, which cancels its streaming inference and
                // kills any running `bash` subprocess.
                tracing::warn!("daemon drain grace exhausted; forcing worker abort");
                for h in &handles {
                    let (has_schedules, processing, tool_running) = h.live_status();
                    if processing {
                        self.record_forced_drain_interruption(
                            h,
                            grace,
                            has_schedules,
                            processing,
                            tool_running,
                        )
                        .await;
                    }
                }
                for ah in &abort_handles {
                    ah.abort();
                }
                false
            }
        };
        // A worker we had to force-abort at the dispatch step (a wedged queue,
        // finding 1) is a forced shutdown, not a clean drain.
        let running_work_clean = phase2_clean && !any_wedged;
        self.forget_generations(drained_generations);
        DrainOutcome {
            running_work_clean,
            park_commit,
        }
    }

    async fn record_forced_drain_interruption(
        &self,
        handle: &SessionWorkerHandle,
        grace: Duration,
        has_active_schedules: bool,
        processing: bool,
        tool_running: bool,
    ) {
        let activity_state = if tool_running {
            "tool_running"
        } else if processing {
            "inference_in_progress"
        } else {
            "scheduled_work"
        };
        let grace_ms = u64::try_from(grace.as_millis()).unwrap_or(u64::MAX);
        match self
            .inner
            .db
            .raise_interrupted_turn(
                handle.session_id,
                &handle.active_agent_name,
                "Daemon shutdown interrupted active work",
            )
            .await
        {
            Ok(interrupt_id) => {
                let data = json!({
                    "reason": "daemon_shutdown_grace_expired",
                    "interrupt_id": interrupt_id.to_string(),
                    "grace_ms": grace_ms,
                    "activity_state": activity_state,
                    "has_active_schedules": has_active_schedules,
                    "processing": processing,
                    "tool_running": tool_running,
                });
                let data_json = match serde_json::to_string(&data) {
                    Ok(data_json) => data_json,
                    Err(error) => {
                        tracing::warn!(
                            session_id = %handle.session_id,
                            error = %error,
                            "serializing forced drain interruption event failed"
                        );
                        return;
                    }
                };
                let session_id = handle.session_id;
                let active_agent_name = handle.active_agent_name.clone();
                if let Err(error) = self.inner.db.blocking_write_for_sync_event(move |conn| {
                    crate::db::Db::insert_session_event_json_conn(
                        conn,
                        session_id,
                        crate::db::session_log::SessionEventKind::TurnInterrupted,
                        Some(&active_agent_name),
                        None,
                        crate::db::session_log::SessionEventContext::default(),
                        crate::db::session_log::now_ms(),
                        &data_json,
                    )
                }) {
                    tracing::warn!(
                        session_id = %handle.session_id,
                        error = %error,
                        "record forced drain interruption event failed"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    session_id = %handle.session_id,
                    error = %error,
                    "record forced drain interruption marker failed"
                );
            }
        }
    }

    /// Snapshot of currently-active session ids. Useful for `cockpit
    /// daemon status` and the `list_sessions` request.
    pub fn active_session_ids(&self) -> Vec<Uuid> {
        crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .keys()
            .copied()
            .collect()
    }

    /// Snapshot live handles belonging to the supplied durable trust root.
    ///
    /// The comparison intentionally uses the worker's already-captured policy
    /// root rather than re-resolving `handle.project_root`: after attachment,
    /// a mutable `.git`/worktree layout must not redirect which live worker a
    /// trust transition controls. The caller performs a policy-projected
    /// refresh under the daemon-wide publication coordinator; this method
    /// deliberately never starts/resumes sessions or reopens paths.
    pub fn live_handles_for_trust_root(
        &self,
        trust_root: &std::path::Path,
    ) -> Vec<SessionWorkerHandle> {
        let handles = crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .values()
            .filter(|entry| !entry.handle.is_closed())
            .map(|entry| entry.handle.clone())
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter(|handle| handle.current_trust_policy().root.root.as_path() == trust_root)
            .collect()
    }

    /// The single daemon-wide lock manager. Exposed so the daemon's
    /// periodic lock sweeper (`read-wait-and-lock-expiry.md`) can call
    /// [`crate::locks::LockManager::sweep_expired`] — there is one authority,
    /// shared with every worker.
    pub fn locks(&self) -> Arc<LockManager> {
        self.inner.locks.clone()
    }

    /// Whether *any* live session worker is currently doing agent work —
    /// either mid-turn (`processing`) or holding an async job
    /// (loop/timer/background). Drives `/caffeinate until-idle` auto-off:
    /// the daemon owns the session workers / `ScheduleAuthority`, so it is the
    /// authority for "is an agent running anywhere?". Lock-free reads of
    /// each worker's shared atomics.
    pub fn any_agent_running(&self) -> bool {
        crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .values()
            .any(|entry| {
                let (has_schedules, processing, _tool_running) = entry.handle.live_status();
                has_schedules || processing
            })
    }

    /// Live `(has_active_schedules, processing, tool_running)` status for a session, or
    /// `None` when no worker is live for it (the browser then treats it
    /// as not-processing / no-jobs). Lock-free read of the worker's
    /// shared atomics (GOALS §17f).
    pub fn live_status(&self, session_id: Uuid) -> Option<(bool, bool, bool)> {
        crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .get(&session_id)
            .map(|entry| entry.handle.live_status())
    }

    /// Current live worker handle for an already-running session. This is the
    /// only acceptable session lookup cache: unlike [`Self::attach`], it never
    /// starts or resumes a worker, and callers must let misses continue through
    /// the shared DB-backed resume path. No cross-process state may be cached
    /// across requests without an invalidation path.
    pub fn live_handle(&self, session_id: Uuid) -> Option<SessionWorkerHandle> {
        crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .get(&session_id)
            .map(|entry| entry.handle.clone())
    }

    /// Stop a live session before archive/delete/discard. This is fail-closed:
    /// it cancels the in-flight turn, sends shutdown, then awaits the worker
    /// task with a bounded timeout. The caller must not mutate/delete DB rows
    /// unless this returns `Ok`.
    pub async fn interrupt_and_stop(&self, session_id: Uuid) -> Result<bool> {
        self.interrupt_and_stop_with_timeout(session_id, DESTRUCTIVE_STOP_TIMEOUT)
            .await
    }

    /// Claim and stop exactly the captured worker channel. Unlike the
    /// session-id convenience API, this never re-enumerates after an await and
    /// therefore cannot target a replacement generation.
    pub(crate) async fn interrupt_and_stop_exact(
        &self,
        handle: &SessionWorkerHandle,
    ) -> Result<bool> {
        let generation = {
            let workers = crate::sync::lock_or_recover(&self.inner.workers);
            let Some(entry) = workers.live.get(&handle.session_id) else {
                return Ok(false);
            };
            if !entry.handle.same_worker_as(handle) {
                bail!(
                    "session {} worker identity changed; refusing to stop its successor",
                    handle.session_id
                );
            }
            entry.generation
        };
        self.interrupt_and_stop_exact_until(
            generation,
            handle,
            tokio::time::Instant::now() + DESTRUCTIVE_STOP_TIMEOUT,
        )
        .await
    }

    async fn interrupt_and_stop_with_timeout(
        &self,
        session_id: Uuid,
        timeout: Duration,
    ) -> Result<bool> {
        let Some((generation, handle)) = self.lookup_entry(session_id) else {
            return Ok(false);
        };
        let deadline = tokio::time::Instant::now() + timeout;
        self.interrupt_and_stop_exact_until(generation, &handle, deadline)
            .await
    }

    /// Stop only the captured worker identity. Session ids are reusable, so
    /// recovery callers must never resolve the id again after an await and
    /// accidentally cancel a successor. Keeping the live entry installed
    /// until terminal cleanup also prevents replacement during this fence.
    async fn interrupt_and_stop_exact_until(
        &self,
        generation: WorkerGeneration,
        handle: &SessionWorkerHandle,
        deadline: tokio::time::Instant,
    ) -> Result<bool> {
        let session_id = handle.session_id;
        let stop_budget = deadline.saturating_duration_since(tokio::time::Instant::now());
        let terminal_cleanup_complete = {
            let workers = crate::sync::lock_or_recover(&self.inner.workers);
            let Some(entry) = workers.live.get(&session_id) else {
                return Ok(false);
            };
            if entry.generation != generation || !entry.handle.same_worker_as(handle) {
                bail!(
                    "session {session_id} worker identity changed; refusing to stop its successor"
                );
            }
            entry.terminal_cleanup_complete.clone()
        };
        let join = {
            let mut joins = crate::sync::lock_or_recover(&self.inner.worker_joins);
            if joins
                .get(&session_id)
                .is_some_and(|entry| entry.generation == generation)
            {
                joins.remove(&session_id).map(|entry| entry.join)
            } else {
                None
            }
        };
        let Some(mut join) = join else {
            let _ = tokio::time::timeout_at(
                deadline,
                handle.send_work(crate::daemon::session_worker::SessionWork::Cancel),
            )
            .await;
            let _ = tokio::time::timeout_at(
                deadline,
                handle.send_work(crate::daemon::session_worker::SessionWork::Shutdown {
                    pause_for_resume: false,
                }),
            )
            .await;
            return self
                .wait_for_missing_join_shutdown(
                    session_id,
                    generation,
                    handle,
                    &terminal_cleanup_complete,
                    deadline,
                    stop_budget,
                )
                .await;
        };

        let _ = tokio::time::timeout_at(
            deadline,
            handle.send_work(crate::daemon::session_worker::SessionWork::Cancel),
        )
        .await;
        let _ = tokio::time::timeout_at(
            deadline,
            handle.send_work(crate::daemon::session_worker::SessionWork::Shutdown {
                pause_for_resume: false,
            }),
        )
        .await;

        match tokio::time::timeout_at(deadline, &mut join).await {
            Ok(join_result) => {
                if let Err(e) = join_result {
                    tracing::warn!(%session_id, error = %e, "session worker stopped with join error");
                }
                if !terminal_cleanup_complete.load(Ordering::Acquire) {
                    // Preserve the exact live entry fail-closed. A closed task
                    // is not a successful stop until its terminal persistence
                    // and lock cleanup have completed, and removing this entry
                    // would let a successor hide that incomplete teardown.
                    bail!(
                        "session {session_id} worker exited before terminal cleanup completed; refusing replacement"
                    );
                }
                self.forget_generation(session_id, generation);
                Ok(true)
            }
            Err(_) => {
                // Claim terminal ownership before aborting. The worker cleanup
                // guard consults this bit, so it cannot retire the generation
                // between task cancellation and generation-bound cleanup.
                //
                // The single destructive-stop deadline already expired. Do
                // not start an unbounded second phase for the gate, lock
                // manager, or durable session store: retain this exact live
                // entry fail-closed and let the explicit terminal-cleanup
                // retry path finish it under a fresh caller-owned deadline.
                let terminal_closing = {
                    let workers = crate::sync::lock_or_recover(&self.inner.workers);
                    let entry = workers
                        .live
                        .get(&session_id)
                        .context("exact worker disappeared before forced-abort ownership claim")?;
                    if entry.generation != generation || !entry.handle.same_worker_as(handle) {
                        bail!("session {session_id} worker changed before forced abort");
                    }
                    entry.terminal_closing.clone()
                };
                terminal_closing.store(true, Ordering::Release);
                join.abort();
                // `abort()` is the deadline action; do not begin a second,
                // unbounded join phase after the caller's stop budget has
                // expired. Dropping the join detaches cancellation completion
                // while the exact live entry remains fail-closed for the
                // explicit terminal-cleanup retry path.
                drop(join);
                bail!(
                    "session {session_id} worker was force-aborted after the bounded {}ms stop deadline; exact generation retained pending terminal cleanup",
                    stop_budget.as_millis()
                )
            }
        }
    }

    async fn wait_for_missing_join_shutdown(
        &self,
        session_id: Uuid,
        generation: WorkerGeneration,
        handle: &SessionWorkerHandle,
        terminal_cleanup_complete: &Arc<AtomicBool>,
        deadline: tokio::time::Instant,
        stop_budget: Duration,
    ) -> Result<bool> {
        match tokio::time::timeout_at(deadline, async {
            while !handle.is_closed() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        {
            Ok(()) => {
                if !terminal_cleanup_complete.load(Ordering::Acquire) {
                    bail!(
                        "session {session_id} worker channel closed before terminal cleanup completed; refusing replacement"
                    );
                }
                self.forget_generation(session_id, generation);
                Ok(true)
            }
            Err(_) => bail!(
                "session {session_id} stop state is missing its worker join and the worker channel stayed open for {}ms; retry destructive session mutation later",
                stop_budget.as_millis()
            ),
        }
    }

    /// Test-only: register a raw worker `JoinHandle` directly, bypassing the
    /// full `Session`/`Driver`/`Model` wiring. Lets the drain tests
    /// (`daemon-graceful-drain-shutdown.md`) inject tasks with controlled
    /// in-flight duration so they can assert the await / grace / force
    /// behavior without standing up a real provider call. No
    /// `SessionWorkerHandle` is inserted, so `drain_all` sends `Shutdown` to
    /// zero handles and exercises the join/timeout/abort path in isolation.
    #[cfg(test)]
    fn insert_test_join(&self, id: Uuid, join: JoinHandle<()>) {
        let generation = {
            let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
            next_generation(&mut workers)
        };
        crate::sync::lock_or_recover(&self.inner.worker_joins).insert(
            id,
            WorkerJoin {
                generation,
                join,
                _config_watcher: None,
            },
        );
    }

    #[cfg(test)]
    pub(crate) fn insert_test_worker(
        &self,
        handle: SessionWorkerHandle,
        join: JoinHandle<()>,
    ) -> WorkerGeneration {
        let id = handle.session_id;
        let generation = {
            let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
            let generation = next_generation(&mut workers);
            workers.live.insert(
                id,
                WorkerEntry {
                    generation,
                    handle,
                    activation_leases: 0,
                    terminal_lock_cleanup_gate: Arc::new(AsyncMutex::new(())),
                    terminal_closing: Arc::new(AtomicBool::new(false)),
                    terminal_cleanup_complete: Arc::new(AtomicBool::new(false)),
                },
            );
            generation
        };
        crate::sync::lock_or_recover(&self.inner.worker_joins).insert(
            id,
            WorkerJoin {
                generation,
                join,
                _config_watcher: None,
            },
        );
        generation
    }

    #[cfg(test)]
    fn insert_test_worker_without_join(&self, handle: SessionWorkerHandle) -> WorkerGeneration {
        let id = handle.session_id;
        let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
        let generation = next_generation(&mut workers);
        workers.live.insert(
            id,
            WorkerEntry {
                generation,
                handle,
                activation_leases: 0,
                terminal_lock_cleanup_gate: Arc::new(AsyncMutex::new(())),
                terminal_closing: Arc::new(AtomicBool::new(false)),
                terminal_cleanup_complete: Arc::new(AtomicBool::new(false)),
            },
        );
        generation
    }

    #[cfg(test)]
    fn live_generation(&self, id: Uuid) -> Option<WorkerGeneration> {
        crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .get(&id)
            .map(|entry| entry.generation)
    }

    #[cfg(test)]
    fn insert_test_worker_with_exit_cleanup(&self, handle: SessionWorkerHandle) {
        let id = handle.session_id;
        let weak = Arc::downgrade(&self.inner);
        let generation = self.insert_test_worker(handle, tokio::spawn(async {}));
        let join = tokio::spawn(async move {
            cleanup_worker_on_exit(weak, id, generation);
        });
        crate::sync::lock_or_recover(&self.inner.worker_joins).insert(
            id,
            WorkerJoin {
                generation,
                join,
                _config_watcher: None,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::proto;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn test_registry() -> SessionRegistry {
        test_registry_with_config_source(crate::daemon::config_source::ConfigSource::fixed(
            ProvidersConfig::default(),
            ExtendedConfig::default(),
        ))
    }

    fn test_registry_with_config_source(
        config_source: crate::daemon::config_source::ConfigSource,
    ) -> SessionRegistry {
        // The DB + lock manager aren't touched by `drain_all`; point them at
        // a throwaway in-memory DB so construction never hits user state.
        let db = Db::open_in_memory().expect("in-memory db");
        let locks = Arc::new(LockManager::in_memory(db.clone()));
        let vault = crate::secure_key::vault_for_db(&db).expect("test vault");
        let reg = SessionRegistry::new(db, locks, ShutdownSignal::new(), None, config_source);
        reg.set_redaction_key_resolver(crate::session::test_redaction_key_resolver());
        reg.set_secret_vault(vault);
        reg
    }

    fn test_session(reg: &SessionRegistry) -> Arc<Session> {
        let tmp = tempfile::tempdir().expect("tempdir");
        Arc::new(
            Session::create_deferred_for_test(
                reg.inner.db.clone(),
                tmp.keep(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .expect("deferred session"),
        )
    }

    fn persisted_test_session(reg: &SessionRegistry) -> Arc<Session> {
        let tmp = tempfile::tempdir().expect("tempdir");
        Arc::new(
            Session::create_for_test(
                reg.inner.db.clone(),
                tmp.keep(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .expect("session"),
        )
    }

    fn test_handle(reg: &SessionRegistry, session: Arc<Session>) -> SessionWorkerHandle {
        session_worker::SessionWorkerHandle::test_handle(session, reg.inner.locks.clone())
    }

    /// Regression guard (`daemon-lifecycle-replay-timing-robustness.md`): the
    /// `attach` future must stay small on the stack. The reconciliation gate +
    /// resume/create sub-futures are `Box::pin`ned so their state lives on the
    /// heap; without that, `attach`'s future ballooned and overflowed the tokio
    /// worker stack at the synchronous `Session::resume` frame (SIGABRT /
    /// pathologically large). This asserts the future stays well under a worker
    /// stack budget so that regression cannot silently return.
    #[test]
    fn attach_future_stays_small_on_stack() {
        let reg = test_registry();
        let env = EnvSnapshot::new(
            crate::env_snapshot::EnvSnapshotSource::DaemonStart,
            Default::default(),
        );
        let fut = reg.attach(
            Some(Uuid::new_v4()),
            None,
            None,
            false,
            None,
            env,
            proto::SessionEntryMode::Code,
        );
        let size = std::mem::size_of_val(&fut);
        assert!(
            size < 4096,
            "attach future grew to {size} bytes; box the heavy sub-futures to keep it small"
        );
    }

    /// A test handle whose work queue keeps a LIVE receiver, so drain's bounded
    /// Shutdown dispatch (finding 1) succeeds and the worker counts as
    /// "delivered". The returned receiver must be kept alive for the duration of
    /// the test; dropping it closes the queue and drain will treat the worker as
    /// undelivered and force-abort it.
    fn test_handle_with_rx(
        reg: &SessionRegistry,
        session: Arc<Session>,
    ) -> (
        SessionWorkerHandle,
        tokio::sync::mpsc::Receiver<session_worker::SessionWork>,
    ) {
        session_worker::SessionWorkerHandle::test_handle_with_receiver(
            session,
            reg.inner.locks.clone(),
        )
    }

    struct NoopSchedulerExecutor;

    #[async_trait]
    impl crate::daemon::scheduler::JobExecutor for NoopSchedulerExecutor {
        async fn execute(&self, _job: crate::daemon::scheduler::ScheduledJob) -> Result<String> {
            Ok("ok".to_string())
        }
    }

    struct PendingSchedulerSleeper;

    #[async_trait]
    impl crate::daemon::scheduler::SchedulerSleeper for PendingSchedulerSleeper {
        async fn sleep_until(&self, _now: i64, _wake_at: Option<i64>) {
            std::future::pending::<()>().await;
        }
    }

    fn test_scheduler_handle() -> crate::daemon::scheduler::DaemonSchedulerHandle {
        let scheduler = Arc::new(crate::daemon::scheduler::DaemonScheduler::new(
            Db::open_in_memory().expect("scheduler db"),
            Arc::new(crate::daemon::scheduler::SystemClock),
            Arc::new(NoopSchedulerExecutor),
        ));
        scheduler.start_with_sleeper(
            ShutdownSignal::new(),
            Arc::new(PendingSchedulerSleeper),
            None,
        )
    }

    #[tokio::test]
    async fn set_scheduler_round_trips() {
        let reg = test_registry();
        assert!(reg.scheduler().is_none());

        let first = test_scheduler_handle();
        reg.set_scheduler(first.clone());
        let got = reg.scheduler().expect("scheduler set");
        assert!(Arc::ptr_eq(got.scheduler(), first.scheduler()));

        let second = test_scheduler_handle();
        reg.set_scheduler(second.clone());
        let got = reg.scheduler().expect("scheduler replaced");
        assert!(Arc::ptr_eq(got.scheduler(), second.scheduler()));
        assert!(!Arc::ptr_eq(got.scheduler(), first.scheduler()));
    }

    #[tokio::test]
    async fn late_set_is_visible_to_already_started_workers() {
        let reg = test_registry();
        let worker_source = reg.scheduler_source();
        assert!(crate::sync::lock_or_recover(&worker_source).is_none());

        let handle = test_scheduler_handle();
        reg.set_scheduler(handle.clone());

        let observed = crate::sync::lock_or_recover(&worker_source)
            .clone()
            .expect("late scheduler visible through worker source");
        assert!(Arc::ptr_eq(observed.scheduler(), handle.scheduler()));
    }

    #[tokio::test]
    async fn worker_receives_scheduler_handle() {
        let reg = test_registry();
        let empty_worker_source = reg.scheduler_source();
        assert!(crate::sync::lock_or_recover(&empty_worker_source).is_none());

        let handle = test_scheduler_handle();
        reg.set_scheduler(handle.clone());
        let worker_source = reg.scheduler_source();
        let observed = crate::sync::lock_or_recover(&worker_source)
            .clone()
            .expect("scheduler visible through worker source");
        assert!(Arc::ptr_eq(observed.scheduler(), handle.scheduler()));
    }

    fn providers_for_btw_model_tests() -> ProvidersConfig {
        use crate::config::providers::{ActiveModelRef, ModelEntry, ProviderEntry};
        use std::collections::BTreeMap;

        let mut providers = BTreeMap::new();
        providers.insert(
            "lmstudio".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".to_string(),
                models: vec![
                    ModelEntry {
                        id: "parent-model".to_string(),
                        ..ModelEntry::default()
                    },
                    ModelEntry {
                        id: "btw-model".to_string(),
                        ..ModelEntry::default()
                    },
                ],
                ..ProviderEntry::default()
            },
        );
        ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".to_string(),
                model: "parent-model".to_string(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        }
    }

    fn assert_no_live_worker(reg: &SessionRegistry, id: Uuid) {
        assert!(!reg.active_session_ids().contains(&id));
        assert!(!reg.any_agent_running());
        assert_eq!(reg.live_status(id), None);
        assert!(matches!(reg.claim_attach(id), AttachClaim::Start(_)));
    }

    #[tokio::test]
    async fn config_watcher_setup_failure_does_not_fail_session_start() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing-layer");
        let source = crate::daemon::config_source::ConfigSource::new(
            |_cwd| Ok((providers_for_btw_model_tests(), ExtendedConfig::default())),
            |_cwd, _provider_id| None,
            move |_cwd| {
                crate::daemon::config_source::ConfigWatchPaths::new(
                    vec![missing.join("config.json")],
                    vec![missing.join("providers")],
                )
            },
        );
        let reg = test_registry_with_config_source(source);
        reg.inner
            .db
            .set_workspace_trust(
                tmp.path(),
                crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            )
            .await
            .unwrap();

        let handle = reg
            .attach(
                None,
                Some(tmp.path().to_path_buf()),
                None,
                false,
                None,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await
            .expect("missing watch paths must not fail session start");

        assert!(reg.lookup(handle.session_id).is_some());
        reg.forget(handle.session_id);
    }

    #[tokio::test]
    async fn modes_session_setup_preflight_authority_survives_config_override_change_for_every_start_path()
     {
        fn write_explicit_model_config(path: &std::path::Path, model: &str) {
            let providers = path.parent().expect("config parent").join("providers");
            std::fs::create_dir_all(&providers).expect("create explicit provider directory");
            std::fs::write(
                path,
                format!(
                    r#"{{"active_model":{{"provider":"lmstudio","model":"{model}"}},"maxPrimaryRounds":17,"hooks":{{"preToolUse":[{{"command":["hook-{model}"]}}]}}}}"#
                ),
            )
            .expect("write explicit config");
            std::fs::write(
                providers.join("lmstudio.json"),
                format!(r#"{{"url":"http://127.0.0.1:9/v1","models":[{{"id":"{model}"}}]}}"#),
            )
            .expect("write explicit provider");
        }

        fn assert_preflight_model(handle: &SessionWorkerHandle, model: &str) {
            assert_eq!(
                handle
                    .active_model_selection()
                    .as_ref()
                    .map(|selection| selection.model.as_str()),
                Some(model),
                "durable/session model must come from the preflight config"
            );
            assert_eq!(
                handle
                    .config_snapshot()
                    .providers
                    .active_model
                    .as_ref()
                    .map(|selection| selection.model.as_str()),
                Some(model),
                "worker snapshot must be the same preflight config"
            );
            assert!(
                handle.config_snapshot().hooks.hooks.iter().any(|hook| hook
                    .command
                    .first()
                    .is_some_and(|command| { command == &format!("hook-{model}") })),
                "worker hooks must be the same preflight config"
            );
        }

        let state = tempfile::tempdir().expect("isolated state");
        let env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(state.path()).await;
        let workspace = state.path().join("workspace");
        let config_a = state.path().join("override-a/config.json");
        let config_b = state.path().join("override-b/config.json");
        std::fs::create_dir_all(&workspace).expect("workspace");
        write_explicit_model_config(&config_a, "model-a");
        write_explicit_model_config(&config_b, "model-b");

        let reg = test_registry_with_config_source(
            crate::daemon::config_source::ConfigSource::production(),
        );
        reg.inner
            .db
            .set_workspace_trust(
                &workspace,
                crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            )
            .await
            .expect("trust workspace");

        let hook_calls = Arc::new(AtomicUsize::new(0));
        let hook_calls_for_start = Arc::clone(&hook_calls);
        let config_b_for_start = config_b.clone();
        reg.set_pre_start_worker_hook(Some(Arc::new(move || {
            hook_calls_for_start.fetch_add(1, Ordering::SeqCst);
            // SAFETY: `TestEnvGuard` holds the process-global environment
            // mutation lock for this whole test. This hook runs synchronously
            // on its owner test task between preflight and worker construction.
            unsafe {
                std::env::set_var(crate::config::dirs::COCKPIT_CONFIG_ENV, &config_b_for_start);
            }
        })));

        let daemon_env = || {
            EnvSnapshot::new(
                crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                Default::default(),
            )
        };

        env.set_cockpit_config(&config_a);
        let created = reg
            .attach(
                None,
                Some(workspace.clone()),
                None,
                false,
                None,
                daemon_env(),
                proto::SessionEntryMode::Code,
            )
            .await
            .expect("create through preflight A");
        assert_preflight_model(&created, "model-a");
        assert!(
            reg.interrupt_and_stop(created.session_id)
                .await
                .expect("stop created worker")
        );

        let assistant_name = "preflight-authority";
        let assistant_home =
            crate::assistants::default_home_dir(assistant_name).expect("canonical assistant home");
        crate::assistants::create_assistant(
            &reg.inner.db,
            crate::assistants::CreateAssistantSpec {
                name: assistant_name.to_string(),
                description: "preflight authority fixture".to_string(),
                prompt: "Keep the attached configuration authority.".to_string(),
                home_dir: assistant_home,
            },
        )
        .await
        .expect("create verified assistant");
        env.set_cockpit_config(&config_a);
        let assistant = reg
            .create_assistant_session(assistant_name, workspace.clone(), None, false, daemon_env())
            .await
            .expect("assistant creation through preflight A");
        assert_preflight_model(&assistant, "model-a");
        assert!(
            reg.interrupt_and_stop(assistant.session_id)
                .await
                .expect("stop assistant worker")
        );

        let persisted = reg
            .inner
            .db
            .create_session(
                "provider",
                workspace.to_str().expect("workspace UTF-8"),
                "Build",
            )
            .await
            .expect("durable session for resume");
        env.set_cockpit_config(&config_a);
        let resumed = reg
            .attach(
                Some(persisted.session_id),
                None,
                None,
                false,
                None,
                daemon_env(),
                proto::SessionEntryMode::Code,
            )
            .await
            .expect("resume through preflight A");
        assert_preflight_model(&resumed, "model-a");
        assert!(
            reg.interrupt_and_stop(resumed.session_id)
                .await
                .expect("stop resumed worker")
        );
        assert_eq!(hook_calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn malformed_response_metrics_tokenizer_blocks_registry_attach_snapshot() {
        fn assert_invalid_tokenizer_blocks_snapshot(
            error: anyhow::Error,
            expected_outer_context: &str,
        ) {
            // Registry callers require the fail-closed boundary, not an
            // implementation-specific concrete error. Each entry point keeps
            // its useful, stable outer context while the tokenizer cause stays
            // redacted throughout the chain.
            assert_eq!(error.to_string(), expected_outer_context);
            let chain = format!("{error:#}");
            assert!(chain.contains("configuration value is invalid"));
            assert!(!chain.contains("invalid-registry-value"));
        }

        let tmp = tempfile::tempdir().unwrap();
        let _home =
            crate::config::dirs::test_support::IsolatedCockpitHome::new_async(tmp.path()).await;
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(project.join(".cockpit")).unwrap();
        std::fs::write(
            project.join(".cockpit/config.json"),
            r#"{"response_metrics_tokenizer":"invalid-registry-value"}"#,
        )
        .unwrap();
        let reg = test_registry_with_config_source(
            crate::daemon::config_source::ConfigSource::production(),
        );
        reg.inner
            .db
            .set_workspace_trust(
                &project,
                crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            )
            .await
            .unwrap();
        let persisted = reg
            .inner
            .db
            .create_session("provider", project.to_str().unwrap(), "Build")
            .await
            .unwrap();
        let error = reg
            .attach(
                None,
                Some(project.clone()),
                None,
                false,
                None,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await
            .err()
            .expect("invalid tokenizer must block registry snapshot");
        assert_invalid_tokenizer_blocks_snapshot(error, "configuration value is invalid");
        let resume_error = reg
            .attach(
                Some(persisted.session_id),
                Some(project.clone()),
                None,
                false,
                None,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await
            .err()
            .expect("invalid tokenizer must block resumed snapshot");
        assert_invalid_tokenizer_blocks_snapshot(resume_error, "configuration value is invalid");
        let assistant_home = crate::assistants::default_home_dir("helper").unwrap();
        std::fs::create_dir_all(&assistant_home).unwrap();
        let assistant_md = "---\nagentId: local/00000000-0000-0000-0000-000000000001\ndescription: Test helper\nexecutionKind: assistant\nmodelSlots:\n  primary:\n    allowDefaultFallback: true\n    locality: any\n    minContextTokens: 1\n    purpose: Primary model\n    requiredCapabilities: [text_generation]\nschemaVersion: 2\n---\n\nHelp with tests.\n";
        std::fs::write(assistant_home.join("assistant.md"), assistant_md).unwrap();
        let content_hash =
            crate::assistants::markdown_content_identity(&reg.inner.db, assistant_md).unwrap();
        reg.inner
            .db
            .upsert_assistant(
                "helper",
                assistant_home.to_str().unwrap(),
                r#"{"installationId":"00000000-0000-0000-0000-000000000001"}"#,
                &content_hash,
            )
            .await
            .unwrap();
        let create_error = reg
            .create_assistant_session(
                "helper",
                project,
                None,
                false,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
            )
            .await
            .err()
            .expect("invalid tokenizer must block assistant snapshot creation");
        assert_invalid_tokenizer_blocks_snapshot(create_error, "configuration value is invalid");
    }

    #[tokio::test]
    async fn config_watcher_task_is_aborted_on_session_forget() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        let generation = reg.insert_test_worker_without_join(handle);
        let config_watcher = tokio::spawn(std::future::pending::<()>());
        let abort_handle = config_watcher.abort_handle();
        let join = tokio::spawn(async {});
        crate::sync::lock_or_recover(&reg.inner.worker_joins).insert(
            id,
            WorkerJoin {
                generation,
                join,
                _config_watcher: Some(ConfigWatcherJoin(config_watcher)),
            },
        );

        reg.forget(id);

        for _ in 0..100 {
            if abort_handle.is_finished() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("forget should abort config watcher task");
    }

    #[tokio::test]
    async fn btw_model_knob_resolution() {
        let reg = test_registry();
        let tmp = tempfile::tempdir().expect("tempdir");
        let parent = Session::create_for_test(
            reg.inner.db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        parent.set_active_model("lmstudio", "parent-model").unwrap();
        let fork = reg
            .inner
            .db
            .create_btw_fork(parent.id, false)
            .await
            .expect("btw fork")
            .info;
        let fork_session = Session::resume_for_test(
            reg.inner.db.clone(),
            fork.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("fork session");
        let providers = providers_for_btw_model_tests();
        let env_snapshot = EnvSnapshot::new(proto::EnvSnapshotSource::ExplicitCli, HashMap::new());
        let redact = Arc::new(RedactionTable::empty());

        let inherited = resolve_session_worker_model(
            &providers,
            &ExtendedConfig::default(),
            &fork_session,
            redact.clone(),
            &env_snapshot,
            None,
            &reg.inner.shutdown,
        )
        .unwrap();
        assert_eq!(inherited.model_id_ref(), "parent-model");

        let overridden = resolve_session_worker_model(
            &providers,
            &ExtendedConfig {
                btw_model: Some("lmstudio:btw-model".into()),
                ..ExtendedConfig::default()
            },
            &fork_session,
            redact.clone(),
            &env_snapshot,
            None,
            &reg.inner.shutdown,
        )
        .unwrap();
        assert_eq!(overridden.model_id_ref(), "btw-model");

        let fallback = resolve_session_worker_model(
            &providers,
            &ExtendedConfig {
                btw_model: Some("missing-provider:model".into()),
                ..ExtendedConfig::default()
            },
            &fork_session,
            redact,
            &env_snapshot,
            None,
            &reg.inner.shutdown,
        )
        .unwrap();
        assert_eq!(fallback.model_id_ref(), "parent-model");
    }
    #[tokio::test]
    async fn explicit_initial_model_is_durable_and_wins_on_cold_resume() {
        let tmp = tempfile::tempdir().unwrap();
        let mut no_default = providers_for_btw_model_tests();
        no_default.active_model = None;
        let source = crate::daemon::config_source::ConfigSource::new(
            move |_cwd| Ok((no_default.clone(), ExtendedConfig::default())),
            |_cwd, _provider_id| None,
            |_cwd| crate::daemon::config_source::ConfigWatchPaths::new(Vec::new(), Vec::new()),
        );
        let reg = test_registry_with_config_source(source);
        reg.inner
            .db
            .set_workspace_trust(
                tmp.path(),
                crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            )
            .await
            .unwrap();
        let selection = ActiveModelRef {
            provider: "lmstudio".to_string(),
            model: "btw-model".to_string(),
            reasoning_effort: Some(crate::config::providers::ActiveReasoningEffort {
                value: "high".to_string(),
            }),
            thinking_mode: Some(crate::config::providers::ThinkingMode::High),
            prompt_cache_retention: Some(crate::config::providers::PromptCacheRetention::Extended),
        };

        let handle = reg
            .attach(
                None,
                Some(tmp.path().to_path_buf()),
                Some(selection.clone()),
                false,
                None,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await
            .expect("explicit model should create a session without a configured default");
        assert_eq!(handle.active_model_selection(), Some(selection.clone()));
        handle.persist_if_needed().unwrap();
        let session_id = handle.session_id;
        reg.forget(session_id);

        let resumed = Session::resume_for_test(
            reg.inner.db.clone(),
            session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("persisted session resumes");
        assert_eq!(resumed.active_model_ref(), Some(selection.clone()));

        let config_with_different_default = providers_for_btw_model_tests();
        let resolved = resolve_session_worker_model(
            &config_with_different_default,
            &ExtendedConfig::default(),
            &resumed,
            Arc::new(RedactionTable::empty()),
            &EnvSnapshot::new(proto::EnvSnapshotSource::ExplicitCli, HashMap::new()),
            None,
            &reg.inner.shutdown,
        )
        .expect("cold resume resolves the persisted session model");
        assert_eq!(resolved.model_id_ref(), "btw-model");

        // A picker recovering an existing model-less session must retain its
        // identity and durably seed it, not create a replacement session.
        let legacy = Session::create_for_test(
            reg.inner.db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let legacy_id = legacy.id;
        let recovered = reg
            .attach(
                Some(legacy_id),
                None,
                Some(selection.clone()),
                false,
                None,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await
            .expect("explicit model should recover the same model-less session");
        assert_eq!(recovered.session_id, legacy_id);
        assert_eq!(recovered.active_model_selection(), Some(selection.clone()));
        reg.forget(legacy_id);
        let durable = Session::resume_for_test(
            reg.inner.db.clone(),
            legacy_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("recovered session remains durable");
        assert_eq!(durable.active_model_ref(), Some(selection.clone()));

        let invalid = Session::create_for_test(
            reg.inner.db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let invalid_id = invalid.id;
        drop(invalid);
        let mut unconfigured = selection.clone();
        unconfigured.provider = "missing-provider".to_string();
        let failed_recovery = reg
            .attach(
                Some(invalid_id),
                None,
                Some(unconfigured),
                false,
                None,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await;
        assert!(failed_recovery.is_err());
        let unchanged = reg
            .inner
            .db
            .get_session(invalid_id)
            .await
            .unwrap()
            .expect("failed recovery keeps the session row");
        assert_eq!(unchanged.provider, None);
        assert_eq!(unchanged.model, None);
        assert_eq!(unchanged.model_selection_json, None);

        // `cockpit run --model` sends the same complete selection as a
        // plan-level pin. Even without a configured default, that pin is the
        // authoritative durable session model rather than a parallel
        // inference-only override.
        let pinned = reg
            .attach(
                None,
                Some(tmp.path().to_path_buf()),
                None,
                false,
                Some(&selection),
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::ExplicitCli,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await
            .expect("structured model pin creates an aligned session");
        assert_eq!(pinned.active_model_selection(), Some(selection.clone()));
        pinned.persist_if_needed().unwrap();
        let pinned_id = pinned.session_id;
        reg.forget(pinned_id);
        assert_eq!(
            Session::resume_for_test(
                reg.inner.db.clone(),
                pinned_id,
                crate::session::test_redaction_key_resolver()
            )
            .unwrap()
            .expect("pinned session persists")
            .active_model_ref(),
            Some(selection.clone())
        );

        let mut conflicting = selection.clone();
        conflicting.model = "other-model".to_string();
        let mismatch = reg
            .attach(
                None,
                Some(tmp.path().to_path_buf()),
                Some(selection.clone()),
                false,
                Some(&conflicting),
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::ExplicitCli,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await;
        let mismatch = match mismatch {
            Ok(_) => panic!("parallel active and pinned selections must be rejected"),
            Err(error) => error,
        };
        assert!(
            mismatch
                .to_string()
                .contains("must be the same complete selection")
        );

        let missing = reg
            .attach(
                None,
                Some(tmp.path().to_path_buf()),
                None,
                false,
                None,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await;
        let missing = match missing {
            Ok(_) => panic!("new session without an explicit or default model must be rejected"),
            Err(error) => error,
        };
        assert!(missing.to_string().contains("no model selected"));
    }

    #[tokio::test]
    async fn concurrent_attach_claims_converge_on_one_started_worker() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let first_ticket = match reg.claim_attach(id) {
            AttachClaim::Start(ticket) => ticket,
            _ => panic!("first attach should claim startup"),
        };
        let generation = first_ticket.generation();

        let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
        let reg_waiter = reg.clone();
        let waiter = tokio::spawn(async move {
            match reg_waiter.claim_attach(id) {
                AttachClaim::Starting(slot) => {
                    waiting_tx.send(()).unwrap();
                    wait_for_start(slot).await.unwrap()
                }
                _ => panic!("second attach should wait for startup"),
            }
        });
        waiting_rx.await.unwrap();

        let handle = test_handle(&reg, session);
        let result = Ok(handle.clone());
        reg.finish_attach_start(first_ticket, &result);
        crate::sync::lock_or_recover(&reg.inner.workers)
            .live
            .insert(
                id,
                WorkerEntry {
                    generation,
                    handle: handle.clone(),
                    activation_leases: 0,
                    terminal_lock_cleanup_gate: Arc::new(AsyncMutex::new(())),
                    terminal_closing: Arc::new(AtomicBool::new(false)),
                    terminal_cleanup_complete: Arc::new(AtomicBool::new(false)),
                },
            );

        let waited = waiter.await.unwrap();
        assert_eq!(waited.session_id, id);
        assert_eq!(reg.lookup(id).unwrap().session_id, id);
    }

    #[test]
    fn failed_attach_start_clears_placeholder_for_retry() {
        let reg = test_registry();
        let id = Uuid::new_v4();
        let ticket = match reg.claim_attach(id) {
            AttachClaim::Start(ticket) => ticket,
            _ => panic!("first attach should claim startup"),
        };
        let result: Result<SessionWorkerHandle> = Err(anyhow::anyhow!("boom"));
        reg.finish_attach_start(ticket, &result);

        match reg.claim_attach(id) {
            AttachClaim::Start(_) => {}
            _ => panic!("failed startup should leave no in-flight placeholder"),
        }
    }

    #[test]
    fn different_session_attaches_claim_independent_start_slots() {
        let reg = test_registry();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        assert!(matches!(reg.claim_attach(first), AttachClaim::Start(_)));
        assert!(matches!(reg.claim_attach(second), AttachClaim::Start(_)));
    }

    #[tokio::test]
    async fn dropped_attach_start_wakes_waiters_with_error() {
        let reg = test_registry();
        let id = Uuid::new_v4();
        let ticket = match reg.claim_attach(id) {
            AttachClaim::Start(ticket) => ticket,
            _ => panic!("first attach should claim startup"),
        };

        let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
        let reg_waiter = reg.clone();
        let waiter = tokio::spawn(async move {
            match reg_waiter.claim_attach(id) {
                AttachClaim::Starting(slot) => {
                    waiting_tx.send(()).unwrap();
                    wait_for_start(slot).await
                }
                _ => panic!("second attach should wait for startup"),
            }
        });
        waiting_rx.await.unwrap();
        drop(ticket);

        let err = match waiter.await.unwrap() {
            Ok(_) => panic!("waiter should receive abandoned-start error"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("abandoned"), "{err}");
        assert!(matches!(reg.claim_attach(id), AttachClaim::Start(_)));
    }

    #[tokio::test]
    async fn panicked_attach_start_wakes_waiters_with_error() {
        let reg = test_registry();
        let id = Uuid::new_v4();
        let ticket = match reg.claim_attach(id) {
            AttachClaim::Start(ticket) => ticket,
            _ => panic!("first attach should claim startup"),
        };

        let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
        let reg_waiter = reg.clone();
        let waiter = tokio::spawn(async move {
            match reg_waiter.claim_attach(id) {
                AttachClaim::Starting(slot) => {
                    waiting_tx.send(()).unwrap();
                    wait_for_start(slot).await
                }
                _ => panic!("second attach should wait for startup"),
            }
        });
        waiting_rx.await.unwrap();
        let panicker = tokio::spawn(async move {
            let _ticket = ticket;
            panic!("start task panic");
        });
        assert!(panicker.await.unwrap_err().is_panic());

        let err = match waiter.await.unwrap() {
            Ok(_) => panic!("waiter should receive abandoned-start error"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("abandoned"), "{err}");
        assert!(matches!(reg.claim_attach(id), AttachClaim::Start(_)));
    }

    #[tokio::test]
    async fn attach_start_waiters_time_out() {
        let reg = test_registry();
        let id = Uuid::new_v4();
        let _ticket = match reg.claim_attach(id) {
            AttachClaim::Start(ticket) => ticket,
            _ => panic!("first attach should claim startup"),
        };
        let slot = match reg.claim_attach(id) {
            AttachClaim::Starting(slot) => slot,
            _ => panic!("second attach should wait for startup"),
        };

        let err = match wait_for_start(slot).await {
            Ok(_) => panic!("waiter should time out"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("did not complete"), "{err}");
    }

    #[tokio::test]
    async fn worker_exit_cleanup_removes_handle_and_join() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        reg.insert_test_worker_with_exit_cleanup(handle);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if reg.lookup(id).is_none()
                    && !crate::sync::lock_or_recover(&reg.inner.worker_joins).contains_key(&id)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup should remove worker promptly");

        assert_no_live_worker(&reg, id);
    }

    #[tokio::test]
    async fn stale_worker_cleanup_cannot_remove_successor_generation() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let old_handle = test_handle(&reg, session.clone());
        let old_join = tokio::spawn(async {});
        let old_generation = reg.insert_test_worker(old_handle, old_join);

        let new_handle = test_handle(&reg, session);
        let new_join = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        let new_generation = reg.insert_test_worker(new_handle, new_join);
        assert_ne!(old_generation, new_generation);

        cleanup_worker_on_exit(Arc::downgrade(&reg.inner), id, old_generation);

        assert_eq!(reg.live_generation(id), Some(new_generation));
        assert!(reg.lookup(id).is_some());
        assert!(crate::sync::lock_or_recover(&reg.inner.worker_joins).contains_key(&id));
    }

    #[tokio::test]
    async fn modes_session_setup_stale_lazy_live_claim_cannot_resume_successor_generation() {
        let reg = test_registry();
        let session = test_session(&reg);
        let session_id = session.id;
        let (old_handle, old_rx) = test_handle_with_rx(&reg, session.clone());
        let old_generation = reg.insert_test_worker_without_join(old_handle);

        let stale_claim = reg
            .claim_live_attach_if_present(session_id)
            .await
            .unwrap()
            .expect("first generation is live");

        // This models the await between deriving the lazy session's daemon-
        // owned root/mode and dispatch activation: A exits, while B attempts
        // to replace the same session id before A's lease resolves.
        drop(old_rx);
        reg.forget_generation(session_id, old_generation);
        assert!(matches!(
            reg.claim_attach(session_id),
            AttachClaim::Activating
        ));
        assert!(
            reg.activate_claimed_live_session(stale_claim)
                .await
                .unwrap()
                .is_none(),
            "a closed generation A must fail before it can resume a successor"
        );
        assert!(matches!(
            reg.claim_attach(session_id),
            AttachClaim::Start(_)
        ));
    }

    #[tokio::test]
    async fn modes_session_setup_ordinary_live_claim_pins_generation_through_activation() {
        let reg = test_registry();
        let session = test_session(&reg);
        let session_id = session.id;
        let (old_handle, old_rx) = test_handle_with_rx(&reg, session);
        let old_generation = reg.insert_test_worker_without_join(old_handle);

        let stale_claim = match reg.claim_attach(session_id) {
            AttachClaim::Live(claim) => claim,
            _ => panic!("the first generation must be claimed live"),
        };

        // Interleave after the normal attach path has accepted generation A,
        // but before it can await lock resumption. A closing must retain its
        // registry generation while the lease is live, so a replacement B
        // cannot be started and resumed using A's already-validated facts.
        drop(old_rx);
        reg.forget_generation(session_id, old_generation);
        assert!(matches!(
            reg.claim_attach(session_id),
            AttachClaim::Activating
        ));
        assert!(
            reg.activate_claimed_live_session(stale_claim)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            reg.claim_attach(session_id),
            AttachClaim::Start(_)
        ));
    }

    #[tokio::test]
    async fn modes_session_setup_terminal_cleanup_retry_retires_only_its_generation() {
        let reg = test_registry();
        let session = test_session(&reg);
        let session_id = session.id;
        let (handle, closed_rx) = test_handle_with_rx(&reg, session);
        let generation = reg.insert_test_worker_without_join(handle);
        {
            let workers = crate::sync::lock_or_recover(&reg.inner.workers);
            let entry = workers.live.get(&session_id).expect("test generation");
            entry.terminal_closing.store(true, Ordering::Release);
            assert!(!entry.terminal_cleanup_complete.load(Ordering::Acquire));
        }
        drop(closed_rx);

        let claim = match reg.claim_attach(session_id) {
            AttachClaim::CleanupRequired(claim) => claim,
            _ => panic!("only the closed terminal generation may own cleanup"),
        };
        reg.complete_terminal_cleanup(&claim)
            .await
            .expect("cleanup retry succeeds");
        drop(claim);

        assert!(matches!(
            reg.claim_attach(session_id),
            AttachClaim::Start(_)
        ));
        assert!(
            reg.live_generation(session_id).is_none(),
            "the cleaned terminal generation is removed before a successor starts"
        );
    }

    #[tokio::test]
    async fn modes_session_setup_start_generation_is_leased_before_reconciliation() {
        let reg = test_registry();
        let session = test_session(&reg);
        let session_id = session.id;
        let ticket = match reg.claim_attach(session_id) {
            AttachClaim::Start(ticket) => ticket,
            _ => panic!("first attach must own startup"),
        };
        let generation = ticket.generation();
        let (handle, closed_rx) = test_handle_with_rx(&reg, session);
        crate::sync::lock_or_recover(&reg.inner.workers)
            .live
            .insert(
                session_id,
                WorkerEntry {
                    generation,
                    handle: handle.clone(),
                    activation_leases: 0,
                    terminal_lock_cleanup_gate: Arc::new(AsyncMutex::new(())),
                    terminal_closing: Arc::new(AtomicBool::new(false)),
                    terminal_cleanup_complete: Arc::new(AtomicBool::new(false)),
                },
            );
        let result = Ok(handle);
        reg.finish_attach_start(ticket, &result);

        let claim = reg
            .claim_live_generation(session_id, generation)
            .expect("published Start generation must receive an activation lease");
        drop(closed_rx);
        reg.forget_generation(session_id, generation);
        assert!(matches!(
            reg.claim_attach(session_id),
            AttachClaim::Activating
        ));
        drop(claim);
        assert!(matches!(
            reg.claim_attach(session_id),
            AttachClaim::Start(_)
        ));
    }

    #[tokio::test]
    async fn modes_session_setup_starting_generation_is_leased_before_reconciliation() {
        let reg = test_registry();
        let session = test_session(&reg);
        let session_id = session.id;
        let ticket = match reg.claim_attach(session_id) {
            AttachClaim::Start(ticket) => ticket,
            _ => panic!("first attach must own startup"),
        };
        let generation = ticket.generation();
        let slot = match reg.claim_attach(session_id) {
            AttachClaim::Starting(slot) => slot,
            _ => panic!("second attach must wait on the first generation"),
        };
        let (handle, closed_rx) = test_handle_with_rx(&reg, session);
        crate::sync::lock_or_recover(&reg.inner.workers)
            .live
            .insert(
                session_id,
                WorkerEntry {
                    generation,
                    handle: handle.clone(),
                    activation_leases: 0,
                    terminal_lock_cleanup_gate: Arc::new(AsyncMutex::new(())),
                    terminal_closing: Arc::new(AtomicBool::new(false)),
                    terminal_cleanup_complete: Arc::new(AtomicBool::new(false)),
                },
            );
        let result = Ok(handle);
        reg.finish_attach_start(ticket, &result);
        wait_for_start(slot)
            .await
            .expect("Starting waiter receives the published generation");

        let claim = reg
            .claim_live_generation(session_id, generation)
            .expect("Starting waiter must lease the exact published generation");
        drop(closed_rx);
        reg.forget_generation(session_id, generation);
        assert!(matches!(
            reg.claim_attach(session_id),
            AttachClaim::Activating
        ));
        drop(claim);
        assert!(matches!(
            reg.claim_attach(session_id),
            AttachClaim::Start(_)
        ));
    }

    #[tokio::test]
    async fn start_worker_refuses_after_drain_begins() {
        let reg = test_registry();
        reg.inner.shutdown.begin_drain();
        let session = test_session(&reg);
        let providers = ProvidersConfig::default();
        let extended = ExtendedConfig::default();
        let env = EnvSnapshot::new(
            crate::env_snapshot::EnvSnapshotSource::DaemonStart,
            Default::default(),
        );
        let policy = WorkspaceTrustPolicy {
            root: crate::config::trust::TrustRoot {
                root: session.project_root.clone(),
                opened_path: session.project_root.clone(),
                kind: crate::config::trust::TrustRootKind::Directory,
            },
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let workspace_root_authority = Arc::new(
            crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority::capture(
                &session.project_root,
                &policy,
            )
            .expect("capture test workspace authority"),
        );
        let worker_publication_guard = reg.inner.worker_publication.lock().await;
        let worker_publication = WorkerPublicationPermit {
            _guard: &worker_publication_guard,
        };
        let err = match reg.start_worker(
            &worker_publication,
            Arc::try_unwrap(session)
                .ok()
                .expect("fresh test session has one owner"),
            &providers,
            &extended,
            false,
            None,
            None,
            policy,
            1,
            workspace_root_authority,
            cockpit_config::config::workspace_config_layer_snapshot_chain(Vec::new()),
            crate::config::extended::hooks::HookRegistry::default(),
            crate::daemon::config_source::ConfigWatchPaths::default(),
            env,
            1,
        ) {
            Ok(_) => panic!("start_worker should refuse after drain begins"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("shutting down"));
        assert!(reg.active_session_ids().is_empty());
    }

    #[tokio::test]
    async fn closed_worker_restart_reads_fresh_trust_after_start_claim() {
        let reg = test_registry();
        let session = persisted_test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        assert!(
            handle.is_closed(),
            "test handle intentionally has no receiver"
        );
        let join = tokio::spawn(async {});
        reg.insert_test_worker(handle, join);
        reg.inner
            .db
            .set_workspace_trust(
                reg.inner
                    .db
                    .get_session(id)
                    .await
                    .unwrap()
                    .expect("persisted session")
                    .project_root
                    .as_ref(),
                crate::db::workspace_trust::WorkspaceTrustMode::Untrusted,
            )
            .await
            .unwrap();

        let result = reg
            .attach(
                Some(id),
                None,
                None,
                false,
                None,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
                proto::SessionEntryMode::Code,
            )
            .await;
        let err = match result {
            Ok(_) => panic!("closed worker restart must observe revoked trust"),
            Err(err) => err,
        };
        assert!(
            err.downcast_ref::<crate::config::trust::WorkspaceTrustError>()
                .is_some(),
            "unexpected error: {err:#}"
        );
        assert!(reg.lookup(id).is_none());
        assert!(!crate::sync::lock_or_recover(&reg.inner.worker_joins).contains_key(&id));
    }

    #[tokio::test]
    async fn concurrent_resume_waiter_preserves_workspace_trust_error() {
        let reg = test_registry();
        let session = persisted_test_session(&reg);
        let id = session.id;
        reg.inner
            .db
            .set_workspace_trust(
                &session.project_root,
                crate::db::workspace_trust::WorkspaceTrustMode::Untrusted,
            )
            .await
            .unwrap();

        let ticket = match reg.claim_attach(id) {
            AttachClaim::Start(ticket) => ticket,
            _ => panic!("first concurrent resume must own the start"),
        };
        let slot = match reg.claim_attach(id) {
            AttachClaim::Starting(slot) => slot,
            _ => panic!("second concurrent resume must wait on the shared start"),
        };
        let worker_publication_guard = reg.inner.worker_publication.lock().await;
        let worker_publication = WorkerPublicationPermit {
            _guard: &worker_publication_guard,
        };
        let result = reg
            .start_resumed_worker(
                id,
                None,
                false,
                EnvSnapshot::new(
                    crate::env_snapshot::EnvSnapshotSource::DaemonStart,
                    Default::default(),
                ),
                ticket.generation(),
                &worker_publication,
            )
            .await;
        match &result {
            Ok(_) => panic!("winner must observe revoked trust"),
            Err(error) => assert!(error.downcast_ref::<WorkspaceTrustError>().is_some()),
        }
        reg.finish_attach_start(ticket, &result);

        let waiter_error = match wait_for_start(slot).await {
            Ok(_) => panic!("waiter must receive the failed start"),
            Err(error) => error,
        };
        assert!(
            waiter_error.downcast_ref::<WorkspaceTrustError>().is_some(),
            "waiter lost typed trust error: {waiter_error:#}"
        );
    }

    /// drain-awaits-in-flight: a worker still finishing its turn must be
    /// awaited to completion (within grace), not abandoned. The join runs to
    /// its natural end and `drain_all` reports a clean drain.
    #[tokio::test]
    async fn drain_awaits_in_flight_work() {
        let reg = test_registry();
        let finished = Arc::new(AtomicBool::new(false));

        let finished_c = finished.clone();
        let join = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            finished_c.store(true, Ordering::SeqCst);
        });
        reg.insert_test_join(Uuid::new_v4(), join);

        // Generous grace: the in-flight work finishes well inside it.
        let clean = reg
            .drain_all(Duration::from_secs(5))
            .await
            .running_work_clean;
        assert!(
            clean,
            "drain should report clean when work finishes in grace"
        );
        assert!(
            finished.load(Ordering::SeqCst),
            "in-flight work must run to completion, not be abandoned"
        );
    }

    /// force-at-deadline: a hung worker (never finishes) is force-aborted at
    /// the grace deadline and `drain_all` reports a forced (non-clean)
    /// drain, so a truncated turn isn't mistaken for a clean finish.
    #[tokio::test]
    async fn force_aborts_hung_worker_at_deadline() {
        let reg = test_registry();
        let aborted = Arc::new(AtomicBool::new(false));

        // A task that "hangs" forever, with a drop guard that records the
        // abort (dropping the task future runs the guard's `Drop`).
        struct AbortFlag(Arc<AtomicBool>);
        impl Drop for AbortFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let flag = AbortFlag(aborted.clone());
        let join = tokio::spawn(async move {
            let _flag = flag;
            std::future::pending::<()>().await;
        });
        reg.insert_test_join(Uuid::new_v4(), join);

        let start = std::time::Instant::now();
        let clean = reg
            .drain_all(Duration::from_millis(120))
            .await
            .running_work_clean;
        assert!(
            !clean,
            "a hung worker must yield a forced (non-clean) drain"
        );
        assert!(
            start.elapsed() >= Duration::from_millis(100),
            "drain should wait out the grace before forcing"
        );
        // The abort dropped the task future, running its guard.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            aborted.load(Ordering::SeqCst),
            "the hung worker must be force-aborted at the deadline"
        );
    }

    /// idle-fast-path: with no live workers, `drain_all` returns promptly and
    /// cleanly — it never sleeps the grace.
    #[tokio::test]
    async fn idle_drain_is_fast_and_clean() {
        let reg = test_registry();
        let start = std::time::Instant::now();
        let clean = reg
            .drain_all(Duration::from_secs(30))
            .await
            .running_work_clean;
        assert!(clean, "idle drain is clean");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "idle drain must not wait out the grace"
        );
    }

    // --- Interrupt park-commit gating
    // (daemon-lifecycle-replay-timing-robustness.md) ---

    use crate::engine::interrupt::ParkCommitTerminal;

    /// Criterion 2: with a registered interrupt waiter, `drain_all` must not
    /// return (so `metadata_guard.cleanup()` cannot release pid/socket) until
    /// the worker's park commits — even though its running-work join already
    /// finished. Fails against pre-fix code, which returned as soon as the join
    /// drained regardless of the un-committed park.
    #[tokio::test]
    async fn drain_park_commits_before_metadata_release() {
        let reg = test_registry();
        let session = test_session(&reg);
        let (handle, _rx) = test_handle_with_rx(&reg, session);
        let park_commit = handle.park_commit();
        park_commit.test_add_registered(); // a turn blocked on a human decision
        // Running work already drained: the join completes immediately, so only
        // the park-commit could hold the drain open.
        reg.insert_test_worker(handle, tokio::spawn(async {}));

        let reg_drain = reg.clone();
        let drain = tokio::spawn(async move { reg_drain.drain_all(Duration::from_secs(5)).await });
        // Let the drain reach its park-commit await.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !drain.is_finished(),
            "drain (→ metadata cleanup) must block until the registered park commits"
        );

        // Release: the worker reports its park committed durably.
        park_commit.report_shutdown_committed();
        let outcome = tokio::time::timeout(Duration::from_secs(2), drain)
            .await
            .expect("drain must complete once the park commits")
            .expect("drain task join");
        assert_eq!(outcome.park_commit, ParkCommitTerminal::Committed);
        assert!(outcome.is_clean());
    }

    /// Finding 2: a DELIVERED worker with no registered interrupt waiter is
    /// STILL awaited by drain — every delivered worker is an obligation, because
    /// an in-flight turn could register one during the drain window and its
    /// post-quiescence commit must gate metadata release. Non-vacuous: the drain
    /// must block until the (initially-Pending) commit lands.
    #[tokio::test]
    async fn drain_awaits_in_flight_worker_without_registered_waiter() {
        let reg = test_registry();
        let session = test_session(&reg);
        let (handle, _rx) = test_handle_with_rx(&reg, session);
        let park_commit = handle.park_commit();
        // Mid-turn, but no interrupt registered yet — the finding-2 window.
        handle.set_processing_for_test(true);
        assert!(
            !park_commit.has_registered_waiters(),
            "precondition: no waiter registered at the drain snapshot"
        );
        reg.insert_test_worker(handle, tokio::spawn(async {}));

        let reg_drain = reg.clone();
        let drain = tokio::spawn(async move { reg_drain.drain_all(Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !drain.is_finished(),
            "drain must await a processing worker's post-quiescence park-commit"
        );

        park_commit.report_shutdown_committed();
        let outcome = tokio::time::timeout(Duration::from_secs(2), drain)
            .await
            .expect("drain completes once the in-flight worker's park commits")
            .expect("drain task join");
        assert!(outcome.is_clean());
    }

    /// Criterion 4: a worker with no registered interrupt waiter owes no park,
    /// so the park-commit signal resolves `Committed` immediately — it does not
    /// wait on the (here force-aborted) running-work drain. Uses an injected
    /// short park deadline so a regressed filter (awaiting every worker) fails
    /// fast as `DeadlineUnresolved` instead of hanging.
    #[tokio::test]
    async fn drain_no_waiter_park_resolves_without_running_work_drain() {
        let reg = test_registry();
        let session = test_session(&reg);
        let (handle, _rx) = test_handle_with_rx(&reg, session);
        let park_commit = handle.park_commit();
        assert!(!park_commit.has_registered_waiters());
        // A no-waiter/idle worker's park-drain loop reports `Committed` promptly
        // (its driver exits as soon as the input closes) — independent of any
        // running-work drain. Simulate that prompt report, then leave running
        // work pending.
        park_commit.report_shutdown_committed();
        reg.insert_test_worker(handle, tokio::spawn(std::future::pending::<()>()));

        // Generous park deadline: it resolves immediately (the report is already
        // present), NOT after the running-work grace — proving the two are
        // decoupled by state, not by a wall-clock race.
        let outcome = reg
            .drain_all_inner(Duration::from_millis(50), Duration::from_secs(5))
            .await;
        assert_eq!(
            outcome.park_commit,
            ParkCommitTerminal::Committed,
            "no-waiter park resolves via its prompt report, not the running-work drain"
        );
        assert!(
            !outcome.running_work_clean,
            "running work was force-aborted at grace, independent of the park signal"
        );
    }

    /// Finding 2 (residual): a DELIVERED worker whose INITIAL park write FAILS
    /// wakes/removes its waiter and lets its driver exit, so by the time the
    /// registry samples live state NEITHER `has_registered_waiters()` NOR
    /// `processing` is observable — yet the worker durably reports `FailedWrite`.
    /// Because the obligation is established at DISPATCH (every delivered worker
    /// is awaited), that terminal is observed and the drain is NOT clean. This
    /// FAILS against the previous post-dispatch `has_registered_waiters() ||
    /// processing` filter, which would drop the obligation and spuriously report
    /// `Committed`, releasing metadata over a failed durable park.
    #[tokio::test]
    async fn drain_observes_failed_initial_park_even_after_waiter_cleared() {
        let reg = test_registry();
        let session = test_session(&reg);
        let (handle, _rx) = test_handle_with_rx(&reg, session);
        let park_commit = handle.park_commit();
        // The failed initial park has already woken/removed the waiter and the
        // driver has exited: no live waiter, not processing — but FailedWrite.
        park_commit.report_shutdown_failed_write();
        assert!(
            !park_commit.has_registered_waiters(),
            "precondition: the failed park cleared the waiter"
        );
        assert!(
            !handle.live_status().1,
            "precondition: the worker is no longer processing"
        );
        reg.insert_test_worker(handle, tokio::spawn(async {}));

        let outcome = reg
            .drain_all_inner(Duration::from_millis(50), Duration::from_millis(200))
            .await;
        assert_eq!(
            outcome.park_commit,
            ParkCommitTerminal::KnownFailedWrite,
            "a delivered worker's FailedWrite must be observed even after its waiter/processing cleared"
        );
        assert!(
            !outcome.is_clean(),
            "the metadata-release gate must see non-clean over a failed durable park"
        );
    }

    /// Criterion 5: a failed park write (`report_shutdown_failed_write`, what
    /// `park_all_registered` publishes on a real `park_interrupt` `Err`) is a
    /// non-clean terminal, yet drain still COMPLETES (does not hang) so
    /// `metadata_guard.cleanup()` runs and a successor can bind.
    #[tokio::test]
    async fn drain_park_failed_write_is_forced_not_clean() {
        let reg = test_registry();
        let session = test_session(&reg);
        let (handle, _rx) = test_handle_with_rx(&reg, session);
        let park_commit = handle.park_commit();
        park_commit.test_add_registered();
        park_commit.report_shutdown_failed_write();
        reg.insert_test_worker(handle, tokio::spawn(async {}));

        let outcome = reg
            .drain_all_inner(Duration::from_millis(50), Duration::from_secs(1))
            .await;
        assert_eq!(outcome.park_commit, ParkCommitTerminal::KnownFailedWrite);
        assert!(
            !outcome.is_clean(),
            "a known-failed write must not impersonate a clean park success"
        );
    }

    /// Criterion 5b: an unresolved park-commit takes the `DeadlineUnresolved`
    /// terminal via an injected expired (zero) deadline — no 5-second sleep,
    /// no wall-clock assertion. Non-clean, but drain still completes so cleanup
    /// runs.
    #[tokio::test]
    async fn drain_park_commit_deadline_is_forced_not_clean() {
        let reg = test_registry();
        let session = test_session(&reg);
        let (handle, _rx) = test_handle_with_rx(&reg, session);
        handle.park_commit().test_add_registered(); // owes a park; never reports
        reg.insert_test_worker(handle, tokio::spawn(async {}));

        let outcome = reg
            .drain_all_inner(Duration::from_millis(50), Duration::ZERO)
            .await;
        assert_eq!(outcome.park_commit, ParkCommitTerminal::DeadlineUnresolved);
        assert!(!outcome.is_clean());
    }

    /// The aggregate signal spans every live worker with a waiter, not just the
    /// first: two owed parks, drain resolves clean only once BOTH commit.
    #[tokio::test]
    async fn drain_park_commit_aggregates_across_workers() {
        let reg = test_registry();
        let (handle_a, _rx_a) = test_handle_with_rx(&reg, test_session(&reg));
        let (handle_b, _rx_b) = test_handle_with_rx(&reg, test_session(&reg));
        let park_a = handle_a.park_commit();
        let park_b = handle_b.park_commit();
        park_a.test_add_registered();
        park_b.test_add_registered();
        reg.insert_test_worker(handle_a, tokio::spawn(async {}));
        reg.insert_test_worker(handle_b, tokio::spawn(async {}));

        let reg_drain = reg.clone();
        let drain = tokio::spawn(async move { reg_drain.drain_all(Duration::from_secs(5)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        park_a.report_shutdown_committed();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !drain.is_finished(),
            "drain must still block on the second worker's park"
        );
        park_b.report_shutdown_committed();
        let outcome = tokio::time::timeout(Duration::from_secs(2), drain)
            .await
            .expect("drain completes once both parks commit")
            .expect("drain task join");
        assert!(outcome.is_clean());
    }

    /// Finding 1: a worker whose work queue can never receive the Shutdown
    /// (closed receiver) is treated as undelivered — force-aborted and EXCLUDED
    /// from the park obligations — so drain's pre-abort path cannot block on a
    /// park-commit the dead worker will never produce. Non-vacuous via state,
    /// not wall-clock: were the undelivered worker (which carries a registered
    /// waiter) still awaited, the park terminal would be `DeadlineUnresolved`;
    /// with finding 1 it is `Committed` (no obligations) and the drain is
    /// `running_work_clean = false` (a forced abort).
    #[tokio::test]
    async fn drain_force_aborts_worker_with_a_wedged_full_queue() {
        let reg = test_registry();
        let session = test_session(&reg);
        // Keep the receiver alive but NEVER drain it, then fill the bounded
        // queue so the drain's Shutdown send has nowhere to go — the wedged
        // case finding 1 targets (an unbounded send would block drain forever).
        let (handle, _rx) = test_handle_with_rx(&reg, session);
        loop {
            if tokio::time::timeout(
                Duration::from_millis(50),
                handle.send_work(session_worker::SessionWork::Cancel),
            )
            .await
            .is_err()
            {
                break; // queue is now full: further sends block
            }
        }
        handle.park_commit().test_add_registered(); // would owe a park if it could receive

        let aborted = Arc::new(AtomicBool::new(false));
        struct AbortFlag(Arc<AtomicBool>);
        impl Drop for AbortFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let flag = AbortFlag(aborted.clone());
        let join = tokio::spawn(async move {
            let _flag = flag;
            std::future::pending::<()>().await;
        });
        reg.insert_test_worker(handle, join);

        // Bounded: with a short injected send/park deadline the wedged send
        // times out and the worker is force-aborted instead of blocking drain.
        let reg_drain = reg.clone();
        let drain = tokio::spawn(async move {
            reg_drain
                .drain_all_inner(Duration::from_millis(50), Duration::from_millis(150))
                .await
        });
        let outcome = tokio::time::timeout(Duration::from_secs(5), drain)
            .await
            .expect("drain must stay bounded despite a wedged worker")
            .expect("drain task join");
        assert_eq!(
            outcome.park_commit,
            ParkCommitTerminal::Committed,
            "a wedged worker is excluded from park obligations, not awaited"
        );
        assert!(
            !outcome.running_work_clean,
            "force-aborting a wedged worker is not a clean drain"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            aborted.load(Ordering::SeqCst),
            "the wedged worker must be force-aborted"
        );
    }

    #[tokio::test]
    async fn drain_removes_cleanly_stopped_worker_handles() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        let join = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        reg.insert_test_worker(handle, join);

        let clean = reg
            .drain_all(Duration::from_secs(1))
            .await
            .running_work_clean;

        assert!(clean);
        assert_no_live_worker(&reg, id);
    }

    #[tokio::test]
    async fn park_on_drain_zero_grace_delivers_shutdown_to_worker_before_force() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let (handle, mut work_rx) = session_worker::SessionWorkerHandle::test_handle_with_receiver(
            session,
            reg.inner.locks.clone(),
        );
        // Simulate the real worker: on Shutdown it parks and reports Committed
        // (every delivered worker is an obligation drain now awaits).
        let park_commit = handle.park_commit();
        let join = tokio::spawn(async move {
            match work_rx.recv().await {
                Some(session_worker::SessionWork::Shutdown { pause_for_resume }) => {
                    assert!(pause_for_resume);
                    park_commit.report_shutdown_committed();
                }
                other => panic!("expected shutdown work before zero-grace force, got {other:?}"),
            }
        });
        reg.insert_test_worker(handle, join);

        let clean = reg.drain_all(Duration::ZERO).await.running_work_clean;

        assert!(
            clean,
            "a worker that parks/exits immediately must finish cleanly under --grace 0"
        );
        assert_no_live_worker(&reg, id);
    }

    #[tokio::test]
    async fn drain_removes_forced_aborted_worker_handles() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        let join = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        reg.insert_test_worker(handle, join);

        let clean = reg
            .drain_all(Duration::from_millis(20))
            .await
            .running_work_clean;

        assert!(!clean);
        assert_no_live_worker(&reg, id);
    }

    #[tokio::test]
    async fn forced_drain_records_interrupted_marker_and_event() {
        let reg = test_registry();
        let session = persisted_test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        handle.set_test_live_status(false, true, true);
        let join = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        reg.insert_test_worker(handle, join);

        let clean = reg
            .drain_all(Duration::from_millis(20))
            .await
            .running_work_clean;

        assert!(!clean);
        let summaries = reg
            .inner
            .db
            .list_session_summaries(None, None, 100)
            .await
            .unwrap();
        let summary = summaries
            .iter()
            .find(|summary| summary.session_id == id)
            .unwrap();
        assert_eq!(
            summary.activity_state,
            Some(crate::daemon::proto::SessionActivityState::Interrupted)
        );
        let events = reg.inner.db.list_session_events(id).await.unwrap();
        let interrupted = events
            .iter()
            .find(|event| event.kind == "turn_interrupted")
            .expect("turn_interrupted event");
        assert_eq!(interrupted.data["reason"], "daemon_shutdown_grace_expired");
        assert_eq!(interrupted.data["activity_state"], "tool_running");
    }

    #[tokio::test]
    async fn mixed_session_drain_clean_blocked_worker_and_forces_long_running_tool_worker() {
        let reg = test_registry();
        let blocked = test_session(&reg);
        let blocked_id = blocked.id;
        let (blocked_handle, mut blocked_rx) =
            session_worker::SessionWorkerHandle::test_handle_with_receiver(
                blocked,
                reg.inner.locks.clone(),
            );
        // The blocked worker parks and reports Committed on Shutdown (a delivered
        // worker drain now awaits); the long-running worker below is closed
        // (WorkerGone) and force-aborted at grace.
        let blocked_park_commit = blocked_handle.park_commit();
        let blocked_join = tokio::spawn(async move {
            match blocked_rx.recv().await {
                Some(session_worker::SessionWork::Shutdown { pause_for_resume }) => {
                    assert!(pause_for_resume);
                    blocked_park_commit.report_shutdown_committed();
                }
                other => panic!("expected blocked worker shutdown, got {other:?}"),
            }
        });
        reg.insert_test_worker(blocked_handle, blocked_join);

        let long_running = persisted_test_session(&reg);
        let long_running_id = long_running.id;
        let long_running_handle = test_handle(&reg, long_running);
        long_running_handle.set_test_live_status(false, true, true);
        let killed = Arc::new(AtomicBool::new(false));
        struct KillFlag(Arc<AtomicBool>);
        impl Drop for KillFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let kill_flag = KillFlag(killed.clone());
        let long_running_join = tokio::spawn(async move {
            let _kill_flag = kill_flag;
            std::future::pending::<()>().await;
        });
        reg.insert_test_worker(long_running_handle, long_running_join);

        let clean = reg
            .drain_all(Duration::from_millis(20))
            .await
            .running_work_clean;

        assert!(!clean, "long-running tool worker should exhaust grace");
        assert_no_live_worker(&reg, blocked_id);
        assert_no_live_worker(&reg, long_running_id);
        tokio::task::yield_now().await;
        assert!(
            killed.load(Ordering::SeqCst),
            "forced drain must abort the long-running worker task"
        );
        let events = reg
            .inner
            .db
            .list_session_events(long_running_id)
            .await
            .unwrap();
        let interrupted = events
            .iter()
            .find(|event| event.kind == "turn_interrupted")
            .expect("long-running worker interrupted event");
        assert_eq!(interrupted.data["reason"], "daemon_shutdown_grace_expired");
        assert_eq!(interrupted.data["activity_state"], "tool_running");
    }

    #[tokio::test]
    async fn forced_drain_does_not_record_interrupted_marker_for_schedule_only_worker() {
        let reg = test_registry();
        let session = persisted_test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        handle.set_test_live_status(true, false, false);
        let join = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        reg.insert_test_worker(handle, join);

        let clean = reg
            .drain_all(Duration::from_millis(20))
            .await
            .running_work_clean;

        assert!(!clean);
        let summaries = reg
            .inner
            .db
            .list_session_summaries(None, None, 100)
            .await
            .unwrap();
        let summary = summaries
            .iter()
            .find(|summary| summary.session_id == id)
            .unwrap();
        assert_eq!(summary.activity_state, None);
        let events = reg.inner.db.list_session_events(id).await.unwrap();
        assert!(events.iter().all(|event| event.kind != "turn_interrupted"));
    }

    #[tokio::test]
    async fn drain_removes_handle_when_shutdown_send_fails() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        let join = tokio::spawn(async {});
        reg.insert_test_worker(handle, join);

        let clean = reg
            .drain_all(Duration::from_secs(1))
            .await
            .running_work_clean;

        assert!(clean);
        assert_no_live_worker(&reg, id);
    }

    #[tokio::test]
    async fn interrupt_and_stop_waits_for_worker_exit_then_forgets() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        let finished = Arc::new(AtomicBool::new(false));
        let finished_c = finished.clone();
        let join = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            finished_c.store(true, Ordering::SeqCst);
        });
        reg.insert_test_worker(handle, join);

        let stopped = reg
            .interrupt_and_stop_with_timeout(id, Duration::from_secs(1))
            .await
            .unwrap();

        assert!(stopped);
        assert!(finished.load(Ordering::SeqCst));
        assert!(reg.lookup(id).is_none());
        assert!(!crate::sync::lock_or_recover(&reg.inner.worker_joins).contains_key(&id));
    }

    #[tokio::test]
    async fn interrupt_and_stop_missing_join_fails_closed_while_channel_open() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let (handle, _rx) = session_worker::SessionWorkerHandle::test_handle_with_receiver(
            session,
            reg.inner.locks.clone(),
        );
        reg.insert_test_worker_without_join(handle);

        let err = reg
            .interrupt_and_stop_with_timeout(id, Duration::from_millis(20))
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("missing its worker join"), "{err}");
        assert!(err.contains("retry"), "{err}");
        assert!(reg.lookup(id).is_some());
    }

    #[tokio::test]
    async fn interrupt_and_stop_missing_join_succeeds_after_channel_closed() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let (handle, rx) = session_worker::SessionWorkerHandle::test_handle_with_receiver(
            session,
            reg.inner.locks.clone(),
        );
        reg.insert_test_worker_without_join(handle);
        drop(rx);

        let stopped = reg
            .interrupt_and_stop_with_timeout(id, Duration::from_secs(1))
            .await
            .unwrap();

        assert!(stopped);
        assert!(reg.lookup(id).is_none());
    }

    #[tokio::test]
    async fn interrupt_and_stop_timeout_keeps_live_worker_registered() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        let join = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        reg.insert_test_worker(handle, join);

        let err = reg
            .interrupt_and_stop_with_timeout(id, Duration::from_millis(20))
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("refusing destructive session mutation")
        );
        assert!(reg.lookup(id).is_some());
        assert!(crate::sync::lock_or_recover(&reg.inner.worker_joins).contains_key(&id));
    }

    #[tokio::test]
    async fn interrupt_and_stop_is_idempotent_after_success() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        let join = tokio::spawn(async {});
        reg.insert_test_worker(handle, join);

        assert!(
            reg.interrupt_and_stop_with_timeout(id, Duration::from_secs(1))
                .await
                .unwrap()
        );
        assert!(
            !reg.interrupt_and_stop_with_timeout(id, Duration::from_secs(1))
                .await
                .unwrap()
        );
    }

    #[test]
    fn poisoned_worker_mutex_is_recovered_on_hot_path_reads() {
        let reg = test_registry();
        let poisoned = reg.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = poisoned.inner.workers.lock().unwrap();
            panic!("poison workers mutex");
        }));

        assert!(reg.active_session_ids().is_empty());
        assert!(!reg.any_agent_running());
        assert_eq!(reg.live_status(Uuid::new_v4()), None);
    }

    #[tokio::test]
    async fn reattach_resume_reacquires_unchanged_only() {
        let db = Db::open_in_memory().expect("db");
        let sid = db
            .create_session("p", "/x", "builder")
            .await
            .expect("session")
            .session_id;
        let locks = Arc::new(LockManager::in_memory(db.clone()));
        let vault = crate::secure_key::vault_for_db(&db).expect("test vault");
        let reg = SessionRegistry::new(
            db,
            locks.clone(),
            ShutdownSignal::new(),
            None,
            crate::daemon::config_source::ConfigSource::fixed(
                ProvidersConfig::default(),
                ExtendedConfig::default(),
            ),
        );
        reg.set_redaction_key_resolver(crate::session::test_redaction_key_resolver());
        reg.set_secret_vault(vault);

        let tmp = tempfile::TempDir::new().unwrap();
        let keep = tmp.path().join("keep.rs");
        let drift = tmp.path().join("drift.rs");
        std::fs::write(&keep, "v1").unwrap();
        std::fs::write(&drift, "v1").unwrap();
        locks.acquire(&keep, "builder", sid).await.unwrap();
        locks.acquire(&drift, "builder", sid).await.unwrap();

        // Last detach while idle → session-scoped release.
        let released = locks.suspend_session(sid).await.unwrap();
        assert_eq!(released.len(), 2);
        assert!(locks.holder(&keep).is_none());
        assert!(locks.holder(&drift).is_none());

        // One file drifts while detached.
        std::fs::write(&drift, "v2").unwrap();

        // Reattach → only the unchanged file is reacquired.
        locks.resume_session(sid).await.unwrap();
        assert_eq!(
            locks.holder(&keep),
            Some((sid, "builder".to_string())),
            "unchanged file reacquired on reattach"
        );
        assert!(
            locks.holder(&drift).is_none(),
            "drifted file is not reacquired"
        );

        // A second concurrent reattach finds no snapshot → reacquires nothing
        // new (multi-attach triggers no extra release/reacquire).
        locks.resume_session(sid).await.unwrap();
        assert_eq!(locks.holder(&keep), Some((sid, "builder".to_string())));
    }

    // ---- Command-backed secret daemon wiring (inc 2) ---------------------

    /// Counting executor: records every invocation and returns a canned token,
    /// so exec-count assertions can distinguish a sync exec from a cache hit.
    struct CountingOkExecutor {
        value: String,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingOkExecutor {
        fn new(value: &str) -> Arc<Self> {
            Arc::new(Self {
                value: value.to_string(),
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl crate::secret_command::CommandSecretExecutor for CountingOkExecutor {
        async fn run(
            &self,
            _argv: &[String],
        ) -> std::result::Result<String, crate::secret_command::CommandSecretError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.value.clone())
        }
    }

    fn command_secret_config_source() -> crate::daemon::config_source::ConfigSource {
        crate::daemon::config_source::ConfigSource::fixed(
            ProvidersConfig::default(),
            ExtendedConfig::default(),
        )
    }

    /// A registry whose vault holds a single command-backed spec and whose
    /// command cache is the supplied counting cache.
    fn registry_with_command_secret(
        name: &str,
        argv: Vec<String>,
        cache: Arc<crate::secret_command::CommandSecretCache>,
    ) -> SessionRegistry {
        let db = Db::open_in_memory().expect("in-memory db");
        let locks = Arc::new(LockManager::in_memory(db.clone()));
        let vault = crate::secure_key::vault_for_db(&db).expect("test vault");
        let mut store = crate::credentials::CredentialStore::from_vault(vault.clone()).unwrap();
        store.set_named_secret_command(name, argv).unwrap();
        store.save().unwrap();
        let reg = SessionRegistry::new(
            db,
            locks,
            ShutdownSignal::new(),
            None,
            command_secret_config_source(),
        );
        reg.set_redaction_key_resolver(crate::session::test_redaction_key_resolver());
        reg.set_secret_vault(vault);
        reg.set_command_secret_cache(cache);
        reg
    }

    fn providers_referencing_secret(name: &str) -> ProvidersConfig {
        use crate::config::providers::{HeaderSpec, ModelEntry, ProviderEntry};
        use std::collections::BTreeMap;

        let mut providers = BTreeMap::new();
        providers.insert(
            "lmstudio".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".to_string(),
                models: vec![ModelEntry {
                    id: "parent-model".to_string(),
                    ..ModelEntry::default()
                }],
                headers: vec![HeaderSpec {
                    name: "Authorization".to_string(),
                    value: format!("Bearer $secret:{name}"),
                }],
                ..ProviderEntry::default()
            },
        );
        ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".to_string(),
                model: "parent-model".to_string(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        }
    }

    fn daemon_start_env() -> EnvSnapshot {
        EnvSnapshot::new(
            crate::env_snapshot::EnvSnapshotSource::DaemonStart,
            Default::default(),
        )
    }

    /// Claim `(provider, project_root)` ownership of a named secret so the
    /// owner-scoped resolution/injection view resolves it. Mirrors the ownership
    /// row a provider save (or the inc4 command-spec RPC) would insert.
    fn claim_provider_ownership(db: &Db, item_id: &str, project_root: &std::path::Path) {
        let root =
            crate::secret_ownership::canonical_owner_root(&project_root.display().to_string());
        let item_id = item_id.to_string();
        db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute(
                "INSERT INTO secret_named_ownership (item_id, owner_kind, project_root, created_at)
                 VALUES (?1, 'provider', ?2, 0)",
                rusqlite::params![item_id, root],
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn root_string(session: &Session) -> String {
        session.project_root.display().to_string()
    }

    /// AC7: the resolved command output joins the per-session redaction table,
    /// while the argv spec never does. Drives the SAME sync build `start_worker`
    /// runs (`session.credential_store()` funnel + `build_with_env_and_credential_store`).
    #[tokio::test]
    async fn command_secret_output_joins_redaction_table_but_spec_does_not() {
        let token = "cmd-resolved-secret-token-abcdef0123456789";
        let program = "resolve-github-token-fetcher-program-longname";
        let cache = crate::secret_command::CommandSecretCache::new(CountingOkExecutor::new(token));
        let reg = registry_with_command_secret(
            "ghcmd",
            vec![program.to_string(), "auth".to_string(), "token".to_string()],
            cache.clone(),
        );
        let session = test_session(&reg);
        claim_provider_ownership(&reg.inner.db, "ghcmd", &session.project_root);

        // Async owner-scoped pre-resolution, then install the cache on the
        // session exactly as `start_worker` does before building any store.
        let providers = providers_referencing_secret("ghcmd");
        reg.preresolve_session_command_secrets(&session, &providers)
            .await;
        assert_eq!(cache.exec_count(), 1);
        session.set_command_secret_cache(Some(reg.command_secret_cache()));

        let table = RedactionTable::build_with_env_and_credential_store(
            &ExtendedConfig::default().redact,
            &session.project_root,
            daemon_start_env().vars(),
            &session.credential_store().unwrap(),
        )
        .unwrap();

        assert_ne!(
            table.scrub(token),
            token,
            "the resolved command output must join the redaction table"
        );
        // The argv spec (a long, otherwise-redactable string) is never a
        // redaction candidate: it lives only in command_specs, never in secrets.
        assert_eq!(
            table.scrub(program),
            program,
            "the argv program must never be redacted"
        );
        // Building the table consulted the cache and never re-execed.
        assert_eq!(cache.exec_count(), 1);
    }

    /// AC6: async pre-resolution must precede the sync redaction AND model
    /// build. Before resolve the owner-scoped model store and the redaction
    /// table see nothing and no exec happens; after resolve both see the cached
    /// value, and constructing the real `Model` never triggers a sync exec.
    #[tokio::test]
    async fn async_resolve_precedes_redaction_and_model_build() {
        let token = "ordering-probe-resolved-token-abcdef0123456789";
        let cache = crate::secret_command::CommandSecretCache::new(CountingOkExecutor::new(token));
        let reg = registry_with_command_secret("ordercmd", vec!["prog".to_string()], cache.clone());
        let session = test_session(&reg);
        claim_provider_ownership(&reg.inner.db, "ordercmd", &session.project_root);
        session.set_command_secret_cache(Some(reg.command_secret_cache()));
        let providers = providers_referencing_secret("ordercmd");

        // BEFORE pre-resolution: the owner-scoped model store and the redaction
        // table observe nothing (the sync lookup never execs), and no exec ran —
        // the hazard the ordering guards against (build-before-resolve).
        assert_eq!(
            session
                .provider_credential_store(&providers)
                .unwrap()
                .named_secret("ordercmd"),
            None,
            "the model store must not see the value before pre-resolution"
        );
        let early = RedactionTable::build_with_env_and_credential_store(
            &ExtendedConfig::default().redact,
            &session.project_root,
            daemon_start_env().vars(),
            &session.credential_store().unwrap(),
        )
        .unwrap();
        assert_eq!(early.scrub(token), token, "no value before pre-resolution");
        // Also construct the REAL model before pre-resolution: the sync model
        // build consults the store's execution-free `named_secret`, so it must
        // NOT exec even when the secret is unresolved (whether the build
        // succeeds or fails-closed on the missing header, exec_count stays 0).
        let _ = resolve_session_worker_model(
            &providers,
            &ExtendedConfig::default(),
            &session,
            Arc::new(early),
            &daemon_start_env(),
            None,
            &reg.inner.shutdown,
        );
        assert_eq!(
            cache.exec_count(),
            0,
            "the sync redaction/model build must never trigger an exec"
        );

        // Real async pre-resolution (the path the session-create callers run).
        reg.preresolve_session_command_secrets(&session, &providers)
            .await;
        assert_eq!(
            cache.exec_count(),
            1,
            "async pre-resolve execs exactly once"
        );

        // AFTER pre-resolution: the owner-scoped model store now expands the ref,
        // the redaction table redacts the value, and building the REAL model
        // consumes the injected store without any further exec.
        assert_eq!(
            session
                .provider_credential_store(&providers)
                .unwrap()
                .named_secret("ordercmd"),
            Some(token),
            "the model store must expand the ref to the cached value"
        );
        let late = RedactionTable::build_with_env_and_credential_store(
            &ExtendedConfig::default().redact,
            &session.project_root,
            daemon_start_env().vars(),
            &session.credential_store().unwrap(),
        )
        .unwrap();
        assert_ne!(late.scrub(token), token, "resolve-before-build injects it");
        let model = resolve_session_worker_model(
            &providers,
            &ExtendedConfig::default(),
            &session,
            Arc::new(late),
            &daemon_start_env(),
            None,
            &reg.inner.shutdown,
        )
        .expect("model build");
        assert_eq!(model.model_id_ref(), "parent-model");
        assert_eq!(
            cache.exec_count(),
            1,
            "redaction + model construction consulted the cache; never a sync exec"
        );
    }

    /// AC4: a provider update that references the command secret re-execs
    /// exactly once more; an update whose reference set does not include it
    /// execs zero times. Exercises the owner-scoped `resolve_provider_command_secrets`
    /// the SaveProviderConfig arm invokes.
    #[tokio::test]
    async fn provider_update_invalidation_reexecutes_once() {
        let cache = crate::secret_command::CommandSecretCache::new(CountingOkExecutor::new(
            "provider-update-token-abcdef0123456789",
        ));
        let reg = registry_with_command_secret("cmd", vec!["prog".to_string()], cache.clone());
        let session = test_session(&reg);
        claim_provider_ownership(&reg.inner.db, "cmd", &session.project_root);
        let root = root_string(&session);

        let referencing: std::collections::BTreeSet<String> =
            ["cmd".to_string()].into_iter().collect();
        let unreferenced: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        // Initial resolution (as at boot / session start).
        reg.resolve_provider_command_secrets(&root, &referencing, false)
            .await;
        assert_eq!(cache.exec_count(), 1);

        // Saving a provider that references the command secret: exactly once more.
        reg.resolve_provider_command_secrets(&root, &referencing, true)
            .await;
        assert_eq!(
            cache.exec_count(),
            2,
            "a referencing provider update must re-exec exactly once more"
        );

        // Saving an unreferenced provider (empty scoped set): zero execs.
        reg.resolve_provider_command_secrets(&root, &unreferenced, true)
            .await;
        assert_eq!(
            cache.exec_count(),
            2,
            "an unreferenced provider update must not re-exec the command secret"
        );
    }

    /// HIGH #3b: a config referencing a command name owned by a DIFFERENT
    /// workspace must NOT execute it — the owner-scoped view drops the foreign
    /// name so pre-resolution never reads its argv.
    #[tokio::test]
    async fn foreign_owned_command_secret_is_not_execed() {
        let cache = crate::secret_command::CommandSecretCache::new(CountingOkExecutor::new(
            "foreign-token-should-never-be-produced",
        ));
        let reg =
            registry_with_command_secret("foreigncmd", vec!["prog".to_string()], cache.clone());
        let session = test_session(&reg);
        // Ownership belongs to a DIFFERENT workspace root, not this session's.
        claim_provider_ownership(
            &reg.inner.db,
            "foreigncmd",
            std::path::Path::new("/some/other/workspace"),
        );
        session.set_command_secret_cache(Some(reg.command_secret_cache()));
        let providers = providers_referencing_secret("foreigncmd");

        reg.preresolve_session_command_secrets(&session, &providers)
            .await;
        assert_eq!(
            cache.exec_count(),
            0,
            "a foreign-owned command name must never be executed"
        );
        assert_eq!(
            session
                .provider_credential_store(&providers)
                .unwrap()
                .named_secret("foreigncmd"),
            None,
            "a foreign-owned command name must never be injected/expanded"
        );
    }
}
