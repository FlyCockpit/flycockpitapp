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
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::json;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::ProvidersConfig;
use crate::config::trust::WorkspaceTrustPolicy;
use crate::daemon::EventSender;
use crate::daemon::session_worker::{self, SessionWorkerHandle};
use crate::daemon::shutdown::ShutdownSignal;
use crate::db::Db;
use crate::engine::model::Model;
use crate::env_snapshot::EnvSnapshot;
use crate::locks::LockManager;
use crate::redact::RedactionTable;
use crate::session::Session;

#[cfg(not(test))]
pub const DESTRUCTIVE_STOP_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub const DESTRUCTIVE_STOP_TIMEOUT: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const START_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const START_WAIT_TIMEOUT: Duration = Duration::from_millis(50);

type WorkerGeneration = u64;

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
    workers: Mutex<WorkerState>,
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
}

struct WorkerState {
    live: HashMap<Uuid, WorkerEntry>,
    starting: HashMap<Uuid, Arc<StartSlot>>,
    next_generation: WorkerGeneration,
}

struct WorkerEntry {
    generation: WorkerGeneration,
    handle: SessionWorkerHandle,
}

struct WorkerJoin {
    generation: WorkerGeneration,
    join: JoinHandle<()>,
}

struct StartSlot {
    generation: WorkerGeneration,
    result: Mutex<Option<std::result::Result<SessionWorkerHandle, String>>>,
    ready: watch::Sender<()>,
}

impl StartSlot {
    fn finish(&self, result: std::result::Result<SessionWorkerHandle, String>) {
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
            Err(e) => Err(e.to_string()),
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
        self.slot.finish(Err(format!(
            "session worker {} start abandoned before completion",
            self.session_id
        )));
    }
}

enum AttachClaim {
    Live(SessionWorkerHandle),
    Starting(Arc<StartSlot>),
    Start(StartTicket),
}

async fn wait_for_start(slot: Arc<StartSlot>) -> Result<SessionWorkerHandle> {
    let mut ready = slot.ready.subscribe();
    loop {
        if let Some(result) = crate::sync::lock_or_recover(&slot.result).clone() {
            return result.clone().map_err(anyhow::Error::msg);
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
    {
        let mut workers = crate::sync::lock_or_recover(&inner.workers);
        if workers
            .live
            .get(&session_id)
            .is_some_and(|entry| entry.generation == generation)
        {
            workers.live.remove(&session_id);
        }
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
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                locks,
                lsp: Arc::new(crate::daemon::lsp::LspManager::new()),
                resource_scheduler,
                workers: Mutex::new(WorkerState {
                    live: HashMap::new(),
                    starting: HashMap::new(),
                    next_generation: 0,
                }),
                worker_joins: Mutex::new(HashMap::new()),
                shutdown,
                global_bus: Mutex::new(None),
            }),
        }
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

    /// Spawn (or look up) the worker for a session. The caller
    /// supplies the resolved provider + extended configs so the
    /// registry can build the model and redaction table without
    /// re-walking the layered config every attach. (Wiring the
    /// resolver inside the daemon lands with the daemon-side `/config`
    /// payload.)
    #[allow(clippy::too_many_arguments)]
    pub async fn attach(
        &self,
        session_id: Option<Uuid>,
        project_root: Option<PathBuf>,
        providers_cfg: &ProvidersConfig,
        extended_cfg: &ExtendedConfig,
        client_no_sandbox: bool,
        model_override: Option<&str>,
        trust_policy: WorkspaceTrustPolicy,
        env_snapshot: EnvSnapshot,
    ) -> Result<SessionWorkerHandle> {
        // Resume path.
        if let Some(id) = session_id {
            match self.claim_attach(id) {
                AttachClaim::Live(handle) => {
                    // Reattach to a still-alive worker (the worker outlives client
                    // disconnects, GOALS §8b). Re-acquire any locks released when
                    // the last client detached while idle
                    // (implementation note). A no-op when no
                    // release snapshot exists — so a second concurrent attach to an
                    // already-attached session triggers nothing.
                    self.resume_session_locks(id);
                    return Ok(handle);
                }
                AttachClaim::Starting(slot) => {
                    let handle = wait_for_start(slot)
                        .await
                        .context("waiting for session worker start")?;
                    self.resume_session_locks(id);
                    return Ok(handle);
                }
                AttachClaim::Start(ticket) => {
                    let generation = ticket.generation();
                    let result = self.start_resumed_worker(
                        id,
                        providers_cfg,
                        extended_cfg,
                        client_no_sandbox,
                        trust_policy,
                        env_snapshot,
                        generation,
                    );
                    self.finish_attach_start(ticket, &result);
                    let handle = result?;
                    self.resume_session_locks(id);
                    return Ok(handle);
                }
            }
        }

        // Create path.
        let Some(project_root) = project_root else {
            bail!("attach requires either session_id or project_root");
        };
        // Lazy persistence (session-id-display-and-lazy-persist): hold the
        // new session in memory with its id assigned but its `sessions` row
        // un-written. The worker persists it on the first user message.
        let session = Session::create_deferred(
            self.inner.db.clone(),
            project_root,
            session_worker::initial_active_agent(extended_cfg),
        )
        .context("creating session")?;
        if let Some(active) = &providers_cfg.active_model {
            session
                .set_active_model(&active.provider, &active.model)
                .context("setting active model on new session")?;
        }
        let generation = {
            let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
            next_generation(&mut workers)
        };
        self.start_worker(
            session,
            providers_cfg,
            extended_cfg,
            client_no_sandbox,
            model_override,
            trust_policy,
            env_snapshot,
            generation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_resumed_worker(
        &self,
        id: Uuid,
        providers_cfg: &ProvidersConfig,
        extended_cfg: &ExtendedConfig,
        client_no_sandbox: bool,
        trust_policy: WorkspaceTrustPolicy,
        env_snapshot: EnvSnapshot,
        generation: WorkerGeneration,
    ) -> Result<SessionWorkerHandle> {
        let session = Session::resume(self.inner.db.clone(), id)
            .context("resuming session")?
            .ok_or_else(|| anyhow::anyhow!("unknown session {id}"))?;
        // Resume keeps the running worker's model; an override only seeds
        // a newly-created session (matched by the server's gating). Plan
        // attribution is likewise create-only.
        self.start_worker(
            session,
            providers_cfg,
            extended_cfg,
            client_no_sandbox,
            None,
            trust_policy,
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

    fn claim_attach(&self, session_id: Uuid) -> AttachClaim {
        let mut state = crate::sync::lock_or_recover(&self.inner.workers);
        if let Some(entry) = state.live.get(&session_id) {
            if entry.handle.is_closed() {
                let generation = entry.generation;
                state.live.remove(&session_id);
                let mut joins = crate::sync::lock_or_recover(&self.inner.worker_joins);
                if joins
                    .get(&session_id)
                    .is_some_and(|join| join.generation == generation)
                {
                    joins.remove(&session_id);
                }
            } else {
                return AttachClaim::Live(entry.handle.clone());
            }
        }
        if let Some(entry) = state.live.get(&session_id) {
            return AttachClaim::Live(entry.handle.clone());
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

    /// Re-acquire any locks released when this session's last client detached
    /// while idle (implementation note). A no-op when the
    /// session has no release snapshot (a fresh session, or a still-attached
    /// one a second client is joining), since `resume_session` consumes the
    /// snapshot the detach edge left. Best-effort: a failed reacquire is logged
    /// — the agent must `readlock` again, never a crash on attach.
    fn resume_session_locks(&self, session_id: Uuid) {
        let locks = self.inner.locks.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                match tokio::task::spawn_blocking(move || locks.resume_session(session_id)).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(
                            error = %e,
                            %session_id,
                            "re-acquiring session locks on reattach failed"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            %session_id,
                            "reattach lock resume blocking task failed"
                        );
                    }
                }
            });
        } else {
            std::thread::spawn(move || {
                if let Err(e) = locks.resume_session(session_id) {
                    tracing::warn!(
                        error = %e,
                        %session_id,
                        "re-acquiring session locks on reattach failed"
                    );
                }
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn start_worker(
        &self,
        session: Session,
        providers_cfg: &ProvidersConfig,
        extended_cfg: &ExtendedConfig,
        client_no_sandbox: bool,
        model_override: Option<&str>,
        trust_policy: WorkspaceTrustPolicy,
        env_snapshot: EnvSnapshot,
        generation: WorkerGeneration,
    ) -> Result<SessionWorkerHandle> {
        if self.inner.shutdown.is_draining() {
            bail!("daemon is shutting down; not starting session workers");
        }
        let session_id = session.id;
        let project_root = session.project_root.clone();

        session.set_trusted_only(extended_cfg.trusted_only);
        session.set_sandbox_escalation_enabled(extended_cfg.sandbox_escalation_enabled);

        // Build per-session redaction table from the immutable session env.
        let redact = RedactionTable::build_with_env(
            &extended_cfg.redact,
            &project_root,
            env_snapshot.vars(),
        )
        .context("building redaction table")?;
        let redact = Arc::new(redact);

        // Build the model from providers config. Errors out loud if
        // no provider is configured for the session's active model. Install
        // the daemon's shared shutdown gate so this worker's inference
        // dispatch refuses new provider requests once a drain begins
        // (`daemon-graceful-drain-shutdown.md`).
        // Config file path for the session's project, used to self-heal the
        // wire-API endpoint (implementation note):
        // write to the most-specific layer that defines the active provider,
        // matching the runtime config write-target rule. `None` when nothing
        // is discoverable (the fallback still works, it just isn't persisted).
        let config_path = providers_cfg.active_model.as_ref().and_then(|active| {
            crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
                crate::config::dirs::config_write_target_for_provider(
                    &project_root,
                    &active.provider,
                )
            })
        });
        let model = {
            let env_lookup = |name: &str| env_snapshot.vars().get(name).cloned();
            let m = Model::from_config_with_env_trusted_only(
                providers_cfg,
                redact.clone(),
                session.trusted_only_flag(),
                env_lookup,
            )
            .context("resolving model")?
            .with_shutdown_gate(self.inner.shutdown.clone());
            let m = match config_path.clone() {
                Some(path) => m.with_config_path(path),
                None => m,
            };
            Arc::new(m)
        };

        // Resolve the active model's extra-request-body fragment from rich
        // reasoning-effort capabilities first, falling back to legacy
        // thinking modes (implementation note). Threaded
        // onto the root spawn's `ModelParams` so every outbound request on the
        // session model carries the vendor reasoning controls.
        let thinking_params = providers_cfg.resolve_active_model_reasoning_params();

        // Plan-level model override (`cockpit run --model`): a well-formed
        // `provider/model` selector built through the same provider pipeline as
        // the session model, with the same shutdown gate. A malformed selector
        // or unconfigured provider degrades to no override rather than failing
        // the attach — the executor already validated `--model` up front.
        let model_override = model_override
            .and_then(crate::config::provider::split_provider_model)
            .and_then(|(provider, model_id)| {
                let env_lookup = |name: &str| env_snapshot.vars().get(name).cloned();
                Model::for_provider_with_env_trusted_only(
                    providers_cfg,
                    &provider,
                    &model_id,
                    redact.clone(),
                    session.trusted_only_flag(),
                    env_lookup,
                )
                .ok()
            })
            .map(|m| {
                let m = m.with_shutdown_gate(self.inner.shutdown.clone());
                let m = match config_path.clone() {
                    Some(path) => m.with_config_path(path),
                    None => m,
                };
                Arc::new(m)
            });

        let session = Arc::new(session);
        let cleanup_inner = Arc::downgrade(&self.inner);
        let cleanup =
            Box::new(move || cleanup_worker_on_exit(cleanup_inner, session_id, generation));
        let (handle, join) = session_worker::spawn(
            session,
            self.inner.locks.clone(),
            redact,
            model,
            model_override,
            thinking_params,
            project_root,
            client_no_sandbox,
            extended_cfg,
            self.inner.lsp.clone(),
            self.inner.resource_scheduler.clone(),
            crate::sync::lock_or_recover(&self.inner.global_bus).clone(),
            trust_policy,
            Some(cleanup),
            env_snapshot,
        );

        crate::sync::lock_or_recover(&self.inner.workers)
            .live
            .insert(
                session_id,
                WorkerEntry {
                    generation,
                    handle: handle.clone(),
                },
            );
        crate::sync::lock_or_recover(&self.inner.worker_joins)
            .insert(session_id, WorkerJoin { generation, join });

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
    /// Returns `true` when every worker drained cleanly within `grace`, and
    /// `false` when the deadline forced an abort — the caller surfaces the
    /// "shutdown was forced" note from that.
    pub async fn drain_all(&self, grace: Duration) -> bool {
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

        // Ask each worker to stop: closes its driver input so the current
        // turn (if any) drains, then the worker task ends.
        for h in &handles {
            let _ = h
                .send_work(crate::daemon::session_worker::SessionWork::Shutdown {
                    pause_for_resume: true,
                })
                .await;
        }
        if grace.is_zero() {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Await all worker tasks concurrently, racing the shared grace
        // deadline. We wait for ALL to finish (or the deadline), never just
        // the first — `join_all` resolves only when every future has. The
        // `abort_handle`s let the deadline arm force-abort whatever's left.
        let abort_handles: Vec<tokio::task::AbortHandle> = joins
            .iter()
            .map(|(_, entry)| entry.join.abort_handle())
            .collect();
        let drain = futures::future::join_all(joins.into_iter().map(|(_, entry)| entry.join));

        let clean = match tokio::time::timeout(grace, drain).await {
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
                        );
                    }
                }
                for ah in &abort_handles {
                    ah.abort();
                }
                false
            }
        };
        self.forget_generations(drained_generations);
        clean
    }

    fn record_forced_drain_interruption(
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
        match self.inner.db.raise_interrupted_turn(
            handle.session_id,
            &handle.active_agent_name,
            "Daemon shutdown interrupted active work",
        ) {
            Ok(interrupt_id) => {
                if let Err(error) = self.inner.db.insert_session_event(
                    handle.session_id,
                    crate::db::session_log::SessionEventKind::TurnInterrupted,
                    Some(&handle.active_agent_name),
                    None,
                    &json!({
                        "reason": "daemon_shutdown_grace_expired",
                        "interrupt_id": interrupt_id.to_string(),
                        "grace_ms": grace_ms,
                        "activity_state": activity_state,
                        "has_active_schedules": has_active_schedules,
                        "processing": processing,
                        "tool_running": tool_running,
                    }),
                ) {
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

    /// The single daemon-wide lock manager. Exposed so the daemon's
    /// periodic lock sweeper (`readlock-wait-and-lock-expiry.md`) can call
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

    /// Current live worker handle for an already-running session. Unlike
    /// [`Self::attach`], this never starts or resumes a worker; side-channel
    /// requests use it to avoid creating work for dead sessions.
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

    async fn interrupt_and_stop_with_timeout(
        &self,
        session_id: Uuid,
        timeout: Duration,
    ) -> Result<bool> {
        let Some((generation, handle)) = self.lookup_entry(session_id) else {
            return Ok(false);
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
            let _ = handle
                .send_work(crate::daemon::session_worker::SessionWork::Cancel)
                .await;
            let _ = handle
                .send_work(crate::daemon::session_worker::SessionWork::Shutdown {
                    pause_for_resume: false,
                })
                .await;
            return self
                .wait_for_missing_join_shutdown(session_id, generation, &handle, timeout)
                .await;
        };

        let _ = handle
            .send_work(crate::daemon::session_worker::SessionWork::Cancel)
            .await;
        let _ = handle
            .send_work(crate::daemon::session_worker::SessionWork::Shutdown {
                pause_for_resume: false,
            })
            .await;

        match tokio::time::timeout(timeout, &mut join).await {
            Ok(join_result) => {
                self.forget_generation(session_id, generation);
                if let Err(e) = join_result {
                    tracing::warn!(%session_id, error = %e, "session worker stopped with join error");
                }
                Ok(true)
            }
            Err(_) => {
                let mut joins = crate::sync::lock_or_recover(&self.inner.worker_joins);
                if crate::sync::lock_or_recover(&self.inner.workers)
                    .live
                    .get(&session_id)
                    .is_some_and(|entry| entry.generation == generation)
                {
                    joins.insert(session_id, WorkerJoin { generation, join });
                }
                bail!(
                    "session {session_id} did not stop within {}ms; refusing destructive session mutation",
                    timeout.as_millis()
                )
            }
        }
    }

    async fn wait_for_missing_join_shutdown(
        &self,
        session_id: Uuid,
        generation: WorkerGeneration,
        handle: &SessionWorkerHandle,
        timeout: Duration,
    ) -> Result<bool> {
        match tokio::time::timeout(timeout, async {
            while !handle.is_closed() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        {
            Ok(()) => {
                self.forget_generation(session_id, generation);
                Ok(true)
            }
            Err(_) => bail!(
                "session {session_id} stop state is missing its worker join and the worker channel stayed open for {}ms; retry destructive session mutation later",
                timeout.as_millis()
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
        crate::sync::lock_or_recover(&self.inner.worker_joins)
            .insert(id, WorkerJoin { generation, join });
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
            workers.live.insert(id, WorkerEntry { generation, handle });
            generation
        };
        crate::sync::lock_or_recover(&self.inner.worker_joins)
            .insert(id, WorkerJoin { generation, join });
        generation
    }

    #[cfg(test)]
    fn insert_test_worker_without_join(&self, handle: SessionWorkerHandle) -> WorkerGeneration {
        let id = handle.session_id;
        let mut workers = crate::sync::lock_or_recover(&self.inner.workers);
        let generation = next_generation(&mut workers);
        workers.live.insert(id, WorkerEntry { generation, handle });
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
        crate::sync::lock_or_recover(&self.inner.worker_joins)
            .insert(id, WorkerJoin { generation, join });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn test_registry() -> SessionRegistry {
        // The DB + lock manager aren't touched by `drain_all`; point them at
        // a throwaway in-memory DB so construction never hits user state.
        let db = Db::open_in_memory().expect("in-memory db");
        let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
        SessionRegistry::new(db, locks, ShutdownSignal::new(), None)
    }

    fn test_session(reg: &SessionRegistry) -> Arc<Session> {
        let tmp = tempfile::tempdir().expect("tempdir");
        Arc::new(
            Session::create_deferred(reg.inner.db.clone(), tmp.keep(), "Build")
                .expect("deferred session"),
        )
    }

    fn persisted_test_session(reg: &SessionRegistry) -> Arc<Session> {
        let tmp = tempfile::tempdir().expect("tempdir");
        Arc::new(Session::create(reg.inner.db.clone(), tmp.keep(), "Build").expect("session"))
    }

    fn test_handle(reg: &SessionRegistry, session: Arc<Session>) -> SessionWorkerHandle {
        session_worker::SessionWorkerHandle::test_handle(session, reg.inner.locks.clone())
    }

    fn assert_no_live_worker(reg: &SessionRegistry, id: Uuid) {
        assert!(!reg.active_session_ids().contains(&id));
        assert!(!reg.any_agent_running());
        assert_eq!(reg.live_status(id), None);
        assert!(matches!(reg.claim_attach(id), AttachClaim::Start(_)));
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

    #[test]
    fn start_worker_refuses_after_drain_begins() {
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
        let err = match reg.start_worker(
            Arc::try_unwrap(session)
                .ok()
                .expect("fresh test session has one owner"),
            &providers,
            &extended,
            false,
            None,
            policy,
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
    async fn attach_claim_drops_closed_stale_handle_and_starts_fresh() {
        let reg = test_registry();
        let session = test_session(&reg);
        let id = session.id;
        let handle = test_handle(&reg, session);
        assert!(
            handle.is_closed(),
            "test handle intentionally has no receiver"
        );
        let join = tokio::spawn(async {});
        reg.insert_test_worker(handle, join);

        match reg.claim_attach(id) {
            AttachClaim::Start(_) => {}
            _ => panic!("closed stale handle should be removed and restarted"),
        }
        assert!(reg.lookup(id).is_none());
        assert!(!crate::sync::lock_or_recover(&reg.inner.worker_joins).contains_key(&id));
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
        let clean = reg.drain_all(Duration::from_secs(5)).await;
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
        let clean = reg.drain_all(Duration::from_millis(120)).await;
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
        let clean = reg.drain_all(Duration::from_secs(30)).await;
        assert!(clean, "idle drain is clean");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "idle drain must not wait out the grace"
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

        let clean = reg.drain_all(Duration::from_secs(1)).await;

        assert!(clean);
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

        let clean = reg.drain_all(Duration::from_millis(20)).await;

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

        let clean = reg.drain_all(Duration::from_millis(20)).await;

        assert!(!clean);
        let summaries = reg
            .inner
            .db
            .list_session_summaries(None, None, 100)
            .unwrap();
        let summary = summaries
            .iter()
            .find(|summary| summary.session_id == id)
            .unwrap();
        assert_eq!(
            summary.activity_state,
            Some(crate::daemon::proto::SessionActivityState::Interrupted)
        );
        let events = reg.inner.db.list_session_events(id).unwrap();
        let interrupted = events
            .iter()
            .find(|event| event.kind == "turn_interrupted")
            .expect("turn_interrupted event");
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

        let clean = reg.drain_all(Duration::from_millis(20)).await;

        assert!(!clean);
        let summaries = reg
            .inner
            .db
            .list_session_summaries(None, None, 100)
            .unwrap();
        let summary = summaries
            .iter()
            .find(|summary| summary.session_id == id)
            .unwrap();
        assert_eq!(summary.activity_state, None);
        let events = reg.inner.db.list_session_events(id).unwrap();
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

        let clean = reg.drain_all(Duration::from_secs(1)).await;

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

    /// Reattach hook (`session-detach-lock-release.md`): the registry's resume
    /// path re-acquires a session's released locks for an unchanged file. A
    /// changed file is not reacquired. A second reattach (snapshot already
    /// consumed) reacquires nothing — the multi-attach nuance.
    async fn wait_until<F>(mut predicate: F)
    where
        F: FnMut() -> bool,
    {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !predicate() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("condition became true");
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
            .expect("session")
            .session_id;
        let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
        let reg = SessionRegistry::new(db, locks.clone(), ShutdownSignal::new(), None);

        let tmp = tempfile::TempDir::new().unwrap();
        let keep = tmp.path().join("keep.rs");
        let drift = tmp.path().join("drift.rs");
        std::fs::write(&keep, "v1").unwrap();
        std::fs::write(&drift, "v1").unwrap();
        locks.acquire(&keep, "builder", sid).unwrap();
        locks.acquire(&drift, "builder", sid).unwrap();

        // Last detach while idle → session-scoped release.
        let released = locks.suspend_session(sid).unwrap();
        assert_eq!(released.len(), 2);
        assert!(locks.holder(&keep).is_none());
        assert!(locks.holder(&drift).is_none());

        // One file drifts while detached.
        std::fs::write(&drift, "v2").unwrap();

        // Reattach → only the unchanged file is reacquired.
        reg.resume_session_locks(sid);
        wait_until(|| locks.holder(&keep).is_some()).await;
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
        reg.resume_session_locks(sid);
        tokio::task::yield_now().await;
        assert_eq!(locks.holder(&keep), Some((sid, "builder".to_string())));
    }
}
