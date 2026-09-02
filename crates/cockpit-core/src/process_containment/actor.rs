//! Daemon-owned ProcessContainment actor.
//!
//! One bounded command queue serializes state transitions per containment.
//! Callers receive a non-serializable [`ContainmentLease`] and must spawn user
//! code only into that lease's process-tree guard when the adapter provides
//! one. The adapter must not run `req.program`. Allocation persists
//! `PlatformAllocated` (still `Creating`); `MembershipProven` is written only
//! after [`ProcessContainmentHandle::prove_membership`] observes kernel
//! membership.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::oneshot;
use uuid::Uuid;

use crate::db::Db;
use crate::db::execution_containments::{CasExecutionContainment, ExecutionContainmentRow};

use super::adapter::{
    AdapterHandle, AllocatedContainment, ContainerExecRequest, NativeSpawnRequest, SharedAdapter,
};
use super::state_machine::reduce;
use super::types::{
    ContainmentError, ContainmentEvent, ContainmentGuarantee, ContainmentLease, ContainmentRecord,
    ContainmentState, EmptyOutcome, LateCallbackKind, LeaseToken, ReduceResult,
    SafeContainmentMetadata, SafeLocator,
};

/// Bounded queue capacity for the containment actor.
pub const CONTAINMENT_QUEUE_CAPACITY: usize = 64;

type Reply<T> = oneshot::Sender<T>;

enum Op {
    CreateAndSpawn {
        session_id: Uuid,
        operation_id: String,
        program: PathBuf,
        args: Vec<String>,
        cwd: PathBuf,
        require_proven: bool,
        reply: Reply<Result<ContainmentLease, ContainmentError>>,
    },
    CreateContainerAndExec {
        session_id: Uuid,
        operation_id: String,
        image: String,
        command: Vec<String>,
        installation_id: String,
        nonce: String,
        require_proven: bool,
        reply: Reply<Result<ContainmentLease, ContainmentError>>,
    },
    Terminate {
        lease: ContainmentLease,
        reply: Reply<Result<(), ContainmentError>>,
    },
    AwaitEmpty {
        lease: ContainmentLease,
        reply: Reply<Result<EmptyOutcome, ContainmentError>>,
    },
    Recover {
        reply: Reply<Result<Vec<(Uuid, EmptyOutcome)>, ContainmentError>>,
    },
    SafeMetadata {
        reply: Reply<SafeContainmentMetadata>,
    },
    BeginSessionDeletion {
        session_id: Uuid,
        reply: Reply<Result<(), ContainmentError>>,
    },
    FinishSessionDeletion {
        session_id: Uuid,
        reply: Reply<Result<(), ContainmentError>>,
    },
    BeginShutdown {
        reply: Reply<()>,
    },
    AwaitAllEmpty {
        deadline: Option<Duration>,
        reply: Reply<Result<(), ContainmentError>>,
    },
    LateCallback {
        containment_id: Uuid,
        generation: u64,
        kind: LateCallbackKind,
        reply: Reply<()>,
    },
    ProcessTreeGuard {
        lease: ContainmentLease,
        reply:
            Reply<Result<Option<Arc<cockpit_host::process::ProcessTreeGuard>>, ContainmentError>>,
    },
    ProveMembership {
        lease: ContainmentLease,
        reply: Reply<Result<(), ContainmentError>>,
    },
    Shutdown {
        reply: Reply<()>,
    },
}

struct LiveEntry {
    record: ContainmentRecord,
    handle: Option<AdapterHandle>,
    lease_token: Arc<LeaseToken>,
}

/// Async handle to the ProcessContainment actor.
#[derive(Clone)]
pub struct ProcessContainmentHandle {
    tx: SyncSender<Op>,
}

impl ProcessContainmentHandle {
    fn enqueue(&self, op: Op) -> Result<(), ContainmentError> {
        match self.tx.try_send(op) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(ContainmentError::QueueSaturated),
            Err(TrySendError::Disconnected(_)) => Err(ContainmentError::ActorStopped),
        }
    }

    async fn await_reply<T: Send + 'static>(
        rx: oneshot::Receiver<T>,
    ) -> Result<T, ContainmentError> {
        rx.await
            .map_err(|_| ContainmentError::Internal("actor dropped reply".into()))
    }

    /// Allocate a containment generation. Does not run user instructions.
    pub async fn create_and_spawn(
        &self,
        session_id: Uuid,
        operation_id: impl Into<String>,
        program: impl Into<PathBuf>,
        args: Vec<String>,
        cwd: impl Into<PathBuf>,
        require_proven: bool,
    ) -> Result<ContainmentLease, ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::CreateAndSpawn {
            session_id,
            operation_id: operation_id.into(),
            program: program.into(),
            args,
            cwd: cwd.into(),
            require_proven,
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    /// Fresh container per generation for container/zerobox strict work.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_container_and_exec(
        &self,
        session_id: Uuid,
        operation_id: impl Into<String>,
        image: impl Into<String>,
        command: Vec<String>,
        installation_id: impl Into<String>,
        nonce: impl Into<String>,
        require_proven: bool,
    ) -> Result<ContainmentLease, ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::CreateContainerAndExec {
            session_id,
            operation_id: operation_id.into(),
            image: image.into(),
            command,
            installation_id: installation_id.into(),
            nonce: nonce.into(),
            require_proven,
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    /// Idempotent terminate of the containment object.
    pub async fn terminate(&self, lease: ContainmentLease) -> Result<(), ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::Terminate { lease, reply })?;
        Self::await_reply(rx).await?
    }

    /// Await same-generation empty oracle.
    ///
    /// This is a probe: a delivered SIGKILL that has not yet drained returns
    /// drain-in-progress Uncertain and keeps the live oracle. Callers that
    /// need ProvenEmpty must use [`Self::await_empty_until`].
    pub async fn await_empty(
        &self,
        lease: ContainmentLease,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::AwaitEmpty { lease, reply })?;
        Self::await_reply(rx).await?
    }

    /// Re-probe [`Self::await_empty`] until ProvenEmpty, a terminal
    /// (non-drain) outcome, or `deadline`.
    ///
    /// A delivered SIGKILL that has not yet drained
    /// ([`EmptyOutcome::is_drain_in_progress`]) is retried. Terminal
    /// Uncertain (unattributable membership, missing locator, forced
    /// fixture) is returned immediately so fail-open paths do not wait
    /// the full deadline.
    pub async fn await_empty_until(
        &self,
        lease: ContainmentLease,
        deadline: Duration,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let until = Instant::now() + deadline;
        loop {
            let outcome = self.await_empty(lease.clone()).await?;
            if !outcome.is_drain_in_progress() {
                return Ok(outcome);
            }
            let now = Instant::now();
            if now >= until {
                return Ok(outcome);
            }
            tokio::time::sleep((until - now).min(Duration::from_millis(5))).await;
        }
    }

    /// Startup recovery for durable rows.
    pub async fn recover(&self) -> Result<Vec<(Uuid, EmptyOutcome)>, ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::Recover { reply })?;
        Self::await_reply(rx).await?
    }

    pub async fn safe_metadata(&self) -> Result<SafeContainmentMetadata, ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::SafeMetadata { reply })?;
        Self::await_reply(rx).await
    }

    /// Commit session Deleting, stop containments, wait for ProvenEmpty.
    pub async fn begin_session_deletion(&self, session_id: Uuid) -> Result<(), ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::BeginSessionDeletion { session_id, reply })?;
        Self::await_reply(rx).await?
    }

    /// After ProvenEmpty for all session containments, allow row deletion.
    pub async fn finish_session_deletion(&self, session_id: Uuid) -> Result<(), ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::FinishSessionDeletion { session_id, reply })?;
        Self::await_reply(rx).await?
    }

    pub async fn begin_shutdown(&self) -> Result<(), ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::BeginShutdown { reply })?;
        Self::await_reply(rx).await?;
        Ok(())
    }

    pub async fn await_all_empty(
        &self,
        deadline: Option<Duration>,
    ) -> Result<(), ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::AwaitAllEmpty { deadline, reply })?;
        Self::await_reply(rx).await?
    }

    pub async fn inject_late_callback(
        &self,
        containment_id: Uuid,
        generation: u64,
        kind: LateCallbackKind,
    ) -> Result<(), ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::LateCallback {
            containment_id,
            generation,
            kind,
            reply,
        })?;
        Self::await_reply(rx).await?;
        Ok(())
    }

    /// Borrow the process-tree guard for this lease so the caller can place
    /// its own child into the generation. `None` on adapters that do not own a
    /// bindable kernel job/group object.
    pub async fn process_tree_guard(
        &self,
        lease: &ContainmentLease,
    ) -> Result<Option<Arc<cockpit_host::process::ProcessTreeGuard>>, ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::ProcessTreeGuard {
            lease: lease.clone(),
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    /// Persist `MembershipProven` only after the adapter's kernel membership
    /// proof succeeds. Allocation (`create_and_spawn`) is not that proof.
    /// Idempotent once the generation is already `Active`.
    pub async fn prove_membership(&self, lease: &ContainmentLease) -> Result<(), ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::ProveMembership {
            lease: lease.clone(),
            reply,
        })?;
        Self::await_reply(rx).await?
    }
}

/// Owns the actor thread.
pub struct ProcessContainmentActor {
    handle: ProcessContainmentHandle,
    join: Option<JoinHandle<()>>,
}

impl ProcessContainmentActor {
    pub fn handle(&self) -> ProcessContainmentHandle {
        self.handle.clone()
    }

    /// Start with an injected adapter (tests / composition).
    pub fn start(db: Db, adapter: SharedAdapter) -> Self {
        let (tx, rx) = mpsc::sync_channel(CONTAINMENT_QUEUE_CAPACITY);
        let handle = ProcessContainmentHandle { tx: tx.clone() };
        let join = thread::Builder::new()
            .name("process-containment".into())
            .spawn(move || {
                // Multi-thread (1 worker) so `Db::read`/`write` `spawn_blocking`
                // cannot deadlock a current-thread `block_on` loop while the
                // daemon also uses the shared Db during shutdown.
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("process-containment-rt")
                    .enable_all()
                    .build()
                    .expect("containment runtime");
                rt.block_on(actor_loop(db, adapter, rx));
                // Drop runtime without blocking forever on stray tasks.
                rt.shutdown_background();
            })
            .expect("spawn containment actor");
        Self {
            handle,
            join: Some(join),
        }
    }

    pub fn shutdown(mut self) {
        let (reply, rx) = oneshot::channel();
        let _ = self.handle.tx.send(Op::Shutdown { reply });
        let _ = rx.blocking_recv();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for ProcessContainmentActor {
    fn drop(&mut self) {
        // Best-effort shutdown: never block the daemon exit path on a full
        // queue or a wedged actor. try_send + detach join when inside Tokio.
        let (reply, rx) = oneshot::channel();
        let _ = self.handle.tx.try_send(Op::Shutdown { reply });
        if let Some(join) = self.join.take() {
            if tokio::runtime::Handle::try_current().is_ok() {
                std::thread::spawn(move || {
                    let _ = rx.blocking_recv();
                    let _ = join.join();
                });
            } else {
                let _ = rx.blocking_recv();
                let _ = join.join();
            }
        }
    }
}

fn wall_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

struct ActorState {
    db: Db,
    adapter: SharedAdapter,
    live: HashMap<Uuid, LiveEntry>,
    intake_closed: bool,
    /// Serialize per-containment: track in-flight command keys.
    in_flight: HashSet<String>,
}

async fn actor_loop(db: Db, adapter: SharedAdapter, rx: Receiver<Op>) {
    let mut state = ActorState {
        db,
        adapter,
        live: HashMap::new(),
        intake_closed: false,
        in_flight: HashSet::new(),
    };
    while let Ok(op) = rx.recv() {
        match op {
            Op::Shutdown { reply } => {
                let _ = reply.send(());
                break;
            }
            Op::SafeMetadata { reply } => {
                let _ = reply.send(state.adapter.safe_metadata());
            }
            Op::BeginShutdown { reply } => {
                state.intake_closed = true;
                // Terminate every live containment.
                let leases: Vec<_> = state
                    .live
                    .iter()
                    .map(|(id, e)| ContainmentLease {
                        containment_id: *id,
                        session_id: e.record.session_id,
                        generation: e.record.generation,
                        guarantee: e.record.guarantee,
                        token: e.lease_token.clone(),
                    })
                    .collect();
                for lease in leases {
                    let _ = terminate_one(&mut state, lease).await;
                }
                let _ = reply.send(());
            }
            Op::CreateAndSpawn {
                session_id,
                operation_id,
                program,
                args,
                cwd,
                require_proven,
                reply,
            } => {
                let result = create_native(
                    &mut state,
                    session_id,
                    operation_id,
                    program,
                    args,
                    cwd,
                    require_proven,
                )
                .await;
                let _ = reply.send(result);
            }
            Op::CreateContainerAndExec {
                session_id,
                operation_id,
                image,
                command,
                installation_id,
                nonce,
                require_proven,
                reply,
            } => {
                let result = create_container(
                    &mut state,
                    session_id,
                    operation_id,
                    image,
                    command,
                    installation_id,
                    nonce,
                    require_proven,
                )
                .await;
                let _ = reply.send(result);
            }
            Op::Terminate { lease, reply } => {
                let result = terminate_one(&mut state, lease).await;
                let _ = reply.send(result);
            }
            Op::AwaitEmpty { lease, reply } => {
                let result = await_empty_one(&mut state, lease).await;
                let _ = reply.send(result);
            }
            Op::Recover { reply } => {
                let result = recover_all(&mut state).await;
                let _ = reply.send(result);
            }
            Op::BeginSessionDeletion { session_id, reply } => {
                let result = begin_session_deletion(&mut state, session_id).await;
                let _ = reply.send(result);
            }
            Op::FinishSessionDeletion { session_id, reply } => {
                let result = finish_session_deletion(&mut state, session_id).await;
                let _ = reply.send(result);
            }
            Op::AwaitAllEmpty { deadline, reply } => {
                let result = await_all_empty(&mut state, deadline).await;
                let _ = reply.send(result);
            }
            Op::LateCallback {
                containment_id,
                generation,
                kind,
                reply,
            } => {
                if let Some(entry) = state.live.get_mut(&containment_id) {
                    let event = ContainmentEvent::LateCallback {
                        callback_generation: generation,
                        kind,
                    };
                    if let ReduceResult::Applied(rec) = reduce(Some(entry.record.clone()), event) {
                        entry.record = *rec;
                    }
                }
                let _ = reply.send(());
            }
            Op::ProcessTreeGuard { lease, reply } => {
                let result = process_tree_guard_one(&state, &lease);
                let _ = reply.send(result);
            }
            Op::ProveMembership { lease, reply } => {
                let result = prove_membership_one(&mut state, lease).await;
                let _ = reply.send(result);
            }
        }
    }
}

fn process_tree_guard_one(
    state: &ActorState,
    lease: &ContainmentLease,
) -> Result<Option<Arc<cockpit_host::process::ProcessTreeGuard>>, ContainmentError> {
    let entry = state
        .live
        .get(&lease.containment_id)
        .ok_or(ContainmentError::NotFound(lease.containment_id))?;
    if entry.record.generation != lease.generation {
        return Err(ContainmentError::GenerationMismatch {
            expected: entry.record.generation,
            got: lease.generation,
        });
    }
    let handle = entry
        .handle
        .as_ref()
        .ok_or_else(|| ContainmentError::Internal("missing handle".into()))?;
    Ok(state.adapter.process_tree_guard(handle))
}

async fn persist_allocated_lease(
    state: &mut ActorState,
    record: ContainmentRecord,
    allocated: AllocatedContainment,
) -> Result<ContainmentLease, ContainmentError> {
    let generation = record.generation;
    let record = match reduce(
        Some(record.clone()),
        ContainmentEvent::PlatformAllocated {
            generation,
            locator: allocated.locator.clone(),
            now_wall_ms: wall_ms(),
        },
    ) {
        ReduceResult::Applied(r) => *r,
        o => return Err(ContainmentError::Internal(format!("{o:?}"))),
    };
    persist_cas_from_creating(state, &record).await?;

    let token = Arc::new(LeaseToken::new(format!("lease-{}", record.containment_id)));
    state.live.insert(
        record.containment_id,
        LiveEntry {
            record: record.clone(),
            handle: Some(allocated.handle),
            lease_token: token.clone(),
        },
    );
    Ok(ContainmentLease {
        containment_id: record.containment_id,
        session_id: record.session_id,
        generation: record.generation,
        guarantee: allocated.guarantee,
        token,
    })
}

async fn prove_membership_one(
    state: &mut ActorState,
    lease: ContainmentLease,
) -> Result<(), ContainmentError> {
    if !lease.is_alive() {
        return Err(ContainmentError::DescendantContainmentUnavailable {
            reason: "containment lease was invalidated before membership could be proven".into(),
        });
    }
    let (from_record, handle) = {
        let entry = state
            .live
            .get(&lease.containment_id)
            .ok_or(ContainmentError::NotFound(lease.containment_id))?;
        if entry.record.generation != lease.generation {
            return Err(ContainmentError::GenerationMismatch {
                expected: entry.record.generation,
                got: lease.generation,
            });
        }
        if entry.record.state == ContainmentState::Active {
            return Ok(());
        }
        if entry.record.state != ContainmentState::Creating {
            return Err(ContainmentError::IllegalTransition {
                from: entry.record.state.as_str().into(),
                to: ContainmentState::Active.as_str().into(),
            });
        }
        let handle = entry
            .handle
            .clone()
            .ok_or_else(|| ContainmentError::Internal("missing handle".into()))?;
        (entry.record.clone(), handle)
    };
    state
        .adapter
        .prove_membership(&handle, lease.generation)
        .await?;
    let rec = match reduce(
        Some(from_record.clone()),
        ContainmentEvent::MembershipProven {
            generation: lease.generation,
            locator: from_record.locator.clone(),
            now_wall_ms: wall_ms(),
        },
    ) {
        ReduceResult::Applied(r) => *r,
        o => return Err(ContainmentError::Internal(format!("{o:?}"))),
    };
    persist_cas_from_creating(state, &rec).await?;
    if let Some(entry) = state.live.get_mut(&lease.containment_id) {
        entry.record = rec;
    }
    Ok(())
}

async fn create_native(
    state: &mut ActorState,
    session_id: Uuid,
    operation_id: String,
    program: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    require_proven: bool,
) -> Result<ContainmentLease, ContainmentError> {
    if state.intake_closed {
        return Err(ContainmentError::ShutdownIntakeClosed);
    }
    if state
        .db
        .is_session_deleting(session_id)
        .await
        .map_err(|e| ContainmentError::Internal(e.to_string()))?
    {
        return Err(ContainmentError::SessionDeleting);
    }

    let containment_id = Uuid::new_v4();
    let generation = 1u64;
    let now = wall_ms();
    let platform_kind = state.adapter.platform_kind();
    let guarantee = state.adapter.guarantee();

    // BeginCreate durable row before platform allocation.
    let event = ContainmentEvent::BeginCreate {
        containment_id,
        session_id,
        operation_id: operation_id.clone(),
        generation,
        platform_kind,
        guarantee,
        now_wall_ms: now,
    };
    let record = match reduce(None, event) {
        ReduceResult::Applied(r) => *r,
        other => {
            return Err(ContainmentError::Internal(format!("reduce: {other:?}")));
        }
    };
    persist_insert(state, &record).await?;

    if require_proven && guarantee == ContainmentGuarantee::Unsupported {
        let reason = state
            .adapter
            .safe_metadata()
            .capability_reason
            .unwrap_or_else(|| "unsupported".into());
        let rec = match reduce(
            Some(record.clone()),
            ContainmentEvent::MarkUnsupported {
                generation,
                reason: reason.clone(),
                now_wall_ms: wall_ms(),
            },
        ) {
            ReduceResult::Applied(r) => *r,
            o => return Err(ContainmentError::Internal(format!("{o:?}"))),
        };
        persist_cas(state, &record, &rec).await?;
        return Err(ContainmentError::DescendantContainmentUnavailable { reason });
    }

    let allocated = match state
        .adapter
        .create_and_spawn(NativeSpawnRequest {
            containment_id,
            session_id,
            generation,
            operation_id: operation_id.clone(),
            program,
            args,
            cwd,
            require_proven,
        })
        .await
    {
        Ok(a) => a,
        Err(e) => {
            let reason = match &e {
                ContainmentError::DescendantContainmentUnavailable { reason } => reason.clone(),
                other => other.to_string(),
            };
            let rec = match reduce(
                Some(record.clone()),
                ContainmentEvent::MarkUnsupported {
                    generation,
                    reason: reason.clone(),
                    now_wall_ms: wall_ms(),
                },
            ) {
                ReduceResult::Applied(r) => *r,
                o => return Err(ContainmentError::Internal(format!("{o:?}"))),
            };
            let _ = persist_cas(state, &record, &rec).await;
            return Err(e);
        }
    };

    persist_allocated_lease(state, record, allocated).await
}

#[allow(clippy::too_many_arguments)]
async fn create_container(
    state: &mut ActorState,
    session_id: Uuid,
    operation_id: String,
    image: String,
    command: Vec<String>,
    installation_id: String,
    nonce: String,
    require_proven: bool,
) -> Result<ContainmentLease, ContainmentError> {
    if state.intake_closed {
        return Err(ContainmentError::ShutdownIntakeClosed);
    }
    if state
        .db
        .is_session_deleting(session_id)
        .await
        .map_err(|e| ContainmentError::Internal(e.to_string()))?
    {
        return Err(ContainmentError::SessionDeleting);
    }

    let containment_id = Uuid::new_v4();
    let generation = 1u64;
    let now = wall_ms();
    let platform_kind = state.adapter.platform_kind();
    let guarantee = ContainmentGuarantee::Proven;

    let record = match reduce(
        None,
        ContainmentEvent::BeginCreate {
            containment_id,
            session_id,
            operation_id: operation_id.clone(),
            generation,
            platform_kind,
            guarantee,
            now_wall_ms: now,
        },
    ) {
        ReduceResult::Applied(r) => *r,
        o => return Err(ContainmentError::Internal(format!("{o:?}"))),
    };
    persist_insert(state, &record).await?;

    let allocated = match state
        .adapter
        .create_container_and_exec(ContainerExecRequest {
            containment_id,
            session_id,
            generation,
            operation_id,
            image,
            command,
            require_proven,
            installation_id,
            nonce,
        })
        .await
    {
        Ok(a) => a,
        Err(e) => {
            let reason = e.to_string();
            let rec = match reduce(
                Some(record.clone()),
                ContainmentEvent::MarkUnsupported {
                    generation,
                    reason,
                    now_wall_ms: wall_ms(),
                },
            ) {
                ReduceResult::Applied(r) => *r,
                o => return Err(ContainmentError::Internal(format!("{o:?}"))),
            };
            let _ = persist_cas(state, &record, &rec).await;
            return Err(e);
        }
    };

    persist_allocated_lease(state, record, allocated).await
}

async fn terminate_one(
    state: &mut ActorState,
    lease: ContainmentLease,
) -> Result<(), ContainmentError> {
    let (from_record, handle) = {
        let entry = state
            .live
            .get(&lease.containment_id)
            .ok_or(ContainmentError::NotFound(lease.containment_id))?;
        if entry.record.generation != lease.generation {
            return Err(ContainmentError::GenerationMismatch {
                expected: entry.record.generation,
                got: lease.generation,
            });
        }
        (entry.record.clone(), entry.handle.clone())
    };
    let cmd_key = format!("{}:terminate:{}", lease.containment_id, lease.generation);
    if !state.in_flight.insert(cmd_key.clone()) {
        // Idempotent: already terminating.
        return Ok(());
    }
    let rec = match reduce(
        Some(from_record.clone()),
        ContainmentEvent::RequestStop {
            generation: lease.generation,
            now_wall_ms: wall_ms(),
        },
    ) {
        ReduceResult::Applied(r) => *r,
        ReduceResult::DuplicateCommand { .. } => {
            state.in_flight.remove(&cmd_key);
            return Ok(());
        }
        o => {
            state.in_flight.remove(&cmd_key);
            return Err(ContainmentError::Internal(format!("{o:?}")));
        }
    };
    let _ = persist_cas(state, &from_record, &rec).await;
    if let Some(entry) = state.live.get_mut(&lease.containment_id) {
        entry.record = rec;
    }
    if let Some(handle) = handle {
        match state.adapter.terminate(&handle, lease.generation).await {
            Ok(()) => {}
            Err(e) => {
                // Force-kill failure is content-free and retryable; never delete durable row.
                state.in_flight.remove(&cmd_key);
                return Err(e);
            }
        }
    }
    state.in_flight.remove(&cmd_key);
    Ok(())
}

async fn await_empty_one(
    state: &mut ActorState,
    lease: ContainmentLease,
) -> Result<EmptyOutcome, ContainmentError> {
    let (from_record, handle) = {
        let entry = state
            .live
            .get(&lease.containment_id)
            .ok_or(ContainmentError::NotFound(lease.containment_id))?;
        if entry.record.generation != lease.generation {
            return Err(ContainmentError::GenerationMismatch {
                expected: entry.record.generation,
                got: lease.generation,
            });
        }
        let handle = entry
            .handle
            .clone()
            .ok_or_else(|| ContainmentError::Internal("missing handle".into()))?;
        (entry.record.clone(), handle)
    };
    let outcome = state.adapter.await_empty(&handle, lease.generation).await?;
    match &outcome {
        EmptyOutcome::ProvenEmpty { generation } => {
            let rec = match reduce(
                Some(from_record.clone()),
                ContainmentEvent::OracleEmpty {
                    generation: *generation,
                    now_wall_ms: wall_ms(),
                },
            ) {
                ReduceResult::Applied(r) => *r,
                ReduceResult::GenerationMismatch { .. } => return Ok(outcome),
                o => return Err(ContainmentError::Internal(format!("{o:?}"))),
            };
            let _ = persist_cas(state, &from_record, &rec).await;
            if let Some(entry) = state.live.get_mut(&lease.containment_id) {
                entry.record = rec;
                entry.lease_token.invalidate();
            }
        }
        EmptyOutcome::Uncertain { generation, reason } => {
            let rec = match reduce(
                Some(from_record.clone()),
                ContainmentEvent::MarkUncertain {
                    generation: *generation,
                    reason: reason.clone(),
                    now_wall_ms: wall_ms(),
                },
            ) {
                ReduceResult::Applied(r) => *r,
                ReduceResult::Illegal { .. } => return Ok(outcome),
                o => return Err(ContainmentError::Internal(format!("{o:?}"))),
            };
            let _ = persist_cas(state, &from_record, &rec).await;
            if let Some(entry) = state.live.get_mut(&lease.containment_id) {
                entry.record = rec;
            }
        }
        EmptyOutcome::Unsupported { .. } => {}
    }
    Ok(outcome)
}

async fn recover_all(
    state: &mut ActorState,
) -> Result<Vec<(Uuid, EmptyOutcome)>, ContainmentError> {
    let rows = state
        .db
        .list_all_execution_containments()
        .await
        .map_err(|e| ContainmentError::Internal(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        if row.state == "empty" {
            continue;
        }
        let locator = SafeLocator::from_json(&row.platform_locator_json);
        let outcome = state.adapter.recover(&locator, row.generation).await?;
        if matches!(outcome, EmptyOutcome::ProvenEmpty { .. }) {
            let _ = state
                .db
                .cas_execution_containment_state(CasExecutionContainment {
                    containment_id: row.containment_id,
                    expected_state: row.state.clone(),
                    expected_generation: row.generation,
                    new_state: "empty".into(),
                    now_wall_ms: wall_ms(),
                    platform_locator_json: None,
                    runtime_context_digest: None,
                    unsupported_reason: None,
                    emptied_at_wall_ms: None,
                })
                .await;
        } else if matches!(outcome, EmptyOutcome::Uncertain { .. }) {
            let _ = state
                .db
                .cas_execution_containment_state(CasExecutionContainment {
                    containment_id: row.containment_id,
                    expected_state: row.state.clone(),
                    expected_generation: row.generation,
                    new_state: "uncertain".into(),
                    now_wall_ms: wall_ms(),
                    platform_locator_json: None,
                    runtime_context_digest: None,
                    unsupported_reason: None,
                    emptied_at_wall_ms: None,
                })
                .await;
        }
        out.push((row.containment_id, outcome));
    }
    Ok(out)
}

async fn begin_session_deletion(
    state: &mut ActorState,
    session_id: Uuid,
) -> Result<(), ContainmentError> {
    state
        .db
        .mark_session_deleting(session_id)
        .await
        .map_err(|e| ContainmentError::Internal(e.to_string()))?;
    let leases: Vec<_> = state
        .live
        .iter()
        .filter(|(_, e)| e.record.session_id == session_id && e.record.state.is_nonempty())
        .map(|(id, e)| ContainmentLease {
            containment_id: *id,
            session_id: e.record.session_id,
            generation: e.record.generation,
            guarantee: e.record.guarantee,
            token: e.lease_token.clone(),
        })
        .collect();
    for lease in leases {
        let _ = terminate_one(state, lease.clone()).await;
        let _ = await_empty_one(state, lease).await;
    }

    // Also stop durable nonempty rows without live handles.
    let rows = state
        .db
        .list_nonempty_execution_containments(Some(session_id))
        .await
        .map_err(|e| ContainmentError::Internal(e.to_string()))?;
    for row in rows {
        if let Some(entry) = state.live.get(&row.containment_id) {
            let lease = ContainmentLease {
                containment_id: row.containment_id,
                session_id,
                generation: entry.record.generation,
                guarantee: entry.record.guarantee,
                token: entry.lease_token.clone(),
            };
            let _ = terminate_one(state, lease.clone()).await;
            let _ = await_empty_one(state, lease).await;
        } else {
            let locator = SafeLocator::from_json(&row.platform_locator_json);
            let _ = state.adapter.recover(&locator, row.generation).await;
        }
    }
    Ok(())
}

async fn finish_session_deletion(
    state: &mut ActorState,
    session_id: Uuid,
) -> Result<(), ContainmentError> {
    let nonempty = state
        .db
        .list_nonempty_execution_containments(Some(session_id))
        .await
        .map_err(|e| ContainmentError::Internal(e.to_string()))?;
    if !nonempty.is_empty() {
        return Err(ContainmentError::DeletionBlocked {
            blockers: nonempty.iter().map(|r| r.containment_id).collect(),
        });
    }
    // Live map must also be empty for this session.
    let live_blockers: Vec<_> = state
        .live
        .iter()
        .filter(|(_, e)| e.record.session_id == session_id && e.record.state.is_nonempty())
        .map(|(id, _)| *id)
        .collect();
    if !live_blockers.is_empty() {
        return Err(ContainmentError::DeletionBlocked {
            blockers: live_blockers,
        });
    }
    Ok(())
}

async fn await_all_empty(
    state: &mut ActorState,
    deadline: Option<Duration>,
) -> Result<(), ContainmentError> {
    // A delivered SIGKILL may take longer than one adapter probe to drain.
    // Re-poll until Empty or the caller deadline so shutdown has a bounded
    // path to ProvenEmpty; the Unix adapter keeps the empty oracle after
    // SIGKILL Uncertain (signal authority is already one-shot).
    let until = deadline.map(|d| Instant::now() + d);
    loop {
        let leases: Vec<_> = state
            .live
            .iter()
            .filter(|(_, e)| e.record.state.is_nonempty())
            .map(|(id, e)| ContainmentLease {
                containment_id: *id,
                session_id: e.record.session_id,
                generation: e.record.generation,
                guarantee: e.record.guarantee,
                token: e.lease_token.clone(),
            })
            .collect();
        for lease in leases {
            let _ = terminate_one(state, lease.clone()).await;
            match await_empty_one(state, lease).await? {
                EmptyOutcome::ProvenEmpty { .. } => {}
                EmptyOutcome::Uncertain { .. } | EmptyOutcome::Unsupported { .. } => {}
            }
        }
        let nonempty = state
            .db
            .list_nonempty_execution_containments(None)
            .await
            .map_err(|e| ContainmentError::Internal(e.to_string()))?;
        let live_nonempty: Vec<_> = state
            .live
            .iter()
            .filter(|(_, e)| e.record.state.is_nonempty())
            .map(|(id, _)| *id)
            .collect();
        if nonempty.is_empty() && live_nonempty.is_empty() {
            return Ok(());
        }
        let Some(until) = until else {
            let mut blockers: Vec<Uuid> = nonempty.iter().map(|r| r.containment_id).collect();
            blockers.extend(live_nonempty);
            return Err(ContainmentError::ShutdownNotClean { blockers });
        };
        let now = Instant::now();
        if now >= until {
            let mut blockers: Vec<Uuid> = nonempty.iter().map(|r| r.containment_id).collect();
            blockers.extend(live_nonempty);
            return Err(ContainmentError::ShutdownNotClean { blockers });
        }
        tokio::time::sleep((until - now).min(Duration::from_millis(5))).await;
    }
}

async fn persist_insert(
    state: &ActorState,
    record: &ContainmentRecord,
) -> Result<(), ContainmentError> {
    let row = ExecutionContainmentRow {
        containment_id: record.containment_id,
        session_id: record.session_id,
        operation_id: record.operation_id.clone(),
        generation: record.generation,
        platform_kind: record.platform_kind.as_str().into(),
        state: record.state.as_str().into(),
        guarantee: record.guarantee.as_str().into(),
        platform_locator_json: record.locator.to_json(),
        runtime_context_digest: record.locator.runtime_context_digest.clone(),
        unsupported_reason: record.unsupported_reason.clone(),
        created_at_wall_ms: record.created_at_wall_ms,
        updated_at_wall_ms: record.updated_at_wall_ms,
        emptied_at_wall_ms: record.emptied_at_wall_ms,
    };
    state
        .db
        .insert_execution_containment(row)
        .await
        .map_err(|e| ContainmentError::Internal(e.to_string()))?;
    Ok(())
}

async fn persist_cas(
    state: &ActorState,
    from: &ContainmentRecord,
    to: &ContainmentRecord,
) -> Result<(), ContainmentError> {
    let _ = state
        .db
        .cas_execution_containment_state(CasExecutionContainment {
            containment_id: to.containment_id,
            expected_state: from.state.as_str().into(),
            expected_generation: to.generation,
            new_state: to.state.as_str().into(),
            now_wall_ms: to.updated_at_wall_ms,
            platform_locator_json: Some(to.locator.to_json()),
            runtime_context_digest: Some(to.locator.runtime_context_digest.clone()),
            unsupported_reason: Some(to.unsupported_reason.clone()),
            emptied_at_wall_ms: Some(to.emptied_at_wall_ms),
        })
        .await
        .map_err(|e| ContainmentError::Internal(e.to_string()))?;
    Ok(())
}

async fn persist_cas_from_creating(
    state: &ActorState,
    to: &ContainmentRecord,
) -> Result<(), ContainmentError> {
    let _ = state
        .db
        .cas_execution_containment_state(CasExecutionContainment {
            containment_id: to.containment_id,
            expected_state: "creating".into(),
            expected_generation: to.generation,
            new_state: to.state.as_str().into(),
            now_wall_ms: to.updated_at_wall_ms,
            platform_locator_json: Some(to.locator.to_json()),
            runtime_context_digest: Some(to.locator.runtime_context_digest.clone()),
            unsupported_reason: Some(to.unsupported_reason.clone()),
            emptied_at_wall_ms: Some(to.emptied_at_wall_ms),
        })
        .await
        .map_err(|e| ContainmentError::Internal(e.to_string()))?;
    Ok(())
}

/// Shared flag for production composition tests.
#[allow(dead_code)]
static ACTOR_STARTED: AtomicBool = AtomicBool::new(false);

#[allow(dead_code)]
pub fn mark_actor_started() {
    ACTOR_STARTED.store(true, Ordering::SeqCst);
}

/// Select default adapter for the current host.
pub fn default_host_adapter() -> SharedAdapter {
    #[cfg(target_os = "linux")]
    {
        Arc::new(super::linux::LinuxCgroupAdapter::production())
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(super::macos::MacosNativeAdapter::production())
    }
    #[cfg(target_os = "windows")]
    {
        Arc::new(super::windows::WindowsJobAdapter::production())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Arc::new(super::fake::FakeUnsupportedAdapter {
            reason: "platform_unsupported".into(),
            kind: super::types::PlatformKind::Unsupported,
        })
    }
}
