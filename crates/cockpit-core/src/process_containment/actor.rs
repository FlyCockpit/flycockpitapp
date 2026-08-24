//! Daemon-owned ProcessContainment actor.
//!
//! One bounded command queue serializes state transitions per containment.
//! Callers receive a non-serializable [`ContainmentLease`] and must not spawn
//! user code outside this actor.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tokio::sync::mpsc::error::TrySendError;
use uuid::Uuid;

use crate::db::Db;
use crate::db::execution_containments::{CasExecutionContainment, ExecutionContainmentRow};

use super::adapter::{
    AdapterHandle, ContainerExecRequest, NativeChildIo, NativeIoSpawnRequest, NativeSpawnRequest,
    SharedAdapter,
};
use super::state_machine::reduce;
use super::types::{
    ContainmentError, ContainmentEvent, ContainmentGuarantee, ContainmentLease, ContainmentRecord,
    EmptyOutcome, LateCallbackKind, LeaseToken, ReduceResult, SafeContainmentMetadata, SafeLocator,
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
    CreateAndSpawnWithIo {
        session_id: Uuid,
        operation_id: String,
        program: PathBuf,
        args: Vec<String>,
        env: std::collections::BTreeMap<String, String>,
        cwd: PathBuf,
        require_proven: bool,
        reply: Reply<Result<(ContainmentLease, NativeChildIo), ContainmentError>>,
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
    tx: mpsc::Sender<Op>,
    reconciliation_tx: mpsc::UnboundedSender<ContainmentLease>,
}

impl ProcessContainmentHandle {
    fn enqueue(&self, op: Op) -> Result<(), ContainmentError> {
        match self.tx.try_send(op) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(ContainmentError::QueueSaturated),
            Err(TrySendError::Closed(_)) => Err(ContainmentError::ActorStopped),
        }
    }

    async fn await_reply<T: Send + 'static>(
        rx: oneshot::Receiver<T>,
    ) -> Result<T, ContainmentError> {
        rx.await
            .map_err(|_| ContainmentError::Internal("actor dropped reply".into()))
    }

    async fn send_owned(&self, op: Op) -> Result<(), ContainmentError> {
        self.tx
            .send(op)
            .await
            .map_err(|_| ContainmentError::ActorStopped)
    }

    /// Create containment and place the initial process before user code.
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

    /// Create Proven native containment and return bounded-IO endpoints for
    /// the initial process. Command/env/stdio are transient and never durable.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_and_spawn_with_io(
        &self,
        session_id: Uuid,
        operation_id: impl Into<String>,
        program: impl Into<PathBuf>,
        args: Vec<String>,
        env: std::collections::BTreeMap<String, String>,
        cwd: impl Into<PathBuf>,
        require_proven: bool,
    ) -> Result<(ContainmentLease, NativeChildIo), ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::CreateAndSpawnWithIo {
            session_id,
            operation_id: operation_id.into(),
            program: program.into(),
            args,
            env,
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
        // Once a lease has been published, cleanup is an ownership operation,
        // not best-effort intake. Backpressure behind the bounded actor queue
        // instead of converting a transient full queue into abandoned cleanup.
        self.send_owned(Op::Terminate { lease, reply }).await?;
        Self::await_reply(rx).await?
    }

    /// Await same-generation empty oracle.
    pub async fn await_empty(
        &self,
        lease: ContainmentLease,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let (reply, rx) = oneshot::channel();
        self.send_owned(Op::AwaitEmpty { lease, reply }).await?;
        Self::await_reply(rx).await?
    }

    /// Transfer cleanup ownership back to the actor from a caller's `Drop`.
    ///
    /// This deliberately bypasses the bounded request queue: cleanup
    /// ownership must not be rejected during queue saturation, and `Drop`
    /// cannot await backpressure. The receiver is actor-owned and is drained
    /// before actor shutdown completes.
    pub(crate) fn enqueue_reconciliation(
        &self,
        lease: ContainmentLease,
    ) -> Result<(), ContainmentError> {
        self.reconciliation_tx
            .send(lease)
            .map_err(|_| ContainmentError::ActorStopped)
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
        let (tx, rx) = mpsc::channel(CONTAINMENT_QUEUE_CAPACITY);
        let (reconciliation_tx, reconciliation_rx) = mpsc::unbounded_channel();
        let handle = ProcessContainmentHandle {
            tx: tx.clone(),
            reconciliation_tx,
        };
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
                rt.block_on(actor_loop(db, adapter, rx, reconciliation_rx));
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
        let Some(join) = self.join.take() else {
            return;
        };
        let tx = self.handle.tx.clone();
        let shutdown = move || shutdown_actor_thread(tx, join);
        if tokio::runtime::Handle::try_current().is_ok() {
            // `blocking_send` panics from an async runtime. Keep the complete
            // synchronous shutdown protocol on an ordinary helper thread;
            // joining that helper preserves this method's explicit-shutdown
            // guarantee without entering Tokio's blocking APIs here.
            let _ = std::thread::spawn(shutdown).join();
        } else {
            shutdown();
        }
    }
}

impl Drop for ProcessContainmentActor {
    fn drop(&mut self) {
        // The explicit daemon shutdown path closes intake and proves all
        // containments empty before dropping this owner. This fallback asks
        // the actor to drain actor-owned reconciliation/live leases as well;
        // inside Tokio the blocking join rides on a plain thread so the async
        // executor itself is not blocked.
        let Some(join) = self.join.take() else {
            return;
        };
        let tx = self.handle.tx.clone();
        let shutdown = move || shutdown_actor_thread(tx, join);
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::spawn(shutdown);
        } else {
            shutdown();
        }
    }
}

fn shutdown_actor_thread(tx: mpsc::Sender<Op>, join: thread::JoinHandle<()>) {
    let (reply, rx) = oneshot::channel();
    if tx.blocking_send(Op::Shutdown { reply }).is_ok() {
        let _ = rx.blocking_recv();
    }
    let _ = join.join();
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
    deleting_sessions: HashSet<Uuid>,
    intake_closed: bool,
    /// Serialize per-containment: track in-flight command keys.
    in_flight: HashSet<String>,
    /// Leases whose allocation reply was dropped after the actor had already
    /// published ownership. Reconciliation stays in the actor state machine;
    /// it is neither an untracked Tokio task nor a blocking retry loop.
    pending_reconciliation: Vec<ContainmentLease>,
}

async fn actor_loop(
    db: Db,
    adapter: SharedAdapter,
    mut rx: mpsc::Receiver<Op>,
    mut reconciliation_rx: mpsc::UnboundedReceiver<ContainmentLease>,
) {
    let mut state = ActorState {
        db,
        adapter,
        live: HashMap::new(),
        deleting_sessions: HashSet::new(),
        intake_closed: false,
        in_flight: HashSet::new(),
        pending_reconciliation: Vec::new(),
    };
    loop {
        let op = if state.pending_reconciliation.is_empty() {
            tokio::select! {
                op = rx.recv() => op,
                lease = reconciliation_rx.recv() => {
                    if let Some(lease) = lease {
                        enqueue_pending_reconciliation(&mut state, lease);
                    }
                    continue;
                }
            }
        } else {
            tokio::select! {
                op = rx.recv() => op,
                lease = reconciliation_rx.recv() => {
                    if let Some(lease) = lease {
                        enqueue_pending_reconciliation(&mut state, lease);
                    }
                    continue;
                }
                // `yield_now` is immediately eligible and `select!` is
                // unbiased, so a continuously-ready ordinary command queue
                // cannot perpetually reset a reconciliation timer and starve
                // actor-owned cleanup.
                _ = tokio::task::yield_now() => {
                    reconcile_one_pending(&mut state).await;
                    continue;
                }
            }
        };
        let Some(op) = op else { break };
        match op {
            Op::Shutdown { reply } => {
                // Shutdown is bounded. If platform truth cannot be proven in
                // time, the durable non-empty/stopping rows intentionally
                // survive for the next startup recovery pass; we never rewrite
                // uncertainty into a false Empty result merely to exit.
                if tokio::time::timeout(
                    Duration::from_secs(5),
                    drain_shutdown_reconciliation(&mut state, &mut reconciliation_rx),
                )
                .await
                .is_err()
                {
                    tracing::warn!(
                        pending = state.pending_reconciliation.len(),
                        live = state.live.len(),
                        "process containment shutdown drain timed out; durable recovery remains required"
                    );
                }
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
                if let Err(Ok(lease)) = reply.send(result) {
                    enqueue_pending_reconciliation(&mut state, lease);
                }
            }
            Op::CreateAndSpawnWithIo {
                session_id,
                operation_id,
                program,
                args,
                env,
                cwd,
                require_proven,
                reply,
            } => {
                let result = create_native_with_io(
                    &mut state,
                    session_id,
                    operation_id,
                    program,
                    args,
                    env,
                    cwd,
                    require_proven,
                )
                .await;
                if let Err(Ok((lease, _io))) = reply.send(result) {
                    // The requester was cancelled after allocation. Ownership
                    // stays with the actor, so reclaim the unpublished lease
                    // instead of leaving a live group with no external owner.
                    enqueue_pending_reconciliation(&mut state, lease);
                }
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
        }
    }
}

fn enqueue_pending_reconciliation(state: &mut ActorState, lease: ContainmentLease) {
    let duplicate = state.pending_reconciliation.iter().any(|pending| {
        pending.containment_id == lease.containment_id && pending.generation == lease.generation
    });
    if !duplicate {
        state.pending_reconciliation.push(lease);
    }
}

async fn drain_shutdown_reconciliation(
    state: &mut ActorState,
    reconciliation_rx: &mut mpsc::UnboundedReceiver<ContainmentLease>,
) {
    state.intake_closed = true;
    while let Ok(lease) = reconciliation_rx.try_recv() {
        enqueue_pending_reconciliation(state, lease);
    }
    let live: Vec<_> = state
        .live
        .iter()
        .filter(|(_, entry)| entry.record.state.is_nonempty())
        .map(|(containment_id, entry)| ContainmentLease {
            containment_id: *containment_id,
            session_id: entry.record.session_id,
            generation: entry.record.generation,
            guarantee: entry.record.guarantee,
            token: entry.lease_token.clone(),
        })
        .collect();
    for lease in live {
        enqueue_pending_reconciliation(state, lease);
    }
    while !state.pending_reconciliation.is_empty() {
        reconcile_one_pending(state).await;
        if !state.pending_reconciliation.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

async fn reconcile_one_pending(state: &mut ActorState) {
    let Some(lease) = state.pending_reconciliation.pop() else {
        return;
    };
    let _ = terminate_one(state, lease.clone()).await;
    match await_empty_one(state, lease.clone()).await {
        Ok(EmptyOutcome::ProvenEmpty { generation }) if generation == lease.generation => {}
        // The actor remains the sole owner and retries later. Other actor
        // commands get priority at the select above, so a slow/uncertain
        // cleanup cannot become a queue-saturation spin or starve shutdown.
        _ => state.pending_reconciliation.insert(0, lease),
    }
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
    if state.deleting_sessions.contains(&session_id)
        || state
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
    let mut record = match reduce(None, event) {
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
            persist_cas(state, &record, &rec).await?;
            return Err(e);
        }
    };

    if require_proven && allocated.guarantee != ContainmentGuarantee::Proven {
        reclaim_unpublished_allocation(state, &allocated.handle, generation).await;
        let failed = match reduce(
            Some(record.clone()),
            ContainmentEvent::CreateFailed {
                generation,
                now_wall_ms: wall_ms(),
            },
        ) {
            ReduceResult::Applied(record) => *record,
            other => return Err(ContainmentError::Internal(format!("{other:?}"))),
        };
        persist_cas(state, &record, &failed).await?;
        return Err(ContainmentError::DescendantContainmentUnavailable {
            reason: "adapter returned a non-proven native allocation".into(),
        });
    }

    record = match reduce(
        Some(record.clone()),
        ContainmentEvent::MembershipProven {
            generation,
            locator: allocated.locator.clone(),
            now_wall_ms: wall_ms(),
        },
    ) {
        ReduceResult::Applied(r) => *r,
        o => return Err(ContainmentError::Internal(format!("{o:?}"))),
    };
    if let Err(error) = persist_cas_from_creating(state, &record).await {
        reclaim_unpublished_allocation(state, &allocated.handle, generation).await;
        return Err(error);
    }

    let token = Arc::new(LeaseToken::new(format!("lease-{containment_id}")));
    state.live.insert(
        containment_id,
        LiveEntry {
            record: record.clone(),
            handle: Some(allocated.handle),
            lease_token: token.clone(),
        },
    );
    Ok(ContainmentLease {
        containment_id,
        session_id,
        generation,
        guarantee: allocated.guarantee,
        token,
    })
}

async fn reclaim_unpublished_allocation(
    state: &ActorState,
    handle: &AdapterHandle,
    generation: u64,
) {
    // Allocation succeeded but durable/live ownership did not. The adapter
    // handle is still available locally, so reclaim it directly and do not
    // return until its same-generation oracle proves emptiness.
    loop {
        let _ = state.adapter.terminate(handle, generation).await;
        if matches!(
            state.adapter.await_empty(handle, generation).await,
            Ok(EmptyOutcome::ProvenEmpty { generation: observed }) if observed == generation
        ) {
            return;
        }
        tokio::task::yield_now().await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn create_native_with_io(
    state: &mut ActorState,
    session_id: Uuid,
    operation_id: String,
    program: PathBuf,
    args: Vec<String>,
    env: std::collections::BTreeMap<String, String>,
    cwd: PathBuf,
    require_proven: bool,
) -> Result<(ContainmentLease, NativeChildIo), ContainmentError> {
    if state.intake_closed {
        return Err(ContainmentError::ShutdownIntakeClosed);
    }
    if state.deleting_sessions.contains(&session_id)
        || state
            .db
            .is_session_deleting(session_id)
            .await
            .map_err(|error| ContainmentError::Internal(error.to_string()))?
    {
        return Err(ContainmentError::SessionDeleting);
    }

    let containment_id = Uuid::new_v4();
    let generation = 1;
    let now = wall_ms();
    let guarantee = state.adapter.guarantee();
    let event = ContainmentEvent::BeginCreate {
        containment_id,
        session_id,
        operation_id: operation_id.clone(),
        generation,
        platform_kind: state.adapter.platform_kind(),
        guarantee,
        now_wall_ms: now,
    };
    let mut record = match reduce(None, event) {
        ReduceResult::Applied(record) => *record,
        other => return Err(ContainmentError::Internal(format!("reduce: {other:?}"))),
    };
    persist_insert(state, &record).await?;

    if require_proven && guarantee == ContainmentGuarantee::Unsupported {
        let reason = state
            .adapter
            .safe_metadata()
            .capability_reason
            .unwrap_or_else(|| "unsupported".into());
        let unsupported = match reduce(
            Some(record.clone()),
            ContainmentEvent::MarkUnsupported {
                generation,
                reason: reason.clone(),
                now_wall_ms: wall_ms(),
            },
        ) {
            ReduceResult::Applied(record) => *record,
            other => return Err(ContainmentError::Internal(format!("{other:?}"))),
        };
        persist_cas(state, &record, &unsupported).await?;
        return Err(ContainmentError::DescendantContainmentUnavailable { reason });
    }

    let allocated = match state
        .adapter
        .create_and_spawn_with_io(NativeIoSpawnRequest {
            containment_id,
            session_id,
            generation,
            operation_id,
            program,
            args,
            cwd,
            env,
            require_proven,
        })
        .await
    {
        Ok(allocated) => allocated,
        Err(error) => {
            let terminal = match &error {
                ContainmentError::DescendantContainmentUnavailable { reason } => {
                    ContainmentEvent::MarkUnsupported {
                        generation,
                        reason: reason.clone(),
                        now_wall_ms: wall_ms(),
                    }
                }
                _ => ContainmentEvent::CreateFailed {
                    generation,
                    now_wall_ms: wall_ms(),
                },
            };
            let failed = match reduce(Some(record.clone()), terminal) {
                ReduceResult::Applied(record) => *record,
                other => return Err(ContainmentError::Internal(format!("{other:?}"))),
            };
            persist_cas(state, &record, &failed).await?;
            return Err(error);
        }
    };

    if require_proven && allocated.allocation.guarantee != ContainmentGuarantee::Proven {
        reclaim_unpublished_allocation(state, &allocated.allocation.handle, generation).await;
        let failed = match reduce(
            Some(record.clone()),
            ContainmentEvent::CreateFailed {
                generation,
                now_wall_ms: wall_ms(),
            },
        ) {
            ReduceResult::Applied(record) => *record,
            other => return Err(ContainmentError::Internal(format!("{other:?}"))),
        };
        persist_cas(state, &record, &failed).await?;
        return Err(ContainmentError::DescendantContainmentUnavailable {
            reason: "adapter returned a non-proven IO allocation".into(),
        });
    }

    record = match reduce(
        Some(record.clone()),
        ContainmentEvent::MembershipProven {
            generation,
            locator: allocated.allocation.locator.clone(),
            now_wall_ms: wall_ms(),
        },
    ) {
        ReduceResult::Applied(record) => *record,
        other => return Err(ContainmentError::Internal(format!("{other:?}"))),
    };
    if let Err(error) = persist_cas_from_creating(state, &record).await {
        reclaim_unpublished_allocation(state, &allocated.allocation.handle, generation).await;
        return Err(error);
    }
    let token = Arc::new(LeaseToken::new(format!("lease-{containment_id}")));
    state.live.insert(
        containment_id,
        LiveEntry {
            record,
            handle: Some(allocated.allocation.handle),
            lease_token: token.clone(),
        },
    );
    Ok((
        ContainmentLease {
            containment_id,
            session_id,
            generation,
            guarantee: allocated.allocation.guarantee,
            token,
        },
        allocated.io,
    ))
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
    if state.deleting_sessions.contains(&session_id)
        || state
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

    let mut record = match reduce(
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
            persist_cas(state, &record, &rec).await?;
            return Err(e);
        }
    };

    record = match reduce(
        Some(record.clone()),
        ContainmentEvent::MembershipProven {
            generation,
            locator: allocated.locator.clone(),
            now_wall_ms: wall_ms(),
        },
    ) {
        ReduceResult::Applied(r) => *r,
        o => return Err(ContainmentError::Internal(format!("{o:?}"))),
    };
    persist_cas_from_creating(state, &record).await?;

    let token = Arc::new(LeaseToken::new(format!("lease-{containment_id}")));
    state.live.insert(
        containment_id,
        LiveEntry {
            record: record.clone(),
            handle: Some(allocated.handle),
            lease_token: token.clone(),
        },
    );
    Ok(ContainmentLease {
        containment_id,
        session_id,
        generation,
        guarantee: allocated.guarantee,
        token,
    })
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
        // The durable transition is idempotent, but the platform terminate is
        // deliberately retried. A previous adapter call can have failed after
        // committing `Stopping`; treating the duplicate as a completed kill
        // would permanently wedge reconciliation.
        ReduceResult::DuplicateCommand { .. } => from_record.clone(),
        o => {
            state.in_flight.remove(&cmd_key);
            return Err(ContainmentError::Internal(format!("{o:?}")));
        }
    };
    if rec != from_record {
        if let Err(error) = persist_cas(state, &from_record, &rec).await {
            state.in_flight.remove(&cmd_key);
            return Err(error);
        }
        if let Some(entry) = state.live.get_mut(&lease.containment_id) {
            entry.record = rec;
        }
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
            persist_cas(state, &from_record, &rec).await?;
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
            persist_cas(state, &from_record, &rec).await?;
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
    state.deleting_sessions.insert(session_id);

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
    _deadline: Option<Duration>,
) -> Result<(), ContainmentError> {
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
    if !nonempty.is_empty() || !live_nonempty.is_empty() {
        let mut blockers: Vec<Uuid> = nonempty.iter().map(|r| r.containment_id).collect();
        blockers.extend(live_nonempty);
        return Err(ContainmentError::ShutdownNotClean { blockers });
    }
    Ok(())
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
    let updated = state
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
    if updated.is_none() {
        return Err(ContainmentError::Internal(
            "containment state compare-and-swap did not apply".into(),
        ));
    }
    Ok(())
}

async fn persist_cas_from_creating(
    state: &ActorState,
    to: &ContainmentRecord,
) -> Result<(), ContainmentError> {
    let updated = state
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
    if updated.is_none() {
        return Err(ContainmentError::Internal(
            "creating containment compare-and-swap did not apply".into(),
        ));
    }
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
        Arc::new(super::macos::MacosNativeAdapter)
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
