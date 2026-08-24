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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, oneshot};
use tokio::sync::mpsc::error::TrySendError;
use uuid::Uuid;

use crate::db::Db;
use crate::db::execution_containments::{CasExecutionContainment, ExecutionContainmentRow};

use super::adapter::{
    AdapterHandle, AllocatedContainment, AllocatedNativeIo, ContainerExecRequest, NativeChildIo,
    NativeIoSpawnRequest, NativeSpawnRequest, SharedAdapter,
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
        cancellation: tokio_util::sync::CancellationToken,
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
}

struct LiveEntry {
    record: ContainmentRecord,
    handle: Option<AdapterHandle>,
    lease_token: Arc<LeaseToken>,
}

struct ReconciliationRequest {
    lease: ContainmentLease,
    completion: Option<Reply<Result<(), ContainmentError>>>,
}

/// Async handle to the ProcessContainment actor.
#[derive(Clone)]
pub struct ProcessContainmentHandle {
    tx: mpsc::Sender<Op>,
    reconciliation_tx: mpsc::UnboundedSender<ReconciliationRequest>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
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
        self.create_and_spawn_with_io_cancellable(
            session_id,
            operation_id,
            program,
            args,
            env,
            cwd,
            require_proven,
            tokio_util::sync::CancellationToken::new(),
        )
        .await
    }

    /// Submit an allocation with an explicit accepted-request cancellation
    /// ticket. Once enqueued, cancellation does not drop ownership: the actor
    /// acknowledges it only after any allocation that crossed the spawn
    /// boundary has reached same-generation ProvenEmpty.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn create_and_spawn_with_io_cancellable(
        &self,
        session_id: Uuid,
        operation_id: impl Into<String>,
        program: impl Into<PathBuf>,
        args: Vec<String>,
        env: std::collections::BTreeMap<String, String>,
        cwd: impl Into<PathBuf>,
        require_proven: bool,
        cancellation: tokio_util::sync::CancellationToken,
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
            cancellation: cancellation.clone(),
            reply,
        })?;
        let result = Self::await_reply(rx).await?;
        if cancellation.is_cancelled()
            && let Ok((lease, _)) = result.as_ref()
        {
            self.reconcile_and_await_empty(lease.clone()).await?;
            return Err(ContainmentError::Internal(
                "allocation request cancelled after cleanup".into(),
            ));
        }
        result
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
            .send(ReconciliationRequest { lease, completion: None })
            .map_err(|_| ContainmentError::ActorStopped)
    }

    /// Transfer cleanup to the actor and wait until its oracle has proved the
    /// exact published generation empty. The actor retries incrementally, so
    /// this wait never monopolizes its command loop.
    pub(crate) async fn reconcile_and_await_empty(
        &self,
        lease: ContainmentLease,
    ) -> Result<(), ContainmentError> {
        let (completion, rx) = oneshot::channel();
        self.reconciliation_tx
            .send(ReconciliationRequest {
                lease,
                completion: Some(completion),
            })
            .map_err(|_| ContainmentError::ActorStopped)?;
        Self::await_reply(rx).await?
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
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = ProcessContainmentHandle {
            tx: tx.clone(),
            reconciliation_tx,
            shutdown_tx,
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
                rt.block_on(actor_loop(db, adapter, rx, reconciliation_rx, shutdown_rx));
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
        match tokio::runtime::Handle::try_current() {
            Ok(handle)
                if matches!(
                    handle.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread
                ) =>
            {
                // Tell Tokio this worker is intentionally entering the sync
                // compatibility contract so it can replace the worker.
                tokio::task::block_in_place(|| {
                    shutdown_actor_thread(self.handle.shutdown_tx.clone(), join);
                });
            }
            Ok(_) => {
                // A current-thread runtime cannot use `block_in_place`; retain
                // the legacy sync contract via an ordinary helper. Async
                // callers should use `shutdown_async` and avoid this cost.
                dispatch_actor_shutdown(self.handle.shutdown_tx.clone(), join, true);
            }
            Err(_) => shutdown_actor_thread(self.handle.shutdown_tx.clone(), join),
        }
    }

    /// Explicit shutdown for async callers. The actor join is a blocking OS
    /// operation, so keep it off Tokio worker threads while preserving the
    /// same synchronous ownership contract as [`Self::shutdown`].
    pub async fn shutdown_async(mut self) {
        let Some(join) = self.join.take() else {
            return;
        };
        let shutdown_tx = self.handle.shutdown_tx.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || {
            shutdown_actor_thread(shutdown_tx, join);
        })
        .await
        {
            tracing::error!(%error, "process-containment shutdown worker failed");
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
        if tokio::runtime::Handle::try_current().is_ok() {
            dispatch_actor_shutdown(self.handle.shutdown_tx.clone(), join, false);
        } else {
            shutdown_actor_thread(self.handle.shutdown_tx.clone(), join);
        }
    }
}

fn dispatch_actor_shutdown(
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    join: thread::JoinHandle<()>,
    wait_for_helper: bool,
) {
    let retained = Arc::new(std::sync::Mutex::new(Some((shutdown_tx, join))));
    let for_helper = retained.clone();
    let helper = thread::Builder::new()
        .name("process-containment-shutdown".into())
        .spawn(move || {
            let owned = for_helper
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some((shutdown_tx, join)) = owned {
                shutdown_actor_thread(shutdown_tx, join);
            }
        });
    match helper {
        Ok(helper) if wait_for_helper => {
            let _ = helper.join();
        }
        Ok(_) => {}
        Err(_) => {
            // Do not drop the actor JoinHandle on helper-thread exhaustion.
            // This fallback can block, but preserves the ownership invariant.
            let owned = retained
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some((shutdown_tx, join)) = owned {
                shutdown_actor_thread(shutdown_tx, join);
            }
        }
    }
}

fn shutdown_actor_thread(
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    join: thread::JoinHandle<()>,
) {
    // `send_replace` cannot be rejected by bounded operation-queue pressure.
    // The actor owns a receiver for its entire lifetime, and channel closure
    // also resolves the selected control branch.
    shutdown_tx.send_replace(true);
    let deadline = Instant::now() + ACTOR_SHUTDOWN_DEADLINE;
    while !join.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if join.is_finished() {
        let _ = join.join();
    } else {
        retain_actor_join(join);
    }
}

/// A shutdown deadline bounds the caller, not actor ownership. If the actor
/// has not exited, move its opaque join handle to a dedicated reaper instead
/// of dropping (detaching) it. The actor continues owning every live adapter
/// handle and durable reconciliation item until its loop actually finishes.
fn retain_actor_join(join: thread::JoinHandle<()>) {
    // Keep a second owner outside the closure. `Builder::spawn` consumes and
    // drops its closure on failure; moving the only JoinHandle directly into
    // that closure would silently detach precisely on the resource-exhaustion
    // path where thread creation fails.
    let retained = Arc::new(std::sync::Mutex::new(Some(join)));
    let for_reaper = retained.clone();
    let spawned = thread::Builder::new()
        .name("process-containment-reaper".into())
        .spawn(move || {
            let join = for_reaper
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(join) = join {
                let _ = join.join();
            }
        });
    if spawned.is_err() {
        // Failure is exceptional and there is no nonblocking OS primitive
        // which can both retain and join a Rust thread. Preserve ownership and
        // correctness by joining on this already-off-runtime shutdown helper.
        let join = retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(join) = join {
            let _ = join.join();
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
    deleting_sessions: HashSet<Uuid>,
    intake_closed: bool,
    /// Serialize per-containment: track in-flight command keys.
    in_flight: HashSet<String>,
    /// Leases whose allocation reply was dropped after the actor had already
    /// published ownership. Reconciliation stays in the actor state machine;
    /// it is neither an untracked Tokio task nor a blocking retry loop.
    pending_reconciliation: Vec<PendingReconciliation>,
    /// Adapter allocations which were never published as leases because the
    /// post-allocation durable transition failed. They remain actor-owned but
    /// are reconciled incrementally, never in an unbounded rollback loop inside
    /// the create operation.
    pending_unpublished: Vec<PendingUnpublished>,
}

struct PendingReconciliation {
    lease: ContainmentLease,
    waiters: Vec<ReconciliationCompletion>,
    next_attempt: tokio::time::Instant,
    backoff: Duration,
}

struct PendingUnpublished {
    handle: AdapterHandle,
    /// The durable Creating row is retained until the adapter proves this
    /// exact generation empty. Only then may reconciliation publish the
    /// terminal CreateFailed transition.
    record: ContainmentRecord,
    generation: u64,
    next_attempt: tokio::time::Instant,
    backoff: Duration,
    /// The create request is not resolved until this exact allocation has
    /// reached same-generation ProvenEmpty and its durable row is terminal.
    waiters: Vec<UnpublishedCompletion>,
}

struct PreparedIoAllocation {
    record: ContainmentRecord,
    request: NativeIoSpawnRequest,
    cancellation: tokio_util::sync::CancellationToken,
    reply: IoCreateReply,
}

struct PreparedNativeAllocation {
    record: ContainmentRecord,
    request: NativeSpawnRequest,
    reply: Reply<Result<ContainmentLease, ContainmentError>>,
}

struct PreparedContainerAllocation {
    record: ContainmentRecord,
    request: ContainerExecRequest,
    reply: Reply<Result<ContainmentLease, ContainmentError>>,
}

enum AllocationCompletion {
    Native {
        prepared: PreparedNativeAllocation,
        result: Result<AllocatedContainment, ContainmentError>,
    },
    Io {
        prepared: PreparedIoAllocation,
        result: Result<AllocatedNativeIo, ContainmentError>,
    },
    Container {
        prepared: PreparedContainerAllocation,
        result: Result<AllocatedContainment, ContainmentError>,
    },
}

type IoCreateReply = Reply<Result<(ContainmentLease, NativeChildIo), ContainmentError>>;

enum ReconciliationCompletion {
    Empty(Reply<Result<(), ContainmentError>>),
    FailedLease(
        Reply<Result<ContainmentLease, ContainmentError>>,
        ContainmentError,
    ),
    FailedIo(IoCreateReply, ContainmentError),
}

enum UnpublishedCompletion {
    Lease(Reply<Result<ContainmentLease, ContainmentError>>, ContainmentError),
    Io(IoCreateReply, ContainmentError),
}

const RECONCILIATION_INITIAL_BACKOFF: Duration = Duration::from_millis(10);
const RECONCILIATION_MAX_BACKOFF: Duration = Duration::from_secs(1);
const ACTOR_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
/// Prevent a permanently ready ordinary queue from starving due cleanup.
const MAX_ORDINARY_OP_BURST: usize = 8;

async fn actor_loop(
    db: Db,
    adapter: SharedAdapter,
    mut rx: mpsc::Receiver<Op>,
    mut reconciliation_rx: mpsc::UnboundedReceiver<ReconciliationRequest>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut state = ActorState {
        db,
        adapter,
        live: HashMap::new(),
        deleting_sessions: HashSet::new(),
        intake_closed: false,
        in_flight: HashSet::new(),
        pending_reconciliation: Vec::new(),
        pending_unpublished: Vec::new(),
    };
    let mut reconciliation_open = true;
    let mut ordinary_op_burst = 0usize;
    let mut allocations = tokio::task::JoinSet::new();
    let mut begin_shutdown_waiters = Vec::new();
    loop {
        // `watch::changed` is edge-triggered, but shutdown is a level. Check
        // it before selecting so a ready queued operation can never win after
        // the owner has closed intake.
        if *shutdown_rx.borrow_and_update() {
            drain_shutdown_reconciliation(
                &mut state,
                &mut rx,
                &mut reconciliation_rx,
                &mut allocations,
            )
            .await;
            break;
        }
        if allocations.is_empty() && !begin_shutdown_waiters.is_empty() {
            finish_begin_shutdown(&mut state, &mut begin_shutdown_waiters).await;
        }
        let cleanup_due = state
            .pending_reconciliation
            .iter()
            .map(|pending| pending.next_attempt)
            .chain(state.pending_unpublished.iter().map(|pending| pending.next_attempt))
            .min()
            .is_some_and(|deadline| deadline <= tokio::time::Instant::now());
        if cleanup_due && ordinary_op_burst >= MAX_ORDINARY_OP_BURST {
            reconcile_one_pending(&mut state).await;
            ordinary_op_burst = 0;
            continue;
        }
        let op = if state.pending_reconciliation.is_empty()
            && state.pending_unpublished.is_empty()
        {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow_and_update() {
                        drain_shutdown_reconciliation(
                            &mut state,
                            &mut rx,
                            &mut reconciliation_rx,
                            &mut allocations,
                        )
                        .await;
                        break;
                    }
                    continue;
                }
                completed = allocations.join_next(), if !allocations.is_empty() => {
                    handle_allocation_join(&mut state, completed).await;
                    continue;
                }
                request = reconciliation_rx.recv(), if reconciliation_open => {
                    if let Some(request) = request {
                        enqueue_pending_reconciliation(&mut state, request);
                    } else {
                        reconciliation_open = false;
                    }
                    continue;
                }
                op = rx.recv() => op,
            }
        } else {
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow_and_update() {
                        drain_shutdown_reconciliation(
                            &mut state,
                            &mut rx,
                            &mut reconciliation_rx,
                            &mut allocations,
                        )
                        .await;
                        break;
                    }
                    continue;
                }
                completed = allocations.join_next(), if !allocations.is_empty() => {
                    handle_allocation_join(&mut state, completed).await;
                    continue;
                }
                request = reconciliation_rx.recv(), if reconciliation_open => {
                    if let Some(request) = request {
                        enqueue_pending_reconciliation(&mut state, request);
                    } else {
                        reconciliation_open = false;
                    }
                    continue;
                }
                op = rx.recv() => op,
                _ = tokio::time::sleep_until(
                    state.pending_reconciliation
                        .iter()
                        .map(|pending| pending.next_attempt)
                        .chain(state.pending_unpublished.iter().map(|pending| pending.next_attempt))
                        .min()
                        .expect("non-empty reconciliation queue has a deadline")
                ) => {
                    reconcile_one_pending(&mut state).await;
                    ordinary_op_burst = 0;
                    continue;
                }
            }
        };
        let Some(op) = op else {
            // Every sender disappeared without the explicit owner signal.
            // This is still a shutdown boundary: retain and reconcile all
            // live ownership before the actor thread exits.
            drain_shutdown_reconciliation(
                &mut state,
                &mut rx,
                &mut reconciliation_rx,
                &mut allocations,
            )
            .await;
            break;
        };
        ordinary_op_burst = ordinary_op_burst.saturating_add(1);
        match op {
            Op::SafeMetadata { reply } => {
                let _ = reply.send(state.adapter.safe_metadata());
            }
            Op::BeginShutdown { reply } => {
                state.intake_closed = true;
                // The accepted allocation set is part of the shutdown
                // snapshot. Defer acknowledgement until each allocation has
                // published or transferred to request-specific cleanup.
                begin_shutdown_waiters.push(reply);
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
                match prepare_native(
                    &mut state,
                    session_id,
                    operation_id,
                    program,
                    args,
                    cwd,
                    require_proven,
                    reply,
                )
                .await
                {
                    Ok(prepared) => {
                        let adapter = state.adapter.clone();
                        allocations.spawn(async move {
                            let result = adapter.create_and_spawn(prepared.request.clone()).await;
                            AllocationCompletion::Native { prepared, result }
                        });
                    }
                    Err((reply, error)) => {
                        let _ = reply.send(Err(error));
                    }
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
                cancellation,
                reply,
            } => {
                if cancellation.is_cancelled() {
                    let _ = reply.send(Err(ContainmentError::Internal(
                        "allocation request cancelled".into(),
                    )));
                    continue;
                }
                match prepare_native_with_io(
                    &mut state,
                    session_id,
                    operation_id,
                    program,
                    args,
                    env,
                    cwd,
                    require_proven,
                    cancellation,
                    reply,
                )
                .await
                {
                    Ok(prepared) => {
                        let adapter = state.adapter.clone();
                        allocations.spawn(async move {
                            let result = adapter
                                .create_and_spawn_with_io(prepared.request.clone())
                                .await;
                            AllocationCompletion::Io { prepared, result }
                        });
                    }
                    Err((reply, error)) => {
                        let _ = reply.send(Err(error));
                    }
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
                match prepare_container(
                    &mut state,
                    session_id,
                    operation_id,
                    image,
                    command,
                    installation_id,
                    nonce,
                    require_proven,
                    reply,
                )
                .await
                {
                    Ok(prepared) => {
                        let adapter = state.adapter.clone();
                        allocations.spawn(async move {
                            let result = adapter
                                .create_container_and_exec(prepared.request.clone())
                                .await;
                            AllocationCompletion::Container { prepared, result }
                        });
                    }
                    Err((reply, error)) => {
                        let _ = reply.send(Err(error));
                    }
                }
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

async fn finish_begin_shutdown(state: &mut ActorState, waiters: &mut Vec<Reply<()>>) {
    let leases: Vec<_> = state
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
    for lease in leases {
        let _ = terminate_one(state, lease).await;
    }
    for reply in waiters.drain(..) {
        let _ = reply.send(());
    }
}

fn enqueue_pending_reconciliation(state: &mut ActorState, request: ReconciliationRequest) {
    let completion = request.completion.map(ReconciliationCompletion::Empty);
    enqueue_pending_reconciliation_inner(state, request.lease, completion);
}

fn enqueue_pending_reconciliation_with_completion(
    state: &mut ActorState,
    lease: ContainmentLease,
    completion: ReconciliationCompletion,
) {
    enqueue_pending_reconciliation_inner(state, lease, Some(completion));
}

fn enqueue_pending_reconciliation_inner(
    state: &mut ActorState,
    lease: ContainmentLease,
    completion: Option<ReconciliationCompletion>,
) {
    if let Some(pending) = state.pending_reconciliation.iter_mut().find(|pending| {
        pending.lease.containment_id == lease.containment_id
            && pending.lease.generation == lease.generation
    }) {
        if let Some(completion) = completion {
            pending.waiters.push(completion);
        }
    } else {
        state.pending_reconciliation.push(PendingReconciliation {
            lease,
            waiters: completion.into_iter().collect(),
            next_attempt: tokio::time::Instant::now(),
            backoff: RECONCILIATION_INITIAL_BACKOFF,
        });
    }
}

async fn drain_shutdown_reconciliation(
    state: &mut ActorState,
    rx: &mut mpsc::Receiver<Op>,
    reconciliation_rx: &mut mpsc::UnboundedReceiver<ReconciliationRequest>,
    allocations: &mut tokio::task::JoinSet<AllocationCompletion>,
) {
    state.intake_closed = true;
    // Close ordinary intake at the shutdown observation boundary. Every
    // already-queued request receives a bounded terminal reply; new sends are
    // rejected by the closed channel instead of hanging behind reconciliation.
    rx.close();
    reject_queued_ops_after_shutdown(rx, &state.adapter);
    // Freeze cleanup intake before taking the live snapshot. `close` rejects
    // later ownership transfers; all requests accepted before this boundary
    // remain readable and are drained below.
    reconciliation_rx.close();
    while let Ok(request) = reconciliation_rx.try_recv() {
        enqueue_pending_reconciliation(state, request);
    }
    // Allocation tasks are actor-owned once accepted. Do not abort or drop
    // them at shutdown: an adapter may already have crossed its native spawn
    // boundary. Poll every task to completion, then route its exact request
    // through normal publication-or-reconciliation handling.
    while !allocations.is_empty() {
        let completed = allocations.join_next().await;
        handle_allocation_join(state, completed).await;
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
        enqueue_pending_reconciliation(state, ReconciliationRequest { lease, completion: None });
    }
    while !state.pending_reconciliation.is_empty() || !state.pending_unpublished.is_empty() {
        reconcile_one_pending(state).await;
        if !state.pending_reconciliation.is_empty() || !state.pending_unpublished.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

async fn handle_allocation_join(
    state: &mut ActorState,
    completed: Option<Result<AllocationCompletion, tokio::task::JoinError>>,
) {
    match completed {
        Some(Ok(AllocationCompletion::Native { prepared, result })) => {
            finish_native(state, prepared, result).await;
        }
        Some(Ok(AllocationCompletion::Io { prepared, result })) => {
            finish_native_with_io(state, prepared, result).await;
        }
        Some(Ok(AllocationCompletion::Container { prepared, result })) => {
            finish_container(state, prepared, result).await;
        }
        Some(Err(error)) => {
            // Adapter implementations are trusted daemon code. A panic is a
            // process-ownership invariant violation because the task's reply
            // and any not-yet-returned opaque handle were unwound together.
            tracing::error!(%error, "containment allocation task failed");
        }
        None => {}
    }
}

fn reject_queued_ops_after_shutdown(rx: &mut mpsc::Receiver<Op>, adapter: &SharedAdapter) {
    while let Ok(op) = rx.try_recv() {
        let error = || ContainmentError::ShutdownIntakeClosed;
        match op {
            Op::CreateAndSpawn { reply, .. }
            | Op::CreateContainerAndExec { reply, .. } => {
                let _ = reply.send(Err(error()));
            }
            Op::CreateAndSpawnWithIo { reply, .. } => {
                let _ = reply.send(Err(error()));
            }
            Op::Terminate { reply, .. }
            | Op::BeginSessionDeletion { reply, .. }
            | Op::FinishSessionDeletion { reply, .. }
            | Op::AwaitAllEmpty { reply, .. } => {
                let _ = reply.send(Err(error()));
            }
            Op::AwaitEmpty { reply, .. } => {
                let _ = reply.send(Err(error()));
            }
            Op::Recover { reply } => {
                let _ = reply.send(Err(error()));
            }
            Op::SafeMetadata { reply } => {
                let _ = reply.send(adapter.safe_metadata());
            }
            Op::BeginShutdown { reply } | Op::LateCallback { reply, .. } => {
                let _ = reply.send(());
            }
        }
    }
}

async fn reconcile_one_pending(state: &mut ActorState) {
    if let Some(index) = state
        .pending_unpublished
        .iter()
        .enumerate()
        .filter(|(_, pending)| pending.next_attempt <= tokio::time::Instant::now())
        .min_by_key(|(_, pending)| pending.next_attempt)
        .map(|(index, _)| index)
    {
        let mut pending = state.pending_unpublished.swap_remove(index);
        let _ = state.adapter.terminate(&pending.handle, pending.generation).await;
        let proven_empty = matches!(
            state.adapter.await_empty(&pending.handle, pending.generation).await,
            Ok(EmptyOutcome::ProvenEmpty { generation }) if generation == pending.generation
        );
        if proven_empty {
            let failed = match reduce(
                Some(pending.record.clone()),
                ContainmentEvent::CreateFailed {
                    generation: pending.generation,
                    now_wall_ms: wall_ms(),
                },
            ) {
                ReduceResult::Applied(record) => *record,
                other => {
                    tracing::error!(?other, "unpublished containment terminal reduction failed");
                    pending.next_attempt = tokio::time::Instant::now() + pending.backoff;
                    pending.backoff = pending.backoff.saturating_mul(2).min(RECONCILIATION_MAX_BACKOFF);
                    state.pending_unpublished.push(pending);
                    return;
                }
            };
            if persist_cas(state, &pending.record, &failed).await.is_err() {
                pending.next_attempt = tokio::time::Instant::now() + pending.backoff;
                pending.backoff = pending.backoff.saturating_mul(2).min(RECONCILIATION_MAX_BACKOFF);
                state.pending_unpublished.push(pending);
            } else {
                for waiter in pending.waiters {
                    match waiter {
                        UnpublishedCompletion::Lease(reply, error) => {
                            let _ = reply.send(Err(error));
                        }
                        UnpublishedCompletion::Io(reply, error) => {
                            let _ = reply.send(Err(error));
                        }
                    }
                }
            }
        } else {
            pending.next_attempt = tokio::time::Instant::now() + pending.backoff;
            pending.backoff = pending.backoff.saturating_mul(2).min(RECONCILIATION_MAX_BACKOFF);
            state.pending_unpublished.push(pending);
        }
        return;
    }
    let Some(index) = state
        .pending_reconciliation
        .iter()
        .enumerate()
        .min_by_key(|(_, pending)| pending.next_attempt)
        .map(|(index, _)| index)
    else {
        return;
    };
    let mut pending = state.pending_reconciliation.swap_remove(index);
    if pending.next_attempt > tokio::time::Instant::now() {
        state.pending_reconciliation.push(pending);
        return;
    }
    let lease = pending.lease.clone();
    let _ = terminate_one(state, lease.clone()).await;
    match await_empty_one(state, lease.clone()).await {
        Ok(EmptyOutcome::ProvenEmpty { generation }) if generation == lease.generation => {
            for waiter in pending.waiters {
                match waiter {
                    ReconciliationCompletion::Empty(waiter) => {
                        let _ = waiter.send(Ok(()));
                    }
                    ReconciliationCompletion::FailedLease(waiter, error) => {
                        let _ = waiter.send(Err(error));
                    }
                    ReconciliationCompletion::FailedIo(waiter, error) => {
                        let _ = waiter.send(Err(error));
                    }
                }
            }
        }
        // The actor remains the sole owner and retries later. Other actor
        // The actor remains responsive between bounded attempts, so a slow or
        // uncertain cleanup cannot become a queue-saturation spin. The
        // shutdown control branch retains absolute priority.
        _ => {
            pending.next_attempt = tokio::time::Instant::now() + pending.backoff;
            pending.backoff = pending
                .backoff
                .saturating_mul(2)
                .min(RECONCILIATION_MAX_BACKOFF);
            state.pending_reconciliation.push(pending);
        }
    }
}

async fn prepare_native(
    state: &mut ActorState,
    session_id: Uuid,
    operation_id: String,
    program: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    require_proven: bool,
    reply: Reply<Result<ContainmentLease, ContainmentError>>,
) -> Result<
    PreparedNativeAllocation,
    (
        Reply<Result<ContainmentLease, ContainmentError>>,
        ContainmentError,
    ),
> {
    if state.intake_closed {
        return Err((reply, ContainmentError::ShutdownIntakeClosed));
    }
    let deleting = match state.db.is_session_deleting(session_id).await {
        Ok(deleting) => deleting,
        Err(error) => {
            return Err((reply, ContainmentError::Internal(error.to_string())));
        }
    };
    if state.deleting_sessions.contains(&session_id) || deleting {
        return Err((reply, ContainmentError::SessionDeleting));
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
            return Err((
                reply,
                ContainmentError::Internal(format!("reduce: {other:?}")),
            ));
        }
    };
    if let Err(error) = persist_insert(state, &record).await {
        return Err((reply, error));
    }

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
            other => {
                return Err((
                    reply,
                    ContainmentError::Internal(format!("{other:?}")),
                ));
            }
        };
        if let Err(error) = persist_cas(state, &record, &rec).await {
            return Err((reply, error));
        }
        return Err((
            reply,
            ContainmentError::DescendantContainmentUnavailable { reason },
        ));
    }

    Ok(PreparedNativeAllocation {
        record,
        request: NativeSpawnRequest {
            containment_id,
            session_id,
            generation,
            operation_id,
            program,
            args,
            cwd,
            require_proven,
        },
        reply,
    })
}

async fn finish_native(
    state: &mut ActorState,
    prepared: PreparedNativeAllocation,
    result: Result<AllocatedContainment, ContainmentError>,
) {
    let PreparedNativeAllocation {
        mut record,
        request,
        reply,
    } = prepared;
    let containment_id = request.containment_id;
    let session_id = request.session_id;
    let generation = request.generation;
    let require_proven = request.require_proven;
    let allocated = match result {
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
                other => {
                    let _ = reply.send(Err(ContainmentError::Internal(format!(
                        "{other:?}"
                    ))));
                    return;
                }
            };
            let reply_result = match persist_cas(state, &record, &failed).await {
                Ok(()) => Err(error),
                Err(persist_error) => Err(persist_error),
            };
            let _ = reply.send(reply_result);
            return;
        }
    };

    let rollback_index = state.pending_unpublished.len();
    reclaim_unpublished_allocation(
        state,
        allocated.handle.clone(),
        record.clone(),
        generation,
    );

    if require_proven && allocated.guarantee != ContainmentGuarantee::Proven {
        state.pending_unpublished[rollback_index]
            .waiters
            .push(UnpublishedCompletion::Lease(
                reply,
                ContainmentError::DescendantContainmentUnavailable {
                    reason: "adapter returned a non-proven native allocation".into(),
                },
            ));
        return;
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
        other => {
            state.pending_unpublished[rollback_index]
                .waiters
                .push(UnpublishedCompletion::Lease(
                    reply,
                    ContainmentError::Internal(format!("{other:?}")),
                ));
            return;
        }
    };
    if let Err(error) = persist_cas_from_creating(state, &record).await {
        state.pending_unpublished[rollback_index]
            .waiters
            .push(UnpublishedCompletion::Lease(reply, error));
        return;
    }
    state.pending_unpublished.swap_remove(rollback_index);

    let token = Arc::new(LeaseToken::new(format!("lease-{containment_id}")));
    state.live.insert(
        containment_id,
        LiveEntry {
            record: record.clone(),
            handle: Some(allocated.handle),
            lease_token: token.clone(),
        },
    );
    let lease = ContainmentLease {
        containment_id,
        session_id,
        generation,
        guarantee: allocated.guarantee,
        token,
    };
    if state.intake_closed || state.deleting_sessions.contains(&session_id) {
        let error = if state.intake_closed {
            ContainmentError::ShutdownIntakeClosed
        } else {
            ContainmentError::SessionDeleting
        };
        enqueue_pending_reconciliation_with_completion(
            state,
            lease,
            ReconciliationCompletion::FailedLease(reply, error),
        );
    } else if let Err(Ok(lease)) = reply.send(Ok(lease)) {
        enqueue_pending_reconciliation(
            state,
            ReconciliationRequest {
                lease,
                completion: None,
            },
        );
    }
}

fn reclaim_unpublished_allocation(
    state: &mut ActorState,
    handle: AdapterHandle,
    record: ContainmentRecord,
    generation: u64,
) {
    state.pending_unpublished.push(PendingUnpublished {
        handle,
        record,
        generation,
        next_attempt: tokio::time::Instant::now(),
        backoff: RECONCILIATION_INITIAL_BACKOFF,
        waiters: Vec::new(),
    });
}

#[allow(clippy::too_many_arguments)]
async fn prepare_native_with_io(
    state: &mut ActorState,
    session_id: Uuid,
    operation_id: String,
    program: PathBuf,
    args: Vec<String>,
    env: std::collections::BTreeMap<String, String>,
    cwd: PathBuf,
    require_proven: bool,
    cancellation: tokio_util::sync::CancellationToken,
    reply: IoCreateReply,
) -> Result<PreparedIoAllocation, (IoCreateReply, ContainmentError)> {
    if state.intake_closed {
        return Err((reply, ContainmentError::ShutdownIntakeClosed));
    }
    let deleting = match state.db.is_session_deleting(session_id).await {
        Ok(deleting) => deleting,
        Err(error) => {
            return Err((reply, ContainmentError::Internal(error.to_string())));
        }
    };
    if state.deleting_sessions.contains(&session_id) || deleting {
        return Err((reply, ContainmentError::SessionDeleting));
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
    let record = match reduce(None, event) {
        ReduceResult::Applied(record) => *record,
        other => {
            return Err((
                reply,
                ContainmentError::Internal(format!("reduce: {other:?}")),
            ));
        }
    };
    if let Err(error) = persist_insert(state, &record).await {
        return Err((reply, error));
    }

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
            other => {
                return Err((
                    reply,
                    ContainmentError::Internal(format!("{other:?}")),
                ));
            }
        };
        if let Err(error) = persist_cas(state, &record, &unsupported).await {
            return Err((reply, error));
        }
        return Err((
            reply,
            ContainmentError::DescendantContainmentUnavailable { reason },
        ));
    }

    Ok(PreparedIoAllocation {
        record,
        request: NativeIoSpawnRequest {
            containment_id,
            session_id,
            generation,
            operation_id,
            program,
            args,
            cwd,
            env,
            capture_io: true,
            require_proven,
        },
        cancellation,
        reply,
    })
}

async fn finish_native_with_io(
    state: &mut ActorState,
    prepared: PreparedIoAllocation,
    result: Result<AllocatedNativeIo, ContainmentError>,
) {
    let PreparedIoAllocation {
        mut record,
        request,
        cancellation,
        reply,
    } = prepared;
    let containment_id = request.containment_id;
    let session_id = request.session_id;
    let generation = request.generation;
    let require_proven = request.require_proven;
    let allocated = match result {
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
                other => {
                    let _ = reply.send(Err(ContainmentError::Internal(format!(
                        "{other:?}"
                    ))));
                    return;
                }
            };
            let result = match persist_cas(state, &record, &failed).await {
                Ok(()) => Err(error),
                Err(persist_error) => Err(persist_error),
            };
            let _ = reply.send(result);
            return;
        }
    };

    let rollback_index = state.pending_unpublished.len();
    reclaim_unpublished_allocation(
        state,
        allocated.allocation.handle.clone(),
        record.clone(),
        generation,
    );

    if require_proven && allocated.allocation.guarantee != ContainmentGuarantee::Proven {
        state.pending_unpublished[rollback_index]
            .waiters
            .push(UnpublishedCompletion::Io(
                reply,
                ContainmentError::DescendantContainmentUnavailable {
                    reason: "adapter returned a non-proven IO allocation".into(),
                },
            ));
        return;
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
        other => {
            state.pending_unpublished[rollback_index]
                .waiters
                .push(UnpublishedCompletion::Io(
                    reply,
                    ContainmentError::Internal(format!("{other:?}")),
                ));
            return;
        }
    };
    if let Err(error) = persist_cas_from_creating(state, &record).await {
        state.pending_unpublished[rollback_index]
            .waiters
            .push(UnpublishedCompletion::Io(reply, error));
        return;
    }
    state.pending_unpublished.swap_remove(rollback_index);
    let token = Arc::new(LeaseToken::new(format!("lease-{containment_id}")));
    state.live.insert(
        containment_id,
        LiveEntry {
            record,
            handle: Some(allocated.allocation.handle),
            lease_token: token.clone(),
        },
    );
    let lease = ContainmentLease {
        containment_id,
        session_id,
        generation,
        guarantee: allocated.allocation.guarantee,
        token,
    };
    if cancellation.is_cancelled()
        || state.intake_closed
        || state.deleting_sessions.contains(&session_id)
    {
        let error = if state.intake_closed {
            ContainmentError::ShutdownIntakeClosed
        } else if state.deleting_sessions.contains(&session_id) {
            ContainmentError::SessionDeleting
        } else {
            ContainmentError::Internal("allocation request cancelled after cleanup".into())
        };
        enqueue_pending_reconciliation_with_completion(
            state,
            lease,
            ReconciliationCompletion::FailedIo(reply, error),
        );
    } else if let Err(Ok((lease, _io))) = reply.send(Ok((lease, allocated.io))) {
        enqueue_pending_reconciliation(
            state,
            ReconciliationRequest {
                lease,
                completion: None,
            },
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn prepare_container(
    state: &mut ActorState,
    session_id: Uuid,
    operation_id: String,
    image: String,
    command: Vec<String>,
    installation_id: String,
    nonce: String,
    require_proven: bool,
    reply: Reply<Result<ContainmentLease, ContainmentError>>,
) -> Result<
    PreparedContainerAllocation,
    (
        Reply<Result<ContainmentLease, ContainmentError>>,
        ContainmentError,
    ),
> {
    if state.intake_closed {
        return Err((reply, ContainmentError::ShutdownIntakeClosed));
    }
    let deleting = match state.db.is_session_deleting(session_id).await {
        Ok(deleting) => deleting,
        Err(error) => {
            return Err((reply, ContainmentError::Internal(error.to_string())));
        }
    };
    if state.deleting_sessions.contains(&session_id) || deleting {
        return Err((reply, ContainmentError::SessionDeleting));
    }

    let containment_id = Uuid::new_v4();
    let generation = 1u64;
    let now = wall_ms();
    let platform_kind = state.adapter.platform_kind();
    let guarantee = state.adapter.guarantee();

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
        other => {
            return Err((
                reply,
                ContainmentError::Internal(format!("{other:?}")),
            ));
        }
    };
    if let Err(error) = persist_insert(state, &record).await {
        return Err((reply, error));
    }

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
            other => {
                return Err((
                    reply,
                    ContainmentError::Internal(format!("{other:?}")),
                ));
            }
        };
        if let Err(error) = persist_cas(state, &record, &unsupported).await {
            return Err((reply, error));
        }
        return Err((
            reply,
            ContainmentError::DescendantContainmentUnavailable { reason },
        ));
    }

    Ok(PreparedContainerAllocation {
        record,
        request: ContainerExecRequest {
            containment_id,
            session_id,
            generation,
            operation_id,
            image,
            command,
            require_proven,
            installation_id,
            nonce,
        },
        reply,
    })
}

async fn finish_container(
    state: &mut ActorState,
    prepared: PreparedContainerAllocation,
    result: Result<AllocatedContainment, ContainmentError>,
) {
    let PreparedContainerAllocation {
        mut record,
        request,
        reply,
    } = prepared;
    let containment_id = request.containment_id;
    let session_id = request.session_id;
    let generation = request.generation;
    let require_proven = request.require_proven;
    let allocated = match result {
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
                other => {
                    let _ = reply.send(Err(ContainmentError::Internal(format!(
                        "{other:?}"
                    ))));
                    return;
                }
            };
            let reply_result = match persist_cas(state, &record, &failed).await {
                Ok(()) => Err(error),
                Err(persist_error) => Err(persist_error),
            };
            let _ = reply.send(reply_result);
            return;
        }
    };
    let rollback_index = state.pending_unpublished.len();
    reclaim_unpublished_allocation(
        state,
        allocated.handle.clone(),
        record.clone(),
        generation,
    );

    if require_proven && allocated.guarantee != ContainmentGuarantee::Proven {
        state.pending_unpublished[rollback_index]
            .waiters
            .push(UnpublishedCompletion::Lease(
                reply,
                ContainmentError::DescendantContainmentUnavailable {
                    reason: "adapter returned a non-proven container allocation".into(),
                },
            ));
        return;
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
        other => {
            state.pending_unpublished[rollback_index]
                .waiters
                .push(UnpublishedCompletion::Lease(
                    reply,
                    ContainmentError::Internal(format!("{other:?}")),
                ));
            return;
        }
    };
    if let Err(error) = persist_cas_from_creating(state, &record).await {
        state.pending_unpublished[rollback_index]
            .waiters
            .push(UnpublishedCompletion::Lease(reply, error));
        return;
    }
    state.pending_unpublished.swap_remove(rollback_index);

    let token = Arc::new(LeaseToken::new(format!("lease-{containment_id}")));
    state.live.insert(
        containment_id,
        LiveEntry {
            record: record.clone(),
            handle: Some(allocated.handle),
            lease_token: token.clone(),
        },
    );
    let lease = ContainmentLease {
        containment_id,
        session_id,
        generation,
        guarantee: allocated.guarantee,
        token,
    };
    if state.intake_closed || state.deleting_sessions.contains(&session_id) {
        let error = if state.intake_closed {
            ContainmentError::ShutdownIntakeClosed
        } else {
            ContainmentError::SessionDeleting
        };
        enqueue_pending_reconciliation_with_completion(
            state,
            lease,
            ReconciliationCompletion::FailedLease(reply, error),
        );
    } else if let Err(Ok(lease)) = reply.send(Ok(lease)) {
        enqueue_pending_reconciliation(
            state,
            ReconciliationRequest {
                lease,
                completion: None,
            },
        );
    }
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
    deadline: Option<Duration>,
) -> Result<(), ContainmentError> {
    let expires_at = deadline.map(|duration| tokio::time::Instant::now() + duration);
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
        let settle = async {
            let _ = terminate_one(state, lease.clone()).await;
            await_empty_one(state, lease).await
        };
        let outcome = match expires_at {
            Some(expires_at) => match tokio::time::timeout_at(expires_at, settle).await {
                Ok(result) => result?,
                Err(_) => break,
            },
            None => settle.await?,
        };
        match outcome {
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
