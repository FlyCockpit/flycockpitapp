use super::handle::*;
use super::helpers::*;
use super::lifecycle::*;
use super::*;
use anyhow::Context;
use sha2::{Digest, Sha256};

pub(super) const INTERRUPT_REDACTION_FAILED: &str = "[redaction failed]";

/// Poll cadence for the graceful-shutdown park-drain loop
/// (`daemon-lifecycle-replay-timing-robustness.md`, finding 2): after each
/// re-park it waits at most this long for the driver task to exit before
/// re-parking again, so a fresh interrupt the in-flight turn registers is
/// caught promptly. Bounded work; the drain path force-aborts the worker at its
/// own deadline regardless, so this never blocks shutdown indefinitely.
const PARK_DRAIN_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// An accepted oversized source has a ten-minute DB-owned lease. Startup and
/// individual dispatches reconcile it synchronously; this bounded worker tick
/// also prevents an idle session from retaining an expired reservation until a
/// later client submission happens to arrive.
const TEXT_ARTIFACT_RESERVATION_REAP_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);
/// A maintenance source may never monopolize the sole session worker. Each
/// turn takes a stable bounded slice; the next interval resumes from the
/// durable/local cursor while client work, replay completions and the other
/// maintenance classes remain selectable.
const AGENT_TREE_MAINTENANCE_ITEMS_PER_TURN: usize = 32;
/// Publication has a global generation fence, so one bounded page must be
/// fully acknowledged before an allowed operation may reserve a newer probe.
/// The periodic refresh arm schedules another page when this returns `more`.
const HOST_CAPABILITY_REFRESH_OUTBOX_ITEMS_PER_TURN: usize = 32;

/// A refresh probe is a short local operation.  An executing row is owned by
/// the process that claimed it, but that owner can be lost without a restart
/// (for example after a task panic or a DB completion error).  Reap only after
/// this bounded lease; live execution has its own immediate completion/failure
/// path below.
const HOST_CAPABILITY_REFRESH_EXECUTION_LEASE: std::time::Duration =
    std::time::Duration::from_secs(60);
/// A claim is renewed while the probe future is pending. This is deliberately
/// shorter than the durable execution lease so a live local probe remains
/// owned even if periodic worker housekeeping runs concurrently.
const HOST_CAPABILITY_REFRESH_EXECUTION_HEARTBEAT_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(20);
const HOST_CAPABILITY_REFRESH_REAPER_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(10);
/// How often the trust-transition drain re-reads the admission gate while no
/// work arrives. The gate is cleared asynchronously by the applied follow-up
/// task, which has no channel into this loop, so the drain cannot rely on new
/// work to wake it. This bounds only the delay between application and the
/// worker resuming buffered work; queued work still wakes the drain instantly.
const TRUST_TRANSITION_GATE_RECHECK: std::time::Duration = std::time::Duration::from_millis(50);
/// A host-operation child is safe to leave unattached during boot only when a
/// concurrent terminalizer has already removed its executable continuation.
/// Missing rows, failed reads, and every live state make root activation
/// unsafe: this epoch must return before it can release the foreground root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostOperationRecoveryReload {
    ConcurrentlyTerminal,
    StillNonterminal,
    Missing,
    LoadFailed,
}

fn classify_host_operation_recovery_reload(
    state: std::result::Result<Option<crate::db::agent_tree_decisions::AgentInstanceState>, ()>,
) -> HostOperationRecoveryReload {
    match state {
        Ok(Some(state)) if state.is_terminal() => HostOperationRecoveryReload::ConcurrentlyTerminal,
        Ok(Some(_)) => HostOperationRecoveryReload::StillNonterminal,
        Ok(None) => HostOperationRecoveryReload::Missing,
        Err(()) => HostOperationRecoveryReload::LoadFailed,
    }
}

fn terminal_host_operation_interrupt_requires_repair(
    state: crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState,
) -> bool {
    matches!(
        state,
        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Completed
            | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Failed
            | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Cancelled
    )
}

/// Holds the one daemon-local dispatch right for a durable refresh operation.
/// The set itself belongs to the shared capability store, so independently
/// constructed session runtimes observe the same owner.  Keeping this guard
/// alive while a direct request waits for its decision closes the small race
/// where the periodic allowed-operation scanner could otherwise spawn a
/// second task for the very same operation.
struct HostCapabilityRefreshDispatchGuard {
    in_flight_operations: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    operation_id: uuid::Uuid,
}

impl HostCapabilityRefreshDispatchGuard {
    fn claim(runtime: &HostCapabilityRefreshRuntime, operation_id: uuid::Uuid) -> Option<Self> {
        let admitted = runtime
            .in_flight_operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(operation_id);
        admitted.then(|| Self {
            in_flight_operations: runtime.in_flight_operations.clone(),
            operation_id,
        })
    }
}

impl Drop for HostCapabilityRefreshDispatchGuard {
    fn drop(&mut self) {
        self.in_flight_operations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.operation_id);
    }
}

fn canonical_host_capability_refresh_receipt(
    snapshot: &cockpit_proto::HostCapabilitySnapshot,
) -> std::result::Result<
    crate::db::agent_tree_decisions::HostCapabilityRefreshSnapshotReceipt,
    String,
> {
    if snapshot.generation == 0 {
        return Err("host capability refresh snapshot generation must be positive".to_string());
    }
    let value = serde_json::to_value(snapshot)
        .map_err(|error| format!("serializing host capability refresh snapshot failed: {error}"))?;
    let canonical =
        crate::db::agent_tree_decisions::canonical_json_bytes(&value).map_err(|error| {
            format!("canonicalizing host capability refresh snapshot failed: {error}")
        })?;
    let result_snapshot_json = String::from_utf8(canonical.clone()).map_err(|error| {
        format!("canonical host capability refresh snapshot was not UTF-8: {error}")
    })?;
    let digest = Sha256::digest(&canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(
        crate::db::agent_tree_decisions::HostCapabilityRefreshSnapshotReceipt {
            result_snapshot_json,
            generation: snapshot.generation,
            digest,
        },
    )
}

/// Recovery attachment must never make the sole worker await a full driver
/// mailbox. A bounded retry keeps the accepted durable checkpoint owned while
/// a just-started driver drains its bootstrap controls; exhaustion leaves the
/// row accepted for the next boot rather than releasing/redelivering it.
const ACCEPTED_LATE_STEER_RECOVERY_RETRY_ATTEMPTS: u8 = 8;
const ACCEPTED_LATE_STEER_RECOVERY_RETRY_DELAY: std::time::Duration =
    std::time::Duration::from_millis(25);

/// Make one durably completed capability refresh visible and acknowledge its
/// publication outbox. `source_session_id` belongs to the durable row, while
/// `session` is only the daemon worker that happened to win the store-wide
/// dispatcher lease. Every session uses the same database and global event
/// bus, so a live worker may safely recover an older receipt owned by a
/// stopped session.
async fn publish_one_completed_host_capability_refresh_operation_while_serialized(
    session: &std::sync::Arc<crate::session::Session>,
    source_session_id: uuid::Uuid,
    operation_id: uuid::Uuid,
    receipt: crate::db::agent_tree_decisions::HostCapabilityRefreshSnapshotReceipt,
    runtime: &HostCapabilityRefreshRuntime,
    global_bus: &Option<EventSender>,
    redaction: &SharedRedactionTable,
) -> std::result::Result<HostCapabilitiesRefreshCompletion, String> {
    // Parse and canonicalize before changing the store. The database also
    // validates this at completion, but an outbox reader must treat the
    // persisted receipt as hostile/corrupt until its bytes, digest, and
    // declared generation agree exactly.
    let snapshot: cockpit_proto::HostCapabilitySnapshot =
        serde_json::from_str(&receipt.result_snapshot_json).map_err(|error| {
            format!("durable host capability refresh result is invalid: {error}")
        })?;
    if snapshot.generation != receipt.generation {
        return Err(format!(
            "durable host capability refresh generation {} disagrees with receipt generation {}",
            snapshot.generation, receipt.generation
        ));
    }
    let value = serde_json::to_value(&snapshot).map_err(|error| {
        format!("serializing durable host capability refresh snapshot failed: {error}")
    })?;
    let canonical =
        crate::db::agent_tree_decisions::canonical_json_bytes(&value).map_err(|error| {
            format!("canonicalizing durable host capability refresh snapshot failed: {error}")
        })?;
    let canonical_json = std::str::from_utf8(&canonical).map_err(|error| {
        format!("canonical host capability refresh snapshot was not UTF-8: {error}")
    })?;
    let digest = Sha256::digest(&canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if canonical_json != receipt.result_snapshot_json || digest != receipt.digest {
        return Err(
            "durable host capability refresh receipt bytes do not match its canonical digest"
                .to_string(),
        );
    }
    let published = runtime.store.publish_committed(snapshot.clone()).map_err(|error| {
        format!(
            "refusing to acknowledge host capability refresh outbox because its committed snapshot is not live: {error}"
        )
    })?;
    let outbox_acked = session
        .db
        .mark_host_capability_refresh_published(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            source_session_id,
            operation_id,
            receipt.generation,
            receipt.digest.clone(),
            crate::agent_tree::system_now_unix_ms(),
        )
        .await
        .map_err(|error| {
            format!("acknowledging host capability refresh publication failed: {error}")
        })?;
    if outbox_acked {
        // The durable acknowledgement, not the in-memory `published` flag,
        // owns the one event.  In the crash-after-swap case `published` is
        // false on recovery but this is still the first durable publication
        // acknowledgement and therefore the one event emission.
        if let Some(global_bus) = global_bus {
            crate::daemon::send_current_event(
                global_bus,
                redaction,
                proto::Event::HostCapabilitiesChanged {
                    snapshot: snapshot.clone(),
                },
            );
        }
    }
    Ok(HostCapabilitiesRefreshCompletion {
        snapshot,
        published,
    })
}

/// Drain the single durable refresh outbox for every session which shares the
/// process-wide snapshot store. The database supplies rows in snapshot-
/// generation order, and this function retains `serial_execution` for the
/// entire scan: N becomes live and is acknowledged before N+1 is considered.
///
async fn drain_completed_host_capability_refresh_outbox_while_serialized(
    session: &std::sync::Arc<crate::session::Session>,
    runtime: &HostCapabilityRefreshRuntime,
    global_bus: &Option<EventSender>,
    redaction: &SharedRedactionTable,
) -> std::result::Result<
    Option<crate::db::agent_tree_decisions::HostCapabilityRefreshOutboxCursor>,
    String,
> {
    // Do not retain a global outbox backlog in memory. Each row is
    // acknowledged before the next maintenance turn asks SQLite for the next
    // keyset page; this also keeps generation order a durable fence rather
    // than a best-effort iterator property.
    let completed = session
        .db
        .completed_unpublished_host_capability_refresh_operations_page(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            None,
            HOST_CAPABILITY_REFRESH_OUTBOX_ITEMS_PER_TURN,
        )
        .await
        .map_err(|error| {
            format!("listing global host capability refresh publication outbox failed: {error}")
        })?;
    let next_cursor = completed.next_cursor;
    for operation in completed.entries {
        let result_snapshot_json = operation.result_snapshot_json.ok_or_else(|| {
            format!(
                "completed host capability refresh {} has no durable snapshot",
                operation.operation_id
            )
        })?;
        let generation = operation.result_snapshot_generation.ok_or_else(|| {
            format!(
                "completed host capability refresh {} has no durable generation",
                operation.operation_id
            )
        })?;
        let digest = operation.result_snapshot_digest.ok_or_else(|| {
            format!(
                "completed host capability refresh {} has no durable digest",
                operation.operation_id
            )
        })?;
        publish_one_completed_host_capability_refresh_operation_while_serialized(
            session,
            operation.session_id,
            operation.operation_id,
            crate::db::agent_tree_decisions::HostCapabilityRefreshSnapshotReceipt {
                result_snapshot_json,
                generation,
                digest,
            },
            runtime,
            global_bus,
            redaction,
        )
        .await?;
    }
    // The worker intentionally restarts its next query at the durable head:
    // every row through `next_cursor` was individually acknowledged above,
    // so that re-read cannot skip a concurrently committed successor. The
    // returned cursor remains the exact ordered proof that this turn stopped
    // at a bounded page boundary; `Some` is the reschedule/fence signal.
    Ok(next_cursor)
}

/// Cross the one durable host-capability refresh probe boundary.  The claim
/// occurs immediately before the local probe; all success/failure outcomes
/// then become durable before a live RPC receiver is notified.  Startup uses
/// this same function for an already-allowed operation, so recovery cannot
/// manufacture a fresh request or decision.
fn host_capability_refresh_execution_lease_expires_at(now_unix_ms: i64) -> i64 {
    now_unix_ms.saturating_add(
        i64::try_from(HOST_CAPABILITY_REFRESH_EXECUTION_LEASE.as_millis()).unwrap_or(i64::MAX),
    )
}

/// Run the probe while periodically extending its exact durable execution
/// lease. A probe can outlast the nominal lease under host contention; the
/// heartbeat proves its task is still alive. If renewal loses an owner or
/// revision fence, drop the staged result without publication.
async fn stage_host_capability_refresh_with_execution_heartbeat(
    session: &std::sync::Arc<crate::session::Session>,
    operation_id: uuid::Uuid,
    lease: &crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionLease,
    runtime: &HostCapabilityRefreshRuntime,
) -> std::result::Result<crate::host_capabilities::StagedHostCapabilityRefresh, String> {
    let stage = crate::host_capabilities::stage_host_capabilities_refresh_at_generation(
        &runtime.store,
        &runtime.probes,
        lease.snapshot_generation(),
    );
    tokio::pin!(stage);
    let mut heartbeat = tokio::time::interval_at(
        tokio::time::Instant::now() + HOST_CAPABILITY_REFRESH_EXECUTION_HEARTBEAT_INTERVAL,
        HOST_CAPABILITY_REFRESH_EXECUTION_HEARTBEAT_INTERVAL,
    );
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            staged = &mut stage => return staged,
            _ = heartbeat.tick() => {
                let now = crate::agent_tree::system_now_unix_ms();
                let renewed = session
                    .db
                    .renew_host_capability_refresh_execution_lease(
                        crate::agent_tree::daemon_host_capability_refresh_authority(),
                        session.id,
                        operation_id,
                        lease,
                        host_capability_refresh_execution_lease_expires_at(now),
                        now,
                    )
                    .await
                    .map_err(|error| format!("renewing host capability refresh execution lease failed: {error}"))?;
                if !renewed {
                    return Err(
                        "host capability refresh lost its execution lease before probe completion"
                            .to_string(),
                    );
                }
            }
        }
    }
}

async fn execute_host_capability_refresh_operation(
    session: &std::sync::Arc<crate::session::Session>,
    operation_id: uuid::Uuid,
    runtime: &HostCapabilityRefreshRuntime,
    global_bus: &Option<EventSender>,
    redaction: &SharedRedactionTable,
) -> std::result::Result<HostCapabilitiesRefreshCompletion, String> {
    // Keep the whole operation linearized with publication, not merely the
    // probe.  If two approved refreshes race, generation N must complete and
    // acknowledge before N+1 can reserve/stage/publish its snapshot.
    // A dispatcher gets one bounded attempt.  An in-flight durable owner is
    // not a reason to park an unbounded task per RPC/maintenance call; the
    // registry admits one task per operation and the periodic reaper tick
    // retries after a receipt becomes publishable or a stale lease is fenced.
    let _serial_execution = runtime.serial_execution.lock().await;
    execute_host_capability_refresh_operation_while_serialized(
        session,
        operation_id,
        runtime,
        global_bus,
        redaction,
    )
    .await
}

async fn execute_host_capability_refresh_operation_while_serialized(
    session: &std::sync::Arc<crate::session::Session>,
    operation_id: uuid::Uuid,
    runtime: &HostCapabilityRefreshRuntime,
    global_bus: &Option<EventSender>,
    redaction: &SharedRedactionTable,
) -> std::result::Result<HostCapabilitiesRefreshCompletion, String> {
    // Before a new probe can reserve its generation, make every older
    // completed receipt from every session sharing this store visible. This
    // is also what lets a live request from session B unblock a crashed
    // session A whose durable completion is waiting only for outbox replay.
    if drain_completed_host_capability_refresh_outbox_while_serialized(
        session, runtime, global_bus, redaction,
    )
    .await?
    .is_some()
    {
        // A later probe is forbidden until every older publication receipt
        // has been acknowledged. The periodic maintenance arm retries the
        // next bounded page; returning here leaves this operation `allowed`.
        return Err(
            "host capability refresh publication outbox has additional older entries".to_string(),
        );
    }
    let now = crate::agent_tree::system_now_unix_ms();
    match session
        .db
        .claim_host_capability_refresh_execution(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            session.id,
            operation_id,
            uuid::Uuid::new_v4(),
            host_capability_refresh_execution_lease_expires_at(now),
            now,
        )
        .await
        .map_err(|error| error.to_string())?
    {
        crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Claimed { lease } => {
            // A probe is read-only, but publication is externally observable.
            // Stage it first, commit the exact durable terminal receipt, and
            // only then swap it into the live capability store. A cancellation
            // or DB failure between these steps therefore cannot leak a
            // successful snapshot whose operation is durably failed.
            return match stage_host_capability_refresh_with_execution_heartbeat(
                session,
                operation_id,
                &lease,
                runtime,
            )
            .await
            {
                Ok(staged) => {
                    let receipt = canonical_host_capability_refresh_receipt(staged.snapshot())?;
                    if receipt.generation != lease.snapshot_generation() {
                        return Err(format!(
                            "host capability refresh staged generation {} does not match durable reservation {}",
                            receipt.generation,
                            lease.snapshot_generation()
                        ));
                    }
                    let completed = match session
                        .db
                        .complete_host_capability_refresh_execution(
                            crate::agent_tree::daemon_host_capability_refresh_authority(),
                            session.id,
                            operation_id,
                            &lease,
                            receipt.result_snapshot_json,
                            receipt.generation,
                            receipt.digest,
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await
                    {
                        Ok(completed) => completed,
                        Err(error) => {
                            // Do not leave an executing operation stranded
                            // merely because its receipt write failed. A
                            // transport/connection error can be ambiguous:
                            // the completion transaction may have won even
                            // though this caller did not receive its OK.
                            // Re-read the durable state before attempting a
                            // failure repair so the live RPC returns the
                            // actual completed receipt in that branch.
                            let message = format!(
                                "persisting host capability refresh completion failed: {error}"
                            );
                            match session
                                    .db
                                    .claim_host_capability_refresh_execution(
                                        crate::agent_tree::daemon_host_capability_refresh_authority(),
                                        session.id,
                                        operation_id,
                                        uuid::Uuid::new_v4(),
                                        host_capability_refresh_execution_lease_expires_at(
                                            crate::agent_tree::system_now_unix_ms(),
                                        ),
                                        crate::agent_tree::system_now_unix_ms(),
                                    )
                                    .await
                                {
                                    Ok(crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Completed {
                                        receipt,
                                    }) => {
                                        return publish_one_completed_host_capability_refresh_operation_while_serialized(
                                            session,
                                            session.id,
                                            operation_id,
                                            receipt,
                                            runtime,
                                            global_bus,
                                            redaction,
                                        )
                                        .await;
                                    }
                                    Ok(crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Failed {
                                        error_text,
                                    })
                                    | Ok(crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Cancelled {
                                        error_text,
                                    }) => return Err(error_text),
                                    Ok(
                                        crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Claimed { .. }
                                        | crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::InFlight
                                        | crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::NotReady,
                                    ) => {}
                                    Err(recovery_error) => {
                                        tracing::error!(%recovery_error, operation_id = %operation_id, "reading ambiguous host capability refresh completion failed; attempting terminal repair");
                                    }
                                }
                            // The completion did not leave a durable
                            // terminal receipt. The immediate repair is
                            // the fast path; the periodic lease reaper
                            // below remains the fallback if this second
                            // write also fails.
                            if let Err(repair_error) = session
                                .db
                                .fail_host_capability_refresh_execution(
                                    crate::agent_tree::daemon_host_capability_refresh_authority(),
                                    session.id,
                                    operation_id,
                                    &lease,
                                    message.clone(),
                                    crate::agent_tree::system_now_unix_ms(),
                                )
                                .await
                            {
                                tracing::error!(%repair_error, operation_id = %operation_id, "host capability refresh completion repair also failed; lease reaper retains recovery ownership");
                            }
                            return Err(message);
                        }
                    };
                    if !completed {
                        // A cancellation or newer owner revision won the
                        // completion fence. Preserve that durable loser for
                        // recovery and, crucially, drop the staged snapshot
                        // without publishing it.
                        let _ = session
                            .db
                            .fail_host_capability_refresh_execution(
                                crate::agent_tree::daemon_host_capability_refresh_authority(),
                                session.id,
                                operation_id,
                                &lease,
                                "host capability refresh lost its owner completion fence"
                                    .to_string(),
                                crate::agent_tree::system_now_unix_ms(),
                            )
                            .await;
                        return Err(
                            "host capability refresh lost its owner completion fence".to_string()
                        );
                    }
                    // Re-read the persisted receipt through the same
                    // outbox publication path recovery uses.  The staged
                    // value is intentionally dropped here: the committed
                    // bytes, not an in-memory probe result, are now the
                    // only authority for publication after this boundary.
                    drop(staged);
                    let operation = session
                        .db
                        .claim_host_capability_refresh_execution(
                            crate::agent_tree::daemon_host_capability_refresh_authority(),
                            session.id,
                            operation_id,
                            uuid::Uuid::new_v4(),
                            host_capability_refresh_execution_lease_expires_at(
                                crate::agent_tree::system_now_unix_ms(),
                            ),
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                    let crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Completed {
                            receipt,
                        } = operation else {
                            return Err("host capability refresh completion receipt disappeared before publication".to_string());
                        };
                    publish_one_completed_host_capability_refresh_operation_while_serialized(
                        session,
                        session.id,
                        operation_id,
                        receipt,
                        runtime,
                        global_bus,
                        redaction,
                    )
                    .await
                }
                Err(error) => {
                    let _ = session
                        .db
                        .fail_host_capability_refresh_execution(
                            crate::agent_tree::daemon_host_capability_refresh_authority(),
                            session.id,
                            operation_id,
                            &lease,
                            error.clone(),
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await;
                    Err(error)
                }
            };
        }
        crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Completed {
            receipt,
        } => {
            return publish_one_completed_host_capability_refresh_operation_while_serialized(
                session,
                session.id,
                operation_id,
                receipt,
                runtime,
                global_bus,
                redaction,
            )
            .await;
        }
        crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::InFlight => {
            // A durable owner already holds the probe boundary. Return
            // promptly; the bounded maintenance scheduler retries this
            // operation after the owner publishes or its lease is fenced.
            Err("host capability refresh is already in flight".to_string())
        }
        crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Failed {
            error_text,
        }
        | crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::Cancelled {
            error_text,
        } => return Err(error_text),
        crate::db::agent_tree_decisions::HostCapabilityRefreshExecutionClaim::NotReady => Err(
            "host capability refresh is not terminally allowed for this probe boundary".to_string(),
        ),
    }
}

/// Drain the daemon-global completion outbox, then schedule this session's
/// operations that have already crossed their durable allow decision but not
/// their probe boundary. This is used both at worker startup and immediately
/// after a terminal decision: a worker for session B can recover an older
/// completed receipt from session A before B stages a later generation.
async fn spawn_ready_host_capability_refresh_operations(
    session: &std::sync::Arc<crate::session::Session>,
    runtime: Option<HostCapabilityRefreshRuntime>,
    global_bus: &Option<EventSender>,
    redaction: &SharedRedactionTable,
    registry: &Arc<WorkerAgentTreeResolverRegistry>,
    terminalization_failure_fence: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let Some(runtime) = runtime else {
        return;
    };
    {
        // One store-wide dispatcher drains every session's durable receipts
        // synchronously. Do not spawn one publisher per session or receipt:
        // that would let a reverse startup order race the generation order.
        let _serial_execution = runtime.serial_execution.lock().await;
        let next_outbox_cursor =
            match drain_completed_host_capability_refresh_outbox_while_serialized(
                session, &runtime, global_bus, redaction,
            )
            .await
            {
                Ok(next_cursor) => next_cursor,
                Err(error) => {
                    tracing::warn!(%error, session_id = %session.id, "draining global host capability refresh publication outbox failed");
                    // A bad or inaccessible older receipt is a durable fence. Do not
                    // schedule a newer local probe until a later tick can repair it.
                    return;
                }
            };
        if next_outbox_cursor.is_some() {
            // The daemon's periodic refresh maintenance arm owns the next
            // rescheduled page. Do not inspect allowed work while any older
            // completed receipt remains unacknowledged.
            return;
        }
    }
    let after = runtime
        .store
        .refresh_allowed_operation_cursor(session.id)
        .map(
            |(created_at_unix_ms, id)| crate::db::agent_tree_decisions::AgentTreePageCursor {
                created_at_unix_ms,
                id,
            },
        );
    let operations = match session
        .db
        .ready_host_capability_refresh_operations_page(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            session.id,
            after,
            AGENT_TREE_MAINTENANCE_ITEMS_PER_TURN,
        )
        .await
    {
        Ok(operations) => operations,
        Err(error) => {
            tracing::warn!(%error, session_id = %session.id, "listing allowed host capability refreshes failed");
            return;
        }
    };
    runtime.store.set_refresh_allowed_operation_cursor(
        session.id,
        operations
            .next_cursor
            .as_ref()
            .map(|cursor| (cursor.created_at_unix_ms, cursor.id)),
    );
    for operation in operations.entries {
        let Some(dispatch_guard) =
            HostCapabilityRefreshDispatchGuard::claim(&runtime, operation.operation_id)
        else {
            continue;
        };
        let recovery_session = session.clone();
        let recovery_runtime = runtime.clone();
        let recovery_global_bus = global_bus.clone();
        let recovery_redaction = redaction.clone();
        let recovery_registry = registry.clone();
        let recovery_terminalization_failure_fence = terminalization_failure_fence.clone();
        tokio::spawn(async move {
            let _dispatch_guard = dispatch_guard;
            let execution = execute_host_capability_refresh_operation(
                &recovery_session,
                operation.operation_id,
                &recovery_runtime,
                &recovery_global_bus,
                &recovery_redaction,
            )
            .await;
            let finalization = finalize_terminal_host_capability_refresh_operation(
                &recovery_session,
                operation.operation_id,
                &recovery_registry,
            )
            .await;
            match finalization {
                HostCapabilityRefreshInterruptFinalization::Finalized
                | HostCapabilityRefreshInterruptFinalization::NonterminalRetryable => {}
                HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure
                | HostCapabilityRefreshInterruptFinalization::NotTyped => {
                    // The probe has already reached its durable operation
                    // state; do not issue it again. Instead force this worker
                    // epoch to stop before it can release more continuations
                    // while the exact child/Attention pair remains retained.
                    fence_host_capability_terminalization_failure(
                        &recovery_terminalization_failure_fence,
                    );
                }
            }
            if let Err(error) = execution {
                tracing::warn!(
                    %error,
                    operation_id = %operation.operation_id,
                    "executing durable host capability refresh failed"
                );
            }
        });
    }
}

fn host_capability_refresh_terminal_child_state(
    state: crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState,
) -> Option<crate::db::agent_tree_decisions::AgentInstanceState> {
    match state {
        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Completed => {
            Some(crate::db::agent_tree_decisions::AgentInstanceState::Completed)
        }
        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Failed => {
            Some(crate::db::agent_tree_decisions::AgentInstanceState::Failed)
        }
        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Cancelled => {
            Some(crate::db::agent_tree_decisions::AgentInstanceState::Cancelled)
        }
        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Pending
        | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Allowed
        | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Executing => None,
    }
}

/// The only outcome that permits an operation's endpoint and Attention row to
/// be released.  In particular, a revision race is not enough: its reload
/// must prove the exact child reached the terminal state dictated by the
/// operation.  A mismatched terminal row is corrupt (or has a different
/// terminal authority) and must remain visible for durable repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostCapabilityRefreshChildTerminalization {
    Verified,
    NotDedicatedChild,
    Missing,
    StillNonterminal,
    IncompatibleTerminal,
    StorageFailure,
}

impl HostCapabilityRefreshChildTerminalization {
    fn permits_terminal_cleanup(self) -> bool {
        self == Self::Verified
    }
}

fn consume_host_capability_terminalization_failure_fence(
    fence: &std::sync::atomic::AtomicBool,
) -> bool {
    fence.swap(false, std::sync::atomic::Ordering::AcqRel)
}

/// A terminal host-refresh operation whose exact child/Attention cleanup could
/// not be verified must stop this epoch before it releases another
/// continuation. Recovery owns the retained durable pair.
fn fence_host_capability_terminalization_failure(fence: &std::sync::atomic::AtomicBool) {
    fence.store(true, std::sync::atomic::Ordering::Release);
}

fn classify_host_capability_refresh_terminal_child(
    expected: crate::db::agent_tree_decisions::AgentInstanceState,
    reloaded: std::result::Result<Option<crate::db::agent_tree_decisions::AgentInstanceState>, ()>,
) -> HostCapabilityRefreshChildTerminalization {
    match reloaded {
        Ok(Some(actual)) if actual == expected => {
            HostCapabilityRefreshChildTerminalization::Verified
        }
        Ok(Some(actual)) if actual.is_terminal() => {
            HostCapabilityRefreshChildTerminalization::IncompatibleTerminal
        }
        Ok(Some(_)) => HostCapabilityRefreshChildTerminalization::StillNonterminal,
        Ok(None) => HostCapabilityRefreshChildTerminalization::Missing,
        Err(()) => HostCapabilityRefreshChildTerminalization::StorageFailure,
    }
}

/// Terminalize exactly the dedicated child owned by the durable operation.
/// A transition CAS can race a root cancellation or another terminalizer; a
/// conflict is accepted only after reloading the exact row and proving its
/// terminal state is the one the durable operation requires.
async fn terminalize_host_capability_refresh_child(
    session: &crate::session::Session,
    agent_instance_id: uuid::Uuid,
    state: crate::db::agent_tree_decisions::AgentInstanceState,
    receipt: &'static str,
) -> HostCapabilityRefreshChildTerminalization {
    let agent = match session
        .db
        .agent_instance(session.id, agent_instance_id)
        .await
    {
        Ok(Some(agent)) => agent,
        Ok(None) => return HostCapabilityRefreshChildTerminalization::Missing,
        Err(error) => {
            tracing::warn!(%error, %agent_instance_id, "loading host capability refresh child for terminalization failed");
            return HostCapabilityRefreshChildTerminalization::StorageFailure;
        }
    };
    if agent.parent_agent_instance_id.is_none() {
        // The squashed schema only admits dedicated children.  Never let a
        // malformed/imported root-owned operation detach the foreground root
        // or acknowledge its Attention row.
        return HostCapabilityRefreshChildTerminalization::NotDedicatedChild;
    }
    if agent.state.is_terminal() {
        return classify_host_capability_refresh_terminal_child(state, Ok(Some(agent.state)));
    }
    match session
        .db
        .transition_agent_instance(
            session.id,
            agent_instance_id,
            agent.revision,
            state,
            receipt,
            crate::agent_tree::system_now_unix_ms(),
        )
        .await
    {
        Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(agent)) => {
            classify_host_capability_refresh_terminal_child(state, Ok(Some(agent.state)))
        }
        Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::AlreadyTerminal(receipt)) => {
            // `transition_agent_instance` proves the receipt belongs to this
            // exact child/session. Compare its durable terminal state rather
            // than treating any terminal winner as interchangeable.
            if receipt.terminal_state == state.as_str() {
                HostCapabilityRefreshChildTerminalization::Verified
            } else {
                HostCapabilityRefreshChildTerminalization::IncompatibleTerminal
            }
        }
        Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::RevisionConflict) => {
            let reloaded = session
                .db
                .agent_instance(session.id, agent_instance_id)
                .await
                .map(|row| row.map(|agent| agent.state))
                .map_err(|_| ());
            classify_host_capability_refresh_terminal_child(state, reloaded)
        }
        Err(error) => {
            tracing::warn!(%error, %agent_instance_id, "terminalizing host capability refresh child failed");
            HostCapabilityRefreshChildTerminalization::StorageFailure
        }
    }
}

/// The direct refresh ingress creates a child and its pre-bind descriptor
/// before it can raise the real QuestionTool interrupt. Every local failure
/// in that interval must close the exact descriptor transactionally rather
/// than terminalizing only the child and leaving boot to discover stale work.
async fn abort_unbound_host_capability_refresh_initialization(
    session: &crate::session::Session,
    operation: crate::agent_tree::HostCapabilitiesRefreshOperation,
    agent_instance_id: uuid::Uuid,
    failure_stage: &'static str,
) {
    match session
        .db
        .abort_host_capability_refresh_initialization(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            session.id,
            operation.operation_id,
            operation.request_id,
            agent_instance_id,
            None,
            crate::agent_tree::system_now_unix_ms(),
        )
        .await
    {
        Ok(crate::db::agent_tree_decisions::HostCapabilityRefreshInitializationAbort::Aborted) => {}
        Ok(
            crate::db::agent_tree_decisions::HostCapabilityRefreshInitializationAbort::AlreadyBound,
        ) => {
            // Never undo an operation that crossed the atomic bind. Its
            // durable decision/operation finalizer owns the exact-once result
            // even if a caller observed an ambiguous local failure.
            tracing::warn!(
                operation_id = %operation.operation_id,
                request_id = %operation.request_id,
                %failure_stage,
                "pre-bind refresh cleanup observed an already-bound operation; preserving durable finalization"
            );
        }
        Ok(outcome) => {
            tracing::warn!(
                operation_id = %operation.operation_id,
                request_id = %operation.request_id,
                ?outcome,
                %failure_stage,
                "pre-bind refresh cleanup did not find a live matching initialization"
            );
        }
        Err(error) => {
            tracing::error!(
                %error,
                operation_id = %operation.operation_id,
                request_id = %operation.request_id,
                %failure_stage,
                "atomically aborting pre-bind host capability refresh initialization failed"
            );
        }
    }
}

/// `execute_*` may deliberately return a retryable failure while the durable
/// operation remains `allowed` (for example, an older global publication page
/// still fences this probe). Only a persisted terminal state may terminalize
/// the dedicated child or acknowledge its Attention row.
async fn finalize_terminal_host_capability_refresh_operation(
    session: &crate::session::Session,
    operation_id: uuid::Uuid,
    registry: &Arc<WorkerAgentTreeResolverRegistry>,
) -> HostCapabilityRefreshInterruptFinalization {
    // This performs no probe or external work, so one immediate retry is safe
    // after a transient DB error/CAS race. A second retained outcome is left
    // fully intact for boot recovery rather than being papered over locally.
    for attempt in 0..2 {
        let operation = match session
            .db
            .host_capability_refresh_operation_by_id(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                session.id,
                operation_id,
            )
            .await
        {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                tracing::warn!(%operation_id, "host capability refresh operation disappeared before typed terminalization; retaining child for durable repair");
                return HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure;
            }
            Err(error) => {
                tracing::warn!(%error, %operation_id, "loading host capability refresh state before typed terminalization failed; retaining child for durable repair");
                if attempt == 0 {
                    tokio::task::yield_now().await;
                    continue;
                }
                return HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure;
            }
        };
        let finalization = handle_terminal_host_capability_refresh_interrupt(
            session,
            session.id,
            operation.interrupt_id,
            registry,
        )
        .await;
        match finalization {
            HostCapabilityRefreshInterruptFinalization::Finalized
            | HostCapabilityRefreshInterruptFinalization::NonterminalRetryable => {
                return finalization;
            }
            HostCapabilityRefreshInterruptFinalization::NotTyped => {
                return HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure;
            }
            HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure
                if attempt == 0 =>
            {
                tokio::task::yield_now().await;
            }
            HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure => {
                return HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure;
            }
        }
    }
    HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure
}

/// Worker-owned deadline directory. Scheduling is not a best-effort spawned
/// sleep: restarts rebuild this map from durable decisions, and the worker
/// loop invokes the same lifecycle CAS for every due entry.
#[derive(Default)]
struct WorkerAgentTreeDeadlines {
    // Keep the deadline in the ordering key.  The old `(decision, deadline)`
    // map required a full scan and temporary `Vec` for every tick, which made
    // a single old backlog allocate proportionally to its total size.  The
    // reverse index makes replacement/cancellation exact without giving up
    // the bounded ordered due range.
    state: std::sync::Mutex<WorkerAgentTreeDeadlineState>,
}

#[derive(Default)]
struct WorkerAgentTreeDeadlineState {
    entries: std::collections::BTreeSet<(i64, uuid::Uuid, uuid::Uuid)>,
    by_decision: std::collections::BTreeMap<(uuid::Uuid, uuid::Uuid), i64>,
    cursor: Option<(i64, uuid::Uuid, uuid::Uuid)>,
}

impl WorkerAgentTreeDeadlines {
    fn due_limited(&self, now_unix_ms: i64, limit: usize) -> Vec<(uuid::Uuid, uuid::Uuid)> {
        if limit == 0 {
            return Vec::new();
        }
        use std::ops::Bound::{Excluded, Included, Unbounded};

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let due_end = (
            now_unix_ms,
            uuid::Uuid::from_u128(u128::MAX),
            uuid::Uuid::from_u128(u128::MAX),
        );
        let mut selected = Vec::with_capacity(limit);

        // Start just after the prior result so a permanently due backlog is
        // fair across ticks. `take(limit)` applies directly to the B-tree
        // iterator: no all-due materialization occurs.
        if let Some(cursor) = state.cursor {
            selected.extend(
                state
                    .entries
                    .range((Excluded(cursor), Included(due_end)))
                    .take(limit)
                    .map(|(_, session_id, decision_request_id)| {
                        (*session_id, *decision_request_id)
                    }),
            );
        }
        if selected.len() < limit {
            selected.extend(
                state
                    .entries
                    .range((Unbounded, Included(due_end)))
                    .take(limit - selected.len())
                    .map(|(_, session_id, decision_request_id)| {
                        (*session_id, *decision_request_id)
                    }),
            );
        }
        state.cursor = selected
            .last()
            .and_then(|(session_id, decision_request_id)| {
                state
                    .by_decision
                    .get(&(*session_id, *decision_request_id))
                    .copied()
                    .map(|deadline| (deadline, *session_id, *decision_request_id))
            });
        selected
    }
}

impl crate::agent_tree::DecisionDeadlineScheduler for WorkerAgentTreeDeadlines {
    fn schedule(
        &self,
        session_id: uuid::Uuid,
        decision_request_id: uuid::Uuid,
        deadline_unix_ms: i64,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(previous) = state
            .by_decision
            .insert((session_id, decision_request_id), deadline_unix_ms)
        {
            state
                .entries
                .remove(&(previous, session_id, decision_request_id));
        }
        state
            .entries
            .insert((deadline_unix_ms, session_id, decision_request_id));
    }

    fn cancel(&self, session_id: uuid::Uuid, decision_request_id: uuid::Uuid) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(deadline) = state.by_decision.remove(&(session_id, decision_request_id)) {
            state
                .entries
                .remove(&(deadline, session_id, decision_request_id));
        }
    }
}

struct WorkerAgentTreeClock;

impl crate::agent_tree::AgentTreeClock for WorkerAgentTreeClock {
    fn now_unix_ms(&self) -> i64 {
        crate::agent_tree::system_now_unix_ms()
    }
}

/// Resolver eligibility comes from live worker ownership and the requesting
/// agent's immutable profile snapshot, never from an agent-provided flag or
/// the session root's model. A profile slot stays user-visible until its exact
/// verified binding has been installed in the daemon-owned utility directory.
#[derive(Clone)]
enum WorkerAgentTreeResolverEndpoint {
    Driver(tokio::sync::mpsc::Sender<crate::engine::driver::DriverControl>),
    Noninteractive(tokio::sync::mpsc::Sender<crate::engine::agent::AgentTreeExecutorRequest>),
    /// A daemon-owned host operation has a durable executor/lifecycle but no
    /// model mailbox. It exists solely as the exact decision owner; automatic
    /// resolution still routes to its live parent or a utility executor.
    HostOperation,
}

/// A concrete mailbox registration, not merely an agent-instance label.
///
/// A resumed executor can legitimately replace an older mailbox for the same
/// durable agent UUID.  Failure handling must therefore identify the exact
/// registration that accepted (or rejected) a packet: blindly deleting by
/// agent UUID lets an old full/closed sender remove its live replacement.
#[derive(Clone)]
struct WorkerAgentTreeResolverEndpointRegistration {
    generation: crate::engine::agent::AgentTreeEndpointGeneration,
    endpoint: WorkerAgentTreeResolverEndpoint,
}

#[derive(Default)]
struct WorkerAgentTreeResolverRegistry {
    /// Only the worker that owns a live executor can register its redacted
    /// decision endpoint. The map stores an exact executor mailbox, never a
    /// generic/root model handle, parent history, or tool context.
    live_parent_endpoints: std::sync::Mutex<
        std::collections::BTreeMap<
            (uuid::Uuid, uuid::Uuid),
            WorkerAgentTreeResolverEndpointRegistration,
        >,
    >,
    /// Immutable-profile utility executors. A key contains the exact profile
    /// snapshot and its bound slot, so a child can never inherit the root
    /// model merely because both happen to be live in one session.
    utility_models:
        std::sync::Mutex<std::collections::BTreeMap<(uuid::Uuid, uuid::Uuid, String), Arc<Model>>>,
}

impl WorkerAgentTreeResolverRegistry {
    fn attach_parent_endpoint(
        &self,
        session_id: uuid::Uuid,
        agent_instance_id: uuid::Uuid,
        endpoint_generation: crate::engine::agent::AgentTreeEndpointGeneration,
        endpoint: tokio::sync::mpsc::Sender<crate::engine::driver::DriverControl>,
    ) -> crate::engine::agent::AgentTreeEndpointGeneration {
        let mut endpoints = self
            .live_parent_endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (session_id, agent_instance_id);
        // A worker-local attachment can be forwarded after a recovery path
        // has already installed a newer incarnation.  Never let that delayed
        // old attach regress the directory and make its later detach relevant
        // again. Equal generations are the same source registration being
        // observed through the recovery fast path and normal event forwarder.
        if endpoints
            .get(&key)
            .is_some_and(|registered| registered.generation > endpoint_generation)
        {
            return endpoint_generation;
        }
        endpoints.insert(
            key,
            WorkerAgentTreeResolverEndpointRegistration {
                generation: endpoint_generation,
                endpoint: WorkerAgentTreeResolverEndpoint::Driver(endpoint),
            },
        );
        endpoint_generation
    }

    fn attach_noninteractive_endpoint(
        &self,
        session_id: uuid::Uuid,
        agent_instance_id: uuid::Uuid,
        endpoint_generation: crate::engine::agent::AgentTreeEndpointGeneration,
        endpoint: tokio::sync::mpsc::Sender<crate::engine::agent::AgentTreeExecutorRequest>,
    ) -> crate::engine::agent::AgentTreeEndpointGeneration {
        let mut endpoints = self
            .live_parent_endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (session_id, agent_instance_id);
        if endpoints
            .get(&key)
            .is_some_and(|registered| registered.generation > endpoint_generation)
        {
            return endpoint_generation;
        }
        endpoints.insert(
            key,
            WorkerAgentTreeResolverEndpointRegistration {
                generation: endpoint_generation,
                endpoint: WorkerAgentTreeResolverEndpoint::Noninteractive(endpoint),
            },
        );
        endpoint_generation
    }

    fn attach_host_operation_endpoint(
        &self,
        session_id: uuid::Uuid,
        agent_instance_id: uuid::Uuid,
    ) -> crate::engine::agent::AgentTreeEndpointGeneration {
        let endpoint_generation = crate::engine::agent::next_agent_tree_endpoint_generation();
        let mut endpoints = self
            .live_parent_endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (session_id, agent_instance_id);
        if endpoints
            .get(&key)
            .is_some_and(|registered| registered.generation > endpoint_generation)
        {
            return endpoint_generation;
        }
        endpoints.insert(
            key,
            WorkerAgentTreeResolverEndpointRegistration {
                generation: endpoint_generation,
                endpoint: WorkerAgentTreeResolverEndpoint::HostOperation,
            },
        );
        endpoint_generation
    }

    /// Remove the current endpoint because the durable host operation itself
    /// is conclusively terminal.  This is deliberately not a mailbox-local
    /// cleanup: no replacement incarnation for this terminal operation is
    /// runnable, and retaining one would violate the durable terminal state.
    fn detach_terminal_host_operation_endpoint(
        &self,
        session_id: uuid::Uuid,
        agent_instance_id: uuid::Uuid,
    ) {
        self.live_parent_endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&(session_id, agent_instance_id));
    }

    /// Withdraw a failed endpoint only if it is still the exact mailbox that
    /// was selected for delivery.  This is the compare-and-remove half of the
    /// warm-parent hand-off: an old mailbox failure can never evict a recovered
    /// replacement registered for the same durable agent UUID.
    fn detach_parent_endpoint_if_generation(
        &self,
        session_id: uuid::Uuid,
        agent_instance_id: uuid::Uuid,
        generation: crate::engine::agent::AgentTreeEndpointGeneration,
    ) -> bool {
        let mut endpoints = self
            .live_parent_endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (session_id, agent_instance_id);
        if endpoints
            .get(&key)
            .is_some_and(|registered| registered.generation == generation)
        {
            endpoints.remove(&key);
            true
        } else {
            false
        }
    }

    fn detach_session(&self, session_id: uuid::Uuid) {
        self.live_parent_endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|(owner_session_id, _), _| *owner_session_id != session_id);
        self.utility_models
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|(owner_session_id, _, _), _| *owner_session_id != session_id);
    }

    fn attach_utility_model(
        &self,
        session_id: uuid::Uuid,
        profile_snapshot_id: uuid::Uuid,
        resolver_slot: String,
        model: Arc<Model>,
    ) {
        self.utility_models
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert((session_id, profile_snapshot_id, resolver_slot), model);
    }

    fn utility_model(
        &self,
        session_id: uuid::Uuid,
        profile_snapshot_id: uuid::Uuid,
        resolver_slot: &str,
    ) -> Option<Arc<Model>> {
        self.utility_models
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&(session_id, profile_snapshot_id, resolver_slot.to_owned()))
            .cloned()
    }

    fn parent_endpoint(
        &self,
        session_id: uuid::Uuid,
        agent_instance_id: uuid::Uuid,
    ) -> Option<WorkerAgentTreeResolverEndpoint> {
        self.parent_endpoint_registration(session_id, agent_instance_id)
            .map(|registered| registered.endpoint)
    }

    fn parent_endpoint_registration(
        &self,
        session_id: uuid::Uuid,
        agent_instance_id: uuid::Uuid,
    ) -> Option<WorkerAgentTreeResolverEndpointRegistration> {
        self.live_parent_endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&(session_id, agent_instance_id))
            .cloned()
    }
}

/// Keeps a daemon-owned host-operation child live in the exact-owner
/// directory for precisely the lifetime of its local executor task. Dropping
/// the task (including cancellation/panic) withdraws only its exact endpoint
/// incarnation, so no later resolver can settle through a stale root-shaped
/// handle and an old Drop cannot evict a recovered replacement.
struct HostOperationEndpointGuard {
    registry: Arc<WorkerAgentTreeResolverRegistry>,
    session_id: uuid::Uuid,
    agent_instance_id: uuid::Uuid,
    endpoint_generation: crate::engine::agent::AgentTreeEndpointGeneration,
}

impl Drop for HostOperationEndpointGuard {
    fn drop(&mut self) {
        self.registry.detach_parent_endpoint_if_generation(
            self.session_id,
            self.agent_instance_id,
            self.endpoint_generation,
        );
    }
}

/// Extract worker-local executor lifecycle events even when a noninteractive
/// child wrapped them in its display-only nested-turn envelope.
fn agent_tree_executor_endpoint_event(
    event: &TurnEvent,
) -> Option<(
    uuid::Uuid,
    bool,
    crate::engine::agent::AgentTreeEndpointGeneration,
)> {
    match event {
        TurnEvent::AgentTreeExecutorEndpointAttached {
            agent_instance_id,
            endpoint_generation,
        } => Some((*agent_instance_id, true, *endpoint_generation)),
        TurnEvent::AgentTreeExecutorEndpointDetached {
            agent_instance_id,
            endpoint_generation,
        } => Some((*agent_instance_id, false, *endpoint_generation)),
        TurnEvent::NestedTurn { inner, .. } => agent_tree_executor_endpoint_event(inner),
        _ => None,
    }
}

fn agent_tree_noninteractive_endpoint_event(
    event: &TurnEvent,
) -> Option<(
    uuid::Uuid,
    crate::engine::agent::AgentTreeEndpointGeneration,
    tokio::sync::mpsc::Sender<crate::engine::agent::AgentTreeExecutorRequest>,
)> {
    match event {
        TurnEvent::AgentTreeNoninteractiveEndpointAttached {
            agent_instance_id,
            endpoint_generation,
            endpoint,
        } => Some((*agent_instance_id, *endpoint_generation, endpoint.clone())),
        TurnEvent::NestedTurn { inner, .. } => agent_tree_noninteractive_endpoint_event(inner),
        _ => None,
    }
}

struct WorkerAgentTreeResolverDirectory {
    registry: Arc<WorkerAgentTreeResolverRegistry>,
}

impl crate::agent_tree::DecisionResolverDirectory for WorkerAgentTreeResolverDirectory {
    fn exact_owner_executor_is_live(
        &self,
        session_id: uuid::Uuid,
        agent_instance_id: uuid::Uuid,
    ) -> bool {
        self.registry
            .parent_endpoint(session_id, agent_instance_id)
            .is_some()
    }

    fn parent_cache_resumable(
        &self,
        session_id: uuid::Uuid,
        parent_agent_instance_id: uuid::Uuid,
    ) -> bool {
        // A host-operation endpoint is live enough to own its durable
        // decision/deadline lifecycle, but it is deliberately not a model
        // cache. Never select it as the warm parent of another automatic
        // decision: that route must always reach an executor that can accept
        // an AgentTree resolver request.
        matches!(
            self.registry
                .parent_endpoint(session_id, parent_agent_instance_id),
            Some(WorkerAgentTreeResolverEndpoint::Driver(_))
                | Some(WorkerAgentTreeResolverEndpoint::Noninteractive(_))
        )
    }

    fn utility_slot_is_compatible(
        &self,
        session_id: uuid::Uuid,
        _agent_instance_id: uuid::Uuid,
        profile_snapshot_id: Option<uuid::Uuid>,
        resolver_slot: &str,
    ) -> bool {
        profile_snapshot_id.is_some_and(|profile_snapshot_id| {
            self.registry
                .utility_model(session_id, profile_snapshot_id, resolver_slot)
                .is_some()
        })
    }
}

#[derive(Debug)]
struct AgentTreeResolverCompletion {
    session_id: uuid::Uuid,
    decision_request_id: uuid::Uuid,
    route: crate::agent_tree::DecisionResolverRoute,
    result: std::result::Result<crate::agent_tree::PublicDecisionAnswer, String>,
}

/// The worker's real executor hand-off for automatic low-risk decisions. It
/// accepts only the redacted packet, delivers a warm route to its exact live
/// parent endpoint (or a cold route to the utility lane), and reports one
/// result back to the worker-owned CAS path. A dropped worker leaves the
/// durable `resolving` claim for recovery; a rejected warm endpoint is removed
/// before the utility fallback is selected.
struct WorkerAgentTreeResolverDelivery {
    registry: Arc<WorkerAgentTreeResolverRegistry>,
    completions: tokio::sync::mpsc::Sender<AgentTreeResolverCompletion>,
}

impl crate::agent_tree::DecisionResolverDelivery for WorkerAgentTreeResolverDelivery {
    fn accept(
        &self,
        session_id: uuid::Uuid,
        route: crate::agent_tree::DecisionResolverRoute,
        packet: crate::agent_tree::RedactedDecisionPacket,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            packet.session_id == session_id,
            "agent-tree resolver packet does not belong to this worker session"
        );
        let prompt = agent_tree_resolver_prompt(&packet)?;
        match route {
            crate::agent_tree::DecisionResolverRoute::WarmParent => {
                let parent_agent_instance_id = packet
                    .parent_agent_instance_id
                    .context("warm-parent decision packet has no parent owner")?;
                let registered = self
                    .registry
                    .parent_endpoint_registration(session_id, parent_agent_instance_id)
                    .context("warm-parent exact executor endpoint is no longer live")?;
                let endpoint_generation = registered.generation;
                let (respond_to, response) = tokio::sync::oneshot::channel();
                let accepted = match registered.endpoint {
                    WorkerAgentTreeResolverEndpoint::Driver(endpoint) => endpoint
                        .try_send(crate::engine::driver::DriverControl::ResolveAgentTreeDecision {
                            agent_instance_id: parent_agent_instance_id,
                            prompt,
                            respond_to,
                        })
                        .map_err(|error| {
                            anyhow::anyhow!("warm-parent endpoint did not accept resolver packet: {error}")
                        }),
                    WorkerAgentTreeResolverEndpoint::Noninteractive(endpoint) => endpoint
                        .try_send(crate::engine::agent::AgentTreeExecutorRequest::ResolveDecision(
                            crate::engine::agent::AgentTreeResolverRequest {
                                prompt,
                                respond_to,
                            },
                        ))
                        .map_err(|error| {
                            anyhow::anyhow!("warm noninteractive endpoint did not accept resolver packet: {error}")
                        }),
                    WorkerAgentTreeResolverEndpoint::HostOperation => Err(anyhow::anyhow!(
                        "host-operation executor cannot resolve a nested warm-parent decision"
                    )),
                };
                if let Err(error) = accepted {
                    // `try_send` returns synchronously for both full and
                    // closed mailboxes. Drop this exact registration before
                    // returning the error so `begin_delivery` reselects the
                    // configured utility route rather than seeing the same
                    // unusable warm parent again.  A concurrent recovered
                    // replacement has a different generation and survives.
                    self.registry.detach_parent_endpoint_if_generation(
                        session_id,
                        parent_agent_instance_id,
                        endpoint_generation,
                    );
                    return Err(error);
                }
                let completions = self.completions.clone();
                let registry = self.registry.clone();
                tokio::spawn(async move {
                    let result = match response.await {
                        Ok(Ok(response)) => agent_tree_resolver_answer(&packet, &response)
                            .map_err(|error| error.to_string()),
                        Ok(Err(error)) => Err(error),
                        Err(error) => Err(format!(
                            "warm-parent endpoint dropped resolver response: {error}"
                        )),
                    };
                    if result.is_err() {
                        // A queued endpoint that subsequently rejects or drops
                        // the packet is not warm for this worker epoch. Remove
                        // it before the lifecycle re-selects the utility
                        // fallback; never retain a false warm-parent receipt.
                        registry.detach_parent_endpoint_if_generation(
                            session_id,
                            parent_agent_instance_id,
                            endpoint_generation,
                        );
                    }
                    let _ = completions
                        .send(AgentTreeResolverCompletion {
                            session_id,
                            decision_request_id: packet.decision_request_id,
                            route,
                            result,
                        })
                        .await;
                });
            }
            crate::agent_tree::DecisionResolverRoute::Utility => {
                let profile_snapshot_id = packet
                    .resolver_profile_snapshot_id
                    .context("utility decision packet has no immutable profile snapshot")?;
                let resolver_slot = packet
                    .resolver_slot
                    .as_deref()
                    .context("utility decision packet has no resolver slot")?;
                let model = self
                    .registry
                    .utility_model(session_id, profile_snapshot_id, resolver_slot)
                    .context("configured utility resolver binding is not live")?;
                let completions = self.completions.clone();
                tokio::spawn(async move {
                    let result = match model
                        .text_completion_for(
                            crate::engine::model::UtilityCallSite::AgentTreeDecision,
                            &prompt,
                        )
                        .await
                    {
                        Ok(response) => agent_tree_resolver_answer(&packet, &response)
                            .map_err(|error| error.to_string()),
                        Err(error) => Err(format!("agent-tree resolver model failed: {error}")),
                    };
                    let _ = completions
                        .send(AgentTreeResolverCompletion {
                            session_id,
                            decision_request_id: packet.decision_request_id,
                            route,
                            result,
                        })
                        .await;
                });
            }
        }
        Ok(())
    }
}

/// Install the daemon-owned utility lane for one immutable agent profile. The
/// selected provider/model comes only from the already verified binding
/// evidence stored in that snapshot. Failure leaves that slot unavailable,
/// which in turn leaves its decisions pending for a human rather than falling
/// back to the session root model.
async fn attach_agent_tree_profile_utility_models(
    session: &std::sync::Arc<crate::session::Session>,
    session_id: uuid::Uuid,
    profile_snapshot_id: uuid::Uuid,
    providers: &crate::config::providers::ProvidersConfig,
    redaction: Arc<RedactionTable>,
    registry: &WorkerAgentTreeResolverRegistry,
) -> Result<()> {
    let snapshot = session
        .db
        .agent_profile_snapshot_by_id(session_id, profile_snapshot_id)
        .await?
        .context("agent-tree utility profile snapshot is absent")?
        .reconstruct()?;
    let credential_store = session.provider_credential_store(providers).ok();
    for binding in snapshot.bindings {
        if !binding.hard_capability_verified {
            continue;
        }
        let provider_id = &binding.selected_provider_alias.provider_id;
        let model_id = &binding.selected_provider_alias.model_id;
        let model = match Model::for_provider_optional_store(
            providers,
            provider_id,
            model_id,
            redaction.clone(),
            credential_store.clone(),
        ) {
            Ok(model) => Arc::new(model),
            Err(error) => {
                tracing::warn!(
                    profile_snapshot_id = %profile_snapshot_id,
                    resolver_slot = %binding.slot_id,
                    provider_id,
                    model_id,
                    %error,
                    "agent-tree configured utility binding is unavailable"
                );
                continue;
            }
        };
        registry.attach_utility_model(session_id, profile_snapshot_id, binding.slot_id, model);
    }
    Ok(())
}

fn agent_tree_resolver_prompt(
    packet: &crate::agent_tree::RedactedDecisionPacket,
) -> anyhow::Result<String> {
    let packet_json =
        serde_json::to_string(packet).context("serializing redacted agent-tree resolver packet")?;
    let owns_interrupt_continuation = serde_json::from_str::<serde_json::Value>(&packet_json)
        .ok()
        .and_then(|packet| {
            packet
                .get("options_contract_json")
                .and_then(serde_json::Value::as_str)
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                .and_then(|contract| contract.get("interrupt_response_contract").cloned())
        })
        .is_some_and(|contract| !contract.is_null());
    let answer_contract = if owns_interrupt_continuation {
        // A linked QuestionTool continuation cannot consume the shorthand
        // option/free-text decision representation. Its parked continuation
        // owns the daemon's typed response envelope, and the lifecycle later
        // checks that envelope against this same redacted contract.
        "Return exactly one JSON object with a `response` member containing a ResolveResponse envelope: \\
         {\"response\":{\"kind\":\"single\",\"data\":{\"selected_id\":\"...\"}}}, \\
         or the matching `multi`, `freetext`, or `batch` envelope required by the redacted interrupt contract. \\
         Do not explain your choice or invent an option."
    } else {
        "Return exactly one JSON object: {\"option_id\":\"...\"} for one offered option, \\
         or {\"free_text\":\"...\"} only when its free-text contract allows it. \\
         Do not explain your choice or invent an option."
    };
    let host_semantic = host_owned_resolver_option(packet)?;
    let host_instruction = host_semantic.as_ref().map_or(String::new(), |option_id| {
        format!(
            " The packet includes a typed daemon-host recommendation for this non-sensitive action; return the recommended opaque option `{option_id}`. Do not infer intent from option order or labels."
        )
    });
    Ok(format!(
        "Resolve this low-risk daemon decision using only its redacted contract.{host_instruction} \\
         {answer_contract}\n\n{packet_json}"
    ))
}

/// Decode the one allowlisted host-owned resolver semantic.  The durable DB
/// created it from an exhaustive host classifier, not from prompt prose, and
/// its option is already daemon-minted/opaque.  Keep this parser strict so a
/// future recommendation field cannot silently become an authority channel.
fn host_owned_resolver_option(
    packet: &crate::agent_tree::RedactedDecisionPacket,
) -> anyhow::Result<Option<String>> {
    let Some(raw) = packet.recommendation_json.as_deref() else {
        return Ok(None);
    };
    let recommendation: serde_json::Value =
        serde_json::from_str(raw).context("decoding redacted host-owned recommendation")?;
    let Some(host_action) = recommendation
        .get("host_action")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };
    anyhow::ensure!(
        packet.decision_class == crate::agent_tree::DecisionClass::LowRisk
            && host_action == "refresh_local_host_capabilities",
        "redacted packet contains an unsupported host-owned action"
    );
    let option_id = recommendation
        .get("option_id")
        .and_then(serde_json::Value::as_str)
        .context("host-owned recommendation is missing its opaque option")?;
    let options: serde_json::Value = serde_json::from_str(&packet.options_contract_json)
        .context("decoding redacted resolver option contract")?;
    anyhow::ensure!(
        redacted_decision_contract_offers_option(&options, option_id),
        "host-owned recommendation is not an offered opaque option"
    );
    Ok(Some(option_id.to_owned()))
}

/// The redacted decision form has two disjoint option carriers: ordinary
/// lifecycle decisions use top-level `options`, while a QuestionTool
/// continuation carries its opaque choices inside the typed question set.
/// A host-owned recommendation must prove membership in either carrier; it
/// must never infer a continuation id from labels or option position.
fn redacted_decision_contract_offers_option(contract: &serde_json::Value, option_id: &str) -> bool {
    let ordinary = contract
        .get("options")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|options| {
            options.iter().any(|option| {
                option.get("id").and_then(serde_json::Value::as_str) == Some(option_id)
            })
        });
    let interrupt = contract
        .get("interrupt_response_contract")
        .and_then(|value| (!value.is_null()).then_some(value))
        .and_then(|contract| contract.get("questions"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|questions| {
            questions.iter().any(|question| {
                question
                    .get("option_ids")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|option_ids| {
                        option_ids.iter().any(|id| id.as_str() == Some(option_id))
                    })
            })
        });
    ordinary || interrupt
}

fn agent_tree_resolver_answer(
    packet: &crate::agent_tree::RedactedDecisionPacket,
    response: &str,
) -> anyhow::Result<crate::agent_tree::PublicDecisionAnswer> {
    let response: serde_json::Value = serde_json::from_str(response.trim())
        .context("agent-tree resolver did not return a JSON object")?;
    let options: serde_json::Value = serde_json::from_str(&packet.options_contract_json)
        .context("decoding redacted resolver option contract")?;
    let host_owned_option = host_owned_resolver_option(packet)?;
    if options
        .get("interrupt_response_contract")
        .is_some_and(|contract| !contract.is_null())
    {
        // `raise_and_wait_with_agent_tree` binds this decision to a parked
        // QuestionTool continuation.  The normal shorthand is deliberately
        // not accepted for that path: emit the typed wire response the
        // original continuation understands.  `resolve_auto_result` remains
        // the authority that validates it against the persisted redacted
        // question set before terminalizing the decision.
        if let Some(option_id) = host_owned_option {
            // The sole real low-risk host ingress is refresh of daemon-local
            // metadata. Its action is selected by this typed host semantic,
            // never by the model guessing between opaque tokens or relying on
            // their list order.
            return Ok(crate::agent_tree::PublicDecisionAnswer::InterruptResponse {
                response: crate::daemon::proto::ResolveResponse::Single {
                    selected_id: option_id,
                },
            });
        }
        let envelope = response.get("response").cloned().unwrap_or(response);
        let response = serde_json::from_value::<crate::daemon::proto::ResolveResponse>(envelope)
            .context("agent-tree resolver did not return a typed interrupt response")?;
        return Ok(crate::agent_tree::PublicDecisionAnswer::InterruptResponse { response });
    }
    if let Some(option_id) = host_owned_option.as_deref() {
        return Ok(crate::agent_tree::PublicDecisionAnswer::Option {
            id: option_id.to_owned(),
        });
    }
    if let Some(option_id) = response
        .get("option_id")
        .and_then(serde_json::Value::as_str)
    {
        let offered = options
            .get("options")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|options| {
                options.iter().any(|option| {
                    option.get("id").and_then(serde_json::Value::as_str) == Some(option_id)
                })
            });
        anyhow::ensure!(offered, "agent-tree resolver selected an unoffered option");
        return Ok(crate::agent_tree::PublicDecisionAnswer::Option {
            id: option_id.to_string(),
        });
    }
    let free_text = response
        .get("free_text")
        .and_then(serde_json::Value::as_str)
        .context("agent-tree resolver response has no permitted answer")?;
    let contract: serde_json::Value = packet
        .free_text_contract_json
        .as_deref()
        .map(|raw| serde_json::from_str::<serde_json::Value>(raw))
        .transpose()
        .context("decoding redacted resolver free-text contract")?
        .context("agent-tree resolver used free text without a contract")?;
    anyhow::ensure!(
        contract.get("allowed").and_then(serde_json::Value::as_bool) == Some(true),
        "agent-tree resolver used prohibited free text"
    );
    let max_chars = contract
        .get("max_chars")
        .and_then(serde_json::Value::as_u64)
        .context("allowed agent-tree resolver free-text contract is missing its bounded maximum")?;
    anyhow::ensure!(
        (1..=10_000).contains(&max_chars),
        "agent-tree resolver free-text contract has an invalid bounded maximum"
    );
    anyhow::ensure!(
        free_text.chars().count() <= max_chars as usize,
        "agent-tree resolver free text exceeds its contract"
    );
    Ok(crate::agent_tree::PublicDecisionAnswer::FreeText {
        text: free_text.to_string(),
    })
}

/// The control tables commit their own ordered `agent_tree` session event in
/// the same SQLite transaction as each state change. This worker relay is the
/// sole conversion to a client invalidation, so creation, waits, resolver
/// claims/releases, timeout/cancel, recovery and terminalization all have the
/// same session-scoped ordering contract.
async fn relay_agent_tree_events(
    session: &Arc<Session>,
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    session_id: uuid::Uuid,
    cursor: &mut i64,
    late_steer_registry: &Arc<WorkerAgentTreeResolverRegistry>,
) {
    let rows = match session
        .db
        .agent_tree_events_after(session_id, *cursor, AGENT_TREE_MAINTENANCE_ITEMS_PER_TURN)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, %session_id, "reading committed agent-tree invalidations failed");
            return;
        }
    };
    if rows.is_empty() {
        return;
    }
    for row in rows {
        let transition = match row.kind.as_str() {
            "agent_created" => proto::AgentTreeTransition::AgentCreated,
            "decision_pending" => proto::AgentTreeTransition::AttentionRaised,
            "attention_transition" => proto::AgentTreeTransition::AttentionStateChanged,
            "recovery_claimed" | "recovery_attached" => {
                proto::AgentTreeTransition::RecoveryAttached
            }
            kind if kind.starts_with("decision_") => {
                proto::AgentTreeTransition::DecisionStateChanged
            }
            _ => proto::AgentTreeTransition::AgentStateChanged,
        };
        let subject_kind = match row.subject_kind.as_str() {
            "agent" => proto::AgentTreeEventSubject::Agent,
            "decision" => proto::AgentTreeEventSubject::Decision,
            other => {
                tracing::warn!(%session_id, session_event_seq = row.session_event_seq, %other, "committed agent-tree event has an invalid subject kind");
                *cursor = row.session_event_seq;
                continue;
            }
        };
        // An event is an ordered invalidation only.  Do not read the live
        // agent or decision row here: it may have moved on since this
        // transaction committed, which would make an old event describe a
        // later state.
        let payload = proto::Event::AgentTreeChanged {
            session_id,
            session_event_seq: row.session_event_seq,
            transition,
            subject_kind,
            subject_id: row.subject_id,
        };
        send_current_session_event(
            session,
            event_tx,
            redaction,
            payload,
            NoticeSource::DaemonDirect,
        );
        // A late steer which lost the race with a new QuestionTool or
        // approval remains `pending` (and therefore is safely
        // releasable). Re-attempt it only when the exact durable owner
        // has made a fresh transition back to `running`; polling the
        // queue while it is waiting would violate the predecessor's
        // ordering and turn a parked continuation into a busy loop.
        //
        // This relay is deliberately only a scheduler. In particular it
        // must never await a driver-control send: an accepted checkpoint
        // may be waiting behind a full control mailbox while that driver
        // is doing inference, and blocking the sole session worker here
        // would stall deadlines, resolver completions, and unrelated
        // work. Accepted checkpoints are attached only by the boot
        // recovery path below; a live `running` event may schedule only a
        // new/pending steer on a detached retry task.
        if row.kind == "agent_transition" && row.subject_kind == "agent" {
            match session.db.agent_instance(session_id, row.subject_id).await {
                Ok(Some(agent))
                    if agent.state
                        == crate::db::agent_tree_decisions::AgentInstanceState::Running =>
                {
                    let retry_session = Arc::clone(session);
                    let retry_registry = Arc::clone(late_steer_registry);
                    tokio::spawn(async move {
                        if let Err(error) = deliver_next_pending_late_user_steer(
                            &retry_session,
                            session_id,
                            agent.agent_instance_id,
                            &retry_registry,
                        )
                        .await
                        {
                            tracing::debug!(%error, agent_instance_id = %agent.agent_instance_id, "no runnable pending late user steer to schedule after agent lifecycle transition");
                        }
                    });
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, agent_instance_id = %row.subject_id, "loading agent state for late-steer reactivation failed")
                }
            }
        }
        *cursor = row.session_event_seq;
    }
}

pub(super) fn persistent_llm_mode_control(
    mode: crate::config::extended::LlmMode,
) -> crate::engine::driver::DriverControl {
    crate::engine::driver::DriverControl::SetLlmMode {
        mode: Some(mode),
        prune_after_switch: true,
    }
}

pub(super) fn session_llm_mode_control(
    mode: crate::config::extended::LlmMode,
) -> crate::engine::driver::DriverControl {
    crate::engine::driver::DriverControl::SetLlmMode {
        mode: Some(mode),
        prune_after_switch: false,
    }
}

pub(super) fn tool_surface_override_control(
    selection: crate::agents::ToolSurfaceSelection,
    prune_after_switch: bool,
    monty_nudge: Option<String>,
) -> crate::engine::driver::DriverControl {
    crate::engine::driver::DriverControl::SetToolSurfaceOverride {
        selection,
        prune_after_switch,
        monty_nudge,
    }
}

pub(super) fn stored_session_llm_mode(
    session: &Session,
) -> Option<crate::config::extended::LlmMode> {
    let raw = session.session_llm_mode_raw()?;
    match session.session_llm_mode() {
        Some(mode) => Some(mode),
        None => {
            tracing::warn!(
                session_id = %session.id,
                mode = %raw,
                "stored session llm mode is invalid; falling back to resolved config mode"
            );
            None
        }
    }
}

pub(super) fn stored_tool_surface_override(
    session: &Session,
) -> Option<crate::agents::ToolSurfaceSelection> {
    let raw = session.tool_surface_override_json()?;
    match serde_json::from_str::<crate::agents::ToolSurfaceSelection>(&raw) {
        Ok(selection) => Some(selection),
        Err(error) => {
            tracing::warn!(
                session_id = %session.id,
                %error,
                "stored tool surface override is invalid JSON; falling back to agent definition"
            );
            None
        }
    }
}

pub(super) fn stored_goal_settings_override(
    session: &Session,
) -> Option<crate::agents::GoalSettingsOverride> {
    let raw = session.goal_settings_override_json()?;
    match crate::agents::parse_goal_settings_override_json(&raw) {
        Ok(override_) => Some(override_),
        Err(error) => {
            tracing::warn!(
                session_id = %session.id,
                %error,
                "stored goal settings override is invalid; falling back to lower-priority defaults"
            );
            None
        }
    }
}

pub(super) struct ParkedReplayCompletion {
    interrupt_id: uuid::Uuid,
    decision: Option<proto::InterruptDecision>,
    was_active: bool,
    result: std::result::Result<crate::engine::driver::ParkedReplayOutcome, String>,
}

/// Start the one canonical replay path for a continuation that was durably
/// claimed as `executing`.  Both a live user answer and startup recovery use
/// this exact hand-off; completion is returned to the worker so SQLite is the
/// only acknowledgement boundary.
fn spawn_parked_interrupt_replay(
    driver_control_tx: tokio::sync::mpsc::Sender<crate::engine::driver::DriverControl>,
    registry: Arc<WorkerAgentTreeResolverRegistry>,
    session_id: uuid::Uuid,
    replay_completion_tx: tokio::sync::mpsc::Sender<ParkedReplayCompletion>,
    interrupt_id: uuid::Uuid,
    agent_instance_id: Option<uuid::Uuid>,
    payload: crate::db::needs_attention::InterruptParkPayload,
    response: crate::daemon::proto::ResolveResponse,
    question: crate::engine::interrupt::PreResolvedInterruptQuestion,
    decision: Option<proto::InterruptDecision>,
    was_active: bool,
) {
    tokio::spawn(async move {
        let (respond_to, replay_result_rx) = tokio::sync::oneshot::channel();
        let delivery = match agent_instance_id {
            Some(agent_instance_id) => match registry.parent_endpoint(session_id, agent_instance_id) {
                Some(WorkerAgentTreeResolverEndpoint::Driver(endpoint)) => endpoint
                    .send(crate::engine::driver::DriverControl::ReplayParkedInterrupt {
                        interrupt_id,
                        agent_instance_id: Some(agent_instance_id),
                        payload: Box::new(payload),
                        response,
                        question: Box::new(question),
                        respond_to,
                    })
                    .await
                    .map_err(|_| "exact interactive executor is unavailable".to_string()),
                Some(WorkerAgentTreeResolverEndpoint::Noninteractive(endpoint)) => endpoint
                    .send(
                        crate::engine::agent::AgentTreeExecutorRequest::ReplayParkedInterrupt {
                            interrupt_id,
                            payload: Box::new(payload),
                            response,
                            question: Box::new(question),
                            respond_to,
                        },
                    )
                    .await
                    .map_err(|_| "exact noninteractive executor is unavailable".to_string()),
                // A host-operation child has no model continuation and never
                // owns a parked QuestionTool replay. Its typed operation
                // recovery path acknowledges the linked Attention row
                // directly after it has terminalized the durable operation.
                Some(WorkerAgentTreeResolverEndpoint::HostOperation) => Err(
                    "host-operation continuation must be acknowledged by its typed durable operation"
                        .to_string(),
                ),
                None => Err("exact parked continuation executor is not attached".to_string()),
            },
            // A legacy unowned row has no agent-tree authority boundary and
            // retains the historical foreground replay route.
            None => driver_control_tx
                .send(crate::engine::driver::DriverControl::ReplayParkedInterrupt {
                    interrupt_id,
                    agent_instance_id: None,
                    payload: Box::new(payload),
                    response,
                    question: Box::new(question),
                    respond_to,
                })
                .await
                .map_err(|_| "driver is not available for parked interrupt replay".to_string()),
        };
        let result = if delivery.is_ok() {
            replay_result_rx.await.unwrap_or_else(|error| {
                Err(format!("exact parked replay response dropped: {error}"))
            })
        } else {
            Err(delivery.expect_err("checked delivery failure"))
        };
        let _ = replay_completion_tx
            .send(ParkedReplayCompletion {
                interrupt_id,
                decision,
                was_active,
                result,
            })
            .await;
    });
}

fn agent_tree_interrupt_owner(
    row: &crate::db::needs_attention::NeedsAttentionRow,
) -> Option<uuid::Uuid> {
    row.agent_instance_id
}

/// A host-capability refresh child is a daemon operation, not a parked model
/// continuation.  Its terminal Attention row has no live driver waiter after
/// restart, so replaying it through the root would both lose the durable
/// operation identity and risk a second probe.  The allowed operation is
/// picked up by the exact-once dispatcher; cancellation/failure/completion
/// acknowledges the already-claimed Attention row directly.
///
/// The outcome of handling the exact host-operation owner of an Attention
/// row. Callers must handle every variant explicitly: only a normal
/// nonterminal operation may wake its dedicated waiter; a failed terminal
/// cleanup must fence the worker without waking or replaying anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostCapabilityRefreshInterruptFinalization {
    NotTyped,
    NonterminalRetryable,
    RetainedTerminalCleanupFailure,
    Finalized,
}

/// A terminal operation may acknowledge its executing Attention row only once
/// its child is durably terminal in the exact state the operation dictates.
/// The acknowledgement itself precedes endpoint detach so a DB failure leaves
/// both recoverable handles in place.
async fn handle_terminal_host_capability_refresh_interrupt(
    session: &Session,
    session_id: uuid::Uuid,
    interrupt_id: uuid::Uuid,
    registry: &Arc<WorkerAgentTreeResolverRegistry>,
) -> HostCapabilityRefreshInterruptFinalization {
    let operation = match session
        .db
        .host_capability_refresh_operation_for_interrupt(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            session_id,
            interrupt_id,
        )
        .await
    {
        Ok(Some(operation)) => operation,
        Ok(None) => return HostCapabilityRefreshInterruptFinalization::NotTyped,
        Err(error) => {
            tracing::warn!(%error, %interrupt_id, "loading host capability refresh interrupt operation failed");
            // Do not hand a possibly typed host continuation to a driver on a
            // storage failure. A later recovery epoch can re-read the exact
            // operation/Attention tuple.
            return HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure;
        }
    };
    match operation.state {
        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Allowed => {
            // `spawn_ready_host_capability_refresh_operations` owns the
            // exact-once dispatch claim. Keep this execution claim until that
            // task commits a durable result and acknowledges it below.
            HostCapabilityRefreshInterruptFinalization::NonterminalRetryable
        }
        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Cancelled
        | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Failed
        | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Completed => {
            let child_terminal_state =
                host_capability_refresh_terminal_child_state(operation.state)
                    .expect("terminal operation states are matched above");
            // A recovery can crash between durable operation terminalization
            // and the child lifecycle CAS. Repair that exact child here,
            // before acknowledging Attention, so a denied/failed/completed
            // daemon operation never remains a live resolver endpoint.
            let terminalization = terminalize_host_capability_refresh_child(
                session,
                operation.agent_instance_id,
                child_terminal_state,
                r#"{"host_operation":"capability_refresh"}"#,
            )
            .await;
            if !terminalization.permits_terminal_cleanup() {
                tracing::warn!(
                    operation_id = %operation.operation_id,
                    interrupt_id = %interrupt_id,
                    ?terminalization,
                    "terminal host capability refresh child was not durably verified; retaining endpoint and Attention for repair"
                );
                return HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure;
            }
            match session.db.complete_executing_interrupt(interrupt_id).await {
                Ok(true) => {
                    tracing::debug!(%interrupt_id, operation_id = %operation.operation_id, "acknowledged terminal host capability refresh Attention directly");
                }
                Ok(false) => {
                    let already_resolved = match session.db.get_interrupt(interrupt_id).await {
                        Ok(Some(row)) => {
                            row.state == crate::db::needs_attention::InterruptState::Resolved
                        }
                        Ok(None) => false,
                        Err(error) => {
                            tracing::warn!(%error, %interrupt_id, operation_id = %operation.operation_id, "reloading unacknowledged host capability refresh Attention failed");
                            false
                        }
                    };
                    if !already_resolved {
                        tracing::warn!(%interrupt_id, operation_id = %operation.operation_id, "terminal host capability refresh Attention was not durably acknowledged; retaining endpoint for repair");
                        return HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure;
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, %interrupt_id, operation_id = %operation.operation_id, "acknowledging terminal host capability refresh Attention failed; retaining endpoint for repair");
                    return HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure;
                }
            }
            registry
                .detach_terminal_host_operation_endpoint(session_id, operation.agent_instance_id);
            HostCapabilityRefreshInterruptFinalization::Finalized
        }
        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Pending
        | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Executing => {
            tracing::debug!(
                %interrupt_id,
                operation_id = %operation.operation_id,
                state = ?operation.state,
                "retaining host capability refresh Attention for its typed operation recovery"
            );
            HostCapabilityRefreshInterruptFinalization::NonterminalRetryable
        }
    }
}

/// Deliver the terminal projection of an AgentTree decision to the one real
/// QuestionTool continuation it owns.  This is shared by automatic resolution
/// and deadline settlement: both have already won the decision CAS, so this
/// function never re-settles the decision or manufactures a second waiter.
async fn deliver_terminal_agent_tree_interrupt(
    session: &Session,
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    interrupts: &Arc<crate::engine::interrupt::InterruptHub>,
    session_id: uuid::Uuid,
    decision_request_id: uuid::Uuid,
    driver_control_tx: tokio::sync::mpsc::Sender<crate::engine::driver::DriverControl>,
    registry: Arc<WorkerAgentTreeResolverRegistry>,
    replay_completion_tx: tokio::sync::mpsc::Sender<ParkedReplayCompletion>,
    terminalization_failure_fence: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let interrupt_id = match session
        .db
        .interrupt_for_decision_request(session_id, decision_request_id)
        .await
    {
        Ok(Some(interrupt_id)) => interrupt_id,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(
                %error,
                %decision_request_id,
                "loading terminal AgentTree interrupt continuation failed"
            );
            return;
        }
    };
    let row = match session.db.get_interrupt(interrupt_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%error, %interrupt_id, "loading terminal AgentTree interrupt failed");
            return;
        }
    };
    let Some(response) = row.response.clone() else {
        tracing::warn!(%interrupt_id, "terminal AgentTree interrupt has no durable response");
        return;
    };
    match row.state {
        crate::db::needs_attention::InterruptState::Resolved => {
            let decision =
                crate::db::needs_attention::summarize_interrupt_decision(&row, &response);
            let seq = record_interrupt_decision_event(session, redaction, interrupt_id, &decision);
            send_current_event(
                event_tx,
                redaction,
                proto::Event::InterruptResolved {
                    session_id,
                    interrupt_id,
                    decision: Some(decision),
                    seq,
                },
            );
            interrupts.resolve(interrupt_id, response);
            interrupts.emit_queue_state().await;
        }
        crate::db::needs_attention::InterruptState::Executing => {
            match handle_terminal_host_capability_refresh_interrupt(
                session,
                session_id,
                interrupt_id,
                &registry,
            )
            .await
            {
                HostCapabilityRefreshInterruptFinalization::Finalized
                | HostCapabilityRefreshInterruptFinalization::NonterminalRetryable => {
                    // A live direct refresh task is still awaiting this real
                    // QuestionTool interrupt. Waking it is not a parked
                    // replay: its typed operation owns dispatch or has
                    // durably completed its terminal acknowledgement.
                    interrupts.resolve(interrupt_id, response);
                    interrupts.emit_queue_state().await;
                    return;
                }
                HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure => {
                    // Do not wake a direct waiter or replay a generic driver
                    // while a terminal child/Attention pair is retained.
                    // The worker loop consumes this fence before another
                    // continuation may cross a provider boundary.
                    fence_host_capability_terminalization_failure(terminalization_failure_fence);
                    return;
                }
                HostCapabilityRefreshInterruptFinalization::NotTyped => {}
            }
            let Some(payload) = row.parked.clone() else {
                tracing::warn!(%interrupt_id, "terminal AgentTree parked interrupt has no replay payload; retaining exact claim for repair");
                return;
            };
            let Some(questions) = row.questions.clone().or_else(|| {
                row.question
                    .clone()
                    .map(|question| crate::daemon::proto::InterruptQuestionSet {
                        questions: vec![question],
                    })
            }) else {
                tracing::warn!(%interrupt_id, "terminal AgentTree parked interrupt has no replay question; retaining exact claim for repair");
                return;
            };
            let occurrence = session
                .db
                .interrupt_question_occurrence(interrupt_id)
                .await
                .unwrap_or(1);
            let question = crate::engine::interrupt::PreResolvedInterruptQuestion {
                agent_instance_id: row.agent_instance_id,
                agent: row.agent_id.clone(),
                description: row.description.clone(),
                questions,
                occurrence,
            };
            let decision = Some(crate::db::needs_attention::summarize_interrupt_decision(
                &row, &response,
            ));
            spawn_parked_interrupt_replay(
                driver_control_tx,
                registry,
                session_id,
                replay_completion_tx,
                interrupt_id,
                agent_tree_interrupt_owner(&row),
                payload,
                response,
                question,
                decision,
                false,
            );
        }
        _ => {}
    }
}

/// Deliver every currently pending steer for one exact live agent owner.
/// Each row has a fresh delivery claim and is acknowledged only after the
/// attached exact-owner continuation accepts it; a send/reply failure releases
/// the exact claim for restart recovery rather than dropping the user
/// instruction.
fn deliver_live_agent_tree_late_user_steers<'a>(
    session: &'a Arc<Session>,
    session_id: uuid::Uuid,
    agent_instance_id: uuid::Uuid,
    registry: &'a std::sync::Arc<WorkerAgentTreeResolverRegistry>,
    recovered_claim: Option<(
        uuid::Uuid,
        Vec<crate::db::agent_tree_decisions::LateUserDecisionSteer>,
    )>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let registered = registry
            .parent_endpoint_registration(session_id, agent_instance_id)
            .context("late user steer has no live exact agent executor")?;
        let endpoint_generation = registered.generation;
        let endpoint = registered.endpoint;
        // `record_late_user_decision_steer` atomically routes a post-auto
        // HostOperation answer to its direct requesting parent. A host endpoint
        // therefore cannot be a valid durable steer target. Detect corruption
        // before taking or modifying a delivery claim: never detach the typed
        // host endpoint, release a row, or substitute the root driver.
        if matches!(&endpoint, WorkerAgentTreeResolverEndpoint::HostOperation) {
            anyhow::bail!(
                "late user steer target is a host operation without a model continuation; durable routing invariant was violated"
            );
        }
        let (steer_epoch, steers) = match recovered_claim {
            Some(claim) => claim,
            None => {
                let steer_epoch = uuid::Uuid::now_v7();
                let steers = session
                    .db
                    .claim_late_user_decision_steers(session_id, agent_instance_id, steer_epoch)
                    .await?;
                (steer_epoch, steers)
            }
        };
        // Claims are deliberately one-at-a-time.  One model turn has one
        // immutable continuation identity, so batching multiple late steers here
        // would make all but one of them indistinguishable to the external
        // journal. The successful receipt below schedules the next owner-local
        // steer only after this identity has completed.
        for steer in steers {
            // A prior exact executor completed this continuation but its worker
            // acknowledgement was interrupted.  Receipt-only recovery is the
            // exactly-once path; do not enqueue the steer a second time.
            if steer.completed_at_unix_ms.is_some() {
                let db = session.db.clone();
                let next_session = session.clone();
                let next_registry = Arc::clone(registry);
                tokio::spawn(async move {
                    match crate::agent_tree::AgentTreeLifecycle::new(db)
                        .ack_late_user_steer_delivery(
                            session_id,
                            steer.steer_id,
                            steer_epoch,
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await
                    {
                        Ok(true) => {
                            if let Err(error) = deliver_next_pending_late_user_steer(
                                &next_session,
                                session_id,
                                agent_instance_id,
                                &next_registry,
                            )
                            .await
                            {
                                tracing::warn!(%error, %agent_instance_id, "scheduling next late user steer after receipt-only recovery failed");
                            }
                        }
                        Ok(false) => tracing::warn!(
                            steer_id = %steer.steer_id,
                            "completed late user steer acknowledgement lost its exact claim"
                        ),
                        Err(error) => tracing::warn!(
                            %error,
                            steer_id = %steer.steer_id,
                            "acknowledging completed late user steer failed"
                        ),
                    }
                });
                continue;
            }
            // `accepted` is a no-redelivery state, not an abandoned claim. A
            // successor receives a distinct resume command carrying the same
            // checkpoint/continuation identity; it must not execute the ordinary
            // acceptance path again just because the daemon epoch changed. In
            // contrast, a newly claimed `pending` steer remains pending until the
            // exact executor reaches the final provider-handoff gate.
            let resume_checkpoint = match steer.execution_state {
                crate::db::agent_tree_decisions::LateUserDecisionSteerExecutionState::Pending => {
                    None
                }
                crate::db::agent_tree_decisions::LateUserDecisionSteerExecutionState::Accepted => {
                    match steer.continuation_checkpoint_json.clone() {
                        Some(checkpoint)
                            if accepted_late_user_steer_checkpoint_matches(&steer, &checkpoint) =>
                        {
                            Some(checkpoint)
                        }
                        Some(_) => {
                            tracing::error!(
                                steer_id = %steer.steer_id,
                                "accepted late user steer checkpoint does not bind its exact immutable owner"
                            );
                            continue;
                        }
                        None => {
                            tracing::error!(
                                steer_id = %steer.steer_id,
                                "accepted late user steer has no durable continuation checkpoint"
                            );
                            continue;
                        }
                    }
                }
                crate::db::agent_tree_decisions::LateUserDecisionSteerExecutionState::Rejected => {
                    tracing::debug!(steer_id = %steer.steer_id, "not resuming rejected late user steer");
                    continue;
                }
                crate::db::agent_tree_decisions::LateUserDecisionSteerExecutionState::Completed => {
                    unreachable!("completed steers are acknowledged above")
                }
            };
            if let Some(checkpoint) = resume_checkpoint.as_deref() {
                // This only restores an already accepted checkpoint to its exact
                // executor; it does not cross the provider boundary. A child
                // parked on a later QuestionTool/approval must receive this
                // association while waiting, so that replay can reinstall the
                // same permit. `late_user_decision_steer_dispatch_permit_is_current`
                // remains the independent `running`-only authority immediately
                // before any provider work.
                let owner_can_restore_checkpoint = session
                    .db
                    .agent_instance(session_id, steer.agent_instance_id)
                    .await?
                    .is_some_and(|owner| {
                        !owner.state.is_terminal()
                            && accepted_late_user_steer_checkpoint_matches(&steer, checkpoint)
                    });
                if !owner_can_restore_checkpoint {
                    tracing::warn!(
                        steer_id = %steer.steer_id,
                        "accepted late user steer owner cannot restore its immutable continuation checkpoint"
                    );
                    continue;
                }
            }
            let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
            // Neither live delivery nor accepted recovery may await a bounded
            // executor mailbox. A pending row is released for a later `running`
            // retry if full; an accepted checkpoint instead gets a bounded
            // boot-recovery retry and remains immutable if it exhausts.
            let delivered = match (&endpoint, resume_checkpoint.as_deref()) {
            (endpoint, None) => try_send_pending_late_user_steer(
                endpoint,
                agent_instance_id,
                steer.steer_id,
                steer.continuation_id,
                steer_epoch,
                steer.payload_json.clone(),
                accepted_tx,
            ),
            (WorkerAgentTreeResolverEndpoint::Driver(driver_control_tx), Some(checkpoint)) => schedule_accepted_late_steer_recovery_control(
                driver_control_tx.clone(),
                crate::engine::driver::DriverControl::ResumeAcceptedLateUserDecisionSteer {
                    agent_instance_id,
                    steer_id: steer.steer_id,
                    continuation_id: steer.continuation_id,
                    recovery_epoch: steer_epoch,
                    payload_json: steer.payload_json.clone(),
                    continuation_checkpoint_json: checkpoint.to_owned(),
                    respond_to: accepted_tx,
                },
            )
            .await,
            (WorkerAgentTreeResolverEndpoint::Noninteractive(executor_tx), Some(checkpoint)) => executor_tx
                .try_send(
                    crate::engine::agent::AgentTreeExecutorRequest::ResumeAcceptedLateUserDecisionSteer {
                        steer_id: steer.steer_id,
                        continuation_id: steer.continuation_id,
                        recovery_epoch: steer_epoch,
                        payload_json: steer.payload_json.clone(),
                        continuation_checkpoint_json: checkpoint.to_owned(),
                        respond_to: accepted_tx,
                    },
                )
                .map_err(|error| {
                    matches!(error, tokio::sync::mpsc::error::TrySendError::Closed(_))
                }),
            (WorkerAgentTreeResolverEndpoint::HostOperation, Some(_)) => {
                // A daemon host operation cannot resume an agent/model steer.
                // Preserve the accepted durable checkpoint for a later exact
                // executor rather than routing it through the root driver.
                Err(true)
            }
        };
            if let Err(endpoint_closed) = delivered {
                if resume_checkpoint.is_some() {
                    // This is boot/recovery attachment, never live pending work.
                    // An accepted row cannot be released if its endpoint is full
                    // or gone: preserve its immutable checkpoint and fail this
                    // worker epoch before an unbound frame can run.
                    anyhow::bail!(
                        "accepted late-steer recovery control was not attached ({})",
                        if endpoint_closed {
                            "executor endpoint closed"
                        } else {
                            "bounded driver mailbox retry exhausted"
                        }
                    );
                }
                let _ = session
                    .db
                    .release_late_user_decision_steer_claim(
                        session_id,
                        steer.steer_id,
                        steer_epoch,
                        crate::agent_tree::system_now_unix_ms(),
                    )
                    .await;
                if endpoint_closed {
                    // `try_send` observed the registration selected above. A
                    // recovered replacement may already own this durable UUID,
                    // so withdraw only the closed sender's exact incarnation.
                    registry.detach_parent_endpoint_if_generation(
                        session_id,
                        agent_instance_id,
                        endpoint_generation,
                    );
                }
                tracing::warn!(
                    steer_id = %steer.steer_id,
                    endpoint_closed,
                    "agent continuation did not accept a nonblocking late user steer delivery"
                );
                continue;
            }
            let db = session.db.clone();
            let next_session = session.clone();
            let next_registry = Arc::clone(registry);
            tokio::spawn(async move {
                // This receiver resolves only after the exact executor either
                // crossed its durable provider-handoff boundary or proved it
                // could not do so. It intentionally remains outside the
                // session-worker loop: cancelling a slow model turn by timing out
                // and releasing an *accepted* claim would allow a second executor
                // to run the same user steer. A non-completed result can, however,
                // still be a `pending` row when a new question/approval parked the
                // owner before handoff; that row is released below so the next
                // transition back to `running` can retry it in order.
                match accepted_rx.await {
                    Ok(crate::engine::driver::LateUserSteerContinuationOutcome::Completed) => {
                        match crate::agent_tree::AgentTreeLifecycle::new(db.clone())
                            .ack_late_user_steer_delivery(
                                session_id,
                                steer.steer_id,
                                steer_epoch,
                                crate::agent_tree::system_now_unix_ms(),
                            )
                            .await
                        {
                            Ok(true) => {
                                if let Err(error) = deliver_next_pending_late_user_steer(
                                    &next_session,
                                    session_id,
                                    agent_instance_id,
                                    &next_registry,
                                )
                                .await
                                {
                                    tracing::warn!(%error, %agent_instance_id, "scheduling next late user steer after durable completion failed");
                                }
                            }
                            Ok(false) => tracing::warn!(
                                steer_id = %steer.steer_id,
                                "completed late user steer acknowledgement lost its exact claim"
                            ),
                            Err(error) => tracing::warn!(
                                %error,
                                steer_id = %steer.steer_id,
                                "acknowledging delivered late user steer failed"
                            ),
                        }
                    }
                    Ok(outcome) => {
                        let diagnostic = outcome
                            .diagnostic()
                            .unwrap_or("owner cancelled before continuation completion");
                        match db
                            .release_late_user_decision_steer_claim(
                                session_id,
                                steer.steer_id,
                                steer_epoch,
                                crate::agent_tree::system_now_unix_ms(),
                            )
                            .await
                        {
                            Ok(true) => tracing::debug!(
                                steer_id = %steer.steer_id,
                                ?outcome,
                                %diagnostic,
                                "late user steer never reached provider handoff; retaining pending order for a later runnable owner revision"
                            ),
                            Ok(false) => tracing::warn!(
                                steer_id = %steer.steer_id,
                                ?outcome,
                                %diagnostic,
                                "late user steer continuation did not complete; retaining exact accepted checkpoint"
                            ),
                            Err(error) => tracing::warn!(
                                %error,
                                steer_id = %steer.steer_id,
                                ?outcome,
                                "releasing undelivered late user steer failed"
                            ),
                        }
                    }
                    Err(_) => {
                        match db
                            .release_late_user_decision_steer_claim(
                                session_id,
                                steer.steer_id,
                                steer_epoch,
                                crate::agent_tree::system_now_unix_ms(),
                            )
                            .await
                        {
                            Ok(true) => tracing::debug!(
                                steer_id = %steer.steer_id,
                                "agent endpoint dropped an undelivered late steer; retaining pending order for retry"
                            ),
                            Ok(false) => tracing::warn!(
                                steer_id = %steer.steer_id,
                                "agent continuation dropped acknowledgement after durable acceptance; retaining exact checkpoint"
                            ),
                            Err(error) => tracing::warn!(
                                %error,
                                steer_id = %steer.steer_id,
                                "releasing dropped late user steer acknowledgement failed"
                            ),
                        }
                    }
                }
            });
        }
        Ok(())
    })
}

/// Enqueue a newly pending late steer without ever waiting for an executor's
/// bounded control mailbox.  A full mailbox is an ordinary retry condition:
/// the caller releases only the still-pending durable claim, then a later
/// owner `running` transition schedules it again.  This helper deliberately
/// has no accepted-checkpoint branch; an accepted steer is boot/recovery-only
/// and its immutable claim must never be released for mailbox pressure.
fn try_send_pending_late_user_steer(
    endpoint: &WorkerAgentTreeResolverEndpoint,
    agent_instance_id: uuid::Uuid,
    steer_id: uuid::Uuid,
    continuation_id: uuid::Uuid,
    recovery_epoch: uuid::Uuid,
    payload_json: String,
    respond_to: tokio::sync::oneshot::Sender<
        crate::engine::driver::LateUserSteerContinuationOutcome,
    >,
) -> std::result::Result<(), bool> {
    match endpoint {
        WorkerAgentTreeResolverEndpoint::Driver(driver_control_tx) => driver_control_tx
            .try_send(
                crate::engine::driver::DriverControl::DeliverLateUserDecisionSteer {
                    agent_instance_id,
                    steer_id,
                    continuation_id,
                    recovery_epoch,
                    payload_json,
                    respond_to,
                },
            )
            .map_err(|error| matches!(error, tokio::sync::mpsc::error::TrySendError::Closed(_))),
        WorkerAgentTreeResolverEndpoint::Noninteractive(executor_tx) => executor_tx
            .try_send(
                crate::engine::agent::AgentTreeExecutorRequest::DeliverLateUserDecisionSteer {
                    steer_id,
                    continuation_id,
                    recovery_epoch,
                    payload_json,
                    respond_to,
                },
            )
            .map_err(|error| matches!(error, tokio::sync::mpsc::error::TrySendError::Closed(_))),
        WorkerAgentTreeResolverEndpoint::HostOperation => {
            // `deliver_live_agent_tree_late_user_steers` rejects this before
            // claiming a row. Keep the match exhaustive if a future caller
            // bypasses that boundary, but do not manufacture a host control
            // continuation from a user-authored steer.
            Err(true)
        }
    }
}

/// Attempt recovery attachment without coupling worker progress to a bounded
/// driver mailbox.  This helper is used only for an already accepted
/// checkpoint during boot/recovery.  A full mailbox retains its DB claim and
/// retries the same control packet only for a bounded startup window; it never calls
/// `release_late_user_decision_steer_claim`, so an accepted user body cannot
/// return to normal live delivery.
async fn schedule_accepted_late_steer_recovery_control(
    driver_control_tx: tokio::sync::mpsc::Sender<crate::engine::driver::DriverControl>,
    control: crate::engine::driver::DriverControl,
) -> std::result::Result<(), bool> {
    match driver_control_tx.try_send(control) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(true),
        Err(tokio::sync::mpsc::error::TrySendError::Full(control)) => {
            let mut control = control;
            for attempt in 1..=ACCEPTED_LATE_STEER_RECOVERY_RETRY_ATTEMPTS {
                // This is bounded startup coordination, not a mailbox send
                // await: the worker remains free of a model/control wait and
                // gives a just-started driver a short chance to drain its
                // bootstrap controls before we fail this recovery epoch.
                tokio::time::sleep(ACCEPTED_LATE_STEER_RECOVERY_RETRY_DELAY).await;
                match driver_control_tx.try_send(control) {
                    Ok(()) => return Ok(()),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(next_control)) => {
                        control = next_control;
                        tracing::debug!(
                            attempt,
                            "accepted late-steer recovery control mailbox remains full; retaining durable checkpoint"
                        );
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return Err(true),
                }
            }
            tracing::warn!(
                "accepted late-steer recovery control retries exhausted; retaining durable checkpoint for next boot"
            );
            Err(false)
        }
    }
}

/// An accepted row is recoverable only when its checkpoint still proves the
/// immutable steer/continuation/owner binding.  The user payload itself stays
/// in the canonical steer row (rather than being copied into a second private
/// blob), so this validation prevents a malformed checkpoint from being used
/// to attach that body to a different executor.
fn accepted_late_user_steer_checkpoint_matches(
    steer: &crate::db::agent_tree_decisions::LateUserDecisionSteer,
    checkpoint_json: &str,
) -> bool {
    let Ok(checkpoint) = serde_json::from_str::<serde_json::Value>(checkpoint_json) else {
        return false;
    };
    let steer_id = steer.steer_id.to_string();
    let continuation_id = steer.continuation_id.to_string();
    let agent_instance_id = steer.agent_instance_id.to_string();
    let decision_request_id = steer.decision_request_id.to_string();
    let payload_bytes = i64::try_from(steer.payload_json.as_bytes().len()).ok();
    let Some(accepted_agent_revision) = steer.accepted_agent_revision else {
        return false;
    };
    let Some(recorded_payload_bytes) = steer.payload_bytes else {
        return false;
    };
    checkpoint
        .get("version")
        .and_then(serde_json::Value::as_u64)
        == Some(1)
        && checkpoint
            .get("steer_id")
            .and_then(serde_json::Value::as_str)
            == Some(steer_id.as_str())
        && checkpoint
            .get("continuation_id")
            .and_then(serde_json::Value::as_str)
            == Some(continuation_id.as_str())
        && checkpoint
            .get("agent_instance_id")
            .and_then(serde_json::Value::as_str)
            == Some(agent_instance_id.as_str())
        && checkpoint
            .get("decision_request_id")
            .and_then(serde_json::Value::as_str)
            == Some(decision_request_id.as_str())
        && checkpoint
            .get("agent_revision")
            .and_then(serde_json::Value::as_i64)
            == Some(accepted_agent_revision)
        && checkpoint
            .get("payload_bytes")
            .and_then(serde_json::Value::as_i64)
            == payload_bytes
        && recorded_payload_bytes == payload_bytes.unwrap_or(-1)
}

/// The root continuation snapshot's parked marker is deliberately separate
/// from the tool payload: the marker proves which durable Attention row is
/// allowed to reattach this root frame, while that row remains the authority
/// for the exact tool call and its response. A malformed marker fails closed
/// rather than allowing an unrelated root question to resume an accepted
/// late-steer continuation after restart.
fn root_parked_interrupt_id_from_snapshot(
    snapshot_json: &str,
) -> anyhow::Result<Option<uuid::Uuid>> {
    let snapshot: serde_json::Value = serde_json::from_str(snapshot_json)
        .context("parsing recovered root continuation snapshot for parked interrupt marker")?;
    snapshot
        .get("parked_interrupt_id")
        .map(|raw| {
            let raw = raw
                .as_str()
                .context("root parked interrupt marker is not a UUID string")?;
            uuid::Uuid::parse_str(raw).context("root parked interrupt marker is not a UUID")
        })
        .transpose()
}

/// Continue an owner-local *pending* steer stream only after its preceding
/// continuation is durably terminal. Accepted checkpoints are intentionally
/// absent from this live scheduler: they are boot/recovery-only work, because
/// attaching one can require a durable executor reattachment and must never
/// wait behind a running driver's bounded control mailbox.
fn deliver_next_pending_late_user_steer<'a>(
    session: &'a Arc<Session>,
    session_id: uuid::Uuid,
    agent_instance_id: uuid::Uuid,
    registry: &'a Arc<WorkerAgentTreeResolverRegistry>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
    deliver_live_agent_tree_late_user_steers(session, session_id, agent_instance_id, registry, None)
}

pub(super) fn redaction_failed_interrupt_decision_payload(
    interrupt_id: uuid::Uuid,
    decision: &crate::daemon::proto::InterruptDecision,
) -> serde_json::Value {
    let lines = decision
        .lines
        .iter()
        .map(|_| {
            serde_json::json!({
                "prompt": INTERRUPT_REDACTION_FAILED,
                "answer": INTERRUPT_REDACTION_FAILED,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "interrupt_id": interrupt_id,
        "decision": {
            "permission": decision.permission,
            "cancelled": decision.cancelled,
            "lines": lines,
        },
    })
}

pub(super) fn record_interrupt_decision_event(
    session: &Session,
    redaction: &SharedRedactionTable,
    interrupt_id: uuid::Uuid,
    decision: &proto::InterruptDecision,
) -> Option<i64> {
    let data = serde_json::json!({
        "interrupt_id": interrupt_id,
        "decision": decision,
    });
    let scrubbed = crate::daemon::current_redaction(redaction).scrub(&data.to_string());
    let redacted_data = serde_json::from_str(&scrubbed).unwrap_or_else(|error| {
        tracing::warn!(
            %error,
            %interrupt_id,
            "interrupt decision redaction produced invalid JSON; persisting fail-closed placeholder"
        );
        redaction_failed_interrupt_decision_payload(interrupt_id, decision)
    });
    let data_json = match serde_json::to_string(&redacted_data) {
        Ok(data_json) => data_json,
        Err(error) => {
            tracing::warn!(%error, %interrupt_id, "serializing interrupt decision failed");
            return None;
        }
    };
    let session_id = session.id;
    session
        .db
        .blocking_write_for_sync_event(move |conn| {
            crate::db::Db::insert_session_event_json_conn(
                conn,
                session_id,
                crate::db::session_log::SessionEventKind::InterruptDecision,
                None,
                None,
                crate::db::session_log::SessionEventContext::default(),
                crate::db::session_log::now_ms(),
                &data_json,
            )
        })
        .map_err(|error| {
            tracing::warn!(%error, %interrupt_id, "recording interrupt decision failed");
            error
        })
        .ok()
}

pub(super) async fn finish_parked_replay_completion(
    session: &Session,
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    interrupts: &Arc<crate::engine::interrupt::InterruptHub>,
    session_id: uuid::Uuid,
    completion: ParkedReplayCompletion,
) -> bool {
    let outcome = match completion.result {
        Ok(outcome) => outcome,
        Err(error) => {
            // AgentTree-owned continuations acknowledge their execution claim
            // only after the exact executor reports successful consumption.
            // In particular, a missing/stale endpoint must leave the durable
            // `executing` row intact for the next recovery epoch; completing
            // it here would discard an already-recorded user response and
            // cause the child to re-run its pre-interrupt model prompt.
            if completion.decision.is_none() {
                let _ = session
                    .db
                    .mark_interrupt_interrupted(completion.interrupt_id)
                    .await;
            }
            tracing::warn!(
                %error,
                interrupt_id = %completion.interrupt_id,
                "parked interrupt replay failed"
            );
            send_current_session_event(
                session,
                event_tx,
                redaction,
                proto::Event::Notice {
                    session_id,
                    text: format!(
                        "Interrupted parked request {}: {error}",
                        completion.interrupt_id
                    ),
                },
                NoticeSource::DaemonDirect,
            );
            interrupts.emit_queue_state().await;
            return false;
        }
    };
    if matches!(
        outcome,
        crate::engine::driver::ParkedReplayOutcome::ParkedAgain
    ) {
        tracing::debug!(
            interrupt_id = %completion.interrupt_id,
            "parked interrupt replay parked on a later prompt"
        );
    }
    let replay_acknowledged = match session
        .db
        .complete_executing_interrupt(completion.interrupt_id)
        .await
    {
        Ok(true) => true,
        Ok(false) => {
            tracing::warn!(interrupt_id = %completion.interrupt_id, "parked interrupt replay lost its durable acknowledgement");
            false
        }
        Err(error) => {
            tracing::warn!(%error, interrupt_id = %completion.interrupt_id, "completing parked interrupt failed");
            false
        }
    };
    if !replay_acknowledged {
        return false;
    }
    let seq = completion.decision.as_ref().and_then(|decision| {
        record_interrupt_decision_event(session, redaction, completion.interrupt_id, decision)
    });
    send_current_event(
        event_tx,
        redaction,
        proto::Event::InterruptResolved {
            session_id,
            interrupt_id: completion.interrupt_id,
            decision: completion.decision,
            seq,
        },
    );
    if matches!(
        outcome,
        crate::engine::driver::ParkedReplayOutcome::ParkedAgain
    ) {
        interrupts.emit_active_from_db().await;
        return true;
    }
    if completion.was_active {
        interrupts.emit_active_from_db().await;
    } else {
        interrupts.emit_queue_state().await;
    }
    true
}

/// A terminal AgentTree decision may replay its parked continuation unless
/// that park is a host-approval tool (bash/write/…). Other decision-linked
/// tools — including `web_search`/`web_fetch` credential HostEffect prompts —
/// park under the dispatched tool name, not `"question"`, and must still
/// replay a recorded answer.
fn should_replay_terminal_linked_tool(
    row: &crate::db::needs_attention::NeedsAttentionRow,
    decision: &crate::db::agent_tree_decisions::DecisionRequestRow,
) -> bool {
    let host_approval =
        decision.host_approval_operation_id.is_some() || decision.decision_class == "host_approval";
    if host_approval {
        tracing::info!(
            interrupt_id = %row.interrupt_id,
            tool = row.parked.as_ref().map(|payload| payload.tool.as_str()),
            decision_class = %decision.decision_class,
            "skipping crash-recovery replay of host-approval parked tool"
        );
        return false;
    }
    if row
        .parked
        .as_ref()
        .is_some_and(|payload| payload.tool != "question")
    {
        tracing::debug!(
            interrupt_id = %row.interrupt_id,
            tool = row.parked.as_ref().map(|payload| payload.tool.as_str()),
            decision_class = %decision.decision_class,
            "replaying terminal linked decision for a non-question parked tool"
        );
    }
    true
}

async fn settle_or_replay_executing_interrupt(
    session: &crate::session::Session,
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
    row: crate::db::needs_attention::NeedsAttentionRow,
    terminal_tree_interrupt_replays: &mut Vec<crate::db::needs_attention::NeedsAttentionRow>,
) {
    let linked_decision = match session
        .db
        .decision_request_for_interrupt(session_id, row.interrupt_id)
        .await
    {
        Ok(decision) => decision,
        Err(error) => {
            tracing::error!(
                %error,
                interrupt_id = %row.interrupt_id,
                "loading executing interrupt lifecycle decision failed"
            );
            return;
        }
    };
    if let Some(decision) = linked_decision.as_ref()
        && decision.state.is_terminal()
        && should_replay_terminal_linked_tool(&row, decision)
    {
        terminal_tree_interrupt_replays.push(row);
        return;
    }
    settle_unrecoverable_interrupt(
        session,
        event_tx,
        redaction,
        session_id,
        row.interrupt_id,
        linked_decision.is_some(),
        interrupt_restart_notice_text(row.interrupt_id, Ok(())),
    )
    .await;
}

pub(super) fn validate_parked_interrupt_payload(
    row: &crate::db::needs_attention::NeedsAttentionRow,
) -> std::result::Result<(), &'static str> {
    let Some(payload) = row.parked.as_ref() else {
        return Err("missing replay payload");
    };
    if payload.tool.trim().is_empty() {
        return Err("missing parked tool name");
    }
    if payload.call_id.trim().is_empty() {
        return Err("missing parked tool call id");
    }
    if payload.resume.agent_id != row.agent_id {
        return Err("parked replay agent does not match interrupt row");
    }
    if payload.resume.call_id != payload.call_id {
        return Err("parked replay call id does not match resume anchor");
    }
    Ok(())
}

fn interrupt_restart_notice_text(interrupt_id: Uuid, payload: Result<(), &'static str>) -> String {
    match payload {
        Ok(()) => format!(
            "Interrupted request {interrupt_id}: replay was in progress during worker restart."
        ),
        Err(reason) => format!("Interrupted request {interrupt_id}: {reason}."),
    }
}

async fn settle_unrecoverable_interrupt(
    session: &crate::session::Session,
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
    interrupt_id: Uuid,
    linked: bool,
    notice_text: String,
) {
    let marked = if linked {
        session
            .db
            .mark_executing_linked_interrupt_interrupted(session_id, interrupt_id)
            .await
    } else {
        session.db.mark_interrupt_interrupted(interrupt_id).await
    };
    match marked {
        Ok(true) => {}
        Ok(false) => tracing::error!(
            %interrupt_id,
            %session_id,
            linked,
            "settling unrecoverable interrupt did not change the durable row"
        ),
        Err(error) => tracing::warn!(
            %error,
            %interrupt_id,
            "marking unrecoverable interrupt failed"
        ),
    }
    send_current_session_event(
        session,
        event_tx,
        redaction,
        proto::Event::Notice {
            session_id,
            text: notice_text,
        },
        NoticeSource::DaemonDirect,
    );
}

pub(super) async fn forward_queue_updates(
    mut queue_update_rx: watch::Receiver<Vec<crate::engine::message::QueuedUserMessage>>,
    event_tx: EventSender,
    redaction: SharedRedactionTable,
    session_id: Uuid,
) {
    while queue_update_rx.changed().await.is_ok() {
        let queue = queue_update_rx.borrow_and_update().clone();
        send_current_event(
            &event_tx,
            &redaction,
            proto::Event::QueueUpdated {
                session_id,
                queue: queue.into_iter().map(queue_item_to_proto).collect(),
            },
        );
    }
}

pub(super) async fn persist_staged_terminal_removal(
    session: &Session,
    queue: &crate::engine::message::UserSubmissionQueue,
    staged: crate::engine::message::StagedQueueRemoval,
    disposition: crate::db::session_log::ClientSubmissionTerminalDisposition,
) -> std::result::Result<
    (
        Vec<crate::engine::message::QueuedUserMessage>,
        Vec<crate::engine::message::QueuedUserMessage>,
        Vec<crate::engine::message::ClientSubmissionReceipt>,
    ),
    proto::ErrorPayload,
> {
    let removed = staged.removed().to_vec();
    let receipts = queue.accepted_receipts(staged.ids()).await;
    let terminal_receipts = receipts
        .iter()
        .map(
            |receipt| crate::db::session_log::ClientSubmissionTerminalReceipt {
                client_submission_id: receipt.id,
                fingerprint: receipt.fingerprint.clone(),
                wire_fingerprint: receipt.wire_fingerprint.clone(),
                origin_principal: receipt.origin_principal.clone(),
                disposition,
            },
        )
        .collect::<Vec<_>>();
    if !terminal_receipts.is_empty()
        && let Err(error) = session
            .db
            .terminalize_queued_text_artifact_submissions(
                session.id,
                terminal_receipts,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
    {
        queue.mark_staged_removal_failed(&staged).await;
        tracing::warn!(
            %error,
            receipt_count = receipts.len(),
            disposition = disposition.as_str(),
            "terminal client-submission receipt write failed; exact queued payload remains held"
        );
        return Err(user_message_database_error(
            &error,
            proto::ErrorCode::Internal,
            "could not durably remove queued message; its exact payload remains held and will not execute; retry the same removal",
        ));
    }
    let snapshot = commit_staged_removal_after_receipts(session, queue, staged, &receipts).await;
    Ok((removed, snapshot, receipts))
}

async fn commit_staged_removal_after_receipts(
    session: &Session,
    queue: &crate::engine::message::UserSubmissionQueue,
    staged: crate::engine::message::StagedQueueRemoval,
    receipts: &[crate::engine::message::ClientSubmissionReceipt],
) -> Vec<crate::engine::message::QueuedUserMessage> {
    let snapshot = queue.commit_staged_removal(staged).await;
    struct TerminalCleanupClock;
    impl crate::media_reservation::MonotonicClock for TerminalCleanupClock {
        fn now_ms(&self) -> u64 {
            0
        }
    }
    let ledger = crate::media_reservation::MediaReservationLedger::new(
        session.db.clone(),
        std::sync::Arc::new(TerminalCleanupClock),
    );
    let wall_ms = chrono::Utc::now()
        .timestamp_millis()
        .try_into()
        .unwrap_or(0);
    for receipt in receipts {
        if let Err(error) = ledger
            .complete_downstream_invocation(&receipt.id.to_string(), wall_ms)
            .await
        {
            tracing::warn!(%error,invocation=%receipt.id,"terminal queue removal left downstream media ownership retryable");
        }
    }
    snapshot
}

fn queue_removal_in_progress_error() -> proto::ErrorPayload {
    proto::ErrorPayload {
        code: proto::ErrorCode::Internal,
        message: "a previous failed queue removal remains held; retry that same removal or cancel the queued work"
            .to_string(),
    }
}

#[cfg(feature = "remote")]
pub(super) fn remote_queue_mutation_response(
    receipt: RemoteQueueMutationReceiptV1,
) -> proto::RemoveQueuedUserMessageResult {
    proto::RemoveQueuedUserMessageResult {
        applied: receipt.applied,
        reason: receipt.reason,
        removed_item: None,
        // QueueUpdated owns the mutable full queue view. Keeping it out of
        // this response makes Applied and Replay byte-identical and secret-free.
        queue: Vec::new(),
    }
}

/// Outcome of committing the transactional remote-operation ledger for an
/// authenticated remote `send_user_message`. Shared by the worker accept path
/// and the dispatch image-duplicate fast path so BOTH reserve the operation
/// through the SAME ledger primitive (no remote send returns accepted without a
/// ledger operation row).
/// Reserve+commit the transactional remote-operation ledger row for a remote
/// send. The request hash (bound to session + client_submission_id + payload in
/// dispatch) is the exactly-once key: a replayed identity returns `Replayed`
/// (no second commit), a reused identity carrying different content returns a
/// conflict, and the CALLER decides whether to enqueue based on the in-memory
/// dedup decision it already made (so a conflicting/duplicate submission never
/// double-enqueues). The closure performs no domain mutation — the ledger row
/// itself is the durable exactly-once acceptance record for the operation.
///
/// KNOWN NON-ATOMICITY (there is NO atomic durable-accept at the daemon accept
/// path yet, and this lane deliberately does NOT try to build one). Three
/// records that morally describe "this send was accepted" are committed
/// SEPARATELY, not in one transaction: for legacy inline/media sends, the
/// run-invocation MARKER (`accept_run_if_marked`, committed in the dispatch
/// arm before the worker dispatch); this transactional LEDGER row (committed
/// here on the worker accept); and the durable MESSAGE itself (written only
/// later when the driver folds it into `session_events`, post-inference).
/// Oversized FCM2 text bypasses this *legacy remote-attachment* ledger because
/// its atomic phase-one `message_operation_receipts` row is itself the durable
/// remote operation ledger (actor, operation id, keyed FCOR hash, request
/// digest, and replay-safe outcome), joined to its reservation and any bound
/// run invocation in one transaction.
/// The ledger DOES prevent a second ACCEPT and a normal-operation replay is
/// idempotent (no double-enqueue). BUT because the three are not mutually atomic,
/// a crash between any two of them leaves an inconsistent prefix: a committed
/// ledger/marker with no durable message; or (the marker predating the driver
/// notify) a run that starts before its marker is visible; and a crash after
/// inference STARTS but before the fold, followed by a client replay, re-drives
/// the enqueue and can invoke the model a SECOND time (a genuine double-EXECUTE
/// — the same exposure a LOCAL send has, which is also durable only at fold).
/// Closing all of these together requires routing acceptance through the atomic
/// `accept_message_with_attachments` (`message_operation_receipts` +
/// `message_submission_receipts` + `message_queue_items` — message + marker +
/// ledger in ONE tx, committed before the driver is notified), which needs the
/// `CanonicalSendUserMessageV2` envelope owned by the
/// `unify-media-model-and-send-user-message-v2-cutover` lane. This lane adds only
/// the ledger row; the marker is unchanged from main; the cross-record atomicity
/// is the V2 cutover's job.
#[cfg(feature = "remote")]
pub(super) async fn reserve_remote_send_operation_impl(
    db: &crate::db::Db,
    remote: &crate::daemon::session_worker::RemoteQueueOperation,
) -> crate::daemon::session_worker::RemoteSendDecision {
    use crate::daemon::session_worker::RemoteSendDecision;
    let outcome = db
        .execute_transactional_remote_operation(
            crate::db::remote_attachment_operations::ReserveRemoteOperation {
                logical_attachment_id: &remote.logical_attachment_id,
                operation_id: &remote.operation_id,
                authenticated_device_id: &remote.authenticated_device_id,
                authenticated_device_generation: remote.authenticated_device_generation,
                operation_class:
                    crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                request_hash: remote.request_hash,
                now_ms: chrono::Utc::now().timestamp_millis(),
            },
            move |_conn| {
                let safe_response = serde_json::to_vec(&serde_json::json!({
                    "schema_version": 1,
                    "kind": "send_user_message_accept",
                }))?;
                Ok(
                    crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                        value: (),
                        safe_response: safe_response.clone(),
                        outbox_kind: "send_user_message".into(),
                        outbox_payload: safe_response,
                    },
                )
            },
        )
        .await;
    match outcome {
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(())) => {
            RemoteSendDecision::Accepted
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(_)) => {
            RemoteSendDecision::Replayed
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict)
        | Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate) => {
            RemoteSendDecision::Rejected(proto::ErrorPayload {
                code: proto::ErrorCode::Conflict,
                message: "remote operation conflict".into(),
            })
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity)
        | Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity) => RemoteSendDecision::Rejected(proto::ErrorPayload {
            code: proto::ErrorCode::Conflict,
            message: "remote operation capacity reached".into(),
        }),
        Err(error) => RemoteSendDecision::Rejected(user_message_database_error(
            &error,
            proto::ErrorCode::Internal,
            "remote send could not be committed to the operation ledger",
        )),
    }
}

struct TextArtifactReceiptJoin;

impl crate::db::db::message_attachments::MessageAcceptanceJoin for TextArtifactReceiptJoin {
    fn validate_and_join(
        &self,
        _: &rusqlite::Connection,
        input: &crate::db::db::message_attachments::AcceptMessageInput,
    ) -> anyhow::Result<()> {
        // The FCM2 codec owns semantic validation. This local join is still an
        // explicit transaction participant so the receipt/queue/reservation
        // composition has the same shape as media admissions.
        anyhow::ensure!(
            input.attachments.is_empty(),
            "oversized text artifact admission cannot carry attachments"
        );
        Ok(())
    }
}

fn validate_oversized_artifact_admission(
    session_id: Uuid,
    submission: &crate::engine::message::UserSubmission,
    admission: &OversizedTextArtifactAdmission,
) -> anyhow::Result<crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2> {
    let receipt = submission
        .client_submissions
        .first()
        .ok_or_else(|| anyhow::anyhow!("oversized admission lacks a client submission receipt"))?;
    anyhow::ensure!(
        submission.client_submissions.len() == 1,
        "oversized artifact admission cannot fold multiple receipts"
    );
    anyhow::ensure!(
        submission.images.is_empty(),
        "oversized artifact admission cannot carry image parts"
    );
    match (
        admission.model_fence.as_ref(),
        submission.expected_model_state_generation,
        submission.expected_model.as_ref(),
    ) {
        (None, None, None) => {}
        (Some((generation, model)), Some(expected_generation), Some(expected_model))
            if *generation == expected_generation && model == expected_model => {}
        _ => {
            anyhow::bail!("oversized artifact admission model fence does not match the submission")
        }
    }
    let canonical = crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2::decode(
        &admission.canonical_message,
    )?;
    anyhow::ensure!(
        canonical.session_id == session_id,
        "FCM2 session does not match worker"
    );
    anyhow::ensure!(
        canonical.request.client_submission_id == receipt.id,
        "FCM2 submission identity does not match queue receipt"
    );
    anyhow::ensure!(
        canonical.request.text == submission.text,
        "FCM2 source text does not match the transport-normalized submission"
    );
    anyhow::ensure!(
        canonical.request.display_text == submission.display_text,
        "FCM2 display text does not match the submission"
    );
    anyhow::ensure!(
        canonical.request.forced_skill == submission.forced_skill,
        "FCM2 forced skill does not match the submission"
    );
    anyhow::ensure!(
        canonical.request.attachments.is_empty(),
        "FCM2 oversized-source admission unexpectedly contains media"
    );
    anyhow::ensure!(
        canonical.request.tag_expansions.len() == submission.tag_expansions.len()
            && canonical
                .request
                .tag_expansions
                .iter()
                .zip(&submission.tag_expansions)
                .all(|(canonical, submitted)| {
                    canonical.tool == submitted.tool
                        && canonical.path == submitted.path
                        && canonical.detail == submitted.detail
                        && canonical.ok == submitted.ok
                }),
        "FCM2 tag expansions do not match the submission"
    );
    anyhow::ensure!(
        canonical.request.text.len() > 64 * 1024,
        "FCM2 artifact admission does not cross the inline threshold"
    );
    anyhow::ensure!(
        canonical.message_request_digest()? == admission.message_request_digest
            && canonical.attachment_set_digest()? == admission.attachment_set_digest,
        "FCM2 receipt digests do not match admission evidence"
    );
    Ok(canonical)
}

fn text_artifact_terminal_error(
    reason: crate::db::db::text_artifacts::TextArtifactRejectReason,
) -> proto::ErrorPayload {
    proto::ErrorPayload {
        code: if reason
            == crate::db::db::text_artifacts::TextArtifactRejectReason::IdempotencyConflict
        {
            proto::ErrorCode::IdempotencyConflict
        } else {
            proto::ErrorCode::UserMessageTerminated
        },
        message: format!("oversized user message is terminal ({})", reason.as_str()),
    }
}

/// Preserve SQLite durability categories at the user-message boundary.
///
/// User-message admission has specialized fallback errors, but those must not
/// erase a storage failure whose commit outcome may be unknown. Clients retain
/// and reconcile the exact submission only for these structured storage codes.
fn user_message_database_error(
    error: &anyhow::Error,
    fallback_code: proto::ErrorCode,
    fallback_message: impl Into<String>,
) -> proto::ErrorPayload {
    let code = match crate::db::classify_database_storage_failure(error.as_ref()) {
        Some(crate::db::DatabaseStorageFailure::Capacity) => proto::ErrorCode::StorageFull,
        Some(crate::db::DatabaseStorageFailure::Memory) => proto::ErrorCode::StorageMemory,
        Some(crate::db::DatabaseStorageFailure::ReadOnly) => proto::ErrorCode::StorageReadOnly,
        Some(crate::db::DatabaseStorageFailure::Io) => proto::ErrorCode::StorageIo,
        Some(crate::db::DatabaseStorageFailure::Corrupt) => proto::ErrorCode::StorageCorrupt,
        None => {
            return proto::ErrorPayload {
                code: fallback_code,
                message: fallback_message.into(),
            };
        }
    };
    proto::ErrorPayload {
        code,
        message: format!("{error:#}"),
    }
}

#[cfg(test)]
mod user_message_database_error_tests {
    use super::*;

    #[test]
    fn every_queue_receipt_storage_failure_keeps_its_ambiguous_reconciliation_code() {
        for (sqlite_code, protocol_code) in [
            (rusqlite::ErrorCode::DiskFull, proto::ErrorCode::StorageFull),
            (
                rusqlite::ErrorCode::OutOfMemory,
                proto::ErrorCode::StorageMemory,
            ),
            (
                rusqlite::ErrorCode::ReadOnly,
                proto::ErrorCode::StorageReadOnly,
            ),
            (
                rusqlite::ErrorCode::SystemIoFailure,
                proto::ErrorCode::StorageIo,
            ),
            (
                rusqlite::ErrorCode::DatabaseCorrupt,
                proto::ErrorCode::StorageCorrupt,
            ),
        ] {
            let sqlite = rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: sqlite_code,
                    extended_code: 0,
                },
                None,
            );
            let error = anyhow::Error::new(sqlite)
                .context("terminal queue receipt commit outcome is ambiguous");
            let payload = user_message_database_error(
                &error,
                proto::ErrorCode::UserMessageNotAccepted,
                "fallback must not win",
            );
            assert_eq!(payload.code, protocol_code);
            assert!(
                payload
                    .message
                    .contains("terminal queue receipt commit outcome is ambiguous")
            );
        }
    }

    #[test]
    fn non_storage_failure_retains_the_phase_specific_fallback() {
        let payload = user_message_database_error(
            &anyhow::anyhow!("validation failed"),
            proto::ErrorCode::UserMessageNotAccepted,
            "phase-specific refusal",
        );
        assert_eq!(payload.code, proto::ErrorCode::UserMessageNotAccepted);
        assert_eq!(payload.message, "phase-specific refusal");
    }
}

/// Map a fresh remote-ledger rejection to the closed FCM2 terminal domain.
/// Once phase one owns a reservation, callers must not leave it accepted just
/// because a later, independent in-memory/remote admission gate declined the
/// message. The exact lease composition below owns the receipt, reservation,
/// and any bound run invocation together.
#[cfg(feature = "remote")]
fn remote_send_rejection_reason(
    error: &proto::ErrorPayload,
) -> crate::db::db::text_artifacts::TextArtifactRejectReason {
    match error.code {
        proto::ErrorCode::Conflict | proto::ErrorCode::IdempotencyConflict => {
            crate::db::db::text_artifacts::TextArtifactRejectReason::IdempotencyConflict
        }
        _ => crate::db::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
    }
}

/// Consume a phase-one lease only when this caller still owns its exact
/// token/expiry pair.  A stale token is deliberately not treated as a
/// rejection: another renewer, materializer, or reaper owns the durable
/// outcome, so reload it and make the client retry rather than inventing a
/// second terminal result.
async fn reject_oversized_text_artifact_admission(
    session: &Session,
    reservation: crate::db::db::text_artifacts::TextArtifactReservation,
    reason: crate::db::db::text_artifacts::TextArtifactRejectReason,
) -> proto::ErrorPayload {
    let replay_session_id = reservation.session_id;
    let replay_operation_id = reservation.operation_id;
    let now_ms = chrono::Utc::now().timestamp_millis();
    match session
        .db
        .reject_and_release_text_artifact_reservation(reservation, reason, now_ms)
        .await
    {
        Ok(crate::db::db::text_artifacts::TextArtifactReservationTransition::Applied(reason)) => {
            text_artifact_terminal_error(reason)
        }
        Ok(crate::db::db::text_artifacts::TextArtifactReservationTransition::Stale) => {
            match session
                .db
                .text_artifact_reservation_replay(replay_session_id, replay_operation_id, now_ms)
                .await
            {
                Ok(crate::db::db::text_artifacts::TextArtifactReservationReplay::Terminal {
                    reason,
                }) => text_artifact_terminal_error(reason),
                Ok(_) => {
                    tracing::warn!(%replay_session_id, operation_id = ?replay_operation_id,
                        "oversized admission changed while terminalizing; retry will join its durable winner");
                    proto::ErrorPayload {
                        code: proto::ErrorCode::UserMessageNotAccepted,
                        message: "oversized user message admission changed; retry".to_owned(),
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, %replay_session_id, operation_id = ?replay_operation_id,
                        "could not reload stale oversized admission after terminalization");
                    user_message_database_error(
                        &error,
                        proto::ErrorCode::UserMessageNotAccepted,
                        "could not finalize oversized user message admission; retry",
                    )
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, %replay_session_id, operation_id = ?replay_operation_id,
                "failed to terminalize oversized user-message admission");
            user_message_database_error(
                &error,
                proto::ErrorCode::UserMessageNotAccepted,
                "could not finalize oversized user message admission; retry",
            )
        }
    }
}

/// Rebuild only phase-one FCM2 oversized text entries after startup
/// reconciliation. The durable receipt/lease remains the authority; the
/// in-memory queue is merely reconstituted so the driver can perform phase
/// two. No security, preflight, translation, title, or provider work occurs
/// here.
pub(super) async fn replay_accepted_oversized_text_artifact_queue(
    session: &Session,
    queue: &crate::engine::message::UserSubmissionQueue,
    target: crate::engine::message::QueueTarget,
    authoritative_active_model_state: &Arc<RwLock<Option<proto::ActiveModelState>>>,
) -> Result<usize> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    session
        .db
        .reap_expired_text_artifact_reservations(now_ms)
        .await
        .context("reconciling expired oversized text reservations")?;
    let rows = session
        .db
        .accepted_message_queue(session.id)
        .await
        .context("loading accepted FCM2 message queue")?;
    let mut replayed = 0usize;
    for row in rows {
        let canonical =
            match crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2::decode(
                &row.canonical_message,
            ) {
                Ok(canonical) => canonical,
                // Accepted attachment rows can also carry FCM2. This replay path
                // owns only text-artifact rows, so another attachment owner keeps
                // responsibility for its own durable restart behavior.
                Err(_) => continue,
            };
        if canonical.session_id != session.id
            || !canonical.request.attachments.is_empty()
            || canonical.request.text.len() <= 64 * 1024
        {
            continue;
        }
        let client_submission_id = Uuid::from_bytes(row.client_submission_id);
        anyhow::ensure!(
            canonical.request.client_submission_id == client_submission_id
                && row.queue_item_id == row.client_submission_id,
            "accepted oversized FCM2 queue identity is inconsistent"
        );
        let reservation = session
            .db
            .reserved_text_artifact_submission(session.id, row.client_submission_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("accepted oversized FCM2 queue row lacks its reservation")
            })?;
        let run_invocation_id =
            if reservation.reservation.run_invocation_bound {
                session
                .db
                .bound_text_artifact_run_invocation(session.id, row.client_submission_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!(
                    "bound oversized FCM2 reservation lacks its exact run invocation binding"
                ))
                .map(Some)?
            } else {
                None
            };
        let durable_model_fence = match reservation.reservation.model_fence.as_ref() {
            None => None,
            Some(fence) => match decode_durable_model_fence(&fence.model_json) {
                Ok(model) => Some((fence.generation, model)),
                Err(error) => {
                    tracing::warn!(%error, session_id = %session.id, client_submission_id = %client_submission_id,
                        "rejecting oversized replay with corrupt durable model fence");
                    let _ = reject_oversized_text_artifact_admission(
                        session,
                        reservation.reservation.clone(),
                        crate::db::db::text_artifacts::TextArtifactRejectReason::PreflightRejected,
                    )
                    .await;
                    continue;
                }
            },
        };
        if let Some((generation, model)) = durable_model_fence.as_ref() {
            let matches = {
                let current = authoritative_active_model_state
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                model_fence_allows_insert(current.as_ref(), *generation, model)
            };
            if !matches {
                tracing::info!(session_id = %session.id, client_submission_id = %client_submission_id,
                    "rejecting oversized replay with stale durable model fence");
                let _ = reject_oversized_text_artifact_admission(
                    session,
                    reservation.reservation.clone(),
                    crate::db::db::text_artifacts::TextArtifactRejectReason::PreflightRejected,
                )
                .await;
                continue;
            }
        }
        let wire_fingerprint = format!(
            "fcm2:{}",
            crate::intel::hex_lower(&canonical.message_request_digest()?)
        );
        let mut submission = crate::engine::message::UserSubmission {
            expected_model_state_generation: durable_model_fence
                .as_ref()
                .map(|(generation, _)| *generation),
            expected_model: durable_model_fence.map(|(_, model)| model),
            kind: crate::engine::message::UserSubmissionKind::User,
            origin: crate::engine::message::SubmissionOrigin::ExternalRoot,
            text: canonical.request.text,
            display_text: canonical.request.display_text,
            tag_expansions: canonical
                .request
                .tag_expansions
                .into_iter()
                .map(|tag| proto::TagExpansionMeta {
                    tool: tag.tool,
                    path: tag.path,
                    detail: tag.detail,
                    ok: tag.ok,
                })
                .collect(),
            images: Vec::new(),
            media: Vec::new(),
            forced_skill: canonical.request.forced_skill.clone(),
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: vec![client_submission_id],
            client_submissions: Vec::new(),
            queue_target: Some(target.clone()),
            // This durable FCM2 queue row is an oversized lease owner.  Keep
            // that identity on the reconstructed submission so a reaper or
            // terminal receipt can never make it fall through the ordinary
            // inline/provider path.
            pending_terminal_disposition: Some(
                crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact,
            ),
            run_invocation_id,
        };
        let fingerprint = submission.client_fingerprint();
        submission
            .client_submissions
            .push(crate::engine::message::ClientSubmissionReceipt {
                id: client_submission_id,
                fingerprint,
                wire_fingerprint,
                origin_principal: None,
            });
        let (_, _, outcome) = queue
            .push_idempotent(
                submission.client_submissions[0].clone(),
                submission,
                target.clone(),
            )
            .await;
        anyhow::ensure!(
            matches!(outcome, crate::engine::message::IdempotentPush::Inserted),
            "duplicate oversized FCM2 queue replay identity"
        );
        replayed += 1;
    }
    Ok(replayed)
}

/// Rebuild accepted V2 inline/media queue entries after daemon restart. The
/// canonical FCM2 row is the authored source of truth; normalized media bytes
/// are reacquired through the daemon-installed storage authority. Any failure
/// aborts worker startup, leaving the accepted receipt intact for a later
/// verified retry rather than dropping a modality or inventing a terminal.
pub(crate) async fn replay_accepted_message_attachment_queue(
    session: &Session,
    queue: &crate::engine::message::UserSubmissionQueue,
    target: crate::engine::message::QueueTarget,
) -> Result<usize> {
    use sha2::{Digest as _, Sha256};

    let rows = session
        .db
        .accepted_message_queue(session.id)
        .await
        .context("loading accepted V2 message queue")?;
    let project_text = session
        .project_root
        .to_str()
        .context("message media project root is not UTF-8")?;
    let project_digest = crate::intel::hex_lower(&Sha256::digest(project_text.as_bytes()));
    let authority = session.message_media_authority();
    let mut replayed = 0usize;
    for row in rows {
        let canonical =
            crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2::decode(
                &row.canonical_message,
            )?;
        anyhow::ensure!(
            canonical.session_id == session.id,
            "accepted V2 queue row belongs to a different session"
        );
        if canonical.request.text.len() > 64 * 1024 {
            anyhow::ensure!(
                canonical.request.attachments.is_empty(),
                "accepted V2 media queue row exceeds the inline text limit"
            );
            continue;
        }
        let client_submission_id = Uuid::from_bytes(row.client_submission_id);
        anyhow::ensure!(
            canonical.request.client_submission_id == client_submission_id
                && row.queue_item_id == row.client_submission_id,
            "accepted V2 queue identity is inconsistent"
        );
        let durable_attachments = session
            .db
            .message_attachment_receipts(session.id, row.client_submission_id)
            .await
            .context("loading accepted V2 attachment receipts")?;
        anyhow::ensure!(
            durable_attachments.len() == canonical.request.attachments.len()
                && durable_attachments
                    .iter()
                    .zip(&canonical.request.attachments)
                    .enumerate()
                    .all(|(ordinal, (durable, canonical))| {
                        durable.ordinal as usize == ordinal
                            && durable.attachment_id == *canonical.attachment_id.as_bytes()
                            && durable.attachment_version == canonical.attachment_version
                            && durable.checksum == canonical.checksum
                            && durable.kind == canonical.kind.code()
                    }),
            "accepted V2 canonical media differs from its durable receipt"
        );
        let media = if canonical.request.attachments.is_empty() {
            Vec::new()
        } else {
            let (storage, ledger) = authority
                .as_ref()
                .context("durable media storage unavailable for accepted V2 replay")?;
            storage
                .acquire_message_media_bound(crate::media_storage::AcquireMessageMediaInput {
                    attachments: canonical.request.attachments.clone(),
                    session_id: session.id,
                    project_digest: project_digest.clone(),
                    consumer_id: client_submission_id.to_string(),
                    ledger,
                    now_unix_ms: chrono::Utc::now().timestamp_millis(),
                })
                .await
                .context("reacquiring accepted V2 media")?
        };
        let run_invocation_id = session
            .db
            .get_run_invocation(client_submission_id)
            .await?
            .map(|_| client_submission_id);
        let wire_fingerprint = format!(
            "fcm2:{}",
            crate::intel::hex_lower(&canonical.message_request_digest()?)
        );
        let request = canonical.request;
        let mut submission = crate::engine::message::UserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: crate::engine::message::UserSubmissionKind::User,
            origin: crate::engine::message::SubmissionOrigin::ExternalRoot,
            text: request.text,
            display_text: request.display_text,
            tag_expansions: request
                .tag_expansions
                .into_iter()
                .map(|tag| proto::TagExpansionMeta {
                    tool: tag.tool,
                    path: tag.path,
                    detail: tag.detail,
                    ok: tag.ok,
                })
                .collect(),
            images: Vec::new(),
            media,
            forced_skill: request.forced_skill,
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: vec![client_submission_id],
            client_submissions: Vec::new(),
            queue_target: Some(target.clone()),
            pending_terminal_disposition: Some(
                crate::engine::message::PendingSubmissionTerminalDisposition::MessageAttachments,
            ),
            run_invocation_id,
        };
        let fingerprint = submission.client_fingerprint();
        submission
            .client_submissions
            .push(crate::engine::message::ClientSubmissionReceipt {
                id: client_submission_id,
                fingerprint,
                wire_fingerprint,
                origin_principal: None,
            });
        let (_, _, outcome) = queue
            .push_idempotent(
                submission.client_submissions[0].clone(),
                submission,
                target.clone(),
            )
            .await;
        anyhow::ensure!(
            matches!(outcome, crate::engine::message::IdempotentPush::Inserted),
            "duplicate accepted V2 queue replay identity"
        );
        replayed += 1;
    }
    Ok(replayed)
}

#[cfg(feature = "remote")]
struct RemoteQueueMutationCommit<'a> {
    session: &'a Session,
    queue: &'a crate::engine::message::UserSubmissionQueue,
    staged: Option<crate::engine::message::StagedQueueRemoval>,
    result: crate::engine::message::RemoveQueuedMessageResult,
    operation: RemoteQueueOperation,
    outbox_kind: &'static str,
    event_tx: &'a EventSender,
    redaction: &'a SharedRedactionTable,
}

#[cfg(feature = "remote")]
async fn commit_remote_queue_mutation(
    input: RemoteQueueMutationCommit<'_>,
) -> std::result::Result<RemoteQueueMutationReceiptV1, proto::ErrorPayload> {
    let RemoteQueueMutationCommit {
        session,
        queue,
        staged,
        result,
        operation,
        outbox_kind,
        event_tx,
        redaction,
    } = input;
    let disposition = crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
    let receipts = if let Some(staged) = staged.as_ref() {
        queue.accepted_receipts(staged.ids()).await
    } else {
        Vec::new()
    };
    if let Some(staged) = staged.as_ref()
        && receipts.is_empty()
    {
        queue.mark_staged_removal_failed(staged).await;
        return Err(proto::ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "queued message lacks its durable acceptance receipt; removal remains held"
                .into(),
        });
    }
    let terminal_receipts = receipts
        .iter()
        .map(
            |receipt| crate::db::session_log::ClientSubmissionTerminalReceipt {
                client_submission_id: receipt.id,
                fingerprint: receipt.fingerprint.clone(),
                wire_fingerprint: receipt.wire_fingerprint.clone(),
                origin_principal: receipt.origin_principal.clone(),
                disposition,
            },
        )
        .collect::<Vec<_>>();
    let reason = remove_reason_to_proto(result);
    let removed_count = u32::try_from(staged.as_ref().map_or(0, |value| value.ids().len()))
        .map_err(|_| proto::ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "queue removal count exceeds protocol bound".into(),
        })?;
    let receipt = RemoteQueueMutationReceiptV1 {
        schema_version: 1,
        applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
        reason,
        removed_count,
    };
    let session_id = session.id;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let outcome = session.db.execute_transactional_remote_operation(
        crate::db::remote_attachment_operations::ReserveRemoteOperation {
            logical_attachment_id: &operation.logical_attachment_id, operation_id: &operation.operation_id,
            authenticated_device_id: &operation.authenticated_device_id, authenticated_device_generation: operation.authenticated_device_generation,
            operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
            request_hash: operation.request_hash, now_ms,
        },
        move |conn| {
            crate::db::Db::terminalize_queued_text_artifact_submissions_conn(
                conn,
                session_id,
                &terminal_receipts,
                now_ms,
            )?;
            receipt.validate()?;
            let safe_response = serde_json::to_vec(&receipt)?;
            Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation { value: receipt, safe_response: safe_response.clone(), outbox_kind: outbox_kind.into(), outbox_payload: safe_response })
        },
    ).await;
    match outcome {
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(receipt)) => {
            if let Some(staged) = staged { let _ = commit_staged_removal_after_receipts(session, queue, staged, &receipts).await; }
            send_terminal_receipts_event(event_tx, redaction, session_id, &receipts, disposition);
            Ok(receipt)
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes)) => {
            let receipt: RemoteQueueMutationReceiptV1 = serde_json::from_slice(&bytes).map_err(|error| proto::ErrorPayload { code: proto::ErrorCode::Internal, message: error.to_string() })?;
            receipt.validate().map_err(|error| proto::ErrorPayload { code: proto::ErrorCode::Internal, message: error.to_string() })?;
            if let Some(staged) = staged { let _ = commit_staged_removal_after_receipts(session, queue, staged, &receipts).await; }
            send_terminal_receipts_event(event_tx, redaction, session_id, &receipts, disposition);
            Ok(receipt)
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate) => {
            if let Some(staged) = staged.as_ref() { queue.abort_staged_removal(staged).await; }
            Err(proto::ErrorPayload { code: proto::ErrorCode::Conflict, message: "remote operation conflict".into() })
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity) => {
            if let Some(staged) = staged.as_ref() { queue.mark_staged_removal_failed(staged).await; }
            Err(proto::ErrorPayload { code: proto::ErrorCode::Conflict, message: "remote operation capacity reached".into() })
        }
        Err(error) => {
            if let Some(staged) = staged.as_ref() { queue.mark_staged_removal_failed(staged).await; }
            Err(user_message_database_error(
                &error,
                proto::ErrorCode::Internal,
                "remote queue operation could not be committed",
            ))
        }
    }
}

fn send_terminal_receipts_event(
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
    receipts: &[crate::engine::message::ClientSubmissionReceipt],
    disposition: crate::db::session_log::ClientSubmissionTerminalDisposition,
) {
    if receipts.is_empty() {
        return;
    }
    send_current_event(
        event_tx,
        redaction,
        proto::Event::UserMessagesTerminated {
            session_id,
            client_submission_ids: receipts.iter().map(|receipt| receipt.id).collect(),
            disposition: disposition.into(),
        },
    );
}

async fn probe_user_message(
    session: &Session,
    queue: &crate::engine::message::UserSubmissionQueue,
    session_id: Uuid,
    client_submission_id: Uuid,
    wire_fingerprint: &str,
    origin_principal: Option<&str>,
) -> std::result::Result<UserMessageProbeResult, proto::ErrorPayload> {
    let durable = session
        .db
        .client_submission_receipt(session_id, client_submission_id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, %session_id, %client_submission_id,
                "client submission probe failed; refusing ambiguous retry");
            user_message_database_error(
                &error,
                proto::ErrorCode::Internal,
                "could not verify whether this message was already accepted; retry",
            )
        })?;

    let terminal = if durable.is_none() {
        session
            .db
            .client_submission_terminal_receipt(session_id, client_submission_id)
            .await
            .map_err(|error| {
                tracing::warn!(%error, %session_id, %client_submission_id,
                    "terminal client submission probe failed; refusing ambiguous retry");
                user_message_database_error(
                    &error,
                    proto::ErrorCode::Internal,
                    "could not verify whether this message was already terminated; retry",
                )
            })?
    } else {
        None
    };

    let (probe, snapshot) = if let Some(receipt) = durable {
        let probe = if receipt.origin_principal.as_deref() != origin_principal {
            crate::engine::message::IdempotentProbe::Conflict
        } else if receipt.wire_fingerprint == wire_fingerprint {
            crate::engine::message::IdempotentProbe::ExactDuplicate
        } else {
            crate::engine::message::IdempotentProbe::ContentCheckRequired
        };
        (probe, queue.snapshot().await)
    } else if let Some(receipt) = terminal {
        if receipt.origin_principal.as_deref() != origin_principal {
            return Ok(UserMessageProbeResult::Conflict);
        }
        if receipt.wire_fingerprint == wire_fingerprint {
            return Err(proto::ErrorPayload {
                code: proto::ErrorCode::UserMessageTerminated,
                message: format!(
                    "client_submission_id {client_submission_id} is terminal ({}) and will not be executed",
                    receipt.disposition.as_str()
                ),
            });
        }
        (
            crate::engine::message::IdempotentProbe::ContentCheckRequired,
            queue.snapshot().await,
        )
    } else {
        queue
            .probe_idempotent(client_submission_id, wire_fingerprint, origin_principal)
            .await
    };
    Ok(match probe {
        crate::engine::message::IdempotentProbe::Unknown => UserMessageProbeResult::Unknown,
        crate::engine::message::IdempotentProbe::ContentCheckRequired => {
            UserMessageProbeResult::ContentCheckRequired
        }
        crate::engine::message::IdempotentProbe::Conflict => UserMessageProbeResult::Conflict,
        crate::engine::message::IdempotentProbe::ExactDuplicate => {
            let queue: Vec<proto::QueueItem> =
                snapshot.into_iter().map(queue_item_to_proto).collect();
            let item = queue
                .iter()
                .find(|item| item.id == client_submission_id)
                .cloned()
                .unwrap_or(proto::QueueItem {
                    id: client_submission_id,
                    status: proto::QueueItemStatus::Folding,
                    text: String::new(),
                    display_text: None,
                    target: proto::QueueTarget::default(),
                });
            UserMessageProbeResult::Duplicate { item, queue }
        }
    })
}

/// Work drained from the FIFO while startup checks for Cancel/Shutdown.
/// Non-stop items stay here in arrival order and are either served first by
/// the live loop or explicitly rejected if startup aborts with no live work.
#[derive(Default)]
struct StartupWorkInbox {
    pending: VecDeque<SessionWork>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupDrain {
    Ready,
    Disconnected,
}

impl StartupWorkInbox {
    fn drain(&mut self, work_rx: &mut mpsc::Receiver<SessionWork>) -> StartupDrain {
        loop {
            match work_rx.try_recv() {
                Ok(work) => self.pending.push_back(work),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => return StartupDrain::Ready,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    return StartupDrain::Disconnected;
                }
            }
        }
    }

    fn pop(&mut self) -> Option<SessionWork> {
        self.pending.pop_front()
    }

    /// Remove the first operation that is safe to execute while a committed
    /// trust revision is waiting for its provider projection. Ordinary work
    /// remains FIFO-stable on either side of the control operation.
    fn pop_trust_transition_control(&mut self) -> Option<SessionWork> {
        let index = self.pending.iter().position(|work| {
            matches!(
                work,
                SessionWork::ReplaceConfigSnapshot { .. } | SessionWork::Shutdown { .. }
            )
        })?;
        self.pending.remove(index)
    }

    fn push(&mut self, work: SessionWork) {
        self.pending.push_back(work);
    }

    fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    fn has_live_work(&self) -> bool {
        self.pending
            .iter()
            .any(|work| !matches!(work, SessionWork::Cancel | SessionWork::Shutdown { .. }))
    }

    fn has_shutdown(&self) -> bool {
        self.pending
            .iter()
            .any(|work| matches!(work, SessionWork::Shutdown { .. }))
    }

    fn should_abort_startup(&self, disconnected: bool) -> bool {
        !self.has_live_work() && (disconnected || self.has_shutdown())
    }

    fn reject_unstarted(&mut self) {
        while let Some(work) = self.pending.pop_front() {
            reject_unstarted_startup_work(work);
        }
    }
}

fn reject_unstarted_startup_work(work: SessionWork) {
    const STOPPED: &str = "session worker stopped before accepting startup work";
    match work {
        SessionWork::UserMessage { respond_to, .. } => {
            let _ = respond_to.send(Err(proto::ErrorPayload {
                code: proto::ErrorCode::UserMessageNotAccepted,
                message: STOPPED.into(),
            }));
        }
        SessionWork::ProbeUserMessage { respond_to, .. } => {
            let _ = respond_to.send(Err(proto::ErrorPayload {
                code: proto::ErrorCode::UserMessageNotAccepted,
                message: STOPPED.into(),
            }));
        }
        SessionWork::EmitRecoveredDefaultTerminals { respond_to, .. } => {
            let _ = respond_to.send(Err(STOPPED.into()));
        }
        SessionWork::SteerDelegation {
            respond_to,
            task_call_id,
            label,
            ..
        } => {
            let _ = respond_to.send(proto::DelegationSteerResult::not_steerable(
                task_call_id,
                Some(label),
                STOPPED.into(),
            ));
        }
        SessionWork::RemoveQueuedUserMessage { respond_to, .. }
        | SessionWork::RemoveNewestQueuedUserMessage { respond_to, .. } => {
            let _ = respond_to.send(Err(proto::ErrorPayload {
                code: proto::ErrorCode::Conflict,
                message: STOPPED.into(),
            }));
        }
        SessionWork::RemoveEditableQueuedUserMessages { respond_to, .. } => {
            let _ = respond_to.send(Err(proto::ErrorPayload {
                code: proto::ErrorCode::Conflict,
                message: STOPPED.into(),
            }));
        }
        SessionWork::ResolveAgentDecision { respond_to, .. } => {
            let _ = respond_to.send(Err(STOPPED.into()));
        }
        SessionWork::RepairResume { respond_to } => {
            let _ = respond_to.send(Err(STOPPED.into()));
        }
        SessionWork::SetRedaction { respond_to, .. } => {
            let _ = respond_to.send(Err(STOPPED.into()));
        }
        SessionWork::SetPreflight { respond_to, .. } => {
            let _ = respond_to.send(Err(STOPPED.into()));
        }
        SessionWork::SetLongcache { respond_to, .. } => {
            let _ = respond_to.send(Err(STOPPED.into()));
        }
        SessionWork::AuthorizeHostCapabilitiesRefresh { respond_to } => {
            let _ = respond_to.send(Err(HostCapabilitiesRefreshError::Internal(STOPPED.into())));
        }
        SessionWork::ReplaceConfigSnapshot { respond_to, .. } => {
            // No worker ever started, so nothing published and nothing can
            // apply: a publication receipt with no follow-up.
            let _ = respond_to.send(ReplaceConfigSnapshotAck::published(
                ReplaceConfigSnapshotResult {
                    generation: 0,
                    changed: false,
                    stale: false,
                },
            ));
        }
        SessionWork::Cancel
        | SessionWork::Shutdown { .. }
        | SessionWork::WakeGoal
        | SessionWork::RepublishQueue
        | SessionWork::ResolveInterrupt { .. }
        | SessionWork::SetActiveModel { .. }
        | SessionWork::SetAgent { .. }
        | SessionWork::SetLlmMode { .. }
        | SessionWork::SetSessionLlmMode { .. }
        | SessionWork::SetToolSurfaceOverride { .. }
        | SessionWork::SetGoalSettingsOverride { .. }
        | SessionWork::SetDelegationRecursion { .. }
        | SessionWork::SetTandemModels { .. }
        | SessionWork::CancelSchedule { .. }
        | SessionWork::Prune
        | SessionWork::Compact
        | SessionWork::Pin { .. } => {}
    }
}

fn abort_startup_if_only_stop(
    inbox: &mut StartupWorkInbox,
    work_rx: &mut mpsc::Receiver<SessionWork>,
) -> bool {
    let disconnected = matches!(inbox.drain(work_rx), StartupDrain::Disconnected);
    if inbox.should_abort_startup(disconnected) {
        inbox.reject_unstarted();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod startup_work_inbox_tests {
    use super::*;

    fn user_message_work(
        text: &str,
    ) -> (
        SessionWork,
        oneshot::Receiver<
            std::result::Result<(proto::QueueItem, Vec<proto::QueueItem>), proto::ErrorPayload>,
        >,
    ) {
        let (respond_to, response) = oneshot::channel();
        (
            SessionWork::UserMessage {
                submission: Box::new(crate::engine::message::UserSubmission::text(text)),
                #[cfg(feature = "remote")]
                remote_operation: None,
                artifact_admission: None,
                respond_to,
            },
            response,
        )
    }

    fn work_text(work: &SessionWork) -> Option<&str> {
        match work {
            SessionWork::UserMessage { submission, .. } => Some(submission.text.as_str()),
            SessionWork::Cancel => Some("cancel"),
            SessionWork::Shutdown { .. } => Some("shutdown"),
            _ => None,
        }
    }

    #[test]
    fn startup_drain_keeps_first_messages_in_fifo_order_ahead_of_shutdown() {
        let (tx, mut rx) = mpsc::channel(8);
        let (first, mut first_rx) = user_message_work("first queued");
        let (second, mut second_rx) = user_message_work("second queued");
        tx.try_send(first).unwrap();
        tx.try_send(second).unwrap();
        tx.try_send(SessionWork::Cancel).unwrap();
        tx.try_send(SessionWork::Shutdown {
            pause_for_resume: false,
        })
        .unwrap();

        let mut inbox = StartupWorkInbox::default();
        assert_eq!(inbox.drain(&mut rx), StartupDrain::Ready);
        assert!(inbox.has_live_work());
        assert!(inbox.has_shutdown());
        assert!(!inbox.should_abort_startup(false));
        assert!(!abort_startup_if_only_stop(&mut inbox, &mut rx));

        assert_eq!(
            work_text(&inbox.pop().expect("first message")),
            Some("first queued")
        );
        assert_eq!(
            work_text(&inbox.pop().expect("second message")),
            Some("second queued")
        );
        assert_eq!(work_text(&inbox.pop().expect("cancel")), Some("cancel"));
        assert_eq!(work_text(&inbox.pop().expect("shutdown")), Some("shutdown"));
        assert!(inbox.is_empty());
        assert!(
            first_rx.try_recv().is_err(),
            "first message is still pending"
        );
        assert!(
            second_rx.try_recv().is_err(),
            "second message is still pending"
        );
    }

    #[test]
    fn startup_stop_without_live_work_rejects_nothing_and_aborts() {
        let (tx, mut rx) = mpsc::channel(4);
        tx.try_send(SessionWork::Cancel).unwrap();
        tx.try_send(SessionWork::Shutdown {
            pause_for_resume: false,
        })
        .unwrap();
        drop(tx);

        let mut inbox = StartupWorkInbox::default();
        assert!(abort_startup_if_only_stop(&mut inbox, &mut rx));
        assert!(inbox.is_empty());
    }

    #[test]
    fn unstarted_user_message_is_rejected_not_dropped() {
        let (work, mut response) = user_message_work("must not vanish");
        let mut inbox = StartupWorkInbox {
            pending: VecDeque::from([work]),
        };
        inbox.reject_unstarted();
        let error = response
            .try_recv()
            .expect("caller observes an explicit rejection")
            .expect_err("startup abort is not an accept");
        assert_eq!(error.code, proto::ErrorCode::UserMessageNotAccepted);
        assert!(error.message.contains("stopped before accepting"));
    }
}

async fn open_session_write_scope_root(
    write_scope: &crate::write_scope::WriteScopeSource,
    session_id: Uuid,
    project_root: &Path,
) {
    // Bind the clone in its own statement: an `if let` scrutinee keeps the
    // MutexGuard temporary alive for the whole block, and holding a std guard
    // across the `.await` below would make this future non-Send.
    let installed_coordinator = crate::sync::lock_or_recover(write_scope).clone();
    if let Some(coordinator) = installed_coordinator {
        match crate::write_scope::CanonicalScope::resolve_under(project_root, ".") {
            Ok(scope) => {
                if let Err(error) = coordinator
                    .ensure_session_root_lease(session_id, "session-root", scope)
                    .await
                {
                    tracing::warn!(
                        error = %error,
                        "could not open the session write-scope root lease"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "session cwd does not resolve; no write-scope root lease opened"
                );
            }
        }
    }
}

async fn materialize_deferred_session_lifecycle(
    session: &Session,
    session_id: Uuid,
    project_root: &Path,
    write_scope: &crate::write_scope::WriteScopeSource,
    reserved_root_id: Uuid,
    root_profile_snapshot_id: Option<Uuid>,
    durable_lifecycle_ready: &mut bool,
) -> anyhow::Result<()> {
    if *durable_lifecycle_ready {
        return Ok(());
    }
    open_session_write_scope_root(write_scope, session_id, project_root).await;
    let tree_now = crate::agent_tree::system_now_unix_ms();
    let workspace_ref = crate::agent_tree::workspace_ref_for_host_path(project_root)?;
    let tree_root = session
        .db
        .ensure_session_root_agent_with_id(
            session_id,
            reserved_root_id,
            root_profile_snapshot_id,
            workspace_ref,
            tree_now,
        )
        .await
        .context("creating durable root agent-tree node after lazy persist")?;
    if tree_root.state == crate::db::agent_tree_decisions::AgentInstanceState::Created {
        match session
            .db
            .transition_agent_instance(
                session_id,
                tree_root.agent_instance_id,
                tree_root.revision,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                "{}",
                tree_now,
            )
            .await
        {
            Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(_)) => {}
            Ok(_) => anyhow::bail!("durable root agent-tree node did not enter running"),
            Err(error) => {
                return Err(error).context("starting durable root agent-tree node");
            }
        }
    }
    *durable_lifecycle_ready = true;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_worker(
    session: Arc<Session>,
    locks: Arc<LockManager>,
    redact: Arc<RedactionTable>,
    model: Arc<Model>,
    model_override: Option<Arc<Model>>,
    thinking_params: Option<serde_json::Value>,
    endpoint_recovery_thinking_params: Option<
        crate::engine::model::EndpointRecoveryAdditionalParams,
    >,
    project_root: PathBuf,
    trust_policy: crate::config::trust::SharedWorkspaceTrustPolicy,
    mut work_rx: mpsc::Receiver<SessionWork>,
    event_tx: EventSender,
    turn_completions: Arc<Mutex<TurnCompletions>>,
    redaction: SharedRedactionTable,
    live: Arc<LiveState>,
    interactive_clients: Arc<std::sync::atomic::AtomicUsize>,
    sandbox_notice_armed: Arc<AtomicBool>,
    env_overlay: Arc<RwLock<HashMap<String, String>>>,
    repair_required: Arc<RwLock<Option<proto::ResumeRepairState>>>,
    foreground: Arc<Mutex<LiveForegroundState>>,
    config_snapshot: Arc<RwLock<SessionConfigSnapshot>>,
    trust_transition_pending: Arc<std::sync::atomic::AtomicI64>,
    authoritative_active_model_state: Arc<RwLock<Option<proto::ActiveModelState>>>,
    lsp: Arc<crate::daemon::lsp::LspManager>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    scheduler: Arc<std::sync::Mutex<Option<crate::daemon::scheduler::DaemonSchedulerHandle>>>,
    write_scope: crate::write_scope::WriteScopeSource,
    global_bus: Option<EventSender>,
    park_commit: crate::engine::interrupt::ParkCommit,
    terminal_lock_cleanup_gate: Arc<tokio::sync::Mutex<()>>,
    terminal_closing: Arc<AtomicBool>,
    terminal_cleanup_complete: Arc<AtomicBool>,
) {
    let session_id = session.id;
    let mut startup_inbox = StartupWorkInbox::default();
    // Destructive stop is 50ms in tests. If Shutdown/Cancel already landed
    // before this task was scheduled, leave before the expensive startup
    // path so `stop_worker` can observe a prompt exit.
    if abort_startup_if_only_stop(&mut startup_inbox, &mut work_rx) {
        return;
    }

    // Session config is resolved by the registry/ConfigSource, then held as a
    // generationed snapshot. Live-safe keys are read from the current snapshot
    // at turn boundaries; agent/model construction uses the snapshot captured
    // for that boundary.
    let start_config = config_snapshot
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let extended_cfg = start_config.extended.clone();
    // Effective LLM mode = active model `mode` override → active provider
    // `mode` override → the persisted global `llm_mode`
    // (implementation note). Re-resolved here so a
    // model/provider that pins a mode takes effect at session start (and on a
    // `/model` change, which restarts the worker on the new active model). A
    // live `/llm-mode` toggle still overrides this for the running session via
    // `DriverControl::SetLlmMode`.
    let llm_mode = stored_session_llm_mode(&session).unwrap_or_else(|| {
        resolve_effective_llm_mode(&session, &start_config.providers, extended_cfg.llm_mode)
    });
    // Root primary: the session's stored active agent (so a resume restarts
    // on `Plan` after a `/plan` swap, `plan.md §4.6.d`), falling back to the
    // configured default when it's unset/unknown. Removed stored primaries
    // force the release default (`Build`).
    let root_agent_name = match session.assistant_name.clone() {
        Some(name) => name,
        None => resolve_root_agent(session_id, &session.db, &extended_cfg, llm_mode).await,
    };
    if session.assistant_name.is_none()
        && let Some(text) =
            super::removed_primary_notice(session_id, &session.db, &extended_cfg).await
    {
        send_current_session_event(
            &session,
            &event_tx,
            &redaction,
            proto::Event::Notice { session_id, text },
            NoticeSource::DaemonDirect,
        );
    }
    let assistant_row = if let Some(name) = session.assistant_name.as_deref() {
        match session.db.get_assistant(name).await {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(%error, assistant = name, "loading assistant row for identity failed");
                None
            }
        }
    } else {
        None
    };
    let assistant_identity_prefix = match assistant_row {
        Some(row) => match crate::assistants::identity::load_for_session(&session.db, &row).await {
            Ok(load) => {
                for text in &load.notices {
                    send_current_session_event(
                        &session,
                        &event_tx,
                        &redaction,
                        proto::Event::Notice {
                            session_id,
                            text: text.clone(),
                        },
                        NoticeSource::DaemonDirect,
                    );
                }
                Some(load.system_prefix)
            }
            Err(error) => {
                tracing::warn!(%error, assistant = %row.name, "loading assistant identity failed");
                send_current_session_event(
                    &session,
                    &event_tx,
                    &redaction,
                    proto::Event::Notice {
                        session_id,
                        text: format!("Assistant identity could not be loaded: {error}"),
                    },
                    NoticeSource::DaemonDirect,
                );
                // Preserve the daemon-authenticated assistant-root marker
                // even when optional SOUL/USER prompt material is malformed.
                // Root definition resolution must still select the private
                // installation snapshot ahead of a same-named workspace file.
                Some(String::new())
            }
        },
        None => None,
    };
    // Capture the daemon-owned installation table once for the entire
    // session.  UUID child references select these authenticated definition
    // snapshots directly; neither child preflight nor construction may fall
    // back to a checkout name lookup.
    let vnext_local_installation_resolver =
        match crate::assistants::local_installation_resolver(&session.db).await {
            Ok(resolver) => resolver,
            Err(error) => {
                // The authenticated local-installation table is part of vNext
                // launch authority.  Starting a session without it would make
                // UUID children ambiguous (or invite a name-lookup fallback),
                // so report a terminal worker failure and refuse the session.
                let message =
                    format!("could not load daemon-local agent installation bindings: {error:#}");
                tracing::error!(%message, %session_id, "session startup refused");
                let mut driver_failed = false;
                emit_session_driver_failed_once(
                    &event_tx,
                    &turn_completions,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                    message,
                );
                return;
            }
        };
    // The daemon's shared shutdown gate, captured before `model` is moved into
    // `spawn_args`. Reused when building model-comparison tandem (shadow)
    // models so a tandem request — itself a new provider round-trip — refuses
    // to dispatch once a drain begins (`model-comparison-tandem-
    // inference.md`).
    let initial_model_for_toggles = model_override.as_ref().unwrap_or(&model);
    let initial_model_for_toggles = (
        initial_model_for_toggles.provider_id().to_string(),
        initial_model_for_toggles.model_id_ref().to_string(),
    );
    let shutdown_gate = model.shutdown_gate();
    let spawn_args = SpawnArgs {
        model,
        env_overlay: env_overlay.clone(),
        // The active model's resolved extra-request-body fragment
        // (implementation note) rides on every outbound
        // request via `ModelParams`; the rest are defaults as before.
        params: ModelParams {
            additional_params: thinking_params,
            endpoint_recovery_additional_params: endpoint_recovery_thinking_params,
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
        config: SessionConfigHandle::new(config_snapshot.clone()),
        session_short_id: session.short_id(),
        assistant_identity_prefix,
        model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
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
        vnext_grant: None,
        // vNext definitions are declarative requests only; the daemon
        // snapshots the core-owned host policy at root construction so their
        // effective grants are both usable and bounded for the whole tree.
        vnext_host_policy: Some(std::sync::Arc::new(
            crate::agents::VnextHostPolicy::for_session_config(&extended_cfg),
        )),
        vnext_local_installation_resolver,
        parent_vnext_grant: None,
        // Recursive-`Swarm` depth (GOALS §24): the `Swarm` root is depth 0;
        // each `bee` fan-out spawn advances it. The ceiling rides along so
        // the `spawn` description shows the remaining budget.
        swarm_depth: 0,
        swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
        // The root primary carries no per-delegation grants — grants attach to
        // an individual `task` delegation, never to the root spawn.
        granted_tools: Vec::new(),
        lock_identity: None,
        write_scope: None,
        // Owner-scoped store for delegated/computer-use model construction: a
        // child's `$secret:` model/header ref can only resolve a secret owned by
        // (provider, this session's workspace), never a foreign workspace's. See
        // `named-secret-ownership-boundary`.
        credential_store: session
            .provider_credential_store(&start_config.providers)
            .ok(),
    };
    let tool_surface_override = stored_tool_surface_override(&session);
    let _goal_settings_override = stored_goal_settings_override(&session);
    let root = Arc::new(
        match builtin::load_with_assistant_db_and_tool_surface_override(
            &root_agent_name,
            &spawn_args,
            &session.db,
            tool_surface_override.as_ref(),
        )
        .await
        {
            Ok(agent) => agent,
            Err(error) if tool_surface_override.is_some() => {
                tracing::warn!(
                    %error,
                    session_id = %session_id,
                    agent = %root_agent_name,
                    "applying stored tool surface override failed; falling back to agent definition"
                );
                builtin::load_with_assistant_db_and_tool_surface_override(
                    &root_agent_name,
                    &spawn_args,
                    &session.db,
                    None,
                )
                .await
                .unwrap_or_else(|_| builtin::default_build(&spawn_args))
            }
            Err(_) => builtin::load_with_assistant_db_and_tool_surface_override(
                &root_agent_name,
                &spawn_args,
                &session.db,
                None,
            )
            .await
            .unwrap_or_else(|_| builtin::default_build(&spawn_args)),
        },
    );

    // Snapshot the resolved agent-guidance file body that just went into
    // the frozen system block (live instructions-file diff injection,
    // prompt `instructions-file-live-diff.md`). This is the start-of-
    // session baseline a later in-place edit is diffed against; the driver
    // checks it on every outbound request. Recomputed on each worker spawn
    // (fresh or resumed) because `builtin::build` re-composes the system
    // block from the current file each time.
    session.snapshot_guidance_baseline(&project_root).await;

    let (queue_update_tx, queue_update_rx) =
        watch::channel::<Vec<crate::engine::message::QueuedUserMessage>>(Vec::new());
    let driver_input_queue = crate::engine::message::UserSubmissionQueue::new(queue_update_tx);
    let foreground_input_target = Arc::new(Mutex::new(crate::engine::message::QueueTarget::root(
        root.name.clone(),
    )));
    // Reconcile exact-expiry leases before rebuilding accepted FCM2 work. A
    // worker restart must either enqueue the still-live owner once or observe
    // its durable terminal/materialized winner; it never reruns preprocessing
    // merely because the in-memory queue was lost.
    let replay_target = foreground_input_target
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    match replay_accepted_message_attachment_queue(
        &session,
        &driver_input_queue,
        replay_target.clone(),
    )
    .await
    {
        Ok(replayed) if replayed > 0 => {
            tracing::info!(%session_id, replayed, "replayed accepted V2 inline/media queue entries");
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(%error, %session_id, "accepted V2 message startup reconciliation failed; refusing provider dispatch");
            send_current_session_event(
                &session,
                &event_tx,
                &redaction,
                proto::Event::Notice {
                    session_id,
                    text:
                        "Accepted message recovery could not be verified; no provider was started."
                            .to_owned(),
                },
                NoticeSource::DaemonDirect,
            );
            return;
        }
    }
    match replay_accepted_oversized_text_artifact_queue(
        &session,
        &driver_input_queue,
        replay_target,
        &authoritative_active_model_state,
    )
    .await
    {
        Ok(replayed) if replayed > 0 => {
            tracing::info!(%session_id, replayed, "replayed accepted oversized FCM2 queue entries");
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(%error, %session_id, "oversized FCM2 startup reconciliation failed; refusing provider dispatch");
            send_current_session_event(
                &session,
                &event_tx,
                &redaction,
                proto::Event::Notice {
                    session_id,
                    text:
                        "Oversized message recovery could not be verified; no provider was started."
                            .to_owned(),
                },
                NoticeSource::DaemonDirect,
            );
            return;
        }
    }
    let (driver_control_tx, driver_control_rx) =
        mpsc::channel::<crate::engine::driver::DriverControl>(WORK_QUEUE_CAPACITY);
    // Construct this before the event forwarder. Child-frame lifecycle events
    // update the same registry that decision delivery consults.
    let tree_resolver_registry = std::sync::Arc::new(WorkerAgentTreeResolverRegistry::default());
    let (engine_event_tx, mut engine_event_rx) = mpsc::channel::<TurnEvent>(WORK_QUEUE_CAPACITY);
    let engine_event_notice_tx = engine_event_tx.clone();

    // Forward engine events → broadcast channel as proto::Event, and
    // maintain the live job/turn status (GOALS §17f) off the same
    // authoritative stream. These signals originate from the driver turn
    // loop (`ThinkingStarted` / `AgentIdle`) and the single `ScheduleAuthority`
    // (`ScheduleStarted` / `ScheduleCompleted`); the forwarder is the one seam they
    // all pass through, so updating here never duplicates the authority.
    let event_tx_for_forward = event_tx.clone();
    let event_tx_for_queue = event_tx.clone();
    let turn_completions_for_forward = turn_completions.clone();
    let redaction_for_forward = redaction.clone();
    let redaction_for_queue = redaction.clone();
    let foreground_input_target_for_forward = foreground_input_target.clone();
    let foreground_for_forward = foreground.clone();
    let live_for_forward = live.clone();
    let sandbox_notice_armed_for_forward = sandbox_notice_armed.clone();
    let session_for_forward = session.clone();
    let authoritative_active_model_state_for_forward = authoritative_active_model_state.clone();
    let tree_resolver_registry_for_forward = tree_resolver_registry.clone();
    let driver_control_for_forward = driver_control_tx.clone();
    // The lock authority + the interactive-client count, for the
    // `AgentIdle`-with-zero-clients release edge
    // (implementation note). When a turn finishes and no
    // interactive client is attached, the session's locks are released here —
    // the second of the two edges (the first is the last-detach drop above).
    let locks_for_forward = locks.clone();
    let interactive_clients_for_forward = interactive_clients.clone();
    let forward = tokio::spawn(async move {
        let send_event = |ev: proto::Event| {
            update_authoritative_active_model_state(
                &authoritative_active_model_state_for_forward,
                &ev,
            );
            // Per-session de-dupe (§6.5): the engine emits `SandboxUnavailable`
            // on every refused `bash` (the verdict is process-lifetime-cached,
            // so it recurs), but the user needs only one persistent notice.
            // Forward the first; drop the recurring duplicates. `set_sandbox`
            // re-arms the latch when the user toggles `/sandbox`.
            if matches!(ev, proto::Event::SandboxUnavailable { .. })
                && !forward_sandbox_unavailable(&sandbox_notice_armed_for_forward)
            {
                return;
            }
            match &ev {
                proto::Event::ThinkingStarted { .. } => {
                    live_for_forward.processing.store(true, Ordering::Relaxed);
                }
                proto::Event::AgentIdle { .. } => {
                    live_for_forward.processing.store(false, Ordering::Relaxed);
                    live_for_forward.tool_running.store(0, Ordering::Relaxed);
                    // Last-detach-while-idle edge, idle side
                    // (implementation note): the turn just finished, so if no
                    // interactive client is attached, release this session's locks now.
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
                    // Saturating: never underflow if a completion is ever seen without its start.
                    let _ = live_for_forward.active_schedules.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |n| Some(n.saturating_sub(1)),
                    );
                }
                proto::Event::ToolStart { .. } => {
                    live_for_forward
                        .tool_running
                        .fetch_add(1, Ordering::Relaxed);
                }
                proto::Event::ToolEnd { .. } | proto::Event::ToolError { .. } => {
                    let _ = live_for_forward.tool_running.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |n| Some(n.saturating_sub(1)),
                    );
                }
                _ => {}
            }
            resolve_turn_terminal_event(&turn_completions_for_forward, &ev);
            // `send` returns `Err` only when there are no subscribers — that's fine.
            send_current_session_event(
                &session_for_forward,
                &event_tx_for_forward,
                &redaction_for_forward,
                ev,
                NoticeSource::EngineTurn,
            );
        };

        let mut coalescer = StreamDeltaCoalescer::default();
        loop {
            if let Some(deadline) = coalescer.deadline() {
                tokio::select! {
                    maybe_event = engine_event_rx.recv() => {
                        let Some(event) = maybe_event else {
                            for ev in coalescer.flush() {
                                send_event(ev);
                            }
                            break;
                        };
                        if let Some((agent_instance_id, attached, endpoint_generation)) =
                            agent_tree_executor_endpoint_event(&event)
                        {
                            if attached {
                                tree_resolver_registry_for_forward.attach_parent_endpoint(
                                    session_id,
                                    agent_instance_id,
                                    endpoint_generation,
                                    driver_control_for_forward.clone(),
                                );
                            } else {
                                tree_resolver_registry_for_forward
                                    .detach_parent_endpoint_if_generation(
                                        session_id,
                                        agent_instance_id,
                                        endpoint_generation,
                                    );
                            }
                        }
                        if let Some((agent_instance_id, endpoint_generation, endpoint)) =
                            agent_tree_noninteractive_endpoint_event(&event)
                        {
                            tree_resolver_registry_for_forward.attach_noninteractive_endpoint(
                                session_id,
                                agent_instance_id,
                                endpoint_generation,
                                endpoint,
                            );
                        }
                        update_live_foreground(
                            &foreground_for_forward,
                            &foreground_input_target_for_forward,
                            &event,
                        );
                        for ev in proto::turn_event_to_proto(event, session_id) {
                            for ready in coalescer.push(ev) {
                                send_event(ready);
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        for ev in coalescer.flush() {
                            send_event(ev);
                        }
                    }
                }
            } else {
                let Some(event) = engine_event_rx.recv().await else {
                    break;
                };
                if let Some((agent_instance_id, attached, endpoint_generation)) =
                    agent_tree_executor_endpoint_event(&event)
                {
                    if attached {
                        tree_resolver_registry_for_forward.attach_parent_endpoint(
                            session_id,
                            agent_instance_id,
                            endpoint_generation,
                            driver_control_for_forward.clone(),
                        );
                    } else {
                        tree_resolver_registry_for_forward.detach_parent_endpoint_if_generation(
                            session_id,
                            agent_instance_id,
                            endpoint_generation,
                        );
                    }
                }
                if let Some((agent_instance_id, endpoint_generation, endpoint)) =
                    agent_tree_noninteractive_endpoint_event(&event)
                {
                    tree_resolver_registry_for_forward.attach_noninteractive_endpoint(
                        session_id,
                        agent_instance_id,
                        endpoint_generation,
                        endpoint,
                    );
                }
                update_live_foreground(
                    &foreground_for_forward,
                    &foreground_input_target_for_forward,
                    &event,
                );
                for ev in proto::turn_event_to_proto(event, session_id) {
                    for ready in coalescer.push(ev) {
                        send_event(ready);
                    }
                }
            }
        }
        close_pending_turn_completions(&turn_completions_for_forward);
    });
    let queue_forward = tokio::spawn(forward_queue_updates(
        queue_update_rx,
        event_tx_for_queue,
        redaction_for_queue,
        session_id,
    ));

    // Build the driver, then capture its async-job command sender (GOALS
    // §22) so a human-initiated `/schedule cancel` reaches the single
    // authority before moving the driver into its task.
    let max_concurrent_schedules = max_concurrent_schedules_for(&extended_cfg);
    let mut driver = Driver::with_max_schedules(
        session.clone(),
        locks.clone(),
        redact.clone(),
        project_root.clone(),
        root,
        max_concurrent_schedules,
    );
    // Keep the exact daemon-owned binding input for every descendant spawn;
    // the driver never reconstructs local UUID references from display names.
    driver.set_vnext_local_installation_resolver(
        spawn_args.vnext_local_installation_resolver.clone(),
    );
    // Install the session config reader before the loop starts so the driver
    // and every `ToolCtx` it builds read config through the generationed
    // snapshot rather than from disk (`engine-config-snapshot-adoption`).
    driver.set_config_handle(SessionConfigHandle::new(config_snapshot.clone()));
    driver.set_assistant_identity_prefix(spawn_args.assistant_identity_prefix.clone());
    // Propagate any plan-level model override to the whole delegation tree
    // (`plan-duplication-and-model-override.md`): the root already runs under
    // it (loaded with the override `SpawnArgs`); this carries it down to
    // delegated subagents whose frontmatter would otherwise win.
    driver.set_model_override(model_override);
    // Recursive-`Swarm` knobs (GOALS §24): the depth ceiling + the global
    // concurrency cap on simultaneously-running `bee` workers, enforced
    // centrally by the single async-job authority.
    driver.set_swarm_config(
        crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
        crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_CONCURRENCY,
    );
    driver.set_lsp_manager(lsp);
    if let Some(scheduler) = resource_scheduler {
        driver.set_resource_scheduler(scheduler);
    }
    driver.set_daemon_scheduler_source(scheduler);
    driver.set_write_scope_source(write_scope.clone());
    // Durable lifecycle rows foreign-key to `sessions`. A resumed session is
    // already persisted; a deferred new session stays in-memory until the
    // first user message (session-id-display-and-lazy-persist) and only then
    // opens write-scope / agent-tree dependents.
    if session.is_persisted() {
        open_session_write_scope_root(&write_scope, session.id, &project_root).await;
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
    let interrupts = Arc::new(
        crate::engine::interrupt::InterruptHub::new(
            event_tx.clone(),
            redaction.clone(),
            interactive_clients,
            session.db.clone(),
            session_id,
        )
        // Wire the shared park-commit rendezvous
        // (`daemon-lifecycle-replay-timing-robustness.md`) so this worker's
        // waiter registration and `SessionWork::Shutdown` park land the
        // drain-path synchronization signal.
        .with_park_commit(park_commit.clone()),
    );
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
        // Live handle over the worker's shared snapshot: the approval policy is
        // read live and trust-aware (the snapshot is resolved by the daemon's
        // `ConfigSource`), so a policy change on the running session takes
        // effect without rebuilding the store.
        SessionConfigHandle::new(config_snapshot.clone()),
    );
    let approver = Arc::new(crate::approval::Approver::new_for_session(
        grant_store,
        session.db.clone(),
        session.clone(),
        redaction.clone(),
        &root_agent_name,
        interrupts.clone(),
    ));
    driver.set_approver(approver);

    // Loop-guard threshold (GOALS §1/§12) from the layered config, same
    // discovery the jobs cap uses. Clamped to ≥ 2 by the setter.
    driver.set_loop_guard_threshold(loop_guard_threshold_for(&extended_cfg));
    driver.set_max_primary_rounds(max_primary_rounds_for(&extended_cfg));
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
    let (_, _, active_wire_api) = active_wire_api_for_session(&session, &start_config.providers);
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
        .await
    {
        Ok(r) => r,
        Err(e) => {
            if responses_strict_replay
                && let Some(repair) =
                    e.downcast_ref::<crate::engine::rehydrate::RehydrateRepairRequired>()
            {
                let state = build_resume_repair_state(&session, &start_config.providers, repair);
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
                send_current_session_event(
                    &session,
                    &event_tx,
                    &redaction,
                    proto::Event::Notice {
                        session_id,
                        text: format!(
                            "Resume repair required for {label}: {}. The transcript is open read-only; fork from the last valid turn, export a debug bundle, or explicitly repair before continuing.",
                            state.detail
                        ),
                    },
                    NoticeSource::DaemonDirect,
                );
            } else {
                tracing::error!(error = %e, session_id = %session_id,
                    "resume rehydration failed; the transcript could not be rebuilt into a \
                     provider-valid conversation");
                send_current_session_event(
                    &session,
                    &event_tx,
                    &redaction,
                    proto::Event::Notice {
                        session_id,
                        text: format!(
                            "Resume failed: the prior conversation could not be rebuilt ({e}). \
                         Start a new session to continue."
                        ),
                    },
                    NoticeSource::DaemonDirect,
                );
            }
            None
        }
    };
    if let Some(r) = &rehydrated
        && r.ledger_fallback
    {
        // Continuity preserved, just less pruned — surface a non-fatal
        // warning (never a silent drop to a fresh context).
        send_current_session_event(
            &session,
            &event_tx,
            &redaction,
            proto::Event::Notice {
                session_id,
                text: "Resume: the prune ledger was inconsistent; restored the full \
                   (unpruned) prior context instead."
                    .to_string(),
            },
            NoticeSource::DaemonDirect,
        );
    }
    if let Some(r) = &rehydrated
        && !r.heals.is_empty()
    {
        // The heal pass stubbed/dropped unpairable rows so the prior
        // conversation could be rebuilt instead of dead-ending — degrade
        // visibly (alongside any ledger-fallback notice above), never a
        // silent alteration of the resumed context.
        let n = r.heals.len();
        send_current_session_event(
            &session,
            &event_tx,
            &redaction,
            proto::Event::Notice {
                session_id,
                text: format!(
                    "Resume: {n} incomplete tool call(s) were stubbed to rebuild the conversation."
                ),
            },
            NoticeSource::DaemonDirect,
        );
    }

    // `sessionStart` observe hooks: fire once per worker start, after
    // rehydration completes. Matcher / `startSource` is `resume` when the
    // session was rehydrated from durable history, else `fresh`. Observe-only /
    // fail-open; the registry comes from the current config snapshot (cloned so
    // no lock guard is held across the hook run).
    {
        let start_source = if rehydrated.is_some() {
            "resume"
        } else {
            "fresh"
        };
        let registry = config_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .hooks()
            .clone();
        crate::engine::agent::hooks::run_observe_hooks(
            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(
                session.process_containment(),
            ),
            &crate::engine::agent::hooks::DefaultProcessEnv,
            &registry,
            crate::config::extended::hooks::HookEvent::SessionStart,
            start_source,
            session.id,
            &project_root,
            &session.db,
            None,
            None,
            None,
            None,
            crate::engine::agent::hooks::ObserveFields {
                start_source: Some(start_source),
                ..Default::default()
            },
        )
        .await;
    }

    // Releasable, debug-build + env-gated pause point
    // (`daemon-lifecycle-replay-timing-robustness.md`, §3 / criterion 1): hold
    // the attach reconciliation BEFORE the crash-surviving `Open → Parked`
    // write so a test can prove the attach path awaits the park-commit signal.
    // Bounded (self-releasing) so the fixed code's reconciliation still lands
    // within `INTERRUPT_PARK_COMMIT_DEADLINE`; not the irreversible
    // `COCKPIT_TEST_PAUSE_PARKED_REPLAY_EXECUTING` loop. Unreachable in release.
    test_injected_park_delay("COCKPIT_TEST_DELAY_STARTUP_RECONCILE_MS").await;
    // A terminal AgentTree decision may have claimed a parked QuestionTool
    // continuation immediately before a worker crash.  Keep the exact row so
    // the fresh root executor can replay it after it attaches below; treating
    // that durable `executing` claim as an interrupted orphan would discard
    // the original continuation and its already-recorded answer.
    let mut terminal_tree_interrupt_replays = Vec::new();
    match session.db.list_reconcilable_interrupts(session_id).await {
        Ok(rows) => {
            for row in rows {
                // A host-capability refresh is a daemon RPC with a durable
                // decision, not a parked driver tool call. It intentionally
                // has no replay payload or in-memory waiter after restart.
                // Keep its exact pending interrupt answerable; decision
                // settlement will schedule the same operation row below.
                match session
                    .db
                    .has_pending_host_capability_refresh_interrupt(
                        crate::agent_tree::daemon_host_capability_refresh_authority(),
                        session_id,
                        row.interrupt_id,
                    )
                    .await
                {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            interrupt_id = %row.interrupt_id,
                            "checking durable host capability refresh interrupt failed"
                        );
                    }
                }
                match row.state {
                    crate::db::needs_attention::InterruptState::Open
                        if validate_parked_interrupt_payload(&row).is_ok() =>
                    {
                        if let Err(error) = session.db.park_interrupt(row.interrupt_id).await {
                            tracing::warn!(
                                %error,
                                interrupt_id = %row.interrupt_id,
                                "parking crash-surviving interrupt failed"
                            );
                        }
                    }
                    crate::db::needs_attention::InterruptState::Parked
                        if validate_parked_interrupt_payload(&row).is_ok() => {}
                    crate::db::needs_attention::InterruptState::Executing
                        if validate_parked_interrupt_payload(&row).is_ok()
                            && row.response.is_some() =>
                    {
                        settle_or_replay_executing_interrupt(
                            &session,
                            &event_tx,
                            &redaction,
                            session_id,
                            row,
                            &mut terminal_tree_interrupt_replays,
                        )
                        .await;
                    }
                    crate::db::needs_attention::InterruptState::Open
                    | crate::db::needs_attention::InterruptState::Parked
                    | crate::db::needs_attention::InterruptState::Executing => {
                        let linked_decision = match session
                            .db
                            .decision_request_for_interrupt(session_id, row.interrupt_id)
                            .await
                        {
                            Ok(decision) => decision,
                            Err(error) => {
                                tracing::error!(
                                    %error,
                                    interrupt_id = %row.interrupt_id,
                                    "loading unrecoverable interrupt lifecycle decision failed"
                                );
                                settle_unrecoverable_interrupt(
                                    &session,
                                    &event_tx,
                                    &redaction,
                                    session_id,
                                    row.interrupt_id,
                                    false,
                                    interrupt_restart_notice_text(
                                        row.interrupt_id,
                                        validate_parked_interrupt_payload(&row),
                                    ),
                                )
                                .await;
                                continue;
                            }
                        };
                        let waiting_host = matches!(
                            row.state,
                            crate::db::needs_attention::InterruptState::Open
                                | crate::db::needs_attention::InterruptState::Parked
                        ) && linked_decision
                            .as_ref()
                            .is_some_and(|decision| !decision.state.is_terminal());
                        if waiting_host {
                            continue;
                        }
                        settle_unrecoverable_interrupt(
                            &session,
                            &event_tx,
                            &redaction,
                            session_id,
                            row.interrupt_id,
                            linked_decision.is_some(),
                            interrupt_restart_notice_text(
                                row.interrupt_id,
                                validate_parked_interrupt_payload(&row),
                            ),
                        )
                        .await;
                    }
                    _ => {}
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, "interrupt reconciliation failed");
        }
    }
    // Publish the attach-path park-commit edge
    // (`daemon-lifecycle-replay-timing-robustness.md`, §3): the crash-surviving
    // `Open → Parked` reconciliation above has now committed (or there was
    // nothing to reconcile), so a client that attached and is awaiting this
    // signal can observe the durable `Parked` row. Always fired (even on the
    // error/empty paths) so `attach` never blocks to the deadline needlessly.
    park_commit.report_startup_reconciled();

    // Session-only redaction source overrides (`/toggle-redaction`). The
    // base config is reloaded at every turn boundary so dotenv/settings/SSH
    // changes made after session start are picked up before the next provider
    // request; these overrides preserve any live toggles without writing them
    // to disk.
    let mut redaction_overrides = RedactionSourceOverrides::default();
    let mut preflight_override = None;
    let mut longcache_enabled = false;
    let mut unsupported_redaction_notified: HashSet<PathBuf> = HashSet::new();

    // The driver above is the fresh root executor. Bind the one stable root
    // tree node to it before recovery, then consume only the claim it has
    // actually accepted. This replaces the former log-and-drop scan: a claim
    // is never acknowledged until an executor exists in this worker.
    // Do not replay prior-worker invalidations. The cursor is captured before
    // this worker creates/reconciles anything, so every transition committed
    // by this boot is relayed in durable sequence order below.
    let mut agent_tree_event_seq = match session.db.latest_agent_tree_event_seq(session_id).await {
        Ok(Some(seq)) => seq,
        Ok(None) => 0,
        Err(error) => {
            tracing::warn!(%error, %session_id, "loading agent-tree invalidation cursor failed; replaying from session start");
            0
        }
    };
    let tree_now = crate::agent_tree::system_now_unix_ms();
    // A prior worker can have crossed the host effect handoff boundary and
    // then died before it recorded the effect's terminal receipt. Reconcile
    // that state before recovery replays any parked continuation: dispatching
    // is submission-unknown, never permission to execute again.
    if let Err(error) = session
        .db
        .reconcile_host_approval_dispatches(session_id, tree_now)
        .await
    {
        tracing::error!(%error, %session_id, "reconciling stranded host approval dispatches failed");
        return;
    }
    if let Err(error) = session
        .db
        .reconcile_host_capability_refresh_operations(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            session_id,
            tree_now,
        )
        .await
    {
        tracing::error!(%error, %session_id, "reconciling interrupted host capability refreshes failed");
        return;
    }
    // Unit/integration worker construction can bypass the daemon boot helper.
    // Re-seed only from a receipt already acknowledged to the live store;
    // completed outbox entries are drained in generation order below before a
    // recovered allowed operation can reserve a later number.
    if let Some(runtime) = start_config.host_capability_refresh_runtime.as_ref() {
        match session
            .db
            .latest_published_host_capability_refresh_snapshot_receipt(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
            )
            .await
        {
            Ok(Some(receipt)) => {
                let snapshot: cockpit_proto::HostCapabilitySnapshot = match serde_json::from_str::<
                    cockpit_proto::HostCapabilitySnapshot,
                >(
                    &receipt.result_snapshot_json,
                ) {
                    Ok(snapshot) if snapshot.generation == receipt.generation => snapshot,
                    Ok(snapshot) => {
                        tracing::error!(
                            snapshot_generation = snapshot.generation,
                            receipt_generation = receipt.generation,
                            %session_id,
                            "durable host capability refresh receipt has mismatched generation"
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::error!(%error, %session_id, "durable host capability refresh receipt is malformed");
                        return;
                    }
                };
                let high_water = match session
                    .db
                    .host_capability_refresh_generation_high_water(
                        crate::agent_tree::daemon_host_capability_refresh_authority(),
                    )
                    .await
                {
                    Ok(high_water) if high_water >= receipt.generation => high_water,
                    Ok(high_water) => {
                        tracing::error!(
                            %session_id,
                            high_water,
                            receipt_generation = receipt.generation,
                            "host capability refresh allocator is behind a completed receipt"
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::error!(%error, %session_id, "loading durable host capability refresh high-water failed");
                        return;
                    }
                };
                runtime.store.observe_durable_generation(high_water);
                let boot_snapshot_is_newer = runtime.store.current().is_some_and(|current| {
                    current.generation > receipt.generation && current.generation == high_water
                });
                if !boot_snapshot_is_newer
                    && let Err(error) = runtime.store.publish_committed(snapshot)
                {
                    tracing::error!(%error, %session_id, "seeding worker host capability store from durable refresh receipt failed");
                    return;
                }
            }
            Ok(None) => match session
                .db
                .host_capability_refresh_generation_high_water(
                    crate::agent_tree::daemon_host_capability_refresh_authority(),
                )
                .await
            {
                Ok(high_water) => runtime.store.observe_durable_generation(high_water),
                Err(error) => {
                    tracing::error!(%error, %session_id, "loading durable host capability refresh high-water failed");
                    return;
                }
            },
            Err(error) => {
                tracing::error!(%error, %session_id, "loading durable host capability refresh receipt failed");
                return;
            }
        }
    }
    // Do not schedule an already-allowed refresh yet. Recovery first attaches
    // every nonterminal dedicated host-operation child below, consumes its
    // exact recovery claim, and repairs terminal child/Attention pairs. A
    // scheduler that runs before that attachment can finish a durable effect
    // while its child remains an unattached generic descriptor.
    let root_profile_snapshot_id = match session.db.agent_profile_snapshot(session_id).await {
        Ok(Some(snapshot)) => match snapshot.reconstruct() {
            Ok(_) => Some(snapshot.snapshot_id),
            Err(error) => {
                tracing::error!(%error, %session_id, "reconstructing immutable root question policy failed");
                Some(snapshot.snapshot_id)
            }
        },
        Ok(None) => None,
        Err(error) => {
            tracing::error!(%error, %session_id, "loading immutable root profile for agent-tree recovery failed");
            None
        }
    };
    let root_workspace_ref = match crate::agent_tree::workspace_ref_for_host_path(&project_root) {
        Ok(workspace_ref) => workspace_ref,
        Err(error) => {
            tracing::error!(%error, %session_id, "deriving durable host workspace reference failed");
            return;
        }
    };
    if abort_startup_if_only_stop(&mut startup_inbox, &mut work_rx) {
        return;
    }
    let mut durable_lifecycle_ready = session.is_persisted();
    let tree_root = if durable_lifecycle_ready {
        match session
            .db
            .ensure_session_root_agent(
                session_id,
                root_profile_snapshot_id,
                root_workspace_ref,
                tree_now,
            )
            .await
        {
            Ok(root) => root,
            Err(error) => {
                tracing::error!(%error, %session_id, "creating durable root agent-tree node failed");
                // Do not run an untracked executor when durable lifecycle setup
                // has failed. The next worker start retries from the DB boundary.
                return;
            }
        }
    } else {
        let _reserved_workspace = root_workspace_ref;
        crate::db::agent_tree_decisions::AgentInstanceRow {
            agent_instance_id: Uuid::new_v4(),
            session_id,
            parent_agent_instance_id: None,
            task_delegation_job_id: None,
            task_delegation_child_uuid: None,
            resolved_profile_snapshot_id: root_profile_snapshot_id,
            workspace_ref: None,
            auto_answer_enabled: false,
            state: crate::db::agent_tree_decisions::AgentInstanceState::Running,
            revision: 0,
            created_at_unix_ms: tree_now,
            updated_at_unix_ms: tree_now,
        }
    };
    let reserved_root_id = tree_root.agent_instance_id;
    let tree_root = if tree_root.state
        == crate::db::agent_tree_decisions::AgentInstanceState::Created
    {
        match session
            .db
            .transition_agent_instance(
                session_id,
                tree_root.agent_instance_id,
                tree_root.revision,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                "{}",
                tree_now,
            )
            .await
        {
            Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(root)) => root,
            Ok(_) | Err(_) => return,
        }
    } else {
        tree_root
    };
    // Agent rows always begin with auto-answer disabled. The immutable profile
    // is the only authority that can reduce this concrete root into an enabled
    // resolver participant; ordinary sessions and missing/off snapshots stay
    // disabled without consulting mutable defaults.
    let tree_root = if let Some(snapshot_id) = tree_root.resolved_profile_snapshot_id {
        match session
            .db
            .set_agent_auto_answer_from_resolved_profile(
                session_id,
                tree_root.agent_instance_id,
                snapshot_id,
                tree_now,
            )
            .await
        {
            Ok(_) => match session
                .db
                .agent_instance(session_id, tree_root.agent_instance_id)
                .await
            {
                Ok(Some(root)) => root,
                Ok(None) | Err(_) => return,
            },
            Err(error) => {
                tracing::error!(%error, %session_id, "applying resolved root auto-answer policy failed");
                return;
            }
        }
    } else {
        tree_root
    };
    driver.set_root_agent_instance_id(tree_root.agent_instance_id);
    let tree_epoch = Uuid::now_v7();
    let tree_lifecycle = crate::agent_tree::AgentTreeLifecycle::new(session.db.clone());
    let tree_deadlines = std::sync::Arc::new(WorkerAgentTreeDeadlines::default());
    // The root driver is the one executor this worker owns at boot. Register
    // its exact control endpoint before recovery so a child can use the warm
    // route only while that concrete owner is live and accepts the packet.
    let root_endpoint_generation = crate::engine::agent::next_agent_tree_endpoint_generation();
    tree_resolver_registry.attach_parent_endpoint(
        session_id,
        tree_root.agent_instance_id,
        root_endpoint_generation,
        driver_control_tx.clone(),
    );
    let (agent_tree_resolver_tx, mut agent_tree_resolver_rx) =
        mpsc::channel::<AgentTreeResolverCompletion>(WORK_QUEUE_CAPACITY);
    let tree_runtime = crate::agent_tree::AgentTreeRuntime::new(
        tree_lifecycle,
        std::sync::Arc::new(WorkerAgentTreeClock),
        std::sync::Arc::new(WorkerAgentTreeResolverDirectory {
            registry: tree_resolver_registry.clone(),
        }),
        tree_deadlines.clone(),
    )
    .with_resolver_delivery(std::sync::Arc::new(WorkerAgentTreeResolverDelivery {
        registry: tree_resolver_registry.clone(),
        completions: agent_tree_resolver_tx,
    }));
    let tree_recovery = if durable_lifecycle_ready {
        match Box::pin(tree_runtime.recover_session(session_id, tree_epoch)).await {
            Ok(recovery) => recovery,
            Err(_) => return,
        }
    } else {
        crate::agent_tree::AgentTreeRecovery {
            claimed_agents: Vec::new(),
            pending_decisions: Vec::new(),
            claimed_late_user_steers: Vec::new(),
            accepted_late_user_steers: Vec::new(),
        }
    };
    // Host-capability refreshes own a small daemon-operation executor rather
    // than parking the foreground root. Every operation state participates in
    // recovery while its dedicated child remains nonterminal: recovery can
    // crash after an operation is terminal but before its child/Attention are
    // acknowledged. Reattach the typed endpoint and consume its exact claim
    // before the generic task descriptor loop; no operation is ever
    // impersonated by the root driver.
    let mut recovered_host_operation_agents = std::collections::BTreeSet::new();
    // Keep the typed decision identities separate from the broader operation
    // inventory. A nonterminal operation can belong to another recovery
    // epoch; only this set has crossed both endpoint registration and the
    // exact claim acknowledgement, so only it may enter the resolver replay
    // handoff below.
    let mut recovered_host_operation_decision_ids = std::collections::BTreeSet::new();
    let mut host_operation_agents = std::collections::BTreeSet::new();
    let mut terminal_host_operation_interrupts = Vec::new();
    match session
        .db
        .nonterminal_host_capability_refresh_operations(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            session_id,
        )
        .await
    {
        Ok(operations) => {
            for operation in operations {
                let agent_instance_id = operation.agent_instance_id;
                host_operation_agents.insert(agent_instance_id);
                if !tree_recovery.claimed_agents.contains(&agent_instance_id) {
                    // The broad operation inventory only keeps this child out
                    // of generic task-descriptor recovery. It is not proof
                    // that the current worker attached an executor. Reload
                    // the exact row to permit a concurrent terminalizer, but
                    // otherwise fail this epoch before root activation.
                    let reloaded = session
                        .db
                        .agent_instance(session_id, agent_instance_id)
                        .await;
                    let reloaded_state = match &reloaded {
                        Ok(Some(agent)) => Ok(Some(agent.state)),
                        Ok(None) => Ok(None),
                        Err(_) => Err(()),
                    };
                    match classify_host_operation_recovery_reload(reloaded_state) {
                        HostOperationRecoveryReload::ConcurrentlyTerminal => {
                            if terminal_host_operation_interrupt_requires_repair(operation.state) {
                                terminal_host_operation_interrupts.push(operation.interrupt_id);
                            }
                            tracing::debug!(
                                %agent_instance_id,
                                operation_id = %operation.operation_id,
                                "host capability refresh child terminalized while its recovery claim was observed; allowing terminal repair"
                            );
                            continue;
                        }
                        HostOperationRecoveryReload::StillNonterminal => {
                            tracing::error!(
                                %agent_instance_id,
                                operation_id = %operation.operation_id,
                                state = ?operation.state,
                                "nonterminal host capability refresh child has no local exact recovery claim; refusing to release root"
                            );
                            return;
                        }
                        HostOperationRecoveryReload::Missing => {
                            tracing::error!(
                                %agent_instance_id,
                                operation_id = %operation.operation_id,
                                "nonterminal host capability refresh operation lost its child row; refusing to release root"
                            );
                            return;
                        }
                        HostOperationRecoveryReload::LoadFailed => {
                            let error =
                                reloaded.expect_err("classification retained the DB load error");
                            tracing::error!(
                                %error,
                                %agent_instance_id,
                                operation_id = %operation.operation_id,
                                "reloading host capability refresh child after lost recovery claim failed; refusing to release root"
                            );
                            return;
                        }
                    }
                }
                let agent = match session
                    .db
                    .agent_instance(session_id, agent_instance_id)
                    .await
                {
                    Ok(Some(agent)) if agent.state.is_terminal() => {
                        if terminal_host_operation_interrupt_requires_repair(operation.state) {
                            terminal_host_operation_interrupts.push(operation.interrupt_id);
                        }
                        tracing::debug!(
                            %agent_instance_id,
                            operation_id = %operation.operation_id,
                            "host capability refresh child terminalized before endpoint attachment; allowing terminal repair"
                        );
                        continue;
                    }
                    Ok(Some(agent)) => agent,
                    Ok(None) => {
                        tracing::error!(
                            %agent_instance_id,
                            operation_id = %operation.operation_id,
                            "nonterminal host capability refresh operation lost its child before endpoint attachment; refusing to release root"
                        );
                        return;
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            %agent_instance_id,
                            operation_id = %operation.operation_id,
                            "loading host capability refresh child before endpoint attachment failed; refusing to release root"
                        );
                        return;
                    }
                };
                let endpoint_generation = tree_resolver_registry
                    .attach_host_operation_endpoint(session_id, agent_instance_id);
                let consumed = match session
                    .db
                    .consume_agent_resume_claims_atomically(
                        session_id,
                        vec![(agent_instance_id, agent.revision)],
                        tree_epoch,
                        crate::agent_tree::system_now_unix_ms(),
                    )
                    .await
                {
                    Ok(consumed) => consumed,
                    Err(error) => {
                        tree_resolver_registry.detach_parent_endpoint_if_generation(
                            session_id,
                            agent_instance_id,
                            endpoint_generation,
                        );
                        tracing::error!(
                            %error,
                            %agent_instance_id,
                            operation_id = %operation.operation_id,
                            "consuming host capability refresh child recovery claim failed; reloading exact state"
                        );
                        let reloaded = session
                            .db
                            .agent_instance(session_id, agent_instance_id)
                            .await;
                        let reloaded_state = match &reloaded {
                            Ok(Some(agent)) => Ok(Some(agent.state)),
                            Ok(None) => Ok(None),
                            Err(_) => Err(()),
                        };
                        match classify_host_operation_recovery_reload(reloaded_state) {
                            HostOperationRecoveryReload::ConcurrentlyTerminal => {
                                if terminal_host_operation_interrupt_requires_repair(
                                    operation.state,
                                ) {
                                    terminal_host_operation_interrupts.push(operation.interrupt_id);
                                }
                                tracing::debug!(
                                    %agent_instance_id,
                                    operation_id = %operation.operation_id,
                                    "host capability refresh child terminalized during failed claim consumption; allowing terminal repair"
                                );
                                continue;
                            }
                            HostOperationRecoveryReload::StillNonterminal => {
                                tracing::error!(
                                    %agent_instance_id,
                                    operation_id = %operation.operation_id,
                                    "nonterminal host capability refresh child lost its exact claim consumption; refusing to release root"
                                );
                            }
                            HostOperationRecoveryReload::Missing => {
                                tracing::error!(
                                    %agent_instance_id,
                                    operation_id = %operation.operation_id,
                                    "host capability refresh child disappeared after failed claim consumption; refusing to release root"
                                );
                            }
                            HostOperationRecoveryReload::LoadFailed => {
                                let reload_error = reloaded
                                    .expect_err("classification retained the DB reload error");
                                tracing::error!(
                                    %reload_error,
                                    %agent_instance_id,
                                    operation_id = %operation.operation_id,
                                    "reloading host capability refresh child after failed claim consumption failed; refusing to release root"
                                );
                            }
                        }
                        return;
                    }
                };
                if consumed {
                    recovered_host_operation_agents.insert(agent_instance_id);
                    if let Some(decision_request_id) = operation.decision_request_id {
                        match session
                            .db
                            .decision_request(session_id, decision_request_id)
                            .await
                        {
                            Ok(Some(decision))
                                if decision.agent_instance_id == agent_instance_id
                                    && matches!(
                                        decision.state,
                                        crate::db::agent_tree_decisions::DecisionState::Pending
                                            | crate::db::agent_tree_decisions::DecisionState::Resolving
                                    )
                                    && tree_recovery
                                        .pending_decisions
                                        .contains(&decision_request_id) =>
                            {
                                recovered_host_operation_decision_ids
                                    .insert(decision_request_id);
                            }
                            Ok(Some(_)) => {
                                tracing::warn!(
                                    %agent_instance_id,
                                    %decision_request_id,
                                    operation_id = %operation.operation_id,
                                    "typed host operation decision is no longer recoverable after endpoint claim; retaining its durable state"
                                );
                            }
                            Ok(None) => {
                                tracing::warn!(
                                    %agent_instance_id,
                                    %decision_request_id,
                                    operation_id = %operation.operation_id,
                                    "typed host operation lost its decision after endpoint claim; retaining operation for durable repair"
                                );
                            }
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    %agent_instance_id,
                                    %decision_request_id,
                                    operation_id = %operation.operation_id,
                                    "loading typed host operation decision after endpoint claim failed; retaining operation for durable repair"
                                );
                            }
                        }
                    }
                    match operation.state {
                        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Pending
                        | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Allowed
                        | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Executing => {}
                        crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Completed
                        | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Failed
                        | crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState::Cancelled => {
                            terminal_host_operation_interrupts.push(operation.interrupt_id);
                        }
                    }
                } else {
                    tree_resolver_registry.detach_parent_endpoint_if_generation(
                        session_id,
                        agent_instance_id,
                        endpoint_generation,
                    );
                    // A failed exact claim may race a terminal transition.
                    // Reload once for that narrow case; a still-live child is
                    // never allowed to hide behind the broad operation set.
                    let reloaded = session
                        .db
                        .agent_instance(session_id, agent_instance_id)
                        .await;
                    let reloaded_state = match &reloaded {
                        Ok(Some(agent)) => Ok(Some(agent.state)),
                        Ok(None) => Ok(None),
                        Err(_) => Err(()),
                    };
                    match classify_host_operation_recovery_reload(reloaded_state) {
                        HostOperationRecoveryReload::ConcurrentlyTerminal => {
                            if terminal_host_operation_interrupt_requires_repair(operation.state) {
                                terminal_host_operation_interrupts.push(operation.interrupt_id);
                            }
                            tracing::debug!(
                                %agent_instance_id,
                                operation_id = %operation.operation_id,
                                "host capability refresh child terminalized during claim race; allowing terminal repair"
                            );
                            continue;
                        }
                        HostOperationRecoveryReload::StillNonterminal => {
                            tracing::error!(
                                %agent_instance_id,
                                operation_id = %operation.operation_id,
                                "nonterminal host capability refresh child recovery claim was not consumable; refusing to release root"
                            );
                        }
                        HostOperationRecoveryReload::Missing => {
                            tracing::error!(
                                %agent_instance_id,
                                operation_id = %operation.operation_id,
                                "host capability refresh child disappeared during claim race; refusing to release root"
                            );
                        }
                        HostOperationRecoveryReload::LoadFailed => {
                            let error =
                                reloaded.expect_err("classification retained the DB reload error");
                            tracing::error!(
                                %error,
                                %agent_instance_id,
                                operation_id = %operation.operation_id,
                                "reloading host capability refresh child after claim race failed; refusing to release root"
                            );
                        }
                    }
                    return;
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, %session_id, "loading nonterminal host capability refresh operation children failed");
        }
    }
    match session
        .db
        .terminal_host_capability_refresh_interrupts_requiring_finalization(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            session_id,
        )
        .await
    {
        Ok(interrupts) => terminal_host_operation_interrupts.extend(interrupts),
        Err(error) => {
            tracing::error!(%error, %session_id, "loading terminal host capability refresh Attention repairs failed; refusing to release root");
            return;
        }
    }
    terminal_host_operation_interrupts.sort_unstable();
    terminal_host_operation_interrupts.dedup();
    // A terminal operation owns the exact final Attention acknowledgement;
    // repair it before generic descriptor recovery sees the child. The
    // helper acknowledges Attention before it detaches the host endpoint. A
    // failed terminalization or acknowledgement must abort this recovery epoch
    // before root activation, not strand a live child behind a released gate.
    for interrupt_id in terminal_host_operation_interrupts {
        match handle_terminal_host_capability_refresh_interrupt(
            &session,
            session_id,
            interrupt_id,
            &tree_resolver_registry,
        )
        .await
        {
            HostCapabilityRefreshInterruptFinalization::Finalized => {}
            HostCapabilityRefreshInterruptFinalization::NonterminalRetryable => {
                tracing::error!(%interrupt_id, "terminal host capability refresh recovery found a nonterminal operation; refusing to release root");
                return;
            }
            HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure => {
                tracing::error!(%interrupt_id, "terminal host capability refresh recovery retained its endpoint or Attention; refusing to release root");
                return;
            }
            HostCapabilityRefreshInterruptFinalization::NotTyped => {
                tracing::error!(%interrupt_id, "terminal host capability refresh recovery lost its typed operation binding; refusing to release root");
                return;
            }
        }
    }
    // The utility directory is keyed by the *requesting* immutable profile,
    // not by the root model.  Recovery has now identified every nonterminal
    // executor this worker may attach, so install each distinct selected
    // snapshot before any of their pending decisions can resume. A missing or
    // unbuildable exact binding is intentionally absent from the directory:
    // that request remains manual instead of borrowing a root/provider model.
    let mut utility_profile_snapshot_ids = std::collections::BTreeSet::new();
    if let Some(profile_snapshot_id) = tree_root.resolved_profile_snapshot_id {
        utility_profile_snapshot_ids.insert(profile_snapshot_id);
    }
    for agent_instance_id in &tree_recovery.claimed_agents {
        match session
            .db
            .agent_instance(session_id, *agent_instance_id)
            .await
        {
            Ok(Some(agent)) => {
                if let Some(profile_snapshot_id) = agent.resolved_profile_snapshot_id {
                    utility_profile_snapshot_ids.insert(profile_snapshot_id);
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, %agent_instance_id, "loading recovered agent profile for utility resolver failed");
            }
        }
    }
    for profile_snapshot_id in utility_profile_snapshot_ids {
        if let Err(error) = attach_agent_tree_profile_utility_models(
            &session,
            session_id,
            profile_snapshot_id,
            &start_config.providers,
            current_redaction(&redaction),
            &tree_resolver_registry,
        )
        .await
        {
            tracing::warn!(%error, %session_id, %profile_snapshot_id, "agent-tree utility resolver profile is unavailable; affected decisions remain manual");
        }
    }
    // Recovery itself can expire a previously parked decision before the
    // driver has attached. Re-read just the terminal execution claims after
    // that durable pass so the original continuation is replayed rather than
    // being stranded until another user action happens.
    match session.db.list_reconcilable_interrupts(session_id).await {
        Ok(rows) => {
            for row in rows {
                if row.state != crate::db::needs_attention::InterruptState::Executing
                    || validate_parked_interrupt_payload(&row).is_err()
                    || row.response.is_none()
                    || terminal_tree_interrupt_replays
                        .iter()
                        .any(|known| known.interrupt_id == row.interrupt_id)
                {
                    continue;
                }
                settle_or_replay_executing_interrupt(
                    &session,
                    &event_tx,
                    &redaction,
                    session_id,
                    row,
                    &mut terminal_tree_interrupt_replays,
                )
                .await;
            }
        }
        Err(error) => {
            tracing::warn!(%error, %session_id, "scanning post-recovery terminal interrupt claims failed")
        }
    }
    let root_claimed = tree_recovery
        .claimed_agents
        .iter()
        .any(|agent_id| *agent_id == tree_root.agent_instance_id);
    // The root is also a recovered executor. Publish its driver endpoint now,
    // but do not let an already-queued submission execute until the exact
    // root claim below has been consumed for this boot epoch.
    let root_activation_gate =
        root_claimed.then(crate::engine::driver::RecoveryActivationGate::new);
    if let Some(gate) = root_activation_gate.clone() {
        driver.set_root_recovery_activation(gate);
    }
    // Resolver replay is allowed only for an executor that this worker has
    // actually attached. Child rows remain claimed for their dedicated
    // rehydrator; replaying their decision through the root would either lose
    // the continuation or attribute it to the wrong UUID.
    let mut root_pending_decisions = Vec::new();
    for decision_request_id in &tree_recovery.pending_decisions {
        match session
            .db
            .decision_request(session_id, *decision_request_id)
            .await
        {
            Ok(Some(decision)) if decision.agent_instance_id == tree_root.agent_instance_id => {
                root_pending_decisions.push(*decision_request_id);
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, %decision_request_id, "loading recovered decision owner failed")
            }
        }
    }

    // A recovery claim is not permission to cancel an executor.  Child
    // continuations keep their exact durable UUID/claim until their own
    // rehydration path attaches them; a restart must never turn ordinary
    // running/waiting work into cancellation merely because the root driver is
    // the first executor available in this worker.
    let root_late_user_steers = tree_recovery
        .claimed_late_user_steers
        .iter()
        .filter(|steer| steer.agent_instance_id == tree_root.agent_instance_id)
        .cloned()
        .collect::<Vec<_>>();
    // Accepted steers are deliberately held apart from new deliveries.  The
    // recovery handoff below sends their checkpoint-resume command only after
    // the exact root endpoint is attached and its resume claim is consumed.
    let root_accepted_late_user_steers = tree_recovery
        .accepted_late_user_steers
        .iter()
        .filter(|steer| steer.agent_instance_id == tree_root.agent_instance_id)
        .cloned()
        .collect::<Vec<_>>();
    let mut root_recovery = crate::agent_tree::AgentTreeRecovery {
        claimed_agents: root_claimed
            .then_some(tree_root.agent_instance_id)
            .into_iter()
            .collect(),
        pending_decisions: root_pending_decisions,
        claimed_late_user_steers: root_late_user_steers.clone(),
        accepted_late_user_steers: root_accepted_late_user_steers.clone(),
    };
    // A root accepted late steer has no task-child descriptor to reattach.
    // Reconstruct its private root continuation before the driver exists, and
    // refuse this worker epoch if the durable proof is absent or ambiguous.
    // The accepted DB claim remains untouched in either failure case so the
    // next boot can retry the same continuation; it must never fall back to
    // the user payload or an unrelated root history.
    if root_accepted_late_user_steers.len() > 1 {
        tracing::error!(
            session_id = %session_id,
            root_agent_instance_id = %tree_root.agent_instance_id,
            count = root_accepted_late_user_steers.len(),
            "root has multiple accepted late-steer checkpoints; retaining all exact claims"
        );
        if let Some(gate) = root_activation_gate.as_ref() {
            gate.abort();
        }
        return;
    }
    if let Some(accepted) = root_accepted_late_user_steers.first() {
        let descriptor = match session
            .db
            .session_root_agent_continuation_for_steer(
                session_id,
                tree_root.agent_instance_id,
                accepted.continuation_id,
            )
            .await
        {
            Ok(Some(descriptor)) => descriptor,
            Ok(None) => {
                tracing::error!(
                    steer_id = %accepted.steer_id,
                    continuation_id = %accepted.continuation_id,
                    "accepted root late steer has no exact durable root continuation snapshot"
                );
                if let Some(gate) = root_activation_gate.as_ref() {
                    gate.abort();
                }
                return;
            }
            Err(error) => {
                tracing::error!(%error, steer_id = %accepted.steer_id, "loading accepted root late-steer continuation failed");
                if let Some(gate) = root_activation_gate.as_ref() {
                    gate.abort();
                }
                return;
            }
        };
        let expected_parked_interrupt_id = match root_parked_interrupt_id_from_snapshot(
            &descriptor.snapshot_json,
        ) {
            Ok(interrupt_id) => interrupt_id,
            Err(error) => {
                tracing::error!(%error, steer_id = %accepted.steer_id, "accepted root late steer has a malformed parked continuation marker");
                if let Some(gate) = root_activation_gate.as_ref() {
                    gate.abort();
                }
                return;
            }
        };
        let root_has_parked_continuation = match session
            .db
            .list_reconcilable_interrupts(session_id)
            .await
        {
            Ok(rows) => match expected_parked_interrupt_id {
                Some(expected_interrupt_id) => {
                    let matched = rows.into_iter().any(|row| {
                        row.interrupt_id == expected_interrupt_id
                            && row.agent_instance_id == Some(tree_root.agent_instance_id)
                            && row.parked.is_some()
                            && matches!(
                                row.state,
                                crate::db::needs_attention::InterruptState::Open
                                    | crate::db::needs_attention::InterruptState::Parked
                                    | crate::db::needs_attention::InterruptState::Executing
                            )
                    });
                    if !matched {
                        tracing::error!(
                            steer_id = %accepted.steer_id,
                            interrupt_id = %expected_interrupt_id,
                            "accepted root late steer parked checkpoint has no exact recoverable interrupt"
                        );
                    }
                    matched
                }
                None => false,
            },
            Err(error) => {
                tracing::error!(%error, steer_id = %accepted.steer_id, "loading root parked continuation for accepted late steer failed");
                if let Some(gate) = root_activation_gate.as_ref() {
                    gate.abort();
                }
                return;
            }
        };
        if expected_parked_interrupt_id.is_some() && !root_has_parked_continuation {
            if let Some(gate) = root_activation_gate.as_ref() {
                gate.abort();
            }
            return;
        }
        if let Err(error) = driver.restore_root_late_user_steer_continuation(
            tree_root.agent_instance_id,
            crate::engine::driver::RecoveredLateUserSteerPermit {
                steer_id: accepted.steer_id,
                continuation_id: accepted.continuation_id,
                recovery_epoch: tree_epoch,
            },
            &descriptor.snapshot_json,
            root_has_parked_continuation,
        ) {
            tracing::error!(%error, steer_id = %accepted.steer_id, "reconstructing accepted root late-steer continuation failed");
            if let Some(gate) = root_activation_gate.as_ref() {
                gate.abort();
            }
            return;
        }
    }
    for agent_instance_id in tree_recovery
        .claimed_agents
        .iter()
        .copied()
        .filter(|agent_instance_id| *agent_instance_id != tree_root.agent_instance_id)
    {
        tracing::info!(
            %session_id,
            %agent_instance_id,
            "retaining recovered child claim until its exact durable executor attaches"
        );
    }
    // Spawn the driver loop.
    if abort_startup_if_only_stop(&mut startup_inbox, &mut work_rx) {
        return;
    }
    let driver_queue_for_loop = driver_input_queue.clone();
    let resolver_registry_for_driver = tree_resolver_registry.clone();
    let mut driver_handle = tokio::spawn(async move {
        crate::config::trust::scope_shared_workspace_trust_policy(trust_policy, async move {
            let driver_loop = Box::pin(driver.run_main_loop(
                driver_queue_for_loop,
                driver_control_rx,
                &engine_event_tx,
            ));
            let outcome = driver_loop.await;
            // The endpoint must disappear before the worker can attempt a
            // subsequent warm delivery. A stale root never qualifies merely
            // because its model handle outlived the driver task.
            resolver_registry_for_driver.detach_session(session_id);
            // Pairing teardown: a driver-loop exit that still holds interactive
            // child frames (only reachable via a fatal `Err` — every clean /
            // cancel / gate / interrupt / inference-failure path already
            // unwinds to root) emits one paired `subagentStop` per abandoned
            // child so no `subagentStart` is left unpaired. No-op when the stack
            // is already at root.
            driver.drain_orphaned_child_stop_hooks().await;
            // Same pairing teardown for detached-`Swarm` children: any child
            // still tracked (its terminal `Completed` was never drained — detach
            // loss / shutdown) emits one paired `subagentStop` (`aborted`) so no
            // `subagentStart` is left unpaired. No-op when every child already
            // completed (each `Completed` removed it from the map).
            driver.drain_orphaned_swarm_stop_hooks().await;
            match outcome {
                Ok(()) => DriverOutcome::Ok,
                Err(e) => {
                    let error = format!("{e:#}");
                    tracing::error!(error = %error, "driver loop terminated with error");
                    DriverOutcome::Err(error)
                }
            }
        })
        .await
    });

    // Reattach task-backed interactive descendants in parent-before-child
    // order. A descriptor is complete only when its durable payload and
    // snapshot can be read; otherwise its resume claim stays intact for a
    // later worker epoch instead of being mass-cancelled or routed through the
    // root. Noninteractive recovery has its own executor path and therefore
    // is deliberately left claimed here rather than impersonated by the
    // foreground driver.
    let mut attached_recovered_agents = std::collections::BTreeSet::new();
    attached_recovered_agents.insert(tree_root.agent_instance_id);
    attached_recovered_agents.extend(recovered_host_operation_agents.iter().copied());
    // A reattached executor is addressable before it may run.  Keep every
    // child gate closed until accepted late-steer checkpoints have been
    // enqueued below; otherwise a recovery can race its own resume command
    // and execute the pre-crash prompt with a fresh inference identity.
    let mut deferred_recovery_activation_gates = Vec::new();
    let mut pending_recovery_agents = tree_recovery
        .claimed_agents
        .iter()
        .copied()
        .filter(|agent_instance_id| *agent_instance_id != tree_root.agent_instance_id)
        .collect::<Vec<_>>();
    // One control hand-off owns an entire batch job. Without this directory a
    // later sibling in the same recovery scan could reconstruct the same DAG
    // a second time after the first member had already attached.
    let mut recovered_batch_jobs = std::collections::HashSet::new();
    loop {
        let mut progressed = false;
        let mut remaining = Vec::new();
        for agent_instance_id in pending_recovery_agents {
            if attached_recovered_agents.contains(&agent_instance_id) {
                continue;
            }
            if host_operation_agents.contains(&agent_instance_id) {
                // A daemon-owned refresh child has a typed operation
                // descriptor, not a task-delegation descriptor. Its own
                // recovery above either attached the HostOperation endpoint
                // or intentionally retained the exact claim for a successor;
                // never reinterpret it as a generic missing child.
                continue;
            }
            let descriptor = match session
                .db
                .task_delegation_recovery_descriptor(session_id, agent_instance_id)
                .await
            {
                Ok(Some(descriptor)) => descriptor,
                Ok(None) => {
                    tracing::warn!(%session_id, %agent_instance_id, "recovered child has no complete task recovery descriptor; retaining exact claim");
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, %session_id, %agent_instance_id, "loading recovered child task descriptor failed; retaining exact claim");
                    continue;
                }
            };
            if !attached_recovered_agents.contains(&descriptor.parent_agent_instance_id) {
                remaining.push(agent_instance_id);
                continue;
            }
            let is_noninteractive = match session
                .db
                .task_delegation_is_noninteractive_for_agent(session_id, agent_instance_id)
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(%error, %agent_instance_id, "checking recovered task executor mode failed; retaining exact claim");
                    continue;
                }
            };
            if is_noninteractive {
                let batch_job =
                    serde_json::from_str::<serde_json::Value>(&descriptor.original_args_json)
                        .ok()
                        .is_some_and(|args| args.get("entries").is_some());
                if batch_job {
                    let batch_id = descriptor.task_call_id.clone();
                    let activation_gate = crate::engine::driver::RecoveryActivationGate::new();
                    // This set records a fully-attached batch, not an attempt.
                    // Inserting before all descriptor/payload/mailbox/claim
                    // work succeeds poisons the current boot after one
                    // transient failure: every later sibling observes the
                    // marker and the durable batch is never retried.  A
                    // successful attachment below is the only linearization
                    // point for suppressing its other members.
                    if recovered_batch_jobs.contains(&batch_id) {
                        continue;
                    }
                    let descriptors = match session
                        .db
                        .task_delegation_recovery_descriptors_for_job(session_id, batch_id.clone())
                        .await
                    {
                        Ok(descriptors) if !descriptors.is_empty() => descriptors,
                        Ok(_) => {
                            remaining.push(agent_instance_id);
                            continue;
                        }
                        Err(error) => {
                            tracing::warn!(%error, task_call_id = %batch_id, "loading recovered batch descriptors failed");
                            remaining.push(agent_instance_id);
                            continue;
                        }
                    };
                    let batch_members = descriptors
                        .iter()
                        .map(|item| item.agent_instance_id)
                        .collect::<Vec<_>>();
                    if descriptors.iter().any(|item| {
                        item.parent_agent_instance_id != descriptor.parent_agent_instance_id
                            || !tree_recovery
                                .claimed_agents
                                .contains(&item.agent_instance_id)
                    }) {
                        tracing::warn!(task_call_id = %batch_id, "recovered batch does not have one claimed parent-owned executor set");
                        remaining.extend(batch_members);
                        continue;
                    }
                    let rows = match session.db.list_task_delegation_children(session_id).await {
                        Ok(rows) => rows,
                        Err(error) => {
                            tracing::warn!(%error, task_call_id = %batch_id, "loading recovered batch child states failed");
                            remaining.extend(batch_members);
                            continue;
                        }
                    };
                    let mut state_by_label = rows
                        .into_iter()
                        .filter(|row| row.task_call_id == batch_id)
                        .map(|row| (row.label.clone(), row))
                        .collect::<std::collections::HashMap<_, _>>();
                    let mut recoveries = Vec::with_capacity(descriptors.len());
                    let mut failed = false;
                    for item in descriptors {
                        let Some(row) = state_by_label.remove(&item.label) else {
                            failed = true;
                            break;
                        };
                        let payload = match session
                            .db
                            .load_task_delegation_payload(&item.task_call_id, &item.label)
                            .await
                        {
                            Ok(payload) => payload.body,
                            Err(error) => {
                                tracing::warn!(%error, task_call_id = %item.task_call_id, label = %item.label, "loading recovered batch payload failed");
                                failed = true;
                                break;
                            }
                        };
                        recoveries.push(crate::engine::driver::RecoveredNoninteractiveTaskChild {
                            agent_instance_id: item.agent_instance_id,
                            parent_agent_instance_id: item.parent_agent_instance_id,
                            task_call_id: item.task_call_id,
                            label: item.label,
                            child_agent: item.child_agent,
                            original_args_json: item.original_args_json,
                            snapshot_json: item.snapshot_json,
                            payload,
                            // The descriptor captures both the durable child
                            // and job status. The batch's current child row is
                            // only a consistency check, never a reason to
                            // revive a backgrounded job as foreground work.
                            was_backgrounded: item.was_backgrounded,
                            activation_gate: activation_gate.clone(),
                        });
                    }
                    if failed {
                        remaining.extend(batch_members);
                        continue;
                    }
                    if state_by_label.values().any(|row| {
                        matches!(
                            row.status,
                            crate::db::task_delegations::DelegationStatus::Running
                                | crate::db::task_delegations::DelegationStatus::Backgrounded
                                | crate::db::task_delegations::DelegationStatus::PausedPendingTool
                        )
                    }) {
                        tracing::warn!(task_call_id = %batch_id, "recovered batch has a live child without an exact lifecycle descriptor");
                        remaining.extend(batch_members);
                        continue;
                    }
                    let terminal_children = state_by_label
                        .into_values()
                        .filter_map(|row| match row.status {
                            crate::db::task_delegations::DelegationStatus::Completed
                            | crate::db::task_delegations::DelegationStatus::Failed
                            | crate::db::task_delegations::DelegationStatus::Cancelled
                            | crate::db::task_delegations::DelegationStatus::Lost => Some(
                                crate::engine::driver::RecoveredNoninteractiveTaskTerminal {
                                    label: row.label,
                                    child_agent: row.child_agent,
                                    report: row.report.unwrap_or_else(|| "recovered terminal batch child has no report".to_string()),
                                    failed: !matches!(row.status, crate::db::task_delegations::DelegationStatus::Completed),
                                },
                            ),
                            crate::db::task_delegations::DelegationStatus::Running
                            | crate::db::task_delegations::DelegationStatus::Backgrounded
                            | crate::db::task_delegations::DelegationStatus::PausedPendingTool
                            // `Created` has no AgentTree node or resume claim:
                            // publication is atomic with the first snapshot,
                            // so it cannot be a reconstructable executor.
                            | crate::db::task_delegations::DelegationStatus::Created => None,
                        })
                        .collect::<Vec<_>>();
                    let (respond_to, attached) = oneshot::channel();
                    if driver_control_tx
                        .send(
                            crate::engine::driver::DriverControl::ReattachNoninteractiveTaskBatch {
                                recoveries,
                                terminal_children,
                                respond_to,
                            },
                        )
                        .await
                        .is_err()
                    {
                        remaining.extend(batch_members);
                        continue;
                    }
                    match attached.await {
                        Ok(Ok(endpoints)) if !endpoints.is_empty() => {
                            let endpoint_ids = endpoints
                                .iter()
                                .map(|endpoint| endpoint.agent_instance_id)
                                .collect::<std::collections::BTreeSet<_>>();
                            if !batch_members
                                .iter()
                                .all(|agent_instance_id| endpoint_ids.contains(agent_instance_id))
                            {
                                activation_gate.abort();
                                tracing::warn!(task_call_id = %batch_id, "recovered batch subtree did not install every batch-root resolver mailbox");
                                remaining.extend(batch_members);
                                continue;
                            }
                            let endpoint_generations = endpoints
                                .iter()
                                .map(|endpoint| {
                                    (
                                        endpoint.agent_instance_id,
                                        tree_resolver_registry.attach_noninteractive_endpoint(
                                            session_id,
                                            endpoint.agent_instance_id,
                                            endpoint.endpoint_generation,
                                            endpoint.endpoint.clone(),
                                        ),
                                    )
                                })
                                .collect::<Vec<_>>();
                            for (endpoint_agent_instance_id, endpoint_generation) in
                                &endpoint_generations
                            {
                                debug_assert!(endpoint_ids.contains(endpoint_agent_instance_id));
                                debug_assert_ne!(*endpoint_generation, 0);
                            }
                            let mut claims = Vec::with_capacity(endpoint_ids.len());
                            for endpoint_agent_instance_id in &endpoint_ids {
                                match session
                                    .db
                                    .agent_instance(session_id, *endpoint_agent_instance_id)
                                    .await
                                {
                                    Ok(Some(agent)) => {
                                        claims.push((*endpoint_agent_instance_id, agent.revision));
                                    }
                                    Ok(None) | Err(_) => break,
                                }
                            }
                            let consumed = claims.len() == endpoint_ids.len()
                                && session
                                    .db
                                    .consume_agent_resume_claims_atomically(
                                        session_id,
                                        claims,
                                        tree_epoch,
                                        crate::agent_tree::system_now_unix_ms(),
                                    )
                                    .await
                                    .unwrap_or(false);
                            if consumed {
                                // Every returned endpoint, including nested
                                // recursive descendants, shares this gate.
                                // Release only after the all-or-nothing claim
                                // acknowledgement commits.
                                deferred_recovery_activation_gates.push(activation_gate.clone());
                                recovered_batch_jobs.insert(batch_id.clone());
                                for endpoint_agent_instance_id in endpoint_ids {
                                    attached_recovered_agents.insert(endpoint_agent_instance_id);
                                    root_recovery
                                        .claimed_agents
                                        .push(endpoint_agent_instance_id);
                                }
                                progressed = true;
                            } else {
                                activation_gate.abort();
                                tracing::warn!(task_call_id = %batch_id, "recovered batch could not consume every exact resume claim");
                                for (endpoint_agent_instance_id, endpoint_generation) in
                                    endpoint_generations
                                {
                                    tree_resolver_registry.detach_parent_endpoint_if_generation(
                                        session_id,
                                        endpoint_agent_instance_id,
                                        endpoint_generation,
                                    );
                                }
                                if let Some(gate) = root_activation_gate.as_ref() {
                                    gate.abort();
                                }
                                driver_handle.abort();
                                return;
                            }
                        }
                        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
                            activation_gate.abort();
                            tracing::warn!(task_call_id = %batch_id, "recovered batch did not install every exact resolver mailbox");
                            remaining.extend(batch_members);
                        }
                    }
                    continue;
                }
                // A detached executor owns a real model loop and its own
                // mailbox. Reattach it from the exact task descriptor rather
                // than treating the foreground root as its parent, then wait
                // until that concrete mailbox has reached the warm registry
                // before consuming the durable resume claim.
                let payload = match session
                    .db
                    .load_task_delegation_payload(&descriptor.task_call_id, &descriptor.label)
                    .await
                {
                    Ok(payload) => payload.body,
                    Err(error) => {
                        tracing::warn!(%error, %agent_instance_id, "loading recovered noninteractive task payload failed; retaining exact claim");
                        continue;
                    }
                };
                let (respond_to, attached) = oneshot::channel();
                let activation_gate = crate::engine::driver::RecoveryActivationGate::new();
                if driver_control_tx
                    .send(
                        crate::engine::driver::DriverControl::ReattachNoninteractiveTaskChild {
                            recovery: crate::engine::driver::RecoveredNoninteractiveTaskChild {
                                agent_instance_id: descriptor.agent_instance_id,
                                parent_agent_instance_id: descriptor.parent_agent_instance_id,
                                task_call_id: descriptor.task_call_id,
                                label: descriptor.label,
                                child_agent: descriptor.child_agent,
                                original_args_json: descriptor.original_args_json,
                                snapshot_json: descriptor.snapshot_json,
                                payload,
                                was_backgrounded: descriptor.was_backgrounded,
                                activation_gate: activation_gate.clone(),
                            },
                            respond_to,
                        },
                    )
                    .await
                    .is_err()
                {
                    remaining.push(agent_instance_id);
                    continue;
                }
                match attached.await {
                    Ok(Ok(endpoints)) if !endpoints.is_empty() => {
                        // A recursive continuation reports every exact live
                        // mailbox beneath this root before the worker consumes
                        // even one claim.  This closes the decision-replay race
                        // where a descendant was durable but not yet warm.
                        let endpoint_ids = endpoints
                            .iter()
                            .map(|endpoint| endpoint.agent_instance_id)
                            .collect::<std::collections::BTreeSet<_>>();
                        if !endpoint_ids.contains(&agent_instance_id) {
                            activation_gate.abort();
                            tracing::warn!(%agent_instance_id, "recovered noninteractive subtree omitted its root resolver mailbox");
                            remaining.push(agent_instance_id);
                            continue;
                        }
                        let endpoint_generations = endpoints
                            .iter()
                            .map(|endpoint| {
                                (
                                    endpoint.agent_instance_id,
                                    tree_resolver_registry.attach_noninteractive_endpoint(
                                        session_id,
                                        endpoint.agent_instance_id,
                                        endpoint.endpoint_generation,
                                        endpoint.endpoint.clone(),
                                    ),
                                )
                            })
                            .collect::<Vec<_>>();
                        // The recursive executor is one recovered unit.  Do
                        // not acknowledge a prefix of its descendants: a
                        // later stale/missing claim would otherwise leave an
                        // attached sibling without a durable recovery
                        // acknowledgement.  Capture every exact revision
                        // first, then consume the complete set in the same
                        // `IMMEDIATE` transaction as the batch path above.
                        let mut claims = Vec::with_capacity(endpoint_ids.len());
                        for endpoint_agent_instance_id in &endpoint_ids {
                            match session
                                .db
                                .agent_instance(session_id, *endpoint_agent_instance_id)
                                .await
                            {
                                Ok(Some(agent)) => {
                                    claims.push((*endpoint_agent_instance_id, agent.revision));
                                }
                                Ok(None) | Err(_) => {
                                    claims.clear();
                                    break;
                                }
                            }
                        }
                        let consumed = !claims.is_empty()
                            && session
                                .db
                                .consume_agent_resume_claims_atomically(
                                    session_id,
                                    claims,
                                    tree_epoch,
                                    crate::agent_tree::system_now_unix_ms(),
                                )
                                .await
                                .unwrap_or(false);
                        if consumed {
                            deferred_recovery_activation_gates.push(activation_gate.clone());
                            for endpoint_agent_instance_id in endpoint_ids {
                                attached_recovered_agents.insert(endpoint_agent_instance_id);
                                root_recovery
                                    .claimed_agents
                                    .push(endpoint_agent_instance_id);
                            }
                            progressed = true;
                        } else {
                            activation_gate.abort();
                            tracing::warn!(%agent_instance_id, "recovered noninteractive subtree attached but an exact resume claim could not be consumed");
                            for (endpoint_agent_instance_id, endpoint_generation) in
                                endpoint_generations
                            {
                                tree_resolver_registry.detach_parent_endpoint_if_generation(
                                    session_id,
                                    endpoint_agent_instance_id,
                                    endpoint_generation,
                                );
                            }
                            if let Some(gate) = root_activation_gate.as_ref() {
                                gate.abort();
                            }
                            driver_handle.abort();
                            return;
                        }
                    }
                    Ok(Ok(_)) => {
                        activation_gate.abort();
                        tracing::warn!(%agent_instance_id, "recovered noninteractive child executor installed no resolver mailbox; retaining exact claim");
                        remaining.push(agent_instance_id);
                    }
                    Ok(Err(error)) => {
                        activation_gate.abort();
                        tracing::warn!(%error, %agent_instance_id, "recovering noninteractive child executor failed; retaining exact claim");
                        remaining.push(agent_instance_id);
                    }
                    Err(_) => {
                        activation_gate.abort();
                        remaining.push(agent_instance_id)
                    }
                }
                continue;
            }
            let payload = match session
                .db
                .load_task_delegation_payload(&descriptor.task_call_id, &descriptor.label)
                .await
            {
                Ok(payload) => payload.body,
                Err(error) => {
                    tracing::warn!(%error, %agent_instance_id, "loading recovered interactive task payload failed; retaining exact claim");
                    continue;
                }
            };
            let (respond_to, attached) = oneshot::channel();
            let activation_gate = crate::engine::driver::RecoveryActivationGate::new();
            let accepted_late_steers = tree_recovery
                .accepted_late_user_steers
                .iter()
                .filter(|steer| steer.agent_instance_id == descriptor.agent_instance_id)
                .collect::<Vec<_>>();
            if accepted_late_steers.len() > 1 {
                tracing::warn!(
                    %agent_instance_id,
                    "recovered interactive child has more than one accepted late-steer checkpoint; retaining exact claim"
                );
                continue;
            }
            let accepted_late_steer = accepted_late_steers.first().map(|steer| {
                crate::engine::driver::RecoveredLateUserSteerPermit {
                    steer_id: steer.steer_id,
                    continuation_id: steer.continuation_id,
                    recovery_epoch: tree_epoch,
                }
            });
            if driver_control_tx
                .send(
                    crate::engine::driver::DriverControl::ReattachInteractiveTaskChild {
                        recovery: crate::engine::driver::RecoveredInteractiveTaskChild {
                            agent_instance_id: descriptor.agent_instance_id,
                            parent_agent_instance_id: descriptor.parent_agent_instance_id,
                            task_call_id: descriptor.task_call_id,
                            label: descriptor.label,
                            child_agent: descriptor.child_agent,
                            original_args_json: descriptor.original_args_json,
                            snapshot_json: descriptor.snapshot_json,
                            payload,
                            accepted_late_steer,
                            activation_gate: activation_gate.clone(),
                        },
                        respond_to,
                    },
                )
                .await
                .is_err()
            {
                remaining.push(agent_instance_id);
                continue;
            }
            match attached.await {
                Ok(Ok(endpoint_generation)) => {
                    // Keep the one-node interactive continuation on the
                    // same atomic acknowledgement path as every recursive
                    // reattach.  Besides making the invariant uniform, this
                    // prevents a later extension from accidentally changing
                    // this branch back into a partial subtree consume.
                    let claims = match session
                        .db
                        .agent_instance(session_id, agent_instance_id)
                        .await
                    {
                        Ok(Some(agent)) => vec![(agent_instance_id, agent.revision)],
                        Ok(None) | Err(_) => Vec::new(),
                    };
                    let claim_consumed = !claims.is_empty()
                        && session
                            .db
                            .consume_agent_resume_claims_atomically(
                                session_id,
                                claims,
                                tree_epoch,
                                crate::agent_tree::system_now_unix_ms(),
                            )
                            .await
                            .unwrap_or(false);
                    if claim_consumed {
                        // Do not wait for the display-event forwarder to run:
                        // recovery must make the exact attached frame warm
                        // before it redelivers that frame's pending decision.
                        tree_resolver_registry.attach_parent_endpoint(
                            session_id,
                            agent_instance_id,
                            endpoint_generation,
                            driver_control_tx.clone(),
                        );
                        deferred_recovery_activation_gates.push(activation_gate.clone());
                        attached_recovered_agents.insert(agent_instance_id);
                        root_recovery.claimed_agents.push(agent_instance_id);
                        progressed = true;
                    } else {
                        activation_gate.abort();
                        tracing::warn!(%agent_instance_id, "recovered child attached but its exact resume claim could not be consumed");
                        // The frame is already live, but it has no durable
                        // recovery acknowledgement.  Do not leave that
                        // unclaimed continuation running (and do not invent a
                        // terminal state): tear down this worker so the same
                        // durable claim is retried by the next epoch.
                        tree_resolver_registry.detach_parent_endpoint_if_generation(
                            session_id,
                            agent_instance_id,
                            endpoint_generation,
                        );
                        if let Some(gate) = root_activation_gate.as_ref() {
                            gate.abort();
                        }
                        driver_handle.abort();
                        return;
                    }
                }
                Ok(Err(error)) => {
                    activation_gate.abort();
                    tracing::warn!(%error, %agent_instance_id, "recovering interactive child executor failed; retaining exact claim");
                }
                Err(_) => {
                    activation_gate.abort();
                    remaining.push(agent_instance_id)
                }
            }
        }
        if !progressed {
            for agent_instance_id in remaining {
                tracing::warn!(%agent_instance_id, "recovered child lineage could not be attached in this worker epoch; retaining exact claim");
            }
            break;
        }
        pending_recovery_agents = remaining;
        if pending_recovery_agents.is_empty() {
            break;
        }
    }
    // A claim is not merely a decision-owner reservation. Every durable
    // nonterminal child (Created, Running, and either waiting state) must
    // attach to a concrete continuation before this worker releases the root.
    // In particular, a transient missing descriptor/payload/mailbox for a
    // running child must fail this epoch rather than silently disappearing
    // after `pending_recovery_agents` falls out of scope. The next worker gets
    // the same durable epoch claim as a whole; it never starts a half-tree.
    for agent_instance_id in &tree_recovery.claimed_agents {
        if *agent_instance_id == tree_root.agent_instance_id
            || attached_recovered_agents.contains(agent_instance_id)
            || recovered_host_operation_agents.contains(agent_instance_id)
        {
            continue;
        }
        match session
            .db
            .agent_instance(session_id, *agent_instance_id)
            .await
        {
            Ok(Some(agent)) if !agent.state.is_terminal() => {
                tracing::warn!(
                    %agent_instance_id,
                    state = ?agent.state,
                    "recovery left a claimed nonterminal child unattached; refusing to release root"
                );
                if let Some(gate) = root_activation_gate.as_ref() {
                    gate.abort();
                }
                driver_handle.abort();
                return;
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, %agent_instance_id, "loading claimed child after recovery failed; refusing to release root");
                if let Some(gate) = root_activation_gate.as_ref() {
                    gate.abort();
                }
                driver_handle.abort();
                return;
            }
        }
    }
    // A pending decision can only be consumed by the exact executor that
    // owns its parked continuation. This is the decision-specific instance of
    // the all-nonterminal guard above; it protects the one-shot settlement
    // boundary before manual input, resolver results, or deadlines arrive.
    for decision_request_id in &tree_recovery.pending_decisions {
        let decision = match session
            .db
            .decision_request(session_id, *decision_request_id)
            .await
        {
            Ok(Some(decision)) => decision,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(%error, %decision_request_id, "loading recovered decision owner failed");
                if let Some(gate) = root_activation_gate.as_ref() {
                    gate.abort();
                }
                driver_handle.abort();
                return;
            }
        };
        if !attached_recovered_agents.contains(&decision.agent_instance_id)
            && !recovered_host_operation_agents.contains(&decision.agent_instance_id)
        {
            tracing::warn!(
                %decision_request_id,
                agent_instance_id = %decision.agent_instance_id,
                "recovery left a decision owner unattached; refusing to process its one-shot decision"
            );
            if let Some(gate) = root_activation_gate.as_ref() {
                gate.abort();
            }
            driver_handle.abort();
            return;
        }
    }
    for decision_request_id in &tree_recovery.pending_decisions {
        match session
            .db
            .decision_request(session_id, *decision_request_id)
            .await
        {
            Ok(Some(decision))
                if decision.agent_instance_id != tree_root.agent_instance_id
                    && !recovered_host_operation_agents.contains(&decision.agent_instance_id)
                    && attached_recovered_agents.contains(&decision.agent_instance_id) =>
            {
                root_recovery.pending_decisions.push(*decision_request_id);
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, %decision_request_id, "loading attached recovered decision owner failed")
            }
        }
    }
    // A daemon-owned refresh child has no model/task descriptor, so it cannot
    // pass through the generic child-recovery append above. Its exact
    // endpoint and resume claim were established before this point and its
    // durable decision binding was revalidated there. Include it only now,
    // after all endpoints are live, so a crash while resolving is redelivered
    // (or released) by the one normal runtime recovery boundary.
    root_recovery
        .pending_decisions
        .extend(recovered_host_operation_decision_ids);
    root_recovery.claimed_late_user_steers.extend(
        tree_recovery
            .claimed_late_user_steers
            .iter()
            .filter(|steer| {
                steer.agent_instance_id != tree_root.agent_instance_id
                    && attached_recovered_agents.contains(&steer.agent_instance_id)
            })
            .cloned(),
    );
    root_recovery.accepted_late_user_steers.extend(
        tree_recovery
            .accepted_late_user_steers
            .iter()
            .filter(|steer| {
                steer.agent_instance_id != tree_root.agent_instance_id
                    && attached_recovered_agents.contains(&steer.agent_instance_id)
            })
            .cloned(),
    );

    // The root claim becomes consumed only after the actual driver task has
    // been spawned with the bound root identity. If this final durable ACK
    // loses its exact epoch/revision race, abort the just-created executor so
    // it cannot run an unclaimed continuation; the next recovery epoch owns
    // retrying the still-durable claim.
    if root_claimed
        && !session
            .db
            .consume_agent_resume_claim(
                session_id,
                tree_root.agent_instance_id,
                tree_root.revision,
                tree_epoch,
                tree_now,
            )
            .await
            .unwrap_or(false)
    {
        if let Some(gate) = root_activation_gate.as_ref() {
            gate.abort();
        }
        driver_handle.abort();
        return;
    }
    // A background finalizer that cannot make its exact child/Attention pair
    // durable must fail this worker epoch rather than silently orphaning it
    // until a future daemon restart.
    let host_capability_terminalization_failure_fence =
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Startup scheduling comes only after every recoverable host-operation
    // child above has installed its typed endpoint/claim (or has been
    // terminalized and acknowledged). This preserves the operation-child
    // lifecycle even when an already-allowed refresh completes immediately.
    spawn_ready_host_capability_refresh_operations(
        &session,
        start_config.host_capability_refresh_runtime.clone(),
        &global_bus,
        &redaction,
        &tree_resolver_registry,
        &host_capability_terminalization_failure_fence,
    )
    .await;
    // Use the same nonblocking exact-owner delivery path for the root.  A
    // boot-time late steer must not monopolize this worker while its resumed
    // root executes an arbitrary model turn; the detached receipt task owns
    // the durable acknowledgement just as it does for every child.
    if let Err(error) = deliver_live_agent_tree_late_user_steers(
        &session,
        session_id,
        tree_root.agent_instance_id,
        &tree_resolver_registry,
        Some((tree_epoch, root_late_user_steers)),
    )
    .await
    {
        tracing::warn!(%error, "delivering recovered root late user steers failed");
    }
    if let Err(error) = deliver_live_agent_tree_late_user_steers(
        &session,
        session_id,
        tree_root.agent_instance_id,
        &tree_resolver_registry,
        Some((tree_epoch, root_accepted_late_user_steers)),
    )
    .await
    {
        tracing::error!(%error, "resuming recovered root late user steer checkpoints failed; retaining checkpoint for a new recovery epoch");
        if let Some(gate) = root_activation_gate.as_ref() {
            gate.abort();
        }
        driver_handle.abort();
        return;
    }

    // The reattached interactive frames use the same exact-owner completion
    // path as a live late steer. Run this only after their resume claims have
    // been consumed and their warm endpoints registered; a failed delivery
    // releases the steer claim without substituting the root continuation.
    for agent_instance_id in attached_recovered_agents
        .iter()
        .copied()
        .filter(|agent_instance_id| *agent_instance_id != tree_root.agent_instance_id)
    {
        if let Err(error) = deliver_live_agent_tree_late_user_steers(
            &session,
            session_id,
            agent_instance_id,
            &tree_resolver_registry,
            Some((
                tree_epoch,
                root_recovery
                    .claimed_late_user_steers
                    .iter()
                    .filter(|steer| steer.agent_instance_id == agent_instance_id)
                    .cloned()
                    .collect(),
            )),
        )
        .await
        {
            tracing::warn!(%error, %agent_instance_id, "delivering recovered child late user steers failed");
        }
        if let Err(error) = deliver_live_agent_tree_late_user_steers(
            &session,
            session_id,
            agent_instance_id,
            &tree_resolver_registry,
            Some((
                tree_epoch,
                root_recovery
                    .accepted_late_user_steers
                    .iter()
                    .filter(|steer| steer.agent_instance_id == agent_instance_id)
                    .cloned()
                    .collect(),
            )),
        )
        .await
        {
            tracing::error!(%error, %agent_instance_id, "resuming recovered child late user steer checkpoints failed; retaining checkpoint for a new recovery epoch");
            if let Some(gate) = root_activation_gate.as_ref() {
                gate.abort();
            }
            driver_handle.abort();
            return;
        }
    }

    // Main work loop.
    enum WorkerInput {
        Work(Box<SessionWork>),
        ParkedReplay(ParkedReplayCompletion),
        AgentTreeResolver(AgentTreeResolverCompletion),
        ReapExpiredTextArtifactReservations,
        RelayAgentTreeEvents,
        ExpireAgentTreeDeadlines,
        ReapStaleHostCapabilityRefreshes,
    }
    let (replay_completion_tx, mut replay_completion_rx) =
        mpsc::channel::<ParkedReplayCompletion>(WORK_QUEUE_CAPACITY);
    // All non-root claims above have either been terminalized or retained for
    // a later recovery retry. The root activation gate remains closed while
    // we attach deadlines/resolvers and schedule exact durable replay, so a
    // queued FCM/client input cannot cross a provider boundary ahead of that
    // reconstructed state.
    let recovered_terminal_deadlines = match tree_runtime
        .resume_recovered_decisions(session_id, &root_recovery)
        .await
    {
        Ok(settlements) => settlements,
        Err(error) => {
            tracing::error!(%error, %session_id, "resuming recovered agent-tree decisions failed before root activation");
            if let Some(gate) = root_activation_gate.as_ref() {
                gate.abort();
            }
            driver_handle.abort();
            return;
        }
    };
    // A recovery deadline winner has the same real QuestionTool ownership as
    // a live timer.  Deliver it immediately through the shared boundary,
    // rather than discovering the resulting `executing` row in a second scan
    // and risking a duplicate parked replay.  The decision CAS supplied by
    // `resume_recovered_decisions` makes each id a once-only delivery source.
    for settlement in recovered_terminal_deadlines {
        if settlement.terminal_state != crate::db::agent_tree_decisions::DecisionState::TimedOut {
            continue;
        }
        deliver_terminal_agent_tree_interrupt(
            &session,
            &event_tx,
            &redaction,
            &interrupts,
            session_id,
            settlement.decision_request_id,
            driver_control_tx.clone(),
            tree_resolver_registry.clone(),
            replay_completion_tx.clone(),
            &host_capability_terminalization_failure_fence,
        )
        .await;
    }
    // Finish recovering terminal AgentTree claims only after the fresh driver
    // exists. The response came from the immutable decision receipt and the
    // `executing` state is its exact-once claim, so this is a redelivery of
    // the original QuestionTool continuation rather than a new turn. Use the
    // same one terminal boundary as live answers, resolver results, and
    // deadlines; a recovery must not have a second replay implementation.
    for row in terminal_tree_interrupt_replays {
        let decision_request_id = match session
            .db
            .decision_request_for_interrupt(session_id, row.interrupt_id)
            .await
        {
            Ok(Some(decision)) => decision.decision_request_id,
            Ok(None) => {
                tracing::warn!(
                    interrupt_id = %row.interrupt_id,
                    "terminal AgentTree replay has no linked durable decision; retaining exact claim for repair"
                );
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    interrupt_id = %row.interrupt_id,
                    "loading recovered terminal AgentTree decision failed"
                );
                continue;
            }
        };
        deliver_terminal_agent_tree_interrupt(
            &session,
            &event_tx,
            &redaction,
            &interrupts,
            session_id,
            decision_request_id,
            driver_control_tx.clone(),
            tree_resolver_registry.clone(),
            replay_completion_tx.clone(),
            &host_capability_terminalization_failure_fence,
        )
        .await;
    }
    if consume_host_capability_terminalization_failure_fence(
        &host_capability_terminalization_failure_fence,
    ) {
        tracing::error!(%session_id, "host capability refresh finalization failed before recovery activation; aborting this worker epoch");
        if let Some(gate) = root_activation_gate.as_ref() {
            gate.abort();
        }
        driver_handle.abort();
        return;
    }
    // Every exact endpoint now has its pending steer/resume command, pending
    // decision/deadline registration, and durable replay schedule before a
    // reattached executor may consume persisted pre-crash or newly queued
    // input. Accepted continuation ids therefore reach their owner before
    // any provider handoff, not after gate release.
    for gate in deferred_recovery_activation_gates {
        gate.release();
    }
    if let Some(gate) = root_activation_gate.as_ref() {
        gate.release();
    }
    let mut driver_failed = false;
    let mut driver_joined = false;
    // Whether every registered interrupt's shutdown park committed durably.
    // Seeded by the initial snapshot's sweep and refined by the post-drain
    // park-drain loop; reported once after the driver quiesces (finding 2).
    let mut shutdown_park_committed = true;
    let mut text_artifact_reservation_reaper =
        tokio::time::interval(TEXT_ARTIFACT_RESERVATION_REAP_INTERVAL);
    text_artifact_reservation_reaper
        .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval` ticks immediately. Startup reconciliation above already
    // performed the required first sweep, so consume that instant rather than
    // adding a redundant write before the work loop begins.
    text_artifact_reservation_reaper.tick().await;
    let mut agent_tree_event_relay = tokio::time::interval(std::time::Duration::from_millis(50));
    agent_tree_event_relay.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut agent_tree_deadline_reaper =
        tokio::time::interval(std::time::Duration::from_millis(100));
    agent_tree_deadline_reaper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut host_capability_refresh_reaper =
        tokio::time::interval(HOST_CAPABILITY_REFRESH_REAPER_INTERVAL);
    host_capability_refresh_reaper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first agent-tree tick is immediate; it deliberately relays the root
    // creation and recovery transitions committed just above. Startup already
    // reconciled stale host refreshes, so consume that reaper's immediate tick
    // before the live loop.
    host_capability_refresh_reaper.tick().await;
    // Same as the other reapers: consume the immediate first tick so the
    // live loop is not born with a ready maintenance arm that can win
    // Tokio's randomized select over an already-queued Shutdown.
    agent_tree_event_relay.tick().await;
    if abort_startup_if_only_stop(&mut startup_inbox, &mut work_rx) {
        driver_handle.abort();
        return;
    }
    let stop = 'worker: loop {
        if consume_host_capability_terminalization_failure_fence(
            &host_capability_terminalization_failure_fence,
        ) {
            tracing::error!(%session_id, "host capability refresh finalization retained a durable child/Attention pair; aborting this worker epoch for exact recovery");
            driver_handle.abort();
            break WorkerStop::DriverFailed;
        }
        // Destructive stop is fail-closed at 50ms in tests. A queued
        // Shutdown/Cancel must not sit behind an immediately-ready
        // maintenance tick.
        let pending_trust_revision =
            trust_transition_pending.load(std::sync::atomic::Ordering::Acquire);
        let transition_control = (pending_trust_revision != 0)
            .then(|| startup_inbox.pop_trust_transition_control())
            .flatten();
        let input = if let Some(work) = transition_control {
            WorkerInput::Work(Box::new(work))
        } else if pending_trust_revision != 0 {
            // A committed trust decision has already replaced the live policy,
            // but its provider projection is not current yet. Search past
            // pre-transition queued work for the revision-bound replacement.
            // ResolveInterrupt is intentionally ordinary: resuming a tool
            // continuation under mixed authority would violate fail-closed
            // admission. Shutdown remains priority recovery; Cancel preserves
            // FIFO because acknowledging it while older buffered work later
            // executes would lie to the caller about the cancellation point.
            //
            // The gate does NOT clear synchronously with the replacement arm.
            // That arm publishes, acks, and (when derived state changed) hands
            // the driver receipt to a follow-up task which clears the gate on
            // application — at the next turn boundary. This loop therefore
            // stays here after the replacement is processed, buffering ordinary
            // work, and leaves on the next iteration only once the follow-up
            // task's CAS lands. That is the intended fail-closed window: it is
            // exactly as long as the in-flight turn, no work is lost, and a
            // second ReplaceConfigSnapshot from a superseding transition is
            // still accepted and processed while it lasts.
            //
            // Because the clear is now asynchronous, this wait must be bounded:
            // an unbounded `recv().await` would park here forever when the gate
            // opens with no further work queued. The bounded re-check is the
            // whole reason for the timeout; it is not a poll for work (work
            // still wakes the recv immediately), so the interval only bounds
            // post-application latency.
            loop {
                match tokio::time::timeout(TRUST_TRANSITION_GATE_RECHECK, work_rx.recv()).await {
                    Ok(Some(
                        work @ (SessionWork::ReplaceConfigSnapshot { .. }
                        | SessionWork::Shutdown { .. }),
                    )) => {
                        break WorkerInput::Work(Box::new(work));
                    }
                    Ok(Some(work)) => startup_inbox.push(work),
                    Ok(None) => break 'worker WorkerStop::WorkerStopped,
                    Err(_) => {
                        if trust_transition_pending.load(std::sync::atomic::Ordering::Acquire) == 0
                        {
                            // The follow-up task cleared the gate. Restart the
                            // outer iteration so buffered work drains in FIFO
                            // order through the ordinary path.
                            continue 'worker;
                        }
                    }
                }
            }
        } else if let Some(work) = startup_inbox.pop() {
            WorkerInput::Work(Box::new(work))
        } else {
            match work_rx.try_recv() {
                Ok(work) => WorkerInput::Work(Box::new(work)),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    break WorkerStop::WorkerStopped;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => tokio::select! {
                // Tokio's default randomized selection prevents a permanently
                // ready work mailbox from being structurally preferred over the
                // periodic maintenance arms. Each maintenance arm performs a
                // bounded slice and its interval uses `Skip`, so no arm can turn
                // a delayed tick into an unbounded catch-up burst or monopolize
                // the worker after overload.
                _ = agent_tree_deadline_reaper.tick() => {
                    WorkerInput::ExpireAgentTreeDeadlines
                }
                _ = host_capability_refresh_reaper.tick() => {
                    WorkerInput::ReapStaleHostCapabilityRefreshes
                }
                _ = text_artifact_reservation_reaper.tick() => {
                    WorkerInput::ReapExpiredTextArtifactReservations
                }
                _ = agent_tree_event_relay.tick() => {
                    WorkerInput::RelayAgentTreeEvents
                }
                replay = replay_completion_rx.recv() => {
                    match replay {
                        Some(replay) => WorkerInput::ParkedReplay(replay),
                        None => continue,
                    }
                }
                resolver = agent_tree_resolver_rx.recv() => {
                    match resolver {
                        Some(resolver) => WorkerInput::AgentTreeResolver(resolver),
                        None => continue,
                    }
                }
                work = work_rx.recv() => {
                    match work {
                        Some(work) => WorkerInput::Work(Box::new(work)),
                        None => break WorkerStop::WorkerStopped,
                    }
                }
                outcome = &mut driver_handle => {
                    driver_joined = true;
                    let outcome = driver_join_outcome(outcome);
                    if let Some(error) = outcome.failure_error() {
                        emit_session_driver_failed_once(
                            &event_tx,
                            &turn_completions,
                            &redaction,
                            session_id,
                            &mut driver_failed,
                            error.to_string(),
                        );
                        break WorkerStop::DriverFailed;
                    }
                    break WorkerStop::DriverExited;
                }
                },
            }
        };
        match input {
            WorkerInput::RelayAgentTreeEvents => {
                // Tool-originated QuestionTool/approval rows are committed by
                // the live driver, not by this work-loop arm.  Reconcile them
                // here so every new eligible request receives real timer
                // registration and an immediate resolver delivery attempt;
                // waiting/resolving rows are never restarted as fresh roots.
                match tree_runtime
                    .reconcile_pending_requests_limited(
                        session_id,
                        AGENT_TREE_MAINTENANCE_ITEMS_PER_TURN,
                    )
                    .await
                {
                    Ok(terminal_deadlines) => {
                        for settlement in terminal_deadlines {
                            if settlement.terminal_state
                                != crate::db::agent_tree_decisions::DecisionState::TimedOut
                            {
                                continue;
                            }
                            // Reconciliation can win a deadline for a live
                            // tool-created request.  Persistence alone is not
                            // enough: this sends the terminal projection to
                            // the exact live waiter or starts the one parked
                            // replay, with the durable CAS as the once-only
                            // delivery fence.
                            deliver_terminal_agent_tree_interrupt(
                                &session,
                                &event_tx,
                                &redaction,
                                &interrupts,
                                session_id,
                                settlement.decision_request_id,
                                driver_control_tx.clone(),
                                tree_resolver_registry.clone(),
                                replay_completion_tx.clone(),
                                &host_capability_terminalization_failure_fence,
                            )
                            .await;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%error, %session_id, "reconciling live agent-tree decisions failed");
                    }
                }
                relay_agent_tree_events(
                    &session,
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut agent_tree_event_seq,
                    &tree_resolver_registry,
                )
                .await;
            }
            WorkerInput::ExpireAgentTreeDeadlines => {
                for (deadline_session_id, decision_request_id) in tree_deadlines.due_limited(
                    crate::agent_tree::system_now_unix_ms(),
                    AGENT_TREE_MAINTENANCE_ITEMS_PER_TURN,
                ) {
                    if deadline_session_id != session_id {
                        continue;
                    }
                    match tree_runtime
                        .expire_deadline(deadline_session_id, decision_request_id)
                        .await
                    {
                        Ok(crate::agent_tree::DecisionSettlement::Resolved(
                            crate::db::agent_tree_decisions::DecisionState::TimedOut,
                        )) => {
                            // A timer is not a substitute for the original
                            // continuation boundary. The durable CAS is the
                            // once-only winner; this shared helper then wakes
                            // the live QuestionTool/approval waiter or starts
                            // the exact parked replay, including the typed
                            // host-refresh special case.
                            deliver_terminal_agent_tree_interrupt(
                                &session,
                                &event_tx,
                                &redaction,
                                &interrupts,
                                session_id,
                                decision_request_id,
                                driver_control_tx.clone(),
                                tree_resolver_registry.clone(),
                                replay_completion_tx.clone(),
                                &host_capability_terminalization_failure_fence,
                            )
                            .await;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(%error, %decision_request_id, "expiring agent-tree deadline failed");
                        }
                    }
                }
            }
            WorkerInput::ReapStaleHostCapabilityRefreshes => {
                let now = crate::agent_tree::system_now_unix_ms();
                match session
                    .db
                    .reap_stale_host_capability_refresh_operations_globally(
                        crate::agent_tree::daemon_host_capability_refresh_authority(),
                        now,
                    )
                    .await
                {
                    Ok(reaped) if reaped > 0 => {
                        tracing::warn!(%session_id, reaped, "reaped stale global host capability refresh execution leases");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(%error, %session_id, "reaping stale host capability refresh executions failed")
                    }
                }
                // This also drains the completed publication outbox, including
                // the narrow crash window after completion CAS and before the
                // in-memory store swap.
                let host_capability_refresh_runtime = {
                    config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .host_capability_refresh_runtime
                        .clone()
                };
                spawn_ready_host_capability_refresh_operations(
                    &session,
                    host_capability_refresh_runtime,
                    &global_bus,
                    &redaction,
                    &tree_resolver_registry,
                    &host_capability_terminalization_failure_fence,
                )
                .await;
            }
            WorkerInput::ReapExpiredTextArtifactReservations => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                if let Err(error) = session
                    .db
                    .reap_expired_text_artifact_reservations(now_ms)
                    .await
                {
                    // This is an opportunistic reconciliation sweep. A failed
                    // transaction leaves the durable accepted lease untouched,
                    // so replay/dispatch can retry without inventing a terminal
                    // outcome outside the DB composition.
                    tracing::warn!(%error, %session_id, "periodic oversized text reservation reap failed");
                }
            }
            WorkerInput::ParkedReplay(completion) => {
                let interrupt_id = completion.interrupt_id;
                let replay_acknowledged = finish_parked_replay_completion(
                    &session,
                    &event_tx,
                    &redaction,
                    &interrupts,
                    session_id,
                    completion,
                )
                .await;
                // A post-auto user steer is dependency-gated by the exact
                // parked replay. Only the durable `executing -> resolved`
                // acknowledgement above releases it; schedule now rather
                // than relying on a future unrelated worker input/restart.
                if replay_acknowledged {
                    match session
                        .db
                        .decision_request_for_interrupt(session_id, interrupt_id)
                        .await
                    {
                        Ok(Some(decision))
                            if decision.state
                                == crate::db::agent_tree_decisions::DecisionState::AutoResolved =>
                        {
                            if let Err(error) = deliver_live_agent_tree_late_user_steers(
                                &session,
                                session_id,
                                decision.agent_instance_id,
                                &tree_resolver_registry,
                                None,
                            )
                            .await
                            {
                                tracing::warn!(%error, %interrupt_id, "scheduling post-auto late steer after replay acknowledgement failed");
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(%error, %interrupt_id, "loading decision after parked replay acknowledgement failed")
                        }
                    }
                }
            }
            WorkerInput::AgentTreeResolver(completion) => {
                let AgentTreeResolverCompletion {
                    session_id: completion_session_id,
                    decision_request_id,
                    route,
                    result,
                } = completion;
                let settlement = match result {
                    Ok(answer) => {
                        tree_runtime
                            .accept_resolver_result(
                                completion_session_id,
                                decision_request_id,
                                route,
                                answer,
                            )
                            .await
                    }
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            %decision_request_id,
                            "agent-tree resolver execution failed; releasing durable claim"
                        );
                        match tree_runtime
                            .abandon_resolver_delivery(completion_session_id, decision_request_id)
                            .await
                        {
                            Ok(_)
                                if route
                                    == crate::agent_tree::DecisionResolverRoute::WarmParent =>
                            {
                                if let Err(retry_error) = tree_runtime
                                    .retry_after_warm_parent_delivery_failure(
                                        completion_session_id,
                                        decision_request_id,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        %retry_error,
                                        %decision_request_id,
                                        "agent-tree utility fallback after warm-parent failure could not start"
                                    );
                                }
                                continue;
                            }
                            Ok(_) => continue,
                            Err(release_error) => Err(release_error),
                        }
                    }
                };
                match settlement {
                    Ok(crate::agent_tree::DecisionSettlement::Resolved(
                        crate::db::agent_tree_decisions::DecisionState::AutoResolved,
                    )) => {
                        let host_capability_refresh_runtime = {
                            config_snapshot
                                .read()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .host_capability_refresh_runtime
                                .clone()
                        };
                        spawn_ready_host_capability_refresh_operations(
                            &session,
                            host_capability_refresh_runtime,
                            &global_bus,
                            &redaction,
                            &tree_resolver_registry,
                            &host_capability_terminalization_failure_fence,
                        )
                        .await;
                        // The automatic result won the durable terminal CAS.
                        // If this is a real QuestionTool row, wake or replay
                        // its original continuation from the projected raw
                        // response rather than treating AgentTree as a
                        // parallel queue.
                        deliver_terminal_agent_tree_interrupt(
                            &session,
                            &event_tx,
                            &redaction,
                            &interrupts,
                            session_id,
                            decision_request_id,
                            driver_control_tx.clone(),
                            tree_resolver_registry.clone(),
                            replay_completion_tx.clone(),
                            &host_capability_terminalization_failure_fence,
                        )
                        .await;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        // A stale completion is harmless: recovery or another
                        // terminal path won its CAS. Try a guarded release
                        // only when the result itself could not be committed.
                        tracing::warn!(
                            %error,
                            %decision_request_id,
                            "settling agent-tree resolver delivery failed"
                        );
                        if let Err(release_error) = tree_runtime
                            .abandon_resolver_delivery(completion_session_id, decision_request_id)
                            .await
                        {
                            tracing::warn!(
                                %release_error,
                                %decision_request_id,
                                "releasing failed agent-tree resolver claim failed"
                            );
                        }
                    }
                }
            }
            WorkerInput::Work(work) => match *work {
                SessionWork::WakeGoal => {
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::WakeGoal,
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::ProbeUserMessage {
                    client_submission_id,
                    wire_fingerprint,
                    origin_principal,
                    respond_to,
                } => {
                    let outcome = Box::pin(probe_user_message(
                        &session,
                        &driver_input_queue,
                        session_id,
                        client_submission_id,
                        &wire_fingerprint,
                        origin_principal.as_deref(),
                    ))
                    .await;
                    let _ = respond_to.send(outcome);
                }
                SessionWork::UserMessage {
                    mut submission,
                    #[cfg(feature = "remote")]
                    remote_operation,
                    artifact_admission,
                    respond_to,
                } => {
                    let client_submission_id = submission
                        .client_submissions
                        .first()
                        .map(|receipt| receipt.id)
                        .expect("wire user submissions carry a client receipt");
                    let receipt = submission
                        .client_submissions
                        .first()
                        .expect("wire user submissions carry a client receipt");
                    // A repair-locked session cannot ever hand this source to
                    // phase two. Check before phase one so an oversized retry
                    // does not create a receipt/lease which the repair gate
                    // would immediately strand.
                    if artifact_admission.is_some()
                        && let Some(state) = repair_required
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                    {
                        let ids = if state.failing_tool_call_ids.is_empty() {
                            "unknown tool id".to_string()
                        } else {
                            state.failing_tool_call_ids.join(", ")
                        };
                        send_current_session_event(
                            &session,
                            &event_tx,
                            &redaction,
                            proto::Event::Notice {
                                session_id,
                                text: format!(
                                    "Read-only resume: refusing to send model context until Responses repair is resolved ({}: {}). Use the resume repair dialog, fork, or export a debug bundle.",
                                    state.failure_kind, ids
                                ),
                            },
                            NoticeSource::DaemonDirect,
                        );
                        let _ = respond_to.send(Err(proto::ErrorPayload {
                            code: proto::ErrorCode::UserMessageNotAccepted,
                            message: format!(
                                "session resume requires explicit repair before accepting message {client_submission_id}"
                            ),
                        }));
                        continue;
                    }
                    // The oversized text path owns a durable FCM2 receipt and
                    // quota lease before any legacy queue, security/preflight,
                    // utility model, title, or primary-model side effect. It is
                    // intentionally handled before the old client-submission
                    // receipt probe: the two receipt families have different
                    // ownership and must never be used as compatibility aliases.
                    let mut phase_one_reservation = None;
                    if let Some(admission) = artifact_admission.as_ref() {
                        if let Err(error) = session.persist_if_needed() {
                            tracing::error!(%error, %session_id, client_submission_id = %receipt.id,
                                "persisting session before FCM2 artifact admission failed");
                            let _ = respond_to.send(Err(user_message_database_error(
                                &error,
                                proto::ErrorCode::UserMessageNotAccepted,
                                "session persistence failed before oversized message admission",
                            )));
                            continue;
                        }
                        if let Err(error) = materialize_deferred_session_lifecycle(
                            &session,
                            session_id,
                            &project_root,
                            &write_scope,
                            reserved_root_id,
                            root_profile_snapshot_id,
                            &mut durable_lifecycle_ready,
                        )
                        .await
                        {
                            tracing::error!(%error, %session_id, client_submission_id = %receipt.id,
                                "durable lifecycle setup after lazy persist failed");
                            let _ = respond_to.send(Err(user_message_database_error(
                                &error,
                                proto::ErrorCode::UserMessageNotAccepted,
                                "session lifecycle setup failed before oversized message admission",
                            )));
                            continue;
                        }
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        if let Err(error) = session
                            .db
                            .reap_expired_text_artifact_reservations(now_ms)
                            .await
                        {
                            tracing::warn!(%error, %session_id,
                                "reconciling expired oversized reservations before admission failed");
                            let _ = respond_to.send(Err(user_message_database_error(
                                &error,
                                proto::ErrorCode::UserMessageNotAccepted,
                                "could not reconcile oversized message admission; retry",
                            )));
                            continue;
                        }
                        let canonical = match validate_oversized_artifact_admission(
                            session_id,
                            &submission,
                            admission,
                        ) {
                            Ok(value) => value,
                            Err(error) => {
                                tracing::warn!(%error, %session_id, client_submission_id = %receipt.id,
                                    "rejecting malformed oversized artifact admission evidence");
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                    code: proto::ErrorCode::BadRequest,
                                    message: "invalid oversized user-message admission".to_owned(),
                                }));
                                continue;
                            }
                        };
                        let accept_input = crate::db::db::message_attachments::AcceptMessageInput {
                            session_id,
                            operation_id: admission.operation_id,
                            actor: admission.actor,
                            request_hash: admission.request_hash,
                            message_request_digest: admission.message_request_digest,
                            attachment_set_digest: admission.attachment_set_digest,
                            client_submission_id: *receipt.id.as_bytes(),
                            queue_item_id: *receipt.id.as_bytes(),
                            canonical_message: admission.canonical_message.clone(),
                            attachments: Vec::new(),
                            outbox_sequence: 0,
                            now_ms,
                        };
                        let source_digest =
                            crate::db::db::text_artifacts::source_digest(&canonical.request.text);
                        let model_fence = match admission
                            .model_fence
                            .as_ref()
                            .map(|(generation, model)| -> anyhow::Result<_> {
                                Ok(crate::db::db::text_artifacts::TextArtifactModelFence {
                                    generation: *generation,
                                    model_json: encode_durable_model_fence(model)?,
                                })
                            })
                            .transpose()
                            .map_err(|error: anyhow::Error| proto::ErrorPayload {
                                code: proto::ErrorCode::BadRequest,
                                message: format!("invalid oversized model fence: {error}"),
                            }) {
                            Ok(model_fence) => model_fence,
                            Err(error) => {
                                let _ = respond_to.send(Err(error));
                                continue;
                            }
                        };
                        let accepted = match admission.run_invocation.as_ref() {
                            Some(run_invocation) => session
                                .db
                                .accept_message_with_text_artifact_reservation_and_run_invocation_with_model_fence(
                                    accept_input,
                                    std::sync::Arc::new(TextArtifactReceiptJoin),
                                    source_digest,
                                    canonical.request.text.len(),
                                    crate::db::db::text_artifacts::TextArtifactRunInvocationInput {
                                        origin_principal_digest: run_invocation
                                            .origin_principal_digest
                                            .clone(),
                                        options_json: run_invocation.options_json.clone(),
                                        options_digest: run_invocation.options_digest.clone(),
                                        content_digest: run_invocation.content_digest.clone(),
                                        max_turns: run_invocation.max_turns,
                                        timeout_ms: run_invocation.timeout_ms,
                                    },
                                    model_fence,
                                )
                                .await,
                            None => {
                                session
                                    .db
                                    .accept_message_with_text_artifact_reservation_with_model_fence(
                                        accept_input,
                                        std::sync::Arc::new(TextArtifactReceiptJoin),
                                        source_digest,
                                        canonical.request.text.len(),
                                        model_fence,
                                    )
                                    .await
                            }
                        };
                        let acquired_phase_one_reservation = match accepted {
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Reserved(reservation)) => reservation,
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Materialized { .. }) => {
                                // Exact durable replay: never enqueue a second
                                // copy or re-run preprocessing/providers.
                                let queue = driver_input_queue
                                    .snapshot()
                                    .await
                                    .into_iter()
                                    .map(queue_item_to_proto)
                                    .collect();
                                let target = foreground_input_target
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .clone();
                                let _ = respond_to.send(Ok((
                                    proto::QueueItem {
                                        id: receipt.id,
                                        status: proto::QueueItemStatus::Folding,
                                        text: submission.text.clone(),
                                        display_text: submission.display_text.clone(),
                                        target: queue_target_to_proto(target),
                                    },
                                    queue,
                                )));
                                continue;
                            }
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Terminal { reason }) => {
                                let _ = respond_to.send(Err(text_artifact_terminal_error(reason)));
                                continue;
                            }
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::RunInvocationRejected(reason)) => {
                                let error = match reason {
                                    crate::db::db::text_artifacts::TextArtifactRunInvocationReject::IdempotencyConflict => proto::ErrorPayload {
                                        code: proto::ErrorCode::IdempotencyConflict,
                                        message: "client_submission_id was already used with different content".to_owned(),
                                    },
                                    crate::db::db::text_artifacts::TextArtifactRunInvocationReject::ClientSubmissionIdUnavailable => proto::ErrorPayload {
                                        code: proto::ErrorCode::ClientSubmissionIdUnavailable,
                                        message: "client_submission_id is unavailable".to_owned(),
                                    },
                                    crate::db::db::text_artifacts::TextArtifactRunInvocationReject::CapacityExceeded => proto::ErrorPayload {
                                        code: proto::ErrorCode::InvocationCapacityExceeded,
                                        message: "invocation capacity exceeded".to_owned(),
                                    },
                                };
                                let _ = respond_to.send(Err(error));
                                continue;
                            }
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Conflict) => {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                    code: proto::ErrorCode::IdempotencyConflict,
                                    message: "client submission id conflicts with an existing oversized message"
                                        .to_owned(),
                                }));
                                continue;
                            }
                            Err(error) => {
                                tracing::warn!(%error, %session_id, client_submission_id = %receipt.id,
                                    "oversized FCM2 receipt/reservation composition failed");
                                let _ = respond_to.send(Err(user_message_database_error(
                                    &error,
                                    proto::ErrorCode::UserMessageNotAccepted,
                                    "could not durably admit oversized user message; retry",
                                )));
                                continue;
                            }
                        };
                        phase_one_reservation = Some(acquired_phase_one_reservation);
                        // The in-memory queue is deliberately not an authority
                        // for this path. Preserve the receipt-keyed durable
                        // identity through every enqueue/requeue so a later
                        // reservation lookup returning None is terminal, not
                        // permission to use the legacy inline route.
                        submission.pending_terminal_disposition = Some(
                            crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact,
                        );
                    }
                    // FCM2 artifact admissions use the message receipt triple
                    // above as their sole durable authority. Never consult the
                    // legacy client-submission receipt family for them.
                    if artifact_admission.is_none() {
                        let terminal_receipt = match session
                            .db
                            .client_submission_terminal_receipt(session_id, receipt.id)
                            .await
                        {
                            Ok(receipt) => receipt,
                            Err(error) => {
                                tracing::warn!(%error, %session_id, client_submission_id = %receipt.id,
                                "terminal client submission lookup failed; refusing ambiguous enqueue");
                                let _ = respond_to.send(Err(user_message_database_error(
                                    &error,
                                    proto::ErrorCode::Internal,
                                    "could not verify whether this message was already terminated; retry",
                                )));
                                continue;
                            }
                        };
                        if let Some(terminal) = terminal_receipt {
                            if terminal.origin_principal != receipt.origin_principal
                                || terminal.fingerprint != receipt.fingerprint
                            {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                code: proto::ErrorCode::BadRequest,
                                message: format!(
                                    "client_submission_id {} was already used for a different payload",
                                    receipt.id
                                ),
                            }));
                            } else {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                code: proto::ErrorCode::UserMessageTerminated,
                                message: format!(
                                    "client_submission_id {} is terminal ({}) and will not be executed",
                                    receipt.id,
                                    terminal.disposition.as_str()
                                ),
                            }));
                            }
                            continue;
                        }
                    }
                    // Early durable-receipt conflict check: a same-UUID
                    // different-content conflict must be rejected with
                    // BadRequest before any driver interaction (persist,
                    // redaction refresh, round limits). Otherwise a driver
                    // availability failure masks the conflict with
                    // UserMessageNotAccepted instead of the correct BadRequest.
                    // Matching durable receipts are final. Acknowledge them
                    // before persist/redaction/driver so a later driver death
                    // cannot reject an identity the ledger already accepted.
                    if artifact_admission.is_none() {
                        let durable = match session
                            .db
                            .client_submission_receipt(session_id, receipt.id)
                            .await
                        {
                            Ok(durable) => durable,
                            Err(error) => {
                                tracing::warn!(%error, %session_id, client_submission_id = %receipt.id,
                                    "early client submission conflict lookup failed; refusing ambiguous enqueue");
                                let _ = respond_to.send(Err(user_message_database_error(
                                    &error,
                                    proto::ErrorCode::Internal,
                                    "could not verify whether this message identity was already used; retry",
                                )));
                                continue;
                            }
                        };
                        if let Some(durable) = durable {
                            if durable.origin_principal != receipt.origin_principal
                                || durable.fingerprint != receipt.fingerprint
                            {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                    code: proto::ErrorCode::BadRequest,
                                    message: format!(
                                        "client_submission_id {} was already used for a different payload",
                                        receipt.id
                                    ),
                                }));
                                continue;
                            }
                            #[cfg(feature = "remote")]
                            if let Some(remote) = remote_operation.as_ref() {
                                match reserve_remote_send_operation(&session.db, remote).await {
                                    RemoteSendDecision::Accepted | RemoteSendDecision::Replayed => {
                                    }
                                    RemoteSendDecision::Rejected(error) => {
                                        let _ = respond_to.send(Err(error));
                                        continue;
                                    }
                                }
                            }
                            let target = foreground_input_target
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .clone();
                            let queue = driver_input_queue
                                .snapshot()
                                .await
                                .into_iter()
                                .map(queue_item_to_proto)
                                .collect();
                            let _ = respond_to.send(Ok((
                                proto::QueueItem {
                                    id: receipt.id,
                                    status: proto::QueueItemStatus::Folding,
                                    text: submission.text.clone(),
                                    display_text: submission.display_text.clone(),
                                    target: queue_target_to_proto(target),
                                },
                                queue,
                            )));
                            continue;
                        }
                    }
                    if artifact_admission.is_none()
                        && let Some(state) = repair_required
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                    {
                        let ids = if state.failing_tool_call_ids.is_empty() {
                            "unknown tool id".to_string()
                        } else {
                            state.failing_tool_call_ids.join(", ")
                        };
                        send_current_session_event(
                            &session,
                            &event_tx,
                            &redaction,
                            proto::Event::Notice {
                                session_id,
                                text: format!(
                                    "Read-only resume: refusing to send model context until Responses repair is resolved ({}: {}). Use the resume repair dialog, fork, or export a debug bundle.",
                                    state.failure_kind, ids
                                ),
                            },
                            NoticeSource::DaemonDirect,
                        );
                        let _ = respond_to.send(Err(proto::ErrorPayload {
                            code: proto::ErrorCode::UserMessageNotAccepted,
                            message: format!(
                                "session resume requires explicit repair before accepting message {client_submission_id}"
                            ),
                        }));
                        continue;
                    }
                    // Lazy persistence (session-id-display-and-lazy-persist):
                    // flush the deferred row on the first user message, then
                    // open write-scope / agent-tree dependents that foreign-key
                    // to `sessions`. Idempotent. A persist failure aborts the
                    // message rather than letting dependents reference a
                    // missing row.
                    match session.persist_if_needed() {
                        Ok(_) => {
                            if let Err(e) = materialize_deferred_session_lifecycle(
                                &session,
                                session_id,
                                &project_root,
                                &write_scope,
                                reserved_root_id,
                                root_profile_snapshot_id,
                                &mut durable_lifecycle_ready,
                            )
                            .await
                            {
                                let error = format!("{e:#}");
                                let database_rejection = user_message_database_error(
                                    &e,
                                    proto::ErrorCode::UserMessageNotAccepted,
                                    format!(
                                        "session lifecycle setup failed before accepting message {client_submission_id}: {error}"
                                    ),
                                );
                                tracing::error!(error = %error, session_id = %session_id,
                                "durable lifecycle setup after lazy persist failed; dropping message");
                                send_current_event(
                                    &event_tx,
                                    &redaction,
                                    proto::Event::SessionPersistFailed {
                                        session_id,
                                        client_submission_id,
                                        error: error.clone(),
                                    },
                                );
                                let rejection = match phase_one_reservation.take() {
                                    Some(reservation) => reject_oversized_text_artifact_admission(
                                        &session,
                                        reservation,
                                        crate::db::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
                                    )
                                    .await,
                                    None => database_rejection,
                                };
                                let _ = respond_to.send(Err(rejection));
                                continue;
                            }
                        }
                        Err(e) => {
                            let error = format!("{e:#}");
                            let database_rejection = user_message_database_error(
                                &e,
                                proto::ErrorCode::UserMessageNotAccepted,
                                format!(
                                    "session persistence failed before accepting message {client_submission_id}: {error}"
                                ),
                            );
                            tracing::error!(error = %error, session_id = %session_id,
                            "persisting session on first message failed; dropping message");
                            send_current_event(
                                &event_tx,
                                &redaction,
                                proto::Event::SessionPersistFailed {
                                    session_id,
                                    client_submission_id,
                                    error: error.clone(),
                                },
                            );
                            let rejection = match phase_one_reservation.take() {
                                Some(reservation) => reject_oversized_text_artifact_admission(
                                    &session,
                                    reservation,
                                    crate::db::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
                                )
                                .await,
                                None => database_rejection,
                            };
                            let _ = respond_to.send(Err(rejection));
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
                    let base_redact = {
                        let snapshot = config_snapshot
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        snapshot.extended.redact.clone()
                    };
                    if !refresh_redaction_for_turn(
                        &session,
                        session_id,
                        &project_root,
                        base_redact,
                        &redaction_overrides,
                        &mut unsupported_redaction_notified,
                        &redaction,
                        &interrupts,
                        &event_tx,
                        &driver_control_tx,
                        &session_env,
                    )
                    .await
                    {
                        emit_session_driver_failed_once(
                            &event_tx,
                            &turn_completions,
                            &redaction,
                            session_id,
                            &mut driver_failed,
                            "driver control channel closed".to_string(),
                        );
                        let rejection = match phase_one_reservation.take() {
                            Some(reservation) => reject_oversized_text_artifact_admission(
                                &session,
                                reservation,
                                crate::db::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
                            )
                            .await,
                            None => proto::ErrorPayload {
                                code: proto::ErrorCode::UserMessageNotAccepted,
                                message: format!(
                                    "session driver became unavailable before accepting message {client_submission_id} while refreshing redaction"
                                ),
                            },
                        };
                        let _ = respond_to.send(Err(rejection));
                        break WorkerStop::DriverFailed;
                    }
                    let max_primary_rounds = {
                        let snapshot = config_snapshot
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        max_primary_rounds_for(&snapshot.extended)
                    };
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetMaxPrimaryRounds {
                            max_primary_rounds,
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        let rejection = match phase_one_reservation.take() {
                            Some(reservation) => reject_oversized_text_artifact_admission(
                                &session,
                                reservation,
                                crate::db::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
                            )
                            .await,
                            None => proto::ErrorPayload {
                                code: proto::ErrorCode::UserMessageNotAccepted,
                                message: format!(
                                    "session driver became unavailable before accepting message {client_submission_id} while applying round limits"
                                ),
                            },
                        };
                        let _ = respond_to.send(Err(rejection));
                        break WorkerStop::DriverFailed;
                    }
                    let target = foreground_input_target
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    let receipt = submission
                        .client_submissions
                        .first()
                        .cloned()
                        .expect("wire user submissions carry a client receipt");
                    if artifact_admission.is_none() {
                        let durable_receipt = match session
                            .db
                            .client_submission_receipt(session_id, receipt.id)
                            .await
                        {
                            Ok(receipt) => receipt,
                            Err(error) => {
                                tracing::warn!(%error, %session_id, client_submission_id = %receipt.id,
                                "client submission dedupe lookup failed; refusing ambiguous enqueue");
                                let _ = respond_to.send(Err(user_message_database_error(
                                    &error,
                                    proto::ErrorCode::Internal,
                                    "could not verify whether this message was already accepted; retry",
                                )));
                                continue;
                            }
                        };
                        if let Some(durable_receipt) = durable_receipt {
                            if durable_receipt.origin_principal != receipt.origin_principal
                                || durable_receipt.fingerprint != receipt.fingerprint
                            {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                code: proto::ErrorCode::BadRequest,
                                message: format!(
                                    "client_submission_id {} was already used for a different payload",
                                    receipt.id
                                ),
                            }));
                                continue;
                            }
                            // The submission is already durable. For an authenticated
                            // remote send, still resolve its operation identity through
                            // the transactional ledger (#3) — record a fresh operation,
                            // replay an already-committed one, or reject an
                            // operation/actor conflict — but NEVER enqueue a second copy.
                            #[cfg(feature = "remote")]
                            if let Some(remote) = remote_operation.as_ref() {
                                match reserve_remote_send_operation(&session.db, remote).await {
                                    RemoteSendDecision::Accepted | RemoteSendDecision::Replayed => {
                                    }
                                    RemoteSendDecision::Rejected(error) => {
                                        let _ = respond_to.send(Err(error));
                                        continue;
                                    }
                                }
                            }
                            let queue = driver_input_queue
                                .snapshot()
                                .await
                                .into_iter()
                                .map(queue_item_to_proto)
                                .collect();
                            let _ = respond_to.send(Ok((
                                proto::QueueItem {
                                    id: receipt.id,
                                    status: proto::QueueItemStatus::Folding,
                                    text: submission.text.clone(),
                                    display_text: submission.display_text.clone(),
                                    target: queue_target_to_proto(target),
                                },
                                queue,
                            )));
                            continue;
                        }
                    }
                    if let (Some(expected_generation), Some(expected_model)) = (
                        submission.expected_model_state_generation,
                        submission.expected_model.as_ref(),
                    ) {
                        let current = authoritative_active_model_state
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone();
                        let matches = model_fence_allows_insert(
                            current.as_ref(),
                            expected_generation,
                            expected_model,
                        );
                        if !matches {
                            let rejection = match phase_one_reservation.take() {
                                Some(reservation) => {
                                    reject_oversized_text_artifact_admission(
                                        &session,
                                        reservation,
                                        crate::db::db::text_artifacts::TextArtifactRejectReason::PreflightRejected,
                                    )
                                    .await
                                }
                                None => proto::ErrorPayload {
                                    code: proto::ErrorCode::ModelGenerationStale,
                                    message: "captured model generation is no longer active"
                                        .to_string(),
                                },
                            };
                            let _ = respond_to.send(Err(rejection));
                            continue;
                        }
                    }
                    // Authenticated remote send: commit the transactional
                    // remote-operation ledger (FCM2 identity) on THIS worker
                    // ACCEPT path (never a dispatch-arm shim — AC5). Make the
                    // in-memory dedup decision FIRST with a NON-mutating peek so
                    // a conflicting or already-accepted submission never commits
                    // a fresh ledger row (#2): only a genuine fresh accept both
                    // commits the ledger AND enqueues; a duplicate records/replays
                    // the operation WITHOUT a second enqueue (#3); a conflict is
                    // rejected with no ledger row. This runs after the terminal /
                    // durable-receipt / model-fence checks above.
                    #[cfg(feature = "remote")]
                    if let Some(remote) = remote_operation.as_ref() {
                        let (peek, snapshot) = driver_input_queue
                            .peek_idempotent(
                                receipt.id,
                                &receipt.fingerprint,
                                receipt.origin_principal.as_deref(),
                            )
                            .await;
                        match peek {
                            crate::engine::message::IdempotentPush::Conflict => {
                                let rejection = match phase_one_reservation.take() {
                                    Some(reservation) => {
                                        reject_oversized_text_artifact_admission(
                                            &session,
                                            reservation,
                                            crate::db::db::text_artifacts::TextArtifactRejectReason::IdempotencyConflict,
                                        )
                                        .await
                                    }
                                    None => proto::ErrorPayload {
                                        code: proto::ErrorCode::BadRequest,
                                        message: format!(
                                            "client_submission_id {} was already used for a different payload",
                                            receipt.id
                                        ),
                                    },
                                };
                                let _ = respond_to.send(Err(rejection));
                                continue;
                            }
                            crate::engine::message::IdempotentPush::Duplicate => {
                                // Already accepted this epoch (not yet durable):
                                // record/replay the operation, never re-enqueue.
                                match reserve_remote_send_operation(&session.db, remote).await {
                                    RemoteSendDecision::Accepted | RemoteSendDecision::Replayed => {
                                        let queue: Vec<proto::QueueItem> =
                                            snapshot.into_iter().map(queue_item_to_proto).collect();
                                        let item = queue
                                            .iter()
                                            .find(|item| item.id == receipt.id)
                                            .cloned()
                                            .unwrap_or(proto::QueueItem {
                                                id: receipt.id,
                                                status: proto::QueueItemStatus::Folding,
                                                text: submission.text.clone(),
                                                display_text: submission.display_text.clone(),
                                                target: queue_target_to_proto(target),
                                            });
                                        let _ = respond_to.send(Ok((item, queue)));
                                    }
                                    RemoteSendDecision::Rejected(error) => {
                                        let _ = respond_to.send(Err(error));
                                    }
                                }
                                continue;
                            }
                            crate::engine::message::IdempotentPush::Inserted => {
                                // Genuine fresh acceptance: commit the ledger,
                                // THEN enqueue below. A conflict/failure here
                                // rejects without enqueuing.
                                match reserve_remote_send_operation(&session.db, remote).await {
                                    RemoteSendDecision::Accepted | RemoteSendDecision::Replayed => {
                                    }
                                    RemoteSendDecision::Rejected(error) => {
                                        // This is a fresh in-memory insertion
                                        // owner. Unlike Duplicate above, it
                                        // still owns the phase-one FCM2 lease
                                        // and must atomically reject/release it
                                        // (including a bound run invocation).
                                        let rejection = match phase_one_reservation.take() {
                                            Some(reservation) => {
                                                reject_oversized_text_artifact_admission(
                                                    &session,
                                                    reservation,
                                                    remote_send_rejection_reason(&error),
                                                )
                                                .await
                                            }
                                            None => error,
                                        };
                                        let _ = respond_to.send(Err(rejection));
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    let (id, snapshot, outcome) = driver_input_queue
                        .push_idempotent(receipt, *submission, target)
                        .await;
                    if matches!(outcome, crate::engine::message::IdempotentPush::Conflict) {
                        let rejection = match phase_one_reservation.take() {
                            Some(reservation) => reject_oversized_text_artifact_admission(
                                &session,
                                reservation,
                                crate::db::db::text_artifacts::TextArtifactRejectReason::IdempotencyConflict,
                            )
                            .await,
                            None => proto::ErrorPayload {
                                code: proto::ErrorCode::BadRequest,
                                message: format!(
                                    "client_submission_id {} was already used for a different payload",
                                    id
                                ),
                            },
                        };
                        let _ = respond_to.send(Err(rejection));
                        continue;
                    }
                    let queue: Vec<proto::QueueItem> =
                        snapshot.into_iter().map(queue_item_to_proto).collect();
                    let item = queue.iter().find(|item| item.id == id).cloned().unwrap_or(
                        proto::QueueItem {
                            id,
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            display_text: None,
                            target: proto::QueueTarget::default(),
                        },
                    );
                    let _ = respond_to.send(Ok((item, queue)));
                }
                SessionWork::EmitRecoveredDefaultTerminals {
                    transactions,
                    respond_to,
                } => {
                    // The retained config journal is not cleanup-safe until
                    // the driver's durable receipt ledger has accepted the
                    // terminal result. A closed driver drops `respond_to`,
                    // which the dispatcher treats as a retained retry rather
                    // than a false terminal acknowledgement.
                    let _ = send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::EmitRecoveredDefaultTerminals {
                            transactions,
                            respond_to: Some(respond_to),
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await;
                }
                SessionWork::SteerDelegation {
                    task_call_id,
                    label,
                    message,
                    origin_principal,
                    respond_to,
                } => {
                    let result = steer_delegation_side_channel(
                        &session,
                        &redact,
                        task_call_id,
                        label,
                        message,
                        origin_principal,
                    )
                    .await;
                    let _ = respond_to.send(result);
                }
                SessionWork::RemoveQueuedUserMessage {
                    queue_item_id,
                    #[cfg(feature = "remote")]
                    remote_operation,
                    respond_to,
                } => {
                    let (result, staged, mut snapshot) =
                        match driver_input_queue.stage_remove(queue_item_id).await {
                            Ok(staged) => staged,
                            Err(_) => {
                                let _ = respond_to.send(Err(queue_removal_in_progress_error()));
                                continue;
                            }
                        };
                    #[cfg(feature = "remote")]
                    if let Some(operation) = remote_operation {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
                        let receipts = if let Some(staged) = staged.as_ref() {
                            driver_input_queue.accepted_receipts(staged.ids()).await
                        } else {
                            Vec::new()
                        };
                        if let Some(staged) = staged.as_ref()
                            && receipts.is_empty()
                        {
                            driver_input_queue.mark_staged_removal_failed(staged).await;
                            let _ = respond_to.send(Err(proto::ErrorPayload {
                                code: proto::ErrorCode::Internal,
                                message: "queued message lacks its durable acceptance receipt; removal remains held".into(),
                            }));
                            continue;
                        }
                        let terminal_receipts = receipts
                            .iter()
                            .map(|receipt| {
                                crate::db::session_log::ClientSubmissionTerminalReceipt {
                                    client_submission_id: receipt.id,
                                    fingerprint: receipt.fingerprint.clone(),
                                    wire_fingerprint: receipt.wire_fingerprint.clone(),
                                    origin_principal: receipt.origin_principal.clone(),
                                    disposition,
                                }
                            })
                            .collect::<Vec<_>>();
                        let reason = remove_reason_to_proto(result);
                        let receipt = RemoteQueueMutationReceiptV1 {
                            schema_version: 1,
                            applied: matches!(
                                reason,
                                proto::RemoveQueuedUserMessageReason::Removed
                            ),
                            reason,
                            removed_count: u32::from(staged.is_some()),
                        };
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        let outcome = session.db.execute_transactional_remote_operation(
                            crate::db::remote_attachment_operations::ReserveRemoteOperation {
                                logical_attachment_id: &operation.logical_attachment_id,
                                operation_id: &operation.operation_id,
                                authenticated_device_id: &operation.authenticated_device_id,
                                authenticated_device_generation: operation.authenticated_device_generation,
                                operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                                request_hash: operation.request_hash,
                                now_ms,
                            },
                            move |conn| {
                                crate::db::Db::terminalize_queued_text_artifact_submissions_conn(
                                    conn,
                                    session_id,
                                    &terminal_receipts,
                                    now_ms,
                                )?;
                                receipt.validate()?;
                                let safe_response = serde_json::to_vec(&receipt)?;
                                Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                                    value: receipt,
                                    safe_response: safe_response.clone(),
                                    outbox_kind: "remove_queued_user_message".into(),
                                    outbox_payload: safe_response,
                                })
                            },
                        ).await;
                        let receipt = match outcome {
                            Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(receipt)) => {
                                if let Some(staged) = staged {
                                    let _ = commit_staged_removal_after_receipts(&session, &driver_input_queue, staged, &receipts).await;
                                    send_terminal_receipts_event(&event_tx, &redaction, session_id, &receipts, disposition);
                                }
                                receipt
                            }
                            Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes)) => match serde_json::from_slice::<RemoteQueueMutationReceiptV1>(&bytes) {
                                Ok(receipt) => {
                                    if let Err(error) = receipt.validate() {
                                        let _ = respond_to.send(Err(proto::ErrorPayload { code: proto::ErrorCode::Internal, message: error.to_string() }));
                                        continue;
                                    }
                                    if let Some(staged) = staged {
                                        let _ = commit_staged_removal_after_receipts(&session, &driver_input_queue, staged, &receipts).await;
                                    }
                                    receipt
                                }
                                Err(error) => { let _ = respond_to.send(Err(proto::ErrorPayload { code: proto::ErrorCode::Internal, message: error.to_string() })); continue; }
                            },
                            Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate) => {
                                if let Some(staged) = staged.as_ref() { driver_input_queue.abort_staged_removal(staged).await; }
                                let _ = respond_to.send(Err(proto::ErrorPayload { code: proto::ErrorCode::Conflict, message: "remote operation conflict".into() })); continue;
                            }
                            Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity) => {
                                if let Some(staged) = staged.as_ref() { driver_input_queue.mark_staged_removal_failed(staged).await; }
                                let _ = respond_to.send(Err(proto::ErrorPayload { code: proto::ErrorCode::Conflict, message: "remote operation capacity reached".into() })); continue;
                            }
                            Err(error) => {
                                if let Some(staged) = staged.as_ref() { driver_input_queue.mark_staged_removal_failed(staged).await; }
                                let _ = respond_to.send(Err(user_message_database_error(
                                    &error,
                                    proto::ErrorCode::Internal,
                                    "remote queue operation could not be committed",
                                ))); continue;
                            }
                        };
                        let _ = respond_to.send(Ok(remote_queue_mutation_response(receipt)));
                        continue;
                    }
                    if let Some(staged) = staged {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
                        let (_, committed_snapshot, receipts) =
                            match persist_staged_terminal_removal(
                                &session,
                                &driver_input_queue,
                                staged,
                                disposition,
                            )
                            .await
                            {
                                Ok(committed) => committed,
                                Err(error) => {
                                    let _ = respond_to.send(Err(error));
                                    continue;
                                }
                            };
                        snapshot = committed_snapshot;
                        send_terminal_receipts_event(
                            &event_tx,
                            &redaction,
                            session_id,
                            &receipts,
                            disposition,
                        );
                    }
                    let reason = remove_reason_to_proto(result);
                    let _ = respond_to.send(Ok(proto::RemoveQueuedUserMessageResult {
                        applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
                        reason,
                        removed_item: None,
                        queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                    }));
                }
                SessionWork::RemoveNewestQueuedUserMessage {
                    target_id,
                    #[cfg(feature = "remote")]
                    remote_operation,
                    respond_to,
                } => {
                    let target_id = target_id.unwrap_or_else(|| {
                        foreground_input_target
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .id
                            .clone()
                    });
                    let (result, staged, mut snapshot) =
                        match driver_input_queue.stage_remove_newest_for(&target_id).await {
                            Ok(staged) => staged,
                            Err(_) => {
                                let _ = respond_to.send(Err(queue_removal_in_progress_error()));
                                continue;
                            }
                        };
                    #[cfg(feature = "remote")]
                    if let Some(operation) = remote_operation {
                        match commit_remote_queue_mutation(RemoteQueueMutationCommit {
                            session: &session,
                            queue: &driver_input_queue,
                            staged,
                            result,
                            operation,
                            outbox_kind: "remove_newest_queued_user_message",
                            event_tx: &event_tx,
                            redaction: &redaction,
                        })
                        .await
                        {
                            Ok(receipt) => {
                                let _ =
                                    respond_to.send(Ok(remote_queue_mutation_response(receipt)));
                            }
                            Err(error) => {
                                let _ = respond_to.send(Err(error));
                            }
                        }
                        continue;
                    }
                    let mut removed_item = None;
                    if let Some(staged) = staged {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
                        let (mut removed, committed_snapshot, receipts) =
                            match persist_staged_terminal_removal(
                                &session,
                                &driver_input_queue,
                                staged,
                                disposition,
                            )
                            .await
                            {
                                Ok(committed) => committed,
                                Err(error) => {
                                    let _ = respond_to.send(Err(error));
                                    continue;
                                }
                            };
                        snapshot = committed_snapshot;
                        removed_item = removed.pop();
                        send_terminal_receipts_event(
                            &event_tx,
                            &redaction,
                            session_id,
                            &receipts,
                            disposition,
                        );
                    }
                    let reason = remove_reason_to_proto(result);
                    let _ = respond_to.send(Ok(proto::RemoveQueuedUserMessageResult {
                        applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
                        reason,
                        removed_item: removed_item.map(queue_item_to_proto),
                        queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                    }));
                }
                SessionWork::RemoveEditableQueuedUserMessages {
                    target_id,
                    #[cfg(feature = "remote")]
                    remote_operation,
                    respond_to,
                } => {
                    let target_id = target_id.unwrap_or_else(|| {
                        foreground_input_target
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .id
                            .clone()
                    });
                    let (result, staged, mut snapshot) = match driver_input_queue
                        .stage_remove_editable_for(&target_id)
                        .await
                    {
                        Ok(staged) => staged,
                        Err(_) => {
                            let _ = respond_to.send(Err(queue_removal_in_progress_error()));
                            continue;
                        }
                    };
                    #[cfg(feature = "remote")]
                    if let Some(operation) = remote_operation {
                        match commit_remote_queue_mutation(RemoteQueueMutationCommit {
                            session: &session,
                            queue: &driver_input_queue,
                            staged,
                            result,
                            operation,
                            outbox_kind: "remove_editable_queued_user_messages",
                            event_tx: &event_tx,
                            redaction: &redaction,
                        })
                        .await
                        {
                            Ok(receipt) => {
                                let _ =
                                    respond_to.send(Ok(proto::RemoveQueuedUserMessagesResult {
                                        applied: receipt.applied,
                                        reason: receipt.reason,
                                        removed_items: Vec::new(),
                                        queue: Vec::new(),
                                    }));
                            }
                            Err(error) => {
                                let _ = respond_to.send(Err(error));
                            }
                        }
                        continue;
                    }
                    let mut removed_items = Vec::new();
                    if let Some(staged) = staged {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
                        let (removed, committed_snapshot, receipts) =
                            match persist_staged_terminal_removal(
                                &session,
                                &driver_input_queue,
                                staged,
                                disposition,
                            )
                            .await
                            {
                                Ok(committed) => committed,
                                Err(error) => {
                                    let _ = respond_to.send(Err(error));
                                    continue;
                                }
                            };
                        removed_items = removed;
                        snapshot = committed_snapshot;
                        send_terminal_receipts_event(
                            &event_tx,
                            &redaction,
                            session_id,
                            &receipts,
                            disposition,
                        );
                    }
                    let reason = remove_reason_to_proto(result);
                    let _ = respond_to.send(Ok(proto::RemoveQueuedUserMessagesResult {
                        applied: !removed_items.is_empty(),
                        reason,
                        removed_items: removed_items.into_iter().map(queue_item_to_proto).collect(),
                        queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                    }));
                }
                SessionWork::RepublishQueue => {
                    driver_input_queue.republish().await;
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
                    if let Some(staged) = driver_input_queue.stage_discard_pending().await {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Cancelled;
                        match persist_staged_terminal_removal(
                            &session,
                            &driver_input_queue,
                            staged,
                            disposition,
                        )
                        .await
                        {
                            Ok((_, _, receipts)) => send_terminal_receipts_event(
                                &event_tx,
                                &redaction,
                                session_id,
                                &receipts,
                                disposition,
                            ),
                            Err(_) => send_current_event(
                                &event_tx,
                                &redaction,
                                proto::Event::Notice {
                                    session_id,
                                    text: "Could not durably cancel queued messages; their exact payloads remain held. Retry cancellation after storage recovers."
                                        .to_string(),
                                },
                            ),
                        }
                    }
                    cancel_handle.cancel();
                }
                SessionWork::ResolveAgentDecision {
                    decision_request_id,
                    answer,
                    respond_to,
                } => {
                    let outcome = async {
                        let linked_interrupt = session
                            .db
                            .interrupt_for_decision_request(session_id, decision_request_id)
                            .await?;
                        let linked_response = match (&linked_interrupt, &answer) {
                            (Some(_), crate::agent_tree::PublicDecisionAnswer::InterruptResponse { response }) => {
                                Some(response.clone())
                            }
                            (Some(_), _) => {
                                anyhow::bail!(
                                    "linked QuestionTool decision {decision_request_id} requires an interrupt response envelope"
                                );
                            }
                            (None, _) => None,
                        };
                        let decision_before = session
                            .db
                            .decision_request(session_id, decision_request_id)
                            .await?
                            .context("agent decision disappeared before settlement")?;
                        anyhow::ensure!(
                            decision_before.decision_class != "host_approval",
                            "host approval decisions can only be resolved through their real host-owned interrupt"
                        );
                        let settlement = tree_runtime
                            .resolve_user_answer(session_id, decision_request_id, answer)
                            .await?;
                        if matches!(
                            settlement,
                            crate::agent_tree::DecisionSettlement::Resolved(_)
                        ) {
                            let host_capability_refresh_runtime = {
                                config_snapshot
                                    .read()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .host_capability_refresh_runtime
                                    .clone()
                            };
                            spawn_ready_host_capability_refresh_operations(
                                &session,
                                host_capability_refresh_runtime,
                                &global_bus,
                                &redaction,
                                &tree_resolver_registry,
                                &host_capability_terminalization_failure_fence,
                            )
                            .await;
                        }
                        if matches!(
                            settlement,
                            crate::agent_tree::DecisionSettlement::Resolved(_)
                        ) && linked_interrupt.is_some()
                        {
                            // The linked row is the legacy continuation owner.
                            // It has already been terminalized by the same
                            // decision CAS, so this helper only wakes/replays
                            // that exact row and never manufactures a second
                            // continuation.
                            deliver_terminal_agent_tree_interrupt(
                                &session,
                                &event_tx,
                                &redaction,
                                &interrupts,
                                session_id,
                                decision_request_id,
                                driver_control_tx.clone(),
                                tree_resolver_registry.clone(),
                                replay_completion_tx.clone(),
                                &host_capability_terminalization_failure_fence,
                            )
                            .await;
                            // Keep the response owned by the typed answer in
                            // scope: this makes a future refactor unable to
                            // accidentally reserialize an unvalidated legacy
                            // answer for the same continuation.
                            let _ = linked_response;
                        }
                        if let crate::agent_tree::DecisionSettlement::Steered {
                            target_agent_instance_id,
                        } = &settlement
                        {
                            deliver_live_agent_tree_late_user_steers(
                                &session,
                                session_id,
                                *target_agent_instance_id,
                                &tree_resolver_registry,
                                None,
                            )
                            .await?;
                        }
                        Ok::<crate::agent_tree::DecisionSettlement, anyhow::Error>(settlement)
                    }
                    .await;
                    let _ = respond_to.send(outcome.map_err(|error| error.to_string()));
                }
                SessionWork::AuthorizeHostCapabilitiesRefresh { respond_to } => {
                    // This is deliberately spawned rather than awaited in the
                    // worker select loop. A manual AgentTree decision must
                    // leave the worker free to accept the matching
                    // `ResolveInterrupt` request, and an automatic resolver
                    // likewise needs this loop to receive its completion.
                    let refresh_session = session.clone();
                    let refresh_interrupts = interrupts.clone();
                    let refresh_agent_name = root_agent_name.clone();
                    let refresh_parent_agent_instance_id = tree_root.agent_instance_id;
                    let refresh_parent_profile_snapshot_id = tree_root.resolved_profile_snapshot_id;
                    let refresh_runtime = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .host_capability_refresh_runtime
                        .clone();
                    let refresh_global_bus = global_bus.clone();
                    let refresh_redaction = redaction.clone();
                    let refresh_tree_resolver_registry = tree_resolver_registry.clone();
                    let refresh_terminalization_failure_fence =
                        host_capability_terminalization_failure_fence.clone();
                    tokio::spawn(async move {
                        let Some(refresh_runtime) = refresh_runtime else {
                            let _ = respond_to.send(Err(HostCapabilitiesRefreshError::Internal(
                                "host capability refresh runtime is unavailable in this worker"
                                    .to_string(),
                            )));
                            return;
                        };
                        let refresh_operation = crate::agent_tree::HostCapabilitiesRefreshOperation::for_dedicated_child();
                        // A refresh is a daemon-owned operation child, not a
                        // second root decision. The foreground root remains
                        // runnable while this child waits, and the child
                        // inherits the root's exact profile/workspace lineage
                        // through the DB transaction.
                        let refresh_child = match refresh_session
                            .db
                            .create_host_capability_refresh_initialization(
                                crate::db::agent_tree_decisions::NewAgentInstance {
                                    session_id: refresh_session.id,
                                    parent_agent_instance_id: Some(
                                        refresh_parent_agent_instance_id,
                                    ),
                                    task_delegation_job_id: None,
                                    task_delegation_child_uuid: None,
                                    resolved_profile_snapshot_id:
                                        refresh_parent_profile_snapshot_id,
                                    workspace_ref: None,
                                    auto_answer_enabled: false,
                                },
                                refresh_operation.operation_id,
                                refresh_operation.request_id,
                                crate::agent_tree::daemon_host_capability_refresh_authority(),
                                crate::agent_tree::system_now_unix_ms(),
                            )
                            .await
                        {
                            Ok(child) => child,
                            Err(error) => {
                                let _ = respond_to.send(Err(
                                    HostCapabilitiesRefreshError::Internal(format!(
                                        "creating durable host capability refresh initialization failed: {error}"
                                    )),
                                ));
                                return;
                            }
                        };
                        let refresh_agent_instance_id = match refresh_session
                            .db
                            .transition_agent_instance(
                                refresh_session.id,
                                refresh_child.agent_instance_id,
                                refresh_child.revision,
                                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                                "{}",
                                crate::agent_tree::system_now_unix_ms(),
                            )
                            .await
                        {
                            Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(
                                child,
                            )) => child.agent_instance_id,
                            Ok(_) | Err(_) => {
                                abort_unbound_host_capability_refresh_initialization(
                                    &refresh_session,
                                    refresh_operation,
                                    refresh_child.agent_instance_id,
                                    "starting the dedicated host capability refresh child",
                                )
                                .await;
                                let _ = respond_to.send(Err(
                                    HostCapabilitiesRefreshError::Internal(
                                        "starting durable host capability refresh child failed"
                                            .to_string(),
                                    ),
                                ));
                                return;
                            }
                        };
                        if let Some(snapshot_id) = refresh_parent_profile_snapshot_id
                            && let Err(error) = refresh_session
                                .db
                                .set_agent_auto_answer_from_resolved_profile(
                                    refresh_session.id,
                                    refresh_agent_instance_id,
                                    snapshot_id,
                                    crate::agent_tree::system_now_unix_ms(),
                                )
                                .await
                        {
                            abort_unbound_host_capability_refresh_initialization(
                                &refresh_session,
                                refresh_operation,
                                refresh_agent_instance_id,
                                "applying the dedicated host capability refresh child profile",
                            )
                            .await;
                            let _ = respond_to.send(Err(HostCapabilitiesRefreshError::Internal(
                                format!(
                                    "applying host capability refresh child profile failed: {error}"
                                ),
                            )));
                            return;
                        }
                        let endpoint_generation = refresh_tree_resolver_registry
                            .attach_host_operation_endpoint(
                                refresh_session.id,
                                refresh_agent_instance_id,
                            );
                        let _refresh_endpoint = HostOperationEndpointGuard {
                            registry: refresh_tree_resolver_registry.clone(),
                            session_id: refresh_session.id,
                            agent_instance_id: refresh_agent_instance_id,
                            endpoint_generation,
                        };
                        let Some(_dispatch_guard) = HostCapabilityRefreshDispatchGuard::claim(
                            &refresh_runtime,
                            refresh_operation.operation_id,
                        ) else {
                            // A UUID collision is already cryptographically
                            // negligible, but a duplicate durable operation
                            // must still be fail-closed rather than adding a
                            // second dispatcher while the first owns it.
                            abort_unbound_host_capability_refresh_initialization(
                                &refresh_session,
                                refresh_operation,
                                refresh_agent_instance_id,
                                "claiming the dedicated host capability refresh dispatcher",
                            )
                            .await;
                            let _ = respond_to.send(Err(HostCapabilitiesRefreshError::Internal(
                                "host capability refresh operation is already being dispatched"
                                    .to_string(),
                            )));
                            return;
                        };
                        let questions = crate::daemon::proto::InterruptQuestionSet {
                            questions: vec![crate::daemon::proto::InterruptQuestion::Single {
                                prompt: "Refresh this daemon's locally probed host-capability snapshot?".to_string(),
                                options: vec![
                                    crate::daemon::proto::InterruptOption {
                                        id: "refresh".to_string(),
                                        label: "Refresh local capabilities".to_string(),
                                        description: Some(
                                            "Re-probe daemon-local capability metadata; no command, credential, external request, or workspace mutation is performed."
                                                .to_string(),
                                        ),
                                        secondary: false,
                                    },
                                    crate::daemon::proto::InterruptOption {
                                        id: "cancel".to_string(),
                                        label: "Not now".to_string(),
                                        description: Some("Leave the current capability snapshot unchanged.".to_string()),
                                        secondary: true,
                                    },
                                ],
                                allow_freetext: false,
                                command_detail: None,
                                permission: false,
                                approval_class: None,
                                sandbox_escalation: None,
                            }],
                        };
                        let outcome = crate::engine::interrupt::raise_and_wait_with_agent_tree(
                            &refresh_session.db,
                            &refresh_interrupts,
                            refresh_session.id,
                            &refresh_agent_name,
                            Some(refresh_agent_instance_id),
                            "Host capability refresh is awaiting its durable AgentTree decision",
                            questions,
                            crate::agent_tree::HostDecisionSubject::HostCapabilitiesRefresh {
                                operation: refresh_operation,
                            },
                            "host capability refresh decision",
                        )
                        .await;
                        if matches!(&outcome, crate::engine::interrupt::InterruptOutcome::Parked) {
                            // Shutdown/restart parked the real durable
                            // QuestionTool continuation. Leave this child
                            // nonterminal so the next worker reattaches the
                            // exact operation owner rather than cancelling a
                            // refresh the user never declined.
                            return;
                        }
                        let allowed = matches!(
                            outcome,
                            crate::engine::interrupt::InterruptOutcome::Resolved(
                                crate::daemon::proto::ResolveResponse::Single { selected_id }
                            ) if selected_id == "refresh"
                        );
                        if !allowed {
                            let finalization = finalize_terminal_host_capability_refresh_operation(
                                &refresh_session,
                                refresh_operation.operation_id,
                                &refresh_tree_resolver_registry,
                            )
                            .await;
                            match finalization {
                                HostCapabilityRefreshInterruptFinalization::Finalized
                                | HostCapabilityRefreshInterruptFinalization::NonterminalRetryable => {}
                                HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure
                                | HostCapabilityRefreshInterruptFinalization::NotTyped => {
                                    fence_host_capability_terminalization_failure(
                                        &refresh_terminalization_failure_fence,
                                    );
                                    tracing::warn!(
                                        operation_id = %refresh_operation.operation_id,
                                        "declined host capability refresh retained its durable child/Attention pair; fencing this worker epoch"
                                    );
                                }
                            }
                            let _ = respond_to.send(Err(HostCapabilitiesRefreshError::Declined));
                            return;
                        }
                        let completion = execute_host_capability_refresh_operation(
                            &refresh_session,
                            refresh_operation.operation_id,
                            &refresh_runtime,
                            &refresh_global_bus,
                            &refresh_redaction,
                        )
                        .await;
                        let finalization = finalize_terminal_host_capability_refresh_operation(
                            &refresh_session,
                            refresh_operation.operation_id,
                            &refresh_tree_resolver_registry,
                        )
                        .await;
                        match finalization {
                            HostCapabilityRefreshInterruptFinalization::Finalized
                            | HostCapabilityRefreshInterruptFinalization::NonterminalRetryable => {}
                            HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure
                            | HostCapabilityRefreshInterruptFinalization::NotTyped => {
                                fence_host_capability_terminalization_failure(
                                    &refresh_terminalization_failure_fence,
                                );
                                tracing::debug!(
                                    operation_id = %refresh_operation.operation_id,
                                    "host capability refresh direct waiter retained its durable child/Attention pair; fencing this worker epoch"
                                );
                            }
                        }
                        let _ = respond_to
                            .send(completion.map_err(HostCapabilitiesRefreshError::Internal));
                    });
                }
                SessionWork::ResolveInterrupt {
                    interrupt_id,
                    response,
                } => {
                    // A QuestionTool interrupt is both the legacy continuation
                    // rendezvous and an AgentTree decision.  Settle the latter
                    // first; only a successful/idempotent terminal receipt may
                    // wake or replay the original parked tool continuation.
                    // This makes duplicate client submits race on the durable
                    // decision CAS instead of on a process-local oneshot.
                    let tree_decision = match session
                        .db
                        .decision_request_for_interrupt(session_id, interrupt_id)
                        .await
                    {
                        Ok(decision) => decision,
                        Err(error) => {
                            tracing::warn!(%error, %interrupt_id, "loading interrupt lifecycle decision failed");
                            interrupts.emit_queue_state().await;
                            continue;
                        }
                    };
                    // Snapshot the real interrupt continuation before its
                    // linked decision changes the owned Attention projection.
                    // A parked row carries the only replay payload for the
                    // original tool call, so rereading after settlement would
                    // silently lose the exact continuation hand-off.
                    let row = session.db.get_interrupt(interrupt_id).await.ok().flatten();
                    let was_active = session
                        .db
                        .list_open_interrupts(session_id)
                        .await
                        .ok()
                        .and_then(|open| open.first().map(|row| row.interrupt_id))
                        == Some(interrupt_id);
                    let decision = row.as_ref().map(|row| {
                        crate::db::needs_attention::summarize_interrupt_decision(row, &response)
                    });
                    let mut tree_settlement_won = false;
                    if let Some(tree_decision) = tree_decision.as_ref() {
                        let envelope = match serde_json::to_string(&response) {
                            Ok(envelope) => envelope,
                            Err(error) => {
                                tracing::warn!(%error, %interrupt_id, "serializing interrupt lifecycle answer failed");
                                interrupts.emit_queue_state().await;
                                continue;
                            }
                        };
                        let settlement = if tree_decision.decision_class == "host_approval" {
                            // This is the actual daemon host-composition
                            // boundary: only the worker that owns the real
                            // interrupt continuation holds this capability.
                            // The DB transaction simultaneously settles the
                            // bound final operation and decision receipt.
                            let offered = row.as_ref().and_then(|row| {
                                row.questions.clone().or_else(|| {
                                    row.question.clone().map(|question| {
                                        crate::daemon::proto::InterruptQuestionSet {
                                            questions: vec![question],
                                        }
                                    })
                                })
                            });
                            if offered.as_ref().is_some_and(|offered| {
                                crate::approval::host_approval_response_allows(&response, offered)
                            }) {
                                let authority = match row.as_ref().map(|row| {
                                    crate::agent_tree::HostApprovalAuthority::for_durable_interrupt_binding(
                                        session_id,
                                        tree_decision,
                                        row,
                                    )
                                }) {
                                    Some(Ok(authority)) => authority,
                                    Some(Err(error)) => {
                                        tracing::warn!(
                                            %error,
                                            %interrupt_id,
                                            decision_request_id = %tree_decision.decision_request_id,
                                            "rejecting host approval settlement without a trusted runtime binding"
                                        );
                                        interrupts.emit_queue_state().await;
                                        continue;
                                    }
                                    None => {
                                        tracing::warn!(
                                            %interrupt_id,
                                            decision_request_id = %tree_decision.decision_request_id,
                                            "rejecting host approval settlement without its real interrupt row"
                                        );
                                        interrupts.emit_queue_state().await;
                                        continue;
                                    }
                                };
                                tree_runtime
                                    .resolve_host_approval(
                                        session_id,
                                        tree_decision.decision_request_id,
                                        interrupt_id,
                                        &envelope,
                                        authority,
                                    )
                                    .await
                            } else {
                                tree_runtime
                                    .cancel_host_approval(
                                        session_id,
                                        tree_decision.decision_request_id,
                                        interrupt_id,
                                        &envelope,
                                    )
                                    .await
                            }
                        } else {
                            tree_runtime
                                .resolve_trusted_private_continuation_answer(
                                    session_id,
                                    tree_decision.decision_request_id,
                                    crate::agent_tree::PrivateDecisionContinuationAnswer::interrupt_response(
                                        response.clone(),
                                    ),
                                )
                                .await
                        };
                        match settlement {
                            Ok(crate::agent_tree::DecisionSettlement::Resolved(_)) => {
                                tree_settlement_won = true;
                            }
                            Ok(crate::agent_tree::DecisionSettlement::Steered {
                                target_agent_instance_id,
                            }) => {
                                // The original QuestionTool continuation has
                                // already consumed the automatic terminal
                                // result. A later human reply is a durable
                                // steer to that same owner, never another
                                // interrupt wakeup or parked replay.
                                if let Err(error) = deliver_live_agent_tree_late_user_steers(
                                    &session,
                                    session_id,
                                    target_agent_instance_id,
                                    &tree_resolver_registry,
                                    None,
                                )
                                .await
                                {
                                    tracing::warn!(
                                        %error,
                                        decision_request_id = %tree_decision.decision_request_id,
                                        "delivering late root interrupt steer failed"
                                    );
                                }
                                interrupts.emit_queue_state().await;
                                continue;
                            }
                            Ok(
                                crate::agent_tree::DecisionSettlement::AlreadyTerminal(_)
                                | crate::agent_tree::DecisionSettlement::Retry,
                            ) => {
                                // A terminal CAS loser cannot wake the same
                                // continuation a second time. The durable
                                // receipt/recovery path remains authoritative.
                                interrupts.emit_queue_state().await;
                                continue;
                            }
                            Err(error) => {
                                tracing::warn!(%error, %interrupt_id, decision_request_id = %tree_decision.decision_request_id, "settling QuestionTool lifecycle decision failed");
                                interrupts.emit_queue_state().await;
                                continue;
                            }
                        }
                    }
                    if tree_settlement_won {
                        let host_capability_refresh_runtime = {
                            config_snapshot
                                .read()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .host_capability_refresh_runtime
                                .clone()
                        };
                        spawn_ready_host_capability_refresh_operations(
                            &session,
                            host_capability_refresh_runtime,
                            &global_bus,
                            &redaction,
                            &tree_resolver_registry,
                            &host_capability_terminalization_failure_fence,
                        )
                        .await;
                        // The winning tree settlement has already projected
                        // the real interrupt to its terminal state.  Do not
                        // fall through to the legacy `resolve_interrupt`
                        // write: it correctly rejects that now-terminal row,
                        // but would leave a live QuestionTool/approval waiter
                        // asleep.  The shared delivery boundary wakes that
                        // exact waiter or replays its owned parked payload.
                        deliver_terminal_agent_tree_interrupt(
                            &session,
                            &event_tx,
                            &redaction,
                            &interrupts,
                            session_id,
                            tree_decision
                                .as_ref()
                                .expect("winning tree settlement has its loaded decision")
                                .decision_request_id,
                            driver_control_tx.clone(),
                            tree_resolver_registry.clone(),
                            replay_completion_tx.clone(),
                            &host_capability_terminalization_failure_fence,
                        )
                        .await;
                        continue;
                    }
                    // A parked host-capability refresh has no model/driver
                    // continuation to replay. Its durable operation owns the
                    // exact allow/cancel result; let that typed dispatcher
                    // execute or directly acknowledge the executing Attention
                    // claim rather than falling through to `ReplayParkedInterrupt`.
                    if row.as_ref().is_some_and(|row| {
                        row.state == crate::db::needs_attention::InterruptState::Parked
                    }) {
                        match handle_terminal_host_capability_refresh_interrupt(
                            &session,
                            session_id,
                            interrupt_id,
                            &tree_resolver_registry,
                        )
                        .await {
                            HostCapabilityRefreshInterruptFinalization::Finalized
                            | HostCapabilityRefreshInterruptFinalization::NonterminalRetryable => {
                                // A parked row normally has no live waiter after a
                                // restart, but resolving the hub is still the exact
                                // typed wakeup if a local park raced the response.
                                // It cannot create a driver replay because this branch
                                // returns before the generic parked path.
                                interrupts.resolve(interrupt_id, response.clone());
                                interrupts.emit_queue_state().await;
                                continue;
                            }
                            HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure => {
                                // A terminal pair that could not be repaired
                                // must not wake its waiter or be generically
                                // replayed; fail this epoch for exact recovery.
                                fence_host_capability_terminalization_failure(
                                    &host_capability_terminalization_failure_fence,
                                );
                                interrupts.emit_queue_state().await;
                                continue;
                            }
                            HostCapabilityRefreshInterruptFinalization::NotTyped => {}
                        }
                    }
                    if let Some(row) = row.as_ref()
                        && row.state == crate::db::needs_attention::InterruptState::Parked
                    {
                        // Linked decisions atomically transition the parked
                        // real interrupt to `executing` only for the terminal
                        // CAS winner. Legacy rows retain their existing claim
                        // boundary. Either way, only the claimant may replay
                        // the original continuation.
                        let claimed = if tree_decision.is_some() {
                            tree_settlement_won
                        } else {
                            match session
                                .db
                                .begin_parked_interrupt_execution(interrupt_id, &response)
                                .await
                            {
                                Ok(claimed) => claimed,
                                Err(error) => {
                                    tracing::warn!(%error, %interrupt_id, "claiming parked interrupt failed");
                                    false
                                }
                            }
                        };
                        if !claimed {
                            interrupts.emit_queue_state().await;
                            continue;
                        }
                        // Process-boundary lifecycle tests kill the daemon while
                        // a parked replay is durably `executing`. The hook is
                        // debug-build + env-gated, so release production binaries
                        // cannot enter this pause.
                        if cfg!(debug_assertions)
                            && std::env::var_os("COCKPIT_TEST_PAUSE_PARKED_REPLAY_EXECUTING")
                                .is_some()
                        {
                            loop {
                                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                            }
                        }
                        let Some(payload) = row.parked.clone() else {
                            let _ = session.db.mark_interrupt_interrupted(interrupt_id).await;
                            send_current_session_event(
                                &session,
                                &event_tx,
                                &redaction,
                                proto::Event::Notice {
                                    session_id,
                                    text: format!(
                                        "Interrupted parked request {interrupt_id}: missing replay payload."
                                    ),
                                },
                                NoticeSource::DaemonDirect,
                            );
                            interrupts.emit_queue_state().await;
                            continue;
                        };
                        let Some(questions) = row.questions.clone().or_else(|| {
                            row.question.clone().map(|question| {
                                crate::daemon::proto::InterruptQuestionSet {
                                    questions: vec![question],
                                }
                            })
                        }) else {
                            let _ = session.db.mark_interrupt_interrupted(interrupt_id).await;
                            send_current_session_event(
                                &session,
                                &event_tx,
                                &redaction,
                                proto::Event::Notice {
                                    session_id,
                                    text: format!(
                                        "Interrupted parked request {interrupt_id}: missing replay question."
                                    ),
                                },
                                NoticeSource::DaemonDirect,
                            );
                            interrupts.emit_queue_state().await;
                            continue;
                        };
                        let occurrence = match session
                            .db
                            .interrupt_question_occurrence(interrupt_id)
                            .await
                        {
                            Ok(occurrence) => occurrence,
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    %interrupt_id,
                                    "failed to compute parked interrupt replay occurrence; using first occurrence"
                                );
                                1
                            }
                        };
                        let question = crate::engine::interrupt::PreResolvedInterruptQuestion {
                            agent_instance_id: row.agent_instance_id,
                            agent: row.agent_id.clone(),
                            description: row.description.clone(),
                            questions,
                            occurrence,
                        };
                        spawn_parked_interrupt_replay(
                            driver_control_tx.clone(),
                            tree_resolver_registry.clone(),
                            session_id,
                            replay_completion_tx.clone(),
                            interrupt_id,
                            agent_tree_interrupt_owner(row),
                            payload,
                            response.clone(),
                            question,
                            decision,
                            was_active,
                        );
                        continue;
                    }
                    if let Err(e) = session.db.resolve_interrupt(interrupt_id, &response).await {
                        tracing::warn!(error = %e, %interrupt_id, "resolve_interrupt failed");
                        interrupts.emit_queue_state().await;
                        continue;
                    }
                    let seq = decision.as_ref().and_then(|decision| {
                        record_interrupt_decision_event(
                            &session,
                            &redaction,
                            interrupt_id,
                            decision,
                        )
                    });
                    send_current_event(
                        &event_tx,
                        &redaction,
                        proto::Event::InterruptResolved {
                            session_id,
                            interrupt_id,
                            decision,
                            seq,
                        },
                    );
                    // Engine-side wakeup (GOALS §3b): hand the resolution to
                    // whatever tool call is blocked on this interrupt id (the
                    // `question` tool). `false` just means nobody was blocked
                    // locally — e.g. a `schedule` needs-attention nudge — and the
                    // DB row update above is the only effect.
                    interrupts.resolve(interrupt_id, response);
                    if was_active {
                        interrupts.emit_active_from_db().await;
                    } else {
                        interrupts.emit_queue_state().await;
                    }
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
                            &turn_completions,
                            &redaction,
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
                            if let Err(error) = session
                                .record_event(
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
                                )
                                .await
                            {
                                tracing::warn!(%error, %session_id, "record resume repair provenance failed");
                            }
                            send_current_session_event(
                                &session,
                                &event_tx,
                                &redaction,
                                proto::Event::Notice { session_id, text },
                                NoticeSource::DaemonDirect,
                            );
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
                SessionWork::SetActiveModel {
                    selection_id,
                    selection_deadline,
                    provider,
                    model,
                    persist_as_default,
                    trigger,
                    reasoning_effort,
                    thinking_mode,
                    prompt_cache_retention,
                } => {
                    if std::time::Instant::now() >= selection_deadline {
                        send_current_session_event(
                            &session,
                            &event_tx,
                            &redaction,
                            proto::Event::ModelSelectionResult {
                                session_id,
                                selection_id,
                                provider,
                                model,
                                reasoning_effort,
                                thinking_mode,
                                prompt_cache_retention,
                                outcome: proto::ModelSelectionOutcome::Rejected {
                                    user_message: "Model selection timed out before the daemon could apply it; retry from /model.".to_string(),
                                    diagnostic_code: "model_selection_deadline_exceeded".to_string(),
                                },
                            },
                            NoticeSource::DaemonDirect,
                        );
                        tracing::warn!(
                            %session_id,
                            %selection_id,
                            "model selection deadline expired before driver dispatch"
                        );
                        continue;
                    }
                    let rejected_provider = provider.clone();
                    let rejected_model = model.clone();
                    let rejected_reasoning_effort = reasoning_effort.clone();
                    let rejected_thinking_mode = thinking_mode;
                    let rejected_prompt_cache_retention = prompt_cache_retention;
                    // Mid-session model switch (implementation note):
                    // route the new `(provider, model)` to the running driver. The
                    // driver owns the whole daemon-side transaction: build first,
                    // then session/config persistence, then the root-primary swap
                    // and authoritative active-model state event. Legitimate
                    // config/session drift (for example an on-disk edit while the
                    // session is live) is reported back to every attached client
                    // instead of being silently reconciled here.
                    let terminal_claimed =
                        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let (completion_tx, mut completion_rx) = tokio::sync::oneshot::channel();
                    let sent = send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetActiveModelWithDeadline {
                            selection_id,
                            deadline: selection_deadline,
                            terminal_claimed: terminal_claimed.clone(),
                            completion: completion_tx,
                            provider,
                            model,
                            persist_as_default,
                            trigger,
                            reasoning_effort,
                            thinking_mode,
                            prompt_cache_retention,
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await;
                    let failure = if !sent {
                        Some((
                            "The daemon driver stopped before it could apply the model selection. Retry from /model.",
                            "model_selection_driver_unavailable",
                        ))
                    } else {
                        match tokio::time::timeout_at(
                            tokio::time::Instant::from_std(selection_deadline),
                            &mut completion_rx,
                        )
                        .await
                        {
                            Ok(Ok(())) => None,
                            Ok(Err(_)) => Some((
                                "The daemon driver stopped before it could apply the model selection. Retry from /model.",
                                "model_selection_driver_unavailable",
                            )),
                            Err(_) => Some((
                                "Model selection timed out before the daemon could apply it; retry from /model.",
                                "model_selection_deadline_exceeded",
                            )),
                        }
                    };
                    if let Some((user_message, diagnostic_code)) = failure
                        && !terminal_claimed.swap(true, std::sync::atomic::Ordering::AcqRel)
                    {
                        send_current_session_event(
                            &session,
                            &event_tx,
                            &redaction,
                            proto::Event::ModelSelectionResult {
                                session_id,
                                selection_id,
                                provider: rejected_provider,
                                model: rejected_model,
                                reasoning_effort: rejected_reasoning_effort,
                                thinking_mode: rejected_thinking_mode,
                                prompt_cache_retention: rejected_prompt_cache_retention,
                                outcome: proto::ModelSelectionOutcome::Rejected {
                                    user_message: user_message.to_string(),
                                    diagnostic_code: diagnostic_code.to_string(),
                                },
                            },
                            NoticeSource::DaemonDirect,
                        );
                    }
                    if !sent {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::ReplaceConfigSnapshot {
                    snapshot,
                    expected_generation,
                    expected_trust_revision,
                    respond_to,
                } => {
                    let result = replace_config_snapshot_if_current(
                        &config_snapshot,
                        *snapshot,
                        expected_generation,
                        expected_trust_revision,
                    );
                    let changed = result.changed;
                    send_config_snapshot_event_if_changed(
                        &event_tx,
                        &redaction,
                        &config_snapshot,
                        session_id,
                        result,
                    );
                    // Publication is complete the instant the CAS lands. The
                    // driver's rebuild of config-derived state is a *separate*
                    // stage: driver controls are serviced only at a turn
                    // boundary, so awaiting it here would block this sequential
                    // loop — and therefore Cancel and Shutdown — for the length
                    // of an arbitrarily long model turn, and would let a refresh
                    // caller's deadline destroy a perfectly healthy worker. The
                    // receipt is handed to a follow-up task instead, and the ack
                    // is sent immediately below.
                    let pending_revision =
                        (!result.stale).then_some(expected_trust_revision.unwrap_or_default());
                    let applied_receipt = if changed {
                        let (applied, applied_rx) = tokio::sync::oneshot::channel();
                        if !send_driver_control_or_fail(
                            &driver_control_tx,
                            crate::engine::driver::DriverControl::RefreshConfigDerivedState {
                                applied,
                            },
                            &event_tx,
                            &turn_completions,
                            &redaction,
                            session_id,
                            &mut driver_failed,
                        )
                        .await
                        {
                            break WorkerStop::DriverFailed;
                        }
                        // Fan-out: the follow-up task owns the driver's
                        // receipt and is the ONLY writer that clears the
                        // admission gate. The receiver it returns rides out on
                        // the ack so an interested caller can observe
                        // application without owning it — dropping it is safe.
                        Some(spawn_config_application_follow_up(
                            applied_rx,
                            trust_transition_pending.clone(),
                            pending_revision,
                            event_tx.clone(),
                            redaction.clone(),
                            session_id,
                        ))
                    } else {
                        // Nothing to apply: no derived state changed, so the
                        // gate for this revision is satisfied by publication
                        // alone and clears here, on the worker loop.
                        clear_trust_transition_gate_on_application(
                            &trust_transition_pending,
                            pending_revision,
                            &event_tx,
                            &redaction,
                            session_id,
                        );
                        None
                    };
                    // No restore-on-send-failure dance: the gate is cleared by
                    // the applied path (or by the `!changed` path above),
                    // independently of whether this ack receiver still exists.
                    let _ = respond_to.send(ReplaceConfigSnapshotAck {
                        generation: result.generation,
                        changed: result.changed,
                        stale: result.stale,
                        applied: applied_receipt,
                    });
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
                        &turn_completions,
                        &redaction,
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
                    let current = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .extended
                        .llm_mode;
                    let resolved = mode.unwrap_or_else(|| current.cycled());
                    if let Err(e) = persist_llm_mode(&project_root, resolved) {
                        tracing::warn!(error = %e, "persisting llm_mode failed");
                    }
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        persistent_llm_mode_control(resolved),
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::SetSessionLlmMode { mode } => {
                    if let Err(error) = session.set_session_llm_mode(mode) {
                        tracing::warn!(%error, session_id = %session_id, "persisting session llm mode failed");
                    }
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        session_llm_mode_control(mode),
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::SetToolSurfaceOverride {
                    override_json,
                    persist_session,
                    prune_after_switch,
                    monty_nudge,
                } => {
                    let selection = match serde_json::from_str::<crate::agents::ToolSurfaceSelection>(
                        &override_json,
                    ) {
                        Ok(selection) => selection,
                        Err(error) => {
                            tracing::warn!(%error, session_id = %session_id, "invalid tool surface override JSON");
                            let _ = engine_event_notice_tx
                                    .send(TurnEvent::Notice {
                                        text: format!(
                                            "Tool surface update failed — invalid override JSON: {error}"
                                        ),
                                    })
                                    .await;
                            continue;
                        }
                    };
                    if persist_session
                        && let Err(error) =
                            session.set_tool_surface_override_json(Some(override_json.clone()))
                    {
                        tracing::warn!(%error, session_id = %session_id, "persisting tool surface override failed");
                        let _ = engine_event_notice_tx
                            .send(TurnEvent::Notice {
                                text: format!(
                                    "Tool surface update failed — could not persist session override: {error:#}"
                                ),
                            })
                            .await;
                        continue;
                    }
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        tool_surface_override_control(selection, prune_after_switch, monty_nudge),
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::SetGoalSettingsOverride {
                    override_json,
                    persist_session,
                } => {
                    if let Some(raw) = override_json.as_deref()
                        && let Err(error) = crate::agents::parse_goal_settings_override_json(raw)
                    {
                        tracing::warn!(%error, session_id = %session_id, "invalid goal settings override JSON");
                        let _ = engine_event_notice_tx
                            .send(TurnEvent::Notice {
                                text: format!(
                                    "Goal settings update failed — invalid override JSON: {error}"
                                ),
                            })
                            .await;
                        continue;
                    }
                    if persist_session
                        && let Err(error) =
                            session.set_goal_settings_override_json(override_json.clone())
                    {
                        tracing::warn!(%error, session_id = %session_id, "persisting goal settings override failed");
                        let _ = engine_event_notice_tx
                            .send(TurnEvent::Notice {
                                text: format!(
                                    "Goal settings update failed — could not persist session override: {error:#}"
                                ),
                            })
                            .await;
                        continue;
                    }
                    let _ = engine_event_notice_tx
                        .send(TurnEvent::Notice {
                            text: "Goal settings updated.".to_string(),
                        })
                        .await;
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
                        &turn_completions,
                        &redaction,
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
                    respond_to,
                } => {
                    // `/toggle-redaction`: mutate the session's in-memory
                    // effective `RedactConfig`, rebuild the newly discoverable
                    // redaction table, then union it into the session's
                    // accumulated egress table. Session-only — never persisted.
                    // Turning a source off stops future discovery; it never
                    // removes values already known in this session.
                    //
                    // Prompt-cache note (`prompt-caching-strategy.md`): changing
                    // what's redacted can change the scrubbed bytes of the cached
                    // prefix, so the *next* outbound request after a toggle is a
                    // one-time cache re-warm. This is accepted — the toggle is a
                    // deliberate, rare user action; `scrub()` output is otherwise
                    // deterministic/byte-stable turn-to-turn (see
                    // `redact::tests::scrub_is_deterministic_within_a_session`),
                    // so it never silently varies the prefix between turns.
                    let mut effective_redact = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .extended
                        .redact
                        .clone();
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
                    match session.credential_store().and_then(|store| {
                        crate::redact::RedactionTable::build_with_env_and_credential_store(
                            &effective_redact,
                            &project_root,
                            &session_env,
                            &store,
                        )
                    }) {
                        Ok(new_table) => {
                            // H1: read the LATEST table, union, persist, and swap
                            // under the per-session redaction-table write lock so
                            // this `/toggle-redaction` refresh serializes with
                            // sealed adoption / approved-secret-file registration
                            // and cannot clobber a concurrently-committed adoption.
                            // The guard is released before the driver `.await`.
                            let table = {
                                let _redaction_guard =
                                    interrupts.lock_redaction_table_write().await;
                                let base = current_redaction(&redaction);
                                match base.union(&new_table) {
                                    Ok(unioned) => {
                                        let unioned = Arc::new(unioned);
                                        // J3: persist BEFORE swapping the live table
                                        // so a persist failure never leaves the live
                                        // table advanced ahead of the durable one (a
                                        // restart would lose the accumulated entry).
                                        // On failure keep the previously-committed
                                        // table live and surface the error.
                                        match session.persist_redaction_table(&unioned) {
                                            Ok(()) => {
                                                set_current_redaction(&redaction, unioned.clone());
                                                unioned
                                            }
                                            Err(error) => {
                                                tracing::warn!(error = %error, %session_id, "persisting redaction table failed; keeping previously committed redaction table live");
                                                base
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        // K6: never overwrite the committed table
                                        // (which may hold a sealed literal adopted this
                                        // turn) with a bare disk scan on a union error.
                                        // Keep the committed `base` live and durable and
                                        // defer the disk delta to the next refresh,
                                        // mirroring
                                        // `InterruptHub::refresh_union_redaction`.
                                        tracing::warn!(error = %error, %session_id, "unioning redaction table failed; keeping committed redaction table live");
                                        base
                                    }
                                }
                            };
                            for path in table.unsupported_files() {
                                if unsupported_redaction_notified.insert(path.clone()) {
                                    send_current_session_event(
                                        &session,
                                        &event_tx,
                                        &redaction,
                                        proto::Event::Notice {
                                            session_id,
                                            text: format!(
                                                "`{}` is an unsupported format; redaction for this file will not work",
                                                path.display()
                                            ),
                                        },
                                        NoticeSource::DaemonDirect,
                                    );
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
                                &turn_completions,
                                &redaction,
                                session_id,
                                &mut driver_failed,
                            )
                            .await
                            {
                                let _ = respond_to
                                    .send(Err("session driver is unavailable".to_string()));
                                break WorkerStop::DriverFailed;
                            }
                            send_current_event(
                                &event_tx,
                                &redaction,
                                proto::Event::RedactionState {
                                    session_id,
                                    scan_environment: effective_redact.scan_environment,
                                    scan_dotenv: effective_redact.scan_dotenv,
                                    scan_ssh_keys: effective_redact.scan_ssh_keys,
                                },
                            );
                            let _ = respond_to.send(Ok((
                                effective_redact.scan_environment,
                                effective_redact.scan_dotenv,
                                effective_redact.scan_ssh_keys,
                            )));
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "rebuilding redaction table failed");
                            let _ = respond_to.send(Err(e.to_string()));
                        }
                    }
                }
                SessionWork::SetPreflight {
                    enabled,
                    respond_to,
                } => {
                    // `/preflight`: resolve the effective value in the worker so the
                    // RPC remains responsive during a running turn, then queue an
                    // explicit driver override and its existing state broadcast. Session-only — never
                    // persisted (mirrors `/toggle-redaction`).
                    let configured = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .extended
                        .preflight
                        .enabled;
                    let target = enabled.unwrap_or(!preflight_override.unwrap_or(configured));
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetPreflight {
                            enabled: Some(target),
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        let _ = respond_to.send(Err("session driver is unavailable".to_string()));
                        break WorkerStop::DriverFailed;
                    }
                    preflight_override = Some(target);
                    let _ = respond_to.send(Ok(target));
                }
                SessionWork::SetLongcache {
                    enabled,
                    respond_to,
                } => {
                    let providers_cfg = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .providers
                        .clone();
                    let target = enabled.unwrap_or(!longcache_enabled);
                    let active_selection = session.active_model_ref();
                    let (active_provider, active_model) = active_selection
                        .as_ref()
                        .map(|active| (active.provider.as_str(), active.model.as_str()))
                        .unwrap_or((
                            initial_model_for_toggles.0.as_str(),
                            initial_model_for_toggles.1.as_str(),
                        ));
                    let supported = providers_cfg
                        .resolve_prompt_cache_retention(
                            active_provider,
                            active_model,
                            Some(crate::config::providers::PromptCacheRetention::Extended),
                        )
                        .is_some();
                    let effective = if target && !supported {
                        longcache_enabled
                    } else {
                        target
                    };
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetLongcache {
                            enabled: Some(target),
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        let _ = respond_to.send(Err("session driver is unavailable".to_string()));
                        break WorkerStop::DriverFailed;
                    }
                    longcache_enabled = effective;
                    let _ = respond_to.send(Ok(effective));
                }
                SessionWork::SetTandemModels { models } => {
                    // `/model-comparison`: build a completion model for each
                    // selected `(provider, model)` from the already-configured
                    // providers, route them to the driver's in-memory tandem set,
                    // and broadcast the resulting state (+ a one-line token-burn
                    // warning when non-empty). Empty disables the feature.
                    // Session-only — never persisted (mirrors `/toggle-redaction`).
                    let providers_cfg = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .providers
                        .clone();
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
                        let store = match session.provider_credential_store(&providers_cfg) {
                            Ok(store) => store,
                            Err(e) => {
                                send_current_session_event(
                                    &session,
                                    &event_tx,
                                    &redaction,
                                    proto::Event::Notice {
                                        session_id,
                                        text: format!(
                                            "model-comparison: skipping `{provider}/{model_id}` — {e:#}"
                                        ),
                                    },
                                    NoticeSource::DaemonDirect,
                                );
                                continue;
                            }
                        };
                        match crate::engine::model::Model::for_provider_with_store(
                            &providers_cfg,
                            provider,
                            model_id,
                            tandem_redact.clone(),
                            |name| session_env.get(name).cloned(),
                            store,
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
                                send_current_session_event(
                                    &session,
                                    &event_tx,
                                    &redaction,
                                    proto::Event::Notice {
                                        session_id,
                                        text: format!(
                                            "model-comparison: skipping `{provider}/{model_id}` — {e:#}"
                                        ),
                                    },
                                    NoticeSource::DaemonDirect,
                                );
                            }
                        }
                    }
                    let labels: Vec<String> = targets
                        .iter()
                        .map(crate::engine::schedule::TandemTarget::label)
                        .collect();
                    // Token-burn warning on a non-empty set (warning only — no cap,
                    // no meter) for tandem model-comparison fan-out.
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
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                    send_current_event(
                        &event_tx,
                        &redaction,
                        proto::Event::TandemState {
                            session_id,
                            models: labels,
                            warning,
                        },
                    );
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
                        &turn_completions,
                        &redaction,
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
                        &turn_completions,
                        &redaction,
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
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::Shutdown { pause_for_resume } => {
                    let (active, pending_tool_count, initial_committed) =
                        shutdown_activity_snapshot(&session, session_id, &interrupts, &live).await;
                    shutdown_park_committed = initial_committed;
                    break WorkerStop::Shutdown {
                        pause_for_resume,
                        active,
                        pending_tool_count,
                    };
                }
            },
        }
    };

    // Drain: close the driver input → the driver finishes its current
    // turn (if any) and exits. Then the engine event channel closes
    // and the forwarder task exits.
    //
    // Registration barrier (`daemon-lifecycle-replay-timing-robustness.md`,
    // finding 2): closing the input FIRST admits no new turn, so the in-flight
    // turn can only run to completion or block on an interrupt. On a graceful
    // (resumable) shutdown we then run a park-drain loop — re-parking any
    // interrupt the in-flight turn registers (waking a blocked driver so its
    // turn ends) until the driver task exits — and only THEN report the
    // shutdown park-commit. This closes the TOCTOU where a turn registered a
    // waiter after the drain's initial snapshot: `Committed` is published only
    // once no further registration is possible. The loop is bounded: the input
    // is closed so the turn must terminate, and the drain path force-aborts
    // this worker at its deadline regardless.
    driver_input_queue.close().await;
    let graceful_park = matches!(
        stop,
        WorkerStop::Shutdown {
            pause_for_resume: true,
            ..
        }
    );
    if !driver_joined {
        if graceful_park {
            loop {
                // Park first so a driver blocked on an interrupt is woken
                // immediately (its tool returns Parked → the turn ends).
                let sweep = interrupts.park_all_registered_collect().await;
                shutdown_park_committed = shutdown_park_committed && sweep.all_committed;
                match tokio::time::timeout(PARK_DRAIN_POLL_INTERVAL, &mut driver_handle).await {
                    Ok(join_result) => {
                        let outcome = driver_join_outcome(join_result);
                        if let Some(error) = outcome.failure_error() {
                            tracing::warn!(session_id = %session_id, error = %error, "driver ended during worker drain");
                        }
                        break;
                    }
                    // Driver still running/blocked: re-park (catch a fresh
                    // registration) and keep waiting for it to exit.
                    Err(_) => continue,
                }
            }
        } else {
            let outcome = driver_join_outcome(driver_handle.await);
            if let Some(error) = outcome.failure_error() {
                tracing::warn!(session_id = %session_id, error = %error, "driver ended during worker drain");
            }
        }
    }
    if graceful_park {
        // Final sweep: the driver task has exited, so no further interrupt can
        // be registered. Report the shutdown park-commit exactly once, now that
        // it is sound: every registered-or-registerable interrupt is parked.
        let sweep = interrupts.park_all_registered_collect().await;
        shutdown_park_committed = shutdown_park_committed && sweep.all_committed;
        interrupts.report_shutdown_commit(shutdown_park_committed);
    }
    drop(driver_input_queue);
    drop(engine_event_notice_tx);
    let _ = forward.await;
    let _ = queue_forward.await;

    // `sessionEnd` observe hooks: fire once per worker teardown, at the same
    // boundary that emits `SessionEnded` below. Fired here — after the driver
    // has drained but BEFORE the DB teardown in the `match stop` arms — so the
    // `session.db` ledger write is guaranteed live. The matcher / `endReason`
    // comes from the CLOSED [`WorkerStop::session_end_matcher`] map (never the
    // human-readable proto reason text). Observe-only / fail-open; the registry
    // is cloned from the current snapshot so no lock guard is held across the
    // hook run.
    {
        let end_matcher = stop.session_end_matcher();
        let registry = config_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .hooks()
            .clone();
        crate::engine::agent::hooks::run_observe_hooks(
            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(
                session.process_containment(),
            ),
            &crate::engine::agent::hooks::DefaultProcessEnv,
            &registry,
            crate::config::extended::hooks::HookEvent::SessionEnd,
            end_matcher,
            session.id,
            &project_root,
            &session.db,
            None,
            None,
            None,
            None,
            crate::engine::agent::hooks::ObserveFields {
                end_reason: Some(end_matcher),
                ..Default::default()
            },
        )
        .await;
    }

    match stop {
        WorkerStop::Shutdown {
            pause_for_resume: true,
            active: true,
            pending_tool_count,
        } => {
            if let Err(e) = session
                .db
                .upsert_paused_session_work(
                    session_id,
                    &root_agent_name,
                    &project_root.display().to_string(),
                    "daemon shutdown paused active work",
                    pending_tool_count,
                    proto::DAEMON_VERSION,
                )
                .await
            {
                tracing::warn!(error = %e, "persisting paused session work failed");
            }
        }
        WorkerStop::Shutdown {
            pause_for_resume: true,
            active: false,
            ..
        } => {}
        _ => {
            // Mark session ended in DB for destructive/explicit worker stops. A
            // graceful daemon drain keeps the session resumable instead.
            // A generation-bound attach may be resuming an idle lock snapshot
            // at this exact instant. Mark the generation closed before waiting
            // for its gate, then serialize permanent cleanup after a winning
            // resume. This gate belongs to one registry generation, so neither
            // side can clear locks installed by a successor incarnation.
            terminal_closing.store(true, std::sync::atomic::Ordering::Release);
            let _terminal_cleanup = terminal_lock_cleanup_gate.lock().await;
            match locks.end_session(session_id).await {
                Ok(()) => {
                    let terminal_session = session.clone();
                    match tokio::task::spawn_blocking(move || terminal_session.end()).await {
                        Ok(Ok(())) => {
                            // This receipt covers both terminal stores. Registry
                            // retirement/replacement must not proceed after only
                            // the lock half completed.
                            terminal_cleanup_complete
                                .store(true, std::sync::atomic::Ordering::Release);
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "session.end() failed during terminal cleanup");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "session.end() terminal cleanup task failed");
                        }
                    }
                }
                Err(e) => {
                    // Do not allow the registry to retire this generation or
                    // start a successor whose locks could be erased by a
                    // failed/unfinished terminal cleanup. Recovery is
                    // deliberately fail-closed rather than id-only cleanup.
                    tracing::warn!(error = %e, "lock cleanup failed during terminal session shutdown");
                }
            }
        }
    }
    send_current_event(
        &event_tx,
        &redaction,
        proto::Event::SessionEnded {
            session_id,
            reason: stop.session_ended_reason().into(),
        },
    );
    tracing::info!(session_id = %session_id, "session worker exited");
}

pub(super) fn model_expectation_matches(
    current: Option<&proto::ActiveModelState>,
    expected_generation: u64,
    expected_model: &cockpit_config::providers::ActiveModelRef,
) -> bool {
    current.is_some_and(|current| {
        current.generation == expected_generation && &current.selection == expected_model
    })
}

pub(super) fn model_fence_allows_insert(
    current: Option<&proto::ActiveModelState>,
    expected_generation: u64,
    expected_model: &cockpit_config::providers::ActiveModelRef,
) -> bool {
    model_expectation_matches(current, expected_generation, expected_model)
}

const DURABLE_ACTIVE_MODEL_FENCE_KEYS: [&str; 5] = [
    "provider",
    "model",
    "reasoning_effort",
    "thinking_mode",
    "prompt_cache_retention",
];

fn decode_durable_model_fence(
    model_json: &str,
) -> anyhow::Result<cockpit_config::providers::ActiveModelRef> {
    let value: serde_json::Value =
        serde_json::from_str(model_json).context("decoding durable oversized model fence")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("durable oversized model fence must be an object"))?;
    anyhow::ensure!(
        object
            .keys()
            .all(|key| DURABLE_ACTIVE_MODEL_FENCE_KEYS.contains(&key.as_str())),
        "durable oversized model fence has unknown fields"
    );
    let model: cockpit_config::providers::ActiveModelRef =
        serde_json::from_value(value).context("decoding typed durable oversized model fence")?;
    model
        .validate()
        .map_err(|error| anyhow::anyhow!(error))
        .context("validating durable oversized model fence")?;
    anyhow::ensure!(
        canonical_durable_model_fence_json(&model)? == model_json,
        "durable oversized model fence is not canonical"
    );
    Ok(model)
}

/// Match the database leaf's canonical JSON representation: serialize the
/// typed DTO into a JSON value first, then render that value.  Direct struct
/// serialization preserves declaration order while the DB validates the
/// parsed `Value` representation, so using the latter on both sides makes a
/// durable fence replay-stable.
fn canonical_durable_model_fence_json(
    model: &cockpit_config::providers::ActiveModelRef,
) -> anyhow::Result<String> {
    serde_json::to_string(&serde_json::to_value(model)?)
        .context("encoding canonical durable oversized model fence")
}

pub(super) fn encode_durable_model_fence(
    model: &cockpit_config::providers::ActiveModelRef,
) -> anyhow::Result<String> {
    model.validate().map_err(|error| anyhow::anyhow!(error))?;
    let encoded = canonical_durable_model_fence_json(model)?;
    let decoded = decode_durable_model_fence(&encoded)?;
    anyhow::ensure!(
        decoded == *model,
        "durable model fence round-trip changed model"
    );
    Ok(encoded)
}

fn update_authoritative_active_model_state(
    state: &Arc<RwLock<Option<proto::ActiveModelState>>>,
    event: &proto::Event,
) {
    let next = match event {
        proto::Event::ActiveModelState {
            selection,
            default_selection,
            diverged,
            generation,
            ..
        } => Some(proto::ActiveModelState {
            selection: selection.clone(),
            default_selection: default_selection.clone(),
            diverged: *diverged,
            generation: *generation,
        }),
        proto::Event::ModelSelectionResult {
            outcome: proto::ModelSelectionOutcome::Applied { active_state, .. },
            ..
        } => Some(proto::ActiveModelState {
            selection: active_state.selection.clone(),
            default_selection: active_state.default_selection.clone(),
            diverged: active_state.diverged,
            generation: active_state.generation,
        }),
        _ => None,
    };
    if let Some(next) = next {
        *state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(next);
    }
}

/// Releasable, debug-build + env-gated injected pause point
/// (`daemon-lifecycle-replay-timing-robustness.md`, matching
/// `COCKPIT_TEST_PAUSE_PARKED_REPLAY_EXECUTING`'s `cfg!(debug_assertions)` +
/// env shape). Sleeps `<var>` milliseconds so a test can force the worst-case
/// drain interleaving deterministically — the park write lands *after* the
/// `--grace` deadline would have fired on the pre-fix code — without relying on
/// host CPU starvation. Bounded/self-releasing, so the fixed drain path still
/// observes a committed park within `INTERRUPT_PARK_COMMIT_DEADLINE`.
/// Compiled out of release binaries entirely.
async fn test_injected_park_delay(_var: &str) {
    #[cfg(debug_assertions)]
    {
        if let Some(ms) =
            std::env::var_os(_var).and_then(|raw| raw.to_str().and_then(|s| s.parse::<u64>().ok()))
        {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
    }
}

pub(super) async fn shutdown_activity_snapshot(
    session: &Session,
    session_id: Uuid,
    interrupts: &crate::engine::interrupt::InterruptHub,
    live: &LiveState,
) -> (bool, i64, bool) {
    // Injected worst-case interleaving for criteria 2/3/8: delay the shutdown
    // park commit so the pre-fix drain path (which released pid/socket at the
    // `--grace` deadline) races ahead of it, while the fixed path awaits the
    // park-commit signal below.
    test_injected_park_delay("COCKPIT_TEST_DELAY_SHUTDOWN_PARK_MS").await;
    // Initial sweep only — the shutdown park-commit is NOT reported here.
    // The worker re-parks (finding 2 registration barrier) and reports once,
    // after the driver task exits, so `Committed` cannot be observed while an
    // in-flight turn could still register a fresh interrupt. The sweep's
    // write-commit status is threaded out so a failed *initial* park (whose
    // waiter is then gone from the map and cannot be re-detected by a later
    // sweep) still surfaces as a non-clean terminal.
    let sweep = interrupts.park_all_registered_collect().await;
    let pending_tool_count = session
        .db
        .list_open_interrupts(session_id)
        .await
        .map(|rows| rows.len() as i64)
        .unwrap_or(sweep.count as i64);
    let active = {
        let (has_schedules, processing) = (live.has_active_schedules(), live.processing());
        has_schedules || processing || pending_tool_count > 0
    };
    (active, pending_tool_count, sweep.all_committed)
}

#[cfg(test)]
mod interrupt_redaction_tests {
    use super::*;

    #[test]
    fn host_operation_claim_loss_reloads_exact_state_and_fails_closed_unless_terminal() {
        use crate::db::agent_tree_decisions::AgentInstanceState;

        for terminal in [
            AgentInstanceState::Completed,
            AgentInstanceState::Failed,
            AgentInstanceState::Cancelled,
        ] {
            assert_eq!(
                classify_host_operation_recovery_reload(Ok(Some(terminal))),
                HostOperationRecoveryReload::ConcurrentlyTerminal,
                "a concurrent terminalization is the only safe reason to leave a host child unattached"
            );
        }
        for lost_or_unavailable in [
            classify_host_operation_recovery_reload(Ok(Some(AgentInstanceState::Running))),
            classify_host_operation_recovery_reload(Ok(None)),
            classify_host_operation_recovery_reload(Err(())),
        ] {
            assert_ne!(
                lost_or_unavailable,
                HostOperationRecoveryReload::ConcurrentlyTerminal,
                "a live, missing, or unreadable child must abort this epoch before root activation rather than strand its operation"
            );
        }
    }

    #[test]
    fn terminal_host_operation_cleanup_refuses_db_errors_and_nonterminal_cas_reloads() {
        use crate::db::agent_tree_decisions::AgentInstanceState;

        let expected = AgentInstanceState::Completed;
        for rejected in [
            classify_host_capability_refresh_terminal_child(expected, Err(())),
            // This is the state observed after a transition CAS lost to a
            // concurrent revision that did not terminalize the child.
            classify_host_capability_refresh_terminal_child(
                expected,
                Ok(Some(AgentInstanceState::WaitingForUser)),
            ),
            classify_host_capability_refresh_terminal_child(expected, Ok(None)),
            // A concurrent cancellation is terminal but is not compatible
            // with an operation that durably completed.
            classify_host_capability_refresh_terminal_child(
                expected,
                Ok(Some(AgentInstanceState::Cancelled)),
            ),
        ] {
            assert!(
                !rejected.permits_terminal_cleanup(),
                "DB failure, missing child, nonterminal CAS reload, and incompatible terminal winner must retain Attention and endpoint: {rejected:?}"
            );
        }
    }

    #[test]
    fn retained_terminalization_feedback_fences_the_current_worker_epoch_once() {
        let fence = std::sync::atomic::AtomicBool::new(false);
        // The preceding regression covers the DB-error and revision-conflict
        // classifications. Their common async dispatcher feedback is a single
        // worker-epoch fence, consumed before the next work-loop turn.
        fence.store(true, std::sync::atomic::Ordering::Release);
        assert!(consume_host_capability_terminalization_failure_fence(
            &fence
        ));
        assert!(
            !consume_host_capability_terminalization_failure_fence(&fence),
            "a retained finalization must abort one epoch, not manufacture repeated cleanup"
        );
    }

    #[test]
    fn direct_terminalization_failure_fences_the_current_worker_epoch_before_reply() {
        let fence = std::sync::atomic::AtomicBool::new(false);

        // The direct SessionWork waiter must use the same fence as the
        // recovered-operation dispatcher: its reply may be observed, but the
        // live worker must not release another continuation while cleanup is
        // retained for recovery.
        fence_host_capability_terminalization_failure(&fence);
        assert!(consume_host_capability_terminalization_failure_fence(
            &fence
        ));
    }

    #[test]
    fn host_refresh_finalization_outcomes_never_conflate_retry_with_terminal_repair_failure() {
        use crate::db::agent_tree_decisions::HostCapabilityRefreshOperationState;

        // An outbox publication fence can leave an otherwise valid operation
        // allowed; scheduler/direct-waiter callers must retry it rather than
        // aborting the worker. The same holds while an owned probe is in
        // flight. These are intentionally distinct from a terminal cleanup
        // failure, which may not wake/replay a parked continuation.
        for state in [
            HostCapabilityRefreshOperationState::Allowed,
            HostCapabilityRefreshOperationState::Pending,
            HostCapabilityRefreshOperationState::Executing,
        ] {
            assert!(!terminal_host_operation_interrupt_requires_repair(state));
            assert_eq!(
                HostCapabilityRefreshInterruptFinalization::NonterminalRetryable,
                HostCapabilityRefreshInterruptFinalization::NonterminalRetryable,
                "{state:?} is scheduled/in flight, not a terminal cleanup failure"
            );
        }

        let retained = HostCapabilityRefreshInterruptFinalization::RetainedTerminalCleanupFailure;
        let finalized = HostCapabilityRefreshInterruptFinalization::Finalized;
        assert_ne!(retained, finalized);
        assert_ne!(
            retained,
            HostCapabilityRefreshInterruptFinalization::NonterminalRetryable,
            "a parked/recovery terminal cleanup failure must fence without waking its waiter"
        );
    }

    #[test]
    fn concurrent_exact_terminalization_is_the_single_cleanup_permit() {
        use crate::db::agent_tree_decisions::AgentInstanceState;

        let exact = classify_host_capability_refresh_terminal_child(
            AgentInstanceState::Failed,
            Ok(Some(AgentInstanceState::Failed)),
        );
        assert_eq!(exact, HostCapabilityRefreshChildTerminalization::Verified);
        assert!(exact.permits_terminal_cleanup());
    }

    #[tokio::test]
    async fn concurrent_terminal_cleanup_acknowledges_attention_exactly_once() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "agent")
            .await
            .unwrap();
        let interrupt_id = db
            .raise_interrupt(
                session.session_id,
                "agent",
                "terminal host operation",
                Some(&crate::db::wire::InterruptQuestion::Freetext {
                    prompt: "retry the terminal host operation?".into(),
                    masked: false,
                }),
            )
            .await
            .unwrap();
        assert!(db.park_interrupt(interrupt_id).await.unwrap());
        assert!(
            db.begin_parked_interrupt_execution(
                interrupt_id,
                &crate::daemon::proto::ResolveResponse::Cancel,
            )
            .await
            .unwrap()
        );

        // This is the acknowledgement race after two workers both reload the
        // same exact terminal child. SQLite's state CAS admits one cleanup;
        // the other observes the durable resolved row and may only detach.
        let first = db.complete_executing_interrupt(interrupt_id);
        let second = db.complete_executing_interrupt(interrupt_id);
        let (first, second) = tokio::join!(first, second);
        let (first, second) = (first.unwrap(), second.unwrap());
        assert!(first || second);
        assert_ne!(first, second);
        assert_eq!(
            db.get_interrupt(interrupt_id).await.unwrap().unwrap().state,
            crate::db::needs_attention::InterruptState::Resolved
        );
    }

    #[test]
    fn deadline_maintenance_backlog_round_robins_in_bounded_slices() {
        let deadlines = WorkerAgentTreeDeadlines::default();
        let session_id = uuid::Uuid::from_u128(1);
        let ids = [
            uuid::Uuid::from_u128(1),
            uuid::Uuid::from_u128(2),
            uuid::Uuid::from_u128(3),
            uuid::Uuid::from_u128(4),
            uuid::Uuid::from_u128(5),
        ];
        for decision_request_id in ids {
            crate::agent_tree::DecisionDeadlineScheduler::schedule(
                &deadlines,
                session_id,
                decision_request_id,
                10,
            );
        }
        let expected = ids.map(|decision_request_id| (session_id, decision_request_id));

        assert_eq!(deadlines.due_limited(10, 2), expected[..2].to_vec());
        assert_eq!(deadlines.due_limited(10, 2), expected[2..4].to_vec());
        assert_eq!(
            deadlines.due_limited(10, 2),
            vec![expected[4], expected[0]],
            "the cursor wraps only after every due decision receives a turn"
        );
    }

    #[test]
    fn deadline_backlog_scan_takes_only_the_requested_ordered_slice() {
        let deadlines = WorkerAgentTreeDeadlines::default();
        let session_id = uuid::Uuid::from_u128(77);
        // A deliberately large same-deadline backlog exercises the B-tree
        // range cursor without constructing an all-due temporary vector.
        for value in 1..=2_048_u128 {
            crate::agent_tree::DecisionDeadlineScheduler::schedule(
                &deadlines,
                session_id,
                uuid::Uuid::from_u128(value),
                10,
            );
        }
        let first = deadlines.due_limited(10, 3);
        let second = deadlines.due_limited(10, 3);
        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 3);
        assert!(
            first.iter().all(|(session, _)| *session == session_id)
                && second.iter().all(|(session, _)| *session == session_id)
        );
        assert!(
            first.iter().all(|entry| !second.contains(entry)),
            "the cursor advances through a large due backlog before wrapping"
        );
    }

    #[test]
    fn refresh_dispatch_registry_is_shared_by_all_runtimes_for_one_store() {
        let store = crate::host_capabilities::HostCapabilitySnapshotStore::new();
        let runtime = HostCapabilityRefreshRuntime {
            store: store.clone(),
            probes: crate::host_capabilities::HostCapabilityProbeInputs::for_unit_tests(
                std::path::PathBuf::from("/workspace"),
            ),
            serial_execution: store.refresh_serialization(),
            in_flight_operations: store.refresh_in_flight_operations(),
        };
        let another_runtime = HostCapabilityRefreshRuntime {
            store: store.clone(),
            probes: crate::host_capabilities::HostCapabilityProbeInputs::for_unit_tests(
                std::path::PathBuf::from("/workspace"),
            ),
            serial_execution: store.refresh_serialization(),
            in_flight_operations: store.refresh_in_flight_operations(),
        };
        let operation_id = uuid::Uuid::new_v4();
        let guard = HostCapabilityRefreshDispatchGuard::claim(&runtime, operation_id)
            .expect("first dispatcher owns the operation");
        assert!(
            HostCapabilityRefreshDispatchGuard::claim(&another_runtime, operation_id).is_none(),
            "a separately built session runtime must observe the same operation owner"
        );
        drop(guard);
        assert!(
            HostCapabilityRefreshDispatchGuard::claim(&runtime, operation_id).is_some(),
            "the one-shot guard is released after its direct or scheduled dispatcher exits"
        );
    }

    #[test]
    fn warm_registry_tracks_exact_interactive_and_noninteractive_endpoints() {
        let registry = WorkerAgentTreeResolverRegistry::default();
        let session_id = uuid::Uuid::new_v4();
        let interactive_id = uuid::Uuid::new_v4();
        let noninteractive_id = uuid::Uuid::new_v4();
        let (driver_tx, _driver_rx) = tokio::sync::mpsc::channel(1);
        let (leaf_tx, _leaf_rx) = tokio::sync::mpsc::channel(1);

        let interactive_generation = crate::engine::agent::next_agent_tree_endpoint_generation();
        let noninteractive_generation = crate::engine::agent::next_agent_tree_endpoint_generation();
        registry.attach_parent_endpoint(
            session_id,
            interactive_id,
            interactive_generation,
            driver_tx,
        );
        registry.attach_noninteractive_endpoint(
            session_id,
            noninteractive_id,
            noninteractive_generation,
            leaf_tx,
        );
        assert!(matches!(
            registry.parent_endpoint(session_id, interactive_id),
            Some(WorkerAgentTreeResolverEndpoint::Driver(_))
        ));
        assert!(matches!(
            registry.parent_endpoint(session_id, noninteractive_id),
            Some(WorkerAgentTreeResolverEndpoint::Noninteractive(_))
        ));

        registry.detach_parent_endpoint_if_generation(
            session_id,
            interactive_id,
            interactive_generation,
        );
        assert!(
            registry
                .parent_endpoint(session_id, interactive_id)
                .is_none()
        );
        registry.detach_session(session_id);
        assert!(
            registry
                .parent_endpoint(session_id, noninteractive_id)
                .is_none()
        );
    }

    #[test]
    fn full_warm_mailbox_is_withdrawn_before_utility_reselection_and_cannot_evict_replacement() {
        let registry = Arc::new(WorkerAgentTreeResolverRegistry::default());
        let session_id = uuid::Uuid::new_v4();
        let parent_agent_instance_id = uuid::Uuid::new_v4();
        let (full_tx, _full_rx) = tokio::sync::mpsc::channel(1);
        full_tx
            .try_send(crate::engine::driver::DriverControl::WakeGoal)
            .expect("test setup fills the exact warm-parent mailbox");
        let failed_generation = registry.attach_parent_endpoint(
            session_id,
            parent_agent_instance_id,
            crate::engine::agent::next_agent_tree_endpoint_generation(),
            full_tx,
        );
        let (completion_tx, _completion_rx) = tokio::sync::mpsc::channel(1);
        let delivery = WorkerAgentTreeResolverDelivery {
            registry: registry.clone(),
            completions: completion_tx,
        };
        let packet = crate::agent_tree::RedactedDecisionPacket {
            decision_request_id: uuid::Uuid::new_v4(),
            agent_instance_id: uuid::Uuid::new_v4(),
            resolver_profile_snapshot_id: None,
            resolver_slot: None,
            parent_agent_instance_id: Some(parent_agent_instance_id),
            session_id,
            task_call_id: None,
            workspace_ref: None,
            options_contract_json: "{}".to_string(),
            free_text_contract_json: None,
            recommendation_json: None,
            rationale_redaction_class: "low_risk".to_string(),
            decision_class: crate::agent_tree::DecisionClass::LowRisk,
            deadline_unix_ms: None,
        };

        assert!(
            crate::agent_tree::DecisionResolverDelivery::accept(
                &delivery,
                session_id,
                crate::agent_tree::DecisionResolverRoute::WarmParent,
                packet,
            )
            .is_err(),
            "a full warm mailbox must synchronously reject so AgentTreeRuntime can reselect utility"
        );
        assert!(
            registry
                .parent_endpoint(session_id, parent_agent_instance_id)
                .is_none(),
            "the rejected mailbox is withdrawn before begin_delivery performs utility fallback"
        );
        let directory = WorkerAgentTreeResolverDirectory {
            registry: registry.clone(),
        };
        assert!(
            !crate::agent_tree::DecisionResolverDirectory::parent_cache_resumable(
                &directory,
                session_id,
                parent_agent_instance_id,
            ),
            "the runtime will now select its configured utility resolver; the generic runtime regression covers that second hand-off"
        );

        let (replacement_tx, _replacement_rx) = tokio::sync::mpsc::channel(1);
        let replacement_generation = registry.attach_parent_endpoint(
            session_id,
            parent_agent_instance_id,
            crate::engine::agent::next_agent_tree_endpoint_generation(),
            replacement_tx,
        );
        assert_ne!(failed_generation, replacement_generation);
        assert!(
            !registry.detach_parent_endpoint_if_generation(
                session_id,
                parent_agent_instance_id,
                failed_generation,
            ),
            "an old failure must not erase a recovered replacement endpoint"
        );
        assert_eq!(
            registry
                .parent_endpoint_registration(session_id, parent_agent_instance_id)
                .expect("replacement survives old compare-and-remove")
                .generation,
            replacement_generation
        );
    }

    #[test]
    fn delayed_endpoint_detach_cannot_evict_a_replacement_incarnation() {
        let registry = WorkerAgentTreeResolverRegistry::default();
        let session_id = uuid::Uuid::new_v4();
        let agent_instance_id = uuid::Uuid::new_v4();
        let (old_tx, _old_rx) = tokio::sync::mpsc::channel(1);
        let old_generation = registry.attach_parent_endpoint(
            session_id,
            agent_instance_id,
            crate::engine::agent::next_agent_tree_endpoint_generation(),
            old_tx,
        );
        let (replacement_tx, _replacement_rx) = tokio::sync::mpsc::channel(1);
        let replacement_generation = registry.attach_parent_endpoint(
            session_id,
            agent_instance_id,
            crate::engine::agent::next_agent_tree_endpoint_generation(),
            replacement_tx,
        );

        // The old frame's forwarded attach can be delayed behind recovery as
        // well. It must not regress the directory before its delayed detach
        // arrives.
        let (delayed_old_tx, _delayed_old_rx) = tokio::sync::mpsc::channel(1);
        registry.attach_parent_endpoint(
            session_id,
            agent_instance_id,
            old_generation,
            delayed_old_tx,
        );

        assert!(
            !registry.detach_parent_endpoint_if_generation(
                session_id,
                agent_instance_id,
                old_generation,
            ),
            "a delayed detached event from the old frame must not remove its replacement"
        );
        assert_eq!(
            registry
                .parent_endpoint_registration(session_id, agent_instance_id)
                .expect("replacement endpoint remains live")
                .generation,
            replacement_generation,
        );
    }

    #[test]
    fn stale_closed_sender_cleanup_cannot_evict_a_replacement_incarnation() {
        let registry = WorkerAgentTreeResolverRegistry::default();
        let session_id = uuid::Uuid::new_v4();
        let agent_instance_id = uuid::Uuid::new_v4();
        let (closed_tx, closed_rx) = tokio::sync::mpsc::channel(1);
        drop(closed_rx);
        let observed_closed_tx = closed_tx.clone();
        let closed_generation = registry.attach_parent_endpoint(
            session_id,
            agent_instance_id,
            crate::engine::agent::next_agent_tree_endpoint_generation(),
            closed_tx,
        );
        let (replacement_tx, _replacement_rx) = tokio::sync::mpsc::channel(1);
        let replacement_generation = registry.attach_parent_endpoint(
            session_id,
            agent_instance_id,
            crate::engine::agent::next_agent_tree_endpoint_generation(),
            replacement_tx,
        );

        assert!(
            observed_closed_tx
                .try_send(crate::engine::driver::DriverControl::WakeGoal)
                .is_err(),
            "test setup retains the old closed sender selected before replacement"
        );

        // This is the late-steer path's ordering: it selected a closed sender,
        // recovery registered a new endpoint, then the stale send failure
        // reaches cleanup. Compare-and-remove must preserve the newer mailbox.
        assert!(
            !registry.detach_parent_endpoint_if_generation(
                session_id,
                agent_instance_id,
                closed_generation,
            ),
            "stale closed-sender cleanup must not remove a new exact executor"
        );
        assert_eq!(
            registry
                .parent_endpoint_registration(session_id, agent_instance_id)
                .expect("new endpoint remains warm after stale cleanup")
                .generation,
            replacement_generation,
        );
    }

    #[test]
    fn stale_host_operation_guard_drop_cannot_evict_a_replacement_incarnation() {
        let registry = Arc::new(WorkerAgentTreeResolverRegistry::default());
        let session_id = uuid::Uuid::new_v4();
        let agent_instance_id = uuid::Uuid::new_v4();
        let old_generation = registry.attach_host_operation_endpoint(session_id, agent_instance_id);
        let old_guard = HostOperationEndpointGuard {
            registry: registry.clone(),
            session_id,
            agent_instance_id,
            endpoint_generation: old_generation,
        };
        let replacement_generation =
            registry.attach_host_operation_endpoint(session_id, agent_instance_id);

        drop(old_guard);

        assert_eq!(
            registry
                .parent_endpoint_registration(session_id, agent_instance_id)
                .expect("stale host-operation Drop must preserve replacement")
                .generation,
            replacement_generation,
        );
    }

    #[test]
    fn full_driver_mailbox_rejects_only_a_pending_late_steer_without_waiting() {
        let (driver_tx, mut driver_rx) = tokio::sync::mpsc::channel(1);
        driver_tx
            .try_send(crate::engine::driver::DriverControl::WakeGoal)
            .expect("test control fills the bounded driver mailbox");
        let endpoint = WorkerAgentTreeResolverEndpoint::Driver(driver_tx);
        let (respond_to, _response) = tokio::sync::oneshot::channel();

        let started = std::time::Instant::now();
        let outcome = try_send_pending_late_user_steer(
            &endpoint,
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "durable pending steer".to_string(),
            respond_to,
        );

        assert_eq!(outcome, Err(false), "full is retryable, not closed");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "a full driver mailbox must not stall the session-worker relay"
        );
        assert!(matches!(
            driver_rx.try_recv(),
            Ok(crate::engine::driver::DriverControl::WakeGoal)
        ));
    }

    #[tokio::test]
    async fn full_driver_mailbox_retries_an_accepted_checkpoint_without_redelivery() {
        let (driver_tx, mut driver_rx) = tokio::sync::mpsc::channel(1);
        driver_tx
            .try_send(crate::engine::driver::DriverControl::WakeGoal)
            .expect("test control fills the bounded driver mailbox");
        let agent_instance_id = uuid::Uuid::new_v4();
        let steer_id = uuid::Uuid::new_v4();
        let continuation_id = uuid::Uuid::new_v4();
        let recovery_epoch = uuid::Uuid::new_v4();
        let (respond_to, _response) = tokio::sync::oneshot::channel();

        let retry = tokio::spawn(schedule_accepted_late_steer_recovery_control(
            driver_tx,
            crate::engine::driver::DriverControl::ResumeAcceptedLateUserDecisionSteer {
                agent_instance_id,
                steer_id,
                continuation_id,
                recovery_epoch,
                payload_json: "durable accepted steer".to_string(),
                continuation_checkpoint_json: "{}".to_string(),
                respond_to,
            },
        ));
        // Let the retry task make its initial `try_send` while the bounded
        // mailbox is still occupied. Draining first would only prove the
        // direct-send fast path, not that a full recovery mailbox preserves
        // this accepted checkpoint for its retry.
        tokio::task::yield_now().await;
        assert!(matches!(
            driver_rx.try_recv(),
            Ok(crate::engine::driver::DriverControl::WakeGoal)
        ));
        assert_eq!(retry.await.expect("retry task joins"), Ok(()));
        let delivered = tokio::time::timeout(std::time::Duration::from_secs(1), driver_rx.recv())
            .await
            .expect("accepted checkpoint retry must not await a full mailbox forever")
            .expect("driver sender remains open");
        assert!(matches!(
            delivered,
            crate::engine::driver::DriverControl::ResumeAcceptedLateUserDecisionSteer {
                agent_instance_id: actual_agent,
                steer_id: actual_steer,
                continuation_id: actual_continuation,
                recovery_epoch: actual_epoch,
                ..
            } if actual_agent == agent_instance_id
                && actual_steer == steer_id
                && actual_continuation == continuation_id
                && actual_epoch == recovery_epoch
        ));
    }

    #[test]
    fn redaction_failure_payload_preserves_shape_without_raw_interrupt_text() {
        let interrupt_id = uuid::Uuid::new_v4();
        let decision = crate::daemon::proto::InterruptDecision {
            permission: true,
            cancelled: false,
            lines: vec![crate::daemon::proto::InterruptDecisionLine {
                prompt: "Run `cat /tmp/secret`?".to_string(),
                answer: "Allow once".to_string(),
            }],
        };

        let payload = redaction_failed_interrupt_decision_payload(interrupt_id, &decision);
        let serialized = payload.to_string();

        assert_eq!(payload["interrupt_id"], interrupt_id.to_string());
        assert_eq!(payload["decision"]["permission"], true);
        assert_eq!(payload["decision"]["cancelled"], false);
        assert_eq!(
            payload["decision"]["lines"][0]["prompt"],
            INTERRUPT_REDACTION_FAILED
        );
        assert_eq!(
            payload["decision"]["lines"][0]["answer"],
            INTERRUPT_REDACTION_FAILED
        );
        assert!(!serialized.contains("/tmp/secret"));
        assert!(!serialized.contains("Allow once"));
    }

    #[test]
    fn resolver_free_text_requires_the_same_positive_persisted_bound() {
        let packet = crate::agent_tree::RedactedDecisionPacket {
            decision_request_id: uuid::Uuid::new_v4(),
            agent_instance_id: uuid::Uuid::new_v4(),
            resolver_profile_snapshot_id: None,
            resolver_slot: None,
            parent_agent_instance_id: None,
            session_id: uuid::Uuid::new_v4(),
            task_call_id: None,
            workspace_ref: None,
            options_contract_json: r#"{"options":[]}"#.to_string(),
            // A stale/corrupt persisted form cannot regain an unlimited
            // parser path just because its boolean says allowed.
            free_text_contract_json: Some(r#"{"allowed":true,"redacted":true}"#.to_string()),
            recommendation_json: None,
            rationale_redaction_class: "sensitive".to_string(),
            decision_class: crate::agent_tree::DecisionClass::LowRisk,
            deadline_unix_ms: None,
        };
        assert!(
            agent_tree_resolver_answer(&packet, r#"{"free_text":"x"}"#)
                .unwrap_err()
                .to_string()
                .contains("missing its bounded maximum")
        );

        let bounded_packet = crate::agent_tree::RedactedDecisionPacket {
            free_text_contract_json: Some(
                r#"{"allowed":true,"max_chars":2,"redacted":true}"#.to_string(),
            ),
            ..packet
        };
        assert_eq!(
            agent_tree_resolver_answer(&bounded_packet, r#"{"free_text":"ok"}"#).unwrap(),
            crate::agent_tree::PublicDecisionAnswer::FreeText {
                text: "ok".to_string(),
            }
        );
    }

    #[test]
    fn resolver_emits_typed_interrupt_response_for_real_question_continuations() {
        let packet = crate::agent_tree::RedactedDecisionPacket {
            decision_request_id: uuid::Uuid::new_v4(),
            agent_instance_id: uuid::Uuid::new_v4(),
            resolver_profile_snapshot_id: None,
            resolver_slot: None,
            parent_agent_instance_id: Some(uuid::Uuid::new_v4()),
            session_id: uuid::Uuid::new_v4(),
            task_call_id: None,
            workspace_ref: None,
            options_contract_json: r#"{
                "options": [],
                "interrupt_response_contract": {"schema":"redacted_interrupt_questions_v1"}
            }"#
            .to_string(),
            free_text_contract_json: None,
            recommendation_json: None,
            rationale_redaction_class: "sensitive".to_string(),
            decision_class: crate::agent_tree::DecisionClass::LowRisk,
            deadline_unix_ms: None,
        };

        let prompt = agent_tree_resolver_prompt(&packet).unwrap();
        assert!(prompt.contains("ResolveResponse envelope"));
        let answer = agent_tree_resolver_answer(
            &packet,
            r#"{"response":{"kind":"single","data":{"selected_id":"refresh"}}}"#,
        )
        .unwrap();
        assert_eq!(
            answer,
            crate::agent_tree::PublicDecisionAnswer::InterruptResponse {
                response: crate::daemon::proto::ResolveResponse::Single {
                    selected_id: "refresh".to_string(),
                },
            }
        );
    }

    #[test]
    fn production_host_refresh_auto_resolution_uses_typed_semantic_not_option_order() {
        let refresh = format!("option:{}", uuid::Uuid::new_v4());
        let cancel = format!("option:{}", uuid::Uuid::new_v4());
        let packet = crate::agent_tree::RedactedDecisionPacket {
            decision_request_id: uuid::Uuid::new_v4(),
            agent_instance_id: uuid::Uuid::new_v4(),
            resolver_profile_snapshot_id: None,
            resolver_slot: None,
            parent_agent_instance_id: None,
            session_id: uuid::Uuid::new_v4(),
            task_call_id: Some("task:daemon-owned".to_string()),
            workspace_ref: Some("workspace:daemon-owned".to_string()),
            // Place cancel first deliberately: there are no labels, and the
            // resolver must not infer behavior from this ordering.
            options_contract_json: serde_json::json!({
                "options": [],
                "interrupt_response_contract": {
                    "schema":"interrupt_question_set_v1",
                    "questions": [{
                        "kind":"single",
                        "option_ids":[cancel.clone(), refresh.clone()],
                        "allow_freetext":false,
                    }],
                },
            })
            .to_string(),
            free_text_contract_json: None,
            recommendation_json: Some(
                serde_json::json!({
                    "option_id": refresh.clone(),
                    "host_action": "refresh_local_host_capabilities",
                    "redacted": true,
                })
                .to_string(),
            ),
            rationale_redaction_class: "sensitive".to_string(),
            decision_class: crate::agent_tree::DecisionClass::LowRisk,
            deadline_unix_ms: None,
        };

        let prompt = agent_tree_resolver_prompt(&packet).unwrap();
        assert!(prompt.contains("typed daemon-host recommendation"));
        let answer = agent_tree_resolver_answer(
            &packet,
            // Even a utility reply selecting the first/cancel token cannot
            // override the host-owned semantic for the one safe ingress.
            &serde_json::json!({
                "response": {"kind":"single", "data":{"selected_id": cancel.clone()}}
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            answer,
            crate::agent_tree::PublicDecisionAnswer::InterruptResponse {
                response: crate::daemon::proto::ResolveResponse::Single {
                    selected_id: refresh
                },
            }
        );
    }
}
