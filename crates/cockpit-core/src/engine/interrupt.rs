//! Interrupt wakeup hub — the bridge that lets a blocked structural
//! tool (`question`, GOALS §3b) wait on a human answer that arrives,
//! out of band, on the daemon's `ResolveInterrupt` path.
//!
//! ## Why this exists
//!
//! The `question` tool runs inside the driver's tool-dispatch loop. It
//! must *block* until the user answers. But the answer round-trips
//! daemon ↔ client over NDJSON and lands in the **session worker's**
//! work loop ([`crate::daemon::session_worker`]) as
//! `SessionWork::ResolveInterrupt` — a different task from the one the
//! tool call is suspended in. The two need a rendezvous.
//!
//! The hub is that rendezvous: a shared registry of
//! `interrupt_id -> oneshot::Sender<ResolveResponse>`. The tool
//! [`register`](InterruptHub::register)s a channel, persists the
//! interrupt, emits the `InterruptRaised` event, and awaits the
//! receiver. The worker, on `ResolveInterrupt`, persists the response
//! and calls [`resolve`](InterruptHub::resolve), which fires the
//! matching sender and wakes the tool.
//!
//! ## Headless / no client
//!
//! Nothing in the hub times out. If no interactive client is attached
//! (headless daemon, scheduled run), the interrupt simply parks in the
//! `needs_attention` table and the tool's `await` blocks indefinitely
//! until *some* client answers — the TUI today, the remote dashboard
//! later (GOALS north star). That is the intended behavior.
//!
//! ## Single authority, like the lock manager
//!
//! One hub per session worker; both the driver (which threads it into
//! every [`crate::engine::tool::ToolCtx`]) and the worker's resolve
//! handler hold an `Arc` to the same instance. The `Mutex` is held only
//! for map insert/remove — never across an `.await`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::sync::lock_or_recover;

use tokio::sync::oneshot;
use uuid::Uuid;

use crate::daemon::proto::{self, InterruptQuestionSet, ResolveResponse};
use crate::daemon::{
    EventSender, SharedRedactionTable, current_redaction, send_current_event, set_current_redaction,
};
use crate::db::needs_attention::InterruptParkPayload;

tokio::task_local! {
    static CURRENT_INTERRUPT_PARK_PAYLOAD: RefCell<InterruptParkPayload>;
}

tokio::task_local! {
    static CURRENT_PRE_RESOLVED_INTERRUPTS: RefCell<PreResolvedInterrupts>;
}

#[derive(Debug, Clone)]
pub struct PreResolvedInterruptQuestion {
    pub agent: String,
    pub description: String,
    pub questions: InterruptQuestionSet,
    pub occurrence: usize,
}

#[derive(Debug, Clone)]
pub struct PreResolvedInterrupt {
    pub interrupt_id: Uuid,
    pub response: ResolveResponse,
    pub question: Option<PreResolvedInterruptQuestion>,
}

#[derive(Debug, Default)]
struct PreResolvedInterrupts {
    answers: HashMap<Uuid, PreResolvedInterrupt>,
    seen_questions: HashMap<String, usize>,
}

pub async fn with_interrupt_park_payload<F>(payload: InterruptParkPayload, fut: F) -> F::Output
where
    F: std::future::Future,
{
    CURRENT_INTERRUPT_PARK_PAYLOAD
        .scope(RefCell::new(payload), fut)
        .await
}

pub fn current_interrupt_park_payload() -> Option<InterruptParkPayload> {
    CURRENT_INTERRUPT_PARK_PAYLOAD
        .try_with(|payload| payload.borrow().clone())
        .ok()
}

pub fn set_current_interrupt_gate_memo(gate: crate::db::needs_attention::InterruptGateMemo) {
    let _ = CURRENT_INTERRUPT_PARK_PAYLOAD.try_with(|payload| {
        payload.borrow_mut().gate = Some(gate);
    });
}

pub async fn with_pre_resolved_interrupt<F>(
    interrupt_id: Uuid,
    response: ResolveResponse,
    fut: F,
) -> F::Output
where
    F: std::future::Future,
{
    with_pre_resolved_interrupts(
        vec![PreResolvedInterrupt {
            interrupt_id,
            response,
            question: None,
        }],
        fut,
    )
    .await
}

pub async fn with_pre_resolved_interrupt_question<F>(
    interrupt_id: Uuid,
    response: ResolveResponse,
    question: PreResolvedInterruptQuestion,
    fut: F,
) -> F::Output
where
    F: std::future::Future,
{
    with_pre_resolved_interrupts(
        vec![PreResolvedInterrupt {
            interrupt_id,
            response,
            question: Some(question),
        }],
        fut,
    )
    .await
}

pub async fn with_pre_resolved_interrupts<F>(
    interrupts: Vec<PreResolvedInterrupt>,
    fut: F,
) -> F::Output
where
    F: std::future::Future,
{
    let answers = interrupts
        .into_iter()
        .map(|entry| (entry.interrupt_id, entry))
        .collect();
    CURRENT_PRE_RESOLVED_INTERRUPTS
        .scope(
            RefCell::new(PreResolvedInterrupts {
                answers,
                seen_questions: HashMap::new(),
            }),
            async {
                let output = fut.await;
                discard_unconsumed_pre_resolved_interrupts();
                output
            },
        )
        .await
}

fn take_matching_pre_resolved_interrupt(
    agent: &str,
    description: &str,
    questions: &InterruptQuestionSet,
) -> Option<(Uuid, ResolveResponse)> {
    let interrupt_id = matching_pre_resolved_interrupt_id(agent, description, questions)?;
    take_pre_resolved_interrupt(interrupt_id).map(|response| (interrupt_id, response))
}

fn matching_pre_resolved_interrupt_id(
    agent: &str,
    description: &str,
    questions: &InterruptQuestionSet,
) -> Option<Uuid> {
    CURRENT_PRE_RESOLVED_INTERRUPTS
        .try_with(|slot| {
            let mut state = slot.borrow_mut();
            let key = question_key(agent, description, questions)?;
            let occurrence = {
                let seen = state.seen_questions.entry(key.clone()).or_default();
                *seen += 1;
                *seen
            };
            state.answers.iter().find_map(|(interrupt_id, entry)| {
                let question = entry.question.as_ref()?;
                (question.occurrence == occurrence
                    && question_key(&question.agent, &question.description, &question.questions)
                        .as_deref()
                        == Some(key.as_str()))
                .then_some(*interrupt_id)
            })
        })
        .ok()
        .flatten()
}

fn take_pre_resolved_interrupt(interrupt_id: Uuid) -> Option<ResolveResponse> {
    CURRENT_PRE_RESOLVED_INTERRUPTS
        .try_with(|slot| {
            slot.borrow_mut()
                .answers
                .remove(&interrupt_id)
                .map(|entry| entry.response)
        })
        .ok()
        .flatten()
}

fn question_key(
    agent: &str,
    description: &str,
    questions: &InterruptQuestionSet,
) -> Option<String> {
    serde_json::to_string(&serde_json::json!({
        "agent": agent,
        "description": description,
        "questions": questions,
    }))
    .ok()
}

fn discard_unconsumed_pre_resolved_interrupts() {
    let _ = CURRENT_PRE_RESOLVED_INTERRUPTS.try_with(|slot| {
        let mut state = slot.borrow_mut();
        for interrupt_id in state.answers.keys() {
            tracing::warn!(
                %interrupt_id,
                "pre-resolved interrupt answer was not consumed during replay"
            );
        }
        state.answers.clear();
    });
}

/// Whether the current tool invocation is replaying a previously parked
/// interrupt. Tools with config-controlled gates must still consume this
/// decision even if their configuration changed while the call was parked.
pub fn pre_resolved_interrupt_pending() -> bool {
    CURRENT_PRE_RESOLVED_INTERRUPTS
        .try_with(|slot| !slot.borrow().answers.is_empty())
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
pub enum InterruptOutcome {
    Resolved(ResolveResponse),
    Parked,
}

impl InterruptOutcome {
    pub fn into_response(self) -> std::result::Result<ResolveResponse, InterruptParked> {
        match self {
            Self::Resolved(response) => Ok(response),
            Self::Parked => Err(InterruptParked),
        }
    }
}

/// Sentinel for a parked interrupt. Downstream dispatch code must stop the
/// turn without fabricating a user answer or a tool result.
#[derive(Debug, thiserror::Error)]
#[error("interrupt parked")]
pub struct InterruptParked;

pub fn is_parked(err: &anyhow::Error) -> bool {
    err.downcast_ref::<InterruptParked>().is_some()
}

/// Shared interrupt rendezvous. Cheap to clone via `Arc`.
pub struct InterruptHub {
    /// Pending wakeups keyed by interrupt id. A sender is inserted by
    /// [`Self::register`] and removed when [`Self::resolve`] fires it
    /// (or when the [`PendingInterrupt`] guard drops on cancellation).
    waiters: Mutex<HashMap<Uuid, oneshot::Sender<InterruptOutcome>>>,
    /// Outbound event channel to attached clients. `None` in
    /// non-daemon paths (tool unit tests, the standalone run shim) where
    /// no client is listening — raising still works; the event is just
    /// not broadcast. Cloned from the session worker's fan-out sender.
    events: Option<EventSender>,
    redaction: Option<SharedRedactionTable>,
    db: Option<crate::db::Db>,
    session_id: Option<Uuid>,
    /// Count of attached *interactive* clients — ones that can answer an
    /// interrupt (the TUI; later the remote dashboard). A `cockpit run`
    /// event pump attaches but cannot answer, so it does not count. The
    /// server bumps this on interactive attach and decrements on detach
    /// via the shared `Arc`. Read by the loop guard (GOALS §1/§12) to
    /// decide headless behavior: 0 means "no human to prompt → don't
    /// block, auto-reject the repeat."
    interactive_clients: Arc<AtomicUsize>,
    /// Serializes EVERY read-modify-write of the live redaction table for this
    /// session (H1) — sealed adoption ([`Self::seal_redaction_with_identity`]),
    /// approved-secret-file registration ([`Self::register_approved_secret_file`]),
    /// and the per-turn refresh union (the driver's refresh via
    /// [`Self::refresh_union_redaction`]; the session-worker refresh, which owns
    /// the [`SharedRedactionTable`] directly, via [`Self::lock_redaction_table_write`]).
    /// A sealed
    /// adoption snapshots the current table, then `await`s key load + AEAD + the
    /// journal transaction before swapping in `snapshot + literal`. Any writer
    /// that reads the table, unions its delta, persists, and swaps OUTSIDE this
    /// lock could snapshot the pre-adoption table and swap its stale union AFTER
    /// the sealed transaction commits — dropping the just-adopted sealed literal
    /// from both the live and the durable table while its history row stays
    /// committed, so a later egress of that literal bypasses live redaction
    /// (decision 10.1 adopted-table invariant). Holding this async mutex across
    /// each writer's whole read→union→persist→swap makes every writer union onto
    /// the previous one's committed result, so no committed union is ever lost.
    /// Every critical section reads the LATEST table under the lock; no `.await`
    /// that could touch the table happens outside it. All writers are async, so
    /// they all serialize on this one `tokio` mutex without a sync/async split.
    redaction_table_write_lock: tokio::sync::Mutex<()>,
}

impl InterruptHub {
    /// Build a hub wired to the worker's client event fan-out, sharing an
    /// externally-owned interactive-client counter so the daemon's attach
    /// lifecycle and the hub read the same cell. The session worker owns
    /// the counter and exposes it on its handle for the server to bump as
    /// interactive clients attach/detach; the loop guard reads it via
    /// [`Self::is_interactive_attached`].
    pub fn new(
        events: EventSender,
        redaction: SharedRedactionTable,
        interactive_clients: Arc<AtomicUsize>,
        db: crate::db::Db,
        session_id: Uuid,
    ) -> Self {
        Self {
            waiters: Mutex::new(HashMap::new()),
            events: Some(events),
            redaction: Some(redaction),
            db: Some(db),
            session_id: Some(session_id),
            interactive_clients,
            redaction_table_write_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Build a detached hub with no client fan-out. Used where no client
    /// is attached (tests, the standalone shim): wakeups still work via
    /// [`Self::resolve`], but no `InterruptRaised` event is emitted.
    pub fn detached() -> Self {
        Self {
            waiters: Mutex::new(HashMap::new()),
            events: None,
            redaction: None,
            db: None,
            session_id: None,
            interactive_clients: Arc::new(AtomicUsize::new(0)),
            redaction_table_write_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Whether at least one interactive client (one that can answer an
    /// interrupt) is currently attached. `false` means headless: the loop
    /// guard must not block on a prompt and instead auto-rejects the
    /// repeat. A detached hub (tests / standalone shim) is always headless.
    pub fn is_interactive_attached(&self) -> bool {
        self.interactive_clients.load(Ordering::SeqCst) > 0
    }

    /// Register a sealed literal in the worker's live egress redaction table,
    /// persist that table, and journal the adoption into protected redaction
    /// history — all under the literal's TYPED canonical identity.
    ///
    /// Sealedness is carried by the typed [`SealedRedactionIdentity`] the whole
    /// way through — it is registered directly via `with_forced_sealed_literal`,
    /// never by serializing the identity to a `sealed:<id>` origin string and
    /// reparsing it here to reconstruct classification. `parse_sealed_redaction_origin`
    /// is kept off this live registration path entirely. This is the single
    /// place where a sealed literal becomes redacted; the legacy
    /// `sealed:<value_id>` wrapper is gone along with the agent-facing sealed
    /// write paths that were its only callers.
    ///
    /// This is the LIVE production sealed-adoption route (via
    /// [`crate::sealed::runtime::SessionRedactionSink`]). Adoption journals a
    /// `Sealed` protected-history row **atomically** with the redaction-table
    /// persist (decision 10.1): the encrypted append is prepared off the DB
    /// thread, then the table persist and the journal append commit in one
    /// transaction. If either the prepare or the transaction fails, the whole
    /// adoption rolls back and the live table is left untouched — a sealed
    /// literal is never adopted half-journaled. Re-adopting the same literal
    /// dedups to an attach (no duplicate row). Sessions carrying the
    /// unjournaled-inference opt-out (scratch / daemon-less) skip journaling.
    ///
    /// The protected-history key resolver is reached from the `Session` this
    /// method already holds ([`crate::session::Session::redaction_key_resolver`]).
    pub async fn seal_redaction_with_identity(
        &self,
        session: &crate::session::Session,
        value: String,
        identity: crate::sealed::identity::SealedRedactionIdentity,
    ) -> anyhow::Result<Option<Arc<crate::redact::RedactionTable>>> {
        let Some(redaction) = &self.redaction else {
            return Ok(None);
        };
        // H1: serialize the read-modify-write below against ALL redaction-table
        // writers for this session (other sealed adoptions, approved-secret-file
        // registration, the per-turn refresh union). The snapshot→await→swap
        // spans a `.await` (key load + AEAD + journal transaction), so any writer
        // that reads the same `base` and swaps its own union afterwards would drop
        // this adoption's literal from the live and durable table even though the
        // history row committed. Holding the async mutex across
        // read→prepare→persist→swap makes each writer see the previous one's
        // committed table as its `base`, so every committed union survives.
        let _adopt_guard = self.redaction_table_write_lock.lock().await;
        // Take the sealed identity ids from the TYPED identity, never from a
        // parsed origin display string. A legacy/unversioned session entry has
        // no record id, so both the record id and the version are `None`.
        let sealed_record_id = identity.record_id.map(|record| record.to_string());
        let sealed_version = identity.record_id.map(|_| i64::from(identity.version));

        let base = current_redaction(redaction);
        let table = Arc::new(base.with_forced_sealed_literal(value.clone(), identity)?);

        if session.unjournaled_inference_allowed() {
            // Opt-out: scratch / daemon-less sessions persist the table without
            // journaling (fail-safe, mirrors the inference path).
            session.persist_redaction_table(&table)?;
        } else {
            // Journal the adoption atomically with the table persist. On any
            // failure this returns Err having persisted nothing, so the live
            // table below is only swapped once the adoption is durable.
            session
                .adopt_sealed_literal_journaled(&table, value, sealed_record_id, sealed_version)
                .await?;
        }
        set_current_redaction(redaction, table.clone());
        Ok(Some(table))
    }

    /// Install a **contained-leak** literal into the worker's live egress
    /// redaction table and persist it, BEFORE the provider turn that reported the
    /// leak is acknowledged, so subsequent output for this and every later turn is
    /// scrubbed of the reported secret (the leak-report Contained transition —
    /// `provider-sensitive-turn barrier`, AC2).
    ///
    /// This is the live-session redaction install the leak-report handler
    /// deliberately does NOT perform: [`crate::leak_report::LeakReportHandler`]
    /// commits the encrypted protected-history row and the leak record, and this
    /// method installs the forced literal so the *live* table scrubs it. The
    /// encrypted protected-history journal is written by the handler, so — unlike
    /// sealed adoption — this path only persists the redaction table and swaps the
    /// live `Arc`; it never re-journals (mirroring
    /// [`Self::register_approved_secret_file`]).
    ///
    /// H1: takes the same [`Self::redaction_table_write_lock`] as sealed adoption
    /// and the per-turn refresh union, and reads the LATEST table under it, so a
    /// concurrent refresh can neither read a stale table nor swap over the
    /// just-installed contained literal. Fail-closed: a failed persist returns
    /// `Err` with the previously-committed table still live — the live table is
    /// never advanced ahead of the durable one, and the caller must then NOT ack
    /// the report as contained. Detached hubs (tests / standalone shim) that own
    /// no shared table return `Ok(None)`; the barrier's own module tests cover the
    /// install-before-ack ordering directly.
    pub async fn install_contained_leak_literal(
        &self,
        session: &crate::session::Session,
        value: String,
    ) -> anyhow::Result<Option<Arc<crate::redact::RedactionTable>>> {
        let Some(redaction) = &self.redaction else {
            return Ok(None);
        };
        let _guard = self.redaction_table_write_lock.lock().await;
        // `with_forced_literal` is the leak-containment adoption seam (decision
        // 11): its literals classify as `ContainedLeak`.
        let table = current_redaction(redaction)
            .with_forced_literal(value, "$leak:contained".to_string())?;
        let table = Arc::new(table);
        // Persist BEFORE swapping the live table (fail-closed): a persist failure
        // must not leave the live table advanced ahead of the durable one.
        session.persist_redaction_table(&table)?;
        set_current_redaction(redaction, table.clone());
        Ok(Some(table))
    }

    /// Register parsed values from an approved secret-bearing file in the
    /// worker's live redaction table before its contents return to a model.
    /// Detached hubs return `None`; callers then retain a local table.
    ///
    /// H1: async so it serializes on the same [`Self::redaction_table_write_lock`]
    /// as sealed adoption — a plain sync writer here could snapshot the
    /// pre-adoption table and swap its stale union after a concurrent sealed
    /// adoption commits, dropping the sealed literal from the live+durable table.
    /// Taking the lock and re-reading the LATEST table under it makes this
    /// registration union onto any concurrently-committed adoption instead of
    /// clobbering it. Fail-closed: a failed persist returns `Err` before the
    /// live table is swapped.
    pub async fn register_approved_secret_file(
        &self,
        session: &crate::session::Session,
        cfg: &crate::config::extended::RedactConfig,
        path: &std::path::Path,
    ) -> anyhow::Result<Option<Arc<crate::redact::RedactionTable>>> {
        let Some(redaction) = &self.redaction else {
            return Ok(None);
        };
        let _guard = self.redaction_table_write_lock.lock().await;
        let table = current_redaction(redaction).with_approved_secret_file(cfg, path)?;
        let table = Arc::new(table);
        session.persist_redaction_table(&table)?;
        set_current_redaction(redaction, table.clone());
        Ok(Some(table))
    }

    /// Union a freshly-built disk-scan table onto the session's LIVE redaction
    /// table under the serialized write lock, persisting the result BEFORE it is
    /// swapped live, and return the committed table.
    ///
    /// This is the per-turn refresh route for a caller that does NOT own the
    /// [`SharedRedactionTable`] directly — namely the engine driver, whose own
    /// `self.redact` is a COPY that a mid-turn sealed adoption never updates.
    /// Routing the driver's refresh through here makes it read the LATEST shared
    /// table (which may already hold a sealed literal adopted this turn via
    /// [`Self::seal_redaction_with_identity`]) under the SAME
    /// [`Self::redaction_table_write_lock`], so the driver can neither read a
    /// stale table nor persist a union that drops a committed adoption from the
    /// durable table (decision 10.1 adopted-table invariant).
    ///
    /// H1 ordering, identical to sealed adoption: read the latest table, union,
    /// **persist, then swap**. A persist failure returns `Err` with the
    /// previously-committed table still live — the live table is never advanced
    /// ahead of the durable one. A union failure keeps the committed table live
    /// unchanged (deferring the disk delta to the next refresh) rather than
    /// clobbering a committed adoption with a bare disk scan.
    ///
    /// Returns `Ok(None)` for a detached hub (tests / standalone shim) that owns
    /// no shared table; the caller then unions onto its own local copy.
    pub async fn refresh_union_redaction(
        &self,
        session: &crate::session::Session,
        new_table: &crate::redact::RedactionTable,
    ) -> anyhow::Result<Option<Arc<crate::redact::RedactionTable>>> {
        let Some(redaction) = &self.redaction else {
            return Ok(None);
        };
        let _guard = self.redaction_table_write_lock.lock().await;
        let base = current_redaction(redaction);
        let table = match base.union(new_table) {
            Ok(table) => Arc::new(table),
            Err(error) => {
                // Never overwrite the committed table (which may hold a sealed
                // literal) with a bare disk scan on a union error: keep the
                // committed table live and defer the disk delta to the next
                // refresh.
                tracing::warn!(error = %error, "unioning redaction table failed; keeping committed table");
                return Ok(Some(base));
            }
        };
        // Persist BEFORE swapping the live table: a persist failure must not
        // leave the live table advanced ahead of the durable one (a restart
        // would then lose the accumulated entry). `?` surfaces the failure with
        // the previously-committed table still live and durable.
        session.persist_redaction_table(&table)?;
        set_current_redaction(redaction, table.clone());
        Ok(Some(table))
    }

    /// Acquire the per-session redaction-table write lock for a caller that owns
    /// the read→union→persist→swap itself (the session-worker per-turn refresh,
    /// which holds the [`SharedRedactionTable`] directly rather than through this
    /// hub). Holding this guard across that whole sequence serializes the refresh
    /// against sealed adoption and approved-secret-file registration on the SAME
    /// lock, so a refresh can neither read a stale table nor swap over a
    /// concurrently-committed adoption. The caller must, under this guard, read
    /// the LATEST table via `current_redaction`, union its delta, persist, then
    /// swap — see [`Self::redaction_table_write_lock`] for the full invariant.
    pub async fn lock_redaction_table_write(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.redaction_table_write_lock.lock().await
    }

    /// Register a wakeup for `interrupt_id` and return the guard the
    /// caller awaits. The guard removes its registry entry on drop, so a
    /// tool whose future is cancelled (e.g. the worker shuts down) never
    /// leaves a dangling sender.
    pub fn register(&self, interrupt_id: Uuid) -> PendingInterrupt<'_> {
        let (tx, rx) = oneshot::channel();
        lock_or_recover(&self.waiters).insert(interrupt_id, tx);
        PendingInterrupt {
            hub: self,
            interrupt_id,
            rx: Some(rx),
        }
    }

    /// Emit `InterruptRaised` to attached clients (no-op when detached).
    /// The `question` tool calls this right after persisting the
    /// interrupt and registering the wakeup, so a client can render the
    /// answering dialog.
    pub async fn emit_raised(
        &self,
        session_id: Uuid,
        interrupt_id: Uuid,
        agent: &str,
        description: &str,
        questions: InterruptQuestionSet,
    ) {
        let open = match (&self.db, self.session_id) {
            (Some(db), Some(owned_session_id)) if owned_session_id == session_id => {
                db.list_open_interrupts(owned_session_id).await.ok()
            }
            _ => None,
        };
        if let Some(open) = &open {
            let active = open.first().map(|row| row.interrupt_id);
            if active != Some(interrupt_id) {
                self.emit_queue_changed(active, open.len().saturating_sub(1));
                return;
            }
        }
        if let (Some(events), Some(redaction)) = (&self.events, &self.redaction) {
            let pending_count = open
                .as_ref()
                .map(|open| open.len().saturating_sub(1))
                .unwrap_or(0);
            // `send` errors only when there are no subscribers — fine,
            // the interrupt still parks in the DB for the next client.
            send_current_event(
                events,
                redaction,
                proto::Event::InterruptRaised {
                    session_id,
                    interrupt_id,
                    agent: agent.to_string(),
                    description: description.to_string(),
                    question: None,
                    questions: Some(questions),
                    pending_count,
                    reason: proto::InterruptRaiseReason::Initial,
                },
            );
        }
    }

    pub async fn emit_active_from_db(&self) {
        let (Some(db), Some(session_id)) = (&self.db, self.session_id) else {
            return;
        };
        let Ok(open) = db.list_open_interrupts(session_id).await else {
            return;
        };
        let Some(active) = open.first() else {
            self.emit_queue_changed(None, 0);
            return;
        };
        let pending_count = open.len().saturating_sub(1);
        self.emit_queue_changed(Some(active.interrupt_id), pending_count);
        let questions = active.questions.clone().or_else(|| {
            active
                .question
                .clone()
                .map(|question| InterruptQuestionSet {
                    questions: vec![question],
                })
        });
        if let (Some(events), Some(redaction), Some(questions)) =
            (&self.events, &self.redaction, questions)
        {
            send_current_event(
                events,
                redaction,
                proto::Event::InterruptRaised {
                    session_id,
                    interrupt_id: active.interrupt_id,
                    agent: active.agent_id.clone(),
                    description: active.description.clone(),
                    question: None,
                    questions: Some(questions),
                    pending_count,
                    reason: proto::InterruptRaiseReason::Advance,
                },
            );
        }
    }

    pub async fn emit_queue_state(&self) {
        let (Some(db), Some(session_id)) = (&self.db, self.session_id) else {
            return;
        };
        if let Ok(open) = db.list_open_interrupts(session_id).await {
            self.emit_queue_changed(
                open.first().map(|row| row.interrupt_id),
                open.len().saturating_sub(1),
            );
        }
    }

    fn emit_queue_changed(&self, active_interrupt_id: Option<Uuid>, pending_count: usize) {
        if let (Some(events), Some(redaction), Some(session_id)) =
            (&self.events, &self.redaction, self.session_id)
        {
            send_current_event(
                events,
                redaction,
                proto::Event::InterruptQueueChanged {
                    session_id,
                    active_interrupt_id,
                    pending_count,
                },
            );
        }
    }

    /// Broadcast the session's current gitignore read-allowlist to attached
    /// clients (no-op when detached). Called right after a "Approve for this
    /// session" outcome lands a new glob, so the TUI `@`-tag popup re-includes
    /// the session-approved entry without a restart
    /// (implementation note). Carries the full set
    /// (replace, not delta); only the allow-set is ever sent. Reuses the same
    /// per-session event fan-out the worker uses for `RedactionState`.
    pub fn emit_gitignore_allow(&self, session_id: Uuid, allow: Vec<String>) {
        if let (Some(events), Some(redaction)) = (&self.events, &self.redaction) {
            // `send` errors only when there are no subscribers — fine; an
            // attaching client re-hydrates the set via the attach broadcast.
            send_current_event(
                events,
                redaction,
                proto::Event::GitignoreAllow { session_id, allow },
            );
        }
    }

    /// Deliver a resolution to whoever is blocked on `interrupt_id`.
    /// Returns `true` if a waiter was woken. `false` means no tool was
    /// blocked on it locally — e.g. the worker restarted and the
    /// in-flight tool future was dropped, or the resolution targets a
    /// `schedule` needs-attention nudge that nobody awaits. The DB row has
    /// already been updated by the caller regardless.
    pub fn resolve(&self, interrupt_id: Uuid, response: ResolveResponse) -> bool {
        let Some(tx) = lock_or_recover(&self.waiters).remove(&interrupt_id) else {
            return false;
        };
        tx.send(InterruptOutcome::Resolved(response)).is_ok()
    }

    #[cfg(test)]
    pub fn has_waiter(&self, interrupt_id: Uuid) -> bool {
        lock_or_recover(&self.waiters).contains_key(&interrupt_id)
    }

    pub async fn park(&self, interrupt_id: Uuid) -> bool {
        let parked = self
            .db
            .as_ref()
            .map(|db| async move { db.park_interrupt(interrupt_id).await.ok() });
        let parked = match parked {
            Some(parked) => parked.await.unwrap_or(false),
            None => false,
        };
        let Some(tx) = lock_or_recover(&self.waiters).remove(&interrupt_id) else {
            return parked;
        };
        let _ = tx.send(InterruptOutcome::Parked);
        true
    }

    pub async fn park_all_registered(&self) -> usize {
        let interrupt_ids = {
            let guard = lock_or_recover(&self.waiters);
            guard.keys().copied().collect::<Vec<_>>()
        };
        let mut count = 0;
        for interrupt_id in interrupt_ids {
            if self.park(interrupt_id).await {
                count += 1;
            }
        }
        count
    }
}

/// Guard returned by [`InterruptHub::register`]. Awaiting it (via
/// [`Self::wait`]) blocks until [`InterruptHub::resolve`] fires for this
/// id; dropping it without resolving removes the registry entry so no
/// stale sender lingers.
pub struct PendingInterrupt<'a> {
    hub: &'a InterruptHub,
    interrupt_id: Uuid,
    /// `Option` so [`Self::wait`] can take the receiver out of `self`
    /// without fighting the `Drop` guard (a `Drop` type can't be moved
    /// out of field-by-field).
    rx: Option<oneshot::Receiver<InterruptOutcome>>,
}

impl PendingInterrupt<'_> {
    /// Block until resolved or parked. A closed wakeup channel is treated
    /// as parked: teardown must never auto-answer or auto-cancel a row.
    pub async fn wait(mut self) -> InterruptOutcome {
        let rx = self.rx.take().expect("wait called once");
        match rx.await {
            Ok(outcome) => outcome,
            Err(_) => InterruptOutcome::Parked,
        }
    }
}

impl Drop for PendingInterrupt<'_> {
    fn drop(&mut self) {
        // Idempotent: `resolve`/`park` already removed it on the happy path.
        let _ = lock_or_recover(&self.hub.waiters).remove(&self.interrupt_id);
    }
}

/// The selected option id from a resolved single-select interrupt
/// (unwrapping a one-question `Batch`); `Cancel` / other shapes → `None`.
pub fn selected_id_of(resp: &ResolveResponse) -> Option<String> {
    match resp {
        ResolveResponse::Single { selected_id } => Some(selected_id.clone()),
        ResolveResponse::Batch { responses } => match responses.first() {
            Some(ResolveResponse::Single { selected_id }) => Some(selected_id.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// The free-text answer from a resolved free-text interrupt (unwrapping a
/// one-question `Batch`); `Cancel` / other shapes → `None`.
pub fn freetext_of(resp: &ResolveResponse) -> Option<String> {
    match resp {
        ResolveResponse::Freetext { text } => Some(text.clone()),
        ResolveResponse::Batch { responses } => match responses.first() {
            Some(ResolveResponse::Freetext { text }) => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Persist → register → emit → wait: raise an interrupt with `set` and
/// block until the user answers (or dismisses). On a DB failure (can't
/// persist) returns [`ResolveResponse::Cancel`] so the caller treats it as
/// a dismissal rather than hanging. `log_label` prefixes the warn on that
/// failure. Shared by the driver and in-turn raise wrappers.
pub async fn raise_and_wait(
    db: &crate::db::Db,
    interrupts: &InterruptHub,
    session_id: Uuid,
    agent: &str,
    description: &str,
    set: InterruptQuestionSet,
    log_label: &str,
) -> InterruptOutcome {
    if let Some((_interrupt_id, response)) =
        take_matching_pre_resolved_interrupt(agent, description, &set)
    {
        return InterruptOutcome::Resolved(response);
    }
    let payload = current_interrupt_park_payload();
    let interrupt_id = match db
        .raise_interrupt_questions_with_payload(
            session_id,
            agent,
            description,
            &set,
            payload.as_ref(),
        )
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, "{log_label}: raising interrupt failed");
            return InterruptOutcome::Resolved(ResolveResponse::Cancel);
        }
    };
    let pending = interrupts.register(interrupt_id);
    interrupts
        .emit_raised(session_id, interrupt_id, agent, description, set)
        .await;
    pending.wait().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    use crate::daemon::proto::{InterruptOption, InterruptQuestion};
    use crate::redact::RedactionTable;

    fn question_set() -> InterruptQuestionSet {
        InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Continue?".into(),
                options: vec![InterruptOption {
                    id: "yes".into(),
                    label: "Yes".into(),
                    description: None,
                    secondary: false,
                }],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        }
    }

    fn attached_hub(
        db: crate::db::Db,
        session_id: Uuid,
    ) -> (InterruptHub, crate::daemon::EventReceiver) {
        let (events, receiver) = tokio::sync::broadcast::channel(16);
        let redaction = Arc::new(RwLock::new(Arc::new(RedactionTable::empty())));
        (
            InterruptHub::new(
                events,
                redaction,
                Arc::new(AtomicUsize::new(1)),
                db,
                session_id,
            ),
            receiver,
        )
    }

    #[tokio::test]
    async fn resolve_wakes_a_registered_waiter() {
        let hub = InterruptHub::detached();
        let id = Uuid::new_v4();
        let pending = hub.register(id);
        assert!(hub.resolve(
            id,
            ResolveResponse::Single {
                selected_id: "y".into(),
            }
        ));
        let got = pending.wait().await;
        assert!(
            matches!(got, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "y")
        );
    }

    #[test]
    fn resolve_unknown_id_returns_false() {
        let hub = InterruptHub::detached();
        assert!(!hub.resolve(Uuid::new_v4(), ResolveResponse::Cancel));
    }

    #[test]
    fn dropping_pending_clears_the_registry() {
        let hub = InterruptHub::detached();
        let id = Uuid::new_v4();
        let pending = hub.register(id);
        drop(pending);
        // No waiter remains, so a late resolve finds nothing.
        assert!(!hub.resolve(id, ResolveResponse::Cancel));
    }

    #[tokio::test]
    async fn poisoned_waiter_mutex_recovers_without_panicking() {
        let hub = InterruptHub::detached();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = hub.waiters.lock().unwrap();
            panic!("poison waiter mutex");
        }));

        let id = Uuid::new_v4();
        let pending = hub.register(id);
        assert!(hub.resolve(id, ResolveResponse::Cancel));
        assert!(matches!(
            pending.wait().await,
            InterruptOutcome::Resolved(ResolveResponse::Cancel)
        ));
    }

    #[tokio::test]
    async fn dropped_sender_resolves_to_parked() {
        // Worker teardown: the registry is cleared (sender dropped)
        // while a tool is still awaiting. `wait` must yield `Parked`.
        let hub = InterruptHub::detached();
        let id = Uuid::new_v4();
        let pending = hub.register(id);
        lock_or_recover(&hub.waiters).clear();
        assert!(matches!(pending.wait().await, InterruptOutcome::Parked));
    }

    #[tokio::test]
    async fn explicit_park_wakes_waiter_as_parked() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let set = question_set();
        let id = db
            .raise_interrupt_questions(session.session_id, "a", "first", &set)
            .await
            .unwrap();
        let pending = hub.register(id);

        assert!(hub.park(id).await);
        assert!(matches!(pending.wait().await, InterruptOutcome::Parked));
        assert_eq!(
            db.get_interrupt(id).await.unwrap().unwrap().state,
            crate::db::needs_attention::InterruptState::Parked
        );
    }

    #[tokio::test]
    async fn interrupt_replay_answer_requires_matching_id() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let hub = Arc::new(hub);
        let resolver_db = db.clone();
        let resolver_hub = hub.clone();
        let session_id = session.session_id;
        tokio::spawn(async move {
            loop {
                if let Some(row) = resolver_db
                    .list_open_interrupts(session_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                {
                    resolver_db
                        .resolve_interrupt(
                            row.interrupt_id,
                            &ResolveResponse::Single {
                                selected_id: "first-live".into(),
                            },
                        )
                        .await
                        .unwrap();
                    assert!(resolver_hub.resolve(
                        row.interrupt_id,
                        ResolveResponse::Single {
                            selected_id: "first-live".into(),
                        }
                    ));
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });

        let stored_id = Uuid::new_v4();
        let wrong_id = Uuid::new_v4();
        let (first, second) = with_pre_resolved_interrupt_question(
            stored_id,
            ResolveResponse::Single {
                selected_id: "second-stored".into(),
            },
            PreResolvedInterruptQuestion {
                agent: "builder".into(),
                description: "second".into(),
                questions: question_set(),
                occurrence: 1,
            },
            async {
                assert!(
                    take_pre_resolved_interrupt(wrong_id).is_none(),
                    "a different interrupt id must not consume the stored answer"
                );
                let first = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "first",
                    question_set(),
                    "test",
                )
                .await;
                assert!(
                    pre_resolved_interrupt_pending(),
                    "the non-matching live raise must leave the stored answer available"
                );
                let second = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "second",
                    question_set(),
                    "test",
                )
                .await;
                (first, second)
            },
        )
        .await;

        assert!(
            matches!(first, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "first-live")
        );
        assert!(
            matches!(second, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "second-stored")
        );
        assert_eq!(
            db.list_open_interrupts(session.session_id)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn interrupt_replay_multiple_parked_answers_keyed_by_id() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let hub = Arc::new(hub);
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();

        let (second, first) = with_pre_resolved_interrupts(
            vec![
                PreResolvedInterrupt {
                    interrupt_id: first_id,
                    response: ResolveResponse::Single {
                        selected_id: "first-stored".into(),
                    },
                    question: Some(PreResolvedInterruptQuestion {
                        agent: "builder".into(),
                        description: "first".into(),
                        questions: question_set(),
                        occurrence: 1,
                    }),
                },
                PreResolvedInterrupt {
                    interrupt_id: second_id,
                    response: ResolveResponse::Single {
                        selected_id: "second-stored".into(),
                    },
                    question: Some(PreResolvedInterruptQuestion {
                        agent: "builder".into(),
                        description: "second".into(),
                        questions: question_set(),
                        occurrence: 1,
                    }),
                },
            ],
            async {
                let second = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "second",
                    question_set(),
                    "test",
                )
                .await;
                let first = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "first",
                    question_set(),
                    "test",
                )
                .await;
                (second, first)
            },
        )
        .await;

        assert!(
            matches!(second, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "second-stored")
        );
        assert!(
            matches!(first, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "first-stored")
        );
        assert_eq!(
            db.list_open_interrupts(session.session_id)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn interrupt_replay_duplicate_prompt_shape_uses_persisted_occurrence() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let hub = Arc::new(hub);
        let resolver_db = db.clone();
        let resolver_hub = hub.clone();
        let session_id = session.session_id;
        tokio::spawn(async move {
            loop {
                if let Some(row) = resolver_db
                    .list_open_interrupts(session_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                {
                    let response = ResolveResponse::Single {
                        selected_id: "first-live".into(),
                    };
                    resolver_db
                        .resolve_interrupt(row.interrupt_id, &response)
                        .await
                        .unwrap();
                    assert!(resolver_hub.resolve(row.interrupt_id, response));
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });

        let stored_id = Uuid::new_v4();
        let (first, second) = with_pre_resolved_interrupt_question(
            stored_id,
            ResolveResponse::Single {
                selected_id: "second-stored".into(),
            },
            PreResolvedInterruptQuestion {
                agent: "builder".into(),
                description: "same prompt".into(),
                questions: question_set(),
                occurrence: 2,
            },
            async {
                let first = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "same prompt",
                    question_set(),
                    "test",
                )
                .await;
                assert!(
                    pre_resolved_interrupt_pending(),
                    "first identical raise must not consume the second occurrence answer"
                );
                let second = raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "same prompt",
                    question_set(),
                    "test",
                )
                .await;
                (first, second)
            },
        )
        .await;

        assert!(
            matches!(first, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "first-live")
        );
        assert!(
            matches!(second, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "second-stored")
        );
    }

    #[tokio::test]
    async fn interrupt_replay_unconsumed_answer_discarded() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let hub = Arc::new(hub);
        let resolver_db = db.clone();
        let resolver_hub = hub.clone();
        let session_id = session.session_id;
        tokio::spawn(async move {
            loop {
                if let Some(row) = resolver_db
                    .list_open_interrupts(session_id)
                    .await
                    .unwrap()
                    .into_iter()
                    .next()
                {
                    let response = ResolveResponse::Single {
                        selected_id: "live".into(),
                    };
                    resolver_db
                        .resolve_interrupt(row.interrupt_id, &response)
                        .await
                        .unwrap();
                    assert!(resolver_hub.resolve(row.interrupt_id, response));
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        });

        let resolved = with_pre_resolved_interrupt_question(
            Uuid::new_v4(),
            ResolveResponse::Single {
                selected_id: "stale".into(),
            },
            PreResolvedInterruptQuestion {
                agent: "builder".into(),
                description: "never raised".into(),
                questions: question_set(),
                occurrence: 1,
            },
            async {
                raise_and_wait(
                    &db,
                    &hub,
                    session.session_id,
                    "builder",
                    "live prompt",
                    question_set(),
                    "test",
                )
                .await
            },
        )
        .await;

        assert!(
            matches!(resolved, InterruptOutcome::Resolved(ResolveResponse::Single { selected_id }) if selected_id == "live")
        );
        assert_eq!(
            db.list_open_interrupts(session.session_id)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn concurrent_raises_keep_fifo_active_and_rehydrate_with_counter() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, mut events) = attached_hub(db.clone(), session.session_id);
        let set = question_set();
        let first = db
            .raise_interrupt_questions(session.session_id, "a", "first", &set)
            .await
            .unwrap();
        hub.emit_raised(session.session_id, first, "a", "first", set.clone())
            .await;
        let second = db
            .raise_interrupt_questions(session.session_id, "b", "second", &set)
            .await
            .unwrap();
        hub.emit_raised(session.session_id, second, "b", "second", set)
            .await;

        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptRaised {
                interrupt_id,
                pending_count: 0,
                reason: proto::InterruptRaiseReason::Initial,
                ..
            }
                if interrupt_id == first
        ));
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptQueueChanged {
                active_interrupt_id: Some(interrupt_id), pending_count: 1, ..
            } if interrupt_id == first
        ));

        hub.emit_active_from_db().await;
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptQueueChanged {
                active_interrupt_id: Some(interrupt_id), pending_count: 1, ..
            } if interrupt_id == first
        ));
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptRaised {
                interrupt_id,
                pending_count: 1,
                reason: proto::InterruptRaiseReason::Advance,
                ..
            }
                if interrupt_id == first
        ));

        db.resolve_interrupt(first, &ResolveResponse::Cancel)
            .await
            .unwrap();
        hub.emit_active_from_db().await;
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptQueueChanged {
                active_interrupt_id: Some(interrupt_id), pending_count: 0, ..
            } if interrupt_id == second
        ));
        assert!(matches!(
            events.recv().await.unwrap().event,
            proto::Event::InterruptRaised {
                interrupt_id,
                pending_count: 0,
                reason: proto::InterruptRaiseReason::Advance,
                ..
            }
                if interrupt_id == second
        ));
    }

    #[tokio::test]
    async fn dropping_active_waiter_leaves_row_open_without_advancing() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, mut events) = attached_hub(db.clone(), session.session_id);
        let set = question_set();
        let first = db
            .raise_interrupt_questions(session.session_id, "a", "first", &set)
            .await
            .unwrap();
        let second = db
            .raise_interrupt_questions(session.session_id, "b", "second", &set)
            .await
            .unwrap();
        let pending = hub.register(first);

        drop(pending);

        let open = db.list_open_interrupts(session.session_id).await.unwrap();
        assert_eq!(open.len(), 2);
        assert_eq!(open[0].interrupt_id, first);
        assert_eq!(open[1].interrupt_id, second);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), events.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn park_all_registered_delegates_to_park_marks_row_and_wakes_waiter() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, _events) = attached_hub(db.clone(), session.session_id);
        let interrupt_id = db
            .raise_interrupt_questions(session.session_id, "a", "first", &question_set())
            .await
            .unwrap();
        let pending = hub.register(interrupt_id);

        assert_eq!(hub.park_all_registered().await, 1);

        assert!(matches!(pending.wait().await, InterruptOutcome::Parked));
        let open = db.list_open_interrupts(session.session_id).await.unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].interrupt_id, interrupt_id);
        assert_eq!(
            open[0].state,
            crate::db::needs_attention::InterruptState::Parked
        );
    }

    #[tokio::test]
    async fn dropping_queued_waiter_leaves_fifo_unchanged() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let (hub, mut events) = attached_hub(db.clone(), session.session_id);
        let set = question_set();
        let first = db
            .raise_interrupt_questions(session.session_id, "a", "first", &set)
            .await
            .unwrap();
        let second = db
            .raise_interrupt_questions(session.session_id, "b", "second", &set)
            .await
            .unwrap();
        let pending = hub.register(second);
        drop(pending);

        let open = db.list_open_interrupts(session.session_id).await.unwrap();
        assert_eq!(open.len(), 2);
        assert_eq!(open[0].interrupt_id, first);
        assert_eq!(open[1].interrupt_id, second);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), events.recv())
                .await
                .is_err()
        );
    }
}
