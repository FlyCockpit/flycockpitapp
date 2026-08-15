//! `use_sealed_value` — the sole use mechanism exposed to untrusted models,
//! built-in tools, and Monty tools.
//!
//! The pipeline is fixed and its order is the security property:
//!
//! 1. Read **metadata only** — the record row, the exact grant row, and (for
//!    Global scope) the Owner's project grant.
//! 2. [`authorize_sealed_use`] decides from that metadata. It performs no I/O,
//!    so a denial provably costs zero secret reads.
//! 3. Claim the grant with a deterministic compare-and-swap. The loser of a
//!    race performs no lookup and no outbound action.
//! 4. Only now resolve the literal.
//! 5. Register redaction **before** the literal is used, preserving
//!    redaction-before-use.
//! 6. Invoke the closed host action, project its result through the declared
//!    safe schema, and refuse anything secret-derived.
//!
//! The return value is the descriptor's **fixed** completion, delivered at the
//! descriptor's **fixed** deadline. The action cannot choose either, cannot
//! fail visibly, and cannot vary either with the literal, so the response
//! carries zero bits. Every pre-invocation failure is the same content-free
//! [`SealedUseDenied`], and denial is decided before any literal is read, so
//! it too is literal-independent.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cockpit_db::db::Db;
use cockpit_db::db::sealed_scope::{SealedClaimedUse, SealedScopeKind};

use super::action::{SealedActionRegistry, SealedActionResult};
use super::compartment::{SealedCompartment, SealedCompartmentKey, SealedLiteral};
use super::grant::{
    SealedAuthorizationInputs, SealedUseContext, SealedUseDenied, UseSealedValueRequest,
    authorize_sealed_use, sealed_grant_selector,
};
use super::identity::{SealedName, SealedProjectTrust, SealedRecordId, SealedRedactionIdentity};

/// Where a resolved literal is registered for redaction before it is used.
///
/// This is a required argument of [`SealedRuntime::use_sealed_value`], not an
/// option: there is no code path that resolves a literal without first handing
/// it to a sink. That is how redaction-before-use survives this feature.
/// Re-reads the canonical project's live trust at the moment of use.
///
/// Authorization reads trust once, but a use spans an authorization, a claim,
/// and a literal read. Owner revocation of workspace trust in that window must
/// deny, so the value is re-read at the point of raw-literal release and
/// compared with the one it was authorised under.
#[async_trait::async_trait]
pub trait SealedProjectTrustSource: Send + Sync {
    /// The project's trust right now. An error denies, fail-closed.
    async fn current_trust(&self) -> anyhow::Result<SealedProjectTrust>;
}

/// A fixed trust value, for tests and for callers that have already pinned it.
#[derive(Debug, Clone, Copy)]
pub struct FixedProjectTrust(pub SealedProjectTrust);

#[async_trait::async_trait]
impl SealedProjectTrustSource for FixedProjectTrust {
    async fn current_trust(&self) -> anyhow::Result<SealedProjectTrust> {
        Ok(self.0)
    }
}

#[async_trait::async_trait]
pub trait SealedRedactionSink: Send + Sync {
    /// Register `literal` under its canonical typed `identity`. Classification
    /// is carried by the typed [`SealedRedactionIdentity`] end-to-end — the sink
    /// never serializes to and reparses a diagnostic origin string to recover
    /// sealedness. Returning `Err` aborts the use — a literal is never used if it
    /// could not be redacted first.
    ///
    /// Async because the production sink journals the adoption into protected
    /// redaction history (an async key load + AEAD prepare, then a DB
    /// transaction) atomically with registering the literal.
    async fn register_before_use(
        &self,
        literal: &SealedLiteral,
        identity: &SealedRedactionIdentity,
    ) -> anyhow::Result<()>;
}

/// Upper bound on sealed-action threads alive at once (running **or**
/// abandoned-past-deadline). A CPU-bound or infinite untrusted action cannot be
/// killed in safe Rust, so an abandoned one keeps a dedicated thread + a core
/// until its blocking call returns; this cap bounds how many such runaways can
/// accumulate, so a burst of adversarial spinners cannot exhaust process
/// threads. Sealed use is Owner-gated and rare, so a small cap is generous.
const MAX_INFLIGHT_SEALED_ACTIONS: usize = 32;

/// Count of live sealed-action threads, gated by [`MAX_INFLIGHT_SEALED_ACTIONS`].
static INFLIGHT_SEALED_ACTIONS: AtomicUsize = AtomicUsize::new(0);

/// An RAII slot in the sealed-action thread budget.
///
/// Acquired before a dedicated action thread is spawned and moved *into* that
/// thread, so the slot is held for the thread's entire life — including after
/// the caller abandons it at the deadline — and released only when the action's
/// blocking call finally returns and the thread exits. That is exactly the
/// window during which a runaway action ties up a thread, so the count reflects
/// real resource pressure rather than merely in-flight calls.
struct SealedActionSlot;

impl SealedActionSlot {
    /// Take a slot, or `None` if the budget is full. Never blocks: waiting for a
    /// slot would make one call's completion depend on other calls' abandoned
    /// spinners, reopening the cross-call timing channel this cap exists to
    /// close. A full budget instead fails the use closed (see the call site).
    fn try_acquire() -> Option<Self> {
        let mut current = INFLIGHT_SEALED_ACTIONS.load(Ordering::Acquire);
        loop {
            if current >= MAX_INFLIGHT_SEALED_ACTIONS {
                return None;
            }
            match INFLIGHT_SEALED_ACTIONS.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for SealedActionSlot {
    fn drop(&mut self) {
        INFLIGHT_SEALED_ACTIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The runtime half of sealed values: closed registry + durable stores.
pub struct SealedRuntime {
    db: Db,
    compartment: SealedCompartment,
    registry: Arc<SealedActionRegistry>,
    /// Counts literal resolutions. This is an observability seam that makes
    /// "zero secret reads on denial" a checkable property rather than a claim.
    literal_reads: Arc<AtomicUsize>,
}

impl SealedRuntime {
    pub fn new(
        db: Db,
        compartment: SealedCompartment,
        registry: Arc<SealedActionRegistry>,
    ) -> Self {
        Self {
            db,
            compartment,
            registry,
            literal_reads: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn compartment(&self) -> &SealedCompartment {
        &self.compartment
    }

    pub fn registry(&self) -> &Arc<SealedActionRegistry> {
        &self.registry
    }

    /// How many literals this runtime has resolved. Every denial branch must
    /// leave this unchanged.
    pub fn literal_reads(&self) -> usize {
        self.literal_reads.load(Ordering::SeqCst)
    }

    /// The sole use mechanism. See the module docs for the fixed ordering.
    pub async fn use_sealed_value(
        &self,
        request: &UseSealedValueRequest,
        ctx: &SealedUseContext,
        redaction: &dyn SealedRedactionSink,
        trust: &dyn SealedProjectTrustSource,
    ) -> Result<SealedActionResult, SealedUseDenied> {
        // ---- 1. metadata only -------------------------------------------
        let record = self
            .db
            .sealed_value_record(request.sealed_value_id.to_string())
            .await
            .map_err(|_| SealedUseDenied)?;
        let grant = self
            .db
            .sealed_action_grant_for(sealed_grant_selector(request, ctx))
            .await
            .map_err(|_| SealedUseDenied)?;
        let global_reaches_project = match record.as_ref() {
            Some(row) if row.scope == SealedScopeKind::Global => self
                .db
                .sealed_global_reaches_project(
                    row.record_id.clone(),
                    ctx.project_key.as_str().to_string(),
                )
                .await
                .map_err(|_| SealedUseDenied)?,
            _ => true,
        };

        // ---- 2. authorize, from metadata alone --------------------------
        let authorized = authorize_sealed_use(
            request,
            ctx,
            SealedAuthorizationInputs {
                record,
                grant,
                global_reaches_project,
            },
            &self.registry,
        )?;

        // ---- 3. deterministic compare-and-swap ownership ----------------
        // The claim is authoritative: it re-checks revocation, expiry, and the
        // record's live lifecycle and version inside the writer transaction,
        // and hands back the locator read in that same transaction. The stale
        // row from step 1 is never used to resolve anything.
        let Some(claimed) = self
            .db
            .claim_sealed_action_grant(
                authorized.grant().grant_id.clone(),
                authorized.grant().use_epoch,
                ctx.now_ms,
            )
            .await
            .map_err(|_| SealedUseDenied)?
        else {
            // Loser of the race, or a record deleted or rotated since it was
            // read: no lookup, no outbound action.
            return Err(SealedUseDenied);
        };

        // ---- 3b. re-check project trust at the point of release ----------
        // `ctx.project_trust` is the value authorization ran against, which is
        // by then a snapshot. Trust can be withdrawn between authorization and
        // this point, and a raw literal must never be released against a
        // project that is no longer trusted. Re-read, and require it to still
        // be trusted *and* to match what was authorised.
        let live_trust = trust.current_trust().await.map_err(|_| SealedUseDenied)?;
        if !live_trust.is_trusted() || live_trust != ctx.project_trust {
            return Err(SealedUseDenied);
        }

        // ---- 4. resolve the literal (the single secret read) ------------
        let literal = self.resolve_literal(&claimed).await?;

        // ---- 5. redaction before use ------------------------------------
        // Build the TYPED sealed identity and register it directly. Sealedness
        // travels as typed state from here to the redaction table; nothing on
        // this path serializes to a `sealed:<id>` string and reparses it to
        // reconstruct classification (the round-trip the settled decision
        // forbids). The diagnostic origin string is derived from this identity
        // only for `cockpit debug redact` display, never for classification.
        let identity = SealedRedactionIdentity {
            scope: claimed.scope,
            record_id: Some(
                SealedRecordId::parse(&claimed.record_id).map_err(|_| SealedUseDenied)?,
            ),
            name: SealedName::canonical(&claimed.name).map_err(|_| SealedUseDenied)?,
            version: u32::try_from(claimed.active_version).map_err(|_| SealedUseDenied)?,
        };
        redaction
            .register_before_use(&literal, &identity)
            .await
            .map_err(|_| SealedUseDenied)?;

        // ---- 6. invoke, then answer at the declared fixed deadline ------
        // The fixed-response window is anchored HERE, after resolution and
        // registration, not before them. Registration now awaits an async key
        // load, an AEAD encrypt, and a DB transaction (the adoption is journaled
        // into protected redaction history atomically with the table persist).
        // That work is variable and dominated by DB latency, so folding it into
        // the timed window would let it consume — and overrun — the descriptor's
        // `response_after` budget: it would eat the action's share of the window
        // and push the response out past the fixed deadline by however long the
        // transaction took, leaking secret-adoption/DB timing and breaking the
        // fixed-deadline contract. Anchoring after registration keeps
        // registration off the caller-visible window: the response lands a fixed
        // `response_after` after the anchor below regardless of key-load,
        // encrypt, or DB time. Registration still precedes any use of the
        // literal, so redaction-before-use is unchanged.
        //
        // Residual: resolution and registration are O(literal length) and now
        // sit before the anchor, so their duration is not padded away. This is
        // the same class of pre-window variability as the metadata reads and the
        // claim above (all decided before the window), and it is our own code,
        // not the untrusted action; the padding's purpose — bounding the action
        // the caller can adversarially time to encode literal bits — is intact.
        // The action's return value — including its error — is discarded
        // without inspection. It cannot select what the caller sees, so it
        // cannot encode a bit of the literal in the response or in the
        // difference between success and failure.
        //
        // The invariant this relies on, stated the way the custody one is:
        //
        //   For a use that reaches invocation, the caller-visible response
        //   AND the caller-visible duration are both pure functions of the
        //   compiled descriptor. Neither takes the literal, the parameters,
        //   nor the action's behaviour as an input.
        //
        // Duration is held to that by a HARD, non-cooperative deadline. A prior
        // implementation wrapped the action in `tokio::time::timeout` and padded
        // with a floor `sleep`. That timeout is *cooperative*: it shares the
        // caller's async task, so an action that never yields — a
        // `std::thread::sleep`, a CPU-bound loop, any non-`.await`ing work —
        // blocks the very task the timeout lives on. The timeout branch is then
        // never polled, the action returns late, and the extra wall-clock time
        // encodes a bit of the literal (branch on a literal bit, then block),
        // defeating the padding. A floor alone is the second half only, which is
        // why 30ms and 1s were still distinguishable before this change.
        //
        // Executor/runtime choice (NO new dependency — a `std::thread`, a
        // `std::sync::mpsc` start gate, a `tokio::sync::oneshot`, and an
        // `AtomicUsize`, all already available):
        // run the untrusted action on a DEDICATED `std::thread`, OFF both the
        // caller's async task and Tokio's shared blocking pool, then have the
        // caller race the action's completion signal against
        // `sleep_until(deadline)`. Because the action no longer runs on the
        // caller's task, the deadline timer is serviced and CAN win even while
        // the action is still blocking — enforcement stops depending on the
        // action cooperating. A dedicated thread (rather than
        // `spawn_blocking`) means a runaway action cannot consume the shared
        // blocking pool the rest of the app depends on. The action's async
        // `invoke` future is driven to completion inside the thread on a private
        // current-thread runtime, independent of the caller's runtime flavour,
        // which also supplies the timer/IO context an action may need.
        let deadline = authorized.action.descriptor().response_after();

        // Bound the number of concurrently-live action threads. Fail closed if
        // the budget is full: this denial depends on OTHER calls' abandoned
        // spinners, never on THIS literal, so it leaks no bit — it is the same
        // content-free denial as every other, and the literal is dropped
        // (zeroized) here without being handed to any action.
        let Some(slot) = SealedActionSlot::try_acquire() else {
            drop(literal);
            return Err(SealedUseDenied);
        };

        let action = Arc::clone(&authorized.action);
        let params = authorized.params.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        // Start gate. `std::thread::spawn` starts the thread running at once, so
        // without this the action could begin its literal-dependent work in the
        // gap between spawn and the anchor below and contend for CPU/scheduler
        // with the caller — making the pre-anchor interval literal-dependent and
        // caller-visible. The thread parks on this gate and does NO work (not
        // even building its runtime) until the caller opens it, immediately
        // after anchoring. The rendezvous is literal-independent: it happens
        // before the action runs. A plain `std::sync::mpsc` parks the thread
        // without needing the private runtime (which is built only after the
        // gate opens), so the wait needs no async context.
        let (start_tx, start_rx) = std::sync::mpsc::channel::<()>();
        // Move the owned literal AND the budget slot onto the dedicated thread.
        // The literal is a self-zeroizing `SealedLiteral`: whenever the action
        // returns — before OR after the deadline — the closure drops it and its
        // buffer is wiped, and the slot is released, so abandonment does not
        // change the zeroization guarantee, only its timing. We never join the
        // thread, so an abandoned action is detached and runs to completion on
        // its own thread. If the OS refuses the thread, the closure (and thus
        // the literal + slot) drops immediately, `done_tx` drops unsent, and the
        // race below still pads to the fixed deadline — fail-closed, no leak.
        let spawned = std::thread::Builder::new()
            .name("sealed-action".to_string())
            .spawn(move || {
                let _slot = slot;
                // Park until the caller opens the gate (strictly after the
                // anchor). Do no action work — not even build the runtime —
                // before this. A dropped `start_tx` (caller gone) also releases
                // this to a clean shutdown that still zeroizes the literal.
                let _ = start_rx.recv();
                if let Ok(local) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    local.block_on(async move {
                        let _ = action.invoke(literal.handle(), &params).await;
                    });
                }
                // Signal completion. If the action panicked, `done_tx` drops
                // without sending; the race below treats that identically to a
                // normal finish (it still only pads to the fixed deadline), so a
                // panic cannot leak a bit either.
                let _ = done_tx.send(());
            });
        // Detach: the `JoinHandle` is dropped, never joined, so the action is
        // abandoned rather than awaited when the deadline wins.
        drop(spawned);

        // Anchor the padded window HERE — after every fallible/variable setup
        // step above (slot acquire, params clone, channel allocation, thread
        // spawn) and BEFORE the action is allowed to start. Thread-spawn latency
        // stays outside the window; opening the gate on the next line lets the
        // action begin only after this anchor, so the window contains ALL of the
        // action's literal-dependent execution and NONE of it precedes the
        // anchor. The only thing between this anchor and the race is opening the
        // gate — a single literal-independent send.
        let deadline_at = tokio::time::Instant::now() + deadline;
        // Open the start gate: the action begins now, strictly after the anchor.
        let _ = start_tx.send(());

        // Race the action's completion against the fixed deadline. The deadline
        // branch can win even against a non-yielding action, because the action
        // is on another thread — this is the whole point.
        tokio::select! {
            _ = done_rx => {
                // Well-behaved: the action finished at or before the deadline.
                // Keep the floor so the response still emerges at exactly
                // `response_after` — a fast action must not pull the response in.
                tokio::time::sleep_until(deadline_at).await;
            }
            () = tokio::time::sleep_until(deadline_at) => {
                // Deadline won while the action was still blocking. Return the
                // constant completion NOW and do not await the action.
                //
                // Residual (unkillable in safe Rust): a CPU-bound or infinite
                // untrusted action holds its one dedicated thread + one core
                // until its blocking call returns; it is detached, not
                // cancelled. `MAX_INFLIGHT_SEALED_ACTIONS` bounds how many such
                // runaways can accumulate so they cannot exhaust process threads
                // or starve the whole app, and running off the shared blocking
                // pool keeps the blast radius off unrelated Tokio work. The
                // SINGLE-call caller-visible completion time is unaffected: it is
                // exactly `response_after` regardless of the action. Abandoning
                // exposes NO additional literal material — the action already
                // held it — it only removes the wall-clock channel; the literal
                // still zeroizes when the action thread finishes.
            }
        }

        // The caller-visible completion time is now `deadline_at` on BOTH paths
        // (padded-up on the fast path, cut-off on the overrun path), a constant
        // function of `response_after` alone — never of the action's runtime or
        // the literal. The response body is the descriptor's fixed completion,
        // byte-identical on every path.
        //
        // Residual, stated plainly: the host scheduler can still add jitter,
        // and an action's *side effect* on a fixed destination remains visible
        // to whoever watches that destination. Neither is a function of the
        // literal that the caller controls. Closing the second needs an egress
        // proxy, which belongs to `sealed-value-owner-management`.
        Ok(authorized.action.descriptor().completion_response())
    }

    /// Resolve from the *claimed* record only.
    ///
    /// Taking [`SealedClaimedUse`] rather than the authorization result is the
    /// point: the pre-authorization row is not in scope here, so a superseded
    /// or deleted locator is unpassable rather than merely unused.
    async fn resolve_literal(
        &self,
        record: &SealedClaimedUse,
    ) -> Result<SealedLiteral, SealedUseDenied> {
        self.literal_reads.fetch_add(1, Ordering::SeqCst);
        match record.scope {
            SealedScopeKind::Session => {
                let Some(vault) = self.compartment.vault() else {
                    return Err(SealedUseDenied);
                };
                // Version fence stays on the claimed record. Decrypt only after
                // claim; a stale grant is already rejected by the claim UPDATE.
                let item_id = crate::secure_key::session_sealed_item_id(
                    &record.scope_key,
                    &record.name,
                    record.active_version,
                );
                match vault.get_item(
                    cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                    &item_id,
                ) {
                    Ok(secret) => {
                        let text = String::from_utf8(secret.as_slice().to_vec())
                            .map_err(|_| SealedUseDenied)?;
                        Ok(SealedLiteral::new(text))
                    }
                    Err(_) => Err(SealedUseDenied),
                }
            }
            SealedScopeKind::Project | SealedScopeKind::Global => {
                let raw = record.compartment_key.as_deref().ok_or(SealedUseDenied)?;
                let key = SealedCompartmentKey::parse(raw).map_err(|_| SealedUseDenied)?;
                self.compartment
                    .get_exact(&key)
                    .map_err(|_| SealedUseDenied)?
                    .ok_or(SealedUseDenied)
            }
        }
    }
}

impl std::fmt::Debug for SealedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedRuntime")
            .field("compartment", &self.compartment)
            .field("registry", &self.registry)
            .finish()
    }
}

/// A sink that records registrations without owning a session, for tests and
/// for headless paths that have no live redaction table.
///
/// It still *requires* a registration to happen, so it cannot be used to skip
/// redaction-before-use — only to observe it.
#[derive(Debug, Default)]
pub struct RecordingRedactionSink {
    origins: std::sync::Mutex<Vec<String>>,
}

impl RecordingRedactionSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Origins registered so far, in order.
    pub fn origins(&self) -> Vec<String> {
        self.origins.lock().expect("sink mutex").clone()
    }
}

#[async_trait::async_trait]
impl SealedRedactionSink for RecordingRedactionSink {
    async fn register_before_use(
        &self,
        _literal: &SealedLiteral,
        identity: &SealedRedactionIdentity,
    ) -> anyhow::Result<()> {
        // Record the derived diagnostic origin string so existing observability
        // assertions still read the canonical origin. The string is derived FROM
        // the typed identity, never parsed back into classification.
        self.origins
            .lock()
            .expect("sink mutex")
            .push(identity.display_origin());
        Ok(())
    }
}

/// The production sink: folds the literal into the live session redaction
/// table and persists it, exactly as session sealed values already do.
pub struct SessionRedactionSink {
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    session: Arc<crate::session::Session>,
}

impl SessionRedactionSink {
    pub fn new(
        interrupts: Arc<crate::engine::interrupt::InterruptHub>,
        session: Arc<crate::session::Session>,
    ) -> Self {
        Self {
            interrupts,
            session,
        }
    }
}

#[async_trait::async_trait]
impl SealedRedactionSink for SessionRedactionSink {
    async fn register_before_use(
        &self,
        literal: &SealedLiteral,
        identity: &SealedRedactionIdentity,
    ) -> anyhow::Result<()> {
        // Fail **closed**. A detached hub owns no redaction table, so
        // `seal_redaction_with_identity` returns `Ok(None)` having registered
        // nothing. Treating that as success would hand the literal to an
        // action with egress unscrubbed — exactly the stored-but-unredacted
        // window this ordering exists to prevent. The typed identity is passed
        // straight through; no origin string is parsed to recover sealedness.
        let registered = self
            .interrupts
            .seal_redaction_with_identity(
                &self.session,
                literal.expose_for_redaction().to_string(),
                identity.clone(),
            )
            .await?;
        if registered.is_none() {
            anyhow::bail!("sealed value cannot be used without a live redaction table");
        }
        Ok(())
    }
}

impl std::fmt::Debug for SessionRedactionSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionRedactionSink")
    }
}
