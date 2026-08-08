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
use super::identity::{SealedName, SealedProjectTrust, SealedRecordId, sealed_redaction_origin};

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

pub trait SealedRedactionSink: Send + Sync {
    /// Register `literal` under its canonical typed `origin`. Returning `Err`
    /// aborts the use — a literal is never used if it could not be redacted
    /// first.
    fn register_before_use(&self, literal: &SealedLiteral, origin: &str) -> anyhow::Result<()>;
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
        // The deadline is anchored here, not at the invocation: resolving the
        // literal and registering it for redaction are both O(literal length),
        // so they are literal-dependent timing too and must sit inside the
        // constant window.
        let started = std::time::Instant::now();
        let literal = self.resolve_literal(&claimed).await?;

        // ---- 5. redaction before use ------------------------------------
        let origin = sealed_redaction_origin(
            claimed.scope,
            SealedRecordId::parse(&claimed.record_id).map_err(|_| SealedUseDenied)?,
            u32::try_from(claimed.active_version).map_err(|_| SealedUseDenied)?,
            &SealedName::canonical(&claimed.name).map_err(|_| SealedUseDenied)?,
        );
        redaction
            .register_before_use(&literal, &origin)
            .map_err(|_| SealedUseDenied)?;

        // ---- 6. invoke, then answer at the declared fixed deadline ------
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
        // Duration is held to that by two halves that must both be present: a
        // hard deadline, so a slow or hanging action cannot push the response
        // out; and a wait to that same deadline, so a fast action cannot pull
        // it in. A floor alone gives only the second half, which is why 30ms
        // and 1s were still distinguishable before this change.
        let deadline = authorized.action.descriptor().response_after();
        let _ = tokio::time::timeout(
            deadline.saturating_sub(started.elapsed()),
            authorized
                .action
                .invoke(literal.handle(), &authorized.params),
        )
        .await;
        drop(literal);

        // Wait out the remainder. Together with the timeout above, every call
        // to this action occupies the same wall time.
        //
        // Residual, stated plainly: the host scheduler can still add jitter,
        // and an action's *side effect* on a fixed destination remains visible
        // to whoever watches that destination. Neither is a function of the
        // literal that the caller controls. Closing the second needs an egress
        // proxy, which belongs to `sealed-value-owner-management`.
        if let Some(remaining) = deadline.checked_sub(started.elapsed()) {
            tokio::time::sleep(remaining).await;
        }

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
            SealedScopeKind::Session => self
                .db
                // The claimed version, not just the record id: a rotation that
                // lands between claim and read must deny, never substitute.
                .sealed_session_literal_for_action(record.record_id.clone(), record.active_version)
                .await
                .map_err(|_| SealedUseDenied)?
                .map(SealedLiteral::new)
                .ok_or(SealedUseDenied),
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

impl SealedRedactionSink for RecordingRedactionSink {
    fn register_before_use(&self, _literal: &SealedLiteral, origin: &str) -> anyhow::Result<()> {
        self.origins
            .lock()
            .expect("sink mutex")
            .push(origin.to_string());
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

impl SealedRedactionSink for SessionRedactionSink {
    fn register_before_use(&self, literal: &SealedLiteral, origin: &str) -> anyhow::Result<()> {
        // Fail **closed**. A detached hub owns no redaction table, so
        // `seal_redaction_at_origin` returns `Ok(None)` having registered
        // nothing. Treating that as success would hand the literal to an
        // action with egress unscrubbed — exactly the stored-but-unredacted
        // window this ordering exists to prevent.
        let registered = self.interrupts.seal_redaction_at_origin(
            &self.session,
            literal.expose_for_redaction().to_string(),
            origin,
        )?;
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
