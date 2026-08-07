//! The single authority coordinator.
//!
//! Every authority CAS, every permit acquisition, and every barrier drain goes
//! through this one object. That is the point: a check-then-mutate performed
//! *outside* the coordinator cannot be linearized against a concurrent
//! transfer, so it would be exactly the race this subsystem exists to remove.
//!
//! # Transfer barrier ordering
//!
//! ```text
//!   admits_subscope(effective authority)      <- base minus delegated exclusions
//!   capability probe (fail fast, zero state)  <- ScopedWritesUnsupported here
//!   Prepared          parent Active(g) -> Transferring(g+1)
//!   ordered acquisition, all-or-nothing:
//!       reserve execution-wide permit
//!       require Proven backend for the COMPLETE effective scope
//!       create containment
//!       prove membership / runtime ownership
//!       release user code                     <- first moment user code exists
//!   drain overlapping parent permits
//!   ParentExcluded    record exclusions, reissue parent token at g+1
//!   ChildActivated    child lease at g+2
//!   ... child runs ...
//!   ChildTerminal     invalidate child token
//!   await ProvenEmpty, resolve publication, release execution permit
//!   ParentRestored    parent -> g+3, fresh full-authority token
//!   Committed
//! ```
//!
//! Any failure before `release user code` unwinds to Active without ever
//! excluding the parent, creating a child record/token/event, or running user
//! code. Unwinding moves the generation *forward*; it never rewinds.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::db::Db;
use crate::db::write_scope_leases::{
    CasWriteScopeLease, CasWriteScopeTransfer, WriteScopeLeaseRow, WriteScopePermitRow,
    WriteScopeTransferRow,
};

use super::backend::{
    ExecutionMode, PublishOutcome, PublishRequest, ScopedWriteCapability, SharedScopedWriteBackend,
};
use super::containment::{ContainmentBarrier, ContainmentTicket, ProvenEmptyOutcome};
use super::events::{WriteScopeEvent, WriteScopeEventSink};
use super::permits::{MutationKind, PermitFootprint};
use super::scope::{CanonicalScope, EffectiveAuthority};
use super::types::{LeaseState, TokenCore, TransferPhase, WriteScopeError, WriteScopeToken};

/// The containment `operation_id` for a write-scope transfer.
///
/// **Derived, never supplied.** Recovery's only durable handle on a transfer
/// that crashed between `create` and the ownership attach is the transfer row
/// itself; the containment it may have spawned is reachable only if its
/// operation id is a pure function of the transfer id. Accepting a free-form
/// operation id would let the two disagree and make the containment
/// unfindable — which is exactly the crash window this closes.
pub fn write_scope_containment_operation_id(transfer_id: Uuid) -> String {
    format!("write-scope-{transfer_id}")
}

/// Proof that a transfer is durably `prepared`, and therefore that a
/// containment created for it will be findable by recovery.
///
/// # Why this exists
///
/// [`OwnershipRecorded`] cannot gate
/// [`super::containment::ContainmentBarrier::create`]: it carries the
/// `containment_id`, which does not exist until `create` has already returned.
/// Requiring it there is circular. So the chain starts one link earlier, at
/// the first thing that *is* durable — the Prepared transfer row.
///
/// `create` takes this witness **instead of** a free-form `operation_id`
/// string, and derives the operation id from it. Three properties fall out at
/// once: a containment cannot exist without a persisted transfer; its
/// operation id is derived from that transfer, so recovery can find it with no
/// schema change; and [`OwnershipRecorded`] can only be minted from *this*
/// witness plus the attach result, so the chain is enforced end to end rather
/// than at one site.
#[derive(Debug)]
pub struct OwnershipReserved {
    transfer_id: Uuid,
    session_id: Uuid,
}

impl OwnershipReserved {
    /// The only constructor. Private to `coordinator`, and takes the persisted
    /// transfer row rather than loose ids, so the witness cannot attest a
    /// transfer that was never written.
    fn from_prepared(row: &WriteScopeTransferRow) -> Self {
        Self {
            transfer_id: row.transfer_id,
            session_id: row.session_id,
        }
    }

    pub fn transfer_id(&self) -> Uuid {
        self.transfer_id
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// The derived containment operation id. Recovery recomputes this from the
    /// transfer row alone.
    pub fn containment_operation_id(&self) -> String {
        write_scope_containment_operation_id(self.transfer_id)
    }
}

/// Proof that a containment ticket and its execution permit are durably
/// recorded against a transfer.
///
/// # Why this shape
///
/// "Persist recoverable ownership before releasing user code" regressed twice
/// as a statement order, then a third time as a witness whose inner field was
/// `pub(crate)` — which any module in this crate could forge, so it documented
/// the invariant instead of enforcing it.
///
/// Now the fields are private and the only constructor is
/// [`Self::from_persisted`], which is private to this module and takes the
/// **row returned by the persist** as its argument. A witness therefore cannot
/// exist unless the write it attests actually happened. It also carries the
/// containment it attests, and
/// [`super::containment::ContainmentBarrier::prove_membership_and_release_user_code`]
/// takes nothing else — so a witness for one transfer cannot release another.
#[derive(Debug)]
pub struct OwnershipRecorded {
    transfer_id: Uuid,
    containment_id: Uuid,
    containment_generation: u64,
}

impl OwnershipRecorded {
    /// The only constructor. Private to `coordinator`, and derives every field
    /// from the persisted row rather than from the caller.
    ///
    /// It also consumes the [`OwnershipReserved`] that authorised `create`, so
    /// the two links cannot be minted independently: releasing user code
    /// requires proof of *both* the reservation that made the containment
    /// findable and the attach that made its ticket durable.
    fn from_reserved_and_persisted(
        reserved: &OwnershipReserved,
        row: &WriteScopeTransferRow,
    ) -> Result<Self, WriteScopeError> {
        if reserved.transfer_id != row.transfer_id {
            return Err(WriteScopeError::Internal(format!(
                "ownership reservation attests transfer {} but the persisted row is {}; \
                 refusing to release user code",
                reserved.transfer_id, row.transfer_id
            )));
        }
        let (Some(containment_id), Some(containment_generation)) =
            (row.containment_id, row.containment_generation)
        else {
            return Err(WriteScopeError::Internal(format!(
                "transfer {} was persisted without a containment ticket; refusing to release \
                 user code",
                row.transfer_id
            )));
        };
        Ok(Self {
            transfer_id: row.transfer_id,
            containment_id,
            containment_generation,
        })
    }

    pub fn transfer_id(&self) -> Uuid {
        self.transfer_id
    }

    pub fn containment_id(&self) -> Uuid {
        self.containment_id
    }

    pub fn containment_generation(&self) -> u64 {
        self.containment_generation
    }
}

/// Injectable wall clock so tests never sleep.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default()
    })
}

/// A request to delegate a strict sub-scope to a child.
#[derive(Debug, Clone)]
pub struct TransferRequest {
    pub parent_lease_id: Uuid,
    pub session_id: Uuid,
    /// The requested sub-scope, already resolved to a canonical path.
    pub sub_scope: CanonicalScope,
    pub child_owner_id: String,
    pub task_id: Option<String>,
    pub mode: ExecutionMode,
    // No `operation_id` here on purpose. It used to be a free-form string
    // passed straight to `ContainmentBarrier::create` and persisted nowhere —
    // so a containment created under it was unfindable by construction, which
    // is precisely why a crash between `create` and the ownership attach could
    // strand a live child. The containment operation id is now *derived* from
    // the transfer id (`write_scope_containment_operation_id`), so the durable
    // transfer row is always enough to find it.
    /// How the child is launched. Carried per-request because the containment
    /// barrier is a daemon-lifetime singleton.
    pub launch: super::containment::ExecutionLaunch,
    /// Highest ancestor the child's execution could rename/replace/redirect.
    /// Defaults to the sub-scope when the caller does not widen it.
    pub reachable_ancestor: Option<PathBuf>,
}

/// Everything a caller needs after a successful transfer.
#[derive(Debug)]
pub struct DelegationHandle {
    pub transfer_id: Uuid,
    pub child_token: WriteScopeToken,
    /// Replacement parent token issued at generation g+1.
    pub parent_token: WriteScopeToken,
    pub containment: ContainmentTicket,
    pub execution_permit_id: Uuid,
}

/// A held mutation permit. The effective path is re-resolved *after*
/// acquisition and the permit is held through the final syscall.
#[derive(Debug)]
pub struct MutationPermit {
    permit_id: Uuid,
    /// The path the caller named. Kept so the permit can be revalidated
    /// against a fresh resolution just before the syscall.
    requested: PathBuf,
    effective_target: PathBuf,
    footprint: PermitFootprint,
}

impl MutationPermit {
    pub fn permit_id(&self) -> Uuid {
        self.permit_id
    }

    /// The path as the caller named it.
    pub fn requested(&self) -> &Path {
        &self.requested
    }

    /// The path the syscall must use. Using the originally-requested path
    /// instead would reintroduce the check-then-mutate gap.
    pub fn effective_target(&self) -> &Path {
        &self.effective_target
    }

    pub fn footprint(&self) -> &PermitFootprint {
        &self.footprint
    }
}

/// Result of reconciling one durable row at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// Child is live inside a Proven populated containment: it keeps ownership.
    ChildResumedOwnership {
        transfer_id: Uuid,
        child_lease_id: Uuid,
    },
    /// Never started or terminal, and ProvenEmpty: the return advanced.
    ReturnAdvanced { transfer_id: Uuid },
    /// Terminal but not ProvenEmpty: authority stays with the child.
    RetainedNotProvenEmpty { transfer_id: Uuid, reason: String },
    /// Durable state does not match reality: authority stays denied.
    Denied { transfer_id: Uuid, reason: String },
    /// Already Committed; nothing to do.
    AlreadyCommitted { transfer_id: Uuid },
}

/// Every token ever issued for a lease, paired with the generation it was
/// issued at, so a generation bump can invalidate exactly the older ones.
type IssuedTokens = HashMap<Uuid, Vec<(u64, Arc<TokenCore>)>>;

/// The single write-authority coordinator.
pub struct WriteScopeCoordinator {
    db: Db,
    backend: SharedScopedWriteBackend,
    containment: Arc<dyn ContainmentBarrier>,
    events: Arc<dyn WriteScopeEventSink>,
    clock: Clock,
    /// Serializes every authority CAS + permit acquisition. Concurrent
    /// contenders linearize here and lose on the versioned CAS.
    serial: tokio::sync::Mutex<()>,
    /// All tokens ever issued per lease, so a generation bump can invalidate
    /// every older one.
    tokens: Mutex<IssuedTokens>,
    shutting_down: std::sync::atomic::AtomicBool,
}

impl WriteScopeCoordinator {
    pub fn new(
        db: Db,
        backend: SharedScopedWriteBackend,
        containment: Arc<dyn ContainmentBarrier>,
        events: Arc<dyn WriteScopeEventSink>,
        clock: Clock,
    ) -> Self {
        Self {
            db,
            backend,
            containment,
            events,
            clock,
            serial: tokio::sync::Mutex::new(()),
            tokens: Mutex::new(HashMap::new()),
            shutting_down: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The filesystem backend this coordinator enforces against.
    ///
    /// The dispatch-time refusal gate probes exactly this, so the fast gate and
    /// the durable transfer can never disagree about whether scoped writes are
    /// available.
    pub fn backend(&self) -> &SharedScopedWriteBackend {
        &self.backend
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    fn issue_token(&self, row: &WriteScopeLeaseRow) -> WriteScopeToken {
        let core = Arc::new(TokenCore::new());
        if let Ok(mut tokens) = self.tokens.lock() {
            let entry = tokens.entry(row.lease_id).or_default();
            // Every authority-changing transition invalidates every older
            // token. Doing it here means no caller can forget.
            for (generation, older) in entry.iter() {
                if *generation < row.generation {
                    older.invalidate();
                }
            }
            entry.push((row.generation, core.clone()));
        }
        WriteScopeToken {
            lease_id: row.lease_id,
            session_id: row.session_id,
            generation: row.generation,
            scope: CanonicalScope::from_canonical(row.scope_path.clone()),
            core,
        }
    }

    /// Invalidate every token for a lease, whatever its generation. Used at
    /// ChildTerminal, where the child must lose authority before return begins.
    fn invalidate_all_tokens(&self, lease_id: Uuid) {
        if let Ok(tokens) = self.tokens.lock()
            && let Some(entry) = tokens.get(&lease_id)
        {
            for (_, core) in entry {
                core.invalidate();
            }
        }
    }

    async fn lease(&self, lease_id: Uuid) -> Result<WriteScopeLeaseRow, WriteScopeError> {
        self.db
            .get_write_scope_lease(lease_id)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
            .ok_or(WriteScopeError::LeaseNotFound(lease_id))
    }

    async fn transfer(&self, transfer_id: Uuid) -> Result<WriteScopeTransferRow, WriteScopeError> {
        self.db
            .get_write_scope_transfer(transfer_id)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
            .ok_or(WriteScopeError::TransferNotFound(transfer_id))
    }

    /// Open the session's root write authority.
    pub async fn open_root_lease(
        &self,
        session_id: Uuid,
        owner_id: impl Into<String>,
        scope: CanonicalScope,
    ) -> Result<WriteScopeToken, WriteScopeError> {
        self.open_root_lease_locked(session_id, owner_id, scope)
            .await
    }

    /// Caller may or may not hold `serial`; opening a root lease touches no
    /// existing authority, so it does not require it.
    async fn open_root_lease_locked(
        &self,
        session_id: Uuid,
        owner_id: impl Into<String>,
        scope: CanonicalScope,
    ) -> Result<WriteScopeToken, WriteScopeError> {
        let now = self.now();
        let row = WriteScopeLeaseRow {
            lease_id: Uuid::new_v4(),
            parent_lease_id: None,
            session_id,
            task_id: None,
            scope_path: scope.path().display().to_string(),
            generation: 1,
            state: LeaseState::Active.as_str().into(),
            owner_id: owner_id.into(),
            version: 1,
            created_at_wall_ms: now,
            updated_at_wall_ms: now,
            released_at_wall_ms: None,
        };
        let row = self
            .db
            .insert_write_scope_lease(row)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        self.events.emit(WriteScopeEvent::LeaseOpened {
            lease_id: row.lease_id,
            generation: row.generation,
        });
        Ok(self.issue_token(&row))
    }

    /// The session's root lease id, if one has been opened.
    ///
    /// The root lease is the authority every delegation descends from; without
    /// one there is nothing to transfer.
    pub async fn session_root_lease(
        &self,
        session_id: Uuid,
    ) -> Result<Option<Uuid>, WriteScopeError> {
        let leases = self
            .db
            .list_write_scope_leases_for_session(session_id)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        Ok(leases
            .into_iter()
            .find(|l| l.parent_lease_id.is_none() && l.state != LeaseState::Released.as_str())
            .map(|l| l.lease_id))
    }

    /// Open the session's root lease if it has none yet, otherwise return the
    /// existing one. Idempotent so worker restarts do not mint a second root.
    pub async fn ensure_session_root_lease(
        &self,
        session_id: Uuid,
        owner_id: impl Into<String>,
        scope: CanonicalScope,
    ) -> Result<Uuid, WriteScopeError> {
        let _guard = self.serial.lock().await;
        if let Some(existing) = self.session_root_lease(session_id).await? {
            return Ok(existing);
        }
        let token = self
            .open_root_lease_locked(session_id, owner_id, scope)
            .await?;
        Ok(token.lease_id())
    }

    /// A lease's base scope minus every currently-delegated descendant
    /// exclusion.
    ///
    /// An exclusion is live from ParentExcluded until ParentRestored — exactly
    /// the window in which the parent is denied inside the sub-scope.
    pub async fn effective_authority(
        &self,
        lease_id: Uuid,
    ) -> Result<EffectiveAuthority, WriteScopeError> {
        let lease = self.lease(lease_id).await?;
        let transfers = self
            .db
            .list_write_scope_transfers_for_parent(lease_id)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        let exclusions = transfers
            .iter()
            .filter(|t| {
                TransferPhase::parse(&t.phase)
                    .map(TransferPhase::parent_denied_in_subscope)
                    .unwrap_or(false)
            })
            .map(|t| CanonicalScope::from_canonical(t.sub_scope_path.clone()))
            .collect();
        Ok(EffectiveAuthority::new(
            CanonicalScope::from_canonical(lease.scope_path),
            exclusions,
        ))
    }

    /// Validate a token against the live lease generation. A late write holding
    /// an old token fails here without reacquiring.
    async fn validate_token(&self, token: &WriteScopeToken) -> Result<(), WriteScopeError> {
        let lease = self.lease(token.lease_id).await?;
        if !token.is_valid() || lease.generation != token.generation {
            return Err(WriteScopeError::StaleGeneration {
                lease_id: token.lease_id,
                token_generation: token.generation,
                current_generation: lease.generation,
            });
        }
        Ok(())
    }

    // -- mutation permits ---------------------------------------------------

    /// Acquire a durable-generation mutation permit, then re-resolve the
    /// effective path *after* acquisition.
    ///
    /// Order matters: resolving first and acquiring second would leave a window
    /// in which another Cockpit mutation renames an ancestor and changes what
    /// the resolved path means.
    pub async fn acquire_mutation_permit(
        &self,
        token: &WriteScopeToken,
        target: &Path,
        kind: MutationKind,
    ) -> Result<MutationPermit, WriteScopeError> {
        let _guard = self.serial.lock().await;
        self.validate_token(token).await?;

        let authority = self.effective_authority(token.lease_id).await?;

        // Authorization is against the *effective* path, so a symlinked target
        // is judged by where it actually lands.
        let effective = crate::path_containment::effective_path(target).map_err(|_| {
            WriteScopeError::EffectivePathChanged {
                path: target.display().to_string(),
            }
        })?;
        // The footprint must be built from the RESOLVED path too. Building it
        // from the raw request would record a symlinked target's influence root
        // under the wrong subtree, and a transfer of the real target would then
        // see no overlap at all.
        let footprint = PermitFootprint::for_mutation(effective.clone(), kind);
        if !authority.base().contains_path(&effective) {
            return Err(WriteScopeError::OutsideScope {
                path: effective.display().to_string(),
                scope: authority.base().display().to_string(),
            });
        }
        if let Some(excluded) = authority
            .exclusions()
            .iter()
            .find(|e| e.contains_path(&effective))
        {
            return Err(WriteScopeError::DeniedInsideDelegatedSubscope {
                path: effective.display().to_string(),
                exclusion: excluded.display().to_string(),
            });
        }

        // Another in-flight mutation must not be able to change this path's
        // meaning before the syscall runs. Only mutation permits are considered:
        // an execution permit is a handover marker for the transfer barrier, and
        // treating it as a conflict here would deadlock every delegated child
        // against its own handover.
        let held = self
            .db
            .list_held_write_scope_permits(Some(token.session_id))
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        let conflicts = held
            .iter()
            .filter(|p| p.kind == super::types::PermitKind::Mutation.as_str())
            .filter(|p| {
                let other_kind = MutationKind::ALL
                    .iter()
                    .copied()
                    .find(|k| k.as_str() == p.influence_kind)
                    .unwrap_or(MutationKind::WriteContent);
                let other =
                    PermitFootprint::for_mutation(PathBuf::from(&p.target_path), other_kind);
                footprint.conflicts_with(&other)
            })
            .count();
        if conflicts > 0 {
            return Err(WriteScopeError::ConflictingMutationPermits {
                count: conflicts,
                path: effective.display().to_string(),
            });
        }

        let now = self.now();
        let row = WriteScopePermitRow {
            permit_id: Uuid::new_v4(),
            session_id: token.session_id,
            lease_id: token.lease_id,
            generation: token.generation,
            kind: super::types::PermitKind::Mutation.as_str().into(),
            influence_kind: kind.as_str().into(),
            influence_root: footprint.influence_root.display().to_string(),
            target_path: effective.display().to_string(),
            state: "held".into(),
            containment_id: None,
            acquired_at_wall_ms: now,
            released_at_wall_ms: None,
        };
        let row = self
            .db
            .insert_write_scope_permit(row)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;

        // Re-resolve AFTER acquiring the permit. From here the permit's overlap
        // set blocks any Cockpit mutation that could change this path's meaning
        // before the syscall runs.
        let revalidated = crate::path_containment::effective_path(target).map_err(|_| {
            WriteScopeError::EffectivePathChanged {
                path: target.display().to_string(),
            }
        })?;
        if revalidated != effective {
            let _ = self
                .db
                .release_write_scope_permit(row.permit_id, self.now())
                .await;
            return Err(WriteScopeError::EffectivePathChanged {
                path: target.display().to_string(),
            });
        }

        Ok(MutationPermit {
            permit_id: row.permit_id,
            requested: target.to_path_buf(),
            effective_target: revalidated,
            footprint,
        })
    }

    /// Re-check a held permit immediately before the final syscall.
    ///
    /// The permit's overlap set stops another *Cockpit* mutation from changing
    /// this path's meaning, but an unrelated same-user host process is outside
    /// that guarantee. This is where such a change is caught: if the requested
    /// path no longer resolves to the effective target the permit was issued
    /// for, the mutation fails closed instead of writing somewhere new.
    pub async fn revalidate_mutation_permit(
        &self,
        token: &WriteScopeToken,
        permit: &MutationPermit,
    ) -> Result<(), WriteScopeError> {
        self.validate_token(token).await?;
        let current = crate::path_containment::effective_path(&permit.requested).map_err(|_| {
            WriteScopeError::EffectivePathChanged {
                path: permit.requested.display().to_string(),
            }
        })?;
        if current != permit.effective_target {
            return Err(WriteScopeError::EffectivePathChanged {
                path: permit.requested.display().to_string(),
            });
        }
        // Exclusions can also have moved under us.
        let authority = self.effective_authority(token.lease_id).await?;
        if !authority.allows_path(&current) {
            return Err(WriteScopeError::OutsideScope {
                path: current.display().to_string(),
                scope: authority.base().display().to_string(),
            });
        }
        Ok(())
    }

    /// Release a mutation permit after the final syscall.
    pub async fn release_mutation_permit(
        &self,
        permit: MutationPermit,
    ) -> Result<(), WriteScopeError> {
        self.db
            .release_write_scope_permit(permit.permit_id, self.now())
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        Ok(())
    }

    /// Every held permit anywhere in the session whose namespace influence
    /// overlaps `scope` and which is not part of this owner's own delegation
    /// chain.
    ///
    /// Session-wide rather than per-lease on purpose: a *sibling* transfer that
    /// widened its `reachable_ancestor` records its execution permit under a
    /// different lease, and a per-lease query would never see it.
    ///
    /// The exclusion is deliberately narrow. An execution permit that was the
    /// *handover* for this owner or one of its ancestors must NOT block —
    /// blocking on it would make nested delegation structurally impossible,
    /// since a child's own handover permit necessarily covers its whole scope.
    /// Descendant isolation is the Proven backend's job
    /// (`backing_tree_unreachable` / `other_uppers_unreachable`), not this
    /// barrier's.
    async fn blocking_permits(
        &self,
        session_id: Uuid,
        parent_lease_id: Uuid,
        scope: &CanonicalScope,
    ) -> Result<Vec<WriteScopePermitRow>, WriteScopeError> {
        let held = self
            .db
            .list_held_write_scope_permits(Some(session_id))
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        let own_chain = self.lease_ancestry(parent_lease_id).await?;

        let mut blocking = Vec::new();
        for permit in held {
            let root = PathBuf::from(&permit.influence_root);
            let overlaps = super::scope::path_contains(&root, scope.path())
                || super::scope::path_contains(scope.path(), &root);
            if !overlaps {
                continue;
            }
            if permit.kind == super::types::PermitKind::Execution.as_str() {
                let handover = self
                    .db
                    .get_write_scope_transfer_by_execution_permit(permit.permit_id)
                    .await
                    .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
                if let Some(handover) = handover
                    && let Some(child) = handover.child_lease_id
                    && own_chain.contains(&child)
                {
                    // This permit is what created us (or an ancestor of us).
                    continue;
                }
            }
            blocking.push(permit);
        }
        Ok(blocking)
    }

    /// `lease_id` plus every ancestor lease, walking `parent_lease_id`.
    async fn lease_ancestry(
        &self,
        lease_id: Uuid,
    ) -> Result<std::collections::HashSet<Uuid>, WriteScopeError> {
        let mut chain = std::collections::HashSet::new();
        let mut current = Some(lease_id);
        while let Some(id) = current {
            if !chain.insert(id) {
                break; // defensive: a cycle would otherwise spin forever
            }
            current = self
                .db
                .get_write_scope_lease(id)
                .await
                .map_err(|e| WriteScopeError::Internal(e.to_string()))?
                .and_then(|row| row.parent_lease_id);
        }
        Ok(chain)
    }

    /// Retire a transfer that never activated a child and hand the parent its
    /// authority back. Generation moves forward; nothing is reused.
    async fn abandon_and_unwind(
        &self,
        parent: &WriteScopeLeaseRow,
        transfer: &WriteScopeTransferRow,
        err: &WriteScopeError,
    ) {
        if let Ok(Some(current)) = self.db.get_write_scope_transfer(transfer.transfer_id).await
            && current.child_lease_id.is_none()
            && current.phase != TransferPhase::Committed.as_str()
        {
            let _ = self
                .db
                .abandon_write_scope_transfer(
                    current.transfer_id,
                    current.phase.clone(),
                    current.version,
                    err.to_string(),
                    self.now(),
                )
                .await;
        }
        self.unwind_to_active(parent, err).await;
    }

    /// Invalidate every token issued for this lease at an older generation.
    fn invalidate_older_tokens(&self, row: &WriteScopeLeaseRow) {
        if let Ok(tokens) = self.tokens.lock()
            && let Some(entry) = tokens.get(&row.lease_id)
        {
            for (generation, core) in entry {
                if *generation < row.generation {
                    core.invalidate();
                }
            }
        }
    }

    // -- transfer -----------------------------------------------------------

    /// The full ordered transfer barrier through ChildActivated.
    pub async fn begin_transfer(
        &self,
        request: TransferRequest,
    ) -> Result<DelegationHandle, WriteScopeError> {
        let _guard = self.serial.lock().await;

        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(WriteScopeError::ShutdownIntakeClosed);
        }
        if self
            .db
            .is_session_deleting(request.session_id)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
        {
            return Err(WriteScopeError::SessionDeleting);
        }

        let parent = self.lease(request.parent_lease_id).await?;
        let parent_state = LeaseState::parse(&parent.state).ok_or_else(|| {
            WriteScopeError::Internal(format!("bad lease state {}", parent.state))
        })?;
        if !parent_state.can_transition_to(LeaseState::Transferring) {
            return Err(WriteScopeError::IllegalTransition {
                from: parent.state.clone(),
                to: LeaseState::Transferring.as_str().into(),
            });
        }

        // Containment against the parent's EFFECTIVE authority, never its base.
        let authority = self.effective_authority(request.parent_lease_id).await?;
        authority.admits_subscope(&request.sub_scope)?;

        // Fail-fast capability probe. On the direct workspace this returns
        // before a single row, token, event, or byte of user code exists.
        let capability = self
            .backend
            .capability_for(&request.sub_scope, request.mode);
        if !capability.is_proven() {
            let reason = match &capability {
                ScopedWriteCapability::Unsupported { reason } => reason.clone(),
                ScopedWriteCapability::Proven(attestation) => format!(
                    "backend `{}` attestation incomplete: missing {:?}",
                    self.backend.kind(),
                    attestation.missing_clauses()
                ),
            };
            return Err(WriteScopeError::unsupported(reason));
        }

        // ---- Prepared: Active(g) -> Transferring(g+1) ----------------------
        // The CAS and the transfer-row insert are ONE durable step. Two
        // autocommits would let a crash strand the parent in `transferring`
        // with no row for recovery to find, and its authority could never be
        // reclaimed.
        let g = parent.generation;
        let now = self.now();
        let transfer_row = WriteScopeTransferRow {
            transfer_id: Uuid::new_v4(),
            session_id: request.session_id,
            parent_lease_id: parent.lease_id,
            child_lease_id: None,
            sub_scope_path: request.sub_scope.path().display().to_string(),
            phase: TransferPhase::Prepared.as_str().into(),
            prepare_parent_generation: g,
            parent_generation: g + 1,
            child_generation: None,
            restored_parent_generation: None,
            backend_kind: self.backend.kind().to_string(),
            capability: "proven".into(),
            unsupported_reason: None,
            containment_id: None,
            containment_generation: None,
            publication_identity: None,
            execution_permit_id: None,
            recovery_phase: Some("pending".into()),
            version: 1,
            created_at_wall_ms: now,
            updated_at_wall_ms: now,
        };
        let (prepared_parent, transfer) = self
            .db
            .prepare_write_scope_transfer(
                CasWriteScopeLease {
                    lease_id: parent.lease_id,
                    expected_state: parent.state.clone(),
                    expected_generation: parent.generation,
                    expected_version: parent.version,
                    new_state: LeaseState::Transferring.as_str().into(),
                    new_generation: g + 1,
                    now_wall_ms: now,
                    released: false,
                },
                transfer_row,
            )
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
            .ok_or_else(|| WriteScopeError::TransferRaceLost {
                scope: request.sub_scope.display().to_string(),
            })?;
        self.invalidate_older_tokens(&prepared_parent);
        self.events.emit(WriteScopeEvent::TransferPrepared {
            transfer_id: transfer.transfer_id,
            parent_lease_id: parent.lease_id,
        });

        // ---- drain the barrier BEFORE any containment or user code ---------
        // Spec: delegation "starts no child while a parent execution-wide
        // permit overlaps the requested subtree". Creating containment first
        // and draining afterwards would run user code inside a scope whose
        // authority is still contested.
        match self
            .blocking_permits(request.session_id, parent.lease_id, &request.sub_scope)
            .await
        {
            Ok(blocking) if !blocking.is_empty() => {
                let err = WriteScopeError::PermitsNotDrained {
                    count: blocking.len(),
                };
                self.abandon_and_unwind(&prepared_parent, &transfer, &err)
                    .await;
                return Err(err);
            }
            Ok(_) => {}
            Err(err) => {
                self.abandon_and_unwind(&prepared_parent, &transfer, &err)
                    .await;
                return Err(err);
            }
        }

        // ---- ordered acquisition, all-or-nothing, BEFORE ParentExcluded ----
        match self
            .acquire_capability_permit_and_containment(&request, &transfer, &prepared_parent)
            .await
        {
            Ok(acquired) => {
                match self
                    .finish_transfer(
                        &request,
                        transfer.clone(),
                        prepared_parent.clone(),
                        acquired,
                    )
                    .await
                {
                    Ok(handle) => Ok(handle),
                    Err(err) => {
                        self.abandon_and_unwind(&prepared_parent, &transfer, &err)
                            .await;
                        Err(err)
                    }
                }
            }
            Err(err) => {
                // Unwind before exclusion, user code, or any child record.
                self.abandon_and_unwind(&prepared_parent, &transfer, &err)
                    .await;
                Err(err)
            }
        }
    }

    /// Reserve permit -> require Proven backend -> create containment -> prove
    /// membership -> release user code. Any failure propagates and the caller
    /// unwinds.
    async fn acquire_capability_permit_and_containment(
        &self,
        request: &TransferRequest,
        transfer: &WriteScopeTransferRow,
        parent: &WriteScopeLeaseRow,
    ) -> Result<AcquiredExecution, WriteScopeError> {
        // 1. Reserve the execution-wide permit first, so it already exists if
        //    anything below fails and a recovery pass has to find it.
        let reachable_ancestor = request
            .reachable_ancestor
            .clone()
            .unwrap_or_else(|| request.sub_scope.path().to_path_buf());
        let footprint = PermitFootprint::for_execution(
            request.sub_scope.path().to_path_buf(),
            reachable_ancestor,
        );
        let now = self.now();
        let permit = self
            .db
            .insert_write_scope_permit(WriteScopePermitRow {
                permit_id: Uuid::new_v4(),
                session_id: request.session_id,
                lease_id: parent.lease_id,
                generation: parent.generation,
                kind: super::types::PermitKind::Execution.as_str().into(),
                influence_kind: footprint.kind.as_str().into(),
                influence_root: footprint.influence_root.display().to_string(),
                target_path: footprint.target.display().to_string(),
                state: "held".into(),
                containment_id: None,
                acquired_at_wall_ms: now,
                released_at_wall_ms: None,
            })
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;

        // 2. Require a Proven backend for the COMPLETE effective scope.
        let capability = self
            .backend
            .capability_for(&request.sub_scope, request.mode);
        if !capability.is_proven() {
            let _ = self
                .db
                .release_write_scope_permit(permit.permit_id, self.now())
                .await;
            let reason = match capability {
                ScopedWriteCapability::Unsupported { reason } => reason,
                ScopedWriteCapability::Proven(a) => {
                    format!("attestation incomplete: missing {:?}", a.missing_clauses())
                }
            };
            return Err(WriteScopeError::unsupported(reason));
        }

        // 3. Sample the publication target's identity, BEFORE any user code
        //    exists. Sampling after release would let an external replacement
        //    that happened in the interval become the accepted baseline, and the
        //    publish-time comparison would then confirm the attacker's inode.
        //
        //    A Proven backend that cannot supply an identity fails closed here:
        //    `broker_only_replace_publication` is unprovable without one, so the
        //    attestation was false.
        let Some(identity) = self.backend.target_identity(&request.sub_scope) else {
            let _ = self
                .db
                .release_write_scope_permit(permit.permit_id, self.now())
                .await;
            return Err(WriteScopeError::unsupported(format!(
                "backend `{}` attests Proven but cannot bind `{}` to a stable inode identity; \
                 replace-only publication cannot be verified",
                self.backend.kind(),
                request.sub_scope.display()
            )));
        };

        // 4. Create containment.
        //
        //    The witness is minted from the durable `prepared` transfer row, so
        //    the containment's operation id is derived from the transfer id.
        //    That is what makes a containment created here findable by recovery
        //    even if the crash lands before step 5 attaches its ticket.
        let reserved = OwnershipReserved::from_prepared(transfer);
        let ticket = match self
            .containment
            .create(&reserved, request.mode, &request.launch)
            .await
        {
            Ok(ticket) => ticket,
            Err(err) => {
                let _ = self
                    .db
                    .release_write_scope_permit(permit.permit_id, self.now())
                    .await;
                return Err(err);
            }
        };

        // 5. Durably attach the containment ticket, its generation, the
        //    execution permit and the publication identity to the transfer
        //    BEFORE any user code exists. A crash in the next instant must be
        //    recoverable as "a child may be running", not as "nothing ever
        //    started" — otherwise recovery retires the transfer and hands the
        //    parent back authority the child is still using.
        let recorded = match self
            .db
            .attach_write_scope_transfer_ownership(
                transfer.transfer_id,
                ticket.containment_id,
                ticket.generation,
                permit.permit_id,
                Some(identity.0.to_string()),
                self.now(),
            )
            .await
        {
            Ok(Some(row)) => {
                match OwnershipRecorded::from_reserved_and_persisted(&reserved, &row) {
                    Ok(recorded) => recorded,
                    Err(err) => {
                        let _ = self.containment.terminate(&ticket).await;
                        let _ = self
                            .db
                            .release_write_scope_permit(permit.permit_id, self.now())
                            .await;
                        return Err(err);
                    }
                }
            }
            Ok(None) => {
                let _ = self.containment.terminate(&ticket).await;
                let _ = self
                    .db
                    .release_write_scope_permit(permit.permit_id, self.now())
                    .await;
                return Err(WriteScopeError::Internal(
                    "transfer left `prepared` before ownership could be recorded".into(),
                ));
            }
            Err(err) => {
                let _ = self.containment.terminate(&ticket).await;
                let _ = self
                    .db
                    .release_write_scope_permit(permit.permit_id, self.now())
                    .await;
                return Err(WriteScopeError::Internal(err.to_string()));
            }
        };

        // 6. Only now may user code run: the type system enforces it, because
        //    `OwnershipRecorded` cannot be minted before the step above.
        if let Err(err) = self
            .containment
            .prove_membership_and_release_user_code(&recorded)
            .await
        {
            let _ = self.containment.terminate(&ticket).await;
            let _ = self
                .db
                .release_write_scope_permit(permit.permit_id, self.now())
                .await;
            return Err(err);
        }

        Ok(AcquiredExecution {
            execution_permit_id: permit.permit_id,
            containment: ticket,
            publication_identity: identity,
        })
    }

    async fn finish_transfer(
        &self,
        request: &TransferRequest,
        transfer: WriteScopeTransferRow,
        parent: WriteScopeLeaseRow,
        acquired: AcquiredExecution,
    ) -> Result<DelegationHandle, WriteScopeError> {
        // The overlapping-permit barrier already drained in `begin_transfer`,
        // before containment existed and before any user code ran.

        // The identity was sampled during acquisition, before user code was
        // released. Re-sampling here would reintroduce the very window the
        // pre-release sample exists to close.
        let publication_identity = Some(acquired.publication_identity.0.to_string());

        // ---- ParentExcluded: record exclusions, reissue parent token at g+1 -
        let transfer = self
            .cas_transfer(
                &transfer,
                TransferPhase::ParentExcluded,
                CasPatch {
                    containment_id: Some(acquired.containment.containment_id),
                    // The containment's OWN generation, persisted so the return
                    // barrier can compare the oracle's answer against it.
                    containment_generation: Some(acquired.containment.generation),
                    publication_identity: Some(publication_identity),
                    execution_permit_id: Some(acquired.execution_permit_id),
                    ..Default::default()
                },
            )
            .await?;
        self.events.emit(WriteScopeEvent::ParentExcluded {
            transfer_id: transfer.transfer_id,
            parent_generation: parent.generation,
        });
        // The replacement parent token is generation g+1 — the same generation
        // the Prepared CAS produced. It carries the new exclusions.
        let parent_token = self.issue_token(&parent);

        // ---- ChildActivated: child lease at g+2 ----------------------------
        let child_generation = transfer.prepare_parent_generation + 2;
        let now = self.now();
        let child_row = WriteScopeLeaseRow {
            lease_id: Uuid::new_v4(),
            parent_lease_id: Some(parent.lease_id),
            session_id: request.session_id,
            task_id: request.task_id.clone(),
            scope_path: request.sub_scope.path().display().to_string(),
            generation: child_generation,
            state: LeaseState::Active.as_str().into(),
            owner_id: request.child_owner_id.clone(),
            version: 1,
            created_at_wall_ms: now,
            updated_at_wall_ms: now,
            released_at_wall_ms: None,
        };
        // Insert the child lease, attach it to the transfer, and move the
        // parent to Delegated in ONE transaction. As separate commits, a crash
        // after the insert left an orphan `active` child lease while the
        // transfer still had no `child_lease_id`, so recovery retired the
        // transfer and reactivated the parent — two owners of one subtree.
        let (child, transfer, _parent) = self
            .db
            .activate_write_scope_child(
                child_row,
                CasWriteScopeTransfer {
                    transfer_id: transfer.transfer_id,
                    expected_phase: transfer.phase.clone(),
                    expected_version: transfer.version,
                    new_phase: TransferPhase::ChildActivated.as_str().into(),
                    now_wall_ms: self.now(),
                    child_lease_id: None,
                    parent_generation: None,
                    child_generation: Some(child_generation),
                    restored_parent_generation: None,
                    containment_id: None,
                    containment_generation: None,
                    publication_identity: None,
                    execution_permit_id: None,
                    recovery_phase: None,
                },
                CasWriteScopeLease {
                    lease_id: parent.lease_id,
                    expected_state: parent.state.clone(),
                    expected_generation: parent.generation,
                    expected_version: parent.version,
                    new_state: LeaseState::Delegated.as_str().into(),
                    new_generation: parent.generation,
                    now_wall_ms: self.now(),
                    released: false,
                },
            )
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
            .ok_or_else(|| WriteScopeError::TransferRaceLost {
                scope: request.sub_scope.display().to_string(),
            })?;

        self.events.emit(WriteScopeEvent::ChildActivated {
            transfer_id: transfer.transfer_id,
            child_lease_id: child.lease_id,
            child_generation,
        });

        Ok(DelegationHandle {
            transfer_id: transfer.transfer_id,
            child_token: self.issue_token(&child),
            parent_token,
            containment: acquired.containment,
            execution_permit_id: acquired.execution_permit_id,
        })
    }

    /// Roll a Transferring parent back to Active. The generation moves
    /// *forward*: rollback never reuses or decrements a generation.
    async fn unwind_to_active(&self, parent: &WriteScopeLeaseRow, err: &WriteScopeError) {
        if let Ok(Some(current)) = self.db.get_write_scope_lease(parent.lease_id).await
            && current.state == LeaseState::Transferring.as_str()
        {
            let _ = self
                .cas_lease(&current, LeaseState::Active, current.generation + 1, false)
                .await;
        }
        self.events.emit(WriteScopeEvent::TransferUnwound {
            parent_lease_id: parent.lease_id,
            reason: err.to_string(),
        });
    }

    /// Mark the child terminal and invalidate its token before return begins.
    pub async fn child_terminal(&self, transfer_id: Uuid) -> Result<(), WriteScopeError> {
        let _guard = self.serial.lock().await;
        let transfer = self.transfer(transfer_id).await?;
        if let Some(child_lease_id) = transfer.child_lease_id {
            self.invalidate_all_tokens(child_lease_id);
        }
        self.cas_transfer(&transfer, TransferPhase::ChildTerminal, CasPatch::default())
            .await?;
        self.events
            .emit(WriteScopeEvent::ChildTerminal { transfer_id });
        Ok(())
    }

    /// Complete the return: ProvenEmpty, publication resolved, permit released,
    /// then and only then restore the parent at a fresh generation.
    pub async fn complete_return(
        &self,
        transfer_id: Uuid,
    ) -> Result<WriteScopeToken, WriteScopeError> {
        let _guard = self.serial.lock().await;
        self.complete_return_locked(transfer_id).await
    }

    /// The return barrier itself. Caller must already hold `serial`; recovery
    /// reuses this so a crashed transfer takes the exact same path as a live
    /// one rather than a parallel, weaker implementation.
    async fn complete_return_locked(
        &self,
        transfer_id: Uuid,
    ) -> Result<WriteScopeToken, WriteScopeError> {
        let transfer = self.transfer(transfer_id).await?;

        // Validate the phase before touching anything. Returning from any other
        // phase would release the child while its token is still live.
        let phase = TransferPhase::parse(&transfer.phase).ok_or_else(|| {
            WriteScopeError::Internal(format!("bad transfer phase {}", transfer.phase))
        })?;
        if phase != TransferPhase::ChildTerminal {
            return Err(WriteScopeError::IllegalPhaseAdvance {
                from: phase.as_str().into(),
                to: TransferPhase::ParentRestored.as_str().into(),
            });
        }

        // 0. A descendant of this child may still own a sub-scope of the scope
        //    we are about to hand back. Restoring now would give the parent
        //    authority over a subtree a grandchild still owns.
        if let Some(child_lease_id) = transfer.child_lease_id {
            let live_descendants = self
                .db
                .list_open_write_scope_transfers_for_parent(child_lease_id)
                .await
                .map_err(|e| WriteScopeError::Internal(e.to_string()))?
                .into_iter()
                .filter(|t| {
                    TransferPhase::parse(&t.phase)
                        .map(TransferPhase::parent_denied_in_subscope)
                        .unwrap_or(false)
                })
                .count();
            if live_descendants > 0 {
                return Err(WriteScopeError::DescendantStillDelegated {
                    transfer_id,
                    count: live_descendants,
                });
            }
        }

        let Some(containment_id) = transfer.containment_id else {
            return Err(WriteScopeError::Internal(
                "transfer has no containment to drain".into(),
            ));
        };
        // The containment's OWN generation, not a lease generation. These are
        // separate counters and confusing them would make the oracle's answer
        // meaningless.
        let Some(expected_containment_generation) = transfer.containment_generation else {
            return Err(WriteScopeError::Internal(
                "transfer has no recorded containment generation".into(),
            ));
        };
        let ticket = ContainmentTicket {
            containment_id,
            generation: expected_containment_generation,
        };

        // 1. The exact child containment must be ProvenEmpty, and the oracle
        //    must be answering about the generation we recorded.
        match self.containment.await_proven_empty(&ticket).await {
            ProvenEmptyOutcome::ProvenEmpty { generation } => {
                if generation != expected_containment_generation {
                    return Err(WriteScopeError::ContainmentGenerationMismatch {
                        expected: expected_containment_generation,
                        got: generation,
                    });
                }
            }
            ProvenEmptyOutcome::Uncertain { reason, .. }
            | ProvenEmptyOutcome::Unsupported { reason } => {
                return Err(WriteScopeError::ContainmentNotProvenEmpty {
                    transfer_id,
                    reason,
                });
            }
        }

        // 2. Broker publication must resolve, against the identity recorded
        //    when the child started. An uncertain publish never restores
        //    authority.
        let scope = CanonicalScope::from_canonical(transfer.sub_scope_path.clone());
        // A transfer that got this far was Proven, so an identity must have
        // been recorded. Publishing without one would compare nothing and could
        // report Published after an undetected replacement.
        let Some(expected_target_identity) = transfer
            .publication_identity
            .as_deref()
            .and_then(|raw| raw.parse::<u64>().ok())
            .map(super::backend::InodeIdentity)
        else {
            return Err(WriteScopeError::unsupported(format!(
                "transfer {transfer_id} has no recorded publication identity; refusing to \
                 publish without an identity to compare against"
            )));
        };
        match self.backend.publish(PublishRequest {
            scope,
            expected_target_identity: Some(expected_target_identity),
        }) {
            PublishOutcome::Published { .. } => {}
            PublishOutcome::Conflict { reason } => {
                return Err(WriteScopeError::PublicationConflict { reason });
            }
            PublishOutcome::Unsupported { reason } => {
                return Err(WriteScopeError::unsupported(reason));
            }
        }

        // 3. Release the execution-wide permit — only now, after ProvenEmpty.
        if let Some(permit_id) = transfer.execution_permit_id {
            self.db
                .release_write_scope_permit(permit_id, self.now())
                .await
                .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        }

        // 4. Release the child lease.
        if let Some(child_lease_id) = transfer.child_lease_id {
            let child = self.lease(child_lease_id).await?;
            self.invalidate_all_tokens(child_lease_id);
            self.cas_lease(&child, LeaseState::Released, child.generation + 1, true)
                .await?;
        }

        // 5. ParentRestored: parent increments again and gets a fresh
        //    full-authority token.
        let parent = self.lease(transfer.parent_lease_id).await?;
        let returning = self
            .cas_lease(&parent, LeaseState::Returning, parent.generation, false)
            .await?
            .ok_or_else(|| WriteScopeError::Internal("parent CAS to Returning lost".into()))?;

        // If other children are still delegated, the parent returns to
        // Delegated, not Active: it regains this sub-scope but not the others.
        let siblings_still_delegated = self
            .db
            .list_write_scope_transfers_for_parent(transfer.parent_lease_id)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
            .iter()
            .any(|t| {
                t.transfer_id != transfer_id
                    && TransferPhase::parse(&t.phase)
                        .map(TransferPhase::parent_denied_in_subscope)
                        .unwrap_or(false)
            });
        let restored_state = if siblings_still_delegated {
            LeaseState::Delegated
        } else {
            LeaseState::Active
        };

        let restored_generation = returning.generation + 1;
        let restored = self
            .cas_lease(&returning, restored_state, restored_generation, false)
            .await?
            .ok_or_else(|| WriteScopeError::Internal("parent restoration CAS lost".into()))?;

        let transfer = self
            .cas_transfer(
                &transfer,
                TransferPhase::ParentRestored,
                CasPatch {
                    restored_parent_generation: Some(restored_generation),
                    ..Default::default()
                },
            )
            .await?;
        self.events.emit(WriteScopeEvent::ParentRestored {
            transfer_id,
            parent_generation: restored_generation,
        });

        self.cas_transfer(
            &transfer,
            TransferPhase::Committed,
            CasPatch {
                recovery_phase: Some(Some("reconciled".into())),
                ..Default::default()
            },
        )
        .await?;
        self.events
            .emit(WriteScopeEvent::TransferCommitted { transfer_id });

        Ok(self.issue_token(&restored))
    }

    // -- CAS helpers --------------------------------------------------------

    async fn cas_lease(
        &self,
        current: &WriteScopeLeaseRow,
        next: LeaseState,
        new_generation: u64,
        released: bool,
    ) -> Result<Option<WriteScopeLeaseRow>, WriteScopeError> {
        let from = LeaseState::parse(&current.state).ok_or_else(|| {
            WriteScopeError::Internal(format!("bad lease state {}", current.state))
        })?;
        if !from.can_transition_to(next) {
            return Err(WriteScopeError::IllegalTransition {
                from: from.as_str().into(),
                to: next.as_str().into(),
            });
        }
        let row = self
            .db
            .cas_write_scope_lease(CasWriteScopeLease {
                lease_id: current.lease_id,
                expected_state: current.state.clone(),
                expected_generation: current.generation,
                expected_version: current.version,
                new_state: next.as_str().into(),
                new_generation,
                now_wall_ms: self.now(),
                released,
            })
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        if let Some(row) = &row
            && row.generation > current.generation
        {
            // A generation change invalidates every older token for this lease.
            if let Ok(tokens) = self.tokens.lock()
                && let Some(entry) = tokens.get(&row.lease_id)
            {
                for (generation, core) in entry {
                    if *generation < row.generation {
                        core.invalidate();
                    }
                }
            }
        }
        Ok(row)
    }

    async fn cas_transfer(
        &self,
        current: &WriteScopeTransferRow,
        next: TransferPhase,
        patch: CasPatch,
    ) -> Result<WriteScopeTransferRow, WriteScopeError> {
        let from = TransferPhase::parse(&current.phase).ok_or_else(|| {
            WriteScopeError::Internal(format!("bad transfer phase {}", current.phase))
        })?;
        if from.next() != Some(next) {
            return Err(WriteScopeError::IllegalPhaseAdvance {
                from: from.as_str().into(),
                to: next.as_str().into(),
            });
        }
        self.db
            .cas_write_scope_transfer_phase(CasWriteScopeTransfer {
                transfer_id: current.transfer_id,
                expected_phase: current.phase.clone(),
                expected_version: current.version,
                new_phase: next.as_str().into(),
                now_wall_ms: self.now(),
                child_lease_id: patch.child_lease_id,
                parent_generation: patch.parent_generation,
                child_generation: patch.child_generation,
                restored_parent_generation: patch.restored_parent_generation,
                containment_id: patch.containment_id,
                containment_generation: patch.containment_generation,
                publication_identity: patch.publication_identity,
                execution_permit_id: patch.execution_permit_id,
                recovery_phase: patch.recovery_phase,
            })
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
            .ok_or(WriteScopeError::TransferNotFound(current.transfer_id))
    }

    // -- recovery / barriers ------------------------------------------------

    /// Reconcile every open transfer against durable containment and lease
    /// generations. Repeatable: running it twice yields the same outcome.
    pub async fn recover(
        &self,
        session_id: Option<Uuid>,
    ) -> Result<Vec<RecoveryOutcome>, WriteScopeError> {
        let _guard = self.serial.lock().await;
        let open = self
            .db
            .list_open_write_scope_transfers(session_id)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        let mut out = Vec::new();
        for transfer in open {
            out.push(self.recover_one(&transfer).await);
        }
        Ok(out)
    }

    async fn recover_one(&self, transfer: &WriteScopeTransferRow) -> RecoveryOutcome {
        let Some(phase) = TransferPhase::parse(&transfer.phase) else {
            return RecoveryOutcome::Denied {
                transfer_id: transfer.transfer_id,
                reason: format!("unknown phase `{}`", transfer.phase),
            };
        };
        let transfer_id = transfer.transfer_id;

        match phase {
            // Crashed before exclusion, or excluded but never activated. Either
            // way no child lease exists, so no authority was ever handed over.
            // Retire the row and hand the parent its scope back — recovery must
            // *do* this, not merely report it, or the parent stays stranded in
            // `transferring` forever.
            TransferPhase::Prepared | TransferPhase::ParentExcluded => {
                // If containment was created we must still see it empty before
                // reclaiming: user code may have been released.
                if let (Some(containment_id), Some(generation)) =
                    (transfer.containment_id, transfer.containment_generation)
                {
                    let ticket = ContainmentTicket {
                        containment_id,
                        generation,
                    };
                    match self.containment.await_proven_empty(&ticket).await {
                        ProvenEmptyOutcome::ProvenEmpty { generation: got }
                            if got == generation => {}
                        ProvenEmptyOutcome::ProvenEmpty { generation: got } => {
                            return RecoveryOutcome::Denied {
                                transfer_id,
                                reason: format!(
                                    "containment generation mismatch: expected {generation}, got {got}"
                                ),
                            };
                        }
                        ProvenEmptyOutcome::Uncertain { reason, .. } => {
                            return RecoveryOutcome::RetainedNotProvenEmpty {
                                transfer_id,
                                reason,
                            };
                        }
                        ProvenEmptyOutcome::Unsupported { reason } => {
                            return RecoveryOutcome::Denied {
                                transfer_id,
                                reason,
                            };
                        }
                    }
                } else {
                    // No ticket on the row. That is NOT proof that nothing was
                    // created: the crash may have landed between
                    // `ContainmentBarrier::create` and the ownership attach, in
                    // which case a containment — and the user code inside it —
                    // exists with no pointer from this row.
                    //
                    // The operation id is derived from the transfer id, so the
                    // row alone is enough to find it. Without this lookup the
                    // ordering is fixed but the crash window is not: we would
                    // retire the transfer and hand the parent back authority a
                    // live child is still using.
                    let operation_id = write_scope_containment_operation_id(transfer_id);
                    match self
                        .db
                        .list_nonempty_execution_containments_for_operation(&operation_id)
                        .await
                    {
                        Ok(rows) if rows.is_empty() => {}
                        Ok(rows) => {
                            let states = rows
                                .iter()
                                .map(|r| format!("{}={}", r.containment_id, r.state))
                                .collect::<Vec<_>>()
                                .join(", ");
                            return RecoveryOutcome::RetainedNotProvenEmpty {
                                transfer_id,
                                reason: format!(
                                    "transfer has no recorded containment ticket, but {} \
                                     non-empty containment(s) exist for derived operation \
                                     `{operation_id}` ({states}); a child may be running, so \
                                     parent authority is not restored",
                                    rows.len()
                                ),
                            };
                        }
                        // Fail closed: if we cannot tell whether a containment
                        // was created, we must not reclaim the scope.
                        Err(err) => {
                            return RecoveryOutcome::RetainedNotProvenEmpty {
                                transfer_id,
                                reason: format!(
                                    "cannot determine whether a containment exists for derived \
                                     operation `{operation_id}`: {err}"
                                ),
                            };
                        }
                    }
                }
                if let Some(permit_id) = transfer.execution_permit_id {
                    let _ = self
                        .db
                        .release_write_scope_permit(permit_id, self.now())
                        .await;
                }
                if let Err(err) = self.retire_unactivated(transfer).await {
                    return RecoveryOutcome::Denied {
                        transfer_id,
                        reason: err.to_string(),
                    };
                }
                RecoveryOutcome::ReturnAdvanced { transfer_id }
            }

            TransferPhase::ChildActivated => {
                let Some(child_lease_id) = transfer.child_lease_id else {
                    return RecoveryOutcome::Denied {
                        transfer_id,
                        reason: "child_activated without a child lease".into(),
                    };
                };
                let (Some(containment_id), Some(expected_generation)) =
                    (transfer.containment_id, transfer.containment_generation)
                else {
                    return RecoveryOutcome::Denied {
                        transfer_id,
                        reason: "child_activated without a recorded containment generation".into(),
                    };
                };
                let ticket = ContainmentTicket {
                    containment_id,
                    generation: expected_generation,
                };
                match self.containment.await_proven_empty(&ticket).await {
                    // Proven populated -> a live child keeps ownership.
                    ProvenEmptyOutcome::Uncertain { reason, .. } => {
                        if reason == POPULATED_MARKER {
                            RecoveryOutcome::ChildResumedOwnership {
                                transfer_id,
                                child_lease_id,
                            }
                        } else {
                            RecoveryOutcome::RetainedNotProvenEmpty {
                                transfer_id,
                                reason,
                            }
                        }
                    }
                    ProvenEmptyOutcome::ProvenEmpty { generation } => {
                        if generation != expected_generation {
                            return RecoveryOutcome::Denied {
                                transfer_id,
                                reason: format!(
                                    "containment generation mismatch: expected \
                                     {expected_generation}, got {generation}"
                                ),
                            };
                        }
                        // The child is gone. Drive the same return the live path
                        // would: ChildTerminal, then the full return barrier.
                        self.drive_return_from_activated(transfer).await
                    }
                    ProvenEmptyOutcome::Unsupported { reason } => RecoveryOutcome::Denied {
                        transfer_id,
                        reason,
                    },
                }
            }

            TransferPhase::ChildTerminal => match self.complete_return_locked(transfer_id).await {
                Ok(_) => RecoveryOutcome::ReturnAdvanced { transfer_id },
                Err(WriteScopeError::ContainmentNotProvenEmpty { reason, .. }) => {
                    RecoveryOutcome::RetainedNotProvenEmpty {
                        transfer_id,
                        reason,
                    }
                }
                Err(err) => RecoveryOutcome::Denied {
                    transfer_id,
                    reason: err.to_string(),
                },
            },

            // Parent authority was already restored; only the Committed marker
            // is missing.
            TransferPhase::ParentRestored => {
                match self
                    .cas_transfer(
                        transfer,
                        TransferPhase::Committed,
                        CasPatch {
                            recovery_phase: Some(Some("reconciled".into())),
                            ..Default::default()
                        },
                    )
                    .await
                {
                    Ok(_) => {
                        self.events
                            .emit(WriteScopeEvent::TransferCommitted { transfer_id });
                        RecoveryOutcome::ReturnAdvanced { transfer_id }
                    }
                    Err(err) => RecoveryOutcome::Denied {
                        transfer_id,
                        reason: err.to_string(),
                    },
                }
            }

            TransferPhase::Committed => RecoveryOutcome::AlreadyCommitted { transfer_id },
        }
    }

    /// Retire a transfer that never activated a child and return the parent to
    /// Active at a forward generation.
    async fn retire_unactivated(
        &self,
        transfer: &WriteScopeTransferRow,
    ) -> Result<(), WriteScopeError> {
        self.db
            .abandon_write_scope_transfer(
                transfer.transfer_id,
                transfer.phase.clone(),
                transfer.version,
                "recovered: transfer never activated a child".into(),
                self.now(),
            )
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        let parent = self.lease(transfer.parent_lease_id).await?;
        if parent.state == LeaseState::Transferring.as_str() {
            self.cas_lease(&parent, LeaseState::Active, parent.generation + 1, false)
                .await?;
        }
        self.events.emit(WriteScopeEvent::TransferCommitted {
            transfer_id: transfer.transfer_id,
        });
        Ok(())
    }

    /// A crashed-but-empty ChildActivated transfer: advance to ChildTerminal,
    /// then run the same return barrier the live path runs.
    async fn drive_return_from_activated(
        &self,
        transfer: &WriteScopeTransferRow,
    ) -> RecoveryOutcome {
        let transfer_id = transfer.transfer_id;
        if let Some(child_lease_id) = transfer.child_lease_id {
            self.invalidate_all_tokens(child_lease_id);
        }
        if let Err(err) = self
            .cas_transfer(transfer, TransferPhase::ChildTerminal, CasPatch::default())
            .await
        {
            return RecoveryOutcome::Denied {
                transfer_id,
                reason: err.to_string(),
            };
        }
        self.events
            .emit(WriteScopeEvent::ChildTerminal { transfer_id });
        match self.complete_return_locked(transfer_id).await {
            Ok(_) => RecoveryOutcome::ReturnAdvanced { transfer_id },
            Err(WriteScopeError::ContainmentNotProvenEmpty { reason, .. }) => {
                RecoveryOutcome::RetainedNotProvenEmpty {
                    transfer_id,
                    reason,
                }
            }
            Err(err) => RecoveryOutcome::Denied {
                transfer_id,
                reason: err.to_string(),
            },
        }
    }

    /// Block new transfers and report the containments/permits that still
    /// prevent session deletion.
    pub async fn begin_session_deletion(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<Uuid>, WriteScopeError> {
        // Same lock as `begin_transfer`: without it, a transfer that already
        // passed its Deleting check could linearize after the mark and create a
        // child in a session being torn down.
        let _guard = self.serial.lock().await;
        self.db
            .mark_session_deleting(session_id)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        self.deletion_blockers_inner(session_id).await
    }

    /// Live leases + held permits that must drain before deletion may proceed.
    pub async fn deletion_blockers(&self, session_id: Uuid) -> Result<Vec<Uuid>, WriteScopeError> {
        let _guard = self.serial.lock().await;
        self.deletion_blockers_inner(session_id).await
    }

    /// Caller must already hold `serial`.
    async fn deletion_blockers_inner(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<Uuid>, WriteScopeError> {
        let mut blockers = Vec::new();
        // Only *delegated* leases block. A session's own root lease is not an
        // outstanding hazard — it is the session's baseline authority, held for
        // as long as the session exists, and it is removed with the session's
        // rows. Counting it would make every session permanently undeletable.
        for lease in self
            .db
            .list_live_write_scope_leases(Some(session_id))
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
            .into_iter()
            .filter(|lease| lease.parent_lease_id.is_some())
        {
            blockers.push(lease.lease_id);
        }
        for permit in self
            .db
            .list_held_write_scope_permits(Some(session_id))
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
        {
            blockers.push(permit.permit_id);
        }
        Ok(blockers)
    }

    /// Close intake. Shutdown cannot report clean while anything is held.
    ///
    /// Takes `serial` so an in-flight `begin_transfer` cannot slip past the
    /// intake check and create a child after shutdown began.
    pub async fn begin_shutdown(&self) -> Result<(), WriteScopeError> {
        let _guard = self.serial.lock().await;
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// `Ok(())` only when no lease is live and no permit is held anywhere.
    pub async fn assert_shutdown_clean(&self) -> Result<(), WriteScopeError> {
        let _guard = self.serial.lock().await;
        // Same rule as deletion: a session root lease is baseline authority, not
        // outstanding delegated authority. Counting roots here would make every
        // shutdown report unclean and force-abort in-flight work on every exit.
        let delegated = self
            .db
            .list_live_write_scope_leases(None)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?
            .into_iter()
            .filter(|lease| lease.parent_lease_id.is_some())
            .count();
        let permits = self
            .db
            .list_held_write_scope_permits(None)
            .await
            .map_err(|e| WriteScopeError::Internal(e.to_string()))?;
        if delegated == 0 && permits.is_empty() {
            return Ok(());
        }
        Err(WriteScopeError::PermitsNotDrained {
            count: delegated + permits.len(),
        })
    }
}

/// Marker a fake containment uses to say "proven populated" rather than
/// "ambiguous". Recovery treats it as evidence the child is live.
pub const POPULATED_MARKER: &str = "proven_populated";

struct AcquiredExecution {
    execution_permit_id: Uuid,
    containment: ContainmentTicket,
    /// Sampled before user code was released.
    publication_identity: super::backend::InodeIdentity,
}

#[derive(Default)]
struct CasPatch {
    child_lease_id: Option<Uuid>,
    parent_generation: Option<u64>,
    child_generation: Option<u64>,
    restored_parent_generation: Option<u64>,
    containment_id: Option<Uuid>,
    containment_generation: Option<u64>,
    publication_identity: Option<Option<String>>,
    execution_permit_id: Option<Uuid>,
    recovery_phase: Option<Option<String>>,
}
