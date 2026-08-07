//! Core types for durable hierarchical write-scope leases.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use uuid::Uuid;

use super::scope::CanonicalScope;

/// Durable lease lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseState {
    /// Owner holds write authority over its effective scope.
    Active,
    /// A transfer is preparing: new work is blocked so the effective
    /// exclusions cannot move under the contender's feet.
    Transferring,
    /// A strict sub-scope is delegated to a child; the owner is denied inside
    /// it but may still write elsewhere in its base scope.
    Delegated,
    /// The child is terminal and the return barrier is draining.
    Returning,
    /// Terminal. Authority is gone and never resurrects.
    Released,
}

impl LeaseState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Transferring => "transferring",
            Self::Delegated => "delegated",
            Self::Returning => "returning",
            Self::Released => "released",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "transferring" => Some(Self::Transferring),
            "delegated" => Some(Self::Delegated),
            "returning" => Some(Self::Returning),
            "released" => Some(Self::Released),
            _ => None,
        }
    }

    /// Legal authority transitions. Everything else is illegal and must be
    /// refused rather than clamped, because a clamp would silently move
    /// authority.
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Active, Self::Transferring)
                | (Self::Active, Self::Released)
                | (Self::Transferring, Self::Delegated)
                // Unwind: a failed acquisition returns authority to the parent.
                | (Self::Transferring, Self::Active)
                // An owner that already delegated one sub-scope may delegate
                // another disjoint one; it still holds authority elsewhere.
                | (Self::Delegated, Self::Transferring)
                | (Self::Delegated, Self::Returning)
                | (Self::Returning, Self::Active)
                // Returning with other children still delegated goes back to
                // Delegated, not Active.
                | (Self::Returning, Self::Delegated)
                | (Self::Returning, Self::Released)
                | (Self::Delegated, Self::Released)
        )
    }
}

/// Ordered transfer phases. A transfer only ever advances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransferPhase {
    /// Parent CASed Active(g) -> Transferring(g+1); new work blocked.
    Prepared,
    /// New effective exclusions recorded; replacement parent token issued at
    /// generation g+1. The parent is denied inside the sub-scope from here.
    ParentExcluded,
    /// Child lease created at generation g+2.
    ChildActivated,
    /// Child token invalidated; return may begin.
    ChildTerminal,
    /// Parent incremented again and reissued a fresh full-authority token.
    ParentRestored,
    /// Terminal.
    Committed,
}

impl TransferPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::ParentExcluded => "parent_excluded",
            Self::ChildActivated => "child_activated",
            Self::ChildTerminal => "child_terminal",
            Self::ParentRestored => "parent_restored",
            Self::Committed => "committed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "prepared" => Some(Self::Prepared),
            "parent_excluded" => Some(Self::ParentExcluded),
            "child_activated" => Some(Self::ChildActivated),
            "child_terminal" => Some(Self::ChildTerminal),
            "parent_restored" => Some(Self::ParentRestored),
            "committed" => Some(Self::Committed),
            _ => None,
        }
    }

    pub fn ordinal(self) -> usize {
        match self {
            Self::Prepared => 0,
            Self::ParentExcluded => 1,
            Self::ChildActivated => 2,
            Self::ChildTerminal => 3,
            Self::ParentRestored => 4,
            Self::Committed => 5,
        }
    }

    /// The next phase in the sequence, or `None` at the terminal phase.
    pub fn next(self) -> Option<Self> {
        match self {
            Self::Prepared => Some(Self::ParentExcluded),
            Self::ParentExcluded => Some(Self::ChildActivated),
            Self::ChildActivated => Some(Self::ChildTerminal),
            Self::ChildTerminal => Some(Self::ParentRestored),
            Self::ParentRestored => Some(Self::Committed),
            Self::Committed => None,
        }
    }

    /// Whether the parent is denied inside the delegated sub-scope at this
    /// phase. True from ParentExcluded until ParentRestored.
    pub fn parent_denied_in_subscope(self) -> bool {
        self.ordinal() >= Self::ParentExcluded.ordinal()
            && self.ordinal() < Self::ParentRestored.ordinal()
    }

    pub const ALL: &'static [TransferPhase] = &[
        Self::Prepared,
        Self::ParentExcluded,
        Self::ChildActivated,
        Self::ChildTerminal,
        Self::ParentRestored,
        Self::Committed,
    ];
}

/// What a permit protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermitKind {
    /// One Cockpit-owned filesystem mutation syscall.
    Mutation,
    /// An entire execution that can run arbitrary user code. Held across the
    /// immediate child's exit and every descendant until the same containment
    /// generation returns ProvenEmpty.
    Execution,
}

impl PermitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mutation => "mutation",
            Self::Execution => "execution",
        }
    }
}

/// Non-serializable, generation-bound proof of write authority.
///
/// Deliberately has no `Serialize`/`Deserialize`: a token must never cross a
/// process boundary or outlive the generation that issued it. Every
/// authority-changing transition invalidates every older token, so a late write
/// that still holds one fails without reacquiring.
#[derive(Clone)]
pub struct WriteScopeToken {
    pub(super) lease_id: Uuid,
    pub(super) session_id: Uuid,
    pub(super) generation: u64,
    pub(super) scope: CanonicalScope,
    pub(super) core: Arc<TokenCore>,
}

pub(super) struct TokenCore {
    pub(super) alive: AtomicBool,
}

impl TokenCore {
    pub(super) fn new() -> Self {
        Self {
            alive: AtomicBool::new(true),
        }
    }

    pub(super) fn invalidate(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    pub(super) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

impl WriteScopeToken {
    pub fn lease_id(&self) -> Uuid {
        self.lease_id
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn scope(&self) -> &CanonicalScope {
        &self.scope
    }

    /// False once any authority-changing transition superseded this token.
    pub fn is_valid(&self) -> bool {
        self.core.is_alive()
    }
}

impl fmt::Debug for WriteScopeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteScopeToken")
            .field("lease_id", &self.lease_id)
            .field("generation", &self.generation)
            .field("scope", &self.scope.display().to_string())
            .field("valid", &self.is_valid())
            .finish()
    }
}

/// Typed failures from the write-scope coordinator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WriteScopeError {
    /// The single most important outcome of this subsystem: no filesystem
    /// backend can isolate arbitrary child syscalls for the requested scope, so
    /// strict writable delegation is refused before any authority changes.
    #[error("scoped writes unsupported: {reason}")]
    ScopedWritesUnsupported { reason: String },

    #[error("invalid write scope `{requested}`: {reason}")]
    InvalidScope { requested: String, reason: String },

    #[error(
        "write scope `{requested}` resolves to `{resolved}`, outside workspace `{workspace_root}`"
    )]
    ScopeEscapesWorkspace {
        requested: String,
        resolved: String,
        workspace_root: String,
    },

    #[error("`{candidate}` is not a strict sub-scope of `{base}`")]
    NotStrictSubscope { candidate: String, base: String },

    #[error("`{candidate}` intersects delegated exclusion `{exclusion}`")]
    IntersectsDelegatedExclusion {
        candidate: String,
        exclusion: String,
    },

    /// A concurrent contender won the versioned CAS. The loser creates no child
    /// record, token, or event.
    #[error("lost the write-scope transfer race for `{scope}`")]
    TransferRaceLost { scope: String },

    #[error(
        "stale write-scope token for lease {lease_id}: generation {token_generation}, current {current_generation}"
    )]
    StaleGeneration {
        lease_id: Uuid,
        token_generation: u64,
        current_generation: u64,
    },

    #[error("write denied: `{path}` is inside delegated sub-scope `{exclusion}`")]
    DeniedInsideDelegatedSubscope { path: String, exclusion: String },

    #[error("write denied: `{path}` is outside write scope `{scope}`")]
    OutsideScope { path: String, scope: String },

    /// The effective meaning of a path changed between authorization and
    /// syscall — an ancestor was renamed, removed, or replaced by a symlink.
    #[error("effective path for `{path}` changed after authorization; refusing to mutate")]
    EffectivePathChanged { path: String },

    #[error("illegal lease transition: {from} -> {to}")]
    IllegalTransition { from: String, to: String },

    #[error("illegal transfer phase advance: {from} -> {to}")]
    IllegalPhaseAdvance { from: String, to: String },

    #[error("write scope lease not found: {0}")]
    LeaseNotFound(Uuid),

    #[error("write scope transfer not found: {0}")]
    TransferNotFound(Uuid),

    /// Containment did not return ProvenEmpty, so authority must not be
    /// restored and the row is retained for recovery.
    #[error("containment not proven empty for transfer {transfer_id}: {reason}")]
    ContainmentNotProvenEmpty { transfer_id: Uuid, reason: String },

    /// A permit that overlaps the authority being removed is still in flight.
    #[error("{count} overlapping permit(s) still held; transfer barrier not drained")]
    PermitsNotDrained { count: usize },

    /// Another in-flight mutation could change this path's meaning before the
    /// syscall runs, so the two may not be held simultaneously.
    #[error("{count} conflicting in-flight mutation permit(s) overlap `{path}`")]
    ConflictingMutationPermits { count: usize, path: String },

    /// A descendant of the returning child still owns a delegated sub-scope.
    #[error("transfer {transfer_id} still has {count} live delegated descendant(s)")]
    DescendantStillDelegated { transfer_id: Uuid, count: usize },

    /// The empty oracle answered for a different containment generation, so it
    /// is not evidence about this child.
    #[error("containment generation mismatch: expected {expected}, oracle reported {got}")]
    ContainmentGenerationMismatch { expected: u64, got: u64 },

    /// The backend could not publish without aliasing or lost track of the
    /// target's identity. Authority is never restored after an uncertain
    /// publish.
    #[error("scoped write publication conflict: {reason}")]
    PublicationConflict { reason: String },

    #[error("session is deleting; new write-scope transfers rejected")]
    SessionDeleting,

    #[error("daemon is shutting down; new write-scope transfers rejected")]
    ShutdownIntakeClosed,

    /// Startup reconciliation could not match durable state to reality. The
    /// authority stays denied rather than guessing.
    #[error("write-scope recovery mismatch for {subject}: {reason}")]
    RecoveryMismatch { subject: String, reason: String },

    #[error("internal write-scope error: {0}")]
    Internal(String),
}

impl WriteScopeError {
    /// True for the fail-closed capability refusal. Callers turn this into a
    /// model-facing refusal rather than an internal error.
    pub fn is_unsupported(&self) -> bool {
        matches!(self, Self::ScopedWritesUnsupported { .. })
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self::ScopedWritesUnsupported {
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_ordinals_match_declared_order() {
        for (i, phase) in TransferPhase::ALL.iter().enumerate() {
            assert_eq!(phase.ordinal(), i, "{phase:?}");
            assert_eq!(TransferPhase::parse(phase.as_str()), Some(*phase));
        }
    }

    #[test]
    fn parent_is_denied_exactly_between_exclusion_and_restore() {
        assert!(!TransferPhase::Prepared.parent_denied_in_subscope());
        assert!(TransferPhase::ParentExcluded.parent_denied_in_subscope());
        assert!(TransferPhase::ChildActivated.parent_denied_in_subscope());
        assert!(TransferPhase::ChildTerminal.parent_denied_in_subscope());
        // Restoration is the point where the denial lifts.
        assert!(!TransferPhase::ParentRestored.parent_denied_in_subscope());
        assert!(!TransferPhase::Committed.parent_denied_in_subscope());
    }

    #[test]
    fn phase_next_walks_the_whole_sequence_once() {
        let mut phase = TransferPhase::Prepared;
        let mut seen = vec![phase];
        while let Some(next) = phase.next() {
            phase = next;
            seen.push(phase);
        }
        assert_eq!(seen, TransferPhase::ALL.to_vec());
    }

    #[test]
    fn illegal_lease_transitions_are_refused() {
        // Legal.
        assert!(LeaseState::Active.can_transition_to(LeaseState::Transferring));
        assert!(LeaseState::Transferring.can_transition_to(LeaseState::Delegated));
        assert!(LeaseState::Transferring.can_transition_to(LeaseState::Active));
        assert!(LeaseState::Delegated.can_transition_to(LeaseState::Returning));
        assert!(LeaseState::Returning.can_transition_to(LeaseState::Active));

        // Illegal: skipping the exclusion barrier entirely.
        assert!(!LeaseState::Active.can_transition_to(LeaseState::Delegated));
        // Illegal: un-delegating without draining the return barrier.
        assert!(!LeaseState::Delegated.can_transition_to(LeaseState::Active));
        // Illegal: resurrecting a released authority.
        assert!(!LeaseState::Released.can_transition_to(LeaseState::Active));
        assert!(!LeaseState::Released.can_transition_to(LeaseState::Transferring));
        // Illegal: self-transition is not an authority change.
        assert!(!LeaseState::Active.can_transition_to(LeaseState::Active));
    }

    #[test]
    fn token_invalidation_is_one_directional() {
        let core = Arc::new(TokenCore::new());
        let token = WriteScopeToken {
            lease_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            generation: 3,
            scope: CanonicalScope::from_canonical("/ws/a"),
            core: core.clone(),
        };
        assert!(token.is_valid());
        core.invalidate();
        assert!(!token.is_valid());
        // No API resurrects it.
        assert!(!token.is_valid());
    }
}
