//! Durable hierarchical write-scope leases.
//!
//! `spawn` transfers a **strict sub-scope** of the caller's write authority to
//! a child. That transfer is durable, generation-checked, and crash-safe: an
//! in-memory overlap set cannot prove exclusive ownership across nested
//! transfer, daemon crash, late writes, and cancellation.
//!
//! # Fail-closed today
//!
//! Strict *writable* delegation requires a filesystem backend that can isolate
//! arbitrary child syscalls. The direct workspace cannot: a child can create or
//! open a hard link to another owner's file, or race an unrelated same-user
//! process, without passing through any Cockpit check. So
//! [`backend::DirectWorkspaceBackend`] — the only production adapter — always
//! answers `Unsupported`, and every strict writable delegated child fails with
//! [`WriteScopeError::ScopedWritesUnsupported`] *before* the parent is excluded,
//! before any child record/token/event exists, and before any user code runs.
//!
//! Delegation to a worker holding no Cockpit write tools, and non-delegated
//! behavior, are unaffected. Note that such a worker is not thereby prevented
//! from writing: it may still hold `bash`, whose sandbox permits writes under
//! the session cwd when no `write_scope` is set on its `ToolCtx`. See
//! [`crate::engine::schedule::authority::SpawnWorkerKind::is_write_capable`].
//!
//! A future `MediatedCowWorkspace` backend is specified by
//! [`backend::ProvenScopedWriteAttestation`] but intentionally not implemented
//! here; it needs its own reviewed foundation, dependencies, threat model, and
//! cross-platform race suite.

pub mod backend;
pub mod containment;
pub mod coordinator;
pub mod events;
pub mod fake;
pub mod permits;
pub mod scope;
pub mod types;

#[cfg(test)]
mod tests;

pub use backend::{
    DIRECT_WORKSPACE_UNSUPPORTED_REASON, DescriptorWalk, DirectWorkspaceBackend, ExecutionMode,
    HardLinkPreflight, InodeIdentity, ProvenScopedWriteAttestation, PublishOutcome, PublishRequest,
    ScopedWriteBackend, ScopedWriteCapability, SharedScopedWriteBackend, ShellSyntaxFilter,
};
pub use containment::{
    ContainmentBarrier, ContainmentTicket, ExecutionLaunch, ProcessContainmentBarrier,
    ProvenEmptyOutcome,
};
/// Late-install cell holding the daemon's single [`WriteScopeCoordinator`].
///
/// The coordinator is built during `boot_with_db`, after the session registry
/// and the driver already exist, so consumers hold this cell rather than a
/// resolved value — a snapshot taken at construction would always be `None`.
pub type WriteScopeSource =
    std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<coordinator::WriteScopeCoordinator>>>>;

pub use coordinator::{
    Clock, DelegationHandle, MutationPermit, OwnershipRecorded, OwnershipReserved, RecoveryOutcome,
    TransferRequest, WriteScopeCoordinator, system_clock, write_scope_containment_operation_id,
};
pub use events::{NullEventSink, RecordingEventSink, WriteScopeEvent, WriteScopeEventSink};
pub use permits::{MutationKind, PermitFootprint};
pub use scope::{CanonicalScope, EffectiveAuthority};
pub use types::{LeaseState, PermitKind, TransferPhase, WriteScopeError, WriteScopeToken};
