//! Optional worktree orchestration, commitless artifact integration, and
//! conflict recovery.
//!
//! This is a coding-path capability, not a mandatory agent role. An agent
//! may edit in place, fan work out to managed worktrees, merge selected
//! artifacts, or apply them uncommitted. No orchestration path creates a
//! user-visible commit, stages unrelated files, or force-removes a pinned
//! or uncertain worktree.

mod artifact;
mod capability;
mod conflict;
mod integration;
mod lifecycle;
mod receipt;
mod validation;

#[cfg(test)]
mod tests;

pub use artifact::{
    ArtifactStore, ParentVisibleArtifact, ProducedArtifact, produce_artifact,
    produce_artifact_from_patch,
};
pub use capability::{
    DirectEditSession, FanOutSpec, ManagedChildWorktree, OrchestrationAction,
    OrchestrationCapability, OrchestratorInit, WorktreeOrchestrator,
};
pub use conflict::{ConflictResolution, ConflictSpecialist, ConflictSpecialistVerdict};
pub use integration::{
    IntegrationMode, IntegrationRequest, IntegrationResult, StaleReason, integrate_artifacts,
};
pub use lifecycle::{
    CleanupDenial, CleanupOutcome, cleanup_managed_worktree, pin_managed_worktree,
};
pub use receipt::repository_id as receipt_repository_id;
pub use receipt::{ArtifactPreconditions, WorkspaceReceipt, capture_workspace_receipt};
pub use validation::{
    CandidateValidation, ValidationEvidence, evidence_digest, worker_must_not_invoke_cargo,
    wt_test_wrapper_path,
};
