//! The closed `ScopedWriteBackend` capability.
//!
//! # Why this exists
//!
//! An arbitrary child process can call `link(2)`, `linkat(2)`,
//! `CreateHardLinkW`, open an already-linked inode, or race another same-user
//! process **without passing through any Cockpit-owned check**. Descriptor
//! walks, a preflight `nlink == 1`, shell syntax filtering, and pre-syscall
//! rechecks therefore never establish strict delegation — they are
//! defense-in-depth only.
//!
//! Process containment (cgroups, job objects, Docker, Podman) contains
//! *processes*. It does not mediate filesystem syscalls against a shared
//! workspace directory, so it cannot make one owner's subtree unreachable from
//! another owner's child. Capability is a property of the **filesystem**
//! backend, not of the process-containment platform — which is why every
//! execution mode below reports the same answer for the direct workspace.
//!
//! Consequently there is exactly one production adapter here,
//! [`DirectWorkspaceBackend`], and it always answers
//! [`ScopedWriteCapability::Unsupported`]. A future `MediatedCowWorkspace`
//! backend is *specified* by [`ProvenScopedWriteAttestation`] but deliberately
//! not implemented: it needs its own reviewed foundation, dependencies, threat
//! model, and cross-platform race suite.

use std::sync::Arc;

use super::scope::CanonicalScope;

/// Execution modes that can run arbitrary user code inside a scope.
///
/// All of them share the same host workspace on the direct backend, so all of
/// them get the same `Unsupported` answer. This enum exists so a test can
/// enumerate them and prove none is quietly special-cased into `Proven`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionMode {
    /// Native host process (`tools/bash`, direct spawn).
    Native,
    /// Zerobox sandboxed execution.
    Zerobox,
    Docker,
    Podman,
}

impl ExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Zerobox => "zerobox",
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    pub const ALL: &'static [ExecutionMode] =
        &[Self::Native, Self::Zerobox, Self::Docker, Self::Podman];
}

/// What a backend must attest before strict writable delegation is allowed.
///
/// Every field must hold. A partially-true attestation is `Unsupported`: there
/// is no `BestEffort` tier, because a single reachable alias defeats the whole
/// exclusivity claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProvenScopedWriteAttestation {
    /// Each writable owner sees a private filesystem view whose inode identity
    /// is distinct from the backing workspace.
    pub private_inode_view: bool,
    /// The backing tree is unreachable to the owner's child processes.
    pub backing_tree_unreachable: bool,
    /// Every other owner's upper layer is unreachable.
    pub other_uppers_unreachable: bool,
    /// Hard-link creation across owner boundaries is denied by the filesystem,
    /// not by a syntax filter.
    pub cross_owner_hard_link_denied: bool,
    /// Results are published only through the daemon broker, copy-on-write /
    /// replace-only, never mutating an existing backing inode.
    pub broker_only_replace_publication: bool,
    /// A crashed owner's private view is cleaned up without publishing.
    pub crash_cleanup: bool,
}

impl ProvenScopedWriteAttestation {
    /// A fully-attesting backend. Only test fixtures may construct this today.
    pub fn complete() -> Self {
        Self {
            private_inode_view: true,
            backing_tree_unreachable: true,
            other_uppers_unreachable: true,
            cross_owner_hard_link_denied: true,
            broker_only_replace_publication: true,
            crash_cleanup: true,
        }
    }

    /// Every clause must hold; there is no partial credit.
    pub fn is_complete(&self) -> bool {
        self.private_inode_view
            && self.backing_tree_unreachable
            && self.other_uppers_unreachable
            && self.cross_owner_hard_link_denied
            && self.broker_only_replace_publication
            && self.crash_cleanup
    }

    /// Names of the clauses that do not hold, for a precise refusal reason.
    pub fn missing_clauses(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.private_inode_view {
            out.push("private_inode_view");
        }
        if !self.backing_tree_unreachable {
            out.push("backing_tree_unreachable");
        }
        if !self.other_uppers_unreachable {
            out.push("other_uppers_unreachable");
        }
        if !self.cross_owner_hard_link_denied {
            out.push("cross_owner_hard_link_denied");
        }
        if !self.broker_only_replace_publication {
            out.push("broker_only_replace_publication");
        }
        if !self.crash_cleanup {
            out.push("crash_cleanup");
        }
        out
    }
}

/// Closed capability answer. Proven or Unsupported only — never BestEffort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopedWriteCapability {
    Proven(ProvenScopedWriteAttestation),
    Unsupported { reason: String },
}

impl ScopedWriteCapability {
    pub fn is_proven(&self) -> bool {
        matches!(self, Self::Proven(a) if a.is_complete())
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self::Unsupported {
            reason: reason.into(),
        }
    }
}

/// Opaque inode identity used to prove a publication produced a *fresh*,
/// unaliased inode rather than mutating an existing backing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InodeIdentity(pub u64);

/// A request to publish a child's private view back into the backing workspace.
#[derive(Debug, Clone)]
pub struct PublishRequest {
    pub scope: CanonicalScope,
    /// Identity the backend recorded for the publication target when the child
    /// started. A change means an ancestor or the target itself was replaced.
    pub expected_target_identity: Option<InodeIdentity>,
}

/// Result of a broker publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    /// A fresh, unaliased inode was published through the broker.
    Published { identity: InodeIdentity },
    /// An external same-user hard link or namespace race was detected. Nothing
    /// was published and authority must not be restored.
    Conflict { reason: String },
    /// This backend cannot publish at all.
    Unsupported { reason: String },
}

/// A filesystem backend that can (or cannot) isolate arbitrary child syscalls
/// within a write scope.
pub trait ScopedWriteBackend: Send + Sync {
    /// Stable label recorded on durable rows.
    fn kind(&self) -> &str;

    /// Capability for the *complete effective scope* under a given execution
    /// mode. Callers must probe the whole scope, not a sample path.
    fn capability_for(&self, scope: &CanonicalScope, mode: ExecutionMode) -> ScopedWriteCapability;

    /// Identity of the publication target as the backend currently sees it.
    ///
    /// Sampled *before* user code is released and handed back at publish time,
    /// so the backend can detect that the target or an ancestor was replaced
    /// while the child ran.
    ///
    /// There is deliberately **no default implementation**. A default returning
    /// `None` would let a backend attest the full clause set while silently
    /// opting out of identity tracking, and `publish` would then accept
    /// `expected_target_identity: None` and report `Published` after an
    /// undetected race. Identity tracking is part of the Proven contract:
    /// `broker_only_replace_publication` is unprovable without it. Returning
    /// `None` from an otherwise-Proven backend is a hard failure, not a
    /// degraded mode.
    fn target_identity(&self, scope: &CanonicalScope) -> Option<InodeIdentity>;

    /// Publish a child's results. Only meaningful for a Proven backend.
    fn publish(&self, request: PublishRequest) -> PublishOutcome;
}

pub type SharedScopedWriteBackend = Arc<dyn ScopedWriteBackend>;

/// Reason string used everywhere the direct workspace refuses.
pub const DIRECT_WORKSPACE_UNSUPPORTED_REASON: &str = "the direct workspace shares inode identity across owners: an arbitrary child process can \
     create or open a hard link (link/linkat/CreateHardLinkW) to a file inside another owner's \
     write scope, or race another same-user process, without passing through any Cockpit check. \
     Descriptor walks, nlink preflights, shell filters, and pre-syscall rechecks are \
     defense-in-depth only and cannot mediate arbitrary child syscalls. Strict writable \
     delegation requires a Proven MediatedCowWorkspace backend, which is not available";

/// The only production adapter: the workspace as it exists on disk today.
///
/// Always `Unsupported`, for every scope and every execution mode. This is the
/// fail-closed default that makes strict writable spawn refuse rather than
/// pretend.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectWorkspaceBackend;

impl ScopedWriteBackend for DirectWorkspaceBackend {
    fn kind(&self) -> &str {
        "direct_workspace"
    }

    fn capability_for(
        &self,
        _scope: &CanonicalScope,
        _mode: ExecutionMode,
    ) -> ScopedWriteCapability {
        // Deliberately ignores both arguments: there is no scope shape and no
        // execution mode for which the direct workspace can isolate arbitrary
        // child syscalls.
        ScopedWriteCapability::unsupported(DIRECT_WORKSPACE_UNSUPPORTED_REASON)
    }

    fn target_identity(&self, _scope: &CanonicalScope) -> Option<InodeIdentity> {
        // The direct workspace cannot bind a publication to a stable inode
        // identity: any same-user process may replace or alias the target. It is
        // Unsupported anyway, so this is never consulted for a real transfer.
        None
    }

    fn publish(&self, _request: PublishRequest) -> PublishOutcome {
        PublishOutcome::Unsupported {
            reason: DIRECT_WORKSPACE_UNSUPPORTED_REASON.to_string(),
        }
    }
}

/// A hard-link preflight observation.
///
/// Exists to be *documented as insufficient*. An `nlink == 1` reading is stale
/// the instant it is taken: an unrelated same-user process may link the inode
/// immediately afterward. This type therefore cannot be converted into a
/// capability — there is no method that returns Proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardLinkPreflight {
    pub nlink: u64,
    pub observed_at_wall_ms: i64,
}

impl HardLinkPreflight {
    /// Always false, regardless of `nlink`. A preflight finding no hard links
    /// is not stable evidence of exclusivity.
    pub fn establishes_strict_delegation(&self) -> bool {
        false
    }

    /// The capability a preflight can contribute: none.
    pub fn capability(&self) -> ScopedWriteCapability {
        ScopedWriteCapability::unsupported(
            "an nlink preflight is a point-in-time observation, not stable evidence: an unrelated \
             same-user process may link the inode immediately afterward",
        )
    }
}

/// A shell command filter. Also documented as insufficient: a child can reach
/// `link(2)` through any binary, interpreter, or already-open descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShellSyntaxFilter;

impl ShellSyntaxFilter {
    pub fn establishes_strict_delegation(&self) -> bool {
        false
    }

    pub fn capability(&self) -> ScopedWriteCapability {
        ScopedWriteCapability::unsupported(
            "shell syntax filtering cannot mediate arbitrary child syscalls: a child reaches \
             link(2) through any binary, interpreter, or inherited descriptor",
        )
    }
}

/// A descriptor walk over the scope. Also insufficient, for the same reason.
#[derive(Debug, Clone, Copy, Default)]
pub struct DescriptorWalk;

impl DescriptorWalk {
    pub fn establishes_strict_delegation(&self) -> bool {
        false
    }

    pub fn capability(&self) -> ScopedWriteCapability {
        ScopedWriteCapability::unsupported(
            "a descriptor walk observes the tree at one instant and cannot prevent a same-user \
             process from creating an alias afterward",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> CanonicalScope {
        CanonicalScope::from_canonical("/ws/a")
    }

    #[test]
    fn direct_workspace_is_unsupported_for_every_execution_mode() {
        let backend = DirectWorkspaceBackend;
        for mode in ExecutionMode::ALL {
            let cap = backend.capability_for(&scope(), *mode);
            assert!(
                !cap.is_proven(),
                "{} must never advertise Proven isolation",
                mode.as_str()
            );
            assert!(matches!(cap, ScopedWriteCapability::Unsupported { .. }));
        }
    }

    #[test]
    fn direct_workspace_cannot_publish() {
        let outcome = DirectWorkspaceBackend.publish(PublishRequest {
            scope: scope(),
            expected_target_identity: None,
        });
        assert!(matches!(outcome, PublishOutcome::Unsupported { .. }));
    }

    #[test]
    fn defense_in_depth_helpers_never_establish_delegation() {
        let preflight = HardLinkPreflight {
            nlink: 1,
            observed_at_wall_ms: 0,
        };
        assert!(!preflight.establishes_strict_delegation());
        assert!(!preflight.capability().is_proven());

        assert!(!ShellSyntaxFilter.establishes_strict_delegation());
        assert!(!ShellSyntaxFilter.capability().is_proven());
        assert!(!DescriptorWalk.establishes_strict_delegation());
        assert!(!DescriptorWalk.capability().is_proven());
    }

    #[test]
    fn attestation_requires_every_clause() {
        assert!(ProvenScopedWriteAttestation::complete().is_complete());
        assert!(
            ProvenScopedWriteAttestation::complete()
                .missing_clauses()
                .is_empty()
        );

        // Drop any single clause and the attestation fails.
        let mut partial = ProvenScopedWriteAttestation::complete();
        partial.cross_owner_hard_link_denied = false;
        assert!(!partial.is_complete());
        assert_eq!(
            partial.missing_clauses(),
            vec!["cross_owner_hard_link_denied"]
        );
        assert!(!ScopedWriteCapability::Proven(partial).is_proven());

        // The default (nothing attested) is not proven.
        assert!(!ProvenScopedWriteAttestation::default().is_complete());
    }
}
