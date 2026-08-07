//! Injected fixtures: a future-capable `MediatedCowWorkspace` backend and a
//! scriptable containment barrier.
//!
//! These exist so the barrier ordering, the external hard-link race, and every
//! crash/recovery interleaving can be exercised deterministically — no timing
//! sleeps, no real overlay filesystem, and no production COW backend (which
//! this prompt deliberately does not authorize).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use async_trait::async_trait;
use uuid::Uuid;

use super::backend::{
    ExecutionMode, InodeIdentity, ProvenScopedWriteAttestation, PublishOutcome, PublishRequest,
    ScopedWriteBackend, ScopedWriteCapability,
};
use super::containment::{
    ContainmentBarrier, ContainmentTicket, ExecutionLaunch, ProvenEmptyOutcome,
};
use super::coordinator::POPULATED_MARKER;
use super::coordinator::{OwnershipRecorded, OwnershipReserved};
use super::scope::CanonicalScope;
use super::types::WriteScopeError;

/// What the injected backend should do when the broker publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishBehavior {
    /// Publish a fresh unaliased inode.
    FreshInode,
    /// An external same-user hard link or namespace race was detected.
    Conflict { reason: String },
    /// **Negative-control only.** Mutate the existing backing inode in place
    /// instead of publishing a fresh one. No real backend may do this; it
    /// exists so the "never mutated an aliased backing inode" assertion can be
    /// shown to actually fail when the property is violated.
    MutateBackingInPlace,
}

/// A stand-in for the future `MediatedCowWorkspace` backend.
///
/// It attests the full clause set, so the coordinator treats it as Proven. It
/// never touches a real filesystem: publication is modelled as minting a new
/// inode identity, which is exactly the property the real backend must have
/// (copy-on-write / replace-only, never mutating an existing backing inode).
pub struct FakeMediatedCowBackend {
    attestation: Mutex<ProvenScopedWriteAttestation>,
    behavior: Mutex<PublishBehavior>,
    next_inode: AtomicU64,
    publishes: AtomicUsize,
    /// Inodes this backend has published, so a test can prove each publication
    /// produced a distinct, unaliased identity.
    published: Mutex<Vec<InodeIdentity>>,
    /// Backing inodes the fixture considers "already aliased". Publishing onto
    /// one of these would be a mutation of an aliased backing inode — the exact
    /// thing that must never happen.
    aliased_backing: Mutex<Vec<InodeIdentity>>,
    /// Backing inodes this backend actually wrote through. Stays empty for a
    /// correct COW publish; only `MutateBackingInPlace` fills it.
    mutated_backing: Mutex<Vec<InodeIdentity>>,
    /// Stable identity per scope, so `target_identity` is meaningful.
    identities: Mutex<std::collections::HashMap<String, InodeIdentity>>,
    /// When false this backend still attests the full clause set but cannot
    /// bind a scope to an inode identity — the "attests Proven but opts out of
    /// identity tracking" shape the coordinator must refuse.
    tracks_identity: Mutex<bool>,
}

impl Default for FakeMediatedCowBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeMediatedCowBackend {
    pub fn new() -> Self {
        Self {
            attestation: Mutex::new(ProvenScopedWriteAttestation::complete()),
            behavior: Mutex::new(PublishBehavior::FreshInode),
            next_inode: AtomicU64::new(1000),
            publishes: AtomicUsize::new(0),
            published: Mutex::new(Vec::new()),
            aliased_backing: Mutex::new(Vec::new()),
            mutated_backing: Mutex::new(Vec::new()),
            identities: Mutex::new(std::collections::HashMap::new()),
            tracks_identity: Mutex::new(true),
        }
    }

    /// Weaken one attestation clause to prove an incomplete attestation is
    /// treated as Unsupported.
    pub fn with_attestation(self, attestation: ProvenScopedWriteAttestation) -> Self {
        *self.attestation.lock().unwrap() = attestation;
        self
    }

    pub fn set_behavior(&self, behavior: PublishBehavior) {
        *self.behavior.lock().unwrap() = behavior;
    }

    pub fn mark_backing_aliased(&self, identity: InodeIdentity) {
        self.aliased_backing.lock().unwrap().push(identity);
    }

    pub fn publish_count(&self) -> usize {
        self.publishes.load(Ordering::SeqCst)
    }

    pub fn published_inodes(&self) -> Vec<InodeIdentity> {
        self.published.lock().unwrap().clone()
    }

    /// True when this backend never wrote through an inode the fixture marked
    /// aliased.
    ///
    /// This is checked against `mutated_backing` — inodes actually written
    /// through — not against `published`, which by construction only ever holds
    /// fresh identities. Checking `published` would make the assertion vacuous.
    pub fn never_mutated_an_aliased_backing_inode(&self) -> bool {
        let aliased = self.aliased_backing.lock().unwrap();
        self.mutated_backing
            .lock()
            .unwrap()
            .iter()
            .all(|id| !aliased.contains(id))
    }

    /// Inodes this backend wrote through in place (always empty for a correct
    /// COW publish).
    pub fn mutated_backing_inodes(&self) -> Vec<InodeIdentity> {
        self.mutated_backing.lock().unwrap().clone()
    }

    /// Make this backend attest Proven while refusing to report any inode
    /// identity. A real backend in this shape cannot prove replace-only
    /// publication, so the coordinator must fail closed before user code runs.
    pub fn without_identity_tracking(self) -> Self {
        *self.tracks_identity.lock().unwrap() = false;
        self
    }

    /// Force the identity this backend reports for a scope, so a test can make
    /// the recorded identity go stale.
    pub fn set_identity(&self, scope: &CanonicalScope, identity: InodeIdentity) {
        self.identities
            .lock()
            .unwrap()
            .insert(scope.display().to_string(), identity);
    }
}

impl ScopedWriteBackend for FakeMediatedCowBackend {
    fn kind(&self) -> &str {
        "fake_mediated_cow"
    }

    fn capability_for(
        &self,
        _scope: &CanonicalScope,
        _mode: ExecutionMode,
    ) -> ScopedWriteCapability {
        ScopedWriteCapability::Proven(*self.attestation.lock().unwrap())
    }

    fn target_identity(&self, scope: &CanonicalScope) -> Option<InodeIdentity> {
        if !*self.tracks_identity.lock().unwrap() {
            return None;
        }
        let key = scope.display().to_string();
        let mut identities = self.identities.lock().unwrap();
        let next = &self.next_inode;
        Some(
            *identities
                .entry(key)
                .or_insert_with(|| InodeIdentity(next.fetch_add(1, Ordering::SeqCst))),
        )
    }

    fn publish(&self, request: PublishRequest) -> PublishOutcome {
        self.publishes.fetch_add(1, Ordering::SeqCst);

        // The identity recorded at child start must still be the target's
        // identity. A change means the target or an ancestor was replaced while
        // the child ran, which is a namespace race, not a publishable result.
        if let Some(expected) = request.expected_target_identity {
            let current = self.target_identity(&request.scope);
            if current != Some(expected) {
                return PublishOutcome::Conflict {
                    reason: format!(
                        "publication target identity changed: recorded {expected:?}, now {current:?}"
                    ),
                };
            }
            if self.aliased_backing.lock().unwrap().contains(&expected) {
                return PublishOutcome::Conflict {
                    reason: "publication target is externally hard-linked".into(),
                };
            }
        }

        match self.behavior.lock().unwrap().clone() {
            PublishBehavior::FreshInode => {
                // Always a brand-new identity: replace-only, never a mutation
                // of an existing backing inode.
                let identity = InodeIdentity(self.next_inode.fetch_add(1, Ordering::SeqCst));
                self.published.lock().unwrap().push(identity);
                PublishOutcome::Published { identity }
            }
            PublishBehavior::Conflict { reason } => PublishOutcome::Conflict { reason },
            PublishBehavior::MutateBackingInPlace => {
                // Negative control: write through the existing backing inode.
                let backing = self
                    .target_identity(&request.scope)
                    .unwrap_or(InodeIdentity(0));
                self.mutated_backing.lock().unwrap().push(backing);
                self.published.lock().unwrap().push(backing);
                PublishOutcome::Published { identity: backing }
            }
        }
    }
}

/// What the fake containment should report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeEmptyBehavior {
    /// Same-generation oracle proves the group empty.
    ProvenEmpty,
    /// Reports ProvenEmpty but for a DIFFERENT generation, which is not
    /// evidence about the child the caller asked about.
    ProvenEmptyAtGeneration(u64),
    /// Proven *populated* — the child is live and keeps ownership.
    ProvenPopulated,
    /// Ambiguous: kill/wait/remove acknowledgement lost, etc.
    Uncertain { reason: String },
    /// The platform cannot prove containment.
    Unsupported { reason: String },
}

/// Records every barrier call so tests can assert exact ordering and the
/// absence of user code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierCall {
    Create { operation_id: String },
    ReleaseUserCode { containment_id: Uuid },
    AwaitEmpty { containment_id: Uuid },
    Terminate { containment_id: Uuid },
}

pub struct FakeContainmentBarrier {
    calls: Mutex<Vec<BarrierCall>>,
    /// Launch parameters seen by `create`, so a test can prove the child's real
    /// program/cwd reached containment rather than a daemon-global placeholder.
    launches: Mutex<Vec<ExecutionLaunch>>,
    empty_behavior: Mutex<FakeEmptyBehavior>,
    /// Force `create` to fail, to assert the unwind ordering.
    fail_create: Mutex<Option<String>>,
    /// Force membership proof / user-code release to fail.
    fail_release: Mutex<Option<String>>,
    next_generation: AtomicU64,
}

impl Default for FakeContainmentBarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeContainmentBarrier {
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            launches: Mutex::new(Vec::new()),
            empty_behavior: Mutex::new(FakeEmptyBehavior::ProvenEmpty),
            fail_create: Mutex::new(None),
            fail_release: Mutex::new(None),
            next_generation: AtomicU64::new(1),
        }
    }

    pub fn set_empty_behavior(&self, behavior: FakeEmptyBehavior) {
        *self.empty_behavior.lock().unwrap() = behavior;
    }

    pub fn fail_create_with(&self, reason: impl Into<String>) {
        *self.fail_create.lock().unwrap() = Some(reason.into());
    }

    pub fn fail_release_with(&self, reason: impl Into<String>) {
        *self.fail_release.lock().unwrap() = Some(reason.into());
    }

    pub fn calls(&self) -> Vec<BarrierCall> {
        self.calls.lock().unwrap().clone()
    }

    /// Launch parameters observed by `create`.
    pub fn launches(&self) -> Vec<ExecutionLaunch> {
        self.launches.lock().unwrap().clone()
    }

    /// True when user code was never released.
    pub fn user_code_never_released(&self) -> bool {
        !self
            .calls()
            .iter()
            .any(|c| matches!(c, BarrierCall::ReleaseUserCode { .. }))
    }

    pub fn created_count(&self) -> usize {
        self.calls()
            .iter()
            .filter(|c| matches!(c, BarrierCall::Create { .. }))
            .count()
    }

    pub fn terminated_count(&self) -> usize {
        self.calls()
            .iter()
            .filter(|c| matches!(c, BarrierCall::Terminate { .. }))
            .count()
    }
}

#[async_trait]
impl ContainmentBarrier for FakeContainmentBarrier {
    async fn create(
        &self,
        reserved: &OwnershipReserved,
        _mode: ExecutionMode,
        launch: &ExecutionLaunch,
    ) -> Result<ContainmentTicket, WriteScopeError> {
        self.launches.lock().unwrap().push(launch.clone());
        self.calls.lock().unwrap().push(BarrierCall::Create {
            operation_id: reserved.containment_operation_id(),
        });
        if let Some(reason) = self.fail_create.lock().unwrap().clone() {
            return Err(WriteScopeError::unsupported(reason));
        }
        Ok(ContainmentTicket {
            containment_id: Uuid::new_v4(),
            generation: self.next_generation.fetch_add(1, Ordering::SeqCst),
        })
    }

    async fn prove_membership_and_release_user_code(
        &self,
        recorded: &OwnershipRecorded,
    ) -> Result<(), WriteScopeError> {
        if let Some(reason) = self.fail_release.lock().unwrap().clone() {
            // Note: no ReleaseUserCode call is recorded on failure, so
            // `user_code_never_released()` stays true.
            return Err(WriteScopeError::unsupported(reason));
        }
        self.calls
            .lock()
            .unwrap()
            .push(BarrierCall::ReleaseUserCode {
                containment_id: recorded.containment_id(),
            });
        Ok(())
    }

    async fn await_proven_empty(&self, ticket: &ContainmentTicket) -> ProvenEmptyOutcome {
        self.calls.lock().unwrap().push(BarrierCall::AwaitEmpty {
            containment_id: ticket.containment_id,
        });
        match self.empty_behavior.lock().unwrap().clone() {
            FakeEmptyBehavior::ProvenEmpty => ProvenEmptyOutcome::ProvenEmpty {
                generation: ticket.generation,
            },
            FakeEmptyBehavior::ProvenEmptyAtGeneration(generation) => {
                ProvenEmptyOutcome::ProvenEmpty { generation }
            }
            FakeEmptyBehavior::ProvenPopulated => ProvenEmptyOutcome::Uncertain {
                generation: ticket.generation,
                reason: POPULATED_MARKER.to_string(),
            },
            FakeEmptyBehavior::Uncertain { reason } => ProvenEmptyOutcome::Uncertain {
                generation: ticket.generation,
                reason,
            },
            FakeEmptyBehavior::Unsupported { reason } => ProvenEmptyOutcome::Unsupported { reason },
        }
    }

    async fn terminate(&self, ticket: &ContainmentTicket) -> Result<(), WriteScopeError> {
        self.calls.lock().unwrap().push(BarrierCall::Terminate {
            containment_id: ticket.containment_id,
        });
        Ok(())
    }
}

/// An adversarial same-user process that creates and removes hard links and
/// renames ancestors around a scope — the thing Cockpit cannot mediate.
///
/// It operates on a real temporary directory so the escapes are genuine
/// syscalls, not simulated.
pub struct ExternalRaceFixture {
    root: std::path::PathBuf,
}

impl ExternalRaceFixture {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Create a hard link to `target` at `alias`, as an unrelated same-user
    /// process would. Returns whether the link was actually created.
    pub fn create_hard_link(&self, target: &str, alias: &str) -> std::io::Result<bool> {
        let target = self.root.join(target);
        let alias = self.root.join(alias);
        if let Some(parent) = alias.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::hard_link(&target, &alias) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub fn remove(&self, path: &str) -> std::io::Result<()> {
        std::fs::remove_file(self.root.join(path))
    }

    /// Rename an ancestor directory, changing the meaning of every path under
    /// it.
    pub fn rename_ancestor(&self, from: &str, to: &str) -> std::io::Result<()> {
        std::fs::rename(self.root.join(from), self.root.join(to))
    }

    /// Replace a directory with a symlink pointing elsewhere.
    #[cfg(unix)]
    pub fn replace_with_symlink(&self, path: &str, target: &str) -> std::io::Result<()> {
        let path = self.root.join(path);
        let target = self.root.join(target);
        std::fs::remove_dir_all(&path).ok();
        std::os::unix::fs::symlink(target, path)
    }

    /// Observed link count for a file.
    pub fn nlink(&self, path: &str) -> std::io::Result<u64> {
        let meta = std::fs::metadata(self.root.join(path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(meta.nlink())
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            Ok(1)
        }
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}
