//! Write-scope test suites, one module per acceptance criterion.
//!
//! Everything here uses injected registry / containment / backend / event /
//! clock seams. There is no `sleep`, no wall-clock dependence, and no reliance
//! on a real overlay filesystem — but the adversarial path cases (symlink
//! escape, `..` traversal, ancestor rename, hard-link aliasing) run against a
//! real temporary directory so the escapes are genuine syscalls.

use std::sync::Arc;

use uuid::Uuid;

use crate::db::Db;

use super::backend::{DirectWorkspaceBackend, ExecutionMode, SharedScopedWriteBackend};
use super::containment::ContainmentBarrier;
use super::coordinator::{Clock, TransferRequest, WriteScopeCoordinator};
use super::events::RecordingEventSink;
use super::fake::{FakeContainmentBarrier, FakeMediatedCowBackend};
use super::scope::CanonicalScope;

mod backend_fails_closed;
mod cancel_delete_shutdown;
mod concurrent_cas;
mod durable_invariant;
mod external_hard_link_race;
mod lease_state_machine;
mod parent_exclusion;
mod restart_recovery;
mod spawn_rename_inventory;
mod strict_subscope;
mod transfer_containment;

/// A deterministic clock; every call advances by one millisecond so ordering is
/// stable without any real time passing.
pub(super) fn test_clock() -> Clock {
    let counter = Arc::new(std::sync::atomic::AtomicI64::new(1_000));
    Arc::new(move || counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
}

/// A workspace on disk plus everything the coordinator needs.
pub(super) struct Harness {
    pub db: Db,
    pub session_id: Uuid,
    pub workspace: tempfile::TempDir,
    pub containment: Arc<FakeContainmentBarrier>,
    pub events: Arc<RecordingEventSink>,
    pub coordinator: WriteScopeCoordinator,
}

impl Harness {
    /// Harness whose backend is the production direct workspace (always
    /// Unsupported).
    pub async fn direct() -> Self {
        Self::with_backend(Arc::new(DirectWorkspaceBackend)).await
    }

    /// Harness with the injected future-capable Proven backend.
    pub async fn proven() -> (Self, Arc<FakeMediatedCowBackend>) {
        let backend = Arc::new(FakeMediatedCowBackend::new());
        let harness = Self::with_backend(backend.clone()).await;
        (harness, backend)
    }

    pub async fn with_backend(backend: SharedScopedWriteBackend) -> Self {
        let workspace = tempfile::tempdir().expect("workspace tempdir");
        // A few subtrees every suite can use.
        for dir in ["a", "a/inner", "b", "ab", "shared"] {
            std::fs::create_dir_all(workspace.path().join(dir)).unwrap();
        }
        let db = Db::open_in_memory().expect("in-memory db");
        let session_id = db
            .create_session(
                "proj",
                &workspace.path().display().to_string(),
                "orchestrator-build",
            )
            .await
            .expect("session")
            .session_id;

        let containment = Arc::new(FakeContainmentBarrier::new());
        let events = Arc::new(RecordingEventSink::new());
        let coordinator = WriteScopeCoordinator::new(
            db.clone(),
            backend.clone(),
            containment.clone() as Arc<dyn ContainmentBarrier>,
            events.clone(),
            test_clock(),
        );
        Self {
            db,
            session_id,
            workspace,
            containment,
            events,
            coordinator,
        }
    }

    pub fn root(&self) -> &std::path::Path {
        self.workspace.path()
    }

    /// Resolve a workspace-relative scope, failing the test on escape.
    pub fn scope(&self, relative: &str) -> CanonicalScope {
        CanonicalScope::resolve_under(self.root(), relative)
            .unwrap_or_else(|e| panic!("scope `{relative}` should resolve: {e}"))
    }

    /// The canonical workspace root as a scope.
    pub fn root_scope(&self) -> CanonicalScope {
        CanonicalScope::from_canonical(
            crate::path_containment::effective_path(self.root()).unwrap(),
        )
    }

    pub async fn open_root(&self, owner: &str) -> super::types::WriteScopeToken {
        self.coordinator
            .open_root_lease(self.session_id, owner, self.root_scope())
            .await
            .expect("root lease opens")
    }

    /// A transfer request for `relative` under `parent_lease_id`.
    pub fn request(&self, parent_lease_id: Uuid, relative: &str) -> TransferRequest {
        TransferRequest {
            parent_lease_id,
            session_id: self.session_id,
            sub_scope: self.scope(relative),
            child_owner_id: format!("child-{relative}"),
            task_id: Some(format!("task-{relative}")),
            mode: ExecutionMode::Native,
            launch: super::containment::ExecutionLaunch::Native {
                program: "/bin/true".into(),
                args: Vec::new(),
                cwd: self.root().to_path_buf(),
            },
            reachable_ancestor: None,
        }
    }
}
