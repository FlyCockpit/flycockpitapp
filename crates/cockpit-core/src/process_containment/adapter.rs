//! Platform containment adapter trait.
//!
//! Adapters own the same-generation empty oracle. Immediate child exit is never
//! that oracle. Tests inject adapters; they never mutate the host cgroup tree,
//! Job Objects, or real processes outside dedicated fixtures.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use cockpit_host::process::ProcessTreeGuard;
use uuid::Uuid;

use super::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, PlatformKind, SafeContainmentMetadata,
    SafeLocator,
};

/// Request to allocate a native containment generation.
///
/// `program` / `args` / `cwd` identify the intended child for audit; adapters
/// must not execute them. The caller spawns the real process (with its own
/// env and stdio) into [`ContainmentAdapter::process_tree_guard`].
#[derive(Clone)]
pub struct NativeSpawnRequest {
    pub containment_id: Uuid,
    pub session_id: Uuid,
    pub generation: u64,
    pub operation_id: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    /// Whether this is a strict Proven workflow (fails if Unsupported).
    pub require_proven: bool,
}

// Argv can carry inline credentials (`--token=…`): an argument count only.
impl std::fmt::Debug for NativeSpawnRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeSpawnRequest")
            .field("containment_id", &self.containment_id)
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("operation_id", &self.operation_id)
            .field("program", &self.program)
            .field("argument_count", &self.args.len())
            .field("cwd", &self.cwd)
            .field("require_proven", &self.require_proven)
            .finish()
    }
}

/// Request to allocate a fresh Docker/Podman container generation.
#[derive(Clone)]
pub struct ContainerExecRequest {
    pub containment_id: Uuid,
    pub session_id: Uuid,
    pub generation: u64,
    pub operation_id: String,
    pub image: String,
    pub command: Vec<String>,
    pub require_proven: bool,
    /// Installation identity hex for labels.
    pub installation_id: String,
    pub nonce: String,
}

impl std::fmt::Debug for ContainerExecRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContainerExecRequest")
            .field("containment_id", &self.containment_id)
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("operation_id", &self.operation_id)
            .field("image", &self.image)
            .field("command_word_count", &self.command.len())
            .field("require_proven", &self.require_proven)
            .field("installation_id", &self.installation_id)
            .finish_non_exhaustive()
    }
}

/// Result of a successful platform allocation. Membership is not proven here:
/// [`ContainmentAdapter::prove_membership`] is the kernel witness, and the
/// actor persists [`super::types::ContainmentEvent::MembershipProven`] only
/// after that returns `Ok`.
#[derive(Debug, Clone)]
pub struct AllocatedContainment {
    pub locator: SafeLocator,
    pub guarantee: ContainmentGuarantee,
    /// Opaque platform handle retained by the adapter (not durable).
    pub handle: AdapterHandle,
}

/// Opaque runtime handle held only by the actor/adapter (not serialized).
#[derive(Debug, Clone)]
pub struct AdapterHandle {
    pub key: String,
}

/// Platform adapter interface.
#[async_trait]
pub trait ContainmentAdapter: Send + Sync + 'static {
    fn platform_kind(&self) -> PlatformKind;
    fn guarantee(&self) -> ContainmentGuarantee;
    fn safe_metadata(&self) -> SafeContainmentMetadata;

    /// Probe capability without allocating. Never spawns user code.
    async fn probe(&self) -> Result<SafeContainmentMetadata, ContainmentError>;

    /// Native path: create the containment object. Must not run user
    /// instructions (`req.program` is identity/audit input, not a spawn).
    /// Callers place their own child via [`Self::process_tree_guard`], prove
    /// membership, then resume. Returns Unsupported before user code when the
    /// platform cannot provide Proven. Success is allocation only — never a
    /// membership witness.
    async fn create_and_spawn(
        &self,
        req: NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError>;

    /// Kernel membership proof for an allocated generation.
    ///
    /// Must fail closed for an empty Windows Job Object (`ActiveProcesses == 0`)
    /// or any other platform object that has never had a member placed. The
    /// actor persists `MembershipProven` only after this returns `Ok`.
    async fn prove_membership(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError>;

    /// Container path: fresh container per generation, full immutable ID oracle.
    async fn create_container_and_exec(
        &self,
        req: ContainerExecRequest,
    ) -> Result<AllocatedContainment, ContainmentError>;

    /// Terminate the containment object (not a PID list). Idempotent.
    async fn terminate(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError>;

    /// Same-generation empty oracle. Only ProvenEmpty is accepted by barriers.
    async fn await_empty(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError>;

    /// Startup recovery against durable locator. Never adopts unowned objects.
    async fn recover(
        &self,
        locator: &SafeLocator,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError>;

    /// Kernel job/group object the caller must spawn into. `None` on adapters
    /// that do not own a bindable object (fakes, container).
    fn process_tree_guard(&self, handle: &AdapterHandle) -> Option<Arc<ProcessTreeGuard>> {
        let _ = handle;
        None
    }
}

pub type SharedAdapter = Arc<dyn ContainmentAdapter>;

#[cfg(test)]
mod value_free_debug_tests {
    use super::*;

    /// Secrets r2 C1: containment requests print argument counts, not argv.
    #[test]
    fn spawn_request_debug_hides_argv() {
        let secret = ["NovelArgv515", "Secret78529"].concat();
        let request = NativeSpawnRequest {
            containment_id: Uuid::nil(),
            session_id: Uuid::nil(),
            generation: 1,
            operation_id: "op".into(),
            program: PathBuf::from("/bin/tool"),
            args: vec![format!("--token={secret}")],
            cwd: PathBuf::from("/tmp"),
            require_proven: false,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(&secret), "{rendered}");
    }
}
