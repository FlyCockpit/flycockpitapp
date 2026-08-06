//! Platform containment adapter trait.
//!
//! Adapters own the same-generation empty oracle. Immediate child exit is never
//! that oracle. Tests inject adapters; they never mutate the host cgroup tree,
//! Job Objects, or real processes outside dedicated fixtures.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use super::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, PlatformKind, SafeContainmentMetadata,
    SafeLocator,
};

/// Request to place the initial process inside kernel/runtime containment
/// before any user-controlled instruction runs.
#[derive(Debug, Clone)]
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

/// Request to allocate a fresh Docker/Podman container generation.
#[derive(Debug, Clone)]
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

/// Result of a successful platform allocation + membership proof.
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

    /// Native path: create containment object, place initial process, prove
    /// membership before user code. Returns Unsupported before user code when
    /// the platform cannot provide Proven.
    async fn create_and_spawn(
        &self,
        req: NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError>;

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
}

pub type SharedAdapter = Arc<dyn ContainmentAdapter>;
