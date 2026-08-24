//! Platform containment adapter trait.
//!
//! Adapters own the same-generation empty oracle. Immediate child exit is never
//! that oracle. Tests inject adapters; they never mutate the host cgroup tree,
//! Job Objects, or real processes outside dedicated fixtures.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
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

/// Native command whose stdio must remain available to the caller while the
/// adapter retains process-placement authority. Arguments and environment are
/// deliberately transient and never enter containment records or diagnostics.
#[derive(Clone)]
pub struct NativeIoSpawnRequest {
    pub(crate) containment_id: Uuid,
    pub(crate) session_id: Uuid,
    pub(crate) generation: u64,
    pub(crate) operation_id: String,
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) cwd: PathBuf,
    pub(crate) env: BTreeMap<String, String>,
    /// Capture returns private pipes to the caller. The non-I/O containment
    /// API sets this false to preserve the native command contract: inherited
    /// environment and the daemon's exact stdio descriptors.
    pub(crate) capture_io: bool,
    pub(crate) require_proven: bool,
}

impl std::fmt::Debug for NativeIoSpawnRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeIoSpawnRequest")
            .field("containment_id", &self.containment_id)
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("argv_count", &self.args.len().saturating_add(1))
            .field("environment_key_count", &self.env.len())
            .field("capture_io", &self.capture_io)
            .field("require_proven", &self.require_proven)
            .finish_non_exhaustive()
    }
}

/// Local process endpoint returned only after membership has been proven.
/// This type is intentionally neither cloneable nor serializable.
pub struct NativeChildIo {
    pub(crate) stdin: Option<Pin<Box<dyn tokio::io::AsyncWrite + Send>>>,
    pub(crate) stdout: Option<Pin<Box<dyn tokio::io::AsyncRead + Send>>>,
    pub(crate) stderr: Option<Pin<Box<dyn tokio::io::AsyncRead + Send>>>,
    pub(crate) wait: Pin<Box<dyn Future<Output = std::io::Result<Option<i32>>> + Send>>,
}

impl std::fmt::Debug for NativeChildIo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeChildIo")
            .field("stdin", &self.stdin.is_some())
            .field("stdout", &self.stdout.is_some())
            .field("stderr", &self.stderr.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct AllocatedNativeIo {
    pub(crate) allocation: AllocatedContainment,
    pub(crate) io: NativeChildIo,
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

    /// Native path with actor-internal stdio endpoints. Only the hook executor
    /// may consume these endpoints, and it applies independent bounded drains
    /// under one operation deadline. Implementations must not release user
    /// code until membership is proven. Unsupported platforms return before
    /// spawning.
    async fn create_and_spawn_with_io(
        &self,
        _req: NativeIoSpawnRequest,
    ) -> Result<AllocatedNativeIo, ContainmentError> {
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: "native_containment_io_unsupported".into(),
        })
    }

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
