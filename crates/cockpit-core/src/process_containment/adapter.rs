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

/// Cancellation ticket shared with privileged native spawners. On Linux its
/// memfd decision byte is locked across the broker's durable commit write, so
/// cancellation and release have one cross-process linearization point.
#[derive(Clone)]
pub(crate) struct AllocationCancellation {
    token: tokio_util::sync::CancellationToken,
    #[cfg(target_os = "linux")]
    decision: Arc<std::os::fd::OwnedFd>,
}

impl AllocationCancellation {
    pub(crate) fn new() -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        let decision = {
            use std::os::fd::{FromRawFd, OwnedFd};
            let fd = unsafe {
                libc::memfd_create(
                    c"flycockpit-allocation-decision".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                )
            };
            if fd < 0 { return Err(std::io::Error::last_os_error()); }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            if unsafe { libc::ftruncate(std::os::fd::AsRawFd::as_raw_fd(&fd), 1) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let seals = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
            if unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&fd), libc::F_ADD_SEALS, seals) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Arc::new(fd)
        };
        Ok(Self {
            token: tokio_util::sync::CancellationToken::new(),
            #[cfg(target_os = "linux")]
            decision,
        })
    }

    /// Durably wins (or observes loss of) the allocation decision without
    /// blocking a Tokio worker on `flock(2)` or `fsync(2)`.
    pub(crate) async fn cancel(&self) -> std::io::Result<()> {
        let cancellation = self.clone();
        tokio::task::spawn_blocking(move || cancellation.cancel_blocking())
            .await
            .map_err(std::io::Error::other)?
    }

    // Kept crate-visible for the Linux transaction unit tests, which exercise
    // the cross-process decision protocol without constructing a runtime.
    pub(crate) fn cancel_blocking(&self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let fd = self.decision.as_raw_fd();
            loop {
                if unsafe { libc::flock(fd, libc::LOCK_EX) } == 0 { break; }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted { return Err(error); }
            }
            let mut state = [0_u8];
            if unsafe { libc::pread(fd, state.as_mut_ptr().cast(), 1, 0) } != 1 {
                let error = std::io::Error::last_os_error();
                unsafe { libc::flock(fd, libc::LOCK_UN) };
                return Err(error);
            }
            if state[0] == 0 {
                let cancelled = [1_u8];
                if unsafe { libc::pwrite(fd, cancelled.as_ptr().cast(), 1, 0) } != 1
                    || unsafe { libc::fsync(fd) } != 0
                {
                    let error = std::io::Error::last_os_error();
                    unsafe { libc::flock(fd, libc::LOCK_UN) };
                    return Err(error);
                }
            }
            if unsafe { libc::flock(fd, libc::LOCK_UN) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        self.token.cancel();
        Ok(())
    }

    pub(crate) fn is_cancelled(&self) -> bool { self.token.is_cancelled() }

    #[cfg(target_os = "linux")]
    pub(crate) fn decision_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&*self.decision)
    }
}

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
    /// Byte-preserving ambient environment used only by the inherited-stdio
    /// native path on Unix. Hook I/O requests always leave this `None` and use
    /// the deliberately clean UTF-8 map above.
    pub(crate) inherited_env: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    /// Capture returns private pipes to the caller. The non-I/O containment
    /// API sets this false to preserve the native command contract: inherited
    /// environment and the daemon's exact stdio descriptors.
    pub(crate) capture_io: bool,
    pub(crate) require_proven: bool,
    /// Cancellation remains attached through the privileged prepare/commit
    /// transaction; it is not merely checked after allocation returns.
    pub(crate) cancellation: AllocationCancellation,
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
