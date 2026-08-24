//! Privilege-separated Linux cgroup-v2 containment broker.
//!
//! The workload process never receives a cgroup fd. The root-owned broker
//! verifies the connecting daemon's kernel credentials, creates a fresh
//! cgroup generation, and uses `clone3(CLONE_INTO_CGROUP)` so there is no
//! post-spawn migration window. Stdio and a pidfd are returned with
//! `SCM_RIGHTS`; all lifecycle authority remains at the broker socket.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::adapter::{
    AdapterHandle, AllocatedContainment, AllocatedNativeIo, NativeChildIo,
    NativeIoSpawnRequest,
};
use super::linux::{MANAGEMENT_BOUNDARY_UNAVAILABLE, ManagementBroker};
use super::types::{
    ContainmentError, ContainmentGuarantee, SafeLocator,
};

const PROTOCOL_VERSION: u32 = 1;
const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup/flycockpit";
const MAX_FRAME: usize = 1024 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 4096;
const MAX_ARGUMENTS: usize = 4096;
const MAX_STRING_BYTES: usize = 128 * 1024;
const SPAWN_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const AUTH_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);
const MAX_PREAUTH_CONNECTIONS: usize = 16;
const MAX_OPERATION_RECORDS_PER_EPOCH: usize = 65_536;
const BROKER_DIRECTORY: &str = "/run/flycockpit";
const REAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct LinuxBrokerConfig {
    pub socket_path: PathBuf,
    pub expected_broker_uid: u32,
    /// Root-opened capability descriptor delivered to the daemon by its
    /// service manager. The descriptor number is public; possession of an fd
    /// for the attested root-owned, mode-0400 inode is the bearer capability.
    pub capability_fd: Option<RawFd>,
}

impl LinuxBrokerConfig {
    pub fn production() -> Self {
        let workload_uid = unsafe { libc::geteuid() };
        Self {
            socket_path: PathBuf::from(format!(
                "/run/flycockpit/containment-broker-{workload_uid}.sock"
            )),
            expected_broker_uid: 0,
            capability_fd: inherited_named_fd("flycockpit-containment-capability"),
        }
    }
}

/// Resolves a systemd-style named descriptor without treating environment
/// metadata as authority. The returned descriptor is authenticated by fstat
/// and broker-side inode comparison before use.
pub fn inherited_named_fd(expected_name: &str) -> Option<RawFd> {
    let listen_pid = std::env::var("LISTEN_PID").ok()?.parse::<u32>().ok()?;
    if listen_pid != std::process::id() {
        return None;
    }
    let count = std::env::var("LISTEN_FDS").ok()?.parse::<usize>().ok()?;
    let names = std::env::var("LISTEN_FDNAMES").ok()?;
    let mut found = None;
    for (index, name) in names.split(':').take(count).enumerate() {
        if name == expected_name {
            if found.is_some() {
                return None;
            }
            found = i32::try_from(3 + index).ok();
        }
    }
    found
}

/// Performs the same peer, capability, framing, and kernel-contract handshake
/// used by the daemon. Installers use this instead of treating service-manager
/// liveness or socket metadata as proof of usable containment.
pub fn doctor_linux_containment_broker(config: LinuxBrokerConfig) -> std::io::Result<()> {
    let capability_raw = config.capability_fd.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "containment capability fd unavailable")
    })?;
    let capability = duplicate_valid_capability(capability_raw)?;
    let stream = connect_authenticated_stream(&config, capability.as_fd())?;
    stream.shutdown(std::net::Shutdown::Both)
}

#[derive(Debug, Clone)]
pub struct LinuxBrokerServerConfig {
    pub socket_path: PathBuf,
    pub cgroup_root: PathBuf,
    pub allowed_uid: u32,
    pub allowed_gid: u32,
    pub capability_fd: RawFd,
    pub state_root: PathBuf,
}

impl LinuxBrokerServerConfig {
    pub fn production(allowed_uid: u32, allowed_gid: u32) -> Self {
        Self {
            socket_path: PathBuf::from(format!(
                "/run/flycockpit/containment-broker-{allowed_uid}.sock"
            )),
            cgroup_root: PathBuf::from(DEFAULT_CGROUP_ROOT).join(format!("u{allowed_uid}")),
            allowed_uid,
            allowed_gid,
            capability_fd: -1,
            state_root: PathBuf::from(format!("/var/lib/flycockpit/containment-broker-{allowed_uid}")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Request {
    Authenticate { version: u32 },
    PrepareSpawn {
        version: u32,
        containment_id: String,
        session_id: String,
        generation: u64,
        operation_id: String,
        program: Vec<u8>,
        args: Vec<String>,
        cwd: Vec<u8>,
        env: Vec<(Vec<u8>, Vec<u8>)>,
        capture_io: bool,
        /// SHA-256 over the canonical, length-delimited spawn request. This is
        /// persisted with the operation identity so an idempotency key can
        /// never be replayed with different executable inputs.
        request_digest: String,
    },
    CommitSpawn { version: u32, session_id: String, operation_id: String },
    CancelOperation { version: u32, session_id: String, operation_id: String },
    OperationStatus { version: u32, session_id: String, operation_id: String },
    Kill { version: u32, key: String, generation: u64 },
    Populated { version: u32, key: String, generation: u64 },
    ExitStatus { version: u32, key: String, generation: u64 },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Response {
    Ready { version: u32, exclusive_delegation: bool },
    Prepared { version: u32, key: String, guard: GuardAttestation },
    Committed { version: u32, key: String },
    Cancelled { version: u32 },
    Operation { version: u32, state: OperationStatus, key: Option<String> },
    Killed { version: u32 },
    Population { version: u32, populated: bool },
    Exited { version: u32, exit_code: Option<i32> },
    Error { version: u32, code: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OperationStatus {
    Prepared,
    Committing,
    Committed,
    /// Kill has been requested but kernel-proven emptiness has not yet been
    /// observed. This durable state is retryable and must never be reported as
    /// cancellation success.
    CleanupRequired,
    /// Disconnect cleanup is pending kernel-proven emptiness.
    DisconnectCleanupRequired,
    Cancelled,
    /// The broker killed this generation because its authenticated owner
    /// disconnected. It must never be reconciled as a successful commit.
    DisconnectAborted,
    Exited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuardAttestation {
    pid: i32,
    clone_into_cgroup: bool,
    private_mount_ns: bool,
    private_cgroup_ns: bool,
    no_new_privs: bool,
    caps_cleared: bool,
    cgroup_mount_read_only: bool,
    seccomp_filter: bool,
}

impl GuardAttestation {
    fn proven(&self) -> bool {
        self.clone_into_cgroup
            && self.private_mount_ns
            && self.private_cgroup_ns
            && self.no_new_privs
            && self.caps_cleared
            && self.cgroup_mount_read_only
            && self.seccomp_filter
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LinuxBrokerClient {
    config: LinuxBrokerConfig,
    // The stream is CLOEXEC and broker-owned. SO_PEERCRED alone is deliberately
    // not treated as an exclusive daemon capability: another process under the
    // same uid can race the daemon. Production remains Unsupported until the
    // installer supplies a root-delivered capability fd to both endpoints.
    stream: Arc<Mutex<Option<UnixStream>>>,
    capability: Arc<OwnedFd>,
    ready: Arc<AtomicBool>,
}

impl LinuxBrokerClient {
    pub(crate) fn connect(config: LinuxBrokerConfig) -> std::io::Result<Self> {
        let capability_raw = config.capability_fd.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "containment capability fd unavailable")
        })?;
        let capability = duplicate_valid_capability(capability_raw)?;
        if unsafe { libc::fcntl(capability_raw, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Readiness is refreshed lazily. The daemon can start while systemd is
        // still bringing up (or restarting) the broker without permanently
        // pinning this adapter to AbsentBroker for its entire lifetime.
        let stream = connect_authenticated_stream(&config, capability.as_fd()).ok();
        unsafe { libc::close(capability_raw) };
        let ready = stream.is_some();
        Ok(Self {
            config,
            stream: Arc::new(Mutex::new(stream)),
            capability: Arc::new(capability),
            ready: Arc::new(AtomicBool::new(ready)),
        })
    }

    fn transact(&self, request: &Request) -> std::io::Result<(Response, Vec<OwnedFd>)> {
        self.transact_with_fds(request, &[])
    }

    fn transact_with_fds(
        &self,
        request: &Request,
        fds: &[RawFd],
    ) -> std::io::Result<(Response, Vec<OwnedFd>)> {
        let mut stream_slot = self.stream.lock().map_err(|_| std::io::Error::other("broker connection poisoned"))?;
        if stream_slot.is_none() {
            match connect_authenticated_stream(&self.config, self.capability.as_fd()) {
                Ok(stream) => {
                    *stream_slot = Some(stream);
                    self.ready.store(true, Ordering::Release);
                }
                Err(error) => {
                    self.ready.store(false, Ordering::Release);
                    return Err(error);
                }
            }
        }
        let stream = stream_slot.as_mut().expect("broker stream initialized");
        let body = serde_json::to_vec(request).map_err(invalid)?;
        let result = send_with_fds(stream.as_raw_fd(), &body, fds)
            .and_then(|()| recv_response_with_fds(stream));
        if result.is_err() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            *stream_slot = None;
            self.ready.store(false, Ordering::Release);
        }
        result
    }

    async fn cancel_and_prove(&self, session_id: &str, operation_id: &str) -> Result<(), ContainmentError> {
        let request = Request::CancelOperation {
            version: PROTOCOL_VERSION,
            session_id: session_id.to_owned(),
            operation_id: operation_id.to_owned(),
        };
        let client = self.clone();
        match tokio::task::spawn_blocking(move || client.transact(&request)).await {
            Ok(Ok((Response::Cancelled { version: PROTOCOL_VERSION }, fds))) if fds.is_empty() => Ok(()),
            _ => Err(unavailable()),
        }
    }
}

fn connect_authenticated_stream(
    config: &LinuxBrokerConfig,
    capability: BorrowedFd<'_>,
) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(&config.socket_path)?;
    verify_peer_uid(&stream, config.expected_broker_uid)?;
    stream.set_read_timeout(Some(FRAME_TIMEOUT))?;
    stream.set_write_timeout(Some(FRAME_TIMEOUT))?;
    let body = serde_json::to_vec(&Request::Authenticate { version: PROTOCOL_VERSION }).map_err(invalid)?;
    send_with_fds(stream.as_raw_fd(), &body, &[capability.as_raw_fd()])?;
    let (response, fds) = recv_response_with_fds(&stream)?;
    if !fds.is_empty() || !matches!(response, Response::Ready { version: PROTOCOL_VERSION, exclusive_delegation: true }) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "broker rejected containment capability"));
    }
    Ok(stream)
}

#[async_trait]
impl ManagementBroker for LinuxBrokerClient {
    fn distinct_identity(&self) -> bool {
        self.config.expected_broker_uid == 0 && unsafe { libc::geteuid() } != 0
    }

    fn exclusive_delegation(&self) -> bool {
        if self.ready.load(Ordering::Acquire) {
            return true;
        }
        let Ok(mut slot) = self.stream.lock() else { return false };
        if slot.is_none() {
            if let Ok(stream) = connect_authenticated_stream(&self.config, self.capability.as_fd()) {
                *slot = Some(stream);
                self.ready.store(true, Ordering::Release);
            }
        }
        self.ready.load(Ordering::Acquire)
    }

    async fn authenticate(&self, _: &str, _: &str, _: u64) -> bool {
        self.exclusive_delegation()
    }

    async fn spawn_with_io(
        &self,
        request: NativeIoSpawnRequest,
    ) -> Result<AllocatedNativeIo, ContainmentError> {
        if request.cancellation.is_cancelled() {
            return Err(ContainmentError::Internal("allocation request cancelled".into()));
        }
        let client = self.clone();
        let generation = request.generation;
        let containment_id = request.containment_id;
        let session_id = request.session_id.to_string();
        let operation_id = request.operation_id.clone();
        let program = request.program.as_os_str().as_bytes().to_vec();
        let cwd = request.cwd.as_os_str().as_bytes().to_vec();
        let mut environment = request.inherited_env.unwrap_or_else(|| {
            request.env.iter().map(|(key, value)| {
                (key.as_bytes().to_vec(), value.as_bytes().to_vec())
            }).collect()
        });
        // Environment order is not semantic. Canonical byte ordering makes
        // request digests stable across libc/hash-map enumeration order and
        // makes duplicate byte keys unambiguously invalid.
        environment.sort_by(|left, right| left.0.cmp(&right.0));
        validate_environment(&environment)
            .map_err(|error| ContainmentError::Internal(error.to_string()))?;
        let request_digest = canonical_spawn_digest(
            &containment_id.to_string(),
            &session_id,
            generation,
            &operation_id,
            &program,
            &request.args,
            &cwd,
            &environment,
            request.capture_io,
        );
        let wire = Request::PrepareSpawn {
            version: PROTOCOL_VERSION,
            containment_id: containment_id.to_string(),
            session_id: session_id.clone(),
            generation,
            operation_id: operation_id.clone(),
            program,
            args: request.args,
            cwd,
            env: environment,
            capture_io: request.capture_io,
            request_digest,
        };
        let capture_io = request.capture_io;
        let cancellation = request.cancellation.clone();
        let cancellation_fd = cancellation.decision_fd().as_raw_fd();
        let (response, mut fds) = tokio::task::spawn_blocking(move || {
            if capture_io {
                client.transact_with_fds(&wire, &[cancellation_fd])
            } else {
                client.transact_with_fds(
                    &wire,
                    &[
                        libc::STDIN_FILENO,
                        libc::STDOUT_FILENO,
                        libc::STDERR_FILENO,
                        cancellation_fd,
                    ],
                )
            }
        })
            .await
            .map_err(|error| ContainmentError::Internal(error.to_string()))?
            .map_err(|_| unavailable())?;
        let (key, guard) = match response {
            Response::Prepared { version: PROTOCOL_VERSION, key, guard } => (key, guard),
            Response::Error { code, .. } => {
                return Err(if matches!(
                    code.as_str(),
                    "kernel_feature_unsupported" | "broker_permission_denied"
                ) {
                    ContainmentError::DescendantContainmentUnavailable { reason: code }
                } else {
                    ContainmentError::Internal(code)
                });
            }
            _ => return Err(unavailable()),
        };
        if cancellation.is_cancelled() {
            self.cancel_and_prove(&session_id, &operation_id).await?;
            return Err(ContainmentError::Internal("allocation request cancelled".into()));
        }
        let expected_fd_count = if capture_io { 4 } else { 1 };
        if fds.len() != expected_fd_count
            || !guard.proven()
            || !verify_client_guard(
                &guard,
                &key,
                fds.last().expect("checked descriptor count").as_fd(),
            )
        {
            self.cancel_and_prove(&session_id, &operation_id).await?;
            return Err(unavailable());
        }
        let pidfd = fds.pop().expect("checked fd count");
        let (stdin, stdout, stderr) = if capture_io {
            let stderr = fds.pop().map(File::from);
            let stdout = fds.pop().map(File::from);
            let stdin = fds.pop().map(File::from);
            (stdin, stdout, stderr)
        } else {
            (None, None, None)
        };
        let commit = Request::CommitSpawn {
            version: PROTOCOL_VERSION,
            session_id: session_id.clone(),
            operation_id: operation_id.clone(),
        };
        if cancellation.is_cancelled() {
            self.cancel_and_prove(&session_id, &operation_id).await?;
            return Err(ContainmentError::Internal("allocation request cancelled".into()));
        }
        let commit_client = self.clone();
        let committed = match tokio::task::spawn_blocking(move || commit_client.transact(&commit)).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => {
                // The commit response may be lost after the broker durably
                // crossed the release boundary. Reconcile the operation; do
                // not blindly cancel a child which may already be running.
                let status_client = self.clone();
                let status = Request::OperationStatus {
                    version: PROTOCOL_VERSION,
                    session_id: session_id.clone(),
                    operation_id: operation_id.clone(),
                };
                match tokio::task::spawn_blocking(move || status_client.transact(&status)).await {
                    Ok(Ok((Response::Operation { version: PROTOCOL_VERSION, state: OperationStatus::Committed | OperationStatus::Exited, key: Some(status_key) }, fds)))
                        if status_key == key && fds.is_empty() =>
                    {
                        (Response::Committed { version: PROTOCOL_VERSION, key: status_key }, Vec::new())
                    }
                    _ => return Err(unavailable()),
                }
            }
        };
        let commit_valid = matches!(
            &committed,
            (Response::Committed { version: PROTOCOL_VERSION, key: committed_key }, extra)
                if committed_key == &key && extra.is_empty()
        );
        if !commit_valid {
            self.cancel_and_prove(&session_id, &operation_id).await?;
            return Err(unavailable());
        }
        if cancellation.is_cancelled() {
            self.cancel_and_prove(&session_id, &operation_id).await?;
            return Err(ContainmentError::Internal("allocation request cancelled".into()));
        }
        let async_pidfd = tokio::io::unix::AsyncFd::new(pidfd)
            .map_err(|error| ContainmentError::Internal(error.to_string()))?;
        let wait_client = self.clone();
        let wait_key = key.clone();
        let wait = Box::pin(async move {
            let mut ready = async_pidfd.readable().await?;
            ready.clear_ready();
            let request = Request::ExitStatus {
                version: PROTOCOL_VERSION,
                key: wait_key,
                generation,
            };
            tokio::task::spawn_blocking(move || match wait_client.transact(&request)? {
                (Response::Exited { version: PROTOCOL_VERSION, exit_code }, fds)
                    if fds.is_empty() => Ok(exit_code),
                _ => Err(invalid("invalid broker exit-status response")),
            })
            .await
            .map_err(std::io::Error::other)?
        });
        let io = NativeChildIo {
            stdin: stdin.map(|file| {
                Box::pin(tokio::fs::File::from_std(file))
                    as std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>
            }),
            stdout: stdout.map(|file| {
                Box::pin(tokio::fs::File::from_std(file))
                    as std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>
            }),
            stderr: stderr.map(|file| {
                Box::pin(tokio::fs::File::from_std(file))
                    as std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>
            }),
            wait,
        };
        Ok(AllocatedNativeIo {
            allocation: AllocatedContainment {
                locator: SafeLocator {
                    locator_key: Some(key.clone()),
                    nonce: Some(format!("g{generation}")),
                    installation_digest: Some("linux-broker-v1".into()),
                    ..Default::default()
                },
                guarantee: ContainmentGuarantee::Proven,
                handle: AdapterHandle { key },
            },
            io,
        })
    }

    async fn can_kill(&self, key: &str, generation: u64) -> bool {
        valid_key(key, generation)
    }

    async fn kill(&self, key: &str, generation: u64) -> Result<(), ContainmentError> {
        let client = self.clone();
        let request = Request::Kill { version: PROTOCOL_VERSION, key: key.into(), generation };
        match tokio::task::spawn_blocking(move || client.transact(&request)).await {
            Ok(Ok((Response::Killed { version: PROTOCOL_VERSION }, fds))) if fds.is_empty() => Ok(()),
            Ok(Ok((Response::Error { code, .. }, _))) => Err(ContainmentError::Internal(code)),
            Ok(Err(error)) => Err(ContainmentError::Internal(error.to_string())),
            Err(error) => Err(ContainmentError::Internal(error.to_string())),
            _ => Err(unavailable()),
        }
    }

    async fn populated(&self, key: &str, generation: u64) -> Option<bool> {
        let client = self.clone();
        let request = Request::Populated { version: PROTOCOL_VERSION, key: key.into(), generation };
        match tokio::task::spawn_blocking(move || client.transact(&request)).await {
            Ok(Ok((Response::Population { version: PROTOCOL_VERSION, populated }, fds)))
                if fds.is_empty() => Some(populated),
            _ => None,
        }
    }
}

fn unavailable() -> ContainmentError {
    ContainmentError::DescendantContainmentUnavailable {
        reason: MANAGEMENT_BOUNDARY_UNAVAILABLE.into(),
    }
}

/// Runs the blocking privileged broker. Service managers must start this as a
/// dedicated root identity with a private mount namespace and no network.
pub fn run_linux_containment_broker(config: LinuxBrokerServerConfig) -> std::io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    verify_canonical_cgroup_root(&config)?;
    let broker_capability = duplicate_valid_capability(config.capability_fd)?;
    unsafe { libc::close(config.capability_fd) };
    let recovered_empty = verify_server_installation(&config)?;
    verify_socket_location(&config)?;
    remove_owned_socket(&config.socket_path)?;
    let listener = UnixListener::bind(&config.socket_path)?;
    chown_path(&config.socket_path, 0, config.allowed_gid)?;
    set_mode(&config.socket_path, 0o660)?;
    let mut operations = recover_operation_records(&config, &recovered_empty)?;
    gc_terminal_operations(&config, &mut operations)?;
    let mut durable_empty = recovered_empty;
    durable_empty.extend(
        operations.values()
            .filter(|operation| matches!(operation.status, OperationStatus::Cancelled | OperationStatus::DisconnectAborted | OperationStatus::Exited))
            .map(|operation| operation.key.clone()),
    );
    let recovered_exit_statuses = operations.values()
        .filter_map(|operation| operation.exit_code.map(|code| (operation.key.clone(), Some(code))))
        .collect();
    let mut state = BrokerState {
        children: BTreeMap::new(),
        operations,
        emptied: durable_empty,
        exit_statuses: recovered_exit_statuses,
    };
    // Keep the root-owned listener alive for the service lifetime. A daemon
    // restart or a broken request connection must not require restarting the
    // privileged broker, and every replacement connection is independently
    // peer-credential and capability authenticated before it can issue a
    // request.
    loop {
        let mut stream = accept_authenticated_connection(
            &listener,
            config.allowed_uid,
            &broker_capability,
        )?;
        // An authenticated daemon may legitimately have no containment work
        // for an arbitrary period. A frame timeout here would turn ordinary
        // idleness into a disconnect and kill every active generation.
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(Some(FRAME_TIMEOUT))?;
        loop {
            retry_pending_cleanups(&config, &mut state);
            match serve_one(&mut stream, &config, &mut state) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    cleanup_connection_children(&config, &mut state);
                    break;
                }
                Err(error) => {
                    cleanup_connection_children(&config, &mut state);
                    // Malformed and unauthorized client traffic is scoped to
                    // that connection. The service remains available for a
                    // freshly authenticated daemon.
                    eprintln!("containment broker connection closed: {error}");
                    break;
                }
            }
        }
    }
}

fn accept_authenticated_connection(
    listener: &UnixListener,
    allowed_uid: u32,
    capability: &OwnedFd,
) -> std::io::Result<UnixStream> {
    let (authenticated_tx, authenticated_rx) = std::sync::mpsc::sync_channel(1);
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    listener.set_nonblocking(true)?;
    loop {
        if let Ok(stream) = authenticated_rx.try_recv() {
            listener.set_nonblocking(false)?;
            return Ok(stream);
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                if active.load(Ordering::Acquire) >= MAX_PREAUTH_CONNECTIONS {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                active.fetch_add(1, Ordering::AcqRel);
                let active = active.clone();
                let sender = authenticated_tx.clone();
                let expected = duplicate_valid_capability(capability.as_raw_fd())?;
                std::thread::spawn(move || {
                    let accepted = stream.set_read_timeout(Some(AUTH_FRAME_TIMEOUT)).is_ok()
                        && stream.set_write_timeout(Some(AUTH_FRAME_TIMEOUT)).is_ok()
                        && verify_peer_uid(&stream, allowed_uid).is_ok()
                        && authenticate_connection(&mut stream, &expected).is_ok();
                    if accepted {
                        let _ = sender.try_send(stream);
                    }
                    active.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(error) => {
                listener.set_nonblocking(false)?;
                return Err(error);
            }
        }
    }
}

#[derive(Default)]
struct BrokerState {
    children: BTreeMap<String, libc::pid_t>,
    operations: BTreeMap<(String, String), BrokerOperation>,
    emptied: BTreeSet<String>,
    exit_statuses: BTreeMap<String, Option<i32>>,
}

struct BrokerOperation {
    status: OperationStatus,
    key: String,
    generation: u64,
    request_digest: String,
    prepared: Option<Spawned>,
    exit_code: Option<i32>,
}

#[derive(Serialize, Deserialize)]
struct DurableOperation {
    /// Linux boot ID. Identities are immutable for this entire epoch; records
    /// from retired boots can be compacted because their processes and pidfds
    /// can no longer exist.
    broker_epoch: String,
    session_id: String,
    operation_id: String,
    status: OperationStatus,
    key: String,
    generation: u64,
    request_digest: String,
    #[serde(default)]
    exit_code: Option<i32>,
}

impl BrokerState {
    fn remember_empty(&mut self, key: String) {
        const MAX_TOMBSTONES: usize = 4096;
        self.emptied.insert(key);
        while self.emptied.len() > MAX_TOMBSTONES {
            if let Some(oldest) = self.emptied.iter().next().cloned() {
                self.emptied.remove(&oldest);
                self.exit_statuses.remove(&oldest);
            }
        }
    }
}

fn serve_one(
    stream: &mut UnixStream,
    config: &LinuxBrokerServerConfig,
    state: &mut BrokerState,
) -> std::io::Result<()> {
    // Idle authenticated connections are allowed indefinitely. Once the first
    // frame byte is readable, however, the complete bounded frame must arrive
    // within FRAME_TIMEOUT so a partial writer cannot monopolize the broker.
    wait_for_frame_start(stream.as_raw_fd())?;
    stream.set_read_timeout(Some(FRAME_TIMEOUT))?;
    let received = recv_with_fds(stream.as_raw_fd(), 4);
    let restore = stream.set_read_timeout(None);
    let (body, request_fds) = received?;
    restore?;
    let request: Request = serde_json::from_slice(&body).map_err(invalid)?;
    match request {
        Request::PrepareSpawn {
            version,
            containment_id,
            session_id,
            generation,
            operation_id,
            program,
            args,
            cwd,
            env,
            capture_io,
            request_digest,
        } if version == PROTOCOL_VERSION => {
            if (capture_io && request_fds.len() != 1)
                || (!capture_io && request_fds.len() != 4)
            {
                return send_response(stream, &Response::Error { version: PROTOCOL_VERSION, code: "invalid_stdio_descriptors".into() }, &[]);
            }
            if uuid::Uuid::parse_str(&session_id).is_err() || !valid_operation_id(&operation_id) {
                return send_response(
                    stream,
                    &Response::Error {
                        version: PROTOCOL_VERSION,
                        code: "invalid_spawn_request".into(),
                    },
                    &[],
                );
            }
            let operation_key = (session_id.clone(), operation_id.clone());
            let expected_digest = canonical_spawn_digest(
                &containment_id,
                &session_id,
                generation,
                &operation_id,
                &program,
                &args,
                &cwd,
                &env,
                capture_io,
            );
            if request_digest != expected_digest {
                return send_response(stream, &Response::Error { version: PROTOCOL_VERSION, code: "request_digest_mismatch".into() }, &[]);
            }
            let requested_key = containment_key(&containment_id, generation)?;
            if let Some(existing) = state.operations.get(&operation_key) {
                if existing.key != requested_key
                    || existing.generation != generation
                    || existing.request_digest != request_digest
                {
                    return send_response(stream, &Response::Error { version: PROTOCOL_VERSION, code: "operation_identity_conflict".into() }, &[]);
                }
                return match (&existing.status, &existing.prepared) {
                    (OperationStatus::Prepared, Some(spawned)) => {
                        let descriptors = prepared_response_fds(spawned, capture_io);
                        send_response(
                            stream,
                            &Response::Prepared { version: PROTOCOL_VERSION, key: existing.key.clone(), guard: spawned.guard.clone() },
                            &descriptors,
                        )
                    }
                    _ => send_response(stream, &Response::Operation { version: PROTOCOL_VERSION, state: existing.status, key: Some(existing.key.clone()) }, &[]),
                };
            }
            if state.operations.iter().any(|(identity, operation)| {
                operation.key == requested_key && identity != &operation_key
            }) {
                return send_response(
                    stream,
                    &Response::Error {
                        version: PROTOCOL_VERSION,
                        code: "containment_locator_already_bound".into(),
                    },
                    &[],
                );
            }
            if state.operations.len() >= MAX_OPERATION_RECORDS_PER_EPOCH {
                return send_response(
                    stream,
                    &Response::Error {
                        version: PROTOCOL_VERSION,
                        code: "broker_epoch_operation_limit_reached".into(),
                    },
                    &[],
                );
            }
            let inherited_stdio = (!capture_io).then(|| [
                request_fds[0].as_raw_fd(),
                request_fds[1].as_raw_fd(),
                request_fds[2].as_raw_fd(),
            ]);
            let cancellation_fd = request_fds.last()
                .expect("validated cancellation descriptor");
            verify_allocation_decision_fd(cancellation_fd.as_fd())?;
            let spawned = spawn_atomic(
                config,
                &containment_id,
                generation,
                &program,
                &args,
                &cwd,
                &env,
                inherited_stdio,
                reopen_fd(cancellation_fd.as_fd())?,
            );
            match spawned {
                Ok(spawned) => {
                    let key = spawned.key.clone();
                    // Publish ownership before any fallible durable write or
                    // response. From this point every failure path is visible
                    // to retry_pending_cleanups and cannot orphan a child.
                    state.operations.insert(operation_key.clone(), BrokerOperation {
                        status: OperationStatus::CleanupRequired,
                        key: key.clone(),
                        generation,
                        request_digest: request_digest.clone(),
                        prepared: Some(spawned),
                        exit_code: None,
                    });
                    if let Err(error) = persist_operation(
                        config,
                        &session_id,
                        &operation_id,
                        OperationStatus::Prepared,
                        &key,
                        generation,
                        &request_digest,
                    ) {
                        return Err(error);
                    }
                    let operation = state.operations.get_mut(&operation_key)
                        .expect("newly owned operation");
                    operation.status = OperationStatus::Prepared;
                    let spawned = operation.prepared.as_ref().expect("prepared child retained");
                    let descriptors = prepared_response_fds(spawned, capture_io);
                    let guard = spawned.guard.clone();
                    if let Err(error) = send_response(
                        &stream,
                        &Response::Prepared {
                            version: PROTOCOL_VERSION,
                            key,
                            guard,
                        },
                        &descriptors,
                    ) {
                        let operation = state.operations.get_mut(&operation_key)
                            .expect("owned operation survives response failure");
                        operation.status = OperationStatus::CleanupRequired;
                        let _ = persist_operation(
                            config,
                            &session_id,
                            &operation_id,
                            OperationStatus::CleanupRequired,
                            &operation.key,
                            generation,
                            &request_digest,
                        );
                        return Err(error);
                    }
                    Ok(())
                }
                Err(error) => send_response(
                    &stream,
                    &Response::Error {
                        version: PROTOCOL_VERSION,
                        code: broker_error_code(&error).into(),
                    },
                    &[],
                ),
            }
        }
        Request::CommitSpawn { version, session_id, operation_id }
            if version == PROTOCOL_VERSION => {
            let identity = (session_id.clone(), operation_id.clone());
            let (key, generation, digest) = {
                let operation = state.operations.get_mut(&identity)
                    .ok_or_else(|| invalid("unknown spawn operation"))?;
                if matches!(operation.status, OperationStatus::Committed | OperationStatus::Exited) {
                    return send_response(stream, &Response::Committed { version: PROTOCOL_VERSION, key: operation.key.clone() }, &[]);
                }
                if !matches!(operation.status, OperationStatus::Prepared) {
                    return send_response(stream, &Response::Error { version: PROTOCOL_VERSION, code: "operation_cancelled".into() }, &[]);
                }
                operation.status = OperationStatus::Committing;
                (
                    operation.key.clone(),
                    operation.generation,
                    operation.request_digest.clone(),
                )
            };
            let decision = state.operations.get(&identity)
                .and_then(|operation| operation.prepared.as_ref())
                .ok_or_else(|| invalid("prepared operation has no child"))?
                .cancellation.as_fd();
            match durably_choose_commit(decision, || {
                persist_operation(
                    config,
                    &session_id,
                    &operation_id,
                    OperationStatus::Committing,
                    &key,
                    generation,
                    &digest,
                )
            }) {
                Ok(true) => {}
                Ok(false) => {
                    state.operations.get_mut(&identity).expect("operation exists").status = OperationStatus::Prepared;
                    return send_response(
                        stream,
                        &Response::Error {
                            version: PROTOCOL_VERSION,
                            code: "operation_cancelled_before_release".into(),
                        },
                        &[],
                    );
                }
                Err(error) => {
                    state.operations.get_mut(&identity).expect("operation exists").status = OperationStatus::CleanupRequired;
                    let _ = persist_operation(
                        config,
                        &session_id,
                        &operation_id,
                        OperationStatus::CleanupRequired,
                        &key,
                        generation,
                        &digest,
                    );
                    return Err(error);
                }
            }
            let mut spawned = state.operations.get_mut(&identity)
                .expect("operation exists")
                .prepared.take()
                .ok_or_else(|| invalid("prepared operation has no child"))?;
            if let Err(error) = release_child(&mut spawned) {
                let operation = state.operations.get_mut(&identity).expect("operation exists");
                operation.status = OperationStatus::CleanupRequired;
                let _ = persist_operation(config, &session_id, &operation_id, OperationStatus::CleanupRequired, &key, generation, &digest);
                if rollback_generation(&config.cgroup_root.join(&key), spawned.pid).is_err() {
                    state.children.insert(key.clone(), spawned.pid);
                }
                return Err(error);
            }
            // Publish cleanup ownership in memory immediately after release.
            // A failed durable Committed write then closes the connection and
            // cleanup_connection_children still kills and proves this child
            // empty instead of orphaning an untracked running generation.
            state.children.insert(key.clone(), spawned.pid);
            {
                let operation = state.operations.get_mut(&identity).expect("operation exists");
                operation.status = OperationStatus::Committed;
            }
            persist_operation(config, &session_id, &operation_id, OperationStatus::Committed, &key, generation, &digest)?;
            send_response(stream, &Response::Committed { version: PROTOCOL_VERSION, key }, &[])
        }
        Request::CancelOperation { version, session_id, operation_id }
            if version == PROTOCOL_VERSION => {
            let identity = (session_id.clone(), operation_id.clone());
            let Some(operation) = state.operations.get_mut(&identity) else {
                return send_response(stream, &Response::Error { version: PROTOCOL_VERSION, code: "operation_not_found".into() }, &[]);
            };
            if matches!(operation.status, OperationStatus::Cancelled) {
                return send_response(stream, &Response::Cancelled { version: PROTOCOL_VERSION }, &[]);
            }
            if matches!(operation.status, OperationStatus::DisconnectAborted | OperationStatus::Exited) {
                return send_response(stream, &Response::Error { version: PROTOCOL_VERSION, code: "operation_already_terminal".into() }, &[]);
            }
            let key = operation.key.clone();
            let generation = operation.generation;
            let digest = operation.request_digest.clone();
            operation.status = OperationStatus::CleanupRequired;
            if let Err(error) = persist_operation(config, &session_id, &operation_id, OperationStatus::CleanupRequired, &key, generation, &digest) {
                // Ownership is deliberately retained. The old durable state
                // remains authoritative and a retry can make progress.
                return Err(error);
            }
            let prepared = state.operations.get_mut(&identity)
                .expect("operation exists")
                .prepared.take();

            let pid = prepared.as_ref().map(|spawned| spawned.pid)
                .or_else(|| state.children.get(&key).copied());
            if let Some(pid) = pid {
                state.children.insert(key.clone(), pid);
            }
            if let Err(error) = cleanup_generation(config, &key, generation, pid, REAP_TIMEOUT) {
                // CleanupRequired plus children ownership remains retryable;
                // never acknowledge cancellation without ProvenEmpty.
                return Err(error);
            }
            if let Some(pid) = state.children.remove(&key) {
                let status = reap_child(pid)?;
                state.exit_statuses.insert(key.clone(), status);
            }
            state.remember_empty(key.clone());
            let operation = state.operations.get_mut(&identity).expect("operation exists");
            operation.status = OperationStatus::Cancelled;
            persist_operation(config, &session_id, &operation_id, OperationStatus::Cancelled, &key, generation, &digest)?;
            send_response(stream, &Response::Cancelled { version: PROTOCOL_VERSION }, &[])
        }
        Request::OperationStatus { version, session_id, operation_id }
            if version == PROTOCOL_VERSION => {
            let operation = state.operations.get(&(session_id, operation_id));
            match operation {
                Some(operation) => send_response(stream, &Response::Operation { version: PROTOCOL_VERSION, state: operation.status, key: Some(operation.key.clone()) }, &[]),
                None => send_response(stream, &Response::Error { version: PROTOCOL_VERSION, code: "operation_not_found".into() }, &[]),
            }
        }
        Request::Kill { version, key, generation } if version == PROTOCOL_VERSION => {
            if state.emptied.contains(&key) {
                return send_response(&stream, &Response::Killed { version: PROTOCOL_VERSION }, &[]);
            }
            let Some(path) = resolve_key_if_present(config, &key, generation)? else {
                state.remember_empty(key);
                return send_response(&stream, &Response::Killed { version: PROTOCOL_VERSION }, &[]);
            };
            fs::write(path.join("cgroup.kill"), b"1")?;
            send_response(&stream, &Response::Killed { version: PROTOCOL_VERSION }, &[])
        }
        Request::Populated { version, key, generation } if version == PROTOCOL_VERSION => {
            if state.emptied.contains(&key) {
                return send_response(
                    &stream,
                    &Response::Population { version: PROTOCOL_VERSION, populated: false },
                    &[],
                );
            }
            let Some(path) = resolve_key_if_present(config, &key, generation)? else {
                // The canonical root and key namespace are exclusively owned
                // by this broker. Absence below that attested root is therefore
                // a durable kernel-backed empty proof, including after terminal
                // operation records have been garbage-collected.
                state.remember_empty(key);
                return send_response(
                    &stream,
                    &Response::Population { version: PROTOCOL_VERSION, populated: false },
                    &[],
                );
            };
            let events = fs::read_to_string(path.join("cgroup.events"))?;
            let populated = parse_populated(&events)?;
            if !populated {
                if let Some(pid) = state.children.get(&key).copied() {
                    let exit_status = reap_child(pid)?;
                    state.exit_statuses.insert(key.clone(), exit_status);
                    state.children.remove(&key);
                }
                fs::remove_dir(&path)?;
                state.remember_empty(key.clone());
                mark_operation_terminal(config, state, &key, OperationStatus::Exited)?;
                persist_exit_status_for_key(config, state, &key)?;
            }
            send_response(&stream, &Response::Population { version: PROTOCOL_VERSION, populated }, &[])
        }
        Request::ExitStatus { version, key, generation } if version == PROTOCOL_VERSION => {
            if !valid_key(&key, generation) {
                return Err(invalid("invalid containment key"));
            }
            let exit_code = if let Some(exit_code) = state.exit_statuses.get(&key) {
                *exit_code
            } else {
                let pid = state.children.get(&key).copied().ok_or_else(|| invalid("unknown child"))?;
                let exit_code = reap_child(pid)?;
                state.children.remove(&key);
                state.exit_statuses.insert(key.clone(), exit_code);
                exit_code
            };
            mark_operation_terminal(config, state, &key, OperationStatus::Exited)?;
            persist_exit_status_for_key(config, state, &key)?;
            send_response(&stream, &Response::Exited { version: PROTOCOL_VERSION, exit_code }, &[])
        }
        _ => send_response(
            &stream,
            &Response::Error { version: PROTOCOL_VERSION, code: "protocol_mismatch".into() },
            &[],
        ),
    }
}

struct Spawned {
    key: String,
    pid: libc::pid_t,
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
    pidfd: OwnedFd,
    release: OwnedFd,
    cancellation: OwnedFd,
    guard: GuardAttestation,
}

fn prepared_response_fds(spawned: &Spawned, capture_io: bool) -> Vec<RawFd> {
    if capture_io {
        vec![
            spawned.stdin.as_raw_fd(),
            spawned.stdout.as_raw_fd(),
            spawned.stderr.as_raw_fd(),
            spawned.pidfd.as_raw_fd(),
        ]
    } else {
        vec![spawned.pidfd.as_raw_fd()]
    }
}

fn reopen_fd(fd: BorrowedFd<'_>) -> std::io::Result<OwnedFd> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    let reopened: OwnedFd = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)?
        .into();
    if !same_capability_inode(fd, reopened.as_fd())? {
        return Err(invalid("reopened allocation decision identity changed"));
    }
    Ok(reopened)
}

fn verify_allocation_decision_fd(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let metadata = fd_stat(fd)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG || metadata.st_size != 1 {
        return Err(invalid("invalid allocation decision descriptor"));
    }
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    let required = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if seals < 0 || seals & required != required {
        return Err(invalid("allocation decision descriptor is not size-sealed"));
    }
    let mut state = [0_u8];
    if unsafe { libc::pread(fd.as_raw_fd(), state.as_mut_ptr().cast(), 1, 0) } != 1
        || state[0] > 1
    {
        return Err(invalid("invalid allocation decision state"));
    }
    Ok(())
}

fn durably_choose_commit(
    fd: BorrowedFd<'_>,
    persist: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<bool> {
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = (|| {
        let mut state = [0_u8];
        if unsafe { libc::pread(fd.as_raw_fd(), state.as_mut_ptr().cast(), 1, 0) } != 1 {
            return Err(std::io::Error::last_os_error());
        }
        if state[0] == 1 { return Ok(false); }
        if state[0] != 0 { return Err(invalid("allocation decision was already finalized")); }
        // Hold the cross-process decision lock through durable persistence.
        // A cancellation which linearized first wrote 1; otherwise this write
        // records the winning commit before any user byte is released.
        persist()?;
        let committed = [2_u8];
        if unsafe { libc::pwrite(fd.as_raw_fd(), committed.as_ptr().cast(), 1, 0) } != 1
            || unsafe { libc::fsync(fd.as_raw_fd()) } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(true)
    })();
    let unlock = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_UN) };
    if unlock != 0 && result.is_ok() { return Err(std::io::Error::last_os_error()); }
    result
}

fn spawn_atomic(
    config: &LinuxBrokerServerConfig,
    containment_id: &str,
    generation: u64,
    program: &[u8],
    args: &[String],
    cwd: &[u8],
    env: &[(Vec<u8>, Vec<u8>)],
    inherited_stdio: Option<[RawFd; 3]>,
    cancellation: OwnedFd,
) -> std::io::Result<Spawned> {
    let key = containment_key(containment_id, generation)?;
    if args.len() > MAX_ARGUMENTS || env.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(invalid("spawn request exceeds entry limit"));
    }
    if program.is_empty()
        || program.len() > MAX_STRING_BYTES
        || cwd.is_empty()
        || cwd.len() > MAX_STRING_BYTES
        || args.iter().any(|value| value.len() > MAX_STRING_BYTES)
    {
        return Err(invalid("spawn request exceeds string limit"));
    }
    validate_environment(env)?;
    let group = config.cgroup_root.join(&key);
    let program = CString::new(program).map_err(|_| invalid("program contains NUL"))?;
    let cwd = CString::new(cwd).map_err(|_| invalid("cwd contains NUL"))?;
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program.clone());
    for arg in args {
        argv.push(CString::new(arg.as_bytes()).map_err(|_| invalid("argument contains NUL"))?);
    }
    let environment = env
        .iter()
        .map(|(key, value)| {
            let mut entry = Vec::with_capacity(key.len() + value.len() + 1);
            entry.extend_from_slice(key);
            entry.push(b'=');
            entry.extend_from_slice(value);
            CString::new(entry)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("environment contains NUL"))?;
    fs::create_dir(&group)?;
    let mut generation_guard = GenerationDirGuard::new(group.clone());
    set_mode(&group, 0o755)?;
    verify_root_owned_migration_file(&group.join("cgroup.procs"))?;
    if !group.join("cgroup.kill").is_file() || !group.join("cgroup.events").is_file() {
        let _ = fs::remove_dir(&group);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "cgroup kill/population oracle unavailable",
        ));
    }
    let cgroup = OpenOptions::new().read(true).open(&group)?;
    let (stdin_read, stdin_write) = pipe_cloexec()?;
    let (stdout_read, stdout_write) = pipe_cloexec()?;
    let (stderr_read, stderr_write) = pipe_cloexec()?;
    let (status_read, status_write) = pipe_cloexec()?;
    let (release_read, release_write) = pipe_cloexec()?;
    let mut argv_ptrs = argv.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs = environment.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    env_ptrs.push(std::ptr::null());
    let seccomp = seccomp_guard_program();
    let cap_last = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Unsupported, "capability ceiling unavailable"))?;

    let mut pidfd_raw: i32 = -1;
    let mut clone_args = CloneArgs {
        flags: CLONE_INTO_CGROUP | libc::CLONE_PIDFD as u64,
        pidfd: (&mut pidfd_raw as *mut i32) as u64,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup.as_raw_fd() as u64,
        ..CloneArgs::default()
    };
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut clone_args as *mut CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        ) as libc::pid_t
    };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            child_exec(
                config,
                inherited_stdio.map_or(stdin_read.as_raw_fd(), |stdio| stdio[0]),
                inherited_stdio.map_or(stdout_write.as_raw_fd(), |stdio| stdio[1]),
                inherited_stdio.map_or(stderr_write.as_raw_fd(), |stdio| stdio[2]),
                status_write.as_raw_fd(),
                release_read.as_raw_fd(),
                &program,
                &cwd,
                &argv_ptrs,
                &env_ptrs,
                &seccomp,
                cap_last,
            )
        }
    }
    drop(stdin_read);
    drop(stdout_write);
    drop(stderr_write);
    drop(status_write);
    drop(release_read);
    let status = File::from(status_read);
    let mut errno = [0_u8; 4];
    match read_exec_handshake(status.as_raw_fd(), &mut errno, SPAWN_HANDSHAKE_TIMEOUT) {
        Ok(1) if errno[0] == 1 => {}
        Ok(4) => {
            let _ = rollback_generation(&group, pid);
            return Err(std::io::Error::from_raw_os_error(i32::from_ne_bytes(errno)));
        }
        Ok(_) | Err(_) => {
            let _ = rollback_generation(&group, pid);
            return Err(std::io::Error::other("child exec handshake failed"));
        }
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
    generation_guard.disarm();
    Ok(Spawned {
        key,
        pid,
        stdin: stdin_write,
        stdout: stdout_read,
        stderr: stderr_read,
        pidfd,
        release: release_write,
        cancellation,
        guard: GuardAttestation {
            pid,
            clone_into_cgroup: true,
            private_mount_ns: true,
            private_cgroup_ns: true,
            no_new_privs: true,
            caps_cleared: true,
            cgroup_mount_read_only: true,
            seccomp_filter: true,
        },
    })
}

fn containment_key(containment_id: &str, generation: u64) -> std::io::Result<String> {
    let id = uuid::Uuid::parse_str(containment_id)
        .map_err(|_| invalid("invalid containment id"))?;
    if generation == 0 {
        return Err(invalid("invalid generation"));
    }
    Ok(format!("fc-{}-g{}", id.simple(), generation))
}

unsafe fn child_exec(
    config: &LinuxBrokerServerConfig,
    stdin: RawFd,
    stdout: RawFd,
    stderr: RawFd,
    status: RawFd,
    release: RawFd,
    program: &CString,
    cwd: &CString,
    argv: &[*const libc::c_char],
    env: &[*const libc::c_char],
    seccomp: &[libc::sock_filter],
    cap_last: u32,
) -> ! {
    if unsafe { libc::dup2(stdin, libc::STDIN_FILENO) } < 0
        || unsafe { libc::dup2(stdout, libc::STDOUT_FILENO) } < 0
        || unsafe { libc::dup2(stderr, libc::STDERR_FILENO) } < 0
        || unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWCGROUP) } != 0
        || unsafe { libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) } != 0
        || unsafe { make_cgroup_mounts_read_only() }.is_err()
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        unsafe { child_fail(status, std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EPERM)) };
    }
    for capability in 0..=cap_last {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            unsafe { child_fail(status, libc::EPERM) };
        }
    }
    if unsafe { install_seccomp_guard(seccomp) }.is_err()
        || unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0
        || unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setgid(config.allowed_gid) } != 0
        || unsafe { libc::setuid(config.allowed_uid) } != 0
        || !unsafe { capabilities_are_empty() }
        || unsafe { libc::chdir(cwd.as_ptr()) } != 0
    {
        unsafe { child_fail(status, libc::EPERM) };
    }
    let ready = [1_u8];
    if unsafe { libc::write(status, ready.as_ptr().cast(), ready.len()) } != 1 {
        unsafe { child_fail(status, libc::EPIPE) };
    }
    let mut released = [0_u8];
    if unsafe { libc::read(release, released.as_mut_ptr().cast(), 1) } != 1 || released[0] != 1 {
        unsafe { child_fail(status, libc::ECANCELED) };
    }
    unsafe { libc::execve(program.as_ptr(), argv.as_ptr(), env.as_ptr()) };
    unsafe { child_fail(status, std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::ENOEXEC)) }
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

unsafe fn make_cgroup_mounts_read_only() -> std::io::Result<()> {
    const AT_RECURSIVE: u32 = 0x8000;
    const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
    let attributes = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mut found_primary = false;
    for line in mountinfo.lines() {
        let mut halves = line.split(" - ");
        let Some(left) = halves.next() else { return Err(invalid("invalid mountinfo")); };
        let Some(right) = halves.next() else { return Err(invalid("invalid mountinfo")); };
        if !right.starts_with("cgroup2 ") { continue; }
        let encoded = left.split_whitespace().nth(4)
            .ok_or_else(|| invalid("cgroup2 mount has no mountpoint"))?;
        let mountpoint = decode_mountinfo_path(encoded)?;
        found_primary |= mountpoint == b"/sys/fs/cgroup";
        let mountpoint = CString::new(mountpoint)
            .map_err(|_| invalid("cgroup2 mountpoint contains NUL"))?;
        let result = unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                libc::AT_FDCWD,
                mountpoint.as_ptr(),
                AT_RECURSIVE,
                &attributes,
                std::mem::size_of::<MountAttr>(),
            )
        };
        if result != 0 { return Err(std::io::Error::last_os_error()); }
    }
    if found_primary { Ok(()) } else { Err(invalid("primary cgroup2 mount is not visible")) }
}

fn decode_mountinfo_path(encoded: &str) -> std::io::Result<Vec<u8>> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || !bytes[index + 1..=index + 3]
                    .iter()
                    .all(|byte| matches!(byte, b'0'..=b'7'))
            {
                return Err(invalid("invalid mountinfo path escape"));
            }
            let value = (bytes[index + 1] - b'0') * 64
                + (bytes[index + 2] - b'0') * 8
                + (bytes[index + 3] - b'0');
            decoded.push(value);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(decoded)
}

fn release_child(spawned: &mut Spawned) -> std::io::Result<()> {
    let released = [1_u8];
    let written = unsafe { libc::write(spawned.release.as_raw_fd(), released.as_ptr().cast(), 1) };
    if written == 1 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

unsafe fn child_fail(status: RawFd, errno: i32) -> ! {
    let bytes = errno.to_ne_bytes();
    unsafe { libc::write(status, bytes.as_ptr().cast(), bytes.len()) };
    unsafe { libc::_exit(126) }
}

struct GenerationDirGuard {
    path: PathBuf,
    armed: bool,
}

impl GenerationDirGuard {
    fn new(path: PathBuf) -> Self { Self { path, armed: true } }
    fn disarm(&mut self) { self.armed = false; }
}

impl Drop for GenerationDirGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn rollback_generation(group: &Path, pid: libc::pid_t) -> std::io::Result<()> {
    fs::write(group.join("cgroup.kill"), b"1")?;
    reap_child(pid)?;
    wait_cgroup_empty(group, std::time::Duration::from_secs(5))?;
    fs::remove_dir(group)
}

fn cleanup_generation(
    config: &LinuxBrokerServerConfig,
    key: &str,
    generation: u64,
    pid: Option<libc::pid_t>,
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    let Some(group) = resolve_key_if_present(config, key, generation)? else {
        if let Some(pid) = pid {
            let _ = reap_child_bounded(pid, timeout)?;
        }
        return Ok(());
    };
    fs::write(group.join("cgroup.kill"), b"1")?;
    if let Some(pid) = pid {
        let _ = reap_child_bounded(pid, timeout)?;
    }
    wait_cgroup_empty(&group, timeout)?;
    fs::remove_dir(group)
}

fn reap_child(pid: libc::pid_t) -> std::io::Result<Option<i32>> {
    reap_child_bounded(pid, REAP_TIMEOUT)
}

fn reap_child_bounded(
    pid: libc::pid_t,
    timeout: std::time::Duration,
) -> std::io::Result<Option<i32>> {
    let deadline = std::time::Instant::now() + timeout;
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
    if pidfd < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    } else {
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let mut descriptor = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let milliseconds = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
            let ready = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
            if ready > 0 {
                break;
            }
            if ready == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "pidfd did not become reapable",
                ));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    loop {
        let mut status = 0;
        // Never use a blocking waitpid in the single broker authority. pidfd
        // readiness above is the bounded kernel completion oracle.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return Ok(decode_wait_status(status));
        }
        if waited == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "pidfd readiness raced child reap",
            ));
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(None);
            }
            return Err(error);
        }
    }
}

fn read_exec_handshake(
    fd: RawFd,
    errno: &mut [u8; 4],
    timeout: std::time::Duration,
) -> std::io::Result<usize> {
    let milliseconds = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if ready == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "child exec handshake timed out",
            ));
        }
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let read = unsafe { libc::read(fd, errno.as_mut_ptr().cast(), errno.len()) };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        return Ok(read as usize);
    }
}

fn wait_cgroup_empty(group: &Path, timeout: std::time::Duration) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let events = fs::read_to_string(group.join("cgroup.events"))?;
        if !parse_populated(&events)? {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "cgroup did not become empty",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn cleanup_connection_children(config: &LinuxBrokerServerConfig, state: &mut BrokerState) {
    let identities = state.operations.keys().cloned().collect::<Vec<_>>();
    for (session_id, operation_id) in identities {
        let identity = (session_id.clone(), operation_id.clone());
        let Some(operation) = state.operations.get_mut(&identity) else { continue };
        let prepared = operation.prepared.take();
        let key = operation.key.clone();
        let generation = operation.generation;
        let digest = operation.request_digest.clone();
        let (pending, terminal) = match operation.status {
            OperationStatus::Prepared | OperationStatus::Committing | OperationStatus::CleanupRequired => {
                (OperationStatus::CleanupRequired, OperationStatus::Cancelled)
            }
            OperationStatus::Committed | OperationStatus::DisconnectCleanupRequired => {
                (OperationStatus::DisconnectCleanupRequired, OperationStatus::DisconnectAborted)
            }
            _ => continue,
        };
        operation.status = pending;
        let _ = persist_operation(config, &session_id, &operation_id, pending, &key, generation, &digest);
        let pid = prepared.as_ref().map(|spawned| spawned.pid)
            .or_else(|| state.children.get(&key).copied());
        if cleanup_generation(config, &key, generation, pid, std::time::Duration::ZERO).is_err() {
            if let Some(pid) = pid {
                state.children.insert(key, pid);
            }
            continue;
        }
        if let Some(pid) = state.children.remove(&key) {
            if let Ok(exit_status) = reap_child(pid) {
                state.exit_statuses.insert(key.clone(), exit_status);
            }
        }
        state.remember_empty(key.clone());
        if let Some(operation) = state.operations.get_mut(&identity) {
            operation.status = terminal;
            let _ = persist_operation(config, &session_id, &operation_id, terminal, &key, generation, &digest);
        }
    }
}

fn retry_pending_cleanups(config: &LinuxBrokerServerConfig, state: &mut BrokerState) {
    let pending = state.operations.iter().filter_map(|(identity, operation)| {
        let terminal = match operation.status {
            OperationStatus::CleanupRequired => OperationStatus::Cancelled,
            OperationStatus::DisconnectCleanupRequired => OperationStatus::DisconnectAborted,
            _ => return None,
        };
        Some((identity.clone(), operation.key.clone(), operation.generation, operation.request_digest.clone(), terminal))
    }).collect::<Vec<_>>();
    for ((session_id, operation_id), key, generation, digest, terminal) in pending {
        if cleanup_generation(config, &key, generation, None, std::time::Duration::ZERO).is_err() {
            continue;
        }
        if let Some(pid) = state.children.remove(&key) {
            if let Ok(exit_status) = reap_child(pid) {
                state.exit_statuses.insert(key.clone(), exit_status);
            }
        }
        state.remember_empty(key.clone());
        if let Some(operation) = state.operations.get_mut(&(session_id.clone(), operation_id.clone())) {
            operation.status = terminal;
            let _ = persist_operation(config, &session_id, &operation_id, terminal, &key, generation, &digest);
        }
    }
}

fn mark_operation_terminal(
    config: &LinuxBrokerServerConfig,
    state: &mut BrokerState,
    key: &str,
    status: OperationStatus,
) -> std::io::Result<()> {
    let identity = state.operations.iter()
        .find(|(_, operation)| operation.key == key)
        .map(|(identity, _)| identity.clone());
    if let Some((session_id, operation_id)) = identity {
        let operation = state.operations.get_mut(&(session_id.clone(), operation_id.clone()))
            .expect("operation identity came from map");
        operation.status = status;
        persist_operation(config, &session_id, &operation_id, status, &operation.key, operation.generation, &operation.request_digest)?;
    }
    gc_terminal_operations(config, &mut state.operations)?;
    Ok(())
}

fn decode_wait_status(status: i32) -> Option<i32> {
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status))
    } else {
        None
    }
}

fn seccomp_guard_program() -> Vec<libc::sock_filter> {
    // Deny namespace/mount mutation after the broker has installed the private,
    // read-only cgroup view. Everything else remains governed by the ordinary
    // hook sandbox and no_new_privs.
    let mut filter = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, 4),
        jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch(), 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // Reject the x32 syscall ABI before comparing syscall numbers. Its
        // high-bit encoding otherwise bypasses a native-number deny list.
        filter.push(jump(BPF_JMP | BPF_JSET | BPF_K, X32_SYSCALL_BIT, 0, 1));
        filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        filter.push(stmt(BPF_JMP | BPF_JA, 1));
        filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }
    for syscall in [libc::SYS_mount, libc::SYS_umount2, libc::SYS_unshare, libc::SYS_setns] {
        filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, syscall as u32, 0, 1));
        filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    // glibc transparently falls back from clone3(2) on ENOSYS. Classic clone
    // exposes flags directly to seccomp, allowing ordinary threads/forks while
    // rejecting every namespace-creating flag.
    filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_clone3 as u32, 0, 1));
    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
    filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_clone as u32, 0, 3));
    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, 16));
    let namespace_flags = (libc::CLONE_NEWNS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS) as u32
        | 0x80; // CLONE_NEWTIME
    filter.push(jump(BPF_JMP | BPF_JSET | BPF_K, namespace_flags, 0, 1));
    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    filter
}

unsafe fn install_seccomp_guard(filter: &[libc::sock_filter]) -> std::io::Result<()> {
    let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut _ };
    let result = unsafe { libc::prctl(libc::PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

unsafe fn capabilities_are_empty() -> bool {
    #[repr(C)]
    struct Header { version: u32, pid: i32 }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data { effective: u32, permitted: u32, inheritable: u32 }
    let mut header = Header { version: 0x2008_0522, pid: 0 };
    let mut data = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
    unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } == 0
        && data.iter().all(|set| set.effective == 0 && set.permitted == 0 && set.inheritable == 0)
}

const CLONE_INTO_CGROUP: u64 = 0x2000_0000_0;
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_JA: u16 = 0x00;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[cfg(target_arch = "x86_64")]
const fn audit_arch() -> u32 { 0xc000_003e }
#[cfg(target_arch = "aarch64")]
const fn audit_arch() -> u32 { 0xc000_00b7 }
#[cfg(target_arch = "x86")]
const fn audit_arch() -> u32 { 0x4000_0003 }
#[cfg(target_arch = "arm")]
const fn audit_arch() -> u32 { 0x4000_0028 }
#[cfg(target_arch = "riscv64")]
const fn audit_arch() -> u32 { 0xc000_00f3 }

const fn stmt(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k: value }
}

const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k: value }
}

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

fn resolve_key(config: &LinuxBrokerServerConfig, key: &str, generation: u64) -> std::io::Result<PathBuf> {
    if !valid_key(key, generation) {
        return Err(invalid("invalid containment key"));
    }
    let path = config.cgroup_root.join(key);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "containment not found"));
    }
    Ok(path)
}

fn resolve_key_if_present(
    config: &LinuxBrokerServerConfig,
    key: &str,
    generation: u64,
) -> std::io::Result<Option<PathBuf>> {
    if !valid_key(key, generation) {
        return Err(invalid("invalid containment key"));
    }
    match resolve_key(config, key, generation) {
        Ok(path) => Ok(Some(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn valid_key(key: &str, generation: u64) -> bool {
    let suffix = format!("-g{generation}");
    key.len() == 3 + 32 + suffix.len()
        && key.starts_with("fc-")
        && key.ends_with(&suffix)
        && key[3..35].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_environment(env: &[(Vec<u8>, Vec<u8>)]) -> std::io::Result<()> {
    let mut previous: Option<&[u8]> = None;
    for (key, value) in env {
        if key.is_empty()
            || key.len() > MAX_STRING_BYTES
            || value.len() > MAX_STRING_BYTES
            || key.contains(&b'=')
            || key.contains(&0)
            || value.contains(&0)
        {
            return Err(invalid("invalid environment entry"));
        }
        if previous.is_some_and(|previous| previous >= key.as_slice()) {
            return Err(invalid("environment keys must be unique and byte-sorted"));
        }
        previous = Some(key);
    }
    Ok(())
}

fn valid_operation_id(operation_id: &str) -> bool {
    !operation_id.is_empty()
        && operation_id.len() <= 128
        && operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn canonical_spawn_digest(
    containment_id: &str,
    session_id: &str,
    generation: u64,
    operation_id: &str,
    program: &[u8],
    args: &[String],
    cwd: &[u8],
    env: &[(Vec<u8>, Vec<u8>)],
    capture_io: bool,
) -> String {
    fn field(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let mut hasher = Sha256::new();
    field(&mut hasher, b"flycockpit-linux-broker-spawn-v1");
    field(&mut hasher, containment_id.as_bytes());
    field(&mut hasher, session_id.as_bytes());
    field(&mut hasher, &generation.to_be_bytes());
    field(&mut hasher, operation_id.as_bytes());
    field(&mut hasher, &[u8::from(capture_io)]);
    field(&mut hasher, program);
    field(&mut hasher, cwd);
    field(&mut hasher, &(args.len() as u64).to_be_bytes());
    for argument in args {
        field(&mut hasher, argument.as_bytes());
    }
    field(&mut hasher, &(env.len() as u64).to_be_bytes());
    for (key, value) in env {
        field(&mut hasher, key);
        field(&mut hasher, value);
    }
    format!("{:x}", hasher.finalize())
}

fn verify_client_guard(guard: &GuardAttestation, key: &str, pidfd: BorrowedFd<'_>) -> bool {
    if guard.pid <= 0 {
        return false;
    }
    let proc_root = PathBuf::from(format!("/proc/{}", guard.pid));
    let status = match fs::read_to_string(proc_root.join("status")) {
        Ok(status) => status,
        Err(_) => return false,
    };
    let expected_uid = unsafe { libc::geteuid() };
    let uid_matches = status.lines().find_map(|line| line.strip_prefix("Uid:\t"))
        .and_then(|ids| ids.split_whitespace().next())
        .and_then(|uid| uid.parse::<u32>().ok()) == Some(expected_uid);
    let cgroup_matches = fs::read_to_string(proc_root.join("cgroup"))
        .ok()
        .is_some_and(|membership| membership.lines().any(|line| {
            line.strip_prefix("0::").is_some_and(|path| {
                path.split('/').next_back() == Some(key)
            })
        }));
    let distinct_mount_ns = fs::read_link(proc_root.join("ns/mnt")).ok()
        != fs::read_link("/proc/self/ns/mnt").ok();
    let distinct_cgroup_ns = fs::read_link(proc_root.join("ns/cgroup")).ok()
        != fs::read_link("/proc/self/ns/cgroup").ok();
    let status_value = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    let no_new_privs = status_value("NoNewPrivs:") == Some("1");
    let seccomp = status_value("Seccomp:") == Some("2");
    let caps_cleared = ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
        .into_iter()
        .all(|name| status_value(name).is_some_and(|value| {
            u64::from_str_radix(value, 16).ok() == Some(0)
        }));
    let cgroup_mount_read_only = fs::read_to_string(proc_root.join("mountinfo"))
        .ok()
        .is_some_and(|mountinfo| {
            let cgroup_mounts = mountinfo.lines().filter_map(|line| {
                let mut halves = line.split(" - ");
                let left = halves.next()?;
                let right = halves.next()?;
                if !right.starts_with("cgroup2 ") { return None; }
                let fields = left.split_whitespace().collect::<Vec<_>>();
                Some((fields.get(4).copied(), fields.get(5).copied()))
            }).collect::<Vec<_>>();
            !cgroup_mounts.is_empty()
                && cgroup_mounts.iter().any(|(mount, _)| *mount == Some("/sys/fs/cgroup"))
                && cgroup_mounts.iter().all(|(_, options)| {
                    options.is_some_and(|options| options.split(',').any(|option| option == "ro"))
                })
        });
    let pidfd_matches = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("Pid:\t"))
                .and_then(|pid| pid.trim().parse::<i32>().ok())
        }) == Some(guard.pid);
    uid_matches
        && cgroup_matches
        && distinct_mount_ns
        && distinct_cgroup_ns
        && no_new_privs
        && seccomp
        && caps_cleared
        && cgroup_mount_read_only
        && pidfd_matches
}

fn parse_populated(events: &str) -> std::io::Result<bool> {
    events
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
        .and_then(|value| match value { "0" => Some(false), "1" => Some(true), _ => None })
        .ok_or_else(|| invalid("invalid cgroup.events"))
}

fn verify_server_installation(config: &LinuxBrokerServerConfig) -> std::io::Result<BTreeSet<String>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "broker must run as root"));
    }
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "cgroup v2 unavailable"));
    }
    verify_state_root(config)?;
    // The delegated root cannot be stat'ed before it exists. Validate the
    // actual parent mount first, create the root, then attest the resulting
    // directory and its kernel-generated control files.
    let parent = config.cgroup_root.parent().ok_or_else(|| invalid("cgroup root has no parent"))?;
    verify_cgroup2_filesystem(parent)?;
    fs::create_dir_all(&config.cgroup_root)?;
    verify_cgroup2_filesystem(&config.cgroup_root)?;
    set_mode(&config.cgroup_root, 0o755)?;
    verify_root_owned_migration_file(Path::new("/sys/fs/cgroup/cgroup.procs"))?;
    verify_root_owned_migration_file(&config.cgroup_root.join("cgroup.procs"))?;
    let metadata = fs::symlink_metadata(&config.cgroup_root)?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "broker cgroup root is not exclusively root-owned",
        ));
    }
    let mut recovered = BTreeSet::new();
    let mut recovering = Vec::new();
    for entry in fs::read_dir(&config.cgroup_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let key = entry.file_name().into_string().map_err(|_| invalid("invalid cgroup key"))?;
        // Never sweep cgroups the broker cannot prove it named. Unknown
        // directories belong to the operator, even under a misconfigured root.
        let generation = key.rsplit_once("-g").and_then(|(_, value)| value.parse().ok());
        if !generation.is_some_and(|generation| valid_key(&key, generation)) {
            continue;
        }
        let group = entry.path();
        fs::write(group.join("cgroup.kill"), b"1")?;
        recovering.push((key, group));
    }
    // Kill every recovered generation first, then share one global deadline.
    // Recovery is therefore bounded by one timeout rather than N timeouts and
    // the listener is never published while an unowned generation survives.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !recovering.is_empty() {
        let mut index = 0;
        while index < recovering.len() {
            let (key, group) = &recovering[index];
            if !parse_populated(&fs::read_to_string(group.join("cgroup.events"))?)? {
                fs::remove_dir(group)?;
                recovered.insert(key.clone());
                recovering.swap_remove(index);
            } else {
                index += 1;
            }
        }
        if recovering.is_empty() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "recovered cgroups did not become empty before the global deadline",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    verify_kernel_spawn_contract(config)?;
    Ok(recovered)
}

fn verify_canonical_cgroup_root(config: &LinuxBrokerServerConfig) -> std::io::Result<()> {
    let expected = PathBuf::from(DEFAULT_CGROUP_ROOT).join(format!("u{}", config.allowed_uid));
    if config.cgroup_root != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "broker cgroup root is not canonical for the allowed uid",
        ));
    }
    Ok(())
}

fn verify_state_root(config: &LinuxBrokerServerConfig) -> std::io::Result<()> {
    let expected = PathBuf::from(format!("/var/lib/flycockpit/containment-broker-{}", config.allowed_uid));
    if config.state_root != expected {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "broker state root is not canonical"));
    }
    fs::create_dir_all(&config.state_root)?;
    set_mode(&config.state_root, 0o700)?;
    let metadata = fs::symlink_metadata(&config.state_root)?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "broker state root is not private root-owned storage"));
    }
    Ok(())
}

fn operation_record_path(config: &LinuxBrokerServerConfig, session_id: &str, operation_id: &str) -> std::io::Result<PathBuf> {
    if uuid::Uuid::parse_str(session_id).is_err() || !valid_operation_id(operation_id) {
        return Err(invalid("invalid operation identity"));
    }
    Ok(config.state_root.join(format!("{session_id}--{operation_id}.json")))
}

fn persist_operation(
    config: &LinuxBrokerServerConfig,
    session_id: &str,
    operation_id: &str,
    status: OperationStatus,
    key: &str,
    generation: u64,
    request_digest: &str,
) -> std::io::Result<()> {
    let destination = operation_record_path(config, session_id, operation_id)?;
    let record = DurableOperation {
        broker_epoch: broker_epoch()?,
        session_id: session_id.to_owned(),
        operation_id: operation_id.to_owned(),
        status,
        key: key.to_owned(),
        generation,
        request_digest: request_digest.to_owned(),
        exit_code: None,
    };
    let bytes = serde_json::to_vec(&record).map_err(invalid)?;
    let temporary = config.state_root.join(format!(".operation-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, destination)?;
    File::open(&config.state_root)?.sync_all()
}

fn persist_exit_status_for_key(
    config: &LinuxBrokerServerConfig,
    state: &BrokerState,
    key: &str,
) -> std::io::Result<()> {
    let Some(((session_id, operation_id), _)) = state.operations.iter()
        .find(|(_, operation)| operation.key == key)
    else {
        return Err(invalid("exit status has no durable operation identity"));
    };
    let destination = operation_record_path(config, session_id, operation_id)?;
    let mut record: DurableOperation = serde_json::from_slice(&fs::read(&destination)?)
        .map_err(invalid)?;
    record.exit_code = state.exit_statuses.get(key).copied().flatten();
    let bytes = serde_json::to_vec(&record).map_err(invalid)?;
    let temporary = config.state_root.join(format!(".operation-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, destination)?;
    File::open(&config.state_root)?.sync_all()
}

fn broker_epoch() -> std::io::Result<String> {
    let epoch = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let epoch = epoch.trim();
    uuid::Uuid::parse_str(epoch).map_err(|_| invalid("invalid kernel boot epoch"))?;
    Ok(epoch.to_owned())
}

fn recover_operation_records(
    config: &LinuxBrokerServerConfig,
    recovered_empty: &BTreeSet<String>,
) -> std::io::Result<BTreeMap<(String, String), BrokerOperation>> {
    let mut operations = BTreeMap::new();
    let current_epoch = broker_epoch()?;
    let mut locator_bindings = BTreeMap::<String, (String, String, String)>::new();
    for entry in fs::read_dir(&config.state_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            return Err(invalid("unexpected entry in broker state root"));
        }
        let metadata = entry.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || metadata.len() > MAX_FRAME as u64 {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "invalid broker operation record"));
        }
        let record: DurableOperation = serde_json::from_slice(&fs::read(entry.path())?).map_err(invalid)?;
        let expected_name = format!("{}--{}.json", record.session_id, record.operation_id);
        if entry.file_name().as_bytes() != expected_name.as_bytes()
            || uuid::Uuid::parse_str(&record.session_id).is_err()
            || !valid_operation_id(&record.operation_id)
            || record.request_digest.len() != 64
            || !record.request_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("durable operation filename or identity mismatch"));
        }
        if !valid_key(&record.key, record.generation) {
            return Err(invalid("invalid durable containment locator"));
        }
        let identity = (record.session_id.clone(), record.operation_id.clone());
        if let Some(previous) = locator_bindings.insert(
            record.key.clone(),
            (identity.0.clone(), identity.1.clone(), record.request_digest.clone()),
        ) {
            if previous != (identity.0.clone(), identity.1.clone(), record.request_digest.clone()) {
                return Err(invalid("durable containment locator has multiple operation identities"));
            }
        }
        if record.broker_epoch != current_epoch {
            fs::remove_file(entry.path())?;
            continue;
        }
        let proven_empty = recovered_empty.contains(&record.key)
            || !config.cgroup_root.join(&record.key).exists();
        let recovered_status = match record.status {
            OperationStatus::Prepared | OperationStatus::Committing | OperationStatus::CleanupRequired => {
                if proven_empty { OperationStatus::Cancelled } else { OperationStatus::CleanupRequired }
            }
            OperationStatus::Committed | OperationStatus::DisconnectCleanupRequired => {
                if proven_empty { OperationStatus::DisconnectAborted } else { OperationStatus::DisconnectCleanupRequired }
            }
            status => status,
        };
        if !matches!(record.status, OperationStatus::Cancelled | OperationStatus::DisconnectAborted | OperationStatus::Exited) {
            persist_operation(config, &record.session_id, &record.operation_id, recovered_status, &record.key, record.generation, &record.request_digest)?;
        }
        if operations.insert(identity, BrokerOperation {
            status: recovered_status,
            key: record.key,
            generation: record.generation,
            request_digest: record.request_digest,
            prepared: None,
            exit_code: record.exit_code,
        }).is_some() {
            return Err(invalid("duplicate durable operation identity"));
        }
        if operations.len() > MAX_OPERATION_RECORDS_PER_EPOCH {
            return Err(invalid("durable operation epoch exceeds bounded replay horizon"));
        }
    }
    File::open(&config.state_root)?.sync_all()?;
    Ok(operations)
}

fn gc_terminal_operations(
    _config: &LinuxBrokerServerConfig,
    _operations: &mut BTreeMap<(String, String), BrokerOperation>,
) -> std::io::Result<()> {
    // Operation IDs are permanent idempotency keys. Deleting a terminal row
    // would allow the same identity to be replayed with different executable
    // inputs. Retention can only be bounded by a future protocol version with
    // an explicit expiry epoch carried by every client request.
    Ok(())
}

fn verify_socket_location(config: &LinuxBrokerServerConfig) -> std::io::Result<()> {
    let parent = config
        .socket_path
        .parent()
        .ok_or_else(|| invalid("broker socket has no parent"))?;
    if parent != Path::new(BROKER_DIRECTORY) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "broker socket is outside the trusted runtime directory",
        ));
    }
    fs::create_dir_all(parent)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "broker runtime directory is not exclusively root-owned",
        ));
    }
    let expected_name = format!("containment-broker-{}.sock", config.allowed_uid);
    if config.socket_path.file_name().and_then(|name| name.to_str()) != Some(&expected_name) {
        return Err(invalid("broker socket name does not match allowed uid"));
    }
    Ok(())
}

fn remove_owned_socket(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || metadata.uid() != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "refusing to replace an unowned broker socket path",
                ));
            }
            fs::remove_file(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn verify_cgroup2_filesystem(path: &Path) -> std::io::Result<()> {
    let existing = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid("path contains NUL"))?;
    let mut stats: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(existing.as_ptr(), &mut stats) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
    if stats.f_type != CGROUP2_SUPER_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "broker root is not on cgroup v2",
        ));
    }
    Ok(())
}

fn verify_kernel_spawn_contract(config: &LinuxBrokerServerConfig) -> std::io::Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let mut spawned = spawn_atomic(
        config,
        &id,
        u64::MAX,
        b"/bin/true",
        &[],
        b"/",
        &[],
        None,
        new_allocation_decision_fd()?,
    )?;
    if !spawned.guard.proven() {
        let _ = rollback_generation(&config.cgroup_root.join(&spawned.key), spawned.pid);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "kernel guard attestation incomplete",
        ));
    }
    release_child(&mut spawned)?;
    drop(spawned.stdin);
    drop(spawned.stdout);
    drop(spawned.stderr);
    drop(spawned.pidfd);
    let group = config.cgroup_root.join(&spawned.key);
    if let Err(error) = reap_child(spawned.pid) {
        let _ = rollback_generation(&group, spawned.pid);
        return Err(error);
    }
    wait_cgroup_empty(&group, std::time::Duration::from_secs(5))?;
    fs::remove_dir(group)
}

fn new_allocation_decision_fd() -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::memfd_create(
            c"flycockpit-broker-self-test-decision".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 { return Err(std::io::Error::last_os_error()); }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::ftruncate(fd.as_raw_fd(), 1) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let seals = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn verify_root_owned_migration_file(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cgroup migration file is not exclusively managed",
        ));
    }
    Ok(())
}

fn verify_peer_uid(stream: &UnixStream, expected: u32) -> std::io::Result<()> {
    let mut credentials = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut credentials as *mut libc::ucred).cast(), &mut length)
    };
    if result != 0 || credentials.uid != expected {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "broker peer credential mismatch"));
    }
    Ok(())
}

fn duplicate_valid_capability(fd: RawFd) -> std::io::Result<OwnedFd> {
    if fd < 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "containment capability fd unavailable"));
    }
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let metadata = fd_stat(duplicate.as_fd())?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_mode & 0o777 != 0o400
    {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "invalid containment capability descriptor"));
    }
    Ok(duplicate)
}

fn same_capability_inode(left: BorrowedFd<'_>, right: BorrowedFd<'_>) -> std::io::Result<bool> {
    let left = fd_stat(left)?;
    let right = fd_stat(right)?;
    Ok(left.st_dev == right.st_dev && left.st_ino == right.st_ino)
}

fn fd_stat(fd: BorrowedFd<'_>) -> std::io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } == 0 {
        Ok(stat)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn authenticate_connection(stream: &mut UnixStream, expected: &OwnedFd) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + AUTH_FRAME_TIMEOUT;
    wait_for_frame_start_until(stream.as_raw_fd(), Some(deadline))?;
    let (body, mut fds) = recv_with_fds_until(
        stream.as_raw_fd(),
        1,
        deadline,
    )?;
    let request: Request = serde_json::from_slice(&body).map_err(invalid)?;
    let Some(capability) = fds.pop() else {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "missing containment capability"));
    };
    if !fds.is_empty()
        || !matches!(request, Request::Authenticate { version: PROTOCOL_VERSION })
        || !same_capability_inode(capability.as_fd(), expected.as_fd())?
    {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "invalid containment capability"));
    }
    send_response(stream, &Response::Ready { version: PROTOCOL_VERSION, exclusive_delegation: true }, &[])
}

fn pipe_cloexec() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn set_mode(path: &Path, mode: libc::mode_t) -> std::io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("path contains NUL"))?;
    if unsafe { libc::chmod(path.as_ptr(), mode) } == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("path contains NUL"))?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn send_response(stream: &UnixStream, response: &Response, fds: &[RawFd]) -> std::io::Result<()> {
    let body = serde_json::to_vec(response).map_err(invalid)?;
    if body.len() > MAX_FRAME { return Err(invalid("frame too large")); }
    send_with_fds(stream.as_raw_fd(), &body, fds)
}

fn recv_response_with_fds(stream: &UnixStream) -> std::io::Result<(Response, Vec<OwnedFd>)> {
    let (body, fds) = recv_with_fds(stream.as_raw_fd(), 4)?;
    let response = serde_json::from_slice(&body).map_err(invalid)?;
    Ok((response, fds))
}

fn send_with_fds(socket: RawFd, body: &[u8], fds: &[RawFd]) -> std::io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(invalid("frame too large"));
    }
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    let mut iov = libc::iovec { iov_base: frame.as_ptr() as *mut _, iov_len: frame.len() };
    let control_len = if fds.is_empty() { 0 } else { unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize } };
    let mut control = vec![0_u8; control_len];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    if !fds.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), fds.len());
        }
    }
    let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut offset = sent as usize;
    while offset < frame.len() {
        let written = unsafe {
            libc::send(
                socket,
                frame[offset..].as_ptr().cast(),
                frame.len() - offset,
                libc::MSG_NOSIGNAL,
            )
        };
        if written <= 0 {
            return Err(if written < 0 { std::io::Error::last_os_error() } else { std::io::Error::new(std::io::ErrorKind::WriteZero, "short broker response") });
        }
        offset += written as usize;
    }
    Ok(())
}

fn recv_with_fds(socket: RawFd, max_fds: usize) -> std::io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    recv_with_fds_until(
        socket,
        max_fds,
        std::time::Instant::now() + FRAME_TIMEOUT,
    )
}

fn recv_with_fds_until(
    socket: RawFd,
    max_fds: usize,
    frame_deadline: std::time::Instant,
) -> std::io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut frame = vec![0_u8; MAX_FRAME + 4];
    let mut iov = libc::iovec { iov_base: frame.as_mut_ptr().cast(), iov_len: frame.len() };
    let mut control = vec![0_u8; unsafe { libc::CMSG_SPACE((max_fds * std::mem::size_of::<RawFd>()) as u32) as usize }];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let received = loop {
        let received = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received >= 0 {
            break received;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    let fds = adopt_rights_messages(&message, max_fds)?;
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(invalid("truncated broker response"));
    }
    let mut received = received as usize;
    while received < 4 {
        let count = recv_retry_until(socket, &mut frame[received..4], frame_deadline)?;
        if count <= 0 { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short broker frame")); }
        received += count as usize;
    }
    let body_len = u32::from_be_bytes(frame[..4].try_into().expect("four byte length")) as usize;
    if body_len > MAX_FRAME { return Err(invalid("frame too large")); }
    let total = body_len + 4;
    while received < total {
        let count = recv_retry_until(socket, &mut frame[received..total], frame_deadline)?;
        if count <= 0 { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short broker frame")); }
        received += count as usize;
    }
    Ok((frame[4..total].to_vec(), fds))
}

fn wait_for_frame_start(socket: RawFd) -> std::io::Result<()> {
    wait_for_frame_start_until(socket, None)
}

fn wait_for_frame_start_until(
    socket: RawFd,
    deadline: Option<std::time::Instant>,
) -> std::io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd: socket,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    loop {
        let timeout = deadline.map_or(-1, |deadline| {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX).max(1)
        });
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "broker frame did not start before deadline",
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn recv_retry_until(
    socket: RawFd,
    buffer: &mut [u8],
    deadline: std::time::Instant,
) -> std::io::Result<isize> {
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "absolute broker frame deadline exceeded",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd: socket,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let milliseconds = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX).max(1);
        let ready = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if ready == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "absolute broker frame deadline exceeded",
            ));
        }
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(error);
        }
        let received = unsafe {
            libc::recv(
                socket,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
            )
        };
        if received >= 0 {
            return Ok(received);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn adopt_rights_messages(message: &libc::msghdr, max_fds: usize) -> std::io::Result<Vec<OwnedFd>> {
    let mut fds = Vec::new();
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            let minimum = libc::CMSG_LEN(0) as usize;
            if (*header).cmsg_len < minimum {
                return Err(invalid("invalid broker control message"));
            }
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*header).cmsg_len - minimum;
                if bytes % std::mem::size_of::<RawFd>() != 0 {
                    return Err(invalid("misaligned broker descriptor payload"));
                }
                let count = bytes / std::mem::size_of::<RawFd>();
                if fds.len().saturating_add(count) > max_fds {
                    // Adopt this message before rejecting so every received
                    // descriptor is closed by OwnedFd on the error path.
                    let data = libc::CMSG_DATA(header).cast::<RawFd>();
                    for index in 0..count {
                        fds.push(OwnedFd::from_raw_fd(*data.add(index)));
                    }
                    return Err(invalid("too many broker descriptors"));
                }
                let data = libc::CMSG_DATA(header).cast::<RawFd>();
                for index in 0..count {
                    fds.push(OwnedFd::from_raw_fd(*data.add(index)));
                }
            } else {
                return Err(invalid("unexpected broker control message"));
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    Ok(fds)
}

fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

fn broker_error_code(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::AlreadyExists => "containment_generation_exists",
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
            "invalid_spawn_request"
        }
        std::io::ErrorKind::NotFound => "spawn_target_not_found",
        std::io::ErrorKind::PermissionDenied => "broker_permission_denied",
        std::io::ErrorKind::Unsupported => "kernel_feature_unsupported",
        _ => "broker_spawn_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_keys_are_generation_bound_and_path_inert() {
        let key = format!("fc-{}-g7", "a".repeat(32));
        assert!(valid_key(&key, 7));
        assert!(!valid_key(&key, 8));
        assert!(!valid_key("../escape-g7", 7));
        assert!(!valid_key(&format!("fc-{}-g7/child", "a".repeat(32)), 7));
    }

    #[test]
    fn broker_population_oracle_is_closed() {
        assert_eq!(parse_populated("populated 0\nfrozen 0\n").unwrap(), false);
        assert_eq!(parse_populated("populated 1\nfrozen 0\n").unwrap(), true);
        assert!(parse_populated("populated 2\n").is_err());
        assert!(parse_populated("frozen 0\n").is_err());
    }

    #[test]
    fn broker_environment_contract_preserves_unix_bytes() {
        let env = vec![(b"ASCII".to_vec(), vec![0xff, b'x'])];
        assert!(validate_environment(&env).is_ok());
        assert!(validate_environment(&[(b"A=B".to_vec(), b"x".to_vec())]).is_err());
        assert!(validate_environment(&[(b"A".to_vec(), vec![0])]).is_err());
        assert!(validate_environment(&[
            (b"B".to_vec(), b"1".to_vec()),
            (b"A".to_vec(), b"2".to_vec()),
        ]).is_err());
        assert!(validate_environment(&[
            (b"A".to_vec(), b"1".to_vec()),
            (b"A".to_vec(), b"2".to_vec()),
        ]).is_err());
    }

    #[test]
    fn mountinfo_paths_are_decoded_before_recursive_sanitization() {
        assert_eq!(decode_mountinfo_path(r#"/sys/fs/cgroup"#).unwrap(), b"/sys/fs/cgroup");
        assert_eq!(decode_mountinfo_path(r#"/cgroup\040view"#).unwrap(), b"/cgroup view");
        assert!(decode_mountinfo_path(r#"/bad\0"#).is_err());
    }

    #[test]
    fn allocation_decision_is_linearized_under_one_cross_process_lock() {
        let cancelled = super::super::adapter::AllocationCancellation::new().unwrap();
        cancelled.cancel().unwrap();
        assert!(!durably_choose_commit(cancelled.decision_fd(), || {
            panic!("cancel-first decision must not persist commit")
        }).unwrap());

        let committed = super::super::adapter::AllocationCancellation::new().unwrap();
        let persisted = std::sync::atomic::AtomicBool::new(false);
        assert!(durably_choose_commit(committed.decision_fd(), || {
            persisted.store(true, Ordering::Release);
            Ok(())
        }).unwrap());
        committed.cancel().unwrap();
        assert!(persisted.load(Ordering::Acquire));
        let mut state = [0_u8];
        assert_eq!(unsafe {
            libc::pread(committed.decision_fd().as_raw_fd(), state.as_mut_ptr().cast(), 1, 0)
        }, 1);
        assert_eq!(state[0], 2, "commit winner cannot be rewritten as pre-release cancellation");
    }

    #[test]
    fn disconnect_terminal_is_not_a_successful_exit() {
        assert!(!matches!(OperationStatus::DisconnectAborted, OperationStatus::Exited));
        assert!(!matches!(OperationStatus::DisconnectCleanupRequired, OperationStatus::Committed));
    }

    #[test]
    fn production_cgroup_root_is_uid_canonical() {
        let config = LinuxBrokerServerConfig::production(1234, 1234);
        assert!(verify_canonical_cgroup_root(&config).is_ok());
        let mut redirected = config;
        redirected.cgroup_root = PathBuf::from("/sys/fs/cgroup/operator-owned");
        assert!(verify_canonical_cgroup_root(&redirected).is_err());
    }

    #[test]
    fn broker_scm_rights_frame_is_bounded_and_ordered() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (read, write) = pipe_cloexec().unwrap();
        let response = Response::Prepared {
            version: PROTOCOL_VERSION,
            key: format!("fc-{}-g3", "b".repeat(32)),
            guard: GuardAttestation {
                pid: std::process::id() as i32,
                clone_into_cgroup: true,
                private_mount_ns: true,
                private_cgroup_ns: true,
                no_new_privs: true,
                caps_cleared: true,
                cgroup_mount_read_only: true,
                seccomp_filter: true,
            },
        };
        let thread = std::thread::spawn(move || {
            send_response(&sender, &response, &[read.as_raw_fd(), write.as_raw_fd()]).unwrap();
        });
        let (received, fds) = recv_response_with_fds(&receiver).unwrap();
        thread.join().unwrap();
        assert!(matches!(received, Response::Prepared { version: PROTOCOL_VERSION, .. }));
        assert_eq!(fds.len(), 2);
    }

    #[test]
    fn seccomp_guard_checks_architecture_and_denies_namespace_mutation() {
        let filter = seccomp_guard_program();
        assert_eq!(filter[0].k, 4);
        assert_eq!(filter[1].k, audit_arch());
        assert_eq!(filter[2].k, SECCOMP_RET_KILL_PROCESS);
        for syscall in [libc::SYS_mount, libc::SYS_umount2, libc::SYS_unshare, libc::SYS_setns] {
            let index = filter.iter().position(|instruction| {
                instruction.code == BPF_JMP | BPF_JEQ | BPF_K
                    && instruction.k == syscall as u32
            }).expect("namespace syscall comparison");
            assert_eq!(filter[index + 1].k, SECCOMP_RET_ERRNO | libc::EPERM as u32);
        }
        let clone = filter.iter().position(|instruction| {
            instruction.code == BPF_JMP | BPF_JEQ | BPF_K
                && instruction.k == libc::SYS_clone as u32
        }).expect("clone comparison");
        assert_eq!(filter[clone + 1].k, 16, "clone flags are inspected");
        assert_eq!(filter.last().expect("allow tail").k, SECCOMP_RET_ALLOW);
    }
}
