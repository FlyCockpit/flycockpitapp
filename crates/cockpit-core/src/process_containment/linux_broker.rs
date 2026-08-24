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
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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
const BROKER_DIRECTORY: &str = "/run/flycockpit";

#[derive(Debug, Clone)]
pub struct LinuxBrokerConfig {
    pub socket_path: PathBuf,
    pub expected_broker_uid: u32,
    /// Root-opened, non-inheritable capability descriptor delivered to the
    /// daemon by its service manager. The number is public; possession of the
    /// underlying open file description is the capability.
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
        env: BTreeMap<String, String>,
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
enum OperationStatus { Prepared, Committing, Committed, Cancelled, Exited }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuardAttestation {
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
    stream: Arc<Mutex<UnixStream>>,
    authenticated: bool,
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
        let mut attempts = 0_u16;
        let stream = loop {
            match UnixStream::connect(&config.socket_path) {
                Ok(stream) => break stream,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => {
                    attempts += 1;
                    if attempts >= 500 {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            // The broker and daemon are ordered systemd units, but Type=simple
            // activation can expose a short bind race. Bound it at startup.
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        unsafe { libc::close(capability_raw) };
        verify_peer_uid(&stream, config.expected_broker_uid)?;
        let request = Request::Authenticate { version: PROTOCOL_VERSION };
        let body = serde_json::to_vec(&request).map_err(invalid)?;
        send_with_fds(stream.as_raw_fd(), &body, &[capability.as_raw_fd()])?;
        let (response, fds) = recv_response_with_fds(&stream)?;
        if !fds.is_empty() || !matches!(response, Response::Ready { version: PROTOCOL_VERSION, exclusive_delegation: true }) {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "broker rejected containment capability"));
        }
        Ok(Self { config, stream: Arc::new(Mutex::new(stream)), authenticated: true })
    }

    fn transact(&self, request: &Request) -> std::io::Result<(Response, Vec<OwnedFd>)> {
        let mut stream = self.stream.lock().map_err(|_| std::io::Error::other("broker connection poisoned"))?;
        write_frame(&mut stream, request)?;
        recv_response_with_fds(&stream)
    }
}

#[async_trait]
impl ManagementBroker for LinuxBrokerClient {
    fn distinct_identity(&self) -> bool {
        self.config.expected_broker_uid == 0 && unsafe { libc::geteuid() } != 0
    }

    fn exclusive_delegation(&self) -> bool {
        self.authenticated
    }

    async fn authenticate(&self, _: &str, _: &str, _: u64) -> bool {
        self.authenticated
    }

    async fn spawn_with_io(
        &self,
        request: NativeIoSpawnRequest,
    ) -> Result<AllocatedNativeIo, ContainmentError> {
        let client = self.clone();
        let generation = request.generation;
        let containment_id = request.containment_id;
        let session_id = request.session_id.to_string();
        let operation_id = request.operation_id.clone();
        let wire = Request::PrepareSpawn {
            version: PROTOCOL_VERSION,
            containment_id: containment_id.to_string(),
            session_id: session_id.clone(),
            generation,
            operation_id: operation_id.clone(),
            program: request.program.as_os_str().as_bytes().to_vec(),
            args: request.args,
            cwd: request.cwd.as_os_str().as_bytes().to_vec(),
            env: request.env,
        };
        let (response, mut fds) = tokio::task::spawn_blocking(move || client.transact(&wire))
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
        if !guard.proven() || fds.len() != 4 {
            let cancel = Request::CancelOperation { version: PROTOCOL_VERSION, session_id, operation_id };
            let client = self.clone();
            let _ = tokio::task::spawn_blocking(move || client.transact(&cancel)).await;
            return Err(unavailable());
        }
        let pidfd = fds.pop().expect("checked fd count");
        let stderr = fds.pop().expect("checked fd count");
        let stdout = fds.pop().expect("checked fd count");
        let stdin = fds.pop().expect("checked fd count");
        let commit = Request::CommitSpawn {
            version: PROTOCOL_VERSION,
            session_id: session_id.clone(),
            operation_id: operation_id.clone(),
        };
        let commit_client = self.clone();
        let committed = tokio::task::spawn_blocking(move || commit_client.transact(&commit))
            .await
            .map_err(|error| ContainmentError::Internal(error.to_string()))?
            .map_err(|_| unavailable())?;
        let commit_valid = matches!(
            &committed,
            (Response::Committed { version: PROTOCOL_VERSION, key: committed_key }, extra)
                if committed_key == &key && extra.is_empty()
        );
        if !commit_valid {
            let cancel = Request::CancelOperation { version: PROTOCOL_VERSION, session_id, operation_id };
            let client = self.clone();
            let _ = tokio::task::spawn_blocking(move || client.transact(&cancel)).await;
            return Err(unavailable());
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
            stdin: Some(Box::pin(tokio::fs::File::from_std(File::from(stdin)))),
            stdout: Some(Box::pin(tokio::fs::File::from_std(File::from(stdout)))),
            stderr: Some(Box::pin(tokio::fs::File::from_std(File::from(stderr)))),
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
    let broker_capability = duplicate_valid_capability(config.capability_fd)?;
    unsafe { libc::close(config.capability_fd) };
    let recovered_empty = verify_server_installation(&config)?;
    verify_socket_location(&config)?;
    remove_owned_socket(&config.socket_path)?;
    let listener = UnixListener::bind(&config.socket_path)?;
    chown_path(&config.socket_path, 0, config.allowed_gid)?;
    set_mode(&config.socket_path, 0o660)?;
    let mut stream = loop {
        let mut candidate = listener.accept()?.0;
        candidate.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        if verify_peer_uid(&candidate, config.allowed_uid).is_ok()
            && authenticate_connection(&mut candidate, &broker_capability).is_ok()
        {
            candidate.set_read_timeout(None)?;
            break candidate;
        }
    };
    fs::remove_file(&config.socket_path)?;
    let operations = recover_operation_records(&config)?;
    let mut durable_empty = recovered_empty;
    durable_empty.extend(
        operations.values()
            .filter(|operation| matches!(operation.status, OperationStatus::Cancelled | OperationStatus::Exited))
            .map(|operation| operation.key.clone()),
    );
    let mut state = BrokerState {
        children: BTreeMap::new(),
        operations,
        emptied: durable_empty,
        exit_statuses: BTreeMap::new(),
    };
    loop {
        match serve_one(&mut stream, &config, &mut state) {
            Ok(()) => {}
            Err(error) if matches!(error.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe) => {
                cleanup_connection_children(&config, &mut state);
                return Ok(());
            }
            Err(error) => {
                cleanup_connection_children(&config, &mut state);
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
    prepared: Option<Spawned>,
}

#[derive(Serialize, Deserialize)]
struct DurableOperation {
    session_id: String,
    operation_id: String,
    status: OperationStatus,
    key: String,
    generation: u64,
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
    let request: Request = read_frame(stream)?;
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
        } if version == PROTOCOL_VERSION => {
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
            if let Some(existing) = state.operations.get(&operation_key) {
                let requested_key = containment_key(&containment_id, generation)?;
                if existing.key != requested_key || existing.generation != generation {
                    return send_response(stream, &Response::Error { version: PROTOCOL_VERSION, code: "operation_identity_conflict".into() }, &[]);
                }
                return match (&existing.status, &existing.prepared) {
                    (OperationStatus::Prepared, Some(spawned)) => send_response(
                        stream,
                        &Response::Prepared { version: PROTOCOL_VERSION, key: existing.key.clone(), guard: spawned.guard.clone() },
                        &[spawned.stdin.as_raw_fd(), spawned.stdout.as_raw_fd(), spawned.stderr.as_raw_fd(), spawned.pidfd.as_raw_fd()],
                    ),
                    _ => send_response(stream, &Response::Operation { version: PROTOCOL_VERSION, state: existing.status, key: Some(existing.key.clone()) }, &[]),
                };
            }
            let spawned = spawn_atomic(config, &containment_id, generation, &program, &args, &cwd, &env);
            match spawned {
                Ok(spawned) => {
                    let key = spawned.key.clone();
                    persist_operation(config, &session_id, &operation_id, OperationStatus::Prepared, &key, generation)?;
                    let result = send_response(
                        &stream,
                        &Response::Prepared {
                            version: PROTOCOL_VERSION,
                            key: key.clone(),
                            guard: spawned.guard.clone(),
                        },
                        &[spawned.stdin.as_raw_fd(), spawned.stdout.as_raw_fd(), spawned.stderr.as_raw_fd(), spawned.pidfd.as_raw_fd()],
                    );
                    if result.is_ok() {
                        state.operations.insert(operation_key, BrokerOperation {
                            status: OperationStatus::Prepared,
                            key,
                            generation,
                            prepared: Some(spawned),
                        });
                    } else {
                        rollback_generation(&config.cgroup_root.join(&key), spawned.pid);
                    }
                    result
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
            let operation = state.operations.get_mut(&(session_id, operation_id))
                .ok_or_else(|| invalid("unknown spawn operation"))?;
            if matches!(operation.status, OperationStatus::Committed | OperationStatus::Exited) {
                return send_response(stream, &Response::Committed { version: PROTOCOL_VERSION, key: operation.key.clone() }, &[]);
            }
            if !matches!(operation.status, OperationStatus::Prepared) {
                return send_response(stream, &Response::Error { version: PROTOCOL_VERSION, code: "operation_cancelled".into() }, &[]);
            }
            let mut spawned = operation.prepared.take().ok_or_else(|| invalid("prepared operation has no child"))?;
            persist_operation(config, &session_id, &operation_id, OperationStatus::Committing, &operation.key, operation.generation)?;
            release_child(&mut spawned)?;
            operation.status = OperationStatus::Committed;
            state.children.insert(operation.key.clone(), spawned.pid);
            persist_operation(config, &session_id, &operation_id, OperationStatus::Committed, &operation.key, operation.generation)?;
            send_response(stream, &Response::Committed { version: PROTOCOL_VERSION, key: operation.key.clone() }, &[])
        }
        Request::CancelOperation { version, session_id, operation_id }
            if version == PROTOCOL_VERSION => {
            if let Some(operation) = state.operations.get_mut(&(session_id, operation_id)) {
                if matches!(operation.status, OperationStatus::Prepared) {
                    if let Some(spawned) = operation.prepared.take() {
                        rollback_generation(&config.cgroup_root.join(&spawned.key), spawned.pid);
                    }
                    operation.status = OperationStatus::Cancelled;
                    persist_operation(config, &session_id, &operation_id, OperationStatus::Cancelled, &operation.key, operation.generation)?;
                } else if matches!(operation.status, OperationStatus::Committing | OperationStatus::Committed) {
                    let path = resolve_key(config, &operation.key, operation.generation)?;
                    fs::write(path.join("cgroup.kill"), b"1")?;
                }
            }
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
            let path = resolve_key(config, &key, generation)?;
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
            let path = resolve_key(config, &key, generation)?;
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
    guard: GuardAttestation,
}

fn spawn_atomic(
    config: &LinuxBrokerServerConfig,
    containment_id: &str,
    generation: u64,
    program: &[u8],
    args: &[String],
    cwd: &[u8],
    env: &BTreeMap<String, String>,
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
        .map(|(key, value)| CString::new(format!("{key}={value}")))
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
                stdin_read.as_raw_fd(),
                stdout_write.as_raw_fd(),
                stderr_write.as_raw_fd(),
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
            rollback_generation(&group, pid);
            return Err(std::io::Error::from_raw_os_error(i32::from_ne_bytes(errno)));
        }
        Ok(_) | Err(_) => {
            rollback_generation(&group, pid);
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
        guard: GuardAttestation {
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
    seccomp: &[libc::sock_filter; 18],
    cap_last: u32,
) -> ! {
    if unsafe { libc::dup2(stdin, libc::STDIN_FILENO) } < 0
        || unsafe { libc::dup2(stdout, libc::STDOUT_FILENO) } < 0
        || unsafe { libc::dup2(stderr, libc::STDERR_FILENO) } < 0
        || unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWCGROUP) } != 0
        || unsafe { libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) } != 0
        || unsafe { libc::mount(std::ptr::null(), c"/sys/fs/cgroup".as_ptr(), std::ptr::null(), libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY, std::ptr::null()) } != 0
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

fn rollback_generation(group: &Path, pid: libc::pid_t) {
    let _ = fs::write(group.join("cgroup.kill"), b"1");
    let _ = reap_child(pid);
    let _ = wait_cgroup_empty(group, std::time::Duration::from_secs(5));
    let _ = fs::remove_dir(group);
}

fn reap_child(pid: libc::pid_t) -> std::io::Result<Option<i32>> {
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return Ok(decode_wait_status(status));
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
    for ((session_id, operation_id), operation) in &mut state.operations {
        if let Some(spawned) = operation.prepared.take() {
            rollback_generation(&config.cgroup_root.join(&spawned.key), spawned.pid);
            operation.status = OperationStatus::Cancelled;
            let _ = persist_operation(config, session_id, operation_id, OperationStatus::Cancelled, &operation.key, operation.generation);
        }
    }
    let children = std::mem::take(&mut state.children);
    for (key, pid) in children {
        let group = config.cgroup_root.join(&key);
        let _ = fs::write(group.join("cgroup.kill"), b"1");
        if let Ok(exit_status) = reap_child(pid) {
            state.exit_statuses.insert(key.clone(), exit_status);
        }
        if wait_cgroup_empty(&group, std::time::Duration::from_secs(5)).is_ok() {
            let _ = fs::remove_dir(&group);
            state.remember_empty(key.clone());
            let _ = mark_operation_terminal(config, state, &key, OperationStatus::Exited);
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
        persist_operation(config, &session_id, &operation_id, status, &operation.key, operation.generation)?;
    }
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

fn seccomp_guard_program() -> [libc::sock_filter; 18] {
    // Deny namespace/mount mutation after the broker has installed the private,
    // read-only cgroup view. Everything else remains governed by the ordinary
    // hook sandbox and no_new_privs.
    let denied = [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_clone,
        libc::SYS_clone3,
    ];
    let mut filter = [stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW); 18];
    filter[0] = stmt(BPF_LD | BPF_W | BPF_ABS, 4);
    filter[1] = jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch(), 1, 0);
    filter[2] = stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    filter[3] = stmt(BPF_LD | BPF_W | BPF_ABS, 0);
    #[cfg(target_arch = "x86_64")]
    {
        // Reject the x32 syscall ABI before comparing syscall numbers. Its
        // high-bit encoding otherwise bypasses a native-number deny list.
        filter[4] = jump(BPF_JMP | BPF_JSET | BPF_K, X32_SYSCALL_BIT, 0, 1);
        filter[5] = stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        filter[4] = stmt(BPF_JMP | BPF_JA, 1);
        filter[5] = stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    }
    for (index, syscall) in denied.into_iter().enumerate() {
        filter[6 + index * 2] = jump(BPF_JMP | BPF_JEQ | BPF_K, syscall as u32, 0, 1);
        filter[7 + index * 2] = stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | libc::EPERM as u32);
    }
    filter
}

unsafe fn install_seccomp_guard(filter: &[libc::sock_filter; 18]) -> std::io::Result<()> {
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

fn valid_key(key: &str, generation: u64) -> bool {
    let suffix = format!("-g{generation}");
    key.len() == 3 + 32 + suffix.len()
        && key.starts_with("fc-")
        && key.ends_with(&suffix)
        && key[3..35].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_environment(env: &BTreeMap<String, String>) -> std::io::Result<()> {
    for (key, value) in env {
        if key.is_empty()
            || key.len() > MAX_STRING_BYTES
            || value.len() > MAX_STRING_BYTES
            || key.as_bytes().contains(&b'=')
            || key.as_bytes().contains(&0)
            || value.as_bytes().contains(&0)
        {
            return Err(invalid("invalid environment entry"));
        }
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
    let expected_cgroup_root = Path::new(DEFAULT_CGROUP_ROOT).join(format!("u{}", config.allowed_uid));
    if config.cgroup_root != expected_cgroup_root {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "broker cgroup root is not the canonical installation root",
        ));
    }
    verify_cgroup2_filesystem(&config.cgroup_root)?;
    verify_state_root(config)?;
    fs::create_dir_all(&config.cgroup_root)?;
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
        wait_cgroup_empty(&group, std::time::Duration::from_secs(5))?;
        fs::remove_dir(&group)?;
        recovered.insert(key);
    }
    verify_kernel_spawn_contract(config)?;
    Ok(recovered)
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
) -> std::io::Result<()> {
    let destination = operation_record_path(config, session_id, operation_id)?;
    let record = DurableOperation {
        session_id: session_id.to_owned(),
        operation_id: operation_id.to_owned(),
        status,
        key: key.to_owned(),
        generation,
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

fn recover_operation_records(config: &LinuxBrokerServerConfig) -> std::io::Result<BTreeMap<(String, String), BrokerOperation>> {
    let mut operations = BTreeMap::new();
    for entry in fs::read_dir(&config.state_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || metadata.len() > MAX_FRAME as u64 {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "invalid broker operation record"));
        }
        let record: DurableOperation = serde_json::from_slice(&fs::read(entry.path())?).map_err(invalid)?;
        if !valid_key(&record.key, record.generation) {
            return Err(invalid("invalid durable containment locator"));
        }
        let recovered_status = match record.status {
            OperationStatus::Prepared | OperationStatus::Committing => OperationStatus::Cancelled,
            OperationStatus::Committed => OperationStatus::Exited,
            status => status,
        };
        if !matches!(record.status, OperationStatus::Cancelled | OperationStatus::Exited) {
            persist_operation(config, &record.session_id, &record.operation_id, recovered_status, &record.key, record.generation)?;
        }
        operations.insert((record.session_id, record.operation_id), BrokerOperation {
            status: recovered_status,
            key: record.key,
            generation: record.generation,
            prepared: None,
        });
    }
    Ok(operations)
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
    let existing = Path::new("/sys/fs/cgroup");
    let existing = CString::new(existing.as_os_str().as_bytes())
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
        &BTreeMap::new(),
    )?;
    if !spawned.guard.proven() {
        rollback_generation(&config.cgroup_root.join(&spawned.key), spawned.pid);
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
        rollback_generation(&group, spawned.pid);
        return Err(error);
    }
    wait_cgroup_empty(&group, std::time::Duration::from_secs(5))?;
    fs::remove_dir(group)
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

fn same_file_description(left: BorrowedFd<'_>, right: BorrowedFd<'_>) -> std::io::Result<bool> {
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
    let (body, mut fds) = recv_with_fds(stream.as_raw_fd(), 1)?;
    let request: Request = serde_json::from_slice(&body).map_err(invalid)?;
    let Some(capability) = fds.pop() else {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "missing containment capability"));
    };
    if !fds.is_empty()
        || !matches!(request, Request::Authenticate { version: PROTOCOL_VERSION })
        || !same_file_description(capability.as_fd(), expected.as_fd())?
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

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).map_err(invalid)?;
    if body.len() > MAX_FRAME { return Err(invalid("frame too large")); }
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(&body)
}

fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> std::io::Result<T> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME { return Err(invalid("frame too large")); }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(invalid)
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
        let count = recv_retry(socket, &mut frame[received..4])?;
        if count <= 0 { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short broker frame")); }
        received += count as usize;
    }
    let body_len = u32::from_be_bytes(frame[..4].try_into().expect("four byte length")) as usize;
    if body_len > MAX_FRAME { return Err(invalid("frame too large")); }
    let total = body_len + 4;
    while received < total {
        let count = recv_retry(socket, &mut frame[received..total])?;
        if count <= 0 { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short broker frame")); }
        received += count as usize;
    }
    Ok((frame[4..total].to_vec(), fds))
}

fn recv_retry(socket: RawFd, buffer: &mut [u8]) -> std::io::Result<isize> {
    loop {
        let received = unsafe {
            libc::recv(socket, buffer.as_mut_ptr().cast(), buffer.len(), libc::MSG_CMSG_CLOEXEC)
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
    fn broker_scm_rights_frame_is_bounded_and_ordered() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let (read, write) = pipe_cloexec().unwrap();
        let response = Response::Prepared {
            version: PROTOCOL_VERSION,
            key: format!("fc-{}-g3", "b".repeat(32)),
            guard: GuardAttestation {
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
        assert_eq!(filter.len(), 18);
        assert_eq!(filter[0].k, 4);
        assert_eq!(filter[1].k, audit_arch());
        assert_eq!(filter[2].k, SECCOMP_RET_KILL_PROCESS);
        for index in [7_usize, 9, 11, 13, 15, 17] {
            assert_eq!(filter[index].k, SECCOMP_RET_ERRNO | libc::EPERM as u32);
        }
    }
}
