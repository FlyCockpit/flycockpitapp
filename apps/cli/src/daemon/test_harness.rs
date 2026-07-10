use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use super::DaemonPaths;

pub(crate) const TEST_OWNER_ENV: &str = "COCKPIT_DAEMON_TEST_OWNER";

const DAEMON_ENV_VARS: &[&str] = &[
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_DATA_HOME",
    "COCKPIT_EPHEMERAL_SOCKET",
    "COCKPIT_EPHEMERAL_PID_FILE",
    TEST_OWNER_ENV,
];

static ENV_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) struct DaemonEnvGuard {
    saved: BTreeMap<&'static str, Option<OsString>>,
    _lock: MutexGuard<'static, ()>,
}

impl DaemonEnvGuard {
    pub(crate) fn new() -> Self {
        let lock = lock_env();
        let mut guard = Self {
            saved: BTreeMap::new(),
            _lock: lock,
        };
        for name in DAEMON_ENV_VARS {
            guard.capture(name);
        }
        guard
    }

    pub(crate) fn set_paths(vars: &[(&'static str, &Path)]) -> Self {
        let mut guard = Self::new();
        for (name, value) in vars {
            guard.set_path(name, value);
        }
        guard
    }

    pub(crate) fn set_path(&mut self, name: &'static str, value: &Path) {
        self.capture(name);
        unsafe {
            std::env::set_var(name, value);
        }
    }

    pub(crate) fn set_string(&mut self, name: &'static str, value: &str) {
        self.capture(name);
        unsafe {
            std::env::set_var(name, value);
        }
    }

    pub(crate) fn remove(&mut self, name: &'static str) {
        self.capture(name);
        unsafe {
            std::env::remove_var(name);
        }
    }

    fn capture(&mut self, name: &'static str) {
        self.saved
            .entry(name)
            .or_insert_with(|| std::env::var_os(name));
    }
}

impl Drop for DaemonEnvGuard {
    fn drop(&mut self) {
        unsafe {
            for (name, value) in std::mem::take(&mut self.saved) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

pub(crate) struct DaemonTestHarness {
    root: tempfile::TempDir,
    pub(crate) state_home: PathBuf,
    pub(crate) _runtime_dir: PathBuf,
    pub(crate) _data_home: PathBuf,
    pub(crate) owner: String,
    tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    _env: DaemonEnvGuard,
}

impl DaemonTestHarness {
    pub(crate) fn new() -> Self {
        sweep_stale_manifests().expect("sweep stale daemon test manifests");
        let root = tempfile::tempdir().expect("daemon harness tempdir");
        let state_home = root.path().join("state");
        let runtime_dir = root.path().join("runtime");
        let data_home = root.path().join("data");
        let owner = uuid::Uuid::new_v4().to_string();
        let mut env = DaemonEnvGuard::new();
        env.set_path("XDG_STATE_HOME", &state_home);
        env.set_path("XDG_RUNTIME_DIR", &runtime_dir);
        env.set_path("XDG_DATA_HOME", &data_home);
        env.remove("COCKPIT_EPHEMERAL_SOCKET");
        env.remove("COCKPIT_EPHEMERAL_PID_FILE");
        env.set_string(TEST_OWNER_ENV, &owner);
        Self {
            root,
            state_home,
            _runtime_dir: runtime_dir,
            _data_home: data_home,
            owner,
            tasks: Vec::new(),
            _env: env,
        }
    }

    pub(crate) fn ephemeral_paths(&self, stem: &str) -> DaemonPaths {
        DaemonPaths {
            socket: self.root.path().join(format!("{stem}.sock")),
            pid_file: self.root.path().join(format!("{stem}.pid")),
            ephemeral: true,
        }
    }

    pub(crate) fn manifest_path(&self, name: &str) -> PathBuf {
        manifest_dir().join(format!("{name}.json"))
    }
}

impl Drop for DaemonTestHarness {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TestDaemonManifest {
    pub(crate) owner: String,
    pub(crate) entries: Vec<TestDaemonManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TestDaemonManifestEntry {
    pub(crate) pid: u32,
    pub(crate) socket: PathBuf,
    pub(crate) pid_file: PathBuf,
    pub(crate) endpoint_file: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CleanupReport {
    pub(crate) removed_files: usize,
    pub(crate) signaled_processes: usize,
    pub(crate) dead_processes: usize,
}

pub(crate) fn write_manifest(path: &Path, manifest: &TestDaemonManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(manifest).context("serializing test daemon manifest")?;
    std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))
}

pub(crate) fn cleanup_manifest(path: &Path) -> Result<CleanupReport> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let manifest: TestDaemonManifest =
        serde_json::from_slice(&bytes).context("parsing test daemon manifest")?;
    let mut report = CleanupReport::default();

    for entry in &manifest.entries {
        if process_alive(entry.pid) {
            verify_test_daemon(entry.pid, &manifest.owner)?;
            signal_process(entry.pid)?;
            report.signaled_processes += 1;
            wait_until_dead(entry.pid);
        } else {
            report.dead_processes += 1;
        }
        report.removed_files += remove_if_exists(&entry.socket);
        report.removed_files += remove_if_exists(&entry.pid_file);
        if let Some(endpoint_file) = &entry.endpoint_file {
            report.removed_files += remove_if_exists(endpoint_file);
        }
    }
    report.removed_files += remove_if_exists(path);
    Ok(report)
}

pub(crate) fn sweep_stale_manifests() -> Result<CleanupReport> {
    let dir = manifest_dir();
    let mut total = CleanupReport::default();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(total);
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let report = cleanup_manifest(&path)?;
        total.removed_files += report.removed_files;
        total.signaled_processes += report.signaled_processes;
        total.dead_processes += report.dead_processes;
    }
    Ok(total)
}

pub(crate) fn manifest_dir() -> PathBuf {
    std::env::temp_dir().join("cockpit-daemon-test-manifests")
}

fn remove_if_exists(path: &Path) -> usize {
    match std::fs::remove_file(path) {
        Ok(()) => 1,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => 0,
    }
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
fn signal_process(pid: u32) -> Result<()> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).with_context(|| format!("signaling pid {pid}"))
    }
}

#[cfg(not(unix))]
fn signal_process(pid: u32) -> Result<()> {
    Err(anyhow!(
        "cannot signal test daemon pid {pid} on this platform"
    ))
}

fn wait_until_dead(pid: u32) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while process_alive(pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
fn verify_test_daemon(pid: u32, owner: &str) -> Result<()> {
    let env = std::fs::read(format!("/proc/{pid}/environ"))
        .with_context(|| format!("reading /proc/{pid}/environ"))?;
    let marker = format!("{TEST_OWNER_ENV}={owner}");
    let has_marker = env
        .split(|b| *b == 0)
        .any(|entry| entry == marker.as_bytes());
    if !has_marker {
        return Err(anyhow!(
            "refusing to signal pid {pid}: missing matching {TEST_OWNER_ENV} marker"
        ));
    }
    let args = super::read_process_cmdline(pid)?;
    if !super::cmdline_is_cockpit_daemon(&args) {
        return Err(anyhow!(
            "refusing to signal pid {pid}: process is not a cockpit daemon"
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_test_daemon(_pid: u32, _owner: &str) -> Result<()> {
    Err(anyhow!(
        "test daemon process identity is unsupported on this platform"
    ))
}
