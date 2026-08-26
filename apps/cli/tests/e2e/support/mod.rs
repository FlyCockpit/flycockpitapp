//! Shared integration-test support for process-boundary CLI coverage.
//!
//! Every harness instance owns a fresh temp root and passes XDG paths only to
//! child commands. The test process environment is never mutated, so tests can
//! run in parallel without sharing daemon sockets, databases, credentials, or
//! logs.

#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt;
use cockpit_cli::integration::{DaemonClient, DaemonStatus};

#[cfg(unix)]
mod hermetic;
#[cfg(target_os = "linux")]
mod mock_secret_service;
#[cfg(unix)]
mod osc52_observer;
#[cfg(unix)]
mod tui_pty;

#[cfg(unix)]
pub use hermetic::*;
#[cfg(target_os = "linux")]
pub use mock_secret_service::*;
#[cfg(unix)]
pub use osc52_observer::*;
#[cfg(unix)]
pub use tui_pty::*;

pub struct IsolatedHome {
    _root: tempfile::TempDir,
    config_home: PathBuf,
    data_home: PathBuf,
    state_home: PathBuf,
    runtime_dir: PathBuf,
    cache_home: PathBuf,
    project: PathBuf,
    extra_env: Vec<(String, String)>,
}

impl IsolatedHome {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("integration temp root");
        let config_home = root.path().join("config");
        let data_home = root.path().join("data");
        let state_home = root.path().join("state");
        let runtime_dir = root.path().join("runtime");
        let cache_home = root.path().join("cache");
        let project = root.path().join("project");
        for dir in [
            &config_home,
            &data_home,
            &state_home,
            &runtime_dir,
            &cache_home,
            &project,
        ] {
            std::fs::create_dir_all(dir).expect("create isolated integration dir");
        }
        Self {
            _root: root,
            config_home,
            data_home,
            state_home,
            runtime_dir,
            cache_home,
            project,
            extra_env: Vec::new(),
        }
    }

    pub fn cockpit(&self) -> Command {
        let mut cmd = Command::cargo_bin("cockpit").expect("cockpit binary");
        self.apply_env(&mut cmd);
        cmd.current_dir(&self.project);
        cmd
    }

    pub fn socket_path(&self) -> PathBuf {
        self.runtime_dir.join("cockpit").join("cockpit.sock")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.state_home.join("cockpit").join("daemon.pid")
    }

    pub fn log_file(&self) -> PathBuf {
        self.cache_home.join("cockpit").join("cockpit.log")
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_home.join("cockpit").join("cockpit.db")
    }

    pub fn config_dir(&self) -> PathBuf {
        self._root.path().join(".config").join("cockpit")
    }

    pub fn project_path(&self) -> &std::path::Path {
        &self.project
    }

    pub fn home_dir(&self) -> &std::path::Path {
        self._root.path()
    }

    pub fn xdg_config_home(&self) -> &std::path::Path {
        &self.config_home
    }

    pub fn xdg_data_home(&self) -> &std::path::Path {
        &self.data_home
    }

    pub fn xdg_state_home(&self) -> &std::path::Path {
        &self.state_home
    }

    pub fn xdg_runtime_dir(&self) -> &std::path::Path {
        &self.runtime_dir
    }

    pub fn xdg_cache_home(&self) -> &std::path::Path {
        &self.cache_home
    }

    pub fn write_local_provider_config(&self, base_url: &str) {
        let config_dir = self.config_dir();
        let providers_dir = config_dir.join("providers");
        std::fs::create_dir_all(&providers_dir).expect("create providers config dir");
        std::fs::write(
            config_dir.join("config.json"),
            r#"{"active_model":{"provider":"local","model":"scripted"},"sandbox_escalation_enabled":false}"#,
        )
        .expect("write integration config.json");
        std::fs::write(
            providers_dir.join("local.json"),
            format!(
                r#"{{
  "url": "{}",
  "auth": "none",
  "wire_api": "completions",
  "allow_insecure_http": true,
  "models": [
    {{"id": "scripted", "manual": true, "can_delegate": false, "subagent_invokable": true}},
    {{"id": "fallback", "manual": true, "subagent_invokable": true}}
  ]
}}"#,
                base_url
            ),
        )
        .expect("write integration provider config");
    }

    /// Merge mouse-copy TUI flags into the isolated `config.json` written by
    /// [`Self::write_local_provider_config`]. Call after pointing the local
    /// provider at a loopback scripted listener.
    pub fn merge_tui_mouse_copy_config(&self) {
        let path = self.config_dir().join("config.json");
        let raw = std::fs::read_to_string(&path).expect("read isolated config.json");
        let mut value: serde_json::Value =
            serde_json::from_str(&raw).expect("parse isolated config.json");
        let object = value
            .as_object_mut()
            .expect("isolated config.json must be an object");
        object.insert(
            "tui".into(),
            serde_json::json!({
                "mouse_capture": true,
                "copy_on_release": true
            }),
        );
        std::fs::write(
            &path,
            serde_json::to_string(&value).expect("serialize merged config.json"),
        )
        .expect("write merged isolated config.json");
    }

    /// Rewrite the dummy local provider to `base_url` and enable mouse capture
    /// plus copy-on-release in `HOME/.config/cockpit/config.json`.
    pub fn write_scripted_provider_with_tui_mouse(&self, base_url: &str) {
        self.write_local_provider_config(base_url);
        self.merge_tui_mouse_copy_config();
    }

    pub fn trust_project(&self) {
        let output = self
            .cockpit()
            .args([
                "trust",
                "set",
                &self.project.display().to_string(),
                "--mode",
                "trust",
            ])
            .output()
            .expect("trust integration project");
        assert_success("cockpit trust set", &output, self);
    }

    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.extra_env.push((key.into(), value.into()));
    }

    /// IsolatedHome unsets `DBUS_SESSION_BUS_ADDRESS` so detach cannot hang
    /// in Secret Service. Doctor treats a missing required keyring as a
    /// failed check; tests that need exit 0 must attach a private bus.
    #[cfg(target_os = "linux")]
    pub fn enable_mock_keyring(&mut self) -> MockSecretService {
        let service = start_mock_secret_service();
        self.set_env("DBUS_SESSION_BUS_ADDRESS", service.address.clone());
        service
    }

    fn apply_env(&self, cmd: &mut Command) {
        cmd.env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("XDG_STATE_HOME", &self.state_home)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("XDG_CACHE_HOME", &self.cache_home)
            .env("HOME", self._root.path())
            .env_remove("COCKPIT_CONFIG")
            .env_remove("COCKPIT_LOG")
            .env_remove("DBUS_SESSION_BUS_ADDRESS");
        for (key, value) in &self.extra_env {
            cmd.env(key, value);
        }
    }
}

pub struct SpawnedDaemon {
    home: IsolatedHome,
}

impl SpawnedDaemon {
    pub async fn start() -> Self {
        Self::start_in(IsolatedHome::new()).await
    }

    pub async fn start_with_home(home: IsolatedHome) -> Self {
        Self::start_in(home).await
    }

    /// Start a debug daemon whose agent-installation RPCs use one immutable
    /// scripted service.  The child receives only a path to non-secret JSON;
    /// the fixture cannot carry credentials or a transport endpoint.
    #[cfg(debug_assertions)]
    pub async fn start_with_agent_installation_fixture(fixture: &serde_json::Value) -> Self {
        Self::start_with_home_agent_installation_fixture(IsolatedHome::new(), fixture).await
    }

    #[cfg(debug_assertions)]
    pub async fn start_with_home_agent_installation_fixture(
        mut home: IsolatedHome,
        fixture: &serde_json::Value,
    ) -> Self {
        let path = home.home_dir().join("agent-installation-fixture.json");
        std::fs::write(
            &path,
            serde_json::to_vec(fixture).expect("serialize agent-installation fixture"),
        )
        .expect("write non-secret agent-installation fixture");
        home.set_env(
            cockpit_cli::integration_test_api::agent_installation::DEBUG_AGENT_INSTALLATION_FIXTURE_ENV,
            path.display().to_string(),
        );
        Self::start_in(home).await
    }

    async fn start_in(home: IsolatedHome) -> Self {
        let output = home
            .cockpit()
            .args(["daemon", "start", "--detach"])
            .env("COCKPIT_LOG", "warn,cockpit::startup=info")
            .output()
            .expect("spawn daemon start command");
        assert_success("cockpit daemon start --detach", &output, &home);
        wait_for_status_handshake(&home, DAEMON_START_HANDSHAKE_TIMEOUT).await;
        Self { home }
    }

    pub fn command(&self) -> Command {
        self.home.cockpit()
    }

    pub fn project_path(&self) -> &std::path::Path {
        self.home.project_path()
    }

    pub fn home(&self) -> &IsolatedHome {
        &self.home
    }

    pub fn db_path(&self) -> PathBuf {
        self.home.db_path()
    }

    pub fn pid(&self) -> u32 {
        self.try_pid().expect("daemon pid file")
    }

    pub fn try_pid(&self) -> Option<u32> {
        std::fs::read_to_string(self.home.pid_file())
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    pub fn socket_path(&self) -> PathBuf {
        self.home.socket_path()
    }

    pub async fn client(&self) -> DaemonClient {
        let client = DaemonClient::connect(&self.socket_path())
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "connect daemon client failed: {err:?}\nlog tail:\n{}",
                    log_tail(&self.home)
                )
            });
        assert!(
            client.is_socket_backed(),
            "integration client must use socket transport"
        );
        client
    }

    pub async fn status(&self) -> DaemonStatus {
        self.client().await.status().await.unwrap_or_else(|err| {
            panic!(
                "daemon status request failed: {err:?}\nlog tail:\n{}",
                log_tail(&self.home)
            )
        })
    }

    pub async fn restart_same_home(&self) {
        let output = self
            .home
            .cockpit()
            .args(["daemon", "start", "--detach"])
            .output()
            .expect("restart daemon in same home");
        assert_success("cockpit daemon start --detach", &output, &self.home);
        self.wait_for_handshake().await;
    }

    pub async fn wait_for_handshake(&self) {
        wait_for_status_handshake(&self.home, DAEMON_RESTART_HANDSHAKE_TIMEOUT).await;
    }

    #[cfg(unix)]
    pub async fn sigterm(&self) {
        self.signal(libc::SIGTERM).await;
    }

    #[cfg(unix)]
    pub async fn sigkill(&self) {
        self.signal(libc::SIGKILL).await;
    }

    #[cfg(unix)]
    async fn signal(&self, signal: libc::c_int) {
        let pid = self.pid();
        let rc = unsafe { libc::kill(pid as libc::pid_t, signal) };
        assert_eq!(
            rc,
            0,
            "signal {signal} to daemon pid {pid} failed: {}\nlog tail:\n{}",
            std::io::Error::last_os_error(),
            log_tail(&self.home)
        );
        wait_until_with_home(
            "daemon process exit",
            Duration::from_secs(5),
            &self.home,
            || async move { !pid_is_live(pid) },
        )
        .await;
    }
}

impl Drop for SpawnedDaemon {
    fn drop(&mut self) {
        let pid = self.try_pid();
        let _ = self
            .home
            .cockpit()
            .args(["daemon", "stop", "--grace", "0"])
            .output();
        #[cfg(unix)]
        if let Some(pid) = pid
            && !wait_for_pid_exit_blocking(pid, Duration::from_secs(2))
        {
            let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            let _ = wait_for_pid_exit_blocking(pid, Duration::from_secs(2));
        }
    }
}

pub fn assert_success(label: &str, output: &Output, home: &IsolatedHome) {
    if output.status.success() {
        return;
    }
    panic!(
        "{label} failed with status {}\nstdout:\n{}\nstderr:\n{}\nlog tail:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        log_tail(home)
    );
}

pub fn assert_failure(label: &str, output: &Output, home: &IsolatedHome) {
    if !output.status.success() {
        return;
    }
    panic!(
        "{label} unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}\nlog tail:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        log_tail(home)
    );
}

pub fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

const DAEMON_START_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(90);
const DAEMON_RESTART_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Cheap liveness check: connect and read the daemon hello line.
///
/// Handshake waits must not exec the debug `cockpit` binary in a tight loop.
/// Each status probe pages in a ~700MB binary and, while boot has bound the
/// socket but not yet entered the accept loop, sits on a 500ms hello timeout.
/// Under nextest load that starves the detached child so it never reaches
/// `daemon: running`.
#[cfg(unix)]
fn socket_answers_hello(socket: &Path) -> bool {
    use std::os::unix::net::UnixStream;

    if !socket.exists() {
        return false;
    }
    let Ok(stream) = UnixStream::connect(socket) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).is_ok() && !line.trim().is_empty()
}

#[cfg(not(unix))]
fn socket_answers_hello(socket: &Path) -> bool {
    socket.exists()
}

fn handshake_debug(home: &IsolatedHome) -> String {
    let pid_raw = std::fs::read_to_string(home.pid_file()).ok();
    let pid = pid_raw
        .as_deref()
        .and_then(|value| value.trim().parse::<u32>().ok());
    let live = {
        #[cfg(unix)]
        {
            pid.map(pid_is_live)
        }
        #[cfg(not(unix))]
        {
            None::<bool>
        }
    };
    let socket = home.socket_path();
    let log = home.log_file();
    let log_bytes = std::fs::metadata(&log).ok().map(|meta| meta.len());
    format!(
        "pid_file={} pid_raw={:?} live={:?} socket_exists={} hello={} log={} log_bytes={:?}\nlog tail:\n{}",
        home.pid_file().display(),
        pid_raw,
        live,
        socket.exists(),
        socket_answers_hello(&socket),
        log.display(),
        log_bytes,
        log_tail(home),
    )
}

async fn wait_for_status_handshake(home: &IsolatedHome, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(20);
    loop {
        if socket_answers_hello(&home.socket_path()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for daemon status handshake\n{}",
            handshake_debug(home)
        );
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(200));
    }
    let status = home
        .cockpit()
        .args(["daemon", "status"])
        .output()
        .expect("daemon status after hello");
    assert!(
        status.status.success() && output_text(&status).contains("daemon: running"),
        "daemon status after hello was not running\nstdout:\n{}\nstderr:\n{}\n{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
        handshake_debug(home)
    );
}

pub async fn wait_until<F, Fut>(label: &str, timeout: Duration, mut probe: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(2);
    loop {
        if probe().await {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

pub async fn wait_until_with_home<F, Fut>(
    label: &str,
    timeout: Duration,
    home: &IsolatedHome,
    mut probe: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(2);
    loop {
        if probe().await {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {label}\nlog tail:\n{}",
            log_tail(home)
        );
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

pub fn log_tail(home: &IsolatedHome) -> String {
    tail_file(home.log_file(), 8192).unwrap_or_else(|| "<no log file>".to_string())
}

fn tail_file(path: PathBuf, max_bytes: usize) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let start = bytes.len().saturating_sub(max_bytes);
    Some(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

#[cfg(unix)]
pub(crate) fn pid_is_live(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(unix)]
pub(crate) fn wait_for_pid_exit_blocking(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_is_live(pid) {
            return true;
        }
        std::thread::yield_now();
    }
    !pid_is_live(pid)
}
