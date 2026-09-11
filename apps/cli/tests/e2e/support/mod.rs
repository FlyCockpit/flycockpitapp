//! Shared integration-test support for process-boundary CLI coverage.
//!
//! Every harness instance owns a fresh temp root and passes XDG paths only to
//! child commands. The test process environment is never mutated, so tests can
//! run in parallel without sharing daemon sockets, databases, credentials, or
//! logs.

#![allow(dead_code)]

#[cfg(unix)]
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd as _, OwnedFd};

use assert_cmd::cargo::CommandCargoExt;
use cockpit_cli::integration::{DaemonClient, DaemonStatus};

#[cfg(unix)]
mod hermetic;
#[cfg(target_os = "linux")]
mod mock_secret_service;
#[cfg(unix)]
mod osc52_observer;
mod replay_launch_barrier;
#[cfg(unix)]
mod tui_pty;

#[cfg(unix)]
pub use hermetic::*;
#[cfg(target_os = "linux")]
pub use mock_secret_service::*;
#[cfg(unix)]
pub use osc52_observer::*;
pub use replay_launch_barrier::*;
#[cfg(unix)]
pub use tui_pty::*;

pub struct IsolatedHome {
    _root: Option<tempfile::TempDir>,
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
        let root = cockpit_test_support::isolated_tempdir();
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
            // Backup-lock ancestry refuses group/other-writable parents.
            // `create_dir_all` honors umask (often 0002 → 0775), which would
            // make an existing-ledger daemon start fail closed.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .expect("restrict isolated integration dir");
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("restrict isolated temp root");
        }
        Self {
            _root: Some(root),
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
        self.config_home.join("cockpit")
    }

    pub fn project_path(&self) -> &std::path::Path {
        &self.project
    }

    pub fn home_dir(&self) -> &std::path::Path {
        self._root.as_ref().expect("isolated home root").path()
    }

    /// Keep the isolated tree when process cleanup cannot prove completion.
    /// Removing its receipt/socket while the owned daemon may still be alive
    /// would hide an escaped generation from the test runner.
    pub fn preserve_after_cleanup_failure(&mut self) -> PathBuf {
        self._root
            .take()
            .expect("isolated home root already preserved")
            .keep()
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
        // The loopback scripted providers are free to run, but the delegation
        // budget ledger treats unpriced token usage as fail-closed under a
        // finite cost ceiling (issue #313). Model them with a legitimate $0
        // price row so multi-round scripts charge real (zero-cost) usage
        // instead of tripping `budget exhausted (cost)` after round one.
        let prices_home = self._root.path().join(".cockpit");
        std::fs::create_dir_all(&prices_home).expect("create isolated prices dir");
        std::fs::write(
            prices_home.join("prices.json"),
            r#"{"scripted": {}, "fallback": {}}"#,
        )
        .expect("write integration prices.json");
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
            .env("HOME", self.home_dir())
            .env_remove("COCKPIT_CONFIG")
            .env_remove("COCKPIT_LOG")
            .env_remove("DBUS_SESSION_BUS_ADDRESS");
        for (key, value) in &self.extra_env {
            cmd.env(key, value);
        }
    }
}

pub struct SpawnedDaemon {
    // Declared before `home` so the exact child is killed and reaped before
    // TempDir removes the isolated socket, endpoint, database, and log tree.
    process: EphemeralDaemonGuard,
    home: IsolatedHome,
}

/// Stable kernel handles for sandbox processes proven to descend from this
/// harness's exact daemon child. Holding pidfds across daemon death avoids PID
/// reuse and lets the assertion wait on process exit without retries or name-
/// based killing.
#[cfg(target_os = "linux")]
pub struct OwnedSandboxDescendants {
    processes: Vec<OwnedSandboxDescendant>,
}

#[cfg(target_os = "linux")]
struct OwnedSandboxDescendant {
    pid: u32,
    command: String,
    executable_name: String,
    pidfd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl OwnedSandboxDescendants {
    pub fn assert_exited(self) {
        use std::os::fd::AsRawFd as _;

        for process in &self.processes {
            let mut pollfd = libc::pollfd {
                fd: process.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                // SAFETY: `pollfd` points to one initialized entry whose fd is
                // an owned pidfd retained by `process` for the whole call. A
                // pidfd becoming readable is the kernel completion signal for
                // this exact process; the enclosing test runner owns hangs.
                let ready = unsafe { libc::poll(&mut pollfd, 1, -1) };
                if ready > 0 && pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                    panic!(
                        "waiting for owned sandbox descendant {} ({}) returned invalid pidfd readiness {:#x}",
                        process.pid, process.command, pollfd.revents
                    );
                }
                if ready > 0 && pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if ready < 0 && error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                panic!(
                    "waiting for owned sandbox descendant {} ({}) failed: {error}",
                    process.pid, process.command
                );
            }
        }
    }
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
        let child = spawn_foreground_daemon(&home);
        let process = EphemeralDaemonGuard::new(child, home.socket_path(), home.pid_file());
        wait_for_status_handshake(&home, DAEMON_START_HANDSHAKE_TIMEOUT).await;
        Self { process, home }
    }

    pub async fn restart_same_home(&self) {
        self.process.reap_current();
        self.process.replace(spawn_foreground_daemon(&self.home));
        self.wait_for_handshake().await;
    }

    /// Exercise the product restart command without deadlocking on the exact
    /// foreground child retained by this harness. The command asks that child
    /// to exit, while this process (its parent) performs the corresponding
    /// wait so the product can observe PID release. After proving the detached
    /// product replacement is usable, normalize it back to an exactly owned
    /// foreground child for the remainder of the test and unwind cleanup.
    pub async fn restart_via_command(&self, grace_secs: u64) -> Output {
        self.restart_via_command_with_socket(grace_secs, true).await
    }

    pub async fn restart_via_unreachable_socket(&self) -> Output {
        std::fs::remove_file(self.home.socket_path())
            .expect("remove daemon socket to drive restart signal fallback");
        self.restart_via_command_with_socket(0, false).await
    }

    async fn restart_via_command_with_socket(
        &self,
        grace_secs: u64,
        socket_reachable: bool,
    ) -> Output {
        let had_owned_child = self.process.has_current();
        let grace = grace_secs.to_string();
        let mut command = self.home.cockpit();
        let mut command_child = command
            .args(["daemon", "restart", "--grace", &grace])
            .env("COCKPIT_LOG", "warn,cockpit::startup=info")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("daemon restart command");

        let owned_child_exited = self
            .process
            .reap_while_command_runs(&mut command_child)
            .expect("coordinate daemon restart with exact child");
        let output = command_child
            .wait_with_output()
            .expect("wait for daemon restart command");
        assert!(
            !had_owned_child || owned_child_exited,
            "daemon restart command exited before its owned daemon (socket reachable: {socket_reachable}); stdout:\n{}\nstderr:\n{}\nlog tail:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            log_tail(&self.home)
        );
        assert_success("daemon restart", &output, &self.home);

        // The command's own detached replacement must publish a usable
        // endpoint before the harness changes its ownership form.
        if let Err(debug) =
            wait_for_status_handshake_result(&self.home, DAEMON_RESTART_HANDSHAKE_TIMEOUT).await
        {
            let _ = self
                .home
                .cockpit()
                .args(["daemon", "stop", "--grace", "0"])
                .output();
            panic!("timed out waiting for product restart handshake\n{debug}");
        }
        let stop = self
            .home
            .cockpit()
            .args(["daemon", "stop", "--grace", "0"])
            .output()
            .expect("stop detached restart replacement");
        assert_success("stop detached restart replacement", &stop, &self.home);

        self.process.replace(spawn_foreground_daemon(&self.home));
        self.wait_for_handshake().await;
        output
    }

    /// Run the product stop command while reaping the exact child from its
    /// actual parent. Without this wait, the exited child remains a zombie and
    /// the product command correctly refuses to treat its PID as released.
    pub fn stop_via_command(&self, grace_secs: u64) -> Output {
        self.stop_via_command_with_socket(grace_secs, true)
    }

    pub fn stop_via_unreachable_socket(&self) -> Output {
        std::fs::remove_file(self.home.socket_path())
            .expect("remove daemon socket to drive signal fallback");
        self.stop_via_command_with_socket(0, false)
    }

    fn stop_via_command_with_socket(&self, grace_secs: u64, socket_reachable: bool) -> Output {
        let grace = grace_secs.to_string();
        let mut command = self.home.cockpit();
        let mut command_child = command
            .args(["daemon", "stop", "--grace", &grace])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("daemon stop command");
        let owned_child_exited = self
            .process
            .reap_while_command_runs(&mut command_child)
            .expect("coordinate daemon stop with exact child");
        command_child
            .wait_with_output()
            .map(|output| {
                assert!(
                    owned_child_exited,
                    "daemon stop command exited before its owned daemon (socket reachable: {socket_reachable}); stdout:\n{}\nstderr:\n{}\nlog tail:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                    log_tail(&self.home)
                );
                output
            })
            .expect("wait for daemon stop command")
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
        cockpit_host::daemon_lifecycle::read_pid_file(&self.home.pid_file())
    }

    /// Snapshot the sandbox launchers below this harness's exact daemon and
    /// pin their identities with pidfds before a SIGKILL test kills the owner.
    #[cfg(target_os = "linux")]
    pub fn capture_owned_sandbox_descendants(&self) -> OwnedSandboxDescendants {
        let daemon_pid = self.pid();
        // A child forked by a non-leader thread reports that thread's TID as
        // PPid in /proc. The daemon's pinned process spawner intentionally has
        // that topology, so ownership begins at every task in the daemon's
        // thread group rather than only at its TGID.
        let mut descendants = std::fs::read_dir(format!("/proc/{daemon_pid}/task"))
            .expect("read daemon task identities")
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            descendants.contains(&daemon_pid),
            "daemon task identities include the thread-group leader"
        );
        let mut processes = Vec::new();
        let mut owned_commands = Vec::new();
        let mut proc_rows = std::fs::read_dir("/proc")
            .expect("read /proc for daemon descendants")
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
                let status = std::fs::read_to_string(entry.path().join("status")).ok()?;
                let ppid = status
                    .lines()
                    .find_map(|line| line.strip_prefix("PPid:\t"))?
                    .trim()
                    .parse::<u32>()
                    .ok()?;
                Some((pid, ppid, entry.path()))
            })
            .collect::<Vec<_>>();
        loop {
            let before = descendants.len();
            for (pid, ppid, _) in &proc_rows {
                if descendants.contains(ppid) {
                    descendants.insert(*pid);
                }
            }
            if descendants.len() == before {
                break;
            }
        }
        for (pid, _, path) in proc_rows.drain(..) {
            if !descendants.contains(&pid) || pid == daemon_pid {
                continue;
            }
            let executable_name = std::fs::read_to_string(path.join("comm"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let command = std::fs::read(path.join("cmdline"))
                .map(|bytes| {
                    String::from_utf8_lossy(&bytes)
                        .replace('\0', " ")
                        .trim()
                        .to_string()
                })
                .unwrap_or_else(|_| executable_name.clone());
            owned_commands.push((pid, executable_name.clone(), command.clone()));
            if executable_name != "bwrap"
                && !executable_name.contains("zerobox")
                && !command.contains("zerobox-linux-sandbox")
            {
                continue;
            }
            // SAFETY: pidfd_open takes a numeric PID and creates a fresh
            // descriptor; the descendant relationship was captured above.
            let raw_fd = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_open,
                    libc::pid_t::try_from(pid).expect("Linux pid fits pid_t"),
                    0,
                )
            };
            assert!(
                raw_fd >= 0,
                "pidfd_open for owned descendant {pid} failed: {}",
                std::io::Error::last_os_error()
            );
            processes.push(OwnedSandboxDescendant {
                pid,
                command,
                executable_name,
                // SAFETY: a successful pidfd_open returned a new descriptor,
                // and this is its sole transfer into an owning Rust handle.
                pidfd: unsafe {
                    OwnedFd::from_raw_fd(
                        std::os::fd::RawFd::try_from(raw_fd).expect("pidfd fits RawFd"),
                    )
                },
            });
        }
        assert!(
            processes
                .iter()
                .any(|process| process.executable_name.contains("zerobox")
                    || process.command.contains("zerobox-linux-sandbox")),
            "no zerobox launcher descended from daemon {daemon_pid}; owned descendants: {owned_commands:?}"
        );
        assert!(
            processes
                .iter()
                .any(|process| process.executable_name == "bwrap"),
            "no bwrap process descended from daemon {daemon_pid}"
        );
        OwnedSandboxDescendants { processes }
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
        // This test process is the child's parent. Reap the exact child here;
        // PID polling would report its zombie as live until this wait occurs.
        self.process.reap_current();
    }
}

fn spawn_foreground_daemon(home: &IsolatedHome) -> std::process::Child {
    // Mirror the production detached-spawn provenance handshake while
    // retaining the foreground Child in this process. The daemon persists
    // this ticket beside its isolated socket for follower CLI commands.
    let launch_ticket = format!(
        "{:032x}{:032x}",
        uuid::Uuid::new_v4().as_u128(),
        uuid::Uuid::new_v4().as_u128()
    );
    let mut command = home.cockpit();
    command
        .args(["daemon", "start", "--foreground"])
        .env("COCKPIT_LOG", "warn,cockpit::startup=info")
        .env("COCKPIT_DAEMON_LAUNCH_TICKET", &launch_ticket)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command.spawn().expect("spawn foreground daemon")
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

/// Window in which a freshly started/restarted daemon must record its pid
/// receipt. After a live owner is observed, the handshake wait is driven by
/// the owner's liveness and the socket hello, not by these budgets — see
/// [`wait_for_status_handshake`].
pub const DAEMON_START_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(90);
const DAEMON_RESTART_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

pub fn daemon_transport_ready_for_home(home: &IsolatedHome) -> bool {
    daemon_transport_ready_for_paths(&home.socket_path(), &home.pid_file())
}

fn daemon_transport_ready_for_paths(socket: &Path, pid_file: &Path) -> bool {
    cockpit_core::daemon::isolated_socket_transport_ready(socket, pid_file)
}

/// Cheap liveness check: connect and read the daemon hello line.
///
/// Handshake waits must not exec the debug `cockpit` binary in a tight loop.
/// Each status probe pages in a ~700MB binary and, while boot has bound the
/// socket but not yet entered the accept loop, sits on a 500ms hello timeout.
/// Under nextest load that starves the detached child so it never reaches
/// `daemon: running`.
#[cfg(unix)]
fn socket_answers_hello(socket: &Path, pid_file: &Path) -> bool {
    use std::os::unix::net::UnixStream;

    if !daemon_transport_ready_for_paths(socket, pid_file) {
        return false;
    }
    let Ok(stream) = UnixStream::connect(socket) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).is_ok() && !line.trim().is_empty()
}

fn hello_line_matches_receipt(
    line: &str,
    receipt: &cockpit_host::daemon_lifecycle::DaemonPidReceipt,
) -> bool {
    let Ok(envelope) = serde_json::from_str::<cockpit_proto::Envelope>(line) else {
        return false;
    };
    matches!(
        envelope.body,
        cockpit_proto::Body::Response { id, response }
            if id.is_nil()
                && matches!(
                    *response,
                    cockpit_proto::Response::DaemonStatus {
                        pid,
                        protocol_version: cockpit_proto::PROTOCOL_VERSION,
                        ..
                    } if pid == receipt.pid
                )
    )
}

/// One exact hello observation bound to the immutable receipt captured for the
/// same generation. Callers compare the receipt file both before and after.
#[cfg(unix)]
pub(crate) fn socket_answers_receipt_hello(
    socket: &Path,
    pid_file: &Path,
    receipt: &cockpit_host::daemon_lifecycle::DaemonPidReceipt,
) -> bool {
    use std::os::unix::net::UnixStream;

    if !daemon_transport_ready_for_paths(socket, pid_file) {
        return false;
    }
    let Ok(stream) = UnixStream::connect(socket) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).is_ok()
        && hello_line_matches_receipt(&line, receipt)
}

#[cfg(windows)]
fn socket_answers_hello(socket: &Path, pid_file: &Path) -> bool {
    if !daemon_transport_ready_for_paths(socket, pid_file) {
        return false;
    }
    let Ok(Some(pipe)) = cockpit_host::named_pipe::read_pipe_identity_if_present(socket) else {
        return false;
    };
    if !cockpit_host::named_pipe::pipe_is_listening(&pipe) {
        return false;
    }
    let Ok(stream) = cockpit_host::named_pipe::open_client_pipe_blocking(&pipe) else {
        return false;
    };
    matches!(
        cockpit_host::named_pipe::read_line_bounded(&stream, Duration::from_millis(200)),
        Ok(line) if !line.trim().is_empty()
    )
}

#[cfg(windows)]
pub(crate) fn socket_answers_receipt_hello(
    socket: &Path,
    pid_file: &Path,
    receipt: &cockpit_host::daemon_lifecycle::DaemonPidReceipt,
) -> bool {
    if !daemon_transport_ready_for_paths(socket, pid_file) {
        return false;
    }
    let Ok(Some(pipe)) = cockpit_host::named_pipe::read_pipe_identity_if_present(socket) else {
        return false;
    };
    let Ok(stream) = cockpit_host::named_pipe::open_client_pipe_blocking(&pipe) else {
        return false;
    };
    matches!(
        cockpit_host::named_pipe::read_line_bounded(&stream, Duration::from_millis(200)),
        Ok(line) if hello_line_matches_receipt(&line, receipt)
    )
}

#[cfg(not(any(unix, windows)))]
fn socket_answers_hello(socket: &Path, pid_file: &Path) -> bool {
    daemon_transport_ready_for_paths(socket, pid_file)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn socket_answers_receipt_hello(
    _socket: &Path,
    _pid_file: &Path,
    _receipt: &cockpit_host::daemon_lifecycle::DaemonPidReceipt,
) -> bool {
    false
}

fn handshake_debug(home: &IsolatedHome) -> String {
    let pid_raw = std::fs::read_to_string(home.pid_file()).ok();
    let pid = cockpit_host::daemon_lifecycle::read_pid_file(&home.pid_file());
    let live = pid.map(cockpit_host::daemon_lifecycle::process_exists);
    let socket = home.socket_path();
    let log = home.log_file();
    let log_bytes = std::fs::metadata(&log).ok().map(|meta| meta.len());
    format!(
        "pid_file={} pid_raw={:?} live={:?} socket_exists={} transport_ready={} hello={} log={} log_bytes={:?}\nlog tail:\n{}",
        home.pid_file().display(),
        pid_raw,
        live,
        socket.exists(),
        daemon_transport_ready_for_home(home),
        socket_answers_hello(&socket, &home.pid_file()),
        log.display(),
        log_bytes,
        log_tail(home),
    )
}

/// Wait for the daemon's status handshake using explicit completion signals
/// rather than a wall-clock budget.
///
/// Boot cost is unbounded on a loaded machine (SQLite durability makes every
/// boot transaction an fsync, and a full workspace test run saturates the
/// disk), so a fixed deadline only converts slow machines into flaky tests.
/// The signals are:
///
/// * the socket answers its hello line — proceed;
/// * a daemon pid recorded in the pid file goes live → dead without ever
///   publishing a hello — the daemon failed to boot; fail immediately;
/// * a dead pid we never observed live is a stale record (e.g. left behind by
///   a SIGKILLed owner while its replacement is still starting) — keep
///   waiting for a live owner.
///
/// `timeout` bounds only the window in which no owner was ever observed; once
/// a live owner is seen, the wait is patient for as long as that owner lives.
async fn wait_for_status_handshake(home: &IsolatedHome, timeout: Duration) {
    if let Err(debug) = wait_for_status_handshake_result(home, timeout).await {
        panic!("timed out waiting for daemon status handshake\n{debug}");
    }
}

async fn wait_for_status_handshake_result(
    home: &IsolatedHome,
    timeout: Duration,
) -> Result<(), String> {
    let no_owner_deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(20);
    let mut last_live_pid: Option<u32> = None;
    loop {
        if daemon_transport_ready_for_home(home)
            && let Ok(client) = DaemonClient::connect(&home.socket_path()).await
            && client.status().await.is_ok()
        {
            return Ok(());
        }
        let recorded_pid = cockpit_host::daemon_lifecycle::read_pid_file(&home.pid_file());
        let owner_progressing = match recorded_pid {
            Some(pid) if cockpit_host::daemon_lifecycle::process_exists(pid) => {
                last_live_pid = Some(pid);
                true
            }
            Some(pid) if last_live_pid == Some(pid) => {
                panic!(
                    "daemon pid {pid} exited before publishing its status handshake\n{}",
                    handshake_debug(home)
                );
            }
            _ => false,
        };
        if !owner_progressing && Instant::now() >= no_owner_deadline {
            return Err(format!(
                "timed out waiting for a live daemon owner to publish its status handshake\n{}",
                handshake_debug(home)
            ));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(200));
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

pub async fn wait_for_daemon_handshake_on_socket(
    socket: &Path,
    pid_file: &Path,
    timeout: Duration,
    mut child_exited: impl FnMut() -> Option<std::process::Output>,
) {
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(10);
    loop {
        if socket_answers_hello(socket, pid_file) {
            return;
        }
        if let Some(output) = child_exited() {
            panic!(
                "daemon exited before handshake on {}: {}",
                socket.display(),
                output_text(&output)
            );
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for daemon handshake on {}",
            socket.display()
        );
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_millis(200));
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
    cockpit_host::daemon_lifecycle::process_exists(pid)
}

/// Panic/unwind guard for foreground test daemons. Ensures the exact child is
/// terminated and reaped before its socket and lifecycle metadata are removed.
pub struct EphemeralDaemonGuard {
    child: std::sync::Mutex<Option<std::process::Child>>,
    socket: PathBuf,
    endpoint: PathBuf,
    pid_file: PathBuf,
}

impl EphemeralDaemonGuard {
    pub fn new(child: std::process::Child, socket: PathBuf, pid_file: PathBuf) -> Self {
        let endpoint = pid_file
            .parent()
            .expect("isolated daemon pid file has a state directory")
            .join("daemon-endpoint.json");
        Self {
            child: std::sync::Mutex::new(Some(child)),
            socket,
            endpoint,
            pid_file,
        }
    }

    pub fn try_wait(&self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let mut child = self.child.lock().unwrap_or_else(|error| error.into_inner());
        match child.as_mut() {
            Some(child) => child.try_wait(),
            None => Ok(None),
        }
    }

    pub fn wait_with_output(&self) -> std::io::Result<std::process::Output> {
        self.child
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("ephemeral daemon process")
            .wait_with_output()
    }

    fn replace(&self, child: std::process::Child) {
        self.reap_current();
        *self.child.lock().unwrap_or_else(|error| error.into_inner()) = Some(child);
    }

    fn reap_current(&self) {
        if let Some(mut child) = self
            .child
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.socket.exists() {
            let _ = std::fs::remove_file(&self.socket);
        }
        if self.endpoint.exists() {
            let _ = std::fs::remove_file(&self.endpoint);
        }
        if self.pid_file.exists() {
            let _ = std::fs::remove_file(&self.pid_file);
        }
    }

    fn has_current(&self) -> bool {
        self.child
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_some()
    }

    fn reap_while_command_runs(&self, command: &mut std::process::Child) -> std::io::Result<bool> {
        if !command.wait()?.success() {
            self.reap_current();
            return Ok(false);
        }
        let Some(mut child) = self
            .child
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        else {
            return Ok(false);
        };
        child.wait()?;
        Ok(true)
    }
}

impl Drop for EphemeralDaemonGuard {
    fn drop(&mut self) {
        self.reap_current();
    }
}
