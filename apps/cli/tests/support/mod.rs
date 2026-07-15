//! Shared integration-test support for process-boundary CLI coverage.
//!
//! Every harness instance owns a fresh temp root and passes XDG paths only to
//! child commands. The test process environment is never mutated, so tests can
//! run in parallel without sharing daemon sockets, databases, credentials, or
//! logs.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt;
use cockpit_cli::integration::{DaemonClient, DaemonStatus};

pub struct IsolatedHome {
    _root: tempfile::TempDir,
    config_home: PathBuf,
    data_home: PathBuf,
    state_home: PathBuf,
    runtime_dir: PathBuf,
    cache_home: PathBuf,
    project: PathBuf,
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

    pub fn project_path(&self) -> &std::path::Path {
        &self.project
    }

    fn apply_env(&self, cmd: &mut Command) {
        cmd.env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("XDG_STATE_HOME", &self.state_home)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("XDG_CACHE_HOME", &self.cache_home)
            .env("HOME", self._root.path())
            .env_remove("COCKPIT_CONFIG")
            .env_remove("COCKPIT_LOG");
    }
}

pub struct SpawnedDaemon {
    home: IsolatedHome,
}

impl SpawnedDaemon {
    pub async fn start() -> Self {
        Self::start_in(IsolatedHome::new()).await
    }

    async fn start_in(home: IsolatedHome) -> Self {
        let output = home
            .cockpit()
            .args(["daemon", "start", "--detach"])
            .output()
            .expect("spawn daemon start command");
        assert_success("cockpit daemon start --detach", &output, &home);
        wait_until_with_home(
            "daemon status handshake",
            Duration::from_secs(5),
            &home,
            || {
                let status = home
                    .cockpit()
                    .args(["daemon", "status"])
                    .output()
                    .expect("daemon status probe");
                async move {
                    status.status.success() && output_text(&status).contains("daemon: running")
                }
            },
        )
        .await;
        Self { home }
    }

    pub fn command(&self) -> Command {
        self.home.cockpit()
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
        wait_until_with_home(
            "daemon status handshake",
            Duration::from_secs(5),
            &self.home,
            || {
                let status = self
                    .home
                    .cockpit()
                    .args(["daemon", "status"])
                    .output()
                    .expect("daemon status probe");
                async move {
                    status.status.success() && output_text(&status).contains("daemon: running")
                }
            },
        )
        .await;
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

fn log_tail(home: &IsolatedHome) -> String {
    tail_file(home.log_file(), 8192).unwrap_or_else(|| "<no log file>".to_string())
}

fn tail_file(path: PathBuf, max_bytes: usize) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let start = bytes.len().saturating_sub(max_bytes);
    Some(String::from_utf8_lossy(&bytes[start..]).into_owned())
}

#[cfg(unix)]
fn pid_is_live(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(unix)]
fn wait_for_pid_exit_blocking(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_is_live(pid) {
            return true;
        }
        std::thread::yield_now();
    }
    !pid_is_live(pid)
}
