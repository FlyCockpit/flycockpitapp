//! Hermetic Cockpit launcher for TUI PTY conformance tests.
//!
//! Resolves the compiled `cockpit` binary once and builds one enumerable
//! [`HermeticLaunchSpec`]. Every fixture-owned subprocess and the PTY child
//! is constructed solely from that spec after `env_clear()`.
//!
//! # Adding a mouse or clipboard scenario
//!
//! Dependent prompts should launch a ready session, inject documented
//! protocol bytes, and assert visible screen outcomes:
//!
//! ```ignore
//! use crate::support::{
//!     HermeticCockpit, HermeticProfile, sgr_left_click, wait_for_screen,
//! };
//!
//! let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
//! session.open_settings();
//! let pos = session
//!     .snapshot()
//!     .find_text("[Close settings]")
//!     .expect("settings close label");
//! session.write_bytes(&sgr_left_click(pos.sgr_x(), pos.sgr_y()));
//! wait_for_screen(&mut session, "composer marker after close", |screen| {
//!     !screen.contains("[Close settings]")
//!         && screen.contains(crate::support::COMPOSER_PLACEHOLDER)
//! });
//!
//! // Clipboard scenarios use HermeticProfile::RemoteOsc52 and inspect
//! // `session.osc52()` metadata only — never payload bytes.
//! ```

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

use super::osc52_observer::Osc52Observer;
use super::tui_pty::{COMPOSER_PLACEHOLDER, CellPos, ScreenSnapshot, UNWANTED_STARTUP_MARKERS};
use super::{IsolatedHome, assert_success, log_tail, output_text, pid_is_live};

/// Dummy loopback provider URL. Foundation tests must not contact a provider.
pub const DUMMY_PROVIDER_URL: &str = "http://127.0.0.1:9/v1";

pub const HERMETIC_TERM: &str = "xterm-256color";
pub const HERMETIC_LOCALE: &str = "C.UTF-8";
pub const REMOTE_OSC52_SSH_CONNECTION: &str = "127.0.0.1 65535 127.0.0.1 22";
/// portable-pty's Unix spawn always injects `SHELL` after `env_clear()`.
/// Pin a constant so the live child never inherits the host/passwd shell.
pub const HERMETIC_PTY_SHELL: &str = "/bin/sh";
/// Fixed system search path. PATH is a poison key (never inherited) but
/// doctor and host tools still need `git`/`rg` from the base system.
pub const HERMETIC_PATH: &str = "/usr/bin:/bin";

pub const INITIAL_PTY_COLS: u16 = 100;
pub const INITIAL_PTY_ROWS: u16 = 30;
/// Hard cap so a dependent fixture cannot allocate an unbounded cell grid.
pub const MAX_PTY_COLS: u16 = 200;
pub const MAX_PTY_ROWS: u16 = 60;

/// Canonical allowlisted environment keys, in declaration order.
pub const HERMETIC_ENV_KEYS: [&str; 10] = [
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_CACHE_HOME",
    "TERM",
    "LANG",
    "LC_ALL",
    "PATH",
];

const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_DAEMON_TIMEOUT: Duration = Duration::from_secs(90);

/// Sole profile variation. `RemoteOsc52` adds one literal SSH variable to
/// the PTY child only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HermeticProfile {
    Default,
    RemoteOsc52,
}

/// Inherited-environment *model* used by the exact-env test. Values are
/// never copied into any launch spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InheritedEnvironmentModel {
    vars: BTreeMap<String, String>,
}

impl InheritedEnvironmentModel {
    pub fn empty() -> Self {
        Self {
            vars: BTreeMap::new(),
        }
    }

    /// Poison sentinels for every excluded SSH/TMUX/WSL/display/proxy/
    /// `COCKPIT_*` variable, plus PATH/loader keys that must not leak.
    pub fn poison_sentinels() -> Self {
        let mut vars = BTreeMap::new();
        for key in EXCLUDED_POISON_KEYS {
            vars.insert((*key).to_string(), format!("POISON_{key}"));
        }
        Self { vars }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.vars.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.vars.keys().map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// Variables that must never appear on a fixture-owned launch path unless
/// the RemoteOsc52 PTY child supplies its one literal `SSH_CONNECTION`.
pub const EXCLUDED_POISON_KEYS: &[&str] = &[
    "SSH_CONNECTION",
    "SSH_TTY",
    "SSH_CLIENT",
    "TMUX",
    "TMUX_PANE",
    "WSL_DISTRO_NAME",
    "WSL_INTEROP",
    "WSLENV",
    "WSL_DISTRO",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_CURRENT_DESKTOP",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "FTP_PROXY",
    "ftp_proxy",
    "COCKPIT_CONFIG",
    "COCKPIT_LOG",
    "COCKPIT_DEV_FORCE_CTX_PCT",
    "COCKPIT_ROOSTER",
    "COCKPIT_REMOTE",
    "COCKPIT_EPHEMERAL_SOCKET",
    "COCKPIT_EPHEMERAL_PID_FILE",
    "PATH",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "DYLD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HermeticLaunchKind {
    TrustSet,
    DaemonStart,
    DaemonStatus,
    DaemonStop,
    PtyChild,
}

/// One enumerable launch path constructed solely from [`HermeticLaunchSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HermeticLaunchPath {
    pub kind: HermeticLaunchKind,
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
}

impl HermeticLaunchPath {
    pub fn env_map(&self) -> BTreeMap<&str, &str> {
        self.env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    pub fn env_value(&self, key: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Build a `std::process::Command` from this path only.
    pub fn std_command(&self) -> Command {
        let mut cmd = Command::new(&self.executable);
        cmd.env_clear();
        cmd.current_dir(&self.cwd);
        cmd.args(&self.args);
        for (key, value) in &self.env {
            cmd.env(key, value);
        }
        cmd
    }

    /// Build a PTY `CommandBuilder` from this path only.
    pub fn pty_command(&self) -> CommandBuilder {
        let mut cmd = CommandBuilder::new(self.executable.as_os_str());
        cmd.env_clear();
        cmd.cwd(&self.cwd);
        for arg in &self.args {
            cmd.arg(arg);
        }
        for (key, value) in &self.env {
            cmd.env(key, value);
        }
        // Pin SHELL after env_clear so portable-pty cannot copy $SHELL or
        // the passwd database into the child.
        cmd.env("SHELL", HERMETIC_PTY_SHELL);
        cmd
    }

    pub fn pty_env_pairs(&self) -> Vec<(String, String)> {
        let builder = self.pty_command();
        builder
            .iter_full_env_as_str()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
}

/// Enumerable launch specification. Inspect this — do not read a live
/// process environment — to assert hermetic command construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HermeticLaunchSpec {
    executable: PathBuf,
    home: PathBuf,
    xdg_config_home: PathBuf,
    xdg_data_home: PathBuf,
    xdg_state_home: PathBuf,
    xdg_runtime_dir: PathBuf,
    xdg_cache_home: PathBuf,
    project: PathBuf,
    profile: HermeticProfile,
    extra_env: Vec<(String, String)>,
}

impl HermeticLaunchSpec {
    fn from_home(home: &IsolatedHome, executable: PathBuf, profile: HermeticProfile) -> Self {
        Self {
            executable,
            home: home.home_dir().to_path_buf(),
            xdg_config_home: home.xdg_config_home().to_path_buf(),
            xdg_data_home: home.xdg_data_home().to_path_buf(),
            xdg_state_home: home.xdg_state_home().to_path_buf(),
            xdg_runtime_dir: home.xdg_runtime_dir().to_path_buf(),
            xdg_cache_home: home.xdg_cache_home().to_path_buf(),
            project: home.project_path().to_path_buf(),
            profile,
            extra_env: Vec::new(),
        }
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn project(&self) -> &Path {
        &self.project
    }

    pub fn profile(&self) -> HermeticProfile {
        self.profile
    }

    pub fn set_extra_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        self.extra_env.retain(|(existing, _)| existing != &key);
        self.extra_env.push((key, value.into()));
    }

    pub fn config_dir(&self) -> PathBuf {
        self.home.join(".config").join("cockpit")
    }

    pub fn subprocess_env(&self) -> Vec<(String, String)> {
        let mut env = vec![
            ("HOME".into(), self.home.display().to_string()),
            (
                "XDG_CONFIG_HOME".into(),
                self.xdg_config_home.display().to_string(),
            ),
            (
                "XDG_DATA_HOME".into(),
                self.xdg_data_home.display().to_string(),
            ),
            (
                "XDG_STATE_HOME".into(),
                self.xdg_state_home.display().to_string(),
            ),
            (
                "XDG_RUNTIME_DIR".into(),
                self.xdg_runtime_dir.display().to_string(),
            ),
            (
                "XDG_CACHE_HOME".into(),
                self.xdg_cache_home.display().to_string(),
            ),
            ("TERM".into(), HERMETIC_TERM.into()),
            ("LANG".into(), HERMETIC_LOCALE.into()),
            ("LC_ALL".into(), HERMETIC_LOCALE.into()),
            // Do not inherit the developer PATH (it is a poison key). A
            // fixed system search path lets doctor find host git/rg without
            // leaking the caller's environment.
            ("PATH".into(), HERMETIC_PATH.into()),
        ];
        env.extend(self.extra_env.iter().cloned());
        env
    }

    pub fn pty_env(&self) -> Vec<(String, String)> {
        let mut env = self.subprocess_env();
        if self.profile == HermeticProfile::RemoteOsc52 {
            env.push(("SSH_CONNECTION".into(), REMOTE_OSC52_SSH_CONNECTION.into()));
        }
        env
    }

    pub fn launch_path(&self, kind: HermeticLaunchKind) -> HermeticLaunchPath {
        let project = self.project.display().to_string();
        let (args, env) = match kind {
            HermeticLaunchKind::TrustSet => (
                vec![
                    "trust".into(),
                    "set".into(),
                    project,
                    "--mode".into(),
                    "trust".into(),
                ],
                self.subprocess_env(),
            ),
            HermeticLaunchKind::DaemonStart => {
                let mut env = self.subprocess_env();
                env.push(("COCKPIT_LOG".into(), "warn,cockpit::startup=info".into()));
                (
                    vec!["daemon".into(), "start".into(), "--detach".into()],
                    env,
                )
            }
            HermeticLaunchKind::DaemonStatus => (
                vec!["daemon".into(), "status".into()],
                self.subprocess_env(),
            ),
            HermeticLaunchKind::DaemonStop => (
                vec!["daemon".into(), "stop".into(), "--grace".into(), "0".into()],
                self.subprocess_env(),
            ),
            HermeticLaunchKind::PtyChild => (vec!["--project".into(), project], self.pty_env()),
        };
        HermeticLaunchPath {
            kind,
            executable: self.executable.clone(),
            args,
            cwd: self.project.clone(),
            env,
        }
    }

    pub fn all_launch_paths(&self) -> Vec<HermeticLaunchPath> {
        [
            HermeticLaunchKind::TrustSet,
            HermeticLaunchKind::DaemonStart,
            HermeticLaunchKind::DaemonStatus,
            HermeticLaunchKind::DaemonStop,
            HermeticLaunchKind::PtyChild,
        ]
        .into_iter()
        .map(|kind| self.launch_path(kind))
        .collect()
    }
}

struct PtyHandles {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    master: Box<dyn portable_pty::MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    observer: Arc<Mutex<PtyObserver>>,
    reader_eof: Arc<AtomicBool>,
    output_bytes: Arc<std::sync::atomic::AtomicU64>,
    reader: Option<std::thread::JoinHandle<()>>,
    pid: u32,
    cols: u16,
    rows: u16,
}

struct PtyObserver {
    parser: vt100::Parser,
    osc52: Osc52Observer,
}

impl PtyObserver {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            parser: vt100::Parser::new(rows, cols, 0),
            osc52: Osc52Observer::new(),
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        self.osc52.feed(bytes);
        self.parser.process(bytes);
    }

    fn finish(&mut self) {
        self.osc52.finish();
    }
}

/// Isolated HOME/XDG/project plus the hermetic launch spec and optional
/// owned PTY/daemon processes.
pub struct HermeticCockpit {
    home: IsolatedHome,
    spec: HermeticLaunchSpec,
    inherited: InheritedEnvironmentModel,
    daemon_pid: Option<u32>,
    reaped_pty_pid: Option<u32>,
    reaped_daemon_pid: Option<u32>,
    pty: Option<PtyHandles>,
    #[cfg(target_os = "linux")]
    _secret_service: Option<super::MockSecretService>,
}

impl HermeticCockpit {
    pub fn prepare(profile: HermeticProfile) -> Self {
        Self::prepare_with_inherited(profile, InheritedEnvironmentModel::poison_sentinels())
    }

    pub fn prepare_with_inherited(
        profile: HermeticProfile,
        inherited: InheritedEnvironmentModel,
    ) -> Self {
        let home = IsolatedHome::new();
        home.write_local_provider_config(DUMMY_PROVIDER_URL);
        let executable = absolute_cargo_bin();
        let spec = HermeticLaunchSpec::from_home(&home, executable, profile);
        Self {
            home,
            spec,
            inherited,
            daemon_pid: None,
            reaped_pty_pid: None,
            reaped_daemon_pid: None,
            pty: None,
            #[cfg(target_os = "linux")]
            _secret_service: None,
        }
    }

    /// Trust the isolated project, start the detached daemon, spawn the
    /// 100×30 PTY child, and wait until the ready composer is visible.
    pub fn launch_ready(profile: HermeticProfile) -> Self {
        let mut session = Self::prepare(profile);
        session.start_trusted_daemon();
        session
            .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
            .expect("spawn hermetic PTY child");
        session
            .wait_until_ready(DEFAULT_READY_TIMEOUT)
            .expect("ready TUI composer");
        session
    }

    pub fn spec(&self) -> &HermeticLaunchSpec {
        &self.spec
    }

    pub fn inherited_environment(&self) -> &InheritedEnvironmentModel {
        &self.inherited
    }

    pub fn home(&self) -> &IsolatedHome {
        &self.home
    }

    pub fn set_extra_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.spec.set_extra_env(key, value);
    }

    /// Start a private-bus Secret Service so the isolated daemon can attach.
    #[cfg(target_os = "linux")]
    pub fn enable_isolated_secret_service(&mut self) {
        let service = super::start_mock_secret_service();
        self.spec
            .extra_env
            .push(("DBUS_SESSION_BUS_ADDRESS".into(), service.address.clone()));
        self._secret_service = Some(service);
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enable_isolated_secret_service(&mut self) {}

    pub fn project_path(&self) -> &Path {
        self.home.project_path()
    }

    pub fn socket_path(&self) -> PathBuf {
        self.home.socket_path()
    }

    pub fn daemon_pid(&self) -> Option<u32> {
        self.daemon_pid
            .or(self.reaped_daemon_pid)
            .or_else(|| self.pid_from_file())
    }

    pub fn pty_pid(&self) -> Option<u32> {
        self.pty.as_ref().map(|pty| pty.pid).or(self.reaped_pty_pid)
    }

    pub fn start_trusted_daemon(&mut self) {
        let trust = self
            .spec
            .launch_path(HermeticLaunchKind::TrustSet)
            .std_command()
            .output()
            .expect("hermetic cockpit trust set");
        assert_success("hermetic cockpit trust set", &trust, &self.home);

        let start = self
            .spec
            .launch_path(HermeticLaunchKind::DaemonStart)
            .std_command()
            .output()
            .expect("hermetic cockpit daemon start --detach");
        assert_success("hermetic cockpit daemon start --detach", &start, &self.home);
        self.wait_for_daemon(DEFAULT_DAEMON_TIMEOUT);
        self.daemon_pid = Some(
            self.pid_from_file()
                .expect("daemon pid file after hermetic daemon start"),
        );
    }

    fn wait_for_daemon(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut delay = Duration::from_millis(20);
        loop {
            if super::socket_answers_hello(&self.home.socket_path()) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for hermetic daemon status handshake\nlog tail:\n{}",
                log_tail(&self.home)
            );
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_millis(200));
        }
        let status = self
            .spec
            .launch_path(HermeticLaunchKind::DaemonStatus)
            .std_command()
            .output()
            .expect("hermetic daemon status after hello");
        assert!(
            status.status.success() && output_text(&status).contains("daemon: running"),
            "hermetic daemon status after hello was not running\n{}\nlog tail:\n{}",
            output_text(&status),
            log_tail(&self.home)
        );
    }

    fn pid_from_file(&self) -> Option<u32> {
        cockpit_host::daemon_lifecycle::read_pid_file(&self.home.pid_file())
    }

    pub fn spawn_pty(&mut self, cols: u16, rows: u16) -> std::io::Result<()> {
        assert_pty_geometry(cols, rows);
        let path = self.spec.launch_path(HermeticLaunchKind::PtyChild);
        let cmd = path.pty_command();
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(std::io::Error::other)?;
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(std::io::Error::other)?;
        drop(pair.slave);
        let master = pair.master;
        let finish = |mut child: Box<dyn portable_pty::Child + Send + Sync>,
                      err: std::io::Error|
         -> std::io::Error {
            let _ = child.kill();
            let _ = child.wait();
            err
        };
        let writer = match master.take_writer() {
            Ok(writer) => writer,
            Err(err) => return Err(finish(child, std::io::Error::other(err))),
        };
        let mut reader = match master.try_clone_reader() {
            Ok(reader) => reader,
            Err(err) => return Err(finish(child, std::io::Error::other(err))),
        };
        let observer = Arc::new(Mutex::new(PtyObserver::new(rows, cols)));
        let reader_eof = Arc::new(AtomicBool::new(false));
        let output_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reader_observer = Arc::clone(&observer);
        let reader_eof_flag = Arc::clone(&reader_eof);
        let output_bytes_flag = Arc::clone(&output_bytes);
        let handle = match std::thread::Builder::new()
            .name("cockpit-e2e-pty-reader".into())
            .spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            output_bytes_flag.fetch_add(n as u64, Ordering::SeqCst);
                            if let Ok(mut observer) = reader_observer.lock() {
                                observer.feed(&buf[..n]);
                            }
                        }
                        Err(_) => break,
                    }
                }
                if let Ok(mut observer) = reader_observer.lock() {
                    observer.finish();
                }
                reader_eof_flag.store(true, Ordering::SeqCst);
            }) {
            Ok(handle) => handle,
            Err(err) => return Err(finish(child, err)),
        };
        let pid = match child.process_id() {
            Some(pid) => pid,
            None => return Err(finish(child, std::io::Error::other("PTY child has no pid"))),
        };
        self.pty = Some(PtyHandles {
            child,
            master,
            writer,
            observer,
            reader_eof,
            output_bytes,
            reader: Some(handle),
            pid,
            cols,
            rows,
        });
        Ok(())
    }

    pub fn wait_until_ready(&mut self, timeout: Duration) -> Result<(), ReadyTimeout> {
        // Production TUI always opens the workspace-trust modal on launch
        // (`StartupWorkspaceTrust::Pending`) even after `cockpit trust set`.
        // Confirm the pre-seeded trust decision so readiness observes the
        // composer rather than the modal.
        let mut confirmed_trust = false;
        let deadline = Instant::now() + timeout;
        let mut delay = Duration::from_millis(2);
        loop {
            let snapshot = self.snapshot();
            let ready = snapshot.contains(COMPOSER_PLACEHOLDER)
                && UNWANTED_STARTUP_MARKERS
                    .iter()
                    .all(|marker| !snapshot.contains(marker));
            if ready {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ReadyTimeout {
                    label: "ready composer marker".into(),
                    screen: snapshot.contents(),
                    log: log_tail(&self.home),
                });
            }
            if !confirmed_trust && snapshot.contains("Choose workspace trust:") {
                self.write_bytes(b"\r");
                confirmed_trust = true;
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_millis(50));
        }
    }

    pub fn wait_until_screen(
        &mut self,
        label: &str,
        timeout: Duration,
        mut pred: impl FnMut(&ScreenSnapshot) -> bool,
    ) -> Result<(), ReadyTimeout> {
        let deadline = Instant::now() + timeout;
        let mut delay = Duration::from_millis(2);
        loop {
            let snapshot = self.snapshot();
            if pred(&snapshot) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ReadyTimeout {
                    label: label.to_string(),
                    screen: snapshot.contents(),
                    log: log_tail(&self.home),
                });
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_millis(50));
        }
    }

    pub fn snapshot(&self) -> ScreenSnapshot {
        let Some(pty) = &self.pty else {
            return ScreenSnapshot::empty();
        };
        let observer = pty.observer.lock().expect("pty observer lock");
        ScreenSnapshot::from_screen(observer.parser.screen())
    }

    pub fn osc52(&self) -> Osc52Observer {
        let Some(pty) = &self.pty else {
            return Osc52Observer::new();
        };
        pty.observer
            .lock()
            .expect("pty observer lock")
            .osc52
            .clone()
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        let Some(pty) = self.pty.as_mut() else {
            panic!("PTY child is not running");
        };
        pty.writer.write_all(bytes).expect("write PTY input");
        pty.writer.flush().expect("flush PTY input");
    }

    pub fn write_str(&mut self, text: &str) {
        self.write_bytes(text.as_bytes());
    }

    pub fn send_enter(&mut self) {
        self.write_bytes(b"\r");
    }

    pub fn type_line(&mut self, text: &str) {
        self.write_str(text);
        self.send_enter();
    }

    pub fn open_settings(&mut self) {
        if self.snapshot().contains("[Close settings]")
            || self.snapshot().contains("pick a config to edit")
        {
            self.write_bytes(b"\x1b");
            let _ = self.wait_until_screen(
                "settings closed before reopen",
                Duration::from_secs(5),
                |screen| {
                    !screen.contains("[Close settings]")
                        && !screen.contains("pick a config to edit")
                },
            );
        }
        self.write_str("/settings");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut submitted_command = false;
        let mut selected_layer = false;
        let mut delay = Duration::from_millis(2);
        loop {
            let snapshot = self.snapshot();
            if snapshot.contains("[Close settings]") {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "settings overlay: {}",
                    ReadyTimeout {
                        label: "settings overlay".into(),
                        screen: snapshot.contents(),
                        log: log_tail(&self.home),
                    }
                );
            }
            if snapshot.contains("pick a config to edit") {
                if !selected_layer {
                    self.write_bytes(b"\r");
                    selected_layer = true;
                }
            } else if snapshot.contains("/settings") && !submitted_command {
                self.write_bytes(b"\r");
                submitted_command = true;
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_millis(50));
        }
    }

    /// Resize the PTY. The observer size is updated because a real terminal
    /// emulator changes its parse geometry on SIGWINCH; tests must still
    /// assert a child-produced reflow, not just this local size.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        assert_pty_geometry(cols, rows);
        let Some(pty) = self.pty.as_mut() else {
            panic!("PTY child is not running");
        };
        pty.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("resize PTY");
        if let Ok(mut observer) = pty.observer.lock() {
            observer.parser.screen_mut().set_size(rows, cols);
        }
        pty.cols = cols;
        pty.rows = rows;
    }

    pub fn output_bytes(&self) -> u64 {
        self.pty
            .as_ref()
            .map(|pty| pty.output_bytes.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    /// Wait until the child emits more terminal bytes than `prev`.
    pub fn wait_for_output_progress(&mut self, prev: u64, label: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut delay = Duration::from_millis(2);
        loop {
            if self.output_bytes() > prev {
                return;
            }
            if Instant::now() >= deadline {
                panic!(
                    "timed out waiting for {label} (output_bytes={} prev={prev})",
                    self.output_bytes()
                );
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_millis(50));
        }
    }

    /// After injecting bytes, force a same-size SIGWINCH so the child must
    /// redraw. Input bytes are written to the PTY before the resize, so the
    /// kernel buffer contains them first. The redraw is the observable
    /// render boundary used by no-op comparisons.
    pub fn checkpoint_input_with_redraw(&mut self) {
        let prev = self.output_bytes();
        let (cols, rows) = self.pty_size().expect("PTY size");
        self.resize(cols, rows);
        self.wait_for_output_progress(
            prev,
            "same-size resize redraw after injected input",
            Duration::from_secs(2),
        );
    }

    /// Attach and policy broadcasts can still land after the ready composer
    /// or settings chrome first appear. No-op input comparisons need the
    /// visible grid to stay unchanged across redraws for a quiet interval,
    /// not merely two adjacent frames.
    pub fn settle_visible_state(&mut self, timeout: Duration) {
        const QUIET: Duration = Duration::from_millis(400);
        let deadline = Instant::now() + timeout;
        let mut prev = self.snapshot().visible_state();
        let mut stable_since = Instant::now();
        loop {
            self.checkpoint_input_with_redraw();
            let now = self.snapshot().visible_state();
            if now == prev {
                if Instant::now().saturating_duration_since(stable_since) >= QUIET {
                    return;
                }
            } else {
                prev = now;
                stable_since = Instant::now();
            }
            if Instant::now() >= deadline {
                panic!("timed out waiting for visible state to settle");
            }
        }
    }

    pub fn pty_size(&self) -> Option<(u16, u16)> {
        self.pty.as_ref().map(|pty| (pty.cols, pty.rows))
    }

    pub fn child_exited(&mut self) -> bool {
        let Some(pty) = self.pty.as_mut() else {
            return true;
        };
        matches!(pty.child.try_wait(), Ok(Some(_)))
    }

    pub fn wait_for_child_exit(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut delay = Duration::from_millis(2);
        loop {
            if self.child_exited() {
                return true;
            }
            if Instant::now() >= deadline {
                return self.child_exited();
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_millis(50));
        }
    }

    /// Stop the PTY child and owned daemon. Safe to call more than once.
    pub fn reap(&mut self) {
        let pty_pid = self.pty.as_ref().map(|pty| pty.pid);
        if pty_pid.is_some() {
            self.reaped_pty_pid = pty_pid;
        }
        if let Some(pty) = self.pty.as_mut() {
            // Own the child handle only. Never SIGKILL a raw numeric PID.
            let _ = pty.child.kill();
            let _ = pty.child.wait();
            if let Some(handle) = pty.reader.take() {
                let _ = handle.join();
            }
            if let Ok(mut observer) = pty.observer.lock() {
                observer.finish();
            }
        }
        self.pty = None;

        let daemon_pid = self.daemon_pid.take();
        if daemon_pid.is_some() {
            self.reaped_daemon_pid = daemon_pid;
        }
        if daemon_pid.is_some() {
            let stop: Result<Output, _> = self
                .spec
                .launch_path(HermeticLaunchKind::DaemonStop)
                .std_command()
                .output();
            let _ = stop;
        }
        if let Some(pid) = daemon_pid {
            assert!(
                super::wait_for_pid_exit_blocking(pid, Duration::from_secs(2)),
                "daemon pid {pid} still live after `cockpit daemon stop`; not sending SIGKILL to a numeric PID"
            );
        }

        let socket = self.socket_path();
        if socket.exists() {
            if daemon_pid.is_none() && self.reaped_daemon_pid.is_none() {
                panic!(
                    "refusing to unlink {} without a recorded daemon pid",
                    socket.display()
                );
            }
            let _ = std::fs::remove_file(&socket);
        }
    }

    pub fn assert_reaped(&self) {
        if let Some(pid) = self.pty_pid() {
            assert!(
                !pid_is_live(pid),
                "PTY child pid {pid} still live after reap"
            );
        }
        if let Some(pid) = self.daemon_pid() {
            assert!(!pid_is_live(pid), "daemon pid {pid} still live after reap");
        }
        assert!(
            !self.socket_path().exists(),
            "isolated daemon socket still exists: {}",
            self.socket_path().display()
        );
    }
}

impl Drop for HermeticCockpit {
    fn drop(&mut self) {
        self.reap();
    }
}

#[derive(Debug)]
pub struct ReadyTimeout {
    pub label: String,
    pub screen: String,
    pub log: String,
}

impl std::fmt::Display for ReadyTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "timed out waiting for {}\nscreen:\n{}\nlog tail:\n{}",
            self.label, self.screen, self.log
        )
    }
}

fn assert_pty_geometry(cols: u16, rows: u16) {
    assert!(
        cols > 0 && rows > 0 && cols <= MAX_PTY_COLS && rows <= MAX_PTY_ROWS,
        "PTY geometry {cols}x{rows} exceeds the fixture bound {MAX_PTY_COLS}x{MAX_PTY_ROWS}"
    );
}

fn absolute_cargo_bin() -> PathBuf {
    static BINARY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BINARY
        .get_or_init(|| {
            let bin = assert_cmd::cargo::cargo_bin("cockpit");
            if bin.is_absolute() {
                bin
            } else {
                std::env::current_dir().expect("current dir").join(bin)
            }
        })
        .clone()
}

/// Shared readiness helper used by scenario modules.
pub fn wait_for_screen(
    session: &mut HermeticCockpit,
    label: &str,
    pred: impl FnMut(&ScreenSnapshot) -> bool,
) {
    session
        .wait_until_screen(label, Duration::from_secs(10), pred)
        .unwrap_or_else(|err| panic!("{err}"));
}

pub fn find_close_settings(session: &HermeticCockpit) -> CellPos {
    session
        .snapshot()
        .find_text("[Close settings]")
        .expect("[Close settings] visible")
}
