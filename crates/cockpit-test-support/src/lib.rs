use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tokio::sync::{Mutex, MutexGuard};

pub mod home_isolation;
pub mod provider;

/// Read a checked-in test fixture with a path-rich failure message.
pub fn read_fixture(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("read test fixture {}: {error}", path.display());
    })
}

/// Builder for a fixture's same-directory staging file. tempfile stages
/// private (0600) files by default; a fixture must keep the mode a plain write
/// would give it (0666 masked by the umask). Windows has no mode bits to set,
/// so the platform split lives here rather than as a cfg-gated mutation.
#[cfg(unix)]
fn fixture_staging_builder() -> tempfile::Builder<'static, 'static> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut builder = tempfile::Builder::new();
    builder.permissions(std::fs::Permissions::from_mode(0o666));
    builder
}

#[cfg(not(unix))]
fn fixture_staging_builder() -> tempfile::Builder<'static, 'static> {
    tempfile::Builder::new()
}

/// Replace a generated test fixture, creating its parent directory first.
///
/// The replacement is atomic: the contents go to a temporary file in the
/// same directory, which is then renamed over `path`. A concurrent reader
/// (another test comparing or scanning fixtures during a regeneration run)
/// sees either the old or the new file, never a truncated one.
pub fn write_fixture(path: &Path, contents: &str) {
    use std::io::Write as _;

    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(parent).unwrap_or_else(|error| {
        panic!(
            "create test fixture directory {}: {error}",
            parent.display()
        );
    });
    let mut staged = fixture_staging_builder()
        .tempfile_in(parent)
        .unwrap_or_else(|error| {
            panic!("stage test fixture {}: {error}", path.display());
        });
    staged
        .write_all(contents.as_bytes())
        .unwrap_or_else(|error| {
            panic!("write test fixture {}: {error}", path.display());
        });
    staged.persist(path).unwrap_or_else(|error| {
        panic!("replace test fixture {}: {}", path.display(), error.error);
    });
}

/// Create a small test root on a latency-isolated temporary filesystem when
/// the platform exposes one, with a normal OS temporary directory as the
/// portable fallback.
///
/// Linux's conventional `/dev/shm` mount keeps fsync-heavy durability fixtures
/// independent of shared workspace-disk latency. Creating the directory is
/// the capability check: containers without that mount (or without access to
/// it), and every other platform, safely fall back to `tempfile::tempdir`.
/// Callers must still exercise their real durable write/flush path; this helper
/// changes only the test root and never mutates `TMPDIR` or a user directory.
pub fn latency_isolated_tempdir() -> tempfile::TempDir {
    #[cfg(target_os = "linux")]
    if let Ok(tempdir) = tempfile::Builder::new()
        .prefix("cockpit-latency-isolated-")
        .tempdir_in("/dev/shm")
    {
        return tempdir;
    }

    tempfile::Builder::new()
        .prefix("cockpit-latency-isolated-")
        .tempdir()
        .expect("create latency-isolated test tempdir fallback")
}

/// Launch spelling `(command, args)` for a `#!/usr/bin/env python3` test
/// fixture script such as a fake stdio MCP server.
///
/// Unix executes the (chmod +x) script directly through its shebang. Windows
/// has no shebang execution, so the script is handed to an absolute Python
/// interpreter found on `PATH`; the `WindowsApps` App Execution Alias stubs
/// (which open the Store instead of running Python) are skipped. Panics with
/// a clear message when no interpreter is available.
pub fn python_script_launch(script: &Path) -> (String, Vec<String>) {
    #[cfg(windows)]
    {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let interpreter = std::env::split_paths(&path)
            .filter(|dir| {
                !dir.components()
                    .any(|part| part.as_os_str().eq_ignore_ascii_case("WindowsApps"))
            })
            .flat_map(|dir| [dir.join("python.exe"), dir.join("python3.exe")])
            .find(|candidate| candidate.is_file())
            .unwrap_or_else(|| panic!("python fixture requires python.exe on PATH"));
        (
            interpreter.to_string_lossy().into_owned(),
            vec![script.to_string_lossy().into_owned()],
        )
    }
    #[cfg(not(windows))]
    {
        (script.to_string_lossy().into_owned(), Vec::new())
    }
}

#[cfg(test)]
mod clippy_workflow_gate;

const COCKPIT_CONFIG_ENV: &str = "COCKPIT_CONFIG";
const COCKPIT_TRUST_ROOT_ENV: &str = "COCKPIT_TRUST_ROOT";
const COCKPIT_TRUST_MODE_ENV: &str = "COCKPIT_TRUST_MODE";

const MANAGED_ENV_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
    COCKPIT_CONFIG_ENV,
    COCKPIT_TRUST_ROOT_ENV,
    COCKPIT_TRUST_MODE_ENV,
];

static TEST_ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

fn test_env_mutex() -> &'static Mutex<()> {
    TEST_ENV_MUTEX.get_or_init(|| Mutex::new(()))
}

/// Create an isolated Cockpit home without coupling daemon/storage acceptance
/// tests to unrelated compiler and linker traffic on the workspace disk.
/// The HOME/XDG production inputs still provide every path consumed by the
/// code under test; only the backing filesystem differs on Linux.
pub fn isolated_tempdir() -> tempfile::TempDir {
    #[cfg(target_os = "linux")]
    {
        // Respect the platform-standard override so loaded acceptance runs can
        // exercise the ordinary disk-backed fallback explicitly. Otherwise
        // prefer tmpfs, but do not make its presence a correctness condition.
        if let Some(tmpdir) = std::env::var_os("TMPDIR") {
            return tempfile::tempdir_in(tmpdir).expect("create isolated Cockpit home in TMPDIR");
        }
        tempfile::tempdir_in("/dev/shm")
            .or_else(|_| tempfile::tempdir())
            .expect("create isolated Cockpit home")
    }
    #[cfg(not(target_os = "linux"))]
    {
        tempfile::tempdir().expect("create isolated Cockpit home tempdir")
    }
}

/// A private directory short enough to root Unix-domain sockets.
///
/// `sockaddr_un.sun_path` is 104 bytes on macOS and 108 on Linux, and the
/// daemon keeps a reserve below that, so a runtime root nested inside an
/// ordinary temp home (`/private/tmp/.tmpXXXXXX/runtime`, or a default macOS
/// `$TMPDIR` under `/var/folders/…`) pushes its socket over budget and the
/// daemon correctly falls back to a shared per-user root. Harnesses that pin
/// `XDG_RUNTIME_DIR` use this instead, rooted directly under the canonical
/// system temp directory (`/tmp` resolves to `/private/tmp` on macOS; the
/// canonical spelling keeps symlink-aware path checks exact).
pub fn short_socket_tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        let root = std::fs::canonicalize("/tmp").expect("resolve the system temp directory");
        tempfile::Builder::new()
            .prefix("c")
            .tempdir_in(root)
            .expect("create short socket tempdir")
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().expect("create socket tempdir")
    }
}

/// The system `true` utility, resolved from the system binary directories
/// only (a developer `PATH` must not choose a fixture's pinned executable).
/// macOS ships it only as `/usr/bin/true`; many Linux distributions have
/// both `/usr/bin/true` and `/bin/true`.
#[cfg(unix)]
pub fn system_true_executable() -> PathBuf {
    ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_file())
        .expect("the system `true` utility exists in /usr/bin or /bin")
}

#[must_use]
pub struct TestEnvGuard {
    _guard: MutexGuard<'static, ()>,
    snapshots: RefCell<Vec<EnvSnapshot>>,
    cwd: PathBuf,
    _tempdir: Option<tempfile::TempDir>,
}

pub struct CockpitConfigOverride<'a> {
    guard: &'a TestEnvGuard,
    old_cockpit_config: Option<OsString>,
}

struct EnvSnapshot {
    name: OsString,
    old: Option<OsString>,
}

impl TestEnvGuard {
    pub async fn lock() -> Self {
        Self::from_guard(test_env_mutex().lock().await)
    }

    pub fn blocking_lock() -> Self {
        Self::from_guard(test_env_mutex().blocking_lock())
    }

    pub fn isolated_cockpit_home() -> Self {
        let tempdir = isolated_tempdir();
        let root = tempdir.path().to_path_buf();
        let mut guard = Self::blocking_lock();
        guard.set_isolated_home(&root);
        guard._tempdir = Some(tempdir);
        guard
    }

    pub async fn isolated_cockpit_home_async() -> Self {
        let tempdir = isolated_tempdir();
        let root = tempdir.path().to_path_buf();
        let mut guard = Self::lock().await;
        guard.set_isolated_home(&root);
        guard._tempdir = Some(tempdir);
        guard
    }

    pub fn isolate_cockpit_home_at(root: &Path) -> Self {
        let guard = Self::blocking_lock();
        guard.set_isolated_home(root);
        guard
    }

    pub async fn isolate_cockpit_home_at_async(root: &Path) -> Self {
        let guard = Self::lock().await;
        guard.set_isolated_home(root);
        guard
    }

    fn from_guard(guard: MutexGuard<'static, ()>) -> Self {
        home_isolation::ensure_real_developer_roots_captured();
        Self {
            _guard: guard,
            snapshots: RefCell::new(
                MANAGED_ENV_VARS
                    .iter()
                    .map(|name| EnvSnapshot {
                        name: OsString::from(name),
                        old: std::env::var_os(name),
                    })
                    .collect(),
            ),
            cwd: std::env::current_dir().expect("capture current test directory"),
            _tempdir: None,
        }
    }

    pub fn set_var<K, V>(&self, key: K, value: V)
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.snapshot_var_if_needed(key.as_ref());
        // SAFETY: every test env mutation routed through this helper is
        // serialized by the process-global tokio mutex held by this guard.
        unsafe { std::env::set_var(key, value) };
    }

    pub fn remove_var<K>(&self, key: K)
    where
        K: AsRef<OsStr>,
    {
        self.snapshot_var_if_needed(key.as_ref());
        // SAFETY: every test env mutation routed through this helper is
        // serialized by the process-global tokio mutex held by this guard.
        unsafe { std::env::remove_var(key) };
    }

    pub fn set_current_dir<P>(&self, path: P) -> std::io::Result<()>
    where
        P: AsRef<Path>,
    {
        std::env::set_current_dir(path)
    }

    fn snapshot_var_if_needed(&self, key: &OsStr) {
        let mut snapshots = self.snapshots.borrow_mut();
        if snapshots
            .iter()
            .any(|snapshot| snapshot.name.as_os_str() == key)
        {
            return;
        }
        snapshots.push(EnvSnapshot {
            name: key.to_os_string(),
            old: std::env::var_os(key),
        });
    }

    pub fn set_cockpit_config(&self, path: &Path) {
        self.set_var(COCKPIT_CONFIG_ENV, path);
    }

    pub fn override_cockpit_config(&self, path: &Path) -> CockpitConfigOverride<'_> {
        let old_cockpit_config = std::env::var_os(COCKPIT_CONFIG_ENV);
        self.set_cockpit_config(path);
        CockpitConfigOverride {
            guard: self,
            old_cockpit_config,
        }
    }

    pub fn remove_cockpit_config(&self) {
        self.remove_var(COCKPIT_CONFIG_ENV);
    }

    pub fn set_isolated_home(&self, root: &Path) {
        let home = root.join("home");
        let data = root.join("data");
        // Match the platform default when a caller has only isolated HOME:
        // config discovery remains XDG-aware, while fixture paths can model
        // the canonical `~/.config/cockpit` layer without a second root.
        let config = home.join(".config");
        let state = root.join("state");
        let runtime = root.join("runtime");
        for dir in [&home, &data, &config, &state, &runtime] {
            std::fs::create_dir_all(dir).expect("create isolated env directory");
        }
        self.set_var("HOME", &home);
        self.set_var("XDG_DATA_HOME", &data);
        self.set_var("XDG_CONFIG_HOME", &config);
        self.set_var("XDG_STATE_HOME", &state);
        self.set_var("XDG_RUNTIME_DIR", &runtime);
        self.remove_cockpit_config();
        self.remove_var(COCKPIT_TRUST_ROOT_ENV);
        self.remove_var(COCKPIT_TRUST_MODE_ENV);
    }

    pub fn path(&self) -> Option<&Path> {
        self._tempdir.as_ref().map(tempfile::TempDir::path)
    }
}

impl Drop for CockpitConfigOverride<'_> {
    fn drop(&mut self) {
        match &self.old_cockpit_config {
            Some(value) => self.guard.set_var(COCKPIT_CONFIG_ENV, value),
            None => self.guard.remove_cockpit_config(),
        }
    }
}

impl Drop for TestEnvGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.cwd);
        for snapshot in self.snapshots.borrow().iter().rev() {
            match &snapshot.old {
                Some(value) => {
                    // SAFETY: the process-global env guard is still held
                    // while Drop restores the captured values.
                    unsafe { std::env::set_var(&snapshot.name, value) }
                }
                None => {
                    // SAFETY: the process-global env guard is still held
                    // while Drop restores the captured absence.
                    unsafe { std::env::remove_var(&snapshot.name) }
                }
            }
        }
    }
}

pub fn managed_env_vars() -> &'static [&'static str] {
    MANAGED_ENV_VARS
}

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("test support crate lives under workspace crates/")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_fixture_replaces_contents_with_the_default_file_mode() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = dir.path().join("golden.txt");
        write_fixture(&fixture, "old");
        write_fixture(&fixture, "new");
        assert_eq!(read_fixture(&fixture), "new");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, [std::ffi::OsString::from("golden.txt")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let plain = dir.path().join("plain.txt");
            std::fs::write(&plain, "plain").unwrap();
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode(&fixture),
                mode(&plain),
                "fixture mode must match a plain write"
            );
        }
    }

    #[derive(Clone, Copy)]
    struct AllowedMutation {
        file: &'static str,
        symbol: &'static str,
        reason: &'static str,
    }

    #[test]
    fn guard_restores_set_variable() {
        let key = "COCKPIT_TEST_SUPPORT_RESTORE_SET";
        let setup = test_env_mutex().blocking_lock();
        // SAFETY: this support-crate self-test holds the shared test env
        // mutex while seeding the value that TestEnvGuard must restore.
        unsafe { std::env::set_var(key, "before") };
        {
            let guard = TestEnvGuard::from_guard(setup);
            guard.set_var(key, "during");
            assert_eq!(std::env::var(key).unwrap(), "during");
        }
        assert_eq!(std::env::var(key).unwrap(), "before");
        let _cleanup = test_env_mutex().blocking_lock();
        // SAFETY: cleanup is serialized by the shared test env mutex.
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn guard_restores_absent_variable() {
        let key = "COCKPIT_TEST_SUPPORT_RESTORE_ABSENT";
        let setup = test_env_mutex().blocking_lock();
        // SAFETY: this support-crate self-test holds the shared test env
        // mutex while seeding the absence that TestEnvGuard must restore.
        unsafe { std::env::remove_var(key) };
        {
            let guard = TestEnvGuard::from_guard(setup);
            guard.set_var(key, "during");
            assert_eq!(std::env::var(key).unwrap(), "during");
        }
        assert!(std::env::var_os(key).is_none());
    }

    #[tokio::test]
    async fn guard_serializes_concurrent_async_acquisition() {
        let (first_entered_tx, first_entered_rx) = tokio::sync::oneshot::channel();
        let (first_can_finish_tx, first_can_finish_rx) = tokio::sync::oneshot::channel();
        let (second_entered_tx, mut second_entered_rx) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(async move {
            let _guard = TestEnvGuard::lock().await;
            first_entered_tx
                .send(())
                .expect("signal first guard acquisition");
            first_can_finish_rx.await.expect("release first guard");
        });

        first_entered_rx
            .await
            .expect("observe first guard acquisition");

        let second = tokio::spawn(async move {
            let _guard = TestEnvGuard::lock().await;
            second_entered_tx
                .send(())
                .expect("signal second guard acquisition");
        });

        assert!(
            second_entered_rx.try_recv().is_err(),
            "second guard acquired while first was held"
        );
        first_can_finish_tx.send(()).expect("release first guard");
        first.await.unwrap();
        second_entered_rx
            .await
            .expect("observe second guard acquisition");
        second.await.unwrap();
    }

    #[test]
    fn home_isolation_redirects_real_paths_without_test_env_guard() {
        let real_config = dirs::config_dir()
            .expect("real developer config dir")
            .join("cockpit");
        let redirected = home_isolation::finalize_test_cockpit_path(
            real_config,
            home_isolation::CockpitHomeKind::Config,
        );
        home_isolation::assert_not_real_developer_cockpit_path(&redirected);
    }

    #[test]
    fn home_isolation_redirects_real_developer_cockpit_paths() {
        let setup = test_env_mutex().blocking_lock();
        home_isolation::ensure_real_developer_roots_captured();
        let real_config = dirs::config_dir()
            .expect("real developer config dir")
            .join("cockpit");
        let redirected = home_isolation::finalize_test_cockpit_path(
            real_config,
            home_isolation::CockpitHomeKind::Config,
        );
        home_isolation::assert_not_real_developer_cockpit_path(&redirected);
        drop(setup);
    }

    #[test]
    fn home_isolation_allow_real_home_env_keeps_developer_paths() {
        let guard = TestEnvGuard::blocking_lock();
        guard.set_var(home_isolation::COCKPIT_TEST_ALLOW_REAL_HOME_ENV, "1");
        let real_config = dirs::config_dir()
            .expect("real developer config dir")
            .join("cockpit");
        let kept = home_isolation::finalize_test_cockpit_path(
            real_config.clone(),
            home_isolation::CockpitHomeKind::Config,
        );
        assert_eq!(kept, real_config);
    }

    #[test]
    fn home_isolation_guard_allows_isolated_cockpit_paths() {
        let tempdir = tempfile::tempdir().expect("isolated home tempdir");
        let guard = TestEnvGuard::isolate_cockpit_home_at(tempdir.path());
        let isolated_config = tempdir.path().join("home/.config/cockpit");
        home_isolation::assert_not_real_developer_cockpit_path(&isolated_config);
        drop(guard);
    }

    #[test]
    fn source_env_mutations_are_guarded_or_explicitly_allowed() {
        const ALLOWED: &[AllowedMutation] = &[
            AllowedMutation {
                file: "apps/cli/src/commands/daemon.rs",
                symbol: "run",
                reason: "foreground daemon startup intentionally exports the no-sandbox marker before worker tasks start",
            },
            AllowedMutation {
                file: "crates/cockpit-core/src/bin/cockpit-daemon-spawn-harness.rs",
                symbol: "run",
                reason: "foreground daemon spawn harness intentionally exports the no-sandbox marker before the runtime starts worker tasks, mirroring foreground daemon startup",
            },
            AllowedMutation {
                file: "crates/cockpit-core/src/daemon/peer_authority.rs",
                symbol: "record_launch_provenance_from_environment",
                reason: "daemon boot scrubs the launch-ticket environment slot once so descendant processes never inherit owner-class provenance",
            },
            AllowedMutation {
                file: "crates/cockpit-core/src/daemon/supervisor.rs",
                symbol: "prepare_process_entry_environment",
                reason: "process-entry hook (CLI main_entry / spawn harness) runs before any runtime or thread; scrubs worker/reexec role env so helpers never inherit it and publishes the worker's exact LISTEN_PID",
            },
            AllowedMutation {
                file: "crates/cockpit-core/src/providers/provider_http.rs",
                symbol: "set",
                reason: "test-local proxy env guard saves/restores one variable serialized by its own static mutex for the test lifetime",
            },
            AllowedMutation {
                file: "crates/cockpit-core/src/providers/provider_http.rs",
                symbol: "drop",
                reason: "test-local proxy env guard restores the saved variable serialized by its own static mutex for the test lifetime",
            },
            AllowedMutation {
                file: "crates/cockpit-config/src/config/trust.rs",
                symbol: "set_runtime_policy",
                reason: "runtime trust policy must be exported to daemon and builder children spawned later",
            },
            AllowedMutation {
                file: "crates/cockpit-config/src/config/trust.rs",
                symbol: "clear_runtime_policy_for_tests",
                reason: "cross-crate test helper resets the production runtime policy cell and inherited trust env",
            },
            AllowedMutation {
                file: "crates/cockpit-core/src/daemon/registry.rs",
                symbol: "assert_preflight_model",
                reason: "preflight hook swaps COCKPIT_CONFIG under an already-held TestEnvGuard to prove start does not reread the ambient path",
            },
            AllowedMutation {
                file: "crates/cockpit-core/src/daemon/session_worker/handle.rs",
                symbol: "from_disk_for_tests_at_generation",
                reason: "test helper save/restores COCKPIT_CONFIG so the tempdir project layer loads even when another test left an explicit path set",
            },
        ];

        let mut violations = Vec::new();
        let mut seen_allowed = vec![false; ALLOWED.len()];
        for root in ["apps", "crates"] {
            collect_env_mutations(
                &workspace_root().join(root),
                ALLOWED,
                &mut seen_allowed,
                &mut violations,
            );
        }

        for (idx, allowed) in ALLOWED.iter().enumerate() {
            assert!(
                seen_allowed[idx],
                "allow-list entry {}::{} was not observed: {}",
                allowed.file, allowed.symbol, allowed.reason
            );
        }

        assert!(
            violations.is_empty(),
            "direct env/current-dir mutations must use cockpit-test-support::TestEnvGuard or be added to the file::symbol allow-list:\n{}",
            violations.join("\n")
        );
    }

    fn collect_env_mutations(
        root: &Path,
        allowed: &[AllowedMutation],
        seen_allowed: &mut [bool],
        violations: &mut Vec<String>,
    ) {
        let entries = std::fs::read_dir(root).unwrap_or_else(|err| {
            panic!("read source directory {}: {err}", root.display());
        });
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if relative_source_path(&path) == "crates/cockpit-test-support" {
                    continue;
                }
                collect_env_mutations(&path, allowed, seen_allowed, violations);
                continue;
            }
            if path.extension().and_then(OsStr::to_str) != Some("rs") {
                continue;
            }
            scan_source_file(&path, allowed, seen_allowed, violations);
        }
    }

    fn scan_source_file(
        path: &Path,
        allowed: &[AllowedMutation],
        seen_allowed: &mut [bool],
        violations: &mut Vec<String>,
    ) {
        let rel = relative_source_path(path);
        let source = std::fs::read_to_string(path).unwrap_or_else(|err| {
            panic!("read source file {}: {err}", path.display());
        });
        let mut symbol = "<module>".to_string();
        // A `use` statement may span several lines (`use std::{\n env::{..}\n};`),
        // so it is accumulated until its terminating `;` and judged as a whole,
        // attributed to the line that opened it.
        let mut pending_use: Option<(usize, String)> = None;
        for (idx, line) in source.lines().enumerate() {
            if let Some(next_symbol) = parse_rust_fn_symbol(line) {
                symbol = next_symbol.to_string();
            }
            if pending_use.is_none() && starts_use_statement(line) {
                pending_use = Some((idx, String::new()));
            }
            let mut flagged_at = line_contains_env_mutation(line).then_some(idx);
            if let Some((start, statement)) = pending_use.as_mut() {
                statement.push_str(line);
                statement.push('\n');
                if line.contains(';') {
                    if flagged_at.is_none() && use_statement_imports_env_mutator(statement) {
                        flagged_at = Some(*start);
                    }
                    pending_use = None;
                }
            }
            let Some(idx) = flagged_at else {
                continue;
            };
            let line = source.lines().nth(idx).unwrap_or(line);
            if let Some(allowed_idx) = allowed
                .iter()
                .position(|entry| entry.file == rel && entry.symbol == symbol)
            {
                seen_allowed[allowed_idx] = true;
                continue;
            }
            violations.push(format!("{}:{} in {symbol}: {}", rel, idx + 1, line.trim()));
        }
    }

    fn line_contains_env_mutation(line: &str) -> bool {
        [
            "std::env::set_var",
            "std::env::remove_var",
            "env::set_var",
            "env::remove_var",
            "env::set_current_dir",
        ]
        .iter()
        .any(|needle| line.contains(needle))
            || contains_bare_set_current_dir_call(line)
    }

    /// Whether `line` opens a `use` declaration (any visibility).
    fn starts_use_statement(line: &str) -> bool {
        let mut rest = line.trim_start();
        if let Some(stripped) = rest.strip_prefix("pub") {
            let stripped = stripped.trim_start();
            rest = match stripped.strip_prefix('(') {
                Some(scoped) => match scoped.find(')') {
                    Some(close) => scoped[close + 1..].trim_start(),
                    None => return false,
                },
                None => stripped,
            };
        }
        rest.starts_with("use ") || rest.starts_with("use\t")
    }

    /// Whether a complete `use` declaration imports a process-environment
    /// mutator from `std::env` (or the module itself by glob), however it is
    /// spelled: grouped (`use std::env::{self, set_var};`), nested across
    /// lines (`use std::{env::{remove_var}};`) or aliased
    /// (`use std::env::set_current_dir as cd;`). An imported mutator can be
    /// called, or taken as a function pointer, under any name, so the import
    /// itself is the mutation site the allow-list must name.
    fn use_statement_imports_env_mutator(statement: &str) -> bool {
        let Some(start) = statement.find("use") else {
            return false;
        };
        let tree = statement[start + "use".len()..]
            .split(';')
            .next()
            .unwrap_or_default();
        let mut paths = Vec::new();
        expand_use_tree(tree, "", &mut paths);
        paths.iter().any(|path| {
            let path = path.trim_start_matches("::");
            let item = path
                .strip_prefix("std::env::")
                .or_else(|| path.strip_prefix("env::"));
            matches!(
                item,
                Some("set_var" | "remove_var" | "set_current_dir" | "*")
            )
        })
    }

    /// Flatten a use tree into its full paths, without aliases or whitespace.
    fn expand_use_tree(tree: &str, prefix: &str, out: &mut Vec<String>) {
        let tree = tree.trim();
        if tree.is_empty() {
            return;
        }
        let join = |path: &str| -> String {
            let path: String = path.split_whitespace().collect();
            match (prefix.is_empty(), path.is_empty()) {
                (true, _) => path,
                (false, true) => prefix.to_string(),
                (false, false) => format!("{prefix}::{path}"),
            }
        };
        let Some(open) = tree.find('{') else {
            let path = tree.split_whitespace().take_while(|token| *token != "as");
            out.push(join(&path.collect::<Vec<_>>().join("")));
            return;
        };
        let Some(close) = tree.rfind('}') else {
            return;
        };
        let head = join(tree[..open].trim().trim_end_matches("::"));
        let inner = &tree[open + 1..close];
        let mut depth = 0usize;
        let mut item_start = 0;
        for (at, ch) in inner.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    expand_use_tree(&inner[item_start..at], &head, out);
                    item_start = at + 1;
                }
                _ => {}
            }
        }
        expand_use_tree(&inner[item_start..], &head, out);
    }

    /// A `set_current_dir(` call reached through an import
    /// (`use std::env::set_current_dir;`) mutates process state exactly like
    /// the qualified form. Method calls (`guard.set_current_dir(`) go through
    /// a serialized test guard and definitions (`fn set_current_dir(`) are
    /// not calls, so neither is flagged.
    fn contains_bare_set_current_dir_call(line: &str) -> bool {
        const NEEDLE: &str = "set_current_dir(";
        line.match_indices(NEEDLE).any(|(at, _)| {
            let before = line[..at].trim_end();
            !before.ends_with('.') && !before.ends_with("fn")
        })
    }

    #[test]
    fn env_mutation_scan_flags_bare_set_current_dir_but_not_guard_methods() {
        assert!(line_contains_env_mutation(
            "    set_current_dir(&dir).unwrap();"
        ));
        assert!(line_contains_env_mutation(
            "let _ = (set_current_dir(dir), 1);"
        ));
        assert!(line_contains_env_mutation(
            "std::env::set_current_dir(dir)?;"
        ));
        assert!(line_contains_env_mutation("env::set_current_dir(dir)?;"));
        assert!(!line_contains_env_mutation("guard.set_current_dir(&dir);"));
        assert!(!line_contains_env_mutation("        .set_current_dir(dir)"));
        assert!(!line_contains_env_mutation(
            "    pub fn set_current_dir(&self, dir: &Path) {"
        ));
    }

    #[test]
    fn env_mutation_scan_flags_grouped_nested_and_aliased_env_imports() {
        for statement in [
            "use std::env::set_current_dir as cd;",
            "use std::env::{self, set_var};",
            "pub(crate) use std::env::{remove_var as unset, var};",
            "use std::{\n    env::{set_current_dir as chdir},\n    path::Path,\n};",
            "use ::std::env::*;",
            "    use std::{ffi::OsStr, env::{self as e, set_var as put}};",
        ] {
            let first = statement.lines().next().unwrap();
            assert!(starts_use_statement(first), "{statement}");
            assert!(
                use_statement_imports_env_mutator(statement),
                "must flag {statement:?}"
            );
        }
        for statement in [
            "use std::env;",
            "use std::env::{self, var, var_os};",
            "use std::{ffi::OsStr, path::{Path, PathBuf}};",
            "use crate::test_env::set_var;",
            "use cockpit_test_support::TestEnvGuard as set_var;",
        ] {
            assert!(
                !use_statement_imports_env_mutator(statement),
                "must not flag {statement:?}"
            );
        }
        assert!(!starts_use_statement("    // use std::env::{set_var};"));
        assert!(!starts_use_statement("let used = 1;"));
    }

    fn parse_rust_fn_symbol(line: &str) -> Option<&str> {
        let mut rest = line.trim_start();
        if let Some(stripped) = rest.strip_prefix("pub ") {
            rest = stripped.trim_start();
        }
        if let Some(stripped) = rest.strip_prefix("async ") {
            rest = stripped.trim_start();
        }
        let rest = rest.strip_prefix("fn ")?;
        rest.split(['(', '<', ' ', '\t']).next()
    }

    fn relative_source_path(path: &Path) -> String {
        path.strip_prefix(workspace_root())
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }
}
