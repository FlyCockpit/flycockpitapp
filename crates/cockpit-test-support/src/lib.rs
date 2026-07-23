use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tokio::sync::{Mutex, MutexGuard};

pub mod provider;

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
        let tempdir = tempfile::tempdir().expect("create isolated cockpit home tempdir");
        let root = tempdir.path().to_path_buf();
        let mut guard = Self::blocking_lock();
        guard.set_isolated_home(&root);
        guard._tempdir = Some(tempdir);
        guard
    }

    pub async fn isolated_cockpit_home_async() -> Self {
        let tempdir = tempfile::tempdir().expect("create isolated cockpit home tempdir");
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
        let config = root.join("config");
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

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
        let first_entered = Arc::new(AtomicBool::new(false));
        let first_can_finish = Arc::new(AtomicBool::new(false));
        let second_entered_while_first_held = Arc::new(AtomicBool::new(false));

        let first_entered_for_task = Arc::clone(&first_entered);
        let first_can_finish_for_task = Arc::clone(&first_can_finish);
        let first = tokio::spawn(async move {
            let _guard = TestEnvGuard::lock().await;
            first_entered_for_task.store(true, Ordering::SeqCst);
            while !first_can_finish_for_task.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        });

        while !first_entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }

        let second_entered_while_first_held_for_task = Arc::clone(&second_entered_while_first_held);
        let second = tokio::spawn(async move {
            let _guard = TestEnvGuard::lock().await;
            second_entered_while_first_held_for_task.store(true, Ordering::SeqCst);
        });

        tokio::task::yield_now().await;
        assert!(!second_entered_while_first_held.load(Ordering::SeqCst));
        first_can_finish.store(true, Ordering::SeqCst);
        first.await.unwrap();
        second.await.unwrap();
        assert!(second_entered_while_first_held.load(Ordering::SeqCst));
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
                file: "crates/cockpit-tui/src/tui/settings/providers/mod.rs",
                symbol: "apply_copilot_setup",
                reason: "interactive Copilot setup injects the fetched token into the current TUI process",
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
        for (idx, line) in source.lines().enumerate() {
            if let Some(next_symbol) = parse_rust_fn_symbol(line) {
                symbol = next_symbol.to_string();
            }
            if !line_contains_env_mutation(line) {
                continue;
            }
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
            "set_current_dir",
        ]
        .iter()
        .any(|needle| line.contains(needle))
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
