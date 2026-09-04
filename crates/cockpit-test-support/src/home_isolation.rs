//! Test-build enforcement for Cockpit config/data/state path resolution.
//!
//! [`TestEnvGuard::set_isolated_home`] installs explicit XDG/HOME overrides that
//! point away from the developer profile; those win unchanged.
//!
//! When no such override is active, resolver functions in `cockpit-config`
//! redirect to a lazy per-process isolated home that mirrors
//! [`TestEnvGuard::set_isolated_home`]'s directory layout:
//! `{root}/home/.config/cockpit`, `{root}/data/cockpit`, `{root}/state/cockpit`.
//!
//! Under `cargo nextest`, each test is its own process so the isolated root is
//! per test. Under `cargo test`, one binary shares a single isolated root across
//! threads; root creation uses [`OnceLock`] and is therefore thread-safe.
//!
//! Set [`COCKPIT_TEST_ALLOW_REAL_HOME_ENV`] to `1` to opt into real developer
//! paths (manual smokes only).

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

/// Opt-in env var for manual smokes that must touch the real developer profile.
pub const COCKPIT_TEST_ALLOW_REAL_HOME_ENV: &str = "COCKPIT_TEST_ALLOW_REAL_HOME";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CockpitHomeKind {
    Config,
    Data,
    State,
}

struct RealDeveloperCockpitRoots {
    home: PathBuf,
    xdg_data: PathBuf,
    config: PathBuf,
    data: PathBuf,
    state: PathBuf,
}

struct ProcessIsolatedHome {
    _tempdir: tempfile::TempDir,
    home: PathBuf,
    xdg_data: PathBuf,
    _xdg_config: PathBuf,
    _xdg_state: PathBuf,
    _runtime: PathBuf,
    config: PathBuf,
    data: PathBuf,
    state: PathBuf,
}

static REAL_DEVELOPER_COCKPIT_ROOTS: OnceLock<RealDeveloperCockpitRoots> = OnceLock::new();
static PROCESS_ISOLATED_HOME: OnceLock<ProcessIsolatedHome> = OnceLock::new();

/// Record the developer-owned Cockpit roots once, before any test mutates
/// `HOME` / XDG variables through [`TestEnvGuard`].
pub fn ensure_real_developer_roots_captured() {
    REAL_DEVELOPER_COCKPIT_ROOTS.get_or_init(|| {
        let home = dirs::home_dir().expect("locate real developer home dir");
        let xdg_data = dirs::data_dir().expect("locate real developer data dir");
        let config_base = dirs::config_dir().expect("locate real developer config dir");
        RealDeveloperCockpitRoots {
            home,
            xdg_data: xdg_data.clone(),
            config: config_base.join("cockpit"),
            data: xdg_data.join("cockpit"),
            state: real_developer_state_dir(),
        }
    });
}

fn real_developer_state_dir() -> PathBuf {
    if let Ok(value) = std::env::var("XDG_STATE_HOME")
        && !value.trim().is_empty()
    {
        return PathBuf::from(value).join("cockpit");
    }
    #[cfg(unix)]
    {
        let home = dirs::home_dir().expect("locate real developer home dir");
        home.join(".local/state/cockpit")
    }
    #[cfg(not(unix))]
    {
        let base = dirs::data_local_dir().expect("locate real developer local data dir");
        base.join("cockpit").join("state")
    }
}

fn process_isolated_home() -> &'static ProcessIsolatedHome {
    PROCESS_ISOLATED_HOME.get_or_init(|| {
        let tempdir = tempfile::TempDir::new().expect("create process-isolated cockpit home");
        let root = tempdir.path();
        let home = root.join("home");
        let xdg_data = root.join("data");
        let xdg_config = home.join(".config");
        let xdg_state = root.join("state");
        let runtime = root.join("runtime");
        let config_cockpit = xdg_config.join("cockpit");
        let data_cockpit = xdg_data.join("cockpit");
        let state_cockpit = xdg_state.join("cockpit");
        for dir in [&home, &xdg_data, &xdg_config, &xdg_state, &runtime] {
            std::fs::create_dir_all(dir).expect("create process-isolated env directory");
        }
        ProcessIsolatedHome {
            _tempdir: tempdir,
            home,
            xdg_data,
            _xdg_config: xdg_config,
            _xdg_state: xdg_state,
            _runtime: runtime,
            config: config_cockpit,
            data: data_cockpit,
            state: state_cockpit,
        }
    })
}

fn allows_real_developer_home() -> bool {
    std::env::var(COCKPIT_TEST_ALLOW_REAL_HOME_ENV)
        .ok()
        .is_some_and(|value| value.trim() == "1")
}

fn is_under_real_developer_roots(path: &Path) -> bool {
    let roots = REAL_DEVELOPER_COCKPIT_ROOTS
        .get()
        .expect("real developer cockpit roots captured above");
    path == roots.home
        || contained_under(&roots.home, path)
        || contained_under(&roots.xdg_data, path)
        || contained_under(&roots.config, path)
        || contained_under(&roots.data, path)
        || contained_under(&roots.state, path)
}

fn replace_path_prefix(path: &Path, from: &Path, to: &Path) -> PathBuf {
    let suffix = path.strip_prefix(from).unwrap_or_else(|_| {
        panic!(
            "path {} must be under prefix {}",
            path.display(),
            from.display()
        )
    });
    to.join(suffix)
}

/// Redirect a developer-profile home directory to the per-process isolated
/// mirror when redirect is active.
pub fn finalize_test_profile_home(home: PathBuf) -> PathBuf {
    ensure_real_developer_roots_captured();
    let roots = REAL_DEVELOPER_COCKPIT_ROOTS
        .get()
        .expect("real developer cockpit roots captured above");
    if home != roots.home && !contained_under(&roots.home, &home) {
        return home;
    }
    if allows_real_developer_home() {
        return home;
    }
    if home == roots.home {
        return process_isolated_home().home.clone();
    }
    replace_path_prefix(&home, &roots.home, &process_isolated_home().home)
}

/// Redirect a developer-profile path to the per-process isolated mirror when
/// redirect is active.
pub fn finalize_test_profile_path(path: PathBuf) -> PathBuf {
    ensure_real_developer_roots_captured();
    if !is_under_real_developer_roots(&path) {
        return path;
    }
    if allows_real_developer_home() {
        return path;
    }
    let roots = REAL_DEVELOPER_COCKPIT_ROOTS
        .get()
        .expect("real developer cockpit roots captured above");
    let isolated = process_isolated_home();
    if contained_under(&roots.config, &path) || path == roots.config {
        return replace_path_prefix(&path, &roots.config, &isolated.config);
    }
    if contained_under(&roots.data, &path) || path == roots.data {
        return replace_path_prefix(&path, &roots.data, &isolated.data);
    }
    if contained_under(&roots.state, &path) || path == roots.state {
        return replace_path_prefix(&path, &roots.state, &isolated.state);
    }
    if path == roots.home || contained_under(&roots.home, &path) {
        return replace_path_prefix(&path, &roots.home, &isolated.home);
    }
    if contained_under(&roots.xdg_data, &path) || path == roots.xdg_data {
        return replace_path_prefix(&path, &roots.xdg_data, &isolated.xdg_data);
    }
    path
}

/// Finalize a resolver result in test builds.
///
/// Precedence: (1) paths already outside the real developer roots (explicit
/// XDG/HOME overrides from [`TestEnvGuard`]) are returned unchanged; (2)
/// [`COCKPIT_TEST_ALLOW_REAL_HOME_ENV`]=`1` keeps the real path; (3) otherwise
/// redirect to the per-process isolated home for `kind`.
pub fn finalize_test_cockpit_path(path: PathBuf, kind: CockpitHomeKind) -> PathBuf {
    ensure_real_developer_roots_captured();
    if !is_under_real_developer_roots(&path) {
        return path;
    }
    if allows_real_developer_home() {
        return path;
    }
    let isolated = process_isolated_home();
    let redirected = match kind {
        CockpitHomeKind::Config => isolated.config.clone(),
        CockpitHomeKind::Data => isolated.data.clone(),
        CockpitHomeKind::State => isolated.state.clone(),
    };
    if is_under_real_developer_roots(&redirected) {
        panic!(
            "process-isolated Cockpit home for {kind:?} still resolves under the real developer profile ({})",
            redirected.display()
        );
    }
    redirected
}

/// Panic when `path` resolves under the captured real developer Cockpit
/// config/data/state roots without an explicit opt-in. Production code never
/// calls this; it covers the unreachable case where redirect did not run.
pub fn assert_not_real_developer_cockpit_path(path: &Path) {
    ensure_real_developer_roots_captured();
    if is_under_real_developer_roots(path) && !allows_real_developer_home() {
        panic!(
            "test resolved a Cockpit home path under the real developer profile \
             ({}); call TestEnvGuard::isolated_cockpit_home[_async] or \
             isolate_cockpit_home_at[_async] and keep the returned guard alive \
             for the whole test before reading or writing config/data/state paths, \
             or set {COCKPIT_TEST_ALLOW_REAL_HOME_ENV}=1 for manual real-dir smokes",
            path.display()
        );
    }
}

fn contained_under(base: &Path, path: &Path) -> bool {
    let base = logical_components(base);
    let path = logical_components(path);
    path.len() >= base.len() && path[..base.len()] == base[..]
}

fn logical_components(path: &Path) -> Vec<Component<'_>> {
    path.components()
        .filter(|component| !matches!(component, Component::CurDir | Component::ParentDir))
        .collect()
}
