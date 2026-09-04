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
//!
//! ## Which "developer profile" is enforced
//!
//! The real developer roots are captured from the *build* environment
//! (`option_env!` at compile time), not from the process environment at first
//! use. Runtime capture cannot work for the `cockpit` binary that e2e tests
//! spawn as a child process: feature unification gives that binary the
//! `test-support` resolvers too, and its inherited XDG/HOME environment is
//! exactly the per-test isolated environment the harness installed. Runtime
//! capture would therefore classify the harness's own isolated roots as "the
//! developer profile" and redirect every explicit e2e override away, breaking
//! all spawned-child path expectations. Compile-time capture sees the true
//! developer shell that produced this test build and is immune to any
//! harness-provided environment, so an explicit XDG/HOME override in a spawned
//! child is honored (it never points at the real developer profile), while an
//! unguarded in-process test that resolves the real profile is still
//! redirected. When the build environment did not define the profile (no
//! compile-time `HOME`), the roots fall back to a first-use runtime capture,
//! which is correct for in-process tests because
//! [`ensure_real_developer_roots_captured`] runs before any [`TestEnvGuard`]
//! mutation.

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

// Compile-time capture of the developer profile that produced this test
// build. See the module docs: runtime capture cannot distinguish the real
// profile from the per-test environment an e2e harness hands a spawned
// `cockpit` child, but the build-time shell is always the true profile.
#[cfg(unix)]
const BUILD_HOME: Option<&str> = option_env!("HOME");
#[cfg(unix)]
const BUILD_XDG_CONFIG_HOME: Option<&str> = option_env!("XDG_CONFIG_HOME");
#[cfg(unix)]
const BUILD_XDG_DATA_HOME: Option<&str> = option_env!("XDG_DATA_HOME");
#[cfg(unix)]
const BUILD_XDG_STATE_HOME: Option<&str> = option_env!("XDG_STATE_HOME");

impl RealDeveloperCockpitRoots {
    /// Roots derived from the build environment, mirroring the platform
    /// defaults the `dirs`-based resolvers would produce in that shell.
    /// `None` when the build environment did not define a home.
    #[cfg(unix)]
    fn from_build_environment() -> Option<Self> {
        let build_home = BUILD_HOME?;
        if build_home.trim().is_empty() {
            return None;
        }
        let home = PathBuf::from(build_home);
        let non_empty = |value: Option<&str>| {
            value
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
        };
        let config_base = non_empty(BUILD_XDG_CONFIG_HOME).unwrap_or_else(|| home.join(".config"));
        let data_base = non_empty(BUILD_XDG_DATA_HOME).unwrap_or_else(|| home.join(".local/share"));
        let state_base =
            non_empty(BUILD_XDG_STATE_HOME).unwrap_or_else(|| home.join(".local/state"));
        Some(Self {
            home,
            xdg_data: data_base.clone(),
            config: config_base.join("cockpit"),
            data: data_base.join("cockpit"),
            state: state_base.join("cockpit"),
        })
    }

    #[cfg(not(unix))]
    fn from_build_environment() -> Option<Self> {
        // `dirs` on Windows resolves known folders, not env vars, so a
        // compile-time env capture cannot reconstruct the profile there.
        None
    }

    /// First-use runtime capture, used only when the build environment did
    /// not define the profile. Correct for in-process tests because it runs
    /// before any [`TestEnvGuard`] mutation.
    fn capture_at_runtime() -> Self {
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
    }
}

/// Record the developer-owned Cockpit roots once. In-process tests capture
/// before any test mutates `HOME` / XDG variables through [`TestEnvGuard`];
/// see the module docs for why the build environment is preferred.
pub fn ensure_real_developer_roots_captured() {
    REAL_DEVELOPER_COCKPIT_ROOTS.get_or_init(|| {
        RealDeveloperCockpitRoots::from_build_environment()
            .unwrap_or_else(RealDeveloperCockpitRoots::capture_at_runtime)
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
