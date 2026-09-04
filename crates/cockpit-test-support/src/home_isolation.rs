//! Fail closed when tests resolve Cockpit config/data/state paths under the
//! real developer profile instead of an isolated home installed by
//! [`TestEnvGuard::set_isolated_home`].

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

struct RealDeveloperCockpitRoots {
    config: PathBuf,
    data: PathBuf,
    state: PathBuf,
}

static REAL_DEVELOPER_COCKPIT_ROOTS: OnceLock<RealDeveloperCockpitRoots> = OnceLock::new();

/// Record the developer-owned Cockpit roots once, before any test mutates
/// `HOME` / XDG variables through [`TestEnvGuard`].
pub fn ensure_real_developer_roots_captured() {
    REAL_DEVELOPER_COCKPIT_ROOTS.get_or_init(|| {
        let config_base = dirs::config_dir().expect("locate real developer config dir");
        let data_base = dirs::data_dir().expect("locate real developer data dir");
        RealDeveloperCockpitRoots {
            config: config_base.join("cockpit"),
            data: data_base.join("cockpit"),
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

/// Panic when `path` resolves under the captured real developer Cockpit
/// config/data/state roots. Production code never calls this.
pub fn assert_not_real_developer_cockpit_path(path: &Path) {
    ensure_real_developer_roots_captured();
    let roots = REAL_DEVELOPER_COCKPIT_ROOTS
        .get()
        .expect("real developer cockpit roots captured above");
    if contained_under(&roots.config, path)
        || contained_under(&roots.data, path)
        || contained_under(&roots.state, path)
    {
        panic!(
            "test resolved a Cockpit home path under the real developer profile \
             ({}); call TestEnvGuard::isolated_cockpit_home[_async] or \
             isolate_cockpit_home_at[_async] and keep the returned guard alive \
             for the whole test before reading or writing config/data/state paths",
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
