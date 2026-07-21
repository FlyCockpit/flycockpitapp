//! Layered-config directory discovery.
//!
//! Walk order (matches the [[config_layering]] plan):
//!
//!   1. Home-scoped: `~/.config/cockpit/`, then `~/.cockpit/`.
//!   2. Machine-local-but-project-scoped: a hashed-cwd dir under the
//!      cockpit data dir. Lets a user override per-cwd without
//!      committing anything to the repo. Hashing the cwd dodges
//!      filename-invalid characters and path-length limits.
//!   3. Every ancestor of `cwd` containing `.cockpit/`, from `cwd` upward,
//!      stopping at the `{$HOME, /srv, /opt, /tmp, /var/tmp, /}` stop set.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// The single per-layer config filename. Holds layer-wide provider metadata
/// and the former `ExtendedConfig` keys at the top level (GOALS §2a).
pub const CONFIG_FILE: &str = "config.json";

/// The per-layer MCP server config filename. Uses normal layered discovery
/// only; [`COCKPIT_CONFIG_ENV`] never redirects it.
pub const MCP_FILE: &str = "mcp.json";

/// Environment variable that points at one concrete `config.json` and bypasses
/// layered `config.json` discovery for runtime loading. It intentionally does
/// not affect sibling files such as `mcp.json`.
pub const COCKPIT_CONFIG_ENV: &str = "COCKPIT_CONFIG";

/// The retired per-layer file. Read by no code path; its presence in a
/// discovered layer triggers a one-time warning via
/// [`warn_if_stray_extended_config`].
pub const LEGACY_EXTENDED_CONFIG_FILE: &str = "extended-config.json";

/// Process-global set of layer directories already warned about, so the
/// stray-`extended-config.json` warning fires at most once per offending
/// layer per process (config is resolved many times per session — a
/// per-resolve warning would spam).
static WARNED_STRAY_EXTENDED: Mutex<Option<std::collections::HashSet<PathBuf>>> = Mutex::new(None);

/// If `layer_dir` still contains an `extended-config.json`, log a single
/// one-time warning (per layer, per process) that the file is no longer
/// read and its keys must be merged into `config.json`. The file itself is
/// never read, renamed, or migrated.
pub fn warn_if_stray_extended_config(layer_dir: &Path) {
    let stray = layer_dir.join(LEGACY_EXTENDED_CONFIG_FILE);
    if !stray.exists() {
        return;
    }
    if mark_stray_warned(&stray) {
        tracing::warn!(
            path = %stray.display(),
            "`extended-config.json` is no longer read; merge its keys into `config.json`"
        );
    }
}

/// Record `stray` in the process-global warned-set, returning `true` only
/// the first time a given path is seen — the dedup decision behind
/// [`warn_if_stray_extended_config`]'s "warn exactly once per layer per
/// process" guarantee. Split out so the dedup is unit-testable without
/// asserting on log output.
fn mark_stray_warned(stray: &Path) -> bool {
    let mut guard = WARNED_STRAY_EXTENDED
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let seen = guard.get_or_insert_with(std::collections::HashSet::new);
    seen.insert(stray.to_path_buf())
}

/// Where a cockpit config directory was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigDirKind {
    /// `~/.config/cockpit/`
    HomeXdg,
    /// `~/.cockpit/`
    HomeDot,
    /// `<cockpit_data_dir>/local-configs/<hash(cwd)>/` — machine-local
    /// per-cwd config. Never checked into a repo.
    MachineLocal,
    /// An ancestor of cwd containing `.cockpit/` (project-scoped layer).
    Project,
}

#[derive(Debug, Clone)]
pub struct ConfigDir {
    pub kind: ConfigDirKind,
    pub path: PathBuf,
}

/// All cockpit config directories that exist on disk and apply to `cwd`.
pub fn discover_config_dirs(cwd: &Path) -> Vec<ConfigDir> {
    let mut out = Vec::new();

    if let Some(home) = dirs::home_dir() {
        let xdg = home.join(".config/cockpit");
        if xdg.is_dir() {
            out.push(ConfigDir {
                kind: ConfigDirKind::HomeXdg,
                path: xdg,
            });
        }
        let dot = home.join(".cockpit");
        if dot.is_dir() {
            out.push(ConfigDir {
                kind: ConfigDirKind::HomeDot,
                path: dot,
            });
        }
    }

    if let Ok(local) = local_config_dir_for(cwd)
        && local.is_dir()
    {
        out.push(ConfigDir {
            kind: ConfigDirKind::MachineLocal,
            path: local,
        });
    }

    for dir in walk_up_to_stops(cwd) {
        let candidate = dir.join(".cockpit");
        if candidate.is_dir() && crate::config::trust::project_config_allowed(&candidate) {
            out.push(ConfigDir {
                kind: ConfigDirKind::Project,
                path: candidate,
            });
        }
    }

    // Single chokepoint: every layered resolver walks through here, so a
    // stray retired `extended-config.json` in any discovered layer warns
    // exactly once per layer per process (deduped in the helper).
    for dir in &out {
        warn_if_stray_extended_config(&dir.path);
    }

    out
}

/// Effective `config.json` files for runtime loading, ordered from least
/// specific to most specific. This is separate from [`discover_config_dirs`]
/// because UI editing still needs the discovered directory order for choosing a
/// concrete layer to write.
pub fn config_file_paths_for_load(cwd: &Path) -> Vec<PathBuf> {
    if let Some(path) = std::env::var_os(COCKPIT_CONFIG_ENV)
        && !path.is_empty()
    {
        let path = PathBuf::from(path);
        if crate::config::trust::project_config_allowed(path.parent().unwrap_or(Path::new(""))) {
            return vec![path];
        }
        return Vec::new();
    }

    file_paths_for_load(cwd, CONFIG_FILE)
}

/// `providers/<provider-id>.json` write target for a runtime mutation that
/// belongs to `provider_id`: the most-specific layer that already defines the
/// provider, else the most-specific discovered layer. `COCKPIT_CONFIG` is a
/// single-layer override, so provider files live beside that exact file.
pub fn config_write_target_for_provider(cwd: &Path, provider_id: &str) -> Option<PathBuf> {
    if crate::config::providers::validate_provider_id_for_filename(provider_id).is_err() {
        return None;
    }
    if let Some(path) = std::env::var_os(COCKPIT_CONFIG_ENV)
        && !path.is_empty()
    {
        let path = PathBuf::from(path);
        if !crate::config::trust::project_config_write_allowed(
            path.parent().unwrap_or(Path::new("")),
        ) {
            return None;
        }
        return crate::config::providers::provider_file_path_for_config(&path, provider_id).ok();
    }

    let mut target = None;
    let mut defining = None;
    for dir in discover_config_dirs(cwd) {
        let path =
            match crate::config::providers::provider_file_path_for_dir(&dir.path, provider_id) {
                Ok(path) => path,
                Err(_) => return None,
            };
        target = Some(path.clone());
        if path.exists() {
            defining = Some(path);
        }
    }
    defining.or(target)
}

/// Most-specific runtime `config.json` write target for mutations that are not
/// tied to one existing entity. Honors `COCKPIT_CONFIG` as the sole layer.
pub fn most_specific_config_write_target(cwd: &Path) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(COCKPIT_CONFIG_ENV)
        && !path.is_empty()
    {
        let path = PathBuf::from(path);
        if crate::config::trust::project_config_write_allowed(
            path.parent().unwrap_or(Path::new("")),
        ) {
            return Some(path);
        }
        return None;
    }

    discover_config_dirs(cwd)
        .into_iter()
        .map(|d| d.path.join(CONFIG_FILE))
        .next_back()
}

/// Effective `mcp.json` files for runtime loading, ordered from least
/// specific to most specific. Unlike [`config_file_paths_for_load`], this
/// always uses normal layered discovery and is never redirected by
/// [`COCKPIT_CONFIG_ENV`].
pub fn mcp_file_paths_for_load(cwd: &Path) -> Vec<PathBuf> {
    file_paths_for_load(cwd, MCP_FILE)
}

fn file_paths_for_load(cwd: &Path, filename: &str) -> Vec<PathBuf> {
    let mut home_and_local = Vec::new();
    let mut project = Vec::new();
    for dir in discover_config_dirs(cwd) {
        match dir.kind {
            ConfigDirKind::Project => project.push(dir.path.join(filename)),
            ConfigDirKind::HomeXdg | ConfigDirKind::HomeDot | ConfigDirKind::MachineLocal => {
                home_and_local.push(dir.path.join(filename));
            }
        }
    }
    project.reverse();
    home_and_local.extend(project);
    home_and_local
}

/// Default places `/settings` will offer when no config exists yet.
pub fn creatable_config_dirs() -> Vec<ConfigDir> {
    let mut out = Vec::new();
    if let Some(home) = dirs::home_dir() {
        out.push(ConfigDir {
            kind: ConfigDirKind::HomeXdg,
            path: home.join(".config/cockpit"),
        });
        out.push(ConfigDir {
            kind: ConfigDirKind::HomeDot,
            path: home.join(".cockpit"),
        });
    }
    out
}

/// Candidate locations for "add a new config scoped to this directory":
/// the project-local `.cockpit/` and the machine-local hashed-cwd dir.
/// Returned even when they don't exist yet — the caller scaffolds them.
pub fn cwd_scoped_creatable_dirs(cwd: &Path) -> Vec<ConfigDir> {
    let project_dir = cwd.join(".cockpit");
    let mut out = Vec::new();
    if crate::config::trust::project_config_write_allowed(&project_dir) {
        out.push(ConfigDir {
            kind: ConfigDirKind::Project,
            path: project_dir,
        });
    }
    if let Ok(local) = local_config_dir_for(cwd) {
        out.push(ConfigDir {
            kind: ConfigDirKind::MachineLocal,
            path: local,
        });
    }
    out
}

/// Stable per-cwd directory under the cockpit data dir. The cwd is
/// canonicalized when possible (so `./foo` and `/abs/foo` map to the
/// same layer), then SHA-256-hashed and truncated to 16 hex chars so
/// it's filename-safe everywhere. Returns an error if the data dir
/// can't be located (no `$HOME` and no XDG data var).
pub fn local_config_dir_for(cwd: &Path) -> anyhow::Result<PathBuf> {
    let canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    let base = crate::config::resolve::cockpit_data_dir()?;
    Ok(base.join("local-configs").join(hex))
}

/// Create `dir` (and parents) and write a minimal `config.json` if one
/// isn't already present. Returns the path of the config file.
pub fn scaffold_config_dir(dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let config_path = dir.join(CONFIG_FILE);
    if !config_path.exists() {
        let default = "{\n  \"agents\": {},\n  \"tools\": {}\n}\n";
        std::fs::write(&config_path, default)?;
    }
    Ok(config_path)
}

/// Walk `cwd` and its ancestors, stopping at the
/// `{$HOME, /srv, /opt, /tmp, /var/tmp, /}` stop set. `/tmp` and `/var/tmp`
/// are shared-host planting boundaries: a user opening `/tmp/victim/project`
/// must not inherit an attacker-created `/tmp/.cockpit`.
pub fn walk_up_to_stops(cwd: &Path) -> Vec<PathBuf> {
    let stops: Vec<PathBuf> = [
        dirs::home_dir(),
        Some(PathBuf::from("/srv")),
        Some(PathBuf::from("/opt")),
        Some(PathBuf::from("/tmp")),
        Some(PathBuf::from("/var/tmp")),
        Some(PathBuf::from("/")),
    ]
    .into_iter()
    .flatten()
    .collect();

    let mut out = Vec::new();
    let mut cursor = Some(cwd);
    while let Some(dir) = cursor {
        if stops.iter().any(|s| dir == s) {
            break;
        }
        out.push(dir.to_path_buf());
        cursor = dir.parent();
    }
    out
}

#[cfg(test)]
pub mod test_support {
    pub struct CockpitConfigOverride {
        _guard: crate::test_env::TestEnvGuard,
    }

    impl CockpitConfigOverride {
        pub fn new(path: &std::path::Path) -> Self {
            let guard = crate::test_env::lock();
            guard.set_cockpit_config(path);
            Self { _guard: guard }
        }
    }

    pub struct IsolatedCockpitHome {
        guard: crate::test_env::TestEnvGuard,
    }

    pub struct IsolatedCockpitConfigOverride<'a> {
        guard: &'a crate::test_env::TestEnvGuard,
        old_cockpit_config: Option<std::ffi::OsString>,
    }

    impl IsolatedCockpitHome {
        pub fn new(root: &std::path::Path) -> Self {
            Self {
                guard: crate::test_env::TestEnvGuard::isolate_cockpit_home_at(root),
            }
        }

        pub async fn new_async(root: &std::path::Path) -> Self {
            let guard = crate::test_env::TestEnvGuard::lock().await;
            guard.set_isolated_home(root);
            Self { guard }
        }

        pub fn override_cockpit_config(
            &self,
            path: &std::path::Path,
        ) -> IsolatedCockpitConfigOverride<'_> {
            let old_cockpit_config = std::env::var_os(super::COCKPIT_CONFIG_ENV);
            self.guard.set_cockpit_config(path);
            IsolatedCockpitConfigOverride {
                guard: &self.guard,
                old_cockpit_config,
            }
        }
    }

    impl Drop for IsolatedCockpitConfigOverride<'_> {
        fn drop(&mut self) {
            match &self.old_cockpit_config {
                Some(v) => self.guard.set_var(super::COCKPIT_CONFIG_ENV, v),
                None => self.guard.remove_cockpit_config(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// The stray-`extended-config.json` warning dedups per layer per
    /// process: the first sighting of a given path returns `true` (warn),
    /// every later sighting returns `false` (already warned) — so the
    /// frequently-called config resolve never spams. A distinct layer path
    /// still warns once on its own.
    #[test]
    fn stray_extended_config_warning_dedups_per_path() {
        let tmp = TempDir::new().unwrap();
        let a = tmp.path().join("layer-a").join(LEGACY_EXTENDED_CONFIG_FILE);
        let b = tmp.path().join("layer-b").join(LEGACY_EXTENDED_CONFIG_FILE);

        // First sighting of each distinct path warns exactly once.
        assert!(mark_stray_warned(&a), "first sighting of a warns");
        assert!(
            !mark_stray_warned(&a),
            "second sighting of a is deduped (no spam)"
        );
        assert!(
            !mark_stray_warned(&a),
            "every further sighting of a stays deduped"
        );
        assert!(mark_stray_warned(&b), "a distinct layer still warns once");
        assert!(!mark_stray_warned(&b), "and then dedups too");
    }

    /// A layer with no leftover `extended-config.json` is a silent no-op.
    #[test]
    fn no_stray_file_is_a_no_op() {
        let tmp = TempDir::new().unwrap();
        // No file written → helper returns without recording anything.
        warn_if_stray_extended_config(tmp.path());
        let stray = tmp.path().join(LEGACY_EXTENDED_CONFIG_FILE);
        // The first real sighting (after creating the file) still warns,
        // proving the no-op path didn't pre-mark it.
        std::fs::write(&stray, "{}").unwrap();
        assert!(mark_stray_warned(&stray));
    }

    #[test]
    fn mcp_file_paths_match_config_file_layer_order_with_filename_swapped() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let home = tmp.path().join("home");
        let parent = tmp.path().join("repo");
        let child = parent.join("child");

        std::fs::create_dir_all(home.join(".config/cockpit")).unwrap();
        std::fs::create_dir_all(parent.join(".cockpit")).unwrap();
        std::fs::create_dir_all(child.join(".cockpit")).unwrap();

        let config_paths = config_file_paths_for_load(&child);
        let mcp_paths = mcp_file_paths_for_load(&child);
        let config_paths_as_mcp: Vec<PathBuf> = config_paths
            .iter()
            .map(|path| path.with_file_name(MCP_FILE))
            .collect();

        assert_eq!(
            config_paths_as_mcp, mcp_paths,
            "mcp.json follows the same home-to-project layer order as config.json"
        );
        assert_eq!(
            mcp_paths,
            vec![
                home.join(".config/cockpit/mcp.json"),
                parent.join(".cockpit/mcp.json"),
                child.join(".cockpit/mcp.json"),
            ]
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn trust_mode_includes_project_config_layers() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(home.join(".config/cockpit")).unwrap();
        std::fs::create_dir_all(repo.join(".cockpit")).unwrap();
        let root = crate::config::trust::resolve_trust_root(&repo).unwrap();
        crate::config::trust::set_runtime_policy(
            root,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        );

        assert_eq!(
            config_file_paths_for_load(&repo),
            vec![
                home.join(".config/cockpit/config.json"),
                repo.join(".cockpit/config.json"),
            ]
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn ignore_config_excludes_project_config_but_keeps_home() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(home.join(".config/cockpit")).unwrap();
        std::fs::create_dir_all(home.join(".cockpit")).unwrap();
        std::fs::create_dir_all(repo.join(".cockpit")).unwrap();
        let root = crate::config::trust::resolve_trust_root(&repo).unwrap();
        crate::config::trust::set_runtime_policy(
            root,
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        );

        assert_eq!(
            config_file_paths_for_load(&repo),
            vec![
                home.join(".config/cockpit/config.json"),
                home.join(".cockpit/config.json"),
            ]
        );
        assert_eq!(
            mcp_file_paths_for_load(&repo),
            vec![
                home.join(".config/cockpit/mcp.json"),
                home.join(".cockpit/mcp.json"),
            ]
        );
        assert!(
            !cwd_scoped_creatable_dirs(&repo)
                .iter()
                .any(|dir| dir.kind == ConfigDirKind::Project)
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn walk_up_stops_at_tmp_boundaries() {
        let cwd = PathBuf::from("/tmp/victim/sub");
        let walked = walk_up_to_stops(&cwd);

        assert_eq!(
            walked,
            vec![
                PathBuf::from("/tmp/victim/sub"),
                PathBuf::from("/tmp/victim")
            ]
        );
        assert!(
            !walked.contains(&PathBuf::from("/tmp")),
            "a planted /tmp/.cockpit layer must not be discovered"
        );

        let var_tmp = PathBuf::from("/var/tmp/victim/sub");
        let walked = walk_up_to_stops(&var_tmp);
        assert_eq!(
            walked,
            vec![
                PathBuf::from("/var/tmp/victim/sub"),
                PathBuf::from("/var/tmp/victim"),
            ]
        );
    }

    #[test]
    fn ignore_config_excludes_parent_project_layer_above_nested_git_root() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let evil = tmp.path().join("evil");
        let nested = evil.join("sub");
        std::fs::create_dir_all(evil.join(".cockpit")).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&nested)
            .status()
            .expect("git init nested root");
        assert!(status.success());
        let root = crate::config::trust::resolve_trust_root(&nested).unwrap();

        crate::config::trust::set_runtime_policy(
            root.clone(),
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        );
        assert!(
            config_file_paths_for_load(&nested).is_empty(),
            "ignore-config must exclude .cockpit layers above a nested trust root"
        );

        crate::config::trust::set_runtime_policy(
            root,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        );
        assert_eq!(
            config_file_paths_for_load(&nested),
            vec![evil.join(".cockpit/config.json")]
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn cockpit_config_env_inside_ignored_project_is_not_loaded() {
        let tmp = TempDir::new().unwrap();
        let env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let repo = tmp.path().join("repo");
        let project_cockpit = repo.join(".cockpit");
        std::fs::create_dir_all(&project_cockpit).unwrap();
        let config = project_cockpit.join("config.json");
        std::fs::write(&config, "{}").unwrap();
        let root = crate::config::trust::resolve_trust_root(&repo).unwrap();
        crate::config::trust::set_runtime_policy(
            root,
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        );
        let _override = env.override_cockpit_config(&config);

        assert!(config_file_paths_for_load(&repo).is_empty());
        assert!(most_specific_config_write_target(&repo).is_none());
        crate::config::trust::clear_runtime_policy_for_tests();
    }
}
