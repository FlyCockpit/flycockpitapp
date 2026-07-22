//! Injectable config-resolution seam for the daemon
//! (`daemon-trust-test-isolation.md`).
//!
//! The daemon resolves layered provider/extended config (and the config
//! write-target for a provider) at attach-create, resume, and worker start.
//! Production wires the real layered discovery exactly once at daemon
//! startup via [`ConfigSource::production`]; tests thread a stub source
//! through the [`DaemonContext`](crate::daemon::server::DaemonContext) /
//! [`SessionRegistry`](crate::daemon::registry::SessionRegistry)
//! constructors instead of mutating `std::env` or reading the developer's
//! live `~/.config/cockpit` (`test-foundations-time-env-fs`: config is a
//! parameter, never ambient process state).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::ProvidersConfig;
use crate::config::trust::WorkspaceTrustPolicy;

type LoadFn = dyn Fn(&Path) -> Result<(ProvidersConfig, ExtendedConfig)> + Send + Sync;
type WriteTargetFn = dyn Fn(&Path, &str) -> Option<PathBuf> + Send + Sync;
type WatchPathsFn = dyn Fn(&Path) -> ConfigWatchPaths + Send + Sync;

/// Files whose parent directories should be watched for live config refresh.
///
/// `config_files` is path-exact so a `COCKPIT_CONFIG=/custom/name.json`
/// source can watch the parent directory without accidentally accepting a
/// sibling `config.json`. `provider_dirs` accepts direct `*.json` children.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigWatchPaths {
    pub config_files: Vec<PathBuf>,
    pub provider_dirs: Vec<PathBuf>,
}

impl ConfigWatchPaths {
    pub fn new(config_files: Vec<PathBuf>, provider_dirs: Vec<PathBuf>) -> Self {
        Self {
            config_files,
            provider_dirs,
        }
    }

    pub fn watched_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = BTreeSet::new();
        for path in &self.config_files {
            if let Some(parent) = path.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
        dirs.extend(self.provider_dirs.iter().cloned());
        dirs.into_iter().collect()
    }
}

/// Source of daemon config resolution: closures for loading the
/// effective `(ProvidersConfig, ExtendedConfig)` for a project root and for
/// resolving the config write-target path for a provider, plus the exact
/// files/directories the daemon may watch to trigger the same load path.
///
/// Trust-policy application deliberately stays *outside* the closures:
/// callers wrap loads in
/// [`with_workspace_trust_policy`](crate::config::trust::with_workspace_trust_policy)
/// (via [`Self::load_with_trust`]) so workspace-trust gating of project
/// layers applies identically to the production source and any injected one.
#[derive(Clone)]
pub struct ConfigSource {
    load: Arc<LoadFn>,
    write_target: Arc<WriteTargetFn>,
    watch_paths: Arc<WatchPathsFn>,
}

impl std::fmt::Debug for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigSource").finish_non_exhaustive()
    }
}

impl ConfigSource {
    pub fn new(
        load: impl Fn(&Path) -> Result<(ProvidersConfig, ExtendedConfig)> + Send + Sync + 'static,
        write_target: impl Fn(&Path, &str) -> Option<PathBuf> + Send + Sync + 'static,
        watch_paths: impl Fn(&Path) -> ConfigWatchPaths + Send + Sync + 'static,
    ) -> Self {
        Self {
            load: Arc::new(load),
            write_target: Arc::new(write_target),
            watch_paths: Arc::new(watch_paths),
        }
    }

    /// The production source: layered discovery from disk. This mirrors the
    /// TUI agent runner's provider and extended-config loading so the
    /// in-process and daemon-mediated paths see identical config behavior
    /// (GOALS §2a), and is the daemon's **only** route to
    /// `secret_ref::load_effective` / `extended::load_for_cwd`.
    pub fn production() -> Self {
        Self::new(
            |cwd| {
                Ok((
                    crate::secret_ref::load_effective(cwd),
                    crate::config::extended::load_for_cwd(cwd),
                ))
            },
            |cwd, provider_id| {
                crate::config::dirs::config_write_target_for_provider(cwd, provider_id)
            },
            |cwd| {
                let config_files = crate::config::dirs::config_file_paths_for_load(cwd);
                let provider_dirs = config_files
                    .iter()
                    .filter_map(|path| path.parent().map(|parent| parent.join("providers")))
                    .collect();
                ConfigWatchPaths::new(config_files, provider_dirs)
            },
        )
    }

    /// A source returning fixed in-memory configs regardless of project
    /// root, with no config write-target. Test contexts inject this so
    /// daemon tests never consult the machine's live config.
    pub fn fixed(providers: ProvidersConfig, extended: ExtendedConfig) -> Self {
        Self::new(
            move |_cwd| Ok((providers.clone(), extended.clone())),
            |_cwd, _provider_id| None,
            |_cwd| ConfigWatchPaths::default(),
        )
    }

    /// Load the effective configs for `cwd` with no workspace-trust policy
    /// applied (the caller's ambient policy, if any, governs).
    pub fn load(&self, cwd: &Path) -> Result<(ProvidersConfig, ExtendedConfig)> {
        (self.load)(cwd)
    }

    /// Load the effective configs for `cwd` under a resolved workspace-trust
    /// policy: the policy (resolved from the DB first) wraps whatever source
    /// runs, so trust gating of project layers is identical in production
    /// and tests.
    pub fn load_with_trust(
        &self,
        cwd: &Path,
        policy: &WorkspaceTrustPolicy,
    ) -> Result<(ProvidersConfig, ExtendedConfig)> {
        crate::config::trust::with_workspace_trust_policy(policy.clone(), || self.load(cwd))
    }

    /// Resolve the config-file write target for `provider_id` (the
    /// most-specific layer defining it). Callers wrap this in
    /// `with_workspace_trust_policy` where the write-target rule is
    /// trust-sensitive, matching the production call shape.
    pub fn config_write_target_for_provider(
        &self,
        cwd: &Path,
        provider_id: &str,
    ) -> Option<PathBuf> {
        (self.write_target)(cwd, provider_id)
    }

    pub fn watch_paths(&self, cwd: &Path) -> ConfigWatchPaths {
        (self.watch_paths)(cwd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_source_fixed_reports_no_watch_paths() {
        let source = ConfigSource::fixed(ProvidersConfig::default(), ExtendedConfig::default());
        assert_eq!(
            source.watch_paths(Path::new("/not-read-from-disk")),
            ConfigWatchPaths::default()
        );
    }

    #[test]
    fn config_source_production_watch_paths_include_layer_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = tmp.path().join(".cockpit");
        std::fs::create_dir_all(layer.join("providers")).unwrap();

        let paths = ConfigSource::production().watch_paths(tmp.path());

        assert!(paths.config_files.contains(&layer.join("config.json")));
        assert!(paths.provider_dirs.contains(&layer.join("providers")));
        assert!(paths.watched_dirs().contains(&layer));
    }

    #[test]
    fn config_watch_paths_exclude_agents_and_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = tmp.path().join(".cockpit");
        std::fs::create_dir_all(layer.join("agents")).unwrap();
        std::fs::create_dir_all(layer.join("providers")).unwrap();
        std::fs::write(layer.join("mcp.json"), "{}").unwrap();
        std::fs::write(layer.join("agents/build.md"), "agent").unwrap();

        let paths = ConfigSource::production().watch_paths(tmp.path());
        let rendered = format!("{paths:?}");

        assert!(!rendered.contains("mcp.json"), "{rendered}");
        assert!(!rendered.contains("agents"), "{rendered}");
    }
}
