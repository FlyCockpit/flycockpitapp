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
type DaemonLoadFn = dyn Fn(&Path) -> Result<DaemonConfigLoad> + Send + Sync;
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

pub struct DaemonConfigLoad {
    pub providers: ProvidersConfig,
    pub extended: ExtendedConfig,
    pub response_metrics_tokenizer_validation:
        std::result::Result<(), crate::config::extended::InvalidResponseMetricsTokenizer>,
    pub participating_layers: Vec<PathBuf>,
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
    daemon_load: Arc<DaemonLoadFn>,
    write_target: Arc<WriteTargetFn>,
    watch_paths: Arc<WatchPathsFn>,
}

impl std::fmt::Debug for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigSource").finish_non_exhaustive()
    }
}

impl ConfigSource {
    /// Construct an advisory injected source. This is suitable only when the
    /// supplied typed config is already known valid. Raw-layer tests and any
    /// future production source must use [`Self::new_with_daemon_load`].
    pub fn new(
        load: impl Fn(&Path) -> Result<(ProvidersConfig, ExtendedConfig)> + Send + Sync + 'static,
        write_target: impl Fn(&Path, &str) -> Option<PathBuf> + Send + Sync + 'static,
        watch_paths: impl Fn(&Path) -> ConfigWatchPaths + Send + Sync + 'static,
    ) -> Self {
        let load = Arc::new(load) as Arc<LoadFn>;
        let daemon_source = load.clone();
        Self {
            daemon_load: Arc::new(move |cwd| {
                let (providers, extended) = daemon_source(cwd)?;
                Ok(DaemonConfigLoad {
                    providers,
                    extended,
                    response_metrics_tokenizer_validation: Ok(()),
                    participating_layers: Vec::new(),
                })
            }),
            load,
            write_target: Arc::new(write_target),
            watch_paths: Arc::new(watch_paths),
        }
    }

    /// Construct an injected source with the same lossless daemon contract as
    /// production. Tests that model raw participating layers use this rather
    /// than allowing the advisory settings view to stand in for validation.
    pub fn new_with_daemon_load(
        load: impl Fn(&Path) -> Result<(ProvidersConfig, ExtendedConfig)> + Send + Sync + 'static,
        daemon_load: impl Fn(&Path) -> Result<DaemonConfigLoad> + Send + Sync + 'static,
        write_target: impl Fn(&Path, &str) -> Option<PathBuf> + Send + Sync + 'static,
        watch_paths: impl Fn(&Path) -> ConfigWatchPaths + Send + Sync + 'static,
    ) -> Self {
        Self {
            load: Arc::new(load),
            daemon_load: Arc::new(daemon_load),
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
        let load = Arc::new(|cwd: &Path| {
            // Fail closed: a layer with an unmaskable pending default-model
            // transaction must surface as a typed error, never as an
            // ambiguous snapshot the daemon then serves to clients.
            Ok((
                crate::secret_ref::try_load_effective(cwd)?,
                crate::config::extended::load_for_cwd(cwd),
            ))
        }) as Arc<LoadFn>;
        let daemon_load = Arc::new(|cwd: &Path| {
            let extended = crate::config::extended::load_for_cwd_for_daemon_contract(cwd);
            Ok(DaemonConfigLoad {
                providers: crate::secret_ref::try_load_effective(cwd)?,
                extended: extended.config,
                response_metrics_tokenizer_validation: extended
                    .response_metrics_tokenizer_validation,
                participating_layers: extended.participating_layers,
            })
        }) as Arc<DaemonLoadFn>;
        Self {
            load,
            daemon_load,
            write_target: Arc::new(|cwd, provider_id| {
                crate::config::dirs::config_write_target_for_provider(cwd, provider_id)
            }),
            watch_paths: Arc::new(|cwd| {
                let config_files = crate::config::dirs::config_file_paths_for_load(cwd);
                let provider_dirs = config_files
                    .iter()
                    .filter_map(|path| path.parent().map(|parent| parent.join("providers")))
                    .collect();
                ConfigWatchPaths::new(config_files, provider_dirs)
            }),
        }
    }

    /// A source returning fixed in-memory configs regardless of project
    /// root, with no config write-target. Test contexts inject this so
    /// daemon tests never consult the machine's live config.
    pub fn fixed(providers: ProvidersConfig, extended: ExtendedConfig) -> Self {
        let daemon_providers = providers.clone();
        let daemon_extended = extended.clone();
        Self::new_with_daemon_load(
            move |_cwd| Ok((providers.clone(), extended.clone())),
            move |_cwd| {
                Ok(DaemonConfigLoad {
                    providers: daemon_providers.clone(),
                    extended: daemon_extended.clone(),
                    response_metrics_tokenizer_validation: Ok(()),
                    participating_layers: Vec::new(),
                })
            },
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

    pub fn load_effective_for_daemon(
        &self,
        cwd: &Path,
        policy: &WorkspaceTrustPolicy,
    ) -> Result<(ProvidersConfig, ExtendedConfig)> {
        crate::config::trust::with_workspace_trust_policy(policy.clone(), || {
            let load = (self.daemon_load)(cwd)?;
            load.response_metrics_tokenizer_validation
                .map_err(anyhow::Error::new)?;
            Ok((load.providers, load.extended))
        })
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

        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let paths = crate::config::trust::with_workspace_trust_policy(policy, || {
            ConfigSource::production().watch_paths(tmp.path())
        });

        assert!(paths.config_files.contains(&layer.join("config.json")));
        assert!(paths.provider_dirs.contains(&layer.join("providers")));
        assert!(paths.watched_dirs().contains(&layer));
    }

    #[test]
    fn injected_daemon_load_contract_cannot_be_bypassed_by_advisory_load() {
        let source = ConfigSource::new_with_daemon_load(
            |_cwd| Ok((ProvidersConfig::default(), ExtendedConfig::default())),
            |_cwd| Err(anyhow::anyhow!("strict daemon validation failed")),
            |_cwd, _provider_id| None,
            |_cwd| ConfigWatchPaths::default(),
        );
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(Path::new("/tmp")).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        assert!(source.load(Path::new("/tmp")).is_ok());
        assert!(
            source
                .load_effective_for_daemon(Path::new("/tmp"), &policy)
                .is_err()
        );
    }

    #[test]
    fn config_watch_paths_exclude_agents_and_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        let layer = tmp.path().join(".cockpit");
        std::fs::create_dir_all(layer.join("agents")).unwrap();
        std::fs::create_dir_all(layer.join("providers")).unwrap();
        std::fs::write(layer.join("mcp.json"), "{}").unwrap();
        std::fs::write(layer.join("agents/build.md"), "agent").unwrap();

        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let paths = crate::config::trust::with_workspace_trust_policy(policy, || {
            ConfigSource::production().watch_paths(tmp.path())
        });
        let rendered = format!("{paths:?}");

        assert!(!rendered.contains("mcp.json"), "{rendered}");
        assert!(!rendered.contains("agents"), "{rendered}");
    }
}
