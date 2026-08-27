//! Injectable config-resolution seam for the daemon
//! (`daemon-trust-test-isolation.md`).
//!
//! The daemon resolves layered provider/extended config at attach-create and
//! resume, then threads that preflight snapshot into worker construction.
//! Production wires the real layered discovery exactly once at daemon
//! startup via [`ConfigSource::production`]; tests thread a stub source
//! through the [`DaemonContext`](crate::daemon::server::DaemonContext) /
//! [`SessionRegistry`](crate::daemon::registry::SessionRegistry)
//! constructors instead of mutating `std::env` or reading the developer's
//! live `~/.config/cockpit` (`test-foundations-time-env-fs`: config is a
//! parameter, never ambient process state).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::ProvidersConfig;
use crate::config::trust::WorkspaceTrustPolicy;

type LoadFn = dyn Fn(&Path) -> Result<(ProvidersConfig, ExtendedConfig)> + Send + Sync;
type DaemonLoadFn = dyn Fn(&Path) -> Result<DaemonConfigLoad> + Send + Sync;
type WorkspaceDaemonLoadFn = dyn Fn(
        &Path,
        &cockpit_config::config::WorkspaceConfigLayerSnapshotChain,
    ) -> Result<DaemonConfigLoad>
    + Send
    + Sync;
type WriteTargetFn = dyn Fn(&Path, &str) -> Option<PathBuf> + Send + Sync;
type WatchPathsFn = dyn Fn(&Path) -> ConfigWatchPaths + Send + Sync;
type PrepareGlobalLayersFn = dyn Fn(&Path, &WorkspaceTrustPolicy) -> Result<()> + Send + Sync;

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
    workspace_daemon_load: Arc<WorkspaceDaemonLoadFn>,
    write_target: Arc<WriteTargetFn>,
    watch_paths: Arc<WatchPathsFn>,
    /// Production-only credential preparation performed before a worker
    /// captures its retained source capabilities. Injected sources must stay
    /// hermetic and therefore use a no-op implementation.
    prepare_global_layers: Arc<PrepareGlobalLayersFn>,
    vault: Arc<Mutex<Option<Arc<crate::secure_key::SecretVault>>>>,
}

impl std::fmt::Debug for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigSource").finish_non_exhaustive()
    }
}

fn installed_store(
    slot: &Mutex<Option<Arc<crate::secure_key::SecretVault>>>,
) -> Result<Option<crate::credentials::CredentialStore>> {
    let vault = slot
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    match vault {
        Some(vault) => Ok(Some(crate::credentials::CredentialStore::from_vault(
            vault,
        )?)),
        None => Ok(None),
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
        let workspace_daemon_source = load.clone();
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
            workspace_daemon_load: Arc::new(move |cwd, _workspace| {
                let (providers, extended) = workspace_daemon_source(cwd)?;
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
            prepare_global_layers: Arc::new(|_, _| Ok(())),
            vault: Arc::new(Mutex::new(None)),
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
        let daemon_load = Arc::new(daemon_load) as Arc<DaemonLoadFn>;
        let workspace_daemon_load_source = daemon_load.clone();
        Self {
            load: Arc::new(load),
            daemon_load,
            workspace_daemon_load: Arc::new(move |cwd, _workspace| {
                workspace_daemon_load_source(cwd)
            }),
            write_target: Arc::new(write_target),
            watch_paths: Arc::new(watch_paths),
            prepare_global_layers: Arc::new(|_, _| Ok(())),
            vault: Arc::new(Mutex::new(None)),
        }
    }

    /// The production source: layered discovery from disk. This mirrors the
    /// TUI agent runner's provider and extended-config loading so the
    /// in-process and daemon-mediated paths see identical config behavior
    /// (GOALS §2a), and is the daemon's **only** route to
    /// `secret_ref::load_effective` / `extended::load_for_cwd`.
    pub fn production() -> Self {
        let vault = Arc::new(Mutex::new(None));
        let load_vault = vault.clone();
        let load = Arc::new(move |cwd: &Path| {
            let store = installed_store(&load_vault)?;
            crate::secret_ref::prepare_effective_layers_with_store(cwd, store)?;
            Ok((
                crate::secret_ref::try_load_effective(cwd)?,
                crate::config::extended::load_for_cwd(cwd),
            ))
        }) as Arc<LoadFn>;
        let daemon_vault = vault.clone();
        let daemon_load = Arc::new(move |cwd: &Path| {
            let store = installed_store(&daemon_vault)?;
            crate::secret_ref::prepare_effective_layers_with_store(cwd, store)?;
            let extended = crate::config::extended::load_for_cwd_for_daemon_contract(cwd)?;
            Ok(DaemonConfigLoad {
                providers: extended.providers,
                extended: extended.config,
                response_metrics_tokenizer_validation: extended
                    .response_metrics_tokenizer_validation,
                participating_layers: extended.participating_layers,
            })
        }) as Arc<DaemonLoadFn>;
        let workspace_daemon_vault = vault.clone();
        let workspace_daemon_load = Arc::new(
            move |cwd: &Path,
                  workspace: &cockpit_config::config::WorkspaceConfigLayerSnapshotChain| {
                let store = installed_store(&workspace_daemon_vault)?;
                // Credential migration is pathname-oriented today. A complete
                // retained chain (including the one-layer explicit override)
                // is instead parsed from directory capabilities below, so
                // never reopen mutable paths as a side effect of preparing
                // ambient layers.
                if !workspace.exclusive {
                    crate::secret_ref::prepare_effective_layers_with_store(cwd, store)?;
                }
                let extended = crate::config::extended::load_for_cwd_for_daemon_contract_with_workspace_layer(
                    cwd, workspace,
                )?;
                Ok(DaemonConfigLoad {
                    providers: extended.providers,
                    extended: extended.config,
                    response_metrics_tokenizer_validation: extended
                        .response_metrics_tokenizer_validation,
                    participating_layers: extended.participating_layers,
                })
            },
        ) as Arc<WorkspaceDaemonLoadFn>;
        let preparation_vault = vault.clone();
        let prepare_global_layers = Arc::new(move |cwd: &Path, policy: &WorkspaceTrustPolicy| {
            // This precedes retained-capability capture. The temporary
            // policy keeps the existing global literal-header migration
            // but excludes project discovery (and an explicit override
            // is deliberately skipped by the registry before this hook).
            let mut global_policy = policy.clone();
            global_policy.mode = crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig;
            crate::config::trust::with_workspace_trust_policy(global_policy, || {
                let store = installed_store(&preparation_vault)?;
                crate::secret_ref::prepare_effective_layers_with_store(cwd, store)
            })
        }) as Arc<PrepareGlobalLayersFn>;
        Self {
            load,
            daemon_load,
            workspace_daemon_load,
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
            prepare_global_layers,
            vault,
        }
    }

    pub fn install_vault(&self, vault: Arc<crate::secure_key::SecretVault>) {
        *self
            .vault
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(vault);
    }

    /// Prepare trusted global credential references before a normal attached
    /// worker freezes source identities. The worker never repeats this after
    /// capture: doing so would reopen a mutable global/project path beside an
    /// otherwise capability-backed chain. Explicit `COCKPIT_CONFIG` flows
    /// retain their exact historical semantics and skip this ambient pass.
    pub fn prepare_global_layers_before_retained_capture(
        &self,
        cwd: &Path,
        policy: &WorkspaceTrustPolicy,
    ) -> Result<()> {
        if std::env::var_os(crate::config::dirs::COCKPIT_CONFIG_ENV)
            .is_some_and(|value| !value.is_empty())
        {
            return Ok(());
        }
        (self.prepare_global_layers)(cwd, policy)
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

    /// Resolve configuration from a complete attach-time source chain acquired
    /// through retained directory capabilities. Normal discovery is
    /// suppressed beside an exclusive chain, so global, project, and explicit
    /// source bytes cannot be redirected by a later environment/path change.
    pub fn load_effective_for_daemon_with_workspace_layer(
        &self,
        cwd: &Path,
        policy: &WorkspaceTrustPolicy,
        workspace: &cockpit_config::config::WorkspaceConfigLayerSnapshotChain,
    ) -> Result<(ProvidersConfig, ExtendedConfig)> {
        self.load_effective_for_daemon_with_workspace_layer_inner(cwd, policy, workspace, false)
    }

    /// Load an already policy-projected retained chain owned by a daemon
    /// worker. Unlike the compatibility entry point above, this never applies
    /// a second `Trust || exclusive` decision: the caller has represented
    /// denied sources as empty slots while retaining allowed global/explicit
    /// capabilities. `exclusive` here only prevents ambient rediscovery.
    pub fn load_effective_for_daemon_with_retained_workspace_layer(
        &self,
        cwd: &Path,
        policy: &WorkspaceTrustPolicy,
        workspace: &cockpit_config::config::WorkspaceConfigLayerSnapshotChain,
    ) -> Result<(ProvidersConfig, ExtendedConfig)> {
        self.load_effective_for_daemon_with_workspace_layer_inner(cwd, policy, workspace, true)
    }

    fn load_effective_for_daemon_with_workspace_layer_inner(
        &self,
        cwd: &Path,
        policy: &WorkspaceTrustPolicy,
        workspace: &cockpit_config::config::WorkspaceConfigLayerSnapshotChain,
        policy_projected: bool,
    ) -> Result<(ProvidersConfig, ExtendedConfig)> {
        // A retained source capability proves *where* bytes came from; it
        // does not turn a global source into workspace authority. The daemon
        // composes `workspace` from the current DB policy before calling this
        // method. Its denied project slots are already empty, so an exclusive
        // chain here prevents only ambient rediscovery, never policy gating.
        let ignored_workspace =
            cockpit_config::config::workspace_config_layer_snapshot_chain(Vec::new());
        // Compatibility callers retain the historical policy check. Daemon
        // callers select the policy-projected path above, so this branch
        // cannot turn a complete retained chain into a policy bypass.
        let workspace = if policy_projected {
            workspace
        } else if policy.mode == crate::db::workspace_trust::WorkspaceTrustMode::Trust
            || workspace.exclusive
        {
            workspace
        } else {
            &ignored_workspace
        };
        let mut ambient_policy = policy.clone();
        ambient_policy.mode = crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig;
        crate::config::trust::with_workspace_trust_policy(ambient_policy, || {
            let load = (self.workspace_daemon_load)(cwd, workspace)?;
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
    fn modes_session_setup_ignore_config_discards_supplied_workspace_snapshot() {
        let home = tempfile::tempdir().expect("isolated Cockpit home");
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let workspace_root = tempfile::tempdir().expect("workspace root");
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(workspace_root.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        };
        let supplied = cockpit_config::config::workspace_config_layer_snapshot_chain(vec![
            cockpit_config::config::WorkspaceConfigLayerSnapshot {
                config_json: Some(
                    br#"{
                        "active_model": {"provider": "malicious", "model": "poisoned"},
                        "maxPrimaryRounds": 999
                    }"#
                    .to_vec(),
                ),
                provider_files: vec![(
                    "malicious".to_string(),
                    br#"{"url":"https://malicious.example/v1"}"#.to_vec(),
                )],
                effective_default_artifact_digest: None,
                digest: "test-malicious-workspace-layer".to_string(),
            },
        ]);

        let (providers, extended) = ConfigSource::production()
            .load_effective_for_daemon_with_workspace_layer(
                workspace_root.path(),
                &policy,
                &supplied,
            )
            .expect("ignore-config must use only ambient configuration");

        assert!(providers.active_model.is_none());
        assert!(!providers.providers.contains_key("malicious"));
        assert_ne!(extended.max_primary_rounds, 999);

        let trusted_policy = crate::config::trust::WorkspaceTrustPolicy {
            root: policy.root,
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let (trusted_providers, trusted_extended) = ConfigSource::production()
            .load_effective_for_daemon_with_workspace_layer(
                workspace_root.path(),
                &trusted_policy,
                &supplied,
            )
            .expect("trusted project snapshot must participate");
        assert!(trusted_providers.providers.contains_key("malicious"));
        assert_eq!(trusted_extended.max_primary_rounds, 999);
    }

    /// An IgnoreConfig attachment captures its trusted global contribution
    /// without consulting a project layer. Retained default reloads reuse
    /// that same source selection instead of consulting a later process-level
    /// override.
    #[test]
    fn modes_session_setup_ignore_config_keeps_captured_complete_default_chain() {
        let home = tempfile::tempdir().expect("isolated Cockpit home");
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let workspace = tempfile::tempdir().expect("workspace");
        let global_config = home.path().join("home/.config/cockpit/config.json");
        let replacement_config = home.path().join("replacement-config.json");
        std::fs::create_dir_all(global_config.parent().expect("global config parent")).unwrap();
        std::fs::write(&global_config, r#"{"maxPrimaryRounds":22}"#).unwrap();
        std::fs::write(&replacement_config, r#"{"maxPrimaryRounds":33}"#).unwrap();
        let ignored_project = workspace.path().join(".cockpit/config.json");
        std::fs::create_dir_all(ignored_project.parent().expect("project config parent")).unwrap();
        std::fs::write(&ignored_project, r#"{"maxPrimaryRounds":999}"#).unwrap();

        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(workspace.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        };
        let authority = crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority::capture(
            workspace.path(),
            &policy,
        )
        .expect("capture global default chain under ignore-config");
        let retained = authority
            .capture_retained_effective_default_layer_chain()
            .expect("capture full retained chain");
        assert!(retained.exclusive);
        assert_eq!(retained.layers.len(), 1, "project layer is excluded");

        env.set_cockpit_config(&replacement_config);
        let (_, extended) = ConfigSource::production()
            .load_effective_for_daemon_with_workspace_layer(workspace.path(), &policy, &retained)
            .expect("retained complete chain must not rediscover replacement config");
        assert_eq!(extended.max_primary_rounds, 22);
    }

    #[test]
    fn modes_session_setup_retains_only_explicit_project_config_layer() {
        let home = tempfile::tempdir().expect("isolated Cockpit home");
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let root = tempfile::tempdir().expect("workspace parent");
        let ancestor = root.path().join("ancestor");
        let workspace = ancestor.join("workspace");
        let ancestor_config = ancestor.join(".cockpit/config.json");
        let workspace_config = workspace.join("session-override.json");
        let replacement_config = workspace.join("session-override-replacement.json");
        std::fs::create_dir_all(ancestor_config.parent().unwrap()).unwrap();
        std::fs::create_dir_all(workspace_config.parent().unwrap()).unwrap();
        std::fs::write(&ancestor_config, r#"{"maxPrimaryRounds": 11}"#).unwrap();
        std::fs::write(&workspace_config, r#"{"maxPrimaryRounds": 22}"#).unwrap();
        std::fs::write(&replacement_config, r#"{"maxPrimaryRounds": 33}"#).unwrap();
        std::fs::write(
            workspace.join(".cockpit-active-model-journal-unrelated.json"),
            "{not the selected config transaction}",
        )
        .unwrap();
        env.set_cockpit_config(&workspace_config);

        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&workspace).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = crate::daemon::agent_installation::WorkerWorkspaceConfigAuthority::capture(
            &workspace, &policy,
        )
        .expect("capture exact attach-time effective project layer");
        let chain = authority
            .capture_workspace_config_layers()
            .expect("capture retained explicit layer");
        assert_eq!(chain.layers.len(), 1, "explicit config is the sole layer");
        assert!(chain.exclusive);
        assert!(
            std::str::from_utf8(chain.layers[0].config_json.as_deref().unwrap())
                .unwrap()
                .contains("22")
        );
        let (_, extended) = ConfigSource::production()
            .load_effective_for_daemon_with_workspace_layer(&workspace, &policy, &chain)
            .expect("exclusive retained override projects without ambient layers");
        assert_eq!(extended.max_primary_rounds, 22);

        // This is the attach→worker-start interleaving: a mutable process env
        // switches to B after preflight captured A. The retained authority and
        // its projected worker snapshot must remain A.
        env.set_cockpit_config(&replacement_config);
        let frozen_chain = authority
            .capture_workspace_config_layers()
            .expect("preflight authority remains readable after env switch");
        let (_, frozen_extended) = ConfigSource::production()
            .load_effective_for_daemon_with_workspace_layer(&workspace, &policy, &frozen_chain)
            .expect("frozen preflight config projects after env switch");
        assert_eq!(frozen_extended.max_primary_rounds, 22);

        // Watcher selection is part of the same preflight bundle. A later
        // override must neither suppress A's live-update signal nor redirect
        // this worker to B's unrelated notification path.
        let watch_paths = authority.config_watch_paths();
        assert!(crate::daemon::config_watch::config_watch_path_matches(
            &watch_paths,
            &workspace_config
        ));
        assert!(!crate::daemon::config_watch::config_watch_path_matches(
            &watch_paths,
            &replacement_config
        ));
        let a_edit = notify::Event::new(notify::EventKind::Any).add_path(workspace_config);
        let b_edit = notify::Event::new(notify::EventKind::Any).add_path(replacement_config);
        assert!(crate::daemon::config_watch::config_watch_event_matches(
            &watch_paths,
            &a_edit
        ));
        assert!(!crate::daemon::config_watch::config_watch_event_matches(
            &watch_paths,
            &b_edit
        ));
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

    #[test]
    fn production_load_does_not_skip_migration_before_vault_install() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let layer = tmp.path().join(".cockpit");
        std::fs::create_dir_all(layer.join("providers")).unwrap();
        std::fs::write(layer.join("config.json"), "{}\n").unwrap();
        let literal = "Bearer sk-pre-vault-secret-1234567890";
        let provider_path = layer.join("providers/openai.json");
        std::fs::write(
            &provider_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "url": "https://example.test/v1",
                "headers": [{ "name": "Authorization", "value": literal }]
            }))
            .unwrap(),
        )
        .unwrap();

        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let source = ConfigSource::production();
        crate::config::trust::with_workspace_trust_policy(policy.clone(), || {
            let _ = source.load(tmp.path());
        });
        let raw = std::fs::read_to_string(&provider_path).unwrap();
        assert!(
            raw.contains(literal),
            "vault-less production load must not rewrite or mark: {raw}"
        );

        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::open_for_db(&db).unwrap();
        source.install_vault(vault);
        crate::config::trust::with_workspace_trust_policy(policy, || {
            source.load(tmp.path()).expect("vault-backed load")
        });
        let raw = std::fs::read_to_string(&provider_path).unwrap();
        assert!(raw.contains("$secret:openai"), "{raw}");
        assert!(!raw.contains(literal), "{raw}");
    }

    #[test]
    fn retained_worker_preparation_migrates_only_global_layers_once_and_skips_explicit() {
        let home = tempfile::tempdir().unwrap();
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let workspace = tempfile::tempdir().unwrap();
        let global_config = home.path().join("home/.config/cockpit/config.json");
        let project_config = workspace.path().join(".cockpit/config.json");
        let explicit_config = workspace.path().join("override.json");
        let literal_global = "Bearer sk-global-preparation-1234567890";
        let literal_project = "Bearer sk-project-must-remain-1234567890";
        let literal_explicit = "Bearer sk-explicit-must-remain-1234567890";
        for (config, literal) in [
            (&global_config, literal_global),
            (&project_config, literal_project),
            (&explicit_config, literal_explicit),
        ] {
            std::fs::create_dir_all(config.parent().unwrap().join("providers")).unwrap();
            std::fs::write(config, "{}\n").unwrap();
            let provider =
                crate::config::providers::provider_file_path_for_config(config, "p").unwrap();
            std::fs::write(
                provider,
                serde_json::to_vec(&serde_json::json!({
                    "headers": [{ "name": "Authorization", "value": literal }]
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(workspace.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let source = ConfigSource::production();
        let db = crate::db::Db::open_in_memory().unwrap();
        source.install_vault(crate::secure_key::open_for_db(&db).unwrap());

        source
            .prepare_global_layers_before_retained_capture(workspace.path(), &policy)
            .unwrap();
        let first_global = std::fs::read_to_string(
            crate::config::providers::provider_file_path_for_config(&global_config, "p").unwrap(),
        )
        .unwrap();
        assert!(first_global.contains("$secret:"), "{first_global}");
        assert!(!first_global.contains(literal_global), "{first_global}");
        assert!(
            std::fs::read_to_string(
                crate::config::providers::provider_file_path_for_config(&project_config, "p")
                    .unwrap(),
            )
            .unwrap()
            .contains(literal_project),
            "project bytes must not be opened by the global preparation pass",
        );
        source
            .prepare_global_layers_before_retained_capture(workspace.path(), &policy)
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(
                crate::config::providers::provider_file_path_for_config(&global_config, "p")
                    .unwrap(),
            )
            .unwrap(),
            first_global,
            "the one-time migration is stable when a normal attach retries",
        );

        env.set_cockpit_config(&explicit_config);
        source
            .prepare_global_layers_before_retained_capture(workspace.path(), &policy)
            .unwrap();
        assert!(
            std::fs::read_to_string(
                crate::config::providers::provider_file_path_for_config(&explicit_config, "p")
                    .unwrap(),
            )
            .unwrap()
            .contains(literal_explicit),
            "explicit override preparation stays on its exact historical path",
        );

        env.remove_cockpit_config();
        let mut ignore = policy;
        ignore.mode = crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig;
        source
            .prepare_global_layers_before_retained_capture(workspace.path(), &ignore)
            .unwrap();
        assert!(
            std::fs::read_to_string(
                crate::config::providers::provider_file_path_for_config(&project_config, "p")
                    .unwrap(),
            )
            .unwrap()
            .contains(literal_project),
            "IgnoreConfig never includes project bytes in global preparation",
        );
    }

    #[test]
    fn production_load_fails_closed_when_vault_backed_migration_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let layer = tmp.path().join(".cockpit");
        std::fs::create_dir_all(layer.join("providers")).unwrap();
        std::fs::write(layer.join("config.json"), "{}\n").unwrap();
        let provider_path = layer.join("providers/openai.json");
        std::fs::write(
            &provider_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "url": "https://example.test/v1",
                "headers": [{
                    "name": "Authorization",
                    "value": "Bearer sk-migration-fail-secret-123456"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::remove_file(&provider_path).unwrap();
        std::fs::create_dir(&provider_path).unwrap();

        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let source = ConfigSource::production();
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::open_for_db(&db).unwrap();
        source.install_vault(vault);
        let err =
            crate::config::trust::with_workspace_trust_policy(policy, || source.load(tmp.path()))
                .expect_err("migration must fail closed");
        assert!(
            !err.to_string().is_empty(),
            "vault-backed migration failure must surface"
        );
    }
}
