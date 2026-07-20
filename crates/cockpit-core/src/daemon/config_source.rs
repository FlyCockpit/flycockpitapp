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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::ProvidersConfig;
use crate::config::trust::WorkspaceTrustPolicy;

type LoadFn = dyn Fn(&Path) -> Result<(ProvidersConfig, ExtendedConfig)> + Send + Sync;
type WriteTargetFn = dyn Fn(&Path, &str) -> Option<PathBuf> + Send + Sync;

/// Source of daemon config resolution: a pair of closures for loading the
/// effective `(ProvidersConfig, ExtendedConfig)` for a project root and for
/// resolving the config write-target path for a provider.
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
    ) -> Self {
        Self {
            load: Arc::new(load),
            write_target: Arc::new(write_target),
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
        )
    }

    /// A source returning fixed in-memory configs regardless of project
    /// root, with no config write-target. Test contexts inject this so
    /// daemon tests never consult the machine's live config.
    pub fn fixed(providers: ProvidersConfig, extended: ExtendedConfig) -> Self {
        Self::new(
            move |_cwd| Ok((providers.clone(), extended.clone())),
            |_cwd, _provider_id| None,
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
}
