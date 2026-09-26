//! Layered-config directory discovery.
//!
//! Walk order (matches the [[config_layering]] plan):
//!
//!   1. Global platform config (`~/.config/cockpit/` on Linux).
//!   2. Machine-local-but-project-scoped: a hashed-cwd dir under the
//!      cockpit data dir. Lets a user override per-cwd without
//!      committing anything to the repo. Hashing the cwd dodges
//!      filename-invalid characters and path-length limits.
//!   3. Every ancestor of `cwd` containing `.cockpit/`, from `cwd` upward,
//!      stopping at the `{$HOME, /srv, /opt, /tmp, /var/tmp, /}` stop set.

use std::path::{Path, PathBuf};

use anyhow::Context;
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

/// Where a cockpit config directory was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDirKind {
    /// Platform-default global config dir (`~/.config/cockpit/` on Linux).
    HomeXdg,
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

/// The canonical user-owned global config directory. Unlike project
/// `.cockpit/` layers, this path is never subject to workspace trust.
pub fn global_config_dir() -> anyhow::Result<PathBuf> {
    crate::config::resolve::cockpit_config_dir()
}

pub(crate) fn global_config_dir_unchecked() -> anyhow::Result<PathBuf> {
    crate::config::resolve::cockpit_config_dir_unchecked()
}

pub(crate) fn global_config_file_unchecked() -> anyhow::Result<PathBuf> {
    Ok(global_config_dir_unchecked()?.join(CONFIG_FILE))
}

/// The canonical global `config.json` path. Onboarding and other
/// user-level setup must use this rather than selecting a workspace layer.
pub fn global_config_file() -> anyhow::Result<PathBuf> {
    Ok(global_config_dir()?.join(CONFIG_FILE))
}

/// Actionable error when a write would have to create the missing global
/// Cockpit config directory. File-write helpers, approval stores, and
/// other side-effect mkdir sites never create that directory; only
/// [`ensure_global_config_dir`] may.
pub const MISSING_GLOBAL_CONFIG_DIR_MESSAGE: &str = "ephemeral daemons cannot create the global Cockpit config directory; start a persistent daemon before onboarding";

/// Ensure the canonical global directory exists and can accept writes.
///
/// This has no workspace-trust dependency. It is the only production
/// creator of the global layer. Authorized callers:
/// persistent daemon boot (before publishing the socket), the first
/// authorized user-level write (`ensure_authorized_global_layer`),
/// onboarding wizard apply, CLI first-run onboarding persist, and an
/// explicit config-layer scaffold ([`ensure_config_layer_dir`]).
/// Read-only commands and every other mkdir helper must not create it.
pub fn ensure_global_config_dir() -> anyhow::Result<PathBuf> {
    let path = global_config_dir()?;
    crate::config::files::ensure_private_writable_dir(&path)?;
    Ok(path)
}

/// True when `path` is the canonical global config directory or a file
/// inside it, and that directory does not currently exist.
///
/// File-write helpers must not create this directory. Call
/// [`ensure_global_config_dir`] from an authorized write funnel instead.
pub fn path_is_under_missing_global_config_dir(path: &Path) -> bool {
    let Ok(global) = global_config_dir_unchecked() else {
        return false;
    };
    !global.is_dir() && cockpit_host::path_containment::contained_under(&global, path)
}

/// Fail closed when `path` is the missing global config directory or a
/// file inside it. The global layer is created only by
/// [`ensure_global_config_dir`].
pub fn refuse_missing_global_config_dir(path: &Path) -> anyhow::Result<()> {
    if path_is_under_missing_global_config_dir(path) {
        anyhow::bail!("{}", MISSING_GLOBAL_CONFIG_DIR_MESSAGE);
    }
    Ok(())
}

/// Create `dir` and parents unless `dir` is the missing global config
/// directory (or lives under it).
///
/// Side-effect mkdir sites — approval locks, file-write helpers, mutation
/// locks, container sandbox Dockerfile materialization — must use this
/// instead of raw `create_dir_all` so an ephemeral/diagnostic owner cannot
/// materialize `~/.config/cockpit`. Nested product paths such as
/// `providers/` and `sandbox/` are included: `create_dir_all` of a
/// descendant would create the missing global parent at umask-default.
/// Authorized creators call [`ensure_global_config_dir`] or
/// [`ensure_config_layer_dir`].
pub fn create_dir_all_except_missing_global(dir: &Path) -> anyhow::Result<()> {
    refuse_missing_global_config_dir(dir)?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(())
}

/// Create `dir` as an explicit config-layer scaffold.
///
/// If `dir` is the canonical global config directory, this goes through
/// [`ensure_global_config_dir`] (0700 + writability probe). Any other
/// layer is created with [`create_dir_all_except_missing_global`], which
/// still refuses to scaffold a missing global layer as a side effect of
/// creating a nested path such as `providers/`.
pub fn ensure_config_layer_dir(dir: &Path) -> anyhow::Result<()> {
    if is_global_config_dir(dir).unwrap_or(false) {
        ensure_global_config_dir()?;
        return Ok(());
    }
    create_dir_all_except_missing_global(dir)
}

/// True when `path` names the canonical global config directory.
///
/// Comparison is symlink-aware via the nearest existing ancestor, so a
/// missing `~/.config/cockpit` cannot fail a read. Resolving the logical
/// global path itself still errors when the platform config dir cannot be
/// located (no `$HOME` / XDG).
pub fn is_global_config_dir(path: &Path) -> anyhow::Result<bool> {
    let global = global_config_dir()?;
    Ok(same_logical_path(path, &global))
}

/// Symlink-safe equality that does not require either path to exist.
fn same_logical_path(left: &Path, right: &Path) -> bool {
    match (
        cockpit_host::path_containment::effective_path(left),
        cockpit_host::path_containment::effective_path(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Global `providers/<provider-id>.json` write target, independent of whether
/// the global directory currently exists on disk.
fn global_provider_write_target(provider_id: &str) -> Option<PathBuf> {
    let dir = global_config_dir().ok()?;
    crate::config::providers::provider_file_path_for_dir(&dir, provider_id).ok()
}

/// All cockpit config directories that exist on disk and apply to `cwd`.
pub fn discover_config_dirs(cwd: &Path) -> Vec<ConfigDir> {
    let mut out = Vec::new();

    if let Ok(global) = global_config_dir()
        && global.is_dir()
    {
        out.push(ConfigDir {
            kind: ConfigDirKind::HomeXdg,
            path: global,
        });
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

    out
}

/// Effective `config.json` files for runtime loading, ordered from least
/// specific to most specific. This is separate from [`discover_config_dirs`]
/// because UI editing still needs the discovered directory order for choosing a
/// concrete layer to write.
pub fn config_file_paths_for_load(cwd: &Path) -> Vec<PathBuf> {
    match try_config_file_paths_for_load(cwd) {
        Ok(paths) => paths,
        Err(error) => {
            // Advisory loads cannot report errors; the strict daemon loads use
            // `try_config_file_paths_for_load` and fail on the same condition.
            tracing::error!(%error, "ignoring an unusable explicit config override");
            Vec::new()
        }
    }
}

/// [`config_file_paths_for_load`] with the explicit-override error surfaced.
/// Strict (daemon-contract and installation) loads use this, so a relative
/// `COCKPIT_CONFIG` is an error everywhere rather than a cwd lookup.
pub fn try_config_file_paths_for_load(
    cwd: &Path,
) -> Result<Vec<PathBuf>, ExplicitConfigOverrideError> {
    if let Some(path) = explicit_config_override()? {
        return Ok(vec![path]);
    }
    Ok(file_paths_for_load(cwd, CONFIG_FILE))
}

/// A `COCKPIT_CONFIG` override that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplicitConfigOverrideError {
    /// The override is not an absolute path, so it would resolve against the
    /// process's working directory.
    Relative(PathBuf),
}

impl std::fmt::Display for ExplicitConfigOverrideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relative(path) => write!(
                f,
                "{COCKPIT_CONFIG_ENV} must be an absolute path (got `{}`)",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ExplicitConfigOverrideError {}

/// The `COCKPIT_CONFIG` explicit override, when set: it supplies the only
/// `config.json` layer. It is an operator-level choice, so it is never
/// filtered by the ambient workspace-trust policy (sessions and
/// installation-wide policy resolve it identically, whatever trust context
/// the caller runs in), and it is never anchored to a project root even when
/// its path looks like `<root>/.cockpit/config.json`. A relative override is
/// an error before anything else.
pub fn explicit_config_override() -> Result<Option<PathBuf>, ExplicitConfigOverrideError> {
    let Some(path) = std::env::var_os(COCKPIT_CONFIG_ENV).filter(|path| !path.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(ExplicitConfigOverrideError::Relative(path));
    }
    Ok(Some(path))
}

/// The `config.json` layers of installation-wide (daemon-global) policy:
/// the `COCKPIT_CONFIG` explicit override exactly as sessions select it,
/// otherwise the canonical global layer. No project root takes part and
/// every returned path is absolute.
pub fn installation_config_file_paths() -> anyhow::Result<Vec<PathBuf>> {
    if let Some(path) = explicit_config_override()? {
        return Ok(vec![path]);
    }
    Ok(vec![global_config_file()?])
}

/// The one write gate for a durable configuration file: a `config.json`
/// layer, a file beside it (`providers/<id>.json`, `mcp.json`, the
/// effective-default journal), judged under the ambient workspace-trust
/// policy.
///
/// Readability is not writability: the `COCKPIT_CONFIG` override is loaded
/// regardless of trust, but a file that passes through a project `.cockpit`
/// directory — judged on every location the path traverses, its spelled
/// entries as well as their resolved targets
/// ([`crate::config::trust::config_file_write_decision`]) — is written only
/// while that project is trusted. The typed configuration documents
/// (`ExtendedConfigDoc`, `providers::ConfigDoc`) enforce this inside every
/// mutating method, so no caller can write one without passing it; target
/// selectors report a refusal as [`ConfigWriteRefused`], never as absence.
pub fn config_layer_write_allowed(path: &Path) -> bool {
    authorize_config_layer_write(path).is_ok()
}

/// [`config_layer_write_allowed`] against an explicit policy, for writers
/// that captured their authority's policy instead of reading the ambient one.
pub fn config_layer_write_allowed_for_policy(
    path: &Path,
    policy: Option<&crate::config::trust::WorkspaceTrustPolicy>,
) -> bool {
    authorize_config_layer_write_for_policy(path, policy).is_ok()
}

/// [`config_layer_write_allowed`] with the refusal as a typed error.
pub fn authorize_config_layer_write(path: &Path) -> Result<(), ConfigWriteRefused> {
    authorize_config_layer_write_for_policy(path, crate::config::trust::runtime_policy().as_ref())
}

/// [`config_layer_write_allowed_for_policy`] with the refusal as a typed error.
pub fn authorize_config_layer_write_for_policy(
    path: &Path,
    policy: Option<&crate::config::trust::WorkspaceTrustPolicy>,
) -> Result<(), ConfigWriteRefused> {
    crate::config::trust::config_file_write_decision(path, policy).map_err(|reason| {
        ConfigWriteRefused {
            path: path.to_path_buf(),
            reason,
        }
    })
}

/// The gate the typed configuration documents run inside every mutating
/// method, before the mutation lock (whose acquisition creates the parent
/// directory) and again before each file is committed.
pub(crate) fn authorize_config_file_write(path: &Path) -> anyhow::Result<()> {
    authorize_config_layer_write(path).map_err(anyhow::Error::from)
}

/// A configuration write refused by workspace trust. Target selectors return
/// this instead of `None`, so a refusal can never be mistaken for "no layer
/// exists yet" and turned into a write to some other layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWriteRefused {
    pub path: PathBuf,
    pub reason: crate::config::trust::ConfigWriteRefusal,
}

impl std::fmt::Display for ConfigWriteRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing to write {}: {}",
            self.path.display(),
            self.reason
        )
    }
}

impl std::error::Error for ConfigWriteRefused {}

/// Why a runtime configuration mutation has no target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWriteTargetError {
    /// Workspace trust refuses the only layer the mutation may target.
    Refused(ConfigWriteRefused),
    /// A workspace-bound mutation ran with no workspace-trust decision in
    /// force, so no workspace layer can be chosen.
    NoWorkspacePolicy,
    /// The provider id cannot name a provider file.
    InvalidProviderId(String),
    /// The explicit override or the per-directory layer could not be resolved.
    Unresolved(String),
}

impl std::fmt::Display for ConfigWriteTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(refused) => refused.fmt(f),
            Self::NoWorkspacePolicy => f.write_str(
                "no workspace-trust decision is in force, so no workspace config layer can be written",
            ),
            Self::InvalidProviderId(id) => write!(f, "`{id}` is not a valid provider id"),
            Self::Unresolved(reason) => write!(f, "no config layer can be resolved: {reason}"),
        }
    }
}

impl std::error::Error for ConfigWriteTargetError {}

impl From<ConfigWriteRefused> for ConfigWriteTargetError {
    fn from(refused: ConfigWriteRefused) -> Self {
        Self::Refused(refused)
    }
}

/// The explicit `COCKPIT_CONFIG` override as a write target: `Ok(None)` when
/// no override is set, the override when workspace trust allows writing it,
/// otherwise the refusal. The override is the only layer load reads, so a
/// refused override never falls back to any other layer.
fn explicit_override_write_target() -> Result<Option<PathBuf>, ConfigWriteTargetError> {
    let Some(path) = explicit_config_override()
        .map_err(|error| ConfigWriteTargetError::Unresolved(error.to_string()))?
    else {
        return Ok(None);
    };
    authorize_config_layer_write(&path)?;
    Ok(Some(path))
}

/// `config.json` target for a **workspace-bound** mutation (per-project
/// sandbox intent, the "approve for this project" gitignore allowlist,
/// review defaults, policy import): the layer that load reads for `cwd` and
/// that belongs to this workspace, never the user-global layer.
///
/// 1. `COCKPIT_CONFIG`, the only layer load reads, when trust allows writing
///    it; a refused override is an error (never a fallback).
/// 2. The nearest discovered project layer (discovery is trust-gated).
/// 3. The existing machine-local layer for `cwd`.
/// 4. A scaffold: the project `<cwd>/.cockpit` under `Trust`, otherwise the
///    machine-local layer for `cwd` (an ignored project's `.cockpit` is never
///    scaffolded).
///
/// With no workspace-trust policy in force there is no workspace to bind to
/// and the mutation is refused. The returned target has passed the write gate.
pub fn workspace_config_write_target(cwd: &Path) -> Result<PathBuf, ConfigWriteTargetError> {
    if let Some(path) = explicit_override_write_target()? {
        return Ok(path);
    }
    let Some(policy) = crate::config::trust::runtime_policy() else {
        return Err(ConfigWriteTargetError::NoWorkspacePolicy);
    };
    let dirs = discover_config_dirs(cwd);
    let target = if let Some(project) = dirs.iter().find(|d| d.kind == ConfigDirKind::Project) {
        project.path.join(CONFIG_FILE)
    } else if let Some(local) = dirs.iter().find(|d| d.kind == ConfigDirKind::MachineLocal) {
        local.path.join(CONFIG_FILE)
    } else if policy.mode == crate::db::workspace_trust::WorkspaceTrustMode::Trust {
        cwd.join(".cockpit").join(CONFIG_FILE)
    } else {
        local_config_dir_for(cwd)
            .map_err(|error| ConfigWriteTargetError::Unresolved(format!("{error:#}")))?
            .join(CONFIG_FILE)
    };
    authorize_config_layer_write_for_policy(&target, Some(&policy))?;
    Ok(target)
}

/// `providers/<provider-id>.json` write target for a runtime mutation that
/// belongs to `provider_id`: the most-specific layer that already defines the
/// provider, else the most-specific discovered layer, else the canonical
/// global layer — even when that directory does not yet exist. User-level
/// config therefore never returns `None` for a valid provider id unless an
/// explicit `COCKPIT_CONFIG` override forbids the write. `COCKPIT_CONFIG` is
/// a single-layer override, so provider files live beside that exact file.
pub fn config_write_target_for_provider(
    cwd: &Path,
    provider_id: &str,
) -> Result<PathBuf, ConfigWriteTargetError> {
    if crate::config::providers::validate_provider_id_for_filename(provider_id).is_err() {
        return Err(ConfigWriteTargetError::InvalidProviderId(
            provider_id.to_string(),
        ));
    }
    if let Some(path) = explicit_override_write_target()? {
        return crate::config::providers::provider_file_path_for_config(&path, provider_id)
            .map_err(|error| ConfigWriteTargetError::Unresolved(format!("{error:#}")));
    }

    // Most-specific first: `target` is the nearest applicable layer (the
    // nearest project, never an outer sibling-shared one), and `defining` is
    // the nearest layer that already holds the provider file — the one load
    // precedence actually reads. Prefer an existing definition, else fall
    // back to the nearest writable layer, else the always-writable global
    // home (independent of `is_dir()` discovery).
    let mut target = None;
    let mut defining = None;
    for dir in config_dirs_most_specific_first(cwd) {
        let path = crate::config::providers::provider_file_path_for_dir(&dir.path, provider_id)
            .map_err(|_| ConfigWriteTargetError::InvalidProviderId(provider_id.to_string()))?;
        if target.is_none() {
            target = Some(path.clone());
        }
        if defining.is_none() && path.exists() {
            defining = Some(path);
        }
    }
    let path = defining
        .or(target)
        .or_else(|| global_provider_write_target(provider_id))
        .ok_or_else(|| {
            ConfigWriteTargetError::Unresolved("the global config directory is unknown".into())
        })?;
    authorize_config_layer_write(&path)?;
    Ok(path)
}

/// Most-specific *discovered* runtime `config.json` write target.
///
/// Honors `COCKPIT_CONFIG` as the sole layer. `Ok(None)` means no config
/// directory currently exists on disk (and no override is set); a refused
/// override is an error, never absence. The returned target has passed the
/// write gate.
pub fn most_specific_existing_config_write_target(
    cwd: &Path,
) -> Result<Option<PathBuf>, ConfigWriteTargetError> {
    if let Some(path) = explicit_override_write_target()? {
        return Ok(Some(path));
    }

    // Nearest project layer wins (consistent with load precedence and the
    // gitignore write path); when no project layer applies, fall back to the
    // most-specific non-project layer that already exists on disk.
    let dirs = discover_config_dirs(cwd);
    let Some(path) = dirs
        .iter()
        .find(|d| d.kind == ConfigDirKind::Project)
        .or_else(|| dirs.last())
        .map(|d| d.path.join(CONFIG_FILE))
    else {
        return Ok(None);
    };
    authorize_config_layer_write(&path)?;
    Ok(Some(path))
}

/// Most-specific runtime `config.json` write target for **user-level**
/// mutations that are not bound to a trusted workspace layer. Honors
/// `COCKPIT_CONFIG` as the sole layer. When no discovered layer applies,
/// falls back to the canonical global layer even when that directory does
/// not yet exist.
///
/// Workspace-bound mutations must use [`workspace_config_write_target`].
pub fn most_specific_config_write_target(cwd: &Path) -> Result<PathBuf, ConfigWriteTargetError> {
    if let Some(path) = most_specific_existing_config_write_target(cwd)? {
        return Ok(path);
    }
    let path = global_config_file()
        .map_err(|error| ConfigWriteTargetError::Unresolved(format!("{error:#}")))?;
    authorize_config_layer_write(&path)?;
    Ok(path)
}

/// Effective `mcp.json` files for runtime loading, ordered from least
/// specific to most specific. Unlike [`config_file_paths_for_load`], this
/// always uses normal layered discovery and is never redirected by
/// [`COCKPIT_CONFIG_ENV`].
pub fn mcp_file_paths_for_load(cwd: &Path) -> Vec<PathBuf> {
    mcp_file_layers_for_load(cwd)
        .into_iter()
        .map(|(_, path)| path)
        .collect()
}

/// Same order as [`mcp_file_paths_for_load`], with each path tagged by the
/// config-dir kind that produced it. Home / machine-local layers are global;
/// project `.cockpit/` layers are workspace.
pub fn mcp_file_layers_for_load(cwd: &Path) -> Vec<(ConfigDirKind, PathBuf)> {
    file_layers_for_load(cwd, MCP_FILE)
}

/// Explicit MCP write target for a client-chosen scope. `global` is the
/// home XDG layer and is returned even when that directory does not yet
/// exist; `workspace` is the nearest project `.cockpit/mcp.json`.
pub fn mcp_write_target_for_scope(cwd: &Path, scope: &str) -> Option<PathBuf> {
    match scope {
        "global" => global_config_dir().ok().map(|dir| dir.join(MCP_FILE)),
        "workspace" => discover_config_dirs(cwd)
            .into_iter()
            .rev()
            .find(|dir| dir.kind == ConfigDirKind::Project)
            .map(|dir| dir.path.join(MCP_FILE)),
        _ => None,
    }
}

fn file_paths_for_load(cwd: &Path, filename: &str) -> Vec<PathBuf> {
    file_layers_for_load(cwd, filename)
        .into_iter()
        .map(|(_, path)| path)
        .collect()
}

fn file_layers_for_load(cwd: &Path, filename: &str) -> Vec<(ConfigDirKind, PathBuf)> {
    let mut home_and_local = Vec::new();
    let mut project = Vec::new();
    for dir in discover_config_dirs(cwd) {
        match dir.kind {
            ConfigDirKind::Project => project.push((dir.kind, dir.path.join(filename))),
            ConfigDirKind::HomeXdg | ConfigDirKind::MachineLocal => {
                home_and_local.push((dir.kind, dir.path.join(filename)));
            }
        }
    }
    project.reverse();
    home_and_local.extend(project);
    home_and_local
}

/// [`discover_config_dirs`] reordered most-specific first: the nearest
/// project layer, then any outer project layers, then machine-local and home.
/// This is load precedence reversed, so `first()` is the layer a runtime
/// mutation must target to actually take effect (and the layer whose
/// "approve for this project" must not leak to sibling projects). Mirrors the
/// nearest-project selection used by the gitignore write path
/// (`nearest_project_config_path`): the deepest ancestor that already holds a
/// `.cockpit/` project layer wins.
pub fn config_dirs_most_specific_first(cwd: &Path) -> Vec<ConfigDir> {
    let mut project = Vec::new();
    let mut home_and_local = Vec::new();
    for dir in discover_config_dirs(cwd) {
        match dir.kind {
            ConfigDirKind::Project => project.push(dir),
            ConfigDirKind::HomeXdg | ConfigDirKind::MachineLocal => {
                home_and_local.push(dir);
            }
        }
    }
    // `project` is already nearest-first; `home_and_local` is
    // `home_and_local` is home-XDG → machine-local, so reverse it to
    // machine-local → home (most specific first) before appending.
    home_and_local.reverse();
    project.extend(home_and_local);
    project
}

/// Default places `/settings` will offer when no config exists yet.
pub fn creatable_config_dirs() -> Vec<ConfigDir> {
    global_config_dir()
        .ok()
        .map(|path| {
            vec![ConfigDir {
                kind: ConfigDirKind::HomeXdg,
                path,
            }]
        })
        .unwrap_or_default()
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
    ensure_config_layer_dir(dir).map_err(|error| std::io::Error::other(error.to_string()))?;
    let config_path = dir.join(CONFIG_FILE);
    if !config_path.exists() {
        let default = "{\n  \"tools\": {}\n}\n";
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

#[cfg(any(test, feature = "test-support"))]
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

    #[test]
    fn global_config_dir_is_created_writable_and_ignores_workspace_trust() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let root = crate::config::trust::resolve_trust_root(&workspace).unwrap();
        crate::config::trust::set_runtime_policy(
            root,
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        );

        let global = ensure_global_config_dir().unwrap();
        assert_eq!(global, tmp.path().join("home/.config/cockpit"));
        assert!(global.is_dir());
        assert_eq!(
            discover_config_dirs(&workspace)
                .into_iter()
                .find(|dir| dir.kind == ConfigDirKind::HomeXdg)
                .map(|dir| dir.path),
            Some(global),
            "workspace trust must not hide the user-owned global config layer"
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn mcp_file_paths_match_config_file_layer_order_with_filename_swapped() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let _trust = crate::config::trust::enter_workspace_trust_policy(
            crate::config::trust::WorkspaceTrustPolicy {
                root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
                mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            },
        );
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
        let mcp_layers = mcp_file_layers_for_load(&child);
        assert_eq!(
            mcp_layers
                .iter()
                .map(|(kind, path)| (*kind, path.clone()))
                .collect::<Vec<_>>(),
            vec![
                (
                    ConfigDirKind::HomeXdg,
                    home.join(".config/cockpit/mcp.json")
                ),
                (ConfigDirKind::Project, parent.join(".cockpit/mcp.json")),
                (ConfigDirKind::Project, child.join(".cockpit/mcp.json")),
            ]
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
            vec![home.join(".config/cockpit/config.json")]
        );
        assert_eq!(
            mcp_file_paths_for_load(&repo),
            vec![home.join(".config/cockpit/mcp.json")]
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

    /// `COCKPIT_CONFIG` is an operator-level choice: it is loaded exactly as
    /// named whatever workspace-trust policy is in scope (sessions and
    /// installation-wide policy must resolve it identically), while writes
    /// into a conventional project path remain trust-gated.
    #[test]
    fn cockpit_config_env_inside_ignored_project_is_loaded_but_not_written() {
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

        assert_eq!(config_file_paths_for_load(&repo), vec![config.clone()]);
        assert_eq!(
            installation_config_file_paths().unwrap(),
            vec![config.clone()]
        );
        assert!(most_specific_config_write_target(&repo).ok().is_none());
        assert!(config_write_target_for_provider(&repo, "p").ok().is_none());
        assert!(!config_layer_write_allowed(&config));
        // The effective-default writer selects the same layer attach reads,
        // and refuses it rather than falling back.
        let refused =
            crate::config::effective_default::resolve_effective_default_write_target(&repo)
                .expect_err("the ignored project override is not a default-model write target");
        assert_eq!(refused.diagnostic_code, "effective_default_trust_denied");
        // The same path under an explicit Trust policy is writable, and the
        // global layer never needs trust.
        let trusted = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&repo).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        assert!(config_layer_write_allowed_for_policy(
            &config,
            Some(&trusted)
        ));
        assert!(!config_layer_write_allowed_for_policy(&config, None));
        assert!(config_layer_write_allowed(&global_config_file().unwrap()));
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// Trust a nested project (`/repo` + `/repo/app`, both with `.cockpit/`)
    /// so both project layers are discovered. Returns `(home, root, app)`.
    fn nested_project_layers(tmp: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
        crate::config::trust::clear_runtime_policy_for_tests();
        let home = tmp.path().join("home");
        let root = tmp.path().join("repo");
        let app = root.join("app");
        std::fs::create_dir_all(home.join(".config/cockpit")).unwrap();
        std::fs::create_dir_all(root.join(".cockpit")).unwrap();
        std::fs::create_dir_all(app.join(".cockpit")).unwrap();
        (home, root, app)
    }

    /// CFG-8 regression: a non-entity config mutation writes to the NEAREST
    /// project layer, not the outermost. With `/repo/.cockpit` and
    /// `/repo/app/.cockpit`, writing from `/repo/app` must land on
    /// `/repo/app/.cockpit/config.json` — otherwise the write is silently
    /// masked on load by the nearer layer. Fails against the pre-fix
    /// `next_back()` (outermost) logic.
    #[test]
    fn most_specific_write_target_prefers_nearest_project_not_outermost() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        let (_home, root, app) = nested_project_layers(&tmp);
        let _trust = crate::config::trust::enter_workspace_trust_policy(
            crate::config::trust::WorkspaceTrustPolicy {
                root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
                mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            },
        );

        assert_eq!(
            most_specific_config_write_target(&app).ok(),
            Some(app.join(".cockpit").join(CONFIG_FILE)),
            "write target must be the nearest project layer"
        );
        assert_ne!(
            most_specific_config_write_target(&app).ok(),
            Some(root.join(".cockpit").join(CONFIG_FILE)),
            "must not resolve to the masked outermost project layer"
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// CFG-8 regression for provider files: with no existing provider file,
    /// the write target is the nearest project's `providers/<id>.json`, not
    /// the outermost. The outermost target is the "approve for this project
    /// leaks to sibling projects" bug. Fails against the pre-fix last-wins loop.
    #[test]
    fn provider_write_target_prefers_nearest_project_not_outermost() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        let (_home, root, app) = nested_project_layers(&tmp);
        let _trust = crate::config::trust::enter_workspace_trust_policy(
            crate::config::trust::WorkspaceTrustPolicy {
                root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
                mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            },
        );

        let nearest =
            crate::config::providers::provider_file_path_for_dir(&app.join(".cockpit"), "default")
                .ok();
        let outer =
            crate::config::providers::provider_file_path_for_dir(&root.join(".cockpit"), "default")
                .ok();
        assert_eq!(
            config_write_target_for_provider(&app, "default").ok(),
            nearest
        );
        assert_ne!(
            config_write_target_for_provider(&app, "default").ok(),
            outer
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// An existing provider definition is preferred, but resolved at the
    /// most-specific (nearest) layer that holds it — the file load precedence
    /// reads. Outer-only definition stays outer (unchanged); once the nearest
    /// layer also defines it, the mutation moves inward. The second assertion
    /// fails against the pre-fix last-wins `defining` (which stayed outer).
    #[test]
    fn provider_write_target_prefers_nearest_existing_definition() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        let (_home, root, app) = nested_project_layers(&tmp);
        let _trust = crate::config::trust::enter_workspace_trust_policy(
            crate::config::trust::WorkspaceTrustPolicy {
                root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
                mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            },
        );

        let outer =
            crate::config::providers::provider_file_path_for_dir(&root.join(".cockpit"), "default")
                .unwrap();
        let inner =
            crate::config::providers::provider_file_path_for_dir(&app.join(".cockpit"), "default")
                .unwrap();

        std::fs::create_dir_all(outer.parent().unwrap()).unwrap();
        std::fs::write(&outer, "{}").unwrap();
        assert_eq!(
            config_write_target_for_provider(&app, "default").ok(),
            Some(outer.clone()),
            "only the outer layer defines it, so that is the definition"
        );

        std::fs::create_dir_all(inner.parent().unwrap()).unwrap();
        std::fs::write(&inner, "{}").unwrap();
        assert_eq!(
            config_write_target_for_provider(&app, "default").ok(),
            Some(inner),
            "nearest layer now defines it, so the mutation must target it"
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// The `COCKPIT_CONFIG` single-layer override still wins over discovered
    /// project layers for both write-target functions.
    #[test]
    fn cockpit_config_override_wins_for_write_targets() {
        let tmp = TempDir::new().unwrap();
        let env = test_support::IsolatedCockpitHome::new(tmp.path());
        let (_home, _root, app) = nested_project_layers(&tmp);
        let _trust = crate::config::trust::enter_workspace_trust_policy(
            crate::config::trust::WorkspaceTrustPolicy {
                root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
                mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            },
        );

        // A non-`.cockpit` parent is always write-allowed, isolating the
        // override branch from workspace-trust concerns.
        let override_cfg = tmp.path().join("explicit-config.json");
        std::fs::write(&override_cfg, "{}").unwrap();
        let _ovr = env.override_cockpit_config(&override_cfg);

        assert_eq!(
            most_specific_config_write_target(&app).ok(),
            Some(override_cfg.clone()),
            "override wins over the nearest project layer"
        );
        assert_eq!(
            config_write_target_for_provider(&app, "default").ok(),
            crate::config::providers::provider_file_path_for_config(&override_cfg, "default").ok(),
            "provider file lives beside the exact override config"
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// When no project layer applies, the fallback is the canonical global
    /// layer. A legacy home dotfile must never take precedence over it.
    #[test]
    fn no_project_fallback_targets_canonical_global_layer() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(home.join(".config/cockpit")).unwrap();
        std::fs::create_dir_all(home.join(".cockpit")).unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();

        assert_eq!(
            most_specific_config_write_target(&work).ok(),
            Some(home.join(".config/cockpit").join(CONFIG_FILE)),
            "no project layer → canonical global layer; legacy home dotfile is ignored"
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// User-level write targets must resolve to the canonical global layer
    /// even when that directory does not exist yet. Read-side discovery keeps
    /// its `is_dir()` gate, so a fresh install still discovers nothing.
    #[test]
    fn user_level_write_targets_do_not_require_the_global_dir_to_exist() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let global = tmp.path().join("home/.config/cockpit");
        assert!(
            !global.is_dir(),
            "fresh-install fixture must not pre-create the global layer"
        );

        assert_eq!(
            config_write_target_for_provider(&work, "default").ok(),
            crate::config::providers::provider_file_path_for_dir(&global, "default").ok(),
            "provider create/first-write falls back to the global layer path"
        );
        assert_eq!(
            most_specific_existing_config_write_target(&work).unwrap(),
            None,
            "workspace-bound mutations must see no discovered layer on a fresh install"
        );
        assert_eq!(
            most_specific_config_write_target(&work).ok(),
            Some(global.join(CONFIG_FILE)),
            "user-level config.json mutations fall back to the global layer path"
        );
        assert_eq!(
            mcp_write_target_for_scope(&work, "global"),
            Some(global.join(MCP_FILE)),
            "MCP global scope is the global layer path even when it is absent"
        );
        assert!(
            discover_config_dirs(&work).is_empty(),
            "read-side discovery must still require the global dir to exist"
        );
        assert!(
            is_global_config_dir(&global).unwrap(),
            "logical compare must treat the missing global dir as the global root"
        );
        assert!(
            !is_global_config_dir(&work).unwrap(),
            "a workspace path is not the global config root"
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// File-write helpers must not scaffold a missing global layer. Only
    /// [`ensure_global_config_dir`] may create it.
    #[test]
    fn file_write_helpers_do_not_create_a_missing_global_config_dir() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let global = tmp.path().join("home/.config/cockpit");
        let config_file = global.join(CONFIG_FILE);
        assert!(
            !global.is_dir(),
            "fresh-install fixture must not pre-create the global layer"
        );
        assert!(path_is_under_missing_global_config_dir(&global));
        assert!(path_is_under_missing_global_config_dir(&config_file));

        let error = crate::config::files::ensure_config_parent_dir(&config_file).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ephemeral daemons cannot create the global Cockpit config directory"),
            "missing global layer must fail closed: {error:#}"
        );
        assert!(
            !global.is_dir(),
            "ensure_config_parent_dir must not create the global config directory"
        );

        let created = ensure_global_config_dir().unwrap();
        assert_eq!(created, global);
        assert!(global.is_dir());
        crate::config::files::ensure_config_parent_dir(&config_file).unwrap();
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn side_effect_mkdir_refuses_a_missing_global_config_dir() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let global = tmp.path().join("home/.config/cockpit");
        let nested = global.join("providers");
        let sandbox = global.join("sandbox");
        assert!(!global.is_dir());

        let error = create_dir_all_except_missing_global(&global).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ephemeral daemons cannot create the global Cockpit config directory"),
            "missing global layer must fail closed: {error:#}"
        );
        let nested_error = create_dir_all_except_missing_global(&nested).unwrap_err();
        assert!(
            nested_error
                .to_string()
                .contains("ephemeral daemons cannot create the global Cockpit config directory"),
            "a nested path must not scaffold the missing global layer: {nested_error:#}"
        );
        let sandbox_error = create_dir_all_except_missing_global(&sandbox).unwrap_err();
        assert!(
            sandbox_error
                .to_string()
                .contains("ephemeral daemons cannot create the global Cockpit config directory"),
            "sandbox materialization must not scaffold the missing global layer: {sandbox_error:#}"
        );
        assert!(
            !global.is_dir(),
            "create_dir_all_except_missing_global must not create the global config directory"
        );

        let other = tmp.path().join("elsewhere");
        create_dir_all_except_missing_global(&other).unwrap();
        assert!(other.is_dir(), "non-global mkdir must still succeed");
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn explicit_scaffold_creates_the_missing_global_layer_through_the_funnel() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let global = tmp.path().join("home/.config/cockpit");
        assert!(!global.is_dir());

        ensure_config_layer_dir(&global).unwrap();
        assert!(global.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&global).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o700,
                "authorized global-layer create must apply owner-only permissions"
            );
        }

        let project = tmp.path().join("workspace/.cockpit");
        ensure_config_layer_dir(&project).unwrap();
        assert!(project.is_dir());
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// B1: workspace trust judges the entry location of every component as
    /// well as its resolved target. A `.cockpit` that is itself a symlink —
    /// to a directory inside the repository or outside it — is still the
    /// project's `.cockpit` layer: under IgnoreConfig it is neither loaded
    /// nor writable (nor is any file beneath it), whatever spelling of the
    /// workspace the caller uses. Under Trust it loads and is writable.
    #[cfg(unix)]
    mod symlinked_project_layer {
        use super::*;
        use crate::db::workspace_trust::WorkspaceTrustMode;

        struct Fixture {
            _tmp: TempDir,
            _env: test_support::IsolatedCockpitHome,
            repo: PathBuf,
            base: PathBuf,
        }

        /// `<base>/repo` with `.cockpit -> <target>` where `target` is
        /// `in_repo` ? `<repo>/conf` : `<base>/outside/conf`, holding a
        /// config.json that disables redaction.
        fn fixture(in_repo: bool) -> Fixture {
            let tmp = TempDir::new().unwrap();
            let env = test_support::IsolatedCockpitHome::new(tmp.path());
            crate::config::trust::clear_runtime_policy_for_tests();
            let base = tmp.path().canonicalize().unwrap();
            let repo = base.join("repo");
            let target = if in_repo {
                repo.join("conf")
            } else {
                base.join("outside/conf")
            };
            std::fs::create_dir_all(&repo).unwrap();
            std::fs::create_dir_all(target.join("providers")).unwrap();
            std::fs::write(target.join(CONFIG_FILE), r#"{"redact":{"enabled":false}}"#).unwrap();
            std::os::unix::fs::symlink(&target, repo.join(".cockpit")).unwrap();
            Fixture {
                _tmp: tmp,
                _env: env,
                repo,
                base,
            }
        }

        fn set_policy(repo: &Path, mode: WorkspaceTrustMode) {
            let root = crate::config::trust::resolve_trust_root(repo).unwrap();
            crate::config::trust::set_runtime_policy(root, mode);
        }

        fn assert_ignored(cwd: &Path, cockpit: &Path) {
            assert!(
                !crate::config::trust::project_config_allowed(cockpit),
                "a symlinked .cockpit must be classified as the project layer: {}",
                cockpit.display()
            );
            assert!(!config_layer_write_allowed(&cockpit.join(CONFIG_FILE)));
            assert!(!config_layer_write_allowed(
                &cockpit.join("providers").join("p.json")
            ));
            assert!(
                !config_file_paths_for_load(cwd)
                    .iter()
                    .any(|path| path.starts_with(cockpit) || path.ends_with("conf/config.json")),
                "the ignored project's layer must not load: {:?}",
                config_file_paths_for_load(cwd)
            );
            assert!(
                matches!(
                    authorize_config_layer_write(&cockpit.join(CONFIG_FILE)),
                    Err(ConfigWriteRefused {
                        reason: crate::config::trust::ConfigWriteRefusal::UntrustedProjectLayer,
                        ..
                    })
                ),
                "the refusal is typed"
            );
        }

        #[test]
        fn in_repo_link_is_ignored_under_ignore_config() {
            let f = fixture(true);
            set_policy(&f.repo, WorkspaceTrustMode::IgnoreConfig);
            assert_ignored(&f.repo, &f.repo.join(".cockpit"));
            crate::config::trust::clear_runtime_policy_for_tests();
        }

        #[test]
        fn out_of_repo_link_is_ignored_under_ignore_config() {
            let f = fixture(false);
            set_policy(&f.repo, WorkspaceTrustMode::IgnoreConfig);
            assert_ignored(&f.repo, &f.repo.join(".cockpit"));
            crate::config::trust::clear_runtime_policy_for_tests();
        }

        /// The caller spells the workspace through a symlinked checkout while
        /// the trust root is canonical: the alias is canonicalized before the
        /// `.cockpit` entry is judged.
        #[test]
        fn alias_workspace_spelling_with_linked_cockpit_is_ignored() {
            let f = fixture(false);
            let alias = f.base.join("alias");
            std::os::unix::fs::symlink(&f.repo, &alias).unwrap();
            set_policy(&f.repo, WorkspaceTrustMode::IgnoreConfig);
            assert_ignored(&alias, &alias.join(".cockpit"));
            crate::config::trust::clear_runtime_policy_for_tests();
        }

        /// A relative spelling is refused instead of being resolved against
        /// the process working directory.
        #[test]
        fn relative_spelling_is_refused() {
            let f = fixture(true);
            set_policy(&f.repo, WorkspaceTrustMode::IgnoreConfig);
            let relative = Path::new("repo/.cockpit");
            assert!(!crate::config::trust::project_config_allowed(relative));
            assert!(matches!(
                authorize_config_layer_write(&relative.join(CONFIG_FILE)),
                Err(ConfigWriteRefused {
                    reason: crate::config::trust::ConfigWriteRefusal::Unclassifiable,
                    ..
                })
            ));
            crate::config::trust::clear_runtime_policy_for_tests();
        }

        /// Inverse: under Trust the linked layer is the project's layer and
        /// loads and is writable.
        #[test]
        fn trusted_linked_layer_loads_and_is_writable() {
            let f = fixture(true);
            set_policy(&f.repo, WorkspaceTrustMode::Trust);
            let cockpit = f.repo.join(".cockpit");
            assert!(crate::config::trust::project_config_allowed(&cockpit));
            assert!(config_layer_write_allowed(&cockpit.join(CONFIG_FILE)));
            assert!(
                config_file_paths_for_load(&f.repo).contains(&cockpit.join(CONFIG_FILE)),
                "{:?}",
                config_file_paths_for_load(&f.repo)
            );
            crate::config::trust::clear_runtime_policy_for_tests();
        }

        /// The sibling predicate: an in-repo entry linked outside the root
        /// (a `.claude/skills` or agent dir) is still repository content and
        /// is blocked; a directory genuinely outside the root is not.
        #[test]
        fn path_blocked_judges_in_repo_links_by_their_entry() {
            let f = fixture(true);
            let outside = f.base.join("outside-skills");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::create_dir_all(f.repo.join(".claude")).unwrap();
            std::os::unix::fs::symlink(&outside, f.repo.join(".claude/skills")).unwrap();
            set_policy(&f.repo, WorkspaceTrustMode::IgnoreConfig);
            assert!(crate::config::trust::path_blocked_by_workspace_trust(
                &f.repo.join(".claude/skills")
            ));
            assert!(!crate::config::trust::path_blocked_by_workspace_trust(
                &outside
            ));
            // A link from outside into the repository is judged by its target.
            let inbound = f.base.join("inbound");
            std::os::unix::fs::symlink(f.repo.join("conf"), &inbound).unwrap();
            assert!(crate::config::trust::path_blocked_by_workspace_trust(
                &inbound
            ));
            crate::config::trust::clear_runtime_policy_for_tests();
        }
    }

    /// A `.cockpit` below the trust root (a subdirectory of a git repository
    /// the session's cwd lies in) is repository content: under IgnoreConfig
    /// it neither loads nor is writable, exactly like `<root>/.cockpit`.
    #[test]
    fn nested_project_layer_below_git_root_is_ignored() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let repo = tmp.path().canonicalize().unwrap().join("repo");
        let sub = repo.join("sub");
        std::fs::create_dir_all(sub.join(".cockpit")).unwrap();
        std::fs::write(sub.join(".cockpit").join(CONFIG_FILE), "{}").unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .expect("git init");
        assert!(status.success());
        let root = crate::config::trust::resolve_trust_root(&sub).unwrap();
        assert_eq!(root.root, repo);
        crate::config::trust::set_runtime_policy(
            root.clone(),
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        );
        assert!(
            config_file_paths_for_load(&sub).is_empty(),
            "{:?}",
            config_file_paths_for_load(&sub)
        );
        assert!(!config_layer_write_allowed(
            &sub.join(".cockpit").join(CONFIG_FILE)
        ));
        crate::config::trust::set_runtime_policy(
            root,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        );
        assert_eq!(
            config_file_paths_for_load(&sub),
            vec![sub.join(".cockpit").join(CONFIG_FILE)]
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    /// B2: a workspace-bound mutation never writes the user-global layer,
    /// never scaffolds an ignored project's `.cockpit`, and reports a
    /// refused override as a typed refusal instead of choosing another
    /// layer.
    mod workspace_write_target {
        use super::*;
        use crate::db::workspace_trust::WorkspaceTrustMode;

        fn setup() -> (TempDir, test_support::IsolatedCockpitHome, PathBuf) {
            let tmp = TempDir::new().unwrap();
            let env = test_support::IsolatedCockpitHome::new(tmp.path());
            crate::config::trust::clear_runtime_policy_for_tests();
            let repo = tmp.path().canonicalize().unwrap().join("repo");
            std::fs::create_dir_all(&repo).unwrap();
            // An existing global layer: the old selector fell back to it.
            ensure_global_config_dir().unwrap();
            std::fs::write(global_config_file().unwrap(), "{}").unwrap();
            (tmp, env, repo)
        }

        fn set_policy(repo: &Path, mode: WorkspaceTrustMode) {
            let root = crate::config::trust::resolve_trust_root(repo).unwrap();
            crate::config::trust::set_runtime_policy(root, mode);
        }

        #[test]
        fn ignore_config_targets_machine_local_not_global_or_project() {
            let (_tmp, _env, repo) = setup();
            set_policy(&repo, WorkspaceTrustMode::IgnoreConfig);
            let target = workspace_config_write_target(&repo).unwrap();
            assert_eq!(
                target,
                local_config_dir_for(&repo).unwrap().join(CONFIG_FILE)
            );
            assert!(!repo.join(".cockpit").exists());
            crate::config::trust::clear_runtime_policy_for_tests();
        }

        #[test]
        fn trust_scaffolds_the_project_layer_not_global() {
            let (_tmp, _env, repo) = setup();
            set_policy(&repo, WorkspaceTrustMode::Trust);
            assert_eq!(
                workspace_config_write_target(&repo).unwrap(),
                repo.join(".cockpit").join(CONFIG_FILE)
            );
            crate::config::trust::clear_runtime_policy_for_tests();
        }

        #[test]
        fn refused_override_is_a_typed_refusal_not_a_fallback() {
            let (_tmp, env, repo) = setup();
            let config = repo.join(".cockpit").join(CONFIG_FILE);
            std::fs::create_dir_all(config.parent().unwrap()).unwrap();
            std::fs::write(&config, "{}").unwrap();
            set_policy(&repo, WorkspaceTrustMode::IgnoreConfig);
            let _override = env.override_cockpit_config(&config);
            for result in [
                workspace_config_write_target(&repo),
                most_specific_config_write_target(&repo),
                most_specific_existing_config_write_target(&repo).map(|path| path.unwrap()),
                config_write_target_for_provider(&repo, "p"),
            ] {
                assert!(
                    matches!(result, Err(ConfigWriteTargetError::Refused(_))),
                    "{result:?}"
                );
            }
            crate::config::trust::clear_runtime_policy_for_tests();
        }

        #[test]
        fn no_policy_is_refused() {
            let (_tmp, _env, repo) = setup();
            assert_eq!(
                workspace_config_write_target(&repo),
                Err(ConfigWriteTargetError::NoWorkspacePolicy)
            );
        }
    }

    /// B2: the configuration documents enforce the write gate inside every
    /// mutating method, before the mutation lock (which would create the
    /// layer's directory), so no caller can write an ignored project's layer
    /// whatever target it selected.
    #[test]
    fn config_documents_refuse_an_ignored_project_layer() {
        let tmp = TempDir::new().unwrap();
        let _env = test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let repo = tmp.path().canonicalize().unwrap().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let root = crate::config::trust::resolve_trust_root(&repo).unwrap();
        crate::config::trust::set_runtime_policy(
            root.clone(),
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        );
        let target = repo.join(".cockpit").join(CONFIG_FILE);
        let mut doc = crate::config::extended::ExtendedConfigDoc::load(&target).unwrap();
        let mut cfg = doc.config();
        cfg.gitignore_allow.push("secret/**".into());
        let error = doc.write(&cfg).unwrap_err();
        assert!(
            error.downcast_ref::<ConfigWriteRefused>().is_some(),
            "{error:#}"
        );
        let mut providers = crate::config::providers::ConfigDoc::load(&target).unwrap();
        let layer = providers.providers();
        assert!(providers.write(&layer).is_err());
        assert!(
            !repo.join(".cockpit").exists(),
            "a refused write must not scaffold the ignored project's layer"
        );
        // Inverse: the same writes succeed once the project is trusted.
        crate::config::trust::set_runtime_policy(
            root,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        );
        doc.write(&cfg).unwrap();
        assert!(target.is_file());
        crate::config::trust::clear_runtime_policy_for_tests();
    }
}
