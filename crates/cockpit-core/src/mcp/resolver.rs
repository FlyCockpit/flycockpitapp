//! Source-tagged effective MCP catalog resolver.
//!
//! Tool dispatch used to re-read every `mcp.json` layer on each `mcp` tool
//! call via [`super::config::McpConfig::discover`]. The resolver is built
//! once per agent construction (or test `ToolCtx`), tagged with the layer
//! that defined each server, and refreshed when the underlying files or
//! session config generation change.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use crate::config::dirs::ConfigDirKind;
use crate::mcp::builtin::BUILTIN_SERVER_ID;
use crate::mcp::config::{McpConfig, ServerConfig};

/// Where an MCP server definition was loaded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpScope {
    Global,
    Workspace,
    Agent,
}

impl McpScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Workspace => "workspace",
            Self::Agent => "agent",
        }
    }

    pub fn from_config_dir_kind(kind: ConfigDirKind) -> Self {
        match kind {
            ConfigDirKind::HomeXdg | ConfigDirKind::HomeDot | ConfigDirKind::MachineLocal => {
                Self::Global
            }
            ConfigDirKind::Project => Self::Workspace,
        }
    }

    /// workspace > agent > global
    fn rank(self) -> u8 {
        match self {
            Self::Global => 0,
            Self::Agent => 1,
            Self::Workspace => 2,
        }
    }
}

pub use super::config::DEFAULT_PROFILE;

/// One server in the effective catalog, including the layer that defined it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub name: String,
    pub server: ServerConfig,
    pub source: McpScope,
    /// More-specific scope that hid this same-named server, if any.
    pub shadowed_by: Option<McpScope>,
    /// Credential profile selected for this agent. Stage 1 always uses
    /// [`DEFAULT_PROFILE`].
    pub profile: String,
    /// True when this server is bound to the agent (agent-scope definition
    /// or an explicit `mcpBindings` entry). Agent-bound servers use
    /// agent-dimensioned approval grant keys.
    pub agent_bound: bool,
}

impl CatalogEntry {
    pub fn is_live(&self) -> bool {
        self.shadowed_by.is_none()
    }
}

/// Merged, source-tagged view of every MCP server visible to one agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveCatalog {
    /// Winning (unshadowed) entries keyed by server name.
    pub servers: BTreeMap<String, CatalogEntry>,
    /// Same-named entries hidden by a more-specific scope. Never silent:
    /// a projection can surface `shadowed_by`.
    pub shadowed: Vec<CatalogEntry>,
    /// A layer tried to define the reserved `cockpit` server.
    pub reserved_builtin_rejected: bool,
}

impl EffectiveCatalog {
    pub fn server_names(&self) -> impl Iterator<Item = &str> {
        self.servers.keys().map(String::as_str)
    }

    /// Wrap a pre-merged [`McpConfig`] as workspace-scoped entries. Used by
    /// tests and non-tool callers that already have a merged document.
    pub fn from_mcp_config(cfg: &McpConfig) -> Self {
        Self::from_mcp_config_with_scope(cfg, McpScope::Workspace)
    }

    pub fn from_mcp_config_with_scope(cfg: &McpConfig, source: McpScope) -> Self {
        let mut servers = BTreeMap::new();
        for (name, server) in &cfg.servers {
            servers.insert(
                name.clone(),
                CatalogEntry {
                    name: name.clone(),
                    server: server.clone(),
                    source,
                    shadowed_by: None,
                    profile: DEFAULT_PROFILE.to_string(),
                    agent_bound: source == McpScope::Agent,
                },
            );
        }
        Self {
            servers,
            shadowed: Vec::new(),
            reserved_builtin_rejected: false,
        }
    }

    fn merge_layer(&mut self, layer: McpConfig, source: McpScope) {
        for (name, server) in layer.servers {
            self.merge_entry(CatalogEntry {
                name,
                server,
                source,
                shadowed_by: None,
                profile: DEFAULT_PROFILE.to_string(),
                agent_bound: source == McpScope::Agent,
            });
        }
    }

    fn merge_entry(&mut self, incoming: CatalogEntry) {
        if incoming.name == BUILTIN_SERVER_ID {
            self.reserved_builtin_rejected = true;
            return;
        }
        match self.servers.get(&incoming.name) {
            None => {
                self.servers.insert(incoming.name.clone(), incoming);
            }
            Some(existing) if existing.source.rank() <= incoming.source.rank() => {
                let mut old = existing.clone();
                if old.source != incoming.source {
                    old.shadowed_by = Some(incoming.source);
                    self.shadowed.push(old);
                }
                self.servers.insert(incoming.name.clone(), incoming);
            }
            Some(existing) => {
                let mut shadowed = incoming;
                shadowed.shadowed_by = Some(existing.source);
                self.shadowed.push(shadowed);
            }
        }
    }

    pub fn to_mcp_config(&self) -> McpConfig {
        McpConfig {
            servers: self
                .servers
                .iter()
                .map(|(name, entry)| (name.clone(), entry.server.clone()))
                .collect(),
        }
    }

    pub fn enabled_servers(&self) -> Vec<(&str, &ServerConfig, &CatalogEntry)> {
        self.servers
            .iter()
            .filter(|(name, entry)| {
                entry.is_live() && entry.server.enabled && name.as_str() != BUILTIN_SERVER_ID
            })
            .map(|(name, entry)| (name.as_str(), &entry.server, entry))
            .collect()
    }

    pub fn has_reserved_builtin_server_config(&self) -> bool {
        self.reserved_builtin_rejected
            || self.servers.contains_key(BUILTIN_SERVER_ID)
            || self
                .shadowed
                .iter()
                .any(|entry| entry.name == BUILTIN_SERVER_ID)
    }

    pub fn get(&self, name: &str) -> Option<&CatalogEntry> {
        self.servers.get(name).filter(|entry| entry.is_live())
    }

    fn apply_bindings(&mut self, bindings: &[crate::agents::McpBinding]) {
        if bindings.is_empty() {
            return;
        }
        let wanted: BTreeMap<&str, &str> = bindings
            .iter()
            .map(|binding| (binding.server.as_str(), binding.profile.as_str()))
            .collect();
        let mut next = BTreeMap::new();
        for (name, mut entry) in std::mem::take(&mut self.servers) {
            let Some(profile) = wanted.get(name.as_str()).copied() else {
                continue;
            };
            if entry.server.auth_for_profile(profile).is_none() {
                tracing::warn!(
                    server = %name,
                    profile,
                    "skipping MCP binding that names an unknown credential profile"
                );
                continue;
            }
            entry.profile = profile.to_string();
            entry.agent_bound = true;
            next.insert(name, entry);
        }
        self.servers = next;
    }

    /// Child catalogs keep scope-level servers and intersect agent-bound
    /// servers with the parent's reachable set.
    pub fn intersect_parent_reachable(&mut self, parent_reachable: &BTreeSet<(String, String)>) {
        self.servers.retain(|name, entry| {
            if entry.agent_bound {
                parent_reachable.contains(&(name.clone(), entry.profile.clone()))
            } else {
                true
            }
        });
    }

    pub fn reachable_bindings(&self) -> BTreeSet<(String, String)> {
        self.servers
            .iter()
            .map(|(name, entry)| (name.clone(), entry.profile.clone()))
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LayerFingerprint {
    path: PathBuf,
    /// `(mtime_nanos, len)` when the file exists.
    stamp: Option<(u128, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CatalogFingerprint {
    layers: Vec<LayerFingerprint>,
    config_generation: u64,
}

struct CachedCatalog {
    fingerprint: CatalogFingerprint,
    catalog: Arc<EffectiveCatalog>,
}

/// Read-only resolver that caches the source-tagged catalog and rebuilds
/// when layer files or the session config generation change.
pub struct EffectiveCatalogResolver {
    cwd: PathBuf,
    config_generation: std::sync::atomic::AtomicU64,
    /// Frozen agent-package `mcp.json`. Binding/package changes apply only
    /// when the agent is rebuilt.
    agent_layer: Option<McpConfig>,
    agent_reserved_rejected: bool,
    bindings: Vec<crate::agents::McpBinding>,
    parent_reachable: Option<BTreeSet<(String, String)>>,
    inner: Mutex<Option<CachedCatalog>>,
}

impl EffectiveCatalogResolver {
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            cwd: PathBuf::new(),
            config_generation: std::sync::atomic::AtomicU64::new(0),
            agent_layer: None,
            agent_reserved_rejected: false,
            bindings: Vec::new(),
            parent_reachable: None,
            inner: Mutex::new(Some(CachedCatalog {
                fingerprint: CatalogFingerprint {
                    layers: Vec::new(),
                    config_generation: 0,
                },
                catalog: Arc::new(EffectiveCatalog::default()),
            })),
        })
    }

    pub fn for_cwd(cwd: impl Into<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            cwd: cwd.into(),
            config_generation: std::sync::atomic::AtomicU64::new(0),
            agent_layer: None,
            agent_reserved_rejected: false,
            bindings: Vec::new(),
            parent_reachable: None,
            inner: Mutex::new(None),
        })
    }

    pub fn with_config_generation(cwd: impl Into<PathBuf>, generation: u64) -> Arc<Self> {
        Self::for_agent_layer(cwd, generation, None, false, Vec::new(), None)
    }

    pub fn for_agent(
        cwd: impl Into<PathBuf>,
        generation: u64,
        def: &crate::agents::AgentDef,
    ) -> Arc<Self> {
        let (layer, reserved) = parse_agent_package_mcp(def);
        Self::for_agent_layer(
            cwd,
            generation,
            layer,
            reserved,
            def.mcp_bindings.clone(),
            None,
        )
    }

    /// Admission-time parent-reachable MCP bindings. `None` for a root
    /// catalog that is not intersected with a parent.
    pub fn parent_reachable(&self) -> Option<BTreeSet<(String, String)>> {
        self.parent_reachable.clone()
    }

    pub fn with_parent_reachable(
        self: &Arc<Self>,
        parent: BTreeSet<(String, String)>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cwd: self.cwd.clone(),
            config_generation: std::sync::atomic::AtomicU64::new(
                self.config_generation
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
            agent_layer: self.agent_layer.clone(),
            agent_reserved_rejected: self.agent_reserved_rejected,
            bindings: self.bindings.clone(),
            parent_reachable: Some(parent),
            inner: Mutex::new(None),
        })
    }

    fn for_agent_layer(
        cwd: impl Into<PathBuf>,
        generation: u64,
        agent_layer: Option<McpConfig>,
        agent_reserved_rejected: bool,
        bindings: Vec<crate::agents::McpBinding>,
        parent_reachable: Option<BTreeSet<(String, String)>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cwd: cwd.into(),
            config_generation: std::sync::atomic::AtomicU64::new(generation),
            agent_layer,
            agent_reserved_rejected,
            bindings,
            parent_reachable,
            inner: Mutex::new(None),
        })
    }

    pub fn from_catalog(catalog: EffectiveCatalog) -> Arc<Self> {
        Arc::new(Self {
            cwd: PathBuf::new(),
            config_generation: std::sync::atomic::AtomicU64::new(0),
            agent_layer: None,
            agent_reserved_rejected: catalog.reserved_builtin_rejected,
            bindings: Vec::new(),
            parent_reachable: None,
            inner: Mutex::new(Some(CachedCatalog {
                fingerprint: CatalogFingerprint {
                    layers: Vec::new(),
                    config_generation: 0,
                },
                catalog: Arc::new(catalog),
            })),
        })
    }

    pub fn observe_config_generation(&self, generation: u64) {
        self.config_generation
            .store(generation, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn catalog(&self) -> Arc<EffectiveCatalog> {
        if self.cwd.as_os_str().is_empty() {
            let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(cached) = guard.as_ref() {
                return cached.catalog.clone();
            }
            return Arc::new(EffectiveCatalog::default());
        }
        let fingerprint = self.current_fingerprint();
        {
            let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(cached) = guard.as_ref()
                && cached.fingerprint == fingerprint
            {
                return cached.catalog.clone();
            }
        }
        let catalog = Arc::new(self.rebuild());
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        *guard = Some(CachedCatalog {
            fingerprint,
            catalog: catalog.clone(),
        });
        catalog
    }

    fn current_fingerprint(&self) -> CatalogFingerprint {
        let layers = if self.cwd.as_os_str().is_empty() {
            Vec::new()
        } else {
            crate::config::dirs::mcp_file_layers_for_load(&self.cwd)
                .into_iter()
                .map(|(_, path)| LayerFingerprint {
                    stamp: file_stamp(&path),
                    path,
                })
                .collect()
        };
        CatalogFingerprint {
            layers,
            config_generation: self
                .config_generation
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    fn rebuild(&self) -> EffectiveCatalog {
        if self.cwd.as_os_str().is_empty() {
            return EffectiveCatalog::default();
        }
        let mut catalog =
            discover_effective_catalog_with_agent(&self.cwd, self.agent_layer.as_ref());
        catalog.reserved_builtin_rejected |= self.agent_reserved_rejected;
        catalog.apply_bindings(&self.bindings);
        if let Some(parent) = &self.parent_reachable {
            catalog.intersect_parent_reachable(parent);
        }
        catalog
    }
}

fn parse_agent_package_mcp(def: &crate::agents::AgentDef) -> (Option<McpConfig>, bool) {
    let Some(files) = def.package_files.as_ref() else {
        return (None, false);
    };
    let Some(bytes) = files.get("mcp.json") else {
        return (None, false);
    };
    let raw = match std::str::from_utf8(bytes) {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(
                agent = %def.name,
                %error,
                "skipping non-UTF-8 agent package mcp.json"
            );
            return (None, false);
        }
    };
    match McpConfig::parse(raw) {
        Ok(cfg) => (Some(cfg), false),
        Err(error) if crate::mcp::config::parse_error_is_reserved_builtin(&error) => {
            tracing::warn!(
                agent = %def.name,
                %error,
                "agent package mcp.json cannot redefine the reserved cockpit server"
            );
            (None, true)
        }
        Err(error) => {
            tracing::warn!(
                agent = %def.name,
                %error,
                "skipping malformed agent package mcp.json"
            );
            (None, false)
        }
    }
}

fn file_stamp(path: &Path) -> Option<(u128, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some((mtime, meta.len()))
}

/// Discover global + workspace layers for `cwd` and merge them with
/// precedence workspace > agent > global. Same-named servers keep a
/// `shadowed_by` marker rather than disappearing silently.
pub fn discover_effective_catalog(cwd: &Path) -> EffectiveCatalog {
    discover_effective_catalog_with_agent(cwd, None)
}

pub fn discover_effective_catalog_with_agent(
    cwd: &Path,
    agent_layer: Option<&McpConfig>,
) -> EffectiveCatalog {
    let layers = crate::config::dirs::mcp_file_layers_for_load(cwd);
    discover_effective_catalog_from_layers(&layers, agent_layer)
}

pub fn discover_effective_catalog_from_layers(
    layers: &[(ConfigDirKind, PathBuf)],
    agent_layer: Option<&McpConfig>,
) -> EffectiveCatalog {
    let mut catalog = EffectiveCatalog::default();
    let mut globals = Vec::new();
    let mut workspaces = Vec::new();
    for (kind, path) in layers {
        match McpScope::from_config_dir_kind(*kind) {
            McpScope::Global => globals.push((*kind, path.clone())),
            McpScope::Workspace => workspaces.push((*kind, path.clone())),
            McpScope::Agent => {}
        }
    }
    load_and_merge_paths(&mut catalog, &globals);
    if let Some(agent) = agent_layer {
        catalog.merge_layer(agent.clone(), McpScope::Agent);
    }
    load_and_merge_paths(&mut catalog, &workspaces);
    catalog
}

fn load_and_merge_paths(catalog: &mut EffectiveCatalog, layers: &[(ConfigDirKind, PathBuf)]) {
    for (kind, path) in layers {
        let Ok(raw) = std::fs::read_to_string(path) else {
            continue;
        };
        match McpConfig::parse(&raw) {
            Ok(layer) => {
                catalog.merge_layer(layer, McpScope::from_config_dir_kind(*kind));
            }
            Err(error) if crate::mcp::config::parse_error_is_reserved_builtin(&error) => {
                catalog.reserved_builtin_rejected = true;
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "skipping mcp config layer that redefines the reserved cockpit server"
                );
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "skipping malformed mcp config layer");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::config::Transport;

    fn write_layer(path: &Path, name: &str, endpoint: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(
            path,
            format!(
                r#"{{ "servers": {{ "{name}": {{ "transport": "streamable", "endpoint": "{endpoint}" }} }} }}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn resolver_matches_discover_on_layered_fixtures() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let home = tmp.path().join("home");
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(home.join(".config/cockpit")).unwrap();
        std::fs::create_dir_all(project.join(".cockpit")).unwrap();

        std::fs::write(
            home.join(".config/cockpit/mcp.json"),
            r#"{ "servers": {
              "shared": { "transport": "streamable", "endpoint": "https://home/mcp" },
              "home_only": { "transport": "streamable", "endpoint": "https://home-only/mcp" }
            } }"#,
        )
        .unwrap();
        write_layer(
            &project.join(".cockpit/mcp.json"),
            "shared",
            "https://project/mcp",
        );

        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&project).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::with_workspace_trust_policy(policy, || {
            let discovered = McpConfig::discover(&project);
            let catalog = discover_effective_catalog(&project);
            assert_eq!(
                catalog.to_mcp_config().servers.keys().collect::<Vec<_>>(),
                discovered.servers.keys().collect::<Vec<_>>(),
            );
            assert_eq!(
                catalog.servers["shared"].server.endpoint.as_deref(),
                discovered.servers["shared"].endpoint.as_deref(),
            );
            assert_eq!(catalog.servers["shared"].source, McpScope::Workspace);
            assert_eq!(catalog.servers["home_only"].source, McpScope::Global);
            assert_eq!(
                catalog.servers["shared"].server.endpoint.as_deref(),
                Some("https://project/mcp")
            );
        });
    }

    #[test]
    fn resolver_caches_until_fingerprint_changes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(project.join(".cockpit")).unwrap();
        write_layer(&project.join(".cockpit/mcp.json"), "svc", "https://one/mcp");

        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&project).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::with_workspace_trust_policy(policy, || {
            let resolver = EffectiveCatalogResolver::for_cwd(&project);
            let first = resolver.catalog();
            let second = resolver.catalog();
            assert!(Arc::ptr_eq(&first, &second), "unchanged layers reuse cache");

            std::fs::write(
                project.join(".cockpit/mcp.json"),
                r#"{ "servers": { "svc": { "transport": "streamable", "endpoint": "https://two/mcp" }, "extra": { "transport": "streamable", "endpoint": "https://extra/mcp" } } }"#,
            )
            .unwrap();
            resolver.observe_config_generation(1);
            let third = resolver.catalog();
            assert_eq!(
                third.servers["svc"].server.endpoint.as_deref(),
                Some("https://two/mcp")
            );
            assert!(third.servers.contains_key("extra"));
        });
    }

    #[test]
    fn from_mcp_config_round_trips_enabled_servers() {
        let mut cfg = McpConfig::default();
        cfg.servers.insert(
            "svc".into(),
            ServerConfig {
                transport: Transport::Streamable,
                endpoint: Some("https://x/mcp".into()),
                command: None,
                args: vec![],
                env: BTreeMap::new(),
                env_credential_refs: BTreeMap::new(),
                auth: Default::default(),
                mode: Default::default(),
                enabled: true,
                cache_ttl_secs: 3600,
                connect_timeout_secs: None,
                timeout_secs: None,
                profiles: BTreeMap::new(),
            },
        );
        let catalog = EffectiveCatalog::from_mcp_config(&cfg);
        assert_eq!(
            catalog.to_mcp_config().servers["svc"].endpoint,
            cfg.servers["svc"].endpoint
        );
        assert_eq!(catalog.servers["svc"].source, McpScope::Workspace);
        assert_eq!(catalog.servers["svc"].profile, DEFAULT_PROFILE);
        let pinned = EffectiveCatalogResolver::from_catalog(catalog.clone());
        assert_eq!(pinned.catalog().servers["svc"].name, "svc");
    }

    fn streamable(endpoint: &str) -> ServerConfig {
        ServerConfig {
            transport: Transport::Streamable,
            endpoint: Some(endpoint.into()),
            command: None,
            args: vec![],
            env: BTreeMap::new(),
            env_credential_refs: BTreeMap::new(),
            auth: Default::default(),
            mode: Default::default(),
            enabled: true,
            cache_ttl_secs: 3600,
            connect_timeout_secs: None,
            timeout_secs: None,
            profiles: BTreeMap::new(),
        }
    }

    fn named_cfg(name: &str, endpoint: &str) -> McpConfig {
        let mut cfg = McpConfig::default();
        cfg.servers.insert(name.into(), streamable(endpoint));
        cfg
    }

    #[test]
    fn precedence_workspace_beats_agent_beats_global() {
        let mut catalog = EffectiveCatalog::default();
        catalog.merge_layer(named_cfg("shared", "https://global/mcp"), McpScope::Global);
        catalog.merge_layer(named_cfg("shared", "https://agent/mcp"), McpScope::Agent);
        catalog.merge_layer(
            named_cfg("shared", "https://workspace/mcp"),
            McpScope::Workspace,
        );
        assert_eq!(
            catalog.servers["shared"].server.endpoint.as_deref(),
            Some("https://workspace/mcp")
        );
        assert_eq!(catalog.servers["shared"].source, McpScope::Workspace);
        let shadowed: Vec<_> = catalog
            .shadowed
            .iter()
            .map(|e| (e.source, e.shadowed_by, e.server.endpoint.clone()))
            .collect();
        assert!(
            shadowed.iter().any(|(source, by, endpoint)| {
                *source == McpScope::Global
                    && *by == Some(McpScope::Agent)
                    && endpoint.as_deref() == Some("https://global/mcp")
            }),
            "global must be marked shadowed by agent: {shadowed:?}"
        );
        assert!(
            shadowed.iter().any(|(source, by, endpoint)| {
                *source == McpScope::Agent
                    && *by == Some(McpScope::Workspace)
                    && endpoint.as_deref() == Some("https://agent/mcp")
            }),
            "agent must be marked shadowed by workspace: {shadowed:?}"
        );
    }

    #[test]
    fn precedence_pairs_record_shadow_markers() {
        let pairs = [
            (McpScope::Global, McpScope::Agent),
            (McpScope::Global, McpScope::Workspace),
            (McpScope::Agent, McpScope::Workspace),
        ];
        for (lower, higher) in pairs {
            let mut catalog = EffectiveCatalog::default();
            catalog.merge_layer(named_cfg("svc", "https://lower/mcp"), lower);
            catalog.merge_layer(named_cfg("svc", "https://higher/mcp"), higher);
            assert_eq!(catalog.servers["svc"].source, higher);
            assert_eq!(
                catalog.servers["svc"].server.endpoint.as_deref(),
                Some("https://higher/mcp")
            );
            assert_eq!(catalog.shadowed.len(), 1);
            assert_eq!(catalog.shadowed[0].source, lower);
            assert_eq!(catalog.shadowed[0].shadowed_by, Some(higher));
        }
    }

    #[test]
    fn agent_layer_is_visible_until_workspace_shadows_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let home = tmp.path().join("home");
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(home.join(".config/cockpit")).unwrap();
        std::fs::create_dir_all(project.join(".cockpit")).unwrap();
        std::fs::write(
            home.join(".config/cockpit/mcp.json"),
            r#"{ "servers": { "shared": { "transport": "streamable", "endpoint": "https://global/mcp" }, "global_only": { "transport": "streamable", "endpoint": "https://g-only/mcp" } } }"#,
        )
        .unwrap();
        write_layer(
            &project.join(".cockpit/mcp.json"),
            "shared",
            "https://workspace/mcp",
        );
        let agent = named_cfg("agent_only", "https://agent/mcp");
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&project).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::with_workspace_trust_policy(policy, || {
            let catalog = discover_effective_catalog_with_agent(&project, Some(&agent));
            assert_eq!(
                catalog.servers["shared"].server.endpoint.as_deref(),
                Some("https://workspace/mcp")
            );
            assert_eq!(catalog.servers["shared"].source, McpScope::Workspace);
            assert_eq!(catalog.servers["agent_only"].source, McpScope::Agent);
            assert_eq!(catalog.servers["global_only"].source, McpScope::Global);
        });
    }

    #[test]
    fn bindings_select_profile_and_hide_unbound_servers() {
        let mut catalog = EffectiveCatalog::default();
        catalog.merge_layer(named_cfg("alpha", "https://a/mcp"), McpScope::Global);
        catalog.merge_layer(named_cfg("beta", "https://b/mcp"), McpScope::Global);
        catalog
            .servers
            .get_mut("alpha")
            .unwrap()
            .server
            .profiles
            .insert(
                "admin".into(),
                crate::mcp::config::Auth::Header(crate::mcp::config::HeaderAuth {
                    header: "Authorization".into(),
                    value: "Bearer $ADMIN".into(),
                    credential_ref: None,
                }),
            );
        catalog.apply_bindings(&[crate::agents::McpBinding {
            server: "alpha".into(),
            profile: "admin".into(),
        }]);
        assert!(catalog.servers.contains_key("alpha"));
        assert!(!catalog.servers.contains_key("beta"));
        assert_eq!(catalog.servers["alpha"].profile, "admin");
        assert!(catalog.servers["alpha"].agent_bound);
    }

    #[test]
    fn child_intersection_keeps_scope_level_and_intersects_agent_bound() {
        let mut catalog = EffectiveCatalog::default();
        catalog.merge_layer(named_cfg("global", "https://g/mcp"), McpScope::Global);
        catalog.merge_layer(named_cfg("bound", "https://a/mcp"), McpScope::Agent);
        catalog.servers.get_mut("bound").unwrap().agent_bound = true;
        let parent = BTreeSet::from([("global".to_string(), DEFAULT_PROFILE.to_string())]);
        catalog.intersect_parent_reachable(&parent);
        assert!(catalog.servers.contains_key("global"));
        assert!(
            !catalog.servers.contains_key("bound"),
            "agent-bound servers not reachable to the parent must drop"
        );
    }

    #[test]
    fn reserved_cockpit_cannot_be_defined_or_shadowed() {
        let mut catalog = EffectiveCatalog::default();
        catalog.merge_layer(
            named_cfg(BUILTIN_SERVER_ID, "https://evil/mcp"),
            McpScope::Workspace,
        );
        catalog.merge_layer(named_cfg("ok", "https://ok/mcp"), McpScope::Global);
        assert!(catalog.has_reserved_builtin_server_config());
        assert!(!catalog.servers.contains_key(BUILTIN_SERVER_ID));
        assert!(catalog.servers.contains_key("ok"));
        assert!(catalog.shadowed.is_empty());
    }
}
