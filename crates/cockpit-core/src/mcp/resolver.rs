//! Source-tagged effective MCP catalog resolver.
//!
//! Tool dispatch used to re-read every `mcp.json` layer on each `mcp` tool
//! call via [`super::config::McpConfig::discover`]. The persistent catalog is
//! admitted once by the root worker, then each agent projects its package
//! layer onto that immutable snapshot without further filesystem discovery.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::dirs::ConfigDirKind;
use crate::mcp::builtin::BUILTIN_SERVER_ID;
use crate::mcp::config::{McpConfig, ServerConfig};

/// Where an MCP server definition was loaded from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpScope {
    Builtin,
    Global,
    Workspace,
    Agent,
}

/// The only scopes allowed to enter persistent MCP routing.
///
/// This deliberately excludes [`McpScope::Builtin`]. A persistent server's
/// configuration and its provenance are stored together in [`CatalogEntry`],
/// so callers cannot manufacture a built-in entry that reaches cache,
/// credential, approval, or transport code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PersistentMcpScope {
    Global,
    Workspace,
    Agent,
}

impl PersistentMcpScope {
    fn from_config_dir_kind(kind: ConfigDirKind) -> Self {
        match kind {
            ConfigDirKind::HomeXdg | ConfigDirKind::HomeDot | ConfigDirKind::MachineLocal => {
                Self::Global
            }
            ConfigDirKind::Project => Self::Workspace,
        }
    }

    fn as_scope(self) -> McpScope {
        match self {
            Self::Global => McpScope::Global,
            Self::Workspace => McpScope::Workspace,
            Self::Agent => McpScope::Agent,
        }
    }
}

impl McpScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Global => "global",
            Self::Workspace => "workspace",
            Self::Agent => "agent",
        }
    }

    /// workspace > agent > global
    fn rank(self) -> u8 {
        match self {
            Self::Builtin => 3,
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
    origin: CatalogOrigin,
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

/// Closed provenance/configuration pair for a catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CatalogOrigin {
    Builtin,
    Persistent {
        scope: PersistentMcpScope,
        server: ServerConfig,
    },
}

impl CatalogEntry {
    pub fn is_live(&self) -> bool {
        self.shadowed_by.is_none()
    }

    pub fn builtin() -> Self {
        Self {
            name: BUILTIN_SERVER_ID.to_string(),
            origin: CatalogOrigin::Builtin,
            shadowed_by: None,
            profile: DEFAULT_PROFILE.to_string(),
            agent_bound: false,
        }
    }

    pub fn persistent(name: String, server: ServerConfig, scope: PersistentMcpScope) -> Self {
        Self {
            name,
            origin: CatalogOrigin::Persistent { scope, server },
            shadowed_by: None,
            profile: DEFAULT_PROFILE.to_string(),
            agent_bound: scope == PersistentMcpScope::Agent,
        }
    }

    pub fn persistent_server(&self) -> Option<&ServerConfig> {
        match &self.origin {
            CatalogOrigin::Builtin => None,
            CatalogOrigin::Persistent { server, .. } => Some(server),
        }
    }

    fn persistent_server_mut(&mut self) -> Option<&mut ServerConfig> {
        match &mut self.origin {
            CatalogOrigin::Builtin => None,
            CatalogOrigin::Persistent { server, .. } => Some(server),
        }
    }

    pub fn source(&self) -> McpScope {
        match &self.origin {
            CatalogOrigin::Builtin => McpScope::Builtin,
            CatalogOrigin::Persistent { scope, .. } => (*scope).as_scope(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.persistent_server().is_none_or(|server| server.enabled)
    }
}

/// Merged, source-tagged view of every MCP server visible to one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveCatalog {
    /// Winning (unshadowed) entries keyed by server name.
    pub servers: BTreeMap<String, CatalogEntry>,
    /// Same-named entries hidden by a more-specific scope. Never silent:
    /// a projection can surface `shadowed_by`.
    pub shadowed: Vec<CatalogEntry>,
    /// A layer tried to define the reserved `cockpit` server.
    pub reserved_builtin_rejected: bool,
}

impl Default for EffectiveCatalog {
    fn default() -> Self {
        Self {
            servers: BTreeMap::from([(BUILTIN_SERVER_ID.to_string(), CatalogEntry::builtin())]),
            shadowed: Vec::new(),
            reserved_builtin_rejected: false,
        }
    }
}

impl EffectiveCatalog {
    /// Wrap a pre-merged [`McpConfig`] as workspace-scoped entries. Used by
    /// tests and non-tool callers that already have a merged document.
    pub fn from_mcp_config(cfg: &McpConfig) -> Self {
        Self::from_mcp_config_with_scope(cfg, PersistentMcpScope::Workspace)
    }

    pub fn from_mcp_config_with_scope(cfg: &McpConfig, source: PersistentMcpScope) -> Self {
        let mut catalog = Self::default();
        for (name, server) in &cfg.servers {
            catalog.merge_entry(CatalogEntry::persistent(
                name.clone(),
                server.clone(),
                source,
            ));
        }
        catalog
    }

    fn merge_layer(&mut self, layer: McpConfig, source: PersistentMcpScope) {
        for (name, server) in layer.servers {
            self.merge_entry(CatalogEntry::persistent(name, server, source));
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
            Some(existing) if existing.source().rank() <= incoming.source().rank() => {
                let mut old = existing.clone();
                if old.source() != incoming.source() {
                    old.shadowed_by = Some(incoming.source());
                    self.shadowed.push(old);
                }
                self.servers.insert(incoming.name.clone(), incoming);
            }
            Some(existing) => {
                let mut shadowed = incoming;
                shadowed.shadowed_by = Some(existing.source());
                self.shadowed.push(shadowed);
            }
        }
    }

    pub fn to_mcp_config(&self) -> McpConfig {
        McpConfig {
            servers: self
                .servers
                .iter()
                .filter_map(|(name, entry)| {
                    entry
                        .persistent_server()
                        .cloned()
                        .map(|server| (name.clone(), server))
                })
                .collect(),
        }
    }

    pub fn enabled_servers(&self) -> Vec<(&str, &ServerConfig, &CatalogEntry)> {
        self.servers
            .iter()
            .filter(|(_, entry)| {
                entry.is_live()
                    && entry
                        .persistent_server()
                        .is_some_and(|server| server.enabled)
            })
            .filter_map(|(name, entry)| {
                entry
                    .persistent_server()
                    .map(|server| (name.as_str(), server, entry))
            })
            .collect()
    }

    pub fn has_reserved_builtin_server_config(&self) -> bool {
        self.reserved_builtin_rejected
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
            if entry.source() == McpScope::Builtin {
                next.insert(name, entry);
                continue;
            }
            let Some(profile) = wanted.get(name.as_str()).copied() else {
                continue;
            };
            let server = entry
                .persistent_server()
                .expect("non-built-in catalog entries carry persistent server configuration");
            if server.auth_for_profile(profile).is_none() {
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

/// Read-only, source-tagged effective catalog resolved during agent
/// construction. It deliberately owns no filesystem paths or config handle:
/// once a root worker has admitted the catalog, every descendant receives the
/// same immutable value through its `ToolCtx`.
pub struct EffectiveCatalogResolver {
    /// Persistent catalog admitted by the root worker, including the built-in
    /// pseudo-server. Agent definitions only project this snapshot; they never
    /// rediscover persistent files.
    root_catalog: Arc<EffectiveCatalog>,
    catalog: Arc<EffectiveCatalog>,
    parent_reachable: Option<BTreeSet<(String, String)>>,
}

impl EffectiveCatalogResolver {
    pub fn empty() -> Arc<Self> {
        Self::from_catalog(EffectiveCatalog::default())
    }

    pub fn for_cwd(cwd: impl Into<PathBuf>) -> Arc<Self> {
        Self::from_catalog(discover_effective_catalog(&cwd.into()))
    }

    pub fn for_agent(cwd: impl Into<PathBuf>, def: &crate::agents::AgentDef) -> Arc<Self> {
        let root_catalog = Self::for_cwd(cwd).root_catalog();
        Self::for_agent_from_root_catalog(root_catalog, def, None)
    }

    /// Project an agent definition onto the immutable catalog admitted by its
    /// root worker. This intentionally performs no filesystem discovery.
    pub fn for_agent_from_root_catalog(
        root_catalog: Arc<EffectiveCatalog>,
        def: &crate::agents::AgentDef,
        parent_reachable: Option<BTreeSet<(String, String)>>,
    ) -> Arc<Self> {
        let (layer, reserved) = parse_agent_package_mcp(def);
        Self::project_root_catalog(
            root_catalog,
            layer,
            reserved,
            def.mcp_bindings.clone(),
            parent_reachable,
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
        let mut catalog = (*self.catalog).clone();
        catalog.intersect_parent_reachable(&parent);
        Arc::new(Self {
            root_catalog: self.root_catalog.clone(),
            catalog: Arc::new(catalog),
            parent_reachable: Some(parent),
        })
    }

    fn project_root_catalog(
        root_catalog: Arc<EffectiveCatalog>,
        agent_layer: Option<McpConfig>,
        agent_reserved_rejected: bool,
        bindings: Vec<crate::agents::McpBinding>,
        parent_reachable: Option<BTreeSet<(String, String)>>,
    ) -> Arc<Self> {
        let mut catalog = (*root_catalog).clone();
        if let Some(agent_layer) = agent_layer {
            catalog.merge_layer(agent_layer, PersistentMcpScope::Agent);
        }
        catalog.reserved_builtin_rejected |= agent_reserved_rejected;
        catalog.apply_bindings(&bindings);
        if let Some(parent) = &parent_reachable {
            catalog.intersect_parent_reachable(parent);
        }
        Arc::new(Self {
            root_catalog,
            catalog: Arc::new(catalog),
            parent_reachable,
        })
    }

    pub fn from_catalog(catalog: EffectiveCatalog) -> Arc<Self> {
        Self::from_root_catalog(Arc::new(catalog))
    }

    pub fn from_root_catalog(catalog: Arc<EffectiveCatalog>) -> Arc<Self> {
        Arc::new(Self {
            root_catalog: catalog.clone(),
            catalog,
            parent_reachable: None,
        })
    }

    pub fn catalog(&self) -> Arc<EffectiveCatalog> {
        self.catalog.clone()
    }

    pub fn root_catalog(&self) -> Arc<EffectiveCatalog> {
        self.root_catalog.clone()
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
        match PersistentMcpScope::from_config_dir_kind(*kind) {
            PersistentMcpScope::Global => globals.push((*kind, path.clone())),
            PersistentMcpScope::Workspace => workspaces.push((*kind, path.clone())),
            PersistentMcpScope::Agent => {}
        }
    }
    load_and_merge_paths(&mut catalog, &globals);
    if let Some(agent) = agent_layer {
        catalog.merge_layer(agent.clone(), PersistentMcpScope::Agent);
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
                catalog.merge_layer(layer, PersistentMcpScope::from_config_dir_kind(*kind));
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
                catalog.servers["shared"]
                    .persistent_server()
                    .unwrap()
                    .endpoint
                    .as_deref(),
                discovered.servers["shared"].endpoint.as_deref(),
            );
            assert_eq!(catalog.servers["shared"].source(), McpScope::Workspace);
            assert_eq!(catalog.servers["home_only"].source(), McpScope::Global);
            assert_eq!(
                catalog.servers["shared"]
                    .persistent_server()
                    .unwrap()
                    .endpoint
                    .as_deref(),
                Some("https://project/mcp")
            );
        });
    }

    #[test]
    fn resolver_is_a_construction_time_snapshot() {
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
            let third = resolver.catalog();
            assert_eq!(
                third.servers["svc"]
                    .persistent_server()
                    .unwrap()
                    .endpoint
                    .as_deref(),
                Some("https://one/mcp"),
                "an active worker must keep its root-resolved catalog"
            );
            assert!(
                !third.servers.contains_key("extra"),
                "new on-disk entries become visible only to a newly built root catalog"
            );
            assert!(Arc::ptr_eq(&first, &third), "tool-time lookup is read-only");
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
        assert_eq!(catalog.servers["svc"].source(), McpScope::Workspace);
        assert_eq!(catalog.servers["svc"].profile, DEFAULT_PROFILE);
        assert_eq!(
            catalog.servers[BUILTIN_SERVER_ID].source(),
            McpScope::Builtin
        );
        assert!(
            catalog.servers[BUILTIN_SERVER_ID]
                .persistent_server()
                .is_none()
        );
        assert!(
            !catalog
                .to_mcp_config()
                .servers
                .contains_key(BUILTIN_SERVER_ID),
            "the host-owned pseudo-server must not enter persistent transport configuration"
        );
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
    fn catalog_entry_origin_couples_scope_and_configuration() {
        let builtin = CatalogEntry::builtin();
        assert_eq!(builtin.source(), McpScope::Builtin);
        assert!(builtin.persistent_server().is_none());

        let persistent = CatalogEntry::persistent(
            "svc".to_string(),
            streamable("https://svc/mcp"),
            PersistentMcpScope::Workspace,
        );
        assert_eq!(persistent.source(), McpScope::Workspace);
        assert!(persistent.persistent_server().is_some());
    }

    #[test]
    fn precedence_workspace_beats_agent_beats_global() {
        let mut catalog = EffectiveCatalog::default();
        catalog.merge_layer(
            named_cfg("shared", "https://global/mcp"),
            PersistentMcpScope::Global,
        );
        catalog.merge_layer(
            named_cfg("shared", "https://agent/mcp"),
            PersistentMcpScope::Agent,
        );
        catalog.merge_layer(
            named_cfg("shared", "https://workspace/mcp"),
            PersistentMcpScope::Workspace,
        );
        assert_eq!(
            catalog.servers["shared"]
                .persistent_server()
                .unwrap()
                .endpoint
                .as_deref(),
            Some("https://workspace/mcp")
        );
        assert_eq!(catalog.servers["shared"].source(), McpScope::Workspace);
        let shadowed: Vec<_> = catalog
            .shadowed
            .iter()
            .map(|e| {
                (
                    e.source(),
                    e.shadowed_by,
                    e.persistent_server()
                        .and_then(|server| server.endpoint.clone()),
                )
            })
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
            (PersistentMcpScope::Global, PersistentMcpScope::Agent),
            (PersistentMcpScope::Global, PersistentMcpScope::Workspace),
            (PersistentMcpScope::Agent, PersistentMcpScope::Workspace),
        ];
        for (lower, higher) in pairs {
            let mut catalog = EffectiveCatalog::default();
            catalog.merge_layer(named_cfg("svc", "https://lower/mcp"), lower);
            catalog.merge_layer(named_cfg("svc", "https://higher/mcp"), higher);
            assert_eq!(catalog.servers["svc"].source(), higher.as_scope());
            assert_eq!(
                catalog.servers["svc"]
                    .persistent_server()
                    .unwrap()
                    .endpoint
                    .as_deref(),
                Some("https://higher/mcp")
            );
            assert_eq!(catalog.shadowed.len(), 1);
            assert_eq!(catalog.shadowed[0].source(), lower.as_scope());
            assert_eq!(catalog.shadowed[0].shadowed_by, Some(higher.as_scope()));
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
                catalog.servers["shared"]
                    .persistent_server()
                    .unwrap()
                    .endpoint
                    .as_deref(),
                Some("https://workspace/mcp")
            );
            assert_eq!(catalog.servers["shared"].source(), McpScope::Workspace);
            assert_eq!(catalog.servers["agent_only"].source(), McpScope::Agent);
            assert_eq!(catalog.servers["global_only"].source(), McpScope::Global);
        });
    }

    #[test]
    fn bindings_select_profile_and_hide_unbound_servers() {
        let mut catalog = EffectiveCatalog::default();
        catalog.merge_layer(
            named_cfg("alpha", "https://a/mcp"),
            PersistentMcpScope::Global,
        );
        catalog.merge_layer(
            named_cfg("beta", "https://b/mcp"),
            PersistentMcpScope::Global,
        );
        catalog
            .servers
            .get_mut("alpha")
            .unwrap()
            .persistent_server_mut()
            .unwrap()
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
        assert!(catalog.servers.contains_key(BUILTIN_SERVER_ID));
        assert_eq!(catalog.servers["alpha"].profile, "admin");
        assert!(catalog.servers["alpha"].agent_bound);
    }

    #[test]
    fn child_intersection_keeps_scope_level_and_intersects_agent_bound() {
        let mut catalog = EffectiveCatalog::default();
        catalog.merge_layer(
            named_cfg("global", "https://g/mcp"),
            PersistentMcpScope::Global,
        );
        catalog.merge_layer(
            named_cfg("bound", "https://a/mcp"),
            PersistentMcpScope::Agent,
        );
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
            PersistentMcpScope::Workspace,
        );
        catalog.merge_layer(
            named_cfg("ok", "https://ok/mcp"),
            PersistentMcpScope::Global,
        );
        assert!(catalog.has_reserved_builtin_server_config());
        assert_eq!(
            catalog.servers[BUILTIN_SERVER_ID].source(),
            McpScope::Builtin
        );
        assert!(
            catalog.servers[BUILTIN_SERVER_ID]
                .persistent_server()
                .is_none()
        );
        assert!(catalog.servers.contains_key("ok"));
        assert!(catalog.shadowed.is_empty());
    }
}
