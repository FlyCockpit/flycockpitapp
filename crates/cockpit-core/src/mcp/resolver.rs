//! Source-tagged effective MCP catalog resolver.
//!
//! Tool dispatch used to re-read every `mcp.json` layer on each `mcp` tool
//! call via [`super::config::McpConfig::discover`]. The resolver is built
//! once per agent construction (or test `ToolCtx`), tagged with the layer
//! that defined each server, and refreshed when the underlying files or
//! session config generation change.

use std::collections::BTreeMap;
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
}

/// Implicit profile name for today's flat `auth` block.
pub const DEFAULT_PROFILE: &str = "default";

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
    /// Same-named entries hidden by a more-specific scope. Empty until
    /// Stage 2 records shadowing instead of silently overwriting.
    pub shadowed: Vec<CatalogEntry>,
}

impl EffectiveCatalog {
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
                },
            );
        }
        Self {
            servers,
            shadowed: Vec::new(),
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
                entry.is_live()
                    && entry.server.enabled
                    && name.as_str() != BUILTIN_SERVER_ID
            })
            .map(|(name, entry)| (name.as_str(), &entry.server, entry))
            .collect()
    }

    pub fn has_reserved_builtin_server_config(&self) -> bool {
        self.servers.contains_key(BUILTIN_SERVER_ID)
            || self
                .shadowed
                .iter()
                .any(|entry| entry.name == BUILTIN_SERVER_ID)
    }

    pub fn get(&self, name: &str) -> Option<&CatalogEntry> {
        self.servers.get(name).filter(|entry| entry.is_live())
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
    inner: Mutex<Option<CachedCatalog>>,
}

impl EffectiveCatalogResolver {
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            cwd: PathBuf::new(),
            config_generation: std::sync::atomic::AtomicU64::new(0),
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
            inner: Mutex::new(None),
        })
    }

    pub fn with_config_generation(cwd: impl Into<PathBuf>, generation: u64) -> Arc<Self> {
        Arc::new(Self {
            cwd: cwd.into(),
            config_generation: std::sync::atomic::AtomicU64::new(generation),
            inner: Mutex::new(None),
        })
    }

    pub fn from_catalog(catalog: EffectiveCatalog) -> Arc<Self> {
        Arc::new(Self {
            cwd: PathBuf::new(),
            config_generation: std::sync::atomic::AtomicU64::new(0),
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
        discover_effective_catalog(&self.cwd)
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

/// Discover global + workspace layers for `cwd` and merge them the same way
/// [`McpConfig::discover`] does (later/more-specific wins), tagging each
/// winning entry with the scope of the layer that defined it.
pub fn discover_effective_catalog(cwd: &Path) -> EffectiveCatalog {
    let layers = crate::config::dirs::mcp_file_layers_for_load(cwd);
    discover_effective_catalog_from_layers(&layers)
}

pub fn discover_effective_catalog_from_layers(
    layers: &[(ConfigDirKind, PathBuf)],
) -> EffectiveCatalog {
    let mut catalog = EffectiveCatalog::default();
    for (kind, path) in layers {
        let Ok(raw) = std::fs::read_to_string(path) else {
            continue;
        };
        match McpConfig::parse(&raw) {
            Ok(layer) => {
                let source = McpScope::from_config_dir_kind(*kind);
                for (name, server) in layer.servers {
                    catalog.servers.insert(
                        name.clone(),
                        CatalogEntry {
                            name,
                            server,
                            source,
                            shadowed_by: None,
                            profile: DEFAULT_PROFILE.to_string(),
                        },
                    );
                }
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "skipping malformed mcp config layer");
            }
        }
    }
    catalog
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
        write_layer(
            &project.join(".cockpit/mcp.json"),
            "svc",
            "https://one/mcp",
        );

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
            },
        );
        let catalog = EffectiveCatalog::from_mcp_config(&cfg);
        assert_eq!(catalog.to_mcp_config().servers["svc"].endpoint, cfg.servers["svc"].endpoint);
        assert_eq!(catalog.servers["svc"].source, McpScope::Workspace);
        assert_eq!(catalog.servers["svc"].profile, DEFAULT_PROFILE);
        let pinned = EffectiveCatalogResolver::from_catalog(catalog.clone());
        assert_eq!(pinned.catalog().servers["svc"].name, "svc");
    }
}
