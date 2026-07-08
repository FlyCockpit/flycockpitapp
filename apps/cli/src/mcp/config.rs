//! MCP server configuration — the layered `.cockpit/mcp.json` schema
//! (GOALS §18a, design-doc D9).
//!
//! Each server declares a `transport` (`streamable` modern HTTP / `stdio`
//! local subprocess / `sse` legacy), the endpoint or command, an `auth`
//! block (one of `oauth` / `header` / `env` / `none`), `enabled`,
//! a catalog `cache_ttl_secs`, and optional remote-transport timeouts:
//! `connect_timeout_secs` (default 10) and `timeout_secs` (default 120).
//!
//! The file is discovered along the normal `.cockpit/` chain (GOALS §2) and
//! layers are merged from least-specific to most-specific. `COCKPIT_CONFIG`
//! only overrides `config.json`; it does not imply a sibling `mcp.json`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Transport used to reach an MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Modern remote servers: POST JSON-RPC directly to one HTTP endpoint
    /// (handles both `application/json` and `text/event-stream` replies).
    Streamable,
    /// Local subprocess: line-delimited JSON-RPC over the child's
    /// stdin/stdout. `command` + `args` + `env`.
    Stdio,
    /// Legacy remote: GET an SSE endpoint to discover the POST URL, then
    /// POST JSON-RPC there.
    Sse,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Streamable => "streamable",
            Transport::Stdio => "stdio",
            Transport::Sse => "sse",
        }
    }
}

/// Legacy mode field (GOALS §18a). All MCP access now routes
/// through the Monty sandbox; old `always-disclose` values deserialize as
/// Monty so existing configs remain usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DisclosureMode {
    /// Tools are *not* in context; reached only through the Python
    /// sandbox `mcp` tool (`mcp.search`/`mcp.invoke`). The default.
    #[default]
    #[serde(alias = "always-disclose", alias = "traditional", alias = "trad")]
    Monty,
}

impl DisclosureMode {
    pub fn is_monty(mode: &Self) -> bool {
        matches!(mode, DisclosureMode::Monty)
    }
}

/// Per-server authentication. Credentials/tokens are stored via
/// `credentials.rs`; `$VAR` references resolve through `envref.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Auth {
    /// OAuth 2.1 + PKCE (reuses the `auth/` flows). `authorize_url` /
    /// `token_url` / `client_id` are discovered or configured; the bearer
    /// token is stored + refreshed and sent in `Authorization`.
    Oauth(OauthAuth),
    /// Static `Authorization: Bearer …` or a custom header key/value.
    Header(HeaderAuth),
    /// Inject secrets via env (esp. stdio). Each value may carry `$VAR`
    /// references resolved at launch.
    Env(EnvAuth),
    /// Unauthenticated / public. The Add-MCP form warns at add-time.
    #[default]
    None,
}

impl Auth {
    pub fn kind_str(&self) -> &'static str {
        match self {
            Auth::Oauth(_) => "oauth",
            Auth::Header(_) => "header",
            Auth::Env(_) => "env",
            Auth::None => "none",
        }
    }
}

/// OAuth 2.1 + PKCE config for a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OauthAuth {
    /// Authorization endpoint (browser redirect target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_url: Option<String>,
    /// Token endpoint (code → token exchange + refresh).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    /// OAuth client id (public client; PKCE means no secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Requested scopes, space-joined into the auth request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// Static-header config: a header name + value. The value may carry
/// `$VAR` references resolved through `envref.rs` at launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderAuth {
    /// Header name. Defaults to `Authorization`.
    #[serde(default = "default_header_name")]
    pub header: String,
    /// Header value (e.g. `Bearer $MY_TOKEN`). `$VAR` resolved at launch.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
    /// Credential-store key for UI-entered header values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
}

fn default_header_name() -> String {
    "Authorization".to_string()
}

/// Env-injection config: a map of env-var name → value (values may carry
/// `$VAR` references resolved at launch). Primarily for stdio servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EnvAuth {
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// Env-var name -> credential-store key for UI-entered env values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credential_refs: BTreeMap<String, String>,
}

/// One configured MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub transport: Transport,

    /// Remote endpoint URL (`streamable` / `sse`). Ignored for stdio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Subprocess command (`stdio`). Ignored for remote transports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Subprocess args (`stdio`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Extra environment for the subprocess (`stdio`). `$VAR` resolved at
    /// launch. The `Auth::Env` vars are merged on top of these.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,

    /// Base subprocess env backed by the credential store.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env_credential_refs: BTreeMap<String, String>,

    /// Authentication block. Defaults to `none`.
    #[serde(default)]
    pub auth: Auth,

    /// Legacy mode value. Defaults to `monty`, accepts old aliases, and is
    /// skipped on new writes.
    #[serde(default, skip_serializing_if = "DisclosureMode::is_monty")]
    pub mode: DisclosureMode,

    /// Whether this server is active. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Catalog-cache TTL in seconds before a re-fetch. Defaults to 3600.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Remote connect timeout in seconds for `streamable` and `sse`
    /// transports. Defaults to 10. Ignored for stdio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,

    /// Remote request timeout in seconds for `streamable` and `sse`
    /// transports. Defaults to 120. For legacy SSE this also bounds waiting
    /// for the endpoint event and each streamed response message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

fn default_true() -> bool {
    true
}

fn default_cache_ttl() -> u64 {
    3600
}

pub const DEFAULT_MCP_CONNECT_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_MCP_REQUEST_TIMEOUT_SECS: u64 = 120;

impl ServerConfig {
    /// The remote endpoint, or an error for a server that needs one.
    pub fn require_endpoint(&self, name: &str) -> Result<&str> {
        self.endpoint.as_deref().with_context(|| {
            format!(
                "MCP server `{name}` ({}) has no `endpoint`",
                self.transport.as_str()
            )
        })
    }

    /// The subprocess command, or an error for a stdio server missing one.
    pub fn require_command(&self, name: &str) -> Result<&str> {
        self.command
            .as_deref()
            .with_context(|| format!("MCP server `{name}` (stdio) has no `command`"))
    }

    pub fn connect_timeout_secs(&self) -> u64 {
        self.connect_timeout_secs
            .unwrap_or(DEFAULT_MCP_CONNECT_TIMEOUT_SECS)
    }

    pub fn request_timeout_secs(&self) -> u64 {
        self.timeout_secs
            .unwrap_or(DEFAULT_MCP_REQUEST_TIMEOUT_SECS)
    }

    pub fn validate_transport_auth(&self, name: &str) -> Result<()> {
        match (&self.transport, &self.auth) {
            (Transport::Stdio, Auth::Oauth(_) | Auth::Header(_)) => {
                anyhow::bail!("MCP server `{name}` uses incompatible stdio auth")
            }
            (Transport::Streamable | Transport::Sse, Auth::Env(_)) => {
                anyhow::bail!("MCP server `{name}` uses env auth on a remote transport")
            }
            _ => Ok(()),
        }
    }
}

/// The whole `mcp.json` document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpConfig {
    #[serde(default)]
    pub servers: BTreeMap<String, ServerConfig>,
}

impl McpConfig {
    /// Parse an `mcp.json` from a string.
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(raw).context("parsing mcp.json")
    }

    /// Load and merge every parseable `mcp.json` layer for `cwd`, or defaults
    /// (empty) when none exists. Server definitions are keyed by name; a
    /// more-specific layer replaces the same server name from a broader layer.
    pub fn discover(cwd: &Path) -> Self {
        let paths = crate::config::dirs::mcp_file_paths_for_load(cwd);
        Self::discover_from_paths(&paths)
    }

    fn discover_from_paths(paths: &[std::path::PathBuf]) -> Self {
        let mut merged = Self::default();
        for path in paths {
            let Ok(raw) = std::fs::read_to_string(path) else {
                continue;
            };
            match Self::parse(&raw) {
                Ok(layer) => {
                    for (name, server) in layer.servers {
                        merged.servers.insert(name, server);
                    }
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping malformed mcp config layer");
                }
            }
        }
        merged
    }

    pub fn write_private(&self, path: &Path) -> Result<()> {
        crate::private_fs::ensure_parent_dir_private(path)?;
        let body = serde_json::to_string_pretty(self).context("serializing mcp.json")?;
        crate::private_fs::write_private_file(path, format!("{body}\n").as_bytes())
    }

    /// Enabled servers, sorted by name.
    pub fn enabled_servers(&self) -> Vec<(&str, &ServerConfig)> {
        self.servers
            .iter()
            .filter(|(_, s)| s.enabled)
            .map(|(n, s)| (n.as_str(), s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_private_creates_private_mcp_file() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".cockpit/mcp.json");
        let mut cfg = McpConfig::default();
        cfg.servers.insert(
            "s".into(),
            ServerConfig {
                transport: Transport::Streamable,
                endpoint: Some("https://x/mcp".into()),
                command: None,
                args: vec![],
                env: BTreeMap::new(),
                env_credential_refs: BTreeMap::new(),
                auth: Auth::Header(HeaderAuth {
                    header: "Authorization".into(),
                    value: "Bearer secret".into(),
                    credential_ref: None,
                }),
                mode: DisclosureMode::Monty,
                enabled: true,
                cache_ttl_secs: 3600,
                connect_timeout_secs: None,
                timeout_secs: None,
            },
        );

        cfg.write_private(&path).unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn parses_all_three_transports_and_four_auth_kinds() {
        let raw = r#"{
          "servers": {
            "http_oauth": {
              "transport": "streamable",
              "endpoint": "https://api.example.com/mcp",
              "auth": { "kind": "oauth", "client_id": "abc", "scopes": ["read"] }
            },
            "stdio_env": {
              "transport": "stdio",
              "command": "npx",
              "args": ["-y", "server"],
              "auth": { "kind": "env", "vars": { "TOKEN": "$GH_TOKEN" } }
            },
            "sse_header": {
              "transport": "sse",
              "endpoint": "https://legacy.example.com/sse",
              "auth": { "kind": "header", "header": "X-Api-Key", "value": "$KEY" },
              "mode": "always-disclose",
              "enabled": false
            },
            "public": {
              "transport": "streamable",
              "endpoint": "https://public.example.com/mcp",
              "auth": { "kind": "none" }
            }
          }
        }"#;
        let cfg = McpConfig::parse(raw).unwrap();
        assert_eq!(cfg.servers.len(), 4);

        let http = &cfg.servers["http_oauth"];
        assert_eq!(http.transport, Transport::Streamable);
        assert_eq!(http.mode, DisclosureMode::Monty, "default mode is monty");
        assert!(http.enabled, "default enabled is true");
        assert_eq!(http.cache_ttl_secs, 3600, "default ttl");
        assert_eq!(
            http.connect_timeout_secs(),
            DEFAULT_MCP_CONNECT_TIMEOUT_SECS
        );
        assert_eq!(
            http.request_timeout_secs(),
            DEFAULT_MCP_REQUEST_TIMEOUT_SECS
        );
        assert!(matches!(http.auth, Auth::Oauth(_)));

        let stdio = &cfg.servers["stdio_env"];
        assert_eq!(stdio.transport, Transport::Stdio);
        assert_eq!(stdio.command.as_deref(), Some("npx"));
        assert_eq!(stdio.args, vec!["-y", "server"]);
        match &stdio.auth {
            Auth::Env(e) => assert_eq!(e.vars["TOKEN"], "$GH_TOKEN"),
            other => panic!("expected env auth, got {other:?}"),
        }

        let sse = &cfg.servers["sse_header"];
        assert_eq!(sse.transport, Transport::Sse);
        assert_eq!(sse.mode, DisclosureMode::Monty);
        assert!(!sse.enabled);
        match &sse.auth {
            Auth::Header(h) => {
                assert_eq!(h.header, "X-Api-Key");
                assert_eq!(h.value, "$KEY");
            }
            other => panic!("expected header auth, got {other:?}"),
        }

        let public = &cfg.servers["public"];
        assert!(matches!(public.auth, Auth::None));
    }

    #[test]
    fn header_auth_defaults_to_authorization() {
        let raw = r#"{ "servers": { "s": {
          "transport": "streamable", "endpoint": "https://x/mcp",
          "auth": { "kind": "header", "value": "Bearer $T" }
        } } }"#;
        let cfg = McpConfig::parse(raw).unwrap();
        match &cfg.servers["s"].auth {
            Auth::Header(h) => assert_eq!(h.header, "Authorization"),
            other => panic!("expected header auth, got {other:?}"),
        }
    }

    #[test]
    fn missing_auth_defaults_to_none() {
        let raw = r#"{ "servers": { "s": {
          "transport": "streamable", "endpoint": "https://x/mcp"
        } } }"#;
        let cfg = McpConfig::parse(raw).unwrap();
        assert!(matches!(cfg.servers["s"].auth, Auth::None));
    }

    #[test]
    fn empty_doc_is_default() {
        assert!(McpConfig::parse("").unwrap().servers.is_empty());
        assert!(McpConfig::parse("{}").unwrap().servers.is_empty());
    }

    #[test]
    fn enabled_servers_include_legacy_always_disclose_aliases() {
        let raw = r#"{ "servers": {
          "a": { "transport": "streamable", "endpoint": "u", "mode": "monty", "enabled": true },
          "b": { "transport": "streamable", "endpoint": "u", "mode": "monty", "enabled": false },
          "c": { "transport": "streamable", "endpoint": "u", "mode": "always-disclose", "enabled": true }
        } }"#;
        let cfg = McpConfig::parse(raw).unwrap();
        let enabled = cfg.enabled_servers();
        assert_eq!(
            enabled.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            vec!["a", "c"]
        );
        assert_eq!(cfg.servers["c"].mode, DisclosureMode::Monty);
    }

    #[test]
    fn timeout_overrides_parse_and_default() {
        let raw = r#"{ "servers": {
          "fast": {
            "transport": "streamable",
            "endpoint": "https://x/mcp",
            "connect_timeout_secs": 2,
            "timeout_secs": 5
          }
        } }"#;
        let cfg = McpConfig::parse(raw).unwrap();
        let fast = &cfg.servers["fast"];
        assert_eq!(fast.connect_timeout_secs(), 2);
        assert_eq!(fast.request_timeout_secs(), 5);
    }

    #[test]
    fn discover_from_paths_merges_servers_with_later_layer_winning() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().join("home-mcp.json");
        let project = tmp.path().join("project-mcp.json");
        std::fs::write(
            &home,
            r#"{ "servers": {
              "shared": { "transport": "streamable", "endpoint": "https://home/mcp" },
              "home_only": { "transport": "stdio", "command": "home" }
            } }"#,
        )
        .unwrap();
        std::fs::write(
            &project,
            r#"{ "servers": {
              "shared": { "transport": "streamable", "endpoint": "https://project/mcp" }
            } }"#,
        )
        .unwrap();

        let cfg = McpConfig::discover_from_paths(&[home, project]);

        assert_eq!(
            cfg.servers["shared"].endpoint.as_deref(),
            Some("https://project/mcp")
        );
        assert!(cfg.servers.contains_key("home_only"));
    }

    #[test]
    fn cockpit_config_env_does_not_redirect_mcp_discovery() {
        let tmp = tempfile::TempDir::new().unwrap();
        let env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(project.join(".cockpit")).unwrap();
        std::fs::write(
            project.join(".cockpit/mcp.json"),
            r#"{ "servers": { "project": { "transport": "streamable", "endpoint": "https://project/mcp" } } }"#,
        )
        .unwrap();
        let override_config = tmp.path().join("override-config.json");
        std::fs::write(&override_config, r#"{"name":"Override"}"#).unwrap();
        let override_mcp = tmp.path().join("mcp.json");
        std::fs::write(
            &override_mcp,
            r#"{ "servers": { "override": { "transport": "streamable", "endpoint": "https://override/mcp" } } }"#,
        )
        .unwrap();
        let _override = env.override_cockpit_config(&override_config);

        let cfg = McpConfig::discover(&project);

        assert!(cfg.servers.contains_key("project"));
        assert!(
            !cfg.servers.contains_key("override"),
            "COCKPIT_CONFIG points at config.json only, not sibling mcp.json"
        );
    }
}
