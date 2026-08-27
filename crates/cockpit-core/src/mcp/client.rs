//! Construct an [`McpClient`] for a configured server, resolving auth
//! (static headers/env + OAuth bearer) per transport.

use std::sync::Arc;

use anyhow::{Result, bail};

use crate::approval::{Approver, AuthorizationRequest, Decision};
use crate::config::extended::ApprovalMode;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::auth;
use super::config::{Auth, ServerConfig, Transport};
use super::protocol::McpClient;
use super::transport::timeout::McpTimeouts;
use super::transport::{
    http::HttpClient,
    sse::SseClient,
    stdio::{StdioAbandonScope, StdioClient, StdioRuntimeContext},
};

#[derive(Clone)]
pub struct McpConnectContext {
    cancel: Option<CancellationToken>,
    stdio_abandon_scope: Option<StdioAbandonScope>,
    approver: Option<Arc<Approver>>,
    approval_mode: ApprovalMode,
    vault: Option<Arc<crate::secure_key::SecretVault>>,
    /// Owning workspace root for named-secret ownership scoping (`owner_kind =
    /// mcp`). Present whenever `vault` is (the daemon always supplies it via
    /// [`Self::from_tool_ctx`]); resolution then only sees `mcp:` secrets owned
    /// by this server/root.
    project_root: Option<String>,
    credential_profile: String,
    agent_id: String,
    agent_bound: bool,
}

impl Default for McpConnectContext {
    fn default() -> Self {
        Self {
            cancel: None,
            stdio_abandon_scope: None,
            approver: None,
            approval_mode: ApprovalMode::default(),
            vault: None,
            project_root: None,
            credential_profile: crate::mcp::config::DEFAULT_PROFILE.to_string(),
            agent_id: String::new(),
            agent_bound: false,
        }
    }
}

impl McpConnectContext {
    pub fn from_tool_ctx(ctx: &crate::engine::tool::ToolCtx) -> Self {
        Self {
            cancel: Some(ctx.cancel.clone()),
            stdio_abandon_scope: Some(StdioAbandonScope {
                session_id: ctx.session.id,
                tool_call_id: ctx.current_tool_call_id.clone(),
            }),
            approver: ctx.approver.clone(),
            approval_mode: ctx.session.approval_mode(),
            vault: Some(ctx.session.secret_vault().clone()),
            project_root: Some(ctx.session.project_root.display().to_string()),
            credential_profile: crate::mcp::config::DEFAULT_PROFILE.to_string(),
            agent_id: ctx.agent_id.clone(),
            agent_bound: false,
        }
    }

    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.credential_profile = profile.into();
        self
    }

    pub fn with_agent_binding(mut self, agent_id: impl Into<String>, agent_bound: bool) -> Self {
        self.agent_id = agent_id.into();
        self.agent_bound = agent_bound;
        self
    }

    async fn authorize_connect(&self, name: &str, cfg: &ServerConfig) -> Result<()> {
        if matches!(self.approval_mode, ApprovalMode::Yolo) {
            return Ok(());
        }
        let Some(approver) = self.approver.as_ref() else {
            bail!("MCP server `{name}` was not connected: no approval client is attached");
        };
        let identity = cfg.connect_identity(name)?;
        match approver
            .authorize(AuthorizationRequest::McpServerConnect {
                server: name,
                identity: &identity,
                agent_bound: self.agent_bound,
            })
            .await?
        {
            Decision::Allow { .. } => Ok(()),
            Decision::NoninteractiveDeny => bail!(crate::approval::NONINTERACTIVE_RUN_DENIAL),
            Decision::StandingReject { scope } => bail!(crate::approval::standing_reject_refusal(
                "mcp server",
                scope
            )),
            Decision::Deny => bail!("MCP server `{name}` connection was not approved"),
        }
    }

    #[cfg(test)]
    pub(crate) fn yolo_for_tests() -> Self {
        Self {
            approval_mode: ApprovalMode::Yolo,
            ..Self::default()
        }
    }

    fn stdio_runtime(&self) -> StdioRuntimeContext {
        StdioRuntimeContext {
            cancel: self.cancel.clone(),
            abandon_scope: self.stdio_abandon_scope.clone(),
        }
    }
}

fn server_requires_secret_store(cfg: &ServerConfig) -> bool {
    if !cfg.env_credential_refs.is_empty() {
        return true;
    }
    cfg.iter_auth_profiles().any(|(_, auth)| match auth {
        Auth::Header(header) => header.credential_ref.is_some(),
        Auth::Env(env) => !env.credential_refs.is_empty(),
        Auth::Oauth(_) => true,
        Auth::None => false,
    })
}

/// Build and `initialize` a client for `server`, applying its auth.
/// Remote transports get resolved headers (including a refreshed OAuth
/// bearer); stdio gets the merged env.
pub async fn connect(name: &str, cfg: &ServerConfig) -> Result<Box<dyn McpClient>> {
    connect_with_context(name, cfg, McpConnectContext::default()).await
}

pub async fn connect_with_context(
    name: &str,
    cfg: &ServerConfig,
    context: McpConnectContext,
) -> Result<Box<dyn McpClient>> {
    context.authorize_connect(name, cfg).await?;
    // Re-derive the same non-secret identity that the authorization prompt
    // bound. Every concrete transport boundary below compares this exact
    // value with its opaque selected capability; headers and credential
    // material are intentionally not part of this identity.
    let connection_effect = serde_json::json!({
        "connect": {
            "server": name,
            "identity": cfg.connect_identity(name)?,
        }
    });
    // Owner-scoped resolution: when the daemon supplies the owning workspace
    // root, this MCP server may only resolve `mcp:` secrets owned by (mcp, that
    // root) — a foreign/cross-kind name fails closed. Callers without a root
    // (no vault or non-daemon) keep the unscoped view.
    // Canonicalize the owning workspace root once (the same form every ownership
    // claim/query uses) and reuse it for the scoped store and the OAuth refresh
    // guard below, so a symlink/trailing-slash spelling can't split resolution
    // from the claim.
    let canonical_root = context
        .project_root
        .as_deref()
        .map(crate::secret_ownership::canonical_owner_root);
    let mut store = match (context.vault.as_ref(), canonical_root.as_deref()) {
        (Some(vault), Some(project_root)) => Some(
            crate::credentials::CredentialStore::from_vault_owner_scoped(
                vault.clone(),
                crate::secret_ownership::OWNER_KIND_MCP,
                project_root,
                &auth::named_secret_references_for(name, cfg, &context.credential_profile),
                // The MCP connect boundary has no cross-config scan; sole-ownership
                // of an unclaimed legacy name is unprovable, so never lazily claim
                // (fail closed on unclaimed). Owned `mcp:` names still resolve.
                None,
            )?,
        ),
        (Some(vault), None) => Some(crate::credentials::CredentialStore::from_vault(
            vault.clone(),
        )?),
        (None, _) => None,
    };
    if store.is_none() && server_requires_secret_store(cfg) {
        bail!("MCP server `{name}` requires an injected vault-backed store for credential refs");
    }
    let mut resolved = auth::resolve_static_for_server_with_store(name, cfg, store.as_ref());
    // OAuth bearer (async; refreshes if expired) → Authorization header.
    if let Some(bearer) = auth::oauth_bearer_with_store_for(
        name,
        &context.credential_profile,
        cfg,
        store.as_mut(),
        canonical_root.as_deref(),
    )
    .await?
    {
        resolved.headers.insert("Authorization".to_string(), bearer);
    }

    let mut client: Box<dyn McpClient> = match cfg.transport {
        Transport::Streamable => {
            if let Some(error) = resolved.header_errors.first() {
                bail!("{error}");
            }

            let endpoint = cfg.require_endpoint(name)?;
            let timeouts =
                McpTimeouts::from_secs(cfg.connect_timeout_secs(), cfg.request_timeout_secs());
            Box::new(HttpClient::new(endpoint, resolved.headers, timeouts)?)
        }
        Transport::Sse => {
            if let Some(error) = resolved.header_errors.first() {
                bail!("{error}");
            }
            let endpoint = cfg.require_endpoint(name)?;
            let timeouts =
                McpTimeouts::from_secs(cfg.connect_timeout_secs(), cfg.request_timeout_secs());
            Box::new(SseClient::new(endpoint, resolved.headers, timeouts)?)
        }
        Transport::Stdio => {
            let command = cfg.require_command(name)?;
            let timeouts =
                McpTimeouts::from_secs(cfg.connect_timeout_secs(), cfg.request_timeout_secs());
            let connect_deadline = Instant::now() + timeouts.connect;
            // The subprocess is the concrete connect effect. Credential
            // resolution above may await, so recheck only here, immediately
            // before ownership transfers to the host process table.
            crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                "mcp_stdio_connect_spawn",
                &[connection_effect.clone()],
            )
            .await?;
            let mut client = match tokio::time::timeout(timeouts.connect, async {
                StdioClient::spawn(
                    name,
                    command,
                    &cfg.args,
                    &resolved.env,
                    timeouts,
                    context.stdio_runtime(),
                )
            })
            .await
            {
                Ok(result) => result?,
                Err(_) => {
                    return Err(crate::mcp::child_failure::ChildFailure::timeout(
                        name,
                        "spawn_deadline_exceeded_connection_reset",
                    )
                    .into());
                }
            };
            let remaining = connect_deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                "mcp_initialize_request",
                &[connection_effect.clone()],
            )
            .await?;
            match tokio::time::timeout(remaining, client.initialize_with_deadline(remaining)).await
            {
                Ok(Ok(())) => return Ok(Box::new(client)),
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    client.poison("initialize timeout").await;
                    return Err(crate::mcp::child_failure::ChildFailure::timeout(
                        name,
                        "initialize_deadline_exceeded_connection_reset",
                    )
                    .into());
                }
            }
        }
    };
    // HTTP/SSE construction is local; initialization sends the first remote
    // request and is therefore their concrete network boundary.
    crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
        "mcp_initialize_request",
        &[connection_effect],
    )
    .await?;
    client.initialize().await?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::config::{Auth, HeaderAuth};

    fn remote_server_with_header(value: &str) -> ServerConfig {
        ServerConfig {
            transport: Transport::Streamable,
            endpoint: Some("https://example.invalid/mcp".into()),
            command: None,
            args: vec![],
            env: Default::default(),
            env_credential_refs: Default::default(),
            auth: Auth::Header(HeaderAuth {
                header: "X-Key".into(),
                value: value.into(),
                credential_ref: None,
            }),
            mode: Default::default(),
            enabled: true,
            cache_ttl_secs: 3600,
            connect_timeout_secs: None,
            timeout_secs: None,
            profiles: BTreeMap::new(),
        }
    }

    fn denied_stdio_server(marker: &std::path::Path) -> ServerConfig {
        ServerConfig {
            transport: Transport::Stdio,
            endpoint: None,
            command: Some("sh".into()),
            args: vec!["-c".into(), format!("touch {}", marker.display())],
            env: Default::default(),
            env_credential_refs: Default::default(),
            auth: Default::default(),
            mode: Default::default(),
            enabled: true,
            cache_ttl_secs: 0,
            connect_timeout_secs: None,
            timeout_secs: None,
            profiles: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn connect_without_vault_fails_closed_on_credential_ref() {
        let mut cfg = remote_server_with_header("fallback-must-not-be-used");
        if let Auth::Header(header) = &mut cfg.auth {
            header.credential_ref = Some("mcp-header-secret".into());
        }
        let error = match connect_with_context("example", &cfg, McpConnectContext::yolo_for_tests())
            .await
        {
            Ok(_) => panic!("credential-ref MCP connect must not proceed without a vault"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("injected vault-backed store"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn stdio_server_connect_requires_approval() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("spawned");
        let error = match connect("stdio", &denied_stdio_server(&marker)).await {
            Ok(_) => panic!("connection unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no approval client"));
        assert!(
            !marker.exists(),
            "connect authorization must happen before spawn"
        );
    }

    #[tokio::test]
    async fn remote_server_connect_requires_approval() {
        let error = match connect("remote", &remote_server_with_header("Bearer public")).await {
            Ok(_) => panic!("connection unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no approval client"));
    }

    #[test]
    fn configured_servers_are_not_approved_eagerly() {
        let temp = tempfile::tempdir().unwrap();
        let mut cfg = crate::mcp::config::McpConfig::default();
        let markers = [
            temp.path().join("one"),
            temp.path().join("two"),
            temp.path().join("three"),
        ];
        for (index, marker) in markers.iter().enumerate() {
            cfg.servers
                .insert(format!("server-{index}"), denied_stdio_server(marker));
        }
        // Configuration/discovery enumerates all servers but does not call the
        // connection seam, so no command is spawned or approval requested.
        assert_eq!(cfg.enabled_servers().len(), 3);
        assert!(markers.iter().all(|marker| !marker.exists()));
    }

    #[tokio::test]
    async fn connect_without_approver_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("spawned");
        let error = match connect("stdio", &denied_stdio_server(&marker)).await {
            Ok(_) => panic!("connection unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no approval client"));
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn remote_header_auth_missing_env_fails_before_connect() {
        let cfg = remote_server_with_header("Bearer $COCKPIT_TEST_MISSING_MCP_HEADER_TOKEN");

        let context = McpConnectContext {
            approval_mode: ApprovalMode::Yolo,
            ..McpConnectContext::default()
        };
        let message = match connect_with_context("remote", &cfg, context).await {
            Ok(_) => panic!("connection unexpectedly succeeded"),
            Err(error) => error.to_string(),
        };

        assert!(
            message.contains("COCKPIT_TEST_MISSING_MCP_HEADER_TOKEN"),
            "{message}"
        );
        assert!(message.contains("X-Key"), "{message}");
    }
}
