//! Construct an [`McpClient`] for a configured server, resolving auth
//! (static headers/env + OAuth bearer) per transport.

use anyhow::{Result, bail};

use super::auth;
use super::config::{ServerConfig, Transport};
use super::protocol::McpClient;
use super::transport::timeout::McpTimeouts;
use super::transport::{http::HttpClient, sse::SseClient, stdio::StdioClient};

/// Build and `initialize` a client for `server`, applying its auth.
/// Remote transports get resolved headers (including a refreshed OAuth
/// bearer); stdio gets the merged env.
pub async fn connect(name: &str, cfg: &ServerConfig) -> Result<Box<dyn McpClient>> {
    let mut resolved = auth::resolve_static_for_server(name, cfg);
    // OAuth bearer (async; refreshes if expired) → Authorization header.
    if let Some(bearer) = auth::oauth_bearer(name, cfg).await? {
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
            Box::new(StdioClient::spawn(command, &cfg.args, &resolved.env)?)
        }
    };
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
        }
    }

    #[tokio::test]
    async fn remote_header_auth_missing_env_fails_before_connect() {
        let cfg = remote_server_with_header("Bearer $COCKPIT_TEST_MISSING_MCP_HEADER_TOKEN");

        let message = match connect("remote", &cfg).await {
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
