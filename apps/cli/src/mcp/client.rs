//! Construct an [`McpClient`] for a configured server, resolving auth
//! (static headers/env + OAuth bearer) per transport.

use anyhow::Result;

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
            let endpoint = cfg.require_endpoint(name)?;
            let timeouts =
                McpTimeouts::from_secs(cfg.connect_timeout_secs(), cfg.request_timeout_secs());
            Box::new(HttpClient::new(endpoint, resolved.headers, timeouts)?)
        }
        Transport::Sse => {
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
