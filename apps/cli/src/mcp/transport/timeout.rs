use std::time::Duration;

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpTimeouts {
    pub connect: Duration,
    pub request: Duration,
}

impl McpTimeouts {
    pub fn from_secs(connect_timeout_secs: u64, timeout_secs: u64) -> Self {
        Self {
            connect: Duration::from_secs(connect_timeout_secs),
            request: Duration::from_secs(timeout_secs),
        }
    }
}

pub fn client(timeouts: McpTimeouts) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.request)
        .build()
        .context("building MCP HTTP client")
}

pub fn timeout_error(label: &str, error: reqwest::Error) -> anyhow::Error {
    if error.is_timeout() {
        anyhow::anyhow!("{label} timed out")
    } else {
        anyhow::Error::new(error).context(label.to_string())
    }
}

pub async fn with_request_timeout<T, F>(label: &str, timeouts: McpTimeouts, fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::time::timeout(timeouts.request, fut).await {
        Ok(result) => result,
        Err(_) => bail!("{label} timed out"),
    }
}
