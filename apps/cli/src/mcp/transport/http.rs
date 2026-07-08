//! Streamable HTTP transport (modern remote MCP servers).
//!
//! POSTs JSON-RPC directly to one endpoint; the server replies with
//! either `application/json` or `text/event-stream` (a single framed
//! message), both of which we parse into a [`JsonRpcResponse`].

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde_json::Value;

use crate::mcp::protocol::{
    JsonRpcRequest, JsonRpcResponse, McpClient, ToolDescriptor, initialize_params, parse_tools_list,
};
use crate::mcp::transport::timeout::{McpTimeouts, timeout_error};

pub struct HttpClient {
    endpoint: String,
    headers: BTreeMap<String, String>,
    http: reqwest::Client,
    next_id: u64,
}

impl HttpClient {
    pub fn new(
        endpoint: impl Into<String>,
        headers: BTreeMap<String, String>,
        timeouts: McpTimeouts,
    ) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint.into(),
            headers,
            http: crate::mcp::transport::timeout::client(timeouts)?,
            next_id: 1,
        })
    }

    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        let id = self.next_id;
        self.next_id += 1;
        let req = JsonRpcRequest::new(id, method, params);
        let mut builder = self
            .http
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .json(&req);
        for (k, v) in &self.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let resp = builder
            .send()
            .await
            .map_err(|error| timeout_error("MCP HTTP request", error))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("MCP HTTP {status}: {body}");
        }
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let text = resp.text().await?;
        let json = if ctype.contains("text/event-stream") {
            extract_sse_json(&text).context("no JSON-RPC message in SSE response")?
        } else {
            text
        };
        serde_json::from_str(&json).context("parsing MCP HTTP response")
    }

    #[cfg(test)]
    async fn test_request(&mut self) -> Result<JsonRpcResponse> {
        self.request("tools/list", None).await
    }
}

/// Extract the JSON payload from the first `data:` line of an SSE frame.
pub(crate) fn extract_sse_json(body: &str) -> Option<String> {
    let mut data = String::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.trim_start());
        }
    }
    if data.is_empty() { None } else { Some(data) }
}

#[async_trait]
impl McpClient for HttpClient {
    async fn initialize(&mut self) -> Result<()> {
        self.request("initialize", Some(initialize_params()))
            .await?
            .into_result()?;
        Ok(())
    }

    async fn list_tools(&mut self) -> Result<Vec<ToolDescriptor>> {
        let result = self.request("tools/list", None).await?.into_result()?;
        parse_tools_list(&result)
    }

    async fn call_tool(&mut self, name: &str, args: Value) -> Result<Value> {
        let params = serde_json::json!({ "name": name, "arguments": args });
        self.request("tools/call", Some(params))
            .await?
            .into_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_json_from_sse_frame() {
        let body = "event: message\ndata: {\"result\":{\"tools\":[]}}\n\n";
        let json = extract_sse_json(body).unwrap();
        assert_eq!(json, "{\"result\":{\"tools\":[]}}");
    }

    #[test]
    fn extracts_multiline_sse_data() {
        let body = "data: {\"a\":1,\ndata: \"b\":2}\n";
        let json = extract_sse_json(body).unwrap();
        assert_eq!(json, "{\"a\":1,\n\"b\":2}");
    }

    #[test]
    fn no_data_returns_none() {
        assert!(extract_sse_json("event: ping\n\n").is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn request_timeout_returns_tool_error_without_real_sleep() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 1024];
            let _ = socket.read(&mut buf).await;
            futures::future::pending::<()>().await;
        });

        let mut client = HttpClient::new(
            format!("http://{addr}/mcp"),
            BTreeMap::new(),
            McpTimeouts::from_secs(10, 1),
        )
        .unwrap();
        let task = tokio::spawn(async move { client.test_request().await });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;

        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("MCP HTTP request timed out"));
    }
}
