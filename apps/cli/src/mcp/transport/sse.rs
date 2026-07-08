//! Legacy SSE transport.
//!
//! GET the SSE endpoint; the server's first `endpoint` event names the
//! POST URL for JSON-RPC requests, and subsequent `message` events carry
//! responses. We open the stream, read the POST URL, then for each
//! request POST and await the matching streamed response.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use futures::StreamExt;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::mcp::protocol::{
    JsonRpcRequest, JsonRpcResponse, McpClient, ToolDescriptor, initialize_params, parse_tools_list,
};
use crate::mcp::transport::timeout::{McpTimeouts, timeout_error, with_request_timeout};

const SSE_FRAME_MAX_BYTES: usize = 256 * 1024;
pub(crate) const SSE_PENDING_CHANNEL_CAP: usize = 128;

pub struct SseClient {
    endpoint: String,
    headers: BTreeMap<String, String>,
    http: reqwest::Client,
    timeouts: McpTimeouts,
    next_id: u64,
    /// Resolved POST URL + the streamed-message receiver, set on connect.
    post_url: Option<String>,
    rx: Option<mpsc::Receiver<std::result::Result<Value, SseFrameError>>>,
    _pump: Option<tokio::task::JoinHandle<()>>,
}

impl SseClient {
    pub fn new(
        endpoint: impl Into<String>,
        headers: BTreeMap<String, String>,
        timeouts: McpTimeouts,
    ) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint.into(),
            headers,
            http: crate::mcp::transport::timeout::client(timeouts)?,
            timeouts,
            next_id: 1,
            post_url: None,
            rx: None,
            _pump: None,
        })
    }

    /// Open the SSE stream, capture the POST URL from the first `endpoint`
    /// event, and spawn a pump that forwards `message` JSON payloads.
    async fn connect(&mut self) -> Result<()> {
        let mut builder = self
            .http
            .get(&self.endpoint)
            .header("Accept", "text/event-stream");
        for (k, v) in &self.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let resp = builder
            .send()
            .await
            .map_err(|error| timeout_error("opening MCP SSE stream", error))?;
        if !resp.status().is_success() {
            bail!("MCP SSE {}", resp.status());
        }
        let mut stream = resp.bytes_stream();

        // Read until we see the `endpoint` event naming the POST URL.
        let mut acc = String::new();
        let mut post_url: Option<String> = None;
        'outer: while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            acc.push_str(&String::from_utf8_lossy(&chunk));
            if acc.len() > SSE_FRAME_MAX_BYTES {
                return Err(SseFrameError::new(acc.len()).into());
            }
            while let Some(idx) = acc.find("\n\n") {
                let frame: String = acc.drain(..idx + 2).collect();
                if let Some((event, data)) = parse_sse_frame(&frame)?
                    && event.as_deref() == Some("endpoint")
                {
                    post_url = Some(absolutize(&self.endpoint, &data));
                    break 'outer;
                }
            }
        }
        let post_url = post_url.context("MCP SSE server never sent an `endpoint` event")?;

        // Pump remaining `message` frames into a channel.
        let (tx, rx) = mpsc::channel(SSE_PENDING_CHANNEL_CAP);
        let pump = tokio::spawn(async move {
            let mut acc = acc;
            while let Some(Ok(chunk)) = stream.next().await {
                acc.push_str(&String::from_utf8_lossy(&chunk));
                if acc.len() > SSE_FRAME_MAX_BYTES {
                    let _ = tx.send(Err(SseFrameError::new(acc.len()))).await;
                    return;
                }
                while let Some(idx) = acc.find("\n\n") {
                    let frame: String = acc.drain(..idx + 2).collect();
                    let parsed = match parse_sse_frame(&frame) {
                        Ok(parsed) => parsed,
                        Err(err) => {
                            let _ = tx.send(Err(err)).await;
                            return;
                        }
                    };
                    if let Some((_event, data)) = parsed
                        && let Ok(val) = serde_json::from_str::<Value>(&data)
                        && tx.send(Ok(val)).await.is_err()
                    {
                        return;
                    }
                }
            }
        });

        self.post_url = Some(post_url);
        self.rx = Some(rx);
        self._pump = Some(pump);
        Ok(())
    }

    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        if self.post_url.is_none() {
            with_request_timeout("opening MCP SSE stream", self.timeouts, self.connect()).await?;
        }
        let post_url = self.post_url.clone().unwrap();
        let id = self.next_id;
        self.next_id += 1;
        let req = JsonRpcRequest::new(id, method, params);
        let mut builder = self
            .http
            .post(&post_url)
            .header("Content-Type", "application/json")
            .json(&req);
        for (k, v) in &self.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let resp = builder
            .send()
            .await
            .map_err(|error| timeout_error("MCP SSE POST", error))?;
        if !resp.status().is_success() {
            bail!("MCP SSE POST {}", resp.status());
        }
        // Await the matching streamed response.
        let rx = self.rx.as_mut().context("SSE stream not connected")?;
        loop {
            let val = match tokio::time::timeout(self.timeouts.request, rx.recv()).await {
                Ok(Some(Ok(value))) => value,
                Ok(Some(Err(error))) => return Err(error.into()),
                Ok(None) => bail!("MCP SSE stream ended before response"),
                Err(_) => bail!("MCP SSE response timed out"),
            };
            match val.get("id").and_then(Value::as_u64) {
                Some(rid) if rid == id => return Ok(serde_json::from_value(val)?),
                _ => continue,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SseFrameError {
    bytes: usize,
    max: usize,
}

impl SseFrameError {
    fn new(bytes: usize) -> Self {
        Self {
            bytes,
            max: SSE_FRAME_MAX_BYTES,
        }
    }
}

impl fmt::Display for SseFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MCP SSE event frame exceeded {} byte limit ({} bytes)",
            self.max, self.bytes
        )
    }
}

impl std::error::Error for SseFrameError {}

/// Parse a single SSE frame into `(event, data)`. `data` lines are joined
/// by newlines per the SSE spec.
pub(crate) fn parse_sse_frame(
    frame: &str,
) -> std::result::Result<Option<(Option<String>, String)>, SseFrameError> {
    if frame.len() > SSE_FRAME_MAX_BYTES {
        return Err(SseFrameError::new(frame.len()));
    }
    let mut event = None;
    let mut data = String::new();
    for line in frame.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            event = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.trim_start());
        }
    }
    if data.is_empty() && event.is_none() {
        return Ok(None);
    }
    Ok(Some((event, data)))
}

/// Resolve a possibly-relative `endpoint` event URL against the SSE base.
fn absolutize(base: &str, target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.to_string();
    }
    // Relative path: take scheme+host from base.
    if let Some(scheme_end) = base.find("://") {
        let after = &base[scheme_end + 3..];
        if let Some(slash) = after.find('/') {
            let origin = &base[..scheme_end + 3 + slash];
            if target.starts_with('/') {
                return format!("{origin}{target}");
            }
            return format!("{origin}/{target}");
        }
    }
    target.to_string()
}

#[async_trait]
impl McpClient for SseClient {
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
    fn parses_endpoint_frame() {
        let frame = "event: endpoint\ndata: /messages?session=abc\n\n";
        let (event, data) = parse_sse_frame(frame).unwrap().unwrap();
        assert_eq!(event.as_deref(), Some("endpoint"));
        assert_eq!(data, "/messages?session=abc");
    }

    #[test]
    fn rejects_oversized_sse_frame() {
        let data = "x".repeat(SSE_FRAME_MAX_BYTES + 1);
        let frame = format!("event: message\ndata: {data}\n\n");
        let err = parse_sse_frame(&frame).unwrap_err();
        assert!(err.to_string().contains("exceeded"));
    }

    #[test]
    fn pending_message_channel_is_bounded() {
        let (tx, _rx) =
            mpsc::channel::<std::result::Result<Value, SseFrameError>>(SSE_PENDING_CHANNEL_CAP);
        for idx in 0..SSE_PENDING_CHANNEL_CAP {
            tx.try_send(Ok(serde_json::json!({ "id": idx }))).unwrap();
        }
        let err = tx
            .try_send(Ok(serde_json::json!({ "id": "overflow" })))
            .unwrap_err();
        assert!(matches!(err, mpsc::error::TrySendError::Full(_)));
    }

    #[test]
    fn absolutizes_relative_endpoint() {
        assert_eq!(
            absolutize("https://h.example.com/sse", "/messages?s=1"),
            "https://h.example.com/messages?s=1"
        );
        assert_eq!(
            absolutize("https://h.example.com/sse", "https://other/x"),
            "https://other/x"
        );
    }
}
