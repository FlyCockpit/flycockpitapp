use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use rig::providers::{anthropic, chatgpt, openai};

use super::wire::{normalize_openai_usage_aliases_bytes, take_normalized_sse_lines};

const PROVIDER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
// Errors and finite successes are bounded before Rig can collect them. SSE
// additionally has a per-line cap and a finite per-response wire-byte budget.
const MAX_INFERENCE_ERROR_BYTES: usize = 8 * 1024 * 1024;
const MAX_INFERENCE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_INFERENCE_STREAM_BYTES: usize = 64 * 1024 * 1024;
const INFERENCE_BODY_TIMEOUT: Duration = Duration::from_secs(120);

fn transport_error(
    error: impl std::error::Error + Send + Sync + 'static,
) -> rig::http_client::Error {
    rig::http_client::Error::Instance(Box::new(error))
}

async fn read_inference_body(
    mut response: reqwest::Response,
    limit: usize,
) -> rig::http_client::Result<bytes::Bytes> {
    let read = async move {
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(transport_error(std::io::Error::other(format!(
                "provider response body exceeded {limit} byte limit"
            ))));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
            if body.len().saturating_add(chunk.len()) > limit {
                return Err(transport_error(std::io::Error::other(format!(
                    "provider response body exceeded {limit} byte limit"
                ))));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(bytes::Bytes::from(body))
    };
    tokio::time::timeout(INFERENCE_BODY_TIMEOUT, read)
        .await
        .map_err(transport_error)?
}

async fn check_inference_status(
    response: reqwest::Response,
) -> rig::http_client::Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let headers = Box::new(response.headers().clone());
    // Keep status and retry headers even when the bounded reader rejects the
    // body. Oversized/failed bodies are dropped, never sent to Rig's collector.
    let body = match read_inference_body(response, MAX_INFERENCE_ERROR_BYTES).await {
        Ok(body) => String::from_utf8_lossy(&body).into_owned(),
        Err(error) => error.to_string(),
    };
    Err(rig::http_client::Error::InvalidStatusCodeWithDetails {
        status,
        body,
        headers,
    })
}

async fn lazy_inference_response<U: From<bytes::Bytes> + Send + 'static>(
    response: reqwest::Response,
) -> rig::http_client::Result<rig::http_client::Response<rig::http_client::LazyBody<U>>> {
    let response = check_inference_status(response).await?;
    let mut builder = rig::http_client::Response::builder()
        .status(response.status())
        .version(response.version());
    *builder.headers_mut().expect("valid response status") = response.headers().clone();
    let body: rig::http_client::LazyBody<U> = Box::pin(async move {
        let bytes = read_inference_body(response, MAX_INFERENCE_RESPONSE_BYTES).await?;
        retain_anthropic_native_items_from_response(&bytes);
        Ok(U::from(normalize_openai_usage_aliases_bytes(bytes)))
    });
    builder
        .body(body)
        .map_err(rig::http_client::Error::Protocol)
}

/// Maximum bytes the SSE line-normalizer may buffer waiting for a `\n`.
///
/// The provider stream is drained line-by-line: `take_normalized_sse_lines`
/// emits every complete `\n`-terminated line and `pending` holds only the
/// trailing partial line between chunks. A provider (or a MITM on a
/// misconfigured `base_url`) that never emits a newline would otherwise grow
/// `pending` without bound and OOM the daemon. Real SSE events are small token
/// deltas, so this cap is far above any legitimate single line while still
/// bounding worst-case memory; crossing it aborts the stream as hostile.
const MAX_SSE_PENDING_BYTES: usize = 16 * 1024 * 1024;

// `openai::Client` is rig's *Responses API* client (POSTs `/responses`).
// Most OpenAI-compatible providers in `src/providers/mod.rs` (z.ai, MiniMax,
// OpenCode Zen, generic openai-compatible, Ollama) speak the *Chat
// Completions* API, so `Model::OpenAi` retains a `CompletionsClient` and
// selects its Responses view only when the configured wire is `responses`.
pub(super) type OpenAiCompatClient = openai::CompletionsClient<UsageAliasHttpClient>;
pub(super) type ChatGptResponsesModel = chatgpt::ResponsesCompletionModel<UsageAliasHttpClient>;
pub(super) type AnthropicCompletionModel =
    anthropic::completion::CompletionModel<UsageAliasHttpClient>;

#[derive(Clone)]
pub struct UsageAliasHttpClient {
    client: reqwest::Client,
    extra_headers: reqwest::header::HeaderMap,
    strip_codex_headers: bool,
    strip_x_api_key: bool,
}

impl Default for UsageAliasHttpClient {
    fn default() -> Self {
        Self::new(Vec::new()).expect("the canonical User-Agent is a valid header")
    }
}

impl fmt::Debug for UsageAliasHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsageAliasHttpClient")
            .field("extra_headers", &self.extra_headers.len())
            .field("strip_codex_headers", &self.strip_codex_headers)
            .field("strip_x_api_key", &self.strip_x_api_key)
            .finish()
    }
}

impl UsageAliasHttpClient {
    pub(super) fn new(extra_headers: Vec<(String, String)>) -> anyhow::Result<Self> {
        Self::with_header_policy(extra_headers, false, false)
    }

    /// Rig's native Anthropic client requires an API key and therefore adds an
    /// `x-api-key` header itself. Bearer-authenticated Anthropic-compatible
    /// providers must never receive that synthetic header.
    pub(super) fn for_anthropic_bearer(
        extra_headers: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        Self::with_header_policy(extra_headers, false, true)
    }

    /// Requests sent over the generic Responses wire must not receive headers
    /// that identify a ChatGPT/Codex subscription, whether they originate in
    /// rig or provider configuration. A generic client may recover between
    /// Completions and Responses without being rebuilt, so this is enforced
    /// per request rather than at construction time.
    pub(super) fn without_codex_headers(
        extra_headers: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        Self::with_header_policy(extra_headers, true, false)
    }

    fn with_header_policy(
        extra_headers: Vec<(String, String)>,
        strip_codex_headers: bool,
        strip_x_api_key: bool,
    ) -> anyhow::Result<Self> {
        let extra_headers = with_canonical_user_agent(extra_headers);
        let mut validated = reqwest::header::HeaderMap::new();
        for (name, value) in extra_headers {
            validated.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes())?,
                reqwest::header::HeaderValue::from_str(&value)?,
            );
        }
        let client = crate::providers::provider_http::client_builder()
            .connect_timeout(PROVIDER_CONNECT_TIMEOUT)
            .build()
            .context("building credentialed inference HTTP client")?;
        Ok(Self {
            client,
            extra_headers: validated,
            strip_codex_headers,
            strip_x_api_key,
        })
    }
}

fn with_canonical_user_agent(mut headers: Vec<(String, String)>) -> Vec<(String, String)> {
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(reqwest::header::USER_AGENT.as_str()))
    {
        headers.push((
            reqwest::header::USER_AGENT.as_str().to_string(),
            crate::user_agent::user_agent().to_string(),
        ));
    }
    headers
}

fn apply_extra_headers<T>(
    req: rig::http_client::Request<T>,
    headers: &reqwest::header::HeaderMap,
    strip_codex_headers: bool,
    strip_x_api_key: bool,
) -> rig::http_client::Request<T> {
    let (mut parts, body) = req.into_parts();
    for (name, value) in headers {
        parts.headers.insert(name.clone(), value.clone());
    }
    if strip_codex_headers && parts.uri.path().ends_with("/responses") {
        for name in [
            "chatgpt-account-id",
            "originator",
            "openai-beta",
            "session_id",
        ] {
            parts.headers.remove(name);
        }
    }
    if strip_x_api_key {
        parts.headers.remove("x-api-key");
    }
    rig::http_client::Request::from_parts(parts, body)
}

fn retain_anthropic_native_items_from_response(bytes: &[u8]) {
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return;
    };
    let Some(content) = body.get("content").and_then(serde_json::Value::as_array) else {
        return;
    };
    for item in content {
        if item.get("type").and_then(serde_json::Value::as_str) == Some("tool_use")
            && item.get("name").and_then(serde_json::Value::as_str) == Some("computer")
        {
            super::retain_native_computer_item(item.clone());
        }
    }
}

#[derive(Default)]
struct AnthropicNativeStreamCapture {
    blocks: std::collections::HashMap<u64, AnthropicNativeToolBlock>,
}

struct AnthropicNativeToolBlock {
    id: Option<String>,
    input: serde_json::Value,
    partial_json: String,
}

impl AnthropicNativeStreamCapture {
    /// Assemble native computer blocks from Anthropic's raw SSE events at the
    /// provider boundary. Generic Rig `ToolCall` JSON is never an extraction
    /// source for this path.
    fn ingest(&mut self, bytes: &[u8]) {
        for line in bytes.split(|byte| *byte == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some(data) = line.strip_prefix(b"data:") else {
                continue;
            };
            let data = data.strip_prefix(b" ").unwrap_or(data);
            if data == b"[DONE]" {
                continue;
            }
            let Ok(event) = serde_json::from_slice::<serde_json::Value>(data) else {
                continue;
            };
            let Some(index) = event.get("index").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            match event.get("type").and_then(serde_json::Value::as_str) {
                Some("content_block_start") => {
                    let Some(block) = event.get("content_block") else {
                        continue;
                    };
                    if block.get("type").and_then(serde_json::Value::as_str) != Some("tool_use")
                        || block.get("name").and_then(serde_json::Value::as_str) != Some("computer")
                    {
                        continue;
                    }
                    self.blocks.insert(
                        index,
                        AnthropicNativeToolBlock {
                            id: block
                                .get("id")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            input: block
                                .get("input")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null),
                            partial_json: String::new(),
                        },
                    );
                }
                Some("content_block_delta") => {
                    let Some(block) = self.blocks.get_mut(&index) else {
                        continue;
                    };
                    if let Some(partial) = event
                        .get("delta")
                        .and_then(|delta| delta.get("partial_json"))
                        .and_then(serde_json::Value::as_str)
                    {
                        block.partial_json.push_str(partial);
                    }
                }
                Some("content_block_stop") => {
                    let Some(block) = self.blocks.remove(&index) else {
                        continue;
                    };
                    let input = if block.partial_json.is_empty() {
                        block.input
                    } else {
                        serde_json::from_str(&block.partial_json).unwrap_or(serde_json::Value::Null)
                    };
                    let mut item = serde_json::json!({
                        "type": "tool_use",
                        "name": "computer",
                        "input": input,
                    });
                    if let Some(id) = block.id {
                        item["id"] = serde_json::Value::String(id);
                    }
                    super::retain_native_computer_item(item);
                }
                _ => {}
            }
        }
    }
}

fn inject_native_computer_continuations(bytes: bytes::Bytes) -> bytes::Bytes {
    let Ok(mut body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return bytes;
    };
    let native_tool_type = body
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .and_then(|tools| {
            tools.iter().find_map(|tool| {
                tool.get("type")
                    .and_then(serde_json::Value::as_str)
                    .filter(|tool_type| {
                        crate::computer::is_reserved_native_computer_tool_name(tool_type)
                    })
            })
        });
    let target = if native_tool_type == Some(crate::computer::OPENAI_COMPUTER_TOOL_TYPE)
        && body
            .get("input")
            .and_then(serde_json::Value::as_array)
            .is_some()
    {
        Some(super::NativeComputerContinuationWire::OpenAiResponses)
    } else if (native_tool_type == Some(crate::computer::ANTHROPIC_COMPUTER_TOOL_TYPE_20251124)
        || native_tool_type == Some(crate::computer::ANTHROPIC_COMPUTER_TOOL_TYPE_20250124))
        && body
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .and_then(|messages| messages.last())
            .and_then(|message| message.get("content"))
            .and_then(serde_json::Value::as_array)
            .is_some()
    {
        Some(super::NativeComputerContinuationWire::AnthropicMessages)
    } else {
        None
    };
    let Some(target) = target else {
        return bytes;
    };
    let continuations = super::take_native_computer_continuations(target);
    if continuations.is_empty() {
        return bytes;
    }
    if let Some(input) = body
        .get_mut("input")
        .and_then(serde_json::Value::as_array_mut)
    {
        input.extend(continuations);
    } else if let Some(messages) = body
        .get_mut("messages")
        .and_then(serde_json::Value::as_array_mut)
    {
        // Anthropic requires every `tool_result` to follow the exact assistant
        // `tool_use` that introduced its ID. Rig does not retain native
        // computer tool blocks in normal assistant history, so keep that raw
        // provider action only until this immediate follow-up request and
        // reconstruct the provider-native assistant/user pair here.
        let (assistant_actions, user_results): (Vec<_>, Vec<_>) =
            continuations.into_iter().partition(|item| {
                item.get("type").and_then(serde_json::Value::as_str) == Some("tool_use")
            });
        if assistant_actions.is_empty() || user_results.is_empty() {
            return bytes;
        }
        messages.push(serde_json::json!({
            "role": "assistant",
            "content": assistant_actions,
        }));
        messages.push(serde_json::json!({
            "role": "user",
            "content": user_results,
        }));
    } else {
        return bytes;
    }
    serde_json::to_vec(&body)
        .map(bytes::Bytes::from)
        .unwrap_or(bytes)
}

impl rig::http_client::HttpClientExt for UsageAliasHttpClient {
    fn send<T, U>(
        &self,
        req: rig::http_client::Request<T>,
    ) -> impl std::future::Future<
        Output = rig::http_client::Result<
            rig::http_client::Response<rig::http_client::LazyBody<U>>,
        >,
    > + Send
    + 'static
    where
        T: Into<bytes::Bytes>,
        T: Send,
        U: From<bytes::Bytes>,
        U: Send + 'static,
    {
        let client = self.client.clone();
        let req = apply_extra_headers(
            req,
            &self.extra_headers,
            self.strip_codex_headers,
            self.strip_x_api_key,
        );
        let (parts, body) = req.into_parts();
        let req = rig::http_client::Request::from_parts(
            parts,
            inject_native_computer_continuations(body.into()),
        );
        async move {
            let (parts, body) = req.into_parts();
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(transport_error)?;
            lazy_inference_response(response).await
        }
    }

    fn send_multipart<U>(
        &self,
        req: rig::http_client::Request<rig::http_client::MultipartForm>,
    ) -> impl std::future::Future<
        Output = rig::http_client::Result<
            rig::http_client::Response<rig::http_client::LazyBody<U>>,
        >,
    > + Send
    + 'static
    where
        U: From<bytes::Bytes>,
        U: Send + 'static,
    {
        let client = self.client.clone();
        let req = apply_extra_headers(
            req,
            &self.extra_headers,
            self.strip_codex_headers,
            self.strip_x_api_key,
        );
        let (parts, body) = req.into_parts();
        let request = client
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .multipart(reqwest::multipart::Form::from(body));
        async move { lazy_inference_response(request.send().await.map_err(transport_error)?).await }
    }

    fn send_streaming<T>(
        &self,
        req: rig::http_client::Request<T>,
    ) -> impl std::future::Future<
        Output = rig::http_client::Result<rig::http_client::StreamingResponse>,
    > + Send
    where
        T: Into<bytes::Bytes> + Send,
    {
        let client = self.client.clone();
        let req = apply_extra_headers(
            req,
            &self.extra_headers,
            self.strip_codex_headers,
            self.strip_x_api_key,
        );
        let (parts, body) = req.into_parts();
        let req = rig::http_client::Request::from_parts(
            parts,
            inject_native_computer_continuations(body.into()),
        );
        async move {
            let (parts, body) = req.into_parts();
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(transport_error)?;
            let response = check_inference_status(response).await?;
            let mut builder = rig::http_client::Response::builder()
                .status(response.status())
                .version(response.version());
            *builder.headers_mut().expect("valid response status") = response.headers().clone();
            let body = Box::pin(
                response
                    .bytes_stream()
                    .map(|chunk| chunk.map_err(transport_error)),
            );
            let stream: Pin<
                Box<
                    dyn rig::wasm_compat::WasmCompatSendStream<
                            InnerItem = rig::http_client::Result<bytes::Bytes>,
                        >,
                >,
            > = Box::pin(futures::stream::unfold(
                (
                    body,
                    Vec::<u8>::new(),
                    false,
                    AnthropicNativeStreamCapture::default(),
                    0usize,
                ),
                |(mut body, mut pending, aborted, mut native_capture, mut received)| async move {
                    // A prior iteration hit the no-newline cap and yielded a
                    // terminal error; end the stream rather than spin.
                    if aborted {
                        return None;
                    }
                    loop {
                        let normalized = take_normalized_sse_lines(&mut pending, false);
                        if !normalized.is_empty() {
                            native_capture.ingest(&normalized);
                            return Some((
                                Ok(normalized),
                                (body, pending, false, native_capture, received),
                            ));
                        }
                        match body.next().await {
                            Some(Ok(bytes)) => {
                                received = received.saturating_add(bytes.len());
                                if received > MAX_INFERENCE_STREAM_BYTES
                                    || pending.len().saturating_add(bytes.len())
                                        > MAX_SSE_PENDING_BYTES
                                {
                                    let error = rig::http_client::Error::Instance(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::InvalidData,
                                            format!(
                                                "provider SSE stream exceeded its byte budget (received {received}, pending {}, line cap {MAX_SSE_PENDING_BYTES}, response cap {MAX_INFERENCE_STREAM_BYTES})",
                                                pending.len(),
                                            ),
                                        ),
                                    ));
                                    return Some((
                                        Err(error),
                                        (body, pending, true, native_capture, received),
                                    ));
                                }
                                pending.extend_from_slice(&bytes);
                            }
                            Some(Err(e)) => {
                                return Some((
                                    Err(e),
                                    (body, pending, false, native_capture, received),
                                ));
                            }
                            None => {
                                let normalized = take_normalized_sse_lines(&mut pending, true);
                                if normalized.is_empty() {
                                    return None;
                                }
                                native_capture.ingest(&normalized);
                                return Some((
                                    Ok(normalized),
                                    (body, pending, false, native_capture, received),
                                ));
                            }
                        }
                    }
                },
            ));
            builder
                .body(stream)
                .map_err(rig::http_client::Error::Protocol)
        }
    }
}

#[cfg(test)]
mod native_computer_tests {
    use super::*;

    #[tokio::test]
    async fn anthropic_native_stream_capture_retains_raw_provider_block() {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        crate::engine::model::capture_native_computer_items(sink.clone(), async {
            let mut capture = AnthropicNativeStreamCapture::default();
            capture.ingest(
                br#"data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu-raw","name":"computer","input":{}}}
data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"action\":\"screenshot\"}"}}
data: {"type":"content_block_stop","index":2}
"#,
            );
        })
        .await;

        let retained = sink.lock().unwrap().clone();
        assert_eq!(
            retained,
            vec![serde_json::json!({
                "type": "tool_use",
                "id": "toolu-raw",
                "name": "computer",
                "input": {"action": "screenshot"},
            })]
        );
    }

    #[tokio::test]
    async fn native_continuation_is_consumed_once_and_never_crosses_wire_api() {
        let continuation = serde_json::json!({
            "type": "computer_call_output",
            "call_id": "call-once",
            "output": {"type": "text", "text": "done"},
        });
        crate::engine::model::with_native_computer_continuations(vec![continuation], async {
            let anthropic = bytes::Bytes::from_static(
                br#"{"messages":[{"role":"user","content":[]}],"tools":[{"type":"computer_20251124","name":"computer"}]}"#,
            );
            let incompatible = inject_native_computer_continuations(anthropic.clone());
            assert_eq!(incompatible, anthropic);
            assert!(!crate::engine::model::native_computer_continuation_was_dispatched());

            let openai =
                bytes::Bytes::from_static(br#"{"input":[],"tools":[{"type":"computer"}]}"#);
            let first = inject_native_computer_continuations(openai.clone());
            assert!(String::from_utf8_lossy(&first).contains("call-once"));
            assert!(crate::engine::model::native_computer_continuation_was_dispatched());

            let retry = inject_native_computer_continuations(openai.clone());
            assert_eq!(retry, openai);
        })
        .await;
    }

    #[tokio::test]
    async fn anthropic_native_continuation_keeps_matching_assistant_tool_use() {
        let assistant_action = serde_json::json!({
            "type": "tool_use",
            "id": "toolu-computer-1",
            "name": "computer",
            "input": {"action": "screenshot"},
        });
        let tool_result = serde_json::json!({
            "type": "tool_result",
            "tool_use_id": "toolu-computer-1",
            "content": [{"type": "text", "text": "done"}],
        });
        crate::engine::model::with_native_computer_continuations(
            vec![assistant_action, tool_result],
            async {
                let request = bytes::Bytes::from_static(
                    br#"{"messages":[{"role":"user","content":[{"type":"text","text":"continue"}]}],"tools":[{"type":"computer_20251124","name":"computer"}]}"#,
                );
                let injected = inject_native_computer_continuations(request);
                let body: serde_json::Value = serde_json::from_slice(&injected).unwrap();
                let messages = body["messages"].as_array().unwrap();
                assert_eq!(messages.len(), 3);
                assert_eq!(messages[1]["role"], "assistant");
                assert_eq!(messages[1]["content"][0]["id"], "toolu-computer-1");
                assert_eq!(messages[2]["role"], "user");
                assert_eq!(messages[2]["content"][0]["tool_use_id"], "toolu-computer-1");
                assert!(crate::engine::model::native_computer_continuation_was_dispatched());
            },
        )
        .await;
    }
}

#[cfg(test)]
mod redirect_policy_tests {
    use super::*;
    use rig::http_client::HttpClientExt;

    #[tokio::test]
    async fn inference_client_rejects_cross_origin_redirect_without_replaying_api_key() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind inference redirect test server");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut buf = [0_u8; 4096];
            let read = socket.read(&mut buf).await.expect("read request");
            let request = String::from_utf8_lossy(&buf[..read]).into_owned();
            let response = concat!(
                "HTTP/1.1 302 Found\r\n",
                "Location: http://credential-leak.invalid/chat/completions\r\n",
                "Content-Length: 0\r\n",
                "Connection: close\r\n\r\n"
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write redirect");
            request
        });

        let client =
            UsageAliasHttpClient::new(vec![("x-api-key".to_string(), "leaked-secret".to_string())])
                .expect("build inference client");
        let url = format!("http://{addr}/v1/chat/completions");
        let req = rig::http_client::Request::builder()
            .method(rig::http_client::Method::POST)
            .uri(url)
            .body(bytes::Bytes::new())
            .expect("build request");
        let result = client.send::<bytes::Bytes, bytes::Bytes>(req).await;
        let err = match result {
            Ok(response) => panic!(
                "redirect must fail closed before replaying credentials; got status {}",
                response.status()
            ),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(message.contains("302"), "{message}");

        let captured = handle.await.expect("server task");
        assert!(
            captured
                .to_ascii_lowercase()
                .contains("x-api-key: leaked-secret"),
            "{captured}"
        );
    }
}

#[cfg(test)]
mod body_budget_tests {
    use super::*;
    use rig::http_client::HttpClientExt;

    async fn adapter_error(
        client: &UsageAliasHttpClient,
        url: &str,
        mode: u8,
    ) -> rig::http_client::Error {
        let request = rig::http_client::Request::builder().method("POST").uri(url);
        match mode {
            0 => client
                .send::<_, bytes::Bytes>(request.body(bytes::Bytes::new()).unwrap())
                .await
                .err(),
            1 => client
                .send_streaming(request.body(bytes::Bytes::new()).unwrap())
                .await
                .err(),
            2 => client
                .send_multipart::<bytes::Bytes>(
                    request
                        .body(rig::http_client::MultipartForm::new())
                        .unwrap(),
                )
                .await
                .err(),
            _ => unreachable!(),
        }
        .expect("non-success status must fail")
    }

    #[tokio::test]
    async fn inference_adapter_bounds_errors_on_all_three_paths_and_preserves_small_diagnostics() {
        for mode in 0..3 {
            for chunked in [false, true] {
                let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![
                    (
                        401,
                        "useful small authentication diagnostic".into(),
                        chunked,
                    ),
                    (400, "x".repeat(MAX_INFERENCE_ERROR_BYTES + 1), chunked),
                ])
                .await;
                let client = UsageAliasHttpClient::default();
                let small = adapter_error(&client, &url, mode).await;
                match small {
                    rig::http_client::Error::InvalidStatusCodeWithDetails {
                        status,
                        body,
                        headers,
                    } => {
                        assert_eq!(status.as_u16(), 401);
                        assert_eq!(body, "useful small authentication diagnostic");
                        assert_eq!(headers["retry-after"], "0");
                    }
                    error => panic!("lost status/body/headers: {error}"),
                }
                // Same adapter after a first credential failure: retry bodies
                // have the identical bound, independent of mode/framing.
                let error = adapter_error(&client, &url, mode).await;
                match error {
                    rig::http_client::Error::InvalidStatusCodeWithDetails {
                        status, body, ..
                    } => {
                        assert_eq!(status.as_u16(), 400);
                        assert!(
                            body.contains("byte limit"),
                            "mode={mode} chunked={chunked}: body len={}",
                            body.len()
                        );
                        assert!(body.len() < 256, "the overflow body must be dropped");
                    }
                    error => panic!("lost error status: {error}"),
                }
                server.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn inference_adapter_accepts_exact_error_limit_and_bounds_finite_successes() {
        for mode in 0..3 {
            let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![(
                400,
                "x".repeat(MAX_INFERENCE_ERROR_BYTES),
                true,
            )])
            .await;
            let error = adapter_error(&UsageAliasHttpClient::default(), &url, mode).await;
            assert!(
                matches!(error, rig::http_client::Error::InvalidStatusCodeWithDetails {body, ..} if body.len() == MAX_INFERENCE_ERROR_BYTES)
            );
            server.await.unwrap();
        }
        for multipart in [false, true] {
            for (body, overflow) in [
                ("{\"useful\":true}".to_string(), false),
                ("x".repeat(MAX_INFERENCE_RESPONSE_BYTES + 1), true),
            ] {
                let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![(
                    200,
                    body.clone(),
                    true,
                )])
                .await;
                let client = UsageAliasHttpClient::default();
                let builder = rig::http_client::Request::builder().method("POST").uri(url);
                let response = if multipart {
                    client
                        .send_multipart::<bytes::Bytes>(
                            builder
                                .body(rig::http_client::MultipartForm::new())
                                .unwrap(),
                        )
                        .await
                        .unwrap()
                } else {
                    client
                        .send::<_, bytes::Bytes>(builder.body(bytes::Bytes::new()).unwrap())
                        .await
                        .unwrap()
                };
                let received = response.into_body().await;
                if overflow {
                    assert!(received.unwrap_err().to_string().contains("byte limit"));
                } else {
                    assert_eq!(received.unwrap().as_ref(), body.as_bytes());
                }
                server.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn inference_adapter_bounds_stream_success_and_keeps_small_sse() {
        for oversized in [false, true] {
            let body = if oversized {
                format!("data: {}\n", "a".repeat(1024 * 1024)).repeat(65)
            } else {
                "data: {\"useful\":true}\n\n".into()
            };
            let (url, server) =
                crate::providers::provider_http::serve_test_bodies(vec![(200, body.clone(), true)])
                    .await;
            let client = UsageAliasHttpClient::default();
            let request = rig::http_client::Request::builder()
                .method("POST")
                .uri(url)
                .body(bytes::Bytes::new())
                .unwrap();
            let mut stream = client.send_streaming(request).await.unwrap().into_body();
            let mut received = 0;
            let mut failed = false;
            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(chunk) => received += chunk.len(),
                    Err(_) => {
                        failed = true;
                        assert!(stream.next().await.is_none(), "budget failure is terminal");
                        break;
                    }
                }
            }
            assert_eq!(failed, oversized);
            if !oversized {
                assert_eq!(received, body.len());
            }
            assert!(received <= MAX_INFERENCE_STREAM_BYTES);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn inference_adapter_pending_error_drop_releases_connection_for_every_mode() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for mode in 0..3 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let (entered, waiting) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 8192];
                let mut headers = Vec::new();
                while !headers.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let read = socket.read(&mut request).await.unwrap();
                    assert!(read > 0);
                    headers.extend_from_slice(&request[..read]);
                }
                socket.write_all(b"HTTP/1.1 400 Bad Request\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n1\r\nx\r\n").await.unwrap();
                entered.send(()).unwrap();
                // Multipart may still have request bytes queued. Drain those
                // and require actual EOF after the owner future is dropped.
                while socket.read(&mut request).await.unwrap_or(0) != 0 {}
            });
            let request = tokio::spawn(async move {
                adapter_error(&UsageAliasHttpClient::default(), &url, mode).await
            });
            waiting.await.unwrap();
            tokio::task::yield_now().await;
            assert!(
                !request.is_finished(),
                "unterminated error body must be pending"
            );
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .expect("dropped adapter releases socket")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn inference_adapter_slow_error_body_has_owned_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let client = UsageAliasHttpClient::default();
        let request = tokio::spawn(async move { adapter_error(&client, &url, 1).await });
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 8192];
        assert!(socket.read(&mut buffer).await.unwrap() > 0);
        socket.write_all(b"HTTP/1.1 400 Bad Request\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n1\r\nx\r\n").await.unwrap();
        // Schedule all ready HTTP work, then advance a paused clock beyond
        // the adapter's own deadline (rather than imposing a test timeout).
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(!request.is_finished());
        tokio::time::pause();
        tokio::time::advance(INFERENCE_BODY_TIMEOUT + Duration::from_secs(1)).await;
        let error = request.await.unwrap();
        assert!(
            matches!(error, rig::http_client::Error::InvalidStatusCodeWithDetails {status, body, ..} if status.as_u16() == 400 && body.contains("deadline has elapsed"))
        );
        assert_eq!(socket.read(&mut buffer).await.unwrap_or(0), 0);
    }
}
