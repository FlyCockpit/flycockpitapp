use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use futures::StreamExt;
use rig::providers::{anthropic, chatgpt, openai};

use super::wire::{normalize_openai_usage_aliases_bytes, take_normalized_sse_lines};

const PROVIDER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
// Every OpenAI-compatible provider in `src/providers/mod.rs` (z.ai,
// MiniMax, OpenCode Zen, generic openai-compatible, Ollama) speaks the
// *Chat Completions* API — `/chat/completions`. We have to construct
// the `CompletionsClient` variant instead, or every non-OpenAI-proper
// endpoint 404s on the wrong path.
pub(super) type OpenAiCompatClient = openai::CompletionsClient<UsageAliasHttpClient>;
pub(super) type ChatGptResponsesModel = chatgpt::ResponsesCompletionModel<UsageAliasHttpClient>;
pub(super) type AnthropicCompletionModel =
    anthropic::completion::CompletionModel<UsageAliasHttpClient>;

#[derive(Clone)]
pub struct UsageAliasHttpClient {
    client: reqwest::Client,
    extra_headers: reqwest::header::HeaderMap,
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
            .finish()
    }
}

impl UsageAliasHttpClient {
    pub(super) fn new(extra_headers: Vec<(String, String)>) -> anyhow::Result<Self> {
        let extra_headers = with_canonical_user_agent(extra_headers);
        let mut validated = reqwest::header::HeaderMap::new();
        for (name, value) in extra_headers {
            validated.insert(
                reqwest::header::HeaderName::from_bytes(name.as_bytes())?,
                reqwest::header::HeaderValue::from_str(&value)?,
            );
        }
        let client = reqwest::Client::builder()
            .connect_timeout(PROVIDER_CONNECT_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Ok(Self {
            client,
            extra_headers: validated,
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
) -> rig::http_client::Request<T> {
    let (mut parts, body) = req.into_parts();
    for (name, value) in headers {
        parts.headers.insert(name.clone(), value.clone());
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
    } else if let Some(content) = body
        .get_mut("messages")
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|messages| messages.last_mut())
        .and_then(|message| message.get_mut("content"))
        .and_then(serde_json::Value::as_array_mut)
    {
        content.extend(continuations);
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
        let req = apply_extra_headers(req, &self.extra_headers);
        let (parts, body) = req.into_parts();
        let req = rig::http_client::Request::from_parts(
            parts,
            inject_native_computer_continuations(body.into()),
        );
        async move {
            let response = client.send::<bytes::Bytes, bytes::Bytes>(req).await?;
            let (parts, body) = response.into_parts();
            let body: rig::http_client::LazyBody<U> = Box::pin(async move {
                let bytes = body.await?;
                retain_anthropic_native_items_from_response(&bytes);
                Ok(U::from(normalize_openai_usage_aliases_bytes(bytes)))
            });
            Ok(rig::http_client::Response::from_parts(parts, body))
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
        self.client
            .send_multipart(apply_extra_headers(req, &self.extra_headers))
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
        let req = apply_extra_headers(req, &self.extra_headers);
        let (parts, body) = req.into_parts();
        let req = rig::http_client::Request::from_parts(
            parts,
            inject_native_computer_continuations(body.into()),
        );
        async move {
            let response = client.send_streaming(req).await?;
            let (parts, body) = response.into_parts();
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
                ),
                |(mut body, mut pending, aborted, mut native_capture)| async move {
                    // A prior iteration hit the no-newline cap and yielded a
                    // terminal error; end the stream rather than spin.
                    if aborted {
                        return None;
                    }
                    loop {
                        let normalized = take_normalized_sse_lines(&mut pending, false);
                        if !normalized.is_empty() {
                            native_capture.ingest(&normalized);
                            return Some((Ok(normalized), (body, pending, false, native_capture)));
                        }
                        match body.next().await {
                            Some(Ok(bytes)) => {
                                pending.extend_from_slice(&bytes);
                                if pending.len() > MAX_SSE_PENDING_BYTES {
                                    let error = rig::http_client::Error::Instance(Box::new(
                                        std::io::Error::new(
                                            std::io::ErrorKind::InvalidData,
                                            format!(
                                                "provider SSE stream buffered {} bytes with no newline (cap {MAX_SSE_PENDING_BYTES}); treating the connection as hostile",
                                                pending.len(),
                                            ),
                                        ),
                                    ));
                                    return Some((
                                        Err(error),
                                        (body, pending, true, native_capture),
                                    ));
                                }
                            }
                            Some(Err(e)) => {
                                return Some((Err(e), (body, pending, false, native_capture)));
                            }
                            None => {
                                let normalized = take_normalized_sse_lines(&mut pending, true);
                                if normalized.is_empty() {
                                    return None;
                                }
                                native_capture.ingest(&normalized);
                                return Some((
                                    Ok(normalized),
                                    (body, pending, false, native_capture),
                                ));
                            }
                        }
                    }
                },
            ));
            Ok(rig::http_client::Response::from_parts(parts, stream))
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

            let openai =
                bytes::Bytes::from_static(br#"{"input":[],"tools":[{"type":"computer"}]}"#);
            let first = inject_native_computer_continuations(openai.clone());
            assert!(String::from_utf8_lossy(&first).contains("call-once"));

            let retry = inject_native_computer_continuations(openai.clone());
            assert_eq!(retry, openai);
        })
        .await;
    }
}
