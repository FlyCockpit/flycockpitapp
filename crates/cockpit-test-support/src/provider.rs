//! Local scripted provider harness for tests.
//!
//! This module intentionally stays free of `cockpit-*` dependencies. A
//! `cockpit-core --dev--> cockpit-test-support --> cockpit-core` cycle is legal
//! in Cargo, but it damages incremental builds and undermines the crate split;
//! driver construction helpers belong in the consuming crate.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDialect {
    ChatCompletions,
    Responses,
    Anthropic,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Turn {
    /// One assistant tool call. `arguments` is serialized verbatim.
    ToolCall {
        id: String,
        name: String,
        arguments: Value,
    },
    /// Several tool calls in ONE assistant message, in the given order.
    ParallelToolCalls(Vec<(String, String, Value)>),
    /// Assistant text.
    Text(String),
    /// Non-2xx response with a verbatim body.
    HttpError { status: u16, body: String },
    /// Accept the request, never respond, hold the connection open.
    Hang,
    /// Emit this exact SSE payload verbatim.
    RawSse(String),
    /// Non-SSE `application/json` body, verbatim.
    RawJson(Value),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// Emit the alias spelling (`input_tokens`/`output_tokens`) instead of
    /// the canonical one.
    pub use_alias_names: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapturedRequest {
    pub request_line: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

#[derive(Debug, Clone)]
struct ScriptedTurn {
    turn: Turn,
    usage: Option<Usage>,
}

#[derive(Debug)]
struct PathStatusRule {
    status: u16,
    remaining: Option<usize>,
}

#[derive(Debug)]
pub struct ScriptedProviderBuilder {
    dialect: WireDialect,
    turns: Vec<ScriptedTurn>,
    path_status: HashMap<String, PathStatusRule>,
    repeat_last: bool,
}

pub struct ScriptedProvider {
    base_url: String,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    request_count: Arc<AtomicUsize>,
    request_rx: mpsc::UnboundedReceiver<CapturedRequest>,
    shutdown_tx: broadcast::Sender<()>,
    accept_task: JoinHandle<()>,
}

#[derive(Debug)]
struct SharedState {
    dialect: WireDialect,
    turns: Vec<ScriptedTurn>,
    path_status: Mutex<HashMap<String, PathStatusRule>>,
    repeat_last: bool,
    script_index: AtomicUsize,
    request_count: Arc<AtomicUsize>,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    request_tx: mpsc::UnboundedSender<CapturedRequest>,
}

#[derive(Debug)]
struct ParsedRequest {
    captured: CapturedRequest,
    path: String,
}

impl Default for ScriptedProviderBuilder {
    fn default() -> Self {
        Self {
            dialect: WireDialect::ChatCompletions,
            turns: Vec::new(),
            path_status: HashMap::new(),
            repeat_last: false,
        }
    }
}

impl ScriptedProviderBuilder {
    pub fn dialect(mut self, d: WireDialect) -> Self {
        self.dialect = d;
        self
    }

    /// Append a turn answered on ANY path.
    pub fn turn(mut self, t: Turn) -> Self {
        self.turns.push(ScriptedTurn {
            turn: t,
            usage: None,
        });
        self
    }

    /// Attach usage to the most recently added turn.
    pub fn with_usage(mut self, u: Usage) -> Self {
        let Some(turn) = self.turns.last_mut() else {
            panic!("with_usage requires a preceding turn");
        };
        turn.usage = Some(u);
        self
    }

    /// Per-path status override, applied before the turn script.
    pub fn path_status(mut self, path: &str, status: u16) -> Self {
        self.path_status.insert(
            path.to_string(),
            PathStatusRule {
                status,
                remaining: None,
            },
        );
        self
    }

    /// Per-path status override for the first `n` requests to that path.
    pub fn path_status_for(mut self, path: &str, status: u16, n: usize) -> Self {
        self.path_status.insert(
            path.to_string(),
            PathStatusRule {
                status,
                remaining: Some(n),
            },
        );
        self
    }

    /// Repeat the last scripted turn after the script has been exhausted.
    pub fn repeat_last(mut self) -> Self {
        self.repeat_last = true;
        self
    }

    pub async fn start(self) -> ScriptedProvider {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind scripted provider");
        let addr = listener.local_addr().expect("scripted provider local addr");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let request_count = Arc::new(AtomicUsize::new(0));
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, _) = broadcast::channel(1);
        let state = Arc::new(SharedState {
            dialect: self.dialect,
            turns: self.turns,
            path_status: Mutex::new(self.path_status),
            repeat_last: self.repeat_last,
            script_index: AtomicUsize::new(0),
            request_count: Arc::clone(&request_count),
            captured: Arc::clone(&captured),
            request_tx,
        });
        let accept_task = spawn_accept_loop(listener, Arc::clone(&state), shutdown_tx.subscribe());
        ScriptedProvider {
            base_url: format!("http://{addr}/v1"),
            captured,
            request_count,
            request_rx,
            shutdown_tx,
            accept_task,
        }
    }

    /// Start the provider from synchronous tests.
    ///
    /// When called inside an existing Tokio runtime, startup is delegated to a
    /// short-lived OS thread so this function does not block that runtime's
    /// executor. The returned provider owns the background runtime that serves
    /// accepted connections.
    pub fn start_blocking(self) -> ScriptedProvider {
        if tokio::runtime::Handle::try_current().is_ok() {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                tx.send(start_on_owned_runtime(self))
                    .expect("send blocking scripted provider");
            });
            return rx.recv().expect("receive blocking scripted provider");
        }
        start_on_owned_runtime(self)
    }
}

impl ScriptedProvider {
    pub fn builder() -> ScriptedProviderBuilder {
        ScriptedProviderBuilder::default()
    }

    /// e.g. "http://127.0.0.1:41234/v1"
    pub fn base_url(&self) -> String {
        self.base_url.clone()
    }

    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    /// Await the next captured request. Panics on timeout so test failures are
    /// loud instead of hanging forever.
    pub async fn next_request(&mut self) -> CapturedRequest {
        tokio::time::timeout(Duration::from_secs(2), self.request_rx.recv())
            .await
            .expect("timed out waiting for scripted provider request")
            .expect("scripted provider request channel closed")
    }

    /// All requests captured so far, in arrival order.
    pub fn captured(&self) -> Vec<CapturedRequest> {
        self.captured
            .lock()
            .expect("scripted provider capture lock poisoned")
            .clone()
    }
}

impl Drop for ScriptedProvider {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
        self.accept_task.abort();
    }
}

fn spawn_accept_loop(
    listener: TcpListener,
    state: Arc<SharedState>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let Ok((stream, _)) = accept else {
                        break;
                    };
                    let state = Arc::clone(&state);
                    let shutdown_rx = shutdown_rx.resubscribe();
                    tokio::spawn(async move {
                        handle_connection(stream, state, shutdown_rx).await;
                    });
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    })
}

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<SharedState>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let parsed = read_http_request(&mut stream).await;
    state.request_count.fetch_add(1, Ordering::SeqCst);
    state
        .captured
        .lock()
        .expect("scripted provider capture lock poisoned")
        .push(parsed.captured.clone());
    let _ = state.request_tx.send(parsed.captured);

    if let Some(status) = state.take_path_status(&parsed.path) {
        write_response(
            &mut stream,
            status,
            "application/json",
            &format!("{{\"error\":\"no route for {}\"}}", parsed.path),
        )
        .await;
        return;
    }

    let Some(turn) = state.next_turn() else {
        write_response(
            &mut stream,
            500,
            "application/json",
            "{\"error\":\"script exhausted\"}",
        )
        .await;
        return;
    };

    match &turn.turn {
        Turn::HttpError { status, body } => {
            write_response(&mut stream, *status, "application/json", body).await;
        }
        Turn::Hang => {
            let _ = shutdown_rx.recv().await;
        }
        Turn::RawSse(payload) => {
            write_response(&mut stream, 200, "text/event-stream", payload).await;
        }
        Turn::RawJson(body) => {
            write_response(&mut stream, 200, "application/json", &body.to_string()).await;
        }
        other => {
            let payload = emit_turn(
                state.dialect.for_request_path(&parsed.path),
                other,
                turn.usage.as_ref(),
            );
            write_response(&mut stream, 200, "text/event-stream", &payload).await;
        }
    }
}

impl WireDialect {
    fn for_request_path(self, path: &str) -> Self {
        if self == Self::ChatCompletions && path.ends_with("/responses") {
            Self::Responses
        } else {
            self
        }
    }
}

fn start_on_owned_runtime(builder: ScriptedProviderBuilder) -> ScriptedProvider {
    let runtime = Box::leak(Box::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build scripted provider runtime"),
    ));
    runtime.block_on(builder.start())
}

impl SharedState {
    fn take_path_status(&self, path: &str) -> Option<u16> {
        let mut rules = self
            .path_status
            .lock()
            .expect("scripted provider path status lock poisoned");
        let rule = rules.get_mut(path)?;
        match &mut rule.remaining {
            None => Some(rule.status),
            Some(remaining) if *remaining > 0 => {
                *remaining -= 1;
                Some(rule.status)
            }
            Some(_) => None,
        }
    }

    fn next_turn(&self) -> Option<ScriptedTurn> {
        let index = self.script_index.fetch_add(1, Ordering::SeqCst);
        if let Some(turn) = self.turns.get(index) {
            return Some(turn.clone());
        }
        if self.repeat_last {
            return self.turns.last().cloned();
        }
        None
    }
}

async fn read_http_request(stream: &mut TcpStream) -> ParsedRequest {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        let s = String::from_utf8_lossy(&buf);
        if let Some(idx) = s.find("\r\n\r\n") {
            let header = &s[..idx];
            let body_start = idx + 4;
            let content_len = header
                .lines()
                .find_map(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower
                        .strip_prefix("content-length:")
                        .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                })
                .unwrap_or(0);
            if buf.len() >= body_start + content_len {
                let body =
                    String::from_utf8_lossy(&buf[body_start..body_start + content_len]).to_string();
                return parsed_request_from_parts(header, &body);
            }
        }
    }
    parsed_request_from_parts(&String::from_utf8_lossy(&buf), "")
}

fn parsed_request_from_parts(header: &str, body: &str) -> ParsedRequest {
    let mut lines = header.lines();
    let request_line = lines.next().unwrap_or("").to_string();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim_start().to_string()))
        })
        .collect();
    let body = serde_json::from_str::<Value>(body).unwrap_or_else(|_| Value::String(body.into()));
    ParsedRequest {
        captured: CapturedRequest {
            request_line,
            headers,
            body,
        },
        path,
    }
}

async fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        reason_phrase(status),
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

fn emit_turn(dialect: WireDialect, turn: &Turn, usage: Option<&Usage>) -> String {
    match dialect {
        WireDialect::ChatCompletions => emit_chat_turn(turn, usage),
        WireDialect::Responses => emit_responses_turn(turn, usage),
        WireDialect::Anthropic => emit_anthropic_turn(turn, usage),
    }
}

fn emit_chat_turn(turn: &Turn, usage: Option<&Usage>) -> String {
    match turn {
        Turn::Text(text) => {
            let text = serde_json::to_string(text).expect("serialize text delta");
            let usage = chat_usage_json(usage);
            format!(
                "data: {{\"id\":\"c\",\"model\":\"local\",\"choices\":[{{\"delta\":{{\"content\":{text}}},\"finish_reason\":null}}],\"usage\":null}}\n\n\
                 data: {{\"id\":\"c\",\"model\":\"local\",\"choices\":[{{\"delta\":{{\"content\":\"\"}},\"finish_reason\":\"stop\"}}],\"usage\":{usage}}}\n\n\
                 data: [DONE]\n\n"
            )
        }
        Turn::ToolCall {
            id,
            name,
            arguments,
        } => emit_chat_tool_calls([(id.as_str(), name.as_str(), arguments)].into_iter(), usage),
        Turn::ParallelToolCalls(calls) => emit_chat_tool_calls(
            calls
                .iter()
                .map(|(id, name, arguments)| (id.as_str(), name.as_str(), arguments)),
            usage,
        ),
        _ => unreachable!("non-SSE turn handled before dialect emission"),
    }
}

fn emit_chat_tool_calls<'a>(
    calls: impl Iterator<Item = (&'a str, &'a str, &'a Value)>,
    usage: Option<&Usage>,
) -> String {
    let tool_calls = calls
        .enumerate()
        .map(|(index, (id, name, arguments))| {
            serde_json::json!({
                "index": index,
                "id": id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": arguments.to_string()
                }
            })
        })
        .collect::<Vec<_>>();
    let start = serde_json::json!({
        "id": "c",
        "model": "local",
        "choices": [{
            "delta": { "tool_calls": tool_calls },
            "finish_reason": null
        }],
        "usage": null
    });
    let finish = serde_json::json!({
        "id": "c",
        "model": "local",
        "choices": [{
            "delta": {},
            "finish_reason": "tool_calls"
        }],
        "usage": usage_value_for_chat(usage)
    });
    format!("data: {start}\n\ndata: {finish}\n\ndata: [DONE]\n\n")
}

fn emit_responses_turn(turn: &Turn, usage: Option<&Usage>) -> String {
    match turn {
        Turn::Text(text) => {
            let delta = serde_json::to_string(text).expect("serialize responses delta");
            let usage = responses_usage_value(usage);
            let completed = serde_json::json!({
                "type": "response.completed",
                "response": {
                    "id": "resp_1",
                    "object": "response",
                    "created_at": 1,
                    "status": "completed",
                    "error": null,
                    "incomplete_details": null,
                    "instructions": null,
                    "max_output_tokens": null,
                    "model": "local",
                    "usage": usage,
                    "output": [{
                        "type": "message",
                        "id": "msg_1",
                        "status": "completed",
                        "role": "assistant",
                        "content": [{
                            "type": "output_text",
                            "annotations": [],
                            "text": text
                        }]
                    }],
                    "tools": []
                }
            });
            format!(
                "data: {{\"type\":\"response.output_text.delta\",\"delta\":{delta}}}\n\ndata: {completed}\n\n"
            )
        }
        Turn::ToolCall {
            id,
            name,
            arguments,
        } => {
            emit_responses_tool_calls([(id.as_str(), name.as_str(), arguments)].into_iter(), usage)
        }
        Turn::ParallelToolCalls(calls) => emit_responses_tool_calls(
            calls
                .iter()
                .map(|(id, name, arguments)| (id.as_str(), name.as_str(), arguments)),
            usage,
        ),
        _ => unreachable!("non-SSE turn handled before dialect emission"),
    }
}

fn emit_responses_tool_calls<'a>(
    calls: impl Iterator<Item = (&'a str, &'a str, &'a Value)>,
    usage: Option<&Usage>,
) -> String {
    let output = calls
        .map(|(id, name, arguments)| {
            serde_json::json!({
                "type": "function_call",
                "id": format!("fc_{id}"),
                "call_id": id,
                "name": name,
                "arguments": arguments.to_string(),
                "status": "completed"
            })
        })
        .collect::<Vec<_>>();
    let completed = serde_json::json!({
        "type": "response.completed",
        "response": {
            "id": "resp_1",
            "object": "response",
            "created_at": 1,
            "status": "completed",
            "error": null,
            "incomplete_details": null,
            "instructions": null,
            "max_output_tokens": null,
            "model": "local",
            "usage": responses_usage_value(usage),
            "output": output,
            "tools": []
        }
    });
    format!("data: {completed}\n\n")
}

fn emit_anthropic_turn(turn: &Turn, usage: Option<&Usage>) -> String {
    let usage = anthropic_usage_value(usage);
    match turn {
        Turn::Text(text) => {
            let delta = serde_json::to_string(text).expect("serialize anthropic delta");
            format!(
                "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"local\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{usage}}}}}\n\n\
                 event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n\
                 event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":{delta}}}}}\n\n\
                 event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n\
                 event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\",\"stop_sequence\":null}},\"usage\":{usage}}}\n\n\
                 event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
            )
        }
        Turn::ToolCall {
            id,
            name,
            arguments,
        } => {
            emit_anthropic_tool_calls([(id.as_str(), name.as_str(), arguments)].into_iter(), usage)
        }
        Turn::ParallelToolCalls(calls) => emit_anthropic_tool_calls(
            calls
                .iter()
                .map(|(id, name, arguments)| (id.as_str(), name.as_str(), arguments)),
            usage,
        ),
        _ => unreachable!("non-SSE turn handled before dialect emission"),
    }
}

fn emit_anthropic_tool_calls<'a>(
    calls: impl Iterator<Item = (&'a str, &'a str, &'a Value)>,
    usage: Value,
) -> String {
    let mut payload = format!(
        "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"local\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{usage}}}}}\n\n"
    );
    for (index, (id, name, arguments)) in calls.enumerate() {
        payload.push_str(&format!(
            "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":{index},\"content_block\":{{\"type\":\"tool_use\",\"id\":\"{id}\",\"name\":\"{name}\",\"input\":{{}}}}}}\n\n"
        ));
        payload.push_str(&format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":{index},\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":{}}}}}\n\n",
            serde_json::to_string(&arguments.to_string()).expect("serialize anthropic partial json")
        ));
        payload.push_str(&format!(
            "event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{index}}}\n\n"
        ));
    }
    payload.push_str(&format!(
        "event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"tool_use\",\"stop_sequence\":null}},\"usage\":{usage}}}\n\n\
         event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
    ));
    payload
}

fn usage_or_default(usage: Option<&Usage>) -> Usage {
    usage.cloned().unwrap_or(Usage {
        prompt_tokens: 1,
        completion_tokens: 1,
        total_tokens: 2,
        use_alias_names: false,
    })
}

fn usage_value_for_chat(usage: Option<&Usage>) -> Value {
    let usage = usage_or_default(usage);
    if usage.use_alias_names {
        serde_json::json!({
            "input_tokens": usage.prompt_tokens,
            "output_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens
        })
    } else {
        serde_json::json!({
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens
        })
    }
}

fn chat_usage_json(usage: Option<&Usage>) -> String {
    usage_value_for_chat(usage).to_string()
}

fn responses_usage_value(usage: Option<&Usage>) -> Value {
    let usage = usage_or_default(usage);
    serde_json::json!({
        "input_tokens": usage.prompt_tokens,
        "input_tokens_details": { "cached_tokens": 0 },
        "output_tokens": usage.completion_tokens,
        "output_tokens_details": { "reasoning_tokens": 0 },
        "total_tokens": usage.total_tokens
    })
}

fn anthropic_usage_value(usage: Option<&Usage>) -> Value {
    let usage = usage_or_default(usage);
    serde_json::json!({
        "input_tokens": usage.prompt_tokens,
        "output_tokens": usage.completion_tokens
    })
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        418 => "I'm a Teapot",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    struct HttpResponse {
        status: u16,
        content_type: String,
        body: String,
    }

    async fn request(provider: &ScriptedProvider, path: &str, body: Value) -> HttpResponse {
        request_with_headers(provider, path, body, &[]).await
    }

    async fn request_with_headers(
        provider: &ScriptedProvider,
        path: &str,
        body: Value,
        headers: &[(&str, &str)],
    ) -> HttpResponse {
        let (addr, prefix) = split_base_url(&provider.base_url());
        let request_path = format!("{prefix}{path}");
        let body = body.to_string();
        let mut stream = TcpStream::connect(&addr).await.expect("connect provider");
        let extra_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect::<String>();
        let request = format!(
            "POST {request_path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response");
        parse_response(&String::from_utf8_lossy(&response))
    }

    fn split_base_url(base_url: &str) -> (String, String) {
        let rest = base_url
            .strip_prefix("http://")
            .expect("test provider base url is http");
        let (addr, path) = rest
            .split_once('/')
            .map(|(addr, path)| (addr.to_string(), format!("/{path}")))
            .unwrap_or_else(|| (rest.to_string(), String::new()));
        (addr, path)
    }

    fn parse_response(raw: &str) -> HttpResponse {
        let (header, body) = raw.split_once("\r\n\r\n").expect("http response body");
        let mut lines = header.lines();
        let status = lines
            .next()
            .expect("status line")
            .split_whitespace()
            .nth(1)
            .expect("status code")
            .parse()
            .expect("numeric status");
        let content_type = lines
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-type")
                        .then(|| value.trim().to_string())
                })
            })
            .unwrap_or_default();
        HttpResponse {
            status,
            content_type,
            body: body.to_string(),
        }
    }

    #[tokio::test]
    async fn scripted_provider_serves_text_turn_as_chat_completions_sse() {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::Text("ok".into()))
            .start()
            .await;

        let response = request(&provider, "/chat/completions", json!({"stream": true})).await;

        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "text/event-stream");
        assert!(response.body.contains(
            "data: {\"id\":\"c\",\"model\":\"local\",\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}],\"usage\":null}"
        ));
        assert!(response.body.contains("data: [DONE]\n\n"));
    }

    #[tokio::test]
    async fn scripted_provider_serves_text_turn_as_responses_sse() {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::Responses)
            .turn(Turn::Text("ok".into()))
            .start()
            .await;

        let response = request(&provider, "/responses", json!({"stream": true})).await;

        assert_eq!(response.status, 200);
        assert!(
            response
                .body
                .contains("data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}")
        );
        assert!(response.body.contains("\"type\":\"response.completed\""));
    }

    #[tokio::test]
    async fn scripted_provider_serves_text_turn_as_anthropic_sse() {
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::Anthropic)
            .turn(Turn::Text("ok".into()))
            .start()
            .await;

        let response = request(&provider, "/messages", json!({"stream": true})).await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("event: message_start\n"));
        assert!(
            response
                .body
                .contains("\"type\":\"text_delta\",\"text\":\"ok\"")
        );
        assert!(response.body.contains("event: message_stop\n"));
    }

    #[tokio::test]
    async fn scripted_provider_serves_tool_call_turn() {
        let provider = ScriptedProvider::builder()
            .turn(Turn::ToolCall {
                id: "call_1".into(),
                name: "lookup".into(),
                arguments: json!({"q": "term"}),
            })
            .start()
            .await;

        let response = request(&provider, "/chat/completions", json!({})).await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("\"finish_reason\":\"tool_calls\""));
        assert!(response.body.contains("\"id\":\"call_1\""));
        assert!(response.body.contains("\"name\":\"lookup\""));
        assert!(response.body.contains(r#""arguments":"{\"q\":\"term\"}""#));
    }

    #[tokio::test]
    async fn scripted_provider_serves_parallel_tool_calls_in_one_message() {
        let provider = ScriptedProvider::builder()
            .turn(Turn::ParallelToolCalls(vec![
                ("call_1".into(), "lookup".into(), json!({"a": 1})),
                ("call_2".into(), "read".into(), json!({"path": "x"})),
            ]))
            .start()
            .await;

        let response = request(&provider, "/chat/completions", json!({})).await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("\"index\":0"));
        assert!(response.body.contains("\"index\":1"));
        assert!(response.body.contains("\"id\":\"call_2\""));
    }

    #[tokio::test]
    async fn scripted_provider_serves_http_error_turn() {
        let provider = ScriptedProvider::builder()
            .turn(Turn::HttpError {
                status: 401,
                body: r#"{"error":{"message":"Unauthorized"}}"#.into(),
            })
            .start()
            .await;

        let response = request(&provider, "/chat/completions", json!({})).await;

        assert_eq!(response.status, 401);
        assert_eq!(response.body, r#"{"error":{"message":"Unauthorized"}}"#);
    }

    #[tokio::test]
    async fn scripted_provider_hang_turn_captures_request_and_never_responds() {
        let mut provider = ScriptedProvider::builder().turn(Turn::Hang).start().await;
        let (addr, prefix) = split_base_url(&provider.base_url());
        let mut stream = TcpStream::connect(&addr).await.expect("connect provider");
        let request = format!(
            "POST {prefix}/chat/completions HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");

        let captured = provider.next_request().await;
        assert_eq!(captured.request_line, "POST /v1/chat/completions HTTP/1.1");
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_millis(50), stream.read(&mut byte)).await;
        assert!(read.is_err(), "hang turn must not respond");
    }

    #[tokio::test]
    async fn scripted_provider_raw_sse_and_raw_json_are_verbatim() {
        let provider = ScriptedProvider::builder()
            .turn(Turn::RawSse("data: raw\n\n".into()))
            .turn(Turn::RawJson(json!({"ok": true})))
            .start()
            .await;

        let sse = request(&provider, "/chat/completions", json!({})).await;
        let json = request(&provider, "/chat/completions", json!({})).await;

        assert_eq!(sse.content_type, "text/event-stream");
        assert_eq!(sse.body, "data: raw\n\n");
        assert_eq!(json.content_type, "application/json");
        assert_eq!(json.body, r#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn scripted_provider_emits_usage_with_and_without_alias_names() {
        let provider = ScriptedProvider::builder()
            .turn(Turn::Text("normal".into()))
            .with_usage(Usage {
                prompt_tokens: 3,
                completion_tokens: 4,
                total_tokens: 7,
                use_alias_names: false,
            })
            .turn(Turn::Text("alias".into()))
            .with_usage(Usage {
                prompt_tokens: 5,
                completion_tokens: 6,
                total_tokens: 11,
                use_alias_names: true,
            })
            .start()
            .await;

        let normal = request(&provider, "/chat/completions", json!({})).await;
        let alias = request(&provider, "/chat/completions", json!({})).await;

        assert!(
            normal
                .body
                .contains(r#""usage":{"completion_tokens":4,"prompt_tokens":3,"total_tokens":7}"#)
        );
        assert!(
            alias
                .body
                .contains(r#""usage":{"input_tokens":5,"output_tokens":6,"total_tokens":11}"#)
        );
    }

    #[tokio::test]
    async fn scripted_provider_path_status_overrides_apply_before_script() {
        let provider = ScriptedProvider::builder()
            .path_status("/v1/responses", 404)
            .turn(Turn::Text("ok".into()))
            .start()
            .await;

        let missing = request(&provider, "/responses", json!({})).await;
        let ok = request(&provider, "/chat/completions", json!({})).await;

        assert_eq!(missing.status, 404);
        assert_eq!(ok.status, 200);
        assert!(ok.body.contains("ok"));
    }

    #[tokio::test]
    async fn scripted_provider_path_status_for_applies_only_n_times() {
        let provider = ScriptedProvider::builder()
            .path_status_for("/v1/responses", 404, 1)
            .turn(Turn::Text("ok".into()))
            .start()
            .await;

        let first = request(&provider, "/responses", json!({})).await;
        let second = request(&provider, "/responses", json!({})).await;

        assert_eq!(first.status, 404);
        assert_eq!(second.status, 200);
        assert!(second.body.contains("ok"));
    }

    #[tokio::test]
    async fn scripted_provider_dispatches_responses_and_chat_paths_from_one_listener() {
        let provider = ScriptedProvider::builder()
            .path_status_for("/v1/responses", 404, 1)
            .turn(Turn::Text("chat fallback".into()))
            .turn(Turn::Text("responses fallback".into()))
            .start()
            .await;

        let responses = request(&provider, "/responses", json!({})).await;
        let chat = request(&provider, "/chat/completions", json!({})).await;
        let responses_ok = request(&provider, "/responses", json!({})).await;

        assert_eq!(responses.status, 404);
        assert_eq!(chat.status, 200);
        assert!(chat.body.contains("chat fallback"));
        assert_eq!(responses_ok.status, 200);
        assert!(responses_ok.body.contains("response.output_text.delta"));
        assert!(responses_ok.body.contains("responses fallback"));
    }

    #[tokio::test]
    async fn scripted_provider_captures_request_line_headers_and_body() {
        let mut provider = ScriptedProvider::builder()
            .turn(Turn::Text("ok".into()))
            .start()
            .await;

        let response = request_with_headers(
            &provider,
            "/chat/completions",
            json!({"messages": [{"role": "user", "content": "hi"}]}),
            &[("X-Test-Header", "Value")],
        )
        .await;
        let captured = provider.next_request().await;

        assert_eq!(response.status, 200);
        assert_eq!(captured.request_line, "POST /v1/chat/completions HTTP/1.1");
        assert!(
            captured
                .headers
                .contains(&("x-test-header".into(), "Value".into()))
        );
        assert_eq!(captured.body["messages"][0]["content"], "hi");
    }

    #[tokio::test]
    async fn scripted_provider_counts_requests() {
        let provider = ScriptedProvider::builder()
            .turn(Turn::Text("one".into()))
            .turn(Turn::Text("two".into()))
            .start()
            .await;

        assert_eq!(provider.request_count(), 0);
        let _ = request(&provider, "/chat/completions", json!({})).await;
        let _ = request(&provider, "/chat/completions", json!({})).await;

        assert_eq!(provider.request_count(), 2);
        assert_eq!(provider.captured().len(), 2);
    }

    #[tokio::test]
    async fn scripted_provider_reports_script_exhausted_past_end() {
        let provider = ScriptedProvider::builder()
            .turn(Turn::Text("one".into()))
            .start()
            .await;

        let _ = request(&provider, "/chat/completions", json!({})).await;
        let exhausted = request(&provider, "/chat/completions", json!({})).await;

        assert_eq!(exhausted.status, 500);
        assert!(exhausted.body.contains("script exhausted"));
    }

    #[tokio::test]
    async fn scripted_provider_repeat_last_answers_unlimited_requests() {
        let provider = ScriptedProvider::builder()
            .turn(Turn::Text("repeat".into()))
            .repeat_last()
            .start()
            .await;

        for _ in 0..3 {
            let response = request(&provider, "/chat/completions", json!({})).await;
            assert_eq!(response.status, 200);
            assert!(response.body.contains("repeat"));
        }
    }
}
