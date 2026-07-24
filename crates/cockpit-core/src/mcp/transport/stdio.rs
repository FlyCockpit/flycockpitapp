//! Stdio transport (local subprocess MCP servers).
//!
//! Spawns the configured command and speaks line-delimited JSON-RPC over
//! the child's stdin/stdout. Extra env (from `env` + `Auth::Env`) is
//! injected into the child. The process is killed on drop.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::mcp::protocol::{
    JsonRpcRequest, JsonRpcResponse, McpClient, ToolDescriptor, initialize_params, parse_tools_list,
};
use crate::mcp::transport::timeout::McpTimeouts;

const STDIO_POISON_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

pub struct StdioClient<R = ChildStdout, W = ChildStdin> {
    state: Arc<StdioState>,
    stdin: W,
    stdout: BufReader<R>,
    next_id: u64,
    timeouts: McpTimeouts,
    cancel: Option<CancellationToken>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StdioAbandonScope {
    pub session_id: Uuid,
    pub tool_call_id: Option<String>,
}

#[derive(Debug)]
struct StdioState {
    server_name: String,
    abandon_scope: Option<StdioAbandonScope>,
    poisoned: AtomicBool,
    awaiting_abandon_hook: AtomicBool,
    poison_reason: Mutex<Option<String>>,
    child: tokio::sync::Mutex<Option<Child>>,
}

#[derive(Clone, Default)]
pub(crate) struct StdioRuntimeContext {
    pub(crate) cancel: Option<CancellationToken>,
    pub(crate) abandon_scope: Option<StdioAbandonScope>,
}

impl StdioClient {
    pub(crate) fn spawn(
        server_name: &str,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        timeouts: McpTimeouts,
        runtime: StdioRuntimeContext,
    ) -> Result<Self> {
        let mut cmd = tokio::process::Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .env_clear()
            .envs(stdio_child_env(std::env::vars(), env));
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawning MCP stdio server `{command}`"))?;
        let stdin = child.stdin.take().context("child stdin missing")?;
        let stdout = child.stdout.take().context("child stdout missing")?;
        Ok(Self::new(
            server_name.to_string(),
            stdin,
            stdout,
            Some(child),
            timeouts,
            runtime,
        ))
    }
}

impl<R, W> StdioClient<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    fn new(
        server_name: String,
        stdin: W,
        stdout: R,
        child: Option<Child>,
        timeouts: McpTimeouts,
        runtime: StdioRuntimeContext,
    ) -> Self {
        let state = Arc::new(StdioState {
            server_name,
            abandon_scope: runtime.abandon_scope,
            poisoned: AtomicBool::new(false),
            awaiting_abandon_hook: AtomicBool::new(false),
            poison_reason: Mutex::new(None),
            child: tokio::sync::Mutex::new(child),
        });
        register_active_stdio(&state);
        Self {
            state,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
            timeouts,
            cancel: runtime.cancel,
        }
    }

    async fn request(&mut self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        self.request_with_deadline(method, params, self.timeouts.request)
            .await
    }

    async fn request_with_deadline(
        &mut self,
        method: &str,
        params: Option<Value>,
        request_timeout: Duration,
    ) -> Result<JsonRpcResponse> {
        self.state.ensure_not_poisoned()?;
        let cancel = self.cancel.clone();
        let outcome = match cancel {
            Some(cancel) => {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => RequestOutcome::Cancelled,
                    result = tokio::time::timeout(request_timeout, self.request_unbounded(method, params)) => {
                        match result {
                            Ok(result) => RequestOutcome::Complete(result),
                            Err(_) => RequestOutcome::TimedOut,
                        }
                    }
                }
            }
            None => {
                match tokio::time::timeout(request_timeout, self.request_unbounded(method, params))
                    .await
                {
                    Ok(result) => RequestOutcome::Complete(result),
                    Err(_) => RequestOutcome::TimedOut,
                }
            }
        };

        match outcome {
            RequestOutcome::Complete(result) => result,
            RequestOutcome::Cancelled => {
                self.state.poison_and_kill("cancellation").await;
                bail!(
                    "MCP stdio request to `{}` was cancelled and the connection was reset",
                    self.state.server_name
                )
            }
            RequestOutcome::TimedOut => {
                self.state.poison_and_kill("timeout").await;
                bail!(
                    "MCP stdio request to `{}` timed out and the connection was reset",
                    self.state.server_name
                )
            }
        }
    }

    async fn request_unbounded(
        &mut self,
        method: &str,
        params: Option<Value>,
    ) -> Result<JsonRpcResponse> {
        let mut guard = InFlightRequestGuard::new(self.state.clone());
        let id = self.next_id;
        // If the future is abandoned after `next_id` advances or while the
        // JSON line is only partly written, this connection cannot be safely
        // resynchronized. Poisoning forces a fresh child for the next call.
        self.next_id += 1;
        let req = JsonRpcRequest::new(id, method, params);
        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.flush().await?;

        // Read lines until we get one that parses as a response carrying
        // our id (servers may emit notifications without an `id`).
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = self.stdout.read_line(&mut buf).await?;
            if n == 0 {
                bail!("MCP stdio server closed the connection");
            }
            let trimmed = buf.trim();
            if trimmed.is_empty() {
                continue;
            }
            let val: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Skip notifications / mismatched ids.
            match val.get("id").and_then(Value::as_u64) {
                Some(rid) if rid == id => {}
                _ => continue,
            }
            let response = serde_json::from_value(val)?;
            guard.disarm();
            return Ok(response);
        }
    }

    pub(crate) async fn poison(&self, reason: &str) {
        self.state.poison_and_kill(reason).await;
    }

    pub(crate) async fn initialize_with_deadline(&mut self, deadline: Duration) -> Result<()> {
        self.request_with_deadline("initialize", Some(initialize_params()), deadline)
            .await?
            .into_result()?;
        Ok(())
    }
}

enum RequestOutcome<T> {
    Complete(Result<T>),
    Cancelled,
    TimedOut,
}

struct InFlightRequestGuard {
    state: Arc<StdioState>,
    disarmed: bool,
}

impl InFlightRequestGuard {
    fn new(state: Arc<StdioState>) -> Self {
        Self {
            state,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for InFlightRequestGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            self.state.mark_abandoned_request();
        }
    }
}

#[derive(Clone, Copy)]
enum PoisonReasonMode {
    Preserve,
    Replace,
}

impl StdioState {
    fn ensure_not_poisoned(&self) -> Result<()> {
        if self.poisoned.load(Ordering::SeqCst) {
            let reason = self
                .poison_reason
                .lock()
                .ok()
                .and_then(|reason| reason.clone())
                .unwrap_or_else(|| "an abandoned request".to_string());
            bail!(
                "MCP stdio server `{}` connection was reset after {reason}; retry to reconnect",
                self.server_name
            );
        }
        Ok(())
    }

    fn poison_sync(&self, reason: &str, reason_mode: PoisonReasonMode) {
        self.mark_poisoned(reason, reason_mode);
        match self.child.try_lock() {
            Ok(mut child) => {
                if let Some(child) = child.as_mut()
                    && let Err(error) = child.start_kill()
                {
                    tracing::warn!(
                        error = %error,
                        server = %self.server_name,
                        "failed to start MCP stdio child teardown"
                    );
                }
            }
            Err(_) => {
                tracing::warn!(
                    server = %self.server_name,
                    "MCP stdio child teardown already in progress"
                );
            }
        }
    }

    async fn poison_and_kill(&self, reason: &str) {
        self.awaiting_abandon_hook.store(false, Ordering::SeqCst);
        self.mark_poisoned(reason, PoisonReasonMode::Replace);
        let child = {
            let mut child = self.child.lock().await;
            child.take()
        };
        let Some(mut child) = child else {
            return;
        };
        if let Err(error) = child.start_kill() {
            tracing::warn!(
                error = %error,
                server = %self.server_name,
                "failed to kill MCP stdio child"
            );
        }
        match tokio::time::timeout(STDIO_POISON_WAIT_TIMEOUT, child.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::warn!(
                error = %error,
                server = %self.server_name,
                "failed waiting for MCP stdio child teardown"
            ),
            Err(_) => tracing::warn!(
                server = %self.server_name,
                "timed out waiting for MCP stdio child teardown"
            ),
        }
    }

    fn mark_poisoned(&self, reason: &str, reason_mode: PoisonReasonMode) {
        let was_poisoned = self.poisoned.swap(true, Ordering::SeqCst);
        if let Ok(mut stored) = self.poison_reason.lock()
            && (!was_poisoned
                || matches!(reason_mode, PoisonReasonMode::Replace)
                || stored.is_none())
        {
            *stored = Some(reason.to_string());
        }
    }

    fn mark_abandoned_request(&self) {
        self.awaiting_abandon_hook.store(true, Ordering::SeqCst);
        self.poison_sync("abandoned request future", PoisonReasonMode::Preserve);
    }
}

fn active_stdio_registry() -> &'static Mutex<Vec<Arc<StdioState>>> {
    static ACTIVE_STDIO: OnceLock<Mutex<Vec<Arc<StdioState>>>> = OnceLock::new();
    ACTIVE_STDIO.get_or_init(|| Mutex::new(Vec::new()))
}

fn register_active_stdio(state: &Arc<StdioState>) {
    if state.abandon_scope.is_none() {
        return;
    }
    if let Ok(mut registry) = active_stdio_registry().lock() {
        registry.push(state.clone());
    }
}

fn unregister_active_stdio(state: &Arc<StdioState>) {
    if let Ok(mut registry) = active_stdio_registry().lock() {
        registry.retain(|entry| !Arc::ptr_eq(entry, state));
    }
}

pub(crate) async fn poison_active_for_scope(scope: &StdioAbandonScope, reason: &str) {
    let states = {
        let Ok(mut registry) = active_stdio_registry().lock() else {
            return;
        };
        let mut states = Vec::new();
        registry.retain(|entry| {
            let matches_scope = entry.abandon_scope.as_ref() == Some(scope);
            if matches_scope {
                states.push(entry.clone());
            }
            !matches_scope
        });
        states
    };
    for state in states {
        state.poison_and_kill(reason).await;
    }
}

fn stdio_child_env(
    parent: impl IntoIterator<Item = (String, String)>,
    explicit: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut child = BTreeMap::new();
    for (key, value) in parent {
        if inherit_stdio_env_var(&key) {
            child.insert(key, value);
        }
    }
    for (key, value) in explicit {
        child.insert(key.clone(), value.clone());
    }
    child
}

pub(crate) fn inherit_stdio_env_var(key: &str) -> bool {
    matches!(
        key,
        "PATH"
            | "HOME"
            | "USER"
            | "LOGNAME"
            | "USERPROFILE"
            | "HOMEDRIVE"
            | "HOMEPATH"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "TEMP"
            | "TMP"
            | "TMPDIR"
            | "LANG"
            | "TERM"
            | "NO_COLOR"
            | "COLORTERM"
    ) || key.starts_with("LC_")
}

impl<R, W> Drop for StdioClient<R, W> {
    fn drop(&mut self) {
        self.state
            .poison_sync("client drop", PoisonReasonMode::Preserve);
        if !self.state.awaiting_abandon_hook.load(Ordering::SeqCst) {
            unregister_active_stdio(&self.state);
        }
    }
}

#[async_trait]
impl<R, W> McpClient for StdioClient<R, W>
where
    R: AsyncRead + Unpin + Send + Sync,
    W: AsyncWrite + Unpin + Send + Sync,
{
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
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    #[test]
    fn stdio_child_env_excludes_ambient_secrets_and_keeps_basics() {
        let parent = [
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/home/alice".to_string()),
            ("LC_ALL".to_string(), "C.UTF-8".to_string()),
            ("OPENAI_API_KEY".to_string(), "ambient-secret".to_string()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "ambient-secret".to_string(),
            ),
        ];
        let child = stdio_child_env(parent, &BTreeMap::new());

        assert_eq!(child.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(child.get("HOME").map(String::as_str), Some("/home/alice"));
        assert_eq!(child.get("LC_ALL").map(String::as_str), Some("C.UTF-8"));
        assert!(!child.contains_key("OPENAI_API_KEY"));
        assert!(!child.contains_key("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn stdio_child_env_includes_explicit_configured_env() {
        let parent = [("OPENAI_API_KEY".to_string(), "ambient-secret".to_string())];
        let mut explicit = BTreeMap::new();
        explicit.insert("SERVER_TOKEN".to_string(), "configured-secret".to_string());
        explicit.insert("PATH".to_string(), "/custom/bin".to_string());

        let child = stdio_child_env(parent, &explicit);

        assert!(!child.contains_key("OPENAI_API_KEY"));
        assert_eq!(
            child.get("SERVER_TOKEN").map(String::as_str),
            Some("configured-secret")
        );
        assert_eq!(child.get("PATH").map(String::as_str), Some("/custom/bin"));
    }

    type TestClient = StdioClient<
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
    >;

    fn test_client(
        request_timeout: Duration,
        cancel: Option<CancellationToken>,
    ) -> (
        TestClient,
        tokio::io::ReadHalf<tokio::io::DuplexStream>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
    ) {
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, server_write) = tokio::io::split(server_stream);
        let client = StdioClient::new(
            "test-server".to_string(),
            client_write,
            client_read,
            None,
            McpTimeouts {
                connect: Duration::from_secs(10),
                request: request_timeout,
            },
            StdioRuntimeContext {
                cancel,
                abandon_scope: None,
            },
        );
        (client, server_read, server_write)
    }

    async fn read_request_id(
        server_read: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
    ) -> u64 {
        let mut reader = BufReader::new(server_read);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let value: Value = serde_json::from_str(line.trim()).unwrap();
        value["id"].as_u64().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_request_times_out_at_configured_deadline() {
        let (client, mut server_read, _server_write) = test_client(Duration::from_secs(1), None);
        let client = Arc::new(tokio::sync::Mutex::new(client));
        let task = tokio::spawn({
            let client = client.clone();
            async move { client.lock().await.list_tools().await }
        });
        let _id = read_request_id(&mut server_read).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(err.to_string().contains("connection was reset"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_request_deadline_covers_notification_flood() {
        let (client, mut server_read, mut server_write) = test_client(Duration::from_secs(1), None);
        let client = Arc::new(tokio::sync::Mutex::new(client));
        let task = tokio::spawn({
            let client = client.clone();
            async move { client.lock().await.list_tools().await }
        });
        let _id = read_request_id(&mut server_read).await;
        for _ in 0..5 {
            server_write
                .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"progress\",\"params\":{}}\n")
                .await
                .unwrap();
        }

        tokio::time::advance(Duration::from_secs(1)).await;
        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_handshake_bounded_by_connect_timeout() {
        let (mut client, mut server_read, _server_write) =
            test_client(Duration::from_secs(120), None);
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(1), client.initialize()).await
        });
        let _id = read_request_id(&mut server_read).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_handshake_uses_connect_deadline_not_request_deadline() {
        let (mut client, mut server_read, _server_write) =
            test_client(Duration::from_secs(1), None);
        let task = tokio::spawn(async move {
            client
                .initialize_with_deadline(Duration::from_secs(5))
                .await
        });
        let _id = read_request_id(&mut server_read).await;

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(!task.is_finished(), "initialize used request timeout");
        tokio::time::advance(Duration::from_secs(4)).await;
        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_timed_out_connection_is_poisoned() {
        let (client, mut server_read, _server_write) = test_client(Duration::from_secs(1), None);
        let client = Arc::new(tokio::sync::Mutex::new(client));
        let task = tokio::spawn({
            let client = client.clone();
            async move { client.lock().await.list_tools().await }
        });
        let _id = read_request_id(&mut server_read).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let _ = task.await.unwrap().unwrap_err();

        let err = client.lock().await.list_tools().await.unwrap_err();
        assert!(err.to_string().contains("test-server"), "{err}");
        assert!(
            err.to_string()
                .contains("connection was reset after timeout"),
            "{err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_poisoned_connection_never_returns_stale_frame() {
        let (client, mut server_read, mut server_write) = test_client(Duration::from_secs(1), None);
        let client = Arc::new(tokio::sync::Mutex::new(client));
        let task = tokio::spawn({
            let client = client.clone();
            async move { client.lock().await.list_tools().await }
        });
        let id = read_request_id(&mut server_read).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        let _ = task.await.unwrap().unwrap_err();

        let late = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": [{ "name": "stale", "description": "", "inputSchema": {} }] }
        });
        server_write
            .write_all(format!("{late}\n").as_bytes())
            .await
            .unwrap();

        let err = client.lock().await.list_tools().await.unwrap_err();
        assert!(err.to_string().contains("connection was reset"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_cancel_abandons_request_and_poisons() {
        let cancel = CancellationToken::new();
        let (client, mut server_read, _server_write) =
            test_client(Duration::from_secs(60), Some(cancel.clone()));
        let client = Arc::new(tokio::sync::Mutex::new(client));
        let task = tokio::spawn({
            let client = client.clone();
            async move { client.lock().await.list_tools().await }
        });
        let _id = read_request_id(&mut server_read).await;
        cancel.cancel();

        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("cancelled"), "{err}");
        let err = client.lock().await.list_tools().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("connection was reset after cancellation"),
            "{err}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_on_abandon_is_idempotent() {
        let scope = StdioAbandonScope {
            session_id: Uuid::new_v4(),
            tool_call_id: Some("call-1".to_string()),
        };
        let (client, _server_read, _server_write) = {
            let (client_stream, server_stream) = tokio::io::duplex(4096);
            let (client_read, client_write) = tokio::io::split(client_stream);
            let (server_read, server_write) = tokio::io::split(server_stream);
            let client = StdioClient::new(
                "test-server".to_string(),
                client_write,
                client_read,
                None,
                McpTimeouts::from_secs(10, 60),
                StdioRuntimeContext {
                    cancel: None,
                    abandon_scope: Some(scope.clone()),
                },
            );
            (client, server_read, server_write)
        };
        let state = client.state.clone();

        poison_active_for_scope(&scope, "abandon hook").await;
        poison_active_for_scope(&scope, "abandon hook").await;

        assert!(state.poisoned.load(Ordering::SeqCst));
        let err = client.state.ensure_not_poisoned().unwrap_err();
        assert!(err.to_string().contains("abandon hook"), "{err}");
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_on_abandon_reaches_dropped_abandoned_client() {
        let scope = StdioAbandonScope {
            session_id: Uuid::new_v4(),
            tool_call_id: Some("call-2".to_string()),
        };
        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (_server_read, _server_write) = tokio::io::split(server_stream);
        let client = StdioClient::new(
            "test-server".to_string(),
            client_write,
            client_read,
            None,
            McpTimeouts::from_secs(10, 60),
            StdioRuntimeContext {
                cancel: None,
                abandon_scope: Some(scope.clone()),
            },
        );
        let state = client.state.clone();

        state.mark_abandoned_request();
        drop(client);
        poison_active_for_scope(&scope, "MCP tool abandon").await;

        let err = state.ensure_not_poisoned().unwrap_err();
        assert!(err.to_string().contains("MCP tool abandon"), "{err}");
        assert!(
            !active_stdio_registry()
                .lock()
                .unwrap()
                .iter()
                .any(|entry| Arc::ptr_eq(entry, &state)),
            "abandon hook should remove matched state from registry"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mcp_stdio_poison_kills_child_process() {
        if std::env::var_os("COCKPIT_MCP_STDIO_TEST_CHILD").is_some() {
            std::thread::park();
            return;
        }

        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg("--ignored")
            .arg("mcp_stdio_poison_kills_child_process")
            .arg("--exact")
            .env("COCKPIT_MCP_STDIO_TEST_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let client = StdioClient::new(
            "child-server".to_string(),
            stdin,
            stdout,
            Some(child),
            McpTimeouts::from_secs(10, 60),
            StdioRuntimeContext::default(),
        );
        let state = client.state.clone();

        client.poison("test poison").await;

        assert!(state.poisoned.load(Ordering::SeqCst));
        assert!(state.child.lock().await.is_none());
    }

    #[test]
    #[ignore]
    fn mcp_stdio_child_process_fixture() {
        if std::env::var_os("COCKPIT_MCP_STDIO_TEST_CHILD").is_some() {
            std::thread::park();
        }
    }
}
