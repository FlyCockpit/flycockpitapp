//! Daemon-owned Language Server Protocol manager.
//!
//! The manager is advisory: every public method returns an empty/tight result
//! on missing, broken, or slow servers rather than failing the calling turn.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use lsp_types::notification::Notification;
use lsp_types::notification::{DidChangeTextDocument, DidOpenTextDocument, PublishDiagnostics};
use lsp_types::request::Request;
use lsp_types::request::{GotoDefinition, HoverRequest, References};
use lsp_types::{
    ClientCapabilities, DidChangeTextDocumentParams, DidOpenTextDocumentParams,
    GotoDefinitionParams, Hover, HoverParams, InitializeParams, InitializeResult,
    InitializedParams, Location, Position, PublishDiagnosticsParams, ReferenceParams,
    TextDocumentContentChangeEvent, TextDocumentIdentifier, TextDocumentItem,
    TextDocumentPositionParams, Uri, WorkDoneProgressParams,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
#[cfg(test)]
use tokio::sync::broadcast;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::extended::{ExtendedConfig, LspAutoInstall};
use crate::daemon::{EventSender, SharedRedactionTable, send_current_event};
#[cfg(test)]
use crate::redact::RedactionTable;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LspServerStatus {
    Installed,
    Missing,
    Disabled,
    Broken,
    Installing,
}

impl LspServerStatus {
    fn as_str(self) -> &'static str {
        match self {
            LspServerStatus::Installed => "installed",
            LspServerStatus::Missing => "missing",
            LspServerStatus::Disabled => "disabled",
            LspServerStatus::Broken => "broken",
            LspServerStatus::Installing => "installing",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LspServerView {
    pub id: String,
    pub status: LspServerStatus,
    pub command: Vec<String>,
    pub install_command: Option<Vec<String>>,
    pub uninstall_command: Option<Vec<String>>,
    pub manual_guidance: String,
    pub cockpit_installed: bool,
}

#[derive(Debug, Clone)]
pub struct LspNavigationRequest {
    pub operation: LspOperation,
    pub file: PathBuf,
    pub line: Option<u32>,
    pub character: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LspOperation {
    Hover,
    Definition,
    References,
}

#[derive(Debug, Clone)]
pub struct LspManager {
    inner: Arc<LspInner>,
}

#[derive(Debug)]
struct LspInner {
    clients: Mutex<HashMap<ClientKey, Arc<LspClient>>>,
    statuses: RwLock<HashMap<String, LspServerStatus>>,
    prompted: Mutex<HashSet<String>>,
    installed: RwLock<HashMap<String, InstalledRecord>>,
    notices: StdMutex<Option<(EventSender, SharedRedactionTable)>>,
}

#[derive(Debug, Clone)]
struct InstalledRecord {
    #[allow(dead_code)]
    command: Vec<String>,
    #[allow(dead_code)]
    installed_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClientKey {
    server_id: String,
    root: PathBuf,
}

impl LspManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(LspInner {
                clients: Mutex::new(HashMap::new()),
                statuses: RwLock::new(HashMap::new()),
                prompted: Mutex::new(HashSet::new()),
                installed: RwLock::new(HashMap::new()),
                notices: StdMutex::new(None),
            }),
        }
    }

    pub fn set_notice_bus(&self, tx: EventSender, redaction: SharedRedactionTable) {
        *crate::sync::lock_or_recover(&self.inner.notices) = Some((tx, redaction));
    }

    #[allow(dead_code)]
    pub async fn server_views(&self, cwd: &Path, config: &ExtendedConfig) -> Vec<LspServerView> {
        let statuses = self.inner.statuses.read().await;
        let installed = self.inner.installed.read().await;
        registry()
            .into_iter()
            .map(|recipe| {
                let recipe = recipe.with_config(config);
                let status = if recipe.disabled {
                    LspServerStatus::Disabled
                } else if let Some(s) = statuses.get(recipe.id) {
                    *s
                } else if command_exists(&recipe.command[0]) {
                    LspServerStatus::Installed
                } else {
                    LspServerStatus::Missing
                };
                let cockpit_installed = installed.contains_key(recipe.id);
                LspServerView {
                    id: recipe.id.to_string(),
                    status,
                    command: recipe.command.clone(),
                    install_command: recipe.install_command(cwd).map(|c| c.argv),
                    uninstall_command: recipe.uninstall_command(cwd).map(|c| c.argv),
                    manual_guidance: recipe.manual_guidance.to_string(),
                    cockpit_installed,
                }
            })
            .collect()
    }

    pub async fn diagnostics_after_write(
        &self,
        cwd: &Path,
        file: &Path,
        config: &ExtendedConfig,
    ) -> String {
        if !config.lsp.enabled || !config.lsp.diagnostics.enabled {
            return String::new();
        }
        let Some(client) = self.client_for_file(cwd, file, config).await else {
            return String::new();
        };
        let text = match tokio::fs::read_to_string(file).await {
            Ok(t) => t,
            Err(e) => {
                debug!("lsp read after write skipped for {}: {e}", file.display());
                return String::new();
            }
        };
        if client.did_open_or_change(file, text).await.is_err() {
            client.mark_broken().await;
            return String::new();
        }
        let doc_timeout = Duration::from_millis(config.lsp.diagnostics.document_timeout_ms);
        let workspace_timeout = Duration::from_millis(config.lsp.diagnostics.workspace_timeout_ms);
        client
            .settle_and_render(
                file,
                Duration::from_millis(config.lsp.diagnostics.debounce_ms),
                doc_timeout,
                workspace_timeout,
                config.lsp.diagnostics.other_files_limit,
                config.lsp.diagnostics.per_file_limit,
            )
            .await
    }

    pub async fn navigate(
        &self,
        cwd: &Path,
        req: LspNavigationRequest,
        config: &ExtendedConfig,
    ) -> String {
        if !config.lsp.enabled {
            return "LSP is disabled.".to_string();
        }
        let Some(client) = self.client_for_file(cwd, &req.file, config).await else {
            return "No available LSP server for this file.".to_string();
        };
        let line = req.line.unwrap_or(1).saturating_sub(1);
        let character = req.character.unwrap_or(1).saturating_sub(1);
        let pos = Position::new(line, character);
        match req.operation {
            LspOperation::Hover => client.hover(&req.file, pos).await,
            LspOperation::Definition => client.definition(&req.file, pos).await,
            LspOperation::References => client.references(&req.file, pos).await,
        }
        .unwrap_or_else(|e| {
            warn!("lsp navigation failed for {}: {e}", req.file.display());
            "LSP navigation unavailable.".to_string()
        })
    }

    pub async fn control(
        &self,
        cwd: &Path,
        server_id: &str,
        action: crate::daemon::proto::LspControlAction,
        config: &ExtendedConfig,
    ) -> String {
        let Some(recipe) = registry()
            .into_iter()
            .find(|r| r.id == server_id)
            .map(|r| r.with_config(config))
        else {
            return format!("Unknown LSP server `{server_id}`.");
        };
        match action {
            crate::daemon::proto::LspControlAction::Check => {
                let status = if recipe.disabled {
                    LspServerStatus::Disabled
                } else if command_exists(&recipe.command[0]) {
                    LspServerStatus::Installed
                } else {
                    LspServerStatus::Missing
                };
                self.inner
                    .statuses
                    .write()
                    .await
                    .insert(recipe.id.to_string(), status);
                format!(
                    "LSP `{}` status: {}. command: {}",
                    recipe.id,
                    status.as_str(),
                    shell_join(&recipe.command)
                )
            }
            crate::daemon::proto::LspControlAction::Install => self.install(&recipe, cwd).await,
            crate::daemon::proto::LspControlAction::Uninstall => self.uninstall(&recipe, cwd).await,
            crate::daemon::proto::LspControlAction::Restart => self.restart(recipe.id).await,
        }
    }

    async fn install(&self, recipe: &Recipe, cwd: &Path) -> String {
        let Some(install) = recipe.install_command(cwd) else {
            let msg = format!(
                "LSP `{}` has no automatic install recipe available. {}",
                recipe.id, recipe.manual_guidance
            );
            self.notice(msg.clone()).await;
            return msg;
        };
        self.inner
            .statuses
            .write()
            .await
            .insert(recipe.id.to_string(), LspServerStatus::Installing);
        let outcome = run_command_capture(&install.argv).await;
        match outcome {
            CommandOutcome::Success { .. } if command_exists(&recipe.command[0]) => {
                self.inner.installed.write().await.insert(
                    recipe.id.to_string(),
                    InstalledRecord {
                        command: install.argv.clone(),
                        installed_at_unix: chrono::Utc::now().timestamp(),
                    },
                );
                self.inner
                    .statuses
                    .write()
                    .await
                    .insert(recipe.id.to_string(), LspServerStatus::Installed);
                format!(
                    "Installed LSP `{}` with `{}`.",
                    recipe.id,
                    shell_join(&install.argv)
                )
            }
            CommandOutcome::Success {
                status,
                stdout,
                stderr,
            } => {
                let msg = install_failure_message(
                    recipe,
                    &install.argv,
                    &format!("{status}; `{}` still not found on PATH", recipe.command[0]),
                    &stdout,
                    &stderr,
                );
                self.inner
                    .statuses
                    .write()
                    .await
                    .insert(recipe.id.to_string(), LspServerStatus::Missing);
                self.notice(msg.clone()).await;
                msg
            }
            CommandOutcome::Failure {
                status,
                stdout,
                stderr,
            } => {
                let msg = install_failure_message(recipe, &install.argv, &status, &stdout, &stderr);
                self.inner
                    .statuses
                    .write()
                    .await
                    .insert(recipe.id.to_string(), LspServerStatus::Missing);
                self.notice(msg.clone()).await;
                msg
            }
        }
    }

    async fn uninstall(&self, recipe: &Recipe, cwd: &Path) -> String {
        if !self.inner.installed.read().await.contains_key(recipe.id) {
            return format!(
                "LSP `{}` was not installed by Cockpit in this daemon session; uninstall skipped.",
                recipe.id
            );
        }
        let Some(uninstall) = recipe.uninstall_command(cwd) else {
            return format!("LSP `{}` has no automatic uninstall recipe.", recipe.id);
        };
        match run_command_capture(&uninstall.argv).await {
            CommandOutcome::Success { .. } => {
                self.inner.installed.write().await.remove(recipe.id);
                self.restart(recipe.id).await;
                self.inner
                    .statuses
                    .write()
                    .await
                    .insert(recipe.id.to_string(), LspServerStatus::Missing);
                format!(
                    "Uninstalled LSP `{}` with `{}`.",
                    recipe.id,
                    shell_join(&uninstall.argv)
                )
            }
            CommandOutcome::Failure {
                status,
                stdout,
                stderr,
            } => {
                format!(
                    "Failed to uninstall LSP `{}` with `{}`: {status}\nstdout tail:\n{}\nstderr tail:\n{}",
                    recipe.id,
                    shell_join(&uninstall.argv),
                    stdout,
                    stderr
                )
            }
        }
    }

    async fn restart(&self, server_id: &str) -> String {
        let mut clients = self.inner.clients.lock().await;
        let before = clients.len();
        clients.retain(|key, _| key.server_id != server_id);
        let stopped = before.saturating_sub(clients.len());
        self.inner.statuses.write().await.remove(server_id);
        format!("Restarted LSP `{server_id}`; stopped {stopped} cached client(s).")
    }

    async fn notice(&self, text: String) {
        if let Some((tx, redaction)) = crate::sync::lock_or_recover(&self.inner.notices).as_ref() {
            send_current_event(
                tx,
                redaction,
                crate::daemon::proto::Event::LspNotice { text },
            );
        }
    }

    async fn client_for_file(
        &self,
        cwd: &Path,
        file: &Path,
        config: &ExtendedConfig,
    ) -> Option<Arc<LspClient>> {
        let recipe = registry()
            .into_iter()
            .map(|r| r.with_config(config))
            .find(|r| r.matches(file))?;
        if recipe.disabled {
            self.inner
                .statuses
                .write()
                .await
                .insert(recipe.id.to_string(), LspServerStatus::Disabled);
            return None;
        }
        let root = find_root(file, cwd, &recipe.root_markers);
        let key = ClientKey {
            server_id: recipe.id.to_string(),
            root: root.clone(),
        };
        let idle_ttl = Duration::from_secs(config.lsp.idle_ttl_secs);
        let max_cached = config.lsp.max_cached_clients.max(1);
        let cached = {
            let mut clients = self.inner.clients.lock().await;
            evict_lsp_clients(&mut clients, Instant::now(), idle_ttl, max_cached);
            clients.get(&key).cloned()
        };
        if let Some(client) = cached
            && !client.is_broken().await
        {
            client.touch();
            return Some(client);
        }
        if !command_exists(&recipe.command[0]) {
            self.handle_missing(&recipe, cwd, config).await;
            return None;
        }
        match LspClient::spawn(recipe.clone(), root).await {
            Ok(client) => {
                let client = Arc::new(client);
                {
                    let mut clients = self.inner.clients.lock().await;
                    clients.insert(key, client.clone());
                    evict_lsp_clients(&mut clients, Instant::now(), idle_ttl, max_cached);
                }
                self.inner
                    .statuses
                    .write()
                    .await
                    .insert(recipe.id.to_string(), LspServerStatus::Installed);
                Some(client)
            }
            Err(e) => {
                warn!("lsp spawn failed for {}: {e}", recipe.id);
                self.inner
                    .statuses
                    .write()
                    .await
                    .insert(recipe.id.to_string(), LspServerStatus::Broken);
                None
            }
        }
    }

    async fn handle_missing(&self, recipe: &Recipe, cwd: &Path, config: &ExtendedConfig) {
        self.inner
            .statuses
            .write()
            .await
            .insert(recipe.id.to_string(), LspServerStatus::Missing);
        match config.lsp.auto_install {
            LspAutoInstall::Off | LspAutoInstall::Ask => {
                let mut prompted = self.inner.prompted.lock().await;
                if prompted.insert(recipe.id.to_string()) {
                    let install = recipe
                        .install_command(cwd)
                        .map(|c| shell_join(&c.argv))
                        .unwrap_or_else(|| "no automatic install recipe available".to_string());
                    warn!(
                        "LSP server `{}` missing; mode={}; install={}; guidance={}",
                        recipe.id,
                        config.lsp.auto_install.as_str(),
                        install,
                        recipe.manual_guidance
                    );
                }
            }
            LspAutoInstall::On => {
                let Some(install) = recipe.install_command(cwd) else {
                    warn!(
                        "LSP server `{}` missing and no install prerequisite is available: {}",
                        recipe.id, recipe.manual_guidance
                    );
                    return;
                };
                self.inner
                    .statuses
                    .write()
                    .await
                    .insert(recipe.id.to_string(), LspServerStatus::Installing);
                match run_command_capture(&install.argv).await {
                    CommandOutcome::Success { .. } if command_exists(&recipe.command[0]) => {
                        self.inner.installed.write().await.insert(
                            recipe.id.to_string(),
                            InstalledRecord {
                                command: install.argv.clone(),
                                installed_at_unix: chrono::Utc::now().timestamp(),
                            },
                        );
                        self.inner
                            .statuses
                            .write()
                            .await
                            .insert(recipe.id.to_string(), LspServerStatus::Installed);
                    }
                    CommandOutcome::Success {
                        status,
                        stdout,
                        stderr,
                    } => {
                        let msg = install_failure_message(
                            recipe,
                            &install.argv,
                            &format!("{status}; `{}` still not found on PATH", recipe.command[0]),
                            &stdout,
                            &stderr,
                        );
                        warn!("{msg}");
                        self.notice(msg).await;
                        self.inner
                            .statuses
                            .write()
                            .await
                            .insert(recipe.id.to_string(), LspServerStatus::Missing);
                    }
                    CommandOutcome::Failure {
                        status,
                        stdout,
                        stderr,
                    } => {
                        let msg = install_failure_message(
                            recipe,
                            &install.argv,
                            &status,
                            &stdout,
                            &stderr,
                        );
                        warn!("{msg}");
                        self.notice(msg).await;
                        self.inner
                            .statuses
                            .write()
                            .await
                            .insert(recipe.id.to_string(), LspServerStatus::Missing);
                    }
                }
            }
        }
    }
}

impl Default for LspManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn builtin_server_views(cwd: &Path, config: &ExtendedConfig) -> Vec<LspServerView> {
    registry()
        .into_iter()
        .map(|recipe| {
            let recipe = recipe.with_config(config);
            let status = if recipe.disabled {
                LspServerStatus::Disabled
            } else if command_exists(&recipe.command[0]) {
                LspServerStatus::Installed
            } else {
                LspServerStatus::Missing
            };
            LspServerView {
                id: recipe.id.to_string(),
                status,
                command: recipe.command.clone(),
                install_command: recipe.install_command(cwd).map(|c| c.argv),
                uninstall_command: recipe.uninstall_command(cwd).map(|c| c.argv),
                manual_guidance: recipe.manual_guidance.to_string(),
                cockpit_installed: false,
            }
        })
        .collect()
}

#[derive(Debug)]
struct LspClient {
    recipe: Recipe,
    root: PathBuf,
    child: Mutex<Child>,
    stdin: Arc<Mutex<ChildStdin>>,
    next_id: Arc<Mutex<u64>>,
    pending: Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Value>>>>,
    diagnostics: Arc<RwLock<HashMap<PathBuf, Vec<lsp_types::Diagnostic>>>>,
    versions: Arc<Mutex<HashMap<PathBuf, i32>>>,
    notify: Arc<Notify>,
    broken: Arc<RwLock<bool>>,
    last_used: StdMutex<Instant>,
}

impl LspClient {
    async fn spawn(recipe: Recipe, root: PathBuf) -> Result<Self> {
        let mut cmd = Command::new(&recipe.command[0]);
        cmd.args(&recipe.command[1..])
            .current_dir(&root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "spawning LSP server `{}` with `{}`",
                recipe.id,
                shell_join(&recipe.command)
            )
        })?;
        let stdin = child.stdin.take().context("LSP child missing stdin")?;
        let stdout = child.stdout.take().context("LSP child missing stdout")?;
        let client = Self {
            recipe,
            root,
            child: Mutex::new(child),
            stdin: Arc::new(Mutex::new(stdin)),
            next_id: Arc::new(Mutex::new(1)),
            pending: Arc::new(Mutex::new(HashMap::new())),
            diagnostics: Arc::new(RwLock::new(HashMap::new())),
            versions: Arc::new(Mutex::new(HashMap::new())),
            notify: Arc::new(Notify::new()),
            broken: Arc::new(RwLock::new(false)),
            last_used: StdMutex::new(Instant::now()),
        };
        client.start_reader(stdout);
        let root_uri = path_to_uri(&client.root)?;
        #[allow(deprecated)]
        let params = InitializeParams {
            process_id: Some(std::process::id()),
            root_uri: Some(root_uri),
            capabilities: ClientCapabilities::default(),
            ..InitializeParams::default()
        };
        let _: InitializeResult = timeout(
            Duration::from_secs(45),
            client.request("initialize", params),
        )
        .await
        .context("LSP initialize timed out")??;
        client
            .notify("initialized", InitializedParams {})
            .await
            .context("sending initialized")?;
        Ok(client)
    }

    fn touch(&self) {
        *crate::sync::lock_or_recover(&self.last_used) = Instant::now();
    }

    fn last_used(&self) -> Instant {
        *crate::sync::lock_or_recover(&self.last_used)
    }

    fn start_reader(&self, stdout: tokio::process::ChildStdout) {
        let pending = self.pending.clone();
        let diagnostics = self.diagnostics.clone();
        let notify = self.notify.clone();
        let broken = self.broken.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_lsp_message(&mut reader).await {
                    Ok(value) => {
                        if let Some(method) = value.get("method").and_then(Value::as_str)
                            && method == PublishDiagnostics::METHOD
                            && let Some(params) = value.get("params")
                            && let Ok(params) =
                                serde_json::from_value::<PublishDiagnosticsParams>(params.clone())
                            && let Some(path) = uri_to_path(&params.uri)
                        {
                            diagnostics.write().await.insert(path, params.diagnostics);
                            notify.notify_waiters();
                            continue;
                        }
                        if let Some(id) = value.get("id").and_then(Value::as_u64)
                            && let Some(tx) = pending.lock().await.remove(&id)
                        {
                            let _ = tx.send(value);
                        }
                    }
                    Err(e) => {
                        debug!("LSP reader ended: {e}");
                        *broken.write().await = true;
                        break;
                    }
                }
            }
        });
    }

    async fn is_broken(&self) -> bool {
        *self.broken.read().await
    }

    async fn mark_broken(&self) {
        *self.broken.write().await = true;
    }

    async fn request<P, R>(&self, method: &str, params: P) -> Result<R>
    where
        P: serde::Serialize,
        R: DeserializeOwned,
    {
        let id = {
            let mut next = self.next_id.lock().await;
            let id = *next;
            *next += 1;
            id
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        if let Err(e) = self
            .write(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await
        {
            remove_lsp_pending(&self.pending, id).await;
            return Err(e);
        }
        let value = match timeout(Duration::from_secs(10), rx).await {
            Ok(result) => result.context("LSP response channel closed")?,
            Err(e) => {
                remove_lsp_pending(&self.pending, id).await;
                return Err(e).context("LSP request timed out");
            }
        };
        if let Some(err) = value.get("error") {
            return Err(anyhow!("LSP `{method}` error: {err}"));
        }
        let result = value.get("result").cloned().unwrap_or(Value::Null);
        serde_json::from_value(result).with_context(|| format!("decoding LSP `{method}` result"))
    }

    async fn notify<P: serde::Serialize>(&self, method: &str, params: P) -> Result<()> {
        self.write(json!({"jsonrpc":"2.0","method":method,"params":params}))
            .await
    }

    async fn write(&self, value: Value) -> Result<()> {
        let bytes = serde_json::to_vec(&value)?;
        let header = format!("Content-Length: {}\r\n\r\n", bytes.len());
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(header.as_bytes()).await?;
        stdin.write_all(&bytes).await?;
        stdin.flush().await?;
        Ok(())
    }

    async fn did_open_or_change(&self, file: &Path, text: String) -> Result<()> {
        let uri = path_to_uri(file)?;
        let mut versions = self.versions.lock().await;
        let version = versions.entry(file.to_path_buf()).or_insert(0);
        *version += 1;
        if *version == 1 {
            self.notify(
                DidOpenTextDocument::METHOD,
                DidOpenTextDocumentParams {
                    text_document: TextDocumentItem {
                        uri,
                        language_id: self.recipe.language_id.to_string(),
                        version: *version,
                        text,
                    },
                },
            )
            .await
        } else {
            self.notify(
                DidChangeTextDocument::METHOD,
                DidChangeTextDocumentParams {
                    text_document: lsp_types::VersionedTextDocumentIdentifier {
                        uri,
                        version: *version,
                    },
                    content_changes: vec![TextDocumentContentChangeEvent {
                        range: None,
                        range_length: None,
                        text,
                    }],
                },
            )
            .await
        }
    }

    async fn settle_and_render(
        &self,
        edited_file: &Path,
        debounce: Duration,
        doc_timeout: Duration,
        workspace_timeout: Duration,
        other_files_limit: usize,
        per_file_limit: usize,
    ) -> String {
        let start = Instant::now();
        loop {
            if self.diagnostics.read().await.contains_key(edited_file) {
                break;
            }
            let remaining = doc_timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }
            if timeout(
                remaining.min(Duration::from_millis(200)),
                self.notify.notified(),
            )
            .await
            .is_err()
            {
                break;
            }
        }
        let _ = timeout(debounce, self.notify.notified()).await;
        let _ = timeout(
            workspace_timeout.min(Duration::from_millis(50)),
            self.notify.notified(),
        )
        .await;
        render_diagnostics(
            &*self.diagnostics.read().await,
            edited_file,
            other_files_limit,
            per_file_limit,
        )
    }

    async fn hover(&self, file: &Path, position: Position) -> Result<String> {
        let params = HoverParams {
            text_document_position_params: tdpp(file, position)?,
            work_done_progress_params: WorkDoneProgressParams::default(),
        };
        let hover: Option<Hover> = self.request(HoverRequest::METHOD, params).await?;
        Ok(match hover {
            Some(h) => format_hover(h),
            None => "No hover result.".to_string(),
        })
    }

    async fn definition(&self, file: &Path, position: Position) -> Result<String> {
        let params = GotoDefinitionParams {
            text_document_position_params: tdpp(file, position)?,
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: Default::default(),
        };
        let result: Option<lsp_types::GotoDefinitionResponse> =
            self.request(GotoDefinition::METHOD, params).await?;
        Ok(format_locations(match result {
            Some(lsp_types::GotoDefinitionResponse::Scalar(loc)) => vec![loc],
            Some(lsp_types::GotoDefinitionResponse::Array(locs)) => locs,
            Some(lsp_types::GotoDefinitionResponse::Link(links)) => links
                .into_iter()
                .map(|l| Location::new(l.target_uri, l.target_selection_range))
                .collect(),
            None => Vec::new(),
        }))
    }

    async fn references(&self, file: &Path, position: Position) -> Result<String> {
        let params = ReferenceParams {
            text_document_position: tdpp(file, position)?,
            context: lsp_types::ReferenceContext {
                include_declaration: true,
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: Default::default(),
        };
        let locs: Option<Vec<Location>> = self.request(References::METHOD, params).await?;
        Ok(format_locations(locs.unwrap_or_default()))
    }
}

fn evict_lsp_clients(
    clients: &mut HashMap<ClientKey, Arc<LspClient>>,
    now: Instant,
    idle_ttl: Duration,
    max_cached: usize,
) {
    clients.retain(|_, client| now.duration_since(client.last_used()) <= idle_ttl);
    if clients.len() <= max_cached {
        return;
    }
    let mut by_age: Vec<_> = clients
        .iter()
        .map(|(key, client)| (key.clone(), client.last_used()))
        .collect();
    by_age.sort_by_key(|(_, last_used)| *last_used);
    let remove_count = clients.len().saturating_sub(max_cached);
    for (key, _) in by_age.into_iter().take(remove_count) {
        clients.remove(&key);
    }
}

#[cfg(test)]
fn select_lsp_evictions(
    entries: &[(ClientKey, Instant)],
    now: Instant,
    idle_ttl: Duration,
    max_cached: usize,
) -> Vec<ClientKey> {
    let mut evict: Vec<_> = entries
        .iter()
        .filter_map(|(key, last_used)| {
            (now.duration_since(*last_used) > idle_ttl).then_some(key.clone())
        })
        .collect();
    let survivors = entries.len().saturating_sub(evict.len());
    if survivors > max_cached {
        let mut cached_survivors: Vec<_> = entries
            .iter()
            .filter(|(key, _)| !evict.contains(key))
            .map(|(key, last_used)| (key.clone(), *last_used))
            .collect();
        cached_survivors.sort_by_key(|(_, last_used)| *last_used);
        evict.extend(
            cached_survivors
                .into_iter()
                .take(survivors - max_cached)
                .map(|(key, _)| key),
        );
    }
    evict
}

async fn remove_lsp_pending(
    pending: &Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Value>>>>,
    id: u64,
) -> bool {
    pending.lock().await.remove(&id).is_some()
}

impl Drop for LspClient {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.try_lock() {
            let _ = child.start_kill();
        }
    }
}

async fn read_lsp_message(reader: &mut BufReader<tokio::process::ChildStdout>) -> Result<Value> {
    let mut content_len = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(anyhow!("LSP stdout closed"));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some(v) = trimmed.strip_prefix("Content-Length:") {
            content_len = Some(v.trim().parse::<usize>()?);
        }
    }
    let len = content_len.context("missing Content-Length")?;
    let mut body = vec![0; len];
    reader.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

fn tdpp(file: &Path, position: Position) -> Result<TextDocumentPositionParams> {
    let uri = path_to_uri(file)?;
    Ok(TextDocumentPositionParams {
        text_document: TextDocumentIdentifier { uri },
        position,
    })
}

fn path_to_uri(path: &Path) -> Result<Uri> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let s = path
        .to_string_lossy()
        .replace('\\', "/")
        .split('/')
        .map(|part| part.replace(' ', "%20"))
        .collect::<Vec<_>>()
        .join("/");
    format!("file://{s}")
        .parse::<Uri>()
        .map_err(|e| anyhow!("invalid file URI for {}: {e}", path.display()))
}

fn uri_to_path(uri: &Uri) -> Option<PathBuf> {
    let s = uri.to_string();
    let rest = s.strip_prefix("file://")?;
    Some(PathBuf::from(rest.replace("%20", " ")))
}

fn render_diagnostics(
    diagnostics: &HashMap<PathBuf, Vec<lsp_types::Diagnostic>>,
    edited_file: &Path,
    other_files_limit: usize,
    per_file_limit: usize,
) -> String {
    let mut files = Vec::new();
    if let Some(ds) = diagnostics.get(edited_file) {
        files.push((edited_file.to_path_buf(), ds.clone()));
    }
    let mut other_count = 0usize;
    for (path, ds) in diagnostics {
        if path != edited_file && other_count < other_files_limit {
            files.push((path.clone(), ds.clone()));
            other_count += 1;
        }
    }
    let mut out = String::new();
    for (path, ds) in files {
        let errors: Vec<_> = ds
            .into_iter()
            .filter(|d| d.severity == Some(lsp_types::DiagnosticSeverity::ERROR))
            .collect();
        if errors.is_empty() {
            continue;
        }
        if out.is_empty() {
            out.push_str("\n\nLSP errors detected; fix them:\n");
        }
        out.push_str(&format!("<diagnostics file=\"{}\">\n", path.display()));
        let total = errors.len();
        for d in errors.into_iter().take(per_file_limit) {
            out.push_str(&format!(
                "ERROR [{}:{}] {}\n",
                d.range.start.line + 1,
                d.range.start.character + 1,
                one_line(&d.message)
            ));
        }
        if total > per_file_limit {
            out.push_str(&format!("... and {} more\n", total - per_file_limit));
        }
        out.push_str("</diagnostics>");
    }
    out
}

fn format_hover(hover: Hover) -> String {
    match hover.contents {
        lsp_types::HoverContents::Scalar(s) => marked_string(s),
        lsp_types::HoverContents::Array(items) => items
            .into_iter()
            .map(marked_string)
            .collect::<Vec<_>>()
            .join("\n"),
        lsp_types::HoverContents::Markup(m) => m.value,
    }
}

fn marked_string(s: lsp_types::MarkedString) -> String {
    match s {
        lsp_types::MarkedString::String(s) => s,
        lsp_types::MarkedString::LanguageString(ls) => ls.value,
    }
}

fn format_locations(locs: Vec<Location>) -> String {
    if locs.is_empty() {
        return "No locations.".to_string();
    }
    locs.into_iter()
        .take(50)
        .map(|l| {
            let uri = l.uri;
            let file = uri_to_path(&uri)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| uri.to_string());
            format!(
                "{}:{}:{}",
                file,
                l.range.start.line + 1,
                l.range.start.character + 1
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Clone)]
struct Recipe {
    id: &'static str,
    language_id: &'static str,
    extensions: Vec<String>,
    root_markers: Vec<String>,
    command: Vec<String>,
    manual_guidance: String,
    disabled: bool,
    install: Vec<InstallRecipe>,
    uninstall: Vec<InstallRecipe>,
}

#[derive(Debug, Clone)]
struct InstallRecipe {
    prerequisite: String,
    argv: Vec<String>,
}

impl Recipe {
    fn with_config(mut self, config: &ExtendedConfig) -> Self {
        if let Some(override_cfg) = config.lsp.servers.get(self.id) {
            self.disabled = !override_cfg.enabled;
            if let Some(command) = &override_cfg.command
                && !command.is_empty()
            {
                self.command = command.clone();
            }
            if !override_cfg.extensions.is_empty() {
                self.extensions = override_cfg.extensions.clone();
            }
            if !override_cfg.root_markers.is_empty() {
                self.root_markers = override_cfg.root_markers.clone();
            }
            if let Some(command) = &override_cfg.install_command
                && !command.is_empty()
            {
                self.install = vec![InstallRecipe {
                    prerequisite: command[0].clone(),
                    argv: command.clone(),
                }];
            }
            if let Some(guidance) = &override_cfg.manual_guidance {
                self.manual_guidance = guidance.clone();
            }
        }
        self
    }

    fn matches(&self, file: &Path) -> bool {
        file.extension()
            .and_then(|e| e.to_str())
            .map(|e| self.extensions.iter().any(|known| known == e))
            .unwrap_or(false)
    }

    fn install_command(&self, _cwd: &Path) -> Option<InstallRecipe> {
        self.install
            .iter()
            .find(|r| command_exists(&r.prerequisite))
            .cloned()
    }

    fn uninstall_command(&self, _cwd: &Path) -> Option<InstallRecipe> {
        self.uninstall
            .iter()
            .find(|r| command_exists(&r.prerequisite))
            .cloned()
    }
}

fn registry() -> Vec<Recipe> {
    vec![
        Recipe {
            id: "rust-analyzer",
            language_id: "rust",
            extensions: vec!["rs".into()],
            root_markers: vec![
                "Cargo.toml".into(),
                "rust-project.json".into(),
                ".git".into(),
            ],
            command: vec!["rust-analyzer".into()],
            manual_guidance: "Install rust-analyzer with rustup or your Rust toolchain package manager; rust-src may also be required.".into(),
            disabled: false,
            install: vec![
                InstallRecipe {
                    prerequisite: "rustup".into(),
                    argv: vec![
                        "rustup".into(),
                        "component".into(),
                        "add".into(),
                        "rust-analyzer".into(),
                    ],
                },
                InstallRecipe {
                    prerequisite: "rustup".into(),
                    argv: vec![
                        "rustup".into(),
                        "component".into(),
                        "add".into(),
                        "rust-src".into(),
                    ],
                },
            ],
            uninstall: vec![InstallRecipe {
                prerequisite: "rustup".into(),
                argv: vec![
                    "rustup".into(),
                    "component".into(),
                    "remove".into(),
                    "rust-analyzer".into(),
                ],
            }],
        },
        Recipe {
            id: "typescript-language-server",
            language_id: "typescript",
            extensions: vec![
                "ts".into(),
                "tsx".into(),
                "js".into(),
                "jsx".into(),
                "mjs".into(),
                "cjs".into(),
            ],
            root_markers: vec![
                "tsconfig.json".into(),
                "jsconfig.json".into(),
                "package.json".into(),
                ".git".into(),
            ],
            command: vec!["typescript-language-server".into(), "--stdio".into()],
            manual_guidance: "Install Node/npm, then install typescript-language-server and typescript globally or provide a custom command.".into(),
            disabled: false,
            install: vec![InstallRecipe {
                prerequisite: "npm".into(),
                argv: vec![
                    "npm".into(),
                    "install".into(),
                    "-g".into(),
                    "typescript-language-server".into(),
                    "typescript".into(),
                ],
            }],
            uninstall: vec![InstallRecipe {
                prerequisite: "npm".into(),
                argv: vec![
                    "npm".into(),
                    "uninstall".into(),
                    "-g".into(),
                    "typescript-language-server".into(),
                    "typescript".into(),
                ],
            }],
        },
        Recipe {
            id: "pyright",
            language_id: "python",
            extensions: vec!["py".into(), "pyi".into()],
            root_markers: vec![
                "pyproject.toml".into(),
                "setup.py".into(),
                "requirements.txt".into(),
                ".git".into(),
            ],
            command: vec!["pyright-langserver".into(), "--stdio".into()],
            manual_guidance: "Install pyright via npm or pip; ensure the user script directory is on PATH.".into(),
            disabled: false,
            install: vec![
                InstallRecipe {
                    prerequisite: "npm".into(),
                    argv: vec![
                        "npm".into(),
                        "install".into(),
                        "-g".into(),
                        "pyright".into(),
                    ],
                },
                InstallRecipe {
                    prerequisite: "python".into(),
                    argv: vec![
                        "python".into(),
                        "-m".into(),
                        "pip".into(),
                        "install".into(),
                        "--user".into(),
                        "pyright".into(),
                    ],
                },
                InstallRecipe {
                    prerequisite: "py".into(),
                    argv: vec![
                        "py".into(),
                        "-m".into(),
                        "pip".into(),
                        "install".into(),
                        "--user".into(),
                        "pyright".into(),
                    ],
                },
            ],
            uninstall: vec![
                InstallRecipe {
                    prerequisite: "npm".into(),
                    argv: vec![
                        "npm".into(),
                        "uninstall".into(),
                        "-g".into(),
                        "pyright".into(),
                    ],
                },
                InstallRecipe {
                    prerequisite: "python".into(),
                    argv: vec![
                        "python".into(),
                        "-m".into(),
                        "pip".into(),
                        "uninstall".into(),
                        "pyright".into(),
                    ],
                },
                InstallRecipe {
                    prerequisite: "py".into(),
                    argv: vec![
                        "py".into(),
                        "-m".into(),
                        "pip".into(),
                        "uninstall".into(),
                        "pyright".into(),
                    ],
                },
            ],
        },
        Recipe {
            id: "gopls",
            language_id: "go",
            extensions: vec!["go".into()],
            root_markers: vec!["go.work".into(), "go.mod".into(), ".git".into()],
            command: vec!["gopls".into()],
            manual_guidance: "Install gopls with go install and ensure GOBIN or GOPATH/bin is on PATH.".into(),
            disabled: false,
            install: vec![InstallRecipe {
                prerequisite: "go".into(),
                argv: vec![
                    "go".into(),
                    "install".into(),
                    "golang.org/x/tools/gopls@latest".into(),
                ],
            }],
            uninstall: Vec::new(),
        },
    ]
}

fn find_root(file: &Path, cwd: &Path, markers: &[String]) -> PathBuf {
    let mut cur = file.parent().unwrap_or(cwd).to_path_buf();
    loop {
        if markers.iter().any(|m| cur.join(m).exists()) {
            return cur;
        }
        if !cur.pop() {
            return cwd.to_path_buf();
        }
    }
}

fn command_exists(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

enum CommandOutcome {
    Success {
        status: String,
        stdout: String,
        stderr: String,
    },
    Failure {
        status: String,
        stdout: String,
        stderr: String,
    },
}

async fn run_command_capture(argv: &[String]) -> CommandOutcome {
    let Some((program, args)) = argv.split_first() else {
        return CommandOutcome::Failure {
            status: "empty command".to_string(),
            stdout: String::new(),
            stderr: String::new(),
        };
    };
    match Command::new(program).args(args).output().await {
        Ok(output) => {
            let status = output.status.to_string();
            let stdout = tail(&String::from_utf8_lossy(&output.stdout), 2000);
            let stderr = tail(&String::from_utf8_lossy(&output.stderr), 2000);
            if output.status.success() {
                CommandOutcome::Success {
                    status,
                    stdout,
                    stderr,
                }
            } else {
                CommandOutcome::Failure {
                    status,
                    stdout,
                    stderr,
                }
            }
        }
        Err(e) => CommandOutcome::Failure {
            status: format!("failed to start: {e}"),
            stdout: String::new(),
            stderr: String::new(),
        },
    }
}

fn install_failure_message(
    recipe: &Recipe,
    argv: &[String],
    status: &str,
    stdout: &str,
    stderr: &str,
) -> String {
    let command = shell_join(argv);
    format!(
        "LSP install failed for `{}`.\ncommand: `{}`\nstatus: {}\nstdout tail:\n{}\nstderr tail:\n{}\nresearch prompt:\n{}",
        recipe.id,
        command,
        status,
        stdout,
        stderr,
        lsp_research_prompt(recipe, &command, status, stdout, stderr)
    )
}

fn lsp_research_prompt(
    recipe: &Recipe,
    command: &str,
    status: &str,
    stdout: &str,
    stderr: &str,
) -> String {
    format!(
        "I am using Cockpit and need to install the `{}` language server. The attempted command was `{}`. It exited with status `{}`. Stdout tail: `{}`. Stderr tail: `{}`. Give me current install steps for this OS and explain how to verify `{}` is on PATH.",
        recipe.id,
        command,
        status,
        one_line(stdout),
        one_line(stderr),
        recipe.command[0]
    )
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        s[s.len() - max..].to_string()
    }
}

fn shell_join(argv: &[String]) -> String {
    argv.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsp_types::{Diagnostic, DiagnosticSeverity, Range};

    #[test]
    fn registry_covers_required_floor() {
        let ids: HashSet<_> = registry().into_iter().map(|r| r.id).collect();
        for id in [
            "rust-analyzer",
            "typescript-language-server",
            "pyright",
            "gopls",
        ] {
            assert!(ids.contains(id), "missing {id}");
        }
    }

    #[test]
    fn server_config_overrides_recipe_fields() {
        let mut config = ExtendedConfig::default();
        config.lsp.servers.insert(
            "rust-analyzer".to_string(),
            crate::config::extended::LspServerConfig {
                enabled: false,
                command: Some(vec!["custom-ra".to_string(), "--stdio".to_string()]),
                install_command: Some(vec!["install-ra".to_string(), "now".to_string()]),
                root_markers: vec!["RA_ROOT".to_string()],
                extensions: vec!["rsx".to_string()],
                manual_guidance: Some("custom guidance".to_string()),
            },
        );
        let recipe = registry()
            .into_iter()
            .find(|r| r.id == "rust-analyzer")
            .unwrap()
            .with_config(&config);
        assert!(recipe.disabled);
        assert_eq!(recipe.command, vec!["custom-ra", "--stdio"]);
        assert_eq!(recipe.install[0].argv, vec!["install-ra", "now"]);
        assert_eq!(recipe.root_markers, vec!["RA_ROOT"]);
        assert_eq!(recipe.extensions, vec!["rsx"]);
        assert_eq!(recipe.manual_guidance, "custom guidance");
    }

    #[test]
    fn lsp_lifecycle_defaults_are_bounded() {
        let cfg = crate::config::extended::LspConfig::default();
        assert_eq!(cfg.idle_ttl_secs, 30 * 60);
        assert_eq!(cfg.max_cached_clients, 16);
    }

    #[test]
    fn lsp_eviction_selects_expired_then_oldest_over_cache_cap() {
        let now = Instant::now();
        let key = |id: &str| ClientKey {
            server_id: id.to_string(),
            root: PathBuf::from(format!("/{id}")),
        };
        let expired = key("expired");
        let old = key("old");
        let newer = key("newer");
        let newest = key("newest");
        let entries = vec![
            (expired.clone(), now - Duration::from_secs(31)),
            (old.clone(), now - Duration::from_secs(20)),
            (newer.clone(), now - Duration::from_secs(10)),
            (newest.clone(), now),
        ];

        let evicted = select_lsp_evictions(&entries, now, Duration::from_secs(30), 2);

        assert!(evicted.contains(&expired), "expired client is evicted");
        assert!(evicted.contains(&old), "oldest survivor enforces cap");
        assert!(!evicted.contains(&newer), "newer survivor remains cached");
        assert!(!evicted.contains(&newest), "newest survivor remains cached");
    }

    #[test]
    fn install_failure_message_contains_copyable_research_prompt() {
        let recipe = registry().into_iter().find(|r| r.id == "gopls").unwrap();
        let msg = install_failure_message(
            &recipe,
            &["go".to_string(), "install".to_string(), "bad".to_string()],
            "exit status: 1",
            "stdout line",
            "stderr line",
        );
        assert!(msg.contains("command: `go install bad`"));
        assert!(msg.contains("status: exit status: 1"));
        assert!(msg.contains("stdout tail:\nstdout line"));
        assert!(msg.contains("stderr tail:\nstderr line"));
        assert!(msg.contains("research prompt:"));
        assert!(msg.contains("Give me current install steps"));
        assert!(msg.contains("verify `gopls` is on PATH"));
    }

    #[tokio::test]
    async fn lsp_pending_remove_clears_entry_and_late_repeat_is_ignored() {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let (tx, _rx) = tokio::sync::oneshot::channel();
        pending.lock().await.insert(7, tx);

        assert!(remove_lsp_pending(&pending, 7).await);
        assert!(pending.lock().await.is_empty());
        assert!(!remove_lsp_pending(&pending, 7).await);
    }

    #[tokio::test]
    async fn notice_bus_mutex_poison_is_recovered() {
        let manager = LspManager::new();
        let poisoned = manager.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = poisoned.inner.notices.lock().unwrap();
            panic!("poison notices mutex");
        }));

        let (tx, mut rx) = broadcast::channel(4);
        let redaction = Arc::new(std::sync::RwLock::new(Arc::new(RedactionTable::empty())));
        manager.set_notice_bus(tx, redaction);
        manager.notice("poison recovered".to_string()).await;

        match rx.recv().await.unwrap() {
            envelope
                if matches!(
                    envelope.event,
                    crate::daemon::proto::Event::LspNotice { .. }
                ) =>
            {
                let crate::daemon::proto::Event::LspNotice { text } = envelope.event else {
                    unreachable!()
                };
                assert_eq!(text, "poison recovered");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn diagnostics_render_errors_only_with_caps_and_edited_first() {
        let tmp = tempfile::tempdir().unwrap();
        let edited = tmp.path().join("src/lib.rs");
        let other = tmp.path().join("src/other.rs");
        let diag = |msg: &str, severity| Diagnostic {
            range: Range::new(Position::new(0, 2), Position::new(0, 4)),
            severity,
            message: msg.to_string(),
            ..Diagnostic::default()
        };
        let mut map = HashMap::new();
        map.insert(
            edited.clone(),
            vec![
                diag("bad", Some(DiagnosticSeverity::ERROR)),
                diag("warn", Some(DiagnosticSeverity::WARNING)),
                diag("worse", Some(DiagnosticSeverity::ERROR)),
            ],
        );
        map.insert(other, vec![diag("other", Some(DiagnosticSeverity::ERROR))]);
        let rendered = render_diagnostics(&map, &edited, 5, 1);
        assert!(rendered.contains("LSP errors detected; fix them:"));
        assert!(rendered.contains(&format!("<diagnostics file=\"{}\">", edited.display())));
        assert!(rendered.contains("ERROR [1:3] bad"));
        assert!(!rendered.contains("warn"));
        assert!(rendered.contains("... and 1 more"));
    }
}
