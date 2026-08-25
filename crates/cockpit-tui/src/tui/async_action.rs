#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AsyncActionId(u64);

#[cfg(test)]
impl AsyncActionId {
    pub fn from_raw_for_test(id: u64) -> Self {
        Self(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AsyncActionKind {
    #[allow(dead_code)]
    DaemonRpc(&'static str),
    Blocking(&'static str),
    Refresh(&'static str),
    Internal(&'static str),
}

/// Classified auto-copy delivery. Never carries plaintext or OS error detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseCopyResult {
    Confirmed,
    Unverified,
    TooLarge,
    Failed,
    Empty,
}

/// Test-only seam: starts the production `mouse.copy` action path and
/// releases a typed result through the completed-action channel.
#[cfg(test)]
pub struct ControllableMouseCopyRunner {
    tx: tokio::sync::oneshot::Sender<MouseCopyResult>,
}

#[cfg(test)]
impl ControllableMouseCopyRunner {
    pub fn release(self, result: MouseCopyResult) {
        let _ = self.tx.send(result);
    }
}

#[derive(Debug)]
pub enum AsyncActionPayload {
    Unit,
    Text(String),
    Bool(bool),
    #[allow(dead_code)]
    DaemonResponse(Box<cockpit_core::daemon::proto::Response>),
    Sessions(Vec<cockpit_core::daemon::proto::SessionSummary>),
    SessionsMutation(crate::tui::sessions_pane::SessionsMutationCompletion),
    SessionMessages {
        session_id: uuid::Uuid,
        before_seq: Option<i64>,
        messages: Vec<cockpit_core::daemon::proto::SessionMessage>,
        has_more: bool,
    },
    ClientSubmissionReceipt {
        client_submission_id: uuid::Uuid,
        result: Result<cockpit_core::daemon::proto::ClientSubmissionReceiptStatus, String>,
    },
    SessionLiveStatus(std::collections::HashMap<uuid::Uuid, (bool, bool)>),
    ResourceSnapshot(cockpit_core::engine::resource_scheduler::ResourceSchedulerSnapshot),
    PromoteResource {
        status: cockpit_core::daemon::proto::ResourcePromoteStatus,
        message: String,
        snapshot: cockpit_core::engine::resource_scheduler::ResourceSchedulerSnapshot,
    },
    ForkCreated {
        parent_session_id: uuid::Uuid,
        socket: std::path::PathBuf,
        session_id: uuid::Uuid,
        short_id: String,
        fork_point_seq: Option<i64>,
        seed_composer: Option<String>,
    },
    NoteRecorded {
        text: String,
    },
    DelegationSteer(cockpit_core::daemon::proto::DelegationSteerResult),
    GuidanceEstimate(crate::tui::agent_runner::GuidanceEstimate),
    StartupGuidanceEstimate {
        cwd: std::path::PathBuf,
        active_model: Option<(String, String)>,
        estimate: crate::tui::agent_runner::GuidanceEstimate,
    },
    StartupDependencyProjection(cockpit_core::external_runtime::DependencyProjection),
    SessionSwitched(Box<crate::tui::agent_runner::SessionSwitchOutcome>),
    ForkSessionSwitched {
        outcome: Box<crate::tui::agent_runner::SessionSwitchOutcome>,
        fork_short_id: String,
        seed_composer: Option<String>,
    },
    SideSessionSwitched {
        outcome: Box<crate::tui::agent_runner::SessionSwitchOutcome>,
        side_short_id: String,
    },
    SideSessionReturned(Box<crate::tui::agent_runner::SessionSwitchOutcome>),
    ContainerAvailability(cockpit_core::container::ContainerAvailability),
    #[cfg(feature = "remote")]
    RemoteDisclosures {
        project_root: String,
        request_generation: u64,
        socket: Option<std::path::PathBuf>,
        launch_session_id: Option<uuid::Uuid>,
        session_id: Option<uuid::Uuid>,
        attachment_epoch: Option<u64>,
        org: Option<cockpit_core::daemon::proto::OrgSyncDisclosure>,
        connector: Option<cockpit_core::daemon::proto::ConnectorDisclosure>,
    },
    AssistantSessionResolved {
        session_id: uuid::Uuid,
        source_session_id: Option<uuid::Uuid>,
    },
    StatsRollup(crate::tui::stats_pane::StatsPaneFetchResult),
    SubagentHistory {
        session_id: uuid::Uuid,
        task_call_id: String,
        label: String,
        history: Vec<crate::tui::history::HistoryEntry>,
        has_more: bool,
        oldest_seq: Option<i64>,
    },
    HistoryPage {
        request_id: u64,
        session_id: uuid::Uuid,
        entries: Vec<crate::tui::history::HistoryEntry>,
        has_more: bool,
        oldest_seq: Option<i64>,
    },
    HistoryPageError {
        request_id: u64,
        session_id: uuid::Uuid,
        message: String,
    },
    SubagentHistoryPage {
        request_id: u64,
        session_id: uuid::Uuid,
        task_call_id: String,
        label: String,
        entries: Vec<crate::tui::history::HistoryEntry>,
        has_more: bool,
        oldest_seq: Option<i64>,
    },
    SubagentHistoryPageError {
        request_id: u64,
        session_id: uuid::Uuid,
        task_call_id: String,
        label: String,
        message: String,
    },
    ProviderUsage(Vec<cockpit_core::providers::usage::ProviderUsageSnapshot>),
    Skills(crate::tui::skills_pane::SkillsPaneFetchResult),
    InventoryBundle(cockpit_core::daemon::proto::Response),
    NotesRpc(crate::tui::notes_pane::NotesRpcResult),
    LeaksRpc(crate::tui::leaks_pane::LeaksRpcResult),
    PasteTokenCount {
        block_id: u64,
        tokens: usize,
    },
    ImagePathProbe {
        request_id: uuid::Uuid,
        request_generation: u64,
        terminal_generation: Option<u64>,
        original: String,
        source_draft_generation: u64,
        cursor: usize,
        png: Option<Vec<u8>>,
    },
    NativeImagePaste {
        request_id: uuid::Uuid,
        request_generation: u64,
        terminal_generation: Option<u64>,
        source_draft_generation: u64,
        cursor: usize,
        png: Option<Vec<u8>>,
    },
    PinState {
        session_id: uuid::Uuid,
        count: usize,
        pinned_seqs: Vec<i64>,
    },
    PinToggle {
        session_id: uuid::Uuid,
        seq: i64,
        now_pinned: bool,
        count: usize,
        pinned_seqs: Vec<i64>,
    },
    PinsReview {
        session_id: uuid::Uuid,
        pins: Vec<cockpit_core::daemon::proto::PinnedMessage>,
    },
    PinMessage {
        session_id: uuid::Uuid,
        seq: i64,
        inserted: bool,
        count: usize,
        pinned_seqs: Vec<i64>,
    },
    PinUnpin {
        session_id: uuid::Uuid,
        seq: i64,
        count: usize,
        pinned_seqs: Vec<i64>,
    },
    LocalCommand {
        label: String,
        raw_output: String,
        failed: bool,
        git_args: Option<String>,
    },
    DaemonProbe {
        cwd: std::path::PathBuf,
        status: cockpit_core::daemon::DaemonStatus,
    },
    OAuthCodexBegin(cockpit_core::auth::codex_oauth::DeviceLogin),
    /// Daemon-issued, display-safe OAuth instructions.  No PKCE state,
    /// device authorization id, callback code, or token record crosses this
    /// frontend boundary.
    OAuthProviderBegin {
        flow_id: String,
        authorize_url: String,
        user_code: Option<String>,
    },
    OAuthAcknowledged,
    OAuthCodexComplete {
        logged_in: bool,
    },
    OAuthGrokBegin {
        login: cockpit_core::auth::xai_oauth::ManualLogin,
    },
    OAuthGrokComplete {
        logged_in: bool,
    },
    /// `/copy … file <path>` published successfully. Metadata only — never
    /// the copied content. `durability_confirmed` is `false` only when the
    /// atomic rename itself succeeded but the follow-up parent-directory
    /// fsync failed: the file is genuinely on disk, but that fact is not
    /// yet guaranteed to survive a crash. The UI must show this
    /// differently from an ordinary success, and must never show it as a
    /// failure — the copy did not fail.
    CopyToFile {
        path: std::path::PathBuf,
        bytes_written: u64,
        durability_confirmed: bool,
    },
    DoctorSnapshot(String),
    FileSuggestions {
        query: String,
        suggestions: Vec<cockpit_core::tags::Suggestion>,
    },
    BtwTransition {
        created: Option<cockpit_core::daemon::proto::BtwForkInfo>,
        ended: bool,
        question: Option<String>,
        error: Option<String>,
    },
    GoalSettings(crate::tui::goal_settings_pane::GoalSettingsCompletion),
    Tools(crate::tui::tools_pane::ToolsCompletion),
    WorkspaceTrust(crate::tui::app::WorkspaceTrustCompletion),
    Sealed(crate::tui::app::slash::SealedCompletion),
    SettingsDaemon(crate::tui::settings::SettingsDaemonEffectCompletion),
    AgentRunnerAttached(Box<crate::tui::agent_runner::AgentRunner>),
    BtwRunnerAttached {
        session_id: uuid::Uuid,
        runner: Box<crate::tui::agent_runner::AgentRunner>,
    },
    MouseCopy(MouseCopyResult),
}

#[derive(Debug)]
pub struct AsyncActionResult {
    pub id: AsyncActionId,
    pub kind: AsyncActionKind,
    pub payload: Result<AsyncActionPayload, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncActionKey(Arc<str>);

impl AsyncActionKey {
    pub fn new(value: impl Into<Arc<str>>) -> Self {
        Self(value.into())
    }
}

impl Hash for AsyncActionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncActionPolicy {
    AllowConcurrent,
    Dedupe(AsyncActionKey),
    Replace(AsyncActionKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncActionStart {
    Started(AsyncActionId),
    Existing(AsyncActionId),
}

impl AsyncActionStart {
    pub fn id(self) -> AsyncActionId {
        match self {
            AsyncActionStart::Started(id) | AsyncActionStart::Existing(id) => id,
        }
    }
}

#[derive(Debug)]
struct PendingAction {
    kind: AsyncActionKind,
    started_at: Instant,
    generation: u64,
    view_generation: u64,
    key: Option<AsyncActionKey>,
    handle: JoinHandle<()>,
    shutdown: Option<Arc<AsyncActionCancellation>>,
}

#[derive(Debug, Default)]
pub struct AsyncActionCancellation {
    cancelled: std::sync::atomic::AtomicBool,
    notify: Notify,
    export_temp: std::sync::Mutex<Option<std::path::PathBuf>>,
}

enum ExportReaperMessage {
    Reap(std::path::PathBuf),
    DrainAndStop(std::sync::mpsc::Sender<()>),
}

struct ExportReaper {
    tx: std::sync::Mutex<Option<std::sync::mpsc::Sender<ExportReaperMessage>>>,
    handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn export_temp_reaper() -> &'static ExportReaper {
    static REAPER: std::sync::OnceLock<ExportReaper> = std::sync::OnceLock::new();
    REAPER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel::<ExportReaperMessage>();
        let handle = std::thread::Builder::new()
            .name("cockpit-export-temp-reaper".to_string())
            .spawn(move || {
                let mut pending = std::collections::VecDeque::new();
                let mut stop = None;
                loop {
                    while let Ok(message) = rx.try_recv() {
                        match message {
                            ExportReaperMessage::Reap(path) => pending.push_back((path, 0u8)),
                            ExportReaperMessage::DrainAndStop(done) => stop = Some(done),
                        }
                    }
                    if let Some((path, attempts)) = pending.pop_front() {
                        match secure_unlink_owned_temp(&path) {
                            Ok(()) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => {
                                if attempts < 3 {
                                    eprintln!("cockpit: export recovery retry {} retained {}: {error}", attempts + 1, path.display());
                                    pending.push_back((path, attempts + 1));
                                    std::thread::sleep(Duration::from_millis(10));
                                } else {
                                    let record = persist_export_recovery_record(&path);
                                    eprintln!("cockpit: CleanupDeferred — export recovery for {} after {error}; recovery_record={}", path.display(), record.as_ref().map_or_else(|e| format!("failed:{e}"), |p| p.display().to_string()));
                                }
                            }
                        }
                        continue;
                    }
                    if let Some(done) = stop.take() {
                        let _ = done.send(());
                        break;
                    }
                    match rx.recv() {
                        Ok(ExportReaperMessage::Reap(path)) => pending.push_back((path, 0u8)),
                        Ok(ExportReaperMessage::DrainAndStop(done)) => stop = Some(done),
                        Err(_) => break,
                    }
                }
            });
        ExportReaper {
            tx: std::sync::Mutex::new(handle.as_ref().ok().map(|_| tx)),
            handle: std::sync::Mutex::new(handle.ok()),
        }
    })
}

fn persist_export_recovery_record(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let root = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing export root"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::other("invalid export temp name"))?;
    let owned = name
        .strip_suffix(".partial")
        .and_then(|stem| stem.rsplit_once('.'))
        .is_some_and(|(target, id)| {
            target.starts_with('.') && target.len() > 1 && uuid::Uuid::parse_str(id).is_ok()
        });
    if !owned {
        return Err(std::io::Error::other("refusing non-owned export temp"));
    }
    let dir = root.join(".cockpit-export-recovery");
    #[cfg(not(windows))]
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let record = dir.join(format!("{}.record", uuid::Uuid::now_v7()));
    #[cfg(windows)]
    let directory = crate::clipboard::recovery::windows::DirHandle::open_or_create(&dir)?;
    #[cfg(windows)]
    let mut file = directory.create_file_exclusive(
        record
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| std::io::Error::other("invalid recovery record name"))?,
    )?;
    #[cfg(not(windows))]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&record)?;
    use std::io::Write as _;
    file.write_all(format!("v1\n{name}\n").as_bytes())?;
    file.sync_all()?;
    #[cfg(windows)]
    directory.sync()?;
    #[cfg(not(windows))]
    std::fs::File::open(&dir)?.sync_all()?;
    Ok(record)
}

fn enqueue_export_temp_reap(path: std::path::PathBuf) {
    let tx = export_temp_reaper()
        .tx
        .lock()
        .expect("export reaper lock poisoned")
        .as_ref()
        .cloned();
    enqueue_export_temp_reap_with(path, tx);
}

fn enqueue_export_temp_reap_with(
    path: std::path::PathBuf,
    tx: Option<std::sync::mpsc::Sender<ExportReaperMessage>>,
) {
    let sent = tx.is_some_and(|tx| tx.send(ExportReaperMessage::Reap(path.clone())).is_ok());
    if !sent {
        synchronous_export_cleanup_fallback(&path);
    }
}

fn synchronous_export_cleanup_fallback(path: &std::path::Path) {
    if let Err(error) = secure_unlink_owned_temp(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        let record = persist_export_recovery_record(path);
        eprintln!(
            "cockpit: CleanupDeferred fallback for {}: {error}; record={:?}",
            path.display(),
            record
        );
    }
}

#[cfg(unix)]
pub(crate) fn secure_unlink_owned_temp(path: &std::path::Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    let parent_path = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?;
    let name = CString::new(
        path.file_name()
            .ok_or_else(|| std::io::Error::other("missing name"))?
            .as_bytes(),
    )?;
    let parent_name = CString::new(parent_path.as_os_str().as_bytes())?;
    let parent_fd = unsafe {
        libc::open(
            parent_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if parent_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let parent = unsafe { std::fs::File::from_raw_fd(parent_fd) };
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "export temp ownership check failed",
        ));
    }
    let rc = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    parent.sync_all()
}

#[cfg(windows)]
pub(crate) fn secure_unlink_owned_temp(path: &std::path::Path) -> std::io::Result<()> {
    use crate::clipboard::recovery::windows::{CheckedEntry, DirHandle};
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing export parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::other("invalid export temp name"))?;
    let directory = DirHandle::open_or_create(parent)?;
    match directory.open_file_verified(name)? {
        CheckedEntry::Missing => Err(std::io::ErrorKind::NotFound.into()),
        CheckedEntry::Unsafe => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "export temp failed held-handle security verification",
        )),
        CheckedEntry::Ok(file) => directory.remove_verified(name, file).map(|_| ()),
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn secure_unlink_owned_temp(_path: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure export cleanup is unavailable on this platform",
    ))
}

pub(crate) const fn secure_export_cleanup_supported() -> bool {
    cfg!(any(unix, windows))
}

pub(crate) fn drain_export_temp_reaper() {
    let reaper = export_temp_reaper();
    let tx = reaper
        .tx
        .lock()
        .expect("export reaper lock poisoned")
        .take();
    if let Some(tx) = tx {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let _ = tx.send(ExportReaperMessage::DrainAndStop(done_tx));
        drop(tx);
        let _ = done_rx.recv();
    }
    if let Some(handle) = reaper
        .handle
        .lock()
        .expect("export reaper lock poisoned")
        .take()
    {
        let _ = handle.join();
    }
}

pub(crate) struct ExportTempReaperGuard;

impl ExportTempReaperGuard {
    pub(crate) fn new() -> Self {
        let _ = export_temp_reaper();
        Self
    }
}

impl Drop for ExportTempReaperGuard {
    fn drop(&mut self) {
        drain_export_temp_reaper();
    }
}

impl Drop for AsyncActionCancellation {
    fn drop(&mut self) {
        if let Some(path) = self
            .export_temp
            .get_mut()
            .expect("export temp owner poisoned")
            .take()
        {
            enqueue_export_temp_reap(path);
        }
    }
}

impl AsyncActionCancellation {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub fn own_export_temp(&self, path: std::path::PathBuf) {
        *self.export_temp.lock().expect("export temp owner poisoned") = Some(path);
    }

    pub fn release_export_temp(&self) {
        self.export_temp
            .lock()
            .expect("export temp owner poisoned")
            .take();
    }

    async fn cleanup_export_temp(&self) -> std::io::Result<()> {
        let path = self
            .export_temp
            .lock()
            .expect("export temp owner poisoned")
            .clone();
        let Some(path) = path else { return Ok(()) };
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {
                self.release_export_temp();
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.release_export_temp();
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn schedule_export_temp_cleanup_retry(&self) -> bool {
        let path = self
            .export_temp
            .lock()
            .expect("export temp owner poisoned")
            .take();
        let Some(path) = path else { return false };
        enqueue_export_temp_reap(path);
        true
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct AsyncActionShutdownReport {
    pub export_reaped: usize,
    pub export_reap_timed_out: usize,
    pub export_join_failed: usize,
    pub export_cleanup_failed: usize,
    pub export_cleanup_timed_out: usize,
    pub export_cleanup_retry_scheduled: usize,
}

#[derive(Debug)]
struct CompletedAction {
    id: AsyncActionId,
    generation: u64,
    kind: AsyncActionKind,
    payload: Result<AsyncActionPayload, String>,
}

#[derive(Debug)]
pub struct AsyncActionRunner {
    next_id: AtomicU64,
    next_generation: AtomicU64,
    view_generation: u64,
    pending: HashMap<AsyncActionId, PendingAction>,
    keyed: HashMap<AsyncActionKey, AsyncActionId>,
    serialized: HashMap<AsyncActionKey, tokio::sync::oneshot::Receiver<()>>,
    cancelled: Vec<AsyncActionResult>,
    tx: mpsc::UnboundedSender<CompletedAction>,
    rx: mpsc::UnboundedReceiver<CompletedAction>,
    notify: Arc<Notify>,
}

impl Default for AsyncActionRunner {
    fn default() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            next_id: AtomicU64::new(1),
            next_generation: AtomicU64::new(1),
            view_generation: 1,
            pending: HashMap::new(),
            keyed: HashMap::new(),
            serialized: HashMap::new(),
            cancelled: Vec::new(),
            tx,
            rx,
            notify: Arc::new(Notify::new()),
        }
    }
}

impl AsyncActionRunner {
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Advance the UI ownership fence and cancel blocking work owned by the
    /// previous view. Exports and non-blocking work may keep running; their
    /// completions are discarded by `drain_completed`, which also releases the
    /// corresponding pending/keyed slots so later deduped requests are not
    /// permanently blocked.
    pub fn advance_view_generation(&mut self) {
        self.view_generation = self.view_generation.wrapping_add(1).max(1);
        let stale = self
            .pending
            .iter()
            .filter_map(|(id, pending)| {
                matches!(&pending.kind, AsyncActionKind::Blocking(_))
                    .then_some(*id)
                    .filter(|_| {
                        !matches!(
                            &pending.kind,
                            AsyncActionKind::Blocking("export.transcript" | "export.debug")
                        )
                    })
            })
            .collect::<Vec<_>>();
        for id in stale {
            self.abort_id(id);
        }
    }

    pub fn expire_blocking(&mut self, now: Instant, timeout: Duration) -> Vec<AsyncActionResult> {
        let expired = self
            .pending
            .iter()
            .filter_map(|(id, pending)| {
                (matches!(&pending.kind, AsyncActionKind::Blocking(_))
                    && now.saturating_duration_since(pending.started_at) >= timeout)
                    .then_some((*id, pending.kind.clone()))
            })
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|(id, kind)| {
                self.abort_id_inner(id, false).then_some(AsyncActionResult {
                    id,
                    kind,
                    payload: Err("operation timed out".to_string()),
                })
            })
            .collect()
    }

    #[cfg(test)]
    pub fn pending_kinds(&self) -> Vec<AsyncActionKind> {
        self.pending
            .values()
            .map(|pending| pending.kind.clone())
            .collect()
    }

    #[cfg(test)]
    pub fn pending_ids(&self) -> Vec<AsyncActionId> {
        let mut ids: Vec<_> = self.pending.keys().copied().collect();
        ids.sort_by_key(|id| id.0);
        ids
    }

    pub fn notifier(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    pub fn is_pending(&self, id: AsyncActionId) -> bool {
        self.pending.contains_key(&id)
    }

    pub fn has_pending_kind(&self, kind: &AsyncActionKind) -> bool {
        self.pending.values().any(|pending| &pending.kind == kind)
    }

    pub fn pending_kind_count(&self, kind: &AsyncActionKind) -> usize {
        self.pending
            .values()
            .filter(|pending| &pending.kind == kind)
            .count()
    }

    pub fn has_pending_key(&self, key: &AsyncActionKey) -> bool {
        self.keyed
            .get(key)
            .is_some_and(|id| self.pending.contains_key(id))
    }

    pub fn has_pending_other_than(&self, kind: &AsyncActionKind) -> bool {
        self.pending.values().any(|pending| &pending.kind != kind)
    }

    pub fn has_pending_not_in(&self, kinds: &[AsyncActionKind]) -> bool {
        self.pending
            .values()
            .any(|pending| !kinds.iter().any(|kind| kind == &pending.kind))
    }

    pub fn pending_kind_elapsed(&self, kind: &AsyncActionKind, now: Instant) -> Option<Duration> {
        self.pending
            .values()
            .filter(|pending| &pending.kind == kind)
            .map(|pending| now.saturating_duration_since(pending.started_at))
            .max()
    }

    pub fn pending_any_kind_elapsed(
        &self,
        kinds: &[AsyncActionKind],
        now: Instant,
    ) -> Option<Duration> {
        self.pending
            .values()
            .filter(|pending| kinds.iter().any(|kind| kind == &pending.kind))
            .map(|pending| now.saturating_duration_since(pending.started_at))
            .max()
    }

    #[cfg(test)]
    pub fn set_pending_kind_started_at(&mut self, kind: &AsyncActionKind, started_at: Instant) {
        for pending in self.pending.values_mut() {
            if &pending.kind == kind {
                pending.started_at = started_at;
            }
        }
    }

    #[cfg(test)]
    pub fn inject_completed_for_test(
        &mut self,
        id: AsyncActionId,
        kind: AsyncActionKind,
        payload: Result<AsyncActionPayload, String>,
    ) {
        let _ = self.tx.send(CompletedAction {
            id,
            generation: 0,
            kind,
            payload,
        });
    }

    pub fn start<F>(
        &mut self,
        kind: AsyncActionKind,
        policy: AsyncActionPolicy,
        future: F,
    ) -> AsyncActionStart
    where
        F: Future<Output = Result<AsyncActionPayload, String>> + Send + 'static,
    {
        self.start_with(kind, policy, None, |tx, notify, id, generation, kind| {
            tokio::spawn(async move {
                let payload = future.await;
                let _ = tx.send(CompletedAction {
                    id,
                    generation,
                    kind,
                    payload,
                });
                notify.notify_one();
            })
        })
    }

    /// Starts an export whose daemon RPC can be cancelled promptly at shutdown
    /// while its owned temporary-file cleanup is given a bounded chance to run.
    pub fn start_export<F, Fut>(
        &mut self,
        kind: AsyncActionKind,
        policy: AsyncActionPolicy,
        work: F,
    ) -> AsyncActionStart
    where
        F: FnOnce(Arc<AsyncActionCancellation>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<AsyncActionPayload, String>> + Send + 'static,
    {
        let cancellation = Arc::new(AsyncActionCancellation::default());
        let worker_cancellation = Arc::clone(&cancellation);
        self.start_with(
            kind,
            policy,
            Some(cancellation),
            move |tx, notify, id, generation, kind| {
                tokio::spawn(async move {
                    let payload = work(worker_cancellation).await;
                    let _ = tx.send(CompletedAction {
                        id,
                        generation,
                        kind,
                        payload,
                    });
                    notify.notify_one();
                })
            },
        )
    }

    /// Start a distinct action in the key's FIFO ordering domain. Unlike
    /// dedupe/replace, every invocation reaches one terminal result, but its
    /// side effect cannot overtake an earlier invocation with the same key.
    pub fn start_serialized<F>(
        &mut self,
        kind: AsyncActionKind,
        key: AsyncActionKey,
        future: F,
    ) -> AsyncActionStart
    where
        F: Future<Output = Result<AsyncActionPayload, String>> + Send + 'static,
    {
        // Assign the predecessor synchronously, before either task is
        // spawned/polled. This is enqueue order, not scheduler/mutex order.
        let predecessor = self.serialized.remove(&key);
        let (release_next, tail) = tokio::sync::oneshot::channel();
        self.serialized.insert(key, tail);
        self.start_with(
            kind,
            AsyncActionPolicy::AllowConcurrent,
            None,
            move |tx, notify, id, generation, kind| {
                tokio::spawn(async move {
                    if let Some(predecessor) = predecessor {
                        let _ = predecessor.await;
                    }
                    let payload = future.await;
                    let _ = tx.send(CompletedAction {
                        id,
                        generation,
                        kind,
                        payload,
                    });
                    notify.notify_one();
                    let _ = release_next.send(());
                })
            },
        )
    }

    pub fn start_blocking<F>(
        &mut self,
        kind: AsyncActionKind,
        policy: AsyncActionPolicy,
        work: F,
    ) -> AsyncActionStart
    where
        F: FnOnce() -> Result<AsyncActionPayload, String> + Send + 'static,
    {
        self.start_with(kind, policy, None, |tx, notify, id, generation, kind| {
            tokio::task::spawn_blocking(move || {
                let payload = work();
                let _ = tx.send(CompletedAction {
                    id,
                    generation,
                    kind,
                    payload,
                });
                notify.notify_one();
            })
        })
    }

    fn start_with<F>(
        &mut self,
        kind: AsyncActionKind,
        policy: AsyncActionPolicy,
        shutdown: Option<Arc<AsyncActionCancellation>>,
        spawn: F,
    ) -> AsyncActionStart
    where
        F: FnOnce(
            mpsc::UnboundedSender<CompletedAction>,
            Arc<Notify>,
            AsyncActionId,
            u64,
            AsyncActionKind,
        ) -> JoinHandle<()>,
    {
        let key = match policy {
            AsyncActionPolicy::AllowConcurrent => None,
            AsyncActionPolicy::Dedupe(key) => {
                if let Some(id) = self.keyed.get(&key).copied()
                    && self.pending.contains_key(&id)
                {
                    return AsyncActionStart::Existing(id);
                }
                Some(key)
            }
            AsyncActionPolicy::Replace(key) => {
                if let Some(id) = self.keyed.get(&key).copied() {
                    self.abort_id(id);
                }
                Some(key)
            }
        };

        let id = AsyncActionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let handle = spawn(
            self.tx.clone(),
            Arc::clone(&self.notify),
            id,
            generation,
            kind.clone(),
        );
        if let Some(key) = &key {
            self.keyed.insert(key.clone(), id);
        }
        self.pending.insert(
            id,
            PendingAction {
                kind,
                started_at: Instant::now(),
                generation,
                view_generation: self.view_generation,
                key,
                handle,
                shutdown,
            },
        );
        AsyncActionStart::Started(id)
    }

    pub fn drain_completed(&mut self) -> Vec<AsyncActionResult> {
        let mut results = Vec::new();
        while let Ok(completed) = self.rx.try_recv() {
            let Some(pending) = self.pending.get(&completed.id) else {
                continue;
            };
            if pending.generation != completed.generation || pending.kind != completed.kind {
                continue;
            }
            let stale_view = pending.view_generation != self.view_generation;
            let pending = self
                .pending
                .remove(&completed.id)
                .expect("validated pending action remains registered");
            if let Some(key) = pending.key
                && self.keyed.get(&key) == Some(&completed.id)
            {
                self.keyed.remove(&key);
            }
            // Stale-view completions (exports left running across
            // `advance_view_generation`, non-blocking work, etc.) must still
            // release pending/keyed ownership so a later same-key action is
            // not permanently stuck behind a discarded result.
            if stale_view {
                continue;
            }
            results.push(AsyncActionResult {
                id: completed.id,
                kind: completed.kind,
                payload: completed.payload,
            });
        }
        results
    }

    pub fn drain_cancelled(&mut self) -> Vec<AsyncActionResult> {
        std::mem::take(&mut self.cancelled)
    }

    pub fn shutdown(&mut self) {
        for (id, pending) in self.pending.drain() {
            if let Some(shutdown) = &pending.shutdown {
                shutdown.cancel();
                shutdown.schedule_export_temp_cleanup_retry();
            }
            pending.handle.abort();
            self.cancelled.push(AsyncActionResult {
                id,
                kind: pending.kind,
                payload: Err("operation cancelled by shutdown".to_string()),
            });
        }
        self.keyed.clear();
        self.serialized.clear();
        while self.rx.try_recv().is_ok() {}
    }

    /// Event-loop shutdown path. Export actions are allowed to finish their
    /// owned atomic publish/temporary-file cleanup before the runtime exits;
    /// unrelated work is cancelled immediately.
    pub async fn shutdown_and_reap(&mut self) -> AsyncActionShutdownReport {
        self.shutdown_and_reap_with_timeout(Duration::from_secs(2))
            .await
    }

    async fn shutdown_and_reap_with_timeout(
        &mut self,
        export_reap_timeout: Duration,
    ) -> AsyncActionShutdownReport {
        self.shutdown_and_reap_with_timeouts(export_reap_timeout, export_reap_timeout)
            .await
    }

    async fn shutdown_and_reap_with_timeouts(
        &mut self,
        export_reap_timeout: Duration,
        cleanup_timeout: Duration,
    ) -> AsyncActionShutdownReport {
        let mut export_handles = Vec::new();
        for (id, pending) in self.pending.drain() {
            let is_export = matches!(
                &pending.kind,
                AsyncActionKind::Blocking("export.transcript" | "export.debug")
            );
            if is_export {
                if let Some(shutdown) = &pending.shutdown {
                    shutdown.cancel();
                }
                export_handles.push((pending.handle, pending.shutdown));
            } else {
                pending.handle.abort();
            }
            self.cancelled.push(AsyncActionResult {
                id,
                kind: pending.kind,
                payload: Err("operation cancelled by shutdown".to_string()),
            });
        }
        self.keyed.clear();
        self.serialized.clear();
        let mut report = AsyncActionShutdownReport::default();
        for (mut handle, cleanup_owner) in export_handles {
            match tokio::time::timeout(export_reap_timeout, &mut handle).await {
                Ok(Ok(())) => report.export_reaped += 1,
                Ok(Err(_)) => report.export_join_failed += 1,
                Err(_) => {
                    report.export_reap_timed_out += 1;
                    handle.abort();
                    let _ = handle.await;
                }
            }
            if let Some(cleanup_owner) = cleanup_owner {
                match tokio::time::timeout(cleanup_timeout, cleanup_owner.cleanup_export_temp())
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        report.export_cleanup_failed += 1;
                        if cleanup_owner.schedule_export_temp_cleanup_retry() {
                            report.export_cleanup_retry_scheduled += 1;
                        }
                    }
                    Err(_) => {
                        report.export_cleanup_timed_out += 1;
                        if cleanup_owner.schedule_export_temp_cleanup_retry() {
                            report.export_cleanup_retry_scheduled += 1;
                        }
                    }
                }
            }
        }
        while self.rx.try_recv().is_ok() {}
        report
    }

    pub fn abort_key(&mut self, key: &AsyncActionKey) -> bool {
        let Some(id) = self.keyed.get(key).copied() else {
            return false;
        };
        self.abort_id(id)
    }

    pub fn abort_id(&mut self, id: AsyncActionId) -> bool {
        self.abort_id_inner(id, true)
    }

    #[cfg(test)]
    pub fn start_controllable_mouse_copy(
        &mut self,
    ) -> (AsyncActionStart, ControllableMouseCopyRunner) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let start = self.start(
            AsyncActionKind::Blocking("mouse.copy"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("mouse.copy")),
            async move {
                match rx.await {
                    Ok(result) => Ok(AsyncActionPayload::MouseCopy(result)),
                    Err(_) => Err("mouse copy dropped".to_string()),
                }
            },
        );
        (start, ControllableMouseCopyRunner { tx })
    }

    fn abort_id_inner(&mut self, id: AsyncActionId, record_cancelled: bool) -> bool {
        let Some(pending) = self.pending.remove(&id) else {
            return false;
        };
        if let Some(key) = pending.key
            && self.keyed.get(&key) == Some(&id)
        {
            self.keyed.remove(&key);
        }
        if let Some(shutdown) = &pending.shutdown {
            shutdown.cancel();
        }
        pending.handle.abort();
        if record_cancelled {
            self.cancelled.push(AsyncActionResult {
                id,
                kind: pending.kind,
                payload: Err("operation cancelled".to_string()),
            });
        }
        true
    }
}

impl Drop for AsyncActionRunner {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;
    use tokio::time::{Duration, sleep};

    async fn wait_for_results(runner: &mut AsyncActionRunner) -> Vec<AsyncActionResult> {
        for _ in 0..20 {
            let results = runner.drain_completed();
            if !results.is_empty() {
                return results;
            }
            sleep(Duration::from_millis(10)).await;
        }
        Vec::new()
    }

    #[tokio::test]
    async fn owned_async_actions_reject_stale_view_generation() {
        let mut runner = AsyncActionRunner::default();
        let (release, barrier) = oneshot::channel::<()>();
        runner.start(
            AsyncActionKind::Blocking("doctor.snapshot"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = barrier.await;
                Ok(AsyncActionPayload::Text("stale".to_string()))
            },
        );

        runner.advance_view_generation();
        let _ = release.send(());
        tokio::task::yield_now().await;

        assert!(runner.drain_completed().is_empty());
        assert_eq!(runner.pending_count(), 0);
    }

    #[tokio::test]
    async fn stale_view_generation_export_releases_pending_and_dedupe_key() {
        let mut runner = AsyncActionRunner::default();
        let key = AsyncActionKey::new("export");
        let (release, barrier) = oneshot::channel::<()>();
        let first = runner.start(
            AsyncActionKind::Blocking("export.transcript"),
            AsyncActionPolicy::Dedupe(key.clone()),
            async move {
                let _ = barrier.await;
                Ok(AsyncActionPayload::Text("stale export".to_string()))
            },
        );
        assert!(matches!(first, AsyncActionStart::Started(_)));

        // Exports are intentionally left running across view-generation advance.
        runner.advance_view_generation();
        assert_eq!(runner.pending_count(), 1);

        let _ = release.send(());
        for _ in 0..20 {
            if runner.drain_completed().is_empty() && runner.pending_count() == 0 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            runner.pending_count(),
            0,
            "stale-view export completion must release pending ownership"
        );

        let second = runner.start(
            AsyncActionKind::Blocking("export.transcript"),
            AsyncActionPolicy::Dedupe(key),
            async { Ok(AsyncActionPayload::Text("retry".to_string())) },
        );
        assert!(
            matches!(second, AsyncActionStart::Started(_)),
            "released dedupe key must allow a subsequent same-key action"
        );
        assert_eq!(wait_for_results(&mut runner).await.len(), 1);
    }

    #[tokio::test]
    async fn queue_edits_apply_in_user_order() {
        let mut runner = AsyncActionRunner::default();
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (release_first, first_barrier) = oneshot::channel::<()>();
        let first_order = Arc::clone(&order);
        runner.start_serialized(
            AsyncActionKind::Blocking("queue.edit"),
            AsyncActionKey::new("queue.edit"),
            async move {
                first_barrier.await.unwrap();
                first_order.lock().unwrap().push(1);
                Ok(AsyncActionPayload::Unit)
            },
        );
        let second_order = Arc::clone(&order);
        runner.start_serialized(
            AsyncActionKind::Blocking("queue.edit"),
            AsyncActionKey::new("queue.edit"),
            async move {
                second_order.lock().unwrap().push(2);
                Ok(AsyncActionPayload::Unit)
            },
        );

        tokio::task::yield_now().await;
        assert!(order.lock().unwrap().is_empty());
        release_first.send(()).unwrap();
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(*order.lock().unwrap(), [1, 2]);
    }

    #[tokio::test]
    async fn owned_async_action_timeout_is_terminal_and_late_completion_is_rejected() {
        let mut runner = AsyncActionRunner::default();
        let (release, barrier) = oneshot::channel::<()>();
        runner.start(
            AsyncActionKind::Blocking("doctor.snapshot"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = barrier.await;
                Ok(AsyncActionPayload::Text("late".to_string()))
            },
        );
        runner.set_pending_kind_started_at(
            &AsyncActionKind::Blocking("doctor.snapshot"),
            Instant::now() - Duration::from_secs(31),
        );

        let expired = runner.expire_blocking(Instant::now(), Duration::from_secs(30));
        assert_eq!(expired.len(), 1);
        assert!(matches!(&expired[0].payload, Err(error) if error.contains("timed out")));
        assert!(runner.drain_cancelled().is_empty());
        let _ = release.send(());
        tokio::task::yield_now().await;
        assert!(runner.drain_completed().is_empty());
    }

    #[tokio::test]
    async fn owned_async_action_cancellation_is_terminal_once() {
        let mut runner = AsyncActionRunner::default();
        let (_release, barrier) = oneshot::channel::<()>();
        let action = runner.start(
            AsyncActionKind::Blocking("doctor.snapshot"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = barrier.await;
                Ok(AsyncActionPayload::Unit)
            },
        );
        assert!(runner.abort_id(action.id()));
        assert!(!runner.abort_id(action.id()));
        let cancelled = runner.drain_cancelled();
        assert_eq!(cancelled.len(), 1);
        assert!(matches!(&cancelled[0].payload, Err(error) if error.contains("cancelled")));
        assert!(runner.drain_cancelled().is_empty());
    }

    #[tokio::test]
    async fn owned_async_actions_reject_late_and_double_completion() {
        let mut runner = AsyncActionRunner::default();
        let (release, barrier) = oneshot::channel::<()>();
        let action = runner.start(
            AsyncActionKind::Blocking("doctor.snapshot"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = barrier.await;
                Ok(AsyncActionPayload::Text("current".to_string()))
            },
        );
        runner.inject_completed_for_test(
            action.id(),
            AsyncActionKind::Blocking("doctor.snapshot"),
            Ok(AsyncActionPayload::Text("stale".to_string())),
        );
        assert!(runner.drain_completed().is_empty());
        assert!(runner.is_pending(action.id()));

        release.send(()).unwrap();
        runner.notifier().notified().await;
        assert_eq!(runner.drain_completed().len(), 1);
        runner.inject_completed_for_test(
            action.id(),
            AsyncActionKind::Blocking("doctor.snapshot"),
            Ok(AsyncActionPayload::Text("duplicate".to_string())),
        );
        assert!(runner.drain_completed().is_empty());
    }

    #[tokio::test]
    async fn replacement_records_exactly_one_cancelled_terminal() {
        let mut runner = AsyncActionRunner::default();
        let key = AsyncActionKey::new("autocomplete.files");
        let (_release, barrier) = oneshot::channel::<()>();
        runner.start(
            AsyncActionKind::Blocking("autocomplete.files"),
            AsyncActionPolicy::Replace(key.clone()),
            async move {
                let _ = barrier.await;
                Ok(AsyncActionPayload::Unit)
            },
        );
        runner.start(
            AsyncActionKind::Blocking("autocomplete.files"),
            AsyncActionPolicy::Replace(key),
            async { Ok(AsyncActionPayload::Unit) },
        );
        assert_eq!(runner.drain_cancelled().len(), 1);
        assert!(runner.drain_cancelled().is_empty());
    }

    #[tokio::test]
    async fn shutdown_waits_for_export_owned_cleanup_barrier() {
        let mut runner = AsyncActionRunner::default();
        let cleaned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cleaned_by_action = Arc::clone(&cleaned);
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        runner.start_export(
            AsyncActionKind::Blocking("export.transcript"),
            AsyncActionPolicy::AllowConcurrent,
            move |_shutdown| async move {
                entered_tx.send(()).unwrap();
                let _ = release_rx.await;
                cleaned_by_action.store(true, Ordering::SeqCst);
                Ok(AsyncActionPayload::Unit)
            },
        );
        let shutdown = tokio::spawn(async move {
            let report = runner.shutdown_and_reap().await;
            (runner, report)
        });
        entered_rx.await.unwrap();
        assert!(!cleaned.load(Ordering::SeqCst));
        release_tx.send(()).unwrap();
        let (mut runner, report) = shutdown.await.unwrap();
        assert!(cleaned.load(Ordering::SeqCst));
        assert_eq!(report.export_reaped, 1);
        assert_eq!(runner.drain_cancelled().len(), 1);
    }

    #[tokio::test]
    async fn shutdown_cancels_export_rpc_promptly() {
        let mut runner = AsyncActionRunner::default();
        let (rpc_started_tx, rpc_started_rx) = oneshot::channel();
        let (rpc_dropped_tx, rpc_dropped_rx) = oneshot::channel();
        runner.start_export(
            AsyncActionKind::Blocking("export.transcript"),
            AsyncActionPolicy::AllowConcurrent,
            move |shutdown| async move {
                rpc_started_tx.send(()).unwrap();
                tokio::select! {
                    () = shutdown.cancelled() => {
                        rpc_dropped_tx.send(()).unwrap();
                        Err("cancelled before daemon replied".to_string())
                    }
                    () = std::future::pending() => unreachable!(),
                }
            },
        );
        rpc_started_rx.await.unwrap();

        let report = runner.shutdown_and_reap().await;

        rpc_dropped_rx.await.unwrap();
        assert_eq!(report.export_reap_timed_out, 0);
        assert_eq!(report.export_reaped, 1);
        assert_eq!(runner.drain_cancelled().len(), 1);
    }

    #[tokio::test]
    async fn shutdown_reports_and_aborts_export_that_exceeds_cleanup_bound() {
        let mut runner = AsyncActionRunner::default();
        runner.start_export(
            AsyncActionKind::Blocking("export.debug"),
            AsyncActionPolicy::AllowConcurrent,
            |_shutdown| async {
                std::future::pending::<Result<AsyncActionPayload, String>>().await
            },
        );

        let report = runner.shutdown_and_reap_with_timeout(Duration::ZERO).await;

        assert_eq!(report.export_reap_timed_out, 1);
        assert_eq!(report.export_reaped, 0);
        assert_eq!(runner.pending_count(), 0);
    }

    #[tokio::test]
    async fn shutdown_abort_reaps_temp_owned_outside_export_future() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = tmp.path().join(".export.partial");
        let worker_partial = partial.clone();
        let (owned_tx, owned_rx) = oneshot::channel();
        let mut runner = AsyncActionRunner::default();
        runner.start_export(
            AsyncActionKind::Blocking("export.transcript"),
            AsyncActionPolicy::AllowConcurrent,
            move |shutdown| async move {
                tokio::fs::write(&worker_partial, b"partial").await.unwrap();
                shutdown.own_export_temp(worker_partial);
                owned_tx.send(()).unwrap();
                std::future::pending::<Result<AsyncActionPayload, String>>().await
            },
        );
        owned_rx.await.unwrap();

        let report = runner
            .shutdown_and_reap_with_timeouts(Duration::ZERO, Duration::from_secs(1))
            .await;

        assert_eq!(report.export_reap_timed_out, 1);
        assert_eq!(report.export_cleanup_failed, 0);
        assert_eq!(report.export_cleanup_timed_out, 0);
        assert!(!partial.exists(), "aborted export left an orphaned partial");
    }

    #[tokio::test]
    async fn export_cleanup_retry_eventually_removes_owned_partial() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = tmp.path().join(".retry.partial");
        tokio::fs::write(&partial, b"partial").await.unwrap();
        let owner = AsyncActionCancellation::default();
        owner.own_export_temp(partial.clone());
        assert!(owner.schedule_export_temp_cleanup_retry());
        // The retry is serviced by the background reaper OS thread; give it
        // real wall-clock time to unlink + fsync rather than busy-yielding
        // within this task (which starves the reaper of observable progress).
        for _ in 0..100 {
            if !partial.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("independent export cleanup retry left an orphan");
    }

    #[tokio::test]
    async fn dropping_temp_owner_enqueues_cleanup_before_any_await() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = tmp.path().join(".drop.partial");
        std::fs::write(&partial, b"partial").unwrap();
        let owner = AsyncActionCancellation::default();
        owner.own_export_temp(partial.clone());
        drop(owner);

        // `drop` enqueues the reap into the background reaper channel
        // synchronously, before this task awaits anything (that is the
        // "before any await" contract). Observing the unlink, however,
        // requires giving the reaper OS thread real wall-clock time to
        // service the queued path — busy-yielding within this task starves
        // the reaper of observable progress (see the sibling retry test).
        for _ in 0..100 {
            if !partial.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("dropping cleanup ownership stranded a partial");
    }

    #[tokio::test]
    async fn dropping_runner_while_export_waits_eventually_reaps_partial() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = tmp.path().join(".runner-drop.partial");
        let worker_partial = partial.clone();
        let (owned_tx, owned_rx) = oneshot::channel();
        let mut runner = AsyncActionRunner::default();
        runner.start_export(
            AsyncActionKind::Blocking("export.transcript"),
            AsyncActionPolicy::AllowConcurrent,
            move |owner| async move {
                std::fs::write(&worker_partial, b"partial").unwrap();
                owner.own_export_temp(worker_partial);
                owned_tx.send(()).unwrap();
                std::future::pending::<Result<AsyncActionPayload, String>>().await
            },
        );
        owned_rx.await.unwrap();
        drop(runner);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        drain_export_temp_reaper();
        assert!(
            !partial.exists(),
            "reaper drain left an owned export partial"
        );
    }

    #[test]
    fn reaper_spawn_failure_fallback_removes_partial_synchronously() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = tmp.path().join(".spawn-failure.partial");
        std::fs::write(&partial, b"partial").unwrap();
        enqueue_export_temp_reap_with(partial.clone(), None);
        assert!(!partial.exists());
    }

    #[test]
    fn reaper_closed_channel_fallback_removes_partial_synchronously() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = tmp.path().join(".closed-channel.partial");
        std::fs::write(&partial, b"partial").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        enqueue_export_temp_reap_with(partial.clone(), Some(tx));
        assert!(!partial.exists());
    }

    #[test]
    fn reaper_guard_drop_drains_cleanup_on_cancelled_run_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = tmp.path().join(".cancelled-run.partial");
        std::fs::write(&partial, b"partial").unwrap();
        let guard = ExportTempReaperGuard::new();
        enqueue_export_temp_reap(partial.clone());
        drop(guard);
        assert!(!partial.exists());
    }

    fn assert_text_payload(result: &AsyncActionResult, expected: &str) {
        assert!(matches!(
            &result.payload,
            Ok(AsyncActionPayload::Text(text)) if text == expected
        ));
    }

    fn assert_bool_payload(result: &AsyncActionResult, expected: bool) {
        assert!(matches!(
            &result.payload,
            Ok(AsyncActionPayload::Bool(value)) if *value == expected
        ));
    }

    #[tokio::test]
    async fn starting_action_records_pending() {
        let mut runner = AsyncActionRunner::default();
        let (_tx, rx) = oneshot::channel::<()>();

        let start = runner.start(
            AsyncActionKind::Internal("pending"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = rx.await;
                Ok(AsyncActionPayload::Unit)
            },
        );

        assert!(matches!(start, AsyncActionStart::Started(_)));
        assert_eq!(runner.pending_count(), 1);
        assert!(runner.is_pending(start.id()));
    }

    #[tokio::test]
    async fn paste_probe_off_event_loop() {
        let mut runner = AsyncActionRunner::default();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let parked = runner.start(
            AsyncActionKind::Internal("paste.test_probe"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = release_rx.await;
                Ok(AsyncActionPayload::Unit)
            },
        );
        assert_eq!(runner.pending_count(), 1);
        runner.start(
            AsyncActionKind::Internal("paste.reducer_progress"),
            AsyncActionPolicy::AllowConcurrent,
            async { Ok(AsyncActionPayload::Bool(true)) },
        );
        runner.notifier().notified().await;
        let progress = runner.drain_completed();
        assert_eq!(progress.len(), 1);
        assert_bool_payload(&progress[0], true);
        assert!(runner.is_pending(parked.id()));

        release_tx.send(()).unwrap();
        runner.notifier().notified().await;
        assert_eq!(runner.drain_completed().len(), 1);

        let replace_key = AsyncActionKey::new("paste.deadline");
        let (stale_tx, stale_rx) = oneshot::channel::<()>();
        let stale = runner.start(
            AsyncActionKind::Internal("paste.deadline"),
            AsyncActionPolicy::Replace(replace_key.clone()),
            async move {
                let _ = stale_rx.await;
                Ok(AsyncActionPayload::Text("late".into()))
            },
        );
        runner.start(
            AsyncActionKind::Internal("paste.deadline"),
            AsyncActionPolicy::Replace(replace_key),
            async { Ok(AsyncActionPayload::Text("replacement".into())) },
        );
        assert!(!runner.is_pending(stale.id()));
        tokio::task::yield_now().await;
        assert!(
            stale_tx.send(()).is_err(),
            "cancelled work cannot settle late"
        );
        runner.notifier().notified().await;
        let settled = runner.drain_completed();
        assert_eq!(settled.len(), 1);
        assert_text_payload(&settled[0], "replacement");
    }

    #[tokio::test]
    async fn completing_delivers_exactly_one_typed_result() {
        let mut runner = AsyncActionRunner::default();
        let (tx, rx) = oneshot::channel::<&'static str>();
        let id = runner
            .start(
                AsyncActionKind::Internal("complete"),
                AsyncActionPolicy::AllowConcurrent,
                async move {
                    let text = rx.await.map_err(|e| e.to_string())?;
                    Ok(AsyncActionPayload::Text(text.to_string()))
                },
            )
            .id();

        tx.send("done").unwrap();
        let results = wait_for_results(&mut runner).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, id);
        assert_eq!(results[0].kind, AsyncActionKind::Internal("complete"));
        assert_text_payload(&results[0], "done");
        assert!(runner.drain_completed().is_empty());
    }

    #[tokio::test]
    async fn superseding_action_ignores_late_result() {
        let mut runner = AsyncActionRunner::default();
        let key = AsyncActionKey::new("refresh");
        let (first_tx, first_rx) = oneshot::channel::<()>();
        let (second_tx, second_rx) = oneshot::channel::<()>();
        let first = runner
            .start(
                AsyncActionKind::Refresh("status"),
                AsyncActionPolicy::Replace(key.clone()),
                async move {
                    let _ = first_rx.await;
                    Ok(AsyncActionPayload::Text("first".to_string()))
                },
            )
            .id();
        let second = runner
            .start(
                AsyncActionKind::Refresh("status"),
                AsyncActionPolicy::Replace(key),
                async move {
                    let _ = second_rx.await;
                    Ok(AsyncActionPayload::Text("second".to_string()))
                },
            )
            .id();

        let _ = first_tx.send(());
        second_tx.send(()).unwrap();
        let results = wait_for_results(&mut runner).await;

        assert_ne!(first, second);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, second);
        assert_text_payload(&results[0], "second");
    }

    #[tokio::test]
    async fn oauth_payload_delivers_and_replace_aborts_prior_generation() {
        let mut runner = AsyncActionRunner::default();
        let key = AsyncActionKey::new("oauth.codex");
        let (first_tx, first_rx) = oneshot::channel::<()>();
        let (second_tx, second_rx) = oneshot::channel::<()>();

        runner.start(
            AsyncActionKind::Internal("oauth.codex.begin"),
            AsyncActionPolicy::Replace(key.clone()),
            async move {
                let _ = first_rx.await;
                Ok(AsyncActionPayload::OAuthCodexComplete { logged_in: false })
            },
        );
        let second = runner
            .start(
                AsyncActionKind::Internal("oauth.codex.begin"),
                AsyncActionPolicy::Replace(key),
                async move {
                    let _ = second_rx.await;
                    Ok(AsyncActionPayload::OAuthCodexComplete { logged_in: true })
                },
            )
            .id();

        first_tx.send(()).unwrap();
        second_tx.send(()).unwrap();
        let results = wait_for_results(&mut runner).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, second);
        assert!(matches!(
            results[0].payload,
            Ok(AsyncActionPayload::OAuthCodexComplete { logged_in: true })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_action_runs_off_event_loop() {
        let mut runner = AsyncActionRunner::default();
        let event_loop_thread = std::thread::current().id();

        runner.start_blocking(
            AsyncActionKind::Blocking("thread-check"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                Ok(AsyncActionPayload::Bool(
                    std::thread::current().id() != event_loop_thread,
                ))
            },
        );

        let results = wait_for_results(&mut runner).await;
        assert_eq!(results.len(), 1);
        assert_bool_payload(&results[0], true);
    }

    #[tokio::test]
    async fn refresh_action_can_dedupe_in_flight() {
        let mut runner = AsyncActionRunner::default();
        let key = AsyncActionKey::new("dedupe");
        let starts = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = oneshot::channel::<()>();
        let starts_for_first = Arc::clone(&starts);

        let first = runner.start(
            AsyncActionKind::Refresh("dedupe"),
            AsyncActionPolicy::Dedupe(key.clone()),
            async move {
                starts_for_first.fetch_add(1, Ordering::SeqCst);
                let _ = rx.await;
                Ok(AsyncActionPayload::Unit)
            },
        );
        let starts_for_second = Arc::clone(&starts);
        let second = runner.start(
            AsyncActionKind::Refresh("dedupe"),
            AsyncActionPolicy::Dedupe(key),
            async move {
                starts_for_second.fetch_add(1, Ordering::SeqCst);
                Ok(AsyncActionPayload::Unit)
            },
        );

        assert_eq!(second, AsyncActionStart::Existing(first.id()));
        tx.send(()).unwrap();
        assert_eq!(wait_for_results(&mut runner).await.len(), 1);
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn blocking_dedupe_retains_completed_action_until_result_is_drained() {
        let mut runner = AsyncActionRunner::default();
        let key = AsyncActionKey::new("blocking-create");
        let starts = Arc::new(AtomicUsize::new(0));
        let first_starts = Arc::clone(&starts);
        let notify = runner.notifier();

        let first = runner.start_blocking(
            AsyncActionKind::Blocking("blocking-create"),
            AsyncActionPolicy::Dedupe(key.clone()),
            move || {
                first_starts.fetch_add(1, Ordering::SeqCst);
                Ok(AsyncActionPayload::Text("created".to_string()))
            },
        );
        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .expect("blocking action completed");

        // Completion is queued, but the action remains registered until the
        // UI drains and adopts it. A repeated creation must not supersede it.
        let second_starts = Arc::clone(&starts);
        let second = runner.start_blocking(
            AsyncActionKind::Blocking("blocking-create"),
            AsyncActionPolicy::Dedupe(key),
            move || {
                second_starts.fetch_add(1, Ordering::SeqCst);
                Ok(AsyncActionPayload::Text("orphan".to_string()))
            },
        );

        assert_eq!(second, AsyncActionStart::Existing(first.id()));
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        let results = runner.drain_completed();
        assert_eq!(results.len(), 1);
        assert_text_payload(&results[0], "created");
    }

    #[tokio::test]
    async fn shutdown_ignores_in_flight_actions_without_panic() {
        let mut runner = AsyncActionRunner::default();
        let (_tx, rx) = oneshot::channel::<()>();
        runner.start(
            AsyncActionKind::Internal("shutdown"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = rx.await;
                Ok(AsyncActionPayload::Unit)
            },
        );

        runner.shutdown();

        assert_eq!(runner.pending_count(), 0);
        assert!(runner.drain_completed().is_empty());
    }
}
