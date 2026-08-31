//! TUI ↔ daemon glue.
//!
//! Phase 4 of the daemon migration: the TUI no longer owns the
//! engine. Instead [`try_spawn`] probes (or auto-promotes) the daemon
//! via [`cockpit_client`], attaches a session at the cwd, and
//! pipes the per-tick event stream from the daemon's broadcast back
//! to the TUI in the same `Arc<Mutex<Vec<TurnEvent>>>` shape the rest
//! of `app.rs` already consumes. The wire-shape of events is
//! [`cockpit_proto::Event`]; we translate to [`TurnEvent`] at
//! the boundary so the TUI rendering paths don't need to know they
//! talk to a daemon.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, Notify, OwnedMutexGuard, RwLock, mpsc, oneshot, watch};
use tokio::task::{AbortHandle, JoinHandle};
use uuid::Uuid;

use cockpit_client::bulk_upload::{
    BulkUserMessageUploadError, INLINE_USER_MESSAGE_TEXT_BYTES, stage_opaque_user_text,
    user_message_needs_bulk,
};
use cockpit_client::image_upload::ImageUploadError;
use cockpit_client::presentation::{
    ControlRequestId, ControlRequestNotDelivered, ControlRequestOutcome, TurnEvent,
};
use cockpit_client::submission::ClientUserSubmission;
use cockpit_client::{ClientEndpoint, DaemonClient, LifecycleClient, LifecycleIntent};
use cockpit_host::jitter::{JitterSource, SystemJitter};
use cockpit_proto::{self as proto, ErrorCode, ErrorPayload, Request, Response};

/// The three 30-day autocomplete count maps fetched at session start.
/// `models` and `slash` are global; `tags` is scoped to this session's
/// project. Empty when the daemon predates `GetUsageCounts`.
#[derive(Default, Clone)]
pub struct UsageCounts {
    pub models: HashMap<String, u64>,
    pub slash: HashMap<String, u64>,
    pub tags: HashMap<String, u64>,
}

/// Sentinel epoch for daemon-global / host-link events that are not bound to
/// one attachment. App routes these through the provisional-global reducer.
pub(crate) const GLOBAL_ATTACHMENT_EPOCH: u64 = u64::MAX;

/// Runner-to-App event envelope. The enqueue stamp is the client/request
/// epoch captured when the producer selected its attachment — never the
/// atomic current epoch at enqueue time.
#[derive(Debug)]
pub(crate) struct QueuedTurnEvent {
    pub(crate) attachment_epoch: u64,
    pub(crate) event: TurnEvent,
}

/// Session id paired with the attachment epoch that published it. Dispatcher
/// wakes carry this captured epoch so late Notices are not re-stamped from
/// the atomic current epoch at enqueue time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SubmissionSessionBinding {
    pub(crate) session_id: Uuid,
    pub(crate) attachment_epoch: u64,
}

impl SubmissionSessionBinding {
    pub(crate) fn new(session_id: Uuid, attachment_epoch: u64) -> Self {
        Self {
            session_id,
            attachment_epoch,
        }
    }
}

/// Handle the TUI keeps to talk to the engine (now via the daemon).
pub struct AttachedRequest {
    pub request: Request,
    pub intended_session_id: Uuid,
    pub intended_attachment_epoch: u64,
    pub response_tx: oneshot::Sender<Result<Response, String>>,
}

#[derive(Clone)]
pub(crate) struct AttachedRequestBinding {
    sender: mpsc::Sender<AttachedRequest>,
    intended_session_id: Uuid,
    intended_attachment_epoch: u64,
}

impl std::fmt::Debug for AttachedRequestBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachedRequestBinding")
            .field("session_id", &self.intended_session_id)
            .field("attachment_epoch", &self.intended_attachment_epoch)
            .finish_non_exhaustive()
    }
}

impl AttachedRequestBinding {
    pub(crate) fn new(
        sender: mpsc::Sender<AttachedRequest>,
        intended_session_id: Uuid,
        intended_attachment_epoch: u64,
    ) -> Self {
        Self {
            sender,
            intended_session_id,
            intended_attachment_epoch,
        }
    }

    pub(crate) fn session_id(&self) -> Uuid {
        self.intended_session_id
    }

    pub(crate) fn attachment_epoch(&self) -> u64 {
        self.intended_attachment_epoch
    }

    pub(crate) async fn request(&self, request: Request) -> Result<Response, String> {
        let (response_tx, response_rx) = oneshot::channel();
        self.sender
            .send(AttachedRequest {
                request,
                intended_session_id: self.intended_session_id,
                intended_attachment_epoch: self.intended_attachment_epoch,
                response_tx,
            })
            .await
            .map_err(|_| "daemon client task has stopped".to_string())?;
        response_rx
            .await
            .map_err(|_| "daemon client dropped reply channel".to_string())?
    }
}

pub struct ControlRequest {
    pub request: Request,
    pub intended_session_id: Uuid,
    pub intended_attachment_epoch: u64,
    pub response_tx: oneshot::Sender<Result<Response, String>>,
}

#[derive(Clone)]
pub(crate) struct BoundUserSubmission {
    pub(crate) submission: ClientUserSubmission,
    pub(crate) optimistic_submission_id: Uuid,
    pub(crate) intended_session_id: Uuid,
    pub(crate) intended_attachment_epoch: u64,
}

pub(crate) enum RunnerInput {
    Submission(Box<BoundUserSubmission>),
    /// Dispatcher-internal release of an already retained submission. It must
    /// bypass the "later submission joins behind retained work" gate.
    RetainedRetry(Box<BoundUserSubmission>),
    /// Submissions accepted while an in-process attach was pending. The
    /// whole ordered batch occupies one bounded-channel slot; once received,
    /// the dispatcher owns every exact payload and drains them in FIFO order.
    SubmissionBatch(Vec<BoundUserSubmission>),
    /// FIFO fence used by an explicit session switch. Once the dispatcher
    /// acknowledges this item, every submission accepted before the switch
    /// was requested has reached a terminal dispatch outcome on its original
    /// attachment.
    Flush(oneshot::Sender<()>),
}

enum UserSubmissionDispatchOutcome {
    Delivered(Box<BoundUserSubmission>),
    StaleAttachment(Box<BoundUserSubmission>),
    Rejected {
        error: String,
        optimistic_submission_id: Uuid,
        session_id: Uuid,
        intended_attachment_epoch: u64,
        // Keep session transitions excluded until the failure event has been
        // enqueued. Otherwise a transport failure from the old attachment can
        // race a completed switch and mark the replacement session's newest
        // optimistic message as failed.
        transition_guard: OwnedMutexGuard<()>,
    },
    Retained {
        error: String,
        bound: Box<BoundUserSubmission>,
        transition_guard: OwnedMutexGuard<()>,
    },
    Ambiguous {
        error: String,
        bound: Box<BoundUserSubmission>,
        transition_guard: OwnedMutexGuard<()>,
    },
}

enum UserSubmissionSendError {
    Rejected(String),
    NotAccepted(String),
    Ambiguous(String),
}

fn classify_image_upload_error(error: ImageUploadError) -> UserSubmissionSendError {
    match error {
        ImageUploadError::Usage(message) => UserSubmissionSendError::Rejected(message),
        ImageUploadError::Daemon(message) | ImageUploadError::Transport(message) => {
            UserSubmissionSendError::Ambiguous(message)
        }
    }
}

fn classify_bulk_user_message_upload_error(
    error: BulkUserMessageUploadError,
) -> UserSubmissionSendError {
    match error {
        BulkUserMessageUploadError::Usage(message) => UserSubmissionSendError::Rejected(message),
        BulkUserMessageUploadError::Daemon(message)
        | BulkUserMessageUploadError::Transport(message) => {
            UserSubmissionSendError::Ambiguous(message)
        }
    }
}

fn classify_compact_response(
    response: Result<Response, proto::ErrorPayload>,
) -> Result<(), UserSubmissionSendError> {
    match response {
        Ok(Response::Ack) => Ok(()),
        Ok(response) => Err(UserSubmissionSendError::Ambiguous(format!(
            "daemon returned an unexpected response to compact: {response:?}"
        ))),
        Err(error) => {
            tracing::warn!(error = ?error, "compact request rejected");
            Err(UserSubmissionSendError::Ambiguous(error.to_string()))
        }
    }
}

fn classify_user_message_response(
    response: Result<Response, proto::ErrorPayload>,
) -> Result<Option<Vec<proto::QueueItem>>, UserSubmissionSendError> {
    match response {
        Ok(Response::UserMessageQueued { queue, .. }) => Ok(Some(queue)),
        // A materialized durable receipt replays as Ack. It is final success,
        // but carries no authoritative queue snapshot to publish.
        Ok(Response::Ack) => Ok(None),
        Ok(_) => Err(UserSubmissionSendError::Ambiguous(
            "daemon returned an unexpected response to send_user_message".to_string(),
        )),
        Err(error) => match error.code {
            proto::ErrorCode::UserMessageNotAccepted => {
                Err(UserSubmissionSendError::NotAccepted(error.message))
            }
            proto::ErrorCode::UserMessageTerminated => {
                Err(UserSubmissionSendError::Rejected(error.message))
            }
            proto::ErrorCode::ModelGenerationStale => {
                Err(UserSubmissionSendError::Rejected(error.message))
            }
            proto::ErrorCode::Internal
            | proto::ErrorCode::Shutdown
            | proto::ErrorCode::StorageFull
            | proto::ErrorCode::StorageMemory
            | proto::ErrorCode::StorageReadOnly
            | proto::ErrorCode::StorageIo
            | proto::ErrorCode::StorageCorrupt => {
                Err(UserSubmissionSendError::Ambiguous(error.message))
            }
            _ => Err(UserSubmissionSendError::Rejected(error.message)),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputNotDelivered {
    QueueFull,
    RunnerClosed,
}

impl std::ops::Deref for BoundUserSubmission {
    type Target = ClientUserSubmission;

    fn deref(&self) -> &Self::Target {
        &self.submission
    }
}

#[cfg(test)]
impl From<ClientUserSubmission> for BoundUserSubmission {
    fn from(submission: ClientUserSubmission) -> Self {
        Self {
            submission,
            optimistic_submission_id: Uuid::new_v4(),
            intended_session_id: Uuid::nil(),
            intended_attachment_epoch: 0,
        }
    }
}

#[cfg(test)]
impl From<ClientUserSubmission> for RunnerInput {
    fn from(submission: ClientUserSubmission) -> Self {
        Self::Submission(Box::new(submission.into()))
    }
}

#[cfg(test)]
impl std::ops::Deref for RunnerInput {
    type Target = BoundUserSubmission;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Submission(bound) => bound,
            Self::RetainedRetry(bound) => bound,
            Self::SubmissionBatch(_) => {
                panic!("test expected one user submission, found a submission batch")
            }
            Self::Flush(_) => panic!("test expected a user submission, found a flush marker"),
        }
    }
}

pub struct AgentRunner {
    /// Send user submissions here (text + any pasted image parts). Each
    /// becomes one V2 message request; the daemon's queue-folding
    /// (GOALS §1c) is performed inside the worker, not here.
    pub(crate) input_tx: mpsc::Sender<RunnerInput>,
    /// Fire-and-forget `RecordUsage` requests (autocomplete tally).
    pub record_tx: mpsc::Sender<Request>,
    /// Response-bearing control requests from TUI commands. Kept separate
    /// from telemetry so a full usage queue cannot block control-plane state.
    pub control_tx: mpsc::Sender<ControlRequest>,
    /// Response-bearing requests sent over the already-attached daemon client.
    pub attached_request_tx: mpsc::Sender<AttachedRequest>,
    /// Drained per tick into [`crate::tui::app::App::history`].
    pub(crate) events: Arc<Mutex<Vec<QueuedTurnEvent>>>,
    pub(crate) event_notify: Arc<Notify>,
    /// Name of whoever's currently on top of the agent stack. The
    /// chrome reads this for the active-agent slot (GOALS §1a).
    pub active_agent: Arc<Mutex<String>>,
    /// Root primary plus any active interactive subagent path. Depth one is
    /// the current runtime behavior, but a vector avoids baking that into
    /// the footer model.
    pub active_agent_path: Arc<Mutex<Vec<String>>>,
    /// Names in the daemon's conditionally filtered skill inventory for the
    /// exact foreground toolbox. `None` until the first attached refresh.
    pub skill_inventory_names: Arc<Mutex<Option<std::collections::HashSet<String>>>>,
    /// Queue-edit foreground target from the attach snapshot. Live updates
    /// arrive as `TurnEvent::ForegroundInputTarget`.
    pub foreground_target: Option<proto::QueueTarget>,
    /// Authoritative active-model snapshot from `Attach`, used to seed chrome
    /// before any later live active-model event arrives.
    pub active_model_state: Option<proto::ActiveModelState>,
    /// Exact daemon-returned setup metadata for this attached session.
    pub session_entry_mode: proto::SessionEntryMode,
    /// This session's full id. Shown in the startup graphic and printed on
    /// exit (session-id-display-and-lazy-persist). Assigned by the daemon at
    /// attach, before the `sessions` row is persisted.
    pub(crate) session_id_state: Arc<Mutex<uuid::Uuid>>,
    pub(crate) attachment_epoch: Arc<AtomicU64>,
    /// Post-apply session identity for the input dispatcher. The transport
    /// epoch advances before App adopts a switch snapshot, so recovery must
    /// not infer the new destination from that earlier signal.
    pub(crate) submission_session_tx: watch::Sender<SubmissionSessionBinding>,
    pub(crate) awaiting_durable: Arc<Mutex<HashMap<Uuid, VecDeque<BoundUserSubmission>>>>,
    /// This session's 6-char display id (GOALS §17b). The TUI captures
    /// it as the predecessor short-id when this session spawns a
    /// `/compact` handoff, so the fresh session can draw a "compacted
    /// from <short-id>" boundary marker.
    pub short_id: String,
    /// This session's project id — the scope for `tag` usage records.
    pub project_id: String,
    /// Frequency counts fetched at attach; the TUI seeds its in-memory
    /// maps from these once.
    pub usage: UsageCounts,
    /// `true` when this TUI *spawned* the daemon it's attached to (the
    /// ephemeral path) and therefore owns its teardown
    /// — the CLI lifecycle composition retains its teardown guard. `false`
    /// when it attached to a pre-existing (canonical or
    /// auto-promoted persistent) daemon, which it must never stop.
    pub owns_daemon: bool,
    /// Whether detaching the final client would reap this owner. Set from the
    /// lifecycle host rather than inferred from the launch preference.
    pub ephemeral_owner: Arc<AtomicBool>,
    /// Capability used for every fresh connection to this exact daemon,
    /// including session switches and reconnects.
    pub(crate) endpoint: ClientEndpoint,
    /// Lifecycle capability retained for an existing-session switch. A
    /// durable Assistant can be selected after the runner was first attached,
    /// so that switch must re-resolve the owner as persistent before Attach.
    lifecycle: LifecycleClient,
    /// The socket of the daemon this runner is attached to. Carried so an
    /// owned ephemeral daemon can be reaped on exit via the guard.
    pub socket: PathBuf,
    /// The daemon's chronological history snapshot for the attached session
    /// (implementation note). On a `/sessions` resume the
    /// app converts these wire entries into TUI `HistoryEntry` rows so the
    /// full prior transcript renders; empty for a freshly-created session.
    pub history: Vec<proto::HistoryEntry>,
    /// Durable work paused during daemon shutdown for this session. Non-empty
    /// only after reattaching to a session that needs an explicit resume/cancel
    /// decision.
    pub paused_work: Vec<proto::PausedWorkSummary>,
    /// Responses resume repair state, when the daemon opened the session
    /// read-only because provider replay cannot be rebuilt safely.
    pub repair_required: Option<proto::ResumeRepairState>,
    /// Non-mutating full-vs-compacted choice returned by an interactive
    /// away-resume attach.
    pub resume_compaction_offer: Option<proto::ResumeCompactionOffer>,
    /// Live `/btw` fork advertised by the daemon when attaching to a parent
    /// session. The TUI may attach a second runner to this session id for the
    /// side pane; the main runner remains bound to the parent.
    pub btw_fork: Option<proto::BtwForkInfo>,
    /// Version advertised by the daemon at attach.
    pub daemon_version: String,
    /// Whether this client is compatible with the daemon protocol/version.
    pub daemon_compatible: bool,
    pub(crate) current_client: Option<Arc<RwLock<DaemonClient>>>,
    pub(crate) attach_context: Option<Arc<RwLock<AttachRequestContext>>>,
    pub(crate) last_applied_seq: Option<Arc<Mutex<Option<i64>>>>,
    /// Client-side forwarding/event tasks owned by this runner. Dropping a TUI
    /// runner must only tear down this socket-side plumbing; daemon-side
    /// session work keeps running until an explicit daemon request stops it.
    pub(crate) client_tasks: ClientTasks,
    /// Test-only controllable `/new` switch: when set, `can_switch_session`
    /// is true and `switch_*_task` awaits this oneshot instead of connecting.
    #[cfg(test)]
    pub(crate) test_session_switch_rx: TestSessionSwitchRx,
    #[cfg(test)]
    pub(crate) test_force_can_switch: bool,
    /// When set, constructing a switch task advances `attachment_epoch` before
    /// returning the future — simulating a fast replacement attach racing
    /// ahead of App's provisional reset.
    #[cfg(test)]
    pub(crate) test_advance_epoch_when_switch_task_created: bool,
}

#[cfg(test)]
type TestSessionSwitchRx =
    Arc<Mutex<Option<oneshot::Receiver<Result<SessionSwitchOutcome, String>>>>>;

#[derive(Default)]
pub(crate) struct ClientTasks {
    handles: Vec<JoinHandle<()>>,
}

impl ClientTasks {
    fn push(&mut self, handle: JoinHandle<()>) {
        self.handles.push(handle);
    }

    fn shutdown(&mut self) {
        for handle in self.handles.drain(..) {
            handle.abort();
        }
    }
}

impl Drop for ClientTasks {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The parts a test runner fixture actually varies. Everything else comes
/// from [`AgentRunner::test_fixture`], so this file stays the single owner of
/// the runner's field list: adding a field must not ripple back out into the
/// per-module fixtures.
#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
pub(crate) struct TestRunnerOverrides {
    pub(crate) input_tx: Option<mpsc::Sender<RunnerInput>>,
    pub(crate) record_tx: Option<mpsc::Sender<Request>>,
    pub(crate) control_tx: Option<mpsc::Sender<ControlRequest>>,
    pub(crate) attached_request_tx: Option<mpsc::Sender<AttachedRequest>>,
    pub(crate) events: Option<Arc<Mutex<Vec<QueuedTurnEvent>>>>,
    /// Also seeds the submission-session binding, so a fixture that pins an
    /// id keeps both halves consistent.
    pub(crate) session_id: Option<uuid::Uuid>,
    pub(crate) short_id: Option<String>,
    pub(crate) socket: Option<PathBuf>,
    pub(crate) last_applied_seq: Option<Arc<Mutex<Option<i64>>>>,
    pub(crate) client_tasks: Option<ClientTasks>,
}

impl std::fmt::Debug for AgentRunner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentRunner")
            .field("session_id", &self.session_id())
            .field("short_id", &self.short_id)
            .field("project_id", &self.project_id)
            .field("owns_daemon", &self.owns_daemon)
            .finish_non_exhaustive()
    }
}

impl AgentRunner {
    /// Retry exact submissions retained after a deterministic pre-acceptance
    /// rejection. Reusing the attachment watch gives the dispatcher a
    /// lossless, coalescing wake without another bounded channel.
    pub(crate) fn retry_retained_user_submissions(&self) {
        self.submission_session_tx
            .send_replace(SubmissionSessionBinding::new(
                self.session_id(),
                self.attachment_epoch(),
            ));
    }

    #[cfg(test)]
    pub(crate) fn stub_with_control_tx(control_tx: mpsc::Sender<ControlRequest>) -> Self {
        Self::test_fixture(TestRunnerOverrides {
            control_tx: Some(control_tx),
            ..Default::default()
        })
    }

    #[cfg(test)]
    pub(crate) fn stub_with_channels(
        control_tx: mpsc::Sender<ControlRequest>,
        input_tx: mpsc::Sender<RunnerInput>,
    ) -> Self {
        Self::stub_with_channels_and_submission_watch(control_tx, input_tx).0
    }

    #[cfg(test)]
    pub(crate) fn stub_with_channels_and_submission_watch(
        control_tx: mpsc::Sender<ControlRequest>,
        input_tx: mpsc::Sender<RunnerInput>,
    ) -> (Self, watch::Receiver<SubmissionSessionBinding>) {
        Self::test_fixture_with_submission_watch(TestRunnerOverrides {
            input_tx: Some(input_tx),
            control_tx: Some(control_tx),
            ..Default::default()
        })
    }

    /// The one authoritative test runner. Fixtures elsewhere in the crate hand
    /// it only the channels/ids they assert against; the defaults below are
    /// the inert "attached, idle, nothing owned" shape.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test_fixture(overrides: TestRunnerOverrides) -> Self {
        Self::test_fixture_with_submission_watch(overrides).0
    }

    /// [`Self::test_fixture`] for callers that must observe dispatcher wakes on
    /// the submission-session watch.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test_fixture_with_submission_watch(
        overrides: TestRunnerOverrides,
    ) -> (Self, watch::Receiver<SubmissionSessionBinding>) {
        let TestRunnerOverrides {
            input_tx,
            record_tx,
            control_tx,
            attached_request_tx,
            events,
            session_id,
            short_id,
            socket,
            last_applied_seq,
            client_tasks,
        } = overrides;
        let session_id = session_id.unwrap_or_else(uuid::Uuid::new_v4);
        let (submission_session_tx, submission_session_rx) =
            watch::channel(SubmissionSessionBinding::new(session_id, 0));
        let runner = Self {
            input_tx: input_tx.unwrap_or_else(|| mpsc::channel(8).0),
            record_tx: record_tx.unwrap_or_else(|| mpsc::channel(1).0),
            control_tx: control_tx.unwrap_or_else(|| mpsc::channel(1).0),
            attached_request_tx: attached_request_tx.unwrap_or_else(|| mpsc::channel(1).0),
            events: events.unwrap_or_else(|| Arc::new(Mutex::new(Vec::new()))),
            event_notify: Arc::new(Notify::new()),
            active_agent: Arc::new(Mutex::new("Build".to_string())),
            active_agent_path: Arc::new(Mutex::new(vec!["Build".to_string()])),
            skill_inventory_names: Arc::new(Mutex::new(None)),
            foreground_target: Some(proto::QueueTarget::root("Build")),
            active_model_state: None,
            session_entry_mode: proto::SessionEntryMode::Code,
            session_id_state: Arc::new(Mutex::new(session_id)),
            attachment_epoch: Arc::new(AtomicU64::new(0)),
            submission_session_tx,
            awaiting_durable: Default::default(),
            short_id: short_id.unwrap_or_else(|| "abc123".to_string()),
            project_id: "project".to_string(),
            usage: UsageCounts::default(),
            owns_daemon: false,
            ephemeral_owner: Arc::new(AtomicBool::new(false)),
            endpoint: ClientEndpoint::Wire(
                socket
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("/tmp/cockpit-test.sock")),
            ),
            lifecycle: LifecycleClient::disconnected(),
            socket: socket.unwrap_or_else(|| PathBuf::from("/tmp/cockpit-test.sock")),
            history: Vec::new(),
            paused_work: Vec::new(),
            repair_required: None,
            resume_compaction_offer: None,
            btw_fork: None,
            daemon_version: "test".to_string(),
            daemon_compatible: true,
            current_client: None,
            attach_context: None,
            last_applied_seq,
            client_tasks: client_tasks.unwrap_or_default(),
            #[cfg(test)]
            test_session_switch_rx: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            test_force_can_switch: false,
            #[cfg(test)]
            test_advance_epoch_when_switch_task_created: false,
        };
        (runner, submission_session_rx)
    }
    /// Stop this runner's socket-side client tasks. This intentionally sends no
    /// daemon request: abandoning a TUI handle must not cancel or discard the
    /// daemon-owned session.
    pub fn shutdown(&mut self) {
        self.client_tasks.shutdown();
    }

    pub fn event_notifier(&self) -> Arc<Notify> {
        Arc::clone(&self.event_notify)
    }

    pub fn session_id(&self) -> uuid::Uuid {
        *self
            .session_id_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn attachment_epoch(&self) -> u64 {
        self.attachment_epoch.load(Ordering::Acquire)
    }

    /// Feed a published wire event through the production AgentRunner
    /// reducer (`apply_incoming_event`). Used by the response-performance
    /// e2e harness; not a production API.
    #[cfg(feature = "test-support")]
    pub(crate) fn apply_published_event(&self, event: proto::Event) {
        let session_id = self.session_id();
        let fallback_seq = Arc::new(Mutex::new(None));
        let last_applied_seq = self.last_applied_seq.as_ref().unwrap_or(&fallback_seq);
        let incoming = IncomingEventContext {
            session_id,
            client_epoch: self.attachment_epoch(),
            attachment_epoch: &self.attachment_epoch,
            events: &self.events,
            event_notify: &self.event_notify,
            active_agent: &self.active_agent,
            active_agent_path: &self.active_agent_path,
            primary_agent: &self.active_agent,
            last_applied_seq,
            awaiting_durable: &self.awaiting_durable,
        };
        apply_incoming_event(event, &incoming);
    }

    pub(crate) fn attached_request_binding(&self) -> AttachedRequestBinding {
        AttachedRequestBinding::new(
            self.attached_request_tx.clone(),
            self.session_id(),
            self.attachment_epoch(),
        )
    }

    pub(crate) fn try_send_input(
        &self,
        submission: ClientUserSubmission,
    ) -> Result<(), InputNotDelivered> {
        self.try_send_optimistic_input(submission, Uuid::now_v7())
            .map_err(|(outcome, _submission)| outcome)
    }

    pub(crate) fn try_send_optimistic_input(
        &self,
        submission: ClientUserSubmission,
        optimistic_submission_id: Uuid,
    ) -> Result<(), (InputNotDelivered, Box<ClientUserSubmission>)> {
        let bound = BoundUserSubmission {
            submission,
            optimistic_submission_id,
            intended_session_id: self.session_id(),
            intended_attachment_epoch: self.attachment_epoch(),
        };
        self.input_tx
            .try_send(RunnerInput::Submission(Box::new(bound)))
            .map_err(|error| {
                let (outcome, input) = match error {
                    tokio::sync::mpsc::error::TrySendError::Full(input) => {
                        (InputNotDelivered::QueueFull, input)
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(input) => {
                        (InputNotDelivered::RunnerClosed, input)
                    }
                };
                let RunnerInput::Submission(bound) = input else {
                    unreachable!("try_send_optimistic_input only sends one submission")
                };
                (outcome, Box::new(bound.submission))
            })
    }

    /// Transfer submissions staged by App during a session switch into the
    /// dispatcher without consuming one bounded-channel slot per message.
    /// `switch_session_task` has already placed and observed a FIFO flush
    /// marker before Attach begins, so the channel has room for this single
    /// post-switch item even when the batch is larger than its capacity.
    pub(crate) fn try_send_session_switch_inputs(
        &self,
        submissions: Vec<(Uuid, ClientUserSubmission)>,
    ) -> Result<(), (InputNotDelivered, Vec<(Uuid, ClientUserSubmission)>)> {
        if submissions.is_empty() {
            return Ok(());
        }
        let intended_session_id = self.session_id();
        let intended_attachment_epoch = self.attachment_epoch();
        let mut bound = submissions
            .into_iter()
            .map(
                |(optimistic_submission_id, submission)| BoundUserSubmission {
                    submission,
                    optimistic_submission_id,
                    intended_session_id,
                    intended_attachment_epoch,
                },
            )
            .collect::<Vec<_>>();
        let input = if bound.len() == 1 {
            RunnerInput::Submission(Box::new(bound.pop().expect("one bound submission")))
        } else {
            RunnerInput::SubmissionBatch(bound)
        };
        self.input_tx.try_send(input).map_err(|error| {
            let (outcome, input) = match error {
                tokio::sync::mpsc::error::TrySendError::Full(input) => {
                    (InputNotDelivered::QueueFull, input)
                }
                tokio::sync::mpsc::error::TrySendError::Closed(input) => {
                    (InputNotDelivered::RunnerClosed, input)
                }
            };
            let submissions = match input {
                RunnerInput::Submission(bound) => {
                    vec![(bound.optimistic_submission_id, bound.submission)]
                }
                RunnerInput::RetainedRetry(_) => {
                    unreachable!("retained retries are dispatcher-internal")
                }
                RunnerInput::SubmissionBatch(bound) => bound
                    .into_iter()
                    .map(|bound| (bound.optimistic_submission_id, bound.submission))
                    .collect(),
                RunnerInput::Flush(_) => unreachable!("only submissions are transferred"),
            };
            (outcome, submissions)
        })
    }

    pub fn can_switch_session(&self) -> bool {
        #[cfg(test)]
        if self.test_force_can_switch {
            return true;
        }
        self.current_client.is_some()
            && self.attach_context.is_some()
            && self.last_applied_seq.is_some()
    }

    /// Install a live-swappable `/new` seam: `can_switch_session` is true and
    /// the next `switch_new_session_task` awaits `outcome_rx` with no socket,
    /// network, or daemon. Returns a handle that observes when the switch
    /// future has taken the receiver (action started).
    #[cfg(test)]
    pub(crate) fn install_live_swappable_switch_seam(
        &mut self,
        outcome_rx: oneshot::Receiver<Result<SessionSwitchOutcome, String>>,
    ) {
        self.test_force_can_switch = true;
        self.last_applied_seq = Some(Arc::new(Mutex::new(Some(0))));
        let (client_epoch_tx, _client_epoch_rx) = watch::channel(self.attachment_epoch());
        self.attach_context = Some(Arc::new(RwLock::new(AttachRequestContext {
            session_id: None,
            project_root: "/tmp/cockpit-test".to_string(),
            no_sandbox: false,
            session_entry_mode: proto::SessionEntryMode::Code,
            env_snapshot: cockpit_core::env_snapshot::capture_tui_shell_env()
                .0
                .to_wire(),
            transition_gate: Arc::new(AsyncMutex::new(())),
            client_epoch_tx,
            attachment_epoch: self.attachment_epoch.clone(),
        })));
        *self
            .test_session_switch_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(outcome_rx);
    }

    #[cfg(test)]
    fn take_test_session_switch_rx(
        &self,
    ) -> Option<oneshot::Receiver<Result<SessionSwitchOutcome, String>>> {
        self.test_session_switch_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    pub(crate) fn has_attached_client(&self) -> bool {
        self.current_client.is_some()
    }

    pub fn switch_session_task(
        &self,
        target: SessionTarget,
    ) -> impl std::future::Future<Output = Result<SessionSwitchOutcome, String>> + Send + 'static
    {
        self.switch_session_task_inner(target, false)
    }

    /// `/new` stages cancellation of an outgoing busy turn until after the
    /// replacement Attach succeeds. The old client is still available at
    /// that point; cancelling through App after adoption would incorrectly
    /// target the new session.
    pub fn switch_new_session_task(
        &self,
        cancel_outgoing_turn_after_attach: bool,
    ) -> impl std::future::Future<Output = Result<SessionSwitchOutcome, String>> + Send + 'static
    {
        self.switch_session_task_inner(SessionTarget::New, cancel_outgoing_turn_after_attach)
    }

    fn switch_session_task_inner(
        &self,
        target: SessionTarget,
        cancel_outgoing_turn_after_attach: bool,
    ) -> impl std::future::Future<Output = Result<SessionSwitchOutcome, String>> + Send + 'static
    {
        #[cfg(test)]
        let test_rx = self.take_test_session_switch_rx();
        #[cfg(test)]
        if self.test_advance_epoch_when_switch_task_created {
            // Simulate replacement attach publishing a new epoch as soon as the
            // switch task exists — before App's provisional reset runs.
            let _ = self.attachment_epoch.fetch_add(1, Ordering::AcqRel);
        }
        let current_client = self.current_client.clone();
        let attach_context = self.attach_context.clone();
        let session_id_state = self.session_id_state.clone();
        let last_applied_seq = self.last_applied_seq.clone();
        let endpoint = self.endpoint.clone();
        let lifecycle = self.lifecycle.clone();
        let input_tx = self.input_tx.clone();
        async move {
            #[cfg(test)]
            if let Some(rx) = test_rx {
                let mut outcome = rx
                    .await
                    .map_err(|_| "test session switch cancelled".to_string())??;
                if let Some(attach_context) = attach_context.as_ref() {
                    let transition_gate = attach_context.read().await.transition_gate.clone();
                    outcome.transition_guard = Some(transition_gate.lock_owned().await);
                }
                let _ = (
                    target,
                    cancel_outgoing_turn_after_attach,
                    current_client,
                    session_id_state,
                    last_applied_seq,
                    endpoint,
                    lifecycle,
                    input_tx,
                );
                return Ok(outcome);
            }
            let Some(current_client) = current_client else {
                return Err("runner has no attached daemon client".to_string());
            };
            let Some(attach_context) = attach_context else {
                return Err("runner has no attach context".to_string());
            };
            let Some(_last_applied_seq) = last_applied_seq else {
                return Err("runner has no session sequence state".to_string());
            };
            // This marker is ordered with user submissions in the same FIFO.
            // Wait before taking the transition gate so accepted old-session
            // work cannot be stranded merely because the switch task won the
            // scheduler race against the input dispatcher.
            flush_accepted_user_submissions(&input_tx).await?;
            // The daemon can emit events for the old attachment until its
            // Attach response is received. Keep event application and the
            // authoritative response in one ordering domain: queued old
            // events are drained by App while this guard is still held.
            let transition_gate = attach_context.read().await.transition_gate.clone();
            let transition_guard = transition_gate.lock_owned().await;
            let mut outcome = switch_session_inner(
                current_client,
                attach_context,
                session_id_state,
                endpoint,
                lifecycle,
                target,
                cancel_outgoing_turn_after_attach,
            )
            .await?;
            outcome.transition_guard = Some(transition_guard);
            Ok(outcome)
        }
    }

    pub(crate) fn apply_session_switch_outcome(&mut self, outcome: &SessionSwitchOutcome) {
        self.session_entry_mode = outcome.session_entry_mode;
        apply_session_switch_state(
            outcome,
            &self.session_id_state,
            self.last_applied_seq
                .as_ref()
                .expect("swappable runner has sequence state"),
            &self.active_agent,
            &self.active_agent_path,
        );
        self.short_id = outcome.short_id.clone();
        self.project_id = outcome.project_id.clone();
        self.foreground_target = outcome.foreground_target.clone();
        self.active_model_state = outcome.active_model_state.clone();
        self.history = outcome.history.clone();
        self.paused_work = outcome.paused_work.clone();
        self.repair_required = outcome.repair_required.clone();
        self.resume_compaction_offer = outcome.resume_compaction_offer.clone();
        self.btw_fork = outcome.btw_fork.clone();
        acknowledge_history_receipts(&self.awaiting_durable, outcome.session_id, &outcome.history);
        self.submission_session_tx
            .send_replace(SubmissionSessionBinding::new(
                outcome.session_id,
                outcome.attachment_epoch,
            ));
    }
}

async fn flush_accepted_user_submissions(
    input_tx: &mpsc::Sender<RunnerInput>,
) -> Result<(), String> {
    let (flushed_tx, flushed_rx) = oneshot::channel();
    input_tx
        .send(RunnerInput::Flush(flushed_tx))
        .await
        .map_err(|_| "session input dispatcher stopped before switch".to_string())?;
    flushed_rx
        .await
        .map_err(|_| "session input dispatcher stopped before flush".to_string())
}

fn push_turn_event(
    events: &Arc<Mutex<Vec<QueuedTurnEvent>>>,
    notify: &Arc<Notify>,
    attachment_epoch: u64,
    event: TurnEvent,
) {
    let mut guard = events
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.push(QueuedTurnEvent {
        attachment_epoch,
        event,
    });
    notify.notify_one();
}

pub(crate) fn drain_turn_events(events: &Arc<Mutex<Vec<QueuedTurnEvent>>>) -> Vec<QueuedTurnEvent> {
    let mut guard = events
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::mem::take(&mut *guard)
}

fn is_global_turn_event(event: &TurnEvent) -> bool {
    // Keep this aligned with `is_global_event` for protocol-derived turn
    // events. `InterruptDecision` is produced from `InterruptResolved` (which
    // is global); stamping it global again here would let a local
    // `push_incoming_turn_event` path bypass client-epoch filtering.
    matches!(
        event,
        TurnEvent::DaemonLinkReconnecting { .. }
            | TurnEvent::DaemonLinkReconnected { .. }
            | TurnEvent::DaemonLinkResynced { .. }
            | TurnEvent::DaemonLinkTerminal { .. }
            | TurnEvent::HostCapabilitiesChanged { .. }
            | TurnEvent::CaffeinateState { .. }
            | TurnEvent::DaemonDraining { .. }
            | TurnEvent::InterruptRaised { .. }
            | TurnEvent::InterruptResolved { .. }
            | TurnEvent::InterruptQueueChanged { .. }
    ) || {
        #[cfg(feature = "remote")]
        {
            matches!(event, TurnEvent::ConnectorStatus { .. })
        }
        #[cfg(not(feature = "remote"))]
        {
            false
        }
    }
}

fn push_incoming_turn_event(ctx: &IncomingEventContext<'_>, event: TurnEvent) {
    let attachment_epoch = if is_global_turn_event(&event) {
        GLOBAL_ATTACHMENT_EPOCH
    } else {
        ctx.client_epoch
    };
    push_turn_event(ctx.events, ctx.event_notify, attachment_epoch, event);
}

async fn dispatch_control_request_for_current_attachment<F, Fut>(
    control_request: ControlRequest,
    session_id_state: &Arc<Mutex<Uuid>>,
    attachment_epoch: &Arc<AtomicU64>,
    transition_gate: Arc<AsyncMutex<()>>,
    send: F,
) where
    F: FnOnce(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response, String>>,
{
    let _transition_guard = transition_gate.lock_owned().await;
    let current_session_id = *session_id_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let current_epoch = attachment_epoch.load(Ordering::Acquire);
    if control_request.intended_session_id != current_session_id
        || control_request.intended_attachment_epoch != current_epoch
    {
        let _ = control_request.response_tx.send(Err(
            "request belongs to a session attachment that has been replaced; retry".to_string(),
        ));
        return;
    }
    let response = send(control_request.request).await;
    let _ = control_request.response_tx.send(response);
}

async fn dispatch_attached_request_for_current_attachment<F, Fut>(
    attached_request: AttachedRequest,
    session_id_state: &Arc<Mutex<Uuid>>,
    attachment_epoch: &Arc<AtomicU64>,
    transition_gate: Arc<AsyncMutex<()>>,
    send: F,
) where
    F: FnOnce(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response, String>>,
{
    let _transition_guard = transition_gate.lock_owned().await;
    let current_session_id = *session_id_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let current_epoch = attachment_epoch.load(Ordering::Acquire);
    if attached_request.intended_session_id != current_session_id
        || attached_request.intended_attachment_epoch != current_epoch
    {
        let _ = attached_request.response_tx.send(Err(
            "request belongs to a session attachment that has been replaced; retry".to_string(),
        ));
        return;
    }
    let response = send(attached_request.request).await;
    let _ = attached_request.response_tx.send(response);
}

async fn dispatch_user_submission_for_current_attachment<F, Fut>(
    bound: BoundUserSubmission,
    session_id_state: &Arc<Mutex<Uuid>>,
    attachment_epoch: &Arc<AtomicU64>,
    transition_gate: Arc<AsyncMutex<()>>,
    send: F,
) -> UserSubmissionDispatchOutcome
where
    F: FnOnce(Uuid, u64, ClientUserSubmission) -> Fut,
    Fut: std::future::Future<Output = Result<(), UserSubmissionSendError>>,
{
    let transition_guard = transition_gate.lock_owned().await;
    let current_session_id = *session_id_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let current_epoch = attachment_epoch.load(Ordering::Acquire);
    if bound.intended_session_id != current_session_id {
        return UserSubmissionDispatchOutcome::StaleAttachment(Box::new(bound));
    }
    // Reconnecting the same session creates a fresh attachment epoch, but it
    // does not change the submission's destination. Dispatch under the
    // transition gate using the current client rather than dropping exact
    // image/tag/display/skill payloads accepted just before the reconnect.
    let _reattached_same_session = bound.intended_attachment_epoch != current_epoch;
    let optimistic_submission_id = bound.optimistic_submission_id;
    match send(
        optimistic_submission_id,
        bound.intended_attachment_epoch,
        bound.submission.clone(),
    )
    .await
    {
        Ok(()) => UserSubmissionDispatchOutcome::Delivered(Box::new(bound)),
        Err(UserSubmissionSendError::Rejected(error)) => UserSubmissionDispatchOutcome::Rejected {
            error,
            optimistic_submission_id,
            session_id: bound.intended_session_id,
            intended_attachment_epoch: bound.intended_attachment_epoch,
            transition_guard,
        },
        Err(UserSubmissionSendError::NotAccepted(error)) => {
            UserSubmissionDispatchOutcome::Retained {
                error,
                bound: Box::new(bound),
                transition_guard,
            }
        }
        Err(UserSubmissionSendError::Ambiguous(error)) => {
            UserSubmissionDispatchOutcome::Ambiguous {
                error,
                bound: Box::new(bound),
                transition_guard,
            }
        }
    }
}

fn record_user_submission_dispatch_outcome(
    outcome: UserSubmissionDispatchOutcome,
    events: &Arc<Mutex<Vec<QueuedTurnEvent>>>,
    event_notify: &Arc<Notify>,
    deferred: &mut HashMap<Uuid, VecDeque<BoundUserSubmission>>,
    retained: &mut HashMap<Uuid, VecDeque<BoundUserSubmission>>,
    awaiting_durable: &Arc<Mutex<HashMap<Uuid, VecDeque<BoundUserSubmission>>>>,
) -> Option<Uuid> {
    match outcome {
        UserSubmissionDispatchOutcome::Delivered(bound) => {
            let session_id = bound.intended_session_id;
            let mut awaiting = awaiting_durable
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let queue = awaiting.entry(session_id).or_default();
            queue.retain(|pending| {
                pending.optimistic_submission_id != bound.optimistic_submission_id
            });
            queue.push_back(*bound);
            return Some(session_id);
        }
        UserSubmissionDispatchOutcome::StaleAttachment(bound) => {
            let intended_session_id = bound.intended_session_id;
            let intended_attachment_epoch = bound.intended_attachment_epoch;
            deferred
                .entry(intended_session_id)
                .or_default()
                .push_back(*bound);
            push_turn_event(
                events,
                event_notify,
                intended_attachment_epoch,
                TurnEvent::Notice {
                    text: format!(
                        "A message accepted for session {} was retained and will be sent when that session is attached again.",
                        &intended_session_id.to_string()[..8]
                    ),
                },
            );
        }
        UserSubmissionDispatchOutcome::Rejected {
            error,
            optimistic_submission_id,
            session_id,
            intended_attachment_epoch,
            transition_guard,
        } => {
            push_turn_event(
                events,
                event_notify,
                intended_attachment_epoch,
                TurnEvent::UserMessageDispatchFailed {
                    error,
                    optimistic_submission_id,
                },
            );
            drop(transition_guard);
            return Some(session_id);
        }
        UserSubmissionDispatchOutcome::Retained {
            error,
            bound,
            transition_guard,
        } => {
            let optimistic_submission_id = bound.optimistic_submission_id;
            let intended_attachment_epoch = bound.intended_attachment_epoch;
            tracing::warn!(%error, client_submission_id = %optimistic_submission_id,
                "send_user_message was not accepted; retaining exact payload until a state-change retry");
            retained
                .entry(bound.intended_session_id)
                .or_default()
                .push_front(*bound);
            push_turn_event(
                events,
                event_notify,
                intended_attachment_epoch,
                TurnEvent::UserMessageDispatchRetained {
                    error,
                    optimistic_submission_id,
                },
            );
            drop(transition_guard);
        }
        UserSubmissionDispatchOutcome::Ambiguous {
            error,
            bound,
            transition_guard,
        } => {
            tracing::warn!(%error, client_submission_id = %bound.optimistic_submission_id,
                "send_user_message outcome ambiguous; retaining exact payload for idempotent retry");
            deferred
                .entry(bound.intended_session_id)
                .or_default()
                .push_back(*bound);
            drop(transition_guard);
        }
    }
    None
}

fn release_next_retained(
    retained: &mut HashMap<Uuid, VecDeque<BoundUserSubmission>>,
    session_id: Uuid,
) -> Option<BoundUserSubmission> {
    let queue = retained.get_mut(&session_id)?;
    let next = queue.pop_front();
    if queue.is_empty() {
        retained.remove(&session_id);
    }
    next
}

struct UserSubmissionDispatcherContext {
    session_id_state: Arc<Mutex<Uuid>>,
    attachment_epoch: Arc<AtomicU64>,
    transition_gate: Arc<AsyncMutex<()>>,
    events: Arc<Mutex<Vec<QueuedTurnEvent>>>,
    event_notify: Arc<Notify>,
    submission_session_rx: watch::Receiver<SubmissionSessionBinding>,
    attachment_ready_rx: mpsc::UnboundedReceiver<Uuid>,
    awaiting_durable: Arc<Mutex<HashMap<Uuid, VecDeque<BoundUserSubmission>>>>,
}

fn take_awaiting_durable_submissions(
    awaiting_durable: &Arc<Mutex<HashMap<Uuid, VecDeque<BoundUserSubmission>>>>,
    session_id: Uuid,
) -> VecDeque<BoundUserSubmission> {
    awaiting_durable
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&session_id)
        .unwrap_or_default()
}

fn acknowledge_durable_submissions(
    awaiting_durable: &Arc<Mutex<HashMap<Uuid, VecDeque<BoundUserSubmission>>>>,
    session_id: Uuid,
    ids: &[Uuid],
) {
    if ids.is_empty() {
        return;
    }
    let mut awaiting = awaiting_durable
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(queue) = awaiting.get_mut(&session_id) else {
        return;
    };
    queue.retain(|bound| !ids.contains(&bound.optimistic_submission_id));
    if queue.is_empty() {
        awaiting.remove(&session_id);
    }
}

fn push_restored_submission_event(
    bound: &BoundUserSubmission,
    events: &Arc<Mutex<Vec<QueuedTurnEvent>>>,
    event_notify: &Arc<Notify>,
) {
    push_turn_event(
        events,
        event_notify,
        bound.intended_attachment_epoch,
        TurnEvent::UserMessageDispatchRestored {
            optimistic_submission_id: bound.optimistic_submission_id,
            text: bound.submission.text.clone(),
            display_text: bound.submission.display_text.clone(),
            tag_expansions: bound.submission.tag_expansions.clone(),
        },
    );
}

async fn run_user_submission_dispatcher<F, Fut>(
    mut input_rx: mpsc::Receiver<RunnerInput>,
    mut context: UserSubmissionDispatcherContext,
    send: F,
) where
    F: Fn(Uuid, u64, ClientUserSubmission) -> Fut + Clone,
    Fut: std::future::Future<Output = Result<(), UserSubmissionSendError>>,
{
    enum DispatcherWake {
        Input(Option<RunnerInput>),
        AttachmentChanged,
        AttachmentReady(Option<Uuid>),
        RetryAmbiguous,
    }

    let mut deferred: HashMap<Uuid, VecDeque<BoundUserSubmission>> = HashMap::new();
    let mut retained: HashMap<Uuid, VecDeque<BoundUserSubmission>> = HashMap::new();
    let mut ready = VecDeque::new();
    let mut retry_ambiguous_at: Option<tokio::time::Instant> = None;
    loop {
        let input = if let Some(input) = ready.pop_front() {
            Some(input)
        } else {
            let wake = tokio::select! {
                input = input_rx.recv() => DispatcherWake::Input(input),
                changed = context.submission_session_rx.changed() => {
                    if changed.is_err() {
                        DispatcherWake::Input(input_rx.recv().await)
                    } else {
                        DispatcherWake::AttachmentChanged
                    }
                }
                session_id = context.attachment_ready_rx.recv() => {
                    DispatcherWake::AttachmentReady(session_id)
                }
                _ = async {
                    match retry_ambiguous_at {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                } => DispatcherWake::RetryAmbiguous,
            };
            match wake {
                DispatcherWake::Input(input) => input,
                DispatcherWake::AttachmentChanged => {
                    // This watch is updated only after App has applied the
                    // switch snapshot and replaced session_id_state. The
                    // binding carries the epoch published with that wake so
                    // delayed Notices are not re-stamped from the atomic.
                    let binding = *context.submission_session_rx.borrow_and_update();
                    let current_session_id = binding.session_id;
                    let awaiting = take_awaiting_durable_submissions(
                        &context.awaiting_durable,
                        current_session_id,
                    );
                    let mut released_ambiguous = !awaiting.is_empty();
                    ready.extend(
                        awaiting
                            .into_iter()
                            .map(|bound| RunnerInput::RetainedRetry(Box::new(bound))),
                    );
                    if let Some(recovered) = deferred.remove(&current_session_id) {
                        released_ambiguous = !recovered.is_empty();
                        ready.extend(
                            recovered
                                .into_iter()
                                .map(|bound| RunnerInput::RetainedRetry(Box::new(bound))),
                        );
                        push_turn_event(
                            &context.events,
                            &context.event_notify,
                            binding.attachment_epoch,
                            TurnEvent::Notice {
                                text: format!(
                                    "Sending retained message{} for reattached session {}.",
                                    if ready.len() == 1 { "" } else { "s" },
                                    &current_session_id.to_string()[..8]
                                ),
                            },
                        );
                    }
                    if !released_ambiguous
                        && let Some(recovered) =
                            release_next_retained(&mut retained, current_session_id)
                    {
                        ready.push_back(RunnerInput::RetainedRetry(Box::new(recovered)));
                    }
                    continue;
                }
                DispatcherWake::AttachmentReady(Some(current_session_id)) => {
                    let awaiting = take_awaiting_durable_submissions(
                        &context.awaiting_durable,
                        current_session_id,
                    );
                    ready.extend(
                        awaiting
                            .into_iter()
                            .map(|bound| RunnerInput::RetainedRetry(Box::new(bound))),
                    );
                    if let Some(recovered) = deferred.remove(&current_session_id) {
                        ready.extend(
                            recovered
                                .into_iter()
                                .map(|bound| RunnerInput::RetainedRetry(Box::new(bound))),
                        );
                    }
                    continue;
                }
                DispatcherWake::AttachmentReady(None) => continue,
                DispatcherWake::RetryAmbiguous => {
                    retry_ambiguous_at = None;
                    let current_session_id = context.submission_session_rx.borrow().session_id;
                    if let Some(recovered) = deferred.remove(&current_session_id) {
                        ready.extend(
                            recovered
                                .into_iter()
                                .map(|bound| RunnerInput::RetainedRetry(Box::new(bound))),
                        );
                    }
                    continue;
                }
            }
        };
        let Some(input) = input else {
            break;
        };
        let (bound, joins_retained, restoring) = match input {
            RunnerInput::Submission(bound) => (bound, true, false),
            RunnerInput::RetainedRetry(bound) => (bound, false, true),
            RunnerInput::SubmissionBatch(batch) => {
                ready.extend(
                    batch
                        .into_iter()
                        .map(|bound| RunnerInput::Submission(Box::new(bound))),
                );
                continue;
            }
            RunnerInput::Flush(flushed_tx) => {
                let _ = flushed_tx.send(());
                continue;
            }
        };
        if restoring {
            push_restored_submission_event(&bound, &context.events, &context.event_notify);
        }
        // Once an ambiguous A is retained, later B submissions for the same
        // session join its FIFO instead of overtaking it. Flush markers remain
        // processable, so a session switch cannot deadlock behind retries.
        if deferred.contains_key(&bound.intended_session_id) {
            deferred
                .entry(bound.intended_session_id)
                .or_default()
                .push_back(*bound);
            continue;
        }
        // A later send is an explicit retry opportunity for a deterministic
        // pre-acceptance rejection. Preserve FIFO: retained A is attempted
        // before the newly arrived B, and if A is rejected again B joins the
        // retained queue rather than overtaking it.
        if joins_retained && retained.contains_key(&bound.intended_session_id) {
            let session_id = bound.intended_session_id;
            retained.entry(session_id).or_default().push_back(*bound);
            let recovered = release_next_retained(&mut retained, session_id)
                .expect("retained queue contains the earlier submission");
            ready.push_front(RunnerInput::RetainedRetry(Box::new(recovered)));
            continue;
        }
        let send = send.clone();
        let outcome = dispatch_user_submission_for_current_attachment(
            *bound,
            &context.session_id_state,
            &context.attachment_epoch,
            context.transition_gate.clone(),
            send,
        )
        .await;
        let unblocked_session = record_user_submission_dispatch_outcome(
            outcome,
            &context.events,
            &context.event_notify,
            &mut deferred,
            &mut retained,
            &context.awaiting_durable,
        );
        if let Some(session_id) = unblocked_session
            && !deferred.contains_key(&session_id)
            && let Some(next) = release_next_retained(&mut retained, session_id)
        {
            ready.push_front(RunnerInput::RetainedRetry(Box::new(next)));
        }
        if !deferred.is_empty() && retry_ambiguous_at.is_none() {
            retry_ambiguous_at = Some(tokio::time::Instant::now() + Duration::from_millis(250));
        }
    }
}

async fn lock_current_client_epoch(
    transition_gate: Arc<AsyncMutex<()>>,
    client_epoch_rx: &watch::Receiver<u64>,
    expected_epoch: u64,
) -> Option<OwnedMutexGuard<()>> {
    let guard = transition_gate.lock_owned().await;
    (*client_epoch_rx.borrow() == expected_epoch).then_some(guard)
}

fn advance_attachment_epoch(context: &AttachRequestContext) -> u64 {
    let previous = context
        .attachment_epoch
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
            Some(epoch.saturating_add(1))
        })
        .expect("attachment epoch update is infallible");
    let next_epoch = previous.saturating_add(1);
    context.client_epoch_tx.send_replace(next_epoch);
    next_epoch
}

#[derive(Clone)]
pub(crate) struct AttachRequestContext {
    session_id: Option<Uuid>,
    project_root: String,
    no_sandbox: bool,
    session_entry_mode: proto::SessionEntryMode,
    env_snapshot: cockpit_proto::EnvSnapshotWire,
    transition_gate: Arc<AsyncMutex<()>>,
    client_epoch_tx: watch::Sender<u64>,
    attachment_epoch: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTarget {
    New,
    Resume {
        session_id: Uuid,
        since_seq: Option<i64>,
    },
}

#[derive(Debug)]
pub struct SessionSwitchOutcome {
    pub target: SessionTarget,
    pub session_id: Uuid,
    pub session_entry_mode: proto::SessionEntryMode,
    /// The lifecycle request replaced an ephemeral owner before this Attach.
    /// Presentation waits for the attached durable mode above.
    pub promoted_from_ephemeral: bool,
    pub short_id: String,
    pub active_agent: String,
    pub active_agent_path: Vec<String>,
    pub last_applied_seq: Option<i64>,
    pub foreground_target: Option<proto::QueueTarget>,
    pub active_model_state: Option<proto::ActiveModelState>,
    pub project_id: String,
    pub history: Vec<proto::HistoryEntry>,
    pub paused_work: Vec<proto::PausedWorkSummary>,
    pub repair_required: Option<proto::ResumeRepairState>,
    pub resume_compaction_offer: Option<proto::ResumeCompactionOffer>,
    pub btw_fork: Option<proto::BtwForkInfo>,
    pub daemon_version: String,
    pub daemon_compatible: bool,
    /// Attachment epoch published by `advance_attachment_epoch` when the
    /// replacement Attach succeeded. App adopts identity only when this
    /// matches the runner's authoritative current epoch.
    pub attachment_epoch: u64,
    /// Held from before the switch Attach request until App has drained all
    /// queued old-epoch events and applied this authoritative snapshot.
    pub(crate) transition_guard: Option<OwnedMutexGuard<()>>,
}

#[derive(Clone)]
struct LocalReconnectDriver {
    endpoint: ClientEndpoint,
}

impl LocalReconnectDriver {
    async fn connect(&self) -> Result<DaemonClient, anyhow::Error> {
        DaemonClient::connect_endpoint(&self.endpoint).await
    }
}

struct IncomingEventContext<'a> {
    session_id: Uuid,
    /// Epoch of the client that produced these events (captured when that
    /// client was selected). Not re-sampled from the atomic at enqueue time.
    client_epoch: u64,
    /// Authoritative current attachment epoch. Agent lifecycle bookkeeping
    /// updates only when `client_epoch` still matches this value.
    attachment_epoch: &'a Arc<AtomicU64>,
    events: &'a Arc<Mutex<Vec<QueuedTurnEvent>>>,
    event_notify: &'a Arc<Notify>,
    active_agent: &'a Arc<Mutex<String>>,
    active_agent_path: &'a Arc<Mutex<Vec<String>>>,
    primary_agent: &'a Arc<Mutex<String>>,
    last_applied_seq: &'a Arc<Mutex<Option<i64>>>,
    awaiting_durable: &'a Arc<Mutex<HashMap<Uuid, VecDeque<BoundUserSubmission>>>>,
}

struct ClientEventState {
    events: Arc<Mutex<Vec<QueuedTurnEvent>>>,
    event_notify: Arc<Notify>,
    active_agent: Arc<Mutex<String>>,
    active_agent_path: Arc<Mutex<Vec<String>>>,
    primary_agent: Arc<Mutex<String>>,
    last_applied_seq: Arc<Mutex<Option<i64>>>,
    attach_context: Arc<RwLock<AttachRequestContext>>,
    attachment_epoch: Arc<AtomicU64>,
    session_id_state: Arc<Mutex<Uuid>>,
    ephemeral_owner: Arc<AtomicBool>,
    skill_refresh_tx: watch::Sender<u64>,
    skill_refresh_generation: u64,
    transition_gate: Arc<AsyncMutex<()>>,
    awaiting_durable: Arc<Mutex<HashMap<Uuid, VecDeque<BoundUserSubmission>>>>,
    attachment_ready_tx: mpsc::UnboundedSender<Uuid>,
    /// Epoch of the currently selected client event stream.
    client_epoch: u64,
}

struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ReconnectBackoff<J = SystemJitter> {
    base: Duration,
    cap: Duration,
    current: Duration,
    jitter: J,
}

struct ReconnectAttach {
    client: DaemonClient,
    session_entry_mode: proto::SessionEntryMode,
    history: Vec<proto::HistoryEntry>,
    paused_work: Vec<proto::PausedWorkSummary>,
    repair_required: Option<proto::ResumeRepairState>,
    active_model_state: Option<proto::ActiveModelState>,
}

struct AttachedPayload {
    session_entry_mode: proto::SessionEntryMode,
    history: Vec<proto::HistoryEntry>,
    paused_work: Vec<proto::PausedWorkSummary>,
    repair_required: Option<proto::ResumeRepairState>,
    active_model_state: Option<proto::ActiveModelState>,
}

enum ReconnectAttachError {
    Retriable(anyhow::Error),
    Terminal(String),
}

impl ReconnectBackoff<SystemJitter> {
    fn new() -> Self {
        Self::with_jitter(SystemJitter)
    }
}

impl<J: JitterSource> ReconnectBackoff<J> {
    fn with_jitter(jitter: J) -> Self {
        let base = Duration::from_millis(500);
        Self {
            base,
            cap: Duration::from_secs(30),
            current: base,
            jitter,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let jitter = self.jitter.duration_up_to(self.current);
        let delay = self.base.saturating_add(jitter).min(self.cap);
        self.current = self.current.saturating_mul(2).min(self.cap);
        delay
    }
}

fn history_entry_seq(entry: &proto::HistoryEntry) -> Option<i64> {
    match entry {
        proto::HistoryEntry::InterruptDecision { seq, .. }
        | proto::HistoryEntry::User { seq, .. }
        | proto::HistoryEntry::UserNote { seq, .. }
        | proto::HistoryEntry::Assistant { seq, .. }
        | proto::HistoryEntry::ToolCall { seq, .. }
        | proto::HistoryEntry::InferenceError { seq, .. }
        | proto::HistoryEntry::CompactBoundary { seq, .. }
        | proto::HistoryEntry::Subagent { seq, .. } => (*seq > 0).then_some(*seq),
    }
}

fn event_persisted_seq(event: &proto::Event) -> Option<i64> {
    match event {
        proto::Event::AssistantText { seq, .. }
        | proto::Event::AssistantDisplayComplete { seq, .. }
        | proto::Event::QueuedUserMessagesFolded { seq, .. }
        | proto::Event::InterruptResolved { seq, .. }
        | proto::Event::ToolEnd { seq, .. }
        | proto::Event::ToolError { seq, .. } => *seq,
        proto::Event::UserMessageRecorded { seq, .. } => Some(*seq),
        proto::Event::HistoryReplay { max_seq, .. } => Some(*max_seq),
        // `AgentTreeChanged` is a durable tree invalidation, but this
        // terminal renderer has no tree projection yet.  It therefore has no
        // transcript effect and must not advance the transcript replay cursor:
        // a higher tree event arriving before a lower transcript event would
        // otherwise make reconnect/live forwarding drop that transcript row.
        proto::Event::AgentTreeChanged { .. } => None,
        _ => None,
    }
}

fn update_last_applied_seq(last_applied_seq: &Arc<Mutex<Option<i64>>>, seq: i64) {
    let mut guard = last_applied_seq
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none_or(|last| seq > last) {
        *guard = Some(seq);
    }
}

fn current_last_applied_seq(last_applied_seq: &Arc<Mutex<Option<i64>>>) -> Option<i64> {
    *last_applied_seq
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn run_skill_inventory_refresh(
    current_client: Arc<RwLock<DaemonClient>>,
    attach_context: Arc<RwLock<AttachRequestContext>>,
    session_id_state: Arc<Mutex<Uuid>>,
    active_agent: Arc<Mutex<String>>,
    skill_inventory_names: Arc<Mutex<Option<std::collections::HashSet<String>>>>,
    refresh_rx: watch::Receiver<u64>,
) {
    run_skill_inventory_refresh_with_request(
        attach_context,
        session_id_state,
        active_agent,
        skill_inventory_names,
        refresh_rx,
        move |project_root, session_id, selected_agent| {
            let current_client = current_client.clone();
            async move {
                let client = current_client.read().await.clone();
                // Inventory is one of the reads the daemon refuses with
                // `RetryLater` while a workspace-trust reconciliation holds a
                // session's admission gate; the same bounded client retry
                // applies as on the attached-request path.
                client
                    .request_ok_retrying_transient(Request::GetInventoryBundle {
                        project_root,
                        session_id,
                        selected_agent,
                    })
                    .await
            }
        },
    )
    .await;
}

async fn run_skill_inventory_refresh_with_request<F, Fut>(
    attach_context: Arc<RwLock<AttachRequestContext>>,
    session_id_state: Arc<Mutex<Uuid>>,
    active_agent: Arc<Mutex<String>>,
    skill_inventory_names: Arc<Mutex<Option<std::collections::HashSet<String>>>>,
    mut refresh_rx: watch::Receiver<u64>,
    mut request_skills: F,
) where
    F: FnMut(String, Uuid, String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<Response>>,
{
    while refresh_rx.changed().await.is_ok() {
        let project_root = attach_context.read().await.project_root.clone();
        let session_id = *session_id_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let selected_agent = active_agent
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        match request_skills(project_root, session_id, selected_agent).await {
            Ok(Response::InventoryBundle { skills, .. }) => {
                let names = skills
                    .into_iter()
                    .map(|skill| skill.name)
                    .collect::<std::collections::HashSet<_>>();
                *skill_inventory_names
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(names);
            }
            Ok(other) => {
                tracing::debug!(?other, "get_inventory_bundle returned unexpected response");
            }
            Err(error) => {
                tracing::debug!(error = ?error, "skill inventory refresh failed");
            }
        }
    }
}

fn spawn_skill_inventory_refresh_task(
    client_tasks: &mut ClientTasks,
    current_client: Arc<RwLock<DaemonClient>>,
    attach_context: Arc<RwLock<AttachRequestContext>>,
    session_id_state: Arc<Mutex<Uuid>>,
    active_agent: Arc<Mutex<String>>,
    skill_inventory_names: Arc<Mutex<Option<std::collections::HashSet<String>>>>,
) -> (watch::Sender<u64>, AbortHandle) {
    let (refresh_tx, refresh_rx) = watch::channel(0);
    let handle = tokio::spawn(run_skill_inventory_refresh(
        current_client,
        attach_context,
        session_id_state,
        active_agent,
        skill_inventory_names,
        refresh_rx,
    ));
    let abort_handle = handle.abort_handle();
    client_tasks.push(handle);
    (refresh_tx, abort_handle)
}

impl ClientEventState {
    fn session_id(&self) -> Uuid {
        *self
            .session_id_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn incoming_context(&self, session_id: Uuid) -> IncomingEventContext<'_> {
        IncomingEventContext {
            session_id,
            client_epoch: self.client_epoch,
            attachment_epoch: &self.attachment_epoch,
            events: &self.events,
            event_notify: &self.event_notify,
            active_agent: &self.active_agent,
            active_agent_path: &self.active_agent_path,
            primary_agent: &self.primary_agent,
            last_applied_seq: &self.last_applied_seq,
            awaiting_durable: &self.awaiting_durable,
        }
    }

    fn trigger_skill_refresh(&mut self) {
        self.skill_refresh_generation = self.skill_refresh_generation.wrapping_add(1);
        self.skill_refresh_tx
            .send_replace(self.skill_refresh_generation);
    }

    fn handle_regular_event(&mut self, event: proto::Event) {
        apply_daemon_lifetime_event(&event, &self.ephemeral_owner);
        if should_refresh_skill_inventory(&event) {
            self.trigger_skill_refresh();
        }
        let session_id = self.session_id();
        let incoming = self.incoming_context(session_id);
        apply_incoming_event(event, &incoming);
    }

    async fn handle_event_with_resync<F, Fut>(&mut self, event: proto::Event, resync: F) -> bool
    where
        F: FnOnce(Uuid, AttachRequestContext, Arc<Mutex<Option<i64>>>) -> Fut,
        Fut: std::future::Future<Output = Result<AttachedPayload, ReconnectAttachError>>,
    {
        if let proto::Event::EventStreamLagged {
            session_id: lag_session_id,
            dropped,
        } = event
        {
            return self.handle_lag_event(lag_session_id, dropped, resync).await;
        }

        self.handle_regular_event(event);
        true
    }

    async fn handle_lag_event<F, Fut>(
        &mut self,
        lag_session_id: Option<Uuid>,
        dropped: u64,
        resync: F,
    ) -> bool
    where
        F: FnOnce(Uuid, AttachRequestContext, Arc<Mutex<Option<i64>>>) -> Fut,
        Fut: std::future::Future<Output = Result<AttachedPayload, ReconnectAttachError>>,
    {
        let attach_snapshot = self.attach_context.read().await.clone();
        let Some(session_id) = attach_snapshot.session_id else {
            return false;
        };
        if lag_session_id.is_some_and(|lag_session_id| lag_session_id != session_id) {
            return true;
        }
        match resync(
            session_id,
            attach_snapshot.clone(),
            self.last_applied_seq.clone(),
        )
        .await
        {
            Ok(attached) => {
                // A successful re-attach is a new isolation epoch even when
                // the daemon and session id are unchanged. Advance before
                // exposing its authoritative snapshot so all old queued
                // outbound work is rejected when this transition gate opens.
                self.client_epoch = advance_attachment_epoch(&attach_snapshot);
                let incoming = self.incoming_context(session_id);
                let active_model_state = apply_attached_payload(attached, &incoming);
                let _ = self.attachment_ready_tx.send(session_id);
                push_turn_event(
                    &self.events,
                    &self.event_notify,
                    GLOBAL_ATTACHMENT_EPOCH,
                    TurnEvent::DaemonLinkResynced { active_model_state },
                );
            }
            Err(ReconnectAttachError::Retriable(error)) => {
                tracing::debug!(
                    error = ?error,
                    dropped,
                    "daemon event stream lag resync failed"
                );
            }
            Err(ReconnectAttachError::Terminal(error)) => {
                tracing::warn!(%error, "daemon event stream lag resync stopped");
                push_turn_event(
                    &self.events,
                    &self.event_notify,
                    GLOBAL_ATTACHMENT_EPOCH,
                    TurnEvent::DaemonLinkTerminal { error },
                );
                return false;
            }
        }
        true
    }
}

fn apply_daemon_lifetime_event(event: &proto::Event, ephemeral_owner: &AtomicBool) {
    if let proto::Event::DaemonLifetimeChanged {
        ephemeral_owner: value,
    } = event
    {
        ephemeral_owner.store(*value, Ordering::Release);
    }
}

fn should_refresh_skill_inventory(event: &proto::Event) -> bool {
    matches!(
        event,
        proto::Event::PrimarySwapped { .. }
            | proto::Event::ForegroundInputTarget { .. }
            | proto::Event::AgentIdle { .. }
    )
}

async fn switch_session_inner(
    current_client: Arc<RwLock<DaemonClient>>,
    attach_context: Arc<RwLock<AttachRequestContext>>,
    session_id_state: Arc<Mutex<Uuid>>,
    endpoint: ClientEndpoint,
    lifecycle: LifecycleClient,
    target: SessionTarget,
    cancel_outgoing_turn_after_attach: bool,
) -> Result<SessionSwitchOutcome, String> {
    // A successful Attach starts a new event epoch even when it resumes the
    // same session id. Adopt a fresh client so the old connection cannot feed
    // pre-Attach events into the new epoch.
    let outgoing_client = current_client.read().await.clone();
    let (endpoint, promoted_from_ephemeral) = match target {
        SessionTarget::Resume { .. } => {
            let resolution = lifecycle
                .resolve(LifecycleIntent::PromoteToPersistent)
                .await
                .map_err(|error| format!("daemon lifecycle: {error}"))?;
            (resolution.endpoint, resolution.promoted_from_ephemeral)
        }
        SessionTarget::New => (endpoint, false),
    };
    let replacement_client = DaemonClient::connect_endpoint(&endpoint)
        .await
        .map_err(|error| format!("connect replacement session client: {error:#}"))?;
    let client_protocol_version = replacement_client.negotiated().version;
    let request_client = replacement_client.clone();
    let mut outcome = switch_session_with_attach_request(
        attach_context.clone(),
        target,
        client_protocol_version,
        move |request| async move { request_client.request(request).await },
    )
    .await?;
    outcome.promoted_from_ephemeral = promoted_from_ephemeral;
    cancel_outgoing_turn_after_successful_attach(
        cancel_outgoing_turn_after_attach,
        move || async move { outgoing_client.request(Request::CancelTurn).await },
    )
    .await;
    // The Attach helper has already installed the daemon-returned id+mode
    // under one context write lock. Publish the synchronous submission id
    // before replacing the client/epoch, so reconnect cannot pair the new
    // mode with the old id while the App awaits its switch outcome.
    *session_id_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = outcome.session_id;
    *current_client.write().await = replacement_client;
    let context = attach_context.read().await;
    let attachment_epoch = advance_attachment_epoch(&context);
    drop(context);
    let mut outcome = outcome;
    outcome.attachment_epoch = attachment_epoch;
    Ok(outcome)
}

async fn cancel_outgoing_turn_after_successful_attach<F, Fut>(requested: bool, send: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<std::result::Result<Response, ErrorPayload>>>,
{
    if !requested {
        return;
    }
    match send().await {
        Ok(Ok(Response::Ack)) => {}
        Ok(Ok(other)) => {
            tracing::warn!(
                ?other,
                "unexpected response cancelling outgoing /new session turn"
            );
        }
        Ok(Err(error)) => {
            tracing::warn!(
                ?error,
                "daemon rejected outgoing /new session turn cancellation"
            );
        }
        Err(error) => {
            tracing::warn!(%error, "could not cancel outgoing /new session turn after replacement attach");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn first_party_session_attach_request(
    session_id: Option<Uuid>,
    since_seq: Option<i64>,
    project_root: String,
    initial_model: Option<cockpit_config::providers::ActiveModelRef>,
    no_sandbox: bool,
    entry_mode: proto::SessionEntryMode,
    model_override: Option<cockpit_config::providers::ActiveModelRef>,
    client_protocol_version: u32,
    env_snapshot: Option<proto::EnvSnapshotWire>,
) -> Request {
    if entry_mode == proto::SessionEntryMode::Code {
        return match session_id {
            Some(session_id) => proto::attach_existing_code_root_v1_request(
                session_id,
                since_seq,
                initial_model,
                no_sandbox,
                true,
                model_override,
                client_protocol_version,
                env_snapshot,
                cockpit_proto::EnvDriftPolicy::Client,
            ),
            None => proto::create_code_root_v1_request(
                project_root,
                initial_model,
                no_sandbox,
                true,
                model_override,
                client_protocol_version,
                env_snapshot,
                cockpit_proto::EnvDriftPolicy::Client,
            ),
        };
    }
    Request::Attach {
        session_id,
        since_seq,
        project_root: Some(project_root),
        initial_model,
        no_sandbox,
        interactive: true,
        session_entry_mode: proto::NonCodeSessionEntryMode::try_from(entry_mode)
            .expect("Code handled above"),
        model_override,
        client_protocol_version,
        env_snapshot,
        env_policy: cockpit_proto::EnvDriftPolicy::Client,
    }
}

async fn switch_session_with_attach_request<F, Fut>(
    attach_context: Arc<RwLock<AttachRequestContext>>,
    target: SessionTarget,
    client_protocol_version: u32,
    send_request: F,
) -> Result<SessionSwitchOutcome, String>
where
    F: FnOnce(Request) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<std::result::Result<Response, ErrorPayload>>>,
{
    let ctx = attach_context.read().await.clone();
    let requested_target = target;
    let (target_session_id, since_seq) = match target {
        SessionTarget::New => (None, None),
        SessionTarget::Resume {
            session_id,
            since_seq,
        } => (Some(session_id), since_seq),
    };
    let request = first_party_session_attach_request(
        target_session_id,
        since_seq,
        ctx.project_root.clone(),
        None,
        ctx.no_sandbox,
        ctx.session_entry_mode,
        None,
        client_protocol_version,
        Some(ctx.env_snapshot.clone()),
    );
    let response = send_request(request)
        .await
        .map_err(|e| format!("attach: {e}"))?;
    let outcome = match response.map(Response::into_first_party_attached) {
        Ok(Response::Attached {
            session_id,
            short_id,
            active_agent: new_active_agent,
            active_agent_path: new_active_agent_path,
            foreground_target,
            active_model_state,
            session_entry_mode,
            project_id,
            history,
            paused_work,
            repair_required,
            resume_compaction_offer,
            btw_fork,
            daemon_version,
            compatible,
            ..
        }) => {
            if target_session_id.is_none() && session_entry_mode != ctx.session_entry_mode {
                return Err(format!(
                    "daemon returned mismatched new-session entry mode: requested {}, received {}",
                    ctx.session_entry_mode.as_str(),
                    session_entry_mode.as_str(),
                ));
            }
            Ok(session_switch_outcome_from_attached(
                SessionSwitchAttached {
                    session_id,
                    short_id,
                    active_agent: new_active_agent,
                    active_agent_path: new_active_agent_path,
                    foreground_target,
                    active_model_state,
                    session_entry_mode,
                    project_id,
                    history,
                    paused_work,
                    repair_required: repair_required.map(|repair| *repair),
                    resume_compaction_offer,
                    btw_fork,
                    daemon_version,
                    daemon_compatible: compatible,
                },
                requested_target,
            ))
        }
        Ok(other) => Err(format!("unexpected attach response: {other:?}")),
        Err(error) if error.code == ErrorCode::ProtocolVersion => {
            Err(incompatible_protocol_chip().to_string())
        }
        Err(error) => Err(format!("attach: daemon error: {error}")),
    }?;
    // The daemon owns both values. One write keeps reconnect from observing
    // a new session id paired with the previous session's mode.
    let mut context = attach_context.write().await;
    context.session_id = Some(outcome.session_id);
    context.session_entry_mode = outcome.session_entry_mode;
    drop(context);
    Ok(outcome)
}

struct SessionSwitchAttached {
    session_id: Uuid,
    short_id: String,
    active_agent: String,
    active_agent_path: Vec<String>,
    foreground_target: Option<proto::QueueTarget>,
    active_model_state: Option<proto::ActiveModelState>,
    session_entry_mode: proto::SessionEntryMode,
    project_id: String,
    history: Vec<proto::HistoryEntry>,
    paused_work: Vec<proto::PausedWorkSummary>,
    repair_required: Option<proto::ResumeRepairState>,
    resume_compaction_offer: Option<proto::ResumeCompactionOffer>,
    btw_fork: Option<proto::BtwForkInfo>,
    daemon_version: String,
    daemon_compatible: bool,
}

fn session_switch_outcome_from_attached(
    attached: SessionSwitchAttached,
    target: SessionTarget,
) -> SessionSwitchOutcome {
    let active_agent_path = if attached.active_agent_path.is_empty() {
        vec![attached.active_agent.clone()]
    } else {
        attached.active_agent_path
    };
    let last_applied_seq = attached.history.iter().filter_map(history_entry_seq).max();
    SessionSwitchOutcome {
        target,
        session_id: attached.session_id,
        session_entry_mode: attached.session_entry_mode,
        promoted_from_ephemeral: false,
        short_id: attached.short_id,
        active_agent: attached.active_agent,
        active_agent_path,
        last_applied_seq,
        foreground_target: attached.foreground_target.map(queue_target_from_proto),
        active_model_state: attached.active_model_state,
        project_id: attached.project_id,
        history: attached.history,
        paused_work: attached.paused_work,
        repair_required: attached.repair_required,
        resume_compaction_offer: attached.resume_compaction_offer,
        btw_fork: attached.btw_fork,
        daemon_version: attached.daemon_version,
        daemon_compatible: attached.daemon_compatible,
        attachment_epoch: 0,
        transition_guard: None,
    }
}

fn apply_session_switch_state(
    outcome: &SessionSwitchOutcome,
    session_id_state: &Arc<Mutex<Uuid>>,
    last_applied_seq: &Arc<Mutex<Option<i64>>>,
    active_agent: &Arc<Mutex<String>>,
    active_agent_path: &Arc<Mutex<Vec<String>>>,
) {
    *active_agent
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = outcome.active_agent.clone();
    *active_agent_path
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = outcome.active_agent_path.clone();
    *last_applied_seq
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = outcome.last_applied_seq;
    *session_id_state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = outcome.session_id;
}

fn is_global_event(event: &proto::Event) -> bool {
    matches!(
        event,
        proto::Event::CaffeinateState { .. }
            | proto::Event::DaemonDraining { .. }
            | proto::Event::DaemonLifetimeChanged { .. }
            | proto::Event::LspNotice { .. }
            | proto::Event::EnvDriftWarning { .. }
            | proto::Event::InterruptRaised { .. }
            | proto::Event::InterruptResolved { .. }
            | proto::Event::InterruptQueueChanged { .. }
            | proto::Event::HostCapabilitiesChanged { .. }
            | proto::Event::ImageControlConfigChanged { .. }
    ) || {
        #[cfg(feature = "remote")]
        {
            matches!(event, proto::Event::ConnectorStatus { .. })
        }
        #[cfg(not(feature = "remote"))]
        {
            false
        }
    }
}

impl Drop for AgentRunner {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Probe for the daemon (auto-promoting one if needed), attach a
/// fresh session at `cwd`, and return the runner handle.
///
/// Returns `Err(String)` instead of `anyhow::Error` so `app.rs` can
/// render the message in its fallback "input captured" stub without
/// having to format an anyhow chain.
pub async fn try_spawn(
    cwd: &Path,
    no_sandbox: bool,
    lifecycle: LifecycleClient,
    intent: LifecycleIntent,
) -> Result<AgentRunner, String> {
    try_spawn_inner(
        cwd,
        None,
        None,
        Some(proto::SessionEntryMode::Code),
        no_sandbox,
        lifecycle,
        intent,
    )
    .await
}

/// Attach a fresh or model-less existing session seeded with the complete
/// selection accepted by the picker. An existing durable selection is never
/// overwritten during attach; the correlated SetActiveModel request does that.
pub async fn try_spawn_with_model(
    cwd: &Path,
    session_id: Option<uuid::Uuid>,
    initial_model: cockpit_config::providers::ActiveModelRef,
    no_sandbox: bool,
    lifecycle: LifecycleClient,
    intent: LifecycleIntent,
) -> Result<AgentRunner, String> {
    try_spawn_with_model_and_entry_mode(
        cwd,
        session_id,
        initial_model,
        no_sandbox,
        lifecycle,
        intent,
        session_id
            .is_none()
            .then_some(proto::SessionEntryMode::Code),
    )
    .await
}

/// Same as [`try_spawn_with_model`], but the caller supplies the new-session
/// entry mode. Resume/existing attaches must pass `None`.
pub async fn try_spawn_with_model_and_entry_mode(
    cwd: &Path,
    session_id: Option<uuid::Uuid>,
    initial_model: cockpit_config::providers::ActiveModelRef,
    no_sandbox: bool,
    lifecycle: LifecycleClient,
    intent: LifecycleIntent,
    requested_session_entry_mode: Option<proto::SessionEntryMode>,
) -> Result<AgentRunner, String> {
    try_spawn_inner(
        cwd,
        session_id,
        Some(initial_model),
        requested_session_entry_mode,
        no_sandbox,
        lifecycle,
        intent,
    )
    .await
}

/// Re-attach to an existing session by id (the `/compact` commit path,
/// T6.e). Same as [`try_spawn`] but resumes `session_id` instead of
/// creating a fresh one, so the TUI switches its event stream + input
/// channel onto the new compaction-handoff session. `no_sandbox` is
/// ignored by the daemon on resume (the session keeps its own state),
/// passed only to keep the attach shape uniform.
pub async fn attach_to_session(
    cwd: &Path,
    session_id: uuid::Uuid,
    no_sandbox: bool,
    lifecycle: LifecycleClient,
    intent: LifecycleIntent,
) -> Result<AgentRunner, String> {
    try_spawn_inner(
        cwd,
        Some(session_id),
        None,
        None,
        no_sandbox,
        lifecycle,
        intent,
    )
    .await
}

fn root_model_override_for_attach(
    session_id: Option<uuid::Uuid>,
    initial_model: &Option<cockpit_config::providers::ActiveModelRef>,
) -> Option<cockpit_config::providers::ActiveModelRef> {
    session_id
        .is_none()
        .then(|| initial_model.clone())
        .flatten()
}

async fn try_spawn_inner(
    cwd: &Path,
    session_id: Option<uuid::Uuid>,
    initial_model: Option<cockpit_config::providers::ActiveModelRef>,
    requested_session_entry_mode: Option<proto::SessionEntryMode>,
    no_sandbox: bool,
    lifecycle: LifecycleClient,
    intent: LifecycleIntent,
) -> Result<AgentRunner, String> {
    // A picker choice made before the first runner exists is an explicit root
    // selection, not merely seed data for a model-less session. Carry the same
    // complete selection in the root-override field so installed vNext launch
    // preparation preserves it and the root factory validates it against the
    // prepared primary-slot routes (or takes the derived-definition path).
    // Resume never accepts this authority: an existing session remains owned
    // by its durable active-model selection.
    let root_model_override = root_model_override_for_attach(session_id, &initial_model);
    let attached = {
        let mut timer = cockpit_core::startup::PhaseTimer::start("agent_runner::try_spawn");
        // A session id is durable but mode-blind at this boundary. Resolve all
        // generic resumes through the persistent policy; Code and Computer
        // remain valid there, while Assistant cannot attach to an ephemeral
        // owner before its durable mode is loaded by the daemon.
        let lifecycle_intent = if session_id.is_some() {
            LifecycleIntent::PromoteToPersistent
        } else {
            intent
        };
        let daemon = lifecycle.resolve(lifecycle_intent).await?;
        timer.phase("resolve_lifecycle");
        let owns_daemon = daemon.owns_daemon;
        let ephemeral_owner = daemon.ephemeral_owner;
        let socket = daemon.socket.clone();
        let startup_notice = daemon.startup_notice.clone();
        let promoted_from_ephemeral = daemon.promoted_from_ephemeral;
        let endpoint = daemon.endpoint;
        let client = DaemonClient::connect_endpoint(&endpoint)
            .await
            .map_err(|error| format!("daemon connect: {error}"))?;
        let project_root = cwd.to_string_lossy().into_owned();
        let (env_snapshot, _env_diagnostic) = cockpit_core::env_snapshot::capture_tui_shell_env();
        let entry_mode = requested_session_entry_mode.unwrap_or(proto::SessionEntryMode::Code);
        let request = first_party_session_attach_request(
            session_id,
            None,
            project_root,
            initial_model,
            no_sandbox,
            entry_mode,
            root_model_override,
            client.negotiated().version,
            Some(env_snapshot.to_wire()),
        );
        let attached = match client.request(request).await {
            Ok(Ok(response)) => response.into_first_party_attached(),
            Ok(Err(error)) if error.code == ErrorCode::ProtocolVersion => {
                return Err(incompatible_protocol_chip().to_string());
            }
            Ok(Err(error)) => return Err(format!("attach: daemon error: {error}")),
            Err(e) => return Err(format!("attach: {e}")),
        };
        let (
            session_id,
            short_id,
            active_agent_name,
            active_agent_path,
            foreground_target,
            active_model_state,
            session_entry_mode,
            project_id,
            history,
            paused_work,
            repair_required,
            resume_compaction_offer,
            btw_fork,
            daemon_version,
            daemon_compatible,
        ) = match attached {
            Response::Attached {
                session_id,
                short_id,
                active_agent,
                active_agent_path,
                foreground_target,
                active_model_state,
                session_entry_mode,
                project_id,
                history,
                paused_work,
                repair_required,
                resume_compaction_offer,
                btw_fork,
                daemon_version,
                compatible,
                ..
            } => (
                session_id,
                short_id,
                active_agent,
                active_agent_path,
                foreground_target,
                active_model_state,
                session_entry_mode,
                project_id,
                history,
                paused_work,
                repair_required.map(|repair| *repair),
                resume_compaction_offer,
                btw_fork,
                daemon_version,
                compatible,
            ),
            other => return Err(format!("unexpected attach response: {other:?}")),
        };
        if let Some(requested_mode) = requested_session_entry_mode
            && session_entry_mode != requested_mode
        {
            return Err(format!(
                "daemon returned mismatched new-session entry mode: requested {}, received {}",
                requested_mode.as_str(),
                session_entry_mode.as_str(),
            ));
        }
        let assistant_promotion_notice =
            promoted_from_ephemeral && session_entry_mode == proto::SessionEntryMode::Assistant;
        // Fetch the autocomplete frequency maps for this session's
        // project. Best-effort: a daemon that doesn't speak
        // `GetUsageCounts` just leaves the maps empty (no ranking).
        let usage = match client
            .request_ok(Request::GetUsageCounts {
                project_id: Some(project_id.clone()),
            })
            .await
        {
            Ok(Response::UsageCounts {
                models,
                slash,
                tags,
            }) => UsageCounts {
                models,
                slash,
                tags,
            },
            _ => UsageCounts::default(),
        };
        let skill_inventory_names = match client
            .request_ok_retrying_transient(Request::GetInventoryBundle {
                project_root: cwd.to_string_lossy().into_owned(),
                session_id,
                selected_agent: active_agent_name.clone(),
            })
            .await
        {
            Ok(Response::InventoryBundle { skills, .. }) => Some(
                skills
                    .into_iter()
                    .map(|skill| skill.name)
                    .collect::<std::collections::HashSet<_>>(),
            ),
            _ => None,
        };
        timer.phase("attach_and_usage");
        timer.done();
        Ok::<_, String>((
            client,
            endpoint,
            lifecycle,
            session_id,
            short_id,
            active_agent_name,
            active_agent_path,
            foreground_target,
            active_model_state,
            session_entry_mode,
            project_id,
            usage,
            skill_inventory_names,
            owns_daemon,
            ephemeral_owner,
            socket,
            startup_notice,
            assistant_promotion_notice,
            history,
            paused_work,
            repair_required,
            resume_compaction_offer,
            btw_fork,
            daemon_version,
            daemon_compatible,
        ))
    }?;
    let (
        client,
        endpoint,
        lifecycle,
        session_id,
        short_id,
        initial_active_agent,
        active_agent_path,
        foreground_target,
        active_model_state,
        session_entry_mode,
        project_id,
        usage,
        initial_skill_names,
        owns_daemon,
        ephemeral_owner,
        socket,
        startup_notice,
        assistant_promotion_notice,
        history,
        paused_work,
        repair_required,
        resume_compaction_offer,
        btw_fork,
        daemon_version,
        daemon_compatible,
    ) = attached;

    let ephemeral_owner = Arc::new(AtomicBool::new(ephemeral_owner));

    let (input_tx, input_rx) = mpsc::channel::<RunnerInput>(32);
    let (record_tx, mut record_rx) = mpsc::channel::<Request>(32);
    let (control_tx, mut control_rx) = mpsc::channel::<ControlRequest>(32);
    let (attached_request_tx, mut attached_request_rx) = mpsc::channel::<AttachedRequest>(32);
    let events = Arc::new(Mutex::new(Vec::new()));
    if let Some(text) = startup_notice {
        events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: 0,
            event: TurnEvent::Notice { text },
        });
    }
    if assistant_promotion_notice {
        events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: 0,
            event: TurnEvent::Notice {
                text: cockpit_core::daemon::client::ASSISTANT_PERSISTENCE_NOTICE.to_string(),
            },
        });
    }
    let event_notify = Arc::new(Notify::new());
    let initial_active_agent_path = if active_agent_path.is_empty() {
        vec![initial_active_agent.clone()]
    } else {
        active_agent_path
    };
    let active_agent = Arc::new(Mutex::new(initial_active_agent));
    let active_agent_path = Arc::new(Mutex::new(initial_active_agent_path));
    let skill_inventory_names = Arc::new(Mutex::new(initial_skill_names));
    let last_applied_seq = Arc::new(Mutex::new(
        history.iter().filter_map(history_entry_seq).max(),
    ));
    let session_id_state = Arc::new(Mutex::new(session_id));
    let current_client = Arc::new(RwLock::new(client));
    let transition_gate = Arc::new(AsyncMutex::new(()));
    let attachment_epoch = Arc::new(AtomicU64::new(0));
    let (submission_session_tx, submission_session_rx) =
        watch::channel(SubmissionSessionBinding::new(session_id, 0));
    let awaiting_durable = Arc::new(Mutex::new(HashMap::new()));
    let local_message_operation_ids = Arc::new(Mutex::new(HashMap::<Uuid, Uuid>::new()));
    let local_message_attachments = Arc::new(Mutex::new(HashMap::<
        Uuid,
        Vec<cockpit_proto::send_user_message_v2::MessageAttachmentIdentity>,
    >::new()));
    let (attachment_ready_tx, attachment_ready_rx) = mpsc::unbounded_channel();
    let (client_epoch_tx, mut client_epoch_rx) = watch::channel(0_u64);
    let attach_context = Arc::new(RwLock::new(AttachRequestContext {
        session_id: Some(session_id),
        project_root: cwd.to_string_lossy().into_owned(),
        no_sandbox,
        session_entry_mode,
        env_snapshot: cockpit_core::env_snapshot::capture_tui_shell_env()
            .0
            .to_wire(),
        transition_gate: transition_gate.clone(),
        client_epoch_tx,
        attachment_epoch: attachment_epoch.clone(),
    }));
    let mut client_tasks = ClientTasks::default();

    // Outbound: upload durable image identities, then send the strict V2
    // command. Ambiguous retries reuse the exact operation and attachment set.
    {
        let current_client = current_client.clone();
        let session_id_state = session_id_state.clone();
        let attachment_epoch = attachment_epoch.clone();
        let transition_gate = transition_gate.clone();
        let events = events.clone();
        let event_notify = event_notify.clone();
        let local_message_operation_ids = local_message_operation_ids.clone();
        let local_message_attachments = local_message_attachments.clone();
        client_tasks.push(tokio::spawn(run_user_submission_dispatcher(
            input_rx,
            UserSubmissionDispatcherContext {
                session_id_state,
                attachment_epoch,
                transition_gate,
                events: events.clone(),
                event_notify: event_notify.clone(),
                submission_session_rx,
                attachment_ready_rx,
                awaiting_durable: awaiting_durable.clone(),
            },
            move |client_submission_id, intended_attachment_epoch, sub| {
                let current_client = current_client.clone();
                let events = events.clone();
                let event_notify = event_notify.clone();
                let local_message_operation_ids = local_message_operation_ids.clone();
                let local_message_attachments = local_message_attachments.clone();
                async move {
                    let client = current_client.read().await.clone();
                    // `/compact` is a daemon operation, not an authored user
                    // turn. Routing the compact notice through SendUserMessage
                    // discarded its Compact/CompactNotice classification and
                    // reconstructed it as an ExternalRoot user prompt. Use
                    // the dedicated RPC so it cannot advance activity or be
                    // sent to the model as ordinary text.
                    if sub.kind == cockpit_client::submission::UserSubmissionKind::Compact {
                        return match client.request(Request::Compact).await {
                            Ok(response) => classify_compact_response(response),
                            Err(error) => {
                                tracing::warn!(error = ?error, "compact transport failed");
                                Err(UserSubmissionSendError::Ambiguous(error.to_string()))
                            }
                        };
                    }
                    let use_bulk = user_message_needs_bulk(&sub.text, sub.display_text.as_deref());
                    // FCM2 source artifacts are intentionally text-only.  Do
                    // this guard before image upload so a rejected mixed
                    // submission does not create an attachment side effect
                    // that cannot form a rehydratable durable message.
                    if use_bulk && !sub.images.is_empty() {
                        return Err(UserSubmissionSendError::Rejected(
                            "media/file submissions cannot carry text over the 64 KiB artifact threshold"
                                .to_owned(),
                        ));
                    }
                    let mut dispatched_operation_id = None;
                    let response = if use_bulk {
                        let transfer = stage_opaque_user_text(&client, &sub.text)
                            .await
                            .map_err(classify_bulk_user_message_upload_error)?;
                        let display_transfer = if sub
                            .display_text
                            .as_ref()
                            .is_some_and(|display| {
                                display.len() > INLINE_USER_MESSAGE_TEXT_BYTES
                            })
                        {
                            let transfer = stage_opaque_user_text(
                                &client,
                                sub.display_text
                                    .as_deref()
                                    .expect("oversized display text was present"),
                            )
                            .await
                            .map_err(classify_bulk_user_message_upload_error)?;
                            Some(transfer)
                        } else {
                            None
                        };
                        client
                            .request(Request::SendUserMessageBulk {
                                origin: sub.origin.into(),
                                expected_model_state_generation: sub
                                    .expected_model_state_generation,
                                expected_model: sub.expected_model,
                                client_submission_id,
                                transfer,
                                display_text: if display_transfer.is_some() {
                                    None
                                } else {
                                    sub.display_text
                                },
                                display_transfer,
                                tag_expansions: sub.tag_expansions,
                                forced_skill: sub.forced_skill,
                                delivery_class_override: sub.delivery_class_override,
                                run_invocation_options: None,
                            })
                            .await
                    } else {
                        let operation_id = {
                            let mut operations = local_message_operation_ids
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            *operations
                                .entry(client_submission_id)
                                .or_insert_with(Uuid::now_v7)
                        };
                        dispatched_operation_id = Some(operation_id);
                        let cached_attachments = local_message_attachments
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .get(&client_submission_id)
                            .cloned();
                        let attachments = match cached_attachments {
                            Some(attachments) => attachments,
                            None => {
                                let attachments =
                                    cockpit_client::image_upload::upload_submission_images(
                                        &client,
                                        session_id,
                                        &sub.images,
                                    )
                                    .await
                                    .map_err(classify_image_upload_error)?;
                                local_message_attachments
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .insert(client_submission_id, attachments.clone());
                                attachments
                            }
                        };
                        client
                            .request(Request::SendUserMessageV2 {
                                ingress:
                                    cockpit_proto::send_user_message_v2::MessageIngressV2::local_direct(
                                        operation_id,
                                        session_id.to_string(),
                                        sub.expected_model_state_generation,
                                        sub.expected_model,
                                        None,
                                        cockpit_proto::send_user_message_v2::SendUserMessageV2 {
                                            client_submission_id,
                                            origin: Default::default(),
                                            text: sub.text,
                                            display_text: sub.display_text,
                                            tag_expansions: sub
                                                .tag_expansions
                                                .into_iter()
                                                .map(Into::into)
                                                .collect(),
                                            forced_skill: sub.forced_skill,
                                            delivery_class_override: sub.delivery_class_override,
                                            resolved_delivery_class: None,
                                            resolved_queue_target: None,
                                            attachments,
                                        },
                                    ),
                            })
                            .await
                    };
                    match response {
                        Ok(response) => {
                            let classified = classify_user_message_response(response);
                            if matches!(
                                &classified,
                                Ok(_) | Err(UserSubmissionSendError::Rejected(_))
                            ) && let Some(operation_id) = dispatched_operation_id
                            {
                                let mut operations = local_message_operation_ids
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                if operations.get(&client_submission_id) == Some(&operation_id) {
                                    operations.remove(&client_submission_id);
                                }
                                local_message_attachments
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .remove(&client_submission_id);
                            }
                            let queue = classified?;
                            if let Some(queue) = queue {
                                push_turn_event(
                                    &events,
                                    &event_notify,
                                    intended_attachment_epoch,
                                    TurnEvent::QueueUpdated {
                                        queue: queue
                                            .into_iter()
                                            .map(queue_item_from_proto)
                                            .collect(),
                                    },
                                );
                            }
                            Ok(())
                        }
                        Err(error) => {
                            tracing::warn!(error = ?error, "send_user_message transport failed");
                            Err(UserSubmissionSendError::Ambiguous(error.to_string()))
                        }
                    }
                }
            },
        )));
    }

    // Outbound: fire-and-forget autocomplete usage records.
    {
        let current_client = current_client.clone();
        client_tasks.push(tokio::spawn(async move {
            while let Some(req) = record_rx.recv().await {
                let client = current_client.read().await.clone();
                if let Err(e) = client.request(req).await {
                    tracing::warn!(error = ?e, "record_usage transport failed");
                }
            }
        }));
    }

    // Outbound: response-bearing TUI control requests. They are isolated from
    // telemetry, so a saturated usage channel cannot drop operator commands.
    {
        let current_client = current_client.clone();
        let session_id_state = session_id_state.clone();
        let attachment_epoch = attachment_epoch.clone();
        let transition_gate = transition_gate.clone();
        client_tasks.push(tokio::spawn(async move {
            while let Some(control_request) = control_rx.recv().await {
                dispatch_control_request_for_current_attachment(
                    control_request,
                    &session_id_state,
                    &attachment_epoch,
                    transition_gate.clone(),
                    |request| {
                        let current_client = current_client.clone();
                        async move {
                            let client = current_client.read().await.clone();
                            client
                                .request_ok(request)
                                .await
                                .map_err(|e| format!("daemon request: {e}"))
                        }
                    },
                )
                .await;
            }
        }));
    }

    // Outbound: response-bearing attached-session RPCs. These must use the
    // same daemon client that completed Attach because attachment is stored in
    // per-client daemon state, not in the socket path.
    {
        let current_client = current_client.clone();
        let session_id_state = session_id_state.clone();
        let attachment_epoch = attachment_epoch.clone();
        let transition_gate = transition_gate.clone();
        client_tasks.push(tokio::spawn(async move {
            while let Some(attached_request) = attached_request_rx.recv().await {
                dispatch_attached_request_for_current_attachment(
                    attached_request,
                    &session_id_state,
                    &attachment_epoch,
                    transition_gate.clone(),
                    |request| {
                        let current_client = current_client.clone();
                        async move {
                            let client = current_client.read().await.clone();
                            // Every attached-session RPC the panes issue —
                            // session-setup snapshot, inventory bundle, agent
                            // effective settings, guidance list/review, guidance
                            // enablement trace — funnels through here, so the
                            // bounded `RetryLater` retry lives in the client
                            // once instead of being copied into each pane. Safe
                            // for the mutations sharing this path too: the
                            // daemon emits `RetryLater` only where re-sending
                            // the identical request is the documented recovery.
                            client
                                .request_ok_retrying_transient(request)
                                .await
                                .map_err(|e| format!("daemon request: {e}"))
                        }
                    },
                )
                .await;
            }
        }));
    }

    let (skill_refresh_tx, skill_refresh_abort) = spawn_skill_inventory_refresh_task(
        &mut client_tasks,
        current_client.clone(),
        attach_context.clone(),
        session_id_state.clone(),
        active_agent.clone(),
        skill_inventory_names.clone(),
    );

    // Inbound: daemon events → translate → push into the shared
    // buffer and update active-agent tracker.
    {
        let events = events.clone();
        let event_notify = event_notify.clone();
        let active_agent = active_agent.clone();
        let active_agent_path = active_agent_path.clone();
        let current_client = current_client.clone();
        let last_applied_seq = last_applied_seq.clone();
        let attach_context = attach_context.clone();
        let attachment_epoch = attachment_epoch.clone();
        let session_id_state = session_id_state.clone();
        let skill_refresh_tx = skill_refresh_tx.clone();
        let awaiting_durable = awaiting_durable.clone();
        let attachment_ready_tx = attachment_ready_tx.clone();
        let event_ephemeral_owner = ephemeral_owner.clone();
        let transition_gate = transition_gate.clone();
        let driver = LocalReconnectDriver {
            endpoint: endpoint.clone(),
        };
        // The current primary (root-frame) agent, tracked so a subagent pop
        // returns the active-agent slot to the right primary after a `/plan`
        // or `/build` swap (not a hardcoded `Build`). Seeded from the
        // attach-time active agent.
        let primary_agent = Arc::new(Mutex::new(
            active_agent_path
                .lock()
                .unwrap()
                .first()
                .cloned()
                .unwrap_or_else(|| active_agent.lock().unwrap().clone()),
        ));
        client_tasks.push(tokio::spawn(async move {
            let _skill_refresh_abort = AbortOnDrop(skill_refresh_abort);
            let mut event_state = ClientEventState {
                events: events.clone(),
                event_notify: event_notify.clone(),
                active_agent: active_agent.clone(),
                active_agent_path: active_agent_path.clone(),
                primary_agent: primary_agent.clone(),
                last_applied_seq: last_applied_seq.clone(),
                attach_context: attach_context.clone(),
                attachment_epoch: attachment_epoch.clone(),
                session_id_state: session_id_state.clone(),
                ephemeral_owner: event_ephemeral_owner,
                skill_refresh_tx,
                skill_refresh_generation: 0,
                transition_gate: transition_gate.clone(),
                awaiting_durable: awaiting_durable.clone(),
                attachment_ready_tx: attachment_ready_tx.clone(),
                client_epoch: 0,
            };
            let mut saw_draining = false;
            loop {
                let client_epoch = *client_epoch_rx.borrow_and_update();
                event_state.client_epoch = client_epoch;
                let client = current_client.read().await.clone();
                let mut attachment_replaced = false;
                loop {
                    let event = tokio::select! {
                        biased;
                        changed = client_epoch_rx.changed() => {
                            if changed.is_err() {
                                return;
                            }
                            attachment_replaced = true;
                            break;
                        }
                        event = client.next_event() => event,
                    };
                    let Some(event) = event else {
                        break;
                    };
                    let Some(_transition_guard) = lock_current_client_epoch(
                        event_state.transition_gate.clone(),
                        &client_epoch_rx,
                        client_epoch,
                    )
                    .await
                    else {
                        attachment_replaced = true;
                        break;
                    };
                    if matches!(event, proto::Event::DaemonDraining { .. }) {
                        saw_draining = true;
                    } else if saw_draining {
                        saw_draining = false;
                    }
                    let resync_driver = driver.clone();
                    let resync_current_client = current_client.clone();
                    if !event_state
                        .handle_event_with_resync(
                            event,
                            move |_session_id, attach_snapshot, last| async move {
                                let attached =
                                    reconnect_and_attach(&resync_driver, &attach_snapshot, &last)
                                        .await?;
                                let (new_client, payload) = split_reconnect_attached(attached);
                                *resync_current_client.write().await = new_client;
                                Ok(payload)
                            },
                        )
                        .await
                    {
                        return;
                    }
                }
                if attachment_replaced {
                    continue;
                }
                if !client.is_socket_backed() {
                    return;
                }

                let mut attempt = 1;
                push_turn_event(
                    &events,
                    &event_notify,
                    GLOBAL_ATTACHMENT_EPOCH,
                    TurnEvent::DaemonLinkReconnecting {
                        restarting: saw_draining,
                        attempt,
                    },
                );
                let mut backoff = ReconnectBackoff::new();
                loop {
                    tokio::time::sleep(backoff.next_delay()).await;
                    let transition_gate = event_state.transition_gate.clone();
                    let _transition_guard = transition_gate.lock_owned().await;
                    let attach_snapshot = attach_context.read().await.clone();
                    let Some(session_id) = attach_snapshot.session_id else {
                        return;
                    };
                    match reconnect_and_attach(&driver, &attach_snapshot, &last_applied_seq).await {
                        Ok(attached) => {
                            let (new_client, payload) = split_reconnect_attached(attached);
                            *current_client.write().await = new_client;
                            let new_epoch = advance_attachment_epoch(&attach_snapshot);
                            event_state.client_epoch = new_epoch;
                            let incoming = IncomingEventContext {
                                session_id,
                                client_epoch: new_epoch,
                                attachment_epoch: &event_state.attachment_epoch,
                                events: &events,
                                event_notify: &event_notify,
                                active_agent: &active_agent,
                                active_agent_path: &active_agent_path,
                                primary_agent: &primary_agent,
                                last_applied_seq: &last_applied_seq,
                                awaiting_durable: &awaiting_durable,
                            };
                            let active_model_state = apply_attached_payload(payload, &incoming);
                            let _ = attachment_ready_tx.send(session_id);
                            saw_draining = false;
                            push_turn_event(
                                &events,
                                &event_notify,
                                GLOBAL_ATTACHMENT_EPOCH,
                                TurnEvent::DaemonLinkReconnected { active_model_state },
                            );
                            break;
                        }
                        Err(ReconnectAttachError::Retriable(error)) => {
                            tracing::debug!(error = ?error, attempt, "daemon reconnect failed");
                            attempt = attempt.saturating_add(1);
                            push_turn_event(
                                &events,
                                &event_notify,
                                GLOBAL_ATTACHMENT_EPOCH,
                                TurnEvent::DaemonLinkReconnecting {
                                    restarting: saw_draining,
                                    attempt,
                                },
                            );
                        }
                        Err(ReconnectAttachError::Terminal(error)) => {
                            tracing::warn!(%error, "daemon reconnect attach stopped");
                            push_turn_event(
                                &events,
                                &event_notify,
                                GLOBAL_ATTACHMENT_EPOCH,
                                TurnEvent::DaemonLinkTerminal { error },
                            );
                            return;
                        }
                    }
                }
            }
        }));
    }

    Ok(AgentRunner {
        input_tx,
        record_tx,
        control_tx,
        attached_request_tx,
        events,
        event_notify,
        active_agent,
        active_agent_path,
        skill_inventory_names,
        foreground_target: foreground_target.map(queue_target_from_proto),
        active_model_state,
        session_entry_mode,
        session_id_state,
        attachment_epoch,
        submission_session_tx,
        awaiting_durable: awaiting_durable.clone(),
        short_id,
        project_id,
        usage,
        owns_daemon,
        ephemeral_owner,
        endpoint,
        lifecycle,
        socket,
        history,
        paused_work,
        repair_required,
        resume_compaction_offer,
        btw_fork,
        daemon_version,
        daemon_compatible,
        current_client: Some(current_client),
        attach_context: Some(attach_context),
        last_applied_seq: Some(last_applied_seq),
        client_tasks,
        #[cfg(test)]
        test_session_switch_rx: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        test_force_can_switch: false,
        #[cfg(test)]
        test_advance_epoch_when_switch_task_created: false,
    })
}

pub(crate) fn incompatible_protocol_chip() -> &'static str {
    "daemon speaks an incompatible protocol; run `cockpit daemon restart`"
}

pub(crate) fn send_control_request(
    control_tx: &mpsc::Sender<ControlRequest>,
    events: &Arc<Mutex<Vec<QueuedTurnEvent>>>,
    event_notify: &Arc<Notify>,
    request_id: ControlRequestId,
    intended_session_id: Uuid,
    intended_attachment_epoch: u64,
    req: Request,
) -> Result<(), ControlRequestNotDelivered> {
    let (response_tx, response_rx) = oneshot::channel();
    match control_tx.try_send(ControlRequest {
        request: req,
        intended_session_id,
        intended_attachment_epoch,
        response_tx,
    }) {
        Ok(()) => {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let events = events.clone();
                let event_notify = event_notify.clone();
                handle.spawn(async move {
                    let outcome = match response_rx.await {
                        Ok(result) => control_response_outcome(result),
                        Err(_) => ControlRequestOutcome::NotDelivered(
                            ControlRequestNotDelivered::RunnerTeardown,
                        ),
                    };
                    push_turn_event(
                        &events,
                        &event_notify,
                        intended_attachment_epoch,
                        TurnEvent::ControlRequestFinished {
                            request_id,
                            outcome,
                        },
                    );
                });
            }
            Ok(())
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            Err(ControlRequestNotDelivered::ChannelFull)
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            Err(ControlRequestNotDelivered::ChannelClosed)
        }
    }
}

pub(crate) fn control_response_outcome(result: Result<Response, String>) -> ControlRequestOutcome {
    match result {
        Ok(Response::Unknown) => {
            ControlRequestOutcome::Rejected("unexpected daemon response: Unknown".to_string())
        }
        Ok(Response::ConfigRefreshed {
            applied_generation,
            changed,
        }) => ControlRequestOutcome::ConfigRefreshed {
            applied_generation,
            changed,
        },
        Ok(Response::HostCapabilities { snapshot }) => ControlRequestOutcome::HostCapabilities {
            snapshot: Box::new(snapshot),
        },
        Ok(Response::ExitGuardStatus {
            ephemeral_owner,
            has_live_work,
        }) => ControlRequestOutcome::ExitGuardStatus {
            ephemeral_owner,
            has_live_work,
        },
        Ok(_) => ControlRequestOutcome::Applied,
        Err(error) => ControlRequestOutcome::Rejected(error),
    }
}

/// Pre-flight sizing for the fresh-chat context indicator (Feature 1).
/// `file` is the basename of the matched guidance file (`None` when the
/// project has none); `guidance_tokens` is its body size (the `… in
/// <file>` label); `system_tokens` is the composed system prompt
/// (role prompt + OS + session).
#[derive(Debug, Clone)]
pub struct GuidanceEstimate {
    pub file: Option<String>,
    pub guidance_tokens: u64,
    pub system_tokens: u64,
    pub model_instruction_tokens: u64,
}

/// Resolve the fresh-chat sizing for `cwd` and the active model. Prefers
/// an already-running daemon's calibrated estimate (no attach, no spawn —
/// calling it at launch never creates a session); on any miss (no daemon,
/// connect/request error, or the daemon couldn't answer) it falls back to
/// a local raw-cl100k computation via [`cockpit_core::engine::builtin`]. The two
/// modes may differ by the calibration factor; each is the best available
/// for its mode. Best-effort and non-blocking for launch.
pub async fn fetch_guidance_estimate_with_endpoint(
    cwd: &Path,
    providers: cockpit_config::providers::ProvidersConfig,
    provider: Option<String>,
    model: Option<String>,
    endpoint: Option<ClientEndpoint>,
) -> GuidanceEstimate {
    if let Some(endpoint) = endpoint
        && let Some(est) =
            daemon_guidance_estimate_at_endpoint(cwd, provider.clone(), model.clone(), &endpoint)
                .await
    {
        return est;
    }
    local_guidance_estimate(cwd, &providers, provider.as_deref(), model.as_deref())
}

/// Ask an already-running daemon for the calibrated estimate. Returns
/// `None` on any failure (no daemon, transport error, or a malformed
/// response) so the caller can fall back to the local computation.
async fn daemon_guidance_estimate_at_endpoint(
    cwd: &Path,
    provider: Option<String>,
    model: Option<String>,
    endpoint: &ClientEndpoint,
) -> Option<GuidanceEstimate> {
    let client = cockpit_client::DaemonClient::connect_endpoint(endpoint)
        .await
        .ok()?;
    let resp = client
        .request_ok(Request::GuidanceEstimate {
            project_root: cwd.to_string_lossy().into_owned(),
            provider,
            model,
        })
        .await
        .ok()?;
    match resp {
        Response::GuidanceEstimate {
            file,
            tokens,
            system_tokens,
            model_instruction_tokens,
        } => Some(GuidanceEstimate {
            file,
            guidance_tokens: tokens,
            system_tokens,
            model_instruction_tokens,
        }),
        _ => None,
    }
}

/// Local fallback: size the guidance file body and the full composed
/// system prompt in-process with the shared raw cl100k tokenizer.
/// Cheap and synchronous — `load_agent_guidance` only stats/reads one
/// small file along the cwd→git-root walk — so it never blocks launch.
fn local_guidance_estimate(
    cwd: &Path,
    providers: &cockpit_config::providers::ProvidersConfig,
    provider: Option<&str>,
    model: Option<&str>,
) -> GuidanceEstimate {
    let file = cockpit_core::engine::builtin::load_agent_guidance(cwd).map(|(path, body)| {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        (name, cockpit_tokenizer::count(&body) as u64)
    });
    // No session exists yet at the fresh-chat indicator, so the system
    // prompt omits the `Session:` line — matching what the engine sends.
    let system_prompt = cockpit_core::engine::builtin::default_chat_system_prompt(cwd, "");
    let system_tokens = cockpit_tokenizer::count(&system_prompt) as u64;
    let model_instruction_tokens = provider
        .zip(model)
        .and_then(|(provider, model)| {
            providers
                .resolve_model_system_prompt(provider, model)
                .map(|prompt| cockpit_tokenizer::count(prompt) as u64)
        })
        .unwrap_or(0);
    match file {
        Some((name, guidance_tokens)) => GuidanceEstimate {
            file: Some(name),
            guidance_tokens,
            system_tokens,
            model_instruction_tokens,
        },
        None => GuidanceEstimate {
            file: None,
            guidance_tokens: 0,
            system_tokens,
            model_instruction_tokens,
        },
    }
}

/// Run one blocking daemon request against an already-running daemon and
/// return the typed response. Connects only — never spawns — so the
/// `/sessions` browser degrades gracefully (no live data, no DB writes,
/// no crash) when the daemon isn't up. This adapter may be called only from an
/// `AsyncActionRunner::start_blocking`/`spawn_blocking` worker; reducers and
/// event handlers use typed async effects. `Err(String)` for any
/// transport/typed failure.
fn daemon_request_blocking(
    lifecycle: cockpit_client::LifecycleClient,
    req: Request,
) -> Result<Response, String> {
    #[cfg(test)]
    {
        let _ = lifecycle;
        return crate::tui::settings::test_daemon_request(req);
    }
    #[cfg(not(test))]
    {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| "no tokio runtime".to_string())?;
        tokio::task::block_in_place(|| {
            runtime.block_on(async {
                let resolved = lifecycle
                    .resolve_default()
                    .await
                    .map_err(|error| format!("daemon lifecycle: {error}"))?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&resolved.endpoint)
                    .await
                    .map_err(|e| format!("daemon connect: {e}"))?;
                client
                    .request_ok(req)
                    .await
                    .map_err(|e| format!("daemon request: {e}"))
            })
        })
    }
}

/// Resolve an Assistant session through a persistent lifecycle acquisition.
/// Code and Computer session work uses the configured default lifetime; an
/// Assistant is durable background work and therefore promotes an idle
/// ephemeral owner before its session row is opened or created.
pub(crate) struct AssistantSessionResolution {
    pub(crate) response: Response,
    pub(crate) startup_notice: Option<String>,
    pub(crate) promoted_from_ephemeral: bool,
}

pub(crate) fn resolve_assistant_session_blocking(
    lifecycle: cockpit_client::LifecycleClient,
    request: Request,
) -> Result<AssistantSessionResolution, String> {
    #[cfg(test)]
    {
        let _ = lifecycle;
        return crate::tui::settings::test_daemon_request(request).map(|response| {
            AssistantSessionResolution {
                response,
                startup_notice: None,
                promoted_from_ephemeral: false,
            }
        });
    }
    #[cfg(not(test))]
    {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| "no tokio runtime".to_string())?;
        tokio::task::block_in_place(|| {
            runtime.block_on(async {
                let resolved = lifecycle
                    .resolve(LifecycleIntent::PromoteToPersistent)
                    .await
                    .map_err(|error| format!("daemon lifecycle: {error}"))?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&resolved.endpoint)
                    .await
                    .map_err(|error| format!("daemon connect: {error}"))?;
                let response = client
                    .request_ok(request)
                    .await
                    .map_err(|error| format!("daemon request: {error}"))?;
                Ok(AssistantSessionResolution {
                    response,
                    startup_notice: resolved.startup_notice,
                    promoted_from_ephemeral: resolved.promoted_from_ephemeral,
                })
            })
        })
    }
}

/// Blocking daemon transport for an [`AsyncActionRunner::start_blocking`]
/// worker only. Naming this boundary distinctly lets source ratchets forbid
/// accidental use from reducers and the async event-loop thread.
///
/// [`AsyncActionRunner::start_blocking`]: crate::tui::async_action::AsyncActionRunner::start_blocking
/// Run one blocking request against the daemon at a *known* `socket` —
/// the socket the attached [`AgentRunner`] is already bound to. Unlike
/// [`daemon_request_blocking`], this never re-resolves the canonical path,
/// so it reuses the established daemon endpoint. Connects only — never
/// spawns. `Err(String)` on
/// any transport/typed failure.
pub(crate) fn daemon_request_at_blocking(
    endpoint: &ClientEndpoint,
    req: Request,
) -> Result<Response, String> {
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| "no tokio runtime".to_string())?;
    let endpoint = endpoint.clone();
    tokio::task::block_in_place(|| {
        runtime.block_on(async {
            let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                .await
                .map_err(|e| format!("daemon connect: {e}"))?;
            client
                .request_ok(req)
                .await
                .map_err(|e| format!("daemon request: {e}"))
        })
    })
}

/// Reveal a leak secret over the sensitive local channel (in-process handoff or
/// the Unix peer-authenticated reveal socket, chosen off the control socket).
/// Returns the revealed `Zeroizing` plaintext **directly** to the caller — it
/// never rides an `AsyncActionPayload` or any ordinary daemon codec.
pub(crate) fn daemon_reveal_leak_blocking(
    endpoint: &ClientEndpoint,
    capability: &proto::LeakRevealToken,
) -> Result<
    cockpit_core::daemon::leak_reveal::RevealedLeakSecret,
    cockpit_core::daemon::leak_reveal::LeakRevealDenied,
> {
    let runtime = match tokio::runtime::Handle::try_current() {
        Ok(runtime) => runtime,
        Err(_) => {
            return Err(cockpit_core::daemon::leak_reveal::LeakRevealDenied::UnavailablePlatform);
        }
    };
    let endpoint = endpoint.clone();
    tokio::task::block_in_place(|| {
        runtime.block_on(async {
            cockpit_core::daemon::leak_reveal::reveal_leak_secret_at_endpoint(&endpoint, capability)
                .await
        })
    })
}

/// Run one request-response RPC against the daemon at `socket`. Unlike
/// [`daemon_request_blocking`] (which probes the *canonical* daemon paths),
/// this targets a specific socket — the one the live runner is attached to.
/// That matters when the runner is bound to a recently resolved endpoint.
fn request_on_endpoint(endpoint: &ClientEndpoint, req: Request) -> Result<Response, String> {
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| "no tokio runtime".to_string())?;
    let endpoint = endpoint.clone();
    tokio::task::block_in_place(|| {
        runtime.block_on(async {
            let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                .await
                .map_err(|e| format!("daemon connect: {e}"))?;
            client
                .request_ok(req)
                .await
                .map_err(|e| format!("daemon request: {e}"))
        })
    })
}

/// Fork `parent_session_id` at its tail into a fresh session on the daemon
/// at `socket`, returning `(session_id, short_id)`. `ephemeral` marks it a
/// throwaway `/side` side-conversation fork (excluded from lists, never
/// auto-titled, discarded on end/exit).
pub fn fork_session_blocking(
    endpoint: &ClientEndpoint,
    parent_session_id: uuid::Uuid,
    fork_point_turn_id: Option<String>,
    ephemeral: bool,
    fresh_thread: bool,
) -> Result<(uuid::Uuid, String), String> {
    match request_on_endpoint(
        endpoint,
        Request::ForkSession {
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
            fresh_thread,
        },
    )? {
        Response::Forked {
            session_id,
            short_id,
            ..
        } => Ok((session_id, short_id)),
        other => Err(format!("unexpected fork response: {other:?}")),
    }
}

/// Discard an ephemeral side-conversation (`/side`) on the daemon at
/// `socket`: stops its worker and deletes its row + descendant forks. A
/// non-ephemeral session is left untouched (daemon-side guard).
pub fn discard_session_blocking(
    endpoint: &ClientEndpoint,
    session_id: uuid::Uuid,
) -> Result<(), String> {
    match request_on_endpoint(endpoint, Request::DiscardSession { session_id })? {
        Response::Ack => Ok(()),
        other => Err(format!("unexpected discard response: {other:?}")),
    }
}

/// List sessions for the `/sessions` browser. `project_id = Some(p)` +
/// `parent = None` → root sessions in `p`; `parent = Some(s)` → direct
/// forks of `s`; both `None` → every open session (all-projects scope).
pub fn list_sessions_blocking(
    endpoint: &ClientEndpoint,
    project_id: Option<String>,
    parent_session_id: Option<uuid::Uuid>,
) -> Result<Vec<proto::SessionSummary>, String> {
    match daemon_request_at_blocking(
        endpoint,
        Request::ListSessions {
            project_id,
            parent_session_id,
            assistant_id: None,
        },
    )? {
        Response::Sessions { sessions } => Ok(sessions),
        other => Err(format!("unexpected list_sessions response: {other:?}")),
    }
}

pub fn read_session_messages_blocking(
    endpoint: &ClientEndpoint,
    session_id: uuid::Uuid,
    before_seq: Option<i64>,
    limit: u32,
) -> Result<(Vec<proto::SessionMessage>, bool), String> {
    match daemon_request_at_blocking(
        endpoint,
        Request::ReadSessionMessages {
            session_id,
            before_seq,
            limit,
        },
    )? {
        Response::SessionMessages {
            session_id: got,
            messages,
            has_more,
        } if got == session_id => Ok((messages, has_more)),
        other => Err(format!(
            "unexpected read_session_messages response: {other:?}"
        )),
    }
}

pub fn read_assistant_inbox_blocking(
    endpoint: &ClientEndpoint,
    main_session_id: uuid::Uuid,
) -> Result<Vec<proto::AssistantInboxItemWire>, String> {
    let response = daemon_request_at_blocking(
        endpoint,
        Request::ReadAssistantInbox {
            main_session_id,
            // Inbox delivery into agent context must not erase the human's
            // durable history view.
            include_delivered: true,
            limit: 100,
        },
    )?;
    match response {
        Response::AssistantInbox {
            main_session_id: got,
            items,
        } if got == main_session_id => {
            let inbox_item_ids: Vec<Uuid> = items.iter().map(|item| item.inbox_item_id).collect();
            if !inbox_item_ids.is_empty() {
                match daemon_request_at_blocking(
                    endpoint,
                    Request::AcknowledgeAssistantInboxHumanRead {
                        main_session_id,
                        inbox_item_ids,
                    },
                )? {
                    Response::Ack => {}
                    other => {
                        return Err(format!(
                            "unexpected acknowledge_assistant_inbox_human_read response: {other:?}"
                        ));
                    }
                }
            }
            Ok(items)
        }
        other => Err(format!(
            "unexpected read_assistant_inbox response: {other:?}"
        )),
    }
}

pub fn read_client_submission_receipt_blocking(
    endpoint: &ClientEndpoint,
    session_id: uuid::Uuid,
    client_submission_id: uuid::Uuid,
) -> Result<proto::ClientSubmissionReceiptStatus, String> {
    match daemon_request_at_blocking(
        endpoint,
        Request::ReadClientSubmissionReceipt {
            session_id,
            client_submission_id,
        },
    )? {
        Response::ClientSubmissionReceipt {
            session_id: got_session,
            client_submission_id: got_id,
            status,
        } if got_session == session_id && got_id == client_submission_id => Ok(status),
        other => Err(format!(
            "unexpected client submission receipt response: {other:?}"
        )),
    }
}

pub fn read_history_page_blocking(
    endpoint: &ClientEndpoint,
    session_id: uuid::Uuid,
    before_seq: Option<i64>,
    limit: u32,
) -> Result<(Vec<proto::HistoryEntry>, bool, Option<i64>), String> {
    match daemon_request_at_blocking(
        endpoint,
        Request::ReadHistoryPage {
            session_id,
            before_seq,
            limit,
        },
    )? {
        Response::HistoryPage {
            session_id: got,
            entries,
            has_more,
            oldest_seq,
        } if got == session_id => Ok((entries, has_more, oldest_seq)),
        other => Err(format!("unexpected read_history_page response: {other:?}")),
    }
}

pub fn read_subagent_history_page_blocking(
    endpoint: &ClientEndpoint,
    session_id: uuid::Uuid,
    task_call_id: String,
    label: String,
    before_seq: Option<i64>,
    limit: u32,
) -> Result<(Vec<proto::HistoryEntry>, bool, Option<i64>), String> {
    match daemon_request_at_blocking(
        endpoint,
        Request::ReadSubagentHistoryPage {
            session_id,
            task_call_id: task_call_id.clone(),
            label: label.clone(),
            before_seq,
            limit,
        },
    )? {
        Response::SubagentHistoryPage {
            session_id: got,
            task_call_id: got_task_call_id,
            label: got_label,
            entries,
            has_more,
            oldest_seq,
        } if got == session_id && got_task_call_id == task_call_id && got_label == label => {
            Ok((entries, has_more, oldest_seq))
        }
        other => Err(format!(
            "unexpected read_subagent_history_page response: {other:?}"
        )),
    }
}

pub(crate) fn resource_snapshot_blocking(
    lifecycle: cockpit_client::LifecycleClient,
) -> Result<proto::Response, String> {
    match daemon_request_blocking(lifecycle, Request::ResourceSnapshot)? {
        response @ Response::ResourceSnapshot { .. } => Ok(response),
        other => Err(format!("unexpected resource_snapshot response: {other:?}")),
    }
}

pub(crate) fn promote_resource_request(
    request_id: uuid::Uuid,
    session_id: Option<uuid::Uuid>,
) -> Request {
    promote_resource_token_request(request_id.to_string(), session_id)
}

pub(crate) fn promote_resource_token_request(
    request_id: String,
    session_id: Option<uuid::Uuid>,
) -> Request {
    let request = Request::PromoteResource {
        request_id,
        session_id,
    };
    #[cfg(test)]
    TEST_RESOURCE_PROMOTE_REQUESTS.with(|requests| requests.borrow_mut().push(request.clone()));
    request
}

#[cfg(test)]
thread_local! {
    static TEST_RESOURCE_PROMOTE_REQUESTS: std::cell::RefCell<Vec<Request>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(test)]
pub(crate) fn take_test_resource_promote_requests() -> Vec<Request> {
    TEST_RESOURCE_PROMOTE_REQUESTS.with(|requests| std::mem::take(&mut *requests.borrow_mut()))
}

pub fn promote_resource_blocking(
    lifecycle: cockpit_client::LifecycleClient,
    request: Request,
) -> Result<proto::Response, String> {
    match daemon_request_blocking(lifecycle, request)? {
        response @ Response::PromoteResourceResult { .. } => Ok(response),
        other => Err(format!("unexpected promote_resource response: {other:?}")),
    }
}

/// Fetch live `(has_active_schedules, processing)` status for the candidate
/// session ids. Daemon down / no live worker → empty map; callers treat
/// absent ids as not-processing / no-jobs.
pub fn session_live_status_blocking(
    endpoint: &ClientEndpoint,
    session_ids: Vec<uuid::Uuid>,
) -> std::collections::HashMap<uuid::Uuid, (bool, bool)> {
    match daemon_request_at_blocking(endpoint, Request::SessionLiveStatus { session_ids }) {
        Ok(Response::SessionLiveStatus { statuses }) => statuses
            .into_iter()
            .map(|s| (s.session_id, (s.has_active_schedules, s.processing)))
            .collect(),
        _ => std::collections::HashMap::new(),
    }
}

fn update_active_agent(
    event: &proto::Event,
    slot: &Arc<Mutex<String>>,
    path: &Arc<Mutex<Vec<String>>>,
    primary: &Arc<Mutex<String>>,
    client_epoch: u64,
    attachment_epoch: &Arc<AtomicU64>,
) {
    // Superseded clients must not mutate runner chrome that App may sync.
    if client_epoch != attachment_epoch.load(Ordering::Acquire) {
        return;
    }
    match event {
        proto::Event::PrimarySwapped { name, .. } => {
            // The root-frame primary changed (`/plan` ↔ `/build`). Track it
            // and, since a swap only happens at idle (no subagent on top),
            // reflect it in the live slot immediately.
            *primary.lock().unwrap() = name.clone();
            *slot.lock().unwrap() = name.clone();
            *path.lock().unwrap() = vec![name.clone()];
        }
        proto::Event::SubagentSpawned { parent, child, .. } => {
            *slot.lock().unwrap() = child.clone();
            let mut path = path.lock().unwrap();
            if let Some(parent_idx) = path.iter().position(|name| name == parent) {
                path.truncate(parent_idx + 1);
            } else {
                path.clear();
                path.push(primary.lock().unwrap().clone());
            }
            path.push(child.clone());
        }
        proto::Event::SubagentReport { agent, .. } => {
            // Pop back to the current primary. v1 supports a depth-1 stack
            // (`Build`/`Plan` → one subagent); deeper trees need a proper
            // stack to track properly.
            *slot.lock().unwrap() = primary.lock().unwrap().clone();
            let mut path = path.lock().unwrap();
            if let Some(agent_idx) = path.iter().position(|name| name == agent) {
                path.truncate(agent_idx);
            } else {
                path.pop();
            }
            if path.is_empty() {
                path.push(primary.lock().unwrap().clone());
            }
        }
        _ => {}
    }
}

fn event_session(event: &proto::Event) -> Option<uuid::Uuid> {
    use proto::Event::*;
    Some(match event {
        ConfigSnapshot { snapshot } => snapshot.session_id,
        ThinkingStarted { session_id, .. }
        | QueueUpdated { session_id, .. }
        | ForegroundInputTarget { session_id, .. }
        | ActiveModelState { session_id, .. }
        | ModelSelectionResult { session_id, .. }
        | DefaultModelUpdateResult { session_id, .. }
        | Reconnecting { session_id, .. }
        | AssistantTextDelta { session_id, .. }
        | ReasoningDelta { session_id, .. }
        | AssistantDisplayTextDelta { session_id, .. }
        | AssistantDisplayReasoningDelta { session_id, .. }
        | AssistantDisplayAttemptReset { session_id, .. }
        | AssistantDisplayComplete { session_id, .. }
        | AssistantDisplayError { session_id, .. }
        | AssistantText { session_id, .. }
        | UserMessageRecorded { session_id, .. }
        | QueuedUserMessagesFolded { session_id, .. }
        | SessionPersistFailed { session_id, .. }
        | SessionDriverFailed { session_id, .. }
        | PreflightStarted { session_id, .. }
        | UserMessagesTerminated { session_id, .. }
        | UserMessageRetracted { session_id, .. }
        | Notice { session_id, .. }
        | SkillAutoInjected { session_id, .. }
        | ToolStart { session_id, .. }
        | ToolProgress { session_id, .. }
        | ToolEnd { session_id, .. }
        | ResourceWait { session_id, .. }
        | ResourceStart { session_id, .. }
        | ResourceClear { session_id, .. }
        | ToolError { session_id, .. }
        | InferenceFailed { session_id, .. }
        | InferenceSucceeded { session_id, .. }
        | InferenceWarning { session_id, .. }
        | BackupUsed { session_id, .. }
        | SubagentSpawned { session_id, .. }
        | SubagentRouting { session_id, .. }
        | SubagentReport { session_id, .. }
        | NestedTurn { session_id, .. }
        | Usage { session_id, .. }
        | InterruptRaised { session_id, .. }
        | InterruptResolved { session_id, .. }
        | HistoryReplay { session_id, .. }
        | InterruptQueueChanged { session_id, .. }
        | AgentIdle { session_id, .. }
        | GoalSupervisionProgress { session_id, .. }
        | PrimarySwapped { session_id, .. }
        | SessionEnded { session_id, .. }
        | ScheduleStarted { session_id, .. }
        | ScheduleProgress { session_id, .. }
        | ScheduleNote { session_id, .. }
        | ScheduleCompleted { session_id, .. }
        | ContextProjection { session_id, .. }
        | Pruned { session_id, .. }
        | CompactReady { session_id, .. }
        | SandboxState { session_id, .. }
        | SandboxEscalationState { session_id, .. }
        | SandboxUnavailable { session_id, .. }
        | CommandCapabilityUnavailable { session_id, .. }
        | RedactionState { session_id, .. }
        | PreflightState { session_id, .. }
        | LongcacheState { session_id, .. }
        | ApprovalModeState { session_id, .. }
        | DelegationRecursionState { session_id, .. }
        | TandemState { session_id, .. }
        | GitignoreAllow { session_id, .. }
        | PausedWorkAvailable { session_id, .. }
        | WaitingForLock { session_id, .. }
        | AgentTreeChanged { session_id, .. }
        | WorkspaceTrustReconciliation { session_id, .. } => *session_id,
        EventStreamLagged {
            session_id: Some(session_id),
            ..
        } => *session_id,
        // Daemon-global events carry no session_id: they reach every
        // client regardless of attachment.
        CaffeinateState { .. } | DaemonDraining { .. } | DaemonLifetimeChanged { .. }
        // Image-control configuration changes are daemon-global: they are
        // keyed by project, not by an attached chat session.
        | ImageControlConfigChanged { .. }
        | TerminalOutput { .. }
        | TerminalClipboard { .. }
        | TerminalViewers { .. }
        | TerminalClosed { .. }
        | Osc52ProtocolViolation { .. }
        | HostCapabilitiesChanged { .. }
        | LspNotice { .. }
        | EventStreamLagged {
            session_id: None, ..
        }
        | EnvDriftWarning { .. }
        | Unknown => return None,
        #[cfg(feature = "remote")]
        ConnectorStatus { .. } => return None,
    })
}

async fn reconnect_and_attach(
    driver: &LocalReconnectDriver,
    attach_context: &AttachRequestContext,
    last_applied_seq: &Arc<Mutex<Option<i64>>>,
) -> Result<ReconnectAttach, ReconnectAttachError> {
    let Some(session_id) = attach_context.session_id else {
        return Err(ReconnectAttachError::Terminal(
            "reconnect has no authoritative attached session".to_string(),
        ));
    };
    let client = driver
        .connect()
        .await
        .map_err(ReconnectAttachError::Retriable)?;
    let payload =
        resync_attach_payload(&client, session_id, attach_context, last_applied_seq).await?;
    Ok(ReconnectAttach {
        client,
        session_entry_mode: payload.session_entry_mode,
        history: payload.history,
        paused_work: payload.paused_work,
        repair_required: payload.repair_required,
        active_model_state: payload.active_model_state,
    })
}

async fn resync_attach_payload(
    client: &DaemonClient,
    session_id: Uuid,
    attach_context: &AttachRequestContext,
    last_applied_seq: &Arc<Mutex<Option<i64>>>,
) -> Result<AttachedPayload, ReconnectAttachError> {
    let payload = request_attach_payload(
        session_id,
        attach_context,
        last_applied_seq,
        client.negotiated().version,
        |request| {
            let client = client.clone();
            async move { client.request(request).await }
        },
    )
    .await?;
    if payload.session_entry_mode != attach_context.session_entry_mode {
        return Err(ReconnectAttachError::Terminal(format!(
            "daemon returned mismatched session entry mode: requested {}, received {}",
            attach_context.session_entry_mode.as_str(),
            payload.session_entry_mode.as_str(),
        )));
    }
    Ok(payload)
}

async fn request_attach_payload<F, Fut>(
    session_id: Uuid,
    attach_context: &AttachRequestContext,
    last_applied_seq: &Arc<Mutex<Option<i64>>>,
    client_protocol_version: u32,
    send_request: F,
) -> Result<AttachedPayload, ReconnectAttachError>
where
    F: FnOnce(Request) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<std::result::Result<Response, ErrorPayload>>>,
{
    let response = send_request(first_party_session_attach_request(
        Some(session_id),
        current_last_applied_seq(last_applied_seq),
        attach_context.project_root.clone(),
        None,
        attach_context.no_sandbox,
        attach_context.session_entry_mode,
        None,
        client_protocol_version,
        Some(attach_context.env_snapshot.clone()),
    ))
    .await
    .map_err(ReconnectAttachError::Retriable)?;
    attach_payload_from_response(response.map(Response::into_first_party_attached))
}

fn attach_payload_from_response(
    response: std::result::Result<Response, ErrorPayload>,
) -> Result<AttachedPayload, ReconnectAttachError> {
    match response {
        Ok(Response::Attached {
            session_entry_mode,
            history,
            paused_work,
            repair_required,
            active_model_state,
            ..
        }) => Ok(AttachedPayload {
            session_entry_mode,
            history,
            paused_work,
            repair_required: repair_required.map(|repair| *repair),
            active_model_state,
        }),
        Ok(other) => Err(ReconnectAttachError::Terminal(format!(
            "reconnect attach returned unexpected response: {other:?}"
        ))),
        Err(error) => {
            let prefix = if error.code == ErrorCode::UnknownSession {
                "session no longer exists"
            } else {
                "daemon rejected reconnect attach"
            };
            Err(ReconnectAttachError::Terminal(format!("{prefix}: {error}")))
        }
    }
}

fn split_reconnect_attached(attached: ReconnectAttach) -> (DaemonClient, AttachedPayload) {
    let client = attached.client;
    let payload = AttachedPayload {
        session_entry_mode: attached.session_entry_mode,
        history: attached.history,
        paused_work: attached.paused_work,
        repair_required: attached.repair_required,
        active_model_state: attached.active_model_state,
    };
    (client, payload)
}

fn apply_attached_payload(
    attached: AttachedPayload,
    ctx: &IncomingEventContext<'_>,
) -> Option<proto::ActiveModelState> {
    let AttachedPayload {
        session_entry_mode: _,
        history,
        paused_work,
        repair_required,
        active_model_state,
    } = attached;
    acknowledge_history_receipts(ctx.awaiting_durable, ctx.session_id, &history);
    if let Some(repair) = repair_required {
        push_incoming_turn_event(ctx, TurnEvent::ResumeRepairRequired { state: repair });
    }
    if !paused_work.is_empty() {
        push_incoming_turn_event(
            ctx,
            TurnEvent::PausedWorkAvailable {
                session_id: ctx.session_id,
                items: paused_work,
            },
        );
    }
    if !history.is_empty() {
        let max_seq = history.iter().filter_map(history_entry_seq).max();
        if let Some(max_seq) = max_seq {
            apply_incoming_event(
                proto::Event::HistoryReplay {
                    session_id: ctx.session_id,
                    entries: history,
                    max_seq,
                },
                ctx,
            );
        } else {
            push_incoming_turn_event(ctx, TurnEvent::HistoryReplay { entries: history });
        }
    }
    active_model_state
}

fn apply_incoming_event(event: proto::Event, ctx: &IncomingEventContext<'_>) {
    // Daemon-global events carry no session_id and must reach this client
    // regardless of which session it's attached to.
    let source_is_global = is_global_event(&event);
    if !source_is_global && event_session(&event) != Some(ctx.session_id) {
        return;
    }
    acknowledge_event_receipts(ctx.awaiting_durable, ctx.session_id, &event);
    let event_session_id = event_session(&event);

    if let proto::Event::HistoryReplay {
        entries, max_seq, ..
    } = event
    {
        let last = current_last_applied_seq(ctx.last_applied_seq);
        if last.is_some_and(|last| max_seq <= last) {
            return;
        }
        let entries: Vec<_> = entries
            .into_iter()
            .filter(|entry| match history_entry_seq(entry) {
                Some(seq) => last.is_none_or(|last| seq > last),
                // An incremental attach has no safe ordering proof for a
                // sequence-less row. Never reapply it; first hydration still
                // accepts the legacy sequence-less entries while `last` is
                // absent.
                None => last.is_none(),
            })
            .collect();
        if entries.is_empty() {
            return;
        }
        let applied_max_seq = entries
            .iter()
            .filter_map(history_entry_seq)
            .max()
            .unwrap_or(max_seq);
        update_last_applied_seq(ctx.last_applied_seq, applied_max_seq);
        push_incoming_turn_event(ctx, TurnEvent::HistoryReplay { entries });
        return;
    }

    if event_session_id == Some(ctx.session_id)
        && let Some(seq) = event_persisted_seq(&event)
    {
        if current_last_applied_seq(ctx.last_applied_seq).is_some_and(|last| seq <= last) {
            return;
        }
        update_last_applied_seq(ctx.last_applied_seq, seq);
    }

    update_active_agent(
        &event,
        ctx.active_agent,
        ctx.active_agent_path,
        ctx.primary_agent,
        ctx.client_epoch,
        ctx.attachment_epoch,
    );
    if let Some(translated) = proto_event_to_turn_event(event) {
        // Protocol-global sources (e.g. LspNotice / EnvDriftWarning) collapse
        // into ordinary TurnEvent::Notice; preserve GLOBAL provenance here.
        if source_is_global {
            push_turn_event(
                ctx.events,
                ctx.event_notify,
                GLOBAL_ATTACHMENT_EPOCH,
                translated,
            );
        } else {
            push_incoming_turn_event(ctx, translated);
        }
    }
}

fn acknowledge_history_receipts(
    awaiting_durable: &Arc<Mutex<HashMap<Uuid, VecDeque<BoundUserSubmission>>>>,
    session_id: Uuid,
    history: &[proto::HistoryEntry],
) {
    for entry in history {
        if let proto::HistoryEntry::User {
            client_submission_ids,
            ..
        } = entry
        {
            acknowledge_durable_submissions(awaiting_durable, session_id, client_submission_ids);
        }
    }
}

fn acknowledge_event_receipts(
    awaiting_durable: &Arc<Mutex<HashMap<Uuid, VecDeque<BoundUserSubmission>>>>,
    session_id: Uuid,
    event: &proto::Event,
) {
    let ids = match event {
        proto::Event::UserMessageRecorded {
            client_submission_ids,
            ..
        } => client_submission_ids,
        proto::Event::QueuedUserMessagesFolded { queue_item_ids, .. } => queue_item_ids,
        proto::Event::UserMessagesTerminated {
            client_submission_ids,
            ..
        } => client_submission_ids,
        proto::Event::HistoryReplay { entries, .. } => {
            acknowledge_history_receipts(awaiting_durable, session_id, entries);
            return;
        }
        _ => return,
    };
    acknowledge_durable_submissions(awaiting_durable, session_id, ids);
}

fn proto_event_to_turn_event(event: proto::Event) -> Option<TurnEvent> {
    use proto::Event::*;
    Some(match event {
        ThinkingStarted { agent, turn_id, .. } => TurnEvent::ThinkingStarted { agent, turn_id },
        Reconnecting {
            agent,
            attempt,
            provider,
            model,
            url,
            ..
        } => TurnEvent::Reconnecting {
            agent,
            attempt,
            provider,
            model,
            url,
        },
        HistoryReplay { entries, .. } => TurnEvent::HistoryReplay { entries },
        InferenceWarning {
            agent,
            provider,
            model,
            phase,
            waited_secs,
            ..
        } => TurnEvent::InferenceWarning {
            agent,
            provider,
            model,
            phase,
            waited_secs,
        },
        AssistantTextDelta { agent, delta, .. } => TurnEvent::AssistantTextDelta { agent, delta },
        ReasoningDelta { agent, delta, .. } => TurnEvent::ReasoningDelta { agent, delta },
        AssistantDisplayTextDelta {
            agent,
            attempt_id,
            delta,
            ..
        } => TurnEvent::AssistantDisplayTextDelta {
            agent,
            attempt_id: cockpit_client::presentation::AssistantAttemptId::new(attempt_id),
            delta,
        },
        AssistantDisplayReasoningDelta {
            agent,
            attempt_id,
            delta,
            ..
        } => TurnEvent::AssistantDisplayReasoningDelta {
            agent,
            attempt_id: cockpit_client::presentation::AssistantAttemptId::new(attempt_id),
            delta,
        },
        AssistantDisplayAttemptReset {
            agent,
            failed_attempt_id,
            replacement_attempt_id,
            reason,
            ..
        } => TurnEvent::AssistantDisplayAttemptReset {
            agent,
            failed_attempt_id: cockpit_client::presentation::AssistantAttemptId::new(
                failed_attempt_id,
            ),
            replacement_attempt_id: cockpit_client::presentation::AssistantAttemptId::new(
                replacement_attempt_id,
            ),
            reason,
        },
        AssistantDisplayComplete {
            agent,
            attempt_id,
            text,
            presentation_text,
            reasoning,
            seq,
            response_performance,
            ..
        } => TurnEvent::AssistantDisplayComplete {
            agent,
            attempt_id: cockpit_client::presentation::AssistantAttemptId::new(attempt_id),
            assistant: cockpit_client::presentation::AssistantTextPayload {
                text,
                presentation_text,
                reasoning,
                seq,
                response_performance: response_performance
                    .and_then(cockpit_client::presentation::ResponsePerformance::from_proto),
            },
        },
        AssistantDisplayError {
            agent,
            attempt_id,
            kind,
            message,
            presentation_text,
            ..
        } => TurnEvent::AssistantDisplayError {
            agent,
            attempt_id: cockpit_client::presentation::AssistantAttemptId::new(attempt_id),
            kind: match kind.as_str() {
                "cancelled" => cockpit_client::presentation::DisplayErrorKind::Cancelled,
                _ => cockpit_client::presentation::DisplayErrorKind::Failed,
            },
            message,
            presentation_text,
        },
        AssistantText {
            agent,
            text,
            presentation_text,
            reasoning,
            seq,
            response_performance,
            ..
        } => TurnEvent::AssistantText {
            agent,
            text,
            presentation_text,
            reasoning,
            seq,
            response_performance: response_performance
                .and_then(cockpit_client::presentation::ResponsePerformance::from_proto),
        },
        UserMessageRecorded {
            seq,
            client_submission_ids,
            preflight_cleaned,
            ..
        } => TurnEvent::UserMessageRecorded {
            seq,
            client_submission_ids,
            preflight_cleaned,
        },
        QueuedUserMessagesFolded {
            text,
            display_text,
            tag_expansions,
            queue_item_ids,
            target,
            seq,
            preflight_cleaned,
            ..
        } => TurnEvent::QueuedUserMessagesFolded {
            text,
            display_text,
            tag_expansions,
            queue_item_ids,
            target: queue_target_from_proto(target),
            seq,
            preflight_cleaned,
        },
        ForegroundInputTarget { target, .. } => TurnEvent::ForegroundInputTarget {
            target: queue_target_from_proto(target),
        },
        ActiveModelState {
            selection,
            default_selection,
            diverged,
            generation,
            ..
        } => TurnEvent::ActiveModelState {
            selection,
            default_selection,
            diverged,
            generation,
        },
        ModelSelectionResult {
            selection_id,
            provider,
            model,
            reasoning_effort,
            thinking_mode,
            prompt_cache_retention,
            outcome,
            ..
        } => TurnEvent::ModelSelectionResult {
            selection_id,
            provider,
            model,
            reasoning_effort,
            thinking_mode,
            prompt_cache_retention,
            outcome,
        },
        DefaultModelUpdateResult {
            default_update_id,
            outcome,
            ..
        } => TurnEvent::DefaultModelUpdateResult {
            default_update_id,
            outcome,
        },
        SessionPersistFailed {
            client_submission_id,
            error,
            ..
        } => TurnEvent::SessionPersistFailed {
            client_submission_id,
            error,
        },
        SessionDriverFailed { error, .. } => TurnEvent::SessionDriverFailed { error },
        PreflightStarted {
            client_submission_ids,
            ..
        } => TurnEvent::PreflightStarted {
            client_submission_ids,
        },
        UserMessagesTerminated {
            client_submission_ids,
            disposition,
            ..
        } => TurnEvent::UserMessagesTerminated {
            client_submission_ids,
            disposition,
        },
        UserMessageRetracted {
            client_submission_ids,
            ..
        } => TurnEvent::UserMessageRetracted {
            client_submission_ids,
        },
        Notice { text, .. } | LspNotice { text } => TurnEvent::Notice { text },
        EnvDriftWarning { diff, policy, .. } => TurnEvent::Notice {
            text: format!(
                "environment differs from daemon baseline (policy: {policy:?}; {} added, {} removed, {} changed keys)",
                diff.added_keys, diff.removed_keys, diff.changed_keys
            ),
        },
        SkillAutoInjected { name, reason, .. } => TurnEvent::SkillAutoInjected { name, reason },
        ToolStart {
            agent,
            call_id,
            tool,
            args,
            ..
        } => TurnEvent::ToolStart {
            agent,
            call_id,
            tool,
            args,
        },
        ToolProgress {
            call_id,
            done,
            total,
            unit,
            ..
        } => TurnEvent::ToolProgress(cockpit_client::presentation::ToolProgress {
            call_id,
            done,
            total,
            unit,
        }),
        ToolEnd {
            agent,
            call_id,
            tool,
            output,
            truncated,
            seq,
            hint,
            ..
        } => TurnEvent::ToolEnd {
            agent,
            call_id,
            tool,
            output,
            truncated,
            seq,
            hint,
        },
        ResourceWait {
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
            ..
        } => TurnEvent::ResourceWait {
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
        },
        ResourceStart {
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
            ..
        } => TurnEvent::ResourceStart {
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
        },
        ResourceClear {
            agent,
            request_id,
            display_id,
            resources,
            command_label,
            ..
        } => TurnEvent::ResourceClear {
            agent,
            request_id,
            display_id,
            resources,
            command_label,
        },
        ToolError {
            agent,
            call_id,
            tool,
            error,
            kind,
            seq,
            ..
        } => TurnEvent::ToolError {
            agent,
            call_id,
            tool,
            error,
            kind,
            seq,
        },
        InferenceFailed {
            agent,
            provider,
            model,
            error_class,
            detail,
            auth_failure,
            ..
        } => TurnEvent::InferenceFailed {
            agent,
            provider,
            model,
            error_class,
            detail,
            auth_failure,
        },
        InferenceSucceeded {
            provider, model, ..
        } => TurnEvent::InferenceSucceeded { provider, model },
        BackupUsed {
            agent,
            primary_model,
            error_class,
            backup_model,
            ..
        } => TurnEvent::BackupUsed {
            agent,
            primary_model,
            error_class,
            backup_model,
        },
        SubagentSpawned {
            parent,
            child,
            task_call_id,
            label,
            prompt,
            requested_cwd,
            resolved_cwd,
            model_trusted,
            routing,
            ..
        } => TurnEvent::SubagentSpawned {
            parent,
            child,
            task_call_id,
            label,
            prompt,
            requested_cwd,
            resolved_cwd,
            model_trusted,
            routing,
        },
        SubagentRouting {
            task_call_id,
            label,
            child,
            provider,
            model,
            model_trusted,
            routing,
            ..
        } => TurnEvent::SubagentRouting {
            task_call_id,
            label,
            child,
            provider,
            model,
            model_trusted,
            routing,
        },
        SubagentReport {
            agent,
            task_call_id,
            label,
            report,
            failed,
            model_trusted,
            routing,
            ..
        } => TurnEvent::SubagentReport {
            agent,
            task_call_id,
            label,
            report,
            failed,
            model_trusted,
            routing,
        },
        NestedTurn {
            task_call_id,
            label,
            parent_task_call_id,
            inner,
            ..
        } => {
            let inner = proto_event_to_turn_event(*inner)?;
            TurnEvent::NestedTurn {
                task_call_id,
                label,
                parent_task_call_id,
                inner: Box::new(inner),
            }
        }
        Usage {
            agent,
            input_tokens,
            output_tokens,
            cached_input_tokens,
            cache_creation_input_tokens,
            ..
        } => TurnEvent::Usage {
            agent,
            usage: cockpit_client::presentation::TokenUsage {
                input_tokens,
                output_tokens,
                cached_input_tokens,
                cache_creation_input_tokens,
            },
        },
        AgentIdle {
            turn_id, reason, ..
        } => TurnEvent::AgentIdle { turn_id, reason },
        GoalSupervisionProgress { done, total, .. } => {
            TurnEvent::GoalSupervisionProgress { done, total }
        }
        PausedWorkAvailable {
            session_id, items, ..
        } => TurnEvent::PausedWorkAvailable { session_id, items },
        ScheduleStarted {
            session_id,
            job_id,
            label,
            kind,
        } => TurnEvent::ScheduleStarted {
            session_id,
            job_id,
            label,
            kind,
        },
        ScheduleProgress { job_id, .. } => TurnEvent::ScheduleProgress { job_id },
        ScheduleNote { job_id, text, .. } => TurnEvent::ScheduleNote { job_id, text },
        ScheduleCompleted {
            job_id,
            label,
            kind,
            failed,
            ..
        } => TurnEvent::ScheduleCompleted {
            job_id,
            label,
            kind,
            failed,
        },
        ContextProjection {
            prunable_tokens,
            cache_cold,
            ..
        } => TurnEvent::ContextProjection {
            prunable_tokens,
            cache_cold,
        },
        Pruned {
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
            ..
        } => TurnEvent::Pruned {
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
        },
        CompactReady {
            new_session_id,
            handoff,
            brief,
            source,
            trigger_ctx_pct,
            tokens_before,
            tokens_after,
            turns_summarized,
            tail_kept,
            tail_trimmed,
            seed_tool_count,
            seed_tool_tokens,
            ..
        } => TurnEvent::CompactReady {
            new_session_id,
            handoff,
            brief,
            source,
            trigger_ctx_pct,
            tokens_before,
            tokens_after,
            turns_summarized,
            tail_kept,
            tail_trimmed,
            seed_tool_count,
            seed_tool_tokens,
        },
        // A question-tool interrupt (GOALS §3b) carries a question batch;
        // surface it so the TUI opens the answering dialog. A bare
        // `InterruptRaised` with no batch (the `schedule` needs-attention
        // nudge) has no dialog and stays a no-op here. `InterruptResolved`
        // is translated below so attention surfaces can clear even for
        // background sessions.
        InterruptRaised {
            session_id,
            interrupt_id,
            description,
            questions: Some(questions),
            pending_count,
            reason,
            ..
        } => TurnEvent::InterruptRaised {
            session_id,
            interrupt_id,
            description,
            questions,
            pending_count,
            reason,
        },
        InterruptQueueChanged {
            session_id,
            active_interrupt_id,
            pending_count,
            ..
        } => TurnEvent::InterruptQueueChanged {
            session_id,
            active_interrupt_id,
            pending_count,
        },
        SandboxState {
            mode,
            container_network_enabled,
            container_availability,
            persisted_intent,
            ..
        } => TurnEvent::SandboxState {
            mode,
            container_network_enabled,
            container_availability,
            persisted_intent,
        },
        SandboxEscalationState { enabled, .. } => TurnEvent::SandboxEscalationState { enabled },
        SandboxUnavailable {
            remedy,
            fix_command,
            ..
        } => TurnEvent::SandboxUnavailable {
            remedy,
            fix_command,
        },
        CommandCapabilityUnavailable {
            text, fix_command, ..
        } => TurnEvent::CommandCapabilityUnavailable { text, fix_command },
        RedactionState {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
            ..
        } => TurnEvent::RedactionState {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
        },
        PreflightState { enabled, .. } => TurnEvent::PreflightState { enabled },
        LongcacheState {
            enabled, supported, ..
        } => TurnEvent::LongcacheState { enabled, supported },
        ApprovalModeState { mode, .. } => TurnEvent::ApprovalModeState { mode },
        DelegationRecursionState {
            enabled,
            default_depth,
            ..
        } => TurnEvent::DelegationRecursionState {
            enabled,
            default_depth,
        },
        TandemState {
            models, warning, ..
        } => TurnEvent::TandemState { models, warning },
        GitignoreAllow { allow, .. } => TurnEvent::GitignoreAllow { allow },
        CaffeinateState {
            active,
            lid_close_guaranteed,
            message,
        } => TurnEvent::CaffeinateState {
            active,
            lid_close_guaranteed,
            message,
        },
        #[cfg(feature = "remote")]
        ConnectorStatus {
            enabled,
            status,
            relay_url,
            relay_id,
            relay_region,
            last_error,
        } => TurnEvent::ConnectorStatus {
            enabled,
            status,
            relay_url,
            relay_id,
            relay_region,
            last_error,
        },
        DaemonDraining { forced } => TurnEvent::DaemonDraining { forced },
        // This event updates the runner's atomic lifecycle projection before
        // translation. It has no renderer event of its own.
        DaemonLifetimeChanged { .. } => return None,
        // The waiting-for-lock indicator (`readlock-wait-and-lock-expiry.md`
        // historical prompt slug): surfaced so the app's chrome shows/clears
        // the transient "waiting for lock" indicator.
        WaitingForLock {
            path,
            holder_agent,
            waiting,
            ..
        } => TurnEvent::WaitingForLock {
            path,
            holder_agent,
            waiting,
        },
        QueueUpdated { queue, .. } => TurnEvent::QueueUpdated {
            queue: queue.into_iter().map(queue_item_from_proto).collect(),
        },
        InterruptResolved {
            session_id,
            interrupt_id,
            decision: Some(decision),
            seq,
            ..
        } => TurnEvent::InterruptDecision {
            session_id,
            interrupt_id,
            decision,
            seq,
        },
        InterruptResolved {
            session_id,
            interrupt_id,
            decision: None,
            ..
        } => TurnEvent::InterruptResolved {
            session_id,
            interrupt_id,
        },
        ConfigSnapshot { snapshot } => TurnEvent::ConfigSnapshot { snapshot },
        HostCapabilitiesChanged { snapshot } => TurnEvent::HostCapabilitiesChanged {
            snapshot: Box::new(snapshot),
        },
        // Agent-tree changes invalidate daemon-owned setup/tree queries.
        // Consume as a refresh signal, never a transcript row: a higher
        // tree seq must not make reconnect drop a later transcript event.
        AgentTreeChanged { session_id, .. } => TurnEvent::AgentTreeChanged { session_id },
        // Workspace-trust reconciliation is daemon-owned and self-resolving.
        // Surface only the two states a person can act on: the window where
        // this session's requests are refused with `RetryLater`, and the
        // terminal failure that needs a daemon restart. `Applied` is the quiet
        // resolution of the pending notice and `StopRetrying` is an internal
        // retry step; neither earns a transcript line.
        WorkspaceTrustReconciliation { state, .. } => match state {
            proto::WorkspaceTrustReconciliationState::Pending => TurnEvent::Notice {
                text: "workspace trust is being applied to this session".to_string(),
            },
            proto::WorkspaceTrustReconciliationState::Failed => TurnEvent::Notice {
                text: "workspace trust could not be applied; restart the cockpit daemon"
                    .to_string(),
            },
            proto::WorkspaceTrustReconciliationState::Applied
            | proto::WorkspaceTrustReconciliationState::StopRetrying => return None,
        },
        // This daemon-global, project-scoped invalidation has no image-control
        // TUI state to refresh yet. Consume its safe projection explicitly so
        // it is neither treated as a session event nor rendered as history.
        ImageControlConfigChanged { .. }
        | InterruptRaised { .. }
        | EventStreamLagged { .. }
        | SessionEnded { .. }
        | TerminalOutput { .. }
        | TerminalClipboard { .. }
        | TerminalViewers { .. }
        | TerminalClosed { .. }
        | Osc52ProtocolViolation { .. }
        | Unknown => return None,
        // The chrome's active-agent slot is updated directly in
        // `update_active_agent`; the swap needs no history-stream entry.
        PrimarySwapped { .. } => return None,
    })
}

fn queue_item_from_proto(item: proto::QueueItem) -> cockpit_proto::QueueItem {
    cockpit_proto::QueueItem {
        id: item.id,
        status: match item.status {
            proto::QueueItemStatus::Queued => proto::QueueItemStatus::Queued,
            proto::QueueItemStatus::Folding => proto::QueueItemStatus::Folding,
        },
        text: item.text,
        display_text: item.display_text,
        target: queue_target_from_proto(item.target),
        delivery_class: item.delivery_class,
        send_now: item.send_now,
    }
}

fn queue_target_from_proto(target: proto::QueueTarget) -> proto::QueueTarget {
    proto::QueueTarget {
        id: target.id,
        agent: target.agent,
        depth: target.depth,
        task_call_id: target.task_call_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    fn complete_test_submission() -> ClientUserSubmission {
        ClientUserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: cockpit_client::submission::UserSubmissionKind::User,
            origin: Default::default(),
            text: "wire text with expanded tag and image sentinel".to_string(),
            display_text: Some("visible @src/lib.rs [image]".to_string()),
            tag_expansions: vec![proto::TagExpansionMeta {
                tool: "read".to_string(),
                path: "src/lib.rs".to_string(),
                detail: "expanded source".to_string(),
                ok: true,
            }],
            images: vec![cockpit_client::image_upload::SubmissionImage::png(vec![
                0x89, b'P', b'N', b'G', 0, 1, 2, 3,
            ])],
            forced_skill: Some("review".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn protocol_mismatch_message_names_daemon_restart() {
        let chip = incompatible_protocol_chip();
        assert_eq!(
            chip,
            "daemon speaks an incompatible protocol; run `cockpit daemon restart`"
        );
        assert!(!chip.contains("unexpected attach response"));
    }

    #[test]
    fn fresh_picker_selection_carries_root_override_but_resume_does_not() {
        let selected = cockpit_config::providers::ActiveModelRef {
            provider: "profile-handle".to_string(),
            model: "alternate-model".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        };
        assert_eq!(
            root_model_override_for_attach(None, &Some(selected.clone())),
            Some(selected.clone()),
            "a pre-attach picker choice must survive installed-root preparation"
        );
        assert_eq!(
            root_model_override_for_attach(Some(Uuid::new_v4()), &Some(selected)),
            None,
            "resume selection authority remains the daemon's durable session row"
        );
    }

    /// Pre-spawn resolution: the local fallback (the only
    /// source feeding the fresh-chat indicator before any daemon exists)
    /// must detect a guidance file sitting in `cwd` and report its basename
    /// plus a non-zero body size. `AGENTS.md` is in the shipped default
    /// `agent_guidance_files`, so this resolves regardless of any host
    /// override that only *adds* names (e.g. `project guidance`). Pins the
    /// no-daemon launch state against silent regression.
    #[test]
    fn local_guidance_estimate_detects_file_in_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "PROJECT RULES\nmore lines\n").unwrap();

        let est = local_guidance_estimate(tmp.path(), &Default::default(), None, None);
        assert_eq!(
            est.file.as_deref(),
            Some("AGENTS.md"),
            "local fallback must detect the guidance file by basename"
        );
        assert!(
            est.guidance_tokens > 0,
            "a non-empty guidance body must size to a non-zero token count"
        );
        // The full composed system prompt is always non-empty (role prompt +
        // identity lines), so the baseline the running estimate folds in is
        // never zero — the refresh-on-connect adopt-guard relies on this.
        assert!(
            est.system_tokens > 0,
            "system prompt baseline must be non-zero"
        );
    }

    /// No guidance file present anywhere on the walk: the local fallback
    /// reports `file = None` (the indicator falls through to the usual
    /// context form) while still sizing the system-prompt baseline. Walks
    /// from a tempdir that has no `AGENTS.md`/`project guidance`.
    #[test]
    fn local_guidance_estimate_none_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("empty-project");
        std::fs::create_dir(&sub).unwrap();

        let est = local_guidance_estimate(&sub, &Default::default(), None, None);
        assert!(
            est.file.is_none(),
            "no guidance file should resolve to None"
        );
        assert_eq!(est.guidance_tokens, 0);
        assert!(est.system_tokens > 0);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_history_page_blocking_rejects_unexpected_response() {
        use cockpit_proto::{Body, Envelope, ProtoStream, RecvFrame, Request, Response};
        use tokio::net::UnixListener;

        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let session_id = uuid::Uuid::new_v4();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut proto = ProtoStream::new(stream);
            proto
                .send(&Envelope::response(
                    uuid::Uuid::nil(),
                    Response::DaemonStatus {
                        pid: 1,
                        uptime_secs: 0,
                        active_sessions: 0,
                        socket_path: "test.sock".to_string(),
                        daemon_version: "test".to_string(),
                        protocol_version: cockpit_proto::PROTOCOL_VERSION,
                        paused_sessions: 0,
                        database_path: "test.db".to_string(),
                        schema_version: 0,
                    },
                ))
                .await
                .unwrap();
            let status = match proto.recv().await.unwrap().unwrap() {
                RecvFrame::Envelope(env) => env,
                RecvFrame::Unknown { .. } => panic!("unexpected unknown frame"),
                RecvFrame::VersionMismatch { .. } => panic!("unexpected version mismatch"),
            };
            let Body::Request {
                id: status_id,
                request: Request::DaemonStatus,
                ..
            } = status.body
            else {
                panic!("expected daemon status handshake request");
            };
            proto
                .send(&Envelope::response(
                    status_id,
                    Response::DaemonStatus {
                        pid: 1,
                        uptime_secs: 0,
                        active_sessions: 0,
                        socket_path: "test.sock".to_string(),
                        daemon_version: "test".to_string(),
                        protocol_version: cockpit_proto::PROTOCOL_VERSION,
                        paused_sessions: 0,
                        database_path: "test.db".to_string(),
                        // Handshake negotiation intentionally ignores database
                        // metadata; keep this socket fixture independent of
                        // cockpit-core's private storage implementation.
                        schema_version: 0,
                    },
                ))
                .await
                .unwrap();
            let env = match proto.recv().await.unwrap().unwrap() {
                RecvFrame::Envelope(env) => env,
                RecvFrame::Unknown { .. } => panic!("unexpected unknown frame"),
                RecvFrame::VersionMismatch { .. } => panic!("unexpected version mismatch"),
            };
            let Body::Request { id, request, .. } = env.body else {
                panic!("expected request envelope");
            };
            match request {
                Request::ReadHistoryPage {
                    session_id: got,
                    before_seq,
                    limit,
                } => {
                    assert_eq!(got, session_id);
                    assert_eq!(before_seq, None);
                    assert_eq!(limit, 20);
                }
                other => panic!("expected read_history_page request, got {other:?}"),
            }
            proto
                .send(&Envelope::response(
                    id,
                    Response::SessionMessages {
                        session_id,
                        messages: Vec::new(),
                        has_more: false,
                    },
                ))
                .await
                .unwrap();
        });

        let endpoint = ClientEndpoint::Wire(socket);
        let err = read_history_page_blocking(&endpoint, session_id, None, 20)
            .expect_err("mismatched response variant is rejected");

        assert!(err.contains("unexpected read_history_page response"));
        assert!(err.contains("SessionMessages"));
        server.await.unwrap();
    }

    fn test_attach_context(project_root: &str) -> Arc<RwLock<AttachRequestContext>> {
        Arc::new(RwLock::new(AttachRequestContext {
            session_id: None,
            project_root: project_root.to_string(),
            no_sandbox: true,
            session_entry_mode: proto::SessionEntryMode::Code,
            env_snapshot: cockpit_proto::EnvSnapshotWire {
                source: cockpit_proto::EnvSnapshotSource::TuiShell,
                digest: String::new(),
                vars: std::collections::HashMap::new(),
            },
            transition_gate: Arc::new(AsyncMutex::new(())),
            client_epoch_tx: watch::channel(0).0,
            attachment_epoch: Arc::new(AtomicU64::new(0)),
        }))
    }

    fn test_skill(name: &str) -> proto::SkillSummary {
        proto::SkillSummary {
            name: name.to_string(),
            description: String::new(),
            source: "test".to_string(),
            user_invocable: true,
        }
    }

    fn attached_response(session_id: Uuid, history: Vec<proto::HistoryEntry>) -> Response {
        Response::Attached {
            session_id,
            short_id: "test01".to_string(),
            project_root: "/tmp/project".to_string(),
            project_id: "project".to_string(),
            active_agent: "Build".to_string(),
            active_agent_path: vec!["Build".to_string()],
            foreground_target: None,
            active_subagent: None,
            active_model_state: None,
            session_entry_mode: proto::SessionEntryMode::Code,
            history,
            paused_work: Vec::new(),
            repair_required: None,
            resume_compaction_offer: None,
            daemon_version: "test".to_string(),
            compatible: true,
            env_baseline: None,
            env_session: None,
            env_drift: None,
            env_policy_applied: cockpit_proto::EnvDriftPolicy::Client,
            btw_fork: None,
        }
    }

    fn drained_event_payloads(events: &Arc<Mutex<Vec<QueuedTurnEvent>>>) -> Vec<TurnEvent> {
        drain_turn_events(events)
            .into_iter()
            .map(|queued| queued.event)
            .collect()
    }

    fn test_event_state(
        session_id: Uuid,
        attach_context: Arc<RwLock<AttachRequestContext>>,
        last_applied_seq: Arc<Mutex<Option<i64>>>,
        skill_refresh_tx: watch::Sender<u64>,
    ) -> (ClientEventState, Arc<Mutex<Vec<QueuedTurnEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let (attachment_ready_tx, _attachment_ready_rx) = mpsc::unbounded_channel();
        let attachment_epoch = Arc::new(AtomicU64::new(0));
        if let Ok(mut context) = attach_context.try_write() {
            context.session_id = Some(session_id);
        }
        (
            ClientEventState {
                events: events.clone(),
                event_notify: Arc::new(Notify::new()),
                active_agent: active_agent.clone(),
                active_agent_path,
                primary_agent: active_agent,
                last_applied_seq,
                attach_context,
                attachment_epoch,
                session_id_state: Arc::new(Mutex::new(session_id)),
                ephemeral_owner: Arc::new(AtomicBool::new(false)),
                skill_refresh_tx,
                skill_refresh_generation: 0,
                transition_gate: Arc::new(AsyncMutex::new(())),
                awaiting_durable: Arc::new(Mutex::new(HashMap::new())),
                attachment_ready_tx,
                client_epoch: 0,
            },
            events,
        )
    }

    fn foreground_target_event(session_id: Uuid) -> proto::Event {
        proto::Event::ForegroundInputTarget {
            session_id,
            target: proto::QueueTarget {
                id: "root".to_string(),
                agent: "Build".to_string(),
                depth: 0,
                task_call_id: None,
            },
        }
    }

    #[tokio::test]
    async fn event_read_before_switch_gate_is_rejected_after_epoch_changes() {
        let transition_gate = Arc::new(AsyncMutex::new(()));
        let switch_guard = transition_gate.clone().lock_owned().await;
        let (epoch_tx, epoch_rx) = watch::channel(9_u64);

        // Model an event already removed from the old client's stream and now
        // waiting to enter the App queue behind the switch's transition gate.
        let limbo_event =
            tokio::spawn(
                async move { lock_current_client_epoch(transition_gate, &epoch_rx, 9).await },
            );
        tokio::task::yield_now().await;
        epoch_tx.send_modify(|epoch| *epoch = 10);
        drop(switch_guard);

        assert!(
            limbo_event.await.unwrap().is_none(),
            "an event read under the old attachment epoch must never enter the new epoch"
        );
    }

    #[tokio::test]
    async fn queued_control_from_old_attachment_is_rejected_without_sending() {
        let session_id = Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(session_id));
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        let transition_gate = Arc::new(AsyncMutex::new(()));
        let (response_tx, response_rx) = oneshot::channel();
        let sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sent_in_request = sent.clone();

        dispatch_control_request_for_current_attachment(
            ControlRequest {
                request: Request::Prune,
                intended_session_id: session_id,
                intended_attachment_epoch: 3,
                response_tx,
            },
            &session_id_state,
            &attachment_epoch,
            transition_gate,
            move |_request| async move {
                sent_in_request.store(true, Ordering::Release);
                Ok(Response::Ack)
            },
        )
        .await;

        assert!(!sent.load(Ordering::Acquire));
        let error = response_rx.await.unwrap().unwrap_err();
        assert!(
            error.contains("attachment that has been replaced"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn successful_lag_resync_rejects_queued_old_attached_request_without_sending() {
        let session_id = Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(session_id));
        let attach_context = test_attach_context("/tmp/project");
        let (attachment_epoch, transition_gate) = {
            let context = attach_context.read().await;
            context.attachment_epoch.store(12, Ordering::Release);
            (
                context.attachment_epoch.clone(),
                context.transition_gate.clone(),
            )
        };
        let transition_guard = transition_gate.clone().lock_owned().await;
        let (response_tx, response_rx) = oneshot::channel();
        let sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sent_in_request = sent.clone();

        let dispatch = tokio::spawn({
            let session_id_state = session_id_state.clone();
            let attachment_epoch = attachment_epoch.clone();
            let transition_gate = transition_gate.clone();
            async move {
                dispatch_attached_request_for_current_attachment(
                    AttachedRequest {
                        request: Request::Prune,
                        intended_session_id: session_id,
                        intended_attachment_epoch: 12,
                        response_tx,
                    },
                    &session_id_state,
                    &attachment_epoch,
                    transition_gate,
                    move |_request| async move {
                        sent_in_request.store(true, Ordering::Release);
                        Ok(Response::Ack)
                    },
                )
                .await;
            }
        });
        tokio::task::yield_now().await;

        let (skill_refresh_tx, _skill_refresh_rx) = watch::channel(0);
        let (mut event_state, _events) = test_event_state(
            session_id,
            attach_context,
            Arc::new(Mutex::new(None)),
            skill_refresh_tx,
        );
        assert!(
            event_state
                .handle_event_with_resync(
                    proto::Event::EventStreamLagged {
                        session_id: Some(session_id),
                        dropped: 1,
                    },
                    move |session_id, _attach_context, _last| async move {
                        attach_payload_from_response(Ok(attached_response(session_id, Vec::new())))
                    },
                )
                .await
        );
        assert_eq!(attachment_epoch.load(Ordering::Acquire), 13);
        drop(transition_guard);
        dispatch.await.unwrap();

        assert!(!sent.load(Ordering::Acquire));
        let error = response_rx.await.unwrap().unwrap_err();
        assert!(
            error.contains("attachment that has been replaced"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn explicit_switch_flushes_every_previously_accepted_submission_before_attach() {
        let old_session_id = Uuid::new_v4();
        let (input_tx, mut input_rx) = mpsc::channel(2);
        for text in ["held first", "queued second"] {
            input_tx
                .send(RunnerInput::Submission(Box::new(BoundUserSubmission {
                    submission: ClientUserSubmission::text(text.to_string()),
                    optimistic_submission_id: Uuid::new_v4(),
                    intended_session_id: old_session_id,
                    intended_attachment_epoch: 7,
                })))
                .await
                .unwrap();
        }
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let worker_delivered = delivered.clone();
        let worker = tokio::spawn(async move {
            while let Some(input) = input_rx.recv().await {
                match input {
                    RunnerInput::Submission(bound) => {
                        worker_delivered.lock().unwrap().push(bound.submission.text)
                    }
                    RunnerInput::RetainedRetry(_) => {
                        panic!("retained retry cannot enter the public input channel")
                    }
                    RunnerInput::SubmissionBatch(batch) => worker_delivered
                        .lock()
                        .unwrap()
                        .extend(batch.into_iter().map(|bound| bound.submission.text)),
                    RunnerInput::Flush(flushed_tx) => {
                        let _ = flushed_tx.send(());
                        break;
                    }
                }
            }
        });

        flush_accepted_user_submissions(&input_tx).await.unwrap();
        worker.await.unwrap();
        assert_eq!(
            &*delivered.lock().unwrap(),
            &["held first", "queued second"]
        );
    }

    #[tokio::test]
    async fn dispatcher_drains_sixty_four_complete_batched_submissions_in_order() {
        let session_id = Uuid::new_v4();
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        let (submission_session_tx, submission_session_rx) =
            watch::channel(SubmissionSessionBinding::new(session_id, 0));
        let (_attachment_ready_tx, attachment_ready_rx) = mpsc::unbounded_channel();
        let (input_tx, input_rx) = mpsc::channel(1);
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let dispatcher = tokio::spawn(run_user_submission_dispatcher(
            input_rx,
            UserSubmissionDispatcherContext {
                session_id_state: Arc::new(Mutex::new(session_id)),
                attachment_epoch,
                transition_gate: Arc::new(AsyncMutex::new(())),
                events: Arc::new(Mutex::new(Vec::new())),
                event_notify: Arc::new(Notify::new()),
                submission_session_rx,
                attachment_ready_rx,
                awaiting_durable: Arc::new(Mutex::new(HashMap::new())),
            },
            move |_client_submission_id, _intended_attachment_epoch, submission| {
                let sent_tx = sent_tx.clone();
                async move {
                    sent_tx.send(submission).unwrap();
                    Ok(())
                }
            },
        ));
        let mut expected = Vec::new();
        let mut batch = Vec::new();
        for index in 0..64 {
            let mut submission = complete_test_submission();
            submission.text = format!("wire-{index}");
            submission.display_text = Some(format!("display-{index}"));
            expected.push(serde_json::to_value(&submission).unwrap());
            batch.push(BoundUserSubmission {
                submission,
                optimistic_submission_id: Uuid::new_v4(),
                intended_session_id: session_id,
                intended_attachment_epoch: 4,
            });
        }
        input_tx
            .send(RunnerInput::SubmissionBatch(batch))
            .await
            .unwrap();

        let mut delivered = Vec::new();
        for _ in 0..64 {
            let submission = tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
                .await
                .expect("dispatcher must drain the retained batch")
                .expect("dispatcher remains live");
            delivered.push(serde_json::to_value(submission).unwrap());
        }
        assert_eq!(delivered, expected);
        assert!(matches!(
            sent_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        drop(input_tx);
        drop(submission_session_tx);
        dispatcher.await.unwrap();
    }

    #[tokio::test]
    async fn queue_ack_retains_exact_submission_until_durable_receipt_and_reconnect_retries_it() {
        let session_id = Uuid::new_v4();
        let client_submission_id = Uuid::now_v7();
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        let (_submission_session_tx, submission_session_rx) =
            watch::channel(SubmissionSessionBinding::new(session_id, 0));
        let (attachment_ready_tx, attachment_ready_rx) = mpsc::unbounded_channel();
        let (input_tx, input_rx) = mpsc::channel(1);
        let events = Arc::new(Mutex::new(Vec::new()));
        let awaiting_durable = Arc::new(Mutex::new(HashMap::new()));
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let submission = complete_test_submission();
        let expected = serde_json::to_value(&submission).unwrap();
        let dispatcher = tokio::spawn(run_user_submission_dispatcher(
            input_rx,
            UserSubmissionDispatcherContext {
                session_id_state: Arc::new(Mutex::new(session_id)),
                attachment_epoch,
                transition_gate: Arc::new(AsyncMutex::new(())),
                events: events.clone(),
                event_notify: Arc::new(Notify::new()),
                submission_session_rx,
                attachment_ready_rx,
                awaiting_durable: awaiting_durable.clone(),
            },
            move |id, _intended_attachment_epoch, submission| {
                let sent_tx = sent_tx.clone();
                async move {
                    sent_tx
                        .send((id, serde_json::to_value(submission).unwrap()))
                        .unwrap();
                    Ok(())
                }
            },
        ));

        input_tx
            .send(RunnerInput::Submission(Box::new(BoundUserSubmission {
                submission,
                optimistic_submission_id: client_submission_id,
                intended_session_id: session_id,
                intended_attachment_epoch: 4,
            })))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
                .await
                .unwrap(),
            Some((client_submission_id, expected.clone()))
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let retained = awaiting_durable
                    .lock()
                    .unwrap()
                    .get(&session_id)
                    .and_then(|queue| queue.front().cloned());
                if let Some(retained) = retained {
                    assert_eq!(retained.optimistic_submission_id, client_submission_id);
                    assert_eq!(serde_json::to_value(retained.submission).unwrap(), expected);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queue ACK retains the complete payload");

        attachment_ready_tx.send(session_id).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
                .await
                .expect("reattach retries an unconfirmed ACK")
                .expect("dispatcher remains live"),
            (client_submission_id, expected)
        );
        assert!(drained_event_payloads(&events).iter().any(|event| {
            matches!(
                event,
                TurnEvent::UserMessageDispatchRestored {
                    optimistic_submission_id,
                    text,
                    display_text,
                    tag_expansions,
                } if *optimistic_submission_id == client_submission_id
                    && text == "wire text with expanded tag and image sentinel"
                    && display_text.as_deref() == Some("visible @src/lib.rs [image]")
                    && !tag_expansions.is_empty()
            )
        }));

        acknowledge_durable_submissions(&awaiting_durable, session_id, &[client_submission_id]);
        assert!(
            awaiting_durable.lock().unwrap().get(&session_id).is_none(),
            "the durable record/fold receipt is the release boundary"
        );

        drop(input_tx);
        dispatcher.await.unwrap();
    }

    #[test]
    fn session_switch_history_releases_durable_tracker_before_destination_is_published() {
        let (control_tx, _control_rx) = mpsc::channel(1);
        let (input_tx, _input_rx) = mpsc::channel(1);
        let (mut runner, mut submission_session_rx) =
            AgentRunner::stub_with_channels_and_submission_watch(control_tx, input_tx);
        runner.last_applied_seq = Some(Arc::new(Mutex::new(Some(0))));

        let destination = Uuid::new_v4();
        let receipt_id = Uuid::new_v4();
        let mut retained = complete_test_submission();
        retained.text = "exact retained wire text".to_string();
        runner.awaiting_durable.lock().unwrap().insert(
            destination,
            VecDeque::from([BoundUserSubmission {
                submission: retained,
                optimistic_submission_id: receipt_id,
                intended_session_id: destination,
                intended_attachment_epoch: 7,
            }]),
        );
        let outcome = SessionSwitchOutcome {
            target: SessionTarget::Resume {
                session_id: destination,
                since_seq: None,
            },
            session_id: destination,
            session_entry_mode: proto::SessionEntryMode::Code,
            promoted_from_ephemeral: false,
            short_id: "dest01".to_string(),
            active_agent: "Build".to_string(),
            active_agent_path: vec!["Build".to_string()],
            last_applied_seq: Some(41),
            foreground_target: Some(cockpit_proto::QueueTarget::root("Build")),
            active_model_state: None,
            project_id: "project".to_string(),
            history: vec![proto::HistoryEntry::User {
                text: "exact retained wire text".to_string(),
                display_text: Some("visible retained draft".to_string()),
                tag_expansions: Vec::new(),
                client_submission_ids: vec![receipt_id],
                ts_ms: 1,
                seq: 41,
                origin_principal: None,
            }],
            paused_work: Vec::new(),
            repair_required: None,
            resume_compaction_offer: None,
            btw_fork: None,
            daemon_version: "test".to_string(),
            daemon_compatible: true,
            attachment_epoch: 0,
            transition_guard: None,
        };

        runner.apply_session_switch_outcome(&outcome);

        assert!(
            runner
                .awaiting_durable
                .lock()
                .unwrap()
                .get(&destination)
                .is_none(),
            "the authoritative attach history must clear receipts before the dispatcher wakes"
        );
        assert!(submission_session_rx.has_changed().unwrap());
        assert_eq!(
            submission_session_rx.borrow_and_update().session_id,
            destination
        );
    }

    #[test]
    fn every_terminal_disposition_releases_only_its_exact_retained_submission() {
        for disposition in [
            proto::UserMessageTerminalDisposition::Removed,
            proto::UserMessageTerminalDisposition::Cancelled,
            proto::UserMessageTerminalDisposition::PreflightRejected,
        ] {
            let session_id = Uuid::new_v4();
            let terminal_id = Uuid::new_v4();
            let still_pending_id = Uuid::new_v4();
            let awaiting = Arc::new(Mutex::new(HashMap::from([(
                session_id,
                VecDeque::from([
                    BoundUserSubmission {
                        submission: complete_test_submission(),
                        optimistic_submission_id: terminal_id,
                        intended_session_id: session_id,
                        intended_attachment_epoch: 2,
                    },
                    BoundUserSubmission {
                        submission: complete_test_submission(),
                        optimistic_submission_id: still_pending_id,
                        intended_session_id: session_id,
                        intended_attachment_epoch: 2,
                    },
                ]),
            )])));

            acknowledge_event_receipts(
                &awaiting,
                session_id,
                &proto::Event::UserMessagesTerminated {
                    session_id,
                    client_submission_ids: vec![terminal_id],
                    disposition,
                },
            );

            let retained = awaiting.lock().unwrap();
            let queue = retained.get(&session_id).expect("B stays retained");
            assert_eq!(queue.len(), 1);
            assert_eq!(queue[0].optimistic_submission_id, still_pending_id);
        }
    }

    #[tokio::test]
    async fn unexpected_success_response_retries_same_id_and_payload_without_overtaking_or_blocking_flush()
     {
        let session_id = Uuid::new_v4();
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        let (submission_session_tx, submission_session_rx) =
            watch::channel(SubmissionSessionBinding::new(session_id, 0));
        let (_attachment_ready_tx, attachment_ready_rx) = mpsc::unbounded_channel();
        let (input_tx, input_rx) = mpsc::channel(4);
        let events = Arc::new(Mutex::new(Vec::new()));
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(Mutex::new(HashMap::<Uuid, serde_json::Value>::new()));
        let execution_count = Arc::new(AtomicUsize::new(0));
        let first_response_dropped = Arc::new(AtomicBool::new(false));
        let (attempt_tx, mut attempt_rx) = mpsc::unbounded_channel();
        let dispatcher = tokio::spawn(run_user_submission_dispatcher(
            input_rx,
            UserSubmissionDispatcherContext {
                session_id_state: Arc::new(Mutex::new(session_id)),
                attachment_epoch,
                transition_gate: Arc::new(AsyncMutex::new(())),
                events: events.clone(),
                event_notify: Arc::new(Notify::new()),
                submission_session_rx,
                attachment_ready_rx,
                awaiting_durable: Arc::new(Mutex::new(HashMap::new())),
            },
            {
                let attempts = attempts.clone();
                let accepted = accepted.clone();
                let execution_count = execution_count.clone();
                let first_response_dropped = first_response_dropped.clone();
                move |client_submission_id, _intended_attachment_epoch, submission| {
                    let attempts = attempts.clone();
                    let accepted = accepted.clone();
                    let execution_count = execution_count.clone();
                    let first_response_dropped = first_response_dropped.clone();
                    let attempt_tx = attempt_tx.clone();
                    async move {
                        let payload = serde_json::to_value(submission).unwrap();
                        attempts
                            .lock()
                            .unwrap()
                            .push((client_submission_id, payload.clone()));
                        attempt_tx.send(client_submission_id).unwrap();
                        let mut accepted = accepted.lock().unwrap();
                        match accepted.entry(client_submission_id) {
                            std::collections::hash_map::Entry::Vacant(entry) => {
                                entry.insert(payload);
                                execution_count.fetch_add(1, Ordering::SeqCst);
                            }
                            std::collections::hash_map::Entry::Occupied(entry) => {
                                assert_eq!(entry.get(), &payload, "retry payload must be exact");
                            }
                        }
                        if !first_response_dropped.swap(true, Ordering::SeqCst) {
                            Err(UserSubmissionSendError::Ambiguous(
                                "response was lost after durable acceptance".to_string(),
                            ))
                        } else {
                            Ok(())
                        }
                    }
                }
            },
        ));

        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let first = complete_test_submission();
        let first_value = serde_json::to_value(&first).unwrap();
        let mut second = complete_test_submission();
        second.text = "second wire payload".to_string();
        input_tx
            .send(RunnerInput::Submission(Box::new(BoundUserSubmission {
                submission: first,
                optimistic_submission_id: first_id,
                intended_session_id: session_id,
                intended_attachment_epoch: 4,
            })))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .unwrap(),
            Some(first_id)
        );

        input_tx
            .send(RunnerInput::Submission(Box::new(BoundUserSubmission {
                submission: second,
                optimistic_submission_id: second_id,
                intended_session_id: session_id,
                intended_attachment_epoch: 4,
            })))
            .await
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(1),
            flush_accepted_user_submissions(&input_tx),
        )
        .await
        .expect("flush must not deadlock behind an ambiguous retry")
        .unwrap();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .unwrap(),
            Some(first_id),
            "A must retry before B"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .unwrap(),
            Some(second_id),
            "B must remain FIFO behind ambiguous A"
        );
        assert_eq!(execution_count.load(Ordering::SeqCst), 2);
        {
            let attempts = attempts.lock().unwrap();
            assert_eq!(attempts.len(), 3);
            assert_eq!(attempts[0].0, first_id);
            assert_eq!(attempts[1].0, first_id);
            assert_eq!(attempts[0].1, first_value);
            assert_eq!(attempts[1].1, first_value);
        }
        assert!(
            drained_event_payloads(&events)
                .iter()
                .all(|event| !matches!(event, TurnEvent::UserMessageDispatchFailed { .. })),
            "ambiguous transport loss must retain, not fail, the optimistic row"
        );
        drop(input_tx);
        drop(submission_session_tx);
        dispatcher.await.unwrap();
    }

    #[tokio::test]
    async fn deterministic_rejection_waits_without_spinning_then_retries_exact_fifo_on_wake() {
        let session_id = Uuid::new_v4();
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        let (submission_session_tx, submission_session_rx) =
            watch::channel(SubmissionSessionBinding::new(session_id, 0));
        let (_attachment_ready_tx, attachment_ready_rx) = mpsc::unbounded_channel();
        let (input_tx, input_rx) = mpsc::channel(4);
        let events = Arc::new(Mutex::new(Vec::new()));
        let attempts = Arc::new(Mutex::new(Vec::<(Uuid, serde_json::Value)>::new()));
        let accept_first = Arc::new(AtomicBool::new(false));
        let (attempt_tx, mut attempt_rx) = mpsc::unbounded_channel();
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let dispatcher = tokio::spawn(run_user_submission_dispatcher(
            input_rx,
            UserSubmissionDispatcherContext {
                session_id_state: Arc::new(Mutex::new(session_id)),
                attachment_epoch,
                transition_gate: Arc::new(AsyncMutex::new(())),
                events: events.clone(),
                event_notify: Arc::new(Notify::new()),
                submission_session_rx,
                attachment_ready_rx,
                awaiting_durable: Arc::new(Mutex::new(HashMap::new())),
            },
            {
                let attempts = attempts.clone();
                let accept_first = accept_first.clone();
                move |client_submission_id, _intended_attachment_epoch, submission| {
                    let attempts = attempts.clone();
                    let accept_first = accept_first.clone();
                    let attempt_tx = attempt_tx.clone();
                    async move {
                        attempts.lock().unwrap().push((
                            client_submission_id,
                            serde_json::to_value(submission).unwrap(),
                        ));
                        attempt_tx.send(client_submission_id).unwrap();
                        if client_submission_id == first_id && !accept_first.load(Ordering::Acquire)
                        {
                            Err(UserSubmissionSendError::NotAccepted(
                                "repair required".to_string(),
                            ))
                        } else {
                            Ok(())
                        }
                    }
                }
            },
        ));

        let first = complete_test_submission();
        let first_value = serde_json::to_value(&first).unwrap();
        let mut second = complete_test_submission();
        second.text = "later wire payload".to_string();
        let second_value = serde_json::to_value(&second).unwrap();
        input_tx
            .send(RunnerInput::Submission(Box::new(BoundUserSubmission {
                submission: first,
                optimistic_submission_id: first_id,
                intended_session_id: session_id,
                intended_attachment_epoch: 4,
            })))
            .await
            .unwrap();
        assert_eq!(attempt_rx.recv().await, Some(first_id));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), attempt_rx.recv())
                .await
                .is_err(),
            "a deterministic rejection must not timer-spin"
        );

        input_tx
            .send(RunnerInput::Submission(Box::new(BoundUserSubmission {
                submission: second,
                optimistic_submission_id: second_id,
                intended_session_id: session_id,
                intended_attachment_epoch: 4,
            })))
            .await
            .unwrap();
        assert_eq!(
            attempt_rx.recv().await,
            Some(first_id),
            "later B retries retained A first"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), attempt_rx.recv())
                .await
                .is_err(),
            "a still-rejected A must stop with B retained behind it"
        );

        accept_first.store(true, Ordering::Release);
        submission_session_tx.send_replace(SubmissionSessionBinding::new(session_id, 0));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .unwrap(),
            Some(first_id),
            "the explicit state-change wake retries A"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), attempt_rx.recv())
                .await
                .unwrap(),
            Some(second_id),
            "B is released only after A succeeds"
        );

        {
            let attempts = attempts.lock().unwrap();
            assert_eq!(
                attempts.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
                vec![first_id, first_id, first_id, second_id]
            );
            for (_, payload) in attempts.iter().take(3) {
                assert_eq!(
                    payload, &first_value,
                    "every A retry payload is byte-equivalent"
                );
            }
            assert_eq!(attempts[3].1, second_value);
        }
        assert_eq!(
            drained_event_payloads(&events)
                .iter()
                .filter(|event| matches!(event, TurnEvent::UserMessageDispatchRetained { .. }))
                .count(),
            2,
            "each rejected attempt is visible without becoming terminal"
        );

        drop(input_tx);
        drop(submission_session_tx);
        dispatcher.await.unwrap();
    }

    #[tokio::test]
    async fn permanent_image_upload_failure_is_terminal_and_does_not_block_fifo() {
        let session_id = Uuid::new_v4();
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        let (submission_session_tx, submission_session_rx) =
            watch::channel(SubmissionSessionBinding::new(session_id, 0));
        let (_attachment_ready_tx, attachment_ready_rx) = mpsc::unbounded_channel();
        let (input_tx, input_rx) = mpsc::channel(2);
        let events = Arc::new(Mutex::new(Vec::new()));
        let (delivered_tx, mut delivered_rx) = mpsc::unbounded_channel();
        let failed_id = Uuid::new_v4();
        let delivered_id = Uuid::new_v4();
        let dispatcher = tokio::spawn(run_user_submission_dispatcher(
            input_rx,
            UserSubmissionDispatcherContext {
                session_id_state: Arc::new(Mutex::new(session_id)),
                attachment_epoch,
                transition_gate: Arc::new(AsyncMutex::new(())),
                events: events.clone(),
                event_notify: Arc::new(Notify::new()),
                submission_session_rx,
                attachment_ready_rx,
                awaiting_durable: Arc::new(Mutex::new(HashMap::new())),
            },
            move |client_submission_id, _intended_attachment_epoch, _submission| {
                let delivered_tx = delivered_tx.clone();
                async move {
                    if client_submission_id == failed_id {
                        return Err(classify_image_upload_error(ImageUploadError::Usage(
                            "image is too large".to_string(),
                        )));
                    }
                    delivered_tx.send(client_submission_id).unwrap();
                    Ok(())
                }
            },
        ));

        input_tx
            .send(RunnerInput::SubmissionBatch(vec![
                BoundUserSubmission {
                    submission: complete_test_submission(),
                    optimistic_submission_id: failed_id,
                    intended_session_id: session_id,
                    intended_attachment_epoch: 4,
                },
                BoundUserSubmission {
                    submission: ClientUserSubmission::text("next payload"),
                    optimistic_submission_id: delivered_id,
                    intended_session_id: session_id,
                    intended_attachment_epoch: 4,
                },
            ]))
            .await
            .unwrap();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), delivered_rx.recv())
                .await
                .expect("permanent failure must not wedge the session FIFO"),
            Some(delivered_id)
        );
        assert!(matches!(
            drained_event_payloads(&events).as_slice(),
            [TurnEvent::UserMessageDispatchFailed {
                error,
                optimistic_submission_id,
            }] if error == "image is too large" && *optimistic_submission_id == failed_id
        ));

        drop(input_tx);
        drop(submission_session_tx);
        dispatcher.await.unwrap();
    }

    #[test]
    fn uncertain_image_upload_failures_remain_ambiguous() {
        for error in [
            ImageUploadError::Daemon("daemon unavailable".to_string()),
            ImageUploadError::Transport("socket closed".to_string()),
        ] {
            assert!(matches!(
                classify_image_upload_error(error),
                UserSubmissionSendError::Ambiguous(_)
            ));
        }
    }

    #[test]
    fn storage_failures_leave_user_message_commit_ambiguous() {
        for code in [
            proto::ErrorCode::StorageFull,
            proto::ErrorCode::StorageMemory,
            proto::ErrorCode::StorageReadOnly,
            proto::ErrorCode::StorageIo,
            proto::ErrorCode::StorageCorrupt,
        ] {
            assert!(matches!(
                classify_user_message_response(Err(proto::ErrorPayload {
                    code,
                    message: "database durability boundary was not confirmed".to_string(),
                })),
                Err(UserSubmissionSendError::Ambiguous(_))
            ));
        }
    }

    #[test]
    fn durable_message_terminal_and_replay_outcomes_are_final() {
        assert!(matches!(
            classify_user_message_response(Ok(Response::Ack)),
            Ok(None)
        ));
        assert!(matches!(
            classify_user_message_response(Err(proto::ErrorPayload {
                code: proto::ErrorCode::UserMessageTerminated,
                message: "durably terminal".to_string(),
            })),
            Err(UserSubmissionSendError::Rejected(_))
        ));
        assert!(matches!(
            classify_user_message_response(Err(proto::ErrorPayload {
                code: proto::ErrorCode::UserMessageNotAccepted,
                message: "retry after repair".to_string(),
            })),
            Err(UserSubmissionSendError::NotAccepted(_))
        ));
    }

    #[tokio::test]
    async fn same_session_reconnect_rebinds_and_delivers_the_complete_submission() {
        let session_id = Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(session_id));
        let attachment_epoch = Arc::new(AtomicU64::new(8));
        let transition_gate = Arc::new(AsyncMutex::new(()));
        let expected = complete_test_submission();
        let expected_value = serde_json::to_value(&expected).unwrap();
        let (sent_tx, sent_rx) = oneshot::channel();

        let outcome = dispatch_user_submission_for_current_attachment(
            BoundUserSubmission {
                submission: expected,
                optimistic_submission_id: Uuid::new_v4(),
                intended_session_id: session_id,
                intended_attachment_epoch: 7,
            },
            &session_id_state,
            &attachment_epoch,
            transition_gate,
            move |_client_submission_id, _intended_attachment_epoch, submission| async move {
                sent_tx.send(submission).unwrap();
                Ok(())
            },
        )
        .await;

        assert!(matches!(
            outcome,
            UserSubmissionDispatchOutcome::Delivered { .. }
        ));
        assert_eq!(
            serde_json::to_value(sent_rx.await.unwrap()).unwrap(),
            expected_value
        );
    }

    #[tokio::test]
    async fn replacement_session_defers_exact_payload_until_original_session_reattaches() {
        let old_session_id = Uuid::new_v4();
        let replacement_session_id = Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(replacement_session_id));
        let attachment_epoch = Arc::new(AtomicU64::new(8));
        let transition_gate = Arc::new(AsyncMutex::new(()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let (submission_session_tx, submission_session_rx) =
            watch::channel(SubmissionSessionBinding::new(replacement_session_id, 0));
        let (_attachment_ready_tx, attachment_ready_rx) = mpsc::unbounded_channel();
        let (input_tx, input_rx) = mpsc::channel(2);
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let expected = complete_test_submission();
        let expected_value = serde_json::to_value(&expected).unwrap();
        let dispatcher = tokio::spawn(run_user_submission_dispatcher(
            input_rx,
            UserSubmissionDispatcherContext {
                session_id_state: session_id_state.clone(),
                attachment_epoch: attachment_epoch.clone(),
                transition_gate,
                events: events.clone(),
                event_notify: notify.clone(),
                submission_session_rx,
                attachment_ready_rx,
                awaiting_durable: Arc::new(Mutex::new(HashMap::new())),
            },
            move |_client_submission_id, _intended_attachment_epoch, submission| {
                let sent_tx = sent_tx.clone();
                async move {
                    sent_tx.send(submission).unwrap();
                    Ok(())
                }
            },
        ));

        input_tx
            .send(RunnerInput::Submission(Box::new(BoundUserSubmission {
                submission: expected,
                optimistic_submission_id: Uuid::new_v4(),
                intended_session_id: old_session_id,
                intended_attachment_epoch: 7,
            })))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .expect("dispatcher reports attachment-scoped retention");
        assert!(matches!(
            sent_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            drained_event_payloads(&events).as_slice(),
            [TurnEvent::Notice { text }] if text.contains("was retained")
        ));

        // Mirror AgentRunner::apply_session_switch_outcome ordering: update
        // the applied identity first, then publish the recovery wake. The
        // earlier transport-epoch signal is deliberately not involved.
        *session_id_state.lock().unwrap() = old_session_id;
        attachment_epoch.store(9, Ordering::Release);
        submission_session_tx.send_replace(SubmissionSessionBinding::new(old_session_id, 9));

        let delivered = tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
            .await
            .expect("reattach releases retained payload")
            .expect("dispatcher remains live");
        assert_eq!(serde_json::to_value(delivered).unwrap(), expected_value);
        assert!(matches!(
            sent_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(
            drained_event_payloads(&events)
                .iter()
                .all(|event| { !matches!(event, TurnEvent::UserMessageDispatchFailed { .. }) })
        );

        drop(input_tx);
        dispatcher.await.unwrap();
    }

    #[tokio::test]
    async fn current_submission_failure_is_enqueued_before_session_transition_can_continue() {
        let session_id = Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(session_id));
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        let transition_gate = Arc::new(AsyncMutex::new(()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());

        let optimistic_submission_id = Uuid::new_v4();
        let outcome = dispatch_user_submission_for_current_attachment(
            BoundUserSubmission {
                submission: ClientUserSubmission::text("current payload".to_string()),
                optimistic_submission_id,
                intended_session_id: session_id,
                intended_attachment_epoch: 4,
            },
            &session_id_state,
            &attachment_epoch,
            transition_gate.clone(),
            |_client_submission_id, _intended_attachment_epoch, _submission| async {
                Err(UserSubmissionSendError::Rejected(
                    "transport stopped".to_string(),
                ))
            },
        )
        .await;
        assert!(transition_gate.try_lock().is_err());
        let awaiting_durable = Arc::new(Mutex::new(HashMap::new()));

        let _ = record_user_submission_dispatch_outcome(
            outcome,
            &events,
            &notify,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &awaiting_durable,
        );
        assert!(transition_gate.try_lock().is_ok());
        assert!(matches!(
            drained_event_payloads(&events).as_slice(),
            [TurnEvent::UserMessageDispatchFailed {
                error,
                optimistic_submission_id: failed_id,
            }] if error == "transport stopped" && *failed_id == optimistic_submission_id
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn skill_inventory_refresh_does_not_block_event_drain() {
        let attach_context = test_attach_context("/tmp/project");
        let skill_inventory_names = Arc::new(Mutex::new(None));
        let session_id = Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(session_id));
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let (refresh_tx, refresh_rx) = watch::channel(0);
        let (list_seen_tx, list_seen_rx) = oneshot::channel();
        let list_seen_tx = Arc::new(Mutex::new(Some(list_seen_tx)));
        let refresh_task = tokio::spawn(run_skill_inventory_refresh_with_request(
            attach_context.clone(),
            session_id_state,
            active_agent,
            skill_inventory_names,
            refresh_rx,
            move |project_root, got_session_id, selected_agent| {
                let list_seen_tx = list_seen_tx.clone();
                async move {
                    assert_eq!(project_root, "/tmp/project");
                    assert_eq!(got_session_id, session_id);
                    assert_eq!(selected_agent, "Build");
                    if let Some(tx) = list_seen_tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    std::future::pending::<anyhow::Result<Response>>().await
                }
            },
        ));
        let last_applied_seq = Arc::new(Mutex::new(None));
        let (mut state, events) =
            test_event_state(session_id, attach_context, last_applied_seq, refresh_tx);

        state.handle_regular_event(foreground_target_event(session_id));
        tokio::time::timeout(Duration::from_secs(1), list_seen_rx)
            .await
            .expect("get_inventory_bundle should be requested")
            .expect("get_inventory_bundle observer should stay alive");

        state.handle_regular_event(proto::Event::AssistantText {
            session_id,
            agent: "Build".to_string(),
            text: "still draining".to_string(),
            presentation_text: None,
            reasoning: String::new(),
            seq: Some(1),
            response_performance: None,
        });
        let drained = drained_event_payloads(&events);
        assert!(matches!(
            drained.as_slice(),
            [TurnEvent::ForegroundInputTarget { .. }, TurnEvent::AssistantText { text, .. }]
                if text == "still draining"
        ));

        refresh_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn skill_inventory_refresh_coalesces_bursts() {
        let attach_context = test_attach_context("/tmp/project");
        let skill_inventory_names = Arc::new(Mutex::new(None));
        let session_id = Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(session_id));
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let (refresh_tx, refresh_rx) = watch::channel(0);
        let (first_seen_tx, first_seen_rx) = oneshot::channel();
        let (release_first_tx, release_first_rx) = oneshot::channel();
        let (count_tx, count_rx) = oneshot::channel();
        let request_count = Arc::new(Mutex::new(0usize));
        let first_seen_tx = Arc::new(Mutex::new(Some(first_seen_tx)));
        let release_first_rx = Arc::new(tokio::sync::Mutex::new(Some(release_first_rx)));
        let refresh_task = tokio::spawn(run_skill_inventory_refresh_with_request(
            attach_context.clone(),
            session_id_state,
            active_agent,
            skill_inventory_names.clone(),
            refresh_rx,
            {
                let request_count = request_count.clone();
                let first_seen_tx = first_seen_tx.clone();
                let release_first_rx = release_first_rx.clone();
                move |project_root, _session_id, _selected_agent| {
                    let request_count = request_count.clone();
                    let first_seen_tx = first_seen_tx.clone();
                    let release_first_rx = release_first_rx.clone();
                    async move {
                        assert_eq!(project_root, "/tmp/project");
                        let count = {
                            let mut guard = request_count.lock().unwrap();
                            *guard += 1;
                            *guard
                        };
                        if count == 1 {
                            if let Some(tx) = first_seen_tx.lock().unwrap().take() {
                                let _ = tx.send(());
                            }
                            let rx = release_first_rx.lock().await.take();
                            if let Some(rx) = rx {
                                let _ = rx.await;
                            }
                        }
                        Ok(Response::InventoryBundle {
                            selected_agent: "Build".into(),
                            agents: Vec::new(),
                            models: Vec::new(),
                            skills: vec![test_skill("refreshed")],
                            session_generation: 0,
                            config_generation: 0,
                            inventory_generation: 0,
                        })
                    }
                }
            },
        ));
        let last_applied_seq = Arc::new(Mutex::new(None));
        let (mut state, _events) =
            test_event_state(session_id, attach_context, last_applied_seq, refresh_tx);

        for _ in 0..5 {
            state.handle_regular_event(foreground_target_event(session_id));
        }
        tokio::time::timeout(Duration::from_secs(1), first_seen_rx)
            .await
            .expect("first get_inventory_bundle should be requested")
            .expect("first get_inventory_bundle observer should stay alive");
        let _ = release_first_tx.send(());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let count = *request_count.lock().unwrap();
                if count >= 1 && skill_inventory_names.lock().unwrap().is_some() {
                    let _ = count_tx.send(count);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("coalesced refresh should complete");
        let request_count = count_rx
            .await
            .expect("request count sender should stay alive");
        assert!(request_count >= 1);
        assert!(
            request_count < 5,
            "watch refresh should coalesce burst, saw {request_count} requests"
        );

        refresh_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lag_marker_triggers_since_seq_reattach() {
        let session_id = Uuid::new_v4();
        let attach_context = test_attach_context("/tmp/project");
        let (attachment_epoch, mut client_epoch_rx) = {
            let context = attach_context.read().await;
            (
                context.attachment_epoch.clone(),
                context.client_epoch_tx.subscribe(),
            )
        };
        let (skill_refresh_tx, _rx) = watch::channel(0);
        let last_applied_seq = Arc::new(Mutex::new(Some(4)));
        let (mut state, events) = test_event_state(
            session_id,
            attach_context,
            last_applied_seq.clone(),
            skill_refresh_tx,
        );

        assert!(
            state
                .handle_event_with_resync(
                    proto::Event::EventStreamLagged {
                        session_id: Some(session_id),
                        dropped: 5,
                    },
                    move |session_id, attach_context, last| {
                        async move {
                            request_attach_payload(
                                session_id,
                                &attach_context,
                                &last,
                                cockpit_proto::PROTOCOL_VERSION,
                                |request| async move {
                                    match request {
                                        Request::AttachExistingCodeRootV1(request) => {
                                            assert_eq!(request.root_id.0, session_id);
                                            assert_eq!(request.since_seq, Some(4));
                                        }
                                        other => panic!("expected attach request, got {other:?}"),
                                    }
                                    Ok(Ok(attached_response(
                                        session_id,
                                        vec![proto::HistoryEntry::Assistant {
                                            agent: "Build".to_string(),
                                            text: "replayed".to_string(),
                                            presentation_text: None,
                                            reasoning: String::new(),
                                            response_performance: None,
                                            ts_ms: 0,
                                            seq: 5,
                                        }],
                                    )))
                                },
                            )
                            .await
                        }
                    }
                )
                .await
        );
        assert_eq!(current_last_applied_seq(&last_applied_seq), Some(5));
        assert_eq!(attachment_epoch.load(Ordering::Acquire), 1);
        client_epoch_rx
            .changed()
            .await
            .expect("successful lag re-attach must publish a new client epoch");
        assert_eq!(*client_epoch_rx.borrow_and_update(), 1);
        let drained = drained_event_payloads(&events);
        assert!(matches!(
            drained.as_slice(),
            [TurnEvent::HistoryReplay { entries }, TurnEvent::DaemonLinkResynced { active_model_state: None }]
                if matches!(entries.as_slice(), [proto::HistoryEntry::Assistant { text, seq: 5, .. }] if text == "replayed")
        ));
    }

    #[tokio::test]
    async fn local_reconnect_attach_retains_authoritative_active_model_snapshot() {
        let session_id = Uuid::new_v4();
        let expected = proto::ActiveModelState {
            selection: cockpit_config::providers::ActiveModelRef {
                provider: "local".to_string(),
                model: "reconnected".to_string(),
                reasoning_effort: Some(cockpit_config::providers::ActiveReasoningEffort {
                    value: "high".to_string(),
                }),
                thinking_mode: Some(cockpit_config::providers::ThinkingMode::High),
                prompt_cache_retention: Some(
                    cockpit_config::providers::PromptCacheRetention::Extended,
                ),
            },
            default_selection: None,
            diverged: true,
            generation: 0,
        };
        let mut response = attached_response(session_id, Vec::new());
        let Response::Attached {
            active_model_state, ..
        } = &mut response
        else {
            unreachable!("attached_response always returns Attached")
        };
        *active_model_state = Some(expected.clone());
        let attach_context = AttachRequestContext {
            session_id: Some(session_id),
            project_root: "/tmp/project".to_string(),
            no_sandbox: false,
            session_entry_mode: proto::SessionEntryMode::Code,
            env_snapshot: cockpit_proto::EnvSnapshotWire {
                source: cockpit_proto::EnvSnapshotSource::TuiShell,
                digest: String::new(),
                vars: std::collections::HashMap::new(),
            },
            transition_gate: Arc::new(AsyncMutex::new(())),
            client_epoch_tx: watch::channel(0).0,
            attachment_epoch: Arc::new(AtomicU64::new(0)),
        };
        let last_applied_seq = Arc::new(Mutex::new(Some(9)));

        let payload = request_attach_payload(
            session_id,
            &attach_context,
            &last_applied_seq,
            proto::PROTOCOL_VERSION,
            |request| async move {
                assert!(matches!(
                    request,
                    Request::AttachExistingCodeRootV1(request)
                        if request.root_id.0 == session_id && request.since_seq == Some(9)
                ));
                Ok(Ok(response))
            },
        )
        .await;
        let payload = match payload {
            Ok(payload) => payload,
            Err(_) => panic!("reconnect attach snapshot must parse"),
        };

        assert_eq!(payload.active_model_state, Some(expected));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lag_marker_resync_emits_no_reconnect_chrome() {
        let session_id = Uuid::new_v4();
        let attach_context = test_attach_context("/tmp/project");
        let (skill_refresh_tx, _rx) = watch::channel(0);
        let last_applied_seq = Arc::new(Mutex::new(Some(1)));
        let (mut state, events) = test_event_state(
            session_id,
            attach_context,
            last_applied_seq,
            skill_refresh_tx,
        );

        assert!(
            state
                .handle_event_with_resync(
                    proto::Event::EventStreamLagged {
                        session_id: None,
                        dropped: 1,
                    },
                    move |session_id, _attach_context, _last| {
                        async move {
                            attach_payload_from_response(Ok(attached_response(
                                session_id,
                                vec![proto::HistoryEntry::Assistant {
                                    agent: "Build".to_string(),
                                    text: "replayed".to_string(),
                                    presentation_text: None,
                                    reasoning: String::new(),
                                    response_performance: None,
                                    ts_ms: 0,
                                    seq: 2,
                                }],
                            )))
                        }
                    }
                )
                .await
        );
        let drained = drained_event_payloads(&events);
        assert!(!drained.iter().any(|event| matches!(
            event,
            TurnEvent::DaemonLinkReconnecting { .. } | TurnEvent::DaemonLinkReconnected { .. }
        )));
        assert!(
            drained
                .iter()
                .any(|event| matches!(event, TurnEvent::DaemonLinkResynced { .. }))
        );
        assert!(
            drained
                .iter()
                .any(|event| matches!(event, TurnEvent::HistoryReplay { .. }))
        );
    }

    fn runner_with_client_task(handle: JoinHandle<()>) -> AgentRunner {
        runner_with_client_task_and_events(handle, Arc::new(Mutex::new(Vec::new())))
    }

    fn runner_with_client_task_and_events(
        handle: JoinHandle<()>,
        events: Arc<Mutex<Vec<QueuedTurnEvent>>>,
    ) -> AgentRunner {
        let mut client_tasks = ClientTasks::default();
        client_tasks.push(handle);
        AgentRunner::test_fixture(TestRunnerOverrides {
            events: Some(events),
            client_tasks: Some(client_tasks),
            ..Default::default()
        })
    }

    async fn assert_task_future_dropped(dropped: Arc<AtomicBool>) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("runner drop should abort and drop client task futures");
    }

    #[tokio::test]
    async fn dropping_agent_runner_aborts_client_tasks() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(dropped.clone());
        let handle = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });

        let runner = runner_with_client_task(handle);
        drop(runner);

        assert_task_future_dropped(dropped).await;
    }

    #[tokio::test]
    async fn dropping_agent_runner_stops_late_event_buffer_writes() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let task_events = events.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            task_events.lock().unwrap().push(QueuedTurnEvent {
                attachment_epoch: 0,
                event: TurnEvent::Notice {
                    text: "late".into(),
                },
            });
        });

        let runner = runner_with_client_task_and_events(handle, events.clone());
        drop(runner);
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(
            events.lock().unwrap().is_empty(),
            "aborted client task must not append late events after runner drop"
        );
    }

    #[test]
    fn agent_runner_switch_session_replaces_session_id_in_place() {
        let old_session_id = uuid::Uuid::new_v4();
        let new_session_id = uuid::Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(old_session_id));
        let last_applied_seq = Arc::new(Mutex::new(Some(2)));
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let history = vec![proto::HistoryEntry::Assistant {
            agent: "Plan".to_string(),
            text: "restored".to_string(),
            presentation_text: None,
            reasoning: String::new(),
            response_performance: None,
            ts_ms: 0,
            seq: 7,
        }];

        let outcome = session_switch_outcome_from_attached(
            SessionSwitchAttached {
                session_id: new_session_id,
                short_id: "def456".to_string(),
                active_agent: "Plan".to_string(),
                active_agent_path: Vec::new(),
                foreground_target: None,
                active_model_state: None,
                session_entry_mode: proto::SessionEntryMode::Code,
                project_id: "new-project".to_string(),
                history,
                paused_work: Vec::new(),
                repair_required: None,
                resume_compaction_offer: None,
                btw_fork: None,
                daemon_version: "test".to_string(),
                daemon_compatible: true,
            },
            SessionTarget::Resume {
                session_id: new_session_id,
                since_seq: Some(2),
            },
        );
        apply_session_switch_state(
            &outcome,
            &session_id_state,
            &last_applied_seq,
            &active_agent,
            &active_agent_path,
        );

        assert_eq!(
            *session_id_state.lock().unwrap(),
            new_session_id,
            "switch must replace the live session id in place"
        );
        assert_eq!(outcome.session_id, new_session_id);
        assert_eq!(outcome.short_id, "def456");
        assert_eq!(outcome.project_id, "new-project");
        assert_eq!(&*active_agent.lock().unwrap(), "Plan");
        assert_eq!(
            &*active_agent_path.lock().unwrap(),
            &vec!["Plan".to_string()]
        );
        assert_eq!(*last_applied_seq.lock().unwrap(), Some(7));
    }

    #[tokio::test]
    async fn new_session_swap_sends_single_attach_request() {
        let initial_session_id = uuid::Uuid::new_v4();
        let new_session_id = uuid::Uuid::new_v4();
        let attach_context = Arc::new(RwLock::new(AttachRequestContext {
            session_id: Some(initial_session_id),
            project_root: "/tmp/project".to_string(),
            no_sandbox: true,
            session_entry_mode: proto::SessionEntryMode::Code,
            env_snapshot: cockpit_proto::EnvSnapshotWire {
                source: cockpit_proto::EnvSnapshotSource::TuiShell,
                digest: String::new(),
                vars: std::collections::HashMap::new(),
            },
            transition_gate: Arc::new(AsyncMutex::new(())),
            client_epoch_tx: watch::channel(0).0,
            attachment_epoch: Arc::new(AtomicU64::new(0)),
        }));
        let last_applied_seq = Arc::new(Mutex::new(Some(9)));
        let session_id_state = Arc::new(Mutex::new(initial_session_id));
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();

        let outcome = switch_session_with_attach_request(
            attach_context,
            SessionTarget::New,
            cockpit_proto::PROTOCOL_VERSION,
            move |request| {
                captured.lock().unwrap().push(request);
                async move {
                    Ok(Ok(Response::Attached {
                        session_id: new_session_id,
                        short_id: "fresh1".to_string(),
                        project_root: "/tmp/project".to_string(),
                        project_id: "project".to_string(),
                        active_agent: "Build".to_string(),
                        active_agent_path: vec!["Build".to_string()],
                        foreground_target: None,
                        active_subagent: None,
                        active_model_state: None,
                        session_entry_mode: proto::SessionEntryMode::Code,
                        history: Vec::new(),
                        paused_work: Vec::new(),
                        repair_required: None,
                        resume_compaction_offer: None,
                        daemon_version: "test".to_string(),
                        compatible: true,
                        env_baseline: None,
                        env_session: None,
                        env_drift: None,
                        env_policy_applied: cockpit_proto::EnvDriftPolicy::Client,
                        btw_fork: None,
                    }))
                }
            },
        )
        .await
        .expect("switch should attach");

        assert_eq!(outcome.session_id, new_session_id);
        assert_eq!(
            *session_id_state.lock().unwrap(),
            initial_session_id,
            "switch future must not mutate runner state before the app accepts its result"
        );
        apply_session_switch_state(
            &outcome,
            &session_id_state,
            &last_applied_seq,
            &active_agent,
            &active_agent_path,
        );
        assert_eq!(*session_id_state.lock().unwrap(), new_session_id);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        match &requests[0] {
            Request::CreateCodeRootV1(request) => {
                assert_eq!(request.workspace_selector.path, "/tmp/project");
                assert!(request.options.no_sandbox);
                assert!(request.options.interactive);
            }
            other => panic!("expected one attach request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn successful_new_attach_cancels_the_outgoing_turn_exactly_once_when_requested() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();

        cancel_outgoing_turn_after_successful_attach(true, move || {
            captured.lock().unwrap().push(Request::CancelTurn);
            async { Ok(Ok(Response::Ack)) }
        })
        .await;

        assert!(matches!(
            requests.lock().unwrap().as_slice(),
            [Request::CancelTurn]
        ));
    }

    #[tokio::test]
    async fn idle_new_attach_does_not_cancel_the_outgoing_session() {
        let called = Arc::new(AtomicBool::new(false));
        let called_in_request = called.clone();

        cancel_outgoing_turn_after_successful_attach(false, move || {
            called_in_request.store(true, Ordering::Release);
            async { Ok(Ok(Response::Ack)) }
        })
        .await;

        assert!(!called.load(Ordering::Acquire));
    }

    #[test]
    fn proto_lifecycle_turn_id_maps_to_turn_events() {
        let session_id = uuid::Uuid::new_v4();

        let event = proto_event_to_turn_event(proto::Event::ThinkingStarted {
            session_id,
            agent: "Build".to_string(),
            turn_id: Some("turn-1".to_string()),
        })
        .expect("thinking event maps");
        assert!(matches!(
            event,
            TurnEvent::ThinkingStarted {
                agent,
                turn_id: Some(turn_id),
            } if agent == "Build" && turn_id == "turn-1"
        ));

        let event = proto_event_to_turn_event(proto::Event::AgentIdle {
            session_id,
            turn_id: Some("turn-1".to_string()),
            reason: cockpit_proto::IdleReason::Completed,
        })
        .expect("idle event maps");
        assert!(matches!(
            event,
            TurnEvent::AgentIdle {
                turn_id: Some(turn_id),
                reason: cockpit_proto::IdleReason::Completed,
            } if turn_id == "turn-1"
        ));
    }

    #[test]
    fn agent_tree_invalidation_does_not_advance_transcript_cursor_or_drop_late_transcript() {
        let session_id = uuid::Uuid::new_v4();
        let event = proto::Event::AgentTreeChanged {
            session_id,
            session_event_seq: 47,
            transition: proto::AgentTreeTransition::AttentionStateChanged,
            subject_kind: proto::AgentTreeEventSubject::Decision,
            subject_id: uuid::Uuid::new_v4(),
        };
        assert_eq!(event_session(&event), Some(session_id));
        assert_eq!(event_persisted_seq(&event), None);
        assert!(
            matches!(
                proto_event_to_turn_event(event.clone()),
                Some(TurnEvent::AgentTreeChanged { session_id: mapped })
                    if mapped == session_id
            ),
            "AgentTreeChanged must refresh setup/tree surfaces without becoming a transcript row"
        );
        // Event streams can reconnect with a tree invalidation before an
        // earlier transcript event. Tree state has no local renderer/cursor,
        // so it must not make that valid transcript event look stale.
        let cursor = Arc::new(Mutex::new(Some(45)));
        if let Some(seq) = event_persisted_seq(&event) {
            update_last_applied_seq(&cursor, seq);
        }
        assert_eq!(current_last_applied_seq(&cursor), Some(45));
        let transcript = proto::Event::AssistantText {
            session_id,
            agent: "Build".to_string(),
            text: "arrived after tree invalidation".to_string(),
            presentation_text: None,
            reasoning: String::new(),
            seq: Some(46),
            response_performance: None,
        };
        let seq = event_persisted_seq(&transcript).expect("transcript events own cursor order");
        assert!(current_last_applied_seq(&cursor).is_none_or(|last| seq > last));
        update_last_applied_seq(&cursor, seq);
        assert_eq!(current_last_applied_seq(&cursor), Some(46));
    }

    #[test]
    fn tool_progress_proto_round_trip() {
        let session_id = uuid::Uuid::new_v4();
        let event = proto::Event::ToolProgress {
            session_id,
            call_id: "call-1".to_string(),
            done: 3400,
            total: 12000,
            unit: "files".to_string(),
        };
        assert_eq!(event_session(&event), Some(session_id));

        match proto_event_to_turn_event(event) {
            Some(TurnEvent::ToolProgress(progress)) => {
                assert_eq!(progress.call_id, "call-1");
                assert_eq!(progress.done, 3400);
                assert_eq!(progress.total, 12000);
                assert_eq!(progress.unit, "files");
            }
            other => panic!("expected tool progress, got {other:?}"),
        }
    }

    #[test]
    fn tool_progress_routes_by_session() {
        let session_id = uuid::Uuid::new_v4();
        let other_session_id = uuid::Uuid::new_v4();
        let progress = proto::Event::ToolProgress {
            session_id,
            call_id: "call-1".to_string(),
            done: 1,
            total: 2,
            unit: "files".to_string(),
        };
        assert_eq!(event_session(&progress), Some(session_id));
        assert!(!is_global_event(&progress));

        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let primary_agent = Arc::new(Mutex::new("Build".to_string()));
        let last_applied_seq = Arc::new(Mutex::new(None));
        let awaiting_durable = Arc::new(Mutex::new(HashMap::new()));
        let attachment_epoch = Arc::new(AtomicU64::new(0));
        let incoming = IncomingEventContext {
            session_id,
            client_epoch: 0,
            attachment_epoch: &attachment_epoch,
            events: &events,
            event_notify: &notify,
            active_agent: &active_agent,
            active_agent_path: &active_agent_path,
            primary_agent: &primary_agent,
            last_applied_seq: &last_applied_seq,
            awaiting_durable: &awaiting_durable,
        };

        apply_incoming_event(
            proto::Event::ToolProgress {
                session_id: other_session_id,
                call_id: "call-2".to_string(),
                done: 1,
                total: 2,
                unit: "files".to_string(),
            },
            &incoming,
        );
        assert!(events.lock().unwrap().is_empty());

        apply_incoming_event(progress, &incoming);
        let drained = events.lock().unwrap();
        assert_eq!(drained.len(), 1);
        assert!(matches!(
            &drained[0].event,
            TurnEvent::ToolProgress(progress)
                if progress.call_id == "call-1" && progress.done == 1 && progress.total == 2
        ));
    }

    #[test]
    fn nested_turn_event_routes_and_decodes() {
        let sid = uuid::Uuid::new_v4();
        let event = proto::Event::NestedTurn {
            session_id: sid,
            task_call_id: "task-1".into(),
            label: "default".into(),
            parent_task_call_id: Some("parent-task".into()),
            inner: Box::new(proto::Event::ReasoningDelta {
                session_id: sid,
                agent: "Explore".into(),
                delta: "thinking".into(),
            }),
        };
        assert_eq!(event_session(&event), Some(sid));
        match proto_event_to_turn_event(event) {
            Some(TurnEvent::NestedTurn {
                task_call_id,
                label,
                parent_task_call_id,
                inner,
            }) => {
                assert_eq!(task_call_id, "task-1");
                assert_eq!(label, "default");
                assert_eq!(parent_task_call_id.as_deref(), Some("parent-task"));
                assert!(matches!(
                    inner.as_ref(),
                    TurnEvent::ReasoningDelta { agent, delta }
                        if agent == "Explore" && delta == "thinking"
                ));
            }
            other => panic!("expected nested turn event, got {other:?}"),
        }
    }

    #[test]
    fn subagent_routing_amend_roundtrips_through_agent_runner() {
        let sid = uuid::Uuid::new_v4();
        let routing = serde_json::json!({
            "provider": "test-provider",
            "resolved_model": "child-model",
            "fallback_decision": "backup",
        });
        let event = proto::Event::SubagentRouting {
            session_id: sid,
            task_call_id: "task-1".into(),
            label: "second".into(),
            child: "explore".into(),
            provider: "test-provider".into(),
            model: "child-model".into(),
            model_trusted: false,
            routing: routing.clone(),
        };

        assert_eq!(event_session(&event), Some(sid));
        match proto_event_to_turn_event(event) {
            Some(TurnEvent::SubagentRouting {
                task_call_id,
                label,
                child,
                provider,
                model,
                model_trusted,
                routing: actual_routing,
            }) => {
                assert_eq!(task_call_id, "task-1");
                assert_eq!(label, "second");
                assert_eq!(child, "explore");
                assert_eq!(provider, "test-provider");
                assert_eq!(model, "child-model");
                assert!(!model_trusted);
                assert_eq!(actual_routing, routing);
            }
            other => panic!("expected subagent routing amend, got {other:?}"),
        }
    }

    #[test]
    fn daemon_global_events_bypass_session_filter_and_translate() {
        let draining = proto::Event::DaemonDraining { forced: true };
        assert!(event_session(&draining).is_none());
        assert!(is_global_event(&draining));
        assert!(matches!(
            proto_event_to_turn_event(draining),
            Some(TurnEvent::DaemonDraining { forced: true })
        ));

        let lifetime = proto::Event::DaemonLifetimeChanged {
            ephemeral_owner: false,
        };
        assert!(event_session(&lifetime).is_none());
        assert!(is_global_event(&lifetime));
        assert!(
            proto_event_to_turn_event(lifetime).is_none(),
            "lifetime updates runner state without adding a history event"
        );

        let owner = std::sync::atomic::AtomicBool::new(true);
        apply_daemon_lifetime_event(
            &proto::Event::DaemonLifetimeChanged {
                ephemeral_owner: false,
            },
            &owner,
        );
        assert!(
            !owner.load(std::sync::atomic::Ordering::Acquire),
            "a second attached TUI must stop using its stale ephemeral policy"
        );

        let image_config_changed = proto::Event::ImageControlConfigChanged {
            event: proto::image_control::ImageControlEventV1::config_changed(
                "daemon".into(),
                "project".into(),
                "/canonical/project".into(),
                "/canonical/project/config.json".into(),
                "revision".into(),
                proto::image_control::ImageConfigMutationCapabilityV1::new("cc".repeat(32)),
                1,
                proto::image_control::ImageConfigChangeSetSafeV1::new("1".into(), vec![]),
            ),
        };
        assert!(event_session(&image_config_changed).is_none());
        assert!(is_global_event(&image_config_changed));
        assert!(
            proto_event_to_turn_event(image_config_changed).is_none(),
            "image-control config changes are not chat-history events"
        );

        let meta = cockpit_proto::EnvSnapshotMeta {
            source: cockpit_proto::EnvSnapshotSource::DaemonStart,
            digest: "digest".into(),
            key_count: 3,
            path_entry_count: 1,
        };
        let drift = cockpit_proto::EnvDiffSummary {
            baseline_digest: "base".into(),
            candidate_digest: "candidate".into(),
            added_keys: 1,
            removed_keys: 2,
            changed_keys: 3,
            changed_secret_keys: vec!["TOKEN".into()],
            path_added: Vec::new(),
            path_removed: Vec::new(),
        };
        let warning = proto::Event::EnvDriftWarning {
            baseline: meta.clone(),
            candidate: meta,
            diff: drift,
            policy: cockpit_proto::EnvDriftPolicy::Daemon,
        };
        assert!(event_session(&warning).is_none());
        assert!(is_global_event(&warning));
        match proto_event_to_turn_event(warning) {
            Some(TurnEvent::Notice { text }) => {
                assert!(text.contains("environment differs"), "{text}");
                assert!(text.contains("1 added, 2 removed, 3 changed"), "{text}");
            }
            other => panic!("expected env drift notice, got {other:?}"),
        }
    }

    #[test]
    fn since_seq_replay_and_live_tool_events_are_seq_idempotent() {
        let sid = uuid::Uuid::new_v4();
        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let primary_agent = Arc::new(Mutex::new("Build".to_string()));
        let last = Arc::new(Mutex::new(Some(5)));
        let awaiting_durable = Arc::new(Mutex::new(HashMap::new()));
        let attachment_epoch = Arc::new(AtomicU64::new(0));
        let incoming = IncomingEventContext {
            session_id: sid,
            client_epoch: 0,
            attachment_epoch: &attachment_epoch,
            events: &events,
            event_notify: &notify,
            active_agent: &active_agent,
            active_agent_path: &active_agent_path,
            primary_agent: &primary_agent,
            last_applied_seq: &last,
            awaiting_durable: &awaiting_durable,
        };

        apply_incoming_event(
            proto::Event::AssistantText {
                session_id: sid,
                agent: "Build".to_string(),
                text: "duplicate".to_string(),
                presentation_text: None,
                reasoning: String::new(),
                seq: Some(5),
                response_performance: None,
            },
            &incoming,
        );
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(current_last_applied_seq(&last), Some(5));

        apply_incoming_event(
            proto::Event::HistoryReplay {
                session_id: sid,
                max_seq: 7,
                entries: vec![
                    proto::HistoryEntry::ToolCall {
                        seq: 6,
                        agent: "Build".to_string(),
                        call_id: "tool-1".to_string(),
                        parent_call_id: None,
                        parent_child_index: None,
                        tool: "read".to_string(),
                        mcp_server: None,
                        mcp_builtin: None,
                        mcp_kind: None,
                        original_input: serde_json::json!({"path": "src/lib.rs"}),
                        wire_input: serde_json::json!({"path": "src/lib.rs"}),
                        recovery_kind: None,
                        recovery_stage: None,
                        output: "body".to_string(),
                        hard_fail: false,
                        truncated: false,
                        hint: None,
                    },
                    proto::HistoryEntry::Assistant {
                        agent: "Build".to_string(),
                        text: "replayed".to_string(),
                        presentation_text: None,
                        reasoning: String::new(),
                        response_performance: None,
                        ts_ms: 0,
                        seq: 7,
                    },
                ],
            },
            &incoming,
        );
        assert_eq!(current_last_applied_seq(&last), Some(7));

        apply_incoming_event(
            proto::Event::ToolEnd {
                session_id: sid,
                agent: "Build".to_string(),
                call_id: "tool-1".to_string(),
                tool: "read".to_string(),
                output: "overlap".to_string(),
                truncated: false,
                seq: Some(7),
                hint: None,
            },
            &incoming,
        );
        assert_eq!(events.lock().unwrap().len(), 1);

        apply_incoming_event(
            proto::Event::ToolEnd {
                session_id: sid,
                agent: "Build".to_string(),
                call_id: "tool-2".to_string(),
                tool: "bash".to_string(),
                output: "live".to_string(),
                truncated: false,
                seq: Some(8),
                hint: None,
            },
            &incoming,
        );

        let drained = drained_event_payloads(&events);
        assert_eq!(drained.len(), 2);
        assert!(matches!(drained[0], TurnEvent::HistoryReplay { .. }));
        assert!(matches!(
            &drained[1],
            TurnEvent::ToolEnd {
                output,
                seq: Some(8),
                ..
            } if output == "live"
        ));
        assert_eq!(current_last_applied_seq(&last), Some(8));
    }

    struct FixedJitter {
        values: Mutex<std::collections::VecDeque<u64>>,
        seen_upper_bounds: Mutex<Vec<u64>>,
    }

    impl JitterSource for FixedJitter {
        fn duration_up_to(&self, cap: Duration) -> Duration {
            let inclusive_upper = cap.as_millis().min(u128::from(u64::MAX)) as u64;
            self.seen_upper_bounds.lock().unwrap().push(inclusive_upper);
            let millis = self
                .values
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(inclusive_upper);
            Duration::from_millis(millis)
        }
    }

    #[test]
    fn reconnect_backoff_uses_injected_jitter_rising_floor_and_cap() {
        let jitter = FixedJitter {
            values: Mutex::new([0, 500, 1_500, 60_000].into()),
            seen_upper_bounds: Mutex::new(Vec::new()),
        };
        let mut backoff = ReconnectBackoff::with_jitter(jitter);

        assert_eq!(backoff.next_delay(), Duration::from_millis(500));
        assert_eq!(backoff.next_delay(), Duration::from_millis(1_000));
        assert_eq!(backoff.next_delay(), Duration::from_millis(2_000));
        assert_eq!(backoff.next_delay(), Duration::from_secs(30));
        assert_eq!(
            *backoff.jitter.seen_upper_bounds.lock().unwrap(),
            vec![500, 1_000, 2_000, 4_000]
        );
    }

    #[tokio::test]
    async fn event_forward_stamps_selected_client_epoch_not_current_atomic() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let selected_client_epoch = 4_u64;
        // Simulate a forwarder that captured epoch 4 when selecting its client,
        // then the authoritative atomic advances before enqueue.
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        attachment_epoch.store(9, Ordering::Release);
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let primary_agent = Arc::new(Mutex::new("Build".to_string()));
        let last_applied_seq = Arc::new(Mutex::new(None));
        let awaiting_durable = Arc::new(Mutex::new(HashMap::new()));
        let session_id = Uuid::new_v4();
        let ctx = IncomingEventContext {
            session_id,
            client_epoch: selected_client_epoch,
            attachment_epoch: &attachment_epoch,
            events: &events,
            event_notify: &notify,
            active_agent: &active_agent,
            active_agent_path: &active_agent_path,
            primary_agent: &primary_agent,
            last_applied_seq: &last_applied_seq,
            awaiting_durable: &awaiting_durable,
        };
        apply_incoming_event(
            proto::Event::Notice {
                session_id,
                text: "from-old-client".into(),
            },
            &ctx,
        );
        let drained = drain_turn_events(&events);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].attachment_epoch, selected_client_epoch);
        assert!(matches!(
            &drained[0].event,
            TurnEvent::Notice { text } if text == "from-old-client"
        ));
        assert_eq!(attachment_epoch.load(Ordering::Acquire), 9);
    }

    #[tokio::test]
    async fn event_forward_stamps_global_epoch_for_lsp_notice_and_env_drift() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let primary_agent = Arc::new(Mutex::new("Build".to_string()));
        let last_applied_seq = Arc::new(Mutex::new(None));
        let awaiting_durable = Arc::new(Mutex::new(HashMap::new()));
        let session_id = Uuid::new_v4();
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        let ctx = IncomingEventContext {
            session_id,
            client_epoch: 4,
            attachment_epoch: &attachment_epoch,
            events: &events,
            event_notify: &notify,
            active_agent: &active_agent,
            active_agent_path: &active_agent_path,
            primary_agent: &primary_agent,
            last_applied_seq: &last_applied_seq,
            awaiting_durable: &awaiting_durable,
        };
        apply_incoming_event(proto::Event::LspNotice { text: "lsp".into() }, &ctx);
        let meta = cockpit_proto::EnvSnapshotMeta {
            source: cockpit_proto::EnvSnapshotSource::DaemonStart,
            digest: "digest".into(),
            key_count: 3,
            path_entry_count: 1,
        };
        let drift = cockpit_proto::EnvDiffSummary {
            baseline_digest: "base".into(),
            candidate_digest: "candidate".into(),
            added_keys: 1,
            removed_keys: 2,
            changed_keys: 3,
            changed_secret_keys: vec!["TOKEN".into()],
            path_added: Vec::new(),
            path_removed: Vec::new(),
        };
        apply_incoming_event(
            proto::Event::EnvDriftWarning {
                baseline: meta.clone(),
                candidate: meta,
                diff: drift,
                policy: cockpit_proto::EnvDriftPolicy::Daemon,
            },
            &ctx,
        );
        let drained = drain_turn_events(&events);
        assert_eq!(drained.len(), 2);
        assert!(
            drained
                .iter()
                .all(|queued| queued.attachment_epoch == GLOBAL_ATTACHMENT_EPOCH)
        );
    }

    #[test]
    fn interrupt_decision_turn_event_is_not_independently_global() {
        assert!(!is_global_turn_event(&TurnEvent::InterruptDecision {
            session_id: Uuid::new_v4(),
            interrupt_id: Uuid::new_v4(),
            decision: cockpit_proto::InterruptDecision {
                permission: true,
                cancelled: false,
                lines: Vec::new(),
            },
            seq: Some(1),
        }));
        assert!(is_global_event(&proto::Event::InterruptResolved {
            session_id: Uuid::new_v4(),
            interrupt_id: Uuid::new_v4(),
            decision: Some(cockpit_proto::InterruptDecision {
                permission: true,
                cancelled: false,
                lines: Vec::new(),
            }),
            seq: Some(1),
        }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn push_turn_event_notifies_waiter_without_timer() {
        use std::future::{Future, poll_fn};
        use std::pin::Pin;
        use std::task::Poll;

        async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
            poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let mut notified = Box::pin(notify.notified());

        assert!(matches!(poll_once(notified.as_mut()).await, Poll::Pending));
        push_turn_event(
            &events,
            &notify,
            0,
            TurnEvent::Notice {
                text: "wake now".into(),
            },
        );

        assert!(matches!(
            poll_once(notified.as_mut()).await,
            Poll::Ready(())
        ));
        assert_eq!(events.lock().unwrap().len(), 1);
    }

    #[test]
    fn turn_event_buffer_push_and_drain_recover_from_poison() {
        let events = Arc::new(Mutex::new(vec![QueuedTurnEvent {
            attachment_epoch: 0,
            event: TurnEvent::Notice {
                text: "before".into(),
            },
        }]));
        let poison_events = events.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poison_events.lock().unwrap();
            panic!("poison event buffer");
        })
        .join();

        push_turn_event(
            &events,
            &Arc::new(Notify::new()),
            0,
            TurnEvent::Notice {
                text: "after".into(),
            },
        );
        let drained = drained_event_payloads(&events);

        assert_eq!(drained.len(), 2);
        assert!(matches!(&drained[0], TurnEvent::Notice { text } if text == "before"));
        assert!(matches!(&drained[1], TurnEvent::Notice { text } if text == "after"));
        assert!(drained_event_payloads(&events).is_empty());
    }

    #[tokio::test]
    async fn explicit_agent_runner_shutdown_is_idempotent() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(dropped.clone());
        let handle = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });

        let mut runner = runner_with_client_task(handle);
        runner.shutdown();
        runner.shutdown();
        drop(runner);

        assert_task_future_dropped(dropped).await;
    }

    #[tokio::test]
    async fn refresh_config_control_outcome_preserves_generation_and_changed() {
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let notified = notify.notified();
        send_control_request(
            &control_tx,
            &events,
            &notify,
            ControlRequestId(41),
            Uuid::new_v4(),
            3,
            Request::RefreshConfig,
        )
        .unwrap();
        let request = control_rx.recv().await.unwrap();
        request
            .response_tx
            .send(Ok(Response::ConfigRefreshed {
                applied_generation: 17,
                changed: false,
            }))
            .unwrap();
        notified.await;
        let drained = drained_event_payloads(&events);
        assert!(matches!(
            drained.as_slice(),
            [TurnEvent::ControlRequestFinished {
                request_id: ControlRequestId(41),
                outcome: ControlRequestOutcome::ConfigRefreshed {
                    applied_generation: 17,
                    changed: false
                }
            }]
        ));
    }

    #[test]
    fn event_forward_skips_active_agent_mutation_for_stale_client_epoch() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let active_agent = Arc::new(Mutex::new("Build".to_string()));
        let active_agent_path = Arc::new(Mutex::new(vec!["Build".to_string()]));
        let primary_agent = Arc::new(Mutex::new("Build".to_string()));
        let last_applied_seq = Arc::new(Mutex::new(None));
        let awaiting_durable = Arc::new(Mutex::new(HashMap::new()));
        let session_id = Uuid::new_v4();
        let selected_client_epoch = 4_u64;
        let attachment_epoch = Arc::new(AtomicU64::new(9));
        let ctx = IncomingEventContext {
            session_id,
            client_epoch: selected_client_epoch,
            attachment_epoch: &attachment_epoch,
            events: &events,
            event_notify: &notify,
            active_agent: &active_agent,
            active_agent_path: &active_agent_path,
            primary_agent: &primary_agent,
            last_applied_seq: &last_applied_seq,
            awaiting_durable: &awaiting_durable,
        };
        apply_incoming_event(
            proto::Event::PrimarySwapped {
                session_id,
                name: "Explore".into(),
            },
            &ctx,
        );
        assert_eq!(&*active_agent.lock().unwrap(), "Build");
        assert_eq!(
            &*active_agent_path.lock().unwrap(),
            &vec!["Build".to_string()]
        );
        assert_eq!(&*primary_agent.lock().unwrap(), "Build");
        // PrimarySwapped updates runner chrome before translation; a stale
        // client must leave both chrome and the turn queue untouched.
        assert!(drain_turn_events(&events).is_empty());
    }

    #[tokio::test]
    async fn retained_dispatcher_notice_uses_binding_epoch_not_current_atomic() {
        let session_id = Uuid::new_v4();
        let session_id_state = Arc::new(Mutex::new(session_id));
        let attachment_epoch = Arc::new(AtomicU64::new(4));
        let transition_gate = Arc::new(AsyncMutex::new(()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let (submission_session_tx, submission_session_rx) =
            watch::channel(SubmissionSessionBinding::new(session_id, 4));
        let (_attachment_ready_tx, attachment_ready_rx) = mpsc::unbounded_channel();
        let (input_tx, input_rx) = mpsc::channel(2);
        let dispatcher = tokio::spawn(run_user_submission_dispatcher(
            input_rx,
            UserSubmissionDispatcherContext {
                session_id_state: session_id_state.clone(),
                attachment_epoch: attachment_epoch.clone(),
                transition_gate,
                events: events.clone(),
                event_notify: notify.clone(),
                submission_session_rx,
                attachment_ready_rx,
                awaiting_durable: Arc::new(Mutex::new(HashMap::new())),
            },
            |_client_submission_id, _intended_attachment_epoch, _submission| async { Ok(()) },
        ));

        // Force a deferred recovery notice: retain under a different session,
        // then publish an AttachmentChanged binding for the destination.
        let other_session = Uuid::new_v4();
        *session_id_state.lock().unwrap() = other_session;
        input_tx
            .send(RunnerInput::Submission(Box::new(BoundUserSubmission {
                submission: complete_test_submission(),
                optimistic_submission_id: Uuid::new_v4(),
                intended_session_id: session_id,
                intended_attachment_epoch: 4,
            })))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .expect("retention notice");
        let _ = drain_turn_events(&events);

        // Destination reattach publishes epoch 5; atomic later advances to 9
        // before the wake is processed — notice must keep binding epoch 5.
        *session_id_state.lock().unwrap() = session_id;
        attachment_epoch.store(9, Ordering::Release);
        submission_session_tx.send_replace(SubmissionSessionBinding::new(session_id, 5));
        // Give the dispatcher a chance to observe the watch change.
        for _ in 0..20 {
            if !events.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let drained = drain_turn_events(&events);
        assert!(
            drained.iter().any(|queued| {
                queued.attachment_epoch == 5
                    && matches!(
                        &queued.event,
                        TurnEvent::Notice { text } if text.contains("reattached session")
                    )
            }),
            "retained-notice must stamp the binding epoch, got {drained:?}"
        );
        assert!(
            drained.iter().all(|queued| queued.attachment_epoch != 9),
            "notice must not sample the advanced atomic epoch"
        );

        drop(input_tx);
        dispatcher.await.unwrap();
    }
}
