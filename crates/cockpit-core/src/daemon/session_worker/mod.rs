//! Per-session worker. One alive at a time per session_id.
//!
//! Owns the [`crate::engine::Driver`] for the session, the
//! per-session redaction table, and the model client. Accepts work
//! requests from any number of attached clients via an
//! `mpsc::Sender<SessionWork>` and fans events out to all attached
//! clients via an event envelope broadcast channel.
//!
//! Lifecycle:
//!
//! - **Spawned** lazily on the first `Attach` to a session_id.
//! - **Stays alive** across client disconnects — per GOALS §8b a
//!   session outlives its TUI client.
//! - **Exits** on explicit `Shutdown` (daemon teardown) or when the
//!   session ends (`Session::end`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot};
use uuid::Uuid;

use crate::daemon::proto;
use crate::daemon::{
    EventReceiver, EventSender, SharedRedactionTable, current_redaction, send_current_event,
    send_event, set_current_redaction,
};
use crate::engine::builtin::{self, SpawnArgs};
use crate::engine::model::{Model, ModelParams};
use crate::engine::{Driver, TurnEvent};
use crate::env_snapshot::EnvSnapshot;
use crate::locks::LockManager;
use crate::redact::RedactionTable;
use crate::session::Session;

/// Channel capacity for outbound events fanned to attached clients.
/// Lagging clients lose events (consistent with the fire-and-forget
/// event-stream contract); a client that lags has to reattach to
/// re-sync.
const EVENT_BROADCAST_CAPACITY: usize = 1024;
const LOCK_SNAPSHOT_WORK_LIMIT: usize = 4;
static LOCK_SNAPSHOT_WORK: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Maximum time a streaming text/reasoning delta waits before broadcast.
/// At 25ms this stays below a 30fps frame while collapsing provider token bursts.
const STREAM_DELTA_COALESCE_WINDOW: std::time::Duration = std::time::Duration::from_millis(25);
/// Flush long merged deltas well below the protocol's 8MiB frame limit.
const STREAM_DELTA_COALESCE_BYTE_CAP: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeltaStreamKey {
    session_id: Uuid,
    agent: String,
    kind: DeltaKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeltaKind {
    AssistantText,
    Reasoning,
}

#[derive(Debug)]
struct PendingDelta {
    key: DeltaStreamKey,
    delta: String,
    deadline: tokio::time::Instant,
}

#[derive(Debug, Default)]
struct StreamDeltaCoalescer {
    pending: Option<PendingDelta>,
}

impl StreamDeltaCoalescer {
    #[cfg(test)]
    fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    fn deadline(&self) -> Option<tokio::time::Instant> {
        self.pending.as_ref().map(|pending| pending.deadline)
    }

    fn push(&mut self, event: proto::Event) -> Vec<proto::Event> {
        let Some((key, delta)) = delta_parts(&event) else {
            let mut out = self.flush();
            out.push(event);
            return out;
        };

        match self.pending.as_mut() {
            Some(pending) if pending.key == key => {
                pending.delta.push_str(&delta);
                if pending.delta.len() >= STREAM_DELTA_COALESCE_BYTE_CAP {
                    self.flush()
                } else {
                    Vec::new()
                }
            }
            Some(_) => {
                let out = self.flush();
                self.pending = Some(PendingDelta {
                    key,
                    delta,
                    deadline: tokio::time::Instant::now() + STREAM_DELTA_COALESCE_WINDOW,
                });
                out
            }
            None => {
                self.pending = Some(PendingDelta {
                    key,
                    delta,
                    deadline: tokio::time::Instant::now() + STREAM_DELTA_COALESCE_WINDOW,
                });
                Vec::new()
            }
        }
    }

    fn flush(&mut self) -> Vec<proto::Event> {
        self.pending
            .take()
            .map(|pending| vec![event_from_pending_delta(pending)])
            .unwrap_or_default()
    }
}

fn delta_parts(event: &proto::Event) -> Option<(DeltaStreamKey, String)> {
    match event {
        proto::Event::AssistantTextDelta {
            session_id,
            agent,
            delta,
        } => Some((
            DeltaStreamKey {
                session_id: *session_id,
                agent: agent.clone(),
                kind: DeltaKind::AssistantText,
            },
            delta.clone(),
        )),
        proto::Event::ReasoningDelta {
            session_id,
            agent,
            delta,
        } => Some((
            DeltaStreamKey {
                session_id: *session_id,
                agent: agent.clone(),
                kind: DeltaKind::Reasoning,
            },
            delta.clone(),
        )),
        _ => None,
    }
}

fn event_from_pending_delta(pending: PendingDelta) -> proto::Event {
    match pending.key.kind {
        DeltaKind::AssistantText => proto::Event::AssistantTextDelta {
            session_id: pending.key.session_id,
            agent: pending.key.agent,
            delta: pending.delta,
        },
        DeltaKind::Reasoning => proto::Event::ReasoningDelta {
            session_id: pending.key.session_id,
            agent: pending.key.agent,
            delta: pending.delta,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoticeSource {
    EngineTurn,
    DaemonDirect,
}

impl NoticeSource {
    fn as_str(self) -> &'static str {
        match self {
            NoticeSource::EngineTurn => "engine_turn",
            NoticeSource::DaemonDirect => "daemon_direct",
        }
    }
}

fn record_notice_event_with_agent(
    session: Option<&Session>,
    agent: Option<&str>,
    redact: &RedactionTable,
    event: &proto::Event,
    source: NoticeSource,
) {
    let Some(session) = session else {
        return;
    };
    let proto::Event::Notice { text, .. } = event else {
        return;
    };
    let scrubbed = redact.scrub(text);
    if let Err(error) = session.record_notice(agent, &scrubbed, source.as_str()) {
        tracing::warn!(
            %error,
            session_id = %session.id,
            source = source.as_str(),
            "recording notice event failed"
        );
    }
}

fn send_current_session_event(
    session: &Session,
    tx: &EventSender,
    redact: &SharedRedactionTable,
    event: proto::Event,
    source: NoticeSource,
) {
    let table = current_redaction(redact);
    send_session_event(session, tx, &table, event, source);
}

fn send_current_session_event_with_agent(
    session: &Session,
    agent: Option<&str>,
    tx: &EventSender,
    redact: &SharedRedactionTable,
    event: proto::Event,
    source: NoticeSource,
) {
    let table = current_redaction(redact);
    send_session_event_with_agent(session, agent, tx, &table, event, source);
}

fn send_session_event(
    session: &Session,
    tx: &EventSender,
    redact: &Arc<RedactionTable>,
    event: proto::Event,
    source: NoticeSource,
) {
    send_session_event_with_agent(session, None, tx, redact, event, source);
}

fn send_session_event_with_agent(
    session: &Session,
    agent: Option<&str>,
    tx: &EventSender,
    redact: &Arc<RedactionTable>,
    event: proto::Event,
    source: NoticeSource,
) {
    record_notice_event_with_agent(Some(session), agent, redact, &event, source);
    send_event(tx, redact, event);
}

/// Inbound work-queue capacity. Generous — user messages, cancels,
/// and resolves are tiny.
const WORK_QUEUE_CAPACITY: usize = 64;

#[derive(Default)]
struct RedactionSourceOverrides {
    scan_environment: Option<bool>,
    scan_dotenv: Option<bool>,
    scan_ssh_keys: Option<bool>,
}

impl RedactionSourceOverrides {
    fn apply_to(&self, cfg: &mut crate::config::extended::RedactConfig) {
        if let Some(v) = self.scan_environment {
            cfg.scan_environment = v;
        }
        if let Some(v) = self.scan_dotenv {
            cfg.scan_dotenv = v;
        }
        if let Some(v) = self.scan_ssh_keys {
            cfg.scan_ssh_keys = v;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn refresh_redaction_for_turn(
    session: &Session,
    session_id: Uuid,
    project_root: &Path,
    base_redact: crate::config::extended::RedactConfig,
    overrides: &RedactionSourceOverrides,
    unsupported_notified: &mut HashSet<PathBuf>,
    accumulated_redact: &SharedRedactionTable,
    event_tx: &EventSender,
    driver_control_tx: &mpsc::Sender<crate::engine::driver::DriverControl>,
    env: &HashMap<String, String>,
) -> bool {
    let mut cfg = base_redact;
    overrides.apply_to(&mut cfg);
    match crate::redact::RedactionTable::build_with_env_and_store(&cfg, project_root, env) {
        Ok(new_table) => {
            let table = match current_redaction(accumulated_redact).union(&new_table) {
                Ok(table) => Arc::new(table),
                Err(error) => {
                    tracing::warn!(error = %error, "unioning redaction table failed");
                    Arc::new(new_table)
                }
            };
            set_current_redaction(accumulated_redact, table.clone());
            if let Err(error) = session.persist_redaction_table(&table) {
                tracing::warn!(error = %error, %session_id, "persisting redaction table failed");
            }
            for path in table.unsupported_files() {
                if unsupported_notified.insert(path.clone()) {
                    send_session_event(
                        session,
                        event_tx,
                        &table,
                        proto::Event::Notice {
                            session_id,
                            text: format!(
                                "`{}` is an unsupported format; redaction for this file will not work",
                                path.display()
                            ),
                        },
                        NoticeSource::DaemonDirect,
                    );
                }
            }
            if driver_control_tx
                .send(crate::engine::driver::DriverControl::SetRedaction {
                    table,
                    scan_environment: None,
                    scan_dotenv: None,
                    scan_ssh_keys: None,
                })
                .await
                .is_err()
            {
                tracing::warn!(session_id = %session_id, "driver control channel closed");
                return false;
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "refreshing redaction table failed");
        }
    }
    true
}

/// Live in-daemon status of a session, maintained by the event
/// forwarder (GOALS §17f / §22). The `ScheduleAuthority` and the driver turn
/// loop are the authorities for jobs and turn-state respectively; their
/// emissions all funnel through the worker's single forwarding seam, so
/// observing them there keeps the single-authority rule intact while
/// giving the browser a cheap, lock-free read for tiers 1-2.
#[derive(Default)]
pub struct LiveState {
    /// Count of live async jobs (loop/timer/background). `ScheduleStarted`
    /// increments, `ScheduleCompleted` decrements.
    active_schedules: AtomicUsize,
    /// Whether a turn is in flight: set on `ThinkingStarted`, cleared on
    /// `AgentIdle`.
    processing: AtomicBool,
    /// Count of tool calls currently between `ToolStart` and `ToolEnd`.
    tool_running: AtomicUsize,
}

impl LiveState {
    pub fn has_active_schedules(&self) -> bool {
        self.active_schedules.load(Ordering::Relaxed) > 0
    }

    pub fn processing(&self) -> bool {
        self.processing.load(Ordering::Relaxed)
    }

    pub fn tool_running(&self) -> bool {
        self.tool_running.load(Ordering::Relaxed) > 0
    }
}

#[derive(Debug, Clone)]
pub struct ForegroundSnapshot {
    pub active_agent_path: Vec<String>,
    pub foreground_target: proto::QueueTarget,
    pub active_subagent: Option<proto::ActiveSubagent>,
}

#[derive(Debug, Clone)]
struct LiveForegroundState {
    root_agent: String,
    active_agent_path: Vec<String>,
    foreground_target: crate::engine::message::QueueTarget,
    active_subagents: Vec<proto::ActiveSubagent>,
}

impl LiveForegroundState {
    fn new(root_agent: String) -> Self {
        Self {
            foreground_target: crate::engine::message::QueueTarget::root(root_agent.clone()),
            active_agent_path: vec![root_agent.clone()],
            active_subagents: Vec::new(),
            root_agent,
        }
    }

    fn snapshot(&self) -> ForegroundSnapshot {
        ForegroundSnapshot {
            active_agent_path: self.active_agent_path.clone(),
            foreground_target: queue_target_to_proto(self.foreground_target.clone()),
            active_subagent: self.active_subagents.last().cloned(),
        }
    }
}

mod handle;
mod helpers;
mod lifecycle;
mod run;
#[cfg(test)]
mod tests;

use self::helpers::queue_target_to_proto;

pub use handle::{
    InteractiveClientGuard, SessionConfigHandle, SessionConfigSnapshot, SessionWork,
    SessionWorkerHandle, spawn,
};
pub use helpers::DAEMON_NO_SANDBOX_ENV;
#[allow(unused_imports)]
pub(crate) use helpers::{resolve_root_agent, resolve_root_agent_conn};
pub(crate) use lifecycle::initial_active_agent;
