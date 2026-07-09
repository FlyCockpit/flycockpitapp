//! Conversation session — DB-backed.
//!
//! A session is the long-lived conversation between a user and a
//! cockpit driver. Per GOALS §8b sessions outlive their TUI client:
//! TUI quit detaches; the daemon keeps the session warm in the DB
//! until a later `cockpit -c` resumes it.
//!
//! What lives here:
//!   - [`Session`]: identity (id, project_id, cwd) plus per-call
//!     write-through into the SQLite `sessions` /
//!     `tool_call_events` / `inference_calls` tables.
//!   - [`ToolCallRow`]: in-memory analog of the §15b row;
//!     converted to a [`crate::db::tool_calls::ToolCallEvent`] before
//!     INSERT.
//!
//! Per-agent transcripts (`Vec<rig::message::Message>`) live on
//! [`crate::engine::driver::AgentSession`] in the driver. `Session`
//! is shared across agents in the same conversation; agent
//! transcripts are private.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;
use crate::db::sessions::SessionRow;
use crate::db::tool_calls::ToolCallEvent;
use crate::engine::repair::Recovery;

/// What the auto-title hook should do after a user message. Returned by
/// [`Session::note_user_content`]; the driver spawns the matching detached
/// utility-model pass (or nothing for `None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleAction {
    /// No pass this turn: this user-turn count is not one of the scheduled
    /// title slots, or the user has manually renamed the session.
    None,
    /// First scheduled slot: title the session now from the first message,
    /// regardless of token count.
    Eager,
    /// Later scheduled slots: regenerate from richer accumulated user-authored
    /// context.
    Refine,
    /// Explicit user-requested utility rename (`/rename` with no title). This
    /// bypasses the automatic schedule and replaces even a previous manual
    /// title, because the user asked for this generation directly.
    Explicit,
}

/// Per-conversation session state. Cloned through `Arc` into every
/// tool invocation. Owns a clone of the `Db` handle (the underlying
/// connection is shared).
pub struct Session {
    pub id: Uuid,
    pub project_id: String,
    pub project_root: PathBuf,
    /// Hydrated from the row; not yet read by any consumer.
    #[allow(dead_code)]
    pub started_at: DateTime<Utc>,
    pub db: Db,
    /// Private per-session tmp dir under the system temp location
    /// (sandboxing part 2). Read+write inside the sandboxed shell and
    /// counted as "inside the boundary" for native-tool path checks, so
    /// sessions can't read each other's tmp. Created lazily on first
    /// [`Self::tmp_dir`] access; removed on [`Self::end`] and on drop.
    /// `Mutex<Option<…>>` so creation is one-shot and `end()` can take it.
    tmp_dir: Mutex<Option<PathBuf>>,
    /// Live sandbox mode for this session. Resolved at spawn time by the
    /// daemon/client `--no-sandbox` precedence and flipped at runtime by
    /// `/sandbox`. In-memory only; resumed sessions re-resolve defaults.
    sandbox_mode: AtomicU8,
    /// Per-session container-network toggle. Only honored by container modes;
    /// default off so container sandboxes start with `--network none`.
    container_network_enabled: AtomicBool,
    /// Command-approval mode for this session right now
    /// (implementation note), encoded by
    /// [`approval_mode_to_u8`] / [`approval_mode_from_u8`]. Resolved at
    /// spawn from [`crate::config::extended::ExtendedConfig::default_approval_mode`]
    /// ([`Self::set_approval_mode`]); read per gated tool call via
    /// [`Self::approval_mode`]. Default `manual` until the spawn path
    /// applies the config default. Distinct from the `auto` *router agent*.
    approval_mode: AtomicU8,
    /// Native shell-output compression for this session right now
    /// (implementation note). Resolved at spawn from
    /// [`crate::config::extended::ExtendedConfig::shell_compression`]
    /// ([`Self::set_shell_compression`]); read per `bash` call via
    /// [`Self::shell_compression_enabled`]. Default ON (compress) until the
    /// spawn path applies the config default. In-memory only — a resumed
    /// session re-resolves from config at re-attach.
    shell_compression_enabled: AtomicBool,
    /// Trusted-only inference mode for this session right now. Seeded from
    /// `trustedOnly` at spawn and flipped live by `/trusted-only`. Models hold
    /// clones of this flag so already-built handles refuse future untrusted
    /// dispatches after a toggle.
    trusted_only: Arc<AtomicBool>,
    /// 6-char human-display id, unique within `project_id`
    /// (GOALS §17b). Populated at create-time; backfilled lazily for
    /// pre-§17 rows on [`Session::resume`].
    pub short_id: String,
    /// Parent session in the fork tree (GOALS §17e). `None` = root.
    // Fork-tree lineage (GOALS §17e); not yet read by any consumer.
    #[allow(dead_code)]
    pub parent_session_id: Option<Uuid>,
    /// Turn id in the parent where this fork branched. `None` for
    /// roots; also `None` for tail-forks where the daemon hadn't yet
    /// resolved the parent's tail turn at fork-time.
    // Fork-tree lineage (GOALS §17e); not yet read by any consumer.
    #[allow(dead_code)]
    pub fork_point_turn_id: Option<String>,
    title: Mutex<Option<String>>,
    user_renamed: Mutex<bool>,
    model: Mutex<Option<String>>,
    provider: Mutex<Option<String>>,
    /// Last time a `[time: ...]` prelude was injected onto a user
    /// message (GOALS §17g). `None` means no prelude has fired yet
    /// in this session — the next user message gets one. Lives in
    /// memory only: the daemon re-evaluates the interval on every
    /// send, so re-attaching a resumed session naturally re-injects.
    pub last_time_prelude: Mutex<Option<DateTime<Utc>>>,
    /// Running token estimate of RAW typed user-authored content
    /// (pre-skill-injection) this session. Bumped by
    /// [`Self::note_user_content`] and retained for stats/compatibility.
    /// Rehydrated from `sessions.user_content_tokens` on resume (migration
    /// 0037) and persisted on each bump.
    user_content_tokens: AtomicUsize,
    /// Count of raw user-authored turns seen by [`Self::note_user_content`].
    /// Rehydrated best-effort from durable `user_message` events on resume;
    /// it does not need a schema column because the transcript is already the
    /// source of truth.
    user_content_turns: AtomicUsize,
    /// Auto-title progress (§17d, migration 0037): last consumed scheduled
    /// title slot (`0`, `1`, `2`, `4`, `8`, or `16`). Stored in the existing
    /// `sessions.title_stage` column so a resumed session never repeats the
    /// same automatic refresh opportunity.
    title_stage: AtomicU8,
    /// Latches once a genuine auto-title failure has surfaced a user
    /// `Notice` (§17d / implementation note), so
    /// a broken/unset utility model is reported once per session rather
    /// than every turn. In-memory only — a resume re-arms it.
    title_failure_noticed: std::sync::atomic::AtomicBool,
    /// Provider-reported usage from the most recent round-trip.
    /// Populated by [`Self::record_usage`] after each `model.complete`
    /// call. The TUI prefers this over the local tiktoken estimate
    /// when it's `Some(_)`.
    last_usage: Mutex<Option<crate::tokens::TokenUsage>>,
    /// Wall-clock instant of the most recent inference send. Stamped by
    /// [`Self::record_usage`]. The cache-cold predicate (GOALS §10) reads
    /// it to decide whether the provider's prompt-cache TTL has elapsed.
    /// In-memory only — a resumed session re-warms naturally.
    last_send_at: Mutex<Option<std::time::Instant>>,
    /// User messages pinned via `/pin` (GOALS §10 / `plan.md` T6.e):
    /// must-survive content injected verbatim into the `/compact`
    /// handoff, never summarized. In pin order.
    pinned_messages: Mutex<Vec<String>>,
    /// In-memory tokenizer-calibration accumulator. Samples inference
    /// calls until a window closes, then fits + persists the best
    /// `(strategy, scale)` for the active `(provider, model)`. Never
    /// persisted in-progress.
    calibrator: Mutex<crate::tokens::Calibrator>,
    /// Loop-guard state (GOALS §1/§12): the signature of the most recent
    /// dispatched tool call and how many times *in a row* that exact
    /// signature has been issued. The dispatcher bumps this per tool call
    /// via [`Self::bump_consecutive_call`] to detect a back-to-back
    /// repeat. In-memory only — a fresh attach starts the chain over,
    /// which is correct (a loop only matters within a live run).
    last_tool_call: Mutex<Option<LastToolCall>>,
    /// The most recent tool call whose RESULT was a recoverable dead-end that
    /// should not be immediately repeated verbatim. Keyed on the final
    /// semantic `(tool, args)` signature after repair / tool recovery. A
    /// different next call clears the slot; an identical next call is
    /// short-circuited without re-running the tool. In-memory only.
    last_recoverable_tool_call: Mutex<Option<LastRecoverableToolCall>>,
    /// Deferred-persistence state (session-id-display-and-lazy-persist).
    /// A freshly-created session is held in memory with its `sessions` row
    /// un-written; `pending_row` carries the row to INSERT on the first
    /// user message. `None` once persisted (and for sessions created /
    /// resumed already-persisted). [`Self::persist_if_needed`] is the one
    /// flush point — it writes the `sessions` row *before* any dependent
    /// write, so FK/ordering invariants hold.
    pending_row: Mutex<Option<SessionRow>>,
    /// Session-scoped gitignore read-allowlist globs added via the approval
    /// flow's "Approve for this session" choice
    /// (implementation note). Unioned with the persisted
    /// per-layer `gitignore_allow` config to form the effective allowlist the
    /// read gate + discovery surfaces consult. In-memory only — reverts on
    /// restart (like `/toggle-redaction`), never persisted.
    gitignore_session_allow: Mutex<Vec<String>>,
    /// Session-scoped reject-memory: the resolved target paths a user
    /// **declined** to allow this session (implementation note).
    /// A retried `read`/`readlock` of a remembered path gets the same refusal
    /// with no re-prompt (avoids prompt thrash). In-memory only — never
    /// persisted; there is no user-facing denylist.
    gitignore_session_reject: Mutex<std::collections::HashSet<String>>,
    /// Dedicated tools the model has SUCCESSFULLY used this session, for the
    /// defensive-mode bash-routing nudge's self-suppression
    /// (implementation note). Keyed by the
    /// tip-target tool name (`read`/`search`/`word`/`symbol_find`/`tree`): once
    /// a name is present, the bash tip pointing to it stops being appended.
    /// In-memory only — a fresh attach starts the nudges over, which is correct
    /// (the nudge is a within-run teaching aid). Recorded at the dispatch site
    /// on a successful call; read at the `bash` result-assembly site.
    adopted_tip_tools: Mutex<std::collections::HashSet<String>>,
    /// Ring of the agent's recent `bash` calls (command string + exit code),
    /// newest-last, capped at [`crate::engine::bash_hints::HISTORY_WINDOW`].
    /// Feeds the post-result hint layer (`engine::bash_hints`), which inspects
    /// the recent chain to spot filter-refinement / empty-thrash loops. In
    /// memory only — a fresh attach starts the window over (the hint is a
    /// within-run nudge). Pushed at the `bash` dispatch site after each call.
    recent_bash: Mutex<std::collections::VecDeque<crate::engine::bash_hints::BashHistoryEntry>>,
}

/// The most recent dispatched tool call's loop-guard signature and its
/// consecutive-repeat count. See [`Session::bump_consecutive_call`].
#[derive(Debug, Clone)]
struct LastToolCall {
    signature: String,
    consecutive: u32,
}

#[derive(Debug, Clone)]
struct LastRecoverableToolCall {
    signature: String,
    message: String,
}

impl Session {
    /// Create a brand-new session, inserting its row in the DB.
    #[allow(dead_code)]
    pub fn create(db: Db, project_root: PathBuf, active_agent: &str) -> Result<Self> {
        let project_id = project_id_for(&project_root);
        let project_root_str = project_root.to_string_lossy().into_owned();
        let row = db
            .create_session(&project_id, &project_root_str, active_agent)
            .context("creating session row")?;
        Self::from_row(db, project_root, row)
    }

    /// Create a brand-new session held **in memory only** — its `sessions`
    /// row is not written yet (session-id-display-and-lazy-persist). The id
    /// and short_id exist immediately (so the TUI can show the id at
    /// startup), but the row lands in the DB only on the first user message
    /// via [`Self::persist_if_needed`]. A session created this way and never
    /// persisted leaves no DB trace and never appears in `session list`.
    pub fn create_deferred(db: Db, project_root: PathBuf, active_agent: &str) -> Result<Self> {
        let project_id = project_id_for(&project_root);
        let project_root_str = project_root.to_string_lossy().into_owned();
        let row = db
            .new_session_row(&project_id, &project_root_str, active_agent)
            .context("building deferred session row")?;
        let session = Self::from_row(db, project_root, row.clone())?;
        *session.pending_row.lock().unwrap() = Some(row);
        Ok(session)
    }

    /// Write the deferred `sessions` row if it hasn't been written yet, and
    /// return `true` when this call performed the write
    /// (session-id-display-and-lazy-persist). Idempotent: a no-op (returns
    /// `false`) for an already-persisted session — including every session
    /// created via [`Self::create`] / [`Self::resume`] / [`Self::create_fork`],
    /// which are persisted from the start.
    ///
    /// This is the **only** flush point, and it MUST be called before any
    /// row that references the session (tool_calls, inference_calls, locks,
    /// …) so the FK/ordering invariant holds. The session worker calls it on
    /// the first user message, ahead of dispatching it to the driver. The
    /// stored row carries the latest provider/model so a model picked before
    /// the first message survives the deferred write.
    pub fn persist_if_needed(&self) -> Result<bool> {
        let row = {
            let mut slot = self.pending_row.lock().unwrap();
            match slot.take() {
                Some(mut row) => {
                    row.provider = self.active_provider();
                    row.model = self.active_model();
                    row
                }
                None => return Ok(false),
            }
        };
        match self.db.insert_session_row(&row) {
            Ok(_) => {}
            Err(e) => {
                // Restore the pending row so a transient failure can retry on
                // the next user message rather than silently losing the session.
                *self.pending_row.lock().unwrap() = Some(row);
                return Err(e).context("persisting deferred session row");
            }
        }
        if row.last_viewed_at.is_some()
            && let Err(e) = self.db.mark_session_viewed(self.id)
        {
            tracing::warn!(error = %e, "persisting deferred session viewed marker failed");
        }
        Ok(true)
    }

    fn stage_pending_row(&self, update: impl FnOnce(&mut SessionRow)) -> bool {
        let mut slot = self.pending_row.lock().unwrap();
        if let Some(row) = slot.as_mut() {
            update(row);
            true
        } else {
            false
        }
    }

    /// Whether this session's `sessions` row has been written
    /// (session-id-display-and-lazy-persist). `false` only for a deferred
    /// session that has not yet seen its first user message; `true`
    /// otherwise. Used by the lazy-persistence tests; the TUI's own
    /// exit-print decision tracks the persistence trigger locally (it can't
    /// reach this daemon-owned state synchronously).
    #[cfg(test)]
    pub fn is_persisted(&self) -> bool {
        self.pending_row.lock().unwrap().is_none()
    }

    /// Branch a fork from `parent` at `fork_point_turn_id` (None = tail).
    /// The new session inherits the parent's project, agent, provider,
    /// and model; its conversation history is reconstructed by the
    /// daemon from the parent's transcript up to the fork point.
    pub fn create_fork(
        db: Db,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
    ) -> Result<Self> {
        let row = db
            .create_fork(parent_session_id, fork_point_turn_id)
            .context("creating fork session row")?;
        let project_root = PathBuf::from(&row.project_root);
        Self::from_row(db, project_root, row)
    }

    /// Resume an existing session. Returns `None` if the id is unknown.
    /// Backfills `short_id` if missing (lazy migration from pre-§17 rows).
    pub fn resume(db: Db, session_id: Uuid) -> Result<Option<Self>> {
        let Some(row) = db.get_session(session_id).context("fetching session")? else {
            return Ok(None);
        };
        let project_root = PathBuf::from(&row.project_root);
        Ok(Some(Self::from_row(db, project_root, row)?))
    }

    fn from_row(db: Db, project_root: PathBuf, row: SessionRow) -> Result<Self> {
        let started_at =
            DateTime::<Utc>::from_timestamp(row.started_at, 0).unwrap_or_else(Utc::now);
        let user_content_turns = count_user_turns_for_title(&db, row.session_id);
        let short_id = match row.short_id {
            Some(s) => s,
            None => db
                .ensure_short_id(row.session_id)
                .context("backfilling short_id")?,
        };
        Ok(Self {
            id: row.session_id,
            project_id: row.project_id,
            project_root,
            started_at,
            db,
            short_id,
            parent_session_id: row.parent_session_id,
            fork_point_turn_id: row.fork_point_turn_id,
            title: Mutex::new(row.title),
            user_renamed: Mutex::new(row.user_renamed),
            model: Mutex::new(row.model),
            provider: Mutex::new(row.provider),
            last_time_prelude: Mutex::new(None),
            user_content_tokens: AtomicUsize::new(row.user_content_tokens.max(0) as usize),
            user_content_turns: AtomicUsize::new(user_content_turns),
            title_stage: AtomicU8::new(normalize_title_slot(row.title_stage)),
            title_failure_noticed: std::sync::atomic::AtomicBool::new(false),
            last_usage: Mutex::new(None),
            last_send_at: Mutex::new(None),
            pinned_messages: Mutex::new(Vec::new()),
            calibrator: Mutex::new(crate::tokens::Calibrator::new()),
            tmp_dir: Mutex::new(None),
            sandbox_mode: AtomicU8::new(sandbox_mode_to_u8(
                crate::tools::sandbox_mode::SandboxMode::Sandbox,
            )),
            container_network_enabled: AtomicBool::new(false),
            // Default `manual` until the spawn path applies the config default.
            approval_mode: AtomicU8::new(approval_mode_to_u8(
                crate::config::extended::ApprovalMode::Manual,
            )),
            // Default ON until the spawn path applies the config default.
            shell_compression_enabled: AtomicBool::new(true),
            trusted_only: Arc::new(AtomicBool::new(false)),
            last_tool_call: Mutex::new(None),
            last_recoverable_tool_call: Mutex::new(None),
            // Persisted by default; `create_deferred` overrides this with the
            // pending row right after construction.
            pending_row: Mutex::new(None),
            gitignore_session_allow: Mutex::new(Vec::new()),
            gitignore_session_reject: Mutex::new(std::collections::HashSet::new()),
            adopted_tip_tools: Mutex::new(std::collections::HashSet::new()),
            recent_bash: Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// The session-scoped gitignore read-allowlist globs added via the
    /// approval flow's "Approve for this session" choice
    /// (implementation note). Cloned out so the caller can
    /// union it with the persisted per-layer config without holding the lock.
    pub fn gitignore_session_allow(&self) -> Vec<String> {
        self.gitignore_session_allow.lock().unwrap().clone()
    }

    /// Add `glob` to the session allowlist (idempotent — a duplicate is
    /// ignored). Called when the user approves a gitignored read "for this
    /// session" (implementation note).
    pub fn add_gitignore_session_allow(&self, glob: impl Into<String>) {
        let glob = glob.into();
        let mut set = self.gitignore_session_allow.lock().unwrap();
        if !set.contains(&glob) {
            set.push(glob);
        }
    }

    /// Whether `path` (a resolved target string) was rejected for a gitignored
    /// read earlier this session (implementation note).
    pub fn gitignore_rejected(&self, path: &str) -> bool {
        self.gitignore_session_reject.lock().unwrap().contains(path)
    }

    /// Remember that the user declined a gitignored read of `path` (a resolved
    /// target string) so a retry gets the same refusal with no re-prompt.
    pub fn remember_gitignore_reject(&self, path: impl Into<String>) {
        self.gitignore_session_reject
            .lock()
            .unwrap()
            .insert(path.into());
    }

    /// Record that the model successfully used the dedicated tool `tool` this
    /// session, for the defensive bash-routing nudge's self-suppression
    /// (implementation note). Only the
    /// tip-target names (`read`/`search`/`word`/`symbol_find`/`tree`) carry
    /// meaning; other names are stored inertly. Idempotent. Called at the
    /// dispatch site on a successful call.
    pub fn record_tip_tool_used(&self, tool: &str) {
        self.adopted_tip_tools
            .lock()
            .unwrap()
            .insert(tool.to_string());
    }

    /// A read-only snapshot of the agent's recent `bash` history (oldest-first,
    /// current call excluded), for the post-result hint layer
    /// (`engine::bash_hints`). Read at the `bash` result-assembly site *before*
    /// [`Self::push_recent_bash`] records the just-finished call.
    pub fn recent_bash(&self) -> Vec<crate::engine::bash_hints::BashHistoryEntry> {
        self.recent_bash.lock().unwrap().iter().cloned().collect()
    }

    /// Record a just-finished `bash` call (command + exit code) into the recent
    /// history ring, evicting the oldest beyond
    /// [`crate::engine::bash_hints::HISTORY_WINDOW`]. Called once per `bash`
    /// dispatch, after the hint layer has read the prior window.
    pub fn push_recent_bash(&self, command: String, exit_code: Option<i32>) {
        let mut ring = self.recent_bash.lock().unwrap();
        ring.push_back(crate::engine::bash_hints::BashHistoryEntry { command, exit_code });
        while ring.len() > crate::engine::bash_hints::HISTORY_WINDOW {
            ring.pop_front();
        }
    }

    /// Whether the model has already adopted the dedicated tool `tip` points
    /// to — i.e. successfully used any of `tip.suppressed_by()` this session.
    /// Once true the bash nudge stops appending that tip (self-suppression).
    pub fn tip_suppressed(&self, tip: crate::tools::shell_compress::BashTip) -> bool {
        let set = self.adopted_tip_tools.lock().unwrap();
        tip.suppressed_by().iter().any(|name| set.contains(*name))
    }

    /// Whether any sandboxing mode is active for this session right now.
    /// Kept as a derived helper so native file-tool checks can remain boolean.
    pub fn sandbox_enabled(&self) -> bool {
        self.sandbox_mode().enabled()
    }

    pub fn sandbox_mode(&self) -> crate::tools::sandbox_mode::SandboxMode {
        sandbox_mode_from_u8(self.sandbox_mode.load(Ordering::Relaxed))
    }

    pub fn set_sandbox_mode(
        &self,
        mode: crate::tools::sandbox_mode::SandboxMode,
    ) -> crate::tools::sandbox_mode::SandboxMode {
        self.sandbox_mode
            .store(sandbox_mode_to_u8(mode), Ordering::Relaxed);
        mode
    }

    /// Legacy on/off setter used by existing callers until the UX prompt grows
    /// mode selection. `true` maps to the zerobox sandbox, `false` to off.
    pub fn set_sandbox_enabled(&self, enabled: bool) -> bool {
        self.set_sandbox_mode(crate::tools::sandbox_mode::SandboxMode::from_enabled(
            enabled,
        ));
        enabled
    }

    #[cfg(test)]
    pub fn toggle_sandbox_mode(&self) -> crate::tools::sandbox_mode::SandboxMode {
        let new = self.sandbox_mode().toggled_legacy();
        self.set_sandbox_mode(new)
    }

    #[cfg(test)]
    pub fn toggle_sandbox_enabled(&self) -> bool {
        self.toggle_sandbox_mode().enabled()
    }

    pub fn container_network_enabled(&self) -> bool {
        self.container_network_enabled.load(Ordering::Relaxed)
    }

    pub fn set_container_network_enabled(&self, enabled: bool) -> bool {
        self.container_network_enabled
            .store(enabled, Ordering::Relaxed);
        enabled
    }

    /// The session's current command-approval mode
    /// (implementation note). Read per gated tool call.
    pub fn approval_mode(&self) -> crate::config::extended::ApprovalMode {
        approval_mode_from_u8(self.approval_mode.load(Ordering::Relaxed))
    }

    /// Set the session's command-approval mode. Used by the spawn path to
    /// apply the config default and by `/settings` to flip it at runtime.
    /// Returns the new mode.
    pub fn set_approval_mode(
        &self,
        mode: crate::config::extended::ApprovalMode,
    ) -> crate::config::extended::ApprovalMode {
        self.approval_mode
            .store(approval_mode_to_u8(mode), Ordering::Relaxed);
        mode
    }

    /// Whether native shell-output compression is active for this session
    /// right now (implementation note). Read per `bash`
    /// call; when false the bash tool returns its output verbatim.
    pub fn shell_compression_enabled(&self) -> bool {
        self.shell_compression_enabled.load(Ordering::Relaxed)
    }

    /// Set the session's shell-compression flag from the config mode. Used
    /// by the spawn path to apply
    /// [`crate::config::extended::ExtendedConfig::shell_compression`].
    /// Returns the new state.
    pub fn set_shell_compression(&self, mode: crate::config::extended::ShellCompression) -> bool {
        let enabled = mode.is_enabled();
        self.shell_compression_enabled
            .store(enabled, Ordering::Relaxed);
        enabled
    }

    /// Whether trusted-only inference mode is active for this session.
    pub fn trusted_only(&self) -> bool {
        self.trusted_only.load(Ordering::Relaxed)
    }

    /// Set trusted-only inference mode for this session and return the new
    /// state. Models built with [`Self::trusted_only_flag`] observe this
    /// immediately before future provider dispatches.
    pub fn set_trusted_only(&self, enabled: bool) -> bool {
        self.trusted_only.store(enabled, Ordering::Relaxed);
        enabled
    }

    /// Toggle trusted-only inference mode for this session.
    pub fn toggle_trusted_only(&self) -> bool {
        let new = !self.trusted_only();
        self.set_trusted_only(new)
    }

    /// Clone the live trusted-only flag for model handles.
    pub fn trusted_only_flag(&self) -> Arc<AtomicBool> {
        self.trusted_only.clone()
    }

    /// The session's private tmp dir (sandboxing part 2), creating it on
    /// first access under `<system temp>/cockpit-session-<id>`. Sandboxed
    /// shells get read+write here, and native-tool path checks treat it
    /// as inside the boundary. Returns `None` only if the directory can't
    /// be created (a degraded but non-fatal state: native checks then
    /// fall back to cwd-only, and the shell sandbox simply omits the tmp
    /// allow entry).
    pub fn tmp_dir(&self) -> Option<PathBuf> {
        let mut slot = self.tmp_dir.lock().unwrap();
        if let Some(dir) = slot.as_ref() {
            return Some(dir.clone());
        }
        let dir = std::env::temp_dir().join(format!("cockpit-session-{}", self.id));
        match std::fs::create_dir_all(&dir) {
            Ok(()) => {
                *slot = Some(dir.clone());
                Some(dir)
            }
            Err(e) => {
                tracing::warn!(error = %e, dir = %dir.display(), "creating session tmp dir failed");
                None
            }
        }
    }

    /// Manually set the session's title. Locks out the auto-titling
    /// pass (GOALS §17d).
    // Manual-rename API (GOALS §17d); retained for the not-yet-wired
    // `/rename` affordance.
    #[allow(dead_code)]
    pub fn rename(&self, new_title: &str) -> Result<()> {
        self.db
            .rename_session(self.id, new_title)
            .context("renaming session")?;
        *self.title.lock().unwrap() = Some(new_title.to_string());
        *self.user_renamed.lock().unwrap() = true;
        Ok(())
    }

    /// Apply an auto-generated title. No-ops (and returns false) if the
    /// user has manually renamed this session.
    pub fn set_auto_title(&self, title: &str) -> Result<bool> {
        let updated = self
            .db
            .set_auto_title(self.id, title)
            .context("setting auto title")?;
        if updated {
            *self.title.lock().unwrap() = Some(title.to_string());
        }
        Ok(updated)
    }

    /// Apply an explicitly user-requested generated title (`/rename` with no
    /// argument). Unlike scheduled auto-titles, this clears the manual-title
    /// guard because the user asked the utility model to replace the current
    /// title.
    pub fn set_explicit_auto_title(&self, title: &str) -> Result<bool> {
        let updated = self
            .db
            .set_explicit_auto_title(self.id, title)
            .context("setting explicit auto title")?;
        if updated {
            *self.title.lock().unwrap() = Some(title.to_string());
            *self.user_renamed.lock().unwrap() = false;
        }
        Ok(updated)
    }

    #[cfg(test)]
    pub fn title(&self) -> Option<String> {
        self.title.lock().unwrap().clone()
    }

    pub fn user_renamed(&self) -> bool {
        *self.user_renamed.lock().unwrap()
    }

    /// Fold a chunk of RAW typed user content (pre-skill-injection) into the
    /// running estimate and decide the bounded auto-title action.
    ///
    /// Automatic title calls are allowed only at deterministic user-turn slots:
    /// `1`, `2`, `4`, `8`, and `16`. The selected slot is persisted before the
    /// detached utility task is spawned, so a failed task or daemon restart does
    /// not repeat the same unchanged context. The first slot keeps the fast
    /// single-message eager title; later slots regenerate from accumulated
    /// user-authored messages.
    ///
    /// Persistence is best-effort: an erroring write is logged, never
    /// propagated, and never blocks the turn.
    pub fn note_user_content(&self, text: &str) -> TitleAction {
        let increment = crate::auto_title::estimate_tokens(text);
        if increment != 0 {
            self.user_content_tokens
                .fetch_add(increment, Ordering::Relaxed);
        }
        let user_turns = if increment == 0 {
            self.user_content_turns.load(Ordering::Relaxed)
        } else {
            self.user_content_turns.fetch_add(1, Ordering::Relaxed) + 1
        };

        if self.user_renamed() {
            if increment != 0 {
                self.persist_title_progress();
            }
            return TitleAction::None;
        }

        if increment != 0
            && let Some(slot) =
                scheduled_title_slot(user_turns, self.title_stage.load(Ordering::Relaxed))
        {
            self.title_stage.store(slot, Ordering::Relaxed);
            self.persist_title_progress();
            return if slot == 1 {
                TitleAction::Eager
            } else {
                TitleAction::Refine
            };
        }

        if increment != 0 {
            self.persist_title_progress();
        }
        TitleAction::None
    }

    /// Compatibility hook retained for older call sites/tests. The schedule is
    /// consumed before the detached utility call starts, so a successful eager
    /// write normally has no progress work left to do.
    pub fn mark_eager_titled(&self) {
        if self.title_stage.load(Ordering::Relaxed) == 0 {
            self.title_stage.store(1, Ordering::Relaxed);
        }
        self.persist_title_progress();
    }

    /// Persist the running estimate + last consumed title slot to the
    /// `sessions` row. Best-effort: an erroring write is logged at warn and
    /// dropped — it never blocks or fails a turn.
    fn persist_title_progress(&self) {
        let tokens = self.user_content_tokens.load(Ordering::Relaxed) as i64;
        let stage = self.title_stage.load(Ordering::Relaxed) as i64;
        if let Err(e) = self.db.set_title_progress(self.id, tokens, stage) {
            tracing::warn!(error = %e, "auto_title: persisting title progress failed");
        }
    }

    /// Read-only view of the running user-content token estimate.
    /// Mostly for tests and `/stats`-style introspection.
    // Retained for `/stats`-style introspection.
    #[allow(dead_code)]
    pub fn user_content_tokens(&self) -> usize {
        self.user_content_tokens.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn user_content_turns(&self) -> usize {
        self.user_content_turns.load(Ordering::Relaxed)
    }

    /// Read-only view of the last consumed auto-title schedule slot. For tests
    /// and introspection.
    #[cfg(test)]
    pub fn title_stage(&self) -> u8 {
        self.title_stage.load(Ordering::Relaxed)
    }

    /// Claim the one-per-session right to surface an auto-title failure
    /// `Notice`. Returns `true` exactly once per session (the first
    /// genuine failure); `false` thereafter, so a broken utility model
    /// doesn't spam the transcript every turn.
    pub fn claim_title_failure_notice(&self) -> bool {
        self.title_failure_noticed
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Compute the `[time: <iso8601>]` prelude for the next user
    /// message (GOALS §17g). Returns `Some` when the first message of
    /// the session is about to fire, or when ≥ `interval_minutes` have
    /// elapsed since the last prelude; otherwise `None`. Updating the
    /// per-session "last prelude" stamp is the side-effect of a
    /// `Some` return — call only when actually about to send.
    pub fn take_time_prelude(&self, interval_minutes: u32) -> Option<String> {
        let now = Utc::now();
        let mut last = self.last_time_prelude.lock().unwrap();
        let should_inject = match *last {
            None => true,
            Some(prev) => (now - prev).num_minutes() >= interval_minutes as i64,
        };
        if !should_inject {
            return None;
        }
        *last = Some(now);
        Some(format!("[time: {}]", now.to_rfc3339()))
    }

    pub fn active_model(&self) -> Option<String> {
        self.model.lock().unwrap().clone()
    }

    pub fn active_provider(&self) -> Option<String> {
        self.provider.lock().unwrap().clone()
    }

    pub fn set_active_model(&self, provider: &str, model: &str) -> Result<()> {
        *self.provider.lock().unwrap() = Some(provider.to_string());
        *self.model.lock().unwrap() = Some(model.to_string());
        if self.stage_pending_row(|row| {
            row.provider = Some(provider.to_string());
            row.model = Some(model.to_string());
        }) {
            return Ok(());
        }
        self.db
            .set_session_model(self.id, provider, model)
            .context("persisting active model")?;
        Ok(())
    }

    pub fn set_active_agent(&self, agent: &str) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.active_agent = agent.to_string();
        }) {
            return Ok(());
        }
        self.db
            .set_session_agent(self.id, agent)
            .context("persisting active agent")
    }

    /// Touch `last_active_at`. Called by the daemon on every
    /// interaction so `cockpit -c` lands on the right session.
    pub fn touch(&self) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.last_active_at = Utc::now().timestamp();
        }) {
            return Ok(());
        }
        self.db.touch_session(self.id).context("touching session")
    }

    /// Mark this session viewed by a client. For an unpersisted deferred
    /// session, stage the marker so the first INSERT carries it; otherwise
    /// write through to the existing row.
    pub fn mark_viewed(&self) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.last_viewed_at = Some(Utc::now().timestamp());
        }) {
            return Ok(());
        }
        self.db
            .mark_session_viewed(self.id)
            .context("marking session viewed")
    }

    /// End the session — sets `ended_at` in the DB. Doesn't drop the
    /// row; history stays queryable via `cockpit session list`. Also
    /// removes the per-session tmp dir (sandboxing part 2): a session's
    /// scratch space doesn't outlive it.
    pub fn end(&self) -> Result<()> {
        self.remove_tmp_dir();
        self.db.end_session(self.id).context("ending session")
    }

    /// Remove the per-session tmp dir if one was created. Idempotent.
    /// Best-effort: a removal failure is logged, never propagated — it
    /// must not block session teardown.
    fn remove_tmp_dir(&self) {
        if let Some(dir) = self.tmp_dir.lock().unwrap().take()
            && let Err(e) = std::fs::remove_dir_all(&dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, dir = %dir.display(), "removing session tmp dir failed");
        }
    }

    /// Append one tool-call audit row to the §15b table.
    pub fn record_tool_call(&self, row: ToolCallRow) -> Result<()> {
        let provider = self.active_provider().unwrap_or_default();
        let model = self.active_model().unwrap_or_default();
        let project_root = self.project_root.to_string_lossy().into_owned();
        let event = ToolCallEvent {
            event_id: row.event_id,
            session_id: self.id,
            call_id: row.call_id,
            provider_item_id: row.identity.provider_item_id,
            provider_call_id: row.identity.provider_call_id,
            provider_call_id_source: row.identity.provider_call_id_source,
            wire_api: row.identity.wire_api,
            provider_family: row.identity.provider_family,
            timestamp: row.timestamp.timestamp(),
            model,
            provider,
            project_id: self.project_id.clone(),
            project_root,
            agent: row.agent,
            tool: row.tool,
            path: row.path,
            recovery: row.recovery,
            hard_fail: row.hard_fail,
            original_input_json: row.original_input_json,
            wire_input_json: row.wire_input_json,
            output: row.output,
            truncated: row.truncated,
            duration_ms: row.duration_ms,
            cockpit_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            llm_mode: Some(row.llm_mode.as_str().to_string()),
            shape_fingerprint: row.shape_fingerprint,
            hint: row.hint,
        };
        self.db
            .insert_tool_call(&event)
            .context("inserting tool_call_event")
    }

    /// Record provider-reported token usage for a round-trip: persist
    /// it to `inference_calls` for `/stats` and store the latest value
    /// on the session so the TUI can show it in the context indicator.
    /// No-op (for the DB write) when the active provider/model isn't set
    /// on the session (background calls during startup).
    ///
    /// `call_id` is the round-trip's id — the SAME value used to key the
    /// captured request body in `inference_requests`
    /// ([`Self::record_inference_request`]) so the metadata row and the
    /// full payload join on `call_id` (session-log-export Part A).
    pub fn record_usage(&self, call_id: Uuid, usage: crate::tokens::TokenUsage) -> Result<()> {
        self.record_usage_inner(call_id, usage, false)
    }

    /// Like [`Self::record_usage`] but flags the persisted `inference_calls`
    /// row as a utility / background call (the `/export debug` bundle routes
    /// it into `inference_requests_utility/`). Used by background round-trips
    /// (the `/compact` handoff brief, etc.) that aren't foreground user turns.
    pub fn record_usage_utility(
        &self,
        call_id: Uuid,
        usage: crate::tokens::TokenUsage,
    ) -> Result<()> {
        self.record_usage_inner(call_id, usage, true)
    }

    fn record_usage_inner(
        &self,
        call_id: Uuid,
        usage: crate::tokens::TokenUsage,
        is_utility: bool,
    ) -> Result<()> {
        *self.last_usage.lock().unwrap() = Some(usage);

        let (Some(provider), Some(model)) = (self.active_provider(), self.active_model()) else {
            return Ok(());
        };
        let row = crate::db::inference_calls::InferenceCallRow {
            call_id,
            session_id: self.id,
            project_id: self.project_id.clone(),
            project_root: self.project_root.to_string_lossy().into_owned(),
            model,
            provider,
            timestamp: Utc::now().timestamp(),
            input_tokens: usage.input_tokens as i64,
            output_tokens: usage.output_tokens as i64,
            cached_input_tokens: usage.cached_input_tokens as i64,
            cache_creation_input_tokens: usage.cache_creation_input_tokens as i64,
            cost_usd_micros: None,
            is_utility,
        };
        self.db
            .insert_inference_call(&row)
            .context("inserting inference_call")
    }

    /// Persist the full assembled (post-redaction) outbound request body
    /// for one inference call, keyed by `call_id` (session-log-export
    /// Part A), with its lifecycle `status`. Always-on — every call, every
    /// session. The payload is the exact as-sent form; no second redaction
    /// pass is applied. Written at DISPATCH with status `pending` and updated
    /// to its terminal value on settle so a hung/failed turn still records an
    /// attempt (implementation note).
    pub fn record_inference_request(
        &self,
        call_id: Uuid,
        payload: &Value,
        status: crate::db::session_log::InferenceRequestStatus,
    ) -> Result<()> {
        self.db
            .insert_inference_request(&call_id.to_string(), self.id, payload, status)
            .context("inserting inference_request")
    }

    /// Persist (or update) one tandem (shadow) inference record for
    /// model-comparison mode (implementation note),
    /// keyed by the per-row `id`. Unlike [`Self::record_inference_request`]
    /// (request body only), a tandem record additionally stores the full raw
    /// `response` + `usage`, and links back to the main call it shadows via
    /// `parent_call_id` (+ `parent_seq`/`agent` for timeline alignment).
    /// Written at dispatch (`pending`, no response) and again on settle
    /// (terminal status + captured response/usage). The `request` body is
    /// already post-redaction (reused from the main call's assembled body) —
    /// no second redaction pass.
    #[allow(clippy::too_many_arguments)]
    pub fn record_tandem_inference(
        &self,
        id: &str,
        parent_call_id: &str,
        parent_seq: Option<i64>,
        agent: Option<&str>,
        provider: &str,
        model: &str,
        request: &Value,
        response: Option<&Value>,
        usage: Option<&Value>,
        status: crate::db::session_log::InferenceRequestStatus,
    ) -> Result<()> {
        self.db
            .upsert_tandem_inference(
                id,
                self.id,
                parent_call_id,
                parent_seq,
                agent,
                provider,
                model,
                request,
                response,
                usage,
                status,
            )
            .context("inserting tandem_inference")
    }

    /// Snapshot the resolved agent-guidance file body at session start
    /// (live instructions-file diff injection, prompt
    /// `instructions-file-live-diff.md`). Called once when the session's
    /// system prompt is composed (the daemon session-worker spawn): the
    /// frozen system block carries this body, so it becomes the baseline a
    /// later in-place edit is diffed against.
    ///
    /// Resolves the same first-matching guidance file
    /// [`crate::engine::builtin`] bakes into the system block. When one
    /// resolves, stores `(path, hash)` on the session row and the body in
    /// the content-addressed `guidance_contents` table. When none resolves,
    /// clears the baseline (NULL) so the feature stays inert for this
    /// session. Best-effort: a failure here must never break session
    /// startup.
    pub fn snapshot_guidance_baseline(&self, cwd: &std::path::Path) {
        let baseline = match crate::engine::builtin::load_agent_guidance(cwd) {
            Some((path, body)) => {
                let hash = crate::engine::guidance_diff::hash_contents(&body);
                if let Err(e) = self.db.put_guidance_contents(&hash, &body) {
                    tracing::warn!(error = %e, "guidance baseline: storing contents failed");
                    return;
                }
                Some(crate::db::guidance::GuidanceBaseline {
                    path: path.display().to_string(),
                    hash,
                })
            }
            None => None,
        };
        if self.stage_pending_row(|row| {
            row.guidance_baseline_path = baseline.as_ref().map(|b| b.path.clone());
            row.guidance_baseline_hash = baseline.as_ref().map(|b| b.hash.clone());
        }) {
            return;
        }
        if let Err(e) = self.db.set_guidance_baseline(self.id, baseline.as_ref()) {
            tracing::warn!(error = %e, "guidance baseline: setting baseline failed");
        }
    }

    /// Check the resolved guidance file for an in-place edit since the
    /// session's stored baseline, and — when one is found — return the
    /// synthetic system-message body to append at the end of history (live
    /// instructions-file diff injection). The returned string is the
    /// authoritative framing header + unified diff (or full contents); the
    /// caller scrubs it through [`crate::redact`] before appending, exactly
    /// like any other outbound content.
    ///
    /// Returns `None` (no injection) when:
    /// - no baseline was stored (no guidance file at session start), or
    /// - re-resolution finds no guidance file (deleted mid-session), or
    /// - re-resolution finds a *different* file than the baseline path
    ///   (the file switched — out of scope), or
    /// - the resolved file's hash is unchanged (idempotent: already at
    ///   baseline, nothing to inject).
    ///
    /// On a real in-place change it persists the new body into the
    /// content-addressed table and **advances the baseline** to the new
    /// `(path, hash)` so the same change is injected exactly once; the next
    /// request diffs from the just-injected version.
    pub fn guidance_change_injection(&self, cwd: &std::path::Path) -> Option<String> {
        let baseline = match self.db.guidance_baseline(self.id) {
            Ok(Some(b)) => b,
            // No baseline stored → feature inert for this session.
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(error = %e, "guidance diff: reading baseline failed");
                return None;
            }
        };

        // Re-resolve the currently-winning guidance file. Deleted → None;
        // switched → a different path. Both are out of scope.
        let (current_path, current_body) = crate::engine::builtin::load_agent_guidance(cwd)?;
        let current_path = current_path.display().to_string();
        if current_path != baseline.path {
            // File deleted or a different file now wins — no in-place
            // change to track. Leave the baseline as-is; do not inject.
            return None;
        }

        let current_hash = crate::engine::guidance_diff::hash_contents(&current_body);
        if current_hash == baseline.hash {
            // Unchanged since baseline — idempotent no-op.
            return None;
        }

        // A genuine in-place edit. Persist the new body (content-addressed,
        // idempotent) and build the injection from the prior stored body.
        if let Err(e) = self.db.put_guidance_contents(&current_hash, &current_body) {
            tracing::warn!(error = %e, "guidance diff: storing new contents failed");
            return None;
        }
        let prior = self
            .db
            .guidance_contents(&baseline.hash)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "guidance diff: reading prior contents failed");
                None
            });
        let injection =
            crate::engine::guidance_diff::decide_injection(prior.as_deref(), &current_body);
        let message = crate::engine::guidance_diff::injection_message(&current_path, &injection);

        // Advance the baseline so this change injects exactly once.
        let advanced = crate::db::guidance::GuidanceBaseline {
            path: current_path,
            hash: current_hash,
        };
        if let Err(e) = self.db.set_guidance_baseline(self.id, Some(&advanced)) {
            tracing::warn!(error = %e, "guidance diff: advancing baseline failed");
            // Returning the message anyway would risk re-injecting the same
            // change next turn (baseline not advanced). Skip this injection
            // rather than risk a loop.
            return None;
        }
        Some(message)
    }

    /// Append one event to the session timeline (session-log-export Part
    /// B). Always-on, engine/daemon-owned. Returns the assigned monotonic
    /// `seq`. Best-effort callers may ignore the result.
    pub fn record_event(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        data: &Value,
    ) -> Result<i64> {
        self.record_event_with_origin(kind, agent, call_id, None, data)
    }

    pub fn record_event_with_origin(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        origin_principal: Option<&str>,
        data: &Value,
    ) -> Result<i64> {
        self.db
            .insert_session_event_with_origin(self.id, kind, agent, call_id, origin_principal, data)
            .context("inserting session_event")
    }

    pub fn set_created_by_principal(&self, principal: Option<String>) -> Result<()> {
        let mut pending = self.pending_row.lock().unwrap();
        if let Some(row) = pending.as_mut() {
            row.created_by_principal = principal;
            return Ok(());
        }
        self.db
            .set_session_created_by_principal(self.id, principal.as_deref())
            .context("setting session creator principal")
    }

    /// Record a `context_pruned` timeline event (session-log-export Part
    /// C). Fired by the real `/prune` path (manual + cache-cold auto): a
    /// wire-only snapshot dedup that elided superseded tool-result bodies.
    /// Carries messages-before/after, wire tokens-before/after, the elided
    /// `original_event_id`s, the reason, and the trigger (auto vs manual).
    ///
    /// Because auto-prune fires right before an inference call, this event
    /// lands immediately before the next `inference_request` event in
    /// `seq` order — the two adjacent request payloads then *show* the
    /// elision directly, which is the before/after-prune audit the export
    /// is for. `agent` is the foreground agent the prune targeted.
    #[allow(clippy::too_many_arguments)]
    pub fn record_context_pruned(
        &self,
        agent: &str,
        auto: bool,
        messages_before: usize,
        messages_after: usize,
        tokens_before: u64,
        tokens_after: u64,
        elided: &[String],
        reason: &str,
        tokens_saved: u64,
        remaining_budget: Option<u64>,
        trigger_reason: Option<&str>,
    ) -> Result<i64> {
        self.record_event(
            crate::db::session_log::SessionEventKind::ContextPruned,
            Some(agent),
            None,
            &serde_json::json!({
                "kind": "prune",
                "trigger": if auto { "auto" } else { "manual" },
                "messages_before": messages_before,
                "messages_after": messages_after,
                "tokens_before": tokens_before,
                "tokens_after": tokens_after,
                // The projected cl100k_base wire saving this prune realized,
                // so `analyze-session-logs` can judge effectiveness without
                // re-diffing the adjacent request payloads.
                "tokens_saved": tokens_saved,
                // Remaining context budget (model window − post-prune input
                // tokens) when the window + last usage are known; `null`
                // otherwise (ctx%-gated metrics inert).
                "remaining_budget": remaining_budget,
                "elided": elided,
                // Present for auto-prune so exports show why it fired
                // (cold cache, no-cache provider, upstream bust, or the warm
                // ctx/prunable threshold branch). Manual `/prune` leaves it
                // null because the trigger is the user command.
                "trigger_reason": trigger_reason,
                // The classifying reason: `overlap-merge`, `exact-identity`,
                // or `mixed` — distinct from the escalation-to-compaction
                // path, which records a `session_compacted` boundary instead.
                "reason": reason,
            }),
        )
    }

    /// Record a `session_compacted` timeline boundary (session-log-export
    /// Part C). `/compact` is a fresh-thread handoff, not an in-session
    /// edit: it starts a brand-new successor session and preserves this
    /// one. Modeled as a session boundary (predecessor → successor short
    /// ids) the export follows like the fork tree, so both sessions land
    /// in one unified `events.json`. Not a `context_pruned` event.
    pub fn record_session_compacted(
        &self,
        agent: &str,
        successor_session_id: Uuid,
        successor_short_id: &str,
        seed_tool_count: usize,
        brief_text: &str,
    ) -> Result<i64> {
        self.record_event(
            crate::db::session_log::SessionEventKind::SessionCompacted,
            Some(agent),
            None,
            &serde_json::json!({
                "kind": "compaction",
                "predecessor_session_id": self.id.to_string(),
                "predecessor_short_id": self.short_id,
                "successor_session_id": successor_session_id.to_string(),
                "successor_short_id": successor_short_id,
                "seed_tool_count": seed_tool_count,
                "brief_text": brief_text,
            }),
        )
    }

    /// Record a `tool_rejected` timeline event (export-audit fidelity). Fired
    /// from the dispatcher's validate-then-repair path (GOALS §12) when a call
    /// is rejected **before** it becomes a `tool_call` row — a hallucinated
    /// tool name (`not_in_advertised_set`), an unrepairable malformed call
    /// (`schema_invalid_unrepairable`), or a path-field pointing at a
    /// nonexistent file (`path_not_found`, model path-hallucination). Carries
    /// the attempted tool `name`, the `reason`, and optionally a compact
    /// corrected-shape hint when the dispatcher emitted one (token economy,
    /// project guidance priority #2): a hallucinated / unrepairable call becomes a
    /// one-query check instead of prose inference.
    /// The `call_id` is the model's per-tool-call id so the rejection joins the
    /// assistant turn that emitted it.
    pub fn record_tool_rejected(
        &self,
        agent: &str,
        call_id: &str,
        tool: &str,
        reason: &str,
    ) -> Result<i64> {
        self.record_tool_rejected_with_correction(agent, call_id, tool, reason, None)
    }

    pub fn record_tool_rejected_with_correction(
        &self,
        agent: &str,
        call_id: &str,
        tool: &str,
        reason: &str,
        correction: Option<Value>,
    ) -> Result<i64> {
        let mut data = serde_json::json!({
            "tool": tool,
            "reason": reason,
        });
        if let Some(correction) = correction {
            data["validation_correction"] = correction;
        }
        self.record_event(
            crate::db::session_log::SessionEventKind::ToolRejected,
            Some(agent),
            Some(call_id),
            &data,
        )
    }

    /// Record a `primary_swap` timeline event (export-audit fidelity). Fired
    /// whenever the root-frame primary is re-rooted (GOALS §26): an `Auto`→
    /// primary `handoff` (trigger `handoff`) or a `/plan`/`/build`/`/swarm`
    /// slash-command swap (trigger `swap_command`). Preserves the wire-vs-user
    /// split (GOALS §14): `display` is the user-facing row and `kickoff` is the
    /// model-facing wire kickoff. The `handoff` path supplies both; the
    /// slash-command swaps inject no kickoff, so `kickoff` is absent there
    /// (`None`) — never fabricated. Carries only `from`/`to`/`trigger`/`display`
    /// /`kickoff` (token economy, project guidance priority #2).
    pub fn record_primary_swap(
        &self,
        from: &str,
        to: &str,
        trigger: &str,
        display: Option<&str>,
        kickoff: Option<&str>,
    ) -> Result<i64> {
        self.record_event(
            crate::db::session_log::SessionEventKind::PrimarySwap,
            Some(from),
            None,
            &serde_json::json!({
                "from": from,
                "to": to,
                "trigger": trigger,
                "display": display,
                "kickoff": kickoff,
            }),
        )
    }

    /// Most recent provider-reported usage, if we've made any calls
    /// this session. Returns `None` before the first round-trip
    /// finishes — callers fall back to a local tiktoken estimate.
    pub fn last_usage(&self) -> Option<crate::tokens::TokenUsage> {
        *self.last_usage.lock().unwrap()
    }

    /// Seed the in-memory `last_usage` **without** writing an
    /// `inference_calls` row. Used by resume rehydration
    /// (implementation note) to recompute the context
    /// indicator from the reconstructed pruned history before the provider
    /// reports a real count — a local estimate, not a real round-trip, so
    /// it must not pollute `/stats`. The next real `record_usage` overwrites
    /// it with the provider's figure.
    pub fn set_last_usage_estimate(&self, usage: crate::tokens::TokenUsage) {
        *self.last_usage.lock().unwrap() = Some(usage);
    }

    /// Stamp "an inference send just happened now." Drives the cache-TTL
    /// arm of the cache-cold predicate (GOALS §10). Called once per
    /// `model.complete` round-trip.
    pub fn note_send(&self) {
        *self.last_send_at.lock().unwrap() = Some(std::time::Instant::now());
    }

    /// Seconds since the last inference send, or `None` if no send has
    /// happened yet this (in-memory) session. `None` means "treat the
    /// cache as cold" — there is no warm prefix to lose.
    pub fn seconds_since_last_send(&self) -> Option<u64> {
        self.last_send_at
            .lock()
            .unwrap()
            .map(|t| t.elapsed().as_secs())
    }

    /// Record a dispatched tool call's loop-guard `signature` and return
    /// how many times *in a row* that exact signature has now been issued
    /// (GOALS §1/§12). A repeat of the immediately-preceding call returns
    /// an incremented count; any different call resets the count to 1.
    /// This is the back-to-back detector: only the immediately-preceding
    /// call is compared, so an intervening different call breaks the
    /// chain.
    ///
    /// Called once per dispatched tool call, *before* the guard decides
    /// whether to run it. The count it returns is compared against the
    /// configured threshold (default 2 = fire on the first exact repeat).
    pub fn bump_consecutive_call(&self, signature: &str) -> u32 {
        let mut slot = self.last_tool_call.lock().unwrap();
        let consecutive = match slot.as_ref() {
            Some(prev) if prev.signature == signature => prev.consecutive.saturating_add(1),
            _ => 1,
        };
        *slot = Some(LastToolCall {
            signature: signature.to_string(),
            consecutive,
        });
        consecutive
    }

    /// Return the stored short-circuit guidance when the immediately
    /// previous recoverable-dead-end call had the same final semantic
    /// signature. A different call clears the slot and returns `None`.
    pub fn repeated_recoverable_tool_call_message(&self, signature: &str) -> Option<String> {
        let mut slot = self.last_recoverable_tool_call.lock().unwrap();
        match slot.as_ref() {
            Some(prev) if prev.signature == signature => Some(prev.message.clone()),
            _ => {
                *slot = None;
                None
            }
        }
    }

    /// Remember that the most recent call with `signature` ended in a
    /// recoverable dead-end and should be short-circuited if repeated
    /// immediately.
    pub fn remember_recoverable_tool_call(&self, signature: String, message: String) {
        *self.last_recoverable_tool_call.lock().unwrap() =
            Some(LastRecoverableToolCall { signature, message });
    }

    /// Clear any remembered recoverable repeat-guard state.
    pub fn clear_recoverable_tool_call(&self) {
        *self.last_recoverable_tool_call.lock().unwrap() = None;
    }

    /// Pin a user message as must-survive (`/pin`). Injected verbatim
    /// into the next `/compact` handoff. No-ops on blank input.
    pub fn pin_message(&self, text: &str) {
        let t = text.trim();
        if !t.is_empty() {
            self.pinned_messages.lock().unwrap().push(t.to_string());
        }
    }

    /// Snapshot of pinned messages, in pin order.
    pub fn pinned_messages(&self) -> Vec<String> {
        self.pinned_messages.lock().unwrap().clone()
    }

    /// Feed one inference round into the tokenizer-calibration window.
    /// `basis` is a consistent text proxy for the round-trip (the
    /// messages sent + the assistant output); `usage` is the provider's
    /// report. Samples are skipped when usage is empty or any input was
    /// cached (caching muddies the input count), and when a fresh
    /// calibration row already exists for the active `(provider,
    /// model)`. When the window closes, the best `(strategy, scale)` is
    /// fitted and persisted with a 90-day expiry.
    pub fn note_calibration_sample(&self, basis: &str, usage: crate::tokens::TokenUsage) {
        if usage.is_empty() || usage.cached_input_tokens != 0 {
            return;
        }
        let (Some(provider), Some(model)) = (self.active_provider(), self.active_model()) else {
            return;
        };
        let now = Utc::now().timestamp();
        if self.db.tokenizer_calibration_fresh(&provider, &model, now) {
            return;
        }
        let actual = usage.input_tokens.saturating_add(usage.output_tokens);
        let mut cal = self.calibrator.lock().unwrap();
        cal.add_sample(basis, actual);
        if cal.window_closed()
            && let Some((strategy, scale)) = cal.result()
        {
            let total = cal.cumulative_actual() as i64;
            let calls = cal.sample_calls() as i64;
            if let Err(e) = self.db.upsert_tokenizer_calibration(
                &provider,
                &model,
                strategy.as_str(),
                scale,
                now,
                now + crate::db::tokenizer_calibration::CALIBRATION_TTL_SECS,
                total,
                calls,
            ) {
                tracing::warn!(error = %e, "upsert tokenizer_calibration failed");
            }
            *cal = crate::tokens::Calibrator::new();
        }
    }
}

impl Drop for Session {
    /// Backstop tmp cleanup (sandboxing part 2): if a session is dropped
    /// without an explicit [`Self::end`] (e.g. an `Arc` ref-count hits
    /// zero on a teardown path that didn't end it), still remove the
    /// scratch dir so it doesn't linger across daemon restarts.
    fn drop(&mut self) {
        self.remove_tmp_dir();
    }
}

/// In-memory analog of `tool_call_events` (GOALS §15b). The driver
/// assembles this; the session converts to [`ToolCallEvent`] and
/// writes via the DB.
#[derive(Debug, Clone)]
pub struct ToolCallRow {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub agent: String,
    pub call_id: String,
    pub identity: ToolCallProviderIdentity,
    pub tool: String,
    pub path: Option<String>,
    /// What the model emitted. Per §14 this is what the user transcript
    /// shows.
    pub original_input_json: Value,
    /// What the next inference call carries. Equal to
    /// `original_input_json` when no §13c rewrite was applied; differs
    /// when shape repair fired or the edit-cascade matched at a
    /// non-canonical stage.
    pub wire_input_json: Value,
    pub recovery: Recovery,
    pub hard_fail: bool,
    pub output: String,
    pub truncated: bool,
    pub duration_ms: u64,
    pub llm_mode: crate::config::extended::LlmMode,
    /// §12 repair shape-fingerprint (implementation note).
    /// `Some` on a recovered or unrepairable call (the call was malformed),
    /// `None` on a clean call. Persisted so `cockpit debug failed-calls` can
    /// group/count failures by model + fingerprint.
    pub shape_fingerprint: Option<String>,
    /// Post-result hint (`engine::bash_hints`), as a JSON `{ kind, text,
    /// severity }`, when a rule matched this (`bash`) call. `None` otherwise.
    /// Persisted to `tool_call_events.hint`; mirrored on the export `data.hint`.
    pub hint: Option<Value>,
}

#[derive(Debug, Clone, Default)]
pub struct ToolCallProviderIdentity {
    pub provider_item_id: Option<String>,
    pub provider_call_id: Option<String>,
    pub provider_call_id_source: Option<String>,
    pub wire_api: Option<String>,
    pub provider_family: Option<String>,
}

impl ToolCallProviderIdentity {
    pub fn synthetic_responses_call(cockpit_call_id: &str) -> Self {
        Self {
            provider_item_id: Some(cockpit_call_id.to_string()),
            provider_call_id: Some(cockpit_call_id.to_string()),
            provider_call_id_source: Some("synthetic_from_cockpit_call_id".to_string()),
            wire_api: Some("responses".to_string()),
            provider_family: Some("cockpit".to_string()),
        }
    }

    pub fn from_provider_call(
        provider: &str,
        model: &str,
        provider_item_id: String,
        provider_call_id: Option<String>,
    ) -> Self {
        let wire_api = crate::config::providers::WireApi::detect_for_provider(provider, model);
        let is_responses = matches!(wire_api, crate::config::providers::WireApi::Responses);
        let (provider_call_id, provider_call_id_source) = match provider_call_id {
            Some(call_id) => (Some(call_id), Some("provider".to_string())),
            None if is_responses => (
                Some(provider_item_id.clone()),
                Some("normalized_from_assistant_id".to_string()),
            ),
            None => (None, None),
        };
        Self {
            provider_item_id: Some(provider_item_id),
            provider_call_id,
            provider_call_id_source,
            wire_api: Some(
                match wire_api {
                    crate::config::providers::WireApi::Responses => "responses",
                    crate::config::providers::WireApi::Completions => "completions",
                    crate::config::providers::WireApi::Auto => "unknown",
                }
                .to_string(),
            ),
            provider_family: Some(provider_family_for_id(provider).to_string()),
        }
    }
}

fn provider_family_for_id(provider: &str) -> &'static str {
    match provider {
        "openai" => "openai",
        "codex-oauth" => "codex",
        "grok" | "grok-oauth" => "xai",
        "anthropic" => "anthropic",
        _ => "unknown",
    }
}

/// Encode an [`crate::config::extended::ApprovalMode`] as the `u8` the
/// session's atomic stores. Inverse of [`approval_mode_from_u8`].
fn sandbox_mode_to_u8(mode: crate::tools::sandbox_mode::SandboxMode) -> u8 {
    match mode {
        crate::tools::sandbox_mode::SandboxMode::Off => 0,
        crate::tools::sandbox_mode::SandboxMode::Sandbox => 1,
        crate::tools::sandbox_mode::SandboxMode::Container => 2,
        crate::tools::sandbox_mode::SandboxMode::ContainerReadonly => 3,
    }
}

fn sandbox_mode_from_u8(value: u8) -> crate::tools::sandbox_mode::SandboxMode {
    match value {
        0 => crate::tools::sandbox_mode::SandboxMode::Off,
        2 => crate::tools::sandbox_mode::SandboxMode::Container,
        3 => crate::tools::sandbox_mode::SandboxMode::ContainerReadonly,
        _ => crate::tools::sandbox_mode::SandboxMode::Sandbox,
    }
}

fn approval_mode_to_u8(mode: crate::config::extended::ApprovalMode) -> u8 {
    use crate::config::extended::ApprovalMode;
    match mode {
        ApprovalMode::Manual => 0,
        ApprovalMode::Auto => 1,
        ApprovalMode::Yolo => 2,
    }
}

/// Decode the session's stored `u8` back to an
/// [`crate::config::extended::ApprovalMode`]. Any unexpected value reads as
/// `Manual` — the fail-safe default (ask the user).
fn approval_mode_from_u8(v: u8) -> crate::config::extended::ApprovalMode {
    use crate::config::extended::ApprovalMode;
    match v {
        1 => ApprovalMode::Auto,
        2 => ApprovalMode::Yolo,
        _ => ApprovalMode::Manual,
    }
}

/// Hash the project root into a 12-char hex id. Stable across symlink
/// shifts because the input is the realpath when available.
pub fn project_id_for(root: &PathBuf) -> String {
    use sha2::{Digest, Sha256};
    let canon = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
    let s = canon.to_string_lossy();
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    let mut hex = String::with_capacity(12);
    for byte in out.iter().take(6) {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

const TITLE_SCHEDULE_SLOTS: [u8; 5] = [1, 2, 4, 8, 16];

fn normalize_title_slot(value: i64) -> u8 {
    match value {
        i64::MIN..=0 => 0,
        1 => 1,
        2 | 3 => 2,
        4..=7 => 4,
        8..=15 => 8,
        _ => 16,
    }
}

fn scheduled_title_slot(user_turns: usize, last_slot: u8) -> Option<u8> {
    let slot = u8::try_from(user_turns).ok()?;
    if TITLE_SCHEDULE_SLOTS.contains(&slot) && slot > last_slot {
        Some(slot)
    } else {
        None
    }
}

fn count_user_turns_for_title(db: &Db, session_id: Uuid) -> usize {
    match db.thread_turns(session_id) {
        Ok(turns) => turns.iter().filter(|t| t.role == "user").count(),
        Err(e) => {
            tracing::debug!(error = %e, "auto_title: reading user turn count failed");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_and_resume_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db.clone(), PathBuf::from("/x"), "Build").unwrap();
        let id = s.id;
        let short = s.short_id.clone();
        drop(s);
        let s2 = Session::resume(db, id).unwrap().unwrap();
        assert_eq!(s2.id, id);
        assert_eq!(s2.short_id, short);
        assert!(s2.parent_session_id.is_none());
        assert!(s2.title().is_none());
        assert!(!s2.user_renamed());
    }

    #[test]
    fn fork_inherits_parent_metadata() {
        let db = Db::open_in_memory().unwrap();
        let parent = Session::create(db.clone(), PathBuf::from("/x"), "Build").unwrap();
        parent.set_active_model("anthropic", "opus-4-7").unwrap();
        let fork_point = parent
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({"text": "fork here"}),
            )
            .unwrap();
        let fork =
            Session::create_fork(db.clone(), parent.id, Some(fork_point.to_string())).unwrap();
        assert_eq!(fork.parent_session_id, Some(parent.id));
        let fork_point = fork_point.to_string();
        assert_eq!(
            fork.fork_point_turn_id.as_deref(),
            Some(fork_point.as_str())
        );
        assert_eq!(fork.project_id, parent.project_id);
        assert_eq!(fork.active_provider().as_deref(), Some("anthropic"));
        assert_eq!(fork.active_model().as_deref(), Some("opus-4-7"));
        assert_ne!(fork.id, parent.id);
        assert_ne!(fork.short_id, parent.short_id);
    }

    #[test]
    fn rename_persists_and_blocks_auto_title() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db.clone(), PathBuf::from("/x"), "a").unwrap();
        s.rename("hand-picked").unwrap();
        assert!(s.user_renamed());
        assert_eq!(s.title().as_deref(), Some("hand-picked"));
        assert!(!s.set_auto_title("robot-name").unwrap());
        assert_eq!(s.title().as_deref(), Some("hand-picked"));
    }

    #[test]
    fn time_prelude_fires_on_first_call() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        let prelude = s.take_time_prelude(5);
        assert!(prelude.is_some());
        let body = prelude.unwrap();
        assert!(body.starts_with("[time: "), "got {body:?}");
        assert!(body.ends_with(']'), "got {body:?}");
    }

    #[test]
    fn time_prelude_suppressed_within_interval() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        assert!(s.take_time_prelude(5).is_some(), "first call should fire");
        assert!(
            s.take_time_prelude(5).is_none(),
            "second call within 5 min should suppress"
        );
    }

    #[test]
    fn time_prelude_fires_at_zero_interval() {
        // A 0-minute interval is the "always inject" config, mainly for
        // tests. Two back-to-back calls both fire.
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        assert!(s.take_time_prelude(0).is_some());
        assert!(s.take_time_prelude(0).is_some());
    }

    /// Build a string whose cl100k_base token count is at least
    /// `target` tokens. Repeats an English sentence so the BPE
    /// merges land realistically (unlike `"x".repeat(N)`, which
    /// collapses to a tiny number of tokens).
    fn text_of_at_least(target: usize) -> String {
        let sentence = "the quick brown fox jumps over the lazy dog. ";
        let mut s = String::new();
        while crate::tokens::count(&s) < target {
            s.push_str(sentence);
        }
        s
    }

    #[test]
    fn note_user_content_eager_fires_on_first_short_message() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        let msg = "a short message";
        assert_eq!(s.note_user_content(msg), TitleAction::Eager);
        assert_eq!(s.user_content_tokens(), crate::tokens::count(msg));
        assert_eq!(s.user_content_turns(), 1);
        assert_eq!(s.title_stage(), 1);
    }

    #[test]
    fn note_user_content_uses_bounded_turn_slots() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        let observed: Vec<_> = (1..=17)
            .filter_map(|turn| {
                let action = s.note_user_content(&format!("turn {turn}"));
                (action != TitleAction::None).then_some((turn, action, s.title_stage()))
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                (1, TitleAction::Eager, 1),
                (2, TitleAction::Refine, 2),
                (4, TitleAction::Refine, 4),
                (8, TitleAction::Refine, 8),
                (16, TitleAction::Refine, 16),
            ]
        );
        assert_eq!(s.note_user_content("turn 18"), TitleAction::None);
        assert_eq!(s.title_stage(), 16);
    }

    #[test]
    fn scheduled_slot_is_consumed_even_without_title_success() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        assert_eq!(s.note_user_content("first"), TitleAction::Eager);
        assert!(s.title().is_none(), "utility task has not landed a title");
        assert_eq!(
            s.note_user_content("third user turn after a missed title slot"),
            TitleAction::Refine,
            "the second user turn still uses the slot-2 refresh, not a repeated eager slot"
        );
    }

    #[test]
    fn note_user_content_skips_when_user_renamed() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        s.rename("user-set").unwrap();
        // No scheduled slot fires once the user has renamed — not even eager.
        assert_eq!(s.note_user_content("hello"), TitleAction::None);
        let big = text_of_at_least(crate::auto_title::TITLE_TOKEN_THRESHOLD);
        assert_eq!(s.note_user_content(&big), TitleAction::None);
    }

    #[test]
    fn note_user_content_empty_is_noop() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        assert_eq!(s.note_user_content(""), TitleAction::None);
        assert_eq!(s.user_content_tokens(), 0);
        assert_eq!(s.user_content_turns(), 0);
    }

    #[test]
    fn non_slot_turns_do_not_fire_even_with_large_content() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        let big = text_of_at_least(crate::auto_title::TITLE_TOKEN_THRESHOLD * 2);
        assert_eq!(s.note_user_content("one"), TitleAction::Eager);
        assert_eq!(s.note_user_content("two"), TitleAction::Refine);
        assert_eq!(s.note_user_content(&big), TitleAction::None);
    }

    #[test]
    fn title_progress_survives_resume() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db.clone(), PathBuf::from("/x"), "a").unwrap();
        let id = s.id;
        s.record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("a"),
            None,
            &json!({"text": "hello"}),
        )
        .unwrap();
        assert_eq!(s.note_user_content("hello"), TitleAction::Eager);
        let carried = s.user_content_tokens();
        assert_eq!(s.title_stage(), 1);
        drop(s);

        let resumed = Session::resume(db, id).unwrap().unwrap();
        assert_eq!(
            resumed.user_content_tokens(),
            carried,
            "cumulative estimate survives resume"
        );
        assert_eq!(resumed.user_content_turns(), 1);
        assert_eq!(resumed.title_stage(), 1);
        assert_eq!(
            resumed.note_user_content("second"),
            TitleAction::Refine,
            "resume advances to the next slot instead of repeating slot 1"
        );
    }

    #[test]
    fn note_user_content_refine_skips_when_user_renamed_after_eager() {
        // A /rename after an eager title wins and blocks later scheduled slots.
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        assert!(s.set_auto_title("eager-title").unwrap());
        s.mark_eager_titled();
        s.rename("user-chosen").unwrap();
        let big = text_of_at_least(crate::auto_title::TITLE_TOKEN_THRESHOLD);
        assert_eq!(s.note_user_content(&big), TitleAction::None);
    }

    #[test]
    fn title_failure_notice_is_one_per_session() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        assert!(s.claim_title_failure_notice(), "first claim wins");
        assert!(
            !s.claim_title_failure_notice(),
            "second claim is suppressed"
        );
    }

    #[test]
    fn fork_inherits_user_content_counter() {
        let db = Db::open_in_memory().unwrap();
        let parent = Session::create(db.clone(), PathBuf::from("/x"), "a").unwrap();
        let _ = parent.note_user_content(&"x".repeat(1000));
        let fork = Session::create_fork(db, parent.id, None).unwrap();
        assert_eq!(fork.user_content_tokens(), parent.user_content_tokens());
    }

    #[test]
    fn tmp_dir_is_per_session_and_isolated() {
        // Two sessions get distinct private tmp dirs (sandboxing part 2),
        // so neither can read the other's scratch.
        let db = Db::open_in_memory().unwrap();
        let a = Session::create(db.clone(), PathBuf::from("/x"), "builder").unwrap();
        let b = Session::create(db, PathBuf::from("/x"), "builder").unwrap();
        let da = a.tmp_dir().unwrap();
        let db_ = b.tmp_dir().unwrap();
        assert_ne!(da, db_, "sessions must not share a tmp dir");
        assert!(da.exists());
        assert!(db_.exists());
        // Idempotent: a second call returns the same dir.
        assert_eq!(a.tmp_dir().unwrap(), da);
    }

    #[test]
    fn tmp_dir_removed_on_end() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "builder").unwrap();
        let dir = s.tmp_dir().unwrap();
        std::fs::write(dir.join("scratch"), "x").unwrap();
        assert!(dir.exists());
        s.end().unwrap();
        assert!(!dir.exists(), "tmp dir must be cleaned up on session end");
    }

    #[test]
    fn tmp_dir_removed_on_drop() {
        let db = Db::open_in_memory().unwrap();
        let dir = {
            let s = Session::create(db, PathBuf::from("/x"), "builder").unwrap();
            let d = s.tmp_dir().unwrap();
            assert!(d.exists());
            d
        };
        assert!(!dir.exists(), "drop is the cleanup backstop");
    }

    #[test]
    fn sandbox_flag_defaults_on_and_toggles() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "builder").unwrap();
        // Sandboxing-enabled (sandboxing part 2): defaults ON.
        assert!(s.sandbox_enabled());
        // Explicit set.
        assert!(!s.set_sandbox_enabled(false));
        assert!(!s.sandbox_enabled());
        assert!(s.set_sandbox_enabled(true));
        assert!(s.sandbox_enabled());
        // Toggle flips and returns the new state.
        assert!(!s.toggle_sandbox_enabled());
        assert!(s.toggle_sandbox_enabled());
        assert!(s.sandbox_enabled());
    }

    #[test]
    fn approval_mode_defaults_manual_and_round_trips() {
        use crate::config::extended::ApprovalMode;
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "builder").unwrap();
        // Fail-safe default until the spawn path applies the config default.
        assert_eq!(s.approval_mode(), ApprovalMode::Manual);
        // Each mode round-trips through the atomic encode/decode.
        for m in [ApprovalMode::Auto, ApprovalMode::Yolo, ApprovalMode::Manual] {
            assert_eq!(s.set_approval_mode(m), m);
            assert_eq!(s.approval_mode(), m);
        }
    }

    #[test]
    fn bump_consecutive_counts_back_to_back_repeats() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "builder").unwrap();
        // First call of a signature → count 1.
        assert_eq!(s.bump_consecutive_call("sig-a"), 1);
        // Immediate repeat → count 2 (the first exact repeat).
        assert_eq!(s.bump_consecutive_call("sig-a"), 2);
        // And again → 3.
        assert_eq!(s.bump_consecutive_call("sig-a"), 3);
    }

    #[test]
    fn bump_consecutive_resets_on_a_different_call() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "builder").unwrap();
        assert_eq!(s.bump_consecutive_call("sig-a"), 1);
        assert_eq!(s.bump_consecutive_call("sig-a"), 2);
        // A different call breaks the chain — count resets to 1.
        assert_eq!(s.bump_consecutive_call("sig-b"), 1);
        // The original signature repeated *after* an intervening call is
        // NOT consecutive — it starts a fresh chain at 1, so a
        // non-consecutive repeat never trips the guard.
        assert_eq!(s.bump_consecutive_call("sig-a"), 1);
    }

    #[test]
    fn repeated_recoverable_tool_call_message_matches_and_clears_on_difference() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "builder").unwrap();

        s.remember_recoverable_tool_call("sig-a".to_string(), "use tree without path".to_string());
        assert_eq!(
            s.repeated_recoverable_tool_call_message("sig-a"),
            Some("use tree without path".to_string())
        );
        assert_eq!(
            s.repeated_recoverable_tool_call_message("sig-b"),
            None,
            "a different intervening call clears the remembered repeat guard"
        );
        assert_eq!(s.repeated_recoverable_tool_call_message("sig-a"), None);
    }

    #[test]
    fn clear_recoverable_tool_call_drops_memory() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "builder").unwrap();

        s.remember_recoverable_tool_call("sig-a".to_string(), "msg".to_string());
        s.clear_recoverable_tool_call();

        assert_eq!(s.repeated_recoverable_tool_call_message("sig-a"), None);
    }

    #[test]
    fn deferred_session_is_not_written_until_first_message() {
        // session-id-display-and-lazy-persist: a deferred session has an id
        // and short_id in memory but no `sessions` row, and never appears in
        // listings until persisted.
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred(db.clone(), PathBuf::from("/x"), "Build").unwrap();
        // Id + short_id exist immediately (for the startup graphic).
        assert!(!s.short_id.is_empty());
        assert!(!s.is_persisted());
        // No DB row yet: not fetchable, not listed.
        assert!(db.get_session(s.id).unwrap().is_none());
        assert!(db.list_sessions(true, 100).unwrap().is_empty());

        // First user message → persist. The flush returns `true` once.
        assert!(
            s.persist_if_needed().unwrap(),
            "first persist writes the row"
        );
        assert!(s.is_persisted());
        let row = db.get_session(s.id).unwrap().expect("row now exists");
        assert_eq!(row.short_id.as_deref(), Some(s.short_id.as_str()));
        assert_eq!(db.list_sessions(true, 100).unwrap().len(), 1);

        // Idempotent: a second flush is a no-op (returns `false`).
        assert!(!s.persist_if_needed().unwrap());
        assert_eq!(db.list_sessions(true, 100).unwrap().len(), 1);
    }

    #[test]
    fn deferred_persist_carries_provider_and_model() {
        // A model picked before the first message survives the deferred
        // write (session-id-display-and-lazy-persist).
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred(db.clone(), PathBuf::from("/x"), "Build").unwrap();
        // set_active_model's DB UPDATE is a no-op while un-persisted; the
        // value lives in memory and must land in the deferred INSERT.
        s.set_active_model("anthropic", "claude-opus-4-7").unwrap();
        assert!(db.get_session(s.id).unwrap().is_none());
        s.persist_if_needed().unwrap();
        let row = db.get_session(s.id).unwrap().unwrap();
        assert_eq!(row.provider.as_deref(), Some("anthropic"));
        assert_eq!(row.model.as_deref(), Some("claude-opus-4-7"));
    }

    #[test]
    fn deferred_persist_carries_agent_touch_and_viewed() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred(db.clone(), PathBuf::from("/x"), "Build").unwrap();
        let original_last_active = {
            let row = s.pending_row.lock().unwrap();
            row.as_ref().unwrap().last_active_at
        };

        s.set_active_agent("Plan").unwrap();
        s.touch().unwrap();
        s.mark_viewed().unwrap();
        assert!(db.get_session(s.id).unwrap().is_none());

        s.persist_if_needed().unwrap();
        let row = db.get_session(s.id).unwrap().unwrap();
        assert_eq!(row.active_agent, "Plan");
        assert!(row.last_active_at >= original_last_active);
        assert!(row.last_viewed_at.is_some());
    }

    #[test]
    fn create_is_persisted_immediately() {
        // The non-deferred constructor writes the row up front, so
        // persist_if_needed is a no-op and is_persisted is true.
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db.clone(), PathBuf::from("/x"), "builder").unwrap();
        assert!(s.is_persisted());
        assert!(!s.persist_if_needed().unwrap());
        assert!(db.get_session(s.id).unwrap().is_some());
    }

    #[test]
    fn record_tool_call_writes_row() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db.clone(), PathBuf::from("/x"), "builder").unwrap();
        s.set_active_model("anthropic", "claude-opus-4-7").unwrap();
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent: "builder".into(),
            call_id: "c-1".into(),
            identity: ToolCallProviderIdentity::default(),
            tool: "read".into(),
            path: Some("src/main.rs".into()),
            original_input_json: json!({"path":"src/main.rs"}),
            wire_input_json: json!({"path":"src/main.rs"}),
            recovery: Recovery::Clean,
            hard_fail: false,
            output: "1: fn main()".into(),
            truncated: false,
            duration_ms: 4,
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
        .unwrap();
        let rows = db.list_tool_calls_for_session(s.id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].model, "claude-opus-4-7");
        assert_eq!(rows[0].provider, "anthropic");
    }

    #[test]
    fn record_tool_call_persists_provider_identity_separately() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db.clone(), PathBuf::from("/x"), "builder").unwrap();
        s.set_active_model("codex-oauth", "gpt-5.5").unwrap();
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent: "builder".into(),
            call_id: "cockpit-internal".into(),
            identity: ToolCallProviderIdentity::from_provider_call(
                "codex-oauth",
                "gpt-5.5",
                "provider-item".into(),
                Some("provider-call".into()),
            ),
            tool: "read".into(),
            path: None,
            original_input_json: json!({"path":"src/main.rs"}),
            wire_input_json: json!({"path":"src/main.rs"}),
            recovery: Recovery::Clean,
            hard_fail: false,
            output: "body".into(),
            truncated: false,
            duration_ms: 4,
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
        .unwrap();

        let row = db.list_tool_calls_for_session(s.id).unwrap().pop().unwrap();
        assert_eq!(row.call_id, "cockpit-internal");
        assert_eq!(row.provider_item_id.as_deref(), Some("provider-item"));
        assert_eq!(row.provider_call_id.as_deref(), Some("provider-call"));
        assert_eq!(row.provider_call_id_source.as_deref(), Some("provider"));
        assert_eq!(row.wire_api.as_deref(), Some("responses"));
        assert_eq!(row.provider_family.as_deref(), Some("codex"));
    }

    // ---- live instructions-file diff injection ----------------------------
    // (prompt `instructions-file-live-diff.md`)

    /// A session rooted in a tempdir holding an `AGENTS.md` guidance file.
    /// Returns the session, the dir handle (kept alive), and the file path.
    fn guidance_session(body: &str) -> (Session, tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("AGENTS.md");
        std::fs::write(&path, body).unwrap();
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, tmp.path().to_path_buf(), "Build").unwrap();
        (s, tmp, path)
    }

    #[test]
    fn snapshot_records_baseline_and_contents() {
        let (s, tmp, _path) = guidance_session("RULE A\nRULE B\n");
        s.snapshot_guidance_baseline(tmp.path());
        let baseline = s.db.guidance_baseline(s.id).unwrap().expect("baseline set");
        assert!(baseline.path.ends_with("AGENTS.md"));
        // The content-addressed table holds the exact body.
        let stored = s.db.guidance_contents(&baseline.hash).unwrap();
        assert_eq!(stored.as_deref(), Some("RULE A\nRULE B\n"));
        // Hash matches the pure hasher over the body.
        assert_eq!(
            baseline.hash,
            crate::engine::guidance_diff::hash_contents("RULE A\nRULE B\n")
        );
    }

    #[test]
    fn deferred_snapshot_baseline_survives_first_persist() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("AGENTS.md");
        std::fs::write(&path, "RULE A\nRULE B\n").unwrap();
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();

        s.snapshot_guidance_baseline(tmp.path());
        assert!(db.get_session(s.id).unwrap().is_none());

        s.persist_if_needed().unwrap();
        let baseline = s.db.guidance_baseline(s.id).unwrap().expect("baseline set");
        assert_eq!(baseline.path, path.display().to_string());
        assert_eq!(
            baseline.hash,
            crate::engine::guidance_diff::hash_contents("RULE A\nRULE B\n")
        );
    }

    #[test]
    fn deferred_guidance_edit_injects_after_first_message_persist() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("AGENTS.md");
        std::fs::write(&path, "line one\nline two\nline three\n").unwrap();
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred(db, tmp.path().to_path_buf(), "Build").unwrap();

        s.snapshot_guidance_baseline(tmp.path());
        s.persist_if_needed().unwrap();
        std::fs::write(&path, "line one\nline TWO\nline three\n").unwrap();

        let msg = s
            .guidance_change_injection(tmp.path())
            .expect("deferred baseline should inject after persist");
        assert!(msg.contains("changed since this conversation began"));
        assert!(msg.contains("line TWO"), "updated guidance missing: {msg}");
        assert!(
            s.guidance_change_injection(tmp.path()).is_none(),
            "same change should be idempotent"
        );
    }

    #[test]
    fn resumed_session_guidance_baseline_still_updates() {
        let (s, tmp, path) = guidance_session("v1\n");
        s.snapshot_guidance_baseline(tmp.path());
        let resumed = Session::resume(s.db.clone(), s.id)
            .unwrap()
            .expect("session should resume");

        std::fs::write(&path, "v2\n").unwrap();
        resumed.snapshot_guidance_baseline(tmp.path());
        assert!(resumed.guidance_change_injection(tmp.path()).is_none());
        std::fs::write(&path, "v3\n").unwrap();
        assert!(resumed.guidance_change_injection(tmp.path()).is_some());
    }

    #[test]
    fn snapshot_with_no_guidance_file_leaves_null_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, tmp.path().to_path_buf(), "Build").unwrap();
        s.snapshot_guidance_baseline(tmp.path());
        assert_eq!(s.db.guidance_baseline(s.id).unwrap(), None);
        // And no injection ever fires for such a session.
        assert!(s.guidance_change_injection(tmp.path()).is_none());
    }

    #[test]
    fn in_place_edit_injects_unified_diff_then_is_idempotent() {
        let (s, tmp, path) =
            guidance_session("line one\nline two\nline three\nline four\nline five\n");
        s.snapshot_guidance_baseline(tmp.path());
        // No change yet → no injection.
        assert!(s.guidance_change_injection(tmp.path()).is_none());

        // Edit one line in place.
        std::fs::write(
            &path,
            "line one\nline two\nline THREE\nline four\nline five\n",
        )
        .unwrap();
        let msg = s
            .guidance_change_injection(tmp.path())
            .expect("a change should inject");
        assert!(
            msg.contains("changed since this conversation began"),
            "header missing: {msg}"
        );
        assert!(msg.contains("- line three"), "diff missing removal: {msg}");
        assert!(msg.contains("+ line THREE"), "diff missing addition: {msg}");

        // Idempotent: the same content does not re-inject (baseline
        // advanced to the edited body).
        assert!(
            s.guidance_change_injection(tmp.path()).is_none(),
            "the same change must not re-inject"
        );

        // A further edit produces a new diff (now diffed from the edited
        // body, not the original).
        std::fs::write(
            &path,
            "line one\nline two\nline THREE\nline FOUR\nline five\n",
        )
        .unwrap();
        let msg2 = s
            .guidance_change_injection(tmp.path())
            .expect("a further change should inject");
        assert!(msg2.contains("+ line FOUR"), "second diff: {msg2}");
        // It diffs from the previously-injected version, so the first edit
        // ("THREE") is now context, not a `+` line.
        assert!(!msg2.contains("+ line THREE"), "second diff: {msg2}");
    }

    #[test]
    fn near_total_rewrite_injects_full_contents_not_a_diff() {
        let (s, tmp, path) = guidance_session("alpha\nbeta\ngamma\ndelta\nepsilon\n");
        s.snapshot_guidance_baseline(tmp.path());
        // Rewrite every line.
        std::fs::write(&path, "ALPHA\nBETA\nGAMMA\nDELTA\nEPSILON\n").unwrap();
        let msg = s
            .guidance_change_injection(tmp.path())
            .expect("a change should inject");
        // Full-contents fallback: the new lines appear verbatim with no
        // `+ ` diff prefixes.
        assert!(msg.contains("ALPHA\nBETA\nGAMMA"), "full contents: {msg}");
        assert!(
            !msg.contains("+ ALPHA"),
            "should not be a noisy diff: {msg}"
        );
        assert!(
            !msg.contains("- alpha"),
            "should not be a noisy diff: {msg}"
        );
    }

    #[test]
    fn deleted_file_injects_nothing_and_does_not_error() {
        let (s, tmp, path) = guidance_session("RULES\n");
        s.snapshot_guidance_baseline(tmp.path());
        std::fs::remove_file(&path).unwrap();
        // Out of scope: deletion is not an in-place change. No injection,
        // no error, and the baseline is left intact.
        assert!(s.guidance_change_injection(tmp.path()).is_none());
        assert!(s.db.guidance_baseline(s.id).unwrap().is_some());
    }

    #[test]
    fn switched_file_injects_nothing() {
        // Start with AGENTS.md as the resolved file.
        let (s, tmp, agents) = guidance_session("AGENTS RULES\n");
        s.snapshot_guidance_baseline(tmp.path());
        // Delete AGENTS.md and add a project guidance — a *different* file now
        // wins. Out of scope: the baseline path no longer matches, so no
        // injection even though guidance content "changed".
        std::fs::remove_file(&agents).unwrap();
        std::fs::write(tmp.path().join("project guidance"), "CLAUDE RULES\n").unwrap();
        assert!(s.guidance_change_injection(tmp.path()).is_none());
    }

    #[test]
    fn snapshot_is_recomputed_to_current_file_on_each_call() {
        // Mirrors a worker respawn (resume): re-snapshotting picks up the
        // current file as the new baseline, so a post-snapshot edit diffs
        // from the latest body.
        let (s, tmp, path) = guidance_session("v1\n");
        s.snapshot_guidance_baseline(tmp.path());
        std::fs::write(&path, "v2\n").unwrap();
        s.snapshot_guidance_baseline(tmp.path());
        // Baseline is now v2 → editing to v2 again is a no-op.
        assert!(s.guidance_change_injection(tmp.path()).is_none());
        // Editing to v3 injects, diffed from v2.
        std::fs::write(&path, "v3\n").unwrap();
        assert!(s.guidance_change_injection(tmp.path()).is_some());
    }
}
