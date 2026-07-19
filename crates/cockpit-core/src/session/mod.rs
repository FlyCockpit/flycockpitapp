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

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;
use crate::db::sessions::SessionRow;
use crate::db::tool_calls::Recovery;
use crate::db::tool_calls::ToolCallEvent;
use crate::model_system_prompt::ModelSystemPromptSnapshot;

mod gitignore;
mod lifecycle;
mod recording;
pub use recording::{ModelSwitchAudit, ModelSwitchOutcome, ModelSwitchTrigger};
mod title;
mod toggles;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEventLineage {
    pub task_call_id: String,
    pub label: String,
}

pub struct SessionCompactionRecord<'a> {
    pub successor_session_id: Uuid,
    pub successor_short_id: &'a str,
    pub seed_tool_count: usize,
    pub brief_text: &'a str,
    pub handoff_text: &'a str,
    pub source: &'a str,
    pub trigger_ctx_pct: Option<f64>,
    pub tokens_before: u64,
    pub tokens_after: u64,
    pub turns_summarized: usize,
    pub tail_kept: usize,
    pub tail_trimmed: usize,
    pub tail_messages: &'a [crate::engine::message::Message],
}

tokio::task_local! {
    static SESSION_EVENT_LINEAGE: Option<SessionEventLineage>;
}

pub async fn with_session_event_lineage<F>(
    lineage: Option<SessionEventLineage>,
    future: F,
) -> F::Output
where
    F: Future,
{
    SESSION_EVENT_LINEAGE.scope(lineage, future).await
}

fn current_session_event_lineage() -> Option<SessionEventLineage> {
    SESSION_EVENT_LINEAGE.try_with(Clone::clone).ok().flatten()
}

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
    pub assistant_name: Option<String>,
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
    /// Whether the session may offer explicit sandbox escalation retries.
    /// Seeded from config at spawn/resume and flipped live by
    /// `/sandbox-escalate` or the settings dialog. Approval mode still gates
    /// any allowed escalation.
    sandbox_escalation_enabled: AtomicBool,
    sandbox_escalation_notice_state: AtomicBool,
    mcp_reserved_cockpit_notice_sent: AtomicBool,
    agent_compact_requested: AtomicBool,
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
    /// Exact tool names on the current foreground agent's live toolbox. The
    /// daemon's skill inventory reads this snapshot so conditional Hermes
    /// activation matches execution, including config tools and grants.
    active_tool_names: Mutex<std::collections::HashSet<String>>,
    active_sandbox_escalate_eligible: AtomicBool,
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
    /// Parent session when this is a persistent `/btw` fork. Loaded from the
    /// DB row; clients cannot assert this in a tool request.
    pub btw_parent_session_id: Option<Uuid>,
    #[allow(dead_code)]
    pub btw_tangent: bool,
    title: Mutex<Option<String>>,
    user_renamed: Mutex<bool>,
    model: Mutex<Option<String>>,
    provider: Mutex<Option<String>>,
    redaction_table_json: Mutex<Option<String>>,
    model_system_prompt_snapshot: Arc<ModelSystemPromptSnapshot>,
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
    /// In-memory marker for the title-nudge slot just consumed by
    /// [`Self::note_user_content`]. This is deliberately not durable: a
    /// resumed session has already passed any previous slot and must not
    /// re-nudge it.
    title_nudge_slot_pending: AtomicU8,
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
    pub fn set_active_tool_names<'a>(
        &self,
        names: impl IntoIterator<Item = &'a str>,
        sandbox_escalate_eligible: bool,
    ) {
        *self.active_tool_names.lock().unwrap() = names.into_iter().map(str::to_string).collect();
        self.active_sandbox_escalate_eligible
            .store(sandbox_escalate_eligible, Ordering::Relaxed);
    }

    pub fn active_tool_names(&self) -> Vec<String> {
        self.active_tool_names
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect()
    }

    pub fn model_system_prompt_snapshot(&self) -> Arc<ModelSystemPromptSnapshot> {
        self.model_system_prompt_snapshot.clone()
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

    pub fn should_note_calibration_sample(&self, usage: crate::tokens::TokenUsage) -> bool {
        if usage.is_empty() || usage.cached_input_tokens != 0 {
            return false;
        }
        let (Some(provider), Some(model)) = (self.active_provider(), self.active_model()) else {
            return false;
        };
        !self
            .db
            .tokenizer_calibration_fresh(&provider, &model, Utc::now().timestamp())
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
    pub parent_call_id: Option<String>,
    pub parent_child_index: Option<i64>,
    pub identity: ToolCallProviderIdentity,
    pub tool: String,
    pub mcp_server: Option<String>,
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
    pub exit_code: Option<i32>,
    pub sandbox_enabled: bool,
    pub sandboxed: bool,
    pub sandbox_unavailable_reason: Option<String>,
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
    pub fn synthetic_cockpit_call(
        cockpit_call_id: &str,
        wire_api: Option<crate::config::providers::WireApi>,
    ) -> Self {
        Self {
            provider_item_id: Some(cockpit_call_id.to_string()),
            provider_call_id: Some(cockpit_call_id.to_string()),
            provider_call_id_source: Some("synthetic_from_cockpit_call_id".to_string()),
            wire_api: wire_api.and_then(wire_api_label).map(str::to_string),
            provider_family: Some("cockpit".to_string()),
        }
    }

    pub fn from_provider_call(
        provider: Option<&str>,
        model: Option<&str>,
        providers: Option<&crate::config::providers::ProvidersConfig>,
        resolved_wire_api: Option<crate::config::providers::WireApi>,
        provider_item_id: String,
        provider_call_id: Option<String>,
    ) -> Self {
        let wire_api = resolved_wire_api.or_else(|| {
            // Fallback only: normal recording passes the concrete endpoint from
            // the resolved model/config. If that is unavailable, keep the old
            // conservative provider-aware detector rather than fabricating a
            // Responses label.
            Some(crate::config::providers::WireApi::detect_for_provider(
                provider?, model?,
            ))
        });
        let is_responses = matches!(wire_api, Some(crate::config::providers::WireApi::Responses));
        let is_completions = matches!(
            wire_api,
            Some(crate::config::providers::WireApi::Completions)
        );
        let (provider_call_id, provider_call_id_source) = match provider_call_id {
            Some(call_id) => (Some(call_id), Some("provider".to_string())),
            None if is_responses => (
                Some(provider_item_id.clone()),
                Some("normalized_from_assistant_id".to_string()),
            ),
            None if is_completions => (
                Some(provider_item_id.clone()),
                Some("completions_tool_call_id".to_string()),
            ),
            None => (None, None),
        };
        Self {
            provider_item_id: Some(provider_item_id),
            provider_call_id,
            provider_call_id_source,
            wire_api: wire_api.and_then(wire_api_label).map(str::to_string),
            provider_family: Some(provider_family_from_config(provider, providers)),
        }
    }
}

fn wire_api_label(wire_api: crate::config::providers::WireApi) -> Option<&'static str> {
    match wire_api {
        crate::config::providers::WireApi::Responses => Some("responses"),
        crate::config::providers::WireApi::Completions => Some("completions"),
        // `Auto` is a configuration directive, not an observed wire endpoint.
        // Preserve that uncertainty as SQL/JSON null instead of inventing a
        // string label.
        crate::config::providers::WireApi::Auto => None,
    }
}

fn provider_family_from_config(
    provider: Option<&str>,
    providers: Option<&crate::config::providers::ProvidersConfig>,
) -> String {
    let Some(provider_id) = provider else {
        return "unset".to_string();
    };
    let Some(entry) = providers.and_then(|cfg| cfg.providers.get(provider_id)) else {
        return "unknown".to_string();
    };
    let family = match entry.effective_template(provider_id) {
        Some(template) => provider_family_for_template(template),
        None => provider_id,
    };
    family.to_string()
}

fn provider_family_for_template(template: &str) -> &str {
    match template {
        "openai" => "openai",
        "codex-oauth" => "codex",
        "grok" | "grok-oauth" => "xai",
        "anthropic" => "anthropic",
        other => other,
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
    use crate::config::providers::{ProviderEntry, ProvidersConfig, WireApi};
    use serde_json::json;

    fn providers_config(
        entries: impl IntoIterator<Item = (&'static str, ProviderEntry)>,
    ) -> ProvidersConfig {
        ProvidersConfig {
            providers: entries
                .into_iter()
                .map(|(id, entry)| (id.to_string(), entry))
                .collect(),
            ..ProvidersConfig::default()
        }
    }

    fn provider_entry(template: Option<&str>, wire_api: WireApi) -> ProviderEntry {
        ProviderEntry {
            template: template.map(str::to_string),
            url: "https://example.test/v1".to_string(),
            wire_api,
            ..ProviderEntry::default()
        }
    }

    fn identity_for(
        provider: Option<&str>,
        model: Option<&str>,
        providers: Option<&ProvidersConfig>,
        wire_api: Option<WireApi>,
        provider_call_id: Option<&str>,
    ) -> ToolCallProviderIdentity {
        ToolCallProviderIdentity::from_provider_call(
            provider,
            model,
            providers,
            wire_api,
            "provider-item".to_string(),
            provider_call_id.map(str::to_string),
        )
    }

    #[test]
    fn provider_family_resolves_for_non_builtin_provider() {
        let providers = providers_config([(
            "openrouter",
            provider_entry(Some("openrouter"), WireApi::Completions),
        )]);

        let identity = identity_for(
            Some("openrouter"),
            Some("claude-sonnet"),
            Some(&providers),
            Some(providers.resolve_wire_api("openrouter", "claude-sonnet")),
            None,
        );

        assert_eq!(identity.provider_family.as_deref(), Some("openrouter"));
        assert_ne!(identity.provider_family.as_deref(), Some("unknown"));
    }

    #[test]
    fn provider_family_resolves_for_custom_named_provider() {
        let providers =
            providers_config([("my-llama-box", provider_entry(None, WireApi::Completions))]);

        let identity = identity_for(
            Some("my-llama-box"),
            Some("llama-local"),
            Some(&providers),
            Some(providers.resolve_wire_api("my-llama-box", "llama-local")),
            None,
        );

        assert_eq!(identity.provider_family.as_deref(), Some("my-llama-box"));
        assert_ne!(identity.provider_family.as_deref(), Some("unknown"));
    }

    #[test]
    fn builtin_provider_families_are_unchanged() {
        let providers = providers_config([
            ("openai", provider_entry(Some("openai"), WireApi::Responses)),
            (
                "codex-oauth",
                provider_entry(Some("codex-oauth"), WireApi::Responses),
            ),
            ("grok", provider_entry(Some("grok"), WireApi::Responses)),
            (
                "grok-oauth",
                provider_entry(Some("grok-oauth"), WireApi::Responses),
            ),
            (
                "anthropic",
                provider_entry(Some("anthropic"), WireApi::Completions),
            ),
        ]);

        for (provider, family) in [
            ("openai", "openai"),
            ("codex-oauth", "codex"),
            ("grok", "xai"),
            ("grok-oauth", "xai"),
            ("anthropic", "anthropic"),
        ] {
            let identity = identity_for(
                Some(provider),
                Some("model"),
                Some(&providers),
                Some(providers.resolve_wire_api(provider, "model")),
                None,
            );
            assert_eq!(identity.provider_family.as_deref(), Some(family));
        }
    }

    #[test]
    fn unset_provider_is_distinct_from_unknown_provider() {
        let providers = ProvidersConfig::default();
        let unset = identity_for(None, Some("model"), Some(&providers), None, None);
        let unknown = identity_for(
            Some("missing-provider"),
            Some("model"),
            Some(&providers),
            None,
            None,
        );

        assert_eq!(unset.provider_family.as_deref(), Some("unset"));
        assert_eq!(unknown.provider_family.as_deref(), Some("unknown"));
    }

    #[test]
    fn completions_wire_mirrors_item_id_into_call_id() {
        let identity = identity_for(
            Some("openrouter"),
            Some("model"),
            None,
            Some(WireApi::Completions),
            None,
        );

        assert_eq!(identity.provider_item_id.as_deref(), Some("provider-item"));
        assert_eq!(identity.provider_call_id.as_deref(), Some("provider-item"));
        assert_eq!(
            identity.provider_call_id_source.as_deref(),
            Some("completions_tool_call_id")
        );
        assert_eq!(identity.wire_api.as_deref(), Some("completions"));
    }

    #[test]
    fn mirrored_call_id_never_claims_provider_source() {
        let identity = identity_for(
            Some("openrouter"),
            Some("model"),
            None,
            Some(WireApi::Completions),
            None,
        );

        assert_eq!(identity.provider_call_id, identity.provider_item_id);
        assert_ne!(
            identity.provider_call_id_source.as_deref(),
            Some("provider")
        );
    }

    #[test]
    fn responses_wire_call_id_sources_are_unchanged() {
        let supplied = identity_for(
            Some("codex-oauth"),
            Some("gpt-5"),
            None,
            Some(WireApi::Responses),
            Some("provider-call"),
        );
        assert_eq!(supplied.provider_call_id.as_deref(), Some("provider-call"));
        assert_eq!(
            supplied.provider_call_id_source.as_deref(),
            Some("provider")
        );

        let normalized = identity_for(
            Some("codex-oauth"),
            Some("gpt-5"),
            None,
            Some(WireApi::Responses),
            None,
        );
        assert_eq!(
            normalized.provider_call_id.as_deref(),
            Some("provider-item")
        );
        assert_eq!(
            normalized.provider_call_id_source.as_deref(),
            Some("normalized_from_assistant_id")
        );
    }

    #[test]
    fn wire_api_honors_explicit_config_override() {
        // `gpt-5-override` under the OpenAI provider would be detected as
        // Responses by the legacy id heuristic; the explicit provider config
        // must win.
        let providers = providers_config([(
            "openai",
            provider_entry(Some("openai"), WireApi::Completions),
        )]);

        let identity = identity_for(
            Some("openai"),
            Some("gpt-5-override"),
            Some(&providers),
            Some(providers.resolve_wire_api("openai", "gpt-5-override")),
            None,
        );

        assert_eq!(identity.wire_api.as_deref(), Some("completions"));
        assert_eq!(
            identity.provider_call_id_source.as_deref(),
            Some("completions_tool_call_id")
        );
    }

    #[test]
    fn wire_api_auto_is_reachable_and_recorded() {
        let identity = identity_for(
            Some("openai"),
            Some("gpt-5-auto"),
            None,
            Some(WireApi::Auto),
            None,
        );

        assert_eq!(identity.wire_api, None);
        assert_eq!(identity.provider_call_id, None);
        assert_eq!(identity.provider_call_id_source, None);
    }

    #[test]
    fn synthetic_call_in_completions_session_is_not_labeled_responses() {
        let identity =
            ToolCallProviderIdentity::synthetic_cockpit_call("seed-1", Some(WireApi::Completions));

        assert_eq!(identity.wire_api.as_deref(), Some("completions"));
        assert_ne!(identity.wire_api.as_deref(), Some("responses"));
        assert_eq!(identity.provider_family.as_deref(), Some("cockpit"));
        assert_eq!(
            identity.provider_call_id_source.as_deref(),
            Some("synthetic_from_cockpit_call_id")
        );
    }

    #[test]
    fn synthetic_call_with_unresolved_wire_records_none() {
        let identity = ToolCallProviderIdentity::synthetic_cockpit_call("seed-1", None);

        assert_eq!(identity.wire_api, None);
        assert_eq!(identity.provider_family.as_deref(), Some("cockpit"));
        assert_eq!(
            identity.provider_call_id_source.as_deref(),
            Some("synthetic_from_cockpit_call_id")
        );
    }

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
    fn nudge_fires_at_slot_8_and_16_only_when_untitled() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        let observed: Vec<_> = (1..=17)
            .filter_map(|turn| {
                let _ = s.note_user_content(&format!("turn {turn}"));
                s.unnamed_session_title_nudge(true, true)
                    .map(|nudge| (turn, nudge))
            })
            .collect();

        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].0, 8);
        assert!(observed[0].1.contains("after 8 user turns"));
        assert_eq!(observed[1].0, 16);
        assert!(observed[1].1.contains("after 16 user turns"));
    }

    #[test]
    fn nudge_does_not_fire_once_titled() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db, PathBuf::from("/x"), "a").unwrap();
        let observed: Vec<_> = (1..=17)
            .filter_map(|turn| {
                let _ = s.note_user_content(&format!("turn {turn}"));
                if turn == 3 {
                    assert!(s.set_auto_title("robot-title").unwrap());
                }
                s.unnamed_session_title_nudge(true, true)
                    .map(|nudge| (turn, nudge))
            })
            .collect();

        assert!(observed.is_empty(), "{observed:?}");
    }

    #[test]
    fn resumed_session_does_not_renudge_a_passed_slot() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create(db.clone(), PathBuf::from("/x"), "a").unwrap();
        let id = s.id;
        for turn in 1..=8 {
            s.record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("a"),
                None,
                &json!({"text": format!("turn {turn}")}),
            )
            .unwrap();
            let _ = s.note_user_content(&format!("turn {turn}"));
        }
        assert_eq!(s.title_stage(), 8);
        drop(s);

        let resumed = Session::resume(db, id).unwrap().unwrap();
        assert_eq!(resumed.user_content_turns(), 8);
        assert_eq!(resumed.title_stage(), 8);
        assert!(
            resumed.unnamed_session_title_nudge(true, true).is_none(),
            "resuming past slot 8 must not re-arm the in-memory nudge"
        );
        for turn in 9..=15 {
            let _ = resumed.note_user_content(&format!("turn {turn}"));
            assert!(resumed.unnamed_session_title_nudge(true, true).is_none());
        }
        let _ = resumed.note_user_content("turn 16");
        assert!(
            resumed
                .unnamed_session_title_nudge(true, true)
                .unwrap()
                .contains("after 16 user turns")
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
            parent_call_id: None,
            parent_child_index: None,
            identity: ToolCallProviderIdentity::default(),
            tool: "read".into(),
            path: Some("src/main.rs".into()),
            mcp_server: None,
            original_input_json: json!({"path":"src/main.rs"}),
            wire_input_json: json!({"path":"src/main.rs"}),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
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
        let providers = providers_config([(
            "codex-oauth",
            provider_entry(Some("codex-oauth"), WireApi::Responses),
        )]);
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            agent: "builder".into(),
            call_id: "cockpit-internal".into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: ToolCallProviderIdentity::from_provider_call(
                Some("codex-oauth"),
                Some("gpt-5.5"),
                Some(&providers),
                Some(WireApi::Responses),
                "provider-item".into(),
                Some("provider-call".into()),
            ),
            tool: "read".into(),
            path: None,
            mcp_server: None,
            original_input_json: json!({"path":"src/main.rs"}),
            wire_input_json: json!({"path":"src/main.rs"}),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
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
