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

#![allow(deprecated)]

use std::collections::VecDeque;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;
use crate::db::sessions::SessionRow;
use crate::db::tool_calls::Recovery;
use crate::db::tool_calls::ToolCallEvent;
use crate::knowledge::KnowledgeBasePromptSnapshot;
use crate::model_system_prompt::ModelSystemPromptSnapshot;

pub mod export;
mod gitignore;
pub mod import;
pub(crate) mod lifecycle;
mod recording;
pub mod sealed_values;
#[cfg(any(test, feature = "test-support"))]
mod test_constructors;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use test_constructors::TestSessionRowOptions;
/// The trusted-child sealed-value capture authority + pending-record registry
/// (leak-report AC7/AC8, sub-increment 2c-2). Exercised end-to-end by its own
/// unit tests; the production coordinator that mints and drives it lands in the
/// follow-up sub-increment (2c-3), so its host-side entry points are
/// `dead_code`-allowed until then, mirroring the not-yet-wired owner-only
/// [`Session::set_sealed_value`] surface in `sealed_values`.
#[allow(dead_code)]
pub(crate) mod trusted_child_capture;
/// Crate-wide re-export of the mid-transaction audit-write fault seam so tests
/// outside the `session` module (e.g. the driver dual-failure test) can arm it.
#[cfg(test)]
pub(crate) use recording::journal_fault;
pub(crate) use recording::notice_severity;
pub use recording::{
    ModelSwitchAudit, ModelSwitchOutcome, ModelSwitchTrigger, SessionEventModelFrame,
};
mod title;
mod toggles;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEventLineage {
    pub task_call_id: String,
    pub label: String,
}

/// Test-only observation of the root that completed worker boot. It exists to
/// verify construction across the worker's snapshot/rebuild boundary without
/// making the driver's live root frame externally observable in production.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct BootedRootProfile {
    pub agent_name: String,
    pub provider_id: String,
    pub model_id: String,
    pub tool_names: Vec<String>,
    pub native_computer: Option<crate::computer::NativeComputerToolConfig>,
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

/// Retained KB source bytes addressed by opaque, session-local read paths.
/// They intentionally stay in memory: a resumed daemon cannot honestly claim
/// it can still serve a prior process's retained source snapshot.
#[derive(Default)]
pub(crate) struct KnowledgeReadSnapshotStore {
    entries: std::collections::HashMap<Uuid, KnowledgeReadSnapshot>,
    /// Least-recently-used at the front. Snapshot citations are a bounded
    /// convenience cache, not durable session state: retaining a newer source
    /// must never make later searches unavailable for the life of a session.
    recency: VecDeque<Uuid>,
    total_bytes: usize,
}

#[derive(Clone)]
pub(crate) struct KnowledgeReadSnapshot {
    pub contents: String,
    pub trust_required: bool,
}

const MAX_KNOWLEDGE_READ_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

impl KnowledgeReadSnapshotStore {
    fn mark_knowledge_read_snapshot_recent(&mut self, id: Uuid) {
        if let Some(position) = self.recency.iter().position(|candidate| *candidate == id) {
            self.recency.remove(position);
        }
        self.recency.push_back(id);
    }

    fn retain(&mut self, contents: String, trust_required: bool, capacity: usize) -> Result<Uuid> {
        if let Some(id) = self
            .entries
            .iter()
            .find(|(_, snapshot)| {
                snapshot.contents == contents && snapshot.trust_required == trust_required
            })
            .map(|(id, _)| *id)
        {
            self.mark_knowledge_read_snapshot_recent(id);
            return Ok(id);
        }
        anyhow::ensure!(
            contents.len() <= capacity,
            "knowledge search source is larger than the per-session {} MiB cited-read cache",
            capacity / (1024 * 1024)
        );
        while self.total_bytes > capacity - contents.len() {
            let evicted_id = self.recency.pop_front().ok_or_else(|| {
                anyhow::anyhow!(
                    "knowledge read snapshot cache lost its eviction order while retaining a source"
                )
            })?;
            let evicted = self.entries.remove(&evicted_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "knowledge read snapshot cache eviction order references a missing source"
                )
            })?;
            self.total_bytes = self
                .total_bytes
                .checked_sub(evicted.contents.len())
                .context("knowledge read snapshot byte count underflow during eviction")?;
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(contents.len())
            .context("knowledge read snapshot byte count overflow")?;
        let id = Uuid::new_v4();
        self.entries.insert(
            id,
            KnowledgeReadSnapshot {
                contents,
                trust_required,
            },
        );
        self.recency.push_back(id);
        Ok(id)
    }

    fn get(&mut self, id: Uuid) -> Option<KnowledgeReadSnapshot> {
        let snapshot = self.entries.get(&id).cloned();
        if snapshot.is_some() {
            self.mark_knowledge_read_snapshot_recent(id);
        }
        snapshot
    }
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

/// Work due for the cache-reusing, same-model metadata fork. The title slots
/// refine both fields; later slots refresh the richer description while still
/// requiring the atomic combined metadata call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataAction {
    None,
    TitleAndDescribe,
    Describe,
}

/// A scheduled self-metadata pass, fenced to the exact user-content
/// generation that made it eligible. The durable token total fences newer user
/// content, while the durable metadata-fork generation fences cancellation,
/// drain, and superseding fork ownership before a generated write can publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataWork {
    pub action: MetadataAction,
    pub expected_user_content_tokens: usize,
    /// Assigned at the foreground dispatch seam. It is included in the
    /// generated write's durable CAS predicate.
    pub expected_metadata_fork_generation: i64,
}

/// Process-wide audit counter: how many times any session waived the
/// durable-before-handoff inference journal barrier. Read by doctor / audit
/// surfaces; never reset in production. `nextest` runs each test in its own
/// process, so tests observe only their own increments.
static UNJOURNALED_INFERENCE_OPTOUTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Total number of audited unjournaled-inference opt-outs taken this process.
pub fn unjournaled_inference_optout_count() -> u64 {
    UNJOURNALED_INFERENCE_OPTOUTS.load(std::sync::atomic::Ordering::Relaxed)
}

/// The exhaustive, audited set of reasons a session may waive the
/// durable-before-provider-handoff inference journal barrier.
///
/// Waiving the barrier is never a silent boolean: a caller must name one of
/// these justifications, every one of which corresponds to a session that
/// provably cannot attach the daemon-owned recovery journal. Ordinary
/// daemon/session-worker sessions never opt out and so keep the barrier as a
/// hard invariant. Adding a variant is adding an audited escape hatch — do so
/// only with an equally narrow, justified caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnjournaledInferenceReason {
    /// The read-only `cockpit ask` docs pipeline (daemon `DocsAsk` handler):
    /// a standalone, directly-run docs session created outside the session
    /// worker, so it has no attached daemon-owned recovery journal and its
    /// inference stays on the primary-row audit path.
    DocsAsk,
    /// The caged background self-improvement / skills review utility
    /// (`assistants/self_improvement.rs`): intentionally retains an isolated
    /// in-memory database, to which a daemon journal (bound to a different DB)
    /// cannot be attached.
    CagedSelfReviewUtility,
}

impl UnjournaledInferenceReason {
    /// Stable, free-text-free label for logs, doctor, and audit surfaces.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DocsAsk => "docs_ask",
            Self::CagedSelfReviewUtility => "caged_self_review_utility",
        }
    }
}

const MAX_SEED_READ_RECEIPTS: usize = 64;
const SEED_READ_RECEIPT_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

struct SeedReadReceiptEntry {
    seed_reads: Vec<crate::engine::seed_reads::SeedRead>,
    issued_at: std::time::Instant,
    state: SeedReadReceiptState,
}

enum SeedReadReceiptState {
    Available,
    Claimed,
}

fn retire_stale_seed_read_receipts(
    receipts: &mut std::collections::HashMap<Uuid, SeedReadReceiptEntry>,
) {
    receipts.retain(|_, entry| {
        matches!(entry.state, SeedReadReceiptState::Claimed)
            || entry.issued_at.elapsed() < SEED_READ_RECEIPT_TTL
    });
}

pub(crate) struct SeedReadReceiptClaim {
    session: Arc<Session>,
    id: Uuid,
    committed: bool,
}

impl SeedReadReceiptClaim {
    pub(crate) fn commit(mut self) {
        self.session
            .seed_read_receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
        self.committed = true;
    }
}

impl Drop for SeedReadReceiptClaim {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut receipts = self
            .session
            .seed_read_receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = receipts.get_mut(&self.id)
            && matches!(entry.state, SeedReadReceiptState::Claimed)
        {
            entry.state = SeedReadReceiptState::Available;
        }
        retire_stale_seed_read_receipts(&mut receipts);
    }
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
    /// Construction provenance for startup-only migrations. This is true only
    /// for a brand-new root created by this process; resume and fork paths are
    /// false even when their durable row is still idle.
    freshly_created: bool,
    pub db: Db,
    /// Ephemeral attachment consent for an in-progress knowledge dream.  This
    /// belongs to the session rather than an individual tool dispatch because
    /// the orchestrator and its delegated readers reconstruct their `ToolCtx`
    /// independently between model turns.
    dream_read_scope: Arc<std::sync::RwLock<Option<std::collections::BTreeSet<Uuid>>>>,
    /// The per-KB dream execution fence acquired by `knowledge_dream_sources`.
    /// It remains session-owned while the orchestrator reads and reasons, then
    /// moves into the detached apply owner so a dispatcher timeout cannot
    /// release it before the completion ledger is settled.
    dream_run_fence: Arc<Mutex<DreamRunFenceState>>,
    /// Daemon-injected wrap-key vault. Session fork, sealed persist, and
    /// redaction-table load use this handle instead of opening a second vault.
    secret_vault: Arc<crate::secure_key::SecretVault>,
    /// Daemon-owned external side-effect journal. Installed by the registry
    /// before the worker starts; absent in isolated unit sessions.
    external_journal: Mutex<Option<Arc<crate::external_journal::ExternalJournal>>>,
    /// Memory-only ACP-forwarded MCP publication slot. It is reachable only
    /// through the session carried by `ToolCtx`, so every descendant observes
    /// the same root-scoped epoch and no declaration enters durable session
    /// state.
    forwarded_mcp_catalog: Arc<crate::mcp::forwarded::ForwardedCatalogSlot>,
    /// One-use host receipts for explore-selected seed reads.  The receipt is
    /// deliberately memory-only: a resumed process fails closed and requires
    /// a fresh explore selection rather than accepting model-synthesized seed
    /// calls after losing the host provenance boundary.
    seed_read_receipts: Mutex<std::collections::HashMap<Uuid, SeedReadReceiptEntry>>,
    /// Turn-pinned transcription egress composed from the same resolved
    /// provider credential, endpoint, capability metadata, and journal.
    transcription_dispatch: Mutex<
        std::collections::HashMap<
            (String, String, u64),
            Arc<crate::audio_transcription::journal::TranscriptionDispatchService>,
        >,
    >,
    /// Daemon-owned durable media reader plus reservation ledger. Installed by
    /// the registry before a worker starts so accepted V2 queue rows and typed
    /// tool results can reacquire normalized bytes after restart.
    message_media_authority: Mutex<
        Option<(
            Arc<crate::media_storage::MediaStorageRecovery>,
            crate::media_reservation::MediaReservationLedger,
        )>,
    >,
    #[cfg(test)]
    test_media_reservation_ledger: Mutex<Option<crate::media_reservation::MediaReservationLedger>>,
    /// Daemon-installed factory for live tool-media subjects. It is absent in
    /// isolated/headless sessions; those paths never inherit media authority.
    tool_media_runtime: Mutex<Option<Arc<crate::tool_media_authority::runtime::ToolMediaRuntime>>>,
    /// Authority materialized for the currently executing interactive user
    /// root fold. Cleared at the turn boundary so later roots, background
    /// work, MCP/Monty, and untrusted children cannot inherit it.
    tool_media_authority: Mutex<Option<Arc<crate::tool_media_authority::SessionMediaAuthority>>>,
    /// Daemon-worker directory for models selected by immutable agent-profile
    /// bindings. Utilities resolve an exact profile snapshot and slot instead
    /// of borrowing the foreground model.
    profile_utility_model_resolver: Mutex<Option<Arc<ProfileUtilityModelResolver>>>,
    /// Daemon-process command-backed secret cache. Late-installed by the
    /// registry / daemon before the worker (or DocsAsk session) builds any
    /// store, so every `credential_store` / `provider_credential_store` this
    /// session builds injects the resolved command outputs the cache holds
    /// (a sync, execution-free lookup). Absent in isolated unit sessions, where
    /// command-backed secrets simply resolve as missing.
    command_secret_cache: Mutex<Option<Arc<crate::secret_command::CommandSecretCache>>>,
    /// Daemon-owned descendant process-containment handle. Late-installed by the
    /// registry / daemon before the worker starts (like [`Self::external_journal`]),
    /// so every lifecycle hook this session spawns runs its child under a proven
    /// containment lease. Absent in isolated unit sessions and non-daemon paths,
    /// where hook spawns fail open as `descendant_containment_unsupported`.
    process_containment: Mutex<Option<crate::process_containment::ProcessContainmentHandle>>,
    /// Required key resolver for protected redaction-history journaling.
    /// Installed at construction by the registry / daemon (production) or the
    /// shared test helper (tests) — never `Option`, never lazily set (decision
    /// 16). Read-only after construction. Consumed by the trusted
    /// inference-request / event journaling chokepoints in `recording.rs`.
    redaction_key_resolver:
        Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
    /// Durable-before-handoff inference journaling is a hard invariant. This
    /// flag is the ONLY sanctioned opt-out, set exclusively through the audited
    /// [`Session::allow_unjournaled_inference`] funnel (a reason is required and
    /// the global audit counter increments). It exists for the narrow set of
    /// daemon-less / isolated-DB sessions that provably cannot attach the
    /// daemon-owned journal (enumerated by [`UnjournaledInferenceReason`]).
    allow_unjournaled_inference: std::sync::atomic::AtomicBool,
    /// The audited justification for the opt-out above, retained for doctor /
    /// audit surfaces. `None` until (and unless) the opt-out is taken.
    unjournaled_inference_reason: Mutex<Option<UnjournaledInferenceReason>>,
    /// Private per-session tmp dir under the system temp location
    /// (sandboxing part 2). Read+write inside the sandboxed shell and
    /// counted as "inside the boundary" for native-tool path checks, so
    /// sessions can't read each other's tmp. Created lazily on first
    /// [`Self::tmp_dir`] access; removed on [`Self::end`] and on drop.
    /// `Mutex<Option<…>>` so creation is one-shot and `end()` can take it.
    tmp_dir: Mutex<Option<PathBuf>>,
    /// Durable per-workspace scratch, partitioned by session under the Cockpit
    /// state directory. Unlike [`Self::tmp_dir`], this directory deliberately
    /// survives session end and daemon restart.
    workspace_scratch_dir: PathBuf,
    /// Per-session host executable shims under the Cockpit data dir. These
    /// are separate from [`Self::tmp_dir`] so shell PATH shims live in a
    /// stable user-data location, but they share the same end/drop cleanup.
    host_shim_dir: Mutex<Option<PathBuf>>,
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
    safety_gate_degrade_notice_key: Mutex<Option<(String, Option<String>)>>,
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
    /// Invocation-scoped Manual/Auto/Yolo override installed while a
    /// durable run with `RunInvocationOptions.approval_mode` is active.
    /// `255` means no override (use session mode). Never written by
    /// [`Self::set_approval_mode`]; cleared when the owning run ends.
    invocation_approval_override: AtomicU8,
    /// Client submission id of the run that owns
    /// [`Self::invocation_approval_override`], when set.
    active_run_invocation_id: Mutex<Option<Uuid>>,
    /// Native shell-output compression for this session right now
    /// (implementation note). Resolved at spawn from
    /// [`crate::config::extended::ExtendedConfig::shell_compression`]
    /// ([`Self::set_shell_compression`]); read per `bash` call via
    /// [`Self::shell_compression_enabled`]. Default ON (compress) until the
    /// spawn path applies the config default. In-memory only — a resumed
    /// session re-resolves from config at re-attach.
    shell_compression_enabled: AtomicBool,
    /// Exact tool names on the current foreground agent's live toolbox. The
    /// daemon's skill inventory reads this snapshot so conditional Hermes
    /// activation matches execution, including config tools and grants.
    active_tool_names: Mutex<std::collections::HashSet<String>>,
    /// Final root construction evidence for worker integration tests. This is
    /// deliberately test-only: production authority remains exclusively on
    /// the driver's live root frame.
    #[cfg(test)]
    booted_root_profile: Mutex<Option<BootedRootProfile>>,
    /// Session-owned image-generation dispatch funnel installed by the daemon
    /// worker before agent turns begin. Isolated/test sessions leave it absent.
    image_generation_dispatch:
        Mutex<Option<Arc<crate::image_generation_job::ImageGenerationDispatchService>>>,
    active_sandbox_escalate_eligible: AtomicBool,
    /// 6-char human-display id, unique within `project_id`
    /// (GOALS §17b). Populated at create-time; backfilled lazily for
    /// pre-§17 rows on [`Session::resume`]. Insert collision retry can
    /// replace the in-memory value — read through [`Self::short_id`].
    short_id: Mutex<String>,
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
    description: Mutex<Option<String>>,
    user_renamed: Mutex<bool>,
    active_agent: Mutex<String>,
    /// Complete session selection, including invocation preferences that are
    /// not part of the provider/model identity.
    model_selection: Mutex<Option<crate::config::providers::ActiveModelRef>>,
    /// Immutable daemon-owned setup metadata. It is never consulted for
    /// agent/model/sandbox/approval authority.
    session_entry_mode: crate::daemon::proto::SessionEntryMode,
    tool_surface_override_json: Mutex<Option<String>>,
    goal_settings_override_json: Mutex<Option<String>>,
    redaction_table_json: Mutex<Option<String>>,
    secret_path_matcher: OnceLock<crate::secret_paths::SecretPathMatcher>,
    model_system_prompt_snapshot: Arc<ModelSystemPromptSnapshot>,
    /// KB identity/freshness facts bound to the active root definition and
    /// rendered into its cached system prefix. Frozen across turns and never
    /// rewritten after a dream completes; root replacement is the sole
    /// rebinding boundary.
    knowledge_base_prompt_snapshot: RwLock<Arc<KnowledgeBasePromptSnapshot>>,
    /// Kept separately from the snapshot value because an empty attachment
    /// set is a valid completed capture. A false value means worker startup
    /// was interrupted before the first root-definition-bound capture.
    knowledge_base_prompt_snapshot_captured: AtomicBool,
    /// Exact KB files returned by search, retained only for follow-up native
    /// `read` calls during this daemon lifetime.
    knowledge_read_snapshots: Mutex<KnowledgeReadSnapshotStore>,
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
    /// One metadata pass waiting for the foreground request that owns its
    /// cached prefix to complete.  It is consumed by that request's turn
    /// phase, never by a later user turn.
    pending_metadata_fork: Mutex<Option<MetadataWork>>,
    /// In-memory two-shot latch for compact self-nudges (`0`, `1`, `2`).
    /// Reset only by successful compaction; prunes deliberately do not re-arm
    /// it because ctx% can oscillate around the threshold.
    compact_self_nudge_stage: AtomicU8,
    /// Latches once a genuine auto-title failure has surfaced a user
    /// `Notice` (§17d / implementation note), so
    /// a broken/unset utility model is reported once per session rather
    /// than every turn. In-memory only — a resume re-arms it.
    title_failure_noticed: std::sync::atomic::AtomicBool,
    /// Latches once a tool call has been blocked because an argument
    /// contained the configured redaction placeholder. The durable notice
    /// is useful once per session; every blocked call still returns its
    /// model-visible invalid-input error.
    redaction_placeholder_noticed: std::sync::atomic::AtomicBool,
    /// Provider-reported usage from the most recent round-trip.
    /// Populated by [`Self::record_usage`] after each `model.complete`
    /// call. The TUI prefers this over the local tiktoken estimate
    /// when it's `Some(_)`.
    last_usage: Mutex<Option<crate::tokens::TokenUsage>>,
    /// The configured endpoint that reported the last real prompt-cache hit.
    /// This is deliberately separate from `last_usage`: context chrome may use
    /// a session-wide estimate, but keep-warm is authorized only by a hit from
    /// the endpoint it is about to refresh.
    last_cache_hit_endpoint: Mutex<Option<(String, String)>>,
    /// Monotonic instant and durable identity of the most recent inference
    /// send. The cache-cold predicate uses the monotonic instant, while the
    /// daemon-scheduled keep-warm callback carries the unique identity across
    /// its durable job boundary. In-memory only — a resumed session re-warms
    /// naturally.
    last_send_at: Mutex<Option<InferenceSendTime>>,
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
    /// A retried `read` of a remembered path gets the same refusal
    /// with no re-prompt (avoids prompt thrash). In-memory only — never
    /// persisted; there is no user-facing denylist.
    gitignore_session_reject: Mutex<std::collections::HashSet<String>>,
    /// Dedicated tools the model has SUCCESSFULLY used this session, for the
    /// defensive-mode bash-routing nudge's self-suppression
    /// (implementation note). Keyed by the
    /// tip-target tool name (`read`/`search`/`code`): once
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

impl Session {
    /// Bind an explore fork's host-captured calls to one subsequent
    /// `Build -> builder` handoff. The opaque receipt is not a capability on
    /// its own: redemption also compares the exact validated calls.
    pub(crate) fn issue_seed_read_receipt(
        &self,
        seed_reads: &[crate::engine::seed_reads::SeedRead],
    ) -> Option<String> {
        let receipt = Uuid::new_v4();
        let argument_bytes = seed_reads.iter().try_fold(0usize, |total, seed| {
            serde_json::to_vec(&seed.args)
                .ok()
                .and_then(|encoded| total.checked_add(encoded.len()))
        });
        if seed_reads.len() > crate::engine::seed_reads::MAX_SEED_READ_CALLS
            || argument_bytes
                .is_none_or(|bytes| bytes > crate::engine::seed_reads::MAX_SEED_READ_ARGUMENT_BYTES)
        {
            return None;
        }
        let mut receipts = self
            .seed_read_receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        retire_stale_seed_read_receipts(&mut receipts);
        while receipts.len() >= MAX_SEED_READ_RECEIPTS {
            let Some(oldest) = receipts
                .iter()
                .filter(|(_, entry)| matches!(entry.state, SeedReadReceiptState::Available))
                .min_by_key(|(_, entry)| entry.issued_at)
                .map(|(id, _)| *id)
            else {
                break;
            };
            receipts.remove(&oldest);
        }
        if receipts.len() >= MAX_SEED_READ_RECEIPTS {
            // Every retained entry is in the narrow admission claim window.
            // Fail closed without growing session memory. Callers omit the
            // selection rather than reporting calls with an unusable receipt.
            return None;
        }
        receipts.insert(
            receipt,
            SeedReadReceiptEntry {
                seed_reads: seed_reads.to_vec(),
                issued_at: std::time::Instant::now(),
                state: SeedReadReceiptState::Available,
            },
        );
        Some(receipt.to_string())
    }

    pub(crate) fn validate_seed_read_receipt(
        &self,
        receipt: &str,
        seed_reads: &[crate::engine::seed_reads::SeedRead],
    ) -> std::result::Result<(), String> {
        let receipt = Uuid::parse_str(receipt)
            .map_err(|_| "seed_reads receipt is not a host-issued UUID".to_string())?;
        let mut receipts = self
            .seed_read_receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        retire_stale_seed_read_receipts(&mut receipts);
        match receipts.get(&receipt) {
            Some(entry) if entry.seed_reads != seed_reads => {
                Err("seed_reads do not match their host-issued explore receipt".to_string())
            }
            Some(entry) if matches!(entry.state, SeedReadReceiptState::Available) => Ok(()),
            Some(_) => Err("seed_reads receipt is already being redeemed".to_string()),
            None => Err("seed_reads receipt is unknown, expired, or already used".to_string()),
        }
    }

    pub(crate) fn claim_seed_read_receipt(
        self: &Arc<Self>,
        receipt: Option<&str>,
        seed_reads: &[crate::engine::seed_reads::SeedRead],
    ) -> std::result::Result<Option<SeedReadReceiptClaim>, String> {
        if seed_reads.is_empty() {
            return Ok(None);
        }
        let raw = receipt
            .ok_or_else(|| "seed_reads require the host-issued explore receipt".to_string())?;
        let id = Uuid::parse_str(raw)
            .map_err(|_| "seed_reads receipt is not a host-issued UUID".to_string())?;
        let mut receipts = self
            .seed_read_receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        retire_stale_seed_read_receipts(&mut receipts);
        match receipts.get_mut(&id) {
            Some(entry) if entry.seed_reads != seed_reads => {
                Err("seed_reads do not match their host-issued explore receipt".to_string())
            }
            Some(entry) if matches!(entry.state, SeedReadReceiptState::Available) => {
                entry.state = SeedReadReceiptState::Claimed;
                Ok(Some(SeedReadReceiptClaim {
                    session: self.clone(),
                    id,
                    committed: false,
                }))
            }
            Some(_) => Err("seed_reads receipt is already being redeemed".to_string()),
            None => Err("seed_reads receipt is unknown, expired, or already used".to_string()),
        }
    }

    pub(crate) fn retain_knowledge_read_snapshot(
        &self,
        contents: String,
        trust_required: bool,
    ) -> Result<Uuid> {
        let mut snapshots = self
            .knowledge_read_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshots.retain(contents, trust_required, MAX_KNOWLEDGE_READ_SNAPSHOT_BYTES)
    }

    pub(crate) fn knowledge_read_snapshot(&self, id: Uuid) -> Option<KnowledgeReadSnapshot> {
        let mut snapshots = self
            .knowledge_read_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshots.get(id)
    }

    /// The session-owned knowledge-dream attachment-consent cell.
    pub(crate) fn dream_read_scope(
        &self,
    ) -> Arc<std::sync::RwLock<Option<std::collections::BTreeSet<Uuid>>>> {
        self.dream_read_scope.clone()
    }

    /// Starts a root turn with no inherited dream attachment consent. A
    /// daemon-installed run fence is promoted for this one internal Dream
    /// turn. The returned guard owns cleanup for every exit path,
    /// including a source lookup that returns empty, errors while redacting,
    /// times out, or never reaches `knowledge_dream_apply`.
    pub(crate) fn begin_dream_read_scope_turn(&self) -> DreamReadScopeTurn {
        let scope = self.dream_read_scope();
        *scope.write().expect("dream read scope lock poisoned") = None;
        let run_fence = self.dream_run_fence.clone();
        let mut current = run_fence
            .lock()
            .expect("knowledge dream run fence state poisoned");
        *current = match std::mem::replace(&mut *current, DreamRunFenceState::Vacant) {
            DreamRunFenceState::Pending(fence) => DreamRunFenceState::Held(fence),
            _ => DreamRunFenceState::Vacant,
        };
        drop(current);
        DreamReadScopeTurn(scope, run_fence)
    }

    /// Install the daemon-owned fence before its internal Dream turn enters
    /// the driver. A later normal root turn cannot inherit this pending state.
    pub(crate) fn install_dream_run_fence(&self, fence: DreamRunFence) -> Result<()> {
        let mut current = self
            .dream_run_fence
            .lock()
            .expect("knowledge dream run fence state poisoned");
        if !matches!(&*current, DreamRunFenceState::Vacant) {
            anyhow::bail!("knowledge dream execution fence was already installed for this session");
        }
        *current = DreamRunFenceState::Pending(fence);
        Ok(())
    }

    /// Undo a not-yet-started daemon Dream turn. Once the driver promotes the
    /// fence to `Held`, its root-turn guard or detached apply owner is solely
    /// responsible for release.
    pub(crate) fn clear_pending_dream_run_fence(&self) {
        let mut current = self
            .dream_run_fence
            .lock()
            .expect("knowledge dream run fence state poisoned");
        if matches!(&*current, DreamRunFenceState::Pending(_)) {
            *current = DreamRunFenceState::Vacant;
        }
    }

    /// Acquire the one per-root/per-KB boundary before selecting dream
    /// sources. The fence stays held through orchestrator model work and is
    /// transferred by [`Self::take_dream_run_fence`] to the apply owner.
    pub(crate) async fn acquire_dream_run_fence(
        &self,
        project_root: &crate::knowledge::dream::CanonicalDreamProjectRoot,
        knowledge_base_id: &str,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let key = DreamRunFenceKey::new(project_root, knowledge_base_id);
        let state = self.dream_run_fence.clone();
        {
            let mut current = state
                .lock()
                .expect("knowledge dream run fence state poisoned");
            match &*current {
                DreamRunFenceState::Vacant => {
                    *current = DreamRunFenceState::Acquiring(key.clone());
                }
                DreamRunFenceState::Pending(_) => {
                    anyhow::bail!(
                        "knowledge dream source selection started before the daemon-owned execution fence entered its root turn"
                    );
                }
                DreamRunFenceState::Acquiring(existing) => {
                    anyhow::bail!(
                        "knowledge dream source selection is already acquiring the per-KB execution fence for `{}`",
                        existing.knowledge_base_id
                    );
                }
                DreamRunFenceState::Held(existing) if existing.key == key => return Ok(()),
                DreamRunFenceState::Held(existing) => {
                    anyhow::bail!(
                        "knowledge dream turn already owns the per-KB execution fence for `{}`",
                        existing.key.knowledge_base_id
                    );
                }
            }
        }
        let mut acquisition = DreamRunFenceAcquisition::new(state.clone(), key.clone());
        let lock = crate::knowledge::dream::knowledge_dream_run_lock_for_root(
            project_root,
            knowledge_base_id,
        );
        let guard = tokio::select! {
            guard = lock.lock_owned() => guard,
            () = cancel.cancelled() => anyhow::bail!("knowledge dream cancelled while waiting for the KB execution fence"),
        };
        let mut current = state
            .lock()
            .expect("knowledge dream run fence state poisoned");
        if !matches!(&*current, DreamRunFenceState::Acquiring(existing) if *existing == key) {
            anyhow::bail!(
                "knowledge dream execution fence lifecycle ended before source selection"
            );
        }
        *current = DreamRunFenceState::Held(DreamRunFence::new(key, guard));
        acquisition.commit();
        Ok(())
    }

    /// Transfer the exact source-selection fence to the task that owns the
    /// sink transaction and completion ledger. Applying without that prior
    /// selection boundary fails closed.
    pub(crate) fn take_dream_run_fence(
        &self,
        project_root: &crate::knowledge::dream::CanonicalDreamProjectRoot,
        knowledge_base_id: &str,
    ) -> Result<DreamRunFence> {
        let key = DreamRunFenceKey::new(project_root, knowledge_base_id);
        let mut current = self
            .dream_run_fence
            .lock()
            .expect("knowledge dream run fence state poisoned");
        match std::mem::replace(&mut *current, DreamRunFenceState::Vacant) {
            DreamRunFenceState::Pending(fence) => {
                *current = DreamRunFenceState::Pending(fence);
                anyhow::bail!(
                    "knowledge dream apply started before its root turn accepted the execution fence"
                );
            }
            DreamRunFenceState::Held(fence) if fence.key == key => Ok(fence),
            DreamRunFenceState::Held(fence) => {
                let selected_knowledge_base_id = fence.key.knowledge_base_id.clone();
                *current = DreamRunFenceState::Held(fence);
                anyhow::bail!(
                    "knowledge dream apply targets `{knowledge_base_id}`, but source selection owns `{}`",
                    selected_knowledge_base_id
                );
            }
            DreamRunFenceState::Acquiring(fence) => {
                *current = DreamRunFenceState::Acquiring(fence);
                anyhow::bail!("knowledge dream apply requires completed source selection");
            }
            DreamRunFenceState::Vacant => {
                anyhow::bail!(
                    "knowledge dream apply requires a prior source-selection execution fence"
                );
            }
        }
    }

    pub(crate) fn is_freshly_created(&self) -> bool {
        self.freshly_created
    }
}

/// Root-turn ownership of ephemeral dream attachment consent. A scope is
/// deliberately never carried into the next reusable session turn.
pub(crate) struct DreamReadScopeTurn(
    Arc<std::sync::RwLock<Option<std::collections::BTreeSet<Uuid>>>>,
    Arc<Mutex<DreamRunFenceState>>,
);

impl Drop for DreamReadScopeTurn {
    fn drop(&mut self) {
        *self.0.write().expect("dream read scope lock poisoned") = None;
        *self
            .1
            .lock()
            .expect("knowledge dream run fence state poisoned") = DreamRunFenceState::Vacant;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DreamRunFenceKey {
    project_root: String,
    knowledge_base_id: String,
}

impl DreamRunFenceKey {
    fn new(
        project_root: &crate::knowledge::dream::CanonicalDreamProjectRoot,
        knowledge_base_id: &str,
    ) -> Self {
        Self {
            project_root: project_root.as_str().to_owned(),
            knowledge_base_id: knowledge_base_id.to_owned(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct DreamRunFence {
    key: DreamRunFenceKey,
    _guard: Arc<tokio::sync::OwnedMutexGuard<()>>,
}

impl DreamRunFence {
    pub(crate) async fn acquire(
        project_root: &crate::knowledge::dream::CanonicalDreamProjectRoot,
        knowledge_base_id: &str,
    ) -> Self {
        let key = DreamRunFenceKey::new(project_root, knowledge_base_id);
        let guard = crate::knowledge::dream::knowledge_dream_run_lock_for_root(
            project_root,
            knowledge_base_id,
        )
        .lock_owned()
        .await;
        Self::new(key, guard)
    }

    fn new(key: DreamRunFenceKey, guard: tokio::sync::OwnedMutexGuard<()>) -> Self {
        Self {
            key,
            _guard: Arc::new(guard),
        }
    }
}

enum DreamRunFenceState {
    Vacant,
    Pending(DreamRunFence),
    Acquiring(DreamRunFenceKey),
    Held(DreamRunFence),
}

struct DreamRunFenceAcquisition {
    state: Arc<Mutex<DreamRunFenceState>>,
    key: DreamRunFenceKey,
    committed: bool,
}

impl DreamRunFenceAcquisition {
    fn new(state: Arc<Mutex<DreamRunFenceState>>, key: DreamRunFenceKey) -> Self {
        Self {
            state,
            key,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for DreamRunFenceAcquisition {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut current = self
            .state
            .lock()
            .expect("knowledge dream run fence state poisoned");
        if matches!(&*current, DreamRunFenceState::Acquiring(existing) if *existing == self.key) {
            *current = DreamRunFenceState::Vacant;
        }
    }
}

pub(crate) type ProfileUtilityModelResolver =
    dyn Fn(Uuid, Uuid, &str) -> Option<Arc<crate::engine::model::Model>> + Send + Sync;

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

/// The durable identity for exactly one inference send. Wall-clock time
/// supplies the daemon-job timing; the paired Tokio monotonic origin supplies
/// the in-process scheduler deadline. `send_id` prevents two sends in one
/// millisecond from being treated as the same cache-producing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InferenceSendIdentity {
    pub unix_millis: i64,
    pub send_id: Uuid,
}

#[derive(Clone, Copy)]
struct InferenceSendTime {
    monotonic: std::time::Instant,
    scheduler_monotonic: tokio::time::Instant,
    identity: InferenceSendIdentity,
}

/// Shared test-only redaction key resolver for constructing `Session`s in unit
/// tests. Returns a real [`crate::redact::protected_redaction_history::RedactionKeyResolver`]
/// (a `MapKeyResolver` with a fixed version-1 key) — never `None`, per decision
/// 16. Importable across the crate's test modules so no test inlines a resolver.
#[cfg(test)]
pub(crate) fn test_redaction_key_resolver()
-> Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver> {
    Arc::new(
        crate::redact::protected_redaction_history::MapKeyResolver::new()
            .with_version(1, [7u8; 32]),
    )
}

impl Session {
    pub(crate) fn set_image_generation_dispatch(
        &self,
        service: Arc<crate::image_generation_job::ImageGenerationDispatchService>,
    ) {
        *crate::sync::lock_or_recover(&self.image_generation_dispatch) = Some(service);
    }

    pub(crate) fn image_generation_dispatch(
        &self,
    ) -> Option<Arc<crate::image_generation_job::ImageGenerationDispatchService>> {
        crate::sync::lock_or_recover(&self.image_generation_dispatch).clone()
    }

    /// Durable 6-char display id. Collision retry at persist can replace the
    /// value assigned at `create_deferred`.
    pub fn short_id(&self) -> String {
        self.short_id
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn set_external_journal(
        &self,
        journal: Option<Arc<crate::external_journal::ExternalJournal>>,
    ) {
        *self.external_journal.lock().unwrap() = journal;
    }

    pub(crate) fn external_journal(&self) -> Option<Arc<crate::external_journal::ExternalJournal>> {
        self.external_journal.lock().unwrap().clone()
    }

    pub(crate) fn forwarded_mcp_slot(&self) -> Arc<crate::mcp::forwarded::ForwardedCatalogSlot> {
        self.forwarded_mcp_catalog.clone()
    }

    pub(crate) fn forwarded_mcp_catalog(
        &self,
    ) -> Option<Arc<crate::mcp::forwarded::AcpForwardedMcpCatalogV1>> {
        self.forwarded_mcp_catalog.active()
    }

    pub(crate) fn transcription_dispatch(
        &self,
        provider_id: &str,
        model_id: &str,
        config_generation: u64,
    ) -> Option<Arc<crate::audio_transcription::journal::TranscriptionDispatchService>> {
        self.transcription_dispatch
            .lock()
            .unwrap()
            .get(&(
                provider_id.to_string(),
                model_id.to_string(),
                config_generation,
            ))
            .cloned()
    }

    pub(crate) async fn compose_transcription_dispatch(
        &self,
        config: &crate::daemon::session_worker::SessionConfigHandle,
        provider_id: &str,
        model_id: &str,
        env: &std::collections::HashMap<String, String>,
    ) -> Option<Arc<crate::audio_transcription::journal::TranscriptionDispatchService>> {
        let resolved = crate::audio_transcription::transport::resolve_vetted_egress(
            self,
            config,
            provider_id,
            model_id,
            env,
        )
        .await
        .and_then(|egress| {
            self.external_journal().map(|journal| {
                Arc::new(
                    crate::audio_transcription::journal::TranscriptionDispatchService::from_http_transport(
                        journal, egress,
                    ),
                )
            })
        });
        let key = (
            provider_id.to_string(),
            model_id.to_string(),
            config.generation(),
        );
        let mut dispatches = self.transcription_dispatch.lock().unwrap();
        dispatches.retain(|(_, _, generation), _| *generation == config.generation());
        match &resolved {
            Some(service) => {
                dispatches.insert(key, service.clone());
            }
            None => {
                dispatches.remove(&key);
            }
        }
        resolved
    }

    pub(crate) fn set_message_media_authority(
        &self,
        authority: Option<(
            Arc<crate::media_storage::MediaStorageRecovery>,
            crate::media_reservation::MediaReservationLedger,
        )>,
    ) {
        *self.message_media_authority.lock().unwrap() = authority;
    }

    pub(crate) fn message_media_authority(
        &self,
    ) -> Option<(
        Arc<crate::media_storage::MediaStorageRecovery>,
        crate::media_reservation::MediaReservationLedger,
    )> {
        self.message_media_authority.lock().unwrap().clone()
    }

    pub(crate) fn media_reservation_ledger(
        &self,
    ) -> Option<crate::media_reservation::MediaReservationLedger> {
        if let Some((_, ledger)) = self.message_media_authority.lock().unwrap().as_ref() {
            return Some(ledger.clone());
        }
        #[cfg(test)]
        {
            return self.test_media_reservation_ledger.lock().unwrap().clone();
        }
        #[cfg(not(test))]
        None
    }

    #[cfg(test)]
    pub(crate) fn set_test_media_reservation_ledger(
        &self,
        ledger: crate::media_reservation::MediaReservationLedger,
    ) {
        *self.test_media_reservation_ledger.lock().unwrap() = Some(ledger);
    }

    pub(crate) fn set_tool_media_runtime(
        &self,
        runtime: Option<Arc<crate::tool_media_authority::runtime::ToolMediaRuntime>>,
    ) {
        *self.tool_media_runtime.lock().unwrap() = runtime;
    }

    pub(crate) fn tool_media_runtime(
        &self,
    ) -> Option<Arc<crate::tool_media_authority::runtime::ToolMediaRuntime>> {
        self.tool_media_runtime.lock().unwrap().clone()
    }

    pub(crate) fn set_tool_media_authority(
        &self,
        authority: Option<Arc<crate::tool_media_authority::SessionMediaAuthority>>,
    ) {
        *self.tool_media_authority.lock().unwrap() = authority;
    }

    pub(crate) fn tool_media_authority(
        &self,
    ) -> Option<Arc<crate::tool_media_authority::SessionMediaAuthority>> {
        self.tool_media_authority.lock().unwrap().clone()
    }

    pub(crate) fn install_profile_utility_model_resolver(
        &self,
        resolver: Arc<ProfileUtilityModelResolver>,
    ) {
        *self.profile_utility_model_resolver.lock().unwrap() = Some(resolver);
    }

    pub(crate) fn profile_utility_model(
        &self,
        profile_snapshot_id: Uuid,
        slot: &str,
    ) -> Option<Arc<crate::engine::model::Model>> {
        self.profile_utility_model_resolver
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|resolve| resolve(self.id, profile_snapshot_id, slot))
    }

    /// Install (or inherit) the daemon-process command-secret cache.
    /// Late-installed like [`Self::set_external_journal`] before the worker /
    /// DocsAsk / fork / scheduled session builds any store, so every credential
    /// store this session builds injects resolved command outputs. Takes an
    /// `Option` so a derived session can copy a parent's cache verbatim
    /// (`child.set_command_secret_cache(parent.command_secret_cache())`) — a
    /// parent without a cache yields `None` and the child resolves as missing.
    pub(crate) fn set_command_secret_cache(
        &self,
        cache: Option<Arc<crate::secret_command::CommandSecretCache>>,
    ) {
        *self.command_secret_cache.lock().unwrap() = cache;
    }

    pub(crate) fn command_secret_cache(
        &self,
    ) -> Option<Arc<crate::secret_command::CommandSecretCache>> {
        self.command_secret_cache.lock().unwrap().clone()
    }

    /// Install (or inherit) the daemon's descendant process-containment handle.
    /// Late-installed like [`Self::set_external_journal`] before the worker /
    /// fork / scheduled session spawns any lifecycle hook. Takes an `Option` so
    /// a derived session copies a parent's handle verbatim
    /// (`child.set_process_containment(parent.process_containment())`).
    pub(crate) fn set_process_containment(
        &self,
        handle: Option<crate::process_containment::ProcessContainmentHandle>,
    ) {
        *self.process_containment.lock().unwrap() = handle;
    }

    /// The daemon containment handle for this session's hook spawns, if
    /// installed. `None` in isolated / non-daemon sessions.
    pub(crate) fn process_containment(
        &self,
    ) -> Option<crate::process_containment::ProcessContainmentHandle> {
        self.process_containment.lock().unwrap().clone()
    }

    /// The session's protected redaction-history key resolver. Required and
    /// installed at construction (decision 16). Consumed by the journaling
    /// chokepoints landed in Layer C.
    pub(crate) fn redaction_key_resolver(
        &self,
    ) -> &Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver> {
        &self.redaction_key_resolver
    }

    pub(crate) fn secret_vault(&self) -> &Arc<crate::secure_key::SecretVault> {
        &self.secret_vault
    }

    pub(crate) fn credential_store(&self) -> anyhow::Result<crate::credentials::CredentialStore> {
        let mut store = crate::credentials::CredentialStore::from_vault(self.secret_vault.clone())?;
        self.inject_command_outputs_if_installed(&mut store);
        Ok(store)
    }

    /// Inject resolved command-backed outputs from the installed daemon cache
    /// into `store` (single funnel; see
    /// [`crate::credentials::CredentialStore::inject_command_outputs`]). A no-op
    /// when no cache is installed (isolated sessions) — command secrets then
    /// resolve as missing. The lock guard is released before the (sync,
    /// execution-free) injection so it is never held across other work.
    fn inject_command_outputs_if_installed(&self, store: &mut crate::credentials::CredentialStore) {
        if let Some(cache) = self.command_secret_cache() {
            store.inject_command_outputs(&cache);
        }
    }

    /// Invalidate and re-resolve the command-backed secret(s) referenced by ONLY
    /// the `provider_id` entry, through this session's OWNER-SCOPED store — the
    /// session-scoped sibling of the daemon registry's
    /// `resolve_provider_command_secrets` (owner-scoped, invalidate-then-
    /// `ensure_resolved`). Used by the engine's `CredentialsRejected` rebuild-
    /// and-retry path (AC5), which has the session but not the registry: a stale
    /// short-lived command token for the FAILING provider is re-minted into the
    /// daemon cache so the subsequently-rebuilt model client observes the fresh
    /// value. Scoped to `provider_id` so a 401 from one provider never invalidates
    /// or executes a sibling provider's command secret.
    ///
    /// Returns `true` iff at least one owner-scoped command-backed secret for
    /// `provider_id` was eligible and re-resolved — the caller gates the rebuild-
    /// and-retry on this so a provider with only a static/env/literal credential
    /// (no command-backed secret) triggers NO exec, no rebuild, and no retry. A
    /// name the owner-scoped store does not know as command-backed (foreign,
    /// unclaimed, or literal) is skipped and never executed. The store is an
    /// owned snapshot, so no lock guard is held across the `.await`s.
    pub(crate) async fn reresolve_provider_command_secrets(
        &self,
        providers: &crate::config::providers::ProvidersConfig,
        provider_id: &str,
    ) -> bool {
        let Some(cache) = self.command_secret_cache() else {
            return false;
        };
        let referenced =
            crate::secret_ref::provider_named_secret_references_for(providers, provider_id);
        if referenced.is_empty() {
            return false;
        }
        let store = match self.provider_credential_store(providers) {
            Ok(store) => store,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "command-secret re-resolution skipped: owner-scoped store unavailable"
                );
                return false;
            }
        };
        let mut reresolved_any = false;
        for name in &referenced {
            let Some(argv) = store.named_secret_command_spec(name) else {
                continue;
            };
            let argv = argv.to_vec();
            cache.invalidate(name);
            // Only a SUCCESSFUL (`Resolved`) re-resolution counts as eligible: a
            // command that fails to resolve leaves the secret still broken, so a
            // rebuild-and-retry would just 401 again with the same stale/missing
            // credential. A referenced-but-failing command ⇒ not eligible ⇒ the
            // caller surfaces the original auth error with no rebuild/retry.
            if cache.ensure_resolved(name, &argv).await.is_resolved() {
                reresolved_any = true;
            }
        }
        reresolved_any
    }

    /// Force-refresh this provider's global auth command, if configured.
    /// Unlike the legacy named-command boolean seam above, command execution
    /// and JSON failures are returned so a rejected request surfaces the auth
    /// failure instead of silently falling back to its original 401.
    pub(crate) async fn refresh_provider_auth_command(
        &self,
        providers: &crate::config::providers::ProvidersConfig,
        provider_id: &str,
    ) -> anyhow::Result<bool> {
        let Some(entry) = providers.providers.get(provider_id) else {
            return Ok(false);
        };
        if entry.auth_command.is_none() {
            return Ok(false);
        }
        let store = self.provider_credential_store(providers)?;
        crate::auth::command::resolve(
            provider_id,
            entry,
            store,
            &|name| std::env::var(name).ok(),
            true,
        )
        .await
        .map_err(crate::auth::command::refresh_failure)?;
        Ok(true)
    }

    /// Owner-scoped provider resolution store. Unlike [`Self::credential_store`]
    /// (the comprehensive view used for redaction and inventory), this restricts
    /// the resolvable `$secret:` names to those owned by (provider, this
    /// session's project root), backfilling legacy references this provider
    /// config actually uses. A provider request built from this store can never
    /// resolve a secret owned by a different kind/workspace. See
    /// `named-secret-ownership-boundary`.
    pub(crate) fn provider_credential_store(
        &self,
        providers: &crate::config::providers::ProvidersConfig,
    ) -> anyhow::Result<crate::credentials::CredentialStore> {
        let mut store = crate::credentials::CredentialStore::from_vault_owner_scoped(
            self.secret_vault.clone(),
            crate::secret_ownership::OWNER_KIND_PROVIDER,
            &crate::secret_ownership::canonical_owner_root(
                &self.project_root.display().to_string(),
            ),
            &crate::secret_ref::provider_named_secret_references(providers),
            // The session boundary has no cross-config scan, so sole-ownership of
            // an unclaimed legacy name is unprovable here: never lazily claim
            // (fail closed on unclaimed). The daemon's provider settings paths
            // establish ownership with a scan; already-owned names still resolve.
            None,
        )?;
        // Inject resolved command outputs from the daemon cache. The store is
        // owner-scoped, so only (provider, this-workspace)-owned command names
        // are present and injectable — a foreign-owned command name is never
        // injected (and, resolved through this same scoped view, never execed).
        self.inject_command_outputs_if_installed(&mut store);
        Ok(store)
    }

    /// Take the audited opt-out from the durable-before-handoff inference
    /// journal barrier.
    ///
    /// This is deliberately NOT a silent boolean toggle: every opt-out must name
    /// a [`UnjournaledInferenceReason`] (enumerating exactly the sessions that
    /// provably cannot attach the daemon-owned journal), and each call bumps the
    /// process-wide audit counter ([`unjournaled_inference_optout_count`]) so
    /// doctor / audit surfaces can observe how often the barrier was waived.
    ///
    /// The barrier itself remains non-optional for every ordinary
    /// (daemon/session-worker) session — those never call this and so a missing
    /// journal refuses the provider handoff (see
    /// `engine::agent::turn_phases::prepare_inference_journal`).
    pub fn allow_unjournaled_inference(&self, reason: UnjournaledInferenceReason) {
        *self.unjournaled_inference_reason.lock().unwrap() = Some(reason);
        // Publish the reason before the fast-path flag so any reader that sees
        // the flag set also sees the justification.
        self.allow_unjournaled_inference
            .store(true, std::sync::atomic::Ordering::Release);
        UNJOURNALED_INFERENCE_OPTOUTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!(
            reason = reason.as_str(),
            "inference journal barrier waived for this session (audited unjournaled opt-out)"
        );
    }

    pub(crate) fn unjournaled_inference_allowed(&self) -> bool {
        self.allow_unjournaled_inference
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// The audited justification recorded for this session's opt-out, if any.
    /// Exposed for doctor / audit rendering; never carries free text.
    pub fn unjournaled_inference_reason(&self) -> Option<UnjournaledInferenceReason> {
        *self.unjournaled_inference_reason.lock().unwrap()
    }

    /// Install a production-shaped in-process external journal so tests exercise
    /// the real durable-before-handoff barrier instead of bypassing it. The
    /// spool lives under the session's project root (kept alive by the test's
    /// own tempdir). This mirrors the daemon's boot-time install; the barrier is
    /// non-optional in test builds, so any test that drives inference must call
    /// this (or take the audited `allow_unjournaled_inference` opt-out).
    #[cfg(test)]
    pub(crate) fn install_test_external_journal(&self) {
        std::fs::create_dir_all(&self.project_root).ok();
        let spool_root = self.project_root.join("cockpit-test-external-journal");
        let journal =
            crate::external_journal::ExternalJournal::for_test_at(self.db.clone(), &spool_root);
        self.set_external_journal(Some(Arc::new(journal)));
    }

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

    #[cfg(test)]
    pub(crate) fn record_booted_root_for_test(&self, root: &crate::engine::agent::Agent) {
        *self.booted_root_profile.lock().unwrap() = Some(BootedRootProfile {
            agent_name: root.name.clone(),
            provider_id: root.model.provider_id().to_string(),
            model_id: root.model.model_id_ref().to_string(),
            tool_names: root.tools.names().into_iter().map(str::to_string).collect(),
            native_computer: root.params.native_computer.clone(),
        });
    }

    #[cfg(test)]
    pub(crate) fn booted_root_profile_for_test(&self) -> Option<BootedRootProfile> {
        self.booted_root_profile.lock().unwrap().clone()
    }

    pub fn model_system_prompt_snapshot(&self) -> Arc<ModelSystemPromptSnapshot> {
        self.model_system_prompt_snapshot.clone()
    }

    /// Stable KB block for the cached root system prompt. Its source is a
    /// root-definition-bound snapshot, never a live registry or dream-status
    /// read.
    pub fn knowledge_base_system_prompt(&self) -> String {
        self.knowledge_base_prompt_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .render_system_block()
    }

    /// Whether worker startup still has to bind the initial root's KB prompt
    /// snapshot. This is intentionally independent of `freshly_created`: a
    /// durable row can survive an interrupted first startup before capture.
    pub(crate) fn needs_knowledge_base_prompt_snapshot_capture(&self) -> bool {
        !self
            .knowledge_base_prompt_snapshot_captured
            .load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn set_knowledge_base_prompt_snapshot_for_test(&mut self, raw: &str) {
        *self
            .knowledge_base_prompt_snapshot
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Arc::new(KnowledgeBasePromptSnapshot::from_json_str(raw));
        self.knowledge_base_prompt_snapshot_captured
            .store(true, Ordering::Release);
    }

    /// Return one-line, per-turn freshness facts for dreams that completed
    /// after this session began. This does not update the cached system prompt.
    /// A failed freshness read fails the turn before model dispatch rather than
    /// sending a turn with a potentially stale prefix and no notice.
    ///
    /// This deliberately does not acknowledge a notice. The caller appends a
    /// returned message to the live turn history immediately before dispatch;
    /// that history is the delivery record. If a turn is cancelled, times out,
    /// or is retried before dispatch, asking again returns the same notice, so
    /// an acknowledgement can never outlive the history that delivers it.
    pub async fn knowledge_base_freshness_notices(&self) -> Result<Vec<String>> {
        let snapshot = self
            .knowledge_base_prompt_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if snapshot.entries().is_empty() {
            return Ok(Vec::new());
        }
        let consumer = self
            .db
            .ensure_installation_identity()
            .await
            .context("loading installation identity for knowledge freshness")?;
        let project_root = self.project_root.to_string_lossy().into_owned();
        let mut fresh = Vec::new();
        for entry in snapshot.entries() {
            let current = self
                .db
                .knowledge_dream_completion(&entry.id, &project_root, consumer.as_hex())
                .await
                .with_context(|| format!("loading knowledge freshness for `{}`", entry.id))?;
            let Some(current) = current else {
                continue;
            };
            if current.revision > entry.dream_completion_revision {
                fresh.push((
                    entry.id.clone(),
                    entry.freshness_notice_name.clone(),
                    current.revision,
                    current.completed_at_unix_ms,
                ));
            }
        }
        Ok(fresh
            .into_iter()
            .map(|(_id, name, revision, timestamp)| {
                format!(
                    "KB {name} finished a new dream at {} (completion revision {revision}); newer knowledge is now available.",
                    crate::knowledge::format_dream_timestamp(timestamp)
                )
            })
            .collect())
    }

    /// Record that the model successfully used the dedicated tool `tool` this
    /// session, for the defensive bash-routing nudge's self-suppression
    /// (implementation note). Only the
    /// tip-target names (`read`/`search`/`code`) carry
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
        let session_id = self.id;
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::set_session_created_by_principal_conn(
                    conn,
                    session_id,
                    principal.as_deref(),
                )
            })
            .context("setting session creator principal")
    }

    /// Stamp "an inference send just happened now." Drives the cache-TTL
    /// arm of the cache-cold predicate (GOALS §10) and establishes the
    /// absolute origin of a keep-warm idle window. Called once per
    /// `model.complete` round-trip.
    pub fn note_send(&self) {
        self.note_send_at(
            std::time::Instant::now(),
            tokio::time::Instant::now(),
            chrono::Utc::now().timestamp_millis(),
        );
    }

    /// Seconds since the last inference send, or `None` if no send has
    /// happened yet this (in-memory) session. `None` means "treat the
    /// cache as cold" — there is no warm prefix to lose.
    pub fn seconds_since_last_send(&self) -> Option<u64> {
        self.last_send_at
            .lock()
            .unwrap()
            .map(|t| t.monotonic.elapsed().as_secs())
    }

    /// Snapshot the latest inference send's durable identity. The timestamp
    /// is only for the daemon job deadline; elapsed-time policy continues to
    /// use [`Self::seconds_since_last_send`] while the session is live.
    pub(crate) fn last_send_identity(&self) -> Option<InferenceSendIdentity> {
        self.last_send_at.lock().unwrap().map(|t| t.identity)
    }

    /// Atomically snapshot the latest send's durable identity and monotonic
    /// origin. Keep-warm derives its absolute execution deadline directly
    /// from this origin, so synchronous preparation cannot extend the idle
    /// window between sampling elapsed time and arming a timer.
    pub(crate) fn last_send_identity_and_origin(
        &self,
    ) -> Option<(InferenceSendIdentity, tokio::time::Instant)> {
        self.last_send_at
            .lock()
            .unwrap()
            .map(|t| (t.identity, t.scheduler_monotonic))
    }

    #[cfg(test)]
    pub(crate) fn note_send_at_for_test(&self, elapsed: std::time::Duration) {
        let elapsed_millis = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
        self.note_send_at(
            std::time::Instant::now()
                .checked_sub(elapsed)
                .unwrap_or_else(std::time::Instant::now),
            tokio::time::Instant::now()
                .checked_sub(elapsed)
                .unwrap_or_else(tokio::time::Instant::now),
            chrono::Utc::now()
                .timestamp_millis()
                .saturating_sub(elapsed_millis),
        );
    }

    /// Force a timestamp collision between two otherwise distinct sends.
    /// This test seam proves that keep-warm fences on the send identity, not
    /// the millisecond used to calculate its deadline.
    #[cfg(test)]
    pub(crate) fn note_send_with_unix_millis_for_test(&self, unix_millis: i64) {
        self.note_send_at(
            std::time::Instant::now(),
            tokio::time::Instant::now(),
            unix_millis,
        );
    }

    fn note_send_at(
        &self,
        monotonic: std::time::Instant,
        scheduler_monotonic: tokio::time::Instant,
        unix_millis: i64,
    ) {
        *self.last_send_at.lock().unwrap() = Some(InferenceSendTime {
            monotonic,
            scheduler_monotonic,
            identity: InferenceSendIdentity {
                unix_millis,
                send_id: Uuid::new_v4(),
            },
        });
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

    pub async fn should_note_calibration_sample(&self, usage: crate::tokens::TokenUsage) -> bool {
        if usage.is_empty() || usage.cached_input_tokens != 0 {
            return false;
        }
        let (Some(provider), Some(model)) = (self.active_provider(), self.active_model()) else {
            return false;
        };
        !self
            .db
            .tokenizer_calibration_fresh(&provider, &model, Utc::now().timestamp())
            .await
    }

    /// Feed one inference round into the tokenizer-calibration window.
    /// `basis` is a consistent text proxy for the round-trip (the
    /// messages sent + the assistant output); `usage` is the provider's
    /// report. Samples are skipped when usage is empty or any input was
    /// cached (caching muddies the input count), and when a fresh
    /// calibration row already exists for the active `(provider,
    /// model)`. When the window closes, the best `(strategy, scale)` is
    /// fitted and persisted with a 90-day expiry.
    pub async fn note_calibration_sample(&self, basis: &str, usage: crate::tokens::TokenUsage) {
        if usage.is_empty() || usage.cached_input_tokens != 0 {
            return;
        }
        let (Some(provider), Some(model)) = (self.active_provider(), self.active_model()) else {
            return;
        };
        let now = Utc::now().timestamp();
        if self
            .db
            .tokenizer_calibration_fresh(&provider, &model, now)
            .await
        {
            return;
        }
        let actual = usage.input_tokens.saturating_add(usage.output_tokens);
        let row = {
            let mut cal = self.calibrator.lock().unwrap();
            cal.add_sample(basis, actual);
            if cal.window_closed() {
                let row = cal.result().map(|(strategy, scale)| {
                    (
                        strategy,
                        scale,
                        cal.cumulative_actual() as i64,
                        cal.sample_calls() as i64,
                    )
                });
                if row.is_some() {
                    *cal = crate::tokens::Calibrator::new();
                }
                row
            } else {
                None
            }
        };
        if let Some((strategy, scale, total, calls)) = row
            && let Err(e) = self
                .db
                .upsert_tokenizer_calibration(
                    &provider,
                    &model,
                    strategy.as_str(),
                    scale,
                    now,
                    now + crate::db::tokenizer_calibration::CALIBRATION_TTL_SECS,
                    total,
                    calls,
                )
                .await
        {
            tracing::warn!(error = %e, "upsert tokenizer_calibration failed");
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
        let wire_api =
            resolved_wire_api.or_else(|| providers?.resolve_wire_api(provider?, model?).into());
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
        crate::config::providers::WireApi::Anthropic => Some("anthropic"),
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

/// Derive a workspace key from the held root directory object, not a path or
/// workspace metadata. This is a read-only observation: resolving a workspace
/// must work on read-only and metadata-limited filesystems, and no user-owned
/// workspace state can change the key while that directory object is live.
pub fn project_id_for(root: &Path) -> Result<String> {
    let canonical = std::fs::canonicalize(root)
        .with_context(|| format!("canonicalizing workspace root {}", root.display()))?;
    let authority =
        cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(
            &canonical,
        )
        .with_context(|| format!("proving workspace root identity {}", canonical.display()))?;
    Ok(project_id_from_workspace_object(authority.identity()))
}

fn project_id_from_workspace_object(object_identity: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"cockpit-workspace-object-identity-v1\0");
    h.update(object_identity.as_bytes());
    let out = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in out {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Resolve a workspace root to the single path spelling that may be persisted
/// in session state or published in a workspace marker.
fn canonical_workspace_root(project_root: &Path) -> Result<PathBuf> {
    let canonical_root = std::fs::canonicalize(project_root)
        .with_context(|| format!("canonicalizing workspace root `{}`", project_root.display()))?;
    anyhow::ensure!(
        canonical_root.is_dir(),
        "workspace root `{}` is not a directory",
        canonical_root.display()
    );
    Ok(canonical_root)
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct WorkspaceDirMarker {
    project_id: String,
    canonical_root: String,
    created_at_unix_ms: i64,
    last_used_at_unix_ms: i64,
}

/// Per-workspace process-local serialization for marker read/modify/write.
///
/// The marker itself is published with a crash-atomic replacement, so readers
/// in other processes observe either the previous complete document or the
/// next one. The mutex preserves the timestamp and canonical-root invariant
/// between concurrent sessions in this daemon before that publication occurs.
static WORKSPACE_MARKER_LOCKS: OnceLock<Mutex<std::collections::HashMap<String, Arc<Mutex<()>>>>> =
    OnceLock::new();

fn workspace_marker_lock(project_id: &str) -> Arc<Mutex<()>> {
    let locks = WORKSPACE_MARKER_LOCKS.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    locks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(project_id.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Return the durable workspace root for a known `project_id`. This is a
/// direct path calculation; it never scans project roots or re-hashes paths.
pub fn workspace_dir_for_project_id(project_id: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        !project_id.is_empty()
            && project_id.len() <= 1024
            && project_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid workspace project id"
    );
    Ok(cockpit_config::config::resolve::cockpit_state_dir()?
        .join("workspaces")
        .join(project_id))
}

/// Recover the canonical workspace path recorded for `project_id`, without a
/// filesystem scan or path re-hash. A missing marker means this workspace has
/// not yet used durable scratch on this machine.
pub fn workspace_root_for_project_id(project_id: &str) -> Result<Option<PathBuf>> {
    let marker_path = workspace_dir_for_project_id(project_id)?.join(".workspace.json");
    let bytes = match std::fs::read(&marker_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading `{}`", marker_path.display()));
        }
    };
    let marker: WorkspaceDirMarker = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing `{}`", marker_path.display()))?;
    anyhow::ensure!(
        marker.project_id == project_id,
        "workspace marker project id does not match directory"
    );
    let canonical_root = PathBuf::from(marker.canonical_root);
    anyhow::ensure!(
        canonical_root.is_absolute(),
        "workspace marker canonical root must be absolute"
    );
    Ok(Some(canonical_root))
}

/// Return the reverse-map details needed by daemon-owned storage maintenance.
/// This reads only the project-id marker; it never scans candidate workspace
/// roots or attempts to rediscover a missing mount.
pub fn workspace_storage_details_for_project_id(
    project_id: &str,
) -> Result<Option<(PathBuf, i64)>> {
    let marker_path = workspace_dir_for_project_id(project_id)?.join(".workspace.json");
    let bytes = match std::fs::read(&marker_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading `{}`", marker_path.display()));
        }
    };
    let marker: WorkspaceDirMarker = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing `{}`", marker_path.display()))?;
    anyhow::ensure!(
        marker.project_id == project_id,
        "workspace marker project id does not match directory"
    );
    let canonical_root = PathBuf::from(marker.canonical_root);
    anyhow::ensure!(
        canonical_root.is_absolute(),
        "workspace marker canonical root must be absolute"
    );
    Ok(Some((canonical_root, marker.last_used_at_unix_ms)))
}

fn workspace_scratch_dir_for_session(
    project_id: &str,
    project_root: &Path,
    session_id: Uuid,
) -> Result<PathBuf> {
    // The marker is the authoritative project_id -> path reverse map. Never
    // publish a caller spelling here: relative paths and inaccessible roots
    // would make its value cwd-dependent or noncanonical on later reads.
    // Canonicalize before creating any durable workspace state so a failed
    // session setup cannot leave a misleading workspace directory behind.
    let canonical_root = canonical_workspace_root(project_root)?
        .to_string_lossy()
        .into_owned();

    let workspace_dir = workspace_dir_for_project_id(project_id)?;
    std::fs::create_dir_all(&workspace_dir)
        .with_context(|| format!("creating `{}`", workspace_dir.display()))?;

    let marker_path = workspace_dir.join(".workspace.json");
    let marker_lock = workspace_marker_lock(project_id);
    let _marker_guard = marker_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Utc::now().timestamp_millis();
    let created_at_unix_ms = match std::fs::read(&marker_path) {
        Ok(bytes) => {
            let marker: WorkspaceDirMarker = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing `{}`", marker_path.display()))?;
            anyhow::ensure!(
                marker.project_id == project_id,
                "workspace marker project id does not match directory"
            );

            if marker.canonical_root == canonical_root {
                marker.created_at_unix_ms
            } else if project_id_for(Path::new(&marker.canonical_root))
                .ok()
                .as_deref()
                == Some(project_id)
            {
                // A live directory object with this identity is already
                // bound to a different canonical root. Never retarget its
                // durable scratch by accepting an alternate pathname.
                anyhow::bail!("workspace marker does not match this project identity");
            } else {
                // Project IDs are derived from directory-object identity.
                // Filesystems may reuse that identity after a workspace is
                // removed, leaving a marker whose old root no longer proves
                // the current project. Replace only that stale reverse map.
                now
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => now,
        Err(error) => {
            return Err(error).with_context(|| format!("reading `{}`", marker_path.display()));
        }
    };
    let marker = WorkspaceDirMarker {
        project_id: project_id.to_string(),
        canonical_root,
        created_at_unix_ms,
        last_used_at_unix_ms: now,
    };
    let mut marker_bytes = serde_json::to_vec_pretty(&marker)?;
    marker_bytes.push(b'\n');
    cockpit_host::private_fs::write_private_file(&marker_path, &marker_bytes)
        .with_context(|| format!("atomically publishing `{}`", marker_path.display()))?;

    let session_dir = workspace_scratch_path_for_session(project_id, session_id)?;
    std::fs::create_dir_all(&session_dir)
        .with_context(|| format!("creating `{}`", session_dir.display()))?;
    Ok(session_dir)
}

/// Calculate a session's durable scratch path without touching the filesystem.
/// Consumers that inspect persisted history use this rather than recreating a
/// marker or depending on the live session object.
pub(crate) fn workspace_scratch_path_for_session(
    project_id: &str,
    session_id: Uuid,
) -> Result<PathBuf> {
    Ok(workspace_dir_for_project_id(project_id)?
        .join("sessions")
        .join(session_id.to_string()))
}

/// Isolate direct, pre-identity test fixtures from the production workspace
/// namespace.  These rows deliberately retain their short labels in the
/// ledger, so using the label as a directory component would bypass the
/// production project-id validation.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn test_fixture_workspace_scratch_path_for_session(
    fixture_project_id: &str,
    session_id: Uuid,
) -> Result<PathBuf> {
    let directory_id = project_id_from_workspace_object(&format!(
        "cockpit-legacy-test-fixture-workspace-v1\\0{fixture_project_id}"
    ));
    Ok(cockpit_config::config::resolve::cockpit_state_dir()?
        .join("test-workspaces")
        .join(directory_id)
        .join("sessions")
        .join(session_id.to_string()))
}

const TITLE_SCHEDULE_SLOTS: [u8; 5] = [1, 2, 4, 8, 16];
const METADATA_SCHEDULE_SLOTS: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

fn normalize_title_slot(value: i64) -> u8 {
    match value {
        i64::MIN..=0 => 0,
        1 => 1,
        2 | 3 => 2,
        4..=7 => 4,
        8..=15 => 8,
        16..=31 => 16,
        32..=63 => 32,
        64..=127 => 64,
        _ => 128,
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

fn scheduled_metadata_slot(user_turns: usize, last_slot: u8) -> Option<u8> {
    let slot = u8::try_from(user_turns).ok()?;
    if METADATA_SCHEDULE_SLOTS.contains(&slot) && slot > last_slot {
        Some(slot)
    } else {
        None
    }
}

fn count_user_turns_for_title(db: &Db, session_id: Uuid) -> usize {
    match db.blocking_write_for_sync_maintenance(move |conn| {
        crate::db::Db::thread_turns_conn(conn, session_id)
    }) {
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

    #[test]
    fn dream_read_scope_turn_clears_on_drop() {
        let scope = Arc::new(std::sync::RwLock::new(Some(
            [Uuid::nil()].into_iter().collect(),
        )));
        let run_fence = Arc::new(Mutex::new(DreamRunFenceState::Vacant));
        {
            let _turn = DreamReadScopeTurn(scope.clone(), run_fence.clone());
            assert!(scope.read().unwrap().is_some());
        }
        assert!(scope.read().unwrap().is_none());
    }

    #[test]
    fn knowledge_read_snapshots_evict_the_least_recently_used_source() {
        let mut snapshots = KnowledgeReadSnapshotStore::default();
        let first = snapshots.retain("one".to_string(), false, 6).unwrap();
        let second = snapshots.retain("two".to_string(), false, 6).unwrap();

        assert_eq!(snapshots.get(first).unwrap().contents, "one");
        let third = snapshots.retain("six".to_string(), false, 6).unwrap();

        assert!(snapshots.get(second).is_none());
        assert_eq!(snapshots.get(first).unwrap().contents, "one");
        assert_eq!(snapshots.get(third).unwrap().contents, "six");
        assert_eq!(snapshots.total_bytes, 6);
    }

    #[tokio::test]
    async fn dream_completion_injects_freshness_without_rewriting_kb_prefix() {
        let db = Db::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut session = Session::create_for_test(
            db.clone(),
            root.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        *session
            .knowledge_base_prompt_snapshot
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(
            KnowledgeBasePromptSnapshot::from_json_str(
                r#"{"entries":[{"id":"team","name":"Team Notes","description":"Shared decisions","last_dreamed_at_unix_ms":null}]}"#,
            ),
        );
        let prefix_before = session.knowledge_base_system_prompt();
        let consumer = db.ensure_installation_identity().await.unwrap();
        let root = root.path().to_string_lossy().into_owned();
        db.attach_session_to_knowledge_base("team", &root, session.id)
            .await
            .unwrap();
        db.record_knowledge_dream_completion("team", &root, consumer.as_hex(), &[session.id])
            .await
            .unwrap();

        let notices = session.knowledge_base_freshness_notices().await.unwrap();
        assert_eq!(notices.len(), 1);
        assert!(notices[0].contains("KB Team Notes finished a new dream at"));
        assert!(notices[0].contains("newer knowledge is now available"));
        assert_eq!(session.knowledge_base_system_prompt(), prefix_before);
        assert_eq!(
            session.knowledge_base_freshness_notices().await.unwrap(),
            notices,
            "detecting freshness must not acknowledge it before the caller records it in history"
        );
    }

    #[tokio::test]
    async fn knowledge_base_freshness_read_failure_is_returned() {
        let db = Db::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut session = Session::create_for_test(
            db,
            root.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        session.set_knowledge_base_prompt_snapshot_for_test(
            r#"{"entries":[{"id":"","name":"Broken","description":"bad fixture","last_dreamed_at_unix_ms":null}]}"#,
        );

        let error = session
            .knowledge_base_freshness_notices()
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("loading knowledge freshness for ``"),
            "{error:#}"
        );
    }

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

    #[tokio::test]
    async fn provider_family_resolves_for_non_builtin_provider() {
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

    #[tokio::test]
    async fn provider_family_resolves_for_custom_named_provider() {
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

    #[tokio::test]
    async fn builtin_provider_families_are_unchanged() {
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

    #[tokio::test]
    async fn unset_provider_is_distinct_from_unknown_provider() {
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

    #[tokio::test]
    async fn completions_wire_mirrors_item_id_into_call_id() {
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

    #[tokio::test]
    async fn mirrored_call_id_never_claims_provider_source() {
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

    #[tokio::test]
    async fn responses_wire_call_id_sources_are_unchanged() {
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

    #[tokio::test]
    async fn wire_api_honors_explicit_config_override() {
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

    #[tokio::test]
    async fn wire_api_auto_is_reachable_and_recorded() {
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

    #[tokio::test]
    async fn synthetic_call_in_completions_session_is_not_labeled_responses() {
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

    #[tokio::test]
    async fn synthetic_call_with_unresolved_wire_records_none() {
        let identity = ToolCallProviderIdentity::synthetic_cockpit_call("seed-1", None);

        assert_eq!(identity.wire_api, None);
        assert_eq!(identity.provider_family.as_deref(), Some("cockpit"));
        assert_eq!(
            identity.provider_call_id_source.as_deref(),
            Some("synthetic_from_cockpit_call_id")
        );
    }

    #[tokio::test]
    async fn create_and_resume_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert!(s.is_freshly_created());
        let id = s.id;
        let short = s.short_id();
        drop(s);
        let s2 = Session::resume_for_test(db, id, crate::session::test_redaction_key_resolver())
            .unwrap()
            .unwrap();
        assert_eq!(s2.id, id);
        assert_eq!(s2.short_id(), short);
        assert!(s2.parent_session_id.is_none());
        assert!(s2.title().is_none());
        assert!(!s2.user_renamed());
        assert!(!s2.is_freshly_created());
    }

    #[test]
    fn resume_restores_persisted_knowledge_base_prompt_snapshot() {
        let db = Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let session_id = session.id;
        let snapshot = r#"{"entries":[{"id":"team","name":"Team Notes","description":"Shared decisions","last_dreamed_at_unix_ms":1000,"dream_completion_revision":1}]}"#;
        db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute(
                "UPDATE sessions
                 SET knowledge_base_prompt_snapshot_json = ?1,
                     knowledge_base_prompt_snapshot_captured = 1
                 WHERE session_id = ?2",
                rusqlite::params![snapshot, session_id.to_string()],
            )
            .context("persisting test knowledge-base prompt snapshot")?;
            Ok(())
        })
        .unwrap();
        drop(session);

        let resumed = Session::resume_for_test(
            db,
            session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            resumed.knowledge_base_system_prompt(),
            "Knowledge bases (root-definition snapshot):\n- Team Notes (id: team): Shared decisions\n  Last dreamed at: 1970-01-01T00:00:01+00:00\nNewer information may live in sessions after these timestamps; search it through the retrieval subagent.\n"
        );
        assert!(
            !resumed.needs_knowledge_base_prompt_snapshot_capture(),
            "a persisted snapshot must not be recaptured on resume"
        );
    }

    #[test]
    fn resume_distinguishes_uncommitted_kb_capture_from_captured_empty_snapshot() {
        let db = Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let session_id = session.id;
        drop(session);

        let interrupted = Session::resume_for_test(
            db.clone(),
            session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap();
        assert!(
            interrupted.needs_knowledge_base_prompt_snapshot_capture(),
            "a durable row before initial capture must retry root binding"
        );
        drop(interrupted);

        db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute(
                "UPDATE sessions
                 SET knowledge_base_prompt_snapshot_json = '{\"entries\":[]}',
                     knowledge_base_prompt_snapshot_captured = 1
                 WHERE session_id = ?1",
                rusqlite::params![session_id.to_string()],
            )
            .context("persisting captured empty knowledge-base snapshot")?;
            Ok(())
        })
        .unwrap();

        let resumed = Session::resume_for_test(
            db,
            session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap();
        assert!(
            !resumed.needs_knowledge_base_prompt_snapshot_capture(),
            "a captured empty snapshot is a completed stable-prefix binding"
        );
    }

    #[tokio::test]
    async fn fork_inherits_parent_metadata() {
        let db = Db::open_in_memory().unwrap();
        let parent = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        parent.set_active_model("anthropic", "opus-4-7").unwrap();
        let fork_point = parent
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({"text": "fork here"}),
            )
            .await
            .unwrap();
        let fork = Session::create_fork_for_test(
            db.clone(),
            parent.id,
            Some(fork_point.to_string()),
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
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
        assert_ne!(fork.short_id(), parent.short_id());
    }

    #[tokio::test]
    async fn rename_persists_and_blocks_auto_title() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        s.rename("hand-picked").unwrap();
        assert!(s.user_renamed());
        assert_eq!(s.title().as_deref(), Some("hand-picked"));
        assert!(!s.set_auto_title("robot-name").unwrap());
        assert_eq!(s.title().as_deref(), Some("hand-picked"));
    }

    #[tokio::test]
    async fn time_prelude_fires_on_first_call() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let prelude = s.take_time_prelude(5);
        assert!(prelude.is_some());
        let body = prelude.unwrap();
        assert!(body.starts_with("[time: "), "got {body:?}");
        assert!(body.ends_with(']'), "got {body:?}");
    }

    #[tokio::test]
    async fn time_prelude_suppressed_within_interval() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert!(s.take_time_prelude(5).is_some(), "first call should fire");
        assert!(
            s.take_time_prelude(5).is_none(),
            "second call within 5 min should suppress"
        );
    }

    #[tokio::test]
    async fn time_prelude_fires_at_zero_interval() {
        // A 0-minute interval is the "always inject" config, mainly for
        // tests. Two back-to-back calls both fire.
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
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

    #[tokio::test]
    async fn note_user_content_eager_fires_on_first_short_message() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let msg = "a short message";
        assert_eq!(s.note_user_content(msg), TitleAction::Eager);
        assert_eq!(s.user_content_tokens(), crate::tokens::count(msg));
        assert_eq!(s.user_content_turns(), 1);
        assert_eq!(s.title_stage(), 1);
    }

    #[tokio::test]
    async fn note_user_content_uses_bounded_turn_slots() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
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

    #[tokio::test]
    async fn scheduled_slot_is_consumed_even_without_title_success() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert_eq!(s.note_user_content("first"), TitleAction::Eager);
        assert!(s.title().is_none(), "utility task has not landed a title");
        assert_eq!(
            s.note_user_content("third user turn after a missed title slot"),
            TitleAction::Refine,
            "the second user turn still uses the slot-2 refresh, not a repeated eager slot"
        );
    }

    #[tokio::test]
    async fn nudge_fires_at_slot_8_and_16_only_when_untitled() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
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

    #[tokio::test]
    async fn nudge_does_not_fire_once_titled() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
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

    #[tokio::test]
    async fn resumed_session_does_not_renudge_a_passed_slot() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let id = s.id;
        for turn in 1..=8 {
            s.record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("a"),
                None,
                &json!({"text": format!("turn {turn}")}),
            )
            .await
            .unwrap();
            let _ = s.note_user_content(&format!("turn {turn}"));
        }
        assert_eq!(s.title_stage(), 8);
        drop(s);

        let resumed =
            Session::resume_for_test(db, id, crate::session::test_redaction_key_resolver())
                .unwrap()
                .unwrap();
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

    #[tokio::test]
    async fn compact_self_nudge_two_shot_latch() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        let first = s
            .compact_self_nudge(Some(62.0), 60, 80, true, true)
            .expect("first nudge fires at nudge threshold");
        assert!(first.contains("mcp.invoke(\"cockpit\", \"request_compact\", {})"));
        assert!(first.contains("62%"));
        assert!(first.contains("80%"));
        assert!(
            s.compact_self_nudge(Some(62.0), 60, 80, true, true)
                .is_none()
        );
        assert!(
            s.compact_self_nudge(Some(69.0), 60, 80, true, true)
                .is_none()
        );

        let second = s
            .compact_self_nudge(Some(71.0), 60, 80, true, true)
            .expect("second nudge fires at nudge + 10");
        assert!(second.contains("71%"));
        assert!(
            s.compact_self_nudge(Some(71.0), 60, 80, true, true)
                .is_none()
        );

        s.reset_compact_self_nudge_latch();
        assert!(
            s.compact_self_nudge(Some(62.0), 60, 80, true, true)
                .is_some()
        );
    }

    #[tokio::test]
    async fn compact_self_nudge_suppressed_when_unactionable() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        assert!(
            s.compact_self_nudge(Some(62.0), 60, 80, true, false)
                .is_none()
        );
        assert!(
            s.compact_self_nudge(Some(62.0), 60, 80, false, true)
                .is_none()
        );
        assert!(s.compact_self_nudge(None, 60, 80, true, true).is_none());
        assert!(
            s.compact_self_nudge(Some(59.0), 60, 80, true, true)
                .is_none()
        );
    }

    #[tokio::test]
    async fn compact_self_nudge_latch_reset_only_on_compaction() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        assert!(
            s.compact_self_nudge(Some(62.0), 60, 80, true, true)
                .is_some()
        );
        assert!(
            s.compact_self_nudge(Some(50.0), 60, 80, true, true)
                .is_none()
        );
        assert!(
            s.compact_self_nudge(Some(62.0), 60, 80, true, true)
                .is_none()
        );
        s.reset_compact_self_nudge_latch();
        assert!(
            s.compact_self_nudge(Some(62.0), 60, 80, true, true)
                .is_some()
        );
    }

    #[tokio::test]
    async fn note_user_content_skips_when_user_renamed() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        s.rename("user-set").unwrap();
        // No scheduled slot fires once the user has renamed — not even eager.
        assert_eq!(s.note_user_content("hello"), TitleAction::None);
        let big = text_of_at_least(crate::auto_title::TITLE_TOKEN_THRESHOLD);
        assert_eq!(s.note_user_content(&big), TitleAction::None);
    }

    #[tokio::test]
    async fn note_user_content_empty_is_noop() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert_eq!(s.note_user_content(""), TitleAction::None);
        assert_eq!(s.user_content_tokens(), 0);
        assert_eq!(s.user_content_turns(), 0);
    }

    #[tokio::test]
    async fn non_slot_turns_do_not_fire_even_with_large_content() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let big = text_of_at_least(crate::auto_title::TITLE_TOKEN_THRESHOLD * 2);
        assert_eq!(s.note_user_content("one"), TitleAction::Eager);
        assert_eq!(s.note_user_content("two"), TitleAction::Refine);
        assert_eq!(s.note_user_content(&big), TitleAction::None);
    }

    #[tokio::test]
    async fn title_progress_survives_resume() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let id = s.id;
        s.record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("a"),
            None,
            &json!({"text": "hello"}),
        )
        .await
        .unwrap();
        assert_eq!(s.note_user_content("hello"), TitleAction::Eager);
        let carried = s.user_content_tokens();
        assert_eq!(s.title_stage(), 1);
        drop(s);

        let resumed =
            Session::resume_for_test(db, id, crate::session::test_redaction_key_resolver())
                .unwrap()
                .unwrap();
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

    #[tokio::test]
    async fn note_user_content_refine_skips_when_user_renamed_after_eager() {
        // A /rename after an eager title wins and blocks later scheduled slots.
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert!(s.set_auto_title("eager-title").unwrap());
        s.mark_eager_titled();
        s.rename("user-chosen").unwrap();
        let big = text_of_at_least(crate::auto_title::TITLE_TOKEN_THRESHOLD);
        assert_eq!(s.note_user_content(&big), TitleAction::None);
    }

    #[tokio::test]
    async fn title_failure_notice_is_one_per_session() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert!(s.claim_title_failure_notice(), "first claim wins");
        assert!(
            !s.claim_title_failure_notice(),
            "second claim is suppressed"
        );
    }

    #[tokio::test]
    async fn redaction_placeholder_notice_is_one_per_session() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert!(s.claim_redaction_placeholder_notice(), "first claim wins");
        assert!(
            !s.claim_redaction_placeholder_notice(),
            "second claim is suppressed"
        );
    }

    #[tokio::test]
    async fn fork_inherits_user_content_counter() {
        let db = Db::open_in_memory().unwrap();
        let parent = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "a",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let _ = parent.note_user_content(&"x".repeat(1000));
        let fork = Session::create_fork_for_test(
            db,
            parent.id,
            None,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert_eq!(fork.user_content_tokens(), parent.user_content_tokens());
    }

    #[tokio::test]
    async fn tmp_dir_is_per_session_and_isolated() {
        // Two sessions get distinct private tmp dirs (sandboxing part 2),
        // so neither can read the other's scratch.
        let db = Db::open_in_memory().unwrap();
        let a = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let b = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let da = a.tmp_dir().unwrap();
        let db_ = b.tmp_dir().unwrap();
        assert_ne!(da, db_, "sessions must not share a tmp dir");
        assert!(da.exists());
        assert!(db_.exists());
        // Idempotent: a second call returns the same dir.
        assert_eq!(a.tmp_dir().unwrap(), da);
    }

    #[tokio::test]
    async fn tmp_dir_removed_on_end() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let dir = s.tmp_dir().unwrap();
        std::fs::write(dir.join("scratch"), "x").unwrap();
        assert!(dir.exists());
        s.end().unwrap();
        assert!(!dir.exists(), "tmp dir must be cleaned up on session end");
    }

    #[test]
    fn test_constructor_supports_a_synthetic_workspace_root() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let synthetic_root = home.path().join("fixture-workspace-that-does-not-exist");
        let db = Db::open_in_memory().unwrap();

        let session = Session::create_for_test(
            db,
            synthetic_root.clone(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        assert_eq!(session.project_root, synthetic_root);
        assert!(session.workspace_scratch_dir().is_dir());
        assert_eq!(
            workspace_root_for_project_id(&session.project_id).unwrap(),
            None,
            "a synthetic fixture must not publish a canonical workspace marker"
        );
    }

    #[test]
    fn test_constructor_resumes_a_persisted_synthetic_workspace_root() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let synthetic_root = home.path().join("fixture-workspace-that-does-not-exist");
        let db = Db::open_in_memory().unwrap();
        let session = Session::create_deferred_for_test(
            db.clone(),
            synthetic_root.clone(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let session_id = session.id;

        assert!(session.persist_if_needed().unwrap());
        drop(session);

        let resumed = Session::resume_for_test(
            db,
            session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(resumed.project_root, synthetic_root);
    }

    #[test]
    fn workspace_scratch_is_durable_and_reverse_mapped_by_project_id() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let project_root = home.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let supplied_root = project_root.join(".");
        let canonical_root = std::fs::canonicalize(&project_root).unwrap();
        let db = Db::open_in_memory().unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let a = Session::create(
            db.clone(),
            supplied_root.clone(),
            "builder",
            &crate::config::extended::ExtendedConfig::default(),
            crate::session::test_redaction_key_resolver(),
            vault.clone(),
        )
        .unwrap();
        let b = Session::create(
            db.clone(),
            supplied_root,
            "builder",
            &crate::config::extended::ExtendedConfig::default(),
            crate::session::test_redaction_key_resolver(),
            vault,
        )
        .unwrap();

        let scratch_a = a.workspace_scratch_dir();
        let scratch_b = b.workspace_scratch_dir();
        assert_ne!(
            scratch_a, scratch_b,
            "concurrent sessions get distinct scratch dirs"
        );
        assert!(scratch_a.ends_with(Path::new("sessions").join(a.id.to_string())));
        assert!(scratch_b.ends_with(Path::new("sessions").join(b.id.to_string())));
        assert_eq!(a.project_root, canonical_root);
        let persisted = db
            .blocking_write_for_sync_maintenance({
                let session_id = a.id;
                move |conn| crate::db::Db::get_session_conn(conn, session_id)
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            persisted.project_root,
            canonical_root.to_string_lossy().into_owned()
        );
        assert_eq!(
            workspace_root_for_project_id(&a.project_id).unwrap(),
            Some(canonical_root)
        );

        a.end().unwrap();
        assert!(scratch_a.exists(), "durable scratch survives session end");
    }

    #[test]
    fn concurrent_workspace_scratch_initialization_keeps_marker_parseable() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let project_root = home.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let project_id = project_id_for(&project_root).unwrap();
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();

        let (first_scratch, second_scratch) = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                workspace_scratch_dir_for_session(&project_id, &project_root, first_id).unwrap()
            });
            let second = scope.spawn(|| {
                workspace_scratch_dir_for_session(&project_id, &project_root, second_id).unwrap()
            });
            (first.join().unwrap(), second.join().unwrap())
        });

        assert_ne!(first_scratch, second_scratch);
        assert_eq!(
            workspace_root_for_project_id(&project_id).unwrap(),
            Some(std::fs::canonicalize(&project_root).unwrap())
        );
    }

    #[test]
    fn workspace_scratch_rejects_uncanonicalizable_project_root() {
        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let missing_root = home.path().join("missing-project");
        let error = project_id_for(&missing_root).unwrap_err();

        assert!(error.to_string().contains("canonicalizing workspace root"));
    }

    #[tokio::test]
    async fn host_shim_dir_is_under_data_dir() {
        let data_dir = PathBuf::from("/data/cockpit");
        let session_id = uuid::Uuid::new_v4();

        let dir = lifecycle::host_shim_bin_dir_for_data_dir(&data_dir, session_id);

        assert!(dir.starts_with(&data_dir));
        assert_eq!(
            dir,
            data_dir
                .join("session-shims")
                .join(session_id.to_string())
                .join("bin")
        );
    }

    #[tokio::test]
    async fn host_shim_dir_removed_on_end() {
        let temp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let dir = temp.path().join("data/cockpit/session-shims/session/bin");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("jq"), "shim").unwrap();
        *s.host_shim_dir.lock().unwrap() = Some(dir.clone());

        s.end().unwrap();

        assert!(
            !dir.parent().unwrap().exists(),
            "host shim session dir must be cleaned up on session end"
        );
    }

    #[tokio::test]
    async fn tmp_dir_removed_on_drop() {
        let db = Db::open_in_memory().unwrap();
        let dir = {
            let s = Session::create_for_test(
                db,
                PathBuf::from("/x"),
                "builder",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap();
            let d = s.tmp_dir().unwrap();
            assert!(d.exists());
            d
        };
        assert!(!dir.exists(), "drop is the cleanup backstop");
    }

    #[tokio::test]
    async fn sandbox_flag_defaults_on_and_toggles() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
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

    #[tokio::test]
    async fn approval_mode_defaults_manual_and_round_trips() {
        use crate::config::extended::ApprovalMode;
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        // Fail-safe default until the spawn path applies the config default.
        assert_eq!(s.approval_mode(), ApprovalMode::Manual);
        // Each mode round-trips through the atomic encode/decode.
        for m in [ApprovalMode::Auto, ApprovalMode::Yolo, ApprovalMode::Manual] {
            assert_eq!(s.set_approval_mode(m), m);
            assert_eq!(s.approval_mode(), m);
        }
    }

    #[tokio::test]
    async fn session_mode_unchanged() {
        use crate::config::extended::ApprovalMode;
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        s.set_approval_mode(ApprovalMode::Manual);
        let before = s.session_approval_mode();
        assert_eq!(before, ApprovalMode::Manual);

        let run_id = Uuid::new_v4();
        // During success-path override.
        s.set_invocation_approval_override(run_id, ApprovalMode::Yolo);
        assert_eq!(s.approval_mode(), ApprovalMode::Yolo);
        assert_eq!(s.session_approval_mode(), before);
        assert_eq!(s.active_run_invocation_id(), Some(run_id));
        s.clear_invocation_approval_override();
        assert_eq!(s.session_approval_mode(), before);
        assert_eq!(s.approval_mode(), before);

        // During failure-style override (auto) then clear.
        s.set_invocation_approval_override(run_id, ApprovalMode::Auto);
        assert_eq!(s.session_approval_mode(), before);
        s.clear_invocation_approval_override();
        assert_eq!(s.session_approval_mode(), before);

        // During cancellation-style: install yolo then clear (terminal cancel).
        s.set_invocation_approval_override(run_id, ApprovalMode::Yolo);
        assert_eq!(s.session_approval_mode(), before);
        s.clear_invocation_approval_override();
        assert_eq!(s.session_approval_mode(), before);
        assert_eq!(s.active_run_invocation_id(), None);

        // set_approval_mode still only mutates session mode, never the override slot
        // when clear.
        s.set_approval_mode(ApprovalMode::Auto);
        assert_eq!(s.session_approval_mode(), ApprovalMode::Auto);
        assert_eq!(s.approval_mode(), ApprovalMode::Auto);
        s.set_approval_mode(ApprovalMode::Manual);
    }

    #[tokio::test]
    async fn auto_fail_closed() {
        use crate::config::extended::ApprovalMode;
        use std::sync::Arc;
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let s = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "builder",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        // Session stays Manual; run override is Auto without a guard model.
        s.set_approval_mode(ApprovalMode::Manual);
        let run_id = Uuid::new_v4();
        s.set_invocation_approval_override(run_id, ApprovalMode::Auto);
        assert_eq!(s.approval_mode(), ApprovalMode::Auto);
        assert_eq!(s.session_approval_mode(), ApprovalMode::Manual);
        // Approver fails closed when Auto has no guard model (auto_allows → false).
        let store = crate::approval::store::GrantStore::new(
            db.clone(),
            s.id,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
        );
        let approver = crate::approval::Approver::new_for_session(
            store,
            db,
            s.clone(),
            Arc::new(std::sync::RwLock::new(Arc::new(
                crate::redact::RedactionTable::empty(),
            ))),
            "builder",
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
        );
        assert_eq!(approver.approval_mode(), ApprovalMode::Auto);
        assert!(!approver.yolo_mode());
        assert!(
            !approver
                .auto_allows(crate::agent_tree::HostEffectClass::Destructive, "rm -rf /")
                .await,
            "Auto without guard model must fail closed"
        );
        s.clear_invocation_approval_override();
    }

    #[tokio::test]
    async fn yolo_hard_gates() {
        use crate::config::extended::ApprovalMode;
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        s.set_approval_mode(ApprovalMode::Manual);
        // Sandbox remains the gate under Yolo invocation override.
        assert!(s.sandbox_enabled());
        let run_id = Uuid::new_v4();
        s.set_invocation_approval_override(run_id, ApprovalMode::Yolo);
        assert_eq!(s.approval_mode(), ApprovalMode::Yolo);
        assert!(
            s.sandbox_enabled(),
            "yolo override must not disable sandbox hard gate"
        );
        assert_eq!(
            s.session_approval_mode(),
            ApprovalMode::Manual,
            "session mode must remain Manual"
        );
        // Explicit set_approval_mode is the only path that mutates session mode.
        s.clear_invocation_approval_override();
        assert_eq!(s.approval_mode(), ApprovalMode::Manual);
        assert!(s.sandbox_enabled());
    }

    #[tokio::test]
    async fn bump_consecutive_counts_back_to_back_repeats() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        // First call of a signature → count 1.
        assert_eq!(s.bump_consecutive_call("sig-a"), 1);
        // Immediate repeat → count 2 (the first exact repeat).
        assert_eq!(s.bump_consecutive_call("sig-a"), 2);
        // And again → 3.
        assert_eq!(s.bump_consecutive_call("sig-a"), 3);
    }

    #[tokio::test]
    async fn bump_consecutive_resets_on_a_different_call() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert_eq!(s.bump_consecutive_call("sig-a"), 1);
        assert_eq!(s.bump_consecutive_call("sig-a"), 2);
        // A different call breaks the chain — count resets to 1.
        assert_eq!(s.bump_consecutive_call("sig-b"), 1);
        // The original signature repeated *after* an intervening call is
        // NOT consecutive — it starts a fresh chain at 1, so a
        // non-consecutive repeat never trips the guard.
        assert_eq!(s.bump_consecutive_call("sig-a"), 1);
    }

    #[tokio::test]
    async fn repeated_recoverable_tool_call_message_matches_and_clears_on_difference() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

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

    #[tokio::test]
    async fn clear_recoverable_tool_call_drops_memory() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        s.remember_recoverable_tool_call("sig-a".to_string(), "msg".to_string());
        s.clear_recoverable_tool_call();

        assert_eq!(s.repeated_recoverable_tool_call_message("sig-a"), None);
    }

    #[tokio::test]
    async fn deferred_session_is_not_written_until_first_message() {
        // session-id-display-and-lazy-persist: a deferred session has an id
        // and short_id in memory but no `sessions` row, and never appears in
        // listings until persisted.
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        // Id + short_id exist immediately (for the startup graphic).
        assert!(!s.short_id().is_empty());
        assert!(!s.is_persisted());
        // No DB row yet: not fetchable, not listed.
        assert!(db.get_session(s.id).await.unwrap().is_none());
        assert!(db.list_sessions(true, 100).await.unwrap().is_empty());

        // First user message → persist. The flush returns `true` once.
        assert!(
            s.persist_if_needed().unwrap(),
            "first persist writes the row"
        );
        assert!(s.is_persisted());
        let row = db.get_session(s.id).await.unwrap().expect("row now exists");
        assert_eq!(row.short_id.as_deref(), Some(s.short_id().as_str()));
        assert_eq!(db.list_sessions(true, 100).await.unwrap().len(), 1);

        // Idempotent: a second flush is a no-op (returns `false`).
        assert!(!s.persist_if_needed().unwrap());
        assert_eq!(db.list_sessions(true, 100).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn deferred_dream_session_persists_its_audit_flag() {
        let db = Db::open_in_memory().unwrap();
        let session = Session::create_deferred_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Dream",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        session.set_deferred_dream_session().unwrap();
        assert!(session.persist_if_needed().unwrap());
        assert!(
            db.get_session(session.id)
                .await
                .unwrap()
                .expect("persisted dream session")
                .is_dream_session
        );
    }

    #[tokio::test]
    async fn persist_if_needed_adopts_collision_retry_short_id() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let claimed = s.short_id();
        let mut competitor = db.new_session_row(&s.project_id, "/x", "a").await.unwrap();
        competitor.short_id = Some(claimed.clone());
        let inserted = db.insert_session_row(&competitor).await.unwrap();
        assert_eq!(inserted.short_id.as_deref(), Some(claimed.as_str()));

        assert!(s.persist_if_needed().unwrap());
        assert_ne!(
            s.short_id(),
            claimed,
            "Attached must report the persisted id"
        );
        let row = db.get_session(s.id).await.unwrap().expect("row exists");
        assert_eq!(row.short_id.as_deref(), Some(s.short_id().as_str()));
    }

    #[tokio::test]
    async fn deferred_persist_carries_the_complete_model_selection() {
        // A model picked before the first message survives the deferred
        // write as one atomic value, including inference preferences.
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let selection = crate::config::providers::ActiveModelRef {
            provider: "anthropic".to_string(),
            model: "claude-opus-4-7".to_string(),
            reasoning_effort: Some(crate::config::providers::ActiveReasoningEffort {
                value: "high".to_string(),
            }),
            thinking_mode: Some(crate::config::providers::ThinkingMode::High),
            prompt_cache_retention: Some(crate::config::providers::PromptCacheRetention::Extended),
        };
        s.set_active_model_ref(selection.clone()).unwrap();
        assert!(db.get_session(s.id).await.unwrap().is_none());
        s.persist_if_needed().unwrap();
        let row = db.get_session(s.id).await.unwrap().unwrap();
        assert_eq!(row.provider.as_deref(), Some("anthropic"));
        assert_eq!(row.model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(
            serde_json::from_str::<crate::config::providers::ActiveModelRef>(
                row.model_selection_json.as_deref().unwrap()
            )
            .unwrap(),
            selection
        );
    }

    #[tokio::test]
    async fn resume_rejects_divergent_model_selection_projections() {
        let db = Db::open_in_memory().unwrap();
        let row = Session::insert_row_for_test(
            &db,
            Path::new("/x"),
            "Build",
            TestSessionRowOptions::default().with_raw_model_selection_fields(
                Some("projection-provider".to_string()),
                Some("projection-model".to_string()),
                Some(
                    serde_json::json!({
                        "provider": "structured-provider",
                        "model": "structured-model",
                        "thinking_mode": "high"
                    })
                    .to_string(),
                ),
            ),
        )
        .await
        .unwrap();

        let error = Session::resume_for_test(
            db,
            row.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .err()
        .expect("divergent projections must not hydrate ambiguous model state")
        .to_string();
        assert!(error.contains("projections disagree"), "{error}");
    }

    #[tokio::test]
    async fn resume_rejects_projection_only_model_state() {
        let db = Db::open_in_memory().unwrap();
        let row = Session::insert_row_for_test(
            &db,
            Path::new("/x"),
            "Build",
            TestSessionRowOptions::default().with_raw_model_selection_fields(
                Some("projection-provider".to_string()),
                Some("projection-model".to_string()),
                None,
            ),
        )
        .await
        .unwrap();

        let error = Session::resume_for_test(
            db,
            row.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .err()
        .expect("projection-only state must not synthesize empty preferences")
        .to_string();
        assert!(error.contains("require model_selection_json"), "{error}");
    }

    #[tokio::test]
    async fn insert_row_for_test_rejects_assistant_with_non_assistant_entry_mode() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.list_sessions(false, 100).await.unwrap().is_empty());

        let error = Session::insert_row_for_test(
            &db,
            Path::new("/x"),
            "Build",
            TestSessionRowOptions::default()
                .with_assistant("helper")
                .with_entry_mode(crate::daemon::proto::SessionEntryMode::Computer),
        )
        .await
        .expect_err("assistant rows must reject non-assistant entry modes")
        .to_string();

        assert_eq!(error, "assistant test row requires assistant entry mode");
        assert!(db.list_sessions(false, 100).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn resume_for_test_rejects_mismatched_raw_project_identity() {
        let db = Db::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();
        let mut row = db
            .new_session_row(
                "deliberately-mismatched-project-id",
                root.path().to_str().unwrap(),
                "Build",
            )
            .await
            .unwrap();
        row = db.insert_session_row(&row).await.unwrap();

        let error = Session::resume_strict_for_test(
            db,
            row.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .err()
        .expect("raw identity mismatch must fail closed")
        .to_string();
        assert_eq!(
            error,
            "persisted session project id does not match canonical workspace root"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_row_persists_canonical_symlink_target_for_resume() {
        let db = Db::open_in_memory().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        let original = fixture.path().join("original");
        let replacement = fixture.path().join("replacement");
        let alias = fixture.path().join("workspace");
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(&replacement).unwrap();
        std::os::unix::fs::symlink(&original, &alias).unwrap();
        let canonical_original = std::fs::canonicalize(&original).unwrap();

        let row =
            Session::insert_row_for_test(&db, &alias, "Build", TestSessionRowOptions::default())
                .await
                .unwrap();
        assert_eq!(PathBuf::from(&row.project_root), canonical_original);

        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&replacement, &alias).unwrap();
        let resumed = Session::resume_for_test(
            db,
            row.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("durable row remains bound to the original canonical target");
        assert_eq!(resumed.project_root, canonical_original);
    }

    #[tokio::test]
    async fn deferred_persist_carries_session_overrides() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let override_json = r#"{"tools":["read","bash"],"toolTiers":{"bash":"disabled"}}"#;

        s.set_tool_surface_override_json(Some(override_json.to_string()))
            .unwrap();
        let goal_override_json = r#"{"enabled":false,"coldSkepticCount":2}"#;
        s.set_goal_settings_override_json(Some(goal_override_json.to_string()))
            .unwrap();
        assert!(db.get_session(s.id).await.unwrap().is_none());

        s.persist_if_needed().unwrap();
        let row = db.get_session(s.id).await.unwrap().unwrap();
        assert_eq!(
            row.tool_surface_override_json.as_deref(),
            Some(override_json)
        );
        assert_eq!(
            row.goal_settings_override_json.as_deref(),
            Some(goal_override_json)
        );
    }

    #[tokio::test]
    async fn deferred_persist_carries_agent_touch_and_viewed() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let original_last_active = {
            let row = s.pending_row.lock().unwrap();
            row.as_ref().unwrap().last_active_at_unix_ms
        };

        s.set_active_agent("Plan").unwrap();
        s.touch().unwrap();
        s.mark_viewed().unwrap();
        assert!(db.get_session(s.id).await.unwrap().is_none());

        s.persist_if_needed().unwrap();
        let row = db.get_session(s.id).await.unwrap().unwrap();
        assert_eq!(row.active_agent, "Plan");
        assert!(row.last_active_at_unix_ms >= original_last_active);
        assert!(row.last_viewed_at_unix_ms.is_some());
    }

    #[tokio::test]
    async fn create_is_persisted_immediately() {
        // The non-deferred constructor writes the row up front, so
        // persist_if_needed is a no-op and is_persisted is true.
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        assert!(s.is_persisted());
        assert!(!s.persist_if_needed().unwrap());
        assert!(db.get_session(s.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn record_tool_call_writes_row() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
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
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();
        let rows = db.list_tool_calls_for_session(s.id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].model, "claude-opus-4-7");
        assert_eq!(rows[0].provider, "anthropic");
    }

    #[tokio::test]
    async fn record_tool_call_persists_provider_identity_separately() {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db.clone(),
            PathBuf::from("/x"),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
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
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();

        let row = db
            .list_tool_calls_for_session(s.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
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
        let s = Session::create_for_test(
            db,
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        (s, tmp, path)
    }

    #[tokio::test]
    async fn snapshot_records_baseline_and_contents() {
        let (s, tmp, _path) = guidance_session("RULE A\nRULE B\n");
        s.snapshot_guidance_baseline(tmp.path()).await;
        let baseline =
            s.db.guidance_baseline(s.id)
                .await
                .unwrap()
                .expect("baseline set");
        assert!(baseline.path.ends_with("AGENTS.md"));
        // The content-addressed table holds the exact body.
        let stored = s.db.guidance_contents(&baseline.hash).await.unwrap();
        assert_eq!(stored.as_deref(), Some("RULE A\nRULE B\n"));
        // Hash matches the pure hasher over the body.
        assert_eq!(
            baseline.hash,
            crate::engine::guidance_diff::hash_contents("RULE A\nRULE B\n")
        );
    }

    #[tokio::test]
    async fn deferred_snapshot_baseline_survives_first_persist() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("AGENTS.md");
        std::fs::write(&path, "RULE A\nRULE B\n").unwrap();
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred_for_test(
            db.clone(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        s.snapshot_guidance_baseline(tmp.path()).await;
        assert!(db.get_session(s.id).await.unwrap().is_none());

        s.persist_if_needed().unwrap();
        let baseline =
            s.db.guidance_baseline(s.id)
                .await
                .unwrap()
                .expect("baseline set");
        assert_eq!(baseline.path, path.display().to_string());
        assert_eq!(
            baseline.hash,
            crate::engine::guidance_diff::hash_contents("RULE A\nRULE B\n")
        );
    }

    #[tokio::test]
    async fn deferred_guidance_edit_injects_after_first_message_persist() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("AGENTS.md");
        std::fs::write(&path, "line one\nline two\nline three\n").unwrap();
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_deferred_for_test(
            db,
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        s.snapshot_guidance_baseline(tmp.path()).await;
        s.persist_if_needed().unwrap();
        std::fs::write(&path, "line one\nline TWO\nline three\n").unwrap();

        let msg = s
            .guidance_change_injection(tmp.path())
            .await
            .expect("deferred baseline should inject after persist");
        assert!(msg.contains("changed since this conversation began"));
        assert!(msg.contains("line TWO"), "updated guidance missing: {msg}");
        assert!(
            s.guidance_change_injection(tmp.path()).await.is_none(),
            "same change should be idempotent"
        );
    }

    #[tokio::test]
    async fn resumed_session_guidance_baseline_still_updates() {
        let (s, tmp, path) = guidance_session("v1\n");
        s.snapshot_guidance_baseline(tmp.path()).await;
        let resumed = Session::resume_for_test(
            s.db.clone(),
            s.id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("session should resume");

        std::fs::write(&path, "v2\n").unwrap();
        resumed.snapshot_guidance_baseline(tmp.path()).await;
        assert!(
            resumed
                .guidance_change_injection(tmp.path())
                .await
                .is_none()
        );
        std::fs::write(&path, "v3\n").unwrap();
        assert!(
            resumed
                .guidance_change_injection(tmp.path())
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn snapshot_with_no_guidance_file_leaves_null_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        s.snapshot_guidance_baseline(tmp.path()).await;
        assert_eq!(s.db.guidance_baseline(s.id).await.unwrap(), None);
        // And no injection ever fires for such a session.
        assert!(s.guidance_change_injection(tmp.path()).await.is_none());
    }

    #[tokio::test]
    async fn in_place_edit_injects_unified_diff_then_is_idempotent() {
        let (s, tmp, path) =
            guidance_session("line one\nline two\nline three\nline four\nline five\n");
        s.snapshot_guidance_baseline(tmp.path()).await;
        // No change yet → no injection.
        assert!(s.guidance_change_injection(tmp.path()).await.is_none());

        // Edit one line in place.
        std::fs::write(
            &path,
            "line one\nline two\nline THREE\nline four\nline five\n",
        )
        .unwrap();
        let msg = s
            .guidance_change_injection(tmp.path())
            .await
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
            s.guidance_change_injection(tmp.path()).await.is_none(),
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
            .await
            .expect("a further change should inject");
        assert!(msg2.contains("+ line FOUR"), "second diff: {msg2}");
        // It diffs from the previously-injected version, so the first edit
        // ("THREE") is now context, not a `+` line.
        assert!(!msg2.contains("+ line THREE"), "second diff: {msg2}");
    }

    #[tokio::test]
    async fn near_total_rewrite_injects_full_contents_not_a_diff() {
        let (s, tmp, path) = guidance_session("alpha\nbeta\ngamma\ndelta\nepsilon\n");
        s.snapshot_guidance_baseline(tmp.path()).await;
        // Rewrite every line.
        std::fs::write(&path, "ALPHA\nBETA\nGAMMA\nDELTA\nEPSILON\n").unwrap();
        let msg = s
            .guidance_change_injection(tmp.path())
            .await
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

    #[tokio::test]
    async fn deleted_file_injects_nothing_and_does_not_error() {
        let (s, tmp, path) = guidance_session("RULES\n");
        s.snapshot_guidance_baseline(tmp.path()).await;
        std::fs::remove_file(&path).unwrap();
        // Out of scope: deletion is not an in-place change. No injection,
        // no error, and the baseline is left intact.
        assert!(s.guidance_change_injection(tmp.path()).await.is_none());
        assert!(s.db.guidance_baseline(s.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn switched_file_injects_nothing() {
        // Start with AGENTS.md as the resolved file.
        let (s, tmp, agents) = guidance_session("AGENTS RULES\n");
        s.snapshot_guidance_baseline(tmp.path()).await;
        // Delete AGENTS.md and add a project guidance — a *different* file now
        // wins. Out of scope: the baseline path no longer matches, so no
        // injection even though guidance content "changed".
        std::fs::remove_file(&agents).unwrap();
        std::fs::write(tmp.path().join("project guidance"), "CLAUDE RULES\n").unwrap();
        assert!(s.guidance_change_injection(tmp.path()).await.is_none());
    }

    #[tokio::test]
    async fn snapshot_is_recomputed_to_current_file_on_each_call() {
        // Mirrors a worker respawn (resume): re-snapshotting picks up the
        // current file as the new baseline, so a post-snapshot edit diffs
        // from the latest body.
        let (s, tmp, path) = guidance_session("v1\n");
        s.snapshot_guidance_baseline(tmp.path()).await;
        std::fs::write(&path, "v2\n").unwrap();
        s.snapshot_guidance_baseline(tmp.path()).await;
        // Baseline is now v2 → editing to v2 again is a no-op.
        assert!(s.guidance_change_injection(tmp.path()).await.is_none());
        // Editing to v3 injects, diffed from v2.
        std::fs::write(&path, "v3\n").unwrap();
        assert!(s.guidance_change_injection(tmp.path()).await.is_some());
    }

    #[test]
    fn replacement_workspace_at_the_same_path_gets_a_new_project_id() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let original = project_id_for(&workspace).unwrap();

        std::fs::rename(&workspace, temp.path().join("retired-workspace")).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        let replacement = project_id_for(&workspace).unwrap();

        assert_ne!(original, replacement);
    }

    #[test]
    fn workspace_contents_cannot_change_a_live_workspace_project_id() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let original = project_id_for(&workspace).unwrap();

        // Workspace contents are not identity input. Their modification and
        // cleanup must not detach a live workspace from its consent state.
        let untracked = workspace.join("repository-artifact");
        std::fs::write(&untracked, "edited by repository tooling").unwrap();
        assert_eq!(project_id_for(&workspace).unwrap(), original);
        std::fs::remove_file(untracked).unwrap();
        assert_eq!(project_id_for(&workspace).unwrap(), original);
    }
}
