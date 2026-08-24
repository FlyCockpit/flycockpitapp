//! Authoritative effective-default `active_model` mutation.
//!
//! One journaled, lock-held operation owns target-layer selection, the atomic
//! config write, reload verification, and the optional guarded session CAS. No
//! caller writes `active_model` through a lower-level helper: this module is
//! the only mutation API for the layer-wide default.
//!
//! # Durable commit boundary
//!
//! The fsynced `prepared` journal record is the commit boundary. Before it,
//! cancellation, a deadline, or any failure rejects with zero mutation. After
//! it, the transaction is owned by recovery: it converges either to both
//! authorities exposing the target reference or to both exposing their
//! recorded prior values, and only then produces a terminal result.
//!
//! # Who may finish a transaction
//!
//! A *config-only* journal can be finished by any configuration read. A
//! journal with a session participant can only be finished by a caller that
//! supplies [`SessionRevisionAuthority`] (daemon startup, attach, or the
//! driver's own Ctrl+Enter transaction). A reader without session authority
//! must neither compensate nor delete such a journal — it *masks* the layer
//! instead, serving the recorded prior bytes so a fresh client never observes
//! a half-committed default. See [`masked_layer_bytes`].
//!
//! # Durability ordering
//!
//! Each phase writes its record to a private temporary file, fsyncs that file,
//! renames it over the journal, and then fsyncs the *containing directory*
//! before the next phase begins. The rename is only durable once the directory
//! entry is; a file-content fsync alone would not survive a crash. Every
//! journal, backup, and config replacement in one transaction lives in that
//! same directory, so one directory fsync per phase orders all of them. On
//! Windows a directory handle cannot be flushed — see [`fsync_dir`] for what
//! is and is not guaranteed there.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::dirs::{
    COCKPIT_CONFIG_ENV, ConfigDir, ConfigDirKind, config_file_paths_for_load, discover_config_dirs,
};
use crate::config::files::{
    ConfigMutationLock, fsync_dir, prepare_atomic_write, read_file_nofollow, remove_file_nofollow,
    write_private_file,
};
use crate::config::providers::{ActiveModelRef, ActiveModelWriteMode, ConfigDoc, ProvidersConfig};

/// Journal and backup file names are keyed by a digest of the **config file**
/// path, not just its directory. An explicit `COCKPIT_CONFIG` target and a
/// conventional `config.json` can share one directory; unkeyed names would let
/// one transaction silently overwrite the other's pending journal or rollback
/// snapshot.
const JOURNAL_PREFIX: &str = ".cockpit-active-model-journal-";
const BACKUP_PREFIX: &str = ".cockpit-active-model-backup-";
const KEY_LEN: usize = 16;

/// Private temporary replacements older than this with no owning transaction
/// are swept. A real process kill between `prepare_atomic_write` and its
/// commit would otherwise leak one forever.
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Safe, non-secret label for the layer that owns the effective default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveDefaultScope {
    User,
    MachineLocal,
    Project,
    ExplicitOverride,
}

impl EffectiveDefaultScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::MachineLocal => "machine/local",
            Self::Project => "project",
            Self::ExplicitOverride => "explicit override",
        }
    }

    fn from_dir_kind(kind: &ConfigDirKind) -> Self {
        match kind {
            ConfigDirKind::HomeXdg | ConfigDirKind::HomeDot => Self::User,
            ConfigDirKind::MachineLocal => Self::MachineLocal,
            ConfigDirKind::Project => Self::Project,
        }
    }
}

/// Crash-injection seam for phase-boundary recovery tests.
///
/// Test-only: production builds contain no injection point at all.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveDefaultCrashPoint {
    AfterJournalPrepared,
    AfterPrivateReplacementPrepared,
    AfterSessionCas,
    AfterSessionCommittedMarker,
    AfterConfigReplaced,
    AfterCommittedMarker,
    AfterReloadVerified,
    AfterJournalCleanup,
    AfterCompensatingMarker,
    /// Compensation itself succeeds but the journal cannot be removed: the
    /// only route to a `recovery_pending` terminal state.
    FailJournalCleanup,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static CRASH_INJECT: std::cell::Cell<Option<EffectiveDefaultCrashPoint>> =
        const { std::cell::Cell::new(None) };
}

/// Install a one-shot crash-inject point for the current thread.
///
/// Test-support only. Enabled by this crate's own tests and by the
/// `test-support` feature, which only `cockpit-core`'s dev-dependencies turn
/// on so daemon-level tests can replay the same phase boundaries.
#[cfg(any(test, feature = "test-support"))]
pub fn set_crash_inject(point: Option<EffectiveDefaultCrashPoint>) {
    CRASH_INJECT.with(|cell| cell.set(point));
}

/// Simulate a process death at `point`: the journal, backup, and both
/// authorities are left exactly as an abrupt kill would leave them, and the
/// in-process transaction unwinds without any compensation.
#[cfg(any(test, feature = "test-support"))]
fn simulate_crash(point: EffectiveDefaultCrashPoint) -> bool {
    CRASH_INJECT.with(|cell| {
        if cell.get() == Some(point) {
            cell.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(not(any(test, feature = "test-support")))]
macro_rules! crash_point {
    ($scope:expr, $point:ident) => {};
}

#[cfg(any(test, feature = "test-support"))]
macro_rules! crash_point {
    ($scope:expr, $point:ident) => {
        if simulate_crash(EffectiveDefaultCrashPoint::$point) {
            return Err(EffectiveDefaultError::simulated_crash($scope));
        }
    };
}

#[cfg(not(any(test, feature = "test-support")))]
macro_rules! crash_point_bail {
    ($point:ident) => {};
}

#[cfg(any(test, feature = "test-support"))]
macro_rules! crash_point_bail {
    ($point:ident) => {
        if simulate_crash(EffectiveDefaultCrashPoint::$point) {
            anyhow::bail!("simulated crash at {}", stringify!($point));
        }
    };
}

/// Durable session-model authority used by the coordinator and by recovery.
///
/// Every mutation is a compare-and-swap against `active_model_revision`: a
/// zero-row result is a concurrent conflict, never permission to overwrite.
pub trait SessionRevisionAuthority {
    /// The single session this authority may act on, when it is bound to one.
    ///
    /// A driver-scoped authority can only ever touch its own session row. The
    /// journal engine refuses to compensate a transaction whose recorded
    /// session is not this one, so a stale journal can never write session
    /// `X`'s prior model into session `Y`. An unbound authority (the daemon's
    /// SQLite one) returns `None` and validates row existence instead.
    fn bound_session_id(&self) -> Option<Uuid> {
        None
    }

    /// Current durable revision, or `None` when the session row is gone.
    fn current_revision(&mut self, session_id: Uuid) -> Result<Option<i64>>;

    /// CAS the durable session model. `Ok(false)` means the guard revision no
    /// longer matches and nothing was written.
    fn cas_set_active_model(
        &mut self,
        session_id: Uuid,
        expected_revision: i64,
        selection: &ActiveModelRef,
    ) -> Result<bool>;
}

/// Sink for a transaction a recovery pass converged.
///
/// Called **before** the journal is deleted. Returning `Err` aborts cleanup so
/// the transaction stays recoverable — a terminal result that cannot be
/// handed off must never be dropped on the floor.
pub trait RecoveredSink {
    fn accept(&mut self, transaction: &RecoveredTransaction) -> Result<()>;
}

impl<F> RecoveredSink for F
where
    F: FnMut(&RecoveredTransaction) -> Result<()>,
{
    fn accept(&mut self, transaction: &RecoveredTransaction) -> Result<()> {
        self(transaction)
    }
}

/// What a recovery pass is permitted and equipped to do.
///
/// Two capabilities gate convergence, and a journal is left strictly alone
/// unless the pass has the one it needs:
///
/// - a **session participant** needs [`SessionRevisionAuthority`];
/// - a **correlated** transaction (a client is waiting for exactly one
///   terminal event) needs a [`RecoveredSink`] to hand that event to.
///
/// A plain configuration read has neither, so it never converges either kind —
/// it masks the layer instead. Only daemon startup and attach supply both.
/// `'a` is the borrow of the capabilities; `'o` is the lifetime of the values
/// behind them. Keeping them separate makes the struct covariant in `'a`, so
/// [`Self::reborrow`] can hand a shorter-lived view to each loop iteration.
pub struct JournalRecovery<'a, 'o: 'a> {
    sessions: Option<&'a mut (dyn SessionRevisionAuthority + 'o)>,
    sink: Option<&'a mut (dyn RecoveredSink + 'o)>,
    /// Explicit recovery attempts (mutation, attach, startup) always do the
    /// work; passive configuration reads may be served from the negative
    /// cache. The cache never changes the *result*, only whether the work is
    /// repeated.
    forced: bool,
}

impl<'a, 'o: 'a> JournalRecovery<'a, 'o> {
    /// A passive configuration read: converges nothing that anyone is waiting
    /// on, and honours the negative cache.
    pub fn read_only() -> Self {
        Self {
            sessions: None,
            sink: None,
            forced: false,
        }
    }

    pub fn with_sessions(sessions: &'a mut (dyn SessionRevisionAuthority + 'o)) -> Self {
        Self {
            sessions: Some(sessions),
            sink: None,
            forced: true,
        }
    }

    pub fn with_sink(mut self, sink: &'a mut (dyn RecoveredSink + 'o)) -> Self {
        self.sink = Some(sink);
        self
    }

    fn reborrow(&mut self) -> JournalRecovery<'_, 'o> {
        JournalRecovery {
            sessions: self.sessions.as_deref_mut(),
            sink: self.sink.as_deref_mut(),
            forced: self.forced,
        }
    }
}

/// Session participant for a session+default transaction.
pub struct SessionDefaultParticipant<'a> {
    pub session_id: Uuid,
    pub prior: ActiveModelRef,
    pub expected_revision: i64,
    pub authority: &'a mut dyn SessionRevisionAuthority,
}

/// The caller-owned identity a terminal result must be correlated to.
///
/// Recorded in the journal so a transaction this process could not finish
/// still produces exactly one correlated terminal event, emitted by whichever
/// recovery pass does finish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransactionCorrelation {
    /// `/model` Ctrl+Enter — terminal `ModelSelectionResult`.
    ModelSelection {
        selection_id: Uuid,
        session_id: Uuid,
    },
    /// `SetDefaultModel` — terminal `DefaultModelUpdateResult`.
    DefaultUpdate {
        default_update_id: Uuid,
        session_id: Uuid,
    },
}

impl TransactionCorrelation {
    pub fn session_id(&self) -> Uuid {
        match self {
            Self::ModelSelection { session_id, .. } | Self::DefaultUpdate { session_id, .. } => {
                *session_id
            }
        }
    }
}

/// How a recovery pass finished a transaction the originating process could
/// not complete. The caller emits the matching correlated terminal event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveredOutcome {
    /// Both durable authorities now hold the requested reference.
    Applied {
        selection: Option<ActiveModelRef>,
        generation: u64,
    },
    /// The config default was verifiably returned to its prior value. What
    /// happened to the *session* half is reported separately, because
    /// claiming "the session model was restored" when it was never touched
    /// (or when the row is gone) would be untrue.
    Restored {
        restored: Option<ActiveModelRef>,
        session: SessionCompensation,
    },
}

/// What compensation did to the session half of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCompensation {
    /// Config-only transaction: there was never a session participant.
    NotApplicable,
    /// The guarded CAS had not run, so the session model never changed.
    Untouched,
    /// The committed CAS was reverted to the recorded prior model.
    Reverted,
    /// A previous pass had already reverted it.
    AlreadyReverted,
    /// The session row no longer exists; there was nothing to restore.
    SessionGone,
}

impl SessionCompensation {
    /// Non-secret phrase describing the session half, for terminal messages.
    pub fn describe(self) -> &'static str {
        match self {
            Self::NotApplicable => "no session was involved",
            Self::Untouched => "the session model was never changed",
            Self::Reverted | Self::AlreadyReverted => "the session model was restored",
            Self::SessionGone => "the session no longer exists",
        }
    }
}

/// A transaction a recovery pass converged, with the identity its terminal
/// event must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredTransaction {
    pub correlation: TransactionCorrelation,
    pub outcome: RecoveredOutcome,
    pub scope_label: String,
    /// The reference the transaction requested, for terminal-event rendering.
    pub requested: Option<ActiveModelRef>,
}

/// Non-secret description of a pending journal, for `cockpit doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalDiagnostic {
    /// Path of the journal file itself. Repairing it is a local-owner action,
    /// so the path is actionable and carries no configuration content.
    pub journal_path: PathBuf,
    pub scope_label: String,
    /// `prepared` | `session_committed` | `committed` | `compensating` |
    /// `unreadable`.
    pub phase: &'static str,
    pub transaction_id: Uuid,
    /// True when the journal carries a session participant and therefore needs
    /// a running daemon (session authority) to finish.
    pub needs_session_authority: bool,
    /// True when a client is waiting for exactly one terminal event. Only a
    /// pass that can deliver that event may converge it, so an ordinary
    /// configuration read will never finish it.
    pub correlated: bool,
    /// True when the record could not be parsed or does not belong here.
    pub out_of_context: bool,
}

/// Verified result of an effective-default mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveDefaultMutationResult {
    /// The effective default proven by the post-commit reload. For a clear
    /// this is the deterministic inherited default (or `None`).
    pub selection: Option<ActiveModelRef>,
    pub generation: u64,
    pub scope_label: String,
    /// True when a concrete layer write was performed.
    pub wrote: bool,
    /// True when the effective default already matched and no bytes changed.
    pub unchanged: bool,
}

/// Typed rejection for effective-default mutation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveDefaultError {
    pub user_message: String,
    pub diagnostic_code: &'static str,
    pub scope_label: Option<String>,
    /// True when the failure happened after the durable commit boundary and
    /// compensation verifiably restored both authorities to their prior
    /// values. The journal is gone, so no later recovery can expose the
    /// target: this is a legitimate terminal rejection.
    pub restored_after_boundary: bool,
    /// True when the transaction crossed the durable commit boundary and this
    /// process could prove **neither** outcome.
    ///
    /// This is *not* a terminal result. The journal and its private backup are
    /// retained, the caller must emit no terminal event and must not claim the
    /// terminal slot, and the next recovery pass with session authority
    /// converges the transaction and emits the correlated terminal event.
    pub recovery_pending: bool,
}

impl EffectiveDefaultError {
    fn new(
        user_message: impl Into<String>,
        diagnostic_code: &'static str,
        scope_label: Option<String>,
    ) -> Self {
        Self {
            user_message: user_message.into(),
            diagnostic_code,
            scope_label,
            restored_after_boundary: false,
            recovery_pending: false,
        }
    }

    fn restored(scope_label: &str, cause: &str, session: SessionCompensation) -> Self {
        Self {
            user_message: format!(
                "The default model was not changed — {cause}. The previous default was restored and {}.",
                session.describe()
            ),
            diagnostic_code: "effective_default_restored_after_boundary",
            scope_label: Some(scope_label.to_string()),
            restored_after_boundary: true,
            recovery_pending: false,
        }
    }

    fn pending(scope_label: &str, cause: &str) -> Self {
        Self {
            user_message: format!(
                "The default model update is still in progress — {cause}. Recovery finishes it at the next daemon start or attach."
            ),
            diagnostic_code: "effective_default_recovery_pending",
            scope_label: Some(scope_label.to_string()),
            restored_after_boundary: false,
            recovery_pending: true,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn simulated_crash(scope_label: &str) -> Self {
        Self::new(
            "default model update interrupted by a simulated crash",
            "effective_default_simulated_crash",
            Some(scope_label.to_string()),
        )
    }

    pub fn into_anyhow(self) -> anyhow::Error {
        anyhow!("{} ({})", self.user_message, self.diagnostic_code)
    }
}

impl std::fmt::Display for EffectiveDefaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.user_message)
    }
}

impl std::error::Error for EffectiveDefaultError {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Prepared,
    SessionCommitted,
    Committed,
    /// Compensation has begun. Recorded **before** the guarded session revert
    /// so a crash mid-revert is resumable: the session may be at
    /// `expected_revision + 1` (revert not applied) or `+ 2` (applied).
    /// Without this marker a re-run would see `+ 2`, call it an unexpected
    /// revision, and refuse forever — bricking recovery and, with it, attach.
    Compensating,
}

impl JournalPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::SessionCommitted => "session_committed",
            Self::Committed => "committed",
            Self::Compensating => "compensating",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JournalSession {
    /// Config-only transaction (`SetDefaultModel`, settings, wizard).
    None,
    Session {
        session_id: Uuid,
        prior: ActiveModelRef,
        target: ActiveModelRef,
        expected_revision: i64,
    },
}

/// Metadata-only journal record. It carries identifiers, digests, and model
/// references — never raw configuration bytes, credentials, or the rollback
/// snapshot itself (which lives in a separate private `0600` sibling).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct JournalRecord {
    transaction_id: Uuid,
    /// Project root this transaction resolved under (its trust context).
    project_root: String,
    trust_mode: Option<String>,
    scope: EffectiveDefaultScope,
    /// Digest of the absolute target path; the raw path is never in metadata.
    target_path_digest: String,
    old_config_digest: String,
    new_config_digest: String,
    /// Value written into the target layer (`None` clears it).
    requested: Option<ActiveModelRef>,
    /// Effective default the post-commit reload must resolve to. Equals
    /// `requested` for a replace and the deterministic inherited default for a
    /// clear.
    expected_effective: Option<ActiveModelRef>,
    session: JournalSession,
    /// Terminal-event identity, when a caller is waiting for one.
    #[serde(default)]
    correlation: Option<TransactionCorrelation>,
    phase: JournalPhase,
}

impl JournalRecord {
    fn session_participant(&self) -> Option<(Uuid, &ActiveModelRef, i64)> {
        match &self.session {
            JournalSession::None => None,
            JournalSession::Session {
                session_id,
                prior,
                expected_revision,
                ..
            } => Some((*session_id, prior, *expected_revision)),
        }
    }

    fn needs_session_authority(&self) -> bool {
        matches!(self.session, JournalSession::Session { .. })
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub path: PathBuf,
    pub scope: EffectiveDefaultScope,
    /// Load-ordered config paths strictly below the target layer. Clearing the
    /// target resolves the inherited default from exactly these.
    lower_paths: Vec<PathBuf>,
}

impl ResolvedTarget {
    pub fn scope_label(&self) -> String {
        self.scope.as_str().to_string()
    }
}

/// Resolve the sole legal write target for the effective default in `cwd`.
///
/// The target is the highest-precedence layer that governs future-session
/// resolution — the last entry of [`config_file_paths_for_load`], so a layer
/// attach would not read is never written. If that layer is missing,
/// unwritable, untrusted, or otherwise ineligible this rejects; it never falls
/// back to a lower-precedence layer.
pub fn resolve_effective_default_write_target(
    cwd: &Path,
) -> Result<ResolvedTarget, EffectiveDefaultError> {
    let explicit = std::env::var_os(COCKPIT_CONFIG_ENV).filter(|value| !value.is_empty());
    let mut paths = config_file_paths_for_load(cwd);
    let Some(path) = paths.pop() else {
        return if explicit.is_some() {
            Err(EffectiveDefaultError::new(
                "explicit COCKPIT_CONFIG is not readable or writable under the current trust policy",
                "effective_default_trust_denied",
                Some(EffectiveDefaultScope::ExplicitOverride.as_str().to_string()),
            ))
        } else {
            Err(EffectiveDefaultError::new(
                "no cockpit config layer applies here — run `/settings` or `/setup` to create one",
                "effective_default_no_layer",
                None,
            ))
        };
    };
    let scope = if explicit.is_some() {
        EffectiveDefaultScope::ExplicitOverride
    } else {
        scope_for_config_path(cwd, &path)
    };
    let scope_label = scope.as_str().to_string();

    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Err(EffectiveDefaultError::new(
            format!(
                "the highest-precedence config layer ({scope_label}) has no directory to write into"
            ),
            "effective_default_target_missing",
            Some(scope_label),
        ));
    };
    if !parent.is_dir() {
        return Err(EffectiveDefaultError::new(
            format!("the highest-precedence config layer ({scope_label}) is missing"),
            "effective_default_target_missing",
            Some(scope_label),
        ));
    }
    Ok(ResolvedTarget {
        path,
        scope,
        lower_paths: paths,
    })
}

/// Prove the resolved target really accepts a replacement from this process.
///
/// Separate from resolution because it *writes*: inspection surfaces
/// (`cockpit models`, the `/settings` scope label) resolve only, while every
/// mutation probes before it touches the durable commit boundary. A permission
/// *bit* check is not a writability check — `Permissions::readonly()` only
/// reflects the owner-write bit, so a root-owned `0755` directory reads as
/// writable and a group-writable one reads as read-only.
fn ensure_target_writable(target: &ResolvedTarget) -> Result<(), EffectiveDefaultError> {
    let scope_label = target.scope_label();
    let parent = config_parent(&target.path);
    if let Err(error) = probe_directory_writable(parent) {
        return Err(EffectiveDefaultError::new(
            safe_cause_owned(
                format!("the highest-precedence config layer ({scope_label}) is not writable"),
                &error,
            ),
            "effective_default_target_unwritable",
            Some(scope_label),
        ));
    }
    if target.path.exists() && !file_is_writable(&target.path) {
        return Err(EffectiveDefaultError::new(
            format!("the highest-precedence config.json ({scope_label}) is not writable"),
            "effective_default_target_unwritable",
            Some(scope_label),
        ));
    }
    Ok(())
}

/// Create and remove a private probe file to prove the directory really
/// accepts a replacement from this process.
fn probe_directory_writable(dir: &Path) -> Result<()> {
    let probe = dir.join(format!(
        ".cockpit-write-probe-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default(),
        Uuid::new_v4(),
    ));
    write_private_file(&probe, b"")?;
    let _ = remove_file_nofollow(&probe);
    Ok(())
}

fn file_is_writable(path: &Path) -> bool {
    std::fs::OpenOptions::new().append(true).open(path).is_ok()
}

fn scope_for_config_path(cwd: &Path, path: &Path) -> EffectiveDefaultScope {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    discover_config_dirs(cwd)
        .iter()
        .find(|dir: &&ConfigDir| dir.path == parent)
        .map(|dir| EffectiveDefaultScope::from_dir_kind(&dir.kind))
        .unwrap_or(EffectiveDefaultScope::Project)
}

/// Log the full diagnostic locally and return a short, path-free summary.
///
/// Terminal events, traces, and remote-visible diagnostics only ever carry the
/// summary: no filesystem path, config body, or credential can leak through an
/// effective-default rejection.
fn safe_cause(summary: &'static str, error: &anyhow::Error) -> String {
    tracing::warn!(%error, summary, "effective-default transaction failure");
    summary.to_string()
}

fn safe_cause_owned(summary: String, error: &anyhow::Error) -> String {
    tracing::warn!(%error, summary, "effective-default transaction failure");
    summary
}

fn path_digest(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hex_digest(hasher.finalize())
}

fn bytes_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(hasher.finalize())
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;

    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Stable per-config-file key so two config files sharing a directory never
/// share a journal or rollback snapshot.
///
/// Keyed on the *canonical* path: two spellings of one file (a relative path,
/// a `..` segment, a symlinked ancestor) must produce one key, or the
/// foreign-journal gate would not see the other spelling's pending
/// transaction and would clobber it.
fn config_key(config_path: &Path) -> String {
    path_digest(&canonical_config_path(config_path))[..KEY_LEN].to_string()
}

/// Best-effort canonical form. The config file itself may not exist yet, so
/// the parent directory is canonicalized (resolving symlinked ancestors) and
/// the file name re-joined. Falls back to lexical absolutization.
fn canonical_config_path(config_path: &Path) -> PathBuf {
    let absolute = std::path::absolute(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) else {
        return absolute;
    };
    match std::fs::canonicalize(parent) {
        Ok(parent) => parent.join(name),
        Err(_) => absolute,
    }
}

fn journal_path_for_config(config_path: &Path) -> PathBuf {
    config_parent(config_path).join(format!("{JOURNAL_PREFIX}{}.json", config_key(config_path)))
}

fn backup_path_for_config(config_path: &Path) -> PathBuf {
    config_parent(config_path).join(format!("{BACKUP_PREFIX}{}", config_key(config_path)))
}

fn config_parent(config_path: &Path) -> &Path {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Config bytes as they exist on disk. An absent file is the empty object so
/// digests stay stable across "create" and "replace".
fn read_config_bytes(path: &Path) -> Result<Vec<u8>> {
    Ok(read_file_nofollow(path)?.unwrap_or_else(|| b"{}\n".to_vec()))
}

fn write_journal(path: &Path, record: &JournalRecord) -> Result<()> {
    let pretty = serde_json::to_string_pretty(record).context("serializing journal")?;
    write_private_file(path, format!("{pretty}\n").as_bytes())?;
    // The rename is only durable once the containing directory is synced.
    fsync_dir(config_parent(path))?;
    Ok(())
}

fn load_journal(path: &Path) -> Result<Option<JournalRecord>> {
    let Some(raw) = read_file_nofollow(path)? else {
        return Ok(None);
    };
    let record: JournalRecord = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing journal {}", path.display()))?;
    Ok(Some(record))
}

/// Build the exact replacement bytes for `config_bytes` with `requested`
/// applied. Deterministic, so recovery can reproduce the committed content
/// from the private backup and check it against `new_config_digest`.
fn replacement_bytes(config_bytes: &[u8], requested: Option<&ActiveModelRef>) -> Result<Vec<u8>> {
    let mut raw: serde_json::Value = if config_bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice(config_bytes).context("parsing config.json")?
    };
    let Some(object) = raw.as_object_mut() else {
        anyhow::bail!("config.json root must be an object");
    };
    match requested {
        Some(active) => {
            let value = serde_json::to_value(active).context("serializing active_model")?;
            object.insert("active_model".to_string(), value);
        }
        None => {
            object.remove("active_model");
        }
    }
    let pretty = serde_json::to_string_pretty(&raw).context("serializing config.json")?;
    Ok(format!("{pretty}\n").into_bytes())
}

/// Effective default that would remain if the target layer stopped declaring
/// one: the merge of every layer strictly below it.
fn inherited_default(lower_paths: &[PathBuf]) -> Option<ActiveModelRef> {
    if lower_paths.is_empty() {
        return None;
    }
    // A pending transaction on a lower layer must not decide what a clear
    // inherits, so these reads are masked like every other resolution.
    let masks = masked_layer_bytes(lower_paths);
    ConfigDoc::providers_from_paths_with_masks(lower_paths, &masks).active_model
}

/// Reject a clear that would expose a provider/model the effective config
/// cannot resolve. A deterministic *absent* default is allowed; a dangling one
/// is not.
fn validate_inherited_default(
    inherited: Option<&ActiveModelRef>,
    effective: &ProvidersConfig,
    scope_label: &str,
) -> Result<(), EffectiveDefaultError> {
    let Some(inherited) = inherited else {
        return Ok(());
    };
    let Some(provider) = effective.providers.get(&inherited.provider) else {
        return Err(EffectiveDefaultError::new(
            format!(
                "clearing the {scope_label} default would inherit `{}/{}`, whose provider is not configured",
                inherited.provider, inherited.model
            ),
            "effective_default_clear_exposes_invalid",
            Some(scope_label.to_string()),
        ));
    };
    if !provider.models.is_empty()
        && !provider
            .models
            .iter()
            .any(|model| model.id == inherited.model)
    {
        return Err(EffectiveDefaultError::new(
            format!(
                "clearing the {scope_label} default would inherit `{}/{}`, which its provider does not list",
                inherited.provider, inherited.model
            ),
            "effective_default_clear_exposes_invalid",
            Some(scope_label.to_string()),
        ));
    }
    Ok(())
}

// ---- Context validation ----------------------------------------------------

/// Reject a journal that does not belong to this config file, this project
/// root, or the current trust policy. Fails closed: an out-of-context journal
/// is never applied and never deleted.
fn journal_context_error(record: &JournalRecord, config_path: &Path) -> Option<&'static str> {
    if record.target_path_digest != path_digest(&canonical_config_path(config_path)) {
        return Some("journal target path digest does not match this config file");
    }
    if record.project_root.is_empty() || !Path::new(&record.project_root).is_absolute() {
        return Some("journal project root is missing or not absolute");
    }
    // A project layer workspace trust no longer allows must not be rewritten
    // by recovery, exactly as attach would not read it.
    let parent = config_parent(config_path);
    if parent.file_name().is_some_and(|name| name == ".cockpit")
        && !crate::config::trust::project_config_write_allowed(parent)
    {
        return Some("journal target layer is no longer allowed by workspace trust");
    }
    if matches!(record.scope, EffectiveDefaultScope::Project)
        && let Some(recorded) = record.trust_mode.as_deref()
        && let Some(current) = crate::config::trust::current_workspace_trust_policy()
        && current.mode.as_str() != recorded
    {
        return Some("journal was written under a different workspace trust mode");
    }
    None
}

// ---- Recovery --------------------------------------------------------------

/// Recover any pending effective-default journal beside `config_path`.
///
/// Idempotent, and safe to call from startup, attach, and any configuration
/// read. A journal with a session participant is only *processed* when
/// `sessions` supplies durable session authority; without it the journal is
/// left completely untouched (no compensation, no deletion) and the layer is
/// masked by [`masked_layer_bytes`] instead.
pub fn recover_effective_default_journal(
    config_path: &Path,
    recovery: JournalRecovery<'_, '_>,
) -> Result<Vec<RecoveredTransaction>> {
    let layer = [config_path.to_path_buf()];
    recover_layer_journals(&layer, recovery)
}

/// Recover journals for every config layer that applies to `cwd`.
///
/// Prefer [`recover_layer_journals`] on hot paths that already know the layer
/// list — this variant repeats layer discovery.
pub fn recover_all_effective_default_journals(
    cwd: &Path,
    recovery: JournalRecovery<'_, '_>,
) -> Result<Vec<RecoveredTransaction>> {
    recover_layer_journals(&config_file_paths_for_load(cwd), recovery)
}

thread_local! {
    /// Directories whose stale-temporary scan already ran on this thread.
    static SWEPT_DIRECTORIES: std::cell::RefCell<std::collections::HashSet<PathBuf>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

thread_local! {
    /// mtime-keyed negative cache for *passive* configuration reads.
    ///
    /// It suppresses duplicate **work**, never changes the **result**: a hit
    /// replays the recorded failure, so a caller behind an unconverged
    /// journal still fails closed instead of seeing a clean `Ok`. Explicit
    /// recovery attempts (mutation, attach, startup) set
    /// [`JournalRecovery::forced`] and bypass it entirely, so a journal that
    /// became convergeable without its mtime changing is never stuck.
    static FAILED_RECOVERIES: std::cell::RefCell<HashMap<PathBuf, (Option<std::time::SystemTime>, String)>> =
        std::cell::RefCell::new(HashMap::new());
}

fn journal_mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::symlink_metadata(path)
        .ok()
        .and_then(|meta| meta.modified().ok())
}

/// The recorded failure for an unchanged journal, if this thread already
/// tried and failed. Replayed verbatim so the caller's outcome is identical.
fn cached_recovery_failure(journal_path: &Path) -> Option<String> {
    let mtime = journal_mtime(journal_path);
    FAILED_RECOVERIES.with(|cache| {
        cache
            .borrow()
            .get(journal_path)
            .filter(|(recorded, _)| *recorded == mtime)
            .map(|(_, message)| message.clone())
    })
}

fn note_recovery_failure(journal_path: &Path, error: &anyhow::Error) {
    let mtime = journal_mtime(journal_path);
    FAILED_RECOVERIES.with(|cache| {
        cache
            .borrow_mut()
            .insert(journal_path.to_path_buf(), (mtime, format!("{error:#}")));
    });
}

fn clear_recovery_failure(journal_path: &Path) {
    FAILED_RECOVERIES.with(|cache| {
        cache.borrow_mut().remove(journal_path);
    });
}

#[cfg(test)]
pub(crate) fn reset_recovery_backoff_for_tests() {
    FAILED_RECOVERIES.with(|cache| cache.borrow_mut().clear());
    SWEPT_DIRECTORIES.with(|swept| swept.borrow_mut().clear());
}

/// Recover journals for an already-discovered layer list.
///
/// Hot config reads pass the paths they already resolved so layer discovery
/// happens exactly once per load.
pub fn recover_layer_journals(
    paths: &[PathBuf],
    mut recovery: JournalRecovery<'_, '_>,
) -> Result<Vec<RecoveredTransaction>> {
    let mut recovered = Vec::new();
    let mut first_error: Option<anyhow::Error> = None;
    for path in paths {
        let journal_path = journal_path_for_config(path);
        // Fast path: no journal file means no recovery work, so an ordinary
        // config read never pays for the cross-process lock. It is still the
        // right place to sweep crash-window debris: an orphan backup or a
        // stale temporary replacement with no owning journal can only come
        // from a process that was killed mid-transaction.
        if !journal_path.exists() {
            sweep_orphans(path);
            continue;
        }
        if !recovery.forced
            && let Some(cached) = cached_recovery_failure(&journal_path)
        {
            // Replay, never downgrade to success.
            if first_error.is_none() {
                first_error = Some(anyhow!("{cached}"));
            }
            continue;
        }
        match recover_one(path, recovery.reborrow()) {
            Ok(mut done) => {
                clear_recovery_failure(&journal_path);
                recovered.append(&mut done);
            }
            Err(error) => {
                note_recovery_failure(&journal_path, &error);
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(recovered),
    }
}

fn recover_one(
    config_path: &Path,
    recovery: JournalRecovery<'_, '_>,
) -> Result<Vec<RecoveredTransaction>> {
    if load_journal(&journal_path_for_config(config_path))?.is_none() {
        return Ok(Vec::new());
    }
    if ConfigMutationLock::is_held_by_current_thread() {
        return recover_under_lock(config_path, recovery);
    }
    let _lock = ConfigMutationLock::acquire(config_path)?;
    recover_under_lock(config_path, recovery)
}

fn recover_under_lock(
    config_path: &Path,
    mut recovery: JournalRecovery<'_, '_>,
) -> Result<Vec<RecoveredTransaction>> {
    let journal_path = journal_path_for_config(config_path);
    // Re-read under the lock: another process may have finished already.
    let Some(record) = load_journal(&journal_path)? else {
        sweep_orphans(config_path);
        return Ok(Vec::new());
    };
    if let Some(reason) = journal_context_error(&record, config_path) {
        // Fail closed: never apply, never delete.
        tracing::error!(
            transaction_id = %record.transaction_id,
            reason,
            "refusing an out-of-context effective-default journal; run `cockpit doctor` to inspect it"
        );
        return Ok(Vec::new());
    }
    // A session-bearing journal needs session authority; a correlated one
    // needs somewhere to hand its exactly-once terminal event. A pass without
    // the required capability leaves the journal *entirely* alone — the layer
    // is masked on read instead, so no client sees a half-committed default
    // and no terminal event is converged into oblivion.
    if record.needs_session_authority() && recovery.sessions.is_none() {
        tracing::debug!(
            transaction_id = %record.transaction_id,
            "leaving a session-bearing effective-default journal for a daemon recovery pass"
        );
        return Ok(Vec::new());
    }
    if record.correlation.is_some() && recovery.sink.is_none() {
        tracing::debug!(
            transaction_id = %record.transaction_id,
            "leaving a correlated effective-default journal for a pass that can deliver its terminal event"
        );
        return Ok(Vec::new());
    }
    // A bound authority may only touch its own session row.
    if let Some((journal_session, _, _)) = record.session_participant()
        && let Some(sessions) = recovery.sessions.as_deref_mut()
        && let Some(bound) = sessions.bound_session_id()
        && bound != journal_session
    {
        tracing::debug!(
            transaction_id = %record.transaction_id,
            "refusing to touch another session's effective-default journal"
        );
        return Ok(Vec::new());
    }

    let backup_path = backup_path_for_config(config_path);
    let scope_label = record.scope.as_str().to_string();
    // From `session_committed` onward the session already holds the target (or
    // there is no session), so finishing the recorded commit is the
    // deterministic outcome. `prepared` and `compensating` converge backwards.
    let forward = matches!(
        record.phase,
        JournalPhase::SessionCommitted | JournalPhase::Committed
    );

    if forward {
        match finish_config_from_journal(config_path, &record, &backup_path) {
            // Writing the recorded bytes is not proof: a higher-precedence
            // layer may have changed out of band between the crash and now.
            // Re-resolve in the recorded project context and only claim
            // `Applied` when the effective default really is the target.
            Ok(()) => match verify_recorded_target_layer(&record, config_path) {
                Ok((effective, generation)) => {
                    if record.phase != JournalPhase::Committed {
                        let mut committed = record.clone();
                        committed.phase = JournalPhase::Committed;
                        write_journal(&journal_path, &committed)?;
                    }
                    // `selection` is what the merged configuration actually
                    // resolves to, so a higher-precedence layer that changed
                    // meanwhile surfaces as divergence in the terminal event
                    // rather than a false claim.
                    let transaction = record.correlation.map(|correlation| RecoveredTransaction {
                        correlation,
                        outcome: RecoveredOutcome::Applied {
                            selection: effective.clone(),
                            generation,
                        },
                        scope_label: scope_label.clone(),
                        requested: record.requested.clone(),
                    });
                    // Hand the terminal event off *before* the journal is
                    // removed, so a delivery failure keeps it recoverable.
                    if let (Some(transaction), Some(sink)) =
                        (transaction.as_ref(), recovery.sink.as_deref_mut())
                    {
                        sink.accept(transaction)?;
                    }
                    finish_journal(config_path, &journal_path, &backup_path)?;
                    return Ok(transaction.into_iter().collect());
                }
                Err(error) => {
                    // Fail closed: the journal stays, and nothing claims
                    // success. A later pass re-evaluates.
                    return Err(error.context(
                        "effective-default recovery could not verify the committed default",
                    ));
                }
            },
            Err(error) => {
                tracing::warn!(
                    %error,
                    transaction_id = %record.transaction_id,
                    "could not finish the effective-default config commit; compensating to the recorded prior values"
                );
            }
        }
    }

    let session_outcome = compensate(
        config_path,
        &journal_path,
        &backup_path,
        &record,
        recovery.sessions.as_deref_mut(),
    )?;
    let transaction = record.correlation.map(|correlation| RecoveredTransaction {
        correlation,
        outcome: RecoveredOutcome::Restored {
            restored: effective_active_model_on_disk(config_path),
            session: session_outcome,
        },
        scope_label,
        requested: record.requested.clone(),
    });
    if let (Some(transaction), Some(sink)) = (transaction.as_ref(), recovery.sink.as_deref_mut()) {
        sink.accept(transaction)?;
    }
    finish_journal(config_path, &journal_path, &backup_path)?;
    Ok(transaction.into_iter().collect())
}

/// Prove the transaction's own authority landed, and report what the merged
/// configuration now resolves to.
///
/// The layer this transaction owns is the only thing it can be held to: its
/// bytes must be exactly the recorded committed content. The *merged* value
/// can legitimately differ if a higher-precedence layer changed between the
/// crash and now — that is divergence to report, not a recovery failure.
/// Treating it as an error would wedge recovery, and with it attach, for the
/// whole project root with no repair path.
fn verify_recorded_target_layer(
    record: &JournalRecord,
    config_path: &Path,
) -> Result<(Option<ActiveModelRef>, u64)> {
    let current = read_config_bytes(config_path)?;
    if bytes_digest(&current) != record.new_config_digest {
        anyhow::bail!(
            "the target layer does not hold the recorded committed content after convergence"
        );
    }
    let project_root = PathBuf::from(&record.project_root);
    // Exclude this layer from masking: its journal is still on disk and it is
    // the very transaction being finished.
    let effective = ConfigDoc::load_effective_masked_except(&project_root, Some(config_path));
    Ok((
        effective.active_model,
        effective.resolution_generation.max(1),
    ))
}

/// Best-effort read of the default the layer now exposes, for terminal-event
/// rendering only. Never fails the restoration.
fn effective_active_model_on_disk(config_path: &Path) -> Option<ActiveModelRef> {
    read_file_nofollow(config_path)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|raw| raw.get("active_model").cloned())
        .and_then(|value| serde_json::from_value::<ActiveModelRef>(value).ok())
}

/// Bring the config file to the exact recorded committed content.
///
/// Fails closed — without writing — when the on-disk bytes are neither the
/// recorded prior nor the recorded committed content, or when the private
/// backup cannot reproduce the committed digest.
fn finish_config_from_journal(
    config_path: &Path,
    record: &JournalRecord,
    backup_path: &Path,
) -> Result<()> {
    let current = read_config_bytes(config_path)?;
    let current_digest = bytes_digest(&current);
    if current_digest == record.new_config_digest {
        return Ok(());
    }
    if current_digest != record.old_config_digest {
        anyhow::bail!(
            "config digest is neither the recorded prior nor the recorded committed content; refusing to overwrite a concurrent change"
        );
    }
    let Some(prior) = read_file_nofollow(backup_path)? else {
        anyhow::bail!("the private rollback snapshot is missing");
    };
    if bytes_digest(&prior) != record.old_config_digest {
        anyhow::bail!("the private rollback snapshot does not match the recorded prior digest");
    }
    let rebuilt = replacement_bytes(&prior, record.requested.as_ref())?;
    if bytes_digest(&rebuilt) != record.new_config_digest {
        anyhow::bail!("the reconstructed replacement does not match the recorded committed digest");
    }
    prepare_atomic_write(config_path, &rebuilt)?.commit()?;
    fsync_dir(config_parent(config_path))?;
    Ok(())
}

/// Restore both authorities to their recorded prior values.
///
/// Records the `compensating` phase **before** touching the session so a crash
/// mid-revert is resumable: a re-run recognizes both `expected_revision + 1`
/// (revert not applied) and `+ 2` (already applied) and finishes the config
/// half instead of refusing forever.
fn compensate(
    config_path: &Path,
    journal_path: &Path,
    backup_path: &Path,
    record: &JournalRecord,
    sessions: Option<&mut (dyn SessionRevisionAuthority + '_)>,
) -> Result<SessionCompensation> {
    let mut session_outcome = SessionCompensation::NotApplicable;
    let already_compensating = record.phase == JournalPhase::Compensating;
    if !already_compensating && record.needs_session_authority() {
        let mut compensating = record.clone();
        compensating.phase = JournalPhase::Compensating;
        write_journal(journal_path, &compensating)?;
        crash_point_bail!(AfterCompensatingMarker);
    }

    if let Some((session_id, prior, expected_revision)) = record.session_participant()
        && let Some(sessions) = sessions
    {
        if let Some(bound) = sessions.bound_session_id()
            && bound != session_id
        {
            anyhow::bail!("refusing to compensate a journal bound to a different session");
        }
        let committed_revision = expected_revision.saturating_add(1);
        let compensated_revision = expected_revision.saturating_add(2);
        match sessions.current_revision(session_id)? {
            // The CAS never ran: nothing to compensate.
            Some(current) if current == expected_revision => {
                session_outcome = SessionCompensation::Untouched;
            }
            Some(current) if current == committed_revision => {
                if !sessions.cas_set_active_model(session_id, committed_revision, prior)? {
                    anyhow::bail!(
                        "session {session_id} advanced concurrently; refusing to overwrite it"
                    );
                }
                session_outcome = SessionCompensation::Reverted;
            }
            // A previous compensation pass already reverted the session. This
            // is only trustworthy once the `compensating` marker is durable.
            Some(current) if current == compensated_revision && already_compensating => {
                session_outcome = SessionCompensation::AlreadyReverted;
            }
            Some(_) => {
                anyhow::bail!(
                    "session {session_id} is at an unexpected active-model revision; refusing to overwrite it"
                );
            }
            // The session row is gone; there is nothing to restore.
            None => {
                session_outcome = SessionCompensation::SessionGone;
            }
        }
    }

    let current = read_config_bytes(config_path)?;
    let current_digest = bytes_digest(&current);
    if current_digest == record.old_config_digest {
        return Ok(session_outcome);
    }
    if current_digest != record.new_config_digest {
        // Someone edited the layer out of band. Compensation must never
        // clobber a conflicting concurrent mutation; the journal stays
        // recoverable and the failure is reported with a safe diagnostic.
        anyhow::bail!(
            "config digest is neither the recorded prior nor the recorded committed content; refusing to overwrite a concurrent change"
        );
    }
    let Some(prior) = read_file_nofollow(backup_path)? else {
        anyhow::bail!("the private rollback snapshot is missing");
    };
    if bytes_digest(&prior) != record.old_config_digest {
        anyhow::bail!("the private rollback snapshot does not match the recorded prior digest");
    }
    prepare_atomic_write(config_path, &prior)?.commit()?;
    fsync_dir(config_parent(config_path))?;
    if bytes_digest(&read_config_bytes(config_path)?) != record.old_config_digest {
        anyhow::bail!("restored config does not match the recorded prior digest");
    }
    Ok(session_outcome)
}

/// Remove the journal and its private backup. Only ever called once the target
/// file has been proven to hold one of the two recorded contents.
fn finish_journal(config_path: &Path, journal_path: &Path, backup_path: &Path) -> Result<()> {
    crash_point_bail!(FailJournalCleanup);
    remove_file_nofollow(backup_path)?;
    remove_file_nofollow(journal_path)?;
    fsync_dir(config_parent(config_path))?;
    Ok(())
}

/// Remove crash-window debris beside `config_path`: a rollback snapshot whose
/// journal is gone, and stale private temporary replacements. Both can only be
/// left behind by a process that died between two steps of one transaction.
/// Remove crash-window debris. Runs at most once per directory per thread and
/// **always under the cross-process mutation lock**: a live transaction writes
/// its rollback snapshot before its journal, so an unlocked, un-aged sweep in
/// that window would delete the snapshot of a transaction that is about to
/// become unconvergeable.
fn sweep_orphans(config_path: &Path) {
    let dir = config_parent(config_path).to_path_buf();
    let first_scan = SWEPT_DIRECTORIES.with(|swept| swept.borrow_mut().insert(dir.clone()));
    if !first_scan {
        return;
    }
    if ConfigMutationLock::is_held_by_current_thread() {
        sweep_orphans_locked(config_path, &dir);
        return;
    }
    let Ok(_lock) = ConfigMutationLock::acquire(config_path) else {
        // Never sweep without the lock; the next pass retries.
        SWEPT_DIRECTORIES.with(|swept| {
            swept.borrow_mut().remove(&dir);
        });
        return;
    };
    sweep_orphans_locked(config_path, &dir);
}

fn sweep_orphans_locked(config_path: &Path, dir: &Path) {
    let now = std::time::SystemTime::now();
    // Re-check journal existence under the lock, and still require the
    // snapshot to be old: belt and braces against a writer that took the lock
    // between our probe and here.
    let backup = backup_path_for_config(config_path);
    if !journal_path_for_config(config_path).exists()
        && file_is_stale(&backup, now)
        && let Err(error) = remove_file_nofollow(&backup)
    {
        tracing::debug!(%error, "could not sweep an orphaned rollback snapshot");
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with('.') || !name.ends_with(".tmp") {
            continue;
        }
        if file_is_stale(&path, now) {
            let _ = remove_file_nofollow(&path);
        }
    }
}

/// True when `path` is a private, regular file this product could have
/// created and it is older than the sweep threshold. Uses
/// `symlink_metadata`, so a planted symlink is never followed.
fn file_is_stale(path: &Path, now: std::time::SystemTime) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o777 != 0o600 {
            return false;
        }
    }
    meta.modified()
        .ok()
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|age| age >= STALE_TEMP_AGE)
}

/// Layers whose pending journal must be masked on read.
///
/// A session-bearing journal cannot be finished without daemon session
/// authority, so a plain config read must not observe whichever half is
/// already published. This returns the recorded **prior** bytes for those
/// layers — the only value both authorities are known to have agreed on.
/// Config-only journals are never masked: ordinary recovery finishes them.
pub(crate) fn masked_layer_bytes(paths: &[PathBuf]) -> HashMap<PathBuf, Vec<u8>> {
    masked_layers(paths).0
}

/// Masks plus the layers that have a pending journal which could **not** be
/// masked (unreadable record, missing or mismatched snapshot).
///
/// An unmaskable pending layer must never be merged live: after a crash at or
/// after the replacement its bytes may already hold the target, and serving
/// them would expose a half-committed default. Callers fail closed instead.
pub(crate) fn masked_layers(paths: &[PathBuf]) -> (HashMap<PathBuf, Vec<u8>>, Vec<PathBuf>) {
    let mut masks = HashMap::new();
    let mut unmaskable = Vec::new();
    for path in paths {
        let journal_path = journal_path_for_config(path);
        if !journal_path.exists() {
            continue;
        }
        let record = match load_journal(&journal_path) {
            Ok(Some(record)) => record,
            // A journal that exists but cannot be read is the worst case: we
            // cannot tell which half is on disk.
            Ok(None) | Err(_) => {
                unmaskable.push(path.clone());
                continue;
            }
        };
        // An out-of-context journal describes some other file; this layer's
        // own bytes are trustworthy.
        if journal_context_error(&record, path).is_some() {
            continue;
        }
        // Anything a plain reader is forbidden to converge must be masked.
        if !record.needs_session_authority() && record.correlation.is_none() {
            continue;
        }
        match read_file_nofollow(&backup_path_for_config(path)) {
            Ok(Some(prior)) if bytes_digest(&prior) == record.old_config_digest => {
                masks.insert(path.clone(), prior);
            }
            _ => unmaskable.push(path.clone()),
        }
    }
    (masks, unmaskable)
}

/// True when any layer in `paths` currently has a journal file.
///
/// Closes the probe race: the layer merge runs outside the mutation lock, so a
/// journal that appears mid-merge must be noticed and the merge repeated.
pub(crate) fn any_journal_present(paths: &[PathBuf]) -> bool {
    paths
        .iter()
        .any(|path| journal_path_for_config(path).exists())
}

/// The journal file that governs `config_path`, whether or not it exists.
///
/// Exposed so daemon-level tests and repair tooling can name the exact file
/// `cockpit doctor` reports. The name is keyed by a digest of the config file
/// path, so two config files in one directory never collide.
pub fn journal_path_for_layer(config_path: &Path) -> PathBuf {
    journal_path_for_config(config_path)
}

/// Non-secret inventory of pending journals for `cwd`, for `cockpit doctor`.
///
/// The repair diagnostic in daemon errors points here, so this must be able to
/// describe a journal recovery refuses to touch.
pub fn journal_diagnostics(cwd: &Path) -> Vec<JournalDiagnostic> {
    let mut out = Vec::new();
    for path in config_file_paths_for_load(cwd) {
        let journal_path = journal_path_for_config(&path);
        if !journal_path.exists() {
            continue;
        }
        let scope_label = scope_for_config_path(cwd, &path).as_str().to_string();
        match load_journal(&journal_path) {
            Ok(Some(record)) => out.push(JournalDiagnostic {
                journal_path,
                scope_label,
                phase: record.phase.as_str(),
                transaction_id: record.transaction_id,
                needs_session_authority: record.needs_session_authority(),
                correlated: record.correlation.is_some(),
                out_of_context: journal_context_error(&record, &path).is_some(),
            }),
            _ => out.push(JournalDiagnostic {
                journal_path,
                scope_label,
                phase: "unreadable",
                transaction_id: Uuid::nil(),
                needs_session_authority: false,
                correlated: false,
                out_of_context: true,
            }),
        }
    }
    out
}

impl ConfigDoc {
    /// Like [`Self::load_effective`] but skips journal *recovery* — used
    /// inside the mutation lock and by recovery itself so neither recurses.
    ///
    /// Masking still applies: a pending session-bearing or correlated
    /// transaction on any layer (including a lower-precedence one) must not
    /// leak its half-committed value into a resolution.
    pub(crate) fn load_effective_without_recovery(cwd: &Path) -> ProvidersConfig {
        Self::load_effective_masked_except(cwd, None)
    }

    /// Masked resolution that deliberately does **not** mask `owned`.
    ///
    /// The layer an in-flight transaction is writing has its own journal on
    /// disk; masking it would serve the prior bytes and make the transaction's
    /// own reload verification fail against itself.
    pub(crate) fn load_effective_masked_except(
        cwd: &Path,
        owned: Option<&Path>,
    ) -> ProvidersConfig {
        let paths = config_file_paths_for_load(cwd);
        let mut masks = masked_layer_bytes(&paths);
        if let Some(owned) = owned {
            let owned = canonical_config_path(owned);
            masks.retain(|path, _| canonical_config_path(path) != owned);
        }
        Self::providers_from_paths_with_masks(&paths, &masks)
            .with_resolution_generation(crate::config::providers::next_load_effective_generation())
    }
}

// ---- Mutation --------------------------------------------------------------

/// Mutate the effective default for `cwd` under the cross-process lock.
///
/// `session` makes this a session+default transaction: both authorities commit
/// or both restore. `None` is a config-only transaction (`SetDefaultModel`,
/// `/settings`, `/setup model`) with no session phase and no session CAS.
///
/// `cancelled` is observed only before the durable commit boundary.
/// `correlation` is recorded in the journal so a transaction this process
/// cannot finish still yields exactly one correlated terminal event later.
pub fn mutate_effective_default(
    cwd: &Path,
    requested: Option<&ActiveModelRef>,
    mode: ActiveModelWriteMode,
    session: Option<SessionDefaultParticipant<'_>>,
    cancelled: Option<&AtomicBool>,
    correlation: Option<TransactionCorrelation>,
) -> Result<EffectiveDefaultMutationResult, EffectiveDefaultError> {
    let target = resolve_effective_default_write_target(cwd)?;
    let scope_label = target.scope_label();
    ensure_target_writable(&target)?;
    let lock = acquire_mutation_lock(&target.path, &scope_label, cancelled)?;

    // Idempotent recovery under the lock we already hold: never mutate on top
    // of a half-committed transaction.
    let mut session = session;
    // Deliberately **no** sink: a mutation may finish its own session's
    // half-committed transaction, but it must never converge a *correlated*
    // journal it did not originate. Doing so would delete another operation's
    // terminal event, leaving that client's pending state open forever. Such a
    // journal is left pending (and masked on read) for daemon recovery, and
    // the conflict gate below refuses this mutation until then.
    let outcome = match session.as_mut() {
        Some(participant) => recover_one(
            &target.path,
            JournalRecovery::with_sessions(&mut *participant.authority),
        ),
        None => recover_one(
            &target.path,
            JournalRecovery {
                sessions: None,
                sink: None,
                forced: true,
            },
        ),
    };
    if let Err(error) = outcome {
        return Err(EffectiveDefaultError::new(
            safe_cause(
                "a previous default-model update is still unresolved",
                &error,
            ),
            "effective_default_recovery_blocked",
            Some(scope_label),
        ));
    }
    // A journal that survived recovery is one this caller may not finish
    // (foreign session, out of context, or a conflicting concurrent change).
    // Its files are keyed to this exact config file, so proceeding would
    // overwrite them: fail closed instead.
    if journal_path_for_config(&target.path).exists() {
        return Err(EffectiveDefaultError::new(
            "another default-model update for this configuration layer is still pending; run `cockpit doctor` to inspect it",
            "effective_default_journal_conflict",
            Some(scope_label),
        ));
    }

    let current = ConfigDoc::load_effective_without_recovery(cwd);
    let generation = current.resolution_generation.max(1);
    let current_active = current.active_model.clone();

    // Clearing resolves to the deterministic inherited default below the
    // target layer, and is rejected outright if that would be dangling.
    let expected_effective = match requested {
        Some(active) => Some(active.clone()),
        None => {
            let inherited = inherited_default(&target.lower_paths);
            validate_inherited_default(inherited.as_ref(), &current, &scope_label)?;
            inherited
        }
    };

    let should_write = match (mode, requested, current_active.as_ref()) {
        (ActiveModelWriteMode::Replace, Some(req), Some(cur)) => req != cur,
        (ActiveModelWriteMode::Replace, Some(_), None) => true,
        // A clear is a no-op only when the target layer declares no default.
        (ActiveModelWriteMode::Replace, None, _) => {
            target_layer_declares_active_model(&target.path)
        }
        (ActiveModelWriteMode::InitializeIfMissing, Some(_), None) => true,
        (ActiveModelWriteMode::InitializeIfMissing, _, _) => false,
    };

    if !should_write {
        // Verify under the lock even for a no-op: a concurrent writer must not
        // let a stale request claim the other writer's model as its own.
        let reloaded = ConfigDoc::load_effective_without_recovery(cwd);
        if reloaded.active_model != current_active {
            return Err(EffectiveDefaultError::new(
                "the effective default changed concurrently during verification",
                "effective_default_concurrent_conflict",
                Some(scope_label),
            ));
        }
        // Only an explicit replace promises the requested model is effective.
        // An initializer that finds a different winner reports that winner —
        // observing it is the entire point, not a mismatch.
        if matches!(mode, ActiveModelWriteMode::Replace)
            && requested.is_some()
            && reloaded.active_model != expected_effective
        {
            return Err(EffectiveDefaultError::new(
                "the effective default did not resolve to the requested model",
                "effective_default_reload_mismatch",
                Some(scope_label),
            ));
        }
        drop(lock);
        return Ok(EffectiveDefaultMutationResult {
            selection: reloaded.active_model,
            generation: reloaded.resolution_generation.max(generation),
            scope_label,
            wrote: false,
            unchanged: true,
        });
    }

    let requested_owned = requested.cloned();
    mutate_under_lock(
        cwd,
        &target,
        &scope_label,
        requested_owned.as_ref(),
        expected_effective,
        session,
        cancelled,
        correlation,
        lock,
    )
}

fn acquire_mutation_lock(
    path: &Path,
    scope_label: &str,
    cancelled: Option<&AtomicBool>,
) -> Result<ConfigMutationLock, EffectiveDefaultError> {
    let acquired = match cancelled {
        Some(flag) => ConfigMutationLock::acquire_cancellable(path, flag),
        None => ConfigMutationLock::acquire(path),
    };
    acquired.map_err(|error| {
        if cancelled.is_some() && error.to_string().contains("cancelled") {
            EffectiveDefaultError::new(
                "the default model update was cancelled before it became durable",
                "effective_default_cancelled",
                Some(scope_label.to_string()),
            )
        } else {
            EffectiveDefaultError::new(
                safe_cause("the config mutation lock could not be acquired", &error),
                "effective_default_lock_failed",
                Some(scope_label.to_string()),
            )
        }
    })
}

fn target_layer_declares_active_model(path: &Path) -> bool {
    read_file_nofollow(path)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .is_some_and(|raw| raw.get("active_model").is_some_and(|v| !v.is_null()))
}

#[allow(clippy::too_many_arguments)]
fn mutate_under_lock(
    cwd: &Path,
    target: &ResolvedTarget,
    scope_label: &str,
    requested: Option<&ActiveModelRef>,
    expected_effective: Option<ActiveModelRef>,
    mut session: Option<SessionDefaultParticipant<'_>>,
    cancelled: Option<&AtomicBool>,
    correlation: Option<TransactionCorrelation>,
    _lock: ConfigMutationLock,
) -> Result<EffectiveDefaultMutationResult, EffectiveDefaultError> {
    let journal_path = journal_path_for_config(&target.path);
    let backup_path = backup_path_for_config(&target.path);

    let old_bytes = read_config_bytes(&target.path).map_err(|error| {
        EffectiveDefaultError::new(
            safe_cause("the config layer could not be read", &error),
            "effective_default_read_failed",
            Some(scope_label.to_string()),
        )
    })?;
    let old_digest = bytes_digest(&old_bytes);
    let new_bytes = replacement_bytes(&old_bytes, requested).map_err(|error| {
        EffectiveDefaultError::new(
            format!("config.json cannot accept a default update: {error}"),
            "effective_default_malformed_config",
            Some(scope_label.to_string()),
        )
    })?;
    let new_digest = bytes_digest(&new_bytes);

    if session.is_some() && requested.is_none() {
        return Err(EffectiveDefaultError::new(
            "a session+default transaction requires a concrete model reference",
            "effective_default_missing_target",
            Some(scope_label.to_string()),
        ));
    }
    // A bound authority may only ever write its own session row.
    if let Some(participant) = session.as_ref()
        && let Some(bound) = participant.authority.bound_session_id()
        && bound != participant.session_id
    {
        return Err(EffectiveDefaultError::new(
            "the session authority is bound to a different session",
            "effective_default_session_mismatch",
            Some(scope_label.to_string()),
        ));
    }

    // Last cancellation observation before the durable commit boundary.
    if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire)) {
        return Err(EffectiveDefaultError::new(
            "the default model update was cancelled before it became durable",
            "effective_default_cancelled",
            Some(scope_label.to_string()),
        ));
    }

    // Private, owner-only rollback snapshot of the prior bytes. It never
    // appears in journal metadata, traces, events, or diagnostics. A crash
    // between here and the prepared record leaves an orphan backup with no
    // journal, which `sweep_orphans` removes on the next pass.
    write_private_file(&backup_path, &old_bytes).map_err(|error| {
        EffectiveDefaultError::new(
            safe_cause(
                "the private rollback snapshot could not be prepared",
                &error,
            ),
            "effective_default_backup_failed",
            Some(scope_label.to_string()),
        )
    })?;

    let journal_session = match session.as_ref() {
        None => JournalSession::None,
        Some(participant) => JournalSession::Session {
            session_id: participant.session_id,
            prior: participant.prior.clone(),
            target: requested.cloned().expect("checked above"),
            expected_revision: participant.expected_revision,
        },
    };
    let mut record = JournalRecord {
        transaction_id: Uuid::new_v4(),
        project_root: cwd.display().to_string(),
        trust_mode: crate::config::trust::current_workspace_trust_policy()
            .map(|policy| policy.mode.as_str().to_string()),
        scope: target.scope.clone(),
        // Canonical on both sides: the journal *name* is keyed on the
        // canonical path, so validating a raw path would make one file under
        // two spellings permanently out of context.
        target_path_digest: path_digest(&canonical_config_path(&target.path)),
        old_config_digest: old_digest,
        new_config_digest: new_digest,
        requested: requested.cloned(),
        expected_effective: expected_effective.clone(),
        session: journal_session,
        correlation,
        phase: JournalPhase::Prepared,
    };

    // ---- Durable commit boundary: the fsynced `prepared` record. ----
    if let Err(error) = write_journal(&journal_path, &record) {
        let _ = remove_file_nofollow(&backup_path);
        return Err(EffectiveDefaultError::new(
            safe_cause("the default-model journal could not be prepared", &error),
            "effective_default_journal_failed",
            Some(scope_label.to_string()),
        ));
    }
    crash_point!(scope_label, AfterJournalPrepared);

    let pending = match prepare_atomic_write(&target.path, &new_bytes) {
        Ok(pending) => pending,
        Err(error) => {
            // The prepared record is durable, so convergence — not a bare
            // rejection — owns the outcome even though nothing changed yet.
            return converge(
                cwd,
                &target.path,
                &journal_path,
                &backup_path,
                &record,
                // The CAS has not run yet, so there is no session half to
                // compensate — and `expected + 1` may belong to someone else.
                None,
                scope_label,
                false,
                &safe_cause("the replacement file could not be prepared", &error),
            );
        }
    };
    crash_point!(scope_label, AfterPrivateReplacementPrepared);

    // Guarded session CAS (session+default only). A zero-row result is a
    // concurrent conflict, never permission to overwrite.
    let mut session_cause = None;
    // A zero-row CAS proves nothing was written. An *error*, by contrast, is
    // ambiguous: the row may or may not have been updated before the failure
    // surfaced. Only the proven case may skip session compensation; the
    // ambiguous one keeps it, where the recorded-revision guard decides
    // safely between "never ran" and "committed".
    let mut session_commit_ambiguous = false;
    if let Some(participant) = session.as_mut() {
        let target_model = requested.expect("checked above");
        match participant.authority.cas_set_active_model(
            participant.session_id,
            participant.expected_revision,
            target_model,
        ) {
            Ok(true) => {}
            Ok(false) => {
                session_cause = Some("the session model changed concurrently".to_string());
            }
            Err(error) => {
                session_commit_ambiguous = true;
                session_cause = Some(safe_cause(
                    "the session model could not be persisted",
                    &error,
                ));
            }
        }
    }
    if let Some(cause) = session_cause {
        drop(pending);
        // Proven-no-commit (zero rows): skip session compensation entirely.
        // Guessing would be unsafe, because `expected + 1` can equal the
        // concurrent writer's revision and "reverting" would clobber them.
        // Ambiguous (error): keep compensation authority — the guard reads the
        // durable revision and only reverts what this transaction committed.
        let session_for_compensation = if session_commit_ambiguous {
            session.as_mut()
        } else {
            None
        };
        return converge(
            cwd,
            &target.path,
            &journal_path,
            &backup_path,
            &record,
            session_for_compensation,
            scope_label,
            false,
            &cause,
        );
    }
    if session.is_some() {
        crash_point!(scope_label, AfterSessionCas);

        record.phase = JournalPhase::SessionCommitted;
        if let Err(error) = write_journal(&journal_path, &record) {
            drop(pending);
            // The durable journal is still at `prepared`; compensation reverts
            // the committed CAS under its revision guard.
            record.phase = JournalPhase::Prepared;
            return converge(
                cwd,
                &target.path,
                &journal_path,
                &backup_path,
                &record,
                session.as_mut(),
                scope_label,
                false,
                &safe_cause(
                    "the session-committed journal phase could not be recorded",
                    &error,
                ),
            );
        }
        crash_point!(scope_label, AfterSessionCommittedMarker);
    }

    if let Err(error) = pending.commit() {
        return converge(
            cwd,
            &target.path,
            &journal_path,
            &backup_path,
            &record,
            session.as_mut(),
            scope_label,
            false,
            &safe_cause("config.json could not be replaced", &error),
        );
    }
    // An fsync failure is a typed failure, never a silent success: the
    // replacement is not provably durable, so converge back to the prior
    // values rather than claim the new default.
    if let Err(error) = fsync_dir(config_parent(&target.path)) {
        return converge(
            cwd,
            &target.path,
            &journal_path,
            &backup_path,
            &record,
            session.as_mut(),
            scope_label,
            false,
            &safe_cause("the config directory could not be fsynced", &error),
        );
    }
    crash_point!(scope_label, AfterConfigReplaced);

    record.phase = JournalPhase::Committed;
    if let Err(error) = write_journal(&journal_path, &record) {
        return converge(
            cwd,
            &target.path,
            &journal_path,
            &backup_path,
            &record,
            session.as_mut(),
            scope_label,
            true,
            &safe_cause("the committed journal phase could not be recorded", &error),
        );
    }
    crash_point!(scope_label, AfterCommittedMarker);

    // Reload verification under the same trust policy and context. This
    // transaction owns `target.path`, so that layer is read live while every
    // other pending layer stays masked.
    let reloaded = ConfigDoc::load_effective_masked_except(cwd, Some(&target.path));
    if reloaded.active_model != expected_effective {
        return converge(
            cwd,
            &target.path,
            &journal_path,
            &backup_path,
            &record,
            session.as_mut(),
            scope_label,
            true,
            "the reloaded effective configuration did not resolve to the requested default",
        );
    }
    crash_point!(scope_label, AfterReloadVerified);

    if let Err(error) = finish_journal(&target.path, &journal_path, &backup_path) {
        // Both authorities already hold the target; the journal is idempotent
        // and the next recovery pass removes it.
        tracing::warn!(%error, "could not clean up a converged effective-default journal");
    }
    crash_point!(scope_label, AfterJournalCleanup);

    Ok(EffectiveDefaultMutationResult {
        selection: reloaded.active_model,
        generation: reloaded.resolution_generation.max(1),
        scope_label: scope_label.to_string(),
        wrote: true,
        unchanged: false,
    })
}

/// Post-boundary convergence. After the fsynced `prepared` record a caller can
/// never receive a bare rejection while recovery might still expose the target.
///
/// When the config replacement is already durable (`forward_allowed`), this
/// finishes the exact intended commit and re-verifies the reload; both
/// authorities then hold the target and the caller gets `Applied`. Otherwise —
/// or when forward verification fails — it compensates to both recorded prior
/// values and verifies the restoration, the only case that may reject. If
/// neither can be proven the error carries `recovery_pending`, which is **not**
/// a terminal result: the journal is retained and a later recovery pass emits
/// the correlated terminal event.
#[allow(clippy::too_many_arguments)]
fn converge(
    cwd: &Path,
    config_path: &Path,
    journal_path: &Path,
    backup_path: &Path,
    record: &JournalRecord,
    session: Option<&mut SessionDefaultParticipant<'_>>,
    scope_label: &str,
    forward_allowed: bool,
    cause: &str,
) -> Result<EffectiveDefaultMutationResult, EffectiveDefaultError> {
    if forward_allowed && finish_config_from_journal(config_path, record, backup_path).is_ok() {
        let reloaded = ConfigDoc::load_effective_masked_except(cwd, Some(config_path));
        if reloaded.active_model == record.expected_effective {
            if let Err(error) = finish_journal(config_path, journal_path, backup_path) {
                tracing::warn!(%error, "could not clean up a forward-converged journal");
            }
            tracing::warn!(
                transaction_id = %record.transaction_id,
                cause,
                "effective-default transaction converged forward after a late failure"
            );
            return Ok(EffectiveDefaultMutationResult {
                selection: reloaded.active_model,
                generation: reloaded.resolution_generation.max(1),
                scope_label: scope_label.to_string(),
                wrote: true,
                unchanged: false,
            });
        }
    }

    // Bind the compensation result before building the error: a `match` in
    // tail position keeps its scrutinee temporary alive to the end of the
    // function body, which would outlive the borrow of `session` taken here.
    let compensated = compensate(
        config_path,
        journal_path,
        backup_path,
        record,
        session.map(|participant| &mut *participant.authority),
    );
    let error = match compensated {
        Ok(session_outcome) => match finish_journal(config_path, journal_path, backup_path) {
            Ok(()) => EffectiveDefaultError::restored(scope_label, cause, session_outcome),
            Err(error) => EffectiveDefaultError::pending(
                scope_label,
                &format!(
                    "{cause}; {}",
                    safe_cause("the journal could not be removed", &error)
                ),
            ),
        },
        Err(error) => EffectiveDefaultError::pending(
            scope_label,
            &format!("{cause}; {}", safe_cause("compensation failed", &error)),
        ),
    };
    Err(error)
}

#[cfg(test)]
mod tests;
