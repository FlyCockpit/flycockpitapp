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
//! Windows the retained-handle backend uses the platform's best available
//! post-rename synchronization semantics.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::dirs::{
    COCKPIT_CONFIG_ENV, ConfigDir, ConfigDirKind, config_file_paths_for_load, discover_config_dirs,
};
use crate::config::files::{
    ConfigMutationLock, atomic_write_leaf_from_retained_directory,
    prepare_atomic_write_from_retained_directory, read_file_nofollow, read_file_nofollow_bounded,
    read_optional_leaf_from_directory_handle, remove_leaf_from_retained_directory,
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
/// A journal is metadata-only; accepting more than one workspace-config leaf
/// before its correlation has been classified would let an untrusted sidecar
/// force an unbounded ambient recovery allocation.
const MAX_EFFECTIVE_DEFAULT_JOURNAL_BYTES: usize = crate::config::MAX_WORKSPACE_CONFIG_FILE_BYTES;
/// Ambient recovery only needs a bounded preflight scan to discover a
/// capability-owned retained journal before it derives any canonical target
/// identity. More candidates are an adversarial/ambiguous sidecar state, not
/// a reason to continue into pathname recovery.
const MAX_AMBIENT_JOURNAL_PREFLIGHT_CANDIDATES: usize = 256;

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

    /// Convert a discovered layer origin to the durable default-write scope.
    /// Kept public because the daemon freezes that scope while it captures a
    /// retained attach-time target; it must not rediscover the layer later.
    pub fn from_dir_kind(kind: &ConfigDirKind) -> Self {
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
    /// Retained config bytes and their committed journal are durable, but the
    /// daemon has not refreshed its authoritative worker snapshot yet.
    AfterRetainedCommitBeforeRefresh,
    /// The daemon refreshed the exact retained chain but has not handed the
    /// correlated terminal receipt to the client yet.
    AfterRetainedRefreshBeforeReceipt,
    /// The retained journal has durably sealed its exact authority, but the
    /// daemon has not yet recorded or delivered the correlated receipt. This
    /// is the decisive A-bound recovery window: a later pathname replacement
    /// must leave the sealed journal pending rather than minting a result for
    /// replacement authority B.
    AfterRetainedAuthoritySealedBeforeReceipt,
    /// The correlated receipt was emitted and durably marked; only private
    /// journal cleanup remains.
    AfterRetainedReceiptBeforeCleanup,
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

/// Per-thread operation evidence for ambient-recovery boundary tests.  The
/// retained path must return before either counter can change; use a
/// thread-local rather than a process-global atomic so parallel test cases do
/// not observe each other's ordinary recovery work.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AmbientRecoveryOperationCounts {
    pub target_canonicalizations: usize,
    pub lock_acquisitions: usize,
    /// Calls into an ambient mutation's writable probe. A retained handoff
    /// must be rejected before this reaches its replacement directory.
    pub mutation_writable_probes: usize,
    /// Ambient mutation lock acquisitions, including canonical lock identity
    /// derivation. A retained handoff must leave this at zero.
    pub mutation_lock_acquisitions: usize,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static AMBIENT_RECOVERY_OPERATION_COUNTS: std::cell::Cell<AmbientRecoveryOperationCounts> =
        const { std::cell::Cell::new(AmbientRecoveryOperationCounts {
            target_canonicalizations: 0,
            lock_acquisitions: 0,
            mutation_writable_probes: 0,
            mutation_lock_acquisitions: 0,
        }) };
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_ambient_recovery_operation_counts_for_tests() {
    AMBIENT_RECOVERY_OPERATION_COUNTS
        .with(|counts| counts.set(AmbientRecoveryOperationCounts::default()));
}

#[cfg(any(test, feature = "test-support"))]
pub fn ambient_recovery_operation_counts_for_tests() -> AmbientRecoveryOperationCounts {
    AMBIENT_RECOVERY_OPERATION_COUNTS.with(std::cell::Cell::get)
}

#[cfg(any(test, feature = "test-support"))]
fn note_ambient_recovery_target_canonicalization_for_tests() {
    AMBIENT_RECOVERY_OPERATION_COUNTS.with(|counts| {
        let mut next = counts.get();
        next.target_canonicalizations += 1;
        counts.set(next);
    });
}

#[cfg(not(any(test, feature = "test-support")))]
fn note_ambient_recovery_target_canonicalization_for_tests() {}

#[cfg(any(test, feature = "test-support"))]
fn note_ambient_recovery_lock_acquisition_for_tests() {
    AMBIENT_RECOVERY_OPERATION_COUNTS.with(|counts| {
        let mut next = counts.get();
        next.lock_acquisitions += 1;
        counts.set(next);
    });
}

#[cfg(any(test, feature = "test-support"))]
fn note_ambient_mutation_writable_probe_for_tests() {
    AMBIENT_RECOVERY_OPERATION_COUNTS.with(|counts| {
        let mut next = counts.get();
        next.mutation_writable_probes += 1;
        counts.set(next);
    });
}

#[cfg(not(any(test, feature = "test-support")))]
fn note_ambient_mutation_writable_probe_for_tests() {}

#[cfg(any(test, feature = "test-support"))]
fn note_ambient_mutation_lock_acquisition_for_tests() {
    AMBIENT_RECOVERY_OPERATION_COUNTS.with(|counts| {
        let mut next = counts.get();
        next.mutation_lock_acquisitions += 1;
        counts.set(next);
    });
}

#[cfg(not(any(test, feature = "test-support")))]
fn note_ambient_mutation_lock_acquisition_for_tests() {}

#[cfg(not(any(test, feature = "test-support")))]
fn note_ambient_recovery_lock_acquisition_for_tests() {}

/// Deterministic retained-directory race seam. It runs after the durable
/// `prepared` journal has been written but before the retained config leaf is
/// replaced, which is the security-critical window for an A→B pathname swap.
/// Production contains no hook or mutable global state.
#[cfg(any(test, feature = "test-support"))]
pub type RetainedMutationHook = std::sync::Arc<dyn Fn() + Send + Sync + 'static>;

#[cfg(any(test, feature = "test-support"))]
static RETAINED_MUTATION_HOOK: std::sync::OnceLock<std::sync::Mutex<Option<RetainedMutationHook>>> =
    std::sync::OnceLock::new();

/// Deterministic seam for the last authority fence: the hook runs only after
/// the retained journal has durably recorded its authority binding and before
/// the daemon can commit the separate SQLite receipt.  It lets integration
/// tests prove that a replacement in that tiny window preserves A's receipt
/// and cannot redirect the already-completed mutation to B.
#[cfg(any(test, feature = "test-support"))]
static RETAINED_AUTHORITY_FENCE_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<RetainedMutationHook>>,
> = std::sync::OnceLock::new();

/// Deterministic ambient-recovery race seam. It runs after a bounded journal
/// read has proved the record non-retained and before the ambient path derives
/// a canonical lock identity. It lets tests replace that pathname with a
/// retained journal and prove the locked re-read exits without touching it.
#[cfg(any(test, feature = "test-support"))]
pub type AmbientRecoveryClassificationHook = std::sync::Arc<dyn Fn() + Send + Sync + 'static>;

#[cfg(any(test, feature = "test-support"))]
static AMBIENT_RECOVERY_CLASSIFICATION_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<AmbientRecoveryClassificationHook>>,
> = std::sync::OnceLock::new();

/// Deterministic ambient-mutation race seam. It runs after target selection
/// and its initial journal classification, but before a writable probe, lock
/// sidecar, canonicalization, config read, or recovery context can touch that
/// mutable pathname. Tests replace A with a retained B here and prove the
/// second bounded classification rejects B without observing it further.
#[cfg(any(test, feature = "test-support"))]
pub type AmbientMutationClassificationHook = std::sync::Arc<dyn Fn() + Send + Sync + 'static>;

#[cfg(any(test, feature = "test-support"))]
static AMBIENT_MUTATION_CLASSIFICATION_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<AmbientMutationClassificationHook>>,
> = std::sync::OnceLock::new();

#[cfg(any(test, feature = "test-support"))]
pub fn set_retained_mutation_hook_for_tests(hook: Option<RetainedMutationHook>) {
    *RETAINED_MUTATION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = hook;
}

#[cfg(any(test, feature = "test-support"))]
pub fn set_retained_authority_fence_hook_for_tests(hook: Option<RetainedMutationHook>) {
    *RETAINED_AUTHORITY_FENCE_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = hook;
}

#[cfg(any(test, feature = "test-support"))]
pub fn set_ambient_recovery_classification_hook_for_tests(
    hook: Option<AmbientRecoveryClassificationHook>,
) {
    *AMBIENT_RECOVERY_CLASSIFICATION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = hook;
}

#[cfg(any(test, feature = "test-support"))]
pub fn set_ambient_mutation_classification_hook_for_tests(
    hook: Option<AmbientMutationClassificationHook>,
) {
    *AMBIENT_MUTATION_CLASSIFICATION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = hook;
}

#[cfg(any(test, feature = "test-support"))]
fn run_retained_mutation_hook_for_tests() {
    let hook = RETAINED_MUTATION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(any(test, feature = "test-support"))]
fn run_retained_authority_fence_hook_for_tests() {
    let hook = RETAINED_AUTHORITY_FENCE_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(any(test, feature = "test-support"))]
fn run_ambient_recovery_classification_hook_for_tests() {
    let hook = AMBIENT_RECOVERY_CLASSIFICATION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(any(test, feature = "test-support"))]
fn run_ambient_mutation_classification_hook_for_tests() {
    let hook = AMBIENT_MUTATION_CLASSIFICATION_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(any(test, feature = "test-support")))]
fn run_retained_mutation_hook_for_tests() {}

#[cfg(not(any(test, feature = "test-support")))]
fn run_retained_authority_fence_hook_for_tests() {}

#[cfg(not(any(test, feature = "test-support")))]
fn run_ambient_recovery_classification_hook_for_tests() {}

#[cfg(not(any(test, feature = "test-support")))]
fn run_ambient_mutation_classification_hook_for_tests() {}

/// Install a one-shot crash-inject point for the current thread.
///
/// Test-support only. Enabled by this crate's own tests and by the
/// `test-support` feature, which only `cockpit-core`'s dev-dependencies turn
/// on so daemon-level tests can replay the same phase boundaries.
#[cfg(any(test, feature = "test-support"))]
pub fn set_crash_inject(point: Option<EffectiveDefaultCrashPoint>) {
    CRASH_INJECT.with(|cell| cell.set(point));
}

/// Copy the currently armed deterministic crash seam into work that is about
/// to run on another thread.  The production transaction path never calls
/// this; daemon integration tests use it when the durable filesystem portion
/// runs in `spawn_blocking` after the request task has armed its seam.
#[cfg(any(test, feature = "test-support"))]
pub fn current_crash_inject_for_tests() -> Option<EffectiveDefaultCrashPoint> {
    CRASH_INJECT.with(std::cell::Cell::get)
}

/// Run one test-only blocking phase with the request task's captured seam.
/// Restoring the worker thread's old value matters because Tokio may reuse it
/// for unrelated tests after the closure completes.
#[cfg(any(test, feature = "test-support"))]
pub fn with_crash_inject_for_tests<T>(
    point: Option<EffectiveDefaultCrashPoint>,
    operation: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<EffectiveDefaultCrashPoint>);

    impl Drop for Restore {
        fn drop(&mut self) {
            CRASH_INJECT.with(|cell| cell.set(self.0));
        }
    }

    CRASH_INJECT.with(|cell| {
        let restore = Restore(cell.replace(point));
        let result = operation();
        drop(restore);
        result
    })
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
    /// Optional absolute deadline for pre-socket cross-process lock
    /// acquisition. Normal interactive recovery retains its existing
    /// unbounded serialization contract.
    lock_deadline: Option<std::time::Instant>,
}

impl<'a, 'o: 'a> JournalRecovery<'a, 'o> {
    /// A passive configuration read: converges nothing that anyone is waiting
    /// on, and honours the negative cache.
    pub fn read_only() -> Self {
        Self {
            sessions: None,
            sink: None,
            forced: false,
            lock_deadline: None,
        }
    }

    pub fn with_sessions(sessions: &'a mut (dyn SessionRevisionAuthority + 'o)) -> Self {
        Self {
            sessions: Some(sessions),
            sink: None,
            forced: true,
            lock_deadline: None,
        }
    }

    pub fn with_sink(mut self, sink: &'a mut (dyn RecoveredSink + 'o)) -> Self {
        self.sink = Some(sink);
        self
    }

    pub fn with_lock_deadline(mut self, deadline: std::time::Instant) -> Self {
        self.lock_deadline = Some(deadline);
        self
    }

    fn reborrow(&mut self) -> JournalRecovery<'_, 'o> {
        JournalRecovery {
            sessions: self.sessions.as_deref_mut(),
            sink: self.sink.as_deref_mut(),
            forced: self.forced,
            lock_deadline: self.lock_deadline,
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
/// Opaque, public-safe proof of the exact retained authority at which a
/// config-only default update linearized.
///
/// The revision is a domain-separated digest produced by the daemon from the
/// retained root/layer identities and target descriptor, plus the worker
/// snapshot generation that was actually published.  It deliberately carries
/// neither a path nor any configuration/provider contents.  Keeping this in
/// the journal correlation means a post-commit recovery cannot turn an
/// operation for authority A into a receipt for a replacement authority B.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultUpdateAuthorityBinding {
    pub authority_revision: String,
    pub config_generation: u64,
}

impl DefaultUpdateAuthorityBinding {
    pub fn new(authority_revision: String, config_generation: u64) -> Result<Self> {
        let binding = Self {
            authority_revision,
            config_generation,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validate bytes reloaded from a durable journal or receipt as well as
    /// freshly constructed bindings. Serde intentionally cannot make this a
    /// construction invariant: hand-corrupted durable state must fail closed,
    /// never become an authority token merely because it deserializes.
    fn validate(&self) -> Result<()> {
        ensure!(
            self.authority_revision.len() == 64
                && self
                    .authority_revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "default-update authority revision must be a lowercase SHA-256 digest"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransactionCorrelation {
    /// `/model` Ctrl+Enter — terminal `ModelSelectionResult`.
    ModelSelection {
        selection_id: Uuid,
        session_id: Uuid,
    },
    /// Legacy/path-authorized config-only default update. Retained attached
    /// updates use [`Self::RetainedDefaultUpdate`] instead: ambient recovery
    /// must never reopen one of those journals by pathname.
    DefaultUpdate {
        default_update_id: Uuid,
        session_id: Uuid,
        /// Filled only after the exact retained worker snapshot has been
        /// refreshed and the daemon is ready to commit the terminal receipt.
        /// `None` is a pending handoff, never a terminal Applied result. It
        /// is written explicitly into every new journal until the final
        /// authority fence seals it.
        authority: Option<DefaultUpdateAuthorityBinding>,
    },
    /// An attached-session `SetDefaultModel` journal whose config, journal,
    /// backup, and lock are all capability-relative to a held directory.
    ///
    /// This distinction is durable on purpose. A startup/ambient recovery
    /// pass has no retained directory authority and therefore must leave this
    /// correlation (including `receipt_emitted` cleanup) for the attached
    /// worker that can prove the exact captured chain.
    RetainedDefaultUpdate {
        default_update_id: Uuid,
        session_id: Uuid,
        authority: Option<DefaultUpdateAuthorityBinding>,
    },
}

impl TransactionCorrelation {
    pub fn session_id(&self) -> Uuid {
        match self {
            Self::ModelSelection { session_id, .. }
            | Self::DefaultUpdate { session_id, .. }
            | Self::RetainedDefaultUpdate { session_id, .. } => *session_id,
        }
    }

    pub fn default_update_authority(&self) -> Option<&DefaultUpdateAuthorityBinding> {
        match self {
            Self::DefaultUpdate { authority, .. }
            | Self::RetainedDefaultUpdate { authority, .. } => authority.as_ref(),
            Self::ModelSelection { .. } => None,
        }
    }

    pub fn default_update_id(&self) -> Option<Uuid> {
        match self {
            Self::DefaultUpdate {
                default_update_id, ..
            }
            | Self::RetainedDefaultUpdate {
                default_update_id, ..
            } => Some(*default_update_id),
            Self::ModelSelection { .. } => None,
        }
    }

    pub fn is_retained_default_update(&self) -> bool {
        matches!(self, Self::RetainedDefaultUpdate { .. })
    }

    pub fn with_default_update_authority(
        &self,
        authority: DefaultUpdateAuthorityBinding,
    ) -> Result<Self> {
        authority.validate()?;
        match self {
            Self::DefaultUpdate {
                default_update_id,
                session_id,
                ..
            } => Ok(Self::DefaultUpdate {
                default_update_id: *default_update_id,
                session_id: *session_id,
                authority: Some(authority),
            }),
            Self::RetainedDefaultUpdate {
                default_update_id,
                session_id,
                ..
            } => Ok(Self::RetainedDefaultUpdate {
                default_update_id: *default_update_id,
                session_id: *session_id,
                authority: Some(authority),
            }),
            Self::ModelSelection { .. } => anyhow::bail!(
                "cannot bind effective-default authority to a model-selection correlation"
            ),
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

/// A committed retained config-only mutation whose correlated terminal receipt
/// has not yet been durably recorded by the daemon.
///
/// The capability clone owns the exact directory descriptor captured at
/// attach. The caller must keep this token until it has published the terminal
/// receipt; then [`Self::finalize_after_terminal_receipt`] marks the already
/// durable receipt handoff and removes the journal/backup through that
/// descriptor. Dropping it without finalizing is intentional crash semantics:
/// recovery still has the committed journal and can converge the operation
/// later.
pub struct RetainedEffectiveDefaultPendingFinalization {
    target: RetainedEffectiveDefaultTarget,
    result: EffectiveDefaultMutationResult,
    transaction_id: Option<Uuid>,
}

/// Immutable proof that a daemon receipt was durably recorded for a retained
/// default update.  The config journal is writable by the workspace owner, so
/// this proof is deliberately only a *claim*: attached-daemon recovery must
/// compare it with the immutable SQLite receipt before it may retire private
/// journal artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedDefaultReceiptProof {
    default_update_id: Uuid,
    session_id: Uuid,
    authority: DefaultUpdateAuthorityBinding,
    canonical_outcome_json: String,
    canonical_outcome_sha256: String,
}

impl RetainedDefaultReceiptProof {
    pub fn new(
        default_update_id: Uuid,
        session_id: Uuid,
        authority: DefaultUpdateAuthorityBinding,
        canonical_outcome_json: &str,
    ) -> Result<Self> {
        authority.validate()?;
        Ok(Self {
            default_update_id,
            session_id,
            authority,
            canonical_outcome_json: canonical_outcome_json.to_string(),
            canonical_outcome_sha256: bytes_digest(canonical_outcome_json.as_bytes()),
        })
    }

    pub fn default_update_id(&self) -> Uuid {
        self.default_update_id
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn authority(&self) -> &DefaultUpdateAuthorityBinding {
        &self.authority
    }

    pub fn matches_canonical_outcome_json(&self, canonical_outcome_json: &str) -> bool {
        self.canonical_outcome_json == canonical_outcome_json
            && self.canonical_outcome_sha256 == bytes_digest(canonical_outcome_json.as_bytes())
    }

    fn validate(&self) -> Result<()> {
        self.authority.validate()?;
        ensure!(
            !self.canonical_outcome_json.is_empty(),
            "retained default receipt proof has no canonical outcome JSON"
        );
        ensure!(
            self.canonical_outcome_sha256.len() == 64
                && self
                    .canonical_outcome_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
            "retained default receipt proof outcome digest is not a SHA-256 digest"
        );
        Ok(())
    }
}

/// A receipt-marked retained journal is intentionally pending until an
/// attached daemon validates its claim against the exact immutable receipt in
/// the session ledger.  Low-level filesystem recovery must never clean it.
pub struct RetainedEffectiveDefaultNeedsReceiptValidation {
    proof: RetainedDefaultReceiptProof,
    finalization: RetainedEffectiveDefaultPendingFinalization,
}

impl RetainedEffectiveDefaultNeedsReceiptValidation {
    pub fn proof(&self) -> &RetainedDefaultReceiptProof {
        &self.proof
    }

    pub fn into_finalization(self) -> RetainedEffectiveDefaultPendingFinalization {
        self.finalization
    }
}

/// A retained recovery pass that has converged filesystem bytes but has not
/// yet refreshed/recorded the correlated terminal receipt. The caller owns
/// the only legal cleanup token until that durable handoff completes.
pub struct RetainedEffectiveDefaultRecovery {
    transactions: Vec<RecoveredTransaction>,
    finalization: Option<RetainedEffectiveDefaultPendingFinalization>,
    needs_receipt_validation: Option<RetainedEffectiveDefaultNeedsReceiptValidation>,
}

impl RetainedEffectiveDefaultRecovery {
    pub fn into_parts(
        self,
    ) -> (
        Vec<RecoveredTransaction>,
        Option<RetainedEffectiveDefaultPendingFinalization>,
        Option<RetainedEffectiveDefaultNeedsReceiptValidation>,
    ) {
        (
            self.transactions,
            self.finalization,
            self.needs_receipt_validation,
        )
    }
}

impl std::fmt::Debug for RetainedEffectiveDefaultPendingFinalization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedEffectiveDefaultPendingFinalization")
            .field("result", &self.result)
            .field("has_transaction", &self.transaction_id.is_some())
            .finish()
    }
}

impl RetainedEffectiveDefaultPendingFinalization {
    pub fn result(&self) -> &EffectiveDefaultMutationResult {
        &self.result
    }

    /// Seal the exact daemon-owned authority that observed the retained
    /// mutation.  This is deliberately a separate, durable step after worker
    /// refresh: the generation is unknowable when the config journal is first
    /// prepared.  The retained verifier runs while updating the journal, so a
    /// replacement before this fence leaves the correlated transaction pending
    /// rather than minting a receipt for the replacement.
    pub fn bind_default_update_authority(
        &mut self,
        authority: DefaultUpdateAuthorityBinding,
    ) -> Result<()> {
        authority.validate()?;
        let Some(transaction_id) = self.transaction_id else {
            // An unchanged mutation has no journal to seal. Its caller still
            // persists the same binding together with the terminal receipt.
            return Ok(());
        };
        self.target.verify_binding()?;
        let _lock = self.target.acquire_lock()?;
        let Some(mut record) = self.target.load_journal()? else {
            anyhow::bail!("retained default journal disappeared before authority fence");
        };
        ensure!(
            record.transaction_id == transaction_id
                && matches!(
                    record.phase,
                    JournalPhase::Prepared | JournalPhase::Committed | JournalPhase::Compensating
                ),
            "retained default journal changed before authority fence"
        );
        let Some(correlation) = record.correlation.take() else {
            anyhow::bail!("retained default journal lost its terminal correlation");
        };
        match correlation.default_update_authority() {
            None => {
                // The authority seal is a one-way linearization boundary. A
                // subsequent recovery may retry this exact bind, but it can
                // never reinterpret an A-bound journal as B.
                record.correlation = Some(correlation.with_default_update_authority(authority)?);
                self.target.write_journal(&record)?;
            }
            Some(existing) if existing == &authority => {
                existing.validate()?;
                // Idempotent retry after a crash following the durable seal:
                // preserve the existing bytes rather than needlessly writing
                // the journal again.
                record.correlation = Some(correlation);
            }
            Some(existing) => {
                existing.validate()?;
                anyhow::bail!(
                    "retained default journal is already sealed for a different authority (stored {}@{}, requested {}@{})",
                    existing.authority_revision,
                    existing.config_generation,
                    authority.authority_revision,
                    authority.config_generation,
                );
            }
        }
        // Deliberately no further identity check here.  The preceding verifier
        // call is the operation's linearization point; a replacement after it
        // must not retroactively invalidate an A-bound receipt or cause a
        // second write through B.  Subsequent attachment operations verify and
        // fail closed instead.
        run_retained_authority_fence_hook_for_tests();
        crash_point_bail!(AfterRetainedAuthoritySealedBeforeReceipt);
        Ok(())
    }

    /// Record in the config journal that the daemon has already committed its
    /// separate durable terminal receipt, then retire only this transaction's
    /// private artifacts. The marker makes a cleanup retry idempotent without
    /// re-opening the terminal handoff after a crash in the cleanup window.
    pub fn finalize_after_terminal_receipt(
        self,
        receipt_proof: &RetainedDefaultReceiptProof,
    ) -> Result<()> {
        let Some(transaction_id) = self.transaction_id else {
            return Ok(());
        };
        self.target.verify_binding()?;
        let _lock = self.target.acquire_lock()?;
        let Some(mut record) = self.target.load_journal()? else {
            anyhow::bail!("retained default journal disappeared before terminal finalization");
        };
        if record.transaction_id != transaction_id
            || !matches!(
                record.phase,
                JournalPhase::Prepared
                    | JournalPhase::Committed
                    | JournalPhase::ReceiptEmitted
                    | JournalPhase::Compensating
            )
        {
            anyhow::bail!("retained default journal changed before terminal finalization");
        }
        let Some(TransactionCorrelation::RetainedDefaultUpdate {
            default_update_id,
            session_id,
            authority: Some(authority),
        }) = &record.correlation
        else {
            anyhow::bail!("retained default journal has no sealed authority receipt binding");
        };
        authority.validate()?;
        receipt_proof.validate()?;
        ensure!(
            receipt_proof.default_update_id == *default_update_id
                && receipt_proof.session_id == *session_id
                && receipt_proof.authority == *authority,
            "retained default receipt proof does not match its journal correlation"
        );
        if record.phase != JournalPhase::ReceiptEmitted {
            record.phase = JournalPhase::ReceiptEmitted;
            record.receipt_proof = Some(receipt_proof.clone());
            self.target.write_journal(&record)?;
        } else if record.receipt_proof.as_ref() != Some(receipt_proof) {
            anyhow::bail!("retained receipt-emitted journal proof does not match terminal receipt");
        }
        crash_point_bail!(AfterRetainedReceiptBeforeCleanup);
        self.target.verify_binding()?;
        self.target.remove_artifacts()
    }
}

/// Test-only crash seam for the daemon handoff that follows a retained commit.
/// In production this is an inline no-op. A simulated crash deliberately
/// leaves the committed journal/backup for retained recovery.
pub fn retained_default_after_refresh_before_terminal_receipt(
    scope_label: &str,
) -> Result<(), EffectiveDefaultError> {
    // The production crash-point macro intentionally compiles away. Keep this
    // parameter observably consumed in that configuration as well, while the
    // test-support expansion still uses it to identify the injected seam.
    let _ = scope_label;
    crash_point!(scope_label, AfterRetainedRefreshBeforeReceipt);
    Ok(())
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
    /// The daemon committed the correlated config-only terminal receipt in
    /// its durable session ledger. A crash after this marker must only retry
    /// private cleanup, never re-open the terminal handoff.
    ReceiptEmitted,
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
            Self::ReceiptEmitted => "receipt_emitted",
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
    /// Immutable receipt claim written only after the daemon has committed its
    /// terminal ledger row. Receipt-emitted retained journals require this
    /// proof *and* attached-daemon ledger validation before cleanup.
    receipt_proof: Option<RetainedDefaultReceiptProof>,
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

/// Capability-bound target for a config-only effective-default transaction.
///
/// The daemon captures this while attaching a worker. Every mutable artifact
/// — the selected `config.json`, its journal, rollback snapshot, and staged
/// replacement — is addressed by a one-component name under `directory`.
/// `canonical_config_path` is retained only for journal identity and redacted
/// diagnostics; it is never opened by the retained backend.
///
/// This is intentionally a config-only primitive. Session+default commits
/// still require the wider durable session authority and continue through the
/// ambient transaction path until they receive their own retained authority
/// contract. `SetDefaultModel` is config-only by protocol.
pub struct RetainedEffectiveDefaultTarget {
    directory: File,
    config_leaf: OsString,
    journal_leaf: OsString,
    backup_leaf: OsString,
    canonical_config_path: PathBuf,
    project_root: PathBuf,
    scope: EffectiveDefaultScope,
    verifier: Option<RetainedEffectiveDefaultVerifier>,
}

/// The generic owned storage descriptor for an effective-default mutation.
/// `RetainedEffectiveDefaultTarget` is its historical public name because the
/// daemon first used it for attached workers; path-authorized callers now use
/// this same descriptor after they have selected a layer.  In both cases the
/// held directory capability, not `canonical_config_path`, is the authority
/// for every leaf operation.
pub type CapturedEffectiveDefaultTarget = RetainedEffectiveDefaultTarget;

/// Immutable, bounded projection of every effective layer selected before an
/// ambient default mutation captured its write target. `target_index` records
/// that layer's original precedence position. Projection is deliberately data-only: once it exists,
/// post-write verification never rediscovers `COCKPIT_CONFIG` or opens a
/// pathname that an attacker can replace.
struct CapturedEffectiveDefaultLayerProjection {
    layers: Vec<crate::config::WorkspaceConfigLayerSnapshot>,
    target_index: usize,
}

impl CapturedEffectiveDefaultLayerProjection {
    fn capture_lower(target: &ResolvedTarget) -> Result<Self> {
        let mut layers = Vec::with_capacity(target.lower_paths.len().saturating_add(1));
        for path in &target.lower_paths {
            layers.push(capture_ambient_config_layer_snapshot(&path)?);
        }
        let target_index = layers.len();
        Ok(Self {
            layers,
            target_index,
        })
    }

    fn push_captured_target(&mut self, target: &CapturedEffectiveDefaultTarget) -> Result<()> {
        anyhow::ensure!(
            self.layers.len() == self.target_index,
            "captured target was inserted more than once"
        );
        self.layers.push(Self::snapshot_target(target)?);
        Ok(())
    }

    /// Capture every non-target layer before the target directory becomes the
    /// write authority. Recovery can legitimately own a lower-precedence
    /// layer after a later layer appeared, so the target is inserted at its
    /// original position rather than implicitly treated as the final layer.
    fn capture_all_except_target(
        paths: &[PathBuf],
        target_index: usize,
    ) -> Result<Vec<crate::config::WorkspaceConfigLayerSnapshot>> {
        anyhow::ensure!(
            target_index < paths.len(),
            "captured effective-default target index is out of range"
        );
        let mut layers = Vec::with_capacity(paths.len().saturating_sub(1));
        for (index, path) in paths.iter().enumerate() {
            if index != target_index {
                layers.push(capture_ambient_config_layer_snapshot(path)?);
            }
        }
        Ok(layers)
    }

    fn from_captured_non_target_layers(
        mut non_target_layers: Vec<crate::config::WorkspaceConfigLayerSnapshot>,
        target_index: usize,
        target: &CapturedEffectiveDefaultTarget,
    ) -> Result<Self> {
        anyhow::ensure!(
            target_index <= non_target_layers.len(),
            "captured effective-default target insertion index is out of range"
        );
        non_target_layers.insert(target_index, Self::snapshot_target(target)?);
        Ok(Self {
            layers: non_target_layers,
            target_index,
        })
    }

    fn snapshot_target(
        target: &CapturedEffectiveDefaultTarget,
    ) -> Result<crate::config::WorkspaceConfigLayerSnapshot> {
        crate::config::files::snapshot_workspace_config_layer_from_retained_config_directory(
            &target.directory,
            &target.config_leaf,
            &target.canonical_config_path,
            None,
            None,
        )
    }

    fn replace_target_snapshot(&mut self, target: &CapturedEffectiveDefaultTarget) -> Result<()> {
        let snapshot = Self::snapshot_target(target)?;
        let Some(target_layer) = self.layers.get_mut(self.target_index) else {
            anyhow::bail!("captured effective-default projection has no target layer");
        };
        *target_layer = snapshot;
        Ok(())
    }

    fn providers(&self) -> Result<ProvidersConfig> {
        ConfigDoc::providers_from_workspace_layer_snapshots(&self.layers)
    }

    fn inherited_default(&self) -> Result<Option<ActiveModelRef>> {
        let lower = self.layers.get(..self.target_index).unwrap_or_default();
        Ok(ConfigDoc::providers_from_workspace_layer_snapshots(lower)?.active_model)
    }

    fn projected_after_target_config(&self, bytes: &[u8]) -> Result<ProvidersConfig> {
        let Some(target_layer) = self.layers.get(self.target_index) else {
            anyhow::bail!("captured effective-default projection has no target layer");
        };
        let mut layers = self.layers.clone();
        *layers
            .get_mut(self.target_index)
            .expect("checked target index") =
            crate::config::files::workspace_config_layer_snapshot_with_config_json(
                target_layer,
                Some(bytes.to_vec()),
            );
        ConfigDoc::providers_from_workspace_layer_snapshots(&layers)
    }

    fn target_declares_active_model(&self) -> bool {
        self.layers
            .get(self.target_index)
            .and_then(|layer| layer.config_json.as_deref())
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
            .is_some_and(|raw| {
                raw.get("active_model")
                    .is_some_and(|value| !value.is_null())
            })
    }
}

/// A higher-layer proof that the pathname binding used to create a retained
/// config descriptor still denotes the same directory identities. The config
/// crate owns all IO through the retained handle; the daemon supplies this
/// check so an A→B path replacement becomes a typed rejection rather than a
/// success for an attachment that no longer exists.
pub type RetainedEffectiveDefaultVerifier =
    std::sync::Arc<dyn Fn() -> Result<()> + Send + Sync + 'static>;

impl std::fmt::Debug for RetainedEffectiveDefaultTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedEffectiveDefaultTarget")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl RetainedEffectiveDefaultTarget {
    /// Construct a descriptor from a daemon-held config-directory handle.
    /// All leaf names are checked at the lower-level openat/NtCreateFile
    /// boundary as well; validating them here makes an invalid descriptor a
    /// creation error rather than a late mutation surprise.
    pub fn new(
        directory: File,
        config_leaf: OsString,
        journal_leaf: OsString,
        backup_leaf: OsString,
        canonical_config_path: PathBuf,
        project_root: PathBuf,
        scope: EffectiveDefaultScope,
    ) -> Result<Self> {
        ensure_single_leaf(&config_leaf)?;
        ensure_single_leaf(&journal_leaf)?;
        ensure_single_leaf(&backup_leaf)?;
        ensure!(
            canonical_config_path.is_absolute(),
            "retained config target path is not absolute"
        );
        ensure!(
            project_root.is_absolute(),
            "retained config project root is not absolute"
        );
        let journal_path = journal_path_for_config(&canonical_config_path);
        let expected_journal = journal_path
            .file_name()
            .context("retained journal has no filename")?;
        let backup_path = backup_path_for_config(&canonical_config_path);
        let expected_backup = backup_path
            .file_name()
            .context("retained backup has no filename")?;
        ensure!(
            expected_journal == journal_leaf.as_os_str()
                && expected_backup == backup_leaf.as_os_str(),
            "retained default transaction artifact descriptor does not match its config target"
        );
        Ok(Self {
            directory,
            config_leaf,
            journal_leaf,
            backup_leaf,
            canonical_config_path,
            project_root,
            scope,
            verifier: None,
        })
    }

    /// Capture the selected ambient target into the same one-directory
    /// capability used by attached workers.  Path discovery is deliberately
    /// complete before this point; callers must not reopen `target.path` for
    /// mutable work after receiving this descriptor.
    ///
    /// The canonical display/lock spelling and directory descriptor are
    /// captured as one stable pair. Retrying on a replacement between the two
    /// observations prevents a mixed descriptor whose lock identity names A
    /// while its openat operations target B.
    pub fn capture_ambient(
        project_root: &Path,
        target: &ResolvedTarget,
    ) -> Result<CapturedEffectiveDefaultTarget> {
        let project_root = std::fs::canonicalize(project_root).with_context(|| {
            format!(
                "canonicalizing effective-default project root {}",
                project_root.display()
            )
        })?;
        let leaf = target
            .path
            .file_name()
            .context("effective-default target has no config filename")?
            .to_os_string();
        for _ in 0..3 {
            let canonical_target = canonical_config_path(&target.path);
            let parent = canonical_target
                .parent()
                .context("effective-default target has no parent")?;
            let directory = crate::config::files::open_directory_handle_nofollow(parent)?;
            if !crate::config::files::directory_handle_matches_path(&directory, parent)? {
                continue;
            }
            let journal_leaf = journal_path_for_config(&canonical_target)
                .file_name()
                .context("effective-default journal has no filename")?
                .to_os_string();
            let backup_leaf = backup_path_for_config(&canonical_target)
                .file_name()
                .context("effective-default backup has no filename")?
                .to_os_string();
            return Self::new(
                directory,
                leaf.clone(),
                journal_leaf,
                backup_leaf,
                canonical_target,
                project_root.clone(),
                target.scope.clone(),
            );
        }
        anyhow::bail!("effective-default target directory changed during capability capture")
    }

    /// Add the daemon's attach-identity verifier. It is intentionally
    /// optional for lower-layer unit tests and local repair tooling, but every
    /// attached-session mutation installs it before beginning the transaction.
    pub fn with_verifier(mut self, verifier: RetainedEffectiveDefaultVerifier) -> Self {
        self.verifier = Some(verifier);
        self
    }

    fn scope_label(&self) -> &str {
        self.scope.as_str()
    }

    fn display_path(&self, leaf: &std::ffi::OsStr) -> PathBuf {
        self.canonical_config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(leaf)
    }

    fn read_leaf(&self, leaf: &std::ffi::OsStr) -> Result<Option<Vec<u8>>> {
        read_optional_leaf_from_directory_handle(
            &self.directory,
            leaf,
            crate::config::MAX_WORKSPACE_CONFIG_FILE_BYTES,
        )
    }

    fn read_config(&self) -> Result<Vec<u8>> {
        Ok(self
            .read_leaf(&self.config_leaf)?
            .unwrap_or_else(|| b"{}\n".to_vec()))
    }

    fn write_private_leaf(&self, leaf: &std::ffi::OsStr, bytes: &[u8]) -> Result<()> {
        atomic_write_leaf_from_retained_directory(
            &self.directory,
            leaf,
            &self.display_path(leaf),
            bytes,
        )
    }

    fn write_journal(&self, record: &JournalRecord) -> Result<()> {
        let pretty =
            serde_json::to_string_pretty(record).context("serializing retained journal")?;
        self.write_private_leaf(&self.journal_leaf, format!("{pretty}\n").as_bytes())
    }

    fn load_journal(&self) -> Result<Option<JournalRecord>> {
        let Some(bytes) = self.read_leaf(&self.journal_leaf)? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_slice(&bytes).context("parsing retained effective-default journal")?,
        ))
    }

    /// Read only the durable correlation under this target's target-local
    /// lock. Daemon policy code uses this to recognize a pending operation
    /// whose retained source has since become ineligible; it must leave that
    /// journal untouched rather than accidentally reuse its client id at a
    /// different currently-selected layer. The correlation is intentionally
    /// secret-free (session/update ids plus an opaque authority digest).
    pub fn retained_transaction_correlation(&self) -> Result<Option<TransactionCorrelation>> {
        self.verify_binding()?;
        let _lock = self.acquire_lock()?;
        Ok(self.load_journal()?.and_then(|record| record.correlation))
    }

    fn remove_leaf(&self, leaf: &std::ffi::OsStr) -> Result<()> {
        remove_leaf_from_retained_directory(&self.directory, leaf, &self.display_path(leaf))
    }

    fn remove_artifacts(&self) -> Result<()> {
        self.remove_leaf(&self.backup_leaf)?;
        self.remove_leaf(&self.journal_leaf)
    }

    fn target_path_digest(&self) -> String {
        path_digest(&self.canonical_config_path)
    }

    fn verify_binding(&self) -> Result<()> {
        match &self.verifier {
            Some(verifier) => verifier(),
            None => Ok(()),
        }
    }

    fn acquire_lock(&self) -> Result<ConfigMutationLock> {
        ConfigMutationLock::acquire_retained(
            &self.directory,
            &self.canonical_config_path,
            self.canonical_config_path
                .parent()
                .unwrap_or_else(|| Path::new(".")),
        )
    }

    fn acquire_lock_cancellable(&self, cancelled: &AtomicBool) -> Result<ConfigMutationLock> {
        ConfigMutationLock::acquire_retained_cancellable(
            &self.directory,
            &self.canonical_config_path,
            self.canonical_config_path
                .parent()
                .unwrap_or_else(|| Path::new(".")),
            cancelled,
        )
    }

    fn ensure_writable(&self) -> Result<()> {
        crate::config::files::probe_directory_writable_from_retained_directory(
            &self.directory,
            self.canonical_config_path
                .parent()
                .unwrap_or_else(|| Path::new(".")),
        )
    }

    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            directory: self.directory.try_clone()?,
            config_leaf: self.config_leaf.clone(),
            journal_leaf: self.journal_leaf.clone(),
            backup_leaf: self.backup_leaf.clone(),
            canonical_config_path: self.canonical_config_path.clone(),
            project_root: self.project_root.clone(),
            scope: self.scope.clone(),
            verifier: self.verifier.clone(),
        })
    }
}

/// Capture one selected effective layer through a stable directory descriptor.
/// The same bounded retry used by the mutation target prevents a pathname
/// replacement from mixing a canonical layer spelling with bytes from a
/// successor directory.
fn capture_ambient_config_layer_snapshot(
    config_path: &Path,
) -> Result<crate::config::WorkspaceConfigLayerSnapshot> {
    let leaf = config_path
        .file_name()
        .context("effective-default layer has no config filename")?
        .to_os_string();
    for _ in 0..3 {
        let canonical_config_path = canonical_config_path(config_path);
        let parent = canonical_config_path
            .parent()
            .context("effective-default layer has no parent")?;
        let directory = crate::config::files::open_directory_handle_nofollow(parent)?;
        if !crate::config::files::directory_handle_matches_path(&directory, parent)? {
            continue;
        }
        let snapshot =
            crate::config::files::snapshot_workspace_config_layer_from_retained_config_directory(
                &directory,
                &leaf,
                &canonical_config_path,
                None,
                None,
            )?;
        if crate::config::files::directory_handle_matches_path(&directory, parent)? {
            return Ok(snapshot);
        }
    }
    anyhow::bail!("effective-default layer changed during capability capture")
}

/// Finish ambient selection by retaining every lower layer as immutable bytes
/// and the selected target as an owned directory capability. The target is
/// captured last; from that point on the mutation, recovery, and verification
/// must use only `projection` and `target` rather than a discovered path.
fn capture_ambient_mutation(
    project_root: &Path,
    selected: &ResolvedTarget,
) -> Result<(
    CapturedEffectiveDefaultTarget,
    CapturedEffectiveDefaultLayerProjection,
)> {
    let mut projection = CapturedEffectiveDefaultLayerProjection::capture_lower(selected)?;
    let target = RetainedEffectiveDefaultTarget::capture_ambient(project_root, selected)?;
    projection.push_captured_target(&target)?;
    Ok((target, projection))
}

fn ensure_single_leaf(leaf: &std::ffi::OsStr) -> Result<()> {
    let mut components = Path::new(leaf).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => anyhow::bail!("retained effective-default descriptor requires one normal leaf"),
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

/// The private rollback snapshot paired with [`journal_path_for_layer`].
///
/// This is exposed for capability-backed readers which have already retained
/// the target config directory and must therefore name the *same* transaction
/// artifacts without reopening the target path.  It is deliberately a path
/// naming helper only; mutation and durable recovery remain owned by this
/// module's normal journal protocol.
pub fn backup_path_for_layer(config_path: &Path) -> PathBuf {
    backup_path_for_config(config_path)
}

fn config_parent(config_path: &Path) -> &Path {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn load_journal(path: &Path) -> Result<Option<JournalRecord>> {
    let Some(raw) = read_file_nofollow_bounded(path, MAX_EFFECTIVE_DEFAULT_JOURNAL_BYTES)? else {
        return Ok(None);
    };
    let record: JournalRecord = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing journal {}", path.display()))?;
    Ok(Some(record))
}

/// The only ambient pre-lock inspection of a journal.  In particular, a
/// retained default-update correlation is an ownership boundary, not merely a
/// recovery mode: once recognized, the ambient path must not canonicalize the
/// target, derive/open a lock sidecar, open the config or backup, or construct
/// any recovery/session context from a mutable pathname.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AmbientJournalClassification {
    Absent,
    RetainedDefaultUpdate,
    NonRetained(JournalRecord),
}

fn classify_ambient_journal(journal_path: &Path) -> Result<AmbientJournalClassification> {
    let Some(raw) = read_file_nofollow_bounded(journal_path, MAX_EFFECTIVE_DEFAULT_JOURNAL_BYTES)?
    else {
        return Ok(AmbientJournalClassification::Absent);
    };
    let record: JournalRecord = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing journal {}", journal_path.display()))?;
    if record
        .correlation
        .as_ref()
        .is_some_and(TransactionCorrelation::is_retained_default_update)
    {
        return Ok(AmbientJournalClassification::RetainedDefaultUpdate);
    }
    Ok(AmbientJournalClassification::NonRetained(record))
}

/// Find capability-owned journals in the supplied directory spelling before
/// deriving a canonical sidecar name for one particular config leaf.
///
/// Journal names are intentionally keyed by the canonical config path so
/// aliases share one transaction. That key cannot be derived before this
/// retained-correlation fence: canonicalizing a replaced ambient path is
/// itself authority work. We therefore perform a bounded, read-only scan of
/// journal metadata first. The conservative rule (any retained journal in
/// this directory stops this ambient pass) is deliberate: a later exact
/// retained worker has the directory capability required to distinguish and
/// finish it, while ambient recovery must never risk treating it as a path
/// journal. Malformed/oversized candidate metadata fails closed.
fn ambient_parent_contains_retained_journal(config_path: &Path) -> Result<bool> {
    let parent = config_parent(config_path);
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "enumerating effective-default journals in {}",
                    parent.display()
                )
            });
        }
    };
    let mut candidates = 0usize;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "enumerating effective-default journals in {}",
                parent.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(JOURNAL_PREFIX) || !name.ends_with(".json") {
            continue;
        }
        candidates += 1;
        anyhow::ensure!(
            candidates <= MAX_AMBIENT_JOURNAL_PREFLIGHT_CANDIDATES,
            "too many effective-default journals beside {}; refusing ambient recovery",
            config_path.display()
        );
        if matches!(
            classify_ambient_journal(&entry.path())?,
            AmbientJournalClassification::RetainedDefaultUpdate
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The complete ambient classification fence.  Do not call
/// [`journal_path_for_config`] before this function: it canonicalizes the
/// mutable target spelling to derive a lock/sidecar identity.
fn classify_ambient_target_journal(config_path: &Path) -> Result<AmbientJournalClassification> {
    if ambient_parent_contains_retained_journal(config_path)? {
        return Ok(AmbientJournalClassification::RetainedDefaultUpdate);
    }
    classify_ambient_journal(&journal_path_for_config(config_path))
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

/// Project the exact `config.json` bytes a default-model mutation would
/// commit, without acquiring a pathname or touching the filesystem.  The
/// retained daemon backend uses this to compute a clear's inherited value
/// from the same captured layer chain that it will mutate.
pub fn projected_config_bytes_for_default_update(
    config_bytes: &[u8],
    requested: Option<&ActiveModelRef>,
) -> Result<Vec<u8>> {
    replacement_bytes(config_bytes, requested)
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

/// Validate a clear result already projected from a capability-bound layer
/// chain.  Kept public so the daemon can use the shared policy/error contract
/// without falling back to path-based effective-config discovery.
pub fn validate_projected_inherited_default(
    inherited: Option<&ActiveModelRef>,
    effective: &ProvidersConfig,
    scope_label: &str,
) -> Result<(), EffectiveDefaultError> {
    validate_inherited_default(inherited, effective, scope_label)
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

/// Project the bytes a read-only, capability-backed config reader may expose
/// while the *exact* effective-default transaction for `canonical_config_path`
/// is still present.  This never mutates, deletes, or pathname-opens an
/// artifact.  The daemon's normal recovery pass remains responsible for the
/// durable convergence; this pure view simply preserves its read contract
/// until that pass can run under the required authority.
///
/// `canonical_config_path` must be the already-canonical descriptor captured
/// with the retained directory capability.  In particular, this helper must
/// not call `canonicalize`: doing so would reintroduce the pathname race the
/// capability boundary exists to prevent.
pub(crate) fn project_retained_effective_default_bytes(
    canonical_config_path: &Path,
    current: Option<Vec<u8>>,
    journal: Option<&[u8]>,
    backup: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    let Some(journal) = journal else {
        return Ok(current);
    };
    let record: JournalRecord =
        serde_json::from_slice(journal).context("parsing retained effective-default journal")?;

    // A stale/foreign artifact must not make an otherwise selected config
    // unreadable.  The artifact is not this leaf's transaction: the exact
    // key plus durable target digest is the authoritative association.
    if record.target_path_digest != path_digest(canonical_config_path)
        || record.project_root.is_empty()
        || !Path::new(&record.project_root).is_absolute()
    {
        return Ok(current);
    }

    let current_bytes = current.as_deref().unwrap_or(b"{}\n");
    let current_digest = bytes_digest(current_bytes);
    let prior = || -> Result<&[u8]> {
        let prior = backup.context("effective-default rollback snapshot is missing")?;
        anyhow::ensure!(
            bytes_digest(prior) == record.old_config_digest,
            "effective-default rollback snapshot does not match its journal"
        );
        Ok(prior)
    };

    // Readers without durable session/event authority must mask every
    // session-bearing or correlated transaction with the recorded prior
    // bytes, exactly as `masked_layers` does for pathname reads.
    if record.needs_session_authority() || record.correlation.is_some() {
        anyhow::ensure!(
            current_digest == record.old_config_digest
                || current_digest == record.new_config_digest,
            "retained config bytes do not match the effective-default journal"
        );
        return Ok(Some(prior()?.to_vec()));
    }

    // Config-only transactions are recoverable without session authority.
    // We project the deterministic side recovery would converge to, while
    // leaving the retained artifacts for the normal, durable recovery pass.
    match record.phase {
        JournalPhase::Committed | JournalPhase::SessionCommitted | JournalPhase::ReceiptEmitted => {
            if current_digest == record.new_config_digest {
                return Ok(current);
            }
            anyhow::ensure!(
                current_digest == record.old_config_digest,
                "retained config bytes do not match the effective-default journal"
            );
            let rebuilt = replacement_bytes(prior()?, record.requested.as_ref())?;
            anyhow::ensure!(
                bytes_digest(&rebuilt) == record.new_config_digest,
                "effective-default journal cannot reproduce its committed config"
            );
            Ok(Some(rebuilt))
        }
        JournalPhase::Prepared | JournalPhase::Compensating => {
            // This is the same short-circuit as `compensate`: when the
            // target layer already still holds the recorded prior bytes,
            // recovery needs neither a rollback snapshot nor a write.  A
            // missing backup must not turn that provably safe state into an
            // attach/refresh outage.
            if current_digest == record.old_config_digest {
                return Ok(current);
            }
            anyhow::ensure!(
                current_digest == record.new_config_digest,
                "retained config bytes do not match the effective-default journal"
            );
            Ok(Some(prior()?.to_vec()))
        }
    }
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
        // Classify before consulting recovery backoff, deriving a lock
        // identity, or opening any other sibling. A retained journal belongs
        // solely to its held-directory worker and is deliberately invisible
        // to every ambient recovery optimization and cleanup path.
        match classify_ambient_target_journal(path)? {
            AmbientJournalClassification::Absent => {
                // Fast path: no journal file means no recovery work, so an
                // ordinary config read never pays for the cross-process lock.
                // It is still the right place to sweep crash-window debris:
                // an orphan backup or a stale temporary replacement with no
                // owning journal can only come from a process killed mid-
                // transaction.
                sweep_orphans(path);
                continue;
            }
            AmbientJournalClassification::RetainedDefaultUpdate => continue,
            AmbientJournalClassification::NonRetained(_) => {}
        }
        let journal_path = journal_path_for_config(path);
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
    let initial = match classify_ambient_target_journal(config_path)? {
        AmbientJournalClassification::Absent => return Ok(Vec::new()),
        AmbientJournalClassification::RetainedDefaultUpdate => {
            tracing::debug!("leaving retained default-update journal for capability recovery");
            return Ok(Vec::new());
        }
        AmbientJournalClassification::NonRetained(record) => record,
    };

    // A replacement can win after the preliminary pathname classification.
    // Capture the current target *after* this seam, then only use its held
    // directory for the lock, journal reread, config repair, and cleanup.
    // In particular, there is no compatibility pathname reopen after the
    // capture, so an A→B swap cannot move a recovery write onto B.
    run_ambient_recovery_classification_hook_for_tests();
    note_ambient_recovery_target_canonicalization_for_tests();
    let (target, mut projection) = capture_ambient_recovery_mutation(config_path, &initial)?;
    if target.load_journal()?.as_ref().is_some_and(|record| {
        record
            .correlation
            .as_ref()
            .is_some_and(TransactionCorrelation::is_retained_default_update)
    }) {
        tracing::debug!(
            "leaving newly captured retained default-update journal for capability recovery"
        );
        return Ok(Vec::new());
    }
    note_ambient_recovery_lock_acquisition_for_tests();
    let lock = target.acquire_lock()?;
    let recovered = recover_captured_under_lock(&target, &mut projection, recovery)?;
    drop(lock);
    Ok(recovered)
}

/// Finish ambient recovery selection before converting it to the same held
/// target/projection pair used by mutation. A changed `COCKPIT_CONFIG` or
/// layer order cannot make a stale journal recover through an unrelated
/// replacement layer: its exact target must still be an active layer in the
/// recorded project context, and its original precedence position is retained
/// in the projection.
fn capture_ambient_recovery_mutation(
    config_path: &Path,
    record: &JournalRecord,
) -> Result<(
    CapturedEffectiveDefaultTarget,
    CapturedEffectiveDefaultLayerProjection,
)> {
    if record.project_root.is_empty() || !Path::new(&record.project_root).is_absolute() {
        anyhow::bail!("effective-default journal project root is missing or not absolute");
    }
    if let Some(reason) = journal_context_error(record, config_path) {
        anyhow::bail!("effective-default journal is out of context: {reason}");
    }
    let project_root = PathBuf::from(&record.project_root);
    let paths = config_file_paths_for_load(&project_root);
    let target_index = paths
        .iter()
        .position(|path| canonical_config_path(path) == canonical_config_path(config_path))
        .context("effective-default journal target is no longer an active config layer")?;
    let selected_path = &paths[target_index];
    // Every pathname-backed layer snapshot is acquired before the target
    // directory is captured. Once the target exists, recovery only touches
    // those immutable bytes and its held directory capability.
    let non_target_layers =
        CapturedEffectiveDefaultLayerProjection::capture_all_except_target(&paths, target_index)?;
    let selected = ResolvedTarget {
        path: selected_path.clone(),
        scope: record.scope.clone(),
        lower_paths: paths[..target_index].to_vec(),
    };
    let target = RetainedEffectiveDefaultTarget::capture_ambient(&project_root, &selected)?;
    let projection = CapturedEffectiveDefaultLayerProjection::from_captured_non_target_layers(
        non_target_layers,
        target_index,
        &target,
    )?;
    Ok((target, projection))
}

/// Remove crash-window debris through a captured directory capability. A
/// transaction creates its backup only while holding the same target-local
/// lock, so a missing journal under that lock proves the backup has no owner.
/// The temporary scan is likewise rooted in the held directory, never a
/// successor that happens to acquire its old pathname.
fn sweep_orphans(config_path: &Path) {
    // The retained-correlation preflight is intentionally the only pathname
    // observation before capture. A retained record belongs to its attached
    // worker and is invisible to ambient cleanup.
    if !matches!(
        ambient_parent_contains_retained_journal(config_path),
        Ok(false)
    ) {
        return;
    }
    let Ok(target) = capture_ambient_orphan_target(config_path) else {
        return;
    };
    let directory_key = target
        .canonical_config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let first_scan =
        SWEPT_DIRECTORIES.with(|swept| swept.borrow_mut().insert(directory_key.clone()));
    if !first_scan {
        return;
    }
    note_ambient_recovery_target_canonicalization_for_tests();
    note_ambient_recovery_lock_acquisition_for_tests();
    let lock = match target.acquire_lock() {
        Ok(lock) => lock,
        Err(_) => {
            SWEPT_DIRECTORIES.with(|swept| {
                swept.borrow_mut().remove(&directory_key);
            });
            return;
        }
    };
    sweep_captured_orphans_locked(&target);
    drop(lock);
}

/// Construct just enough descriptor for no-journal cleanup. The descriptor's
/// project/scope values are never used to authorize a write here; the held
/// parent and exact artifact leaves are the sole authority.
fn capture_ambient_orphan_target(config_path: &Path) -> Result<CapturedEffectiveDefaultTarget> {
    let parent = config_parent(config_path);
    let selected = ResolvedTarget {
        path: config_path.to_path_buf(),
        scope: EffectiveDefaultScope::Project,
        lower_paths: Vec::new(),
    };
    RetainedEffectiveDefaultTarget::capture_ambient(parent, &selected)
}

fn sweep_captured_orphans_locked(target: &CapturedEffectiveDefaultTarget) {
    // A journal that appeared after the preflight is read through A's held
    // directory. Never sweep any of its artifacts, regardless of correlation.
    if !matches!(target.load_journal(), Ok(None)) {
        return;
    }
    if let Err(error) = target.remove_leaf(&target.backup_leaf) {
        tracing::debug!(%error, "could not sweep an orphaned rollback snapshot");
    }
    match crate::config::files::stale_private_temp_leaves_from_retained_directory(
        &target.directory,
        STALE_TEMP_AGE,
    ) {
        Ok(leaves) => {
            for leaf in leaves {
                let display = target.display_path(&leaf);
                if let Err(error) =
                    remove_leaf_from_retained_directory(&target.directory, &leaf, &display)
                {
                    tracing::debug!(%error, "could not sweep a stale effective-default temporary");
                }
            }
        }
        Err(error) => {
            tracing::debug!(%error, "could not enumerate retained effective-default temporaries")
        }
    }
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

/// Mutate a config-only default through an attach-time retained directory.
///
/// This is the capability backend for daemon `SetDefaultModel`.  It shares
/// the stable cross-process lock, journal record format, digest checks, and
/// durable ordering of the ambient engine, but it deliberately performs every
/// selected-layer operation relative to `target.directory`.  In particular it
/// does not call `COCKPIT_CONFIG`, layer discovery, canonicalization, or any
/// path-based config/journal helper after the target has been captured.
///
/// The caller supplies the effective value it has already projected from the
/// same retained layer chain. That keeps policy validation and final worker
/// snapshot publication outside this low-level transaction while preserving a
/// complete, durable record for recovery.
pub fn mutate_effective_default_retained(
    target: &RetainedEffectiveDefaultTarget,
    requested: Option<&ActiveModelRef>,
    expected_effective: Option<ActiveModelRef>,
    correlation: TransactionCorrelation,
) -> Result<RetainedEffectiveDefaultPendingFinalization, EffectiveDefaultError> {
    let scope_label = target.scope_label();
    if !matches!(
        &correlation,
        TransactionCorrelation::RetainedDefaultUpdate { .. }
    ) {
        return Err(EffectiveDefaultError::new(
            "the retained config-only default backend requires a default-update correlation",
            "effective_default_invalid_correlation",
            Some(scope_label.to_string()),
        ));
    }
    if let Some(authority) = correlation.default_update_authority()
        && let Err(error) = authority.validate()
    {
        return Err(EffectiveDefaultError::new(
            safe_cause("the retained default receipt authority is invalid", &error),
            "effective_default_invalid_authority",
            Some(scope_label.to_string()),
        ));
    }
    target.verify_binding().map_err(|error| {
        EffectiveDefaultError::new(
            safe_cause(
                "the retained config authority changed before mutation",
                &error,
            ),
            "effective_default_authority_changed",
            Some(scope_label.to_string()),
        )
    })?;
    // The retained backend must never acquire its serialization primitive by
    // reopening the captured pathname. This lock leaf is opened relative to
    // the held config directory and is the same deterministic sibling leaf
    // used by an ambient writer for this exact canonical target.
    let lock = target.acquire_lock().map_err(|error| {
        EffectiveDefaultError::new(
            safe_cause(
                "the retained config mutation lock could not be acquired",
                &error,
            ),
            "effective_default_lock_failed",
            Some(scope_label.to_string()),
        )
    })?;

    // We never discard a correlated transaction without delivering its one
    // terminal result. A later retained recovery pass owns it; this request
    // fails closed instead of overwriting its journal/backup pair.
    if target
        .load_journal()
        .map_err(|error| {
            EffectiveDefaultError::new(
                safe_cause(
                    "the retained default-model journal could not be read",
                    &error,
                ),
                "effective_default_recovery_blocked",
                Some(scope_label.to_string()),
            )
        })?
        .is_some()
    {
        return Err(EffectiveDefaultError::new(
            "another default-model update for this configuration layer is still pending; run `cockpit doctor` to inspect it",
            "effective_default_journal_conflict",
            Some(scope_label.to_string()),
        ));
    }

    let old_bytes = target.read_config().map_err(|error| {
        EffectiveDefaultError::new(
            safe_cause("the retained config layer could not be read", &error),
            "effective_default_read_failed",
            Some(scope_label.to_string()),
        )
    })?;
    let old_digest = bytes_digest(&old_bytes);
    let old_active = active_model_from_config_bytes(&old_bytes);
    let should_write = match requested {
        Some(requested) => old_active.as_ref() != Some(requested),
        None => old_active.is_some(),
    };
    if !should_write {
        drop(lock);
        return target
            .try_clone()
            .map(|target| RetainedEffectiveDefaultPendingFinalization {
                target,
                result: EffectiveDefaultMutationResult {
                    selection: expected_effective,
                    generation: 0,
                    scope_label: scope_label.to_string(),
                    wrote: false,
                    unchanged: true,
                },
                transaction_id: None,
            })
            .map_err(|error| {
                EffectiveDefaultError::new(
                    safe_cause("the retained config authority could not be preserved for receipt verification", &error),
                    "effective_default_authority_changed",
                    Some(scope_label.to_string()),
                )
            });
    }

    let new_bytes = replacement_bytes(&old_bytes, requested).map_err(|error| {
        EffectiveDefaultError::new(
            format!("config.json cannot accept a default update: {error}"),
            "effective_default_malformed_config",
            Some(scope_label.to_string()),
        )
    })?;
    let new_digest = bytes_digest(&new_bytes);
    let mut record = JournalRecord {
        transaction_id: Uuid::new_v4(),
        project_root: target.project_root.display().to_string(),
        trust_mode: crate::config::trust::current_workspace_trust_policy()
            .map(|policy| policy.mode.as_str().to_string()),
        scope: target.scope.clone(),
        target_path_digest: target.target_path_digest(),
        old_config_digest: old_digest,
        new_config_digest: new_digest,
        requested: requested.cloned(),
        expected_effective: expected_effective.clone(),
        session: JournalSession::None,
        correlation: Some(correlation),
        receipt_proof: None,
        phase: JournalPhase::Prepared,
    };

    if let Err(error) = target.write_private_leaf(&target.backup_leaf, &old_bytes) {
        return Err(EffectiveDefaultError::new(
            safe_cause(
                "the retained private rollback snapshot could not be prepared",
                &error,
            ),
            "effective_default_backup_failed",
            Some(scope_label.to_string()),
        ));
    }
    if let Err(error) = target.write_journal(&record) {
        let _ = target.remove_leaf(&target.backup_leaf);
        return Err(EffectiveDefaultError::new(
            safe_cause(
                "the retained default-model journal could not be prepared",
                &error,
            ),
            "effective_default_journal_failed",
            Some(scope_label.to_string()),
        ));
    }
    crash_point!(scope_label, AfterJournalPrepared);
    run_retained_mutation_hook_for_tests();
    if let Err(error) = target.verify_binding() {
        return retained_restore_or_pending(
            target,
            &old_bytes,
            &record,
            scope_label,
            &safe_cause(
                "the retained config authority changed before replacement",
                &error,
            ),
        );
    }

    if let Err(error) = target.write_private_leaf(&target.config_leaf, &new_bytes) {
        return retained_restore_or_pending(
            target,
            &old_bytes,
            &record,
            scope_label,
            &safe_cause(
                "the retained config replacement could not be committed",
                &error,
            ),
        );
    }
    crash_point!(scope_label, AfterConfigReplaced);
    if let Err(error) = target.verify_binding() {
        return retained_restore_or_pending(
            target,
            &old_bytes,
            &record,
            scope_label,
            &safe_cause(
                "the retained config authority changed after replacement",
                &error,
            ),
        );
    }

    record.phase = JournalPhase::Committed;
    if let Err(error) = target.write_journal(&record) {
        // A correlated commit is never allowed to fall through as a bare
        // success: without a durable committed marker its later terminal
        // handoff would be unrecoverable. Restore or retain the prepared
        // journal instead.
        return retained_restore_or_pending(
            target,
            &old_bytes,
            &record,
            scope_label,
            &safe_cause(
                "the retained committed journal phase could not be recorded",
                &error,
            ),
        );
    }
    crash_point!(scope_label, AfterCommittedMarker);
    crash_point!(scope_label, AfterRetainedCommitBeforeRefresh);
    if let Err(error) = target.verify_binding() {
        return retained_restore_or_pending(
            target,
            &old_bytes,
            &record,
            scope_label,
            &safe_cause(
                "the retained config authority changed before completion",
                &error,
            ),
        );
    }

    // Dispatch must refresh the same retained worker snapshot and publish the
    // correlated receipt before this committed journal is retired. Returning a
    // capability-bound finalization token preserves recovery across any crash
    // or failed refresh in that handoff window.
    let finalization_target = target.try_clone().map_err(|error| {
        EffectiveDefaultError::pending(
            scope_label,
            &safe_cause(
                "the retained config authority could not be preserved for terminal finalization",
                &error,
            ),
        )
    })?;
    Ok(RetainedEffectiveDefaultPendingFinalization {
        target: finalization_target,
        result: EffectiveDefaultMutationResult {
            selection: expected_effective,
            generation: 0,
            scope_label: scope_label.to_string(),
            wrote: true,
            unchanged: false,
        },
        transaction_id: Some(record.transaction_id),
    })
}

fn active_model_from_config_bytes(bytes: &[u8]) -> Option<ActiveModelRef> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|raw| raw.get("active_model").cloned())
        .and_then(|value| serde_json::from_value(value).ok())
}

fn retained_config_matches(target: &RetainedEffectiveDefaultTarget, digest: &str) -> bool {
    target
        .read_config()
        .map(|bytes| bytes_digest(&bytes) == digest)
        .unwrap_or(false)
}

fn retained_restore_or_pending(
    target: &RetainedEffectiveDefaultTarget,
    old_bytes: &[u8],
    record: &JournalRecord,
    scope_label: &str,
    cause: &str,
) -> Result<RetainedEffectiveDefaultPendingFinalization, EffectiveDefaultError> {
    let current = match target.read_config() {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(EffectiveDefaultError::pending(
                scope_label,
                &format!(
                    "{cause}; {}",
                    safe_cause("the retained config could not be re-read", &error)
                ),
            ));
        }
    };
    let digest = bytes_digest(&current);
    if digest != record.old_config_digest {
        if digest != record.new_config_digest {
            return Err(EffectiveDefaultError::pending(
                scope_label,
                &format!("{cause}; retained config changed concurrently"),
            ));
        }
        if let Err(error) = target.write_private_leaf(&target.config_leaf, old_bytes) {
            return Err(EffectiveDefaultError::pending(
                scope_label,
                &format!(
                    "{cause}; {}",
                    safe_cause("the retained config could not be restored", &error)
                ),
            ));
        }
    }
    if !retained_config_matches(target, &record.old_config_digest) {
        return Err(EffectiveDefaultError::pending(
            scope_label,
            &format!("{cause}; retained restoration could not be verified"),
        ));
    }
    match target.remove_artifacts() {
        Ok(()) => Err(EffectiveDefaultError::restored(
            scope_label,
            cause,
            SessionCompensation::NotApplicable,
        )),
        Err(error) => Err(EffectiveDefaultError::pending(
            scope_label,
            &format!(
                "{cause}; {}",
                safe_cause("the retained journal could not be removed", &error)
            ),
        )),
    }
}

/// Recover one config-only journal through the same retained directory that
/// created it. This is the recovery counterpart of
/// [`mutate_effective_default_retained`]: it never uses a current
/// `COCKPIT_CONFIG` value to find the journal after a worker has attached.
///
/// A correlated journal is deliberately retained after its filesystem bytes
/// converge. The daemon must refresh the exact retained worker chain and
/// commit the terminal receipt to its durable ledger before it calls the
/// returned finalization token; a recovery pass may never make a waiting
/// request disappear merely because it repaired filesystem state.
pub fn recover_retained_effective_default_journal(
    target: &RetainedEffectiveDefaultTarget,
) -> Result<RetainedEffectiveDefaultRecovery> {
    target.verify_binding()?;
    let _lock = target.acquire_lock()?;
    let Some(record) = target.load_journal()? else {
        return Ok(RetainedEffectiveDefaultRecovery {
            transactions: Vec::new(),
            finalization: None,
            needs_receipt_validation: None,
        });
    };
    if record.target_path_digest != target.target_path_digest()
        || record.project_root != target.project_root.display().to_string()
        || record.needs_session_authority()
    {
        anyhow::bail!("retained effective-default journal is out of context");
    }
    if !matches!(
        &record.correlation,
        Some(TransactionCorrelation::RetainedDefaultUpdate { .. }) | None
    ) {
        anyhow::bail!(
            "retained effective-default backend refuses a non-config-only terminal correlation"
        );
    }
    if let Some(authority) = record
        .correlation
        .as_ref()
        .and_then(TransactionCorrelation::default_update_authority)
    {
        // A journal is unbound until the authoritative worker refresh reaches
        // its final fence, but a binding that is present is immutable proof.
        // Do not treat a syntactically corrupt proof as absent: retain every
        // artifact so a repair can inspect it rather than converging under an
        // invented authority.
        authority.validate()?;
    }
    // A previous daemon may have committed the receipt handoff but died
    // before cleanup. The marker itself lives beside workspace configuration
    // and is therefore never self-authenticating: return a typed token so the
    // attached daemon can prove the exact ledger receipt before cleanup.
    if record.phase == JournalPhase::ReceiptEmitted {
        let Some(TransactionCorrelation::RetainedDefaultUpdate {
            default_update_id,
            session_id,
            authority: Some(authority),
        }) = &record.correlation
        else {
            anyhow::bail!("retained receipt-emitted journal has no sealed authority binding");
        };
        let Some(proof) = record.receipt_proof.clone() else {
            anyhow::bail!("retained receipt-emitted journal has no durable receipt proof");
        };
        proof.validate()?;
        ensure!(
            proof.default_update_id == *default_update_id
                && proof.session_id == *session_id
                && proof.authority == *authority,
            "retained receipt-emitted journal proof does not match its correlation"
        );
        return Ok(RetainedEffectiveDefaultRecovery {
            transactions: Vec::new(),
            finalization: None,
            needs_receipt_validation: Some(RetainedEffectiveDefaultNeedsReceiptValidation {
                proof,
                finalization: RetainedEffectiveDefaultPendingFinalization {
                    target: target.try_clone()?,
                    result: EffectiveDefaultMutationResult {
                        selection: None,
                        generation: 0,
                        scope_label: target.scope_label().to_string(),
                        wrote: true,
                        unchanged: false,
                    },
                    transaction_id: Some(record.transaction_id),
                },
            }),
        });
    }

    let current = target.read_config()?;
    let current_digest = bytes_digest(&current);
    let forward = matches!(record.phase, JournalPhase::Committed);
    let transaction = if forward {
        if current_digest == record.old_config_digest {
            let Some(prior) = target.read_leaf(&target.backup_leaf)? else {
                anyhow::bail!("retained rollback snapshot is missing");
            };
            if bytes_digest(&prior) != record.old_config_digest {
                anyhow::bail!("retained rollback snapshot does not match its journal");
            }
            let rebuilt = replacement_bytes(&prior, record.requested.as_ref())?;
            if bytes_digest(&rebuilt) != record.new_config_digest {
                anyhow::bail!("retained journal cannot reproduce committed config");
            }
            target.verify_binding()?;
            target.write_private_leaf(&target.config_leaf, &rebuilt)?;
            target.verify_binding()?;
        } else if current_digest != record.new_config_digest {
            anyhow::bail!("retained config changed concurrently during forward recovery");
        }
        record
            .correlation
            .clone()
            .map(|correlation| RecoveredTransaction {
                correlation,
                outcome: RecoveredOutcome::Applied {
                    selection: record.expected_effective.clone(),
                    // The caller refreshes the exact retained worker snapshot
                    // before publishing this receipt; generation zero prevents a
                    // path-derived resolution generation from being fabricated.
                    generation: 0,
                },
                scope_label: target.scope_label().to_string(),
                requested: record.requested.clone(),
            })
    } else {
        if current_digest == record.new_config_digest {
            let Some(prior) = target.read_leaf(&target.backup_leaf)? else {
                anyhow::bail!("retained rollback snapshot is missing");
            };
            if bytes_digest(&prior) != record.old_config_digest {
                anyhow::bail!("retained rollback snapshot does not match its journal");
            }
            target.verify_binding()?;
            target.write_private_leaf(&target.config_leaf, &prior)?;
            target.verify_binding()?;
        } else if current_digest != record.old_config_digest {
            anyhow::bail!("retained config changed concurrently during compensation");
        }
        let config_bytes = target.read_config()?;
        record
            .correlation
            .clone()
            .map(|correlation| RecoveredTransaction {
                correlation,
                outcome: RecoveredOutcome::Restored {
                    restored: active_model_from_config_bytes(&config_bytes),
                    session: SessionCompensation::NotApplicable,
                },
                scope_label: target.scope_label().to_string(),
                requested: record.requested.clone(),
            })
    };

    let transactions = transaction.into_iter().collect::<Vec<_>>();
    if transactions.is_empty() {
        // Uncorrelated retained journals have no client receipt to protect.
        target.verify_binding()?;
        target.remove_artifacts()?;
        return Ok(RetainedEffectiveDefaultRecovery {
            transactions,
            finalization: None,
            needs_receipt_validation: None,
        });
    }
    let finalization = RetainedEffectiveDefaultPendingFinalization {
        target: target.try_clone()?,
        // Recovery supplies the actual terminal outcome separately. This value
        // is intentionally never exposed; it only keeps the token shape shared
        // with a newly committed mutation.
        result: EffectiveDefaultMutationResult {
            selection: None,
            generation: 0,
            scope_label: target.scope_label().to_string(),
            wrote: true,
            unchanged: false,
        },
        transaction_id: Some(record.transaction_id),
    };
    Ok(RetainedEffectiveDefaultRecovery {
        transactions,
        finalization: Some(finalization),
        needs_receipt_validation: None,
    })
}

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
    // Capture the selected parent before the mutation touches any sidecar.
    // This is the ambient-to-capability handoff: a subsequent A→B directory
    // replacement can never redirect the probe or lock below to B.
    let (captured_target, mut captured_projection) = capture_ambient_mutation(cwd, &target)
        .map_err(|error| {
            EffectiveDefaultError::new(
                safe_cause("the effective-default target could not be captured", &error),
                "effective_default_target_changed",
                Some(scope_label.clone()),
            )
        })?;
    if let Some(authority) = correlation
        .as_ref()
        .and_then(TransactionCorrelation::default_update_authority)
        && let Err(error) = authority.validate()
    {
        return Err(EffectiveDefaultError::new(
            safe_cause("the default receipt authority is invalid", &error),
            "effective_default_invalid_authority",
            Some(scope_label),
        ));
    }
    // The selected journal is classified through the held A directory before
    // every capability-local side effect. The deterministic seam runs after
    // that capture: a replacement changes only the compatibility pathname,
    // never the directory used by the probe or lock.
    ambient_captured_mutation_journal_fence(&captured_target, &scope_label)?;
    run_ambient_mutation_classification_hook_for_tests();
    ambient_captured_mutation_journal_fence(&captured_target, &scope_label)?;
    note_ambient_mutation_writable_probe_for_tests();
    captured_target.ensure_writable().map_err(|error| {
        EffectiveDefaultError::new(
            safe_cause(
                "the highest-precedence config layer is not writable",
                &error,
            ),
            "effective_default_target_unwritable",
            Some(scope_label.clone()),
        )
    })?;
    // The writable probe is its own filesystem operation. Reclassify the held
    // target immediately before deriving the target-local lock identity.
    ambient_captured_mutation_journal_fence(&captured_target, &scope_label)?;
    note_ambient_mutation_lock_acquisition_for_tests();
    let lock = match cancelled {
        Some(flag) => captured_target.acquire_lock_cancellable(flag),
        None => captured_target.acquire_lock(),
    }
    .map_err(|error| {
        if cancelled.is_some() && error.to_string().contains("cancelled") {
            EffectiveDefaultError::new(
                "the default model update was cancelled before it became durable",
                "effective_default_cancelled",
                Some(scope_label.clone()),
            )
        } else {
            EffectiveDefaultError::new(
                safe_cause("the config mutation lock could not be acquired", &error),
                "effective_default_lock_failed",
                Some(scope_label.clone()),
            )
        }
    })?;
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
        Some(participant) => recover_captured_under_lock(
            &captured_target,
            &mut captured_projection,
            JournalRecovery::with_sessions(&mut *participant.authority),
        ),
        None => recover_captured_under_lock(
            &captured_target,
            &mut captured_projection,
            JournalRecovery {
                sessions: None,
                sink: None,
                forced: true,
                lock_deadline: None,
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
    if captured_target
        .load_journal()
        .map_err(|error| {
            EffectiveDefaultError::new(
                safe_cause(
                    "the pending default-model journal could not be re-read",
                    &error,
                ),
                "effective_default_recovery_blocked",
                Some(scope_label.clone()),
            )
        })?
        .is_some()
    {
        return Err(EffectiveDefaultError::new(
            "another default-model update for this configuration layer is still pending; run `cockpit doctor` to inspect it",
            "effective_default_journal_conflict",
            Some(scope_label),
        ));
    }

    captured_projection
        .replace_target_snapshot(&captured_target)
        .map_err(|error| {
            EffectiveDefaultError::new(
                safe_cause("the captured config layer could not be refreshed", &error),
                "effective_default_read_failed",
                Some(scope_label.clone()),
            )
        })?;
    let current = captured_projection.providers().map_err(|error| {
        EffectiveDefaultError::new(
            safe_cause(
                "the captured effective configuration could not be projected",
                &error,
            ),
            "effective_default_read_failed",
            Some(scope_label.clone()),
        )
    })?;
    let generation = crate::config::providers::next_load_effective_generation().max(1);
    let current_active = current.active_model.clone();

    // Clearing resolves to the deterministic inherited default below the
    // target layer, and is rejected outright if that would be dangling.
    let expected_effective = match requested {
        Some(active) => Some(active.clone()),
        None => {
            let inherited = captured_projection.inherited_default().map_err(|error| {
                EffectiveDefaultError::new(
                    safe_cause(
                        "the captured inherited default could not be projected",
                        &error,
                    ),
                    "effective_default_read_failed",
                    Some(scope_label.clone()),
                )
            })?;
            validate_inherited_default(inherited.as_ref(), &current, &scope_label)?;
            inherited
        }
    };

    let should_write = match (mode, requested, current_active.as_ref()) {
        (ActiveModelWriteMode::Replace, Some(req), Some(cur)) => req != cur,
        (ActiveModelWriteMode::Replace, Some(_), None) => true,
        // A clear is a no-op only when the target layer declares no default.
        (ActiveModelWriteMode::Replace, None, _) => {
            captured_projection.target_declares_active_model()
        }
        (ActiveModelWriteMode::InitializeIfMissing, Some(_), None) => true,
        (ActiveModelWriteMode::InitializeIfMissing, _, _) => false,
    };

    if !should_write {
        // Verify under the lock even for a no-op: a concurrent writer must not
        // let a stale request claim the other writer's model as its own.
        let reloaded = captured_projection.providers().map_err(|error| {
            EffectiveDefaultError::new(
                safe_cause(
                    "the captured effective configuration could not be projected",
                    &error,
                ),
                "effective_default_read_failed",
                Some(scope_label.clone()),
            )
        })?;
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
            generation,
            scope_label,
            wrote: false,
            unchanged: true,
        });
    }

    let requested_owned = requested.cloned();
    mutate_under_lock(
        &captured_target,
        &mut captured_projection,
        &scope_label,
        requested_owned.as_ref(),
        expected_effective,
        session,
        cancelled,
        correlation,
        lock,
    )
}

/// Capability-relative retained-journal fence for an ambient mutation.
/// It intentionally reads the selected target's journal through the held
/// directory descriptor; after ambient selection/capture, an A→B pathname
/// replacement must not influence this ownership decision.
fn ambient_captured_mutation_journal_fence(
    target: &CapturedEffectiveDefaultTarget,
    scope_label: &str,
) -> Result<(), EffectiveDefaultError> {
    let record = target.load_journal().map_err(|error| {
        EffectiveDefaultError::new(
            safe_cause(
                "the pending default-model journal could not be classified",
                &error,
            ),
            "effective_default_recovery_blocked",
            Some(scope_label.to_string()),
        )
    })?;
    if record.as_ref().is_some_and(|record| {
        record
            .correlation
            .as_ref()
            .is_some_and(TransactionCorrelation::is_retained_default_update)
    }) {
        return Err(EffectiveDefaultError::new(
            "an attached default-model update is still pending for this configuration layer",
            "effective_default_journal_conflict",
            Some(scope_label.to_string()),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn mutate_under_lock(
    target: &CapturedEffectiveDefaultTarget,
    projection: &mut CapturedEffectiveDefaultLayerProjection,
    scope_label: &str,
    requested: Option<&ActiveModelRef>,
    expected_effective: Option<ActiveModelRef>,
    mut session: Option<SessionDefaultParticipant<'_>>,
    cancelled: Option<&AtomicBool>,
    correlation: Option<TransactionCorrelation>,
    _lock: ConfigMutationLock,
) -> Result<EffectiveDefaultMutationResult, EffectiveDefaultError> {
    let old_bytes = target.read_config().map_err(|error| {
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
    target
        .write_private_leaf(&target.backup_leaf, &old_bytes)
        .map_err(|error| {
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
        project_root: target.project_root.display().to_string(),
        trust_mode: crate::config::trust::current_workspace_trust_policy()
            .map(|policy| policy.mode.as_str().to_string()),
        scope: target.scope.clone(),
        // Canonical on both sides: the journal *name* is keyed on the
        // canonical path, so validating a raw path would make one file under
        // two spellings permanently out of context.
        target_path_digest: target.target_path_digest(),
        old_config_digest: old_digest,
        new_config_digest: new_digest,
        requested: requested.cloned(),
        expected_effective: expected_effective.clone(),
        session: journal_session,
        correlation,
        receipt_proof: None,
        phase: JournalPhase::Prepared,
    };

    // ---- Durable commit boundary: the fsynced `prepared` record. ----
    if let Err(error) = target.write_journal(&record) {
        let _ = target.remove_leaf(&target.backup_leaf);
        return Err(EffectiveDefaultError::new(
            safe_cause("the default-model journal could not be prepared", &error),
            "effective_default_journal_failed",
            Some(scope_label.to_string()),
        ));
    }
    crash_point!(scope_label, AfterJournalPrepared);

    let prepared_directory = target.directory.try_clone().map_err(|error| {
        let error = anyhow::Error::from(error);
        EffectiveDefaultError::new(
            safe_cause(
                "the captured config directory could not be retained",
                &error,
            ),
            "effective_default_read_failed",
            Some(scope_label.to_string()),
        )
    })?;
    let pending = match prepare_atomic_write_from_retained_directory(
        prepared_directory,
        &target.config_leaf,
        &target.display_path(&target.config_leaf),
        &new_bytes,
    ) {
        Ok(pending) => pending,
        Err(error) => {
            // The prepared record is durable, so convergence — not a bare
            // rejection — owns the outcome even though nothing changed yet.
            return converge_captured(
                target,
                projection,
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
        return converge_captured(
            target,
            projection,
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
        if let Err(error) = target.write_journal(&record) {
            drop(pending);
            // The durable journal is still at `prepared`; compensation reverts
            // the committed CAS under its revision guard.
            record.phase = JournalPhase::Prepared;
            return converge_captured(
                target,
                projection,
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
        return converge_captured(
            target,
            projection,
            &record,
            session.as_mut(),
            scope_label,
            false,
            &safe_cause("config.json could not be replaced", &error),
        );
    }
    // `PreparedAtomicWrite::commit` fsyncs the retained parent directory
    // before returning; no pathname-based fsync follows this boundary.
    crash_point!(scope_label, AfterConfigReplaced);

    record.phase = JournalPhase::Committed;
    if let Err(error) = target.write_journal(&record) {
        return converge_captured(
            target,
            projection,
            &record,
            session.as_mut(),
            scope_label,
            true,
            &safe_cause("the committed journal phase could not be recorded", &error),
        );
    }
    crash_point!(scope_label, AfterCommittedMarker);

    // Reload only the held target and merge it with the bounded snapshots
    // captured before this transaction. No ambient layer is rediscovered.
    let persisted = match target.read_config() {
        Ok(bytes) if bytes_digest(&bytes) == record.new_config_digest => bytes,
        Ok(_) => {
            return converge_captured(
                target,
                projection,
                &record,
                session.as_mut(),
                scope_label,
                true,
                "the retained config layer changed before reload verification",
            );
        }
        Err(error) => {
            return converge_captured(
                target,
                projection,
                &record,
                session.as_mut(),
                scope_label,
                true,
                &safe_cause("the captured config layer could not be reloaded", &error),
            );
        }
    };
    let reloaded = projection
        .projected_after_target_config(&persisted)
        .map_err(|error| {
            EffectiveDefaultError::pending(
                scope_label,
                &safe_cause(
                    "the captured effective configuration could not be projected",
                    &error,
                ),
            )
        })?;
    if reloaded.active_model != expected_effective {
        return converge_captured(
            target,
            projection,
            &record,
            session.as_mut(),
            scope_label,
            true,
            "the reloaded effective configuration did not resolve to the requested default",
        );
    }
    crash_point!(scope_label, AfterReloadVerified);

    if let Err(error) = finish_captured_journal(target) {
        // Both authorities already hold the target; the journal is idempotent
        // and the next recovery pass removes it.
        tracing::warn!(%error, "could not clean up a converged effective-default journal");
    }
    crash_point!(scope_label, AfterJournalCleanup);

    Ok(EffectiveDefaultMutationResult {
        selection: reloaded.active_model,
        generation: crate::config::providers::next_load_effective_generation().max(1),
        scope_label: scope_label.to_string(),
        wrote: true,
        unchanged: false,
    })
}

/// Post-boundary convergence for an ambient mutation after it has captured
/// its target.  Unlike the historical pathname helper this never calls layer
/// discovery, canonicalization, or a path based config/journal primitive: the
/// held directory and the pre-captured layer projection remain authoritative
/// until the transaction is either finished or restored.
#[allow(clippy::too_many_arguments)]
fn converge_captured(
    target: &CapturedEffectiveDefaultTarget,
    projection: &mut CapturedEffectiveDefaultLayerProjection,
    record: &JournalRecord,
    session: Option<&mut SessionDefaultParticipant<'_>>,
    scope_label: &str,
    forward_allowed: bool,
    cause: &str,
) -> Result<EffectiveDefaultMutationResult, EffectiveDefaultError> {
    if forward_allowed && finish_captured_config_from_journal(target, record).is_ok() {
        if projection.replace_target_snapshot(target).is_ok()
            && let Ok(reloaded) = projection.providers()
            && reloaded.active_model == record.expected_effective
        {
            if let Err(error) = finish_captured_journal(target) {
                tracing::warn!(%error, "could not clean up a forward-converged journal");
            }
            tracing::warn!(
                transaction_id = %record.transaction_id,
                cause,
                "effective-default transaction converged forward after a late failure"
            );
            return Ok(EffectiveDefaultMutationResult {
                selection: reloaded.active_model,
                generation: crate::config::providers::next_load_effective_generation().max(1),
                scope_label: scope_label.to_string(),
                wrote: true,
                unchanged: false,
            });
        }
    }

    // Bind the compensation result before building the error: a `match` in
    // tail position keeps its scrutinee temporary alive to the end of the
    // function body, which would outlive the borrow of `session` taken here.
    let compensated = compensate_captured(
        target,
        record,
        session.map(|participant| &mut *participant.authority),
    );
    let error = match compensated {
        Ok(session_outcome) => match finish_captured_journal(target) {
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

/// Capability-relative journal-forward repair.
fn finish_captured_config_from_journal(
    target: &CapturedEffectiveDefaultTarget,
    record: &JournalRecord,
) -> Result<()> {
    let current = target.read_config()?;
    let current_digest = bytes_digest(&current);
    if current_digest == record.new_config_digest {
        return Ok(());
    }
    if current_digest != record.old_config_digest {
        anyhow::bail!(
            "config digest is neither the recorded prior nor the recorded committed content; refusing to overwrite a concurrent change"
        );
    }
    let Some(prior) = target.read_leaf(&target.backup_leaf)? else {
        anyhow::bail!("the private rollback snapshot is missing");
    };
    if bytes_digest(&prior) != record.old_config_digest {
        anyhow::bail!("the private rollback snapshot does not match the recorded prior digest");
    }
    let rebuilt = replacement_bytes(&prior, record.requested.as_ref())?;
    if bytes_digest(&rebuilt) != record.new_config_digest {
        anyhow::bail!("the reconstructed replacement does not match the recorded committed digest");
    }
    target.write_private_leaf(&target.config_leaf, &rebuilt)
}

/// Capability-relative compensation. Session CAS remains identical to the
/// historical state machine; config/journal reads and writes are all relative
/// to the same captured directory as the original mutation.
fn compensate_captured(
    target: &CapturedEffectiveDefaultTarget,
    record: &JournalRecord,
    sessions: Option<&mut (dyn SessionRevisionAuthority + '_)>,
) -> Result<SessionCompensation> {
    let mut session_outcome = SessionCompensation::NotApplicable;
    let already_compensating = record.phase == JournalPhase::Compensating;
    if !already_compensating && record.needs_session_authority() {
        let mut compensating = record.clone();
        compensating.phase = JournalPhase::Compensating;
        target.write_journal(&compensating)?;
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
            Some(current) if current == compensated_revision && already_compensating => {
                session_outcome = SessionCompensation::AlreadyReverted;
            }
            Some(_) => anyhow::bail!(
                "session {session_id} is at an unexpected active-model revision; refusing to overwrite it"
            ),
            None => {
                session_outcome = SessionCompensation::SessionGone;
            }
        }
    }

    let current = target.read_config()?;
    let current_digest = bytes_digest(&current);
    if current_digest == record.old_config_digest {
        return Ok(session_outcome);
    }
    if current_digest != record.new_config_digest {
        anyhow::bail!(
            "config digest is neither the recorded prior nor the recorded committed content; refusing to overwrite a concurrent change"
        );
    }
    let Some(prior) = target.read_leaf(&target.backup_leaf)? else {
        anyhow::bail!("the private rollback snapshot is missing");
    };
    if bytes_digest(&prior) != record.old_config_digest {
        anyhow::bail!("the private rollback snapshot does not match the recorded prior digest");
    }
    target.write_private_leaf(&target.config_leaf, &prior)?;
    if bytes_digest(&target.read_config()?) != record.old_config_digest {
        anyhow::bail!("restored config does not match the recorded prior digest");
    }
    Ok(session_outcome)
}

/// Capability-relative artifact cleanup.  The retained directory fsync in
/// `remove_leaf_from_retained_directory` provides the same durability order
/// as the former path-based `finish_journal`.
fn finish_captured_journal(target: &CapturedEffectiveDefaultTarget) -> Result<()> {
    crash_point_bail!(FailJournalCleanup);
    target.remove_artifacts()
}

/// Validate an ambient journal against the already-captured target rather
/// than reopening its diagnostic pathname.  The target descriptor was built
/// only after normal layer selection completed; its canonical display path is
/// data for the lock/journal key, never a second filesystem authority.
fn captured_journal_context_error(
    record: &JournalRecord,
    target: &CapturedEffectiveDefaultTarget,
) -> Option<&'static str> {
    if record.target_path_digest != target.target_path_digest() {
        return Some("journal target path digest does not match this config file");
    }
    if record.project_root != target.project_root.display().to_string() {
        return Some("journal project root does not match the captured mutation context");
    }
    if record.scope != target.scope {
        return Some("journal scope does not match the captured mutation target");
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

/// Recover an ambient, non-retained journal while the caller already owns the
/// captured target's target-local lock. It must not reopen any selected layer
/// after `capture_ambient_mutation` returned.
fn recover_captured_under_lock(
    target: &CapturedEffectiveDefaultTarget,
    projection: &mut CapturedEffectiveDefaultLayerProjection,
    mut recovery: JournalRecovery<'_, '_>,
) -> Result<Vec<RecoveredTransaction>> {
    let Some(record) = target.load_journal()? else {
        return Ok(Vec::new());
    };
    if record
        .correlation
        .as_ref()
        .is_some_and(TransactionCorrelation::is_retained_default_update)
    {
        // A retained journal may only be finalized through the daemon's exact
        // attach-time authority. Leave it in place so the mutation conflict
        // gate below remains fail-closed.
        return Ok(Vec::new());
    }
    if let Some(reason) = captured_journal_context_error(&record, target) {
        tracing::error!(
            transaction_id = %record.transaction_id,
            reason,
            "refusing an out-of-context captured effective-default journal"
        );
        return Ok(Vec::new());
    }
    if let Some(authority) = record
        .correlation
        .as_ref()
        .and_then(TransactionCorrelation::default_update_authority)
    {
        authority.validate()?;
    }
    if record.phase == JournalPhase::ReceiptEmitted {
        if matches!(
            &record.correlation,
            Some(TransactionCorrelation::DefaultUpdate {
                authority: None,
                ..
            })
        ) {
            anyhow::bail!("receipt-emitted default-update journal has no sealed authority binding");
        }
        finish_captured_journal(target)?;
        return Ok(Vec::new());
    }
    if record.needs_session_authority() && recovery.sessions.is_none() {
        return Ok(Vec::new());
    }
    if record.correlation.is_some() && recovery.sink.is_none() {
        return Ok(Vec::new());
    }
    if let Some((journal_session, _, _)) = record.session_participant()
        && let Some(sessions) = recovery.sessions.as_deref_mut()
        && let Some(bound) = sessions.bound_session_id()
        && bound != journal_session
    {
        return Ok(Vec::new());
    }

    let scope_label = record.scope.as_str().to_string();
    let forward = matches!(
        record.phase,
        JournalPhase::SessionCommitted | JournalPhase::Committed
    );
    if forward {
        match finish_captured_config_from_journal(target, &record) {
            Ok(()) => {
                projection.replace_target_snapshot(target)?;
                let effective = projection.providers()?.active_model;
                if record.phase != JournalPhase::Committed {
                    let mut committed = record.clone();
                    committed.phase = JournalPhase::Committed;
                    target.write_journal(&committed)?;
                }
                let transaction =
                    record
                        .correlation
                        .clone()
                        .map(|correlation| RecoveredTransaction {
                            correlation,
                            outcome: RecoveredOutcome::Applied {
                                selection: effective,
                                generation:
                                    crate::config::providers::next_load_effective_generation()
                                        .max(1),
                            },
                            scope_label: scope_label.clone(),
                            requested: record.requested.clone(),
                        });
                if let (Some(transaction), Some(sink)) =
                    (transaction.as_ref(), recovery.sink.as_deref_mut())
                {
                    sink.accept(transaction)?;
                }
                finish_captured_journal(target)?;
                return Ok(transaction.into_iter().collect());
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    transaction_id = %record.transaction_id,
                    "could not finish captured effective-default commit; compensating"
                );
            }
        }
    }

    let session_outcome = compensate_captured(target, &record, recovery.sessions.as_deref_mut())?;
    let config_bytes = target.read_config()?;
    let transaction = record
        .correlation
        .clone()
        .map(|correlation| RecoveredTransaction {
            correlation,
            outcome: RecoveredOutcome::Restored {
                restored: active_model_from_config_bytes(&config_bytes),
                session: session_outcome,
            },
            scope_label,
            requested: record.requested.clone(),
        });
    if let (Some(transaction), Some(sink)) = (transaction.as_ref(), recovery.sink.as_deref_mut()) {
        sink.accept(transaction)?;
    }
    finish_captured_journal(target)?;
    Ok(transaction.into_iter().collect())
}

#[cfg(test)]
mod tests;
