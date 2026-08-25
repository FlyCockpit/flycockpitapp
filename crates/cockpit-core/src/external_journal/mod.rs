//! Generic durable journal for ambiguous external side effects.
//!
//! One bounded, restart-safe, idempotent journal serves every non-idempotent
//! external action — computer input, transcription, sidecars, image
//! generation, inference recovery — so no consumer duplicates accepted work or
//! invents a second spool.
//!
//! SQLite (`cockpit_db::external_journal`) is authoritative. The filesystem
//! side is one fixed, private, owner-only spool of 64-KiB two-slot
//! authenticated capsules that exists solely to carry a post-handoff
//! transition when the database cannot record it.
//!
//! The ordering contract is the whole point:
//!
//! 1. `prepared` commits in SQLite before anything touches the filesystem.
//! 2. A capsule is created exclusively, physically allocated to all 65,536
//!    bytes, sentinel-verified in both slots, fsynced, and its parent
//!    directory fsynced.
//! 3. The `prepared` slot and then the inactive `dispatching` slot are written,
//!    fsynced, and reread-verified.
//! 4. SQLite commits `dispatching`.
//! 5. Only then may a provider or backend be called.
//!
//! Any failure in 1–4 yields zero external handoff. After 5, a database
//! failure writes the next already-allocated capsule slot before any outcome
//! is reported; if that also fails, the unresolved fact is retained in memory,
//! all new external effects stop, and doctor reports critical. Ambiguous
//! non-idempotent submission is never automatically retried.
//!
//! This prompt owns the generic state/journal only. Consumer-specific
//! projection and integration stay with each consumer.

pub mod capsule;
pub(crate) mod fsguard;
pub mod keys;
pub mod projection;
pub mod spool;

#[cfg(any(unix, test))]
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use cockpit_db::Db;
use cockpit_db::external_journal::{
    CapsuleAdmission, CapsulePartition, EXTERNAL_JOURNAL_ADMISSION_BYTES,
    EXTERNAL_JOURNAL_ADMISSION_CAPSULES, EXTERNAL_JOURNAL_HARD_LIMIT_BYTES,
    EXTERNAL_JOURNAL_HARD_LIMIT_CAPSULES, EXTERNAL_JOURNAL_PREPARED_TTL_MS,
    EXTERNAL_JOURNAL_RECOVERY_RESERVE_BYTES, EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES,
    ExternalJournalAgeReport, ExternalJournalCapacity, ExternalJournalRecord, ExternalJournalState,
    ExternalPrepareOutcome, ExternalTransitionOutcome, PrepareExternalOperation,
};
#[cfg(any(unix, test))]
use cockpit_db::filesystem_identity::FilesystemIdentityV1;

pub(crate) use fsguard::DirGuard;
#[cfg(unix)]
pub(crate) use fsguard::{HeldEntryIdentity, HeldRenameEffect};
pub use fsguard::{
    OpenStrictness, SPOOL_DIR_MODE, SPOOL_FILE_MODE, SPOOL_PERMISSION_POLICY, SpoolPermissionPolicy,
};

use capsule::{CapsuleSlot, authentic_slots};
use keys::SpoolKeyRing;
use projection::{Digest, SafeToken, SanitizedProjection};
use spool::{CapsulePresence, Spool, SpoolAccess};

/// Every way the external journal can refuse to proceed.
#[derive(Debug, thiserror::Error)]
pub enum ExternalJournalError {
    #[error("external journal projection is invalid: {0}")]
    Projection(String),
    #[error("external journal projection is {len} bytes; the encoder cap is {cap}")]
    ProjectionTooLarge { len: usize, cap: usize },
    #[error("external journal capsule is invalid: {0}")]
    Capsule(String),
    #[error("external journal spool failed: {0}")]
    Spool(String),
    #[error("external journal containment check failed: {0}")]
    Containment(String),
    #[error("external journal spool permissions are insecure: {0}")]
    InsecurePermissions(String),
    #[error("external journal spool key version {0} is unavailable")]
    UnknownKeyVersion(u32),
    #[error("external journal capsule {0} does not exist")]
    CapsuleMissing(String),
    #[error("external journal quarantine name {0} is already taken")]
    QuarantineNameTaken(String),
    #[error("illegal external journal transition {from} -> {to}: {reason}")]
    IllegalTransition {
        from: &'static str,
        to: &'static str,
        reason: String,
    },
    #[error(
        "external journal capsule holds authenticated {state} evidence at version {version} \
         that the database cannot legally reach from {current}"
    )]
    UnreachableEvidence {
        version: i64,
        state: &'static str,
        current: &'static str,
    },
    #[error("external journal key store failed: {0}")]
    KeyStore(String),
    #[error("external journal database failed: {0}")]
    Database(String),
    #[error(
        "external journal recovery capacity is exhausted \
         (admission {} capsules / {} bytes)",
        .0.admission_capsules,
        .0.admission_bytes
    )]
    CapacityExhausted(ExternalJournalCapacity),
    #[error("external journal dispatch is blocked: {0}")]
    DispatchBlocked(String),
    #[error("external journal system-integrity failure: {0}")]
    SystemIntegrity(String),
    #[error("external journal state error: {0}")]
    State(String),
    #[error("external journal outcome {requested} cannot be applied to a record that is {current}")]
    OutcomeConflict {
        requested: &'static str,
        current: &'static str,
    },
    #[error(
        "external journal fallback chain would strand an outcome: \
         {surviving} -> {requested} is not a legal edge"
    )]
    FallbackChainBroken {
        surviving: &'static str,
        requested: &'static str,
    },
    #[error(
        "external journal capsule already holds {pending} pending version(s) above the \
         committed version {committed}; a further fallback would overwrite the bridging slot"
    )]
    FallbackDepthExceeded { committed: i64, pending: i64 },
}

/// Re-target a provider outcome onto a record whose cancellation fact is set.
///
/// Once cancellation is requested, authoritative successful completion must be
/// `completed_after_cancel`; plain `succeeded` is permanently unreachable. A
/// provider that reports success after a cancellation raced the handoff is
/// therefore recorded as `completed_after_cancel`, never dropped.
fn cancellation_aware_outcome(
    record: &ExternalJournalRecord,
    requested: ExternalJournalState,
) -> ExternalJournalState {
    if record.is_cancellation_requested() && requested == ExternalJournalState::Succeeded {
        ExternalJournalState::CompletedAfterCancel
    } else {
        requested
    }
}

/// Classify a database error.
///
/// A legality rejection is a statement about the state graph, not about
/// infrastructure. Mapping it to `Database` would send a rejected outcome down
/// the spool-fallback path, where it would become durable, wrong, and
/// permanently unimportable.
fn db_error(error: anyhow::Error) -> ExternalJournalError {
    match cockpit_db::external_journal::illegal_transition_cause(&error) {
        Some(illegal) => ExternalJournalError::IllegalTransition {
            from: illegal.from.as_str(),
            to: illegal.to.as_str(),
            reason: illegal.reason.clone(),
        },
        None => ExternalJournalError::Database(format!("{error:#}")),
    }
}

/// Deterministic database fault points, exercised only by in-crate tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DbFaults {
    /// Every database call fails, modelling a real outage — reads included, so
    /// the pending-fallback drain takes its true failure path.
    pub db_offline: bool,
    pub fail_prepared_commit: bool,
    pub fail_dispatching_commit: bool,
    /// Fail *after* the `dispatching` commit succeeded, to exercise the
    /// post-commit path where the capsule must be retained.
    pub fail_after_dispatching_commit: bool,
    pub fail_outcome_commit: bool,
    pub fail_capsule_reservation: bool,
}

/// An unresolved fact retained in memory because every durable medium failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedFact {
    pub operation_id: Uuid,
    pub state: ExternalJournalState,
    pub journal_version: i64,
    pub observed_at_wall_ms: i64,
}

/// Proof that pre-dispatch provisioning completed. Holding one is the only
/// legitimate way to reach a provider.
#[derive(Debug, Clone)]
pub struct DispatchTicket {
    pub operation_id: Uuid,
    capsule_uuid: Uuid,
    /// Journal version the last written slot asserts.
    version: i64,
    /// State the last written slot asserts.
    state: ExternalJournalState,
    /// Slot the last write landed in. The next write uses the other one.
    active_slot: u8,
    /// Version SQLite is known to hold. Lower than `version` exactly while a
    /// spool fallback is waiting to be imported.
    committed_version: i64,
    projection: Vec<u8>,
}

impl DispatchTicket {
    pub fn capsule_uuid(&self) -> Uuid {
        self.capsule_uuid
    }

    pub fn version(&self) -> i64 {
        self.version
    }

    pub fn active_slot(&self) -> u8 {
        self.active_slot
    }

    /// The state the last written slot asserts.
    pub fn state(&self) -> ExternalJournalState {
        self.state
    }

    /// Whether a spool fallback is still waiting to reach SQLite.
    pub fn has_pending_fallback(&self) -> bool {
        self.committed_version < self.version
    }

    fn inactive_slot(&self) -> u8 {
        1 - self.active_slot
    }
}

/// Where an outcome became durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeDurability {
    /// SQLite recorded it, which is authoritative.
    Database,
    /// The first compare-and-set lost a race. The outcome was re-targeted onto
    /// whatever state actually won — typically a cancellation that landed
    /// between handoff and evidence, turning `succeeded` into
    /// `completed_after_cancel` — and that transition committed.
    DatabaseAfterReconcile,
    /// SQLite failed; the already-allocated capsule slot carries it until
    /// recovery imports it.
    SpoolFallback,
}

impl OutcomeDurability {
    /// Whether SQLite, the authoritative store, holds the outcome.
    pub fn is_authoritative(self) -> bool {
        matches!(self, Self::Database | Self::DatabaseAfterReconcile)
    }
}

/// Result of replaying one capsule's authenticated slot chain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ChainImport {
    imported: usize,
    /// Version gaps: an intermediate fact existed once and no longer does.
    skipped: usize,
}

/// What one recovery pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    pub scanned: usize,
    pub imported: usize,
    pub idempotent: usize,
    pub quarantined: usize,
    pub removed: usize,
    pub foreign_quarantined: usize,
    /// Records converted from `dispatching` to `submission_unknown`.
    pub converted: usize,
    /// Ledger rows released because their capsule file was gone.
    pub released_without_medium: usize,
    /// Pre-dispatch capsules reclaimed from a crashed provisioning attempt.
    pub reclaimed_prepared: usize,
    /// Capsules holding authenticated evidence the database cannot reach.
    pub unreachable_evidence: usize,
    /// Intermediate facts a replay could not reconstruct, recorded rather than
    /// silently skipped.
    pub skipped_facts: usize,
}

/// Structured capacity/age diagnostics for doctor, headless, and TUI status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalJournalStatus {
    pub capacity: ExternalJournalCapacity,
    pub age: ExternalJournalAgeReport,
    pub spool_allocated_bytes: u64,
    pub quarantined_entries: usize,
    pub integrity_failure: Option<String>,
}

impl ExternalJournalStatus {
    /// Whether new external work is refused right now.
    pub fn dispatch_blocked(&self) -> bool {
        self.integrity_failure.is_some()
            || self.quarantined_entries > 0
            || self.capacity.admission_blocked()
    }

    /// Whether doctor must report critical.
    pub fn is_critical(&self) -> bool {
        self.integrity_failure.is_some() || self.age.is_critical() || self.dispatch_blocked()
    }

    /// Exact record/byte/age counts, one line each.
    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "capsules: {}/{} admission, {}/{} recovery reserve, {}/{} hard limit",
                self.capacity.admission_capsules,
                EXTERNAL_JOURNAL_ADMISSION_CAPSULES,
                self.capacity.recovery_capsules,
                EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES,
                self.capacity.total_capsules(),
                EXTERNAL_JOURNAL_HARD_LIMIT_CAPSULES,
            ),
            format!(
                "bytes: {}/{} admission, {}/{} recovery reserve, {}/{} hard limit",
                self.capacity.admission_bytes,
                EXTERNAL_JOURNAL_ADMISSION_BYTES,
                self.capacity.recovery_bytes,
                EXTERNAL_JOURNAL_RECOVERY_RESERVE_BYTES,
                self.capacity.total_bytes(),
                EXTERNAL_JOURNAL_HARD_LIMIT_BYTES,
            ),
            format!(
                "spool: {} bytes allocated on disk",
                self.spool_allocated_bytes
            ),
            format!(
                "unresolved: {} record(s); {} warning, {} critical, oldest {} ms",
                self.age.unresolved, self.age.warning, self.age.critical, self.age.oldest_age_ms
            ),
        ];
        lines.push(if self.quarantined_entries > 0 {
            format!(
                "quarantine: FAILED ({} entr(y|ies) withheld; new external work blocked)",
                self.quarantined_entries
            )
        } else {
            "quarantine: ok (0 entries)".to_string()
        });
        lines.push(match self.capacity.admission_block_reason() {
            Some(reason) => {
                format!("admission: FAILED ({reason} exhausted; new external work blocked)")
            }
            None => "admission: ok".to_string(),
        });
        lines.push(match &self.integrity_failure {
            Some(reason) => format!("integrity: FAILED ({reason})"),
            None => "integrity: ok".to_string(),
        });
        if self.age.critical > 0 {
            lines.push(format!(
                "age: FAILED ({} unresolved record(s) past 24h)",
                self.age.critical
            ));
        } else if self.age.warning > 0 {
            lines.push(format!(
                "age: WARNING ({} unresolved record(s) past 15m)",
                self.age.warning
            ));
        } else {
            lines.push("age: ok".to_string());
        }
        lines
    }
}

/// The journal facade: SQLite plus the capsule spool plus the key ring.
pub struct ExternalJournal {
    db: Db,
    spool: Spool,
    keys: SpoolKeyRing,
    integrity: Arc<Mutex<Option<String>>>,
    unresolved_facts: Arc<Mutex<Vec<UnresolvedFact>>>,
    db_faults: Arc<Mutex<DbFaults>>,
    #[cfg(test)]
    fail_remote_rename_cleanup_sync: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_remote_rename_cleanup_unlink: std::sync::atomic::AtomicBool,
    /// Test-only ordering barrier: when installed, `begin_dispatch` parks inside
    /// the durable-commit critical section until released, letting a test prove
    /// no provider handoff happens until the journal authorizes it.
    #[cfg(test)]
    dispatch_gate: std::sync::Mutex<Option<DispatchGate>>,
}

/// Test handle that parks the journal inside [`ExternalJournal::begin_dispatch`]
/// so a caller can observe that the provider handoff has not happened yet.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct DispatchGate {
    reached: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(test)]
impl DispatchGate {
    /// Resolve once `begin_dispatch` has entered the parked critical section.
    pub(crate) async fn wait_until_reached(&self) {
        self.reached.notified().await;
    }

    /// Let the parked `begin_dispatch` proceed to its durable commit.
    pub(crate) fn release(&self) {
        self.release.notify_one();
    }
}

impl std::fmt::Debug for ExternalJournal {
    /// Spool root and key versions only. No record content, no key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalJournal")
            .field("spool_root", &self.spool.root_path())
            .field("key_versions", &self.keys.retained_versions())
            .field("integrity_failure", &self.integrity_failure().is_some())
            .finish()
    }
}

impl ExternalJournal {
    #[cfg(test)]
    pub(crate) fn for_test_at(db: Db, root: &std::path::Path) -> Self {
        Self::new(
            db,
            Spool::open_at(root, SpoolAccess::Create).expect("open test external journal spool"),
            SpoolKeyRing::for_test(&[(1, [0x51; 32])], 1).expect("test spool keys"),
        )
    }

    /// Install (or replace) the `begin_dispatch` ordering barrier and return its
    /// handle. Used by ordering tests to prove journal-commit-before-handoff.
    #[cfg(test)]
    pub(crate) fn install_dispatch_gate(&self) -> DispatchGate {
        let gate = DispatchGate {
            reached: std::sync::Arc::new(tokio::sync::Notify::new()),
            release: std::sync::Arc::new(tokio::sync::Notify::new()),
        };
        *self.dispatch_gate.lock().unwrap() = Some(gate.clone());
        gate
    }
    /// Open the owner-private namespace used by remote operation recovery.
    /// Callers receive a held no-follow directory authority, never its path.
    pub(crate) fn remote_operation_artifact_dir(&self) -> Result<DirGuard, ExternalJournalError> {
        if !cfg!(any(target_os = "linux", target_os = "macos")) {
            return Err(ExternalJournalError::Containment(
                "remote operation artifacts require Unix held-handle and owner-mode enforcement"
                    .into(),
            ));
        }
        let root = DirGuard::open_root(self.spool.root_path(), false)?;
        root.verify_private()?;
        let operations = root.open_child_dir("remote-operations", true)?;
        operations.verify_private()?;
        root.sync()?;
        Ok(operations)
    }

    #[cfg(any(unix, test))]
    pub(crate) fn write_remote_rename_artifact(
        &self,
        artifact_id: Uuid,
        record: &RemoteRenameArtifactV1,
    ) -> Result<(), ExternalJournalError> {
        let dir = self.remote_operation_artifact_dir()?;
        let name = remote_rename_artifact_name(artifact_id, record.dispatch_generation);
        let bytes = record.encode()?;
        let mut file = dir.create_file_exclusive(&name)?;
        file.write_all(&bytes).map_err(|error| {
            ExternalJournalError::Spool(format!("write rename artifact: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            ExternalJournalError::Spool(format!("fsync rename artifact: {error}"))
        })?;
        dir.sync()?;
        Ok(())
    }

    #[cfg(any(unix, test))]
    pub(crate) fn read_remote_rename_artifact(
        &self,
        artifact_id: Uuid,
        dispatch_generation: u64,
    ) -> Result<RemoteRenameArtifactV1, ExternalJournalError> {
        let dir = self.remote_operation_artifact_dir()?;
        let name = remote_rename_artifact_name(artifact_id, dispatch_generation);
        let mut file = dir.open_file_verified(&name)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|error| {
            ExternalJournalError::Spool(format!("read rename artifact: {error}"))
        })?;
        RemoteRenameArtifactV1::decode(&bytes)
    }

    pub(crate) fn remove_all_remote_rename_artifacts(
        &self,
        artifact_id: Uuid,
    ) -> Result<(), ExternalJournalError> {
        let dir = self.remote_operation_artifact_dir()?;
        let prefix = format!("{artifact_id}.");
        for name in dir.list_file_names()? {
            let Some(generation) = name
                .strip_prefix(&prefix)
                .and_then(|value| value.strip_suffix(".rr1"))
            else {
                continue;
            };
            if !generation.is_empty() && generation.bytes().all(|byte| byte.is_ascii_digit()) {
                let _held = dir.open_file_verified(&name)?;
                #[cfg(test)]
                if self
                    .fail_remote_rename_cleanup_unlink
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    return Err(ExternalJournalError::Spool(
                        "injected rename artifact unlink failure".into(),
                    ));
                }
                dir.remove_file(&name)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt as _;
                    if _held
                        .metadata()
                        .map_err(|error| {
                            ExternalJournalError::Spool(format!(
                                "verify removed rename artifact: {error}"
                            ))
                        })?
                        .nlink()
                        != 0
                    {
                        return Err(ExternalJournalError::Containment(
                            "rename artifact unlink identity proof failed".into(),
                        ));
                    }
                }
            }
        }
        #[cfg(test)]
        if self
            .fail_remote_rename_cleanup_sync
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ExternalJournalError::Spool(
                "injected rename artifact directory fsync failure".into(),
            ));
        }
        dir.sync()
    }

    #[cfg(test)]
    pub(crate) fn fail_next_remote_rename_cleanup_sync(&self) {
        self.fail_remote_rename_cleanup_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_remote_rename_cleanup_unlink(&self) {
        self.fail_remote_rename_cleanup_unlink
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "remote")]
    pub(crate) async fn drain_remote_rename_artifact_cleanup(
        &self,
    ) -> Result<usize, ExternalJournalError> {
        let intents = self
            .db
            .remote_rename_artifact_cleanup_intents()
            .await
            .map_err(db_error)?;
        let mut completed = 0;
        for intent in intents {
            let artifact_id = Uuid::parse_str(&intent.artifact_id)
                .map_err(|error| ExternalJournalError::Containment(error.to_string()))?;
            self.remove_all_remote_rename_artifacts(artifact_id)?;
            if self
                .db
                .complete_remote_rename_artifact_cleanup(
                    &intent.logical_attachment_id,
                    &intent.operation_id,
                    &intent.artifact_id,
                )
                .await
                .map_err(db_error)?
            {
                completed += 1;
            }
        }
        Ok(completed)
    }

    pub fn new(db: Db, spool: Spool, keys: SpoolKeyRing) -> Self {
        Self {
            db,
            spool,
            keys,
            integrity: Arc::new(Mutex::new(None)),
            unresolved_facts: Arc::new(Mutex::new(Vec::new())),
            db_faults: Arc::new(Mutex::new(DbFaults::default())),
            #[cfg(test)]
            fail_remote_rename_cleanup_sync: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_remote_rename_cleanup_unlink: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            dispatch_gate: std::sync::Mutex::new(None),
        }
    }

    /// Build the production journal and run startup recovery.
    ///
    /// This is the daemon-boot entry point and the only place the fixed spool
    /// and the native secure store are wired together. It reserves and
    /// revalidates recovery capacity *before* any external dispatch can be
    /// enabled: recovery runs first, then admission is revalidated, and a
    /// failure of either leaves the journal in a state where
    /// [`Self::ensure_dispatch_allowed`] refuses.
    pub async fn start(
        db: Db,
        secure_key: &crate::secure_key::SecureKeyHandle,
        now_wall_ms: i64,
    ) -> Result<(Self, RecoveryReport), ExternalJournalError> {
        Self::start_at(db, &spool::default_spool_root()?, secure_key, now_wall_ms).await
    }

    /// Testable core of [`Self::start`], with an explicit spool root.
    pub async fn start_at(
        db: Db,
        spool_root: &std::path::Path,
        secure_key: &crate::secure_key::SecureKeyHandle,
        now_wall_ms: i64,
    ) -> Result<(Self, RecoveryReport), ExternalJournalError> {
        let spool = Spool::open_at(spool_root, SpoolAccess::Create)?;
        let referenced = db
            .external_journal_referenced_key_versions()
            .await
            .map_err(db_error)?;
        let keys = SpoolKeyRing::load_from_secure_store(secure_key, &referenced).await?;

        // Activate the ring's reference immediately, before any capsule
        // exists. `load_from_secure_store` leaves it `Reserved`, and the
        // secure-key actor's startup reconcile — which runs before this on
        // every later boot — releases an orphaned `Reserved` reference.
        // `Released` is terminal for non-sealed kinds, so a ring left merely
        // reserved across a restart would make every later activation, and
        // therefore every dispatch, fail permanently.
        let active_version = i64::from(keys.active_version());
        db.activate_external_journal_spool_key(active_version)
            .await
            .map_err(db_error)?;

        let journal = Self::new(db, spool, keys);
        let report = journal.recover(now_wall_ms).await?;
        #[cfg(feature = "remote")]
        {
            journal.drain_remote_rename_artifact_cleanup().await?;
        }
        // Bounded housekeeping: session deletion writes a tombstone every time,
        // including ephemeral sweeps, so it needs a retention policy.
        journal
            .db
            .prune_external_journal_tombstones(now_wall_ms)
            .await
            .map_err(db_error)?;
        journal.ensure_dispatch_allowed().await?;
        Ok((journal, report))
    }

    pub fn spool(&self) -> &Spool {
        &self.spool
    }

    pub fn keys(&self) -> &SpoolKeyRing {
        &self.keys
    }

    #[cfg(test)]
    pub(crate) fn set_db_faults(&self, faults: DbFaults) {
        *self.db_faults.lock().expect("db fault mutex") = faults;
    }

    fn db_faults(&self) -> DbFaults {
        *self.db_faults.lock().expect("db fault mutex")
    }

    /// The retained in-memory facts from a system-integrity failure.
    pub fn unresolved_facts(&self) -> Vec<UnresolvedFact> {
        self.unresolved_facts
            .lock()
            .expect("unresolved fact mutex")
            .clone()
    }

    /// The latched system-integrity failure, if any.
    pub fn integrity_failure(&self) -> Option<String> {
        self.integrity.lock().expect("integrity mutex").clone()
    }

    fn latch_integrity_failure(&self, reason: String) {
        let mut guard = self.integrity.lock().expect("integrity mutex");
        if guard.is_none() {
            *guard = Some(reason);
        }
    }

    /// Wall clock for the one latch site that carries no injected time.
    /// Only ever used as an observation timestamp on an integrity fault.
    fn now_for_latch(&self) -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    /// Latch in memory *and* durably.
    ///
    /// The in-memory latch dies with the process and is invisible to a doctor
    /// run that holds no journal instance, so anything that can still reach
    /// the database records the fault there too. A failure to persist is
    /// deliberately swallowed: the memory latch has already blocked dispatch,
    /// and the next pass that reaches a healthy database records it.
    async fn latch_and_persist(&self, reason: String, now_wall_ms: i64) {
        self.latch_integrity_failure(reason.clone());
        if let Err(error) = self
            .db
            .record_external_journal_integrity_fault(&reason, now_wall_ms)
            .await
        {
            tracing::warn!(%error, "external journal integrity fault could not be persisted");
        }
    }

    /// Revalidate recovery capacity and containment before any new dispatch.
    /// Startup calls this before enabling external work.
    pub async fn ensure_dispatch_allowed(&self) -> Result<(), ExternalJournalError> {
        if let Some(reason) = self.integrity_failure() {
            return Err(ExternalJournalError::DispatchBlocked(format!(
                "system-integrity failure: {reason}"
            )));
        }
        // A fault recorded by an earlier process still blocks dispatch.
        if let Some(reason) = self
            .db
            .external_journal_integrity_fault()
            .await
            .map_err(db_error)?
        {
            self.latch_integrity_failure(reason.clone());
            return Err(ExternalJournalError::DispatchBlocked(format!(
                "system-integrity failure: {reason}"
            )));
        }
        if let Err(error) = self.spool.verify_permissions() {
            // Insecure spool permissions are an integrity fact per the prompt's
            // edge case: block new dispatch rather than repairing silently.
            self.latch_and_persist(format!("spool permissions: {error}"), self.now_for_latch())
                .await;
            return Err(error);
        }
        let quarantined = self.spool.list_quarantined()?.len();
        if quarantined > 0 {
            return Err(ExternalJournalError::DispatchBlocked(format!(
                "{quarantined} quarantined spool entr(y|ies)"
            )));
        }
        let capacity = self
            .db
            .external_journal_capacity()
            .await
            .map_err(db_error)?;
        if capacity.admission_blocked() {
            return Err(ExternalJournalError::CapacityExhausted(capacity));
        }
        Ok(())
    }

    /// Commit a `prepared` record. No filesystem or provider work happens here.
    pub async fn prepare(
        &self,
        owner_session_id: &SafeToken,
        idempotency_key: &SafeToken,
        projection: &SanitizedProjection,
        now_wall_ms: i64,
    ) -> Result<ExternalJournalRecord, ExternalJournalError> {
        if self.db_faults().db_offline || self.db_faults().fail_prepared_commit {
            return Err(ExternalJournalError::Database(
                "injected prepared commit failure".to_string(),
            ));
        }
        let encoded = projection.encode()?;
        let request = PrepareExternalOperation {
            operation_kind: projection.body.operation_kind_token(),
            owner_session_id: owner_session_id.clone(),
            idempotency_key: idempotency_key.clone(),
            payload_digest: Digest::of(&encoded),
            payload_len: encoded.len(),
            provider_idempotency: None,
        };
        let outcome = self
            .db
            .prepare_external_operation(request, now_wall_ms)
            .await
            .map_err(db_error)?;
        Ok(match outcome {
            ExternalPrepareOutcome::Created(record) | ExternalPrepareOutcome::Existing(record) => {
                record
            }
        })
    }

    /// Provision the capsule and commit `dispatching`.
    ///
    /// Returning `Ok` is the only proof that a provider call may happen. Every
    /// error path leaves the record at `prepared` with no capsule, which is
    /// durable proof that dispatch never began.
    pub async fn begin_dispatch(
        &self,
        operation_id: Uuid,
        projection: &SanitizedProjection,
        now_wall_ms: i64,
    ) -> Result<DispatchTicket, ExternalJournalError> {
        self.ensure_dispatch_allowed().await?;

        // Test-only ordering barrier. Parking here — inside the only method
        // whose `Ok` authorizes a provider handoff — lets a test observe that no
        // provider call has happened while the journal has not yet committed
        // `dispatching`. Cloned out of the lock so the guard is not held across
        // the await.
        #[cfg(test)]
        {
            let gate = self.dispatch_gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                gate.reached.notify_one();
                gate.release.notified().await;
            }
        }

        let record = self
            .db
            .external_operation(operation_id)
            .await
            .map_err(db_error)?
            .ok_or_else(|| {
                ExternalJournalError::State(format!("unknown operation {operation_id}"))
            })?;
        if record.state != ExternalJournalState::Prepared {
            return Err(ExternalJournalError::State(format!(
                "operation {operation_id} is {} and cannot begin dispatch",
                record.state.as_str()
            )));
        }
        let encoded = projection.encode()?;
        if Digest::of(&encoded) != record.payload_digest {
            return Err(ExternalJournalError::State(
                "projection does not match the immutable payload digest".to_string(),
            ));
        }

        // 1. Reserve admission capacity before anything is created on disk.
        let version_at_admission = record.version;
        let capsule_uuid = Uuid::new_v4();
        if self.db_faults().fail_capsule_reservation {
            return Err(ExternalJournalError::Database(
                "injected capsule reservation failure".to_string(),
            ));
        }
        let reservation = self
            .db
            .reserve_external_journal_capsule(
                operation_id,
                capsule_uuid,
                i64::from(self.keys.active_version()),
                CapsulePartition::Admission,
                self.keys.secure_store_backed(),
                now_wall_ms,
            )
            .await
            .map_err(db_error)?;
        // `AlreadyReserved` means a previous attempt owns this capsule. We must
        // never delete a concurrent holder's file, so track who created what.
        let (capsule_uuid, reserved_here) = match reservation {
            CapsuleAdmission::Reserved(reservation) => (reservation.capsule_uuid, true),
            CapsuleAdmission::AlreadyReserved(reservation) => (reservation.capsule_uuid, false),
            CapsuleAdmission::Full(capacity) => {
                return Err(ExternalJournalError::CapacityExhausted(capacity));
            }
        };

        // 2. Provision the capsule. Exclusive creation is the ownership token:
        // only the caller that created the file in *this* call may write its
        // slots. A loser that reused a winner's capsule would rewrite both
        // slots from its own stale record and destroy the winner's fallback
        // evidence, so it aborts instead. A capsule left behind by a crashed
        // pre-dispatch attempt is reclaimed by recovery, which can do so
        // safely because a `prepared` record proves no dispatch began.
        if let Err(error) = self.spool.create_capsule(capsule_uuid) {
            self.roll_back_undispatched(operation_id, capsule_uuid, reserved_here, false)
                .await;
            return Err(error);
        }

        // 3. Re-read after admission: the record may have moved while we were
        // provisioning, and slots must never be written from a stale record.
        let record = self
            .db
            .external_operation(operation_id)
            .await
            .map_err(db_error)?
            .ok_or_else(|| {
                ExternalJournalError::State(format!("unknown operation {operation_id}"))
            })?;
        if record.state != ExternalJournalState::Prepared || record.version != version_at_admission
        {
            let error = ExternalJournalError::State(format!(
                "operation {operation_id} changed to {} during provisioning",
                record.state.as_str()
            ));
            self.roll_back_undispatched(operation_id, capsule_uuid, reserved_here, true)
                .await;
            return Err(error);
        }

        // 4-5. Write both slots, then commit the database transition.
        match self
            .provision_and_commit(&record, capsule_uuid, &encoded, now_wall_ms)
            .await
        {
            Ok(ticket) => Ok(ticket),
            Err(error) => {
                self.roll_back_undispatched(operation_id, capsule_uuid, reserved_here, true)
                    .await;
                Err(error)
            }
        }
    }

    /// Undo pre-dispatch provisioning, but only where undoing is provably safe.
    ///
    /// Three rules, in order:
    ///
    /// 1. If the record already left `prepared`, the `dispatching` commit
    ///    succeeded. An external effect may exist, so the capsule is the
    ///    fallback medium and **nothing** is deleted or released. Recovery
    ///    converts the record to `submission_unknown`.
    /// 2. The reservation is rolled back first, because that is the call that
    ///    validates legality. A refused rollback aborts the cleanup.
    /// 3. The capsule file is deleted only if this call created it. A capsule
    ///    belonging to a concurrent holder is never touched.
    async fn roll_back_undispatched(
        &self,
        operation_id: Uuid,
        capsule_uuid: Uuid,
        reserved_here: bool,
        created_here: bool,
    ) {
        match self.db.external_operation(operation_id).await {
            Ok(Some(record))
                if record.state != ExternalJournalState::Prepared
                    || record.dispatch_may_have_started() =>
            {
                tracing::warn!(
                    %operation_id,
                    state = record.state.as_str(),
                    "external journal dispatch failed after the dispatching commit; \
                     retaining the capsule as the fallback medium"
                );
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                // Cannot prove the record is still undispatched. Retaining a
                // capsule wastes 64 KiB; deleting one can lose a durable
                // medium, so retain.
                tracing::warn!(
                    %operation_id,
                    "external journal rollback could not confirm the record; retaining the capsule"
                );
                return;
            }
        }

        // The reservation and the capsule file have separate owners. Winning
        // the reservation does not mean owning the file: an `AlreadyReserved`
        // caller may have created it first and be dispatching with it right
        // now. Deleting its ledger row would leave a dispatched operation with
        // no reservation — never released, orphan-quarantined at the next
        // boot, and dispatch blocked. So roll the row back only when we own
        // the file, or when no file exists at all.
        let capsule_present = self.spool.capsule_presence(capsule_uuid) != CapsulePresence::Missing;
        if reserved_here && !created_here && capsule_present {
            tracing::warn!(
                %operation_id,
                %capsule_uuid,
                "external journal reservation retained: the capsule belongs to another dispatcher"
            );
            return;
        }
        if reserved_here {
            match self
                .db
                .rollback_external_journal_capsule_reservation(operation_id)
                .await
            {
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(
                        %operation_id,
                        %error,
                        "external journal reservation rollback refused; retaining the capsule"
                    );
                    return;
                }
            }
        }
        if created_here && let Err(error) = self.spool.remove_capsule(capsule_uuid) {
            tracing::warn!(%operation_id, %error, "external journal capsule cleanup failed");
        }
    }

    /// Write both capsule slots, then commit `dispatching`.
    ///
    /// The capsule already exists and is fully allocated when this runs, so
    /// nothing here creates a file, a directory entry, or a disk block.
    async fn provision_and_commit(
        &self,
        record: &ExternalJournalRecord,
        capsule_uuid: Uuid,
        encoded: &[u8],
        now_wall_ms: i64,
    ) -> Result<DispatchTicket, ExternalJournalError> {
        // Slot 0 asserts `prepared` at the current journal version.
        let prepared_slot = self.slot(
            record.operation_id,
            0,
            record.version,
            record.state,
            now_wall_ms,
            encoded,
        );
        self.spool
            .write_slot(capsule_uuid, 0, &prepared_slot.encode(&self.keys)?)?;

        // Slot 1 asserts `dispatching` at the next journal version. This is the
        // last write before the database commit and the provider call.
        let dispatch_version = record
            .version
            .checked_add(1)
            .ok_or_else(|| ExternalJournalError::State("journal version overflow".to_string()))?;
        let dispatch_slot = self.slot(
            record.operation_id,
            1,
            dispatch_version,
            ExternalJournalState::Dispatching,
            now_wall_ms,
            encoded,
        );
        self.spool
            .write_slot(capsule_uuid, 1, &dispatch_slot.encode(&self.keys)?)?;

        if self.db_faults().fail_dispatching_commit {
            return Err(ExternalJournalError::Database(
                "injected dispatching commit failure".to_string(),
            ));
        }
        let outcome = self
            .db
            .transition_external_operation(
                record.operation_id,
                record.version,
                ExternalJournalState::Dispatching,
                now_wall_ms,
            )
            .await
            .map_err(db_error)?;
        // Only a genuine commit produces a ticket. Adopting another writer's
        // `dispatching` would hand out two tickets for one capsule.
        let committed = match outcome {
            ExternalTransitionOutcome::Committed(record) => record,
            other => {
                return Err(ExternalJournalError::State(format!(
                    "dispatching commit lost its race; record is {}",
                    other.record().state.as_str()
                )));
            }
        };
        if self.db_faults().fail_after_dispatching_commit {
            return Err(ExternalJournalError::Database(
                "injected post-commit failure".to_string(),
            ));
        }

        Ok(DispatchTicket {
            operation_id: record.operation_id,
            capsule_uuid,
            version: committed.version,
            state: ExternalJournalState::Dispatching,
            active_slot: 1,
            committed_version: committed.version,
            projection: encoded.to_vec(),
        })
    }

    fn slot(
        &self,
        operation_id: Uuid,
        slot_index: u8,
        journal_version: i64,
        state: ExternalJournalState,
        now_wall_ms: i64,
        projection: &[u8],
    ) -> CapsuleSlot {
        CapsuleSlot {
            slot_index,
            operation_id,
            journal_version: journal_version.max(0) as u64,
            key_version: self.keys.active_version(),
            state,
            updated_at_wall_ms: now_wall_ms,
            projection: projection.to_vec(),
        }
    }

    /// Record a post-handoff outcome.
    ///
    /// SQLite first. If SQLite fails, the next already-allocated capsule slot
    /// is written before any outcome is reported. If that also fails, the fact
    /// is retained in memory, dispatch is latched off, and doctor goes
    /// critical: the product does not claim restart durability when every
    /// provisioned durable medium has failed.
    pub async fn record_outcome(
        &self,
        ticket: &mut DispatchTicket,
        outcome: ExternalJournalState,
        now_wall_ms: i64,
    ) -> Result<OutcomeDurability, ExternalJournalError> {
        // A previous call fell back to the spool, so SQLite is behind the
        // capsule. Import the pending slot chain before layering another
        // outcome on top; otherwise this transition would compare-and-set
        // against a version SQLite never saw and silently conflict.
        let mut reconciled = false;
        if ticket.has_pending_fallback() {
            match self.drain_pending_fallback(ticket, now_wall_ms).await {
                Ok(drained) => reconciled = drained,
                // The database is still down. The pending slot stays on disk
                // and this outcome joins the chain behind it; propagating here
                // would lose the outcome entirely, which is the one thing the
                // fallback medium exists to prevent.
                Err(ExternalJournalError::Database(_)) => {}
                Err(other) => return Err(other),
            }
        }

        let db_result = if self.db_faults().fail_outcome_commit || self.db_faults().db_offline {
            Err(ExternalJournalError::Database(
                "injected outcome commit failure".to_string(),
            ))
        } else {
            self.db
                .transition_external_operation(
                    ticket.operation_id,
                    ticket.version,
                    outcome,
                    now_wall_ms,
                )
                .await
                .map_err(db_error)
        };

        match db_result {
            Ok(ExternalTransitionOutcome::Committed(record))
            | Ok(ExternalTransitionOutcome::Duplicate(record)) => {
                self.adopt_committed(ticket, &record).await?;
                Ok(if reconciled {
                    OutcomeDurability::DatabaseAfterReconcile
                } else {
                    OutcomeDurability::Database
                })
            }
            // A lost compare-and-set is never reported as durable success.
            Ok(ExternalTransitionOutcome::Conflict(current)) => {
                self.retarget_outcome(ticket, current, outcome, now_wall_ms)
                    .await
            }
            // A legality rejection is not an outage. The state graph refused
            // this edge, so retarget it — typically a cancellation that landed
            // between handoff and evidence, turning `succeeded` into
            // `completed_after_cancel`. Writing the rejected state into a
            // capsule slot instead would make it durable and unimportable.
            Err(ExternalJournalError::IllegalTransition { .. }) => {
                let current = self
                    .db
                    .external_operation(ticket.operation_id)
                    .await
                    .map_err(db_error)?
                    .ok_or_else(|| {
                        ExternalJournalError::State(format!(
                            "operation {} vanished",
                            ticket.operation_id
                        ))
                    })?;
                self.retarget_outcome(ticket, current, outcome, now_wall_ms)
                    .await
            }
            Err(db_failure) => {
                self.write_fallback(ticket, outcome, now_wall_ms, &db_failure)
                    .await
            }
        }
    }

    /// Re-target a refused outcome onto the state that actually holds.
    async fn retarget_outcome(
        &self,
        ticket: &mut DispatchTicket,
        current: ExternalJournalRecord,
        outcome: ExternalJournalState,
        now_wall_ms: i64,
    ) -> Result<OutcomeDurability, ExternalJournalError> {
        let effective = cancellation_aware_outcome(&current, outcome);
        if current.state == effective {
            self.adopt_committed(ticket, &current).await?;
            return Ok(OutcomeDurability::DatabaseAfterReconcile);
        }
        if !current.state.allows_transition_to(effective) {
            return Err(ExternalJournalError::OutcomeConflict {
                requested: outcome.as_str(),
                current: current.state.as_str(),
            });
        }
        let retried = self
            .db
            .transition_external_operation(
                ticket.operation_id,
                current.version,
                effective,
                now_wall_ms,
            )
            .await
            .map_err(db_error)?;
        match retried {
            ExternalTransitionOutcome::Committed(record)
            | ExternalTransitionOutcome::Duplicate(record) => {
                self.adopt_committed(ticket, &record).await?;
                Ok(OutcomeDurability::DatabaseAfterReconcile)
            }
            ExternalTransitionOutcome::Conflict(current) => {
                Err(ExternalJournalError::OutcomeConflict {
                    requested: outcome.as_str(),
                    current: current.state.as_str(),
                })
            }
        }
    }

    /// Adopt a committed record into the ticket and clean up if it is terminal.
    async fn adopt_committed(
        &self,
        ticket: &mut DispatchTicket,
        record: &ExternalJournalRecord,
    ) -> Result<(), ExternalJournalError> {
        ticket.version = record.version;
        ticket.state = record.state;
        ticket.committed_version = record.version;
        if record.state.is_terminal() {
            // Terminal capsules are removed only after SQLite confirms.
            self.confirm_and_release(record).await?;
        }
        Ok(())
    }

    /// Write the outcome into the inactive, already-allocated capsule slot.
    async fn write_fallback(
        &self,
        ticket: &mut DispatchTicket,
        outcome: ExternalJournalState,
        now_wall_ms: i64,
        db_failure: &ExternalJournalError,
    ) -> Result<OutcomeDurability, ExternalJournalError> {
        // A capsule has exactly two slots, so it can hold at most two versions
        // above the one the database committed. A third consecutive fallback
        // would overwrite the slot that bridges from the committed version,
        // and recovery would then see authenticated evidence it cannot reach —
        // a false corruption report on a plain three-outcome outage. Refuse
        // instead, and retain the fact in memory like any other unwritable
        // outcome.
        let pending = ticket.version.saturating_sub(ticket.committed_version);
        if pending >= 2 {
            let full = ExternalJournalError::FallbackDepthExceeded {
                committed: ticket.committed_version,
                pending,
            };
            self.retain_unresolved(ticket, outcome, now_wall_ms, &full.to_string())
                .await;
            return Err(full);
        }

        let slot_index = ticket.inactive_slot();
        // The surviving slot is the one we are about to overwrite's partner:
        // the currently active slot. Recovery replays the two slots in version
        // order, so the new state must be a legal successor of the surviving
        // one. Without this check a second consecutive fallback would leave
        // `dispatching` and `succeeded` on disk with the intermediate
        // `accepted` overwritten, and recovery could never bridge the gap.
        if !ticket.state.allows_transition_to(outcome) {
            let broken = ExternalJournalError::FallbackChainBroken {
                surviving: ticket.state.as_str(),
                requested: outcome.as_str(),
            };
            self.retain_unresolved(ticket, outcome, now_wall_ms, &broken.to_string())
                .await;
            return Err(broken);
        }

        let next_version = ticket
            .version
            .checked_add(1)
            .ok_or_else(|| ExternalJournalError::State("journal version overflow".to_string()))?;
        let slot = self.slot(
            ticket.operation_id,
            slot_index,
            next_version,
            outcome,
            now_wall_ms,
            &ticket.projection,
        );
        let written = slot.encode(&self.keys).and_then(|bytes| {
            self.spool
                .write_slot(ticket.capsule_uuid, slot_index, &bytes)
        });
        match written {
            Ok(()) => {
                ticket.version = next_version;
                ticket.state = outcome;
                ticket.active_slot = slot_index;
                Ok(OutcomeDurability::SpoolFallback)
            }
            Err(spool_failure) => {
                let reason = format!(
                    "database and spool both failed after handoff \
                     (database: {db_failure}; spool: {spool_failure})"
                );
                self.retain_unresolved(ticket, outcome, now_wall_ms, &reason)
                    .await;
                Err(ExternalJournalError::SystemIntegrity(reason))
            }
        }
    }

    /// Every provisioned durable medium failed. Keep the fact in memory, stop
    /// all new external effects, and let doctor report critical.
    async fn retain_unresolved(
        &self,
        ticket: &DispatchTicket,
        outcome: ExternalJournalState,
        now_wall_ms: i64,
        reason: &str,
    ) {
        self.unresolved_facts
            .lock()
            .expect("unresolved fact mutex")
            .push(UnresolvedFact {
                operation_id: ticket.operation_id,
                state: outcome,
                journal_version: ticket.version.saturating_add(1),
                observed_at_wall_ms: now_wall_ms,
            });
        // Best effort: the database may be the thing that failed, but when it
        // is only the spool the fault still has to survive this process.
        self.latch_and_persist(reason.to_string(), now_wall_ms)
            .await;
    }

    /// Import the capsule slots a previous fallback wrote, so SQLite catches up
    /// before the next outcome is applied. Returns whether anything imported.
    async fn drain_pending_fallback(
        &self,
        ticket: &mut DispatchTicket,
        now_wall_ms: i64,
    ) -> Result<bool, ExternalJournalError> {
        if self.db_faults().db_offline {
            return Err(ExternalJournalError::Database(
                "injected database outage".to_string(),
            ));
        }
        let Some(record) = self
            .db
            .external_operation(ticket.operation_id)
            .await
            .map_err(db_error)?
        else {
            return Ok(false);
        };
        let chain = self
            .import_capsule_chain(ticket.operation_id, ticket.capsule_uuid, now_wall_ms)
            .await?;
        let refreshed = self
            .db
            .external_operation(ticket.operation_id)
            .await
            .map_err(db_error)?
            .unwrap_or(record);
        ticket.version = refreshed.version;
        ticket.state = refreshed.state;
        ticket.committed_version = refreshed.version;
        Ok(chain.imported > 0)
    }

    /// Record the orthogonal cancellation fact.
    pub async fn request_cancellation(
        &self,
        operation_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<ExternalJournalRecord, ExternalJournalError> {
        let outcome = self
            .db
            .request_external_operation_cancellation(operation_id, now_wall_ms)
            .await
            .map_err(db_error)?;
        let record = outcome.record().clone();
        if record.state.is_terminal() {
            self.confirm_and_release(&record).await?;
        }
        Ok(record)
    }

    /// Remove a terminal record's capsule after SQLite confirms the state.
    async fn confirm_and_release(
        &self,
        record: &ExternalJournalRecord,
    ) -> Result<(), ExternalJournalError> {
        let confirmed = self
            .db
            .external_operation(record.operation_id)
            .await
            .map_err(db_error)?
            .ok_or_else(|| {
                ExternalJournalError::State(format!("operation {} vanished", record.operation_id))
            })?;
        if !confirmed.state.is_terminal() {
            return Ok(());
        }
        if let Some(reservation) = self
            .db
            .external_journal_capsule(record.operation_id)
            .await
            .map_err(db_error)?
        {
            let _ = self.spool.remove_capsule(reservation.capsule_uuid);
        }
        self.db
            .release_external_journal_capsule(record.operation_id)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    /// Import every authenticated slot of one capsule, in version order.
    ///
    /// Stepwise on purpose. A capsule can hold two consecutive fallback
    /// transitions while SQLite is still at the pre-fallback version, and the
    /// state graph has no `dispatching -> succeeded` edge; replaying the
    /// versions in order is what stops a terminal outcome being stranded.
    /// Returns how many transitions committed.
    async fn import_capsule_chain(
        &self,
        operation_id: Uuid,
        capsule_uuid: Uuid,
        now_wall_ms: i64,
    ) -> Result<ChainImport, ExternalJournalError> {
        let first = self
            .spool
            .read_slot(capsule_uuid, 0)
            .and_then(|bytes| CapsuleSlot::decode(&bytes, operation_id, &self.keys));
        let second = self
            .spool
            .read_slot(capsule_uuid, 1)
            .and_then(|bytes| CapsuleSlot::decode(&bytes, operation_id, &self.keys));
        let slots = authentic_slots(first, second)
            .map_err(|reason| ExternalJournalError::Capsule(reason.as_str().to_string()))?;

        let mut imported = 0usize;
        let mut skipped = 0usize;
        let mut previous_version = self
            .db
            .external_operation(operation_id)
            .await
            .map_err(db_error)?
            .map(|record| record.version)
            .unwrap_or_default();
        for slot in slots {
            let version = i64::try_from(slot.journal_version).map_err(|_| {
                ExternalJournalError::Capsule("slot version out of range".to_string())
            })?;
            let outcome = self
                .db
                .import_external_journal_record(operation_id, version, slot.state, now_wall_ms)
                .await
                .map_err(db_error)?;
            match outcome {
                ExternalTransitionOutcome::Committed(record) => {
                    // Versions are contiguous when every intermediate fact
                    // survived. A gap means an intermediate slot was lost, so
                    // record it explicitly rather than letting a legal edge
                    // paper over a fact that no longer exists anywhere.
                    if record.version > previous_version.saturating_add(1) {
                        tracing::warn!(
                            %operation_id,
                            from = previous_version,
                            to = record.version,
                            "external journal replay skipped an intermediate fact"
                        );
                        skipped += 1;
                    }
                    previous_version = record.version;
                    imported += 1;
                }
                ExternalTransitionOutcome::Duplicate(record) => {
                    previous_version = previous_version.max(record.version);
                }
                // Authenticated evidence strictly newer than the database that
                // no legal edge can reach — the intermediate slot that would
                // have bridged it was corrupted or overwritten. Silently
                // counting this as "nothing to import" and then downgrading
                // the record to `submission_unknown` would discard a
                // authenticated terminal outcome, so it is an integrity fault.
                ExternalTransitionOutcome::Conflict(current) => {
                    if version > current.version {
                        return Err(ExternalJournalError::UnreachableEvidence {
                            version,
                            state: slot.state.as_str(),
                            current: current.state.as_str(),
                        });
                    }
                }
            }
        }
        Ok(ChainImport { imported, skipped })
    }

    /// Run recovery before accepting new external effects.
    ///
    /// Startup calls this, then [`Self::ensure_dispatch_allowed`], before any
    /// dispatch is enabled.
    pub async fn recover(&self, now_wall_ms: i64) -> Result<RecoveryReport, ExternalJournalError> {
        // An insecure spool is an integrity fact, not something to repair.
        if let Err(error) = self.spool.verify_permissions() {
            self.latch_and_persist(format!("spool permissions: {error}"), now_wall_ms)
                .await;
            return Err(error);
        }
        let mut report = RecoveryReport::default();

        // Anything under `capsules/` that is not a valid internal capsule name
        // is hostile by construction: quarantine without parsing it.
        for name in self.spool.list_foreign_entries()? {
            self.spool.quarantine_foreign_entry(&name)?;
            report.foreign_quarantined += 1;
        }

        let reservations = self
            .db
            .list_external_journal_capsules()
            .await
            .map_err(db_error)?;
        let known: std::collections::BTreeSet<Uuid> = reservations
            .iter()
            .map(|reservation| reservation.capsule_uuid)
            .collect();

        for reservation in &reservations {
            match self.spool.capsule_presence(reservation.capsule_uuid) {
                // The durable medium is genuinely gone. SQLite still holds the
                // record, so nothing is lost — but leaving the reservation
                // would drain admission capacity permanently, which is exactly
                // the leak a cancellation racing terminal cleanup produces.
                CapsulePresence::Missing => {
                    if self
                        .db
                        .release_external_journal_capsule_without_medium(reservation.operation_id)
                        .await
                        .map_err(db_error)?
                    {
                        report.released_without_medium += 1;
                    }
                    report.converted += usize::from(
                        self.convert_if_dispatching(reservation.operation_id, now_wall_ms)
                            .await?,
                    );
                    continue;
                }
                // Present but untrustworthy. This is not a missing medium: the
                // hostile file must be quarantined and dispatch blocked, and
                // the reservation must NOT be released, or the file would
                // become invisible to both the ledger and the orphan sweep.
                CapsulePresence::Unverifiable { detail } => {
                    self.quarantine(
                        reservation.operation_id,
                        reservation.capsule_uuid,
                        &detail,
                        now_wall_ms,
                    )
                    .await?;
                    self.latch_and_persist(
                        format!(
                            "capsule {} failed verification: {detail}",
                            reservation.capsule_uuid
                        ),
                        now_wall_ms,
                    )
                    .await;
                    report.quarantined += 1;
                    continue;
                }
                CapsulePresence::Verified => {}
            }
            report.scanned += 1;

            // A `prepared` record carries durable proof that dispatch never
            // began, so its capsule is pre-dispatch scaffolding holding nothing
            // that matters. Reclaim it so a crashed provisioning attempt cannot
            // wedge the operation behind a capsule no dispatcher owns.
            let record = self
                .db
                .external_operation(reservation.operation_id)
                .await
                .map_err(db_error)?;
            if record
                .as_ref()
                .is_some_and(|record| record.state == ExternalJournalState::Prepared)
            {
                self.spool.remove_capsule(reservation.capsule_uuid)?;
                if self
                    .db
                    .rollback_external_journal_capsule_reservation(reservation.operation_id)
                    .await
                    .map_err(db_error)?
                {
                    report.reclaimed_prepared += 1;
                }
                continue;
            }

            match self
                .import_capsule_chain(
                    reservation.operation_id,
                    reservation.capsule_uuid,
                    now_wall_ms,
                )
                .await
            {
                Ok(chain) => {
                    report.imported += chain.imported;
                    report.skipped_facts += chain.skipped;
                    if chain.imported == 0 {
                        report.idempotent += 1;
                    }
                }
                Err(ExternalJournalError::Capsule(reason)) => {
                    self.quarantine(
                        reservation.operation_id,
                        reservation.capsule_uuid,
                        &reason,
                        now_wall_ms,
                    )
                    .await?;
                    report.quarantined += 1;
                }
                // Explicit, never silent: quarantine, latch, and skip the
                // conversion that would have downgraded the lost evidence.
                Err(unreachable @ ExternalJournalError::UnreachableEvidence { .. }) => {
                    let detail = unreachable.to_string();
                    self.quarantine(
                        reservation.operation_id,
                        reservation.capsule_uuid,
                        &detail,
                        now_wall_ms,
                    )
                    .await?;
                    self.latch_and_persist(detail, now_wall_ms).await;
                    report.unreachable_evidence += 1;
                    continue;
                }
                Err(error) => return Err(error),
            }

            // Whatever the capsule said, a record still sitting in
            // `dispatching` has no evidence for an outcome and may already have
            // produced an external effect.
            report.converted += usize::from(
                self.convert_if_dispatching(reservation.operation_id, now_wall_ms)
                    .await?,
            );

            if let Some(record) = self
                .db
                .external_operation(reservation.operation_id)
                .await
                .map_err(db_error)?
                && record.state.is_terminal()
            {
                self.confirm_and_release(&record).await?;
                report.removed += 1;
            }
        }

        // A capsule on disk with no ledger row cannot be attributed to an
        // operation, so it is quarantined rather than trusted.
        for capsule_uuid in self.spool.list_capsules()? {
            if !known.contains(&capsule_uuid) {
                self.quarantine_file_only(capsule_uuid, "orphan capsule", now_wall_ms)
                    .await?;
                report.quarantined += 1;
            }
        }

        Ok(report)
    }

    /// Convert a record still in `dispatching` to `submission_unknown`.
    async fn convert_if_dispatching(
        &self,
        operation_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<bool, ExternalJournalError> {
        let converted = self
            .db
            .convert_dispatching_without_evidence(operation_id, now_wall_ms)
            .await
            .map_err(db_error)?;
        if converted.is_some() {
            tracing::warn!(
                %operation_id,
                "external journal record found in dispatching without evidence; \
                 recorded as submission_unknown"
            );
        }
        Ok(converted.is_some())
    }

    /// Quarantine a capsule and its ledger row, blocking new dispatch.
    async fn quarantine(
        &self,
        operation_id: Uuid,
        capsule_uuid: Uuid,
        reason: &str,
        now_wall_ms: i64,
    ) -> Result<(), ExternalJournalError> {
        tracing::warn!(%operation_id, reason, "quarantining external journal capsule");
        self.quarantine_file_only(capsule_uuid, reason, now_wall_ms)
            .await?;
        // Bounded on the database side: a burst of quarantines can never
        // silently exceed the 1,024 / 64 MiB recovery reserve.
        self.db
            .quarantine_external_journal_capsule(operation_id)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    /// Move a capsule file into quarantine, latching integrity if the move
    /// cannot be proven safe.
    async fn quarantine_file_only(
        &self,
        capsule_uuid: Uuid,
        reason: &str,
        now_wall_ms: i64,
    ) -> Result<(), ExternalJournalError> {
        match self.spool.quarantine_capsule(capsule_uuid) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Refusing to rename an entry we could not prove contained is
                // the right call; it just means the spool is compromised, so
                // stop all new external effects rather than continuing.
                let detail = format!("quarantine of {capsule_uuid} ({reason}) failed: {error}");
                self.latch_and_persist(detail.clone(), now_wall_ms).await;
                Err(ExternalJournalError::Containment(detail))
            }
        }
    }

    /// Commit `prepared -> expired` for aged records with no-dispatch proof.
    pub async fn expire_prepared(
        &self,
        now_wall_ms: i64,
    ) -> Result<Vec<Uuid>, ExternalJournalError> {
        let expired = self
            .db
            .expire_prepared_external_operations(now_wall_ms, EXTERNAL_JOURNAL_PREPARED_TTL_MS)
            .await
            .map_err(db_error)?;
        for operation_id in &expired {
            if let Some(record) = self
                .db
                .external_operation(*operation_id)
                .await
                .map_err(db_error)?
            {
                self.confirm_and_release(&record).await?;
            }
        }
        Ok(expired)
    }

    /// Structured capacity/age diagnostics.
    pub async fn status(
        &self,
        now_wall_ms: i64,
    ) -> Result<ExternalJournalStatus, ExternalJournalError> {
        let mut status = collect_status(&self.db, Some(&self.spool), now_wall_ms).await?;
        if let Some(reason) = self.integrity_failure() {
            status.integrity_failure = Some(reason);
        }
        Ok(status)
    }
}

#[cfg(any(unix, test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteRenameArtifactV1 {
    pub logical_attachment_id: Uuid,
    pub operation_id: Uuid,
    pub dispatch_generation: u64,
    pub source_identity: FilesystemIdentityV1,
    pub source_parent_identity: FilesystemIdentityV1,
    pub target_parent_identity: FilesystemIdentityV1,
    pub source_name: String,
    pub target_name: String,
}

#[cfg(any(unix, test))]
fn remote_rename_artifact_name(artifact_id: Uuid, generation: u64) -> String {
    format!("{artifact_id}.{generation}.rr1")
}

#[cfg(any(unix, test))]
impl RemoteRenameArtifactV1 {
    const FIXED: usize = 4 + 16 + 16 + 8 + 57 * 3 + 2 + 2;

    fn encode(&self) -> Result<Vec<u8>, ExternalJournalError> {
        if self.logical_attachment_id.is_nil()
            || self.operation_id.is_nil()
            || self.operation_id.get_version_num() != 7
            || self.dispatch_generation == 0
        {
            return Err(ExternalJournalError::Containment(
                "rename artifact identity or generation is invalid".into(),
            ));
        }
        let source = self.source_name.as_bytes();
        let target = self.target_name.as_bytes();
        let source_len = u16::try_from(source.len()).map_err(|_| {
            ExternalJournalError::Containment("rename source name is too long".into())
        })?;
        let target_len = u16::try_from(target.len()).map_err(|_| {
            ExternalJournalError::Containment("rename target name is too long".into())
        })?;
        if source.is_empty()
            || target.is_empty()
            || source.contains(&0)
            || target.contains(&0)
            || self.source_name.contains('/')
            || self.source_name.contains('\\')
            || self.target_name.contains('/')
            || self.target_name.contains('\\')
            || matches!(self.source_name.as_str(), "." | "..")
            || matches!(self.target_name.as_str(), "." | "..")
        {
            return Err(ExternalJournalError::Containment(
                "rename artifact names must be nonempty and NUL-free".into(),
            ));
        }
        let mut out = Vec::with_capacity(Self::FIXED + source.len() + target.len());
        out.extend_from_slice(b"RRA1");
        out.extend_from_slice(self.logical_attachment_id.as_bytes());
        out.extend_from_slice(self.operation_id.as_bytes());
        out.extend_from_slice(&self.dispatch_generation.to_be_bytes());
        for identity in [
            self.source_identity,
            self.source_parent_identity,
            self.target_parent_identity,
        ] {
            out.extend_from_slice(
                &identity
                    .encode()
                    .map_err(|error| ExternalJournalError::Containment(error.to_string()))?,
            );
        }
        out.extend_from_slice(&source_len.to_be_bytes());
        out.extend_from_slice(source);
        out.extend_from_slice(&target_len.to_be_bytes());
        out.extend_from_slice(target);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ExternalJournalError> {
        if bytes.len() < Self::FIXED || &bytes[..4] != b"RRA1" {
            return Err(ExternalJournalError::Containment(
                "invalid rename artifact header".into(),
            ));
        }
        let mut cursor = 4;
        let take = |cursor: &mut usize, len: usize| -> Result<&[u8], ExternalJournalError> {
            let end = cursor.checked_add(len).ok_or_else(|| {
                ExternalJournalError::Containment("rename artifact length overflow".into())
            })?;
            let value = bytes.get(*cursor..end).ok_or_else(|| {
                ExternalJournalError::Containment("truncated rename artifact".into())
            })?;
            *cursor = end;
            Ok(value)
        };
        let logical_attachment_id = Uuid::from_slice(take(&mut cursor, 16)?)
            .map_err(|error| ExternalJournalError::Containment(error.to_string()))?;
        let operation_id = Uuid::from_slice(take(&mut cursor, 16)?)
            .map_err(|error| ExternalJournalError::Containment(error.to_string()))?;
        let dispatch_generation = u64::from_be_bytes(take(&mut cursor, 8)?.try_into().unwrap());
        let decode_identity = |cursor: &mut usize| {
            FilesystemIdentityV1::decode(take(cursor, 57)?)
                .map_err(|error| ExternalJournalError::Containment(error.to_string()))
        };
        let source_identity = decode_identity(&mut cursor)?;
        let source_parent_identity = decode_identity(&mut cursor)?;
        let target_parent_identity = decode_identity(&mut cursor)?;
        let source_len = u16::from_be_bytes(take(&mut cursor, 2)?.try_into().unwrap()) as usize;
        let source_name = std::str::from_utf8(take(&mut cursor, source_len)?)
            .map_err(|error| ExternalJournalError::Containment(error.to_string()))?
            .to_owned();
        let target_len = u16::from_be_bytes(take(&mut cursor, 2)?.try_into().unwrap()) as usize;
        let target_name = std::str::from_utf8(take(&mut cursor, target_len)?)
            .map_err(|error| ExternalJournalError::Containment(error.to_string()))?
            .to_owned();
        if cursor != bytes.len() {
            return Err(ExternalJournalError::Containment(
                "trailing rename artifact bytes".into(),
            ));
        }
        let decoded = Self {
            logical_attachment_id,
            operation_id,
            dispatch_generation,
            source_identity,
            source_parent_identity,
            target_parent_identity,
            source_name,
            target_name,
        };
        if decoded.encode()? != bytes {
            return Err(ExternalJournalError::Containment(
                "noncanonical rename artifact".into(),
            ));
        }
        Ok(decoded)
    }
}

/// Collect status without a key ring, for surfaces that only report.
pub async fn collect_status(
    db: &Db,
    spool: Option<&Spool>,
    now_wall_ms: i64,
) -> Result<ExternalJournalStatus, ExternalJournalError> {
    let capacity = db.external_journal_capacity().await.map_err(db_error)?;
    let age = db
        .external_journal_age_report(now_wall_ms)
        .await
        .map_err(db_error)?;
    let (spool_allocated_bytes, quarantined_entries) = match spool {
        Some(spool) => (spool.allocated_bytes()?, spool.list_quarantined()?.len()),
        None => (0, 0),
    };
    let integrity_failure = db
        .external_journal_integrity_fault()
        .await
        .map_err(db_error)?;
    Ok(ExternalJournalStatus {
        capacity,
        age,
        spool_allocated_bytes,
        quarantined_entries,
        integrity_failure,
    })
}

#[cfg(test)]
mod tests;
