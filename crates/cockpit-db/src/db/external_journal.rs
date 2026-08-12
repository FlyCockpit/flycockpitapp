//! Authoritative SQLite state machine for the generic external side-effect
//! journal.
//!
//! One bounded, restart-safe, idempotent journal serves every non-idempotent
//! external action (computer input, transcription, sidecars, image generation,
//! inference recovery) so no consumer invents a second spool. SQLite is
//! authoritative here; the fixed 64-KiB two-slot filesystem capsule lives in
//! `cockpit-core::external_journal` and only carries the minimum sanitized
//! projection needed when this database cannot record a post-handoff
//! transition.
//!
//! Rows hold digests and bounded tokens only. Never write prompts, typed
//! input, pixels, raw paths/URLs, credentials, headers, provider payloads,
//! signed query values, or spool HMAC key material through this module.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::db::Db;
use crate::db::secure_key::{
    activate_consumer_ref_conn, begin_release_consumer_ref_conn, get_namespace_conn,
    reserve_consumer_ref_conn,
};

/// Exact allocated size of one recovery capsule, in bytes.
pub const EXTERNAL_JOURNAL_CAPSULE_BYTES: i64 = 65_536;

/// Strict encoder cap for the sanitized canonical operation projection.
pub const EXTERNAL_JOURNAL_MAX_PROJECTION_BYTES: usize = 24 * 1024;

/// Hard ceiling on live capsules, admission plus recovery reserve.
pub const EXTERNAL_JOURNAL_HARD_LIMIT_CAPSULES: i64 = 4_096;

/// Hard ceiling on allocated capsule bytes (256 MiB).
pub const EXTERNAL_JOURNAL_HARD_LIMIT_BYTES: i64 = 256 * 1024 * 1024;

/// Capsules new operations may consume.
pub const EXTERNAL_JOURNAL_ADMISSION_CAPSULES: i64 = 3_072;

/// Allocated bytes new operations may consume (192 MiB).
pub const EXTERNAL_JOURNAL_ADMISSION_BYTES: i64 = 192 * 1024 * 1024;

/// Capsules reserved for recovery/import/quarantine bookkeeping.
pub const EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES: i64 = 1_024;

/// Allocated bytes reserved for recovery bookkeeping (64 MiB).
pub const EXTERNAL_JOURNAL_RECOVERY_RESERVE_BYTES: i64 = 64 * 1024 * 1024;

/// Age at which a `prepared` record with durable no-dispatch proof expires.
pub const EXTERNAL_JOURNAL_PREPARED_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Age at which unresolved work starts warning.
pub const EXTERNAL_JOURNAL_UNRESOLVED_WARN_MS: i64 = 15 * 60 * 1000;

/// Age at which unresolved work becomes doctor-critical.
pub const EXTERNAL_JOURNAL_UNRESOLVED_CRITICAL_MS: i64 = 24 * 60 * 60 * 1000;

/// Longest accepted identity token.
pub const EXTERNAL_JOURNAL_TOKEN_MAX_LEN: usize = 64;

/// Rows expired by one `prepared -> expired` sweep transaction.
pub const EXTERNAL_JOURNAL_EXPIRY_BATCH: usize = 256;

/// How long a session tombstone is retained after deletion.
///
/// A tombstone exists so resolution after session deletion can emit
/// owner-visible recovery status. Once nothing unresolved references the
/// session there is nothing left to explain, so the row is prunable.
pub const EXTERNAL_JOURNAL_TOMBSTONE_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Tombstones removed by one bounded prune pass.
pub const EXTERNAL_JOURNAL_TOMBSTONE_PRUNE_BATCH: usize = 256;

/// Secure-store namespace owning versioned spool HMAC material.
pub const EXTERNAL_JOURNAL_SPOOL_NAMESPACE: &str = "external-journal-spool/v1";

/// Consumer kind recorded against every reserved spool key version.
pub const EXTERNAL_JOURNAL_SPOOL_CONSUMER_KIND: &str = "external_journal_spool";

/// Stable consumer-reference id for one spool key version.
///
/// The reference lifecycle is the load-bearing part: a version stays reachable
/// while any capsule references it, and is released in the same transaction
/// that removes the last one.
pub fn external_journal_spool_key_reference_id(key_version: i64) -> String {
    format!("external-journal-spool:v{key_version}")
}

/// Parse a spool consumer id back to its key version.
pub fn external_journal_spool_key_version_from_reference(reference_id: &str) -> Option<i64> {
    reference_id
        .strip_prefix("external-journal-spool:v")?
        .parse()
        .ok()
}

/// A bounded `[a-z0-9_-]` identity token.
///
/// Operation kinds, owner-session ids, and idempotency keys all pass through
/// this type at the database boundary, so a caller cannot smuggle a prompt,
/// path, URL, header, credential, or signed query value into a journal row by
/// handing the module a `String`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExternalJournalToken(String);

impl ExternalJournalToken {
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() || value.len() > EXTERNAL_JOURNAL_TOKEN_MAX_LEN {
            bail!(
                "external journal token must be 1..={EXTERNAL_JOURNAL_TOKEN_MAX_LEN} bytes, got {}",
                value.len()
            );
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        {
            bail!("external journal token allows only [a-z0-9_-]");
        }
        Ok(Self(value.to_string()))
    }

    /// Bind an owner session by its canonical lowercase hyphenated UUID.
    pub fn for_session(session_id: Uuid) -> Self {
        Self(session_id.hyphenated().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ExternalJournalToken {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<ExternalJournalToken> for String {
    fn from(value: ExternalJournalToken) -> Self {
        value.0
    }
}

impl std::fmt::Display for ExternalJournalToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A lowercase SHA-256 hex digest.
///
/// Content never reaches a journal row or a capsule directly; it is hashed
/// into one of these first, which is what makes forbidden content
/// unrepresentable rather than merely discouraged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ExternalJournalDigest(String);

impl ExternalJournalDigest {
    /// Hash arbitrary bytes. The input never leaves this function.
    pub fn of(bytes: &[u8]) -> Self {
        let raw = Sha256::digest(bytes);
        let mut hex = String::with_capacity(64);
        for byte in raw {
            hex.push_str(&format!("{byte:02x}"));
        }
        Self(hex)
    }

    pub fn parse(value: &str) -> Result<Self> {
        let lower_hex = value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        if value.len() != 64 || !lower_hex {
            bail!("external journal digest must be 64 lowercase hex characters");
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Short prefix for diagnostics. Never the full digest in a log line.
    pub fn short(&self) -> &str {
        &self.0[..12]
    }
}

impl TryFrom<String> for ExternalJournalDigest {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<ExternalJournalDigest> for String {
    fn from(value: ExternalJournalDigest) -> Self {
        value.0
    }
}

/// The exact monotonic external-operation state graph.
///
/// `cancellation_requested` is deliberately **not** terminal: provider
/// evidence still chooses the authoritative outcome afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExternalJournalState {
    Prepared,
    Dispatching,
    Accepted,
    Rejected,
    SubmissionUnknown,
    Reconciling,
    CancellationRequested,
    Cancelled,
    Expired,
    CompletedAfterCancel,
    Succeeded,
    Failed,
}

impl ExternalJournalState {
    /// Every state, in graph order.
    pub const ALL: [Self; 12] = [
        Self::Prepared,
        Self::Dispatching,
        Self::Accepted,
        Self::Rejected,
        Self::SubmissionUnknown,
        Self::Reconciling,
        Self::CancellationRequested,
        Self::Cancelled,
        Self::Expired,
        Self::CompletedAfterCancel,
        Self::Succeeded,
        Self::Failed,
    ];

    /// Stable on-disk string. Keep aligned with the migration `CHECK` set.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Dispatching => "dispatching",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::SubmissionUnknown => "submission_unknown",
            Self::Reconciling => "reconciling",
            Self::CancellationRequested => "cancellation_requested",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::CompletedAfterCancel => "completed_after_cancel",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "dispatching" => Ok(Self::Dispatching),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "submission_unknown" => Ok(Self::SubmissionUnknown),
            "reconciling" => Ok(Self::Reconciling),
            "cancellation_requested" => Ok(Self::CancellationRequested),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            "completed_after_cancel" => Ok(Self::CompletedAfterCancel),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            other => bail!("unknown external journal state: {other}"),
        }
    }

    /// Terminal states accept no further transition.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelled
                | Self::Expired
                | Self::CompletedAfterCancel
                | Self::Succeeded
                | Self::Failed
                | Self::Rejected
        )
    }

    /// Work that has left `prepared` but has not reached a terminal state and
    /// can never be age-deleted: an external effect may already exist.
    ///
    /// `dispatching` counts. It is committed immediately before the provider
    /// call, so a record found in it after a restart may already have produced
    /// an external effect; recovery converts it to `submission_unknown`, and
    /// until it does it must still warn at 15m and go critical at 24h rather
    /// than looking like harmless in-flight work.
    pub fn is_unresolved(self) -> bool {
        matches!(
            self,
            Self::Dispatching
                | Self::Accepted
                | Self::SubmissionUnknown
                | Self::CancellationRequested
                | Self::Reconciling
        )
    }

    /// The exact edge set. Everything absent here is rejected.
    pub fn allows_transition_to(self, next: Self) -> bool {
        match self {
            Self::Prepared => matches!(next, Self::Dispatching | Self::Cancelled | Self::Expired),
            Self::Dispatching => matches!(
                next,
                Self::Accepted
                    | Self::Rejected
                    | Self::SubmissionUnknown
                    | Self::CancellationRequested
            ),
            Self::Accepted => matches!(
                next,
                Self::Succeeded
                    | Self::CompletedAfterCancel
                    | Self::Failed
                    | Self::CancellationRequested
            ),
            Self::SubmissionUnknown => {
                matches!(next, Self::Reconciling | Self::CancellationRequested)
            }
            Self::Reconciling => matches!(
                next,
                Self::Accepted
                    | Self::Rejected
                    | Self::SubmissionUnknown
                    | Self::Failed
                    | Self::CancellationRequested
            ),
            Self::CancellationRequested => matches!(
                next,
                Self::Cancelled
                    | Self::Accepted
                    | Self::CompletedAfterCancel
                    | Self::Failed
                    | Self::SubmissionUnknown
                    | Self::Reconciling
            ),
            Self::Cancelled
            | Self::Expired
            | Self::CompletedAfterCancel
            | Self::Succeeded
            | Self::Failed
            | Self::Rejected => false,
        }
    }
}

/// Provider idempotency evidence. Retry of an ambiguous non-idempotent
/// submission is permitted only when both halves are recorded.
///
/// `Debug` is redacted: a provider idempotency key is provider-issued
/// correlatable material and must not reach a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderIdempotency {
    pub key: ExternalJournalToken,
    pub contract: ExternalJournalToken,
}

impl std::fmt::Debug for ProviderIdempotency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderIdempotency")
            .field("key", &"[REDACTED]")
            .field("contract", &self.contract.as_str())
            .finish()
    }
}

/// A durable journal record.
///
/// `Debug` is implemented by hand. Even though every identity field is a
/// bounded token, an owner session id and an idempotency key are
/// caller-correlatable, so diagnostics get digests and short prefixes rather
/// than the raw values.
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalJournalRecord {
    pub operation_id: Uuid,
    pub operation_kind: ExternalJournalToken,
    pub owner_session_id: ExternalJournalToken,
    pub idempotency_key: ExternalJournalToken,
    pub payload_digest: ExternalJournalDigest,
    pub payload_len: i64,
    pub state: ExternalJournalState,
    pub version: i64,
    pub provider_idempotency: Option<ProviderIdempotency>,
    pub cancellation_requested_at_wall_ms: Option<i64>,
    pub cancellation_requested_version: Option<i64>,
    pub created_at_wall_ms: i64,
    pub updated_at_wall_ms: i64,
    pub dispatch_started_at_wall_ms: Option<i64>,
    pub terminal_at_wall_ms: Option<i64>,
}

impl std::fmt::Debug for ExternalJournalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalJournalRecord")
            .field("operation_id", &self.operation_id)
            .field("operation_kind", &self.operation_kind.as_str())
            .field(
                "owner_session",
                &ExternalJournalDigest::of(self.owner_session_id.as_str().as_bytes())
                    .short()
                    .to_string(),
            )
            .field(
                "idempotency_key",
                &ExternalJournalDigest::of(self.idempotency_key.as_str().as_bytes())
                    .short()
                    .to_string(),
            )
            .field("payload_digest", &self.payload_digest.short())
            .field("payload_len", &self.payload_len)
            .field("state", &self.state.as_str())
            .field("version", &self.version)
            .field("provider_idempotency", &self.provider_idempotency.is_some())
            .field(
                "cancellation_requested_at_wall_ms",
                &self.cancellation_requested_at_wall_ms,
            )
            .field(
                "cancellation_requested_version",
                &self.cancellation_requested_version,
            )
            .field("created_at_wall_ms", &self.created_at_wall_ms)
            .field("updated_at_wall_ms", &self.updated_at_wall_ms)
            .field(
                "dispatch_started_at_wall_ms",
                &self.dispatch_started_at_wall_ms,
            )
            .field("terminal_at_wall_ms", &self.terminal_at_wall_ms)
            .finish()
    }
}

impl ExternalJournalRecord {
    /// Whether the orthogonal cancellation fact is set.
    pub fn is_cancellation_requested(&self) -> bool {
        self.cancellation_requested_at_wall_ms.is_some()
    }

    /// Whether an external effect could already exist.
    pub fn dispatch_may_have_started(&self) -> bool {
        self.dispatch_started_at_wall_ms.is_some()
    }

    /// Retry of an ambiguous submission is allowed only under a recorded
    /// provider idempotency key *and* contract. Never blind-resubmit.
    pub fn retry_permitted(&self) -> bool {
        self.provider_idempotency.is_some()
    }
}

/// Result of a compare-and-set transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalTransitionOutcome {
    /// The transition committed and bumped the version.
    Committed(ExternalJournalRecord),
    /// The record already sat in the requested state; nothing was written and
    /// no second event was emitted.
    Duplicate(ExternalJournalRecord),
    /// Another writer won the version race; the caller sees the current row.
    Conflict(ExternalJournalRecord),
}

impl ExternalTransitionOutcome {
    /// The current record, whichever branch was taken.
    pub fn record(&self) -> &ExternalJournalRecord {
        match self {
            Self::Committed(record) | Self::Duplicate(record) | Self::Conflict(record) => record,
        }
    }

    pub fn is_committed(&self) -> bool {
        matches!(self, Self::Committed(_))
    }
}

/// Result of preparing an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalPrepareOutcome {
    /// A fresh `prepared` record was committed.
    Created(ExternalJournalRecord),
    /// The identity already exists; the caller sees the current record.
    Existing(ExternalJournalRecord),
}

impl ExternalPrepareOutcome {
    pub fn record(&self) -> &ExternalJournalRecord {
        match self {
            Self::Created(record) | Self::Existing(record) => record,
        }
    }
}

/// Immutable identity and payload facts for a new operation.
///
/// Every field is a validated token or digest, so the database boundary
/// cannot be handed a raw `String` carrying forbidden content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareExternalOperation {
    pub operation_kind: ExternalJournalToken,
    pub owner_session_id: ExternalJournalToken,
    pub idempotency_key: ExternalJournalToken,
    pub payload_digest: ExternalJournalDigest,
    pub payload_len: usize,
    pub provider_idempotency: Option<ProviderIdempotency>,
}

/// Which fixed capacity partition a capsule draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsulePartition {
    /// New external work. Bounded by 3,072 capsules / 192 MiB.
    Admission,
    /// Recovery/import/quarantine bookkeeping. Bounded by 1,024 / 64 MiB.
    Recovery,
}

impl CapsulePartition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Recovery => "recovery",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "admission" => Ok(Self::Admission),
            "recovery" => Ok(Self::Recovery),
            other => bail!("unknown capsule partition: {other}"),
        }
    }

    /// Capsule-count ceiling for this partition.
    pub fn capsule_limit(self) -> i64 {
        match self {
            Self::Admission => EXTERNAL_JOURNAL_ADMISSION_CAPSULES,
            Self::Recovery => EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES,
        }
    }

    /// Allocated-byte ceiling for this partition.
    pub fn byte_limit(self) -> i64 {
        match self {
            Self::Admission => EXTERNAL_JOURNAL_ADMISSION_BYTES,
            Self::Recovery => EXTERNAL_JOURNAL_RECOVERY_RESERVE_BYTES,
        }
    }
}

/// A reserved capsule slot in the capacity ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleReservation {
    pub operation_id: Uuid,
    pub capsule_uuid: Uuid,
    pub key_version: i64,
    pub partition: CapsulePartition,
    pub allocated_bytes: i64,
}

/// Why a capsule reservation is being released. Each reason carries its own
/// precondition so no caller can free capacity a live operation still needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleReleaseReason {
    /// The operation reached a terminal state and SQLite confirmed it.
    TerminalConfirmed,
    /// Pre-dispatch provisioning failed; the record never left `prepared`.
    UndispatchedRollback,
    /// The capsule file is gone, so the reservation accounts for a durable
    /// medium that no longer exists.
    MediumMissing,
}

/// What the ledger did when a capsule was quarantined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineLedgerOutcome {
    /// The row moved into the bounded recovery partition.
    MovedToRecovery,
    /// The recovery reserve was full, so the row stayed in its partition and
    /// was only flagged. Dispatch is blocked either way.
    FlaggedInPlace,
    NotFound,
}

/// Outcome of a capsule admission attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleAdmission {
    Reserved(CapsuleReservation),
    /// The reservation already exists; capsule creation is idempotent.
    AlreadyReserved(CapsuleReservation),
    /// The partition or the hard limit is full. No capsule, so no dispatch.
    Full(ExternalJournalCapacity),
}

/// Exact record/byte counts for doctor, headless, and TUI status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExternalJournalCapacity {
    pub admission_capsules: i64,
    pub admission_bytes: i64,
    pub recovery_capsules: i64,
    pub recovery_bytes: i64,
    pub quarantined_capsules: i64,
}

impl ExternalJournalCapacity {
    /// Saturating on purpose: a corrupted ledger must report "over the limit",
    /// never panic or wrap into an apparently-free partition.
    pub fn total_capsules(&self) -> i64 {
        self.admission_capsules
            .saturating_add(self.recovery_capsules)
    }

    /// Saturating for the same reason as [`Self::total_capsules`].
    pub fn total_bytes(&self) -> i64 {
        self.admission_bytes.saturating_add(self.recovery_bytes)
    }

    /// Whether new external work is blocked by a full partition.
    ///
    /// A full *recovery* partition blocks admission too: the reserve exists so
    /// a successful handoff always has somewhere to write its fallback, and
    /// once it is gone no new external effect may be started.
    pub fn admission_blocked(&self) -> bool {
        self.admission_block_reason().is_some()
    }

    /// Why admission is blocked, for status surfaces.
    pub fn admission_block_reason(&self) -> Option<&'static str> {
        if self.admission_capsules >= EXTERNAL_JOURNAL_ADMISSION_CAPSULES {
            Some("admission capsule count")
        } else if self.admission_bytes >= EXTERNAL_JOURNAL_ADMISSION_BYTES {
            Some("admission byte budget")
        } else if self.recovery_capsules >= EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES {
            Some("recovery reserve capsule count")
        } else if self.recovery_bytes >= EXTERNAL_JOURNAL_RECOVERY_RESERVE_BYTES {
            Some("recovery reserve byte budget")
        } else if self.total_capsules() >= EXTERNAL_JOURNAL_HARD_LIMIT_CAPSULES
            || self.total_bytes() >= EXTERNAL_JOURNAL_HARD_LIMIT_BYTES
        {
            Some("hard limit")
        } else {
            None
        }
    }
}

/// Age buckets for unresolved work. Unresolved records never age-expire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExternalJournalAgeReport {
    pub unresolved: i64,
    pub warning: i64,
    pub critical: i64,
    pub oldest_age_ms: i64,
}

impl ExternalJournalAgeReport {
    pub fn is_critical(&self) -> bool {
        self.critical > 0
    }

    pub fn is_warning(&self) -> bool {
        self.warning > 0
    }
}

/// Consumer-queue lifecycle. A queue entry expires in its own terminal state
/// and never invents an external-journal operation row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalQueueState {
    Queued,
    Journaled,
    Cancelled,
    Expired,
}

impl ExternalQueueState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Journaled => "journaled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "journaled" => Ok(Self::Journaled),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            other => bail!("unknown external queue state: {other}"),
        }
    }
}

const RECORD_COLUMNS: &str = "operation_id, operation_kind, owner_session_id, idempotency_key, \
     payload_digest, payload_len, state, version, provider_idempotency_key, \
     provider_idempotency_contract, cancellation_requested_at_wall_ms, \
     cancellation_requested_version, created_at_wall_ms, updated_at_wall_ms, \
     dispatch_started_at_wall_ms, terminal_at_wall_ms";

/// Turn any decode failure into a column-tagged rusqlite error.
fn decode_failure(index: usize, error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::other(error.to_string())),
    )
}

/// Decode a row, re-validating every stored token and digest.
///
/// Re-validating on read means a row written by something that bypassed this
/// module cannot smuggle unbounded content back into memory.
fn decode_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExternalJournalRecord> {
    let operation_id: String = row.get(0)?;
    let operation_kind: String = row.get(1)?;
    let owner_session_id: String = row.get(2)?;
    let idempotency_key: String = row.get(3)?;
    let payload_digest: String = row.get(4)?;
    let state: String = row.get(6)?;
    let provider_key: Option<String> = row.get(8)?;
    let provider_contract: Option<String> = row.get(9)?;
    Ok(ExternalJournalRecord {
        operation_id: Uuid::parse_str(&operation_id).map_err(|error| decode_failure(0, error))?,
        operation_kind: ExternalJournalToken::parse(&operation_kind)
            .map_err(|error| decode_failure(1, error))?,
        owner_session_id: ExternalJournalToken::parse(&owner_session_id)
            .map_err(|error| decode_failure(2, error))?,
        idempotency_key: ExternalJournalToken::parse(&idempotency_key)
            .map_err(|error| decode_failure(3, error))?,
        payload_digest: ExternalJournalDigest::parse(&payload_digest)
            .map_err(|error| decode_failure(4, error))?,
        payload_len: row.get(5)?,
        state: ExternalJournalState::parse(&state).map_err(|error| decode_failure(6, error))?,
        version: row.get(7)?,
        provider_idempotency: match (provider_key, provider_contract) {
            (Some(key), Some(contract)) => Some(ProviderIdempotency {
                key: ExternalJournalToken::parse(&key).map_err(|error| decode_failure(8, error))?,
                contract: ExternalJournalToken::parse(&contract)
                    .map_err(|error| decode_failure(9, error))?,
            }),
            _ => None,
        },
        cancellation_requested_at_wall_ms: row.get(10)?,
        cancellation_requested_version: row.get(11)?,
        created_at_wall_ms: row.get(12)?,
        updated_at_wall_ms: row.get(13)?,
        dispatch_started_at_wall_ms: row.get(14)?,
        terminal_at_wall_ms: row.get(15)?,
    })
}

/// Load one record by id inside an open transaction.
pub fn external_operation_conn(
    conn: &Connection,
    operation_id: Uuid,
) -> Result<Option<ExternalJournalRecord>> {
    conn.query_row(
        &format!(
            "SELECT {RECORD_COLUMNS} FROM external_journal_operations WHERE operation_id = ?1"
        ),
        params![operation_id.to_string()],
        decode_record,
    )
    .optional()
    .context("loading external journal operation")
}

fn external_operation_by_identity_conn(
    conn: &Connection,
    operation_kind: &ExternalJournalToken,
    owner_session_id: &ExternalJournalToken,
    idempotency_key: &ExternalJournalToken,
) -> Result<Option<ExternalJournalRecord>> {
    conn.query_row(
        &format!(
            "SELECT {RECORD_COLUMNS} FROM external_journal_operations
             WHERE operation_kind = ?1 AND owner_session_id = ?2 AND idempotency_key = ?3"
        ),
        params![
            operation_kind.as_str(),
            owner_session_id.as_str(),
            idempotency_key.as_str()
        ],
        decode_record,
    )
    .optional()
    .context("loading external journal operation by identity")
}

/// Append the transition event. The migration's partial unique index makes a
/// second terminal event impossible, so a duplicate terminal write fails
/// loudly rather than emitting twice.
fn insert_event_conn(
    conn: &Connection,
    record: &ExternalJournalRecord,
    from_state: ExternalJournalState,
    now_wall_ms: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO external_journal_events (
             event_id, operation_id, version, from_state, to_state, terminal,
             cancellation_requested_at_wall_ms, emitted_at_wall_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            Uuid::new_v4().to_string(),
            record.operation_id.to_string(),
            record.version,
            from_state.as_str(),
            record.state.as_str(),
            i64::from(record.state.is_terminal()),
            record.cancellation_requested_at_wall_ms,
            now_wall_ms,
        ],
    )
    .context("emitting external journal transition event")?;
    Ok(())
}

/// Whether the cancellation fact forbids this edge.
///
/// Once cancellation is requested, authoritative successful completion must be
/// `completed_after_cancel`; plain `succeeded` is permanently unreachable.
fn cancellation_permits(
    record: &ExternalJournalRecord,
    next: ExternalJournalState,
) -> Result<(), &'static str> {
    if record.is_cancellation_requested() && next == ExternalJournalState::Succeeded {
        return Err("plain succeeded is forbidden after a cancellation request");
    }
    Ok(())
}

/// Whether `expired` is provable for this record.
fn expiry_permitted(record: &ExternalJournalRecord) -> Result<(), &'static str> {
    if record.dispatch_may_have_started() {
        return Err("expired requires durable proof that dispatch never began");
    }
    Ok(())
}

/// A transition the state graph forbids.
///
/// Distinct from an infrastructure failure on purpose: a caller holding a
/// post-handoff outcome must route a legality rejection through
/// cancellation-aware retargeting, and must **never** mistake it for a
/// database outage and write the rejected state into a capsule slot, where it
/// would be durable, wrong, and permanently unimportable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalExternalTransition {
    pub from: ExternalJournalState,
    pub to: ExternalJournalState,
    pub reason: String,
}

impl std::fmt::Display for IllegalExternalTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "illegal external journal transition {} -> {}: {}",
            self.from.as_str(),
            self.to.as_str(),
            self.reason
        )
    }
}

impl std::error::Error for IllegalExternalTransition {}

/// Pure edge validation used by both the DB layer and the state-matrix tests.
pub fn validate_external_transition(
    record: &ExternalJournalRecord,
    next: ExternalJournalState,
) -> Result<()> {
    if !record.state.allows_transition_to(next) {
        return Err(illegal_transition(
            record.state,
            next,
            "edge is not in the state graph",
        ));
    }
    if let Err(reason) = cancellation_permits(record, next) {
        return Err(illegal_transition(record.state, next, reason));
    }
    if next == ExternalJournalState::Expired
        && let Err(reason) = expiry_permitted(record)
    {
        return Err(illegal_transition(record.state, next, reason));
    }
    Ok(())
}

/// Build a typed legality rejection.
///
/// A free function rather than a local closure: the blocking-boundary gate
/// resolves crate-local free functions but fails closed on indirect callables
/// reached from a public body, and it is right to do so.
fn illegal_transition(
    from: ExternalJournalState,
    to: ExternalJournalState,
    reason: &str,
) -> anyhow::Error {
    anyhow::Error::new(IllegalExternalTransition {
        from,
        to,
        reason: reason.to_string(),
    })
}

/// Whether an error is a legality rejection rather than an infrastructure
/// failure.
pub fn illegal_transition_cause(error: &anyhow::Error) -> Option<&IllegalExternalTransition> {
    error.downcast_ref::<IllegalExternalTransition>()
}

/// Apply a validated transition to an already-loaded record inside a
/// transaction, emitting exactly one event.
fn commit_transition_conn(
    conn: &Connection,
    current: &ExternalJournalRecord,
    next: ExternalJournalState,
    now_wall_ms: i64,
    request_cancellation: bool,
) -> Result<ExternalJournalRecord> {
    commit_transition_at_version_conn(conn, current, next, now_wall_ms, request_cancellation, None)
}

/// Apply a validated transition, optionally at an explicit version.
///
/// Imports pass the authenticated slot's own `journal_version` rather than
/// letting the record advance by one. Renumbering would be silent history
/// rewriting: a slot asserting v4 imported as v3 makes a genuine gap — an
/// intermediate fact that existed and no longer does, possibly cancellation
/// evidence — indistinguishable from a contiguous replay.
fn commit_transition_at_version_conn(
    conn: &Connection,
    current: &ExternalJournalRecord,
    next: ExternalJournalState,
    now_wall_ms: i64,
    request_cancellation: bool,
    target_version: Option<i64>,
) -> Result<ExternalJournalRecord> {
    validate_external_transition(current, next)?;

    let next_version = match target_version {
        Some(version) => {
            if version <= current.version {
                bail!(
                    "external journal import version {version} does not advance {}",
                    current.version
                );
            }
            version
        }
        None => current
            .version
            .checked_add(1)
            .context("external journal version overflow")?,
    };
    // The cancellation fact is monotonic: the first request wins forever.
    let (cancel_at, cancel_version) = if current.is_cancellation_requested() {
        (
            current.cancellation_requested_at_wall_ms,
            current.cancellation_requested_version,
        )
    } else if request_cancellation || next == ExternalJournalState::CancellationRequested {
        (Some(now_wall_ms), Some(next_version))
    } else {
        (None, None)
    };
    let dispatch_started = if next == ExternalJournalState::Dispatching {
        Some(current.dispatch_started_at_wall_ms.unwrap_or(now_wall_ms))
    } else {
        current.dispatch_started_at_wall_ms
    };
    let terminal_at = if next.is_terminal() {
        Some(now_wall_ms)
    } else {
        current.terminal_at_wall_ms
    };

    let updated = conn
        .execute(
            "UPDATE external_journal_operations
                SET state = ?1,
                    version = ?2,
                    updated_at_wall_ms = ?3,
                    cancellation_requested_at_wall_ms = ?4,
                    cancellation_requested_version = ?5,
                    dispatch_started_at_wall_ms = ?6,
                    terminal_at_wall_ms = ?7
              WHERE operation_id = ?8 AND version = ?9",
            params![
                next.as_str(),
                next_version,
                now_wall_ms,
                cancel_at,
                cancel_version,
                dispatch_started,
                terminal_at,
                current.operation_id.to_string(),
                current.version,
            ],
        )
        .context("committing external journal transition")?;
    if updated != 1 {
        bail!("external journal compare-and-set lost its version race");
    }

    let record = external_operation_conn(conn, current.operation_id)?
        .context("external journal record vanished mid-transition")?;
    insert_event_conn(conn, &record, current.state, now_wall_ms)?;
    Ok(record)
}

/// Compare-and-set a transition inside an open transaction.
pub fn transition_external_operation_conn(
    conn: &Connection,
    operation_id: Uuid,
    expected_version: i64,
    next: ExternalJournalState,
    now_wall_ms: i64,
) -> Result<ExternalTransitionOutcome> {
    let current = external_operation_conn(conn, operation_id)?
        .with_context(|| format!("unknown external journal operation {operation_id}"))?;
    if current.version != expected_version {
        // Two recovery workers may poll; only one version commits. A repeat of
        // an already-applied transition returns the current record.
        if current.state == next {
            return Ok(ExternalTransitionOutcome::Duplicate(current));
        }
        return Ok(ExternalTransitionOutcome::Conflict(current));
    }
    if current.state == next {
        return Ok(ExternalTransitionOutcome::Duplicate(current));
    }
    let record = commit_transition_conn(conn, &current, next, now_wall_ms, false)?;
    Ok(ExternalTransitionOutcome::Committed(record))
}

/// Prepare a journal row inside a caller-owned transaction. This is the only
/// seam for domain preflight that must commit its reservation and the durable
/// external-effect identity atomically.
pub(crate) fn prepare_external_operation_conn(
    conn: &Connection,
    request: &PrepareExternalOperation,
    now_wall_ms: i64,
) -> Result<ExternalPrepareOutcome> {
    if request.payload_len > EXTERNAL_JOURNAL_MAX_PROJECTION_BYTES {
        bail!(
            "external journal projection is {} bytes; the encoder cap is {}",
            request.payload_len,
            EXTERNAL_JOURNAL_MAX_PROJECTION_BYTES
        );
    }
    let payload_len = i64::try_from(request.payload_len)
        .context("external journal projection length overflow")?;
    if let Some(existing) = external_operation_by_identity_conn(
        conn,
        &request.operation_kind,
        &request.owner_session_id,
        &request.idempotency_key,
    )? {
        return Ok(ExternalPrepareOutcome::Existing(existing));
    }
    let operation_id = Uuid::new_v4();
    let (provider_key, provider_contract) = match &request.provider_idempotency {
        Some(evidence) => (
            Some(evidence.key.as_str().to_string()),
            Some(evidence.contract.as_str().to_string()),
        ),
        None => (None, None),
    };
    conn.execute(
        "INSERT INTO external_journal_operations (
             operation_id, operation_kind, owner_session_id, idempotency_key,
             payload_digest, payload_len, state, version,
             provider_idempotency_key, provider_idempotency_contract,
             created_at_wall_ms, updated_at_wall_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'prepared', 1, ?7, ?8, ?9, ?9)",
        params![
            operation_id.to_string(),
            request.operation_kind.as_str(),
            request.owner_session_id.as_str(),
            request.idempotency_key.as_str(),
            request.payload_digest.as_str(),
            payload_len,
            provider_key,
            provider_contract,
            now_wall_ms,
        ],
    )
    .context("inserting prepared external journal operation")?;
    let record = external_operation_conn(conn, operation_id)?
        .context("prepared external journal record vanished")?;
    insert_event_conn(conn, &record, ExternalJournalState::Prepared, now_wall_ms)?;
    Ok(ExternalPrepareOutcome::Created(record))
}

impl Db {
    /// Commit a `prepared` record before any external handoff.
    ///
    /// Identity `(operation_kind, owner_session, idempotency_key)` is unique;
    /// re-preparing the same identity returns the existing record instead of
    /// creating a second external effect.
    pub async fn prepare_external_operation(
        &self,
        request: PrepareExternalOperation,
        now_wall_ms: i64,
    ) -> Result<ExternalPrepareOutcome> {
        self.transaction(move |conn| prepare_external_operation_conn(conn, &request, now_wall_ms))
            .await
    }

    /// Load one record by id.
    pub async fn external_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<ExternalJournalRecord>> {
        self.read(move |conn| external_operation_conn(conn, operation_id))
            .await
    }

    /// Load one record by its stable identity triple.
    pub async fn external_operation_by_identity(
        &self,
        operation_kind: &ExternalJournalToken,
        owner_session_id: &ExternalJournalToken,
        idempotency_key: &ExternalJournalToken,
    ) -> Result<Option<ExternalJournalRecord>> {
        let operation_kind = operation_kind.clone();
        let owner_session_id = owner_session_id.clone();
        let idempotency_key = idempotency_key.clone();
        self.read(move |conn| {
            external_operation_by_identity_conn(
                conn,
                &operation_kind,
                &owner_session_id,
                &idempotency_key,
            )
        })
        .await
    }

    /// Compare-and-set one transition. Emits at most one event.
    pub async fn transition_external_operation(
        &self,
        operation_id: Uuid,
        expected_version: i64,
        next: ExternalJournalState,
        now_wall_ms: i64,
    ) -> Result<ExternalTransitionOutcome> {
        self.transaction(move |conn| {
            transition_external_operation_conn(
                conn,
                operation_id,
                expected_version,
                next,
                now_wall_ms,
            )
        })
        .await
    }

    /// Record the orthogonal cancellation fact and move to the state that the
    /// current state permits.
    ///
    /// While `prepared` this proves no effect and commits `prepared ->
    /// cancelled`. After the `dispatching` commit it can only reach
    /// `cancellation_requested`; provider evidence later chooses `cancelled`,
    /// `completed_after_cancel`, `failed`, or continued unknown/reconciling.
    pub async fn request_external_operation_cancellation(
        &self,
        operation_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<ExternalTransitionOutcome> {
        self.transaction(move |conn| {
            let current = external_operation_conn(conn, operation_id)?
                .with_context(|| format!("unknown external journal operation {operation_id}"))?;
            if current.state.is_terminal() || current.is_cancellation_requested() {
                // Monotonic: the first request already set the fact, and a
                // terminal record keeps whatever it recorded.
                return Ok(ExternalTransitionOutcome::Duplicate(current));
            }
            let next = match current.state {
                ExternalJournalState::Prepared => ExternalJournalState::Cancelled,
                _ => ExternalJournalState::CancellationRequested,
            };
            let record = commit_transition_conn(conn, &current, next, now_wall_ms, true)?;
            Ok(ExternalTransitionOutcome::Committed(record))
        })
        .await
    }

    /// Every transition event emitted for one operation, oldest first.
    pub async fn external_operation_events(
        &self,
        operation_id: Uuid,
    ) -> Result<Vec<ExternalJournalTransitionEvent>> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT version, from_state, to_state, terminal,
                            cancellation_requested_at_wall_ms, emitted_at_wall_ms
                       FROM external_journal_events
                      WHERE operation_id = ?1
                      ORDER BY version ASC",
                )
                .context("preparing external journal event query")?;
            let rows = stmt
                .query_map(params![operation_id.to_string()], |row| {
                    let from_state: String = row.get(1)?;
                    let to_state: String = row.get(2)?;
                    let terminal: i64 = row.get(3)?;
                    Ok((
                        row.get::<_, i64>(0)?,
                        from_state,
                        to_state,
                        terminal == 1,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .context("querying external journal events")?;
            let mut out = Vec::new();
            for row in rows {
                let (version, from_state, to_state, terminal, cancel_at, emitted_at) =
                    row.context("decoding external journal event")?;
                out.push(ExternalJournalTransitionEvent {
                    operation_id,
                    version,
                    from_state: ExternalJournalState::parse(&from_state)?,
                    to_state: ExternalJournalState::parse(&to_state)?,
                    terminal,
                    cancellation_requested_at_wall_ms: cancel_at,
                    emitted_at_wall_ms: emitted_at,
                });
            }
            Ok(out)
        })
        .await
    }

    /// Commit `prepared -> expired` for records older than the 24-hour TTL
    /// that carry durable proof dispatch never began. Unresolved work is never
    /// touched here.
    pub async fn expire_prepared_external_operations(
        &self,
        now_wall_ms: i64,
        ttl_ms: i64,
    ) -> Result<Vec<Uuid>> {
        self.transaction(move |conn| {
            let cutoff = now_wall_ms
                .checked_sub(ttl_ms)
                .context("external journal expiry cutoff overflow")?;
            let mut stmt = conn
                .prepare(
                    "SELECT operation_id FROM external_journal_operations
                      WHERE state = 'prepared'
                        AND dispatch_started_at_wall_ms IS NULL
                        AND created_at_wall_ms <= ?1
                      ORDER BY created_at_wall_ms ASC
                      LIMIT ?2",
                )
                .context("preparing external journal expiry scan")?;
            let batch = i64::try_from(EXTERNAL_JOURNAL_EXPIRY_BATCH)
                .context("external journal expiry batch overflow")?;
            let ids = stmt
                .query_map(params![cutoff, batch], |row| row.get::<_, String>(0))
                .context("scanning expirable external journal operations")?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("collecting expirable external journal operations")?;
            drop(stmt);

            let mut expired = Vec::with_capacity(ids.len());
            for id in ids {
                let operation_id =
                    Uuid::parse_str(&id).context("decoding expirable operation id")?;
                let current = external_operation_conn(conn, operation_id)?
                    .context("expirable external journal record vanished")?;
                let record = commit_transition_conn(
                    conn,
                    &current,
                    ExternalJournalState::Expired,
                    now_wall_ms,
                    false,
                )?;
                expired.push(record.operation_id);
            }
            Ok(expired)
        })
        .await
    }

    /// Unresolved-work age buckets. Nothing here is ever age-deleted.
    pub async fn external_journal_age_report(
        &self,
        now_wall_ms: i64,
    ) -> Result<ExternalJournalAgeReport> {
        self.read(move |conn| external_journal_age_report_conn(conn, now_wall_ms))
            .await
    }

    /// Exact capsule/byte counts per partition.
    pub async fn external_journal_capacity(&self) -> Result<ExternalJournalCapacity> {
        self.read(external_journal_capacity_conn).await
    }

    /// Reserve one 64-KiB capsule against a fixed partition.
    ///
    /// Both the count and the allocated-byte admission are checked before
    /// capsule creation, so a full partition yields no capsule and therefore
    /// no dispatch.
    pub async fn reserve_external_journal_capsule(
        &self,
        operation_id: Uuid,
        capsule_uuid: Uuid,
        key_version: i64,
        partition: CapsulePartition,
        secure_store_backed: bool,
        now_wall_ms: i64,
    ) -> Result<CapsuleAdmission> {
        self.transaction(move |conn| {
            if let Some(existing) = capsule_reservation_conn(conn, operation_id)? {
                return Ok(CapsuleAdmission::AlreadyReserved(existing));
            }
            let capacity = external_journal_capacity_conn(conn)?;
            let (used_capsules, used_bytes) = match partition {
                CapsulePartition::Admission => {
                    (capacity.admission_capsules, capacity.admission_bytes)
                }
                CapsulePartition::Recovery => (capacity.recovery_capsules, capacity.recovery_bytes),
            };
            let next_capsules = used_capsules
                .checked_add(1)
                .context("capsule count overflow")?;
            let next_bytes = used_bytes
                .checked_add(EXTERNAL_JOURNAL_CAPSULE_BYTES)
                .context("capsule byte overflow")?;
            let next_total_capsules = capacity
                .total_capsules()
                .checked_add(1)
                .context("total capsule count overflow")?;
            let next_total_bytes = capacity
                .total_bytes()
                .checked_add(EXTERNAL_JOURNAL_CAPSULE_BYTES)
                .context("total capsule byte overflow")?;
            if next_capsules > partition.capsule_limit()
                || next_bytes > partition.byte_limit()
                || next_total_capsules > EXTERNAL_JOURNAL_HARD_LIMIT_CAPSULES
                || next_total_bytes > EXTERNAL_JOURNAL_HARD_LIMIT_BYTES
            {
                return Ok(CapsuleAdmission::Full(capacity));
            }
            conn.execute(
                "INSERT INTO external_journal_spool_capsules (
                     operation_id, capsule_uuid, key_version, allocated_bytes,
                     capacity_partition, quarantined, created_at_wall_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
                params![
                    operation_id.to_string(),
                    capsule_uuid.to_string(),
                    key_version,
                    EXTERNAL_JOURNAL_CAPSULE_BYTES,
                    partition.as_str(),
                    now_wall_ms,
                ],
            )
            .context("reserving external journal capsule")?;
            // Same transaction, per the secure-key consumer contract: the
            // reference becomes Active exactly when the capsule row that makes
            // the key reachable is written. Never check-then-write across two
            // transactions.
            if secure_store_backed {
                activate_spool_key_reference_conn(conn, key_version)?;
            }
            Ok(CapsuleAdmission::Reserved(CapsuleReservation {
                operation_id,
                capsule_uuid,
                key_version,
                partition,
                allocated_bytes: EXTERNAL_JOURNAL_CAPSULE_BYTES,
            }))
        })
        .await
    }

    /// The reservation for one operation, if any.
    pub async fn external_journal_capsule(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<CapsuleReservation>> {
        self.read(move |conn| capsule_reservation_conn(conn, operation_id))
            .await
    }

    /// Every live capsule reservation, oldest first. Recovery iterates this
    /// rather than trusting whatever the spool directory happens to contain.
    pub async fn list_external_journal_capsules(&self) -> Result<Vec<CapsuleReservation>> {
        self.read(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT operation_id, capsule_uuid, key_version, allocated_bytes,
                            capacity_partition
                       FROM external_journal_spool_capsules
                      ORDER BY created_at_wall_ms ASC",
                )
                .context("preparing capsule reservation scan")?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .context("scanning capsule reservations")?;
            let mut out = Vec::new();
            for row in rows {
                let (operation_id, capsule_uuid, key_version, allocated_bytes, partition) =
                    row.context("decoding capsule reservation")?;
                out.push(CapsuleReservation {
                    operation_id: Uuid::parse_str(&operation_id)
                        .context("decoding reservation operation id")?,
                    capsule_uuid: Uuid::parse_str(&capsule_uuid)
                        .context("decoding reservation capsule uuid")?,
                    key_version,
                    partition: CapsulePartition::parse(&partition)?,
                    allocated_bytes,
                });
            }
            Ok(out)
        })
        .await
    }

    /// Release a capsule reservation. Refuses unless the operation's terminal
    /// state is confirmed in SQLite first.
    pub async fn release_external_journal_capsule(&self, operation_id: Uuid) -> Result<bool> {
        self.release_external_journal_capsule_reservation(
            operation_id,
            CapsuleReleaseReason::TerminalConfirmed,
        )
        .await
    }

    /// Release a reservation whose durable medium is gone.
    ///
    /// Recovery uses this when a ledger row survives but its capsule file does
    /// not (a cancellation racing terminal cleanup, or an operator deletion).
    /// SQLite still holds the record, so nothing is lost; without this the
    /// reservation would drain admission capacity permanently.
    pub async fn release_external_journal_capsule_without_medium(
        &self,
        operation_id: Uuid,
    ) -> Result<bool> {
        self.release_external_journal_capsule_reservation(
            operation_id,
            CapsuleReleaseReason::MediumMissing,
        )
        .await
    }

    /// Undo a capsule reservation whose provisioning failed before dispatch.
    ///
    /// Refuses once the record has left `prepared`: after the `dispatching`
    /// commit an external effect may exist and the capsule must survive as the
    /// fallback medium.
    pub async fn rollback_external_journal_capsule_reservation(
        &self,
        operation_id: Uuid,
    ) -> Result<bool> {
        self.release_external_journal_capsule_reservation(
            operation_id,
            CapsuleReleaseReason::UndispatchedRollback,
        )
        .await
    }

    async fn release_external_journal_capsule_reservation(
        &self,
        operation_id: Uuid,
        reason: CapsuleReleaseReason,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let record = external_operation_conn(conn, operation_id)?
                .with_context(|| format!("unknown external journal operation {operation_id}"))?;
            match reason {
                CapsuleReleaseReason::TerminalConfirmed => {
                    if !record.state.is_terminal() {
                        bail!(
                            "refusing to release capsule for non-terminal state {}",
                            record.state.as_str()
                        );
                    }
                }
                CapsuleReleaseReason::UndispatchedRollback => {
                    if record.state != ExternalJournalState::Prepared
                        || record.dispatch_may_have_started()
                    {
                        bail!(
                            "refusing to roll back a capsule reservation for state {}",
                            record.state.as_str()
                        );
                    }
                }
                // The caller proved the file is gone; any state may release.
                CapsuleReleaseReason::MediumMissing => {}
            }
            let Some(reservation) = capsule_reservation_conn(conn, operation_id)? else {
                return Ok(false);
            };
            conn.execute(
                "DELETE FROM external_journal_spool_capsules WHERE operation_id = ?1",
                params![operation_id.to_string()],
            )
            .context("releasing external journal capsule")?;
            release_spool_key_reference_if_unused_conn(conn, reservation.key_version)?;
            Ok(true)
        })
        .await
    }

    /// Move a capsule reservation into the recovery partition and flag it
    /// quarantined. Quarantine blocks new dispatch until it is cleared.
    pub async fn quarantine_external_journal_capsule(
        &self,
        operation_id: Uuid,
    ) -> Result<QuarantineLedgerOutcome> {
        self.transaction(move |conn| {
            let Some(reservation) = capsule_reservation_conn(conn, operation_id)? else {
                return Ok(QuarantineLedgerOutcome::NotFound);
            };
            if reservation.partition == CapsulePartition::Recovery {
                conn.execute(
                    "UPDATE external_journal_spool_capsules
                        SET quarantined = 1 WHERE operation_id = ?1",
                    params![operation_id.to_string()],
                )
                .context("flagging external journal capsule quarantined")?;
                return Ok(QuarantineLedgerOutcome::MovedToRecovery);
            }

            // Moving a capsule into the recovery partition consumes reserve
            // capacity. Check it the same way admission is checked so a burst
            // of quarantines can never silently exceed 1,024 / 64 MiB.
            let capacity = external_journal_capacity_conn(conn)?;
            let next_capsules = capacity
                .recovery_capsules
                .checked_add(1)
                .context("recovery capsule count overflow")?;
            let next_bytes = capacity
                .recovery_bytes
                .checked_add(reservation.allocated_bytes)
                .context("recovery capsule byte overflow")?;
            if next_capsules > EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES
                || next_bytes > EXTERNAL_JOURNAL_RECOVERY_RESERVE_BYTES
            {
                // The reserve is full. Flag in place rather than overflowing
                // it: the quarantine flag alone already blocks new dispatch.
                conn.execute(
                    "UPDATE external_journal_spool_capsules
                        SET quarantined = 1 WHERE operation_id = ?1",
                    params![operation_id.to_string()],
                )
                .context("flagging external journal capsule quarantined")?;
                return Ok(QuarantineLedgerOutcome::FlaggedInPlace);
            }
            conn.execute(
                "UPDATE external_journal_spool_capsules
                    SET quarantined = 1, capacity_partition = 'recovery'
                  WHERE operation_id = ?1",
                params![operation_id.to_string()],
            )
            .context("quarantining external journal capsule")?;
            Ok(QuarantineLedgerOutcome::MovedToRecovery)
        })
        .await
    }

    /// Key versions still referenced by a live capsule. Rotation must keep
    /// every one of these available until its records are imported or
    /// quarantined.
    pub async fn external_journal_referenced_key_versions(&self) -> Result<Vec<i64>> {
        self.read(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT key_version FROM external_journal_spool_capsules
                      ORDER BY key_version ASC",
                )
                .context("preparing referenced key version query")?;
            let versions = stmt
                .query_map([], |row| row.get::<_, i64>(0))
                .context("querying referenced key versions")?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("collecting referenced key versions")?;
            Ok(versions)
        })
        .await
    }

    /// Convert a `dispatching` record with no authenticated evidence into
    /// `submission_unknown`.
    ///
    /// `dispatching` is committed immediately before the provider call, so a
    /// record still sitting in it after a restart, a quarantined capsule, or an
    /// unavailable key version may already have produced an external effect.
    /// The prompt's edge case is explicit: crash after `dispatching` without
    /// evidence becomes `submission_unknown`. Returns `None` when the record
    /// has already moved on, so two recovery workers converge.
    pub async fn convert_dispatching_without_evidence(
        &self,
        operation_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<Option<ExternalJournalRecord>> {
        self.transaction(move |conn| {
            let current = external_operation_conn(conn, operation_id)?
                .with_context(|| format!("unknown external journal operation {operation_id}"))?;
            if current.state != ExternalJournalState::Dispatching {
                return Ok(None);
            }
            let record = commit_transition_conn(
                conn,
                &current,
                ExternalJournalState::SubmissionUnknown,
                now_wall_ms,
                false,
            )?;
            Ok(Some(record))
        })
        .await
    }

    /// Import a spool record by compare-and-set. A strictly newer authenticated
    /// version wins; stale or equal versions are idempotent no-ops.
    pub async fn import_external_journal_record(
        &self,
        operation_id: Uuid,
        spool_version: i64,
        spool_state: ExternalJournalState,
        now_wall_ms: i64,
    ) -> Result<ExternalTransitionOutcome> {
        self.transaction(move |conn| {
            let current = external_operation_conn(conn, operation_id)?
                .with_context(|| format!("unknown external journal operation {operation_id}"))?;
            if spool_version <= current.version {
                return Ok(ExternalTransitionOutcome::Duplicate(current));
            }
            if current.state == spool_state {
                return Ok(ExternalTransitionOutcome::Duplicate(current));
            }
            if validate_external_transition(&current, spool_state).is_err() {
                return Ok(ExternalTransitionOutcome::Conflict(current));
            }
            // Preserve the slot's own version so a gap stays visible.
            let record = commit_transition_at_version_conn(
                conn,
                &current,
                spool_state,
                now_wall_ms,
                false,
                Some(spool_version),
            )?;
            Ok(ExternalTransitionOutcome::Committed(record))
        })
        .await
    }

    /// Record a consumer-queue entry that has not yet created a journal row.
    pub async fn enqueue_external_queue_entry(
        &self,
        operation_kind: &ExternalJournalToken,
        owner_session_id: &ExternalJournalToken,
        idempotency_key: &ExternalJournalToken,
        now_wall_ms: i64,
    ) -> Result<Uuid> {
        let operation_kind = operation_kind.as_str().to_string();
        let owner_session_id = owner_session_id.as_str().to_string();
        let idempotency_key = idempotency_key.as_str().to_string();
        self.transaction(move |conn| {
            if let Some(existing) = conn
                .query_row(
                    "SELECT queue_entry_id FROM external_journal_queue_entries
                      WHERE operation_kind = ?1 AND owner_session_id = ?2
                        AND idempotency_key = ?3",
                    params![operation_kind, owner_session_id, idempotency_key],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .context("looking up external queue entry")?
            {
                return Uuid::parse_str(&existing).context("decoding queue entry id");
            }
            let queue_entry_id = Uuid::new_v4();
            conn.execute(
                "INSERT INTO external_journal_queue_entries (
                     queue_entry_id, operation_kind, owner_session_id, idempotency_key,
                     state, created_at_wall_ms, updated_at_wall_ms
                 ) VALUES (?1, ?2, ?3, ?4, 'queued', ?5, ?5)",
                params![
                    queue_entry_id.to_string(),
                    operation_kind,
                    owner_session_id,
                    idempotency_key,
                    now_wall_ms,
                ],
            )
            .context("inserting external queue entry")?;
            Ok(queue_entry_id)
        })
        .await
    }

    /// Bind a queue entry to the journal row it created.
    pub async fn mark_external_queue_journaled(
        &self,
        queue_entry_id: Uuid,
        operation_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<bool> {
        self.write(move |conn| {
            let updated = conn
                .execute(
                    "UPDATE external_journal_queue_entries
                        SET state = 'journaled', journal_operation_id = ?1,
                            updated_at_wall_ms = ?2
                      WHERE queue_entry_id = ?3 AND state = 'queued'",
                    params![
                        operation_id.to_string(),
                        now_wall_ms,
                        queue_entry_id.to_string()
                    ],
                )
                .context("marking external queue entry journaled")?;
            Ok(updated == 1)
        })
        .await
    }

    /// Expire aged `queued` consumer entries in their own terminal state. This
    /// deliberately creates no external-journal operation row.
    pub async fn expire_external_queue_entries(
        &self,
        now_wall_ms: i64,
        ttl_ms: i64,
    ) -> Result<u64> {
        self.write(move |conn| {
            let cutoff = now_wall_ms
                .checked_sub(ttl_ms)
                .context("external queue expiry cutoff overflow")?;
            let updated = conn
                .execute(
                    "UPDATE external_journal_queue_entries
                        SET state = 'expired', updated_at_wall_ms = ?1
                      WHERE state = 'queued' AND created_at_wall_ms <= ?2",
                    params![now_wall_ms, cutoff],
                )
                .context("expiring external queue entries")?;
            u64::try_from(updated).context("external queue expiry count overflow")
        })
        .await
    }

    /// Queue-entry state, for tests and consumer status surfaces.
    pub async fn external_queue_entry_state(
        &self,
        queue_entry_id: Uuid,
    ) -> Result<Option<ExternalQueueState>> {
        self.read(move |conn| {
            let raw: Option<String> = conn
                .query_row(
                    "SELECT state FROM external_journal_queue_entries WHERE queue_entry_id = ?1",
                    params![queue_entry_id.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .context("loading external queue entry state")?;
            raw.map(|value| ExternalQueueState::parse(&value))
                .transpose()
        })
        .await
    }

    /// Write a session-deletion tombstone. Unresolved operations survive it so
    /// late provider evidence still resolves exactly once.
    pub async fn tombstone_external_journal_session(
        &self,
        owner_session_id: &ExternalJournalToken,
        now_wall_ms: i64,
    ) -> Result<i64> {
        let owner_session_id = owner_session_id.clone();
        self.transaction(move |conn| {
            tombstone_external_journal_session_conn(conn, &owner_session_id, now_wall_ms)
        })
        .await
    }

    /// Whether a session was deleted. Resolution after deletion emits
    /// owner-visible recovery status without recreating session content.
    pub async fn external_journal_session_tombstoned(
        &self,
        owner_session_id: &ExternalJournalToken,
    ) -> Result<bool> {
        let owner_session_id = owner_session_id.as_str().to_string();
        self.read(move |conn| {
            let found: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM external_journal_session_tombstones
                      WHERE owner_session_id = ?1",
                    params![owner_session_id],
                    |row| row.get(0),
                )
                .optional()
                .context("looking up external journal session tombstone")?;
            Ok(found.is_some())
        })
        .await
    }
}

/// Record the durable integrity fault inside an open transaction.
///
/// First writer wins: the original cause is the useful one, and later faults
/// are usually consequences of it.
pub fn record_external_journal_integrity_fault_conn(
    conn: &Connection,
    detail: &str,
    now_wall_ms: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO external_journal_integrity_faults (
             fault_id, detail, observed_at_wall_ms
         ) VALUES ('current', ?1, ?2)
         ON CONFLICT (fault_id) DO NOTHING",
        params![detail, now_wall_ms],
    )
    .context("recording external journal integrity fault")?;
    Ok(())
}

/// Read the durable integrity fault inside an open transaction.
pub fn external_journal_integrity_fault_conn(conn: &Connection) -> Result<Option<String>> {
    conn.query_row(
        "SELECT detail FROM external_journal_integrity_faults WHERE fault_id = 'current'",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .context("loading external journal integrity fault")
}

/// Write a session-deletion tombstone for a session id.
///
/// `delete_session_conn` calls this rather than building the owner token
/// itself: the blocking-boundary gate cannot resolve an associated function
/// reached through a crate-local path from a public body, and a free function
/// keeps that call graph explicit.
pub fn tombstone_external_journal_session_id_conn(
    conn: &Connection,
    session_id: Uuid,
    now_wall_ms: i64,
) -> Result<i64> {
    tombstone_external_journal_session_conn(
        conn,
        &ExternalJournalToken::for_session(session_id),
        now_wall_ms,
    )
}

/// Write a session-deletion tombstone inside an open transaction.
///
/// Called by `delete_session_conn` so that no session can be removed without
/// one. Returns the number of unresolved operations that survive the deletion.
pub fn tombstone_external_journal_session_conn(
    conn: &Connection,
    owner_session_id: &ExternalJournalToken,
    now_wall_ms: i64,
) -> Result<i64> {
    let owner_session_id = owner_session_id.as_str();
    let unresolved: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM external_journal_operations
              WHERE owner_session_id = ?1
                AND state IN (
                    'dispatching', 'accepted', 'submission_unknown',
                    'cancellation_requested', 'reconciling'
                )",
            params![owner_session_id],
            |row| row.get(0),
        )
        .context("counting unresolved operations for tombstone")?;
    conn.execute(
        "INSERT INTO external_journal_session_tombstones (
             owner_session_id, deleted_at_wall_ms, unresolved_at_deletion
         ) VALUES (?1, ?2, ?3)
         ON CONFLICT (owner_session_id) DO UPDATE SET
             deleted_at_wall_ms = excluded.deleted_at_wall_ms,
             unresolved_at_deletion = excluded.unresolved_at_deletion",
        params![owner_session_id, now_wall_ms, unresolved],
    )
    .context("writing external journal session tombstone")?;
    Ok(unresolved)
}

impl Db {
    /// Reserve and activate the spool key reference the journal's ring owns.
    ///
    /// Run once at journal start, before any capsule exists, so the reference
    /// is `Active` rather than `Reserved` when the next boot's secure-key
    /// startup reconcile inspects it.
    pub async fn activate_external_journal_spool_key(&self, key_version: i64) -> Result<()> {
        self.transaction(move |conn| activate_external_journal_spool_key_conn(conn, key_version))
            .await
    }

    /// Record a durable integrity fault so doctor stays critical across
    /// restarts and without a live journal instance.
    pub async fn record_external_journal_integrity_fault(
        &self,
        detail: &str,
        now_wall_ms: i64,
    ) -> Result<()> {
        let detail = detail.to_string();
        self.write(move |conn| {
            record_external_journal_integrity_fault_conn(conn, &detail, now_wall_ms)
        })
        .await
    }

    /// The durable integrity fault, if one was recorded.
    pub async fn external_journal_integrity_fault(&self) -> Result<Option<String>> {
        self.read(external_journal_integrity_fault_conn).await
    }

    /// Prune aged session tombstones that no unresolved operation still needs.
    ///
    /// Every session deletion writes one, including ephemeral sweeps, so
    /// without this the table grows without bound. Batched so one pass can
    /// never hold a long write transaction.
    pub async fn prune_external_journal_tombstones(&self, now_wall_ms: i64) -> Result<u64> {
        self.write(move |conn| {
            let cutoff = now_wall_ms
                .checked_sub(EXTERNAL_JOURNAL_TOMBSTONE_RETENTION_MS)
                .context("external journal tombstone cutoff overflow")?;
            let batch = i64::try_from(EXTERNAL_JOURNAL_TOMBSTONE_PRUNE_BATCH)
                .context("external journal tombstone batch overflow")?;
            let removed = conn
                .execute(
                    "DELETE FROM external_journal_session_tombstones
                      WHERE owner_session_id IN (
                          SELECT t.owner_session_id
                            FROM external_journal_session_tombstones AS t
                           WHERE t.deleted_at_wall_ms <= ?1
                             AND NOT EXISTS (
                                 SELECT 1 FROM external_journal_operations AS o
                                  WHERE o.owner_session_id = t.owner_session_id
                                    AND o.state IN (
                                        'dispatching', 'accepted', 'submission_unknown',
                                        'cancellation_requested', 'reconciling'
                                    )
                             )
                           ORDER BY t.deleted_at_wall_ms ASC
                           LIMIT ?2
                      )",
                    params![cutoff, batch],
                )
                .context("pruning external journal session tombstones")?;
            u64::try_from(removed).context("external journal tombstone prune count overflow")
        })
        .await
    }

    /// Every operation that still needs recovery attention, oldest first.
    pub async fn list_unresolved_external_operations(&self) -> Result<Vec<ExternalJournalRecord>> {
        self.read(|conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {RECORD_COLUMNS} FROM external_journal_operations
                      WHERE state IN (
                          'dispatching', 'accepted', 'submission_unknown',
                          'cancellation_requested', 'reconciling'
                      )
                      ORDER BY updated_at_wall_ms ASC"
                ))
                .context("preparing unresolved external journal query")?;
            let rows = stmt
                .query_map([], decode_record)
                .context("querying unresolved external journal operations")?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("collecting unresolved external journal operations")?;
            Ok(rows)
        })
        .await
    }
}

/// One emitted transition event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalJournalTransitionEvent {
    pub operation_id: Uuid,
    pub version: i64,
    pub from_state: ExternalJournalState,
    pub to_state: ExternalJournalState,
    pub terminal: bool,
    pub cancellation_requested_at_wall_ms: Option<i64>,
    pub emitted_at_wall_ms: i64,
}

fn capsule_reservation_conn(
    conn: &Connection,
    operation_id: Uuid,
) -> Result<Option<CapsuleReservation>> {
    let row = conn
        .query_row(
            "SELECT capsule_uuid, key_version, allocated_bytes, capacity_partition
               FROM external_journal_spool_capsules WHERE operation_id = ?1",
            params![operation_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .context("loading external journal capsule reservation")?;
    let Some((capsule_uuid, key_version, allocated_bytes, partition)) = row else {
        return Ok(None);
    };
    Ok(Some(CapsuleReservation {
        operation_id,
        capsule_uuid: Uuid::parse_str(&capsule_uuid).context("decoding capsule uuid")?,
        key_version,
        partition: CapsulePartition::parse(&partition)?,
        allocated_bytes,
    }))
}

/// Reserve-then-activate the spool key reference inside an open transaction.
///
/// This is the consumer half of the native secure-key lifecycle: a version
/// stays reachable while any capsule references it. `NotFound` is tolerated —
/// it means no secure-key metadata exists for this installation (an in-memory
/// test database, or a boot where the native store was unavailable), in which
/// case there is no reference to keep alive. Every other non-success is fatal
/// so a `Retiring` or conflicting version can never be silently written under.
fn activate_spool_key_reference_conn(conn: &Connection, key_version: i64) -> Result<()> {
    use crate::db::secure_key::ReserveResult;

    let reference_id = external_journal_spool_key_reference_id(key_version);
    let reserved = reserve_consumer_ref_conn(
        conn,
        &reference_id,
        EXTERNAL_JOURNAL_SPOOL_NAMESPACE,
        key_version,
        EXTERNAL_JOURNAL_SPOOL_CONSUMER_KIND,
        &reference_id,
    )
    .context("reserving external journal spool key reference")?;
    match reserved {
        ReserveResult::Reserved(_) | ReserveResult::Idempotent(_) => {}
        ReserveResult::NotFound => return Ok(()),
        other => {
            bail!("external journal spool key version {key_version} is not reservable: {other:?}")
        }
    }
    if !activate_consumer_ref_conn(conn, &reference_id)
        .context("activating external journal spool key reference")?
    {
        bail!("external journal spool key reference {reference_id} is not activatable");
    }
    Ok(())
}

/// Reserve and activate the spool key reference for a ring the journal owns.
///
/// Called once at journal start, before any capsule exists. Moving the
/// reference to `Active` immediately is what keeps the next boot's
/// `startup_reconcile` from treating it as an orphaned reservation.
pub fn activate_external_journal_spool_key_conn(conn: &Connection, key_version: i64) -> Result<()> {
    activate_spool_key_reference_conn(conn, key_version)
}

/// Begin releasing the spool key reference once no capsule references it.
///
/// Rotation keeps every referenced version available until all records using
/// it are imported or quarantined; this is where "no longer referenced" is
/// decided, in the same transaction that removed the last capsule row.
fn release_spool_key_reference_if_unused_conn(conn: &Connection, key_version: i64) -> Result<()> {
    // Exactly the reconciliation predicate, so release and reconcile can never
    // disagree about whether a version still has a consumer.
    if external_journal_spool_key_version_in_use_conn(conn, key_version)? {
        return Ok(());
    }
    let reference_id = external_journal_spool_key_reference_id(key_version);
    // A missing reference simply means this installation never reserved one.
    begin_release_consumer_ref_conn(conn, &reference_id)
        .context("releasing external journal spool key reference")?;
    Ok(())
}

/// Whether a spool key version is still in use.
///
/// This predicate is authoritative for the `external_journal_spool` consumer
/// kind, and it is deliberately wider than "a capsule references it".
///
/// The consumer of a spool key is the **spool**, not an individual capsule. A
/// freshly provisioned installation reserves the active version at journal
/// start and only writes its first capsule when something is dispatched, so
/// between those two moments the ledger is legitimately empty. The secure-key
/// actor's `startup_reconcile` runs *before* the journal starts on the next
/// boot; if this returned `false` for that window it would mark the reference
/// `Released`, which is terminal for non-sealed kinds, and every later
/// activation — and therefore every dispatch — would fail forever.
///
/// So a reference exists while either:
///
/// * a capsule row references the version (records still need it), or
/// * the version is still reservable (`Active`/`Retained`) in the spool
///   namespace, meaning the journal's key ring holds or may hold it.
///
/// A `Retiring`/`Retired`/absent version with no capsules genuinely has no
/// consumer and is correctly released.
pub fn external_journal_spool_consumer_exists_conn(
    conn: &Connection,
    consumer_id: &str,
) -> Result<bool> {
    let Some(key_version) = external_journal_spool_key_version_from_reference(consumer_id) else {
        bail!("unrecognised external journal spool consumer id");
    };
    external_journal_spool_key_version_in_use_conn(conn, key_version)
}

/// The single predicate for "this spool key version still has a consumer".
///
/// A version is in use while a capsule references it, or while it is the
/// namespace's **active** version — the one the journal's key ring writes new
/// slots under, which is legitimately capsule-free between a fresh boot and
/// the first dispatch.
///
/// Deliberately narrower than "reservable": a `Retained` version that no
/// capsule references has genuinely lost its consumer, so it can be released
/// and later retired. Retaining those forever would make rotation a one-way
/// door — a superseded version could never complete its retire cycle.
pub fn external_journal_spool_key_version_in_use_conn(
    conn: &Connection,
    key_version: i64,
) -> Result<bool> {
    if external_journal_spool_key_version_referenced_conn(conn, key_version)? {
        return Ok(true);
    }
    let namespace = get_namespace_conn(conn, EXTERNAL_JOURNAL_SPOOL_NAMESPACE)
        .context("loading external journal spool namespace")?;
    Ok(namespace.is_some_and(|row| row.active_version == Some(key_version)))
}

/// Whether any capsule row references this spool key version.
pub fn external_journal_spool_key_version_referenced_conn(
    conn: &Connection,
    key_version: i64,
) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM external_journal_spool_capsules WHERE key_version = ?1",
            params![key_version],
            |row| row.get(0),
        )
        .context("counting capsules for a spool key version")?;
    Ok(count > 0)
}

/// Unresolved-work age buckets inside an open transaction.
pub fn external_journal_age_report_conn(
    conn: &Connection,
    now_wall_ms: i64,
) -> Result<ExternalJournalAgeReport> {
    let mut stmt = conn
        .prepare(
            "SELECT updated_at_wall_ms FROM external_journal_operations
              WHERE state IN (
                  'dispatching', 'accepted', 'submission_unknown',
                  'cancellation_requested', 'reconciling'
              )",
        )
        .context("preparing external journal age scan")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .context("scanning unresolved external journal work")?;
    let mut report = ExternalJournalAgeReport::default();
    for row in rows {
        let updated = row.context("decoding unresolved timestamp")?;
        let age = now_wall_ms.saturating_sub(updated).max(0);
        report.unresolved += 1;
        report.oldest_age_ms = report.oldest_age_ms.max(age);
        if age >= EXTERNAL_JOURNAL_UNRESOLVED_CRITICAL_MS {
            report.critical += 1;
        } else if age >= EXTERNAL_JOURNAL_UNRESOLVED_WARN_MS {
            report.warning += 1;
        }
    }
    Ok(report)
}

/// Capacity counts inside an open transaction.
pub fn external_journal_capacity_conn(conn: &Connection) -> Result<ExternalJournalCapacity> {
    let mut capacity = ExternalJournalCapacity::default();
    let mut stmt = conn
        .prepare(
            "SELECT capacity_partition, COUNT(*), COALESCE(SUM(allocated_bytes), 0),
                    COALESCE(SUM(quarantined), 0)
               FROM external_journal_spool_capsules
              GROUP BY capacity_partition",
        )
        .context("preparing external journal capacity query")?;
    let rows = stmt
        .query_map([], |row| {
            let partition: String = row.get(0)?;
            Ok((
                partition,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .context("querying external journal capacity")?;
    for row in rows {
        let (partition, count, bytes, quarantined) =
            row.context("decoding external journal capacity row")?;
        capacity.quarantined_capsules += quarantined;
        match CapsulePartition::parse(&partition)? {
            CapsulePartition::Admission => {
                capacity.admission_capsules = count;
                capacity.admission_bytes = bytes;
            }
            CapsulePartition::Recovery => {
                capacity.recovery_capsules = count;
                capacity.recovery_bytes = bytes;
            }
        }
    }
    Ok(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether the byte offset sits inside a line comment.
    ///
    /// Prose is not code. An earlier version of these scans matched their own
    /// explanatory comments, which is how a check can look green while testing
    /// nothing.
    fn in_line_comment(source: &str, index: usize) -> bool {
        let line_start = source[..index].rfind('\n').map_or(0, |at| at + 1);
        source[line_start..index].contains("//")
    }

    /// Production half of a source file.
    ///
    /// Slicing at the first `#[cfg(test)]` *attribute* is wrong: these files
    /// carry `#[cfg(test)]` on individual items hundreds of lines above the
    /// test module, which silently truncated every scan below to nothing.
    fn production_half(source: &str) -> &str {
        match source.find("\nmod tests {") {
            Some(at) => &source[..at],
            None => source,
        }
    }

    /// Every `fn NAME(` defined in a Rust source slice.
    fn fn_names(source: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (index, _) in source.match_indices("fn ") {
            let rest = &source[index + 3..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() && rest[name.len()..].starts_with('(') {
                out.push(name);
            }
        }
        out
    }

    /// The brace-matched body of the named function.
    fn fn_body(source: &str, name: &str) -> Option<String> {
        let at = source.find(&format!("fn {name}("))?;
        let open = source[at..].find('{')? + at;
        let mut depth = 0usize;
        for (offset, byte) in source[open..].bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(source[open..open + offset + 1].to_string());
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// The paren-matched argument text of every `marker` call.
    fn wrapper_arguments(source: &str, marker: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (index, _) in source.match_indices(marker) {
            let Some(open) = source[index..].find('(').map(|at| at + index) else {
                continue;
            };
            let mut depth = 0usize;
            for (offset, byte) in source[open..].bytes().enumerate() {
                match byte {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            out.push(source[open..open + offset + 1].to_string());
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        out
    }

    /// Re-link a session so it is a cascade descendant of `parent` reachable
    /// **only** through `btw_parent_session_id`.
    ///
    /// `create_btw_fork` sets both FK columns, so a real `/btw` row is also a
    /// fork-tree child and a parent-only walk finds it by accident. The
    /// database cascades on either column independently, so the walk has to as
    /// well — and only a btw-only row can prove it.
    async fn relink_as_btw_only_child(db: &Db, child: Uuid, parent: Uuid) {
        db.write(move |conn| {
            let updated = conn.execute(
                "UPDATE sessions
                    SET parent_session_id = NULL, btw_parent_session_id = ?2
                  WHERE session_id = ?1",
                params![child.to_string(), parent.to_string()],
            )?;
            assert_eq!(updated, 1);
            Ok(())
        })
        .await
        .unwrap();
    }

    fn token(value: &str) -> ExternalJournalToken {
        ExternalJournalToken::parse(value).expect("valid token")
    }

    fn prepare_request(key: &str) -> PrepareExternalOperation {
        PrepareExternalOperation {
            operation_kind: token("computer_input"),
            owner_session_id: token("session-a"),
            idempotency_key: token(key),
            payload_digest: ExternalJournalDigest::of(b"canonical projection"),
            payload_len: 128,
            provider_idempotency: None,
        }
    }

    async fn prepared(db: &Db, key: &str, now: i64) -> ExternalJournalRecord {
        db.prepare_external_operation(prepare_request(key), now)
            .await
            .unwrap()
            .record()
            .clone()
    }

    /// Drive a record to `dispatching` so later transitions are legal.
    async fn dispatching(db: &Db, key: &str, now: i64) -> ExternalJournalRecord {
        let record = prepared(db, key, now).await;
        db.transition_external_operation(
            record.operation_id,
            record.version,
            ExternalJournalState::Dispatching,
            now,
        )
        .await
        .unwrap()
        .record()
        .clone()
    }

    // ---- criterion 1: state matrix ----------------------------------------

    /// The exact edge set from the prompt, as (from, to) pairs.
    const LISTED_EDGES: &[(ExternalJournalState, ExternalJournalState)] = &[
        (
            ExternalJournalState::Prepared,
            ExternalJournalState::Dispatching,
        ),
        (
            ExternalJournalState::Prepared,
            ExternalJournalState::Cancelled,
        ),
        (
            ExternalJournalState::Prepared,
            ExternalJournalState::Expired,
        ),
        (
            ExternalJournalState::Dispatching,
            ExternalJournalState::Accepted,
        ),
        (
            ExternalJournalState::Dispatching,
            ExternalJournalState::Rejected,
        ),
        (
            ExternalJournalState::Dispatching,
            ExternalJournalState::SubmissionUnknown,
        ),
        (
            ExternalJournalState::Dispatching,
            ExternalJournalState::CancellationRequested,
        ),
        (
            ExternalJournalState::Accepted,
            ExternalJournalState::Succeeded,
        ),
        (
            ExternalJournalState::Accepted,
            ExternalJournalState::CompletedAfterCancel,
        ),
        (ExternalJournalState::Accepted, ExternalJournalState::Failed),
        (
            ExternalJournalState::Accepted,
            ExternalJournalState::CancellationRequested,
        ),
        (
            ExternalJournalState::SubmissionUnknown,
            ExternalJournalState::Reconciling,
        ),
        (
            ExternalJournalState::SubmissionUnknown,
            ExternalJournalState::CancellationRequested,
        ),
        (
            ExternalJournalState::Reconciling,
            ExternalJournalState::Accepted,
        ),
        (
            ExternalJournalState::Reconciling,
            ExternalJournalState::Rejected,
        ),
        (
            ExternalJournalState::Reconciling,
            ExternalJournalState::SubmissionUnknown,
        ),
        (
            ExternalJournalState::Reconciling,
            ExternalJournalState::Failed,
        ),
        (
            ExternalJournalState::Reconciling,
            ExternalJournalState::CancellationRequested,
        ),
        (
            ExternalJournalState::CancellationRequested,
            ExternalJournalState::Cancelled,
        ),
        (
            ExternalJournalState::CancellationRequested,
            ExternalJournalState::Accepted,
        ),
        (
            ExternalJournalState::CancellationRequested,
            ExternalJournalState::CompletedAfterCancel,
        ),
        (
            ExternalJournalState::CancellationRequested,
            ExternalJournalState::Failed,
        ),
        (
            ExternalJournalState::CancellationRequested,
            ExternalJournalState::SubmissionUnknown,
        ),
        (
            ExternalJournalState::CancellationRequested,
            ExternalJournalState::Reconciling,
        ),
    ];

    #[test]
    fn external_journal_state_matrix_accepts_exactly_the_listed_edges() {
        for from in ExternalJournalState::ALL {
            for to in ExternalJournalState::ALL {
                let listed = LISTED_EDGES.contains(&(from, to));
                assert_eq!(
                    from.allows_transition_to(to),
                    listed,
                    "edge {} -> {} should be {}",
                    from.as_str(),
                    to.as_str(),
                    if listed { "accepted" } else { "rejected" }
                );
            }
        }
    }

    #[test]
    fn external_journal_state_matrix_terminality() {
        for state in ExternalJournalState::ALL {
            let outgoing = ExternalJournalState::ALL
                .iter()
                .filter(|next| state.allows_transition_to(**next))
                .count();
            assert_eq!(
                state.is_terminal(),
                outgoing == 0,
                "{} terminality disagrees with its outgoing edges",
                state.as_str()
            );
        }
        assert!(ExternalJournalState::Expired.is_terminal());
        assert!(!ExternalJournalState::CancellationRequested.is_terminal());
    }

    #[test]
    fn external_journal_state_matrix_expired_reachable_only_from_prepared() {
        let sources: Vec<_> = ExternalJournalState::ALL
            .iter()
            .filter(|from| from.allows_transition_to(ExternalJournalState::Expired))
            .copied()
            .collect();
        assert_eq!(sources, vec![ExternalJournalState::Prepared]);
    }

    #[tokio::test]
    async fn external_journal_state_matrix_rejects_unlisted_edge_in_db() {
        let db = Db::open_in_memory().unwrap();
        let record = prepared(&db, "k1", 1_000).await;
        let error = db
            .transition_external_operation(
                record.operation_id,
                record.version,
                ExternalJournalState::Accepted,
                1_100,
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("illegal external journal transition"),
            "unexpected error: {error}"
        );
        let reloaded = db
            .external_operation(record.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.state, ExternalJournalState::Prepared);
        assert_eq!(reloaded.version, 1);
    }

    #[tokio::test]
    async fn external_journal_state_matrix_expired_requires_no_dispatch_proof() {
        let db = Db::open_in_memory().unwrap();
        let dispatched = dispatching(&db, "k1", 1_000).await;
        // Roll back to prepared is impossible, so prove the guard directly on a
        // record that carries dispatch proof.
        let error = validate_external_transition(
            &ExternalJournalRecord {
                state: ExternalJournalState::Prepared,
                ..dispatched.clone()
            },
            ExternalJournalState::Expired,
        )
        .unwrap_err();
        assert!(error.to_string().contains("durable proof"), "{error}");

        let clean = prepared(&db, "k2", 1_000).await;
        validate_external_transition(&clean, ExternalJournalState::Expired).unwrap();
    }

    // ---- criterion 10: cancellation fact ----------------------------------

    #[tokio::test]
    async fn external_journal_cancellation_fact_prepared_proves_no_effect() {
        let db = Db::open_in_memory().unwrap();
        let record = prepared(&db, "k1", 1_000).await;
        let outcome = db
            .request_external_operation_cancellation(record.operation_id, 1_500)
            .await
            .unwrap();
        let cancelled = outcome.record();
        assert!(outcome.is_committed());
        assert_eq!(cancelled.state, ExternalJournalState::Cancelled);
        assert_eq!(cancelled.cancellation_requested_at_wall_ms, Some(1_500));
        assert!(!cancelled.dispatch_may_have_started());
    }

    #[tokio::test]
    async fn external_journal_cancellation_fact_after_dispatch_cannot_jump_to_cancelled() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let outcome = db
            .request_external_operation_cancellation(record.operation_id, 1_500)
            .await
            .unwrap();
        assert_eq!(
            outcome.record().state,
            ExternalJournalState::CancellationRequested
        );
        assert!(
            !ExternalJournalState::Dispatching
                .allows_transition_to(ExternalJournalState::Cancelled)
        );
    }

    #[tokio::test]
    async fn external_journal_cancellation_fact_is_immutable_and_survives_reconciliation() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let requested = db
            .request_external_operation_cancellation(record.operation_id, 1_500)
            .await
            .unwrap()
            .record()
            .clone();
        let first_at = requested.cancellation_requested_at_wall_ms.unwrap();
        let first_version = requested.cancellation_requested_version.unwrap();

        // A second request is idempotent and cannot replace the fact.
        let again = db
            .request_external_operation_cancellation(record.operation_id, 9_999)
            .await
            .unwrap();
        assert!(matches!(again, ExternalTransitionOutcome::Duplicate(_)));
        assert_eq!(
            again.record().cancellation_requested_at_wall_ms,
            Some(first_at)
        );

        // cancellation_requested -> reconciling -> accepted preserves it.
        let reconciling = db
            .transition_external_operation(
                record.operation_id,
                requested.version,
                ExternalJournalState::Reconciling,
                2_000,
            )
            .await
            .unwrap()
            .record()
            .clone();
        assert_eq!(
            reconciling.cancellation_requested_at_wall_ms,
            Some(first_at)
        );
        let accepted = db
            .transition_external_operation(
                record.operation_id,
                reconciling.version,
                ExternalJournalState::Accepted,
                2_100,
            )
            .await
            .unwrap()
            .record()
            .clone();
        assert_eq!(accepted.cancellation_requested_at_wall_ms, Some(first_at));
        assert_eq!(accepted.cancellation_requested_version, Some(first_version));

        // Plain `succeeded` is permanently unreachable.
        let error = db
            .transition_external_operation(
                record.operation_id,
                accepted.version,
                ExternalJournalState::Succeeded,
                2_200,
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("plain succeeded is forbidden"),
            "{error}"
        );

        // The authoritative successful completion is completed_after_cancel.
        let done = db
            .transition_external_operation(
                record.operation_id,
                accepted.version,
                ExternalJournalState::CompletedAfterCancel,
                2_300,
            )
            .await
            .unwrap()
            .record()
            .clone();
        assert_eq!(done.state, ExternalJournalState::CompletedAfterCancel);
        assert_eq!(done.cancellation_requested_at_wall_ms, Some(first_at));

        let events = db
            .external_operation_events(record.operation_id)
            .await
            .unwrap();
        let terminals: Vec<_> = events.iter().filter(|event| event.terminal).collect();
        assert_eq!(terminals.len(), 1);
        assert_eq!(
            terminals[0].to_state,
            ExternalJournalState::CompletedAfterCancel
        );
        assert_eq!(
            terminals[0].cancellation_requested_at_wall_ms,
            Some(first_at)
        );
    }

    #[tokio::test]
    async fn external_journal_cancellation_fact_failure_branch_keeps_the_fact() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let requested = db
            .request_external_operation_cancellation(record.operation_id, 1_500)
            .await
            .unwrap()
            .record()
            .clone();
        let failed = db
            .transition_external_operation(
                record.operation_id,
                requested.version,
                ExternalJournalState::Failed,
                1_800,
            )
            .await
            .unwrap()
            .record()
            .clone();
        assert_eq!(failed.state, ExternalJournalState::Failed);
        assert_eq!(failed.cancellation_requested_at_wall_ms, Some(1_500));
    }

    #[tokio::test]
    async fn external_journal_cancellation_fact_cancelled_branch_is_terminal() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let requested = db
            .request_external_operation_cancellation(record.operation_id, 1_500)
            .await
            .unwrap()
            .record()
            .clone();
        let cancelled = db
            .transition_external_operation(
                record.operation_id,
                requested.version,
                ExternalJournalState::Cancelled,
                1_900,
            )
            .await
            .unwrap()
            .record()
            .clone();
        assert_eq!(cancelled.state, ExternalJournalState::Cancelled);
        assert_eq!(cancelled.terminal_at_wall_ms, Some(1_900));
    }

    // ---- criterion 5: exactly once ----------------------------------------

    #[tokio::test]
    async fn external_journal_exactly_once_duplicate_prepare_returns_current_record() {
        let db = Db::open_in_memory().unwrap();
        let first = db
            .prepare_external_operation(prepare_request("k1"), 1_000)
            .await
            .unwrap();
        assert!(matches!(first, ExternalPrepareOutcome::Created(_)));
        let second = db
            .prepare_external_operation(prepare_request("k1"), 1_100)
            .await
            .unwrap();
        assert!(matches!(second, ExternalPrepareOutcome::Existing(_)));
        assert_eq!(second.record().operation_id, first.record().operation_id);
    }

    #[tokio::test]
    async fn external_journal_exactly_once_two_recovery_workers_commit_one_version() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let first = db
            .transition_external_operation(
                record.operation_id,
                record.version,
                ExternalJournalState::SubmissionUnknown,
                1_200,
            )
            .await
            .unwrap();
        assert!(first.is_committed());
        // The losing worker still holds the stale version.
        let second = db
            .transition_external_operation(
                record.operation_id,
                record.version,
                ExternalJournalState::Rejected,
                1_300,
            )
            .await
            .unwrap();
        assert!(matches!(second, ExternalTransitionOutcome::Conflict(_)));
        assert_eq!(
            second.record().state,
            ExternalJournalState::SubmissionUnknown
        );
        // The loser sees the winner's committed record: prepared(1) ->
        // dispatching(2) -> submission_unknown(3).
        assert_eq!(second.record().version, 3);

        let events = db
            .external_operation_events(record.operation_id)
            .await
            .unwrap();
        let versions: Vec<_> = events.iter().map(|event| event.version).collect();
        assert_eq!(versions, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn external_journal_exactly_once_repeat_transition_returns_current_record() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let first = db
            .transition_external_operation(
                record.operation_id,
                record.version,
                ExternalJournalState::Accepted,
                1_200,
            )
            .await
            .unwrap();
        let duplicate = db
            .transition_external_operation(
                record.operation_id,
                first.record().version,
                ExternalJournalState::Accepted,
                1_300,
            )
            .await
            .unwrap();
        assert!(matches!(duplicate, ExternalTransitionOutcome::Duplicate(_)));
        assert_eq!(duplicate.record().version, first.record().version);
    }

    #[tokio::test]
    async fn external_journal_exactly_once_emits_one_terminal_event() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let accepted = db
            .transition_external_operation(
                record.operation_id,
                record.version,
                ExternalJournalState::Accepted,
                1_200,
            )
            .await
            .unwrap()
            .record()
            .clone();
        db.transition_external_operation(
            record.operation_id,
            accepted.version,
            ExternalJournalState::Succeeded,
            1_300,
        )
        .await
        .unwrap();
        let events = db
            .external_operation_events(record.operation_id)
            .await
            .unwrap();
        assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);

        // Nothing follows a terminal state.
        let error = db
            .transition_external_operation(
                record.operation_id,
                accepted.version + 1,
                ExternalJournalState::Failed,
                1_400,
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("illegal external journal transition"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn external_journal_exactly_once_session_tombstone_keeps_unresolved_work() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        db.transition_external_operation(
            record.operation_id,
            record.version,
            ExternalJournalState::Accepted,
            1_200,
        )
        .await
        .unwrap();

        let unresolved = db
            .tombstone_external_journal_session(&token("session-a"), 1_500)
            .await
            .unwrap();
        assert_eq!(unresolved, 1);
        assert!(
            db.external_journal_session_tombstoned(&token("session-a"))
                .await
                .unwrap()
        );
        let survivor = db
            .external_operation(record.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(survivor.state, ExternalJournalState::Accepted);

        // Resolution after deletion still commits exactly one terminal event.
        db.transition_external_operation(
            record.operation_id,
            survivor.version,
            ExternalJournalState::Succeeded,
            1_900,
        )
        .await
        .unwrap();
        let events = db
            .external_operation_events(record.operation_id)
            .await
            .unwrap();
        assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
    }

    #[tokio::test]
    async fn external_journal_exactly_once_import_is_idempotent_for_stale_versions() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let imported = db
            .import_external_journal_record(
                record.operation_id,
                record.version + 1,
                ExternalJournalState::SubmissionUnknown,
                1_400,
            )
            .await
            .unwrap();
        assert!(imported.is_committed());

        for version in [1, 2, 3] {
            let repeat = db
                .import_external_journal_record(
                    record.operation_id,
                    version,
                    ExternalJournalState::SubmissionUnknown,
                    1_500,
                )
                .await
                .unwrap();
            assert!(matches!(repeat, ExternalTransitionOutcome::Duplicate(_)));
        }
        let events = db
            .external_operation_events(record.operation_id)
            .await
            .unwrap();
        assert_eq!(events.len(), 3);
    }

    // ---- criterion 4: age policy ------------------------------------------

    #[tokio::test]
    async fn external_journal_age_policy_expires_prepared_only_with_no_dispatch_proof() {
        let db = Db::open_in_memory().unwrap();
        let stale = prepared(&db, "stale", 0).await;
        let fresh = prepared(&db, "fresh", EXTERNAL_JOURNAL_PREPARED_TTL_MS).await;
        let dispatched = dispatching(&db, "dispatched", 0).await;

        let now = EXTERNAL_JOURNAL_PREPARED_TTL_MS + 1;
        let expired = db
            .expire_prepared_external_operations(now, EXTERNAL_JOURNAL_PREPARED_TTL_MS)
            .await
            .unwrap();
        assert_eq!(expired, vec![stale.operation_id]);

        assert_eq!(
            db.external_operation(stale.operation_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            ExternalJournalState::Expired
        );
        assert_eq!(
            db.external_operation(fresh.operation_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            ExternalJournalState::Prepared
        );
        assert_eq!(
            db.external_operation(dispatched.operation_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            ExternalJournalState::Dispatching
        );
    }

    #[tokio::test]
    async fn external_journal_age_policy_consumer_queue_expires_in_its_own_state() {
        let db = Db::open_in_memory().unwrap();
        let entry = db
            .enqueue_external_queue_entry(
                &token("transcription"),
                &token("session-a"),
                &token("q1"),
                0,
            )
            .await
            .unwrap();
        let expired = db
            .expire_external_queue_entries(
                EXTERNAL_JOURNAL_PREPARED_TTL_MS + 1,
                EXTERNAL_JOURNAL_PREPARED_TTL_MS,
            )
            .await
            .unwrap();
        assert_eq!(expired, 1);
        assert_eq!(
            db.external_queue_entry_state(entry).await.unwrap(),
            Some(ExternalQueueState::Expired)
        );
        // No journal row was invented for the queued work.
        assert!(
            db.external_operation_by_identity(
                &token("transcription"),
                &token("session-a"),
                &token("q1")
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn external_journal_age_policy_warns_then_criticals_and_never_deletes() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 0).await;
        db.transition_external_operation(
            record.operation_id,
            record.version,
            ExternalJournalState::Accepted,
            0,
        )
        .await
        .unwrap();

        let quiet = db.external_journal_age_report(1_000).await.unwrap();
        assert_eq!((quiet.unresolved, quiet.warning, quiet.critical), (1, 0, 0));

        let warned = db
            .external_journal_age_report(EXTERNAL_JOURNAL_UNRESOLVED_WARN_MS)
            .await
            .unwrap();
        assert_eq!(
            (warned.unresolved, warned.warning, warned.critical),
            (1, 1, 0)
        );
        assert!(warned.is_warning() && !warned.is_critical());

        let critical = db
            .external_journal_age_report(EXTERNAL_JOURNAL_UNRESOLVED_CRITICAL_MS)
            .await
            .unwrap();
        assert_eq!(
            (critical.unresolved, critical.warning, critical.critical),
            (1, 0, 1)
        );
        assert!(critical.is_critical());

        // Age never deletes unresolved work.
        let expired = db
            .expire_prepared_external_operations(
                EXTERNAL_JOURNAL_UNRESOLVED_CRITICAL_MS * 10,
                EXTERNAL_JOURNAL_PREPARED_TTL_MS,
            )
            .await
            .unwrap();
        assert!(expired.is_empty());
        assert_eq!(
            db.external_operation(record.operation_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            ExternalJournalState::Accepted
        );
    }

    // ---- criterion 3: capacity partitions ---------------------------------

    #[test]
    fn external_journal_spool_limits_constants_are_exact() {
        assert_eq!(EXTERNAL_JOURNAL_CAPSULE_BYTES, 65_536);
        assert_eq!(EXTERNAL_JOURNAL_MAX_PROJECTION_BYTES, 24_576);
        assert_eq!(EXTERNAL_JOURNAL_ADMISSION_CAPSULES, 3_072);
        assert_eq!(EXTERNAL_JOURNAL_ADMISSION_BYTES, 201_326_592);
        assert_eq!(EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES, 1_024);
        assert_eq!(EXTERNAL_JOURNAL_RECOVERY_RESERVE_BYTES, 67_108_864);
        assert_eq!(EXTERNAL_JOURNAL_HARD_LIMIT_CAPSULES, 4_096);
        assert_eq!(EXTERNAL_JOURNAL_HARD_LIMIT_BYTES, 268_435_456);
        assert_eq!(
            EXTERNAL_JOURNAL_ADMISSION_CAPSULES + EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES,
            EXTERNAL_JOURNAL_HARD_LIMIT_CAPSULES
        );
        assert_eq!(
            EXTERNAL_JOURNAL_ADMISSION_BYTES + EXTERNAL_JOURNAL_RECOVERY_RESERVE_BYTES,
            EXTERNAL_JOURNAL_HARD_LIMIT_BYTES
        );
        assert_eq!(
            EXTERNAL_JOURNAL_HARD_LIMIT_CAPSULES * EXTERNAL_JOURNAL_CAPSULE_BYTES,
            EXTERNAL_JOURNAL_HARD_LIMIT_BYTES
        );
    }

    #[test]
    fn external_journal_spool_limits_capacity_arithmetic_is_checked() {
        // A corrupted or hostile ledger must saturate into "blocked", never
        // wrap into an apparently-free partition.
        let saturated = ExternalJournalCapacity {
            admission_capsules: i64::MAX,
            admission_bytes: i64::MAX,
            recovery_capsules: i64::MAX,
            recovery_bytes: i64::MAX,
            quarantined_capsules: 0,
        };
        assert_eq!(saturated.total_capsules(), i64::MAX);
        assert_eq!(saturated.total_bytes(), i64::MAX);
        assert!(saturated.admission_blocked());

        // Exactly at the boundary is already blocked; one below is not.
        let at_limit = ExternalJournalCapacity {
            admission_capsules: EXTERNAL_JOURNAL_ADMISSION_CAPSULES,
            admission_bytes: EXTERNAL_JOURNAL_ADMISSION_BYTES,
            ..ExternalJournalCapacity::default()
        };
        assert!(at_limit.admission_blocked());
        let below_limit = ExternalJournalCapacity {
            admission_capsules: EXTERNAL_JOURNAL_ADMISSION_CAPSULES - 1,
            admission_bytes: EXTERNAL_JOURNAL_ADMISSION_BYTES - EXTERNAL_JOURNAL_CAPSULE_BYTES,
            ..ExternalJournalCapacity::default()
        };
        assert!(!below_limit.admission_blocked());
    }

    #[tokio::test]
    async fn external_journal_spool_limits_admission_boundary_blocks_new_work() {
        let db = Db::open_in_memory().unwrap();
        // Fill the admission partition to exactly its boundary without paying
        // for 3,072 real rows: seed the ledger directly.
        db.write(|conn| {
            for index in 0..EXTERNAL_JOURNAL_ADMISSION_CAPSULES {
                let operation_id = Uuid::new_v4().to_string();
                conn.execute(
                    "INSERT INTO external_journal_operations (
                         operation_id, operation_kind, owner_session_id, idempotency_key,
                         payload_digest, payload_len, state, version,
                         created_at_wall_ms, updated_at_wall_ms
                     ) VALUES (?1, 'seed', 'session-seed', ?2, ?3, 0, 'prepared', 1, 0, 0)",
                    params![operation_id, index.to_string(), "c".repeat(64)],
                )?;
                conn.execute(
                    "INSERT INTO external_journal_spool_capsules (
                         operation_id, capsule_uuid, key_version, allocated_bytes,
                         capacity_partition, quarantined, created_at_wall_ms
                     ) VALUES (?1, ?2, 1, 65536, 'admission', 0, 0)",
                    params![operation_id, Uuid::new_v4().to_string()],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();

        let capacity = db.external_journal_capacity().await.unwrap();
        assert_eq!(
            capacity.admission_capsules,
            EXTERNAL_JOURNAL_ADMISSION_CAPSULES
        );
        assert_eq!(capacity.admission_bytes, EXTERNAL_JOURNAL_ADMISSION_BYTES);
        assert!(capacity.admission_blocked());

        let record = prepared(&db, "overflow", 1_000).await;
        let admission = db
            .reserve_external_journal_capsule(
                record.operation_id,
                Uuid::new_v4(),
                1,
                CapsulePartition::Admission,
                false,
                1_000,
            )
            .await
            .unwrap();
        assert!(matches!(admission, CapsuleAdmission::Full(_)));

        // The 1,024 / 64 MiB recovery reserve is still available.
        let reserve = db
            .reserve_external_journal_capsule(
                record.operation_id,
                Uuid::new_v4(),
                1,
                CapsulePartition::Recovery,
                false,
                1_000,
            )
            .await
            .unwrap();
        assert!(matches!(reserve, CapsuleAdmission::Reserved(_)));
        let after = db.external_journal_capacity().await.unwrap();
        assert_eq!(after.recovery_capsules, 1);
        assert_eq!(
            after.total_bytes(),
            EXTERNAL_JOURNAL_ADMISSION_BYTES + 65_536
        );
    }

    #[tokio::test]
    async fn external_journal_spool_limits_reject_oversized_projection() {
        let db = Db::open_in_memory().unwrap();
        let mut request = prepare_request("k1");
        request.payload_len = EXTERNAL_JOURNAL_MAX_PROJECTION_BYTES;
        db.prepare_external_operation(request, 1_000).await.unwrap();

        let mut oversized = prepare_request("k2");
        oversized.payload_len = EXTERNAL_JOURNAL_MAX_PROJECTION_BYTES + 1;
        let error = db
            .prepare_external_operation(oversized, 1_000)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("encoder cap"), "{error}");
    }

    #[tokio::test]
    async fn external_journal_spool_limits_capsule_release_requires_terminal_state() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        db.reserve_external_journal_capsule(
            record.operation_id,
            Uuid::new_v4(),
            1,
            CapsulePartition::Admission,
            false,
            1_000,
        )
        .await
        .unwrap();

        let error = db
            .release_external_journal_capsule(record.operation_id)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("non-terminal"), "{error}");

        db.transition_external_operation(
            record.operation_id,
            record.version,
            ExternalJournalState::Rejected,
            1_100,
        )
        .await
        .unwrap();
        assert!(
            db.release_external_journal_capsule(record.operation_id)
                .await
                .unwrap()
        );
        assert_eq!(
            db.external_journal_capacity()
                .await
                .unwrap()
                .total_capsules(),
            0
        );
    }

    #[tokio::test]
    async fn external_journal_spool_limits_reservation_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let record = prepared(&db, "k1", 1_000).await;
        let capsule_uuid = Uuid::new_v4();
        let first = db
            .reserve_external_journal_capsule(
                record.operation_id,
                capsule_uuid,
                1,
                CapsulePartition::Admission,
                false,
                1_000,
            )
            .await
            .unwrap();
        assert!(matches!(first, CapsuleAdmission::Reserved(_)));
        let second = db
            .reserve_external_journal_capsule(
                record.operation_id,
                Uuid::new_v4(),
                2,
                CapsulePartition::Admission,
                false,
                1_000,
            )
            .await
            .unwrap();
        match second {
            CapsuleAdmission::AlreadyReserved(reservation) => {
                assert_eq!(reservation.capsule_uuid, capsule_uuid);
                assert_eq!(reservation.key_version, 1);
            }
            other => panic!("unexpected admission: {other:?}"),
        }
        assert_eq!(
            db.external_journal_capacity()
                .await
                .unwrap()
                .admission_capsules,
            1
        );
    }

    #[tokio::test]
    async fn external_journal_spool_limits_quarantine_moves_to_recovery_partition() {
        let db = Db::open_in_memory().unwrap();
        let record = prepared(&db, "k1", 1_000).await;
        db.reserve_external_journal_capsule(
            record.operation_id,
            Uuid::new_v4(),
            3,
            CapsulePartition::Admission,
            false,
            1_000,
        )
        .await
        .unwrap();
        assert_eq!(
            db.quarantine_external_journal_capsule(record.operation_id)
                .await
                .unwrap(),
            QuarantineLedgerOutcome::MovedToRecovery
        );
        let capacity = db.external_journal_capacity().await.unwrap();
        assert_eq!(capacity.admission_capsules, 0);
        assert_eq!(capacity.recovery_capsules, 1);
        assert_eq!(capacity.quarantined_capsules, 1);
        assert_eq!(
            db.external_journal_referenced_key_versions().await.unwrap(),
            vec![3]
        );
    }

    // ---- criterion 8: squashed schema -------------------------------------

    #[tokio::test]
    async fn external_journal_schema_squashed_into_0001_initial() {
        let sql = include_str!("migrations/0001_initial.sql");
        assert!(sql.contains("CREATE TABLE external_journal_operations"));
        assert!(sql.contains("CREATE TABLE external_journal_events"));
        assert!(sql.contains("CREATE TABLE external_journal_spool_capsules"));
        assert!(sql.contains("CREATE TABLE external_journal_queue_entries"));
        assert!(sql.contains("CREATE TABLE external_journal_session_tombstones"));
        assert!(sql.contains("CREATE TABLE external_journal_integrity_faults"));
        // Operations-table guards must be row-level, not column-scoped, or a
        // writer that omits a column from its SET list slips past them.
        // Every operations-table trigger must be row-level. A column-scoped
        // `BEFORE UPDATE OF x` fires only when the statement's SET list
        // mentions `x`, so a writer that omits a column would slip past it.
        // Checked per trigger header — a blanket search over the whole file
        // would match this very explanation, and did.
        for block in sql.split("CREATE TRIGGER external_journal_ops_").skip(1) {
            let header = block
                .split("\nBEGIN")
                .next()
                .expect("trigger header precedes BEGIN");
            assert!(
                header.contains("BEFORE UPDATE ON external_journal_operations"),
                "operations trigger is not row-level: {header}"
            );
            assert!(
                !header.contains("UPDATE OF"),
                "operations trigger is column-scoped: {header}"
            );
        }
        assert!(sql.contains("CREATE UNIQUE INDEX uq_external_journal_events_terminal"));
        assert!(sql.contains("payload_len <= 24576"));
        assert!(sql.contains("allocated_bytes = 65536"));

        // Every state string in the enum is inside the migration CHECK set.
        for state in ExternalJournalState::ALL {
            assert!(
                sql.contains(&format!("'{}'", state.as_str())),
                "migration is missing state {}",
                state.as_str()
            );
        }

        // The external-journal schema lives entirely in `0001_initial.sql`;
        // later migrations (`0002_goal_inference_provenance`,
        // `0003_media_resource_reservation_ledger`) add unrelated tables. Three
        // migration files ship in this build, so the expected schema version is
        // three. Adding a fourth migration must update this literal.
        assert_eq!(crate::db::EXPECTED_SCHEMA_VERSION, 3);

        let db = Db::open_in_memory().unwrap();
        let tables = db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT name FROM sqlite_master
                      WHERE name LIKE 'external_journal%' OR name LIKE 'uq_external_journal%'
                         OR name LIKE 'idx_external_journal%'
                      ORDER BY name",
                )?;
                let names = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(names)
            })
            .await
            .unwrap();
        for expected in [
            "external_journal_events",
            "external_journal_operations",
            "external_journal_queue_entries",
            "external_journal_session_tombstones",
            "external_journal_spool_capsules",
            "idx_external_journal_ops_unresolved",
            "uq_external_journal_events_terminal",
            "uq_external_journal_events_version",
        ] {
            assert!(
                tables.iter().any(|name| name == expected),
                "missing {expected}"
            );
        }
    }

    /// Every production `DELETE FROM sessions` must go through
    /// `delete_session_conn`, which writes the tombstone in the same
    /// transaction. A new raw delete would let a session vanish while its
    /// unresolved external operations lost their owner-visible marker.
    #[test]
    fn external_journal_exactly_once_session_delete_always_tombstones() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let sessions = std::fs::read_to_string(manifest.join("src/db/sessions.rs")).unwrap();

        let delete_fn = sessions
            .split("pub fn delete_session_conn")
            .nth(1)
            .expect("delete_session_conn exists");
        let body = &delete_fn[..delete_fn.find("\n}").expect("function body ends")];
        // Either tombstone entrypoint is fine; the invariant is that one runs
        // before the delete, in the same transaction.
        assert!(
            body.contains("tombstone_external_journal_session"),
            "delete_session_conn must record the tombstone before deleting"
        );
        assert!(
            body.find("tombstone_external_journal_session") < body.find("DELETE FROM sessions"),
            "the tombstone must be written before the delete"
        );

        // Writing the tombstone in the same *function* is not enough: under
        // `Db::write` each statement autocommits separately, so a failure
        // between them leaves a tombstone for a live session or a deleted
        // session with no marker. No production `write`/blocking wrapper may
        // reach `delete_session_conn`, directly or through a helper.
        let mut checked_a_transaction = false;
        for file in ["src/db/sessions.rs", "src/db/retention.rs"] {
            let source = std::fs::read_to_string(manifest.join(file)).unwrap();
            let production = production_half(&source);

            // Names that reach the delete, following one level of helper
            // indirection at a time until the set stops growing.
            let mut reaching = vec!["delete_session_conn".to_string()];
            loop {
                let mut grew = false;
                for name in fn_names(production) {
                    if reaching.contains(&name) {
                        continue;
                    }
                    let Some(body) = fn_body(production, &name) else {
                        continue;
                    };
                    if reaching.iter().any(|target| body.contains(target.as_str())) {
                        reaching.push(name);
                        grew = true;
                    }
                }
                if !grew {
                    break;
                }
            }

            for wrapper in ["self.write(", "blocking_write_"] {
                for argument in wrapper_arguments(production, wrapper) {
                    for name in &reaching {
                        assert!(
                            !argument.contains(name.as_str()),
                            "{file}: `{wrapper}` reaches `{name}`; \
                             session deletion must run inside Db::transaction"
                        );
                    }
                }
            }
            for argument in wrapper_arguments(production, "self.transaction(") {
                if reaching.iter().any(|name| argument.contains(name.as_str())) {
                    checked_a_transaction = true;
                }
            }
        }
        assert!(
            checked_a_transaction,
            "the check is vacuous unless some transaction reaches the delete"
        );

        // Any other occurrence in the storage layer must be inside a test
        // module exercising raw cascade behaviour, never production code.
        for file in [
            "src/db/sessions.rs",
            "src/db/pins.rs",
            "src/db/session_search.rs",
        ] {
            let source = std::fs::read_to_string(manifest.join(file)).unwrap();
            let test_marker = source.find("\nmod tests {");
            let mut cursor = 0usize;
            while let Some(offset) = source[cursor..].find("DELETE FROM sessions") {
                let index = cursor + offset;
                if in_line_comment(&source, index) {
                    cursor = index + 1;
                    continue;
                }
                let inside_delete_fn = source[..index]
                    .rfind("pub fn delete_session_conn")
                    .is_some()
                    && source[..index]
                        .rfind("pub fn delete_session_conn")
                        .map(|start| source[start..index].matches("\n}").count() == 0)
                        .unwrap_or(false);
                let inside_tests = test_marker.is_some_and(|marker| index > marker);
                assert!(
                    inside_delete_fn || inside_tests,
                    "{file} has a production `DELETE FROM sessions` outside delete_session_conn"
                );
                cursor = index + 1;
            }
        }
    }

    /// A mid-delete failure must roll back every half: no tombstone without
    /// the deletion, no deletion without the tombstone — for the whole cascade
    /// set, not just the requested root.
    #[tokio::test]
    async fn external_journal_exactly_once_session_delete_rolls_back_as_one_unit() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "Auto").await.unwrap();
        // A descendant fork: `DELETE FROM sessions` cascades to it, so it must
        // be tombstoned by the same statement that tombstones the root.
        let child = db.create_fork(root.session_id, None).await.unwrap();
        assert_ne!(child.session_id, root.session_id);
        // And one reachable only through the btw edge, which a parent-only
        // walk cannot see.
        let btw_only = db.create_session("p", "/x", "Auto").await.unwrap();
        relink_as_btw_only_child(&db, btw_only.session_id, root.session_id).await;
        let root_owner = ExternalJournalToken::for_session(root.session_id);
        let child_owner = ExternalJournalToken::for_session(child.session_id);
        let btw_only_owner = ExternalJournalToken::for_session(btw_only.session_id);

        // Inject a failure after `delete_session_conn` has written the
        // tombstones and issued the delete, inside the same transaction.
        let root_id = root.session_id;
        let failed: Result<()> = db
            .transaction(move |conn| {
                crate::db::sessions::delete_session_conn(conn, root_id)?;
                bail!("injected mid-delete failure")
            })
            .await;
        assert!(failed.is_err());

        // Nothing survived, for either session. Under `Db::write` the
        // statements autocommit separately and these fail.
        assert!(
            db.get_session(root_id).await.unwrap().is_some(),
            "a rolled-back delete must leave the root in place"
        );
        assert!(
            db.get_session(child.session_id).await.unwrap().is_some(),
            "a rolled-back delete must leave the descendant in place"
        );
        assert!(
            db.get_session(btw_only.session_id).await.unwrap().is_some(),
            "a rolled-back delete must leave the btw-only descendant in place"
        );
        for owner in [&root_owner, &child_owner, &btw_only_owner] {
            assert!(
                !db.external_journal_session_tombstoned(owner).await.unwrap(),
                "a rolled-back delete must leave no orphan tombstone"
            );
        }

        // And the committed path applies all of it.
        db.delete_session(root_id).await.unwrap();
        assert!(db.get_session(root_id).await.unwrap().is_none());
        assert!(
            db.get_session(child.session_id).await.unwrap().is_none(),
            "the descendant is cascade-deleted"
        );
        assert!(
            db.get_session(btw_only.session_id).await.unwrap().is_none(),
            "the btw-only descendant is cascade-deleted too"
        );
        assert!(
            db.external_journal_session_tombstoned(&root_owner)
                .await
                .unwrap(),
            "a committed delete must always leave its tombstone"
        );
        assert!(
            db.external_journal_session_tombstoned(&child_owner)
                .await
                .unwrap(),
            "a cascade-deleted descendant must be tombstoned too"
        );
        assert!(
            db.external_journal_session_tombstoned(&btw_only_owner)
                .await
                .unwrap(),
            "a descendant reachable only via btw_parent_session_id must be \
             tombstoned; the walk must follow both cascade edges"
        );
    }

    /// An unknown id has an empty delete set, so it must not be tombstoned.
    #[tokio::test]
    async fn external_journal_exactly_once_unknown_session_delete_writes_no_tombstone() {
        let db = Db::open_in_memory().unwrap();
        let ghost = Uuid::new_v4();
        db.delete_session(ghost).await.unwrap();
        assert!(
            !db.external_journal_session_tombstoned(&ExternalJournalToken::for_session(ghost))
                .await
                .unwrap(),
            "deleting a session that does not exist cascades nothing, so it \
             must leave no tombstone behind"
        );
    }

    /// Every path that deletes sessions goes through `delete_session_conn`, so
    /// the cascade tombstones cover retention and ephemeral discard as well.
    #[tokio::test]
    async fn external_journal_exactly_once_cascade_paths_all_tombstone_descendants() {
        let db = Db::open_in_memory().unwrap();

        // Ephemeral discard: a `/btw` row that itself has a fork.
        let parent = db.create_session("p", "/x", "Auto").await.unwrap();
        let btw = db
            .create_btw_fork(parent.session_id, false)
            .await
            .unwrap()
            .info
            .session_id;
        let btw_child = db.create_fork(btw, None).await.unwrap();
        assert!(db.discard_ephemeral_session(btw).await.unwrap());
        for id in [btw, btw_child.session_id] {
            assert!(db.get_session(id).await.unwrap().is_none());
            assert!(
                db.external_journal_session_tombstoned(&ExternalJournalToken::for_session(id))
                    .await
                    .unwrap(),
                "ephemeral discard must tombstone the whole cascade set"
            );
        }

        // Retention expiry: a closed root with a closed fork.
        let old_root = db.create_session("p", "/y", "Auto").await.unwrap();
        let old_child = db.create_fork(old_root.session_id, None).await.unwrap();
        // Eligibility needs the whole subtree closed and the root idle before
        // the cutoff, so set `ended_at` and `last_active_at` on both.
        for id in [old_root.session_id, old_child.session_id] {
            db.write(move |conn| {
                conn.execute(
                    "UPDATE sessions SET ended_at = 1, last_active_at = 1
                      WHERE session_id = ?1",
                    params![id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        }
        let now_secs = chrono::Utc::now().timestamp();
        let removed = db.expire_old_sessions(now_secs).await.unwrap();
        assert_eq!(removed, 1, "one root expires, cascading to its fork");
        for id in [old_root.session_id, old_child.session_id] {
            assert!(db.get_session(id).await.unwrap().is_none());
            assert!(
                db.external_journal_session_tombstoned(&ExternalJournalToken::for_session(id))
                    .await
                    .unwrap(),
                "retention expiry must tombstone the whole cascade set"
            );
        }
    }

    /// The external-journal schema is defined only in `0001_initial.sql`. Later
    /// append-only migrations may *reference* external-journal objects (e.g. a
    /// foreign key), but none may `CREATE` external-journal tables — the whole
    /// journal schema stays squashed into the initial migration.
    #[test]
    fn external_journal_tables_are_defined_only_in_0001_initial() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db/migrations");
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let sql = std::fs::read_to_string(entry.path()).unwrap();
            let defines_journal = sql.contains("CREATE TABLE external_journal");
            if name == "0001_initial.sql" {
                assert!(
                    defines_journal,
                    "0001_initial.sql must define the external-journal schema"
                );
            } else {
                assert!(
                    !defines_journal,
                    "{name} must not create external-journal tables"
                );
            }
        }
    }

    // ---- criterion 6: fault convergence without blind resubmission --------

    #[tokio::test]
    async fn external_journal_fault_no_blind_retry_without_provider_contract() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let unknown = db
            .transition_external_operation(
                record.operation_id,
                record.version,
                ExternalJournalState::SubmissionUnknown,
                1_100,
            )
            .await
            .unwrap()
            .record()
            .clone();
        assert!(!unknown.retry_permitted());

        let mut with_contract = prepare_request("k2");
        with_contract.provider_idempotency = Some(ProviderIdempotency {
            key: token("idem-1"),
            contract: token("provider-contract-v1"),
        });
        let contracted = db
            .prepare_external_operation(with_contract, 1_000)
            .await
            .unwrap()
            .record()
            .clone();
        assert!(contracted.retry_permitted());
    }

    #[tokio::test]
    async fn external_journal_fault_reconnect_converges_without_losing_unknown_work() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("journal.db");
        let record = {
            let db = Db::open(&path).unwrap();
            let record = dispatching(&db, "k1", 1_000).await;
            db.transition_external_operation(
                record.operation_id,
                record.version,
                ExternalJournalState::SubmissionUnknown,
                1_100,
            )
            .await
            .unwrap();
            record
        };

        // Restart: the unknown fact is durable and still unresolved.
        let db = Db::open(&path).unwrap();
        let reopened = db
            .external_operation(record.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reopened.state, ExternalJournalState::SubmissionUnknown);
        assert!(reopened.state.is_unresolved());
        let unresolved = db.list_unresolved_external_operations().await.unwrap();
        assert_eq!(unresolved.len(), 1);

        let reconciled = db
            .transition_external_operation(
                record.operation_id,
                reopened.version,
                ExternalJournalState::Reconciling,
                1_200,
            )
            .await
            .unwrap();
        assert!(reconciled.is_committed());
    }

    #[tokio::test]
    async fn external_journal_fault_import_conflict_never_forces_an_illegal_state() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        db.transition_external_operation(
            record.operation_id,
            record.version,
            ExternalJournalState::Rejected,
            1_100,
        )
        .await
        .unwrap();
        // A newer but illegal spool version cannot resurrect a terminal record.
        let outcome = db
            .import_external_journal_record(
                record.operation_id,
                99,
                ExternalJournalState::Accepted,
                1_200,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, ExternalTransitionOutcome::Conflict(_)));
        assert_eq!(outcome.record().state, ExternalJournalState::Rejected);
    }

    // ---- criterion 7: redaction sentinels ---------------------------------

    #[tokio::test]
    async fn external_journal_redaction_sentinels_absent_from_sqlite() {
        const SENTINELS: &[&str] = &[
            "SENTINEL-PROMPT-TEXT",
            "SENTINEL-TYPED-INPUT",
            "SENTINEL-BEARER-TOKEN",
            "/sentinel/raw/path",
            "https://sentinel.example/signed?sig=SENTINEL",
        ];

        // The mechanism, not a coincidence: forbidden content cannot even be
        // constructed as an identity token or a digest, so it can never be
        // handed to the database boundary in the first place.
        for sentinel in SENTINELS {
            assert!(
                ExternalJournalToken::parse(sentinel).is_err(),
                "token accepted {sentinel}"
            );
            assert!(
                ExternalJournalDigest::parse(sentinel).is_err(),
                "digest accepted {sentinel}"
            );
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("journal.db");
        let db = Db::open(&path).unwrap();

        // Now drive a real operation whose *inputs* were the sentinels: only
        // their digests survive into the row.
        let record = db
            .prepare_external_operation(
                PrepareExternalOperation {
                    operation_kind: token("computer_input"),
                    owner_session_id: token("session-a"),
                    idempotency_key: token("k1"),
                    payload_digest: ExternalJournalDigest::of(
                        b"SENTINEL-PROMPT-TEXT /sentinel/raw/path SENTINEL-BEARER-TOKEN",
                    ),
                    payload_len: 128,
                    provider_idempotency: Some(ProviderIdempotency {
                        key: token("idem-1"),
                        contract: token("provider-contract-v1"),
                    }),
                },
                1_000,
            )
            .await
            .unwrap()
            .record()
            .clone();
        let dispatched = db
            .transition_external_operation(
                record.operation_id,
                record.version,
                ExternalJournalState::Dispatching,
                1_050,
            )
            .await
            .unwrap()
            .record()
            .clone();
        db.transition_external_operation(
            record.operation_id,
            dispatched.version,
            ExternalJournalState::Accepted,
            1_100,
        )
        .await
        .unwrap();

        // The redacted Debug must not expose the raw identity either.
        let rendered = format!("{record:?}");
        assert!(!rendered.contains("session-a"), "{rendered}");
        assert!(!rendered.contains("idem-1"), "{rendered}");
        assert!(
            !rendered.contains("provider-contract-v1"),
            "provider evidence must render as presence only: {rendered}"
        );
        assert!(
            rendered.contains("provider_idempotency: true"),
            "presence itself is safe and useful: {rendered}"
        );
        assert!(
            !rendered.contains(record.payload_digest.as_str()),
            "the full payload digest must not reach a log line"
        );
        // The evidence type redacts its own key wherever it is rendered
        // directly rather than through the record.
        let evidence = format!("{:?}", record.provider_idempotency.as_ref().unwrap());
        assert!(evidence.contains("[REDACTED]"), "{evidence}");
        assert!(!evidence.contains("idem-1"), "{evidence}");

        db.write(|conn| {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            Ok(())
        })
        .await
        .unwrap();
        drop(db);

        let bytes = std::fs::read(&path).unwrap();
        for sentinel in SENTINELS {
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel.as_bytes()),
                "sentinel {sentinel} leaked into the database file"
            );
        }
    }

    // ---- item 10: identity validation at the database boundary -----------

    #[test]
    fn external_journal_redaction_identity_tokens_are_bounded() {
        assert!(ExternalJournalToken::parse("computer_input").is_ok());
        assert!(ExternalJournalToken::parse(&"a".repeat(EXTERNAL_JOURNAL_TOKEN_MAX_LEN)).is_ok());
        assert!(
            ExternalJournalToken::parse(&"a".repeat(EXTERNAL_JOURNAL_TOKEN_MAX_LEN + 1)).is_err()
        );
        assert!(ExternalJournalToken::parse("").is_err());
        assert!(ExternalJournalToken::parse("Upper").is_err());
        assert!(ExternalJournalToken::parse("with space").is_err());
        // A session UUID is a valid token, which is how owners are bound.
        let session = Uuid::new_v4();
        assert_eq!(
            ExternalJournalToken::for_session(session).as_str(),
            session.hyphenated().to_string()
        );
    }

    #[tokio::test]
    async fn external_journal_redaction_rejects_unbounded_stored_values() {
        // A row written by something that bypassed this module cannot smuggle
        // unbounded content back into memory: decoding re-validates.
        let db = Db::open_in_memory().unwrap();
        db.write(|conn| {
            conn.execute(
                "INSERT INTO external_journal_operations (
                     operation_id, operation_kind, owner_session_id, idempotency_key,
                     payload_digest, payload_len, state, version,
                     created_at_wall_ms, updated_at_wall_ms
                 ) VALUES (?1, 'computer_input', 'session-a',
                           'SENTINEL-PROMPT-TEXT', ?2, 0, 'prepared', 1, 0, 0)",
                params![Uuid::nil().to_string(), "a".repeat(64)],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(db.external_operation(Uuid::nil()).await.is_err());
    }

    // ---- item 3: dispatching is unresolved -------------------------------

    #[tokio::test]
    async fn external_journal_age_policy_dispatching_counts_as_unresolved() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 0).await;
        assert!(record.state.is_unresolved());

        let warned = db
            .external_journal_age_report(EXTERNAL_JOURNAL_UNRESOLVED_WARN_MS)
            .await
            .unwrap();
        assert_eq!((warned.unresolved, warned.warning), (1, 1));
        let critical = db
            .external_journal_age_report(EXTERNAL_JOURNAL_UNRESOLVED_CRITICAL_MS)
            .await
            .unwrap();
        assert_eq!(critical.critical, 1);

        // Recovery converts it, because a record found here after a restart may
        // already have produced an external effect.
        let converted = db
            .convert_dispatching_without_evidence(record.operation_id, 5_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(converted.state, ExternalJournalState::SubmissionUnknown);
        // Idempotent: a second worker sees nothing left to convert.
        assert!(
            db.convert_dispatching_without_evidence(record.operation_id, 5_100)
                .await
                .unwrap()
                .is_none()
        );
    }

    // ---- item 6/7: capacity invariants -----------------------------------

    #[test]
    fn external_journal_spool_limits_full_recovery_reserve_blocks_admission() {
        let reserve_full = ExternalJournalCapacity {
            recovery_capsules: EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES,
            ..ExternalJournalCapacity::default()
        };
        assert!(reserve_full.admission_blocked());
        assert_eq!(
            reserve_full.admission_block_reason(),
            Some("recovery reserve capsule count")
        );
        let bytes_full = ExternalJournalCapacity {
            recovery_bytes: EXTERNAL_JOURNAL_RECOVERY_RESERVE_BYTES,
            ..ExternalJournalCapacity::default()
        };
        assert!(bytes_full.admission_blocked());
    }

    #[tokio::test]
    async fn external_journal_spool_limits_quarantine_respects_the_recovery_reserve() {
        let db = Db::open_in_memory().unwrap();
        // Fill the recovery reserve exactly.
        db.write(|conn| {
            for index in 0..EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES {
                let operation_id = Uuid::new_v4().to_string();
                conn.execute(
                    "INSERT INTO external_journal_operations (
                         operation_id, operation_kind, owner_session_id, idempotency_key,
                         payload_digest, payload_len, state, version,
                         created_at_wall_ms, updated_at_wall_ms
                     ) VALUES (?1, 'seed', 'session-seed', ?2, ?3, 0, 'prepared', 1, 0, 0)",
                    params![operation_id, index.to_string(), "b".repeat(64)],
                )?;
                conn.execute(
                    "INSERT INTO external_journal_spool_capsules (
                         operation_id, capsule_uuid, key_version, allocated_bytes,
                         capacity_partition, quarantined, created_at_wall_ms
                     ) VALUES (?1, ?2, 1, 65536, 'recovery', 0, 0)",
                    params![operation_id, Uuid::new_v4().to_string()],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();

        let record = prepared(&db, "k1", 1_000).await;
        db.reserve_external_journal_capsule(
            record.operation_id,
            Uuid::new_v4(),
            1,
            CapsulePartition::Admission,
            false,
            1_000,
        )
        .await
        .unwrap();

        // Moving into a full reserve would exceed 1,024 / 64 MiB, so the row is
        // flagged in place instead. Dispatch is blocked either way.
        assert_eq!(
            db.quarantine_external_journal_capsule(record.operation_id)
                .await
                .unwrap(),
            QuarantineLedgerOutcome::FlaggedInPlace
        );
        let capacity = db.external_journal_capacity().await.unwrap();
        assert_eq!(
            capacity.recovery_capsules,
            EXTERNAL_JOURNAL_RECOVERY_RESERVE_CAPSULES
        );
        assert_eq!(capacity.quarantined_capsules, 1);
        assert!(capacity.admission_blocked());
    }

    #[tokio::test]
    async fn external_journal_spool_limits_release_without_medium_frees_capacity() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        db.reserve_external_journal_capsule(
            record.operation_id,
            Uuid::new_v4(),
            1,
            CapsulePartition::Admission,
            false,
            1_000,
        )
        .await
        .unwrap();

        // A non-terminal record refuses the terminal release path...
        assert!(
            db.release_external_journal_capsule(record.operation_id)
                .await
                .is_err()
        );
        // ...and refuses the undispatched rollback path...
        assert!(
            db.rollback_external_journal_capsule_reservation(record.operation_id)
                .await
                .is_err()
        );
        // ...but a proven-missing medium releases, so capacity cannot drain.
        assert!(
            db.release_external_journal_capsule_without_medium(record.operation_id)
                .await
                .unwrap()
        );
        assert_eq!(
            db.external_journal_capacity()
                .await
                .unwrap()
                .total_capsules(),
            0
        );
    }

    // ---- item 14: SQL-level integrity backstop ---------------------------

    #[tokio::test]
    async fn external_journal_schema_squashed_triggers_reject_impossible_history() {
        let db = Db::open_in_memory().unwrap();
        let record = prepared(&db, "k1", 1_000).await;
        let operation_id = record.operation_id.to_string();

        // An illegal edge cannot be inserted even by raw SQL.
        let illegal = db
            .write({
                let operation_id = operation_id.clone();
                move |conn| {
                    conn.execute(
                        "INSERT INTO external_journal_events (
                             event_id, operation_id, version, from_state, to_state,
                             terminal, emitted_at_wall_ms
                         ) VALUES (?1, ?2, 9, 'prepared', 'succeeded', 1, 0)",
                        params![Uuid::new_v4().to_string(), operation_id],
                    )?;
                    Ok(())
                }
            })
            .await;
        assert!(illegal.is_err(), "trigger must reject an illegal edge");

        // A mislabelled terminal flag cannot bypass the unique terminal index.
        let mislabelled = db
            .write({
                let operation_id = operation_id.clone();
                move |conn| {
                    conn.execute(
                        "INSERT INTO external_journal_events (
                             event_id, operation_id, version, from_state, to_state,
                             terminal, emitted_at_wall_ms
                         ) VALUES (?1, ?2, 9, 'prepared', 'cancelled', 0, 0)",
                        params![Uuid::new_v4().to_string(), operation_id],
                    )?;
                    Ok(())
                }
            })
            .await;
        assert!(mislabelled.is_err(), "terminal flag must agree with state");

        // A genuine rewind: advance to version 2 first, then try to go back.
        db.transition_external_operation(
            record.operation_id,
            record.version,
            ExternalJournalState::Dispatching,
            1_100,
        )
        .await
        .unwrap();
        let rewound = db
            .write({
                let operation_id = operation_id.clone();
                move |conn| {
                    conn.execute(
                        "UPDATE external_journal_operations SET version = 1
                          WHERE operation_id = ?1",
                        params![operation_id],
                    )?;
                    Ok(())
                }
            })
            .await;
        assert!(rewound.is_err(), "version must be monotonic");
    }

    /// The operations-table triggers must not depend on an event row being
    /// written: a writer that updates the row directly must still be refused.
    #[tokio::test]
    async fn external_journal_schema_squashed_row_triggers_fire_without_events() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        let operation_id = record.operation_id.to_string();

        // An illegal edge written straight to the row, no event inserted.
        let illegal = db
            .write({
                let operation_id = operation_id.clone();
                move |conn| {
                    conn.execute(
                        "UPDATE external_journal_operations
                            SET state = 'succeeded', version = version + 1
                          WHERE operation_id = ?1",
                        params![operation_id],
                    )?;
                    Ok(())
                }
            })
            .await;
        assert!(illegal.is_err(), "row-level edge legality must be enforced");

        // A state change that does not mention `version` in its SET list —
        // the exact shape a column-scoped trigger would miss.
        let unversioned = db
            .write({
                let operation_id = operation_id.clone();
                move |conn| {
                    conn.execute(
                        "UPDATE external_journal_operations SET state = 'accepted'
                          WHERE operation_id = ?1",
                        params![operation_id],
                    )?;
                    Ok(())
                }
            })
            .await;
        assert!(
            unversioned.is_err(),
            "a state change without a version bump must be refused"
        );

        // Terminal immutability, again without an event row.
        db.transition_external_operation(
            record.operation_id,
            record.version,
            ExternalJournalState::Rejected,
            1_100,
        )
        .await
        .unwrap();
        let resurrect = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE external_journal_operations
                        SET state = 'accepted', version = version + 1
                      WHERE operation_id = ?1",
                    params![operation_id],
                )?;
                Ok(())
            })
            .await;
        assert!(resurrect.is_err(), "a terminal record must stay terminal");
    }

    #[tokio::test]
    async fn external_journal_spool_security_integrity_fault_is_durable() {
        let db = Db::open_in_memory().unwrap();
        assert!(
            db.external_journal_integrity_fault()
                .await
                .unwrap()
                .is_none()
        );
        db.record_external_journal_integrity_fault("spool and database both failed", 1_000)
            .await
            .unwrap();
        assert_eq!(
            db.external_journal_integrity_fault().await.unwrap(),
            Some("spool and database both failed".to_string())
        );
        // First writer wins: the original cause is the useful one.
        db.record_external_journal_integrity_fault("a later consequence", 2_000)
            .await
            .unwrap();
        assert_eq!(
            db.external_journal_integrity_fault().await.unwrap(),
            Some("spool and database both failed".to_string())
        );
    }

    #[tokio::test]
    async fn external_journal_cancellation_fact_trigger_blocks_rewrites() {
        let db = Db::open_in_memory().unwrap();
        let record = dispatching(&db, "k1", 1_000).await;
        db.request_external_operation_cancellation(record.operation_id, 1_500)
            .await
            .unwrap();
        let operation_id = record.operation_id.to_string();

        let rewritten = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE external_journal_operations
                        SET cancellation_requested_at_wall_ms = 9999
                      WHERE operation_id = ?1",
                    params![operation_id],
                )?;
                Ok(())
            })
            .await;
        assert!(rewritten.is_err(), "the cancellation fact is immutable");
    }
}
