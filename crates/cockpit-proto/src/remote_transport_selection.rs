//! Downgrade-resistant multi-transport connection orchestration — pure reducer.
//!
//! This module implements the transport-selection state machine that orchestrates
//! an authorized set of WebRTC and E2E WebSocket transport epochs without
//! downgrade. It prefers WebRTC for initial establishment, allows multiple
//! simultaneous read/write transports, and merges all operations through one
//! daemon-ordered idempotent logical attachment stream.
//!
//! The reducer is **pure**: it takes explicit `now`, persisted retry-budget
//! input, adapter events, and emitted commands. It never branches on raw
//! adapter/client strings — all platform errors are mapped to the closed
//! `RemoteReachabilityClass` / `RemoteTransportCloseReason` taxonomy by the
//! adapter before they reach the orchestrator. The operation ledger is
//! integrated by interface only.
//!
//! Cross-language contract: the constants, enums, and pure reducer surface here
//! mirror `packages/cockpit-protocol/src/remote-transport-selection.ts`. The
//! golden transition/route traces are committed as fixtures consumed by
//! web/native/Rust.
//!
//! # What this module owns
//!
//! - The closed parent/child state enums and TURN durable lifecycle.
//! - The fixed downgrade-resistant constants (deadline, probes, health
//!   thresholds, retry budget, caps, drain window).
//! - The pure authorized-plan computation (policy/capability/consent/quota
//!   meet).
//! - The pure caps enforcement, retry-budget evaluator, health grader, and
//!   deterministic route selector.
//! - The typed denial taxonomy.
//!
//! # What this module does NOT own
//!
//! - WebRTC/fallback endpoint implementation (owned by `cockpit-core`).
//! - Postgres/Redis storage wiring. The serializable-transaction wiring is the
//!   server's responsibility; this module is the pure budget evaluator.
//! - Platform error string mapping. Adapters map platform errors into the
//!   closed taxonomy before calling the orchestrator.

use serde::{Deserialize, Serialize};

/// Cross-language schema version for the transport-selection contract.
pub const REMOTE_TRANSPORT_SELECTION_SCHEMA_VERSION: u8 = 1;

/// The two physical transport kinds the orchestrator may establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTransportKind {
    WebRtc,
    WebSocket,
}

/// Parent orchestrator states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteParentState {
//! Cross-language shared fixtures and typed enums for the remote transport
//! selection state machine.
//!
//! This module owns the pure type vocabulary consumed by the Rust orchestrator
//! (`cockpit-core::daemon::transport_selection`) and the TypeScript/protocol
//! consumers. It intentionally contains no state-machine logic — only the
//! typed enums, constants, and error taxonomy that both sides share so
//! neither branches on raw strings.
//!
//! # What this module owns
//!
//! - Transport kind, user preference, parent/child state, durable lifecycle,
//!   reachability class, health tier, routing class, and second-child reason
//!   enums.
//! - The fixed policy constants (deadline, retry delay, budgets, probe
//!   intervals, buffer/ACK thresholds).
//! - The typed denial taxonomy.
//! - The retry-reservation key and reservation record shapes.
//!
//! # What this module does NOT own
//!
//! - The reducer logic, timer emission, or route computation (owned by
//!   `cockpit-core::daemon::transport_selection`).
//! - Platform error mapping (owned by adapters).

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────
// Transport kind and user preference
// ─────────────────────────────────────────────────────────────────────────

/// The two physical authenticated transport kinds. The routed-current cap is
/// one child per kind, two total (plus one TURN replacement exception).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Webrtc,
    Websocket,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webrtc => "webrtc",
            Self::Websocket => "websocket",
        }
    }
}

/// User transport preference. Narrows only — never silently overrides a
/// forced kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserTransportPreference {
    /// Start WebRTC first; fall back to WebSocket only after deadline or a
    /// closed reachability class.
    Auto,
    /// WebRTC only; never start fallback.
    Webrtc,
    /// WebSocket only; start only authorized fallback.
    Websocket,
}

// ─────────────────────────────────────────────────────────────────────────
// Parent and child state
// ─────────────────────────────────────────────────────────────────────────

/// Parent states for the transport selection lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParentState {
    Planning,
    Establishing,
    Active,
    Degraded,
    Denied,
    Failed,
    Cancelled,
    Superseded,
}

/// Ordinary child states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteOrdinaryChildState {
/// Ordinary child states for each transport epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildState {
    Pending,
    Authenticating,
    Active,
    Degraded,
    Closing,
    Closed,
}

/// The exact durable lifecycle of a TURN replacement pair. Transport adapter
/// states cannot invent a fourth durable lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTurnLifecycle {
    Current,
    ReplacementPending,
    Draining,
}

/// User transport preference. It can narrow only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteUserPreference {
    Auto,
    WebRtc,
    WebSocket,
}

/// Closed reachability classes reported by adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteReachabilityClass {
/// Durable lifecycle for a TURN replacement pair. Transport adapter states
/// cannot invent a fourth durable lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableLifecycle {
    /// The sole current generation carrying application work.
    Current,
    /// A pending replacement that may authorize/allocate/negotiate/prove
    /// but carries no application operation.
    ReplacementPending,
    /// A draining predecessor handling only already-assigned
    /// replay/ACK/control and ledger-reserved work.
    Draining,
}

// ─────────────────────────────────────────────────────────────────────────
// Reachability classes (closed taxonomy — adapters map platform errors)
// ─────────────────────────────────────────────────────────────────────────

/// The exact closed reachability taxonomy. Adapters map platform errors to
/// these classes; the orchestrator never branches on raw strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityClass {
    IceNoCandidatePair,
    IceTimeout,
    NetworkUnreachable,
    TurnUnreachable,
}

/// The complete closed-reason taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTransportCloseReason {
    IceNoCandidatePair,
    IceTimeout,
    NetworkUnreachable,
    TurnUnreachable,
    AuthFailure,
    ProofFailure,
    CertificateFailure,
    VersionFailure,
    IntegrityFailure,
    RevocationFailure,
    PolicyFailure,
    QuotaFailure,
    ConsentFailure,
    LocalClose,
    PeerClose,
    Superseded,
}

impl RemoteTransportCloseReason {
    /// Is a close reason terminal (security/policy/consent) — never fallback?
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::AuthFailure
                | Self::ProofFailure
                | Self::CertificateFailure
                | Self::VersionFailure
                | Self::IntegrityFailure
                | Self::RevocationFailure
                | Self::PolicyFailure
                | Self::QuotaFailure
                | Self::ConsentFailure
        )
    }

    /// Is a close reason a reachability failure — may fallback under auto?
    pub fn is_reachability(self) -> bool {
    /// Transient degraded state — not a fallback trigger until three
    /// consecutive 5-second liveness probes fail.
    IceDisconnected,
}

/// Whether a reachability class is a closed fallback trigger or a
/// non-fallback degraded/terminal class.
impl ReachabilityClass {
    /// Returns `true` if this class is a closed reachability fallback
    /// trigger (as opposed to a degraded or terminal failure).
    pub fn is_closed_fallback_trigger(self) -> bool {
        matches!(
            self,
            Self::IceNoCandidatePair
                | Self::IceTimeout
                | Self::NetworkUnreachable
                | Self::TurnUnreachable
        )
    }
}

/// The exact named continuity reasons that permit a second authorized kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteSecondChildReason {
// ─────────────────────────────────────────────────────────────────────────
// Health tier
// ─────────────────────────────────────────────────────────────────────────

/// Health tier used for deterministic routing among current children.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthTier {
    Healthy,
    Degraded,
    Failed,
}

// ─────────────────────────────────────────────────────────────────────────
// Routing class
// ─────────────────────────────────────────────────────────────────────────

/// Operation routing class for deterministic transport selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingClass {
    Control,
    Interactive,
    Bulk,
}

// ─────────────────────────────────────────────────────────────────────────
// Second-child reason
// ─────────────────────────────────────────────────────────────────────────

/// The exact named reasons a second authorized kind may be established once
/// one child is active. Speculative racing is never a legal reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecondChildReason {
    PreferredPathRecovery,
    NetworkHandoff,
    OperatorForce,
    DegradedPathReplacement,
    CredentialRotation,
}

/// Initial-establishment deadline for `auto` (seconds).
pub const REMOTE_AUTO_INITIAL_DEADLINE_SECONDS: u64 = 10;
/// Allowed policy range minimum (inclusive).
pub const REMOTE_AUTO_INITIAL_DEADLINE_MIN_SECONDS: u64 = 3;
/// Allowed policy range maximum (inclusive).
pub const REMOTE_AUTO_INITIAL_DEADLINE_MAX_SECONDS: u64 = 30;
/// WebRTC liveness probe interval in seconds.
pub const REMOTE_WEBRTC_PROBE_INTERVAL_SECONDS: u64 = 5;
/// `ice_disconnected` maps to `network_unreachable` after this many failed probes.
pub const REMOTE_WEBRTC_DISCONNECTED_FAIL_PROBES: u32 = 3;
/// WebRTC health: healthy after this many consecutive successes.
pub const REMOTE_WEBRTC_HEALTHY_SUCCESS_PROBES: u32 = 2;
/// WebRTC health: degraded after this many consecutive misses.
pub const REMOTE_WEBRTC_DEGRADED_MISS_PROBES: u32 = 3;
/// WebRTC health: failed after this many consecutive misses.
pub const REMOTE_WEBRTC_FAILED_MISS_PROBES: u32 = 6;
/// WebRTC health: degraded buffer threshold (4 MiB).
pub const REMOTE_WEBRTC_DEGRADED_BUFFER_BYTES: u64 = 4 * 1024 * 1024;
/// WebRTC health: degraded buffer sustained over this many probes.
pub const REMOTE_WEBRTC_DEGRADED_BUFFER_PROBES: u32 = 2;
/// WebSocket health: degraded oldest unacked age (seconds).
pub const REMOTE_WEBSOCKET_DEGRADED_OLDEST_UNACKED_SECONDS: u64 = 3;
/// WebSocket health: degraded buffer threshold (4 MiB).
pub const REMOTE_WEBSOCKET_DEGRADED_BUFFER_BYTES: u64 = 4 * 1024 * 1024;
/// WebSocket health: failed at the Nth retransmission.
pub const REMOTE_WEBSOCKET_FAILED_RETRANSMISSION: u32 = 3;
/// Health recovery consecutive healthy intervals.
pub const REMOTE_HEALTH_RECOVERY_INTERVALS: u32 = 2;
/// Per-kind retry budget: initial + one retry.
pub const REMOTE_MAX_RETRIES_PER_KIND: u32 = 1;
/// Injected exponential retry delay (ms).
pub const REMOTE_RETRY_DELAY_MS: u64 = 1000;
/// TURN draining max duration (seconds).
pub const REMOTE_TURN_DRAIN_MAX_SECONDS: u64 = 30;

/// At most one routed-current WebRTC child.
pub const REMOTE_MAX_CURRENT_WEBRTC: usize = 1;
/// At most one routed-current WebSocket child.
pub const REMOTE_MAX_CURRENT_WEBSOCKET: usize = 1;
/// At most two ordinary pending children total.
pub const REMOTE_MAX_PENDING_CHILDREN_TOTAL: usize = 2;
/// At most one ordinary pending child per kind.
pub const REMOTE_MAX_PENDING_CHILDREN_PER_KIND: usize = 1;
/// Physical cap during TURN replacement.
pub const REMOTE_MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT: usize = 3;
/// Physical cap otherwise.
pub const REMOTE_MAX_PHYSICAL_CHILDREN_NORMAL: usize = 2;

/// Compute the physical child cap given whether a TURN replacement is in progress.
pub fn physical_child_cap(turn_replacement_in_progress: bool) -> usize {
    if turn_replacement_in_progress {
        REMOTE_MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT
    } else {
        REMOTE_MAX_PHYSICAL_CHILDREN_NORMAL
    }
}

/// Maximum reservations per train.
pub const REMOTE_RETRY_BUDGET_MAX_PER_TRAIN: usize = 4;
/// Maximum committed reservations in the preceding rolling window.
pub const REMOTE_RETRY_BUDGET_MAX_PER_HOUR: usize = 12;
/// Rolling window length in seconds.
pub const REMOTE_RETRY_BUDGET_WINDOW_SECONDS: u64 = 3600;
/// Random foreground train id byte length.
pub const REMOTE_TRAIN_ID_BYTES: usize = 16;
/// The sole durable budget authority schema name.
pub const REMOTE_RETRY_RESERVATION_SCHEMA: &str = "RemoteTransportRetryReservation";

/// Typed denial reasons from the budget authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteRetryBudgetDenialReason {
    MaxPerTrainExceeded,
    MaxPerHourExceeded,
    DuplicateChildAttempt,
    DatabaseOutage,
    KindRetryExhausted,
}

/// Reservation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteReservationType {
    Initial,
    Retry,
    Replacement,
}

/// A persisted retry-budget reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTransportRetryReservationV1 {
    pub schema_version: u8,
    pub reservation_id: String,
// ─────────────────────────────────────────────────────────────────────────
// Typed denial taxonomy
// ─────────────────────────────────────────────────────────────────────────

/// Typed denial reasons. The orchestrator returns these instead of silently
/// overriding user force or creating unauthorized children.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportDenial {
    #[error("transport kind not authorized by attempt grant")]
    KindNotAuthorized,
    #[error("transport kind not available in deployment")]
    KindNotAvailable,
    #[error("ip consent does not permit this transport")]
    IpConsentDenied,
    #[error("quota exhausted for this transport")]
    QuotaExhausted,
    #[error("client does not support this transport")]
    ClientCapabilityMissing,
    #[error("user preference forces a disallowed transport")]
    PreferenceDisallowed,
    #[error("policy denies this transport combination")]
    PolicyDenied,
    #[error("retry budget exhausted")]
    RetryBudgetExhausted,
    #[error("database outage denies new children")]
    DatabaseOutage,
    #[error("security failure is terminal and never falls back")]
    SecurityFailure,
    #[error("child cap exceeded")]
    ChildCapExceeded,
}

// ─────────────────────────────────────────────────────────────────────────
// Fixed policy constants
// ─────────────────────────────────────────────────────────────────────────

/// Initial WebRTC establishment deadline before WebSocket fallback starts
/// (for `auto` preference). Server-signed; allowed policy values 3..=30.
pub const INITIAL_DEADLINE_SECS: u64 = 10;

/// Minimum allowed server-signed deadline value (inclusive).
pub const MIN_DEADLINE_SECS: u64 = 3;

/// Maximum allowed server-signed deadline value (inclusive).
pub const MAX_DEADLINE_SECS: u64 = 30;

/// Liveness probe interval for WebRTC health checks.
pub const LIVENESS_PROBE_INTERVAL_SECS: u64 = 5;

/// Number of consecutive liveness probe failures before `ice_disconnected`
/// maps to `network_unreachable`.
pub const ICE_DISCONNECTED_FALLBACK_MISSES: u32 = 3;

/// WebRTC: healthy after this many consecutive successful probes.
pub const WEBRTC_HEALTHY_CONSECUTIVE_SUCCESSES: u32 = 2;

/// WebRTC: degraded after this many consecutive misses.
pub const WEBRTC_DEGRADED_MISSES: u32 = 3;

/// WebRTC: degraded when buffered bytes >= this threshold for two probes.
pub const WEBRTC_DEGRADED_BUFFER_BYTES: u64 = 4 * 1024 * 1024;

/// WebRTC: failed after this many consecutive misses.
pub const WEBRTC_FAILED_MISSES: u32 = 6;

/// WebSocket: degraded when oldest unacked age >= this threshold.
pub const WEBSOCKET_DEGRADED_UNACKED_AGE_SECS: u64 = 3;

/// WebSocket: degraded when buffered bytes >= this threshold.
pub const WEBSOCKET_DEGRADED_BUFFER_BYTES: u64 = 4 * 1024 * 1024;

/// WebSocket: failed at the fallback's Nth retransmission.
pub const WEBSOCKET_FAILED_RETRANSMISSIONS: u32 = 3;

/// Recovery requires this many consecutive healthy probes/ACK intervals.
pub const RECOVERY_CONSECUTIVE_HEALTHY: u32 = 2;

/// Draining timeout: old draining finishes within this many seconds.
pub const DRAINING_TIMEOUT_SECS: u64 = 30;

/// TURN credential renewal lead time (seconds before expiry when
/// replacement_pending starts).
pub const RENEWAL_LEAD_SECS: u64 = 30;

/// Maximum routed-current children per logical attachment (one per kind).
pub const MAX_ROUTED_CURRENT_CHILDREN: usize = 2;

/// Maximum ordinary pending children total.
pub const MAX_ORDINARY_PENDING_CHILDREN: usize = 2;

/// Maximum pending children per kind.
pub const MAX_PENDING_PER_KIND: usize = 1;

/// The sole three-physical-child exception: during TURN replacement, the
/// physical authenticated cap is three (current WebRTC + its one noncurrent
/// mate + optional current WebSocket), otherwise two.
pub const MAX_PHYSICAL_CHILDREN_TURN_EXCEPTION: usize = 3;

/// Maximum reservations per train.
pub const MAX_RESERVATIONS_PER_TRAIN: u32 = 4;

/// Maximum committed reservations in the preceding rolling window.
pub const MAX_COMMITTED_RESERVATIONS_ROLLING: u32 = 12;

/// Rolling window duration in seconds (3,600 = 1 hour).
pub const ROLLING_WINDOW_SECS: u64 = 3_600;

/// Retry delay: injected exponential 1 second, then no further same-kind
/// retry.
pub const RETRY_DELAY_SECS: u64 = 1;

/// Maximum same-kind retries per train (initial establishment plus one
/// fresh retry).
pub const MAX_SAME_KIND_RETRIES: u32 = 1;

/// `trainId` byte length (random 16-byte foreground identifier).
pub const TRAIN_ID_BYTES: usize = 16;

// ─────────────────────────────────────────────────────────────────────────
// Retry reservation (Postgres durable budget authority)
// ─────────────────────────────────────────────────────────────────────────

/// The sole durable budget authority key, keyed by
/// tenant/account/client-device/logical-attachment, train id, transport kind,
/// and child attempt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RemoteTransportRetryReservationKey {
    pub tenant_id: String,
    pub account_id: String,
    pub client_device_id: String,
    pub logical_attachment_id: String,
    pub train_id: String,
    pub transport_kind: RemoteTransportKind,
    pub child_attempt_id: String,
    pub reservation_type: RemoteReservationType,
    pub reserved_at_ms: i64,
    pub expires_at_ms: i64,
    pub terminal_outcome: Option<RemoteReservationTerminalOutcome>,
    pub terminal_at_ms: Option<i64>,
}

/// Terminal outcome of a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteReservationTerminalOutcome {
    Active,
    Cancelled,
    ReservationFailed,
}

/// Outcome of a serializable reservation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteRetryReservationOutcome {
    Reserved(RemoteTransportRetryReservationV1),
    Duplicate(RemoteTransportRetryReservationV1),
    Rejected(RemoteRetryBudgetDenialReason),
}

/// Snapshot of committed reservations for budget enforcement.
#[derive(Debug, Clone, Default)]
pub struct RemoteRetryBudgetSnapshot {
    pub train_reservations: Vec<RemoteTransportRetryReservationV1>,
    pub rolling_window_reservations: Vec<RemoteTransportRetryReservationV1>,
}

/// A reservation request.
#[derive(Debug, Clone)]
pub struct RemoteRetryBudgetRequest {
    pub train_id: String,
    pub transport_kind: RemoteTransportKind,
    pub child_attempt_id: String,
    pub reservation_type: RemoteReservationType,
}

/// Evaluate a reservation request against the durable budget snapshot.
///
/// One serializable transaction idempotently reserves each initial/retry/
/// replacement child, rejects more than four reservations per train or twelve
/// committed reservations in the preceding rolling 3,600 seconds. Exact
/// duplicates by child attempt are idempotent and do not count twice.
pub fn evaluate_retry_budget(
    snapshot: &RemoteRetryBudgetSnapshot,
    request: &RemoteRetryBudgetRequest,
    now_ms: i64,
) -> RemoteRetryReservationOutcome {
    if let Some(matched) = snapshot
        .train_reservations
        .iter()
        .find(|r| r.train_id == request.train_id && r.child_attempt_id == request.child_attempt_id)
    {
        return RemoteRetryReservationOutcome::Duplicate(matched.clone());
    }
    if snapshot.train_reservations.len() >= REMOTE_RETRY_BUDGET_MAX_PER_TRAIN {
        return RemoteRetryReservationOutcome::Rejected(
            RemoteRetryBudgetDenialReason::MaxPerTrainExceeded,
        );
    }
    let window_start_ms = now_ms - (REMOTE_RETRY_BUDGET_WINDOW_SECONDS as i64) * 1000;
    let mut seen = std::collections::HashSet::new();
    let mut rolling_count = 0usize;
    for r in &snapshot.rolling_window_reservations {
        if seen.contains(&r.child_attempt_id) {
            continue;
        }
        let ref_time = r.terminal_at_ms.unwrap_or(r.reserved_at_ms);
        if ref_time >= window_start_ms && ref_time <= now_ms {
            seen.insert(r.child_attempt_id.clone());
            rolling_count += 1;
        }
    }
    if rolling_count >= REMOTE_RETRY_BUDGET_MAX_PER_HOUR {
        return RemoteRetryReservationOutcome::Rejected(
            RemoteRetryBudgetDenialReason::MaxPerHourExceeded,
        );
    }
    let kind_retry_count = snapshot
        .train_reservations
        .iter()
        .filter(|r| r.transport_kind == request.transport_kind)
        .filter(|r| r.reservation_type == RemoteReservationType::Retry)
        .count();
    if request.reservation_type == RemoteReservationType::Retry
        && kind_retry_count >= REMOTE_MAX_RETRIES_PER_KIND as usize
    {
        return RemoteRetryReservationOutcome::Rejected(
            RemoteRetryBudgetDenialReason::KindRetryExhausted,
        );
    }
    let reservation = RemoteTransportRetryReservationV1 {
        schema_version: REMOTE_TRANSPORT_SELECTION_SCHEMA_VERSION,
        reservation_id: format!("res_{}", request.child_attempt_id),
        tenant_id: String::new(),
        account_id: String::new(),
        client_device_id: String::new(),
        logical_attachment_id: String::new(),
        train_id: request.train_id.clone(),
        transport_kind: request.transport_kind,
        child_attempt_id: request.child_attempt_id.clone(),
        reservation_type: request.reservation_type,
        reserved_at_ms: now_ms,
        expires_at_ms: now_ms + (REMOTE_RETRY_BUDGET_WINDOW_SECONDS as i64) * 1000,
        terminal_outcome: None,
        terminal_at_ms: None,
    };
    RemoteRetryReservationOutcome::Reserved(reservation)
}

/// Database outage denies new children/retries.
pub fn retry_budget_outcome_outage() -> RemoteRetryReservationOutcome {
    RemoteRetryReservationOutcome::Rejected(RemoteRetryBudgetDenialReason::DatabaseOutage)
}

/// IP-consent tri-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteIpConsentTriState {
    DirectAllowed,
    RelayOnly,
    Unavailable,
}

/// Participant privacy classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteParticipantPrivacy {
    DirectAllowed,
    TurnRequired,
    RelayOnly,
}

/// Passive client capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteClientCapabilities {
    pub webrtc_supported: bool,
    pub websocket_supported: bool,
}

/// Live quota snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteLiveQuota {
    pub remaining_reservations_this_hour: u32,
    pub remaining_bytes: u64,
    pub remaining_allocation_seconds: u64,
    pub exhausted: bool,
}

/// The full authorization input set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTransportPlanInput {
    pub deployment_webrtc: bool,
    pub deployment_websocket: bool,
    pub service_webrtc: bool,
    pub service_websocket: bool,
    pub tenant_webrtc: bool,
    pub tenant_websocket: bool,
    pub daemon_webrtc: bool,
    pub daemon_websocket: bool,
    pub ip_consent: RemoteIpConsentTriState,
    pub participant_privacy: RemoteParticipantPrivacy,
    pub live_quota: RemoteLiveQuota,
    pub client_capabilities: RemoteClientCapabilities,
    pub user_preference: RemoteUserPreference,
}

/// Typed denial for the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RemoteTransportPlanDenial {
    NoAuthorizedTransport {
        detail: String,
    },
    PreferenceUnavailable {
        preference: RemoteUserPreference,
        detail: String,
    },
    QuotaExhausted {
        detail: String,
    },
    ConsentUnavailable {
        detail: String,
    },
    PrivacyRelayOnlyNoTurn {
        detail: String,
    },
}

/// The authorized plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTransportAuthorizedPlan {
    pub webrtc_authorized: bool,
    pub websocket_authorized: bool,
    pub turn_required: bool,
    pub denial: Option<RemoteTransportPlanDenial>,
}

/// Compute the authorized transport plan from the full input intersection.
pub fn compute_authorized_plan(input: &RemoteTransportPlanInput) -> RemoteTransportAuthorizedPlan {
    if input.live_quota.exhausted {
        return RemoteTransportAuthorizedPlan {
            webrtc_authorized: false,
            websocket_authorized: false,
            turn_required: false,
            denial: Some(RemoteTransportPlanDenial::QuotaExhausted {
                detail: "live quota exhausted".into(),
            }),
        };
    }
    if input.ip_consent == RemoteIpConsentTriState::Unavailable {
        return RemoteTransportAuthorizedPlan {
            webrtc_authorized: false,
            websocket_authorized: false,
            turn_required: false,
            denial: Some(RemoteTransportPlanDenial::ConsentUnavailable {
                detail: "ip consent unavailable".into(),
            }),
        };
    }
    let turn_required = matches!(
        input.participant_privacy,
        RemoteParticipantPrivacy::TurnRequired | RemoteParticipantPrivacy::RelayOnly
    );
    if input.participant_privacy == RemoteParticipantPrivacy::RelayOnly && !turn_required {
        return RemoteTransportAuthorizedPlan {
            webrtc_authorized: false,
            websocket_authorized: false,
            turn_required: false,
            denial: Some(RemoteTransportPlanDenial::PrivacyRelayOnlyNoTurn {
                detail: "relay-only privacy without turn".into(),
            }),
        };
    }
    let webrtc_meet = input.deployment_webrtc
        && input.service_webrtc
        && input.tenant_webrtc
        && input.daemon_webrtc
        && input.client_capabilities.webrtc_supported;
    let websocket_meet = input.deployment_websocket
        && input.service_websocket
        && input.tenant_websocket
        && input.daemon_websocket
        && input.client_capabilities.websocket_supported;
    match input.user_preference {
        RemoteUserPreference::WebRtc => {
            if !webrtc_meet {
                return RemoteTransportAuthorizedPlan {
                    webrtc_authorized: false,
                    websocket_authorized: false,
                    turn_required,
                    denial: Some(RemoteTransportPlanDenial::PreferenceUnavailable {
                        preference: RemoteUserPreference::WebRtc,
                        detail: "webrtc preference but webrtc not authorized".into(),
                    }),
                };
            }
            RemoteTransportAuthorizedPlan {
                webrtc_authorized: true,
                websocket_authorized: false,
                turn_required,
                denial: None,
            }
        }
        RemoteUserPreference::WebSocket => {
            if !websocket_meet {
                return RemoteTransportAuthorizedPlan {
                    webrtc_authorized: false,
                    websocket_authorized: false,
                    turn_required,
                    denial: Some(RemoteTransportPlanDenial::PreferenceUnavailable {
                        preference: RemoteUserPreference::WebSocket,
                        detail: "websocket preference but websocket not authorized".into(),
                    }),
                };
            }
            RemoteTransportAuthorizedPlan {
                webrtc_authorized: false,
                websocket_authorized: true,
                turn_required,
                denial: None,
            }
        }
        RemoteUserPreference::Auto => {
            if !webrtc_meet && !websocket_meet {
                return RemoteTransportAuthorizedPlan {
                    webrtc_authorized: false,
                    websocket_authorized: false,
                    turn_required,
                    denial: Some(RemoteTransportPlanDenial::NoAuthorizedTransport {
                        detail: "no transport authorized".into(),
                    }),
                };
            }
            RemoteTransportAuthorizedPlan {
                webrtc_authorized: webrtc_meet,
                websocket_authorized: websocket_meet,
                turn_required,
                denial: None,
            }
        }
    }
}

/// Validate the auto initial deadline against the allowed policy range.
#[allow(clippy::result_unit_err)]
pub fn validate_auto_deadline_seconds(seconds: u64) -> Result<(), ()> {
    if (REMOTE_AUTO_INITIAL_DEADLINE_MIN_SECONDS..=REMOTE_AUTO_INITIAL_DEADLINE_MAX_SECONDS)
        .contains(&seconds)
    {
        Ok(())
    } else {
        Err(())
    }
}

/// `ice_disconnected` maps to `network_unreachable` after 3 consecutive failed probes.
pub fn ice_disconnected_to_reachability(
    consecutive_failed_probes: u32,
) -> Option<RemoteReachabilityClass> {
    if consecutive_failed_probes >= REMOTE_WEBRTC_DISCONNECTED_FAIL_PROBES {
        Some(RemoteReachabilityClass::NetworkUnreachable)
    } else {
        None
    }
}

/// Computed health grade for a current child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteChildHealth {
    Healthy,
    Degraded,
    Failed,
}

/// A child's rolling health counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RemoteChildHealthCounters {
    pub health: Option<RemoteChildHealth>,
    pub consecutive_healthy: u32,
    pub consecutive_misses: u32,
    pub consecutive_buffer_high: u32,
}

/// Compute the health grade for a WebRTC child from a probe.
pub fn compute_webrtc_health(
    counters: RemoteChildHealthCounters,
    success: bool,
    buffered_bytes: u64,
) -> RemoteChildHealthCounters {
    let buffer_high = buffered_bytes >= REMOTE_WEBRTC_DEGRADED_BUFFER_BYTES;
    let consecutive_healthy = if success {
        counters.consecutive_healthy + 1
    } else {
        0
    };
    let consecutive_misses = if success {
        0
    } else {
        counters.consecutive_misses + 1
    };
    let consecutive_buffer_high = if buffer_high {
        counters.consecutive_buffer_high + 1
    } else {
        0
    };
    if consecutive_misses >= REMOTE_WEBRTC_FAILED_MISS_PROBES {
        return RemoteChildHealthCounters {
            health: Some(RemoteChildHealth::Failed),
            consecutive_healthy: 0,
            consecutive_misses,
            consecutive_buffer_high: 0,
        };
    }
    if consecutive_misses >= REMOTE_WEBRTC_DEGRADED_MISS_PROBES
        || consecutive_buffer_high >= REMOTE_WEBRTC_DEGRADED_BUFFER_PROBES
    {
        return RemoteChildHealthCounters {
            health: Some(RemoteChildHealth::Degraded),
            consecutive_healthy,
            consecutive_misses,
            consecutive_buffer_high,
        };
    }
    if consecutive_healthy >= REMOTE_WEBRTC_HEALTHY_SUCCESS_PROBES {
        return RemoteChildHealthCounters {
            health: Some(RemoteChildHealth::Healthy),
            consecutive_healthy,
            consecutive_misses: 0,
            consecutive_buffer_high,
        };
    }
    RemoteChildHealthCounters {
        health: counters.health,
        consecutive_healthy,
        consecutive_misses,
        consecutive_buffer_high,
    }
}

/// Compute the health grade for a WebSocket child from an ACK sample.
pub fn compute_websocket_health(
    counters: RemoteChildHealthCounters,
    oldest_unacked_age_seconds: u64,
    buffered_bytes: u64,
    retransmission_count: u32,
) -> RemoteChildHealthCounters {
    let is_degraded = oldest_unacked_age_seconds
        >= REMOTE_WEBSOCKET_DEGRADED_OLDEST_UNACKED_SECONDS
        || buffered_bytes >= REMOTE_WEBSOCKET_DEGRADED_BUFFER_BYTES;
    let is_failed = retransmission_count >= REMOTE_WEBSOCKET_FAILED_RETRANSMISSION;
    if is_failed {
        return RemoteChildHealthCounters {
            health: Some(RemoteChildHealth::Failed),
            consecutive_healthy: 0,
            consecutive_misses: 0,
            consecutive_buffer_high: 0,
        };
    }
    if is_degraded {
        return RemoteChildHealthCounters {
            health: Some(RemoteChildHealth::Degraded),
            consecutive_healthy: 0,
            consecutive_misses: 0,
            consecutive_buffer_high: 0,
        };
    }
    let consecutive_healthy = counters.consecutive_healthy + 1;
    if consecutive_healthy >= REMOTE_HEALTH_RECOVERY_INTERVALS {
        return RemoteChildHealthCounters {
            health: Some(RemoteChildHealth::Healthy),
            consecutive_healthy,
            consecutive_misses: 0,
            consecutive_buffer_high: 0,
        };
    }
    RemoteChildHealthCounters {
        health: counters.health,
        consecutive_healthy,
        consecutive_misses: 0,
        consecutive_buffer_high: 0,
    }
}

/// Routing lane (mirror of remote_transport::lane::RemoteLane subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteRouteLane {
    Control,
    Interactive,
    Bulk,
}

/// A routable child view for the deterministic selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRoutableChild {
    pub child_attempt_id: String,
    pub transport_kind: RemoteTransportKind,
    pub transport_epoch: String,
    pub turn_lifecycle: Option<RemoteTurnLifecycle>,
    pub health: RemoteChildHealth,
    pub writable_bytes: u64,
}

/// Select the current child for a delivery on the given lane.
///
/// Routing is deterministic among `current` children only: replacement-pending
/// and draining are never selected.
#[allow(clippy::needless_lifetimes)]
pub fn select_route_child<'a>(
    children: &'a [RemoteRoutableChild],
    lane: RemoteRouteLane,
) -> Option<&'a RemoteRoutableChild> {
    let is_current = |c: &RemoteRoutableChild| {
        !matches!(
            c.turn_lifecycle,
            Some(RemoteTurnLifecycle::ReplacementPending) | Some(RemoteTurnLifecycle::Draining)
        )
    };
    let by_epoch = |a: &&RemoteRoutableChild, b: &&RemoteRoutableChild| {
        a.transport_epoch.cmp(&b.transport_epoch)
    };
    let kind_rank = |k: RemoteTransportKind| match k {
        RemoteTransportKind::WebRtc => 0u8,
        RemoteTransportKind::WebSocket => 1u8,
    };
    match lane {
        RemoteRouteLane::Control => {
            let healthy = children
                .iter()
                .filter(|c| is_current(c) && c.health == RemoteChildHealth::Healthy);
            let degraded = children
                .iter()
                .filter(|c| is_current(c) && c.health == RemoteChildHealth::Degraded);
            healthy
                .min_by(by_epoch)
                .or_else(|| degraded.min_by(by_epoch))
        }
        RemoteRouteLane::Interactive => {
            let healthy_webrtc = children.iter().filter(|c| {
                is_current(c)
                    && c.health == RemoteChildHealth::Healthy
                    && c.transport_kind == RemoteTransportKind::WebRtc
            });
            if let Some(best) = healthy_webrtc.min_by(by_epoch) {
                return Some(best);
            }
            let healthy_ws = children.iter().filter(|c| {
                is_current(c)
                    && c.health == RemoteChildHealth::Healthy
                    && c.transport_kind == RemoteTransportKind::WebSocket
            });
            if let Some(best) = healthy_ws.min_by(by_epoch) {
                return Some(best);
            }
            let degraded = children
                .iter()
                .filter(|c| is_current(c) && c.health == RemoteChildHealth::Degraded);
            degraded.min_by(by_epoch)
        }
        RemoteRouteLane::Bulk => {
            let healthy = children
                .iter()
                .filter(|c| is_current(c) && c.health == RemoteChildHealth::Healthy);
            if let Some(best) = healthy.max_by(|a, b| {
                a.writable_bytes
                    .cmp(&b.writable_bytes)
                    .then_with(|| kind_rank(b.transport_kind).cmp(&kind_rank(a.transport_kind)))
                    .then_with(|| a.transport_epoch.cmp(&b.transport_epoch).reverse())
            }) {
                return Some(best);
            }
            let degraded = children
                .iter()
                .filter(|c| is_current(c) && c.health == RemoteChildHealth::Degraded);
            degraded.min_by(by_epoch)
        }
    pub train_id: [u8; TRAIN_ID_BYTES],
    pub transport_kind: TransportKind,
    pub child_attempt: u64,
}

/// The durable reservation record. One serializable transaction idempotently
/// reserves each initial/retry/replacement child, writes expiry/terminal
/// outcome, and enforces the per-train and rolling-hour caps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTransportRetryReservation {
    pub key: RemoteTransportRetryReservationKey,
    pub reserved_at_ms: i64,
    pub expires_at_ms: i64,
    pub terminal: bool,
    pub terminal_outcome: Option<ReservationOutcome>,
}

/// Terminal outcome written when a child reaches a terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationOutcome {
    Active,
    Cancelled,
    Failed,
    ReservationFailed,
}

// ─────────────────────────────────────────────────────────────────────────
// Validation helpers
// ─────────────────────────────────────────────────────────────────────────

/// Validate that a server-signed deadline is within the allowed 3..=30 range.
pub fn validate_deadline_secs(secs: u64) -> Result<(), TransportDenial> {
    if (MIN_DEADLINE_SECS..=MAX_DEADLINE_SECS).contains(&secs) {
        Ok(())
    } else {
        Err(TransportDenial::PolicyDenied)
    }
}
