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
    #[error("relay is required but TURN is unavailable")]
    RelayRequiredTurnUnavailable,
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
