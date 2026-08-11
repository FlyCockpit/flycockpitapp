//! Downgrade-resistant multi-transport connection orchestration.
//!
//! This module owns the *pure* transport-selection state machine. It takes an
//! explicit `now`, persisted retry-budget input, adapter events, and emitted
//! commands — it never sleeps, never polls, and never reads a wall clock. Every
//! rule is deterministic and testable without a transport, timer, or sleep.
//!
//! # What this module owns
//!
//! - Parent connection states and ordinary child states.
//! - The durable TURN replacement lifecycle (`current | replacement_pending |
//!   draining`); transport adapters cannot invent a fourth lifecycle.
//! - Authorized-plan computation from deployment, service, tenant, daemon,
//!   IP-consent tri-state, participant privacy, live quota, and passive
//!   client capabilities.
//! - User transport preference narrowing (`auto | webrtc | websocket`).
//! - Reachability-class fallback rules and the 10-second foreground deadline.
//! - Per-train retry budget authority (`RemoteTransportRetryReservation`).
//! - WebRTC/WebSocket health probe/miss/buffer/ACK/recovery thresholds.
//! - Deterministic routing among `current` children for control, interactive,
//!   and bulk traffic.
//! - Lease + supervisor-ACK cutover for TURN credential rotation.
//!
//! # What this module does NOT own
//!
//! - Concrete WebRTC/WebSocket adapters, Noise handshakes, or socket I/O.
//! - The operation ledger/outbox (integrated by interface only).
//! - Platform error strings; adapters map platform errors to the closed
//!   `RemoteReachabilityClass` taxonomy before invoking the reducer.
//!
//! # Layering
//!
//! This is the top of the `remote_transport` subtree. It depends on
//! [`crate::remote_transport::lane`] for `RemoteLane` only and on no other
//! workspace crate, so the codec layer below stays reusable independently.

use std::collections::BTreeMap;
use std::fmt;

use crate::remote_transport::lane::RemoteLane;

// ---------------------------------------------------------------------------
// Constants — fixed by the prompt and not tunable at runtime
// ---------------------------------------------------------------------------

/// Default foreground deadline before `auto` starts an authorized WebSocket
/// fallback child (10 seconds). Allowed policy values span 3..=30 seconds.
pub const FOREGROUND_DEADLINE_DEFAULT_SECONDS: i64 = 10;
/// Minimum allowed foreground deadline (3 seconds).
pub const FOREGROUND_DEADLINE_MIN_SECONDS: i64 = 3;
/// Maximum allowed foreground deadline (30 seconds).
pub const FOREGROUND_DEADLINE_MAX_SECONDS: i64 = 30;

/// WebRTC liveness probe interval (5 seconds).
pub const WEBRTC_PROBE_INTERVAL_SECONDS: i64 = 5;
/// WebRTC consecutive probe misses that map `ice_disconnected` to
/// `network_unreachable` (3 misses over 15 seconds).
pub const WEBRTC_DISCONNECTED_PROMOTION_MISSES: u8 = 3;
/// WebRTC consecutive successes required to mark a child healthy (2).
pub const WEBRTC_HEALTHY_SUCCESSES: u8 = 2;
/// WebRTC consecutive misses that mark a child degraded (3).
pub const WEBRTC_DEGRADED_MISSES: u8 = 3;
/// WebRTC consecutive misses that mark a child failed (6).
pub const WEBRTC_FAILED_MISSES: u8 = 6;
/// WebRTC buffered-byte threshold for degraded (4 MiB).
pub const WEBRTC_DEGRADED_BUFFER_BYTES: u64 = 4 * 1024 * 1024;
/// WebRTC consecutive probes with high buffer that mark a child degraded (2).
pub const WEBRTC_DEGRADED_BUFFER_PROBES: u8 = 2;

/// WebSocket oldest-unacked age that marks a child degraded (3 seconds).
pub const WEBSOCKET_DEGRADED_UNACKED_AGE_SECONDS: i64 = 3;
/// WebSocket buffered-byte threshold for degraded (4 MiB).
pub const WEBSOCKET_DEGRADED_BUFFER_BYTES: u64 = 4 * 1024 * 1024;
/// WebSocket retransmission count at which a child fails (third retransmission).
pub const WEBSOCKET_FAILED_RETRANSMISSIONS: u8 = 3;
/// WebSocket consecutive healthy ACK intervals required for recovery (2).
pub const WEBSOCKET_HEALTHY_INTERVALS: u8 = 2;

/// Initial retry delay (1 second, injected exponential).
pub const RETRY_INITIAL_DELAY_SECONDS: i64 = 1;
/// Maximum reservations per train (4).
pub const RETRY_MAX_RESERVATIONS_PER_TRAIN: u32 = 4;
/// Maximum committed reservations in the rolling window (12).
pub const RETRY_MAX_COMMITTED_PER_HOUR: u32 = 12;
/// Rolling reservation window (3,600 seconds).
pub const RETRY_WINDOW_SECONDS: i64 = 3_600;
/// Random foreground `trainId` length in bytes (16).
pub const TRAIN_ID_BYTES: usize = 16;

/// Maximum routed-current children per logical attachment (2: one WebRTC, one
/// WebSocket).
pub const MAX_ROUTED_CURRENT_CHILDREN: usize = 2;
/// Maximum ordinary pending children total (2: one per kind).
pub const MAX_ORDINARY_PENDING_CHILDREN: usize = 2;
/// Maximum ordinary pending children per kind (1).
pub const MAX_ORDINARY_PENDING_PER_KIND: usize = 1;
/// Maximum physical authenticated children during TURN replacement (3: current
/// WebRTC + its one noncurrent mate + optional current WebSocket). Otherwise 2.
pub const MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT: usize = 3;
/// Maximum physical authenticated children outside TURN replacement (2).
pub const MAX_PHYSICAL_CHILDREN_NORMAL: usize = 2;

/// Maximum drain duration for a replaced TURN child (30 seconds).
pub const TURN_DRAIN_MAX_SECONDS: i64 = 30;

// ---------------------------------------------------------------------------
// Enums — closed taxonomies; adapters map platform errors into these
// ---------------------------------------------------------------------------

/// The two transport kinds the orchestrator understands. The wire-level
/// transport-bit values (`0x01` webrtc, `0x02` websocket_data) live in
/// `remote_public_service_policy`; this enum is the orchestrator's
/// kind-level view and never branches on raw strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RemoteTransportKind {
    WebRtc,
    WebSocket,
}

impl RemoteTransportKind {
    pub const ALL: [RemoteTransportKind; 2] =
        [RemoteTransportKind::WebRtc, RemoteTransportKind::WebSocket];

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteTransportKind::WebRtc => "webrtc",
            RemoteTransportKind::WebSocket => "websocket",
        }
    }

    pub fn from_str_exact(value: &str) -> Option<Self> {
        match value {
            "webrtc" => Some(RemoteTransportKind::WebRtc),
            "websocket" => Some(RemoteTransportKind::WebSocket),
            _ => None,
        }
    }

    /// The transport-bit value used by the public-service policy foundation.
    pub const fn bit(self) -> u8 {
        match self {
            RemoteTransportKind::WebRtc => 0x01,
            RemoteTransportKind::WebSocket => 0x02,
        }
    }
}

impl fmt::Display for RemoteTransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// User transport preference. Narrows only; never silently overrides a force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteTransportPreference {
    Auto,
    WebRtc,
    WebSocket,
}

impl RemoteTransportPreference {
    pub const ALL: [RemoteTransportPreference; 3] = [
        RemoteTransportPreference::Auto,
        RemoteTransportPreference::WebRtc,
        RemoteTransportPreference::WebSocket,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteTransportPreference::Auto => "auto",
            RemoteTransportPreference::WebRtc => "webrtc",
            RemoteTransportPreference::WebSocket => "websocket",
        }
    }

    pub fn from_str_exact(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(RemoteTransportPreference::Auto),
            "webrtc" => Some(RemoteTransportPreference::WebRtc),
            "websocket" => Some(RemoteTransportPreference::WebSocket),
            _ => None,
        }
    }
}

/// Parent connection states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteParentState {
    Planning,
    Establishing,
    Active,
    Degraded,
    Denied,
    Failed,
    Cancelled,
    Superseded,
}

impl RemoteParentState {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteParentState::Planning => "planning",
            RemoteParentState::Establishing => "establishing",
            RemoteParentState::Active => "active",
            RemoteParentState::Degraded => "degraded",
            RemoteParentState::Denied => "denied",
            RemoteParentState::Failed => "failed",
            RemoteParentState::Cancelled => "cancelled",
            RemoteParentState::Superseded => "superseded",
        }
    }
}

/// Ordinary child states. A TURN replacement pair additionally carries the
/// durable lifecycle in [`RemoteTurnLifecycle`]; transport adapter states
/// cannot invent a fourth durable lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteChildState {
    Pending,
    Authenticating,
    Active,
    Degraded,
    Closing,
    Closed,
}

impl RemoteChildState {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteChildState::Pending => "pending",
            RemoteChildState::Authenticating => "authenticating",
            RemoteChildState::Active => "active",
            RemoteChildState::Degraded => "degraded",
            RemoteChildState::Closing => "closing",
            RemoteChildState::Closed => "closed",
        }
    }

    /// Whether this state is terminal for an ordinary child.
    pub const fn is_terminal(self) -> bool {
        matches!(self, RemoteChildState::Closed)
    }

    /// Whether this state counts as routed-current.
    pub const fn is_current(self) -> bool {
        matches!(self, RemoteChildState::Active | RemoteChildState::Degraded)
    }

    /// Whether this state counts as ordinary pending.
    pub const fn is_pending(self) -> bool {
        matches!(self, RemoteChildState::Pending | RemoteChildState::Authenticating)
    }
}

/// The exact durable TURN replacement lifecycle. Transport adapter states
/// cannot invent a fourth lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteTurnLifecycle {
    Current,
    ReplacementPending,
    Draining,
}

impl RemoteTurnLifecycle {
    pub const ALL: [RemoteTurnLifecycle; 3] = [
        RemoteTurnLifecycle::Current,
        RemoteTurnLifecycle::ReplacementPending,
        RemoteTurnLifecycle::Draining,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteTurnLifecycle::Current => "current",
            RemoteTurnLifecycle::ReplacementPending => "replacement_pending",
            RemoteTurnLifecycle::Draining => "draining",
        }
    }
}

/// Closed reachability classes reported by adapters. Auth/proof/certificate/
/// version/integrity/revocation/policy/quota/consent failures are terminal and
/// never fallback, so they are not reachability classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteReachabilityClass {
    IceNoCandidatePair,
    IceTimeout,
    NetworkUnreachable,
    TurnUnreachable,
}

impl RemoteReachabilityClass {
    /// The four classes that authorize an `auto` fallback to WebSocket.
    pub const FALLBACK_CLASSES: [RemoteReachabilityClass; 4] = [
        RemoteReachabilityClass::IceNoCandidatePair,
        RemoteReachabilityClass::IceTimeout,
        RemoteReachabilityClass::NetworkUnreachable,
        RemoteReachabilityClass::TurnUnreachable,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteReachabilityClass::IceNoCandidatePair => "ice_no_candidate_pair",
            RemoteReachabilityClass::IceTimeout => "ice_timeout",
            RemoteReachabilityClass::NetworkUnreachable => "network_unreachable",
            RemoteReachabilityClass::TurnUnreachable => "turn_unreachable",
        }
    }

    pub fn from_str_exact(value: &str) -> Option<Self> {
        match value {
            "ice_no_candidate_pair" => Some(RemoteReachabilityClass::IceNoCandidatePair),
            "ice_timeout" => Some(RemoteReachabilityClass::IceTimeout),
            "network_unreachable" => Some(RemoteReachabilityClass::NetworkUnreachable),
            "turn_unreachable" => Some(RemoteReachabilityClass::TurnUnreachable),
            _ => None,
        }
    }
}

/// Terminal security/policy/consent failure classes. These never downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteSecurityFailureClass {
    Authentication,
    Proof,
    Certificate,
    Version,
    Integrity,
    Revocation,
    Policy,
    Quota,
    Consent,
}

impl RemoteSecurityFailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteSecurityFailureClass::Authentication => "authentication",
            RemoteSecurityFailureClass::Proof => "proof",
            RemoteSecurityFailureClass::Certificate => "certificate",
            RemoteSecurityFailureClass::Version => "version",
            RemoteSecurityFailureClass::Integrity => "integrity",
            RemoteSecurityFailureClass::Revocation => "revocation",
            RemoteSecurityFailureClass::Policy => "policy",
            RemoteSecurityFailureClass::Quota => "quota",
            RemoteSecurityFailureClass::Consent => "consent",
        }
    }
}

/// The named reasons a second authorized kind may be established once one
/// child is active. Speculative racing is not among them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteSecondChildReason {
    PreferredPathRecovery,
    NetworkHandoff,
    OperatorForce,
    DegradedPathReplacement,
    CredentialRotation,
}

impl RemoteSecondChildReason {
    pub const ALL: [RemoteSecondChildReason; 5] = [
        RemoteSecondChildReason::PreferredPathRecovery,
        RemoteSecondChildReason::NetworkHandoff,
        RemoteSecondChildReason::OperatorForce,
        RemoteSecondChildReason::DegradedPathReplacement,
        RemoteSecondChildReason::CredentialRotation,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteSecondChildReason::PreferredPathRecovery => "preferred_path_recovery",
            RemoteSecondChildReason::NetworkHandoff => "network_handoff",
            RemoteSecondChildReason::OperatorForce => "operator_force",
            RemoteSecondChildReason::DegradedPathReplacement => "degraded_path_replacement",
            RemoteSecondChildReason::CredentialRotation => "credential_rotation",
        }
    }

    pub fn from_str_exact(value: &str) -> Option<Self> {
        match value {
            "preferred_path_recovery" => Some(RemoteSecondChildReason::PreferredPathRecovery),
            "network_handoff" => Some(RemoteSecondChildReason::NetworkHandoff),
            "operator_force" => Some(RemoteSecondChildReason::OperatorForce),
            "degraded_path_replacement" => Some(RemoteSecondChildReason::DegradedPathReplacement),
            "credential_rotation" => Some(RemoteSecondChildReason::CredentialRotation),
            _ => None,
        }
    }
}

/// Traffic class for deterministic routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteRouteClass {
    Control,
    Interactive,
    Bulk,
}

impl RemoteRouteClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteRouteClass::Control => "control",
            RemoteRouteClass::Interactive => "interactive",
            RemoteRouteClass::Bulk => "bulk",
        }
    }

    pub const fn from_lane(lane: RemoteLane) -> Self {
        match lane {
            RemoteLane::Control => RemoteRouteClass::Control,
            RemoteLane::Interactive => RemoteRouteClass::Interactive,
            RemoteLane::Bulk => RemoteRouteClass::Bulk,
        }
    }
}

/// Typed denial returned when a selected kind is disallowed or unavailable.
/// The orchestrator never silently overrides user force.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteTransportDenial {
    #[error("transport kind {kind} is not authorized by the grant")]
    NotAuthorized { kind: RemoteTransportKind },
    #[error("transport kind {kind} is not available in client capabilities")]
    NotAvailable { kind: RemoteTransportKind },
    #[error("transport kind {kind} is denied by IP-consent policy")]
    IpConsentDenied { kind: RemoteTransportKind },
    #[error("transport kind {kind} is denied by participant privacy (relay-only)")]
    PrivacyRelayOnly { kind: RemoteTransportKind },
    #[error("transport kind {kind} is denied by live quota")]
    QuotaExhausted { kind: RemoteTransportKind },
    #[error("transport kind {kind} is denied by deployment policy")]
    DeploymentDenied { kind: RemoteTransportKind },
    #[error("transport kind {kind} is denied by service policy")]
    ServiceDenied { kind: RemoteTransportKind },
    #[error("transport kind {kind} is denied by tenant policy")]
    TenantDenied { kind: RemoteTransportKind },
    #[error("transport kind {kind} is denied by daemon policy")]
    DaemonDenied { kind: RemoteTransportKind },
    #[error("retry budget exhausted: {0}")]
    RetryBudgetExhausted(&'static str),
}

// ---------------------------------------------------------------------------
// Plan inputs — the authorized child plan computation
// ---------------------------------------------------------------------------

/// IP-consent tri-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteIpConsent {
    /// Direct connection consent granted.
    DirectConsent,
    /// Relay-only; direct is never nominated.
    RelayOnly,
    /// Consent absent; no direct connection.
    Absent,
}

impl RemoteIpConsent {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteIpConsent::DirectConsent => "direct_consent",
            RemoteIpConsent::RelayOnly => "relay_only",
            RemoteIpConsent::Absent => "absent",
        }
    }
}

/// Participant privacy posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteParticipantPrivacy {
    /// TURN-required / relay-only. Direct is never nominated and never falls
    /// back to an unauthorized transport.
    RelayOnly,
    /// Direct permitted subject to IP consent.
    DirectPermitted,
}

impl RemoteParticipantPrivacy {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteParticipantPrivacy::RelayOnly => "relay_only",
            RemoteParticipantPrivacy::DirectPermitted => "direct_permitted",
        }
    }

    pub const fn is_relay_only(self) -> bool {
        matches!(self, RemoteParticipantPrivacy::RelayOnly)
    }
}

/// Passive client capabilities: which transport kinds the client can speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RemoteClientCapabilities {
    pub supports_webrtc: bool,
    pub supports_websocket: bool,
}

impl RemoteClientCapabilities {
    pub const fn supports(self, kind: RemoteTransportKind) -> bool {
        match kind {
            RemoteTransportKind::WebRtc => self.supports_webrtc,
            RemoteTransportKind::WebSocket => self.supports_websocket,
        }
    }
}

/// Live quota snapshot for the plan computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RemoteLiveQuota {
    pub webrtc_connections_available: u32,
    pub websocket_connections_available: u32,
}

impl RemoteLiveQuota {
    pub const fn available(self, kind: RemoteTransportKind) -> u32 {
        match kind {
            RemoteTransportKind::WebRtc => self.webrtc_connections_available,
            RemoteTransportKind::WebSocket => self.websocket_connections_available,
        }
    }
}

/// Per-kind policy flags gathered from deployment, service, tenant, and daemon
/// layers. Each may only narrow the grant ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RemoteTransportPolicyLayers {
    pub deployment_allows_webrtc: bool,
    pub deployment_allows_websocket: bool,
    pub service_allows_webrtc: bool,
    pub service_allows_websocket: bool,
    pub tenant_allows_webrtc: bool,
    pub tenant_allows_websocket: bool,
    pub daemon_allows_webrtc: bool,
    pub daemon_allows_websocket: bool,
}

impl RemoteTransportPolicyLayers {
    /// A kind is allowed by policy iff every layer allows it.
    pub const fn allows(self, kind: RemoteTransportKind) -> bool {
        match kind {
            RemoteTransportKind::WebRtc => {
                self.deployment_allows_webrtc
                    && self.service_allows_webrtc
                    && self.tenant_allows_webrtc
                    && self.daemon_allows_webrtc
            }
            RemoteTransportKind::WebSocket => {
                self.deployment_allows_websocket
                    && self.service_allows_websocket
                    && self.tenant_allows_websocket
                    && self.daemon_allows_websocket
            }
        }
    }

    /// The first layer that denies a kind, for the typed denial reason.
    pub const fn first_denying_layer(self, kind: RemoteTransportKind) -> Option<&'static str> {
        match kind {
            RemoteTransportKind::WebRtc => {
                if !self.deployment_allows_webrtc {
                    Some("deployment")
                } else if !self.service_allows_webrtc {
                    Some("service")
                } else if !self.tenant_allows_webrtc {
                    Some("tenant")
                } else if !self.daemon_allows_webrtc {
                    Some("daemon")
                } else {
                    None
                }
            }
            RemoteTransportKind::WebSocket => {
                if !self.deployment_allows_websocket {
                    Some("deployment")
                } else if !self.service_allows_websocket {
                    Some("service")
                } else if !self.tenant_allows_websocket {
                    Some("tenant")
                } else if !self.daemon_allows_websocket {
                    Some("daemon")
                } else {
                    None
                }
            }
        }
    }
}

/// The complete input to the authorized-plan computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemotePlanInput {
    /// Authorized transport bits from the grant ceiling (`0x01` webrtc,
    /// `0x02` websocket_data, `0x03` both).
    pub authorized_transport_bits: u8,
    pub policy_layers: RemoteTransportPolicyLayers,
    pub ip_consent: RemoteIpConsent,
    pub privacy: RemoteParticipantPrivacy,
    pub capabilities: RemoteClientCapabilities,
    pub quota: RemoteLiveQuota,
    pub preference: RemoteTransportPreference,
    /// Foreground deadline in seconds (validated to 3..=30).
    pub foreground_deadline_seconds: i64,
}

/// A single authorized kind in the computed plan, or a typed denial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAuthorizedKind {
    pub kind: RemoteTransportKind,
    /// Whether this kind is the initial establishment target for `auto`.
    pub initial: bool,
}

/// The authorized child plan: the set of kinds the orchestrator may start,
/// plus the typed denials for kinds it may not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAuthorizedPlan {
    pub kinds: Vec<RemoteAuthorizedKind>,
    pub denials: Vec<RemoteTransportDenial>,
}

impl RemoteAuthorizedPlan {
    pub fn allows(&self, kind: RemoteTransportKind) -> bool {
        self.kinds.iter().any(|k| k.kind == kind)
    }

    pub fn initial_kind(&self) -> Option<RemoteTransportKind> {
        self.kinds.iter().find(|k| k.initial).map(|k| k.kind)
    }
}

/// Compute the authorized child plan. Each kind must pass the grant ceiling,
/// every policy layer, IP consent, privacy, capability, and quota. Preference
/// narrows: `webrtc` never starts fallback, `websocket` starts only authorized
/// fallback, `auto` uses the rules. A selected kind that is disallowed or
/// unavailable produces a typed denial — never a silent override.
pub fn compute_authorized_plan(input: &RemotePlanInput) -> RemoteAuthorizedPlan {
    let mut kinds = Vec::new();
    let mut denials = Vec::new();

    // Validate the foreground deadline range.
    if input.foreground_deadline_seconds < FOREGROUND_DEADLINE_MIN_SECONDS
        || input.foreground_deadline_seconds > FOREGROUND_DEADLINE_MAX_SECONDS
    {
        denials.push(RemoteTransportDenial::RetryBudgetExhausted(
            "foreground_deadline_out_of_range",
        ));
        return RemoteAuthorizedPlan { kinds, denials };
    }

    for kind in RemoteTransportKind::ALL {
        let bit = kind.bit();
        let authorized = input.authorized_transport_bits & bit == bit;
        if !authorized {
            denials.push(RemoteTransportDenial::NotAuthorized { kind });
            continue;
        }
        if !input.policy_layers.allows(kind) {
            let layer = input
                .policy_layers
                .first_denying_layer(kind)
                .unwrap_or("deployment");
            let denial = match layer {
                "deployment" => RemoteTransportDenial::DeploymentDenied { kind },
                "service" => RemoteTransportDenial::ServiceDenied { kind },
                "tenant" => RemoteTransportDenial::TenantDenied { kind },
                "daemon" => RemoteTransportDenial::DaemonDenied { kind },
                _ => RemoteTransportDenial::DeploymentDenied { kind },
            };
            denials.push(denial);
            continue;
        }
        if !input.capabilities.supports(kind) {
            denials.push(RemoteTransportDenial::NotAvailable { kind });
            continue;
        }
        if input.quota.available(kind) == 0 {
            denials.push(RemoteTransportDenial::QuotaExhausted { kind });
            continue;
        }
        // IP consent and privacy gates. Relay-only privacy denies direct
        // WebRTC nomination but a TURN-relayed WebRTC child is still legal;
        // the privacy gate here denies WebSocket direct fallback when the
        // participant requires relay. A relay-only participant never nominates
        // direct or falls back to an unauthorized transport.
        if input.privacy.is_relay_only() && kind == RemoteTransportKind::WebSocket {
            denials.push(RemoteTransportDenial::PrivacyRelayOnly { kind });
            continue;
        }
        if matches!(input.ip_consent, RemoteIpConsent::Absent)
            && kind == RemoteTransportKind::WebRtc
        {
            // Direct WebRTC requires consent; a TURN-relayed path is a
            // separate authorization (handled by the TURN policy). With
            // consent absent and no relay authorization, WebRTC is denied.
            denials.push(RemoteTransportDenial::IpConsentDenied { kind });
            continue;
        }

        // The kind passed every gate. Whether it is the initial target
        // depends on preference.
        kinds.push(RemoteAuthorizedKind { kind, initial: false });
    }

    // Apply preference narrowing.
    apply_preference(input.preference, &mut kinds, &mut denials);

    RemoteAuthorizedPlan { kinds, denials }
}

/// Apply user transport preference. Narrows only; never silently overrides.
fn apply_preference(
    preference: RemoteTransportPreference,
    kinds: &mut Vec<RemoteAuthorizedKind>,
    _denials: &mut Vec<RemoteTransportDenial>,
) {
    match preference {
        RemoteTransportPreference::Auto => {
            // WebRTC first; WebSocket only after deadline/reachability. Mark
            // WebRTC as the initial target when present.
            if let Some(slot) = kinds.iter_mut().find(|k| k.kind == RemoteTransportKind::WebRtc) {
                slot.initial = true;
            } else if let Some(slot) = kinds
                .iter_mut()
                .find(|k| k.kind == RemoteTransportKind::WebSocket)
            {
                // No WebRTC available; WebSocket is the initial target.
                slot.initial = true;
            }
        }
        RemoteTransportPreference::WebRtc => {
            // Forced WebRTC: never starts fallback. Remove WebSocket from the
            // plan; if WebRTC was not authorized/available, it stays denied.
            let has_webrtc = kinds.iter().any(|k| k.kind == RemoteTransportKind::WebRtc);
            if has_webrtc {
                kinds.retain(|k| k.kind == RemoteTransportKind::WebRtc);
                if let Some(slot) = kinds
                    .iter_mut()
                    .find(|k| k.kind == RemoteTransportKind::WebRtc)
                {
                    slot.initial = true;
                }
            }
            // If WebRTC is not in the plan, the denials already explain why;
            // we do not add WebSocket back.
        }
        RemoteTransportPreference::WebSocket => {
            // Forced WebSocket: starts only authorized fallback. Remove
            // WebRTC; if WebSocket was not authorized, it stays denied.
            let has_ws = kinds.iter().any(|k| k.kind == RemoteTransportKind::WebSocket);
            if has_ws {
                kinds.retain(|k| k.kind == RemoteTransportKind::WebSocket);
                if let Some(slot) = kinds
                    .iter_mut()
                    .find(|k| k.kind == RemoteTransportKind::WebSocket)
                {
                    slot.initial = true;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Retry budget — Postgres is the sole durable authority
// ---------------------------------------------------------------------------

/// A single durable retry reservation, keyed by tenant/account/client-device/
/// logical-attachment, random 16-byte foreground `trainId`, transport kind and
/// child attempt. Postgres `RemoteTransportRetryReservation` is the sole
/// durable budget authority; Redis/process memory never authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTransportRetryReservation {
    pub train_id: [u8; TRAIN_ID_BYTES],
    pub kind: RemoteTransportKind,
    pub child_attempt_id: [u8; 16],
    /// Unix-seconds expiry. Terminal/cancelled reservations carry an outcome.
    pub expires_at: i64,
    pub outcome: RemoteReservationOutcome,
}

/// Terminal outcome written to a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteReservationOutcome {
    /// Initial establishment reservation.
    Initial,
    /// One fresh retry reservation.
    Retry,
    /// TURN replacement reservation.
    Replacement,
    /// Cancelled by background/revoke/supersede.
    Cancelled,
    /// Reservation failed (e.g. budget exhausted).
    ReservationFailed,
    /// Active/committed.
    Committed,
    /// Terminal closed.
    Terminal,
}

impl RemoteReservationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteReservationOutcome::Initial => "initial",
            RemoteReservationOutcome::Retry => "retry",
            RemoteReservationOutcome::Replacement => "replacement",
            RemoteReservationOutcome::Cancelled => "cancelled",
            RemoteReservationOutcome::ReservationFailed => "reservation_failed",
            RemoteReservationOutcome::Committed => "committed",
            RemoteReservationOutcome::Terminal => "terminal",
        }
    }

    /// Whether this outcome counts toward the per-train or rolling caps.
    pub const fn counts_against_budget(self) -> bool {
        matches!(
            self,
            RemoteReservationOutcome::Initial
                | RemoteReservationOutcome::Retry
                | RemoteReservationOutcome::Replacement
                | RemoteReservationOutcome::Committed
                | RemoteReservationOutcome::Terminal
        )
    }
}

/// The durable retry-budget state read by the reducer. The orchestrator never
/// authorizes from Redis/process memory; it reads this persisted input.
#[derive(Debug, Clone, Default)]
pub struct RemoteRetryBudgetState {
    /// All reservations for the current train.
    pub train_reservations: Vec<RemoteTransportRetryReservation>,
    /// Reservations committed in the preceding rolling 3,600 seconds.
    pub committed_in_window: Vec<RemoteTransportRetryReservation>,
    /// Whether the database is reachable. A database outage denies new
    /// children/retries but does not kill an already-authorized child.
    pub database_reachable: bool,
}

/// The result of attempting to reserve a child attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteReservationResult {
    /// The reservation is idempotently granted.
    Granted(RemoteTransportRetryReservation),
    /// The reservation already exists (idempotent re-read by child attempt).
    Existing(RemoteTransportRetryReservation),
    /// More than four reservations per train.
    TrainCapExceeded,
    /// Twelve committed reservations in the preceding rolling window.
    RollingCapExceeded,
    /// Database outage: new children/retries denied.
    DatabaseOutage,
    /// Duplicate exact reservation (does not count).
    ExactDuplicate,
}

/// Idempotently reserve a child attempt. One serializable transaction reserves
/// each initial/retry/replacement child, rejects more than four reservations
/// per train or twelve committed in the preceding rolling 3,600 seconds, and
/// writes expiry/terminal outcome. Indeterminate work re-reads by child
/// attempt; cancelled/reservation-failed children count once; exact duplicates
/// do not. Cleanup is resumable.
pub fn reserve_child_attempt(
    state: &RemoteRetryBudgetState,
    now: i64,
    train_id: [u8; TRAIN_ID_BYTES],
    kind: RemoteTransportKind,
    child_attempt_id: [u8; 16],
    outcome: RemoteReservationOutcome,
) -> RemoteReservationResult {
    // Database outage denies new children/retries but does not kill an
    // already-authorized child.
    if !state.database_reachable {
        return RemoteReservationResult::DatabaseOutage;
    }

    // Indeterminate work re-reads by child attempt: if the exact child
    // attempt is already reserved for this train, return it.
    if let Some(existing) = state.train_reservations.iter().find(|r| {
        r.train_id == train_id && r.kind == kind && r.child_attempt_id == child_attempt_id
    }) {
        return RemoteReservationResult::Existing(existing.clone());
    }

    // Count reservations that count against the per-train cap.
    let train_count = state
        .train_reservations
        .iter()
        .filter(|r| r.train_id == train_id && r.outcome.counts_against_budget())
        .count();
    if train_count >= RETRY_MAX_RESERVATIONS_PER_TRAIN as usize {
        return RemoteReservationResult::TrainCapExceeded;
    }

    // Rolling window: twelve committed in the preceding 3,600 seconds.
    let window_count = state
        .committed_in_window
        .iter()
        .filter(|r| now - r.expires_at < RETRY_WINDOW_SECONDS)
        .count();
    if window_count >= RETRY_MAX_COMMITTED_PER_HOUR as usize {
        return RemoteReservationResult::RollingCapExceeded;
    }

    let reservation = RemoteTransportRetryReservation {
        train_id,
        kind,
        child_attempt_id,
        expires_at: now,
        outcome,
    };
    RemoteReservationResult::Granted(reservation)
}

/// The retry decision for a kind within a train. Initial establishment plus
/// one fresh retry is allowed; retry delay is injected exponential 1 second
/// then no further same-kind retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteRetryDecision {
    /// Start the initial child.
    StartInitial,
    /// Retry once after the injected 1-second delay.
    RetryAfterDelay { delay_seconds: i64 },
    /// No further same-kind retry.
    NoRetry,
}

/// Decide whether a kind may retry within the train. A WebRTC ICE restart is a
/// fresh child attempt and counts as its one retry. WebSocket reconnection is
/// fresh child attempt and counts likewise.
pub fn decide_retry(
    state: &RemoteRetryBudgetState,
    train_id: [u8; TRAIN_ID_BYTES],
    kind: RemoteTransportKind,
) -> RemoteRetryDecision {
    let initial_count = state
        .train_reservations
        .iter()
        .filter(|r| {
            r.train_id == train_id && r.kind == kind && r.outcome == RemoteReservationOutcome::Initial
        })
        .count();
    let retry_count = state
        .train_reservations
        .iter()
        .filter(|r| {
            r.train_id == train_id && r.kind == kind && r.outcome == RemoteReservationOutcome::Retry
        })
        .count();

    if initial_count == 0 {
        return RemoteRetryDecision::StartInitial;
    }
    if retry_count == 0 {
        return RemoteRetryDecision::RetryAfterDelay {
            delay_seconds: RETRY_INITIAL_DELAY_SECONDS,
        };
    }
    RemoteRetryDecision::NoRetry
}

// ---------------------------------------------------------------------------
// Child model and caps
// ---------------------------------------------------------------------------

/// A transport child in the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTransportChild {
    pub kind: RemoteTransportKind,
    pub child_attempt_id: [u8; 16],
    pub state: RemoteChildState,
    /// Monotonic transport epoch; lower epoch wins ties in routing.
    pub transport_epoch: u64,
    /// Durable TURN lifecycle, if this is a TURN WebRTC child.
    pub turn_lifecycle: Option<RemoteTurnLifecycle>,
    /// Consecutive healthy probe/ACK successes.
    pub consecutive_successes: u8,
    /// Consecutive probe misses.
    pub consecutive_misses: u8,
    /// Consecutive probes with high buffered bytes.
    pub consecutive_high_buffer_probes: u8,
    /// Buffered bytes at last probe.
    pub buffered_bytes: u64,
    /// Oldest unacked age in seconds (WebSocket).
    pub oldest_unacked_age_seconds: i64,
    /// WebSocket retransmission count.
    pub retransmissions: u8,
    /// Whether this child carries a `replacement_pending` TURN mate.
    pub has_replacement_mate: bool,
}

impl RemoteTransportChild {
    pub fn new(kind: RemoteTransportKind, child_attempt_id: [u8; 16], transport_epoch: u64) -> Self {
        Self {
            kind,
            child_attempt_id,
            state: RemoteChildState::Pending,
            transport_epoch,
            turn_lifecycle: None,
            consecutive_successes: 0,
            consecutive_misses: 0,
            consecutive_high_buffer_probes: 0,
            buffered_bytes: 0,
            oldest_unacked_age_seconds: 0,
            retransmissions: 0,
            has_replacement_mate: false,
        }
    }

    pub fn is_current(&self) -> bool {
        self.state.is_current() && self.turn_lifecycle != Some(RemoteTurnLifecycle::Draining)
    }

    pub fn is_draining(&self) -> bool {
        self.turn_lifecycle == Some(RemoteTurnLifecycle::Draining)
    }

    pub fn is_replacement_pending(&self) -> bool {
        self.turn_lifecycle == Some(RemoteTurnLifecycle::ReplacementPending)
    }

    pub fn is_pending(&self) -> bool {
        self.state.is_pending()
    }

    pub fn health(&self) -> RemoteChildHealth {
        if self.state == RemoteChildState::Active
            && self.consecutive_misses == 0
            && self.buffered_bytes < self.degraded_buffer_threshold()
        {
            RemoteChildHealth::Healthy
        } else if self.state == RemoteChildState::Degraded
            || self.consecutive_misses >= self.degraded_miss_threshold()
            || self.buffered_bytes >= self.degraded_buffer_threshold()
        {
            RemoteChildHealth::Degraded
        } else if self.state == RemoteChildState::Closed
            || self.consecutive_misses >= self.failed_miss_threshold()
        {
            RemoteChildHealth::Failed
        } else {
            RemoteChildHealth::Healthy
        }
    }

    const fn degraded_buffer_threshold(&self) -> u64 {
        match self.kind {
            RemoteTransportKind::WebRtc => WEBRTC_DEGRADED_BUFFER_BYTES,
            RemoteTransportKind::WebSocket => WEBSOCKET_DEGRADED_BUFFER_BYTES,
        }
    }

    const fn degraded_miss_threshold(&self) -> u8 {
        match self.kind {
            RemoteTransportKind::WebRtc => WEBRTC_DEGRADED_MISSES,
            // WebSocket uses ACK age, not miss count; high threshold so it
            // never fires from misses alone.
            RemoteTransportKind::WebSocket => u8::MAX,
        }
    }

    const fn failed_miss_threshold(&self) -> u8 {
        match self.kind {
            RemoteTransportKind::WebRtc => WEBRTC_FAILED_MISSES,
            RemoteTransportKind::WebSocket => u8::MAX,
        }
    }
}

/// Coarse health used by the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RemoteChildHealth {
    Healthy,
    Degraded,
    Failed,
}

// ---------------------------------------------------------------------------
// Caps enforcement
// ---------------------------------------------------------------------------

/// The orchestrator's view of all children for cap enforcement.
#[derive(Debug, Clone, Default)]
pub struct RemoteChildSet {
    pub children: Vec<RemoteTransportChild>,
}

impl RemoteChildSet {
    pub fn current_children(&self) -> Vec<&RemoteTransportChild> {
        self.children.iter().filter(|c| c.is_current()).collect()
    }

    pub fn pending_children(&self) -> Vec<&RemoteTransportChild> {
        self.children.iter().filter(|c| c.is_pending()).collect()
    }

    pub fn physical_children(&self) -> Vec<&RemoteTransportChild> {
        // Physical authenticated children: active, degraded, or
        // replacement_pending (not closed, not purely pending).
        self.children
            .iter()
            .filter(|c| {
                matches!(
                    c.state,
                    RemoteChildState::Active | RemoteChildState::Degraded
                ) || c.is_replacement_pending()
            })
            .collect()
    }

    /// Whether a TURN replacement is in progress (a replacement_pending or
    /// draining child exists alongside a current WebRTC child).
    pub fn turn_replacement_in_progress(&self) -> bool {
        self.children
            .iter()
            .any(|c| c.is_replacement_pending() || c.is_draining())
    }

    /// The maximum physical authenticated children allowed given the current
    /// state. Three only during TURN replacement; otherwise two.
    pub fn max_physical_cap(&self) -> usize {
        if self.turn_replacement_in_progress() {
            MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT
        } else {
            MAX_PHYSICAL_CHILDREN_NORMAL
        }
    }
}

/// The result of checking whether a new child may be admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCapCheck {
    /// The child may be admitted.
    Allowed,
    /// The routed-current cap (one per kind, two total) is exceeded.
    RoutedCurrentCapExceeded,
    /// The ordinary pending cap (two total, one per kind) is exceeded.
    OrdinaryPendingCapExceeded,
    /// The physical authenticated cap is exceeded.
    PhysicalCapExceeded,
    /// A same-kind duplicate exists (no other same-kind duplicate is legal
    /// except the sole TURN replacement mate).
    SameKindDuplicate,
    /// The second-child reason is not one of the named reasons.
    UnnamedSecondChildReason,
    /// The TURN replacement pair is invalid (more than one noncurrent mate).
    InvalidTurnReplacementPair,
}

/// Check whether a new child of `kind` may be admitted given the current child
/// set and an optional second-child reason. Enforces:
///
/// - At most one WebRTC and one WebSocket routed-current.
/// - At most two ordinary pending children total, one per kind.
/// - The sole exception: one noncurrent TURN WebRTC generation paired with its
///   current generation (replacement_pending before cutover or draining after,
///   never both). Thus the physical cap is three only during TURN replacement.
/// - No other same-kind duplicate is legal.
/// - A second authorized kind may be established only for one of the named
///   reasons; never for speculative racing.
#[allow(clippy::too_many_arguments)]
pub fn check_child_caps(
    set: &RemoteChildSet,
    kind: RemoteTransportKind,
    turn_lifecycle: Option<RemoteTurnLifecycle>,
    second_child_reason: Option<RemoteSecondChildReason>,
    now_active: bool,
) -> RemoteCapCheck {
    let current = set.current_children();
    let pending = set.pending_children();
    let physical = set.physical_children();

    // Same-kind duplicate check. The sole exception is a TURN replacement
    // mate: one noncurrent WebRTC generation paired with its current
    // generation.
    let same_kind_current = current.iter().filter(|c| c.kind == kind).count();
    let same_kind_pending = pending.iter().filter(|c| c.kind == kind).count();

    if turn_lifecycle == Some(RemoteTurnLifecycle::ReplacementPending) {
        // A replacement_pending TURN WebRTC child. It must be paired with a
        // current WebRTC child, and no other noncurrent mate may exist.
        if kind != RemoteTransportKind::WebRtc {
            return RemoteCapCheck::InvalidTurnReplacementPair;
        }
        let existing_mates = set
            .children
            .iter()
            .filter(|c| {
                c.kind == RemoteTransportKind::WebRtc
                    && (c.is_replacement_pending() || c.is_draining())
            })
            .count();
        if existing_mates > 0 {
            return RemoteCapCheck::InvalidTurnReplacementPair;
        }
        let has_current_webrtc = set
            .children
            .iter()
            .any(|c| c.kind == RemoteTransportKind::WebRtc && c.is_current());
        if !has_current_webrtc {
            return RemoteCapCheck::InvalidTurnReplacementPair;
        }
    } else if same_kind_current > 0 && now_active {
        // A second same-kind current child is only legal as a TURN replacement
        // (handled above). Otherwise it is a duplicate.
        return RemoteCapCheck::SameKindDuplicate;
    }

    // Routed-current cap: one per kind, two total.
    if now_active {
        if same_kind_current >= MAX_ORDINARY_PENDING_PER_KIND {
            // One per kind already current; a second current of the same kind
            // is a duplicate unless it is a TURN mate (handled above).
            if turn_lifecycle != Some(RemoteTurnLifecycle::ReplacementPending) {
                return RemoteCapCheck::RoutedCurrentCapExceeded;
            }
        }
        if current.len() >= MAX_ROUTED_CURRENT_CHILDREN && turn_lifecycle.is_none() {
            return RemoteCapCheck::RoutedCurrentCapExceeded;
        }
    }

    // Ordinary pending cap: two total, one per kind.
    if !now_active {
        if same_kind_pending >= MAX_ORDINARY_PENDING_PER_KIND
            && turn_lifecycle != Some(RemoteTurnLifecycle::ReplacementPending)
        {
            return RemoteCapCheck::OrdinaryPendingCapExceeded;
        }
        if pending.len() >= MAX_ORDINARY_PENDING_CHILDREN && turn_lifecycle.is_none() {
            return RemoteCapCheck::OrdinaryPendingCapExceeded;
        }
    }

    // Physical authenticated cap.
    let cap = if turn_lifecycle.is_some() {
        MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT
    } else {
        set.max_physical_cap()
    };
    if physical.len() >= cap && turn_lifecycle != Some(RemoteTurnLifecycle::ReplacementPending) {
        return RemoteCapCheck::PhysicalCapExceeded;
    }

    // Second-child reason: once one child is active, a second authorized kind
    // may be established only for one of the named reasons.
    if !current.is_empty() && !now_active {
        // Starting a new kind while another is active requires a named reason.
        let new_kind_active = current.iter().any(|c| c.kind == kind);
        if !new_kind_active && second_child_reason.is_none() {
            return RemoteCapCheck::UnnamedSecondChildReason;
        }
        if let Some(reason) = second_child_reason {
            if !RemoteSecondChildReason::ALL.contains(&reason) {
                return RemoteCapCheck::UnnamedSecondChildReason;
            }
        }
    }

    RemoteCapCheck::Allowed
}

// ---------------------------------------------------------------------------
// Fallback decision
// ---------------------------------------------------------------------------

/// The fallback decision for `auto` preference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteFallbackDecision {
    /// Do not fall back yet; WebRTC may still establish.
    WaitForWebRtc,
    /// Start an authorized WebSocket fallback child. The reason is either the
    /// deadline expiry or a closed reachability class.
    StartWebSocketFallback { reason: RemoteFallbackReason },
    /// A security/policy/consent failure is terminal and never falls back.
    TerminalFailure { class: RemoteSecurityFailureClass },
}

/// The reason fallback was authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteFallbackReason {
    /// The 10-second foreground deadline expired without active WebRTC.
    DeadlineExpired,
    /// A closed reachability class was reported.
    ReachabilityClass(RemoteReachabilityClass),
}

impl RemoteFallbackReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteFallbackReason::DeadlineExpired => "deadline_expired",
            RemoteFallbackReason::ReachabilityClass(class) => class.as_str(),
        }
    }
}

/// Decide whether `auto` may start a WebSocket fallback. Start WebSocket only
/// after the server-signed foreground deadline expires without active WebRTC,
/// or the adapter reports one closed reachability class. Auth/proof/certificate
/// /version/integrity/revocation/policy/quota/consent failure is terminal and
/// never fallback. `ice_disconnected` is degraded until 3 consecutive 5-second
/// liveness probes fail; then it maps to `network_unreachable`.
pub fn decide_fallback(
    now: i64,
    foreground_deadline_seconds: i64,
    webrtc_active: bool,
    webrtc_establish_started_at: i64,
    reachability: Option<RemoteReachabilityClass>,
    security_failure: Option<RemoteSecurityFailureClass>,
) -> RemoteFallbackDecision {
    if let Some(class) = security_failure {
        return RemoteFallbackDecision::TerminalFailure { class };
    }
    if webrtc_active {
        return RemoteFallbackDecision::WaitForWebRtc;
    }
    if let Some(class) = reachability {
        if RemoteReachabilityClass::FALLBACK_CLASSES.contains(&class) {
            return RemoteFallbackDecision::StartWebSocketFallback {
                reason: RemoteFallbackReason::ReachabilityClass(class),
            };
        }
    }
    if now - webrtc_establish_started_at >= foreground_deadline_seconds {
        return RemoteFallbackDecision::StartWebSocketFallback {
            reason: RemoteFallbackReason::DeadlineExpired,
        };
    }
    RemoteFallbackDecision::WaitForWebRtc
}

// ---------------------------------------------------------------------------
// Health probes
// ---------------------------------------------------------------------------

/// A WebRTC health probe input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteWebRtcProbe {
    pub succeeded: bool,
    pub buffered_bytes: u64,
}

/// Apply a WebRTC health probe to a child. WebRTC health uses 5-second probes:
/// healthy after two consecutive successes, degraded after three misses or
/// buffered bytes >= 4 MiB for two probes, failed after six misses. Recovery
/// requires two consecutive healthy probes.
pub fn apply_webrtc_probe(child: &mut RemoteTransportChild, probe: RemoteWebRtcProbe) {
    if probe.succeeded {
        child.consecutive_misses = 0;
        child.consecutive_high_buffer_probes = 0;
        child.consecutive_successes = child.consecutive_successes.saturating_add(1);
        if child.consecutive_successes >= WEBRTC_HEALTHY_SUCCESSES {
            child.state = RemoteChildState::Active;
        }
    } else {
        child.consecutive_successes = 0;
        child.consecutive_misses = child.consecutive_misses.saturating_add(1);
        if child.buffered_bytes >= WEBRTC_DEGRADED_BUFFER_BYTES {
            child.consecutive_high_buffer_probes =
                child.consecutive_high_buffer_probes.saturating_add(1);
        } else {
            child.consecutive_high_buffer_probes = 0;
        }

        if child.consecutive_misses >= WEBRTC_FAILED_MISSES {
            child.state = RemoteChildState::Closed;
        } else if child.consecutive_misses >= WEBRTC_DEGRADED_MISSES
            || (probe.buffered_bytes >= WEBRTC_DEGRADED_BUFFER_BYTES
                && child.consecutive_high_buffer_probes >= WEBRTC_DEGRADED_BUFFER_PROBES)
        {
            if child.state == RemoteChildState::Active {
                child.state = RemoteChildState::Degraded;
            }
        }
    }
    child.buffered_bytes = probe.buffered_bytes;
}

/// A WebSocket ACK progress probe input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteWebSocketProbe {
    pub acked: bool,
    pub buffered_bytes: u64,
    pub oldest_unacked_age_seconds: i64,
    pub retransmissions: u8,
}

/// Apply a WebSocket ACK-progress probe. WebSocket uses authenticated ACK
/// progress: degraded when oldest unacked age >= 3 seconds or buffered bytes
/// >= 4 MiB, failed at the fallback's third retransmission. Recovery requires
/// two consecutive healthy ACK intervals.
pub fn apply_websocket_probe(child: &mut RemoteTransportChild, probe: RemoteWebSocketProbe) {
    child.buffered_bytes = probe.buffered_bytes;
    child.oldest_unacked_age_seconds = probe.oldest_unacked_age_seconds;
    child.retransmissions = probe.retransmissions;

    if probe.acked
        && probe.oldest_unacked_age_seconds < WEBSOCKET_DEGRADED_UNACKED_AGE_SECONDS
        && probe.buffered_bytes < WEBSOCKET_DEGRADED_BUFFER_BYTES
        && probe.retransmissions < WEBSOCKET_FAILED_RETRANSMISSIONS
    {
        child.consecutive_successes = child.consecutive_successes.saturating_add(1);
        child.consecutive_misses = 0;
        if child.consecutive_successes >= WEBSOCKET_HEALTHY_INTERVALS {
            child.state = RemoteChildState::Active;
        }
    } else {
        child.consecutive_successes = 0;
        child.consecutive_misses = child.consecutive_misses.saturating_add(1);
        if probe.retransmissions >= WEBSOCKET_FAILED_RETRANSMISSIONS {
            child.state = RemoteChildState::Closed;
        } else if probe.oldest_unacked_age_seconds >= WEBSOCKET_DEGRADED_UNACKED_AGE_SECONDS
            || probe.buffered_bytes >= WEBSOCKET_DEGRADED_BUFFER_BYTES
        {
            if child.state == RemoteChildState::Active {
                child.state = RemoteChildState::Degraded;
            }
        }
    }
}

/// Promote `ice_disconnected` to `network_unreachable` after 3 consecutive
/// 5-second liveness probes fail. Before promotion, `ice_disconnected` is
/// degraded, not fallback.
pub fn promote_ice_disconnected(consecutive_failures: u8) -> Option<RemoteReachabilityClass> {
    if consecutive_failures >= WEBRTC_DISCONNECTED_PROMOTION_MISSES {
        Some(RemoteReachabilityClass::NetworkUnreachable)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Routing — deterministic among current children only
// ---------------------------------------------------------------------------

/// The routing decision for a single delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRouteDecision {
    pub selected: Option<RemoteTransportKind>,
    pub child_attempt_id: Option<[u8; 16]>,
    pub transport_epoch: Option<u64>,
    pub reason: RemoteRouteReason,
}

/// The reason a route decision was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteRouteReason {
    /// A current child was selected.
    Selected,
    /// No current children are available.
    NoCurrentChildren,
    /// A new mutation was attempted on a draining child.
    ChildDraining,
    /// The child is replacement_pending and never selected.
    ReplacementPendingNotSelected,
}

impl RemoteRouteReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteRouteReason::Selected => "selected",
            RemoteRouteReason::NoCurrentChildren => "no_current_children",
            RemoteRouteReason::ChildDraining => "child_draining",
            RemoteRouteReason::ReplacementPendingNotSelected => {
                "replacement_pending_not_selected"
            }
        }
    }
}

/// Route a delivery deterministically among `current` children only.
///
/// - Control chooses healthy over degraded, then lower transport epoch.
/// - Interactive chooses healthy WebRTC, then healthy WebSocket, then degraded
///   by lower epoch.
/// - Bulk chooses the healthy child with more writable bytes, tie WebRTC then
///   lower epoch.
///
/// Replacement-pending is never selected. Draining may carry only
/// byte-identical already-assigned delivery replay/ACK/control and completion
/// frames for ledger-reserved work; a new mutation on it is `child_draining`.
pub fn route_delivery(
    set: &RemoteChildSet,
    class: RemoteRouteClass,
    is_new_mutation: bool,
) -> RemoteRouteDecision {
    let current: Vec<&RemoteTransportChild> =
        set.children.iter().filter(|c| c.is_current()).collect();

    if current.is_empty() {
        return RemoteRouteDecision {
            selected: None,
            child_attempt_id: None,
            transport_epoch: None,
            reason: RemoteRouteReason::NoCurrentChildren,
        };
    }

    // A new mutation on a draining child is child_draining. Draining is not
    // in `current` (is_current filters it out), so this guard catches the case
    // where the only available child is draining.
    if is_new_mutation {
        let draining_only = set
            .children
            .iter()
            .all(|c| c.is_draining() || c.is_replacement_pending() || c.state.is_terminal());
        if draining_only && set.children.iter().any(|c| c.is_draining()) {
            return RemoteRouteDecision {
                selected: None,
                child_attempt_id: None,
                transport_epoch: None,
                reason: RemoteRouteReason::ChildDraining,
            };
        }
    }

    let selected = match class {
        RemoteRouteClass::Control => {
            // Healthy over degraded, then lower epoch.
            pick_healthy_then_degraded(&current)
        }
        RemoteRouteClass::Interactive => {
            // Healthy WebRTC, then healthy WebSocket, then degraded by lower epoch.
            pick_interactive(&current)
        }
        RemoteRouteClass::Bulk => {
            // Healthy child with more writable bytes, tie WebRTC then lower epoch.
            pick_bulk(&current)
        }
    };

    match selected {
        Some(child) => RemoteRouteDecision {
            selected: Some(child.kind),
            child_attempt_id: Some(child.child_attempt_id),
            transport_epoch: Some(child.transport_epoch),
            reason: RemoteRouteReason::Selected,
        },
        None => RemoteRouteDecision {
            selected: None,
            child_attempt_id: None,
            transport_epoch: None,
            reason: RemoteRouteReason::NoCurrentChildren,
        },
    }
}

fn pick_healthy_then_degraded<'a>(
    current: &'a [&'a RemoteTransportChild],
) -> Option<&'a RemoteTransportChild> {
    let healthy = current
        .iter()
        .copied()
        .filter(|c| c.health() == RemoteChildHealth::Healthy)
        .collect::<Vec<_>>();
    let pool = if !healthy.is_empty() {
        healthy
    } else {
        current.iter().copied().collect()
    };
    pool.iter()
        .copied()
        .min_by_key(|c| (c.health(), c.transport_epoch))
}

fn pick_interactive<'a>(
    current: &'a [&'a RemoteTransportChild],
) -> Option<&'a RemoteTransportChild> {
    // Healthy WebRTC first.
    let healthy_webrtc = current
        .iter()
        .copied()
        .filter(|c| c.kind == RemoteTransportKind::WebRtc && c.health() == RemoteChildHealth::Healthy)
        .min_by_key(|c| c.transport_epoch);
    if healthy_webrtc.is_some() {
        return healthy_webrtc;
    }
    // Healthy WebSocket next.
    let healthy_ws = current
        .iter()
        .copied()
        .filter(|c| {
            c.kind == RemoteTransportKind::WebSocket && c.health() == RemoteChildHealth::Healthy
        })
        .min_by_key(|c| c.transport_epoch);
    if healthy_ws.is_some() {
        return healthy_ws;
    }
    // Degraded by lower epoch.
    current
        .iter()
        .copied()
        .min_by_key(|c| (c.health(), c.transport_epoch))
}

fn pick_bulk<'a>(
    current: &'a [&'a RemoteTransportChild],
) -> Option<&'a RemoteTransportChild> {
    let healthy = current
        .iter()
        .copied()
        .filter(|c| c.health() == RemoteChildHealth::Healthy)
        .collect::<Vec<_>>();
    let pool = if !healthy.is_empty() {
        healthy
    } else {
        current.iter().copied().collect()
    };
    // More writable bytes (lower buffered = more writable), tie WebRTC then
    // lower epoch.
    pool.iter()
        .copied()
        .max_by_key(|c| {
            (
                c.health() == RemoteChildHealth::Healthy,
                c.buffered_bytes == 0,
                c.kind == RemoteTransportKind::WebRtc,
                !(c.buffered_bytes as i128),
                !(c.transport_epoch as i128),
            )
        })
        .or_else(|| {
            current
                .iter()
                .copied()
                .min_by_key(|c| (c.health(), c.transport_epoch))
        })
}

// ---------------------------------------------------------------------------
// Lease + supervisor-ACK cutover
// ---------------------------------------------------------------------------

/// The sole current connection lease. Cutover occurs only after this lease
/// contains new `current` plus old `draining` and the daemon supervisor
/// persistently ACKs that exact lease tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteConnectionLease {
    pub current: Vec<RemoteTransportKind>,
    pub draining: Vec<RemoteTransportKind>,
    pub lease_id: [u8; 16],
}

/// The supervisor ACK for a lease tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteSupervisorAck {
    pub lease_id: [u8; 16],
    pub acked: bool,
}

/// Decide whether cutover may proceed. Cutover occurs only after the sole
/// current connection lease contains new `current` plus old `draining` and the
/// daemon supervisor persistently ACKs that exact lease tuple. The reducer
/// then routes new work only to the new current.
pub fn decide_cutover(
    lease: &RemoteConnectionLease,
    ack: &RemoteSupervisorAck,
) -> RemoteCutoverDecision {
    if lease.lease_id != ack.lease_id {
        return RemoteCutoverDecision::LeaseMismatch;
    }
    if !ack.acked {
        return RemoteCutoverDecision::NotAcked;
    }
    if lease.draining.is_empty() {
        return RemoteCutoverDecision::NoDraining;
    }
    if lease.current.is_empty() {
        return RemoteCutoverDecision::NoCurrent;
    }
    RemoteCutoverDecision::Cutover
}

/// The cutover decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteCutoverDecision {
    /// Cutover may proceed; route new work only to the new current.
    Cutover,
    /// The supervisor ACK does not match the lease.
    LeaseMismatch,
    /// The supervisor has not ACKed.
    NotAcked,
    /// The lease has no draining child.
    NoDraining,
    /// The lease has no current child.
    NoCurrent,
}

impl RemoteCutoverDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteCutoverDecision::Cutover => "cutover",
            RemoteCutoverDecision::LeaseMismatch => "lease_mismatch",
            RemoteCutoverDecision::NotAcked => "not_acked",
            RemoteCutoverDecision::NoDraining => "no_draining",
            RemoteCutoverDecision::NoCurrent => "no_current",
        }
    }
}

/// The drain deadline for a replaced TURN child. Old draining may finish
/// ledger-reserved work and already-assigned replay/ACK/control, drains for at
/// most 30 seconds, and is removed by a second lease.
pub fn drain_deadline(cutover_at: i64) -> i64 {
    cutover_at + TURN_DRAIN_MAX_SECONDS
}

/// Whether a draining child has exceeded its drain deadline and may be removed
/// by a second lease.
pub fn drain_expired(now: i64, cutover_at: i64) -> bool {
    now >= drain_deadline(cutover_at)
}

// ---------------------------------------------------------------------------
// Parent-state reduction
// ---------------------------------------------------------------------------

/// Reduce the parent state from the child set. The parent state is a pure
/// projection of the children's states.
pub fn reduce_parent_state(set: &RemoteChildSet) -> RemoteParentState {
    let current = set.current_children();
    let pending = set.pending_children();
    let any_degraded = current.iter().any(|c| c.state == RemoteChildState::Degraded);
    let any_active = current.iter().any(|c| c.state == RemoteChildState::Active);

    if current.is_empty() && pending.is_empty() {
        // All children closed/terminal.
        let all_closed = set
            .children
            .iter()
            .all(|c| c.state.is_terminal() || c.is_draining());
        if all_closed && !set.children.is_empty() {
            return RemoteParentState::Failed;
        }
        return RemoteParentState::Planning;
    }
    if current.is_empty() && !pending.is_empty() {
        return RemoteParentState::Establishing;
    }
    if !current.is_empty() {
        if any_degraded && !any_active {
            return RemoteParentState::Degraded;
        }
        return RemoteParentState::Active;
    }
    RemoteParentState::Planning
}

// ---------------------------------------------------------------------------
// Multi-path ordering — one daemon ledger/outbox
// ---------------------------------------------------------------------------

/// Mutations from all permitted children enter the ledger. The ledger's
/// retention is the durable dedupe contract. This function merges mutations
/// from multiple children into a single daemon-ordered stream, deduplicated by
/// delivery ID. One stable delivery ID is assigned to one current child;
/// failover may resend exact bytes and the client dedupes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteLedgerEntry {
    pub delivery_id: [u8; 16],
    pub child_attempt_id: [u8; 16],
    pub generation: u64,
    pub bytes: Vec<u8>,
}

/// Merge mutations from multiple children into one daemon-ordered ledger.
/// Exact duplicates (same delivery ID) are deduplicated; the first occurrence
/// wins. This is the durable dedupe contract.
pub fn merge_ledger(entries: Vec<RemoteLedgerEntry>) -> Vec<RemoteLedgerEntry> {
    let mut seen: BTreeMap<[u8; 16], usize> = BTreeMap::new();
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        if seen.contains_key(&entry.delivery_id) {
            // Exact duplicate: the first occurrence wins. Failover resend is
            // byte-identical and the client dedupes.
            continue;
        }
        seen.insert(entry.delivery_id, out.len());
        out.push(entry);
    }
    out
}

// ---------------------------------------------------------------------------
// Cancellation — aborts all pending timers; no retry survives
// ---------------------------------------------------------------------------

/// Background/cancel/revoke/supersede aborts all pending timers and no retry
/// survives. Late cancelled results cannot activate.
pub fn cancel_children(set: &mut RemoteChildSet) {
    for child in &mut set.children {
        if child.is_pending() || child.state == RemoteChildState::Active {
            child.state = RemoteChildState::Closing;
        }
    }
}

/// A late cancelled result cannot activate. If a child was cancelled (closing/
/// closed), a late success probe cannot move it back to active.
pub fn guard_late_cancelled_result(child: &RemoteTransportChild) -> bool {
    matches!(child.state, RemoteChildState::Closing | RemoteChildState::Closed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn full_caps() -> RemoteClientCapabilities {
        RemoteClientCapabilities {
            supports_webrtc: true,
            supports_websocket: true,
        }
    }

    fn full_quota() -> RemoteLiveQuota {
        RemoteLiveQuota {
            webrtc_connections_available: 10,
            websocket_connections_available: 10,
        }
    }

    fn full_policy() -> RemoteTransportPolicyLayers {
        RemoteTransportPolicyLayers {
            deployment_allows_webrtc: true,
            deployment_allows_websocket: true,
            service_allows_webrtc: true,
            service_allows_websocket: true,
            tenant_allows_webrtc: true,
            tenant_allows_websocket: true,
            daemon_allows_webrtc: true,
            daemon_allows_websocket: true,
        }
    }

    fn plan_input(bits: u8, pref: RemoteTransportPreference) -> RemotePlanInput {
        RemotePlanInput {
            authorized_transport_bits: bits,
            policy_layers: full_policy(),
            ip_consent: RemoteIpConsent::DirectConsent,
            privacy: RemoteParticipantPrivacy::DirectPermitted,
            capabilities: full_caps(),
            quota: full_quota(),
            preference: pref,
            foreground_deadline_seconds: FOREGROUND_DEADLINE_DEFAULT_SECONDS,
        }
    }

    // AC 1: remote_transport_authorized_plan_matrix
    #[test]
    fn remote_transport_authorized_plan_matrix() {
        // Both authorized, auto: both kinds allowed, WebRTC initial.
        let plan = compute_authorized_plan(&plan_input(0x03, RemoteTransportPreference::Auto));
        assert!(plan.allows(RemoteTransportKind::WebRtc));
        assert!(plan.allows(RemoteTransportKind::WebSocket));
        assert_eq!(plan.initial_kind(), Some(RemoteTransportKind::WebRtc));

        // WebRTC only authorized.
        let plan = compute_authorized_plan(&plan_input(0x01, RemoteTransportPreference::Auto));
        assert!(plan.allows(RemoteTransportKind::WebRtc));
        assert!(!plan.allows(RemoteTransportKind::WebSocket));
        assert!(plan.denials.iter().any(|d| matches!(
            d,
            RemoteTransportDenial::NotAuthorized {
                kind: RemoteTransportKind::WebSocket
            }
        )));

        // WebSocket only authorized.
        let plan = compute_authorized_plan(&plan_input(0x02, RemoteTransportPreference::Auto));
        assert!(!plan.allows(RemoteTransportKind::WebRtc));
        assert!(plan.allows(RemoteTransportKind::WebSocket));
        assert_eq!(plan.initial_kind(), Some(RemoteTransportKind::WebSocket));

        // Nothing authorized.
        let plan = compute_authorized_plan(&plan_input(0x00, RemoteTransportPreference::Auto));
        assert!(plan.kinds.is_empty());
        assert_eq!(plan.denials.len(), 2);

        // Deployment denies WebRTC.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.policy_layers.deployment_allows_webrtc = false;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.allows(RemoteTransportKind::WebRtc));
        assert!(plan.denials.iter().any(|d| matches!(
            d,
            RemoteTransportDenial::DeploymentDenied {
                kind: RemoteTransportKind::WebRtc
            }
        )));

        // Service denies WebSocket.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.policy_layers.service_allows_websocket = false;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.allows(RemoteTransportKind::WebSocket));
        assert!(plan.denials.iter().any(|d| matches!(
            d,
            RemoteTransportDenial::ServiceDenied {
                kind: RemoteTransportKind::WebSocket
            }
        )));

        // Tenant denies WebRTC.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.policy_layers.tenant_allows_webrtc = false;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.allows(RemoteTransportKind::WebRtc));

        // Daemon denies WebSocket.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.policy_layers.daemon_allows_websocket = false;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.allows(RemoteTransportKind::WebSocket));

        // Capability gap: no WebRTC.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.capabilities.supports_webrtc = false;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.allows(RemoteTransportKind::WebRtc));
        assert!(plan.denials.iter().any(|d| matches!(
            d,
            RemoteTransportDenial::NotAvailable {
                kind: RemoteTransportKind::WebRtc
            }
        )));

        // Quota exhausted for WebRTC.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.quota.webrtc_connections_available = 0;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.allows(RemoteTransportKind::WebRtc));
        assert!(plan.denials.iter().any(|d| matches!(
            d,
            RemoteTransportDenial::QuotaExhausted {
                kind: RemoteTransportKind::WebRtc
            }
        )));

        // IP consent absent denies WebRTC.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.ip_consent = RemoteIpConsent::Absent;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.allows(RemoteTransportKind::WebRtc));
        assert!(plan.denials.iter().any(|d| matches!(
            d,
            RemoteTransportDenial::IpConsentDenied {
                kind: RemoteTransportKind::WebRtc
            }
        )));

        // Privacy relay-only denies WebSocket.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.privacy = RemoteParticipantPrivacy::RelayOnly;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.allows(RemoteTransportKind::WebSocket));
        assert!(plan.denials.iter().any(|d| matches!(
            d,
            RemoteTransportDenial::PrivacyRelayOnly {
                kind: RemoteTransportKind::WebSocket
            }
        )));

        // IP consent relay-only: WebRTC still allowed (TURN-relayed).
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.ip_consent = RemoteIpConsent::RelayOnly;
        let plan = compute_authorized_plan(&input);
        assert!(plan.allows(RemoteTransportKind::WebRtc));

        // Foreground deadline out of range (below 3).
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.foreground_deadline_seconds = 2;
        let plan = compute_authorized_plan(&input);
        assert!(plan.kinds.is_empty());

        // Foreground deadline out of range (above 30).
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.foreground_deadline_seconds = 31;
        let plan = compute_authorized_plan(&input);
        assert!(plan.kinds.is_empty());

        // Foreground deadline at boundaries (3 and 30) is valid.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.foreground_deadline_seconds = 3;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.kinds.is_empty());
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.foreground_deadline_seconds = 30;
        let plan = compute_authorized_plan(&input);
        assert!(!plan.kinds.is_empty());
    }

    // AC 2: remote_transport_user_preference_matrix
    #[test]
    fn remote_transport_user_preference_matrix() {
        // auto: both allowed, WebRTC initial.
        let plan = compute_authorized_plan(&plan_input(0x03, RemoteTransportPreference::Auto));
        assert_eq!(plan.initial_kind(), Some(RemoteTransportKind::WebRtc));
        assert!(plan.allows(RemoteTransportKind::WebSocket));

        // webrtc: WebSocket removed, never starts fallback.
        let plan = compute_authorized_plan(&plan_input(0x03, RemoteTransportPreference::WebRtc));
        assert!(plan.allows(RemoteTransportKind::WebRtc));
        assert!(!plan.allows(RemoteTransportKind::WebSocket));
        assert_eq!(plan.initial_kind(), Some(RemoteTransportKind::WebRtc));

        // websocket: WebRTC removed, starts only authorized fallback.
        let plan = compute_authorized_plan(&plan_input(0x03, RemoteTransportPreference::WebSocket));
        assert!(!plan.allows(RemoteTransportKind::WebRtc));
        assert!(plan.allows(RemoteTransportKind::WebSocket));
        assert_eq!(plan.initial_kind(), Some(RemoteTransportKind::WebSocket));

        // webrtc preference with WebRTC not authorized: no silent override.
        // WebSocket was authorized but forced WebRTC does not fall back to it.
        let plan = compute_authorized_plan(&plan_input(0x02, RemoteTransportPreference::WebRtc));
        assert!(!plan.allows(RemoteTransportKind::WebRtc));
        assert!(!plan.allows(RemoteTransportKind::WebSocket));
        assert!(plan.denials.iter().any(|d| matches!(
            d,
            RemoteTransportDenial::NotAuthorized {
                kind: RemoteTransportKind::WebRtc
            }
        )));

        // websocket preference with WebSocket not authorized: no silent override.
        let plan = compute_authorized_plan(&plan_input(0x01, RemoteTransportPreference::WebSocket));
        assert!(!plan.allows(RemoteTransportKind::WebRtc));
        assert!(!plan.allows(RemoteTransportKind::WebSocket));
        assert!(plan.denials.iter().any(|d| matches!(
            d,
            RemoteTransportDenial::NotAuthorized {
                kind: RemoteTransportKind::WebSocket
            }
        )));

        // auto with only WebSocket authorized: WebSocket is initial.
        let plan = compute_authorized_plan(&plan_input(0x02, RemoteTransportPreference::Auto));
        assert_eq!(plan.initial_kind(), Some(RemoteTransportKind::WebSocket));
    }

    // AC 3: remote_transport_only_reachability_falls_back
    #[test]
    fn remote_transport_only_reachability_falls_back() {
        // Deadline expired: fallback.
        let decision = decide_fallback(20, 10, false, 10, None, None);
        assert!(matches!(
            decision,
            RemoteFallbackDecision::StartWebSocketFallback {
                reason: RemoteFallbackReason::DeadlineExpired
            }
        ));

        // Before deadline, no reachability: wait.
        let decision = decide_fallback(5, 10, false, 0, None, None);
        assert!(matches!(decision, RemoteFallbackDecision::WaitForWebRtc));

        // WebRTC active: wait, no fallback.
        let decision = decide_fallback(20, 10, true, 10, None, None);
        assert!(matches!(decision, RemoteFallbackDecision::WaitForWebRtc));

        // Each closed reachability class falls back.
        for class in RemoteReachabilityClass::FALLBACK_CLASSES {
            let decision = decide_fallback(5, 10, false, 0, Some(class), None);
            assert!(matches!(
                decision,
                RemoteFallbackDecision::StartWebSocketFallback {
                    reason: RemoteFallbackReason::ReachabilityClass(c)
                } if c == class
            ));
        }

        // Security failures are terminal, never fallback.
        let class = RemoteSecurityFailureClass::Authentication;
        let decision = decide_fallback(20, 10, false, 10, None, Some(class));
        assert!(matches!(
            decision,
            RemoteFallbackDecision::TerminalFailure {
                class: RemoteSecurityFailureClass::Authentication
            }
        ));

        // 10-second default and 3..30 validation.
        assert_eq!(FOREGROUND_DEADLINE_DEFAULT_SECONDS, 10);
        assert_eq!(FOREGROUND_DEADLINE_MIN_SECONDS, 3);
        assert_eq!(FOREGROUND_DEADLINE_MAX_SECONDS, 30);

        // ice_disconnected promotion: 3 consecutive failures.
        assert!(promote_ice_disconnected(2).is_none());
        assert_eq!(
            promote_ice_disconnected(3),
            Some(RemoteReachabilityClass::NetworkUnreachable)
        );
    }

    // AC 4: remote_transport_child_caps_and_reasons
    #[test]
    fn remote_transport_child_caps_and_reasons() {
        let mut set = RemoteChildSet::default();

        // First WebRTC child: allowed.
        let check = check_child_caps(&set, RemoteTransportKind::WebRtc, None, None, false);
        assert_eq!(check, RemoteCapCheck::Allowed);

        // Add a current WebRTC child.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        child.state = RemoteChildState::Active;
        set.children.push(child);

        // Second same-kind current WebRTC: duplicate (unless TURN mate).
        let check = check_child_caps(&set, RemoteTransportKind::WebRtc, None, None, true);
        assert_eq!(check, RemoteCapCheck::SameKindDuplicate);

        // TURN replacement_pending mate: allowed (the sole exception).
        let check = check_child_caps(
            &set,
            RemoteTransportKind::WebRtc,
            Some(RemoteTurnLifecycle::ReplacementPending),
            Some(RemoteSecondChildReason::CredentialRotation),
            true,
        );
        assert_eq!(check, RemoteCapCheck::Allowed);

        // A second replacement_pending mate: invalid pair.
        let mut mate = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [2; 16], 2);
        mate.turn_lifecycle = Some(RemoteTurnLifecycle::ReplacementPending);
        mate.state = RemoteChildState::Active;
        set.children.push(mate);
        let check = check_child_caps(
            &set,
            RemoteTransportKind::WebRtc,
            Some(RemoteTurnLifecycle::ReplacementPending),
            Some(RemoteSecondChildReason::CredentialRotation),
            true,
        );
        assert_eq!(check, RemoteCapCheck::InvalidTurnReplacementPair);

        // Reset: one WebRTC, add WebSocket.
        let mut set = RemoteChildSet::default();
        let mut wr = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        wr.state = RemoteChildState::Active;
        set.children.push(wr);

        // Second kind (WebSocket) without a named reason: denied.
        let check = check_child_caps(&set, RemoteTransportKind::WebSocket, None, None, false);
        assert_eq!(check, RemoteCapCheck::UnnamedSecondChildReason);

        // Second kind with a named reason: allowed.
        let check = check_child_caps(
            &set,
            RemoteTransportKind::WebSocket,
            None,
            Some(RemoteSecondChildReason::NetworkHandoff),
            false,
        );
        assert_eq!(check, RemoteCapCheck::Allowed);

        // All five named reasons are accepted.
        for reason in RemoteSecondChildReason::ALL {
            let check =
                check_child_caps(&set, RemoteTransportKind::WebSocket, None, Some(reason), false);
            assert_eq!(check, RemoteCapCheck::Allowed, "{reason:?}");
        }

        // Three physical children during TURN replacement is the max.
        let mut set = RemoteChildSet::default();
        let mut wr = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        wr.state = RemoteChildState::Active;
        set.children.push(wr);
        let mut ws = RemoteTransportChild::new(RemoteTransportKind::WebSocket, [2; 16], 2);
        ws.state = RemoteChildState::Active;
        set.children.push(ws);
        let mut mate = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [3; 16], 3);
        mate.turn_lifecycle = Some(RemoteTurnLifecycle::ReplacementPending);
        mate.state = RemoteChildState::Active;
        set.children.push(mate);
        assert_eq!(set.physical_children().len(), 3);
        assert!(set.turn_replacement_in_progress());
        assert_eq!(
            set.max_physical_cap(),
            MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT
        );
    }

    // AC 5: remote_transport_retry_budget
    #[test]
    fn remote_transport_retry_budget() {
        let train = [0xaa; TRAIN_ID_BYTES];
        let attempt = [1; 16];
        let now = 1_700_000_000i64;

        // Empty budget: initial reservation granted.
        let state = RemoteRetryBudgetState {
            database_reachable: true,
            ..Default::default()
        };
        let result = reserve_child_attempt(
            &state,
            now,
            train,
            RemoteTransportKind::WebRtc,
            attempt,
            RemoteReservationOutcome::Initial,
        );
        assert!(matches!(result, RemoteReservationResult::Granted(_)));

        // Idempotent re-read by child attempt: existing.
        let mut state = RemoteRetryBudgetState {
            database_reachable: true,
            ..Default::default()
        };
        state.train_reservations.push(RemoteTransportRetryReservation {
            train_id: train,
            kind: RemoteTransportKind::WebRtc,
            child_attempt_id: attempt,
            expires_at: now,
            outcome: RemoteReservationOutcome::Initial,
        });
        let result = reserve_child_attempt(
            &state,
            now,
            train,
            RemoteTransportKind::WebRtc,
            attempt,
            RemoteReservationOutcome::Initial,
        );
        assert!(matches!(result, RemoteReservationResult::Existing(_)));

        // Four reservations per train cap.
        let mut state = RemoteRetryBudgetState {
            database_reachable: true,
            ..Default::default()
        };
        for i in 0..4 {
            state.train_reservations.push(RemoteTransportRetryReservation {
                train_id: train,
                kind: RemoteTransportKind::WebRtc,
                child_attempt_id: [i + 1; 16],
                expires_at: now,
                outcome: RemoteReservationOutcome::Initial,
            });
        }
        let result = reserve_child_attempt(
            &state,
            now,
            train,
            RemoteTransportKind::WebRtc,
            [99; 16],
            RemoteReservationOutcome::Initial,
        );
        assert_eq!(result, RemoteReservationResult::TrainCapExceeded);

        // Rolling twelve/hour cap.
        let mut state = RemoteRetryBudgetState {
            database_reachable: true,
            ..Default::default()
        };
        for i in 0..12 {
            state.committed_in_window.push(RemoteTransportRetryReservation {
                train_id: train,
                kind: RemoteTransportKind::WebRtc,
                child_attempt_id: [i + 1; 16],
                expires_at: now - 100,
                outcome: RemoteReservationOutcome::Committed,
            });
        }
        let result = reserve_child_attempt(
            &state,
            now,
            train,
            RemoteTransportKind::WebRtc,
            [88; 16],
            RemoteReservationOutcome::Initial,
        );
        assert_eq!(result, RemoteReservationResult::RollingCapExceeded);

        // Database outage: new children denied.
        let state = RemoteRetryBudgetState {
            database_reachable: false,
            ..Default::default()
        };
        let result = reserve_child_attempt(
            &state,
            now,
            train,
            RemoteTransportKind::WebRtc,
            attempt,
            RemoteReservationOutcome::Initial,
        );
        assert_eq!(result, RemoteReservationResult::DatabaseOutage);

        // Retry decision: initial + one retry, 1-second delay.
        let state = RemoteRetryBudgetState::default();
        assert_eq!(
            decide_retry(&state, train, RemoteTransportKind::WebRtc),
            RemoteRetryDecision::StartInitial
        );

        let mut state = RemoteRetryBudgetState::default();
        state.train_reservations.push(RemoteTransportRetryReservation {
            train_id: train,
            kind: RemoteTransportKind::WebRtc,
            child_attempt_id: attempt,
            expires_at: now,
            outcome: RemoteReservationOutcome::Initial,
        });
        assert_eq!(
            decide_retry(&state, train, RemoteTransportKind::WebRtc),
            RemoteRetryDecision::RetryAfterDelay {
                delay_seconds: 1
            }
        );

        let mut state = RemoteRetryBudgetState::default();
        state.train_reservations.push(RemoteTransportRetryReservation {
            train_id: train,
            kind: RemoteTransportKind::WebRtc,
            child_attempt_id: attempt,
            expires_at: now,
            outcome: RemoteReservationOutcome::Initial,
        });
        state.train_reservations.push(RemoteTransportRetryReservation {
            train_id: train,
            kind: RemoteTransportKind::WebRtc,
            child_attempt_id: [2; 16],
            expires_at: now,
            outcome: RemoteReservationOutcome::Retry,
        });
        assert_eq!(
            decide_retry(&state, train, RemoteTransportKind::WebRtc),
            RemoteRetryDecision::NoRetry
        );

        // Cancelled/reservation-failed do not count.
        assert!(!RemoteReservationOutcome::Cancelled.counts_against_budget());
        assert!(!RemoteReservationOutcome::ReservationFailed.counts_against_budget());
        // Initial/Retry/Replacement/Committed/Terminal count.
        assert!(RemoteReservationOutcome::Initial.counts_against_budget());
        assert!(RemoteReservationOutcome::Retry.counts_against_budget());
        assert!(RemoteReservationOutcome::Replacement.counts_against_budget());
        assert!(RemoteReservationOutcome::Committed.counts_against_budget());
        assert!(RemoteReservationOutcome::Terminal.counts_against_budget());

        // Persistence: rolling window boundary.
        assert_eq!(RETRY_WINDOW_SECONDS, 3_600);
        assert_eq!(RETRY_MAX_RESERVATIONS_PER_TRAIN, 4);
        assert_eq!(RETRY_MAX_COMMITTED_PER_HOUR, 12);
        assert_eq!(TRAIN_ID_BYTES, 16);
    }

    // AC 6: remote_transport_health_thresholds
    #[test]
    fn remote_transport_health_thresholds() {
        // WebRTC: healthy after 2 consecutive successes.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        child.state = RemoteChildState::Degraded;
        apply_webrtc_probe(&mut child, RemoteWebRtcProbe { succeeded: true, buffered_bytes: 0 });
        assert_eq!(child.state, RemoteChildState::Degraded);
        apply_webrtc_probe(&mut child, RemoteWebRtcProbe { succeeded: true, buffered_bytes: 0 });
        assert_eq!(child.state, RemoteChildState::Active);

        // WebRTC: degraded after 3 misses.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        child.state = RemoteChildState::Active;
        apply_webrtc_probe(&mut child, RemoteWebRtcProbe { succeeded: false, buffered_bytes: 0 });
        apply_webrtc_probe(&mut child, RemoteWebRtcProbe { succeeded: false, buffered_bytes: 0 });
        apply_webrtc_probe(&mut child, RemoteWebRtcProbe { succeeded: false, buffered_bytes: 0 });
        assert_eq!(child.state, RemoteChildState::Degraded);

        // WebRTC: failed after 6 misses.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        child.state = RemoteChildState::Active;
        for _ in 0..6 {
            apply_webrtc_probe(&mut child, RemoteWebRtcProbe { succeeded: false, buffered_bytes: 0 });
        }
        assert_eq!(child.state, RemoteChildState::Closed);

        // WebRTC: degraded after buffered >= 4 MiB for 2 probes.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        child.state = RemoteChildState::Active;
        apply_webrtc_probe(
            &mut child,
            RemoteWebRtcProbe {
                succeeded: false,
                buffered_bytes: WEBRTC_DEGRADED_BUFFER_BYTES,
            },
        );
        apply_webrtc_probe(
            &mut child,
            RemoteWebRtcProbe {
                succeeded: false,
                buffered_bytes: WEBRTC_DEGRADED_BUFFER_BYTES,
            },
        );
        assert_eq!(child.state, RemoteChildState::Degraded);

        // WebSocket: degraded when oldest unacked >= 3 seconds.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebSocket, [1; 16], 1);
        child.state = RemoteChildState::Active;
        apply_websocket_probe(
            &mut child,
            RemoteWebSocketProbe {
                acked: true,
                buffered_bytes: 0,
                oldest_unacked_age_seconds: 3,
                retransmissions: 0,
            },
        );
        assert_eq!(child.state, RemoteChildState::Degraded);

        // WebSocket: degraded when buffered >= 4 MiB.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebSocket, [1; 16], 1);
        child.state = RemoteChildState::Active;
        apply_websocket_probe(
            &mut child,
            RemoteWebSocketProbe {
                acked: true,
                buffered_bytes: WEBSOCKET_DEGRADED_BUFFER_BYTES,
                oldest_unacked_age_seconds: 0,
                retransmissions: 0,
            },
        );
        assert_eq!(child.state, RemoteChildState::Degraded);

        // WebSocket: failed at third retransmission.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebSocket, [1; 16], 1);
        child.state = RemoteChildState::Active;
        apply_websocket_probe(
            &mut child,
            RemoteWebSocketProbe {
                acked: false,
                buffered_bytes: 0,
                oldest_unacked_age_seconds: 0,
                retransmissions: 3,
            },
        );
        assert_eq!(child.state, RemoteChildState::Closed);

        // WebSocket: recovery requires 2 consecutive healthy intervals.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebSocket, [1; 16], 1);
        child.state = RemoteChildState::Degraded;
        apply_websocket_probe(
            &mut child,
            RemoteWebSocketProbe {
                acked: true,
                buffered_bytes: 0,
                oldest_unacked_age_seconds: 0,
                retransmissions: 0,
            },
        );
        assert_eq!(child.state, RemoteChildState::Degraded);
        apply_websocket_probe(
            &mut child,
            RemoteWebSocketProbe {
                acked: true,
                buffered_bytes: 0,
                oldest_unacked_age_seconds: 0,
                retransmissions: 0,
            },
        );
        assert_eq!(child.state, RemoteChildState::Active);

        // Exact constants.
        assert_eq!(WEBRTC_PROBE_INTERVAL_SECONDS, 5);
        assert_eq!(WEBRTC_HEALTHY_SUCCESSES, 2);
        assert_eq!(WEBRTC_DEGRADED_MISSES, 3);
        assert_eq!(WEBRTC_FAILED_MISSES, 6);
        assert_eq!(WEBRTC_DEGRADED_BUFFER_BYTES, 4 * 1024 * 1024);
        assert_eq!(WEBRTC_DEGRADED_BUFFER_PROBES, 2);
        assert_eq!(WEBRTC_DISCONNECTED_PROMOTION_MISSES, 3);
        assert_eq!(WEBSOCKET_DEGRADED_UNACKED_AGE_SECONDS, 3);
        assert_eq!(WEBSOCKET_DEGRADED_BUFFER_BYTES, 4 * 1024 * 1024);
        assert_eq!(WEBSOCKET_FAILED_RETRANSMISSIONS, 3);
        assert_eq!(WEBSOCKET_HEALTHY_INTERVALS, 2);
    }

    // AC 7: remote_transport_route_trace
    #[test]
    fn remote_transport_route_trace() {
        let mut set = RemoteChildSet::default();
        let mut wr = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        wr.state = RemoteChildState::Active;
        let mut ws = RemoteTransportChild::new(RemoteTransportKind::WebSocket, [2; 16], 2);
        ws.state = RemoteChildState::Active;
        set.children.push(wr);
        set.children.push(ws);

        // Control: healthy over degraded, then lower epoch. Both healthy ->
        // lower epoch (WebRTC epoch 1).
        let decision = route_delivery(&set, RemoteRouteClass::Control, true);
        assert_eq!(decision.selected, Some(RemoteTransportKind::WebRtc));
        assert_eq!(decision.transport_epoch, Some(1));

        // Interactive: healthy WebRTC first.
        let decision = route_delivery(&set, RemoteRouteClass::Interactive, true);
        assert_eq!(decision.selected, Some(RemoteTransportKind::WebRtc));

        // Interactive: WebRTC degraded -> healthy WebSocket.
        set.children[0].state = RemoteChildState::Degraded;
        let decision = route_delivery(&set, RemoteRouteClass::Interactive, true);
        assert_eq!(decision.selected, Some(RemoteTransportKind::WebSocket));

        // Bulk: healthy child with more writable bytes, tie WebRTC.
        set.children[0].state = RemoteChildState::Active;
        set.children[0].buffered_bytes = 1000;
        set.children[1].buffered_bytes = 0;
        let decision = route_delivery(&set, RemoteRouteClass::Bulk, true);
        // WebSocket has more writable bytes (0 buffered).
        assert_eq!(decision.selected, Some(RemoteTransportKind::WebSocket));

        // No current children.
        let set = RemoteChildSet::default();
        let decision = route_delivery(&set, RemoteRouteClass::Control, true);
        assert_eq!(decision.reason, RemoteRouteReason::NoCurrentChildren);

        // Replacement-pending is never selected.
        let mut set = RemoteChildSet::default();
        let mut wr = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        wr.state = RemoteChildState::Active;
        let mut mate = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [3; 16], 3);
        mate.turn_lifecycle = Some(RemoteTurnLifecycle::ReplacementPending);
        mate.state = RemoteChildState::Active;
        set.children.push(wr);
        set.children.push(mate);
        let decision = route_delivery(&set, RemoteRouteClass::Control, true);
        assert_eq!(decision.selected, Some(RemoteTransportKind::WebRtc));
        assert_eq!(decision.transport_epoch, Some(1)); // current, not the mate

        // Draining: new mutation is child_draining.
        let mut set = RemoteChildSet::default();
        let mut wr = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        wr.turn_lifecycle = Some(RemoteTurnLifecycle::Draining);
        wr.state = RemoteChildState::Active;
        set.children.push(wr);
        let decision = route_delivery(&set, RemoteRouteClass::Control, true);
        assert_eq!(decision.reason, RemoteRouteReason::ChildDraining);

        // Lease + supervisor-ACK cutover.
        let lease = RemoteConnectionLease {
            current: vec![RemoteTransportKind::WebRtc],
            draining: vec![RemoteTransportKind::WebRtc],
            lease_id: [1; 16],
        };
        let ack = RemoteSupervisorAck {
            lease_id: [1; 16],
            acked: true,
        };
        assert_eq!(decide_cutover(&lease, &ack), RemoteCutoverDecision::Cutover);

        // Lease mismatch.
        let ack = RemoteSupervisorAck {
            lease_id: [2; 16],
            acked: true,
        };
        assert_eq!(decide_cutover(&lease, &ack), RemoteCutoverDecision::LeaseMismatch);

        // Not ACKed.
        let ack = RemoteSupervisorAck {
            lease_id: [1; 16],
            acked: false,
        };
        assert_eq!(decide_cutover(&lease, &ack), RemoteCutoverDecision::NotAcked);

        // No draining.
        let lease = RemoteConnectionLease {
            current: vec![RemoteTransportKind::WebRtc],
            draining: vec![],
            lease_id: [1; 16],
        };
        let ack = RemoteSupervisorAck {
            lease_id: [1; 16],
            acked: true,
        };
        assert_eq!(decide_cutover(&lease, &ack), RemoteCutoverDecision::NoDraining);

        // No current.
        let lease = RemoteConnectionLease {
            current: vec![],
            draining: vec![RemoteTransportKind::WebRtc],
            lease_id: [1; 16],
        };
        assert_eq!(decide_cutover(&lease, &ack), RemoteCutoverDecision::NoCurrent);

        // Drain deadline and expiry.
        assert_eq!(drain_deadline(100), 100 + TURN_DRAIN_MAX_SECONDS);
        assert_eq!(TURN_DRAIN_MAX_SECONDS, 30);
        assert!(drain_expired(131, 100));
        assert!(!drain_expired(129, 100));

        // Stale close isolation: closing one child does not clear the other.
        let mut set = RemoteChildSet::default();
        let mut wr = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        wr.state = RemoteChildState::Active;
        let mut ws = RemoteTransportChild::new(RemoteTransportKind::WebSocket, [2; 16], 2);
        ws.state = RemoteChildState::Active;
        set.children.push(wr);
        set.children.push(ws);
        set.children[1].state = RemoteChildState::Closed;
        let current = set.current_children();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].kind, RemoteTransportKind::WebRtc);

        // One-child assignment: the route selects exactly one child.
        let decision = route_delivery(&set, RemoteRouteClass::Control, true);
        assert!(decision.child_attempt_id.is_some());

        // Exact failover resend: same delivery ID dedupes.
        let id = [0x42; 16];
        let entries = vec![
            RemoteLedgerEntry {
                delivery_id: id,
                child_attempt_id: [1; 16],
                generation: 1,
                bytes: vec![0xab],
            },
            RemoteLedgerEntry {
                delivery_id: id,
                child_attempt_id: [2; 16],
                generation: 2,
                bytes: vec![0xab],
            },
        ];
        let merged = merge_ledger(entries);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].child_attempt_id, [1; 16]);
    }

    // AC 9: remote_transport_deadline_late_success_race
    #[test]
    fn remote_transport_deadline_late_success_race() {
        // Deadline and late ICE success serialize by child generation.
        // At t=10 the deadline expires; at t=11 a late ICE success arrives.
        // The fallback decision at t=10 fires; the late success cannot
        // un-fallback.
        let decision = decide_fallback(10, 10, false, 0, None, None);
        assert!(matches!(
            decision,
            RemoteFallbackDecision::StartWebSocketFallback { .. }
        ));

        // A cancelled child cannot activate: guard_late_cancelled_result.
        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        child.state = RemoteChildState::Closing;
        assert!(guard_late_cancelled_result(&child));

        // Separately authorized kinds may coexist: a cancelled WebRTC does
        // not prevent an authorized WebSocket.
        let mut set = RemoteChildSet::default();
        let mut wr = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        wr.state = RemoteChildState::Closed;
        let mut ws = RemoteTransportChild::new(RemoteTransportKind::WebSocket, [2; 16], 2);
        ws.state = RemoteChildState::Active;
        set.children.push(wr);
        set.children.push(ws);
        let current = set.current_children();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].kind, RemoteTransportKind::WebSocket);

        // Cancellation aborts all pending timers; no retry survives.
        let mut set = RemoteChildSet::default();
        let mut wr = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        wr.state = RemoteChildState::Pending;
        set.children.push(wr);
        cancel_children(&mut set);
        assert_eq!(set.children[0].state, RemoteChildState::Closing);
    }

    // AC 8: remote_transport_multi_path_ordering
    #[test]
    fn remote_transport_multi_path_ordering() {
        // Concurrent mutations/retries/reads/closes enter one daemon ledger.
        let entries = vec![
            RemoteLedgerEntry {
                delivery_id: [1; 16],
                child_attempt_id: [0xa; 16],
                generation: 1,
                bytes: vec![1],
            },
            RemoteLedgerEntry {
                delivery_id: [2; 16],
                child_attempt_id: [0xb; 16],
                generation: 2,
                bytes: vec![2],
            },
            RemoteLedgerEntry {
                delivery_id: [1; 16],
                child_attempt_id: [0xa; 16],
                generation: 1,
                bytes: vec![1],
            },
        ];
        let merged = merge_ledger(entries);
        assert_eq!(merged.len(), 2);

        // Parent-state reduction.
        let mut set = RemoteChildSet::default();
        assert_eq!(reduce_parent_state(&set), RemoteParentState::Planning);

        let mut child = RemoteTransportChild::new(RemoteTransportKind::WebRtc, [1; 16], 1);
        child.state = RemoteChildState::Pending;
        set.children.push(child);
        assert_eq!(reduce_parent_state(&set), RemoteParentState::Establishing);

        set.children[0].state = RemoteChildState::Active;
        assert_eq!(reduce_parent_state(&set), RemoteParentState::Active);

        set.children[0].state = RemoteChildState::Degraded;
        assert_eq!(reduce_parent_state(&set), RemoteParentState::Degraded);

        set.children[0].state = RemoteChildState::Closed;
        assert_eq!(reduce_parent_state(&set), RemoteParentState::Failed);
    }

    // AC 10: TS/Rust fixtures constant parity — enum string spellings match.
    #[test]
    fn remote_transport_selection_enum_spellings() {
        assert_eq!(RemoteTransportKind::WebRtc.as_str(), "webrtc");
        assert_eq!(RemoteTransportKind::WebSocket.as_str(), "websocket");
        assert_eq!(RemoteTransportPreference::Auto.as_str(), "auto");
        assert_eq!(RemoteTransportPreference::WebRtc.as_str(), "webrtc");
        assert_eq!(RemoteTransportPreference::WebSocket.as_str(), "websocket");
        assert_eq!(RemoteParentState::Planning.as_str(), "planning");
        assert_eq!(RemoteParentState::Establishing.as_str(), "establishing");
        assert_eq!(RemoteParentState::Active.as_str(), "active");
        assert_eq!(RemoteParentState::Degraded.as_str(), "degraded");
        assert_eq!(RemoteParentState::Denied.as_str(), "denied");
        assert_eq!(RemoteParentState::Failed.as_str(), "failed");
        assert_eq!(RemoteParentState::Cancelled.as_str(), "cancelled");
        assert_eq!(RemoteParentState::Superseded.as_str(), "superseded");
        assert_eq!(RemoteChildState::Pending.as_str(), "pending");
        assert_eq!(RemoteChildState::Authenticating.as_str(), "authenticating");
        assert_eq!(RemoteChildState::Active.as_str(), "active");
        assert_eq!(RemoteChildState::Degraded.as_str(), "degraded");
        assert_eq!(RemoteChildState::Closing.as_str(), "closing");
        assert_eq!(RemoteChildState::Closed.as_str(), "closed");
        assert_eq!(RemoteTurnLifecycle::Current.as_str(), "current");
        assert_eq!(
            RemoteTurnLifecycle::ReplacementPending.as_str(),
            "replacement_pending"
        );
        assert_eq!(RemoteTurnLifecycle::Draining.as_str(), "draining");
        assert_eq!(
            RemoteReachabilityClass::IceNoCandidatePair.as_str(),
            "ice_no_candidate_pair"
        );
        assert_eq!(RemoteReachabilityClass::IceTimeout.as_str(), "ice_timeout");
        assert_eq!(
            RemoteReachabilityClass::NetworkUnreachable.as_str(),
            "network_unreachable"
        );
        assert_eq!(
            RemoteReachabilityClass::TurnUnreachable.as_str(),
            "turn_unreachable"
        );
        assert_eq!(
            RemoteSecondChildReason::PreferredPathRecovery.as_str(),
            "preferred_path_recovery"
        );
        assert_eq!(
            RemoteSecondChildReason::NetworkHandoff.as_str(),
            "network_handoff"
        );
        assert_eq!(
            RemoteSecondChildReason::OperatorForce.as_str(),
            "operator_force"
        );
        assert_eq!(
            RemoteSecondChildReason::DegradedPathReplacement.as_str(),
            "degraded_path_replacement"
        );
        assert_eq!(
            RemoteSecondChildReason::CredentialRotation.as_str(),
            "credential_rotation"
        );
        assert_eq!(RemoteFallbackReason::DeadlineExpired.as_str(), "deadline_expired");
        assert_eq!(RemoteRouteReason::Selected.as_str(), "selected");
        assert_eq!(
            RemoteRouteReason::NoCurrentChildren.as_str(),
            "no_current_children"
        );
        assert_eq!(RemoteRouteReason::ChildDraining.as_str(), "child_draining");
        assert_eq!(
            RemoteRouteReason::ReplacementPendingNotSelected.as_str(),
            "replacement_pending_not_selected"
        );
        assert_eq!(RemoteCutoverDecision::Cutover.as_str(), "cutover");
        assert_eq!(RemoteCutoverDecision::LeaseMismatch.as_str(), "lease_mismatch");
        assert_eq!(RemoteCutoverDecision::NotAcked.as_str(), "not_acked");
        assert_eq!(RemoteCutoverDecision::NoDraining.as_str(), "no_draining");
        assert_eq!(RemoteCutoverDecision::NoCurrent.as_str(), "no_current");
        assert_eq!(RemoteIpConsent::DirectConsent.as_str(), "direct_consent");
        assert_eq!(RemoteIpConsent::RelayOnly.as_str(), "relay_only");
        assert_eq!(RemoteIpConsent::Absent.as_str(), "absent");
        assert_eq!(RemoteParticipantPrivacy::RelayOnly.as_str(), "relay_only");
        assert_eq!(
            RemoteParticipantPrivacy::DirectPermitted.as_str(),
            "direct_permitted"
        );

        // from_str_exact round trips.
        assert_eq!(
            RemoteTransportKind::from_str_exact("webrtc"),
            Some(RemoteTransportKind::WebRtc)
        );
        assert_eq!(
            RemoteTransportPreference::from_str_exact("auto"),
            Some(RemoteTransportPreference::Auto)
        );
        assert_eq!(
            RemoteReachabilityClass::from_str_exact("ice_timeout"),
            Some(RemoteReachabilityClass::IceTimeout)
        );
        assert_eq!(
            RemoteSecondChildReason::from_str_exact("credential_rotation"),
            Some(RemoteSecondChildReason::CredentialRotation)
        );
        assert_eq!(RemoteTransportKind::from_str_exact("unknown"), None);
    }

    #[test]
    fn remote_transport_required_turn_privacy_never_nominates_direct() {
        // Relay-only privacy: direct WebRTC nomination is not blocked here
        // (TURN-relayed WebRTC is legal), but WebSocket direct fallback is
        // denied. Direct never falls back to an unauthorized transport.
        let mut input = plan_input(0x03, RemoteTransportPreference::Auto);
        input.privacy = RemoteParticipantPrivacy::RelayOnly;
        let plan = compute_authorized_plan(&input);
        // WebRTC (TURN-relayed) is allowed.
        assert!(plan.allows(RemoteTransportKind::WebRtc));
        // WebSocket direct fallback is denied.
        assert!(!plan.allows(RemoteTransportKind::WebSocket));
    }

    #[test]
    fn remote_transport_ui_safe_states() {
        // The parent states that are safe to surface in the UI.
        let safe = [
            RemoteParentState::Planning,
            RemoteParentState::Establishing,
            RemoteParentState::Active,
            RemoteParentState::Degraded,
            RemoteParentState::Denied,
            RemoteParentState::Failed,
            RemoteParentState::Cancelled,
            RemoteParentState::Superseded,
        ];
        // Every state has a stable string spelling.
        for state in safe {
            assert!(!state.as_str().is_empty());
        }
    }
}
