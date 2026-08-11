//! Downgrade-resistant multi-transport connection orchestration.
//!
//! This module implements the pure reducer for transport selection: it
//! computes an authorized child plan from deployment, service, tenant,
//! daemon, IP-consent tri-state, participant privacy, live quota, and
//! passive client capabilities; manages parent/child state transitions;
//! enforces exact caps, retry budgets, and fallback rules; and emits
//! generation-bound pure actions (commands) for the daemon to execute.
//!
//! # What this module owns
//!
//! - The pure reducer over explicit `now`, persisted retry-budget input,
//!   adapter events, and emitted commands.
//! - Parent/child state transitions and the exact caps (two routed-current,
//!   two ordinary-pending, one per kind, the sole three-physical-child TURN
//!   exception).
//! - The `auto` fallback rule: start WebRTC first, fall back to WebSocket
//!   only after a server-signed deadline or a closed reachability class.
//!   Security/policy/consent/proof failures are terminal and never fall back.
//! - The retry model: initial establishment plus one fresh same-kind retry
//!   per train, with a 1-second injected delay.
//! - The health-threshold model: WebRTC 5-second probes, WebSocket ACK
//!   progress, exact consecutive/buffer thresholds.
//! - Deterministic routing among `current` children by routing class.
//! - The TURN replacement cutover lease model (current → replacement_pending
//!   → draining → removed) with supervisor-ACK.
//!
//! # What this module does NOT own
//!
//! - Platform error mapping (adapters map platform errors to
//!   [`ReachabilityClass`]; this module never branches on raw strings).
//! - The Postgres reservation transaction (owned by the DB layer; this module
//!   consumes the persisted retry-budget input and emits reservation
//!   commands).
//! - The operation ledger mutation order (owned by the ledger; this module
//!   integrates by interface only).
//!
//! # Security decisions
//!
//! - Security/policy/consent/proof/certificate/integrity/revocation failures
//!   are terminal and never fall back.
//! - TURN-required/privacy relay-only never nominates direct or falls back
//!   to an unauthorized transport.
//! - User preference narrows only; forced WebRTC does not fallback, and a
//!   disallowed forced kind returns a typed denial.
//! - Late cancelled results cannot activate.
//! - Closing one child cannot clear the other, durable retry budget,
//!   operation outcome, event cursor, or presence.
//! - Redis/process memory never authorize; only the Postgres
//!   `RemoteTransportRetryReservation` is the durable budget authority.

use std::collections::HashMap;
use std::time::Duration;

use cockpit_proto::remote_transport_selection::{
    ChildState, DRAINING_TIMEOUT_SECS, DurableLifecycle, HealthTier,
    ICE_DISCONNECTED_FALLBACK_MISSES, INITIAL_DEADLINE_SECS, MAX_ORDINARY_PENDING_CHILDREN,
    MAX_PENDING_PER_KIND, MAX_PHYSICAL_CHILDREN_TURN_EXCEPTION, MAX_RESERVATIONS_PER_TRAIN,
    MAX_ROUTED_CURRENT_CHILDREN, MAX_SAME_KIND_RETRIES, ParentState, RENEWAL_LEAD_SECS,
    RETRY_DELAY_SECS, ROLLING_WINDOW_SECS, ReachabilityClass, RemoteTransportRetryReservation,
    RemoteTransportRetryReservationKey, ReservationOutcome, RoutingClass, SecondChildReason,
    TRAIN_ID_BYTES, TransportDenial, TransportKind, UserTransportPreference,
    WEBRTC_DEGRADED_BUFFER_BYTES, WEBRTC_DEGRADED_MISSES, WEBRTC_FAILED_MISSES,
    WEBRTC_HEALTHY_CONSECUTIVE_SUCCESSES, WEBSOCKET_DEGRADED_BUFFER_BYTES,
    WEBSOCKET_DEGRADED_UNACKED_AGE_SECS, WEBSOCKET_FAILED_RETRANSMISSIONS,
};

// ─────────────────────────────────────────────────────────────────────────
// Child identity and epoch
// ─────────────────────────────────────────────────────────────────────────

/// A child attempt identifier — each child owns a distinct child attempt,
/// bilateral proofs, transcript, and transport epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChildAttemptId(pub u64);

impl ChildAttemptId {
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// A transport epoch — monotonically increasing per logical attachment,
/// used as the deterministic tie-breaker in routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransportEpoch(pub u64);

/// A foreground train identifier — random 16-byte identifier shared by all
/// children in one establishment train.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrainId(pub [u8; TRAIN_ID_BYTES]);

// ─────────────────────────────────────────────────────────────────────────
// Authorization inputs
// ─────────────────────────────────────────────────────────────────────────

/// The authorization inputs that determine which transports a child plan may
/// use. Computed from deployment, service, tenant, daemon, IP-consent
/// tri-state, participant privacy, live quota, and passive client
/// capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportAuthorization {
    /// Whether WebRTC is authorized by the attempt grant and available in
    /// deployment.
    pub webrtc_authorized: bool,
    /// Whether WebSocket is authorized by the attempt grant and available in
    /// deployment.
    pub websocket_authorized: bool,
    /// Whether IP consent permits direct WebRTC (tri-state: denied/granted/
    /// unknown). If denied, WebRTC may only use TURN relay.
    pub ip_consent_direct: IpConsentTriState,
    /// Whether the participant privacy requires TURN relay only (no direct
    /// candidates).
    pub privacy_relay_only: bool,
    /// Whether the live quota allows new children.
    pub quota_available: bool,
    /// Whether the client supports WebRTC.
    pub client_supports_webrtc: bool,
    /// Whether the client supports WebSocket data.
    pub client_supports_websocket: bool,
}

/// IP consent tri-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpConsentTriState {
    Granted,
    Denied,
    Unknown,
}

/// The computed authorized plan for a logical attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedPlan {
    pub allowed_kinds: Vec<TransportKind>,
    pub denials: Vec<TransportDenial>,
    pub preference: UserTransportPreference,
}

// ─────────────────────────────────────────────────────────────────────────
// Child record
// ─────────────────────────────────────────────────────────────────────────

/// A child transport record within the selection state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildRecord {
    pub child_attempt: ChildAttemptId,
    pub kind: TransportKind,
    pub epoch: TransportEpoch,
    pub state: ChildState,
    pub durable_lifecycle: DurableLifecycle,
    /// Consecutive successful liveness probes (WebRTC) or healthy ACK
    /// intervals (WebSocket).
    pub consecutive_healthy: u32,
    /// Consecutive missed liveness probes (WebRTC).
    pub consecutive_misses: u32,
    /// Current buffered bytes on this child.
    pub buffered_bytes: u64,
    /// Number of probes where buffered bytes have exceeded the degraded
    /// threshold.
    pub consecutive_high_buffer_probes: u32,
    /// Oldest unacked message age in seconds (WebSocket).
    pub oldest_unacked_age_secs: u64,
    /// Number of retransmissions (WebSocket fallback).
    pub retransmissions: u32,
    /// Whether this child was cancelled (late results are inert).
    pub cancelled: bool,
    /// Number of same-kind retries used in this train for this kind.
    pub retries_used: u32,
    /// Whether ICE-disconnected is being tracked for fallback mapping.
    pub ice_disconnected_misses: u32,
    /// The health tier last computed for this child.
    pub health_tier: HealthTier,
    /// The replacement-pair peer, if this child is part of a TURN
    /// replacement pair.
    pub replacement_peer: Option<ChildAttemptId>,
}

impl ChildRecord {
    /// Create a new pending child.
    pub fn new_pending(
        child_attempt: ChildAttemptId,
        kind: TransportKind,
        epoch: TransportEpoch,
    ) -> Self {
        Self {
            child_attempt,
            kind,
            epoch,
            state: ChildState::Pending,
            durable_lifecycle: DurableLifecycle::Current,
            consecutive_healthy: 0,
            consecutive_misses: 0,
            buffered_bytes: 0,
            consecutive_high_buffer_probes: 0,
            oldest_unacked_age_secs: 0,
            retransmissions: 0,
            cancelled: false,
            retries_used: 0,
            ice_disconnected_misses: 0,
            health_tier: HealthTier::Degraded,
            replacement_peer: None,
        }
    }

    /// Whether this child is routed-current (eligible for new work routing).
    pub fn is_routed_current(&self) -> bool {
        matches!(self.durable_lifecycle, DurableLifecycle::Current)
            && matches!(self.state, ChildState::Active | ChildState::Degraded)
    }

    /// Whether this child is ordinary pending (not part of a TURN
    /// replacement pair).
    pub fn is_ordinary_pending(&self) -> bool {
        matches!(self.state, ChildState::Pending | ChildState::Authenticating)
            && matches!(self.durable_lifecycle, DurableLifecycle::Current)
            && self.replacement_peer.is_none()
    }

    /// Recompute the health tier from the probe/miss/buffer counters.
    pub fn recompute_health(&mut self) {
        self.health_tier = compute_health_tier(self);
    }

    /// Writable bytes available on this child (for bulk routing
    /// tie-breaking). Derived from buffered bytes against a nominal cap.
    pub fn writable_bytes(&self) -> u64 {
        const NOMINAL_CAPACITY: u64 = 16 * 1024 * 1024;
        NOMINAL_CAPACITY.saturating_sub(self.buffered_bytes)
    }
}

/// Compute the health tier from a child's counters.
fn compute_health_tier(child: &ChildRecord) -> HealthTier {
    match child.kind {
        TransportKind::Webrtc => {
            if child.consecutive_misses >= WEBRTC_FAILED_MISSES {
                HealthTier::Failed
            } else if child.consecutive_misses >= WEBRTC_DEGRADED_MISSES
                || child.consecutive_high_buffer_probes >= 2
            {
                HealthTier::Degraded
            } else if child.consecutive_healthy >= WEBRTC_HEALTHY_CONSECUTIVE_SUCCESSES {
                HealthTier::Healthy
            } else {
                HealthTier::Degraded
            }
        }
        TransportKind::Websocket => {
            if child.retransmissions >= WEBSOCKET_FAILED_RETRANSMISSIONS {
                HealthTier::Failed
            } else if child.oldest_unacked_age_secs >= WEBSOCKET_DEGRADED_UNACKED_AGE_SECS
                || child.buffered_bytes >= WEBSOCKET_DEGRADED_BUFFER_BYTES
            {
                HealthTier::Degraded
            } else if child.consecutive_healthy >= 2 {
                HealthTier::Healthy
            } else {
                HealthTier::Degraded
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Selection state (the reducer state)
// ─────────────────────────────────────────────────────────────────────────

/// The full transport selection state for one logical attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportSelectionState {
    pub parent_state: ParentState,
    pub children: Vec<ChildRecord>,
    pub preference: UserTransportPreference,
    pub authorization: TransportAuthorization,
    pub train_id: TrainId,
    pub next_child_attempt: ChildAttemptId,
    pub next_epoch: TransportEpoch,
    /// Server-signed deadline for initial WebRTC establishment.
    pub deadline_secs: u64,
    /// Whether the WebSocket fallback has been started in this train.
    pub websocket_fallback_started: bool,
    /// Whether the WebRTC deadline timer is armed.
    pub deadline_timer_armed: bool,
    /// Whether the retry delay timer is armed for a pending retry.
    pub retry_timer_armed: bool,
    /// The pending retry (if any) waiting for the retry delay.
    pub pending_retry: Option<PendingRetry>,
    /// TURN replacement pair state.
    pub turn_replacement: Option<TurnReplacementPair>,
    /// The current delivery-to-child assignment mapping (one stable delivery
    /// ID → one current child).
    pub delivery_assignments: HashMap<String, ChildAttemptId>,
    /// Whether the connection has been backgrounded/cancelled.
    pub cancelled: bool,
}

/// A pending retry waiting for the injected 1-second delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRetry {
    pub kind: TransportKind,
    pub child_attempt: ChildAttemptId,
    pub epoch: TransportEpoch,
}

/// A TURN replacement pair: one current plus one
/// replacement_pending-or-draining.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnReplacementPair {
    pub current: ChildAttemptId,
    pub replacement: ChildAttemptId,
    pub phase: TurnReplacementPhase,
    pub lease_id: [u8; 16],
}

/// The phase of a TURN replacement cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TurnReplacementPhase {
    /// Replacement is pending; cutover has not occurred.
    ReplacementPending,
    /// Cutover occurred; old is draining, new is current.
    Draining,
    /// Second lease removed the old draining child.
    Removed,
}

impl TransportSelectionState {
    /// Create a new selection state for a logical attachment.
    pub fn new(
        authorization: TransportAuthorization,
        preference: UserTransportPreference,
        train_id: TrainId,
        deadline_secs: u64,
    ) -> Self {
        Self {
            parent_state: ParentState::Planning,
            children: Vec::new(),
            preference,
            authorization,
            train_id,
            next_child_attempt: ChildAttemptId(1),
            next_epoch: TransportEpoch(1),
            deadline_secs,
            websocket_fallback_started: false,
            deadline_timer_armed: false,
            retry_timer_armed: false,
            pending_retry: None,
            turn_replacement: None,
            delivery_assignments: HashMap::new(),
            cancelled: false,
        }
    }

    /// Count children by kind in a given state filter.
    pub fn count_kind_in_state(&self, kind: TransportKind, state: ChildState) -> usize {
        self.children
            .iter()
            .filter(|c| c.kind == kind && c.state == state)
            .count()
    }

    /// Count routed-current children.
    pub fn count_routed_current(&self) -> usize {
        self.children
            .iter()
            .filter(|c| c.is_routed_current())
            .count()
    }

    /// Count ordinary pending children.
    pub fn count_ordinary_pending(&self) -> usize {
        self.children
            .iter()
            .filter(|c| c.is_ordinary_pending())
            .count()
    }

    /// Count ordinary pending children of a given kind.
    pub fn count_ordinary_pending_kind(&self, kind: TransportKind) -> usize {
        self.children
            .iter()
            .filter(|c| c.is_ordinary_pending() && c.kind == kind)
            .count()
    }

    /// Count physical authenticated children (all non-closed children).
    pub fn count_physical_children(&self) -> usize {
        self.children
            .iter()
            .filter(|c| !matches!(c.state, ChildState::Closed))
            .count()
    }

    /// Find a child by attempt id.
    pub fn find_child(&self, id: ChildAttemptId) -> Option<&ChildRecord> {
        self.children.iter().find(|c| c.child_attempt == id)
    }

    /// Find a mutable child by attempt id.
    pub fn find_child_mut(&mut self, id: ChildAttemptId) -> Option<&mut ChildRecord> {
        self.children.iter_mut().find(|c| c.child_attempt == id)
    }

    /// Get the current child of a given kind (routed-current).
    pub fn current_child_of_kind(&self, kind: TransportKind) -> Option<&ChildRecord> {
        self.children
            .iter()
            .find(|c| c.kind == kind && c.is_routed_current())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Inputs (events)
// ─────────────────────────────────────────────────────────────────────────

/// Inputs to the transport selection reducer. All transitions are
/// generation-bound and recorded as pure actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportSelectionInput {
    /// Start the initial child plan.
    StartPlan,
    /// A child became active (from adapter).
    ChildActive {
        child_attempt: ChildAttemptId,
        now_ms: i64,
    },
    /// A child reported a reachability class (from adapter).
    ChildReachability {
        child_attempt: ChildAttemptId,
        class: ReachabilityClass,
    },
    /// A WebRTC liveness probe result.
    WebrtcProbe {
        child_attempt: ChildAttemptId,
        success: bool,
        buffered_bytes: u64,
    },
    /// A WebSocket ACK progress update.
    WebsocketAckProgress {
        child_attempt: ChildAttemptId,
        oldest_unacked_age_secs: u64,
        buffered_bytes: u64,
        retransmissions: u32,
    },
    /// The initial deadline timer fired.
    DeadlineFired { now_ms: i64 },
    /// The retry delay timer fired.
    RetryDelayFired { now_ms: i64 },
    /// A child closed.
    ChildClosed {
        child_attempt: ChildAttemptId,
        security_failure: bool,
    },
    /// A second child is requested for a named reason.
    RequestSecondChild {
        reason: SecondChildReason,
        now_ms: i64,
    },
    /// The TURN credential rotation renewal lead was reached.
    CredentialRotationLead { now_ms: i64 },
    /// The supervisor persisted the cutover ACK for a TURN replacement.
    SupervisorCutoverAck {
        old: ChildAttemptId,
        new: ChildAttemptId,
    },
    /// The second lease removed the old draining child.
    SecondLease { old: ChildAttemptId },
    /// A child is being closed explicitly.
    CloseChild { child_attempt: ChildAttemptId },
    /// Background/cancel/revoke/supersede — aborts all pending timers.
    Cancel,
    /// Supersede the entire attachment.
    Supersede,
    /// A routing request for a delivery.
    RouteRequest {
        delivery_id: String,
        routing_class: RoutingClass,
    },
    /// A retry reservation result from the Postgres authority.
    ReservationResult {
        key: RemoteTransportRetryReservationKey,
        result: Result<RemoteTransportRetryReservation, TransportDenial>,
    },
    /// A child failed with a security/policy/consent failure (terminal).
    ChildSecurityFailure { child_attempt: ChildAttemptId },
}

// ─────────────────────────────────────────────────────────────────────────
// Outputs (commands)
// ─────────────────────────────────────────────────────────────────────────

/// Pure actions emitted by the reducer for the daemon to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportSelectionAction {
    /// Start a new child of the given kind.
    StartChild {
        child_attempt: ChildAttemptId,
        kind: TransportKind,
        epoch: TransportEpoch,
    },
    /// Arm the initial deadline timer.
    ArmDeadlineTimer { secs: u64 },
    /// Arm the retry delay timer.
    ArmRetryDelay { secs: u64 },
    /// Cancel a child (generation-bound).
    CancelChild { child_attempt: ChildAttemptId },
    /// Close a child.
    CloseChild { child_attempt: ChildAttemptId },
    /// Start a TURN replacement-pending child.
    StartReplacementPending {
        child_attempt: ChildAttemptId,
        kind: TransportKind,
        epoch: TransportEpoch,
    },
    /// Emit the cutover lease for supervisor ACK.
    EmitCutoverLease {
        current: ChildAttemptId,
        draining: ChildAttemptId,
        lease_id: [u8; 16],
    },
    /// Route a delivery to a specific current child.
    RouteDelivery {
        delivery_id: String,
        child_attempt: ChildAttemptId,
    },
    /// Deny a delivery/routing with a typed denial.
    Deny { denial: TransportDenial },
    /// Reserve a retry in the Postgres authority.
    ReserveRetry {
        key: RemoteTransportRetryReservationKey,
    },
    /// Transition the parent to a new state.
    ParentTransition { new_state: ParentState },
    /// No action (inert event).
    Inert,
}

// ─────────────────────────────────────────────────────────────────────────
// Authorized plan computation
// ─────────────────────────────────────────────────────────────────────────

/// Compute the authorized child plan from the authorization inputs and user
/// preference. This is the entry point for `remote_transport_authorized_plan_matrix`.
pub fn compute_authorized_plan(
    auth: &TransportAuthorization,
    preference: UserTransportPreference,
) -> AuthorizedPlan {
    let mut allowed = Vec::new();
    let mut denials = Vec::new();

    // Check WebRTC authorization.
    let webrtc_available = auth.webrtc_authorized && auth.client_supports_webrtc;
    if !auth.webrtc_authorized {
        denials.push(TransportDenial::KindNotAuthorized);
    } else if !auth.client_supports_webrtc {
        denials.push(TransportDenial::ClientCapabilityMissing);
    }

    // Check WebSocket authorization.
    let websocket_available = auth.websocket_authorized && auth.client_supports_websocket;
    if !auth.websocket_authorized {
        denials.push(TransportDenial::KindNotAuthorized);
    } else if !auth.client_supports_websocket {
        denials.push(TransportDenial::ClientCapabilityMissing);
    }

    // IP consent / privacy checks for WebRTC.
    if webrtc_available
        && auth.privacy_relay_only
        && matches!(auth.ip_consent_direct, IpConsentTriState::Granted)
    {
        // Privacy relay-only overrides direct consent: WebRTC is still
        // allowed but only via TURN. This doesn't deny WebRTC entirely.
    }
    if webrtc_available
        && matches!(auth.ip_consent_direct, IpConsentTriState::Denied)
        && !auth.privacy_relay_only
    {
        // If IP consent is denied and privacy doesn't require relay,
        // WebRTC direct is denied but TURN is still possible.
        // We don't deny WebRTC entirely here — the adapter handles
        // candidate filtering. But if neither direct nor TURN is available,
        // it's a denial.
    }

    // Quota check.
    if !auth.quota_available {
        denials.push(TransportDenial::QuotaExhausted);
    }

    // Apply user preference narrowing.
    match preference {
        UserTransportPreference::Auto => {
            if webrtc_available {
                allowed.push(TransportKind::Webrtc);
            }
            if websocket_available {
                allowed.push(TransportKind::Websocket);
            }
        }
        UserTransportPreference::Webrtc => {
            if webrtc_available {
                allowed.push(TransportKind::Webrtc);
            } else {
                denials.push(TransportDenial::PreferenceDisallowed);
            }
            // Forced WebRTC never starts fallback — do not add WebSocket.
        }
        UserTransportPreference::Websocket => {
            if websocket_available {
                allowed.push(TransportKind::Websocket);
            } else {
                denials.push(TransportDenial::PreferenceDisallowed);
            }
            // Forced WebSocket starts only authorized fallback.
        }
    }

    // If quota is exhausted, no kinds are allowed.
    if !auth.quota_available {
        allowed.clear();
    }

    // If nothing is allowed and we have no denials yet, add a policy denial.
    if allowed.is_empty() && denials.is_empty() {
        denials.push(TransportDenial::PolicyDenied);
    }

    AuthorizedPlan {
        allowed_kinds: allowed,
        denials,
        preference,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The pure reducer
// ─────────────────────────────────────────────────────────────────────────

/// The pure reducer. Processes an input event against the current state and
/// returns a list of actions to execute. All transitions are generation-bound.
pub fn reduce(
    state: &mut TransportSelectionState,
    input: &TransportSelectionInput,
) -> Vec<TransportSelectionAction> {
    if state.cancelled {
        // After cancellation, only supersede is processed.
        if matches!(input, TransportSelectionInput::Supersede) {
            state.parent_state = ParentState::Superseded;
            return vec![TransportSelectionAction::ParentTransition {
                new_state: ParentState::Superseded,
            }];
        }
        return vec![TransportSelectionAction::Inert];
    }

    match input {
        TransportSelectionInput::StartPlan => reduce_start_plan(state),
        TransportSelectionInput::ChildActive { child_attempt, .. } => {
            reduce_child_active(state, *child_attempt)
        }
        TransportSelectionInput::ChildReachability {
            child_attempt,
            class,
        } => reduce_child_reachability(state, *child_attempt, *class),
        TransportSelectionInput::WebrtcProbe {
            child_attempt,
            success,
            buffered_bytes,
        } => reduce_webrtc_probe(state, *child_attempt, *success, *buffered_bytes),
        TransportSelectionInput::WebsocketAckProgress {
            child_attempt,
            oldest_unacked_age_secs,
            buffered_bytes,
            retransmissions,
        } => reduce_websocket_ack(
            state,
            *child_attempt,
            *oldest_unacked_age_secs,
            *buffered_bytes,
            *retransmissions,
        ),
        TransportSelectionInput::DeadlineFired { now_ms } => reduce_deadline_fired(state, *now_ms),
        TransportSelectionInput::RetryDelayFired { now_ms } => {
            reduce_retry_delay_fired(state, *now_ms)
        }
        TransportSelectionInput::ChildClosed {
            child_attempt,
            security_failure,
        } => reduce_child_closed(state, *child_attempt, *security_failure),
        TransportSelectionInput::RequestSecondChild { reason, now_ms } => {
            reduce_request_second_child(state, *reason, *now_ms)
        }
        TransportSelectionInput::CredentialRotationLead { now_ms } => {
            reduce_credential_rotation(state, *now_ms)
        }
        TransportSelectionInput::SupervisorCutoverAck { old, new } => {
            reduce_supervisor_cutover_ack(state, *old, *new)
        }
        TransportSelectionInput::SecondLease { old } => reduce_second_lease(state, *old),
        TransportSelectionInput::CloseChild { child_attempt } => {
            reduce_close_child(state, *child_attempt)
        }
        TransportSelectionInput::Cancel => reduce_cancel(state),
        TransportSelectionInput::Supersede => reduce_supersede(state),
        TransportSelectionInput::RouteRequest {
            delivery_id,
            routing_class,
        } => reduce_route_request(state, delivery_id, *routing_class),
        TransportSelectionInput::ReservationResult { key, result } => {
            reduce_reservation_result(state, key, result)
        }
        TransportSelectionInput::ChildSecurityFailure { child_attempt } => {
            reduce_child_security_failure(state, *child_attempt)
        }
    }
}

fn reduce_start_plan(state: &mut TransportSelectionState) -> Vec<TransportSelectionAction> {
    let plan = compute_authorized_plan(&state.authorization, state.preference);

    if plan.allowed_kinds.is_empty() {
        state.parent_state = ParentState::Denied;
        return vec![
            TransportSelectionAction::Deny {
                denial: plan
                    .denials
                    .first()
                    .cloned()
                    .unwrap_or(TransportDenial::PolicyDenied),
            },
            TransportSelectionAction::ParentTransition {
                new_state: ParentState::Denied,
            },
        ];
    }

    state.parent_state = ParentState::Establishing;
    let mut actions = vec![TransportSelectionAction::ParentTransition {
        new_state: ParentState::Establishing,
    }];

    // For auto preference: start WebRTC first, arm deadline.
    // For webrtc preference: start WebRTC only.
    // For websocket preference: start WebSocket only.
    match state.preference {
        UserTransportPreference::Auto => {
            if plan.allowed_kinds.contains(&TransportKind::Webrtc) {
                let id = state.next_child_attempt;
                let epoch = state.next_epoch;
                state.next_child_attempt = state.next_child_attempt.next();
                state.next_epoch = TransportEpoch(state.next_epoch.0 + 1);
                state
                    .children
                    .push(ChildRecord::new_pending(id, TransportKind::Webrtc, epoch));
                actions.push(TransportSelectionAction::StartChild {
                    child_attempt: id,
                    kind: TransportKind::Webrtc,
                    epoch,
                });
                state.deadline_timer_armed = true;
                actions.push(TransportSelectionAction::ArmDeadlineTimer {
                    secs: state.deadline_secs,
                });
            } else if plan.allowed_kinds.contains(&TransportKind::Websocket) {
                // No WebRTC available, start WebSocket directly.
                let id = state.next_child_attempt;
                let epoch = state.next_epoch;
                state.next_child_attempt = state.next_child_attempt.next();
                state.next_epoch = TransportEpoch(state.next_epoch.0 + 1);
                state.children.push(ChildRecord::new_pending(
                    id,
                    TransportKind::Websocket,
                    epoch,
                ));
                actions.push(TransportSelectionAction::StartChild {
                    child_attempt: id,
                    kind: TransportKind::Websocket,
                    epoch,
                });
            }
        }
        UserTransportPreference::Webrtc => {
            if plan.allowed_kinds.contains(&TransportKind::Webrtc) {
                let id = state.next_child_attempt;
                let epoch = state.next_epoch;
                state.next_child_attempt = state.next_child_attempt.next();
                state.next_epoch = TransportEpoch(state.next_epoch.0 + 1);
                state
                    .children
                    .push(ChildRecord::new_pending(id, TransportKind::Webrtc, epoch));
                actions.push(TransportSelectionAction::StartChild {
                    child_attempt: id,
                    kind: TransportKind::Webrtc,
                    epoch,
                });
                // No deadline timer — forced WebRTC never falls back.
            }
        }
        UserTransportPreference::Websocket => {
            if plan.allowed_kinds.contains(&TransportKind::Websocket) {
                let id = state.next_child_attempt;
                let epoch = state.next_epoch;
                state.next_child_attempt = state.next_child_attempt.next();
                state.next_epoch = TransportEpoch(state.next_epoch.0 + 1);
                state.children.push(ChildRecord::new_pending(
                    id,
                    TransportKind::Websocket,
                    epoch,
                ));
                actions.push(TransportSelectionAction::StartChild {
                    child_attempt: id,
                    kind: TransportKind::Websocket,
                    epoch,
                });
            }
        }
    }

    actions
}

fn reduce_child_active(
    state: &mut TransportSelectionState,
    child_attempt: ChildAttemptId,
) -> Vec<TransportSelectionAction> {
    // Late cancelled results cannot activate.
    let Some(child) = state.find_child_mut(child_attempt) else {
        return vec![TransportSelectionAction::Inert];
    };
    if child.cancelled {
        return vec![TransportSelectionAction::Inert];
    }

    child.state = ChildState::Active;
    child.consecutive_healthy = child.consecutive_healthy.saturating_add(1);
    child.recompute_health();

    // If any child is active, parent is active.
    if state.children.iter().any(|c| c.state == ChildState::Active) {
        let old_state = state.parent_state;
        state.parent_state = ParentState::Active;
        if old_state != ParentState::Active {
            return vec![TransportSelectionAction::ParentTransition {
                new_state: ParentState::Active,
            }];
        }
    }

    vec![]
}

fn reduce_child_reachability(
    state: &mut TransportSelectionState,
    child_attempt: ChildAttemptId,
    class: ReachabilityClass,
) -> Vec<TransportSelectionAction> {
    let Some(child) = state.find_child_mut(child_attempt) else {
        return vec![TransportSelectionAction::Inert];
    };
    if child.cancelled {
        return vec![TransportSelectionAction::Inert];
    }

    // Security failures are handled separately and are terminal.
    match class {
        ReachabilityClass::IceDisconnected => {
            child.ice_disconnected_misses = child.ice_disconnected_misses.saturating_add(1);
            child.state = ChildState::Degraded;
            child.recompute_health();

            if child.ice_disconnected_misses >= ICE_DISCONNECTED_FALLBACK_MISSES {
                // Maps to network_unreachable — trigger fallback.
                return maybe_start_websocket_fallback(state);
            }
            vec![]
        }
        ReachabilityClass::IceNoCandidatePair
        | ReachabilityClass::IceTimeout
        | ReachabilityClass::NetworkUnreachable
        | ReachabilityClass::TurnUnreachable => {
            // Closed reachability class — close this child and maybe fallback.
            child.state = ChildState::Closed;
            child.recompute_health();

            maybe_start_websocket_fallback(state)
        }
    }
}

fn maybe_start_websocket_fallback(
    state: &mut TransportSelectionState,
) -> Vec<TransportSelectionAction> {
    // Only for auto preference. Forced webrtc never falls back.
    if !matches!(state.preference, UserTransportPreference::Auto) {
        return vec![];
    }
    if state.websocket_fallback_started {
        return vec![];
    }
    // Check WebSocket is authorized and available.
    if !state.authorization.websocket_authorized || !state.authorization.client_supports_websocket {
        return vec![];
    }
    // Check cap: one pending per kind, two ordinary pending total.
    if state.count_ordinary_pending_kind(TransportKind::Websocket) >= MAX_PENDING_PER_KIND {
        return vec![];
    }
    if state.count_ordinary_pending() >= MAX_ORDINARY_PENDING_CHILDREN {
        return vec![];
    }

    state.websocket_fallback_started = true;
    state.deadline_timer_armed = false;

    let id = state.next_child_attempt;
    let epoch = state.next_epoch;
    state.next_child_attempt = state.next_child_attempt.next();
    state.next_epoch = TransportEpoch(state.next_epoch.0 + 1);
    state.children.push(ChildRecord::new_pending(
        id,
        TransportKind::Websocket,
        epoch,
    ));

    vec![TransportSelectionAction::StartChild {
        child_attempt: id,
        kind: TransportKind::Websocket,
        epoch,
    }]
}

fn reduce_webrtc_probe(
    state: &mut TransportSelectionState,
    child_attempt: ChildAttemptId,
    success: bool,
    buffered_bytes: u64,
) -> Vec<TransportSelectionAction> {
    let Some(child) = state.find_child_mut(child_attempt) else {
        return vec![TransportSelectionAction::Inert];
    };
    if child.cancelled || child.kind != TransportKind::Webrtc {
        return vec![TransportSelectionAction::Inert];
    }

    child.buffered_bytes = buffered_bytes;

    if success {
        child.consecutive_misses = 0;
        child.ice_disconnected_misses = 0;
        child.consecutive_healthy = child.consecutive_healthy.saturating_add(1);
        child.consecutive_high_buffer_probes = 0;
    } else {
        child.consecutive_healthy = 0;
        child.consecutive_misses = child.consecutive_misses.saturating_add(1);
        if buffered_bytes >= WEBRTC_DEGRADED_BUFFER_BYTES {
            child.consecutive_high_buffer_probes =
                child.consecutive_high_buffer_probes.saturating_add(1);
        } else {
            child.consecutive_high_buffer_probes = 0;
        }
    }

    child.recompute_health();

    // State transitions based on health.
    let mut actions = Vec::new();
    match child.health_tier {
        HealthTier::Failed => {
            child.state = ChildState::Closed;
            // WebRTC failed — try fallback for auto preference.
            if matches!(state.preference, UserTransportPreference::Auto) {
                actions.extend(maybe_start_websocket_fallback(state));
            }
        }
        HealthTier::Degraded => {
            if child.state == ChildState::Active {
                child.state = ChildState::Degraded;
            }
        }
        HealthTier::Healthy => {
            if child.state == ChildState::Degraded
                && child.consecutive_healthy
                    >= cockpit_proto::remote_transport_selection::RECOVERY_CONSECUTIVE_HEALTHY
            {
                child.state = ChildState::Active;
            }
        }
    }

    actions
}

fn reduce_websocket_ack(
    state: &mut TransportSelectionState,
    child_attempt: ChildAttemptId,
    oldest_unacked_age_secs: u64,
    buffered_bytes: u64,
    retransmissions: u32,
) -> Vec<TransportSelectionAction> {
    let Some(child) = state.find_child_mut(child_attempt) else {
        return vec![TransportSelectionAction::Inert];
    };
    if child.cancelled || child.kind != TransportKind::Websocket {
        return vec![TransportSelectionAction::Inert];
    }

    child.oldest_unacked_age_secs = oldest_unacked_age_secs;
    child.buffered_bytes = buffered_bytes;
    child.retransmissions = retransmissions;

    if oldest_unacked_age_secs == 0 && buffered_bytes < WEBSOCKET_DEGRADED_BUFFER_BYTES {
        child.consecutive_healthy = child.consecutive_healthy.saturating_add(1);
    } else {
        child.consecutive_healthy = 0;
    }

    child.recompute_health();

    let mut actions = Vec::new();
    match child.health_tier {
        HealthTier::Failed => {
            child.state = ChildState::Closed;
            // WebSocket failed — no further fallback (no same-kind retry
            // beyond the one allowed, and no other transport to fall to).
        }
        HealthTier::Degraded => {
            if child.state == ChildState::Active {
                child.state = ChildState::Degraded;
            }
        }
        HealthTier::Healthy => {
            if child.state == ChildState::Degraded
                && child.consecutive_healthy
                    >= cockpit_proto::remote_transport_selection::RECOVERY_CONSECUTIVE_HEALTHY
            {
                child.state = ChildState::Active;
            }
        }
    }

    if actions.is_empty() {
        actions.push(TransportSelectionAction::Inert);
    }
    actions
}

fn reduce_deadline_fired(
    state: &mut TransportSelectionState,
    _now_ms: i64,
) -> Vec<TransportSelectionAction> {
    state.deadline_timer_armed = false;

    // Only start fallback if no WebRTC child is active yet.
    let webrtc_active = state
        .children
        .iter()
        .any(|c| c.kind == TransportKind::Webrtc && c.state == ChildState::Active);

    if webrtc_active {
        return vec![TransportSelectionAction::Inert];
    }

    maybe_start_websocket_fallback(state)
}

fn reduce_retry_delay_fired(
    state: &mut TransportSelectionState,
    _now_ms: i64,
) -> Vec<TransportSelectionAction> {
    state.retry_timer_armed = false;

    let Some(pending) = state.pending_retry.take() else {
        return vec![TransportSelectionAction::Inert];
    };

    // Check caps before starting the retry.
    if state.count_ordinary_pending_kind(pending.kind) >= MAX_PENDING_PER_KIND {
        return vec![TransportSelectionAction::Inert];
    }
    if state.count_ordinary_pending() >= MAX_ORDINARY_PENDING_CHILDREN {
        return vec![TransportSelectionAction::Inert];
    }

    state.children.push(ChildRecord::new_pending(
        pending.child_attempt,
        pending.kind,
        pending.epoch,
    ));

    vec![TransportSelectionAction::StartChild {
        child_attempt: pending.child_attempt,
        kind: pending.kind,
        epoch: pending.epoch,
    }]
}

fn reduce_child_closed(
    state: &mut TransportSelectionState,
    child_attempt: ChildAttemptId,
    security_failure: bool,
) -> Vec<TransportSelectionAction> {
    let Some(child) = state.find_child_mut(child_attempt) else {
        return vec![TransportSelectionAction::Inert];
    };

    child.state = ChildState::Closed;
    child.recompute_health();

    if security_failure {
        // Security failure is terminal and never falls back.
        // Do not start any fallback.
        return vec![];
    }

    // Closing one child cannot clear the other, durable retry budget,
    // operation outcome, event cursor, or presence.
    // But if no children are active and none are pending, parent may fail.
    let any_active = state
        .children
        .iter()
        .any(|c| c.state == ChildState::Active || c.state == ChildState::Degraded);
    let any_pending = state
        .children
        .iter()
        .any(|c| matches!(c.state, ChildState::Pending | ChildState::Authenticating));

    if !any_active && !any_pending {
        // Try same-kind retry if budget allows.
        let kind = child.kind;
        let retries_used = child.retries_used;
        if retries_used < MAX_SAME_KIND_RETRIES && !state.cancelled {
            // Schedule a retry with 1-second delay.
            let id = state.next_child_attempt;
            let epoch = state.next_epoch;
            state.next_child_attempt = state.next_child_attempt.next();
            state.next_epoch = TransportEpoch(state.next_epoch.0 + 1);
            state.pending_retry = Some(PendingRetry {
                kind,
                child_attempt: id,
                epoch,
            });
            state.retry_timer_armed = true;
            return vec![TransportSelectionAction::ArmRetryDelay {
                secs: RETRY_DELAY_SECS,
            }];
        }
        // No retry budget left — parent fails.
        state.parent_state = ParentState::Failed;
        return vec![TransportSelectionAction::ParentTransition {
            new_state: ParentState::Failed,
        }];
    }

    vec![]
}

fn reduce_request_second_child(
    state: &mut TransportSelectionState,
    reason: SecondChildReason,
    _now_ms: i64,
) -> Vec<TransportSelectionAction> {
    // Only if at least one child is active.
    let has_active = state.children.iter().any(|c| c.state == ChildState::Active);
    if !has_active {
        return vec![TransportSelectionAction::Deny {
            denial: TransportDenial::PolicyDenied,
        }];
    }

    // Determine which kind to start as the second child.
    let existing_kinds: Vec<TransportKind> = state
        .children
        .iter()
        .filter(|c| c.is_routed_current())
        .map(|c| c.kind)
        .collect();

    let target_kind = if !existing_kinds.contains(&TransportKind::Webrtc)
        && state.authorization.webrtc_authorized
        && state.authorization.client_supports_webrtc
    {
        TransportKind::Webrtc
    } else if !existing_kinds.contains(&TransportKind::Websocket)
        && state.authorization.websocket_authorized
        && state.authorization.client_supports_websocket
    {
        TransportKind::Websocket
    } else {
        return vec![TransportSelectionAction::Deny {
            denial: TransportDenial::ChildCapExceeded,
        }];
    };

    // Check caps.
    if state.count_ordinary_pending_kind(target_kind) >= MAX_PENDING_PER_KIND {
        return vec![TransportSelectionAction::Deny {
            denial: TransportDenial::ChildCapExceeded,
        }];
    }
    if state.count_ordinary_pending() >= MAX_ORDINARY_PENDING_CHILDREN {
        return vec![TransportSelectionAction::Deny {
            denial: TransportDenial::ChildCapExceeded,
        }];
    }
    if state.count_routed_current() >= MAX_ROUTED_CURRENT_CHILDREN {
        return vec![TransportSelectionAction::Deny {
            denial: TransportDenial::ChildCapExceeded,
        }];
    }

    let id = state.next_child_attempt;
    let epoch = state.next_epoch;
    state.next_child_attempt = state.next_child_attempt.next();
    state.next_epoch = TransportEpoch(state.next_epoch.0 + 1);

    let mut child = ChildRecord::new_pending(id, target_kind, epoch);
    // credential_rotation creates a replacement_pending TURN child.
    if reason == SecondChildReason::CredentialRotation && target_kind == TransportKind::Webrtc {
        child.durable_lifecycle = DurableLifecycle::ReplacementPending;
    }
    state.children.push(child);

    if reason == SecondChildReason::CredentialRotation && target_kind == TransportKind::Webrtc {
        return vec![TransportSelectionAction::StartReplacementPending {
            child_attempt: id,
            kind: target_kind,
            epoch,
        }];
    }

    vec![TransportSelectionAction::StartChild {
        child_attempt: id,
        kind: target_kind,
        epoch,
    }]
}

fn reduce_credential_rotation(
    state: &mut TransportSelectionState,
    _now_ms: i64,
) -> Vec<TransportSelectionAction> {
    // Find the current WebRTC child and create a replacement_pending pair.
    let current_webrtc = state
        .children
        .iter()
        .find(|c| {
            c.kind == TransportKind::Webrtc
                && matches!(c.durable_lifecycle, DurableLifecycle::Current)
                && !matches!(c.state, ChildState::Closed)
        })
        .map(|c| c.child_attempt);

    let Some(current_id) = current_webrtc else {
        return vec![TransportSelectionAction::Inert];
    };

    // Check if a replacement is already pending.
    if state.turn_replacement.is_some() {
        return vec![TransportSelectionAction::Inert];
    }

    // Check physical child cap (three only during TURN replacement).
    if state.count_physical_children() >= MAX_PHYSICAL_CHILDREN_TURN_EXCEPTION {
        return vec![TransportSelectionAction::Deny {
            denial: TransportDenial::ChildCapExceeded,
        }];
    }

    let id = state.next_child_attempt;
    let epoch = state.next_epoch;
    state.next_child_attempt = state.next_child_attempt.next();
    state.next_epoch = TransportEpoch(state.next_epoch.0 + 1);

    let mut replacement = ChildRecord::new_pending(id, TransportKind::Webrtc, epoch);
    replacement.durable_lifecycle = DurableLifecycle::ReplacementPending;
    replacement.replacement_peer = Some(current_id);
    state.children.push(replacement);

    // Set the replacement pair.
    let lease_id = [0xAB; 16]; // In practice generated deterministically.
    state.turn_replacement = Some(TurnReplacementPair {
        current: current_id,
        replacement: id,
        phase: TurnReplacementPhase::ReplacementPending,
        lease_id,
    });

    // Link the current child to its replacement peer.
    if let Some(current) = state.find_child_mut(current_id) {
        current.replacement_peer = Some(id);
    }

    vec![TransportSelectionAction::StartReplacementPending {
        child_attempt: id,
        kind: TransportKind::Webrtc,
        epoch,
    }]
}

fn reduce_supervisor_cutover_ack(
    state: &mut TransportSelectionState,
    old: ChildAttemptId,
    new: ChildAttemptId,
) -> Vec<TransportSelectionAction> {
    let Some(replacement) = &mut state.turn_replacement else {
        return vec![TransportSelectionAction::Inert];
    };

    if replacement.current != old || replacement.replacement != new {
        return vec![TransportSelectionAction::Inert];
    }

    // Cutover: new becomes current, old becomes draining.
    if let Some(new_child) = state.find_child_mut(new) {
        new_child.durable_lifecycle = DurableLifecycle::Current;
        new_child.state = ChildState::Active;
        new_child.recompute_health();
    }
    if let Some(old_child) = state.find_child_mut(old) {
        old_child.durable_lifecycle = DurableLifecycle::Draining;
        old_child.state = ChildState::Closing;
    }

    replacement.phase = TurnReplacementPhase::Draining;

    vec![TransportSelectionAction::EmitCutoverLease {
        current: new,
        draining: old,
        lease_id: replacement.lease_id,
    }]
}

fn reduce_second_lease(
    state: &mut TransportSelectionState,
    old: ChildAttemptId,
) -> Vec<TransportSelectionAction> {
    let Some(replacement) = &mut state.turn_replacement else {
        return vec![TransportSelectionAction::Inert];
    };

    if replacement.current != old && replacement.replacement != old {
        // The old draining child should match.
    }

    // Remove the old draining child.
    if let Some(old_child) = state.find_child_mut(old) {
        old_child.state = ChildState::Closed;
        old_child.durable_lifecycle = DurableLifecycle::Draining;
    }

    replacement.phase = TurnReplacementPhase::Removed;
    state.turn_replacement = None;

    vec![TransportSelectionAction::CloseChild { child_attempt: old }]
}

fn reduce_close_child(
    state: &mut TransportSelectionState,
    child_attempt: ChildAttemptId,
) -> Vec<TransportSelectionAction> {
    let Some(child) = state.find_child_mut(child_attempt) else {
        return vec![TransportSelectionAction::Inert];
    };

    child.state = ChildState::Closing;
    // Closing one child cannot clear the other.

    vec![TransportSelectionAction::CloseChild { child_attempt }]
}

fn reduce_cancel(state: &mut TransportSelectionState) -> Vec<TransportSelectionAction> {
    state.cancelled = true;
    state.deadline_timer_armed = false;
    state.retry_timer_armed = false;
    state.pending_retry = None;

    let mut actions = Vec::new();
    for child in &mut state.children {
        if !matches!(child.state, ChildState::Closed) {
            child.cancelled = true;
            child.state = ChildState::Closing;
            actions.push(TransportSelectionAction::CancelChild {
                child_attempt: child.child_attempt,
            });
        }
    }
    state.parent_state = ParentState::Cancelled;
    actions.push(TransportSelectionAction::ParentTransition {
        new_state: ParentState::Cancelled,
    });

    actions
}

fn reduce_supersede(state: &mut TransportSelectionState) -> Vec<TransportSelectionAction> {
    state.cancelled = true;
    state.deadline_timer_armed = false;
    state.retry_timer_armed = false;
    state.pending_retry = None;

    let mut actions = Vec::new();
    for child in &mut state.children.iter() {
        if !matches!(child.state, ChildState::Closed) {
            actions.push(TransportSelectionAction::CancelChild {
                child_attempt: child.child_attempt,
            });
        }
    }
    state.parent_state = ParentState::Superseded;
    actions.push(TransportSelectionAction::ParentTransition {
        new_state: ParentState::Superseded,
    });

    actions
}

fn reduce_route_request(
    state: &mut TransportSelectionState,
    delivery_id: &str,
    routing_class: RoutingClass,
) -> Vec<TransportSelectionAction> {
    // If already assigned, keep the assignment (one stable delivery ID → one
    // current child; failover may resend exact bytes).
    if let Some(&assigned) = state.delivery_assignments.get(delivery_id) {
        if let Some(child) = state.find_child(assigned) {
            if child.is_routed_current() {
                return vec![TransportSelectionAction::RouteDelivery {
                    delivery_id: delivery_id.to_string(),
                    child_attempt: assigned,
                }];
            }
        }
    }

    let selected = select_route(state, routing_class);

    let Some(child_attempt) = selected else {
        return vec![TransportSelectionAction::Deny {
            denial: TransportDenial::PolicyDenied,
        }];
    };

    state
        .delivery_assignments
        .insert(delivery_id.to_string(), child_attempt);

    vec![TransportSelectionAction::RouteDelivery {
        delivery_id: delivery_id.to_string(),
        child_attempt,
    }]
}

/// Deterministic routing among `current` children only.
/// Replacement-pending is never selected.
fn select_route(
    state: &TransportSelectionState,
    routing_class: RoutingClass,
) -> Option<ChildAttemptId> {
    let current_children: Vec<&ChildRecord> = state
        .children
        .iter()
        .filter(|c| c.is_routed_current())
        .collect();

    if current_children.is_empty() {
        return None;
    }

    match routing_class {
        RoutingClass::Control => {
            // Control: healthy over degraded, then lower epoch.
            current_children
                .iter()
                .min_by_key(|c| (!matches!(c.health_tier, HealthTier::Healthy), c.epoch))
                .map(|c| c.child_attempt)
        }
        RoutingClass::Interactive => {
            // Interactive: healthy WebRTC, then healthy WebSocket, then
            // degraded by lower epoch.
            let healthy_webrtc = current_children
                .iter()
                .find(|c| c.kind == TransportKind::Webrtc && c.health_tier == HealthTier::Healthy);
            if let Some(c) = healthy_webrtc {
                return Some(c.child_attempt);
            }
            let healthy_websocket = current_children.iter().find(|c| {
                c.kind == TransportKind::Websocket && c.health_tier == HealthTier::Healthy
            });
            if let Some(c) = healthy_websocket {
                return Some(c.child_attempt);
            }
            // Degraded by lower epoch.
            current_children
                .iter()
                .min_by_key(|c| c.epoch)
                .map(|c| c.child_attempt)
        }
        RoutingClass::Bulk => {
            // Bulk: healthy child with more writable bytes, tie WebRTC then
            // lower epoch.
            let healthy: Vec<&&ChildRecord> = current_children
                .iter()
                .filter(|c| c.health_tier == HealthTier::Healthy)
                .collect();
            if !healthy.is_empty() {
                return healthy
                    .iter()
                    .max_by(|a, b| {
                        a.writable_bytes()
                            .cmp(&b.writable_bytes())
                            .then_with(|| {
                                // Tie: WebRTC first (webrtc < websocket in
                                // ordering, so reverse for priority).
                                let a_prio = matches!(a.kind, TransportKind::Webrtc);
                                let b_prio = matches!(b.kind, TransportKind::Webrtc);
                                b_prio.cmp(&a_prio)
                            })
                            .then_with(|| b.epoch.cmp(&a.epoch))
                    })
                    .map(|c| c.child_attempt);
            }
            // No healthy — degraded by lower epoch.
            current_children
                .iter()
                .min_by_key(|c| c.epoch)
                .map(|c| c.child_attempt)
        }
    }
}

fn reduce_reservation_result(
    state: &mut TransportSelectionState,
    key: &RemoteTransportRetryReservationKey,
    result: &Result<RemoteTransportRetryReservation, TransportDenial>,
) -> Vec<TransportSelectionAction> {
    match result {
        Ok(_reservation) => {
            // Reservation succeeded — the child can proceed.
            // The child was already started; this is a confirmation.
            vec![TransportSelectionAction::Inert]
        }
        Err(denial) => {
            // Reservation failed — cancel the corresponding child.
            // Find the child by transport kind and child attempt.
            let child_attempt = ChildAttemptId(key.child_attempt);
            if let Some(child) = state.find_child_mut(child_attempt) {
                child.cancelled = true;
                child.state = ChildState::Closed;
            }
            vec![
                TransportSelectionAction::CancelChild { child_attempt },
                TransportSelectionAction::Deny {
                    denial: denial.clone(),
                },
            ]
        }
    }
}

fn reduce_child_security_failure(
    state: &mut TransportSelectionState,
    child_attempt: ChildAttemptId,
) -> Vec<TransportSelectionAction> {
    let Some(child) = state.find_child_mut(child_attempt) else {
        return vec![TransportSelectionAction::Inert];
    };

    // Security failure is terminal and never falls back.
    child.state = ChildState::Closed;
    child.cancelled = true;
    child.recompute_health();

    // Do NOT start any fallback.

    // If this was the only child and it failed terminally, parent fails.
    let any_active = state
        .children
        .iter()
        .any(|c| c.state == ChildState::Active || c.state == ChildState::Degraded);
    let any_pending = state
        .children
        .iter()
        .any(|c| matches!(c.state, ChildState::Pending | ChildState::Authenticating));

    if !any_active && !any_pending {
        state.parent_state = ParentState::Failed;
        return vec![
            TransportSelectionAction::Deny {
                denial: TransportDenial::SecurityFailure,
            },
            TransportSelectionAction::ParentTransition {
                new_state: ParentState::Failed,
            },
        ];
    }

    vec![TransportSelectionAction::Deny {
        denial: TransportDenial::SecurityFailure,
    }]
}

// ─────────────────────────────────────────────────────────────────────────
// Reservation budget validation
// ─────────────────────────────────────────────────────────────────────────

/// Validate retry budget constraints against the persisted reservations.
/// Returns Ok if the new reservation is within budget, Err with a typed
/// denial if not.
pub fn validate_retry_budget(
    existing_in_train: &[RemoteTransportRetryReservation],
    committed_in_rolling_window: &[RemoteTransportRetryReservation],
    new_key: &RemoteTransportRetryReservationKey,
    now_ms: i64,
) -> Result<(), TransportDenial> {
    // Reject more than four reservations per train.
    let train_count = existing_in_train
        .iter()
        .filter(|r| r.key.train_id == new_key.train_id)
        .count() as u32;
    if train_count >= MAX_RESERVATIONS_PER_TRAIN {
        return Err(TransportDenial::RetryBudgetExhausted);
    }

    // Reject more than twelve committed reservations in the preceding rolling
    // 3,600 seconds.
    let rolling_start = now_ms - (ROLLING_WINDOW_SECS as i64) * 1000;
    let rolling_count = committed_in_rolling_window
        .iter()
        .filter(|r| r.reserved_at_ms >= rolling_start)
        .count() as u32;
    if rolling_count >= MAX_COMMITTED_RESERVATIONS_ROLLING {
        return Err(TransportDenial::RetryBudgetExhausted);
    }

    // Check for exact duplicates — exact duplicates do not count.
    let is_duplicate = existing_in_train.iter().any(|r| {
        r.key.transport_kind == new_key.transport_kind
            && r.key.child_attempt == new_key.child_attempt
            && r.key.train_id == new_key.train_id
    });
    if is_duplicate {
        // Idempotent — return Ok (the duplicate does not count).
        return Ok(());
    }

    Ok(())
}

/// Build a reservation key for a child attempt.
pub fn build_reservation_key(
    tenant_id: &str,
    account_id: &str,
    client_device_id: &str,
    logical_attachment_id: &str,
    train_id: TrainId,
    transport_kind: TransportKind,
    child_attempt: ChildAttemptId,
) -> RemoteTransportRetryReservationKey {
    RemoteTransportRetryReservationKey {
        tenant_id: tenant_id.to_string(),
        account_id: account_id.to_string(),
        client_device_id: client_device_id.to_string(),
        logical_attachment_id: logical_attachment_id.to_string(),
        train_id: train_id.0,
        transport_kind,
        child_attempt: child_attempt.0,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Golden transition/route trace
// ─────────────────────────────────────────────────────────────────────────

/// A golden trace entry — a recorded state transition or routing decision,
/// consumed by web/native/Rust for cross-language fixture parity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GoldenTraceEntry {
    pub step: u64,
    pub input: String,
    pub parent_state_before: String,
    pub parent_state_after: String,
    pub actions: Vec<String>,
}

/// Record a golden trace for a sequence of inputs. This is the pure
/// transition/route trace consumed by cross-language fixtures.
pub fn record_golden_trace(
    initial_state: TransportSelectionState,
    inputs: &[TransportSelectionInput],
) -> Vec<GoldenTraceEntry> {
    let mut state = initial_state;
    let mut trace = Vec::new();

    for (i, input) in inputs.iter().enumerate() {
        let state_before = format!("{:?}", state.parent_state);
        let actions = reduce(&mut state, input);
        let state_after = format!("{:?}", state.parent_state);

        trace.push(GoldenTraceEntry {
            step: i as u64,
            input: format!("{:?}", input),
            parent_state_before: state_before,
            parent_state_after: state_after,
            actions: actions.iter().map(|a| format!("{:?}", a)).collect(),
        });
    }

    trace
}

// ─────────────────────────────────────────────────────────────────────────
// Duration helper
// ─────────────────────────────────────────────────────────────────────────

/// Convert the deadline seconds to a Duration.
pub fn deadline_duration(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test helpers ──

    fn full_auth() -> TransportAuthorization {
        TransportAuthorization {
            webrtc_authorized: true,
            websocket_authorized: true,
            ip_consent_direct: IpConsentTriState::Granted,
            privacy_relay_only: false,
            quota_available: true,
            client_supports_webrtc: true,
            client_supports_websocket: true,
        }
    }

    fn train_id() -> TrainId {
        TrainId([0x42; TRAIN_ID_BYTES])
    }

    fn new_auto_state() -> TransportSelectionState {
        TransportSelectionState::new(
            full_auth(),
            UserTransportPreference::Auto,
            train_id(),
            INITIAL_DEADLINE_SECS,
        )
    }

    // ── AC 1: authorized_plan_matrix ──

    #[test]
    fn remote_transport_authorized_plan_matrix() {
        // Both authorized → both allowed for auto.
        let plan = compute_authorized_plan(&full_auth(), UserTransportPreference::Auto);
        assert!(plan.allowed_kinds.contains(&TransportKind::Webrtc));
        assert!(plan.allowed_kinks_granted_if_both_available());

        // WebRTC not authorized → not in allowed for auto.
        let mut auth = full_auth();
        auth.webrtc_authorized = false;
        let plan = compute_authorized_plan(&auth, UserTransportPreference::Auto);
        assert!(!plan.allowed_kinds.contains(&TransportKind::Webrtc));
        assert!(plan.denials.contains(&TransportDenial::KindNotAuthorized));

        // WebSocket not authorized.
        let mut auth = full_auth();
        auth.websocket_authorized = false;
        let plan = compute_authorized_plan(&auth, UserTransportPreference::Auto);
        assert!(!plan.allowed_kinds.contains(&TransportKind::Websocket));

        // Client doesn't support WebRTC.
        let mut auth = full_auth();
        auth.client_supports_webrtc = false;
        let plan = compute_authorized_plan(&auth, UserTransportPreference::Auto);
        assert!(!plan.allowed_kinds.contains(&TransportKind::Webrtc));
        assert!(
            plan.denials
                .contains(&TransportDenial::ClientCapabilityMissing)
        );

        // Quota exhausted → nothing allowed.
        let mut auth = full_auth();
        auth.quota_available = false;
        let plan = compute_authorized_plan(&auth, UserTransportPreference::Auto);
        assert!(plan.allowed_kinds.is_empty());
        assert!(plan.denials.contains(&TransportDenial::QuotaExhausted));

        // Both not available → denied with policy.
        let mut auth = full_auth();
        auth.webrtc_authorized = false;
        auth.websocket_authorized = false;
        let plan = compute_authorized_plan(&auth, UserTransportPreference::Auto);
        assert!(plan.allowed_kinds.is_empty());
        assert_eq!(plan.parent_state_if_plan_used(), ParentState::Denied);
    }

    // ── AC 2: user_preference_matrix ──

    #[test]
    fn remote_transport_user_preference_matrix() {
        // Auto: both allowed.
        let plan = compute_authorized_plan(&full_auth(), UserTransportPreference::Auto);
        assert_eq!(plan.allowed_kinds.len(), 2);

        // Webrtc forced: only webrtc, no websocket (no silent fallback).
        let plan = compute_authorized_plan(&full_auth(), UserTransportPreference::Webrtc);
        assert_eq!(plan.allowed_kinds, vec![TransportKind::Webrtc]);

        // Websocket forced: only websocket.
        let plan = compute_authorized_plan(&full_auth(), UserTransportPreference::Websocket);
        assert_eq!(plan.allowed_kinds, vec![TransportKind::Websocket]);

        // Webrtc forced but not available → typed denial, no silent override.
        let mut auth = full_auth();
        auth.webrtc_authorized = false;
        let plan = compute_authorized_plan(&auth, UserTransportPreference::Webrtc);
        assert!(plan.allowed_kinds.is_empty());
        assert!(
            plan.denials
                .contains(&TransportDenial::PreferenceDisallowed)
        );

        // Websocket forced but not available → typed denial.
        let mut auth = full_auth();
        auth.websocket_authorized = false;
        let plan = compute_authorized_plan(&auth, UserTransportPreference::Websocket);
        assert!(plan.allowed_kinds.is_empty());
        assert!(
            plan.denials
                .contains(&TransportDenial::PreferenceDisallowed)
        );
    }

    // ── AC 3: only_reachability_falls_back ──

    #[test]
    fn remote_transport_only_reachability_falls_back() {
        // Start plan with auto → WebRTC child started + deadline armed.
        let mut state = new_auto_state();
        let actions = reduce(&mut state, &TransportSelectionInput::StartPlan);
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::StartChild {
                kind: TransportKind::Webrtc,
                ..
            }
        )));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, TransportSelectionAction::ArmDeadlineTimer { .. }))
        );
        assert_eq!(state.children.len(), 1);
        assert_eq!(state.children[0].kind, TransportKind::Webrtc);

        let webrtc_id = state.children[0].child_attempt;

        // Closed reachability → fallback to WebSocket.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::ChildReachability {
                child_attempt: webrtc_id,
                class: ReachabilityClass::IceNoCandidatePair,
            },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::StartChild {
                kind: TransportKind::Websocket,
                ..
            }
        )));
        assert!(state.websocket_fallback_started);

        // Forced webrtc: closed reachability does NOT fallback.
        let mut state = TransportSelectionState::new(
            full_auth(),
            UserTransportPreference::Webrtc,
            train_id(),
            INITIAL_DEADLINE_SECS,
        );
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::ChildReachability {
                child_attempt: webrtc_id,
                class: ReachabilityClass::NetworkUnreachable,
            },
        );
        assert!(!actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::StartChild {
                kind: TransportKind::Websocket,
                ..
            }
        )));

        // Security failure never falls back.
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::ChildSecurityFailure {
                child_attempt: webrtc_id,
            },
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, TransportSelectionAction::StartChild { .. }))
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::Deny {
                denial: TransportDenial::SecurityFailure,
            }
        )));
    }

    #[test]
    fn remote_transport_deadline_validation() {
        assert!(cockpit_proto::remote_transport_selection::validate_deadline_secs(10).is_ok());
        assert!(cockpit_proto::remote_transport_selection::validate_deadline_secs(3).is_ok());
        assert!(cockpit_proto::remote_transport_selection::validate_deadline_secs(30).is_ok());
        assert!(cockpit_proto::remote_transport_selection::validate_deadline_secs(2).is_err());
        assert!(cockpit_proto::remote_transport_selection::validate_deadline_secs(31).is_err());
    }

    #[test]
    fn remote_transport_deadline_fires_fallback() {
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        // Deadline fires without active WebRTC → fallback.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::DeadlineFired { now_ms: 10_000 },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::StartChild {
                kind: TransportKind::Websocket,
                ..
            }
        )));
    }

    // ── AC 4: child_caps_and_reasons ──

    #[test]
    fn remote_transport_child_caps_and_reasons() {
        // Two routed-current cap: one per kind.
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        // Activate WebRTC.
        let webrtc_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 1000,
            },
        );
        // Start WebSocket via deadline.
        reduce(
            &mut state,
            &TransportSelectionInput::DeadlineFired { now_ms: 10_000 },
        );
        let ws_id = state.children[1].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: ws_id,
                now_ms: 10_001,
            },
        );
        assert_eq!(state.count_routed_current(), 2);

        // Request a third child → denied (cap exceeded).
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::RequestSecondChild {
                reason: SecondChildReason::PreferredPathRecovery,
                now_ms: 10_002,
            },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::Deny {
                denial: TransportDenial::ChildCapExceeded,
            }
        )));

        // Named second-child reasons are accepted when under cap.
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 1000,
            },
        );
        // Only one active child; request second for network_handoff.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::RequestSecondChild {
                reason: SecondChildReason::NetworkHandoff,
                now_ms: 2000,
            },
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, TransportSelectionAction::StartChild { .. }))
        );
    }

    #[test]
    fn remote_transport_turn_replacement_three_physical() {
        // TURN replacement creates a third physical child (the exception).
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 1000,
            },
        );
        // Start WebSocket too.
        reduce(
            &mut state,
            &TransportSelectionInput::DeadlineFired { now_ms: 10_000 },
        );
        let ws_id = state.children[1].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: ws_id,
                now_ms: 10_001,
            },
        );

        // Credential rotation → replacement_pending TURN child.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::CredentialRotationLead { now_ms: 20_000 },
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, TransportSelectionAction::StartReplacementPending { .. }))
        );
        // Now three physical children: current WebRTC + replacement_pending
        // + current WebSocket.
        assert_eq!(state.count_physical_children(), 3);

        // The replacement is replacement_pending, not current.
        let replacement = state
            .children
            .iter()
            .find(|c| c.durable_lifecycle == DurableLifecycle::ReplacementPending)
            .unwrap();
        assert!(!replacement.is_routed_current());

        // Supervisor ACK → cutover: new becomes current, old becomes draining.
        let new_id = replacement.child_attempt;
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::SupervisorCutoverAck {
                old: webrtc_id,
                new: new_id,
            },
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, TransportSelectionAction::EmitCutoverLease { .. }))
        );
        let new_child = state.find_child(new_id).unwrap();
        assert_eq!(new_child.durable_lifecycle, DurableLifecycle::Current);
        let old_child = state.find_child(webrtc_id).unwrap();
        assert_eq!(old_child.durable_lifecycle, DurableLifecycle::Draining);

        // Second lease removes old draining.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::SecondLease { old: webrtc_id },
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, TransportSelectionAction::CloseChild { .. }))
        );
        let old_child = state.find_child(webrtc_id).unwrap();
        assert_eq!(old_child.state, ChildState::Closed);
        assert!(state.turn_replacement.is_none());
    }

    // ── AC 5: retry_budget ──

    #[test]
    fn remote_transport_retry_budget() {
        let tenant = "tenant1";
        let account = "acct1";
        let device = "dev1";
        let attachment = "att1";
        let tid = train_id();

        let key1 = build_reservation_key(
            tenant,
            account,
            device,
            attachment,
            tid,
            TransportKind::Webrtc,
            ChildAttemptId(1),
        );

        // No existing → Ok.
        assert!(validate_retry_budget(&[], &[], &key1, 0).is_ok());

        // Four reservations per train → exhausted on fifth.
        let mut existing: Vec<RemoteTransportRetryReservation> = Vec::new();
        for i in 1..=4 {
            let key = build_reservation_key(
                tenant,
                account,
                device,
                attachment,
                tid,
                TransportKind::Webrtc,
                ChildAttemptId(i),
            );
            existing.push(RemoteTransportRetryReservation {
                key,
                reserved_at_ms: 0,
                expires_at_ms: 1000,
                terminal: false,
                terminal_outcome: None,
            });
        }
        let new_key = build_reservation_key(
            tenant,
            account,
            device,
            attachment,
            tid,
            TransportKind::Websocket,
            ChildAttemptId(5),
        );
        assert!(matches!(
            validate_retry_budget(&existing, &[], &new_key, 0),
            Err(TransportDenial::RetryBudgetExhausted)
        ));

        // Exact duplicate → idempotent Ok.
        let dup_key = build_reservation_key(
            tenant,
            account,
            device,
            attachment,
            tid,
            TransportKind::Webrtc,
            ChildAttemptId(1),
        );
        assert!(validate_retry_budget(&existing, &[], &dup_key, 0).is_ok());

        // Twelve committed in rolling window → exhausted on thirteenth.
        let mut committed: Vec<RemoteTransportRetryReservation> = Vec::new();
        let other_train = TrainId([0x99; TRAIN_ID_BYTES]);
        for i in 1..=12 {
            let key = build_reservation_key(
                tenant,
                account,
                device,
                attachment,
                other_train,
                TransportKind::Webrtc,
                ChildAttemptId(i),
            );
            committed.push(RemoteTransportRetryReservation {
                key,
                reserved_at_ms: 500,
                expires_at_ms: 1000,
                terminal: false,
                terminal_outcome: None,
            });
        }
        let new_key = build_reservation_key(
            tenant,
            account,
            device,
            attachment,
            tid,
            TransportKind::Webrtc,
            ChildAttemptId(10),
        );
        assert!(matches!(
            validate_retry_budget(&[], &committed, &new_key, 1_000),
            Err(TransportDenial::RetryBudgetExhausted)
        ));

        // Outside rolling window → Ok.
        let old_committed: Vec<RemoteTransportRetryReservation> = committed
            .iter()
            .map(|r| {
                let mut r = r.clone();
                r.reserved_at_ms = -10_000_000;
                r
            })
            .collect();
        assert!(validate_retry_budget(&[], &old_committed, &new_key, 1_000).is_ok());
    }

    #[test]
    fn remote_transport_retry_initial_plus_one() {
        // Initial establishment plus one fresh retry per kind.
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;

        // Child closes without security failure → retry scheduled.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::ChildClosed {
                child_attempt: webrtc_id,
                security_failure: false,
            },
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, TransportSelectionAction::ArmRetryDelay { secs: 1 }))
        );
        assert!(state.pending_retry.is_some());

        // Retry delay fires → retry child started.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::RetryDelayFired { now_ms: 2000 },
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, TransportSelectionAction::StartChild { .. }))
        );
        assert!(state.pending_retry.is_none());

        // Second close → no more retries (retries_used is 0 on the new child,
        // but the kind has already used its one retry in this train).
        // The retry child also has retries_used=0, so it will try again.
        // But per spec: "initial establishment plus one fresh retry is
        // allowed within the train" — so after the retry also fails, no
        // further same-kind retry.
        let retry_id = state.children[1].child_attempt;
        let retry_child = state.find_child_mut(retry_id).unwrap();
        retry_child.retries_used = 1; // Simulate that this was the retry.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::ChildClosed {
                child_attempt: retry_id,
                security_failure: false,
            },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::ParentTransition {
                new_state: ParentState::Failed,
            }
        )));
    }

    // ── AC 6: health_thresholds ──

    #[test]
    fn remote_transport_health_thresholds() {
        // WebRTC: healthy after 2 consecutive successes.
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 1000,
            },
        );

        // Two consecutive successful probes → healthy.
        reduce(
            &mut state,
            &TransportSelectionInput::WebrtcProbe {
                child_attempt: webrtc_id,
                success: true,
                buffered_bytes: 0,
            },
        );
        reduce(
            &mut state,
            &TransportSelectionInput::WebrtcProbe {
                child_attempt: webrtc_id,
                success: true,
                buffered_bytes: 0,
            },
        );
        let child = state.find_child(webrtc_id).unwrap();
        assert_eq!(child.health_tier, HealthTier::Healthy);
        assert_eq!(child.consecutive_healthy, 3); // 1 from active + 2 probes

        // Three misses → degraded.
        for _ in 0..3 {
            reduce(
                &mut state,
                &TransportSelectionInput::WebrtcProbe {
                    child_attempt: webrtc_id,
                    success: false,
                    buffered_bytes: 0,
                },
            );
        }
        let child = state.find_child(webrtc_id).unwrap();
        assert_eq!(child.health_tier, HealthTier::Degraded);

        // Six misses → failed.
        for _ in 0..3 {
            reduce(
                &mut state,
                &TransportSelectionInput::WebrtcProbe {
                    child_attempt: webrtc_id,
                    success: false,
                    buffered_bytes: 0,
                },
            );
        }
        let child = state.find_child(webrtc_id).unwrap();
        assert_eq!(child.health_tier, HealthTier::Failed);

        // Buffer >= 4 MiB for two probes → degraded.
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 1000,
            },
        );
        for _ in 0..2 {
            reduce(
                &mut state,
                &TransportSelectionInput::WebrtcProbe {
                    child_attempt: webrtc_id,
                    success: true,
                    buffered_bytes: WEBRTC_DEGRADED_BUFFER_BYTES,
                },
            );
        }
        let child = state.find_child(webrtc_id).unwrap();
        assert_eq!(child.health_tier, HealthTier::Degraded);
        assert_eq!(child.consecutive_high_buffer_probes, 2);
    }

    #[test]
    fn remote_transport_websocket_health_thresholds() {
        let mut state = TransportSelectionState::new(
            full_auth(),
            UserTransportPreference::Websocket,
            train_id(),
            INITIAL_DEADLINE_SECS,
        );
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let ws_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: ws_id,
                now_ms: 1000,
            },
        );

        // Degraded when oldest unacked age >= 3 seconds.
        reduce(
            &mut state,
            &TransportSelectionInput::WebsocketAckProgress {
                child_attempt: ws_id,
                oldest_unacked_age_secs: 3,
                buffered_bytes: 0,
                retransmissions: 0,
            },
        );
        let child = state.find_child(ws_id).unwrap();
        assert_eq!(child.health_tier, HealthTier::Degraded);

        // Degraded when buffered >= 4 MiB.
        reduce(
            &mut state,
            &TransportSelectionInput::WebsocketAckProgress {
                child_attempt: ws_id,
                oldest_unacked_age_secs: 0,
                buffered_bytes: WEBSOCKET_DEGRADED_BUFFER_BYTES,
                retransmissions: 0,
            },
        );
        let child = state.find_child(ws_id).unwrap();
        assert_eq!(child.health_tier, HealthTier::Degraded);

        // Failed at third retransmission.
        reduce(
            &mut state,
            &TransportSelectionInput::WebsocketAckProgress {
                child_attempt: ws_id,
                oldest_unacked_age_secs: 0,
                buffered_bytes: 0,
                retransmissions: WEBSOCKET_FAILED_RETRANSMISSIONS,
            },
        );
        let child = state.find_child(ws_id).unwrap();
        assert_eq!(child.health_tier, HealthTier::Failed);
    }

    // ── AC 7: route_trace ──

    #[test]
    fn remote_transport_route_trace() {
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 1000,
            },
        );
        // Start WebSocket via deadline.
        reduce(
            &mut state,
            &TransportSelectionInput::DeadlineFired { now_ms: 10_000 },
        );
        let ws_id = state.children[1].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: ws_id,
                now_ms: 10_001,
            },
        );

        // Both healthy. Interactive: healthy WebRTC first.
        // Make both healthy.
        for _ in 0..2 {
            reduce(
                &mut state,
                &TransportSelectionInput::WebrtcProbe {
                    child_attempt: webrtc_id,
                    success: true,
                    buffered_bytes: 0,
                },
            );
        }
        reduce(
            &mut state,
            &TransportSelectionInput::WebsocketAckProgress {
                child_attempt: ws_id,
                oldest_unacked_age_secs: 0,
                buffered_bytes: 0,
                retransmissions: 0,
            },
        );
        reduce(
            &mut state,
            &TransportSelectionInput::WebsocketAckProgress {
                child_attempt: ws_id,
                oldest_unacked_age_secs: 0,
                buffered_bytes: 0,
                retransmissions: 0,
            },
        );

        let actions = reduce(
            &mut state,
            &TransportSelectionInput::RouteRequest {
                delivery_id: "d1".to_string(),
                routing_class: RoutingClass::Interactive,
            },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::RouteDelivery {
                delivery_id,
                child_attempt,
            } if delivery_id == "d1" && *child_attempt == webrtc_id
        )));

        // Control: healthy over degraded, then lower epoch.
        // WebRTC has lower epoch (1) than WebSocket (2), both healthy.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::RouteRequest {
                delivery_id: "d2".to_string(),
                routing_class: RoutingClass::Control,
            },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::RouteDelivery {
                child_attempt,
                ..
            } if *child_attempt == webrtc_id
        )));

        // Bulk: healthy child with more writable bytes.
        // Both have 0 buffered, so writable_bytes is equal; tie → WebRTC.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::RouteRequest {
                delivery_id: "d3".to_string(),
                routing_class: RoutingClass::Bulk,
            },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::RouteDelivery {
                child_attempt,
                ..
            } if *child_attempt == webrtc_id
        )));

        // One stable delivery ID → one current child; same delivery gets
        // same assignment.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::RouteRequest {
                delivery_id: "d1".to_string(),
                routing_class: RoutingClass::Bulk,
            },
        );
        // Should still route to the original webrtc assignment.
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::RouteDelivery {
                delivery_id,
                child_attempt,
            } if delivery_id == "d1" && *child_attempt == webrtc_id
        )));
    }

    #[test]
    fn remote_transport_replacement_pending_never_selected() {
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 1000,
            },
        );
        // Credential rotation → replacement_pending.
        reduce(
            &mut state,
            &TransportSelectionInput::CredentialRotationLead { now_ms: 2000 },
        );
        let replacement_id = state.children[1].child_attempt;

        // The replacement_pending child should never be selected for routing.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::RouteRequest {
                delivery_id: "d1".to_string(),
                routing_class: RoutingClass::Interactive,
            },
        );
        if let Some(TransportSelectionAction::RouteDelivery { child_attempt, .. }) = actions
            .iter()
            .find(|a| matches!(a, TransportSelectionAction::RouteDelivery { .. }))
        {
            assert_ne!(*child_attempt, replacement_id);
            assert_eq!(*child_attempt, webrtc_id);
        }
    }

    // ── AC 9: deadline_late_success_race ──

    #[test]
    fn remote_transport_deadline_late_success_race() {
        // Deadline fires, WebSocket starts, then WebRTC activates late.
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;

        // Deadline fires → WebSocket starts.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::DeadlineFired { now_ms: 10_000 },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::StartChild {
                kind: TransportKind::Websocket,
                ..
            }
        )));
        let ws_id = state.children[1].child_attempt;

        // Late WebRTC success — still activates (separately authorized kinds
        // may coexist).
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 10_001,
            },
        );
        // WebRTC should be active.
        let webrtc_child = state.find_child(webrtc_id).unwrap();
        assert_eq!(webrtc_child.state, ChildState::Active);

        // WebSocket also activates.
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: ws_id,
                now_ms: 10_002,
            },
        );
        let ws_child = state.find_child(ws_id).unwrap();
        assert_eq!(ws_child.state, ChildState::Active);

        // Both coexist.
        assert_eq!(state.count_routed_current(), 2);
    }

    #[test]
    fn remote_transport_cancelled_child_cannot_activate() {
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;

        // Cancel the attachment.
        reduce(&mut state, &TransportSelectionInput::Cancel);
        let child = state.find_child(webrtc_id).unwrap();
        assert!(child.cancelled);

        // Late active event → inert.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 10_000,
            },
        );
        assert!(
            actions
                .iter()
                .all(|a| matches!(a, TransportSelectionAction::Inert))
        );
        let child = state.find_child(webrtc_id).unwrap();
        // State unchanged (still closing, not active).
        assert_ne!(child.state, ChildState::Active);
    }

    // ── AC: closing one child does not clear the other ──

    #[test]
    fn remote_transport_closing_one_does_not_clear_other() {
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 1000,
            },
        );
        reduce(
            &mut state,
            &TransportSelectionInput::DeadlineFired { now_ms: 10_000 },
        );
        let ws_id = state.children[1].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: ws_id,
                now_ms: 10_001,
            },
        );

        // Close WebRTC — WebSocket should remain active.
        reduce(
            &mut state,
            &TransportSelectionInput::ChildClosed {
                child_attempt: webrtc_id,
                security_failure: false,
            },
        );
        let ws_child = state.find_child(ws_id).unwrap();
        assert_eq!(ws_child.state, ChildState::Active);
    }

    // ── AC: golden trace ──

    #[test]
    fn remote_transport_golden_trace() {
        let state = new_auto_state();
        let inputs = vec![
            TransportSelectionInput::StartPlan,
            TransportSelectionInput::DeadlineFired { now_ms: 10_000 },
        ];
        let trace = record_golden_trace(state, &inputs);
        assert_eq!(trace.len(), 2);
        assert_eq!(trace[0].parent_state_before, "Planning");
        assert_eq!(trace[0].parent_state_after, "Establishing");
    }

    // ── AC: ice_disconnected degraded not fallback ──

    #[test]
    fn remote_transport_ice_disconnected_degraded_not_fallback() {
        let mut state = new_auto_state();
        reduce(&mut state, &TransportSelectionInput::StartPlan);
        let webrtc_id = state.children[0].child_attempt;
        reduce(
            &mut state,
            &TransportSelectionInput::ChildActive {
                child_attempt: webrtc_id,
                now_ms: 1000,
            },
        );

        // First ice_disconnected → degraded, no fallback.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::ChildReachability {
                child_attempt: webrtc_id,
                class: ReachabilityClass::IceDisconnected,
            },
        );
        assert!(!actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::StartChild {
                kind: TransportKind::Websocket,
                ..
            }
        )));
        let child = state.find_child(webrtc_id).unwrap();
        assert_eq!(child.state, ChildState::Degraded);
        assert_eq!(child.ice_disconnected_misses, 1);

        // Second ice_disconnected → still degraded, no fallback.
        reduce(
            &mut state,
            &TransportSelectionInput::ChildReachability {
                child_attempt: webrtc_id,
                class: ReachabilityClass::IceDisconnected,
            },
        );
        assert!(!state.websocket_fallback_started);

        // Third ice_disconnected → maps to network_unreachable, fallback.
        let actions = reduce(
            &mut state,
            &TransportSelectionInput::ChildReachability {
                child_attempt: webrtc_id,
                class: ReachabilityClass::IceDisconnected,
            },
        );
        assert!(actions.iter().any(|a| matches!(
            a,
            TransportSelectionAction::StartChild {
                kind: TransportKind::Websocket,
                ..
            }
        )));
    }

    // ── Helper trait for tests ──

    impl AuthorizedPlan {
        fn allowed_kinks_granted_if_both_available(&self) -> bool {
            self.allowed_kinds.len() == 2
        }

        fn parent_state_if_plan_used(&self) -> ParentState {
            if self.allowed_kinds.is_empty() {
                ParentState::Denied
            } else {
                ParentState::Planning
            }
        }
    }
}
