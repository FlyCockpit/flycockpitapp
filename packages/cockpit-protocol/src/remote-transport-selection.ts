/**
 * Downgrade-resistant multi-transport connection orchestration — pure reducer.
 *
 * This module implements the transport-selection state machine that orchestrates
 * an authorized set of WebRTC and E2E WebSocket transport epochs without
 * downgrade. It prefers WebRTC for initial establishment, allows multiple
 * simultaneous read/write transports, and merges all operations through one
 * daemon-ordered idempotent logical attachment stream.
 *
 * The reducer is **pure**: it takes explicit `now`, persisted retry-budget
 * input, adapter events, and emitted commands. It never branches on raw
 * adapter/client strings — all platform errors are mapped to the closed
 * `RemoteReachabilityClass` / `RemoteTransportCloseReason` taxonomy by the
 * adapter before they reach the orchestrator. The operation ledger is
 * integrated by interface only.
 *
 * Cross-language contract: the constants and enums here mirror
 * `crates/cockpit-proto/src/remote_transport_selection.rs`, and the authorized
 * plan mirrors the Rust `AuthorizedPlan`. The committed fixtures under
 * `fixtures/remote-transport-selection/` are the single source of truth, split
 * by ownership: the `cockpit-proto` test target owns `vocabulary.json` /
 * `constants.json` (wire surface); the `cockpit-core` test target owns
 * `plan-matrix.json` / `traces.json` (behavior, produced by the real
 * `compute_authorized_plan` / `reduce`). This module's suite asserts the same
 * files through `computeAuthorizedPlan` and `transportSelectionReducer`.
 *
 * The authorized plan is the multi-denial Rust-aligned shape: `allowedKinds`,
 * a `denials` array drawn only from the closed {@link REMOTE_TRANSPORT_DENIALS}
 * vocabulary, `preference`, and `turnRequired`. `unavailable` consent withholds
 * **both** kinds (`ip_consent_denied`, empty `allowedKinds`); `relay_only`
 * consent or privacy `relay_only`/`turn_required` with `turnAvailable: false`
 * denies WebRTC only (`relay_required_turn_unavailable`) while WebSocket stays
 * authorized.
 *
 * Staging: this reducer is a staged foundation with **no production caller
 * yet** — the daemon/gateway wiring is owned by the
 * `wire-websocket-fallback-into-transport-selection` followup.
 *
 * @see remote-transport-selection-state-machine
 */

// ---------------------------------------------------------------------------
// Transport kinds and identity
// ---------------------------------------------------------------------------

/** The two physical transport kinds the orchestrator may establish. */
export type RemoteTransportKind = "webrtc" | "websocket";

export const REMOTE_TRANSPORT_KINDS: readonly RemoteTransportKind[] = ["webrtc", "websocket"];

/** A random 16-byte foreground train id, base64url-spelled (22 chars). */
export type RemoteTrainId = string;

/** A random 16-byte child-attempt id, base64url-spelled (22 chars). */
export type RemoteChildAttemptId = string;

/** A random 16-byte transport-epoch id, base64url-spelled (22 chars). */
export type RemoteTransportEpoch = string;

/** Monotonically increasing per-child generation within a train. */
export type RemoteChildGeneration = number;

// ---------------------------------------------------------------------------
// Parent and child state enums
// ---------------------------------------------------------------------------

/**
 * Parent orchestrator states. The parent owns the logical attachment's
 * transport plan and supervises every child.
 */
export const REMOTE_PARENT_STATES = [
  "planning",
  "establishing",
  "active",
  "degraded",
  "denied",
  "failed",
  "cancelled",
  "superseded",
] as const;
export type RemoteParentState = (typeof REMOTE_PARENT_STATES)[number];

/**
 * Ordinary child states. Every child owns a distinct child attempt, bilateral
 * proofs, transcript, and transport epoch.
 */
export const REMOTE_ORDINARY_CHILD_STATES = [
  "pending",
  "authenticating",
  "active",
  "degraded",
  "closing",
  "closed",
] as const;
export type RemoteOrdinaryChildState = (typeof REMOTE_ORDINARY_CHILD_STATES)[number];

/**
 * The exact durable lifecycle of a TURN replacement pair. Transport adapter
 * states cannot invent a fourth durable lifecycle.
 */
export const REMOTE_TURN_LIFECYCLE = ["current", "replacement_pending", "draining"] as const;
export type RemoteTurnLifecycle = (typeof REMOTE_TURN_LIFECYCLE)[number];

// ---------------------------------------------------------------------------
// User transport preference
// ---------------------------------------------------------------------------

/**
 * User transport preference. It can narrow only: `webrtc` never starts
 * fallback, `websocket` starts only authorized fallback, and `auto` uses the
 * rules below. If the selected kind is disallowed/unavailable, the orchestrator
 * returns a typed denial; it never silently overrides user force.
 */
export const REMOTE_USER_PREFERENCES = ["auto", "webrtc", "websocket"] as const;
export type RemoteUserPreference = (typeof REMOTE_USER_PREFERENCES)[number];

// ---------------------------------------------------------------------------
// Closed reachability and close-reason taxonomy
// ---------------------------------------------------------------------------

/**
 * Closed reachability classes reported by adapters — the complete set, mirroring
 * the Rust `ReachabilityClass` serde vocabulary (including `ice_disconnected`,
 * which appears last in `vocabulary.json`).
 *
 * `ice_disconnected` is DEGRADED, not fallback: it does NOT itself trigger
 * fallback. It only maps to `network_unreachable` after 3 consecutive 5-second
 * liveness probes fail (see {@link iceDisconnectedToReachability}). The classes
 * that DO trigger fallback for `auto` preference are the strict subset
 * {@link REMOTE_REACHABILITY_FALLBACK_CLASSES}.
 */
export const REMOTE_REACHABILITY_CLASSES = [
  "ice_no_candidate_pair",
  "ice_timeout",
  "network_unreachable",
  "turn_unreachable",
  "ice_disconnected",
] as const;
export type RemoteReachabilityClass = (typeof REMOTE_REACHABILITY_CLASSES)[number];

/**
 * The reachability classes that directly trigger fallback under `auto`. This is
 * {@link REMOTE_REACHABILITY_CLASSES} minus the degraded-only `ice_disconnected`
 * — encoding the non-fallback handling of `ice_disconnected` explicitly so it
 * cannot silently drift into a fallback trigger.
 */
export const REMOTE_REACHABILITY_FALLBACK_CLASSES: readonly RemoteReachabilityClass[] = [
  "ice_no_candidate_pair",
  "ice_timeout",
  "network_unreachable",
  "turn_unreachable",
];

/**
 * The complete closed-reason taxonomy. Security/policy/consent failures are
 * terminal and never fall back. Reachability failures may fall back (for
 * `auto`/`websocket` preference). The orchestrator never branches on raw
 * adapter strings — adapters map platform errors into this closed set.
 */
export const REMOTE_TRANSPORT_CLOSE_REASONS = [
  "ice_no_candidate_pair",
  "ice_timeout",
  "network_unreachable",
  "turn_unreachable",
  "auth_failure",
  "proof_failure",
  "certificate_failure",
  "version_failure",
  "integrity_failure",
  "revocation_failure",
  "policy_failure",
  "quota_failure",
  "consent_failure",
  "local_close",
  "peer_close",
  "superseded",
] as const;
export type RemoteTransportCloseReason = (typeof REMOTE_TRANSPORT_CLOSE_REASONS)[number];

/** Reasons that are terminal and must never trigger fallback. */
export const REMOTE_TERMINAL_CLOSE_REASONS: ReadonlySet<RemoteTransportCloseReason> = Object.freeze(
  new Set<RemoteTransportCloseReason>([
    "auth_failure",
    "proof_failure",
    "certificate_failure",
    "version_failure",
    "integrity_failure",
    "revocation_failure",
    "policy_failure",
    "quota_failure",
    "consent_failure",
  ]),
);

/** Reasons that are reachability failures and may trigger fallback. */
export const REMOTE_REACHABILITY_CLOSE_REASONS: ReadonlySet<RemoteTransportCloseReason> =
  Object.freeze(
    new Set<RemoteTransportCloseReason>([
      "ice_no_candidate_pair",
      "ice_timeout",
      "network_unreachable",
      "turn_unreachable",
    ]),
  );

/** Is a close reason terminal (security/policy/consent) — never fallback? */
export function isTerminalCloseReason(reason: RemoteTransportCloseReason): boolean {
  return REMOTE_TERMINAL_CLOSE_REASONS.has(reason);
}

/** Is a close reason a reachability failure — may fallback under auto? */
export function isReachabilityCloseReason(reason: RemoteTransportCloseReason): boolean {
  return REMOTE_REACHABILITY_CLOSE_REASONS.has(reason);
}

// ---------------------------------------------------------------------------
// Second-child reasons (the only legal reasons to start a second kind)
// ---------------------------------------------------------------------------

/**
 * The exact named continuity reasons that permit a second authorized kind once
 * one child is active. It never starts merely for speculative racing.
 */
export const REMOTE_SECOND_CHILD_REASONS = [
  "preferred_path_recovery",
  "network_handoff",
  "operator_force",
  "degraded_path_replacement",
  "credential_rotation",
] as const;
export type RemoteSecondChildReason = (typeof REMOTE_SECOND_CHILD_REASONS)[number];

// ---------------------------------------------------------------------------
// Routing lanes (mirror remote-transport-lanes)
// ---------------------------------------------------------------------------

/**
 * The closed routing/route-lane class vocabulary — exactly the Rust
 * `RoutingClass` serde `snake_case` names committed in `vocabulary.json`. The
 * TS type is derived from this constant so the fixture assertion compares the
 * exported constant directly (never a hand-written literal that could drift).
 */
export const REMOTE_ROUTE_LANES = ["control", "interactive", "bulk"] as const;
export type RemoteRouteLane = (typeof REMOTE_ROUTE_LANES)[number];

// ---------------------------------------------------------------------------
// Fixed constants — downgrade-resistant contract
// ---------------------------------------------------------------------------

/**
 * Initial-establishment deadline for `auto`: start WebSocket only after a
 * server-signed foreground deadline of this many seconds expires without
 * active WebRTC, or the adapter reports a closed reachability class.
 */
export const REMOTE_AUTO_INITIAL_DEADLINE_SECONDS = 10;
export const REMOTE_AUTO_INITIAL_DEADLINE_MIN_SECONDS = 3;
export const REMOTE_AUTO_INITIAL_DEADLINE_MAX_SECONDS = 30;
export const REMOTE_WEBRTC_PROBE_INTERVAL_SECONDS = 5;
export const REMOTE_WEBRTC_DISCONNECTED_FAIL_PROBES = 3;
export const REMOTE_WEBRTC_HEALTHY_SUCCESS_PROBES = 2;
export const REMOTE_WEBRTC_DEGRADED_MISS_PROBES = 3;
export const REMOTE_WEBRTC_FAILED_MISS_PROBES = 6;
export const REMOTE_WEBRTC_DEGRADED_BUFFER_BYTES = 4 * 1024 * 1024;
export const REMOTE_WEBRTC_DEGRADED_BUFFER_PROBES = 2;
export const REMOTE_WEBSOCKET_DEGRADED_OLDEST_UNACKED_SECONDS = 3;
export const REMOTE_WEBSOCKET_DEGRADED_BUFFER_BYTES = 4 * 1024 * 1024;
export const REMOTE_WEBSOCKET_FAILED_RETRANSMISSION = 3;
export const REMOTE_HEALTH_RECOVERY_INTERVALS = 2;
export const REMOTE_MAX_RETRIES_PER_KIND = 1;
export const REMOTE_RETRY_DELAY_MS = 1000;
export const REMOTE_TURN_DRAIN_MAX_SECONDS = 30;

// ---------------------------------------------------------------------------
// Caps — routed-current and pending
// ---------------------------------------------------------------------------

export const REMOTE_MAX_CURRENT_WEBRTC = 1;
export const REMOTE_MAX_CURRENT_WEBSOCKET = 1;
export const REMOTE_MAX_PENDING_CHILDREN_TOTAL = 2;
export const REMOTE_MAX_PENDING_CHILDREN_PER_KIND = 1;
export const REMOTE_MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT = 3;
export const REMOTE_MAX_PHYSICAL_CHILDREN_NORMAL = 2;

// ---------------------------------------------------------------------------
// Retry budget — Postgres durable authority
// ---------------------------------------------------------------------------

export const REMOTE_RETRY_BUDGET_MAX_PER_TRAIN = 4;
export const REMOTE_RETRY_BUDGET_MAX_PER_HOUR = 12;
export const REMOTE_RETRY_BUDGET_WINDOW_SECONDS = 3600;
export const REMOTE_TRAIN_ID_BYTES = 16;
export const REMOTE_RETRY_RESERVATION_SCHEMA = "RemoteTransportRetryReservation" as const;

/**
 * The closed reservation terminal-outcome vocabulary — exactly the Rust
 * `ReservationOutcome` serde `snake_case` names committed in `vocabulary.json`
 * (`active | cancelled | failed | reservation_failed`). `failed` is the terminal
 * outcome for a reservation whose child attempt failed after activation; it is
 * distinct from `reservation_failed` (the reservation itself could not be made).
 */
export const REMOTE_RESERVATION_TERMINAL_OUTCOMES = [
  "active",
  "cancelled",
  "failed",
  "reservation_failed",
] as const;
export type RemoteReservationTerminalOutcome =
  (typeof REMOTE_RESERVATION_TERMINAL_OUTCOMES)[number];

export interface RemoteTransportRetryReservationV1 {
  readonly schemaVersion: 1;
  readonly reservationId: string;
  readonly tenantId: string;
  readonly accountId: string;
  readonly clientDeviceId: string;
  readonly logicalAttachmentId: string;
  readonly trainId: RemoteTrainId;
  readonly transportKind: RemoteTransportKind;
  readonly childAttemptId: RemoteChildAttemptId;
  readonly reservationType: "initial" | "retry" | "replacement";
  readonly reservedAtMs: number;
  readonly expiresAtMs: number;
  readonly terminalOutcome: RemoteReservationTerminalOutcome | null;
  readonly terminalAtMs: number | null;
}

export interface RemoteRetryBudgetSnapshot {
  readonly trainReservations: readonly RemoteTransportRetryReservationV1[];
  readonly rollingWindowReservations: readonly RemoteTransportRetryReservationV1[];
}

export type RemoteRetryReservationOutcome =
  | { readonly status: "reserved"; readonly reservation: RemoteTransportRetryReservationV1 }
  | { readonly status: "duplicate"; readonly reservation: RemoteTransportRetryReservationV1 }
  | { readonly status: "rejected"; readonly reason: RemoteRetryBudgetDenialReason };

export const REMOTE_RETRY_BUDGET_DENIAL_REASONS = [
  "max_per_train_exceeded",
  "max_per_hour_exceeded",
  "duplicate_child_attempt",
  "database_outage",
  "kind_retry_exhausted",
] as const;
export type RemoteRetryBudgetDenialReason = (typeof REMOTE_RETRY_BUDGET_DENIAL_REASONS)[number];

// ---------------------------------------------------------------------------
// Plan inputs — policy / capability / consent / quota
// ---------------------------------------------------------------------------

/**
 * The closed consent-capability tri-state — exactly the Rust
 * `ConsentCapability` serde `snake_case` names committed in `vocabulary.json`.
 * The TS type is derived from this constant so the fixture assertion compares
 * the exported constant directly (never a hand-written literal).
 */
export const REMOTE_IP_CONSENT_CAPABILITIES = [
  "direct_allowed",
  "relay_only",
  "unavailable",
] as const;
export type RemoteIpConsentTriState = (typeof REMOTE_IP_CONSENT_CAPABILITIES)[number];
export type RemoteParticipantPrivacy = "direct_allowed" | "turn_required" | "relay_only";

export interface RemoteClientCapabilities {
  readonly webrtcSupported: boolean;
  readonly websocketSupported: boolean;
}

export interface RemoteLiveQuota {
  readonly remainingReservationsThisHour: number;
  readonly remainingBytes: number;
  readonly remainingAllocationSeconds: number;
  readonly exhausted: boolean;
}

export interface RemoteTransportPlanInput {
  readonly deploymentWebrtc: boolean;
  readonly deploymentWebsocket: boolean;
  readonly serviceWebrtc: boolean;
  readonly serviceWebsocket: boolean;
  readonly tenantWebrtc: boolean;
  readonly tenantWebsocket: boolean;
  readonly daemonWebrtc: boolean;
  readonly daemonWebsocket: boolean;
  readonly ipConsent: RemoteIpConsentTriState;
  readonly participantPrivacy: RemoteParticipantPrivacy;
  /**
   * Whether an authorized TURN relay is currently available. When consent or
   * privacy force TURN and this is `false`, WebRTC is denied
   * (`relay_required_turn_unavailable`) while WebSocket stays authorized.
   */
  readonly turnAvailable: boolean;
  readonly liveQuota: RemoteLiveQuota;
  readonly clientCapabilities: RemoteClientCapabilities;
  readonly userPreference: RemoteUserPreference;
}

/**
 * The single closed denial vocabulary — exactly the Rust `TransportDenial`
 * serde `snake_case` names (committed in `vocabulary.json`). There is no
 * parallel TypeScript-only denial string.
 */
export const REMOTE_TRANSPORT_DENIALS = [
  "kind_not_authorized",
  "kind_not_available",
  "ip_consent_denied",
  "quota_exhausted",
  "client_capability_missing",
  "preference_disallowed",
  "policy_denied",
  "relay_required_turn_unavailable",
  "retry_budget_exhausted",
  "database_outage",
  "security_failure",
  "child_cap_exceeded",
] as const;
export type RemoteTransportDenial = (typeof REMOTE_TRANSPORT_DENIALS)[number];

/**
 * The authorized plan, identical in shape to the Rust `AuthorizedPlan`:
 * `allowedKinds` (presence of `webrtc` / `websocket`, not separate booleans),
 * a multi-entry `denials` array of the closed vocabulary (empty when fully
 * allowed), the `preference`, and a `turnRequired` flag.
 */
export interface RemoteTransportAuthorizedPlan {
  readonly allowedKinds: readonly RemoteTransportKind[];
  readonly denials: readonly RemoteTransportDenial[];
  readonly preference: RemoteUserPreference;
  readonly turnRequired: boolean;
}

// ---------------------------------------------------------------------------
// Health probe inputs
// ---------------------------------------------------------------------------

export interface RemoteWebRtcHealthProbe {
  readonly kind: "webrtc";
  readonly childAttemptId: RemoteChildAttemptId;
  readonly atMs: number;
  readonly success: boolean;
  readonly bufferedBytes: number;
}

export interface RemoteWebSocketAckSample {
  readonly kind: "websocket";
  readonly childAttemptId: RemoteChildAttemptId;
  readonly atMs: number;
  readonly oldestUnackedAgeSeconds: number;
  readonly bufferedBytes: number;
  readonly retransmissionCount: number;
}

export type RemoteHealthSample = RemoteWebRtcHealthProbe | RemoteWebSocketAckSample;

/**
 * The closed health-tier vocabulary — exactly the Rust `HealthTier` serde
 * `snake_case` names committed in `vocabulary.json`. The TS type is derived from
 * this constant so the fixture assertion compares the exported constant directly
 * (never a hand-written literal).
 */
export const REMOTE_HEALTH_TIERS = ["healthy", "degraded", "failed"] as const;
export type RemoteChildHealth = (typeof REMOTE_HEALTH_TIERS)[number];

// ---------------------------------------------------------------------------
// Child record
// ---------------------------------------------------------------------------

export interface RemoteTransportChild {
  readonly childAttemptId: RemoteChildAttemptId;
  readonly transportKind: RemoteTransportKind;
  readonly transportEpoch: RemoteTransportEpoch;
  readonly generation: RemoteChildGeneration;
  readonly state: RemoteOrdinaryChildState;
  readonly turnLifecycle: RemoteTurnLifecycle | null;
  readonly health: RemoteChildHealth;
  readonly consecutiveHealthy: number;
  readonly consecutiveMisses: number;
  readonly consecutiveBufferHigh: number;
  /**
   * Buffered (undrained) bytes on this transport, mirroring the Rust
   * `ChildRecord::buffered_bytes`. Bulk routing ranks by the derived writable
   * capacity ({@link childWritableBytes}), so a congested child sinks in the
   * bulk ordering exactly as it does in the Rust source of truth.
   */
  readonly bufferedBytes: number;
  readonly pendingTimerId: string | null;
  readonly secondChildReason: RemoteSecondChildReason | null;
  readonly deadlineExpiresAtMs: number | null;
  readonly closedReason: RemoteTransportCloseReason | null;
}

// ---------------------------------------------------------------------------
// Emitted commands (pure actions)
// ---------------------------------------------------------------------------

export type RemoteTransportCommand =
  | {
      readonly kind: "start_child";
      readonly transportKind: RemoteTransportKind;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly transportEpoch: RemoteTransportEpoch;
      readonly generation: RemoteChildGeneration;
      readonly reservationType: "initial" | "retry" | "replacement";
      readonly secondChildReason: RemoteSecondChildReason | null;
    }
  | {
      readonly kind: "schedule_deadline_timer";
      readonly timerId: string;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly fireAtMs: number;
      readonly deadlineSeconds: number;
    }
  | { readonly kind: "cancel_timer"; readonly timerId: string }
  | {
      readonly kind: "schedule_retry";
      readonly timerId: string;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly transportKind: RemoteTransportKind;
      readonly fireAtMs: number;
      readonly delayMs: number;
    }
  | {
      readonly kind: "schedule_liveness_probe";
      readonly timerId: string;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly fireAtMs: number;
      readonly intervalSeconds: number;
    }
  | {
      readonly kind: "begin_turn_replacement";
      readonly currentChildAttemptId: RemoteChildAttemptId;
      readonly replacementChildAttemptId: RemoteChildAttemptId;
      readonly transportEpoch: RemoteTransportEpoch;
      readonly reason: RemoteSecondChildReason;
    }
  | {
      readonly kind: "commit_connection_lease";
      readonly leaseId: string;
      readonly currentChildAttemptIds: readonly RemoteChildAttemptId[];
      readonly drainingChildAttemptIds: readonly RemoteChildAttemptId[];
    }
  | {
      readonly kind: "route_delivery";
      readonly deliveryId: string;
      readonly lane: RemoteRouteLane;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly payloadBytes: number;
    }
  | {
      readonly kind: "failover_resend";
      readonly deliveryId: string;
      readonly targetChildAttemptId: RemoteChildAttemptId;
    }
  | { readonly kind: "deny"; readonly denials: readonly RemoteTransportDenial[] }
  | {
      readonly kind: "close_child";
      readonly childAttemptId: RemoteChildAttemptId;
      readonly reason: RemoteTransportCloseReason;
    }
  | {
      readonly kind: "record_ledger_mutation";
      readonly deliveryId: string;
      readonly childAttemptId: RemoteChildAttemptId;
    };

// ---------------------------------------------------------------------------
// Adapter events (inputs to the reducer)
// ---------------------------------------------------------------------------

export type RemoteTransportEvent =
  | {
      readonly kind: "plan_requested";
      readonly atMs: number;
      readonly input: RemoteTransportPlanInput;
      readonly trainId: RemoteTrainId;
    }
  | {
      readonly kind: "child_attempt_reserved";
      readonly atMs: number;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly transportKind: RemoteTransportKind;
      readonly transportEpoch: RemoteTransportEpoch;
      readonly generation: RemoteChildGeneration;
      readonly reservation: RemoteTransportRetryReservationV1;
    }
  | {
      readonly kind: "child_reservation_rejected";
      readonly atMs: number;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly transportKind: RemoteTransportKind;
      readonly reason: RemoteRetryBudgetDenialReason;
    }
  | {
      readonly kind: "child_authenticating";
      readonly atMs: number;
      readonly childAttemptId: RemoteChildAttemptId;
    }
  | {
      readonly kind: "child_active";
      readonly atMs: number;
      readonly childAttemptId: RemoteChildAttemptId;
    }
  | {
      readonly kind: "child_degraded_signal";
      readonly atMs: number;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly signal: "ice_disconnected";
    }
  | {
      readonly kind: "child_closed";
      readonly atMs: number;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly reason: RemoteTransportCloseReason;
    }
  | { readonly kind: "health_probe"; readonly atMs: number; readonly sample: RemoteHealthSample }
  | {
      readonly kind: "deadline_timer_fired";
      readonly atMs: number;
      readonly timerId: string;
      readonly childAttemptId: RemoteChildAttemptId;
    }
  | {
      /**
       * The injected retry delay elapsed for the pending same-kind retry. This
       * mirrors the Rust `RetryDelayFired` input: the retried child attempt is
       * allocated when the prior child closed (into the pending-retry slot), and
       * this event promotes it into a live `start_child`. (Renamed from the
       * old `retry_timer_fired`; the retry model now matches the canonical Rust
       * `pending_retry`/`kind_retries` shape rather than a per-child counter.)
       */
      readonly kind: "retry_delay_fired";
      readonly atMs: number;
    }
  | {
      readonly kind: "liveness_probe_timer_fired";
      readonly atMs: number;
      readonly timerId: string;
      readonly childAttemptId: RemoteChildAttemptId;
    }
  | {
      readonly kind: "second_child_requested";
      readonly atMs: number;
      readonly reason: RemoteSecondChildReason;
      readonly childAttemptId: RemoteChildAttemptId;
      readonly transportEpoch: RemoteTransportEpoch;
    }
  | {
      /**
       * The TURN credential-rotation renewal lead was reached (the caller derives
       * the lead from the credential TTL via `renewal_lead_seconds`). This mirrors
       * the Rust `CredentialRotationLead` input and is handled by a dedicated
       * reducer path that mirrors `reduce_credential_rotation`: it requires an
       * eligible live CURRENT WebRTC child and enforces the authorized plan +
       * replacement-pair / physical-cap constraints, and is INERT otherwise. It
       * is DISTINCT from `second_child_requested{reason:"credential_rotation"}`
       * and never admits a new kind — in particular it never starts WebRTC from a
       * WebSocket-only plan.
       */
      readonly kind: "credential_rotation_lead";
      readonly atMs: number;
    }
  | {
      readonly kind: "lease_supervisor_acked";
      readonly atMs: number;
      readonly leaseId: string;
      readonly currentChildAttemptIds: readonly RemoteChildAttemptId[];
      readonly drainingChildAttemptIds: readonly RemoteChildAttemptId[];
    }
  | {
      readonly kind: "route_request";
      readonly atMs: number;
      readonly deliveryId: string;
      readonly lane: RemoteRouteLane;
      readonly payloadBytes: number;
    }
  | { readonly kind: "background"; readonly atMs: number }
  | { readonly kind: "cancel"; readonly atMs: number }
  | { readonly kind: "revoke"; readonly atMs: number }
  | { readonly kind: "supersede"; readonly atMs: number };

// ---------------------------------------------------------------------------
// Orchestrator state
// ---------------------------------------------------------------------------

export interface RemoteTransportOrchestratorState {
  readonly parentState: RemoteParentState;
  readonly trainId: RemoteTrainId | null;
  readonly plan: RemoteTransportAuthorizedPlan | null;
  readonly children: readonly RemoteTransportChild[];
  readonly activeLease: {
    readonly leaseId: string;
    readonly currentChildAttemptIds: readonly RemoteChildAttemptId[];
    readonly drainingChildAttemptIds: readonly RemoteChildAttemptId[];
    readonly supervisorAcked: boolean;
  } | null;
  readonly pendingTimers: readonly string[];
  readonly deliveryAssignments: ReadonlyMap<string, RemoteChildAttemptId>;
  readonly ledgerDeliveries: ReadonlyMap<string, readonly RemoteChildAttemptId[]>;
  /**
   * The same-kind retry awaiting its injected delay, mirroring the Rust
   * `pending_retry` slot: the retried child attempt id/epoch are allocated when
   * the prior child closes and consumed by `retry_delay_fired`.
   */
  readonly pendingRetry: {
    readonly kind: RemoteTransportKind;
    readonly childAttemptId: RemoteChildAttemptId;
    readonly transportEpoch: RemoteTransportEpoch;
  } | null;
  /**
   * Per-kind retries already used in this train, mirroring the Rust
   * `kind_retries_used`. Bounds same-kind retries to {@link REMOTE_MAX_RETRIES_PER_KIND}.
   */
  readonly kindRetries: { readonly webrtc: number; readonly websocket: number };
  readonly lastEventAtMs: number;
}

export const REMOTE_TRANSPORT_SELECTION_SCHEMA_VERSION = 1 as const;

export function initialTransportOrchestratorState(): RemoteTransportOrchestratorState {
  return {
    parentState: "planning",
    trainId: null,
    plan: null,
    children: [],
    activeLease: null,
    pendingTimers: [],
    deliveryAssignments: new Map(),
    ledgerDeliveries: new Map(),
    pendingRetry: null,
    kindRetries: { webrtc: 0, websocket: 0 },
    lastEventAtMs: 0,
  };
}

// ---------------------------------------------------------------------------
// Plan computation — authorization matrix
// ---------------------------------------------------------------------------

/**
 * Compute the authorized plan. This mirrors the Rust `compute_authorized_plan`
 * byte-for-byte (see `plan-matrix.json`):
 *
 * - `ipConsent === "unavailable"` withholds **both** kinds with
 *   `ip_consent_denied` and an empty `allowedKinds`.
 * - `relay_only` consent, or privacy `relay_only`/`turn_required`, force TURN
 *   for WebRTC (`turnRequired: true`); with `turnAvailable: false`, WebRTC
 *   alone is denied `relay_required_turn_unavailable` while WebSocket stays
 *   authorized.
 * - Otherwise each kind is admitted when its own authorization and client
 *   capability allow, narrowed by preference and cleared wholly by quota.
 */
export function computeAuthorizedPlan(
  input: RemoteTransportPlanInput,
): RemoteTransportAuthorizedPlan {
  // `unavailable` consent is a hard gate that PRECEDES per-kind authorization:
  // neither kind is admitted and the denial is ALWAYS `ip_consent_denied`, never
  // masked by a per-kind `kind_not_authorized` / `client_capability_missing`
  // (which would happen if the per-kind sweep ran first and a kind was also
  // unauthorized). Mirrors the Rust `compute_authorized_plan` early return.
  if (input.ipConsent === "unavailable") {
    return {
      allowedKinds: [],
      denials: ["ip_consent_denied"],
      preference: input.userPreference,
      turnRequired: false,
    };
  }

  const turnForced =
    input.ipConsent === "relay_only" ||
    input.participantPrivacy === "relay_only" ||
    input.participantPrivacy === "turn_required";
  const turnRequired = turnForced;

  // A kind is authorized when its whole policy meet holds (deployment, service,
  // tenant, daemon), tracked separately from the passive client capability so
  // the denial reasons match Rust.
  const webrtcAuthorized =
    input.deploymentWebrtc && input.serviceWebrtc && input.tenantWebrtc && input.daemonWebrtc;
  const websocketAuthorized =
    input.deploymentWebsocket &&
    input.serviceWebsocket &&
    input.tenantWebsocket &&
    input.daemonWebsocket;

  const webrtc = admitKind(
    webrtcAuthorized,
    input.clientCapabilities.webrtcSupported,
    turnForced && !input.turnAvailable,
  );
  // The TURN gate revokes only WebRTC; WebSocket is independently authorized.
  const websocket = admitKind(
    websocketAuthorized,
    input.clientCapabilities.websocketSupported,
    false,
  );

  const allowedKinds: RemoteTransportKind[] = [];
  const denials: RemoteTransportDenial[] = [];

  switch (input.userPreference) {
    case "auto":
      pushKind("webrtc", webrtc, allowedKinds, denials);
      pushKind("websocket", websocket, allowedKinds, denials);
      break;
    case "webrtc":
      if (webrtc === null) {
        allowedKinds.push("webrtc");
      } else {
        denials.push(webrtc);
        denials.push("preference_disallowed");
      }
      break;
    case "websocket":
      if (websocket === null) {
        allowedKinds.push("websocket");
      } else {
        denials.push(websocket);
        denials.push("preference_disallowed");
      }
      break;
    default: {
      const _exhaustive: never = input.userPreference;
      throw new Error(`unreachable user preference: ${_exhaustive}`);
    }
  }

  if (input.liveQuota.exhausted) {
    allowedKinds.length = 0;
    denials.push("quota_exhausted");
  }

  if (allowedKinds.length === 0 && denials.length === 0) {
    denials.push("policy_denied");
  }

  return {
    allowedKinds,
    denials: dedupeAdjacent(denials),
    preference: input.userPreference,
    turnRequired,
  };
}

/**
 * The single highest-precedence denial for a kind, or `null` when admitted.
 * Consent unavailability is handled ahead of this sweep in
 * {@link computeAuthorizedPlan}, so it is not a parameter here.
 */
function admitKind(
  authorized: boolean,
  clientSupported: boolean,
  turnGateDenied: boolean,
): RemoteTransportDenial | null {
  if (!authorized) return "kind_not_authorized";
  if (!clientSupported) return "client_capability_missing";
  if (turnGateDenied) return "relay_required_turn_unavailable";
  return null;
}

function pushKind(
  kind: RemoteTransportKind,
  admission: RemoteTransportDenial | null,
  allowedKinds: RemoteTransportKind[],
  denials: RemoteTransportDenial[],
): void {
  if (admission === null) {
    allowedKinds.push(kind);
  } else {
    denials.push(admission);
  }
}

/** Collapse consecutive duplicate denials (matching Rust `Vec::dedup`). */
function dedupeAdjacent(denials: readonly RemoteTransportDenial[]): RemoteTransportDenial[] {
  const out: RemoteTransportDenial[] = [];
  for (const denial of denials) {
    if (out[out.length - 1] !== denial) out.push(denial);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Deadline validation
// ---------------------------------------------------------------------------

export function validateAutoDeadlineSeconds(
  seconds: number,
): { readonly ok: true } | { readonly ok: false; readonly reason: "out_of_range" } {
  if (
    !Number.isInteger(seconds) ||
    seconds < REMOTE_AUTO_INITIAL_DEADLINE_MIN_SECONDS ||
    seconds > REMOTE_AUTO_INITIAL_DEADLINE_MAX_SECONDS
  ) {
    return { ok: false, reason: "out_of_range" };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Caps enforcement
// ---------------------------------------------------------------------------

export function countCurrentChildren(
  children: readonly RemoteTransportChild[],
  kind: RemoteTransportKind,
): number {
  return children.filter(
    (c) =>
      c.transportKind === kind &&
      (c.state === "active" || c.state === "degraded") &&
      c.turnLifecycle !== "draining",
  ).length;
}

export function countPendingChildren(
  children: readonly RemoteTransportChild[],
  kind: RemoteTransportKind,
): number {
  return children.filter(
    (c) => c.transportKind === kind && (c.state === "pending" || c.state === "authenticating"),
  ).length;
}

export function countAllPendingChildren(children: readonly RemoteTransportChild[]): number {
  return children.filter((c) => c.state === "pending" || c.state === "authenticating").length;
}

export function countPhysicalChildren(children: readonly RemoteTransportChild[]): number {
  return children.filter((c) => c.turnLifecycle !== "draining").length;
}

export function checkChildCaps(
  children: readonly RemoteTransportChild[],
  kind: RemoteTransportKind,
  isReplacement: boolean,
): { readonly ok: true } | { readonly ok: false; readonly reason: RemoteChildCapDenial } {
  if (isReplacement && kind === "webrtc") {
    const turnPending = children.filter(
      (c) => c.transportKind === "webrtc" && c.turnLifecycle === "replacement_pending",
    ).length;
    if (turnPending >= 1) {
      return { ok: false, reason: "turn_replacement_already_pending" };
    }
    return { ok: true };
  }
  const currentCount = countCurrentChildren(children, kind);
  const maxCurrent = kind === "webrtc" ? REMOTE_MAX_CURRENT_WEBRTC : REMOTE_MAX_CURRENT_WEBSOCKET;
  if (currentCount >= maxCurrent) {
    return { ok: false, reason: "current_cap_exceeded" };
  }
  const pendingCount = countPendingChildren(children, kind);
  if (pendingCount >= REMOTE_MAX_PENDING_CHILDREN_PER_KIND) {
    return { ok: false, reason: "pending_cap_per_kind_exceeded" };
  }
  const allPending = countAllPendingChildren(children);
  if (allPending >= REMOTE_MAX_PENDING_CHILDREN_TOTAL) {
    return { ok: false, reason: "pending_cap_total_exceeded" };
  }
  return { ok: true };
}

export type RemoteChildCapDenial =
  | "current_cap_exceeded"
  | "pending_cap_per_kind_exceeded"
  | "pending_cap_total_exceeded"
  | "turn_replacement_already_pending";

export function physicalChildCap(turnReplacementInProgress: boolean): number {
  return turnReplacementInProgress
    ? REMOTE_MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT
    : REMOTE_MAX_PHYSICAL_CHILDREN_NORMAL;
}

// ---------------------------------------------------------------------------
// Retry budget enforcement
// ---------------------------------------------------------------------------

export function evaluateRetryBudget(
  snapshot: RemoteRetryBudgetSnapshot,
  request: {
    readonly trainId: RemoteTrainId;
    readonly transportKind: RemoteTransportKind;
    readonly childAttemptId: RemoteChildAttemptId;
    readonly reservationType: "initial" | "retry" | "replacement";
  },
  nowMs: number,
): RemoteRetryReservationOutcome {
  const trainMatch = snapshot.trainReservations.find(
    (r) => r.trainId === request.trainId && r.childAttemptId === request.childAttemptId,
  );
  if (trainMatch !== undefined) {
    return { status: "duplicate", reservation: trainMatch };
  }
  const trainCount = snapshot.trainReservations.length;
  if (trainCount >= REMOTE_RETRY_BUDGET_MAX_PER_TRAIN) {
    return { status: "rejected", reason: "max_per_train_exceeded" };
  }
  const windowStartMs = nowMs - REMOTE_RETRY_BUDGET_WINDOW_SECONDS * 1000;
  const seenAttempts = new Set<string>();
  let rollingCount = 0;
  for (const r of snapshot.rollingWindowReservations) {
    if (seenAttempts.has(r.childAttemptId)) continue;
    const refTime = r.terminalAtMs ?? r.reservedAtMs;
    if (refTime >= windowStartMs && refTime <= nowMs) {
      seenAttempts.add(r.childAttemptId);
      rollingCount++;
    }
  }
  if (rollingCount >= REMOTE_RETRY_BUDGET_MAX_PER_HOUR) {
    return { status: "rejected", reason: "max_per_hour_exceeded" };
  }
  const kindRetryCount = snapshot.trainReservations.filter(
    (r) => r.transportKind === request.transportKind && r.reservationType === "retry",
  ).length;
  if (request.reservationType === "retry" && kindRetryCount >= REMOTE_MAX_RETRIES_PER_KIND) {
    return { status: "rejected", reason: "kind_retry_exhausted" };
  }
  const reservation: RemoteTransportRetryReservationV1 = {
    schemaVersion: 1,
    reservationId: `res_${request.childAttemptId}`,
    tenantId: "",
    accountId: "",
    clientDeviceId: "",
    logicalAttachmentId: "",
    trainId: request.trainId,
    transportKind: request.transportKind,
    childAttemptId: request.childAttemptId,
    reservationType: request.reservationType,
    reservedAtMs: nowMs,
    expiresAtMs: nowMs + REMOTE_RETRY_BUDGET_WINDOW_SECONDS * 1000,
    terminalOutcome: null,
    terminalAtMs: null,
  };
  return { status: "reserved", reservation };
}

export function retryBudgetOutcomeOutage(): RemoteRetryReservationOutcome {
  return { status: "rejected", reason: "database_outage" };
}

export function markReservationTerminal(
  reservation: RemoteTransportRetryReservationV1,
  outcome: RemoteReservationTerminalOutcome,
  atMs: number,
): RemoteTransportRetryReservationV1 {
  return { ...reservation, terminalOutcome: outcome, terminalAtMs: atMs };
}

// ---------------------------------------------------------------------------
// Health computation
// ---------------------------------------------------------------------------

export function computeWebRtcHealth(
  child: RemoteTransportChild,
  probe: RemoteWebRtcHealthProbe,
): {
  readonly health: RemoteChildHealth;
  readonly consecutiveHealthy: number;
  readonly consecutiveMisses: number;
  readonly consecutiveBufferHigh: number;
} {
  // Buffer backpressure is tracked independently of liveness: a probe reporting
  // buffered bytes above the degraded threshold is a high-buffer probe whether
  // or not the liveness check itself succeeded, and two consecutive high-buffer
  // probes degrade the child even while it stays live. This mirrors the Rust
  // `reduce_webrtc_probe`, where `consecutive_high_buffer_probes` advances on any
  // high-buffer probe (and resets only when the buffer drops back under the
  // threshold), so the two reducers grade WebRTC health identically for the
  // golden traces.
  const consecutiveHealthy = probe.success ? child.consecutiveHealthy + 1 : 0;
  const consecutiveMisses = probe.success ? 0 : child.consecutiveMisses + 1;
  const bufferHigh = probe.bufferedBytes >= REMOTE_WEBRTC_DEGRADED_BUFFER_BYTES;
  const consecutiveBufferHigh = bufferHigh ? child.consecutiveBufferHigh + 1 : 0;
  if (consecutiveMisses >= REMOTE_WEBRTC_FAILED_MISS_PROBES) {
    return { health: "failed", consecutiveHealthy: 0, consecutiveMisses, consecutiveBufferHigh: 0 };
  }
  if (
    consecutiveMisses >= REMOTE_WEBRTC_DEGRADED_MISS_PROBES ||
    consecutiveBufferHigh >= REMOTE_WEBRTC_DEGRADED_BUFFER_PROBES
  ) {
    return { health: "degraded", consecutiveHealthy, consecutiveMisses, consecutiveBufferHigh };
  }
  if (consecutiveHealthy >= REMOTE_WEBRTC_HEALTHY_SUCCESS_PROBES) {
    return { health: "healthy", consecutiveHealthy, consecutiveMisses: 0, consecutiveBufferHigh };
  }
  return { health: child.health, consecutiveHealthy, consecutiveMisses, consecutiveBufferHigh };
}

export function computeWebSocketHealth(
  child: RemoteTransportChild,
  sample: RemoteWebSocketAckSample,
): {
  readonly health: RemoteChildHealth;
  readonly consecutiveHealthy: number;
  readonly consecutiveMisses: number;
  readonly consecutiveBufferHigh: number;
} {
  const isDegraded =
    sample.oldestUnackedAgeSeconds >= REMOTE_WEBSOCKET_DEGRADED_OLDEST_UNACKED_SECONDS ||
    sample.bufferedBytes >= REMOTE_WEBSOCKET_DEGRADED_BUFFER_BYTES;
  const isFailed = sample.retransmissionCount >= REMOTE_WEBSOCKET_FAILED_RETRANSMISSION;
  if (isFailed) {
    return {
      health: "failed",
      consecutiveHealthy: 0,
      consecutiveMisses: 0,
      consecutiveBufferHigh: 0,
    };
  }
  if (isDegraded) {
    return {
      health: "degraded",
      consecutiveHealthy: 0,
      consecutiveMisses: 0,
      consecutiveBufferHigh: 0,
    };
  }
  const consecutiveHealthy = child.consecutiveHealthy + 1;
  if (consecutiveHealthy >= REMOTE_HEALTH_RECOVERY_INTERVALS) {
    return {
      health: "healthy",
      consecutiveHealthy,
      consecutiveMisses: 0,
      consecutiveBufferHigh: 0,
    };
  }
  return {
    health: child.health,
    consecutiveHealthy,
    consecutiveMisses: 0,
    consecutiveBufferHigh: 0,
  };
}

// ---------------------------------------------------------------------------
// `ice_disconnected` maps to `network_unreachable` after 3 consecutive failed
// liveness probes.
// ---------------------------------------------------------------------------
export function iceDisconnectedToReachability(
  consecutiveFailedProbes: number,
): RemoteReachabilityClass | null {
  if (consecutiveFailedProbes >= REMOTE_WEBRTC_DISCONNECTED_FAIL_PROBES) {
    return "network_unreachable";
  }
  return null;
}

// ---------------------------------------------------------------------------
// Routing — deterministic among current children only
// ---------------------------------------------------------------------------

/**
 * Nominal per-child send capacity, mirroring the Rust `ChildRecord`
 * `NOMINAL_CAPACITY` used by `writable_bytes()`. Writable capacity is derived
 * from buffered bytes so bulk routing ranks the same way in both languages.
 */
export const REMOTE_TRANSPORT_NOMINAL_CAPACITY_BYTES = 16 * 1024 * 1024;

/**
 * Writable bytes available on a child for bulk routing tie-breaking, derived
 * from buffered bytes exactly as the Rust `ChildRecord::writable_bytes()`
 * (`NOMINAL_CAPACITY.saturating_sub(buffered_bytes)`).
 */
export function childWritableBytes(child: RemoteTransportChild): number {
  return Math.max(0, REMOTE_TRANSPORT_NOMINAL_CAPACITY_BYTES - child.bufferedBytes);
}

export function selectRouteChild(
  children: readonly RemoteTransportChild[],
  lane: RemoteRouteLane,
): RemoteTransportChild | null {
  const current = children.filter(
    (c) =>
      (c.state === "active" || c.state === "degraded") &&
      c.turnLifecycle !== "replacement_pending" &&
      c.turnLifecycle !== "draining",
  );
  if (current.length === 0) return null;
  const healthy = current.filter((c) => c.health === "healthy");
  const degraded = current.filter((c) => c.health === "degraded");
  const byEpoch = (a: RemoteTransportChild, b: RemoteTransportChild) =>
    a.transportEpoch < b.transportEpoch ? -1 : a.transportEpoch > b.transportEpoch ? 1 : 0;
  switch (lane) {
    case "control": {
      const pool = healthy.length > 0 ? healthy : degraded;
      if (pool.length === 0) return null;
      return [...pool].sort(byEpoch)[0]!;
    }
    case "interactive": {
      const healthyWebrtc = healthy.filter((c) => c.transportKind === "webrtc");
      if (healthyWebrtc.length > 0) return [...healthyWebrtc].sort(byEpoch)[0]!;
      const healthyWebsocket = healthy.filter((c) => c.transportKind === "websocket");
      if (healthyWebsocket.length > 0) return [...healthyWebsocket].sort(byEpoch)[0]!;
      if (degraded.length > 0) return [...degraded].sort(byEpoch)[0]!;
      return null;
    }
    case "bulk": {
      if (healthy.length > 0) {
        return [...healthy].sort((a, b) => {
          const aw = childWritableBytes(a);
          const bw = childWritableBytes(b);
          if (bw !== aw) return bw - aw;
          if (a.transportKind !== b.transportKind) {
            return a.transportKind === "webrtc" ? -1 : 1;
          }
          return byEpoch(a, b);
        })[0]!;
      }
      if (degraded.length > 0) return [...degraded].sort(byEpoch)[0]!;
      return null;
    }
    default: {
      const _exhaustive: never = lane;
      throw new Error(`unreachable lane: ${_exhaustive}`);
    }
  }
}

// ---------------------------------------------------------------------------
// TURN replacement cutover
// ---------------------------------------------------------------------------

export function buildConnectionLease(
  leaseId: string,
  currentChildAttemptIds: readonly RemoteChildAttemptId[],
  drainingChildAttemptIds: readonly RemoteChildAttemptId[],
): {
  readonly leaseId: string;
  readonly currentChildAttemptIds: readonly RemoteChildAttemptId[];
  readonly drainingChildAttemptIds: readonly RemoteChildAttemptId[];
  readonly supervisorAcked: boolean;
} {
  return { leaseId, currentChildAttemptIds, drainingChildAttemptIds, supervisorAcked: false };
}

export function isTurnReplacementLeaseValid(lease: {
  readonly currentChildAttemptIds: readonly RemoteChildAttemptId[];
  readonly drainingChildAttemptIds: readonly RemoteChildAttemptId[];
}): boolean {
  return lease.currentChildAttemptIds.length === 1 && lease.drainingChildAttemptIds.length === 1;
}

// ---------------------------------------------------------------------------
// Authorized WebSocket fallback — the single admission gate
// ---------------------------------------------------------------------------

/**
 * Start the authorized WebSocket fallback child, mirroring the Rust
 * `maybe_start_websocket_fallback`. Admission goes through the authorized plan
 * (`allowedKinds`), NOT raw authorization booleans, so a fallback can never
 * admit a kind the plan denies (e.g. under `unavailable` consent). It is a no-op
 * unless the preference is `auto`, the plan admits `websocket`, and no
 * non-closed WebSocket child already exists (the "already started" idempotency
 * guard, in place of the Rust `websocket_fallback_started` flag). The caller is
 * responsible for any "no active WebRTC" precondition (mirroring
 * `reduce_deadline_fired`).
 */
function startAuthorizedWebsocketFallback(
  state: RemoteTransportOrchestratorState,
  deps: {
    readonly nextChildAttemptId: () => RemoteChildAttemptId;
    readonly nextTransportEpoch: () => RemoteTransportEpoch;
    readonly nextGeneration: (kind: RemoteTransportKind) => RemoteChildGeneration;
  },
  commands: RemoteTransportCommand[],
): RemoteTransportOrchestratorState {
  const plan = state.plan;
  if (plan === null || plan.preference !== "auto") return state;
  if (!plan.allowedKinds.includes("websocket")) return state;
  const hasWebsocket = state.children.some(
    (c) => c.transportKind === "websocket" && c.state !== "closed",
  );
  if (hasWebsocket) return state;
  const childAttemptId = deps.nextChildAttemptId();
  const transportEpoch = deps.nextTransportEpoch();
  const generation = deps.nextGeneration("websocket");
  commands.push({
    kind: "start_child",
    transportKind: "websocket",
    childAttemptId,
    transportEpoch,
    generation,
    reservationType: "initial",
    secondChildReason: null,
  });
  return state;
}

// ---------------------------------------------------------------------------
// The pure reducer
// ---------------------------------------------------------------------------

export function transportSelectionReducer(
  state: RemoteTransportOrchestratorState,
  event: RemoteTransportEvent,
  deps: {
    readonly retryBudget: RemoteRetryBudgetSnapshot | null;
    readonly nextChildAttemptId: () => RemoteChildAttemptId;
    readonly nextTransportEpoch: () => RemoteTransportEpoch;
    readonly nextGeneration: (kind: RemoteTransportKind) => RemoteChildGeneration;
    readonly now: () => number;
  },
): {
  readonly state: RemoteTransportOrchestratorState;
  readonly commands: readonly RemoteTransportCommand[];
} {
  const commands: RemoteTransportCommand[] = [];
  let next: RemoteTransportOrchestratorState = { ...state, lastEventAtMs: event.atMs };
  switch (event.kind) {
    case "plan_requested": {
      const plan = computeAuthorizedPlan(event.input);
      next = { ...next, trainId: event.trainId, plan };
      if (plan.allowedKinds.length === 0) {
        next = { ...next, parentState: "denied" };
        commands.push({ kind: "deny", denials: plan.denials });
        return { state: next, commands };
      }
      next = { ...next, parentState: "establishing" };
      if (plan.allowedKinds.includes("webrtc")) {
        const childAttemptId = deps.nextChildAttemptId();
        const transportEpoch = deps.nextTransportEpoch();
        const generation = deps.nextGeneration("webrtc");
        commands.push({
          kind: "start_child",
          transportKind: "webrtc",
          childAttemptId,
          transportEpoch,
          generation,
          reservationType: "initial",
          secondChildReason: null,
        });
        if (event.input.userPreference === "auto") {
          const timerId = `deadline_${childAttemptId}`;
          commands.push({
            kind: "schedule_deadline_timer",
            timerId,
            childAttemptId,
            fireAtMs: event.atMs + REMOTE_AUTO_INITIAL_DEADLINE_SECONDS * 1000,
            deadlineSeconds: REMOTE_AUTO_INITIAL_DEADLINE_SECONDS,
          });
          next = { ...next, pendingTimers: [...next.pendingTimers, timerId] };
        }
      } else if (plan.allowedKinds.includes("websocket")) {
        const childAttemptId = deps.nextChildAttemptId();
        const transportEpoch = deps.nextTransportEpoch();
        const generation = deps.nextGeneration("websocket");
        commands.push({
          kind: "start_child",
          transportKind: "websocket",
          childAttemptId,
          transportEpoch,
          generation,
          reservationType: "initial",
          secondChildReason: null,
        });
      }
      return { state: next, commands };
    }
    case "child_attempt_reserved": {
      const child: RemoteTransportChild = {
        childAttemptId: event.childAttemptId,
        transportKind: event.transportKind,
        transportEpoch: event.transportEpoch,
        generation: event.generation,
        state: "pending",
        turnLifecycle: null,
        health: "degraded",
        consecutiveHealthy: 0,
        consecutiveMisses: 0,
        consecutiveBufferHigh: 0,
        bufferedBytes: 0,
        pendingTimerId: null,
        secondChildReason: null,
        deadlineExpiresAtMs: null,
        closedReason: null,
      };
      next = { ...next, children: [...next.children, child] };
      return { state: next, commands };
    }
    case "child_reservation_rejected": {
      if (event.reason === "database_outage") {
        next = {
          ...next,
          parentState: next.children.some((c) => c.state === "active")
            ? next.parentState
            : "denied",
        };
      }
      return { state: next, commands };
    }
    case "child_authenticating": {
      next = {
        ...next,
        children: next.children.map((c) =>
          c.childAttemptId === event.childAttemptId ? { ...c, state: "authenticating" } : c,
        ),
      };
      return { state: next, commands };
    }
    case "child_active": {
      const child = next.children.find((c) => c.childAttemptId === event.childAttemptId);
      if (child === undefined) return { state: next, commands };
      if (child.state === "closing" || child.state === "closed") {
        return { state: next, commands };
      }
      const updatedChild: RemoteTransportChild = {
        ...child,
        state: "active",
        health: "healthy",
        consecutiveHealthy: child.consecutiveHealthy,
      };
      next = {
        ...next,
        children: next.children.map((c) =>
          c.childAttemptId === event.childAttemptId ? updatedChild : c,
        ),
      };
      if (child.deadlineExpiresAtMs !== null) {
        const timerId = `deadline_${child.childAttemptId}`;
        commands.push({ kind: "cancel_timer", timerId });
        next = { ...next, pendingTimers: next.pendingTimers.filter((t) => t !== timerId) };
      }
      if (next.parentState === "establishing") {
        next = { ...next, parentState: "active" };
      }
      return { state: next, commands };
    }
    case "child_degraded_signal": {
      const child = next.children.find((c) => c.childAttemptId === event.childAttemptId);
      if (child === undefined) return { state: next, commands };
      if (event.signal === "ice_disconnected") {
        const timerId = `liveness_${child.childAttemptId}`;
        commands.push({
          kind: "schedule_liveness_probe",
          timerId,
          childAttemptId: child.childAttemptId,
          fireAtMs: event.atMs + REMOTE_WEBRTC_PROBE_INTERVAL_SECONDS * 1000,
          intervalSeconds: REMOTE_WEBRTC_PROBE_INTERVAL_SECONDS,
        });
        next = {
          ...next,
          children: next.children.map((c) =>
            c.childAttemptId === event.childAttemptId ? { ...c, health: "degraded" } : c,
          ),
        };
      }
      return { state: next, commands };
    }
    case "child_closed": {
      const child = next.children.find((c) => c.childAttemptId === event.childAttemptId);
      if (child === undefined) return { state: next, commands };
      const updatedChild: RemoteTransportChild = {
        ...child,
        state: "closed",
        closedReason: event.reason,
        pendingTimerId: null,
      };
      next = {
        ...next,
        children: next.children.map((c) =>
          c.childAttemptId === event.childAttemptId ? updatedChild : c,
        ),
      };
      const childTimerIds = [
        `deadline_${child.childAttemptId}`,
        `liveness_${child.childAttemptId}`,
        `retry_${child.childAttemptId}`,
      ];
      for (const timerId of childTimerIds) {
        if (next.pendingTimers.includes(timerId)) {
          commands.push({ kind: "cancel_timer", timerId });
        }
      }
      next = {
        ...next,
        pendingTimers: next.pendingTimers.filter((t) => !childTimerIds.includes(t)),
      };

      // Canonical close handling, mirroring the Rust `reduce_child_closed`:
      //   - A terminal (security/policy/consent) close arms no retry and drives
      //     no parent transition here (the explicit `ChildSecurityFailure` path
      //     owns terminal failure). WebSocket fallback is NOT started on close —
      //     the deadline / reachability paths own fallback; close arms a
      //     same-kind retry instead.
      //   - Otherwise, once no child is active OR pending, a same-kind retry is
      //     armed while the per-kind retry budget allows; when it is exhausted
      //     the parent fails.
      const securityFailure = isTerminalCloseReason(event.reason);
      if (securityFailure) {
        return { state: next, commands };
      }

      const anyActive = next.children.some((c) => c.state === "active" || c.state === "degraded");
      const anyPending = next.children.some(
        (c) => c.state === "pending" || c.state === "authenticating",
      );
      if (!anyActive && !anyPending) {
        const kind = child.transportKind;
        const cancelledOrDenied = next.parentState === "cancelled" || next.parentState === "denied";
        if (next.kindRetries[kind] < REMOTE_MAX_RETRIES_PER_KIND && !cancelledOrDenied) {
          const retryAttemptId = deps.nextChildAttemptId();
          const retryEpoch = deps.nextTransportEpoch();
          const retryTimerId = `retry_${retryAttemptId}`;
          next = {
            ...next,
            kindRetries: {
              webrtc: next.kindRetries.webrtc + (kind === "webrtc" ? 1 : 0),
              websocket: next.kindRetries.websocket + (kind === "websocket" ? 1 : 0),
            },
            pendingRetry: {
              kind,
              childAttemptId: retryAttemptId,
              transportEpoch: retryEpoch,
            },
            // Track the retry timer so a subsequent cancel/revoke/supersede/
            // background emits its cancellation and clears the pending retry — a
            // late `retry_delay_fired` must then find no pending retry and start
            // nothing (mirrors the Rust cancel/supersede clearing `pending_retry`
            // plus the cancelled-guard short-circuit).
            pendingTimers: [...next.pendingTimers, retryTimerId],
          };
          commands.push({
            kind: "schedule_retry",
            timerId: retryTimerId,
            childAttemptId: retryAttemptId,
            transportKind: kind,
            fireAtMs: event.atMs + REMOTE_RETRY_DELAY_MS,
            delayMs: REMOTE_RETRY_DELAY_MS,
          });
        } else if (!cancelledOrDenied) {
          next = { ...next, parentState: "failed" };
        }
      }
      return { state: next, commands };
    }
    case "health_probe": {
      const child = next.children.find((c) => c.childAttemptId === event.sample.childAttemptId);
      if (child === undefined) return { state: next, commands };
      if (child.state === "closed" || child.state === "closing") return { state: next, commands };
      let result: {
        readonly health: RemoteChildHealth;
        readonly consecutiveHealthy: number;
        readonly consecutiveMisses: number;
        readonly consecutiveBufferHigh: number;
      };
      if (event.sample.kind === "webrtc") {
        result = computeWebRtcHealth(child, event.sample);
      } else {
        result = computeWebSocketHealth(child, event.sample);
      }
      const updatedChild: RemoteTransportChild = {
        ...child,
        health: result.health,
        consecutiveHealthy: result.consecutiveHealthy,
        consecutiveMisses: result.consecutiveMisses,
        consecutiveBufferHigh: result.consecutiveBufferHigh,
        // Track buffered bytes so bulk routing derives writable capacity exactly
        // as the Rust reducer (which stores `buffered_bytes` on every probe).
        bufferedBytes: event.sample.bufferedBytes,
      };
      // Mirror the Rust `reduce_webrtc_probe` / `reduce_websocket_ack` FAILED
      // branch: on reaching the failed-probe threshold the child transitions to
      // `closed` in reducer state (so routing can no longer select it), not
      // merely emitting a teardown command that leaves it routable. For a failed
      // WebRTC child under `auto`, the authorized WebSocket fallback is started
      // (Rust starts it via `maybe_start_websocket_fallback`); a failed WebSocket
      // child just closes with no fallback.
      const finalChild: RemoteTransportChild =
        result.health === "failed"
          ? { ...updatedChild, state: "closed", closedReason: "network_unreachable" }
          : updatedChild;
      if (result.health === "failed") {
        commands.push({
          kind: "close_child",
          childAttemptId: child.childAttemptId,
          reason: "network_unreachable",
        });
      }
      next = {
        ...next,
        children: next.children.map((c) =>
          c.childAttemptId === event.sample.childAttemptId ? finalChild : c,
        ),
      };
      if (result.health === "failed" && event.sample.kind === "webrtc") {
        next = startAuthorizedWebsocketFallback(next, deps, commands);
      }
      return { state: next, commands };
    }
    case "deadline_timer_fired": {
      // The initial deadline is a train-global decision (mirrors the Rust
      // `reduce_deadline_fired`, whose input carries no child id): it decides
      // from the AGGREGATE current state, never from the identity or liveness of
      // the original initial child. A nonterminal close of that child before the
      // deadline must NOT suppress the fallback — an earlier revision returned
      // early when the original child was `closed`, so a WebRTC that dropped
      // before its deadline silently lost the WebSocket fallback. If any WebRTC
      // child is active the deadline is inert; otherwise start the authorized
      // WebSocket fallback (idempotent via the fallback's own guards).
      next = { ...next, pendingTimers: next.pendingTimers.filter((t) => t !== event.timerId) };
      const webrtcActive = next.children.some(
        (c) => c.transportKind === "webrtc" && c.state === "active",
      );
      if (!webrtcActive) {
        next = startAuthorizedWebsocketFallback(next, deps, commands);
      }
      return { state: next, commands };
    }
    case "retry_delay_fired": {
      // Canonical `RetryDelayFired`: consume the pending-retry slot (allocated
      // when the prior child closed) and promote it into a live `start_child`.
      // The child is materialised by the subsequent `child_attempt_reserved`, as
      // for every other start path in this reducer. Caps are re-checked at fire
      // time exactly as the Rust `reduce_retry_delay_fired`.
      const pending = next.pendingRetry;
      if (pending === null) return { state: next, commands };
      // Consume the pending-retry slot AND its tracked timer.
      next = {
        ...next,
        pendingRetry: null,
        pendingTimers: next.pendingTimers.filter((t) => t !== `retry_${pending.childAttemptId}`),
      };
      // A retry may only start while the parent remains eligible. If the parent
      // has already reached a terminal/aborted state a late `retry_delay_fired`
      // is inert — it must never resurrect a child after termination (mirrors the
      // Rust cancelled-guard short-circuit; cancel/supersede also clear the
      // pending retry, so this is a second line of defence).
      if (
        next.parentState === "cancelled" ||
        next.parentState === "denied" ||
        next.parentState === "failed" ||
        next.parentState === "superseded"
      ) {
        return { state: next, commands };
      }
      if (
        countPendingChildren(next.children, pending.kind) >= REMOTE_MAX_PENDING_CHILDREN_PER_KIND
      ) {
        return { state: next, commands };
      }
      if (countAllPendingChildren(next.children) >= REMOTE_MAX_PENDING_CHILDREN_TOTAL) {
        return { state: next, commands };
      }
      const generation = deps.nextGeneration(pending.kind);
      commands.push({
        kind: "start_child",
        transportKind: pending.kind,
        childAttemptId: pending.childAttemptId,
        transportEpoch: pending.transportEpoch,
        generation,
        reservationType: "retry",
        secondChildReason: null,
      });
      return { state: next, commands };
    }
    case "liveness_probe_timer_fired": {
      next = { ...next, pendingTimers: next.pendingTimers.filter((t) => t !== event.timerId) };
      return { state: next, commands };
    }
    case "second_child_requested": {
      // Mirror the Rust `reduce_request_second_child`. The eligible second-child
      // kinds are exactly the authorized plan's `allowedKinds` — NEVER the raw
      // authorization booleans — so a plan that denies a kind (e.g. WebRTC under
      // `relay_required_turn_unavailable`, or any kind under `unavailable`
      // consent) can never start it as a second child.
      const hasActive = next.children.some((c) => c.state === "active");
      if (!hasActive) {
        commands.push({ kind: "deny", denials: ["policy_denied"] });
        return { state: next, commands };
      }
      const routedCurrent = next.children.filter(
        (c) =>
          (c.state === "active" || c.state === "degraded") &&
          c.turnLifecycle !== "draining" &&
          c.turnLifecycle !== "replacement_pending",
      );
      const existingKinds = new Set(routedCurrent.map((c) => c.transportKind));
      const allowed = next.plan?.allowedKinds ?? [];
      let target: RemoteTransportKind | null = null;
      if (!existingKinds.has("webrtc") && allowed.includes("webrtc")) {
        target = "webrtc";
      } else if (!existingKinds.has("websocket") && allowed.includes("websocket")) {
        target = "websocket";
      }
      if (
        target === null ||
        countPendingChildren(next.children, target) >= REMOTE_MAX_PENDING_CHILDREN_PER_KIND ||
        countAllPendingChildren(next.children) >= REMOTE_MAX_PENDING_CHILDREN_TOTAL ||
        routedCurrent.length >= REMOTE_MAX_CURRENT_WEBRTC + REMOTE_MAX_CURRENT_WEBSOCKET
      ) {
        commands.push({ kind: "deny", denials: ["child_cap_exceeded"] });
        return { state: next, commands };
      }
      const newAttemptId = deps.nextChildAttemptId();
      const transportEpoch = deps.nextTransportEpoch();
      const generation = deps.nextGeneration(target);
      // Credential rotation on a WebRTC target starts a fresh replacement-pending
      // child (Rust `reduce_request_second_child` emits a lone
      // `StartReplacementPending`); every other named reason starts an ordinary
      // second child. `reservationType: "replacement"` is what the trace oracle
      // normalises to `start_replacement_pending`.
      const isReplacement = event.reason === "credential_rotation" && target === "webrtc";
      commands.push({
        kind: "start_child",
        transportKind: target,
        childAttemptId: newAttemptId,
        transportEpoch,
        generation,
        reservationType: isReplacement ? "replacement" : "initial",
        secondChildReason: event.reason,
      });
      return { state: next, commands };
    }
    case "credential_rotation_lead": {
      // Mirror the Rust `reduce_credential_rotation`. It requires a live CURRENT
      // WebRTC child and is otherwise INERT; it NEVER admits a new kind and never
      // starts WebRTC from a WebSocket-only plan. Distinct from
      // `second_child_requested{reason:"credential_rotation"}`.
      const currentWebrtc = next.children.find(
        (c) =>
          c.transportKind === "webrtc" &&
          c.state !== "closed" &&
          c.turnLifecycle !== "draining" &&
          c.turnLifecycle !== "replacement_pending",
      );
      if (currentWebrtc === undefined) return { state: next, commands };
      // Authorized-plan gate: the plan must still admit WebRTC. A WebSocket-only
      // plan (or `unavailable` consent → empty `allowedKinds`) admits no WebRTC,
      // so credential rotation is inert — it must not start unauthorized WebRTC.
      if (!(next.plan?.allowedKinds.includes("webrtc") ?? false)) {
        return { state: next, commands };
      }
      // A replacement already in progress (a pending or draining pair, or a
      // committed cutover lease) is inert — mirrors `turn_replacement.is_some()`.
      const replacementInProgress =
        next.activeLease !== null ||
        next.children.some(
          (c) => c.turnLifecycle === "replacement_pending" || c.turnLifecycle === "draining",
        );
      if (replacementInProgress) return { state: next, commands };
      // Physical-child cap (the three-child TURN exception).
      if (countPhysicalChildren(next.children) >= REMOTE_MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT) {
        commands.push({ kind: "deny", denials: ["child_cap_exceeded"] });
        return { state: next, commands };
      }
      const newAttemptId = deps.nextChildAttemptId();
      const transportEpoch = deps.nextTransportEpoch();
      const generation = deps.nextGeneration("webrtc");
      commands.push({
        kind: "begin_turn_replacement",
        currentChildAttemptId: currentWebrtc.childAttemptId,
        replacementChildAttemptId: newAttemptId,
        transportEpoch,
        reason: "credential_rotation",
      });
      commands.push({
        kind: "start_child",
        transportKind: "webrtc",
        childAttemptId: newAttemptId,
        transportEpoch,
        generation,
        reservationType: "replacement",
        secondChildReason: "credential_rotation",
      });
      return { state: next, commands };
    }
    case "lease_supervisor_acked": {
      if (next.activeLease !== null && next.activeLease.leaseId === event.leaseId) {
        next = { ...next, activeLease: { ...next.activeLease, supervisorAcked: true } };
        next = {
          ...next,
          children: next.children.map((c) => {
            if (event.drainingChildAttemptIds.includes(c.childAttemptId)) {
              return { ...c, turnLifecycle: "draining" };
            }
            if (event.currentChildAttemptIds.includes(c.childAttemptId)) {
              return { ...c, turnLifecycle: "current" };
            }
            return c;
          }),
        };
      }
      return { state: next, commands };
    }
    case "route_request": {
      const selected = selectRouteChild(next.children, event.lane);
      if (selected === null) return { state: next, commands };
      const existing = next.deliveryAssignments.get(event.deliveryId);
      const targetChildAttemptId = existing ?? selected.childAttemptId;
      if (existing === undefined) {
        const newAssignments = new Map(next.deliveryAssignments);
        newAssignments.set(event.deliveryId, targetChildAttemptId);
        next = { ...next, deliveryAssignments: newAssignments };
      }
      commands.push({
        kind: "route_delivery",
        deliveryId: event.deliveryId,
        lane: event.lane,
        childAttemptId: targetChildAttemptId,
        payloadBytes: event.payloadBytes,
      });
      commands.push({
        kind: "record_ledger_mutation",
        deliveryId: event.deliveryId,
        childAttemptId: targetChildAttemptId,
      });
      const prior = next.ledgerDeliveries.get(event.deliveryId) ?? [];
      if (!prior.includes(targetChildAttemptId)) {
        const newLedger = new Map(next.ledgerDeliveries);
        newLedger.set(event.deliveryId, [...prior, targetChildAttemptId]);
        next = { ...next, ledgerDeliveries: newLedger };
      }
      return { state: next, commands };
    }
    case "background":
    case "cancel":
    case "revoke":
    case "supersede": {
      for (const timerId of next.pendingTimers) {
        commands.push({ kind: "cancel_timer", timerId });
      }
      // Abort all pending timers AND drop any pending same-kind retry, so a late
      // `retry_delay_fired` finds nothing to start after termination/background
      // (mirrors the Rust cancel/supersede clearing `pending_retry`).
      next = { ...next, pendingTimers: [], pendingRetry: null };
      if (event.kind === "cancel") next = { ...next, parentState: "cancelled" };
      else if (event.kind === "supersede") next = { ...next, parentState: "superseded" };
      else if (event.kind === "background") next = { ...next, parentState: next.parentState };
      else if (event.kind === "revoke") next = { ...next, parentState: "cancelled" };
      return { state: next, commands };
    }
    default: {
      const _exhaustive: never = event;
      throw new Error(`unreachable transport event: ${_exhaustive}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Failover resend — exact bytes, client dedupes
// ---------------------------------------------------------------------------

export function failoverResend(
  deliveryId: string,
  targetChildAttemptId: RemoteChildAttemptId,
): RemoteTransportCommand {
  return { kind: "failover_resend", deliveryId, targetChildAttemptId };
}

// ---------------------------------------------------------------------------
// Draining constraints
// ---------------------------------------------------------------------------

export function isDrainingAllowedMutation(
  child: RemoteTransportChild,
  deliveryId: string,
  assignedDeliveries: ReadonlySet<string>,
): { readonly allowed: boolean; readonly reason?: "child_draining" } {
  if (child.turnLifecycle === "draining") {
    if (!assignedDeliveries.has(deliveryId)) {
      return { allowed: false, reason: "child_draining" };
    }
  }
  return { allowed: true };
}
