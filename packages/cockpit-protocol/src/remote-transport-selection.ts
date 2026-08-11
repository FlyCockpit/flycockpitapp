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
 * Cross-language contract: the constants, enums, and pure reducer surface here
 * mirror `crates/cockpit-proto/src/remote_transport_selection.rs`. The golden
 * transition/route traces are committed as fixtures consumed by web/native/Rust.
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
 * Closed reachability classes reported by adapters. These are the only signals
 * that trigger fallback for `auto` preference (other than the deadline).
 * `ice_disconnected` is degraded, not fallback, until 3 consecutive 5-second
 * liveness probes fail; then it maps to `network_unreachable`.
 */
export const REMOTE_REACHABILITY_CLASSES = [
  "ice_no_candidate_pair",
  "ice_timeout",
  "network_unreachable",
  "turn_unreachable",
] as const;
export type RemoteReachabilityClass = (typeof REMOTE_REACHABILITY_CLASSES)[number];

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

export type RemoteRouteLane = "control" | "interactive" | "bulk";

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
  readonly terminalOutcome: "active" | "cancelled" | "reservation_failed" | null;
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

export type RemoteIpConsentTriState = "direct_allowed" | "relay_only" | "unavailable";
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
  readonly liveQuota: RemoteLiveQuota;
  readonly clientCapabilities: RemoteClientCapabilities;
  readonly userPreference: RemoteUserPreference;
}

export type RemoteTransportPlanDenial =
  | { readonly kind: "no_authorized_transport"; readonly detail: string }
  | {
      readonly kind: "preference_unavailable";
      readonly preference: RemoteUserPreference;
      readonly detail: string;
    }
  | { readonly kind: "quota_exhausted"; readonly detail: string }
  | { readonly kind: "consent_unavailable"; readonly detail: string }
  | { readonly kind: "privacy_relay_only_no_turn"; readonly detail: string };

export interface RemoteTransportAuthorizedPlan {
  readonly webrtcAuthorized: boolean;
  readonly websocketAuthorized: boolean;
  readonly turnRequired: boolean;
  readonly denial: RemoteTransportPlanDenial | null;
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
export type RemoteChildHealth = "healthy" | "degraded" | "failed";

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
  readonly writableBytes: number;
  readonly pendingTimerId: string | null;
  readonly secondChildReason: RemoteSecondChildReason | null;
  readonly retryCount: number;
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
  | { readonly kind: "deny"; readonly denial: RemoteTransportPlanDenial }
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
      readonly writableBytes: number;
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
      readonly kind: "retry_timer_fired";
      readonly atMs: number;
      readonly timerId: string;
      readonly childAttemptId: RemoteChildAttemptId;
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
    lastEventAtMs: 0,
  };
}

// ---------------------------------------------------------------------------
// Plan computation — authorization matrix
// ---------------------------------------------------------------------------

export function computeAuthorizedPlan(
  input: RemoteTransportPlanInput,
): RemoteTransportAuthorizedPlan {
  if (input.liveQuota.exhausted) {
    return {
      webrtcAuthorized: false,
      websocketAuthorized: false,
      turnRequired: false,
      denial: { kind: "quota_exhausted", detail: "live quota exhausted" },
    };
  }
  if (input.ipConsent === "unavailable") {
    return {
      webrtcAuthorized: false,
      websocketAuthorized: false,
      turnRequired: false,
      denial: { kind: "consent_unavailable", detail: "ip consent unavailable" },
    };
  }
  const turnRequired =
    input.participantPrivacy === "turn_required" || input.participantPrivacy === "relay_only";
  if (input.participantPrivacy === "relay_only" && !turnRequired) {
    return {
      webrtcAuthorized: false,
      websocketAuthorized: false,
      turnRequired: false,
      denial: { kind: "privacy_relay_only_no_turn", detail: "relay-only privacy without turn" },
    };
  }
  const webrtcMeet =
    input.deploymentWebrtc &&
    input.serviceWebrtc &&
    input.tenantWebrtc &&
    input.daemonWebrtc &&
    input.clientCapabilities.webrtcSupported;
  const websocketMeet =
    input.deploymentWebsocket &&
    input.serviceWebsocket &&
    input.tenantWebsocket &&
    input.daemonWebsocket &&
    input.clientCapabilities.websocketSupported;
  switch (input.userPreference) {
    case "webrtc":
      if (!webrtcMeet) {
        return {
          webrtcAuthorized: false,
          websocketAuthorized: false,
          turnRequired,
          denial: {
            kind: "preference_unavailable",
            preference: "webrtc",
            detail: "webrtc preference but webrtc not authorized",
          },
        };
      }
      return { webrtcAuthorized: true, websocketAuthorized: false, turnRequired, denial: null };
    case "websocket":
      if (!websocketMeet) {
        return {
          webrtcAuthorized: false,
          websocketAuthorized: false,
          turnRequired,
          denial: {
            kind: "preference_unavailable",
            preference: "websocket",
            detail: "websocket preference but websocket not authorized",
          },
        };
      }
      return { webrtcAuthorized: false, websocketAuthorized: true, turnRequired, denial: null };
    case "auto": {
      if (!webrtcMeet && !websocketMeet) {
        return {
          webrtcAuthorized: false,
          websocketAuthorized: false,
          turnRequired,
          denial: { kind: "no_authorized_transport", detail: "no transport authorized" },
        };
      }
      return {
        webrtcAuthorized: webrtcMeet,
        websocketAuthorized: websocketMeet,
        turnRequired,
        denial: null,
      };
    }
    default: {
      const _exhaustive: never = input.userPreference;
      throw new Error(`unreachable user preference: ${_exhaustive}`);
    }
  }
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
  outcome: "active" | "cancelled" | "reservation_failed",
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
  const bufferHigh = probe.bufferedBytes >= REMOTE_WEBRTC_DEGRADED_BUFFER_BYTES;
  const consecutiveHealthy = probe.success ? child.consecutiveHealthy + 1 : 0;
  const consecutiveMisses = probe.success ? 0 : child.consecutiveMisses + 1;
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
          if (b.writableBytes !== a.writableBytes) return b.writableBytes - a.writableBytes;
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
      if (plan.denial !== null) {
        next = { ...next, parentState: "denied" };
        commands.push({ kind: "deny", denial: plan.denial });
        return { state: next, commands };
      }
      next = { ...next, parentState: "establishing" };
      if (plan.webrtcAuthorized) {
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
      } else if (plan.websocketAuthorized) {
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
        writableBytes: 0,
        pendingTimerId: null,
        secondChildReason: null,
        retryCount: 0,
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
        writableBytes: event.writableBytes,
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
      if (
        isReachabilityCloseReason(event.reason) &&
        next.plan?.websocketAuthorized &&
        next.plan.webrtcAuthorized
      ) {
        const hasWebsocket = next.children.some(
          (c) => c.transportKind === "websocket" && c.state !== "closed",
        );
        const hasActiveWebrtc = next.children.some(
          (c) => c.transportKind === "webrtc" && (c.state === "active" || c.state === "degraded"),
        );
        if (!hasWebsocket && !hasActiveWebrtc) {
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
      }
      const anyActive = next.children.some(
        (c) =>
          c.state === "active" ||
          c.state === "degraded" ||
          c.state === "pending" ||
          c.state === "authenticating",
      );
      if (!anyActive && next.parentState !== "denied" && next.parentState !== "cancelled") {
        next = { ...next, parentState: "failed" };
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
      };
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
          c.childAttemptId === event.sample.childAttemptId ? updatedChild : c,
        ),
      };
      return { state: next, commands };
    }
    case "deadline_timer_fired": {
      const child = next.children.find((c) => c.childAttemptId === event.childAttemptId);
      if (child === undefined) return { state: next, commands };
      if (child.state === "closed" || child.state === "closing") return { state: next, commands };
      const hasActiveWebrtc = next.children.some(
        (c) => c.transportKind === "webrtc" && (c.state === "active" || c.state === "degraded"),
      );
      const hasWebsocket = next.children.some(
        (c) => c.transportKind === "websocket" && c.state !== "closed",
      );
      if (!hasActiveWebrtc && !hasWebsocket && next.plan?.websocketAuthorized) {
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
      next = { ...next, pendingTimers: next.pendingTimers.filter((t) => t !== event.timerId) };
      return { state: next, commands };
    }
    case "retry_timer_fired": {
      const child = next.children.find((c) => c.childAttemptId === event.childAttemptId);
      if (child === undefined) return { state: next, commands };
      if (child.state === "closed" || child.state === "closing") return { state: next, commands };
      if (child.retryCount >= REMOTE_MAX_RETRIES_PER_KIND) return { state: next, commands };
      const newAttemptId = deps.nextChildAttemptId();
      const transportEpoch = deps.nextTransportEpoch();
      const generation = deps.nextGeneration(child.transportKind);
      commands.push({
        kind: "start_child",
        transportKind: child.transportKind,
        childAttemptId: newAttemptId,
        transportEpoch,
        generation,
        reservationType: "retry",
        secondChildReason: null,
      });
      next = {
        ...next,
        children: next.children.map((c) =>
          c.childAttemptId === event.childAttemptId ? { ...c, retryCount: c.retryCount + 1 } : c,
        ),
        pendingTimers: next.pendingTimers.filter((t) => t !== event.timerId),
      };
      return { state: next, commands };
    }
    case "liveness_probe_timer_fired": {
      next = { ...next, pendingTimers: next.pendingTimers.filter((t) => t !== event.timerId) };
      return { state: next, commands };
    }
    case "second_child_requested": {
      const child = next.children.find((c) => c.childAttemptId === event.childAttemptId);
      if (child === undefined) return { state: next, commands };
      if (event.reason === "credential_rotation") {
        const newAttemptId = deps.nextChildAttemptId();
        commands.push({
          kind: "begin_turn_replacement",
          currentChildAttemptId: child.childAttemptId,
          replacementChildAttemptId: newAttemptId,
          transportEpoch: event.transportEpoch,
          reason: event.reason,
        });
        commands.push({
          kind: "start_child",
          transportKind: "webrtc",
          childAttemptId: newAttemptId,
          transportEpoch: event.transportEpoch,
          generation: deps.nextGeneration("webrtc"),
          reservationType: "replacement",
          secondChildReason: event.reason,
        });
      } else {
        const otherKind: RemoteTransportKind =
          child.transportKind === "webrtc" ? "websocket" : "webrtc";
        const authorized =
          otherKind === "webrtc" ? next.plan?.webrtcAuthorized : next.plan?.websocketAuthorized;
        if (authorized) {
          const capCheck = checkChildCaps(next.children, otherKind, false);
          if (capCheck.ok) {
            const newAttemptId = deps.nextChildAttemptId();
            const transportEpoch = deps.nextTransportEpoch();
            const generation = deps.nextGeneration(otherKind);
            commands.push({
              kind: "start_child",
              transportKind: otherKind,
              childAttemptId: newAttemptId,
              transportEpoch,
              generation,
              reservationType: "initial",
              secondChildReason: event.reason,
            });
          }
        }
      }
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
      next = { ...next, pendingTimers: [] };
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
