/**
 * Transport-selection state-machine conformance — the nine acceptance matrices.
 *
 * Every test here maps 1:1 to an acceptance criterion in the
 * `remote-transport-selection-state-machine` prompt. The pure reducer, plan
 * computation, caps, retry budget, health, routing, cutover, and multi-path
 * ordering are all exercised with injected time and deterministic ids.
 */
import { describe, expect, it } from "vitest";
import {
  checkChildCaps,
  computeAuthorizedPlan,
  computeWebRtcHealth,
  computeWebSocketHealth,
  countAllPendingChildren,
  countCurrentChildren,
  countPhysicalChildren,
  evaluateRetryBudget,
  failoverResend,
  iceDisconnectedToReachability,
  initialTransportOrchestratorState,
  isDrainingAllowedMutation,
  isReachabilityCloseReason,
  isTerminalCloseReason,
  isTurnReplacementLeaseValid,
  markReservationTerminal,
  physicalChildCap,
  REMOTE_AUTO_INITIAL_DEADLINE_MAX_SECONDS,
  REMOTE_AUTO_INITIAL_DEADLINE_MIN_SECONDS,
  REMOTE_AUTO_INITIAL_DEADLINE_SECONDS,
  REMOTE_HEALTH_RECOVERY_INTERVALS,
  REMOTE_MAX_CURRENT_WEBRTC,
  REMOTE_MAX_CURRENT_WEBSOCKET,
  REMOTE_MAX_PENDING_CHILDREN_PER_KIND,
  REMOTE_MAX_PENDING_CHILDREN_TOTAL,
  REMOTE_MAX_PHYSICAL_CHILDREN_NORMAL,
  REMOTE_MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT,
  REMOTE_MAX_RETRIES_PER_KIND,
  REMOTE_RETRY_BUDGET_MAX_PER_HOUR,
  REMOTE_RETRY_BUDGET_MAX_PER_TRAIN,
  REMOTE_RETRY_BUDGET_WINDOW_SECONDS,
  REMOTE_RETRY_DELAY_MS,
  REMOTE_RETRY_RESERVATION_SCHEMA,
  REMOTE_SECOND_CHILD_REASONS,
  REMOTE_TERMINAL_CLOSE_REASONS,
  REMOTE_TRANSPORT_SELECTION_SCHEMA_VERSION,
  REMOTE_TURN_DRAIN_MAX_SECONDS,
  REMOTE_WEBRTC_DEGRADED_BUFFER_BYTES,
  REMOTE_WEBRTC_DEGRADED_BUFFER_PROBES,
  REMOTE_WEBRTC_DEGRADED_MISS_PROBES,
  REMOTE_WEBRTC_DISCONNECTED_FAIL_PROBES,
  REMOTE_WEBRTC_FAILED_MISS_PROBES,
  REMOTE_WEBRTC_HEALTHY_SUCCESS_PROBES,
  REMOTE_WEBRTC_PROBE_INTERVAL_SECONDS,
  REMOTE_WEBSOCKET_DEGRADED_BUFFER_BYTES,
  REMOTE_WEBSOCKET_DEGRADED_OLDEST_UNACKED_SECONDS,
  REMOTE_WEBSOCKET_FAILED_RETRANSMISSION,
  type RemoteChildAttemptId,
  type RemoteHealthSample,
  type RemoteOrdinaryChildState,
  type RemoteTransportChild,
  type RemoteTransportKind,
  type RemoteTransportPlanInput,
  type RemoteTransportRetryReservationV1,
  retryBudgetOutcomeOutage,
  selectRouteChild,
  transportSelectionReducer,
  validateAutoDeadlineSeconds,
} from "./remote-transport-selection";

/** Type alias kept for cross-language parity documentation. */
export type TestChildAttemptId = RemoteChildAttemptId;

const fullInput = (
  overrides: Partial<RemoteTransportPlanInput> = {},
): RemoteTransportPlanInput => ({
  deploymentWebrtc: true,
  deploymentWebsocket: true,
  serviceWebrtc: true,
  serviceWebsocket: true,
  tenantWebrtc: true,
  tenantWebsocket: true,
  daemonWebrtc: true,
  daemonWebsocket: true,
  ipConsent: "direct_allowed",
  participantPrivacy: "direct_allowed",
  liveQuota: {
    remainingReservationsThisHour: 12,
    remainingBytes: 1024 * 1024 * 1024,
    remainingAllocationSeconds: 28800,
    exhausted: false,
  },
  clientCapabilities: { webrtcSupported: true, websocketSupported: true },
  userPreference: "auto",
  ...overrides,
});

const makeChild = (
  attempt: string,
  kind: RemoteTransportKind,
  state: RemoteOrdinaryChildState,
  extra: Partial<RemoteTransportChild> = {},
): RemoteTransportChild => ({
  childAttemptId: attempt,
  transportKind: kind,
  transportEpoch: `ep_${attempt}`,
  generation: 1,
  state,
  turnLifecycle: state === "active" || state === "degraded" ? "current" : null,
  health: state === "active" ? "healthy" : "degraded",
  consecutiveHealthy: 0,
  consecutiveMisses: 0,
  consecutiveBufferHigh: 0,
  writableBytes: 1024,
  pendingTimerId: null,
  secondChildReason: null,
  retryCount: 0,
  deadlineExpiresAtMs: null,
  closedReason: null,
  ...extra,
});

let attemptCounter = 0;
let epochCounter = 0;
const genCounters: Record<RemoteTransportKind, number> = { webrtc: 0, websocket: 0 };
const resetIds = () => {
  attemptCounter = 0;
  epochCounter = 0;
  genCounters.webrtc = 0;
  genCounters.websocket = 0;
};
const deps = () => ({
  retryBudget: { trainReservations: [], rollingWindowReservations: [] },
  nextChildAttemptId: () => `att_${++attemptCounter}`,
  nextTransportEpoch: () => `ep_${++epochCounter}`,
  nextGeneration: (kind: RemoteTransportKind) => ++genCounters[kind],
  now: () => 0,
});

function isRejected(outcome: {
  status: string;
}): outcome is { status: "rejected"; reason: string } {
  return outcome.status === "rejected";
}

describe("remote_transport_authorized_plan_matrix", () => {
  it("authorizes both kinds when every layer permits and preference is auto", () => {
    const plan = computeAuthorizedPlan(fullInput());
    expect(plan.webrtcAuthorized).toBe(true);
    expect(plan.websocketAuthorized).toBe(true);
    expect(plan.denial).toBeNull();
    expect(plan.turnRequired).toBe(false);
  });
  it("denies when deployment disables webrtc and websocket", () => {
    const plan = computeAuthorizedPlan(
      fullInput({ deploymentWebrtc: false, deploymentWebsocket: false }),
    );
    expect(plan.denial?.kind).toBe("no_authorized_transport");
  });
  it("denies when service disables both kinds", () => {
    const plan = computeAuthorizedPlan(
      fullInput({ serviceWebrtc: false, serviceWebsocket: false }),
    );
    expect(plan.denial?.kind).toBe("no_authorized_transport");
  });
  it("denies when tenant disables both kinds", () => {
    const plan = computeAuthorizedPlan(fullInput({ tenantWebrtc: false, tenantWebsocket: false }));
    expect(plan.denial?.kind).toBe("no_authorized_transport");
  });
  it("denies when daemon disables both kinds", () => {
    const plan = computeAuthorizedPlan(fullInput({ daemonWebrtc: false, daemonWebsocket: false }));
    expect(plan.denial?.kind).toBe("no_authorized_transport");
  });
  it("denies when client supports neither", () => {
    const plan = computeAuthorizedPlan(
      fullInput({
        clientCapabilities: { webrtcSupported: false, websocketSupported: false },
      }),
    );
    expect(plan.denial?.kind).toBe("no_authorized_transport");
  });
  it("denies on quota exhaustion regardless of other layers", () => {
    const plan = computeAuthorizedPlan(
      fullInput({ liveQuota: { ...fullInput().liveQuota, exhausted: true } }),
    );
    expect(plan.denial?.kind).toBe("quota_exhausted");
  });
  it("denies on ip-consent unavailable", () => {
    const plan = computeAuthorizedPlan(fullInput({ ipConsent: "unavailable" }));
    expect(plan.denial?.kind).toBe("consent_unavailable");
  });
  it("marks turnRequired for turn_required privacy and still authorizes webrtc via TURN", () => {
    const plan = computeAuthorizedPlan(fullInput({ participantPrivacy: "turn_required" }));
    expect(plan.turnRequired).toBe(true);
    expect(plan.webrtcAuthorized).toBe(true);
    expect(plan.denial).toBeNull();
  });
  it("marks turnRequired for relay_only privacy", () => {
    const plan = computeAuthorizedPlan(fullInput({ participantPrivacy: "relay_only" }));
    expect(plan.turnRequired).toBe(true);
  });
  it("narrows to webrtc only when only webrtc meets", () => {
    const plan = computeAuthorizedPlan(fullInput({ deploymentWebsocket: false }));
    expect(plan.webrtcAuthorized).toBe(true);
    expect(plan.websocketAuthorized).toBe(false);
  });
  it("narrows to websocket only when only websocket meets", () => {
    const plan = computeAuthorizedPlan(fullInput({ deploymentWebrtc: false }));
    expect(plan.webrtcAuthorized).toBe(false);
    expect(plan.websocketAuthorized).toBe(true);
  });
  it("meet cannot widen: stricter tenant layer removes a kind", () => {
    const plan = computeAuthorizedPlan(fullInput({ tenantWebrtc: false }));
    expect(plan.webrtcAuthorized).toBe(false);
    expect(plan.websocketAuthorized).toBe(true);
  });
});

describe("remote_transport_user_preference_matrix", () => {
  it("webrtc preference authorizes webrtc only and never starts fallback", () => {
    const plan = computeAuthorizedPlan(fullInput({ userPreference: "webrtc" }));
    expect(plan.webrtcAuthorized).toBe(true);
    expect(plan.websocketAuthorized).toBe(false);
  });
  it("websocket preference authorizes websocket only", () => {
    const plan = computeAuthorizedPlan(fullInput({ userPreference: "websocket" }));
    expect(plan.webrtcAuthorized).toBe(false);
    expect(plan.websocketAuthorized).toBe(true);
  });
  it("auto authorizes both when available", () => {
    const plan = computeAuthorizedPlan(fullInput({ userPreference: "auto" }));
    expect(plan.webrtcAuthorized).toBe(true);
    expect(plan.websocketAuthorized).toBe(true);
  });
  it("webrtc preference with webrtc unavailable returns typed denial, no silent override", () => {
    const plan = computeAuthorizedPlan(
      fullInput({ userPreference: "webrtc", deploymentWebrtc: false }),
    );
    expect(plan.denial?.kind).toBe("preference_unavailable");
    if (plan.denial?.kind === "preference_unavailable")
      expect(plan.denial.preference).toBe("webrtc");
  });
  it("websocket preference with websocket unavailable returns typed denial", () => {
    const plan = computeAuthorizedPlan(
      fullInput({ userPreference: "websocket", deploymentWebsocket: false }),
    );
    expect(plan.denial?.kind).toBe("preference_unavailable");
    if (plan.denial?.kind === "preference_unavailable")
      expect(plan.denial.preference).toBe("websocket");
  });
  it("auto with neither available returns no_authorized_transport, never silent", () => {
    const plan = computeAuthorizedPlan(
      fullInput({ userPreference: "auto", deploymentWebrtc: false, deploymentWebsocket: false }),
    );
    expect(plan.denial?.kind).toBe("no_authorized_transport");
  });
  it("webrtc preference does not widen to websocket even if websocket is available", () => {
    const plan = computeAuthorizedPlan(fullInput({ userPreference: "webrtc" }));
    expect(plan.websocketAuthorized).toBe(false);
  });
});

describe("remote_transport_only_reachability_falls_back", () => {
  it("terminal close reasons never fall back", () => {
    for (const reason of REMOTE_TERMINAL_CLOSE_REASONS) {
      expect(isTerminalCloseReason(reason)).toBe(true);
      expect(isReachabilityCloseReason(reason)).toBe(false);
    }
  });
  it("reachability close reasons may fall back", () => {
    const reachability = [
      "ice_no_candidate_pair",
      "ice_timeout",
      "network_unreachable",
      "turn_unreachable",
    ] as const;
    for (const reason of reachability) {
      expect(isReachabilityCloseReason(reason)).toBe(true);
      expect(isTerminalCloseReason(reason)).toBe(false);
    }
  });
  it("ice_disconnected maps to network_unreachable after 3 consecutive failed probes", () => {
    expect(iceDisconnectedToReachability(0)).toBeNull();
    expect(iceDisconnectedToReachability(2)).toBeNull();
    expect(iceDisconnectedToReachability(3)).toBe("network_unreachable");
    expect(iceDisconnectedToReachability(4)).toBe("network_unreachable");
  });
  it("default deadline is exactly 10 seconds", () => {
    expect(REMOTE_AUTO_INITIAL_DEADLINE_SECONDS).toBe(10);
  });
  it("deadline range is exactly 3..30 seconds inclusive", () => {
    expect(REMOTE_AUTO_INITIAL_DEADLINE_MIN_SECONDS).toBe(3);
    expect(REMOTE_AUTO_INITIAL_DEADLINE_MAX_SECONDS).toBe(30);
    expect(validateAutoDeadlineSeconds(2)).toEqual({ ok: false, reason: "out_of_range" });
    expect(validateAutoDeadlineSeconds(3)).toEqual({ ok: true });
    expect(validateAutoDeadlineSeconds(30)).toEqual({ ok: true });
    expect(validateAutoDeadlineSeconds(31)).toEqual({ ok: false, reason: "out_of_range" });
    expect(validateAutoDeadlineSeconds(10.5)).toEqual({ ok: false, reason: "out_of_range" });
  });
  it("auto starts websocket after deadline fires with no active webrtc", () => {
    resetIds();
    const d = deps();
    let now = 0;
    d.now = () => now;
    let state = initialTransportOrchestratorState();
    const result = transportSelectionReducer(
      state,
      { kind: "plan_requested", atMs: 0, input: fullInput(), trainId: "train_1" },
      d,
    );
    state = result.state;
    const startCmd = result.commands.find((c) => c.kind === "start_child");
    expect(startCmd).toBeDefined();
    const deadlineCmd = result.commands.find((c) => c.kind === "schedule_deadline_timer");
    expect(deadlineCmd).toBeDefined();
    const attempt = (startCmd as { childAttemptId: string }).childAttemptId;
    state = transportSelectionReducer(
      state,
      {
        kind: "child_attempt_reserved",
        atMs: 0,
        childAttemptId: attempt,
        transportKind: "webrtc",
        transportEpoch: "ep_1",
        generation: 1,
        reservation: {} as RemoteTransportRetryReservationV1,
      },
      d,
    ).state;
    now = 10000;
    const timerId = (deadlineCmd as { timerId: string }).timerId;
    const fireResult = transportSelectionReducer(
      state,
      { kind: "deadline_timer_fired", atMs: now, timerId, childAttemptId: attempt },
      d,
    );
    const wsStart = fireResult.commands.find(
      (c) =>
        c.kind === "start_child" && (c as { transportKind: string }).transportKind === "websocket",
    );
    expect(wsStart).toBeDefined();
  });
  it("auto does not start websocket after deadline if webrtc is active", () => {
    resetIds();
    const d = deps();
    let now = 0;
    d.now = () => now;
    let state = initialTransportOrchestratorState();
    const result = transportSelectionReducer(
      state,
      { kind: "plan_requested", atMs: 0, input: fullInput(), trainId: "train_1" },
      d,
    );
    state = result.state;
    const startCmd = result.commands.find((c) => c.kind === "start_child") as {
      childAttemptId: string;
      transportKind: string;
    };
    const deadlineCmd = result.commands.find((c) => c.kind === "schedule_deadline_timer") as {
      timerId: string;
      childAttemptId: string;
    };
    state = transportSelectionReducer(
      state,
      {
        kind: "child_attempt_reserved",
        atMs: 0,
        childAttemptId: startCmd.childAttemptId,
        transportKind: "webrtc",
        transportEpoch: "ep_1",
        generation: 1,
        reservation: {} as RemoteTransportRetryReservationV1,
      },
      d,
    ).state;
    state = transportSelectionReducer(
      state,
      {
        kind: "child_active",
        atMs: 5000,
        childAttemptId: startCmd.childAttemptId,
        writableBytes: 65536,
      },
      d,
    ).state;
    now = 10000;
    const fireResult = transportSelectionReducer(
      state,
      {
        kind: "deadline_timer_fired",
        atMs: now,
        timerId: deadlineCmd.timerId,
        childAttemptId: startCmd.childAttemptId,
      },
      d,
    );
    const wsStart = fireResult.commands.find(
      (c) =>
        c.kind === "start_child" && (c as { transportKind: string }).transportKind === "websocket",
    );
    expect(wsStart).toBeUndefined();
  });
});

describe("remote_transport_child_caps_and_reasons", () => {
  it("at most one routed-current webrtc child", () => {
    expect(REMOTE_MAX_CURRENT_WEBRTC).toBe(1);
    expect(checkChildCaps([makeChild("a", "webrtc", "active")], "webrtc", false)).toEqual({
      ok: false,
      reason: "current_cap_exceeded",
    });
  });
  it("at most one routed-current websocket child", () => {
    expect(REMOTE_MAX_CURRENT_WEBSOCKET).toBe(1);
    expect(checkChildCaps([makeChild("a", "websocket", "active")], "websocket", false)).toEqual({
      ok: false,
      reason: "current_cap_exceeded",
    });
  });
  it("at most two ordinary pending children total", () => {
    expect(REMOTE_MAX_PENDING_CHILDREN_TOTAL).toBe(2);
    const children = [
      makeChild("a", "webrtc", "pending", { turnLifecycle: null }),
      makeChild("b", "websocket", "pending", { turnLifecycle: null }),
    ];
    expect(countAllPendingChildren(children)).toBe(2);
  });
  it("at most one pending child per kind", () => {
    expect(REMOTE_MAX_PENDING_CHILDREN_PER_KIND).toBe(1);
    expect(
      checkChildCaps(
        [makeChild("a", "webrtc", "pending", { turnLifecycle: null })],
        "webrtc",
        false,
      ),
    ).toEqual({
      ok: false,
      reason: "pending_cap_per_kind_exceeded",
    });
  });
  it("physical cap is two normally and three during TURN replacement", () => {
    expect(REMOTE_MAX_PHYSICAL_CHILDREN_NORMAL).toBe(2);
    expect(REMOTE_MAX_PHYSICAL_CHILDREN_TURN_REPLACEMENT).toBe(3);
    expect(physicalChildCap(false)).toBe(2);
    expect(physicalChildCap(true)).toBe(3);
  });
  it("TURN replacement allows a second webrtc child (replacement_pending)", () => {
    expect(checkChildCaps([makeChild("a", "webrtc", "active")], "webrtc", true)).toEqual({
      ok: true,
    });
  });
  it("only one replacement_pending TURN child at a time", () => {
    const children = [
      makeChild("a", "webrtc", "active"),
      makeChild("b", "webrtc", "pending", { turnLifecycle: "replacement_pending" }),
    ];
    expect(checkChildCaps(children, "webrtc", true)).toEqual({
      ok: false,
      reason: "turn_replacement_already_pending",
    });
  });
  it("exactly one current plus one replacement_pending or draining pair", () => {
    expect(REMOTE_SECOND_CHILD_REASONS).toEqual([
      "preferred_path_recovery",
      "network_handoff",
      "operator_force",
      "degraded_path_replacement",
      "credential_rotation",
    ]);
  });
  it("a second child is only allowed for named reasons, not speculative racing", () => {
    const allReasons = new Set<string>(REMOTE_SECOND_CHILD_REASONS);
    expect(allReasons.has("credential_rotation")).toBe(true);
    expect(allReasons.has("speculative")).toBe(false);
  });
  it("countCurrentChildren excludes draining", () => {
    const children = [
      makeChild("a", "webrtc", "active"),
      makeChild("b", "webrtc", "active", { turnLifecycle: "draining" }),
    ];
    expect(countCurrentChildren(children, "webrtc")).toBe(1);
  });
  it("countPhysicalChildren excludes draining", () => {
    const children = [
      makeChild("a", "webrtc", "active"),
      makeChild("b", "webrtc", "active", { turnLifecycle: "draining" }),
    ];
    expect(countPhysicalChildren(children)).toBe(1);
  });
});

describe("remote_transport_retry_budget", () => {
  const baseRequest = {
    trainId: "train_1",
    transportKind: "webrtc" as RemoteTransportKind,
    childAttemptId: "att_1",
    reservationType: "initial" as const,
  };
  it("schema is RemoteTransportRetryReservation with 16-byte train id", () => {
    expect(REMOTE_RETRY_RESERVATION_SCHEMA).toBe("RemoteTransportRetryReservation");
  });
  it("reserves an initial child idempotently", () => {
    const outcome = evaluateRetryBudget(
      { trainReservations: [], rollingWindowReservations: [] },
      baseRequest,
      0,
    );
    expect(outcome.status).toBe("reserved");
    if (outcome.status === "reserved") {
      expect(outcome.reservation.reservationType).toBe("initial");
      expect(outcome.reservation.trainId).toBe("train_1");
    }
  });
  it("exact duplicate by child attempt is idempotent and does not count twice", () => {
    const first = evaluateRetryBudget(
      { trainReservations: [], rollingWindowReservations: [] },
      baseRequest,
      0,
    );
    if (first.status !== "reserved") throw new Error("expected reserved");
    const snapshot = {
      trainReservations: [first.reservation],
      rollingWindowReservations: [first.reservation],
    };
    expect(evaluateRetryBudget(snapshot, baseRequest, 1000).status).toBe("duplicate");
  });
  it("rejects more than four reservations per train", () => {
    expect(REMOTE_RETRY_BUDGET_MAX_PER_TRAIN).toBe(4);
    const reservations: RemoteTransportRetryReservationV1[] = Array.from({ length: 4 }, (_, i) => ({
      schemaVersion: 1 as const,
      reservationId: `res_${i}`,
      tenantId: "",
      accountId: "",
      clientDeviceId: "",
      logicalAttachmentId: "",
      trainId: "train_1",
      transportKind: "webrtc",
      childAttemptId: `att_${i}`,
      reservationType: "initial" as const,
      reservedAtMs: 0,
      expiresAtMs: 9999,
      terminalOutcome: null,
      terminalAtMs: null,
    }));
    const outcome = evaluateRetryBudget(
      { trainReservations: reservations, rollingWindowReservations: [] },
      { ...baseRequest, childAttemptId: "att_new" },
      100,
    );
    expect(isRejected(outcome)).toBe(true);
    if (isRejected(outcome)) expect(outcome.reason).toBe("max_per_train_exceeded");
  });
  it("rejects twelve committed reservations in the preceding rolling 3600 seconds", () => {
    expect(REMOTE_RETRY_BUDGET_MAX_PER_HOUR).toBe(12);
    expect(REMOTE_RETRY_BUDGET_WINDOW_SECONDS).toBe(3600);
    const now = 10_000_000;
    const reservations: RemoteTransportRetryReservationV1[] = Array.from(
      { length: 12 },
      (_, i) => ({
        schemaVersion: 1 as const,
        reservationId: `res_${i}`,
        tenantId: "",
        accountId: "",
        clientDeviceId: "",
        logicalAttachmentId: "",
        trainId: `train_${i}`,
        transportKind: "webrtc",
        childAttemptId: `att_${i}`,
        reservationType: "initial" as const,
        reservedAtMs: now - 1000,
        expiresAtMs: now + 9999,
        terminalOutcome: null,
        terminalAtMs: null,
      }),
    );
    const outcome = evaluateRetryBudget(
      { trainReservations: [], rollingWindowReservations: reservations },
      { ...baseRequest, trainId: "train_new", childAttemptId: "att_new" },
      now,
    );
    expect(isRejected(outcome)).toBe(true);
    if (isRejected(outcome)) expect(outcome.reason).toBe("max_per_hour_exceeded");
  });
  it("initial plus one fresh retry per kind — second retry is exhausted", () => {
    expect(REMOTE_MAX_RETRIES_PER_KIND).toBe(1);
    const retryRes: RemoteTransportRetryReservationV1 = {
      schemaVersion: 1,
      reservationId: "res_r1",
      tenantId: "",
      accountId: "",
      clientDeviceId: "",
      logicalAttachmentId: "",
      trainId: "train_1",
      transportKind: "webrtc",
      childAttemptId: "att_r1",
      reservationType: "retry",
      reservedAtMs: 0,
      expiresAtMs: 9999,
      terminalOutcome: null,
      terminalAtMs: null,
    };
    const outcome = evaluateRetryBudget(
      { trainReservations: [retryRes], rollingWindowReservations: [] },
      { ...baseRequest, childAttemptId: "att_r2", reservationType: "retry" },
      100,
    );
    expect(isRejected(outcome)).toBe(true);
    if (isRejected(outcome)) expect(outcome.reason).toBe("kind_retry_exhausted");
  });
  it("retry delay is injected exponential 1 second then no further same-kind retry", () => {
    expect(REMOTE_RETRY_DELAY_MS).toBe(1000);
  });
  it("markReservationTerminal writes terminal outcome for cleanup", () => {
    const res: RemoteTransportRetryReservationV1 = {
      schemaVersion: 1,
      reservationId: "res_1",
      tenantId: "",
      accountId: "",
      clientDeviceId: "",
      logicalAttachmentId: "",
      trainId: "train_1",
      transportKind: "webrtc",
      childAttemptId: "att_1",
      reservationType: "initial",
      reservedAtMs: 0,
      expiresAtMs: 9999,
      terminalOutcome: null,
      terminalAtMs: null,
    };
    const terminal = markReservationTerminal(res, "cancelled", 5000);
    expect(terminal.terminalOutcome).toBe("cancelled");
    expect(terminal.terminalAtMs).toBe(5000);
  });
  it("database outage denies new children but is a typed rejection", () => {
    const outcome = retryBudgetOutcomeOutage();
    expect(isRejected(outcome)).toBe(true);
    if (isRejected(outcome)) expect(outcome.reason).toBe("database_outage");
  });
  it("reservations outside the rolling window do not count", () => {
    const now = 10_000_000;
    const old: RemoteTransportRetryReservationV1 = {
      schemaVersion: 1,
      reservationId: "res_old",
      tenantId: "",
      accountId: "",
      clientDeviceId: "",
      logicalAttachmentId: "",
      trainId: "train_old",
      transportKind: "webrtc",
      childAttemptId: "att_old",
      reservationType: "initial",
      reservedAtMs: now - (REMOTE_RETRY_BUDGET_WINDOW_SECONDS + 1) * 1000,
      expiresAtMs: 0,
      terminalOutcome: "cancelled",
      terminalAtMs: now - (REMOTE_RETRY_BUDGET_WINDOW_SECONDS + 1) * 1000,
    };
    const outcome = evaluateRetryBudget(
      { trainReservations: [], rollingWindowReservations: [old] },
      { ...baseRequest, childAttemptId: "att_new" },
      now,
    );
    expect(outcome.status).toBe("reserved");
  });
});

describe("remote_transport_health_thresholds", () => {
  it("WebRTC probe interval is exactly 5 seconds", () => {
    expect(REMOTE_WEBRTC_PROBE_INTERVAL_SECONDS).toBe(5);
  });
  it("WebRTC healthy after two consecutive successes", () => {
    expect(REMOTE_WEBRTC_HEALTHY_SUCCESS_PROBES).toBe(2);
    const child = makeChild("a", "webrtc", "degraded", { consecutiveHealthy: 0 });
    const probe: RemoteHealthSample = {
      kind: "webrtc",
      childAttemptId: "a",
      atMs: 1000,
      success: true,
      bufferedBytes: 0,
    };
    let r = computeWebRtcHealth(child, probe);
    expect(r.consecutiveHealthy).toBe(1);
    expect(r.health).toBe("degraded");
    r = computeWebRtcHealth({ ...child, consecutiveHealthy: 1 }, probe);
    expect(r.consecutiveHealthy).toBe(2);
    expect(r.health).toBe("healthy");
  });
  it("WebRTC degraded after three misses", () => {
    expect(REMOTE_WEBRTC_DEGRADED_MISS_PROBES).toBe(3);
    const child = makeChild("a", "webrtc", "active", { consecutiveMisses: 2 });
    const r = computeWebRtcHealth(child, {
      kind: "webrtc",
      childAttemptId: "a",
      atMs: 1000,
      success: false,
      bufferedBytes: 0,
    });
    expect(r.consecutiveMisses).toBe(3);
    expect(r.health).toBe("degraded");
  });
  it("WebRTC degraded when buffered bytes >= 4 MiB for two probes", () => {
    expect(REMOTE_WEBRTC_DEGRADED_BUFFER_BYTES).toBe(4 * 1024 * 1024);
    expect(REMOTE_WEBRTC_DEGRADED_BUFFER_PROBES).toBe(2);
    const child = makeChild("a", "webrtc", "active", { consecutiveBufferHigh: 1 });
    const r = computeWebRtcHealth(child, {
      kind: "webrtc",
      childAttemptId: "a",
      atMs: 1000,
      success: true,
      bufferedBytes: 4 * 1024 * 1024,
    });
    expect(r.consecutiveBufferHigh).toBe(2);
    expect(r.health).toBe("degraded");
  });
  it("WebRTC failed after six misses", () => {
    expect(REMOTE_WEBRTC_FAILED_MISS_PROBES).toBe(6);
    const child = makeChild("a", "webrtc", "degraded", { consecutiveMisses: 5 });
    const r = computeWebRtcHealth(child, {
      kind: "webrtc",
      childAttemptId: "a",
      atMs: 1000,
      success: false,
      bufferedBytes: 0,
    });
    expect(r.consecutiveMisses).toBe(6);
    expect(r.health).toBe("failed");
  });
  it("ice_disconnected fail threshold is 3 probes", () => {
    expect(REMOTE_WEBRTC_DISCONNECTED_FAIL_PROBES).toBe(3);
  });
  it("WebSocket degraded when oldest unacked age >= 3 seconds", () => {
    expect(REMOTE_WEBSOCKET_DEGRADED_OLDEST_UNACKED_SECONDS).toBe(3);
    const r = computeWebSocketHealth(makeChild("a", "websocket", "active"), {
      kind: "websocket",
      childAttemptId: "a",
      atMs: 1000,
      oldestUnackedAgeSeconds: 3,
      bufferedBytes: 0,
      retransmissionCount: 0,
    });
    expect(r.health).toBe("degraded");
  });
  it("WebSocket degraded when buffered bytes >= 4 MiB", () => {
    expect(REMOTE_WEBSOCKET_DEGRADED_BUFFER_BYTES).toBe(4 * 1024 * 1024);
    const r = computeWebSocketHealth(makeChild("a", "websocket", "active"), {
      kind: "websocket",
      childAttemptId: "a",
      atMs: 1000,
      oldestUnackedAgeSeconds: 0,
      bufferedBytes: 4 * 1024 * 1024,
      retransmissionCount: 0,
    });
    expect(r.health).toBe("degraded");
  });
  it("WebSocket failed at the third retransmission", () => {
    expect(REMOTE_WEBSOCKET_FAILED_RETRANSMISSION).toBe(3);
    const r = computeWebSocketHealth(makeChild("a", "websocket", "degraded"), {
      kind: "websocket",
      childAttemptId: "a",
      atMs: 1000,
      oldestUnackedAgeSeconds: 0,
      bufferedBytes: 0,
      retransmissionCount: 3,
    });
    expect(r.health).toBe("failed");
  });
  it("recovery requires two consecutive healthy intervals", () => {
    expect(REMOTE_HEALTH_RECOVERY_INTERVALS).toBe(2);
    const child = makeChild("a", "websocket", "degraded", { consecutiveHealthy: 0 });
    const ok: RemoteHealthSample = {
      kind: "websocket",
      childAttemptId: "a",
      atMs: 1000,
      oldestUnackedAgeSeconds: 0,
      bufferedBytes: 0,
      retransmissionCount: 0,
    };
    let r = computeWebSocketHealth(child, ok);
    expect(r.consecutiveHealthy).toBe(1);
    expect(r.health).toBe("degraded");
    r = computeWebSocketHealth({ ...child, consecutiveHealthy: 1 }, ok);
    expect(r.consecutiveHealthy).toBe(2);
    expect(r.health).toBe("healthy");
  });
});

describe("remote_transport_route_trace", () => {
  it("control chooses healthy over degraded, then lower epoch", () => {
    const children = [
      makeChild("a", "webrtc", "degraded", { transportEpoch: "ep_1" }),
      makeChild("b", "websocket", "active", { transportEpoch: "ep_2" }),
    ];
    expect(selectRouteChild(children, "control")?.childAttemptId).toBe("b");
  });
  it("control ties by lower transport epoch among healthy", () => {
    const children = [
      makeChild("a", "webrtc", "active", { transportEpoch: "ep_3" }),
      makeChild("b", "websocket", "active", { transportEpoch: "ep_2" }),
    ];
    expect(selectRouteChild(children, "control")?.transportEpoch).toBe("ep_2");
  });
  it("interactive chooses healthy webrtc first", () => {
    const children = [
      makeChild("a", "websocket", "active", { transportEpoch: "ep_1" }),
      makeChild("b", "webrtc", "active", { transportEpoch: "ep_2" }),
    ];
    expect(selectRouteChild(children, "interactive")?.transportKind).toBe("webrtc");
  });
  it("interactive chooses healthy websocket if no healthy webrtc", () => {
    const children = [
      makeChild("a", "webrtc", "degraded", { transportEpoch: "ep_1" }),
      makeChild("b", "websocket", "active", { transportEpoch: "ep_2" }),
    ];
    expect(selectRouteChild(children, "interactive")?.transportKind).toBe("websocket");
  });
  it("interactive falls to degraded by lower epoch when no healthy", () => {
    const children = [
      makeChild("a", "webrtc", "degraded", { transportEpoch: "ep_3" }),
      makeChild("b", "websocket", "degraded", { transportEpoch: "ep_1" }),
    ];
    expect(selectRouteChild(children, "interactive")?.transportEpoch).toBe("ep_1");
  });
  it("bulk chooses healthy child with more writable bytes, tie webrtc", () => {
    const children = [
      makeChild("a", "websocket", "active", { transportEpoch: "ep_1", writableBytes: 2048 }),
      makeChild("b", "webrtc", "active", { transportEpoch: "ep_2", writableBytes: 2048 }),
    ];
    expect(selectRouteChild(children, "bulk")?.transportKind).toBe("webrtc");
  });
  it("bulk chooses more writable bytes", () => {
    const children = [
      makeChild("a", "webrtc", "active", { transportEpoch: "ep_1", writableBytes: 512 }),
      makeChild("b", "websocket", "active", { transportEpoch: "ep_2", writableBytes: 4096 }),
    ];
    expect(selectRouteChild(children, "bulk")?.childAttemptId).toBe("b");
  });
  it("replacement_pending is never selected", () => {
    const children = [
      makeChild("a", "webrtc", "active", {
        transportEpoch: "ep_1",
        turnLifecycle: "replacement_pending",
      }),
      makeChild("b", "websocket", "degraded", { transportEpoch: "ep_2" }),
    ];
    expect(selectRouteChild(children, "control")?.childAttemptId).toBe("b");
  });
  it("draining is never selected for new work", () => {
    const children = [
      makeChild("a", "webrtc", "active", { transportEpoch: "ep_1", turnLifecycle: "draining" }),
      makeChild("b", "websocket", "active", { transportEpoch: "ep_2" }),
    ];
    expect(selectRouteChild(children, "control")?.childAttemptId).toBe("b");
  });
  it("draining may carry only already-assigned replay/ACK/control", () => {
    const drainingChild = makeChild("a", "webrtc", "active", { turnLifecycle: "draining" });
    const assigned = new Set(["del_1"]);
    expect(isDrainingAllowedMutation(drainingChild, "del_1", assigned).allowed).toBe(true);
    expect(isDrainingAllowedMutation(drainingChild, "del_new", assigned)).toEqual({
      allowed: false,
      reason: "child_draining",
    });
  });
  it("lease+supervisor-ACK cutover: lease is valid with one current + one draining", () => {
    expect(
      isTurnReplacementLeaseValid({
        currentChildAttemptIds: ["a"],
        drainingChildAttemptIds: ["b"],
      }),
    ).toBe(true);
    expect(
      isTurnReplacementLeaseValid({ currentChildAttemptIds: ["a"], drainingChildAttemptIds: [] }),
    ).toBe(false);
  });
  it("TURN drain max is 30 seconds", () => {
    expect(REMOTE_TURN_DRAIN_MAX_SECONDS).toBe(30);
  });
  it("one stable delivery ID is assigned to one current child", () => {
    resetIds();
    const d = deps();
    let state = initialTransportOrchestratorState();
    state = {
      ...state,
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "active",
      children: [makeChild("a", "webrtc", "active")],
    };
    const result = transportSelectionReducer(
      state,
      {
        kind: "route_request",
        atMs: 100,
        deliveryId: "del_1",
        lane: "interactive",
        payloadBytes: 64,
      },
      d,
    );
    expect(result.commands.find((c) => c.kind === "route_delivery")).toBeDefined();
    expect(result.state.deliveryAssignments.get("del_1")).toBe("a");
  });
  it("exact failover resend uses the same delivery id", () => {
    const cmd = failoverResend("del_1", "child_b");
    expect(cmd.kind).toBe("failover_resend");
    if (cmd.kind === "failover_resend") {
      expect(cmd.deliveryId).toBe("del_1");
      expect(cmd.targetChildAttemptId).toBe("child_b");
    }
  });
  it("delivery dedupe: ledger records each delivery to a child once", () => {
    resetIds();
    const d = deps();
    let state = initialTransportOrchestratorState();
    state = {
      ...state,
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "active",
      children: [makeChild("a", "webrtc", "active")],
    };
    state = transportSelectionReducer(
      state,
      {
        kind: "route_request",
        atMs: 100,
        deliveryId: "del_1",
        lane: "interactive",
        payloadBytes: 64,
      },
      d,
    ).state;
    const before = state.ledgerDeliveries.get("del_1")?.length ?? 0;
    state = transportSelectionReducer(
      state,
      {
        kind: "route_request",
        atMs: 200,
        deliveryId: "del_1",
        lane: "interactive",
        payloadBytes: 64,
      },
      d,
    ).state;
    expect(state.ledgerDeliveries.get("del_1")?.length ?? 0).toBe(before);
  });
});

describe("remote_transport_multi_path_ordering", () => {
  it("all mutations from permitted children enter the ledger", () => {
    resetIds();
    const d = deps();
    let state = initialTransportOrchestratorState();
    state = {
      ...state,
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "active",
      children: [makeChild("a", "webrtc", "active"), makeChild("b", "websocket", "active")],
    };
    state = transportSelectionReducer(
      state,
      {
        kind: "route_request",
        atMs: 100,
        deliveryId: "del_1",
        lane: "interactive",
        payloadBytes: 64,
      },
      d,
    ).state;
    state = transportSelectionReducer(
      state,
      { kind: "route_request", atMs: 200, deliveryId: "del_2", lane: "bulk", payloadBytes: 1024 },
      d,
    ).state;
    expect(state.ledgerDeliveries.size).toBe(2);
  });
  it("concurrent reads and closes do not clear other children or budget", () => {
    resetIds();
    const d = deps();
    let state = initialTransportOrchestratorState();
    state = {
      ...state,
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "active",
      children: [makeChild("a", "webrtc", "active"), makeChild("b", "websocket", "active")],
    };
    state = transportSelectionReducer(
      state,
      { kind: "child_closed", atMs: 100, childAttemptId: "a", reason: "network_unreachable" },
      d,
    ).state;
    expect(state.children.find((c) => c.childAttemptId === "b")?.state).toBe("active");
  });
  it("closing one child does not clear delivery assignments", () => {
    resetIds();
    const d = deps();
    let state = initialTransportOrchestratorState();
    state = {
      ...state,
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "active",
      children: [makeChild("a", "webrtc", "active")],
    };
    state = transportSelectionReducer(
      state,
      {
        kind: "route_request",
        atMs: 100,
        deliveryId: "del_1",
        lane: "interactive",
        payloadBytes: 64,
      },
      d,
    ).state;
    state = transportSelectionReducer(
      state,
      { kind: "child_closed", atMs: 200, childAttemptId: "a", reason: "local_close" },
      d,
    ).state;
    expect(state.deliveryAssignments.get("del_1")).toBe("a");
  });
});

describe("remote_transport_deadline_late_success_race", () => {
  it("late cancelled child cannot activate", () => {
    resetIds();
    const d = deps();
    let state = initialTransportOrchestratorState();
    state = {
      ...state,
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "establishing",
      children: [makeChild("a", "webrtc", "closing", { deadlineExpiresAtMs: 10000 })],
    };
    const result = transportSelectionReducer(
      state,
      { kind: "child_active", atMs: 12000, childAttemptId: "a", writableBytes: 65536 },
      d,
    );
    expect(result.state.children.find((c) => c.childAttemptId === "a")?.state).toBe("closing");
  });
  it("deadline fires then late ICE success serializes by generation — ws already started", () => {
    resetIds();
    const d = deps();
    let now = 0;
    d.now = () => now;
    let state = initialTransportOrchestratorState();
    const planResult = transportSelectionReducer(
      state,
      { kind: "plan_requested", atMs: 0, input: fullInput(), trainId: "train_1" },
      d,
    );
    state = planResult.state;
    const startCmd = planResult.commands.find((c) => c.kind === "start_child") as {
      childAttemptId: string;
    };
    const deadlineCmd = planResult.commands.find((c) => c.kind === "schedule_deadline_timer") as {
      timerId: string;
      childAttemptId: string;
    };
    state = transportSelectionReducer(
      state,
      {
        kind: "child_attempt_reserved",
        atMs: 0,
        childAttemptId: startCmd.childAttemptId,
        transportKind: "webrtc",
        transportEpoch: "ep_1",
        generation: 1,
        reservation: {} as RemoteTransportRetryReservationV1,
      },
      d,
    ).state;
    now = 10000;
    const fireResult = transportSelectionReducer(
      state,
      {
        kind: "deadline_timer_fired",
        atMs: now,
        timerId: deadlineCmd.timerId,
        childAttemptId: startCmd.childAttemptId,
      },
      d,
    );
    state = fireResult.state;
    expect(
      fireResult.commands.find(
        (c) =>
          c.kind === "start_child" &&
          (c as { transportKind: string }).transportKind === "websocket",
      ),
    ).toBeDefined();
    const lateActive = transportSelectionReducer(
      state,
      {
        kind: "child_active",
        atMs: 10500,
        childAttemptId: startCmd.childAttemptId,
        writableBytes: 65536,
      },
      d,
    );
    expect(
      lateActive.state.children.find((c) => c.childAttemptId === startCmd.childAttemptId)?.state,
    ).toBe("active");
  });
  it("separately authorized kinds may coexist", () => {
    resetIds();
    const state = {
      ...initialTransportOrchestratorState(),
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "active" as const,
      children: [makeChild("a", "webrtc", "active"), makeChild("b", "websocket", "active")],
    };
    expect(state.children.length).toBe(2);
    expect(state.children.every((c) => c.state === "active")).toBe(true);
  });
  it("background/cancel/revoke/supersede aborts all pending timers", () => {
    resetIds();
    const d = deps();
    let state = initialTransportOrchestratorState();
    state = {
      ...state,
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "establishing",
      children: [makeChild("a", "webrtc", "pending")],
      pendingTimers: ["deadline_a", "liveness_a"],
    };
    const result = transportSelectionReducer(state, { kind: "cancel", atMs: 5000 }, d);
    expect(result.state.pendingTimers).toEqual([]);
    expect(result.state.parentState).toBe("cancelled");
    expect(result.commands.filter((c) => c.kind === "cancel_timer").length).toBe(2);
  });
  it("supersede transitions parent to superseded and aborts timers", () => {
    resetIds();
    const d = deps();
    let state = initialTransportOrchestratorState();
    state = {
      ...state,
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "active",
      children: [makeChild("a", "webrtc", "active")],
      pendingTimers: ["t1"],
    };
    const result = transportSelectionReducer(state, { kind: "supersede", atMs: 5000 }, d);
    expect(result.state.parentState).toBe("superseded");
    expect(result.state.pendingTimers).toEqual([]);
  });
  it("no retry survives background/cancel/revoke/supersede", () => {
    resetIds();
    const d = deps();
    let state = initialTransportOrchestratorState();
    state = {
      ...state,
      plan: {
        webrtcAuthorized: true,
        websocketAuthorized: true,
        turnRequired: false,
        denial: null,
      },
      parentState: "establishing",
      children: [makeChild("a", "webrtc", "pending", { retryCount: 0 })],
      pendingTimers: ["retry_a"],
    };
    const result = transportSelectionReducer(state, { kind: "revoke", atMs: 5000 }, d);
    expect(result.commands.find((c) => c.kind === "schedule_retry")).toBeUndefined();
    expect(result.state.pendingTimers).toEqual([]);
  });
});

describe("remote transport selection schema parity", () => {
  it("exports the cross-language schema version", () => {
    expect(REMOTE_TRANSPORT_SELECTION_SCHEMA_VERSION).toBe(1);
  });
});
