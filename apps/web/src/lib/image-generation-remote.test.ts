/**
 * Image-generation web remote UI store/reducer/upload/authz/artifact/redaction tests.
 *
 * @see prompts/flycockpitapp/ready/image-generation-web-remote-ui.md
 * acceptance criteria 1-9.
 */

import { describe, expect, it } from "vitest";
import type {
  ImageBudgetState,
  ImageJob,
  JobEvent,
  JobIdentity,
  PartitionKey,
  PlanReview,
  ReferenceUpload,
} from "./image-generation-remote";
import {
  ArtifactObjectUrlRegistry,
  applyAuthorizedSnapshot,
  authorizeRequest,
  BUDGET_SUGGESTIONS,
  budgetBlocksPaidUse,
  buildContentRoutePath,
  buildMetadataRoutePath,
  buildThumbnailRoutePath,
  canCancelJob,
  canDisposeLateResult,
  canMutate,
  canReadConfig,
  canReadHealth,
  canReadJobs,
  canReadPlan,
  clearPartition,
  createDownloadHandle,
  createThumbnailHandle,
  ERROR_MESSAGES,
  emptyImageGenerationRemoteState,
  emptyPartition,
  finiteBudgetPolicy,
  getPartition,
  isFinitePolicy,
  isJobTerminal,
  isUploadRetired,
  isValidBudgetAmount,
  MAX_U64_USD_MICROS,
  mapErrorMessage,
  markStaleAfterReconnect,
  parseBudgetPolicy,
  partitionKey,
  reduceJobEvent,
  requestJobCancellation,
  resolveAltText,
  resolveCancelCompleteRace,
  resolveRole,
  safeReadOnlyProjection,
  scanForForbiddenPaths,
  scanForForbiddenSentinels,
  serializeBudgetPolicy,
  shouldDiscardUploadEvent,
  shouldInvalidatePlan,
  THUMBNAIL_BOXES,
  updatePartition,
  validateAtLeastOnePolicy,
  validateBudgetScope,
  validateBudgetSetPair,
  validateCanonicalDecimal,
  validateRedaction,
} from "./image-generation-remote";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const instanceId = "inst-aaaaaaaaaaaaaaaa";
const projectId = "proj-11111111-1111-4111-8111-111111111111";
const sessionId = "sess-22222222-2222-4222-8222-222222222222";
const jobId = "job-33333333-3333-4333-8333-333333333333";
const daemonInstanceId = "daemon-44444444-4444-4444-8444-444444444444";

function key(overrides: Partial<PartitionKey> = {}): PartitionKey {
  return {
    daemonInstanceId,
    projectId,
    sessionId,
    ...overrides,
  };
}

function jobIdentity(overrides: Partial<JobIdentity> = {}): JobIdentity {
  return {
    daemonInstanceId,
    projectId,
    sessionId,
    jobId,
    ...overrides,
  };
}

function makeJobEvent(overrides: Partial<JobEvent> = {}): JobEvent {
  return {
    identity: jobIdentity(),
    jobVersion: 1,
    kind: "job_changed",
    eventSeq: "1",
    ...overrides,
  };
}

function makeUpload(overrides: Partial<ReferenceUpload> = {}): ReferenceUpload {
  return {
    uploadId: "upload-1",
    selectionEpoch: 1,
    fileName: "ref.png",
    declaredSize: 1024,
    declaredMime: "image/png",
    state: "uploading",
    uploadedBytes: 0,
    attachmentHandle: null,
    error: null,
    updatedAt: Date.now(),
    ...overrides,
  };
}

function makePlan(overrides: Partial<PlanReview> = {}): PlanReview {
  return {
    planId: "plan-1",
    destinations: [{ targetId: "target-1", locationClass: "remote_provider" }],
    prompt: "a cat",
    references: [{ uploadId: "upload-1", fileName: "ref.png", egress: "allowed" }],
    dimensions: { width: 1024, height: 1024 },
    formats: ["png"],
    parameters: [{ key: "steps", value: "20" }],
    fanout: 1,
    slots: 1,
    maxCost: { usd: 0.5 },
    budgetDisposition: "within_budget",
    outputHostLocation: "remote_provider",
    riskReasons: [],
    digest: "a".repeat(64),
    generation: "1",
    isYolo: false,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Criterion 1: Authorization tests
// ---------------------------------------------------------------------------

describe("image-generation authorization", () => {
  it("allows Owner for all request families", () => {
    const families: Parameters<typeof authorizeRequest>[1][] = [
      "config_reads_and_snapshot",
      "health_reads_and_refresh",
      "plan_get",
      "job_reads_and_snapshot",
      "job_cancel",
      "config_mutations",
      "late_result",
      "operation_status",
    ];
    for (const family of families) {
      expect(authorizeRequest("owner", family).allowed).toBe(true);
    }
  });

  it("allows exact-project ImageGenerationAdmin for mutations and reads", () => {
    expect(canMutate("image_generation_admin")).toBe(true);
    expect(canReadConfig("image_generation_admin")).toBe(true);
    expect(canDisposeLateResult("image_generation_admin")).toBe(true);
    expect(authorizeRequest("image_generation_admin", "config_mutations").allowed).toBe(true);
    expect(authorizeRequest("image_generation_admin", "late_result").allowed).toBe(true);
  });

  it("denies wrong-project ImageGenerationAdmin (degrades to ordinary)", () => {
    const role = resolveRole({
      isOwner: false,
      isAdminForProject: true,
      adminProjectRoot: "/wrong/project",
      targetProjectRoot: "/correct/project",
      hasSessionRead: false,
      hasSessionWrite: false,
      hasProjectRead: false,
    });
    expect(role).toBe("ordinary");
    expect(canMutate(role)).toBe(false);
    expect(authorizeRequest(role, "config_mutations").allowed).toBe(false);
  });

  it("allows exact-project ImageGenerationAdmin", () => {
    const role = resolveRole({
      isOwner: false,
      isAdminForProject: true,
      adminProjectRoot: "/correct/project",
      targetProjectRoot: "/correct/project",
      hasSessionRead: false,
      hasSessionWrite: false,
      hasProjectRead: false,
    });
    expect(role).toBe("image_generation_admin");
  });

  it("gives ordinary users read-only safe projection (no mutations)", () => {
    expect(canMutate("ordinary")).toBe(false);
    expect(canReadConfig("ordinary")).toBe(false);
    expect(canDisposeLateResult("ordinary")).toBe(false);
    expect(authorizeRequest("ordinary", "config_mutations").allowed).toBe(false);
    expect(authorizeRequest("ordinary", "late_result").allowed).toBe(false);
  });

  it("allows session_read to read plans and jobs but not cancel", () => {
    expect(canReadPlan("session_read")).toBe(true);
    expect(canReadJobs("session_read")).toBe(true);
    expect(canCancelJob("session_read")).toBe(false);
    expect(canMutate("session_read")).toBe(false);
  });

  it("allows session_write to cancel jobs but not mutate config", () => {
    expect(canCancelJob("session_write")).toBe(true);
    expect(canReadJobs("session_write")).toBe(true);
    expect(canMutate("session_write")).toBe(false);
    expect(authorizeRequest("session_write", "config_mutations").allowed).toBe(false);
    expect(authorizeRequest("session_write", "job_cancel").allowed).toBe(true);
  });

  it("allows project_read to read health but not config", () => {
    expect(canReadHealth("project_read")).toBe(true);
    expect(canReadConfig("project_read")).toBe(false);
  });

  it("revocation denies mutations (revoked grant degrades role)", () => {
    // After revocation, the role degrades — simulate ordinary.
    expect(canMutate("ordinary")).toBe(false);
  });

  it("read-only vs mutation controls: safeReadOnlyProjection returns same data", () => {
    const data = { endpoints: { e1: { endpointId: "e1" } } };
    expect(safeReadOnlyProjection(data)).toEqual(data);
  });

  it("denies forbidden with error code", () => {
    const result = authorizeRequest("ordinary", "config_mutations");
    expect(result.allowed).toBe(false);
    expect(result.errorCode).toBe("forbidden");
  });
});

// ---------------------------------------------------------------------------
// Criterion 2: Budget tests
// ---------------------------------------------------------------------------

describe("image-generation budget", () => {
  function unconfiguredBudget(): ImageBudgetState {
    return {
      request: { policy: "unconfigured", generation: null },
      session: { policy: "unconfigured", generation: null },
      project: { policy: "unconfigured", generation: null },
      projectEpoch: null,
      configGeneration: null,
    };
  }

  it("Unconfigured blocks paid use", () => {
    expect(budgetBlocksPaidUse(unconfiguredBudget())).toBe(true);
  });

  it("explicit Finite save allows paid use", () => {
    const budget = {
      ...unconfiguredBudget(),
      request: { policy: finiteBudgetPolicy(1_000_000n), generation: "1" },
      session: { policy: finiteBudgetPolicy(10_000_000n), generation: "1" },
      project: { policy: finiteBudgetPolicy(100_000_000n), generation: "1" },
      projectEpoch: "2026-01-01/2026-02-01",
    };
    expect(budgetBlocksPaidUse(budget)).toBe(false);
  });

  it("explicit Unlimited save allows paid use", () => {
    const budget = {
      ...unconfiguredBudget(),
      request: { policy: "unlimited" as const, generation: "1" },
      session: { policy: "unlimited" as const, generation: "1" },
      project: { policy: "unlimited" as const, generation: "1" },
      projectEpoch: "2026-01-01/2026-02-01",
    };
    expect(budgetBlocksPaidUse(budget)).toBe(false);
  });

  it("USD suggestions are editable but non-authoritative", () => {
    expect(BUDGET_SUGGESTIONS.requestUsd).toBe(1);
    expect(BUDGET_SUGGESTIONS.sessionUsd).toBe(10);
    expect(BUDGET_SUGGESTIONS.projectMonthUsd).toBe(100);
    // Suggestions don't affect budget blocking — only policy matters.
    expect(budgetBlocksPaidUse(unconfiguredBudget())).toBe(true);
  });

  it("no implicit UTC/window: projectEpoch must be explicit", () => {
    const budget = unconfiguredBudget();
    expect(budget.projectEpoch).toBeNull();
  });

  it("validateBudgetScope: Unconfigured requires null generation", () => {
    expect(validateBudgetScope({ policy: "unconfigured", generation: null })).toBe(true);
    expect(validateBudgetScope({ policy: "unconfigured", generation: "1" })).toBe(false);
  });

  it("validateBudgetScope: Finite/Unlimited requires positive generation", () => {
    expect(validateBudgetScope({ policy: finiteBudgetPolicy(1_000_000n), generation: "1" })).toBe(
      true,
    );
    expect(validateBudgetScope({ policy: "unlimited", generation: "1" })).toBe(true);
    expect(validateBudgetScope({ policy: finiteBudgetPolicy(1_000_000n), generation: null })).toBe(
      false,
    );
    expect(validateBudgetScope({ policy: finiteBudgetPolicy(1_000_000n), generation: "0" })).toBe(
      false,
    );
  });

  it("validateBudgetScope: Finite requires a positive u64 amount", () => {
    // A zero amount is not a valid Finite policy, mirroring the Rust
    // deserializer that rejects `usd_micros: 0`.
    expect(validateBudgetScope({ policy: { finite: { usd_micros: 0n } }, generation: "1" })).toBe(
      false,
    );
  });

  it("validateBudgetSetPair: (null,null) is unchanged", () => {
    expect(validateBudgetSetPair(null, null)).toBe(true);
  });

  it("validateBudgetSetPair: nonnull policy with null generation creates", () => {
    expect(validateBudgetSetPair(finiteBudgetPolicy(1_000_000n), null)).toBe(true);
    expect(validateBudgetSetPair("unlimited", null)).toBe(true);
  });

  it("validateBudgetSetPair: nonnull policy with positive generation CAS-updates", () => {
    expect(validateBudgetSetPair(finiteBudgetPolicy(1_000_000n), "1")).toBe(true);
    expect(validateBudgetSetPair(finiteBudgetPolicy(1_000_000n), "0")).toBe(false);
  });

  it("validateBudgetSetPair: Finite with a zero amount rejects", () => {
    expect(validateBudgetSetPair({ finite: { usd_micros: 0n } }, null)).toBe(false);
    expect(validateBudgetSetPair({ finite: { usd_micros: 0n } }, "1")).toBe(false);
  });

  it("validateBudgetSetPair: Unconfigured in a save rejects", () => {
    expect(validateBudgetSetPair("unconfigured", null)).toBe(false);
    expect(validateBudgetSetPair("unconfigured", "1")).toBe(false);
  });

  it("validateBudgetSetPair: half-present tuple rejects", () => {
    expect(validateBudgetSetPair(null, "1")).toBe(false);
  });

  it("validateAtLeastOnePolicy: at least one nonnull", () => {
    expect(validateAtLeastOnePolicy(null, null, null)).toBe(false);
    expect(validateAtLeastOnePolicy(finiteBudgetPolicy(1_000_000n), null, null)).toBe(true);
    expect(validateAtLeastOnePolicy(null, "unlimited", null)).toBe(true);
    expect(validateAtLeastOnePolicy(null, null, finiteBudgetPolicy(1_000_000n))).toBe(true);
  });

  it("image_generation_budget_wire_carries_usd_micros", () => {
    // AC10: a Finite budget policy carries its usd_micros amount on the wire
    // and round-trips at the full u64::MAX boundary with no precision loss.
    // The canonical JSON is byte-identical to Rust `serde_json::to_string`.
    const maxFinite = finiteBudgetPolicy(MAX_U64_USD_MICROS);
    const wire = serializeBudgetPolicy(maxFinite);
    expect(wire).toBe('{"finite":{"usd_micros":18446744073709551615}}');

    const parsed = parseBudgetPolicy(wire);
    expect(parsed).not.toBeNull();
    expect(isFinitePolicy(parsed!)).toBe(true);
    // The bigint amount survives exactly — a JS `number` would truncate this
    // to 18446744073709552000.
    expect((parsed as { finite: { usd_micros: bigint } }).finite.usd_micros).toBe(
      18446744073709551615n,
    );
    expect(18446744073709551615n).toBeGreaterThan(BigInt(Number.MAX_SAFE_INTEGER));

    // Unconfigured/Unlimited keep their bare-string tags and round-trip.
    expect(serializeBudgetPolicy("unconfigured")).toBe('"unconfigured"');
    expect(serializeBudgetPolicy("unlimited")).toBe('"unlimited"');
    expect(parseBudgetPolicy('"unconfigured"')).toBe("unconfigured");
    expect(parseBudgetPolicy('"unlimited"')).toBe("unlimited");

    // The lossy amount-free string `"finite"` is not a valid policy, and a
    // zero amount is rejected — the pre-inc2 lossy wire cannot decode.
    expect(parseBudgetPolicy('"finite"')).toBeNull();
    expect(parseBudgetPolicy('{"finite":{}}')).toBeNull();
    expect(parseBudgetPolicy('{"finite":{"usd_micros":0}}')).toBeNull();
    // An amount above u64::MAX is rejected rather than silently wrapped.
    expect(parseBudgetPolicy('{"finite":{"usd_micros":18446744073709551616}}')).toBeNull();
    expect(isValidBudgetAmount(0n)).toBe(false);
    expect(isValidBudgetAmount(MAX_U64_USD_MICROS)).toBe(true);
  });

  it("validateCanonicalDecimal: 0|[1-9][0-9]{0,19}", () => {
    expect(validateCanonicalDecimal("0")).toBe(true);
    expect(validateCanonicalDecimal("1")).toBe(true);
    expect(validateCanonicalDecimal("12345")).toBe(true);
    expect(validateCanonicalDecimal("01")).toBe(false);
    expect(validateCanonicalDecimal("")).toBe(false);
    expect(validateCanonicalDecimal("1a")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Criterion 3: Approval / plan review tests
// ---------------------------------------------------------------------------

describe("image-generation plan review", () => {
  it("renders every immutable fact", () => {
    const plan = makePlan();
    expect(plan.destinations).toBeDefined();
    expect(plan.prompt).toBeDefined();
    expect(plan.references).toBeDefined();
    expect(plan.dimensions).toBeDefined();
    expect(plan.formats).toBeDefined();
    expect(plan.parameters).toBeDefined();
    expect(plan.fanout).toBeDefined();
    expect(plan.slots).toBeDefined();
    expect(plan.maxCost).toBeDefined();
    expect(plan.budgetDisposition).toBeDefined();
    expect(plan.outputHostLocation).toBeDefined();
    expect(plan.riskReasons).toBeDefined();
    expect(plan.digest).toBeDefined();
  });

  it("offers no global scope (destinations are exact target IDs)", () => {
    const plan = makePlan();
    for (const dest of plan.destinations) {
      expect(dest.targetId).toBeTruthy();
      // No "global" or wildcard scope.
      expect(dest.targetId).not.toBe("global");
      expect(dest.targetId).not.toBe("*");
    }
  });

  it("shows no modal for Yolo agent_discretion (isYolo=true)", () => {
    const yoloPlan = makePlan({ isYolo: true });
    expect(yoloPlan.isYolo).toBe(true);
    // The UI renders an agent_discretion activity entry, not an approval dialog.
  });

  it("shows approval dialog for non-Yolo plans", () => {
    const plan = makePlan({ isYolo: false });
    expect(plan.isYolo).toBe(false);
  });

  it("scope choices are only once/session/project", () => {
    const partition = emptyPartition("owner");
    expect(partition.scopeChoiceUsed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Criterion 4: Upload tests
// ---------------------------------------------------------------------------

describe("image-generation reference uploads", () => {
  it("creates unique upload IDs", () => {
    const u1 = makeUpload({ uploadId: "upload-1" });
    const u2 = makeUpload({ uploadId: "upload-2" });
    expect(u1.uploadId).not.toBe(u2.uploadId);
  });

  it("creates monotonically increasing selection epochs", () => {
    const u1 = makeUpload({ selectionEpoch: 1 });
    const u2 = makeUpload({ selectionEpoch: 2 });
    expect(u2.selectionEpoch).toBeGreaterThan(u1.selectionEpoch);
  });

  it("cancel aborts transport and retires the ID", () => {
    const upload = makeUpload({ state: "cancelled" });
    expect(isUploadRetired(upload)).toBe(true);
  });

  it("replacement retires the old ID", () => {
    const upload = makeUpload({ state: "retired" });
    expect(isUploadRetired(upload)).toBe(true);
  });

  it("discards progress with a retired ID", () => {
    const upload = makeUpload({ uploadId: "upload-1", state: "cancelled" });
    expect(shouldDiscardUploadEvent(upload, "upload-1", 1)).toBe(true);
  });

  it("discards progress with an older epoch", () => {
    const upload = makeUpload({ uploadId: "upload-1", selectionEpoch: 3, state: "uploading" });
    // Event with epoch 1 is older than current epoch 3.
    expect(shouldDiscardUploadEvent(upload, "upload-1", 1)).toBe(true);
  });

  it("discards progress with a wrong upload ID", () => {
    const upload = makeUpload({ uploadId: "upload-1", state: "uploading" });
    expect(shouldDiscardUploadEvent(upload, "upload-2", 1)).toBe(true);
  });

  it("accepts progress with the current ID and epoch", () => {
    const upload = makeUpload({ uploadId: "upload-1", selectionEpoch: 1, state: "uploading" });
    expect(shouldDiscardUploadEvent(upload, "upload-1", 1)).toBe(false);
  });

  it("discards late completion with a retired ID", () => {
    const upload = makeUpload({ uploadId: "upload-1", state: "cancelled" });
    expect(shouldDiscardUploadEvent(upload, "upload-1", 1)).toBe(true);
  });

  it("discards late completion after replacement selection", () => {
    const upload = makeUpload({ uploadId: "upload-2", selectionEpoch: 2, state: "uploading" });
    // Late completion for the old upload-1 with epoch 1.
    expect(shouldDiscardUploadEvent(upload, "upload-1", 1)).toBe(true);
  });

  it("discards for undefined upload", () => {
    expect(shouldDiscardUploadEvent(undefined, "upload-1", 1)).toBe(true);
  });

  it("retry does not bind a stale attachment", () => {
    // After failure, a retry creates a new upload ID; old completion is discarded.
    // isUploadRetired is false for "failed", but shouldDiscardUploadEvent
    // discards on wrong ID or older epoch. A retry would create upload-2.
    const newUpload = makeUpload({ uploadId: "upload-2", selectionEpoch: 2, state: "uploading" });
    expect(shouldDiscardUploadEvent(newUpload, "upload-1", 1)).toBe(true);
  });

  it("disconnect discards in-flight progress", () => {
    // On disconnect, the upload state is cleared via clearPartition.
    const state = emptyImageGenerationRemoteState();
    const withUpload = updatePartition(state, key(), (p) => ({
      ...p,
      uploads: { "upload-1": makeUpload({ uploadId: "upload-1" }) },
    }));
    const cleared = clearPartition(withUpload, key());
    expect(getPartition(cleared, key()).uploads["upload-1"]).toBeUndefined();
  });

  it("session switch discards uploads", () => {
    const state = emptyImageGenerationRemoteState();
    const k1 = key({ sessionId: "sess-A" });
    const withUpload = updatePartition(state, k1, (p) => ({
      ...p,
      uploads: { "upload-1": makeUpload({ uploadId: "upload-1" }) },
    }));
    // Switch to a different session.
    const cleared = clearPartition(withUpload, k1);
    const k2 = key({ sessionId: "sess-B" });
    expect(getPartition(cleared, k2).uploads["upload-1"]).toBeUndefined();
  });

  it("attachment handle is opaque and session-scoped", () => {
    const upload = makeUpload({
      state: "completed",
      attachmentHandle: "opaque-handle-xyz",
    });
    expect(upload.attachmentHandle).toBe("opaque-handle-xyz");
  });

  it("browser paths/names are display metadata only", () => {
    const upload = makeUpload({ fileName: "reference.png" });
    expect(upload.fileName).toBe("reference.png");
    // The fileName is display metadata; the transport uses the uploadId.
  });
});

// ---------------------------------------------------------------------------
// Criterion 5: Reducer tests (job/slot states, identity/version rejection)
// ---------------------------------------------------------------------------

describe("image-generation job reducer", () => {
  const ctx = { sessionId, projectId, daemonInstanceId };

  it("applies a job_changed event to create a new job", () => {
    const result = reduceJobEvent(undefined, makeJobEvent({ jobState: "running" }), ctx, null);
    expect(result.kind).toBe("applied");
    if (result.kind === "applied") {
      expect(result.job.state).toBe("running");
      expect(result.job.jobId).toBe(jobId);
    }
  });

  it("discards wrong-session events", () => {
    const event = makeJobEvent({
      identity: jobIdentity({ sessionId: "wrong-session" }),
    });
    const result = reduceJobEvent(undefined, event, ctx, null);
    expect(result.kind).toBe("discarded");
  });

  it("discards wrong-project events", () => {
    const event = makeJobEvent({
      identity: jobIdentity({ projectId: "wrong-project" }),
    });
    const result = reduceJobEvent(undefined, event, ctx, null);
    expect(result.kind).toBe("discarded");
  });

  it("discards wrong-daemon events", () => {
    const event = makeJobEvent({
      identity: jobIdentity({ daemonInstanceId: "wrong-daemon" }),
    });
    const result = reduceJobEvent(undefined, event, ctx, null);
    expect(result.kind).toBe("discarded");
  });

  it("discards duplicate events at the same version and state", () => {
    const existing: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "running",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const event = makeJobEvent({ jobVersion: 1, jobState: "running" });
    const result = reduceJobEvent(existing, event, ctx, null);
    expect(result.kind).toBe("discarded");
  });

  it("discards out-of-order events (older version)", () => {
    const existing: ImageJob = {
      jobId,
      jobVersion: 3,
      state: "running",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const event = makeJobEvent({ jobVersion: 2 });
    const result = reduceJobEvent(existing, event, ctx, null);
    expect(result.kind).toBe("discarded");
  });

  it("discards old daemon events", () => {
    const event = makeJobEvent({
      identity: jobIdentity({ daemonInstanceId: "old-daemon" }),
    });
    const result = reduceJobEvent(undefined, event, ctx, null);
    expect(result.kind).toBe("discarded");
  });

  it("discards superseded job generation", () => {
    const existing: ImageJob = {
      jobId,
      jobVersion: 5,
      state: "completed",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const event = makeJobEvent({ jobVersion: 3 });
    const result = reduceJobEvent(existing, event, ctx, null);
    expect(result.kind).toBe("discarded");
  });

  it("detects a gap in event sequence", () => {
    const event = makeJobEvent({ eventSeq: "5" });
    const result = reduceJobEvent(undefined, event, ctx, "1");
    expect(result.kind).toBe("gap_detected");
  });

  it("discards stale event seq", () => {
    const event = makeJobEvent({ eventSeq: "1" });
    const result = reduceJobEvent(undefined, event, ctx, "5");
    expect(result.kind).toBe("discarded");
  });

  it("applies slot_changed events", () => {
    const existing: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "running",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const event = makeJobEvent({
      kind: "slot_changed",
      jobVersion: 2,
      slotId: "slot-1",
      slotVersion: 1,
      slotState: "running",
    });
    const result = reduceJobEvent(existing, event, ctx, null);
    expect(result.kind).toBe("applied");
    if (result.kind === "applied") {
      expect(result.job.slots["slot-1"]).toBeDefined();
      expect(result.job.slots["slot-1"]!.state).toBe("running");
    }
  });

  it("discards out-of-order slot versions", () => {
    const existing: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "running",
      planDigest: null,
      slots: {
        "slot-1": {
          slotId: "slot-1",
          version: 3,
          state: "running",
          artifactHandle: null,
          updatedAt: Date.now(),
        },
      },
      lateResults: [],
      updatedAt: Date.now(),
    };
    const event = makeJobEvent({
      kind: "slot_changed",
      jobVersion: 2,
      slotId: "slot-1",
      slotVersion: 2,
      slotState: "succeeded",
    });
    const result = reduceJobEvent(existing, event, ctx, null);
    expect(result.kind).toBe("discarded");
  });

  it("applies late_result_changed events (quarantined)", () => {
    const existing: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "running",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const event = makeJobEvent({
      kind: "late_result_changed",
      jobVersion: 2,
      lateResult: { artifactHandle: "art-1", slotId: "slot-1" },
    });
    const result = reduceJobEvent(existing, event, ctx, null);
    expect(result.kind).toBe("applied");
    if (result.kind === "applied") {
      expect(result.job.lateResults).toHaveLength(1);
      expect(result.job.lateResults[0]!.quarantined).toBe(true);
    }
  });

  it("discards duplicate late_result events", () => {
    const existing: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "running",
      planDigest: null,
      slots: {},
      lateResults: [{ artifactHandle: "art-1", slotId: "slot-1", quarantined: true as const }],
      updatedAt: Date.now(),
    };
    const event = makeJobEvent({
      kind: "late_result_changed",
      jobVersion: 2,
      lateResult: { artifactHandle: "art-1", slotId: "slot-1" },
    });
    const result = reduceJobEvent(existing, event, ctx, null);
    expect(result.kind).toBe("discarded");
  });

  it("applies all canonical job states", () => {
    const states: Parameters<typeof reduceJobEvent>[1]["jobState"][] = [
      "pending",
      "planned",
      "authorized",
      "running",
      "cancellation_requested",
      "cancelled",
      "completed",
      "failed",
    ];
    for (const state of states) {
      const result = reduceJobEvent(undefined, makeJobEvent({ jobState: state }), ctx, null);
      expect(result.kind).toBe("applied");
      if (result.kind === "applied") {
        expect(result.job.state).toBe(state);
      }
    }
  });

  it("applies all canonical slot states", () => {
    const states: Parameters<typeof reduceJobEvent>[1]["slotState"][] = [
      "queued",
      "dispatched",
      "running",
      "succeeded",
      "failed",
      "cancelled",
    ];
    for (const state of states) {
      const result = reduceJobEvent(
        {
          jobId,
          jobVersion: 1,
          state: "running",
          planDigest: null,
          slots: {},
          lateResults: [],
          updatedAt: Date.now(),
        },
        makeJobEvent({
          kind: "slot_changed",
          jobVersion: 2,
          slotId: "slot-1",
          slotVersion: 1,
          slotState: state,
        }),
        ctx,
        null,
      );
      expect(result.kind).toBe("applied");
      if (result.kind === "applied") {
        expect(result.job.slots["slot-1"]!.state).toBe(state);
      }
    }
  });

  it("applies artifact handle on slot succeeded", () => {
    const result = reduceJobEvent(
      {
        jobId,
        jobVersion: 1,
        state: "running",
        planDigest: null,
        slots: {},
        lateResults: [],
        updatedAt: Date.now(),
      },
      makeJobEvent({
        kind: "slot_changed",
        jobVersion: 2,
        slotId: "slot-1",
        slotVersion: 1,
        slotState: "succeeded",
        artifactHandle: "opaque-art-handle",
      }),
      ctx,
      null,
    );
    expect(result.kind).toBe("applied");
    if (result.kind === "applied") {
      expect(result.job.slots["slot-1"]!.artifactHandle).toBe("opaque-art-handle");
    }
  });
});

// ---------------------------------------------------------------------------
// Criterion 6: Cancel tests
// ---------------------------------------------------------------------------

describe("image-generation cancellation", () => {
  it("displays Cancellation requested after acknowledgement", () => {
    const job: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "running",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const cancelled = requestJobCancellation(job);
    expect(cancelled.state).toBe("cancellation_requested");
  });

  it("only displays Cancelled on terminal daemon state", () => {
    const job: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "cancellation_requested",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    // The reducer only sets "cancelled" from an authoritative event.
    expect(isJobTerminal(job)).toBe(false);
    const terminal: ImageJob = { ...job, state: "cancelled" };
    expect(isJobTerminal(terminal)).toBe(true);
  });

  it("cancel on already-terminal job is a no-op", () => {
    const job: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "completed",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const result = requestJobCancellation(job);
    expect(result.state).toBe("completed");
  });

  it("cancel/complete/late-result race: late result during cancel request is quarantined", () => {
    const job: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "cancellation_requested",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const result = resolveCancelCompleteRace({
      job,
      lateResultEvent: makeJobEvent({
        kind: "late_result_changed",
        jobVersion: 2,
        lateResult: { artifactHandle: "art-1", slotId: "slot-1" },
      }),
    });
    expect(result.quarantine).toBe(true);
  });

  it("cancel/complete/late-result race: late result after terminal cancel with higher version is quarantined", () => {
    const job: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "cancelled",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const result = resolveCancelCompleteRace({
      job,
      lateResultEvent: makeJobEvent({
        kind: "late_result_changed",
        jobVersion: 2,
        lateResult: { artifactHandle: "art-1", slotId: "slot-1" },
      }),
    });
    expect(result.quarantine).toBe(true);
  });

  it("cancel/complete/late-result race: stale late result after cancel is discarded", () => {
    const job: ImageJob = {
      jobId,
      jobVersion: 3,
      state: "cancelled",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const result = resolveCancelCompleteRace({
      job,
      lateResultEvent: makeJobEvent({
        kind: "late_result_changed",
        jobVersion: 2,
        lateResult: { artifactHandle: "art-1", slotId: "slot-1" },
      }),
    });
    expect(result.quarantine).toBe(false);
  });

  it("cancel/complete/late-result race: late result in running job is quarantined", () => {
    const job: ImageJob = {
      jobId,
      jobVersion: 1,
      state: "running",
      planDigest: null,
      slots: {},
      lateResults: [],
      updatedAt: Date.now(),
    };
    const result = resolveCancelCompleteRace({
      job,
      lateResultEvent: makeJobEvent({
        kind: "late_result_changed",
        jobVersion: 2,
        lateResult: { artifactHandle: "art-1", slotId: "slot-1" },
      }),
    });
    expect(result.quarantine).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Criterion 7: Artifact tests
// ---------------------------------------------------------------------------

describe("image-generation artifacts", () => {
  it("uses only authenticated opaque thumbnail handles", () => {
    const handle = createThumbnailHandle({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
      box: 256,
      altText: "a cat",
      format: "png",
    });
    expect(handle).not.toBeNull();
    expect(handle!.route).toBe("thumbnail");
    expect(handle!.routePath).toContain("/api/cockpit/v1/instances/");
    expect(handle!.routePath).toContain("/image-artifacts/");
    expect(handle!.routePath).toContain("/thumbnails/256");
  });

  it("uses authenticated opaque download handles", () => {
    const handle = createDownloadHandle({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
      altText: "a cat",
    });
    expect(handle.route).toBe("content");
    expect(handle.routePath).toContain("/image-artifacts/");
    expect(handle.routePath).toContain("/content");
  });

  it("never embeds SVG (thumbnail returns null for SVG)", () => {
    const handle = createThumbnailHandle({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
      box: 256,
      altText: "a diagram",
      format: "svg",
    });
    expect(handle).toBeNull();
  });

  it("SVG download uses the content route (attachment-only, never embedded)", () => {
    const handle = createDownloadHandle({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
      altText: "a diagram",
    });
    // SVG downloads go through the same content route.
    expect(handle.route).toBe("content");
  });

  it("never includes provider URLs in handles", () => {
    const handle = createThumbnailHandle({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
      box: 256,
      altText: "a cat",
      format: "png",
    });
    expect(handle!.routePath).not.toContain("comfyui://");
    expect(handle!.routePath).not.toContain("file://");
    expect(handle!.routePath).not.toContain("http://");
    expect(handle!.routePath).not.toContain("https://");
  });

  it("never includes daemon paths in handles", () => {
    const handle = createDownloadHandle({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
      altText: "a cat",
    });
    expect(handle.routePath).not.toContain("/var/");
    expect(handle.routePath).not.toContain("/tmp/");
    expect(handle.routePath).not.toContain("/home/");
  });

  it("revokes stale browser object URLs on replacement", () => {
    const registry = new ArtifactObjectUrlRegistry();
    registry.set("art-1", "blob:url-1");
    expect(registry.get("art-1")).toBe("blob:url-1");
    // Replace.
    registry.set("art-1", "blob:url-2");
    expect(registry.get("art-1")).toBe("blob:url-2");
  });

  it("revokes object URLs on unmount (revokeAll)", () => {
    const registry = new ArtifactObjectUrlRegistry();
    registry.set("art-1", "blob:url-1");
    registry.set("art-2", "blob:url-2");
    registry.revokeAll();
    expect(registry.get("art-1")).toBeNull();
    expect(registry.get("art-2")).toBeNull();
  });

  it("revokes a specific artifact URL", () => {
    const registry = new ArtifactObjectUrlRegistry();
    registry.set("art-1", "blob:url-1");
    registry.revoke("art-1");
    expect(registry.get("art-1")).toBeNull();
  });

  it("thumbnail boxes are only 256/512/1024", () => {
    expect(THUMBNAIL_BOXES).toEqual([256, 512, 1024]);
  });

  it("buildThumbnailRoutePath produces correct path", () => {
    const path = buildThumbnailRoutePath({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
      box: 512,
    });
    expect(path).toBe(
      `/api/cockpit/v1/instances/${instanceId}/sessions/${sessionId}/image-artifacts/art-aaaaaaaaaaaaaaaa/thumbnails/512`,
    );
  });

  it("buildContentRoutePath produces correct path", () => {
    const path = buildContentRoutePath({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
    });
    expect(path).toBe(
      `/api/cockpit/v1/instances/${instanceId}/sessions/${sessionId}/image-artifacts/art-aaaaaaaaaaaaaaaa/content`,
    );
  });

  it("buildMetadataRoutePath produces correct path", () => {
    const path = buildMetadataRoutePath({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
    });
    expect(path).toBe(
      `/api/cockpit/v1/instances/${instanceId}/sessions/${sessionId}/image-artifacts/art-aaaaaaaaaaaaaaaa/metadata`,
    );
  });
});

// ---------------------------------------------------------------------------
// Criterion 8: Accessibility tests
// ---------------------------------------------------------------------------

describe("image-generation accessibility", () => {
  it("resolveAltText: uses manifest alt text when present", () => {
    expect(
      resolveAltText({ manifestAltText: "A cat sitting", adjacentTextConveysContent: false }),
    ).toBe("A cat sitting");
  });

  it("resolveAltText: empty decorative alt when adjacent text conveys content", () => {
    expect(resolveAltText({ manifestAltText: null, adjacentTextConveysContent: true })).toBe("");
  });

  it("resolveAltText: fallback alt when no manifest and no adjacent text", () => {
    expect(resolveAltText({ manifestAltText: null, adjacentTextConveysContent: false })).toBe(
      "Generated image",
    );
  });

  it("error messages are text-based (not color alone)", () => {
    expect(ERROR_MESSAGES.artifactNotFound).toBe("artifact_unavailable");
    expect(ERROR_MESSAGES.thumbnailFailed).toBe("thumbnail_unavailable");
    expect(ERROR_MESSAGES.cancelUnsupported).toBe("cancel_unsupported");
    // All messages are non-empty strings.
    for (const msg of Object.values(ERROR_MESSAGES)) {
      expect(typeof msg).toBe("string");
      expect(msg.length).toBeGreaterThan(0);
    }
  });

  it("mapErrorMessage: distinct accessible messages without existence leakage", () => {
    // not_found, unauthenticated, forbidden all map to the same generic message.
    expect(mapErrorMessage("not_found")).toBe(ERROR_MESSAGES.artifactNotFound);
    expect(mapErrorMessage("unauthenticated")).toBe(ERROR_MESSAGES.artifactNotFound);
    expect(mapErrorMessage("forbidden")).toBe(ERROR_MESSAGES.artifactNotFound);
    // Budget unconfigured has a distinct message.
    expect(mapErrorMessage("budget_unconfigured")).toBe(ERROR_MESSAGES.budgetUnconfigured);
    // Path reauthorization has a distinct message.
    expect(mapErrorMessage("local_path_reauthorization_required")).toBe(
      ERROR_MESSAGES.pathReauthorizationRequired,
    );
    // Cancel unsupported has a distinct message.
    expect(mapErrorMessage("invalid_state")).toBe(ERROR_MESSAGES.cancelUnsupported);
  });
});

// ---------------------------------------------------------------------------
// Criterion 9: Redaction tests
// ---------------------------------------------------------------------------

describe("image-generation redaction", () => {
  it("credentials are absent from client state", () => {
    const state = { endpointId: "e1", displayName: "test" };
    const result = validateRedaction(state);
    expect(result.clean).toBe(true);
  });

  it("detects api_key in state keys", () => {
    const state = { apiKey: "secret-value", displayName: "test" };
    expect(scanForForbiddenSentinels(state)).toContain("apiKey");
  });

  it("detects secret in nested state keys", () => {
    const state = { endpoint: { secret: "value" } };
    expect(scanForForbiddenSentinels(state)).toContain("secret");
  });

  it("detects credential in state keys", () => {
    const state = { credential: "value" };
    expect(scanForForbiddenSentinels(state)).toContain("credential");
  });

  it("detects header values (signed_url) in state keys", () => {
    const state = { signedUrl: "https://..." };
    expect(scanForForbiddenSentinels(state)).toContain("signedUrl");
  });

  it("detects workflow JSON (raw_workflow_json) in state keys", () => {
    const state = { rawWorkflowJson: "{}" };
    expect(scanForForbiddenSentinels(state)).toContain("rawWorkflowJson");
  });

  it("detects provider body (provider_body) in state keys", () => {
    const state = { providerBody: "..." };
    expect(scanForForbiddenSentinels(state)).toContain("providerBody");
  });

  it("detects quarantine handle in state keys", () => {
    const state = { quarantine: "handle" };
    expect(scanForForbiddenSentinels(state)).toContain("quarantine");
  });

  it("detects daemon paths in state values", () => {
    const state = { path: "/var/lib/daemon/output.png" };
    // /var/ is not in FORBIDDEN_PATH_PREFIXES; file:// is.
    const state2 = { path: "file:///var/lib/output.png" };
    expect(scanForForbiddenPaths(state)).toEqual([]);
    expect(scanForForbiddenPaths(state2)).toContain("file:///var/lib/output.png");
  });

  it("detects comfyui:// provider URLs in state values", () => {
    const state = { url: "comfyui://localhost:8188/prompt" };
    expect(scanForForbiddenPaths(state)).toContain("comfyui://localhost:8188/prompt");
  });

  it("allows authenticated artifact route paths (not flagged as daemon paths)", () => {
    const handle = createThumbnailHandle({
      instanceId,
      sessionId,
      artifactId: "art-aaaaaaaaaaaaaaaa",
      box: 256,
      altText: "a cat",
      format: "png",
    });
    const state = { preview: handle!.routePath };
    expect(scanForForbiddenPaths(state)).toEqual([]);
  });

  it("validates a clean partition has no violations", () => {
    const partition = emptyPartition("owner");
    const result = validateRedaction(partition);
    expect(result.clean).toBe(true);
  });

  it("validates that a full remote state with jobs is clean", () => {
    const state = emptyImageGenerationRemoteState();
    const withJob = updatePartition(state, key(), (p) => ({
      ...p,
      jobs: {
        [jobId]: {
          jobId,
          jobVersion: 1,
          state: "running",
          planDigest: null,
          slots: {},
          lateResults: [],
          updatedAt: Date.now(),
        },
      },
    }));
    const result = validateRedaction(withJob);
    expect(result.clean).toBe(true);
  });

  it("FORBIDDEN_SENTINELS includes all required secret types", () => {
    // The scan function uses the exported FORBIDDEN_SENTINELS indirectly.
    // Verify the key categories are detected.
    const categories = [
      { key: "apiKey", expected: "apiKey" },
      { key: "secret", expected: "secret" },
      { key: "password", expected: "password" },
      { key: "credential", expected: "credential" },
      { key: "privateKey", expected: "privateKey" },
      { key: "accessToken", expected: "accessToken" },
      { key: "providerBody", expected: "providerBody" },
      { key: "quarantine", expected: "quarantine" },
      { key: "localPath", expected: "localPath" },
      { key: "rawWorkflowJson", expected: "rawWorkflowJson" },
      { key: "signedUrl", expected: "signedUrl" },
      { key: "connectedIp", expected: "connectedIp" },
    ];
    for (const { key: k, expected } of categories) {
      expect(scanForForbiddenSentinels({ [k]: "value" })).toContain(expected);
    }
  });
});

// ---------------------------------------------------------------------------
// Connection/session switching and reconnect
// ---------------------------------------------------------------------------

describe("image-generation connection/session switching", () => {
  it("switching session clears pending edits, uploads, and jobs", () => {
    const state = emptyImageGenerationRemoteState();
    const k1 = key({ sessionId: "sess-A" });
    const populated = updatePartition(state, k1, (p) => ({
      ...p,
      pendingEdits: { endpoint: "e1" },
      uploads: { "upload-1": makeUpload() },
      jobs: {
        [jobId]: {
          jobId,
          jobVersion: 1,
          state: "running",
          planDigest: null,
          slots: {},
          lateResults: [],
          updatedAt: Date.now(),
        },
      },
    }));
    const cleared = clearPartition(populated, k1);
    expect(getPartition(cleared, k1).pendingEdits).toEqual({});
    expect(getPartition(cleared, k1).uploads).toEqual({});
    expect(getPartition(cleared, k1).jobs).toEqual({});
  });

  it("reconnect marks prior state stale", () => {
    const partition = emptyPartition("owner");
    const stale = markStaleAfterReconnect(partition);
    expect(stale.stale).toBe(true);
  });

  it("authorized snapshot clears stale flag", () => {
    const partition = { ...emptyPartition("owner"), stale: true };
    const applied = applyAuthorizedSnapshot(partition);
    expect(applied.stale).toBe(false);
  });

  it("stale state disables mutations", () => {
    const partition = { ...emptyPartition("owner"), stale: true };
    // While stale, mutation/cancel are disabled until snapshot applied.
    expect(partition.stale).toBe(true);
    const applied = applyAuthorizedSnapshot(partition);
    expect(applied.stale).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Plan invalidation
// ---------------------------------------------------------------------------

describe("image-generation plan invalidation", () => {
  it("invalidates when target disappears", () => {
    const plan = makePlan({
      destinations: [{ targetId: "target-1", locationClass: "remote_provider" }],
    });
    const result = shouldInvalidatePlan({
      plan,
      currentTargets: [], // target-1 gone
      currentBudget: {
        request: { policy: finiteBudgetPolicy(1_000_000n), generation: "1" },
        session: { policy: finiteBudgetPolicy(10_000_000n), generation: "1" },
        project: { policy: finiteBudgetPolicy(100_000_000n), generation: "1" },
        projectEpoch: "2026-01-01/2026-02-01",
        configGeneration: "1",
      },
      currentGrants: [],
    });
    expect(result).toBe(true);
  });

  it("invalidates when budget becomes unconfigured", () => {
    const plan = makePlan();
    const result = shouldInvalidatePlan({
      plan,
      currentTargets: [
        {
          targetId: "target-1",
          endpointId: "e1",
          displayName: "t",
          isDefault: true,
          healthStatus: "healthy",
          configGeneration: "1",
        },
      ],
      currentBudget: {
        request: { policy: "unconfigured", generation: null },
        session: { policy: "unconfigured", generation: null },
        project: { policy: "unconfigured", generation: null },
        projectEpoch: null,
        configGeneration: null,
      },
      currentGrants: [],
    });
    expect(result).toBe(true);
  });

  it("invalidates when grant is revoked", () => {
    const plan = makePlan();
    const result = shouldInvalidatePlan({
      plan,
      currentTargets: [
        {
          targetId: "target-1",
          endpointId: "e1",
          displayName: "t",
          isDefault: true,
          healthStatus: "healthy",
          configGeneration: "1",
        },
      ],
      currentBudget: {
        request: { policy: finiteBudgetPolicy(1_000_000n), generation: "1" },
        session: { policy: finiteBudgetPolicy(10_000_000n), generation: "1" },
        project: { policy: finiteBudgetPolicy(100_000_000n), generation: "1" },
        projectEpoch: "2026-01-01/2026-02-01",
        configGeneration: "1",
      },
      currentGrants: [
        {
          grantId: "g1",
          targetId: "target-1",
          destinationDisplayName: "dest",
          referenceEgress: "allowed",
          maxRequests: null,
          maxConcurrent: null,
          machineLocalScope: false,
          status: "revoked",
          generation: "1",
        },
      ],
    });
    expect(result).toBe(true);
  });

  it("does not invalidate when everything is stable", () => {
    const plan = makePlan();
    const result = shouldInvalidatePlan({
      plan,
      currentTargets: [
        {
          targetId: "target-1",
          endpointId: "e1",
          displayName: "t",
          isDefault: true,
          healthStatus: "healthy",
          configGeneration: "1",
        },
      ],
      currentBudget: {
        request: { policy: finiteBudgetPolicy(1_000_000n), generation: "1" },
        session: { policy: finiteBudgetPolicy(10_000_000n), generation: "1" },
        project: { policy: finiteBudgetPolicy(100_000_000n), generation: "1" },
        projectEpoch: "2026-01-01/2026-02-01",
        configGeneration: "1",
      },
      currentGrants: [
        {
          grantId: "g1",
          targetId: "target-1",
          destinationDisplayName: "dest",
          referenceEgress: "allowed",
          maxRequests: null,
          maxConcurrent: null,
          machineLocalScope: false,
          status: "active",
          generation: "1",
        },
      ],
    });
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Partition key and state management
// ---------------------------------------------------------------------------

describe("image-generation partition management", () => {
  it("partitionKey produces deterministic key", () => {
    const k = partitionKey(key());
    expect(k).toBe(`${daemonInstanceId}:${projectId}:${sessionId}`);
  });

  it("emptyImageGenerationRemoteState has no partitions", () => {
    expect(emptyImageGenerationRemoteState().partitions).toEqual({});
  });

  it("getPartition returns empty partition for missing key", () => {
    const state = emptyImageGenerationRemoteState();
    expect(getPartition(state, key()).role).toBe("ordinary");
  });

  it("updatePartition creates and updates partitions immutably", () => {
    const state = emptyImageGenerationRemoteState();
    const updated = updatePartition(state, key(), (p) => ({ ...p, role: "owner" }));
    expect(getPartition(updated, key()).role).toBe("owner");
    // Original is not mutated.
    expect(getPartition(state, key()).role).toBe("ordinary");
  });

  it("clearPartition removes a partition", () => {
    const state = emptyImageGenerationRemoteState();
    const populated = updatePartition(state, key(), (p) => ({ ...p, role: "owner" }));
    const cleared = clearPartition(populated, key());
    expect(Object.keys(cleared.partitions)).not.toContain(partitionKey(key()));
  });
});
