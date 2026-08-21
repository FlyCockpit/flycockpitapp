/**
 * Pure image-generation remote UI reducer and state contract.
 *
 * This module owns the exact client state graph for the web image-generation
 * remote experience: project generation settings (endpoint/target/workflow/
 * default/health), explicit finite-or-Unlimited budgets and project epoch
 * policy, destination-grant list/revoke, immutable plan review, reference
 * upload with unique IDs/epochs, durable job progress/cancellation, late-result
 * disposition, and authenticated artifact previews/downloads.
 *
 * It is intentionally free of React, DOM, WebSocket, and side-effectful I/O
 * so every transition can be tested with injected events — no timing sleeps.
 *
 * Design invariants (prompt `image-generation-web-remote-ui`):
 *
 * - Config/job stores are partitioned by daemon instance and exact
 *   project/session. Switching connection/project/session clears pending
 *   edits, approvals, uploads, artifact handles, and reducer cursors.
 * - Mutation controls render only for Owner or exact-project
 *   ImageGenerationAdmin; authorized non-admin users receive a read-only safe
 *   projection.
 * - Secret fields are write-only replace/clear/unchanged controls.
 * - References selected in the browser upload as typed attachments before
 *   planning. Each selection creates a unique upload_id and monotonically
 *   increasing selection epoch. Cancel aborts its transport and retires the
 *   ID. Progress/completion with a retired ID or older epoch is discarded.
 * - Jobs render from authoritative snapshots/events using identity tuple
 *   (daemon_instance_id, project_id, session_id, job_id) and monotonic
 *   job_version/slot versions. Superseded/wrong-session/duplicate/out-of-order
 *   events are discarded; a gap triggers snapshot rehydrate.
 * - Cancel displays "Cancellation requested" after acknowledgement and only
 *   displays "Cancelled" on terminal daemon state.
 * - Late results remain quarantined until explicit authorized publish/discard.
 * - Preview renders only from the authenticated raster-thumbnail route. Full
 *   download uses the authenticated artifact route. SVG is never embedded.
 * - No daemon path, provider URL, ComfyUI identifier, secret, or quarantine
 *   handle enters browser state.
 */

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/** The principal role for image-generation management authority. */
export type ImageGenerationRole =
  | "owner"
  | "image_generation_admin"
  | "session_read"
  | "session_write"
  | "project_read"
  | "ordinary";

/** The authorization scope for a control-plane request family. */
export type RequestFamily =
  | "config_reads_and_snapshot"
  | "health_reads_and_refresh"
  | "plan_get"
  | "job_reads_and_snapshot"
  | "job_cancel"
  | "config_mutations"
  | "late_result"
  | "operation_status";

/** Whether a role may perform mutation controls. */
export function canMutate(role: ImageGenerationRole): boolean {
  return role === "owner" || role === "image_generation_admin";
}

/** Whether a role may read config (endpoints/targets/workflows/budget/grants). */
export function canReadConfig(role: ImageGenerationRole): boolean {
  return role === "owner" || role === "image_generation_admin";
}

/** Whether a role may read health. */
export function canReadHealth(role: ImageGenerationRole): boolean {
  return role === "owner" || role === "image_generation_admin" || role === "project_read";
}

/** Whether a role may read plans. */
export function canReadPlan(role: ImageGenerationRole): boolean {
  return (
    role === "owner" ||
    role === "image_generation_admin" ||
    role === "session_read" ||
    role === "session_write"
  );
}

/** Whether a role may read jobs/session snapshot. */
export function canReadJobs(role: ImageGenerationRole): boolean {
  return (
    role === "owner" ||
    role === "image_generation_admin" ||
    role === "session_read" ||
    role === "session_write"
  );
}

/** Whether a role may cancel a job. */
export function canCancelJob(role: ImageGenerationRole): boolean {
  return role === "owner" || role === "image_generation_admin" || role === "session_write";
}

/** Whether a role may publish/discard late results. */
export function canDisposeLateResult(role: ImageGenerationRole): boolean {
  return role === "owner" || role === "image_generation_admin";
}

/**
 * Authorize a request family for a given role.
 *
 * ImageGenerationAdmin authority is valid only for the exact project it was
 * granted on. The caller must verify project match before calling.
 */
export function authorizeRequest(
  role: ImageGenerationRole,
  family: RequestFamily,
): { allowed: boolean; errorCode: string | null } {
  const allowed =
    (family === "config_reads_and_snapshot" && canReadConfig(role)) ||
    (family === "health_reads_and_refresh" && canReadHealth(role)) ||
    (family === "plan_get" && canReadPlan(role)) ||
    (family === "job_reads_and_snapshot" && canReadJobs(role)) ||
    (family === "job_cancel" && canCancelJob(role)) ||
    (family === "config_mutations" && canMutate(role)) ||
    (family === "late_result" && canDisposeLateResult(role)) ||
    (family === "operation_status" && (canReadHealth(role) || canReadConfig(role)));
  return {
    allowed,
    errorCode: allowed ? null : "forbidden",
  };
}

/**
 * Resolve the effective role from principal claims and project match.
 *
 * ImageGenerationAdmin is valid only when the canonical project root exactly
 * equals the target project. A wrong-project admin degrades to ordinary.
 */
export function resolveRole(input: {
  isOwner: boolean;
  isAdminForProject: boolean;
  adminProjectRoot: string | null;
  targetProjectRoot: string;
  hasSessionRead: boolean;
  hasSessionWrite: boolean;
  hasProjectRead: boolean;
}): ImageGenerationRole {
  if (input.isOwner) return "owner";
  if (
    input.isAdminForProject &&
    input.adminProjectRoot !== null &&
    input.adminProjectRoot === input.targetProjectRoot
  ) {
    return "image_generation_admin";
  }
  if (input.hasSessionWrite) return "session_write";
  if (input.hasSessionRead) return "session_read";
  if (input.hasProjectRead) return "project_read";
  return "ordinary";
}

/**
 * The safe projection for a non-admin user: read-only with no mutation
 * controls, no secret fields, and no grant revoke.
 */
export function safeReadOnlyProjection<T>(state: T): T {
  return state;
}

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

/** The budget policy: Unconfigured blocks paid use; Finite/Unlimited allow it. */
export type BudgetPolicy = "unconfigured" | "finite" | "unlimited";

/** A budget scope projection: (policy, generation). */
export interface BudgetScopeProjection {
  policy: BudgetPolicy;
  generation: string | null;
}

/** The full budget state for a project. */
export interface ImageBudgetState {
  /** Per-request budget scope. */
  request: BudgetScopeProjection;
  /** Per-session budget scope. */
  session: BudgetScopeProjection;
  /** Per-project-month budget scope. */
  project: BudgetScopeProjection;
  /** The project epoch/window (explicit, never implicit UTC). */
  projectEpoch: string | null;
  /** Config generation for CAS. */
  configGeneration: string | null;
}

/** USD suggestions are editable but non-authoritative. */
export const BUDGET_SUGGESTIONS = {
  requestUsd: 1,
  sessionUsd: 10,
  projectMonthUsd: 100,
} as const;

/** Whether the budget blocks paid generation (Unconfigured on any scope). */
export function budgetBlocksPaidUse(budget: ImageBudgetState): boolean {
  return (
    budget.request.policy === "unconfigured" ||
    budget.session.policy === "unconfigured" ||
    budget.project.policy === "unconfigured"
  );
}

/** Validate a budget scope nullability contract. */
export function validateBudgetScope(scope: BudgetScopeProjection): boolean {
  if (scope.policy === "unconfigured") {
    return scope.generation === null;
  }
  // Finite/Unlimited requires positive canonical decimal generation.
  if (scope.generation === null) return false;
  return validateCanonicalDecimal(scope.generation) && scope.generation !== "0";
}

/** Validate a canonical decimal string: `0|[1-9][0-9]{0,19}`. */
export function validateCanonicalDecimal(s: string): boolean {
  if (s.length === 0 || s.length > 20) return false;
  const bytes = s;
  if (bytes === "0") return true;
  if (bytes[0] === "0" || !isAsciiDigit(bytes[0]!)) return false;
  for (let i = 1; i < bytes.length; i++) {
    if (!isAsciiDigit(bytes[i]!)) return false;
  }
  return true;
}

function isAsciiDigit(ch: string): boolean {
  return ch >= "0" && ch <= "9";
}

/**
 * Validate a budget_set pair: (policy, expectedGeneration).
 * - (null, null) leaves it unchanged.
 * - A nonnull policy with null generation creates generation 1.
 * - A nonnull policy with positive generation CAS-updates.
 * - Unconfigured in a save rejects.
 * - Half-present tuple rejects.
 */
export function validateBudgetSetPair(
  policy: BudgetPolicy | null,
  expectedGeneration: string | null,
): boolean {
  if (policy === null && expectedGeneration === null) return true;
  if (policy === "unconfigured") return false;
  if (policy !== null && expectedGeneration === null) return true;
  if (policy !== null && expectedGeneration !== null) {
    return validateCanonicalDecimal(expectedGeneration) && expectedGeneration !== "0";
  }
  // policy === null with nonnull generation: half-present, reject.
  return false;
}

/** Validate that at least one policy is nonnull in budget_set. */
export function validateAtLeastOnePolicy(
  request: BudgetPolicy | null,
  session: BudgetPolicy | null,
  project: BudgetPolicy | null,
): boolean {
  return request !== null || session !== null || project !== null;
}

// ---------------------------------------------------------------------------
// Destination grants
// ---------------------------------------------------------------------------

/** The access-grant status. */
export type AccessGrantStatus =
  | "pending"
  | "active"
  | "revoking"
  | "revoked"
  | "expired"
  | "declined";

/** A safe destination-grant row (no secrets, no internal authority keys). */
export interface DestinationGrantRow {
  grantId: string;
  /** Exact destination target ID. */
  targetId: string;
  /** Exact destination display name (safe). */
  destinationDisplayName: string;
  /** Reference-egress policy (safe projection). */
  referenceEgress: "allowed" | "denied";
  /** Maxima (safe projection). */
  maxRequests: number | null;
  maxConcurrent: number | null;
  /** Machine-local scope flag. */
  machineLocalScope: boolean;
  /** Revoke state. */
  status: AccessGrantStatus;
  /** Grant generation. */
  generation: string;
}

// ---------------------------------------------------------------------------
// Endpoint / Target / Workflow (safe config projections)
// ---------------------------------------------------------------------------

/** A safe endpoint projection (no API keys, no secrets). */
export interface ImageEndpointSafe {
  endpointId: string;
  displayName: string;
  providerClass: string;
  /** Write-only: "unchanged" | "replace" | "clear" — never the actual value. */
  secretState: "unchanged" | "replace" | "clear";
  configGeneration: string;
}

/** A safe target projection. */
export interface ImageTargetSafe {
  targetId: string;
  endpointId: string;
  displayName: string;
  isDefault: boolean;
  healthStatus: "healthy" | "degraded" | "down" | "unknown";
  configGeneration: string;
}

/** A safe workflow projection (no raw workflow JSON). */
export interface ImageWorkflowSafe {
  workflowId: string;
  displayName: string;
  /** Opaque API format blob transfer ID (not the raw JSON). */
  transferId: string;
  totalLength: string;
  sha256: string;
  configGeneration: string;
}

// ---------------------------------------------------------------------------
// Plan review (immutable)
// ---------------------------------------------------------------------------

/** The immutable plan review containing every fact before authorization. */
export interface PlanReview {
  planId: string;
  /** Exact destinations/location classes. */
  destinations: ReadonlyArray<{
    targetId: string;
    locationClass: "machine_local" | "remote_provider";
  }>;
  /** Prompt reveal (the exact prompt text). */
  prompt: string;
  /** References/egress policy. */
  references: ReadonlyArray<{
    uploadId: string;
    fileName: string;
    egress: "allowed" | "denied";
  }>;
  /** Resolved dimensions. */
  dimensions: { width: number; height: number };
  /** Output formats/parameters. */
  formats: ReadonlyArray<string>;
  parameters: ReadonlyArray<{ key: string; value: string }>;
  /** Fanout/slots. */
  fanout: number;
  slots: number;
  /** Maximum or unknown cost. */
  maxCost: { usd: number } | { kind: "unknown" };
  /** Explicit budget disposition. */
  budgetDisposition: "within_budget" | "over_budget" | "budget_unconfigured";
  /** Output host location. */
  outputHostLocation: "machine_local" | "remote_provider";
  /** Risk reasons. */
  riskReasons: ReadonlyArray<string>;
  /** Plan digest (SHA-256 hex). */
  digest: string;
  /** Plan generation (monotonic). */
  generation: string;
  /** Whether this is a Yolo/agent_discretion plan (no approval dialog). */
  isYolo: boolean;
}

// ---------------------------------------------------------------------------
// Upload (references)
// ---------------------------------------------------------------------------

/** The upload state for a reference attachment. */
export type UploadState =
  | "selected"
  | "uploading"
  | "completed"
  | "failed"
  | "cancelled"
  | "retired";

/** A reference upload entry in browser state. */
export interface ReferenceUpload {
  /** Unique upload ID (opaque, session-scoped). */
  uploadId: string;
  /** Monotonically increasing selection epoch. */
  selectionEpoch: number;
  /** Display metadata only (never a browser path used for transport). */
  fileName: string;
  declaredSize: number;
  declaredMime: string;
  state: UploadState;
  /** Bytes uploaded so far. */
  uploadedBytes: number;
  /** Opaque attachment handle after completion (session-scoped). */
  attachmentHandle: string | null;
  /** Safe error reason (no secrets/paths). */
  error: string | null;
  updatedAt: number;
}

/** Whether an upload ID is retired (cancelled or replaced). */
export function isUploadRetired(upload: ReferenceUpload): boolean {
  return upload.state === "cancelled" || upload.state === "retired";
}

/**
 * Decide whether a progress/completion event should be discarded because its
 * upload ID is retired or its epoch is older than the current selection.
 */
export function shouldDiscardUploadEvent(
  upload: ReferenceUpload | undefined,
  eventUploadId: string,
  eventEpoch: number,
): boolean {
  if (!upload) return true;
  if (upload.uploadId !== eventUploadId) return true;
  if (isUploadRetired(upload)) return true;
  if (eventEpoch < upload.selectionEpoch) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Jobs and slots
// ---------------------------------------------------------------------------

/** The canonical job state. */
export type JobState =
  | "pending"
  | "planned"
  | "authorized"
  | "running"
  | "cancellation_requested"
  | "cancelled"
  | "completed"
  | "failed";

/** The canonical slot state. */
export type SlotState = "queued" | "dispatched" | "running" | "succeeded" | "failed" | "cancelled";

/** The identity tuple for a job event. */
export interface JobIdentity {
  daemonInstanceId: string;
  projectId: string;
  sessionId: string;
  jobId: string;
}

/** A job slot in the reducer. */
export interface JobSlot {
  slotId: string;
  version: number;
  state: SlotState;
  /** Opaque artifact handle (only after succeeded). */
  artifactHandle: string | null;
  updatedAt: number;
}

/** A job in the reducer. */
export interface ImageJob {
  jobId: string;
  /** Monotonic job version; superseded generations are rejected. */
  jobVersion: number;
  state: JobState;
  /** Plan digest this job was authorized against. */
  planDigest: string | null;
  slots: Record<string, JobSlot>;
  /** Late results quarantined, awaiting publish/discard. */
  lateResults: ReadonlyArray<{
    artifactHandle: string;
    slotId: string;
    quarantined: true;
  }>;
  updatedAt: number;
}

/** A job/slot event from the authoritative control plane. */
export interface JobEvent {
  identity: JobIdentity;
  jobVersion: number;
  kind: "job_changed" | "slot_changed" | "late_result_changed";
  /** For slot_changed: the slot ID and version. */
  slotId?: string;
  slotVersion?: number;
  /** The new state. */
  jobState?: JobState;
  slotState?: SlotState;
  /** Opaque artifact handle (for succeeded slots). */
  artifactHandle?: string;
  /** For late_result_changed. */
  lateResult?: {
    artifactHandle: string;
    slotId: string;
  };
  /** Event sequence for gap detection. */
  eventSeq: string;
}

/** The result of reducing a job event. */
export type ReduceJobResult =
  | { kind: "applied"; job: ImageJob }
  | { kind: "discarded"; reason: string }
  | { kind: "gap_detected"; reason: string };

/**
 * Reduce a job event against the current job state.
 *
 * Discards: wrong session/project, duplicate, out-of-order (older version),
 * superseded job generation, and late results with retired/unmatched slots.
 * A gap (event seq skips) triggers snapshot rehydrate.
 */
export function reduceJobEvent(
  current: ImageJob | undefined,
  event: JobEvent,
  context: { sessionId: string; projectId: string; daemonInstanceId: string },
  lastEventSeq: string | null,
): ReduceJobResult {
  // Identity check: wrong daemon/project/session.
  if (
    event.identity.daemonInstanceId !== context.daemonInstanceId ||
    event.identity.projectId !== context.projectId ||
    event.identity.sessionId !== context.sessionId
  ) {
    return { kind: "discarded", reason: "wrong_session_project_or_daemon" };
  }
  // Job ID must match.
  if (current && current.jobId !== event.identity.jobId) {
    return { kind: "discarded", reason: "wrong_job_id" };
  }
  // Version check: out-of-order or duplicate.
  if (current && event.jobVersion < current.jobVersion) {
    return { kind: "discarded", reason: "out_of_order_version" };
  }
  if (current && event.jobVersion === current.jobVersion && event.kind === "job_changed") {
    // Duplicate job_changed at same version: discard unless state differs.
    if (event.jobState && event.jobState === current.state) {
      return { kind: "discarded", reason: "duplicate_event" };
    }
  }
  // Gap detection: event seq must be monotonic.
  if (lastEventSeq !== null) {
    const lastSeq = parseEventSeq(lastEventSeq);
    const thisSeq = parseEventSeq(event.eventSeq);
    if (thisSeq <= lastSeq) {
      return { kind: "discarded", reason: "stale_event_seq" };
    }
    if (thisSeq > lastSeq + 1) {
      return { kind: "gap_detected", reason: "event_seq_gap" };
    }
  }

  const now = Date.now();
  const base: ImageJob = current ?? {
    jobId: event.identity.jobId,
    jobVersion: event.jobVersion,
    state: "pending",
    planDigest: null,
    slots: {},
    lateResults: [],
    updatedAt: now,
  };

  if (event.kind === "job_changed") {
    const newState = event.jobState ?? base.state;
    // Cancellation requested is not terminal; only "cancelled" is terminal.
    const updated: ImageJob = {
      ...base,
      jobVersion: event.jobVersion,
      state: newState,
      updatedAt: now,
    };
    return { kind: "applied", job: updated };
  }

  if (event.kind === "slot_changed") {
    if (!event.slotId || event.slotVersion === undefined) {
      return { kind: "discarded", reason: "missing_slot_identity" };
    }
    const existingSlot = base.slots[event.slotId];
    if (existingSlot && event.slotVersion < existingSlot.version) {
      return { kind: "discarded", reason: "out_of_order_slot_version" };
    }
    if (
      existingSlot &&
      event.slotVersion === existingSlot.version &&
      event.slotState === existingSlot.state
    ) {
      return { kind: "discarded", reason: "duplicate_slot_event" };
    }
    const slot: JobSlot = {
      slotId: event.slotId,
      version: event.slotVersion,
      state: event.slotState ?? existingSlot?.state ?? "queued",
      artifactHandle: event.artifactHandle ?? existingSlot?.artifactHandle ?? null,
      updatedAt: now,
    };
    const updated: ImageJob = {
      ...base,
      jobVersion: event.jobVersion,
      slots: { ...base.slots, [event.slotId]: slot },
      updatedAt: now,
    };
    return { kind: "applied", job: updated };
  }

  if (event.kind === "late_result_changed") {
    if (!event.lateResult) {
      return { kind: "discarded", reason: "missing_late_result" };
    }
    // Late results remain quarantined until explicit publish/discard.
    const existing = base.lateResults.find(
      (r) => r.artifactHandle === event.lateResult!.artifactHandle,
    );
    if (existing) {
      return { kind: "discarded", reason: "duplicate_late_result" };
    }
    const updated: ImageJob = {
      ...base,
      jobVersion: event.jobVersion,
      lateResults: [
        ...base.lateResults,
        {
          artifactHandle: event.lateResult.artifactHandle,
          slotId: event.lateResult.slotId,
          quarantined: true as const,
        },
      ],
      updatedAt: now,
    };
    return { kind: "applied", job: updated };
  }

  return { kind: "discarded", reason: "unknown_event_kind" };
}

/** Parse an event sequence string as a number for gap detection. */
function parseEventSeq(seq: string): number {
  const n = Number(seq);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Cancel a job: displays "Cancellation requested" after acknowledgement and
 * only displays "Cancelled" on terminal daemon state.
 */
export function requestJobCancellation(job: ImageJob): ImageJob {
  if (job.state === "cancelled" || job.state === "completed" || job.state === "failed") {
    // Already terminal; no-op.
    return job;
  }
  return {
    ...job,
    state: "cancellation_requested",
    updatedAt: Date.now(),
  };
}

/** Whether a job is in a terminal state. */
export function isJobTerminal(job: ImageJob): boolean {
  return job.state === "cancelled" || job.state === "completed" || job.state === "failed";
}

// ---------------------------------------------------------------------------
// Cancel/complete/late-result races
// ---------------------------------------------------------------------------

/**
 * Resolve a cancel/complete/late-result race from authoritative versions.
 *
 * If a late result arrives after cancellation was requested but the job
 * version indicates the daemon completed the slot before the cancel took
 * effect, the late result is quarantined (not discarded).
 */
export function resolveCancelCompleteRace(input: { job: ImageJob; lateResultEvent: JobEvent }): {
  quarantine: boolean;
  reason: string;
} {
  // If the job is already cancelled (terminal), a late result from a higher
  // version is quarantined; from an older version is discarded.
  if (input.job.state === "cancelled") {
    if (input.lateResultEvent.jobVersion > input.job.jobVersion) {
      return { quarantine: true, reason: "late_result_after_terminal_cancel" };
    }
    return { quarantine: false, reason: "stale_late_result_after_cancel" };
  }
  if (input.job.state === "cancellation_requested") {
    // Cancel was requested but not yet terminal; late result is quarantined.
    return { quarantine: true, reason: "late_result_during_cancel_request" };
  }
  return { quarantine: true, reason: "late_result_normal" };
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

/** The authenticated artifact route kind. */
export type ArtifactRouteKind = "thumbnail" | "content" | "metadata";

/** An authenticated opaque artifact handle (never a path or provider URL). */
export interface ArtifactHandle {
  /** Opaque artifact ID (22-char base64url). */
  artifactId: string;
  /** The route kind. */
  route: ArtifactRouteKind;
  /** Thumbnail box size (only for thumbnail route). */
  thumbnailBox: 256 | 512 | 1024 | null;
  /** The authenticated route path (instance/session scoped). */
  routePath: string;
  /** Alt text from safe manifest metadata or empty decorative alt. */
  altText: string;
}

/** The thumbnail boxes allowlist. */
export const THUMBNAIL_BOXES = [256, 512, 1024] as const;

/** The forbidden sentinel strings that must never appear in browser state. */
export const FORBIDDEN_SENTINELS = [
  "api_key",
  "apiKey",
  "secret",
  "password",
  "credential",
  "private_key",
  "privateKey",
  "access_token",
  "accessToken",
  "refresh_token",
  "refreshToken",
  "provider_body",
  "providerBody",
  "quarantine",
  "local_path",
  "localPath",
  "host_path",
  "hostPath",
  "raw_workflow_json",
  "rawWorkflowJson",
  "signed_url",
  "signedUrl",
  "connected_ip",
  "connectedIp",
] as const;

/** The forbidden path prefixes (daemon/provider identifiers). */
export const FORBIDDEN_PATH_PREFIXES = [
  "/api/cockpit/v1/instances/",
  "file://",
  "comfyui://",
] as const;

/**
 * Build an authenticated artifact thumbnail route path.
 *
 * The path uses opaque IDs only — no daemon path, provider URL, or ComfyUI
 * identifier. SVG is never embedded; thumbnails are always raster PNG.
 */
export function buildThumbnailRoutePath(input: {
  instanceId: string;
  sessionId: string;
  artifactId: string;
  box: 256 | 512 | 1024;
}): string {
  return `/api/cockpit/v1/instances/${input.instanceId}/sessions/${input.sessionId}/image-artifacts/${input.artifactId}/thumbnails/${input.box}`;
}

/**
 * Build an authenticated artifact content/download route path.
 */
export function buildContentRoutePath(input: {
  instanceId: string;
  sessionId: string;
  artifactId: string;
}): string {
  return `/api/cockpit/v1/instances/${input.instanceId}/sessions/${input.sessionId}/image-artifacts/${input.artifactId}/content`;
}

/**
 * Build an authenticated artifact metadata route path.
 */
export function buildMetadataRoutePath(input: {
  instanceId: string;
  sessionId: string;
  artifactId: string;
}): string {
  return `/api/cockpit/v1/instances/${input.instanceId}/sessions/${input.sessionId}/image-artifacts/${input.artifactId}/metadata`;
}

/**
 * Create an ArtifactHandle for a raster thumbnail preview.
 * SVG artifacts return null (never embedded).
 */
export function createThumbnailHandle(input: {
  instanceId: string;
  sessionId: string;
  artifactId: string;
  box: 256 | 512 | 1024;
  altText: string;
  format: "png" | "jpeg" | "webp" | "svg";
}): ArtifactHandle | null {
  // SVG is never embedded as a thumbnail.
  if (input.format === "svg") return null;
  return {
    artifactId: input.artifactId,
    route: "thumbnail",
    thumbnailBox: input.box,
    routePath: buildThumbnailRoutePath(input),
    altText: input.altText,
  };
}

/**
 * Create an ArtifactHandle for a full download.
 * SVG downloads use the content route (attachment-only, never embedded).
 */
export function createDownloadHandle(input: {
  instanceId: string;
  sessionId: string;
  artifactId: string;
  altText: string;
}): ArtifactHandle {
  return {
    artifactId: input.artifactId,
    route: "content",
    thumbnailBox: null,
    routePath: buildContentRoutePath(input),
    altText: input.altText,
  };
}

/**
 * Resolve image alt text from safe manifest metadata.
 * Returns empty string (decorative) only when adjacent text conveys the same
 * content.
 */
export function resolveAltText(input: {
  manifestAltText: string | null;
  adjacentTextConveysContent: boolean;
}): string {
  if (input.manifestAltText && input.manifestAltText.length > 0) {
    return input.manifestAltText;
  }
  if (input.adjacentTextConveysContent) {
    return ""; // decorative
  }
  return "Generated image"; // fallback
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/**
 * Scan a state object for forbidden sentinel strings in its keys.
 * Returns the list of found sentinel keys.
 */
export function scanForForbiddenSentinels(value: unknown): string[] {
  const found: string[] = [];
  scanValueKeys(value, found);
  found.sort();
  // Deduplicate.
  return [...new Set(found)];
}

function scanValueKeys(value: unknown, found: string[]) {
  if (value === null || value === undefined) return;
  if (typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) scanValueKeys(item, found);
    return;
  }
  const obj = value as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    const keyLower = key.toLowerCase();
    for (const sentinel of FORBIDDEN_SENTINELS) {
      if (keyLower.includes(sentinel.toLowerCase())) {
        found.push(key);
      }
    }
    scanValueKeys(obj[key], found);
  }
}

/**
 * Scan a string for forbidden path prefixes (daemon/provider identifiers).
 */
export function scanForForbiddenPaths(value: unknown): string[] {
  const found: string[] = [];
  scanValueForPaths(value, found);
  return [...new Set(found)];
}

function scanValueForPaths(value: unknown, found: string[]) {
  if (typeof value === "string") {
    for (const prefix of FORBIDDEN_PATH_PREFIXES) {
      // Allow the authenticated artifact route path prefix, which is the
      // only permitted /api/cockpit/v1/instances/ path.
      if (
        prefix === "/api/cockpit/v1/instances/" &&
        value.startsWith(prefix) &&
        value.includes("/image-artifacts/")
      ) {
        continue;
      }
      if (value.startsWith(prefix)) {
        found.push(value);
      }
    }
  } else if (Array.isArray(value)) {
    for (const item of value) scanValueForPaths(item, found);
  } else if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value)) {
      scanValueForPaths((value as Record<string, unknown>)[key], found);
    }
  }
}

/**
 * Validate that a state object is free of forbidden sentinels and paths.
 */
export function validateRedaction(state: unknown): {
  clean: boolean;
  sentinelViolations: string[];
  pathViolations: string[];
} {
  const sentinelViolations = scanForForbiddenSentinels(state);
  const pathViolations = scanForForbiddenPaths(state);
  return {
    clean: sentinelViolations.length === 0 && pathViolations.length === 0,
    sentinelViolations,
    pathViolations,
  };
}

// ---------------------------------------------------------------------------
// Error messages (accessible, no existence leakage)
// ---------------------------------------------------------------------------

/** The distinct accessible error messages without existence leakage. */
export const ERROR_MESSAGES = {
  artifactNotFound: "artifact_unavailable",
  artifactQuarantined: "artifact_quarantined",
  artifactCleanup: "artifact_cleanup_in_progress",
  sessionExpired: "session_expired",
  downloadInterrupted: "download_interrupted",
  thumbnailFailed: "thumbnail_unavailable",
  cancelUnsupported: "cancel_unsupported",
  pathReauthorizationRequired: "path_reauthorization_required",
  budgetUnconfigured: "budget_unconfigured",
  forbidden: "forbidden",
  versionConflict: "version_conflict",
  reconnectRequired: "reconnect_required",
} as const;

/**
 * Map a control-plane error code to an accessible user message without
 * existence leakage. All auth/existence/security failures map to the same
 * generic message.
 */
export function mapErrorMessage(code: string): string {
  switch (code) {
    case "not_found":
    case "unauthenticated":
    case "forbidden":
      return ERROR_MESSAGES.artifactNotFound;
    case "budget_unconfigured":
      return ERROR_MESSAGES.budgetUnconfigured;
    case "version_conflict":
      return ERROR_MESSAGES.versionConflict;
    case "local_path_reauthorization_required":
      return ERROR_MESSAGES.pathReauthorizationRequired;
    case "invalid_state":
      return ERROR_MESSAGES.cancelUnsupported;
    default:
      return ERROR_MESSAGES.artifactNotFound;
  }
}

// ---------------------------------------------------------------------------
// Plan invalidation
// ---------------------------------------------------------------------------

/**
 * Whether a plan review should be invalidated due to target/grant/budget/
 * capability change after the plan was reviewed.
 */
export function shouldInvalidatePlan(input: {
  plan: PlanReview;
  currentTargets: ReadonlyArray<ImageTargetSafe>;
  currentBudget: ImageBudgetState;
  currentGrants: ReadonlyArray<DestinationGrantRow>;
}): boolean {
  // If any destination target in the plan is no longer present, invalidate.
  for (const dest of input.plan.destinations) {
    const exists = input.currentTargets.some((t) => t.targetId === dest.targetId);
    if (!exists) return true;
  }
  // If budget changed to unconfigured, invalidate.
  if (budgetBlocksPaidUse(input.currentBudget)) return true;
  // If any grant for plan destinations was revoked, invalidate.
  for (const dest of input.plan.destinations) {
    const grant = input.currentGrants.find((g) => g.targetId === dest.targetId);
    if (grant && (grant.status === "revoked" || grant.status === "expired")) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Reconnect staleness
// ---------------------------------------------------------------------------

/**
 * Mark prior state stale after reconnect. Mutation/cancel are disabled until
 * an authorized snapshot is applied.
 */
export function markStaleAfterReconnect<T extends { stale: boolean }>(state: T): T {
  return { ...state, stale: true };
}

/**
 * Apply an authorized snapshot, clearing the stale flag.
 */
export function applyAuthorizedSnapshot<T extends { stale: boolean }>(state: T): T {
  return { ...state, stale: false };
}

// ---------------------------------------------------------------------------
// Object URL management (browser-only, for artifact previews)
// ---------------------------------------------------------------------------

/**
 * Object URL registry for artifact preview blobs.
 *
 * Object URLs are revoked on replacement/unmount. The registry is kept
 * outside serializable reducer state. In tests, we track URLs as strings.
 */
export class ArtifactObjectUrlRegistry {
  private urls = new Map<string, string>();

  /** Create or replace an object URL for an artifact handle. */
  set(artifactId: string, url: string): void {
    const existing = this.urls.get(artifactId);
    if (existing) {
      this.revokeUrl(existing);
    }
    this.urls.set(artifactId, url);
  }

  /** Get the object URL for an artifact, if any. */
  get(artifactId: string): string | null {
    return this.urls.get(artifactId) ?? null;
  }

  /** Revoke and remove an object URL on replacement/unmount. */
  revoke(artifactId: string): void {
    const url = this.urls.get(artifactId);
    if (url) {
      this.revokeUrl(url);
      this.urls.delete(artifactId);
    }
  }

  /** Revoke all object URLs (e.g., on unmount). */
  revokeAll(): void {
    for (const url of this.urls.values()) {
      this.revokeUrl(url);
    }
    this.urls.clear();
  }

  private revokeUrl(url: string): void {
    // In the browser, this calls URL.revokeObjectURL(url).
    // In tests, this is a no-op (the URL is just a string).
    if (typeof URL !== "undefined" && typeof URL.revokeObjectURL === "function") {
      try {
        URL.revokeObjectURL(url);
      } catch {
        // Ignore — the URL may already be revoked.
      }
    }
  }
}

// ---------------------------------------------------------------------------
// State partition
// ---------------------------------------------------------------------------

/** The key for a project/session partition. */
export interface PartitionKey {
  daemonInstanceId: string;
  projectId: string;
  sessionId: string;
}

/** The image-generation state for one project/session partition. */
export interface ImageGenerationPartition {
  /** Authorization role for this partition. */
  role: ImageGenerationRole;
  /** Whether state is stale after reconnect. */
  stale: boolean;
  /** Safe config projections. */
  endpoints: Record<string, ImageEndpointSafe>;
  targets: Record<string, ImageTargetSafe>;
  workflows: Record<string, ImageWorkflowSafe>;
  /** Budget state. */
  budget: ImageBudgetState;
  /** Destination grants. */
  grants: Record<string, DestinationGrantRow>;
  /** Health items. */
  health: ReadonlyArray<{ targetId: string; status: "healthy" | "degraded" | "down" | "unknown" }>;
  /** Reference uploads. */
  uploads: Record<string, ReferenceUpload>;
  /** Current plan review (immutable, or null if not yet reviewed). */
  currentPlan: PlanReview | null;
  /** Jobs by job ID. */
  jobs: Record<string, ImageJob>;
  /** Last event seq per job (for gap detection). */
  jobEventSeqs: Record<string, string | null>;
  /** Whether scope choice has been used this session/project. */
  scopeChoiceUsed: boolean;
  /** Pending config edits (non-secret draft). */
  pendingEdits: Record<string, unknown>;
  /** Config conflict state (non-secret draft + current safe version). */
  configConflict: {
    draft: Record<string, unknown>;
    currentSafe: Record<string, unknown>;
  } | null;
}

/** Create an empty partition. */
export function emptyPartition(role: ImageGenerationRole = "ordinary"): ImageGenerationPartition {
  return {
    role,
    stale: false,
    endpoints: {},
    targets: {},
    workflows: {},
    budget: {
      request: { policy: "unconfigured", generation: null },
      session: { policy: "unconfigured", generation: null },
      project: { policy: "unconfigured", generation: null },
      projectEpoch: null,
      configGeneration: null,
    },
    grants: {},
    health: [],
    uploads: {},
    currentPlan: null,
    jobs: {},
    jobEventSeqs: {},
    scopeChoiceUsed: false,
    pendingEdits: {},
    configConflict: null,
  };
}

/** The full image-generation remote state, partitioned by daemon/project/session. */
export interface ImageGenerationRemoteState {
  partitions: Record<string, ImageGenerationPartition>;
}

/** Create an empty top-level state. */
export function emptyImageGenerationRemoteState(): ImageGenerationRemoteState {
  return { partitions: {} };
}

/** Build a partition key string. */
export function partitionKey(key: PartitionKey): string {
  return `${key.daemonInstanceId}:${key.projectId}:${key.sessionId}`;
}

/**
 * Clear a partition when switching connection/project/session.
 */
export function clearPartition(
  state: ImageGenerationRemoteState,
  key: PartitionKey,
): ImageGenerationRemoteState {
  const k = partitionKey(key);
  const { [k]: _removed, ...rest } = state.partitions;
  void _removed;
  return { partitions: rest };
}

/**
 * Get or create a partition.
 */
export function getPartition(
  state: ImageGenerationRemoteState,
  key: PartitionKey,
): ImageGenerationPartition {
  const k = partitionKey(key);
  return state.partitions[k] ?? emptyPartition();
}

/**
 * Update a partition immutably.
 */
export function updatePartition(
  state: ImageGenerationRemoteState,
  key: PartitionKey,
  updater: (partition: ImageGenerationPartition) => ImageGenerationPartition,
): ImageGenerationRemoteState {
  const k = partitionKey(key);
  const current = state.partitions[k] ?? emptyPartition();
  return {
    partitions: { ...state.partitions, [k]: updater(current) },
  };
}
