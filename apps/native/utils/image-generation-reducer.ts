/**
 * Image-generation native job/slot/plan/late-result reducer.
 *
 * Reuses native session-event infrastructure and normalized project/session
 * stores. Render jobs by daemon/project/session/job/version and stable slot
 * IDs. Acknowledged cancel displays `Cancellation requested`; terminal
 * `Cancelled` appears only from daemon state. Quarantined late results are
 * not previewed and require explicit authorized publish/discard.
 *
 * Store/reducer identity is `(daemon_instance_id, project_id, session_id,
 * job_id)` plus monotonic entity versions. Switch/reconnect clears pending
 * uploads, approvals, artifact handles, edits, and cursors before rehydrate.
 * Duplicate/out-of-order/gap/wrong-identity events cannot regress or
 * contaminate state.
 */

import {
  type EventEntityKind,
  type EventKind,
  type ImageControlEventV1,
  type ImageGenerationArtifactState,
  type ImageGenerationJobState,
  type ImageGenerationLatePublicationState,
  type ImageGenerationSlotState,
  isTerminalJobState,
} from "./image-generation-contracts";
import { containsForbiddenSentinel } from "./image-generation-redaction";

// ---------------------------------------------------------------------------
// Entity versions
// ---------------------------------------------------------------------------

/** A monotonic entity version (canonical decimal string). */
export type EntityVersion = string;

/** Compare two canonical decimal entity versions. Returns negative/zero/positive. */
export function compareEntityVersion(a: EntityVersion, b: EntityVersion): number {
  const aNum = BigInt(a);
  const bNum = BigInt(b);
  if (aNum < bNum) return -1;
  if (aNum > bNum) return 1;
  return 0;
}

/** Returns `true` if `candidate` is newer than `current` (strictly greater). */
export function isNewerVersion(
  candidate: EntityVersion,
  current: EntityVersion | undefined,
): boolean {
  if (current === undefined) return true;
  return compareEntityVersion(candidate, current) > 0;
}

/** Returns `true` if `candidate` is newer than or equal to `current`. */
export function isAtLeastVersion(
  candidate: EntityVersion,
  current: EntityVersion | undefined,
): boolean {
  if (current === undefined) return true;
  return compareEntityVersion(candidate, current) >= 0;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/** The canonical identity tuple for a generation entity. */
export interface GenerationIdentity {
  daemonInstanceId: string;
  projectId: string;
  sessionId: string;
  jobId: string;
}

/** Returns `true` if an event identity matches the reducer's current identity. */
export function eventIdentityMatches(
  current: GenerationIdentity,
  event: { daemonInstanceId: string; projectId: string; sessionId?: string },
): boolean {
  if (event.daemonInstanceId !== current.daemonInstanceId) return false;
  if (event.projectId !== current.projectId) return false;
  // Session-scoped events must match the session; project-scoped events pass.
  if (event.sessionId && event.sessionId !== current.sessionId) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Job record
// ---------------------------------------------------------------------------

/** A stable job record rendered by daemon/project/session/job/version. */
export interface GenerationJobRecord {
  jobId: string;
  daemonInstanceId: string;
  projectId: string;
  sessionId: string;
  jobGeneration: EntityVersion;
  state: ImageGenerationJobState;
  /** Slots keyed by stable slot ID. */
  slots: Map<string, GenerationSlotRecord>;
  /** Late-quarantined artifacts keyed by artifact ID. */
  lateResults: Map<string, LateResultRecord>;
  /** The immutable plan review, if available. */
  planReview: unknown | null;
  /** Monotonic event high-water mark. */
  eventHighWater: EntityVersion;
  /** Whether cancel was acknowledged by the client (not yet terminal). */
  cancelRequested: boolean;
}

/** A stable slot record. */
export interface GenerationSlotRecord {
  slotId: string;
  slotGeneration: EntityVersion;
  state: ImageGenerationSlotState;
  artifactId: string | null;
  artifactState: ImageGenerationArtifactState | null;
}

/** A late-quarantined result requiring explicit authorized publish/discard. */
export interface LateResultRecord {
  artifactId: string;
  artifactGeneration: EntityVersion;
  artifactState: ImageGenerationArtifactState;
  publicationState: ImageGenerationLatePublicationState;
  /** Not previewed; requires explicit disposition. */
  disposition: "pending" | "publish_requested" | "discard_requested" | "published" | "discarded";
}

// ---------------------------------------------------------------------------
// Reducer state
// ---------------------------------------------------------------------------

/** The generation reducer state. */
export interface GenerationReducerState {
  /** Jobs keyed by job ID. */
  jobs: Map<string, GenerationJobRecord>;
  /** The current identity tuple. */
  identity: GenerationIdentity;
  /** Whether the reducer is rehydrating after reconnect. */
  rehydrating: boolean;
}

/** The result of reducing an event. */
export interface GenerationReducerResult {
  state: GenerationReducerState;
  /** A warning for an unknown/malformed/stale event. */
  warning?: string;
}

/** Create an empty reducer state bound to an identity. */
export function createGenerationReducerState(identity: GenerationIdentity): GenerationReducerState {
  return { jobs: new Map(), identity, rehydrating: false };
}

// ---------------------------------------------------------------------------
// Event parsing
// ---------------------------------------------------------------------------

const GENERATION_EVENT_WARN_PREFIX = "[native-image-generation] unknown event";

function eventWarning(detail: string): string {
  return `${GENERATION_EVENT_WARN_PREFIX}: ${detail}`;
}

/** Parse a raw event into a typed `ImageControlEventV1`, or return null on malformed. */
export function parseGenerationEvent(raw: unknown): ImageControlEventV1 | null {
  if (!raw || typeof raw !== "object") return null;
  const record = raw as Record<string, unknown>;
  if (typeof record.schemaVersion !== "number") return null;
  if (typeof record.deliveryId !== "string") return null;
  if (typeof record.eventSeq !== "string") return null;
  if (typeof record.daemonInstanceId !== "string") return null;
  if (typeof record.projectId !== "string") return null;
  if (typeof record.entityKind !== "string") return null;
  if (typeof record.entityId !== "string") return null;
  if (typeof record.entityGeneration !== "string") return null;
  if (typeof record.kind !== "string") return null;
  // Redact before storing.
  if (containsForbiddenSentinel(record)) return null;
  return {
    schemaVersion: record.schemaVersion,
    deliveryId: record.deliveryId,
    eventSeq: record.eventSeq,
    daemonInstanceId: record.daemonInstanceId,
    projectId: record.projectId,
    sessionId: typeof record.sessionId === "string" ? record.sessionId : undefined,
    entityKind: record.entityKind as EventEntityKind,
    entityId: record.entityId,
    entityGeneration: record.entityGeneration,
    kind: record.kind as EventKind,
    safeProjection: record.safeProjection,
  };
}

/** Returns `true` if an event seq is strictly greater than the current high-water. */
function isNewerEventSeq(eventSeq: string, current: EntityVersion | undefined): boolean {
  return isNewerVersion(eventSeq, current);
}

// ---------------------------------------------------------------------------
// Job/slot state derivation from events
// ---------------------------------------------------------------------------

function deriveJobStateFromEvent(event: ImageControlEventV1): ImageGenerationJobState | null {
  const projection = event.safeProjection;
  if (!projection || typeof projection !== "object") return null;
  const record = projection as Record<string, unknown>;
  const state = record.state;
  if (typeof state !== "string") return null;
  if (
    state === "pending" ||
    state === "running" ||
    state === "cancel_requested" ||
    state === "cancelled" ||
    state === "succeeded" ||
    state === "failed" ||
    state === "late_quarantined"
  ) {
    return state;
  }
  return null;
}

function deriveSlotStateFromEvent(event: ImageControlEventV1): ImageGenerationSlotState | null {
  const projection = event.safeProjection;
  if (!projection || typeof projection !== "object") return null;
  const record = projection as Record<string, unknown>;
  const state = record.state;
  if (typeof state !== "string") return null;
  if (
    state === "pending" ||
    state === "dispatched" ||
    state === "accepted" ||
    state === "succeeded" ||
    state === "failed" ||
    state === "cancelled" ||
    state === "late_quarantined"
  ) {
    return state;
  }
  return null;
}

function deriveArtifactStateFromEvent(
  event: ImageControlEventV1,
): ImageGenerationArtifactState | null {
  const projection = event.safeProjection;
  if (!projection || typeof projection !== "object") return null;
  const record = projection as Record<string, unknown>;
  const state = record.artifact_state ?? record.artifactState;
  if (typeof state !== "string") return null;
  if (
    state === "allocating" ||
    state === "writing" ||
    state === "retained" ||
    state === "late_quarantined" ||
    state === "cleanup_pending" ||
    state === "deleting" ||
    state === "tombstoned" ||
    state === "security_blocked"
  ) {
    return state;
  }
  return null;
}

function deriveLatePublicationState(
  event: ImageControlEventV1,
): ImageGenerationLatePublicationState | null {
  const projection = event.safeProjection;
  if (!projection || typeof projection !== "object") return null;
  const record = projection as Record<string, unknown>;
  const state = record.publication_state ?? record.publicationState;
  if (typeof state !== "string") return null;
  if (
    state === "reserved" ||
    state === "copy_authorized" ||
    state === "copy_committed" ||
    state === "published" ||
    state === "aborted" ||
    state === "expired" ||
    state === "security_blocked" ||
    state === "delete_authorized"
  ) {
    return state;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

/** Reduce a generation event into the state. Duplicate/out-of-order/gap/wrong-identity events are rejected. */
export function reduceGenerationEvent(
  state: GenerationReducerState,
  raw: unknown,
): GenerationReducerResult {
  const event = parseGenerationEvent(raw);
  if (!event) {
    return { state, warning: eventWarning("malformed_event") };
  }

  // Identity gating: wrong daemon/project/session cannot regress or contaminate state.
  if (!eventIdentityMatches(state.identity, event)) {
    return { state, warning: eventWarning("wrong_identity") };
  }

  // Duplicate/gap detection by event seq.
  // Jobs are keyed by job ID; for project-scoped events, the job ID is the entity ID.
  const jobId = event.entityId;
  const job = state.jobs.get(jobId);

  if (job && !isNewerEventSeq(event.eventSeq, job.eventHighWater)) {
    // Duplicate or out-of-order event: ignore.
    return { state, warning: eventWarning("stale_event_seq") };
  }

  switch (event.kind) {
    case "job_changed":
      return reduceJobChanged(state, event, jobId);
    case "slot_changed":
      return reduceSlotChanged(state, event, jobId);
    case "late_result_changed":
      return reduceLateResultChanged(state, event, jobId);
    case "plan_changed":
      return reducePlanChanged(state, event, jobId);
    case "config_changed":
    case "health_changed":
    case "budget_changed":
    case "destination_grant_changed":
    case "operation_changed":
      // Project/admin-scoped events that don't mutate job/slot state here.
      return { state };
    default:
      return { state, warning: eventWarning(`unknown_kind:${event.kind}`) };
  }
}

function ensureJob(
  state: GenerationReducerState,
  _event: ImageControlEventV1,
  jobId: string,
): GenerationJobRecord {
  const existing = state.jobs.get(jobId);
  if (existing) return existing;
  return {
    jobId,
    daemonInstanceId: state.identity.daemonInstanceId,
    projectId: state.identity.projectId,
    sessionId: state.identity.sessionId,
    jobGeneration: "0",
    state: "pending",
    slots: new Map(),
    lateResults: new Map(),
    planReview: null,
    eventHighWater: "0",
    cancelRequested: false,
  };
}

function reduceJobChanged(
  state: GenerationReducerState,
  event: ImageControlEventV1,
  jobId: string,
): GenerationReducerResult {
  const job = ensureJob(state, event, jobId);
  // Entity generation gating: strictly older generation cannot regress.
  if (!isNewerVersion(event.entityGeneration, job.jobGeneration)) {
    return { state, warning: eventWarning("stale_entity_generation") };
  }
  const derivedState = deriveJobStateFromEvent(event);
  // Terminal `Cancelled` appears only from daemon state, not from client cancel acknowledgement.
  const next: GenerationJobRecord = {
    ...job,
    jobGeneration: event.entityGeneration,
    eventHighWater: event.eventSeq,
    state: derivedState ?? job.state,
    // If the daemon reports a terminal state, clear the cancel-requested flag.
    cancelRequested: derivedState && isTerminalJobState(derivedState) ? false : job.cancelRequested,
  };
  state.jobs.set(jobId, next);
  return { state };
}

function reduceSlotChanged(
  state: GenerationReducerState,
  event: ImageControlEventV1,
  jobId: string,
): GenerationReducerResult {
  const job = ensureJob(state, event, jobId);
  // The slot ID is in the safe projection.
  const projection = event.safeProjection;
  if (!projection || typeof projection !== "object") {
    return { state, warning: eventWarning("missing_slot_projection") };
  }
  const record = projection as Record<string, unknown>;
  const slotId = typeof record.slot_id === "string" ? record.slot_id : null;
  if (!slotId) {
    return { state, warning: eventWarning("missing_slot_id") };
  }
  const existingSlot = job.slots.get(slotId);
  if (existingSlot && !isNewerVersion(event.entityGeneration, existingSlot.slotGeneration)) {
    return { state, warning: eventWarning("stale_slot_generation") };
  }
  const slotState = deriveSlotStateFromEvent(event) ?? existingSlot?.state ?? "pending";
  const artifactId =
    typeof record.artifact_id === "string"
      ? record.artifact_id
      : (existingSlot?.artifactId ?? null);
  const artifactState = deriveArtifactStateFromEvent(event) ?? existingSlot?.artifactState ?? null;
  const nextSlot: GenerationSlotRecord = {
    slotId,
    slotGeneration: event.entityGeneration,
    state: slotState,
    artifactId,
    artifactState,
  };
  const nextJob: GenerationJobRecord = {
    ...job,
    eventHighWater: event.eventSeq,
    slots: new Map(job.slots).set(slotId, nextSlot),
  };
  state.jobs.set(jobId, nextJob);
  return { state };
}

function reduceLateResultChanged(
  state: GenerationReducerState,
  event: ImageControlEventV1,
  jobId: string,
): GenerationReducerResult {
  const job = ensureJob(state, event, jobId);
  const projection = event.safeProjection;
  if (!projection || typeof projection !== "object") {
    return { state, warning: eventWarning("missing_late_result_projection") };
  }
  const record = projection as Record<string, unknown>;
  const artifactId = typeof record.artifact_id === "string" ? record.artifact_id : null;
  if (!artifactId) {
    return { state, warning: eventWarning("missing_artifact_id") };
  }
  const existing = job.lateResults.get(artifactId);
  if (existing && !isNewerVersion(event.entityGeneration, existing.artifactGeneration)) {
    return { state, warning: eventWarning("stale_late_result_generation") };
  }
  const artifactState =
    deriveArtifactStateFromEvent(event) ?? existing?.artifactState ?? "late_quarantined";
  const publicationState =
    deriveLatePublicationState(event) ?? existing?.publicationState ?? "reserved";
  // Quarantined late results are not previewed; disposition stays pending until explicit action.
  const disposition = existing?.disposition ?? "pending";
  const nextLate: LateResultRecord = {
    artifactId,
    artifactGeneration: event.entityGeneration,
    artifactState,
    publicationState,
    disposition,
  };
  const nextJob: GenerationJobRecord = {
    ...job,
    eventHighWater: event.eventSeq,
    lateResults: new Map(job.lateResults).set(artifactId, nextLate),
  };
  state.jobs.set(jobId, nextJob);
  return { state };
}

function reducePlanChanged(
  state: GenerationReducerState,
  event: ImageControlEventV1,
  jobId: string,
): GenerationReducerResult {
  const job = ensureJob(state, event, jobId);
  if (!isNewerVersion(event.entityGeneration, job.jobGeneration)) {
    return { state, warning: eventWarning("stale_plan_generation") };
  }
  // The plan review is immutable; render every fact. Store the safe projection.
  const nextJob: GenerationJobRecord = {
    ...job,
    jobGeneration: event.entityGeneration,
    eventHighWater: event.eventSeq,
    planReview: event.safeProjection,
  };
  state.jobs.set(jobId, nextJob);
  return { state };
}

// ---------------------------------------------------------------------------
// Cancel acknowledgement
// ---------------------------------------------------------------------------

/** Acknowledge a cancel request. Displays `Cancellation requested`; does not predict provider cancellation. */
export function acknowledgeCancel(
  state: GenerationReducerState,
  jobId: string,
): GenerationReducerResult {
  const job = state.jobs.get(jobId);
  if (!job) return { state, warning: eventWarning("cancel_unknown_job") };
  if (isTerminalJobState(job.state)) {
    // Already terminal from daemon state; no-op.
    return { state };
  }
  const next: GenerationJobRecord = { ...job, cancelRequested: true };
  state.jobs.set(jobId, next);
  return { state };
}

/** The cancel view: `Cancellation requested` when acknowledged and not yet terminal. */
export function cancelView(
  job: GenerationJobRecord | null | undefined,
):
  | { kind: "none" }
  | { kind: "requested"; label: "Cancellation requested" }
  | { kind: "terminal"; label: "Cancelled" } {
  if (!job) return { kind: "none" };
  if (job.state === "cancelled") return { kind: "terminal", label: "Cancelled" };
  if (job.cancelRequested && !isTerminalJobState(job.state)) {
    return { kind: "requested", label: "Cancellation requested" };
  }
  return { kind: "none" };
}

// ---------------------------------------------------------------------------
// Late result disposition
// ---------------------------------------------------------------------------

/** Request publication of a quarantined late result. Requires authorized disposition. */
export function requestLateResultPublish(
  state: GenerationReducerState,
  jobId: string,
  artifactId: string,
): GenerationReducerResult {
  const job = state.jobs.get(jobId);
  if (!job) return { state, warning: eventWarning("late_result_unknown_job") };
  const late = job.lateResults.get(artifactId);
  if (!late) return { state, warning: eventWarning("late_result_unknown_artifact") };
  if (late.disposition === "published" || late.disposition === "discarded") {
    return { state, warning: eventWarning("late_result_already_disposed") };
  }
  const nextLate: LateResultRecord = { ...late, disposition: "publish_requested" };
  const nextJob: GenerationJobRecord = {
    ...job,
    lateResults: new Map(job.lateResults).set(artifactId, nextLate),
  };
  state.jobs.set(jobId, nextJob);
  return { state };
}

/** Request discard of a quarantined late result. Requires authorized disposition. */
export function requestLateResultDiscard(
  state: GenerationReducerState,
  jobId: string,
  artifactId: string,
): GenerationReducerResult {
  const job = state.jobs.get(jobId);
  if (!job) return { state, warning: eventWarning("late_result_unknown_job") };
  const late = job.lateResults.get(artifactId);
  if (!late) return { state, warning: eventWarning("late_result_unknown_artifact") };
  if (late.disposition === "published" || late.disposition === "discarded") {
    return { state, warning: eventWarning("late_result_already_disposed") };
  }
  const nextLate: LateResultRecord = { ...late, disposition: "discard_requested" };
  const nextJob: GenerationJobRecord = {
    ...job,
    lateResults: new Map(job.lateResults).set(artifactId, nextLate),
  };
  state.jobs.set(jobId, nextJob);
  return { state };
}

/** Apply a daemon-confirmed late-result disposition. */
export function applyLateResultDisposition(
  state: GenerationReducerState,
  jobId: string,
  artifactId: string,
  disposition: "published" | "discarded",
): GenerationReducerResult {
  const job = state.jobs.get(jobId);
  if (!job) return { state };
  const late = job.lateResults.get(artifactId);
  if (!late) return { state };
  const nextLate: LateResultRecord = { ...late, disposition };
  const nextJob: GenerationJobRecord = {
    ...job,
    lateResults: new Map(job.lateResults).set(artifactId, nextLate),
  };
  state.jobs.set(jobId, nextJob);
  return { state };
}

/** Returns `true` if a late result is quarantined and not yet disposed (not previewed). */
export function isLateResultQuarantinedPending(late: LateResultRecord): boolean {
  return (
    late.artifactState === "late_quarantined" &&
    late.disposition !== "published" &&
    late.disposition !== "discarded"
  );
}

// ---------------------------------------------------------------------------
// Switch/reconnect: clear pending state before rehydrate
// ---------------------------------------------------------------------------

/** Clear all jobs, slots, late results, plan reviews, and cursors on switch/reconnect. */
export function clearGenerationState(state: GenerationReducerState): GenerationReducerState {
  return {
    jobs: new Map(),
    identity: state.identity,
    rehydrating: true,
  };
}

/** Rebind the reducer to a new identity, clearing pending state before rehydrate. */
export function rebindGenerationState(
  _state: GenerationReducerState,
  identity: GenerationIdentity,
): GenerationReducerState {
  return { jobs: new Map(), identity, rehydrating: true };
}

/** Mark rehydration complete. */
export function finishRehydrate(state: GenerationReducerState): GenerationReducerState {
  return { ...state, rehydrating: false };
}

// ---------------------------------------------------------------------------
// Snapshot hydration
// ---------------------------------------------------------------------------

/** Hydrate from a session snapshot (plans/jobs). Used after reconnect. */
export function hydrateGenerationSnapshot(
  state: GenerationReducerState,
  snapshot: {
    component: "plans" | "jobs";
    items: readonly unknown[];
    snapshotGeneration: EntityVersion;
    eventHighWater: EntityVersion;
  },
): GenerationReducerState {
  const next = new Map(state.jobs);
  for (const item of snapshot.items) {
    if (!item || typeof item !== "object") continue;
    const record = item as Record<string, unknown>;
    const jobId = typeof record.job_id === "string" ? record.job_id : null;
    if (!jobId) continue;
    if (containsForbiddenSentinel(record)) continue;
    const jobGeneration = typeof record.job_generation === "string" ? record.job_generation : "0";
    const existing = next.get(jobId);
    if (existing && !isNewerVersion(jobGeneration, existing.jobGeneration)) continue;
    const stateValue = typeof record.state === "string" ? record.state : "pending";
    const slotsMap = new Map<string, GenerationSlotRecord>();
    if (Array.isArray(record.slots)) {
      for (const slotRaw of record.slots) {
        if (!slotRaw || typeof slotRaw !== "object") continue;
        const slot = slotRaw as Record<string, unknown>;
        const slotId = typeof slot.slot_id === "string" ? slot.slot_id : null;
        if (!slotId) continue;
        slotsMap.set(slotId, {
          slotId,
          slotGeneration: typeof slot.slot_generation === "string" ? slot.slot_generation : "0",
          state: (typeof slot.state === "string"
            ? slot.state
            : "pending") as ImageGenerationSlotState,
          artifactId: typeof slot.artifact_id === "string" ? slot.artifact_id : null,
          artifactState:
            typeof slot.artifact_state === "string"
              ? (slot.artifact_state as ImageGenerationArtifactState)
              : null,
        });
      }
    }
    next.set(jobId, {
      jobId,
      daemonInstanceId: state.identity.daemonInstanceId,
      projectId: state.identity.projectId,
      sessionId: state.identity.sessionId,
      jobGeneration,
      state: stateValue as ImageGenerationJobState,
      slots: slotsMap,
      lateResults: new Map(),
      planReview: record.plan ?? null,
      eventHighWater: snapshot.eventHighWater,
      cancelRequested: false,
    });
  }
  return { ...state, jobs: next, rehydrating: false };
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

/** All jobs for the current identity, sorted by job generation. */
export function sortedJobs(state: GenerationReducerState): GenerationJobRecord[] {
  return [...state.jobs.values()].sort((a, b) =>
    compareEntityVersion(a.jobGeneration, b.jobGeneration),
  );
}

/** A job by ID, or null. */
export function jobById(state: GenerationReducerState, jobId: string): GenerationJobRecord | null {
  return state.jobs.get(jobId) ?? null;
}

/** All quarantined late results pending disposition across all jobs. */
export function pendingLateResults(state: GenerationReducerState): Array<{
  job: GenerationJobRecord;
  late: LateResultRecord;
}> {
  const results: Array<{ job: GenerationJobRecord; late: LateResultRecord }> = [];
  for (const job of state.jobs.values()) {
    for (const late of job.lateResults.values()) {
      if (isLateResultQuarantinedPending(late)) {
        results.push({ job, late });
      }
    }
  }
  return results;
}
