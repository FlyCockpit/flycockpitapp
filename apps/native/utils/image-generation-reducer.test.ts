import { describe, expect, it } from "vitest";
import {
  acknowledgeCancel,
  applyLateResultDisposition,
  cancelView,
  clearGenerationState,
  compareEntityVersion,
  createGenerationReducerState,
  type GenerationIdentity,
  hydrateGenerationSnapshot,
  isLateResultQuarantinedPending,
  isNewerVersion,
  jobById,
  parseGenerationEvent,
  pendingLateResults,
  rebindGenerationState,
  reduceGenerationEvent,
  requestLateResultDiscard,
  requestLateResultPublish,
  sortedJobs,
} from "./image-generation-reducer";

const identity: GenerationIdentity = {
  daemonInstanceId: "daemon-1",
  projectId: "project-1",
  sessionId: "session-1",
  jobId: "job-1",
};

function jobEvent(overrides: Partial<Record<string, unknown>>): Record<string, unknown> {
  return {
    schemaVersion: 1,
    deliveryId: "delivery-1",
    eventSeq: "1",
    daemonInstanceId: identity.daemonInstanceId,
    projectId: identity.projectId,
    sessionId: identity.sessionId,
    entityKind: "job",
    entityId: identity.jobId,
    entityGeneration: "1",
    kind: "job_changed",
    safeProjection: { state: "running" },
    ...overrides,
  };
}

function slotEvent(
  slotId: string,
  generation: string,
  overrides: Partial<Record<string, unknown>> = {},
): unknown {
  return {
    schemaVersion: 1,
    deliveryId: `delivery-slot-${slotId}-${generation}`,
    eventSeq: generation,
    daemonInstanceId: identity.daemonInstanceId,
    projectId: identity.projectId,
    sessionId: identity.sessionId,
    entityKind: "slot",
    entityId: identity.jobId,
    entityGeneration: generation,
    kind: "slot_changed",
    safeProjection: { slot_id: slotId, state: "dispatched", artifact_id: `artifact-${slotId}` },
    ...overrides,
  };
}

function lateResultEvent(artifactId: string, generation: string): unknown {
  return {
    schemaVersion: 1,
    deliveryId: `delivery-late-${artifactId}-${generation}`,
    eventSeq: generation,
    daemonInstanceId: identity.daemonInstanceId,
    projectId: identity.projectId,
    sessionId: identity.sessionId,
    entityKind: "artifact",
    entityId: identity.jobId,
    entityGeneration: generation,
    kind: "late_result_changed",
    safeProjection: {
      artifact_id: artifactId,
      artifact_state: "late_quarantined",
      publication_state: "reserved",
    },
  };
}

describe("image generation job reducer", () => {
  it("compares entity versions correctly", () => {
    expect(compareEntityVersion("1", "2")).toBeLessThan(0);
    expect(compareEntityVersion("2", "1")).toBeGreaterThan(0);
    expect(compareEntityVersion("1", "1")).toBe(0);
    expect(isNewerVersion("2", "1")).toBe(true);
    expect(isNewerVersion("1", "1")).toBe(false);
    expect(isNewerVersion("1", undefined)).toBe(true);
  });

  it("parses a valid generation event and rejects malformed", () => {
    expect(parseGenerationEvent(jobEvent({}))).not.toBeNull();
    expect(parseGenerationEvent({})).toBeNull();
    expect(parseGenerationEvent({ ...jobEvent({}), entityKind: 123 })).toBeNull();
  });

  it("applies a job_changed event and renders by daemon/project/session/job/version", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ entityGeneration: "1", eventSeq: "1" })).state;
    const job = jobById(state, identity.jobId);
    expect(job).not.toBeNull();
    expect(job?.state).toBe("running");
    expect(job?.jobGeneration).toBe("1");
    expect(job?.daemonInstanceId).toBe(identity.daemonInstanceId);
    expect(job?.projectId).toBe(identity.projectId);
    expect(job?.sessionId).toBe(identity.sessionId);
  });

  it("rejects duplicate events (same event seq)", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "1" })).state;
    const result = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "2" }));
    expect(result.warning).toContain("stale_event_seq");
    // State unchanged.
    expect(jobById(result.state, identity.jobId)?.jobGeneration).toBe("1");
  });

  it("rejects out-of-order events (older event seq)", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "5", entityGeneration: "1" })).state;
    const result = reduceGenerationEvent(state, jobEvent({ eventSeq: "3", entityGeneration: "2" }));
    expect(result.warning).toContain("stale_event_seq");
  });

  it("rejects wrong-identity events (wrong daemon/project/session)", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "1" })).state;
    const wrongDaemon = reduceGenerationEvent(
      state,
      jobEvent({ daemonInstanceId: "daemon-other", eventSeq: "2", entityGeneration: "2" }),
    );
    expect(wrongDaemon.warning).toContain("wrong_identity");
    const wrongProject = reduceGenerationEvent(
      state,
      jobEvent({ projectId: "project-other", eventSeq: "2", entityGeneration: "2" }),
    );
    expect(wrongProject.warning).toContain("wrong_identity");
    const wrongSession = reduceGenerationEvent(
      state,
      jobEvent({ sessionId: "session-other", eventSeq: "2", entityGeneration: "2" }),
    );
    expect(wrongSession.warning).toContain("wrong_identity");
  });

  it("rejects stale entity generation (older job generation cannot regress)", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "5", entityGeneration: "3" })).state;
    const result = reduceGenerationEvent(state, jobEvent({ eventSeq: "6", entityGeneration: "2" }));
    expect(result.warning).toContain("stale_entity_generation");
  });

  it("applies slot_changed events with stable slot IDs", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "1" })).state;
    state = reduceGenerationEvent(state, slotEvent("slot-1", "2")).state;
    state = reduceGenerationEvent(state, slotEvent("slot-2", "3")).state;
    const job = jobById(state, identity.jobId);
    expect(job?.slots.size).toBe(2);
    expect(job?.slots.get("slot-1")?.state).toBe("dispatched");
    expect(job?.slots.get("slot-2")?.artifactId).toBe("artifact-slot-2");
  });

  it("rejects stale slot generation", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "1" })).state;
    state = reduceGenerationEvent(state, slotEvent("slot-1", "5")).state;
    // Newer eventSeq but older entityGeneration -> stale slot generation.
    const result = reduceGenerationEvent(state, slotEvent("slot-1", "3", { eventSeq: "6" }));
    expect(result.warning).toContain("stale_slot_generation");
  });

  it("cancel acknowledgement shows 'Cancellation requested' and terminal only from daemon", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(
      state,
      jobEvent({ eventSeq: "1", entityGeneration: "1", safeProjection: { state: "running" } }),
    ).state;
    let job = jobById(state, identity.jobId);
    expect(cancelView(job).kind).toBe("none");

    state = acknowledgeCancel(state, identity.jobId).state;
    job = jobById(state, identity.jobId);
    expect(job?.cancelRequested).toBe(true);
    const view = cancelView(job);
    expect(view.kind).toBe("requested");
    if (view.kind === "requested") expect(view.label).toBe("Cancellation requested");

    // Terminal Cancelled appears only from daemon state.
    state = reduceGenerationEvent(
      state,
      jobEvent({ eventSeq: "2", entityGeneration: "2", safeProjection: { state: "cancelled" } }),
    ).state;
    job = jobById(state, identity.jobId);
    expect(job?.state).toBe("cancelled");
    expect(job?.cancelRequested).toBe(false);
    const terminalView = cancelView(job);
    expect(terminalView.kind).toBe("terminal");
  });

  it("cancel acknowledgement is a no-op when already terminal", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(
      state,
      jobEvent({ eventSeq: "1", entityGeneration: "1", safeProjection: { state: "succeeded" } }),
    ).state;
    state = acknowledgeCancel(state, identity.jobId).state;
    const job = jobById(state, identity.jobId);
    expect(job?.cancelRequested).toBe(false);
  });

  it("quarantined late results are not previewed and require explicit publish/discard", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "1" })).state;
    state = reduceGenerationEvent(state, lateResultEvent("artifact-late", "2")).state;
    const pending = pendingLateResults(state);
    expect(pending).toHaveLength(1);
    expect(pending[0].late.artifactId).toBe("artifact-late");
    expect(isLateResultQuarantinedPending(pending[0].late)).toBe(true);

    // Request publish.
    state = requestLateResultPublish(state, identity.jobId, "artifact-late").state;
    let job = jobById(state, identity.jobId);
    expect(job?.lateResults.get("artifact-late")?.disposition).toBe("publish_requested");

    // Daemon confirms publication.
    state = applyLateResultDisposition(state, identity.jobId, "artifact-late", "published").state;
    job = jobById(state, identity.jobId);
    expect(job?.lateResults.get("artifact-late")?.disposition).toBe("published");
    expect(pendingLateResults(state)).toHaveLength(0);
  });

  it("requestLateResultDiscard sets discard_requested", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "1" })).state;
    state = reduceGenerationEvent(state, lateResultEvent("artifact-late", "2")).state;
    state = requestLateResultDiscard(state, identity.jobId, "artifact-late").state;
    const job = jobById(state, identity.jobId);
    expect(job?.lateResults.get("artifact-late")?.disposition).toBe("discard_requested");
  });

  it("clearGenerationState clears jobs on switch/reconnect", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "1" })).state;
    state = clearGenerationState(state);
    expect(sortedJobs(state)).toHaveLength(0);
    expect(state.rehydrating).toBe(true);
  });

  it("rebindGenerationState clears and rebinds identity", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "1" })).state;
    const newIdentity = { ...identity, sessionId: "session-2", jobId: "job-2" };
    state = rebindGenerationState(state, newIdentity);
    expect(sortedJobs(state)).toHaveLength(0);
    expect(state.identity.sessionId).toBe("session-2");
  });

  it("hydrateGenerationSnapshot rehydrates jobs after reconnect", () => {
    let state = createGenerationReducerState(identity);
    state = rebindGenerationState(state, identity);
    state = hydrateGenerationSnapshot(state, {
      component: "jobs",
      items: [
        {
          job_id: identity.jobId,
          job_generation: "5",
          state: "running",
          slots: [
            { slot_id: "slot-1", slot_generation: "1", state: "dispatched", artifact_id: "a-1" },
          ],
        },
      ],
      snapshotGeneration: "5",
      eventHighWater: "10",
    });
    expect(state.rehydrating).toBe(false);
    const job = jobById(state, identity.jobId);
    expect(job?.jobGeneration).toBe("5");
    expect(job?.state).toBe("running");
    expect(job?.slots.get("slot-1")?.slotId).toBe("slot-1");
    expect(job?.eventHighWater).toBe("10");
  });

  it("hydrateGenerationSnapshot rejects stale and forbidden-sentinel items", () => {
    let state = createGenerationReducerState(identity);
    state = reduceGenerationEvent(state, jobEvent({ eventSeq: "1", entityGeneration: "10" })).state;
    state = hydrateGenerationSnapshot(state, {
      component: "jobs",
      items: [
        // Stale (older generation).
        { job_id: identity.jobId, job_generation: "5", state: "pending" },
        // Forbidden sentinel.
        { job_id: "job-bad", job_generation: "20", state: "running", secret: "leak" },
        // Valid new job.
        { job_id: "job-new", job_generation: "1", state: "pending" },
      ],
      snapshotGeneration: "20",
      eventHighWater: "20",
    });
    expect(jobById(state, identity.jobId)?.jobGeneration).toBe("10");
    expect(jobById(state, "job-bad")).toBeNull();
    expect(jobById(state, "job-new")?.jobGeneration).toBe("1");
  });

  it("rejects events with forbidden sentinel keys", () => {
    let state = createGenerationReducerState(identity);
    const result = reduceGenerationEvent(
      state,
      jobEvent({ eventSeq: "1", entityGeneration: "1", secret: "leak" }),
    );
    expect(result.warning).toContain("malformed_event");
  });
});
