import { describe, expect, it, vi } from "vitest";
import {
  addOptimisticUserMessage,
  applyLiveEvent,
  mergeAttach,
  reduceRemoteSessionEvent,
  resetRemoteSessionEventWarningsForTests,
  updateSessionSharedWithCollaborators,
  useRemoteSessionsStore,
  type WebSessionSummary,
  warnUnhandledRemoteSessionEvent,
} from "./remote-sessions";

const sessionId = "11111111-1111-4111-8111-111111111111";
const interruptId = "22222222-2222-4222-8222-222222222222";

const empty = {
  status: "connected" as const,
  projects: [],
  sessionsByProject: {},
  detailsBySession: {},
  statsRollupByProject: {},
};

const attachFixture = {
  session_id: sessionId,
  short_id: "s1",
  project_root: "/work/app",
  project_id: "project_1",
  active_agent: "Build",
  history: [
    { role: "assistant" as const, seq: 2, agent: "Build", text: "I will inspect." },
    { role: "user" as const, seq: 1, text: "Please fix checkout" },
  ],
};

function withDetail() {
  return mergeAttach(empty, attachFixture);
}

function event(event: string, data: Record<string, unknown>) {
  return { v: 1, kind: "evt", event, data } as const;
}

describe("remote session reducers", () => {
  it("orders attach history by sequence and tracks nextSeq", () => {
    const state = mergeAttach(empty, attachFixture);
    const detail = state.detailsBySession[sessionId];
    expect(detail.history.map((entry) => entry.seq)).toEqual([1, 2]);
    expect(detail.nextSeq).toBe(3);
    expect(detail.summary.sessionId).toBe(sessionId);
  });

  it("merges reconnect backfill without dropping newer optimistic entries", () => {
    const first = addOptimisticUserMessage(withDetail(), sessionId, "newer", "local-1");
    const state = mergeAttach(first, attachFixture);
    expect(
      state.detailsBySession[sessionId].history.some(
        (entry) => entry.id === "user:pending:local-1",
      ),
    ).toBe(true);
  });

  it("applies committed history replay and assistant deltas", () => {
    const withAttach = withDetail();
    const replayed = applyLiveEvent(
      withAttach,
      event("history_replay", {
        session_id: sessionId,
        max_seq: 5,
        entries: [{ role: "assistant", seq: 5, agent: "Build", text: "Hello" }],
      }),
    );
    const streamed = applyLiveEvent(
      replayed,
      event("assistant_text_delta", { session_id: sessionId, agent: "Build", delta: " world" }),
    );
    const final = applyLiveEvent(
      streamed,
      event("assistant_text", {
        session_id: sessionId,
        agent: "Build",
        seq: 6,
        text: "Hello world",
      }),
    );
    expect(final.detailsBySession[sessionId].history).toContainEqual({
      id: "assistant:6",
      kind: "assistant_text",
      seq: 6,
      text: "Hello world",
    });
  });

  it("applies reasoning deltas and tool-call lifecycle", () => {
    const started = applyLiveEvent(
      withDetail(),
      event("tool_start", {
        session_id: sessionId,
        agent: "Build",
        call_id: "tool1",
        tool: "shell",
        args: { cmd: "pnpm test" },
      }),
    );
    const reasoned = applyLiveEvent(
      started,
      event("reasoning_delta", { session_id: sessionId, agent: "Build", delta: "Thinking" }),
    );
    const ended = applyLiveEvent(
      reasoned,
      event("tool_end", {
        session_id: sessionId,
        agent: "Build",
        call_id: "tool1",
        tool: "shell",
        seq: 7,
        output: "ok",
      }),
    );
    expect(ended.detailsBySession[sessionId].history).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "assistant_reasoning", text: "Thinking" }),
        expect.objectContaining({ kind: "tool_call", callId: "tool1", status: "succeeded" }),
      ]),
    );
  });

  it("adds and resolves interrupts through daemon question shapes", () => {
    const raised = applyLiveEvent(
      withDetail(),
      event("interrupt_raised", {
        session_id: sessionId,
        interrupt_id: interruptId,
        agent: "Build",
        description: "Approval needed",
        question: {
          kind: "single",
          data: {
            prompt: "Run command?",
            options: [{ id: "approve_once", label: "Approve once" }],
            permission: true,
          },
        },
      }),
    );
    const resolved = applyLiveEvent(
      raised,
      event("interrupt_resolved", { session_id: sessionId, interrupt_id: interruptId, seq: 8 }),
    );
    expect(resolved.detailsBySession[sessionId].history).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "interrupt",
          interrupt: expect.objectContaining({ interruptId, resolved: true }),
        }),
      ]),
    );
  });

  it("updates session summaries and usage without losing details", () => {
    const withUsage = applyLiveEvent(
      withDetail(),
      event("usage", {
        session_id: sessionId,
        agent: "Build",
        input_tokens: 1,
        output_tokens: 2,
      }),
    );
    const updated = applyLiveEvent(
      withUsage,
      event("agent_idle", {
        session_id: sessionId,
        turn_id: "turn1",
        reason: { kind: "needs_intervention" },
      }),
    );
    expect(updated.detailsBySession[sessionId].usage?.totalTokens).toBe(3);
    expect(updated.detailsBySession[sessionId].summary.status).toBe("needs_intervention");
  });

  it("tolerates and warns once for unknown event kinds", () => {
    resetRemoteSessionEventWarningsForTests();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const state = withDetail();
    const result = reduceRemoteSessionEvent(
      state,
      event("future_event", { session_id: sessionId }),
    );
    expect(result.state).toBe(state);
    warnUnhandledRemoteSessionEvent(result.warningKind, false);
    warnUnhandledRemoteSessionEvent(result.warningKind, false);
    warnUnhandledRemoteSessionEvent("prod_only", true);
    expect(warn).toHaveBeenCalledExactlyOnceWith("[remote-sessions] unhandled event: future_event");
    warn.mockRestore();
  });

  it("tolerates malformed known-kind event without dropping siblings", () => {
    const state = withDetail();
    const malformed = reduceRemoteSessionEvent(
      state,
      event("assistant_text", { session_id: sessionId }),
    );
    const valid = reduceRemoteSessionEvent(
      malformed.state,
      event("assistant_text", { session_id: sessionId, seq: 9, text: "valid" }),
    );
    expect(malformed.state).toBe(state);
    expect(malformed.warningKind).toBe("assistant_text");
    expect(valid.state.detailsBySession[sessionId].history).toContainEqual({
      id: "assistant:9",
      kind: "assistant_text",
      seq: 9,
      text: "valid",
    });

    const malformedTool = reduceRemoteSessionEvent(
      state,
      event("tool_start", { session_id: sessionId, tool: "shell" }),
    );
    expect(malformedTool.state).toBe(state);
    expect(malformedTool.warningKind).toBe("tool_start");

    const malformedToolEnd = reduceRemoteSessionEvent(
      state,
      event("tool_end", { session_id: sessionId, call_id: "tool1", tool: "shell" }),
    );
    expect(malformedToolEnd.state).toBe(state);
    expect(malformedToolEnd.warningKind).toBe("tool_end");
  });

  it("optimistically shares sessions and reverts when the daemon rejects the toggle", async () => {
    const baseSummary: WebSessionSummary = {
      ...withDetail().detailsBySession[sessionId].summary,
      sharedWithCollaborators: false,
    };
    const base = updateSessionSharedWithCollaborators(
      {
        ...withDetail(),
        sessionsByProject: { [baseSummary.projectRoot]: [baseSummary] },
        detailsBySession: {
          [sessionId]: { ...withDetail().detailsBySession[sessionId], summary: baseSummary },
        },
      },
      sessionId,
      false,
    );
    const shareSession = vi.fn().mockRejectedValueOnce(new Error("denied"));
    useRemoteSessionsStore.setState({
      instances: { i1: base },
      clients: { i1: { shareSession } as never },
    });

    await expect(
      useRemoteSessionsStore.getState().shareSession("i1", sessionId, true),
    ).rejects.toThrow("denied");

    expect(shareSession).toHaveBeenCalledWith(sessionId, true);
    const state = useRemoteSessionsStore.getState().instances.i1;
    expect(state.detailsBySession[sessionId].summary.sharedWithCollaborators).toBe(false);
    expect(state.sessionsByProject["/work/app"][0]?.sharedWithCollaborators).toBe(false);
  });
});
