import type { HistoryPageResult } from "@flycockpit/cockpit-protocol";
import { describe, expect, it, vi } from "vitest";
import {
  addOptimisticUserMessage,
  applyLiveEvent,
  interruptDecisionView,
  mergeAttach,
  mergeHistoryPage,
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
    expect(detail.paging).toEqual({
      oldestSeq: 1,
      hasMore: true,
      isLoading: false,
      error: null,
    });
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

  it("prepends older history pages, dedupes replayed rows, and updates paging state", () => {
    const detail = withDetail().detailsBySession[sessionId];
    const merged = mergeHistoryPage(detail, {
      session_id: sessionId,
      entries: [
        { role: "user", seq: 0, text: "Earlier question" },
        { role: "user", seq: 1, text: "Duplicate from page" },
        {
          role: "tool_call",
          seq: 2,
          agent: "Build",
          call_id: "duplicate-seq-tool",
          tool: "shell",
          original_input: {},
          wire_input: {},
          output: "duplicate",
          hard_fail: false,
          truncated: false,
        },
      ],
      has_more: false,
    });

    expect(merged.history.map((entry) => entry.seq)).toEqual([0, 1, 2]);
    expect(
      merged.history.find((entry) => entry.seq === 1 && entry.kind === "user_message"),
    ).toMatchObject({ text: "Please fix checkout" });
    expect(merged.history.find((entry) => entry.seq === 2)).toMatchObject({
      kind: "assistant_text",
      text: "I will inspect.",
    });
    expect(merged.nextSeq).toBe(3);
    expect(merged.paging).toEqual({
      oldestSeq: 0,
      hasMore: false,
      isLoading: false,
      error: null,
    });
  });

  it("keeps live-tail entries ordered after an older page is prepended", () => {
    const paged = {
      ...withDetail(),
      detailsBySession: {
        [sessionId]: mergeHistoryPage(withDetail().detailsBySession[sessionId], {
          session_id: sessionId,
          entries: [{ role: "user", seq: 0, text: "Earlier question" }],
          has_more: true,
        }),
      },
    };
    const live = applyLiveEvent(
      paged,
      event("assistant_text", {
        session_id: sessionId,
        agent: "Build",
        seq: 3,
        text: "Live response",
      }),
    );

    expect(live.detailsBySession[sessionId].history.map((entry) => entry.seq)).toEqual([
      0, 1, 2, 3,
    ]);
  });

  it("preserves synthetic pending rows that share sentinel sequences during page merges", () => {
    const withPendingUsers = addOptimisticUserMessage(
      addOptimisticUserMessage(withDetail(), sessionId, "first pending", "local-1"),
      sessionId,
      "second pending",
      "local-2",
    );
    const withRunningTools = applyLiveEvent(
      applyLiveEvent(
        withPendingUsers,
        event("tool_start", {
          session_id: sessionId,
          agent: "Build",
          call_id: "tool1",
          tool: "shell",
          args: { cmd: "one" },
        }),
      ),
      event("tool_start", {
        session_id: sessionId,
        agent: "Build",
        call_id: "tool2",
        tool: "shell",
        args: { cmd: "two" },
      }),
    );
    const merged = mergeHistoryPage(withRunningTools.detailsBySession[sessionId], {
      session_id: sessionId,
      entries: [{ role: "user", seq: 0, text: "Earlier question" }],
      has_more: true,
    });

    expect(
      merged.history.filter((entry) => entry.kind === "user_message" && entry.seq > 1000),
    ).toHaveLength(2);
    expect(
      merged.history.filter((entry) => entry.kind === "tool_call" && entry.status === "running"),
    ).toHaveLength(2);
  });

  it("keeps already-paged older rows when attach refreshes a truncated snapshot", () => {
    const paged = mergeHistoryPage(withDetail().detailsBySession[sessionId], {
      session_id: sessionId,
      entries: [{ role: "user", seq: 0, text: "Earlier question" }],
      has_more: false,
    });
    const state = mergeAttach(
      {
        ...withDetail(),
        detailsBySession: { [sessionId]: paged },
      },
      attachFixture,
    );

    expect(state.detailsBySession[sessionId].history.map((entry) => entry.seq)).toEqual([0, 1, 2]);
    expect(state.detailsBySession[sessionId].paging).toMatchObject({
      oldestSeq: 0,
      hasMore: false,
    });
  });

  it("keeps already-paged older rows when history replay refreshes a truncated snapshot", () => {
    const paged = mergeHistoryPage(withDetail().detailsBySession[sessionId], {
      session_id: sessionId,
      entries: [{ role: "user", seq: 0, text: "Earlier question" }],
      has_more: false,
    });
    const replayed = applyLiveEvent(
      {
        ...withDetail(),
        detailsBySession: { [sessionId]: paged },
      },
      event("history_replay", {
        session_id: sessionId,
        max_seq: 2,
        entries: [{ role: "assistant", seq: 2, agent: "Build", text: "Updated snapshot" }],
      }),
    );

    expect(replayed.detailsBySession[sessionId].history.map((entry) => entry.seq)).toEqual([
      0, 1, 2,
    ]);
    expect(
      replayed.detailsBySession[sessionId].history.find((entry) => entry.seq === 2),
    ).toMatchObject({
      kind: "assistant_text",
      text: "Updated snapshot",
    });
    expect(replayed.detailsBySession[sessionId].paging).toMatchObject({
      oldestSeq: 0,
      hasMore: false,
    });
  });

  it("maps interrupt decisions as resolved non-interactive history records", () => {
    const state = mergeAttach(empty, {
      ...attachFixture,
      history: [
        {
          role: "interrupt_decision" as const,
          seq: 4,
          decision: {
            permission: true,
            cancelled: false,
            lines: [{ prompt: "Run command?", answer: "Approved once" }],
          },
        },
      ],
    });
    const entry = state.detailsBySession[sessionId].history[0];
    if (!entry) throw new Error("missing interrupt decision entry");

    expect(entry).toMatchObject({ kind: "interrupt_decision", seq: 4 });
    expect(interruptDecisionView(entry)).toEqual({
      interactive: false,
      permission: true,
      cancelled: false,
      lines: [{ prompt: "Run command?", answer: "Approved once" }],
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

  it("allows only one older-history request in flight and stops when exhausted", async () => {
    let resolvePage: (page: HistoryPageResult) => void = () => {};
    const readHistoryPage = vi.fn(
      () =>
        new Promise<HistoryPageResult>((resolve) => {
          resolvePage = resolve;
        }),
    );
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { readHistoryPage } as never },
    });

    const first = useRemoteSessionsStore.getState().loadOlderHistory("i1", sessionId);
    const second = useRemoteSessionsStore.getState().loadOlderHistory("i1", sessionId);
    await Promise.resolve();

    expect(readHistoryPage).toHaveBeenCalledExactlyOnceWith({
      session_id: sessionId,
      before_seq: 1,
      limit: 100,
    });
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].paging,
    ).toMatchObject({ isLoading: true, error: null });

    useRemoteSessionsStore.setState((state) => ({
      instances: {
        ...state.instances,
        i1: mergeAttach(state.instances.i1 ?? empty, attachFixture),
      },
      clients: state.clients,
    }));
    await useRemoteSessionsStore.getState().loadOlderHistory("i1", sessionId);
    expect(readHistoryPage).toHaveBeenCalledTimes(1);

    resolvePage({
      session_id: sessionId,
      entries: [{ role: "user", seq: 0, text: "Earlier question" }],
      has_more: false,
    });
    await first;
    await second;
    await useRemoteSessionsStore.getState().loadOlderHistory("i1", sessionId);

    expect(readHistoryPage).toHaveBeenCalledTimes(1);
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].paging,
    ).toMatchObject({ oldestSeq: 0, hasMore: false, isLoading: false, error: null });
  });

  it("keeps current history intact when older-history loading fails", async () => {
    const readHistoryPage = vi.fn().mockRejectedValueOnce(new Error("relay unavailable"));
    const base = withDetail();
    useRemoteSessionsStore.setState({
      instances: { i1: base },
      clients: { i1: { readHistoryPage } as never },
    });

    await useRemoteSessionsStore.getState().loadOlderHistory("i1", sessionId);

    const detail = useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId];
    expect(detail.history).toEqual(base.detailsBySession[sessionId].history);
    expect(detail.paging).toMatchObject({
      oldestSeq: 1,
      hasMore: true,
      isLoading: false,
      error: "relay unavailable",
    });
  });
});
