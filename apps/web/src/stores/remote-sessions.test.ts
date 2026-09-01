import { type HistoryPageResult, PROTOCOL_VERSION } from "@flycockpit/cockpit-protocol";
import { RemoteSessionError } from "@flycockpit/cockpit-protocol/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  addOptimisticUserMessage,
  applyLiveEvent,
  applyRemoteSessionClientEvent,
  interruptDecisionView,
  isCurrentWebComposerAttempt,
  isWebAttachmentReady,
  matchingWebComposerRetryForSession,
  mergeAttach,
  mergeHistoryPage,
  reduceRemoteSessionEvent,
  resetRemoteSessionEventWarningsForTests,
  updateSessionSharedWithCollaborators,
  useRemoteSessionsStore,
  WebSessionCreatedWithSetupError,
  type WebSessionSummary,
  warnUnhandledRemoteSessionEvent,
  webAttachmentAfterConnectionStatus,
} from "./remote-sessions";

const sessionId = "11111111-1111-4111-8111-111111111111";
const interruptId = "22222222-2222-4222-8222-222222222222";

afterEach(() => vi.restoreAllMocks());

const empty = {
  status: "connected" as const,
  attachment: {
    connectionEpoch: 1,
    phase: "applied" as const,
    sessionId,
  },
  projects: [],
  sessionsByProject: {},
  detailsBySession: {},
  statsRollupByProject: {},
};

const attachFixture = {
  session_id: sessionId,
  session_entry_mode: "assistant" as const,
  short_id: "s1",
  project_root: "/work/app",
  project_id: "project_1",
  active_agent: "Build",
  paused_work: [],
  daemon_version: "0.1.0",
  compatible: true,
  env_policy_applied: "daemon" as const,
  history: [
    { role: "assistant" as const, seq: 2, agent: "Build", text: "I will inspect." },
    { role: "user" as const, seq: 1, text: "Please fix checkout" },
  ],
};

function withDetail() {
  return mergeAttach(empty, attachFixture);
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function withAttachment(
  state: ReturnType<typeof withDetail>,
  phase: "detached" | "pending" | "applied" | "failed",
  attachedSessionId?: string,
  connectionEpoch = 1,
) {
  return {
    ...state,
    attachment: {
      connectionEpoch,
      phase,
      sessionId: attachedSessionId,
    },
  };
}

function event(event: string, data: Record<string, unknown>) {
  return { v: PROTOCOL_VERSION, kind: "evt", event, data } as const;
}

describe("remote session reducers", () => {
  it("removes durable user rows from live and replayed retractions", () => {
    const live = applyLiveEvent(
      withDetail(),
      event("user_message_removed", {
        session_id: sessionId,
        seq: 1,
        client_submission_ids: [],
      }),
    );
    expect(live.detailsBySession[sessionId].history.map((entry) => entry.id)).toEqual([
      "assistant:2",
    ]);

    const replay = applyLiveEvent(
      withDetail(),
      event("history_replay", {
        session_id: sessionId,
        max_seq: 3,
        removed_user_message_seqs: [1],
        entries: [{ role: "assistant", seq: 2, agent: "Build", text: "I will inspect." }],
      }),
    );
    expect(replay.detailsBySession[sessionId].history.map((entry) => entry.id)).toEqual([
      "assistant:2",
    ]);
  });

  it("scopes an exact retry to its session and restores it after returning", () => {
    const retry = {
      sessionId,
      params: {
        client_submission_id: "44444444-4444-4444-8444-444444444444",
        text: "identical text",
        display_text: "exact payload for session A",
      },
    };
    const otherSessionId = "55555555-5555-4555-8555-555555555555";
    const retriesBySession = { [sessionId]: retry };

    expect(matchingWebComposerRetryForSession(sessionId, retry.params.text, retriesBySession)).toBe(
      retry.params,
    );
    expect(
      matchingWebComposerRetryForSession(otherSessionId, retry.params.text, retriesBySession),
    ).toBeNull();
    expect(matchingWebComposerRetryForSession(sessionId, retry.params.text, retriesBySession)).toBe(
      retry.params,
    );
    expect(
      isCurrentWebComposerAttempt({
        currentSessionId: otherSessionId,
        attemptedSessionId: sessionId,
        latestAttempt: 3,
        attempt: 3,
      }),
    ).toBe(false);
  });

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

  it("seeds authoritative active model state from the attach snapshot", () => {
    const state = mergeAttach(empty, {
      ...attachFixture,
      active_model_state: {
        selection: { provider: "openai", model: "gpt-5" },
        default_selection: { provider: "openai", model: "gpt-5-pro" },
        diverged: true,
        generation: 4,
      },
    });

    expect(state.detailsBySession[sessionId].activeModel).toEqual({
      selection: { provider: "openai", model: "gpt-5" },
      defaultSelection: { provider: "openai", model: "gpt-5-pro" },
      provider: "openai",
      model: "gpt-5",
      configProvider: "openai",
      configModel: "gpt-5-pro",
      diverged: true,
      generation: 4,
    });
    expect(state.detailsBySession[sessionId].summary.model).toBe("openai/gpt-5");
  });

  it("replaces a cached higher generation with the authoritative reconnect snapshot", () => {
    const cached = mergeAttach(empty, {
      ...attachFixture,
      active_model_state: {
        selection: { provider: "cached", model: "old" },
        default_selection: { provider: "cached", model: "default" },
        diverged: true,
        generation: 9,
      },
    });
    const reconnected = mergeAttach(cached, {
      ...attachFixture,
      active_model_state: {
        selection: { provider: "authoritative", model: "current" },
        default_selection: { provider: "authoritative", model: "current" },
        diverged: false,
        generation: 0,
      },
    });

    expect(reconnected.detailsBySession[sessionId].activeModel).toEqual({
      selection: { provider: "authoritative", model: "current" },
      defaultSelection: { provider: "authoritative", model: "current" },
      provider: "authoritative",
      model: "current",
      configProvider: "authoritative",
      configModel: "current",
      diverged: false,
      generation: 0,
    });
    expect(reconnected.detailsBySession[sessionId].summary.model).toBe("authoritative/current");
    expect(reconnected.sessionsByProject["/work/app"][0].model).toBe("authoritative/current");
  });

  it("hydrates paused work from the authoritative attach snapshot", () => {
    const pausedWork = {
      session_id: sessionId,
      active_agent: "Build",
      project_root: "/work/app",
      reason: "daemon_shutdown",
      pending_tool_count: 2,
      daemon_version: "0.1.0",
      updated_at: 42,
    };
    const attached = mergeAttach(empty, {
      ...attachFixture,
      paused_work: [pausedWork],
    });

    expect(attached.detailsBySession[sessionId].pausedWork).toEqual({
      items: [pausedWork],
    });
    expect(attached.detailsBySession[sessionId].summary.attention).toEqual({
      kind: "paused_work",
    });
  });

  it("clears stale paused work when the authoritative attach snapshot is empty", () => {
    const paused = applyLiveEvent(
      withDetail(),
      event("paused_work_available", {
        session_id: sessionId,
        items: [{ id: "stale-work", agent: "Build" }],
      }),
    );
    const reattached = mergeAttach(paused, attachFixture);

    expect(reattached.detailsBySession[sessionId].pausedWork).toBeUndefined();
    expect(reattached.detailsBySession[sessionId].summary.attention).toBeNull();
  });

  it("hydrates repair-required attach state and blocks remote sends", async () => {
    const repairRequired = {
      session_id: sessionId,
      short_id: "s1",
      provider: "anthropic",
      model: "claude",
      wire_api: "messages",
      failure_kind: "missing_tool_result",
      failing_tool_call_ids: ["call-1"],
      safe_last_turn_seq: 4,
      suggested_actions: ["open_read_only" as const],
      detail: "Open this session read-only until it is repaired.",
    };
    const state = mergeAttach(empty, { ...attachFixture, repair_required: repairRequired });
    const sendUserMessage = vi.fn();
    useRemoteSessionsStore.setState({
      instances: { i1: state },
      clients: { i1: { sendUserMessage } as never },
    });

    expect(state.detailsBySession[sessionId].repairRequired).toEqual(repairRequired);
    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionId, "do not send"),
    ).rejects.toThrow(repairRequired.detail);
    expect(sendUserMessage).not.toHaveBeenCalled();
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

  it("uses attach and replay receipts to replace only accepted optimistic rows", () => {
    const attachAccepted = "44444444-4444-4444-8444-444444444444";
    const replayAccepted = "55555555-5555-4555-8555-555555555555";
    const unrelated = "66666666-6666-4666-8666-666666666666";
    let state = addOptimisticUserMessage(withDetail(), sessionId, "attach pending", attachAccepted);
    state = addOptimisticUserMessage(state, sessionId, "replay pending", replayAccepted);
    state = addOptimisticUserMessage(state, sessionId, "still pending", unrelated);

    state = mergeAttach(state, {
      ...attachFixture,
      history: [
        ...attachFixture.history,
        {
          role: "user" as const,
          seq: 3,
          text: "attach accepted",
          client_submission_ids: [attachAccepted],
        },
      ],
    });
    expect(state.detailsBySession[sessionId].history).toContainEqual(
      expect.objectContaining({
        id: "user:3",
        text: "attach accepted",
        clientSubmissionIds: [attachAccepted],
      }),
    );
    expect(state.detailsBySession[sessionId].history).not.toContainEqual(
      expect.objectContaining({ id: `user:pending:${attachAccepted}` }),
    );

    state = applyLiveEvent(
      state,
      event("history_replay", {
        session_id: sessionId,
        max_seq: 4,
        entries: [
          {
            role: "user",
            seq: 4,
            text: "replay accepted",
            client_submission_ids: [replayAccepted],
          },
        ],
      }),
    );
    const ids = state.detailsBySession[sessionId].history.map((entry) => entry.id);
    expect(ids).not.toContain(`user:pending:${replayAccepted}`);
    expect(ids).toContain(`user:pending:${unrelated}`);
    expect(state.detailsBySession[sessionId].history).toContainEqual(
      expect.objectContaining({
        id: "user:4",
        text: "replay accepted",
        clientSubmissionIds: [replayAccepted],
      }),
    );
  });

  it("folds multiple queued optimistic rows into one canonical user row", () => {
    const first = "44444444-4444-4444-8444-444444444444";
    const second = "55555555-5555-4555-8555-555555555555";
    const unrelated = "66666666-6666-4666-8666-666666666666";
    let state = addOptimisticUserMessage(withDetail(), sessionId, "first pending", first);
    state = addOptimisticUserMessage(state, sessionId, "second pending", second);
    state = addOptimisticUserMessage(state, sessionId, "unrelated pending", unrelated);

    state = applyLiveEvent(
      state,
      event("queued_user_messages_folded", {
        session_id: sessionId,
        text: "raw folded text",
        display_text: "display folded text",
        preflight_cleaned: "cleaned folded text",
        tag_expansions: [{ tag: "src", replacement: "source context" }],
        queue_item_ids: [first, second],
        target: { id: "root", agent: "Build", depth: 0 },
        seq: 7,
      }),
    );

    const history = state.detailsBySession[sessionId].history;
    expect(history.filter((entry) => entry.id === "user:7")).toEqual([
      expect.objectContaining({
        id: "user:7",
        seq: 7,
        text: "display folded text",
        clientSubmissionIds: [first, second],
      }),
    ]);
    expect(history.map((entry) => entry.id)).not.toContain(`user:pending:${first}`);
    expect(history.map((entry) => entry.id)).not.toContain(`user:pending:${second}`);
    expect(history.map((entry) => entry.id)).toContain(`user:pending:${unrelated}`);
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

  it("accepts same-generation config corrections and rejects older model state", () => {
    const first = applyLiveEvent(
      withDetail(),
      event("active_model_state", {
        session_id: sessionId,
        selection: { provider: "openai", model: "gpt-5" },
        default_selection: { provider: "openai", model: "gpt-5-pro" },
        diverged: true,
        generation: 7,
      }),
    );
    const stale = applyLiveEvent(
      applyLiveEvent(
        first,
        event("active_model_state", {
          session_id: sessionId,
          selection: {
            provider: "openai",
            model: "gpt-5",
            reasoning_effort: { value: "high" },
            thinking_mode: "high",
            prompt_cache_retention: "extended",
          },
          default_selection: {
            provider: "openai",
            model: "gpt-5",
            reasoning_effort: { value: "high" },
            thinking_mode: "high",
            prompt_cache_retention: "extended",
          },
          diverged: false,
          generation: 7,
        }),
      ),
      event("active_model_state", {
        session_id: sessionId,
        selection: { provider: "anthropic", model: "claude" },
        diverged: false,
        generation: 6,
      }),
    );
    const next = applyLiveEvent(
      stale,
      event("active_model_state", {
        session_id: sessionId,
        selection: { provider: "openai", model: "gpt-5-mini" },
        diverged: false,
        generation: 8,
      }),
    );

    expect(first.detailsBySession[sessionId].activeModel).toMatchObject({
      provider: "openai",
      model: "gpt-5",
      configProvider: "openai",
      configModel: "gpt-5-pro",
      diverged: true,
      generation: 7,
    });
    expect(stale.detailsBySession[sessionId].activeModel).toMatchObject({
      provider: "openai",
      model: "gpt-5",
      configProvider: "openai",
      configModel: "gpt-5",
      diverged: false,
      generation: 7,
    });
    expect(next.detailsBySession[sessionId].activeModel).toMatchObject({
      model: "gpt-5-mini",
      generation: 8,
    });
    expect(next.detailsBySession[sessionId].summary.model).toBe("openai/gpt-5-mini");
    expect(next.sessionsByProject["/work/app"][0].model).toBe("openai/gpt-5-mini");
  });

  it("accepts same-generation terminal corrections to default and divergence state", () => {
    const initial = applyLiveEvent(
      withDetail(),
      event("active_model_state", {
        session_id: sessionId,
        selection: { provider: "openai", model: "gpt-5" },
        default_selection: { provider: "openai", model: "old-default" },
        diverged: true,
        generation: 7,
      }),
    );
    const corrected = applyLiveEvent(
      initial,
      event("model_selection_result", {
        session_id: sessionId,
        selection_id: "33333333-3333-4333-8333-333333333333",
        provider: "openai",
        model: "gpt-5",
        reasoning_effort: "high",
        thinking_mode: "high",
        prompt_cache_retention: "extended",
        outcome: {
          status: "applied",
          active_state: {
            selection: {
              provider: "openai",
              model: "gpt-5",
              reasoning_effort: { value: "high" },
              thinking_mode: "high",
              prompt_cache_retention: "extended",
            },
            default_selection: {
              provider: "openai",
              model: "gpt-5",
              reasoning_effort: { value: "high" },
              thinking_mode: "high",
              prompt_cache_retention: "extended",
            },
            diverged: false,
            generation: 7,
          },
          default_update: {
            status: "verified",
            selection: {
              provider: "openai",
              model: "gpt-5",
              reasoning_effort: { value: "high" },
              thinking_mode: "high",
              prompt_cache_retention: "extended",
            },
            generation: 7,
            scope_label: "user",
            unchanged: false,
          },
        },
      }),
    );

    expect(corrected.detailsBySession[sessionId].activeModel).toMatchObject({
      provider: "openai",
      model: "gpt-5",
      configProvider: "openai",
      configModel: "gpt-5",
      diverged: false,
      generation: 7,
    });
    expect(corrected.detailsBySession[sessionId].activeModel?.selection).toEqual({
      provider: "openai",
      model: "gpt-5",
      reasoning_effort: { value: "high" },
      thinking_mode: "high",
      prompt_cache_retention: "extended",
    });
    expect(corrected.detailsBySession[sessionId].summary.model).toBe("openai/gpt-5");
    expect(corrected.sessionsByProject["/work/app"][0].model).toBe("openai/gpt-5");
  });

  it("does not invent active state from a rejected model-selection result", () => {
    const state = applyLiveEvent(
      withDetail(),
      event("model_selection_result", {
        session_id: sessionId,
        selection_id: "33333333-3333-4333-8333-333333333333",
        provider: "openai",
        model: "gpt-5",
        outcome: {
          status: "rejected",
          user_message: "Model selection was rejected.",
          diagnostic_code: "model_switch_rejected",
        },
      }),
    );

    expect(state.detailsBySession[sessionId].activeModel).toBeUndefined();
    expect(state.detailsBySession[sessionId].summary.model).toBeUndefined();
  });

  it("tracks inference failures", () => {
    const withFailure = applyLiveEvent(
      withDetail(),
      event("inference_failed", {
        session_id: sessionId,
        agent: "Build",
        provider: "openai",
        model: "gpt-5",
        error_class: { kind: "http", status: 401 },
        detail: "provider rejected credentials",
        auth_failure: { kind: "credentials_rejected", status: 401 },
      }),
    );
    const failure = withFailure.detailsBySession[sessionId].history.at(-1);

    expect(failure).toMatchObject({
      kind: "inference_failure",
      failure: {
        provider: "openai",
        model: "gpt-5",
        errorClass: "http 401",
        recovery: { kind: "credentials_rejected", status: 401 },
      },
    });
  });

  it("keeps sandbox unavailable sticky until sandboxing is disabled", () => {
    const unavailable = applyLiveEvent(
      withDetail(),
      event("sandbox_unavailable", {
        session_id: sessionId,
        remedy: "Enable unprivileged user namespaces.",
        fix_command: "sysctl -w kernel.unprivileged_userns_clone=1",
      }),
    );
    const stillSticky = applyLiveEvent(
      unavailable,
      event("sandbox_state", {
        session_id: sessionId,
        mode: "workspace_write",
        enabled: true,
        container_availability: "available",
      }),
    );
    const cleared = applyLiveEvent(
      stillSticky,
      event("sandbox_state", {
        session_id: sessionId,
        mode: "read_only",
        enabled: false,
        container_availability: "available",
      }),
    );

    expect(unavailable.detailsBySession[sessionId].sandboxUnavailable).toEqual({
      remedy: "Enable unprivileged user namespaces.",
      fixCommand: "sysctl -w kernel.unprivileged_userns_clone=1",
    });
    expect(stillSticky.detailsBySession[sessionId].sandboxUnavailable).toEqual(
      unavailable.detailsBySession[sessionId].sandboxUnavailable,
    );
    expect(cleared.detailsBySession[sessionId].sandboxUnavailable).toBeUndefined();
  });

  it("tracks daemon draining and waiting locks", () => {
    const draining = applyLiveEvent(withDetail(), event("daemon_draining", { forced: false }));
    const forced = applyLiveEvent(draining, event("daemon_draining", { forced: true }));
    const waiting = applyLiveEvent(
      forced,
      event("waiting_for_lock", {
        session_id: sessionId,
        path: "src/main.ts",
        holder_agent: "Review",
        waiting: true,
      }),
    );
    const cleared = applyLiveEvent(
      waiting,
      event("waiting_for_lock", {
        session_id: sessionId,
        path: "src/main.ts",
        holder_agent: "Review",
        waiting: false,
      }),
    );

    expect(draining.draining).toEqual({ forced: false });
    expect(forced.draining).toEqual({ forced: true });
    expect(waiting.detailsBySession[sessionId].waitingLocks).toEqual({
      "src/main.ts": { path: "src/main.ts", holderAgent: "Review" },
    });
    expect(cleared.detailsBySession[sessionId].waitingLocks).toEqual({});
  });

  it("surfaces and clears paused work from daemon events", () => {
    const available = applyLiveEvent(
      withDetail(),
      event("paused_work_available", {
        session_id: sessionId,
        items: [{ id: "work1", agent: "Build" }],
      }),
    );
    const cleared = applyLiveEvent(
      available,
      event("paused_work_available", { session_id: sessionId, items: [] }),
    );

    expect(available.detailsBySession[sessionId].pausedWork?.items).toHaveLength(1);
    expect(available.detailsBySession[sessionId].summary.attention).toEqual({
      kind: "paused_work",
    });
    expect(cleared.detailsBySession[sessionId].pausedWork).toBeUndefined();
    expect(cleared.detailsBySession[sessionId].summary.attention).toBeNull();
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

  it("blocks a cached session throughout the connected-before-attach reconnect gap", async () => {
    resetRemoteSessionEventWarningsForTests();
    const attachResult = deferred<typeof attachFixture>();
    const sendUserMessage = vi.fn().mockResolvedValue(undefined);
    const resumePausedWork = vi.fn().mockResolvedValue(undefined);
    const cancelPausedWork = vi.fn().mockResolvedValue(undefined);
    const resolveInterrupt = vi.fn().mockResolvedValue(undefined);
    const attach = vi.fn().mockReturnValue(attachResult.promise);
    const client = {
      attach,
      cancelPausedWork,
      resolveInterrupt,
      resumePausedWork,
      sendUserMessage,
    };
    useRemoteSessionsStore.setState({
      instances: { i1: withAttachment(withDetail(), "detached", undefined, 9) },
      clients: { i1: client as never },
    });

    expect(isWebAttachmentReady(useRemoteSessionsStore.getState().instances.i1, sessionId)).toBe(
      false,
    );
    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionId, "too early"),
    ).rejects.toThrow("attachment is not ready");
    await expect(
      useRemoteSessionsStore.getState().resumePausedWork("i1", sessionId),
    ).rejects.toThrow("attachment is not ready");
    await expect(
      useRemoteSessionsStore.getState().cancelPausedWork("i1", sessionId),
    ).rejects.toThrow("attachment is not ready");
    await expect(
      useRemoteSessionsStore.getState().resolveInterrupt("i1", {
        sessionId,
        interruptId,
        selection: { kind: "cancel" },
      }),
    ).rejects.toThrow("attachment is not ready");
    expect(sendUserMessage).not.toHaveBeenCalled();
    expect(resumePausedWork).not.toHaveBeenCalled();
    expect(cancelPausedWork).not.toHaveBeenCalled();
    expect(resolveInterrupt).not.toHaveBeenCalled();

    const attaching = useRemoteSessionsStore.getState().attach("i1", sessionId);
    expect(useRemoteSessionsStore.getState().instances.i1.attachment).toEqual({
      connectionEpoch: 9,
      phase: "pending",
      sessionId,
    });
    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionId, "still too early"),
    ).rejects.toThrow("attachment is not ready");

    attachResult.resolve(attachFixture);
    await attaching;
    expect(useRemoteSessionsStore.getState().instances.i1.attachment).toEqual({
      connectionEpoch: 9,
      phase: "applied",
      sessionId,
    });
    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, "now safe");
    expect(sendUserMessage).toHaveBeenCalledTimes(1);
  });

  it("starts a detached generation epoch on reconnect but preserves a live epoch", () => {
    const cached = withAttachment(withDetail(), "applied", sessionId, 9);
    expect(
      webAttachmentAfterConnectionStatus({ ...cached, status: "offline" }, "connected"),
    ).toEqual({
      connectionEpoch: 10,
      phase: "detached",
    });
    expect(webAttachmentAfterConnectionStatus(cached, "connected")).toBe(cached.attachment);
    expect(webAttachmentAfterConnectionStatus(cached, "offline")).toEqual({
      connectionEpoch: 9,
      phase: "detached",
    });
  });

  it("surfaces a failed attach and lets the same selected session retry", async () => {
    resetRemoteSessionEventWarningsForTests();
    const sessionB = "33333333-3333-4333-8333-333333333333";
    const attach = vi
      .fn()
      .mockRejectedValueOnce(new Error("hydration failed"))
      .mockResolvedValueOnce({
        ...attachFixture,
        session_id: sessionB,
        short_id: "s-b",
        history: [],
      });
    const sendUserMessage = vi.fn().mockResolvedValue(undefined);
    const state = mergeAttach(withDetail(), {
      ...attachFixture,
      session_id: sessionB,
      short_id: "s-b",
      history: [],
    });
    useRemoteSessionsStore.setState({
      instances: { i1: state },
      clients: { i1: { attach, sendUserMessage } as never },
    });

    await useRemoteSessionsStore.getState().attach("i1", sessionB);
    expect(useRemoteSessionsStore.getState().instances.i1.attachment).toEqual({
      connectionEpoch: 1,
      phase: "failed",
      sessionId: sessionB,
      error: "hydration failed",
    });
    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionB, "unsafe"),
    ).rejects.toThrow("attachment is not ready");

    await useRemoteSessionsStore.getState().attach("i1", sessionB);
    expect(attach).toHaveBeenCalledTimes(2);
    expect(useRemoteSessionsStore.getState().instances.i1.attachment).toEqual({
      connectionEpoch: 1,
      phase: "applied",
      sessionId: sessionB,
    });
  });

  it("stays pending until exact retained-payload replay completes", async () => {
    resetRemoteSessionEventWarningsForTests();
    const submission = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "@review exact wire text",
      display_text: "visible draft",
      tag_expansions: [{ tag: "review", replacement: "expanded review context" }],
      forced_skill: "review",
    };
    const replay = deferred<void>();
    const sendUserMessage = vi
      .fn()
      .mockRejectedValueOnce(new Error("Request timed out."))
      .mockReturnValueOnce(replay.promise);
    const attach = vi.fn().mockResolvedValue({ ...attachFixture, history: [] });
    const client = { attach, sendUserMessage };
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: client as never },
    });
    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission),
    ).rejects.toThrow("Request timed out.");
    useRemoteSessionsStore.setState((state) => ({
      instances: {
        ...state.instances,
        i1: withAttachment(state.instances.i1, "detached", undefined, 2),
      },
    }));

    const attaching = useRemoteSessionsStore.getState().attach("i1", sessionId);
    await vi.waitFor(() => expect(sendUserMessage).toHaveBeenCalledTimes(2));
    expect(sendUserMessage.mock.calls[1]?.[0]).toBe(submission);
    expect(useRemoteSessionsStore.getState().instances.i1.attachment.phase).toBe("pending");
    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionId, "must wait"),
    ).rejects.toThrow("attachment is not ready");
    expect(sendUserMessage).toHaveBeenCalledTimes(2);

    replay.resolve();
    await attaching;
    expect(useRemoteSessionsStore.getState().instances.i1.attachment).toEqual({
      connectionEpoch: 2,
      phase: "applied",
      sessionId,
    });
  });

  it("ignores stale B attach and replay after rapid B then C selection", async () => {
    resetRemoteSessionEventWarningsForTests();
    const sessionB = "33333333-3333-4333-8333-333333333333";
    const sessionC = "44444444-4444-4444-8444-444444444444";
    const retained = {
      client_submission_id: "55555555-5555-4555-8555-555555555555",
      text: "@review B wire payload",
      display_text: "B visible draft",
      tag_expansions: [{ tag: "review", replacement: "B exact expansion" }],
      forced_skill: "review",
    };
    const bResult = deferred<typeof attachFixture>();
    const cResult = deferred<typeof attachFixture>();
    const sendUserMessage = vi
      .fn()
      .mockRejectedValueOnce(new Error("Request timed out."))
      .mockResolvedValue(undefined);
    const attach = vi.fn((input: { session_id?: string }) =>
      input.session_id === sessionB ? bResult.promise : cResult.promise,
    );
    let state = mergeAttach(withDetail(), {
      ...attachFixture,
      session_id: sessionB,
      short_id: "s-b",
      history: [],
    });
    state = mergeAttach(state, {
      ...attachFixture,
      session_id: sessionC,
      short_id: "s-c",
      history: [],
    });
    state = withAttachment(state, "applied", sessionB);
    const client = { attach, sendUserMessage };
    useRemoteSessionsStore.setState({
      instances: { i1: state },
      clients: { i1: client as never },
    });
    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionB, retained),
    ).rejects.toThrow("Request timed out.");

    const attachB = useRemoteSessionsStore.getState().attach("i1", sessionB);
    const attachC = useRemoteSessionsStore.getState().attach("i1", sessionC);
    cResult.resolve({
      ...attachFixture,
      session_id: sessionC,
      short_id: "s-c",
      history: [],
    });
    await attachC;
    bResult.resolve({
      ...attachFixture,
      session_id: sessionB,
      short_id: "s-b",
      history: [],
    });
    await attachB;

    expect(useRemoteSessionsStore.getState().instances.i1.attachment).toEqual({
      connectionEpoch: 1,
      phase: "applied",
      sessionId: sessionC,
    });
    expect(sendUserMessage).toHaveBeenCalledTimes(1);

    await useRemoteSessionsStore.getState().attach("i1", sessionB);
    expect(sendUserMessage).toHaveBeenNthCalledWith(2, retained);
    expect(sendUserMessage.mock.calls[1]?.[0]).toBe(retained);
    expect(useRemoteSessionsStore.getState().instances.i1.attachment.sessionId).toBe(sessionB);
  });

  it("does not let a superseded create response issue controls against a newer attachment", async () => {
    resetRemoteSessionEventWarningsForTests();
    const createdSession = "33333333-3333-4333-8333-333333333333";
    const selectedSession = "44444444-4444-4444-8444-444444444444";
    const createResult = deferred<typeof attachFixture>();
    const selectedResult = deferred<typeof attachFixture>();
    const attach = vi.fn((input: Record<string, unknown>) =>
      "project_root" in input ? createResult.promise : selectedResult.promise,
    );
    const setAgent = vi.fn().mockResolvedValue(undefined);
    const renameSession = vi.fn().mockResolvedValue(undefined);
    const client = { attach, renameSession, setAgent };
    const initial = withDetail();
    useRemoteSessionsStore.setState({
      instances: {
        i1: {
          ...initial,
          sessionsByProject: {
            "/work/app": [
              initial.detailsBySession[sessionId].summary,
              {
                ...initial.detailsBySession[sessionId].summary,
                sessionId: selectedSession,
              },
            ],
          },
        },
      },
      clients: { i1: client as never },
    });

    const creating = useRemoteSessionsStore.getState().createSession("i1", {
      projectRoot: "/work/app",
      title: "Created title",
      agent: "Review",
    });
    const selecting = useRemoteSessionsStore.getState().attach("i1", selectedSession);
    selectedResult.resolve({
      ...attachFixture,
      session_id: selectedSession,
      short_id: "selected",
      history: [],
    });
    await selecting;
    createResult.resolve({
      ...attachFixture,
      session_id: createdSession,
      short_id: "created",
      history: [],
    });

    await expect(creating).rejects.toThrow("superseded");
    expect(setAgent).not.toHaveBeenCalled();
    expect(renameSession).not.toHaveBeenCalled();
    expect(useRemoteSessionsStore.getState().instances.i1.attachment).toEqual({
      connectionEpoch: 1,
      phase: "applied",
      sessionId: selectedSession,
    });
  });

  it("keeps a successfully created session authoritative when optional setup fails", async () => {
    resetRemoteSessionEventWarningsForTests();
    const createdSession = "33333333-3333-4333-8333-333333333333";
    const attach = vi.fn().mockResolvedValue({
      ...attachFixture,
      session_id: createdSession,
      short_id: "created",
      history: [],
    });
    const setAgent = vi.fn().mockRejectedValue(new Error("agent rejected"));
    const renameSession = vi.fn().mockResolvedValue(undefined);
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { attach, renameSession, setAgent } as never },
    });

    const creating = useRemoteSessionsStore.getState().createSession("i1", {
      projectRoot: "/work/app",
      title: "Created title",
      agent: "Review",
    });

    await expect(creating).rejects.toBeInstanceOf(WebSessionCreatedWithSetupError);
    await expect(creating).rejects.toMatchObject({
      session: { summary: { sessionId: createdSession } },
    });
    expect(renameSession).not.toHaveBeenCalled();
    expect(useRemoteSessionsStore.getState().instances.i1.attachment).toEqual({
      connectionEpoch: 1,
      phase: "applied",
      sessionId: createdSession,
    });
  });

  it("reattaches the previous session when the create attach fails", async () => {
    resetRemoteSessionEventWarningsForTests();
    const attach = vi
      .fn()
      .mockRejectedValueOnce(new Error("create attach failed"))
      .mockResolvedValueOnce(attachFixture);
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { attach } as never },
    });

    await expect(
      useRemoteSessionsStore.getState().createSession("i1", {
        projectRoot: "/work/new-project",
      }),
    ).rejects.toThrow("create attach failed");

    expect(attach).toHaveBeenNthCalledWith(1, {
      project_root: "/work/new-project",
      interactive: true,
      session_entry_mode: "assistant",
      initial_model: undefined,
    });
    expect(attach).toHaveBeenNthCalledWith(2, {
      session_id: sessionId,
      interactive: true,
      session_entry_mode: "assistant",
    });
    expect(useRemoteSessionsStore.getState().instances.i1.attachment).toEqual({
      connectionEpoch: 1,
      phase: "applied",
      sessionId,
    });
  });

  it("retains and resends the exact complete submission after ambiguous transport loss", async () => {
    resetRemoteSessionEventWarningsForTests();
    const submission = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "@review inspect this",
      display_text: "inspect this",
      tag_expansions: [{ tag: "review", replacement: "review the patch" }],
      forced_skill: "review",
    };
    const sendUserMessage = vi
      .fn()
      .mockRejectedValueOnce(new Error("Request timed out."))
      .mockResolvedValueOnce(undefined);
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { sendUserMessage } as never },
    });

    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission),
    ).rejects.toThrow("Request timed out.");
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].history,
    ).toContainEqual(
      expect.objectContaining({
        id: `user:pending:${submission.client_submission_id}`,
        text: submission.display_text,
      }),
    );
    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission);

    expect(sendUserMessage).toHaveBeenNthCalledWith(1, submission);
    expect(sendUserMessage).toHaveBeenNthCalledWith(2, submission);
    expect(
      useRemoteSessionsStore
        .getState()
        .instances.i1.detailsBySession[sessionId].history.filter(
          (entry) => entry.id === `user:pending:${submission.client_submission_id}`,
        ),
    ).toEqual([
      expect.objectContaining({
        id: `user:pending:${submission.client_submission_id}`,
        text: submission.display_text,
      }),
    ]);
  });

  it("gives a deliberate same-text web submission a fresh UUID after a queue ACK", async () => {
    resetRemoteSessionEventWarningsForTests();
    const queued = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "repeat exactly",
    };
    const nextId = "55555555-5555-4555-8555-555555555555";
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(nextId);
    const sendUserMessage = vi.fn().mockResolvedValue(undefined);
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { sendUserMessage } as never },
    });

    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, queued);
    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, queued.text);

    expect(sendUserMessage).toHaveBeenNthCalledWith(1, queued);
    expect(sendUserMessage).toHaveBeenNthCalledWith(2, {
      client_submission_id: nextId,
      text: queued.text,
    });
  });

  it("replays a queue-ACKed exact submission after attach until history carries its receipt", async () => {
    resetRemoteSessionEventWarningsForTests();
    const submission = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "@review exact wire text",
      display_text: "visible draft",
      tag_expansions: [{ tag: "review", replacement: "expanded review context" }],
      forced_skill: "review",
    };
    const sendUserMessage = vi.fn().mockResolvedValue(undefined);
    const attach = vi
      .fn()
      .mockResolvedValueOnce({ ...attachFixture, history: [] })
      .mockResolvedValueOnce({
        ...attachFixture,
        history: [
          {
            role: "user" as const,
            seq: 9,
            text: submission.text,
            display_text: submission.display_text,
            client_submission_ids: [submission.client_submission_id],
          },
        ],
      });
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { sendUserMessage, attach } as never },
    });

    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission);
    await useRemoteSessionsStore.getState().attach("i1", sessionId);

    expect(sendUserMessage).toHaveBeenNthCalledWith(1, submission);
    expect(sendUserMessage).toHaveBeenNthCalledWith(2, submission);
    expect(sendUserMessage.mock.calls[1]?.[0]).toBe(submission);

    await useRemoteSessionsStore.getState().attach("i1", sessionId);
    expect(sendUserMessage).toHaveBeenCalledTimes(2);
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].history,
    ).toContainEqual(
      expect.objectContaining({
        id: "user:9",
        text: submission.display_text,
        clientSubmissionIds: [submission.client_submission_id],
      }),
    );
  });

  it("retires a terminal submission UUID during reconnect replay", async () => {
    resetRemoteSessionEventWarningsForTests();
    const terminalId = "44444444-4444-4444-8444-444444444444";
    const nextId = "66666666-6666-4666-8666-666666666666";
    const submission = {
      client_submission_id: terminalId,
      text: "do not resurrect",
      display_text: "do not resurrect",
    };
    const sendUserMessage = vi
      .fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(
        new RemoteSessionError("removed", "user_message_terminated", {
          code: "user_message_terminated",
        }),
      )
      .mockResolvedValueOnce(undefined);
    const attach = vi.fn().mockResolvedValue({ ...attachFixture, history: [] });
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(nextId);
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { sendUserMessage, attach } as never },
    });

    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission);
    await useRemoteSessionsStore.getState().attach("i1", sessionId);
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].history,
    ).not.toContainEqual(expect.objectContaining({ id: "user:pending:" + terminalId }));

    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission.text);
    expect(sendUserMessage.mock.calls[2]?.[0]).toMatchObject({
      client_submission_id: nextId,
      text: submission.text,
    });
  });

  it("retires a connected terminal event so reconnect neither ghosts nor replays it", async () => {
    resetRemoteSessionEventWarningsForTests();
    const submission = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "blocked exact wire text",
      display_text: "blocked draft",
    };
    const sendUserMessage = vi.fn().mockResolvedValue(undefined);
    const attach = vi.fn().mockResolvedValue({ ...attachFixture, history: [] });
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { sendUserMessage, attach } as never },
    });
    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission);

    const current = useRemoteSessionsStore.getState().instances.i1;
    useRemoteSessionsStore.setState((state) => ({
      ...state,
      instances: {
        ...state.instances,
        i1: applyRemoteSessionClientEvent(
          "i1",
          current,
          event("user_messages_terminated", {
            session_id: sessionId,
            client_submission_ids: [submission.client_submission_id],
            disposition: "preflight_rejected",
          }),
        ),
      },
    }));
    await useRemoteSessionsStore.getState().attach("i1", sessionId);

    expect(sendUserMessage).toHaveBeenCalledTimes(1);
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].history,
    ).not.toContainEqual(
      expect.objectContaining({ id: `user:pending:${submission.client_submission_id}` }),
    );
  });

  it("keeps an exact rich retry across activity in another session", async () => {
    resetRemoteSessionEventWarningsForTests();
    const otherSessionId = "66666666-6666-4666-8666-666666666666";
    const submission = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "@review inspect this",
      display_text: "inspect this",
      tag_expansions: [{ tag: "review", replacement: "review the patch" }],
      forced_skill: "review",
    };
    const sendUserMessage = vi
      .fn()
      .mockRejectedValueOnce(new Error("Request timed out."))
      .mockResolvedValue(undefined);
    const attach = vi.fn((input: { session_id?: string }) =>
      Promise.resolve({
        ...attachFixture,
        session_id: input.session_id ?? sessionId,
        short_id: input.session_id === otherSessionId ? "s2" : "s1",
        history: [],
      }),
    );
    const state = mergeAttach(withDetail(), {
      ...attachFixture,
      session_id: otherSessionId,
      short_id: "s2",
      history: [],
    });
    useRemoteSessionsStore.setState({
      instances: { i1: state },
      clients: { i1: { attach, sendUserMessage } as never },
    });

    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission),
    ).rejects.toThrow("Request timed out.");
    await useRemoteSessionsStore.getState().attach("i1", otherSessionId);
    await useRemoteSessionsStore.getState().sendMessage("i1", otherSessionId, "other session");
    await useRemoteSessionsStore.getState().attach("i1", sessionId);

    expect(sendUserMessage).toHaveBeenNthCalledWith(1, submission);
    expect(sendUserMessage.mock.calls[1]?.[0]).toMatchObject({ text: "other session" });
    expect(sendUserMessage).toHaveBeenNthCalledWith(3, submission);
    expect(sendUserMessage.mock.calls[2]?.[0]).toBe(submission);
  });

  it("treats an attach receipt as authoritative when an ambiguous send fails later", async () => {
    resetRemoteSessionEventWarningsForTests();
    const acceptedId = "44444444-4444-4444-8444-444444444444";
    let rejectSend: ((error: Error) => void) | undefined;
    const sendUserMessage = vi.fn(
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectSend = reject;
        }),
    );
    const attach = vi.fn().mockResolvedValue({
      ...attachFixture,
      history: [
        ...attachFixture.history,
        {
          role: "user" as const,
          seq: 9,
          text: "durably accepted",
          client_submission_ids: [acceptedId],
        },
      ],
    });
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { sendUserMessage, attach } as never },
    });

    const sending = useRemoteSessionsStore.getState().sendMessage("i1", sessionId, {
      client_submission_id: acceptedId,
      text: "durably accepted",
      display_text: "durably accepted",
    });
    await vi.waitFor(() => expect(sendUserMessage).toHaveBeenCalledTimes(1));
    await useRemoteSessionsStore.getState().attach("i1", sessionId);
    rejectSend?.(new Error("Request timed out."));

    await expect(sending).resolves.toBeUndefined();
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].history,
    ).toContainEqual(
      expect.objectContaining({
        id: "user:9",
        text: "durably accepted",
        clientSubmissionIds: [acceptedId],
      }),
    );
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].history,
    ).not.toContainEqual(expect.objectContaining({ id: `user:pending:${acceptedId}` }));
  });

  it("keeps concurrent retained submissions independent by client id", async () => {
    resetRemoteSessionEventWarningsForTests();
    const first = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "first",
      display_text: "first exact",
    };
    const second = {
      client_submission_id: "55555555-5555-4555-8555-555555555555",
      text: "second",
      display_text: "second exact",
    };
    let rejectFirst: ((error: Error) => void) | undefined;
    let resolveSecond: (() => void) | undefined;
    const sendUserMessage = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise((_resolve, reject) => {
            rejectFirst = reject;
          }),
      )
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveSecond = () => resolve(undefined);
          }),
      )
      .mockResolvedValue(undefined);
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { sendUserMessage } as never },
    });

    const firstSend = useRemoteSessionsStore.getState().sendMessage("i1", sessionId, first);
    const secondSend = useRemoteSessionsStore.getState().sendMessage("i1", sessionId, second);
    rejectFirst?.(new Error("transport lost"));
    resolveSecond?.();
    await expect(firstSend).rejects.toThrow("transport lost");
    await expect(secondSend).resolves.toBeUndefined();

    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, first);
    expect(sendUserMessage).toHaveBeenNthCalledWith(3, first);
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].history,
    ).toContainEqual(expect.objectContaining({ id: `user:pending:${first.client_submission_id}` }));
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].history,
    ).toContainEqual(
      expect.objectContaining({ id: `user:pending:${second.client_submission_id}` }),
    );
  });

  it("preserves every optimistic row when one exact durable persistence fails", () => {
    const firstId = "44444444-4444-4444-8444-444444444444";
    const secondId = "55555555-5555-4555-8555-555555555555";
    const base = withDetail();
    const history = [
      {
        id: `user:pending:${firstId}`,
        seq: Number.MAX_SAFE_INTEGER - 2,
        kind: "user_message" as const,
        text: "first",
        actor: { origin: "web" as const },
      },
      {
        id: `user:pending:${secondId}`,
        seq: Number.MAX_SAFE_INTEGER - 2,
        kind: "user_message" as const,
        text: "second",
        actor: { origin: "web" as const },
      },
    ];
    const state = {
      ...base,
      detailsBySession: {
        ...base.detailsBySession,
        [sessionId]: { ...base.detailsBySession[sessionId], history },
      },
    };

    const result = applyLiveEvent(
      state,
      event("session_persist_failed", {
        session_id: sessionId,
        client_submission_id: firstId,
        error: "disk full",
      }),
    );

    expect(result).toBe(state);
    expect(result.detailsBySession[sessionId].history).toBe(history);
  });

  it.each([
    "internal",
    "shutdown",
  ])("retains one optimistic row and the exact complete submission after typed %s ambiguity", async (code) => {
    resetRemoteSessionEventWarningsForTests();
    const submission = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "@review inspect this",
      display_text: "inspect this",
      tag_expansions: [{ tag: "review", replacement: "review the patch" }],
      forced_skill: "review",
    };
    const sendUserMessage = vi
      .fn()
      .mockRejectedValueOnce(new RemoteSessionError("acceptance uncertain", code, { code }))
      .mockResolvedValueOnce(undefined);
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { sendUserMessage } as never },
    });

    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission),
    ).rejects.toMatchObject({ code });
    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, submission);

    expect(sendUserMessage).toHaveBeenNthCalledWith(1, submission);
    expect(sendUserMessage).toHaveBeenNthCalledWith(2, submission);
    expect(sendUserMessage.mock.calls[1]?.[0]).toBe(submission);
    expect(
      useRemoteSessionsStore
        .getState()
        .instances.i1.detailsBySession[sessionId].history.filter(
          (entry) => entry.id === `user:pending:${submission.client_submission_id}`,
        ),
    ).toEqual([
      expect.objectContaining({
        id: `user:pending:${submission.client_submission_id}`,
        text: submission.display_text,
      }),
    ]);
  });

  it("removes a rejected optimistic row and gives the next submission a new identity", async () => {
    resetRemoteSessionEventWarningsForTests();
    const newSubmissionId = "66666666-6666-4666-8666-666666666666";
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(newSubmissionId);
    const rejectedSubmission = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "run tests",
    };
    const sendUserMessage = vi
      .fn()
      .mockRejectedValueOnce(new RemoteSessionError("busy", "busy", { code: "busy" }))
      .mockResolvedValueOnce(undefined);
    useRemoteSessionsStore.setState({
      instances: { i1: withDetail() },
      clients: { i1: { sendUserMessage } as never },
    });

    await expect(
      useRemoteSessionsStore.getState().sendMessage("i1", sessionId, rejectedSubmission),
    ).rejects.toBeInstanceOf(RemoteSessionError);
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].history,
    ).not.toContainEqual(
      expect.objectContaining({ id: `user:pending:${rejectedSubmission.client_submission_id}` }),
    );

    await useRemoteSessionsStore.getState().sendMessage("i1", sessionId, rejectedSubmission.text);
    expect(sendUserMessage).toHaveBeenLastCalledWith({
      client_submission_id: newSubmissionId,
      text: rejectedSubmission.text,
    });
  });

  it("sends paused-work actions without optimistically clearing daemon state", async () => {
    const base = applyLiveEvent(
      withDetail(),
      event("paused_work_available", {
        session_id: sessionId,
        items: [{ id: "work1", agent: "Build" }],
      }),
    );
    const resumePausedWork = vi.fn().mockResolvedValue(undefined);
    const cancelPausedWork = vi.fn().mockResolvedValue(undefined);
    useRemoteSessionsStore.setState({
      instances: { i1: base },
      clients: { i1: { resumePausedWork, cancelPausedWork } as never },
    });

    await useRemoteSessionsStore.getState().resumePausedWork("i1", sessionId);
    await useRemoteSessionsStore.getState().cancelPausedWork("i1", sessionId);

    expect(resumePausedWork).toHaveBeenCalledWith(sessionId);
    expect(cancelPausedWork).toHaveBeenCalledWith(sessionId);
    expect(
      useRemoteSessionsStore.getState().instances.i1.detailsBySession[sessionId].pausedWork?.items,
    ).toHaveLength(1);
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

describe("remote_display_events_v11_web", () => {
  it("remote_display_events_v11_web", () => {
    const base = withDetail();
    const sessionDetail = base.detailsBySession[sessionId];
    expect(sessionDetail).toBeTruthy();

    // Typed display deltas coalesce by attempt_id.
    let state = reduceRemoteSessionEvent(base, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 1, delta: "Hel" },
    }).state;
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 1, delta: "lo" },
    }).state;
    let history = state.detailsBySession[sessionId].history;
    expect(history.some((e) => e.kind === "assistant_text" && e.text === "Hello")).toBe(true);

    // Typed reasoning deltas coalesce within one attempt.
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 1, delta: "Think" },
    }).state;
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 1, delta: "ing" },
    }).state;
    history = state.detailsBySession[sessionId].history;
    expect(history.some((e) => e.kind === "assistant_reasoning" && e.text === "Thinking")).toBe(
      true,
    );

    // Complete uses presentation_text when present and clears attempt-scoped
    // reasoning (optionally finalizing durable reasoning from the payload).
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_complete",
      data: {
        session_id: sessionId,
        attempt_id: 1,
        text: "Bonjour",
        presentation_text: "Hello",
        reasoning: "Thinking",
        seq: 99,
      },
    }).state;
    history = state.detailsBySession[sessionId].history;
    const complete = history.find((e) => e.id === "assistant:99");
    expect(complete?.kind).toBe("assistant_text");
    if (complete?.kind === "assistant_text") expect(complete.text).toBe("Hello");
    expect(history.some((e) => e.id === "reasoning:pending:1")).toBe(false);
    expect(history.some((e) => e.id === "reasoning:99" && e.kind === "assistant_reasoning")).toBe(
      true,
    );

    // Fallback / legacy assistant_text uses presentation_text ?? text.
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_text",
      data: { session_id: sessionId, text: "raw", presentation_text: "shown", seq: 100 },
    }).state;
    history = state.detailsBySession[sessionId].history;
    const shown = history.find((e) => e.id === "assistant:100");
    expect(shown?.kind).toBe("assistant_text");
    if (shown?.kind === "assistant_text") expect(shown.text).toBe("shown");

    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_text",
      data: { session_id: sessionId, text: "legacy only", seq: 101 },
    }).state;
    history = state.detailsBySession[sessionId].history;
    const legacy = history.find((e) => e.id === "assistant:101");
    expect(legacy?.kind).toBe("assistant_text");
    if (legacy?.kind === "assistant_text") expect(legacy.text).toBe("legacy only");

    // Reset removes text and reasoning for the failed attempt; replacement
    // reasoning starts a distinct row.
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 7, delta: "gone" },
    }).state;
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 7, delta: "old reasoning" },
    }).state;
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_attempt_reset",
      data: {
        session_id: sessionId,
        failed_attempt_id: 7,
        replacement_attempt_id: 8,
        reason: "timeout",
      },
    }).state;
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 8, delta: "new reasoning" },
    }).state;
    history = state.detailsBySession[sessionId].history;
    expect(history.some((e) => e.id === "assistant:pending:7")).toBe(false);
    expect(history.some((e) => e.id === "reasoning:pending:7")).toBe(false);
    expect(
      history.some(
        (e) =>
          e.id === "reasoning:pending:8" &&
          e.kind === "assistant_reasoning" &&
          e.text === "new reasoning",
      ),
    ).toBe(true);

    // Fallback complete (no presentation_text) displays text.
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 9, delta: "fb" },
    }).state;
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_complete",
      data: { session_id: sessionId, attempt_id: 9, text: "fallback body", seq: 102 },
    }).state;
    history = state.detailsBySession[sessionId].history;
    const fallback = history.find((e) => e.id === "assistant:102");
    expect(fallback?.kind).toBe("assistant_text");
    if (fallback?.kind === "assistant_text") expect(fallback.text).toBe("fallback body");

    // Error converts provisional to inference_failure without a performance chip.
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 11, delta: "partial" },
    }).state;
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 11, delta: "failed reasoning" },
    }).state;
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_error",
      data: {
        session_id: sessionId,
        attempt_id: 11,
        kind: "failed",
        message: "provider failed",
        presentation_text: "partial",
      },
    }).state;
    history = state.detailsBySession[sessionId].history;
    expect(history.some((e) => e.id === "assistant:pending:11")).toBe(false);
    expect(history.some((e) => e.id === "reasoning:pending:11")).toBe(false);
    expect(history.some((e) => e.kind === "inference_failure")).toBe(true);

    // Complete with seq:None then AssistantText must not duplicate the reply.
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 42, delta: "live" },
    }).state;
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_complete",
      data: {
        session_id: sessionId,
        attempt_id: 42,
        text: "live final",
        // seq omitted — timeline write failure path
      },
    }).state;
    history = state.detailsBySession[sessionId].history;
    expect(
      history.filter((e) => e.kind === "assistant_text" && e.text === "live final"),
    ).toHaveLength(1);
    state = reduceRemoteSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_text",
      data: { session_id: sessionId, text: "live final", seq: 200 },
    }).state;
    history = state.detailsBySession[sessionId].history;
    const liveFinals = history.filter(
      (e) => e.kind === "assistant_text" && e.text === "live final",
    );
    expect(liveFinals).toHaveLength(1);
    expect(liveFinals[0]?.id).toBe("assistant:200");
    expect(history.some((e) => e.id === "assistant:pending:42")).toBe(false);

    // Legacy attach/history entry without presentation_text displays text.
    const legacyAttach = mergeAttach(empty, {
      ...attachFixture,
      history: [
        { role: "assistant" as const, seq: 1, agent: "Build", text: "legacy attach body" },
        {
          role: "assistant" as const,
          seq: 2,
          agent: "Build",
          text: "wire",
          presentation_text: "shown attach",
        },
      ],
    });
    const attachHistory = legacyAttach.detailsBySession[sessionId].history;
    expect(attachHistory.find((e) => e.id === "assistant:1")).toMatchObject({
      kind: "assistant_text",
      text: "legacy attach body",
    });
    expect(attachHistory.find((e) => e.id === "assistant:2")).toMatchObject({
      kind: "assistant_text",
      text: "shown attach",
    });
  });
});
