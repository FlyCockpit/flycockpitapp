import { describe, expect, it, vi } from "vitest";
import { emptyNativeDaemonState } from "./daemon-state";
import {
  appendOptimisticUserMessage,
  type NativeSessionEventState,
  nativeAttachRuntimeState,
  reconcileRecordedUserMessage,
  reduceNativeSessionEvent,
  removeOptimisticUserMessage,
  resolveResponseForInterrupt,
  warnNativeSessionEvent,
} from "./session-events";

const sessionId = "11111111-1111-4111-8111-111111111111";
const interruptId = "22222222-2222-4222-8222-222222222222";

const initialState: NativeSessionEventState = {
  selectedSessionId: sessionId,
  history: [],
};

describe("native session event helpers", () => {
  it("drops unknown events with exactly one warning", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const result = reduceNativeSessionEvent(initialState, {
      v: 1,
      kind: "evt",
      event: "future_native_event",
      data: { session_id: sessionId },
    });

    expect(result.state).toBe(initialState);
    expect(result.warning).toBe("[native-remote] unknown event: future_native_event");
    warnNativeSessionEvent(result);
    expect(warn).toHaveBeenCalledExactlyOnceWith(
      "[native-remote] unknown event: future_native_event",
    );
    warn.mockRestore();
  });

  it("drops known unhandled events without a warning", () => {
    const result = reduceNativeSessionEvent(initialState, {
      v: 1,
      kind: "evt",
      event: "usage",
      data: {
        session_id: sessionId,
        agent: "Build",
        input_tokens: 1,
        output_tokens: 2,
        cached_input_tokens: 0,
        cache_creation_input_tokens: 0,
      },
    });

    expect(result.state).toBe(initialState);
    expect(result.warning).toBeUndefined();
  });

  it("drops malformed known handled events with one warning", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const result = reduceNativeSessionEvent(initialState, {
      v: 1,
      kind: "evt",
      event: "assistant_text_delta",
      data: { session_id: sessionId },
    });

    expect(result.state).toBe(initialState);
    expect(result.warning).toBe("[native-remote] unknown event: assistant_text_delta");
    warnNativeSessionEvent(result);
    expect(warn).toHaveBeenCalledExactlyOnceWith(
      "[native-remote] unknown event: assistant_text_delta",
    );
    warn.mockRestore();
  });

  it("applies handled history replay events", () => {
    const result = reduceNativeSessionEvent(initialState, {
      v: 1,
      kind: "evt",
      event: "history_replay",
      data: {
        session_id: sessionId,
        max_seq: 7,
        entries: [{ role: "user", seq: 7, text: "hello", ts_ms: 1700000000000 }],
      },
    });

    expect(result.warning).toBeUndefined();
    expect(result.state.history).toEqual([
      { id: "user:7", kind: "user_message", seq: 7, text: "hello" },
    ]);
  });

  it("turns live inference failures into structured transcript surfaces", () => {
    const result = reduceNativeSessionEvent(initialState, {
      v: 1,
      kind: "evt",
      event: "inference_failed",
      data: {
        session_id: sessionId,
        agent: "Build",
        provider: "openai",
        model: "gpt-5",
        error_class: "auth",
        detail: "bad token",
        auth_failure: { kind: "credentials_rejected", status: 401 },
      },
    });

    expect(result.state.history).toEqual([
      {
        id: "inference:1",
        kind: "inference_error",
        seq: 1,
        view: expect.objectContaining({
          headline: "openai gpt-5 failed",
          errorClass: "auth",
          recovery: expect.objectContaining({
            kind: "reauthenticate",
            label: "Credentials rejected (HTTP 401)",
            action: "reauthenticate",
          }),
        }),
      },
    ]);
  });

  it("hydrates attach-time active model and paused work state", () => {
    const runtime = nativeAttachRuntimeState(
      {
        session_id: sessionId,
        short_id: "s1",
        project_root: "/work/app",
        project_id: "project_1",
        active_agent: "Build",
        history: [],
        active_model_state: {
          provider: "openai",
          model: "gpt-4o",
          config_provider: "openai",
          config_model: "gpt-5",
          diverged: true,
          generation: 4,
        },
        paused_work: [{ session_id: sessionId, reason: "daemon_shutdown" }],
      } as never,
      {
        ...emptyNativeDaemonState,
        draining: { forced: false, copy: "Daemon draining" },
        sandboxNotice: { remedy: "Start Docker", fixCommand: "open -a Docker" },
        waitingForLock: { path: "/work/app", holderAgent: "Build" },
      },
    );

    expect(runtime.activeModel).toMatchObject({
      provider: "openai",
      model: "gpt-4o",
      configProvider: "openai",
      configModel: "gpt-5",
      diverged: true,
      generation: 4,
    });
    expect(runtime.daemonState.pausedWork).toEqual({
      sessionId,
      items: [{ session_id: sessionId, reason: "daemon_shutdown" }],
    });
    expect(runtime.daemonState.draining).toEqual({ forced: false, copy: "Daemon draining" });
    expect(runtime.daemonState.sandboxNotice).toEqual({
      remedy: "Start Docker",
      fixCommand: "open -a Docker",
    });
    expect(runtime.daemonState.waitingForLock).toEqual({
      path: "/work/app",
      holderAgent: "Build",
    });
  });

  it("streams assistant deltas into a pending row and replaces it with final text", () => {
    const delta = reduceNativeSessionEvent(initialState, {
      v: 1,
      kind: "evt",
      event: "assistant_text_delta",
      data: { session_id: sessionId, agent: "Build", delta: "hel" },
    });

    expect(delta.state.history).toEqual([
      {
        id: "assistant:pending",
        kind: "assistant_text",
        seq: Number.MAX_SAFE_INTEGER - 1,
        text: "hel",
      },
    ]);

    const nextDelta = reduceNativeSessionEvent(delta.state, {
      v: 1,
      kind: "evt",
      event: "assistant_text_delta",
      data: { session_id: sessionId, agent: "Build", delta: "lo" },
    });
    expect(nextDelta.state.history[0]).toMatchObject({ text: "hello" });

    const final = reduceNativeSessionEvent(nextDelta.state, {
      v: 1,
      kind: "evt",
      event: "assistant_text",
      data: {
        session_id: sessionId,
        agent: "Build",
        text: "hello!",
        reasoning: "done",
        seq: 8,
      },
    });

    expect(final.state.history).toEqual([
      { id: "assistant:8", kind: "assistant_text", seq: 8, text: "hello!" },
    ]);

    const fallbackFinal = reduceNativeSessionEvent(
      {
        selectedSessionId: sessionId,
        history: [
          { id: "assistant:4", kind: "assistant_text", seq: 4, text: "old" },
          ...appendOptimisticUserMessage(delta.state.history, "pending user", "9"),
        ],
      },
      {
        v: 1,
        kind: "evt",
        event: "assistant_text",
        data: { session_id: sessionId, agent: "Build", text: "fallback seq" },
      },
    );
    expect(fallbackFinal.state.history.find((entry) => entry.id === "assistant:5")).toEqual({
      id: "assistant:5",
      kind: "assistant_text",
      seq: 5,
      text: "fallback seq",
    });
  });

  it("keeps optimistic user messages visible and reconciles recorded seqs", () => {
    const optimistic = appendOptimisticUserMessage([], "run tests", "1");

    expect(optimistic).toEqual([
      {
        id: "user:pending:1",
        kind: "user_message",
        seq: Number.MAX_SAFE_INTEGER - 2,
        text: "run tests",
      },
    ]);

    expect(reconcileRecordedUserMessage(optimistic, { seq: 9 })).toEqual([
      { id: "user:9", kind: "user_message", seq: 9, text: "run tests" },
    ]);
    expect(
      reconcileRecordedUserMessage([], { seq: 10, preflight_cleaned: "cleaned text" }),
    ).toEqual([{ id: "user:10", kind: "user_message", seq: 10, text: "cleaned text" }]);
    expect(
      reconcileRecordedUserMessage(
        [
          { id: "assistant:4", kind: "assistant_text", seq: 4, text: "old" },
          ...appendOptimisticUserMessage([], "pending", "2"),
        ],
        {},
      ),
    ).toEqual([
      { id: "assistant:4", kind: "assistant_text", seq: 4, text: "old" },
      { id: "user:5", kind: "user_message", seq: 5, text: "pending" },
    ]);

    expect(
      removeOptimisticUserMessage(
        [
          ...optimistic,
          { id: "assistant:11", kind: "assistant_text", seq: 11, text: "still here" },
        ],
        "1",
      ),
    ).toEqual([{ id: "assistant:11", kind: "assistant_text", seq: 11, text: "still here" }]);
  });

  it("maps minimal interrupt answers to ResolveResponse variants", () => {
    expect(
      resolveResponseForInterrupt(
        {
          kind: "single",
          data: {
            prompt: "Approve?",
            options: [{ id: "approve_once", label: "Approve once" }],
            permission: true,
          },
        },
        "approve",
        "",
      ),
    ).toEqual({ kind: "single", data: { selected_id: "approve_once" } });

    expect(
      resolveResponseForInterrupt(
        { kind: "freetext", data: { prompt: "Why?" } },
        "answer",
        "because",
      ),
    ).toEqual({ kind: "freetext", data: { text: "because" } });

    expect(
      resolveResponseForInterrupt(
        {
          kind: "single",
          data: {
            prompt: "Approve?",
            options: [{ id: "approve_once", label: "Approve once" }],
          },
        },
        "deny",
        "",
      ),
    ).toEqual({ kind: "cancel" });
  });

  it("adds and resolves interrupt events", () => {
    const raised = reduceNativeSessionEvent(initialState, {
      v: 1,
      kind: "evt",
      event: "interrupt_raised",
      data: {
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
      },
    });

    expect(raised.state.history).toHaveLength(1);
    expect(raised.state.history[0]).toMatchObject({
      kind: "interrupt",
      interrupt: { interruptId, resolved: false },
    });

    const resolved = reduceNativeSessionEvent(raised.state, {
      v: 1,
      kind: "evt",
      event: "interrupt_resolved",
      data: { session_id: sessionId, interrupt_id: interruptId },
    });
    expect(resolved.state.history[0]).toMatchObject({
      kind: "interrupt",
      interrupt: { interruptId, resolved: true },
    });
  });
});
