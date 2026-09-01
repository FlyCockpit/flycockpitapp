import { PROTOCOL_VERSION } from "@flycockpit/cockpit-protocol";
import {
  isAmbiguousUserMessageSendError,
  RemoteSessionError,
  shouldRetainUserMessageSubmission,
} from "@flycockpit/cockpit-protocol/client";
import { describe, expect, it, vi } from "vitest";
import { emptyNativeDaemonState } from "./daemon-state";
import {
  acceptedClientSubmissionIdsFromEvent,
  appendOptimisticUserMessage,
  clearAcceptedRetryDrafts,
  clientSubmissionIdsFromHistory,
  forgetUserMessageSubmission,
  isCurrentUserMessageSubmission,
  type NativeSessionEventState,
  nativeAttachRuntimeState,
  prepareUserMessageSubmission,
  type RetainedUserMessageSubmissions,
  reconcileAcceptedRetrySubmissions,
  reconcileRecordedUserMessage,
  reduceNativeSessionEvent,
  removeOptimisticUserMessage,
  restoreRetainedUserMessagesAfterAttach,
  retainUserMessageSubmission,
  toNativeHistoryEntry,
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
      v: PROTOCOL_VERSION,
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
      v: PROTOCOL_VERSION,
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
      v: PROTOCOL_VERSION,
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
      v: PROTOCOL_VERSION,
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

  it("removes durable user rows from live and replayed retractions", () => {
    const recorded = reduceNativeSessionEvent(initialState, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "history_replay",
      data: {
        session_id: sessionId,
        max_seq: 8,
        entries: [
          { role: "user", seq: 7, text: "retract me", ts_ms: 1700000000000 },
          { role: "assistant", seq: 8, agent: "Build", text: "retained", ts_ms: 1700000000001 },
        ],
      },
    }).state;

    const live = reduceNativeSessionEvent(recorded, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "user_message_removed",
      data: { session_id: sessionId, seq: 7, client_submission_ids: [] },
    });
    expect(live.state.history.map((entry) => entry.id)).toEqual(["assistant:8"]);

    const replay = reduceNativeSessionEvent(recorded, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "history_replay",
      data: {
        session_id: sessionId,
        max_seq: 9,
        removed_user_message_seqs: [7],
        entries: [{ role: "assistant", seq: 8, agent: "Build", text: "retained", ts_ms: 1700000000001 }],
      },
    });
    expect(replay.state.history.map((entry) => entry.id)).toEqual(["assistant:8"]);
  });

  it("extracts durable submission receipts from history, replay, and queue folds", () => {
    const acceptedId = "44444444-4444-4444-8444-444444444444";
    expect(
      clientSubmissionIdsFromHistory([
        { role: "user", seq: 7, text: "accepted", client_submission_ids: [acceptedId] },
      ]),
    ).toEqual([acceptedId]);
    expect(
      acceptedClientSubmissionIdsFromEvent(
        {
          v: PROTOCOL_VERSION,
          kind: "evt",
          event: "history_replay",
          data: {
            session_id: sessionId,
            max_seq: 7,
            entries: [
              { role: "user", seq: 7, text: "accepted", client_submission_ids: [acceptedId] },
            ],
          },
        },
        sessionId,
      ),
    ).toEqual([acceptedId]);
    expect(
      acceptedClientSubmissionIdsFromEvent(
        {
          v: PROTOCOL_VERSION,
          kind: "evt",
          event: "user_messages_terminated",
          data: {
            session_id: sessionId,
            client_submission_ids: [acceptedId],
            disposition: "cancelled",
          },
        },
        sessionId,
      ),
    ).toEqual([acceptedId]);
    expect(
      acceptedClientSubmissionIdsFromEvent(
        {
          v: PROTOCOL_VERSION,
          kind: "evt",
          event: "queued_user_messages_folded",
          data: {
            session_id: sessionId,
            text: "folded",
            queue_item_ids: [acceptedId],
            target: { id: "root", agent: "Build", depth: 0 },
          },
        },
        sessionId,
      ),
    ).toEqual([acceptedId]);
  });

  it("turns live inference failures into structured transcript surfaces", () => {
    const result = reduceNativeSessionEvent(initialState, {
      v: PROTOCOL_VERSION,
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
        session_entry_mode: "code",
        short_id: "s1",
        project_root: "/work/app",
        project_id: "project_1",
        active_agent: "Build",
        history: [],
        active_model_state: {
          selection: { provider: "openai", model: "gpt-4o" },
          default_selection: { provider: "openai", model: "gpt-5" },
          diverged: true,
          generation: 4,
        },
        paused_work: [{ session_id: sessionId, reason: "daemon_shutdown" }],
        repair_required: {
          session_id: sessionId,
          short_id: "s1",
          provider: "openai",
          model: "gpt-4o",
          wire_api: "responses",
          failure_kind: "orphan_tool_result",
          failing_tool_call_ids: ["tool-1"],
          safe_last_turn_seq: 7,
          suggested_actions: ["open_read_only"],
          detail: "Open read-only until repaired.",
        },
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
    expect(runtime.daemonState.repairRequired).toEqual(
      expect.objectContaining({
        failure_kind: "orphan_tool_result",
        detail: "Open read-only until repaired.",
      }),
    );
  });

  it("accepts same-generation terminal corrections to default and divergence state", () => {
    const initial = reduceNativeSessionEvent(initialState, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "active_model_state",
      data: {
        session_id: sessionId,
        selection: { provider: "openai", model: "gpt-5" },
        default_selection: { provider: "openai", model: "old-default" },
        diverged: true,
        generation: 7,
      },
    });
    const corrected = reduceNativeSessionEvent(initial.state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "model_selection_result",
      data: {
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
      },
    });

    expect(corrected.warning).toBeUndefined();
    expect(corrected.state.activeModel).toMatchObject({
      provider: "openai",
      model: "gpt-5",
      configProvider: "openai",
      configModel: "gpt-5",
      diverged: false,
      generation: 7,
    });
    expect(corrected.state.activeModel?.selection).toEqual({
      provider: "openai",
      model: "gpt-5",
      reasoning_effort: { value: "high" },
      thinking_mode: "high",
      prompt_cache_retention: "extended",
    });
  });

  it("accepts same-generation full config corrections from active-model state", () => {
    const initial = reduceNativeSessionEvent(initialState, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "active_model_state",
      data: {
        session_id: sessionId,
        selection: { provider: "openai", model: "gpt-5" },
        default_selection: { provider: "openai", model: "old-default" },
        diverged: true,
        generation: 7,
      },
    });
    const corrected = reduceNativeSessionEvent(initial.state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "active_model_state",
      data: {
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
      },
    });

    expect(corrected.warning).toBeUndefined();
    expect(corrected.state.activeModel).toMatchObject({
      provider: "openai",
      model: "gpt-5",
      configProvider: "openai",
      configModel: "gpt-5",
      diverged: false,
      generation: 7,
    });
    expect(corrected.state.activeModel?.defaultSelection).toEqual({
      provider: "openai",
      model: "gpt-5",
      reasoning_effort: { value: "high" },
      thinking_mode: "high",
      prompt_cache_retention: "extended",
    });
  });

  it("does not invent active state from a rejected model-selection result", () => {
    const result = reduceNativeSessionEvent(initialState, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "model_selection_result",
      data: {
        session_id: sessionId,
        selection_id: "33333333-3333-4333-8333-333333333333",
        provider: "openai",
        model: "gpt-5",
        outcome: {
          status: "rejected",
          user_message: "Model selection was rejected.",
          diagnostic_code: "model_switch_rejected",
        },
      },
    });

    expect(result.warning).toBeUndefined();
    expect(result.state).toBe(initialState);
    expect(result.state.activeModel).toBeUndefined();
  });

  it("rejects the removed flat active-model event without changing cached state", () => {
    const cached = {
      ...initialState,
      activeModel: {
        selection: { provider: "cached", model: "current" },
        defaultSelection: { provider: "cached", model: "current" },
        provider: "cached",
        model: "current",
        configProvider: "cached",
        configModel: "current",
        diverged: false,
        generation: 9,
      },
    };
    const result = reduceNativeSessionEvent(cached, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "active_model_state",
      data: {
        session_id: sessionId,
        provider: "flat",
        model: "removed-v5-shape",
        diverged: true,
        generation: 10,
      },
    });

    expect(result.warning).toBe("[native-remote] unknown event: active_model_state");
    expect(result.state).toBe(cached);
    expect(result.state.activeModel).toBe(cached.activeModel);
  });

  it("streams assistant deltas into a pending row and replaces it with final text", () => {
    const delta = reduceNativeSessionEvent(initialState, {
      v: PROTOCOL_VERSION,
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
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_text_delta",
      data: { session_id: sessionId, agent: "Build", delta: "lo" },
    });
    expect(nextDelta.state.history[0]).toMatchObject({ text: "hello" });

    const final = reduceNativeSessionEvent(nextDelta.state, {
      v: PROTOCOL_VERSION,
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
        v: PROTOCOL_VERSION,
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

    expect(
      reconcileRecordedUserMessage(optimistic, {
        seq: 9,
        client_submission_ids: ["1"],
      }),
    ).toEqual([{ id: "user:9", kind: "user_message", seq: 9, text: "run tests" }]);
    expect(
      reconcileRecordedUserMessage([], { seq: 10, preflight_cleaned: "cleaned text" }),
    ).toEqual([{ id: "user:10", kind: "user_message", seq: 10, text: "cleaned text" }]);
    expect(
      reconcileRecordedUserMessage(
        [
          { id: "assistant:4", kind: "assistant_text", seq: 4, text: "old" },
          ...appendOptimisticUserMessage([], "pending", "2"),
        ],
        { client_submission_ids: [] },
      ),
    ).toEqual([
      { id: "assistant:4", kind: "assistant_text", seq: 4, text: "old" },
      {
        id: "user:pending:2",
        kind: "user_message",
        seq: Number.MAX_SAFE_INTEGER - 2,
        text: "pending",
      },
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

  it("folds multiple native optimistic rows into one canonical user row", () => {
    const first = "44444444-4444-4444-8444-444444444444";
    const second = "55555555-5555-4555-8555-555555555555";
    const unrelated = "66666666-6666-4666-8666-666666666666";
    const history = appendOptimisticUserMessage(
      appendOptimisticUserMessage(
        appendOptimisticUserMessage([], "first pending", first),
        "second pending",
        second,
      ),
      "unrelated pending",
      unrelated,
    );

    const result = reduceNativeSessionEvent(
      { ...initialState, history },
      {
        v: PROTOCOL_VERSION,
        kind: "evt",
        event: "queued_user_messages_folded",
        data: {
          session_id: sessionId,
          text: "raw folded text",
          display_text: "display folded text",
          preflight_cleaned: "cleaned folded text",
          tag_expansions: [{ tag: "src", replacement: "source context" }],
          queue_item_ids: [first, second],
          target: { id: "root", agent: "Build", depth: 0 },
          seq: 7,
        },
      },
    );

    expect(result.warning).toBeUndefined();
    expect(result.state.history.filter((entry) => entry.id === "user:7")).toEqual([
      { id: "user:7", kind: "user_message", seq: 7, text: "display folded text" },
    ]);
    expect(result.state.history.map((entry) => entry.id)).not.toContain(`user:pending:${first}`);
    expect(result.state.history.map((entry) => entry.id)).not.toContain(`user:pending:${second}`);
    expect(result.state.history.map((entry) => entry.id)).toContain(`user:pending:${unrelated}`);
  });

  it("retains the complete user submission for an exact same-session retry", () => {
    const retained = {
      sessionId,
      params: {
        client_submission_id: "44444444-4444-4444-8444-444444444444",
        text: "@review inspect this",
        display_text: "inspect this",
        tag_expansions: [{ tag: "review", replacement: "review the patch" }],
        forced_skill: "review",
      },
    };

    const retry = prepareUserMessageSubmission(sessionId, retained.params.text, retained);

    expect(retry).toEqual({ submission: retained, isRetry: true });
    expect(retry.submission.params).toBe(retained.params);
  });

  it("keeps an exact retry available after switching away and back", () => {
    const retained: RetainedUserMessageSubmissions = new Map();
    const original = {
      sessionId,
      params: {
        client_submission_id: "44444444-4444-4444-8444-444444444444",
        text: "same visible text",
        display_text: "exact expanded display",
        tag_expansions: [{ tag: "review", replacement: "exact expansion" }],
        forced_skill: "review",
      },
    };
    const otherSessionId = "66666666-6666-4666-8666-666666666666";
    retainUserMessageSubmission(retained, original);

    const elsewhere = prepareUserMessageSubmission(otherSessionId, original.params.text, original);
    const returned = prepareUserMessageSubmission(sessionId, original.params.text, original);

    expect(elsewhere.isRetry).toBe(false);
    expect(elsewhere.submission.sessionId).toBe(otherSessionId);
    expect(returned).toEqual({ submission: original, isRetry: true });
    expect(returned.submission.params).toBe(original.params);
  });

  it("restores every queue-ACKed optimistic row after an attach without a durable receipt", () => {
    const retained: RetainedUserMessageSubmissions = new Map();
    const first = {
      sessionId,
      params: {
        client_submission_id: "44444444-4444-4444-8444-444444444444",
        text: "expanded first",
        display_text: "visible first",
      },
    };
    const second = {
      sessionId,
      params: {
        client_submission_id: "66666666-6666-4666-8666-666666666666",
        text: "expanded second",
        display_text: "visible second",
      },
    };
    retainUserMessageSubmission(retained, first);
    retainUserMessageSubmission(retained, second);

    const restored = restoreRetainedUserMessagesAfterAttach(
      [{ id: "assistant:1", seq: 1, kind: "assistant_text", text: "existing" }],
      sessionId,
      retained,
    );

    expect(restored).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "user:pending:" + first.params.client_submission_id,
          text: first.params.display_text,
        }),
        expect.objectContaining({
          id: "user:pending:" + second.params.client_submission_id,
          text: second.params.display_text,
        }),
      ]),
    );
  });

  it("a delayed durable receipt clears only the matching retry-ready drafts", () => {
    const first = {
      sessionId,
      params: {
        client_submission_id: "44444444-4444-4444-8444-444444444444",
        text: "first exact wire text",
        display_text: "first visible draft",
      },
    };
    const otherSessionId = "55555555-5555-4555-8555-555555555555";
    const second = {
      sessionId: otherSessionId,
      params: {
        client_submission_id: "66666666-6666-4666-8666-666666666666",
        text: "second exact wire text",
        display_text: "second visible draft",
      },
    };
    const reconciled = reconcileAcceptedRetrySubmissions(
      { [sessionId]: first, [otherSessionId]: second },
      [first.params.client_submission_id, second.params.client_submission_id],
    );
    const messages = clearAcceptedRetryDrafts(
      {
        [sessionId]: " first exact wire text ",
        [otherSessionId]: "newer user edit",
      },
      reconciled.accepted,
    );

    expect(reconciled.retries).toEqual({});
    expect(messages).toEqual({
      [sessionId]: "",
      [otherSessionId]: "newer user edit",
    });
  });

  it("tracks multiple complete retained submissions independently by client id", () => {
    const retained: RetainedUserMessageSubmissions = new Map();
    const first = {
      sessionId,
      params: {
        client_submission_id: "44444444-4444-4444-8444-444444444444",
        text: "same text",
        display_text: "first exact payload",
      },
    };
    const second = {
      sessionId,
      params: {
        client_submission_id: "55555555-5555-4555-8555-555555555555",
        text: "same text",
        display_text: "second exact payload",
      },
    };

    retainUserMessageSubmission(retained, first);
    retainUserMessageSubmission(retained, second);
    forgetUserMessageSubmission(retained, second.params.client_submission_id);

    expect(retained.get(first.params.client_submission_id)).toBe(first);
    expect(retained.has(second.params.client_submission_id)).toBe(false);
    expect(prepareUserMessageSubmission(sessionId, first.params.text, first)).toEqual({
      submission: first,
      isRetry: true,
    });
    expect(
      isCurrentUserMessageSubmission(sessionId, first.params.client_submission_id, first),
    ).toBe(true);
    expect(
      isCurrentUserMessageSubmission(
        "66666666-6666-4666-8666-666666666666",
        first.params.client_submission_id,
        first,
      ),
    ).toBe(false);
  });

  it("gives a deliberate same-text submission a fresh UUID without an explicit retry marker", () => {
    const queued = {
      sessionId,
      params: {
        client_submission_id: "44444444-4444-4444-8444-444444444444",
        text: "repeat exactly",
        display_text: "repeat exactly",
      },
    };
    const retained: RetainedUserMessageSubmissions = new Map();
    retainUserMessageSubmission(retained, queued);

    const fresh = prepareUserMessageSubmission(sessionId, queued.params.text, undefined);
    const retry = prepareUserMessageSubmission(sessionId, queued.params.text, queued);

    expect(fresh.isRetry).toBe(false);
    expect(fresh.submission.params.client_submission_id).not.toBe(
      queued.params.client_submission_id,
    );
    expect(retry).toEqual({ submission: queued, isRetry: true });
  });

  it("keeps all optimistic rows when one exact durable persistence fails", () => {
    const firstId = "44444444-4444-4444-8444-444444444444";
    const secondId = "55555555-5555-4555-8555-555555555555";
    const state = {
      ...initialState,
      history: appendOptimisticUserMessage(
        appendOptimisticUserMessage([], "first", firstId),
        "second",
        secondId,
      ),
    };

    const result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "session_persist_failed",
      data: {
        session_id: sessionId,
        client_submission_id: firstId,
        error: "disk full",
      },
    });

    expect(result.warning).toBeUndefined();
    expect(result.state).toBe(state);
    expect(result.state.history.map((entry) => entry.id)).toEqual([
      `user:pending:${firstId}`,
      `user:pending:${secondId}`,
    ]);
  });

  it("terminal events retire only their correlated optimistic submission", () => {
    const firstId = "44444444-4444-4444-8444-444444444444";
    const secondId = "55555555-5555-4555-8555-555555555555";
    const state = {
      ...initialState,
      history: appendOptimisticUserMessage(
        appendOptimisticUserMessage([], "first", firstId),
        "second",
        secondId,
      ),
    };

    const result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "user_messages_terminated",
      data: {
        session_id: sessionId,
        client_submission_ids: [firstId],
        disposition: "preflight_rejected",
      },
    });

    expect(result.warning).toBeUndefined();
    expect(result.state.history.map((entry) => entry.id)).toEqual([`user:pending:${secondId}`]);
  });

  it.each([
    "internal",
    "shutdown",
  ])("retains the exact native submission without another optimistic row after typed %s ambiguity", (code) => {
    const retained = {
      sessionId,
      params: {
        client_submission_id: "44444444-4444-4444-8444-444444444444",
        text: "@review inspect this",
        display_text: "inspect this",
        tag_expansions: [{ tag: "review", replacement: "review the patch" }],
        forced_skill: "review",
      },
    };
    const history = appendOptimisticUserMessage(
      [],
      retained.params.display_text,
      retained.params.client_submission_id,
    );
    const error = new RemoteSessionError("acceptance uncertain", code, { code });

    expect(isAmbiguousUserMessageSendError(error)).toBe(true);
    const retry = prepareUserMessageSubmission(sessionId, retained.params.text, retained);
    const retryHistory = retry.isRetry
      ? history
      : appendOptimisticUserMessage(
          history,
          retry.submission.params.display_text ?? retry.submission.params.text,
          retry.submission.params.client_submission_id,
        );

    expect(retry.submission.params).toBe(retained.params);
    expect(retryHistory).toBe(history);
    expect(retryHistory).toHaveLength(1);
  });

  it("classifies a definitive native rejection for optimistic-row cleanup", () => {
    const rejection = new RemoteSessionError("payload rejected", "bad_request", {
      code: "bad_request",
    });

    expect(isAmbiguousUserMessageSendError(rejection)).toBe(false);
    expect(shouldRetainUserMessageSubmission(rejection)).toBe(false);
    expect(
      shouldRetainUserMessageSubmission(
        new RemoteSessionError("not accepted", "user_message_not_accepted", {
          code: "user_message_not_accepted",
        }),
      ),
    ).toBe(true);
    expect(
      shouldRetainUserMessageSubmission(
        new RemoteSessionError("terminal", "user_message_terminated", {
          code: "user_message_terminated",
        }),
      ),
    ).toBe(false);
  });

  it("adds and resolves interrupt events", () => {
    const raised = reduceNativeSessionEvent(initialState, {
      v: PROTOCOL_VERSION,
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
      v: PROTOCOL_VERSION,
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

describe("remote_display_events_v11_native", () => {
  it("remote_display_events_v11_native", () => {
    let state = initialState;

    let result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 1, delta: "Hel" },
    });
    state = result.state;
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 1, delta: "lo" },
    });
    state = result.state;
    expect(state.history.some((e) => e.kind === "assistant_text" && e.text === "Hello")).toBe(true);

    // Typed reasoning deltas coalesce within one attempt.
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 1, delta: "Think" },
    });
    state = result.state;
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 1, delta: "ing" },
    });
    state = result.state;
    expect(
      state.history.some((e) => e.kind === "assistant_reasoning" && e.text === "Thinking"),
    ).toBe(true);

    // Translated success: presentation_text wins; attempt reasoning cleared.
    result = reduceNativeSessionEvent(state, {
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
    });
    state = result.state;
    expect(state.history.find((e) => e.id === "assistant:99")).toMatchObject({
      kind: "assistant_text",
      text: "Hello",
    });
    expect(state.history.some((e) => e.id === "assistant:reasoning:pending:1")).toBe(false);
    expect(state.history.find((e) => e.id === "reasoning:99")).toMatchObject({
      kind: "assistant_reasoning",
      text: "Thinking",
    });

    // Fallback complete without presentation_text.
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_complete",
      data: { session_id: sessionId, attempt_id: 2, text: "fallback body", seq: 100 },
    });
    state = result.state;
    expect(state.history.find((e) => e.id === "assistant:100")).toMatchObject({
      kind: "assistant_text",
      text: "fallback body",
    });

    // Legacy assistant_text missing presentation_text.
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_text",
      data: { session_id: sessionId, text: "legacy only", seq: 101 },
    });
    state = result.state;
    expect(state.history.find((e) => e.id === "assistant:101")).toMatchObject({
      kind: "assistant_text",
      text: "legacy only",
    });

    // Reset removes text and reasoning for the failed attempt; replacement
    // reasoning starts a distinct row.
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 7, delta: "gone" },
    });
    state = result.state;
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 7, delta: "old reasoning" },
    });
    state = result.state;
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_attempt_reset",
      data: {
        session_id: sessionId,
        failed_attempt_id: 7,
        replacement_attempt_id: 8,
        reason: "timeout",
      },
    });
    state = result.state;
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 8, delta: "new reasoning" },
    });
    state = result.state;
    expect(state.history.some((e) => e.id === "assistant:pending:7")).toBe(false);
    expect(state.history.some((e) => e.id === "assistant:reasoning:pending:7")).toBe(false);
    expect(state.history).toContainEqual(
      expect.objectContaining({
        id: "assistant:reasoning:pending:8",
        kind: "assistant_reasoning",
        text: "new reasoning",
      }),
    );

    // Error becomes inference_error row.
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 11, delta: "partial" },
    });
    state = result.state;
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_reasoning_delta",
      data: { session_id: sessionId, attempt_id: 11, delta: "failed reasoning" },
    });
    state = result.state;
    result = reduceNativeSessionEvent(state, {
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
    });
    state = result.state;
    expect(state.history.some((e) => e.id === "assistant:pending:11")).toBe(false);
    expect(state.history.some((e) => e.id === "assistant:reasoning:pending:11")).toBe(false);
    expect(state.history.some((e) => e.kind === "inference_error")).toBe(true);

    // Complete with seq:None then AssistantText must not duplicate the reply.
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_text_delta",
      data: { session_id: sessionId, attempt_id: 42, delta: "live" },
    });
    state = result.state;
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_display_complete",
      data: { session_id: sessionId, attempt_id: 42, text: "live final" },
    });
    state = result.state;
    expect(
      state.history.filter((e) => e.kind === "assistant_text" && e.text === "live final"),
    ).toHaveLength(1);
    result = reduceNativeSessionEvent(state, {
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "assistant_text",
      data: { session_id: sessionId, text: "live final", seq: 200 },
    });
    state = result.state;
    const liveFinals = state.history.filter(
      (e) => e.kind === "assistant_text" && e.text === "live final",
    );
    expect(liveFinals).toHaveLength(1);
    expect(liveFinals[0]?.id).toBe("assistant:200");
    expect(state.history.some((e) => e.id === "assistant:pending:42")).toBe(false);

    // Legacy missing presentation on wire history entry.
    const legacy = toNativeHistoryEntry(
      { role: "assistant", seq: 3, agent: "Build", text: "legacy wire" },
      3,
    );
    expect(legacy).toMatchObject({ kind: "assistant_text", text: "legacy wire" });
    const translated = toNativeHistoryEntry(
      {
        role: "assistant",
        seq: 4,
        agent: "Build",
        text: "wire",
        presentation_text: "shown",
      },
      4,
    );
    expect(translated).toMatchObject({ kind: "assistant_text", text: "shown" });
  });
});
