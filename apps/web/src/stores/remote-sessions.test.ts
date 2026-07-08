import { attachResultSchema, type LiveEvent } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import { addOptimisticUserMessage, applyLiveEvent, mergeAttach } from "./remote-sessions";

const attachFixture = {
  session: {
    sessionId: "s1",
    projectRoot: "/work/app",
    title: "Fix checkout",
    shortId: "s1",
    status: "needs_attention",
    archived: false,
    pinned: true,
    forkCount: 1,
    turnCount: 2,
    attention: { kind: "approval", interruptId: "int1" },
    updatedAt: 1783296000,
    createdBy: { userId: "u1", displayName: "Chris", origin: "web" },
    agent: "codex",
    model: "gpt-5",
  },
  history: [
    {
      id: "h1",
      seq: 1,
      ts: 1783296000,
      kind: "user_message",
      text: "Please fix checkout",
      actor: { userId: "u1", displayName: "Chris", origin: "web" },
      attachments: [],
    },
    { id: "h2", seq: 2, ts: 1783296010, kind: "assistant_text", text: "I will inspect." },
    {
      id: "h3",
      seq: 3,
      ts: 1783296020,
      kind: "tool_call",
      callId: "tool1",
      name: "shell",
      status: "succeeded",
      durationMs: 230,
      userFacing: true,
      output: { summary: "tests failed" },
    },
    {
      id: "h4",
      seq: 4,
      ts: 1783296030,
      kind: "interrupt",
      interrupt: {
        interruptId: "int1",
        kind: "approval",
        title: "Run migration?",
        body: "Approve running db push?",
        choices: ["approve", "deny"],
        resolved: false,
      },
    },
  ],
  nextSeq: 5,
  schedules: [],
};

const empty = {
  status: "connected" as const,
  projects: [],
  sessionsByProject: {},
  detailsBySession: {},
};

describe("remote session reducers", () => {
  it("orders attach backfill by sequence and tracks nextSeq", () => {
    const attach = attachResultSchema.parse({
      ...attachFixture,
      history: [...attachFixture.history].reverse(),
    });
    const state = mergeAttach(empty, attach);
    const detail = state.detailsBySession.s1;
    expect(detail.history.map((entry) => entry.seq)).toEqual([1, 2, 3, 4]);
    expect(detail.nextSeq).toBe(5);
  });

  it("merges reconnect backfill without dropping newer optimistic entries", () => {
    const attach = attachResultSchema.parse(attachFixture);
    const first = addOptimisticUserMessage(
      mergeAttach(empty, attach),
      "s1",
      "newer",
      "local-1",
      1783296050000,
    );
    const reattach = attachResultSchema.parse({ ...attachFixture, nextSeq: 5 });
    const state = mergeAttach(first, reattach);
    expect(state.detailsBySession.s1.history.some((entry) => entry.id === "local-1")).toBe(true);
  });

  it("applies history entries and assistant deltas in order", () => {
    const attach = attachResultSchema.parse(attachFixture);
    const withAttach = mergeAttach(empty, attach);
    const entryEvent: LiveEvent = {
      type: "history_entry",
      sessionId: "s1",
      entry: { id: "h5", seq: 5, ts: 1783296040, kind: "assistant_text", text: "Hello" },
    };
    const deltaEvent: LiveEvent = {
      type: "assistant_delta",
      sessionId: "s1",
      seq: 6,
      entryId: "h5",
      delta: " world",
    };
    const state = applyLiveEvent(applyLiveEvent(withAttach, entryEvent), deltaEvent);
    const entry = state.detailsBySession.s1.history.find((entry) => entry.id === "h5");
    expect(entry).toMatchObject({ kind: "assistant_text", text: "Hello world" });
    expect(state.detailsBySession.s1.nextSeq).toBe(7);
  });

  it("marks interrupts resolved for all viewers", () => {
    const attach = attachResultSchema.parse(attachFixture);
    const state = applyLiveEvent(mergeAttach(empty, attach), {
      type: "interrupt_resolved",
      sessionId: "s1",
      interruptId: "int1",
      seq: 7,
    });
    const interrupt = state.detailsBySession.s1.history.find((entry) => entry.kind === "interrupt");
    expect(interrupt).toMatchObject({ interrupt: { resolved: true } });
  });

  it("updates session summaries and usage without losing details", () => {
    const attach = attachResultSchema.parse(attachFixture);
    const withAttach = mergeAttach(empty, attach);
    const updated = applyLiveEvent(withAttach, {
      type: "session_updated",
      summary: { ...attach.session, title: "Renamed", updatedAt: attach.session.updatedAt + 10 },
    });
    const withUsage = applyLiveEvent(updated, {
      type: "usage",
      sessionId: "s1",
      usage: { inputTokens: 1, outputTokens: 2, totalTokens: 3 },
    });
    expect(withUsage.detailsBySession.s1.summary.title).toBe("Renamed");
    expect(withUsage.detailsBySession.s1.usage?.totalTokens).toBe(3);
  });
});
