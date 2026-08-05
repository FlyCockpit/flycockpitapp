import { PROTOCOL_VERSION } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import {
  canBeginNativeHistoryPageLoad,
  emptyNativeHistoryPagingState,
  loadNativeHistoryPage,
  markNativeHistoryPageError,
  markNativeHistoryPageLoading,
  mergeNativeHistoryEntries,
  mergeNativeHistoryPage,
  mergeNativeHistorySnapshot,
  NATIVE_HISTORY_PAGE_LIMIT,
  NATIVE_TRANSCRIPT_LIST,
  NativeHistoryPagingCoordinator,
  nativeHistoryMergeKey,
  nativeHistoryPageRequestParams,
  nativeTranscriptScreenScrollOwners,
  pagingFromNativeHistory,
} from "./history-paging";
import { NativeAttachCoordinator } from "./session-attach";
import {
  appendOptimisticUserMessage,
  interruptDecisionView,
  type NativeHistoryEntry,
  reduceNativeSessionEvent,
  toNativeHistoryEntry,
} from "./session-events";

const sessionId = "11111111-1111-4111-8111-111111111111";

function settled(
  seq: number,
  kind: "user_message" | "assistant_text" = "user_message",
  text = `msg-${seq}`,
): NativeHistoryEntry {
  return { id: `${kind === "user_message" ? "user" : "assistant"}:${seq}`, seq, kind, text };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((next, fail) => {
    resolve = next;
    reject = fail;
  });
  return { promise, resolve, reject };
}

describe("native_history_paging_generation", () => {
  it("invalidates in-flight page attempts when attach lifecycle and connection epoch change", () => {
    const attach = new NativeAttachCoordinator();
    const paging = new NativeHistoryPagingCoordinator();
    const clientA = {};
    const clientB = {};

    const attachAttempt = attach.begin(clientA, 1, sessionId);
    expect(attach.markApplied(attachAttempt, clientA, 1)).toBe(true);
    expect(attach.finish(attachAttempt, clientA, 1)).toBe(true);

    const gen = paging.currentRequestGeneration();
    const attempt = paging.begin(
      {
        client: clientA,
        connectionEpoch: 1,
        sessionId,
        requestGeneration: gen,
        beforeSeq: 10,
      },
      { hasMore: true, isLoading: false },
    );
    expect(attempt).not.toBeNull();

    // Reconnect: attach invalidates and connectionEpoch advances with a new client.
    attach.invalidate();
    paging.invalidate();
    const nextGen = paging.currentRequestGeneration();
    expect(nextGen).toBeGreaterThan(gen);

    expect(paging.completeSuccess(attempt!, clientA, 1, gen)).toBe(false);
    expect(paging.completeError(attempt!, clientA, 1, gen)).toBe(false);
    expect(paging.hasInFlight()).toBe(false);

    const fresh = paging.begin(
      {
        client: clientB,
        connectionEpoch: 2,
        sessionId,
        requestGeneration: nextGen,
        beforeSeq: 5,
      },
      { hasMore: true, isLoading: false },
    );
    expect(fresh).not.toBeNull();
    expect(
      paging.matchesGeneration(fresh!, {
        client: clientB,
        connectionEpoch: 2,
        sessionId,
        requestGeneration: nextGen,
        beforeSeq: 5,
      }),
    ).toBe(true);
  });

  it("treats session switch and switch-away/back as a new request generation", () => {
    const paging = new NativeHistoryPagingCoordinator();
    const client = {};
    const gen0 = paging.currentRequestGeneration();
    const first = paging.begin(
      {
        client,
        connectionEpoch: 3,
        sessionId: "session-a",
        requestGeneration: gen0,
        beforeSeq: 4,
      },
      { hasMore: true, isLoading: false },
    );
    expect(first).not.toBeNull();

    paging.bumpRequestGeneration();
    const gen1 = paging.currentRequestGeneration();
    expect(paging.completeSuccess(first!, client, 3, gen0)).toBe(false);

    const second = paging.begin(
      {
        client,
        connectionEpoch: 3,
        sessionId: "session-b",
        requestGeneration: gen1,
        beforeSeq: 9,
      },
      { hasMore: true, isLoading: false },
    );
    expect(second?.sessionId).toBe("session-b");
    expect(second?.requestGeneration).toBe(gen1);
  });

  it("rejects begin when the caller still holds a stale requestGeneration", () => {
    const paging = new NativeHistoryPagingCoordinator();
    const client = {};
    const staleGen = paging.currentRequestGeneration();
    paging.invalidate();
    expect(
      paging.begin(
        {
          client,
          connectionEpoch: 1,
          sessionId,
          requestGeneration: staleGen,
          beforeSeq: 1,
        },
        { hasMore: true, isLoading: false },
      ),
    ).toBeNull();
  });
});

describe("native_history_merge_sequence_identity", () => {
  it("merges settled rows by seq and pending rows by id without collapsing sentinels", () => {
    const settledRows = [settled(2), settled(3, "assistant_text", "hi")];
    const withPending = appendOptimisticUserMessage(settledRows, "pending text", "local-1");
    const pageOlder = [settled(1, "user_message", "earlier")];
    const overlapping = [
      settled(2, "user_message", "stale duplicate from page"),
      settled(0, "user_message", "oldest"),
    ];

    const merged = mergeNativeHistoryEntries(withPending, [...pageOlder, ...overlapping]);
    expect(merged.map((entry) => entry.seq)).toEqual([0, 1, 2, 3, Number.MAX_SAFE_INTEGER - 2]);
    expect(merged.find((entry) => entry.seq === 2)).toMatchObject({
      text: "msg-2",
    });
    expect(nativeHistoryMergeKey(withPending[withPending.length - 1]!)).toMatch(/^id:/);
    expect(nativeHistoryMergeKey(settled(2))).toBe("seq:2");
    expect(merged.filter((entry) => entry.id.startsWith("user:pending:"))).toHaveLength(1);
  });

  it("dedupes full-page duplicates and keeps live inserts ordered after reverse completion", () => {
    const base = [settled(5), settled(6, "assistant_text", "tail")];
    const reversePage = [settled(3), settled(4), settled(5, "user_message", "dup-5")];
    const afterPage = mergeNativeHistoryPage(base, pagingFromNativeHistory(base), {
      session_id: sessionId,
      entries: reversePage.map((entry) => {
        const text = "text" in entry ? entry.text : "";
        return entry.kind === "assistant_text"
          ? { role: "assistant" as const, seq: entry.seq, text, agent: "Build" }
          : { role: "user" as const, seq: entry.seq, text };
      }),
      has_more: true,
      oldest_seq: 3,
    });

    expect(afterPage.history.map((e) => e.seq)).toEqual([3, 4, 5, 6]);
    expect(afterPage.history.find((e) => e.seq === 5)).toMatchObject({ text: "msg-5" });
    expect(afterPage.paging).toMatchObject({ oldestSeq: 3, hasMore: true, isLoading: false });

    const live: NativeHistoryEntry = settled(7, "assistant_text", "live");
    const withLive = mergeNativeHistoryEntries(afterPage.history, [live]);
    expect(withLive.map((e) => e.seq)).toEqual([3, 4, 5, 6, 7]);
  });

  it("preserves older paged rows across a truncated history_replay snapshot", () => {
    const paged = mergeNativeHistoryEntries([settled(5), settled(6)], [settled(1), settled(2)]);
    const replayed = mergeNativeHistorySnapshot(paged, [
      settled(5, "user_message", "refreshed-5"),
      settled(6, "assistant_text", "refreshed-6"),
    ]);
    expect(replayed.map((e) => e.seq)).toEqual([1, 2, 5, 6]);
    expect(replayed.find((e) => e.seq === 5)).toMatchObject({ text: "refreshed-5" });
  });
});

describe("native_history_load_one_in_flight", () => {
  it("guards one in-flight request, supports retry after error, empty terminal page, has_more, and cancellation", async () => {
    const coordinator = new NativeHistoryPagingCoordinator();
    const client = {
      readHistoryPage: async () => {
        throw new Error("unreachable");
      },
    };
    const gen = coordinator.currentRequestGeneration();
    const paging = {
      oldestSeq: 10,
      hasMore: true,
      isLoading: false,
      error: null,
    };

    expect(
      canBeginNativeHistoryPageLoad({ hasMore: true, isLoading: false, hasInFlight: false }),
    ).toBe(true);
    expect(
      canBeginNativeHistoryPageLoad({ hasMore: false, isLoading: false, hasInFlight: false }),
    ).toBe(false);

    const attempt = coordinator.begin(
      {
        client,
        connectionEpoch: 1,
        sessionId,
        requestGeneration: gen,
        beforeSeq: 10,
      },
      paging,
    );
    expect(attempt).not.toBeNull();
    expect(
      coordinator.begin(
        {
          client,
          connectionEpoch: 1,
          sessionId,
          requestGeneration: gen,
          beforeSeq: 10,
        },
        { ...paging, isLoading: true },
      ),
    ).toBeNull();
    expect(
      canBeginNativeHistoryPageLoad({
        hasMore: true,
        isLoading: false,
        hasInFlight: coordinator.hasInFlight(),
      }),
    ).toBe(false);

    // Cancellation mid-flight clears the guard so a later retry can begin.
    expect(coordinator.cancelIfCurrent(attempt!, client, 1, gen)).toBe(true);
    expect(coordinator.hasInFlight()).toBe(false);

    const loading = markNativeHistoryPageLoading(paging);
    expect(loading.isLoading).toBe(true);
    expect(loading.error).toBeNull();

    const failed = markNativeHistoryPageError(loading, "relay unavailable");
    expect(failed).toEqual({
      oldestSeq: 10,
      hasMore: true,
      isLoading: false,
      error: "relay unavailable",
    });

    const emptyTerminal = mergeNativeHistoryPage([settled(10)], paging, {
      session_id: sessionId,
      entries: [],
      has_more: false,
      oldest_seq: null,
    });
    expect(emptyTerminal.paging).toEqual({
      oldestSeq: 10,
      hasMore: false,
      isLoading: false,
      error: null,
    });

    expect(nativeHistoryPageRequestParams({ sessionId, beforeSeq: 10 })).toEqual({
      session_id: sessionId,
      before_seq: 10,
      limit: NATIVE_HISTORY_PAGE_LIMIT,
    });
    expect(NATIVE_HISTORY_PAGE_LIMIT).toBe(100);

    const pageDeferred = deferred<{
      session_id: string;
      entries: [];
      has_more: boolean;
      oldest_seq: number | null;
    }>();
    const asyncClient = {
      readHistoryPage: () => pageDeferred.promise,
    };
    const loadPromise = loadNativeHistoryPage({
      coordinator,
      client: asyncClient,
      connectionEpoch: 2,
      sessionId,
      requestGeneration: coordinator.currentRequestGeneration(),
      paging: { oldestSeq: 4, hasMore: true, isLoading: false, error: null },
      history: [settled(4)],
    });
    // Second concurrent load is skipped while first is in flight.
    const skipped = await loadNativeHistoryPage({
      coordinator,
      client: asyncClient,
      connectionEpoch: 2,
      sessionId,
      requestGeneration: coordinator.currentRequestGeneration(),
      paging: { oldestSeq: 4, hasMore: true, isLoading: false, error: null },
      history: [settled(4)],
    });
    expect(skipped).toEqual({ kind: "skipped" });

    pageDeferred.resolve({
      session_id: sessionId,
      entries: [],
      has_more: false,
      oldest_seq: null,
    });
    const done = await loadPromise;
    expect(done.kind).toBe("success");
    if (done.kind === "success") {
      expect(done.paging.hasMore).toBe(false);
    }
  });

  it("retry after error re-enters begin once the failed attempt is completed", async () => {
    const coordinator = new NativeHistoryPagingCoordinator();
    let calls = 0;
    const client = {
      readHistoryPage: async () => {
        calls += 1;
        if (calls === 1) throw new Error("temporary");
        return {
          session_id: sessionId,
          entries: [{ role: "user" as const, seq: 1, text: "older" }],
          has_more: false,
          oldest_seq: 1,
        };
      },
    };
    const gen = coordinator.currentRequestGeneration();
    const first = await loadNativeHistoryPage({
      coordinator,
      client,
      connectionEpoch: 1,
      sessionId,
      requestGeneration: gen,
      paging: { oldestSeq: 2, hasMore: true, isLoading: false, error: null },
      history: [settled(2)],
    });
    expect(first.kind).toBe("error");
    if (first.kind === "error") {
      expect(first.paging.error).toBe("temporary");
      expect(first.paging.isLoading).toBe(false);
    }

    const second = await loadNativeHistoryPage({
      coordinator,
      client,
      connectionEpoch: 1,
      sessionId,
      requestGeneration: gen,
      paging: { oldestSeq: 2, hasMore: true, isLoading: false, error: "temporary" },
      history: [settled(2)],
    });
    expect(second.kind).toBe("success");
    if (second.kind === "success") {
      expect(second.history.map((e) => e.seq)).toEqual([1, 2]);
      expect(second.paging.hasMore).toBe(false);
    }
  });
});

describe("native_history_virtualized_list", () => {
  it("declares a single FlatList owner with no nested same-axis unbounded ScrollView", () => {
    expect(NATIVE_TRANSCRIPT_LIST).toEqual({
      component: "FlatList",
      virtualized: true,
      nestedSameAxisUnboundedScrollView: false,
      ownsScrolling: true,
    });
    expect(
      NATIVE_TRANSCRIPT_LIST.component === "FlatList" ||
        NATIVE_TRANSCRIPT_LIST.component === "SectionList",
    ).toBe(true);
    const owners = nativeTranscriptScreenScrollOwners();
    expect(owners.containerScrollable).toBe(false);
    expect(owners.nestedSameAxisUnboundedScrollView).toBe(false);
    expect(owners.transcriptList.component).toBe("FlatList");
    expect(owners.transcriptList.ownsScrolling).toBe(true);
  });
});

describe("stale page success and error", () => {
  it("cannot mutate history, cursor, loading, error, or viewport after generation invalidation", async () => {
    const coordinator = new NativeHistoryPagingCoordinator();
    const pageDeferred = deferred<{
      session_id: string;
      entries: { role: "user"; seq: number; text: string }[];
      has_more: boolean;
      oldest_seq: number;
    }>();
    const client = {
      readHistoryPage: () => pageDeferred.promise,
    };
    const historyBefore = [settled(5)];
    const pagingBefore = {
      oldestSeq: 5,
      hasMore: true,
      isLoading: false,
      error: null as string | null,
    };
    const gen = coordinator.currentRequestGeneration();
    const loadPromise = loadNativeHistoryPage({
      coordinator,
      client,
      connectionEpoch: 1,
      sessionId,
      requestGeneration: gen,
      paging: pagingBefore,
      history: historyBefore,
    });

    coordinator.invalidate();
    pageDeferred.resolve({
      session_id: sessionId,
      entries: [{ role: "user", seq: 1, text: "should not apply" }],
      has_more: false,
      oldest_seq: 1,
    });
    const result = await loadPromise;
    expect(result).toEqual({ kind: "stale" });
    // Callers keep prior state on stale — pagingBefore/historyBefore unchanged.
    expect(historyBefore).toEqual([settled(5)]);
    expect(pagingBefore).toEqual({
      oldestSeq: 5,
      hasMore: true,
      isLoading: false,
      error: null,
    });

    const errDeferred = deferred<never>();
    const errClient = {
      readHistoryPage: () => errDeferred.promise,
    };
    const gen2 = coordinator.currentRequestGeneration();
    const errPromise = loadNativeHistoryPage({
      coordinator,
      client: errClient,
      connectionEpoch: 2,
      sessionId,
      requestGeneration: gen2,
      paging: pagingBefore,
      history: historyBefore,
    });
    coordinator.invalidate();
    errDeferred.reject(new Error("late failure"));
    expect(await errPromise).toEqual({ kind: "stale" });
    expect(pagingBefore.error).toBeNull();
  });
});

describe("interrupt_decision history rows", () => {
  it("maps structured decision/lines rather than flattening to reasoning text", () => {
    const entry = toNativeHistoryEntry(
      {
        role: "interrupt_decision",
        seq: 4,
        decision: {
          permission: true,
          cancelled: false,
          lines: [{ prompt: "Run command?", answer: "Approved once" }],
        },
      },
      0,
    );
    expect(entry).toMatchObject({
      kind: "interrupt_decision",
      seq: 4,
      decision: {
        permission: true,
        cancelled: false,
        lines: [{ prompt: "Run command?", answer: "Approved once" }],
      },
    });
    expect(interruptDecisionView(entry)).toEqual({
      interactive: false,
      permission: true,
      cancelled: false,
      lines: [{ prompt: "Run command?", answer: "Approved once" }],
    });
    expect(entry.kind).not.toBe("assistant_reasoning");
  });

  it("preserves interrupt_decision through page merge", () => {
    const merged = mergeNativeHistoryPage([settled(5)], emptyNativeHistoryPagingState(), {
      session_id: sessionId,
      entries: [
        {
          role: "interrupt_decision",
          seq: 2,
          decision: {
            permission: false,
            cancelled: true,
            lines: [{ prompt: "Continue?", answer: "" }],
          },
        },
      ],
      has_more: true,
      oldest_seq: 2,
    });
    const decision = merged.history.find((e) => e.seq === 2);
    expect(decision?.kind).toBe("interrupt_decision");
    if (decision?.kind === "interrupt_decision") {
      expect(interruptDecisionView(decision)?.cancelled).toBe(true);
    }
  });
});

describe("live event merge during paging", () => {
  it("merges assistant text by identity/order without dropping older pages", () => {
    const history = mergeNativeHistoryEntries([settled(5)], [settled(1), settled(2)]);
    const result = reduceNativeSessionEvent(
      { history, selectedSessionId: sessionId },
      {
        v: PROTOCOL_VERSION,
        kind: "evt",
        event: "assistant_text",
        data: {
          session_id: sessionId,
          agent: "Build",
          seq: 6,
          text: "live tail",
        },
      },
    );
    expect(result.state.history.map((e) => e.seq)).toEqual([1, 2, 5, 6]);
  });
});

describe("live events during in-flight page", () => {
  it("merges the page against resolveHistory so live appends are retained", async () => {
    const coordinator = new NativeHistoryPagingCoordinator();
    let history: NativeHistoryEntry[] = [settled(5)];
    const deferredPage = deferred<{
      entries: Array<{ seq: number; id: string; kind: string; text: string }>;
      has_more: boolean;
      oldest_seq: number;
      session_id: string;
    }>();
    const client = {
      readHistoryPage: async () => deferredPage.promise as never,
    };
    const load = loadNativeHistoryPage({
      coordinator,
      client,
      connectionEpoch: 1,
      sessionId,
      requestGeneration: coordinator.currentRequestGeneration(),
      paging: { oldestSeq: 5, hasMore: true, isLoading: true, error: null },
      history,
      resolveHistory: () => history,
    });
    history = [...history, settled(6, "assistant_text", "live")];
    deferredPage.resolve({
      entries: [{ seq: 4, id: "user:4", kind: "user_message", text: "older" }],
      has_more: false,
      oldest_seq: 4,
      session_id: sessionId,
    });
    const result = await load;
    expect(result.kind).toBe("success");
    if (result.kind === "success") {
      const seqs = result.history
        .map((e) => e.seq)
        .filter((s): s is number => typeof s === "number");
      expect(seqs).toEqual(expect.arrayContaining([4, 5, 6]));
      expect(result.prepended).toBe(true);
    }
  });

  it("stale page completion returns kind stale without paging payload", async () => {
    const coordinator = new NativeHistoryPagingCoordinator();
    const client = {
      readHistoryPage: async () => {
        coordinator.invalidate();
        return {
          entries: [],
          has_more: false,
          oldest_seq: null,
          session_id: sessionId,
        } as never;
      },
    };
    const result = await loadNativeHistoryPage({
      coordinator,
      client,
      connectionEpoch: 1,
      sessionId,
      requestGeneration: 0,
      paging: { oldestSeq: 5, hasMore: true, isLoading: true, error: null },
      history: [settled(5)],
    });
    expect(result.kind).toBe("stale");
    expect(result).not.toHaveProperty("paging");
    expect(result).not.toHaveProperty("history");
  });
});
