import type { HistoryEntry, HistoryPageResult } from "@flycockpit/cockpit-protocol";
import {
  mergeNativeHistoryEntries,
  mergeNativeHistorySnapshot,
  type NativeHistoryEntry,
  nativeHistoryMergeKey,
  oldestSeqFromNativeHistory,
  toNativeHistoryEntry,
} from "./session-events";

export {
  mergeNativeHistoryEntries,
  mergeNativeHistorySnapshot,
  nativeHistoryMergeKey,
  oldestSeqFromNativeHistory,
};

/** Daemon-clamped page size requested by native back-paging. */
export const NATIVE_HISTORY_PAGE_LIMIT = 100;

/**
 * Screen list contract: one virtualized owner, never nested inside an unbounded
 * same-axis ScrollView for the transcript.
 */
export const NATIVE_TRANSCRIPT_LIST = {
  component: "FlatList" as const,
  virtualized: true,
  nestedSameAxisUnboundedScrollView: false,
  ownsScrolling: true,
};

/** Layout contract for the project transcript screen scroll ownership. */
export function nativeTranscriptScreenScrollOwners() {
  return {
    containerScrollable: false as const,
    transcriptList: NATIVE_TRANSCRIPT_LIST,
    nestedSameAxisUnboundedScrollView: false as const,
  };
}

export type NativeHistoryPagingState = {
  oldestSeq: number | null;
  hasMore: boolean;
  isLoading: boolean;
  error: string | null;
};

export type NativeHistoryPageAttempt = {
  id: number;
  client: object;
  connectionEpoch: number;
  sessionId: string;
  requestGeneration: number;
  beforeSeq: number | null;
};

export type NativeHistoryPagingGeneration = {
  client: object;
  connectionEpoch: number;
  sessionId: string;
  requestGeneration: number;
  beforeSeq: number | null;
};

export function emptyNativeHistoryPagingState(): NativeHistoryPagingState {
  return {
    oldestSeq: null,
    hasMore: false,
    isLoading: false,
    error: null,
  };
}

export function pagingFromNativeHistory(
  history: readonly NativeHistoryEntry[],
  current?: NativeHistoryPagingState,
): NativeHistoryPagingState {
  const oldestSeq = oldestSeqFromNativeHistory(history);
  return {
    oldestSeq,
    hasMore: current?.hasMore ?? oldestSeq !== null,
    isLoading: false,
    error: null,
  };
}

function historyPageOldestSeq(page: HistoryPageResult) {
  const raw = page as HistoryPageResult & { oldest_seq?: unknown };
  return typeof raw.oldest_seq === "number" ? raw.oldest_seq : null;
}

export function mergeNativeHistoryPage(
  history: readonly NativeHistoryEntry[],
  _paging: NativeHistoryPagingState,
  page: HistoryPageResult,
): { history: NativeHistoryEntry[]; paging: NativeHistoryPagingState } {
  const pageEntries = page.entries.map((entry, index) => toNativeHistoryEntry(entry, index));
  const merged = mergeNativeHistoryEntries(history, pageEntries);
  return {
    history: merged,
    paging: {
      oldestSeq: historyPageOldestSeq(page) ?? oldestSeqFromNativeHistory(merged),
      hasMore: page.has_more,
      isLoading: false,
      error: null,
    },
  };
}

export function markNativeHistoryPageLoading(
  paging: NativeHistoryPagingState,
): NativeHistoryPagingState {
  return { ...paging, isLoading: true, error: null };
}

export function markNativeHistoryPageError(
  paging: NativeHistoryPagingState,
  error: string,
): NativeHistoryPagingState {
  return { ...paging, isLoading: false, error };
}

export function canBeginNativeHistoryPageLoad(input: {
  hasMore: boolean;
  isLoading: boolean;
  hasInFlight: boolean;
}) {
  return input.hasMore && !input.isLoading && !input.hasInFlight;
}

export function nativeHistoryPageRequestParams(input: {
  sessionId: string;
  beforeSeq: number | null;
}) {
  return {
    session_id: input.sessionId,
    before_seq: input.beforeSeq,
    limit: NATIVE_HISTORY_PAGE_LIMIT,
  };
}

export function historyPageErrorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Could not load older history.";
}

/**
 * Generation-bound in-flight page request coordinator. One request is in flight
 * per full (client, connectionEpoch, sessionId, requestGeneration, beforeSeq)
 * tuple; stale success/error is ignored via {@link isCurrent}.
 */
export class NativeHistoryPagingCoordinator {
  private nextId = 0;
  private requestGeneration = 0;
  private inFlight: NativeHistoryPageAttempt | null = null;

  currentRequestGeneration() {
    return this.requestGeneration;
  }

  /**
   * Invalidate on client identity change, connectionEpoch bump (reconnect), or
   * session switch. Also used when attach lifecycle is invalidated.
   */
  invalidate() {
    this.requestGeneration += 1;
    this.inFlight = null;
  }

  /** Explicit request generation bump (switch away/back without epoch change). */
  bumpRequestGeneration() {
    this.invalidate();
  }

  hasInFlight() {
    return this.inFlight !== null;
  }

  inFlightAttempt() {
    return this.inFlight;
  }

  begin(
    generation: NativeHistoryPagingGeneration,
    state: Pick<NativeHistoryPagingState, "hasMore" | "isLoading">,
  ): NativeHistoryPageAttempt | null {
    // In-flight ownership is the coordinator; isLoading is UI mirror state and
    // may already be true when the load helper runs after markLoading.
    if (!state.hasMore || this.hasInFlight()) return null;
    if (generation.requestGeneration !== this.requestGeneration) return null;

    const attempt: NativeHistoryPageAttempt = {
      id: ++this.nextId,
      client: generation.client,
      connectionEpoch: generation.connectionEpoch,
      sessionId: generation.sessionId,
      requestGeneration: generation.requestGeneration,
      beforeSeq: generation.beforeSeq,
    };
    this.inFlight = attempt;
    return attempt;
  }

  isCurrent(
    attempt: NativeHistoryPageAttempt,
    client: object | null,
    connectionEpoch: number,
    requestGeneration: number,
  ) {
    return (
      this.inFlight?.id === attempt.id &&
      attempt.client === client &&
      attempt.connectionEpoch === connectionEpoch &&
      attempt.requestGeneration === requestGeneration &&
      attempt.requestGeneration === this.requestGeneration
    );
  }

  matchesGeneration(attempt: NativeHistoryPageAttempt, generation: NativeHistoryPagingGeneration) {
    return (
      this.isCurrent(
        attempt,
        generation.client,
        generation.connectionEpoch,
        generation.requestGeneration,
      ) &&
      attempt.sessionId === generation.sessionId &&
      attempt.beforeSeq === generation.beforeSeq
    );
  }

  /**
   * Accept a success only for the exact in-flight generation tuple. Returns
   * false for stale results so callers leave history/cursor/loading/error alone.
   */
  completeSuccess(
    attempt: NativeHistoryPageAttempt,
    client: object | null,
    connectionEpoch: number,
    requestGeneration: number,
  ) {
    if (!this.isCurrent(attempt, client, connectionEpoch, requestGeneration)) return false;
    this.inFlight = null;
    return true;
  }

  /**
   * Accept an error only for the exact in-flight generation tuple. Stale errors
   * must not clear or set loading/error state.
   */
  completeError(
    attempt: NativeHistoryPageAttempt,
    client: object | null,
    connectionEpoch: number,
    requestGeneration: number,
  ) {
    if (!this.isCurrent(attempt, client, connectionEpoch, requestGeneration)) return false;
    this.inFlight = null;
    return true;
  }

  /** Drop in-flight without applying (cancellation / generation bump mid-flight). */
  cancelIfCurrent(
    attempt: NativeHistoryPageAttempt,
    client: object | null,
    connectionEpoch: number,
    requestGeneration: number,
  ) {
    if (!this.isCurrent(attempt, client, connectionEpoch, requestGeneration)) return false;
    this.inFlight = null;
    return true;
  }
}

export type NativeHistoryPageClient = {
  readHistoryPage: (params: {
    session_id: string;
    limit: number;
    before_seq?: number | null;
  }) => Promise<HistoryPageResult>;
};

/**
 * One-shot page load. Applies pure success/error only when the attempt is still
 * current for the generation tuple. No network sleeps; caller supplies the client.
 */
export async function loadNativeHistoryPage(input: {
  coordinator: NativeHistoryPagingCoordinator;
  client: NativeHistoryPageClient & object;
  connectionEpoch: number;
  sessionId: string;
  requestGeneration: number;
  paging: NativeHistoryPagingState;
  /**
   * Optional latest-history resolver. When provided, success merges against
   * this snapshot (captured after the generation check) so live events that
   * arrived during the request are not dropped.
   */
  resolveHistory?: () => readonly NativeHistoryEntry[];
  history: readonly NativeHistoryEntry[];
}): Promise<
  | { kind: "skipped" }
  | {
      kind: "success";
      history: NativeHistoryEntry[];
      paging: NativeHistoryPagingState;
      prepended: boolean;
    }
  | { kind: "error"; paging: NativeHistoryPagingState }
  | { kind: "stale" }
> {
  const beforeSeq = input.paging.oldestSeq;
  const attempt = input.coordinator.begin(
    {
      client: input.client,
      connectionEpoch: input.connectionEpoch,
      sessionId: input.sessionId,
      requestGeneration: input.requestGeneration,
      beforeSeq,
    },
    input.paging,
  );
  if (!attempt) return { kind: "skipped" };

  try {
    const page = await input.client.readHistoryPage(
      nativeHistoryPageRequestParams({
        sessionId: input.sessionId,
        beforeSeq,
      }),
    );
    if (
      !input.coordinator.completeSuccess(
        attempt,
        input.client,
        input.connectionEpoch,
        input.requestGeneration,
      )
    ) {
      return { kind: "stale" };
    }
    const latestHistory = input.resolveHistory?.() ?? input.history;
    const beforeLen = latestHistory.length;
    const merged = mergeNativeHistoryPage(latestHistory, input.paging, page);
    return {
      kind: "success",
      ...merged,
      prepended: merged.history.length > beforeLen,
    };
  } catch (error) {
    if (
      !input.coordinator.completeError(
        attempt,
        input.client,
        input.connectionEpoch,
        input.requestGeneration,
      )
    ) {
      return { kind: "stale" };
    }
    return {
      kind: "error",
      paging: markNativeHistoryPageError(input.paging, historyPageErrorMessage(error)),
    };
  }
}

/** Map wire history rows through the same entry converter the screen uses. */
export function nativeEntriesFromWire(entries: readonly HistoryEntry[]) {
  return entries.map((entry, index) => toNativeHistoryEntry(entry, index));
}
