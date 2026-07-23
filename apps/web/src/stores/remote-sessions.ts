import type {
  AttachResult,
  EventEnvelope,
  FsListResult,
  FsReadResult,
  FsWriteResult,
  GitDiffFileResult,
  GitStatusResult,
  HistoryPageResult,
  InterruptQuestion,
  ResolveResponse,
  HistoryEntry as WireHistoryEntry,
  SessionSummary as WireSessionSummary,
} from "@flycockpit/cockpit-protocol";
import { eventEnvelopeSchema } from "@flycockpit/cockpit-protocol";
import { RemoteSessionClient } from "@flycockpit/cockpit-protocol/client";
import { create } from "zustand";

type ConnectionStatus = "idle" | "connecting" | "connected" | "offline" | "error";

export type WebProjectRow = {
  projectId: string;
  projectRoot: string;
  displayName: string;
  sessionCount: number;
  archivedCount: number;
  attentionCount: number;
};

export type WebSessionSummary = {
  sessionId: string;
  projectId: string;
  projectRoot: string;
  title: string;
  shortId?: string;
  status: string;
  archived: boolean;
  pinned: boolean;
  forkCount: number;
  turnCount: number;
  attention: { kind: "approval"; interruptId: string } | null;
  updatedAt: number;
  createdBy: { userId: string; displayName?: string; origin?: string } | null;
  agent: string;
  model?: string;
  sharedWithCollaborators: boolean;
};

export type WebInterrupt = {
  interruptId: string;
  kind: "question" | "approval";
  title: string;
  body?: string;
  resolved: boolean;
  question: InterruptQuestion;
};

export type WebHistoryEntry =
  | {
      id: string;
      seq: number;
      ts?: number;
      kind:
        | "user_message"
        | "user_note"
        | "assistant_text"
        | "assistant_reasoning"
        | "inference_error";
      text: string;
      actor?: { userId?: string; displayName?: string; origin?: string };
    }
  | {
      id: string;
      seq: number;
      ts?: number;
      kind: "tool_call";
      callId: string;
      name: string;
      status: "running" | "succeeded" | "failed";
      input?: unknown;
      output?: unknown;
    }
  | { id: string; seq: number; ts?: number; kind: "boundary"; label: string }
  | { id: string; seq: number; ts?: number; kind: "subagent_report"; title: string; body: string }
  | { id: string; seq: number; ts?: number; kind: "interrupt"; interrupt: WebInterrupt }
  | {
      id: string;
      seq: number;
      ts?: number;
      kind: "interrupt_decision";
      decision: {
        permission: boolean;
        cancelled: boolean;
        lines: { prompt: string; answer: string }[];
      };
    };

export type WebUsage = {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
};

export type SessionPagingState = {
  oldestSeq: number | null;
  hasMore: boolean;
  isLoading: boolean;
  error: string | null;
};

const webInterruptResolutionValues = ["approve", "deny", "answer"] as const;
export type WebInterruptResolution = (typeof webInterruptResolutionValues)[number];

export type SessionDetail = {
  summary: WebSessionSummary;
  history: WebHistoryEntry[];
  schedules: unknown[];
  nextSeq: number;
  usage: WebUsage | null;
  paging: SessionPagingState;
};

type InstanceRemoteState = {
  status: ConnectionStatus;
  statusDetail?: string;
  projects: WebProjectRow[];
  sessionsByProject: Record<string, WebSessionSummary[]>;
  detailsBySession: Record<string, SessionDetail>;
  statsRollupByProject: Record<string, unknown>;
};

type TokenInfo = { token: string; relayUrl: string };

type RemoteSessionState = {
  instances: Record<string, InstanceRemoteState>;
  clients: Record<string, RemoteSessionClient | undefined>;
  ensureInstance: (instanceId: string) => void;
  connect: (instanceId: string, tokenInfo: TokenInfo) => void;
  disconnect: (instanceId: string) => void;
  loadProjects: (instanceId: string) => Promise<void>;
  loadSessions: (instanceId: string, projectRoot: string) => Promise<void>;
  loadStatsRollup: (instanceId: string, projectId: string) => Promise<void>;
  attach: (instanceId: string, sessionId: string) => Promise<void>;
  loadOlderHistory: (instanceId: string, sessionId: string) => Promise<void>;
  createSession: (
    instanceId: string,
    input: { projectRoot: string; title?: string; agent?: string; model?: string },
  ) => Promise<SessionDetail>;
  sendMessage: (instanceId: string, sessionId: string, text: string) => Promise<void>;
  resolveInterrupt: (
    instanceId: string,
    input: {
      sessionId: string;
      interruptId: string;
      resolution: WebInterruptResolution;
      answer?: string;
    },
  ) => Promise<void>;
  renameSession: (instanceId: string, sessionId: string, title: string) => Promise<void>;
  archiveSession: (instanceId: string, sessionId: string, archived: boolean) => Promise<void>;
  shareSession: (instanceId: string, sessionId: string, shared: boolean) => Promise<void>;
  forkSession: (instanceId: string, sessionId: string) => Promise<void>;
  listFiles: (
    instanceId: string,
    input: { projectRoot: string; path: string; showHidden: boolean },
  ) => Promise<FsListResult>;
  readFile: (
    instanceId: string,
    input: { projectRoot: string; path: string },
  ) => Promise<FsReadResult>;
  writeFile: (
    instanceId: string,
    input: { projectRoot: string; path: string; content: string; baseHash?: string },
  ) => Promise<FsWriteResult>;
  createDirectory: (
    instanceId: string,
    input: { projectRoot: string; path: string },
  ) => Promise<void>;
  renamePath: (
    instanceId: string,
    input: { projectRoot: string; fromPath: string; toPath: string },
  ) => Promise<void>;
  deletePath: (instanceId: string, input: { projectRoot: string; path: string }) => Promise<void>;
  gitStatus: (instanceId: string, input: { projectRoot: string }) => Promise<GitStatusResult>;
  gitDiffFile: (
    instanceId: string,
    input: { projectRoot: string; path: string },
  ) => Promise<GitDiffFileResult>;
};

const pendingAssistantId = "assistant:pending";
const pendingReasoningId = "reasoning:pending";
const pendingUserPrefix = "user:pending:";
const pendingUserSeq = Number.MAX_SAFE_INTEGER - 3;
const pendingReasoningSeq = Number.MAX_SAFE_INTEGER - 2;
const pendingAssistantSeq = Number.MAX_SAFE_INTEGER - 1;
const pendingInterruptSeq = Number.MAX_SAFE_INTEGER;
const warnedEventKinds = new Set<string>();
const historyPageInFlight = new Set<string>();
const historyPageLimit = 100;

const emptyInstance = (): InstanceRemoteState => ({
  status: "idle",
  projects: [],
  sessionsByProject: {},
  detailsBySession: {},
  statsRollupByProject: {},
});

function stringField(record: Record<string, unknown>, key: string) {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function numberField(record: Record<string, unknown>, key: string) {
  const value = record[key];
  return typeof value === "number" ? value : undefined;
}

function booleanField(record: Record<string, unknown>, key: string) {
  const value = record[key];
  return typeof value === "boolean" ? value : undefined;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Could not load older history.";
}

function recordField(record: Record<string, unknown>, key: string) {
  const value = record[key];
  return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
}

function eventData(event: EventEnvelope) {
  const data = event.data;
  return data && typeof data === "object" ? (data as Record<string, unknown>) : null;
}

function sortHistory(history: WebHistoryEntry[]) {
  return [...history].sort((a, b) => a.seq - b.seq || a.id.localeCompare(b.id));
}

function upsertHistory(history: WebHistoryEntry[], entry: WebHistoryEntry) {
  return sortHistory([entry, ...history.filter((item) => item.id !== entry.id)]);
}

function nextLocalSeq(history: WebHistoryEntry[]) {
  const maxSeq = history.reduce(
    (max, entry) => (entry.seq < pendingUserSeq ? Math.max(max, entry.seq) : max),
    0,
  );
  return maxSeq + 1;
}

function oldestSeqFromHistory(history: WebHistoryEntry[]) {
  const oldest = history.reduce<number | null>((min, entry) => {
    if (entry.seq >= pendingUserSeq) return min;
    return min === null ? entry.seq : Math.min(min, entry.seq);
  }, null);
  return oldest;
}

function pagingFromHistory(
  history: WebHistoryEntry[],
  current?: SessionPagingState,
): SessionPagingState {
  const oldestSeq = oldestSeqFromHistory(history);
  return {
    oldestSeq,
    hasMore: current?.hasMore ?? oldestSeq !== null,
    isLoading: current?.isLoading ?? false,
    error: null,
  };
}

function historyPageOldestSeq(page: HistoryPageResult) {
  const raw = page as HistoryPageResult & { oldest_seq?: unknown };
  return typeof raw.oldest_seq === "number" ? raw.oldest_seq : null;
}

function historyMergeKey(entry: WebHistoryEntry) {
  if (
    entry.seq >= pendingUserSeq ||
    entry.id === pendingAssistantId ||
    entry.id === pendingReasoningId ||
    entry.id.startsWith(pendingUserPrefix) ||
    (entry.kind === "tool_call" && entry.status === "running")
  ) {
    return `id:${entry.id}`;
  }
  return `seq:${entry.seq}`;
}

function mergeHistoryEntries(history: WebHistoryEntry[], entries: WebHistoryEntry[]) {
  const byKey = new Map<string, WebHistoryEntry>();
  for (const entry of entries) byKey.set(historyMergeKey(entry), entry);
  for (const entry of history) byKey.set(historyMergeKey(entry), entry);
  return sortHistory([...byKey.values()]);
}

function mergeHistorySnapshot(current: WebHistoryEntry[], snapshot: WebHistoryEntry[]) {
  if (!snapshot.length) return sortHistory(current);
  const nextSeq = nextSeqFromHistory(snapshot);
  const oldestSnapshotSeq = oldestSeqFromHistory(snapshot);
  const snapshotIds = new Set(snapshot.map((entry) => entry.id));
  const preserved = current.filter(
    (entry) =>
      !snapshotIds.has(entry.id) &&
      ((oldestSnapshotSeq !== null && entry.seq < oldestSnapshotSeq) || entry.seq >= nextSeq),
  );
  return mergeHistoryEntries(snapshot, preserved);
}

export function mergeHistoryPage(detail: SessionDetail, page: HistoryPageResult): SessionDetail {
  const pageEntries = page.entries.map((entry, index) => toWebHistoryEntry(entry, index));
  const history = mergeHistoryEntries(detail.history, pageEntries);
  return {
    ...detail,
    history,
    nextSeq: nextSeqFromHistory(history),
    paging: {
      oldestSeq: historyPageOldestSeq(page) ?? oldestSeqFromHistory(history),
      hasMore: page.has_more,
      isLoading: false,
      error: null,
    },
  };
}

export function markHistoryPageLoading(detail: SessionDetail): SessionDetail {
  return { ...detail, paging: { ...detail.paging, isLoading: true, error: null } };
}

export function markHistoryPageError(detail: SessionDetail, error: string): SessionDetail {
  return { ...detail, paging: { ...detail.paging, isLoading: false, error } };
}

function projectDisplayName(projectRoot: string) {
  return projectRoot.split("/").filter(Boolean).at(-1) ?? projectRoot;
}

export function interruptDecisionView(entry: WebHistoryEntry): {
  interactive: false;
  permission: boolean;
  cancelled: boolean;
  lines: { prompt: string; answer: string }[];
} | null {
  if (entry.kind !== "interrupt_decision") return null;
  return {
    interactive: false,
    permission: entry.decision.permission,
    cancelled: entry.decision.cancelled,
    lines: entry.decision.lines,
  };
}

export function toWebSessionSummary(session: WireSessionSummary): WebSessionSummary {
  const raw = session as Record<string, unknown>;
  const createdByPrincipal = stringField(raw, "created_by_principal");
  return {
    sessionId: session.session_id,
    projectId: session.project_id,
    projectRoot: session.project_root,
    title: session.title ?? session.short_id ?? session.session_id,
    shortId: session.short_id,
    status: stringField(raw, "activity_state") ?? "idle",
    archived: booleanField(raw, "archived") ?? false,
    pinned: booleanField(raw, "pinned") ?? false,
    forkCount: numberField(raw, "fork_count") ?? 0,
    turnCount: session.turns,
    attention: null,
    updatedAt: session.last_active_at,
    createdBy: createdByPrincipal ? { userId: createdByPrincipal, origin: "daemon" } : null,
    agent: session.active_agent,
    model: stringField(raw, "model"),
    sharedWithCollaborators: session.shared_with_collaborators ?? false,
  };
}

export function projectsFromSessions(sessions: WireSessionSummary[]): WebProjectRow[] {
  const projects = new Map<string, WebProjectRow>();
  for (const session of sessions) {
    const summary = toWebSessionSummary(session);
    const existing = projects.get(summary.projectId);
    if (existing) {
      existing.sessionCount += 1;
      if (summary.archived) existing.archivedCount += 1;
      if (summary.attention) existing.attentionCount += 1;
      continue;
    }
    projects.set(summary.projectId, {
      projectId: summary.projectId,
      projectRoot: summary.projectRoot,
      displayName: projectDisplayName(summary.projectRoot),
      sessionCount: 1,
      archivedCount: summary.archived ? 1 : 0,
      attentionCount: summary.attention ? 1 : 0,
    });
  }
  return [...projects.values()].sort((a, b) => a.projectRoot.localeCompare(b.projectRoot));
}

function toWebHistoryEntry(entry: WireHistoryEntry, fallbackSeq = 0): WebHistoryEntry {
  const seq = typeof entry.seq === "number" ? entry.seq : fallbackSeq;
  if (entry.role === "user") {
    return {
      id: "user:" + seq,
      seq,
      ts: entry.ts_ms ? Math.floor(entry.ts_ms / 1000) : undefined,
      kind: "user_message",
      text: entry.display_text ?? entry.text,
      actor: { origin: entry.origin_principal ?? "daemon" },
    };
  }
  if (entry.role === "user_note") {
    return { id: "user-note:" + seq, seq, ts: entry.ts_ms, kind: "user_note", text: entry.text };
  }
  if (entry.role === "assistant") {
    return {
      id: "assistant:" + seq,
      seq,
      ts: entry.ts_ms ? Math.floor(entry.ts_ms / 1000) : undefined,
      kind: "assistant_text",
      text: entry.text,
    };
  }
  if (entry.role === "tool_call") {
    return {
      id: "tool:" + entry.call_id,
      seq,
      kind: "tool_call",
      callId: entry.call_id,
      name: entry.tool,
      status: entry.hard_fail ? "failed" : "succeeded",
      input: entry.original_input,
      output: entry.output,
    };
  }
  if (entry.role === "inference_error") {
    return {
      id: "inference:" + seq,
      seq,
      kind: "inference_error",
      text: entry.detail ? `${entry.summary}\n${entry.detail}` : entry.summary,
    };
  }
  if (entry.role === "compact_boundary") {
    return {
      id: "boundary:" + seq,
      seq,
      kind: "boundary",
      label: entry.brief ?? `Compact handoff from ${entry.predecessor_short_id}`,
    };
  }
  if (entry.role === "subagent") {
    return {
      id: "subagent:" + entry.task_call_id,
      seq,
      kind: "subagent_report",
      title: entry.label,
      body: `${entry.parent} -> ${entry.child}`,
    };
  }
  return {
    id: "interrupt-decision:" + seq,
    seq,
    kind: "interrupt_decision",
    decision: {
      permission: entry.decision.permission,
      cancelled: entry.decision.cancelled,
      lines: entry.decision.lines,
    },
  };
}

function nextSeqFromHistory(history: WebHistoryEntry[]) {
  return history.reduce(
    (max, entry) => (entry.seq < pendingUserSeq ? Math.max(max, entry.seq + 1) : max),
    1,
  );
}

function attachSummary(attach: AttachResult, current?: WebSessionSummary): WebSessionSummary {
  return {
    sessionId: attach.session_id,
    projectId: attach.project_id,
    projectRoot: attach.project_root,
    title: current?.title ?? attach.short_id,
    shortId: attach.short_id,
    status: current?.status ?? "idle",
    archived: current?.archived ?? false,
    pinned: current?.pinned ?? false,
    forkCount: current?.forkCount ?? 0,
    turnCount: current?.turnCount ?? 0,
    attention: current?.attention ?? null,
    updatedAt: current?.updatedAt ?? Date.now(),
    createdBy: current?.createdBy ?? null,
    agent: attach.active_agent,
    model: current?.model,
    sharedWithCollaborators: current?.sharedWithCollaborators ?? false,
  };
}

export function mergeAttach(
  existing: InstanceRemoteState,
  attach: AttachResult,
): InstanceRemoteState {
  const current = existing.detailsBySession[attach.session_id];
  const mappedHistory = attach.history.map((entry, index) => toWebHistoryEntry(entry, index));
  const mergedHistory = mergeHistorySnapshot(current?.history ?? [], mappedHistory);
  const summary = attachSummary(attach, current?.summary);
  return {
    ...existing,
    sessionsByProject: {
      ...existing.sessionsByProject,
      [summary.projectRoot]: upsertSession(
        existing.sessionsByProject[summary.projectRoot] ?? [],
        summary,
      ),
    },
    detailsBySession: {
      ...existing.detailsBySession,
      [summary.sessionId]: {
        summary,
        history: mergedHistory,
        schedules: current?.schedules ?? [],
        nextSeq: nextSeqFromHistory(mergedHistory),
        usage: current?.usage ?? null,
        paging: pagingFromHistory(mergedHistory, current?.paging),
      },
    },
  };
}

function upsertSession(sessions: WebSessionSummary[], summary: WebSessionSummary) {
  return [summary, ...sessions.filter((session) => session.sessionId !== summary.sessionId)].sort(
    (a, b) => b.updatedAt - a.updatedAt,
  );
}

function sessionIdFromEvent(event: EventEnvelope) {
  const data = eventData(event);
  return data ? stringField(data, "session_id") : undefined;
}

function eventWarningKind(raw: unknown) {
  if (!raw || typeof raw !== "object") return "unknown";
  const record = raw as Record<string, unknown>;
  const event = record.event ?? record.type;
  return typeof event === "string" && event ? event : "unknown";
}

function updateDetail(
  existing: InstanceRemoteState,
  sessionId: string,
  updater: (detail: SessionDetail) => SessionDetail,
) {
  const detail = existing.detailsBySession[sessionId];
  if (!detail) return existing;
  return {
    ...existing,
    detailsBySession: {
      ...existing.detailsBySession,
      [sessionId]: updater(detail),
    },
  };
}

function appendAssistantDelta(history: WebHistoryEntry[], delta: string) {
  const pending = history.find((entry) => entry.id === pendingAssistantId);
  if (pending?.kind === "assistant_text") {
    return history.map((entry) =>
      entry.id === pendingAssistantId && entry.kind === "assistant_text"
        ? { ...entry, text: entry.text + delta }
        : entry,
    );
  }
  return sortHistory([
    ...history,
    { id: pendingAssistantId, seq: pendingAssistantSeq, kind: "assistant_text", text: delta },
  ]);
}

function appendReasoningDelta(history: WebHistoryEntry[], delta: string) {
  const pending = history.find((entry) => entry.id === pendingReasoningId);
  if (pending?.kind === "assistant_reasoning") {
    return history.map((entry) =>
      entry.id === pendingReasoningId && entry.kind === "assistant_reasoning"
        ? { ...entry, text: entry.text + delta }
        : entry,
    );
  }
  return sortHistory([
    ...history,
    { id: pendingReasoningId, seq: pendingReasoningSeq, kind: "assistant_reasoning", text: delta },
  ]);
}

function applyAssistantText(history: WebHistoryEntry[], data: Record<string, unknown>) {
  const text = stringField(data, "text");
  if (!text) return null;
  const seq = numberField(data, "seq") ?? nextLocalSeq(history);
  return upsertHistory(
    history.filter((entry) => entry.id !== pendingAssistantId),
    { id: "assistant:" + seq, seq, kind: "assistant_text", text },
  );
}

function applyToolStart(history: WebHistoryEntry[], data: Record<string, unknown>) {
  const callId = stringField(data, "call_id");
  const tool = stringField(data, "tool");
  if (!callId || !tool) return null;
  return upsertHistory(history, {
    id: "tool:" + callId,
    seq: pendingInterruptSeq - 10,
    kind: "tool_call",
    callId,
    name: tool,
    status: "running",
    input: data.args,
  });
}

function applyToolFinish(
  history: WebHistoryEntry[],
  data: Record<string, unknown>,
  failed: boolean,
) {
  const callId = stringField(data, "call_id");
  const tool = stringField(data, "tool");
  if (!callId || !tool) return null;
  const seq = numberField(data, "seq") ?? nextLocalSeq(history);
  return upsertHistory(history, {
    id: "tool:" + callId,
    seq,
    kind: "tool_call",
    callId,
    name: tool,
    status: failed ? "failed" : "succeeded",
    output: failed ? stringField(data, "error") : stringField(data, "output"),
  });
}

function interruptQuestionTitle(question: InterruptQuestion) {
  return question.data.prompt;
}

function interruptQuestionBody(question: InterruptQuestion, fallback: string) {
  if (question.kind === "single") return question.data.command_detail?.full_command ?? fallback;
  return fallback;
}

function resolveResponseForInterrupt(
  question: InterruptQuestion,
  resolution: WebInterruptResolution,
  answer?: string,
): ResolveResponse {
  if (resolution === "deny") return { kind: "cancel" };
  if (question.kind === "freetext") return { kind: "freetext", data: { text: answer ?? "" } };
  if (question.kind === "multi") {
    const selected = question.data.options[0]?.id;
    return selected ? { kind: "multi", data: { selected_ids: [selected] } } : { kind: "cancel" };
  }
  const selected = question.data.options[0]?.id;
  return selected ? { kind: "single", data: { selected_id: selected } } : { kind: "cancel" };
}

function usageFromData(data: Record<string, unknown>): WebUsage {
  const inputTokens = numberField(data, "input_tokens") ?? 0;
  const outputTokens = numberField(data, "output_tokens") ?? 0;
  return {
    inputTokens,
    outputTokens,
    totalTokens: inputTokens + outputTokens,
  };
}

export function reduceRemoteSessionEvent(
  existing: InstanceRemoteState,
  raw: unknown,
): { state: InstanceRemoteState; warningKind?: string } {
  const parsed = eventEnvelopeSchema.safeParse(raw);
  if (!parsed.success) return { state: existing, warningKind: eventWarningKind(raw) };
  const event = parsed.data;
  if ("__unknown" in event && event.__unknown) {
    return { state: existing, warningKind: event.event };
  }

  const data = eventData(event);
  const sessionId = sessionIdFromEvent(event);

  if (event.event === "assistant_text_delta") {
    if (!sessionId || typeof data?.delta !== "string")
      return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        history: appendAssistantDelta(detail.history, data.delta as string),
      })),
    };
  }

  if (event.event === "reasoning_delta") {
    if (!sessionId || typeof data?.delta !== "string")
      return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        history: appendReasoningDelta(detail.history, data.delta as string),
      })),
    };
  }

  if (event.event === "assistant_text") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    if (typeof data.text !== "string") return { state: existing, warningKind: event.event };
    const state = updateDetail(existing, sessionId, (detail) => {
      const history = applyAssistantText(detail.history, data);
      if (!history) return detail;
      return { ...detail, history, nextSeq: nextSeqFromHistory(history) };
    });
    return { state };
  }

  if (event.event === "history_replay") {
    const entries = data?.entries;
    if (!sessionId || !Array.isArray(entries)) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const replayedHistory = sortHistory(
          entries.map((entry, index) => toWebHistoryEntry(entry as WireHistoryEntry, index)),
        );
        const history = mergeHistorySnapshot(detail.history, replayedHistory);
        return {
          ...detail,
          history,
          nextSeq: nextSeqFromHistory(history),
          paging: pagingFromHistory(history, detail.paging),
        };
      }),
    };
  }

  if (event.event === "user_message_recorded") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const pending = detail.history.find(
          (entry) => entry.kind === "user_message" && entry.id.startsWith(pendingUserPrefix),
        );
        const text =
          stringField(data, "preflight_cleaned") ??
          (pending?.kind === "user_message" ? pending.text : null);
        if (!text) return detail;
        const seq = numberField(data, "seq") ?? nextLocalSeq(detail.history);
        const history = upsertHistory(
          detail.history.filter((entry) => entry.id !== pending?.id),
          { id: "user:" + seq, seq, kind: "user_message", text, actor: { origin: "web" } },
        );
        return { ...detail, history, nextSeq: nextSeqFromHistory(history) };
      }),
    };
  }

  if (event.event === "tool_start") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    if (!stringField(data, "call_id") || !stringField(data, "tool"))
      return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const history = applyToolStart(detail.history, data);
        return history ? { ...detail, history } : detail;
      }),
    };
  }

  if (event.event === "tool_end" || event.event === "tool_error") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    if (!stringField(data, "call_id") || !stringField(data, "tool"))
      return { state: existing, warningKind: event.event };
    if (event.event === "tool_end" && typeof data.output !== "string")
      return { state: existing, warningKind: event.event };
    if (event.event === "tool_error" && typeof data.error !== "string")
      return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const history = applyToolFinish(detail.history, data, event.event === "tool_error");
        return history ? { ...detail, history, nextSeq: nextSeqFromHistory(history) } : detail;
      }),
    };
  }

  if (event.event === "interrupt_raised") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const interruptId = stringField(data, "interrupt_id");
    const description = stringField(data, "description") ?? "";
    const question = data.question as InterruptQuestion | null | undefined;
    if (!interruptId || !question) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        history: upsertHistory(detail.history, {
          id: "interrupt:" + interruptId,
          seq: pendingInterruptSeq,
          kind: "interrupt",
          interrupt: {
            interruptId,
            kind: question.kind === "freetext" ? "question" : "approval",
            title: interruptQuestionTitle(question),
            body: interruptQuestionBody(question, description),
            resolved: false,
            question,
          },
        }),
      })),
    };
  }

  if (event.event === "interrupt_resolved") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const interruptId = stringField(data, "interrupt_id");
    if (!interruptId) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        history: detail.history.map((entry) =>
          entry.kind === "interrupt" && entry.interrupt.interruptId === interruptId
            ? { ...entry, interrupt: { ...entry.interrupt, resolved: true } }
            : entry,
        ),
        nextSeq: Math.max(detail.nextSeq, (numberField(data, "seq") ?? detail.nextSeq - 1) + 1),
      })),
    };
  }

  if (event.event === "usage") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        usage: usageFromData(data),
      })),
    };
  }

  if (event.event === "agent_idle") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const reason = recordField(data, "reason");
    const status = reason ? stringField(reason, "kind") : undefined;
    if (!status) return { state: existing, warningKind: event.event };
    return { state: updateSessionSummary(existing, sessionId, { status }) };
  }

  return { state: existing, warningKind: event.event };
}

export function applyLiveEvent(
  existing: InstanceRemoteState,
  event: EventEnvelope,
): InstanceRemoteState {
  return reduceRemoteSessionEvent(existing, event).state;
}

export function warnUnhandledRemoteSessionEvent(
  kind: string | undefined,
  prod = import.meta.env.PROD,
) {
  if (!kind || prod || warnedEventKinds.has(kind)) return;
  warnedEventKinds.add(kind);
  console.warn(`[remote-sessions] unhandled event: ${kind}`);
}

export function resetRemoteSessionEventWarningsForTests() {
  warnedEventKinds.clear();
  historyPageInFlight.clear();
}

export function addOptimisticUserMessage(
  existing: InstanceRemoteState,
  sessionId: string,
  text: string,
  clientMessageId: string,
): InstanceRemoteState {
  return updateDetail(existing, sessionId, (detail) => {
    const history = upsertHistory(detail.history, {
      id: pendingUserPrefix + clientMessageId,
      seq: pendingUserSeq,
      kind: "user_message",
      text,
      actor: { origin: "web" },
    });
    return { ...detail, history };
  });
}

export function updateSessionSharedWithCollaborators(
  existing: InstanceRemoteState,
  sessionId: string,
  sharedWithCollaborators: boolean,
): InstanceRemoteState {
  const updateSummary = (summary: WebSessionSummary): WebSessionSummary =>
    summary.sessionId === sessionId ? { ...summary, sharedWithCollaborators } : summary;
  const sessionsByProject = Object.fromEntries(
    Object.entries(existing.sessionsByProject).map(([projectRoot, sessions]) => [
      projectRoot,
      sessions.map(updateSummary),
    ]),
  );
  const detail = existing.detailsBySession[sessionId];
  return {
    ...existing,
    sessionsByProject,
    detailsBySession: detail
      ? {
          ...existing.detailsBySession,
          [sessionId]: { ...detail, summary: updateSummary(detail.summary) },
        }
      : existing.detailsBySession,
  };
}

function setInstance(
  instances: Record<string, InstanceRemoteState>,
  instanceId: string,
  updater: (current: InstanceRemoteState) => InstanceRemoteState,
) {
  return { ...instances, [instanceId]: updater(instances[instanceId] ?? emptyInstance()) };
}

function projectIdForRoot(current: InstanceRemoteState, projectRoot: string) {
  return (
    current.projects.find((project) => project.projectRoot === projectRoot)?.projectId ??
    projectRoot
  );
}

export const useRemoteSessionsStore = create<RemoteSessionState>()((set, get) => ({
  instances: {},
  clients: {},
  ensureInstance: (instanceId) => {
    set((state) => ({ instances: setInstance(state.instances, instanceId, (current) => current) }));
  },
  connect: (instanceId, tokenInfo) => {
    const current = get().clients[instanceId];
    if (current) return;
    const client = new RemoteSessionClient({
      instanceId,
      relayUrl: tokenInfo.relayUrl,
      token: tokenInfo.token,
      baseUrl: window.location.origin,
      onStatus: (status, statusDetail) => {
        set((state) => ({
          instances: setInstance(state.instances, instanceId, (current) => ({
            ...current,
            status,
            statusDetail,
          })),
        }));
      },
      onEvent: (event) => {
        set((state) => {
          const result = reduceRemoteSessionEvent(
            state.instances[instanceId] ?? emptyInstance(),
            event,
          );
          warnUnhandledRemoteSessionEvent(result.warningKind);
          return {
            instances: { ...state.instances, [instanceId]: result.state },
          };
        });
      },
    });
    set((state) => ({
      clients: { ...state.clients, [instanceId]: client },
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        status: "connecting",
      })),
    }));
    client.connect();
  },
  disconnect: (instanceId) => {
    get().clients[instanceId]?.close();
    set((state) => ({
      clients: { ...state.clients, [instanceId]: undefined },
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        status: "offline",
      })),
    }));
  },
  loadProjects: async (instanceId) => {
    const result = await get().clients[instanceId]?.listSessions({});
    if (!result) return;
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        projects: projectsFromSessions(result.sessions),
      })),
    }));
  },
  loadSessions: async (instanceId, projectRoot) => {
    const current = get().instances[instanceId] ?? emptyInstance();
    const result = await get().clients[instanceId]?.listSessions({
      project_id: projectIdForRoot(current, projectRoot),
    });
    if (!result) return;
    const sessions = result.sessions.map(toWebSessionSummary);
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        sessionsByProject: { ...current.sessionsByProject, [projectRoot]: sessions },
      })),
    }));
  },
  loadStatsRollup: async (instanceId, projectId) => {
    let result: unknown;
    try {
      result = await get().clients[instanceId]?.statsRollup({
        project_id: projectId,
        range: "all_time",
      });
    } catch {
      return;
    }
    const rollup =
      result && typeof result === "object" && "rollup" in result ? result.rollup : null;
    if (!rollup) return;
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        statsRollupByProject: { ...current.statsRollupByProject, [projectId]: rollup },
      })),
    }));
  },
  attach: async (instanceId, sessionId) => {
    const result = await get().clients[instanceId]?.attach({
      session_id: sessionId,
      interactive: true,
    });
    if (!result) return;
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) =>
        mergeAttach(current, result),
      ),
    }));
  },
  loadOlderHistory: async (instanceId, sessionId) => {
    const client = get().clients[instanceId];
    const detail = get().instances[instanceId]?.detailsBySession[sessionId];
    const inFlightKey = `${instanceId}:${sessionId}`;
    if (
      !client ||
      !detail ||
      detail.paging.isLoading ||
      !detail.paging.hasMore ||
      historyPageInFlight.has(inFlightKey)
    ) {
      return;
    }

    historyPageInFlight.add(inFlightKey);
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) =>
        updateDetail(current, sessionId, markHistoryPageLoading),
      ),
    }));

    try {
      const page = await client.readHistoryPage({
        session_id: sessionId,
        before_seq: detail.paging.oldestSeq,
        limit: historyPageLimit,
      });
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) =>
          updateDetail(current, sessionId, (detail) => mergeHistoryPage(detail, page)),
        ),
      }));
    } catch (error) {
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) =>
          updateDetail(current, sessionId, (detail) =>
            markHistoryPageError(detail, errorMessage(error)),
          ),
        ),
      }));
    } finally {
      historyPageInFlight.delete(inFlightKey);
    }
  },
  createSession: async (instanceId, input) => {
    const result = await get().clients[instanceId]?.attach({
      project_root: input.projectRoot,
      interactive: true,
      model_override: input.model,
    });
    if (!result) throw new Error("Instance connection is not open.");
    let created: SessionDetail | null = null;
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => {
        const next = mergeAttach(current, result);
        created = next.detailsBySession[result.session_id] ?? null;
        return next;
      }),
    }));
    if (!created) throw new Error("Instance did not return a session.");
    if (input.agent) await get().clients[instanceId]?.setAgent(input.agent);
    if (input.title) await get().clients[instanceId]?.renameSession(result.session_id, input.title);
    if (input.agent || input.title) {
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) =>
          updateSessionSummary(current, result.session_id, {
            agent: input.agent ?? created?.summary.agent,
            title: input.title ?? created?.summary.title,
          }),
        ),
      }));
    }
    return created;
  },
  sendMessage: async (instanceId, sessionId, text) => {
    const clientMessageId = crypto.randomUUID();
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) =>
        addOptimisticUserMessage(current, sessionId, text, clientMessageId),
      ),
    }));
    await get().clients[instanceId]?.sendUserMessage({ text });
  },
  resolveInterrupt: async (instanceId, input) => {
    const detail = get().instances[instanceId]?.detailsBySession[input.sessionId];
    const entry = detail?.history.find(
      (entry) => entry.kind === "interrupt" && entry.interrupt.interruptId === input.interruptId,
    );
    if (entry?.kind !== "interrupt") return;
    await get().clients[instanceId]?.resolveInterrupt(
      input.interruptId,
      resolveResponseForInterrupt(entry.interrupt.question, input.resolution, input.answer),
    );
  },
  renameSession: async (instanceId, sessionId, title) => {
    await get().clients[instanceId]?.renameSession(sessionId, title);
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) =>
        updateSessionSummary(current, sessionId, { title }),
      ),
    }));
  },
  archiveSession: async (instanceId, sessionId, archived) => {
    if (archived) await get().clients[instanceId]?.archiveSession(sessionId);
    else await get().clients[instanceId]?.unarchiveSession(sessionId);
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) =>
        updateSessionSummary(current, sessionId, { archived }),
      ),
    }));
  },
  shareSession: async (instanceId, sessionId, shared) => {
    const client = get().clients[instanceId];
    if (!client) throw new Error("Instance connection is not open.");
    const current = get().instances[instanceId];
    const previous = current?.detailsBySession[sessionId]?.summary.sharedWithCollaborators;
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) =>
        updateSessionSharedWithCollaborators(current, sessionId, shared),
      ),
    }));
    try {
      await client.shareSession(sessionId, shared);
    } catch (error) {
      if (previous !== undefined) {
        set((state) => ({
          instances: setInstance(state.instances, instanceId, (current) =>
            updateSessionSharedWithCollaborators(current, sessionId, previous),
          ),
        }));
      }
      throw error;
    }
  },
  forkSession: async (instanceId, sessionId) => {
    await get().clients[instanceId]?.forkSession({ parent_session_id: sessionId });
  },
  listFiles: async (instanceId, input) => {
    const result = await get().clients[instanceId]?.listFiles(
      input.projectRoot,
      input.path,
      input.showHidden,
    );
    if (!result) throw new Error("Instance connection is not open.");
    return result;
  },
  readFile: async (instanceId, input) => {
    const result = await get().clients[instanceId]?.readFile(input.projectRoot, input.path);
    if (!result) throw new Error("Instance connection is not open.");
    return result;
  },
  writeFile: async (instanceId, input) => {
    const result = await get().clients[instanceId]?.writeFile(
      input.projectRoot,
      input.path,
      input.content,
      input.baseHash,
    );
    if (!result) throw new Error("Instance connection is not open.");
    return result;
  },
  createDirectory: async (instanceId, input) => {
    const client = get().clients[instanceId];
    if (!client) throw new Error("Instance connection is not open.");
    await client.createDirectory(input.projectRoot, input.path);
  },
  renamePath: async (instanceId, input) => {
    const client = get().clients[instanceId];
    if (!client) throw new Error("Instance connection is not open.");
    await client.renamePath(input.projectRoot, input.fromPath, input.toPath);
  },
  deletePath: async (instanceId, input) => {
    const client = get().clients[instanceId];
    if (!client) throw new Error("Instance connection is not open.");
    await client.deletePath(input.projectRoot, input.path);
  },
  gitStatus: async (instanceId, input) => {
    const result = await get().clients[instanceId]?.gitStatus(input.projectRoot);
    if (!result) throw new Error("Instance connection is not open.");
    return result;
  },
  gitDiffFile: async (instanceId, input) => {
    const result = await get().clients[instanceId]?.gitDiffFile(input.projectRoot, input.path);
    if (!result) throw new Error("Instance connection is not open.");
    return result;
  },
}));

function updateSessionSummary(
  existing: InstanceRemoteState,
  sessionId: string,
  patch: Partial<WebSessionSummary>,
) {
  const updateSummary = (summary: WebSessionSummary): WebSessionSummary =>
    summary.sessionId === sessionId ? { ...summary, ...patch } : summary;
  const sessionsByProject = Object.fromEntries(
    Object.entries(existing.sessionsByProject).map(([projectRoot, sessions]) => [
      projectRoot,
      sessions.map(updateSummary),
    ]),
  );
  const detail = existing.detailsBySession[sessionId];
  return {
    ...existing,
    sessionsByProject,
    detailsBySession: detail
      ? {
          ...existing.detailsBySession,
          [sessionId]: { ...detail, summary: updateSummary(detail.summary) },
        }
      : existing.detailsBySession,
  };
}
