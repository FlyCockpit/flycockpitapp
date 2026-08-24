import {
  type AttachResult,
  activeModelStateSchema,
  createClientSubmissionId,
  type EventEnvelope,
  eventEnvelopeSchema,
  type HistoryEntry,
  type InterruptQuestion,
  modelSelectionResultDataSchema,
} from "@flycockpit/cockpit-protocol";
import type { SendUserMessageParams } from "@flycockpit/cockpit-protocol/client";
import { daemonStateReducer, emptyNativeDaemonState, type NativeDaemonState } from "./daemon-state";
import {
  type ActiveModelState,
  type AuthFailureKind,
  activeModelReducer,
  type InferenceFailureView,
  inferenceFailureView,
} from "./inference-failure-view";

export const NATIVE_REMOTE_EVENT_WARN_PREFIX = "[native-remote] unknown event";

export type NativeInterrupt = {
  interruptId: string;
  kind: "question" | "approval";
  title: string;
  body?: string;
  resolved: boolean;
  question: InterruptQuestion;
};

export type NativeHistoryEntry =
  | {
      id: string;
      seq: number;
      kind: "user_message" | "user_note" | "assistant_text" | "assistant_reasoning";
      text: string;
    }
  | {
      id: string;
      seq: number;
      kind: "inference_error";
      view: InferenceFailureView;
    }
  | {
      id: string;
      seq: number;
      kind: "tool_call";
      name: string;
      status: string;
    }
  | {
      id: string;
      seq: number;
      kind: "boundary";
      label: string;
    }
  | {
      id: string;
      seq: number;
      kind: "subagent_report";
      title: string;
      body: string;
    }
  | {
      id: string;
      seq: number;
      kind: "interrupt";
      interrupt: NativeInterrupt;
    }
  | {
      id: string;
      seq: number;
      kind: "interrupt_decision";
      decision: {
        permission: boolean;
        cancelled: boolean;
        lines: { prompt: string; answer: string }[];
      };
    };

export type NativeSessionEventState = {
  history: NativeHistoryEntry[];
  selectedSessionId: string | null;
  daemonState?: NativeDaemonState;
  activeModel?: ActiveModelState | null;
  llmMode?: string | null;
};

export type NativeSessionEventResult = {
  state: NativeSessionEventState;
  warning?: string;
};

export type NativeAttachRuntimeState = {
  daemonState: NativeDaemonState;
  activeModel: ActiveModelState | null;
  llmMode: string | null;
};

const pendingAssistantId = "assistant:pending";
const pendingReasoningId = "assistant:reasoning:pending";
const pendingDisplayReasoningPrefix = `${pendingReasoningId}:`;
const pendingUserPrefix = "user:pending:";
const pendingUserSeq = Number.MAX_SAFE_INTEGER - 2;
const pendingAssistantSeq = Number.MAX_SAFE_INTEGER - 1;
const pendingReasoningSeq = Number.MAX_SAFE_INTEGER - 3;
const pendingInterruptSeq = Number.MAX_SAFE_INTEGER;

function pendingDisplayId(attemptId: string | number) {
  return `${pendingAssistantId}:${attemptId}`;
}

function pendingDisplayReasoningId(attemptId: string | number) {
  return `${pendingReasoningId}:${attemptId}`;
}

function rawEventName(raw: unknown) {
  if (!raw || typeof raw !== "object") return "unknown";
  const record = raw as Record<string, unknown>;
  const name = record.event ?? record.type;
  return typeof name === "string" && name ? name : "unknown";
}

function eventWarning(event: string) {
  return `${NATIVE_REMOTE_EVENT_WARN_PREFIX}: ${event}`;
}

function eventDataRecord(event: EventEnvelope) {
  const data = event.data;
  return data && typeof data === "object" ? (data as Record<string, unknown>) : null;
}

function eventStateWithDaemon(
  state: NativeSessionEventState,
  event: EventEnvelope,
): NativeSessionEventState {
  return {
    ...state,
    daemonState: daemonStateReducer(
      state.daemonState ?? emptyNativeDaemonState,
      event,
      state.selectedSessionId,
    ),
  };
}

function activeModelInputFromRecord(value: unknown) {
  const parsed = activeModelStateSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

function authFailureFromData(value: unknown): AuthFailureKind | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (record.kind === "credentials_rejected") {
    return {
      kind: "credentials_rejected",
      status: typeof record.status === "number" ? record.status : null,
    };
  }
  if (record.kind === "missing_entitlement") {
    return {
      kind: "missing_entitlement",
      feature: typeof record.feature === "string" ? record.feature : null,
    };
  }
  if (record.kind === "oauth_expired") {
    return {
      kind: "oauth_expired",
      provider: typeof record.provider === "string" ? record.provider : null,
    };
  }
  if (record.kind === "provider_not_configured") return { kind: "provider_not_configured" };
  return null;
}

function seqOf(entry: { seq?: number }, fallback: number) {
  return typeof entry.seq === "number" ? entry.seq : fallback;
}

function entryId(prefix: string, seq: number) {
  return `${prefix}:${seq}`;
}

function nextLocalSeq(history: NativeHistoryEntry[]) {
  const maxSeq = history.reduce(
    (max, entry) => (entry.seq < pendingUserSeq ? Math.max(max, entry.seq) : max),
    0,
  );
  return maxSeq + 1;
}

export function toNativeHistoryEntry(entry: HistoryEntry, fallbackSeq = 0): NativeHistoryEntry {
  const seq = seqOf(entry, fallbackSeq);
  if (entry.role === "user") {
    return {
      id: entryId("user", seq),
      seq,
      kind: "user_message",
      text: entry.display_text ?? entry.text,
    };
  }
  if (entry.role === "user_note") {
    return {
      id: entryId("user-note", seq),
      seq,
      kind: "user_note",
      text: entry.text,
    };
  }
  if (entry.role === "assistant") {
    const assistant = entry as HistoryEntry & {
      presentation_text?: string | null;
      text: string;
    };
    return {
      id: entryId("assistant", seq),
      seq,
      kind: "assistant_text",
      text: assistant.presentation_text ?? assistant.text,
    };
  }
  if (entry.role === "tool_call") {
    return {
      id: entryId("tool", seq),
      seq,
      kind: "tool_call",
      name: entry.tool,
      status: entry.hard_fail ? "failed" : "succeeded",
    };
  }
  if (entry.role === "inference_error") {
    return {
      id: entryId("inference", seq),
      seq,
      kind: "inference_error",
      view: inferenceFailureView({
        error_class: entry.summary,
        detail: entry.detail ?? entry.summary,
      }),
    };
  }
  if (entry.role === "compact_boundary") {
    return {
      id: entryId("boundary", seq),
      seq,
      kind: "boundary",
      label: entry.brief ?? `Compact handoff from ${entry.predecessor_short_id}`,
    };
  }
  if (entry.role === "subagent") {
    return {
      id: entryId("subagent", seq),
      seq,
      kind: "subagent_report",
      title: entry.label,
      body: `${entry.parent} -> ${entry.child}`,
    };
  }
  if (entry.role === "interrupt_decision") {
    const decision =
      entry.decision && typeof entry.decision === "object"
        ? (entry.decision as {
            permission?: unknown;
            cancelled?: unknown;
            lines?: unknown;
          })
        : null;
    const lines = Array.isArray(decision?.lines)
      ? decision.lines.filter((line): line is { prompt: string; answer: string } => {
          if (!line || typeof line !== "object") return false;
          const record = line as Record<string, unknown>;
          return typeof record.prompt === "string" && typeof record.answer === "string";
        })
      : [];
    return {
      id: entryId("interrupt-decision", seq),
      seq,
      kind: "interrupt_decision",
      decision: {
        permission: decision?.permission === true,
        cancelled: decision?.cancelled === true,
        lines,
      },
    };
  }
  return {
    id: entryId("unknown", seq),
    seq,
    kind: "assistant_reasoning",
    text: "Unknown transcript entry",
  };
}

/** Resolved interrupt decision view — non-interactive, structured lines only. */
export function interruptDecisionView(entry: NativeHistoryEntry): {
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

export function nativeAttachRuntimeState(
  attach: AttachResult,
  previousDaemonState: NativeDaemonState = emptyNativeDaemonState,
): NativeAttachRuntimeState {
  const activeModelInput = activeModelInputFromRecord(attach.active_model_state);
  const pausedWork = attach.paused_work;
  return {
    daemonState: {
      ...previousDaemonState,
      pausedWork: pausedWork.length ? { sessionId: attach.session_id, items: pausedWork } : null,
      repairRequired: attach.repair_required ?? null,
    },
    activeModel: activeModelInput ? activeModelReducer(null, activeModelInput) : null,
    llmMode: null,
  };
}

export function sortNativeHistory(history: NativeHistoryEntry[]) {
  return [...history].sort((a, b) => a.seq - b.seq || a.id.localeCompare(b.id));
}

/**
 * Settled rows merge by seq; pending/optimistic rows merge by id and are never
 * collapsed into settled rows here (acknowledgement reducers own that).
 */
export function nativeHistoryMergeKey(entry: NativeHistoryEntry) {
  if (
    entry.seq >= pendingUserSeq ||
    entry.id === pendingAssistantId ||
    entry.id === pendingReasoningId ||
    entry.id.startsWith(pendingDisplayReasoningPrefix) ||
    entry.id.startsWith(pendingUserPrefix) ||
    (entry.kind === "tool_call" && entry.status === "running") ||
    (entry.kind === "interrupt" && !entry.interrupt.resolved)
  ) {
    return `id:${entry.id}`;
  }
  return `seq:${entry.seq}`;
}

export function mergeNativeHistoryEntries(
  history: readonly NativeHistoryEntry[],
  entries: readonly NativeHistoryEntry[],
) {
  const byKey = new Map<string, NativeHistoryEntry>();
  // Incoming first; existing history wins on key collision so settled window
  // rows are preferred over overlapping page duplicates.
  for (const entry of entries) byKey.set(nativeHistoryMergeKey(entry), entry);
  for (const entry of history) byKey.set(nativeHistoryMergeKey(entry), entry);
  return sortNativeHistory([...byKey.values()]);
}

export function oldestSeqFromNativeHistory(history: readonly NativeHistoryEntry[]) {
  return history.reduce<number | null>((min, entry) => {
    if (entry.seq >= pendingUserSeq) return min;
    return min === null ? entry.seq : Math.min(min, entry.seq);
  }, null);
}

function nextSeqFromHistory(history: readonly NativeHistoryEntry[]) {
  return history.reduce(
    (max, entry) => (entry.seq < pendingUserSeq ? Math.max(max, entry.seq + 1) : max),
    1,
  );
}

/**
 * Preserve older paged rows and pending/live tail when a truncated snapshot
 * (attach/history_replay) refreshes the mid-window.
 */
export function mergeNativeHistorySnapshot(
  current: readonly NativeHistoryEntry[],
  snapshot: readonly NativeHistoryEntry[],
) {
  const withoutLiveErrors = current.filter(
    (entry) => !String(entry.id).startsWith("inference:live:"),
  );
  if (!snapshot.length) return sortNativeHistory([...withoutLiveErrors]);
  const nextSeq = nextSeqFromHistory(snapshot);
  const oldestSnapshotSeq = oldestSeqFromNativeHistory(snapshot);
  const snapshotIds = new Set(snapshot.map((entry) => entry.id));
  const preserved = withoutLiveErrors.filter(
    (entry) =>
      !snapshotIds.has(entry.id) &&
      ((oldestSnapshotSeq !== null && entry.seq < oldestSnapshotSeq) || entry.seq >= nextSeq),
  );
  return mergeNativeHistoryEntries(snapshot, preserved);
}

function upsertHistory(history: NativeHistoryEntry[], entry: NativeHistoryEntry) {
  return sortNativeHistory([entry, ...history.filter((item) => item.id !== entry.id)]);
}

function sessionIdFromEvent(event: EventEnvelope) {
  const data = event.data;
  if (!data || typeof data !== "object") return null;
  const sessionId = (data as Record<string, unknown>).session_id;
  return typeof sessionId === "string" ? sessionId : null;
}

function interruptTitle(question: InterruptQuestion) {
  return question.data.prompt;
}

function interruptBody(question: InterruptQuestion) {
  if (question.kind !== "single") return undefined;
  return question.data.command_detail?.full_command;
}

function appendAssistantDelta(history: NativeHistoryEntry[], delta: string): NativeHistoryEntry[] {
  const pending = history.find(
    (entry) => entry.kind === "assistant_text" && entry.id === pendingAssistantId,
  );
  if (pending?.kind === "assistant_text") {
    return history.map((entry) =>
      entry.id === pendingAssistantId && entry.kind === "assistant_text"
        ? { ...entry, text: entry.text + delta }
        : entry,
    );
  }
  const pendingEntry: NativeHistoryEntry = {
    id: pendingAssistantId,
    seq: pendingAssistantSeq,
    kind: "assistant_text",
    text: delta,
  };
  return sortNativeHistory([...history, pendingEntry]);
}

function appendDisplayTextDelta(
  history: NativeHistoryEntry[],
  attemptId: string | number,
  delta: string,
): NativeHistoryEntry[] {
  const id = pendingDisplayId(attemptId);
  const pending = history.find((entry) => entry.kind === "assistant_text" && entry.id === id);
  if (pending?.kind === "assistant_text") {
    return history.map((entry) =>
      entry.id === id && entry.kind === "assistant_text"
        ? { ...entry, text: entry.text + delta }
        : entry,
    );
  }
  return sortNativeHistory([
    ...history,
    { id, seq: pendingAssistantSeq, kind: "assistant_text", text: delta },
  ]);
}

function appendDisplayReasoningDelta(
  history: NativeHistoryEntry[],
  attemptId: string | number,
  delta: string,
): NativeHistoryEntry[] {
  const id = pendingDisplayReasoningId(attemptId);
  const pending = history.find((entry) => entry.kind === "assistant_reasoning" && entry.id === id);
  if (pending?.kind === "assistant_reasoning") {
    return history.map((entry) =>
      entry.id === id && entry.kind === "assistant_reasoning"
        ? { ...entry, text: entry.text + delta }
        : entry,
    );
  }
  return sortNativeHistory([
    ...history,
    { id, seq: pendingReasoningSeq, kind: "assistant_reasoning", text: delta },
  ]);
}

function applyAssistantText(
  history: NativeHistoryEntry[],
  data: { seq?: number; text: string; presentation_text?: string },
) {
  const seq = typeof data.seq === "number" ? data.seq : nextLocalSeq(history);
  const text = data.presentation_text ?? data.text;
  const finalEntry: NativeHistoryEntry = {
    id: entryId("assistant", seq),
    seq,
    kind: "assistant_text",
    text,
  };
  // Drop legacy pending and attempt-keyed provisionals left when Complete
  // had seq:None so AssistantText does not duplicate the reply.
  const cleaned = history.filter(
    (entry) =>
      entry.id !== pendingAssistantId && !String(entry.id).startsWith(`${pendingAssistantId}:`),
  );
  return upsertHistory(cleaned, finalEntry);
}

function applyDisplayComplete(
  history: NativeHistoryEntry[],
  data: Record<string, unknown>,
): NativeHistoryEntry[] | null {
  const attemptId = data.attempt_id;
  if (attemptId === undefined || attemptId === null) return null;
  const text =
    (typeof data.presentation_text === "string" ? data.presentation_text : undefined) ??
    (typeof data.text === "string" ? data.text : "") ??
    "";
  const reasoning = typeof data.reasoning === "string" ? data.reasoning : "";
  const seq = typeof data.seq === "number" ? data.seq : undefined;
  const displayAttemptId = attemptId as string | number;
  let withoutPending = history.filter(
    (entry) =>
      entry.id !== pendingDisplayId(displayAttemptId) &&
      entry.id !== pendingDisplayReasoningId(displayAttemptId),
  );
  if (!text.trim() && !reasoning.trim()) return withoutPending;
  if (seq == null) {
    if (text.trim()) {
      withoutPending = sortNativeHistory([
        ...withoutPending,
        {
          id: pendingDisplayId(displayAttemptId),
          seq: pendingAssistantSeq,
          kind: "assistant_text",
          text,
        },
      ]);
    }
    if (reasoning.trim()) {
      withoutPending = sortNativeHistory([
        ...withoutPending,
        {
          id: pendingDisplayReasoningId(displayAttemptId),
          seq: pendingReasoningSeq,
          kind: "assistant_reasoning",
          text: reasoning,
        },
      ]);
    }
    return withoutPending;
  }
  if (text.trim()) {
    withoutPending = upsertHistory(withoutPending, {
      id: entryId("assistant", seq),
      seq,
      kind: "assistant_text",
      text,
    });
  }
  if (reasoning.trim()) {
    withoutPending = upsertHistory(withoutPending, {
      id: entryId("reasoning", seq),
      seq,
      kind: "assistant_reasoning",
      text: reasoning,
    });
  }
  return withoutPending;
}

function applyDisplayAttemptReset(
  history: NativeHistoryEntry[],
  data: Record<string, unknown>,
): NativeHistoryEntry[] {
  const failed = data.failed_attempt_id;
  if (failed === undefined || failed === null) return history;
  const failedAttemptId = failed as string | number;
  return history.filter(
    (entry) =>
      entry.id !== pendingDisplayId(failedAttemptId) &&
      entry.id !== pendingDisplayReasoningId(failedAttemptId),
  );
}

function applyDisplayError(
  history: NativeHistoryEntry[],
  data: Record<string, unknown>,
): NativeHistoryEntry[] | null {
  const attemptId = data.attempt_id;
  if (attemptId === undefined || attemptId === null) return null;
  const message = typeof data.message === "string" ? data.message : "assistant display error";
  const presentation =
    typeof data.presentation_text === "string" ? data.presentation_text : undefined;
  const detail = presentation?.trim() ? `${presentation}\n${message}` : message;
  // Live-only error row: pending-range seq; dropped on history_replay merge.
  const seq = pendingAssistantSeq;
  const displayAttemptId = attemptId as string | number;
  return upsertHistory(
    history.filter(
      (entry) =>
        entry.id !== pendingDisplayId(displayAttemptId) &&
        entry.id !== pendingDisplayReasoningId(displayAttemptId) &&
        !String(entry.id).startsWith("inference:live:"),
    ),
    {
      id: `inference:live:${displayAttemptId}`,
      seq,
      kind: "inference_error",
      view: inferenceFailureView({
        error_class: typeof data.kind === "string" ? data.kind : "failed",
        detail,
      }),
    },
  );
}

export function appendOptimisticUserMessage(
  history: NativeHistoryEntry[],
  text: string,
  localId: string,
): NativeHistoryEntry[] {
  return sortNativeHistory([
    ...history,
    {
      id: pendingUserPrefix + localId,
      seq: pendingUserSeq,
      kind: "user_message",
      text,
    },
  ]);
}

export type RetainedUserMessageSubmission = {
  sessionId: string;
  params: SendUserMessageParams;
};

export type RetainedUserMessageSubmissions = Map<string, RetainedUserMessageSubmission>;

export type RetainedUserMessageSubmissionsBySession = Readonly<
  Record<string, RetainedUserMessageSubmission | undefined>
>;

export function restoreRetainedUserMessagesAfterAttach(
  history: NativeHistoryEntry[],
  sessionId: string,
  retained: ReadonlyMap<string, RetainedUserMessageSubmission>,
) {
  let next = history;
  for (const submission of retained.values()) {
    if (submission.sessionId !== sessionId) continue;
    const id = pendingUserPrefix + submission.params.client_submission_id;
    if (next.some((entry) => entry.id === id)) continue;
    next = appendOptimisticUserMessage(
      next,
      submission.params.display_text ?? submission.params.text,
      submission.params.client_submission_id,
    );
  }
  return next;
}

export function reconcileAcceptedRetrySubmissions(
  retries: RetainedUserMessageSubmissionsBySession,
  acceptedIds: readonly string[],
) {
  if (acceptedIds.length === 0) {
    return { retries, accepted: [] as RetainedUserMessageSubmission[] };
  }
  const acceptedIdsSet = new Set(acceptedIds);
  const accepted: RetainedUserMessageSubmission[] = [];
  const next = { ...retries };
  for (const [sessionId, retry] of Object.entries(retries)) {
    if (!retry || !acceptedIdsSet.has(retry.params.client_submission_id)) continue;
    accepted.push(retry);
    delete next[sessionId];
  }
  return { retries: accepted.length > 0 ? next : retries, accepted };
}

export function clearAcceptedRetryDrafts(
  messages: Readonly<Record<string, string>>,
  accepted: readonly RetainedUserMessageSubmission[],
) {
  const next = { ...messages };
  let changed = false;
  for (const retry of accepted) {
    if ((next[retry.sessionId] ?? "").trim() !== retry.params.text) continue;
    next[retry.sessionId] = "";
    changed = true;
  }
  return changed ? next : messages;
}

export function prepareUserMessageSubmission(
  sessionId: string,
  text: string,
  explicitRetry: RetainedUserMessageSubmission | undefined,
) {
  if (explicitRetry?.sessionId === sessionId && explicitRetry.params.text === text) {
    return { submission: explicitRetry, isRetry: true };
  }
  return {
    submission: {
      sessionId,
      params: { client_submission_id: createClientSubmissionId(), text },
    },
    isRetry: false,
  };
}

export function retainUserMessageSubmission(
  retained: RetainedUserMessageSubmissions,
  submission: RetainedUserMessageSubmission,
) {
  const id = submission.params.client_submission_id;
  const exact = retained.get(id);
  if (exact) return exact;
  retained.set(id, submission);
  return submission;
}

export function forgetUserMessageSubmission(
  retained: RetainedUserMessageSubmissions,
  clientSubmissionId: string,
) {
  retained.delete(clientSubmissionId);
}

export function clientSubmissionIdsFromHistory(entries: readonly HistoryEntry[]) {
  return entries.flatMap((entry) =>
    entry.role === "user" ? (entry.client_submission_ids ?? []) : [],
  );
}

export function acceptedClientSubmissionIdsFromEvent(
  raw: unknown,
  selectedSessionId: string | null,
) {
  const parsed = eventEnvelopeSchema.safeParse(raw);
  if (!parsed.success || ("__unknown" in parsed.data && parsed.data.__unknown)) return [];
  const event = parsed.data;
  const sessionId = sessionIdFromEvent(event);
  if (sessionId && selectedSessionId && sessionId !== selectedSessionId) return [];
  const data = eventDataRecord(event);
  if (!data) return [];
  if (event.event === "user_message_recorded") {
    return Array.isArray(data.client_submission_ids)
      ? data.client_submission_ids.filter((id): id is string => typeof id === "string")
      : [];
  }
  if (event.event === "queued_user_messages_folded") {
    return Array.isArray(data.queue_item_ids)
      ? data.queue_item_ids.filter((id): id is string => typeof id === "string")
      : [];
  }
  if (event.event === "user_messages_terminated" || event.event === "user_message_retracted") {
    return Array.isArray(data.client_submission_ids)
      ? data.client_submission_ids.filter((id): id is string => typeof id === "string")
      : [];
  }
  if (event.event !== "history_replay" || !Array.isArray(data.entries)) return [];
  return data.entries.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const record = entry as Record<string, unknown>;
    if (record.role !== "user" || !Array.isArray(record.client_submission_ids)) return [];
    return record.client_submission_ids.filter((id): id is string => typeof id === "string");
  });
}

export function isCurrentUserMessageSubmission(
  currentSessionId: string | null,
  latestClientSubmissionId: string | null,
  submission: RetainedUserMessageSubmission,
) {
  return (
    currentSessionId === submission.sessionId &&
    latestClientSubmissionId === submission.params.client_submission_id
  );
}

export function removeOptimisticUserMessage(
  history: NativeHistoryEntry[],
  localId: string,
): NativeHistoryEntry[] {
  return history.filter((entry) => entry.id !== pendingUserPrefix + localId);
}

export function reconcileRecordedUserMessage(
  history: NativeHistoryEntry[],
  data: {
    seq?: number;
    preflight_cleaned?: string | null;
    client_submission_ids?: string[];
    text?: string;
    display_text?: string;
  },
): NativeHistoryEntry[] {
  const pending = history.find(
    (entry) =>
      entry.kind === "user_message" &&
      data.client_submission_ids?.some((id) => entry.id === pendingUserPrefix + id),
  );
  const text =
    data.display_text ??
    data.preflight_cleaned ??
    data.text ??
    (pending?.kind === "user_message" ? pending.text : null);
  if (text === undefined || text === null) return history;
  const seq = typeof data.seq === "number" ? data.seq : nextLocalSeq(history);
  const recorded: NativeHistoryEntry = {
    id: entryId("user", seq),
    seq,
    kind: "user_message",
    text,
  };
  return upsertHistory(
    history.filter(
      (entry) => !data.client_submission_ids?.some((id) => entry.id === pendingUserPrefix + id),
    ),
    recorded,
  );
}

export function reduceNativeSessionEvent(
  state: NativeSessionEventState,
  raw: unknown,
): NativeSessionEventResult {
  const parsed = eventEnvelopeSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      state,
      warning: eventWarning(rawEventName(raw)),
    };
  }
  const event = parsed.data;
  if ("__unknown" in event && event.__unknown) {
    return {
      state,
      warning: eventWarning(event.event),
    };
  }

  const sessionId = sessionIdFromEvent(event);
  if (sessionId && sessionId !== state.selectedSessionId) return { state };

  if (
    event.event === "daemon_draining" ||
    event.event === "sandbox_unavailable" ||
    event.event === "sandbox_state" ||
    event.event === "waiting_for_lock" ||
    event.event === "paused_work_available"
  ) {
    return { state: eventStateWithDaemon(state, event) };
  }

  if (event.event === "active_model_state") {
    const data = eventDataRecord(event);
    if (!data) return { state, warning: eventWarning(event.event) };
    const activeModel = activeModelInputFromRecord(data);
    if (!activeModel) return { state, warning: eventWarning(event.event) };
    if (
      state.activeModel &&
      typeof activeModel.generation === "number" &&
      activeModel.generation < state.activeModel.generation
    ) {
      return { state };
    }
    return {
      state: {
        ...state,
        activeModel: activeModelReducer(state.activeModel ?? null, activeModel),
      },
    };
  }

  if (event.event === "model_selection_result") {
    const parsedResult = modelSelectionResultDataSchema.safeParse(event.data);
    if (!parsedResult.success) return { state, warning: eventWarning(event.event) };
    if (parsedResult.data.outcome.status === "rejected") return { state };
    const activeModel = activeModelInputFromRecord(parsedResult.data.outcome.active_state);
    if (!activeModel) return { state, warning: eventWarning(event.event) };
    // Terminal applied results may correct default/divergence fields at the
    // same generation after a verified default save, so equality is accepted.
    // A strictly older generation is still stale and must not clobber newer
    // state — same rule as `active_model_state` above, and as the web client.
    if (
      state.activeModel &&
      typeof activeModel.generation === "number" &&
      activeModel.generation < state.activeModel.generation
    ) {
      return { state };
    }
    return {
      state: {
        ...state,
        activeModel: activeModelReducer(state.activeModel ?? null, activeModel),
      },
    };
  }

  if (event.event === "llm_mode_changed") {
    const data = eventDataRecord(event);
    if (typeof data?.mode !== "string") return { state, warning: eventWarning(event.event) };
    return { state: { ...state, llmMode: data.mode } };
  }

  if (event.event === "inference_failed") {
    const data = eventDataRecord(event);
    if (!data) return { state, warning: eventWarning(event.event) };
    const seq = nextLocalSeq(state.history);
    return {
      state: {
        ...state,
        history: upsertHistory(state.history, {
          id: entryId("inference", seq),
          seq,
          kind: "inference_error",
          view: inferenceFailureView({
            provider: typeof data.provider === "string" ? data.provider : undefined,
            model: typeof data.model === "string" ? data.model : undefined,
            error_class: typeof data.error_class === "string" ? data.error_class : undefined,
            detail: typeof data.detail === "string" ? data.detail : undefined,
            auth_failure: authFailureFromData(data.auth_failure),
          }),
        }),
      },
    };
  }

  if (event.event === "history_replay") {
    const data = event.data as { entries: HistoryEntry[] };
    const snapshot = data.entries.map((entry, index) => toNativeHistoryEntry(entry, index));
    return {
      state: {
        ...state,
        history: mergeNativeHistorySnapshot(state.history, snapshot),
      },
    };
  }

  if (event.event === "assistant_text_delta") {
    const data = eventDataRecord(event);
    if (typeof data?.delta !== "string") return { state, warning: eventWarning(event.event) };
    return { state: { ...state, history: appendAssistantDelta(state.history, data.delta) } };
  }

  if (event.event === "assistant_display_text_delta") {
    const data = eventDataRecord(event);
    if (typeof data?.delta !== "string" || data.attempt_id == null) {
      return { state, warning: eventWarning(event.event) };
    }
    return {
      state: {
        ...state,
        history: appendDisplayTextDelta(
          state.history,
          data.attempt_id as string | number,
          data.delta,
        ),
      },
    };
  }

  if (event.event === "assistant_display_reasoning_delta") {
    const data = eventDataRecord(event);
    if (typeof data?.delta !== "string" || data.attempt_id == null) {
      return { state, warning: eventWarning(event.event) };
    }
    return {
      state: {
        ...state,
        history: appendDisplayReasoningDelta(
          state.history,
          data.attempt_id as string | number,
          data.delta,
        ),
      },
    };
  }

  if (event.event === "assistant_display_attempt_reset") {
    const data = eventDataRecord(event);
    if (!data) return { state, warning: eventWarning(event.event) };
    return { state: { ...state, history: applyDisplayAttemptReset(state.history, data) } };
  }

  if (event.event === "assistant_display_complete") {
    const data = eventDataRecord(event);
    if (!data) return { state, warning: eventWarning(event.event) };
    const history = applyDisplayComplete(state.history, data);
    if (!history) return { state, warning: eventWarning(event.event) };
    return { state: { ...state, history } };
  }

  if (event.event === "assistant_display_error") {
    const data = eventDataRecord(event);
    if (!data) return { state, warning: eventWarning(event.event) };
    const history = applyDisplayError(state.history, data);
    if (!history) return { state, warning: eventWarning(event.event) };
    return { state: { ...state, history } };
  }

  if (event.event === "assistant_text") {
    const data = eventDataRecord(event);
    if (typeof data?.text !== "string") return { state, warning: eventWarning(event.event) };
    return {
      state: {
        ...state,
        history: applyAssistantText(state.history, {
          text: data.text,
          presentation_text:
            typeof data.presentation_text === "string" ? data.presentation_text : undefined,
          seq: typeof data.seq === "number" ? data.seq : undefined,
        }),
      },
    };
  }

  if (event.event === "queued_user_messages_folded") {
    const data = eventDataRecord(event);
    if (!data) return { state, warning: eventWarning(event.event) };
    return {
      state: {
        ...state,
        history: reconcileRecordedUserMessage(state.history, {
          seq: typeof data.seq === "number" ? data.seq : undefined,
          client_submission_ids: Array.isArray(data.queue_item_ids)
            ? data.queue_item_ids.filter((id): id is string => typeof id === "string")
            : [],
          text: typeof data.text === "string" ? data.text : undefined,
          display_text: typeof data.display_text === "string" ? data.display_text : undefined,
          preflight_cleaned:
            typeof data.preflight_cleaned === "string" || data.preflight_cleaned === null
              ? data.preflight_cleaned
              : undefined,
        }),
      },
    };
  }

  if (event.event === "user_message_recorded") {
    const data = eventDataRecord(event);
    if (!data) return { state, warning: eventWarning(event.event) };
    return {
      state: {
        ...state,
        history: reconcileRecordedUserMessage(state.history, {
          seq: typeof data.seq === "number" ? data.seq : undefined,
          client_submission_ids: Array.isArray(data.client_submission_ids)
            ? data.client_submission_ids.filter((id): id is string => typeof id === "string")
            : [],
          preflight_cleaned:
            typeof data.preflight_cleaned === "string" || data.preflight_cleaned === null
              ? data.preflight_cleaned
              : undefined,
        }),
      },
    };
  }

  if (event.event === "session_persist_failed") {
    // The matching optimistic row remains visible and its exact wire payload stays
    // retained by the caller for a retry. In particular, do not disturb any other
    // in-flight submission when one durable write fails.
    return { state };
  }

  if (event.event === "user_messages_terminated" || event.event === "user_message_retracted") {
    const data = eventDataRecord(event);
    if (!data || !Array.isArray(data.client_submission_ids)) {
      return { state, warning: eventWarning(event.event) };
    }
    const terminalIds = data.client_submission_ids.filter(
      (id): id is string => typeof id === "string",
    );
    return {
      state: {
        ...state,
        history: state.history.filter(
          (entry) => !terminalIds.some((id) => entry.id === pendingUserPrefix + id),
        ),
      },
    };
  }

  if (event.event === "interrupt_raised") {
    const data = event.data as {
      interrupt_id: string;
      description: string;
      question?: InterruptQuestion | null;
    };
    if (!data.question) return { state };
    const entry: NativeHistoryEntry = {
      id: `interrupt:${data.interrupt_id}`,
      seq: pendingInterruptSeq,
      kind: "interrupt",
      interrupt: {
        interruptId: data.interrupt_id,
        kind: data.question.kind === "freetext" ? "question" : "approval",
        title: interruptTitle(data.question),
        body: interruptBody(data.question) ?? data.description,
        resolved: false,
        question: data.question,
      },
    };
    return { state: { ...state, history: upsertHistory(state.history, entry) } };
  }

  if (event.event === "interrupt_resolved") {
    const data = event.data as { interrupt_id: string };
    return {
      state: {
        ...state,
        history: state.history.map((entry) =>
          entry.kind === "interrupt" && entry.interrupt.interruptId === data.interrupt_id
            ? { ...entry, interrupt: { ...entry.interrupt, resolved: true } }
            : entry,
        ),
      },
    };
  }

  return { state };
}

export function warnNativeSessionEvent(result: NativeSessionEventResult) {
  if (result.warning) console.warn(result.warning);
}
