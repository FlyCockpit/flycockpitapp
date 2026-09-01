import type {
  ActiveModelRef,
  AttachResult,
  EventEnvelope,
  FsListResult,
  FsReadResult,
  FsWriteResult,
  GitDiffFileResult,
  GitStatusResult,
  HistoryPageResult,
  InterruptQuestion,
  ResumeRepairState,
  StorageCleanupCompletedResult,
  StorageCleanupPreviewResult,
  StorageReportResult,
  HistoryEntry as WireHistoryEntry,
  SessionSummary as WireSessionSummary,
} from "@flycockpit/cockpit-protocol";
import {
  activeModelStateSchema,
  createClientSubmissionId,
  eventEnvelopeSchema,
  modelSelectionResultDataSchema,
} from "@flycockpit/cockpit-protocol";
import {
  RemoteSessionClient,
  type SendUserMessageParams,
  shouldRetainUserMessageSubmission,
} from "@flycockpit/cockpit-protocol/client";
import { create } from "zustand";
import {
  type AuthRecoveryView,
  authRecoveryView,
  errorClassLabel,
} from "@/lib/inference-failure-view";
import { type InterruptSelection, resolveFromSelection } from "@/lib/interrupt-view";

export type ConnectionStatus = "idle" | "connecting" | "connected" | "offline" | "error";

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
  sessionEntryMode: WireSessionSummary["session_entry_mode"];
  projectId: string;
  projectRoot: string;
  title: string;
  description?: string;
  shortId?: string;
  status: string;
  archived: boolean;
  pinned: boolean;
  forkCount: number;
  turnCount: number;
  attention: { kind: "approval"; interruptId: string } | { kind: "paused_work" } | null;
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
      kind: "user_message" | "user_note" | "assistant_text" | "assistant_reasoning";
      text: string;
      actor?: { userId?: string; displayName?: string; origin?: string };
      clientSubmissionIds?: string[];
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
    }
  | {
      id: string;
      seq: number;
      ts?: number;
      kind: "inference_failure";
      failure: WebInferenceFailure;
    };

export type WebActiveModelState = {
  selection: ActiveModelRef;
  defaultSelection?: ActiveModelRef;
  provider: string;
  model: string;
  configProvider?: string;
  configModel?: string;
  diverged: boolean;
  generation: number;
};

export type WebSandboxUnavailable = {
  remedy: string;
  fixCommand?: string;
};

export type WebWaitingLock = {
  path: string;
  holderAgent: string;
};

export type WebPausedWork = {
  items: unknown[];
};

export type WebInferenceFailure = {
  agent: string;
  provider: string;
  model: string;
  errorClass: string;
  detail: string;
  recovery: AuthRecoveryView;
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

export type SessionDetail = {
  summary: WebSessionSummary;
  history: WebHistoryEntry[];
  schedules: unknown[];
  nextSeq: number;
  usage: WebUsage | null;
  paging: SessionPagingState;
  activeModel?: WebActiveModelState;
  sandboxUnavailable?: WebSandboxUnavailable;
  waitingLocks: Record<string, WebWaitingLock>;
  pausedWork?: WebPausedWork;
  repairRequired?: ResumeRepairState;
};

export class WebSessionCreatedWithSetupError extends Error {
  constructor(
    readonly session: SessionDetail,
    setupError: unknown,
  ) {
    super(errorMessage(setupError));
    this.name = "WebSessionCreatedWithSetupError";
  }
}

export type WebAttachmentState = {
  connectionEpoch: number;
  phase: "detached" | "pending" | "applied" | "failed";
  sessionId?: string;
  error?: string;
};

export type InstanceRemoteState = {
  status: ConnectionStatus;
  statusDetail?: string;
  attachment: WebAttachmentState;
  draining?: { forced: boolean };
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
  getStorageReport: (instanceId: string) => Promise<StorageReportResult>;
  dismissStorageManagementHint: (instanceId: string, expectedVersion: number) => Promise<void>;
  previewStorageCleanup: (
    instanceId: string,
    target: Parameters<RemoteSessionClient["previewStorageCleanup"]>[0]["target"],
  ) => Promise<StorageCleanupPreviewResult>;
  executeStorageCleanup: (
    instanceId: string,
    previewId: string,
  ) => Promise<StorageCleanupCompletedResult>;
  attach: (instanceId: string, sessionId: string) => Promise<void>;
  loadOlderHistory: (instanceId: string, sessionId: string) => Promise<void>;
  createSession: (
    instanceId: string,
    input: {
      projectRoot: string;
      title?: string;
      agent?: string;
      initialModel?: ActiveModelRef;
    },
  ) => Promise<SessionDetail>;
  sendMessage: (
    instanceId: string,
    sessionId: string,
    input: string | SendUserMessageParams,
  ) => Promise<void>;
  resolveInterrupt: (
    instanceId: string,
    input: {
      sessionId: string;
      interruptId: string;
      selection: InterruptSelection;
    },
  ) => Promise<void>;
  renameSession: (instanceId: string, sessionId: string, title: string) => Promise<void>;
  archiveSession: (instanceId: string, sessionId: string, archived: boolean) => Promise<void>;
  shareSession: (instanceId: string, sessionId: string, shared: boolean) => Promise<void>;
  forkSession: (instanceId: string, sessionId: string) => Promise<void>;
  resumePausedWork: (instanceId: string, sessionId: string) => Promise<void>;
  cancelPausedWork: (instanceId: string, sessionId: string) => Promise<void>;
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
const pendingDisplayAssistantPrefix = "assistant:pending:";
const pendingDisplayReasoningPrefix = "reasoning:pending:";
const pendingUserPrefix = "user:pending:";
const pendingUserSeq = Number.MAX_SAFE_INTEGER - 3;
const pendingReasoningSeq = Number.MAX_SAFE_INTEGER - 2;
const pendingAssistantSeq = Number.MAX_SAFE_INTEGER - 1;
const pendingInterruptSeq = Number.MAX_SAFE_INTEGER;
const warnedEventKinds = new Set<string>();
const historyPageInFlight = new Set<string>();
const pendingUserSubmissions = new Map<string, Map<string, SendUserMessageParams>>();
const historyPageLimit = 100;

type WebAttachAttempt = {
  id: number;
  client: RemoteSessionClient;
  connectionEpoch: number;
  sessionId?: string;
};

class WebAttachCoordinator {
  private nextId = 0;
  private current: WebAttachAttempt | null = null;

  begin(
    client: RemoteSessionClient,
    connectionEpoch: number,
    sessionId?: string,
  ): WebAttachAttempt {
    const attempt = {
      id: ++this.nextId,
      client,
      connectionEpoch,
      sessionId,
    };
    this.current = attempt;
    return attempt;
  }

  bindSession(attempt: WebAttachAttempt, sessionId: string) {
    if (attempt.id !== this.current?.id) return false;
    attempt.sessionId = sessionId;
    return true;
  }

  invalidate() {
    this.nextId += 1;
    this.current = null;
  }

  isCurrent(
    attempt: WebAttachAttempt,
    client: RemoteSessionClient | undefined,
    connectionEpoch: number,
  ) {
    return (
      attempt.id === this.current?.id &&
      attempt.client === client &&
      attempt.connectionEpoch === connectionEpoch
    );
  }

  finish(
    attempt: WebAttachAttempt,
    client: RemoteSessionClient | undefined,
    connectionEpoch: number,
  ) {
    if (!this.isCurrent(attempt, client, connectionEpoch)) return false;
    this.current = null;
    return true;
  }
}

const webAttachCoordinators = new Map<string, WebAttachCoordinator>();

function webAttachCoordinator(instanceId: string) {
  let coordinator = webAttachCoordinators.get(instanceId);
  if (!coordinator) {
    coordinator = new WebAttachCoordinator();
    webAttachCoordinators.set(instanceId, coordinator);
  }
  return coordinator;
}

export type WebComposerRetrySubmission = {
  sessionId: string;
  params: SendUserMessageParams;
};

export function matchingWebComposerRetry(
  sessionId: string,
  text: string,
  retry?: WebComposerRetrySubmission | null,
) {
  return retry?.sessionId === sessionId && retry.params.text === text ? retry.params : null;
}

export function matchingWebComposerRetryForSession(
  sessionId: string,
  text: string,
  retries: Readonly<Record<string, WebComposerRetrySubmission | undefined>>,
) {
  return matchingWebComposerRetry(sessionId, text, retries[sessionId]);
}

export function isCurrentWebComposerAttempt(input: {
  currentSessionId: string | null;
  attemptedSessionId: string;
  latestAttempt: number;
  attempt: number;
}) {
  return (
    input.currentSessionId === input.attemptedSessionId && input.latestAttempt === input.attempt
  );
}

function pendingUserSubmissionKey(instanceId: string, sessionId: string) {
  return `${instanceId}:${sessionId}`;
}

function retainedUserSubmission(
  retained: ReadonlyMap<string, SendUserMessageParams> | undefined,
  input: string | SendUserMessageParams,
) {
  if (typeof input !== "string") {
    const exact = retained?.get(input.client_submission_id);
    return exact ? { submission: exact, isRetry: true } : { submission: input, isRetry: false };
  }
  return {
    submission: { client_submission_id: createClientSubmissionId(), text: input },
    isRetry: false,
  };
}

function retainUserSubmission(key: string, submission: SendUserMessageParams) {
  let retained = pendingUserSubmissions.get(key);
  if (!retained) {
    retained = new Map();
    pendingUserSubmissions.set(key, retained);
  }
  const exact = retained.get(submission.client_submission_id);
  if (exact) return exact;
  retained.set(submission.client_submission_id, submission);
  return submission;
}

function forgetUserSubmission(key: string, clientSubmissionId: string) {
  const retained = pendingUserSubmissions.get(key);
  if (!retained) return;
  retained.delete(clientSubmissionId);
  if (retained.size === 0) pendingUserSubmissions.delete(key);
}

async function replayPendingUserSubmissions(
  client: RemoteSessionClient,
  instanceId: string,
  sessionId: string,
  isCurrent: () => boolean,
) {
  const key = pendingUserSubmissionKey(instanceId, sessionId);
  const snapshot = [...(pendingUserSubmissions.get(key)?.values() ?? [])];
  const rejectedIds: string[] = [];
  for (const submission of snapshot) {
    if (!isCurrent()) return { current: false, rejectedIds };
    if (!pendingUserSubmissions.get(key)?.has(submission.client_submission_id)) continue;
    try {
      await client.sendUserMessage(submission);
    } catch (error) {
      if (!isCurrent()) return { current: false, rejectedIds };
      if (
        shouldRetainUserMessageSubmission(error) &&
        pendingUserSubmissions.get(key)?.has(submission.client_submission_id)
      ) {
        // Preserve FIFO when the destination is still temporarily unable to
        // accept A; sending later B would overtake the exact retained request.
        break;
      }
      forgetUserSubmission(key, submission.client_submission_id);
      rejectedIds.push(submission.client_submission_id);
    }
  }
  return { current: isCurrent(), rejectedIds };
}

function acceptedClientSubmissionIdsFromHistory(entries: readonly WireHistoryEntry[]) {
  return entries.flatMap((entry) =>
    entry.role === "user" ? (entry.client_submission_ids ?? []) : [],
  );
}

function acceptedClientSubmissionIdsFromEvent(event: EventEnvelope) {
  const data = eventData(event);
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

function forgetAcceptedUserSubmissions(
  instanceId: string,
  sessionId: string,
  clientSubmissionIds: readonly string[],
) {
  const key = pendingUserSubmissionKey(instanceId, sessionId);
  for (const id of clientSubmissionIds) forgetUserSubmission(key, id);
}

/// Apply one client event and retire any exact submissions that the daemon has
/// durably recorded or terminated. Kept as one production helper so tests can
/// verify UI reduction and reconnect-replay ownership together.
export function applyRemoteSessionClientEvent(
  instanceId: string,
  existing: InstanceRemoteState,
  event: unknown,
) {
  const parsedEvent = eventEnvelopeSchema.safeParse(event);
  if (parsedEvent.success && !("__unknown" in parsedEvent.data)) {
    const settledSessionId = sessionIdFromEvent(parsedEvent.data);
    if (settledSessionId) {
      forgetAcceptedUserSubmissions(
        instanceId,
        settledSessionId,
        acceptedClientSubmissionIdsFromEvent(parsedEvent.data),
      );
    }
  }
  const result = reduceRemoteSessionEvent(existing, event);
  warnUnhandledRemoteSessionEvent(result.warningKind);
  return result.state;
}

const emptyInstance = (): InstanceRemoteState => ({
  status: "idle",
  attachment: { connectionEpoch: 0, phase: "detached" },
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
    entry.id.startsWith(pendingDisplayAssistantPrefix) ||
    entry.id.startsWith(pendingDisplayReasoningPrefix) ||
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

function isLiveDisplayErrorEntry(entry: WebHistoryEntry) {
  return entry.id.startsWith("assistant-error:live:");
}

function mergeHistorySnapshot(current: WebHistoryEntry[], snapshot: WebHistoryEntry[]) {
  // Always drop live-only typed display errors on attach/replay, including
  // empty authoritative snapshots.
  const withoutLiveErrors = current.filter((entry) => !isLiveDisplayErrorEntry(entry));
  if (!snapshot.length) return sortHistory(withoutLiveErrors);
  const nextSeq = nextSeqFromHistory(snapshot);
  const oldestSnapshotSeq = oldestSeqFromHistory(snapshot);
  const snapshotIds = new Set(snapshot.map((entry) => entry.id));
  const recordedClientSubmissionIds = new Set(
    snapshot.flatMap((entry) =>
      entry.kind === "user_message" ? (entry.clientSubmissionIds ?? []) : [],
    ),
  );
  const preserved = withoutLiveErrors.filter(
    (entry) =>
      !snapshotIds.has(entry.id) &&
      !(
        entry.id.startsWith(pendingUserPrefix) &&
        recordedClientSubmissionIds.has(entry.id.slice(pendingUserPrefix.length))
      ) &&
      ((oldestSnapshotSeq !== null && entry.seq < oldestSnapshotSeq) || entry.seq >= nextSeq),
  );
  return mergeHistoryEntries(snapshot, preserved);
}

function removeDurableUserMessages(history: WebHistoryEntry[], seqs: readonly number[]) {
  if (!seqs.length) return history;
  const removed = new Set(seqs);
  return history.filter((entry) => entry.kind !== "user_message" || !removed.has(entry.seq));
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
    sessionEntryMode: session.session_entry_mode,
    projectId: session.project_id,
    projectRoot: session.project_root,
    title: session.title ?? session.short_id ?? session.session_id,
    description: session.description ?? undefined,
    shortId: session.short_id,
    status: stringField(raw, "activity_state") ?? "idle",
    archived: booleanField(raw, "archived") ?? false,
    pinned: booleanField(raw, "pinned") ?? false,
    forkCount: numberField(raw, "fork_count") ?? 0,
    turnCount: session.turns,
    attention: null,
    updatedAt: session.last_active_at_unix_ms,
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
      clientSubmissionIds: entry.client_submission_ids ?? [],
    };
  }
  if (entry.role === "user_note") {
    return { id: "user-note:" + seq, seq, ts: entry.ts_ms, kind: "user_note", text: entry.text };
  }
  if (entry.role === "assistant") {
    const assistant = entry as WireHistoryEntry & {
      presentation_text?: string | null;
      text: string;
    };
    return {
      id: "assistant:" + seq,
      seq,
      ts: entry.ts_ms ? Math.floor(entry.ts_ms / 1000) : undefined,
      kind: "assistant_text",
      text: assistant.presentation_text ?? assistant.text,
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
  if (!("decision" in entry)) {
    const raw = entry as Record<string, unknown>;
    const text =
      stringField(raw, "display_text") ??
      stringField(raw, "text") ??
      stringField(raw, "summary") ??
      stringField(raw, "detail") ??
      "Unsupported history entry.";
    return { id: "history:" + seq, seq, kind: "assistant_text", text };
  }
  const decision =
    entry.decision && typeof entry.decision === "object"
      ? (entry.decision as Record<string, unknown>)
      : null;
  const lines = Array.isArray(decision?.lines)
    ? decision.lines.filter((line): line is { prompt: string; answer: string } => {
        if (!line || typeof line !== "object") return false;
        const record = line as Record<string, unknown>;
        return typeof record.prompt === "string" && typeof record.answer === "string";
      })
    : [];
  return {
    id: "interrupt-decision:" + seq,
    seq,
    kind: "interrupt_decision",
    decision: {
      permission: booleanField(decision ?? {}, "permission") ?? false,
      cancelled: booleanField(decision ?? {}, "cancelled") ?? false,
      lines,
    },
  };
}

function nextSeqFromHistory(history: WebHistoryEntry[]) {
  return history.reduce(
    (max, entry) => (entry.seq < pendingUserSeq ? Math.max(max, entry.seq + 1) : max),
    1,
  );
}

function attachSummary(
  attach: AttachResult,
  activeModel: WebActiveModelState | undefined,
  current?: WebSessionSummary,
): WebSessionSummary {
  return {
    sessionId: attach.session_id,
    sessionEntryMode: attach.session_entry_mode,
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
    model: activeModel ? `${activeModel.provider}/${activeModel.model}` : undefined,
    sharedWithCollaborators: current?.sharedWithCollaborators ?? false,
  };
}

export function mergeAttach(
  existing: InstanceRemoteState,
  attach: AttachResult,
): InstanceRemoteState {
  const current = existing.detailsBySession[attach.session_id];
  const mappedHistory = attach.history.map((entry, index) => toWebHistoryEntry(entry, index));
  const removedUserMessageSeqs = Array.isArray(attach.removed_user_message_seqs)
    ? attach.removed_user_message_seqs.filter((seq): seq is number => typeof seq === "number")
    : [];
  const mergedHistory = mergeHistorySnapshot(
    removeDurableUserMessages(current?.history ?? [], removedUserMessageSeqs),
    mappedHistory,
  );
  const attachedActiveModel = attach.active_model_state
    ? activeModelFromData(attach.active_model_state as Record<string, unknown>)
    : null;
  // Attach is a new live-worker epoch. Its snapshot is authoritative even
  // when a previous connection cached a numerically higher generation.
  const activeModel = attachedActiveModel ?? undefined;
  const summary = attachSummary(attach, activeModel, current?.summary);
  const attached = {
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
        activeModel,
        sandboxUnavailable: current?.sandboxUnavailable,
        waitingLocks: current?.waitingLocks ?? {},
        pausedWork: undefined,
        repairRequired: attach.repair_required,
      },
    },
  };
  return applyPausedWork(attached, summary.sessionId, attach.paused_work);
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
  const text = stringField(data, "presentation_text") ?? stringField(data, "text");
  if (!text) return null;
  const seq = numberField(data, "seq") ?? nextLocalSeq(history);
  // Drop legacy pending and any attempt-keyed provisional rows left by
  // AssistantDisplayComplete when seq was unknown (write-failure path).
  const cleaned = history.filter(
    (entry) =>
      entry.id !== pendingAssistantId && !String(entry.id).startsWith(`${pendingAssistantId}:`),
  );
  return upsertHistory(cleaned, { id: "assistant:" + seq, seq, kind: "assistant_text", text });
}

function pendingDisplayId(attemptId: string | number) {
  return `${pendingAssistantId}:${attemptId}`;
}

function pendingDisplayReasoningId(attemptId: string | number) {
  return `${pendingReasoningId}:${attemptId}`;
}

function appendDisplayTextDelta(
  history: WebHistoryEntry[],
  attemptId: string | number,
  delta: string,
) {
  const id = pendingDisplayId(attemptId);
  const pending = history.find((entry) => entry.id === id);
  if (pending?.kind === "assistant_text") {
    return history.map((entry) =>
      entry.id === id && entry.kind === "assistant_text"
        ? { ...entry, text: entry.text + delta }
        : entry,
    );
  }
  return sortHistory([
    ...history,
    { id, seq: pendingAssistantSeq, kind: "assistant_text", text: delta },
  ]);
}

function appendDisplayReasoningDelta(
  history: WebHistoryEntry[],
  attemptId: string | number,
  delta: string,
) {
  const id = pendingDisplayReasoningId(attemptId);
  const pending = history.find((entry) => entry.id === id);
  if (pending?.kind === "assistant_reasoning") {
    return history.map((entry) =>
      entry.id === id && entry.kind === "assistant_reasoning"
        ? { ...entry, text: entry.text + delta }
        : entry,
    );
  }
  return sortHistory([
    ...history,
    { id, seq: pendingReasoningSeq, kind: "assistant_reasoning", text: delta },
  ]);
}

function applyDisplayComplete(history: WebHistoryEntry[], data: Record<string, unknown>) {
  const attemptId = data.attempt_id;
  if (attemptId === undefined || attemptId === null) return null;
  const text = stringField(data, "presentation_text") ?? stringField(data, "text") ?? "";
  const reasoning = stringField(data, "reasoning") ?? "";
  const seq = numberField(data, "seq");
  const displayAttemptId = attemptId as string | number;
  // Drop attempt-scoped text + reasoning provisionals; Complete owns the
  // terminal payload (attempt IDs are live-only).
  let withoutPending = history.filter(
    (entry) =>
      entry.id !== pendingDisplayId(displayAttemptId) &&
      entry.id !== pendingDisplayReasoningId(displayAttemptId),
  );
  if (!text.trim() && !reasoning.trim()) return withoutPending;
  // seq:None (timeline write failure): keep attempt-keyed provisionals so a
  // following AssistantText can upsert once without duplicating the reply.
  if (seq == null) {
    if (text.trim()) {
      withoutPending = sortHistory([
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
      withoutPending = sortHistory([
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
      id: "assistant:" + seq,
      seq,
      kind: "assistant_text",
      text,
    });
  }
  if (reasoning.trim()) {
    withoutPending = upsertHistory(withoutPending, {
      id: "reasoning:" + seq,
      seq,
      kind: "assistant_reasoning",
      text: reasoning,
    });
  }
  return withoutPending;
}

function applyDisplayAttemptReset(history: WebHistoryEntry[], data: Record<string, unknown>) {
  const failed = data.failed_attempt_id;
  if (failed === undefined || failed === null) return history;
  const failedAttemptId = failed as string | number;
  return history.filter(
    (entry) =>
      entry.id !== pendingDisplayId(failedAttemptId) &&
      entry.id !== pendingDisplayReasoningId(failedAttemptId),
  );
}

function applyDisplayError(history: WebHistoryEntry[], data: Record<string, unknown>) {
  const attemptId = data.attempt_id;
  if (attemptId === undefined || attemptId === null) return null;
  const message = stringField(data, "message") ?? "assistant display error";
  const presentation = stringField(data, "presentation_text");
  const detail = presentation?.trim() ? `${presentation}\n${message}` : message;
  // Live-only error row: pending-range seq so history_replay attach drops it.
  const seq = pendingAssistantSeq;
  const displayAttemptId = attemptId as string | number;
  return upsertHistory(
    history.filter(
      (entry) =>
        entry.id !== pendingDisplayId(displayAttemptId) &&
        entry.id !== pendingDisplayReasoningId(displayAttemptId) &&
        !String(entry.id).startsWith("assistant-error:live:"),
    ),
    {
      id: "assistant-error:live:" + displayAttemptId,
      seq,
      kind: "inference_failure",
      failure: {
        agent: stringField(data, "agent") ?? "assistant",
        provider: "",
        model: "",
        errorClass: stringField(data, "kind") ?? "failed",
        detail,
        recovery: { kind: "generic", messageKey: "remote.authGeneric" },
      },
    },
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

function usageFromData(data: Record<string, unknown>): WebUsage {
  const inputTokens = numberField(data, "input_tokens") ?? 0;
  const outputTokens = numberField(data, "output_tokens") ?? 0;
  return {
    inputTokens,
    outputTokens,
    totalTokens: inputTokens + outputTokens,
  };
}

function applyInferenceFailure(history: WebHistoryEntry[], data: Record<string, unknown>) {
  const agent = stringField(data, "agent");
  const provider = stringField(data, "provider");
  const model = stringField(data, "model");
  const detail = stringField(data, "detail");
  if (!agent || !provider || !model || !detail) return null;
  const seq = numberField(data, "seq") ?? nextLocalSeq(history);
  return upsertHistory(history, {
    id: "inference-failure:" + seq,
    seq,
    kind: "inference_failure",
    failure: {
      agent,
      provider,
      model,
      detail,
      errorClass: errorClassLabel(data.error_class),
      recovery: authRecoveryView(data.auth_failure),
    },
  });
}

function activeModelFromData(data: Record<string, unknown>): WebActiveModelState | null {
  const parsed = activeModelStateSchema.safeParse(data);
  if (!parsed.success) return null;
  const { selection, default_selection: defaultSelection, diverged, generation } = parsed.data;
  return {
    selection,
    defaultSelection: defaultSelection ?? undefined,
    provider: selection.provider,
    model: selection.model,
    configProvider: defaultSelection?.provider,
    configModel: defaultSelection?.model,
    diverged,
    generation,
  };
}

function applyActiveModelState(
  existing: InstanceRemoteState,
  sessionId: string,
  activeModel: WebActiveModelState,
  acceptSameGeneration: boolean,
) {
  const current = existing.detailsBySession[sessionId]?.activeModel;
  if (
    current &&
    (activeModel.generation < current.generation ||
      (!acceptSameGeneration && activeModel.generation === current.generation))
  ) {
    return existing;
  }
  const state = updateDetail(existing, sessionId, (detail) => ({ ...detail, activeModel }));
  return updateSessionSummary(state, sessionId, {
    model: `${activeModel.provider}/${activeModel.model}`,
  });
}

function applyPausedWork(existing: InstanceRemoteState, sessionId: string, items: unknown[]) {
  const attention = items.length ? ({ kind: "paused_work" } as const) : null;
  const state = updateDetail(existing, sessionId, (detail) => ({
    ...detail,
    pausedWork: items.length ? { items } : undefined,
  }));
  const currentAttention = state.detailsBySession[sessionId]?.summary.attention;
  if (currentAttention?.kind === "approval" && items.length) return state;
  if (currentAttention?.kind === "approval" && !items.length) return state;
  return updateSessionSummary(state, sessionId, { attention });
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

  if (event.event === "assistant_display_text_delta") {
    if (!sessionId || typeof data?.delta !== "string" || data.attempt_id == null)
      return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        history: appendDisplayTextDelta(
          detail.history,
          data.attempt_id as string | number,
          data.delta as string,
        ),
      })),
    };
  }

  if (event.event === "assistant_display_reasoning_delta") {
    if (!sessionId || typeof data?.delta !== "string" || data.attempt_id == null)
      return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        history: appendDisplayReasoningDelta(
          detail.history,
          data.attempt_id as string | number,
          data.delta as string,
        ),
      })),
    };
  }

  if (event.event === "assistant_display_attempt_reset") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        history: applyDisplayAttemptReset(detail.history, data),
      })),
    };
  }

  if (event.event === "assistant_display_complete") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const state = updateDetail(existing, sessionId, (detail) => {
      const history = applyDisplayComplete(detail.history, data);
      if (!history) return detail;
      return { ...detail, history, nextSeq: nextSeqFromHistory(history) };
    });
    return { state };
  }

  if (event.event === "assistant_display_error") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const state = updateDetail(existing, sessionId, (detail) => {
      const history = applyDisplayError(detail.history, data);
      if (!history) return detail;
      return { ...detail, history, nextSeq: nextSeqFromHistory(history) };
    });
    return { state };
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
    const removedUserMessageSeqs = Array.isArray(data.removed_user_message_seqs)
      ? data.removed_user_message_seqs.filter((seq): seq is number => typeof seq === "number")
      : [];
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const replayedHistory = sortHistory(
          entries.map((entry, index) => toWebHistoryEntry(entry as WireHistoryEntry, index)),
        );
        const history = mergeHistorySnapshot(
          removeDurableUserMessages(detail.history, removedUserMessageSeqs),
          replayedHistory,
        );
        return {
          ...detail,
          history,
          nextSeq: nextSeqFromHistory(history),
          paging: pagingFromHistory(history, detail.paging),
        };
      }),
    };
  }

  if (event.event === "queued_user_messages_folded") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const clientSubmissionIds = Array.isArray(data.queue_item_ids)
      ? data.queue_item_ids.filter((id): id is string => typeof id === "string")
      : [];
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const text =
          stringField(data, "display_text") ??
          stringField(data, "preflight_cleaned") ??
          stringField(data, "text");
        if (text === undefined || text === null) return detail;
        const seq = numberField(data, "seq") ?? nextLocalSeq(detail.history);
        const history = upsertHistory(
          detail.history.filter(
            (entry) => !clientSubmissionIds.some((id) => entry.id === pendingUserPrefix + id),
          ),
          {
            id: "user:" + seq,
            seq,
            kind: "user_message",
            text,
            actor: { origin: "web" },
            clientSubmissionIds,
          },
        );
        return { ...detail, history, nextSeq: nextSeqFromHistory(history) };
      }),
    };
  }

  if (event.event === "user_message_recorded") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const clientSubmissionIds = Array.isArray(data.client_submission_ids)
          ? data.client_submission_ids.filter((id): id is string => typeof id === "string")
          : [];
        const pending = detail.history.find(
          (entry) =>
            entry.kind === "user_message" &&
            clientSubmissionIds.some((id) => entry.id === pendingUserPrefix + id),
        );
        const text =
          stringField(data, "preflight_cleaned") ??
          (pending?.kind === "user_message" ? pending.text : null);
        if (!text) return detail;
        const seq = numberField(data, "seq") ?? nextLocalSeq(detail.history);
        const history = upsertHistory(
          detail.history.filter(
            (entry) => !clientSubmissionIds.some((id) => entry.id === pendingUserPrefix + id),
          ),
          {
            id: "user:" + seq,
            seq,
            kind: "user_message",
            text,
            actor: { origin: "web" },
            clientSubmissionIds,
          },
        );
        return { ...detail, history, nextSeq: nextSeqFromHistory(history) };
      }),
    };
  }

  if (event.event === "user_message_removed") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const seq = numberField(data, "seq");
    if (seq === undefined) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const history = removeDurableUserMessages(detail.history, [seq]);
        if (history === detail.history) return detail;
        return {
          ...detail,
          history,
          nextSeq: nextSeqFromHistory(history),
          paging: pagingFromHistory(history, detail.paging),
        };
      }),
    };
  }

  if (event.event === "session_persist_failed") {
    // Preserve the exact optimistic row for the identified submission. The send
    // path retains its complete wire payload for retry and other in-flight rows
    // must remain untouched.
    return { state: existing };
  }

  if (event.event === "user_messages_terminated" || event.event === "user_message_retracted") {
    if (!sessionId || !data || !Array.isArray(data.client_submission_ids)) {
      return { state: existing, warningKind: event.event };
    }
    const terminalIds = data.client_submission_ids.filter(
      (id): id is string => typeof id === "string",
    );
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        history: detail.history.filter(
          (entry) => !terminalIds.some((id) => entry.id === pendingUserPrefix + id),
        ),
      })),
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

  if (event.event === "active_model_state") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const activeModel = activeModelFromData(data);
    if (!activeModel) return { state: existing, warningKind: event.event };
    return {
      // Config/default corrections do not advance the selection generation.
      // Event order within a live attachment is authoritative, so accept an
      // equal generation while continuing to reject genuinely older state.
      state: applyActiveModelState(existing, sessionId, activeModel, true),
    };
  }

  if (event.event === "model_selection_result") {
    const parsedResult = modelSelectionResultDataSchema.safeParse(event.data);
    if (!parsedResult.success) return { state: existing, warningKind: event.event };
    if (parsedResult.data.outcome.status === "rejected") return { state: existing };
    const activeModel = activeModelFromData(parsedResult.data.outcome.active_state);
    if (!activeModel) return { state: existing, warningKind: event.event };
    // The terminal result can correct default/divergence state without a
    // selection-generation increment, so equality is accepted here.
    return {
      state: applyActiveModelState(existing, parsedResult.data.session_id, activeModel, true),
    };
  }

  if (event.event === "inference_failed") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const history = applyInferenceFailure(detail.history, data);
        return history ? { ...detail, history, nextSeq: nextSeqFromHistory(history) } : detail;
      }),
    };
  }

  if (event.event === "sandbox_unavailable") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const remedy = stringField(data, "remedy");
    if (!remedy) return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        sandboxUnavailable: {
          remedy,
          fixCommand: stringField(data, "fix_command"),
        },
      })),
    };
  }

  if (event.event === "sandbox_state") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    if (booleanField(data, "enabled") !== false) return { state: existing };
    return {
      state: updateDetail(existing, sessionId, (detail) => ({
        ...detail,
        sandboxUnavailable: undefined,
      })),
    };
  }

  if (event.event === "daemon_draining") {
    if (!data) return { state: existing, warningKind: event.event };
    const forced = booleanField(data, "forced");
    if (forced === undefined) return { state: existing, warningKind: event.event };
    return { state: { ...existing, draining: { forced } } };
  }

  if (event.event === "waiting_for_lock") {
    if (!sessionId || !data) return { state: existing, warningKind: event.event };
    const path = stringField(data, "path");
    const holderAgent = stringField(data, "holder_agent");
    const waiting = booleanField(data, "waiting");
    if (!path || !holderAgent || waiting === undefined)
      return { state: existing, warningKind: event.event };
    return {
      state: updateDetail(existing, sessionId, (detail) => {
        const waitingLocks = { ...detail.waitingLocks };
        if (waiting) waitingLocks[path] = { path, holderAgent };
        else delete waitingLocks[path];
        return { ...detail, waitingLocks };
      }),
    };
  }

  if (event.event === "paused_work_available") {
    if (!sessionId || !data || !Array.isArray(data.items))
      return { state: existing, warningKind: event.event };
    return { state: applyPausedWork(existing, sessionId, data.items) };
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
  pendingUserSubmissions.clear();
  webAttachCoordinators.clear();
}

export function isWebAttachmentReady(
  remote: InstanceRemoteState | undefined,
  sessionId: string | null,
) {
  return (
    remote?.status === "connected" &&
    sessionId !== null &&
    remote.attachment.phase === "applied" &&
    remote.attachment.sessionId === sessionId
  );
}

export function webAttachmentAfterConnectionStatus(
  current: Pick<InstanceRemoteState, "attachment" | "status">,
  status: ConnectionStatus,
): WebAttachmentState {
  if (status === "connected" && current.status !== "connected") {
    return {
      connectionEpoch: current.attachment.connectionEpoch + 1,
      phase: "detached",
    };
  }
  if (status !== "connected") {
    return {
      connectionEpoch: current.attachment.connectionEpoch,
      phase: "detached",
    };
  }
  return current.attachment;
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

export function removeOptimisticUserMessage(
  existing: InstanceRemoteState,
  sessionId: string,
  clientMessageId: string,
): InstanceRemoteState {
  return updateDetail(existing, sessionId, (detail) => ({
    ...detail,
    history: detail.history.filter((entry) => entry.id !== pendingUserPrefix + clientMessageId),
  }));
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

function isCurrentWebAttachAttempt(
  state: Pick<RemoteSessionState, "clients" | "instances">,
  instanceId: string,
  coordinator: WebAttachCoordinator,
  attempt: WebAttachAttempt,
) {
  const remote = state.instances[instanceId];
  return (
    remote?.status === "connected" &&
    coordinator.isCurrent(attempt, state.clients[instanceId], remote.attachment.connectionEpoch)
  );
}

function attachedWebClient(
  state: Pick<RemoteSessionState, "clients" | "instances">,
  instanceId: string,
  sessionId: string,
) {
  const remote = state.instances[instanceId];
  const client = state.clients[instanceId];
  return client && isWebAttachmentReady(remote, sessionId) ? client : undefined;
}

function attachmentNotReadyError() {
  return new Error("The selected session attachment is not ready.");
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
    const coordinator = webAttachCoordinator(instanceId);
    coordinator.invalidate();
    let client: RemoteSessionClient;
    client = new RemoteSessionClient({
      instanceId,
      relayUrl: tokenInfo.relayUrl,
      token: tokenInfo.token,
      baseUrl: window.location.origin,
      onStatus: (status, statusDetail) => {
        if (get().clients[instanceId] !== client) return;
        set((state) => ({
          ...state,
          instances: setInstance(state.instances, instanceId, (current) => {
            if (state.clients[instanceId] !== client) return current;
            const attachment = webAttachmentAfterConnectionStatus(current, status);
            if (attachment !== current.attachment) {
              coordinator.invalidate();
            }
            return {
              ...current,
              status,
              statusDetail,
              attachment,
            };
          }),
        }));
      },
      onEvent: (event) => {
        if (get().clients[instanceId] !== client) return;
        set((state) => ({
          ...state,
          instances: {
            ...state.instances,
            [instanceId]:
              state.clients[instanceId] === client
                ? applyRemoteSessionClientEvent(
                    instanceId,
                    state.instances[instanceId] ?? emptyInstance(),
                    event,
                  )
                : (state.instances[instanceId] ?? emptyInstance()),
          },
        }));
      },
    });
    set((state) => ({
      clients: { ...state.clients, [instanceId]: client },
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        status: "connecting",
        attachment: {
          connectionEpoch: current.attachment.connectionEpoch,
          phase: "detached",
        },
      })),
    }));
    client.connect();
  },
  disconnect: (instanceId) => {
    get().clients[instanceId]?.close();
    webAttachCoordinator(instanceId).invalidate();
    set((state) => ({
      clients: { ...state.clients, [instanceId]: undefined },
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        status: "offline",
        attachment: {
          connectionEpoch: current.attachment.connectionEpoch,
          phase: "detached",
        },
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
  getStorageReport: async (instanceId) => {
    const client = get().clients[instanceId];
    if (!client) throw new Error("Instance connection is not open.");
    return client.getStorageReport();
  },
  dismissStorageManagementHint: async (instanceId, expectedVersion) => {
    const client = get().clients[instanceId];
    if (!client) throw new Error("Instance connection is not open.");
    await client.dismissStorageManagementHint(expectedVersion);
  },
  previewStorageCleanup: async (instanceId, target) => {
    const client = get().clients[instanceId];
    if (!client) throw new Error("Instance connection is not open.");
    return client.previewStorageCleanup({ target });
  },
  executeStorageCleanup: async (instanceId, previewId) => {
    const client = get().clients[instanceId];
    if (!client) throw new Error("Instance connection is not open.");
    return client.executeStorageCleanup(previewId);
  },
  attach: async (instanceId, sessionId) => {
    const initial = get();
    const client = initial.clients[instanceId];
    const remote = initial.instances[instanceId];
    if (!client || remote?.status !== "connected") return;
    const session =
      Object.values(remote.sessionsByProject)
        .flat()
        .find((candidate) => candidate.sessionId === sessionId) ??
      remote.detailsBySession[sessionId]?.summary;
    if (!session || session.sessionEntryMode === "code") {
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) => ({
          ...current,
          attachment: {
            connectionEpoch: remote.attachment.connectionEpoch,
            phase: "failed",
            sessionId,
            error: "This client can attach only assistant or computer sessions.",
          },
        })),
      }));
      return;
    }

    const connectionEpoch = remote.attachment.connectionEpoch;
    const coordinator = webAttachCoordinator(instanceId);
    const attempt = coordinator.begin(client, connectionEpoch, sessionId);
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        attachment: { connectionEpoch, phase: "pending", sessionId },
      })),
    }));
    const isCurrent = () => isCurrentWebAttachAttempt(get(), instanceId, coordinator, attempt);

    try {
      const result = await client.attach({
        session_id: sessionId,
        interactive: true,
        session_entry_mode: session.sessionEntryMode,
      });
      if (!isCurrent()) return;
      if (result.session_id !== sessionId) {
        throw new Error("Instance attached a different session than requested.");
      }
      forgetAcceptedUserSubmissions(
        instanceId,
        result.session_id,
        acceptedClientSubmissionIdsFromHistory(result.history),
      );
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) =>
          mergeAttach(current, result),
        ),
      }));

      const replay = await replayPendingUserSubmissions(
        client,
        instanceId,
        result.session_id,
        isCurrent,
      );
      if (!replay.current || !isCurrent()) return;
      if (!coordinator.finish(attempt, get().clients[instanceId], connectionEpoch)) return;
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) => {
          const reconciled = replay.rejectedIds.reduce(
            (next, id) => removeOptimisticUserMessage(next, result.session_id, id),
            current,
          );
          return {
            ...reconciled,
            attachment: {
              connectionEpoch,
              phase: "applied",
              sessionId: result.session_id,
            },
          };
        }),
      }));
    } catch (error) {
      if (!isCurrent()) return;
      if (!coordinator.finish(attempt, get().clients[instanceId], connectionEpoch)) return;
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) => ({
          ...current,
          attachment: {
            connectionEpoch,
            phase: "failed",
            sessionId,
            error: errorMessage(error),
          },
        })),
      }));
    }
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
    const initial = get();
    const client = initial.clients[instanceId];
    const remote = initial.instances[instanceId];
    if (!client || remote?.status !== "connected") {
      throw new Error("Instance connection is not open.");
    }
    const previousSessionId =
      remote.attachment.phase === "applied" ? remote.attachment.sessionId : undefined;
    const connectionEpoch = remote.attachment.connectionEpoch;
    const coordinator = webAttachCoordinator(instanceId);
    const attempt = coordinator.begin(client, connectionEpoch);
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        attachment: { connectionEpoch, phase: "pending" },
      })),
    }));
    const isCurrent = () => isCurrentWebAttachAttempt(get(), instanceId, coordinator, attempt);

    try {
      const result = await client.attach({
        project_root: input.projectRoot,
        interactive: true,
        session_entry_mode: "assistant",
        initial_model: input.initialModel,
      });
      if (!isCurrent() || !coordinator.bindSession(attempt, result.session_id)) {
        throw new Error("Session creation was superseded by a newer attachment.");
      }
      forgetAcceptedUserSubmissions(
        instanceId,
        result.session_id,
        acceptedClientSubmissionIdsFromHistory(result.history),
      );
      let created: SessionDetail | null = null;
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) => {
          const next = mergeAttach(current, result);
          created = next.detailsBySession[result.session_id] ?? null;
          return {
            ...next,
            attachment: {
              connectionEpoch,
              phase: "pending",
              sessionId: result.session_id,
            },
          };
        }),
      }));
      if (!created) throw new Error("Instance did not return a session.");

      const replay = await replayPendingUserSubmissions(
        client,
        instanceId,
        result.session_id,
        isCurrent,
      );
      if (!replay.current || !isCurrent()) {
        throw new Error("Session creation was superseded by a newer attachment.");
      }
      let agentApplied = false;
      let titleApplied = false;
      try {
        if (input.agent) {
          await client.setAgent(input.agent);
          if (!isCurrent()) {
            throw new Error("Session creation was superseded by a newer attachment.");
          }
          agentApplied = true;
        }
        if (input.title) {
          await client.renameSession(result.session_id, input.title);
          if (!isCurrent()) {
            throw new Error("Session creation was superseded by a newer attachment.");
          }
          titleApplied = true;
        }
      } catch (setupError) {
        if (!isCurrent()) {
          throw new Error("Session creation was superseded by a newer attachment.");
        }
        if (!coordinator.finish(attempt, get().clients[instanceId], connectionEpoch)) {
          throw new Error("Session creation was superseded by a newer attachment.");
        }
        let attachedCreated: SessionDetail | null = null;
        set((state) => ({
          instances: setInstance(state.instances, instanceId, (current) => {
            const reconciled = replay.rejectedIds.reduce(
              (next, id) => removeOptimisticUserMessage(next, result.session_id, id),
              current,
            );
            const updated = updateSessionSummary(reconciled, result.session_id, {
              agent: agentApplied ? input.agent : created?.summary.agent,
              title: titleApplied ? input.title : created?.summary.title,
            });
            const next = {
              ...updated,
              attachment: {
                connectionEpoch,
                phase: "applied" as const,
                sessionId: result.session_id,
              },
            };
            attachedCreated = next.detailsBySession[result.session_id] ?? created;
            return next;
          }),
        }));
        throw new WebSessionCreatedWithSetupError(attachedCreated ?? created, setupError);
      }
      if (input.agent || input.title || replay.rejectedIds.length > 0) {
        set((state) => ({
          instances: setInstance(state.instances, instanceId, (current) => {
            const reconciled = replay.rejectedIds.reduce(
              (next, id) => removeOptimisticUserMessage(next, result.session_id, id),
              current,
            );
            return updateSessionSummary(reconciled, result.session_id, {
              agent: input.agent ?? created?.summary.agent,
              title: input.title ?? created?.summary.title,
            });
          }),
        }));
      }
      if (!coordinator.finish(attempt, get().clients[instanceId], connectionEpoch)) {
        throw new Error("Session creation was superseded by a newer attachment.");
      }
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) => ({
          ...current,
          attachment: {
            connectionEpoch,
            phase: "applied",
            sessionId: result.session_id,
          },
        })),
      }));
      return created;
    } catch (error) {
      if (isCurrent()) {
        coordinator.finish(attempt, get().clients[instanceId], connectionEpoch);
        set((state) => ({
          instances: setInstance(state.instances, instanceId, (current) => ({
            ...current,
            attachment: {
              connectionEpoch,
              phase: "failed",
              sessionId: previousSessionId ?? attempt.sessionId,
              error: errorMessage(error),
            },
          })),
        }));
        if (previousSessionId) {
          await get().attach(instanceId, previousSessionId);
        }
      }
      throw error;
    }
  },
  sendMessage: async (instanceId, sessionId, input) => {
    const client = attachedWebClient(get(), instanceId, sessionId);
    if (!client) throw attachmentNotReadyError();
    const repairRequired = get().instances[instanceId]?.detailsBySession[sessionId]?.repairRequired;
    if (repairRequired) throw new Error(repairRequired.detail);
    const key = pendingUserSubmissionKey(instanceId, sessionId);
    const prepared = retainedUserSubmission(pendingUserSubmissions.get(key), input);
    const submission = retainUserSubmission(key, prepared.submission);
    const isRetry = prepared.isRetry || submission !== prepared.submission;
    if (!isRetry) {
      set((state) => ({
        instances: setInstance(state.instances, instanceId, (current) =>
          addOptimisticUserMessage(
            current,
            sessionId,
            submission.display_text ?? submission.text,
            submission.client_submission_id,
          ),
        ),
      }));
    }

    try {
      await client.sendUserMessage(submission);
    } catch (error) {
      const retainable = shouldRetainUserMessageSubmission(error);
      if (retainable && !pendingUserSubmissions.get(key)?.has(submission.client_submission_id)) {
        // A durable event/attach receipt won the race with the ambiguous
        // transport result. Acceptance is authoritative; do not reopen retry.
        return;
      }
      if (!retainable) {
        forgetUserSubmission(key, submission.client_submission_id);
        set((state) => ({
          instances: setInstance(state.instances, instanceId, (current) =>
            removeOptimisticUserMessage(current, sessionId, submission.client_submission_id),
          ),
        }));
      }
      throw error;
    }
    // `UserMessageQueued` is not durable. The live record/fold event or an
    // authoritative attach snapshot releases this exact payload.
  },
  resolveInterrupt: async (instanceId, input) => {
    const client = attachedWebClient(get(), instanceId, input.sessionId);
    if (!client) throw attachmentNotReadyError();
    const detail = get().instances[instanceId]?.detailsBySession[input.sessionId];
    const entry = detail?.history.find(
      (entry) => entry.kind === "interrupt" && entry.interrupt.interruptId === input.interruptId,
    );
    if (entry?.kind !== "interrupt") return;
    await client.resolveInterrupt(
      input.interruptId,
      resolveFromSelection(entry.interrupt.question, input.selection),
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
    await get().clients[instanceId]?.forkSession({
      parent_session_id: sessionId,
      fresh_thread: false,
    });
  },
  resumePausedWork: async (instanceId, sessionId) => {
    const client = attachedWebClient(get(), instanceId, sessionId);
    if (!client) throw attachmentNotReadyError();
    await client.resumePausedWork(sessionId);
  },
  cancelPausedWork: async (instanceId, sessionId) => {
    const client = attachedWebClient(get(), instanceId, sessionId);
    if (!client) throw attachmentNotReadyError();
    await client.cancelPausedWork(sessionId);
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
