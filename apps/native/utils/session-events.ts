import {
  type AttachResult,
  type EventEnvelope,
  eventEnvelopeSchema,
  type HistoryEntry,
  type InterruptQuestion,
  type ResolveResponse,
} from "@flycockpit/cockpit-protocol";
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

export type InterruptResolutionAction = "approve" | "deny" | "answer";

const pendingAssistantId = "assistant:pending";
const pendingUserPrefix = "user:pending:";
const pendingUserSeq = Number.MAX_SAFE_INTEGER - 2;
const pendingAssistantSeq = Number.MAX_SAFE_INTEGER - 1;
const pendingInterruptSeq = Number.MAX_SAFE_INTEGER;

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
  if (!value || typeof value !== "object") return null;
  const data = value as Record<string, unknown>;
  return {
    provider: typeof data.provider === "string" ? data.provider : undefined,
    model: typeof data.model === "string" ? data.model : undefined,
    config_provider: typeof data.config_provider === "string" ? data.config_provider : undefined,
    config_model: typeof data.config_model === "string" ? data.config_model : undefined,
    diverged: typeof data.diverged === "boolean" ? data.diverged : undefined,
    generation: typeof data.generation === "number" ? data.generation : undefined,
  };
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
    return {
      id: entryId("assistant", seq),
      seq,
      kind: "assistant_text",
      text: entry.text,
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
    return {
      id: entryId("interrupt-decision", seq),
      seq,
      kind: "assistant_reasoning",
      text: entry.decision.cancelled ? "Interrupt cancelled" : "Interrupt resolved",
    };
  }
  return {
    id: entryId("unknown", seq),
    seq,
    kind: "assistant_reasoning",
    text: "Unknown transcript entry",
  };
}

export function nativeAttachRuntimeState(
  attach: AttachResult,
  previousDaemonState: NativeDaemonState = emptyNativeDaemonState,
): NativeAttachRuntimeState {
  const raw = attach as AttachResult & {
    active_model_state?: unknown;
    paused_work?: unknown;
  };
  const activeModelInput = activeModelInputFromRecord(raw.active_model_state);
  const pausedWork = Array.isArray(raw.paused_work)
    ? raw.paused_work.filter((item) => item && typeof item === "object")
    : [];
  return {
    daemonState: {
      ...previousDaemonState,
      pausedWork: pausedWork.length ? { sessionId: attach.session_id, items: pausedWork } : null,
    },
    activeModel: activeModelInput ? activeModelReducer(null, activeModelInput) : null,
    llmMode: null,
  };
}

export function sortNativeHistory(history: NativeHistoryEntry[]) {
  return [...history].sort((a, b) => a.seq - b.seq || a.id.localeCompare(b.id));
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

function applyAssistantText(history: NativeHistoryEntry[], data: { seq?: number; text: string }) {
  const seq = typeof data.seq === "number" ? data.seq : nextLocalSeq(history);
  const finalEntry: NativeHistoryEntry = {
    id: entryId("assistant", seq),
    seq,
    kind: "assistant_text",
    text: data.text,
  };
  return upsertHistory(
    history.filter((entry) => entry.id !== pendingAssistantId),
    finalEntry,
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

export function removeOptimisticUserMessage(
  history: NativeHistoryEntry[],
  localId: string,
): NativeHistoryEntry[] {
  return history.filter((entry) => entry.id !== pendingUserPrefix + localId);
}

export function reconcileRecordedUserMessage(
  history: NativeHistoryEntry[],
  data: { seq?: number; preflight_cleaned?: string | null },
): NativeHistoryEntry[] {
  const pending = history.find(
    (entry) => entry.kind === "user_message" && entry.id.startsWith(pendingUserPrefix),
  );
  const text = data.preflight_cleaned || (pending?.kind === "user_message" ? pending.text : null);
  if (!text) return history;
  const seq = typeof data.seq === "number" ? data.seq : nextLocalSeq(history);
  const recorded: NativeHistoryEntry = {
    id: entryId("user", seq),
    seq,
    kind: "user_message",
    text,
  };
  return upsertHistory(
    history.filter((entry) => entry.id !== pending?.id),
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
    return {
      state: {
        ...state,
        activeModel: activeModelReducer(state.activeModel ?? null, {
          ...activeModelInputFromRecord(data),
        }),
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
    return {
      state: {
        ...state,
        history: sortNativeHistory(
          data.entries.map((entry, index) => toNativeHistoryEntry(entry, index)),
        ),
      },
    };
  }

  if (event.event === "assistant_text_delta") {
    const data = eventDataRecord(event);
    if (typeof data?.delta !== "string") return { state, warning: eventWarning(event.event) };
    return { state: { ...state, history: appendAssistantDelta(state.history, data.delta) } };
  }

  if (event.event === "assistant_text") {
    const data = eventDataRecord(event);
    if (typeof data?.text !== "string") return { state, warning: eventWarning(event.event) };
    return {
      state: {
        ...state,
        history: applyAssistantText(state.history, {
          text: data.text,
          seq: typeof data.seq === "number" ? data.seq : undefined,
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
          preflight_cleaned:
            typeof data.preflight_cleaned === "string" || data.preflight_cleaned === null
              ? data.preflight_cleaned
              : undefined,
        }),
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

export function resolveResponseForInterrupt(
  question: InterruptQuestion,
  action: InterruptResolutionAction,
  answer: string,
): ResolveResponse {
  if (action === "deny") return { kind: "cancel" };
  if (question.kind === "freetext") return { kind: "freetext", data: { text: answer } };
  if (question.kind === "multi") {
    const selected = question.data.options[0]?.id;
    return selected ? { kind: "multi", data: { selected_ids: [selected] } } : { kind: "cancel" };
  }
  const selected = question.data.options[0]?.id;
  return selected ? { kind: "single", data: { selected_id: selected } } : { kind: "cancel" };
}
