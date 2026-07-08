import type {
  AttachResult,
  CockpitUsage,
  HistoryEntry,
  LiveEvent,
  ProjectSummary,
  SessionSummary,
} from "@flycockpit/cockpit-protocol";
import { create } from "zustand";
import { RemoteSessionClient } from "@/lib/remote-sessions/client";

type ConnectionStatus = "idle" | "connecting" | "connected" | "offline" | "error";

export type SessionDetail = {
  summary: SessionSummary;
  history: HistoryEntry[];
  schedules: unknown[];
  nextSeq: number;
  usage: CockpitUsage | null;
};

type InstanceRemoteState = {
  status: ConnectionStatus;
  statusDetail?: string;
  projects: ProjectSummary[];
  sessionsByProject: Record<string, SessionSummary[]>;
  detailsBySession: Record<string, SessionDetail>;
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
  attach: (instanceId: string, sessionId: string) => Promise<void>;
  createSession: (
    instanceId: string,
    input: { projectRoot: string; title?: string; agent?: string; model?: string },
  ) => Promise<AttachResult>;
  sendMessage: (instanceId: string, sessionId: string, text: string) => Promise<void>;
  resolveInterrupt: (
    instanceId: string,
    input: {
      sessionId: string;
      interruptId: string;
      resolution: "approve" | "deny" | "answer";
      answer?: string;
    },
  ) => Promise<void>;
  renameSession: (instanceId: string, sessionId: string, title: string) => Promise<void>;
  archiveSession: (instanceId: string, sessionId: string, archived: boolean) => Promise<void>;
  forkSession: (instanceId: string, sessionId: string) => Promise<void>;
  listFiles: (
    instanceId: string,
    input: { projectRoot: string; path: string; showHidden: boolean },
  ) => Promise<import("@flycockpit/cockpit-protocol").FsListResult>;
  readFile: (
    instanceId: string,
    input: { projectRoot: string; path: string },
  ) => Promise<import("@flycockpit/cockpit-protocol").FsReadResult>;
  writeFile: (
    instanceId: string,
    input: { projectRoot: string; path: string; content: string; baseHash?: string },
  ) => Promise<import("@flycockpit/cockpit-protocol").FsWriteResult>;
  createDirectory: (
    instanceId: string,
    input: { projectRoot: string; path: string },
  ) => Promise<void>;
  renamePath: (
    instanceId: string,
    input: { projectRoot: string; fromPath: string; toPath: string },
  ) => Promise<void>;
  deletePath: (instanceId: string, input: { projectRoot: string; path: string }) => Promise<void>;
  gitStatus: (
    instanceId: string,
    input: { projectRoot: string },
  ) => Promise<import("@flycockpit/cockpit-protocol").GitStatusResult>;
  gitDiffFile: (
    instanceId: string,
    input: { projectRoot: string; path: string },
  ) => Promise<import("@flycockpit/cockpit-protocol").GitDiffFileResult>;
};

const emptyInstance = (): InstanceRemoteState => ({
  status: "idle",
  projects: [],
  sessionsByProject: {},
  detailsBySession: {},
});

function sortHistory(history: HistoryEntry[]) {
  return [...history].sort((a, b) => a.seq - b.seq || a.id.localeCompare(b.id));
}

function upsertHistory(history: HistoryEntry[], entry: HistoryEntry) {
  return sortHistory([entry, ...history.filter((item) => item.id !== entry.id)]);
}

export function mergeAttach(
  existing: InstanceRemoteState,
  attach: AttachResult,
): InstanceRemoteState {
  const current = existing.detailsBySession[attach.session.sessionId];
  const mergedHistory = sortHistory([
    ...(current?.history ?? []).filter((entry) => entry.seq >= attach.nextSeq),
    ...attach.history,
  ]);
  return {
    ...existing,
    detailsBySession: {
      ...existing.detailsBySession,
      [attach.session.sessionId]: {
        summary: attach.session,
        history: mergedHistory,
        schedules: attach.schedules,
        nextSeq: attach.nextSeq,
        usage: current?.usage ?? null,
      },
    },
  };
}

export function applyLiveEvent(
  existing: InstanceRemoteState,
  event: LiveEvent,
): InstanceRemoteState {
  if (event.type === "session_updated") {
    const projectRoot = event.summary.projectRoot;
    const sessions = existing.sessionsByProject[projectRoot] ?? [];
    const nextSessions = [
      event.summary,
      ...sessions.filter((s) => s.sessionId !== event.summary.sessionId),
    ].sort((a, b) => b.updatedAt - a.updatedAt);
    const detail = existing.detailsBySession[event.summary.sessionId];
    return {
      ...existing,
      sessionsByProject: { ...existing.sessionsByProject, [projectRoot]: nextSessions },
      detailsBySession: detail
        ? {
            ...existing.detailsBySession,
            [event.summary.sessionId]: { ...detail, summary: event.summary },
          }
        : existing.detailsBySession,
    };
  }

  const sessionId = "sessionId" in event ? event.sessionId : null;
  if (!sessionId) return existing;
  const detail = existing.detailsBySession[sessionId];
  if (!detail) return existing;

  if (event.type === "history_entry") {
    return {
      ...existing,
      detailsBySession: {
        ...existing.detailsBySession,
        [sessionId]: {
          ...detail,
          history: upsertHistory(detail.history, event.entry),
          nextSeq: Math.max(detail.nextSeq, event.entry.seq + 1),
        },
      },
    };
  }

  if (event.type === "assistant_delta") {
    return {
      ...existing,
      detailsBySession: {
        ...existing.detailsBySession,
        [sessionId]: {
          ...detail,
          history: detail.history.map((entry) =>
            entry.id === event.entryId && entry.kind === "assistant_text"
              ? { ...entry, text: entry.text + event.delta }
              : entry,
          ),
          nextSeq: Math.max(detail.nextSeq, event.seq + 1),
        },
      },
    };
  }

  if (event.type === "interrupt_resolved") {
    return {
      ...existing,
      detailsBySession: {
        ...existing.detailsBySession,
        [sessionId]: {
          ...detail,
          history: detail.history.map((entry) =>
            entry.kind === "interrupt" && entry.interrupt.interruptId === event.interruptId
              ? { ...entry, interrupt: { ...entry.interrupt, resolved: true } }
              : entry,
          ),
          nextSeq: event.seq ? Math.max(detail.nextSeq, event.seq + 1) : detail.nextSeq,
        },
      },
    };
  }

  if (event.type === "usage") {
    return {
      ...existing,
      detailsBySession: {
        ...existing.detailsBySession,
        [sessionId]: { ...detail, usage: event.usage },
      },
    };
  }

  if (event.type === "schedule_updated") {
    return {
      ...existing,
      detailsBySession: {
        ...existing.detailsBySession,
        [sessionId]: { ...detail, schedules: [event.schedule] },
      },
    };
  }

  return existing;
}

export function addOptimisticUserMessage(
  existing: InstanceRemoteState,
  sessionId: string,
  text: string,
  clientMessageId: string,
  now = Date.now(),
): InstanceRemoteState {
  const detail = existing.detailsBySession[sessionId];
  if (!detail) return existing;
  const optimistic: HistoryEntry = {
    id: clientMessageId,
    seq: detail.nextSeq,
    ts: Math.floor(now / 1000),
    kind: "user_message",
    text,
    attachments: [],
    actor: { origin: "web" },
  };
  return {
    ...existing,
    detailsBySession: {
      ...existing.detailsBySession,
      [sessionId]: {
        ...detail,
        history: upsertHistory(detail.history, optimistic),
        nextSeq: detail.nextSeq + 1,
      },
    },
  };
}

function setInstance(
  instances: Record<string, InstanceRemoteState>,
  instanceId: string,
  updater: (current: InstanceRemoteState) => InstanceRemoteState,
) {
  return { ...instances, [instanceId]: updater(instances[instanceId] ?? emptyInstance()) };
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
        set((state) => ({
          instances: setInstance(state.instances, instanceId, (current) =>
            applyLiveEvent(current, event as LiveEvent),
          ),
        }));
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
    const result = await get().clients[instanceId]?.listProjects();
    if (!result) return;
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        projects: result.projects,
      })),
    }));
  },
  loadSessions: async (instanceId, projectRoot) => {
    const result = await get().clients[instanceId]?.listSessions(projectRoot);
    if (!result) return;
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => ({
        ...current,
        sessionsByProject: { ...current.sessionsByProject, [projectRoot]: result.sessions },
      })),
    }));
  },
  attach: async (instanceId, sessionId) => {
    const current = get().instances[instanceId]?.detailsBySession[sessionId];
    const result = await get().clients[instanceId]?.attach(sessionId, current?.nextSeq);
    if (!result) return;
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) =>
        mergeAttach(current, result),
      ),
    }));
  },
  createSession: async (instanceId, input) => {
    const result = await get().clients[instanceId]?.createSession(input);
    if (!result) throw new Error("Instance connection is not open.");
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) =>
        mergeAttach(current, result),
      ),
    }));
    return result;
  },
  sendMessage: async (instanceId, sessionId, text) => {
    const clientMessageId = crypto.randomUUID();
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) =>
        addOptimisticUserMessage(current, sessionId, text, clientMessageId),
      ),
    }));
    await get().clients[instanceId]?.sendUserMessage(sessionId, text, clientMessageId);
  },
  resolveInterrupt: async (instanceId, input) => {
    await get().clients[instanceId]?.resolveInterrupt(input);
  },
  renameSession: async (instanceId, sessionId, title) => {
    await get().clients[instanceId]?.renameSession(sessionId, title);
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => {
        const detail = current.detailsBySession[sessionId];
        if (!detail) return current;
        return {
          ...current,
          detailsBySession: {
            ...current.detailsBySession,
            [sessionId]: { ...detail, summary: { ...detail.summary, title } },
          },
        };
      }),
    }));
  },
  archiveSession: async (instanceId, sessionId, archived) => {
    await get().clients[instanceId]?.archiveSession(sessionId, archived);
    set((state) => ({
      instances: setInstance(state.instances, instanceId, (current) => {
        const detail = current.detailsBySession[sessionId];
        if (!detail) return current;
        return {
          ...current,
          detailsBySession: {
            ...current.detailsBySession,
            [sessionId]: { ...detail, summary: { ...detail.summary, archived } },
          },
        };
      }),
    }));
  },
  forkSession: async (instanceId, sessionId) => {
    await get().clients[instanceId]?.forkSession(sessionId);
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
