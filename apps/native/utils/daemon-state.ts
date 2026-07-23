import type { EventEnvelope } from "@flycockpit/cockpit-protocol";

export type SandboxNotice = {
  remedy: string;
  fixCommand: string | null;
};

export type DrainingNotice = {
  forced: boolean;
  copy: string;
};

export type WaitingForLockNotice = {
  path: string;
  holderAgent: string;
};

export type PausedWorkNotice = {
  sessionId: string;
  items: unknown[];
};

export type NativeDaemonState = {
  sandboxNotice: SandboxNotice | null;
  draining: DrainingNotice | null;
  waitingForLock: WaitingForLockNotice | null;
  pausedWork: PausedWorkNotice | null;
};

export type PausedWorkClient = {
  resumePausedWork: (sessionId: string) => Promise<unknown>;
  cancelPausedWork: (sessionId: string) => Promise<unknown>;
};

export const emptyNativeDaemonState: NativeDaemonState = {
  sandboxNotice: null,
  draining: null,
  waitingForLock: null,
  pausedWork: null,
};

function eventData(event: EventEnvelope) {
  const data = event.data;
  return data && typeof data === "object" ? (data as Record<string, unknown>) : null;
}

function stringField(data: Record<string, unknown>, key: string) {
  const value = data[key];
  return typeof value === "string" ? value : null;
}

function booleanField(data: Record<string, unknown>, key: string) {
  const value = data[key];
  return typeof value === "boolean" ? value : null;
}

function sandboxAvailable(data: Record<string, unknown>) {
  const availability = data.container_availability;
  if (availability && typeof availability === "object") {
    const available = (availability as Record<string, unknown>).available;
    if (available === true) return true;
  }
  return data.enabled === false;
}

export function daemonStateReducer(
  state: NativeDaemonState,
  event: EventEnvelope,
  selectedSessionId: string | null,
): NativeDaemonState {
  const data = eventData(event);

  if (event.event === "daemon_draining") {
    const forced = data ? booleanField(data, "forced") === true : false;
    return {
      ...state,
      draining: {
        forced,
        copy: forced
          ? "The daemon is draining and has reached its grace deadline."
          : "The daemon is draining. New input is paused.",
      },
    };
  }

  const sessionId = data ? stringField(data, "session_id") : null;
  if (sessionId && selectedSessionId && sessionId !== selectedSessionId) return state;

  if (event.event === "sandbox_unavailable" && data) {
    const remedy = stringField(data, "remedy");
    if (!remedy) return state;
    return {
      ...state,
      sandboxNotice: {
        remedy,
        fixCommand: stringField(data, "fix_command"),
      },
    };
  }

  if (event.event === "sandbox_state" && data && sandboxAvailable(data)) {
    return { ...state, sandboxNotice: null };
  }

  if (event.event === "waiting_for_lock" && data) {
    if (booleanField(data, "waiting") === false) return { ...state, waitingForLock: null };
    const path = stringField(data, "path");
    const holderAgent = stringField(data, "holder_agent");
    if (!path || !holderAgent) return state;
    return { ...state, waitingForLock: { path, holderAgent } };
  }

  if (event.event === "paused_work_available" && data) {
    const items = Array.isArray(data.items) ? data.items : [];
    const pausedSessionId = stringField(data, "session_id");
    if (!pausedSessionId) return state;
    if (items.length === 0) return { ...state, pausedWork: null };
    return { ...state, pausedWork: { sessionId: pausedSessionId, items } };
  }

  return state;
}

export function composerSendDisabled(input: {
  message: string;
  busy: boolean;
  draining: DrainingNotice | null;
}) {
  return !input.message.trim() || input.busy || Boolean(input.draining);
}

export async function resumePausedWorkAction(
  client: Pick<PausedWorkClient, "resumePausedWork">,
  state: NativeDaemonState,
) {
  if (!state.pausedWork) return;
  await client.resumePausedWork(state.pausedWork.sessionId);
}

export async function cancelPausedWorkAction(
  client: Pick<PausedWorkClient, "cancelPausedWork">,
  state: NativeDaemonState,
) {
  if (!state.pausedWork) return;
  await client.cancelPausedWork(state.pausedWork.sessionId);
}
