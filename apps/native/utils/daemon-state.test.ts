import type { EventEnvelope } from "@flycockpit/cockpit-protocol";
import { describe, expect, it, vi } from "vitest";
import {
  cancelPausedWorkAction,
  composerSendDisabled,
  daemonStateReducer,
  emptyNativeDaemonState,
  resumePausedWorkAction,
} from "./daemon-state";

const sessionId = "11111111-1111-4111-8111-111111111111";

function event(event: string, data: Record<string, unknown>): EventEnvelope {
  return { v: 1, kind: "evt", event, data } as EventEnvelope;
}

describe("daemonStateReducer", () => {
  it("sets and clears sandbox unavailable notices", () => {
    const unavailable = daemonStateReducer(
      emptyNativeDaemonState,
      event("sandbox_unavailable", {
        session_id: sessionId,
        remedy: "Install Docker",
        fix_command: "brew install docker",
      }),
      sessionId,
    );

    expect(unavailable.sandboxNotice).toEqual({
      remedy: "Install Docker",
      fixCommand: "brew install docker",
    });

    const available = daemonStateReducer(
      unavailable,
      event("sandbox_state", {
        session_id: sessionId,
        enabled: true,
        container_availability: { available: true },
      }),
      sessionId,
    );
    expect(available.sandboxNotice).toBeNull();
  });

  it("sets a global daemon draining flag with forced copy", () => {
    const state = daemonStateReducer(
      emptyNativeDaemonState,
      event("daemon_draining", { forced: true }),
      sessionId,
    );

    expect(state.draining).toEqual({
      forced: true,
      copy: "The daemon is draining and has reached its grace deadline.",
    });
    expect(composerSendDisabled({ message: "hello", busy: false, draining: state.draining })).toBe(
      true,
    );
    expect(composerSendDisabled({ message: "hello", busy: false, draining: null })).toBe(false);
  });

  it("sets and clears waiting-for-lock indicators", () => {
    const waiting = daemonStateReducer(
      emptyNativeDaemonState,
      event("waiting_for_lock", {
        session_id: sessionId,
        waiting: true,
        path: "src/app.ts",
        holder_agent: "Build",
      }),
      sessionId,
    );

    expect(waiting.waitingForLock).toEqual({ path: "src/app.ts", holderAgent: "Build" });

    const cleared = daemonStateReducer(
      waiting,
      event("waiting_for_lock", {
        session_id: sessionId,
        waiting: false,
        path: "src/app.ts",
        holder_agent: "Build",
      }),
      sessionId,
    );
    expect(cleared.waitingForLock).toBeNull();
  });

  it("sets paused work indicators for the selected session", () => {
    const item = { session_id: sessionId, reason: "daemon_shutdown" };
    const state = daemonStateReducer(
      emptyNativeDaemonState,
      event("paused_work_available", {
        session_id: sessionId,
        items: [item],
      }),
      sessionId,
    );

    expect(state.pausedWork).toEqual({ sessionId, items: [item] });

    const cleared = daemonStateReducer(
      state,
      event("paused_work_available", {
        session_id: sessionId,
        items: [],
      }),
      sessionId,
    );
    expect(cleared.pausedWork).toBeNull();
  });

  it("dispatches paused-work resume and cancel without optimistic clearing", async () => {
    const state = {
      ...emptyNativeDaemonState,
      pausedWork: { sessionId, items: [{ reason: "daemon_shutdown" }] },
    };
    const client = {
      resumePausedWork: vi.fn().mockResolvedValue({}),
      cancelPausedWork: vi.fn().mockResolvedValue({}),
    };

    await resumePausedWorkAction(client, state);
    await cancelPausedWorkAction(client, state);

    expect(client.resumePausedWork).toHaveBeenCalledExactlyOnceWith(sessionId);
    expect(client.cancelPausedWork).toHaveBeenCalledExactlyOnceWith(sessionId);
    expect(state.pausedWork).toEqual({ sessionId, items: [{ reason: "daemon_shutdown" }] });
  });
});
