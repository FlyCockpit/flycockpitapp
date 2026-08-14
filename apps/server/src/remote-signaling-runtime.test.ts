/**
 * Composition-level tests for `installRemoteSignalingGateway`: the single
 * `upgrade` dispatcher (routes `/api/remote/ws` to the gateway, destroys every
 * other upgrade socket unless the `additionalUpgrade` seam claims it) and the
 * `close()` teardown (drains sockets with 1001, closes the injected wake + store).
 *
 * Real `node:http` loopback server on port 0, awaited socket events, no sleeps.
 */
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import { MemoryRemoteSignalingAttemptStore } from "@flycockpit/api/lib/remote-signaling-store";
import { afterEach, describe, expect, it, vi } from "vitest";
import WebSocket from "ws";
import {
  REMOTE_GATEWAY_SUBPROTOCOL,
  REMOTE_GATEWAY_WS_PATH,
} from "./remote-signaling-gateway/close-codes";
import {
  connectWs,
  rejectingDaemonVerifier,
  waitForClose,
} from "./remote-signaling-gateway/test-fixtures";
import { InMemoryRemoteSignalingWakeSubscription } from "./remote-signaling-gateway/wake-subscription";
import {
  type InstalledRemoteSignalingGateway,
  type InstallRemoteSignalingGatewayDeps,
  installRemoteSignalingGateway,
} from "./remote-signaling-runtime";

const CONFIGURED_ORIGIN = "https://app.example.test";

interface TestServer {
  server: Server;
  installed: InstalledRemoteSignalingGateway;
  store: MemoryRemoteSignalingAttemptStore;
  wake: InMemoryRemoteSignalingWakeSubscription;
  wsUrl: (path: string) => string;
  close: () => Promise<void>;
}

const cleanups: Array<() => Promise<void>> = [];

async function setup(
  overrides: Partial<InstallRemoteSignalingGatewayDeps> = {},
): Promise<TestServer> {
  const store =
    (overrides.store as MemoryRemoteSignalingAttemptStore | undefined) ??
    new MemoryRemoteSignalingAttemptStore();
  const wake =
    (overrides.wake as InMemoryRemoteSignalingWakeSubscription | undefined) ??
    new InMemoryRemoteSignalingWakeSubscription();
  const server = createServer();
  const installed = installRemoteSignalingGateway(server, {
    configuredOrigin: CONFIGURED_ORIGIN,
    daemonCertificateVerifier: rejectingDaemonVerifier,
    additionalUpgrade: overrides.additionalUpgrade,
    store,
    wake,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;

  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await installed.close().catch(() => {});
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      setTimeout(() => resolve(), 2_000).unref();
    });
  };
  cleanups.push(close);

  return {
    server,
    installed,
    store,
    wake,
    wsUrl: (path: string) => `ws://127.0.0.1:${port}${path}`,
    close,
  };
}

/**
 * Connect a signal WebSocket and resolve with the FIRST terminal outcome. A
 * destroyed upgrade socket surfaces as "error" (handshake reset) or "close"; a
 * completed handshake surfaces as "open"; the timer only fires if the socket
 * silently hangs (which the assertions treat as a failure, not a pass).
 */
async function connectOutcome(url: string): Promise<"open" | "error" | "close" | "timeout"> {
  type Outcome = "open" | "error" | "close" | "timeout";
  const ws = new WebSocket(url, REMOTE_GATEWAY_SUBPROTOCOL.signal, {
    headers: { origin: CONFIGURED_ORIGIN },
    perMessageDeflate: false,
  });
  try {
    return await Promise.race<Outcome>([
      new Promise<Outcome>((resolve) => ws.once("open", () => resolve("open"))),
      new Promise<Outcome>((resolve) => ws.once("error", () => resolve("error"))),
      new Promise<Outcome>((resolve) => ws.once("close", () => resolve("close"))),
      new Promise<Outcome>((resolve) => {
        setTimeout(() => resolve("timeout"), 2_000).unref();
      }),
    ]);
  } finally {
    ws.removeAllListeners();
    try {
      ws.terminate();
    } catch {
      // ignore
    }
  }
}

afterEach(async () => {
  for (const close of cleanups.splice(0)) await close().catch(() => {});
});

describe("remote_signaling_runtime", () => {
  it("routes an upgrade on the gateway path to the gateway and opens the socket", async () => {
    const env = await setup();
    const ws = await connectWs(env.wsUrl(REMOTE_GATEWAY_WS_PATH), {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: CONFIGURED_ORIGIN },
    });
    expect(ws.readyState).toBe(WebSocket.OPEN);
    ws.close();
  });

  it("destroys upgrade sockets on non-gateway paths (never opens)", async () => {
    const env = await setup();
    const outcome = await connectOutcome(env.wsUrl("/api/other"));
    // Must be a terminal socket error/close, not "open" and not a silent hang.
    expect(outcome).not.toBe("open");
    expect(["error", "close"]).toContain(outcome);
  });

  it("close() drains open sockets with WebSocket close code 1001", async () => {
    const env = await setup();
    const ws = await connectWs(env.wsUrl(REMOTE_GATEWAY_WS_PATH), {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: CONFIGURED_ORIGIN },
    });
    expect(ws.readyState).toBe(WebSocket.OPEN);
    const closed = waitForClose(ws);
    await env.installed.close();
    const { code } = await closed;
    expect(code).toBe(1001);
  });

  it("close() closes the injected store and wake connections", async () => {
    const store = new MemoryRemoteSignalingAttemptStore();
    const wake = new InMemoryRemoteSignalingWakeSubscription();
    const storeClose = vi.spyOn(store, "close");
    const wakeClose = vi.spyOn(wake, "close");
    const env = await setup({ store, wake });
    await env.installed.close();
    expect(storeClose).toHaveBeenCalledTimes(1);
    expect(wakeClose).toHaveBeenCalledTimes(1);
  });

  it("still destroys non-gateway paths the additionalUpgrade seam declines", async () => {
    const additionalUpgrade = vi.fn((request: IncomingMessage, socket: Duplex): boolean => {
      const url = new URL(request.url ?? "/", "http://gateway.local");
      if (url.pathname === "/api/handled") {
        socket.destroy();
        return true;
      }
      return false;
    });
    const env = await setup({ additionalUpgrade });
    const outcome = await connectOutcome(env.wsUrl("/api/unhandled"));
    // The seam is consulted, declines the path, and the dispatcher still destroys it.
    expect(additionalUpgrade).toHaveBeenCalled();
    expect(outcome).not.toBe("open");
    expect(["error", "close"]).toContain(outcome);
  });
});
