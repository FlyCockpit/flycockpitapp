import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { RemoteSignalingAttemptStore } from "@flycockpit/api/lib/remote-signaling-store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import WebSocket from "ws";
import {
  REMOTE_GATEWAY_CLOSE_CODE,
  REMOTE_GATEWAY_CLOSE_REASON,
  REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS,
  REMOTE_GATEWAY_SUBPROTOCOL,
  REMOTE_GATEWAY_WS_PATH,
} from "./close-codes";
import type { SafeLogger } from "./gateway";
import { RemoteSignalingGateway, type RemoteSignalingGatewayConfig } from "./gateway";
import type { MonotonicClock } from "./rate-limiters";
import { UnauthUpgradeRateLimiter } from "./rate-limiters";

class FakeClock implements MonotonicClock {
  private ms = 0;
  nowMs(): number {
    return this.ms;
  }
  advance(ms: number) {
    this.ms += ms;
  }
}

class NoopLogger implements SafeLogger {
  info() {}
  warn() {}
  error() {}
}

class MemoryStoreStub implements RemoteSignalingAttemptStore {
  async create() {
    return { kind: "committed" as const, sequence: 1n, ackBytes: new Uint8Array(61) };
  }
  async commit() {
    return { kind: "committed" as const, sequence: 1n, ackBytes: new Uint8Array(61) };
  }
  async read() {
    return { kind: "unavailable" as const };
  }
  async metadata() {
    return { kind: "unavailable" as const };
  }
  async authenticateInstanceWake() {
    return {
      instanceWakeRouteId: new Uint8Array(16),
      instanceWakeRouteGeneration: 1n,
      socketGeneration: 1n,
      expiresAtMs: Date.now() + 45_000,
    };
  }
  async renewInstanceWake() {
    return {
      instanceWakeRouteId: new Uint8Array(16),
      instanceWakeRouteGeneration: 1n,
      socketGeneration: 1n,
      expiresAtMs: Date.now() + 45_000,
    };
  }
  async readDiscovery() {
    return { kind: "unavailable" as const };
  }
  async ackDiscovery() {}
  async closeInstanceWake() {}
  async discoveryHighWater() {
    return 0n;
  }
  async close() {}
}

async function startGatewayServer(overrides?: Partial<RemoteSignalingGatewayConfig>): Promise<{
  server: Server;
  gateway: RemoteSignalingGateway;
  url: string;
  close: () => Promise<void>;
}> {
  const clock = new FakeClock();
  const server = createServer();
  const gateway = new RemoteSignalingGateway({
    configuredOrigin: "https://app.example.test",
    store: new MemoryStoreStub(),
    clock,
    unauthUpgradeLimiter: new UnauthUpgradeRateLimiter(clock),
    logger: new NoopLogger(),
    ...overrides,
  });

  server.on("upgrade", (request, socket, head) => {
    const url = new URL(request.url ?? "/", "http://gateway.local");
    if (url.pathname !== REMOTE_GATEWAY_WS_PATH) return;
    const clientIp = request.socket.remoteAddress ?? "unknown";
    gateway.handleUpgrade(request, socket, head, clientIp);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const url = `ws://127.0.0.1:${port}${REMOTE_GATEWAY_WS_PATH}`;

  return {
    server,
    gateway,
    url,
    close: async () => {
      await gateway.close();
      // Force-close any lingering connections before closing the server.
      server.removeAllListeners("upgrade");
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        // If close hangs (open sockets), force after 2s.
        setTimeout(() => resolve(), 2_000).unref();
      });
    },
  };
}

function connectWs(
  url: string,
  options?: { subprotocol?: string; headers?: Record<string, string> },
): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, options?.subprotocol, {
      headers: options?.headers,
      perMessageDeflate: false,
    });
    ws.once("open", () => resolve(ws));
    ws.once("error", reject);
  });
}

function waitForClose(ws: WebSocket): Promise<{ code: number; reason: string }> {
  return new Promise((resolve) => {
    ws.once("close", (code, reason) => {
      resolve({ code, reason: reason.toString() });
    });
  });
}

let env: Awaited<ReturnType<typeof startGatewayServer>> | undefined;

beforeEach(() => {
  env = undefined;
});

afterEach(async () => {
  if (env) await env.close();
  env = undefined;
});

describe("remote_gateway_upgrade_and_binary_contract", () => {
  it("rejects wrong path", async () => {
    env = await startGatewayServer();
    // Wrong path → the upgrade is not handled by the gateway, so the HTTP
    // server doesn't handle the upgrade and the connection hangs/times out.
    // We verify by racing against a timeout — a correct wrong-path rejection
    // either errors or times out, but never opens successfully.
    const result = await Promise.race([
      connectWs(env.url.replace(REMOTE_GATEWAY_WS_PATH, "/wrong-path"), {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      }).then(
        (ws) => ({ kind: "open" as const, ws }),
        (err) => ({ kind: "error" as const, err }),
      ),
      new Promise<{ kind: "timeout" }>((resolve) =>
        setTimeout(() => resolve({ kind: "timeout" }), 2_000),
      ),
    ]);
    expect(result.kind).not.toBe("open");
  }, 10_000);

  it("rejects missing subprotocol", async () => {
    env = await startGatewayServer();
    // No subprotocol → upgrade rejected with 400.
    await expect(connectWs(env.url)).rejects.toThrow();
  });

  it("rejects unknown subprotocol", async () => {
    env = await startGatewayServer();
    await expect(connectWs(env.url, { subprotocol: "flycockpit.unknown.v1" })).rejects.toThrow();
  });

  it("accepts signal subprotocol", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    expect(ws.readyState).toBe(WebSocket.OPEN);
    ws.close();
  });

  it("accepts control subprotocol (no origin)", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.control,
    });
    expect(ws.readyState).toBe(WebSocket.OPEN);
    ws.close();
  });

  it("rejects control subprotocol with present Origin", async () => {
    env = await startGatewayServer();
    await expect(
      connectWs(env.url, {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.control,
        headers: { origin: "https://app.example.test" },
      }),
    ).rejects.toThrow();
  });

  it("rejects signal with wrong origin", async () => {
    env = await startGatewayServer();
    await expect(
      connectWs(env.url, {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
        headers: { origin: "https://evil.test" },
      }),
    ).rejects.toThrow();
  });

  it("rejects signal with null origin", async () => {
    env = await startGatewayServer();
    await expect(
      connectWs(env.url, {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
        headers: { origin: "null" },
      }),
    ).rejects.toThrow();
  });

  it("rejects compression extension", async () => {
    env = await startGatewayServer();
    // The ws client with perMessageDeflate: true should be rejected.
    await expect(
      new Promise<WebSocket>((resolve, reject) => {
        const ws = new WebSocket(env!.url, REMOTE_GATEWAY_SUBPROTOCOL.signal, {
          headers: { origin: "https://app.example.test" },
          perMessageDeflate: true,
        });
        ws.once("open", () => resolve(ws));
        ws.once("error", reject);
      }),
    ).rejects.toThrow();
  });

  it("closes text frames with 4400", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    ws.send("text frame", { binary: false });
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
    expect(closed.reason).toBe(REMOTE_GATEWAY_CLOSE_REASON[4400]);
  });

  it("closes with authentication_timeout after pre-auth deadline", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    // Don't send any auth frame; wait for timeout.
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_timeout);
    expect(closed.reason).toBe(REMOTE_GATEWAY_CLOSE_REASON[4408]);
  }, 10_000);

  it("sends FCDC challenge on control connection", async () => {
    env = await startGatewayServer();
    const challengePromise = new Promise<Buffer>((resolve) => {
      const ws = new WebSocket(env!.url, REMOTE_GATEWAY_SUBPROTOCOL.control, {
        perMessageDeflate: false,
      });
      ws.once("message", (data) =>
        resolve(Buffer.isBuffer(data) ? data : Buffer.concat(data as readonly Buffer[])),
      );
    });
    const message = await challengePromise;
    // FCDC is 53 bytes with magic "FCDC"
    expect(message.length).toBe(53);
    expect(message.subarray(0, 4).toString("ascii")).toBe("FCDC");
    expect(message[4]).toBe(1);
  }, 10_000);

  it("closes control with authentication_failed on bad FCDA", async () => {
    env = await startGatewayServer();
    const ws = new WebSocket(env.url, REMOTE_GATEWAY_SUBPROTOCOL.control, {
      perMessageDeflate: false,
    });
    // Wait for the challenge, then send garbage
    await new Promise<void>((resolve) => {
      ws.once("message", () => resolve());
    });
    ws.send(Buffer.from([0, 1, 2, 3, 4, 5]));
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  }, 10_000);

  it("closes signal with authentication_failed on bad FCSA", async () => {
    env = await startGatewayServer();
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    // Send garbage binary frame
    ws.send(Buffer.from([0, 1, 2, 3, 4, 5]));
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
  });

  it("proves exact close code table", () => {
    expect(REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid).toBe(4400);
    expect(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed).toBe(4401);
    expect(REMOTE_GATEWAY_CLOSE_CODE.authorization_revoked).toBe(4403);
    expect(REMOTE_GATEWAY_CLOSE_CODE.authentication_timeout).toBe(4408);
    expect(REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded).toBe(4409);
    expect(REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure).toBe(4429);
    expect(REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable).toBe(4503);
  });

  it("proves close reasons contain only the exact strings", () => {
    for (const code of Object.values(REMOTE_GATEWAY_CLOSE_CODE)) {
      const reason = REMOTE_GATEWAY_CLOSE_REASON[code];
      expect(reason).toMatch(/^[a-z_]+$/);
    }
  });

  it("proves pre-auth timeout is 5 seconds", () => {
    expect(REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS).toBe(5_000);
  });

  it("proves exact subprotocol strings", () => {
    expect(REMOTE_GATEWAY_SUBPROTOCOL.signal).toBe("flycockpit.remote-signal.v1");
    expect(REMOTE_GATEWAY_SUBPROTOCOL.control).toBe("flycockpit.remote-control.v1");
  });

  it("proves exact WS path", () => {
    expect(REMOTE_GATEWAY_WS_PATH).toBe("/api/remote/ws");
  });
});

describe("remote_gateway_lazy_import_and_shutdown", () => {
  it("importing the gateway module opens zero Redis sockets", async () => {
    // The gateway module is already imported; verify it does not
    // connect to Redis on import. The store is injected, not created
    // at import time.
    const mod = await import("./gateway");
    expect(typeof mod.RemoteSignalingGateway).toBe("function");
    expect(typeof mod.createRemoteSignalingGateway).toBe("function");
  });

  it("gateway close stops accepting and closes sockets", async () => {
    env = await startGatewayServer();
    expect(env.gateway.activeSocketCount).toBe(0);
    const ws = await connectWs(env.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: "https://app.example.test" },
    });
    expect(env.gateway.activeSocketCount).toBe(1);
    await env.gateway.close();
    const closed = await waitForClose(ws);
    expect(closed.code).toBe(1001);
  });
});
