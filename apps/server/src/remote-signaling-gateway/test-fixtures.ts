/**
 * Shared test harness for the signaling gateway (NOT a `*.test.ts`, so importing
 * it registers no tests). Provides a loopback HTTP server on port 0, a real
 * `MemoryRemoteSignalingAttemptStore` wired to an in-process wake bus, an
 * injectable deterministic clock, and `ws` connect/close helpers.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { MemoryRemoteSignalingAttemptStore } from "@flycockpit/api/lib/remote-signaling-store";
import WebSocket from "ws";
import { REMOTE_GATEWAY_WS_PATH } from "./close-codes";
import {
  DaemonCertificateVerificationError,
  type DaemonCertificateVerifier,
} from "./daemon-certificate-verifier";
import {
  RemoteSignalingGateway,
  type RemoteSignalingGatewayConfig,
  type SafeLogger,
} from "./gateway";
import type { MonotonicClock } from "./rate-limiters";
import { UnauthUpgradeRateLimiter } from "./rate-limiters";
import { InMemoryRemoteSignalingWakeSubscription } from "./wake-subscription";

export class FakeClock implements MonotonicClock {
  private ms = 0;
  nowMs(): number {
    return this.ms;
  }
  advance(ms: number) {
    this.ms += ms;
  }
}

export class NoopLogger implements SafeLogger {
  info() {}
  warn() {}
  error() {}
}

/** A verifier that authenticates nothing — the FCDA codec rejects malformed frames first. */
export const rejectingDaemonVerifier: DaemonCertificateVerifier = {
  async verify() {
    throw new DaemonCertificateVerificationError("test: no daemon verifier configured");
  },
};

export interface GatewayTestEnv {
  server: Server;
  gateway: RemoteSignalingGateway;
  store: MemoryRemoteSignalingAttemptStore;
  wake: InMemoryRemoteSignalingWakeSubscription;
  url: string;
  close: () => Promise<void>;
}

export async function startGatewayServer(
  overrides?: Partial<RemoteSignalingGatewayConfig>,
): Promise<GatewayTestEnv> {
  const clock = new FakeClock();
  const wake = new InMemoryRemoteSignalingWakeSubscription();
  const store = new MemoryRemoteSignalingAttemptStore(
    () => Date.now(),
    (out) => out.set(crypto.getRandomValues(new Uint8Array(out.length))),
    (route) => wake.publishAttempt(route),
  );
  const server = createServer();
  const gateway = new RemoteSignalingGateway({
    configuredOrigin: "https://app.example.test",
    store,
    clock,
    unauthUpgradeLimiter: new UnauthUpgradeRateLimiter(clock),
    daemonCertificateVerifier: rejectingDaemonVerifier,
    wake,
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
    store,
    wake,
    url,
    close: async () => {
      await gateway.close();
      server.removeAllListeners("upgrade");
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        setTimeout(() => resolve(), 2_000).unref();
      });
    },
  };
}

export function connectWs(
  url: string,
  options?: { subprotocol?: string | string[]; headers?: Record<string, string> },
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

export function waitForClose(ws: WebSocket): Promise<{ code: number; reason: string }> {
  return new Promise((resolve) => {
    ws.once("close", (code, reason) => resolve({ code, reason: reason.toString() }));
  });
}

export function nextBinaryMessage(ws: WebSocket): Promise<Buffer> {
  return new Promise((resolve) => {
    ws.once("message", (data) =>
      resolve(Buffer.isBuffer(data) ? data : Buffer.concat(data as readonly Buffer[])),
    );
  });
}
