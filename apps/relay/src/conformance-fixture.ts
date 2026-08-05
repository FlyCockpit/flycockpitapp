import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { RelayControlMessage } from "@flycockpit/relay-protocol";
import { createRelayKeySet, signRelayToken } from "@flycockpit/relay-protocol/tokens";
import { createRelayServer, type RelayServerConfig } from "./server";

export type RelayUnderTest = {
  mode: "in-process";
  relayId: string;
  wsUrl: string;
  httpUrl: string;
  signToken(input: Parameters<typeof signRelayToken>[0], audience?: string): Promise<string>;
  publishControl(message: RelayControlMessage): Promise<void>;
  logs(): string;
  stop(): Promise<void>;
};

type RelayTestConfig = {
  relayId?: string;
  issuer?: string;
  secret?: string;
  heartbeatMs?: number;
  leaseTtlMs?: number;
  maxFrameBytes?: number;
  maxChannelsPerClient?: number;
  maxConnectionsPerInstance?: number;
  clientRateLimitPerSecond?: number;
  controlIngestUrl?: string;
  controlSecret?: string;
  redisUrl?: string;
};

const defaultConfig = {
  relayId: "relay-test",
  issuer: "https://app.example.test",
  secret: "1234567890abcdef1234567890abcdef",
  heartbeatMs: 1_000,
  leaseTtlMs: 30_000,
  maxFrameBytes: 1024 * 1024,
  maxChannelsPerClient: 2,
  maxConnectionsPerInstance: 10,
  clientRateLimitPerSecond: 100,
  controlSecret: "control-secret-control-secret-1234",
} satisfies Required<Omit<RelayTestConfig, "controlIngestUrl" | "redisUrl">>;

/**
 * Starts the temporary TypeScript relay bridge in-process via `createRelayServer`.
 * External binary selection is intentionally unsupported: the former Rust
 * WebSocket relay server was retired, and the long-term owner is TypeScript
 * `apps/server`.
 */
export async function startRelayUnderTest(
  overrides: RelayTestConfig = {},
): Promise<RelayUnderTest> {
  const config = { ...defaultConfig, ...overrides };
  const logs: string[] = [];
  const keySet = createRelayKeySet(config.secret);
  const jwksServer = createServer((request, response) => {
    if (request.method === "GET" && request.url === "/api/relay/jwks.json") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(keySet.jwks));
      return;
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not_found" }));
  });
  await listen(jwksServer, 0);
  const jwksUrl = `http://127.0.0.1:${portOf(jwksServer)}/api/relay/jwks.json`;

  try {
    return await startInProcessRelay(config, jwksUrl, jwksServer, logs);
  } catch (err) {
    await closeServer(jwksServer);
    throw err;
  }
}

async function startInProcessRelay(
  config: Required<Omit<RelayTestConfig, "controlIngestUrl" | "redisUrl">> &
    Pick<RelayTestConfig, "controlIngestUrl" | "redisUrl">,
  jwksUrl: string,
  jwksServer: Server,
  logs: string[],
): Promise<RelayUnderTest> {
  const handle = createRelayServer({
    relayId: config.relayId,
    jwksUrl,
    tokenIssuer: config.issuer,
    heartbeatMs: config.heartbeatMs,
    leaseTtlMs: config.leaseTtlMs,
    maxFrameBytes: config.maxFrameBytes,
    maxChannelsPerClient: config.maxChannelsPerClient,
    maxConnectionsPerInstance: config.maxConnectionsPerInstance,
    clientRateLimitPerSecond: config.clientRateLimitPerSecond,
    controlIngestUrl: config.controlIngestUrl,
    controlSecret: config.controlSecret,
    redisUrl: config.redisUrl,
    logger: captureLogger(logs),
  } satisfies RelayServerConfig);
  await listen(handle.server, 0);
  const httpUrl = `http://127.0.0.1:${portOf(handle.server)}`;
  return {
    mode: "in-process",
    relayId: config.relayId,
    wsUrl: httpUrl.replace("http://", "ws://"),
    httpUrl,
    async signToken(tokenInput, audience = config.relayId) {
      return (
        await signRelayToken(tokenInput, {
          secret: config.secret,
          issuer: config.issuer,
          audience,
        })
      ).token;
    },
    async publishControl(message) {
      const response = await fetch(`${httpUrl}/control`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${config.controlSecret}`,
        },
        body: JSON.stringify(message),
      });
      if (!response.ok) {
        throw new Error(`control request failed with ${response.status}: ${await response.text()}`);
      }
    },
    logs: () => logs.join(""),
    stop: async () => {
      await handle.close();
      await closeServer(jwksServer);
    },
  };
}

function captureLogger(logs: string[]): Pick<typeof console, "error" | "info" | "warn"> {
  return {
    info: (...args) => logs.push(`${args.join(" ")}\n`),
    warn: (...args) => logs.push(`${args.join(" ")}\n`),
    error: (...args) => logs.push(`${args.join(" ")}\n`),
  };
}

async function listen(server: Server, port: number) {
  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
}

function portOf(server: Server) {
  return (server.address() as AddressInfo).port;
}

async function closeServer(server: Server) {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
}
