import { type ChildProcessByStdio, spawn } from "node:child_process";
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Readable } from "node:stream";
import type { RelayControlMessage } from "@flycockpit/relay-protocol";
import { createRelayKeySet, signRelayToken } from "@flycockpit/relay-protocol/tokens";
import { createRelayServer, type RelayServerConfig } from "./server";

export type RelayUnderTest = {
  mode: "in-process" | "subprocess";
  relayId: string;
  wsUrl: string;
  httpUrl: string;
  signToken(input: Parameters<typeof signRelayToken>[0], audience?: string): Promise<string>;
  publishControl(message: RelayControlMessage): Promise<void>;
  logs(): string;
  stop(): Promise<void>;
};

type RelayChild = ChildProcessByStdio<null, Readable, Readable>;

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

  const relayBin = process.env.RELAY_UNDER_TEST_BIN;
  try {
    if (relayBin) {
      return await startSubprocessRelay(relayBin, config, jwksUrl, jwksServer, logs);
    }
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
  return relayHandle({
    mode: "in-process",
    config,
    httpUrl,
    logs,
    stop: async () => {
      await handle.close();
      await closeServer(jwksServer);
    },
  });
}

async function startSubprocessRelay(
  relayBin: string,
  config: Required<Omit<RelayTestConfig, "controlIngestUrl" | "redisUrl">> &
    Pick<RelayTestConfig, "controlIngestUrl" | "redisUrl">,
  jwksUrl: string,
  jwksServer: Server,
  logs: string[],
): Promise<RelayUnderTest> {
  const port = await pickFreePort();
  const env = {
    ...process.env,
    NODE_ENV: "test",
    RELAY_ID: config.relayId,
    RELAY_PORT: String(port),
    RELAY_TOKEN_ISSUER: config.issuer,
    RELAY_JWKS_URL: jwksUrl,
    RELAY_HEARTBEAT_MS: String(config.heartbeatMs),
    RELAY_LEASE_TTL_MS: String(config.leaseTtlMs),
    RELAY_MAX_FRAME_BYTES: String(config.maxFrameBytes),
    RELAY_MAX_CHANNELS_PER_CLIENT: String(config.maxChannelsPerClient),
    RELAY_MAX_CONNECTIONS_PER_INSTANCE: String(config.maxConnectionsPerInstance),
    RELAY_CLIENT_RATE_LIMIT_PER_SECOND: String(config.clientRateLimitPerSecond),
    RELAY_CONTROL_SECRET: config.controlSecret,
    ...(config.controlIngestUrl ? { RELAY_CONTROL_INGEST_URL: config.controlIngestUrl } : {}),
    ...(config.redisUrl ? { REDIS_URL: config.redisUrl } : {}),
  };
  const child = spawn(relayBin, [], { env, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (chunk) => logs.push(chunk.toString()));
  child.stderr.on("data", (chunk) => logs.push(chunk.toString()));
  const exit = once(child, "exit").then(([code, signal]) => ({ code, signal }));
  const httpUrl = `http://127.0.0.1:${port}`;

  for (let attempt = 0; attempt < 100; attempt += 1) {
    const exited = await Promise.race([exit, sleep(50).then(() => null)]);
    if (exited) {
      throw new Error(
        `relay subprocess exited before /healthz was ready: code=${exited.code} signal=${exited.signal}\n` +
          capturedLogs(logs),
      );
    }
    try {
      const response = await fetch(`${httpUrl}/healthz`);
      const body = (await response.json()) as { ok?: boolean };
      if (response.ok && body.ok === true) {
        return relayHandle({
          mode: "subprocess",
          config,
          httpUrl,
          logs,
          stop: async () => {
            await stopSubprocess(child);
            await closeServer(jwksServer);
          },
        });
      }
    } catch {
      // Keep polling until the relay binds or exits.
    }
  }

  await stopSubprocess(child);
  await closeServer(jwksServer);
  throw new Error(`relay subprocess did not become healthy within 10s\n${capturedLogs(logs)}`);
}

function relayHandle(input: {
  mode: RelayUnderTest["mode"];
  config: Required<Omit<RelayTestConfig, "controlIngestUrl" | "redisUrl">> &
    Pick<RelayTestConfig, "controlIngestUrl" | "redisUrl">;
  httpUrl: string;
  logs: string[];
  stop(): Promise<void>;
}): RelayUnderTest {
  return {
    mode: input.mode,
    relayId: input.config.relayId,
    wsUrl: input.httpUrl.replace("http://", "ws://"),
    httpUrl: input.httpUrl,
    async signToken(tokenInput, audience = input.config.relayId) {
      return (
        await signRelayToken(tokenInput, {
          secret: input.config.secret,
          issuer: input.config.issuer,
          audience,
        })
      ).token;
    },
    async publishControl(message) {
      const response = await fetch(`${input.httpUrl}/control`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${input.config.controlSecret}`,
        },
        body: JSON.stringify(message),
      });
      if (!response.ok) {
        throw new Error(`control request failed with ${response.status}: ${await response.text()}`);
      }
    },
    logs: () => input.logs.join(""),
    stop: input.stop,
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

async function pickFreePort() {
  const server = createServer();
  await listen(server, 0);
  const port = portOf(server);
  await closeServer(server);
  return port;
}

async function stopSubprocess(child: RelayChild) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  const exited = await Promise.race([
    once(child, "exit").then(() => true),
    sleep(500).then(() => false),
  ]);
  if (!exited) {
    child.kill("SIGKILL");
    await once(child, "exit");
  }
}

function capturedLogs(logs: string[]) {
  return `captured stdout/stderr:\n${logs.join("")}`;
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
