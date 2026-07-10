import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { join } from "node:path";
import type {
  ClientRelayFrame,
  DaemonClientRelayFrame,
  RelayControlMessage,
} from "@flycockpit/relay-protocol";
import { afterEach, expect, it } from "vitest";
import WebSocket from "ws";
import { type RelayUnderTest, startRelayUnderTest } from "./conformance-fixture";

let relay: RelayUnderTest | undefined;
let ingestServer: Server | undefined;

const backpressureIt = process.env.RELAY_UNDER_TEST_BIN ? it : it.fails;

// Backpressure is expected to fail against the TypeScript relay until rust-relay-implementation
// lands bounded buffering behavior. The Rust implementation must make this same test pass.
backpressureIt(
  "closes or throttles a slow peer instead of buffering daemon output indefinitely",
  async () => {
    relay = await startRelayUnderTest();
    const daemon = await openDaemon(relay);
    const client = await openClient(relay, {
      tokenType: "client",
      instanceId: "instance-1",
      userId: "user-1",
    });
    pauseSocket(client);
    const clientFrame = loadFixture<ClientRelayFrame>("client-relay-frame.json");
    const daemonFrame = loadFixture<DaemonClientRelayFrame>("daemon-client-relay-frame.json");
    client.send(JSON.stringify(clientFrame));
    await nextMessage(daemon);

    for (let index = 0; index < 10_000; index += 1) {
      daemon.send(JSON.stringify({ ...daemonFrame, channelId: clientFrame.channelId }));
    }

    await sleep(100);
    expect(client.readyState).not.toBe(WebSocket.OPEN);
  },
);

it("rejects garbage tokens during websocket upgrade", async () => {
  relay = await startRelayUnderTest();
  const ws = connect(relay, "/ws/daemon", "garbage");

  await expect(rejected(ws)).resolves.toMatchObject({ message: expect.stringContaining("401") });
});

it("refuses tokens minted for a different relay during websocket upgrade", async () => {
  relay = await startRelayUnderTest();
  const daemon = connect(
    relay,
    "/ws/daemon",
    await relay.signToken(
      { tokenType: "connector", instanceId: "instance-1", userId: "owner-1" },
      "relay-other",
    ),
  );

  await expect(rejected(daemon)).resolves.toMatchObject({
    message: expect.stringContaining("401"),
  });
});

it("closes post-upgrade connections with 4401 when the token type is wrong for the route", async () => {
  relay = await startRelayUnderTest();
  const client = connect(
    relay,
    "/ws/client",
    await relay.signToken({ tokenType: "user", userId: "user-1" }),
  );
  const close = closed(client);

  await opened(client);
  await expect(close).resolves.toMatchObject({ code: 4401 });
});

it("accepts a client connection but closes it with instance_offline when no daemon is present", async () => {
  relay = await startRelayUnderTest();
  const client = connect(
    relay,
    "/ws/client",
    await relay.signToken({ tokenType: "client", instanceId: "instance-1", userId: "user-1" }),
  );
  const message = nextMessage(client);
  const close = closed(client);
  await opened(client);

  await expect(message).resolves.toMatchObject({ type: "system", code: "instance_offline" });
  await expect(close).resolves.toMatchObject({ code: 4404 });
});

it("closes a replaced daemon with 4409", async () => {
  relay = await startRelayUnderTest();
  const first = await openDaemon(relay);
  const firstMessage = nextMessage(first);
  const firstClose = closed(first);
  await openDaemon(relay, "instance-1", "owner-2");

  await expect(firstMessage).resolves.toMatchObject({ type: "system", code: "daemon_replaced" });
  await expect(firstClose).resolves.toMatchObject({ code: 4409 });
});

it("pairs a daemon and client, stamps principals, and routes daemon replies by channel", async () => {
  relay = await startRelayUnderTest();
  const daemon = await openDaemon(relay);
  const client = await openClient(relay, {
    tokenType: "client",
    instanceId: "instance-1",
    userId: "user-1",
    grants: [{ scope: "terminal", projectRoot: null }],
  });
  const clientFrame = loadFixture<ClientRelayFrame>("client-relay-frame.json");
  const daemonFrame = loadFixture<DaemonClientRelayFrame>("daemon-client-relay-frame.json");

  client.send(JSON.stringify(clientFrame));
  await expect(nextMessage(daemon)).resolves.toMatchObject({
    v: 1,
    channelId: clientFrame.channelId,
    from: "client",
    principal: { userId: "user-1", grants: [{ scope: "terminal", projectRoot: null }] },
    payload: clientFrame.payload,
  });

  daemon.send(JSON.stringify({ ...daemonFrame, channelId: clientFrame.channelId }));
  await expect(nextMessage(client)).resolves.toMatchObject({
    v: 1,
    channelId: clientFrame.channelId,
    payload: daemonFrame.payload,
  });
});

it("passes opaque payloads byte-identically after canonical key normalization", async () => {
  relay = await startRelayUnderTest();
  const daemon = await openDaemon(relay);
  const client = await openClient(relay, {
    tokenType: "client",
    instanceId: "instance-1",
    userId: "user-1",
  });
  const source = loadFixture<{ payload: unknown }>("daemon-control-relay-frame.json").payload;
  const frame = { ...loadFixture<ClientRelayFrame>("client-relay-frame.json"), payload: source };

  client.send(JSON.stringify(frame));
  const received = (await nextMessage(daemon)) as { payload: unknown };

  expect(stableJson(received.payload)).toBe(stableJson(source));
});

it("rejects clients that try to supply their own principal", async () => {
  relay = await startRelayUnderTest();
  const daemon = await openDaemon(relay);
  const client = await openClient(relay, {
    tokenType: "client",
    instanceId: "instance-1",
    userId: "user-1",
  });
  const daemonMessage = noMessage(daemon, 75);
  const close = closed(client);

  client.send(
    JSON.stringify({
      ...loadFixture<ClientRelayFrame>("client-relay-frame.json"),
      principal: { userId: "spoofed", grants: [] },
    }),
  );

  await expect(close).resolves.toMatchObject({ code: 4400 });
  await expect(daemonMessage).resolves.toBeUndefined();
});

it("closes oversized frames with 1009", async () => {
  relay = await startRelayUnderTest({ maxFrameBytes: 16 });
  await openDaemon(relay);
  const client = await openClient(relay, {
    tokenType: "client",
    instanceId: "instance-1",
    userId: "user-1",
  });
  const close = closed(client);

  client.send(JSON.stringify(loadFixture<ClientRelayFrame>("client-relay-frame.json")));

  await expect(close).resolves.toMatchObject({ code: 1009 });
});

it("rate limits clients with 4429", async () => {
  relay = await startRelayUnderTest({ clientRateLimitPerSecond: 1 });
  const daemon = await openDaemon(relay);
  const client = await openClient(relay, {
    tokenType: "client",
    instanceId: "instance-1",
    userId: "user-1",
  });
  const frame = loadFixture<ClientRelayFrame>("client-relay-frame.json");
  const close = closed(client);

  client.send(JSON.stringify(frame));
  await nextMessage(daemon);
  client.send(JSON.stringify({ ...frame, channelId: "ch-client-2" }));

  await expect(close).resolves.toMatchObject({ code: 4429 });
});

it("disconnects daemon and clients through forced-disconnect control messages", async () => {
  relay = await startRelayUnderTest();
  const daemon = await openDaemon(relay);
  const client = await openClient(relay, {
    tokenType: "client",
    instanceId: "instance-1",
    userId: "user-1",
  });

  const clientMessage = nextMessage(client);
  const clientClose = closed(client);
  const daemonClose = closed(daemon);
  await relay.publishControl(loadFixture<RelayControlMessage>("control-disconnect-instance.json"));

  await expect(clientMessage).resolves.toMatchObject({
    type: "system",
    code: "forced_disconnect",
  });
  await expect(clientClose).resolves.toMatchObject({ code: 4410 });
  await expect(daemonClose).resolves.toMatchObject({ code: 4410 });
});

it("sends the relay control secret on user-presence and daemon control ingest", async () => {
  const ingest = await startIngestServer();
  ingestServer = ingest.server;
  relay = await startRelayUnderTest({ controlIngestUrl: ingest.url });

  const user = connect(
    relay,
    "/ws/user",
    await relay.signToken({ tokenType: "user", userId: "user-1" }),
  );
  await opened(user);
  user.send(JSON.stringify(loadFixture("user-presence-relay-frame.json")));

  await waitFor(() => expect(ingest.requests).toHaveLength(1));

  const daemon = await openDaemon(relay);
  daemon.send(JSON.stringify(loadFixture("daemon-control-relay-frame.json")));

  await waitFor(() => expect(ingest.requests).toHaveLength(2));
  for (const request of ingest.requests) {
    expect(request.headers.authorization).toBe("Bearer control-secret-control-secret-1234");
  }
});

it("does not write frame bodies to logs", async () => {
  relay = await startRelayUnderTest();
  const daemon = await openDaemon(relay);
  const client = await openClient(relay, {
    tokenType: "client",
    instanceId: "instance-1",
    userId: "user-1",
  });
  const frame = loadFixture<ClientRelayFrame>("client-relay-frame.json");

  client.send(JSON.stringify(frame));
  await nextMessage(daemon);

  expect(relay.logs()).not.toContain(stableJson(frame.payload));
});

afterEach(async () => {
  await Promise.allSettled([relay?.stop(), closeServer(ingestServer)]);
  relay = undefined;
  ingestServer = undefined;
});

function connect(current: RelayUnderTest, path: string, rawToken: string) {
  return new WebSocket(`${current.wsUrl}${path}`, {
    headers: { authorization: `Bearer ${rawToken}` },
  });
}

async function openDaemon(current: RelayUnderTest, instanceId = "instance-1", userId = "owner-1") {
  const daemon = connect(
    current,
    "/ws/daemon",
    await current.signToken({ tokenType: "connector", instanceId, userId }),
  );
  await opened(daemon);
  await waitForDaemon(current);
  return daemon;
}

async function openClient(
  current: RelayUnderTest,
  tokenInput: Parameters<RelayUnderTest["signToken"]>[0],
) {
  const client = connect(current, "/ws/client", await current.signToken(tokenInput));
  await opened(client);
  return client;
}

function opened(ws: WebSocket) {
  return new Promise<void>((resolve, reject) => {
    ws.once("open", () => resolve());
    ws.once("error", reject);
  });
}

function closed(ws: WebSocket) {
  return new Promise<{ code: number; reason: string }>((resolve) => {
    ws.once("close", (code, reason) => resolve({ code, reason: reason.toString() }));
    ws.once("error", () => {
      // ws emits an error for HTTP upgrade rejection before the close event.
    });
  });
}

function rejected(ws: WebSocket) {
  return new Promise<Error>((resolve, reject) => {
    ws.once("error", (err) => resolve(err));
    ws.once("open", () => reject(new Error("websocket unexpectedly opened")));
  });
}

function nextMessage(ws: WebSocket) {
  return new Promise<unknown>((resolve) => {
    ws.once("message", (data) => resolve(JSON.parse(data.toString())));
  });
}

async function noMessage(ws: WebSocket, ms: number) {
  const message = Symbol("message");
  const result = await Promise.race([nextMessage(ws).then(() => message), sleep(ms)]);
  if (result === message) throw new Error("unexpected relay frame");
}

async function waitForDaemon(current: RelayUnderTest) {
  await waitFor(async () => {
    const response = await fetch(`${current.httpUrl}/metrics`);
    const metrics = (await response.json()) as { daemons?: number };
    expect(metrics.daemons).toBeGreaterThanOrEqual(1);
  });
}

async function waitFor(assertion: () => void | Promise<void>, timeoutMs = 1_000) {
  const started = Date.now();
  let lastError: unknown;
  while (Date.now() - started < timeoutMs) {
    try {
      await assertion();
      return;
    } catch (err) {
      lastError = err;
      await sleep(20);
    }
  }
  throw lastError;
}

async function startIngestServer() {
  const requests: Array<{ headers: IncomingMessage["headers"]; body: unknown }> = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request)
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    requests.push({
      headers: request.headers,
      body: JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown,
    });
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  return { server, requests, url: `http://127.0.0.1:${port}/api/relay/control-ingest` };
}

async function closeServer(server?: Server) {
  if (!server?.listening) return;
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
}

function loadFixture<T = unknown>(name: string): T {
  return JSON.parse(
    readFileSync(
      join(import.meta.dirname, "../../../packages/relay-protocol/fixtures", name),
      "utf8",
    ),
  ) as T;
}

function stableJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => [key, sortKeys(child)]),
  );
}

function pauseSocket(ws: WebSocket) {
  (ws as unknown as { _socket?: { pause(): void } })._socket?.pause();
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
