import type { AddressInfo } from "node:net";
import { signRelayToken, verifyRelayTokenWithSecret } from "@flycockpit/relay-protocol/tokens";
import { afterEach, describe, expect, it, vi } from "vitest";
import WebSocket from "ws";
import { MemoryPresenceStore } from "./presence";
import { createRelayServer, type RelayServerConfig, type RelayServerHandle } from "./server";

const secret = "1234567890abcdef1234567890abcdef";
const issuer = "https://app.example.test";

let handles: RelayServerHandle[] = [];

afterEach(async () => {
  await Promise.allSettled(handles.map((handle) => handle.close()));
  handles = [];
});

async function token(input: Parameters<typeof signRelayToken>[0]) {
  return (await signRelayToken(input, { secret, issuer })).token;
}

async function startRelay(logs: string[] = [], overrides: Partial<RelayServerConfig> = {}) {
  const presenceStore = new MemoryPresenceStore();
  const handle = createRelayServer({
    relayId: "relay-test",
    jwksUrl: "https://app.example.test/api/relay/jwks.json",
    tokenIssuer: issuer,
    heartbeatMs: 1_000,
    leaseTtlMs: 30_000,
    maxFrameBytes: 1024 * 1024,
    maxChannelsPerClient: 2,
    maxConnectionsPerInstance: 10,
    clientRateLimitPerSecond: 100,
    presenceStore,
    verifyToken: (raw) => verifyRelayTokenWithSecret(raw, { secret, issuer }),
    logger: {
      info: (...args) => logs.push(args.join(" ")),
      warn: (...args) => logs.push(args.join(" ")),
      error: (...args) => logs.push(args.join(" ")),
    },
    ...overrides,
  });
  await new Promise<void>((resolve) => handle.server.listen(0, resolve));
  handles.push(handle);
  const port = (handle.server.address() as AddressInfo).port;
  return { handle, url: `ws://127.0.0.1:${port}` };
}

function connect(url: string, path: string, rawToken: string) {
  const ws = new WebSocket(`${url}${path}`, { headers: { authorization: `Bearer ${rawToken}` } });
  return ws;
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
  return new Promise<void>((resolve) => {
    ws.once("error", () => resolve());
  });
}

function nextMessage(ws: WebSocket) {
  return new Promise<unknown>((resolve) => {
    ws.once("message", (data) => resolve(JSON.parse(data.toString())));
  });
}

async function waitForLease(handle: RelayServerHandle, instanceId: string) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const lease = await handle.presenceStore.getDaemonLease(instanceId);
    if (lease) return lease;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("lease was not created");
}

describe("relay server", () => {
  it("rejects garbage tokens during websocket upgrade", async () => {
    const { url } = await startRelay();
    const ws = connect(url, "/ws/daemon", "garbage");

    await expect(rejected(ws)).resolves.toBeUndefined();
  });

  it("accepts a client connection but closes it with instance_offline when no daemon is present", async () => {
    const { url } = await startRelay();
    const client = connect(
      url,
      "/ws/client",
      await token({ tokenType: "client", instanceId: "instance-1", userId: "user-1" }),
    );
    const message = nextMessage(client);
    const close = closed(client);
    await opened(client);

    await expect(message).resolves.toMatchObject({ type: "system", code: "instance_offline" });
    await expect(close).resolves.toMatchObject({ code: 4404 });
  });

  it("pairs a daemon and client, stamps principals, and routes daemon replies by channel", async () => {
    const { handle, url } = await startRelay();
    const daemon = connect(
      url,
      "/ws/daemon",
      await token({ tokenType: "connector", instanceId: "instance-1", userId: "owner-1" }),
    );
    await opened(daemon);
    await waitForLease(handle, "instance-1");

    const client = connect(
      url,
      "/ws/client",
      await token({
        tokenType: "client",
        instanceId: "instance-1",
        userId: "user-1",
        grants: [{ scope: "terminal", projectRoot: null }],
      }),
    );
    await opened(client);

    client.send(JSON.stringify({ v: 1, channelId: "ch-1", payload: { text: "hello" } }));
    await expect(nextMessage(daemon)).resolves.toMatchObject({
      v: 1,
      channelId: "ch-1",
      from: "client",
      principal: { userId: "user-1", grants: [{ scope: "terminal", projectRoot: null }] },
      payload: { text: "hello" },
    });

    daemon.send(JSON.stringify({ v: 1, channelId: "ch-1", payload: { text: "world" } }));
    await expect(nextMessage(client)).resolves.toMatchObject({
      v: 1,
      channelId: "ch-1",
      payload: { text: "world" },
    });
  });

  it("disconnects daemon and clients through forced-disconnect control messages", async () => {
    const { handle, url } = await startRelay();
    const daemon = connect(
      url,
      "/ws/daemon",
      await token({ tokenType: "connector", instanceId: "instance-1", userId: "owner-1" }),
    );
    await opened(daemon);
    await waitForLease(handle, "instance-1");

    const client = connect(
      url,
      "/ws/client",
      await token({ tokenType: "client", instanceId: "instance-1", userId: "user-1" }),
    );
    await opened(client);

    const clientMessage = nextMessage(client);
    const clientClose = closed(client);
    const daemonClose = closed(daemon);
    await handle.publishControl({ type: "disconnect_instance", instanceId: "instance-1" });

    await expect(clientMessage).resolves.toMatchObject({
      type: "system",
      code: "forced_disconnect",
    });
    await expect(clientClose).resolves.toMatchObject({ code: 4410 });
    await expect(daemonClose).resolves.toMatchObject({ code: 4410 });
  });

  it("sends the relay control secret on user-presence and daemon control ingest", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    const { url } = await startRelay([], {
      controlIngestUrl: "https://api.example.test/api/relay/control-ingest",
      controlSecret: "control-secret-control-secret-1234",
    });

    const user = connect(url, "/ws/user", await token({ tokenType: "user", userId: "user-1" }));
    await opened(user);
    user.send(
      JSON.stringify({
        v: 1,
        type: "presence",
        clientId: "client-1",
        visible: true,
        ts: "2026-07-10T00:00:00.000Z",
      }),
    );

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    const daemon = connect(
      url,
      "/ws/daemon",
      await token({ tokenType: "connector", instanceId: "instance-1", userId: "owner-1" }),
    );
    await opened(daemon);
    daemon.send(
      JSON.stringify({
        v: 1,
        to: "control",
        event: "APPROVAL_NEEDED",
        payload: { eventId: "evt-1" },
      }),
    );

    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    for (const call of fetchMock.mock.calls) {
      expect(call[1]).toMatchObject({
        headers: expect.objectContaining({
          authorization: "Bearer control-secret-control-secret-1234",
        }),
      });
    }
    fetchMock.mockRestore();
  });

  it("does not write frame bodies to logs", async () => {
    const logs: string[] = [];
    const { handle, url } = await startRelay(logs);
    const daemon = connect(
      url,
      "/ws/daemon",
      await token({ tokenType: "connector", instanceId: "instance-1", userId: "owner-1" }),
    );
    await opened(daemon);
    await waitForLease(handle, "instance-1");
    const client = connect(
      url,
      "/ws/client",
      await token({ tokenType: "client", instanceId: "instance-1", userId: "user-1" }),
    );
    await opened(client);

    client.send(
      JSON.stringify({ v: 1, channelId: "secret", payload: { value: "DO_NOT_LOG_SECRET" } }),
    );
    await nextMessage(daemon);

    expect(logs.join("\n")).not.toContain("DO_NOT_LOG_SECRET");
  });
});
