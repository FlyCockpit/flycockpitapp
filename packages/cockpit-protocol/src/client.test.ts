import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PROTOCOL_VERSION } from ".";
import { RemoteSessionClient, RemoteSessionError, remoteSessionClientRelayUrl } from "./client";

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  readonly listeners = new Map<string, Array<(event?: unknown) => void>>();
  readonly sent: string[] = [];
  readyState = 0;

  constructor(readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type: string, listener: (event?: unknown) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.readyState = 3;
    this.emit("close");
  }

  open() {
    this.readyState = 1;
    this.emit("open");
  }

  message(payload: unknown) {
    this.emit("message", { data: JSON.stringify({ v: 1, channelId: "sessions:i1", payload }) });
  }

  private emit(type: string, event?: unknown) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

function makeClient(options: Partial<ConstructorParameters<typeof RemoteSessionClient>[0]> = {}) {
  const client = new RemoteSessionClient({
    instanceId: "i1",
    relayUrl: "wss://relay.flycockpit.test/ws",
    token: "tok",
    WebSocketImpl: FakeWebSocket,
    ...options,
  });
  client.connect();
  const socket = FakeWebSocket.instances[0];
  socket?.open();
  if (!socket) throw new Error("fake socket was not constructed");
  return { client, socket };
}

describe("RemoteSessionClient", () => {
  beforeEach(() => {
    FakeWebSocket.instances = [];
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "33333333-3333-4333-8333-333333333333",
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("builds relay URLs for web-relative and native-absolute transports", () => {
    expect(remoteSessionClientRelayUrl("/relay", "tok", "https://app.flycockpit.test")).toBe(
      "https://app.flycockpit.test/relay/client?token=tok",
    );
    expect(remoteSessionClientRelayUrl("wss://relay.flycockpit.test/ws", "tok")).toBe(
      "wss://relay.flycockpit.test/ws/client?token=tok",
    );
  });

  it("sends a relay frame wrapping a cockpit-proto req envelope with a uuid id", async () => {
    const { client, socket } = makeClient();
    const request = client.sendUserMessage("hello");
    const relay = JSON.parse(socket.sent[0] ?? "{}");

    expect(relay).toMatchObject({
      v: 1,
      channelId: "sessions:i1",
      payload: {
        v: PROTOCOL_VERSION,
        kind: "req",
        id: "33333333-3333-4333-8333-333333333333",
        request: "send_user_message",
        params: { text: "hello" },
      },
    });
    expect(relay.payload.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );

    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: relay.payload.id,
      response: "ack",
    });
    await expect(request).resolves.toBeUndefined();
  });

  it("resolves a pending request from a res frame", async () => {
    const { client, socket } = makeClient();
    const request = client.listSessions({});
    const relay = JSON.parse(socket.sent[0] ?? "{}");

    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: relay.payload.id,
      response: "sessions",
      data: { sessions: [] },
    });

    await expect(request).resolves.toEqual({ sessions: [] });
  });

  it("resolves session_live_status responses", async () => {
    const { client, socket } = makeClient();
    const request = client.sessionLiveStatus(["11111111-1111-4111-8111-111111111111"]);
    const relay = JSON.parse(socket.sent[0] ?? "{}");

    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: relay.payload.id,
      response: "session_live_status",
      data: {
        statuses: [
          {
            session_id: "11111111-1111-4111-8111-111111111111",
            has_active_schedules: true,
            processing: false,
          },
        ],
      },
    });

    await expect(request).resolves.toEqual({
      statuses: [
        {
          session_id: "11111111-1111-4111-8111-111111111111",
          has_active_schedules: true,
          processing: false,
        },
      ],
    });
  });

  it("rejects a pending request from an err frame with code and data", async () => {
    const { client, socket } = makeClient();
    const request = client.listSessions({});
    const relay = JSON.parse(socket.sent[0] ?? "{}");

    socket.message({
      v: PROTOCOL_VERSION,
      kind: "err",
      id: relay.payload.id,
      error: { code: "authorization", message: "No access" },
    });

    await expect(request).rejects.toMatchObject({
      name: "RemoteSessionError",
      code: "authorization",
      data: { code: "authorization", message: "No access" },
    } satisfies Partial<RemoteSessionError>);
  });

  it("forwards evt frames and tolerates unknown event kinds without throwing", () => {
    const onEvent = vi.fn();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const { socket } = makeClient({ onEvent });

    expect(() =>
      socket.message({
        v: PROTOCOL_VERSION,
        kind: "evt",
        event: "future_daemon_event",
        data: { payload: true },
      }),
    ).not.toThrow();

    expect(onEvent).toHaveBeenCalledWith(
      expect.objectContaining({ event: "future_daemon_event", __unknown: true }),
    );
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("unknown daemon event kind: future_daemon_event"),
      expect.objectContaining({ event: "future_daemon_event" }),
    );
  });
});
