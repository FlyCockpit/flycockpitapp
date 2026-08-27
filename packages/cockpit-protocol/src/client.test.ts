import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import responsesFixture from "../fixtures/daemon-wire/responses.json" with { type: "json" };
import { PROTOCOL_VERSION } from ".";
import {
  isAmbiguousUserMessageSendError,
  isRemoteSessionError,
  RemoteSessionClient,
  RemoteSessionError,
  remoteSessionClientRelayUrl,
  shouldRetainUserMessageSubmission,
} from "./client";

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

  emit(type: string, event?: unknown) {
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

  it("fails closed before emitting a legacy remote user-message frame", async () => {
    const { client, socket } = makeClient();

    await expect(
      client.sendUserMessage({
        client_submission_id: "44444444-4444-7444-8444-444444444444",
        text: "hello",
      }),
    ).rejects.toMatchObject({
      code: "unavailable",
      message: expect.stringContaining("remote V2 message sending is unavailable"),
    });
    expect(socket.sent).toEqual([]);
  });
  it("modes_session_setup_requires a creation mode while leaving resumed attach mode daemon-owned", async () => {
    const { client, socket } = makeClient();
    const fresh = client.attach({
      project_root: "/work/project",
      session_entry_mode: "assistant",
    });
    const freshRelay = JSON.parse(socket.sent[0] ?? "{}");
    expect(freshRelay.payload.params).toMatchObject({
      project_root: "/work/project",
      session_entry_mode: "assistant",
    });
    socket.message({ ...responsesFixture.attached, id: freshRelay.payload.id });
    await expect(fresh).resolves.toEqual(responsesFixture.attached.data);

    const resumed = client.attach({
      session_id: "11111111-1111-4111-8111-111111111111",
    });
    const resumedRelay = JSON.parse(socket.sent[1] ?? "{}");
    expect(resumedRelay.payload.params).toEqual({
      session_id: "11111111-1111-4111-8111-111111111111",
    });
    socket.message({ ...responsesFixture.attached, id: resumedRelay.payload.id });
    await expect(resumed).resolves.toEqual(responsesFixture.attached.data);
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

  it("sends the complete v6 active-model selection and favorite requests", async () => {
    const { client, socket } = makeClient();
    const selection = client.setActiveModel({
      selection_id: "44444444-4444-4444-8444-444444444444",
      provider: "anthropic",
      model: "claude-opus-4-1",
      trigger: "picker",
      reasoning_effort: "high",
      thinking_mode: "high",
      prompt_cache_retention: "extended",
      persist_as_default: true,
    });
    const selectionRelay = JSON.parse(socket.sent[0] ?? "{}");
    expect(selectionRelay.payload).toMatchObject({
      request: "set_active_model",
      params: {
        selection_id: "44444444-4444-4444-8444-444444444444",
        provider: "anthropic",
        model: "claude-opus-4-1",
        trigger: "picker",
        reasoning_effort: "high",
        thinking_mode: "high",
        prompt_cache_retention: "extended",
        persist_as_default: true,
      },
    });
    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: selectionRelay.payload.id,
      response: "ack",
    });
    await expect(selection).resolves.toBeUndefined();

    const favorite = client.setModelFavorite({
      provider: "anthropic",
      model: "claude-opus-4-1",
      favorite: true,
    });
    const favoriteRelay = JSON.parse(socket.sent[1] ?? "{}");
    expect(favoriteRelay.payload).toMatchObject({
      request: "set_model_favorite",
      params: {
        provider: "anthropic",
        model: "claude-opus-4-1",
        favorite: true,
      },
    });
    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: favoriteRelay.payload.id,
      response: "ack",
    });
    await expect(favorite).resolves.toBeUndefined();
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

    const rejection = await request.catch((error: unknown) => error);
    expect(isRemoteSessionError(rejection)).toBe(true);
    expect(rejection).toMatchObject({
      name: "RemoteSessionError",
      code: "authorization",
      data: { code: "authorization", message: "No access" },
    } satisfies Partial<RemoteSessionError>);
  });

  it("classifies only uncertain user-message failures as ambiguous", () => {
    expect(
      isAmbiguousUserMessageSendError(
        new RemoteSessionError("receipt lookup failed", "internal", { code: "internal" }),
      ),
    ).toBe(true);
    expect(
      isAmbiguousUserMessageSendError(
        new RemoteSessionError("daemon is shutting down", "shutdown", { code: "shutdown" }),
      ),
    ).toBe(true);
    for (const code of [
      "storage_full",
      "storage_memory",
      "storage_read_only",
      "storage_io",
      "storage_corrupt",
    ]) {
      expect(
        isAmbiguousUserMessageSendError(
          new RemoteSessionError("durability outcome is unknown", code, { code }),
        ),
      ).toBe(true);
    }
    expect(isAmbiguousUserMessageSendError(new Error("socket closed"))).toBe(true);
    expect(
      isAmbiguousUserMessageSendError(
        new RemoteSessionError("payload rejected", "bad_request", { code: "bad_request" }),
      ),
    ).toBe(false);
  });

  it("retains deterministic pre-queue failures without calling them ambiguous", () => {
    const error = new RemoteSessionError("message was not accepted", "user_message_not_accepted", {
      code: "user_message_not_accepted",
    });
    expect(isAmbiguousUserMessageSendError(error)).toBe(false);
    expect(shouldRetainUserMessageSubmission(error)).toBe(true);
    const terminal = new RemoteSessionError(
      "message reached a durable terminal disposition",
      "user_message_terminated",
      { code: "user_message_terminated" },
    );
    expect(isAmbiguousUserMessageSendError(terminal)).toBe(false);
    expect(shouldRetainUserMessageSubmission(terminal)).toBe(false);
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

  it("ignores late callbacks from an old socket without clobbering the new epoch", async () => {
    const onEvent = vi.fn();
    const onStatus = vi.fn();
    vi.mocked(globalThis.crypto.randomUUID)
      .mockReturnValueOnce("33333333-3333-4333-8333-333333333331")
      .mockReturnValueOnce("33333333-3333-4333-8333-333333333332");
    const { client, socket: oldSocket } = makeClient({ onEvent, onStatus });
    const oldRequest = client.listSessions({});
    oldSocket.readyState = 3;

    client.connect();
    const newSocket = FakeWebSocket.instances[1];
    if (!newSocket) throw new Error("replacement socket was not constructed");
    newSocket.open();
    await expect(oldRequest).rejects.toThrow("replaced");

    const newRequest = client.listSessions({});
    const newRelay = JSON.parse(newSocket.sent[0] ?? "{}");
    oldSocket.emit("close");
    oldSocket.message({
      v: PROTOCOL_VERSION,
      kind: "evt",
      event: "notice",
      data: {
        session_id: "11111111-1111-4111-8111-111111111111",
        text: "stale old-socket event",
      },
    });
    oldSocket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: newRelay.payload.id,
      response: "sessions",
      data: { sessions: [{ stale: true }] },
    });

    expect(onEvent).not.toHaveBeenCalled();
    expect(onStatus).not.toHaveBeenLastCalledWith("offline");
    newSocket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: newRelay.payload.id,
      response: "sessions",
      data: { sessions: [] },
    });
    await expect(newRequest).resolves.toEqual({ sessions: [] });
  });
});
