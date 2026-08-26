import { RELAY_ENVELOPE_VERSION } from "@flycockpit/relay-protocol/envelopes";
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

function queuedResponse(requestId: string, clientSubmissionId: string) {
  return {
    ...responsesFixture.user_message_queued,
    id: requestId,
    data: {
      item: { ...responsesFixture.user_message_queued.data.item, id: clientSubmissionId },
      queue: responsesFixture.user_message_queued.data.queue.map((item) => ({
        ...item,
        id: clientSubmissionId,
      })),
    },
  };
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
      v: RELAY_ENVELOPE_VERSION,
      channelId: "sessions:i1",
      payload: {
        v: PROTOCOL_VERSION,
        kind: "req",
        id: "33333333-3333-4333-8333-333333333333",
        request: "send_user_message",
        params: {
          client_submission_id: "33333333-3333-4333-8333-333333333333",
          text: "hello",
        },
      },
    });
    expect(relay.payload.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );

    const response = queuedResponse(relay.payload.id, relay.payload.params.client_submission_id);
    socket.message(response);
    await expect(request).resolves.toEqual(response.data);
  });

  it("resends a caller-retained complete user submission unchanged", async () => {
    const { client, socket } = makeClient();
    const submission = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "@review inspect this",
      display_text: "inspect this",
      tag_expansions: [{ tag: "review", replacement: "review the patch" }],
      image_refs: [{ id: "55555555-5555-4555-8555-555555555555", detail: "high" }],
      forced_skill: "review",
    };

    const first = client.sendUserMessage(submission);
    const firstRelay = JSON.parse(socket.sent[0] ?? "{}");
    const firstResponse = queuedResponse(firstRelay.payload.id, submission.client_submission_id);
    socket.message(firstResponse);
    await expect(first).resolves.toEqual(firstResponse.data);

    const retry = client.sendUserMessage(submission);
    const retryRelay = JSON.parse(socket.sent[1] ?? "{}");
    expect(retryRelay.payload.params).toEqual(firstRelay.payload.params);
    expect(retryRelay.payload.params).toEqual(submission);
    const retryResponse = queuedResponse(retryRelay.payload.id, submission.client_submission_id);
    socket.message(retryResponse);
    await expect(retry).resolves.toEqual(retryResponse.data);
  });

  it("stages a 64KiB-plus remote user message in bounded bulk chunks before its reference request", async () => {
    const { client, socket } = makeClient();
    const submission = {
      client_submission_id: "44444444-4444-4444-8444-444444444444",
      text: "x".repeat(65_537),
    };
    const request = client.sendUserMessage(submission);

    await vi.waitFor(() => expect(socket.sent).toHaveLength(1));
    const chunk = JSON.parse(socket.sent[0] ?? "{}");
    expect(chunk.payload).toMatchObject({
      request: "write_bulk_transfer_chunk",
      params: {
        chunk_index: 0,
        transfer: {
          mime_class: "opaque",
          total_length: "65537",
        },
      },
    });
    expect(chunk.payload.params.data_base64.length).toBeLessThanOrEqual(256 * 1024);
    expect(JSON.stringify(chunk).length).toBeLessThan(524_360);

    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: chunk.payload.id,
      response: "bulk_transfer_chunk_accepted",
      data: {
        next_chunk_index: 1,
        received_bytes: "65537",
        complete: true,
        idle_timeout_ms: 60_000,
      },
    });
    await vi.waitFor(() => expect(socket.sent).toHaveLength(2));
    const bulk = JSON.parse(socket.sent[1] ?? "{}");
    expect(bulk.payload).toMatchObject({
      request: "send_user_message_bulk",
      params: {
        client_submission_id: submission.client_submission_id,
        transfer: chunk.payload.params.transfer,
      },
    });
    expect(bulk.payload.params.text).toBeUndefined();
    expect(JSON.stringify(bulk).length).toBeLessThan(524_360);

    const response = queuedResponse(bulk.payload.id, submission.client_submission_id);
    socket.message(response);
    await expect(request).resolves.toEqual(response.data);
  });

  it("rejects a generic or stale bulk-chunk acknowledgement before sending the bulk request", async () => {
    const { client, socket } = makeClient();
    const request = client.sendUserMessage({
      client_submission_id: "46464646-4646-4646-8646-464646464646",
      text: "x".repeat(65_537),
    });

    await vi.waitFor(() => expect(socket.sent).toHaveLength(1));
    const chunk = JSON.parse(socket.sent[0] ?? "{}");
    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: chunk.payload.id,
      response: "ack",
      data: { next_chunk_index: 1, received_bytes: "65537", complete: true },
    });
    await expect(request).rejects.toThrow("Unexpected daemon response");
    expect(socket.sent).toHaveLength(1);

    const retry = client.sendUserMessage({
      client_submission_id: "47474747-4747-4747-8747-474747474747",
      text: "x".repeat(65_537),
    });
    await vi.waitFor(() => expect(socket.sent).toHaveLength(2));
    const stale = JSON.parse(socket.sent[1] ?? "{}");
    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: stale.payload.id,
      response: "bulk_transfer_chunk_accepted",
      data: { next_chunk_index: 0, received_bytes: "0", complete: false, idle_timeout_ms: 60_000 },
    });
    await expect(retry).rejects.toThrow("invalid bulk-transfer chunk acknowledgement");
    expect(socket.sent).toHaveLength(2);
  });

  it("omits an explicitly empty display form beside an oversized source transfer", async () => {
    const { client, socket } = makeClient();
    const submission = {
      client_submission_id: "44444444-4444-4444-8444-444444444445",
      text: "x".repeat(65_537),
      display_text: "",
    };
    const request = client.sendUserMessage(submission);

    await vi.waitFor(() => expect(socket.sent).toHaveLength(1));
    const sourceChunk = JSON.parse(socket.sent[0] ?? "{}");
    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: sourceChunk.payload.id,
      response: "bulk_transfer_chunk_accepted",
      data: {
        next_chunk_index: 1,
        received_bytes: "65537",
        complete: true,
        idle_timeout_ms: 60_000,
      },
    });

    await vi.waitFor(() => expect(socket.sent).toHaveLength(2));
    const bulk = JSON.parse(socket.sent[1] ?? "{}");
    expect(bulk.payload.params.display_text).toBeUndefined();
    expect(bulk.payload.params.display_transfer).toBeUndefined();
    expect(JSON.stringify(bulk).length).toBeLessThan(524_360);

    const response = queuedResponse(bulk.payload.id, submission.client_submission_id);
    socket.message(response);
    await expect(request).resolves.toEqual(response.data);
  });

  it("stages a 64KiB-plus display form with its source before the bounded reference request", async () => {
    const { client, socket } = makeClient();
    const submission = {
      client_submission_id: "45454545-4545-4545-8545-454545454545",
      text: "short",
      display_text: "d".repeat(65_537),
    };
    const request = client.sendUserMessage(submission);

    await vi.waitFor(() => expect(socket.sent).toHaveLength(1));
    const sourceChunk = JSON.parse(socket.sent[0] ?? "{}");
    expect(sourceChunk.payload).toMatchObject({
      request: "write_bulk_transfer_chunk",
      params: { chunk_index: 0, transfer: { mime_class: "opaque", total_length: "5" } },
    });
    expect(JSON.stringify(sourceChunk).length).toBeLessThan(524_360);
    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: sourceChunk.payload.id,
      response: "bulk_transfer_chunk_accepted",
      data: { next_chunk_index: 1, received_bytes: "5", complete: true, idle_timeout_ms: 60_000 },
    });

    await vi.waitFor(() => expect(socket.sent).toHaveLength(2));
    const displayChunk = JSON.parse(socket.sent[1] ?? "{}");
    expect(displayChunk.payload).toMatchObject({
      request: "write_bulk_transfer_chunk",
      params: {
        chunk_index: 0,
        transfer: { mime_class: "opaque", total_length: "65537" },
      },
    });
    expect(JSON.stringify(displayChunk).length).toBeLessThan(524_360);
    socket.message({
      v: PROTOCOL_VERSION,
      kind: "res",
      id: displayChunk.payload.id,
      response: "bulk_transfer_chunk_accepted",
      data: {
        next_chunk_index: 1,
        received_bytes: "65537",
        complete: true,
        idle_timeout_ms: 60_000,
      },
    });

    await vi.waitFor(() => expect(socket.sent).toHaveLength(3));
    const bulk = JSON.parse(socket.sent[2] ?? "{}");
    expect(bulk.payload).toMatchObject({
      request: "send_user_message_bulk",
      params: {
        client_submission_id: submission.client_submission_id,
        transfer: sourceChunk.payload.params.transfer,
        display_transfer: displayChunk.payload.params.transfer,
      },
    });
    expect(bulk.payload.params.display_text).toBeUndefined();
    expect(JSON.stringify(bulk).length).toBeLessThan(524_360);

    const response = queuedResponse(bulk.payload.id, submission.client_submission_id);
    socket.message(response);
    await expect(request).resolves.toEqual(response.data);
  });

  it("stages an exact-8MiB remote user message through bounded bulk frames", async () => {
    const { client, socket } = makeClient();
    const submission = {
      client_submission_id: "55555555-5555-4555-8555-555555555555",
      text: "z".repeat(8 * 1024 * 1024),
    };
    const rawChunkBytes = 3 * ((256 * 1024) / 4);
    const chunkCount = Math.ceil(new TextEncoder().encode(submission.text).length / rawChunkBytes);
    const request = client.sendUserMessage(submission);

    for (let index = 0; index < chunkCount; index += 1) {
      await vi.waitFor(() => expect(socket.sent).toHaveLength(index + 1));
      const frame = JSON.parse(socket.sent[index] ?? "{}");
      expect(frame.payload).toMatchObject({
        request: "write_bulk_transfer_chunk",
        params: {
          chunk_index: index,
          transfer: {
            mime_class: "opaque",
            total_length: String(8 * 1024 * 1024),
          },
        },
      });
      expect(frame.payload.params.data_base64.length).toBeLessThanOrEqual(256 * 1024);
      expect(JSON.stringify(frame).length).toBeLessThan(524_360);
      socket.message({
        v: PROTOCOL_VERSION,
        kind: "res",
        id: frame.payload.id,
        response: "bulk_transfer_chunk_accepted",
        data: {
          next_chunk_index: index + 1,
          received_bytes: String(Math.min((index + 1) * rawChunkBytes, 8 * 1024 * 1024)),
          complete: index + 1 === chunkCount,
          idle_timeout_ms: 60_000,
        },
      });
    }

    await vi.waitFor(() => expect(socket.sent).toHaveLength(chunkCount + 1));
    const bulk = JSON.parse(socket.sent[chunkCount] ?? "{}");
    expect(bulk.payload).toMatchObject({
      request: "send_user_message_bulk",
      params: {
        client_submission_id: submission.client_submission_id,
        transfer: {
          mime_class: "opaque",
          total_length: String(8 * 1024 * 1024),
        },
      },
    });
    expect(bulk.payload.params.text).toBeUndefined();
    expect(JSON.stringify(bulk).length).toBeLessThan(524_360);

    const response = queuedResponse(bulk.payload.id, submission.client_submission_id);
    socket.message(response);
    await expect(request).resolves.toEqual(response.data);
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
