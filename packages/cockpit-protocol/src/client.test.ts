import { describe, expect, it } from "vitest";
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

describe("RemoteSessionClient", () => {
  it("builds relay URLs for web-relative and native-absolute transports", () => {
    expect(remoteSessionClientRelayUrl("/relay", "tok", "https://app.flycockpit.test")).toBe(
      "https://app.flycockpit.test/relay/client?token=tok",
    );
    expect(remoteSessionClientRelayUrl("wss://relay.flycockpit.test/ws", "tok")).toBe(
      "wss://relay.flycockpit.test/ws/client?token=tok",
    );
  });

  it("constructs shared web and native clients with distinct request prefixes", async () => {
    FakeWebSocket.instances = [];
    const web = new RemoteSessionClient({
      instanceId: "i1",
      relayUrl: "/relay",
      token: "tok",
      idPrefix: "web",
      baseUrl: "https://app.flycockpit.test",
      WebSocketImpl: FakeWebSocket,
    });
    const native = new RemoteSessionClient({
      instanceId: "i1",
      relayUrl: "wss://relay.flycockpit.test/ws",
      token: "tok",
      idPrefix: "native",
      WebSocketImpl: FakeWebSocket,
    });

    web.connect();
    native.connect();
    FakeWebSocket.instances[0]?.open();
    FakeWebSocket.instances[1]?.open();

    const webRequest = web.listProjects();
    const nativeRequest = native.listProjects();
    const webEnvelope = JSON.parse(FakeWebSocket.instances[0]?.sent[0] ?? "{}").payload;
    const nativeEnvelope = JSON.parse(FakeWebSocket.instances[1]?.sent[0] ?? "{}").payload;
    expect(webEnvelope.id).toBe("web-1");
    expect(nativeEnvelope.id).toBe("native-1");

    FakeWebSocket.instances[0]?.message({
      type: "response",
      id: "web-1",
      ok: true,
      result: { projects: [] },
    });
    FakeWebSocket.instances[1]?.message({
      type: "response",
      id: "native-1",
      ok: true,
      result: { projects: [] },
    });

    await expect(webRequest).resolves.toEqual({ projects: [] });
    await expect(nativeRequest).resolves.toEqual({ projects: [] });
  });

  it("preserves daemon error code and data on rejected responses", async () => {
    FakeWebSocket.instances = [];
    const client = new RemoteSessionClient({
      instanceId: "i1",
      relayUrl: "wss://relay.flycockpit.test/ws",
      token: "tok",
      idPrefix: "native",
      WebSocketImpl: FakeWebSocket,
    });
    client.connect();
    FakeWebSocket.instances[0]?.open();
    const request = client.listProjects();
    FakeWebSocket.instances[0]?.message({
      type: "response",
      id: "native-1",
      ok: false,
      error: { code: "FORBIDDEN", message: "No access", data: { instanceId: "i1" } },
    });

    await expect(request).rejects.toMatchObject({
      name: "RemoteSessionError",
      code: "FORBIDDEN",
      data: { instanceId: "i1" },
    } satisfies Partial<RemoteSessionError>);
  });
});
