import {
  type AttachResult,
  type ClientRequest,
  createEnvelope,
  parseAttachResult,
  parseListProjectsResult,
  parseListSessionsResult,
  serverMessageSchema,
} from "@flycockpit/cockpit-protocol";
import {
  type DaemonClientRelayFrame,
  daemonClientRelayFrameSchema,
} from "@flycockpit/relay-protocol/envelopes";

type Status = "idle" | "connecting" | "connected" | "offline" | "error";

type ClientOptions = {
  instanceId: string;
  relayUrl: string;
  token: string;
  onStatus?: (status: Status, detail?: string) => void;
  onEvent?: (event: unknown) => void;
};

type Pending = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
};

function clientRelayUrl(relayUrl: string, token: string) {
  const url = new URL(relayUrl);
  if (!url.pathname.endsWith("/client")) {
    url.pathname = url.pathname.replace(/\/$/, "") + "/client";
  }
  url.searchParams.set("token", token);
  return url.toString();
}

export class NativeRemoteSessionClient {
  private ws: WebSocket | null = null;
  private pending = new Map<string, Pending>();
  private requestSeq = 0;
  private readonly channelId: string;

  constructor(private readonly options: ClientOptions) {
    this.channelId = "sessions:" + options.instanceId;
  }

  connect() {
    if (
      this.ws &&
      (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)
    )
      return;
    this.options.onStatus?.("connecting");
    const ws = new WebSocket(clientRelayUrl(this.options.relayUrl, this.options.token));
    this.ws = ws;
    ws.addEventListener("open", () => this.options.onStatus?.("connected"));
    ws.addEventListener("close", () => {
      if (this.ws === ws) this.ws = null;
      this.options.onStatus?.("offline");
      for (const pending of this.pending.values())
        pending.reject(new Error("Instance connection closed."));
      this.pending.clear();
    });
    ws.addEventListener("error", () =>
      this.options.onStatus?.("error", "Relay connection failed."),
    );
    ws.addEventListener("message", (event) => this.handleMessage(event.data));
  }

  close() {
    this.ws?.close();
    this.ws = null;
  }

  async listProjects() {
    return parseListProjectsResult(await this.send({ type: "list_projects" }));
  }

  async listSessions(projectRoot: string) {
    return parseListSessionsResult(await this.send({ type: "list_sessions", projectRoot }));
  }

  async attach(sessionId: string, sinceSeq?: number): Promise<AttachResult> {
    return parseAttachResult(await this.send({ type: "attach", sessionId, sinceSeq }));
  }

  async sendUserMessage(sessionId: string, text: string, clientMessageId: string) {
    return this.send({ type: "send_user_message", sessionId, text, clientMessageId });
  }

  async resolveInterrupt(input: {
    sessionId: string;
    interruptId: string;
    resolution: "approve" | "deny" | "answer";
    answer?: string;
  }) {
    return this.send({ type: "resolve_interrupt", ...input });
  }

  private send(request: ClientRequest) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error("Instance connection is not open."));
    }
    const id = "native-" + ++this.requestSeq;
    const envelope = createEnvelope(id, request);
    const promise = new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (!this.pending.delete(id)) return;
        reject(new Error("Request timed out."));
      }, 30_000);
    });
    this.ws.send(JSON.stringify({ v: 1, channelId: this.channelId, payload: envelope }));
    return promise;
  }

  private handleMessage(raw: unknown) {
    let frame: DaemonClientRelayFrame;
    try {
      frame = daemonClientRelayFrameSchema.parse(JSON.parse(String(raw)));
    } catch {
      return;
    }
    const message = serverMessageSchema.safeParse(frame.payload);
    if (!message.success) return;
    if (message.data.type === "event") {
      this.options.onEvent?.(message.data.event);
      return;
    }
    const pending = this.pending.get(message.data.id);
    if (!pending) return;
    this.pending.delete(message.data.id);
    if (message.data.ok) pending.resolve(message.data.result);
    else pending.reject(new Error(message.data.error.message));
  }
}
