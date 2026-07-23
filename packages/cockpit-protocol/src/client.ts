import {
  type DaemonClientRelayFrame,
  daemonClientRelayFrameSchema,
  RELAY_ENVELOPE_VERSION,
} from "@flycockpit/relay-protocol/envelopes";
import {
  type ClientRequest,
  createEnvelope,
  parseAckResult,
  parseAttachResult,
  parseFsListResult,
  parseFsReadResult,
  parseFsStatResult,
  parseFsWriteResult,
  parseGitDiffFileResult,
  parseGitStatusResult,
  parseHistoryPageResult,
  parseListSessionsResult,
  parseSessionLiveStatusResult,
  parseSessionMessagesResult,
  type ResolveResponse,
  serverMessageSchema,
} from ".";

export type RemoteSessionStatus = "idle" | "connecting" | "connected" | "offline" | "error";

type Listener = { data?: unknown } | unknown;

export type RemoteSessionWebSocket = {
  readonly readyState: number;
  send(data: string): void;
  close(): void;
  addEventListener(type: "open" | "close" | "error", listener: () => void): void;
  addEventListener(type: "message", listener: (event: Listener) => void): void;
};

export type RemoteSessionWebSocketConstructor = new (url: string) => RemoteSessionWebSocket;

export type RemoteSessionClientOptions = {
  instanceId: string;
  relayUrl: string;
  token: string;
  baseUrl?: string;
  WebSocketImpl?: RemoteSessionWebSocketConstructor;
  onStatus?: (status: RemoteSessionStatus, detail?: string) => void;
  onEvent?: (event: unknown) => void;
};

type Pending = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
};

type ParamsOf<Name extends ClientRequest["request"]> = Extract<
  ClientRequest,
  { request: Name }
>["params"];

export class RemoteSessionError extends Error {
  readonly code: string;
  readonly data: unknown;

  constructor(message: string, code: string, data: unknown) {
    super(message);
    this.name = "RemoteSessionError";
    this.code = code;
    this.data = data;
  }
}

export function remoteSessionClientRelayUrl(relayUrl: string, token: string, baseUrl?: string) {
  const url = baseUrl ? new URL(relayUrl, baseUrl) : new URL(relayUrl);
  if (!url.pathname.endsWith("/client")) {
    url.pathname = url.pathname.replace(/\/$/, "") + "/client";
  }
  url.searchParams.set("token", token);
  return url.toString();
}

function defaultWebSocket() {
  return (globalThis as { WebSocket?: RemoteSessionWebSocketConstructor }).WebSocket;
}

function messageData(event: Listener) {
  if (event && typeof event === "object" && "data" in event) return event.data;
  return event;
}

function nextRequestId() {
  return globalThis.crypto.randomUUID();
}

function warn(message: string, detail?: unknown) {
  console.warn(`[cockpit-protocol] ${message}`, detail);
}

export class RemoteSessionClient {
  private ws: RemoteSessionWebSocket | null = null;
  private readonly pending = new Map<string, Pending>();
  private readonly channelId: string;

  constructor(private readonly options: RemoteSessionClientOptions) {
    this.channelId = "sessions:" + options.instanceId;
  }

  connect() {
    if (this.ws && (this.ws.readyState === 0 || this.ws.readyState === 1)) return;
    const WebSocketImpl = this.options.WebSocketImpl ?? defaultWebSocket();
    if (!WebSocketImpl) {
      this.options.onStatus?.("error", "WebSocket is not available.");
      return;
    }
    this.options.onStatus?.("connecting");
    const ws = new WebSocketImpl(
      remoteSessionClientRelayUrl(this.options.relayUrl, this.options.token, this.options.baseUrl),
    );
    this.ws = ws;
    ws.addEventListener("open", () => this.options.onStatus?.("connected"));
    ws.addEventListener("close", () => {
      if (this.ws === ws) this.ws = null;
      this.options.onStatus?.("offline");
      for (const pending of this.pending.values()) {
        pending.reject(new Error("Instance connection closed."));
      }
      this.pending.clear();
    });
    ws.addEventListener("error", () =>
      this.options.onStatus?.("error", "Relay connection failed."),
    );
    ws.addEventListener("message", (event) => this.handleMessage(messageData(event)));
  }

  close() {
    this.ws?.close();
    this.ws = null;
  }

  async attach(params: ParamsOf<"attach"> = {}) {
    return parseAttachResult(await this.send({ request: "attach", params }));
  }

  async sendUserMessage(params: ParamsOf<"send_user_message"> | string) {
    const requestParams = typeof params === "string" ? { text: params } : params;
    return parseAckResult(await this.send({ request: "send_user_message", params: requestParams }));
  }

  async resolveInterrupt(interrupt_id: string, response: ResolveResponse) {
    return parseAckResult(
      await this.send({ request: "resolve_interrupt", params: { interrupt_id, response } }),
    );
  }

  async listSessions(params: ParamsOf<"list_sessions"> = {}) {
    return parseListSessionsResult(await this.send({ request: "list_sessions", params }));
  }

  async readSessionMessages(params: ParamsOf<"read_session_messages">) {
    return parseSessionMessagesResult(
      await this.send({ request: "read_session_messages", params }),
    );
  }

  async readHistoryPage(params: ParamsOf<"read_history_page">) {
    return parseHistoryPageResult(await this.send({ request: "read_history_page", params }));
  }

  async sessionLiveStatus(session_ids: string[]) {
    return parseSessionLiveStatusResult(
      await this.send({ request: "session_live_status", params: { session_ids } }),
    );
  }

  async archiveSession(session_id: string, cascade = false) {
    return parseAckResult(
      await this.send({ request: "archive_session", params: { session_id, cascade } }),
    );
  }

  async unarchiveSession(session_id: string) {
    return parseAckResult(
      await this.send({ request: "unarchive_session", params: { session_id } }),
    );
  }

  async forkSession(params: ParamsOf<"fork_session">) {
    return this.send({ request: "fork_session", params });
  }

  async renameSession(session_id: string, title: string) {
    return parseAckResult(
      await this.send({ request: "rename_session", params: { session_id, title } }),
    );
  }

  async shareSession(session_id: string, shared: boolean) {
    return parseAckResult(
      await this.send({ request: "share_session", params: { session_id, shared } }),
    );
  }

  async deleteSession(session_id: string, cascade = false) {
    return parseAckResult(
      await this.send({ request: "delete_session", params: { session_id, cascade } }),
    );
  }

  async setActiveModel(params: ParamsOf<"set_active_model">) {
    return parseAckResult(await this.send({ request: "set_active_model", params }));
  }

  async setAgent(name: string) {
    return parseAckResult(await this.send({ request: "set_agent", params: { name } }));
  }

  async statsRollup(params: ParamsOf<"stats_rollup">) {
    return this.send({ request: "stats_rollup", params });
  }

  async resumePausedWork(session_id: string) {
    return parseAckResult(
      await this.send({ request: "resume_paused_work", params: { session_id } }),
    );
  }

  async cancelPausedWork(session_id: string) {
    return parseAckResult(
      await this.send({ request: "cancel_paused_work", params: { session_id } }),
    );
  }

  async listFiles(project_root: string, path: string, show_hidden = false) {
    return parseFsListResult(
      await this.send({ request: "fs_list", params: { project_root, path, show_hidden } }),
    );
  }

  async statFile(project_root: string, path: string) {
    return parseFsStatResult(
      await this.send({ request: "fs_stat", params: { project_root, path } }),
    );
  }

  async readFile(project_root: string, path: string, base64 = false) {
    return parseFsReadResult(
      await this.send({ request: "fs_read", params: { project_root, path, base64 } }),
    );
  }

  async writeFile(project_root: string, path: string, content: string, base_hash?: string) {
    return parseFsWriteResult(
      await this.send({ request: "fs_write", params: { project_root, path, content, base_hash } }),
    );
  }

  async createDirectory(project_root: string, path: string) {
    return parseAckResult(
      await this.send({ request: "fs_create_dir", params: { project_root, path } }),
    );
  }

  async renamePath(project_root: string, from_path: string, to_path: string) {
    return parseAckResult(
      await this.send({ request: "fs_rename", params: { project_root, from_path, to_path } }),
    );
  }

  async deletePath(project_root: string, path: string) {
    return parseAckResult(
      await this.send({ request: "fs_delete", params: { project_root, path } }),
    );
  }

  async gitStatus(project_root: string) {
    return parseGitStatusResult(
      await this.send({ request: "git_status", params: { project_root } }),
    );
  }

  async gitDiffFile(project_root: string, path: string) {
    return parseGitDiffFileResult(
      await this.send({ request: "git_diff_file", params: { project_root, path } }),
    );
  }

  private send(request: ClientRequest) {
    if (this.ws?.readyState !== 1) {
      return Promise.reject(new Error("Instance connection is not open."));
    }
    const id = nextRequestId();
    const envelope = createEnvelope(id, request);
    const promise = new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      globalThis.setTimeout(() => {
        if (!this.pending.delete(id)) return;
        reject(new Error("Request timed out."));
      }, 30_000);
    });
    this.ws.send(
      JSON.stringify({
        v: RELAY_ENVELOPE_VERSION,
        channelId: this.channelId,
        payload: envelope,
      }),
    );
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
    if (!message.success) {
      warn("failed to parse daemon payload", message.error);
      return;
    }
    if (message.data.kind === "evt") {
      if ("__unknown" in message.data && message.data.__unknown) {
        warn(`unknown daemon event kind: ${message.data.event}`, message.data);
      }
      this.options.onEvent?.(message.data);
      return;
    }
    if (message.data.kind === "res") {
      const pending = this.pending.get(message.data.id);
      if (!pending) return;
      this.pending.delete(message.data.id);
      pending.resolve(message.data.data);
      return;
    }

    if (!message.data.id) {
      warn(`out-of-band daemon error: ${message.data.error.code}`, message.data.error);
      return;
    }
    const pending = this.pending.get(message.data.id);
    if (!pending) return;
    this.pending.delete(message.data.id);
    pending.reject(
      new RemoteSessionError(
        message.data.error.message,
        message.data.error.code,
        message.data.error,
      ),
    );
  }
}
