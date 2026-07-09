import {
  type AttachResult,
  type ClientRequest,
  createEnvelope,
  parseAckResult,
  parseAttachResult,
  parseFsListResult,
  parseFsReadResult,
  parseFsWriteResult,
  parseGitDiffFileResult,
  parseGitStatusResult,
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
  const url = new URL(relayUrl, window.location.origin);
  if (!url.pathname.endsWith("/client")) {
    url.pathname = url.pathname.replace(/\/$/, "") + "/client";
  }
  url.searchParams.set("token", token);
  return url.toString();
}

export class RemoteSessionClient {
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
    ) {
      return;
    }
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

  async createSession(input: {
    projectRoot: string;
    title?: string;
    agent?: string;
    model?: string;
  }) {
    return parseAttachResult(await this.send({ type: "create_session", ...input }));
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

  async renameSession(sessionId: string, title: string) {
    return this.send({ type: "rename_session", sessionId, title });
  }

  async archiveSession(sessionId: string, archived: boolean) {
    return this.send({ type: "archive_session", sessionId, archived });
  }

  async shareSession(sessionId: string, shared: boolean) {
    return parseAckResult(await this.send({ type: "share_session", sessionId, shared }));
  }

  async listFiles(projectRoot: string, path: string, showHidden: boolean) {
    return parseFsListResult(await this.send({ type: "fs_list", projectRoot, path, showHidden }));
  }

  async readFile(projectRoot: string, path: string) {
    return parseFsReadResult(await this.send({ type: "fs_read", projectRoot, path }));
  }

  async writeFile(projectRoot: string, path: string, content: string, baseHash?: string) {
    return parseFsWriteResult(
      await this.send({ type: "fs_write", projectRoot, path, content, baseHash }),
    );
  }

  async createDirectory(projectRoot: string, path: string) {
    return parseAckResult(await this.send({ type: "fs_create_dir", projectRoot, path }));
  }

  async renamePath(projectRoot: string, fromPath: string, toPath: string) {
    return parseAckResult(await this.send({ type: "fs_rename", projectRoot, fromPath, toPath }));
  }

  async deletePath(projectRoot: string, path: string) {
    return parseAckResult(await this.send({ type: "fs_delete", projectRoot, path }));
  }

  async gitStatus(projectRoot: string) {
    return parseGitStatusResult(await this.send({ type: "git_status", projectRoot }));
  }

  async gitDiffFile(projectRoot: string, path: string) {
    return parseGitDiffFileResult(await this.send({ type: "git_diff_file", projectRoot, path }));
  }

  async forkSession(sessionId: string) {
    return this.send({ type: "fork_session", sessionId });
  }

  private send(request: ClientRequest) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error("Instance connection is not open."));
    }
    const id = "web-" + ++this.requestSeq;
    const envelope = createEnvelope(id, request);
    const promise = new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      window.setTimeout(() => {
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
