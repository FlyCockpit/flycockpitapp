import {
  TERMINAL_PROTOCOL_VERSION,
  type TerminalClientPayload,
  type TerminalDaemonPayload,
  terminalDaemonPayloadSchema,
} from "@flycockpit/relay-protocol/terminal";

export type TerminalClientStatus = "idle" | "connecting" | "open" | "reattachable" | "closed";

export type TerminalClientEvents = {
  status: (status: TerminalClientStatus) => void;
  opened: (meta: { terminalId: string; viewerCount: number; recording: boolean }) => void;
  output: (data: string) => void;
  clipboard: (text: string) => void;
  attachmentProgress: (progress: {
    uploadId: string;
    receivedBytes: number;
    totalBytes: number;
  }) => void;
  error: (error: { code: string; message?: string }) => void;
};

type Listener<K extends keyof TerminalClientEvents> = TerminalClientEvents[K];
type AnyListener = (...args: unknown[]) => void;

type TerminalClientOptions = {
  relayUrl: string;
  token: string;
  channelId: string;
  cwd?: string;
  cols: number;
  rows: number;
  terminalId?: string;
};

const CHUNK_BYTES = 48 * 1024;

export class TerminalClient {
  private ws: WebSocket | null = null;
  private listeners = new Map<keyof TerminalClientEvents, Set<AnyListener>>();
  private terminalId: string | null = null;
  private closedByUser = false;

  constructor(private readonly options: TerminalClientOptions) {
    this.terminalId = options.terminalId ?? null;
  }

  on<K extends keyof TerminalClientEvents>(event: K, listener: Listener<K>): () => void {
    const set = this.listeners.get(event) ?? new Set<AnyListener>();
    this.listeners.set(event, set);
    const wrapped = listener as unknown as AnyListener;
    set.add(wrapped);
    return () => set.delete(wrapped);
  }

  connect() {
    if (this.ws) return;
    this.emit("status", "connecting");
    const ws = new WebSocket(clientRelayUrl(this.options.relayUrl, this.options.token));
    this.ws = ws;

    ws.addEventListener("open", () => {
      if (this.terminalId) {
        this.sendPayload({
          type: "terminal.attach",
          v: TERMINAL_PROTOCOL_VERSION,
          terminalId: this.terminalId,
          cols: this.options.cols,
          rows: this.options.rows,
        });
      } else {
        this.sendPayload({
          type: "terminal.open",
          v: TERMINAL_PROTOCOL_VERSION,
          cwd: this.options.cwd,
          cols: this.options.cols,
          rows: this.options.rows,
        });
      }
    });

    ws.addEventListener("message", (event) => {
      this.handleMessage(event.data);
    });

    ws.addEventListener("close", () => {
      this.ws = null;
      this.emit(
        "status",
        this.closedByUser ? "closed" : this.terminalId ? "reattachable" : "closed",
      );
    });

    ws.addEventListener("error", () => {
      this.emit("error", { code: "connection_failed" });
    });
  }

  input(data: string) {
    if (!data) return;
    this.sendPayload({ type: "terminal.input", v: TERMINAL_PROTOCOL_VERSION, data });
  }

  resize(cols: number, rows: number) {
    this.sendPayload({ type: "terminal.resize", v: TERMINAL_PROTOCOL_VERSION, cols, rows });
  }

  close() {
    this.closedByUser = true;
    this.sendPayload({ type: "terminal.close", v: TERMINAL_PROTOCOL_VERSION });
    this.ws?.close();
    this.ws = null;
    this.emit("status", "closed");
  }

  async uploadImage(file: File, onProgress?: (sentBytes: number, totalBytes: number) => void) {
    const uploadId = crypto.randomUUID();
    const buffer = new Uint8Array(await file.arrayBuffer());
    let offset = 0;
    while (offset < buffer.byteLength) {
      const end = Math.min(offset + CHUNK_BYTES, buffer.byteLength);
      const chunk = buffer.slice(offset, end);
      this.sendPayload({
        type: "terminal.attachment_chunk",
        v: TERMINAL_PROTOCOL_VERSION,
        uploadId,
        name: file.name || "pasted-image.png",
        mimeType: file.type || "application/octet-stream",
        size: buffer.byteLength,
        offset,
        dataBase64: uint8ToBase64(chunk),
        final: end === buffer.byteLength,
      });
      offset = end;
      onProgress?.(offset, buffer.byteLength);
    }
  }

  private sendPayload(payload: TerminalClientPayload) {
    if (this.ws?.readyState !== WebSocket.OPEN) return;
    this.ws.send(JSON.stringify({ v: 1, channelId: this.options.channelId, payload }));
  }

  private handleMessage(raw: unknown) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(String(raw));
    } catch {
      this.emit("error", { code: "bad_frame" });
      return;
    }
    if (isSystemFrame(parsed)) {
      this.emit("error", { code: parsed.code });
      return;
    }
    if (!isRelayPayloadFrame(parsed)) return;
    let payload: TerminalDaemonPayload;
    try {
      payload = terminalDaemonPayloadSchema.parse(parsed.payload);
    } catch {
      this.emit("error", { code: "bad_frame" });
      return;
    }
    if (payload.type === "terminal.opened") {
      this.terminalId = payload.terminalId;
      this.emit("status", "open");
      this.emit("opened", {
        terminalId: payload.terminalId,
        viewerCount: payload.viewerCount,
        recording: payload.recording,
      });
      return;
    }
    if (payload.type === "terminal.output") this.emit("output", payload.data);
    if (payload.type === "terminal.clipboard") this.emit("clipboard", payload.text);
    if (payload.type === "terminal.attachment_progress") this.emit("attachmentProgress", payload);
    if (payload.type === "terminal.error") this.emit("error", payload);
  }

  private emit<K extends keyof TerminalClientEvents>(
    event: K,
    ...args: Parameters<TerminalClientEvents[K]>
  ) {
    const set = this.listeners.get(event);
    for (const listener of set ?? []) listener(...args);
  }
}

function clientRelayUrl(relayUrl: string, token: string) {
  const url = new URL(relayUrl, window.location.origin);
  url.pathname = url.pathname.replace(/\/$/, "") + "/client";
  url.searchParams.set("token", token);
  return url.toString();
}

function isRelayPayloadFrame(value: unknown): value is { payload: unknown } {
  return typeof value === "object" && value !== null && "payload" in value;
}

function isSystemFrame(value: unknown): value is { type: "system"; code: string } {
  return (
    typeof value === "object" &&
    value !== null &&
    "type" in value &&
    (value as { type: unknown }).type === "system" &&
    "code" in value &&
    typeof (value as { code: unknown }).code === "string"
  );
}

function uint8ToBase64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
