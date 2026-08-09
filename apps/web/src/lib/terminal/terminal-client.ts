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
    operationId: string;
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
  private binding: { id: string; epoch: number } | null = null;
  private ingressWaiters = new Map<
    string,
    (state: { state: "prepared" | "committed"; nextOffset: number }) => void
  >();
  private pendingIngress: {
    operationId: string;
    mediaType: "image/png" | "image/jpeg" | "image/gif" | "image/webp";
    size: number;
    sha256: string;
  } | null = null;
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
    if (!data || !this.binding) return;
    this.sendPayload({
      type: "terminal.input",
      v: TERMINAL_PROTOCOL_VERSION,
      data,
      bindingId: this.binding.id,
      bindingEpoch: this.binding.epoch,
    });
  }

  resize(cols: number, rows: number) {
    if (!this.binding) return;
    this.sendPayload({
      type: "terminal.resize",
      v: TERMINAL_PROTOCOL_VERSION,
      cols,
      rows,
      bindingId: this.binding.id,
      bindingEpoch: this.binding.epoch,
    });
  }

  close() {
    this.closedByUser = true;
    if (this.binding)
      this.sendPayload({
        type: "terminal.close",
        v: TERMINAL_PROTOCOL_VERSION,
        bindingId: this.binding.id,
        bindingEpoch: this.binding.epoch,
      });
    this.ws?.close();
    this.ws = null;
    this.emit("status", "closed");
  }

  async uploadImage(file: File, onProgress?: (sentBytes: number, totalBytes: number) => void) {
    if (!this.binding) throw new Error("terminal binding is unavailable");
    if (
      !(
        file.type === "image/png" ||
        file.type === "image/jpeg" ||
        file.type === "image/gif" ||
        file.type === "image/webp"
      )
    ) {
      throw new Error("unsupported terminal image type");
    }
    const operationId = crypto.randomUUID();
    const buffer = new Uint8Array(await file.arrayBuffer());
    if (buffer.byteLength < 1 || buffer.byteLength > 10 * 1024 * 1024) {
      throw new Error("terminal image size is outside the allowed range");
    }
    const sha256 = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", buffer)));
    const mediaType = file.type as "image/png" | "image/jpeg" | "image/gif" | "image/webp";
    this.pendingIngress = { operationId, mediaType, size: buffer.byteLength, sha256 };
    const identity = () => {
      if (!this.binding) throw new Error("terminal binding is unavailable");
      return { operationId, bindingId: this.binding.id, bindingEpoch: this.binding.epoch };
    };
    let acknowledgement = this.waitForIngress(operationId);
    this.sendPayload({
      type: "terminal.ingress_begin",
      v: TERMINAL_PROTOCOL_VERSION,
      ...identity(),
      mediaType,
      size: buffer.byteLength,
      sha256,
    });
    let offset = (await acknowledgement).nextOffset;
    while (offset < buffer.byteLength) {
      const end = Math.min(offset + CHUNK_BYTES, buffer.byteLength);
      const chunk = buffer.slice(offset, end);
      acknowledgement = this.waitForIngress(operationId);
      this.sendPayload({
        type: "terminal.ingress_chunk",
        v: TERMINAL_PROTOCOL_VERSION,
        ...identity(),
        offset,
        dataBase64: uint8ToBase64(chunk),
      });
      offset = (await acknowledgement).nextOffset;
      onProgress?.(offset, buffer.byteLength);
    }
    acknowledgement = this.waitForIngress(operationId);
    this.sendPayload({
      type: "terminal.ingress_finish",
      v: TERMINAL_PROTOCOL_VERSION,
      ...identity(),
    });
    const receipt = await acknowledgement;
    if (receipt.state !== "committed") throw new Error("terminal ingress did not commit");
    this.pendingIngress = null;
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
      this.binding = { id: payload.bindingId, epoch: payload.bindingEpoch };
      if (this.pendingIngress) {
        this.sendPayload({
          type: "terminal.ingress_begin",
          v: TERMINAL_PROTOCOL_VERSION,
          operationId: this.pendingIngress.operationId,
          bindingId: this.binding.id,
          bindingEpoch: this.binding.epoch,
          mediaType: this.pendingIngress.mediaType,
          size: this.pendingIngress.size,
          sha256: this.pendingIngress.sha256,
        });
      }
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
    if (payload.type === "terminal.ingress_state") {
      this.ingressWaiters.get(payload.operationId)?.(payload);
      this.ingressWaiters.delete(payload.operationId);
      this.emit("attachmentProgress", {
        operationId: payload.operationId,
        receivedBytes: payload.nextOffset,
        totalBytes:
          this.pendingIngress?.operationId === payload.operationId
            ? this.pendingIngress.size
            : payload.nextOffset,
      });
    }
    if (payload.type === "terminal.error") this.emit("error", payload);
  }

  private emit<K extends keyof TerminalClientEvents>(
    event: K,
    ...args: Parameters<TerminalClientEvents[K]>
  ) {
    const set = this.listeners.get(event);
    for (const listener of set ?? []) listener(...args);
  }

  private waitForIngress(operationId: string) {
    return new Promise<{ state: "prepared" | "committed"; nextOffset: number }>(
      (resolve, reject) => {
        const timer = window.setTimeout(() => {
          this.ingressWaiters.delete(operationId);
          reject(new Error("terminal ingress acknowledgement timed out"));
        }, 30_000);
        this.ingressWaiters.set(operationId, (state) => {
          window.clearTimeout(timer);
          resolve(state);
        });
      },
    );
  }
}

function bytesToHex(bytes: Uint8Array) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
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
