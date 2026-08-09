import {
  TERMINAL_PROTOCOL_VERSION,
  type TerminalClientPayload,
  type TerminalDaemonPayload,
  terminalDaemonPayloadSchema,
} from "@flycockpit/relay-protocol/terminal";
import {
  TerminalFileIngressController,
  type TerminalIngressIdentity,
  type TerminalIngressReceipt,
  type TerminalIngressRequest,
  type TerminalIngressTransport,
} from "./terminal-file-ingress";

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

export class TerminalClient {
  private ws: WebSocket | null = null;
  private listeners = new Map<keyof TerminalClientEvents, Set<AnyListener>>();
  private terminalId: string | null = null;
  private binding: { id: string; epoch: number } | null = null;
  private ingressWaiters = new Map<
    string,
    {
      resolve: (state: TerminalIngressReceipt) => void;
      reject: (error: Error) => void;
      removeAbort: () => void;
    }
  >();
  private terminalGeneration: number | null = null;
  private readonly ingress: TerminalFileIngressController;
  private closedByUser = false;

  constructor(private readonly options: TerminalClientOptions) {
    this.terminalId = options.terminalId ?? null;
    this.ingress = new TerminalFileIngressController(
      this.ingressTransport(),
      () => this.ingressIdentity(),
      undefined,
      (snapshot) => {
        if (!snapshot || snapshot.phase === "Queued") return;
        this.emit("attachmentProgress", {
          operationId: snapshot.operationId,
          receivedBytes: snapshot.nextOffset,
          totalBytes: snapshot.size,
        });
      },
    );
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
      if (this.closedByUser) {
        this.emit("status", "closed");
        return;
      }
      if (!this.terminalId) {
        this.emit("status", "closed");
        this.ingress.updateIdentity(null);
        return;
      }
      this.emit("status", "connecting");
      queueMicrotask(() => {
        if (!this.closedByUser && !this.ws) this.connect();
      });
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
    this.ingress.cancelAll();
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
    const remove = this.on("attachmentProgress", (progress) =>
      onProgress?.(progress.receivedBytes, progress.totalBytes),
    );
    try {
      const outcome = await this.ingress.enqueue(file);
      if (outcome.kind !== "committed") throw new Error(outcome.code);
    } finally {
      remove();
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
      this.binding = { id: payload.bindingId, epoch: payload.bindingEpoch };
      this.terminalGeneration = payload.terminalGeneration;
      this.ingress.updateIdentity(this.ingressIdentity());
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
      const waiter = this.ingressWaiters.get(payload.operationId);
      if (waiter) {
        waiter.removeAbort();
        waiter.resolve(payload);
      }
      this.ingressWaiters.delete(payload.operationId);
    }
    if (payload.type === "terminal.error") {
      for (const [operationId, waiter] of this.ingressWaiters) {
        waiter.removeAbort();
        waiter.reject(new Error(mapIngressHostError(payload.code)));
        this.ingressWaiters.delete(operationId);
      }
      this.emit("error", payload);
    }
  }

  private emit<K extends keyof TerminalClientEvents>(
    event: K,
    ...args: Parameters<TerminalClientEvents[K]>
  ) {
    const set = this.listeners.get(event);
    for (const listener of set ?? []) listener(...args);
  }

  private waitForIngress(operationId: string, signal: AbortSignal) {
    return new Promise<TerminalIngressReceipt>((resolve, reject) => {
      const abort = () => {
        if (this.ingressWaiters.get(operationId)?.reject !== reject) return;
        this.ingressWaiters.delete(operationId);
        reject(new DOMException("terminal ingress request cancelled", "AbortError"));
      };
      signal.addEventListener("abort", abort, { once: true });
      this.ingressWaiters.set(operationId, {
        resolve,
        reject,
        removeAbort: () => signal.removeEventListener("abort", abort),
      });
      if (signal.aborted) abort();
    });
  }

  private ingressIdentity(): TerminalIngressIdentity | null {
    if (!this.binding || !this.terminalId || !this.terminalGeneration) return null;
    return {
      clientInstanceId: this.options.channelId,
      sessionId: this.options.channelId,
      terminalId: this.terminalId,
      terminalGeneration: this.terminalGeneration,
      bindingId: this.binding.id,
      bindingEpoch: this.binding.epoch,
    };
  }

  private ingressTransport(): TerminalIngressTransport {
    const request = (
      request: TerminalIngressRequest,
      signal: AbortSignal,
      payload: TerminalClientPayload,
    ) => this.requestIngress(request.operationId, signal, payload);
    return {
      begin: (value, signal) =>
        request(value, signal, {
          type: "terminal.ingress_begin",
          v: TERMINAL_PROTOCOL_VERSION,
          operationId: value.operationId,
          bindingId: value.bindingId,
          bindingEpoch: value.bindingEpoch,
          mediaType: value.mediaType,
          size: value.size,
          sha256: value.sha256,
        }),
      chunk: (value, signal) =>
        request(value, signal, {
          type: "terminal.ingress_chunk",
          v: TERMINAL_PROTOCOL_VERSION,
          operationId: value.operationId,
          bindingId: value.bindingId,
          bindingEpoch: value.bindingEpoch,
          offset: value.offset,
          dataBase64: value.dataBase64,
        }),
      finish: (value, signal) => request(value, signal, ingressIdentityPayload("finish", value)),
      status: (value, signal) => request(value, signal, ingressIdentityPayload("status", value)),
      abort: (value, signal) => request(value, signal, ingressIdentityPayload("abort", value)),
    };
  }

  private requestIngress(
    operationId: string,
    signal: AbortSignal,
    payload: TerminalClientPayload,
  ): Promise<TerminalIngressReceipt> {
    const acknowledgement = this.waitForIngress(operationId, signal);
    this.sendPayload(payload);
    return acknowledgement;
  }
}

function ingressIdentityPayload(
  action: "finish" | "status" | "abort",
  value: TerminalIngressRequest,
): TerminalClientPayload {
  const payload = {
    type: `terminal.ingress_${action}`,
    v: TERMINAL_PROTOCOL_VERSION,
    operationId: value.operationId,
    bindingId: value.bindingId,
    bindingEpoch: value.bindingEpoch,
  };
  return payload as TerminalClientPayload;
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

function mapIngressHostError(code: string) {
  if (code === "offline" || code === "revoked" || code === "scope_denied") {
    return "TerminalUnavailable";
  }
  return "UploadFailed";
}
