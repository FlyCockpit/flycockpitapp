import {
  type DaemonClientRelayFrame,
  daemonClientRelayFrameSchema,
  RELAY_ENVELOPE_VERSION,
} from "@flycockpit/relay-protocol/envelopes";
import {
  type ClientRequest,
  createClientSubmissionId,
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
  parseUserMessageQueuedResult,
  type ResolveResponse,
  serverMessageSchema,
} from ".";
import { encodeProtocolIdBase64Url, formatCanonicalU64DecimalString } from "./remote-protocol-id";
import { bytesToHex, sha256 } from "./remote-transport-lanes";

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
  epoch: number;
  expectedResponse?: string;
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
};

type ParamsOf<Name extends ClientRequest["request"]> = Extract<
  ClientRequest,
  { request: Name }
>["params"];

export type SendUserMessageParams = ParamsOf<"send_user_message">;

const INLINE_USER_MESSAGE_BYTES = 64 * 1024;
const MAX_BULK_USER_MESSAGE_BYTES = 8 * 1024 * 1024;
// Rust accepts base64 chunks up to 256KiB; this raw size encodes exactly to
// that bound and leaves the relay application frame well below 524360 bytes.
const BULK_USER_MESSAGE_CHUNK_BYTES = 3 * ((256 * 1024) / 4);

function randomBulkTransferId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  if (bytes.every((byte) => byte === 0)) bytes[0] = 1;
  return encodeProtocolIdBase64Url(bytes);
}

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]!);
  }
  return globalThis.btoa(binary);
}

function isExactBulkChunkAcceptance(
  value: unknown,
  nextChunkIndex: number,
  receivedBytes: number,
  complete: boolean,
): boolean {
  if (!value || typeof value !== "object") return false;
  const acknowledgement = value as Record<string, unknown>;
  return (
    acknowledgement.next_chunk_index === nextChunkIndex &&
    acknowledgement.received_bytes === String(receivedBytes) &&
    acknowledgement.complete === complete
  );
}

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

export function isRemoteSessionError(error: unknown): error is RemoteSessionError {
  return error instanceof RemoteSessionError;
}

/**
 * Whether a failed `send_user_message` may have been accepted before the
 * failure became observable. Retrying these failures with the same complete
 * submission is safe because the daemon deduplicates `client_submission_id`.
 *
 * Keep this in lockstep with the TUI dispatcher: internal failures can happen
 * while acceptance is being reconciled, shutdown is conservatively retryable
 * across a daemon lifecycle transition, and transport failures have no
 * authoritative response at all.
 */
export function isAmbiguousUserMessageSendError(error: unknown): boolean {
  if (!isRemoteSessionError(error)) return true;
  return (
    error.code === "internal" ||
    error.code === "shutdown" ||
    error.code === "storage_full" ||
    error.code === "storage_memory" ||
    error.code === "storage_read_only" ||
    error.code === "storage_io" ||
    error.code === "storage_corrupt"
  );
}

export function shouldRetainUserMessageSubmission(error: unknown): boolean {
  return (
    isAmbiguousUserMessageSendError(error) ||
    (isRemoteSessionError(error) && error.code === "user_message_not_accepted")
  );
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
  private connectionEpoch = 0;
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
    const epoch = ++this.connectionEpoch;
    this.rejectPendingOutsideEpoch(epoch, new Error("Instance connection was replaced."));
    const ws = new WebSocketImpl(
      remoteSessionClientRelayUrl(this.options.relayUrl, this.options.token, this.options.baseUrl),
    );
    this.ws = ws;
    ws.addEventListener("open", () => {
      if (!this.isCurrentSocket(ws, epoch)) return;
      this.options.onStatus?.("connected");
    });
    ws.addEventListener("close", () => {
      this.rejectPendingEpoch(epoch, new Error("Instance connection closed."));
      if (!this.isCurrentSocket(ws, epoch)) return;
      this.ws = null;
      this.options.onStatus?.("offline");
    });
    ws.addEventListener("error", () => {
      if (!this.isCurrentSocket(ws, epoch)) return;
      this.options.onStatus?.("error", "Relay connection failed.");
    });
    ws.addEventListener("message", (event) => {
      if (!this.isCurrentSocket(ws, epoch)) return;
      this.handleMessage(messageData(event), epoch);
    });
  }

  close() {
    const ws = this.ws;
    if (!ws) return;
    const epoch = this.connectionEpoch;
    this.ws = null;
    this.connectionEpoch += 1;
    this.rejectPendingEpoch(epoch, new Error("Instance connection closed."));
    ws.close();
  }

  async attach(params: ParamsOf<"attach"> = {}) {
    return parseAttachResult(await this.send({ request: "attach", params }));
  }

  async sendUserMessage(params: SendUserMessageParams | string) {
    const requestParams =
      typeof params === "string"
        ? { client_submission_id: createClientSubmissionId(), text: params }
        : params;
    const encoder = new TextEncoder();
    const textBytes = encoder.encode(requestParams.text);
    const displayBytes =
      requestParams.display_text === undefined
        ? undefined
        : encoder.encode(requestParams.display_text);
    if (textBytes.length > MAX_BULK_USER_MESSAGE_BYTES) {
      throw new RemoteSessionError(
        "message text exceeds the 8 MiB FCM2 limit",
        "bad_request",
        undefined,
      );
    }
    if ((displayBytes?.length ?? 0) > MAX_BULK_USER_MESSAGE_BYTES) {
      throw new RemoteSessionError(
        "message display text exceeds the 8 MiB FCM2 limit",
        "bad_request",
        undefined,
      );
    }
    // One large FCM2 field is enough to overflow the remote application frame.
    // Two individually inline-sized fields can do it too after JSON escaping,
    // so stage the display form once their combined source bytes cross the
    // inline boundary. The request remains a small pair of typed references.
    const stageDisplay =
      displayBytes !== undefined &&
      displayBytes.length > 0 &&
      (displayBytes.length > INLINE_USER_MESSAGE_BYTES ||
        textBytes.length + displayBytes.length > INLINE_USER_MESSAGE_BYTES);
    const useBulk = textBytes.length > INLINE_USER_MESSAGE_BYTES || stageDisplay;
    if (useBulk) {
      if (textBytes.length === 0) {
        throw new RemoteSessionError(
          "bulk user messages require non-empty text",
          "bad_request",
          undefined,
        );
      }
      const transfer = await this.stageOpaqueUserMessageTransfer(textBytes);
      const display_transfer =
        displayBytes !== undefined && stageDisplay
          ? await this.stageOpaqueUserMessageTransfer(displayBytes)
          : undefined;
      const { text: _text, display_text, ...metadata } = requestParams;
      const result = parseUserMessageQueuedResult(
        await this.send({
          request: "send_user_message_bulk",
          params: {
            ...metadata,
            transfer,
            ...(display_transfer ? { display_transfer } : display_text ? { display_text } : {}),
          },
        }),
      );
      if (result.item.id !== requestParams.client_submission_id) {
        throw new Error("Daemon queued a different client submission.");
      }
      return result;
    }
    const result = parseUserMessageQueuedResult(
      await this.send({ request: "send_user_message", params: requestParams }),
    );
    if (result.item.id !== requestParams.client_submission_id) {
      throw new Error("Daemon queued a different client submission.");
    }
    return result;
  }

  private async stageOpaqueUserMessageTransfer(bytes: Uint8Array) {
    const transfer = {
      transfer_id: randomBulkTransferId(),
      total_length: formatCanonicalU64DecimalString(BigInt(bytes.length)),
      sha256: bytesToHex(await sha256(bytes)),
      mime_class: "opaque" as const,
    };
    for (
      let offset = 0, chunkIndex = 0;
      offset < bytes.length;
      offset += BULK_USER_MESSAGE_CHUNK_BYTES, chunkIndex += 1
    ) {
      const chunk = bytes.slice(offset, offset + BULK_USER_MESSAGE_CHUNK_BYTES);
      const accepted = await this.send(
        {
          request: "write_bulk_transfer_chunk",
          params: {
            transfer,
            chunk_index: chunkIndex,
            data_base64: base64Encode(chunk),
          },
        },
        "bulk_transfer_chunk_accepted",
      );
      const expectedReceived = offset + chunk.length;
      if (
        !isExactBulkChunkAcceptance(
          accepted,
          chunkIndex + 1,
          expectedReceived,
          expectedReceived === bytes.length,
        )
      ) {
        throw new Error("Daemon returned an invalid bulk-transfer chunk acknowledgement.");
      }
    }
    return transfer;
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

  async deleteSession(session_id: string) {
    return parseAckResult(await this.send({ request: "delete_session", params: { session_id } }));
  }

  async setActiveModel(params: ParamsOf<"set_active_model">) {
    return parseAckResult(await this.send({ request: "set_active_model", params }));
  }

  async setModelFavorite(params: ParamsOf<"set_model_favorite">) {
    return parseAckResult(await this.send({ request: "set_model_favorite", params }));
  }

  /// Replace (or clear) the effective default model for **new** sessions in
  /// the attached client's configuration context. Local-owner-only, and it
  /// never changes the model of a running session. The ack only means the
  /// request was accepted; the verified outcome arrives as a correlated
  /// `default_model_update_result` event carrying `default_update_id`.
  async setDefaultModel(params: ParamsOf<"set_default_model">) {
    return parseAckResult(await this.send({ request: "set_default_model", params }));
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

  private send(request: ClientRequest, expectedResponse?: string) {
    const ws = this.ws;
    const epoch = this.connectionEpoch;
    if (ws?.readyState !== 1) {
      return Promise.reject(new Error("Instance connection is not open."));
    }
    const id = nextRequestId();
    const envelope = createEnvelope(id, request);
    const promise = new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { epoch, expectedResponse, resolve, reject });
      globalThis.setTimeout(() => {
        const pending = this.pending.get(id);
        if (!pending || pending.epoch !== epoch) return;
        this.pending.delete(id);
        reject(new Error("Request timed out."));
      }, 30_000);
    });
    try {
      ws.send(
        JSON.stringify({
          v: RELAY_ENVELOPE_VERSION,
          channelId: this.channelId,
          payload: envelope,
        }),
      );
    } catch (error) {
      const pending = this.pending.get(id);
      if (pending?.epoch === epoch) {
        this.pending.delete(id);
        pending.reject(error instanceof Error ? error : new Error(String(error)));
      }
    }
    return promise;
  }

  private isCurrentSocket(ws: RemoteSessionWebSocket, epoch: number) {
    return this.ws === ws && this.connectionEpoch === epoch;
  }

  private rejectPendingEpoch(epoch: number, error: Error) {
    for (const [id, pending] of this.pending) {
      if (pending.epoch !== epoch) continue;
      this.pending.delete(id);
      pending.reject(error);
    }
  }

  private rejectPendingOutsideEpoch(epoch: number, error: Error) {
    for (const [id, pending] of this.pending) {
      if (pending.epoch === epoch) continue;
      this.pending.delete(id);
      pending.reject(error);
    }
  }

  private handleMessage(raw: unknown, epoch: number) {
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
      if (!pending || pending.epoch !== epoch) return;
      this.pending.delete(message.data.id);
      if (pending.expectedResponse && message.data.response !== pending.expectedResponse) {
        pending.reject(new Error(`Unexpected daemon response: ${message.data.response}`));
        return;
      }
      pending.resolve(message.data.data);
      return;
    }

    if (!message.data.id) {
      warn(`out-of-band daemon error: ${message.data.error.code}`, message.data.error);
      return;
    }
    const pending = this.pending.get(message.data.id);
    if (!pending || pending.epoch !== epoch) return;
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
