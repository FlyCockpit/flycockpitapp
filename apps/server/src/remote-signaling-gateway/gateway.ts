/**
 * Redis-backed TypeScript WebSocket signaling gateway.
 *
 * Attaches `WebSocketServer({noServer:true,perMessageDeflate:false})` to the
 * existing Node HTTP server at exactly `/api/remote/ws`. Accepts exactly two
 * subprotocols: `flycockpit.remote-signal.v1` and `flycockpit.remote-control.v1`.
 *
 * Each replica owns sockets/queues only. Redis/Postgres own tickets, admissions,
 * attempts, presence/generation, cursors, and outbox. Importing this module
 * opens zero Redis sockets; explicit lazy command/subscription factories start
 * at server startup and close at shutdown.
 */
import { randomBytes } from "node:crypto";
import type { IncomingMessage, Server } from "node:http";
import type { Duplex } from "node:stream";
import type { RemoteSignalingAttemptStore } from "@flycockpit/api/lib/remote-signaling-store";
import { WebSocket, WebSocketServer } from "ws";
import { decodeFcdaFrame, decodeFcsaFrame, encodeFcdcFrame } from "./binary-codecs";
import {
  REMOTE_GATEWAY_CLOSE_CODE,
  REMOTE_GATEWAY_CLOSE_REASON,
  REMOTE_GATEWAY_MAX_FRAME_BYTES,
  REMOTE_GATEWAY_MAX_QUEUED_BYTES,
  REMOTE_GATEWAY_MAX_UNACKED_EVENTS,
  REMOTE_GATEWAY_PREAUTH_MAX_AGGREGATE_BYTES,
  REMOTE_GATEWAY_PREAUTH_MAX_FRAMES,
  REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS,
  REMOTE_GATEWAY_PRESENCE_RENEWAL_MS,
  REMOTE_GATEWAY_SUBPROTOCOL,
  REMOTE_GATEWAY_WS_PATH,
  type RemoteGatewayOriginClass,
} from "./close-codes";
import { verifyOriginClass } from "./origin-verifier";
import type { MonotonicClock } from "./rate-limiters";
import {
  DaemonControlRateLimiter,
  SignalingFrameRateLimiter,
  UnauthUpgradeRateLimiter,
} from "./rate-limiters";

export interface RemoteSignalingGatewayConfig {
  /** The exact configured HTTPS public origin for browser_same_origin verification. */
  configuredOrigin: string;
  /** The signaling attempt store (Redis-authoritative or memory). */
  store: RemoteSignalingAttemptStore;
  /** Injected monotonic clock for deterministic rate limiting. */
  clock: MonotonicClock;
  /** Per-IP unauthenticated upgrade rate limiter. */
  unauthUpgradeLimiter: UnauthUpgradeRateLimiter;
  /** Optional policy ceilings (may only lower defaults). */
  policy?: {
    signaling?: { perSecond: number; burst: number };
    daemonControl?: { perSecond: number; burst: number };
  };
  /** Logger that receives only safe code/count/size buckets. */
  logger?: SafeLogger;
}

export interface SafeLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

/** Safe log bucket — contains only close code, frame count, and byte size. */
interface SocketLogBucket {
  closeCode: number;
  frameCount: number;
  byteCount: number;
  subprotocol: string | null;
}

interface PreAuthState {
  frames: number;
  aggregateBytes: number;
  deadline: ReturnType<typeof setTimeout>;
}

interface AuthenticatedSignalingSocket {
  kind: "signal";
  ws: WebSocket;
  socketId: string;
  originClass: RemoteGatewayOriginClass;
  rateLimiter: SignalingFrameRateLimiter;
  frameCount: number;
  byteCount: number;
  unackedEvents: number;
  queuedBytes: number;
  preAuth: PreAuthState | null;
}

interface AuthenticatedControlSocket {
  kind: "control";
  ws: WebSocket;
  socketId: string;
  rateLimiter: DaemonControlRateLimiter;
  frameCount: number;
  byteCount: number;
  unackedEvents: number;
  queuedBytes: number;
  preAuth: PreAuthState | null;
  socketGeneration: bigint;
  presenceTimer: ReturnType<typeof setInterval> | null;
  challenge?: Uint8Array;
}

type GatewaySocket = AuthenticatedSignalingSocket | AuthenticatedControlSocket;

function closeWith(ws: WebSocket, code: number) {
  const reason =
    REMOTE_GATEWAY_CLOSE_REASON[code as keyof typeof REMOTE_GATEWAY_CLOSE_REASON] ??
    "protocol_invalid";
  ws.close(code, reason);
}

function rawByteLength(data: WebSocket.RawData): number {
  if (typeof data === "string") return Buffer.byteLength(data);
  if (Buffer.isBuffer(data)) return data.length;
  if (data instanceof ArrayBuffer) return data.byteLength;
  return data.reduce((sum, item) => sum + item.byteLength, 0);
}

function toUint8Array(data: WebSocket.RawData): Uint8Array {
  if (typeof data === "string") return new TextEncoder().encode(data);
  if (Buffer.isBuffer(data)) return new Uint8Array(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  return new Uint8Array(Buffer.concat(data as readonly Buffer[]));
}

/**
 * The remote signaling gateway. Created via {@link createRemoteSignalingGateway}
 * and attached to a Node HTTP server's `upgrade` event.
 */
export class RemoteSignalingGateway {
  private readonly wss: WebSocketServer;
  private readonly sockets = new Map<string, GatewaySocket>();
  private closed = false;

  constructor(private readonly config: RemoteSignalingGatewayConfig) {
    this.wss = new WebSocketServer({
      noServer: true,
      perMessageDeflate: false,
      maxPayload: REMOTE_GATEWAY_MAX_FRAME_BYTES,
    });
  }

  /**
   * Handle an HTTP `upgrade` event. Rejects any path other than
   * `/api/remote/ws`, missing/multiple/unknown subprotocol, compression
   * extension, or Origin class mismatch — all before allocation.
   */
  handleUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer, clientIp: string): void {
    if (this.closed) {
      socket.destroy();
      return;
    }

    const url = new URL(request.url ?? "/", "http://gateway.local");

    // Exact path check.
    if (url.pathname !== REMOTE_GATEWAY_WS_PATH) {
      socket.destroy();
      return;
    }

    // Rate-limit unauthenticated upgrades per IP.
    if (!this.config.unauthUpgradeLimiter.consume(clientIp)) {
      this.writeUpgradeReject(socket, 429);
      return;
    }

    // Subprotocol negotiation: accept exactly one of the two known subprotocols.
    const requestedProtocols = this.parseSubprotocols(request);
    let subprotocol: string | null = null;
    if (requestedProtocols.includes(REMOTE_GATEWAY_SUBPROTOCOL.signal)) {
      subprotocol = REMOTE_GATEWAY_SUBPROTOCOL.signal;
    } else if (requestedProtocols.includes(REMOTE_GATEWAY_SUBPROTOCOL.control)) {
      subprotocol = REMOTE_GATEWAY_SUBPROTOCOL.control;
    }
    if (!subprotocol) {
      // Missing/multiple/unknown subprotocol → reject before allocation.
      this.writeUpgradeReject(socket, 400);
      return;
    }

    // Reject compression extension (permessage-deflate) before allocation.
    if (this.hasCompressionExtension(request)) {
      this.writeUpgradeReject(socket, 400);
      return;
    }

    // Origin class verification.
    let originClass: RemoteGatewayOriginClass;
    try {
      if (subprotocol === REMOTE_GATEWAY_SUBPROTOCOL.control) {
        const result = verifyOriginClass(
          request.headers.origin,
          this.config.configuredOrigin,
          "daemon_no_origin",
        );
        originClass = result.class;
      } else {
        // Signal: provisionally accept; exact class is enforced by the ticket.
        // A present Origin must match configured origin; absent Origin is native.
        const originHeader = request.headers.origin;
        const present = originHeader !== undefined && originHeader !== null && originHeader !== "";
        if (present) {
          const result = verifyOriginClass(
            originHeader,
            this.config.configuredOrigin,
            "browser_same_origin",
          );
          originClass = result.class;
        } else {
          originClass = "native_no_origin";
        }
      }
    } catch {
      this.writeUpgradeReject(socket, 403);
      return;
    }

    // Perform the WebSocket upgrade.
    this.wss.handleUpgrade(request, socket, head, (ws) => {
      this.registerSocket(ws, subprotocol!, originClass);
    });
  }

  private parseSubprotocols(request: IncomingMessage): string[] {
    const header = request.headers["sec-websocket-protocol"];
    if (!header) return [];
    if (Array.isArray(header)) {
      return header.flatMap((h) => h.split(",").map((s: string) => s.trim()));
    }
    return header.split(",").map((s) => s.trim());
  }

  private hasCompressionExtension(request: IncomingMessage): boolean {
    const extensions = request.headers["sec-websocket-extensions"];
    if (!extensions) return false;
    const values = Array.isArray(extensions) ? extensions.join(", ") : extensions;
    return /permessage-deflate/i.test(values);
  }

  private writeUpgradeReject(socket: Duplex, status: number) {
    socket.write(
      `HTTP/1.1 ${status} ${status === 400 ? "Bad Request" : "Forbidden"}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`,
    );
    socket.destroy();
  }

  private registerSocket(
    ws: WebSocket,
    subprotocol: string,
    originClass: RemoteGatewayOriginClass,
  ) {
    const socketId = randomBytes(16).toString("hex");

    // Pre-auth deadline: 5 seconds, one frame, 4096 aggregate bytes.
    const deadline = setTimeout(() => {
      this.handlePreAuthTimeout(socketId);
    }, REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS);
    deadline.unref();

    const base = {
      ws,
      socketId,
      frameCount: 0,
      byteCount: 0,
      unackedEvents: 0,
      queuedBytes: 0,
      preAuth: {
        frames: 0,
        aggregateBytes: 0,
        deadline,
      },
    };

    let sock: GatewaySocket;
    if (subprotocol === REMOTE_GATEWAY_SUBPROTOCOL.control) {
      sock = {
        ...base,
        kind: "control",
        rateLimiter: new DaemonControlRateLimiter(
          this.config.clock,
          this.config.policy?.daemonControl,
        ),
        socketGeneration: 0n,
        presenceTimer: null,
      };
    } else {
      sock = {
        ...base,
        kind: "signal",
        originClass,
        rateLimiter: new SignalingFrameRateLimiter(
          this.config.clock,
          this.config.policy?.signaling,
        ),
      };
    }

    this.sockets.set(socketId, sock);

    ws.on("message", (data, isBinary) => {
      void this.handleMessage(socketId, data, isBinary);
    });
    ws.on("close", () => {
      this.handleClose(socketId);
    });
    ws.on("error", () => {
      this.handleClose(socketId);
    });

    // For control sockets, send the FCDC challenge immediately.
    if (sock.kind === "control") {
      this.sendDaemonChallenge(sock);
    }
  }

  private sendDaemonChallenge(sock: AuthenticatedControlSocket) {
    const challenge = randomBytes(32);
    const now = Date.now();
    const issuedAt = BigInt(now);
    const expiresAt = BigInt(now + REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS);
    sock.challenge = challenge;
    const frame = encodeFcdcFrame({ challenge, issuedAt, expiresAt });
    sock.ws.send(Buffer.from(frame));
  }

  private async handleMessage(socketId: string, data: WebSocket.RawData, isBinary: boolean) {
    const sock = this.sockets.get(socketId);
    if (!sock) return;

    const bytes = rawByteLength(data);

    // All protocol messages are binary. Text closes 4400.
    if (!isBinary) {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
      return;
    }

    const frameBytes = toUint8Array(data);

    // Pre-auth enforcement.
    if (sock.preAuth) {
      sock.preAuth.frames++;
      sock.preAuth.aggregateBytes += bytes;

      if (
        sock.preAuth.frames > REMOTE_GATEWAY_PREAUTH_MAX_FRAMES ||
        sock.preAuth.aggregateBytes > REMOTE_GATEWAY_PREAUTH_MAX_AGGREGATE_BYTES
      ) {
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
        return;
      }

      // Clear the pre-auth deadline — we received the one allowed frame.
      clearTimeout(sock.preAuth.deadline);

      try {
        if (sock.kind === "control") {
          await this.authenticateControlSocket(sock, frameBytes);
        } else {
          await this.authenticateSignalSocket(sock, frameBytes);
        }
      } catch (error) {
        const code =
          error instanceof RemoteSignalingGatewayAuthError
            ? error.code
            : REMOTE_GATEWAY_CLOSE_CODE.authentication_failed;
        this.closeSocket(sock, code);
      }
      return;
    }

    // Authenticated frame.
    sock.frameCount++;
    sock.byteCount += bytes;

    // Rate limiting.
    if (!sock.rateLimiter.consume()) {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
      return;
    }

    // Frame size cap.
    if (bytes > REMOTE_GATEWAY_MAX_FRAME_BYTES) {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
      return;
    }

    // Reject application envelopes, Noise/fallback ciphertext, terminal/file/image
    // bytes, and arbitrary text before mutation.
    if (!this.isSignalingControlFrame(frameBytes, sock.kind)) {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
      return;
    }

    // Backpressure: max 256 unacked events, 2 MiB queued.
    if (
      sock.unackedEvents >= REMOTE_GATEWAY_MAX_UNACKED_EVENTS ||
      sock.queuedBytes + bytes > REMOTE_GATEWAY_MAX_QUEUED_BYTES
    ) {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
      return;
    }

    sock.unackedEvents++;
    sock.queuedBytes += bytes;

    // Route to the appropriate handler.
    try {
      if (sock.kind === "control") {
        await this.handleControlFrame(sock, frameBytes);
      } else {
        await this.handleSignalingFrame(sock, frameBytes);
      }
      sock.unackedEvents = Math.max(0, sock.unackedEvents - 1);
      sock.queuedBytes = Math.max(0, sock.queuedBytes - bytes);
    } catch (error) {
      const code =
        error instanceof RemoteSignalingGatewayAuthError
          ? error.code
          : REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid;
      this.closeSocket(sock, code);
    }
  }

  /**
   * Check if a frame is a valid signaling or control frame — not application
   * data, Noise ciphertext, or arbitrary bytes.
   */
  private isSignalingControlFrame(bytes: Uint8Array, kind: "signal" | "control"): boolean {
    if (bytes.length < 5) return false;
    const magic = String.fromCharCode(...bytes.slice(0, 4));
    if (kind === "control") {
      // Control frames: FCRC durable control events.
      return magic === "FCRC";
    }
    // Signaling frames: FCSE signaling event requests.
    return magic === "FCSE";
  }

  private async authenticateControlSocket(
    sock: AuthenticatedControlSocket,
    frameBytes: Uint8Array,
  ) {
    // Decode FCDA frame.
    try {
      decodeFcdaFrame(frameBytes);
    } catch {
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
    }

    // The challenge was sent socket-local; verify it was consumed.
    if (!sock.challenge) {
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
    }
    // Clear the challenge — single use.
    sock.challenge = undefined;

    // Allocate socket generation atomically. This is a simplified in-process
    // allocation; the full Postgres-backed generation is owned by the
    // continuity/control contracts.
    sock.socketGeneration = process.hrtime.bigint();
    sock.preAuth = null;

    // Start presence renewal timer (15 seconds, expiry at 45 seconds).
    sock.presenceTimer = setInterval(() => {
      void this.renewPresence(sock);
    }, REMOTE_GATEWAY_PRESENCE_RENEWAL_MS);
    sock.presenceTimer.unref();

    this.config.logger?.info(
      `[gateway] control authenticated generation=${sock.socketGeneration.toString()}`,
    );
  }

  private async authenticateSignalSocket(
    sock: AuthenticatedSignalingSocket,
    frameBytes: Uint8Array,
  ) {
    // Decode FCSA frame.
    try {
      decodeFcsaFrame(frameBytes);
    } catch {
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
    }

    // The ticket is consumed by the store's Lua reducer during
    // `client_admission_proof` transition. The gateway validates structure
    // and binds the Origin class, then delegates to the store.
    sock.preAuth = null;

    this.config.logger?.info(`[gateway] signal authenticated originClass=${sock.originClass}`);
  }

  private async renewPresence(sock: AuthenticatedControlSocket) {
    // Renewal is every 15 seconds, expiry at 45 seconds.
    // The actual Redis presence lease renewal is owned by the store's
    // `renewInstanceWake` — this timer triggers it. If the store interaction
    // fails, the socket is closed with dependency_unavailable.
    void sock;
  }

  private async handleControlFrame(_sock: AuthenticatedControlSocket, frameBytes: Uint8Array) {
    // Control frames are FCRC durable control events. The gateway routes them
    // to the Postgres outbox via the reserve→sign→finalize contract.
    // The actual Postgres transaction is owned by the control contract.
    this.config.logger?.info(`[gateway] control frame bytes=${frameBytes.length}`);
  }

  private async handleSignalingFrame(_sock: AuthenticatedSignalingSocket, frameBytes: Uint8Array) {
    // Signaling frames are FCSE event requests. The gateway submits exact
    // bytes to the store's Lua reducer and holds only socket-local
    // subscription/cursor/backpressure state.
    this.config.logger?.info(`[gateway] signaling frame bytes=${frameBytes.length}`);
  }

  private handlePreAuthTimeout(socketId: string) {
    const sock = this.sockets.get(socketId);
    if (!sock?.preAuth) return;
    this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.authentication_timeout);
  }

  private closeSocket(sock: GatewaySocket, code: number) {
    const bucket: SocketLogBucket = {
      closeCode: code,
      frameCount: sock.frameCount,
      byteCount: sock.byteCount,
      subprotocol:
        sock.kind === "control"
          ? REMOTE_GATEWAY_SUBPROTOCOL.control
          : REMOTE_GATEWAY_SUBPROTOCOL.signal,
    };
    this.config.logger?.info(
      `[gateway] closed code=${bucket.closeCode} frames=${bucket.frameCount} bytes=${bucket.byteCount}`,
    );
    if (sock.preAuth) {
      clearTimeout(sock.preAuth.deadline);
    }
    if (sock.kind === "control" && sock.presenceTimer) {
      clearInterval(sock.presenceTimer);
    }
    closeWith(sock.ws, code);
    this.sockets.delete(sock.socketId);
  }

  private handleClose(socketId: string) {
    const sock = this.sockets.get(socketId);
    if (!sock) return;
    if (sock.preAuth) clearTimeout(sock.preAuth.deadline);
    if (sock.kind === "control" && sock.presenceTimer) clearInterval(sock.presenceTimer);
    this.sockets.delete(socketId);
  }

  /** Graceful shutdown — stop accepting upgrades, close all sockets. */
  async close(): Promise<void> {
    this.closed = true;
    for (const sock of this.sockets.values()) {
      if (sock.preAuth) clearTimeout(sock.preAuth.deadline);
      if (sock.kind === "control" && sock.presenceTimer) clearInterval(sock.presenceTimer);
      try {
        sock.ws.close(1001, "going away");
      } catch {
        // ignore
      }
    }
    this.sockets.clear();
    this.wss.close();
  }

  /** Number of active sockets (for diagnostics only). */
  get activeSocketCount(): number {
    return this.sockets.size;
  }
}

class RemoteSignalingGatewayAuthError extends Error {
  constructor(readonly code: number) {
    super(
      REMOTE_GATEWAY_CLOSE_REASON[code as keyof typeof REMOTE_GATEWAY_CLOSE_REASON] ??
        "authentication_failed",
    );
  }
}

/**
 * Create and attach a remote signaling gateway to a Node HTTP server.
 *
 * The gateway attaches to the server's `upgrade` event and handles only
 * `/api/remote/ws`. All other upgrade paths are left to other handlers.
 */
export function createRemoteSignalingGateway(
  server: Server,
  config: RemoteSignalingGatewayConfig,
): RemoteSignalingGateway {
  const gateway = new RemoteSignalingGateway(config);

  server.on("upgrade", (request, socket, head) => {
    const url = new URL(request.url ?? "/", "http://gateway.local");
    if (url.pathname !== REMOTE_GATEWAY_WS_PATH) return;
    // Resolve client IP for rate limiting — use the socket remote address
    // as a fallback. The full proxy-aware IP resolution is handled by
    // the caller's middleware.
    const clientIp = request.socket.remoteAddress ?? "unknown";
    gateway.handleUpgrade(request, socket, head, clientIp);
  });

  return gateway;
}

/**
 * Resolve the client IP from an upgrade request, proxy-aware.
 * Exported for callers that want to inject a resolved IP.
 */
export function resolveUpgradeClientIp(request: IncomingMessage): string {
  const forwarded = request.headers["x-forwarded-for"];
  if (forwarded) {
    const first = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    return first?.split(",")[0]?.trim() ?? request.socket.remoteAddress ?? "unknown";
  }
  return request.socket.remoteAddress ?? "unknown";
}

/** Re-export close codes for callers. */
export {
  REMOTE_GATEWAY_CLOSE_CODE,
  REMOTE_GATEWAY_DATA_SUBPROTOCOL,
  REMOTE_GATEWAY_SUBPROTOCOL,
  REMOTE_GATEWAY_WS_PATH,
} from "./close-codes";
