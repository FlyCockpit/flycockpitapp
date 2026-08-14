/**
 * Redis-backed TypeScript WebSocket signaling gateway.
 *
 * Terminates `WebSocketServer({noServer:true,perMessageDeflate:false})` at exactly
 * `/api/remote/ws`, accepting exactly one of two subprotocols:
 * `flycockpit.remote-signal.v1` (one client child attempt) and
 * `flycockpit.remote-control.v1` (one daemon instance generation).
 *
 * Each replica owns only sockets, per-socket cursors, and backpressure state. The
 * injected `RemoteSignalingAttemptStore` (Redis-authoritative or memory) owns
 * tickets, admissions, attempts, presence/generation, and committed-event
 * cursors. Wake notifications ({@link RemoteSignalingWakeSubscription}) are pure
 * nudges; every committed event is read back through the store, so a reconnecting
 * socket resumes by re-reading and no committed event is skipped or synthesized.
 *
 * Daemon control authentication verifies a real identity-CA-signed certificate
 * plus a P-256 signature over the domain-separated control-auth preimage; client
 * authentication consumes a single-use Redis ticket atomically with the store's
 * `client_admission_proof` transition.
 *
 * Durable server→daemon control delivery is implemented here: after control
 * auth, the socket streams the per-instance `RemoteDaemonControlOutbox`
 * (`RemoteDaemonControlOutboxStore`, Postgres-authoritative) as the exact
 * compact control-event JWS UTF-8 bytes in binary frames — no re-sign, no FCRC
 * wrap — advancing a socket-local cursor from the daemon-reported FCDA
 * `lastControlSeq`, woken on append by the dedicated control-outbox Redis
 * channel. The deployment-scoped `RemoteAuthorityControlOutbox` is NOT the
 * daemon stream. Post-auth control-socket inbound frames demux to FCSE
 * (signaling), the 26-byte kind-2 control-delivery ACK, and FCRQ replay (served
 * from the same Postgres page reader as N JWS + terminal FCRP); inbound FCRC and
 * unknown magics close 4400 and never append.
 */
import { createHash, randomBytes } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import type { RemoteDaemonControlOutboxStore } from "@flycockpit/api/lib/remote-daemon-control-outbox";
import { RemoteDaemonControlOutboxError } from "@flycockpit/api/lib/remote-daemon-control-outbox";
import type {
  RemoteInstanceWakeLeaseV1,
  RemoteSignalingActorBindingV1,
  RemoteSignalingAttemptStore,
} from "@flycockpit/api/lib/remote-signaling-store";
import { RemoteSignalingStoreError } from "@flycockpit/api/lib/remote-signaling-store";
import {
  decodeClientAdmissionProofV1,
  decodeRemoteSignalingEventRequestV1,
  encodeRemoteSignalingEventRequestV1,
  remoteChildAuthenticationDigests,
} from "@flycockpit/cockpit-protocol";
import { WebSocket, WebSocketServer } from "ws";
import {
  decodeControlReplayRequest,
  decodeFcdaFrame,
  decodeFcsaFrame,
  decodeGatewayAck,
  encodeControlReplayPageTrailer,
  encodeFcdcFrame,
  REMOTE_GATEWAY_ACK_BYTES,
  RemoteGatewayAckKind,
} from "./binary-codecs";
import {
  REMOTE_GATEWAY_CLOSE_CODE,
  REMOTE_GATEWAY_CLOSE_REASON,
  REMOTE_GATEWAY_MAX_FRAME_BYTES,
  REMOTE_GATEWAY_MAX_QUEUED_BYTES,
  REMOTE_GATEWAY_MAX_UNACKED_EVENTS,
  REMOTE_GATEWAY_PREAUTH_MAX_AGGREGATE_BYTES_CONTROL,
  REMOTE_GATEWAY_PREAUTH_MAX_AGGREGATE_BYTES_SIGNAL,
  REMOTE_GATEWAY_PREAUTH_MAX_FRAMES,
  REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS,
  REMOTE_GATEWAY_PRESENCE_RENEWAL_MS,
  REMOTE_GATEWAY_SIGNAL_LEASE_RENEWAL_MS,
  REMOTE_GATEWAY_SUBPROTOCOL,
  REMOTE_GATEWAY_WS_PATH,
  type RemoteGatewayOriginClass,
} from "./close-codes";
import {
  DaemonCertificateVerificationError,
  type DaemonCertificateVerifier,
} from "./daemon-certificate-verifier";
import { verifyOriginClass } from "./origin-verifier";
import type { MonotonicClock } from "./rate-limiters";
import {
  DaemonControlRateLimiter,
  SignalingFrameRateLimiter,
  UnauthUpgradeRateLimiter,
} from "./rate-limiters";
import type { RemoteSignalingWakeSubscription } from "./wake-subscription";

export interface RemoteSignalingGatewayConfig {
  /** The exact configured HTTPS public origin for browser_same_origin verification. */
  configuredOrigin: string;
  /** The signaling attempt store (Redis-authoritative or memory). */
  store: RemoteSignalingAttemptStore;
  /** The per-instance daemon control-outbox page reader (Postgres or memory). */
  controlOutbox: RemoteDaemonControlOutboxStore;
  /** Injected monotonic clock for deterministic rate limiting. */
  clock: MonotonicClock;
  /** Per-IP unauthenticated upgrade rate limiter. */
  unauthUpgradeLimiter: UnauthUpgradeRateLimiter;
  /** Verifies FCDA daemon certificates against the daemon identity-CA ring. */
  daemonCertificateVerifier: DaemonCertificateVerifier;
  /** Wake-notification source for committed-event delivery. */
  wake: RemoteSignalingWakeSubscription;
  /** Injected wall clock (ms since epoch) for FCDC expiry / certificate validity. */
  now?: () => number;
  /** Optional policy ceilings (may only lower defaults). */
  policy?: {
    signaling?: { perSecond: number; burst: number };
    daemonControl?: { perSecond: number; burst: number };
    /** Outbound backpressure ceilings (may only lower the defaults). */
    backpressure?: { maxQueuedBytes?: number; maxUnackedEvents?: number };
  };
  /** Logger that receives only safe code/count/size buckets. */
  logger?: SafeLogger;
}

export interface SafeLogger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

interface PreAuthState {
  frames: number;
  aggregateBytes: number;
  deadline: ReturnType<typeof setTimeout>;
  /** Control sockets only: the exact 53 encoded FCDC frame + its expiry. */
  fcdcFrame?: Uint8Array;
  fcdcExpiresAtMs?: number;
}

interface SignalSocketState {
  kind: "signal";
  ws: WebSocket;
  socketId: string;
  originClass: RemoteGatewayOriginClass;
  rateLimiter: SignalingFrameRateLimiter;
  frameCount: number;
  byteCount: number;
  /** Outbound frames handed to `ws.send` that have not yet flushed. */
  pendingSends: number;
  preAuth: PreAuthState | null;
  queue: Promise<void>;
  closed: boolean;
  // Bound at admission:
  instanceId?: string;
  childAttemptId?: Uint8Array;
  actor?: RemoteSignalingActorBindingV1;
  deviceAttachmentId?: string;
  leaseId?: string;
  leaseTimer: ReturnType<typeof setInterval> | null;
  cursor: bigint;
  attemptWakeUnsub?: () => void;
}

interface ControlSocketState {
  kind: "control";
  ws: WebSocket;
  socketId: string;
  rateLimiter: DaemonControlRateLimiter;
  frameCount: number;
  byteCount: number;
  /** Outbound frames handed to `ws.send` that have not yet flushed. */
  pendingSends: number;
  preAuth: PreAuthState | null;
  queue: Promise<void>;
  closed: boolean;
  socketGeneration: bigint;
  presenceTimer: ReturnType<typeof setInterval> | null;
  // Bound at auth:
  instanceId?: string;
  certificateGeneration?: bigint;
  lease?: RemoteInstanceWakeLeaseV1;
  instanceWakeUnsub?: () => void;
  discoveryCursor: bigint;
  childCursors: Map<string, bigint>;
  childUnsubs: Map<string, () => void>;
  /**
   * Socket-local exclusive lower bound for live control-outbox delivery. Seeded
   * from the daemon-reported FCDA `lastControlSeq`; advances only for frames
   * handed to `ws.send`, so a 4429 close never drops an unsent committed event.
   */
  controlCursor: bigint;
  controlWakeUnsub?: () => void;
  /**
   * Monotonic token for the at-most-one in-flight FCRQ replay per socket. A
   * second FCRQ arriving before its FCRP supersedes the prior request
   * (cancel-and-replace): the stale replay observes a newer token and stops.
   */
  controlReplayToken: number;
}

type GatewaySocket = SignalSocketState | ControlSocketState;

/** Auth/relay failure carrying the exact close code to send. */
class RemoteSignalingGatewayAuthError extends Error {
  constructor(readonly code: number) {
    super(
      REMOTE_GATEWAY_CLOSE_REASON[code as keyof typeof REMOTE_GATEWAY_CLOSE_REASON] ??
        "authentication_failed",
    );
  }
}

function closeWith(ws: WebSocket, code: number) {
  const reason =
    REMOTE_GATEWAY_CLOSE_REASON[code as keyof typeof REMOTE_GATEWAY_CLOSE_REASON] ??
    "protocol_invalid";
  try {
    ws.close(code, reason);
  } catch {
    // ignore
  }
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

const controlJwsEncoder = new TextEncoder();

function magicOf(bytes: Uint8Array): string {
  return String.fromCharCode(bytes[0]!, bytes[1]!, bytes[2]!, bytes[3]!);
}

/**
 * A control-outbox read failure — Postgres unavailable or a corrupt oversized
 * JWS — closes the socket 4503 (dependency_unavailable). Both fail closed: an
 * oversized row is never skipped (skipping would brick the sequence).
 */
function isControlOutboxError(error: unknown): error is RemoteDaemonControlOutboxError {
  return error instanceof RemoteDaemonControlOutboxError;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function mapStoreErrorCode(error: unknown): number {
  if (error instanceof RemoteSignalingStoreError) {
    switch (error.code) {
      case "auth_failed":
        return REMOTE_GATEWAY_CLOSE_CODE.authentication_failed;
      case "conflict":
        return REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded;
      case "limit":
        return REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure;
      case "invalid_transition":
        return REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid;
      default:
        // retry (after one retry), corrupt, unavailable — non-enumerating.
        return REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable;
    }
  }
  return REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable;
}

/**
 * The remote signaling gateway. Attached to a Node HTTP server's `upgrade` event
 * by {@link createRemoteSignalingGateway} or, in production, by the composition
 * dispatcher in `remote-signaling-runtime.ts`.
 */
export class RemoteSignalingGateway {
  private readonly wss: WebSocketServer;
  private readonly sockets = new Map<string, GatewaySocket>();
  private readonly now: () => number;
  /** Effective outbound backpressure ceilings — policy may only LOWER the defaults. */
  private readonly maxQueuedBytes: number;
  private readonly maxUnackedEvents: number;
  private closed = false;

  constructor(private readonly config: RemoteSignalingGatewayConfig) {
    this.now = config.now ?? (() => Date.now());
    this.maxQueuedBytes = Math.min(
      config.policy?.backpressure?.maxQueuedBytes ?? REMOTE_GATEWAY_MAX_QUEUED_BYTES,
      REMOTE_GATEWAY_MAX_QUEUED_BYTES,
    );
    this.maxUnackedEvents = Math.min(
      config.policy?.backpressure?.maxUnackedEvents ?? REMOTE_GATEWAY_MAX_UNACKED_EVENTS,
      REMOTE_GATEWAY_MAX_UNACKED_EVENTS,
    );
    this.wss = new WebSocketServer({
      noServer: true,
      perMessageDeflate: false,
      maxPayload: REMOTE_GATEWAY_MAX_FRAME_BYTES,
      handleProtocols: (protocols) => {
        if (protocols.size !== 1) return false;
        const [offered] = protocols;
        if (
          offered === REMOTE_GATEWAY_SUBPROTOCOL.signal ||
          offered === REMOTE_GATEWAY_SUBPROTOCOL.control
        )
          return offered;
        return false;
      },
    });
  }

  /**
   * Handle an HTTP `upgrade` event for `/api/remote/ws`. Rejects wrong path,
   * missing/multiple/unknown subprotocol, compression extension, or Origin-class
   * mismatch — all before allocation.
   */
  handleUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer, clientIp: string): void {
    if (this.closed) {
      socket.destroy();
      return;
    }

    const url = new URL(request.url ?? "/", "http://gateway.local");
    if (url.pathname !== REMOTE_GATEWAY_WS_PATH) {
      socket.destroy();
      return;
    }

    if (!this.config.unauthUpgradeLimiter.consume(clientIp)) {
      this.writeUpgradeReject(socket, 429);
      return;
    }

    // Exactly one known subprotocol must be offered.
    const requestedProtocols = this.parseSubprotocols(request);
    if (requestedProtocols.length !== 1) {
      this.writeUpgradeReject(socket, 400);
      return;
    }
    const subprotocol = requestedProtocols[0]!;
    if (
      subprotocol !== REMOTE_GATEWAY_SUBPROTOCOL.signal &&
      subprotocol !== REMOTE_GATEWAY_SUBPROTOCOL.control
    ) {
      this.writeUpgradeReject(socket, 400);
      return;
    }

    if (this.hasCompressionExtension(request)) {
      this.writeUpgradeReject(socket, 400);
      return;
    }

    let originClass: RemoteGatewayOriginClass;
    try {
      if (subprotocol === REMOTE_GATEWAY_SUBPROTOCOL.control) {
        originClass = verifyOriginClass(
          request.headers.origin,
          this.config.configuredOrigin,
          "daemon_no_origin",
        ).class;
      } else {
        const originHeader = request.headers.origin;
        const present = originHeader !== undefined && originHeader !== null && originHeader !== "";
        originClass = present
          ? verifyOriginClass(originHeader, this.config.configuredOrigin, "browser_same_origin")
              .class
          : "native_no_origin";
      }
    } catch {
      this.writeUpgradeReject(socket, 403);
      return;
    }

    this.wss.handleUpgrade(request, socket, head, (ws) => {
      this.registerSocket(ws, subprotocol, originClass);
    });
  }

  private parseSubprotocols(request: IncomingMessage): string[] {
    const header = request.headers["sec-websocket-protocol"];
    if (!header) return [];
    const values = Array.isArray(header) ? header : [header];
    return values
      .flatMap((h: string) => h.split(",").map((s: string) => s.trim()))
      .filter((s: string) => s.length > 0);
  }

  private hasCompressionExtension(request: IncomingMessage): boolean {
    const extensions = request.headers["sec-websocket-extensions"];
    if (!extensions) return false;
    const values = Array.isArray(extensions) ? extensions.join(", ") : extensions;
    return /permessage-deflate/i.test(values);
  }

  private writeUpgradeReject(socket: Duplex, status: number) {
    const label =
      status === 400 ? "Bad Request" : status === 429 ? "Too Many Requests" : "Forbidden";
    socket.write(`HTTP/1.1 ${status} ${label}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    socket.destroy();
  }

  private registerSocket(
    ws: WebSocket,
    subprotocol: string,
    originClass: RemoteGatewayOriginClass,
  ) {
    const socketId = randomBytes(16).toString("hex");
    const deadline = setTimeout(() => {
      this.handlePreAuthTimeout(socketId);
    }, REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS);
    deadline.unref();

    const base = {
      ws,
      socketId,
      frameCount: 0,
      byteCount: 0,
      pendingSends: 0,
      preAuth: { frames: 0, aggregateBytes: 0, deadline } as PreAuthState,
      queue: Promise.resolve(),
      closed: false,
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
        discoveryCursor: 0n,
        childCursors: new Map(),
        childUnsubs: new Map(),
        controlCursor: 0n,
        controlReplayToken: 0,
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
        leaseTimer: null,
        cursor: 0n,
      };
    }

    this.sockets.set(socketId, sock);
    ws.on("message", (data, isBinary) => {
      this.enqueue(sock, () => this.processMessage(sock, data, isBinary));
    });
    ws.on("close", () => this.cleanup(sock));
    ws.on("error", () => this.cleanup(sock));

    if (sock.kind === "control") this.sendDaemonChallenge(sock);
  }

  private enqueue(sock: GatewaySocket, task: () => Promise<void>) {
    sock.queue = sock.queue.then(task).catch(() => {});
  }

  private sendDaemonChallenge(sock: ControlSocketState) {
    const challenge = randomBytes(32);
    const now = this.now();
    const frame = encodeFcdcFrame({
      challenge,
      issuedAt: BigInt(now),
      expiresAt: BigInt(now + REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS),
    });
    if (sock.preAuth) {
      sock.preAuth.fcdcFrame = frame;
      sock.preAuth.fcdcExpiresAtMs = now + REMOTE_GATEWAY_PREAUTH_TIMEOUT_MS;
    }
    try {
      sock.ws.send(Buffer.from(frame));
    } catch {
      // ignore
    }
  }

  private async processMessage(sock: GatewaySocket, data: WebSocket.RawData, isBinary: boolean) {
    if (sock.closed) return;
    const bytes = rawByteLength(data);

    if (!isBinary) {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
      return;
    }
    const frameBytes = toUint8Array(data);

    if (sock.preAuth) {
      sock.preAuth.frames++;
      sock.preAuth.aggregateBytes += bytes;
      const cap =
        sock.kind === "control"
          ? REMOTE_GATEWAY_PREAUTH_MAX_AGGREGATE_BYTES_CONTROL
          : REMOTE_GATEWAY_PREAUTH_MAX_AGGREGATE_BYTES_SIGNAL;
      if (
        sock.preAuth.frames > REMOTE_GATEWAY_PREAUTH_MAX_FRAMES ||
        sock.preAuth.aggregateBytes > cap
      ) {
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
        return;
      }
      clearTimeout(sock.preAuth.deadline);
      try {
        if (sock.kind === "control") await this.authenticateControlSocket(sock, frameBytes);
        else await this.authenticateSignalSocket(sock, frameBytes);
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
    if (!sock.rateLimiter.consume()) {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
      return;
    }
    if (bytes > REMOTE_GATEWAY_MAX_FRAME_BYTES || frameBytes.length < 5) {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
      return;
    }

    // Post-auth inbound demux.
    //   FCSE                     -> signaling/discovery commit path (both kinds).
    //   26-byte ACK (control)    -> kind-2 control-delivery progress (observability
    //                               only; at-least-once redelivery ignores it).
    //   FCRQ (control)           -> serve N JWS + terminal FCRP from readPage.
    //   inbound FCRC             -> 4400; never a client->server outbox append.
    //   unknown magic            -> 4400.
    // The ACK/FCRQ kinds are legal only on an authenticated control socket.
    // An ACK carries no magic: its first byte is the version (1), never an ASCII
    // magic byte, so a magic frame that happens to be 26 bytes still demuxes by
    // magic below.
    if (
      sock.kind === "control" &&
      frameBytes.length === REMOTE_GATEWAY_ACK_BYTES &&
      frameBytes[0] === 1
    ) {
      this.handleControlDeliveryAck(sock, frameBytes);
      return;
    }
    const magic = magicOf(frameBytes);
    if (magic === "FCSE") {
      await this.handleSignalingEvent(sock, frameBytes);
      return;
    }
    if (sock.kind === "control" && magic === "FCRQ") {
      await this.serveControlReplay(sock, frameBytes);
      return;
    }
    this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
  }

  /**
   * Accept a 26-byte control-delivery ACK on an authenticated control socket. A
   * structurally valid kind-2 ACK advances observability only; it never gates
   * mint, outbox durability, or the socket-local cursor (a missing ACK is
   * redelivered on reconnect and deduped by the daemon). A malformed ACK is a
   * protocol error (4400); a well-formed but non-kind-2 ACK is ignored for
   * durability — an unknown kind is never treated as a successful control ACK.
   */
  private handleControlDeliveryAck(sock: ControlSocketState, frameBytes: Uint8Array) {
    let ack: ReturnType<typeof decodeGatewayAck>;
    try {
      ack = decodeGatewayAck(frameBytes);
    } catch {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
      return;
    }
    if (ack.kind === RemoteGatewayAckKind.control_event_delivery)
      this.config.logger?.info("[gateway] control delivery ack kind=2");
  }

  // ---- Daemon control authentication (FCDA) -------------------------------

  private async authenticateControlSocket(sock: ControlSocketState, frameBytes: Uint8Array) {
    if (!sock.preAuth?.fcdcFrame || sock.preAuth.fcdcExpiresAtMs === undefined)
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
    if (this.now() >= sock.preAuth.fcdcExpiresAtMs)
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.authentication_timeout);

    let fcda: ReturnType<typeof decodeFcdaFrame>;
    try {
      fcda = decodeFcdaFrame(frameBytes);
    } catch {
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
    }

    let identity: Awaited<ReturnType<DaemonCertificateVerifier["verify"]>>;
    try {
      identity = await this.config.daemonCertificateVerifier.verify({
        fcdcFrame: sock.preAuth.fcdcFrame,
        certificateJws: fcda.certificateJws,
        fcdaSignature: fcda.signature,
        fcdaBytesBeforeSignature: fcda.bytesBeforeSignature,
        configuredOrigin: this.config.configuredOrigin,
        nowSeconds: BigInt(Math.floor(this.now() / 1000)),
      });
    } catch (error) {
      if (error instanceof DaemonCertificateVerificationError)
        throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable);
    }

    let socketGeneration: bigint;
    let highWater: bigint;
    let lease: RemoteInstanceWakeLeaseV1;
    try {
      socketGeneration = await this.config.store.allocateControlSocketGeneration(
        identity.instanceId,
        identity.certificateGeneration,
      );
      highWater = await this.config.store.discoveryHighWater(
        identity.instanceId,
        identity.certificateGeneration,
      );
      // A daemon claiming a future discovery position is reconciliation-invalid.
      if (fcda.lastDiscoverySeq > highWater)
        throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded);
      lease = await this.config.store.authenticateInstanceWake(
        identity.instanceId,
        identity.certificateGeneration,
        socketGeneration,
        highWater,
      );
    } catch (error) {
      if (error instanceof RemoteSignalingGatewayAuthError) throw error;
      throw new RemoteSignalingGatewayAuthError(mapStoreErrorCode(error));
    }

    sock.instanceId = identity.instanceId;
    sock.certificateGeneration = identity.certificateGeneration;
    sock.socketGeneration = socketGeneration;
    sock.lease = lease;
    sock.discoveryCursor = highWater;
    // Resume durable control delivery from the daemon-reported cursor. A claim
    // above the outbox high-water is detected as a 4409 conflict on first read.
    sock.controlCursor = fcda.lastControlSeq;
    sock.preAuth = null;

    sock.instanceWakeUnsub = this.config.wake.subscribeInstance(lease.instanceWakeRouteId, () => {
      this.enqueue(sock, () => this.deliverControlDiscovery(sock));
    });
    sock.controlWakeUnsub = this.config.wake.subscribeControlOutbox(
      identity.instanceId,
      identity.certificateGeneration,
      () => {
        this.enqueue(sock, () => this.deliverControlOutbox(sock));
      },
    );
    sock.presenceTimer = setInterval(() => {
      this.enqueue(sock, () => this.renewPresence(sock));
    }, REMOTE_GATEWAY_PRESENCE_RENEWAL_MS);
    sock.presenceTimer.unref();

    this.config.logger?.info(
      `[gateway] control authenticated generation=${socketGeneration.toString()}`,
    );
    this.enqueue(sock, () => this.deliverControlDiscovery(sock));
    this.enqueue(sock, () => this.deliverControlOutbox(sock));
  }

  private async renewPresence(sock: ControlSocketState) {
    if (sock.closed || !sock.instanceId || sock.certificateGeneration === undefined || !sock.lease)
      return;
    try {
      sock.lease = await this.config.store.renewInstanceWake(
        sock.instanceId,
        sock.certificateGeneration,
        sock.lease,
      );
    } catch (error) {
      // A store-level conflict/unavailable means the lease was superseded -> 4409.
      // A transport/dependency failure (Redis outage) -> 4503.
      const code =
        error instanceof RemoteSignalingStoreError
          ? REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded
          : REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable;
      this.closeSocket(sock, code);
    }
  }

  /**
   * Renew the signal socket's per-attachment lease for its whole lifetime, so a
   * still-open socket never falls out of the lease set (which would let extra
   * sockets bypass the cap of two). Re-acquiring a held lease refreshes it; a
   * genuine renewal failure closes the socket rather than hold a phantom slot.
   */
  private async renewSignalLease(sock: SignalSocketState) {
    if (sock.closed || !sock.deviceAttachmentId || !sock.leaseId) return;
    try {
      await this.config.store.acquireSignalingSocketLease(sock.deviceAttachmentId, sock.leaseId);
    } catch (error) {
      const code =
        error instanceof RemoteSignalingStoreError
          ? REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded
          : REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable;
      this.closeSocket(sock, code);
    }
  }

  // ---- Client authentication (FCSA) ---------------------------------------

  private async authenticateSignalSocket(sock: SignalSocketState, frameBytes: Uint8Array) {
    let frame: ReturnType<typeof decodeFcsaFrame>;
    let proof: ReturnType<typeof decodeClientAdmissionProofV1>;
    try {
      frame = decodeFcsaFrame(frameBytes);
      proof = decodeClientAdmissionProofV1(frame.admissionProof);
    } catch {
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
    }

    const route = await this.config.store.resolveAdmissionTicket(frame.ticketId);
    if (!route || !equalBytes(route.childAttemptId, proof.childAttemptId))
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);

    const requestBytes = encodeRemoteSignalingEventRequestV1({
      transport: proof.chosenTransport,
      producerRole: 2,
      eventKind: 3,
      childAttemptId: proof.childAttemptId,
      eventId: proof.proofJti,
      payload: frame.admissionProof,
    });
    const secretSha256Hex = createHash("sha256")
      .update(Buffer.from(frame.ticketSecret))
      .digest("hex");

    let admission: Awaited<ReturnType<RemoteSignalingAttemptStore["commitClientAdmission"]>>;
    try {
      admission = await this.config.store.commitClientAdmission(
        route.daemonInstanceId,
        route.childAttemptId,
        requestBytes,
        { ticketId: frame.ticketId, secretSha256Hex, originClass: sock.originClass },
      );
    } catch (error) {
      throw new RemoteSignalingGatewayAuthError(mapStoreErrorCode(error));
    }

    // Store-enforced concurrency cap: at most 2 live signal sockets per attachment.
    try {
      await this.config.store.acquireSignalingSocketLease(
        admission.deviceAttachmentId,
        sock.socketId,
      );
    } catch {
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded);
    }

    sock.instanceId = route.daemonInstanceId;
    sock.childAttemptId = route.childAttemptId;
    sock.actor = admission.actor;
    sock.deviceAttachmentId = admission.deviceAttachmentId;
    sock.leaseId = sock.socketId;
    sock.cursor = 0n;
    sock.preAuth = null;

    // Keep the lease alive for the socket's whole lifetime (released on close).
    sock.leaseTimer = setInterval(() => {
      this.enqueue(sock, () => this.renewSignalLease(sock));
    }, REMOTE_GATEWAY_SIGNAL_LEASE_RENEWAL_MS);
    sock.leaseTimer.unref();

    const meta = await this.config.store.metadata(route.daemonInstanceId, route.childAttemptId);
    if ("kind" in meta)
      throw new RemoteSignalingGatewayAuthError(REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable);
    sock.attemptWakeUnsub = this.config.wake.subscribeAttempt(meta.attemptWakeRouteId, () => {
      this.enqueue(sock, () => this.deliverSignal(sock));
    });
    this.config.logger?.info(`[gateway] signal authenticated originClass=${sock.originClass}`);
    this.enqueue(sock, () => this.deliverSignal(sock));
  }

  // ---- Post-auth relay -----------------------------------------------------

  private async handleSignalingEvent(sock: GatewaySocket, frameBytes: Uint8Array) {
    let request: ReturnType<typeof decodeRemoteSignalingEventRequestV1>;
    try {
      request = decodeRemoteSignalingEventRequestV1(frameBytes);
    } catch {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
      return;
    }

    let instanceId: string;
    let childAttemptId: Uint8Array;
    let actor: RemoteSignalingActorBindingV1;
    if (sock.kind === "signal") {
      if (!sock.instanceId || !sock.childAttemptId || !sock.actor) {
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
        return;
      }
      // Signal socket produces client (role 2) events for its admitted attempt only.
      if (request.producerRole !== 2 || !equalBytes(request.childAttemptId, sock.childAttemptId)) {
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
        return;
      }
      instanceId = sock.instanceId;
      childAttemptId = sock.childAttemptId;
      actor = sock.actor;
    } else {
      if (!sock.instanceId || sock.certificateGeneration === undefined) {
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
        return;
      }
      // Control socket produces daemon (role 3) events for any child of its instance.
      if (request.producerRole !== 3) {
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
        return;
      }
      instanceId = sock.instanceId;
      childAttemptId = request.childAttemptId;
      actor = { role: "daemon", actor: sock.instanceId, generation: sock.certificateGeneration };
    }

    let result: Awaited<ReturnType<RemoteSignalingAttemptStore["commit"]>>;
    try {
      result = await this.commitWithRetry(instanceId, childAttemptId, frameBytes, actor);
    } catch (error) {
      this.closeSocket(sock, mapStoreErrorCode(error));
      return;
    }
    // The FCAK reply is backpressure-guarded like any other outbound frame.
    if (!this.trySend(sock, result.ackBytes))
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
  }

  private async commitWithRetry(
    instanceId: string,
    childAttemptId: Uint8Array,
    frameBytes: Uint8Array,
    actor: RemoteSignalingActorBindingV1,
  ) {
    try {
      return await this.config.store.commit(instanceId, childAttemptId, frameBytes, actor);
    } catch (error) {
      if (error instanceof RemoteSignalingStoreError && error.code === "retry")
        return await this.config.store.commit(instanceId, childAttemptId, frameBytes, actor);
      throw error;
    }
  }

  /**
   * Send an authenticated outbound frame under backpressure control. Returns
   * false (the caller closes 4429) when the outbound queue would exceed the
   * queued-bytes or unacked-event ceiling — this guards FCAK replies (including
   * idempotent replays) exactly like committed-event deliveries, so a stalled
   * peer can never grow the outbound queue past the cap. `pendingSends` is
   * decremented when `ws.send` flushes the frame.
   */
  private trySend(sock: GatewaySocket, bytes: Uint8Array): boolean {
    if (
      sock.pendingSends >= this.maxUnackedEvents ||
      sock.ws.bufferedAmount + bytes.length > this.maxQueuedBytes
    )
      return false;
    sock.pendingSends++;
    try {
      sock.ws.send(Buffer.from(bytes), () => {
        sock.pendingSends = Math.max(0, sock.pendingSends - 1);
      });
    } catch {
      sock.pendingSends = Math.max(0, sock.pendingSends - 1);
      return false;
    }
    return true;
  }

  /** Deliver committed peer events to a signal socket by socket-local cursor. */
  private async deliverSignal(sock: SignalSocketState) {
    if (sock.closed || !sock.instanceId || !sock.childAttemptId) return;
    const code = await this.pumpEvents(
      sock,
      sock.instanceId,
      sock.childAttemptId,
      () => sock.cursor,
      (sequence) => {
        sock.cursor = sequence;
      },
      "client",
    );
    if (code) this.closeSocket(sock, code);
  }

  /** Control-socket discovery: deliver `attempt_available` and relay per-child events. */
  private async deliverControlDiscovery(sock: ControlSocketState) {
    // Snapshot the authenticated binding once (L17: property narrowing does not
    // survive the awaits below).
    const instanceId = sock.instanceId;
    const certificateGeneration = sock.certificateGeneration;
    const socketGeneration = sock.socketGeneration;
    if (
      sock.closed ||
      !instanceId ||
      certificateGeneration === undefined ||
      socketGeneration === 0n
    )
      return;
    let read: Awaited<ReturnType<RemoteSignalingAttemptStore["readDiscovery"]>>;
    try {
      read = await this.config.store.readDiscovery(
        instanceId,
        certificateGeneration,
        socketGeneration,
        sock.discoveryCursor,
      );
    } catch (error) {
      this.closeSocket(sock, mapStoreErrorCode(error));
      return;
    }
    if (read.kind === "unavailable") return;
    if (read.kind === "expired_gap") {
      try {
        await this.config.store.ackDiscovery(
          instanceId,
          certificateGeneration,
          socketGeneration,
          read.expectedAfterSeq,
          read.expiredThroughSeq,
          true,
        );
        sock.discoveryCursor = read.expiredThroughSeq;
      } catch {
        return;
      }
      this.enqueue(sock, () => this.deliverControlDiscovery(sock));
      return;
    }

    for (const entry of read.entries) {
      const attempt = await this.config.store.read(instanceId, entry.childAttemptId, 0n);
      if (attempt.kind !== "events") return;
      const available = attempt.events.find((event) => event.sequence === 1n);
      // Verify the discovery entry's authBundleDigest against the delivered event.
      if (
        !available ||
        !equalBytes(
          remoteChildAuthenticationDigests(available.request.payload).authBundleDigest,
          entry.authBundleDigest,
        )
      )
        return;
      if (!this.trySend(sock, available.requestBytes)) {
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
        return;
      }
      try {
        await this.config.store.ackDiscovery(
          instanceId,
          certificateGeneration,
          socketGeneration,
          sock.discoveryCursor,
          entry.discoverySeq,
        );
      } catch (error) {
        this.closeSocket(sock, mapStoreErrorCode(error));
        return;
      }
      sock.discoveryCursor = entry.discoverySeq;

      const childKey = Buffer.from(entry.childAttemptId).toString("hex");
      if (!sock.childUnsubs.has(childKey)) {
        sock.childCursors.set(childKey, 1n); // attempt_available (seq 1) already delivered
        const childId = entry.childAttemptId.slice();
        const metadata = await this.config.store.metadata(instanceId, childId);
        if (!("kind" in metadata)) {
          sock.childUnsubs.set(
            childKey,
            this.config.wake.subscribeAttempt(metadata.attemptWakeRouteId, () => {
              this.enqueue(sock, () => this.deliverControlChild(sock, childId, childKey));
            }),
          );
        }
        this.enqueue(sock, () => this.deliverControlChild(sock, childId, childKey));
      }
    }
  }

  /** Relay a discovered child's committed client/server events to the control socket. */
  private async deliverControlChild(
    sock: ControlSocketState,
    childId: Uint8Array,
    childKey: string,
  ) {
    if (sock.closed || !sock.instanceId) return;
    const code = await this.pumpEvents(
      sock,
      sock.instanceId,
      childId,
      () => sock.childCursors.get(childKey) ?? 0n,
      (sequence) => sock.childCursors.set(childKey, sequence),
      "daemon",
    );
    if (code) this.closeSocket(sock, code);
  }

  /**
   * Read committed events after the socket-local cursor and deliver those NOT
   * produced by `ownRole`. Returns a close code on backpressure/dependency
   * failure, or 0 on success. The cursor advances only for delivered/skipped
   * events, so a 4429 never drops a committed event — reconnect re-reads it.
   */
  private async pumpEvents(
    sock: GatewaySocket,
    instanceId: string,
    childAttemptId: Uint8Array,
    getCursor: () => bigint,
    setCursor: (sequence: bigint) => void,
    ownRole: "client" | "daemon",
  ): Promise<number> {
    for (;;) {
      const cursor = getCursor();
      let read: Awaited<ReturnType<RemoteSignalingAttemptStore["read"]>>;
      try {
        read = await this.config.store.read(instanceId, childAttemptId, cursor);
      } catch {
        return REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable;
      }
      if (read.kind !== "events") return REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable;
      if (read.events.length === 0) return 0;
      for (const event of read.events) {
        if (event.sequence <= getCursor()) continue;
        if (event.actor.role !== ownRole) {
          // Cursor only advances for a frame we actually queued, so a 4429 close
          // never drops a committed event — reconnect re-reads it.
          if (!this.trySend(sock, event.requestBytes))
            return REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure;
        }
        setCursor(event.sequence);
      }
      if (getCursor() >= read.latestSequence) return 0;
    }
  }

  // ---- Durable control-outbox delivery (server -> daemon) ------------------

  /**
   * Drain the per-instance control outbox to the daemon as exact
   * `controlEventJws` UTF-8 bytes (no re-sign, no FCRC wrap, no FCRP trailer for
   * live delivery), in `controlSeq` order, from the socket-local cursor. The
   * cursor advances only for a frame handed to `ws.send`, so a 4429 close never
   * drops an unsent committed event — reconnect re-reads from Postgres. A daemon
   * claiming a control cursor above the outbox high-water closes 4409.
   */
  private async deliverControlOutbox(sock: ControlSocketState) {
    const instanceId = sock.instanceId;
    const certificateGeneration = sock.certificateGeneration;
    if (sock.closed || !instanceId || certificateGeneration === undefined) return;
    for (;;) {
      let page: Awaited<ReturnType<RemoteDaemonControlOutboxStore["readDaemonControlOutboxPage"]>>;
      try {
        page = await this.config.controlOutbox.readDaemonControlOutboxPage({
          daemonInstanceProtocolId: instanceId,
          daemonCertificateGeneration: certificateGeneration,
          afterControlSeq: sock.controlCursor,
        });
      } catch (error) {
        if (isControlOutboxError(error))
          this.config.logger?.warn(`[gateway] control outbox read code=${error.code}`);
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable);
        return;
      }
      if (sock.controlCursor > page.highWaterSeq) {
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded);
        return;
      }
      if (page.events.length === 0) return;
      for (const event of page.events) {
        if (sock.closed) return;
        if (!this.trySend(sock, controlJwsEncoder.encode(event.controlEventJws))) {
          this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
          return;
        }
        sock.controlCursor = event.controlSeq;
      }
      if (!page.truncated) return;
    }
  }

  /**
   * Serve an FCRQ replay page for gap recovery: N exact `controlEventJws` frames
   * (`controlSeq > afterControlSeq`, same wire form as live delivery) followed by
   * exactly one terminal FCRP trailer whose `eventCount` equals N. Replay is
   * independent of the live cursor. Inbound frames are processed sequentially per
   * socket (they chain on `sock.queue`), so at most one replay runs at a time: a
   * second FCRQ waits for the prior FCRP rather than interleaving. `token` is a
   * forward guard that abandons an in-flight page if a newer FCRQ ever begins
   * before this one finishes (e.g. if inbound handling becomes concurrent).
   */
  private async serveControlReplay(sock: ControlSocketState, frameBytes: Uint8Array) {
    const instanceId = sock.instanceId;
    const certificateGeneration = sock.certificateGeneration;
    if (sock.closed || !instanceId || certificateGeneration === undefined) {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
      return;
    }
    let request: ReturnType<typeof decodeControlReplayRequest>;
    try {
      request = decodeControlReplayRequest(frameBytes);
    } catch {
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.protocol_invalid);
      return;
    }
    const token = ++sock.controlReplayToken;
    let page: Awaited<ReturnType<RemoteDaemonControlOutboxStore["readDaemonControlOutboxPage"]>>;
    try {
      page = await this.config.controlOutbox.readDaemonControlOutboxPage({
        daemonInstanceProtocolId: instanceId,
        daemonCertificateGeneration: certificateGeneration,
        afterControlSeq: request.afterControlSeq,
      });
    } catch (error) {
      if (isControlOutboxError(error))
        this.config.logger?.warn(`[gateway] control replay read code=${error.code}`);
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.dependency_unavailable);
      return;
    }
    // Superseded by a newer FCRQ while reading: drop this torn page silently.
    if (sock.closed || token !== sock.controlReplayToken) return;
    for (const event of page.events) {
      if (sock.closed || token !== sock.controlReplayToken) return;
      if (!this.trySend(sock, controlJwsEncoder.encode(event.controlEventJws))) {
        this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
        return;
      }
    }
    if (sock.closed || token !== sock.controlReplayToken) return;
    const trailer = encodeControlReplayPageTrailer({
      highWaterSeq: page.highWaterSeq,
      truncated: page.truncated,
      eventCount: page.events.length,
    });
    if (!this.trySend(sock, trailer))
      this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.rate_or_backpressure);
  }

  // ---- Lifecycle -----------------------------------------------------------

  private handlePreAuthTimeout(socketId: string) {
    const sock = this.sockets.get(socketId);
    if (!sock?.preAuth) return;
    this.closeSocket(sock, REMOTE_GATEWAY_CLOSE_CODE.authentication_timeout);
  }

  private cleanup(sock: GatewaySocket) {
    if (sock.closed) return;
    sock.closed = true;
    if (sock.preAuth) clearTimeout(sock.preAuth.deadline);
    if (sock.kind === "control") {
      if (sock.presenceTimer) clearInterval(sock.presenceTimer);
      sock.instanceWakeUnsub?.();
      sock.controlWakeUnsub?.();
      for (const unsub of sock.childUnsubs.values()) unsub();
      sock.childUnsubs.clear();
      if (sock.instanceId && sock.certificateGeneration !== undefined && sock.lease) {
        const { instanceId, certificateGeneration, lease } = sock;
        void this.config.store
          .closeInstanceWake(instanceId, certificateGeneration, lease)
          .catch(() => {});
      }
    } else {
      if (sock.leaseTimer) clearInterval(sock.leaseTimer);
      sock.attemptWakeUnsub?.();
      if (sock.deviceAttachmentId && sock.leaseId) {
        const { deviceAttachmentId, leaseId } = sock;
        void this.config.store
          .releaseSignalingSocketLease(deviceAttachmentId, leaseId)
          .catch(() => {});
      }
    }
    this.sockets.delete(sock.socketId);
  }

  private closeSocket(sock: GatewaySocket, code: number) {
    if (sock.closed) return;
    this.config.logger?.info(
      `[gateway] closed code=${code} frames=${sock.frameCount} bytes=${sock.byteCount}`,
    );
    const ws = sock.ws;
    this.cleanup(sock);
    closeWith(ws, code);
  }

  /** Graceful shutdown — stop accepting upgrades, close all sockets 1001. */
  async close(): Promise<void> {
    this.closed = true;
    for (const sock of [...this.sockets.values()]) {
      const ws = sock.ws;
      this.cleanup(sock);
      try {
        ws.close(1001, "going away");
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

/**
 * Create and attach a remote signaling gateway to a Node HTTP server's `upgrade`
 * event for `/api/remote/ws` only. The production composition dispatcher
 * (`installRemoteSignalingGateway`) owns routing and destroys non-gateway upgrade
 * sockets; this helper is for focused tests that supply their own resolved IP.
 */
export function createRemoteSignalingGateway(
  server: {
    on(
      event: "upgrade",
      listener: (req: IncomingMessage, socket: Duplex, head: Buffer) => void,
    ): unknown;
  },
  config: RemoteSignalingGatewayConfig,
): RemoteSignalingGateway {
  const gateway = new RemoteSignalingGateway(config);
  server.on("upgrade", (request, socket, head) => {
    const url = new URL(request.url ?? "/", "http://gateway.local");
    if (url.pathname !== REMOTE_GATEWAY_WS_PATH) return;
    const clientIp = request.socket.remoteAddress ?? "unknown";
    gateway.handleUpgrade(request, socket, head, clientIp);
  });
  return gateway;
}

/** Re-export the gateway surface for callers. */
export {
  REMOTE_GATEWAY_CLOSE_CODE,
  REMOTE_GATEWAY_DATA_SUBPROTOCOL,
  REMOTE_GATEWAY_SUBPROTOCOL,
  REMOTE_GATEWAY_WS_PATH,
} from "./close-codes";
