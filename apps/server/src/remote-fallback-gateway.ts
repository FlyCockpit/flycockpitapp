import { randomBytes } from "node:crypto";
import type { IncomingMessage, Server } from "node:http";
import {
  decodeRemoteFallbackOuterRecordV1,
  encodeRemoteFallbackChallengeV1,
  REMOTE_FALLBACK_AUTH_MAX_BYTES,
  REMOTE_FALLBACK_MAX_MESSAGE_BYTES,
  REMOTE_FALLBACK_SUBPROTOCOL,
  type RemoteFallbackTicketV1,
} from "@flycockpit/cockpit-protocol";
import { type RawData, WebSocket, WebSocketServer } from "ws";
import {
  type RemoteFallbackAdmissionSource,
  type RemoteFallbackCertificateVerifier,
  verifyRemoteFallbackSocketAdmission,
} from "./remote-fallback-runtime";

export interface RemoteFallbackGatewayHooks {
  redisTimeMillis(): Promise<bigint>;
  classifyOrigin(request: IncomingMessage): "web" | "native" | "daemon" | null;
  admitted(input: {
    ticket: RemoteFallbackTicketV1;
    socket: WebSocket;
  }): Promise<RemoteFallbackGatewaySession>;
  disconnected(input: { ticket: RemoteFallbackTicketV1; wasActive: boolean }): Promise<void>;
}
export interface RemoteFallbackGatewaySession {
  phase():
    | "noise_handshake"
    | "noise_commit_pending"
    | "proof_pending"
    | "lease_pending"
    | "active"
    | "closing";
  opaquePacket(bytes: Uint8Array): Promise<void>;
}

function close(socket: WebSocket, code: number): void {
  if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)
    socket.close(code);
}
function rawBytes(data: RawData): Uint8Array {
  if (Array.isArray(data)) return new Uint8Array(Buffer.concat(data));
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
}

export function installRemoteFallbackGateway(input: {
  server: Server;
  source: RemoteFallbackAdmissionSource;
  certificates: RemoteFallbackCertificateVerifier;
  hooks: RemoteFallbackGatewayHooks;
}): { close(): Promise<void> } {
  const sockets = new Set<WebSocket>();
  const websocketServer = new WebSocketServer({
    noServer: true,
    maxPayload: REMOTE_FALLBACK_MAX_MESSAGE_BYTES,
    perMessageDeflate: false,
  });
  const onUpgrade = (
    request: IncomingMessage,
    socket: import("node:stream").Duplex,
    head: Buffer,
  ) => {
    if (
      request.url !== "/remote/data" ||
      request.headers["sec-websocket-protocol"]
        ?.split(",")
        .map((value) => value.trim())
        .includes(REMOTE_FALLBACK_SUBPROTOCOL) !== true
    )
      return;
    websocketServer.handleUpgrade(request, socket, head, (websocket) =>
      websocketServer.emit("connection", websocket, request),
    );
  };
  input.server.on("upgrade", onUpgrade);
  websocketServer.on("connection", async (socket, request) => {
    sockets.add(socket);
    const originClass = input.hooks.classifyOrigin(request);
    if (!originClass || socket.protocol !== REMOTE_FALLBACK_SUBPROTOCOL) {
      close(socket, 1008);
      return;
    }
    const issuedAt = await input.hooks.redisTimeMillis().catch(() => null);
    if (issuedAt === null) {
      close(socket, 1011);
      return;
    }
    const challengeFrame = encodeRemoteFallbackChallengeV1({
      challenge: randomBytes(32),
      issuedAt,
      expiresAt: issuedAt + 30_000n,
    });
    socket.send(challengeFrame, { binary: true });
    const authTimer = setTimeout(() => close(socket, 1008), 30_000);
    authTimer.unref();
    let ticket: RemoteFallbackTicketV1 | undefined;
    let session: RemoteFallbackGatewaySession | undefined;
    let processing = Promise.resolve();
    socket.on("message", (data, isBinary) => {
      processing = processing
        .then(async () => {
          if (!isBinary) {
            close(socket, 1008);
            return;
          }
          const bytes = rawBytes(data);
          if (!ticket) {
            if (bytes.length > REMOTE_FALLBACK_AUTH_MAX_BYTES) {
              close(socket, 1009);
              return;
            }
            try {
              const nowMillis = await input.hooks.redisTimeMillis();
              ticket = await verifyRemoteFallbackSocketAdmission({
                challengeFrame,
                authFrame: bytes,
                subprotocol: socket.protocol,
                originClass,
                nowMillis,
                source: input.source,
                certificates: input.certificates,
              });
              session = await input.hooks.admitted({ ticket, socket });
              clearTimeout(authTimer);
            } catch {
              close(socket, 1008);
            }
            return;
          }
          if (!session) {
            close(socket, 1008);
            return;
          }
          const phase = session.phase();
          if (phase === "closing" || bytes.length > REMOTE_FALLBACK_MAX_MESSAGE_BYTES) {
            close(socket, bytes.length > REMOTE_FALLBACK_MAX_MESSAGE_BYTES ? 1009 : 1008);
            return;
          }
          try {
            if (phase === "active") decodeRemoteFallbackOuterRecordV1(bytes);
            else if (phase !== "noise_handshake" || bytes.length > 4_100)
              throw new Error("fallback_data_before_active");
            await session.opaquePacket(bytes);
          } catch {
            close(socket, 1008);
          }
        })
        .catch(() => close(socket, 1011));
    });
    socket.on("close", () => {
      clearTimeout(authTimer);
      sockets.delete(socket);
      if (ticket)
        void input.hooks.disconnected({ ticket, wasActive: session?.phase() === "active" });
    });
    socket.on("error", () => close(socket, 1011));
  });
  return {
    async close() {
      input.server.off("upgrade", onUpgrade);
      for (const socket of sockets) close(socket, 1012);
      await new Promise<void>((resolve) => websocketServer.close(() => resolve()));
    },
  };
}
