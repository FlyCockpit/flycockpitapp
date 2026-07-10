import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import {
  type ClientRelayFrame,
  clientRelayFrameSchema,
  type DaemonRelayFrame,
  daemonRelayFrameSchema,
  type RelayControlMessage,
  type RelayGrant,
  type RelayTokenPayload,
  relayControlMessageSchema,
  type UserRelayFrame,
  userRelayFrameSchema,
} from "@flycockpit/relay-protocol";
import { createRemoteRelayTokenVerifier } from "@flycockpit/relay-protocol/tokens";
import WebSocket, { WebSocketServer } from "ws";
import { createPresenceStore, type PresenceStore } from "./presence.js";

type Logger = Pick<typeof console, "error" | "info" | "warn">;

type RateState = { windowStartedAt: number; count: number };

type DaemonConnection = {
  kind: "daemon";
  ws: WebSocket;
  connectionId: string;
  instanceId: string;
  userId: string;
  isAlive: boolean;
  frameCount: number;
  byteCount: number;
};

type ClientConnection = {
  kind: "client";
  ws: WebSocket;
  connectionId: string;
  instanceId: string;
  userId: string;
  grants: RelayGrant[];
  channels: Set<string>;
  isAlive: boolean;
  rate: RateState;
  frameCount: number;
  byteCount: number;
};

type UserConnection = {
  kind: "user";
  ws: WebSocket;
  connectionId: string;
  userId: string;
  isAlive: boolean;
};

export type RelayServerConfig = {
  relayId: string;
  port?: number;
  jwksUrl: string;
  tokenIssuer: string;
  heartbeatMs: number;
  leaseTtlMs: number;
  maxFrameBytes: number;
  maxChannelsPerClient: number;
  maxConnectionsPerInstance: number;
  clientRateLimitPerSecond: number;
  controlIngestUrl?: string;
  controlSecret?: string;
  redisUrl?: string;
  logger?: Logger;
  presenceStore?: PresenceStore;
  verifyToken?: (token: string) => Promise<RelayTokenPayload>;
};

export type RelayServerHandle = {
  server: Server;
  presenceStore: PresenceStore;
  publishControl(message: RelayControlMessage): Promise<void>;
  close(): Promise<void>;
};

const CLOSE_AUTH = 4401;
const CLOSE_OFFLINE = 4404;
const CLOSE_REPLACED = 4409;
const CLOSE_RATE_LIMITED = 4429;
const CLOSE_BAD_FRAME = 4400;
const CLOSE_FORCED = 4410;

function sendJson(ws: WebSocket, value: unknown) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(value));
}

function writeHttp(socket: Duplex, status: number, message: string) {
  socket.write(`HTTP/1.1 ${status} ${message}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  socket.destroy();
}

function bearerToken(request: IncomingMessage, url: URL) {
  const header = request.headers.authorization;
  if (header?.startsWith("Bearer ")) return header.slice("Bearer ".length).trim();
  return url.searchParams.get("token") ?? "";
}

function byteLength(data: WebSocket.RawData) {
  if (typeof data === "string") return Buffer.byteLength(data);
  if (Buffer.isBuffer(data)) return data.length;
  if (data instanceof ArrayBuffer) return data.byteLength;
  return data.reduce((sum, item) => sum + item.byteLength, 0);
}

async function readJsonBody(request: IncomingMessage, maxBytes: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > maxBytes) throw new Error("body_too_large");
    chunks.push(buffer);
  }
  if (chunks.length === 0) return null;
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

function parseJson(data: WebSocket.RawData) {
  if (typeof data === "string") return JSON.parse(data) as unknown;
  if (Array.isArray(data)) return JSON.parse(Buffer.concat(data).toString("utf8")) as unknown;
  if (Buffer.isBuffer(data)) return JSON.parse(data.toString("utf8")) as unknown;
  return JSON.parse(Buffer.from(new Uint8Array(data)).toString("utf8")) as unknown;
}

export function createRelayServer(config: RelayServerConfig): RelayServerHandle {
  const logger = config.logger ?? console;
  const presenceStore = config.presenceStore ?? createPresenceStore(config.redisUrl);
  const verifyToken =
    config.verifyToken ??
    createRemoteRelayTokenVerifier({
      jwksUrl: config.jwksUrl,
      issuer: config.tokenIssuer,
      audience: config.relayId,
    });
  const daemonWss = new WebSocketServer({
    noServer: true,
    maxPayload: config.maxFrameBytes,
    perMessageDeflate: false,
  });
  const clientWss = new WebSocketServer({
    noServer: true,
    maxPayload: config.maxFrameBytes,
    perMessageDeflate: false,
  });
  const userWss = new WebSocketServer({
    noServer: true,
    maxPayload: config.maxFrameBytes,
    perMessageDeflate: false,
  });

  const daemonsByInstance = new Map<string, DaemonConnection>();
  const clientsByConnection = new Map<string, ClientConnection>();
  const usersByConnection = new Map<string, UserConnection>();
  const channelOwners = new Map<string, ClientConnection>();
  let totalFrames = 0;
  let totalBytes = 0;

  const channelKey = (instanceId: string, channelId: string) => instanceId + ":" + channelId;

  async function unregisterDaemon(connection: DaemonConnection) {
    const current = daemonsByInstance.get(connection.instanceId);
    if (current?.connectionId === connection.connectionId)
      daemonsByInstance.delete(connection.instanceId);
    await presenceStore.deleteDaemonLease(connection.instanceId, connection.connectionId);
    logger.info(
      `[relay] daemon disconnected instance=${connection.instanceId} connection=${connection.connectionId} frames=${connection.frameCount} bytes=${connection.byteCount}`,
    );
  }

  function unregisterClient(connection: ClientConnection) {
    clientsByConnection.delete(connection.connectionId);
    for (const channelId of connection.channels) {
      const key = channelKey(connection.instanceId, channelId);
      if (channelOwners.get(key)?.connectionId === connection.connectionId)
        channelOwners.delete(key);
    }
    logger.info(
      `[relay] client disconnected instance=${connection.instanceId} user=${connection.userId} connection=${connection.connectionId} frames=${connection.frameCount} bytes=${connection.byteCount}`,
    );
  }

  async function registerDaemon(ws: WebSocket, payload: RelayTokenPayload) {
    if (payload.tokenType !== "connector" || !payload.instanceId) {
      ws.close(CLOSE_AUTH);
      return;
    }
    const connection: DaemonConnection = {
      kind: "daemon",
      ws,
      connectionId: randomUUID(),
      instanceId: payload.instanceId,
      userId: payload.userId,
      isAlive: true,
      frameCount: 0,
      byteCount: 0,
    };
    const previous = daemonsByInstance.get(connection.instanceId);
    if (previous) {
      sendJson(previous.ws, { v: 1, type: "system", code: "daemon_replaced" });
      previous.ws.close(CLOSE_REPLACED);
      await unregisterDaemon(previous);
    }
    daemonsByInstance.set(connection.instanceId, connection);
    await presenceStore.setDaemonLease(
      {
        instanceId: connection.instanceId,
        relayId: config.relayId,
        connectionId: connection.connectionId,
        expiresAt: Date.now() + config.leaseTtlMs,
      },
      config.leaseTtlMs,
    );
    logger.info(
      `[relay] daemon connected instance=${connection.instanceId} connection=${connection.connectionId}`,
    );

    ws.on("pong", () => {
      connection.isAlive = true;
      void presenceStore.touchDaemonLease(
        connection.instanceId,
        connection.connectionId,
        Date.now() + config.leaseTtlMs,
        config.leaseTtlMs,
      );
    });
    ws.on("close", () => void unregisterDaemon(connection));
    ws.on("error", (err) =>
      logger.warn(`[relay] daemon error instance=${connection.instanceId}: ${err.message}`),
    );
    ws.on("message", (data) => void handleDaemonMessage(connection, data));
  }

  async function registerClient(ws: WebSocket, payload: RelayTokenPayload) {
    if (payload.tokenType !== "client" || !payload.instanceId) {
      ws.close(CLOSE_AUTH);
      return;
    }
    const lease = await presenceStore.getDaemonLease(payload.instanceId);
    const daemon = daemonsByInstance.get(payload.instanceId);
    if (!lease || lease.relayId !== config.relayId || !daemon) {
      sendJson(ws, { v: 1, type: "system", code: "instance_offline" });
      ws.close(CLOSE_OFFLINE);
      return;
    }
    const activeForInstance = Array.from(clientsByConnection.values()).filter(
      (client) => client.instanceId === payload.instanceId,
    ).length;
    if (activeForInstance >= config.maxConnectionsPerInstance) {
      sendJson(ws, { v: 1, type: "system", code: "rate_limited" });
      ws.close(CLOSE_RATE_LIMITED);
      return;
    }
    const connection: ClientConnection = {
      kind: "client",
      ws,
      connectionId: randomUUID(),
      instanceId: payload.instanceId,
      userId: payload.userId,
      grants: payload.grants,
      channels: new Set(),
      isAlive: true,
      rate: { windowStartedAt: Date.now(), count: 0 },
      frameCount: 0,
      byteCount: 0,
    };
    clientsByConnection.set(connection.connectionId, connection);
    logger.info(
      `[relay] client connected instance=${connection.instanceId} user=${connection.userId} connection=${connection.connectionId}`,
    );
    ws.on("pong", () => {
      connection.isAlive = true;
    });
    ws.on("close", () => unregisterClient(connection));
    ws.on("error", (err) =>
      logger.warn(`[relay] client error instance=${connection.instanceId}: ${err.message}`),
    );
    ws.on("message", (data) => handleClientMessage(connection, data));
  }

  function registerUser(ws: WebSocket, payload: RelayTokenPayload) {
    if (payload.tokenType !== "user") {
      ws.close(CLOSE_AUTH);
      return;
    }
    const connection: UserConnection = {
      kind: "user",
      ws,
      connectionId: randomUUID(),
      userId: payload.userId,
      isAlive: true,
    };
    usersByConnection.set(connection.connectionId, connection);
    logger.info(
      `[relay] user connected user=${connection.userId} connection=${connection.connectionId}`,
    );
    ws.on("pong", () => {
      connection.isAlive = true;
    });
    ws.on("close", () => {
      usersByConnection.delete(connection.connectionId);
      logger.info(
        `[relay] user disconnected user=${connection.userId} connection=${connection.connectionId}`,
      );
    });
    ws.on("message", (data) => void handleUserMessage(connection, data));
  }

  async function handleUserMessage(connection: UserConnection, data: WebSocket.RawData) {
    const bytes = byteLength(data);
    totalFrames += 1;
    totalBytes += bytes;
    let frame: UserRelayFrame;
    try {
      frame = userRelayFrameSchema.parse(parseJson(data));
    } catch {
      sendJson(connection.ws, { v: 1, type: "system", code: "bad_frame" });
      connection.ws.close(CLOSE_BAD_FRAME);
      return;
    }
    if (!controlIngestConfigured || !config.controlIngestUrl || !config.controlSecret) return;
    try {
      await fetch(config.controlIngestUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${config.controlSecret}`,
        },
        body: JSON.stringify({
          relayId: config.relayId,
          event: "user_presence",
          userId: connection.userId,
          payload: { clientId: frame.clientId, visible: frame.visible, ts: frame.ts },
        }),
      });
    } catch (err) {
      logger.warn(
        `[relay] user presence ingest failed user=${connection.userId}: ${
          err instanceof Error ? err.message : "unknown"
        }`,
      );
    }
  }

  function overRateLimit(connection: ClientConnection) {
    const now = Date.now();
    if (now - connection.rate.windowStartedAt >= 1000) {
      connection.rate = { windowStartedAt: now, count: 0 };
    }
    connection.rate.count += 1;
    return connection.rate.count > config.clientRateLimitPerSecond;
  }

  function handleClientMessage(connection: ClientConnection, data: WebSocket.RawData) {
    const bytes = byteLength(data);
    connection.frameCount += 1;
    connection.byteCount += bytes;
    totalFrames += 1;
    totalBytes += bytes;
    if (overRateLimit(connection)) {
      sendJson(connection.ws, { v: 1, type: "system", code: "rate_limited" });
      connection.ws.close(CLOSE_RATE_LIMITED);
      return;
    }
    const daemon = daemonsByInstance.get(connection.instanceId);
    if (!daemon || daemon.ws.readyState !== WebSocket.OPEN) {
      sendJson(connection.ws, { v: 1, type: "system", code: "instance_offline" });
      connection.ws.close(CLOSE_OFFLINE);
      return;
    }
    let frame: ClientRelayFrame;
    try {
      frame = clientRelayFrameSchema.parse(parseJson(data));
    } catch {
      sendJson(connection.ws, { v: 1, type: "system", code: "bad_frame" });
      connection.ws.close(CLOSE_BAD_FRAME);
      return;
    }
    if (!connection.channels.has(frame.channelId)) {
      if (connection.channels.size >= config.maxChannelsPerClient) {
        sendJson(connection.ws, { v: 1, type: "system", code: "channel_limit" });
        return;
      }
      connection.channels.add(frame.channelId);
      channelOwners.set(channelKey(connection.instanceId, frame.channelId), connection);
    }
    sendJson(daemon.ws, {
      v: 1,
      channelId: frame.channelId,
      from: "client",
      principal: { userId: connection.userId, grants: connection.grants },
      payload: frame.payload,
    });
  }

  async function handleDaemonMessage(connection: DaemonConnection, data: WebSocket.RawData) {
    const bytes = byteLength(data);
    connection.frameCount += 1;
    connection.byteCount += bytes;
    totalFrames += 1;
    totalBytes += bytes;
    let frame: DaemonRelayFrame;
    try {
      frame = daemonRelayFrameSchema.parse(parseJson(data));
    } catch {
      connection.ws.close(CLOSE_BAD_FRAME);
      return;
    }
    if (!("channelId" in frame)) {
      if (controlIngestConfigured && config.controlIngestUrl && config.controlSecret) {
        try {
          await fetch(config.controlIngestUrl, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${config.controlSecret}`,
            },
            body: JSON.stringify({
              instanceId: connection.instanceId,
              relayId: config.relayId,
              event: frame.event,
              payload: frame.payload,
            }),
          });
        } catch (err) {
          logger.warn(
            `[relay] control ingest failed instance=${connection.instanceId}: ${
              err instanceof Error ? err.message : "unknown"
            }`,
          );
        }
      } else {
        logger.info(
          `[relay] control frame dropped instance=${connection.instanceId} reason=ingest_unconfigured`,
        );
      }
      return;
    }
    const client = channelOwners.get(channelKey(connection.instanceId, frame.channelId));
    if (!client || client.ws.readyState !== WebSocket.OPEN) return;
    sendJson(client.ws, frame);
  }

  async function handleControl(message: RelayControlMessage) {
    if (message.type === "notify_user") {
      for (const user of usersByConnection.values()) {
        if (user.userId === message.userId) {
          sendJson(user.ws, { v: 1, type: "notification", notification: message.notification });
        }
      }
      return;
    }
    if (message.type === "disconnect_instance") {
      const daemon = daemonsByInstance.get(message.instanceId);
      if (daemon) {
        sendJson(daemon.ws, { v: 1, type: "system", code: "forced_disconnect" });
        daemon.ws.close(CLOSE_FORCED);
      }
      for (const client of clientsByConnection.values()) {
        if (client.instanceId === message.instanceId) {
          sendJson(client.ws, { v: 1, type: "system", code: "forced_disconnect" });
          client.ws.close(CLOSE_FORCED);
        }
      }
      return;
    }
    for (const client of clientsByConnection.values()) {
      if (
        client.userId === message.userId &&
        (!message.instanceId || client.instanceId === message.instanceId)
      ) {
        sendJson(client.ws, { v: 1, type: "system", code: "forced_disconnect" });
        client.ws.close(CLOSE_FORCED);
      }
    }
    for (const user of usersByConnection.values()) {
      if (user.userId === message.userId) {
        sendJson(user.ws, { v: 1, type: "system", code: "forced_disconnect" });
        user.ws.close(CLOSE_FORCED);
      }
    }
  }

  const heartbeat = setInterval(() => {
    for (const connection of [
      ...daemonsByInstance.values(),
      ...clientsByConnection.values(),
      ...usersByConnection.values(),
    ]) {
      if (!connection.isAlive) {
        connection.ws.terminate();
        continue;
      }
      connection.isAlive = false;
      connection.ws.ping();
    }
  }, config.heartbeatMs);
  heartbeat.unref();

  const controlIngestConfigured = Boolean(config.controlIngestUrl && config.controlSecret);
  if (config.controlIngestUrl && !config.controlSecret) {
    logger.error(
      "[relay] RELAY_CONTROL_INGEST_URL is set but RELAY_CONTROL_SECRET is missing; control ingest is disabled",
    );
  }

  let unsubscribeControl: (() => Promise<void>) | undefined;
  void presenceStore
    .subscribeControl((message) => void handleControl(message))
    .then((unsubscribe) => {
      unsubscribeControl = unsubscribe;
    });

  async function handleUpgrade(
    kind: "daemon" | "client" | "user",
    request: IncomingMessage,
    socket: Duplex,
    head: Buffer,
  ) {
    const url = new URL(request.url ?? "/", "http://relay.local");
    const token = bearerToken(request, url);
    let payload: RelayTokenPayload;
    try {
      payload = await verifyToken(token);
    } catch {
      writeHttp(socket, 401, "Unauthorized");
      return;
    }
    const wss = kind === "daemon" ? daemonWss : kind === "client" ? clientWss : userWss;
    wss.handleUpgrade(request, socket, head, (ws) => {
      if (kind === "daemon") return void registerDaemon(ws, payload);
      if (kind === "client") return void registerClient(ws, payload);
      registerUser(ws, payload);
    });
  }

  const server = createServer(async (request: IncomingMessage, response: ServerResponse) => {
    const url = new URL(request.url ?? "/", "http://relay.local");
    if (request.method === "GET" && url.pathname === "/healthz") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, relayId: config.relayId }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/control") {
      if (!config.controlSecret) {
        response.writeHead(404, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "not_found" }));
        return;
      }
      const auth = request.headers.authorization ?? "";
      if (auth !== `Bearer ${config.controlSecret}`) {
        response.writeHead(401, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      try {
        const body = await readJsonBody(request, config.maxFrameBytes);
        const message = relayControlMessageSchema.parse(body);
        await handleControl(message);
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ ok: true }));
      } catch {
        response.writeHead(400, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "bad_request" }));
      }
      return;
    }
    if (request.method === "GET" && url.pathname === "/metrics") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          relayId: config.relayId,
          daemons: daemonsByInstance.size,
          clients: clientsByConnection.size,
          users: usersByConnection.size,
          frames: totalFrames,
          bytes: totalBytes,
        }),
      );
      return;
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not_found" }));
  });

  server.on("upgrade", (request, socket, head) => {
    const url = new URL(request.url ?? "/", "http://relay.local");
    if (url.pathname === "/ws/daemon") return void handleUpgrade("daemon", request, socket, head);
    if (url.pathname === "/ws/client") return void handleUpgrade("client", request, socket, head);
    if (url.pathname === "/ws/user") return void handleUpgrade("user", request, socket, head);
    writeHttp(socket, 404, "Not Found");
  });

  if (config.port) server.listen(config.port);

  return {
    server,
    presenceStore,
    publishControl(message) {
      return presenceStore.publishControl(message);
    },
    async close() {
      clearInterval(heartbeat);
      await unsubscribeControl?.();
      for (const ws of [...daemonWss.clients, ...clientWss.clients, ...userWss.clients]) ws.close();
      if (server.listening) {
        await new Promise<void>((resolve, reject) =>
          server.close((err) => (err ? reject(err) : resolve())),
        );
      }
      await presenceStore.close();
    },
  };
}
