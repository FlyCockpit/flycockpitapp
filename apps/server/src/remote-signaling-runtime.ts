/**
 * Composition + wiring for the remote signaling gateway (mirrors
 * `remote-fallback-runtime.ts`). Owns the single `upgrade` dispatcher that routes
 * `/api/remote/ws` to the gateway and destroys every other upgrade socket
 * (leaving an explicit seam where the WebSocket data-fallback path will attach),
 * builds the identity-CA-backed daemon certificate verifier fail-closed, and the
 * lazy Redis command/subscription connections.
 */
import { readFileSync } from "node:fs";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import {
  type AuthorityRingFile,
  authorityRingDigest,
  CachedAuthorityVerifier,
  normalizeAuthorityIssuer,
  parseAuthorityConfig,
  parseAuthorityRingFile,
} from "@flycockpit/api/lib/remote-authority";
import {
  RedisRemoteSignalingAttemptStore,
  type RemoteSignalingAttemptStore,
} from "@flycockpit/api/lib/remote-signaling-store";
import type { env as envType } from "@flycockpit/env/server";
import { createRedisConnection } from "@flycockpit/queue/connection";
import { resolveClientIpFromParts } from "./client-ip.js";
import { REMOTE_GATEWAY_WS_PATH } from "./remote-signaling-gateway/close-codes";
import {
  type DaemonCertificateVerifier,
  RingDaemonCertificateVerifier,
} from "./remote-signaling-gateway/daemon-certificate-verifier";
import {
  RemoteSignalingGateway,
  type RemoteSignalingGatewayConfig,
  type SafeLogger,
} from "./remote-signaling-gateway/gateway";
import {
  type MonotonicClock,
  UnauthUpgradeRateLimiter,
} from "./remote-signaling-gateway/rate-limiters";
import type { RemoteSignalingWakeSubscription } from "./remote-signaling-gateway/wake-subscription";

type Redis = ReturnType<typeof createRedisConnection>;

interface UpgradableServer {
  on(
    event: "upgrade",
    listener: (request: IncomingMessage, socket: Duplex, head: Buffer) => void,
  ): unknown;
  off(
    event: "upgrade",
    listener: (request: IncomingMessage, socket: Duplex, head: Buffer) => void,
  ): unknown;
}

const systemMonotonicClock: MonotonicClock = { nowMs: () => performance.now() };

export interface InstallRemoteSignalingGatewayDeps {
  configuredOrigin: string;
  store: RemoteSignalingAttemptStore;
  daemonCertificateVerifier: DaemonCertificateVerifier;
  wake: RemoteSignalingWakeSubscription;
  clock?: MonotonicClock;
  unauthUpgradeLimiter?: UnauthUpgradeRateLimiter;
  now?: () => number;
  logger?: SafeLogger;
  policy?: RemoteSignalingGatewayConfig["policy"];
  /** Seam for the WebSocket data-fallback path. Return true if it handled the upgrade. */
  additionalUpgrade?: (request: IncomingMessage, socket: Duplex, head: Buffer) => boolean;
}

export interface InstalledRemoteSignalingGateway {
  gateway: RemoteSignalingGateway;
  /** Stop upgrades, close sockets 1001, and close the wake + store connections. */
  close(): Promise<void>;
}

/**
 * Attach the gateway and a single upgrade dispatcher to a Node HTTP server.
 * `/api/remote/ws` routes to the gateway; every other upgrade socket is
 * destroyed (no FD leak, no hang) unless an injected `additionalUpgrade` seam
 * handles it.
 */
export function installRemoteSignalingGateway(
  server: UpgradableServer,
  deps: InstallRemoteSignalingGatewayDeps,
): InstalledRemoteSignalingGateway {
  const clock = deps.clock ?? systemMonotonicClock;
  const gateway = new RemoteSignalingGateway({
    configuredOrigin: deps.configuredOrigin,
    store: deps.store,
    clock,
    unauthUpgradeLimiter: deps.unauthUpgradeLimiter ?? new UnauthUpgradeRateLimiter(clock),
    daemonCertificateVerifier: deps.daemonCertificateVerifier,
    wake: deps.wake,
    now: deps.now,
    logger: deps.logger,
    policy: deps.policy,
  });

  const onUpgrade = (request: IncomingMessage, socket: Duplex, head: Buffer) => {
    const url = new URL(request.url ?? "/", "http://gateway.local");
    if (url.pathname === REMOTE_GATEWAY_WS_PATH) {
      const clientIp = resolveClientIpFromParts(
        request.headers["x-forwarded-for"],
        request.socket.remoteAddress,
      );
      gateway.handleUpgrade(request, socket, head, clientIp);
      return;
    }
    // Seam: wire-websocket-fallback-into-transport-selection adds its path here.
    if (deps.additionalUpgrade?.(request, socket, head)) return;
    socket.destroy();
  };
  server.on("upgrade", onUpgrade);

  return {
    gateway,
    async close() {
      server.off("upgrade", onUpgrade);
      await gateway.close();
      await deps.wake.close().catch(() => {});
      await deps.store.close().catch(() => {});
    },
  };
}

/**
 * Build the daemon identity-CA certificate verifier from its dedicated env group.
 * Returns `undefined` when the group is entirely absent (feature off); throws
 * (fail closed) when it is partial or the ring is unparseable / not digest-pinned.
 * The grant-signing ring is deliberately never the trust anchor here.
 */
export function loadDaemonIdentityCaVerifier(
  env: typeof envType,
  nowSeconds: () => number,
): DaemonCertificateVerifier | undefined {
  const file = env.REMOTE_DAEMON_IDENTITY_CA_KEY_FILE;
  const digests = env.REMOTE_DAEMON_IDENTITY_CA_KEY_DIGESTS;
  if (file === undefined && digests === undefined) return undefined;
  if (
    file === undefined ||
    digests === undefined ||
    env.REMOTE_AUTHORITY_ISSUER === undefined ||
    env.REMOTE_AUTHORITY_DEPLOYMENT_ID === undefined
  )
    throw new Error(
      "daemon identity-CA ring requires REMOTE_DAEMON_IDENTITY_CA_KEY_FILE, REMOTE_DAEMON_IDENTITY_CA_KEY_DIGESTS, REMOTE_AUTHORITY_ISSUER, and REMOTE_AUTHORITY_DEPLOYMENT_ID together",
    );

  const issuer = normalizeAuthorityIssuer(env.REMOTE_AUTHORITY_ISSUER);
  const deploymentId = env.REMOTE_AUTHORITY_DEPLOYMENT_ID;
  const config = parseAuthorityConfig({ issuer, deploymentId, digests });
  const loadRing = (): AuthorityRingFile =>
    parseAuthorityRingFile(JSON.parse(readFileSync(file, "utf8")));
  const ring = loadRing();
  const ringDigest = authorityRingDigest(ring, {
    issuer: config.issuer,
    deploymentId: config.deploymentId,
  });
  if (!config.allowedDigests.includes(ringDigest))
    throw new Error("daemon identity-CA ring digest is not in the pinned digest set");

  const ringVerifier = new CachedAuthorityVerifier(config.issuer, ring, nowSeconds, async () =>
    loadRing(),
  );
  return new RingDaemonCertificateVerifier(ringVerifier, config.issuer);
}

/** Redis Pub/Sub wake source over the store's existing attempt/instance wake channels. */
export class RedisRemoteSignalingWakeSubscription implements RemoteSignalingWakeSubscription {
  private readonly attemptHandlers = new Map<string, Set<() => void>>();
  private readonly instanceHandlers = new Map<string, Set<() => void>>();
  private static readonly ATTEMPT_PREFIX = "flycockpit:remote-signaling:attempt-wake:";
  private static readonly INSTANCE_PREFIX = "flycockpit:remote-signaling:instance-wake:";
  private ready: Promise<void> | undefined;

  constructor(private readonly conn: Redis) {}

  private ensureSubscribed(): Promise<void> {
    this.ready ??= (async () => {
      this.conn.on("pmessage", (_pattern: string, channel: string) => {
        if (channel.startsWith(RedisRemoteSignalingWakeSubscription.ATTEMPT_PREFIX)) {
          const key = channel.slice(RedisRemoteSignalingWakeSubscription.ATTEMPT_PREFIX.length);
          for (const handler of this.attemptHandlers.get(key) ?? []) handler();
        } else if (channel.startsWith(RedisRemoteSignalingWakeSubscription.INSTANCE_PREFIX)) {
          const key = channel.slice(RedisRemoteSignalingWakeSubscription.INSTANCE_PREFIX.length);
          for (const handler of this.instanceHandlers.get(key) ?? []) handler();
        }
      });
      await this.conn.psubscribe(
        `${RedisRemoteSignalingWakeSubscription.ATTEMPT_PREFIX}*`,
        `${RedisRemoteSignalingWakeSubscription.INSTANCE_PREFIX}*`,
      );
    })();
    return this.ready;
  }

  private subscribe(
    map: Map<string, Set<() => void>>,
    key: string,
    handler: () => void,
  ): () => void {
    void this.ensureSubscribed();
    let set = map.get(key);
    if (!set) {
      set = new Set();
      map.set(key, set);
    }
    set.add(handler);
    return () => {
      const current = map.get(key);
      if (!current) return;
      current.delete(handler);
      if (current.size === 0) map.delete(key);
    };
  }

  subscribeAttempt(routeId: Uint8Array, handler: () => void): () => void {
    return this.subscribe(this.attemptHandlers, Buffer.from(routeId).toString("hex"), handler);
  }
  subscribeInstance(routeId: Uint8Array, handler: () => void): () => void {
    return this.subscribe(this.instanceHandlers, Buffer.from(routeId).toString("hex"), handler);
  }
  async close(): Promise<void> {
    await this.conn.quit().catch(() => {});
  }
}

export interface CreateServerRemoteSignalingGatewayDeps {
  env: typeof envType;
  server: UpgradableServer;
  /** Injected connection factory (tests). Defaults to `createRedisConnection`. */
  redisFactory?: () => Redis;
  logger?: SafeLogger;
}

/**
 * Production wiring. Installs the gateway only when the daemon identity-CA ring
 * is configured; when remote authority is enabled but the identity-CA ring is
 * missing, throws (fail closed — never an accept-any-cert path). Returns
 * `undefined` when the feature is off.
 */
export function createServerRemoteSignalingGateway(
  deps: CreateServerRemoteSignalingGatewayDeps,
): InstalledRemoteSignalingGateway | undefined {
  const { env } = deps;
  const verifier = loadDaemonIdentityCaVerifier(env, () => Math.floor(Date.now() / 1000));
  const remoteAuthorityConfigured = env.REMOTE_GRANT_SIGNING_KEY_FILE !== undefined;

  if (!verifier) {
    if (remoteAuthorityConfigured)
      throw new Error(
        "remote signaling gateway requires the daemon identity-CA ring (REMOTE_DAEMON_IDENTITY_CA_KEY_FILE / REMOTE_DAEMON_IDENTITY_CA_KEY_DIGESTS) when remote authority is configured",
      );
    return undefined;
  }

  const makeRedis = deps.redisFactory ?? (() => createRedisConnection({ maxRetriesPerRequest: 3 }));
  const store = new RedisRemoteSignalingAttemptStore(makeRedis());
  const wake = new RedisRemoteSignalingWakeSubscription(
    deps.redisFactory ? deps.redisFactory() : createRedisConnection({ maxRetriesPerRequest: null }),
  );
  const configuredOrigin = new URL(env.CORS_ORIGIN ?? env.BETTER_AUTH_URL).origin;

  return installRemoteSignalingGateway(deps.server, {
    configuredOrigin,
    store,
    daemonCertificateVerifier: verifier,
    wake,
    logger: deps.logger,
  });
}
