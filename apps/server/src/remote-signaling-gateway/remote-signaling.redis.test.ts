/**
 * Real-Redis integration for the signaling gateway. Named `*.redis.test.ts` so it
 * only runs when `TEST_REDIS_URL` is set. Two gateway replicas over two loopback
 * servers share one Redis via `RedisRemoteSignalingAttemptStore` +
 * `RedisRemoteSignalingWakeSubscription`, so daemon auth, client admission, relay,
 * the single-use ticket, and the per-attachment lease cap are exercised against
 * the authoritative store — not the memory parity.
 */

import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { MemoryRemoteDaemonControlOutboxStore } from "@flycockpit/api/lib/remote-daemon-control-outbox";
import {
  RedisRemoteSignalingAttemptStore,
  type RemoteSignalingAttemptStore,
} from "@flycockpit/api/lib/remote-signaling-store";
import { createRedisConnection } from "@flycockpit/queue/connection";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type WebSocket from "ws";
import {
  installRemoteSignalingGateway,
  RedisRemoteSignalingWakeSubscription,
} from "../remote-signaling-runtime";
import { encodeFcsaFrame } from "./binary-codecs";
import {
  REMOTE_GATEWAY_CLOSE_CODE,
  REMOTE_GATEWAY_SUBPROTOCOL,
  REMOTE_GATEWAY_WS_PATH,
} from "./close-codes";
import {
  actor,
  buildRingVerifier,
  CONFIGURED_ORIGIN,
  clientAdmissionProofPayload,
  connectWithQueue,
  id,
  makeIdentityRing,
  mintDaemonCertificate,
  request,
  sha256Bytes,
  signFcda,
  type TestIdentityRing,
} from "./identity-fixtures";
import { NoopLogger, waitForClose } from "./test-fixtures";

const url = process.env.TEST_REDIS_URL;
if (!url) throw new Error("TEST_REDIS_URL is required for the Redis integration suite");
const redisUrl = url;

type RedisConnection = ReturnType<typeof createRedisConnection>;

interface RedisReplica {
  store: RemoteSignalingAttemptStore;
  server: Server;
  url: string;
  command: RedisConnection;
  close(): Promise<void>;
}

async function startRedisReplica(ring: TestIdentityRing): Promise<RedisReplica> {
  const command = createRedisConnection({ url: redisUrl, maxRetriesPerRequest: 1 });
  const subscription = createRedisConnection({ url: redisUrl, maxRetriesPerRequest: null });
  const store = new RedisRemoteSignalingAttemptStore(command);
  const wake = new RedisRemoteSignalingWakeSubscription(subscription);
  const server = createServer();
  const installed = installRemoteSignalingGateway(server, {
    configuredOrigin: CONFIGURED_ORIGIN,
    store,
    controlOutbox: new MemoryRemoteDaemonControlOutboxStore(),
    daemonCertificateVerifier: buildRingVerifier(ring.ring),
    wake,
    logger: new NoopLogger(),
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    store,
    server,
    command,
    url: `ws://127.0.0.1:${port}${REMOTE_GATEWAY_WS_PATH}`,
    close: async () => {
      await installed.close().catch(() => {});
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        setTimeout(() => resolve(), 2_000).unref();
      });
    },
  };
}

function racedClose(ws: WebSocket, ms: number): Promise<{ closed: boolean; code?: number }> {
  return Promise.race([
    waitForClose(ws).then((closed) => ({ closed: true, code: closed.code })),
    new Promise<{ closed: false }>((resolve) => setTimeout(() => resolve({ closed: false }), ms)),
  ]);
}

describe("remote_signaling_gateway_redis", () => {
  const instances: string[] = [];
  let ring: TestIdentityRing;
  let replicaA: RedisReplica;
  let replicaB: RedisReplica;

  const attempt = (instance: string, transportKind: "webrtc" | "websocket_data" = "webrtc") => ({
    daemonInstanceId: instance,
    childAttemptId: id(1),
    transportKind,
    participantRefs: ["opaque-a", "opaque-b"] as const,
  });

  /** Seed a daemon_offered attempt on a store and mint its single-use ticket. */
  async function seed(
    store: RemoteSignalingAttemptStore,
    instance: string,
    child: Uint8Array,
    attachment: string,
  ) {
    await store.create(
      { ...attempt(instance), childAttemptId: child },
      request(1, 1, 1, 1, child),
      actor("server"),
    );
    await store.commit(instance, child, request(2, 3, 2, 1, child), actor("daemon"));
    const proofBytes = clientAdmissionProofPayload({ childAttemptId: child });
    const { ticketId, secret } = await store.issueClientAdmissionTicket({
      daemonInstanceId: instance,
      childAttemptId: child,
      originClass: "browser_same_origin",
      accountId: "acct-redis",
      deviceAttachmentId: attachment,
      deviceGeneration: 5n,
      admissionProofSha256: sha256Bytes(proofBytes),
    });
    return { ticketId, secret, proofBytes };
  }

  function newInstance(): string {
    const instance = randomBytes(16).toString("base64url");
    instances.push(instance);
    return instance;
  }

  beforeAll(async () => {
    ring = makeIdentityRing();
    replicaA = await startRedisReplica(ring);
    replicaB = await startRedisReplica(ring);
  });

  afterAll(async () => {
    for (const instance of instances) {
      const keys = await replicaA.command.keys(`flycockpit:remote-signaling:{${instance}}*`);
      if (keys.length) await replicaA.command.del(...keys);
    }
    await replicaA.close();
    await replicaB.close();
  });

  it("authenticates a daemon control socket on replica A", async () => {
    const cert = mintDaemonCertificate({
      ring: ring.ring,
      kid: ring.kid,
      ringPrivateKey: ring.privateKey,
    });
    instances.push(cert.instanceId);
    const { ws, queue } = await connectWithQueue(replicaA.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.control,
    });
    const fcdc = await queue.next();
    ws.send(
      Buffer.from(
        signFcda({
          fcdcFrame: fcdc,
          certJws: cert.certJws,
          daemonPrivateKey: cert.daemonPrivateKey,
          instanceProtocolId: cert.instanceProtocolId,
          certificateGeneration: cert.certificateGeneration,
        }),
      ),
    );
    const outcome = await racedClose(ws, 500);
    expect(outcome.closed).toBe(false);
    ws.close();
  }, 15_000);

  it("admits a client on replica B and relays a cross-replica peer event", async () => {
    const instance = newInstance();
    const { ticketId, secret, proofBytes } = await seed(
      replicaB.store,
      instance,
      id(1),
      "attach-b",
    );
    const { ws, queue } = await connectWithQueue(replicaB.url, {
      subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
      headers: { origin: CONFIGURED_ORIGIN },
    });
    ws.send(
      Buffer.from(encodeFcsaFrame({ ticketId, ticketSecret: secret, admissionProof: proofBytes })),
    );
    // Two initial peer deliveries prove the admission committed.
    expect((await queue.next()).length).toBeGreaterThan(0);
    expect((await queue.next()).length).toBeGreaterThan(0);

    // Client offer -> exact FCAK ack (relay round-trip on B).
    ws.send(Buffer.from(request(4, 2, 4, 1, id(1))));
    const ack = await queue.next();
    const page = await replicaB.store.read(instance, id(1), 0n);
    expect(page.kind).toBe("events");
    if (page.kind === "events") {
      const committed = page.events.find((event) => event.sequence === 4n);
      expect(Buffer.from(ack)).toEqual(Buffer.from(committed!.ackBytes));
    }

    // Daemon answer committed via replica A -> delivered to B's socket over Redis wake.
    const answer = request(5, 3, 5, 1, id(1));
    await replicaA.store.commit(instance, id(1), answer, actor("daemon"));
    expect(Buffer.from(await queue.next())).toEqual(Buffer.from(answer));
    ws.close();
  }, 15_000);

  it("admits exactly one of two racing sockets sharing a single-use ticket", async () => {
    const instance = newInstance();
    const { ticketId, secret, proofBytes } = await seed(
      replicaA.store,
      instance,
      id(1),
      "attach-race",
    );
    const connect = (target: RedisReplica, proof: Uint8Array) =>
      connectWithQueue(target.url, {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
        headers: { origin: CONFIGURED_ORIGIN },
      }).then(({ ws, queue }) => {
        ws.send(
          Buffer.from(encodeFcsaFrame({ ticketId, ticketSecret: secret, admissionProof: proof })),
        );
        return { ws, queue };
      });
    // The ticket is bound to `proofBytes`; a distinct proof (fresh proofJti) can
    // never satisfy the digest, so the single-use ticket admits exactly one.
    const distinctProof = clientAdmissionProofPayload({ proofJti: id(200) });
    const first = await connect(replicaA, proofBytes);
    const second = await connect(replicaB, distinctProof);
    const secondClosed = await waitForClose(second.ws);
    expect(secondClosed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.authentication_failed);
    const firstOutcome = await racedClose(first.ws, 500);
    expect(firstOutcome.closed).toBe(false);
    first.ws.close();
  }, 15_000);

  it("closes the third concurrent admit for one attachment with 4409", async () => {
    const instance = newInstance();
    const attachment = "attach-cap";
    const admit = async (target: RedisReplica, child: Uint8Array) => {
      const { ticketId, secret, proofBytes } = await seed(
        target.store,
        instance,
        child,
        attachment,
      );
      const { ws, queue } = await connectWithQueue(target.url, {
        subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
        headers: { origin: CONFIGURED_ORIGIN },
      });
      ws.send(
        Buffer.from(
          encodeFcsaFrame({ ticketId, ticketSecret: secret, admissionProof: proofBytes }),
        ),
      );
      return { ws, queue };
    };
    const a = await admit(replicaA, id(1));
    await a.queue.next();
    const b = await admit(replicaB, id(2));
    await b.queue.next();
    const c = await admit(replicaA, id(3));
    const closed = await waitForClose(c.ws);
    expect(closed.code).toBe(REMOTE_GATEWAY_CLOSE_CODE.conflict_or_superseded);
    a.ws.close();
    b.ws.close();
  }, 20_000);
});
