/**
 * Real-Redis multi-replica control-outbox wake integration. Named
 * `*.redis.test.ts` so it only runs when `TEST_REDIS_URL` is set. Two gateway
 * replicas over two loopback servers share one Redis (attempt store + wake bus)
 * and one control outbox (memory double standing in for the shared Postgres
 * authority). A control-outbox append + `notifyDaemonControlOutboxAppend` wake
 * on one connection reaches the replica holding the socket; the other no-ops.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  MemoryRemoteDaemonControlOutboxStore,
  notifyDaemonControlOutboxAppend,
} from "@flycockpit/api/lib/remote-daemon-control-outbox";
import { RedisRemoteSignalingAttemptStore } from "@flycockpit/api/lib/remote-signaling-store";
import { createRedisConnection } from "@flycockpit/queue/connection";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  installRemoteSignalingGateway,
  RedisRemoteSignalingWakeSubscription,
} from "../remote-signaling-runtime";
import { REMOTE_GATEWAY_SUBPROTOCOL, REMOTE_GATEWAY_WS_PATH } from "./close-codes";
import {
  buildRingVerifier,
  connectWithQueue,
  makeIdentityRing,
  mintDaemonCertificate,
  signFcda,
  type TestIdentityRing,
} from "./identity-fixtures";
import { NoopLogger, waitForClose } from "./test-fixtures";

const url = process.env.TEST_REDIS_URL;
if (!url) throw new Error("TEST_REDIS_URL is required for the Redis integration suite");
const redisUrl = url;

type RedisConnection = ReturnType<typeof createRedisConnection>;

interface RedisReplica {
  server: Server;
  url: string;
  command: RedisConnection;
  close(): Promise<void>;
}

const te = new TextEncoder();
const eid = (n: number): Uint8Array => {
  const bytes = new Uint8Array(16);
  bytes[15] = n & 0xff;
  return bytes;
};

async function startReplica(
  ring: TestIdentityRing,
  controlOutbox: MemoryRemoteDaemonControlOutboxStore,
): Promise<RedisReplica> {
  const command = createRedisConnection({ url: redisUrl, maxRetriesPerRequest: 1 });
  const subscription = createRedisConnection({ url: redisUrl, maxRetriesPerRequest: null });
  const server = createServer();
  const installed = installRemoteSignalingGateway(server, {
    configuredOrigin: "https://app.example.test",
    store: new RedisRemoteSignalingAttemptStore(command),
    controlOutbox,
    daemonCertificateVerifier: buildRingVerifier(ring.ring),
    wake: new RedisRemoteSignalingWakeSubscription(subscription),
    logger: new NoopLogger(),
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
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

describe("remote_gateway_control_outbox_wake_multi_replica", () => {
  const outbox = new MemoryRemoteDaemonControlOutboxStore();
  let ring: TestIdentityRing;
  let replicaA: RedisReplica;
  let replicaB: RedisReplica;
  const instances: string[] = [];

  beforeAll(async () => {
    ring = makeIdentityRing();
    replicaA = await startReplica(ring, outbox);
    replicaB = await startReplica(ring, outbox);
  });

  afterAll(async () => {
    for (const instance of instances) {
      const keys = await replicaA.command.keys(`flycockpit:remote-signaling:{${instance}}*`);
      if (keys.length) await replicaA.command.del(...keys);
    }
    await replicaA.close();
    await replicaB.close();
  });

  it("wakes only the replica holding the control socket", async () => {
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
    // Let control auth settle (presence lease + wake subscription established).
    await new Promise((resolve) => setTimeout(resolve, 200));

    const jws = "eyJhbGciOiJFUzI1NiJ9.eyJzZXEiOjF9.multi-replica";
    outbox.append({
      daemonInstanceProtocolId: cert.instanceId,
      daemonCertificateGeneration: cert.certificateGeneration,
      controlSeq: 1n,
      eventId: eid(1),
      controlEventJws: jws,
    });
    // Wake is published from replica B's connection; only replica A (which holds
    // the socket + subscription) delivers.
    await notifyDaemonControlOutboxAppend(replicaB.command, {
      daemonInstanceProtocolId: cert.instanceId,
      daemonCertificateGeneration: cert.certificateGeneration,
      highWaterSeq: 1n,
    });

    expect(Buffer.from(await queue.next())).toEqual(Buffer.from(te.encode(jws)));
    ws.close();
    await waitForClose(ws);
  }, 20_000);
});
