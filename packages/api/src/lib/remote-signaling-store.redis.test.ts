import { randomBytes } from "node:crypto";
import {
  decodeRemoteSignalingEventRequestV1,
  encodeDaemonAdmissionOfferV1,
  encodeRemoteChildAuthenticationBundleV1,
  encodeRemoteSignalingEventRequestV1,
  remoteChildAuthenticationDigests,
} from "@flycockpit/cockpit-protocol";
import { createRedisConnection } from "@flycockpit/queue/connection";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RedisRemoteSignalingAttemptStore } from "./remote-signaling-store";

const url = process.env.TEST_REDIS_URL;
if (!url) throw new Error("TEST_REDIS_URL is required for the Redis integration suite");
const instance = randomBytes(16).toString("base64url");
const id = (start: number) => Uint8Array.from({ length: 16 }, (_, index) => start + index);
const digest = (start: number) => Uint8Array.from({ length: 32 }, (_, index) => start + index);
const actor = (role: "server" | "client" | "daemon") => ({
  role,
  actor: `redis-${role}`,
  generation: 1n,
});
const request = (kind: number, role: 1 | 2 | 3, event: number, childAttemptId = id(1)) =>
  encodeRemoteSignalingEventRequestV1({
    transport: 1,
    producerRole: role,
    eventKind: kind as 1,
    childAttemptId,
    eventId: id(event),
    payload:
      kind === 1
        ? encodeRemoteChildAuthenticationBundleV1({
            childAttemptId,
            grantJws: Uint8Array.of(1),
            clientCertificateJws: Uint8Array.of(2),
            daemonCertificateJws: Uint8Array.of(3),
            authorityStatusJws: Uint8Array.of(4),
            servicePolicyJws: Uint8Array.of(5),
          })
        : kind === 2
          ? encodeDaemonAdmissionOfferV1({
              instanceId: id(20),
              daemonDeviceId: id(40),
              daemonDeviceGeneration: 1n,
              daemonCertificateId: id(60),
              daemonCertificateGeneration: 1n,
              logicalAttachmentId: id(80),
              childAttemptId,
              grantJti: id(100),
              grantDigest: digest(1),
              serverNonce: digest(40),
              serviceVersion: 1n,
              policyEpoch: 1n,
              policyDigest: digest(80),
              authorizedTransportBits: 1,
              daemonTupleIds: [1],
              offerJti: id(120),
              issuedAt: 1n,
              expiresAt: 2n,
              signature: new Uint8Array(64).fill(9),
            })
          : new Uint8Array(),
  });

describe("real Redis remote signaling reducer", () => {
  let redisA: ReturnType<typeof createRedisConnection>;
  let redisB: ReturnType<typeof createRedisConnection>;
  let storeA: RedisRemoteSignalingAttemptStore;
  let storeB: RedisRemoteSignalingAttemptStore;
  beforeAll(async () => {
    redisA = createRedisConnection({ url, maxRetriesPerRequest: 1 });
    redisB = createRedisConnection({ url, maxRetriesPerRequest: 1 });
    storeA = new RedisRemoteSignalingAttemptStore(redisA, (out) => out.fill(9));
    storeB = new RedisRemoteSignalingAttemptStore(redisB, (out) => out.fill(10));
  });
  afterAll(async () => {
    const keys = await redisA.keys(`flycockpit:remote-signaling:{${instance}}:*`);
    if (keys.length) await redisA.del(...keys);
    await Promise.all([storeA.close(), storeB.close()]);
  });

  it("remote_signaling_concurrent_writers_are_linearized", async () => {
    const input = {
      daemonInstanceId: instance,
      childAttemptId: id(1),
      transportKind: "webrtc" as const,
      participantRefs: ["opaque-a", "opaque-b"] as const,
    };
    await storeA.create(input, request(1, 1, 40), actor("server"));
    const offer = request(2, 3, 41);
    const [left, right] = await Promise.all([
      storeA.commit(input.daemonInstanceId, id(1), offer, actor("daemon")),
      storeB.commit(input.daemonInstanceId, id(1), offer, actor("daemon")),
    ]);
    expect(new Set([left.kind, right.kind])).toEqual(new Set(["committed", "replay"]));
    expect(left.sequence).toBe(2n);
    expect(right.sequence).toBe(2n);
    const keys = await redisA.keys(`flycockpit:remote-signaling:{${instance}}:*`);
    expect(keys.sort()).toEqual([
      `flycockpit:remote-signaling:{${instance}}:attempt:AQIDBAUGBwgJCgsMDQ4PEA:events`,
      `flycockpit:remote-signaling:{${instance}}:attempt:AQIDBAUGBwgJCgsMDQ4PEA:idempotency`,
      `flycockpit:remote-signaling:{${instance}}:attempt:AQIDBAUGBwgJCgsMDQ4PEA:metadata`,
    ]);
    expect(await Promise.all(keys.map((key) => redisA.type(key)))).toEqual(
      expect.arrayContaining(["hash", "stream", "hash"]),
    );
  });
  it("remote_signaling_cursor_replay_survives_missed_pubsub", async () => {
    const child = id(2),
      available = request(1, 1, 60, child),
      bundle = decodeRemoteSignalingEventRequestV1(available).payload,
      lease = await storeA.authenticateInstanceWake(instance, 7n, 3n, 0n),
      input = {
        daemonInstanceId: instance,
        childAttemptId: child,
        transportKind: "webrtc" as const,
        participantRefs: ["opaque-c", "opaque-d"] as const,
        discovery: {
          daemonCertificateGeneration: 7n,
          discoveryId: id(80),
          authBundleDigest: remoteChildAuthenticationDigests(bundle).authBundleDigest,
        },
      };
    await storeA.create(input, available, actor("server"));
    const discovered = await storeA.readDiscovery(instance, 7n, 3n, 0n);
    expect(discovered.kind).toBe("entries");
    if (discovered.kind === "entries") expect(discovered.entries[0]?.childAttemptId).toEqual(child);
    await storeA.ackDiscovery(instance, 7n, 3n, 0n, 1n);
    expect(await storeA.discoveryHighWater(instance, 7n)).toBe(1n);
    await storeA.closeInstanceWake(instance, 7n, lease);
  });
});
