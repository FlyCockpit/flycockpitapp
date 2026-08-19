import { randomBytes } from "node:crypto";
import {
  decodeRemoteSignalingEventRequestV1,
  encodeDaemonAdmissionOfferV1,
  encodeRemoteChildAuthenticationBundleV1,
  encodeRemoteSignalingEventRequestV1,
  encodeRemoteWebRtcCandidateV1,
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
        : kind === 6
          ? encodeRemoteWebRtcCandidateV1({
              role: (role === 2 ? 1 : 2) as 1 | 2,
              childAttemptId,
              transportEpoch: id(90),
              candidateId: id(event),
              sdpMid: "0",
              sdpMLineIndex: 0,
              candidate: "candidate:1 1 UDP 1 192.0.2.1 9 typ host",
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
const attemptMetadataKey = (child: Uint8Array) =>
  `flycockpit:remote-signaling:{${instance}}:attempt:${Buffer.from(child).toString("base64url")}:metadata`;
const input = (child: Uint8Array, participantRefs: readonly [string, string]) => ({
  daemonInstanceId: instance,
  childAttemptId: child,
  transportKind: "webrtc" as const,
  participantRefs,
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

  it("redis_signaling_absolute_ttl_never_refreshes", async () => {
    const child = id(31);
    await storeA.create(
      input(child, ["opaque-ttl-a", "opaque-ttl-b"]),
      request(1, 1, 30, child),
      actor("server"),
    );
    const meta0 = await storeA.metadata(instance, child);
    if (!("expiresAtMs" in meta0)) throw new Error("attempt metadata should exist after create");
    // A successful commit must NOT slide the absolute deadline forward.
    await storeA.commit(instance, child, request(2, 3, 31, child), actor("daemon"));
    const meta1 = await storeA.metadata(instance, child);
    if (!("expiresAtMs" in meta1)) throw new Error("attempt metadata should still exist");
    expect(meta1.expiresAtMs).toBe(meta0.expiresAtMs);
    // Force the absolute deadline into the past: activity must not have extended
    // it, so the reducer fails closed and purges state rather than refreshing.
    await redisA.hset(attemptMetadataKey(child), "expiresAtMs", "1");
    await expect(
      storeA.commit(instance, child, request(2, 3, 32, child), actor("daemon")),
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(await storeA.metadata(instance, child)).toEqual({ kind: "unavailable" });
  });

  it("redis_signaling_limits_are_atomic", async () => {
    const child = id(41);
    await storeA.create(
      input(child, ["opaque-lim-a", "opaque-lim-b"]),
      request(1, 1, 40, child),
      actor("server"),
    );
    // Drive directly to `offered` so the ICE-candidate cap (the reducer limit
    // under test) is exercised without the full admission handshake.
    await redisA.hset(attemptMetadataKey(child), "state", "offered");
    for (let index = 0; index < 64; index++)
      await storeA.commit(instance, child, request(6, 2, 100 + index, child), actor("client"));
    const counter = await redisA.hget(attemptMetadataKey(child), "clientCandidates");
    expect(counter).toBe("64");
    // The 65th candidate exceeds the per-role cap and must be rejected...
    await expect(
      storeA.commit(instance, child, request(6, 2, 200, child), actor("client")),
    ).rejects.toMatchObject({ code: "invalid_transition" });
    // ...atomically: the rejected commit performed no partial mutation.
    expect(await redisA.hget(attemptMetadataKey(child), "clientCandidates")).toBe("64");
    const page = await storeA.read(instance, child, 0n);
    expect(page.kind === "events" && page.latestSequence).toBe(65n);
  });

  it("redis_signaling_wake_route_privacy", async () => {
    const child = id(51);
    const participantA = "opaque-priv-a";
    const participantB = "opaque-priv-b";
    const sub = createRedisConnection({ url, maxRetriesPerRequest: 1 });
    try {
      const received = new Promise<{ channel: string; message: string }>((resolve) => {
        sub.on("pmessage", (_pattern, channel, message) => resolve({ channel, message }));
      });
      await sub.psubscribe("flycockpit:remote-signaling:attempt-wake:*");
      await storeA.create(
        input(child, [participantA, participantB]),
        request(1, 1, 50, child),
        actor("server"),
      );
      const { channel, message } = await received;

      const meta = await storeA.metadata(instance, child);
      const routeId = "attemptWakeRouteId" in meta ? meta.attemptWakeRouteId : undefined;
      if (!routeId) throw new Error("attempt metadata should exist");
      const routeHex = Buffer.from(Array.from(routeId)).toString("hex");
      const childHex = Buffer.from(Array.from(child)).toString("hex");

      // Only the opaque route id rides the fanout channel — not the child id.
      expect(channel).toBe(`flycockpit:remote-signaling:attempt-wake:${routeHex}`);
      expect(routeHex).not.toBe(childHex);

      // The payload carries exactly the route id and the latest sequence.
      const parsed = JSON.parse(message) as Record<string, unknown>;
      expect(Object.keys(parsed).sort()).toEqual(["attemptWakeRouteId", "latestSeq"]);
      expect(parsed.attemptWakeRouteId).toBe(routeHex);
      expect(parsed.latestSeq).toBe("1");

      // Precondition: the participant refs really are held in server state, so
      // their absence from the fanout proves they were withheld, not missing.
      expect(await redisA.hget(attemptMetadataKey(child), "participantA")).toBe(participantA);
      expect(await redisA.hget(attemptMetadataKey(child), "participantB")).toBe(participantB);
      for (const secret of [participantA, participantB, childHex]) {
        expect(message.includes(secret)).toBe(false);
        expect(channel.includes(secret)).toBe(false);
      }
    } finally {
      await sub.quit();
    }
  });
});
