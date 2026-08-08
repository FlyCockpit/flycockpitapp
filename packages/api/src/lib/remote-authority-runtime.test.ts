import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  type AuthorityPrivateKey,
  AuthorityPublicSnapshot,
  type AuthorityRingFile,
  authorityRingDigest,
  createRemoteAuthorityStatusJws,
  FileAuthoritySigner,
  type MembershipSnapshot,
  type ObservationLease,
  type PublicAuthorityRing,
  parseAuthorityRingFile,
  publicAuthorityRing,
  publicAuthorityRingDigest,
  type RemoteAuthorityStatusV1,
  RingAuthorityVerifier,
  reduceAuthorityRollout,
  verifyRemoteAuthorityStatusJws,
} from "./remote-authority";
import {
  type AuthorityLifecycleRecord,
  type AuthorityObservationStore,
  type AuthorityRuntimeStore,
  type FinalizedAuthorityStatus,
  RemoteAuthorityRuntime,
} from "./remote-authority-runtime";

const issuer = "https://authority.example";
const deploymentId = "prod_1";
const issuerDigest = createHash("sha256").update(issuer).digest("hex");

function makeRing(): AuthorityRingFile {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = privateKey.export({ format: "jwk" });
  const key: AuthorityPrivateKey = {
    kid: "k0",
    alg: "ES256",
    kty: "EC",
    crv: "P-256",
    x: jwk.x!,
    y: jwk.y!,
    d: jwk.d!,
    state: "current",
    activatedAt: "1",
    retireAt: null,
  };
  return parseAuthorityRingFile({
    schemaVersion: 1,
    revision: "1",
    authorityEpoch: "1",
    currentKid: "k0",
    keys: [key],
  });
}

function observation(digest: string, replicaId: string, replicaGeneration = "1"): ObservationLease {
  return {
    issuerDigest,
    deploymentId,
    membershipGeneration: "1",
    replicaId,
    replicaGeneration,
    leaseGeneration: "1",
    revision: "1",
    digest,
    currentKid: "k0",
    publicKids: ["k0"],
    authorityEpoch: "1",
    observedRedisTime: "100",
    expiresAt: "130",
  };
}

describe("RemoteAuthorityRuntime outage recovery", () => {
  it("fails closed during Redis loss and requires a newer status before recovering", async () => {
    const ring = makeRing();
    const digest = authorityRingDigest(ring, { issuer, deploymentId });
    const dir = await mkdtemp(join(tmpdir(), "authority-runtime-"));
    const keyFile = join(dir, "ring.json");
    await writeFile(keyFile, JSON.stringify(ring), { mode: 0o600 });
    let now = "100";
    let redisDown = false;
    let lifecycle: AuthorityLifecycleRecord = {
      revision: "1",
      ringDigest: digest,
      authorityEpoch: "1",
      currentKid: "k0",
      revokedKids: [],
      highestStatusGeneration: "0",
    };
    let finalized: FinalizedAuthorityStatus | null = null;
    let reservations = 0;
    const publicRing = publicAuthorityRing(ring, { issuer, deploymentId });
    const store = {
      bootstrapAuthority: async () => undefined,
      loadLifecycle: async () => lifecycle,
      loadMembership: async (): Promise<MembershipSnapshot> => ({
        membershipGeneration: "1",
        members: [{ replicaId: "replica-a", replicaGeneration: "1", state: "required" }],
      }),
      promoteJoiningReplica: async () => false,
      drainReplica: async () => true,
      loadPublicRings: async () => new Map([[digest, publicRing]]),
      observePublicRing: async () => undefined,
      loadHighestFinalizedStatus: async () => finalized,
      reserveAndFinalizeStatus: async (args) => {
        reservations++;
        lifecycle = { ...lifecycle, highestStatusGeneration: args.status.statusGeneration };
        finalized = { compactJws: args.compactJws, status: args.status };
        return true;
      },
      acquireStatusLease: async () => true,
      prepareLifecycleTransition: async () => false,
      markTransitionStatusSigned: async () => false,
      commitLifecycleTransition: async () => false,
      reserveMint: async () => {
        throw new Error("not used");
      },
      ensureOpenSigningFence: async () => true,
      closeAndFreezeSigningFence: async () => true,
      finalizeMint: async () => {
        throw new Error("not used");
      },
    } satisfies AuthorityRuntimeStore;
    const observations = {
      redisTime: async () => {
        if (redisDown) throw new Error("offline");
        return now;
      },
      nextLeaseGeneration: async () => "1",
      publishLease: async () => undefined,
      listLeases: async () => [observation(digest, "replica-a")],
    } satisfies AuthorityObservationStore;
    let monotonic = 0;
    const snapshot = new AuthorityPublicSnapshot(() => monotonic);
    const runtime = new RemoteAuthorityRuntime({
      keyFile,
      issuer,
      deploymentId,
      digests: JSON.stringify([digest]),
      replicaId: "replica-a",
      store,
      observations,
      snapshot,
    });

    expect((await runtime.tick()).ready).toBe(true);
    expect(reservations).toBe(1);
    redisDown = true;
    expect(await runtime.tick()).toMatchObject({ ready: false, reason: "redis_unavailable" });
    redisDown = false;
    now = "101";
    expect((await runtime.tick()).ready).toBe(true);
    expect(reservations).toBe(2);
    expect(finalized?.status.statusGeneration).toBe("2");
  });
});

describe("authority overlap, replacement, and public status boundaries", () => {
  it("requires every required D0/D1/D2 member while ignoring a draining member", () => {
    const publicRing = publicAuthorityRing(makeRing(), { issuer, deploymentId }),
      digest = publicAuthorityRingDigest(publicRing),
      rings = new Map<string, PublicAuthorityRing>([[digest, publicRing]]);
    const members: MembershipSnapshot = {
      membershipGeneration: "1",
      members: [
        { replicaId: "old", replicaGeneration: "1", state: "draining" },
        { replicaId: "a", replicaGeneration: "1", state: "required" },
        { replicaId: "b", replicaGeneration: "2", state: "required" },
      ],
    };
    const leases = [
      observation(digest, "old"),
      observation(digest, "a"),
      observation(digest, "b", "1"),
    ];
    const decision = reduceAuthorityRollout({
      now: "100",
      issuerDigest,
      deploymentId,
      snapshot: members,
      leases,
      plan: [digest],
      rings,
      localDigest: digest,
    });
    expect(decision).toMatchObject({
      ready: false,
      reason: "missing_or_ambiguous_required_lease",
    });
    leases[2] = observation(digest, "b", "2");
    expect(
      reduceAuthorityRollout({
        now: "100",
        issuerDigest,
        deploymentId,
        snapshot: members,
        leases,
        plan: [digest],
        rings,
        localDigest: digest,
      }).ready,
    ).toBe(true);
  });

  it("authorizes only the committed signer and expires the public snapshot cache", async () => {
    const ring = makeRing();
    const digest = authorityRingDigest(ring, { issuer, deploymentId });
    const body: RemoteAuthorityStatusV1 = {
      schemaVersion: 1,
      iss: issuer,
      aud: "flycockpit-remote-authority-status-v1",
      deploymentId,
      revision: "1",
      ringDigest: digest,
      authorityEpoch: "1",
      statusGeneration: "1",
      revokedKids: [],
      iat: "100",
      validUntil: "160",
    };
    const compact = await createRemoteAuthorityStatusJws(
      body,
      new FileAuthoritySigner(ring.keys[0]!),
    );
    await expect(
      verifyRemoteAuthorityStatusJws(compact, new RingAuthorityVerifier(ring, "100"), {
        issuer,
        deploymentId,
        ringDigest: digest,
        authorityEpoch: "1",
        minimumGeneration: "1",
        now: "100",
        authorizedSignerKid: "replacement",
      }),
    ).rejects.toThrow("status scope, generation, or time mismatch");

    let monotonic = 0;
    const snapshot = new AuthorityPublicSnapshot(() => monotonic);
    snapshot.publish({ keys: [] }, compact, "160", "100");
    expect(snapshot.read("status", "160")?.body).toBe(compact);
    monotonic = 61;
    expect(snapshot.read("status", "161")).toBeUndefined();
  });
});
