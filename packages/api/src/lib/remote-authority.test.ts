import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalizeRfc8785 } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import fixture from "../../fixtures/remote-authority-v1.json";
import {
  type AuthorityPrivateKey,
  AuthorityPublicSnapshot,
  type AuthorityRingFile,
  authorityRetirementFloor,
  authorityRingDigest,
  canonicalAuthorityRing,
  createRemoteAuthorityStatusJws,
  FileAuthoritySigner,
  type ObservationLease,
  type PublicAuthorityRing,
  parseAuthorityConfig,
  parseAuthorityRingFile,
  publicAuthorityJwks,
  publicAuthorityRing,
  publicAuthorityRingDigest,
  REMOTE_AUTHORITY,
  RingAuthorityVerifier,
  reconcileAuthorityFence,
  reduceAuthorityRollout,
  reserveAuthorityMint,
  validateLifecycleTransition,
  validateThreeDigestPlan,
  verifyRemoteAuthorityStatusJws,
} from "./remote-authority";
import { readAuthorityRingFile } from "./remote-authority-file";

const makeKey = (kid: string, state: AuthorityPrivateKey["state"]): AuthorityPrivateKey => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" }),
    jwk = privateKey.export({ format: "jwk" });
  return {
    kid,
    alg: "ES256",
    kty: "EC",
    crv: "P-256",
    x: jwk.x!,
    y: jwk.y!,
    d: jwk.d!,
    state,
    activatedAt: "1",
    retireAt: null,
  };
};
const ring = (keys: AuthorityPrivateKey[], revision = "1", epoch = "1"): AuthorityRingFile =>
  parseAuthorityRingFile({
    schemaVersion: 1,
    revision,
    authorityEpoch: epoch,
    currentKid: keys.find((k) => k.state === "current")!.kid,
    keys: [...keys].sort((a, b) => Buffer.compare(Buffer.from(a.kid), Buffer.from(b.kid))),
  });
const cfg = { issuer: "https://authority.example", deploymentId: "prod_1" };
describe("remote_authority_file_provider_rejects_unsafe_ring", () => {
  it("rejects permissions, symlinks and malformed rings", async () => {
    const dir = await mkdtemp(join(tmpdir(), "authority-test-")),
      path = join(dir, "ring.json"),
      value = ring([makeKey("k0", "current")]);
    await writeFile(path, JSON.stringify(value), { mode: 0o600 });
    expect((await readAuthorityRingFile(path)).currentKid).toBe("k0");
    await chmod(path, 0o644);
    await expect(readAuthorityRingFile(path)).rejects.toThrow();
    const link = join(dir, "link.json");
    await symlink(path, link);
    await expect(readAuthorityRingFile(link)).rejects.toThrow();
    expect(() => parseAuthorityRingFile({ ...value, extra: true })).toThrow();
    expect(() =>
      parseAuthorityRingFile({ ...value, keys: [value.keys[0], value.keys[0]] }),
    ).toThrow();
    await expect(readAuthorityRingFile("relative.json")).rejects.toThrow("absolute");
    await chmod(path, 0o600);
    await expect(readAuthorityRingFile(path, "2", value)).rejects.toThrow("nonmonotonic");
    const other = makeKey("other", "current");
    expect(() =>
      parseAuthorityRingFile({
        ...value,
        keys: [{ ...value.keys[0]!, x: other.x, y: other.y }],
      }),
    ).toThrow("private/public mismatch");
    const { d: _private, ...publicOnly } = value.keys[0]!;
    expect(() => parseAuthorityRingFile({ ...value, keys: [publicOnly] })).toThrow();
    expect(() =>
      parseAuthorityRingFile({
        ...value,
        keys: [{ ...value.keys[0]!, x: "A".repeat(43), y: "A".repeat(43) }],
      }),
    ).toThrow();
    const unsafe = join(dir, "unsafe");
    await mkdir(unsafe, { mode: 0o777 });
    await chmod(unsafe, 0o777);
    const unsafePath = join(unsafe, "ring.json");
    await writeFile(unsafePath, JSON.stringify(value), { mode: 0o600 });
    await expect(readAuthorityRingFile(unsafePath)).rejects.toThrow("parent is unsafe");
  });
});
describe("remote_authority_canonical_digest_vectors", () => {
  it("binds issuer/deployment and exact u64 strings", () => {
    const value = ring([makeKey("é", "current"), makeKey("z", "verification_only")]);
    const digest = authorityRingDigest(value, cfg);
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(canonicalAuthorityRing(value, cfg)).not.toContain('"d"');
    expect(authorityRingDigest(value, { ...cfg, deploymentId: "prod_2" })).not.toBe(digest);
    for (const n of [
      "9007199254740991",
      "9007199254740992",
      "9007199254740993",
      "18446744073709551615",
    ]) {
      expect(() => parseAuthorityRingFile({ ...value, revision: n })).not.toThrow();
    }
    expect(() =>
      parseAuthorityConfig({
        issuer: cfg.issuer,
        deploymentId: cfg.deploymentId,
        digests: '["' + digest + '"]',
      }),
    ).not.toThrow();
  });
  it("matches the Rust public-only fixture", () => {
    expect(canonicalizeRfc8785(fixture.canonicalRing)).toBe(fixture.canonicalUtf8);
    expect(publicAuthorityRingDigest(fixture.canonicalRing as PublicAuthorityRing)).toBe(
      fixture.digest,
    );
    expect(fixture.u64Boundaries).toHaveLength(4);
  });
});
describe("remote_authority_sign_verify_matrix", () => {
  it("signs only with current and verifies exact kid", async () => {
    const value = ring([makeKey("k0", "current")]),
      input = new TextEncoder().encode("claims"),
      signer = new FileAuthoritySigner(value.keys[0]!),
      verifier = new RingAuthorityVerifier(value, "1"),
      signature = await signer.signP1363(input, "mint-1");
    expect(signature).toHaveLength(64);
    expect(await verifier.verifyP1363(input, signature, "k0")).toBe(true);
    expect(await verifier.verifyP1363(input, signature, "unknown")).toBe(false);
    expect(() => new FileAuthoritySigner({ ...value.keys[0]!, state: "revoked" })).toThrow();
  });
});
describe("remote_authority_three_digest_rollout", () => {
  it("validates exact additive/promote changes and complete membership", () => {
    const k0 = makeKey("k0", "current"),
      k1 = makeKey("k1", "verification_only"),
      d0 = publicAuthorityRing(ring([k0], "1", "1"), cfg),
      d1 = publicAuthorityRing(ring([k0, k1], "2", "2"), cfg),
      d2 = publicAuthorityRing(
        ring(
          [
            { ...k0, state: "verification_only" },
            { ...k1, state: "current" },
          ],
          "3",
          "3",
        ),
        cfg,
      );
    validateThreeDigestPlan(d0, d1, d2);
    expect(() => validateThreeDigestPlan(d0, { ...d1, currentKid: "k1" }, d2)).toThrow();
    expect(() =>
      validateThreeDigestPlan(
        d0,
        { ...d1, keys: d1.keys.map((key) => ({ ...key, activatedAt: "2" })) },
        d2,
      ),
    ).toThrow();
    expect(() =>
      validateThreeDigestPlan(d0, d1, {
        ...d2,
        keys: d2.keys.map((key) => (key.kid === "k0" ? { ...key, x: key.y } : key)),
      }),
    ).toThrow();
    const digests = [d0, d1, d2].map(publicAuthorityRingDigest),
      rings = new Map<string, PublicAuthorityRing>(digests.map((d, i) => [d, [d0, d1, d2][i]!]));
    const lease = (replicaId: string, digest: string): ObservationLease => ({
      issuerDigest: "issuer",
      deploymentId: cfg.deploymentId,
      membershipGeneration: "1",
      replicaId,
      replicaGeneration: "1",
      leaseGeneration: "1",
      revision: rings.get(digest)!.revision,
      digest,
      currentKid: rings.get(digest)!.currentKid,
      publicKids: rings.get(digest)!.keys.map((k) => k.kid),
      authorityEpoch: rings.get(digest)!.authorityEpoch,
      observedRedisTime: "10",
      expiresAt: "40",
    });
    const snapshot = {
      membershipGeneration: "1",
      members: [
        { replicaId: "a", replicaGeneration: "1", state: "required" as const },
        { replicaId: "b", replicaGeneration: "1", state: "required" as const },
      ],
    };
    for (const [name, local, observed] of [
      ["D0-only", 0, [0, 0]],
      ["D0/D1", 0, [0, 1]],
      ["D0/D1-local-D1", 1, [0, 1]],
      ["D1-only", 1, [1, 1]],
      ["D1/D2", 2, [1, 2]],
      ["D2-only", 2, [2, 2]],
    ] as const) {
      const decision = reduceAuthorityRollout({
        now: "10",
        issuerDigest: "issuer",
        deploymentId: cfg.deploymentId,
        snapshot,
        leases: [lease("a", digests[observed[0]]!), lease("b", digests[observed[1]]!)],
        plan: digests as [string, string, string],
        rings,
        localDigest: digests[local]!,
      });
      expect(decision.ready, name).toBe(true);
      expect(decision.mayMint, name).toBe(true);
    }
    expect(
      reduceAuthorityRollout({
        now: "10",
        issuerDigest: "issuer",
        deploymentId: cfg.deploymentId,
        snapshot,
        leases: [lease("a", digests[2]!), lease("b", digests[2]!)],
        plan: [digests[2]!] as [string],
        rings,
        localDigest: digests[2]!,
      }),
    ).toMatchObject({ ready: true, phase: "steady", signingKid: "k1" });
    expect(
      reduceAuthorityRollout({
        now: "10",
        issuerDigest: "issuer",
        deploymentId: cfg.deploymentId,
        snapshot,
        leases: [lease("a", digests[1]!), lease("b", digests[1]!)],
        plan: digests as [string, string, string],
        rings,
        localDigest: digests[2]!,
      }).ready,
    ).toBe(true);
    expect(
      reduceAuthorityRollout({
        now: "10",
        issuerDigest: "issuer",
        deploymentId: cfg.deploymentId,
        snapshot,
        leases: [lease("a", digests[0]!), lease("b", digests[2]!)],
        plan: digests as [string, string, string],
        rings,
        localDigest: digests[2]!,
      }).ready,
    ).toBe(false);
  });
});
describe("remote_authority_jwks_and_status_public_only", () => {
  it("creates bounded status and outage snapshot", async () => {
    const value = ring([makeKey("k0", "current")]),
      signer = new FileAuthoritySigner(value.keys[0]!),
      digest = authorityRingDigest(value, cfg),
      status = await createRemoteAuthorityStatusJws(
        {
          schemaVersion: 1,
          iss: cfg.issuer,
          aud: "flycockpit-remote-authority-status-v1",
          deploymentId: cfg.deploymentId,
          revision: "1",
          ringDigest: digest,
          authorityEpoch: "1",
          statusGeneration: "1",
          revokedKids: [],
          iat: "100",
          validUntil: "160",
        },
        signer,
      );
    expect(status.split(".")).toHaveLength(3);
    const verified = await verifyRemoteAuthorityStatusJws(
      status,
      new RingAuthorityVerifier(value, "100"),
      {
        issuer: cfg.issuer,
        deploymentId: cfg.deploymentId,
        ringDigest: digest,
        authorityEpoch: "1",
        minimumGeneration: "1",
        now: "100",
        authorizedSignerKid: "k0",
      },
    );
    expect(verified.header.kid).toBe("k0");
    const jwks = publicAuthorityJwks(value, "100");
    expect(JSON.stringify(jwks)).not.toContain('"d"');
    let monotonic = 0;
    const snapshot = new AuthorityPublicSnapshot(() => monotonic);
    snapshot.publish(jwks, status, "160", "100");
    expect(snapshot.read("jwks", "160")).toBeDefined();
    monotonic = 61;
    expect(snapshot.read("jwks", "161")).toBeUndefined();
    expect(REMOTE_AUTHORITY.statusLifetime).toBe(60n);
  });
});

describe("remote_authority_replica_lease_races", () => {
  it("fails closed for empty, expired, replaced, or regressed membership observations", () => {
    const value = publicAuthorityRing(ring([makeKey("k0", "current")]), cfg),
      digest = publicAuthorityRingDigest(value),
      base = {
        now: "10",
        issuerDigest: "issuer",
        deploymentId: cfg.deploymentId,
        plan: [digest] as [string],
        rings: new Map([[digest, value]]),
        localDigest: digest,
      };
    expect(
      reduceAuthorityRollout({
        ...base,
        snapshot: { membershipGeneration: "1", members: [] },
        leases: [],
      }).ready,
    ).toBe(false);
    const snapshot = {
        membershipGeneration: "2",
        members: [{ replicaId: "a", replicaGeneration: "2", state: "required" as const }],
      },
      lease: ObservationLease = {
        issuerDigest: "issuer",
        deploymentId: cfg.deploymentId,
        membershipGeneration: "2",
        replicaId: "a",
        replicaGeneration: "1",
        leaseGeneration: "1",
        revision: "1",
        digest,
        currentKid: "k0",
        publicKids: ["k0"],
        authorityEpoch: "1",
        observedRedisTime: "1",
        expiresAt: "10",
      };
    expect(reduceAuthorityRollout({ ...base, snapshot, leases: [lease] }).ready).toBe(false);
    expect(
      reduceAuthorityRollout({
        ...base,
        previousRedisTime: "11",
        snapshot,
        leases: [{ ...lease, replicaGeneration: "2", expiresAt: "40" }],
      }).reason,
    ).toBe("redis_time_regression");
  });
});

describe("remote_authority_retirement_floor", () => {
  it("closes reservations, reconciles provider outcomes, and computes the exact floor", () => {
    const fence = { kid: "k0", signingGeneration: "7", state: "open" as const },
      reserved = reserveAuthorityMint(fence, {
        mintId: "m1",
        deploymentId: cfg.deploymentId,
        signingGeneration: "7",
        kid: "k0",
        claimsHash: "a".repeat(64),
      });
    const { state: _state, ...entry } = reserved;
    expect(() => reserveAuthorityMint({ ...fence, state: "closing" }, entry)).toThrow();
    const result = reconcileAuthorityFence({
      fence: { ...fence, state: "closing", cutoff: "100" },
      rows: [reserved],
      provider: new Map([["m1", "confirmed_not_started" as const]]),
      postgresNow: "100",
    });
    expect(result.rows[0]?.state).toBe("aborted");
    expect(result.fence.state).toBe("frozen");
    const indeterminate = reconcileAuthorityFence({
      fence: { ...fence, state: "closing" },
      rows: [reserved],
      provider: new Map([["m1", "indeterminate"]]),
      postgresNow: "101",
    });
    expect(indeterminate).toMatchObject({ ready: false, fence: { state: "closing" } });
    const signed = reconcileAuthorityFence({
      fence: { ...fence, state: "closing" },
      rows: [reserved],
      provider: new Map([["m1", "confirmed_signed"]]),
      postgresNow: "102",
    });
    expect(signed.rows[0]?.state).toBe("signed");
    const finalized = reconcileAuthorityFence({
      fence: signed.fence,
      rows: signed.rows,
      provider: new Map(),
      postgresNow: "103",
    });
    expect(finalized.rows[0]).toMatchObject({ state: "finalized", signedAt: "103" });
    expect(finalized.fence).toMatchObject({ state: "frozen", cutoff: "103" });
    expect(authorityRetirementFloor("100")).toBe("2592160");
  });
});

describe("remote_authority_outage_matrix", () => {
  it.each([
    { publishedAt: "100", statusExpiry: "200", lastServed: "160" },
    { publishedAt: "100", statusExpiry: "130", lastServed: "130" },
  ])("serves the paired public snapshot only through the earlier bound %#", ({
    publishedAt,
    statusExpiry,
    lastServed,
  }) => {
    let monotonic = 0;
    const snapshot = new AuthorityPublicSnapshot(() => monotonic);
    snapshot.publish({ keys: [] }, "status", statusExpiry, publishedAt);
    expect(snapshot.read("jwks", publishedAt)).toBeDefined();
    expect(snapshot.read("status", lastServed)?.body).toBe("status");
    monotonic = Number(BigInt(lastServed) - BigInt(publishedAt) + 1n);
    expect(snapshot.read("jwks", (BigInt(lastServed) + 1n).toString())).toBeUndefined();
    expect(snapshot.read("status", (BigInt(lastServed) + 1n).toString())).toBeUndefined();
  });

  it("encodes the exact lease renewal, expiry, refresh, and recovery timing constants", () => {
    expect(REMOTE_AUTHORITY.leaseRenew).toBe(10n);
    expect(REMOTE_AUTHORITY.leaseTtl).toBe(30n);
    expect(REMOTE_AUTHORITY.statusRefresh).toBe(20n);
    expect(REMOTE_AUTHORITY.statusLifetime).toBe(60n);

    const value = publicAuthorityRing(ring([makeKey("k0", "current")]), cfg),
      digest = publicAuthorityRingDigest(value),
      snapshot = {
        membershipGeneration: "1",
        members: [{ replicaId: "a", replicaGeneration: "1", state: "required" as const }],
      },
      lease: ObservationLease = {
        issuerDigest: "issuer",
        deploymentId: cfg.deploymentId,
        membershipGeneration: "1",
        replicaId: "a",
        replicaGeneration: "1",
        leaseGeneration: "1",
        revision: "1",
        digest,
        currentKid: "k0",
        publicKids: ["k0"],
        authorityEpoch: "1",
        observedRedisTime: "100",
        expiresAt: "130",
      },
      input = {
        issuerDigest: "issuer",
        deploymentId: cfg.deploymentId,
        snapshot,
        leases: [lease],
        plan: [digest] as [string],
        rings: new Map([[digest, value]]),
        localDigest: digest,
      };
    expect(reduceAuthorityRollout({ ...input, now: "129" }).ready).toBe(true);
    expect(reduceAuthorityRollout({ ...input, now: "130" }).ready).toBe(false);
    expect(reduceAuthorityRollout({ ...input, now: "99", previousRedisTime: "100" }).ready).toBe(
      false,
    );
  });
});

describe("remote_authority_revocation_epoch_bound", () => {
  it("binds continuous generations to epochs and rejects stale authority after validity plus skew", async () => {
    const k0 = makeKey("k0", "current"),
      k1 = makeKey("k1", "verification_only"),
      before = ring([k0, k1], "8", "12"),
      after = ring(
        [
          { ...k0, state: "revoked" },
          { ...k1, state: "current" },
        ],
        "9",
        "13",
      ),
      beforeDigest = authorityRingDigest(before, cfg),
      afterDigest = authorityRingDigest(after, cfg),
      oldStatus = await createRemoteAuthorityStatusJws(
        {
          schemaVersion: 1,
          iss: cfg.issuer,
          aud: "flycockpit-remote-authority-status-v1",
          deploymentId: cfg.deploymentId,
          revision: "8",
          ringDigest: beforeDigest,
          authorityEpoch: "12",
          statusGeneration: "40",
          revokedKids: [],
          iat: "100",
          validUntil: "160",
        },
        new FileAuthoritySigner(k0),
      ),
      refreshedStatus = await createRemoteAuthorityStatusJws(
        {
          schemaVersion: 1,
          iss: cfg.issuer,
          aud: "flycockpit-remote-authority-status-v1",
          deploymentId: cfg.deploymentId,
          revision: "8",
          ringDigest: beforeDigest,
          authorityEpoch: "12",
          statusGeneration: "41",
          revokedKids: [],
          iat: "120",
          validUntil: "180",
        },
        new FileAuthoritySigner(k0),
      ),
      revokedStatus = await createRemoteAuthorityStatusJws(
        {
          schemaVersion: 1,
          iss: cfg.issuer,
          aud: "flycockpit-remote-authority-status-v1",
          deploymentId: cfg.deploymentId,
          revision: "9",
          ringDigest: afterDigest,
          authorityEpoch: "13",
          statusGeneration: "42",
          revokedKids: ["k0"],
          iat: "140",
          validUntil: "200",
        },
        new FileAuthoritySigner({ ...k1, state: "current" }),
      );

    expect(
      (
        await verifyRemoteAuthorityStatusJws(
          refreshedStatus,
          new RingAuthorityVerifier(before, "120"),
          {
            issuer: cfg.issuer,
            deploymentId: cfg.deploymentId,
            ringDigest: beforeDigest,
            authorityEpoch: "12",
            minimumGeneration: "41",
            now: "120",
            authorizedSignerKid: "k0",
          },
        )
      ).payload.statusGeneration,
    ).toBe("41");
    await expect(
      verifyRemoteAuthorityStatusJws(oldStatus, new RingAuthorityVerifier(before, "221"), {
        issuer: cfg.issuer,
        deploymentId: cfg.deploymentId,
        ringDigest: beforeDigest,
        authorityEpoch: "12",
        minimumGeneration: "40",
        now: "221",
        authorizedSignerKid: "k0",
      }),
    ).rejects.toThrow("status scope, generation, or time mismatch");
    const committed = await verifyRemoteAuthorityStatusJws(
      revokedStatus,
      new RingAuthorityVerifier(after, "140"),
      {
        issuer: cfg.issuer,
        deploymentId: cfg.deploymentId,
        ringDigest: afterDigest,
        authorityEpoch: "13",
        minimumGeneration: "42",
        now: "140",
        authorizedSignerKid: "k1",
      },
    );
    expect(committed.payload.revokedKids).toEqual(["k0"]);
    expect(publicAuthorityJwks(after, "140").keys.map((key) => key.kid)).toEqual(["k1"]);
  });

  it("requires one counter increment, a replacement signer, and stable transition identity", () => {
    const transition = {
      transitionId: "revocation-1",
      state: "status_signed" as const,
      fromRevision: "8",
      toRevision: "9",
      fromDigest: "a".repeat(64),
      toDigest: "b".repeat(64),
      fromAuthorityEpoch: "12",
      toAuthorityEpoch: "13",
      fromCurrentKid: "k0",
      toCurrentKid: "k1",
      statusGeneration: "42",
      statusBodyDigest: "c".repeat(64),
      signingGeneration: "13",
    };
    expect(validateLifecycleTransition(transition, "k1")).toBe(transition);
    expect(validateLifecycleTransition({ ...transition, state: "committed" }, "k1")).toEqual({
      ...transition,
      state: "committed",
    });
    expect(() => validateLifecycleTransition(transition, "")).toThrow(
      "authorized non-revoked signer",
    );
    expect(() =>
      validateLifecycleTransition({ ...transition, toAuthorityEpoch: "12" }, "k1"),
    ).toThrow("lifecycle counters must increment");
  });
});
