import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, symlink, writeFile } from "node:fs/promises";
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
      },
    );
    expect(verified.header.kid).toBe("k0");
    const jwks = publicAuthorityJwks(value, "100");
    expect(JSON.stringify(jwks)).not.toContain('"d"');
    const snapshot = new AuthorityPublicSnapshot();
    snapshot.publish(jwks, status, "160", "100");
    expect(snapshot.read("jwks", "160")).toBeDefined();
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
    expect(authorityRetirementFloor("100")).toBe("2592160");
  });
});

describe("remote_authority_outage_matrix", () => {
  it("serves the paired public snapshot only through the earlier 60-second bound", () => {
    const snapshot = new AuthorityPublicSnapshot();
    snapshot.publish({ keys: [] }, "status", "200", "100");
    expect(snapshot.read("status", "160")?.body).toBe("status");
    expect(snapshot.read("status", "161")).toBeUndefined();
  });
});
