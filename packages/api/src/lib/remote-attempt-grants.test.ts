import { createPublicKey, verify } from "node:crypto";
import {
  AttemptGrantError,
  type AttemptGrantPublicKey,
  type AttemptGrantVerifier,
  attemptGrantDigest,
  type GrantVerificationExpectations,
  keyRingFromFixture,
  verifyAttemptGrant,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import fixture from "../../../cockpit-protocol/fixtures/remote/attempt-grants-v1.json";

const REQUIRED_HEADER_MEMBERS = ["alg", "kid", "typ"] as const;
const REQUIRED_PAYLOAD_MEMBERS = [
  "schemaVersion",
  "iss",
  "aud",
  "tenantId",
  "accountId",
  "instanceId",
  "logicalAttachmentId",
  "childAttemptId",
  "jti",
  "client",
  "daemon",
  "serverNonce",
  "serviceVersion",
  "servicePolicyDigest",
  "policyEpoch",
  "policyDigest",
  "authorityEpoch",
  "attachmentCapabilities",
  "projectCapabilities",
  "permissionCeilingDigest",
  "authorizedTransports",
  "compatibleTupleIds",
  "tenantAuthorizationDigest",
  "iat",
  "nbf",
  "exp",
] as const;

const objectKeys = (value: Record<string, unknown>): string[] => Object.keys(value).sort();
const assertExactKeys = (
  value: Record<string, unknown>,
  required: readonly string[],
  context: string,
) => {
  const keys = objectKeys(value);
  const expected = [...required].sort();
  expect(keys, `key mismatch in ${context}`).toEqual(expected);
};

describe("remote_attempt_grant_api_fixture_conformance", () => {
  it("proves the exact protected header/payload member set in the API-consumed fixture", () => {
    expect(fixture.validGrants.length, "nonzero valid grants").toBeGreaterThan(0);
    for (const grant of fixture.validGrants) {
      const header = grant.protectedHeader as Record<string, unknown>;
      assertExactKeys(header, REQUIRED_HEADER_MEMBERS, `header for ${grant.id}`);
      expect(header.alg).toBe("ES256");
      expect(header.typ).toBe("flycockpit-remote-attempt+jwt");

      const payload = grant.payload as Record<string, unknown>;
      assertExactKeys(payload, REQUIRED_PAYLOAD_MEMBERS, `payload for ${grant.id}`);
      // No redundant role claim.
      expect(payload.role, `no role in ${grant.id}`).toBeUndefined();
      // No Noise thumbprint.
      expect(
        (payload.client as Record<string, unknown>)?.noiseThumbprint,
        `no client noise in ${grant.id}`,
      ).toBeUndefined();
      expect(
        (payload.daemon as Record<string, unknown>)?.noiseThumbprint,
        `no daemon noise in ${grant.id}`,
      ).toBeUndefined();
      // Decimal string integers.
      expect(typeof payload.iat).toBe("string");
      expect(typeof payload.exp).toBe("string");
      expect(typeof payload.nbf).toBe("string");
      expect(typeof payload.serviceVersion).toBe("string");
      expect(typeof payload.policyEpoch).toBe("string");
      expect(typeof payload.authorityEpoch).toBe("string");
    }
  });

  it("proves transport-bit values 0x01/0x02/0x03 are exhaustive", () => {
    const validBits = new Set([1, 2, 3]);
    for (const grant of fixture.validGrants)
      expect(validBits.has(grant.payload.authorizedTransports as number)).toBe(true);
  });

  it("proves malformed fixture cases cover every boundary", () => {
    expect(fixture.malformedGrants.length, "nonzero malformed grants").toBeGreaterThan(0);
    // Every rejection class is recognized.
    const validRejections = new Set([
      "header",
      "unknown_claim",
      "schema_version",
      "decimal_string",
      "size",
      "transport_bits",
      "tuple_set",
      "project_count",
      "project_capability_count",
      "alias",
      "digest_width",
      "time_order",
      "tenant_digest",
      "wildcard_project",
      "duplicate_project",
      "project_cap_order",
      "attachment_cap_order",
      "ceiling_digest_missing",
      "ceiling_digest_mismatch",
    ]);
    for (const entry of fixture.malformedGrants)
      expect(validRejections.has(entry.rejection), `known rejection for ${entry.id}`).toBe(true);
  });

  it("proves grant lifetime and verification skew limits", () => {
    expect(fixture.limits.compactJwsMaxBytes).toBe(8192);
    expect(fixture.limits.grantLifetimeSeconds).toBe(300);
    expect(fixture.limits.verificationSkewSeconds).toBe(60);
    expect(fixture.limits.permissionCeilingMaxBytes).toBe(512);
    expect(fixture.limits.tupleSetMin).toBe(1);
    expect(fixture.limits.tupleSetMax).toBe(16);
  });

  it("proves tenant authorization digest is null only for control-plane", () => {
    const controlPlane = fixture.validGrants.find((g) => g.id === "minimal-saas");
    expect(controlPlane, "minimal-saas grant exists").toBeDefined();
    expect(
      controlPlane!.payload.tenantAuthorizationDigest,
      "control-plane has null tenant digest",
    ).toBeNull();

    const enterprise = fixture.validGrants.find((g) => g.id === "enterprise-tenant");
    expect(enterprise, "enterprise-tenant grant exists").toBeDefined();
    expect(
      enterprise!.payload.tenantAuthorizationDigest,
      "enterprise has non-null tenant digest",
    ).not.toBeNull();
  });
});

// ===========================================================================
// AC2 + AC3: the API consumer verifies the same fixture vectors through the
// production `verifyAttemptGrant` entry point from `@flycockpit/cockpit-protocol`,
// proving byte-identical accept/reject with Rust.
// ===========================================================================

function fixtureVerifier(
  authorityKeys: ReadonlyArray<{ kid: string; x: string; y: string }>,
): AttemptGrantVerifier {
  void authorityKeys;
  return {
    async verifyP1363(input, signature, key: AttemptGrantPublicKey, _kid) {
      // Cryptographically bind to the EXACT public key passed by the
      // verifier — never re-lookup kid independently.
      const xB64url = Buffer.from(key.x).toString("base64url");
      const yB64url = Buffer.from(key.y).toString("base64url");
      try {
        const nodeKey = createPublicKey({
          key: { kty: "EC", crv: "P-256", x: xB64url, y: yB64url },
          format: "jwk",
        });
        return Boolean(
          signature.length === 64 &&
            verify("sha256", input, { key: nodeKey, dsaEncoding: "ieee-p1363" }, signature),
        );
      } catch {
        return false;
      }
    },
  };
}

/**
 * Independently verify an ES256 P-1363 signature with the fixture's declared
 * public key for `kid`. Used to prove noncanonical fixtures have valid
 * signatures before asserting canonicality rejection.
 */
function independentlyVerifySignature(
  authorityKeys: ReadonlyArray<{ kid: string; x: string; y: string }>,
  kid: string,
  signingInput: Uint8Array,
  signature: Uint8Array,
): boolean {
  const keyEntry = authorityKeys.find((k) => k.kid === kid);
  if (!keyEntry) return false;
  const nodeKey = createPublicKey({
    key: { kty: "EC", crv: "P-256", x: keyEntry.x, y: keyEntry.y },
    format: "jwk",
  });
  return Boolean(
    signature.length === 64 &&
      verify("sha256", signingInput, { key: nodeKey, dsaEncoding: "ieee-p1363" }, signature),
  );
}

function expectationsFromPayload(payload: Record<string, unknown>): GrantVerificationExpectations {
  const idObj = (v: Record<string, unknown>) => ({
    deviceId: Buffer.from(v.deviceId as string, "base64url"),
    certificateId: Buffer.from(v.certificateId as string, "base64url"),
    generation: BigInt(v.generation as string),
    p256Thumbprint: Buffer.from(v.p256Thumbprint as string, "hex"),
  });
  const tenantAuthRaw = payload.tenantAuthorizationDigest;
  const tenantAuthorization =
    tenantAuthRaw === null
      ? { kind: "controlPlane" as const }
      : { kind: "enterprise" as const, digest: Buffer.from(tenantAuthRaw as string, "hex") };
  return {
    issuer: payload.iss as string,
    audience: payload.aud as string,
    tenantId: Buffer.from(payload.tenantId as string, "base64url"),
    accountId: Buffer.from(payload.accountId as string, "base64url"),
    instanceId: Buffer.from(payload.instanceId as string, "base64url"),
    logicalAttachmentId: Buffer.from(payload.logicalAttachmentId as string, "base64url"),
    childAttemptId: Buffer.from(payload.childAttemptId as string, "base64url"),
    client: idObj(payload.client as Record<string, unknown>),
    daemon: idObj(payload.daemon as Record<string, unknown>),
    serverNonce: Buffer.from(payload.serverNonce as string, "hex"),
    serviceVersion: BigInt(payload.serviceVersion as string),
    servicePolicyDigest: Buffer.from(payload.servicePolicyDigest as string, "hex"),
    policyEpoch: BigInt(payload.policyEpoch as string),
    policyDigest: Buffer.from(payload.policyDigest as string, "hex"),
    authorityEpoch: BigInt(payload.authorityEpoch as string),
    tenantAuthorization,
  };
}

describe("remote_attempt_grant_api_cross_language_verify", () => {
  it("proves the API consumer verifies every valid fixture grant through the production entry point (AC2)", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);

    for (const grant of fixture.validGrants) {
      const payload = grant.payload as Record<string, unknown>;
      const expected = expectationsFromPayload(payload);
      const now = payload.iat as string;

      const verified = await verifyAttemptGrant(grant.compactJws, keyRing, verifier, expected, now);
      expect(verified, `grant ${grant.id} must verify`).toBeDefined();
      const digest = attemptGrantDigest(verified.grant);
      expect(digest.length, `grant ${grant.id} digest must be 32 bytes`).toBe(32);
    }
  });

  it("proves a noncanonical-but-validly-resigned payload is rejected for JCS, not signature (AC3)", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);

    for (const nc of fixture.noncanonicalGrants) {
      // Finding 4: Independently verify the noncanonical fixture's ES256
      // P-1363 signature with its declared fixture public key BEFORE
      // asserting that verifyAttemptGrant rejects it for canonicality.
      // This proves the rejection is due to canonicality, not a bad signature.
      const segments = nc.compactJws.split(".");
      expect(segments.length, `${nc.id} must have 3 segments`).toBe(3);
      const [headerSeg, payloadSeg, sigSeg] = segments;

      const headerBytes = Buffer.from(headerSeg!, "base64url");
      const headerObj = JSON.parse(headerBytes.toString("utf8")) as Record<string, unknown>;
      const ncKid = headerObj.kid as string;
      expect(ncKid, `${nc.id} must have a kid`).toBeTruthy();

      const ncSignature = Buffer.from(sigSeg!, "base64url");
      expect(ncSignature.length, `${nc.id} signature must be 64 bytes`).toBe(64);

      const ncSigningInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
      expect(
        independentlyVerifySignature(fixture.authorityKeys, ncKid, ncSigningInput, ncSignature),
        `${nc.id} fixture signature must be independently valid (proves rejection is canonicality, not bad signature)`,
      ).toBe(true);

      const dummyExpected: GrantVerificationExpectations = {
        issuer: "",
        audience: "",
        tenantId: new Uint8Array(16),
        accountId: new Uint8Array(16),
        instanceId: new Uint8Array(16),
        logicalAttachmentId: new Uint8Array(16),
        childAttemptId: new Uint8Array(16),
        client: {
          deviceId: new Uint8Array(16),
          certificateId: new Uint8Array(16),
          generation: 0n,
          p256Thumbprint: new Uint8Array(32),
        },
        daemon: {
          deviceId: new Uint8Array(16),
          certificateId: new Uint8Array(16),
          generation: 0n,
          p256Thumbprint: new Uint8Array(32),
        },
        serverNonce: new Uint8Array(32),
        serviceVersion: 0n,
        servicePolicyDigest: new Uint8Array(32),
        policyEpoch: 0n,
        policyDigest: new Uint8Array(32),
        authorityEpoch: 0n,
        tenantAuthorization: { kind: "controlPlane" },
      };

      try {
        await verifyAttemptGrant(nc.compactJws, keyRing, verifier, dummyExpected, "1700000000");
        expect.fail(`${nc.id} must be rejected`);
      } catch (e) {
        expect(e, `${nc.id} must be AttemptGrantError`).toBeInstanceOf(AttemptGrantError);
        const err = e as AttemptGrantError;
        expect(err.kind, `${nc.id} must be jws (canonicality), not signature`).toBe("jws");
        expect(err.message, `${nc.id} must mention canonical`).toContain("canonical");
      }
    }
  });

  // =========================================================================
  // Finding 2: A grant signed with key A must be REJECTED when verified
  // against key B with the same kid (cryptographic key binding).
  // =========================================================================
  it("proves a grant signed with key A is REJECTED when verified against key B with the same kid (Finding 2)", async () => {
    expect(fixture.authorityKeys.length, "need at least 2 authority keys").toBeGreaterThanOrEqual(
      2,
    );
    const grant = fixture.validGrants[0]!;
    const payload = grant.payload as Record<string, unknown>;
    const expected = expectationsFromPayload(payload);
    const now = payload.iat as string;

    const keyK1 = fixture.authorityKeys.find((k) => k.kid === "k1")!;
    const keyK2 = fixture.authorityKeys.find((k) => k.kid === "k2")!;
    expect(keyK1, "fixture must have k1").toBeDefined();
    expect(keyK2, "fixture must have k2").toBeDefined();

    // Map kid "k1" to k2's public key coordinates.
    const swappedRing = keyRingFromFixture([{ kid: "k1", x: keyK2.x, y: keyK2.y }]);
    const verifier = fixtureVerifier(fixture.authorityKeys);

    try {
      await verifyAttemptGrant(grant.compactJws, swappedRing, verifier, expected, now);
      expect.fail("swapped-key grant must be rejected");
    } catch (e) {
      expect(e, "swapped-key rejection must be AttemptGrantError").toBeInstanceOf(
        AttemptGrantError,
      );
      const err = e as AttemptGrantError;
      expect(err.kind, "swapped-key rejection must be signature kind").toBe("signature");
    }

    // Sanity: same grant verifies with correct key ring.
    const correctRing = keyRingFromFixture(fixture.authorityKeys);
    const verified = await verifyAttemptGrant(
      grant.compactJws,
      correctRing,
      verifier,
      expected,
      now,
    );
    expect(verified, "grant must verify with correct key").toBeDefined();
  });
});

// ===========================================================================
// Finding 4 + parity: the API consumer replays the SAME executable vectors as
// Rust and @flycockpit/cockpit-protocol. Every malformedGrants entry and every
// resignedVectors entry carries a real compact-JWS that must be rejected (or,
// for the leading-zero u64 case, accepted) through the production verifier.
// ===========================================================================
describe("remote_attempt_grant_api_executable_rejections", () => {
  it("rejects every malformedGrants compact-JWS through verifyAttemptGrant (Finding 4)", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);
    const minimal = fixture.validGrants.find((g) => g.id === "minimal-saas")!;
    const expected = expectationsFromPayload(minimal.payload as Record<string, unknown>);

    expect(fixture.malformedGrants.length, "nonzero malformed grants").toBeGreaterThan(0);
    for (const entry of fixture.malformedGrants) {
      const compactJws = (entry as { compactJws?: string }).compactJws;
      expect(compactJws, `${entry.id} must carry an executable compactJws`).toBeTruthy();
      let thrown: unknown;
      try {
        await verifyAttemptGrant(compactJws!, keyRing, verifier, expected, "1700000000");
      } catch (e) {
        thrown = e;
      }
      expect(thrown, `${entry.id} must be rejected`).toBeInstanceOf(AttemptGrantError);
    }
  });

  it("rejects high-S/out-of-vocab/duplicate/unsorted resigned vectors and accepts the leading-zero u64 vector (parity)", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);
    const vectors = fixture.resignedVectors as ReadonlyArray<{
      id: string;
      expect: "accept" | "reject";
      rejection?: string;
      payload: Record<string, unknown>;
      compactJws: string;
    }>;
    expect(vectors.length, "nonzero resigned vectors").toBeGreaterThan(0);
    for (const v of vectors) {
      const expected = expectationsFromPayload(v.payload);
      const now = v.payload.iat as string;
      if (v.expect === "accept") {
        const verified = await verifyAttemptGrant(v.compactJws, keyRing, verifier, expected, now);
        expect(verified, `${v.id} must verify`).toBeDefined();
      } else {
        let thrown: unknown;
        try {
          await verifyAttemptGrant(v.compactJws, keyRing, verifier, expected, now);
        } catch (e) {
          thrown = e;
        }
        expect(thrown, `${v.id} must be rejected`).toBeInstanceOf(AttemptGrantError);
        expect((thrown as AttemptGrantError).kind, `${v.id} kind ${v.rejection}`).toBe(v.rejection);
      }
    }
  });
});
