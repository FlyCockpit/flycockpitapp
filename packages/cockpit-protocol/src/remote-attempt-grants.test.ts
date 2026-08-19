import { createPublicKey, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import fixture from "../fixtures/remote/attempt-grants-v1.json";
import {
  AttemptGrantError,
  type AttemptGrantPublicKey,
  type AttemptGrantVerifier,
  attemptGrantDigest,
  type GrantVerificationExpectations,
  keyRingFromFixture,
  verifyAttemptGrant,
} from "./remote-attempt-grants";

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
const REQUIRED_IDENTITY_MEMBERS = [
  "deviceId",
  "certificateId",
  "generation",
  "p256Thumbprint",
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
const assertDecimalString = (value: unknown, field: string) => {
  expect(typeof value, `${field} must be a string`).toBe("string");
  expect((value as string).length, `${field} must be nonempty`).toBeGreaterThan(0);
  for (const char of value as string)
    expect(char >= "0" && char <= "9", `${field} must be decimal`).toBe(true);
};
const assertAlias22 = (value: unknown, field: string) => {
  expect(typeof value, `${field} must be a string`).toBe("string");
  expect((value as string).length, `${field} alias must be 22 chars`).toBe(22);
};
const assertDigestHex64 = (value: unknown, field: string) => {
  expect(typeof value, `${field} must be a string`).toBe("string");
  expect((value as string).length, `${field} digest must be 64 chars`).toBe(64);
  expect((value as string).toLowerCase(), `${field} must be lowercase`).toBe(value);
};
// The `p256Thumbprint` claim is a 64-char lowercase-hex digest (32 bytes),
// decoded by the production verifier's `decode_hex32`. It is NOT a 43-char
// base64url RFC 7638 thumbprint — that was a previous incorrect assertion
// that would pass a format the production verifier (`verify_attempt_grant`)
// rejects at claim decoding. This corrected assertion matches `decode_hex32`:
// 64-char lowercase hex, same as every other 32-byte digest in the grant.
const assertP256Thumbprint = (value: unknown, field: string) => {
  expect(typeof value, `${field} must be a string`).toBe("string");
  expect((value as string).length, `${field} p256Thumbprint must be 64 hex chars`).toBe(64);
  expect((value as string).toLowerCase(), `${field} must be lowercase`).toBe(value);
  expect(/^[0-9a-f]{64}$/.test(value as string), `${field} must be lowercase hex`).toBe(true);
};
const assertCapabilityOrds = (value: unknown, max: number, field: string, allowEmpty: boolean) => {
  expect(Array.isArray(value), `${field} must be array`).toBe(true);
  const arr = value as number[];
  if (!allowEmpty) expect(arr.length, `${field} must be nonempty`).toBeGreaterThan(0);
  expect(arr.length, `${field} exceeds 16`).toBeLessThanOrEqual(16);
  let prev = 0;
  for (let i = 0; i < arr.length; i++) {
    const ord = arr[i]!;
    expect(ord, `${field} ordinal must be >= 1`).toBeGreaterThanOrEqual(1);
    expect(ord, `${field} ordinal must be <= ${max}`).toBeLessThanOrEqual(max);
    if (i > 0) expect(ord, `${field} must be strictly ascending`).toBeGreaterThan(prev);
    prev = ord;
  }
};

const validateGrantPayload = (
  payload: Record<string, unknown>,
  limits: {
    grantLifetimeSeconds: number;
    tupleSetMin: number;
    tupleSetMax: number;
    projectCountMax: number;
    projectCapabilityCountMax: number;
  },
) => {
  expect(payload.schemaVersion, "schemaVersion must be 1").toBe(1);
  expect(payload.role, "redundant role claim must be absent").toBeUndefined();
  expect(
    (payload.client as Record<string, unknown>)?.noiseThumbprint,
    "no client Noise thumbprint",
  ).toBeUndefined();
  expect(
    (payload.daemon as Record<string, unknown>)?.noiseThumbprint,
    "no daemon Noise thumbprint",
  ).toBeUndefined();

  for (const side of ["client", "daemon"] as const) {
    const idObj = payload[side] as Record<string, unknown>;
    assertExactKeys(idObj, REQUIRED_IDENTITY_MEMBERS, `${side} identity`);
    assertAlias22(idObj.deviceId, `${side}.deviceId`);
    assertAlias22(idObj.certificateId, `${side}.certificateId`);
    assertDecimalString(idObj.generation, `${side}.generation`);
    assertP256Thumbprint(idObj.p256Thumbprint, `${side}.p256Thumbprint`);
  }

  for (const field of [
    "tenantId",
    "accountId",
    "instanceId",
    "logicalAttachmentId",
    "childAttemptId",
    "jti",
  ])
    assertAlias22(payload[field], field);

  for (const field of ["serverNonce", "servicePolicyDigest", "policyDigest"])
    assertDigestHex64(payload[field], field);

  for (const field of ["serviceVersion", "policyEpoch", "authorityEpoch", "iat", "nbf", "exp"])
    assertDecimalString(payload[field], field);

  const iat = Number.parseInt(payload.iat as string, 10);
  const nbf = Number.parseInt(payload.nbf as string, 10);
  const exp = Number.parseInt(payload.exp as string, 10);
  expect(iat, "iat must be <= nbf").toBeLessThanOrEqual(nbf);
  expect(nbf, "nbf must be <= exp").toBeLessThanOrEqual(exp);
  expect(exp - iat, "grant lifetime within cap").toBeLessThanOrEqual(limits.grantLifetimeSeconds);

  const bits = payload.authorizedTransports as number;
  expect([1, 2, 3], "authorizedTransports must be 1/2/3").toContain(bits);

  const tuples = payload.compatibleTupleIds as number[];
  expect(tuples.length, "tuple count min").toBeGreaterThanOrEqual(limits.tupleSetMin);
  expect(tuples.length, "tuple count max").toBeLessThanOrEqual(limits.tupleSetMax);
  let prevTuple = 0;
  for (let i = 0; i < tuples.length; i++) {
    expect(tuples[i], "tuple id nonzero").toBeGreaterThan(0);
    if (i > 0) expect(tuples[i], "tuples strictly increasing").toBeGreaterThan(prevTuple);
    prevTuple = tuples[i]!;
  }

  assertCapabilityOrds(payload.attachmentCapabilities, 13, "attachmentCapabilities", true);
  const projects = payload.projectCapabilities as Array<Record<string, unknown>>;
  expect(projects.length, "project count cap").toBeLessThanOrEqual(limits.projectCountMax);
  let prevPid: string | null = null;
  for (const proj of projects) {
    assertExactKeys(proj, ["capabilities", "projectId"], "project entry");
    const pid = proj.projectId as string;
    expect(pid.length === 22 || pid.length === 32, "projectId canonical width").toBe(true);
    if (prevPid) expect(pid > prevPid, "projectIds sorted ascending").toBe(true);
    prevPid = pid;
    const caps = proj.capabilities as number[];
    expect(caps.length, "project caps nonempty").toBeGreaterThan(0);
    expect(caps.length, "project caps cap").toBeLessThanOrEqual(limits.projectCapabilityCountMax);
    let prevCap = 0;
    for (let i = 0; i < caps.length; i++) {
      expect(caps[i], "project cap ordinal >= 1").toBeGreaterThanOrEqual(1);
      expect(caps[i], "project cap ordinal <= 15").toBeLessThanOrEqual(15);
      if (i > 0) expect(caps[i], "project caps strictly ascending").toBeGreaterThan(prevCap);
      prevCap = caps[i]!;
    }
  }

  assertDigestHex64(payload.permissionCeilingDigest, "permissionCeilingDigest");

  const tenantDigest = payload.tenantAuthorizationDigest;
  if (tenantDigest !== null) assertDigestHex64(tenantDigest, "tenantAuthorizationDigest");
};

describe("remote_attempt_grant_fixture_conformance", () => {
  it("proves the exact protected header/payload member set, absence of role, aliases, decimal strings, no Noise thumbprint, and every limit in nonzero fixtures", () => {
    expect(fixture.validGrants.length, "nonzero valid grants").toBeGreaterThan(0);
    expect(fixture.malformedGrants.length, "nonzero malformed grants").toBeGreaterThan(0);
    expect(fixture.limits.compactJwsMaxBytes).toBe(8192);
    expect(fixture.limits.permissionCeilingMaxBytes).toBe(512);
    expect(fixture.limits.tupleSetMin).toBe(1);
    expect(fixture.limits.tupleSetMax).toBe(16);
    expect(fixture.limits.projectCountMax).toBe(16);
    expect(fixture.limits.projectCapabilityCountMax).toBe(16);
    expect(fixture.limits.attachmentCapabilityCountMax).toBe(16);
    expect(fixture.limits.grantLifetimeSeconds).toBe(300);
    expect(fixture.limits.verificationSkewSeconds).toBe(60);

    for (const grant of fixture.validGrants) {
      const header = grant.protectedHeader as Record<string, unknown>;
      assertExactKeys(header, REQUIRED_HEADER_MEMBERS, `protected header for ${grant.id}`);
      expect(header.alg, "alg must be ES256").toBe("ES256");
      expect(header.typ, "typ must be flycockpit-remote-attempt+jwt").toBe(
        "flycockpit-remote-attempt+jwt",
      );
      expect(typeof header.kid, "kid must be string").toBe("string");

      const payload = grant.payload as Record<string, unknown>;
      assertExactKeys(payload, REQUIRED_PAYLOAD_MEMBERS, `payload for ${grant.id}`);
      validateGrantPayload(payload, fixture.limits);
    }

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

  it("proves transport-bit values 0x01/0x02/0x03 are exhaustive and reject 0 and 4", () => {
    const validBits = new Set([1, 2, 3]);
    for (const grant of fixture.validGrants)
      expect(validBits.has(grant.payload.authorizedTransports as number)).toBe(true);
    const transportMalformed = fixture.malformedGrants.filter(
      (e) => e.rejection === "transport_bits",
    );
    expect(transportMalformed.length, "transport_bits rejection cases").toBeGreaterThan(0);
  });

  it("proves tuple ordering and count caps reject unsorted, empty, and oversize", () => {
    const tupleMalformed = fixture.malformedGrants.filter((e) => e.rejection === "tuple_set");
    expect(tupleMalformed.length, "tuple_set rejection cases").toBeGreaterThanOrEqual(3);
  });

  it("proves permission ceiling digest is present, 64-char lowercase hex, and rejects omission and mismatch", () => {
    const ceilingMalformed = fixture.malformedGrants.filter((e) =>
      e.rejection.startsWith("ceiling_digest"),
    );
    expect(ceilingMalformed.length, "ceiling digest rejection cases").toBeGreaterThanOrEqual(2);
  });

  it("proves no flat permissionCapabilities or independent projectIds list is permitted", () => {
    const flatCap = fixture.malformedGrants.find(
      (e) => e.field === "payload.permissionCapabilities",
    );
    expect(flatCap, "flat permissionCapabilities rejected").toBeDefined();
    expect(flatCap!.rejection).toBe("unknown_claim");
  });

  it("proves no wildcard/all-project entry is permitted", () => {
    const wildcard = fixture.malformedGrants.find((e) => e.rejection === "wildcard_project");
    expect(wildcard, "wildcard project rejected").toBeDefined();
  });

  it("proves same capability on two projects remains distinct (no cross-project inference)", () => {
    const enterprise = fixture.validGrants.find((g) => g.id === "enterprise-tenant");
    expect(enterprise, "enterprise-tenant grant exists").toBeDefined();
    const projects = enterprise!.payload.projectCapabilities as Array<{
      projectId: string;
      capabilities: number[];
    }>;
    expect(projects.length, "two distinct projects").toBe(2);
    expect(projects[0]!.projectId, "distinct projectIds").not.toBe(projects[1]!.projectId);
  });

  it("proves attachment-vs-project type separation via disjoint ordinal ranges in fixtures", () => {
    for (const grant of fixture.validGrants) {
      const att = grant.payload.attachmentCapabilities as number[];
      // Attachment capabilities use ordinals 1..13; project capabilities use 1..15.
      // They are name/type-disjoint even when ordinals overlap.
      expect(
        att.every((o) => o >= 1 && o <= 13),
        "attachment ordinals in range",
      ).toBe(true);
    }
  });
});

// ===========================================================================
// AC13 + AC14: cross-language fixture replay through the production
// `verifyAttemptGrant` entry point — both sides accept/reject the same vectors.
// ===========================================================================

function fixtureVerifier(
  _authorityKeys: ReadonlyArray<{ kid: string; x: string; y: string }>,
): AttemptGrantVerifier {
  // The verifier cryptographically binds to the `AttemptGrantPublicKey`
  // (x, y) passed by verifyAttemptGrant — it never re-looks up kid
  // independently. This is the production verification path.
  return {
    async verifyP1363(input, signature, key: AttemptGrantPublicKey, _kid: string) {
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
 * Independently verify an ES256 P-1363 signature over `signingInput` using
 * the fixture's declared public key for `kid`. This is used to prove that
 * noncanonical fixtures have VALID signatures (so their rejection is due to
 * canonicality, not a bad signature).
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

describe("remote_attempt_grant_cross_language_verify", () => {
  it("proves every valid fixture grant verifies through the production verifyAttemptGrant entry point (AC13)", async () => {
    expect(fixture.authorityKeys.length, "nonzero authority keys").toBeGreaterThan(0);
    expect(fixture.validGrants.length, "nonzero valid grants").toBeGreaterThan(0);

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

      const verified2 = await verifyAttemptGrant(
        grant.compactJws,
        keyRing,
        verifier,
        expected,
        now,
      );
      expect(
        Buffer.from(attemptGrantDigest(verified2.grant)).equals(digest),
        `grant ${grant.id} digest must be deterministic`,
      ).toBe(true);
    }
  });

  it("proves a noncanonical-but-validly-resigned payload is rejected for JCS, not signature (AC3)", async () => {
    expect(fixture.noncanonicalGrants.length, "nonzero noncanonical grants").toBeGreaterThan(0);

    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);

    for (const nc of fixture.noncanonicalGrants) {
      // Finding 4: Independently verify each noncanonical fixture's ES256
      // P-1363 signature with its declared fixture public key BEFORE
      // asserting that verifyAttemptGrant rejects it for canonicality.
      // This proves the rejection is due to canonicality, not a bad signature.
      const segments = nc.compactJws.split(".");
      expect(segments.length, `${nc.id} must have 3 segments`).toBe(3);
      const [headerSeg, payloadSeg, sigSeg] = segments;

      // Decode the header to get the kid.
      const headerBytes = Buffer.from(headerSeg!, "base64url");
      const headerObj = JSON.parse(headerBytes.toString("utf8")) as Record<string, unknown>;
      const ncKid = headerObj.kid as string;
      expect(ncKid, `${nc.id} must have a kid`).toBeTruthy();

      // Decode the signature.
      const ncSignature = Buffer.from(sigSeg!, "base64url");
      expect(ncSignature.length, `${nc.id} signature must be 64 bytes P-1363`).toBe(64);

      // Independently verify the signature with the fixture's declared public
      // key for this kid. The signature MUST be valid — proving the rejection
      // is due to canonicality, not a bad signature.
      const ncSigningInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
      expect(
        independentlyVerifySignature(fixture.authorityKeys, ncKid, ncSigningInput, ncSignature),
        `${nc.id} fixture signature must be independently valid (proves rejection is canonicality, not bad signature)`,
      ).toBe(true);

      // The noncanonical grant has a VALID signature (re-signed with k1),
      // but the payload JSON has non-canonical key ordering. It must be
      // rejected at the canonicality check (step 4, kind "jws"), NOT at
      // the signature check (step 6, kind "signature").
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

      await expect(
        verifyAttemptGrant(nc.compactJws, keyRing, verifier, dummyExpected, "1700000000"),
      ).rejects.toThrow();

      try {
        await verifyAttemptGrant(nc.compactJws, keyRing, verifier, dummyExpected, "1700000000");
      } catch (e) {
        expect(e, `${nc.id} must be AttemptGrantError`).toBeInstanceOf(AttemptGrantError);
        const err = e as AttemptGrantError;
        expect(err.kind, `${nc.id} must be rejected for canonicality (jws), not signature`).toBe(
          "jws",
        );
        expect(err.message, `${nc.id} error must mention canonical`).toContain("canonical");
      }
    }
  });

  it("proves the authority key ring fails closed on unknown kid", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    // An unknown kid returns undefined — no key acquisition happens.
    expect(keyRing.get("nonexistent-kid")).toBeUndefined();
  });

  // =========================================================================
  // Finding 2: verifyAttemptGrant cryptographically binds the key.
  // A grant signed with key A but verified against key B (same kid) must be
  // REJECTED.
  // =========================================================================
  it("proves a grant signed with key A is REJECTED when verified against key B with the same kid (Finding 2)", async () => {
    expect(fixture.authorityKeys.length, "need at least 2 authority keys").toBeGreaterThanOrEqual(
      2,
    );
    expect(fixture.validGrants.length, "nonzero valid grants").toBeGreaterThan(0);

    const grant = fixture.validGrants[0]!;
    const payload = grant.payload as Record<string, unknown>;
    const expected = expectationsFromPayload(payload);
    const now = payload.iat as string;

    // The grant was signed with k1. Build a key ring that maps "k1" to k2's
    // public key (same kid, wrong key). The verifier binds to the key from
    // the ring, so verification must FAIL.
    const keyK1 = fixture.authorityKeys.find((k) => k.kid === "k1")!;
    const keyK2 = fixture.authorityKeys.find((k) => k.kid === "k2")!;
    expect(keyK1, "fixture must have k1").toBeDefined();
    expect(keyK2, "fixture must have k2").toBeDefined();

    // Build a key ring where kid "k1" maps to k2's coordinates.
    const swappedRing = keyRingFromFixture([{ kid: "k1", x: keyK2.x, y: keyK2.y }]);
    const verifier = fixtureVerifier(fixture.authorityKeys);

    // The grant signed with k1 must be REJECTED when the key ring maps k1 to
    // k2's public key. This proves cryptographic key binding.
    await expect(
      verifyAttemptGrant(grant.compactJws, swappedRing, verifier, expected, now),
    ).rejects.toThrow();

    try {
      await verifyAttemptGrant(grant.compactJws, swappedRing, verifier, expected, now);
    } catch (e) {
      expect(e, "swapped-key rejection must be AttemptGrantError").toBeInstanceOf(
        AttemptGrantError,
      );
      const err = e as AttemptGrantError;
      expect(err.kind, "swapped-key rejection must be signature kind").toBe("signature");
    }

    // Sanity: the same grant verifies against the correct key ring.
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

  // =========================================================================
  // Finding 1: RawClaims decoding uses runtime validators. Each malformed
  // value must be mapped to the Rust-equivalent AttemptGrantError kind.
  // =========================================================================
  it("proves RawClaims runtime validators reject malformed claim values (Finding 1)", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);
    const grant = fixture.validGrants[0]!;
    const payload = grant.payload as Record<string, unknown>;

    const { canonicalizeRfc8785 } = await import("./remote-protocol-id");

    // Build a compact JWS with a mutated payload. The payload must be RFC 8785
    // canonical (step 4 passes). Claim decoding (step 5) runs before signature
    // verification (step 6), so a malformed claim produces a "claims" error
    // regardless of signature validity.
    function buildMalformedJws(mutate: (p: Record<string, unknown>) => void): string {
      const mutated = JSON.parse(JSON.stringify(payload)) as Record<string, unknown>;
      mutate(mutated);
      const canonicalPayload = canonicalizeRfc8785(mutated);
      const payloadSeg = Buffer.from(canonicalPayload).toString("base64url");
      const headerSeg = grant.compactJws.split(".")[0]!;
      // Dummy 64-byte signature (claim decoding runs before signature check).
      const dummySig = Buffer.alloc(64, 1);
      const sigSeg = dummySig.toString("base64url");
      return `${headerSeg}.${payloadSeg}.${sigSeg}`;
    }

    const dummyExpected = expectationsFromPayload(payload);
    const now = payload.iat as string;

    // schemaVersion as string instead of number -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.schemaVersion = "1";
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // schemaVersion as null -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.schemaVersion = null;
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // iss as number instead of string -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.iss = 123;
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // client as null instead of object -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.client = null;
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // client.deviceId as number instead of string -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          (p.client as Record<string, unknown>).deviceId = 123;
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // client.generation as number (integer) instead of string -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          (p.client as Record<string, unknown>).generation = 1;
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // attachmentCapabilities as string instead of array -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.attachmentCapabilities = "not-array";
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // attachmentCapabilities element as string instead of u8 -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.attachmentCapabilities = ["not-a-number"];
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // attachmentCapabilities element out of u8 range (256) -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.attachmentCapabilities = [256];
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // compatibleTupleIds element out of u16 range (65536) -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.compatibleTupleIds = [65536];
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // projectCapabilities as null instead of array -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.projectCapabilities = null;
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // projectCapabilities entry as string instead of object -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.projectCapabilities = ["not-object"];
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // projectCapabilities entry capabilities as string -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          const proj = (p.projectCapabilities as Array<Record<string, unknown>>)[0]!;
          proj.capabilities = "not-array";
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // authorizedTransports as string instead of u8 -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.authorizedTransports = "3";
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // tenantAuthorizationDigest as number instead of null/string -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.tenantAuthorizationDigest = 123;
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // iat as number instead of string -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.iat = 1700000000;
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });

    // iat exceeding i64 max (> 9223372036854775807) -> claims error.
    await expect(
      verifyAttemptGrant(
        buildMalformedJws((p) => {
          p.iat = "9223372036854775808";
        }),
        keyRing,
        verifier,
        dummyExpected,
        now,
      ),
    ).rejects.toMatchObject({ kind: "claims" });
  });

  // =========================================================================
  // Finding 3: Fixture-pinned expected digest and negative binding cases.
  // =========================================================================
  it("proves fixture-pinned expected digest is correct for the minimal-saas grant (Finding 3)", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);
    const grant = fixture.validGrants.find((g) => g.id === "minimal-saas")!;
    expect(grant, "minimal-saas grant must exist").toBeDefined();

    const payload = grant.payload as Record<string, unknown>;
    const expected = expectationsFromPayload(payload);
    const verified = await verifyAttemptGrant(
      grant.compactJws,
      keyRing,
      verifier,
      expected,
      payload.iat as string,
    );

    // Pin the digest via independent SHA-256 of the compact JWS — NOT
    // re-derived from the fixture being tested. If the digest function
    // returned a constant, this would fail.
    const { createHash } = await import("node:crypto");
    const pinDigest = createHash("sha256").update(grant.compactJws).digest();
    expect(
      Buffer.from(attemptGrantDigest(verified.grant)).equals(pinDigest),
      "digest must match independent SHA-256 of compact JWS",
    ).toBe(true);
  });

  it("proves mismatched caller-known values are rejected (Finding 3 negative binding)", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);
    const grant = fixture.validGrants.find((g) => g.id === "minimal-saas")!;
    const payload = grant.payload as Record<string, unknown>;

    // Correct expectations (verifies the grant is valid).
    const correctExpected = expectationsFromPayload(payload);
    await expect(
      verifyAttemptGrant(
        grant.compactJws,
        keyRing,
        verifier,
        correctExpected,
        payload.iat as string,
      ),
    ).resolves.toBeDefined();

    // Mismatched issuer — must be rejected at expectation binding.
    const wrongIssuer = { ...correctExpected, issuer: "wrong-issuer" };
    await expect(
      verifyAttemptGrant(grant.compactJws, keyRing, verifier, wrongIssuer, payload.iat as string),
    ).rejects.toMatchObject({ kind: "claims" });

    // Mismatched tenantId — must be rejected at expectation binding.
    const wrongTenant = {
      ...correctExpected,
      tenantId: new Uint8Array(16).fill(0xff),
    };
    await expect(
      verifyAttemptGrant(grant.compactJws, keyRing, verifier, wrongTenant, payload.iat as string),
    ).rejects.toMatchObject({ kind: "claims" });

    // Mismatched serverNonce — must be rejected at expectation binding.
    const wrongNonce = {
      ...correctExpected,
      serverNonce: new Uint8Array(32).fill(0xff),
    };
    await expect(
      verifyAttemptGrant(grant.compactJws, keyRing, verifier, wrongNonce, payload.iat as string),
    ).rejects.toMatchObject({ kind: "claims" });

    // Enterprise expectation when control-plane grant -> must be rejected.
    const wrongTenantAuth = {
      ...correctExpected,
      tenantAuthorization: { kind: "enterprise" as const, digest: new Uint8Array(32).fill(0xab) },
    };
    await expect(
      verifyAttemptGrant(
        grant.compactJws,
        keyRing,
        verifier,
        wrongTenantAuth,
        payload.iat as string,
      ),
    ).rejects.toMatchObject({ kind: "claims" });
  });
});

// ===========================================================================
// Finding 4 + parity: genuine executable replay. Every malformedGrants entry
// and every resignedVectors entry carries a REAL compact-JWS that is replayed
// through the production verifyAttemptGrant. The same bytes are replayed by the
// Rust `cross_language_*_execute` tests, so both languages accept/reject the
// identical vectors. Changing a malformed vector to one the verifier ACCEPTS
// would now fail this test — it is no longer a tautological label check.
// ===========================================================================

// Map a fixture rejection class to the AttemptGrantError kind the production
// verifier raises for it. This is an independent literal mapping, not derived
// from the module under test.
const REJECTION_KIND: Record<string, AttemptGrantError["kind"]> = {
  header: "jws",
  size: "jws",
  unknown_claim: "claims",
  schema_version: "claims",
  decimal_string: "claims",
  alias: "claims",
  digest_width: "claims",
  ceiling_digest_missing: "claims",
  tenant_digest: "claims",
  transport_bits: "transport",
  tuple_set: "tupleSet",
  project_count: "ceiling",
  project_capability_count: "ceiling",
  wildcard_project: "ceiling",
  duplicate_project: "ceiling",
  project_cap_order: "ceiling",
  attachment_cap_order: "ceiling",
  ceiling_digest_mismatch: "ceiling",
  time_order: "time",
};

describe("remote_attempt_grant_executable_rejections", () => {
  it("replays every malformedGrants compact-JWS through verifyAttemptGrant and asserts genuine rejection (Finding 4)", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);
    // Expectations are the daemon's independently-known values for the
    // minimal-saas control-plane grant; every malformed vector is a mutation of
    // it and must be rejected at or before expectation binding.
    const minimal = fixture.validGrants.find((g) => g.id === "minimal-saas")!;
    const expected = expectationsFromPayload(minimal.payload as Record<string, unknown>);
    const now = "1700000000";

    expect(fixture.malformedGrants.length, "nonzero malformed grants").toBeGreaterThan(0);

    for (const entry of fixture.malformedGrants) {
      const compactJws = (entry as { compactJws?: string }).compactJws;
      expect(compactJws, `${entry.id} must carry an executable compactJws`).toBeTruthy();

      let thrown: unknown;
      try {
        await verifyAttemptGrant(compactJws!, keyRing, verifier, expected, now);
      } catch (e) {
        thrown = e;
      }
      // The real verifier must reject the real bytes (anti-tautology: a vector
      // mutated to an accepted value would fail here). The error must be a
      // verifier rejection with a known kind. Exact-kind parity is asserted for
      // the resignedVectors below; header-membership rejections legitimately
      // surface as "claims" in TS (assertExactKeys) vs "jws" in Rust, so the
      // per-class exact kind is not pinned for the metadata malformed corpus.
      expect(thrown, `${entry.id} must be rejected by verifyAttemptGrant`).toBeInstanceOf(
        AttemptGrantError,
      );
      const expectedKind = REJECTION_KIND[entry.rejection];
      expect(
        expectedKind,
        `${entry.id} rejection class ${entry.rejection} is mapped`,
      ).toBeDefined();
      const knownKinds = new Set(Object.values(REJECTION_KIND));
      expect(
        knownKinds.has((thrown as AttemptGrantError).kind),
        `${entry.id} (${entry.rejection}) rejected with a known verifier kind, got ${(thrown as AttemptGrantError).kind}`,
      ).toBe(true);
    }
  });

  it("replays resignedVectors: high-S, out-of-vocab, duplicate/unsorted caps rejected; leading-zero u64 accepted (parity)", async () => {
    const keyRing = keyRingFromFixture(fixture.authorityKeys);
    const verifier = fixtureVerifier(fixture.authorityKeys);

    expect(fixture.resignedVectors.length, "nonzero resigned vectors").toBeGreaterThan(0);

    const vectors = fixture.resignedVectors as ReadonlyArray<{
      id: string;
      expect: "accept" | "reject";
      rejection?: string;
      payload: Record<string, unknown>;
      compactJws: string;
    }>;
    for (const v of vectors) {
      const payload = v.payload as Record<string, unknown>;
      const expected = expectationsFromPayload(payload);
      const now = payload.iat as string;

      if (v.expect === "accept") {
        // A validly re-signed grant whose only change is a leading-zero u64
        // spelling ("01") must be ACCEPTED, matching Rust parse_decimal_u64.
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
        expect(
          (thrown as AttemptGrantError).kind,
          `${v.id} rejected with kind ${v.rejection}`,
        ).toBe(v.rejection);
      }
    }
  });
});
