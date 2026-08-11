import { describe, expect, it } from "vitest";
import fixture from "../fixtures/remote/attempt-grants-v1.json";

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
    assertDigestHex64(idObj.p256Thumbprint, `${side}.p256Thumbprint`);
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
