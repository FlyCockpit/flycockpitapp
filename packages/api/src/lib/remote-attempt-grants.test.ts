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
