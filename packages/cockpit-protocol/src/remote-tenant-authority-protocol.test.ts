import { describe, expect, it } from "vitest";
import registry from "../fixtures/remote-wire-magic-registry-v1.json";
import fixture from "../fixtures/tenant-authority-protocol-v1.json";
import {
  approvalCardinality,
  assertTenantAuthorityWireMagics,
  closedSurfaceGuard,
  EVIDENCE_TYPES,
  FCIR_REASONS,
  FCTA_ENVELOPE_VERSION,
  FCTA_VALIDITY_SECONDS,
  FCTO_REASON_CODES,
  FCTO_RESULT_KINDS,
  FUTURE_ISSUED_TOLERANCE_SECONDS,
  foundationConsumptionGuard,
  IDEMPOTENCY_RETENTION_HOURS,
  isCrossProtocolMagic,
  MAX_ARTIFACT_BYTES,
  MAX_BODY_BYTES,
  MAX_FCTV_RESULT_BYTES,
  MAX_REQUEST_BYTES,
  MAX_RESULT_BYTES,
  MAX_STATEMENT_JWS_BYTES,
  NETWORK_DEADLINE_SECONDS,
  RETENTION_FLOOR_SECONDS,
  SIGNING_DOMAINS,
  STATEMENT_LIFETIME_ATTEMPT,
  STATEMENT_LIFETIME_DENIAL_STATUS,
  STATEMENT_LIFETIME_HIGH_ASSURANCE,
  TENANT_AUTHORITY_MAGICS,
  TENANT_AUTHORITY_OPERATIONS,
  tenantAuthorityOperationFromDiscriminant,
  VERIFIER_CACHE_SECONDS,
  VERIFIER_SKEW_SECONDS,
  validateNormalizedHttpsOrigin,
} from "./remote-tenant-authority-protocol";
import { parseRemoteWireMagicRegistry } from "./remote-wire-magic-registry";

describe("tenant_authority_protocol_cross_language_vectors", () => {
  it("proves the closed surface of eleven operations", () => {
    closedSurfaceGuard();
    foundationConsumptionGuard();
    expect(fixture.operations).toHaveLength(11);
    for (let i = 0; i < fixture.operations.length; i++) {
      const op = fixture.operations[i]!;
      expect(op.discriminant).toBe(i + 1);
      const parsed = tenantAuthorityOperationFromDiscriminant(op.discriminant);
      expect(parsed.name).toBe(op.name);
    }
    expect(TENANT_AUTHORITY_OPERATIONS).toHaveLength(11);
  });

  it("proves the twenty evidence types partition", () => {
    expect(fixture.evidenceTypes).toHaveLength(20);
    expect(EVIDENCE_TYPES).toHaveLength(20);
    for (let i = 0; i < fixture.evidenceTypes.length; i++) {
      const et = fixture.evidenceTypes[i]!;
      expect(et.discriminant).toBe(i + 1);
      const parsed = EVIDENCE_TYPES[i]!;
      expect(parsed.name).toBe(et.name);
      expect(parsed.cap).toBe(et.cap);
      expect(parsed.category).toBe(et.category);
    }
    const jws = EVIDENCE_TYPES.filter((e) => e.category === "compact_jws").length;
    const json = EVIDENCE_TYPES.filter((e) => e.category === "canonical_json").length;
    const bin = EVIDENCE_TYPES.filter((e) => e.category === "binary").length;
    expect(jws).toBe(6);
    expect(json).toBe(1);
    expect(bin).toBe(13);
  });

  it("proves the five FCTO result kinds and nineteen reason codes", () => {
    expect(fixture.resultKinds).toHaveLength(5);
    expect(FCTO_RESULT_KINDS).toHaveLength(5);
    for (let i = 0; i < fixture.resultKinds.length; i++) {
      expect(fixture.resultKinds[i]!.discriminant).toBe(i + 1);
      expect(FCTO_RESULT_KINDS[i]!.discriminant).toBe(i + 1);
      expect(FCTO_RESULT_KINDS[i]!.name).toBe(fixture.resultKinds[i]!.name);
    }
    expect(fixture.reasonCodes).toHaveLength(19);
    expect(FCTO_REASON_CODES).toHaveLength(19);
    expect(FCTO_REASON_CODES[0].discriminant).toBe(0);
  });

  it("proves the six signing domains", () => {
    expect(fixture.signingDomains).toHaveLength(6);
    expect(SIGNING_DOMAINS).toHaveLength(6);
    for (const name of fixture.signingDomains) {
      expect(SIGNING_DOMAINS.some((d) => d.name === name)).toBe(true);
    }
  });

  it("proves envelope constants match the fixture", () => {
    expect(fixture.envelope.magic).toBe(TENANT_AUTHORITY_MAGICS.fcta);
    expect(fixture.envelope.version).toBe(FCTA_ENVELOPE_VERSION);
    expect(fixture.envelope.maxBodyBytes).toBe(MAX_BODY_BYTES);
    expect(fixture.envelope.maxRequestBytes).toBe(MAX_REQUEST_BYTES);
    expect(fixture.envelope.maxResultBytes).toBe(MAX_RESULT_BYTES);
    expect(fixture.envelope.maxStatementJwsBytes).toBe(MAX_STATEMENT_JWS_BYTES);
    expect(fixture.envelope.maxArtifactBytes).toBe(MAX_ARTIFACT_BYTES);
    expect(fixture.envelope.maxFctvBytes).toBe(MAX_FCTV_RESULT_BYTES);
    expect(fixture.envelope.validitySeconds).toBe(FCTA_VALIDITY_SECONDS);
    expect(fixture.envelope.futureIssuedToleranceSeconds).toBe(FUTURE_ISSUED_TOLERANCE_SECONDS);
    expect(fixture.envelope.networkDeadlineSeconds).toBe(NETWORK_DEADLINE_SECONDS);
    expect(fixture.envelope.idempotencyRetentionHours).toBe(IDEMPOTENCY_RETENTION_HOURS);
  });

  it("proves FCIR reasons", () => {
    expect(fixture.fctirReasons).toHaveLength(5);
    expect(FCIR_REASONS).toHaveLength(5);
    for (let i = 0; i < fixture.fctirReasons.length; i++) {
      expect(fixture.fctirReasons[i]!.discriminant).toBe(i + 1);
      expect(FCIR_REASONS[i]!.discriminant).toBe(i + 1);
      expect(FCIR_REASONS[i]!.name).toBe(fixture.fctirReasons[i]!.name);
    }
  });

  it("proves statement lifetimes", () => {
    expect(fixture.statementLifetimes.attempt).toBe(STATEMENT_LIFETIME_ATTEMPT);
    expect(fixture.statementLifetimes.activation).toBe(STATEMENT_LIFETIME_HIGH_ASSURANCE);
    expect(fixture.statementLifetimes.denial).toBe(STATEMENT_LIFETIME_DENIAL_STATUS);
    expect(fixture.statementLifetimes.status).toBe(STATEMENT_LIFETIME_DENIAL_STATUS);
    expect(fixture.statementLifetimes.verifierCacheSeconds).toBe(VERIFIER_CACHE_SECONDS);
    expect(fixture.statementLifetimes.verifierSkewSeconds).toBe(VERIFIER_SKEW_SECONDS);
    expect(fixture.statementLifetimes.retentionFloorSeconds).toBe(RETENTION_FLOOR_SECONDS);
  });

  it("proves wire-magic registry ownership and cross-protocol rejection", () => {
    expect(fixture.wireMagics.FCTA).toBe("RemoteTenantAuthorityAuthorizationV1");
    expect(fixture.wireMagics.FCTO).toBe("RemoteTenantAuthorityResultV1");
    expect(fixture.wireMagics.FCTV).toBe("RemoteTenantAuthorityRevocationEvidenceV1");
    expect(fixture.wireMagics.FCIR).toBe("RemoteIdentityRevocationRequestV1");
    const parsed = parseRemoteWireMagicRegistry(registry);
    assertTenantAuthorityWireMagics(parsed);
    expect(fixture.crossProtocolMagics.turn).toBe("FCTR");
    expect(fixture.crossProtocolMagics.relationshipConsent).toBe("FCRS");
    expect(isCrossProtocolMagic("FCTR")).toBe(true);
    expect(isCrossProtocolMagic("FCRS")).toBe(true);
    expect(isCrossProtocolMagic("FCTA")).toBe(false);
  });

  it("proves the approval cardinality matrix", () => {
    expect(approvalCardinality(4, undefined)).toBe("none");
    expect(approvalCardinality(9, undefined)).toBe("none");
    expect(approvalCardinality(10, undefined)).toBe("none");
    expect(approvalCardinality(1, undefined)).toBe("owner_plus_security_admin");
    expect(approvalCardinality(5, undefined)).toBe("owner_plus_security_admin");
    expect(approvalCardinality(8, undefined)).toBe("owner_plus_security_admin");
    expect(approvalCardinality(6, undefined)).toBe("owner_plus_security_admin");
    expect(approvalCardinality(2, 1)).toBe("one_security_admin");
    expect(approvalCardinality(2, 2)).toBe("none");
    expect(approvalCardinality(2, 3)).toBe("one_security_admin");
    expect(approvalCardinality(11, 1)).toBe("none");
    expect(approvalCardinality(11, 2)).toBe("one_security_admin");
    expect(approvalCardinality(3, 1)).toBe("one_security_admin");
    expect(approvalCardinality(3, 2)).toBe("owner_plus_security_admin");
    expect(approvalCardinality(7, 4)).toBe("none");
    expect(approvalCardinality(7, 1)).toBe("owner_plus_security_admin");
  });

  it("validates normalized HTTPS origins", () => {
    expect(() => validateNormalizedHttpsOrigin("https://tenant.flycockpit.example")).not.toThrow();
    expect(() =>
      validateNormalizedHttpsOrigin("https://tenant.flycockpit.example:8443"),
    ).not.toThrow();
    expect(() => validateNormalizedHttpsOrigin("http://tenant.flycockpit.example")).toThrow();
    expect(() => validateNormalizedHttpsOrigin("https://Tenant.flycockpit.example")).toThrow();
    expect(() => validateNormalizedHttpsOrigin("https://tenant.flycockpit.example:443")).toThrow();
    expect(() => validateNormalizedHttpsOrigin("https://tenant.flycockpit.example/")).toThrow();
    expect(() => validateNormalizedHttpsOrigin("https://tenant.flycockpit.example?q=1")).toThrow();
  });
});
