import { describe, expect, it } from "vitest";
import {
  decodeRemoteAdminApprovalEvidenceV1,
  decodeRemoteCredentialRegistryV1,
  encodeRemoteAdminApprovalEvidenceV1,
  encodeRemoteCredentialRegistryV1,
} from "./remote-admin-passkey";
import { tagProtocolIdBytes } from "./remote-protocol-id";

const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);
describe("remote_admin_webauthn_registration_assertion", () => {
  it("round trips the exact FCWR format and rejects trailing bytes", () => {
    const encoded = encodeRemoteCredentialRegistryV1({
      tenantId: tagProtocolIdBytes("tenant", bytes(16, 1)),
      registryGeneration: 1n,
      rpId: "admin.example.com",
      origin: "https://admin.example.com",
      entries: [
        {
          principalId: tagProtocolIdBytes("account", bytes(16, 2)),
          role: 1,
          credentialIdHash: bytes(32, 3),
          coseAlg: -7,
          p256X: bytes(32, 4),
          p256Y: bytes(32, 5),
          declaredCustody: 2,
          state: 1,
          createdAt: 10n,
          revokedAt: null,
        },
      ],
    });
    expect(new TextDecoder().decode(encoded.slice(0, 4))).toBe("FCWR");
    expect(decodeRemoteCredentialRegistryV1(encoded, () => true).registryGeneration).toBe(1n);
    expect(() =>
      decodeRemoteCredentialRegistryV1(new Uint8Array([...encoded, 0]), () => true),
    ).toThrow("trailing_bytes");
  });

  it("round trips the exact FCWA field order and closed discriminants", () => {
    const evidence = encodeRemoteAdminApprovalEvidenceV1({
      tenantId: tagProtocolIdBytes("tenant", bytes(16, 1)),
      principalId: tagProtocolIdBytes("account", bytes(16, 2)),
      role: 2,
      registryGeneration: 9n,
      credentialIdHash: bytes(32, 3),
      operation: 4,
      canonicalRequestDigest: bytes(32, 4),
      operationEpoch: 10n,
      issuedAt: 11n,
      expiresAt: 12n,
      challengeId: bytes(16, 5),
      challengeHash: bytes(32, 6),
      rpId: "admin.example.com",
      origin: "https://admin.example.com",
      authenticatorData: bytes(37, 7),
      clientDataJson: new TextEncoder().encode("{}"),
      coseAlg: -7,
      signatureP1363: bytes(64, 8),
    });
    expect(new TextDecoder().decode(evidence.slice(0, 4))).toBe("FCWA");
    const decoded = decodeRemoteAdminApprovalEvidenceV1(evidence);
    expect(decoded.registryGeneration).toBe(9n);
    expect(decoded.operation).toBe(4);
    expect(decoded.signatureP1363).toEqual(bytes(64, 8));
    expect(() => decodeRemoteAdminApprovalEvidenceV1(new Uint8Array([...evidence, 0]))).toThrow(
      "trailing_bytes",
    );
    const unknownOperation = evidence.slice();
    unknownOperation[78] = 0;
    expect(() => decodeRemoteAdminApprovalEvidenceV1(unknownOperation)).toThrow(
      "approval_discriminant",
    );
  });

  it("rejects invalid RP/origin and duplicate credential identities", () => {
    const entry = {
      principalId: tagProtocolIdBytes("account", bytes(16, 2)),
      role: 1 as const,
      credentialIdHash: bytes(32, 3),
      coseAlg: -7 as const,
      p256X: bytes(32, 4),
      p256Y: bytes(32, 5),
      declaredCustody: 2 as const,
      state: 1 as const,
      createdAt: 10n,
      revokedAt: null,
    };
    const base = {
      tenantId: tagProtocolIdBytes("tenant", bytes(16, 1)),
      registryGeneration: 1n,
      rpId: "admin.example.com",
      origin: "https://admin.example.com",
    };
    expect(() => encodeRemoteCredentialRegistryV1({ ...base, entries: [entry, entry] })).toThrow(
      "duplicate_entry",
    );
    expect(() =>
      encodeRemoteCredentialRegistryV1({ ...base, rpId: "UPPER.example", entries: [entry] }),
    ).toThrow("rp_id_invalid");
    expect(() =>
      encodeRemoteCredentialRegistryV1({
        ...base,
        origin: "http://admin.example.com",
        entries: [entry],
      }),
    ).toThrow("origin_invalid");
  });
});
