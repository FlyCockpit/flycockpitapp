import { describe, expect, it } from "vitest";
import webauthnFixtures from "../fixtures/remote-admin-webauthn-v1.json";
import {
  decodeRemoteAdminApprovalEvidenceV1,
  decodeRemoteCredentialRegistryV1,
  encodeRemoteAdminApprovalEvidenceV1,
  encodeRemoteCredentialRegistryV1,
  type RemoteAdminOperation,
} from "./remote-admin-passkey";
import { tagProtocolIdBytes } from "./remote-protocol-id";

const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);
describe("remote_admin_webauthn_registration_assertion", () => {
  it("commits browser, hardware-key, and UV-rejection interoperability fixtures", () => {
    expect(webauthnFixtures.version).toBe(1);
    expect(webauthnFixtures.fixtures.map((fixture) => fixture.name)).toEqual([
      "browser-synced-passkey",
      "external-security-key",
      "uv-missing-rejected",
    ]);
    for (const fixture of webauthnFixtures.fixtures) {
      expect(Boolean(fixture.authenticatorFlags & 0x01)).toBe(fixture.userPresent);
      expect(Boolean(fixture.authenticatorFlags & 0x04)).toBe(fixture.userVerified);
      expect(Boolean(fixture.authenticatorFlags & 0x08)).toBe(fixture.backupEligible);
      expect(Boolean(fixture.authenticatorFlags & 0x10)).toBe(fixture.backupState);
    }
  });
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

  it("round trips every FCWA operation 1..11 and rejects 0 and 12", () => {
    const encodeWithOperation = (operation: number): Uint8Array =>
      encodeRemoteAdminApprovalEvidenceV1({
        tenantId: tagProtocolIdBytes("tenant", bytes(16, 1)),
        principalId: tagProtocolIdBytes("account", bytes(16, 2)),
        role: 2,
        registryGeneration: 9n,
        credentialIdHash: bytes(32, 3),
        operation: operation as RemoteAdminOperation,
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
    for (let operation = 1; operation <= 11; operation++) {
      const encoded = encodeWithOperation(operation);
      // Operation byte lives at offset 78 (magic4+ver1+tenant16+principal16+role1+gen8+hash32).
      expect(encoded[78]).toBe(operation);
      expect(decodeRemoteAdminApprovalEvidenceV1(encoded).operation).toBe(operation);
    }
    expect(() => encodeWithOperation(0)).toThrow("approval_discriminant");
    expect(() => encodeWithOperation(12)).toThrow("approval_discriminant");
    // Tamper a valid operation-11 encoding up to 12 and confirm decode rejects it,
    // so the bound is enforced on the wire and not only at encode time.
    const eleven = encodeWithOperation(11);
    const twelve = eleven.slice();
    twelve[78] = 12;
    expect(() => decodeRemoteAdminApprovalEvidenceV1(twelve)).toThrow("approval_discriminant");
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
    const earlier = { ...entry, principalId: tagProtocolIdBytes("account", bytes(16, 1)) };
    expect(() => encodeRemoteCredentialRegistryV1({ ...base, entries: [entry, earlier] })).toThrow(
      "entries_unsorted",
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
