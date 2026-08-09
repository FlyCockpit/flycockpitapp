import { tagProtocolIdBytes } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import { type BootstrapChallenge, commitRemoteAdminBootstrap } from "./remote-admin-bootstrap";
import { classifyRemotePolicyRevision } from "./remote-admin-policy";
import {
  actionRequiresDualControl,
  assertQuorumAfterChange,
  assertRequiredApprovalPair,
  REMOTE_ADMIN_ACTIONS,
  roleCanStartAction,
} from "./remote-admin-roles";
import {
  consumeStepUp,
  evaluateAndAdvanceCounter,
  RECOVERY_COOLING_DEFAULT_SECONDS,
  RECOVERY_TTL_DEFAULT_SECONDS,
  recoveryReady,
  validateRecoveryTiming,
} from "./remote-admin-state";
import {
  normalizeCanonicalLowSDerSignature,
  verifyPortableRemoteAdminApproval,
} from "./remote-admin-webauthn";

describe("remote_admin_roles_corrected_tests_first", () => {
  it("exhausts the closed role/action matrix", () => {
    const owner = new Set([
      "tenant_lifecycle",
      "billing",
      "membership",
      "ordinary_role_assignment",
      "enterprise_log_export",
      "credential_governance",
      "security_role_change",
      "remote_connection_policy_weakening",
      "authority_activation",
      "signer_replacement",
      "recovery",
    ]);
    const security = new Set([
      "credential_governance",
      "security_role_change",
      "tenant_signer_configuration",
      "remote_connection_policy_equal_or_stronger",
      "remote_connection_policy_weakening",
      "device_daemon_trust",
      "authority_activation",
      "signer_replacement",
      "recovery",
    ]);
    for (const action of REMOTE_ADMIN_ACTIONS) {
      expect(roleCanStartAction("MEMBER", action), `MEMBER ${action}`).toBe(false);
      expect(roleCanStartAction("OWNER", action), `OWNER ${action}`).toBe(owner.has(action));
      expect(roleCanStartAction("SECURITY_ADMIN", action), `SECURITY_ADMIN ${action}`).toBe(
        security.has(action),
      );
    }
    for (const action of [
      "authority_activation",
      "signer_replacement",
      "recovery",
      "security_role_change",
      "credential_governance",
      "remote_connection_policy_weakening",
    ] as const)
      expect(actionRequiresDualControl(action)).toBe(true);
  });
  it("requires distinct owner and security administrator and protects last quorum", () => {
    const owner = { principalId: "owner", credentialIdHash: "a", role: "OWNER" as const };
    const security = {
      principalId: "security",
      credentialIdHash: "b",
      role: "SECURITY_ADMIN" as const,
    };
    expect(() => assertRequiredApprovalPair("recovery", [owner, security])).not.toThrow();
    expect(() =>
      assertRequiredApprovalPair("recovery", [owner, { ...security, principalId: "owner" }]),
    ).toThrow();
    expect(() =>
      assertQuorumAfterChange({ activeOwners: 1, activeSecurityAdmins: 1, ownerDelta: -1 }),
    ).toThrow("last_owner_protected");
  });
});

describe("remote_admin_step_up_scope", () => {
  it("binds five minute step-up to exact scope and consumes once", () => {
    const row = {
      id: "opaque",
      tenantId: "t",
      principalId: "p",
      credentialIdHash: "hash",
      role: "OWNER" as const,
      action: "billing" as const,
      sessionId: "s",
      challengeId: "c",
      issuedAt: 100,
      expiresAt: 300_100,
      consumedAt: null,
    };
    const scope = {
      tenantId: "t",
      principalId: "p",
      credentialIdHash: "hash",
      role: "OWNER" as const,
      action: "billing" as const,
      sessionId: "s",
      challengeId: "c",
    };
    consumeStepUp(row, scope, 200);
    expect(() => consumeStepUp(row, scope, 201)).toThrow("consumed");
  });
});

describe("remote_admin_dual_control_distinctness", () => {
  it("accepts only a distinct OWNER plus SECURITY_ADMIN", () => {
    const owner = { principalId: "owner", credentialIdHash: "owner-key", role: "OWNER" as const };
    const security = {
      principalId: "security",
      credentialIdHash: "security-key",
      role: "SECURITY_ADMIN" as const,
    };
    expect(() =>
      assertRequiredApprovalPair("authority_activation", [owner, security]),
    ).not.toThrow();
    expect(() =>
      assertRequiredApprovalPair("authority_activation", [
        owner,
        { ...security, principalId: "owner" },
      ]),
    ).toThrow("principals_not_distinct");
    expect(() =>
      assertRequiredApprovalPair("authority_activation", [
        owner,
        { ...security, credentialIdHash: "owner-key" },
      ]),
    ).toThrow("credentials_not_distinct");
    expect(() =>
      assertRequiredApprovalPair("authority_activation", [
        owner,
        { ...owner, principalId: "owner-2", credentialIdHash: "owner-key-2" },
      ]),
    ).toThrow("role_pair_invalid");
  });
});

describe("remote_admin_policy_weakening", () => {
  const current = {
    minimumProtocolVersion: 2,
    minimumKeyBits: 256,
    sessionTtlSeconds: 300,
    attemptGrantTtlSeconds: 60,
    requireDeviceTrust: true,
    requireDaemonTrust: true,
  };
  it("computes weakening across every security dimension", () => {
    expect(classifyRemotePolicyRevision(current, current)).toBe("equal_or_stronger");
    expect(classifyRemotePolicyRevision(current, { ...current, minimumProtocolVersion: 1 })).toBe(
      "weakening",
    );
    expect(classifyRemotePolicyRevision(current, { ...current, sessionTtlSeconds: 301 })).toBe(
      "weakening",
    );
    expect(classifyRemotePolicyRevision(current, { ...current, requireDeviceTrust: false })).toBe(
      "weakening",
    );
  });
});

describe("remote_admin_webauthn_registration_assertion", () => {
  it("strictly normalizes only canonical low-S DER", () => {
    const normalized = normalizeCanonicalLowSDerSignature(
      Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01),
    );
    expect(normalized).toHaveLength(64);
    expect(normalized[31]).toBe(1);
    expect(normalized[63]).toBe(1);
    expect(() =>
      normalizeCanonicalLowSDerSignature(
        Uint8Array.of(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01),
      ),
    ).toThrow("noncanonical");
    expect(() => normalizeCanonicalLowSDerSignature(Uint8Array.of(0x30, 0))).toThrow();
  });

  it("applies signer-owned counter rules", () => {
    expect(
      evaluateAndAdvanceCounter(
        { lastAcceptedSignCount: 0n, state: "active", stateGeneration: 1n },
        0n,
      ).next.lastAcceptedSignCount,
    ).toBe(0n);
    expect(
      evaluateAndAdvanceCounter(
        { lastAcceptedSignCount: 1n, state: "active", stateGeneration: 1n },
        2n,
      ).next.lastAcceptedSignCount,
    ).toBe(2n);
    expect(
      evaluateAndAdvanceCounter(
        { lastAcceptedSignCount: 2n, state: "active", stateGeneration: 1n },
        2n,
      ).next.state,
    ).toBe("suspect");
  });

  it("independently verifies portable P1363 evidence without a session assertion", async () => {
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
    const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
    const decode = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
    const challenge = new Uint8Array(32).fill(7);
    const rpId = "admin.example.com",
      origin = "https://admin.example.com";
    const clientDataJson = new TextEncoder().encode(
      JSON.stringify({
        type: "webauthn.get",
        challenge: Buffer.from(challenge).toString("base64url"),
        origin,
        crossOrigin: false,
      }),
    );
    const authenticatorData = new Uint8Array(37);
    authenticatorData.set(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId))),
      0,
    );
    authenticatorData[32] = 0x05;
    const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJson));
    const signed = new Uint8Array(authenticatorData.length + clientHash.length);
    signed.set(authenticatorData);
    signed.set(clientHash, authenticatorData.length);
    const signatureP1363 = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, signed),
    );
    const credential = {
      principalId: tagProtocolIdBytes("account", new Uint8Array(16).fill(1)),
      role: 1 as const,
      credentialIdHash: new Uint8Array(32).fill(2),
      coseAlg: -7 as const,
      p256X: decode(jwk.x!),
      p256Y: decode(jwk.y!),
      declaredCustody: 3 as const,
      state: 1 as const,
      createdAt: 1n,
      revokedAt: null,
    };
    await expect(
      verifyPortableRemoteAdminApproval({
        credential,
        policy: { rpId, origin },
        expectedChallenge: challenge,
        evidence: {
          tenantId: tagProtocolIdBytes("tenant", new Uint8Array(16).fill(3)),
          principalId: credential.principalId,
          role: 1,
          registryGeneration: 1n,
          credentialIdHash: credential.credentialIdHash,
          operation: 5,
          canonicalRequestDigest: new Uint8Array(32),
          operationEpoch: 1n,
          issuedAt: 1n,
          expiresAt: 2n,
          challengeId: new Uint8Array(16),
          challengeHash: new Uint8Array(await crypto.subtle.digest("SHA-256", challenge)),
          rpId,
          origin,
          authenticatorData,
          clientDataJson,
          coseAlg: -7,
          signatureP1363,
        },
      }),
    ).resolves.toEqual({ signCount: 0n });
  });
});

describe("remote_admin_recovery_timeline", () => {
  it("enforces configured boundaries, cooling, reconfirmation, and expiry", () => {
    expect(() =>
      validateRecoveryTiming(RECOVERY_COOLING_DEFAULT_SECONDS, RECOVERY_TTL_DEFAULT_SECONDS),
    ).not.toThrow();
    expect(() => validateRecoveryTiming(86_399, RECOVERY_TTL_DEFAULT_SECONDS)).toThrow();
    expect(() => validateRecoveryTiming(604_801, 700_000)).toThrow();
    expect(() => validateRecoveryTiming(100_000, 186_399)).toThrow();
    expect(() => validateRecoveryTiming(100_000, 2_592_001)).toThrow();
    const proposal = {
      digest: "d",
      ownerId: "o",
      securityAdminId: "s",
      coolingEndsAt: 10,
      expiresAt: 20,
      ownerReconfirmedAt: 11,
      securityReconfirmedAt: 12,
      state: "PENDING" as const,
    };
    expect(() => recoveryReady(proposal, 12, "d")).not.toThrow();
    expect(() => recoveryReady(proposal, 21, "d")).toThrow();
    expect(() => recoveryReady({ ...proposal, ownerReconfirmedAt: 9 }, 12, "d")).toThrow();
    expect(() => recoveryReady({ ...proposal, state: "CANCELLED" as const }, 12, "d")).toThrow();
  });
});

describe("remote_admin_lockout_guards", () => {
  it("atomically seals generation-1 owner bootstrap and returns an exact retry", async () => {
    const digest = new Uint8Array([1]);
    const challenge: BootstrapChallenge = {
      id: "c",
      kind: "OWNER_BOOTSTRAP" as const,
      orgId: null,
      nominatorId: "creator",
      nomineeId: "creator-account",
      requestDigest: digest,
      challengeHash: new Uint8Array(32),
      issuedAt: 0,
      expiresAt: 300_000,
      consumedAt: null,
      committedDigest: null,
      committedResult: null,
    };
    const tx = {
      serializable: <T>(callback: () => Promise<T>) => callback(),
      lockChallenge: async () => ({
        challenge,
        nominator: { id: "creator", active: true, role: "MEMBER" as const },
        nominee: { id: "creator-account", active: true, role: "MEMBER" as const },
        ownerBootstrapSealed: false,
        securityAdminBootstrapSealed: false,
        activeSecurityAdmins: 0,
      }),
      insertCredentialAndMembership: async () => ({ orgId: "org" }),
      sealAndAudit: async (input: { result: { orgId: string }; committedDigest: Uint8Array }) => {
        challenge.consumedAt = 1;
        challenge.committedDigest = input.committedDigest;
        challenge.committedResult = input.result;
      },
    };
    const request = {
      tx,
      challengeId: "c",
      now: 1,
      acceptedDigest: digest,
      credential: {
        credentialIdHash: new Uint8Array(32),
        p256X: new Uint8Array(32),
        p256Y: new Uint8Array(32),
        coseAlg: -7 as const,
        declaredCustody: 3 as const,
      },
    };
    await expect(commitRemoteAdminBootstrap(request)).resolves.toEqual({ orgId: "org" });
    await expect(commitRemoteAdminBootstrap(request)).resolves.toEqual({ orgId: "org" });
  });
});
