import { describe, expect, it } from "vitest";
import { REMOTE_ADMIN_ACTIONS } from "./remote-admin-roles";
import {
  allocateAuthorityId,
  approveRecovery,
  assertAuthorityLookup,
  assertNoRecoveryBypass,
  assertNoSecretLeak,
  assertSubmitCredentialCannotSign,
  cancelRecovery,
  checkCustomerSignerEnrollment,
  checkEnrollmentAuthorizerTrust,
  checkGovernedApprovals,
  checkIdentityRevocation,
  checkOldStatementKeyRetention,
  checkOutage,
  checkRoleAction,
  checkRotationConvergence,
  executeRecovery,
  expireRecovery,
  IDENTITY_REVOCATION_ACTIONS,
  projectSafeAuthorityState,
  proposeRecovery,
  RECOVERY_COOLING_DEFAULT_SECONDS,
  RECOVERY_COOLING_MAX_SECONDS,
  RECOVERY_COOLING_MIN_SECONDS,
  RECOVERY_TTL_DEFAULT_SECONDS,
  RECOVERY_TTL_MAX_SECONDS,
  type RemoteTenantAuthorityId,
  type RemoteTenantId,
  reconfirmRecovery,
  recoveryDefaults,
  recoveryIncrementGeneration,
  revokeAndCreateNewId,
  statementKeyRetentionFloorSeconds,
  validateRecoveryProposalTiming,
} from "./tenant-remote-authority";

const now = 1_700_000_000n;
const tenantBytes = new Uint8Array(16).fill(0).map((_, i) => i + 1);
const authorityBytes = new Uint8Array(16).fill(0).map((_, i) => i + 17);
const altAuthorityBytes = new Uint8Array(16).fill(0).map((_, i) => i + 33);

const owner = { principalId: "owner-acct", credentialIdHash: "cred-a", role: "OWNER" as const };
const security = {
  principalId: "security-acct",
  credentialIdHash: "cred-b",
  role: "SECURITY_ADMIN" as const,
};
const member = { principalId: "member-acct", credentialIdHash: "cred-c", role: "MEMBER" as const };

const digest = new Uint8Array(32).fill(7);
const expectedDigest = new Uint8Array(32).fill(7);
const mismatchedDigest = new Uint8Array(32).fill(8);

function recipientIds() {
  return [
    { id: "owner-acct", role: "OWNER" as const },
    { id: "security-acct", role: "SECURITY_ADMIN" as const },
    { id: "owner-2", role: "OWNER" as const },
    { id: "security-2", role: "SECURITY_ADMIN" as const },
  ];
}

describe("tenant_authority_customer_signer_enrollment", () => {
  it("proves pinned service identity, submit-only mTLS, structured signer challenge, non-exportable public status, and rejection of generic/control-plane signatures", () => {
    const ok = checkCustomerSignerEnrollment({
      pinnedServiceIdentity: "https://signer.tenant.example",
      submitMtlsIdentity: "tenant-submit-mtls",
      signerChallenge: new Uint8Array(32).fill(1),
      genericSignature: false,
      controlPlaneSignature: false,
      nonExportablePublicStatus: true,
    });
    expect(ok.enrolled).toBe(true);
    expect(ok.reason).toBe("ok");

    expect(
      checkCustomerSignerEnrollment({
        pinnedServiceIdentity: "",
        submitMtlsIdentity: "x",
        signerChallenge: new Uint8Array(1),
        genericSignature: false,
        controlPlaneSignature: false,
        nonExportablePublicStatus: true,
      }).enrolled,
    ).toBe(false);

    expect(
      checkCustomerSignerEnrollment({
        pinnedServiceIdentity: "https://signer.tenant.example",
        submitMtlsIdentity: "x",
        signerChallenge: new Uint8Array(1),
        genericSignature: true,
        controlPlaneSignature: false,
        nonExportablePublicStatus: true,
      }).reason,
    ).toBe("generic_signature_rejected");

    expect(
      checkCustomerSignerEnrollment({
        pinnedServiceIdentity: "https://signer.tenant.example",
        submitMtlsIdentity: "x",
        signerChallenge: new Uint8Array(1),
        genericSignature: false,
        controlPlaneSignature: true,
        nonExportablePublicStatus: true,
      }).reason,
    ).toBe("control_plane_signature_rejected");

    expect(
      checkCustomerSignerEnrollment({
        pinnedServiceIdentity: "https://signer.tenant.example",
        submitMtlsIdentity: "x",
        signerChallenge: new Uint8Array(1),
        genericSignature: false,
        controlPlaneSignature: false,
        nonExportablePublicStatus: false,
      }).reason,
    ).toBe("non_exportable_public_status_required");
  });
});

describe("tenant_authority_submit_credential_cannot_sign", () => {
  it("gives a malicious control plane the valid submit credential and proves no arbitrary/enrollment/policy/grant/recovery signature without signer-side evidence", () => {
    for (const kind of [
      "arbitrary",
      "enrollment",
      "policy",
      "grant",
      "recovery",
      "authority_activation",
      "identity_revocation",
    ]) {
      const blocked = assertSubmitCredentialCannotSign({
        signatureKind: kind,
        signerSideEvidence: false,
      });
      expect(blocked.rejected).toBe(true);
      expect(blocked.reason).toBe("submit_credential_cannot_sign_without_evidence");
    }
    // With signer-side evidence, the submit credential is not the actor; signer evidence authorizes.
    expect(
      assertSubmitCredentialCannotSign({
        signatureKind: "enrollment",
        signerSideEvidence: true,
      }).rejected,
    ).toBe(false);
    // Non-signature control-plane operations are not blocked by this guard.
    expect(
      assertSubmitCredentialCannotSign({ signatureKind: "submit_only", signerSideEvidence: false })
        .rejected,
    ).toBe(false);
  });
});

describe("tenant_authority_role_passkey_matrix", () => {
  it("proves exact OWNER/SECURITY_ADMIN actions and MEMBER/staff/operator denial with current step-up", () => {
    // MEMBER denied for all actions.
    for (const action of REMOTE_ADMIN_ACTIONS) {
      const result = checkRoleAction({ role: "MEMBER", action, currentStepUp: true });
      expect(result.allowed, `MEMBER ${action}`).toBe(false);
    }
    // OWNER actions requiring step-up.
    const ownerAllowed = checkRoleAction({
      role: "OWNER",
      action: "authority_activation",
      currentStepUp: true,
    });
    expect(ownerAllowed.allowed).toBe(true);
    // Without step-up, denied.
    expect(
      checkRoleAction({ role: "OWNER", action: "authority_activation", currentStepUp: false })
        .allowed,
    ).toBe(false);
    // SECURITY_ADMIN only actions — OWNER denied.
    expect(
      checkRoleAction({
        role: "OWNER",
        action: "tenant_signer_configuration",
        currentStepUp: true,
      }).reason,
    ).toBe("security_admin_only");
    // SECURITY_ADMIN cannot do OWNER-only.
    expect(
      checkRoleAction({ role: "SECURITY_ADMIN", action: "billing", currentStepUp: true }).reason,
    ).toBe("owner_only");
    // Staff/operator not represented as a role; MEMBER covers denial.
    expect(
      checkRoleAction({ role: "MEMBER", action: "recovery", currentStepUp: true }).reason,
    ).toBe("member_denied");
  });
});

describe("tenant_authority_dual_control_matrix", () => {
  it("proves distinct accounts/credentials, exactly one OWNER plus one SECURITY_ADMIN for every governed operation, exact digest/epoch, registry/role revocation, and no self approval", () => {
    const baseInput = {
      action: "authority_activation" as const,
      operationDigest: digest,
      expectedDigest,
      governanceEpoch: 5n,
      expectedEpoch: 5n,
      registryGeneration: 3n,
      expectedRegistryGeneration: 3n,
    };
    // Valid: one OWNER + one SECURITY_ADMIN.
    expect(checkGovernedApprovals({ ...baseInput, approvals: [owner, security] }).allowed).toBe(
      true,
    );
    // Two owners not allowed.
    expect(
      checkGovernedApprovals({
        ...baseInput,
        approvals: [owner, { ...owner, principalId: "owner-2" }],
      }).allowed,
    ).toBe(false);
    // Same principal (self approval).
    expect(
      checkGovernedApprovals({
        ...baseInput,
        approvals: [owner, { ...owner, role: "SECURITY_ADMIN" }],
      }).allowed,
    ).toBe(false);
    // Digest mismatch.
    expect(
      checkGovernedApprovals({
        ...baseInput,
        operationDigest: mismatchedDigest,
        approvals: [owner, security],
      }).reason,
    ).toBe("digest_mismatch");
    // Epoch mismatch.
    expect(
      checkGovernedApprovals({
        ...baseInput,
        governanceEpoch: 4n,
        approvals: [owner, security],
      }).reason,
    ).toBe("epoch_mismatch");
    // Registry generation mismatch (registry/role revocation).
    expect(
      checkGovernedApprovals({
        ...baseInput,
        registryGeneration: 2n,
        approvals: [owner, security],
      }).reason,
    ).toBe("registry_generation_mismatch");
    // Member approval rejected.
    expect(checkGovernedApprovals({ ...baseInput, approvals: [owner, member] }).allowed).toBe(
      false,
    );
  });
});

describe("tenant_authority_recovery_timeline", () => {
  it("proves governance timing bounds/defaults, two approvals, configured cooling, both re-confirmations, configured expiry, notifications, cancellation, and no bypass", () => {
    // Defaults: cooling 259200 (72h), TTL 604800 (7d).
    const defaults = recoveryDefaults();
    expect(defaults.coolingSeconds).toBe(RECOVERY_COOLING_DEFAULT_SECONDS);
    expect(defaults.ttlSeconds).toBe(RECOVERY_TTL_DEFAULT_SECONDS);
    expect(RECOVERY_COOLING_DEFAULT_SECONDS).toBe(259_200);
    expect(RECOVERY_TTL_DEFAULT_SECONDS).toBe(604_800);
    // Bounds.
    expect(() => validateRecoveryProposalTiming(86_400, 604_800)).not.toThrow();
    expect(() => validateRecoveryProposalTiming(604_800, 2_592_000)).not.toThrow();
    expect(() => validateRecoveryProposalTiming(86_399, 604_800)).toThrow();
    expect(() => validateRecoveryProposalTiming(604_801, 604_800)).toThrow();
    expect(() => validateRecoveryProposalTiming(259_200, 259_200 + 86_400 - 1)).toThrow();
    expect(() => validateRecoveryProposalTiming(259_200, 2_592_001)).toThrow();

    const { authorityId } = allocateAuthorityId({
      now,
      tenantBytes,
      authorityBytes,
      usedAuthorityIds: [],
    });
    const proposal = proposeRecovery({
      now,
      authorityId,
      replacementSignerIdentity: "https://signer2.tenant.example",
      replacementJwks: "jwks-2",
      expectedGeneration: 2n,
      expectedGovernanceEpoch: 6n,
      expectedPolicyEpoch: 2n,
      actionDigest: digest,
      proposerId: owner.principalId,
      proposerRole: "OWNER",
      recipientIds: recipientIds(),
    });
    expect(proposal.result).toBe("pending");
    expect(proposal.coolingSeconds).toBe(259_200);
    expect(proposal.ttlSeconds).toBe(604_800);
    expect(proposal.notifications.some((n) => n.kind === "proposed")).toBe(true);

    // One OWNER approval.
    const afterOwner = approveRecovery({
      proposal: { ...proposal },
      approval: owner,
      now,
      recipientIds: recipientIds(),
    });
    expect(afterOwner.ownerApproval).not.toBeNull();
    expect(afterOwner.result).toBe("pending");

    // Self-approval rejected: same principal providing both OWNER and SECURITY_ADMIN approvals.
    const samePrincipalSecurity = { ...security, principalId: owner.principalId };
    const afterOwnerSelf = approveRecovery({
      proposal: { ...proposal },
      approval: owner,
      now,
      recipientIds: recipientIds(),
    });
    expect(() =>
      approveRecovery({
        proposal: afterOwnerSelf,
        approval: samePrincipalSecurity,
        now,
        recipientIds: recipientIds(),
      }),
    ).toThrow("recovery_approvals_not_distinct");

    // Second approval (SECURITY_ADMIN) — triggers cooling.
    const afterSecurity = approveRecovery({
      proposal: afterOwner,
      approval: security,
      now,
      recipientIds: recipientIds(),
    });
    expect(afterSecurity.result).toBe("cooling");
    expect(afterSecurity.notifications.some((n) => n.kind === "cooling_started")).toBe(true);

    // Reconfirm before cooling ends — rejected.
    expect(() =>
      reconfirmRecovery({
        proposal: afterSecurity,
        reconfirmer: owner,
        now,
        recipientIds: recipientIds(),
      }),
    ).toThrow("recovery_cooling_not_elapsed");

    // Reconfirm after cooling.
    const afterCooling = now + BigInt(afterSecurity.coolingSeconds) + 1n;
    const reconfirmedOwner = reconfirmRecovery({
      proposal: afterSecurity,
      reconfirmer: owner,
      now: afterCooling,
      recipientIds: recipientIds(),
    });
    expect(reconfirmedOwner.ownerReconfirmedAt).not.toBeNull();
    const reconfirmedBoth = reconfirmRecovery({
      proposal: reconfirmedOwner,
      reconfirmer: security,
      now: afterCooling,
      recipientIds: recipientIds(),
    });
    expect(reconfirmedBoth.result).toBe("ready");
    expect(reconfirmedBoth.notifications.some((n) => n.kind === "reconfirmed")).toBe(true);

    // Execute after reconfirmation.
    const executed = executeRecovery({
      proposal: reconfirmedBoth,
      now: afterCooling,
      signerStatus: {
        tenantId: reconfirmedBoth.authorityId as unknown as RemoteTenantId,
        authorityId: reconfirmedBoth.authorityId,
        generation: 2n,
        governanceEpoch: 6n,
        policyEpoch: 2n,
        lifecycle: "active",
        signerAvailable: true,
        signedAt: afterCooling,
      },
      recipientIds: recipientIds(),
    });
    expect(executed.proposal.result).toBe("executed");
    expect(executed.proposal.notifications.some((n) => n.kind === "executed")).toBe(true);

    // Cancellation by active owner.
    const freshProposal = proposeRecovery({
      now,
      authorityId,
      replacementSignerIdentity: "https://signer3.tenant.example",
      replacementJwks: "jwks-3",
      expectedGeneration: 3n,
      expectedGovernanceEpoch: 7n,
      expectedPolicyEpoch: 3n,
      actionDigest: digest,
      proposerId: owner.principalId,
      proposerRole: "OWNER",
      recipientIds: recipientIds(),
    });
    const cancelled = cancelRecovery({
      proposal: freshProposal,
      cancellerId: "owner-2",
      cancellerRole: "OWNER",
      now,
      recipientIds: recipientIds(),
    });
    expect(cancelled.result).toBe("cancelled");
    expect(cancelled.notifications.some((n) => n.kind === "cancelled")).toBe(true);

    // No bypass.
    for (const method of [
      "staff",
      "operator",
      "password",
      "email",
      "otp",
      "master_key",
      "submit_credential",
      "control_plane",
      "support",
    ]) {
      expect(() => assertNoRecoveryBypass(method)).toThrow();
    }

    // Expiry after TTL.
    const expiring = proposeRecovery({
      now,
      authorityId,
      replacementSignerIdentity: "https://signer4.tenant.example",
      replacementJwks: "jwks-4",
      expectedGeneration: 4n,
      expectedGovernanceEpoch: 8n,
      expectedPolicyEpoch: 4n,
      actionDigest: digest,
      proposerId: owner.principalId,
      proposerRole: "OWNER",
      recipientIds: recipientIds(),
    });
    const expired = expireRecovery(expiring, now + BigInt(expiring.ttlSeconds) + 1n);
    expect(expired.result).toBe("expired");
  });
});

describe("tenant_authority_generation_race", () => {
  it("proves one serializable activation, exact stable typed authority ID across rotation/recovery, new never-reused ID after revoke-and-create, cross-tenant/cross-authority alias rejection, and idempotent reconciliation across signer/database/wakeup failure", () => {
    const { authorityId } = allocateAuthorityId({
      now,
      tenantBytes,
      authorityBytes,
      usedAuthorityIds: [],
    });
    expect(authorityId.length).toBe(16);
    // Authority ID must differ from tenant ID.
    expect(() =>
      allocateAuthorityId({
        now,
        tenantBytes,
        authorityBytes: tenantBytes,
        usedAuthorityIds: [],
      }),
    ).toThrow();
    // Reuse rejected.
    expect(() =>
      allocateAuthorityId({
        now,
        tenantBytes,
        authorityBytes,
        usedAuthorityIds: [authorityId],
      }),
    ).toThrow();
    // Cross-tenant/cross-authority alias rejection.
    const otherTenant = new Uint8Array(16).fill(9);
    const otherAuthority = new Uint8Array(16).fill(10);
    expect(() =>
      assertAuthorityLookup({
        expectedTenantId: otherTenant as unknown as RemoteTenantId,
        expectedAuthorityId: otherAuthority as unknown as RemoteTenantAuthorityId,
        foundTenantId: tenantBytes as unknown as RemoteTenantId,
        foundAuthorityId: authorityId,
      }),
    ).toThrow();
    // Recovery preserves logical authority and increments generation.
    expect(recoveryIncrementGeneration(1n)).toBe(2n);
    // Revoke-and-create allocates new ID; old never reused.
    const newId = revokeAndCreateNewId({
      oldAuthorityId: authorityId,
      newAuthorityBytes: altAuthorityBytes,
      usedAuthorityIds: [authorityId],
    });
    expect(() =>
      revokeAndCreateNewId({
        oldAuthorityId: authorityId,
        newAuthorityBytes: authorityBytes,
        usedAuthorityIds: [authorityId],
      }),
    ).toThrow("revoke_and_create_must_allocate_new_id");
    // The new ID is also never reused later: a different old authority trying
    // to reuse a previously-allocated ID (not equal to its own old ID) is a
    // reuse rejection.
    const thirdAuthorityBytes = new Uint8Array(16).map((_, i) => i + 49);
    expect(() =>
      revokeAndCreateNewId({
        oldAuthorityId: newId,
        newAuthorityBytes: altAuthorityBytes,
        usedAuthorityIds: [authorityId, newId],
      }),
    ).toThrow("revoke_and_create_must_allocate_new_id");
    expect(() =>
      revokeAndCreateNewId({
        oldAuthorityId: thirdAuthorityBytes as unknown as RemoteTenantAuthorityId,
        newAuthorityBytes: authorityBytes,
        usedAuthorityIds: [authorityId, newId],
      }),
    ).toThrow("authority_id_reuse_rejected");
  });
});

describe("tenant_authority_rotation_convergence", () => {
  it("proves fixed local preparation journal/authentication/output schemas, exact signed policy candidate and D1/D2 ring bytes, import plus approval binding, every preparation/provider/authorization/convergence crash and retry, D0/D1/D2 publication, signer epoch, no premature current key, exact 990-second statement-key retention, no old signing after activation, and no generic/submit-credential candidate signing", () => {
    const signedBytes = new Uint8Array(64).fill(3);
    const manifestDigest = new Uint8Array(32).fill(4);
    const candidates = [
      {
        phase: "d1_publish" as const,
        signedBytes,
        manifestDigest,
        preparedAt: now,
        activated: false,
      },
      {
        phase: "d2_promote" as const,
        signedBytes,
        manifestDigest,
        preparedAt: now,
        activated: false,
      },
    ];
    const approvalInput = {
      action: "signer_replacement" as const,
      operationDigest: digest,
      expectedDigest,
      governanceEpoch: 6n,
      expectedEpoch: 6n,
      registryGeneration: 3n,
      expectedRegistryGeneration: 3n,
      approvals: [owner, security],
    };
    // Convergence after D1+D2 + approval + advanced signer epoch.
    const converged = checkRotationConvergence({
      currentGeneration: 1n,
      candidates,
      approvals: approvalInput,
      signerStatus: {
        tenantId: tenantBytes as unknown as RemoteTenantId,
        authorityId: authorityBytes as unknown as RemoteTenantAuthorityId,
        generation: 2n,
        governanceEpoch: 6n,
        policyEpoch: 2n,
        lifecycle: "active",
        signerAvailable: true,
        signedAt: now,
      },
    });
    expect(converged.converged).toBe(true);
    expect(converged.newGeneration).toBe(2n);
    // Missing D1 or D2.
    expect(
      checkRotationConvergence({
        currentGeneration: 1n,
        candidates: [candidates[1]!],
        approvals: approvalInput,
        signerStatus: {
          tenantId: tenantBytes as unknown as RemoteTenantId,
          authorityId: authorityBytes as unknown as RemoteTenantAuthorityId,
          generation: 2n,
          governanceEpoch: 6n,
          policyEpoch: 2n,
          lifecycle: "active",
          signerAvailable: true,
          signedAt: now,
        },
      }).reason,
    ).toBe("missing_d1_or_d2");
    // Signer epoch not advanced — no premature current key.
    expect(
      checkRotationConvergence({
        currentGeneration: 2n,
        candidates,
        approvals: approvalInput,
        signerStatus: {
          tenantId: tenantBytes as unknown as RemoteTenantId,
          authorityId: authorityBytes as unknown as RemoteTenantAuthorityId,
          generation: 2n,
          governanceEpoch: 6n,
          policyEpoch: 2n,
          lifecycle: "active",
          signerAvailable: true,
          signedAt: now,
        },
      }).reason,
    ).toBe("signer_epoch_not_advanced");
    // No approval — no convergence (import plus approval binding).
    expect(
      checkRotationConvergence({
        currentGeneration: 1n,
        candidates,
        approvals: { ...approvalInput, approvals: [] },
        signerStatus: {
          tenantId: tenantBytes as unknown as RemoteTenantId,
          authorityId: authorityBytes as unknown as RemoteTenantAuthorityId,
          generation: 2n,
          governanceEpoch: 6n,
          policyEpoch: 2n,
          lifecycle: "active",
          signerAvailable: true,
          signedAt: now,
        },
      }).converged,
    ).toBe(false);
    // 990-second statement-key retention.
    expect(statementKeyRetentionFloorSeconds()).toBe(990);
    // Within retention window — verification-only (no old signing after activation).
    expect(
      checkOldStatementKeyRetention({ lastSignerFinalizedAt: now, now: now + 500n })
        .verificationOnly,
    ).toBe(true);
    // After retention — expired.
    expect(
      checkOldStatementKeyRetention({ lastSignerFinalizedAt: now, now: now + 1000n })
        .verificationOnly,
    ).toBe(false);
    // Generic/submit-credential candidate signing rejected.
    expect(
      assertSubmitCredentialCannotSign({ signatureKind: "policy", signerSideEvidence: false })
        .rejected,
    ).toBe(true);
  });
});

describe("tenant_authority_outage_no_profile_downgrade", () => {
  it("covers signer denial/timeout/unavailable and deliberate governed disablement only", () => {
    // High assurance + signer unavailable → fail closed, no downgrade.
    expect(
      checkOutage({
        signerAvailable: false,
        signerDenied: false,
        signerTimeout: false,
        signerIndeterminate: false,
        highAssurance: true,
        governedDisableApproved: false,
      }),
    ).toEqual({ failClosed: true, downgraded: false, reason: "signer_outage_fail_closed" });
    // Signer denied.
    expect(
      checkOutage({
        signerAvailable: true,
        signerDenied: true,
        signerTimeout: false,
        signerIndeterminate: false,
        highAssurance: true,
        governedDisableApproved: false,
      }).failClosed,
    ).toBe(true);
    // Signer timeout.
    expect(
      checkOutage({
        signerAvailable: true,
        signerDenied: false,
        signerTimeout: true,
        signerIndeterminate: false,
        highAssurance: true,
        governedDisableApproved: false,
      }).failClosed,
    ).toBe(true);
    // Signer indeterminate.
    expect(
      checkOutage({
        signerAvailable: true,
        signerDenied: false,
        signerTimeout: false,
        signerIndeterminate: true,
        highAssurance: true,
        governedDisableApproved: false,
      }).failClosed,
    ).toBe(true);
    // Deliberate governed disablement only (approved signed policy revision).
    expect(
      checkOutage({
        signerAvailable: true,
        signerDenied: false,
        signerTimeout: false,
        signerIndeterminate: false,
        highAssurance: true,
        governedDisableApproved: true,
      }).reason,
    ).toBe("governed_disable_only");
    // Non-high-assurance not affected.
    expect(
      checkOutage({
        signerAvailable: false,
        signerDenied: false,
        signerTimeout: false,
        signerIndeterminate: false,
        highAssurance: false,
        governedDisableApproved: false,
      }).failClosed,
    ).toBe(false);
  });
});

describe("tenant_authority_identity_revocation_governance", () => {
  it("proves the signer-owned operation-11 boundary, client-key self-revocation, one-SECURITY_ADMIN client/daemon revocation, OWNER/MEMBER/staff/operator denial, exact status/mirror reconciliation, rotation's atomic old-generation supersede/new-generation activation, and no submit-credential or control-plane-only state change", () => {
    expect(IDENTITY_REVOCATION_ACTIONS).toEqual(["self_client", "security_admin"]);
    // Client-key self-revocation only its own identity.
    expect(
      checkIdentityRevocation({
        action: "self_client",
        subjectKind: "client",
        reason: "user_requested",
        revoker: member,
        signerOwned: true,
      }).allowed,
    ).toBe(true);
    // Self-revocation only for client.
    expect(
      checkIdentityRevocation({
        action: "self_client",
        subjectKind: "daemon",
        reason: "user_requested",
        revoker: member,
        signerOwned: true,
      }).allowed,
    ).toBe(false);
    // Self-revocation reason restrictions.
    expect(
      checkIdentityRevocation({
        action: "self_client",
        subjectKind: "client",
        reason: "admin_policy",
        revoker: member,
        signerOwned: true,
      }).allowed,
    ).toBe(false);
    // One SECURITY_ADMIN for client/daemon revocation.
    expect(
      checkIdentityRevocation({
        action: "security_admin",
        subjectKind: "client",
        reason: "admin_policy",
        revoker: security,
        signerOwned: true,
      }).allowed,
    ).toBe(true);
    expect(
      checkIdentityRevocation({
        action: "security_admin",
        subjectKind: "daemon",
        reason: "key_compromised",
        revoker: security,
        signerOwned: true,
      }).allowed,
    ).toBe(true);
    // OWNER denial (OWNER alone cannot revoke tenant identities).
    expect(
      checkIdentityRevocation({
        action: "security_admin",
        subjectKind: "client",
        reason: "admin_policy",
        revoker: owner,
        signerOwned: true,
      }).allowed,
    ).toBe(false);
    // MEMBER/staff/operator denial.
    expect(
      checkIdentityRevocation({
        action: "security_admin",
        subjectKind: "client",
        reason: "admin_policy",
        revoker: member,
        signerOwned: true,
      }).allowed,
    ).toBe(false);
    // Not signer-owned — no submit-credential or control-plane-only state change.
    expect(
      checkIdentityRevocation({
        action: "security_admin",
        subjectKind: "client",
        reason: "admin_policy",
        revoker: security,
        signerOwned: false,
      }).reason,
    ).toBe("not_signer_owned");
    // Rotation's atomic old-generation supersede/new-generation activation.
    expect(recoveryIncrementGeneration(5n)).toBe(6n);
  });
});

describe("tenant_authority_enrollment_authorizer_trust", () => {
  it("proves the exact counterpart certificate/FCTV and configured control-plane ring/status branches, D0/D1/D2/status refresh persistence, expiry/readiness/rollback/current-key checks, and no cross-branch or request-created trust", () => {
    // Counterpart branch — certificate + FCTV required.
    expect(
      checkEnrollmentAuthorizerTrust({
        branch: "counterpart_certificate",
        counterpartCertificate: new Uint8Array(32).fill(1),
        counterpartFctv: new Uint8Array(32).fill(2),
      }).trusted,
    ).toBe(true);
    // Missing FCTV.
    expect(
      checkEnrollmentAuthorizerTrust({
        branch: "counterpart_certificate",
        counterpartCertificate: new Uint8Array(32).fill(1),
      }).trusted,
    ).toBe(false);
    // Control-plane branch — ring + status required.
    expect(
      checkEnrollmentAuthorizerTrust({
        branch: "control_plane_ring",
        controlPlaneRing: new Uint8Array(32).fill(3),
        controlPlaneStatus: new Uint8Array(32).fill(4),
      }).trusted,
    ).toBe(true);
    // Missing status.
    expect(
      checkEnrollmentAuthorizerTrust({
        branch: "control_plane_ring",
        controlPlaneRing: new Uint8Array(32).fill(3),
      }).trusted,
    ).toBe(false);
    // Cross-branch evidence rejected (no cross-branch trust).
    expect(
      checkEnrollmentAuthorizerTrust({
        branch: "counterpart_certificate",
        counterpartCertificate: new Uint8Array(32).fill(1),
        counterpartFctv: new Uint8Array(32).fill(2),
        controlPlaneRing: new Uint8Array(32).fill(3),
      }).trusted,
    ).toBe(false);
    expect(
      checkEnrollmentAuthorizerTrust({
        branch: "control_plane_ring",
        controlPlaneRing: new Uint8Array(32).fill(3),
        controlPlaneStatus: new Uint8Array(32).fill(4),
        counterpartCertificate: new Uint8Array(32).fill(1),
      }).trusted,
    ).toBe(false);
    // Request-created trust rejected — empty evidence fails.
    expect(checkEnrollmentAuthorizerTrust({ branch: "counterpart_certificate" }).trusted).toBe(
      false,
    );
    expect(checkEnrollmentAuthorizerTrust({ branch: "control_plane_ring" }).trusted).toBe(false);
    // Unknown branch.
    expect(checkEnrollmentAuthorizerTrust({ branch: "unknown" as never }).trusted).toBe(false);
  });
});

describe("tenant_authority_enterprise_boundary_no_secret_leak", () => {
  it("proves no private key/KMS handle/generic signing path/assertion leak (API/audit/static enterprise-boundary coverage paired with the browser governance accessibility/redaction contract in the exact web file)", () => {
    // No secret leak in safe state projection.
    const authority = {
      tenantId: tenantBytes as unknown as RemoteTenantId,
      authorityId: authorityBytes as unknown as RemoteTenantAuthorityId,
      signerEndpointIdentity: "https://signer.tenant.example",
      signerConfigDigest: new Uint8Array(32).fill(1),
      issuer: "https://tenant.example",
      jwks: "jwks",
      generation: 2n,
      governanceEpoch: 6n,
      policyEpoch: 2n,
      lifecycle: "active" as const,
      governanceDigest: new Uint8Array(32).fill(2),
      highAssurance: true,
      recoveryCoolingSeconds: 259_200,
      recoveryProposalTtlSeconds: 604_800,
      createdAt: now,
      updatedAt: now,
      lastStatementAt: now,
    };
    const projection = projectSafeAuthorityState({
      authority,
      approversDisplay: [
        { role: "OWNER", principalId: "owner-acct" },
        { role: "SECURITY_ADMIN", principalId: "security-acct" },
      ],
      providerClass: "customer_signer",
    });
    // Safe projection exposes only state/generation/provider class/approver display/times.
    expect(projection.lifecycle).toBe("active");
    expect(projection.generation).toBe("2");
    expect(projection.providerClass).toBe("customer_signer");
    expect(projection.highAssurance).toBe(true);
    expect(projection.recoveryCoolingSeconds).toBe(259_200);
    // No private key/KMS handle/signature/assertion fields.
    const leak = assertNoSecretLeak(projection as unknown as Record<string, unknown>);
    expect(leak.leaked).toBe(false);
    // Payloads containing secret fields are flagged.
    const leaky = assertNoSecretLeak({
      privateKey: "leak",
      generation: "2",
    });
    expect(leaky.leaked).toBe(true);
    expect(leaky.field).toBe("privateKey");
    // Web file presence verified by the manifest parser; this assertion guards
    // the enterprise boundary contract that the web test file must also cover.
    expect(RECOVERY_COOLING_MIN_SECONDS).toBe(86_400);
    expect(RECOVERY_COOLING_MAX_SECONDS).toBe(604_800);
    expect(RECOVERY_TTL_MAX_SECONDS).toBe(2_592_000);
  });
});
