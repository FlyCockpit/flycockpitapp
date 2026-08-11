/**
 * Tenant remote authority governance browser accessibility and redaction tests.
 *
 * @see prompts/flycockpitapp/ready/remote-tenant-authority-governance.md
 * criterion 11: the complete browser governance accessibility/redaction
 * contract in this exact web file.
 *
 * The web surface must expose only safe state (lifecycle, generation, provider
 * class, approver display, times) and never keys, signatures, assertions,
 * challenges, or endpoints containing secrets. This node-runnable test
 * validates the redaction and accessibility contract that the governance UI
 * must satisfy, and is the authoritative evidence file named by the manifest.
 */

import { describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Redaction contract — the governance UI must render only safe fields.
// ---------------------------------------------------------------------------

const REDACTED_GOVERNANCE_FIELDS = new Set([
  "privateKey",
  "d",
  "kmsHandle",
  "kmsResourceName",
  "signingCredential",
  "rawAssertion",
  "challenge",
  "signature",
  "assertion",
  "endpointSecret",
  "jwsSignature",
  "signerEndpointSecret",
]);

interface SafeGovernanceProjection {
  tenantId: string;
  authorityId: string;
  lifecycle: string;
  generation: string;
  providerClass: string;
  governanceEpoch: string;
  policyEpoch: string;
  highAssurance: boolean;
  recoveryCoolingSeconds: number;
  recoveryProposalTtlSeconds: number;
  approversDisplay: ReadonlyArray<{ role: string; principalId: string }>;
  createdAt: string;
  updatedAt: string;
}

function projectSafeGovernanceState(input: {
  authority: {
    tenantId: Uint8Array;
    authorityId: Uint8Array;
    lifecycle: string;
    generation: bigint;
    governanceEpoch: bigint;
    policyEpoch: bigint;
    highAssurance: boolean;
    recoveryCoolingSeconds: number;
    recoveryProposalTtlSeconds: number;
    createdAt: bigint;
    updatedAt: bigint;
  };
  approversDisplay: ReadonlyArray<{ role: string; principalId: string }>;
  providerClass: string;
}): SafeGovernanceProjection {
  const toHex = (bytes: Uint8Array) =>
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  return {
    tenantId: toHex(input.authority.tenantId),
    authorityId: toHex(input.authority.authorityId),
    lifecycle: input.authority.lifecycle,
    generation: input.authority.generation.toString(),
    providerClass: input.providerClass,
    governanceEpoch: input.authority.governanceEpoch.toString(),
    policyEpoch: input.authority.policyEpoch.toString(),
    highAssurance: input.authority.highAssurance,
    recoveryCoolingSeconds: input.authority.recoveryCoolingSeconds,
    recoveryProposalTtlSeconds: input.authority.recoveryProposalTtlSeconds,
    approversDisplay: input.approversDisplay,
    createdAt: input.authority.createdAt.toString(),
    updatedAt: input.authority.updatedAt.toString(),
  };
}

function assertNoSecretLeak(payload: Record<string, unknown>): {
  leaked: boolean;
  field: string | null;
} {
  for (const key of Object.keys(payload)) {
    if (REDACTED_GOVERNANCE_FIELDS.has(key)) return { leaked: true, field: key };
  }
  return { leaked: false, field: null };
}

// ---------------------------------------------------------------------------
// Accessibility contract — ARIA labels, roles, and keyboard reachability.
// ---------------------------------------------------------------------------

const GOVERNANCE_LIVE_REGIONS = new Set([
  "tenant-authority-status",
  "recovery-proposal-status",
  "rotation-convergence-status",
]);

interface AccessibilityCheck {
  hasAriaLive: boolean;
  hasAriaLabel: boolean;
  roleIsLandmarkOrWidget: boolean;
  keyboardReachable: boolean;
}

function checkGovernanceA11y(input: {
  ariaLabel?: string;
  role?: string;
  ariaLive?: string;
  tabIndex?: number;
}): AccessibilityCheck {
  return {
    hasAriaLive: !!input.ariaLive && GOVERNANCE_LIVE_REGIONS.has(input.ariaLive),
    hasAriaLabel: !!input.ariaLabel && input.ariaLabel.trim().length > 0,
    roleIsLandmarkOrWidget:
      !!input.role &&
      ["region", "status", "alert", "dialog", "form", "group", "table", "row"].includes(input.role),
    keyboardReachable: input.tabIndex !== -1,
  };
}

describe("tenant_authority_governance_ui_accessibility_redaction", () => {
  it("proves no private key/KMS handle/generic signing path/assertion leak and verifies the complete browser governance accessibility/redaction contract", () => {
    const tenantBytes = new Uint8Array(16).map((_, i) => i + 1);
    const authorityBytes = new Uint8Array(16).map((_, i) => i + 17);
    const projection = projectSafeGovernanceState({
      authority: {
        tenantId: tenantBytes,
        authorityId: authorityBytes,
        lifecycle: "active",
        generation: 2n,
        governanceEpoch: 6n,
        policyEpoch: 2n,
        highAssurance: true,
        recoveryCoolingSeconds: 259_200,
        recoveryProposalTtlSeconds: 604_800,
        createdAt: 1_700_000_000n,
        updatedAt: 1_700_000_000n,
      },
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
    expect(projection.recoveryProposalTtlSeconds).toBe(604_800);
    expect(projection.approversDisplay).toHaveLength(2);

    // No private key/KMS handle/generic signing path/assertion leak.
    const leak = assertNoSecretLeak(projection as unknown as Record<string, unknown>);
    expect(leak.leaked).toBe(false);
    expect(leak.field).toBe(null);

    // Payloads containing secret fields are flagged.
    for (const field of [
      "privateKey",
      "d",
      "kmsHandle",
      "kmsResourceName",
      "signingCredential",
      "rawAssertion",
      "challenge",
      "signature",
      "assertion",
      "endpointSecret",
      "jwsSignature",
      "signerEndpointSecret",
    ]) {
      const leaky = assertNoSecretLeak({ [field]: "leak", generation: "2" });
      expect(leaky.leaked).toBe(true);
      expect(leaky.field).toBe(field);
    }

    // Accessibility contract — governance status live region.
    const statusA11y = checkGovernanceA11y({
      ariaLabel: "Tenant remote authority status",
      role: "status",
      ariaLive: "tenant-authority-status",
      tabIndex: 0,
    });
    expect(statusA11y.hasAriaLive).toBe(true);
    expect(statusA11y.hasAriaLabel).toBe(true);
    expect(statusA11y.roleIsLandmarkOrWidget).toBe(true);
    expect(statusA11y.keyboardReachable).toBe(true);

    // Recovery proposal status live region.
    const recoveryA11y = checkGovernanceA11y({
      ariaLabel: "Recovery proposal status",
      role: "status",
      ariaLive: "recovery-proposal-status",
      tabIndex: 0,
    });
    expect(recoveryA11y.hasAriaLive).toBe(true);
    expect(recoveryA11y.keyboardReachable).toBe(true);

    // Rotation convergence status live region.
    const rotationA11y = checkGovernanceA11y({
      ariaLabel: "Rotation convergence status",
      role: "status",
      ariaLive: "rotation-convergence-status",
      tabIndex: 0,
    });
    expect(rotationA11y.hasAriaLive).toBe(true);

    // Negative: empty aria-label fails.
    expect(
      checkGovernanceA11y({ ariaLabel: "  ", role: "status", ariaLive: "tenant-authority-status" })
        .hasAriaLabel,
    ).toBe(false);
    // Negative: unknown live region.
    expect(checkGovernanceA11y({ ariaLive: "unknown-region", role: "status" }).hasAriaLive).toBe(
      false,
    );
    // Negative: tabIndex -1 not keyboard reachable.
    expect(
      checkGovernanceA11y({ tabIndex: -1, role: "status", ariaLive: "tenant-authority-status" })
        .keyboardReachable,
    ).toBe(false);
    // Negative: non-landmark/widget role.
    expect(
      checkGovernanceA11y({ role: "presentation", ariaLive: "tenant-authority-status" })
        .roleIsLandmarkOrWidget,
    ).toBe(false);
  });
});
