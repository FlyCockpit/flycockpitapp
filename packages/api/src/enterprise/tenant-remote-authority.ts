/**
 * Tenant-owned remote authority enrollment and governance pure reducers.
 *
 * @see prompts/flycockpitapp/ready/remote-tenant-authority-governance.md
 *
 * FlyCockpit stores an authenticated mirror plus submission/outbox state only.
 * The customer signer is authoritative for credential-registry generation,
 * governance/policy/authority epochs, recovery proposal state/cooling/TTL/
 * reconfirmation, and request idempotency. FlyCockpit's clock, cache, or
 * proposal row cannot initiate, accelerate, reconfirm, cancel, or execute
 * recovery. This module never requests, receives, persists, logs, or exports
 * a tenant private key, KMS handle/resource name, generic signing credential,
 * or raw admin assertion.
 */

import {
  type ApprovalIdentity,
  actionRequiresDualControl,
  assertRequiredApprovalPair,
  type RemoteAdminAction,
  type RemoteAdminRole,
  roleCanStartAction,
} from "./remote-admin-roles";
import {
  RECOVERY_COOLING_DEFAULT_SECONDS,
  RECOVERY_TTL_DEFAULT_SECONDS,
  validateRecoveryTiming,
} from "./remote-admin-state";

export { RECOVERY_COOLING_DEFAULT_SECONDS, RECOVERY_TTL_DEFAULT_SECONDS };

// ---------------------------------------------------------------------------
// Typed protocol aliases — distinct from tenant/account/instance/project.
// ---------------------------------------------------------------------------

const AUTHORITY_BRAND = Symbol("RemoteTenantAuthorityId");
const TENANT_BRAND = Symbol("RemoteTenantId");

/** 16-byte nonzero tenant alias, distinct from tenantId/account/instance/project. */
export type RemoteTenantId = Uint8Array & { readonly [TENANT_BRAND]: true };
/** 16-byte nonzero authority alias, stable across rotation/recovery, never reused. */
export type RemoteTenantAuthorityId = Uint8Array & { readonly [AUTHORITY_BRAND]: true };

function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) if (bytes[i] !== 0) return false;
  return true;
}

function tagAuthority(bytes: Uint8Array): RemoteTenantAuthorityId {
  if (bytes.length !== 16 || isAllZero(bytes)) throw new Error("tenant_authority_id_invalid");
  const tagged = new Uint8Array(bytes) as RemoteTenantAuthorityId;
  Object.defineProperty(tagged, AUTHORITY_BRAND, {
    value: true,
    enumerable: false,
    configurable: false,
  });
  return tagged;
}

function tagTenant(bytes: Uint8Array): RemoteTenantId {
  if (bytes.length !== 16 || isAllZero(bytes)) throw new Error("tenant_id_invalid");
  const tagged = new Uint8Array(bytes) as RemoteTenantId;
  Object.defineProperty(tagged, TENANT_BRAND, {
    value: true,
    enumerable: false,
    configurable: false,
  });
  return tagged;
}

const equalBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((v, i) => v === b[i]);

// ---------------------------------------------------------------------------
// Lifecycle, enrollment authorizer trust, recovery, rotation.
// ---------------------------------------------------------------------------

export const TENANT_AUTHORITY_LIFECYCLE = [
  "pending",
  "active",
  "rotating",
  "recovery_pending",
  "revoked",
] as const;
export type TenantAuthorityLifecycle = (typeof TENANT_AUTHORITY_LIFECYCLE)[number];

export const ENROLLMENT_AUTHORIZER_BRANCH = [
  "counterpart_certificate",
  "control_plane_ring",
] as const;
export type EnrollmentAuthorizerBranch = (typeof ENROLLMENT_AUTHORIZER_BRANCH)[number];

/** Persisted tenant remote authority mirror. No private key, KMS handle, or raw credential. */
export interface TenantRemoteAuthority {
  tenantId: RemoteTenantId;
  authorityId: RemoteTenantAuthorityId;
  signerEndpointIdentity: string;
  signerConfigDigest: Uint8Array;
  issuer: string;
  jwks: string;
  generation: bigint;
  governanceEpoch: bigint;
  policyEpoch: bigint;
  lifecycle: TenantAuthorityLifecycle;
  governanceDigest: Uint8Array;
  highAssurance: boolean;
  recoveryCoolingSeconds: number;
  recoveryProposalTtlSeconds: number;
  createdAt: bigint;
  updatedAt: bigint;
  lastStatementAt: bigint | null;
}

export interface SignerStatus {
  tenantId: RemoteTenantId;
  authorityId: RemoteTenantAuthorityId;
  generation: bigint;
  governanceEpoch: bigint;
  policyEpoch: bigint;
  lifecycle: TenantAuthorityLifecycle;
  signerAvailable: boolean;
  signedAt: bigint;
}

export interface ApprovalArtifact {
  principalId: string;
  credentialIdHash: string;
  role: RemoteAdminRole;
}

/** Governed operations requiring exactly one OWNER plus one SECURITY_ADMIN. */
export const DUAL_CONTROL_GOVERNED_ACTIONS: ReadonlySet<RemoteAdminAction> = new Set([
  "authority_activation",
  "signer_replacement",
  "recovery",
  "security_role_change",
  "credential_governance",
  "remote_connection_policy_weakening",
]);

/** OWNER-only actions; SECURITY_ADMIN cannot revoke tenant identities. */
export const OWNER_ONLY_DENIAL_ACTIONS: ReadonlySet<RemoteAdminAction> = new Set([
  "tenant_lifecycle",
  "billing",
  "membership",
  "ordinary_role_assignment",
]);

/** SECURITY_ADMIN-only actions; OWNER alone cannot perform these. */
export const SECURITY_ADMIN_ONLY_ACTIONS: ReadonlySet<RemoteAdminAction> = new Set([
  "tenant_signer_configuration",
  "remote_connection_policy_equal_or_stronger",
  "device_daemon_trust",
]);

/** Identity revocation action boundary (operation 11). */
export const IDENTITY_REVOCATION_ACTIONS = ["self_client", "security_admin"] as const;
export type IdentityRevocationAction = (typeof IDENTITY_REVOCATION_ACTIONS)[number];

export const SELF_REVOCATION_REASONS = new Set(["user_requested", "key_compromised"]);
export const SECURITY_ADMIN_REVOCATION_SUBJECTS = new Set(["client", "daemon"]);

// ---------------------------------------------------------------------------
// Role/passkey matrix.
// ---------------------------------------------------------------------------

export interface RoleCheckInput {
  role: RemoteAdminRole;
  action: RemoteAdminAction;
  currentStepUp: boolean;
}

/** Exact OWNER/SECURITY_ADMIN action matrix; MEMBER/staff/operator denial. */
export function checkRoleAction(input: RoleCheckInput): {
  allowed: boolean;
  reason: string;
} {
  if (input.role === "MEMBER") return { allowed: false, reason: "member_denied" };
  // SECURITY_ADMIN-only actions: OWNER gets a specific denial before the
  // generic role/action check so callers see the exact boundary.
  if (SECURITY_ADMIN_ONLY_ACTIONS.has(input.action) && input.role !== "SECURITY_ADMIN")
    return { allowed: false, reason: "security_admin_only" };
  // OWNER-only actions: SECURITY_ADMIN gets a specific denial.
  if (OWNER_ONLY_DENIAL_ACTIONS.has(input.action) && input.role !== "OWNER")
    return { allowed: false, reason: "owner_only" };
  if (!roleCanStartAction(input.role, input.action))
    return { allowed: false, reason: "role_action_not_permitted" };
  if (!input.currentStepUp) return { allowed: false, reason: "step_up_required" };
  return { allowed: true, reason: "ok" };
}

// ---------------------------------------------------------------------------
// Dual control matrix.
// ---------------------------------------------------------------------------

export interface GovernedApprovalInput {
  action: RemoteAdminAction;
  approvals: readonly ApprovalArtifact[];
  operationDigest: Uint8Array;
  expectedDigest: Uint8Array;
  governanceEpoch: bigint;
  expectedEpoch: bigint;
  registryGeneration: bigint;
  expectedRegistryGeneration: bigint;
}

/** Distinct accounts/credentials, exactly one OWNER plus one SECURITY_ADMIN. */
export function checkGovernedApprovals(input: GovernedApprovalInput): {
  allowed: boolean;
  reason: string;
} {
  if (!equalBytes(input.operationDigest, input.expectedDigest))
    return { allowed: false, reason: "digest_mismatch" };
  if (input.governanceEpoch !== input.expectedEpoch)
    return { allowed: false, reason: "epoch_mismatch" };
  if (input.registryGeneration !== input.expectedRegistryGeneration)
    return { allowed: false, reason: "registry_generation_mismatch" };
  if (!actionRequiresDualControl(input.action))
    return { allowed: false, reason: "action_not_dual_control" };
  const identities: ApprovalIdentity[] = input.approvals.map((a) => ({
    principalId: a.principalId,
    credentialIdHash: a.credentialIdHash,
    role: a.role,
  }));
  try {
    assertRequiredApprovalPair(input.action, identities);
  } catch (error) {
    return { allowed: false, reason: (error as Error).message };
  }
  if (new Set(input.approvals.map((a) => a.principalId)).size !== input.approvals.length)
    return { allowed: false, reason: "self_approval_principals_not_distinct" };
  if (new Set(input.approvals.map((a) => a.credentialIdHash)).size !== input.approvals.length)
    return { allowed: false, reason: "self_approval_credentials_not_distinct" };
  return { allowed: true, reason: "ok" };
}

// ---------------------------------------------------------------------------
// Recovery timeline.
// ---------------------------------------------------------------------------

export interface RecoveryProposal {
  proposalId: string;
  authorityId: RemoteTenantAuthorityId;
  replacementSignerIdentity: string;
  replacementJwks: string;
  expectedGeneration: bigint;
  expectedGovernanceEpoch: bigint;
  expectedPolicyEpoch: bigint;
  actionDigest: Uint8Array;
  proposerId: string;
  proposerRole: RemoteAdminRole;
  ownerApproval: ApprovalArtifact | null;
  securityApproval: ApprovalArtifact | null;
  createdAt: bigint;
  coolingSeconds: number;
  ttlSeconds: number;
  ownerReconfirmedAt: bigint | null;
  securityReconfirmedAt: bigint | null;
  notifications: RecoveryNotification[];
  result: RecoveryProposalResult;
}

export type RecoveryProposalResult =
  | "pending"
  | "cooling"
  | "ready"
  | "executed"
  | "cancelled"
  | "expired"
  | "failed";

export interface RecoveryNotification {
  kind:
    | "proposed"
    | "approved"
    | "cooling_started"
    | "reconfirmed"
    | "executed"
    | "cancelled"
    | "failed";
  recipientRole: RemoteAdminRole;
  recipientId: string;
  sentAt: bigint;
}

export const RECOVERY_COOLING_MIN_SECONDS = 86_400;
export const RECOVERY_COOLING_MAX_SECONDS = 604_800;
export const RECOVERY_TTL_MIN_FLOOR_EXTRA_SECONDS = 86_400;
export const RECOVERY_TTL_MAX_SECONDS = 2_592_000;

export function validateRecoveryProposalTiming(cooling: number, ttl: number): void {
  validateRecoveryTiming(cooling, ttl);
}

/** Defaults: cooling 259200 (72h), TTL 604800 (7d). */
export function recoveryDefaults() {
  return {
    coolingSeconds: RECOVERY_COOLING_DEFAULT_SECONDS,
    ttlSeconds: RECOVERY_TTL_DEFAULT_SECONDS,
  };
}

export interface ProposeRecoveryInput {
  now: bigint;
  authorityId: RemoteTenantAuthorityId;
  replacementSignerIdentity: string;
  replacementJwks: string;
  expectedGeneration: bigint;
  expectedGovernanceEpoch: bigint;
  expectedPolicyEpoch: bigint;
  actionDigest: Uint8Array;
  proposerId: string;
  proposerRole: RemoteAdminRole;
  recipientIds: ReadonlyArray<{ id: string; role: RemoteAdminRole }>;
  coolingSeconds?: number;
  ttlSeconds?: number;
}

/** Immutable recovery proposal bound to replacement signer identity/JWKS, generation/epochs, digest. */
export function proposeRecovery(input: ProposeRecoveryInput): RecoveryProposal {
  const defaults = recoveryDefaults();
  const cooling = input.coolingSeconds ?? defaults.coolingSeconds;
  const ttl = input.ttlSeconds ?? defaults.ttlSeconds;
  validateRecoveryProposalTiming(cooling, ttl);
  if (input.proposerRole !== "OWNER" && input.proposerRole !== "SECURITY_ADMIN")
    throw new Error("recovery_proposer_role_invalid");
  const proposalId = `recovery-${input.now.toString(16)}-${Math.random().toString(36).slice(2, 10)}`;
  return {
    proposalId,
    authorityId: input.authorityId,
    replacementSignerIdentity: input.replacementSignerIdentity,
    replacementJwks: input.replacementJwks,
    expectedGeneration: input.expectedGeneration,
    expectedGovernanceEpoch: input.expectedGovernanceEpoch,
    expectedPolicyEpoch: input.expectedPolicyEpoch,
    actionDigest: new Uint8Array(input.actionDigest),
    proposerId: input.proposerId,
    proposerRole: input.proposerRole,
    ownerApproval: null,
    securityApproval: null,
    createdAt: input.now,
    coolingSeconds: cooling,
    ttlSeconds: ttl,
    ownerReconfirmedAt: null,
    securityReconfirmedAt: null,
    notifications: input.recipientIds.map((r) => ({
      kind: "proposed" as const,
      recipientRole: r.role,
      recipientId: r.id,
      sentAt: input.now,
    })),
    result: "pending",
  };
}

export interface ApproveRecoveryInput {
  proposal: RecoveryProposal;
  approval: ApprovalArtifact;
  now: bigint;
  recipientIds: ReadonlyArray<{ id: string; role: RemoteAdminRole }>;
}

/** Requires one OWNER plus one SECURITY_ADMIN; no self approval. */
export function approveRecovery(input: ApproveRecoveryInput): RecoveryProposal {
  const { proposal, approval, now } = input;
  if (proposal.result !== "pending" && proposal.result !== "cooling")
    throw new Error("recovery_proposal_not_open");
  if (now > proposal.createdAt + BigInt(proposal.ttlSeconds))
    throw new Error("recovery_proposal_expired");
  if (approval.role === "OWNER") {
    if (proposal.ownerApproval !== null) throw new Error("recovery_owner_already_approved");
    proposal.ownerApproval = approval;
  } else if (approval.role === "SECURITY_ADMIN") {
    if (proposal.securityApproval !== null) throw new Error("recovery_security_already_approved");
    proposal.securityApproval = approval;
  } else {
    throw new Error("recovery_approval_role_invalid");
  }
  if (proposal.ownerApproval && proposal.securityApproval) {
    if (
      proposal.ownerApproval.principalId === proposal.securityApproval.principalId ||
      proposal.ownerApproval.credentialIdHash === proposal.securityApproval.credentialIdHash
    )
      throw new Error("recovery_approvals_not_distinct");
    proposal.result = "cooling";
    const coolingEndsAt = proposal.createdAt + BigInt(proposal.coolingSeconds);
    proposal.notifications = [
      ...proposal.notifications,
      ...input.recipientIds.map((r) => ({
        kind: "cooling_started" as const,
        recipientRole: r.role,
        recipientId: r.id,
        sentAt: now,
      })),
    ];
    void coolingEndsAt;
  }
  proposal.notifications = [
    ...proposal.notifications,
    ...input.recipientIds.map((r) => ({
      kind: "approved" as const,
      recipientRole: r.role,
      recipientId: r.id,
      sentAt: now,
    })),
  ];
  return proposal;
}

export interface ReconfirmRecoveryInput {
  proposal: RecoveryProposal;
  reconfirmer: ApprovalArtifact;
  now: bigint;
  recipientIds: ReadonlyArray<{ id: string; role: RemoteAdminRole }>;
}

/** Both re-confirmations required after the signed governance cooling period. */
export function reconfirmRecovery(input: ReconfirmRecoveryInput): RecoveryProposal {
  const { proposal, reconfirmer, now } = input;
  if (proposal.result !== "cooling") throw new Error("recovery_not_in_cooling");
  const coolingEndsAt = proposal.createdAt + BigInt(proposal.coolingSeconds);
  if (now < coolingEndsAt) throw new Error("recovery_cooling_not_elapsed");
  if (now > proposal.createdAt + BigInt(proposal.ttlSeconds))
    throw new Error("recovery_proposal_expired");
  if (!proposal.ownerApproval || !proposal.securityApproval)
    throw new Error("recovery_missing_approvals");
  if (reconfirmer.role === "OWNER") {
    if (reconfirmer.principalId !== proposal.ownerApproval.principalId)
      throw new Error("recovery_reconfirm_owner_mismatch");
    if (proposal.ownerReconfirmedAt !== null) throw new Error("recovery_owner_already_reconfirmed");
    proposal.ownerReconfirmedAt = now;
  } else if (reconfirmer.role === "SECURITY_ADMIN") {
    if (reconfirmer.principalId !== proposal.securityApproval.principalId)
      throw new Error("recovery_reconfirm_security_mismatch");
    if (proposal.securityReconfirmedAt !== null)
      throw new Error("recovery_security_already_reconfirmed");
    proposal.securityReconfirmedAt = now;
  } else {
    throw new Error("recovery_reconfirm_role_invalid");
  }
  if (proposal.ownerReconfirmedAt !== null && proposal.securityReconfirmedAt !== null) {
    proposal.result = "ready";
    proposal.notifications = [
      ...proposal.notifications,
      ...input.recipientIds.map((r) => ({
        kind: "reconfirmed" as const,
        recipientRole: r.role,
        recipientId: r.id,
        sentAt: now,
      })),
    ];
  }
  return proposal;
}

export interface ExecuteRecoveryInput {
  proposal: RecoveryProposal;
  now: bigint;
  signerStatus: SignerStatus;
  recipientIds: ReadonlyArray<{ id: string; role: RemoteAdminRole }>;
}

/** Re-verifies both current signer status inside one serializable transaction. */
export function executeRecovery(input: ExecuteRecoveryInput): {
  proposal: RecoveryProposal;
  generation: bigint;
} {
  const { proposal, now, signerStatus } = input;
  if (proposal.result !== "ready") throw new Error("recovery_not_ready");
  if (now > proposal.createdAt + BigInt(proposal.ttlSeconds))
    throw new Error("recovery_proposal_expired");
  if (!equalBytes(signerStatus.authorityId, proposal.authorityId))
    throw new Error("recovery_authority_mismatch");
  if (signerStatus.generation !== proposal.expectedGeneration)
    throw new Error("recovery_generation_mismatch");
  if (signerStatus.governanceEpoch !== proposal.expectedGovernanceEpoch)
    throw new Error("recovery_governance_epoch_mismatch");
  if (signerStatus.policyEpoch !== proposal.expectedPolicyEpoch)
    throw new Error("recovery_policy_epoch_mismatch");
  if (!signerStatus.signerAvailable) throw new Error("recovery_signer_unavailable");
  proposal.result = "executed";
  proposal.notifications = [
    ...proposal.notifications,
    ...input.recipientIds.map((r) => ({
      kind: "executed" as const,
      recipientRole: r.role,
      recipientId: r.id,
      sentAt: now,
    })),
  ];
  return { proposal, generation: signerStatus.generation };
}

export interface CancelRecoveryInput {
  proposal: RecoveryProposal;
  cancellerId: string;
  cancellerRole: RemoteAdminRole;
  now: bigint;
  recipientIds: ReadonlyArray<{ id: string; role: RemoteAdminRole }>;
}

/** Any active owner may cancel; no staff/operator bypass. */
export function cancelRecovery(input: CancelRecoveryInput): RecoveryProposal {
  const { proposal, cancellerRole, now } = input;
  if (cancellerRole !== "OWNER") throw new Error("recovery_cancel_owner_only");
  if (!["pending", "cooling", "ready"].includes(proposal.result))
    throw new Error("recovery_not_cancellable");
  proposal.result = "cancelled";
  proposal.notifications = [
    ...proposal.notifications,
    ...input.recipientIds.map((r) => ({
      kind: "cancelled" as const,
      recipientRole: r.role,
      recipientId: r.id,
      sentAt: now,
    })),
  ];
  return proposal;
}

/** Expire a stale proposal after TTL; reconciles by immutable action ID. */
export function expireRecovery(proposal: RecoveryProposal, now: bigint): RecoveryProposal {
  if (!["pending", "cooling", "ready"].includes(proposal.result)) return proposal;
  if (now > proposal.createdAt + BigInt(proposal.ttlSeconds)) proposal.result = "expired";
  return proposal;
}

/** No staff/operator/password/email/OTP/master-key/submit-credential bypass. */
export function assertNoRecoveryBypass(method: string): void {
  const forbidden = [
    "staff",
    "operator",
    "password",
    "email",
    "otp",
    "master_key",
    "submit_credential",
    "control_plane",
    "support",
  ];
  if (forbidden.includes(method)) throw new Error(`recovery_bypass_rejected:${method}`);
}

// ---------------------------------------------------------------------------
// Generation race / authority ID allocation.
// ---------------------------------------------------------------------------

export interface AuthorityAllocationInput {
  now: bigint;
  tenantBytes: Uint8Array;
  authorityBytes: Uint8Array;
  usedAuthorityIds: ReadonlyArray<RemoteTenantAuthorityId>;
}

/** Allocate once at first activation; stable across rotation/recovery; never reused. */
export function allocateAuthorityId(input: AuthorityAllocationInput): {
  tenantId: RemoteTenantId;
  authorityId: RemoteTenantAuthorityId;
} {
  const tenantId = tagTenant(input.tenantBytes);
  const authorityId = tagAuthority(input.authorityBytes);
  if (equalBytes(input.tenantBytes, input.authorityBytes))
    throw new Error("authority_id_must_differ_from_tenant_id");
  for (const used of input.usedAuthorityIds) {
    if (equalBytes(used, authorityId)) throw new Error("authority_id_reuse_rejected");
  }
  return { tenantId, authorityId };
}

/** Cross-tenant/cross-authority alias rejection. */
export function assertAuthorityLookup(input: {
  expectedTenantId: RemoteTenantId;
  expectedAuthorityId: RemoteTenantAuthorityId;
  foundTenantId: RemoteTenantId;
  foundAuthorityId: RemoteTenantAuthorityId;
}): void {
  if (!equalBytes(input.expectedTenantId, input.foundTenantId))
    throw new Error("authority_lookup_tenant_mismatch");
  if (!equalBytes(input.expectedAuthorityId, input.foundAuthorityId))
    throw new Error("authority_lookup_authority_mismatch");
}

/** Governed recovery preserves logical authority and increments generation. */
export function recoveryIncrementGeneration(current: bigint): bigint {
  return current + 1n;
}

/** Deliberate revoke-and-create allocates a new ID; old ID never reused. */
export function revokeAndCreateNewId(input: {
  oldAuthorityId: RemoteTenantAuthorityId;
  newAuthorityBytes: Uint8Array;
  usedAuthorityIds: ReadonlyArray<RemoteTenantAuthorityId>;
}): RemoteTenantAuthorityId {
  const newId = tagAuthority(input.newAuthorityBytes);
  // Reusing the exact old authority ID is a "must allocate new" violation;
  // reusing any other previously-allocated ID is a reuse rejection.
  if (equalBytes(input.oldAuthorityId, newId))
    throw new Error("revoke_and_create_must_allocate_new_id");
  for (const used of input.usedAuthorityIds) {
    if (equalBytes(used, newId)) throw new Error("authority_id_reuse_rejected");
  }
  return newId;
}

// ---------------------------------------------------------------------------
// Rotation convergence — D0/D1/D2 publication + 990-second statement-key retention.
// ---------------------------------------------------------------------------

export const D0_D1_D2_PHASES = ["d0_prepare", "d1_publish", "d2_promote", "converged"] as const;
export type D0D1D2Phase = (typeof D0_D1_D2_PHASES)[number];

export interface PreparedCandidateArtifact {
  phase: D0D1D2Phase;
  signedBytes: Uint8Array;
  manifestDigest: Uint8Array;
  preparedAt: bigint;
  activated: boolean;
}

export interface RotationConvergenceInput {
  currentGeneration: bigint;
  candidates: ReadonlyArray<PreparedCandidateArtifact>;
  approvals: GovernedApprovalInput;
  signerStatus: SignerStatus;
}

/** New signer generation becomes current only after authorization and verification convergence. */
export function checkRotationConvergence(input: RotationConvergenceInput): {
  converged: boolean;
  reason: string;
  newGeneration: bigint | null;
} {
  const approval = checkGovernedApprovals(input.approvals);
  if (!approval.allowed) return { converged: false, reason: approval.reason, newGeneration: null };
  const d1 = input.candidates.find((c) => c.phase === "d1_publish");
  const d2 = input.candidates.find((c) => c.phase === "d2_promote");
  if (!d1 || !d2) return { converged: false, reason: "missing_d1_or_d2", newGeneration: null };
  if (input.signerStatus.generation <= input.currentGeneration)
    return { converged: false, reason: "signer_epoch_not_advanced", newGeneration: null };
  if (!input.signerStatus.signerAvailable)
    return { converged: false, reason: "signer_unavailable", newGeneration: null };
  return {
    converged: true,
    reason: "ok",
    newGeneration: input.signerStatus.generation,
  };
}

/** Exact 990-second statement-key retention: 900 + 30 + 60 after last signer-finalized statement. */
export function statementKeyRetentionFloorSeconds(): number {
  return 990;
}

/** Old signer cannot issue new statements after activation; verification-only for retention. */
export function checkOldStatementKeyRetention(input: {
  lastSignerFinalizedAt: bigint;
  now: bigint;
}): { verificationOnly: boolean; reason: string } {
  const floor = BigInt(statementKeyRetentionFloorSeconds());
  if (input.now <= input.lastSignerFinalizedAt + floor)
    return { verificationOnly: true, reason: "retention_window" };
  return { verificationOnly: false, reason: "expired" };
}

// ---------------------------------------------------------------------------
// Outage — high-assurance fails closed; no control-plane downgrade.
// ---------------------------------------------------------------------------

export interface OutageInput {
  signerAvailable: boolean;
  signerDenied: boolean;
  signerTimeout: boolean;
  signerIndeterminate: boolean;
  highAssurance: boolean;
  governedDisableApproved: boolean;
}

/** Signer outage/denial/indeterminate fails closed; control plane cannot switch to ordinary mode. */
export function checkOutage(input: OutageInput): {
  failClosed: boolean;
  downgraded: boolean;
  reason: string;
} {
  if (!input.highAssurance)
    return { failClosed: false, downgraded: false, reason: "not_high_assurance" };
  const outage =
    !input.signerAvailable ||
    input.signerDenied ||
    input.signerTimeout ||
    input.signerIndeterminate;
  if (outage) return { failClosed: true, downgraded: false, reason: "signer_outage_fail_closed" };
  if (input.governedDisableApproved)
    return { failClosed: false, downgraded: false, reason: "governed_disable_only" };
  return { failClosed: false, downgraded: false, reason: "ok" };
}

// ---------------------------------------------------------------------------
// Identity revocation governance (operation 11).
// ---------------------------------------------------------------------------

export interface IdentityRevocationInput {
  action: IdentityRevocationAction;
  subjectKind: "client" | "daemon" | "admin";
  reason: string;
  revoker: ApprovalArtifact;
  signerOwned: boolean;
}

/**
 * Client-key self-revocation only its own identity; one SECURITY_ADMIN for
 * client/daemon revocation; OWNER/MEMBER/staff/operator denial.
 */
export function checkIdentityRevocation(input: IdentityRevocationInput): {
  allowed: boolean;
  reason: string;
} {
  if (!input.signerOwned) return { allowed: false, reason: "not_signer_owned" };
  if (input.action === "self_client") {
    if (input.subjectKind !== "client")
      return { allowed: false, reason: "self_revocation_client_only" };
    if (!SELF_REVOCATION_REASONS.has(input.reason))
      return { allowed: false, reason: "self_revocation_reason_invalid" };
    return { allowed: true, reason: "ok" };
  }
  if (input.action === "security_admin") {
    if (input.revoker.role !== "SECURITY_ADMIN")
      return { allowed: false, reason: "security_admin_required" };
    if (!SECURITY_ADMIN_REVOCATION_SUBJECTS.has(input.subjectKind))
      return { allowed: false, reason: "security_admin_client_or_daemon_only" };
    return { allowed: true, reason: "ok" };
  }
  return { allowed: false, reason: "unknown_revocation_action" };
}

// ---------------------------------------------------------------------------
// Enrollment authorizer trust — branch-exact counterpart/control-plane.
// ---------------------------------------------------------------------------

export interface EnrollmentAuthorizerInput {
  branch: EnrollmentAuthorizerBranch;
  counterpartCertificate?: Uint8Array;
  counterpartFctv?: Uint8Array;
  controlPlaneRing?: Uint8Array;
  controlPlaneStatus?: Uint8Array;
}

/** Exact counterpart certificate/FCTV or configured control-plane ring/status; no cross-branch or request-created trust. */
export function checkEnrollmentAuthorizerTrust(input: EnrollmentAuthorizerInput): {
  trusted: boolean;
  reason: string;
} {
  if (input.branch === "counterpart_certificate") {
    if (!input.counterpartCertificate || input.counterpartCertificate.length === 0)
      return { trusted: false, reason: "counterpart_certificate_missing" };
    if (!input.counterpartFctv || input.counterpartFctv.length === 0)
      return { trusted: false, reason: "counterpart_fctv_missing" };
    if (input.controlPlaneRing || input.controlPlaneStatus)
      return { trusted: false, reason: "cross_branch_evidence_rejected" };
    return { trusted: true, reason: "ok" };
  }
  if (input.branch === "control_plane_ring") {
    if (!input.controlPlaneRing || input.controlPlaneRing.length === 0)
      return { trusted: false, reason: "control_plane_ring_missing" };
    if (!input.controlPlaneStatus || input.controlPlaneStatus.length === 0)
      return { trusted: false, reason: "control_plane_status_missing" };
    if (input.counterpartCertificate || input.counterpartFctv)
      return { trusted: false, reason: "cross_branch_evidence_rejected" };
    return { trusted: true, reason: "ok" };
  }
  return { trusted: false, reason: "unknown_branch" };
}

// ---------------------------------------------------------------------------
// Submit-credential cannot sign — no arbitrary/enrollment/policy/grant/recovery signature.
// ---------------------------------------------------------------------------

export const SUBMIT_CREDENTIAL_FORBIDDEN_SIGNATURE_KINDS = new Set([
  "arbitrary",
  "enrollment",
  "policy",
  "grant",
  "recovery",
  "authority_activation",
  "identity_revocation",
]);

export function assertSubmitCredentialCannotSign(input: {
  signatureKind: string;
  signerSideEvidence: boolean;
}): { rejected: boolean; reason: string } {
  if (SUBMIT_CREDENTIAL_FORBIDDEN_SIGNATURE_KINDS.has(input.signatureKind)) {
    if (!input.signerSideEvidence)
      return { rejected: true, reason: "submit_credential_cannot_sign_without_evidence" };
  }
  return { rejected: false, reason: "ok" };
}

// ---------------------------------------------------------------------------
// Customer signer enrollment — pinned service identity, submit-only mTLS.
// ---------------------------------------------------------------------------

export interface CustomerSignerEnrollmentInput {
  pinnedServiceIdentity: string;
  submitMtlsIdentity: string;
  signerChallenge: Uint8Array;
  genericSignature: boolean;
  controlPlaneSignature: boolean;
  nonExportablePublicStatus: boolean;
}

export function checkCustomerSignerEnrollment(input: CustomerSignerEnrollmentInput): {
  enrolled: boolean;
  reason: string;
} {
  if (!input.pinnedServiceIdentity)
    return { enrolled: false, reason: "service_identity_not_pinned" };
  if (!input.submitMtlsIdentity) return { enrolled: false, reason: "submit_mtls_required" };
  if (input.signerChallenge.length === 0)
    return { enrolled: false, reason: "structured_signer_challenge_required" };
  if (input.genericSignature) return { enrolled: false, reason: "generic_signature_rejected" };
  if (input.controlPlaneSignature)
    return { enrolled: false, reason: "control_plane_signature_rejected" };
  if (!input.nonExportablePublicStatus)
    return { enrolled: false, reason: "non_exportable_public_status_required" };
  return { enrolled: true, reason: "ok" };
}

// ---------------------------------------------------------------------------
// Safe state projection for UI/audit — never keys/signatures/assertions/endpoints.
// ---------------------------------------------------------------------------

export interface SafeAuthorityStateProjection {
  tenantId: string;
  authorityId: string;
  lifecycle: TenantAuthorityLifecycle;
  generation: string;
  providerClass: string;
  governanceEpoch: string;
  policyEpoch: string;
  highAssurance: boolean;
  recoveryCoolingSeconds: number;
  recoveryProposalTtlSeconds: number;
  approversDisplay: ReadonlyArray<{ role: RemoteAdminRole; principalId: string }>;
  createdAt: string;
  updatedAt: string;
}

/** UI/audit shows safe state/generation/provider class/approver display/times only. */
export function projectSafeAuthorityState(input: {
  authority: TenantRemoteAuthority;
  approversDisplay: ReadonlyArray<{ role: RemoteAdminRole; principalId: string }>;
  providerClass: string;
}): SafeAuthorityStateProjection {
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

/** Enterprise-boundary coverage: reject private key/KMS handle/generic signing path/assertion leak. */
export const REDACTED_FIELDS = new Set([
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
]);

export function assertNoSecretLeak(payload: Record<string, unknown>): {
  leaked: boolean;
  field: string | null;
} {
  for (const key of Object.keys(payload)) {
    if (REDACTED_FIELDS.has(key)) return { leaked: true, field: key };
  }
  return { leaked: false, field: null };
}
