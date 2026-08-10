import type { RemoteAdminAction, RemoteAdminRole } from "./remote-admin-roles";

export type RemoteAdminStepUpV1 = {
  id: string;
  tenantId: string;
  principalId: string;
  credentialIdHash: string;
  role: RemoteAdminRole;
  action: RemoteAdminAction;
  sessionId: string;
  challengeId: string;
  issuedAt: number;
  expiresAt: number;
  consumedAt: number | null;
};
export function consumeStepUp(
  row: RemoteAdminStepUpV1,
  expected: Omit<RemoteAdminStepUpV1, "id" | "issuedAt" | "expiresAt" | "consumedAt">,
  now: number,
) {
  if (row.consumedAt !== null) throw new Error("remote_admin_step_up_consumed");
  if (now < row.issuedAt || now > row.expiresAt || row.expiresAt - row.issuedAt > 300_000)
    throw new Error("remote_admin_step_up_expired");
  if (
    row.tenantId !== expected.tenantId ||
    row.principalId !== expected.principalId ||
    row.action !== expected.action ||
    row.sessionId !== expected.sessionId ||
    row.credentialIdHash !== expected.credentialIdHash ||
    row.role !== expected.role ||
    row.challengeId !== expected.challengeId
  )
    throw new Error("remote_admin_step_up_scope_mismatch");
  row.consumedAt = now;
}
export function assertCeremonyRetryScope(
  ceremony: { kind: string; principalId: string; sessionId: string | null },
  expected: { kinds: readonly string[]; principalId: string; sessionId?: string },
) {
  if (
    !expected.kinds.includes(ceremony.kind) ||
    ceremony.principalId !== expected.principalId ||
    (expected.sessionId !== undefined && ceremony.sessionId !== expected.sessionId)
  )
    throw new Error("remote_admin_ceremony_retry_scope_mismatch");
}

export type CounterState = {
  lastAcceptedSignCount: bigint;
  state: "active" | "suspect";
  stateGeneration: bigint;
};
export type CounterDecision = { next: CounterState; accepted: boolean };
export function evaluateAndAdvanceCounter(state: CounterState, observed: bigint): CounterDecision {
  if (state.state !== "active") throw new Error("remote_admin_credential_suspect");
  if (state.lastAcceptedSignCount === 0n && observed === 0n) return { next: state, accepted: true };
  if (observed > state.lastAcceptedSignCount)
    return {
      next: {
        ...state,
        lastAcceptedSignCount: observed,
        stateGeneration: state.stateGeneration + 1n,
      },
      accepted: true,
    };
  return {
    next: { ...state, state: "suspect", stateGeneration: state.stateGeneration + 1n },
    accepted: false,
  };
}

export const RECOVERY_COOLING_DEFAULT_SECONDS = 259_200;
export const RECOVERY_TTL_DEFAULT_SECONDS = 604_800;
export function validateRecoveryTiming(cooling: number, ttl: number) {
  if (!Number.isInteger(cooling) || cooling < 86_400 || cooling > 604_800)
    throw new Error("recovery_cooling_invalid");
  if (!Number.isInteger(ttl) || ttl < cooling + 86_400 || ttl > 2_592_000)
    throw new Error("recovery_ttl_invalid");
}
export type RecoveryProposal = {
  digest: string;
  ownerId: string;
  securityAdminId: string;
  coolingEndsAt: number;
  expiresAt: number;
  ownerReconfirmedAt: number | null;
  securityReconfirmedAt: number | null;
  state: "PENDING" | "COOLING" | "READY" | "CANCELLED" | "EXECUTED" | "EXPIRED";
};
export function recoveryReady(proposal: RecoveryProposal, now: number, digest: string) {
  if (
    !["PENDING", "COOLING", "READY"].includes(proposal.state) ||
    digest !== proposal.digest ||
    now < proposal.coolingEndsAt ||
    now > proposal.expiresAt ||
    proposal.ownerReconfirmedAt === null ||
    proposal.securityReconfirmedAt === null ||
    proposal.ownerReconfirmedAt < proposal.coolingEndsAt ||
    proposal.securityReconfirmedAt < proposal.coolingEndsAt ||
    proposal.ownerId === proposal.securityAdminId
  )
    throw new Error("remote_admin_recovery_not_ready");
}
