export const REMOTE_ADMIN_ROLES = ["OWNER", "SECURITY_ADMIN", "MEMBER"] as const;
export type RemoteAdminRole = (typeof REMOTE_ADMIN_ROLES)[number];

export const REMOTE_ADMIN_ACTIONS = [
  "tenant_lifecycle",
  "billing",
  "membership",
  "ordinary_role_assignment",
  "credential_governance",
  "security_role_change",
  "tenant_signer_configuration",
  "remote_connection_policy_equal_or_stronger",
  "remote_connection_policy_weakening",
  "device_daemon_trust",
  "authority_activation",
  "signer_replacement",
  "recovery",
  "enterprise_log_export",
] as const;
export type RemoteAdminAction = (typeof REMOTE_ADMIN_ACTIONS)[number];

const OWNER_ACTIONS = new Set<RemoteAdminAction>([
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
const SECURITY_ACTIONS = new Set<RemoteAdminAction>([
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
const DUAL_CONTROL_ACTIONS = new Set<RemoteAdminAction>([
  "authority_activation",
  "signer_replacement",
  "recovery",
  "security_role_change",
  "credential_governance",
  "remote_connection_policy_weakening",
]);

export function roleCanStartAction(role: RemoteAdminRole, action: RemoteAdminAction): boolean {
  if (role === "MEMBER") return false;
  return role === "OWNER" ? OWNER_ACTIONS.has(action) : SECURITY_ACTIONS.has(action);
}

export function actionRequiresDualControl(action: RemoteAdminAction): boolean {
  return DUAL_CONTROL_ACTIONS.has(action);
}

export type ApprovalIdentity = {
  principalId: string;
  credentialIdHash: string;
  role: RemoteAdminRole;
};

export function assertRequiredApprovalPair(
  action: RemoteAdminAction,
  approvals: readonly ApprovalIdentity[],
): void {
  const expectedCount = actionRequiresDualControl(action) ? 2 : 1;
  if (approvals.length !== expectedCount) throw new Error("remote_admin_approval_cardinality");
  if (new Set(approvals.map((approval) => approval.principalId)).size !== approvals.length)
    throw new Error("remote_admin_principals_not_distinct");
  if (new Set(approvals.map((approval) => approval.credentialIdHash)).size !== approvals.length)
    throw new Error("remote_admin_credentials_not_distinct");
  if (expectedCount === 2) {
    const roles = new Set(approvals.map((approval) => approval.role));
    if (!roles.has("OWNER") || !roles.has("SECURITY_ADMIN"))
      throw new Error("remote_admin_role_pair_invalid");
  } else if (!roleCanStartAction(approvals[0]!.role, action)) {
    throw new Error("remote_admin_action_role_invalid");
  }
}

export function assertQuorumAfterChange(input: {
  activeOwners: number;
  activeSecurityAdmins: number;
  ownerDelta?: number;
  securityAdminDelta?: number;
}): void {
  if (input.activeOwners + (input.ownerDelta ?? 0) < 1) throw new Error("last_owner_protected");
  if (input.activeSecurityAdmins + (input.securityAdminDelta ?? 0) < 1)
    throw new Error("last_security_admin_protected");
}
