export type AuthRecoveryKind =
  | "credentials_rejected"
  | "missing_entitlement"
  | "oauth_expired"
  | "provider_not_configured"
  | "generic";

export type AuthRecoveryView = {
  kind: AuthRecoveryKind;
  messageKey: string;
  status?: number;
  feature?: string;
  provider?: string;
};

export function authRecoveryView(authFailure: unknown): AuthRecoveryView {
  const record =
    authFailure && typeof authFailure === "object"
      ? (authFailure as Record<string, unknown>)
      : null;
  const kind = typeof record?.kind === "string" ? record.kind : null;

  if (kind === "credentials_rejected") {
    const status = typeof record?.status === "number" ? record.status : undefined;
    return { kind, messageKey: "remote.authCredentialsRejected", status };
  }

  if (kind === "missing_entitlement") {
    const feature = typeof record?.feature === "string" ? record.feature : undefined;
    return { kind, messageKey: "remote.authMissingEntitlement", feature };
  }

  if (kind === "oauth_expired") {
    const provider = typeof record?.provider === "string" ? record.provider : undefined;
    return { kind, messageKey: "remote.authOAuthExpired", provider };
  }

  if (kind === "provider_not_configured") {
    return { kind, messageKey: "remote.authProviderNotConfigured" };
  }

  return { kind: "generic", messageKey: "remote.inferenceFailureGeneric" };
}

export function errorClassLabel(errorClass: unknown): string {
  if (typeof errorClass === "string") return errorClass;
  if (!errorClass || typeof errorClass !== "object") return "unknown";
  const record = errorClass as Record<string, unknown>;
  const kind = typeof record.kind === "string" ? record.kind : "unknown";
  if (typeof record.status === "number") return `${kind} ${record.status}`;
  if (typeof record.feature === "string") return `${kind}: ${record.feature}`;
  return kind;
}
