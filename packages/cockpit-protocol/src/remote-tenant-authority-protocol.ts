/**
 * Transport-neutral canonical tenant-authority request, evidence, result,
 * status, and error protocol package.
 *
 * This module is the sole neutral owner of the closed tenant-authority
 * protocol surface: eleven operations, FCTA request envelope, FCTO result
 * envelope, twenty evidence types, the closed result/reason matrix, the
 * signing-domain enum, and the wire-magic registry guard.
 *
 * It consumes identity codecs from ./remote-identity-protocol and the
 * wire-magic registry from ./remote-wire-magic-registry. It never redefines,
 * re-encodes, or independently hashes those bytes.
 *
 * No function exported by this module signs caller-selected bytes.
 */

import { REMOTE_IDENTITY_MAGICS } from "./remote-identity-protocol";
import {
  assertRegisteredProductionMagics,
  type RemoteWireMagicOwnerV1,
} from "./remote-wire-magic-registry";

export const TENANT_AUTHORITY_MAGICS = {
  fcta: "FCTA",
  fcto: "FCTO",
  fctv: "FCTV",
  fcir: "FCIR",
  fcar: "FCAR",
  fcqr: "FCQR",
  fcrh: "FCRH",
  fcmi: "FCMI",
  fctr: "FCTR",
  fcrs: "FCRS",
} as const;

export const MAX_BODY_BYTES = 261_760;
export const MAX_REQUEST_BYTES = 262_144;
export const MAX_RESULT_BYTES = 16_384;
export const MAX_STATEMENT_JWS_BYTES = 16_000;
export const MAX_ARTIFACT_BYTES = 16_000;
export const MAX_FCTV_BYTES = 16_384;
export const MAX_FCTV_JWS_BYTES = 16_000;
export const MAX_FCTV_RESULT_BYTES = 16_057;
export const FCTA_VALIDITY_SECONDS = 60;
export const FUTURE_ISSUED_TOLERANCE_SECONDS = 60;
export const NETWORK_DEADLINE_SECONDS = 10;
export const IDEMPOTENCY_RETENTION_HOURS = 24;
export const STATEMENT_LIFETIME_ATTEMPT = 300;
export const STATEMENT_LIFETIME_HIGH_ASSURANCE = 900;
export const STATEMENT_LIFETIME_DENIAL_STATUS = 60;
export const VERIFIER_CACHE_SECONDS = 30;
export const VERIFIER_SKEW_SECONDS = 60;
export const RETENTION_FLOOR_SECONDS = 990;

export const TENANT_AUTHORITY_OPERATIONS = [
  { discriminant: 1, name: "authority_activation" },
  { discriminant: 2, name: "device_enrollment" },
  { discriminant: 3, name: "policy_revision" },
  { discriminant: 4, name: "attempt_grant" },
  { discriminant: 5, name: "authority_rotation" },
  { discriminant: 6, name: "credential_registry_revision" },
  { discriminant: 7, name: "recovery_lifecycle" },
  { discriminant: 8, name: "recovery_execution" },
  { discriminant: 9, name: "tenant_authority_status" },
  { discriminant: 10, name: "tenant_identity_revocation_status" },
  { discriminant: 11, name: "identity_revocation" },
] as const;

export function tenantAuthorityOperationFromDiscriminant(
  v: number,
): (typeof TENANT_AUTHORITY_OPERATIONS)[number] {
  const found = TENANT_AUTHORITY_OPERATIONS.find((op) => op.discriminant === v);
  if (!found) throw new Error(`unknown operation discriminant ${v}`);
  return found;
}

export const DEVICE_ENROLLMENT_ACTIONS = [
  { discriminant: 1, name: "enroll" },
  { discriminant: 2, name: "renew" },
  { discriminant: 3, name: "rotate" },
] as const;

export const CREDENTIAL_REGISTRY_ACTIONS = [
  { discriminant: 1, name: "add_credential" },
  { discriminant: 2, name: "revoke_credential" },
  { discriminant: 3, name: "assign_security_role" },
  { discriminant: 4, name: "remove_security_role" },
] as const;

export const RECOVERY_LIFECYCLE_ACTIONS = [
  { discriminant: 1, name: "propose" },
  { discriminant: 2, name: "reconfirm" },
  { discriminant: 3, name: "cancel" },
  { discriminant: 4, name: "expire" },
] as const;

export const IDENTITY_REVOCATION_ACTIONS = [
  { discriminant: 1, name: "self_client" },
  { discriminant: 2, name: "security_admin" },
] as const;

export type EvidenceCategory = "compact_jws" | "canonical_json" | "binary";

export interface EvidenceTypeSpec {
  discriminant: number;
  name: string;
  category: EvidenceCategory;
  typ?: string;
  magic?: string;
  cap: number;
}

export const EVIDENCE_TYPES: readonly EvidenceTypeSpec[] = [
  {
    discriminant: 1,
    name: "authority_ring",
    category: "compact_jws",
    typ: "flycockpit-tenant-authority-ring+jws",
    cap: 32768,
  },
  {
    discriminant: 2,
    name: "authority_status",
    category: "compact_jws",
    typ: "flycockpit-tenant-authority-status+jws",
    cap: 16384,
  },
  { discriminant: 3, name: "mtls_identity", category: "binary", magic: "FCMI", cap: 8192 },
  { discriminant: 4, name: "credential_registry", category: "binary", magic: "FCWR", cap: 131072 },
  { discriminant: 5, name: "admin_approval", category: "binary", magic: "FCWA", cap: 16384 },
  {
    discriminant: 6,
    name: "identity_certificate",
    category: "compact_jws",
    typ: "flycockpit-remote-identity-certificate+jws",
    cap: 4096,
  },
  { discriminant: 7, name: "possession_proof", category: "binary", magic: "FCPP", cap: 4096 },
  { discriminant: 8, name: "custody_evidence", category: "binary", magic: "FCCE", cap: 65536 },
  {
    discriminant: 9,
    name: "public_service_policy",
    category: "compact_jws",
    typ: "flycockpit-public-remote-policy+jws",
    cap: 16384,
  },
  {
    discriminant: 10,
    name: "tenant_policy",
    category: "compact_jws",
    typ: "flycockpit-tenant-remote-policy+jws",
    cap: 16384,
  },
  { discriminant: 11, name: "revocation_status", category: "binary", magic: "FCTV", cap: 16384 },
  { discriminant: 12, name: "attempt_request", category: "binary", magic: "FCAR", cap: 16384 },
  { discriminant: 13, name: "quota_request", category: "binary", magic: "FCQR", cap: 4096 },
  { discriminant: 14, name: "recovery_history", category: "binary", magic: "FCRH", cap: 65536 },
  { discriminant: 15, name: "identity_proposal", category: "binary", magic: "FCIP", cap: 4096 },
  { discriminant: 16, name: "enrollment_transcript", category: "binary", magic: "FCEN", cap: 1024 },
  {
    discriminant: 17,
    name: "enrollment_confirmation",
    category: "binary",
    magic: "FCCF",
    cap: 168,
  },
  {
    discriminant: 18,
    name: "identity_revocation_request",
    category: "binary",
    magic: "FCIR",
    cap: 4096,
  },
  {
    discriminant: 19,
    name: "control_plane_authority_ring",
    category: "canonical_json",
    cap: 32768,
  },
  {
    discriminant: 20,
    name: "control_plane_authority_status",
    category: "compact_jws",
    typ: "flycockpit-remote-authority-status+jws",
    cap: 16384,
  },
] as const;

export function evidenceTypeFromDiscriminant(v: number): EvidenceTypeSpec {
  const found = EVIDENCE_TYPES.find((e) => e.discriminant === v);
  if (!found) throw new Error(`unknown evidence type discriminant ${v}`);
  return found;
}

export const FCTO_RESULT_KINDS = [
  { discriminant: 1, name: "authorized" },
  { discriminant: 2, name: "denied" },
  { discriminant: 3, name: "authority_status" },
  { discriminant: 4, name: "identity_revocation_status" },
  { discriminant: 5, name: "error" },
] as const;

export const FCTO_REASON_CODES = [
  { discriminant: 0, name: "none" },
  { discriminant: 1, name: "malformed" },
  { discriminant: 2, name: "unsupported_version" },
  { discriminant: 3, name: "unknown_operation" },
  { discriminant: 4, name: "request_too_large" },
  { discriminant: 5, name: "unauthenticated" },
  { discriminant: 6, name: "tenant_or_authority_not_found" },
  { discriminant: 7, name: "request_conflict" },
  { discriminant: 8, name: "stale_epoch" },
  { discriminant: 9, name: "invalid_evidence" },
  { discriminant: 10, name: "invalid_approval" },
  { discriminant: 11, name: "revoked" },
  { discriminant: 12, name: "quota_exceeded" },
  { discriminant: 13, name: "policy_denied" },
  { discriminant: 14, name: "provider_unavailable" },
  { discriminant: 15, name: "indeterminate" },
  { discriminant: 16, name: "deadline_exceeded" },
  { discriminant: 17, name: "not_ready" },
  { discriminant: 18, name: "internal" },
] as const;

const DENIAL_REASONS = new Set([9, 10, 11, 12, 13]);
const ERROR_REASONS = new Set([1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 18]);

export function isDenialReason(discriminant: number): boolean {
  return DENIAL_REASONS.has(discriminant);
}

export function isErrorReason(discriminant: number): boolean {
  return ERROR_REASONS.has(discriminant);
}

export const SIGNING_DOMAINS = [
  { name: "TenantAuthorityRingV1", typ: "flycockpit-tenant-authority-ring+jws" },
  { name: "TenantRemotePolicyV1", typ: "flycockpit-tenant-remote-policy+jws" },
  { name: "TenantAuthorityStatusV1", typ: "flycockpit-tenant-authority-status+jws" },
  {
    name: "TenantIdentityRevocationStatusV1",
    typ: "flycockpit-tenant-identity-revocation-status+jws",
  },
  { name: "TenantAuthorizationStatementV1", typ: "flycockpit-tenant-authorization-statement+jws" },
  { name: "RemoteTenantAuthorityWatermarkV1", typ: undefined },
] as const;

export const FCIR_REASONS = [
  { discriminant: 1, name: "user_requested" },
  { discriminant: 2, name: "device_lost" },
  { discriminant: 3, name: "key_compromised" },
  { discriminant: 4, name: "admin_policy" },
  { discriminant: 5, name: "instance_retired" },
] as const;

export type ApprovalCardinality = "none" | "one_security_admin" | "owner_plus_security_admin";

export function approvalCardinality(operation: number, action?: number): ApprovalCardinality {
  switch (operation) {
    case 1:
    case 5:
    case 8:
    case 6:
      return "owner_plus_security_admin";
    case 7: {
      if (action === undefined) throw new Error("recovery_lifecycle requires a closed action");
      if (action === 4) return "none";
      return "owner_plus_security_admin";
    }
    case 2: {
      if (action === undefined) throw new Error("device_enrollment requires a closed action");
      if (action === 1 || action === 3) return "one_security_admin";
      return "none";
    }
    case 3: {
      if (action === 1) return "one_security_admin";
      if (action === 2) return "owner_plus_security_admin";
      throw new Error("policy_revision action must be 1 or 2");
    }
    case 11: {
      if (action === undefined) throw new Error("identity_revocation requires a closed action");
      if (action === 1) return "none";
      return "one_security_admin";
    }
    case 4:
    case 9:
    case 10:
      return "none";
    default:
      throw new Error(`unknown operation ${operation}`);
  }
}

export function assertTenantAuthorityWireMagics(registry: readonly RemoteWireMagicOwnerV1[]): void {
  assertRegisteredProductionMagics(registry, [
    { magic: "FCTA", symbolicType: "RemoteTenantAuthorityAuthorizationV1" },
    { magic: "FCTO", symbolicType: "RemoteTenantAuthorityResultV1" },
    { magic: "FCTV", symbolicType: "RemoteTenantAuthorityRevocationEvidenceV1" },
    { magic: "FCIR", symbolicType: "RemoteIdentityRevocationRequestV1" },
  ]);
  assertRegisteredProductionMagics(registry, [
    { magic: "FCTR", symbolicType: "RemoteTurnProviderResultV1" },
    { magic: "FCRS", symbolicType: "RemoteRelationshipConsentStatusV1" },
  ]);
}

export function isCrossProtocolMagic(magic: string): boolean {
  return magic === "FCTR" || magic === "FCRS";
}

export function validateNormalizedHttpsOrigin(s: string): void {
  if (!s.startsWith("https://")) throw new Error("origin must use HTTPS");
  if (s.length < 1 || s.length > 255) throw new Error("origin length must be 1..255");
  const authority = s.slice("https://".length);
  if (authority.length === 0) throw new Error("origin must have authority");
  if (/\s/.test(authority) || /[A-Z]/.test(authority)) throw new Error("origin must be lowercase");
  if (/[/?#@]/.test(authority))
    throw new Error("origin must not have path/query/fragment/credentials");
  if (authority.endsWith(":443")) throw new Error("origin must omit default port 443");
  const host = authority.includes(":")
    ? (() => {
        const idx = authority.indexOf(":");
        const h = authority.slice(0, idx);
        const port = authority.slice(idx + 1);
        if (
          port.length === 0 ||
          port.startsWith("0") ||
          !/^\d+$/.test(port) ||
          Number.isNaN(Number.parseInt(port, 10))
        )
          throw new Error("origin port is noncanonical");
        return h;
      })()
    : authority;
  if (host.length === 0 || host.startsWith(".") || host.endsWith("."))
    throw new Error("origin host is noncanonical");
  for (const label of host.split(".")) {
    if (
      label.length === 0 ||
      label.startsWith("-") ||
      label.endsWith("-") ||
      !/^[a-z0-9-]+$/.test(label)
    )
      throw new Error("origin host label is noncanonical");
  }
}

export function foundationConsumptionGuard(): void {
  if (REMOTE_IDENTITY_MAGICS.proposal !== "FCIP") throw new Error("FCIP mismatch");
  if (REMOTE_IDENTITY_MAGICS.possession !== "FCPP") throw new Error("FCPP mismatch");
  if (REMOTE_IDENTITY_MAGICS.confirmation !== "FCCF") throw new Error("FCCF mismatch");
}

export function closedSurfaceGuard(): void {
  if (TENANT_AUTHORITY_OPERATIONS.length !== 11) throw new Error("must be 11 operations");
  if (EVIDENCE_TYPES.length !== 20) throw new Error("must be 20 evidence types");
  if (FCTO_RESULT_KINDS.length !== 5) throw new Error("must be 5 result kinds");
  if (FCTO_REASON_CODES.length !== 19) throw new Error("must be 19 reason codes");
  if (SIGNING_DOMAINS.length !== 6) throw new Error("must be 6 signing domains");
  if (DEVICE_ENROLLMENT_ACTIONS.length !== 3)
    throw new Error("must be 3 device-enrollment actions");
  if (CREDENTIAL_REGISTRY_ACTIONS.length !== 4)
    throw new Error("must be 4 credential-registry actions");
  if (RECOVERY_LIFECYCLE_ACTIONS.length !== 4)
    throw new Error("must be 4 recovery-lifecycle actions");
  if (IDENTITY_REVOCATION_ACTIONS.length !== 2)
    throw new Error("must be 2 identity-revocation actions");
  if (FCIR_REASONS.length !== 5) throw new Error("must be 5 FCIR reasons");
  const jws = EVIDENCE_TYPES.filter((e) => e.category === "compact_jws").length;
  const json = EVIDENCE_TYPES.filter((e) => e.category === "canonical_json").length;
  const bin = EVIDENCE_TYPES.filter((e) => e.category === "binary").length;
  if (jws !== 6) throw new Error("must be 6 compact JWS evidence types");
  if (json !== 1) throw new Error("must be 1 canonical JSON evidence type");
  if (bin !== 13) throw new Error("must be 13 binary evidence types");
}
