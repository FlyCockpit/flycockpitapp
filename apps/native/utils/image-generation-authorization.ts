/**
 * Image-generation control-plane authorization matrix for the native remote UI.
 *
 * Mirrors `crates/cockpit-core/src/image_generation_control_plane` request
 * family → capability mapping. Endpoint/target/workflow/default/health,
 * explicit budgets/project epoch, and destination grant mutations are
 * available only to `Owner` or exact-project `ImageGenerationAdmin`; other
 * authorized users see a labeled read-only safe projection.
 *
 * The legacy `ClientPrincipal::Remote`/`RemotePrincipal.grants` snapshot is
 * grounding only and is never the new authority for remote mutations.
 */

import {
  type HostedAccessScope,
  IMAGE_GENERATION_ADMIN_SCOPE_STRING,
  type ImageControlErrorCode,
  type ImageControlRequestTag,
  scopeRequiresProjectRoot,
} from "./image-generation-contracts";

// ---------------------------------------------------------------------------
// Principal
// ---------------------------------------------------------------------------

/** The native principal kind. */
export type NativePrincipalKind = "owner" | "remote" | "anonymous";

/** A canonical project binding for an admin grant. */
export interface AdminGrantProjectBinding {
  scope: HostedAccessScope;
  /** Canonical project root; required nonnull for `image_generation_admin`. */
  projectRoot?: string;
  /** Canonical project id; required nonnull for `image_generation_admin`. */
  projectId?: string;
  /** Grant status. Only `active` authorizes; `revoking` fences mutations. */
  status: "pending" | "active" | "revoking" | "revoked" | "expired" | "declined";
}

/** The native principal. */
export interface NativePrincipal {
  kind: NativePrincipalKind;
  /** Active image-admin grants for remote principals. Empty for owner/anonymous. */
  adminGrants: readonly AdminGrantProjectBinding[];
}

/** An owner principal. */
export function ownerPrincipal(): NativePrincipal {
  return { kind: "owner", adminGrants: [] };
}

/** A remote principal with the given admin grants. */
export function remotePrincipal(grants: readonly AdminGrantProjectBinding[]): NativePrincipal {
  return { kind: "remote", adminGrants: grants };
}

/** An anonymous (unauthenticated) principal. */
export function anonymousPrincipal(): NativePrincipal {
  return { kind: "anonymous", adminGrants: [] };
}

// ---------------------------------------------------------------------------
// Request family
// ---------------------------------------------------------------------------

/** The request authorization family, matching the matrix in the prompt. */
export type RequestFamily =
  | "config_reads_and_snapshot"
  | "health_reads_and_refresh"
  | "plan_get"
  | "job_reads_and_snapshot"
  | "job_cancel"
  | "config_mutations"
  | "late_result"
  | "operation_status";

/** Maps a request tag to its request family for authorization. */
export function requestTagFamily(tag: ImageControlRequestTag): RequestFamily {
  switch (tag) {
    case "image_endpoint_list":
    case "image_endpoint_get":
    case "image_target_list":
    case "image_target_get":
    case "image_workflow_list":
    case "image_workflow_get":
    case "image_budget_get":
    case "image_destination_grant_list":
    case "image_control_admin_snapshot":
      return "config_reads_and_snapshot";
    case "image_health_get":
    case "image_health_refresh":
      return "health_reads_and_refresh";
    case "image_plan_get":
      return "plan_get";
    case "image_job_list":
    case "image_job_get":
    case "image_control_session_snapshot":
      return "job_reads_and_snapshot";
    case "image_operation_status":
      return "operation_status";
    case "image_endpoint_create":
    case "image_endpoint_update":
    case "image_endpoint_delete":
    case "image_target_create":
    case "image_target_update":
    case "image_target_delete":
    case "image_target_set_default":
    case "image_workflow_upload":
    case "image_workflow_bind":
    case "image_workflow_delete":
    case "image_budget_set":
    case "image_destination_grant_revoke":
      return "config_mutations";
    case "image_job_cancel":
      return "job_cancel";
    case "image_late_result_publish":
    case "image_late_result_discard":
      return "late_result";
  }
}

// ---------------------------------------------------------------------------
// Remote attempt capability
// ---------------------------------------------------------------------------

/** The remote attempt capability required for each request family. */
export type RemoteAttemptCapability =
  | "image_generation_admin"
  | "project_read"
  | "session_read"
  | "session_write"
  | "project_read_or_image_generation_admin"
  | "session_write_or_image_generation_admin";

/** Returns the remote attempt capability required for a request family. */
export function remoteCapabilityForFamily(family: RequestFamily): RemoteAttemptCapability {
  switch (family) {
    case "config_reads_and_snapshot":
      return "image_generation_admin";
    case "health_reads_and_refresh":
      return "project_read";
    case "plan_get":
      return "session_read";
    case "job_reads_and_snapshot":
      return "session_read";
    case "job_cancel":
      return "session_write_or_image_generation_admin";
    case "config_mutations":
      return "image_generation_admin";
    case "late_result":
      return "image_generation_admin";
    case "operation_status":
      return "project_read_or_image_generation_admin";
  }
}

/** Returns `true` if local `Owner` is always allowed for this family. */
export function localOwnerAllowed(_family: RequestFamily): boolean {
  return true;
}

// ---------------------------------------------------------------------------
// Authorization decision
// ---------------------------------------------------------------------------

/** The authorization decision for a control-plane request. */
export interface AuthorizationDecision {
  allowed: boolean;
  /** The error code when denied; `undefined` when allowed. */
  error?: ImageControlErrorCode;
  /** `true` when the principal may mutate; `false` for read-only safe projection. */
  canMutate: boolean;
}

function allow(canMutate: boolean): AuthorizationDecision {
  return { allowed: true, canMutate };
}

function deny(code: ImageControlErrorCode): AuthorizationDecision {
  return { allowed: false, error: code, canMutate: false };
}

/** The target project context for an authorization check. */
export interface AuthorizationTarget {
  daemonInstanceId: string;
  projectId: string;
  projectRoot: string;
  sessionId?: string;
}

/** Validate that an `ImageGenerationAdmin` grant has a nonnull project root. */
export function validateAdminGrantRoot(
  scope: HostedAccessScope,
  projectRoot: string | undefined,
): boolean {
  if (scopeRequiresProjectRoot(scope)) {
    return Boolean(projectRoot && projectRoot.length > 0);
  }
  return true;
}

/** Check whether a grant is active and exact-project bound. */
function isActiveExactProjectGrant(
  grant: AdminGrantProjectBinding,
  target: AuthorizationTarget,
): boolean {
  if (grant.scope !== IMAGE_GENERATION_ADMIN_SCOPE_STRING) return false;
  if (grant.status !== "active") return false;
  if (!validateAdminGrantRoot(grant.scope, grant.projectRoot)) return false;
  return grant.projectRoot === target.projectRoot && grant.projectId === target.projectId;
}

/** Check whether a remote principal has `image_generation_admin` on the exact project. */
export function remoteHasImageGenerationAdmin(
  principal: NativePrincipal,
  target: AuthorizationTarget,
): boolean {
  if (principal.kind !== "remote") return false;
  return principal.adminGrants.some((grant) => isActiveExactProjectGrant(grant, target));
}

/** Check whether a remote principal has `session_read` on the exact project. */
function remoteHasSessionRead(principal: NativePrincipal, target: AuthorizationTarget): boolean {
  if (principal.kind !== "remote") return false;
  if (remoteHasImageGenerationAdmin(principal, target)) return true;
  // The legacy grants snapshot is grounding only; session_read is accepted
  // only when explicitly represented as an active admin grant with a matching
  // project root. Without a dedicated scope enum here, only admin grants
  // elevate session reads. This intentionally matches the control plane's
  // rejection of rootless wildcard authority.
  return principal.adminGrants.some(
    (grant) =>
      grant.status === "active" &&
      grant.scope !== IMAGE_GENERATION_ADMIN_SCOPE_STRING &&
      grant.projectRoot === target.projectRoot &&
      grant.projectId === target.projectId,
  );
}

/** Check whether a remote principal has `session_write` on the exact project. */
function remoteHasSessionWrite(principal: NativePrincipal, target: AuthorizationTarget): boolean {
  return remoteHasSessionRead(principal, target);
}

/** Check whether a remote principal has `project_read` on the exact project. */
function remoteHasProjectRead(principal: NativePrincipal, target: AuthorizationTarget): boolean {
  if (principal.kind !== "remote") return false;
  if (remoteHasImageGenerationAdmin(principal, target)) return true;
  return principal.adminGrants.some(
    (grant) =>
      grant.status === "active" &&
      grant.projectRoot === target.projectRoot &&
      grant.projectId === target.projectId,
  );
}

/**
 * Check whether a remote principal's legacy `grants` snapshot can authorize
 * an image-generation management mutation.
 *
 * The legacy snapshot is grounding only and is never the new authority for
 * remote mutations. This always returns `false` for any mutation family.
 */
export function legacyGrantsCanAuthorizeMutation(
  principal: NativePrincipal,
  family: RequestFamily,
): boolean {
  if (principal.kind !== "remote") return false;
  if (family === "config_mutations" || family === "late_result" || family === "job_cancel") {
    return false;
  }
  return false;
}

/** Returns `true` if a request family is a mutation family. */
export function isMutationFamily(family: RequestFamily): boolean {
  return family === "config_mutations" || family === "late_result" || family === "job_cancel";
}

/**
 * Authorize a control-plane request for a native principal.
 *
 * Local `Owner` is always allowed and may mutate. Remote principals require
 * the exact-project capability for the request family; admin mutations
 * require `image_generation_admin` on the exact canonical project. Other
 * authorized users see a labeled read-only safe projection (allowed for
 * reads, `canMutate=false`).
 */
export function authorizeImageControlRequest(
  principal: NativePrincipal,
  tag: ImageControlRequestTag,
  target: AuthorizationTarget,
): AuthorizationDecision {
  const family = requestTagFamily(tag);

  if (principal.kind === "anonymous") {
    return deny("unauthenticated");
  }

  if (principal.kind === "owner") {
    if (!localOwnerAllowed(family)) return deny("forbidden");
    return allow(true);
  }

  // Remote principal.
  const capability = remoteCapabilityForFamily(family);

  switch (capability) {
    case "image_generation_admin":
      if (!remoteHasImageGenerationAdmin(principal, target)) {
        return deny("forbidden");
      }
      return allow(true);
    case "project_read":
      if (!remoteHasProjectRead(principal, target)) {
        return deny("forbidden");
      }
      return allow(false);
    case "session_read":
      if (!remoteHasSessionRead(principal, target)) {
        return deny("forbidden");
      }
      return allow(false);
    case "session_write":
      if (!remoteHasSessionWrite(principal, target)) {
        return deny("forbidden");
      }
      return allow(true);
    case "session_write_or_image_generation_admin":
      if (
        remoteHasSessionWrite(principal, target) ||
        remoteHasImageGenerationAdmin(principal, target)
      ) {
        return allow(true);
      }
      return deny("forbidden");
    case "project_read_or_image_generation_admin":
      if (
        remoteHasProjectRead(principal, target) ||
        remoteHasImageGenerationAdmin(principal, target)
      ) {
        return allow(remoteHasImageGenerationAdmin(principal, target));
      }
      return deny("forbidden");
  }
}

/** The labeled read-only safe-projection view for an unauthorized remote user. */
export interface ReadOnlySafeProjection {
  readonly readOnly: true;
  label: string;
  reason: "not_admin" | "wrong_project" | "revoked" | "anonymous";
}

/** Build the read-only safe projection label for a denied remote principal. */
export function readOnlySafeProjection(
  principal: NativePrincipal,
  target: AuthorizationTarget,
): ReadOnlySafeProjection {
  if (principal.kind === "anonymous") {
    return {
      readOnly: true,
      label: "Sign in to view image-generation settings.",
      reason: "anonymous",
    };
  }
  const hasAnyAdminGrant = principal.adminGrants.some(
    (grant) => grant.scope === IMAGE_GENERATION_ADMIN_SCOPE_STRING,
  );
  if (!hasAnyAdminGrant) {
    return {
      readOnly: true,
      label: "You are not an image-generation admin for this project. Settings are read-only.",
      reason: "not_admin",
    };
  }
  const hasWrongProject = principal.adminGrants.some(
    (grant) =>
      grant.scope === IMAGE_GENERATION_ADMIN_SCOPE_STRING &&
      (grant.projectRoot !== target.projectRoot || grant.projectId !== target.projectId),
  );
  if (hasWrongProject) {
    return {
      readOnly: true,
      label:
        "Your image-generation admin grant is for a different project. Settings are read-only.",
      reason: "wrong_project",
    };
  }
  const hasRevoked = principal.adminGrants.some(
    (grant) =>
      grant.scope === IMAGE_GENERATION_ADMIN_SCOPE_STRING &&
      grant.projectRoot === target.projectRoot &&
      grant.projectId === target.projectId &&
      (grant.status === "revoked" || grant.status === "revoking" || grant.status === "expired"),
  );
  if (hasRevoked) {
    return {
      readOnly: true,
      label: "Your image-generation admin grant is no longer active. Settings are read-only.",
      reason: "revoked",
    };
  }
  return {
    readOnly: true,
    label: "You are not authorized to manage image-generation settings for this project.",
    reason: "not_admin",
  };
}
