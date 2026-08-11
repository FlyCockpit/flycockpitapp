import { describe, expect, it } from "vitest";
import {
  type AdminGrantProjectBinding,
  type AuthorizationTarget,
  anonymousPrincipal,
  authorizeImageControlRequest,
  isMutationFamily,
  legacyGrantsCanAuthorizeMutation,
  ownerPrincipal,
  readOnlySafeProjection,
  remotePrincipal,
  requestTagFamily,
  validateAdminGrantRoot,
} from "./image-generation-authorization";
import { IMAGE_GENERATION_ADMIN_SCOPE_STRING } from "./image-generation-contracts";

const target: AuthorizationTarget = {
  daemonInstanceId: "daemon-1",
  projectId: "project-1",
  projectRoot: "/projects/project-1",
  sessionId: "session-1",
};

const wrongProjectTarget: AuthorizationTarget = {
  daemonInstanceId: "daemon-1",
  projectId: "project-other",
  projectRoot: "/projects/project-other",
  sessionId: "session-1",
};

function activeAdminGrant(projectId: string, projectRoot: string): AdminGrantProjectBinding {
  return {
    scope: IMAGE_GENERATION_ADMIN_SCOPE_STRING,
    projectId,
    projectRoot,
    status: "active",
  };
}

describe("image generation authorization", () => {
  it("owner is always allowed and may mutate", () => {
    const owner = ownerPrincipal();
    for (const tag of [
      "image_endpoint_create",
      "image_budget_set",
      "image_job_cancel",
      "image_late_result_publish",
      "image_endpoint_list",
    ] as const) {
      const decision = authorizeImageControlRequest(owner, tag, target);
      expect(decision.allowed).toBe(true);
      expect(decision.canMutate).toBe(true);
    }
  });

  it("anonymous is always denied unauthenticated", () => {
    const anon = anonymousPrincipal();
    const decision = authorizeImageControlRequest(anon, "image_endpoint_list", target);
    expect(decision.allowed).toBe(false);
    expect(decision.error).toBe("unauthenticated");
  });

  it("exact-project ImageGenerationAdmin may mutate config", () => {
    const admin = remotePrincipal([activeAdminGrant(target.projectId, target.projectRoot)]);
    const decision = authorizeImageControlRequest(admin, "image_endpoint_create", target);
    expect(decision.allowed).toBe(true);
    expect(decision.canMutate).toBe(true);
  });

  it("wrong-project ImageGenerationAdmin is forbidden for config mutations", () => {
    const admin = remotePrincipal([activeAdminGrant("project-other", "/projects/other")]);
    const decision = authorizeImageControlRequest(admin, "image_endpoint_create", target);
    expect(decision.allowed).toBe(false);
    expect(decision.error).toBe("forbidden");
  });

  it("ordinary session-read user sees read-only safe projection for config reads", () => {
    // A remote principal with a non-admin active grant on the exact project.
    const ordinary = remotePrincipal([
      {
        scope: "project_files",
        projectId: target.projectId,
        projectRoot: target.projectRoot,
        status: "active",
      },
    ]);
    const decision = authorizeImageControlRequest(ordinary, "image_health_get", target);
    expect(decision.allowed).toBe(true);
    expect(decision.canMutate).toBe(false);
  });

  it("exact-project admin may cancel jobs (session_write_or_admin)", () => {
    const admin = remotePrincipal([activeAdminGrant(target.projectId, target.projectRoot)]);
    const decision = authorizeImageControlRequest(admin, "image_job_cancel", target);
    expect(decision.allowed).toBe(true);
    expect(decision.canMutate).toBe(true);
  });

  it("revoked admin grant is forbidden for mutations", () => {
    const revoked = remotePrincipal([
      { ...activeAdminGrant(target.projectId, target.projectRoot), status: "revoked" },
    ]);
    const decision = authorizeImageControlRequest(revoked, "image_endpoint_create", target);
    expect(decision.allowed).toBe(false);
    expect(decision.error).toBe("forbidden");
  });

  it("revoking admin grant is forbidden for mutations (fence)", () => {
    const revoking = remotePrincipal([
      { ...activeAdminGrant(target.projectId, target.projectRoot), status: "revoking" },
    ]);
    const decision = authorizeImageControlRequest(revoking, "image_budget_set", target);
    expect(decision.allowed).toBe(false);
    expect(decision.error).toBe("forbidden");
  });

  it("rootless admin grant is invalid and forbidden", () => {
    const rootless = remotePrincipal([
      {
        scope: IMAGE_GENERATION_ADMIN_SCOPE_STRING,
        projectId: target.projectId,
        projectRoot: undefined,
        status: "active",
      },
    ]);
    expect(validateAdminGrantRoot(IMAGE_GENERATION_ADMIN_SCOPE_STRING, undefined)).toBe(false);
    const decision = authorizeImageControlRequest(rootless, "image_endpoint_create", target);
    expect(decision.allowed).toBe(false);
    expect(decision.error).toBe("forbidden");
  });

  it("legacy grants snapshot never authorizes a mutation", () => {
    const admin = remotePrincipal([activeAdminGrant(target.projectId, target.projectRoot)]);
    expect(legacyGrantsCanAuthorizeMutation(admin, "config_mutations")).toBe(false);
    expect(legacyGrantsCanAuthorizeMutation(admin, "late_result")).toBe(false);
    expect(legacyGrantsCanAuthorizeMutation(admin, "job_cancel")).toBe(false);
  });

  it("isMutationFamily identifies mutation families", () => {
    expect(isMutationFamily(requestTagFamily("image_endpoint_create"))).toBe(true);
    expect(isMutationFamily(requestTagFamily("image_late_result_publish"))).toBe(true);
    expect(isMutationFamily(requestTagFamily("image_job_cancel"))).toBe(true);
    expect(isMutationFamily(requestTagFamily("image_endpoint_list"))).toBe(false);
    expect(isMutationFamily(requestTagFamily("image_health_get"))).toBe(false);
  });

  it("read-only safe projection labels distinct denial reasons", () => {
    const notAdmin = remotePrincipal([
      {
        scope: "project_files",
        projectId: target.projectId,
        projectRoot: target.projectRoot,
        status: "active",
      },
    ]);
    const notAdminProjection = readOnlySafeProjection(notAdmin, target);
    expect(notAdminProjection.readOnly).toBe(true);
    expect(notAdminProjection.reason).toBe("not_admin");

    const wrongProject = remotePrincipal([activeAdminGrant("other", "/projects/other")]);
    const wrongProjection = readOnlySafeProjection(wrongProject, target);
    expect(wrongProjection.reason).toBe("wrong_project");

    const revoked = remotePrincipal([
      { ...activeAdminGrant(target.projectId, target.projectRoot), status: "revoked" },
    ]);
    const revokedProjection = readOnlySafeProjection(revoked, target);
    expect(revokedProjection.reason).toBe("revoked");

    const anonProjection = readOnlySafeProjection(anonymousPrincipal(), target);
    expect(anonProjection.reason).toBe("anonymous");
  });

  it("operation_status accepts project_read or admin", () => {
    const admin = remotePrincipal([activeAdminGrant(target.projectId, target.projectRoot)]);
    const decision = authorizeImageControlRequest(admin, "image_operation_status", target);
    expect(decision.allowed).toBe(true);
    expect(decision.canMutate).toBe(true);
  });

  it("wrong-project target is denied for admin-only reads", () => {
    const admin = remotePrincipal([activeAdminGrant(target.projectId, target.projectRoot)]);
    const decision = authorizeImageControlRequest(admin, "image_endpoint_list", wrongProjectTarget);
    expect(decision.allowed).toBe(false);
    expect(decision.error).toBe("forbidden");
  });
});
