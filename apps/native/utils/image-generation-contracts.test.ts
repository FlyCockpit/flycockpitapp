import { describe, expect, it } from "vitest";
import {
  CONTROL_PLANE_SCHEMA_VERSION,
  IMAGE_CONTROL_REQUEST_TAGS,
  type ImageControlRequestTag,
  requestTagClassification,
  requestTagRequiresSessionId,
  type SnapshotComponent,
  snapshotComponentIsAdmin,
  snapshotComponentIsSession,
} from "./image-generation-contracts";

describe("image generation contracts", () => {
  it("exposes the V1 schema version and admin ordinal", () => {
    expect(CONTROL_PLANE_SCHEMA_VERSION).toBe(1);
  });

  it("classifies every request tag as read-only or mutation", () => {
    const readOnly: ImageControlRequestTag[] = [];
    const mutation: ImageControlRequestTag[] = [];
    for (const tag of IMAGE_CONTROL_REQUEST_TAGS) {
      const cls = requestTagClassification(tag);
      if (cls === "read_only") readOnly.push(tag);
      else mutation.push(tag);
    }
    // Safe reads + runtime reads.
    expect(readOnly).toContain("image_endpoint_list");
    expect(readOnly).toContain("image_plan_get");
    expect(readOnly).toContain("image_control_admin_snapshot");
    // Mutations.
    expect(mutation).toContain("image_endpoint_create");
    expect(mutation).toContain("image_budget_set");
    expect(mutation).toContain("image_job_cancel");
    expect(mutation).toContain("image_late_result_publish");
  });

  it("requires session id for session-scoped tags only", () => {
    expect(requestTagRequiresSessionId("image_plan_get")).toBe(true);
    expect(requestTagRequiresSessionId("image_job_list")).toBe(true);
    expect(requestTagRequiresSessionId("image_job_cancel")).toBe(true);
    expect(requestTagRequiresSessionId("image_late_result_discard")).toBe(true);
    expect(requestTagRequiresSessionId("image_endpoint_list")).toBe(false);
    expect(requestTagRequiresSessionId("image_health_get")).toBe(false);
  });

  it("partitions snapshot components into admin vs session", () => {
    const admin: SnapshotComponent[] = [
      "endpoints",
      "targets",
      "workflows",
      "health",
      "budget",
      "destination_grants",
    ];
    const session: SnapshotComponent[] = ["plans", "jobs"];
    for (const c of admin) expect(snapshotComponentIsAdmin(c)).toBe(true);
    for (const c of admin) expect(snapshotComponentIsSession(c)).toBe(false);
    for (const c of session) expect(snapshotComponentIsSession(c)).toBe(true);
    for (const c of session) expect(snapshotComponentIsAdmin(c)).toBe(false);
  });
});
