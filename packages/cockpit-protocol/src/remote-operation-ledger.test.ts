import { describe, expect, it } from "vitest";
import fixture from "../fixtures/remote-operation-classification-v1.json" with { type: "json" };

describe("remote operation classification fixture", () => {
  it("is unique, total, and locks reviewed recovery evidence", () => {
    expect(fixture.schemaVersion).toBe(1);
    expect(fixture.rows.length).toBeGreaterThan(100);
    expect(new Set(fixture.rows.map((row) => row.tag)).size).toBe(fixture.rows.length);
    expect(fixture.rows.every((row) => typeof row.fcorSchema === "string")).toBe(true);
    expect(fixture.rows.every((row) => typeof row.fcorCanonicalSchema === "string")).toBe(true);
    const byTag = new Map(fixture.rows.map((row) => [row.tag, row]));
    for (const tag of [
      "cancel_run_invocation",
      "create_goal",
      "mark_app_flag_seen",
      "resolve_assistant_session",
    ]) {
      expect(byTag.get(tag)).toMatchObject({
        class: "transactional_mutation",
        strategy: "sql_transaction",
        evidence: null,
      });
    }
    expect(byTag.get("write_bulk_transfer_chunk")).toMatchObject({
      class: "nonrepeatable_mutation",
      strategy: "nonrepeatable_dispatch",
      evidence: null,
    });
    expect(byTag.get("set_default_model")).toMatchObject({
      class: "idempotent_adapter_mutation",
      strategy: "staged_filesystem_commit",
      evidence: "staged_artifact_fingerprints_and_fsync_barriers",
    });
    expect(byTag.get("set_workspace_trust")).toMatchObject({
      class: "idempotent_adapter_mutation",
      strategy: "durable_desired_state",
      evidence: "desired_state_generation_and_observed_digest",
    });
    expect(byTag.get("mark_app_flag_seen")?.fcorSchema).toBe("key:AppFlagKey|expected_version:u64");
    expect(byTag.get("fs_rename")?.fcorSchema).toBe(
      "project_root:String|from_path:String|to_path:String",
    );
    expect(byTag.get("refresh_env")?.fcorCanonicalSchema).toBe("vars:map<string,string>");
    expect(byTag.get("unknown")).toMatchObject({
      class: "rejected",
      strategy: "rejected_before_dispatch",
    });
  });
});
