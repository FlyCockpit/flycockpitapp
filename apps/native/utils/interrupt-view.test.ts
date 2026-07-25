import type { GrantKind, InterruptQuestion } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import { interruptView, resolveFromSelection } from "./interrupt-view";

const richApproval = {
  kind: "single",
  data: {
    prompt: "Run command?",
    options: [
      { id: "approve_once", label: "Approve once" },
      {
        id: "escalate_run_unconfined_once",
        label: "Run once without sandbox",
        description: "Run without the current sandbox restrictions.",
      },
    ],
    allow_freetext: true,
    permission: true,
    approval_class: "command",
    command_detail: {
      full_command: "npm run release",
      step: 1,
      step_count: 3,
      cwd: "/work/flycockpit",
      risk_tier: "mutating",
      risk_reasons: ["publishes artifacts", "uses credentials"],
      affected_targets: ["npm registry", "dist/"],
      native_tool_hints: ["Review package version first."],
      offered_scopes: ["once", "session"],
      policy_cap: "session",
      write_content: { content: "release notes", dynamic: true },
    },
    sandbox_escalation: {
      confined_exit: 1,
      confined_stderr: "permission denied",
      suggested_paths: ["/work/flycockpit/dist"],
      suggested_access: "write",
      denial: { confidence: "high", evidence: [{ kind: "path", data: "/work/flycockpit/dist" }] },
    },
  },
} satisfies InterruptQuestion;

describe("interrupt view mapping", () => {
  it("surfaces command risk, targets, scopes, and option groups for single approvals", () => {
    const view = interruptView(richApproval);

    expect(view.kind).toBe("single");
    if (view.kind !== "single") throw new Error("expected single view");
    expect(view.commandDetail).toMatchObject({
      fullCommand: "npm run release",
      cwd: "/work/flycockpit",
      stepLabel: "Step 1 of 3",
      risk: { label: "mutating", tone: "medium" },
      reasons: ["publishes artifacts", "uses credentials"],
      affectedTargets: ["npm registry", "dist/"],
      nativeToolHints: ["Review package version first."],
      offeredScopes: ["once", "session"],
      policyCap: "session",
      writeContent: { preview: "release notes", truncated: false, dynamic: true },
    });
    expect(view.commandDetail?.scopeOptions).toEqual([
      { id: "once", label: "Allow once", secondary: true },
      { id: "session", label: "Allow for this session", secondary: true },
    ]);
    expect(view.primaryOptions).toEqual([{ id: "approve_once", label: "Approve once" }]);
    expect(view.secondaryOptions).toEqual([
      {
        id: "escalate_run_unconfined_once",
        label: "Run once without sandbox",
        description: "Run without the current sandbox restrictions.",
      },
    ]);
  });

  it("suppresses freetext for permission singles only", () => {
    const permissionView = interruptView(richApproval);
    const questionView = interruptView({
      kind: "single",
      data: {
        prompt: "Pick or answer",
        options: [{ id: "one", label: "One" }],
        allow_freetext: true,
      },
    });

    expect(permissionView.kind).toBe("single");
    expect(questionView.kind).toBe("single");
    if (permissionView.kind !== "single" || questionView.kind !== "single") {
      throw new Error("expected single views");
    }
    expect(permissionView.freeText).toBe(false);
    expect(questionView.freeText).toBe(true);
  });

  it("keeps secondary options separated for multi prompts", () => {
    const view = interruptView({
      kind: "multi",
      data: {
        prompt: "Select targets",
        options: [
          { id: "src", label: "src" },
          { id: "tests", label: "tests", secondary: true },
        ],
      },
    });

    expect(view.kind).toBe("multi");
    if (view.kind !== "multi") throw new Error("expected multi view");
    expect(view.primaryOptions.map((option) => option.id)).toEqual(["src"]);
    expect(view.secondaryOptions.map((option) => option.id)).toEqual(["tests"]);
  });

  it("marks masked freetext for secure entry", () => {
    const view = interruptView({ kind: "freetext", data: { prompt: "Token", masked: true } });

    expect(view).toMatchObject({
      kind: "freetext",
      masked: true,
      secureTextEntry: true,
    });
  });

  it("resolves every native question selection variant", () => {
    expect(
      resolveFromSelection(richApproval, { kind: "single", selectedId: "approve_once" }),
    ).toEqual({
      kind: "single",
      data: { selected_id: "approve_once" },
    });
    expect(
      resolveFromSelection(
        {
          kind: "multi",
          data: {
            prompt: "Targets",
            options: [
              { id: "src", label: "src" },
              { id: "tests", label: "tests" },
            ],
          },
        },
        { kind: "multi", selectedIds: ["src", "tests"] },
      ),
    ).toEqual({ kind: "multi", data: { selected_ids: ["src", "tests"] } });
    expect(
      resolveFromSelection(
        { kind: "freetext", data: { prompt: "Reason" } },
        { kind: "freetext", text: "because" },
      ),
    ).toEqual({ kind: "freetext", data: { text: "because" } });
    expect(resolveFromSelection(richApproval, { kind: "cancel" })).toEqual({ kind: "cancel" });
  });

  it("renders sandbox escalation as an explicit non-primary opt-in", () => {
    const view = interruptView(richApproval);

    expect(view.kind).toBe("single");
    if (view.kind !== "single") throw new Error("expected single view");
    expect(view.sandboxEscalation).toMatchObject({
      confinedExit: 1,
      confinedStderrPreview: "permission denied",
      confinedStderrTruncated: false,
      suggestedPaths: ["/work/flycockpit/dist"],
      suggestedAccess: "write",
      denial: { confidence: "high", evidenceCount: 1 },
    });
    expect(view.escalationOptionIds).toEqual(["escalate_run_unconfined_once"]);
    expect(view.primaryOptions.map((option) => option.id)).not.toContain(
      "escalate_run_unconfined_once",
    );
  });

  it.each<GrantKind>([
    "command",
    "path",
    "mcp_tool",
  ])("displays approval class label for %s grants", (approvalClass) => {
    const view = interruptView({
      ...richApproval,
      data: { ...richApproval.data, approval_class: approvalClass },
    });

    expect(view.kind).toBe("single");
    if (view.kind !== "single") throw new Error("expected single view");
    expect(view.approvalClass).toBe(approvalClass);
    expect(view.approvalClassLabel).toBe(
      approvalClass === "mcp_tool"
        ? "MCP tool"
        : approvalClass.charAt(0).toUpperCase() + approvalClass.slice(1),
    );
  });

  it("uses neutral risk styling for unknown risk tiers", () => {
    const view = interruptView({
      ...richApproval,
      data: {
        ...richApproval.data,
        command_detail: { ...richApproval.data.command_detail, risk_tier: "future-tier" },
      },
    });

    expect(view.kind).toBe("single");
    if (view.kind !== "single") throw new Error("expected single view");
    expect(view.commandDetail?.risk).toEqual({
      tier: "future-tier",
      label: "future-tier",
      tone: "neutral",
    });
  });
});
