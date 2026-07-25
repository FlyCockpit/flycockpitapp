import type { GrantKind, InterruptQuestion } from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import {
  interruptView,
  maskedDisplayValue,
  resolveFromSelection,
  riskVariant,
} from "./interrupt-view";

const richApproval = {
  kind: "single",
  data: {
    prompt: "Run command?",
    options: [
      { id: "approve_once", label: "Approve once" },
      { id: "escalate_grant_session", label: "Grant paths for this session" },
      { id: "escalate_grant_project", label: "Grant paths for this project" },
      { id: "reject", label: "Deny" },
      { id: "escalate_run_unconfined_once", label: "Run once without sandbox" },
    ],
    allow_freetext: true,
    permission: true,
    approval_class: "command",
    command_detail: {
      full_command: "pnpm publish",
      step: 1,
      step_count: 2,
      cwd: "/work/flycockpit",
      risk_tier: "mutating",
      risk_reasons: ["publishes artifacts"],
      affected_targets: ["registry"],
      native_tool_hints: ["Confirm package name."],
      offered_scopes: ["session", "project"],
      policy_cap: "project",
      write_content: { content: "release notes", dynamic: true },
    },
    sandbox_escalation: {
      confined_exit: 13,
      confined_stderr: "permission denied",
      suggested_paths: ["/work/flycockpit/dist"],
      suggested_access: "write",
      denial: { confidence: "high", evidence: [{ kind: "stderr_permission_marker" }] },
    },
  },
} satisfies InterruptQuestion;

describe("web interrupt view", () => {
  it("dispatches every question kind into a view model", () => {
    expect(interruptView(richApproval).kind).toBe("single");
    expect(
      interruptView({
        kind: "multi",
        data: { prompt: "Pick files", options: [{ id: "src", label: "src" }] },
      }).kind,
    ).toBe("multi");
    expect(interruptView({ kind: "freetext", data: { prompt: "Secret", masked: true } })).toEqual(
      expect.objectContaining({ kind: "freetext", inputType: "password", masked: true }),
    );
  });

  it("exposes risk, command detail, approval class, scope choices, and option groups", () => {
    const view = interruptView(richApproval);

    expect(view.kind).toBe("single");
    if (view.kind !== "single") throw new Error("expected single view");
    expect(view.frame).toBe("approval");
    expect(view.commandDetail).toMatchObject({
      fullCommand: "pnpm publish",
      cwd: "/work/flycockpit",
      stepLabel: "Step 1 of 2",
      risk: { label: "mutating", variant: "medium" },
      reasons: ["publishes artifacts"],
      affectedTargets: ["registry"],
      nativeToolHints: ["Confirm package name."],
      offeredScopes: ["session", "project"],
      policyCap: "project",
      writeContent: { preview: "release notes", truncated: false, dynamic: true },
    });
    expect(view.approvalClassLabelKey).toBe("remote.interruptClassCommand");
    expect(view.primaryOptions.map((option) => option.id)).toEqual(["approve_once", "reject"]);
    expect(view.secondaryOptions.map((option) => option.id)).toEqual([
      "escalate_run_unconfined_once",
    ]);
  });

  it("surfaces only daemon-offered grant scope option ids", () => {
    const view = interruptView(richApproval);

    expect(view.kind).toBe("single");
    if (view.kind !== "single") throw new Error("expected single view");
    expect(view.commandDetail?.scopeChoices).toEqual([
      {
        scope: "session",
        optionId: "escalate_grant_session",
        labelKey: "remote.interruptScopeSession",
      },
      {
        scope: "project",
        optionId: "escalate_grant_project",
        labelKey: "remote.interruptScopeProject",
      },
    ]);
  });

  it.each<GrantKind>([
    "command",
    "path",
    "mcp_tool",
  ])("labels %s approval classes", (approvalClass) => {
    const view = interruptView({
      ...richApproval,
      data: { ...richApproval.data, approval_class: approvalClass },
    });

    expect(view.kind).toBe("single");
    if (view.kind !== "single") throw new Error("expected single view");
    expect(view.approvalClassLabelKey).toBe(
      approvalClass === "mcp_tool"
        ? "remote.interruptClassMcpTool"
        : `remote.interruptClass${approvalClass.charAt(0).toUpperCase()}${approvalClass.slice(1)}`,
    );
  });

  it.each([
    ["ordinary", "low"],
    ["mutating", "medium"],
    ["destructive", "high"],
    ["privileged", "critical"],
    ["future", "neutral"],
  ] as const)("maps risk tier %s to %s", (tier, variant) => {
    expect(riskVariant(tier)).toBe(variant);
  });

  it("exposes sandbox escalation context and resolves to a daemon option id", () => {
    const view = interruptView(richApproval);

    expect(view.kind).toBe("single");
    if (view.kind !== "single") throw new Error("expected single view");
    expect(view.sandboxEscalation).toMatchObject({
      confinedExit: 13,
      confinedStderrPreview: "permission denied",
      suggestedPaths: ["/work/flycockpit/dist"],
      suggestedAccess: "write",
      denial: { confidence: "high", evidenceCount: 1 },
    });
    expect(view.escalationOptionIds).toEqual(["escalate_run_unconfined_once"]);
    expect(
      resolveFromSelection(richApproval, {
        kind: "single",
        selectedId: view.escalationOptionIds[0],
      }),
    ).toEqual({ kind: "single", data: { selected_id: "escalate_run_unconfined_once" } });
  });

  it("separates permission approvals from questions and suppresses approval freetext", () => {
    const approvalView = interruptView(richApproval);
    const questionView = interruptView({
      kind: "single",
      data: {
        prompt: "Choose or answer",
        options: [{ id: "one", label: "One" }],
        allow_freetext: true,
      },
    });

    expect(approvalView.kind).toBe("single");
    expect(questionView.kind).toBe("single");
    if (approvalView.kind !== "single" || questionView.kind !== "single") {
      throw new Error("expected single views");
    }
    expect(approvalView.frame).toBe("approval");
    expect(approvalView.freeText).toBe(false);
    expect(questionView.frame).toBe("question");
    expect(questionView.freeText).toBe(true);
  });

  it("removes resolve affordances for read-only viewers", () => {
    const view = interruptView(richApproval, { readOnly: true });

    expect(view).toMatchObject({ readOnly: true, canResolve: false });
  });

  it("builds the correct ResolveResponse per interaction", () => {
    expect(
      resolveFromSelection(richApproval, { kind: "single", selectedId: "approve_once" }),
    ).toEqual({
      kind: "single",
      data: { selected_id: "approve_once" },
    });
    expect(
      resolveFromSelection(
        { kind: "multi", data: { prompt: "Pick", options: [{ id: "src", label: "src" }] } },
        { kind: "multi", selectedIds: ["src"] },
      ),
    ).toEqual({ kind: "multi", data: { selected_ids: ["src"] } });
    expect(
      resolveFromSelection(
        { kind: "freetext", data: { prompt: "Token", masked: true } },
        { kind: "freetext", text: "secret-token" },
      ),
    ).toEqual({ kind: "freetext", data: { text: "secret-token" } });
    expect(maskedDisplayValue("secret-token", true)).toBe("************");
    expect(resolveFromSelection(richApproval, { kind: "cancel" })).toEqual({ kind: "cancel" });
  });
});
