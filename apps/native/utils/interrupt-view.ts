import type {
  CommandDetail,
  GrantKind,
  InterruptOption,
  InterruptQuestion,
  ResolveResponse,
  SandboxEscalation,
} from "@flycockpit/cockpit-protocol";

export type RiskTone = "neutral" | "low" | "medium" | "high" | "critical";

export type InterruptSelection =
  | { kind: "single"; selectedId: string }
  | { kind: "multi"; selectedIds: string[] }
  | { kind: "freetext"; text: string }
  | { kind: "cancel" };

export type ScopeOptionView = {
  id: string;
  label: string;
  secondary: true;
};

export type CommandDetailView = {
  fullCommand: string;
  cwd?: string;
  stepLabel: string;
  risk: {
    tier: string | null;
    label: string;
    tone: RiskTone;
  };
  reasons: string[];
  affectedTargets: string[];
  nativeToolHints: string[];
  offeredScopes: string[];
  scopeOptions: ScopeOptionView[];
  policyCap?: string;
  writeContent?: {
    preview: string;
    truncated: boolean;
    dynamic: boolean;
  };
};

export type SandboxEscalationView = {
  confinedExit: number;
  confinedStderrPreview: string;
  confinedStderrTruncated: boolean;
  suggestedPaths: string[];
  suggestedAccess?: string;
  denial?: {
    confidence: string;
    evidenceCount: number;
  };
};

export type InterruptView =
  | {
      kind: "single";
      prompt: string;
      permission: boolean;
      freeText: boolean;
      primaryOptions: InterruptOption[];
      secondaryOptions: InterruptOption[];
      commandDetail?: CommandDetailView;
      approvalClass?: GrantKind;
      approvalClassLabel?: string;
      sandboxEscalation?: SandboxEscalationView;
      escalationOptionIds: string[];
    }
  | {
      kind: "multi";
      prompt: string;
      freeText: boolean;
      primaryOptions: InterruptOption[];
      secondaryOptions: InterruptOption[];
    }
  | {
      kind: "freetext";
      prompt: string;
      masked: boolean;
      secureTextEntry: boolean;
    };

const WRITE_CONTENT_PREVIEW_LIMIT = 600;
const STDERR_PREVIEW_LIMIT = 800;

export function interruptView(question: InterruptQuestion): InterruptView {
  if (question.kind === "freetext") {
    const masked = question.data.masked === true;
    return {
      kind: "freetext",
      prompt: question.data.prompt,
      masked,
      secureTextEntry: masked,
    };
  }

  const { primaryOptions, secondaryOptions } = splitOptions(question.data.options);

  if (question.kind === "multi") {
    return {
      kind: "multi",
      prompt: question.data.prompt,
      freeText: question.data.allow_freetext === true,
      primaryOptions,
      secondaryOptions,
    };
  }

  const permission = question.data.permission === true;
  const commandDetail = question.data.command_detail
    ? commandDetailView(question.data.command_detail)
    : undefined;
  const sandboxEscalation = question.data.sandbox_escalation
    ? sandboxEscalationView(question.data.sandbox_escalation)
    : undefined;
  const singleOptions = splitOptions(question.data.options, sandboxEscalation !== undefined);

  return {
    kind: "single",
    prompt: question.data.prompt,
    permission,
    freeText: !permission && question.data.allow_freetext === true,
    primaryOptions: singleOptions.primaryOptions,
    secondaryOptions: singleOptions.secondaryOptions,
    commandDetail,
    approvalClass: question.data.approval_class,
    approvalClassLabel: question.data.approval_class
      ? approvalClassLabel(question.data.approval_class)
      : undefined,
    sandboxEscalation,
    escalationOptionIds: sandboxEscalation
      ? singleOptions.secondaryOptions
          .filter((option) => option.id.startsWith("escalate_"))
          .map((option) => option.id)
      : [],
  };
}

export function resolveFromSelection(
  question: InterruptQuestion,
  selection: InterruptSelection,
): ResolveResponse {
  switch (selection.kind) {
    case "cancel":
      return { kind: "cancel" };
    case "single":
      if (question.kind !== "single") {
        throw new Error(`Cannot resolve ${question.kind} interrupt with single selection.`);
      }
      return { kind: "single", data: { selected_id: selection.selectedId } };
    case "multi":
      if (question.kind !== "multi") {
        throw new Error(`Cannot resolve ${question.kind} interrupt with multi selection.`);
      }
      return { kind: "multi", data: { selected_ids: selection.selectedIds } };
    case "freetext":
      if (question.kind === "single" && question.data.permission === true) {
        throw new Error("Permission interrupts do not accept freetext responses.");
      }
      if (question.kind !== "freetext" && question.data.allow_freetext !== true) {
        throw new Error(`Cannot resolve ${question.kind} interrupt with freetext.`);
      }
      return { kind: "freetext", data: { text: selection.text } };
  }
}

function splitOptions(options: InterruptOption[], sandboxEscalation = false) {
  const isSecondary = (option: InterruptOption) =>
    option.secondary === true || (sandboxEscalation && option.id.startsWith("escalate_"));
  const primaryOptions = options.filter((option) => !isSecondary(option));
  const secondaryOptions = options.filter(isSecondary);
  return { primaryOptions, secondaryOptions };
}

function commandDetailView(detail: CommandDetail): CommandDetailView {
  const writeContent = detail.write_content
    ? truncatePreview(detail.write_content.content, WRITE_CONTENT_PREVIEW_LIMIT)
    : undefined;
  const offeredScopes = detail.offered_scopes ?? [];

  return {
    fullCommand: detail.full_command,
    cwd: detail.cwd,
    stepLabel: `Step ${detail.step} of ${detail.step_count}`,
    risk: riskView(detail.risk_tier),
    reasons: detail.risk_reasons ?? [],
    affectedTargets: detail.affected_targets ?? [],
    nativeToolHints: detail.native_tool_hints ?? [],
    offeredScopes,
    scopeOptions: offeredScopes.map((scope) => ({
      id: scope,
      label: scopeLabel(scope),
      secondary: true,
    })),
    policyCap: detail.policy_cap,
    writeContent: writeContent
      ? {
          preview: writeContent.preview,
          truncated: writeContent.truncated,
          dynamic: detail.write_content?.dynamic === true,
        }
      : undefined,
  };
}

function sandboxEscalationView(escalation: SandboxEscalation): SandboxEscalationView {
  const stderr = truncatePreview(escalation.confined_stderr, STDERR_PREVIEW_LIMIT);
  return {
    confinedExit: escalation.confined_exit,
    confinedStderrPreview: stderr.preview,
    confinedStderrTruncated: stderr.truncated,
    suggestedPaths: escalation.suggested_paths ?? [],
    suggestedAccess: escalation.suggested_access,
    denial: escalation.denial
      ? {
          confidence: escalation.denial.confidence,
          evidenceCount: escalation.denial.evidence.length,
        }
      : undefined,
  };
}

function riskView(tier: string | undefined): CommandDetailView["risk"] {
  const normalized = tier?.trim().toLowerCase() ?? "";
  if (normalized === "ordinary" || normalized === "low") {
    return { tier: tier ?? null, label: tier ?? "unknown", tone: "low" };
  }
  if (normalized === "mutating" || normalized === "medium") {
    return { tier: tier ?? null, label: tier ?? "unknown", tone: "medium" };
  }
  if (normalized === "destructive" || normalized === "high") {
    return { tier: tier ?? null, label: tier ?? "unknown", tone: "high" };
  }
  if (normalized === "privileged" || normalized === "critical") {
    return { tier: tier ?? null, label: tier ?? "unknown", tone: "critical" as const };
  }
  return { tier: tier ?? null, label: tier ?? "unknown", tone: "neutral" as const };
}

function approvalClassLabel(kind: GrantKind) {
  if (kind === "mcp_tool") return "MCP tool";
  return kind.charAt(0).toUpperCase() + kind.slice(1);
}

function scopeLabel(scope: string) {
  const known: Record<string, string> = {
    once: "Allow once",
    session: "Allow for this session",
    project: "Allow for this project",
    workspace: "Allow for this workspace",
    global: "Allow globally",
  };
  return known[scope] ?? scope.replaceAll("_", " ").replaceAll("-", " ");
}

function truncatePreview(value: string, limit: number) {
  if (value.length <= limit) return { preview: value, truncated: false };
  return { preview: `${value.slice(0, limit)}...`, truncated: true };
}
