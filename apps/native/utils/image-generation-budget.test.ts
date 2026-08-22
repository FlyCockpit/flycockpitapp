import { describe, expect, it } from "vitest";
import {
  approvalModeView,
  type BudgetScope,
  BudgetScopeView,
  budgetScopeProjection,
  DEFAULT_BUDGET_SUGGESTIONS,
  destinationGrantsGrantSessionControl,
  initialBudgetViews,
  isAllBudgetsUnconfigured,
  isBudgetUnconfigured,
  isGlobalApprovalScopeOffered,
  planReviewBlocksOnUnconfiguredBudget,
  planReviewOfferedForScope,
  validateAtLeastOnePolicy,
  validateBudgetSetPair,
  validateCanonicalDecimal,
  yoloShowsNoModal,
} from "./image-generation-budget";
import {
  finiteBudgetPolicy,
  isFinitePolicy,
  unconfiguredBudgetScope,
} from "./image-generation-contracts";

describe("image generation budget and approval", () => {
  it("initial budget views are Unconfigured with editable suggestions only", () => {
    const views = initialBudgetViews();
    expect(isBudgetUnconfigured(views.request)).toBe(true);
    expect(isBudgetUnconfigured(views.session)).toBe(true);
    expect(isBudgetUnconfigured(views.project)).toBe(true);
    expect(isAllBudgetsUnconfigured(views)).toBe(true);
    // USD 1/request, USD 10/session, USD 100/project-month.
    expect(views.request.suggestionUsdMicros).toBe(DEFAULT_BUDGET_SUGGESTIONS.request);
    expect(views.session.suggestionUsdMicros).toBe(DEFAULT_BUDGET_SUGGESTIONS.session);
    expect(views.project.suggestionUsdMicros).toBe(DEFAULT_BUDGET_SUGGESTIONS.project);
    // Project window/timezone has no default.
    expect(views.project.windowTimezone).toBeUndefined();
  });

  it("suggestions are not persisted until explicit save (Unconfigured blocks)", () => {
    const views = initialBudgetViews();
    // Even with a suggestion, the policy is Unconfigured.
    expect(views.request.policy).toBe("unconfigured");
    expect(planReviewBlocksOnUnconfiguredBudget(views)).toBe(true);
  });

  it("validateBudgetSetPair: (null,null) unchanged, Unconfigured in save rejects", () => {
    expect(validateBudgetSetPair(null, null).valid).toBe(true);
    expect(validateBudgetSetPair("unconfigured", null).valid).toBe(false);
    expect(validateBudgetSetPair("unconfigured", "1").valid).toBe(false);
  });

  it("validateBudgetSetPair: nonnull policy with null generation creates generation 1", () => {
    expect(validateBudgetSetPair(finiteBudgetPolicy(1_000_000n), null).valid).toBe(true);
    expect(validateBudgetSetPair("unlimited", null).valid).toBe(true);
  });

  it("validateBudgetSetPair: nonnull policy with positive generation CAS-updates", () => {
    expect(validateBudgetSetPair(finiteBudgetPolicy(1_000_000n), "1").valid).toBe(true);
    expect(validateBudgetSetPair("unlimited", "10").valid).toBe(true);
    expect(validateBudgetSetPair(finiteBudgetPolicy(1_000_000n), "0").valid).toBe(false);
    expect(validateBudgetSetPair(finiteBudgetPolicy(1_000_000n), "invalid").valid).toBe(false);
  });

  it("validateBudgetSetPair: Finite with a zero amount rejects", () => {
    // Mirrors the Rust deserializer rejecting `usd_micros: 0`.
    const result = validateBudgetSetPair(finiteBudgetPolicy(0n), null);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.errorCode).toBe("invalid_amount");
  });

  it("validateBudgetSetPair: half-present tuple rejects", () => {
    expect(validateBudgetSetPair(null, "1").valid).toBe(false);
  });

  it("validateCanonicalDecimal matches 0|[1-9][0-9]{0,19}", () => {
    expect(validateCanonicalDecimal("0")).toBe(true);
    expect(validateCanonicalDecimal("1")).toBe(true);
    expect(validateCanonicalDecimal("123")).toBe(true);
    expect(validateCanonicalDecimal("01")).toBe(false);
    expect(validateCanonicalDecimal("")).toBe(false);
    expect(validateCanonicalDecimal("1a")).toBe(false);
  });

  it("validateAtLeastOnePolicy requires at least one nonnull policy", () => {
    expect(validateAtLeastOnePolicy(finiteBudgetPolicy(1_000_000n), null, null)).toBe(true);
    expect(validateAtLeastOnePolicy(null, "unlimited", null)).toBe(true);
    expect(validateAtLeastOnePolicy(null, null, null)).toBe(false);
  });

  it("budgetScopeProjection: Unconfigured -> (Unconfigured,null)", () => {
    const view: BudgetScopeView = { scope: "request", policy: "unconfigured" };
    const projection = budgetScopeProjection(view);
    expect(projection.policy).toBe("unconfigured");
    expect(projection.generation).toBeUndefined();
    expect(unconfiguredBudgetScope().policy).toBe("unconfigured");
  });

  it("budgetScopeProjection: Finite -> (Finite,positive-generation)", () => {
    const view: BudgetScopeView = {
      scope: "request",
      policy: finiteBudgetPolicy(1_000_000n),
      generation: "1",
    };
    const projection = budgetScopeProjection(view);
    expect(isFinitePolicy(projection.policy)).toBe(true);
    if (isFinitePolicy(projection.policy)) {
      expect(projection.policy.finite.usd_micros).toBe(1_000_000n);
    }
    expect(projection.generation).toBe("1");
  });

  it("approval scope is only per-session/per-project; global is absent", () => {
    expect(isGlobalApprovalScopeOffered()).toBe(false);
    expect(planReviewOfferedForScope("session")).toBe(true);
    expect(planReviewOfferedForScope("project")).toBe(true);
  });

  it("yolo shows agent_discretion activity and no modal", () => {
    const yolo = approvalModeView(true);
    expect(yolo.yolo).toBe(true);
    if (yolo.yolo) expect(yolo.activity).toBe("agent_discretion");
    expect(yoloShowsNoModal(yolo)).toBe(true);

    const explicit = approvalModeView(false);
    expect(explicit.yolo).toBe(false);
    expect(yoloShowsNoModal(explicit)).toBe(false);
  });

  it("project destination grants do not grant current session control", () => {
    expect(destinationGrantsGrantSessionControl()).toBe(false);
  });

  it("budget scopes are request/session/project only", () => {
    const scopes: BudgetScope[] = ["request", "session", "project"];
    expect(scopes).toHaveLength(3);
    expect(scopes).not.toContain("global");
  });
});
