/**
 * Image-generation native budget and approval scope.
 *
 * USD 1/request, USD 10/session, and USD 100/project-month are editable
 * suggestions only; nothing is selected/persisted until explicit save, and
 * project window/timezone has no default.
 *
 * Approval scope is only per-session/per-project; global is absent. Yolo
 * shows `agent_discretion` activity and no modal.
 *
 * Project destination grants do not grant current session control.
 */

import {
  type ApprovalModeView,
  type ApprovalScope,
  type BudgetPolicy,
  type BudgetScopeProjection,
  type ImageControlRequestTag,
  isFinitePolicy,
  isValidBudgetAmount,
  unconfiguredBudgetScope,
} from "./image-generation-contracts";

// ---------------------------------------------------------------------------
// Budget scope
// ---------------------------------------------------------------------------

/** The three budget scopes. */
export type BudgetScope = "request" | "session" | "project";

/** A budget scope view with policy and editable suggestion. */
export interface BudgetScopeView {
  scope: BudgetScope;
  policy: BudgetPolicy;
  generation?: string;
  /** Editable suggestion only; not persisted until explicit save. */
  suggestionUsdMicros?: number;
  /** Project window/timezone has no default. */
  windowTimezone?: string;
}

/** The default editable suggestions: USD 1/request, USD 10/session, USD 100/project-month. */
export const DEFAULT_BUDGET_SUGGESTIONS: Readonly<Record<BudgetScope, number>> = {
  request: 1_000_000, // USD 1 in micros
  session: 10_000_000, // USD 10 in micros
  project: 100_000_000, // USD 100 in micros
};

/** Build the initial budget views with Unconfigured policy and editable suggestions. */
export function initialBudgetViews(): Record<BudgetScope, BudgetScopeView> {
  return {
    request: {
      scope: "request",
      policy: "unconfigured",
      suggestionUsdMicros: DEFAULT_BUDGET_SUGGESTIONS.request,
    },
    session: {
      scope: "session",
      policy: "unconfigured",
      suggestionUsdMicros: DEFAULT_BUDGET_SUGGESTIONS.session,
    },
    project: {
      scope: "project",
      policy: "unconfigured",
      suggestionUsdMicros: DEFAULT_BUDGET_SUGGESTIONS.project,
      windowTimezone: undefined,
    },
  };
}

/** Returns `true` if a budget scope is Unconfigured (blocks generation). */
export function isBudgetUnconfigured(view: BudgetScopeView): boolean {
  return view.policy === "unconfigured";
}

/** Returns `true` if all budget scopes are Unconfigured. */
export function isAllBudgetsUnconfigured(views: Record<BudgetScope, BudgetScopeView>): boolean {
  return (
    isBudgetUnconfigured(views.request) &&
    isBudgetUnconfigured(views.session) &&
    isBudgetUnconfigured(views.project)
  );
}

/** The result of validating a `image_budget_set` scope pair. */
export type BudgetSetValidation =
  | { valid: true }
  | {
      valid: false;
      errorCode:
        | "unconfigured_in_save"
        | "half_present_tuple"
        | "invalid_generation"
        | "invalid_amount";
    };

/** Validate a `image_budget_set` scope pair: `(policy, expected_generation)`. */
export function validateBudgetSetPair(
  policy: BudgetPolicy | null,
  expectedGeneration: string | null,
): BudgetSetValidation {
  if (policy === null && expectedGeneration === null) {
    return { valid: true }; // unchanged
  }
  if (policy === "unconfigured") {
    return { valid: false, errorCode: "unconfigured_in_save" };
  }
  if (policy === null) {
    // policy === null with nonnull generation: half-present tuple rejects.
    return { valid: false, errorCode: "half_present_tuple" };
  }
  // policy is "unlimited" or a Finite carrying its amount.
  if (isFinitePolicy(policy) && !isValidBudgetAmount(policy.finite.usd_micros)) {
    return { valid: false, errorCode: "invalid_amount" };
  }
  if (expectedGeneration === null) {
    return { valid: true }; // create generation 1
  }
  if (!validateCanonicalDecimal(expectedGeneration) || expectedGeneration === "0") {
    return { valid: false, errorCode: "invalid_generation" };
  }
  return { valid: true }; // CAS-update
}

/** Validate a canonical decimal string matching `0|[1-9][0-9]{0,19}`. */
export function validateCanonicalDecimal(s: string): boolean {
  if (s.length === 0 || s.length > 20) return false;
  if (s === "0") return true;
  if (s[0] === "0") return false;
  return /^[0-9]+$/.test(s);
}

/** Validate that at least one policy is nonnull in `image_budget_set`. */
export function validateAtLeastOnePolicy(
  request: BudgetPolicy | null,
  session: BudgetPolicy | null,
  project: BudgetPolicy | null,
): boolean {
  return request !== null || session !== null || project !== null;
}

/** The budget scope projection for a selected scope. */
export function budgetScopeProjection(view: BudgetScopeView): BudgetScopeProjection {
  if (view.policy === "unconfigured") return unconfiguredBudgetScope();
  return view.generation
    ? { policy: view.policy, generation: view.generation }
    : unconfiguredBudgetScope();
}

// ---------------------------------------------------------------------------
// Approval scope
// ---------------------------------------------------------------------------

/** Returns `true` if an approval scope is per-session. */
export function isSessionApprovalScope(scope: ApprovalScope): boolean {
  return scope === "session";
}

/** Returns `true` if an approval scope is per-project. */
export function isProjectApprovalScope(scope: ApprovalScope): boolean {
  return scope === "project";
}

/** Returns `true` if global scope is offered (it never is). */
export function isGlobalApprovalScopeOffered(): boolean {
  return false;
}

/** The approval mode view for a given yolo flag. */
export function approvalModeView(yolo: boolean): ApprovalModeView {
  if (yolo) {
    return { yolo: true, activity: "agent_discretion" };
  }
  return { yolo: false };
}

/** Returns `true` if yolo mode shows `agent_discretion` activity and no modal. */
export function yoloShowsNoModal(view: ApprovalModeView): boolean {
  return view.yolo === true;
}

// ---------------------------------------------------------------------------
// Destination grants
// ---------------------------------------------------------------------------

/** Returns `true` if project destination grants grant current session control (they do not). */
export function destinationGrantsGrantSessionControl(): boolean {
  return false;
}

/** The request tags that destination grants affect. */
export const DESTINATION_GRANT_REQUEST_TAGS: readonly ImageControlRequestTag[] = [
  "image_destination_grant_list",
  "image_destination_grant_revoke",
];

// ---------------------------------------------------------------------------
// Plan review gating
// ---------------------------------------------------------------------------

/** Returns `true` if plan review should block when budget is Unconfigured. */
export function planReviewBlocksOnUnconfiguredBudget(
  views: Record<BudgetScope, BudgetScopeView>,
): boolean {
  return isAllBudgetsUnconfigured(views);
}

/** Returns `true` if a plan review should be offered for the scope. */
export function planReviewOfferedForScope(scope: ApprovalScope): boolean {
  return scope === "session" || scope === "project";
}
