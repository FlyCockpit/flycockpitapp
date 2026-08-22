/**
 * Image-generation control-plane V1 contracts for the native remote UI.
 *
 * These TypeScript types mirror the redacted, transport-free V1 surface
 * owned by `crates/cockpit-core/src/image_generation_control_plane`. The
 * native app consumes only the safe projection: credentials/headers, raw
 * workflow bytes, signed query strings, quarantine handles, and unauthorized
 * host paths never enter these types, state, logs, or UI.
 *
 * The module is UI-free and transport-free. It does not register, redefine,
 * re-encode, or independently hash any foundation-owned capability or
 * permission-ceiling byte; the ordinal constants are imported as documented
 * values only for stable error mapping.
 */

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/** Schema version for all image-generation control-plane V1 structures. */
export const CONTROL_PLANE_SCHEMA_VERSION = 1 as const;

/** The foundation-owned ordinal for `image_generation_admin`. */
export const IMAGE_GENERATION_ADMIN_ORDINAL = 15 as const;

/** The hosted access-grant scope string for image-generation admin authority. */
export const IMAGE_GENERATION_ADMIN_SCOPE_STRING = "image_generation_admin";

/** Maximum number of items returned by a list/page request. */
export const MAX_LIST_LIMIT = 100;

/** Default list/page limit. */
export const DEFAULT_LIST_LIMIT = 50;

/** Maximum cursor size in bytes (opaque base64url). */
export const MAX_CURSOR_BYTES = 512;

/** Maximum number of changes in a config change set. */
export const MAX_CONFIG_CHANGES = 100;

// ---------------------------------------------------------------------------
// Principal scope
// ---------------------------------------------------------------------------

/**
 * The unified principal grant scope. Mirrors the Rust
 * `PrincipalScope` / `RelayGrantScope` enums (the parallel `HostedAccessScope`
 * island was deleted): `image_generation_admin` requires a nonnull canonical
 * project root and confers no terminal/agent/project-file authority.
 */
export type PrincipalScope =
  | "terminal"
  | "agent"
  | "agent_readonly"
  | "project_files"
  | "image_generation_admin";

export const PRINCIPAL_SCOPE_STRINGS: readonly PrincipalScope[] = [
  "terminal",
  "agent",
  "agent_readonly",
  "project_files",
  "image_generation_admin",
];

/** Returns `true` if this scope requires a nonnull project root. */
export function scopeRequiresProjectRoot(scope: PrincipalScope): boolean {
  return scope === "image_generation_admin";
}

// ---------------------------------------------------------------------------
// Operation kind
// ---------------------------------------------------------------------------

/** The closed operation-kind enum. */
export type ImageOperationKindV1 = "remote_attachment" | "local_owner";

export const IMAGE_OPERATION_KINDS: readonly ImageOperationKindV1[] = [
  "remote_attachment",
  "local_owner",
];

// ---------------------------------------------------------------------------
// Request tags
// ---------------------------------------------------------------------------

/** The exact request tags for the image-generation control plane V1. */
export type ImageControlRequestTag =
  // Safe configuration reads
  | "image_endpoint_list"
  | "image_endpoint_get"
  | "image_target_list"
  | "image_target_get"
  | "image_workflow_list"
  | "image_workflow_get"
  | "image_budget_get"
  | "image_destination_grant_list"
  // Runtime/job reads
  | "image_health_get"
  | "image_plan_get"
  | "image_job_list"
  | "image_job_get"
  | "image_operation_status"
  | "image_control_admin_snapshot"
  | "image_control_session_snapshot"
  // Configuration mutations
  | "image_endpoint_create"
  | "image_endpoint_update"
  | "image_endpoint_delete"
  | "image_target_create"
  | "image_target_update"
  | "image_target_delete"
  | "image_target_set_default"
  | "image_workflow_upload"
  | "image_workflow_bind"
  | "image_workflow_delete"
  // Policy/runtime mutations
  | "image_health_refresh"
  | "image_budget_set"
  | "image_destination_grant_revoke"
  | "image_job_cancel"
  | "image_late_result_publish"
  | "image_late_result_discard";

export const IMAGE_CONTROL_REQUEST_TAGS: readonly ImageControlRequestTag[] = [
  "image_endpoint_list",
  "image_endpoint_get",
  "image_target_list",
  "image_target_get",
  "image_workflow_list",
  "image_workflow_get",
  "image_budget_get",
  "image_destination_grant_list",
  "image_health_get",
  "image_plan_get",
  "image_job_list",
  "image_job_get",
  "image_operation_status",
  "image_control_admin_snapshot",
  "image_control_session_snapshot",
  "image_endpoint_create",
  "image_endpoint_update",
  "image_endpoint_delete",
  "image_target_create",
  "image_target_update",
  "image_target_delete",
  "image_target_set_default",
  "image_workflow_upload",
  "image_workflow_bind",
  "image_workflow_delete",
  "image_health_refresh",
  "image_budget_set",
  "image_destination_grant_revoke",
  "image_job_cancel",
  "image_late_result_publish",
  "image_late_result_discard",
];

/** Request classification for the operation ledger. */
export type RequestClassification = "read_only" | "transactional_mutation";

/** Returns the classification for a request tag. */
export function requestTagClassification(tag: ImageControlRequestTag): RequestClassification {
  switch (tag) {
    case "image_endpoint_list":
    case "image_endpoint_get":
    case "image_target_list":
    case "image_target_get":
    case "image_workflow_list":
    case "image_workflow_get":
    case "image_budget_get":
    case "image_destination_grant_list":
    case "image_health_get":
    case "image_plan_get":
    case "image_job_list":
    case "image_job_get":
    case "image_operation_status":
    case "image_control_admin_snapshot":
    case "image_control_session_snapshot":
      return "read_only";
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
    case "image_health_refresh":
    case "image_budget_set":
    case "image_destination_grant_revoke":
    case "image_job_cancel":
    case "image_late_result_publish":
    case "image_late_result_discard":
      return "transactional_mutation";
  }
}

/** Returns `true` if this tag requires `sessionId` in the command body. */
export function requestTagRequiresSessionId(tag: ImageControlRequestTag): boolean {
  return (
    tag === "image_budget_get" ||
    tag === "image_plan_get" ||
    tag === "image_job_list" ||
    tag === "image_job_get" ||
    tag === "image_control_session_snapshot" ||
    tag === "image_budget_set" ||
    tag === "image_job_cancel" ||
    tag === "image_late_result_publish" ||
    tag === "image_late_result_discard"
  );
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/** The closed error-code enum for `ImageControlErrorV1`. */
export type ImageControlErrorCode =
  | "malformed"
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "version_conflict"
  | "idempotency_conflict"
  | "cursor_stale"
  | "invalid_state"
  | "local_path_reauthorization_required"
  | "budget_unconfigured"
  | "capability_unavailable"
  | "authority_unavailable"
  | "lease_expired"
  | "operation_indeterminate"
  | "capacity"
  | "internal";

export const IMAGE_CONTROL_ERROR_CODES: readonly ImageControlErrorCode[] = [
  "malformed",
  "unauthenticated",
  "forbidden",
  "not_found",
  "version_conflict",
  "idempotency_conflict",
  "cursor_stale",
  "invalid_state",
  "local_path_reauthorization_required",
  "budget_unconfigured",
  "capability_unavailable",
  "authority_unavailable",
  "lease_expired",
  "operation_indeterminate",
  "capacity",
  "internal",
];

/** Only `authority_unavailable|capacity|internal` may be retryable before commit. */
export function isRetryableBeforeCommit(code: ImageControlErrorCode): boolean {
  return code === "authority_unavailable" || code === "capacity" || code === "internal";
}

/** `ImageControlErrorV1`. */
export interface ImageControlErrorV1 {
  schemaVersion: number;
  code: ImageControlErrorCode;
  retryable: boolean;
  operationId?: string;
  currentEntityGeneration?: string;
  currentConfigGeneration?: string;
}

// ---------------------------------------------------------------------------
// Entity kind
// ---------------------------------------------------------------------------

/** The closed entity-kind enum for `entityRefs`. */
export type ImageEntityKind =
  | "endpoint"
  | "target"
  | "workflow"
  | "budget"
  | "destination_grant"
  | "plan"
  | "job"
  | "slot"
  | "artifact";

/** Mutation outcome. */
export type MutationOutcome = "committed";

/** One entity ref in a mutation result. */
export interface EntityRef {
  kind: ImageEntityKind;
  id: string;
  generation: string;
}

/** `ImageMutationResultV1`. */
export interface ImageMutationResultV1 {
  operationId: string;
  outcome: MutationOutcome;
  entityRefs: EntityRef[];
  configGeneration?: string;
}

// ---------------------------------------------------------------------------
// Operation status
// ---------------------------------------------------------------------------

export type OperationState = "reserved" | "committed" | "rejected" | "outcome_unknown";

export type OperationOutcome =
  | { kind: "committed"; result: ImageMutationResultV1 }
  | { kind: "rejected"; error: ImageControlErrorV1 };

/** `ImageOperationStatusV1`. */
export interface ImageOperationStatusV1 {
  operationKind: ImageOperationKindV1;
  queriedOperationId: string;
  state: OperationState;
  outcome?: OperationOutcome;
}

// ---------------------------------------------------------------------------
// Snapshot component
// ---------------------------------------------------------------------------

/** Admin/session snapshot component. */
export type SnapshotComponent =
  | "endpoints"
  | "targets"
  | "workflows"
  | "health"
  | "budget"
  | "destination_grants"
  | "plans"
  | "jobs";

/** Returns `true` if this is an admin snapshot component. */
export function snapshotComponentIsAdmin(component: SnapshotComponent): boolean {
  return (
    component === "endpoints" ||
    component === "targets" ||
    component === "workflows" ||
    component === "health" ||
    component === "budget" ||
    component === "destination_grants"
  );
}

/** Returns `true` if this is a session snapshot component. */
export function snapshotComponentIsSession(component: SnapshotComponent): boolean {
  return component === "plans" || component === "jobs";
}

// ---------------------------------------------------------------------------
// Control result
// ---------------------------------------------------------------------------

export type ControlResult =
  | { type: "page"; items: unknown[]; nextCursor?: string; snapshotGeneration: string }
  | { type: "entity"; item: unknown }
  | { type: "health"; items: unknown[]; refreshEpoch: string; configGeneration: string }
  | { type: "budget"; item: unknown }
  | { type: "plan"; item: unknown }
  | { type: "job"; item: unknown }
  | { type: "operation"; item: ImageOperationStatusV1 }
  | {
      type: "snapshot";
      component: SnapshotComponent;
      items: unknown[];
      nextCursor?: string;
      snapshotGeneration: string;
      eventHighWater: string;
    }
  | { type: "mutation"; item: ImageMutationResultV1 };

/** `ImageControlResponseV1`. */
export interface ImageControlResponseV1 {
  schemaVersion: number;
  kind: ImageControlRequestTag;
  daemonInstanceId: string;
  projectId: string;
  result: ControlResult;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/** Event entity kind. */
export type EventEntityKind =
  | "project"
  | "target"
  | "budget"
  | "destination_grant"
  | "plan"
  | "job"
  | "slot"
  | "artifact"
  | "operation";

/** Event kind. */
export type EventKind =
  | "config_changed"
  | "health_changed"
  | "budget_changed"
  | "destination_grant_changed"
  | "plan_changed"
  | "job_changed"
  | "slot_changed"
  | "late_result_changed"
  | "operation_changed";

/** `ImageControlEventV1`. The native reducer consumes only this safe projection. */
export interface ImageControlEventV1 {
  schemaVersion: number;
  deliveryId: string;
  eventSeq: string;
  daemonInstanceId: string;
  projectId: string;
  sessionId?: string;
  entityKind: EventEntityKind;
  entityId: string;
  entityGeneration: string;
  kind: EventKind;
  safeProjection: unknown;
}

// ---------------------------------------------------------------------------
// Reply outcome
// ---------------------------------------------------------------------------

export type ReplyOutcome =
  | { kind: "ok"; response: ImageControlResponseV1 }
  | { kind: "error"; error: ImageControlErrorV1 };

// ---------------------------------------------------------------------------
// Budget policy
// ---------------------------------------------------------------------------

/** The largest representable `u64` (spend-ledger `usd_micros` upper bound). */
export const MAX_U64_USD_MICROS = 18446744073709551615n;

/**
 * The non-lossy budget policy DTO, mirroring the Rust spend-ledger
 * `BudgetPolicy` exactly: `Unconfigured` blocks generation, `Unlimited` allows
 * it, and `Finite` allows it while carrying its explicit `usd_micros` amount.
 * The wire form is serde external tagging — `"unconfigured"`, `"unlimited"`,
 * and `{ "finite": { "usd_micros": <integer> } }` — so a `Finite` never
 * appears without an amount.
 *
 * `usd_micros` is a `bigint`, never a `number`: the `u64` wire value can reach
 * `u64::MAX`, which exceeds `Number.MAX_SAFE_INTEGER`, so a `number` would
 * truncate large amounts.
 */
export type BudgetPolicy = "unconfigured" | "unlimited" | { finite: { usd_micros: bigint } };

/** Narrow a {@link BudgetPolicy} to its `Finite` case. */
export function isFinitePolicy(policy: BudgetPolicy): policy is { finite: { usd_micros: bigint } } {
  return typeof policy === "object" && policy !== null && "finite" in policy;
}

/** Construct a `Finite` budget policy from a positive `u64` micros amount. */
export function finiteBudgetPolicy(usdMicros: bigint): { finite: { usd_micros: bigint } } {
  return { finite: { usd_micros: usdMicros } };
}

/** Whether a `Finite` amount is a positive `u64` (`1..=u64::MAX`), mirroring
 *  the Rust `BudgetPolicy` deserializer that rejects `usd_micros: 0`. */
export function isValidBudgetAmount(usdMicros: bigint): boolean {
  return usdMicros >= 1n && usdMicros <= MAX_U64_USD_MICROS;
}

/** The budget scope projection: `(Unconfigured,null)` or `(Finite|Unlimited,positive-generation)`. */
export interface BudgetScopeProjection {
  policy: BudgetPolicy;
  generation?: string;
}

/** Construct an `Unconfigured` projection. */
export function unconfiguredBudgetScope(): BudgetScopeProjection {
  return { policy: "unconfigured", generation: undefined };
}

/** Construct a `Finite` projection carrying its `usd_micros` amount. */
export function finiteBudgetScope(usdMicros: bigint, generation: string): BudgetScopeProjection {
  return { policy: finiteBudgetPolicy(usdMicros), generation };
}

/** Construct an `Unlimited` projection. */
export function unlimitedBudgetScope(generation: string): BudgetScopeProjection {
  return { policy: "unlimited", generation };
}

// ---------------------------------------------------------------------------
// Late result disposition
// ---------------------------------------------------------------------------

/** The explicit late-result disposition. */
export type LateResultDisposition = "publish" | "discard";

// ---------------------------------------------------------------------------
// Artifact state (dependency-owned DB enum mirrors)
// ---------------------------------------------------------------------------

/** The artifact lifecycle state. Late-quarantined results are not previewed. */
export type ImageGenerationArtifactState =
  | "allocating"
  | "writing"
  | "retained"
  | "late_quarantined"
  | "cleanup_pending"
  | "deleting"
  | "tombstoned"
  | "security_blocked";

/** The artifact component lifecycle state. */
export type ImageGenerationArtifactComponentState =
  | "planned"
  | "writing"
  | "ready"
  | "cleanup_pending"
  | "deleting"
  | "tombstoned"
  | "security_blocked";

/** The late-publication lifecycle state. */
export type ImageGenerationLatePublicationState =
  | "reserved"
  | "copy_authorized"
  | "copy_committed"
  | "published"
  | "aborted"
  | "expired"
  | "security_blocked"
  | "delete_authorized";

/** Terminal states: the artifact will not transition further from the client's view. */
export const TERMINAL_ARTIFACT_STATES: readonly ImageGenerationArtifactState[] = [
  "tombstoned",
  "security_blocked",
];

/** Quarantined late-result state: not previewed, requires explicit publish/discard. */
export function isLateQuarantined(state: ImageGenerationArtifactState): boolean {
  return state === "late_quarantined";
}

/** Returns `true` if the artifact state is terminal. */
export function isTerminalArtifactState(state: ImageGenerationArtifactState): boolean {
  return TERMINAL_ARTIFACT_STATES.includes(state);
}

// ---------------------------------------------------------------------------
// Job/slot canonical state
// ---------------------------------------------------------------------------

/** Canonical job state derived from daemon events. `Cancellation requested` is client-acknowledged only. */
export type ImageGenerationJobState =
  | "pending"
  | "running"
  | "cancel_requested"
  | "cancelled"
  | "succeeded"
  | "failed"
  | "late_quarantined";

/** Canonical slot state derived from daemon events. */
export type ImageGenerationSlotState =
  | "pending"
  | "dispatched"
  | "accepted"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "late_quarantined";

/** The job/slot states that are terminal from the daemon's authoritative view. */
export const TERMINAL_JOB_STATES: readonly ImageGenerationJobState[] = [
  "cancelled",
  "succeeded",
  "failed",
];

/** Returns `true` if the job state is terminal (authoritative daemon state only). */
export function isTerminalJobState(state: ImageGenerationJobState): boolean {
  return TERMINAL_JOB_STATES.includes(state);
}

// ---------------------------------------------------------------------------
// Plan review (immutable)
// ---------------------------------------------------------------------------

/** A typed plan parameter value. */
export type TypedPlanParameter =
  | { type: "boolean"; value: boolean }
  | { type: "integer"; value: number }
  | { type: "text"; value: string };

/** One output slot in an immutable plan. */
export interface PlanOutputSlot {
  slotId: string;
  slotIndex: number;
  sampleIndex: number;
  managedArtifactId: string;
  publicationName: string;
  attemptCount: number;
}

/** One target in an immutable plan. */
export interface PlanTarget {
  targetId: string;
  targetConfigGeneration: number;
  destination: {
    adapterKind: string;
    destinationGeneration: number;
  };
  referenceArtifactCount: number;
  requested: { width: number; height: number; format: string };
  resolved: { width: number; height: number; format: string; mime: string };
  typedParameters: Record<string, TypedPlanParameter>;
  sampleCount: number;
  maxAttempts: number;
  slots: PlanOutputSlot[];
}

/** One required grant in an immutable plan. */
export interface PlanGrantRequirement {
  grantKind: string;
  authorityDigest: string;
  generation: number;
}

/** Spend reservation in an immutable plan. */
export interface PlanSpendReservation {
  required: boolean;
  policyVersion: number;
  reservationId: string;
  maximumUsdMicros?: number;
  planDigest: string;
}

/** The immutable plan review projection. Every fact is rendered. */
export interface ImageGenerationPlanReview {
  schemaVersion: number;
  kind: string;
  jobId: string;
  ownerSessionId: string;
  configGeneration: number;
  requiredGrants: PlanGrantRequirement[];
  spend: PlanSpendReservation;
  outputAuthority: {
    canonicalDestinationDigest: string;
    authorityGeneration: number;
    filenamePrefix: string;
    extension: string;
  };
  targets: PlanTarget[];
  planDigest: string;
}

// ---------------------------------------------------------------------------
// Plan review scope
// ---------------------------------------------------------------------------

/** Approval scope is only per-session/per-project; global is absent. */
export type ApprovalScope = "session" | "project";

/** Yolo mode: shows `agent_discretion` activity and no modal. */
export interface YoloModeView {
  yolo: true;
  activity: "agent_discretion";
}

/** Non-yolo approval mode requiring an explicit modal. */
export interface ExplicitApprovalModeView {
  yolo: false;
}

export type ApprovalModeView = YoloModeView | ExplicitApprovalModeView;
