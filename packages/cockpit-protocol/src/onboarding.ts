import { z } from "zod";

/** Redacted metadata emitted before the daemon has opened a secret vault. */
export const onboardingStageSchema = z.enum([
  "welcome",
  "profile",
  "secure_store",
  "provider",
  "model",
  "agent",
  "lifetime",
  "complete",
]);
export type OnboardingStage = z.infer<typeof onboardingStageSchema>;

export const onboardingBootstrapStateSchema = z.enum([
  "awaiting_choice",
  "awaiting_passphrase",
  "materializing",
  "ready",
  "failed",
]);
export type OnboardingBootstrapState = z.infer<typeof onboardingBootstrapStateSchema>;

export const onboardingSecurePlacementSchema = z.enum([
  "automatic",
  "keyring",
  "passphrase_file",
  "machine_bound_file",
]);
export type OnboardingSecurePlacement = z.infer<typeof onboardingSecurePlacementSchema>;

export const onboardingReceiptStatusSchema = z.enum([
  "pending",
  "committed",
  "rejected",
  "unknown",
]);
export type OnboardingReceiptStatus = z.infer<typeof onboardingReceiptStatusSchema>;

export const onboardingTransitionReceiptSchema = z
  .object({
    run_id: z.string().uuid(),
    attempt_id: z.string().uuid(),
    consumed_revision: z.number().int().nonnegative(),
    receipt_id: z.string().uuid(),
    status: onboardingReceiptStatusSchema,
  })
  .strict();
export type OnboardingTransitionReceipt = z.infer<typeof onboardingTransitionReceiptSchema>;

const featureCapabilitySchema = z
  .object({
    id: z.string(),
    state: z.enum(["available", "missing", "unsupported", "failed"]),
    reason: z.string(),
    fix_command: z.string().optional(),
    remedy_text: z.string().optional(),
    dependency_ids: z.array(z.string()).optional(),
  })
  .strict();

const catalogDependencySchema = z
  .object({
    id: z.string(),
    state: z.enum([
      "pending",
      "available",
      "missing",
      "incompatible",
      "timed_out",
      "failed",
      "unknown",
      "not_applicable",
    ]),
    importance: z.enum([
      "required_for_default_safety",
      "required_when_feature_selected",
      "optional_integration",
      "optional_accelerator",
    ]),
    target: z.enum(["host", "container"]),
    required_version: z.string().optional(),
    discovered_version: z.string().optional(),
    cause: z.unknown().optional(),
    remedy: z.unknown().optional(),
    reason: z.string(),
  })
  .strict();

export const onboardingHostCapabilitiesSchema = z
  .object({
    generation: z.number().int().nonnegative(),
    features: z.array(featureCapabilitySchema),
    dependencies: z.array(catalogDependencySchema),
    secretStore: z
      .object({
        intent: z.enum(["unconfigured", "database", "keyring"]),
        effective_placement: z.enum(["unavailable", "database", "keyring"]),
        fail_closed_reason: z.string().nullable().optional(),
        fix_command: z.string().nullable().optional(),
      })
      .strict(),
  })
  .strict();

export const onboardingBootstrapSnapshotSchema = z
  .object({
    run_id: z.string().uuid(),
    attempt_id: z.string().uuid(),
    revision: z.number().int().nonnegative(),
    stage: onboardingStageSchema,
    bootstrap_state: onboardingBootstrapStateSchema,
    limited_mode: z.boolean(),
    lifetime_selection: z.string().optional(),
    host_capabilities: onboardingHostCapabilitiesSchema,
    last_receipt: onboardingTransitionReceiptSchema.optional(),
  })
  .strict();
export type OnboardingBootstrapSnapshot = z.infer<typeof onboardingBootstrapSnapshotSchema>;

export const beginOrReopenOnboardingSchema = z
  .object({
    expected_revision: z.number().int().nonnegative().optional(),
    client_operation_id: z.string().min(1).max(128),
    reentry: z.boolean(),
  })
  .strict();
export type BeginOrReopenOnboarding = z.infer<typeof beginOrReopenOnboardingSchema>;

export const onboardingTransitionKindSchema = z.enum([
  "advance",
  "defer_provider",
  "back",
  "complete",
]);
export type OnboardingTransitionKind = z.infer<typeof onboardingTransitionKindSchema>;

export const onboardingStageSettlementSchema = z
  .object({
    run_id: z.string().uuid(),
    attempt_id: z.string().uuid(),
    stage_revision: z.number().int().nonnegative(),
    settlement_operation_id: z.string().min(1).max(128),
    provider_id: z.string().optional(),
    config_generation: z.number().int().nonnegative(),
  })
  .strict();
export type OnboardingStageSettlement = z.infer<typeof onboardingStageSettlementSchema>;

export const applyOnboardingTransitionSchema = z
  .object({
    run_id: z.string().uuid(),
    attempt_id: z.string().uuid(),
    expected_revision: z.number().int().nonnegative(),
    client_operation_id: z.string().min(1).max(128),
    transition: onboardingTransitionKindSchema,
    settlement: onboardingStageSettlementSchema.optional(),
  })
  .strict();
export type ApplyOnboardingTransition = z.infer<typeof applyOnboardingTransitionSchema>;

export const onboardingReceiptQuerySchema = z
  .object({
    run_id: z.string().uuid(),
    attempt_id: z.string().uuid(),
    client_operation_id: z.string().min(1).max(128),
  })
  .strict();
export type OnboardingReceiptQuery = z.infer<typeof onboardingReceiptQuerySchema>;

export const onboardingTransitionResultSchema = z
  .object({
    snapshot: onboardingBootstrapSnapshotSchema,
    receipt: onboardingTransitionReceiptSchema,
  })
  .strict();
export type OnboardingTransitionResult = z.infer<typeof onboardingTransitionResultSchema>;

export const lockedBootstrapHelloSchema = z
  .object({
    protocol_version: z.number().int().nonnegative(),
    bootstrap_available: z.boolean(),
    host_capabilities: onboardingHostCapabilitiesSchema,
    snapshot: onboardingBootstrapSnapshotSchema.optional(),
  })
  .strict();
export type LockedBootstrapHello = z.infer<typeof lockedBootstrapHelloSchema>;

/** A passphrase is intentionally absent: it is Rust-only sensitive ingress. */
export const onboardingBootstrapEventSchema = z
  .object({
    run_id: z.string().uuid(),
    attempt_id: z.string().uuid(),
    revision: z.number().int().nonnegative(),
    state: onboardingBootstrapStateSchema,
  })
  .strict();
export type OnboardingBootstrapEvent = z.infer<typeof onboardingBootstrapEventSchema>;
