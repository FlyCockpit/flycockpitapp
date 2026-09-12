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

/**
 * The host-capability projection is defined by the daemon capability protocol.
 * It is an opaque redacted projection here so this mirror cannot accidentally
 * add credential or path fields to the bootstrap surface.
 */
export const onboardingBootstrapSnapshotSchema = z
  .object({
    run_id: z.string().uuid(),
    attempt_id: z.string().uuid(),
    revision: z.number().int().nonnegative(),
    stage: onboardingStageSchema,
    bootstrap_state: onboardingBootstrapStateSchema,
    limited_mode: z.boolean(),
    lifetime_selection: z.string().optional(),
    host_capabilities: z.object({}).passthrough(),
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

export const applyOnboardingTransitionSchema = z
  .object({
    run_id: z.string().uuid(),
    attempt_id: z.string().uuid(),
    expected_revision: z.number().int().nonnegative(),
    client_operation_id: z.string().min(1).max(128),
    transition: onboardingTransitionKindSchema,
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

export interface LockedBootstrapHello {
  protocol_version: number;
  bootstrap_available: boolean;
  host_capabilities: object;
  snapshot?: OnboardingBootstrapSnapshot;
}

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
