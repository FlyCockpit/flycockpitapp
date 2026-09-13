import { z } from "zod";

export const agentAuthoringDtoVersionSchema = z.literal(1);

export const agentAuthoringCatalogOriginSchema = z.enum(["bundled", "cached", "live"]);
export const agentAuthoringSourceKindSchema = z.enum([
  "bundled_frontier",
  "first_party_catalog",
  "third_party",
  "authored",
]);
export const agentPolicyTrustClassificationSchema = z.enum(["trusted", "untrusted", "unset"]);
export const authoredAgentReceiptStatusSchema = z.enum([
  "pending",
  "committed",
  "rejected",
  "unknown",
]);
export const authoredAgentRejectReasonSchema = z.enum([
  "empty_grants",
  "duplicate_routes",
  "absent_default",
  "non_enabled_default",
  "unsupported_capability",
  "omitted_model_trust_confirmation",
  "illegal_tool_tier",
  "invalid_nested_graph",
  "unpinned_third_party_source",
  "missing_third_party_trust_confirmation",
  "unapproved_remote_sidecar_egress",
  "per_agent_trust_override",
  "invalid_frontmatter",
  "incomplete_package",
  "stale_draft",
]);

export const agentPolicyRouteSchema = z
  .object({
    provider_id: z.string(),
    model_id: z.string(),
    trust: agentPolicyTrustClassificationSchema,
    confirmation_required: z.boolean(),
    trust_is_shared: z.literal(true),
    capabilities: z.array(z.string()),
    location: z.string().optional(),
    auto_prune: z.boolean(),
    sidecar_eligible: z.boolean(),
    remote_sidecar_egress_required: z.boolean(),
  })
  .strict();

export const agentPolicySnapshotSchema = z
  .object({
    policy_revision: z.string().min(1),
    routes: z.array(agentPolicyRouteSchema),
    catalog_origin: agentAuthoringCatalogOriginSchema,
    catalog_revision: z.string(),
    bundled_frontier_slug: z.string(),
  })
  .strict();

export const agentAuthoringCompatibleRouteSchema = z
  .object({
    provider_id: z.string(),
    model_id: z.string(),
  })
  .strict();

export const agentAuthoringSourceSchema = z
  .object({
    kind: agentAuthoringSourceKindSchema,
    slug: z.string().optional(),
    display_name: z.string(),
    source_locator: z.string().optional(),
    compatible_routes: z.array(agentAuthoringCompatibleRouteSchema),
    definition_frontmatter_yaml: z.string().optional(),
  })
  .strict();

export const agentAuthoringProjectionSchema = z
  .object({
    dto_version: agentAuthoringDtoVersionSchema,
    policy: agentPolicySnapshotSchema,
    sources: z.array(agentAuthoringSourceSchema),
    review_trust_disclosure: z.string().min(1),
  })
  .strict();
export type AgentAuthoringProjection = z.infer<typeof agentAuthoringProjectionSchema>;

export const authoredAgentSourceSchema = z
  .object({
    kind: agentAuthoringSourceKindSchema,
    source_locator: z.string(),
    pin: z.string().optional(),
    third_party_trust_confirmed: z.boolean().optional(),
  })
  .strict();

export const authoredAgentChildSchema = z
  .object({
    relative_path: z.string(),
    markdown: z.string(),
  })
  .strict();

export const authoredSidecarDeclarationSchema = z
  .object({
    provider_id: z.string(),
    model_id: z.string(),
    remote_image_egress_confirmed: z.boolean(),
  })
  .strict();

export const modelTrustConfirmationSchema = z
  .object({
    provider_id: z.string(),
    model_id: z.string(),
    confirmed: z.boolean(),
  })
  .strict();

export const authoredAgentPackageDraftSchema = z
  .object({
    dto_version: agentAuthoringDtoVersionSchema,
    name: z.string().min(1),
    markdown: z.string().min(1),
    source: authoredAgentSourceSchema,
    children: z.array(authoredAgentChildSchema).optional(),
    mcp_json: z.string().optional(),
    sidecars: z.array(authoredSidecarDeclarationSchema).optional(),
    policy_revision: z.string().min(1),
    model_trust_confirmations: z.array(modelTrustConfirmationSchema).optional(),
    make_default: z.boolean(),
    draft_revision: z.string().optional(),
  })
  .strict();

export const applyAuthoredAgentPackageRequestSchema = z
  .object({
    client_operation_id: z.string().min(1),
    expected_policy_revision: z.string().min(1),
    package: authoredAgentPackageDraftSchema,
    onboarding: z
      .object({
        run_id: z.string().uuid(),
        attempt_id: z.string().uuid(),
        stage_revision: z.number().int().nonnegative(),
      })
      .strict()
      .optional(),
  })
  .strict();
export type ApplyAuthoredAgentPackageRequest = z.infer<
  typeof applyAuthoredAgentPackageRequestSchema
>;

export const authoredAgentReviewGrantSchema = z
  .object({
    provider_id: z.string(),
    model_id: z.string(),
    is_default: z.boolean(),
    trust: agentPolicyTrustClassificationSchema,
    trust_is_shared: z.literal(true),
  })
  .strict();

export const authoredAgentReviewSchema = z
  .object({
    agent_name: z.string(),
    grants: z.array(authoredAgentReviewGrantSchema),
    tool_tier_preferences: z.array(z.tuple([z.string(), z.string()])),
    verification_label: z.string().optional(),
    interactive_subagents: z.boolean(),
    goal_skeptics_label: z.string(),
    children: z.array(z.string()),
    sidecars: z.array(z.string()).optional(),
    source: z.string(),
    trust_is_shared: z.boolean(),
    trust_disclosure: z.string(),
  })
  .strict();

export const applyAuthoredAgentPackageReceiptSchema = z
  .object({
    client_operation_id: z.string(),
    receipt_id: z.string().uuid(),
    status: authoredAgentReceiptStatusSchema,
    package_digest: z.string(),
    policy_revision: z.string(),
    installation_id: z.string().optional(),
    default_selected: z.boolean(),
    review: authoredAgentReviewSchema,
  })
  .strict();

export const applyAuthoredAgentPackageOutcomeSchema = z.discriminatedUnion("outcome", [
  applyAuthoredAgentPackageReceiptSchema.extend({ outcome: z.literal("receipt") }),
  z
    .object({
      outcome: z.literal("policy_revision_conflict"),
      projection: agentAuthoringProjectionSchema,
    })
    .strict(),
  z
    .object({
      outcome: z.literal("rejected"),
      reason: authoredAgentRejectReasonSchema,
      message: z.string(),
      projection: agentAuthoringProjectionSchema.optional(),
    })
    .strict(),
]);

export const authoredAgentPackageReceiptQuerySchema = z
  .object({
    client_operation_id: z.string().min(1),
  })
  .strict();
