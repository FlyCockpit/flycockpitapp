import { describe, expect, it } from "vitest";
import {
  agentAuthoringProjectionSchema,
  applyAuthoredAgentPackageOutcomeSchema,
  applyAuthoredAgentPackageRequestSchema,
} from "./agent-authoring";

const projection = {
  dto_version: 1 as const,
  policy: {
    policy_revision: "a".repeat(64),
    routes: [
      {
        provider_id: "vendor",
        model_id: "exact-a",
        trust: "untrusted",
        confirmation_required: true,
        trust_is_shared: true,
        capabilities: ["text_generation"],
        auto_prune: true,
        sidecar_eligible: false,
        remote_sidecar_egress_required: false,
      },
    ],
    catalog_origin: "bundled",
    catalog_revision: "464140ba6ee9e1669ef1c3f37d82de8c7edd83d7",
    bundled_frontier_slug: "frontier-coding",
  },
  sources: [
    {
      kind: "bundled_frontier",
      slug: "frontier-coding",
      display_name: "Frontier coding",
      compatible_routes: [{ provider_id: "vendor", model_id: "exact-a" }],
    },
  ],
  review_trust_disclosure:
    "Trust classification is shared global provider/model policy, not a per-agent override.",
};

describe("agent authoring wire projection", () => {
  it("accepts a redacted policy snapshot and rejects secret-bearing fields", () => {
    expect(agentAuthoringProjectionSchema.safeParse(projection).success).toBe(true);
    expect(
      agentAuthoringProjectionSchema.safeParse({
        ...projection,
        api_key: "canary",
      }).success,
    ).toBe(false);
  });

  it("round-trips an apply request without profile handles", () => {
    const parsed = applyAuthoredAgentPackageRequestSchema.safeParse({
      client_operation_id: "op-1",
      expected_policy_revision: "a".repeat(64),
      package: {
        dto_version: 1,
        name: "helper",
        markdown: "---\ndescription: helper\n---\nbody\n",
        source: { kind: "authored", source_locator: "authored/helper" },
        policy_revision: "a".repeat(64),
        make_default: true,
      },
    });
    expect(parsed.success).toBe(true);
    expect(JSON.stringify(parsed.data)).not.toContain("profile_handle");
  });

  it("accepts a committed receipt and a policy-revision conflict", () => {
    expect(
      applyAuthoredAgentPackageOutcomeSchema.safeParse({
        outcome: "receipt",
        client_operation_id: "op-1",
        receipt_id: "11111111-1111-4111-8111-111111111111",
        status: "committed",
        package_digest: "b".repeat(64),
        policy_revision: "a".repeat(64),
        default_selected: true,
        review: {
          agent_name: "helper",
          grants: [
            {
              provider_id: "vendor",
              model_id: "exact-a",
              is_default: true,
              trust: "untrusted",
              trust_is_shared: true,
            },
          ],
          tool_tier_preferences: [],
          interactive_subagents: false,
          goal_skeptics_label: "Goal skeptics off",
          children: [],
          source: "authored/helper",
          trust_is_shared: true,
          trust_disclosure:
            "Trust classification is shared global provider/model policy, not a per-agent override.",
        },
      }).success,
    ).toBe(true);
    expect(
      applyAuthoredAgentPackageOutcomeSchema.safeParse({
        outcome: "policy_revision_conflict",
        projection,
      }).success,
    ).toBe(true);
  });
});
