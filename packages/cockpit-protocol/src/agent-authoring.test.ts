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
        source: {
          kind: "authored",
          source_locator: "authored/helper",
          third_party_trust_confirmed: false,
        },
        policy_revision: "a".repeat(64),
        make_default: true,
      },
    });
    expect(parsed.success).toBe(true);
    expect(JSON.stringify(parsed.data)).not.toContain("profile_handle");
  });

  it("accepts every apply outcome with recursive review children", () => {
    const review = {
      agent_name: "helper",
      grants: [
        {
          provider_id: "vendor",
          model_id: "exact-a",
          is_default: true,
          trust: "untrusted",
          trust_is_shared: false,
        },
      ],
      tool_tier_preferences: [],
      interactive_subagents: false,
      goal_skeptics_label: "Goal skeptics off",
      children: [
        {
          path: "subagents/reviewer.md",
          grants: [],
          tool_tier_preferences: [["shell", "read_only"]],
          interactive_subagents: false,
          goal_skeptics_label: "Goal skeptics on",
          children: [],
        },
      ],
      source: "authored/helper",
      make_default: true,
      trust_is_shared: false,
      trust_disclosure:
        "Trust classification is shared global provider/model policy, not a per-agent override.",
    } as const;

    expect(
      applyAuthoredAgentPackageOutcomeSchema.safeParse({
        outcome: "receipt",
        client_operation_id: "op-1",
        receipt_id: "11111111-1111-4111-8111-111111111111",
        status: "committed",
        package_digest: "b".repeat(64),
        policy_revision: "a".repeat(64),
        default_selected: true,
        result_config_generation: 2,
        review,
      }).success,
    ).toBe(true);
    expect(
      applyAuthoredAgentPackageOutcomeSchema.safeParse({ outcome: "review", ...review }).success,
    ).toBe(true);
    expect(
      applyAuthoredAgentPackageOutcomeSchema.safeParse({
        outcome: "policy_revision_conflict",
        projection,
      }).success,
    ).toBe(true);
  });

  it("mirrors serde omission rules and safe u64 bounds", () => {
    const request = {
      client_operation_id: "",
      expected_policy_revision: "",
      package: {
        dto_version: 1,
        name: "",
        markdown: "",
        source: {
          kind: "authored",
          source_locator: "",
          third_party_trust_confirmed: false,
        },
        policy_revision: "",
        make_default: false,
      },
    };
    expect(applyAuthoredAgentPackageRequestSchema.safeParse(request).success).toBe(true);
    expect(
      applyAuthoredAgentPackageRequestSchema.safeParse({
        ...request,
        validate_only: false,
      }).success,
    ).toBe(false);
    expect(
      applyAuthoredAgentPackageRequestSchema.safeParse({
        ...request,
        package: { ...request.package, children: [] },
      }).success,
    ).toBe(false);
    expect(
      applyAuthoredAgentPackageRequestSchema.safeParse({
        ...request,
        onboarding: {
          run_id: "11111111-1111-4111-8111-111111111111",
          attempt_id: "22222222-2222-4222-8222-222222222222",
          stage_revision: Number.MAX_SAFE_INTEGER + 1,
        },
      }).success,
    ).toBe(false);
  });
});
