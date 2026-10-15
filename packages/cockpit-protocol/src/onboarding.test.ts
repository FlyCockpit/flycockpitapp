import { describe, expect, it } from "vitest";
import {
  clientEnvelopeSchema,
  eventEnvelopeSchema,
  lockedReadyConstructionSchema,
  onboardingBootstrapSnapshotSchema,
  PROTOCOL_VERSION,
  redactionCoverageStatusSchema,
  responseEnvelopeSchema,
} from "./index";

const snapshot = {
  run_id: "11111111-1111-4111-8111-111111111111",
  attempt_id: "22222222-2222-4222-8222-222222222222",
  revision: 3,
  stage: "secure_store",
  bootstrap_state: "awaiting_passphrase",
  limited_mode: false,
  host_capabilities: {
    generation: 0,
    features: [],
    dependencies: [],
    secretStore: {
      intent: "unconfigured",
      effective_placement: "unavailable",
      fail_closed_reason: null,
      fix_command: null,
    },
  },
};

describe("daemon onboarding wire projection", () => {
  it("routes the named bootstrap request, response, and event envelopes", () => {
    expect(
      clientEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "req",
        id: "33333333-3333-4333-8333-333333333333",
        request: "get_onboarding_bootstrap_snapshot",
      }).success,
    ).toBe(true);
    expect(
      responseEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "res",
        id: "33333333-3333-4333-8333-333333333333",
        response: "onboarding_bootstrap_snapshot",
        data: snapshot,
      }).success,
    ).toBe(true);
    expect(
      eventEnvelopeSchema.safeParse({
        v: PROTOCOL_VERSION,
        kind: "evt",
        event: "onboarding_bootstrap",
        data: {
          run_id: snapshot.run_id,
          attempt_id: snapshot.attempt_id,
          revision: snapshot.revision,
          state: snapshot.bootstrap_state,
        },
      }).success,
    ).toBe(true);
  });

  it.each([
    "passphrase",
    "credential",
    "oauth_token",
    "provider_config",
    "filesystem_path",
  ])("rejects a secret-bearing or authority-bypassing %s field", (field) => {
    expect(
      onboardingBootstrapSnapshotSchema.safeParse({ ...snapshot, [field]: "canary" }).success,
    ).toBe(false);
  });
});

describe("typed redaction coverage state", () => {
  it.each([
    "capture_failed",
    "busy",
    "sources_changed",
    "source_file_over_limit",
    "ssh_keys_over_budget",
    "sources_over_budget",
    "held_by_open_sessions",
  ])("preserves %s through construction and projection schemas", (reason) => {
    const failure = { failed: { reason: { redaction_coverage: reason } } };
    expect(lockedReadyConstructionSchema.parse(failure)).toEqual(failure);
    for (const session_id of [undefined, snapshot.run_id]) {
      const status = { session_id, unavailable: reason };
      expect(redactionCoverageStatusSchema.parse(status)).toEqual(status);
      const frame = {
        v: PROTOCOL_VERSION,
        kind: "evt",
        event: "redaction_coverage_status",
        data: status,
      };
      expect(eventEnvelopeSchema.parse(frame)).toEqual(frame);
    }
  });

  it("rejects missing or unknown failure reasons and secret-bearing status", () => {
    for (const failure of ["failed", { failed: {} }, { failed: { reason: "unknown" } }]) {
      expect(lockedReadyConstructionSchema.safeParse(failure).success).toBe(false);
    }
    expect(redactionCoverageStatusSchema.parse({})).toEqual({});
    expect(redactionCoverageStatusSchema.safeParse({ unavailable: "unknown" }).success).toBe(false);
    expect(redactionCoverageStatusSchema.safeParse({ credential: "canary" }).success).toBe(false);
  });
});
