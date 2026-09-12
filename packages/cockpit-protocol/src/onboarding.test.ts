import { describe, expect, it } from "vitest";
import {
  clientEnvelopeSchema,
  eventEnvelopeSchema,
  onboardingBootstrapSnapshotSchema,
  PROTOCOL_VERSION,
  responseEnvelopeSchema,
} from "./index";

const snapshot = {
  run_id: "11111111-1111-4111-8111-111111111111",
  attempt_id: "22222222-2222-4222-8222-222222222222",
  revision: 3,
  stage: "secure_store",
  bootstrap_state: "awaiting_passphrase",
  limited_mode: false,
  host_capabilities: {},
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
