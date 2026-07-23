import { describe, expect, it } from "vitest";
import {
  type ActiveModelState,
  activeModelReducer,
  activeModelView,
  inferenceFailureView,
} from "./inference-failure-view";

describe("inferenceFailureView", () => {
  it("maps auth failures to recovery affordances", () => {
    expect(
      inferenceFailureView({
        provider: "openai",
        model: "gpt-5",
        error_class: "auth",
        detail: "bad key",
        auth_failure: { kind: "credentials_rejected", status: 401 },
      }).recovery,
    ).toMatchObject({
      kind: "reauthenticate",
      label: "Credentials rejected (HTTP 401)",
      action: "reauthenticate",
      guidance: "Re-authenticate this provider from an available provider entry point.",
    });

    expect(
      inferenceFailureView({
        provider: "openai",
        model: "gpt-5",
        error_class: "entitlement",
        auth_failure: { kind: "missing_entitlement", feature: "GPT-5" },
      }).recovery,
    ).toMatchObject({ kind: "upgrade", label: "This needs GPT-5" });

    expect(
      inferenceFailureView({
        provider: "github",
        model: "copilot",
        error_class: "oauth",
        auth_failure: { kind: "oauth_expired", provider: "GitHub" },
      }).recovery,
    ).toMatchObject({
      kind: "reconnect",
      label: "GitHub sign-in expired",
      action: "reconnect_provider",
      provider: "GitHub",
      guidance: "Reconnect this provider from an available provider entry point.",
    });

    expect(
      inferenceFailureView({
        provider: "anthropic",
        model: "claude",
        error_class: "config",
        auth_failure: { kind: "provider_not_configured" },
      }).recovery,
    ).toMatchObject({ kind: "configure", label: "Provider not configured" });
  });

  it("maps non-auth inference failures without recovery actions", () => {
    expect(
      inferenceFailureView({
        provider: "openai",
        model: "gpt-5",
        error_class: "rate_limit",
        detail: "try later",
      }),
    ).toEqual({
      headline: "openai gpt-5 failed",
      detail: "try later",
      provider: "openai",
      model: "gpt-5",
      errorClass: "rate_limit",
      recovery: { kind: "none", label: null },
    });
  });
});

describe("active model state", () => {
  it("keeps the highest generation", () => {
    const high = activeModelReducer(null, {
      provider: "openai",
      model: "gpt-5",
      generation: 10,
    });
    const stale = activeModelReducer(high, {
      provider: "anthropic",
      model: "claude",
      generation: 9,
    });

    expect(stale).toBe(high);
  });

  it("produces divergence view state only when the daemon reports divergence", () => {
    const diverged: ActiveModelState = {
      provider: "openai",
      model: "gpt-4o",
      configProvider: "openai",
      configModel: "gpt-5",
      diverged: true,
      generation: 1,
    };
    expect(activeModelView(diverged, "normal").divergence).toBe(
      "Configured openai/gpt-5 is not active",
    );
    expect(activeModelView({ ...diverged, diverged: false }, "normal").divergence).toBeNull();
  });
});
