import { describe, expect, it } from "vitest";
import { authRecoveryView, errorClassLabel, llmModeView } from "./inference-failure-view";

describe("inference failure view helpers", () => {
  it("maps missing auth failure to the generic recovery view", () => {
    expect(authRecoveryView(undefined)).toEqual({
      kind: "generic",
      messageKey: "remote.inferenceFailureGeneric",
    });
  });

  it("maps rejected credentials without throwing on optional status", () => {
    expect(authRecoveryView({ kind: "credentials_rejected", status: 401 })).toEqual({
      kind: "credentials_rejected",
      messageKey: "remote.authCredentialsRejected",
      status: 401,
    });
  });

  it("maps missing entitlement recovery details", () => {
    expect(
      authRecoveryView({ kind: "missing_entitlement", feature: "xai_multi_agent_tools_beta" }),
    ).toEqual({
      kind: "missing_entitlement",
      messageKey: "remote.authMissingEntitlement",
      feature: "xai_multi_agent_tools_beta",
    });
  });

  it("maps expired OAuth provider recovery details", () => {
    expect(authRecoveryView({ kind: "oauth_expired", provider: "github" })).toEqual({
      kind: "oauth_expired",
      messageKey: "remote.authOAuthExpired",
      provider: "github",
    });
  });

  it("maps provider-not-configured failures", () => {
    expect(authRecoveryView({ kind: "provider_not_configured" })).toEqual({
      kind: "provider_not_configured",
      messageKey: "remote.authProviderNotConfigured",
    });
  });

  it("falls back for unknown future auth failures", () => {
    expect(authRecoveryView({ kind: "future_auth_failure" })).toEqual({
      kind: "generic",
      messageKey: "remote.inferenceFailureGeneric",
    });
  });

  it("maps known and unknown llm modes to label keys", () => {
    expect(llmModeView("defensive")).toEqual({
      mode: "defensive",
      labelKey: "remote.llmMode.defensive",
    });
    expect(llmModeView("experimental")).toEqual({ labelKey: "remote.llmMode.unknown" });
  });

  it("formats structured error classes without leaking raw objects", () => {
    expect(errorClassLabel({ kind: "http", status: 429 })).toBe("http 429");
    expect(errorClassLabel({ kind: "missing_tool_entitlement", feature: "tools" })).toBe(
      "missing_tool_entitlement: tools",
    );
    expect(errorClassLabel("timeout_idle")).toBe("timeout_idle");
  });
});
