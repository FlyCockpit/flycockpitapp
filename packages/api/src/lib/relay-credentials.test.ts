import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "https://app.example.test",
    COCKPIT_RELAY_URL: undefined,
    RELAY_CONTROL_SECRET: undefined,
  },
}));

const { relayControlUrl, resetRelayControlConfig, setRelayControlConfig } = await import(
  "./relay-config"
);
const { verifyRelayCredential } = await import("./relay-credentials");

afterEach(() => {
  resetRelayControlConfig();
});

describe("relay credentials", () => {
  it("accepts boot-installed relay control config when env relay settings are absent", () => {
    setRelayControlConfig({
      relayId: "boot-relay",
      controlSecret: "s".repeat(32),
      controlUrl: "http://127.0.0.1:43101/control",
    });

    expect(relayControlUrl()).toBe("http://127.0.0.1:43101/control");
    expect(
      verifyRelayCredential(
        new Request("https://app.example.test/api/relay/control-ingest", {
          headers: { authorization: `Bearer ${"s".repeat(32)}` },
        }),
      ),
    ).toEqual({ relayId: "boot-relay", mode: "embedded" });
  });
});
