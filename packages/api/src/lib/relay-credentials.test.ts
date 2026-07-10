import { afterEach, describe, expect, it, vi } from "vitest";

const envState = vi.hoisted(() => ({
  BETTER_AUTH_URL: "https://app.example.test",
  COCKPIT_RELAY_URL: undefined as string | undefined,
  RELAY_CONTROL_SECRET: undefined as string | undefined,
  DEPLOYMENT_PROFILE: "oss" as "hosted" | "enterprise" | "oss",
}));

const fleetMocks = vi.hoisted(() => ({
  verifyFleetSessionToken: vi.fn(),
}));

vi.mock("@flycockpit/env/server", () => ({ env: envState }));
vi.mock("@flycockpit/api/enterprise/relay-fleet", () => fleetMocks);

const { relayControlUrl, resetRelayControlConfig, setRelayControlConfig } = await import(
  "./relay-config"
);
const { verifyRelayCredential } = await import("./relay-credentials");

afterEach(() => {
  resetRelayControlConfig();
  envState.DEPLOYMENT_PROFILE = "oss";
  fleetMocks.verifyFleetSessionToken.mockReset();
});

describe("relay credentials", () => {
  it("accepts boot-installed relay control config when env relay settings are absent", async () => {
    setRelayControlConfig({
      relayId: "boot-relay",
      controlSecret: "s".repeat(32),
      controlUrl: "http://127.0.0.1:43101/control",
    });

    expect(relayControlUrl()).toBe("http://127.0.0.1:43101/control");
    await expect(
      verifyRelayCredential(
        new Request("https://app.example.test/api/relay/control-ingest", {
          headers: { authorization: `Bearer ${"s".repeat(32)}` },
        }),
      ),
    ).resolves.toEqual({ relayId: "boot-relay", mode: "embedded" });
  });

  it("accepts enterprise fleet session tokens without embedded relay control config", async () => {
    envState.DEPLOYMENT_PROFILE = "hosted";
    fleetMocks.verifyFleetSessionToken.mockResolvedValue({
      relayId: "fleet-relay",
      expiresAt: Date.now() + 60_000,
    });

    await expect(
      verifyRelayCredential(
        new Request("https://app.example.test/api/relay/heartbeat", {
          headers: { authorization: "Bearer fleet-session" },
        }),
      ),
    ).resolves.toEqual({ relayId: "fleet-relay", mode: "fleet" });
    expect(fleetMocks.verifyFleetSessionToken).toHaveBeenCalledWith("fleet-session");
  });
});
