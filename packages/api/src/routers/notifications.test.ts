import type { Session } from "@flycockpit/auth";
import { createRouterClient } from "@orpc/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { verifyRelayToken } from "../lib/relay-tokens";
import { notificationsRouter } from "./notifications";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

const envState = vi.hoisted(() => ({
  BETTER_AUTH_SECRET: "1234567890abcdef1234567890abcdef",
  BETTER_AUTH_URL: "https://app.example.test",
  DEPLOYMENT_PROFILE: "oss" as "hosted" | "enterprise" | "oss",
  COCKPIT_RELAY_ID: "relay-test",
  COCKPIT_RELAY_URL: "wss://relay.example.test/ws",
  RELAY_CONTROL_SECRET: "x".repeat(32),
}));

const fleetMocks = vi.hoisted(() => ({
  selectUserRelay: vi.fn(),
}));

vi.mock("@flycockpit/env/server", () => ({ env: envState }));
vi.mock("../enterprise/relay-fleet", () => fleetMocks);

function buildContext(): Context {
  return {
    session: {
      user: {
        id: "user-1",
        email: "user@example.test",
        name: "User",
        emailVerified: true,
        role: "user",
        twoFactorEnabled: false,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
      },
      session: {
        id: "session-1",
        userId: "user-1",
        token: "session-token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
      },
    } as Session,
  };
}

describe("notificationsRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    envState.DEPLOYMENT_PROFILE = "oss";
    fleetMocks.selectUserRelay.mockResolvedValue({
      relayId: "relay-fleet",
      region: "iad",
      wsUrl: "wss://fleet.example.test/ws",
    });
  });

  it("mints user relay tokens for the configured relay audience", async () => {
    const client = createRouterClient(notificationsRouter, { context: buildContext() });

    const result = await client.mintUserRelayToken();

    expect(result.relayUrl).toBe("wss://relay.example.test/ws");
    await expect(verifyRelayToken(result.token, "relay-test")).resolves.toMatchObject({
      aud: "relay-test",
      tokenType: "user",
      userId: "user-1",
    });
  });

  it("mints hosted user relay tokens for the selected fleet relay", async () => {
    envState.DEPLOYMENT_PROFILE = "hosted";
    const client = createRouterClient(notificationsRouter, { context: buildContext() });

    const result = await client.mintUserRelayToken();

    expect(fleetMocks.selectUserRelay).toHaveBeenCalledWith("user-1");
    expect(result.relayUrl).toBe("wss://fleet.example.test/ws");
    await expect(verifyRelayToken(result.token, "relay-fleet")).resolves.toMatchObject({
      aud: "relay-fleet",
      tokenType: "user",
      userId: "user-1",
    });
  });
});
