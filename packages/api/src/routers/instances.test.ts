import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { createInstanceCredential } from "../lib/instance-credentials";
import { verifyRelayToken } from "../lib/relay-tokens";
import { instancesRouter } from "./instances";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "1234567890abcdef1234567890abcdef",
    BETTER_AUTH_URL: "https://app.example.test",
    DEPLOYMENT_PROFILE: "oss",
    PRODUCT_NAME: "Flycockpit",
    COCKPIT_INSTANCE_LIMIT: 2,
    COCKPIT_RELAY_URL: "wss://relay.example.test/ws",
  },
}));

const { default: prisma } = await import("@flycockpit/db");
const { env } = await import("@flycockpit/env/server");

const mutableEnv = env as unknown as { DEPLOYMENT_PROFILE: "hosted" | "enterprise" | "oss" };

const db = prisma as unknown as {
  appSetting: { findMany: MockInstance };
  user: { findUnique: MockInstance };
  cockpitInstance: {
    findMany: MockInstance;
    findUnique: MockInstance;
    findFirst: MockInstance;
    count: MockInstance;
    create: MockInstance;
    update: MockInstance;
  };
  deviceCode: { findUnique: MockInstance };
  instanceAccessGrant: { findMany: MockInstance; updateMany: MockInstance };
};

function buildContext(user: Partial<Session["user"]> | null = {}): Context {
  if (user === null) return { session: null };
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
        createdAt: user?.createdAt instanceof Date ? user.createdAt : new Date("2025-01-01"),
        updatedAt: user?.updatedAt instanceof Date ? user.updatedAt : new Date("2025-01-01"),
        ...user,
      },
      session: {
        id: "session-1",
        userId: user?.id ?? "user-1",
        token: "session-token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: user?.createdAt instanceof Date ? user.createdAt : new Date("2025-01-01"),
        updatedAt: user?.updatedAt instanceof Date ? user.updatedAt : new Date("2025-01-01"),
      },
    } as Session,
  };
}

function instance(overrides: Record<string, unknown> = {}) {
  return {
    id: "instance-1",
    userId: "user-1",
    displayName: "laptop",
    hostname: "laptop",
    os: "linux",
    arch: "x64",
    cliVersion: "0.1.0",
    status: "ACTIVE",
    secretPrefix: "prefix",
    secretHash: "hash",
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-01"),
    lastSeenAt: null,
    revokedAt: null,
    ...overrides,
  };
}

describe("instancesRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mutableEnv.DEPLOYMENT_PROFILE = "oss";
    db.appSetting.findMany.mockResolvedValue([]);
    db.user.findUnique.mockResolvedValue({ plan: "FREE", hostedTrialEndsAt: null });
    db.instanceAccessGrant.findMany.mockResolvedValue([]);
    db.instanceAccessGrant.updateMany.mockResolvedValue({ count: 0 });
  });

  it("registers a new instance and returns the one-time product credential", async () => {
    db.cockpitInstance.count.mockResolvedValue(0);
    db.cockpitInstance.create.mockImplementation(async ({ data }) =>
      instance({ id: "new-id", ...data }),
    );

    const client = createRouterClient(instancesRouter, { context: buildContext() });
    const result = await client.register({
      hostname: "devbox",
      os: "linux",
      arch: "x64",
      cliVersion: "1.2.3",
    });

    expect(result.instanceId).toBe("new-id");
    expect(result.instanceToken).toMatch(/^fci_/);
    expect(result.account).toEqual({ userId: "user-1", email: "user@example.test" });
    expect(db.cockpitInstance.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        userId: "user-1",
        displayName: "devbox",
        hostname: "devbox",
        secretHash: expect.any(String),
        secretPrefix: expect.any(String),
      }),
    });
  });

  it("rejects registration when the active instance cap is reached", async () => {
    db.cockpitInstance.count.mockResolvedValue(2);
    const client = createRouterClient(instancesRouter, { context: buildContext() });

    await expect(
      client.register({ hostname: "h", os: "linux", arch: "x64", cliVersion: "1" }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("FORBIDDEN");
      return true;
    });
    expect(db.cockpitInstance.create).not.toHaveBeenCalled();
  });

  it("rehydrates an owned active instance and rotates its product credential", async () => {
    db.cockpitInstance.findFirst.mockResolvedValue(instance());
    db.cockpitInstance.update.mockImplementation(async ({ data }) => instance({ ...data }));

    const client = createRouterClient(instancesRouter, { context: buildContext() });
    const result = await client.register({
      instanceId: "instance-1",
      hostname: "renamed-host",
      displayName: "Workstation",
      os: "linux",
      arch: "arm64",
      cliVersion: "2.0.0",
    });

    expect(result.instanceId).toBe("instance-1");
    expect(result.instanceToken).toMatch(/^fci_/);
    expect(db.cockpitInstance.count).not.toHaveBeenCalled();
    expect(db.cockpitInstance.update).toHaveBeenCalledWith({
      where: { id: "instance-1" },
      data: expect.objectContaining({ displayName: "Workstation", hostname: "renamed-host" }),
    });
  });

  it("mints a connector relay token only for a valid, active instance secret", async () => {
    const credential = createInstanceCredential();
    db.cockpitInstance.findUnique.mockResolvedValue(
      instance({ secretPrefix: credential.prefix, secretHash: credential.hash }),
    );
    db.cockpitInstance.update.mockResolvedValue(instance());

    const client = createRouterClient(instancesRouter, { context: buildContext(null) });
    const result = await client.mintConnectorToken({
      instanceId: "instance-1",
      instanceToken: credential.token,
    });

    expect(result.relayUrl).toBe("wss://relay.example.test/ws");
    const payload = await verifyRelayToken(result.token);
    expect(payload).toMatchObject({
      aud: "relay",
      tokenType: "connector",
      instanceId: "instance-1",
      userId: "user-1",
      grants: [],
    });
    expect(payload!.exp - payload!.iat).toBe(300);
  });

  it("blocks connector tokens when the owner's plan has no instance entitlement", async () => {
    const credential = createInstanceCredential();
    mutableEnv.DEPLOYMENT_PROFILE = "hosted";
    db.user.findUnique.mockResolvedValue({ plan: "FREE", hostedTrialEndsAt: null });
    db.cockpitInstance.findUnique.mockResolvedValue(
      instance({ secretPrefix: credential.prefix, secretHash: credential.hash }),
    );

    const client = createRouterClient(instancesRouter, { context: buildContext(null) });
    await expect(
      client.mintConnectorToken({ instanceId: "instance-1", instanceToken: credential.token }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("FORBIDDEN");
      expect(error.message).toMatch(/current plan/i);
      return true;
    });
    expect(db.cockpitInstance.update).not.toHaveBeenCalled();
  });

  it("rejects revoked instance credentials", async () => {
    const credential = createInstanceCredential();
    db.cockpitInstance.findUnique.mockResolvedValue(
      instance({
        secretPrefix: credential.prefix,
        secretHash: credential.hash,
        status: "REVOKED",
        revokedAt: new Date(),
      }),
    );

    const client = createRouterClient(instancesRouter, { context: buildContext(null) });
    await expect(
      client.mintConnectorToken({ instanceId: "instance-1", instanceToken: credential.token }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("FORBIDDEN");
      return true;
    });
  });

  it("mints owner client tokens without terminal grants", async () => {
    db.cockpitInstance.findUnique.mockResolvedValue(instance());

    const client = createRouterClient(instancesRouter, { context: buildContext() });
    const result = await client.mintClientToken({ instanceId: "instance-1" });
    const payload = await verifyRelayToken(result.token);

    expect(payload).toMatchObject({ tokenType: "client", aud: "relay", instanceId: "instance-1" });
    expect(payload?.grants.map((grant) => grant.scope).sort()).toEqual([
      "agent",
      "agent_readonly",
      "project_files",
    ]);
  });

  it("mints grantee client tokens with exactly active shared grants", async () => {
    db.cockpitInstance.findUnique.mockResolvedValue(instance({ userId: "owner-1" }));
    db.instanceAccessGrant.findMany.mockResolvedValue([
      { scope: "AGENT", projectRoot: "/repo" },
      { scope: "PROJECT_FILES", projectRoot: null },
    ]);

    const client = createRouterClient(instancesRouter, {
      context: buildContext({ id: "grantee-1", email: "grantee@example.test" }),
    });
    const result = await client.mintClientToken({ instanceId: "instance-1" });
    const payload = await verifyRelayToken(result.token);

    expect(payload).toMatchObject({
      tokenType: "client",
      instanceId: "instance-1",
      userId: "grantee-1",
    });
    expect(payload?.grants).toEqual([
      { scope: "agent", projectRoot: "/repo" },
      { scope: "project_files", projectRoot: null },
    ]);
  });

  it("rejects grantee client tokens when no active shared grants exist", async () => {
    db.cockpitInstance.findUnique.mockResolvedValue(instance({ userId: "owner-1" }));
    db.instanceAccessGrant.findMany.mockResolvedValue([]);
    const client = createRouterClient(instancesRouter, {
      context: buildContext({ id: "grantee-1", email: "grantee@example.test" }),
    });

    await expect(client.mintClientToken({ instanceId: "instance-1" })).rejects.toSatisfy(
      (error: ORPCError) => {
        expect(error.code).toBe("NOT_FOUND");
        return true;
      },
    );
  });

  it("mints terminal client tokens after a recent 2FA step-up", async () => {
    db.cockpitInstance.findUnique.mockResolvedValue(instance());
    db.user.findUnique.mockResolvedValue({
      terminalStepUpRelaxed: false,
      plan: "FREE",
      hostedTrialEndsAt: null,
    });

    const client = createRouterClient(instancesRouter, {
      context: buildContext({ twoFactorEnabled: true, createdAt: new Date() } as Partial<
        Session["user"]
      >),
    });
    const result = await client.mintTerminalClientToken({ instanceId: "instance-1" });
    const payload = await verifyRelayToken(result.token);

    expect(payload?.grants).toEqual([{ scope: "terminal", projectRoot: null }]);
    expect(result.stepUpExpiresAt).toBeInstanceOf(Date);
  });

  it("rejects terminal client tokens when 2FA step-up is stale", async () => {
    db.cockpitInstance.findUnique.mockResolvedValue(instance());
    db.user.findUnique.mockResolvedValue({
      terminalStepUpRelaxed: false,
      plan: "FREE",
      hostedTrialEndsAt: null,
    });

    const client = createRouterClient(instancesRouter, {
      context: buildContext({
        twoFactorEnabled: true,
        createdAt: new Date(Date.now() - 10 * 60 * 1000),
      } as Partial<Session["user"]>),
    });

    await expect(client.mintTerminalClientToken({ instanceId: "instance-1" })).rejects.toSatisfy(
      (error: ORPCError) => {
        expect(error.code).toBe("FORBIDDEN");
        expect(error.message).toMatch(/reauthentication/i);
        return true;
      },
    );
  });

  it("mints terminal client tokens when the owner relaxed step-up", async () => {
    db.cockpitInstance.findUnique.mockResolvedValue(instance());
    db.user.findUnique.mockResolvedValue({
      terminalStepUpRelaxed: true,
      plan: "FREE",
      hostedTrialEndsAt: null,
    });

    const client = createRouterClient(instancesRouter, {
      context: buildContext({
        twoFactorEnabled: true,
        createdAt: new Date(Date.now() - 10 * 60 * 1000),
      } as Partial<Session["user"]>),
    });

    await expect(
      client.mintTerminalClientToken({ instanceId: "instance-1" }),
    ).resolves.toMatchObject({
      relayUrl: "wss://relay.example.test/ws",
      stepUpExpiresAt: null,
    });
  });

  it("revokes only owned instances", async () => {
    db.cockpitInstance.findUnique.mockResolvedValue(instance({ userId: "someone-else" }));
    const client = createRouterClient(instancesRouter, { context: buildContext() });

    await expect(client.revoke({ instanceId: "instance-1" })).rejects.toSatisfy(
      (error: ORPCError) => {
        expect(error.code).toBe("NOT_FOUND");
        return true;
      },
    );
    expect(db.cockpitInstance.update).not.toHaveBeenCalled();
  });

  it("looks up device code metadata for the approval page", async () => {
    db.deviceCode.findUnique.mockResolvedValue({
      userCode: "ABCD-1234",
      status: "pending",
      clientId: "cockpit-cli",
      scope: "account:instance",
      expiresAt: new Date("2026-01-01"),
    });
    const client = createRouterClient(instancesRouter, { context: buildContext() });

    await expect(client.lookupDeviceCode({ userCode: "ABCD-1234" })).resolves.toMatchObject({
      clientId: "cockpit-cli",
      status: "pending",
    });
  });
});
