import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Context } from "../context";
import { instanceSharingRouter } from "./instance-sharing";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  return { default: db };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "1234567890abcdef1234567890abcdef",
    BETTER_AUTH_URL: "https://app.example.test",
    DEPLOYMENT_PROFILE: "oss",
    PRODUCT_NAME: "Flycockpit",
    COCKPIT_INSTANCE_LIMIT: 2,
    COCKPIT_INSTANCE_GRANTEE_LIMIT: 2,
    COCKPIT_RELAY_URL: "wss://relay.example.test/ws",
    RELAY_CONTROL_SECRET: "1234567890abcdef1234567890abcdef",
  },
}));

vi.mock("@flycockpit/mailer", () => ({
  sendEmail: vi.fn(),
  renderShareInvite: vi.fn(() => ({ subject: "Share", html: "<p>Share</p>" })),
}));

const { default: prisma } = await import("@flycockpit/db");
const { sendEmail, renderShareInvite } = await import("@flycockpit/mailer");

const db = prisma as unknown as {
  appSetting: { findMany: MockInstance };
  cockpitInstance: { findUnique: MockInstance };
  user: { findUnique: MockInstance };
  instanceAccessGrant: {
    findMany: MockInstance;
    findFirst: MockInstance;
    findUnique: MockInstance;
    create: MockInstance;
    update: MockInstance;
    updateMany: MockInstance;
  };
  instanceAuditEvent: { create: MockInstance; findMany: MockInstance };
};
const sendEmailMock = sendEmail as unknown as MockInstance;
const renderShareInviteMock = renderShareInvite as unknown as MockInstance;

function buildContext(user: Partial<Session["user"]> = {}): Context {
  return {
    session: {
      user: {
        id: "owner-1",
        email: "owner@example.test",
        name: "Owner",
        emailVerified: true,
        role: "user",
        twoFactorEnabled: false,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        locale: "en-US",
        createdAt: new Date("2026-01-01"),
        updatedAt: new Date("2026-01-01"),
        ...user,
      },
      session: {
        id: "session-1",
        userId: user.id ?? "owner-1",
        token: "session-token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2026-01-01"),
        updatedAt: new Date("2026-01-01"),
      },
    } as Session,
  };
}

function instance(overrides: Record<string, unknown> = {}) {
  return {
    id: "instance-1",
    userId: "owner-1",
    displayName: "Devbox",
    hostname: "devbox",
    os: "linux",
    arch: "x64",
    cliVersion: "1.0.0",
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

function grant(overrides: Record<string, unknown> = {}) {
  return {
    id: "grant-1",
    instanceId: "instance-1",
    ownerId: "owner-1",
    granteeUserId: null,
    granteeEmail: "grantee@example.test",
    scope: "AGENT",
    projectRoot: "/repo",
    projectRootKey: "/repo",
    status: "PENDING",
    invitedAt: new Date("2026-01-01"),
    acceptedAt: null,
    revokedAt: null,
    expiresAt: null,
    createdBy: "owner-1",
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-01"),
    ...overrides,
  };
}

describe("instanceSharingRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    db.appSetting.findMany.mockResolvedValue([]);
    db.cockpitInstance.findUnique.mockResolvedValue(instance());
    db.user.findUnique.mockResolvedValue(null);
    db.instanceAccessGrant.findMany.mockResolvedValue([]);
    db.instanceAccessGrant.findFirst.mockResolvedValue(null);
    db.instanceAccessGrant.updateMany.mockResolvedValue({ count: 0 });
    db.instanceAccessGrant.create.mockImplementation(async ({ data }) => grant(data));
    db.instanceAccessGrant.update.mockImplementation(async ({ data }) => grant(data));
    db.instanceAuditEvent.create.mockResolvedValue({ id: "audit-1" });
    db.instanceAuditEvent.findMany.mockResolvedValue([]);
    sendEmailMock.mockResolvedValue(undefined);
  });

  it("invites a non-user by email and leaves the grant pending", async () => {
    const client = createRouterClient(instanceSharingRouter, { context: buildContext() });
    const result = await client.invite({
      instanceId: "instance-1",
      email: "Grantee@Example.Test",
      scopes: ["agent"],
      projectRoot: "/repo",
    });

    expect(result.emailSent).toBe(true);
    expect(result.grants[0]).toMatchObject({
      granteeEmail: "grantee@example.test",
      scope: "agent",
      status: "pending",
      projectRoot: "/repo",
    });
    expect(db.instanceAccessGrant.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        granteeEmail: "grantee@example.test",
        granteeUserId: null,
        scope: "AGENT",
        status: "PENDING",
      }),
    });
    expect(renderShareInviteMock).toHaveBeenCalledWith(
      expect.objectContaining({ existingUser: false }),
    );
    expect(sendEmailMock).toHaveBeenCalledWith(
      expect.objectContaining({ to: "grantee@example.test" }),
    );
  });

  it("attaches an existing user id to pending invitations but still requires acceptance", async () => {
    db.user.findUnique.mockResolvedValue({
      id: "grantee-1",
      email: "grantee@example.test",
      locale: "es-MX",
    });
    const client = createRouterClient(instanceSharingRouter, { context: buildContext() });
    const result = await client.invite({
      instanceId: "instance-1",
      email: "grantee@example.test",
      scopes: ["project_files"],
      projectRoot: "/repo",
      expiresIn: "30d",
    });

    expect(result.grants[0]).toMatchObject({ granteeUserId: "grantee-1", status: "pending" });
    expect(renderShareInviteMock).toHaveBeenCalledWith(
      expect.objectContaining({ existingUser: true, locale: "es-MX" }),
    );
  });

  it("rejects non-owners before creating grants", async () => {
    db.cockpitInstance.findUnique.mockResolvedValue(instance({ userId: "someone-else" }));
    const client = createRouterClient(instanceSharingRouter, { context: buildContext() });

    await expect(
      client.invite({ instanceId: "instance-1", email: "g@example.test", scopes: ["agent"] }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("NOT_FOUND");
      return true;
    });
    expect(db.instanceAccessGrant.create).not.toHaveBeenCalled();
  });

  it("requires owner 2FA before granting terminal access", async () => {
    const client = createRouterClient(instanceSharingRouter, { context: buildContext() });

    await expect(
      client.invite({ instanceId: "instance-1", email: "g@example.test", scopes: ["terminal"] }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("FORBIDDEN");
      expect(error.message).toMatch(/two-factor/i);
      return true;
    });
  });

  it("is idempotent for duplicate pending grants", async () => {
    db.instanceAccessGrant.findFirst.mockResolvedValue(grant({ id: "existing-grant" }));
    const client = createRouterClient(instanceSharingRouter, { context: buildContext() });
    const result = await client.invite({
      instanceId: "instance-1",
      email: "grantee@example.test",
      scopes: ["agent"],
      projectRoot: "/repo",
    });

    expect(result.grants[0]?.id).toBe("existing-grant");
    expect(db.instanceAccessGrant.create).not.toHaveBeenCalled();
  });

  it("accepts pending grants only for the matching verified email", async () => {
    db.instanceAccessGrant.findFirst.mockResolvedValue(grant());
    db.instanceAccessGrant.update.mockResolvedValue(
      grant({ status: "ACTIVE", granteeUserId: "grantee-1", acceptedAt: new Date("2026-01-02") }),
    );
    const client = createRouterClient(instanceSharingRouter, {
      context: buildContext({ id: "grantee-1", email: "grantee@example.test" }),
    });

    const result = await client.accept({ grantId: "grant-1" });
    expect(result).toMatchObject({ status: "active", granteeUserId: "grantee-1" });
    expect(db.instanceAccessGrant.update).toHaveBeenCalledWith({
      where: { id: "grant-1" },
      data: expect.objectContaining({ status: "ACTIVE", granteeUserId: "grantee-1" }),
    });
  });

  it("declines pending grants", async () => {
    db.instanceAccessGrant.findFirst.mockResolvedValue(grant());
    db.instanceAccessGrant.update.mockResolvedValue(grant({ status: "DECLINED" }));
    const client = createRouterClient(instanceSharingRouter, {
      context: buildContext({ id: "grantee-1", email: "grantee@example.test" }),
    });

    await expect(client.decline({ grantId: "grant-1" })).resolves.toMatchObject({
      status: "declined",
    });
  });

  it("revokes grants and sends relay disconnects for active grantees", async () => {
    db.instanceAccessGrant.findUnique.mockResolvedValue(
      grant({ status: "ACTIVE", granteeUserId: "grantee-1" }),
    );
    db.instanceAccessGrant.update.mockResolvedValue(
      grant({ status: "REVOKED", granteeUserId: "grantee-1", revokedAt: new Date() }),
    );
    const client = createRouterClient(instanceSharingRouter, { context: buildContext() });

    const result = await client.revoke({ grantId: "grant-1" });
    expect(result.disconnectSent).toBe(true);
    expect(global.fetch).toHaveBeenCalledWith(
      "https://relay.example.test/control",
      expect.objectContaining({
        method: "POST",
        body: expect.stringContaining('"disconnect_user"'),
      }),
    );
  });

  it("surfaces pending grants for a newly signed-in matching email", async () => {
    db.instanceAccessGrant.findMany.mockResolvedValue([{ ...grant(), Instance: instance() }]);
    const client = createRouterClient(instanceSharingRouter, {
      context: buildContext({ id: "grantee-1", email: "grantee@example.test" }),
    });

    await expect(client.listPendingForMe()).resolves.toMatchObject({
      invitations: [{ granteeEmail: "grantee@example.test", instance: { id: "instance-1" } }],
    });
  });
});
