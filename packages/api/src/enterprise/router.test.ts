import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Context } from "../context";
import { createInstanceCredential } from "../lib/instance-credentials";
import { enterpriseRouter } from "./router";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {
    DEPLOYMENT_PROFILE: "enterprise",
    COCKPIT_INSTANCE_LIMIT: 10,
    PRODUCT_NAME: "Flycockpit",
    BETTER_AUTH_SECRET: "1234567890abcdef1234567890abcdef",
    BETTER_AUTH_URL: "https://app.example.test",
  },
}));

vi.mock("../lib/entitlements", () => ({
  can: vi.fn().mockResolvedValue(true),
}));

vi.mock("@flycockpit/queue", () => ({
  enterpriseLogExportQueue: { add: vi.fn().mockResolvedValue({ id: "job-1" }) },
}));

vi.mock("./log-export", () => ({
  createEnterpriseExportDownloadUrl: vi.fn().mockResolvedValue({
    url: "https://signed.example.test/export",
    expiresIn: 300,
    filename: "export.jsonl",
  }),
}));

const { default: prisma } = await import("@flycockpit/db");
const { enterpriseLogExportQueue } = await import("@flycockpit/queue");

const db = prisma as unknown as {
  appSetting: { findMany: MockInstance };
  cockpitInstance: { findUnique: MockInstance; findMany: MockInstance };
  enterpriseOrg: { findFirst: MockInstance; create: MockInstance; update: MockInstance };
  enterpriseOrgMember: {
    findFirst: MockInstance;
    findUnique: MockInstance;
    findMany: MockInstance;
    upsert: MockInstance;
  };
  enterpriseLogBatch: { findFirst: MockInstance; create: MockInstance; count: MockInstance };
  enterpriseLogEvent: { createMany: MockInstance; count: MockInstance; findFirst: MockInstance };
  enterpriseLogExport: { create: MockInstance; findMany: MockInstance; findUnique: MockInstance };
  enterpriseAuditLog: { create: MockInstance };
};
const exportQueue = enterpriseLogExportQueue as unknown as { add: MockInstance };

const org = {
  id: "org-1",
  name: "Acme",
  slug: "acme",
  policyVersion: 7,
  logSyncMandated: true,
  syncSessionEvents: true,
  syncMessageEvents: true,
  syncToolCallEvents: false,
  syncInferenceEvents: true,
  syncTruncationEvents: true,
  includeLocalModels: false,
  backfill: false,
  backlogPolicy: "since_join",
  retentionDays: 365,
  createdAt: new Date("2026-01-01"),
  updatedAt: new Date("2026-01-01"),
};

function buildContext(role = "admin"): Context {
  return {
    session: {
      user: {
        id: "admin-1",
        email: "admin@example.test",
        name: "Admin",
        emailVerified: true,
        role,
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
        userId: "admin-1",
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

function setupInstance() {
  const credential = createInstanceCredential();
  db.cockpitInstance.findUnique.mockResolvedValue({
    id: "instance-1",
    userId: "member-1",
    status: "ACTIVE",
    revokedAt: null,
    secretPrefix: credential.prefix,
    secretHash: credential.hash,
  });
  db.enterpriseOrgMember.findFirst.mockResolvedValue({
    id: "membership-1",
    orgId: "org-1",
    userId: "member-1",
    role: "MEMBER",
    EnterpriseOrg: org,
  });
  return credential;
}

describe("enterpriseRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.appSetting.findMany.mockResolvedValue([]);
    db.enterpriseAuditLog.create.mockResolvedValue({});
    db.enterpriseLogExport.findMany.mockResolvedValue([]);
    db.cockpitInstance.findMany.mockResolvedValue([]);
    db.enterpriseOrgMember.findMany.mockResolvedValue([]);
    db.enterpriseLogEvent.count.mockResolvedValue(0);
    db.enterpriseLogBatch.count.mockResolvedValue(0);
    db.enterpriseLogEvent.findFirst.mockResolvedValue(null);
  });

  it("ingests only event kinds enabled by policy and returns the policy version", async () => {
    const credential = setupInstance();
    db.enterpriseLogBatch.findFirst.mockResolvedValue(null);
    db.enterpriseLogBatch.create.mockResolvedValue({ id: "batch-1" });
    db.enterpriseLogEvent.createMany.mockResolvedValue({ count: 1 });

    const client = createRouterClient(enterpriseRouter, { context: buildContext() });
    const result = await client.ingest({
      instanceId: "instance-1",
      instanceToken: credential.token,
      schemaVersion: 1,
      events: [
        {
          seq: 1,
          sessionId: "session-1",
          kind: "MESSAGE",
          payload: {},
          redactionVersion: "cli-redaction-v1",
        },
        {
          seq: 2,
          sessionId: "session-1",
          kind: "TOOL_CALL",
          payload: { toolName: "shell" },
          redactionVersion: "cli-redaction-v1",
        },
      ],
    });

    expect(result).toEqual({
      duplicate: false,
      acceptedEvents: 1,
      droppedEvents: 1,
      policyVersion: 7,
    });
    expect(db.enterpriseLogEvent.createMany.mock.calls[0]?.[0].data).toHaveLength(1);
    expect(db.enterpriseLogEvent.createMany.mock.calls[0]?.[0].data[0]).toMatchObject({
      kind: "MESSAGE",
      orgId: "org-1",
      userId: "member-1",
    });
  });

  it("treats replayed sequence ranges as idempotent duplicates", async () => {
    const credential = setupInstance();
    db.enterpriseLogBatch.findFirst.mockResolvedValue({ id: "batch-1", eventCount: 1 });

    const client = createRouterClient(enterpriseRouter, { context: buildContext() });
    await expect(
      client.ingest({
        instanceId: "instance-1",
        instanceToken: credential.token,
        events: [
          {
            seq: 9,
            sessionId: "session-1",
            kind: "MESSAGE",
            payload: {},
            redactionVersion: "cli-redaction-v1",
          },
        ],
      }),
    ).resolves.toMatchObject({ duplicate: true, acceptedEvents: 0 });
    expect(db.enterpriseLogEvent.createMany).not.toHaveBeenCalled();
  });

  it("rejects ingest from an instance whose owner is not an org member", async () => {
    const credential = createInstanceCredential();
    db.cockpitInstance.findUnique.mockResolvedValue({
      id: "instance-1",
      userId: "outsider",
      status: "ACTIVE",
      revokedAt: null,
      secretPrefix: credential.prefix,
      secretHash: credential.hash,
    });
    db.enterpriseOrgMember.findFirst.mockResolvedValue(null);

    const client = createRouterClient(enterpriseRouter, { context: buildContext() });
    await expect(
      client.ingest({
        instanceId: "instance-1",
        instanceToken: credential.token,
        events: [
          {
            seq: 1,
            sessionId: "s",
            kind: "MESSAGE",
            payload: {},
            redactionVersion: "cli-redaction-v1",
          },
        ],
      }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("FORBIDDEN");
      return true;
    });
  });

  it("allows org admins to create exports and writes an audit row", async () => {
    db.enterpriseOrgMember.findUnique.mockResolvedValue({ role: "ORG_ADMIN" });
    db.enterpriseLogExport.create.mockResolvedValue({
      id: "export-1",
      orgId: "org-1",
      requestedById: "admin-1",
      format: "CHAT_JSONL",
      status: "QUEUED",
    });

    const client = createRouterClient(enterpriseRouter, { context: buildContext() });
    await expect(
      client.createExport({ format: "CHAT_JSONL", filters: { orgId: "org-1" } }),
    ).resolves.toMatchObject({ id: "export-1" });
    expect(exportQueue.add).toHaveBeenCalledWith("enterprise-log-export", { exportId: "export-1" });
    expect(db.enterpriseAuditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ action: "enterprise.export.create", entityId: "export-1" }),
      }),
    );
  });

  it("blocks non-org-admin export creation", async () => {
    db.enterpriseOrgMember.findUnique.mockResolvedValue({ role: "MEMBER" });
    const client = createRouterClient(enterpriseRouter, { context: buildContext() });
    await expect(
      client.createExport({ format: "RAW_NDJSON", filters: { orgId: "org-1" } }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("FORBIDDEN");
      return true;
    });
    expect(exportQueue.add).not.toHaveBeenCalled();
  });
});
