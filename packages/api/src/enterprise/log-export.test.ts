import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

vi.mock("../lib/storage", () => ({
  putStorageObject: vi.fn(),
  presignGet: vi
    .fn()
    .mockResolvedValue({ url: "https://signed.example.test/export", expiresIn: 300 }),
}));

const { default: prisma } = await import("@flycockpit/db");
const { putStorageObject } = await import("../lib/storage");
const { generateEnterpriseLogExport, pruneEnterpriseLogs } = await import("./log-export");

const db = prisma as unknown as {
  enterpriseLogExport: { findUnique: ReturnType<typeof vi.fn>; update: ReturnType<typeof vi.fn> };
  enterpriseLogEvent: { findMany: ReturnType<typeof vi.fn>; deleteMany: ReturnType<typeof vi.fn> };
  enterpriseLogBatch: { deleteMany: ReturnType<typeof vi.fn> };
  enterpriseOrg: { findMany: ReturnType<typeof vi.fn> };
  enterpriseAuditLog: { create: ReturnType<typeof vi.fn> };
};
const storage = putStorageObject as unknown as ReturnType<typeof vi.fn>;

describe("enterprise log exports", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.enterpriseAuditLog.create.mockResolvedValue({});
  });

  it("generates an artifact, stores it, updates manifest counts, and audits completion", async () => {
    db.enterpriseLogExport.findUnique.mockResolvedValue({
      id: "export-1",
      orgId: "org-1",
      requestedById: "admin-1",
      format: "RAW_NDJSON",
      filters: { orgId: "org-1" },
    });
    db.enterpriseLogExport.update.mockImplementation(async ({ data }) => ({
      id: "export-1",
      ...data,
    }));
    db.enterpriseLogEvent.findMany.mockResolvedValue([
      {
        id: "event-1",
        orgId: "org-1",
        userId: "user-1",
        instanceId: "instance-1",
        seq: 1,
        sessionId: "session-1",
        projectRoot: "/repo",
        kind: "MESSAGE",
        occurredAt: new Date("2026-01-01T00:00:00.000Z"),
        model: "gpt-test",
        role: "user",
        content: "hello",
        payload: {},
        redactionVersion: "cli-redaction-v1",
        truncated: false,
      },
    ]);
    storage.mockResolvedValue(undefined);

    await expect(generateEnterpriseLogExport("export-1")).resolves.toMatchObject({
      status: "READY",
      manifest: { eventCount: 1, sessionCount: 1 },
    });
    expect(storage).toHaveBeenCalledWith(
      "enterprise-exports/org-1/export-1/raw_ndjson.ndjson",
      expect.any(Buffer),
      "application/x-ndjson; charset=utf-8",
    );
    expect(db.enterpriseAuditLog.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ action: "enterprise.export.completed" }),
      }),
    );
  });

  it("prunes events and batches past each org retention window", async () => {
    db.enterpriseOrg.findMany.mockResolvedValue([{ id: "org-1", retentionDays: 30 }]);
    db.enterpriseLogEvent.deleteMany.mockResolvedValue({ count: 3 });
    db.enterpriseLogBatch.deleteMany.mockResolvedValue({ count: 1 });

    await expect(pruneEnterpriseLogs(new Date("2026-02-01T00:00:00.000Z"))).resolves.toEqual([
      { orgId: "org-1", deletedEvents: 3, deletedBatches: 1 },
    ]);
    expect(db.enterpriseLogEvent.deleteMany).toHaveBeenCalledWith({
      where: { orgId: "org-1", createdAt: { lt: new Date("2026-01-02T00:00:00.000Z") } },
    });
  });
});
