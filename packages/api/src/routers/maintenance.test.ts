import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

const { default: prisma } = await import("@flycockpit/db");
const { maintenanceRouter } = await import("./maintenance");

const db = prisma as unknown as {
  appSetting: { findUnique: MockInstance };
  asset: { count: MockInstance; updateMany: MockInstance };
  video: { count: MockInstance; updateMany: MockInstance };
};

function buildContext(role: "admin" | "user" | null): Context {
  if (role === null) return { session: null };
  return {
    session: {
      user: {
        id: "admin-user-id",
        email: "admin@example.com",
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
        id: "test-session-id",
        userId: "admin-user-id",
        token: "test-token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
      },
    } as Session,
  };
}

describe("maintenanceRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.appSetting.findUnique.mockResolvedValue(null);
    db.asset.count.mockResolvedValue(0);
    db.video.count.mockResolvedValue(0);
    db.asset.updateMany.mockResolvedValue({ count: 0 });
    db.video.updateMany.mockResolvedValue({ count: 0 });
  });

  it("reports legacy enum backfill status", async () => {
    db.asset.count.mockResolvedValueOnce(5);
    db.video.count.mockResolvedValueOnce(7);

    const client = createRouterClient(maintenanceRouter, { context: buildContext("admin") });

    await expect(client.legacyEnumBackfillStatus()).resolves.toEqual({
      assetsRemaining: 5,
      videosRemaining: 7,
      totalRemaining: 12,
    });
  });

  it("backfills nullable enum columns from legacy booleans", async () => {
    db.asset.updateMany.mockResolvedValueOnce({ count: 5 }).mockResolvedValueOnce({ count: 6 });
    db.video.updateMany.mockResolvedValueOnce({ count: 7 }).mockResolvedValueOnce({ count: 8 });

    const client = createRouterClient(maintenanceRouter, { context: buildContext("admin") });
    const result = await client.backfillLegacyEnums();

    expect(result.changed).toEqual({
      assetsServerVerified: 5,
      assetsClientHint: 6,
      videosInclude4k: 7,
      videosStandard: 8,
    });
    expect(db.asset.updateMany).toHaveBeenNthCalledWith(1, {
      where: { metadataState: null, isMetadataVerified: true },
      data: { metadataState: "SERVER_VERIFIED" },
    });
    expect(db.asset.updateMany).toHaveBeenNthCalledWith(2, {
      where: { metadataState: null, isMetadataVerified: false },
      data: { metadataState: "CLIENT_HINT" },
    });
    expect(db.video.updateMany).toHaveBeenNthCalledWith(1, {
      where: { ladderPolicy: null, ladderIncludes4k: true },
      data: { ladderPolicy: "INCLUDE_4K" },
    });
    expect(db.video.updateMany).toHaveBeenNthCalledWith(2, {
      where: { ladderPolicy: null, ladderIncludes4k: false },
      data: { ladderPolicy: "STANDARD" },
    });
  });

  it("404s status and backfill procedures for non-admins", async () => {
    const client = createRouterClient(maintenanceRouter, { context: buildContext("user") });

    await expect(client.legacyEnumBackfillStatus()).rejects.toSatisfy((err: ORPCError) => {
      expect(err.code).toBe("NOT_FOUND");
      return true;
    });
    await expect(client.backfillLegacyEnums()).rejects.toSatisfy((err: ORPCError) => {
      expect(err.code).toBe("NOT_FOUND");
      return true;
    });
  });
});
