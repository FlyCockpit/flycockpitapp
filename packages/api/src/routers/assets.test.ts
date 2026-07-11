import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { assetsRouter } from "./assets";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {},
  ADMIN_EMAILS: new Set<string>(),
}));

// The worker-safe env is a distinct module (@flycockpit/env/shared) that the
// router's import graph touches transitively (db / storage / queue). Mocking
// @flycockpit/env/server alone no longer suppresses the real env validators.
vi.mock("@flycockpit/env/shared", () => ({
  env: {},
  S3_FORCE_PATH_STYLE: false,
  VIDEO_ENABLE_4K: false,
}));

// `move`/`delete` exercise the storage helper; mock it so tests never hit S3.
vi.mock("../../lib/storage", () => ({
  deleteStorageObject: vi.fn().mockResolvedValue(undefined),
}));

const { default: prisma } = await import("@flycockpit/db");

const db = prisma as unknown as {
  asset: {
    findMany: MockInstance;
    findUnique: MockInstance;
    update: MockInstance;
    updateMany: MockInstance;
    delete: MockInstance;
    count: MockInstance;
  };
  folder: {
    findUnique: MockInstance;
    findMany: MockInstance;
    upsert: MockInstance;
  };
};

function buildContext(
  sessionOverride?: Partial<{
    user: Partial<Session["user"]>;
    session: Partial<Session["session"]>;
  }> | null,
): Context {
  if (sessionOverride === null) return { session: null };
  return {
    session: {
      user: {
        id: "test-user-id",
        email: "test@example.com",
        name: "Test User",
        emailVerified: true,
        role: "user",
        twoFactorEnabled: false,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
        ...sessionOverride?.user,
      },
      session: {
        id: "test-session-id",
        userId: sessionOverride?.user?.id ?? "test-user-id",
        token: "test-token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
        ...sessionOverride?.session,
      },
    } as Session,
  };
}

function makeAsset(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "asset-1",
    createdAt: new Date(),
    updatedAt: new Date(),
    storageKey: "assets/abc",
    mimeType: "image/png",
    size: 100,
    visibility: "PUBLIC",
    ownerId: "test-user-id",
    width: 100,
    height: 100,
    blurhash: null,
    folderId: null,
    Folder: null,
    ...overrides,
  };
}

describe("assets router", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("listByPath", () => {
    it("filters by exact path (null = root)", async () => {
      db.asset.findMany.mockResolvedValue([makeAsset({ folderId: null, Folder: null })]);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.listByPath();

      expect(result.items).toHaveLength(1);
      const where = (db.asset.findMany.mock.calls[0]?.[0] as { where: Record<string, unknown> })
        .where;
      expect(where.folderId).toBeNull();
      // No folder lookup needed for root.
      expect(db.folder.findUnique).not.toHaveBeenCalled();
    });

    it("filters by a specific path by resolving the Folder first", async () => {
      db.folder.findUnique.mockResolvedValue({ id: "folder-1" });
      db.asset.findMany.mockResolvedValue([
        makeAsset({ folderId: "folder-1", Folder: { path: "/images/blog/" } }),
      ]);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.listByPath({ path: "/images/blog/" });

      expect(result.items[0]?.path).toBe("/images/blog/");
      expect(db.folder.findUnique).toHaveBeenCalledWith({
        where: { path: "/images/blog/" },
        select: { id: true },
      });
      const where = (db.asset.findMany.mock.calls[0]?.[0] as { where: { folderId: string } }).where;
      expect(where.folderId).toBe("folder-1");
    });

    it("returns an empty page when the folder doesn't exist (no false root match)", async () => {
      db.folder.findUnique.mockResolvedValue(null);
      db.asset.findMany.mockResolvedValue([]);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.listByPath({ path: "/nope/" });

      expect(result.items).toHaveLength(0);
      const where = (db.asset.findMany.mock.calls[0]?.[0] as { where: { folderId: string } }).where;
      // Sentinel id ensures we never accidentally return root rows.
      expect(where.folderId).not.toBeNull();
      expect(where.folderId).not.toBe("");
    });

    it("throws NOT_FOUND for non-admin callers", async () => {
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      await expect(client.listByPath()).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("NOT_FOUND");
        return true;
      });
    });

    it("emits asset URLs that point at the visibility-aware endpoints", async () => {
      db.asset.findMany.mockResolvedValue([makeAsset({ id: "asset-1", mimeType: "image/png" })]);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.listByPath();

      expect(result.items[0]?.url).toBe("/api/assets/asset-1");
      expect(result.items[0]?.imageUrl).toBe("/api/images/asset-1");
    });

    it("derives a label distinct from the id for every shape", async () => {
      db.asset.findMany.mockResolvedValue([
        // file-like basename → basename wins
        makeAsset({ id: "a1", storageKey: "assets/xyz/photo.jpg" }),
        // no file extension but has dimensions → mime + dimensions
        makeAsset({
          id: "a2",
          storageKey: "assets/clx123cuid",
          mimeType: "image/png",
          width: 640,
          height: 480,
        }),
        // no extension, no dimensions → short id suffix prefixed with …
        makeAsset({
          id: "ghk2v9t7eca3rp1oel8o0j2b",
          storageKey: "assets/ghk2v9t7eca3rp1oel8o0j2b",
          mimeType: "application/octet-stream",
          width: null,
          height: null,
        }),
      ]);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.listByPath();

      expect(result.items[0]?.label).toBe("photo.jpg");
      expect(result.items[1]?.label).toBe("image/png · 640×480");
      expect(result.items[2]?.label).toBe("…l8o0j2b");
      // The core contract: label MUST never equal the bare id.
      for (const item of result.items) {
        expect(item.label).not.toBe(item.id);
      }
    });
  });

  describe("listPaths", () => {
    it("merges the folder list with a synthetic root row", async () => {
      db.folder.findMany.mockResolvedValue([
        { id: "f1", path: "/images/", _count: { Assets: 3 } },
        { id: "f2", path: "/images/blog/", _count: { Assets: 2 } },
      ]);
      db.asset.count.mockResolvedValue(5);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.listPaths();

      expect(result).toEqual([
        { path: null, count: 5 },
        { path: "/images/", count: 3 },
        { path: "/images/blog/", count: 2 },
      ]);
      expect(db.asset.count).toHaveBeenCalledWith({ where: { folderId: null } });
    });

    it("omits the root row when no folder-less assets exist", async () => {
      db.folder.findMany.mockResolvedValue([{ id: "f1", path: "/images/", _count: { Assets: 3 } }]);
      db.asset.count.mockResolvedValue(0);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.listPaths();
      expect(result).toEqual([{ path: "/images/", count: 3 }]);
    });
  });

  describe("search", () => {
    it("filters to public assets when publicOnly is true", async () => {
      db.asset.findMany.mockResolvedValue([makeAsset({ visibility: "PUBLIC" })]);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      await client.search({ query: "", limit: 10, publicOnly: true });

      expect(db.asset.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            mimeType: { startsWith: "image/" },
            visibility: "PUBLIC",
          }),
        }),
      );
    });
  });

  describe("move", () => {
    it("upserts the destination Folder then updateMany on folderId", async () => {
      db.folder.upsert.mockResolvedValue({ id: "folder-1" });
      db.asset.updateMany.mockResolvedValue({ count: 2 });

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.move({ ids: ["a", "b"], path: "/images/blog/" });

      expect(result.count).toBe(2);
      expect(db.folder.upsert).toHaveBeenCalledWith({
        where: { path: "/images/blog/" },
        create: { path: "/images/blog/" },
        update: {},
        select: { id: true },
      });
      expect(db.asset.updateMany).toHaveBeenCalledWith({
        where: { id: { in: ["a", "b"] } },
        data: { folderId: "folder-1" },
      });
    });

    it("moves to root (folderId null) without touching Folder", async () => {
      db.asset.updateMany.mockResolvedValue({ count: 1 });

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.move({ ids: ["a"], path: null });

      expect(result.count).toBe(1);
      expect(db.folder.upsert).not.toHaveBeenCalled();
      expect(db.asset.updateMany).toHaveBeenCalledWith({
        where: { id: { in: ["a"] } },
        data: { folderId: null },
      });
    });

    it("rejects malformed paths", async () => {
      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      await expect(client.move({ ids: ["a"], path: "no-leading-slash" })).rejects.toThrow();
      expect(db.asset.updateMany).not.toHaveBeenCalled();
    });
  });

  describe("setVisibility", () => {
    it("flips visibility and returns the serialized asset", async () => {
      db.asset.findUnique.mockResolvedValue(makeAsset({ visibility: "RESTRICTED" }));
      db.asset.update.mockResolvedValue(makeAsset({ visibility: "PUBLIC" }));

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.setVisibility({ id: "asset-1", visibility: "PUBLIC" });

      expect(result.visibility).toBe("PUBLIC");
      expect(db.asset.update).toHaveBeenCalledWith({
        where: { id: "asset-1" },
        data: { visibility: "PUBLIC" },
        include: { Folder: true },
      });
    });

    it("returns NOT_FOUND for unknown ids", async () => {
      db.asset.findUnique.mockResolvedValue(null);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      await expect(client.setVisibility({ id: "nope", visibility: "PUBLIC" })).rejects.toSatisfy(
        (err: ORPCError) => {
          expect(err.code).toBe("NOT_FOUND");
          return true;
        },
      );
      expect(db.asset.update).not.toHaveBeenCalled();
    });

    it("enforces the admin gate", async () => {
      const ctx = buildContext({ user: { role: "user" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      await expect(client.setVisibility({ id: "asset-1", visibility: "PUBLIC" })).rejects.toSatisfy(
        (err: ORPCError) => {
          expect(err.code).toBe("NOT_FOUND");
          return true;
        },
      );
      expect(db.asset.update).not.toHaveBeenCalled();
    });
  });

  describe("delete", () => {
    it("removes the row and best-effort deletes the storage object", async () => {
      db.asset.findUnique.mockResolvedValue(makeAsset());
      db.asset.delete.mockResolvedValue(makeAsset());

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      const result = await client.delete({ id: "asset-1" });

      expect(result.success).toBe(true);
      expect(db.asset.delete).toHaveBeenCalledWith({ where: { id: "asset-1" } });
    });

    it("returns NOT_FOUND for unknown ids", async () => {
      db.asset.findUnique.mockResolvedValue(null);

      const ctx = buildContext({ user: { role: "admin" } });
      const client = createRouterClient(assetsRouter, { context: ctx });

      await expect(client.delete({ id: "nope" })).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("NOT_FOUND");
        return true;
      });
    });
  });
});
