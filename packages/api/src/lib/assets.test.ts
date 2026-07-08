import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {},
  ADMIN_EMAILS: new Set<string>(),
}));

// Stub storage so the lib sees a non-null `storage` and the helpers we call
// are intercepted before they reach the real S3 client.
vi.mock("./storage", () => {
  return {
    storage: { bucket: "test-bucket", client: {} },
    presignPut: vi.fn(),
    headStorageObject: vi.fn(),
    getStorageObject: vi.fn(),
    putStorageObject: vi.fn(),
    deleteStorageObject: vi.fn(),
  };
});

const { default: prisma } = await import("@flycockpit/db");
const storageModule = await import("./storage");
const { AssetError, finalizeAsset, presignAsset } = await import("./assets");

const db = prisma as unknown as {
  asset: {
    create: MockInstance;
    findUnique: MockInstance;
    update: MockInstance;
  };
};

const presignPutMock = storageModule.presignPut as unknown as MockInstance;
const headMock = storageModule.headStorageObject as unknown as MockInstance;

function makeRow(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "asset-1",
    storageKey: "assets/abc",
    mimeType: "image/png",
    size: 1024,
    visibility: "RESTRICTED",
    ownerId: "user-1",
    width: 100,
    height: 100,
    blurhash: "L00",
    status: "PENDING",
    metadataState: "CLIENT_HINT",
    createdAt: new Date(),
    updatedAt: new Date(),
    path: null,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("presignAsset", () => {
  it("creates a PENDING row with the client-supplied hint and returns the signed URL", async () => {
    presignPutMock.mockResolvedValue({
      url: "https://s3.example/signed",
      headers: { "Content-Type": "image/png", "Content-Length": "1024" },
      expiresIn: 300,
    });
    db.asset.create.mockResolvedValue(makeRow());

    const result = await presignAsset({
      mimeType: "image/png",
      size: 1024,
      visibility: "RESTRICTED",
      ownerId: "user-1",
      hint: { width: 100, height: 100, blurhash: "L00" },
    });

    expect(result.assetId).toBe("asset-1");
    expect(result.upload.url).toBe("https://s3.example/signed");
    expect(db.asset.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          status: "PENDING",
          metadataState: "CLIENT_HINT",
          width: 100,
          height: 100,
          blurhash: "L00",
        }),
      }),
    );
  });

  it("nulls missing hint fields rather than persisting undefined", async () => {
    presignPutMock.mockResolvedValue({ url: "u", headers: {}, expiresIn: 300 });
    db.asset.create.mockResolvedValue(makeRow({ width: null, height: null, blurhash: null }));

    await presignAsset({
      mimeType: "application/pdf",
      size: 50,
      visibility: "PUBLIC",
      ownerId: "user-1",
    });

    expect(db.asset.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ width: null, height: null, blurhash: null }),
      }),
    );
  });
});

describe("finalizeAsset", () => {
  const viewer = { kind: "user" as const, userId: "user-1", role: "user" };

  it("flips status to READY when HEAD confirms the object", async () => {
    db.asset.findUnique.mockResolvedValue(makeRow());
    headMock.mockResolvedValue({ contentLength: 1024, contentType: "image/png" });
    db.asset.update.mockResolvedValue(makeRow({ status: "READY" }));

    const meta = await finalizeAsset({ assetId: "asset-1", viewer });

    expect(meta.status).toBe("READY");
    expect(db.asset.update).toHaveBeenCalledWith({
      where: { id: "asset-1" },
      data: { status: "READY" },
    });
  });

  it("is idempotent on already-READY rows (no HEAD, no update)", async () => {
    db.asset.findUnique.mockResolvedValue(makeRow({ status: "READY" }));

    const meta = await finalizeAsset({ assetId: "asset-1", viewer });

    expect(meta.status).toBe("READY");
    expect(headMock).not.toHaveBeenCalled();
    expect(db.asset.update).not.toHaveBeenCalled();
  });

  it("throws UPLOAD_MISSING when HEAD returns null", async () => {
    db.asset.findUnique.mockResolvedValue(makeRow());
    headMock.mockResolvedValue(null);

    await expect(finalizeAsset({ assetId: "asset-1", viewer })).rejects.toMatchObject({
      name: "AssetError",
      code: "UPLOAD_MISSING",
    });
    expect(db.asset.update).not.toHaveBeenCalled();
  });

  it("throws SIZE_MISMATCH when stored size differs from presigned size", async () => {
    db.asset.findUnique.mockResolvedValue(makeRow({ size: 1024 }));
    headMock.mockResolvedValue({ contentLength: 999, contentType: "image/png" });

    await expect(finalizeAsset({ assetId: "asset-1", viewer })).rejects.toMatchObject({
      name: "AssetError",
      code: "SIZE_MISMATCH",
    });
  });

  it("404s a non-owner caller (presence is not leaked)", async () => {
    db.asset.findUnique.mockResolvedValue(makeRow({ ownerId: "someone-else" }));

    await expect(
      finalizeAsset({
        assetId: "asset-1",
        viewer: { kind: "user", userId: "user-1", role: "user" },
      }),
    ).rejects.toMatchObject({ name: "AssetError", code: "NOT_FOUND" });
    expect(headMock).not.toHaveBeenCalled();
  });

  it("admin can finalize an asset they don't own", async () => {
    db.asset.findUnique.mockResolvedValue(makeRow({ ownerId: "someone-else" }));
    headMock.mockResolvedValue({ contentLength: 1024, contentType: "image/png" });
    db.asset.update.mockResolvedValue(makeRow({ ownerId: "someone-else", status: "READY" }));

    const meta = await finalizeAsset({
      assetId: "asset-1",
      viewer: { kind: "user", userId: "admin-1", role: "admin" },
    });
    expect(meta.status).toBe("READY");
  });

  it("throws NOT_FOUND for an unknown asset id", async () => {
    db.asset.findUnique.mockResolvedValue(null);
    await expect(finalizeAsset({ assetId: "missing", viewer })).rejects.toMatchObject({
      name: "AssetError",
      code: "NOT_FOUND",
    });
  });
});

describe("AssetError", () => {
  it("preserves the code field for HTTP mapping", () => {
    const err = new AssetError("UPLOAD_MISSING", "x");
    expect(err.code).toBe("UPLOAD_MISSING");
    expect(err.name).toBe("AssetError");
  });
});
