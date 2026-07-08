import type { Session } from "@flycockpit/auth";
import { createRouterClient, ORPCError } from "@orpc/server";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  const db = mockDeep();
  db.appSetting.findMany.mockResolvedValue([]);
  return { default: db };
});

vi.mock("@flycockpit/env/server", () => ({
  env: {
    VIDEO_UPLOAD_MAX_BYTES: 10 * 1024 * 1024 * 1024,
    IMAGE_TRANSFORM_MAX_INPUT_PIXELS: 50_000_000,
  },
  ADMIN_EMAILS: new Set<string>(),
  VIDEO_ENABLE_4K: false,
}));

// Mock the queue producers so .add() resolves and we can assert on calls.
const transcodeVideoAdd = vi.fn().mockResolvedValue({ id: "j-1" });
const transcodeAudioTrackAdd = vi.fn().mockResolvedValue({ id: "j-2" });
const cleanupVideosAdd = vi.fn().mockResolvedValue({ id: "j-3" });
vi.mock("@flycockpit/queue", () => ({
  transcodeVideoQueue: { add: transcodeVideoAdd },
  transcodeAudioTrackQueue: { add: transcodeAudioTrackAdd },
  cleanupVideosQueue: { add: cleanupVideosAdd },
}));

// Mock the storage layer so we don't try to talk to S3.
const createMultipart = vi.fn();
const presignPart = vi.fn();
const completeMultipart = vi.fn();
const abortMultipart = vi.fn();
const headStorageObject = vi.fn();
const putStorageObject = vi.fn();
const deleteStorageObject = vi.fn();
const listStorageObjects = vi.fn();
async function* emptyList() {
  // no-op generator
}
vi.mock("../lib/storage", () => ({
  createMultipartUpload: (key: string, mime: string) => createMultipart(key, mime),
  presignUploadPart: (key: string, uploadId: string, partNumber: number) =>
    presignPart(key, uploadId, partNumber),
  completeMultipartUpload: (key: string, uploadId: string, parts: unknown) =>
    completeMultipart(key, uploadId, parts),
  abortMultipartUpload: (key: string, uploadId: string) => abortMultipart(key, uploadId),
  headStorageObject: (key: string) => headStorageObject(key),
  putStorageObject: (key: string, body: unknown, mime: string) => putStorageObject(key, body, mime),
  deleteStorageObject: (key: string) => deleteStorageObject(key),
  listStorageObjects: (prefix: string) => listStorageObjects(prefix),
  storage: { bucket: "test", client: {} },
  getStorageObjectRange: vi.fn(),
}));

const { default: prisma } = await import("@flycockpit/db");
const { videosRouter } = await import("./videos");

const db = prisma as unknown as {
  $transaction: MockInstance;
  video: {
    findUnique: MockInstance;
    findMany: MockInstance;
    create: MockInstance;
    update: MockInstance;
    delete: MockInstance;
    deleteMany: MockInstance;
  };
  videoAudioTrack: {
    findUnique: MockInstance;
    findMany: MockInstance;
    create: MockInstance;
    delete: MockInstance;
    deleteMany: MockInstance;
    update: MockInstance;
    upsert: MockInstance;
    updateMany: MockInstance;
  };
  videoSubtitleTrack: {
    findUnique: MockInstance;
    findMany: MockInstance;
    upsert: MockInstance;
    delete: MockInstance;
    updateMany: MockInstance;
  };
  videoRendition: {
    findMany: MockInstance;
  };
};

// `mockDeep` returns chained mocks for any property access, but `$transaction`
// needs to actually run the callback with a tx client. Wire it to invoke the
// passed function with the same deep mock so reads/writes inside the
// transaction hit the regular per-model mocks.
db.$transaction.mockImplementation(async (fn: unknown) => {
  if (typeof fn === "function") return await (fn as (tx: typeof db) => Promise<unknown>)(db);
  return fn;
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildContext(override?: Partial<Session["user"]> | null): Context {
  if (override === null) return { session: null };
  return {
    session: {
      user: {
        id: "user-1",
        email: "test@example.com",
        name: "Test",
        emailVerified: true,
        role: "user",
        twoFactorEnabled: false,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        ...override,
      },
      session: {
        id: "session-1",
        userId: override?.id ?? "user-1",
        token: "t",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: null,
        userAgent: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    } as Session,
  };
}

function makeVideoRow(over: Record<string, unknown> = {}) {
  return {
    id: "vid-1",
    title: "Demo",
    description: null,
    status: "PENDING",
    failureReason: null,
    visibility: "RESTRICTED",
    ownerId: "user-1",
    sourceLocale: "en-US",
    durationSeconds: null,
    width: null,
    height: null,
    sourceKey: "rawVideos/vid-1/source",
    sourceSize: null,
    sourceMimeType: "video/mp4",
    posterAssetId: null,
    ladderPolicy: "STANDARD",
    createdAt: new Date(),
    updatedAt: new Date(),
    uploadHeartbeatAt: new Date(),
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("videosRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listStorageObjects.mockImplementation(() => emptyList());
  });

  describe("start", () => {
    it("creates a PENDING Video row and initiates a multipart upload", async () => {
      createMultipart.mockResolvedValue({ uploadId: "mpu-1" });
      db.video.create.mockResolvedValue(makeVideoRow());

      const client = createRouterClient(videosRouter, { context: buildContext() });

      const result = await client.start({
        title: "Demo",
        description: null,
        visibility: "RESTRICTED",
        sourceLocale: "en-US",
        sourceMimeType: "video/mp4",
        sourceSize: 1024,
        ladderPolicy: "STANDARD",
      });

      expect(result.uploadId).toBe("mpu-1");
      expect(result.storageKey).toMatch(/^rawVideos\/[a-f0-9-]+\/source$/);
      expect(db.video.create).toHaveBeenCalledOnce();
      expect(createMultipart).toHaveBeenCalledOnce();
    });

    it("rejects sources over VIDEO_UPLOAD_MAX_BYTES", async () => {
      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(
        client.start({
          title: "Big",
          description: null,
          visibility: "RESTRICTED",
          sourceLocale: "en-US",
          sourceMimeType: "video/mp4",
          sourceSize: 11 * 1024 * 1024 * 1024,
          ladderPolicy: "STANDARD",
        }),
      ).rejects.toThrow();
    });

    it("requires authentication", async () => {
      const client = createRouterClient(videosRouter, { context: buildContext(null) });
      await expect(
        client.start({
          title: "x",
          description: null,
          visibility: "RESTRICTED",
          sourceLocale: "en-US",
          sourceMimeType: "video/mp4",
          sourceSize: 1024,
          ladderPolicy: "STANDARD",
        }),
      ).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("UNAUTHORIZED");
        return true;
      });
    });
  });

  describe("complete", () => {
    it("finalizes the multipart upload, flips to TRANSCODING, enqueues transcode job", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow({ status: "PENDING" }));
      headStorageObject.mockResolvedValue({ contentLength: 2048, contentType: "video/mp4" });
      db.video.update.mockResolvedValue(makeVideoRow({ status: "TRANSCODING" }));

      const client = createRouterClient(videosRouter, { context: buildContext() });

      const result = await client.complete({
        videoId: "vid-1",
        uploadId: "mpu-1",
        parts: [{ partNumber: 1, etag: "etag-1" }],
      });

      expect(result.status).toBe("TRANSCODING");
      expect(completeMultipart).toHaveBeenCalledOnce();
      // Allow for the fire-and-forget enqueue to run. The procedure dispatches
      // asynchronously, so we wait one microtask.
      await Promise.resolve();
      expect(transcodeVideoAdd).toHaveBeenCalledWith("transcode-video", {
        videoId: "vid-1",
      });
    });

    it("404s for a non-owner", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow({ ownerId: "other-user" }));

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(
        client.complete({
          videoId: "vid-1",
          uploadId: "mpu-1",
          parts: [{ partNumber: 1, etag: "etag-1" }],
        }),
      ).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("NOT_FOUND");
        return true;
      });
    });

    it("admins can complete any user's upload", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow({ ownerId: "other-user" }));
      headStorageObject.mockResolvedValue({ contentLength: 1, contentType: "video/mp4" });
      db.video.update.mockResolvedValue(makeVideoRow({ status: "TRANSCODING" }));

      const client = createRouterClient(videosRouter, {
        context: buildContext({ role: "admin" }),
      });
      const result = await client.complete({
        videoId: "vid-1",
        uploadId: "mpu-1",
        parts: [{ partNumber: 1, etag: "e" }],
      });
      expect(result.status).toBe("TRANSCODING");
    });

    it("rejects completion when the stored video object size differs from the accepted size", async () => {
      db.video.findUnique.mockResolvedValue(
        makeVideoRow({ status: "PENDING", sourceSize: BigInt(2048) }),
      );
      headStorageObject.mockResolvedValue({ contentLength: 1024, contentType: "video/mp4" });

      const client = createRouterClient(videosRouter, { context: buildContext() });

      await expect(
        client.complete({
          videoId: "vid-1",
          uploadId: "mpu-1",
          parts: [{ partNumber: 1, etag: "etag-1" }],
        }),
      ).rejects.toThrow();

      expect(db.video.update).not.toHaveBeenCalled();
      expect(transcodeVideoAdd).not.toHaveBeenCalled();
    });
  });

  describe("abort", () => {
    it("aborts the multipart, deletes the PENDING row, and sweeps the source bytes", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow());
      abortMultipart.mockResolvedValue(undefined);
      db.video.deleteMany.mockResolvedValue({ count: 1 });
      deleteStorageObject.mockResolvedValue(undefined);

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.abort({ videoId: "vid-1", uploadId: "mpu-1" });

      expect(result.ok).toBe(true);
      expect(abortMultipart).toHaveBeenCalledWith("rawVideos/vid-1/source", "mpu-1");
      expect(db.video.deleteMany).toHaveBeenCalledWith({
        where: { id: "vid-1", status: "PENDING" },
      });
      expect(deleteStorageObject).toHaveBeenCalledWith("rawVideos/vid-1/source");
    });

    it("does not delete source bytes if abort loses the pending-row race", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow());
      abortMultipart.mockResolvedValue(undefined);
      db.video.deleteMany.mockResolvedValue({ count: 0 });

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.abort({ videoId: "vid-1", uploadId: "mpu-1" });

      expect(result.ok).toBe(true);
      expect(abortMultipart).toHaveBeenCalledWith("rawVideos/vid-1/source", "mpu-1");
      expect(db.video.deleteMany).toHaveBeenCalledWith({
        where: { id: "vid-1", status: "PENDING" },
      });
      expect(deleteStorageObject).not.toHaveBeenCalled();
    });

    it("no-ops for a non-owner and does not touch storage or the row", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow({ ownerId: "other-user" }));

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.abort({ videoId: "vid-1", uploadId: "mpu-1" });

      expect(result.ok).toBe(true);
      expect(abortMultipart).not.toHaveBeenCalled();
      expect(deleteStorageObject).not.toHaveBeenCalled();
      expect(db.video.deleteMany).not.toHaveBeenCalled();
    });
  });

  describe("get permissions", () => {
    it("returns full payload for the owner", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow({ status: "READY" }));
      db.videoAudioTrack.findMany.mockResolvedValue([]);
      db.videoSubtitleTrack.findMany.mockResolvedValue([]);
      db.videoRendition.findMany.mockResolvedValue([]);

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.get({ id: "vid-1" });
      expect(result.id).toBe("vid-1");
      expect(result.playlistUrl).toBe("/api/videos/vid-1/playlist.m3u8");
    });

    it("404s a RESTRICTED video for a non-owner anonymous viewer", async () => {
      db.video.findUnique.mockResolvedValue(
        makeVideoRow({ status: "READY", visibility: "RESTRICTED", ownerId: "other-user" }),
      );

      const client = createRouterClient(videosRouter, { context: buildContext(null) });
      await expect(client.get({ id: "vid-1" })).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("NOT_FOUND");
        return true;
      });
    });

    it("allows anonymous viewers on a PUBLIC + READY video", async () => {
      db.video.findUnique.mockResolvedValue(
        makeVideoRow({ status: "READY", visibility: "PUBLIC", ownerId: "other-user" }),
      );
      db.videoAudioTrack.findMany.mockResolvedValue([]);
      db.videoSubtitleTrack.findMany.mockResolvedValue([]);
      db.videoRendition.findMany.mockResolvedValue([]);

      const client = createRouterClient(videosRouter, { context: buildContext(null) });
      const result = await client.get({ id: "vid-1" });
      expect(result.visibility).toBe("PUBLIC");
    });

    it("blocks anonymous viewers on a PUBLIC + non-READY video (no leaking unfinished encodes)", async () => {
      db.video.findUnique.mockResolvedValue(
        makeVideoRow({ status: "TRANSCODING", visibility: "PUBLIC", ownerId: "other-user" }),
      );

      const client = createRouterClient(videosRouter, { context: buildContext(null) });
      await expect(client.get({ id: "vid-1" })).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("NOT_FOUND");
        return true;
      });
    });
  });

  describe("delete", () => {
    it("requires ownership", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow({ ownerId: "other-user" }));
      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(client.delete({ id: "vid-1" })).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("NOT_FOUND");
        return true;
      });
      expect(db.video.delete).not.toHaveBeenCalled();
    });

    it("deletes the owner's video", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow());
      db.video.delete.mockResolvedValue(undefined);

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.delete({ id: "vid-1" });
      expect(result.ok).toBe(true);
      expect(db.video.delete).toHaveBeenCalledOnce();
      expect(listStorageObjects).toHaveBeenCalledWith("videos/vid-1/");
      expect(listStorageObjects).toHaveBeenCalledWith("rawVideos/vid-1/");
      expect(db.video.delete.mock.invocationCallOrder[0]).toBeLessThan(
        listStorageObjects.mock.invocationCallOrder[0]!,
      );
    });

    it("does not delete video storage if the row delete fails", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow());
      db.video.delete.mockRejectedValue(new Error("db unavailable"));

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(client.delete({ id: "vid-1" })).rejects.toThrow("db unavailable");

      expect(listStorageObjects).not.toHaveBeenCalled();
      expect(deleteStorageObject).not.toHaveBeenCalled();
    });
  });

  describe("audio tracks", () => {
    it("heartbeats pending audio uploads", async () => {
      db.videoAudioTrack.findUnique.mockResolvedValue({
        id: "aud-1",
        videoId: "vid-1",
        status: "PENDING",
        sourceKey: "rawVideos/vid-1/a/aud-1/source",
        Video: { ownerId: "user-1" },
      });
      db.videoAudioTrack.update.mockResolvedValue({});

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.heartbeatAudioTrack({ audioTrackId: "aud-1" });

      expect(result.ok).toBe(true);
      expect(db.videoAudioTrack.update).toHaveBeenCalledWith({
        where: { id: "aud-1" },
        data: { uploadHeartbeatAt: expect.any(Date) },
      });
    });

    it("refreshes the audio upload heartbeat when presigning parts", async () => {
      db.videoAudioTrack.findUnique.mockResolvedValue({
        id: "aud-1",
        videoId: "vid-1",
        status: "PENDING",
        sourceKey: "rawVideos/vid-1/a/aud-1/source",
        Video: { ownerId: "user-1" },
      });
      db.videoAudioTrack.update.mockResolvedValue({});
      presignPart.mockResolvedValue({ url: "https://upload.example/part-1", partNumber: 1 });

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.presignAudioTrackParts({
        audioTrackId: "aud-1",
        uploadId: "mpu-1",
        partNumbers: [1],
      });

      expect(result.parts).toHaveLength(1);
      expect(db.videoAudioTrack.update).toHaveBeenCalledWith({
        where: { id: "aud-1" },
        data: { uploadHeartbeatAt: expect.any(Date) },
      });
    });

    it("aborts the multipart and surfaces CONFLICT when two callers race the same (videoId, locale)", async () => {
      // Owner's READY video — gate checks pass.
      db.video.findUnique.mockResolvedValue(
        makeVideoRow({ status: "READY", sourceLocale: "en-US" }),
      );
      // Multipart create succeeds.
      createMultipart.mockResolvedValue({ uploadId: "mpu-aud-1" });
      // Inside the transaction, `findUnique` re-reads — still no row.
      db.videoAudioTrack.findUnique.mockResolvedValueOnce(null);
      // The losing transaction's create hits the unique-constraint violation.
      // The codebase's `isUniqueConstraintError` is duck-typed on `.code`, so
      // a plain object reproduces a P2002 from Prisma without pulling in the
      // Prisma client type (which is fully mocked in this file).
      const p2002 = Object.assign(new Error("Unique constraint failed"), { code: "P2002" });
      db.videoAudioTrack.create.mockRejectedValue(p2002);
      abortMultipart.mockResolvedValue(undefined);

      const client = createRouterClient(videosRouter, { context: buildContext() });

      await expect(
        client.startAudioTrack({
          videoId: "vid-1",
          locale: "es-MX",
          label: "Spanish",
          mimeType: "audio/mp4",
          size: 1024,
        }),
      ).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("CONFLICT");
        return true;
      });

      // The orphan multipart must be aborted with the same key+uploadId.
      expect(abortMultipart).toHaveBeenCalledOnce();
      const [abortedKey, abortedUploadId] = abortMultipart.mock.calls[0] ?? [];
      expect(abortedKey).toMatch(/^rawVideos\/vid-1\/a\/[a-f0-9-]+\/source$/);
      expect(abortedUploadId).toBe("mpu-aud-1");
    });

    it("deletes the exact replaced audio source after the replacement row commits", async () => {
      db.video.findUnique.mockResolvedValue(
        makeVideoRow({ status: "READY", sourceLocale: "en-US" }),
      );
      createMultipart.mockResolvedValue({ uploadId: "mpu-aud-1" });
      db.videoAudioTrack.findUnique.mockResolvedValue({
        id: "aud-old",
        videoId: "vid-1",
        locale: "es-MX",
        sourceKey: "rawVideos/vid-1/a/aud-old/source",
      });
      db.videoAudioTrack.delete.mockResolvedValue({});
      db.videoAudioTrack.create.mockResolvedValue({});
      deleteStorageObject.mockResolvedValue(undefined);

      const client = createRouterClient(videosRouter, { context: buildContext() });

      const result = await client.startAudioTrack({
        videoId: "vid-1",
        locale: "es-MX",
        label: "Spanish",
        mimeType: "audio/mp4",
        size: 1024,
      });

      expect(result.audioTrackId).toMatch(/^[a-f0-9-]+$/);
      expect(db.videoAudioTrack.delete).toHaveBeenCalledWith({ where: { id: "aud-old" } });
      expect(deleteStorageObject).toHaveBeenCalledWith("rawVideos/vid-1/a/aud-old/source");
    });

    it("aborts and deletes a pending audio multipart upload", async () => {
      db.videoAudioTrack.findUnique.mockResolvedValue({
        id: "aud-1",
        videoId: "vid-1",
        status: "PENDING",
        sourceKey: "rawVideos/vid-1/a/aud-1/source",
        Video: { ownerId: "user-1" },
      });
      abortMultipart.mockResolvedValue(undefined);
      deleteStorageObject.mockResolvedValue(undefined);
      db.videoAudioTrack.deleteMany.mockResolvedValue({ count: 1 });

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.abortAudioTrack({ audioTrackId: "aud-1", uploadId: "mpu-aud-1" });

      expect(result.ok).toBe(true);
      expect(abortMultipart).toHaveBeenCalledWith("rawVideos/vid-1/a/aud-1/source", "mpu-aud-1");
      expect(db.videoAudioTrack.deleteMany).toHaveBeenCalledWith({
        where: { id: "aud-1", status: "PENDING" },
      });
      expect(deleteStorageObject).toHaveBeenCalledWith("rawVideos/vid-1/a/aud-1/source");
    });

    it("does not delete audio source bytes if abort loses the pending-row race", async () => {
      db.videoAudioTrack.findUnique.mockResolvedValue({
        id: "aud-1",
        videoId: "vid-1",
        status: "PENDING",
        sourceKey: "rawVideos/vid-1/a/aud-1/source",
        Video: { ownerId: "user-1" },
      });
      abortMultipart.mockResolvedValue(undefined);
      db.videoAudioTrack.deleteMany.mockResolvedValue({ count: 0 });

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.abortAudioTrack({ audioTrackId: "aud-1", uploadId: "mpu-aud-1" });

      expect(result.ok).toBe(true);
      expect(abortMultipart).toHaveBeenCalledWith("rawVideos/vid-1/a/aud-1/source", "mpu-aud-1");
      expect(db.videoAudioTrack.deleteMany).toHaveBeenCalledWith({
        where: { id: "aud-1", status: "PENDING" },
      });
      expect(deleteStorageObject).not.toHaveBeenCalled();
    });

    it("404s a non-owner abortAudioTrack and does not touch storage or the row", async () => {
      db.videoAudioTrack.findUnique.mockResolvedValue({
        id: "aud-1",
        videoId: "vid-1",
        status: "PENDING",
        sourceKey: "rawVideos/vid-1/a/aud-1/source",
        Video: { ownerId: "other-user" },
      });

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(
        client.abortAudioTrack({ audioTrackId: "aud-1", uploadId: "mpu-aud-1" }),
      ).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("NOT_FOUND");
        return true;
      });

      expect(abortMultipart).not.toHaveBeenCalled();
      expect(deleteStorageObject).not.toHaveBeenCalled();
      expect(db.videoAudioTrack.deleteMany).not.toHaveBeenCalled();
    });

    it("deletes raw source bytes and processed segments when deleting a dub", async () => {
      deleteStorageObject.mockResolvedValue(undefined);
      db.videoAudioTrack.findUnique.mockResolvedValue({
        id: "aud-1",
        videoId: "vid-1",
        locale: "es-MX",
        isDefault: false,
        sourceKey: "rawVideos/vid-1/a/aud-1/source",
        Video: { ownerId: "user-1" },
      });
      db.videoAudioTrack.delete.mockResolvedValue({});

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.deleteAudioTrack({ id: "aud-1" });

      expect(result.ok).toBe(true);
      expect(db.videoAudioTrack.delete).toHaveBeenCalledWith({ where: { id: "aud-1" } });
      expect(deleteStorageObject).toHaveBeenCalledWith("rawVideos/vid-1/a/aud-1/source");
      expect(db.videoAudioTrack.delete.mock.invocationCallOrder[0]).toBeLessThan(
        deleteStorageObject.mock.invocationCallOrder[0]!,
      );
    });

    it("does not delete audio bytes if deleting the row fails", async () => {
      db.videoAudioTrack.findUnique.mockResolvedValue({
        id: "aud-1",
        videoId: "vid-1",
        locale: "es-MX",
        isDefault: false,
        sourceKey: "rawVideos/vid-1/a/aud-1/source",
        Video: { ownerId: "user-1" },
      });
      db.videoAudioTrack.delete.mockRejectedValue(new Error("db unavailable"));

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(client.deleteAudioTrack({ id: "aud-1" })).rejects.toThrow("db unavailable");

      expect(deleteStorageObject).not.toHaveBeenCalled();
    });

    it("rejects audio completion when the stored object size differs from the accepted size", async () => {
      db.videoAudioTrack.findUnique.mockResolvedValue({
        id: "aud-1",
        videoId: "vid-1",
        status: "PENDING",
        sourceKey: "rawVideos/vid-1/a/aud-1/source",
        sourceSize: BigInt(2048),
        Video: { ownerId: "user-1" },
      });
      headStorageObject.mockResolvedValue({ contentLength: 1024, contentType: "audio/mp4" });

      const client = createRouterClient(videosRouter, { context: buildContext() });

      await expect(
        client.finalizeAudioTrack({
          audioTrackId: "aud-1",
          uploadId: "mpu-aud-1",
          parts: [{ partNumber: 1, etag: "etag-1" }],
        }),
      ).rejects.toSatisfy((err: ORPCError) => {
        expect(err.code).toBe("CONFLICT");
        return true;
      });

      expect(db.videoAudioTrack.update).not.toHaveBeenCalled();
      expect(transcodeAudioTrackAdd).not.toHaveBeenCalled();
    });
  });

  describe("addSubtitleTrack", () => {
    it("converts SRT to WebVTT before persisting", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow());
      db.videoSubtitleTrack.upsert.mockResolvedValue({ id: "sub-1" });
      db.videoSubtitleTrack.updateMany.mockResolvedValue({ count: 0 });

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await client.addSubtitleTrack({
        videoId: "vid-1",
        locale: "en-US",
        label: "English",
        kind: "SUBTITLES",
        isDefault: false,
        content: "1\n00:00:01,000 --> 00:00:02,000\nHello\n",
        format: "srt",
      });

      expect(putStorageObject).toHaveBeenCalledOnce();
      const body = putStorageObject.mock.calls[0]?.[1] as Uint8Array;
      const decoded = new TextDecoder().decode(body);
      expect(decoded).toMatch(/^WEBVTT/);
      // SRT uses comma as decimal sep; VTT uses period. The conversion must swap.
      expect(decoded).toMatch(/00:00:01\.000/);
      expect(decoded).not.toMatch(/00:00:01,000/);
    });

    it("stores subtitle updates under a new key before deleting the replaced object", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow());
      db.videoSubtitleTrack.findUnique.mockResolvedValue({
        storageKey: "videos/vid-1/t/en-US.subtitles.old.vtt",
      });
      db.videoSubtitleTrack.upsert.mockResolvedValue({ id: "sub-1" });
      db.videoSubtitleTrack.updateMany.mockResolvedValue({ count: 0 });

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await client.addSubtitleTrack({
        videoId: "vid-1",
        locale: "en-US",
        label: "English",
        kind: "SUBTITLES",
        isDefault: false,
        content: "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHello\n",
        format: "vtt",
      });

      const stagedKey = putStorageObject.mock.calls[0]?.[0] as string;
      expect(stagedKey).toMatch(/^videos\/vid-1\/t\/en-US\.subtitles\.[a-f0-9-]+\.vtt$/);
      const upsert = db.videoSubtitleTrack.upsert.mock.calls[0]?.[0] as {
        create: { storageKey: string };
        update: { storageKey: string };
      };
      expect(upsert.create.storageKey).toBe(stagedKey);
      expect(upsert.update.storageKey).toBe(stagedKey);
      expect(deleteStorageObject).toHaveBeenCalledWith("videos/vid-1/t/en-US.subtitles.old.vtt");
      expect(putStorageObject.mock.invocationCallOrder[0]).toBeLessThan(
        db.videoSubtitleTrack.upsert.mock.invocationCallOrder[0]!,
      );
      expect(db.videoSubtitleTrack.upsert.mock.invocationCallOrder[0]).toBeLessThan(
        deleteStorageObject.mock.invocationCallOrder[0]!,
      );
    });

    it("deletes a staged subtitle object if the row upsert fails", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow());
      db.videoSubtitleTrack.findUnique.mockResolvedValue(null);
      db.videoSubtitleTrack.upsert.mockRejectedValue(new Error("db unavailable"));

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(
        client.addSubtitleTrack({
          videoId: "vid-1",
          locale: "en-US",
          label: "English",
          kind: "SUBTITLES",
          isDefault: false,
          content: "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHello\n",
          format: "vtt",
        }),
      ).rejects.toThrow("db unavailable");

      const stagedKey = putStorageObject.mock.calls[0]?.[0] as string;
      expect(stagedKey).toMatch(/^videos\/vid-1\/t\/en-US\.subtitles\.[a-f0-9-]+\.vtt$/);
      expect(deleteStorageObject).toHaveBeenCalledWith(stagedKey);
    });

    it("deletes only staged subtitle bytes when an update upsert fails", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow());
      db.videoSubtitleTrack.findUnique.mockResolvedValue({
        id: "sub-1",
        storageKey: "videos/vid-1/t/en-US.subtitles.vtt",
      });
      db.videoSubtitleTrack.upsert.mockRejectedValue(new Error("db unavailable"));

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(
        client.addSubtitleTrack({
          videoId: "vid-1",
          locale: "en-US",
          label: "English",
          kind: "SUBTITLES",
          isDefault: false,
          content: "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHello\n",
          format: "vtt",
        }),
      ).rejects.toThrow("db unavailable");

      const stagedKey = putStorageObject.mock.calls[0]?.[0] as string;
      expect(stagedKey).toMatch(/^videos\/vid-1\/t\/en-US\.subtitles\.[a-f0-9-]+\.vtt$/);
      expect(deleteStorageObject).toHaveBeenCalledWith(stagedKey);
      expect(deleteStorageObject).not.toHaveBeenCalledWith("videos/vid-1/t/en-US.subtitles.vtt");
    });

    it("deletes staged subtitle bytes if a concurrent create wins before rollback", async () => {
      db.video.findUnique.mockResolvedValue(makeVideoRow());
      db.videoSubtitleTrack.findUnique.mockResolvedValue({
        id: "sub-concurrent",
        storageKey: "videos/vid-1/t/en-US.subtitles.concurrent.vtt",
      });
      db.videoSubtitleTrack.upsert.mockRejectedValue(new Error("db unavailable"));

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(
        client.addSubtitleTrack({
          videoId: "vid-1",
          locale: "en-US",
          label: "English",
          kind: "SUBTITLES",
          isDefault: false,
          content: "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHello\n",
          format: "vtt",
        }),
      ).rejects.toThrow("db unavailable");

      expect(db.videoSubtitleTrack.findUnique).toHaveBeenCalledWith({
        where: {
          videoId_locale_kind: {
            videoId: "vid-1",
            locale: "en-US",
            kind: "SUBTITLES",
          },
        },
        select: { storageKey: true },
      });
      const stagedKey = putStorageObject.mock.calls[0]?.[0] as string;
      expect(deleteStorageObject).toHaveBeenCalledWith(stagedKey);
      expect(deleteStorageObject).not.toHaveBeenCalledWith(
        "videos/vid-1/t/en-US.subtitles.concurrent.vtt",
      );
    });

    it("deletes a subtitle row before deleting its object", async () => {
      db.videoSubtitleTrack.findUnique.mockResolvedValue({
        id: "sub-1",
        storageKey: "videos/vid-1/t/en-US.subtitles.vtt",
        Video: { ownerId: "user-1" },
      });
      db.videoSubtitleTrack.delete.mockResolvedValue({});

      const client = createRouterClient(videosRouter, { context: buildContext() });
      const result = await client.deleteSubtitleTrack({ id: "sub-1" });

      expect(result.ok).toBe(true);
      expect(db.videoSubtitleTrack.delete).toHaveBeenCalledWith({ where: { id: "sub-1" } });
      expect(deleteStorageObject).toHaveBeenCalledWith("videos/vid-1/t/en-US.subtitles.vtt");
      expect(db.videoSubtitleTrack.delete.mock.invocationCallOrder[0]).toBeLessThan(
        deleteStorageObject.mock.invocationCallOrder[0]!,
      );
    });

    it("does not delete subtitle bytes if deleting the row fails", async () => {
      db.videoSubtitleTrack.findUnique.mockResolvedValue({
        id: "sub-1",
        storageKey: "videos/vid-1/t/en-US.subtitles.vtt",
        Video: { ownerId: "user-1" },
      });
      db.videoSubtitleTrack.delete.mockRejectedValue(new Error("db unavailable"));

      const client = createRouterClient(videosRouter, { context: buildContext() });
      await expect(client.deleteSubtitleTrack({ id: "sub-1" })).rejects.toThrow("db unavailable");

      expect(deleteStorageObject).not.toHaveBeenCalled();
    });
  });
});
