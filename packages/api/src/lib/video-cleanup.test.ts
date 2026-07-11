import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

const deleteStorageObject = vi.fn().mockResolvedValue(undefined);
const deleteStorageObjects = vi.fn().mockResolvedValue({ deleted: [], errors: [] });
const listStorageObjects = vi.fn(async function* () {});
const listIncompleteMultipartUploads = vi.fn(async function* () {});
const abortMultipartUpload = vi.fn();

vi.mock("./storage", () => ({
  abortMultipartUpload,
  deleteStorageObject,
  deleteStorageObjects,
  listIncompleteMultipartUploads,
  listStorageObjects,
  storage: { bucket: "test", client: {}, keyPrefix: "" },
}));

const { default: prisma } = await import("@flycockpit/db");
const { parseTrackObjectKey, runVideoCleanup } = await import("./video-cleanup");

const db = prisma as unknown as {
  video: {
    findUnique: MockInstance;
    findMany: MockInstance;
    deleteMany: MockInstance;
    updateMany: MockInstance;
  };
  videoAudioTrack: {
    findUnique: MockInstance;
    findFirst: MockInstance;
    findMany: MockInstance;
    deleteMany: MockInstance;
    updateMany: MockInstance;
  };
  videoSubtitleTrack: {
    findFirst: MockInstance;
    findMany: MockInstance;
  };
};

describe("runVideoCleanup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listStorageObjects.mockImplementation(async function* () {});
    deleteStorageObjects.mockImplementation(async (keys: string[]) => ({
      deleted: keys,
      errors: [],
    }));
    db.video.findUnique.mockResolvedValue(null);
    db.video.findMany.mockResolvedValue([]);
    db.video.deleteMany.mockResolvedValue({ count: 0 });
    db.video.updateMany.mockResolvedValue({ count: 0 });
    db.videoAudioTrack.findUnique.mockResolvedValue(null);
    db.videoAudioTrack.findFirst.mockResolvedValue(null);
    db.videoAudioTrack.findMany.mockResolvedValue([]);
    db.videoAudioTrack.deleteMany.mockResolvedValue({ count: 0 });
    db.videoAudioTrack.updateMany.mockResolvedValue({ count: 0 });
    db.videoSubtitleTrack.findFirst.mockResolvedValue(null);
    db.videoSubtitleTrack.findMany.mockResolvedValue([]);
  });

  it("re-checks pending videos at delete time before deleting storage", async () => {
    db.video.findMany.mockResolvedValue([{ id: "video-1", sourceKey: "rawVideos/video-1/source" }]);
    db.video.deleteMany.mockResolvedValue({ count: 0 });

    const result = await runVideoCleanup({ pendingMaxAgeMs: 1 });

    expect(result.pendingVideosReaped).toBe(0);
    expect(db.video.deleteMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ id: "video-1", status: "PENDING" }),
      }),
    );
    expect(deleteStorageObject).not.toHaveBeenCalled();
  });

  it("deletes stale audio-track rows before deleting their source objects", async () => {
    db.videoAudioTrack.findMany.mockResolvedValue([
      { id: "track-1", sourceKey: "rawVideos/video-1/a/track-1/source" },
    ]);
    db.videoAudioTrack.deleteMany.mockResolvedValue({ count: 1 });

    const result = await runVideoCleanup({ pendingMaxAgeMs: 1 });

    expect(result.pendingAudioTracksReaped).toBe(1);
    expect(db.videoAudioTrack.deleteMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ id: "track-1", status: "PENDING" }),
      }),
    );
    expect(deleteStorageObject).toHaveBeenCalledWith("rawVideos/video-1/a/track-1/source");
    expect(db.videoAudioTrack.deleteMany.mock.invocationCallOrder[0]).toBeLessThan(
      deleteStorageObject.mock.invocationCallOrder[0]!,
    );
  });

  it("marks stale transcodes failed", async () => {
    db.video.updateMany.mockResolvedValue({ count: 2 });
    db.videoAudioTrack.updateMany.mockResolvedValue({ count: 1 });

    const result = await runVideoCleanup({ transcodingMaxAgeMs: 1 });

    expect(result.staleTranscodingVideosFailed).toBe(2);
    expect(result.staleTranscodingAudioTracksFailed).toBe(1);
    expect(db.video.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ status: "TRANSCODING" }),
        data: expect.objectContaining({ status: "FAILED" }),
      }),
    );
    expect(db.videoAudioTrack.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ status: "TRANSCODING" }),
        data: expect.objectContaining({ status: "FAILED" }),
      }),
    );
  });

  it("deletes output audio objects for live videos when the audio track row is gone", async () => {
    listStorageObjects.mockImplementation(async function* (prefix: string) {
      if (prefix === "videos/") {
        yield {
          key: "videos/video-1/a/es-MX/playlist.m3u8",
          size: 10,
          lastModified: new Date("2026-01-01"),
        };
      }
    });
    db.video.findUnique.mockResolvedValue({ id: "video-1" });
    db.videoAudioTrack.findUnique.mockResolvedValue(null);

    const result = await runVideoCleanup({ objectMinAgeMs: 1 });

    expect(result.orphanObjectsDeleted).toBe(1);
    expect(db.videoAudioTrack.findUnique).toHaveBeenCalledWith({
      where: { videoId_locale: { videoId: "video-1", locale: "es-MX" } },
      select: { id: true },
    });
    expect(deleteStorageObjects).toHaveBeenCalledWith(["videos/video-1/a/es-MX/playlist.m3u8"]);
  });

  it("keeps output audio objects when the live video still has that audio track", async () => {
    listStorageObjects.mockImplementation(async function* (prefix: string) {
      if (prefix === "videos/") {
        yield {
          key: "videos/video-1/a/es-MX/playlist.m3u8",
          size: 10,
          lastModified: new Date("2026-01-01"),
        };
      }
    });
    db.video.findUnique.mockResolvedValue({ id: "video-1" });
    db.videoAudioTrack.findUnique.mockResolvedValue({ id: "track-1" });

    const result = await runVideoCleanup({ objectMinAgeMs: 1 });

    expect(result.orphanObjectsDeleted).toBe(0);
    expect(deleteStorageObjects).not.toHaveBeenCalled();
  });

  it("keeps non-track objects for live videos without track lookups", async () => {
    listStorageObjects.mockImplementation(async function* (prefix: string) {
      if (prefix === "videos/") {
        yield {
          key: "videos/video-1/v/720/segment-00001.ts",
          size: 10,
          lastModified: new Date("2026-01-01"),
        };
      }
    });
    db.video.findUnique.mockResolvedValue({ id: "video-1" });

    const result = await runVideoCleanup({ objectMinAgeMs: 1 });

    expect(result.orphanObjectsDeleted).toBe(0);
    expect(db.videoAudioTrack.findUnique).not.toHaveBeenCalled();
    expect(db.videoAudioTrack.findFirst).not.toHaveBeenCalled();
    expect(db.videoSubtitleTrack.findFirst).not.toHaveBeenCalled();
    expect(deleteStorageObjects).not.toHaveBeenCalled();
  });

  it("deletes raw audio source objects for live videos when no track references the key", async () => {
    listStorageObjects.mockImplementation(async function* (prefix: string) {
      if (prefix === "rawVideos/") {
        yield {
          key: "rawVideos/video-1/a/track-1/source",
          size: 10,
          lastModified: new Date("2026-01-01"),
        };
      }
    });
    db.video.findUnique.mockResolvedValue({ id: "video-1" });
    db.videoAudioTrack.findFirst.mockResolvedValue(null);

    const result = await runVideoCleanup({ objectMinAgeMs: 1 });

    expect(result.orphanObjectsDeleted).toBe(1);
    expect(db.videoAudioTrack.findFirst).toHaveBeenCalledWith({
      where: { videoId: "video-1", sourceKey: "rawVideos/video-1/a/track-1/source" },
      select: { id: true },
    });
    expect(deleteStorageObjects).toHaveBeenCalledWith(["rawVideos/video-1/a/track-1/source"]);
  });

  it("deletes subtitle objects for live videos when no subtitle row references the key", async () => {
    listStorageObjects.mockImplementation(async function* (prefix: string) {
      if (prefix === "videos/") {
        yield {
          key: "videos/video-1/t/en-US.subtitles.vtt",
          size: 10,
          lastModified: new Date("2026-01-01"),
        };
      }
    });
    db.video.findUnique.mockResolvedValue({ id: "video-1" });
    db.videoSubtitleTrack.findFirst.mockResolvedValue(null);
    db.videoSubtitleTrack.findMany.mockResolvedValue([]);

    const result = await runVideoCleanup({ objectMinAgeMs: 1 });

    expect(result.orphanObjectsDeleted).toBe(1);
    expect(db.videoSubtitleTrack.findFirst).toHaveBeenCalledWith({
      where: { videoId: "video-1", storageKey: "videos/video-1/t/en-US.subtitles.vtt" },
      select: { id: true },
    });
    expect(deleteStorageObjects).toHaveBeenCalledWith(["videos/video-1/t/en-US.subtitles.vtt"]);
  });
});

describe("parseTrackObjectKey", () => {
  function parse(key: string, videoId = "video-1") {
    return parseTrackObjectKey(key.split("/"), key, videoId);
  }

  it("classifies raw audio source objects", () => {
    expect(parse("rawVideos/video-1/a/track-1/source")).toEqual({
      kind: "rawAudioSource",
      key: "rawVideos/video-1/a/track-1/source",
    });
  });

  it("classifies output audio objects by locale", () => {
    expect(parse("videos/video-1/a/es-MX/playlist.m3u8")).toEqual({
      kind: "audioOutput",
      locale: "es-MX",
    });
  });

  it("classifies subtitle objects", () => {
    expect(parse("videos/video-1/t/en-US.subtitles.vtt")).toEqual({
      kind: "subtitle",
      key: "videos/video-1/t/en-US.subtitles.vtt",
    });
  });

  it("ignores non-track video objects and mismatched video ids", () => {
    expect(parse("videos/video-1/v/720/segment-00001.ts")).toBeNull();
    expect(parse("videos/video-2/a/es-MX/playlist.m3u8")).toBeNull();
    expect(parse("rawVideos/video-2/a/track-1/source")).toBeNull();
  });
});
