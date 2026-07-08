import { describe, expect, it, vi } from "vitest";

vi.mock("@flycockpit/auth/roles", () => ({
  isAdminRole: (role: string | null | undefined) => role === "admin",
}));

vi.mock("@flycockpit/db", () => ({
  default: {},
}));

vi.mock("./storage", () => ({
  storage: {},
  createMultipartUpload: vi.fn(),
  deleteStorageObject: vi.fn(),
  getStorageObjectRange: vi.fn(),
  headStorageObject: vi.fn(),
  abortMultipartUpload: vi.fn(),
  completeMultipartUpload: vi.fn(),
  presignUploadPart: vi.fn(),
}));

const { buildMasterPlaylist } = await import("./videos.js");

describe("buildMasterPlaylist", () => {
  it("keeps control characters inside quoted HLS attributes", () => {
    const playlist = buildMasterPlaylist({
      video: {
        id: "video-1",
        title: "Video",
        description: null,
        status: "READY",
        failureReason: null,
        visibility: "PUBLIC",
        ownerId: null,
        sourceLocale: "en-US",
        durationSeconds: 60,
        width: 1920,
        height: 1080,
        sourceKey: "videos/video-1/source",
        sourceSize: 100,
        sourceMimeType: "video/mp4",
        posterAssetId: null,
        ladderPolicy: "STANDARD",
      },
      renditions: [{ height: 720, width: 1280, bandwidth: 2_500_000, codecs: "avc1.4d401f" }],
      audioTracks: [
        {
          locale: "en-US",
          label: 'English"\n#EXT-X-STREAM-INF:BANDWIDTH=1\nhttps://evil.example/x.m3u8',
          isDefault: true,
        },
      ],
      subtitleTracks: [
        {
          locale: "es-MX",
          label: "Spanish\r\n#EXT-X-ENDLIST",
          kind: "SUBTITLES",
          isDefault: false,
        },
      ],
    });

    const lines = playlist.split("\n");
    expect(lines.filter((line) => line.startsWith("#EXT-X-STREAM-INF")).length).toBe(1);
    expect(lines.some((line) => line === "https://evil.example/x.m3u8")).toBe(false);
    expect(lines.some((line) => line === "#EXT-X-ENDLIST")).toBe(false);
    expect(playlist).toContain('NAME="English\\" #EXT-X-STREAM-INF:BANDWIDTH=1');
    expect(playlist).toContain('NAME="Spanish  #EXT-X-ENDLIST"');
  });
});
