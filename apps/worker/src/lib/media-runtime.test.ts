import { describe, expect, it, vi } from "vitest";
import { resolveMediaRuntimePair } from "./media-runtime.js";

describe("resolveMediaRuntimePair", () => {
  it("returns configured paths only after both compatible versions pass", async () => {
    const probe = vi.fn(async (program: string) =>
      program.endsWith("ffmpeg") ? "ffmpeg version 7.1" : "ffprobe version 7.0",
    );
    await expect(
      resolveMediaRuntimePair({ ffmpeg: "/tools/ffmpeg", ffprobe: "/tools/ffprobe" }, probe),
    ).resolves.toEqual({ ffmpeg: "/tools/ffmpeg", ffprobe: "/tools/ffprobe" });
    expect(probe).toHaveBeenCalledTimes(2);
  });

  it("fails closed for mismatched or unparseable versions", async () => {
    for (const evidence of [
      ["ffmpeg version 7.1", "ffprobe version 6.1"],
      ["ffmpeg unknown", "ffprobe version 7.1"],
    ]) {
      let index = 0;
      await expect(
        resolveMediaRuntimePair(
          { ffmpeg: "ffmpeg", ffprobe: "ffprobe" },
          async () => evidence[index++]!,
        ),
      ).rejects.toThrow("compatible FFmpeg/FFprobe pair");
    }
  });
});
