import { afterEach, describe, expect, it, vi } from "vitest";

import { type MultipartProtocol, uploadMultipart } from "./video-client";

describe("uploadMultipart", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("completes multipart uploads with parts sorted by part number", async () => {
    const file = new File([new Uint8Array(9 * 1024 * 1024)], "video.mp4", {
      type: "video/mp4",
    });
    const complete = vi.fn().mockResolvedValue(undefined);
    const protocol: MultipartProtocol = {
      presignParts: vi.fn().mockResolvedValue({
        parts: [
          { url: "https://upload.example/part-1", partNumber: 1 },
          { url: "https://upload.example/part-2", partNumber: 2 },
        ],
      }),
      complete,
      abort: vi.fn().mockResolvedValue(undefined),
      heartbeat: vi.fn().mockResolvedValue(undefined),
    };

    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("part-1")) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      return new Response(null, {
        status: 200,
        headers: { etag: url.endsWith("part-1") ? '"etag-1"' : '"etag-2"' },
      });
    });

    await uploadMultipart({ file, protocol, concurrency: 2 });

    expect(complete).toHaveBeenCalledWith({
      parts: [
        { partNumber: 1, etag: '"etag-1"' },
        { partNumber: 2, etag: '"etag-2"' },
      ],
    });
  });
});
