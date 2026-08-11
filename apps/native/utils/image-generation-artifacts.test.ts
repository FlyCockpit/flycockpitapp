import { describe, expect, it } from "vitest";
import {
  type ArtifactRouteRequest,
  artifactErrorMessage,
  canPreviewInline,
  classifyPublishedPath,
  collisionSafeSandboxFilename,
  contentTypeForMediaKind,
  isProviderUrl,
  isReadOnlyArtifactRequest,
  isSanitizedSvg,
  isValidatedRaster,
  previewStrategy,
  rasterDownloadFilename,
  rejectUnsafeMetadata,
  sandboxDownloadPath,
  sha256Hex,
  THUMBNAIL_BOXES,
  thumbnailOutputDimensions,
  thumbnailSupported,
  validateArtifactId,
  validateArtifactRouteRequest,
  verifyArtifactDownload,
  verifyChecksum,
} from "./image-generation-artifacts";

describe("image generation artifacts", () => {
  it("classifies validated raster vs sanitized SVG", () => {
    expect(isValidatedRaster("image/png")).toBe(true);
    expect(isValidatedRaster("image/jpeg")).toBe(true);
    expect(isValidatedRaster("image/webp")).toBe(true);
    expect(isValidatedRaster("image/svg+xml")).toBe(false);
    expect(isSanitizedSvg("image/svg+xml")).toBe(true);
    expect(isSanitizedSvg("image/png")).toBe(false);
  });

  it("returns the exact content type and download filename for each format", () => {
    expect(contentTypeForMediaKind("image/png")).toBe("image/png");
    expect(contentTypeForMediaKind("image/svg+xml")).toBe("image/svg+xml");
    expect(rasterDownloadFilename("image/png")).toBe("flycockpit-generated-image.png");
    expect(rasterDownloadFilename("image/jpeg")).toBe("flycockpit-generated-image.jpg");
    expect(rasterDownloadFilename("image/webp")).toBe("flycockpit-generated-image.webp");
    expect(rasterDownloadFilename("image/svg+xml")).toBeNull();
  });

  it("SVG is downloaded as attachment and previewed only through raster thumbnail", () => {
    expect(previewStrategy("image/svg+xml")).toBe("svg_thumbnail_only");
    expect(previewStrategy("image/png")).toBe("raster_thumbnail");
    expect(canPreviewInline("image/svg+xml")).toBe(false);
    expect(canPreviewInline("image/png")).toBe(true);
    expect(thumbnailSupported("image/svg+xml")).toBe(false);
    expect(thumbnailSupported("image/png")).toBe(true);
  });

  it("produces a collision-safe device-local sandbox filename", () => {
    const filename = collisionSafeSandboxFilename({
      artifactId: "ABCDEFGHIJKLMNOPQRSTUV",
      mediaKind: "image/png",
      artifactGeneration: "1",
    });
    expect(filename).toContain("flycockpit-generated-image");
    expect(filename).toContain("ABCDEFGHIJKLMNOPQRSTUV".slice(0, 16));
    expect(filename).toMatch(/\.png$/);

    const svgFilename = collisionSafeSandboxFilename({
      artifactId: "ABCDEFGHIJKLMNOPQRSTUV",
      mediaKind: "image/svg+xml",
      artifactGeneration: "1",
    });
    expect(svgFilename).toMatch(/\.svg$/);
  });

  it("sandboxDownloadPath namespaced under the artifact directory", () => {
    const path = sandboxDownloadPath({
      artifactId: "ABCDEFGHIJKLMNOPQRSTUV",
      mediaKind: "image/png",
      artifactGeneration: "1",
      directory: "/sandbox/image-generation-artifacts",
    });
    expect(path.startsWith("/sandbox/image-generation-artifacts/")).toBe(true);
  });

  it("classifies a daemon-host published path as host-only metadata, never opened as a device path", () => {
    const hostPath = classifyPublishedPath("/var/lib/daemon/output.png");
    expect(hostPath?.hostOnly).toBe(true);
    expect(hostPath?.label).toContain("daemon host");
    expect(classifyPublishedPath("https://example.com/x.png")).toBeNull();
  });

  it("isProviderUrl rejects provider URLs that must never be rendered", () => {
    expect(isProviderUrl("https://openai.com/image.png")).toBe(true);
    expect(isProviderUrl("not-a-url")).toBe(false);
  });

  it("rejectUnsafeMetadata flags host paths and provider URLs in metadata", () => {
    expect(rejectUnsafeMetadata({ path: "/var/lib/output.png" })).toBe(true);
    expect(rejectUnsafeMetadata({ url: "https://openai.com/x.png" })).toBe(true);
    expect(rejectUnsafeMetadata({ artifact_id: "abc" })).toBe(false);
    expect(rejectUnsafeMetadata({ secret: "leak" })).toBe(true);
  });

  it("validates artifact route requests with opaque IDs only", () => {
    const metadata: ArtifactRouteRequest = {
      kind: "metadata",
      artifactId: "ABCDEFGHIJKLMNOPQRSTUV",
      sessionId: "session-1",
    };
    expect(validateArtifactRouteRequest(metadata)).toBe(true);

    const download: ArtifactRouteRequest = {
      kind: "download",
      artifactId: "ABCDEFGHIJKLMNOPQRSTUV",
      sessionId: "session-1",
    };
    expect(validateArtifactRouteRequest(download)).toBe(true);

    const thumbnail: ArtifactRouteRequest = {
      kind: "thumbnail",
      artifactId: "ABCDEFGHIJKLMNOPQRSTUV",
      sessionId: "session-1",
      boxSize: 256,
    };
    expect(validateArtifactRouteRequest(thumbnail)).toBe(true);
    // Invalid box size.
    expect(validateArtifactRouteRequest({ ...thumbnail, boxSize: 128 })).toBe(false);

    // Invalid artifact ID (wrong length).
    expect(validateArtifactRouteRequest({ ...metadata, artifactId: "short" })).toBe(false);

    expect(isReadOnlyArtifactRequest(metadata)).toBe(true);
    expect(
      isReadOnlyArtifactRequest({ kind: "transfer_cancel", transferId: "ABCDEFGHIJKLMNOPQRSTUV" }),
    ).toBe(false);
  });

  it("validateArtifactId rejects non-22-char and non-base64url", () => {
    expect(validateArtifactId("ABCDEFGHIJKLMNOPQRSTUV")).toBe(true);
    expect(validateArtifactId("short")).toBe(false);
    expect(validateArtifactId("ABCDEFGHIJKLMNOPQRSTUVW")).toBe(false);
    expect(validateArtifactId("ABCDEFGHIJKLMNOPQRSTUVWXY")).toBe(false);
  });

  it("thumbnailOutputDimensions computes no-upscale dimensions", () => {
    expect(thumbnailOutputDimensions(100, 100, 256)).toEqual([100, 100]);
    expect(thumbnailOutputDimensions(1024, 512, 256)).toEqual([256, 128]);
    expect(thumbnailOutputDimensions(512, 1024, 256)).toEqual([128, 256]);
    expect(thumbnailOutputDimensions(0, 100, 256)).toBeNull();
  });

  it("THUMBNAIL_BOXES is exactly 256, 512, 1024", () => {
    expect([...THUMBNAIL_BOXES]).toEqual([256, 512, 1024]);
  });

  it("verifyChecksum validates a SHA-256 against downloaded bytes", () => {
    const bytes = new TextEncoder().encode("hello");
    // SHA-256 of "hello".
    const expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    expect(verifyChecksum(bytes, expected)).toBe(true);
    expect(
      verifyChecksum(bytes, "0000000000000000000000000000000000000000000000000000000000000000"),
    ).toBe(false);
  });

  it("sha256Hex matches a known vector", () => {
    const bytes = new TextEncoder().encode("hello");
    expect(sha256Hex(bytes)).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
  });

  it("verifyArtifactDownload verifies checksum and returns a collision-safe sandbox path", () => {
    const bytes = new TextEncoder().encode("hello");
    const expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const result = verifyArtifactDownload({
      bytes,
      mediaKind: "image/png",
      expectedSha256Hex: expected,
      artifactId: "ABCDEFGHIJKLMNOPQRSTUV",
      artifactGeneration: "1",
      sandboxDirectory: "/sandbox/image-generation-artifacts",
    });
    expect(result.kind).toBe("success");
    if (result.kind === "success") {
      expect(result.checksumVerified).toBe(true);
      expect(result.sandboxPath.startsWith("/sandbox/image-generation-artifacts/")).toBe(true);
      expect(result.contentType).toBe("image/png");
    }
  });

  it("verifyArtifactDownload reports checksum mismatch", () => {
    const bytes = new TextEncoder().encode("hello");
    const result = verifyArtifactDownload({
      bytes,
      mediaKind: "image/png",
      expectedSha256Hex: "0000000000000000000000000000000000000000000000000000000000000000",
      artifactId: "ABCDEFGHIJKLMNOPQRSTUV",
      artifactGeneration: "1",
      sandboxDirectory: "/sandbox/image-generation-artifacts",
    });
    expect(result.kind).toBe("checksum_mismatch");
  });

  it("verifyArtifactDownload rejects unsupported media kinds", () => {
    const result = verifyArtifactDownload({
      bytes: new Uint8Array(0),
      mediaKind: "image/gif",
      expectedSha256Hex: "abc",
      artifactId: "ABCDEFGHIJKLMNOPQRSTUV",
      artifactGeneration: "1",
      sandboxDirectory: "/sandbox",
    });
    expect(result.kind).toBe("error");
  });

  it("artifactErrorMessage provides stable messages without leaking inaccessible metadata", () => {
    expect(artifactErrorMessage("artifact_unavailable")).toContain("unavailable");
    expect(artifactErrorMessage("thumbnail_unavailable_for_format")).toContain(
      "Thumbnails are not available",
    );
    expect(artifactErrorMessage("range_not_satisfiable")).toContain("range");
    expect(artifactErrorMessage("thumbnail_capacity")).toContain("capacity");
    // No message leaks a host path or provider URL.
    for (const code of [
      "malformed",
      "artifact_unavailable",
      "thumbnail_unavailable_for_format",
      "thumbnail_unavailable",
      "range_not_satisfiable",
      "thumbnail_capacity",
      "internal",
    ] as const) {
      const msg = artifactErrorMessage(code);
      expect(msg).not.toContain("/var/");
      expect(msg).not.toContain("https://");
    }
  });
});
