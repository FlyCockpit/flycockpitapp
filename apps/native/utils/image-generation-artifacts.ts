/**
 * Image-generation native artifact routes, checksum, sandbox filenames, and
 * preview/download flow.
 *
 * Previews use authenticated raster-thumbnail bytes copied into app sandbox.
 * Downloads use authenticated artifact bytes, checksum verification, and a
 * collision-safe device-local filename before share/open. A daemon-host
 * published path is labeled host-only metadata and is never opened as a
 * device path; SVG is downloaded as attachment and previewed only through
 * raster thumbnail.
 *
 * Routes are keyed only by opaque artifact IDs. The app never accepts a
 * filesystem path, redirects to a provider URL, or serves the user-owned
 * published copy. `ImageGenerationAdmin` by itself is not artifact/session
 * authority.
 */

import {
  containsForbiddenSentinel,
  isHostPathString,
  isProviderUrlString,
} from "./image-generation-redaction";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Schema version for image-artifact route V1 structures. */
export const IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION = 1;

/** The exact allowlist of thumbnail bounding boxes. */
export const THUMBNAIL_BOXES: readonly number[] = [256, 512, 1024];

/** The closed filename map for validated raster downloads. */
export const RASTER_DOWNLOAD_FILENAME_PNG = "flycockpit-generated-image.png";
export const RASTER_DOWNLOAD_FILENAME_JPEG = "flycockpit-generated-image.jpg";
export const RASTER_DOWNLOAD_FILENAME_WEBP = "flycockpit-generated-image.webp";
export const RASTER_THUMBNAIL_FILENAME = "flycockpit-generated-thumbnail.png";
export const SVG_DOWNLOAD_FILENAME = "flycockpit-generated-image.svg";

/** The exact `Content-Type` values for validated formats. */
export const CONTENT_TYPE_PNG = "image/png";
export const CONTENT_TYPE_JPEG = "image/jpeg";
export const CONTENT_TYPE_WEBP = "image/webp";
export const CONTENT_TYPE_SVG = "image/svg+xml";
export const CONTENT_TYPE_THUMBNAIL_PNG = "image/png";

/** The app-sandbox directory namespace for image-generation artifacts. */
export const ARTIFACT_SANDBOX_DIRECTORY = "image-generation-artifacts";

// ---------------------------------------------------------------------------
// Route kind
// ---------------------------------------------------------------------------

/** The three application routes. */
export type ImageArtifactRouteKind = "metadata" | "content" | "thumbnail";

/** Returns `true` if a route forbids a `Range` header structurally. */
export function routeForbidsRangeStructurally(route: ImageArtifactRouteKind): boolean {
  return route === "metadata";
}

// ---------------------------------------------------------------------------
// Media kind classification
// ---------------------------------------------------------------------------

/** Returns `true` if a media kind is a validated raster format eligible for full download with Range. */
export function isValidatedRaster(mediaKind: string): boolean {
  return (
    mediaKind === "image/png" ||
    mediaKind === "png" ||
    mediaKind === "image/jpeg" ||
    mediaKind === "jpeg" ||
    mediaKind === "jpg" ||
    mediaKind === "image/webp" ||
    mediaKind === "webp"
  );
}

/** Returns `true` if a media kind is sanitized SVG. */
export function isSanitizedSvg(mediaKind: string): boolean {
  return mediaKind === "image/svg+xml" || mediaKind === "svg";
}

/** Returns the exact `Content-Type` for a validated media kind. */
export function contentTypeForMediaKind(mediaKind: string): string | null {
  switch (mediaKind) {
    case "image/png":
    case "png":
      return CONTENT_TYPE_PNG;
    case "image/jpeg":
    case "jpeg":
    case "jpg":
      return CONTENT_TYPE_JPEG;
    case "image/webp":
    case "webp":
      return CONTENT_TYPE_WEBP;
    case "image/svg+xml":
    case "svg":
      return CONTENT_TYPE_SVG;
    default:
      return null;
  }
}

/** The exact download filename for a validated raster format. */
export function rasterDownloadFilename(mediaKind: string): string | null {
  switch (mediaKind) {
    case "image/png":
    case "png":
      return RASTER_DOWNLOAD_FILENAME_PNG;
    case "image/jpeg":
    case "jpeg":
    case "jpg":
      return RASTER_DOWNLOAD_FILENAME_JPEG;
    case "image/webp":
    case "webp":
      return RASTER_DOWNLOAD_FILENAME_WEBP;
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// Collision-safe sandbox filename
// ---------------------------------------------------------------------------

/** A collision-safe device-local filename for an artifact download. */
export function collisionSafeSandboxFilename(input: {
  artifactId: string;
  mediaKind: string;
  artifactGeneration: string;
}): string {
  const base = isSanitizedSvg(input.mediaKind)
    ? SVG_DOWNLOAD_FILENAME
    : (rasterDownloadFilename(input.mediaKind) ?? RASTER_DOWNLOAD_FILENAME_PNG);
  // Insert the opaque artifact ID and generation before the extension to avoid collisions.
  const dotIndex = base.lastIndexOf(".");
  if (dotIndex <= 0) return base;
  const stem = base.slice(0, dotIndex);
  const ext = base.slice(dotIndex);
  return `${stem}-${sanitizeFilenameSegment(input.artifactId)}-${sanitizeFilenameSegment(
    input.artifactGeneration,
  )}${ext}`;
}

/** Sanitize a segment for use in a filename: keep only base64url/digit chars. */
function sanitizeFilenameSegment(value: string): string {
  const sanitized = value.replace(/[^A-Za-z0-9_-]/g, "");
  return sanitized.length > 16 ? sanitized.slice(0, 16) : sanitized;
}

/** The app-sandbox path for an artifact download within the namespaced directory. */
export function sandboxDownloadPath(input: {
  artifactId: string;
  mediaKind: string;
  artifactGeneration: string;
  directory: string;
}): string {
  const filename = collisionSafeSandboxFilename(input);
  return `${input.directory}/${filename}`;
}

// ---------------------------------------------------------------------------
// SVG thumbnail-only preview
// ---------------------------------------------------------------------------

/** Returns `true` if an artifact may be previewed inline (raster only; SVG is thumbnail-only). */
export function canPreviewInline(mediaKind: string): boolean {
  return isValidatedRaster(mediaKind);
}

/** Returns the preview strategy for a media kind. */
export function previewStrategy(
  mediaKind: string,
): "raster_thumbnail" | "svg_thumbnail_only" | "none" {
  if (isValidatedRaster(mediaKind)) return "raster_thumbnail";
  if (isSanitizedSvg(mediaKind)) return "svg_thumbnail_only";
  return "none";
}

/** Returns `true` if a thumbnail request is supported for the media kind. */
export function thumbnailSupported(mediaKind: string): boolean {
  // SVG thumbnails return 409 thumbnail_unavailable_for_format before any work.
  return isValidatedRaster(mediaKind);
}

// ---------------------------------------------------------------------------
// Host path / provider URL rejection
// ---------------------------------------------------------------------------

/** A daemon-host published path: labeled host-only metadata, never opened as a device path. */
export interface HostPathMetadata {
  readonly hostOnly: true;
  label: string;
  /** The raw path is never opened, rendered, or stored in state. */
  rawPath: string;
}

/** Classify a published path as host-only metadata. Never opened as a device path. */
export function classifyPublishedPath(path: string): HostPathMetadata | null {
  if (!isHostPathString(path)) return null;
  return {
    hostOnly: true,
    label: "Published on the daemon host. Not accessible from this device.",
    rawPath: path,
  };
}

/** Returns `true` if a value is a provider URL that must never be rendered or opened. */
export function isProviderUrl(value: unknown): boolean {
  return isProviderUrlString(value);
}

/** Reject an artifact metadata value that contains a host path or provider URL. */
export function rejectUnsafeMetadata(metadata: unknown): boolean {
  if (!metadata || typeof metadata !== "object") return false;
  if (containsForbiddenSentinel(metadata)) return true;
  const record = metadata as Record<string, unknown>;
  for (const value of Object.values(record)) {
    if (typeof value === "string" && (isHostPathString(value) || isProviderUrlString(value))) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Checksum verification
// ---------------------------------------------------------------------------

/** Verify a SHA-256 checksum against downloaded bytes. */
export function verifyChecksum(bytes: Uint8Array, expectedSha256Hex: string): boolean {
  const actual = sha256Hex(bytes);
  return actual === expectedSha256Hex.toLowerCase();
}

/** Compute the lowercase hex SHA-256 of a byte slice. */
export function sha256Hex(bytes: Uint8Array): string {
  // Use the Web Crypto API when available; otherwise a pure-JS fallback.
  if (typeof crypto !== "undefined" && crypto.subtle) {
    // Synchronous fallback for environments without async digest.
  }
  return sha256HexPure(bytes);
}

/** Pure-JS SHA-256 implementation (FIPS 180-4). */
function sha256HexPure(bytes: Uint8Array): string {
  const k = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const len = bytes.length;
  const bitLen = BigInt(len) * 8n;
  // Padding: append 0x80, then zeros, then 64-bit big-endian length.
  const paddedLen = Math.ceil((len + 1 + 8) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[len] = 0x80;
  // 64-bit big-endian length in the last 8 bytes.
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 4, Number(bitLen & 0xffffffffn), false);
  view.setUint32(paddedLen - 8, Number((bitLen >> 32n) & 0xffffffffn), false);

  const w = new Uint32Array(64);
  for (let i = 0; i < paddedLen; i += 64) {
    for (let t = 0; t < 16; t++) {
      w[t] = view.getUint32(i + t * 4, false);
    }
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let t = 0; t < 64; t++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + s1 + ch + k[t] + w[t]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }
  return [...h].map((v) => v.toString(16).padStart(8, "0")).join("");
}

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

// ---------------------------------------------------------------------------
// Thumbnail dimensions (no upscale)
// ---------------------------------------------------------------------------

/** Compute the thumbnail output dimensions for source `w,h` and box `b`. No upscale. */
export function thumbnailOutputDimensions(
  width: number,
  height: number,
  boxSize: number,
): [number, number] | null {
  if (width <= 0 || height <= 0 || boxSize <= 0) return null;
  if (width <= boxSize && height <= boxSize) return [width, height];
  if (width >= height) {
    const outW = boxSize;
    const scaled = Math.floor((height * boxSize) / width);
    return [outW, Math.max(1, scaled)];
  }
  const outH = boxSize;
  const scaled = Math.floor((width * boxSize) / height);
  return [Math.max(1, scaled), outH];
}

// ---------------------------------------------------------------------------
// Artifact route request
// ---------------------------------------------------------------------------

/** The artifact route request kinds. */
export type ArtifactRouteRequest =
  | { kind: "metadata"; artifactId: string; sessionId: string }
  | { kind: "download"; artifactId: string; sessionId: string; rangeHeader?: string }
  | {
      kind: "thumbnail";
      artifactId: string;
      sessionId: string;
      boxSize: number;
      rangeHeader?: string;
    }
  | { kind: "transfer_cancel"; transferId: string };

/** Returns `true` if an artifact route request is read-only. */
export function isReadOnlyArtifactRequest(request: ArtifactRouteRequest): boolean {
  return request.kind !== "transfer_cancel";
}

/** Validate an artifact route request. */
export function validateArtifactRouteRequest(request: ArtifactRouteRequest): boolean {
  switch (request.kind) {
    case "metadata":
      return validateArtifactId(request.artifactId) && request.sessionId.length > 0;
    case "download":
      return (
        validateArtifactId(request.artifactId) &&
        request.sessionId.length > 0 &&
        (!request.rangeHeader || request.rangeHeader.length <= 256)
      );
    case "thumbnail":
      return (
        validateArtifactId(request.artifactId) &&
        request.sessionId.length > 0 &&
        THUMBNAIL_BOXES.includes(request.boxSize) &&
        (!request.rangeHeader || request.rangeHeader.length <= 256)
      );
    case "transfer_cancel":
      return validateTransferId(request.transferId);
  }
}

/** Validate a 22-char unpadded base64url opaque artifact ID. */
export function validateArtifactId(artifactId: string): boolean {
  if (artifactId.length !== 22) return false;
  return /^[A-Za-z0-9_-]+$/.test(artifactId);
}

/** Validate a 22-char unpadded base64url transfer ID. */
export function validateTransferId(transferId: string): boolean {
  return validateArtifactId(transferId);
}

// ---------------------------------------------------------------------------
// Artifact error codes
// ---------------------------------------------------------------------------

/** The exact artifact daemon error codes. */
export type ImageArtifactErrorCode =
  | "malformed"
  | "artifact_unavailable"
  | "thumbnail_unavailable_for_format"
  | "thumbnail_unavailable"
  | "range_not_satisfiable"
  | "thumbnail_capacity"
  | "internal";

/** A stable recovery message for an artifact error code, without leaking inaccessible metadata. */
export function artifactErrorMessage(code: ImageArtifactErrorCode): string {
  switch (code) {
    case "malformed":
      return "The artifact request was malformed.";
    case "artifact_unavailable":
      return "The artifact is unavailable, quarantined, or has been cleaned up.";
    case "thumbnail_unavailable_for_format":
      return "Thumbnails are not available for this format. Download the full artifact instead.";
    case "thumbnail_unavailable":
      return "The thumbnail is not available right now. Try again shortly.";
    case "range_not_satisfiable":
      return "The requested byte range is not satisfiable.";
    case "thumbnail_capacity":
      return "The thumbnail service is at capacity. Try again shortly.";
    case "internal":
      return "An internal error occurred. Try again.";
  }
}

// ---------------------------------------------------------------------------
// Download result
// ---------------------------------------------------------------------------

/** The result of an authenticated artifact download with checksum verification. */
export type ArtifactDownloadResult =
  | {
      kind: "success";
      bytes: Uint8Array;
      mediaKind: string;
      checksumVerified: boolean;
      sandboxPath: string;
      contentType: string;
    }
  | { kind: "checksum_mismatch"; expected: string; actual: string }
  | { kind: "error"; code: ImageArtifactErrorCode; message: string };

/** Verify a downloaded artifact and produce a download result. */
export function verifyArtifactDownload(input: {
  bytes: Uint8Array;
  mediaKind: string;
  expectedSha256Hex: string;
  artifactId: string;
  artifactGeneration: string;
  sandboxDirectory: string;
}): ArtifactDownloadResult {
  const contentType = contentTypeForMediaKind(input.mediaKind);
  if (!contentType) {
    return {
      kind: "error",
      code: "malformed",
      message: "Unsupported media kind for download.",
    };
  }
  const actual = sha256Hex(input.bytes);
  if (actual !== input.expectedSha256Hex.toLowerCase()) {
    return {
      kind: "checksum_mismatch",
      expected: input.expectedSha256Hex,
      actual,
    };
  }
  const sandboxPath = sandboxDownloadPath({
    artifactId: input.artifactId,
    mediaKind: input.mediaKind,
    artifactGeneration: input.artifactGeneration,
    directory: input.sandboxDirectory,
  });
  return {
    kind: "success",
    bytes: input.bytes,
    mediaKind: input.mediaKind,
    checksumVerified: true,
    sandboxPath,
    contentType,
  };
}
