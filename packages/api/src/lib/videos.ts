import { randomUUID } from "node:crypto";

import { isAdminRole } from "@flycockpit/auth/roles";
import prisma from "@flycockpit/db";

import {
  type CompletedPart,
  createMultipartUpload,
  deleteStorageObject,
  getStorageObjectRange,
  headStorageObject,
  type PresignedUploadPart,
  type StorageObjectRange,
  abortMultipartUpload as s3AbortMultipartUpload,
  completeMultipartUpload as s3CompleteMultipartUpload,
  presignUploadPart as s3PresignUploadPart,
  storage,
} from "./storage";

/**
 * Permission boundary for the video pattern. The HLS playlist + segment +
 * audio + subtitle + thumbnail endpoints (apps/server/src/video-routes.ts)
 * all call into this module — there is no duplicate auth logic in the route
 * layer. The same Cache-Control rule as Asset applies: PUBLIC videos get a
 * 24h shared cache, RESTRICTED videos get 24h browser cache only.
 *
 * Why the storage layout matters here, not in the route file: every artifact
 * URL the route emits is a 24-hour bearer token, same as asset URLs. The
 * route's job is HTTP framing; this module's job is "is the caller allowed
 * to see *anything* about this video, and where do its bytes live."
 */

export type VideoVisibility = "PUBLIC" | "RESTRICTED";
export type VideoStatus = "PENDING" | "TRANSCODING" | "READY" | "FAILED";
export type VideoTrackStatus = "PENDING" | "TRANSCODING" | "READY" | "FAILED";
export type VideoSubtitleKind = "SUBTITLES" | "CAPTIONS" | "DESCRIPTIONS";
export type VideoLadderPolicy = "STANDARD" | "INCLUDE_4K";

export type VideoMeta = {
  id: string;
  title: string;
  description: string | null;
  status: VideoStatus;
  failureReason: string | null;
  visibility: VideoVisibility;
  ownerId: string | null;
  sourceLocale: string;
  durationSeconds: number | null;
  width: number | null;
  height: number | null;
  sourceKey: string | null;
  sourceSize: number | null;
  sourceMimeType: string | null;
  posterAssetId: string | null;
  ladderPolicy: VideoLadderPolicy;
};

export type Viewer = { kind: "anonymous" } | { kind: "user"; userId: string; role: string };

export class VideoError extends Error {
  constructor(
    public code:
      | "NOT_FOUND"
      | "FORBIDDEN"
      | "STORAGE_DISABLED"
      | "GONE"
      | "ALREADY_FINALIZED"
      | "UPLOAD_MISSING"
      | "SIZE_MISMATCH"
      | "INVALID_STATE",
    message: string,
  ) {
    super(message);
    this.name = "VideoError";
  }
}

/**
 * Default permission rule. PUBLIC + READY videos are visible to everyone;
 * PUBLIC + non-READY are still visible to the owner/admin but 404 for the
 * general public so an unfinished encode doesn't leak via a guessed URL.
 * Customize for org-scoped sharing by replacing this single function.
 */
export function canViewVideo(video: VideoMeta, viewer: Viewer): boolean {
  if (video.visibility === "PUBLIC" && video.status === "READY") return true;
  if (viewer.kind === "anonymous") return false;
  if (isAdminRole(viewer.role)) return true;
  return video.ownerId !== null && video.ownerId === viewer.userId;
}

export function videoCacheControl(visibility: VideoVisibility): string {
  if (visibility === "PUBLIC") {
    return "public, max-age=86400, immutable";
  }
  return "private, max-age=86400";
}

/**
 * Short-cache the master playlist — a viewer who switches audio mid-stream,
 * or refreshes after we add a new dub, should pick up the new track within
 * minutes, not 24 hours. Per-rendition playlists are also dynamic-ish
 * (segment list grows during live use cases), but for VOD they're static
 * after encode — we lump them in here too for simplicity.
 */
export function playlistCacheControl(visibility: VideoVisibility): string {
  if (visibility === "PUBLIC") {
    return "public, max-age=300";
  }
  return "private, max-age=300";
}

// ---------------------------------------------------------------------------
// Lookup + permission helper
// ---------------------------------------------------------------------------

export async function loadVideoMeta(videoId: string): Promise<VideoMeta | null> {
  const row = await prisma.video.findUnique({ where: { id: videoId } });
  if (!row) return null;
  return toVideoMeta(row);
}

/**
 * Resolve a video for an artifact request and check permissions. Used by
 * every route that emits or proxies a video artifact. Throws a VideoError
 * the route layer maps to an HTTP status — same shape as fetchAsset().
 */
export async function authorizeVideoRead(videoId: string, viewer: Viewer): Promise<VideoMeta> {
  if (!storage) throw new VideoError("STORAGE_DISABLED", "Object storage is not configured");
  const meta = await loadVideoMeta(videoId);
  if (!meta) throw new VideoError("NOT_FOUND", "Video not found");
  if (!canViewVideo(meta, viewer)) {
    // 404 (not 403) — see the matching note in assets.ts: don't leak existence.
    throw new VideoError("FORBIDDEN", "Not allowed to view this video");
  }
  return meta;
}

// ---------------------------------------------------------------------------
// Storage key helpers — keep paths consistent between the worker and the
// route layer. Never inline a video S3 key; route through these helpers.
// ---------------------------------------------------------------------------

export const videoStorageKeys = {
  raw(videoId: string) {
    return `rawVideos/${videoId}/source`;
  },
  rawAudio(videoId: string, trackId: string) {
    return `rawVideos/${videoId}/a/${trackId}/source`;
  },
  masterPlaylist(videoId: string) {
    return `videos/${videoId}/playlist.m3u8`;
  },
  videoRenditionPlaylist(videoId: string, height: number) {
    return `videos/${videoId}/v/${height}/playlist.m3u8`;
  },
  videoRenditionSegment(videoId: string, height: number, segmentName: string) {
    return `videos/${videoId}/v/${height}/${segmentName}`;
  },
  audioTrackPlaylist(videoId: string, locale: string) {
    return `videos/${videoId}/a/${locale}/playlist.m3u8`;
  },
  audioTrackSegment(videoId: string, locale: string, segmentName: string) {
    return `videos/${videoId}/a/${locale}/${segmentName}`;
  },
  subtitleTrackFilename(locale: string, kind: VideoSubtitleKind) {
    return `${locale}.${kind.toLowerCase()}.vtt`;
  },
  subtitleTrack(videoId: string, locale: string, kind: VideoSubtitleKind) {
    return `videos/${videoId}/t/${locale}.${kind.toLowerCase()}.vtt`;
  },
  subtitleTrackUpload(videoId: string, locale: string, kind: VideoSubtitleKind, uploadId: string) {
    const base = `${locale}.${kind.toLowerCase()}.${uploadId}.vtt`;
    return `videos/${videoId}/t/${base}`;
  },
  thumbnailsVtt(videoId: string) {
    return `videos/${videoId}/thumbs.vtt`;
  },
  thumbnailSprite(videoId: string, index: number) {
    return `videos/${videoId}/thumbs/${String(index).padStart(3, "0")}.jpg`;
  },
  poster(videoId: string) {
    return `videos/${videoId}/poster.jpg`;
  },
} as const;

// ---------------------------------------------------------------------------
// Multipart upload orchestration (raw video sources)
// ---------------------------------------------------------------------------

export type StartUploadInput = {
  ownerId: string;
  title: string;
  description?: string | null;
  visibility: VideoVisibility;
  sourceLocale: string;
  sourceMimeType: string;
  sourceSize: number;
  ladderPolicy?: VideoLadderPolicy;
};

export type StartUploadResult = {
  videoId: string;
  uploadId: string;
  storageKey: string;
};

/**
 * Create a PENDING Video row and initiate a multipart upload against
 * `rawVideos/<id>/source`. The client then requests presigned URLs per part,
 * PUTs each part, and calls completeVideoUpload to finalize.
 */
export async function startVideoUpload(input: StartUploadInput): Promise<StartUploadResult> {
  if (!storage) throw new VideoError("STORAGE_DISABLED", "Object storage is not configured");

  const videoId = newVideoId();
  const storageKey = videoStorageKeys.raw(videoId);
  const { uploadId } = await createMultipartUpload(storageKey, input.sourceMimeType);

  try {
    await prisma.video.create({
      data: {
        id: videoId,
        title: input.title,
        description: input.description ?? null,
        status: "PENDING",
        visibility: input.visibility,
        ownerId: input.ownerId,
        sourceLocale: input.sourceLocale,
        sourceKey: storageKey,
        sourceSize: BigInt(input.sourceSize),
        sourceMimeType: input.sourceMimeType,
        uploadHeartbeatAt: new Date(),
        ladderPolicy: input.ladderPolicy ?? "STANDARD",
        ladderIncludes4k: (input.ladderPolicy ?? "STANDARD") === "INCLUDE_4K",
      },
    });
  } catch (err) {
    // Roll back the multipart so we don't accrue orphan storage charges.
    await s3AbortMultipartUpload(storageKey, uploadId).catch(() => {});
    throw err;
  }

  return { videoId, uploadId, storageKey };
}

/**
 * Issue presigned URLs for a batch of part numbers. The client uploads each
 * part concurrently, collects the per-part ETag, and submits them to
 * completeVideoUpload.
 */
export async function presignVideoUploadParts(input: {
  videoId: string;
  uploadId: string;
  partNumbers: number[];
  viewer: Viewer;
}): Promise<PresignedUploadPart[]> {
  const meta = await loadVideoMeta(input.videoId);
  if (!meta) throw new VideoError("NOT_FOUND", "Video not found");
  if (!isOwnerOrAdmin(meta, input.viewer)) {
    throw new VideoError("NOT_FOUND", "Video not found");
  }
  if (meta.status !== "PENDING" || !meta.sourceKey) {
    throw new VideoError("INVALID_STATE", "Upload already finalized");
  }
  return Promise.all(
    input.partNumbers.map((partNumber) =>
      s3PresignUploadPart(meta.sourceKey!, input.uploadId, partNumber),
    ),
  );
}

export type CompleteUploadInput = {
  videoId: string;
  uploadId: string;
  parts: CompletedPart[];
  viewer: Viewer;
};

/**
 * Finalize the multipart upload, HEAD the resulting object, and flip the
 * row to TRANSCODING. The transcode worker is enqueued by the route layer
 * after this returns so the caller can decide whether to wait. Idempotent
 * for already-TRANSCODING/READY rows.
 */
export async function completeVideoUpload(input: CompleteUploadInput): Promise<VideoMeta> {
  if (!storage) throw new VideoError("STORAGE_DISABLED", "Object storage is not configured");
  const meta = await loadVideoMeta(input.videoId);
  if (!meta) throw new VideoError("NOT_FOUND", "Video not found");
  if (!isOwnerOrAdmin(meta, input.viewer)) {
    throw new VideoError("NOT_FOUND", "Video not found");
  }
  if (meta.status !== "PENDING") {
    // Idempotent — a retry after a flaky network is normal.
    return meta;
  }
  if (!meta.sourceKey) {
    throw new VideoError("INVALID_STATE", "Video has no source key");
  }

  await s3CompleteMultipartUpload(meta.sourceKey, input.uploadId, input.parts);

  const head = await headStorageObject(meta.sourceKey);
  if (!head) throw new VideoError("UPLOAD_MISSING", "Storage object is missing");
  if (meta.sourceSize !== null && head.contentLength !== meta.sourceSize) {
    throw new VideoError("SIZE_MISMATCH", "Uploaded object size does not match expected size");
  }

  const updated = await prisma.video.update({
    where: { id: meta.id },
    data: {
      status: "TRANSCODING",
      sourceSize: BigInt(head.contentLength),
    },
  });
  return toVideoMeta(updated);
}

export async function abortVideoUpload(input: {
  videoId: string;
  uploadId: string;
  viewer: Viewer;
}): Promise<void> {
  const meta = await loadVideoMeta(input.videoId);
  if (!meta) return;
  if (!isOwnerOrAdmin(meta, input.viewer)) return;
  if (meta.sourceKey) {
    await s3AbortMultipartUpload(meta.sourceKey, input.uploadId).catch(() => {});
  }
  // Atomic check-and-delete: if a worker flipped status out of PENDING
  // between loadVideoMeta() and now, leave the row alone — and don't touch
  // the source bytes either, since the worker still needs them.
  const deleted = await prisma.video
    .deleteMany({ where: { id: input.videoId, status: "PENDING" } })
    .catch(() => ({ count: 0 }));
  if (deleted.count > 0 && meta.sourceKey) {
    await deleteStorageObject(meta.sourceKey).catch(() => {});
  }
}

export async function heartbeatVideoUpload(input: {
  videoId: string;
  viewer: Viewer;
}): Promise<void> {
  const meta = await loadVideoMeta(input.videoId);
  if (!meta) throw new VideoError("NOT_FOUND", "Video not found");
  if (!isOwnerOrAdmin(meta, input.viewer)) {
    throw new VideoError("NOT_FOUND", "Video not found");
  }
  if (meta.status !== "PENDING") return;
  await prisma.video.update({
    where: { id: meta.id },
    data: { uploadHeartbeatAt: new Date() },
  });
}

// ---------------------------------------------------------------------------
// Artifact reads
// ---------------------------------------------------------------------------

/**
 * Fetch a stored artifact (segment, playlist, subtitle, thumbnail) and pass
 * through an optional Range header. The caller has already authorized the
 * read via `authorizeVideoRead`; this is just the byte read.
 */
export async function readVideoArtifact(
  key: string,
  range: string | null,
): Promise<StorageObjectRange | null> {
  return getStorageObjectRange(key, range);
}

// ---------------------------------------------------------------------------
// Master playlist generation
// ---------------------------------------------------------------------------

export type MasterPlaylistInput = {
  video: VideoMeta;
  renditions: Array<{ height: number; width: number; bandwidth: number; codecs: string }>;
  audioTracks: Array<{ locale: string; label: string; isDefault: boolean }>;
  subtitleTracks: Array<{
    locale: string;
    label: string;
    kind: VideoSubtitleKind;
    isDefault: boolean;
  }>;
};

/**
 * Build an HLS master playlist for a Video. We generate this at request time
 * (rather than baking it during the worker pass) so adding a new audio track
 * or subtitle track shows up immediately — no re-encode required.
 *
 * The playlist references segment playlists by relative path. The route
 * layer (apps/server/src/video-routes.ts) serves those at
 * `/api/videos/<id>/v/<height>/playlist.m3u8` and friends.
 */
export function buildMasterPlaylist(input: MasterPlaylistInput): string {
  const lines: string[] = ["#EXTM3U", "#EXT-X-VERSION:6", "#EXT-X-INDEPENDENT-SEGMENTS"];

  // Subtitles: EXT-X-MEDIA TYPE=SUBTITLES, one per (locale, kind).
  for (const sub of input.subtitleTracks) {
    const attrs = [
      "TYPE=SUBTITLES",
      'GROUP-ID="subs"',
      `NAME=${quote(sub.label)}`,
      sub.isDefault ? "DEFAULT=YES" : "DEFAULT=NO",
      "AUTOSELECT=YES",
      `LANGUAGE=${quote(sub.locale)}`,
      `URI=${quote(`t/${videoStorageKeys.subtitleTrackFilename(sub.locale, sub.kind)}`)}`,
    ];
    lines.push(`#EXT-X-MEDIA:${attrs.join(",")}`);
  }

  // Audio renditions: EXT-X-MEDIA TYPE=AUDIO, one per (locale).
  for (const audio of input.audioTracks) {
    const attrs = [
      "TYPE=AUDIO",
      'GROUP-ID="audio"',
      `NAME=${quote(audio.label)}`,
      audio.isDefault ? "DEFAULT=YES" : "DEFAULT=NO",
      "AUTOSELECT=YES",
      `LANGUAGE=${quote(audio.locale)}`,
      `URI=${quote(`a/${audio.locale}/playlist.m3u8`)}`,
    ];
    lines.push(`#EXT-X-MEDIA:${attrs.join(",")}`);
  }

  // Sorted ascending by bandwidth so well-behaved players pick the lowest
  // rendition first and ramp up — better startup time on flaky connections.
  const sorted = [...input.renditions].sort((a, b) => a.bandwidth - b.bandwidth);
  for (const r of sorted) {
    const attrs = [
      `BANDWIDTH=${r.bandwidth}`,
      `RESOLUTION=${r.width}x${r.height}`,
      `CODECS=${quote(r.codecs)}`,
      'AUDIO="audio"',
    ];
    if (input.subtitleTracks.length > 0) {
      attrs.push('SUBTITLES="subs"');
    }
    lines.push(`#EXT-X-STREAM-INF:${attrs.join(",")}`);
    lines.push(`v/${r.height}/playlist.m3u8`);
  }

  return `${lines.join("\n")}\n`;
}

function quote(s: string): string {
  return `"${stripHlsControlChars(s).replace(/"/g, '\\"')}"`;
}

function stripHlsControlChars(s: string): string {
  let out = "";
  for (const char of s) {
    const code = char.charCodeAt(0);
    out += code < 32 || code === 127 ? " " : char;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function isOwnerOrAdmin(meta: VideoMeta, viewer: Viewer): boolean {
  if (viewer.kind === "anonymous") return false;
  if (isAdminRole(viewer.role)) return true;
  return meta.ownerId !== null && meta.ownerId === viewer.userId;
}

export function isVideoOwnerOrAdmin(meta: VideoMeta, viewer: Viewer): boolean {
  return isOwnerOrAdmin(meta, viewer);
}

function newVideoId(): string {
  // The Prisma schema uses cuid(2) by default. We don't have the runtime
  // helper exposed here, so reuse randomUUID — the row id is opaque to the
  // app, and S3 storage keys are derived from it.
  return randomUUID();
}

type VideoRow = {
  id: string;
  title: string;
  description: string | null;
  status: { toString(): string } | string;
  failureReason: string | null;
  visibility: { toString(): string } | string;
  ownerId: string | null;
  sourceLocale: string;
  durationSeconds: number | null;
  width: number | null;
  height: number | null;
  sourceKey: string | null;
  sourceSize: bigint | null;
  sourceMimeType: string | null;
  posterAssetId: string | null;
  ladderPolicy: { toString(): string } | string | null;
  ladderIncludes4k: boolean;
};

export function toVideoMeta(row: VideoRow): VideoMeta {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    status: String(row.status) as VideoStatus,
    failureReason: row.failureReason,
    visibility: String(row.visibility) as VideoVisibility,
    ownerId: row.ownerId,
    sourceLocale: row.sourceLocale,
    durationSeconds: row.durationSeconds,
    width: row.width,
    height: row.height,
    sourceKey: row.sourceKey,
    sourceSize: row.sourceSize === null ? null : Number(row.sourceSize),
    sourceMimeType: row.sourceMimeType,
    posterAssetId: row.posterAssetId,
    ladderPolicy:
      row.ladderPolicy === null
        ? row.ladderIncludes4k
          ? "INCLUDE_4K"
          : "STANDARD"
        : (String(row.ladderPolicy) as VideoLadderPolicy),
  };
}
