import { z } from "zod";

/**
 * Job schemas — define the shape of each job's payload here.
 * Both producers and workers import from this file so the contract is shared.
 */

export const echoJobSchema = z.object({
  message: z.string(),
});

export type EchoJobData = z.infer<typeof echoJobSchema>;

/**
 * Re-derive an Asset row's width/height/blurhash from the bytes in S3 and
 * flip metadataState to SERVER_VERIFIED. Enqueued by the presigned-upload
 * finalize handler so client-supplied hints are eventually replaced with
 * server-verified values.
 */
export const analyzeAssetJobSchema = z.object({
  assetId: z.string().min(1),
});

export type AnalyzeAssetJobData = z.infer<typeof analyzeAssetJobSchema>;

/**
 * Sweep orphan PENDING Asset rows, orphan S3 objects under the `assets/`
 * prefix, and incomplete multipart uploads. Triggered manually from the
 * admin cleanup page (`reason: "admin"`) or by the 24h cron (`reason: "cron"`).
 *
 * The thresholds default to: 5 minutes for PENDING rows, 15 minutes minimum
 * age for orphan S3 objects (the in-flight grace window), 24 hours for
 * incomplete multiparts. Override only from automated tests.
 */
export const cleanupAssetsJobSchema = z.object({
  reason: z.enum(["admin", "cron"]),
  pendingMaxAgeMs: z.number().int().positive().optional(),
  objectMinAgeMs: z.number().int().positive().optional(),
  multipartMaxAgeMs: z.number().int().positive().optional(),
});

export type CleanupAssetsJobData = z.infer<typeof cleanupAssetsJobSchema>;

/**
 * Run the ffmpeg HLS ladder against a freshly-uploaded raw video. Produces:
 *   * per-rendition video segments (360/540/720/1080[+2160]) at
 *     `videos/<id>/v/<height>/...`,
 *   * the default audio track at `videos/<id>/a/<sourceLocale>/...`,
 *   * sprite-sheet thumbnails + a WebVTT manifest for hover previews,
 *   * a poster image (midpoint frame) if the Video row doesn't already have
 *     a user-supplied posterAssetId,
 *   * the master playlist at `videos/<id>/playlist.m3u8`.
 *
 * Flips Video.status PENDING -> TRANSCODING -> READY (or FAILED on terminal
 * failure). Sets VideoRendition rows and the default VideoAudioTrack row.
 *
 * Concurrency is kept low in the worker (CPU + memory hog). For low-volume
 * deployments, consolidate into the general queue — see the video pipeline notes.
 */
export const transcodeVideoJobSchema = z.object({
  videoId: z.string().min(1),
});

export type TranscodeVideoJobData = z.infer<typeof transcodeVideoJobSchema>;

/**
 * Generate HLS audio segments for an additional VideoAudioTrack (a dub) and
 * append the rendition to the master playlist. The track's `sourceKey` must
 * point at a finalized upload; the worker extracts AAC audio (whether the
 * source is .mp3/.wav/.m4a or a full video) and writes segments under
 * `videos/<videoId>/a/<locale>/...`.
 *
 * Validates duration matches the canonical video within ±2s; on mismatch
 * flips the track to FAILED and surfaces `failureReason` to the admin UI.
 * Frame-shifted dubs are not supported — those should be modeled as a
 * separate Video joined by a translationGroup convention.
 */
export const transcodeAudioTrackJobSchema = z.object({
  audioTrackId: z.string().min(1),
});

export type TranscodeAudioTrackJobData = z.infer<typeof transcodeAudioTrackJobSchema>;

/**
 * Sweep orphan PENDING Video / VideoAudioTrack rows and unreferenced S3
 * objects under `videos/` and `rawVideos/`. Same shape as cleanupAssets but
 * scoped to the video prefixes — keeps the two domains independent so
 * removing the video pattern doesn't touch asset cleanup.
 */
export const cleanupVideosJobSchema = z.object({
  reason: z.enum(["admin", "cron"]),
  pendingMaxAgeMs: z.number().int().positive().optional(),
  transcodingMaxAgeMs: z.number().int().positive().optional(),
  objectMinAgeMs: z.number().int().positive().optional(),
  multipartMaxAgeMs: z.number().int().positive().optional(),
});

export type CleanupVideosJobData = z.infer<typeof cleanupVideosJobSchema>;

/**
 * Run the database seed (`packages/db/prisma/seed.ts → runSeed()`). Admin-only,
 * on-demand — there is no cron for this. `requestedBy` is the admin user id,
 * logged by the worker so a seed run is attributable.
 *
 * The handler is single-attempt (`attempts: 1`): a seed is author-written and
 * may not be safe to auto-retry, so a failure surfaces to the admin who then
 * decides whether to re-run.
 */
export const seedJobSchema = z.object({
  requestedBy: z.string().min(1),
});

export type SeedJobData = z.infer<typeof seedJobSchema>;

/** Generate an enterprise log export artifact from already-ingested events. */
export const enterpriseLogExportJobSchema = z.object({
  exportId: z.string().min(1),
});

export type EnterpriseLogExportJobData = z.infer<typeof enterpriseLogExportJobSchema>;

/**
 * Queue names — use these constants instead of string literals.
 */
export const QUEUE_NAMES = {
  echo: "echo",
  analyzeAsset: "analyze-asset",
  cleanupAssets: "cleanup-assets",
  transcodeVideo: "transcode-video",
  transcodeAudioTrack: "transcode-audio-track",
  cleanupVideos: "cleanup-videos",
  seed: "seed",
  enterpriseLogExport: "enterprise-log-export",
} as const;

/** Repeat key for the 24h video-cleanup cron. */
export const CLEANUP_VIDEOS_CRON_KEY = "cleanup-videos-daily";

/**
 * Once a day at 03:45 UTC — staggered 30 min after cleanup-assets so the two
 * sweeps don't pile on the same Redis + S3 quota window.
 */
export const CLEANUP_VIDEOS_CRON_PATTERN = "45 3 * * *";

/** Repeat key for the 24h asset-cleanup cron. */
export const CLEANUP_ASSETS_CRON_KEY = "cleanup-assets-daily";

/** Once a day at 03:15 UTC. Quiet hours for most consumer apps. */
export const CLEANUP_ASSETS_CRON_PATTERN = "15 3 * * *";
