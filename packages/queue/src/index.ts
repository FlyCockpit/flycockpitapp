import { Queue } from "bullmq";
import { redisConnection } from "./connection.js";
import { QUEUE_NAMES } from "./jobs.js";

export { FlowProducer, Job, Queue, QueueEvents, Worker } from "bullmq";
export { createRedisConnection, redisConnection } from "./connection.js";
export {
  type AnalyzeAssetJobData,
  analyzeAssetJobSchema,
  CLEANUP_ASSETS_CRON_KEY,
  CLEANUP_ASSETS_CRON_PATTERN,
  CLEANUP_VIDEOS_CRON_KEY,
  CLEANUP_VIDEOS_CRON_PATTERN,
  type CleanupAssetsJobData,
  type CleanupVideosJobData,
  cleanupAssetsJobSchema,
  cleanupVideosJobSchema,
  type EchoJobData,
  type EnterpriseLogExportJobData,
  echoJobSchema,
  enterpriseLogExportJobSchema,
  QUEUE_NAMES,
  type SeedJobData,
  seedJobSchema,
  type TranscodeAudioTrackJobData,
  type TranscodeVideoJobData,
  transcodeAudioTrackJobSchema,
  transcodeVideoJobSchema,
} from "./jobs.js";

const defaultJobOptions = {
  attempts: 3,
  backoff: { type: "exponential" as const, delay: 1000 },
  removeOnComplete: { age: 3600, count: 1000 },
  removeOnFail: { age: 86400, count: 5000 },
};

/** Pre-configured echo queue. Add more queues here as needed. */
export const echoQueue = new Queue(QUEUE_NAMES.echo, {
  connection: redisConnection,
  defaultJobOptions,
});

/** Re-derives Asset metadata from S3 bytes after a presigned upload finalizes. */
export const analyzeAssetQueue = new Queue(QUEUE_NAMES.analyzeAsset, {
  connection: redisConnection,
  defaultJobOptions,
});

/**
 * Sweeps orphan PENDING Asset rows + orphan S3 objects. Triggered by the
 * admin cleanup page on demand and by a 24h cron registered in the worker.
 * Single-attempt — a transient failure is logged and the next cron firing
 * picks it up; retrying immediately would burn API quota for no gain.
 */
export const cleanupAssetsQueue = new Queue(QUEUE_NAMES.cleanupAssets, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/**
 * Encodes a raw uploaded video into an HLS adaptive ladder + sprite-sheet
 * thumbnails. CPU-heavy; the worker pins concurrency low (default 1) so
 * multiple in-flight encodes don't fight for the same cores.
 *
 * `attempts: 1` because the encode is deterministic — a failure is almost
 * always input-related (corrupt source, unsupported codec) and retrying
 * burns minutes of CPU for the same outcome. Failures surface in the admin
 * UI via Video.failureReason; admins can re-upload or re-enqueue manually.
 */
export const transcodeVideoQueue = new Queue(QUEUE_NAMES.transcodeVideo, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/**
 * Encodes a single additional audio track (a dub) into HLS segments and
 * appends it to the existing master playlist. Lighter than transcodeVideo —
 * no video re-encode, no thumbnail generation — but still CPU-bound on AAC
 * encoding, so attempts stay at 1 for the same reason.
 */
export const transcodeAudioTrackQueue = new Queue(QUEUE_NAMES.transcodeAudioTrack, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/**
 * Sweeps orphan PENDING Video + VideoAudioTrack rows and unreferenced S3
 * objects under the video prefixes. Single-attempt like cleanupAssets — the
 * next cron firing picks up any transient failure.
 */
export const cleanupVideosQueue = new Queue(QUEUE_NAMES.cleanupVideos, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/**
 * Runs the database seed on demand from the admin "Run seed" button. Single-
 * attempt — an author-written seed is not guaranteed safe to auto-retry, so a
 * failure surfaces to the admin instead of silently re-running. Concurrency is
 * pinned to 1 in the worker so two seed runs never overlap.
 */
export const seedQueue = new Queue(QUEUE_NAMES.seed, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/** Generates enterprise log export artifacts. Potentially large, so concurrency stays low. */
export const enterpriseLogExportQueue = new Queue(QUEUE_NAMES.enterpriseLogExport, {
  connection: redisConnection,
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
    removeOnComplete: { age: 86400, count: 1000 },
  },
});
