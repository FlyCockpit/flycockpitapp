import { Queue } from "bullmq";
import { getRedisConnection } from "./connection.js";
import { QUEUE_NAMES } from "./jobs.js";

export { FlowProducer, Job, Queue, QueueEvents, Worker } from "bullmq";
export {
  closeRedisConnection,
  createRedisConnection,
  getRedisConnection,
  resetRedisConnectionForTests,
} from "./connection.js";
export {
  ACTIVATE_DUE_POLICIES_REPEAT_EVERY_MS,
  ACTIVATE_DUE_POLICIES_REPEAT_KEY,
  type ActivateDuePoliciesJobData,
  type AnalyzeAssetJobData,
  activateDuePoliciesJobSchema,
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

function lazyQueue(
  name: string,
  options: Omit<NonNullable<ConstructorParameters<typeof Queue>[1]>, "connection">,
): Queue {
  let queue: Queue | undefined;
  const current = () =>
    (queue ??= new Queue(name, { ...options, connection: getRedisConnection() }));
  return new Proxy({} as Queue, {
    get: (_target, property) => {
      const value = Reflect.get(current(), property);
      return typeof value === "function" ? value.bind(current()) : value;
    },
    set: (_target, property, value) => Reflect.set(current(), property, value),
  });
}

/** Pre-configured echo queue. Add more queues here as needed. */
export const echoQueue = lazyQueue(QUEUE_NAMES.echo, {
  defaultJobOptions,
});

/** Re-derives Asset metadata from S3 bytes after a presigned upload finalizes. */
export const analyzeAssetQueue = lazyQueue(QUEUE_NAMES.analyzeAsset, {
  defaultJobOptions,
});

/**
 * Sweeps orphan PENDING Asset rows + orphan S3 objects. Triggered by the
 * admin cleanup page on demand and by a 24h cron registered in the worker.
 * Single-attempt — a transient failure is logged and the next cron firing
 * picks it up; retrying immediately would burn API quota for no gain.
 */
export const cleanupAssetsQueue = lazyQueue(QUEUE_NAMES.cleanupAssets, {
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
export const transcodeVideoQueue = lazyQueue(QUEUE_NAMES.transcodeVideo, {
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
export const transcodeAudioTrackQueue = lazyQueue(QUEUE_NAMES.transcodeAudioTrack, {
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
export const cleanupVideosQueue = lazyQueue(QUEUE_NAMES.cleanupVideos, {
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
export const seedQueue = lazyQueue(QUEUE_NAMES.seed, {
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});

/** Generates enterprise log export artifacts. Potentially large, so concurrency stays low. */
export const enterpriseLogExportQueue = lazyQueue(QUEUE_NAMES.enterpriseLogExport, {
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
    removeOnComplete: { age: 86400, count: 1000 },
  },
});

/**
 * Wakes up the public-service-policy activation state machine. A DB-time
 * state machine, so a single attempt is enough — the next firing resumes from
 * durable row state. Concurrency is pinned to 1 in the worker.
 */
export const activateDuePoliciesQueue = lazyQueue(QUEUE_NAMES.activateDuePolicies, {
  defaultJobOptions: {
    ...defaultJobOptions,
    attempts: 1,
  },
});
