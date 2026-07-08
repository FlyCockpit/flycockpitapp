import { storage } from "@flycockpit/api/lib/storage";
import { env } from "@flycockpit/env/shared";
import type {
  AnalyzeAssetJobData,
  CleanupAssetsJobData,
  CleanupVideosJobData,
  EchoJobData,
  EnterpriseLogExportJobData,
  SeedJobData,
  TranscodeAudioTrackJobData,
  TranscodeVideoJobData,
} from "@flycockpit/queue";
import {
  CLEANUP_ASSETS_CRON_KEY,
  CLEANUP_ASSETS_CRON_PATTERN,
  CLEANUP_VIDEOS_CRON_KEY,
  CLEANUP_VIDEOS_CRON_PATTERN,
  cleanupAssetsQueue,
  cleanupVideosQueue,
  createRedisConnection,
  QUEUE_NAMES,
} from "@flycockpit/queue";
import { Worker } from "bullmq";

import { handleAnalyzeAssetJob } from "./handlers/analyze-asset.js";
import { handleCleanupAssetsJob } from "./handlers/cleanup-assets.js";
import { handleCleanupVideosJob } from "./handlers/cleanup-videos.js";
import { handleEchoJob } from "./handlers/echo.js";
import { handleSeedJob } from "./handlers/seed.js";
import {
  handleTranscodeAudioTrackJob,
  markTranscodeAudioTrackFailed,
} from "./handlers/transcode-audio-track.js";
import { handleTranscodeVideoJob, markTranscodeVideoFailed } from "./handlers/transcode-video.js";
import {
  closeOperationalAlertConnection,
  sendOperationalFailureAlert,
} from "./operational-alerts.js";

// ---------------------------------------------------------------------------
// Startup retry — wait for Redis before starting the worker
// ---------------------------------------------------------------------------

const MAX_RETRIES = 10;
const BASE_DELAY_MS = 500;
const REDIS_PING_TIMEOUT_MS = 5000;

const connection = createRedisConnection();

for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
  try {
    await withTimeout(connection.ping(), REDIS_PING_TIMEOUT_MS, "Redis ping timed out");
    console.log("[worker] Redis is reachable.");
    break;
  } catch (err) {
    if (attempt === MAX_RETRIES) {
      console.error("[worker] FATAL: Redis not reachable after max retries. Exiting.");
      process.exit(1);
    }
    const delay = BASE_DELAY_MS * 2 ** (attempt - 1);
    console.warn(
      `[worker] Redis not ready (attempt ${attempt}/${MAX_RETRIES}), retrying in ${delay}ms…`,
      err instanceof Error ? err.message : err,
    );
    await new Promise((r) => setTimeout(r, delay));
  }
}

// ---------------------------------------------------------------------------
// Worker setup
// ---------------------------------------------------------------------------

const echoWorker = new Worker<EchoJobData>(QUEUE_NAMES.echo, handleEchoJob, {
  connection,
  concurrency: 5,
});

echoWorker.on("completed", (job) => {
  console.log(`[echo] Job ${job.id} completed`);
});

echoWorker.on("failed", (job, err) => {
  console.error(`[echo] Job ${job?.id} failed:`, err.message);
  void reportJobFailure("echo", job, err);
});

const analyzeAssetWorker = new Worker<AnalyzeAssetJobData>(
  QUEUE_NAMES.analyzeAsset,
  handleAnalyzeAssetJob,
  // Keep concurrency low — sharp is CPU-bound and these jobs allocate large
  // buffers. Bump only after measuring memory + CPU on the worker host.
  { connection, concurrency: 2 },
);

analyzeAssetWorker.on("completed", (job) => {
  console.log(`[analyze-asset] Job ${job.id} completed`);
});

analyzeAssetWorker.on("failed", (job, err) => {
  console.error(`[analyze-asset] Job ${job?.id} failed:`, err.message);
  void reportJobFailure("analyze-asset", job, err);
});

const cleanupAssetsWorker = new Worker<CleanupAssetsJobData>(
  QUEUE_NAMES.cleanupAssets,
  handleCleanupAssetsJob,
  // Concurrency: 1. The job iterates the whole asset prefix and we never
  // want two sweeps stepping on each other (a row could be deleted twice or
  // a sweep could resurface an object the other one just deleted).
  { connection, concurrency: 1 },
);

cleanupAssetsWorker.on("completed", (job) => {
  console.log(`[cleanup-assets] Job ${job.id} completed`);
});

cleanupAssetsWorker.on("failed", (job, err) => {
  console.error(`[cleanup-assets] Job ${job?.id} failed:`, err.message);
  void reportJobFailure("cleanup-assets", job, err);
});

// Video transcoding — CPU-heavy, low concurrency. Bump
// VIDEO_TRANSCODE_CONCURRENCY only on workers with enough cores for parallel
// encodes (8+ cores recommended for 2 concurrent jobs).
const transcodeVideoWorker = new Worker<TranscodeVideoJobData>(
  QUEUE_NAMES.transcodeVideo,
  handleTranscodeVideoJob,
  { connection, concurrency: env.VIDEO_TRANSCODE_CONCURRENCY },
);

transcodeVideoWorker.on("completed", (job) => {
  console.log(`[transcode-video] Job ${job.id} completed`);
});

transcodeVideoWorker.on("failed", (job, err) => {
  console.error(`[transcode-video] Job ${job?.id} failed:`, err.message);
  if (job?.data.videoId && isTerminalFailure(job)) {
    void markTranscodeVideoFailed(job.data.videoId, err.message);
  }
  void reportJobFailure("transcode-video", job, err);
});

// Audio-track transcoding — lighter than full video, can run higher
// concurrency on the same worker host without contention.
const transcodeAudioTrackWorker = new Worker<TranscodeAudioTrackJobData>(
  QUEUE_NAMES.transcodeAudioTrack,
  handleTranscodeAudioTrackJob,
  { connection, concurrency: env.VIDEO_AUDIO_TRANSCODE_CONCURRENCY },
);

transcodeAudioTrackWorker.on("completed", (job) => {
  console.log(`[transcode-audio-track] Job ${job.id} completed`);
});

transcodeAudioTrackWorker.on("failed", (job, err) => {
  console.error(`[transcode-audio-track] Job ${job?.id} failed:`, err.message);
  if (job?.data.audioTrackId && isTerminalFailure(job)) {
    void markTranscodeAudioTrackFailed(job.data.audioTrackId, err.message);
  }
  void reportJobFailure("transcode-audio-track", job, err);
});

// Video cleanup — same shape as cleanup-assets but scoped to video prefixes.
const cleanupVideosWorker = new Worker<CleanupVideosJobData>(
  QUEUE_NAMES.cleanupVideos,
  handleCleanupVideosJob,
  { connection, concurrency: 1 },
);

cleanupVideosWorker.on("completed", (job) => {
  console.log(`[cleanup-videos] Job ${job.id} completed`);
});

cleanupVideosWorker.on("failed", (job, err) => {
  console.error(`[cleanup-videos] Job ${job?.id} failed:`, err.message);
  void reportJobFailure("cleanup-videos", job, err);
});

// Database seed — on-demand only (no cron). Concurrency 1: never run two seeds
// at once. Single-attempt; a failed author-written seed surfaces to the admin.
const seedWorker = new Worker<SeedJobData>(QUEUE_NAMES.seed, handleSeedJob, {
  connection,
  concurrency: 1,
});

seedWorker.on("completed", (job) => {
  console.log(`[seed] Job ${job.id} completed`);
});

seedWorker.on("failed", (job, err) => {
  console.error(`[seed] Job ${job?.id} failed:`, err.message);
  void reportJobFailure("seed", job, err);
});

// Enterprise log export — the handler pulls in commercially licensed code
// (packages/api/src/enterprise/, see its LICENSE), so it is loaded lazily and
// only on deployments operating under a FlyCockpit commercial agreement.
// `oss` self-hosts never load or execute it; the queue is never populated
// there either (logExport is entitlement-gated to the enterprise profile).
let enterpriseLogExportWorker: Worker<EnterpriseLogExportJobData> | null = null;
if (env.DEPLOYMENT_PROFILE !== "oss") {
  const { handleEnterpriseLogExportJob } = await import("./handlers/enterprise-log-export.js");
  enterpriseLogExportWorker = new Worker<EnterpriseLogExportJobData>(
    QUEUE_NAMES.enterpriseLogExport,
    handleEnterpriseLogExportJob,
    { connection, concurrency: 1 },
  );

  enterpriseLogExportWorker.on("completed", (job) => {
    console.log(`[enterprise-log-export] Job ${job.id} completed`);
  });

  enterpriseLogExportWorker.on("failed", (job, err) => {
    console.error(`[enterprise-log-export] Job ${job?.id} failed:`, err.message);
    void reportJobFailure("enterprise-log-export", job, err);
  });
} else {
  console.log("[enterprise-log-export] Skipped — DEPLOYMENT_PROFILE is oss.");
}

// Register the daily sweep. `repeatJobKey` + `jobId` make this idempotent —
// restarting the worker won't queue a second cron entry.
if (storage) {
  try {
    await cleanupAssetsQueue.add(
      "cleanup-assets",
      { reason: "cron" },
      {
        repeat: { pattern: CLEANUP_ASSETS_CRON_PATTERN, key: CLEANUP_ASSETS_CRON_KEY },
        jobId: CLEANUP_ASSETS_CRON_KEY,
      },
    );
    console.log(`[cleanup-assets] Registered cron (${CLEANUP_ASSETS_CRON_PATTERN}).`);
  } catch (err) {
    console.error("[cleanup-assets] Failed to register cron:", err);
  }

  try {
    await cleanupVideosQueue.add(
      "cleanup-videos",
      { reason: "cron" },
      {
        repeat: { pattern: CLEANUP_VIDEOS_CRON_PATTERN, key: CLEANUP_VIDEOS_CRON_KEY },
        jobId: CLEANUP_VIDEOS_CRON_KEY,
      },
    );
    console.log(`[cleanup-videos] Registered cron (${CLEANUP_VIDEOS_CRON_PATTERN}).`);
  } catch (err) {
    console.error("[cleanup-videos] Failed to register cron:", err);
  }
} else {
  console.log("[cleanup] Object storage is not configured; cleanup crons not registered.");
}

console.log("Worker started — listening for jobs…");

// ---------------------------------------------------------------------------
// Graceful shutdown — close the worker, then disconnect Redis
// ---------------------------------------------------------------------------

let isShuttingDown = false;

async function shutdown(signal: string) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`[worker] Received ${signal} — shutting down…`);

  try {
    await Promise.all([
      echoWorker.close(),
      analyzeAssetWorker.close(),
      cleanupAssetsWorker.close(),
      transcodeVideoWorker.close(),
      transcodeAudioTrackWorker.close(),
      cleanupVideosWorker.close(),
      seedWorker.close(),
      ...(enterpriseLogExportWorker ? [enterpriseLogExportWorker.close()] : []),
    ]);
    console.log("[worker] BullMQ workers closed.");
  } catch (err) {
    console.error("[worker] Error closing workers:", err);
  }

  try {
    connection.disconnect();
    closeOperationalAlertConnection();
    console.log("[worker] Redis disconnected.");
  } catch (err) {
    console.error("[worker] Error disconnecting Redis:", err);
  }

  console.log("[worker] Shutdown complete.");
  process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (err) => {
        clearTimeout(timeout);
        reject(err);
      },
    );
  });
}

type FailedJob = {
  id?: string | number;
  attemptsMade: number;
  finishedOn?: number;
  opts: { attempts?: number };
};

// BullMQ emits `failed` on every attempt, not only the last one. Act (alert,
// mark FAILED) only once the job has exhausted its retries so a queue with
// `attempts > 1` doesn't fire one alert per retry. A missing job handle (rare:
// lock lost) is treated as terminal so the failure is still surfaced.
function isTerminalFailure(job: FailedJob | undefined, err?: Error): boolean {
  if (!job) return true;
  if (err?.name === "UnrecoverableError") return true;
  if (job.finishedOn !== undefined) return true;
  return job.attemptsMade >= (job.opts.attempts ?? 1);
}

async function reportJobFailure(
  queue: string,
  job: FailedJob | undefined,
  err: Error,
): Promise<void> {
  if (!isTerminalFailure(job, err)) return;
  try {
    await sendOperationalFailureAlert({ queue, jobId: job?.id, message: err.message });
  } catch (alertErr) {
    console.error(
      `[${queue}] Failed to send operational alert:`,
      alertErr instanceof Error ? alertErr.message : alertErr,
    );
  }
}
