import { runVideoCleanup } from "@flycockpit/api/lib/video-cleanup";
import type { CleanupVideosJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";

/**
 * Three-phase video cleanup. Same shape as cleanup-assets but scoped to the
 * `videos/` and `rawVideos/` prefixes — see packages/api/src/lib/video-cleanup.ts.
 */
export async function handleCleanupVideosJob(job: Job<CleanupVideosJobData>) {
  console.log(`[cleanup-videos] Job ${job.id} starting (reason=${job.data.reason})`);
  const summary = await runVideoCleanup({
    pendingMaxAgeMs: job.data.pendingMaxAgeMs,
    transcodingMaxAgeMs: job.data.transcodingMaxAgeMs,
    objectMinAgeMs: job.data.objectMinAgeMs,
    multipartMaxAgeMs: job.data.multipartMaxAgeMs,
  });
  console.log(
    `[cleanup-videos] Job ${job.id} complete: ${summary.pendingVideosReaped} pending videos, ` +
      `${summary.pendingAudioTracksReaped} pending audio tracks, ` +
      `${summary.staleTranscodingVideosFailed} stale video transcodes, ` +
      `${summary.staleTranscodingAudioTracksFailed} stale audio transcodes, ` +
      `${summary.orphanObjectsDeleted} orphan objects (${summary.orphanObjectsBytes} bytes), ` +
      `${summary.multipartUploadsAborted} multiparts aborted`,
  );
  return summary;
}
