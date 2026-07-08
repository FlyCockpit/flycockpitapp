import { runCleanup } from "@flycockpit/api/lib/asset-cleanup";
import type { CleanupAssetsJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";

/**
 * Reap orphan PENDING Asset rows and orphan S3 objects under the asset
 * prefix. Same code path whether the admin clicked the button or the 24h
 * cron fired.
 */
export async function handleCleanupAssetsJob(job: Job<CleanupAssetsJobData>) {
  const { reason, pendingMaxAgeMs, objectMinAgeMs, multipartMaxAgeMs } = job.data;
  const start = Date.now();
  const result = await runCleanup({
    pendingMaxAgeMs,
    objectMinAgeMs,
    multipartMaxAgeMs,
  });
  console.log(`[cleanup-assets] Job ${job.id} (${reason}) finished in ${Date.now() - start}ms`, {
    result,
  });
  return { reason, ...result };
}
