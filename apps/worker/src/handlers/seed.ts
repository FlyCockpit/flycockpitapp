import { runSeed } from "@flycockpit/db/seed";
import type { SeedJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";

/**
 * Run the database seed (`packages/db/prisma/seed.ts → runSeed()`) off the
 * request path. The same `runSeed()` is what `prisma db seed` and the inline
 * (no-queue) admin path call — see the inline no-worker variant. The returned
 * SeedResult becomes the BullMQ job returnValue so the admin "Run seed" page
 * can render the per-step summary by polling `queue.getJob`.
 */
export async function handleSeedJob(job: Job<SeedJobData>) {
  const start = Date.now();
  console.log(`[seed] Job ${job.id} requested by ${job.data.requestedBy}`);
  const result = await runSeed();
  const durationMs = Date.now() - start;
  console.log(
    `[seed] Job ${job.id} finished in ${durationMs}ms — ${result.summary.length} step(s)`,
  );
  return { ...result, durationMs };
}
