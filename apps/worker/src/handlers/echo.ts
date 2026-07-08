import prisma from "@flycockpit/db";
import type { EchoJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";

/**
 * Process an echo job: log the message and persist it as an AppSetting
 * so downstream systems can read the last echo value.
 */
export async function handleEchoJob(job: Job<EchoJobData>) {
  console.log(`[echo] Processing job ${job.id}: ${job.data.message}`);

  await prisma.appSetting.upsert({
    where: { key: `echo:${job.id}` },
    update: { value: job.data.message },
    create: { key: `echo:${job.id}`, value: job.data.message },
  });

  return { echoed: job.data.message };
}
