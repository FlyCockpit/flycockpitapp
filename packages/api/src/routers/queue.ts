import {
  analyzeAssetQueue,
  cleanupAssetsQueue,
  cleanupVideosQueue,
  echoJobSchema,
  echoQueue,
  QUEUE_NAMES,
  seedQueue,
  transcodeAudioTrackQueue,
  transcodeVideoQueue,
} from "@flycockpit/queue";
import { z } from "zod";
import { adminOr404Procedure } from "../index";

const queuesByName = {
  [QUEUE_NAMES.echo]: echoQueue,
  [QUEUE_NAMES.analyzeAsset]: analyzeAssetQueue,
  [QUEUE_NAMES.cleanupAssets]: cleanupAssetsQueue,
  [QUEUE_NAMES.transcodeVideo]: transcodeVideoQueue,
  [QUEUE_NAMES.transcodeAudioTrack]: transcodeAudioTrackQueue,
  [QUEUE_NAMES.cleanupVideos]: cleanupVideosQueue,
  [QUEUE_NAMES.seed]: seedQueue,
} as const;

const queueNameSchema = z.enum([
  QUEUE_NAMES.echo,
  QUEUE_NAMES.analyzeAsset,
  QUEUE_NAMES.cleanupAssets,
  QUEUE_NAMES.transcodeVideo,
  QUEUE_NAMES.transcodeAudioTrack,
  QUEUE_NAMES.cleanupVideos,
  QUEUE_NAMES.seed,
]);

export const queueRouter = {
  enqueueEcho: adminOr404Procedure.input(echoJobSchema).handler(async ({ input }) => {
    const job = await echoQueue.add("echo", input);
    return { jobId: job.id };
  }),

  getJob: adminOr404Procedure
    .input(
      z.object({
        jobId: z.string(),
        queue: queueNameSchema.default(QUEUE_NAMES.echo),
      }),
    )
    .handler(async ({ input }) => {
      const queue = queuesByName[input.queue];
      const job = await queue.getJob(input.jobId);
      if (!job) return null;
      const state = await job.getState();
      return {
        id: job.id,
        data: job.data,
        state,
        returnValue: job.returnvalue,
        failedReason: job.failedReason,
      };
    }),

  listFailed: adminOr404Procedure
    .input(
      z
        .object({
          limit: z.number().int().min(1).max(100).default(20),
        })
        .optional(),
    )
    .handler(async ({ input }) => {
      const limit = input?.limit ?? 20;
      const entries = await Promise.all(
        Object.entries(queuesByName).map(async ([queueName, queue]) => {
          const jobs = await queue.getJobs(["failed"], 0, limit - 1, false);
          return Promise.all(
            jobs.map(async (job) => ({
              queue: queueName,
              id: job.id ?? null,
              name: job.name,
              failedReason: job.failedReason ?? null,
              attemptsMade: job.attemptsMade,
              timestamp: job.timestamp,
              finishedOn: job.finishedOn ?? null,
            })),
          );
        }),
      );
      const items = entries
        .flat()
        .sort((a, b) => (b.finishedOn ?? b.timestamp) - (a.finishedOn ?? a.timestamp))
        .slice(0, limit);
      return { items };
    }),
};
