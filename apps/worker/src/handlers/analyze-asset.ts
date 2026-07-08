import { analyzeStoredAsset } from "@flycockpit/api/lib/assets";
import type { AnalyzeAssetJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";

/**
 * Re-derive an Asset's width/height/blurhash from the bytes in S3 and flip
 * metadataState to SERVER_VERIFIED. Enqueued by the presigned-upload finalize
 * handler so client-supplied hints are eventually replaced with server-verified
 * values.
 *
 * Lazy import on the API side keeps sharp out of bundles that don't need it.
 */
export async function handleAnalyzeAssetJob(job: Job<AnalyzeAssetJobData>) {
  const { assetId } = job.data;
  const result = await analyzeStoredAsset(assetId);
  if (!result) {
    console.warn(
      `[analyze-asset] Job ${job.id}: asset ${assetId} not analyzable (missing or pending)`,
    );
    return { skipped: true, assetId };
  }
  return {
    assetId,
    metadataState: result.metadataState,
    width: result.width,
    height: result.height,
  };
}
