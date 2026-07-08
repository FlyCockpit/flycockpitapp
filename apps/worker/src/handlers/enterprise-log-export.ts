import { generateEnterpriseLogExport } from "@flycockpit/api/enterprise/log-export";
import type { EnterpriseLogExportJobData } from "@flycockpit/queue";
import type { Job } from "bullmq";

export async function handleEnterpriseLogExportJob(job: Job<EnterpriseLogExportJobData>) {
  console.log("[enterprise-log-export] Job " + job.id + ": export=" + job.data.exportId);
  const result = await generateEnterpriseLogExport(job.data.exportId);
  return { exportId: result.id, status: result.status };
}
