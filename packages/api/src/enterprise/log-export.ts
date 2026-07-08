import prisma from "@flycockpit/db";
import { presignGet, putStorageObject } from "../lib/storage";
import { logEnterpriseAudit } from "./audit";
import { type EnterpriseExportFilters, enterpriseExportFiltersSchema } from "./contracts";
import { buildEnterpriseExportArtifact } from "./log-transform";

export async function generateEnterpriseLogExport(exportId: string) {
  const exportRow = await prisma.enterpriseLogExport.findUnique({ where: { id: exportId } });
  if (!exportRow) throw new Error("Enterprise log export not found: " + exportId);

  await prisma.enterpriseLogExport.update({
    where: { id: exportId },
    data: { status: "RUNNING", failureReason: null },
  });

  try {
    const filters = enterpriseExportFiltersSchema.parse(exportRow.filters);
    const events = await prisma.enterpriseLogEvent.findMany({
      where: eventWhere(filters),
      orderBy: [{ sessionId: "asc" }, { seq: "asc" }],
    });
    const artifact = buildEnterpriseExportArtifact(events, exportRow.format, filters);
    const extension = exportRow.format === "RAW_NDJSON" ? "ndjson" : "jsonl";
    const storageKey =
      "enterprise-exports/" +
      exportRow.orgId +
      "/" +
      exportId +
      "/" +
      exportRow.format.toLowerCase() +
      "." +
      extension;
    const body = Buffer.from(artifact.body, "utf8");

    await putStorageObject(storageKey, body, artifact.contentType);
    const updated = await prisma.enterpriseLogExport.update({
      where: { id: exportId },
      data: {
        status: "READY",
        manifest: artifact.manifest,
        artifactStorageKey: storageKey,
        artifactSizeBytes: body.byteLength,
        completedAt: new Date(),
      },
    });
    await logEnterpriseAudit({
      orgId: exportRow.orgId,
      userId: exportRow.requestedById,
      action: "enterprise.export.completed",
      entity: "EnterpriseLogExport",
      entityId: exportId,
      metadata: { format: exportRow.format, eventCount: artifact.manifest.eventCount },
    });
    return updated;
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown export failure";
    await prisma.enterpriseLogExport.update({
      where: { id: exportId },
      data: { status: "FAILED", failureReason: message },
    });
    await logEnterpriseAudit({
      orgId: exportRow.orgId,
      userId: exportRow.requestedById,
      action: "enterprise.export.failed",
      entity: "EnterpriseLogExport",
      entityId: exportId,
      metadata: { error: message },
    });
    throw err;
  }
}

export async function createEnterpriseExportDownloadUrl(exportId: string) {
  const exportRow = await prisma.enterpriseLogExport.findUnique({ where: { id: exportId } });
  if (!exportRow?.artifactStorageKey || exportRow.status !== "READY") return null;
  const filename =
    "flycockpit-" +
    exportRow.format.toLowerCase() +
    "-" +
    exportId +
    "." +
    (exportRow.format === "RAW_NDJSON" ? "ndjson" : "jsonl");
  const signed = await presignGet(exportRow.artifactStorageKey, filename);
  return { ...signed, filename };
}

export async function pruneEnterpriseLogs(now = new Date()) {
  const orgs = await prisma.enterpriseOrg.findMany({ select: { id: true, retentionDays: true } });
  const results: Array<{ orgId: string; deletedEvents: number; deletedBatches: number }> = [];
  for (const org of orgs) {
    const cutoff = new Date(now.getTime() - org.retentionDays * 24 * 60 * 60 * 1000);
    const deletedEvents = await prisma.enterpriseLogEvent.deleteMany({
      where: { orgId: org.id, createdAt: { lt: cutoff } },
    });
    const deletedBatches = await prisma.enterpriseLogBatch.deleteMany({
      where: { orgId: org.id, createdAt: { lt: cutoff } },
    });
    results.push({
      orgId: org.id,
      deletedEvents: deletedEvents.count,
      deletedBatches: deletedBatches.count,
    });
  }
  return results;
}

function eventWhere(filters: EnterpriseExportFilters) {
  return {
    orgId: filters.orgId,
    ...(filters.dateFrom || filters.dateTo
      ? {
          occurredAt: {
            ...(filters.dateFrom ? { gte: new Date(filters.dateFrom) } : {}),
            ...(filters.dateTo ? { lte: new Date(filters.dateTo) } : {}),
          },
        }
      : {}),
    ...(filters.userIds?.length ? { userId: { in: filters.userIds } } : {}),
    ...(filters.instanceIds?.length ? { instanceId: { in: filters.instanceIds } } : {}),
    ...(filters.projectRoots?.length ? { projectRoot: { in: filters.projectRoots } } : {}),
    ...(filters.eventKinds?.length ? { kind: { in: filters.eventKinds } } : {}),
  };
}
