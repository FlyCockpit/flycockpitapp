import prisma from "@flycockpit/db";
import { enterpriseLogExportQueue } from "@flycockpit/queue";
import { ORPCError } from "@orpc/server";
import { z } from "zod";
import { adminOr404Procedure, protectedProcedure, publicProcedure } from "../index";
import { logEnterpriseAudit } from "./audit";
import {
  createEnterpriseExportInputSchema,
  enterpriseIngestInputSchema,
  enterprisePolicyUpdateInputSchema,
} from "./contracts";
import { createEnterpriseExportDownloadUrl } from "./log-export";
import {
  authenticateEnterpriseInstance,
  getPrimaryOrgForUser,
  policyFromOrg,
  requireEnterpriseLogExport,
  requireOrgAdmin,
  slugifyOrgName,
} from "./orgs";

const orgIdInput = z.object({ orgId: z.string().min(1) });
const exportIdInput = z.object({ exportId: z.string().min(1) });

export const enterpriseRouter = {
  bootstrap: adminOr404Procedure
    .input(z.object({ name: z.string().trim().min(1).max(120).default("Enterprise") }).optional())
    .handler(async ({ input, context }) => {
      await requireEnterpriseLogExport(context.session.user.id);
      const existing = await prisma.enterpriseOrg.findFirst({ orderBy: { createdAt: "asc" } });
      if (existing) {
        await ensureOrgAdmin(existing.id, context.session.user.id);
        return { org: existing, policy: policyFromOrg(existing) };
      }
      const name = input?.name ?? "Enterprise";
      const org = await prisma.enterpriseOrg.create({
        data: {
          name,
          slug: slugifyOrgName(name),
          Members: { create: { userId: context.session.user.id, role: "ORG_ADMIN" } },
        },
      });
      await logEnterpriseAudit({
        orgId: org.id,
        userId: context.session.user.id,
        action: "enterprise.org.bootstrap",
        entity: "EnterpriseOrg",
        entityId: org.id,
        metadata: { name },
      });
      return { org, policy: policyFromOrg(org) };
    }),

  overview: protectedProcedure.handler(async ({ context }) => {
    await requireEnterpriseLogExport(context.session.user.id);
    const membership = await getPrimaryOrgForUser(context.session.user.id);
    if (!membership) return { org: null, membership: null, policy: null };
    const [members, exports, instances, eventCount] = await Promise.all([
      prisma.enterpriseOrgMember.findMany({
        where: { orgId: membership.orgId },
        orderBy: [{ role: "asc" }, { createdAt: "asc" }],
        include: { User: { select: { id: true, name: true, email: true } } },
      }),
      prisma.enterpriseLogExport.findMany({
        where: { orgId: membership.orgId },
        orderBy: { createdAt: "desc" },
        take: 20,
      }),
      listOrgInstances(membership.orgId),
      prisma.enterpriseLogEvent.count({ where: { orgId: membership.orgId } }),
    ]);
    return {
      org: membership.EnterpriseOrg,
      membership: { role: membership.role },
      policy: policyFromOrg(membership.EnterpriseOrg),
      members,
      exports,
      instances,
      eventCount,
    };
  }),

  updatePolicy: protectedProcedure
    .input(enterprisePolicyUpdateInputSchema)
    .handler(async ({ input, context }) => {
      await requireOrgAdmin(context.session.user.id, input.orgId);
      const org = await prisma.enterpriseOrg.update({
        where: { id: input.orgId },
        data: {
          logSyncMandated: input.logSyncMandated,
          syncSessionEvents: input.syncSessionEvents,
          syncMessageEvents: input.syncMessageEvents,
          syncToolCallEvents: input.syncToolCallEvents,
          syncInferenceEvents: input.syncInferenceEvents,
          syncTruncationEvents: input.syncTruncationEvents,
          includeLocalModels: input.includeLocalModels,
          backfill: input.backfill,
          backlogPolicy: input.backlogPolicy,
          retentionDays: input.retentionDays,
          policyVersion: { increment: 1 },
        },
      });
      await logEnterpriseAudit({
        orgId: org.id,
        userId: context.session.user.id,
        action: "enterprise.policy.update",
        entity: "EnterpriseOrg",
        entityId: org.id,
        metadata: { policyVersion: org.policyVersion },
      });
      return { org, policy: policyFromOrg(org) };
    }),

  instancePolicy: publicProcedure
    .input(z.object({ instanceId: z.string().min(1), instanceToken: z.string().min(1) }))
    .handler(async ({ input }) => {
      const { org } = await authenticateEnterpriseInstance(input.instanceId, input.instanceToken);
      return policyFromOrg(org);
    }),

  ingest: publicProcedure.input(enterpriseIngestInputSchema).handler(async ({ input }) => {
    const { instance, org } = await authenticateEnterpriseInstance(
      input.instanceId,
      input.instanceToken,
    );
    await requireEnterpriseLogExport(instance.userId);
    const firstSeq = Math.min(...input.events.map((event) => event.seq));
    const lastSeq = Math.max(...input.events.map((event) => event.seq));
    const existing = await prisma.enterpriseLogBatch.findFirst({
      where: { instanceId: instance.id, firstSeq, lastSeq },
      select: { id: true, eventCount: true },
    });
    if (existing) {
      return {
        duplicate: true,
        acceptedEvents: 0,
        droppedEvents: input.events.length,
        policyVersion: org.policyVersion,
      };
    }

    const policy = policyFromOrg(org);
    const accepted = input.events.filter((event) => policy.logSync.eventKindPolicy[event.kind]);
    const batch = await prisma.enterpriseLogBatch.create({
      data: {
        orgId: org.id,
        instanceId: instance.id,
        userId: instance.userId,
        schemaVersion: input.schemaVersion,
        idempotencyKey: input.idempotencyKey,
        firstSeq,
        lastSeq,
        eventCount: accepted.length,
        policyVersion: org.policyVersion,
      },
    });
    await prisma.enterpriseLogEvent.createMany({
      data: accepted.map((event) => ({
        orgId: org.id,
        batchId: batch.id,
        instanceId: instance.id,
        userId: instance.userId,
        seq: event.seq,
        sessionId: event.sessionId,
        projectRoot: event.projectRoot,
        kind: event.kind,
        occurredAt: event.occurredAt ? new Date(event.occurredAt) : null,
        model: event.model,
        role: event.role,
        content: event.content,
        payload: event.payload,
        redactionVersion: event.redactionVersion,
        truncated: event.truncated,
      })),
      skipDuplicates: true,
    });
    return {
      duplicate: false,
      acceptedEvents: accepted.length,
      droppedEvents: input.events.length - accepted.length,
      policyVersion: org.policyVersion,
    };
  }),

  createExport: protectedProcedure
    .input(createEnterpriseExportInputSchema)
    .handler(async ({ input, context }) => {
      await requireOrgAdmin(context.session.user.id, input.filters.orgId);
      const exportRow = await prisma.enterpriseLogExport.create({
        data: {
          orgId: input.filters.orgId,
          requestedById: context.session.user.id,
          format: input.format,
          filters: input.filters,
        },
      });
      await enterpriseLogExportQueue.add("enterprise-log-export", { exportId: exportRow.id });
      await logEnterpriseAudit({
        orgId: input.filters.orgId,
        userId: context.session.user.id,
        action: "enterprise.export.create",
        entity: "EnterpriseLogExport",
        entityId: exportRow.id,
        metadata: { format: input.format, filters: input.filters },
      });
      return exportRow;
    }),

  listExports: protectedProcedure.input(orgIdInput).handler(async ({ input, context }) => {
    await requireOrgAdmin(context.session.user.id, input.orgId);
    return prisma.enterpriseLogExport.findMany({
      where: { orgId: input.orgId },
      orderBy: { createdAt: "desc" },
      take: 100,
    });
  }),

  downloadExport: protectedProcedure.input(exportIdInput).handler(async ({ input, context }) => {
    const exportRow = await prisma.enterpriseLogExport.findUnique({
      where: { id: input.exportId },
    });
    if (!exportRow) throw new ORPCError("NOT_FOUND", { message: "Export not found." });
    await requireOrgAdmin(context.session.user.id, exportRow.orgId);
    const signed = await createEnterpriseExportDownloadUrl(input.exportId);
    if (!signed) throw new ORPCError("CONFLICT", { message: "Export artifact is not ready." });
    await logEnterpriseAudit({
      orgId: exportRow.orgId,
      userId: context.session.user.id,
      action: "enterprise.export.download",
      entity: "EnterpriseLogExport",
      entityId: exportRow.id,
      metadata: { format: exportRow.format },
    });
    return signed;
  }),

  transparency: protectedProcedure.handler(async ({ context }) => {
    await requireEnterpriseLogExport(context.session.user.id);
    const membership = await getPrimaryOrgForUser(context.session.user.id);
    if (!membership) throw new ORPCError("NOT_FOUND", { message: "Enterprise org not found." });
    const [eventCount, batchCount, lastEvent] = await Promise.all([
      prisma.enterpriseLogEvent.count({
        where: { orgId: membership.orgId, userId: context.session.user.id },
      }),
      prisma.enterpriseLogBatch.count({
        where: { orgId: membership.orgId, userId: context.session.user.id },
      }),
      prisma.enterpriseLogEvent.findFirst({
        where: { orgId: membership.orgId, userId: context.session.user.id },
        orderBy: { createdAt: "desc" },
        select: { createdAt: true },
      }),
    ]);
    return {
      org: membership.EnterpriseOrg,
      policy: policyFromOrg(membership.EnterpriseOrg),
      stats: { eventCount, batchCount, lastSyncedAt: lastEvent?.createdAt ?? null },
    };
  }),
};

async function ensureOrgAdmin(orgId: string, userId: string) {
  await prisma.enterpriseOrgMember.upsert({
    where: { orgId_userId: { orgId, userId } },
    create: { orgId, userId, role: "ORG_ADMIN" },
    update: { role: "ORG_ADMIN" },
  });
}

async function listOrgInstances(orgId: string) {
  const members = await prisma.enterpriseOrgMember.findMany({
    where: { orgId },
    select: { userId: true },
  });
  const userIds = members.map((member) => member.userId);
  if (userIds.length === 0) return [];
  return prisma.cockpitInstance.findMany({
    where: { userId: { in: userIds } },
    orderBy: [{ lastSeenAt: "desc" }, { createdAt: "desc" }],
    include: { User: { select: { id: true, name: true, email: true } } },
  });
}
