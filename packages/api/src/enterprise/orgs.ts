import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/server";
import { ORPCError } from "@orpc/server";
import { can } from "../lib/entitlements";
import { parseInstanceToken, verifyInstanceSecret } from "../lib/instance-credentials";
import type { EnterpriseEventKind } from "./contracts";

export type EnterpriseOrgPolicy = {
  orgId: string;
  policyVersion: number;
  logSync: {
    mandated: boolean;
    eventKindPolicy: Record<EnterpriseEventKind, boolean>;
    includeLocalModels: boolean;
    backfill: boolean;
    backlogPolicy: string;
    retentionDays: number;
  };
};

export function slugifyOrgName(name: string) {
  const slug = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return slug || "enterprise";
}

export function policyFromOrg(org: {
  id: string;
  policyVersion: number;
  logSyncMandated: boolean;
  syncSessionEvents: boolean;
  syncMessageEvents: boolean;
  syncToolCallEvents: boolean;
  syncInferenceEvents: boolean;
  syncTruncationEvents: boolean;
  includeLocalModels: boolean;
  backfill: boolean;
  backlogPolicy: string;
  retentionDays: number;
}): EnterpriseOrgPolicy {
  return {
    orgId: org.id,
    policyVersion: org.policyVersion,
    logSync: {
      mandated: org.logSyncMandated,
      eventKindPolicy: {
        SESSION: org.syncSessionEvents,
        MESSAGE: org.syncMessageEvents,
        TOOL_CALL: org.syncToolCallEvents,
        TOOL_RESULT: org.syncToolCallEvents,
        INFERENCE: org.syncInferenceEvents,
        TRUNCATION: org.syncTruncationEvents,
      },
      includeLocalModels: org.includeLocalModels,
      backfill: org.backfill,
      backlogPolicy: org.backlogPolicy,
      retentionDays: org.retentionDays,
    },
  };
}

export async function requireEnterpriseLogExport(userId: string) {
  if (env.DEPLOYMENT_PROFILE !== "enterprise" || !(await can(userId, "logExport"))) {
    throw new ORPCError("FORBIDDEN", { message: "Enterprise log export is not enabled." });
  }
}

export async function requireOrgAdmin(userId: string, orgId: string) {
  await requireEnterpriseLogExport(userId);
  const member = await prisma.enterpriseOrgMember.findUnique({
    where: { orgId_userId: { orgId, userId } },
    select: { role: true },
  });
  if (member?.role !== "ORG_ADMIN") {
    throw new ORPCError("FORBIDDEN", { message: "Only org admins can manage enterprise exports." });
  }
  return member;
}

export async function getPrimaryOrgForUser(userId: string) {
  return prisma.enterpriseOrgMember.findFirst({
    where: { userId },
    orderBy: [{ role: "asc" }, { createdAt: "asc" }],
    include: { EnterpriseOrg: true },
  });
}

export async function authenticateEnterpriseInstance(instanceId: string, instanceToken: string) {
  const parsed = parseInstanceToken(instanceToken);
  if (!parsed) throw new ORPCError("UNAUTHORIZED", { message: "Invalid instance token." });

  const instance = await prisma.cockpitInstance.findUnique({ where: { id: instanceId } });
  if (!instance || instance.secretPrefix !== parsed.prefix) {
    throw new ORPCError("UNAUTHORIZED", { message: "Invalid instance token." });
  }
  if (String(instance.status) !== "ACTIVE" || instance.revokedAt) {
    throw new ORPCError("FORBIDDEN", { message: "This instance has been revoked." });
  }
  if (!verifyInstanceSecret(parsed.secret, instance.secretHash)) {
    throw new ORPCError("UNAUTHORIZED", { message: "Invalid instance token." });
  }

  const member = await prisma.enterpriseOrgMember.findFirst({
    where: { userId: instance.userId },
    include: { EnterpriseOrg: true },
    orderBy: [{ role: "asc" }, { createdAt: "asc" }],
  });
  if (!member)
    throw new ORPCError("FORBIDDEN", { message: "Instance owner is not in an enterprise org." });

  return { instance, member, org: member.EnterpriseOrg };
}
