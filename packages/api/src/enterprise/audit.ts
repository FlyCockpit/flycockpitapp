import prisma from "@flycockpit/db";
import type { JsonValue } from "./contracts";

export type EnterpriseAuditInput = {
  orgId: string;
  userId: string;
  action: string;
  entity?: string;
  entityId?: string;
  metadata?: Record<string, JsonValue>;
};

export async function logEnterpriseAudit(input: EnterpriseAuditInput): Promise<void> {
  try {
    await prisma.enterpriseAuditLog.create({
      data: {
        orgId: input.orgId,
        userId: input.userId,
        action: input.action,
        entity: input.entity,
        entityId: input.entityId,
        metadata: input.metadata,
      },
    });
  } catch (err) {
    console.error("[enterprise-audit] failed to write entry", err);
  }
}
