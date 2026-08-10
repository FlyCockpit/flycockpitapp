import { randomUUID } from "node:crypto";
import prisma from "@flycockpit/db";

const MAX_ATTEMPTS = 8;
const LEASE_MS = 60_000;

export type RemoteAdminNotificationDelivery = {
  eventId: string;
  userId: string;
  event: string;
  payload: unknown;
};

/** Claims each recipient independently; delivery must be idempotent on eventId+userId. */
export async function deliverRemoteAdminNotificationBatch(input: {
  now?: Date;
  limit?: number;
  deliver: (notification: RemoteAdminNotificationDelivery) => Promise<void>;
}) {
  const now = input.now ?? new Date();
  const leaseToken = randomUUID();
  const candidates = await prisma.remoteAdminNotificationRecipient.findMany({
    where: {
      OR: [
        { state: "PENDING", nextAttemptAt: { lte: now } },
        { state: "PROCESSING", leaseUntil: { lt: now } },
      ],
    },
    orderBy: [{ nextAttemptAt: "asc" }, { id: "asc" }],
    take: Math.max(1, Math.min(input.limit ?? 100, 500)),
    select: { id: true },
  });
  if (candidates.length === 0) return { claimed: 0, delivered: 0, failed: 0 };
  const ids = candidates.map((candidate) => candidate.id);
  await prisma.remoteAdminNotificationRecipient.updateMany({
    where: {
      id: { in: ids },
      OR: [
        { state: "PENDING", nextAttemptAt: { lte: now } },
        { state: "PROCESSING", leaseUntil: { lt: now } },
      ],
    },
    data: { state: "PROCESSING", leaseToken, leaseUntil: new Date(now.getTime() + LEASE_MS) },
  });
  const claimed = await prisma.remoteAdminNotificationRecipient.findMany({
    where: { leaseToken, state: "PROCESSING" },
    include: { Outbox: true },
  });
  let delivered = 0;
  let failed = 0;
  for (const recipient of claimed) {
    try {
      await input.deliver({
        eventId: recipient.outboxId,
        userId: recipient.userId,
        event: recipient.Outbox.event,
        payload: recipient.Outbox.payload,
      });
      await prisma.remoteAdminNotificationRecipient.updateMany({
        where: { id: recipient.id, leaseToken, state: "PROCESSING" },
        data: {
          state: "DELIVERED",
          deliveredAt: now,
          attempts: { increment: 1 },
          leaseToken: null,
          leaseUntil: null,
          lastErrorCode: null,
        },
      });
      delivered += 1;
    } catch {
      const attempts = recipient.attempts + 1;
      const terminal = attempts >= MAX_ATTEMPTS;
      await prisma.remoteAdminNotificationRecipient.updateMany({
        where: { id: recipient.id, leaseToken, state: "PROCESSING" },
        data: {
          state: terminal ? "FAILED" : "PENDING",
          attempts,
          nextAttemptAt: new Date(now.getTime() + Math.min(3_600_000, 2 ** attempts * 1000)),
          leaseToken: null,
          leaseUntil: null,
          lastErrorCode: "DELIVERY_FAILED",
        },
      });
      failed += 1;
    }
  }
  const outboxIds = [...new Set(claimed.map((recipient) => recipient.outboxId))];
  for (const outboxId of outboxIds) {
    const outstanding = await prisma.remoteAdminNotificationRecipient.count({
      where: { outboxId, state: { in: ["PENDING", "PROCESSING"] } },
    });
    if (outstanding === 0)
      await prisma.remoteAdminNotificationOutbox.updateMany({
        where: { id: outboxId, deliveredAt: null },
        data: { deliveredAt: now },
      });
  }
  return { claimed: claimed.length, delivered, failed };
}
