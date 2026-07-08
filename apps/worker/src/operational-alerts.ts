import { createHash } from "node:crypto";
import { isAdminRole } from "@flycockpit/auth/roles";
import prisma from "@flycockpit/db";
import { isEmailConfigured, sendEmail } from "@flycockpit/mailer";
import { createRedisConnection } from "@flycockpit/queue";

type AlertArgs = {
  queue: string;
  jobId: string | number | undefined;
  message: string;
};

const ALERT_COOLDOWN_SECONDS = 60 * 60;
const alertConnection = createRedisConnection();

export async function sendOperationalFailureAlert(args: AlertArgs): Promise<void> {
  if (!isEmailConfigured()) return;
  if (!(await reserveAlertSlot(args))) return;

  const admins = await prisma.user.findMany({
    where: {
      emailVerified: true,
      operationalAlerts: true,
    },
    select: {
      email: true,
      role: true,
    },
  });
  const recipients = admins.filter((admin) => isAdminRole(admin.role)).map((admin) => admin.email);
  if (recipients.length === 0) return;

  const jobLabel = args.jobId === undefined ? "unknown" : String(args.jobId);
  const subject = `[${args.queue}] background job failed`;
  const html = `
    <p>A background job failed permanently.</p>
    <dl>
      <dt>Queue</dt><dd>${escapeHtml(args.queue)}</dd>
      <dt>Job</dt><dd>${escapeHtml(jobLabel)}</dd>
      <dt>Error</dt><dd>${escapeHtml(args.message)}</dd>
    </dl>
  `;

  await Promise.allSettled(
    recipients.map((to) =>
      sendEmail({
        to,
        subject,
        html,
      }),
    ),
  );
}

export function closeOperationalAlertConnection(): void {
  alertConnection.disconnect();
}

async function reserveAlertSlot(args: AlertArgs): Promise<boolean> {
  const fingerprint = createHash("sha256")
    .update(args.queue)
    .update("\0")
    .update(normalizeError(args.message))
    .digest("hex")
    .slice(0, 32);
  const key = `operational-alert:${args.queue}:${fingerprint}`;
  try {
    const result = await alertConnection.set(key, "1", "EX", ALERT_COOLDOWN_SECONDS, "NX");
    return result === "OK";
  } catch (err) {
    console.error(
      `[${args.queue}] Failed to reserve operational alert cooldown:`,
      err instanceof Error ? err.message : err,
    );
    return true;
  }
}

function normalizeError(message: string): string {
  return message
    .replaceAll(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, "<uuid>")
    .replaceAll(/\b\d+\b/g, "<number>")
    .trim()
    .slice(0, 500);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
