import { DEFAULT_LOCALE, isSupportedLocale } from "@flycockpit/config/locales";
import prisma from "@flycockpit/db";
import {
  type AttentionEventType,
  type AttentionNotificationPayload,
  attentionEventTypeSchema,
  attentionNotificationPayloadSchema,
  type RelayControlMessage,
} from "@flycockpit/relay-protocol";
import { ORPCError } from "@orpc/server";
import { z } from "zod";
import { sendNativePushToUser } from "./native-push";
import {
  getMissingRelayControlConfigKeys,
  getRelayControlConfig,
  relayControlUrl,
} from "./relay-config";
import { sendPushNotification } from "./web-push";

export { type AttentionEventType, attentionEventTypeSchema };

export const NOTIFICATION_TYPES = attentionEventTypeSchema.options;

export const PRESENCE_TTL_MS = 45_000;
export const COALESCE_WINDOW_MS = 60_000;

export const relayControlIngestSchema = z
  .object({
    instanceId: z.string().trim().min(1).max(128).optional(),
    relayId: z.string().trim().min(1).max(120).optional(),
    event: z.string().trim().min(1).max(128).optional(),
    userId: z.string().trim().min(1).max(128).optional(),
    payload: z.unknown(),
  })
  .strict();

export const userPresencePayloadSchema = z
  .object({
    clientId: z.string().trim().min(1).max(128),
    visible: z.boolean(),
    ts: z.string().datetime().optional(),
  })
  .strict();

export type NotificationDeliveryChannel = "toast" | "webpush" | "none";

export function decideNotificationDelivery(input: {
  activelyPresent: boolean;
  masterEnabled: boolean;
  typeEnabled: boolean;
  instanceMuted: boolean;
  duplicateInWindow: boolean;
}): {
  channel: NotificationDeliveryChannel;
  deliveredVia: "TOAST" | "PUSH" | "SUPPRESSED_DUPLICATE" | null;
} {
  if (!input.masterEnabled || !input.typeEnabled || input.instanceMuted) {
    return { channel: "none", deliveredVia: null };
  }
  if (input.duplicateInWindow) {
    return { channel: "none", deliveredVia: "SUPPRESSED_DUPLICATE" };
  }
  return input.activelyPresent
    ? { channel: "toast", deliveredVia: "TOAST" }
    : { channel: "webpush", deliveredVia: "PUSH" };
}

export function notificationDefaults(type: AttentionEventType) {
  switch (type) {
    case "QUESTION_RAISED":
      return { title: "Question needs your answer", body: "Open the session to respond." };
    case "APPROVAL_NEEDED":
      return { title: "Approval needed", body: "Open the session to review the request." };
    case "TURN_DONE":
      return { title: "Turn finished", body: "Open the session to see the result." };
    case "TURN_ERROR":
      return { title: "Turn hit an error", body: "Open the session to inspect it." };
    case "SCHEDULE_DONE":
      return { title: "Scheduled work finished", body: "Open the session to review it." };
  }
}

export function normalizeAttentionPayload(payload: unknown): AttentionNotificationPayload {
  const loose = payload as Record<string, unknown>;
  const normalized = {
    eventId: loose.eventId ?? loose.event_id,
    sessionId: loose.sessionId ?? loose.session_id,
    projectRoot: loose.projectRoot ?? loose.project_root,
    eventType: loose.eventType ?? loose.event_type,
    fixedStringTitle: loose.fixedStringTitle ?? loose.fixed_string_title,
    fixedStringBody: loose.fixedStringBody ?? loose.fixed_string_body,
    ts: loose.ts,
    targetPrincipal: loose.targetPrincipal ?? loose.target_principal,
  };
  return attentionNotificationPayloadSchema.parse(normalized);
}

export async function recordUserPresenceHeartbeat(input: {
  userId: string;
  clientId: string;
  visible: boolean;
  now?: Date;
}) {
  const now = input.now ?? new Date();
  const expiresAt = new Date(now.getTime() + PRESENCE_TTL_MS);
  if (!input.visible) {
    await prisma.userPresenceLease.deleteMany({
      where: { userId: input.userId, clientId: input.clientId },
    });
    return { present: false };
  }
  await prisma.userPresenceLease.upsert({
    where: { userId_clientId: { userId: input.userId, clientId: input.clientId } },
    update: { visible: true, expiresAt },
    create: { userId: input.userId, clientId: input.clientId, visible: true, expiresAt },
  });
  return { present: true, expiresAt };
}

export async function isActivelyPresent(userId: string, now = new Date()) {
  const count = await prisma.userPresenceLease.count({
    where: {
      userId,
      visible: true,
      expiresAt: { gt: now },
    },
  });
  return count > 0;
}

function userLocale(locale: string | null | undefined) {
  return locale && isSupportedLocale(locale) ? locale : DEFAULT_LOCALE;
}

function deepLink(locale: string, instanceId: string, event: AttentionNotificationPayload) {
  const projectId = encodeURIComponent(event.projectRoot || "default");
  const params = new URLSearchParams({ session: event.sessionId, interrupt: event.eventId });
  if (event.projectRoot) params.set("projectRoot", event.projectRoot);
  return `/${locale}/instances/${encodeURIComponent(instanceId)}/projects/${projectId}?${params.toString()}`;
}

export async function createInstanceShareInviteNotification(input: {
  userId: string;
  instanceId: string;
  instanceName: string;
  ownerName: string;
  grantIds: string[];
  locale?: string | null;
}) {
  const eventId =
    "instance-share-invite:" + input.instanceId + ":" + input.grantIds.sort().join(",");
  const locale = userLocale(input.locale);
  return prisma.notification.create({
    data: {
      eventId,
      userId: input.userId,
      instanceId: input.instanceId,
      sessionRef: null,
      projectRoot: null,
      type: "INSTANCE_SHARE_INVITE",
      title: input.ownerName + " shared " + input.instanceName + " with you",
      body: "Open your instances to review the invitation.",
      deepLinkUrl: `/${locale}/instances`,
      deliveredVia: "TOAST",
    },
  });
}

async function sendWebPushToUser(
  userId: string,
  payload: { title: string; body: string; url: string },
) {
  const subscriptions = await prisma.pushSubscription.findMany({ where: { userId } });
  const body = JSON.stringify({
    title: payload.title,
    body: payload.body,
    data: { url: payload.url },
  });
  const results = await Promise.allSettled(
    subscriptions.map(async (sub) => {
      try {
        await sendPushNotification(
          { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
          body,
        );
      } catch (err: unknown) {
        const statusCode = (err as { statusCode?: number }).statusCode;
        if (statusCode === 404 || statusCode === 410) {
          await prisma.pushSubscription.delete({ where: { id: sub.id } });
        }
        throw err;
      }
    }),
  );
  return {
    sent: results.filter((result) => result.status === "fulfilled").length,
    total: subscriptions.length,
  };
}

export async function publishToast(message: RelayControlMessage) {
  const config = getRelayControlConfigForPublish();
  if (!config) return false;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    const response = await fetch(config.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${config.controlSecret}`,
      },
      body: JSON.stringify(message),
      signal: controller.signal,
    }).finally(() => clearTimeout(timer));
    if (!response.ok) {
      console.warn(`[relay-control] publishToast failed status=${response.status}`);
    }
    return response.ok;
  } catch (err) {
    console.warn(
      `[relay-control] publishToast failed: ${err instanceof Error ? err.message : "unknown"}`,
    );
    return false;
  }
}

function getRelayControlConfigForPublish() {
  const url = relayControlUrl();
  if (!url) {
    const missing = getMissingRelayControlConfigKeys();
    console.warn(
      `[relay-control] publishToast skipped; missing ${missing.join(", ") || "relay control config"}.`,
    );
    return null;
  }
  const config = getRelayControlConfig();
  return config ? { url, controlSecret: config.controlSecret } : null;
}

async function resolveRecipients(
  instance: { id: string; userId: string },
  event: AttentionNotificationPayload,
) {
  const targetUserId = event.targetPrincipal?.userId;
  const recipients = new Set<string>();
  if (targetUserId) recipients.add(targetUserId);
  else recipients.add(instance.userId);

  if (targetUserId && targetUserId !== instance.userId) {
    const ownerSetting = await prisma.notificationInstanceSetting.findUnique({
      where: { userId_instanceId: { userId: instance.userId, instanceId: instance.id } },
      select: { ownerReceivesSharedSessions: true },
    });
    if (ownerSetting?.ownerReceivesSharedSessions) recipients.add(instance.userId);
  }
  return [...recipients];
}

export async function ingestAttentionNotification(input: {
  instanceId: string;
  payload: unknown;
  now?: Date;
  deps?: {
    isActivelyPresent?: (userId: string, now: Date) => Promise<boolean>;
    sendWebPushToUser?: typeof sendWebPushToUser;
    sendNativePushToUser?: typeof sendNativePushToUser;
    publishToast?: typeof publishToast;
  };
}) {
  const event = normalizeAttentionPayload(input.payload);
  const now = input.now ?? new Date();
  const instance = await prisma.cockpitInstance.findUnique({
    where: { id: input.instanceId },
    select: { id: true, userId: true, displayName: true },
  });
  if (!instance) throw new ORPCError("NOT_FOUND", { message: "Instance not found." });

  const recipientIds = await resolveRecipients(instance, event);
  const users = await prisma.user.findMany({
    where: { id: { in: recipientIds } },
    select: {
      id: true,
      locale: true,
      notificationAlerts: true,
      NotificationPreferences: { select: { type: true, enabled: true } },
      NotificationInstanceSettings: {
        where: { instanceId: instance.id },
        select: { muted: true, ownerReceivesSharedSessions: true },
      },
    },
  });

  const defaults = notificationDefaults(event.eventType);
  const title = event.fixedStringTitle || defaults.title;
  const body = event.fixedStringBody || defaults.body;
  const outcomes = [];

  for (const user of users) {
    const alreadyRecorded = await prisma.notification.findUnique({
      where: { eventId_userId: { eventId: event.eventId, userId: user.id } },
    });
    if (alreadyRecorded) {
      outcomes.push({ userId: user.id, channel: "none", reason: "idempotent" });
      continue;
    }

    const instanceSetting = user.NotificationInstanceSettings[0];
    const typePref = user.NotificationPreferences.find(
      (pref) => String(pref.type) === event.eventType,
    );
    const recent = await prisma.notification.findFirst({
      where: {
        userId: user.id,
        instanceId: instance.id,
        sessionRef: event.sessionId,
        type: event.eventType,
        deliveredVia: { in: ["TOAST", "PUSH"] },
        createdAt: { gte: new Date(now.getTime() - COALESCE_WINDOW_MS) },
      },
      orderBy: { createdAt: "desc" },
    });
    const activelyPresent = await (input.deps?.isActivelyPresent ?? isActivelyPresent)(
      user.id,
      now,
    );
    const decision = decideNotificationDelivery({
      activelyPresent,
      masterEnabled: user.notificationAlerts !== false,
      typeEnabled: typePref?.enabled ?? true,
      instanceMuted: instanceSetting?.muted === true,
      duplicateInWindow: Boolean(recent),
    });

    if (!decision.deliveredVia) {
      outcomes.push({ userId: user.id, channel: decision.channel, reason: "preference" });
      continue;
    }

    const url = deepLink(userLocale(user.locale), instance.id, event);
    const notification = await prisma.notification.create({
      data: {
        eventId: event.eventId,
        userId: user.id,
        instanceId: instance.id,
        sessionRef: event.sessionId,
        projectRoot: event.projectRoot ?? null,
        type: event.eventType,
        title,
        body,
        deepLinkUrl: url,
        deliveredVia: decision.deliveredVia,
      },
    });

    if (decision.channel === "toast") {
      await (input.deps?.publishToast ?? publishToast)({
        type: "notify_user",
        userId: user.id,
        notification: {
          id: notification.id,
          type: event.eventType,
          title,
          body,
          url,
          instanceId: instance.id,
          sessionRef: event.sessionId,
          createdAt: notification.createdAt.toISOString(),
        },
      });
    } else if (decision.channel === "webpush") {
      await Promise.all([
        (input.deps?.sendWebPushToUser ?? sendWebPushToUser)(user.id, { title, body, url }),
        (input.deps?.sendNativePushToUser ?? sendNativePushToUser)(user.id, { title, body, url }),
      ]);
    }

    outcomes.push({
      userId: user.id,
      channel: decision.channel,
      deliveredVia: decision.deliveredVia,
    });
  }

  return { eventId: event.eventId, recipients: outcomes };
}

export function parseRelayAttentionIngest(body: unknown) {
  const parsed = relayControlIngestSchema.parse(body);
  if (parsed.event === "user_presence") {
    if (!parsed.userId) throw new ORPCError("BAD_REQUEST", { message: "Missing user id." });
    return {
      kind: "presence" as const,
      relayId: parsed.relayId ?? null,
      userId: parsed.userId,
      payload: userPresencePayloadSchema.parse(parsed.payload),
    };
  }
  if (!parsed.instanceId) throw new ORPCError("BAD_REQUEST", { message: "Missing instance id." });
  return {
    kind: "attention" as const,
    relayId: parsed.relayId ?? null,
    instanceId: parsed.instanceId,
    payload: parsed.payload,
  };
}
