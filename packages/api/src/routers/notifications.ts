import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/server";
import { ORPCError } from "@orpc/server";
import { z } from "zod";
import { protectedProcedure } from "../index";
import {
  attentionEventTypeSchema,
  NOTIFICATION_TYPES,
  recordUserPresenceHeartbeat,
} from "../lib/notifications";
import { createRelayToken } from "../lib/relay-tokens";
import { requireConfiguredRelayForMint } from "../lib/relay-url";

function serializeNotification(notification: {
  id: string;
  createdAt: Date;
  instanceId: string;
  sessionRef: string | null;
  projectRoot: string | null;
  type: unknown;
  title: string;
  body: string | null;
  deepLinkUrl: string;
  deliveredVia: unknown;
  readAt: Date | null;
  resolvedAt: Date | null;
  CockpitInstance?: { displayName: string } | null;
}) {
  return {
    id: notification.id,
    createdAt: notification.createdAt,
    instanceId: notification.instanceId,
    instanceName: notification.CockpitInstance?.displayName ?? null,
    sessionRef: notification.sessionRef,
    projectRoot: notification.projectRoot,
    type: String(notification.type),
    title: notification.title,
    body: notification.body,
    deepLinkUrl: notification.deepLinkUrl,
    deliveredVia: String(notification.deliveredVia),
    readAt: notification.readAt,
    resolvedAt: notification.resolvedAt,
  };
}

const instanceSettingInput = z.object({
  instanceId: z.string().min(1),
  muted: z.boolean().optional(),
  ownerReceivesSharedSessions: z.boolean().optional(),
});

async function resolveUserRelayTarget(userId: string) {
  if (env.DEPLOYMENT_PROFILE === "oss") {
    const target = requireConfiguredRelayForMint();
    return { relayId: target.relayId, relayUrl: target.relayUrl };
  }

  const { selectUserRelay } = await import("../enterprise/relay-fleet");
  const target = await selectUserRelay(userId);
  return { relayId: target.relayId, relayUrl: target.wsUrl };
}

export const notificationsRouter = {
  listMine: protectedProcedure
    .input(z.object({ limit: z.number().int().min(1).max(100).default(30) }))
    .handler(async ({ input, context }) => {
      const notifications = await prisma.notification.findMany({
        where: { userId: context.session.user.id },
        orderBy: { createdAt: "desc" },
        take: input.limit,
        include: { CockpitInstance: { select: { displayName: true } } },
      });
      return { notifications: notifications.map(serializeNotification) };
    }),

  unreadCount: protectedProcedure.handler(async ({ context }) => {
    const count = await prisma.notification.count({
      where: { userId: context.session.user.id, readAt: null },
    });
    return { count };
  }),

  markRead: protectedProcedure
    .input(z.object({ notificationId: z.string().min(1) }))
    .handler(async ({ input, context }) => {
      await prisma.notification.updateMany({
        where: { id: input.notificationId, userId: context.session.user.id },
        data: { readAt: new Date() },
      });
      return { success: true };
    }),

  resolveForSession: protectedProcedure
    .input(
      z.object({
        instanceId: z.string().min(1),
        sessionRef: z.string().min(1),
      }),
    )
    .handler(async ({ input, context }) => {
      await prisma.notification.updateMany({
        where: {
          userId: context.session.user.id,
          instanceId: input.instanceId,
          sessionRef: input.sessionRef,
          resolvedAt: null,
        },
        data: { resolvedAt: new Date() },
      });
      return { success: true };
    }),

  visibleHeartbeat: protectedProcedure
    .input(z.object({ clientId: z.string().min(1).max(128), visible: z.boolean() }))
    .handler(async ({ input, context }) => {
      return recordUserPresenceHeartbeat({
        userId: context.session.user.id,
        clientId: input.clientId,
        visible: input.visible,
      });
    }),

  mintUserRelayToken: protectedProcedure.handler(async ({ context }) => {
    const relayTarget = await resolveUserRelayTarget(context.session.user.id);
    const relay = await createRelayToken(
      {
        tokenType: "user",
        userId: context.session.user.id,
        grants: [],
      },
      relayTarget.relayId,
    );
    return { token: relay.token, expiresAt: relay.expiresAt, relayUrl: relayTarget.relayUrl };
  }),

  myPreferences: protectedProcedure.handler(async ({ context }) => {
    const user = await prisma.user.findUnique({
      where: { id: context.session.user.id },
      select: { notificationAlerts: true },
    });
    const [typePrefs, instanceSettings] = await Promise.all([
      prisma.notificationPreference.findMany({
        where: { userId: context.session.user.id },
        select: { type: true, enabled: true },
      }),
      prisma.notificationInstanceSetting.findMany({
        where: { userId: context.session.user.id },
        select: { instanceId: true, muted: true, ownerReceivesSharedSessions: true },
      }),
    ]);
    const typeMap = new Map(typePrefs.map((pref) => [String(pref.type), pref.enabled]));
    return {
      notificationAlerts: user?.notificationAlerts ?? true,
      types: NOTIFICATION_TYPES.map((type) => ({ type, enabled: typeMap.get(type) ?? true })),
      instances: instanceSettings,
    };
  }),

  updateMyPreferences: protectedProcedure
    .input(
      z.object({
        notificationAlerts: z.boolean().optional(),
        types: z
          .array(z.object({ type: attentionEventTypeSchema, enabled: z.boolean() }))
          .optional(),
        instances: z.array(instanceSettingInput).optional(),
      }),
    )
    .handler(async ({ input, context }) => {
      const userId = context.session.user.id;
      if (input.notificationAlerts !== undefined) {
        await prisma.user.update({
          where: { id: userId },
          data: { notificationAlerts: input.notificationAlerts },
        });
      }
      for (const pref of input.types ?? []) {
        await prisma.notificationPreference.upsert({
          where: { userId_type: { userId, type: pref.type } },
          update: { enabled: pref.enabled },
          create: { userId, type: pref.type, enabled: pref.enabled },
        });
      }
      for (const setting of input.instances ?? []) {
        const instance = await prisma.cockpitInstance.findUnique({
          where: { id: setting.instanceId },
          select: { userId: true },
        });
        if (!instance || instance.userId !== userId) {
          throw new ORPCError("NOT_FOUND", { message: "Instance not found." });
        }
        await prisma.notificationInstanceSetting.upsert({
          where: { userId_instanceId: { userId, instanceId: setting.instanceId } },
          update: {
            ...(setting.muted !== undefined ? { muted: setting.muted } : {}),
            ...(setting.ownerReceivesSharedSessions !== undefined
              ? { ownerReceivesSharedSessions: setting.ownerReceivesSharedSessions }
              : {}),
          },
          create: {
            userId,
            instanceId: setting.instanceId,
            muted: setting.muted ?? false,
            ownerReceivesSharedSessions: setting.ownerReceivesSharedSessions ?? false,
          },
        });
      }
      return { success: true };
    }),
};
