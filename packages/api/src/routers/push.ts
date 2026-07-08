import prisma from "@flycockpit/db";
import { env } from "@flycockpit/env/server";
import { z } from "zod";

import { adminOr404Procedure, protectedProcedure } from "../index";
import {
  disableNativePushToken,
  nativePushRegistrationInputSchema,
  nativePushTokenSchema,
  upsertNativePushToken,
} from "../lib/native-push";
import {
  pushEndpointSchema,
  pushSubscriptionInputSchema,
  upsertPushSubscription,
} from "../lib/push-subscription";

export const pushRouter = {
  subscribe: protectedProcedure
    .input(pushSubscriptionInputSchema)
    .handler(async ({ input, context }) => {
      await upsertPushSubscription(context.session.user.id, input);
      return { success: true };
    }),

  unsubscribe: protectedProcedure
    .input(z.object({ endpoint: pushEndpointSchema }))
    .handler(async ({ input, context }) => {
      await prisma.pushSubscription.deleteMany({
        where: {
          endpoint: input.endpoint,
          userId: context.session.user.id,
        },
      });
      return { success: true };
    }),

  registerNative: protectedProcedure
    .input(nativePushRegistrationInputSchema)
    .handler(async ({ input, context }) => {
      await upsertNativePushToken(context.session.user.id, input);
      return { success: true };
    }),

  unregisterNative: protectedProcedure
    .input(z.object({ token: nativePushTokenSchema }))
    .handler(async ({ input, context }) => {
      await disableNativePushToken(context.session.user.id, input.token);
      return { success: true };
    }),

  send: adminOr404Procedure
    .input(
      z.object({
        title: z.string(),
        body: z.string(),
        url: z.string().optional(),
        userId: z.string().optional(),
      }),
    )
    .handler(async ({ input }) => {
      const { sendPushNotification } = await import("../lib/web-push");

      const where = input.userId ? { userId: input.userId } : {};
      const subscriptions = await prisma.pushSubscription.findMany({ where });

      const payload = JSON.stringify({
        title: input.title,
        body: input.body,
        data: { url: input.url ?? "/" },
      });

      const results = await Promise.allSettled(
        subscriptions.map(async (sub) => {
          try {
            await sendPushNotification(
              {
                endpoint: sub.endpoint,
                keys: { p256dh: sub.p256dh, auth: sub.auth },
              },
              payload,
            );
          } catch (err: unknown) {
            const webPushErr = err as { statusCode?: number };
            if (webPushErr.statusCode === 410 || webPushErr.statusCode === 404) {
              await prisma.pushSubscription.delete({ where: { id: sub.id } });
            }
            throw err;
          }
        }),
      );

      const sent = results.filter((r) => r.status === "fulfilled").length;
      return { sent, total: subscriptions.length };
    }),

  vapidPublicKey: protectedProcedure.handler(() => {
    return { key: env.VAPID_PUBLIC_KEY ?? null };
  }),
};
