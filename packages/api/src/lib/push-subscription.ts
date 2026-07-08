import prisma from "@flycockpit/db";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

/**
 * Shared Zod schema for a push-subscription payload.
 *
 * Used by both the `push.subscribe` oRPC procedure and the dedicated
 * `POST /sw/push-renew` HTTP endpoint that the service worker calls when the
 * browser rotates VAPID keys (`pushsubscriptionchange`). Keeping the shape in
 * one place prevents the two call sites from drifting.
 */
const allowedPushServiceHostSuffixes = [
  "fcm.googleapis.com",
  "android.googleapis.com",
  "updates.push.services.mozilla.com",
  "web.push.apple.com",
  "push.apple.com",
  "notify.windows.com",
];

export const pushEndpointSchema = z
  .string()
  .url()
  .refine((value) => isAllowedPushEndpoint(value), {
    message: "Push endpoint must be an HTTPS browser push service URL.",
  });

export const pushSubscriptionInputSchema = z.object({
  endpoint: pushEndpointSchema,
  keys: z.object({
    p256dh: z.string(),
    auth: z.string(),
  }),
});

export type PushSubscriptionInput = z.infer<typeof pushSubscriptionInputSchema>;

/**
 * Upsert a web-push subscription for the given user.
 *
 * Endpoint is the natural primary key. The same user can refresh keys for an
 * existing endpoint, but another user cannot claim it by submitting the same
 * endpoint.
 */
export async function upsertPushSubscription(userId: string, input: PushSubscriptionInput) {
  const existing = await prisma.pushSubscription.findUnique({
    where: { endpoint: input.endpoint },
    select: { userId: true },
  });

  if (existing && existing.userId !== userId) {
    throw new ORPCError("CONFLICT", {
      message: "Push subscription endpoint is already registered to another user.",
    });
  }

  if (existing) {
    await prisma.pushSubscription.update({
      where: { endpoint: input.endpoint },
      data: {
        p256dh: input.keys.p256dh,
        auth: input.keys.auth,
      },
    });
    return;
  }

  await prisma.pushSubscription.create({
    data: {
      endpoint: input.endpoint,
      p256dh: input.keys.p256dh,
      auth: input.keys.auth,
      userId,
    },
  });
}

function isAllowedPushEndpoint(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }

  if (url.protocol !== "https:") return false;
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (isBlockedEndpointHost(hostname)) return false;
  return allowedPushServiceHostSuffixes.some(
    (suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`),
  );
}

function isBlockedEndpointHost(hostname: string): boolean {
  if (hostname === "localhost" || hostname.endsWith(".localhost")) return true;
  if (hostname.startsWith("[") || hostname.endsWith("]")) return true;
  return isPrivateIpv4(hostname);
}

function isPrivateIpv4(hostname: string): boolean {
  const parts = hostname.split(".").map((part) => Number.parseInt(part, 10));
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return false;
  }
  const a = parts[0];
  const b = parts[1];
  if (a === undefined || b === undefined) return true;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}
