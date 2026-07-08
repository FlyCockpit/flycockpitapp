import prisma from "@flycockpit/db";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

export const nativePushTokenSchema = z
  .string()
  .trim()
  .min(16)
  .max(512)
  .refine(
    (token) =>
      token.startsWith("ExponentPushToken[") ||
      token.startsWith("ExpoPushToken[") ||
      token.startsWith("ExpoPushToken"),
    { message: "Native push token must be an Expo push token." },
  );

export const nativePushPlatformSchema = z.enum(["ios", "android", "web"]);

export const nativePushRegistrationInputSchema = z.object({
  token: nativePushTokenSchema,
  platform: nativePushPlatformSchema,
  deviceId: z.string().trim().min(1).max(160).optional(),
});

export type NativePushRegistrationInput = z.infer<typeof nativePushRegistrationInputSchema>;

export async function upsertNativePushToken(userId: string, input: NativePushRegistrationInput) {
  const existing = await prisma.nativePushToken.findUnique({ where: { token: input.token } });
  if (existing && existing.userId !== userId) {
    throw new ORPCError("CONFLICT", {
      message: "This device is already registered to another user.",
    });
  }
  if (existing) {
    await prisma.nativePushToken.update({
      where: { token: input.token },
      data: { platform: input.platform, deviceId: input.deviceId ?? null, enabled: true },
    });
    return;
  }
  await prisma.nativePushToken.create({
    data: {
      token: input.token,
      platform: input.platform,
      deviceId: input.deviceId ?? null,
      userId,
      enabled: true,
    },
  });
}

export async function disableNativePushToken(userId: string, token: string) {
  await prisma.nativePushToken.updateMany({
    where: { token, userId },
    data: { enabled: false },
  });
}

type NativePushPayload = { title: string; body: string; url: string };

export async function sendNativePushToUser(userId: string, payload: NativePushPayload) {
  const tokens = await prisma.nativePushToken.findMany({ where: { userId, enabled: true } });
  if (!tokens.length) return { sent: 0, total: 0 };

  const messages = tokens.map((token) => ({
    to: token.token,
    title: payload.title,
    body: payload.body,
    data: { url: payload.url },
  }));

  const response = await fetch("https://exp.host/--/api/v2/push/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(messages),
  });

  if (!response.ok) return { sent: 0, total: tokens.length };
  const body = (await response.json().catch(() => null)) as {
    data?: Array<{ status?: string; details?: { error?: string } }>;
  } | null;
  const receipts = Array.isArray(body?.data) ? body.data : [];
  let sent = 0;
  await Promise.all(
    tokens.map(async (token, index) => {
      const receipt = receipts[index];
      if (receipt?.status === "ok") sent += 1;
      if (receipt?.details?.error === "DeviceNotRegistered") {
        await prisma.nativePushToken.update({ where: { id: token.id }, data: { enabled: false } });
      }
    }),
  );
  return { sent, total: tokens.length };
}
