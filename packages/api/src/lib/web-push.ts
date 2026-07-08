import { env } from "@flycockpit/env/server";

interface PushSubscription {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
}

let initialized = false;

async function getWebPush() {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const webpush = (await import("web-push")) as {
    setVapidDetails(subject: string, publicKey: string, privateKey: string): void;
    sendNotification(
      subscription: PushSubscription,
      payload: string | null,
      options?: { TTL?: number; urgency?: string; topic?: string },
    ): Promise<{ statusCode: number; body: string }>;
  };

  if (!initialized && env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY) {
    webpush.setVapidDetails(env.VAPID_SUBJECT, env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
    initialized = true;
  }

  return webpush;
}

export async function sendPushNotification(subscription: PushSubscription, payload: string) {
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) {
    throw new Error("VAPID keys not configured");
  }

  const webpush = await getWebPush();
  return webpush.sendNotification(subscription, payload, {
    TTL: 60 * 60,
    urgency: "high",
  });
}
