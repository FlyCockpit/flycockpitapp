import { useMutation, useQuery } from "@tanstack/react-query";
import { useCallback, useMemo } from "react";

import { client, orpc } from "@/utils/orpc";

function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

export function usePushNotifications() {
  const vapidKeyQuery = useQuery(orpc.push.vapidPublicKey.queryOptions());

  const isSupported =
    typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window;

  const permission =
    typeof window !== "undefined" && "Notification" in window ? Notification.permission : "default";

  const subscribeMutation = useMutation({
    mutationFn: async () => {
      const vapidKey = vapidKeyQuery.data?.key;
      if (!vapidKey) throw new Error("VAPID key not available");

      const granted = await Notification.requestPermission();
      if (granted !== "granted") throw new Error("Permission denied");

      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(vapidKey) as BufferSource,
      });

      const json = subscription.toJSON();
      await client.push.subscribe({
        endpoint: json.endpoint!,
        keys: {
          p256dh: json.keys!.p256dh!,
          auth: json.keys!.auth!,
        },
      });

      return subscription;
    },
  });

  const unsubscribeMutation = useMutation({
    mutationFn: async () => {
      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.getSubscription();
      if (!subscription) return;

      await client.push.unsubscribe({ endpoint: subscription.endpoint });
      await subscription.unsubscribe();
    },
  });

  const subscribe = useCallback(() => subscribeMutation.mutate(), [subscribeMutation]);

  const unsubscribe = useCallback(() => unsubscribeMutation.mutate(), [unsubscribeMutation]);

  return useMemo(
    () => ({
      isSupported,
      permission,
      subscribe,
      unsubscribe,
      isSubscribing: subscribeMutation.isPending,
      isUnsubscribing: unsubscribeMutation.isPending,
    }),
    [
      isSupported,
      permission,
      subscribe,
      unsubscribe,
      subscribeMutation.isPending,
      unsubscribeMutation.isPending,
    ],
  );
}
