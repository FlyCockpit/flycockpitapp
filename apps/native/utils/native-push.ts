import Constants from "expo-constants";
import * as Notifications from "expo-notifications";
import { useEffect, useRef } from "react";
import { Platform } from "react-native";
import { type NativeRouteTarget, routeFromCockpitUrl } from "./deep-links";

type NativeRouter = { push: (target: NativeRouteTarget) => void };

type NativePushPlatform = "ios" | "android" | "web";

function nativePushPlatform(): NativePushPlatform {
  return Platform.OS === "ios" || Platform.OS === "android" ? Platform.OS : "web";
}

import { orpc } from "@/utils/orpc";

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldShowBanner: true,
    shouldShowList: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
  }),
});

function notificationUrl(response: Notifications.NotificationResponse) {
  const value = response.notification.request.content.data?.url;
  return typeof value === "string" ? value : null;
}

function pushRoute(router: NativeRouter, target: NativeRouteTarget) {
  if (target.pathname === "/instances/[instanceId]") {
    router.push({ pathname: target.pathname, params: target.params });
    return;
  }
  router.push({ pathname: target.pathname, params: target.params });
}

export function useNativeNotificationRouting(router: NativeRouter, signedIn: boolean) {
  const pending = useRef<NativeRouteTarget | null>(null);

  useEffect(() => {
    let mounted = true;
    const handleResponse = (response: Notifications.NotificationResponse) => {
      const url = notificationUrl(response);
      if (!url) return;
      const target = routeFromCockpitUrl(url);
      if (!target) return;
      if (!signedIn) {
        pending.current = target;
        return;
      }
      pushRoute(router, target);
    };
    Notifications.getLastNotificationResponseAsync().then((response) => {
      if (mounted && response) handleResponse(response);
    });
    const sub = Notifications.addNotificationResponseReceivedListener(handleResponse);
    return () => {
      mounted = false;
      sub.remove();
    };
  }, [router, signedIn]);

  useEffect(() => {
    if (!signedIn || !pending.current) return;
    const target = pending.current;
    pending.current = null;
    pushRoute(router, target);
  }, [router, signedIn]);
}

export async function registerNativePushToken() {
  if (Platform.OS === "web") return { registered: false, reason: "web" as const };

  const existing = await Notifications.getPermissionsAsync();
  const finalStatus =
    existing.status === "granted"
      ? existing.status
      : (await Notifications.requestPermissionsAsync()).status;
  if (finalStatus !== "granted") return { registered: false, reason: "permission" as const };

  const projectId =
    Constants.expoConfig?.extra?.eas?.projectId ?? Constants.easConfig?.projectId ?? undefined;
  const token = (await Notifications.getExpoPushTokenAsync(projectId ? { projectId } : undefined))
    .data;
  await orpc.push.registerNative.call({
    token,
    platform: nativePushPlatform(),
    deviceId: Constants.sessionId ?? undefined,
  });
  return { registered: true, token };
}
