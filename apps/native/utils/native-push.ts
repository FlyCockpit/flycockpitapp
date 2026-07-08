import Constants from "expo-constants";
import * as Notifications from "expo-notifications";
import { Platform } from "react-native";

type NativePushPlatform = "ios" | "android" | "web";

function nativePushPlatform(): NativePushPlatform {
  return Platform.OS === "ios" || Platform.OS === "android" ? Platform.OS : "web";
}

import { orpc } from "@/utils/orpc";

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
