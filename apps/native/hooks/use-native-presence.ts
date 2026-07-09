import * as SecureStore from "expo-secure-store";
import { useEffect, useMemo, useState } from "react";
import { AppState, Platform } from "react-native";
import { orpc } from "@/utils/orpc";

const HEARTBEAT_MS = 25_000;
const CLIENT_ID_KEY = "flycockpit:native-notification-client-id";

function randomId() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return "native-" + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

async function getClientId() {
  if (Platform.OS === "web") return "native-web";
  const existing = await SecureStore.getItemAsync(CLIENT_ID_KEY);
  if (existing) return existing;
  const id = randomId();
  await SecureStore.setItemAsync(CLIENT_ID_KEY, id);
  return id;
}

export function useNativePresenceHeartbeat(enabled: boolean) {
  const [clientId, setClientId] = useState<string | null>(null);
  const visible = useMemo(() => AppState.currentState === "active", []);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    getClientId().then((id) => {
      if (!cancelled) setClientId(id);
    });
    return () => {
      cancelled = true;
    };
  }, [enabled]);

  useEffect(() => {
    if (!enabled || !clientId) return;
    let currentVisible = visible;
    const sendHeartbeat = (nextVisible: boolean) => {
      currentVisible = nextVisible;
      void orpc.notifications.visibleHeartbeat.call({ clientId, visible: nextVisible });
    };
    sendHeartbeat(currentVisible);
    const interval = setInterval(() => sendHeartbeat(currentVisible), HEARTBEAT_MS);
    const sub = AppState.addEventListener("change", (state) => {
      sendHeartbeat(state === "active");
    });
    return () => {
      clearInterval(interval);
      sub.remove();
      void orpc.notifications.visibleHeartbeat.call({ clientId, visible: false });
    };
  }, [clientId, enabled, visible]);
}
