import {
  type UserNotificationRelayFrame,
  userNotificationRelayFrameSchema,
} from "@flycockpit/relay-protocol/envelopes";
import { toast } from "@flycockpit/ui/components/sileo";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef } from "react";
import { useDeferredSession } from "@/stores/session";
import { client, orpc } from "@/utils/orpc";

const HEARTBEAT_MS = 25_000;

function getClientId() {
  const key = "flycockpit:notification-client-id";
  const existing = window.localStorage.getItem(key);
  if (existing) return existing;
  const id = crypto.randomUUID();
  window.localStorage.setItem(key, id);
  return id;
}

function userRelayUrl(relayUrl: string, token: string) {
  const url = new URL(relayUrl, window.location.origin);
  if (!url.pathname.endsWith("/user")) {
    url.pathname = url.pathname.replace(/\/$/, "") + "/user";
  }
  url.searchParams.set("token", token);
  return url.toString();
}

export function useUserNotifications() {
  const session = useDeferredSession();
  const queryClient = useQueryClient();
  const signedIn = Boolean(session.data?.user);
  const clientId = useMemo(() => (typeof window === "undefined" ? "server" : getClientId()), []);
  const socketRef = useRef<WebSocket | null>(null);

  const tokenQuery = useQuery({
    ...orpc.notifications.mintUserRelayToken.queryOptions(),
    enabled: signedIn,
    refetchInterval: signedIn ? 4 * 60 * 1000 : false,
    retry: 1,
  });

  const sendHeartbeat = useCallback(
    (visible: boolean) => {
      if (!signedIn || typeof document === "undefined") return;
      const frame = JSON.stringify({
        v: 1,
        type: "presence",
        clientId,
        visible,
        ts: new Date().toISOString(),
      });
      const socket = socketRef.current;
      if (socket?.readyState === WebSocket.OPEN) {
        socket.send(frame);
        return;
      }
      void client.notifications.visibleHeartbeat({ clientId, visible });
    },
    [clientId, signedIn],
  );

  useEffect(() => {
    if (!signedIn) return;
    const onVisibility = () => sendHeartbeat(document.visibilityState === "visible");
    onVisibility();
    const interval = window.setInterval(onVisibility, HEARTBEAT_MS);
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", onVisibility);
    window.addEventListener("blur", onVisibility);
    window.addEventListener("pagehide", () => sendHeartbeat(false));
    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onVisibility);
      window.removeEventListener("blur", onVisibility);
      sendHeartbeat(false);
    };
  }, [sendHeartbeat, signedIn]);

  useEffect(() => {
    if (!signedIn || !tokenQuery.data) return;
    const ws = new WebSocket(userRelayUrl(tokenQuery.data.relayUrl, tokenQuery.data.token));
    socketRef.current = ws;
    ws.addEventListener("open", () => sendHeartbeat(document.visibilityState === "visible"));
    ws.addEventListener("message", (event) => {
      let frame: UserNotificationRelayFrame;
      try {
        frame = userNotificationRelayFrameSchema.parse(JSON.parse(event.data));
      } catch {
        return;
      }
      const note = frame.notification;
      toast.info(note.body ? `${note.title}: ${note.body}` : note.title, {
        action: {
          label: "Open",
          onClick: () => {
            window.location.assign(note.url);
          },
        },
      });
      void queryClient.invalidateQueries({ queryKey: orpc.notifications.key() });
    });
    ws.addEventListener("close", () => {
      if (socketRef.current === ws) socketRef.current = null;
    });
    return () => {
      if (socketRef.current === ws) socketRef.current = null;
      ws.close();
    };
  }, [queryClient, sendHeartbeat, signedIn, tokenQuery.data]);
}
