import { useEffect } from "react";
import { useRemoteSessionsStore } from "@/stores/remote-sessions";

type TokenInfo = { token: string; relayUrl: string } | null | undefined;

export function useRemoteInstanceConnection(instanceId: string, tokenInfo: TokenInfo) {
  const connect = useRemoteSessionsStore((state) => state.connect);
  const disconnect = useRemoteSessionsStore((state) => state.disconnect);
  const loadProjects = useRemoteSessionsStore((state) => state.loadProjects);

  useEffect(() => {
    if (!tokenInfo) return;
    connect(instanceId, tokenInfo);
    const timer = window.setTimeout(() => void loadProjects(instanceId), 250);
    return () => {
      window.clearTimeout(timer);
      disconnect(instanceId);
    };
  }, [connect, disconnect, instanceId, loadProjects, tokenInfo]);
}
