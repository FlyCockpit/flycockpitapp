import { useEffect } from "react";
import { useRemoteSessionsStore } from "@/stores/remote-sessions";

export function useRemoteProjectSessions(input: {
  instanceId: string;
  projectId: string;
  projectRoot: string | null;
  sessionId: string | null;
  connected: boolean;
}) {
  const loadSessions = useRemoteSessionsStore((state) => state.loadSessions);
  const loadStatsRollup = useRemoteSessionsStore((state) => state.loadStatsRollup);
  const attach = useRemoteSessionsStore((state) => state.attach);

  useEffect(() => {
    if (!input.connected || !input.projectRoot) return;
    void loadSessions(input.instanceId, input.projectRoot);
    void loadStatsRollup(input.instanceId, input.projectId);
  }, [
    input.connected,
    input.instanceId,
    input.projectId,
    input.projectRoot,
    loadSessions,
    loadStatsRollup,
  ]);

  useEffect(() => {
    if (!input.connected || !input.sessionId) return;
    void attach(input.instanceId, input.sessionId);
  }, [attach, input.connected, input.instanceId, input.sessionId]);
}
