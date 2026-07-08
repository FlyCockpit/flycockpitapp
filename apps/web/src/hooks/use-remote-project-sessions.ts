import { useEffect } from "react";
import { useRemoteSessionsStore } from "@/stores/remote-sessions";

export function useRemoteProjectSessions(input: {
  instanceId: string;
  projectRoot: string | null;
  sessionId: string | null;
  connected: boolean;
}) {
  const loadSessions = useRemoteSessionsStore((state) => state.loadSessions);
  const attach = useRemoteSessionsStore((state) => state.attach);

  useEffect(() => {
    if (!input.connected || !input.projectRoot) return;
    void loadSessions(input.instanceId, input.projectRoot);
  }, [input.connected, input.instanceId, input.projectRoot, loadSessions]);

  useEffect(() => {
    if (!input.connected || !input.sessionId) return;
    void attach(input.instanceId, input.sessionId);
  }, [attach, input.connected, input.instanceId, input.sessionId]);
}
