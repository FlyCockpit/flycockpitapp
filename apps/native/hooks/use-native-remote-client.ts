import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { orpc } from "@/utils/orpc";
import { NativeRemoteSessionClient } from "@/utils/remote-session-client";

export type NativeConnectionStatus = "idle" | "connecting" | "connected" | "offline" | "error";

export function useNativeRemoteClient(instanceId: string | undefined) {
  const tokenQuery = useQuery({
    ...orpc.instances.mintClientToken.queryOptions({ input: { instanceId: instanceId ?? "" } }),
    enabled: Boolean(instanceId),
  });
  const [client, setClient] = useState<NativeRemoteSessionClient | null>(null);
  const [status, setStatus] = useState<NativeConnectionStatus>("idle");
  const [statusDetail, setStatusDetail] = useState<string | undefined>();

  useEffect(() => {
    if (!instanceId || !tokenQuery.data) return;
    const nextClient = new NativeRemoteSessionClient({
      instanceId,
      token: tokenQuery.data.token,
      relayUrl: tokenQuery.data.relayUrl,
      onStatus: (nextStatus, detail) => {
        setStatus(nextStatus);
        setStatusDetail(detail);
      },
    });
    setClient(nextClient);
    nextClient.connect();
    return () => {
      nextClient.close();
      setClient(null);
      setStatus("idle");
      setStatusDetail(undefined);
    };
  }, [instanceId, tokenQuery.data]);

  return { client, status, statusDetail, tokenQuery };
}
