import {
  type RemoteSessionClient,
  type RemoteSessionStatus,
} from "@flycockpit/cockpit-protocol/client";
import { useQuery } from "@tanstack/react-query";
import * as Network from "expo-network";
import { useEffect, useState } from "react";
import { AppState } from "react-native";
import { orpc } from "@/utils/orpc";
import { createNativeRemoteSessionClient } from "@/utils/remote-session-client";

export type NativeConnectionStatus = RemoteSessionStatus;

export function useNativeRemoteClient(
  instanceId: string | undefined,
  onEvent?: (event: unknown) => void,
) {
  const tokenQuery = useQuery({
    ...orpc.instances.mintClientToken.queryOptions({ input: { instanceId: instanceId ?? "" } }),
    enabled: Boolean(instanceId),
  });
  const [client, setClient] = useState<RemoteSessionClient | null>(null);
  const [status, setStatus] = useState<NativeConnectionStatus>("idle");
  const [statusDetail, setStatusDetail] = useState<string | undefined>();

  useEffect(() => {
    if (!instanceId || !tokenQuery.data) return;
    const nextClient = createNativeRemoteSessionClient({
      instanceId,
      token: tokenQuery.data.token,
      relayUrl: tokenQuery.data.relayUrl,
      onStatus: (nextStatus, detail) => {
        setStatus(nextStatus);
        setStatusDetail(detail);
      },
      onEvent,
    });
    setClient(nextClient);
    Network.getNetworkStateAsync().then((network) => {
      if (network.isInternetReachable === false) {
        setStatus("offline");
        setStatusDetail("Device is offline.");
        return;
      }
      nextClient.connect();
    });
    return () => {
      nextClient.close();
      setClient(null);
      setStatus("idle");
      setStatusDetail(undefined);
    };
  }, [instanceId, tokenQuery.data, onEvent]);

  useEffect(() => {
    if (!client) return;
    const sub = AppState.addEventListener("change", (state) => {
      if (state !== "active") return;
      Network.getNetworkStateAsync().then((network) => {
        if (network.isInternetReachable === false) {
          setStatus("offline");
          setStatusDetail("Device is offline.");
          return;
        }
        if (status === "offline" || status === "error") client.connect();
      });
    });
    return () => sub.remove();
  }, [client, status]);

  return { client, status, statusDetail, tokenQuery };
}
