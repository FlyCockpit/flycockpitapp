import {
  RemoteSessionClient,
  type RemoteSessionClientOptions,
  type RemoteSessionStatus,
} from "@flycockpit/cockpit-protocol/client";
import { useQuery } from "@tanstack/react-query";
import * as Network from "expo-network";
import { useEffect, useRef, useState } from "react";
import { AppState } from "react-native";
import { orpc } from "@/utils/orpc";

export type NativeConnectionStatus = RemoteSessionStatus;

export function nextNativeConnectionEpoch(
  previous: NativeConnectionStatus,
  next: NativeConnectionStatus,
  currentEpoch: number,
) {
  return next === "connected" && previous !== "connected" ? currentEpoch + 1 : currentEpoch;
}

export function nativeConnectionEpochUpdater(
  previous: NativeConnectionStatus,
  next: NativeConnectionStatus,
) {
  return (currentEpoch: number) => nextNativeConnectionEpoch(previous, next, currentEpoch);
}

export type NativeRemoteClientInput = {
  instanceId: string;
  token: string;
  relayUrl: string;
  onStatus: RemoteSessionClientOptions["onStatus"];
  onEvent?: RemoteSessionClientOptions["onEvent"];
};

export type NativeRemoteClientLifecycle = {
  dispose: () => void;
  runIfCurrent: (action: () => void) => boolean;
};

export function createNativeRemoteClientLifecycle(): NativeRemoteClientLifecycle {
  let disposed = false;
  return {
    dispose: () => {
      disposed = true;
    },
    runIfCurrent: (action) => {
      if (disposed) return false;
      action();
      return true;
    },
  };
}

export function continueAfterNativeNetworkCheck(
  lifecycle: NativeRemoteClientLifecycle,
  networkState: Promise<{ isInternetReachable?: boolean | null }>,
  onOnline: () => void,
  onOffline: () => void,
) {
  return networkState.then(
    (network) => {
      lifecycle.runIfCurrent(() => {
        if (network.isInternetReachable === false) {
          onOffline();
        } else {
          onOnline();
        }
      });
    },
    () => {
      // Failure to inspect reachability is not proof of being offline. Let the
      // WebSocket provide the authoritative connection result instead of
      // stranding the client in `idle` or leaking an unhandled rejection.
      lifecycle.runIfCurrent(onOnline);
    },
  );
}

export function nativeRemoteClientOptions(
  input: NativeRemoteClientInput,
): RemoteSessionClientOptions {
  return {
    instanceId: input.instanceId,
    token: input.token,
    relayUrl: input.relayUrl,
    onStatus: input.onStatus,
    onEvent: input.onEvent,
  };
}

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
  const [connectionEpoch, setConnectionEpoch] = useState(0);
  const previousStatusRef = useRef<NativeConnectionStatus>("idle");

  useEffect(() => {
    if (!instanceId || !tokenQuery.data) return;
    const lifecycle = createNativeRemoteClientLifecycle();
    const nextClient = new RemoteSessionClient(
      nativeRemoteClientOptions({
        instanceId,
        token: tokenQuery.data.token,
        relayUrl: tokenQuery.data.relayUrl,
        onStatus: (nextStatus, detail) => {
          lifecycle.runIfCurrent(() => {
            const previousStatus = previousStatusRef.current;
            previousStatusRef.current = nextStatus;
            setConnectionEpoch(nativeConnectionEpochUpdater(previousStatus, nextStatus));
            setStatus(nextStatus);
            setStatusDetail(detail);
          });
        },
        onEvent: onEvent
          ? (event) => {
              lifecycle.runIfCurrent(() => onEvent(event));
            }
          : undefined,
      }),
    );
    setClient(nextClient);
    void continueAfterNativeNetworkCheck(
      lifecycle,
      Network.getNetworkStateAsync(),
      () => nextClient.connect(),
      () => {
        setStatus("offline");
        setStatusDetail("Device is offline.");
      },
    );
    return () => {
      lifecycle.dispose();
      nextClient.close();
      previousStatusRef.current = "idle";
      setClient(null);
      setStatus("idle");
      setStatusDetail(undefined);
    };
  }, [instanceId, tokenQuery.data, onEvent]);

  useEffect(() => {
    if (!client) return;
    const lifecycle = createNativeRemoteClientLifecycle();
    const sub = AppState.addEventListener("change", (state) => {
      if (state !== "active") return;
      void continueAfterNativeNetworkCheck(
        lifecycle,
        Network.getNetworkStateAsync(),
        () => {
          if (status === "offline" || status === "error") client.connect();
        },
        () => {
          setStatus("offline");
          setStatusDetail("Device is offline.");
        },
      );
    });
    return () => {
      lifecycle.dispose();
      sub.remove();
    };
  }, [client, status]);

  return { client, status, statusDetail, connectionEpoch, tokenQuery };
}
