import type { RemoteSessionClientOptions } from "@flycockpit/cockpit-protocol/client";
import { describe, expect, it, vi } from "vitest";
import {
  continueAfterNativeNetworkCheck,
  createNativeRemoteClientLifecycle,
  type NativeConnectionStatus,
  nativeConnectionEpochUpdater,
  nativeRemoteClientOptions,
  nextNativeConnectionEpoch,
} from "./use-native-remote-client";

vi.mock("expo-network", () => ({
  getNetworkStateAsync: vi.fn(),
}));

vi.mock("react-native", () => ({
  AppState: {
    addEventListener: vi.fn(() => ({ remove: vi.fn() })),
  },
}));

vi.mock("@/utils/orpc", () => ({
  orpc: {
    instances: {
      mintClientToken: {
        queryOptions: vi.fn(() => ({})),
      },
    },
  },
}));

describe("nativeRemoteClientOptions", () => {
  it("constructs shared client options without native id prefixes", () => {
    const onStatus = vi.fn();
    const onEvent = vi.fn();

    const options = nativeRemoteClientOptions({
      instanceId: "inst_123",
      token: "token_123",
      relayUrl: "wss://relay.example/session",
      onStatus,
      onEvent,
    }) satisfies RemoteSessionClientOptions;

    expect(options).toEqual({
      instanceId: "inst_123",
      token: "token_123",
      relayUrl: "wss://relay.example/session",
      onStatus,
      onEvent,
    });
    expect(options).not.toHaveProperty(["id", "Prefix"].join(""));
  });

  it("advances once for every distinct connected epoch", () => {
    let epoch = nextNativeConnectionEpoch("idle", "connected", 0);
    expect(epoch).toBe(1);
    epoch = nextNativeConnectionEpoch("connected", "connected", epoch);
    expect(epoch).toBe(1);
    epoch = nextNativeConnectionEpoch("connected", "offline", epoch);
    expect(epoch).toBe(1);
    epoch = nextNativeConnectionEpoch("offline", "connecting", epoch);
    expect(epoch).toBe(1);
    epoch = nextNativeConnectionEpoch("connecting", "connected", epoch);
    expect(epoch).toBe(2);
  });

  it("captures prior status before deferred consecutive epoch updaters execute", () => {
    let previous: NativeConnectionStatus = "offline";
    const deferredUpdaters: Array<(current: number) => number> = [];
    for (const next of ["connecting", "connected"] as const) {
      const capturedPrevious = previous;
      previous = next;
      deferredUpdaters.push(nativeConnectionEpochUpdater(capturedPrevious, next));
    }

    expect(deferredUpdaters.reduce((epoch, update) => update(epoch), 6)).toBe(7);
  });

  it("does not connect an obsolete initial client after its network check resolves", async () => {
    let resolveNetwork!: (network: { isInternetReachable: boolean }) => void;
    const network = new Promise<{ isInternetReachable: boolean }>((resolve) => {
      resolveNetwork = resolve;
    });
    const lifecycle = createNativeRemoteClientLifecycle();
    const connect = vi.fn();
    const markOffline = vi.fn();
    const completion = continueAfterNativeNetworkCheck(lifecycle, network, connect, markOffline);

    lifecycle.dispose();
    resolveNetwork({ isInternetReachable: true });
    await completion;

    expect(connect).not.toHaveBeenCalled();
    expect(markOffline).not.toHaveBeenCalled();
  });

  it("does not mutate status after an AppState resume listener is disposed", async () => {
    let resolveNetwork!: (network: { isInternetReachable: boolean }) => void;
    const network = new Promise<{ isInternetReachable: boolean }>((resolve) => {
      resolveNetwork = resolve;
    });
    const lifecycle = createNativeRemoteClientLifecycle();
    const reconnect = vi.fn();
    const markOffline = vi.fn();
    const completion = continueAfterNativeNetworkCheck(lifecycle, network, reconnect, markOffline);

    lifecycle.dispose();
    resolveNetwork({ isInternetReachable: false });
    await completion;

    expect(reconnect).not.toHaveBeenCalled();
    expect(markOffline).not.toHaveBeenCalled();
  });

  it("conservatively connects when a current network-state check rejects", async () => {
    const lifecycle = createNativeRemoteClientLifecycle();
    const connect = vi.fn();
    const markOffline = vi.fn();

    await continueAfterNativeNetworkCheck(
      lifecycle,
      Promise.reject(new Error("network inspection unavailable")),
      connect,
      markOffline,
    );

    expect(connect).toHaveBeenCalledOnce();
    expect(markOffline).not.toHaveBeenCalled();
  });

  it("ignores a rejected network-state check after disposal", async () => {
    const lifecycle = createNativeRemoteClientLifecycle();
    const connect = vi.fn();
    const markOffline = vi.fn();
    lifecycle.dispose();

    await continueAfterNativeNetworkCheck(
      lifecycle,
      Promise.reject(new Error("late network inspection failure")),
      connect,
      markOffline,
    );

    expect(connect).not.toHaveBeenCalled();
    expect(markOffline).not.toHaveBeenCalled();
  });

  it("suppresses obsolete status and event callbacks", () => {
    const lifecycle = createNativeRemoteClientLifecycle();
    const onStatus = vi.fn();
    const onEvent = vi.fn();
    lifecycle.dispose();

    expect(lifecycle.runIfCurrent(onStatus)).toBe(false);
    expect(lifecycle.runIfCurrent(onEvent)).toBe(false);
    expect(onStatus).not.toHaveBeenCalled();
    expect(onEvent).not.toHaveBeenCalled();
  });
});
