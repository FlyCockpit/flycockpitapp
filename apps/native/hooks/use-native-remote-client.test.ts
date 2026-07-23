import type { RemoteSessionClientOptions } from "@flycockpit/cockpit-protocol/client";
import { describe, expect, it, vi } from "vitest";
import { nativeRemoteClientOptions } from "./use-native-remote-client";

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
});
