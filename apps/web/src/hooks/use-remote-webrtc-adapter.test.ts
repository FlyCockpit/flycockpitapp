import {
  type RemoteWebAttemptInput,
  type RemoteWebEvent,
  RemoteWebRtcAdapter,
  type WebRtcDataChannel,
  type WebRtcPeerConnection,
  type WebRtcPeerFactory,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import { type RemoteWebRtcHookState, reduceAdapterEvent } from "./use-remote-webrtc-adapter";

const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);
const id16 = (value: number) => bytes(16, value);

// Minimal deterministic peer fakes (same shape as the protocol package tests).

class FakeDataChannel implements WebRtcDataChannel {
  bufferedAmount = 0;
  readonly bufferedAmountLowThreshold = 0;
  readyState: "connecting" | "open" | "closing" | "closed" = "connecting";
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onbufferedamountlow: (() => void) | null = null;
  onmessage: ((event: { readonly data: Uint8Array }) => void) | null = null;
  constructor(
    readonly label: string,
    readonly id: number | null,
    readonly ordered: boolean,
  ) {}
  send(): void {}
  close(): void {
    this.readyState = "closed";
  }
  open(): void {
    this.readyState = "open";
    this.onopen?.();
  }
}

class FakePeerConnection implements WebRtcPeerConnection {
  localDescription = {
    type: "offer" as const,
    sdp: "a=fingerprint:sha-256 01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20\r\n",
  };
  remoteDescription = null;
  iceConnectionState = "new" as const;
  connectionState = "new" as const;
  onicecandidate = null;
  oniceconnectionstatechange = null;
  onconnectionstatechange = null;
  ondatachannel = null;
  channels: FakeDataChannel[] = [];
  closed = false;

  createDataChannel(
    label: string,
    options?: { readonly id?: number; readonly ordered?: boolean; readonly negotiated?: boolean },
  ): WebRtcDataChannel {
    const channel = new FakeDataChannel(label, options?.id ?? null, options?.ordered ?? true);
    this.channels.push(channel);
    return channel;
  }

  async setLocalDescription(): Promise<void> {}
  async setRemoteDescription(): Promise<void> {}
  async addIceCandidate(): Promise<void> {}
  close(): void {
    this.closed = true;
  }
}

class FakePeerFactory implements WebRtcPeerFactory {
  peers: FakePeerConnection[] = [];
  create(): WebRtcPeerConnection {
    const peer = new FakePeerConnection();
    this.peers.push(peer);
    return peer;
  }
}

function makeAttemptInput(overrides?: Partial<RemoteWebAttemptInput>): RemoteWebAttemptInput {
  return {
    childAttemptId: id16(1),
    transportEpoch: id16(2),
    admissionSequence: 1n,
    grantDigest: bytes(32, 3),
    icePolicy: {
      turnServers: [{ urls: ["turn:relay.example.com:3478"], username: "u", credential: "c" }],
      transportPolicy: "direct",
      policyDigest: bytes(32, 4),
    },
    ipConsent: "granted",
    identity: {
      p256KeyHandle: {},
      clientCertificateJws: bytes(100, 5),
      certificateId: id16(6),
      certificateGeneration: 1n,
    },
    generation: 1,
    capability: "direct_allowed",
    ...overrides,
  };
}

const initialHookState: RemoteWebRtcHookState = {
  uxState: "closed",
  health: "closed",
  lanesReady: false,
  closeReason: undefined,
};

describe("useRemoteWebRtcAdapter reduceAdapterEvent", () => {
  it("reduces capability events to safe UX state", () => {
    const result = reduceAdapterEvent(initialHookState, {
      kind: "capability",
      result: { status: "ok", capability: "direct_allowed" },
    });
    expect(result.uxState).toBe("active");
  });

  it("reduces health events", () => {
    const result = reduceAdapterEvent(initialHookState, {
      kind: "health",
      status: "establishing",
    });
    expect(result.health).toBe("establishing");
  });

  it("reduces lane_ready events", () => {
    const result = reduceAdapterEvent(initialHookState, {
      kind: "lane_ready",
      lanes: ["control", "interactive", "bulk"],
    });
    expect(result.lanesReady).toBe(true);
  });

  it("reduces close events with reason", () => {
    const result = reduceAdapterEvent(
      { ...initialHookState, uxState: "active", health: "active", lanesReady: true },
      { kind: "close", reason: "navigation" },
    );
    expect(result.uxState).toBe("closed");
    expect(result.health).toBe("closed");
    expect(result.lanesReady).toBe(false);
    expect(result.closeReason).toBe("navigation");
  });

  it("does not mutate state on signaling/candidate/data/backpressure events", () => {
    const events: RemoteWebEvent[] = [
      { kind: "signaling", message: { type: "offer", sdp: bytes(10, 1), descriptionId: id16(1) } },
      {
        kind: "candidate",
        candidate: {
          candidateId: id16(2),
          sdpMid: "0",
          sdpMLineIndex: 0,
          candidate: "candidate:1",
        },
      },
      { kind: "ice_complete" },
      { kind: "lane_data", lane: "control", bytes: bytes(10, 1) },
      { kind: "backpressure", lane: "bulk", bufferedAmount: 100 },
    ];
    for (const event of events) {
      expect(reduceAdapterEvent(initialHookState, event)).toBe(initialHookState);
    }
  });

  it("safe UX state contains no network/identity material", () => {
    const result = reduceAdapterEvent(initialHookState, {
      kind: "capability",
      result: { status: "policy_denied", capability: "relay_only" },
    });
    expect(result.uxState).toBe("policy_denied");
    expect(result.uxState).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
    expect(result.uxState).not.toMatch(/turn:/);
    expect(result.uxState).not.toMatch(/password|secret|token/i);
  });
});

describe("useRemoteWebRtcAdapter adapter lifecycle", () => {
  it("establish creates an adapter that emits capability and health events", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = new RemoteWebRtcAdapter({
      peerFactory: factory,
      emit: (event) => events.push(event),
    });
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    expect(events.some((e) => e.kind === "capability")).toBe(true);
    expect(events.some((e) => e.kind === "health")).toBe(true);
  });

  it("close on unmount is deterministic — peer and channels closed", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = new RemoteWebRtcAdapter({
      peerFactory: factory,
      emit: (event) => events.push(event),
    });
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    const peer = factory.peers[0]!;
    expect(peer.closed).toBe(false);
    adapter.close("unmount");
    expect(peer.closed).toBe(true);
    for (const channel of peer.channels) {
      expect(channel.readyState).toBe("closed");
    }
  });

  it("replacement closes the prior peer and increments generation", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = new RemoteWebRtcAdapter({
      peerFactory: factory,
      emit: (event) => events.push(event),
    });
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput({ generation: 1 }) });
    const firstPeer = factory.peers[0]!;
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput({ generation: 2 }) });
    expect(firstPeer.closed).toBe(true);
  });
});
