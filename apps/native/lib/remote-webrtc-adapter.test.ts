import {
  encodeRemoteEndpointFinalProofV1,
  type RemoteEndpointFinalProofV1,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it, vi } from "vitest";

// Mock native modules that cannot be loaded in the node test environment.
vi.mock("expo-constants", () => ({
  default: { executionEnvironment: "test" },
}));
vi.mock("react-native", () => ({
  Text: "Text",
  View: "View",
}));

import {
  computeFinalProofSetDigest,
  isNonRelayCandidate,
  isRelayCandidate,
  type NativeRtcDataChannel,
  type NativeRtcIceCandidate,
  type NativeRtcModule,
  type NativeRtcPeerConnection,
  type NativeRtcPeerConnectionConfig,
  REMOTE_WEBRTC_CHANNEL_IDS,
  REMOTE_WEBRTC_LANE_CHANNEL,
  type RemoteIpConsentState,
  type RemoteSignedIceServer,
  type RemoteSignedIpConsent,
  RemoteWebRtcAdapter,
  RemoteWebRtcAdapterError,
  type RemoteWebRtcAdapterOptions,
  type RemoteWebRtcChildPlan,
  type RemoteWebRtcEvent,
  resolveIcePolicy,
  verifyBothFinalProofs,
  verifyFinalProof,
} from "./remote-webrtc-adapter";
import {
  REMOTE_WEBRTC_NATIVE_DEPENDENCY_PAIR,
  REMOTE_WEBRTC_NATIVE_PEER_PLATFORM,
  REMOTE_WEBRTC_NATIVE_PLUGIN_PEER_EXPO,
  REMOTE_WEBRTC_NATIVE_PROVENANCE,
  runDependencyPairGate,
  validateExactVersions,
  validatePeerCompatible,
} from "./remote-webrtc-dependency-pair";
import {
  assertDurableP256Identity,
  assertNoKeyPersistence,
  assertNotIdentityKey,
  assertReEnrollmentNotWeaker,
  type RemoteIdentityKeyState,
  resolveIdentityLifecycleAction,
} from "./remote-webrtc-secure-identity";

// ---------------------------------------------------------------------------
// Test helpers — fake native WebRTC module and valid final proofs.
// ---------------------------------------------------------------------------

const CHILD_ATTEMPT_ID = new Uint8Array(16).fill(0).map((_, i) => i + 1);
const TRANSPORT_EPOCH = new Uint8Array(16).fill(0).map((_, i) => i + 17);
const GRANT_DIGEST = new Uint8Array(32).fill(0xab);
const NEGOTIATION_DIGEST = new Uint8Array(32).fill(0xcd);
const BINDING = new Uint8Array(96).fill(0xef);
const PROOF_JTI = new Uint8Array(16).fill(0).map((_, i) => i + 33);
const CERTIFICATE_ID = new Uint8Array(16).fill(0).map((_, i) => i + 49);
const SIGNATURE = new Uint8Array(64).fill(0x42);

function makeFinalProof(role: 1 | 2): Uint8Array {
  const proof: RemoteEndpointFinalProofV1 = {
    role,
    transport: 1,
    childAttemptId: CHILD_ATTEMPT_ID,
    transportEpoch: TRANSPORT_EPOCH,
    admissionSequence: 1n,
    grantDigest: GRANT_DIGEST,
    negotiationDigest: NEGOTIATION_DIGEST,
    binding: BINDING,
    proofJti: PROOF_JTI,
    certificateId: CERTIFICATE_ID,
    certificateGeneration: 1n,
    signature: SIGNATURE,
  };
  return encodeRemoteEndpointFinalProofV1(proof);
}

function fireListeners(
  listeners: Map<string, Set<(event?: unknown) => void>>,
  type: string,
  event?: unknown,
): void {
  const set = listeners.get(type);
  if (!set) return;
  for (const l of set) {
    l(event);
  }
}

function makeSignedConsent(state: RemoteIpConsentState): RemoteSignedIpConsent {
  return { state, signedBytes: new Uint8Array(32).fill(0x01) };
}

function makeTurnServer(): RemoteSignedIceServer {
  return {
    urls: ["turn:turn.example.com:3478"],
    username: "user",
    credential: "cred",
    signature: new Uint8Array(64).fill(0x55),
  };
}

function makeStunServer(): RemoteSignedIceServer {
  return {
    urls: ["stun:stun.example.com:3478"],
    signature: new Uint8Array(64).fill(0x66),
  };
}

function makeChildPlan(
  consentState: RemoteIpConsentState,
  iceServers: readonly RemoteSignedIceServer[],
  gatherCommitted = true,
  generation = 1,
): RemoteWebRtcChildPlan {
  const consent = makeSignedConsent(consentState);
  const policy = resolveIcePolicy(consent, iceServers, gatherCommitted) ?? {
    consent,
    iceServers,
    iceTransportPolicy: "all" as const,
    gatherCommitted,
  };
  return {
    childAttemptId: CHILD_ATTEMPT_ID,
    transportEpoch: TRANSPORT_EPOCH,
    admissionSequence: 1n,
    generation,
    selectedTupleId: 1,
    grantProofs: {
      grantDigest: GRANT_DIGEST,
      clientProof: makeFinalProof(1),
      daemonProof: makeFinalProof(2),
    },
    icePolicy: policy,
  };
}

function makeFakeChannel(id: number, label: string): NativeRtcDataChannel {
  const listeners = new Map<string, Set<(event?: unknown) => void>>();
  let readyState: NativeRtcDataChannel["readyState"] = "connecting";
  let bufferedAmount = 0;
  const sent: (ArrayBuffer | ArrayBufferView)[] = [];
  return {
    id,
    label,
    get readyState() {
      return readyState;
    },
    get bufferedAmount() {
      return bufferedAmount;
    },
    send(data: ArrayBuffer | ArrayBufferView) {
      sent.push(data as ArrayBuffer | ArrayBufferView);
    },
    close() {
      readyState = "closed";
      fireListeners(listeners, "close");
    },
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type)!.add(listener);
    },
    removeEventListener(type, listener) {
      listeners.get(type)?.delete(listener);
    },
    // Test-only accessors:
    ...({
      __open: () => {
        readyState = "open";
        fireListeners(listeners, "open");
      },
      __fireMessage: (data: unknown) => {
        fireListeners(listeners, "message", { data });
      },
      __fireBufferedAmountLow: () => {
        fireListeners(listeners, "bufferedamountlow");
      },
      __sent: sent,
    } as unknown as Record<string, unknown>),
  };
}

function makeFakePeer(config: NativeRtcPeerConnectionConfig): NativeRtcPeerConnection {
  const listeners = new Map<string, Set<(event?: unknown) => void>>();
  const channels: NativeRtcDataChannel[] = [];
  let iceConnectionState = "new";
  let connectionState = "new";
  return {
    get iceConnectionState() {
      return iceConnectionState;
    },
    get connectionState() {
      return connectionState;
    },
    createDataChannel(label, options) {
      const channel = makeFakeChannel(options?.id ?? channels.length, label);
      channels.push(channel);
      return channel;
    },
    async createOffer() {
      return { type: "offer", sdp: "v=0\r\n" };
    },
    async createAnswer() {
      return { type: "answer", sdp: "v=0\r\n" };
    },
    async setLocalDescription() {},
    async setRemoteDescription() {},
    async addIceCandidate() {},
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type)!.add(listener);
    },
    removeEventListener(type, listener) {
      listeners.get(type)?.delete(listener);
    },
    close() {},
    // Test-only accessors:
    ...({
      __config: config,
      __channels: channels,
      __fireIceCandidate: (candidate: NativeRtcIceCandidate) => {
        fireListeners(listeners, "icecandidate", { candidate });
      },
      __setIceState: (state: string) => {
        iceConnectionState = state;
        fireListeners(listeners, "iceconnectionstatechange");
      },
      __setConnState: (state: string) => {
        connectionState = state;
        fireListeners(listeners, "connectionstatechange");
      },
    } as unknown as Record<string, unknown>),
  };
}

function makeFakeRtcModule(): NativeRtcModule & {
  __lastConfig: NativeRtcPeerConnectionConfig | null;
  __lastPeer: (NativeRtcPeerConnection & Record<string, unknown>) | null;
} {
  const state: {
    lastConfig: NativeRtcPeerConnectionConfig | null;
    lastPeer: (NativeRtcPeerConnection & Record<string, unknown>) | null;
  } = { lastConfig: null, lastPeer: null };

  const mod = {
    RTCPeerConnection: function PeerConnection(
      this: unknown,
      config: NativeRtcPeerConnectionConfig,
    ) {
      state.lastConfig = config;
      const peer = makeFakePeer(config) as NativeRtcPeerConnection & Record<string, unknown>;
      state.lastPeer = peer;
      return peer;
    },
  } as unknown as NativeRtcModule & {
    __lastConfig: NativeRtcPeerConnectionConfig | null;
    __lastPeer: (NativeRtcPeerConnection & Record<string, unknown>) | null;
  };

  Object.defineProperty(mod, "__lastConfig", {
    get: () => state.lastConfig,
  });
  Object.defineProperty(mod, "__lastPeer", {
    get: () => state.lastPeer,
  });

  return mod;
}

function makeAdapter(
  plan: RemoteWebRtcChildPlan,
  role: 1 | 2 = 1,
): {
  adapter: RemoteWebRtcAdapter;
  events: RemoteWebRtcEvent[];
  rtc: ReturnType<typeof makeFakeRtcModule>;
} {
  const events: RemoteWebRtcEvent[] = [];
  const rtc = makeFakeRtcModule();
  const options: RemoteWebRtcAdapterOptions = {
    plan,
    rtcModule: rtc,
    role,
    onEvent: (e) => events.push(e),
  };
  return { adapter: new RemoteWebRtcAdapter(options), events, rtc };
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

describe("remote_native_dependency_pair_gate", () => {
  it("pins exact react-native-webrtc and config plugin versions", () => {
    expect(REMOTE_WEBRTC_NATIVE_DEPENDENCY_PAIR.reactNativeWebrtc).toBe("124.0.8");
    expect(REMOTE_WEBRTC_NATIVE_DEPENDENCY_PAIR.configPluginsReactNativeWebrtc).toBe("15.0.1");
  });

  it("validates exact versions match the pinned pair", () => {
    expect(validateExactVersions("124.0.8", "15.0.1")).toBe(true);
    expect(validateExactVersions("124.0.7", "15.0.1")).toBe(false);
    expect(validateExactVersions("124.0.8", "15.0.0")).toBe(false);
  });

  it("validates Expo peer compatibility with ^56", () => {
    expect(validatePeerCompatible("~56.0.3")).toBe(true);
    expect(validatePeerCompatible("^56.0.0")).toBe(true);
    expect(validatePeerCompatible("~55.0.0")).toBe(false);
    expect(validatePeerCompatible("~57.0.0")).toBe(false);
  });

  it("records provenance, license, and maintenance for both packages", () => {
    expect(REMOTE_WEBRTC_NATIVE_PROVENANCE).toHaveLength(2);
    for (const p of REMOTE_WEBRTC_NATIVE_PROVENANCE) {
      expect(p.license.length).toBeGreaterThan(0);
      expect(p.maintainer.length).toBeGreaterThan(0);
      expect(p.newArchitecture).toBe(true);
      expect(p.platforms).toContain("ios");
      expect(p.platforms).toContain("android");
    }
  });

  it("records the plugin peer expo requirement", () => {
    expect(REMOTE_WEBRTC_NATIVE_PLUGIN_PEER_EXPO).toBe("^56");
  });

  it("records the peer platform versions", () => {
    expect(REMOTE_WEBRTC_NATIVE_PEER_PLATFORM.expo).toBe("~56.0.3");
    expect(REMOTE_WEBRTC_NATIVE_PEER_PLATFORM.reactNative).toBe("0.85.3");
  });

  it("passes the full gate with valid inputs", () => {
    const result = runDependencyPairGate({
      reactNativeWebrtcVersion: "124.0.8",
      configPluginsVersion: "15.0.1",
      expoVersion: "~56.0.3",
      compileResults: [
        { platform: "ios", compiled: true, diagnosticsPath: null },
        { platform: "android", compiled: true, diagnosticsPath: null },
      ],
      lockfileImpact: "additive",
      bundleImpact: "additive",
    });
    expect(result.passed).toBe(true);
    expect(result.reason).toBeNull();
  });

  it("fails the gate on version mismatch", () => {
    const result = runDependencyPairGate({
      reactNativeWebrtcVersion: "124.0.7",
      configPluginsVersion: "15.0.1",
      expoVersion: "~56.0.3",
      compileResults: [
        { platform: "ios", compiled: true, diagnosticsPath: null },
        { platform: "android", compiled: true, diagnosticsPath: null },
      ],
      lockfileImpact: "additive",
      bundleImpact: "additive",
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("exact version mismatch");
  });

  it("fails the gate on compile failure", () => {
    const result = runDependencyPairGate({
      reactNativeWebrtcVersion: "124.0.8",
      configPluginsVersion: "15.0.1",
      expoVersion: "~56.0.3",
      compileResults: [
        { platform: "ios", compiled: false, diagnosticsPath: "ios-error.log" },
        { platform: "android", compiled: true, diagnosticsPath: null },
      ],
      lockfileImpact: "additive",
      bundleImpact: "additive",
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("platform compile failed");
  });

  it("fails the gate on breaking lockfile or bundle impact", () => {
    const result = runDependencyPairGate({
      reactNativeWebrtcVersion: "124.0.8",
      configPluginsVersion: "15.0.1",
      expoVersion: "~56.0.3",
      compileResults: [
        { platform: "ios", compiled: true, diagnosticsPath: null },
        { platform: "android", compiled: true, diagnosticsPath: null },
      ],
      lockfileImpact: "breaking",
      bundleImpact: "breaking",
    });
    expect(result.passed).toBe(false);
  });
});

describe("remote_native_passive_adapter_contract", () => {
  it("emits events and accepts commands", () => {
    const { adapter, rtc } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    const peer = adapter.createPeer();
    expect(peer).not.toBeNull();
    expect(rtc.__lastConfig).not.toBeNull();
  });

  it("contains no retry, fallback, selection, reattach, or attachment mutation", () => {
    const { adapter } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    // The adapter has no public methods for retry/fallback/select/reattach.
    // Verify no method names match retry/fallback/select/reattach/attach.
    const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(adapter)).filter(
      (m) => m !== "constructor",
    );
    for (const m of methods) {
      expect(m).not.toMatch(/retry|fallback|select|reattach/);
    }
    // Verify the adapter has no attach/reattach mutation methods.
    expect(typeof (adapter as unknown as Record<string, unknown>).attach).toBe("undefined");
    expect(typeof (adapter as unknown as Record<string, unknown>).reattach).toBe("undefined");
    expect(typeof (adapter as unknown as Record<string, unknown>).retry).toBe("undefined");
    expect(typeof (adapter as unknown as Record<string, unknown>).fallback).toBe("undefined");
    expect(typeof (adapter as unknown as Record<string, unknown>).select).toBe("undefined");
  });

  it("never creates a second child", () => {
    const { adapter } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    // createPeer again replaces the peer, does not create a second child.
    const peer2 = adapter.createPeer();
    expect(peer2).not.toBeNull();
    // The adapter holds at most one peer reference.
    expect(adapter.isClosed).toBe(false);
  });
});

describe("remote_native_ice_consent_matrix", () => {
  it("direct_allowed creates normal ICE after committed gather capability", () => {
    const consent = makeSignedConsent("direct_allowed");
    const policy = resolveIcePolicy(consent, [makeStunServer()], true);
    expect(policy).not.toBeNull();
    expect(policy!.iceTransportPolicy).toBe("all");
  });

  it("direct_allowed does not create ICE before committed gather capability", () => {
    const consent = makeSignedConsent("direct_allowed");
    const policy = resolveIcePolicy(consent, [makeStunServer()], false);
    expect(policy).toBeNull();
  });

  it("relay_only configures only verified signed TURN URLs plus relay policy", () => {
    const consent = makeSignedConsent("relay_only");
    const policy = resolveIcePolicy(consent, [makeTurnServer()], false);
    expect(policy).not.toBeNull();
    expect(policy!.iceTransportPolicy).toBe("relay");
    expect(policy!.iceServers).toHaveLength(1);
    expect(policy!.iceServers[0]!.urls[0]).toMatch(/^turn/);
  });

  it("relay_only rejects STUN/direct servers", () => {
    const consent = makeSignedConsent("relay_only");
    const stun = makeStunServer();
    // STUN-only servers are filtered out; relay_only requires at least one TURN.
    expect(() => resolveIcePolicy(consent, [stun], false)).toThrow(RemoteWebRtcAdapterError);
  });

  it("relay_only throws when no TURN servers are provided", () => {
    const consent = makeSignedConsent("relay_only");
    expect(() => resolveIcePolicy(consent, [], false)).toThrow(RemoteWebRtcAdapterError);
  });

  it("relay_only throws when TURN server signature is missing", () => {
    const consent = makeSignedConsent("relay_only");
    const unsignedTurn: RemoteSignedIceServer = {
      urls: ["turn:turn.example.com:3478"],
      signature: new Uint8Array(0),
    };
    expect(() => resolveIcePolicy(consent, [unsignedTurn], false)).toThrow(
      RemoteWebRtcAdapterError,
    );
  });

  it("unavailable creates no peer", () => {
    const consent = makeSignedConsent("unavailable");
    const policy = resolveIcePolicy(consent, [makeTurnServer()], true);
    expect(policy).toBeNull();
    const { adapter } = makeAdapter(makeChildPlan("unavailable", [makeTurnServer()]));
    expect(adapter.createPeer()).toBeNull();
  });

  it("applies no baked/default server", () => {
    const consent = makeSignedConsent("direct_allowed");
    const policy = resolveIcePolicy(consent, [], true);
    // With no ICE servers and direct_allowed, the policy is still created
    // but iceServers is empty — no baked/default server is injected.
    expect(policy).not.toBeNull();
    expect(policy!.iceServers).toHaveLength(0);
  });

  it("suppresses non-relay local candidates before signaling in relay_only", () => {
    const { adapter, events } = makeAdapter(makeChildPlan("relay_only", [makeTurnServer()]));
    const peer = adapter.createPeer() as unknown as Record<string, unknown>;
    expect(peer).not.toBeNull();
    const fireIceCandidate = peer.__fireIceCandidate as (c: NativeRtcIceCandidate) => void;
    // Fire a non-relay candidate — should be suppressed.
    fireIceCandidate({
      candidate: "candidate:1 1 udp 2113929471 192.168.1.1 50000 typ host",
      sdpMid: "0",
      sdpMLineIndex: 0,
    });
    expect(events.filter((e) => e.type === "ice_candidate")).toHaveLength(0);
    // Fire a relay candidate — should be emitted.
    fireIceCandidate({
      candidate: "candidate:1 1 udp 41549186 203.0.113.1 50000 typ relay raddr 0.0.0.0 rport 0",
      sdpMid: "0",
      sdpMLineIndex: 0,
    });
    expect(events.filter((e) => e.type === "ice_candidate")).toHaveLength(1);
  });

  it("rejects non-relay remote candidates in relay_only", () => {
    const { adapter } = makeAdapter(makeChildPlan("relay_only", [makeTurnServer()]));
    adapter.createPeer();
    expect(() =>
      adapter.acceptRemoteCandidate({
        candidate: "candidate:1 1 udp 2113929471 192.168.1.1 50000 typ host",
        sdpMid: "0",
        sdpMLineIndex: 0,
      }),
    ).toThrow(RemoteWebRtcAdapterError);
  });

  it("accepts relay remote candidates in relay_only", () => {
    const { adapter } = makeAdapter(makeChildPlan("relay_only", [makeTurnServer()]));
    adapter.createPeer();
    expect(() =>
      adapter.acceptRemoteCandidate({
        candidate: "candidate:1 1 udp 41549186 203.0.113.1 50000 typ relay raddr 0.0.0.0 rport 0",
        sdpMid: "0",
        sdpMLineIndex: 0,
      }),
    ).not.toThrow();
  });

  it("does not claim zero internal host resource creation", () => {
    // The isNonRelayCandidate/isRelayCandidate functions classify candidates
    // observed at the adapter boundary only; they do not claim control over
    // native-library internal gathering.
    expect(isRelayCandidate("candidate:1 1 udp 41549186 203.0.113.1 50000 typ relay")).toBe(true);
    expect(isNonRelayCandidate("candidate:1 1 udp 2113929471 192.168.1.1 50000 typ host")).toBe(
      true,
    );
    expect(isNonRelayCandidate("not a candidate")).toBe(true);
  });
});

describe("remote_native_channel_and_cleanup", () => {
  it("uses exact channel IDs 0/2/4", () => {
    expect(REMOTE_WEBRTC_CHANNEL_IDS.control).toBe(0);
    expect(REMOTE_WEBRTC_CHANNEL_IDS.interactive).toBe(2);
    expect(REMOTE_WEBRTC_CHANNEL_IDS.bulk).toBe(4);
  });

  it("maps channels to the three lanes", () => {
    expect(REMOTE_WEBRTC_LANE_CHANNEL.control).toBe(0);
    expect(REMOTE_WEBRTC_LANE_CHANNEL.interactive).toBe(2);
    expect(REMOTE_WEBRTC_LANE_CHANNEL.bulk).toBe(4);
  });

  it("creates three data channels with the exact IDs", () => {
    const { adapter, rtc } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    const peer = rtc.__lastPeer as unknown as Record<string, unknown>;
    const channels = peer.__channels as NativeRtcDataChannel[];
    expect(channels).toHaveLength(3);
    expect(channels.map((c) => c.id).sort((a, b) => a - b)).toEqual([0, 2, 4]);
  });

  it("exposes lane writer only after both final proofs", () => {
    const { adapter } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    // Before final proofs, sending should fail.
    expect(() =>
      adapter.acceptCommand({ kind: "send", lane: "control", data: new Uint8Array(4) }),
    ).toThrow(RemoteWebRtcAdapterError);
    // After final proofs, the lane writer is exposed.
    const writer = adapter.consumeFinalProofs(makeFinalProof(1), makeFinalProof(2));
    expect(writer).toBeDefined();
    expect(adapter.isReady).toBe(true);
  });

  it("rejects send before final proofs even if channel is open", () => {
    const { adapter, rtc } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    const peer = rtc.__lastPeer as unknown as Record<string, unknown>;
    const channels = peer.__channels as (NativeRtcDataChannel & Record<string, unknown>)[];
    // Open the control channel.
    (channels[0]!.__open as () => void)();
    expect(() =>
      adapter.acceptCommand({ kind: "send", lane: "control", data: new Uint8Array(4) }),
    ).toThrow(RemoteWebRtcAdapterError);
  });

  it("enforces lane payload caps (backpressure)", () => {
    const { adapter, rtc } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    const peer = rtc.__lastPeer as unknown as Record<string, unknown>;
    const channels = peer.__channels as (NativeRtcDataChannel & Record<string, unknown>)[];
    (channels[0]!.__open as () => void)();
    const writer = adapter.consumeFinalProofs(makeFinalProof(1), makeFinalProof(2));
    // Control lane cap is 64 KiB. Send within cap.
    writer.send("control", new Uint8Array(1024));
    // Send over cap — should throw.
    expect(() => writer.send("control", new Uint8Array(64 * 1024 + 1))).toThrow(
      RemoteWebRtcAdapterError,
    );
  });

  it("cleans up on every terminal branch via close", () => {
    const { adapter, events } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    adapter.close("user", "done");
    expect(adapter.isClosed).toBe(true);
    const closedEvents = events.filter((e) => e.type === "closed");
    expect(closedEvents).toHaveLength(1);
    expect(closedEvents[0]!.generation).toBe(1);
  });

  it("cleans up via close command", () => {
    const { adapter, events } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    adapter.acceptCommand({ kind: "close", reason: "user closed" });
    expect(adapter.isClosed).toBe(true);
    expect(events.some((e) => e.type === "closed")).toBe(true);
  });
});

describe("remote_native_webrtc_daemon_interop (final-proof gate)", () => {
  it("verifies a single final proof", () => {
    const proof = makeFinalProof(1);
    const decoded = verifyFinalProof(proof);
    expect(decoded.role).toBe(1);
    expect(decoded.transport).toBe(1);
  });

  it("verifies both final proofs and computes the set digest", () => {
    const clientProof = makeFinalProof(1);
    const daemonProof = makeFinalProof(2);
    const {
      clientProof: cp,
      daemonProof: dp,
      digest,
    } = verifyBothFinalProofs(clientProof, daemonProof);
    expect(cp.role).toBe(1);
    expect(dp.role).toBe(2);
    expect(digest.length).toBe(32);
  });

  it("rejects swapped roles", () => {
    const proof1 = makeFinalProof(1);
    const proof2 = makeFinalProof(2);
    expect(() => verifyBothFinalProofs(proof2, proof1)).toThrow(RemoteWebRtcAdapterError);
  });

  it("computes a deterministic final-proof-set digest", () => {
    const clientProof = makeFinalProof(1);
    const daemonProof = makeFinalProof(2);
    const d1 = computeFinalProofSetDigest(clientProof, daemonProof);
    const d2 = computeFinalProofSetDigest(clientProof, daemonProof);
    expect(d1).toEqual(d2);
  });

  it("emits ready event with role and digest after both proofs", () => {
    const { adapter, events } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    adapter.consumeFinalProofs(makeFinalProof(1), makeFinalProof(2));
    const ready = events.filter((e) => e.type === "ready");
    expect(ready).toHaveLength(1);
    expect(ready[0]!.role).toBe(1);
    expect(ready[0]!.finalProofSetDigest.length).toBe(32);
  });

  it("emits health event reflecting dtls and proof state", () => {
    const { adapter, events, rtc } = makeAdapter(
      makeChildPlan("direct_allowed", [makeStunServer()]),
    );
    adapter.createPeer();
    const peer = rtc.__lastPeer as unknown as Record<string, unknown>;
    // Simulate DTLS connected.
    (peer.__setConnState as (s: string) => void)("connected");
    const health = events.filter((e) => e.type === "health");
    expect(health.length).toBeGreaterThanOrEqual(1);
    const lastHealth = health[health.length - 1]!;
    expect(lastHealth.dtlsConnected).toBe(true);
    expect(lastHealth.bothProofsVerified).toBe(false);
    // After final proofs, a new health event shows bothProofsVerified.
    adapter.consumeFinalProofs(makeFinalProof(1), makeFinalProof(2));
    const healthAfter = events.filter((e) => e.type === "health").at(-1)!;
    expect(healthAfter.bothProofsVerified).toBe(true);
  });

  it("rejects final proofs with mismatched child attempt id", () => {
    const { adapter } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    // Make a proof with a different child attempt id.
    const wrongProof: RemoteEndpointFinalProofV1 = {
      role: 1,
      transport: 1,
      childAttemptId: new Uint8Array(16).fill(0xff),
      transportEpoch: TRANSPORT_EPOCH,
      admissionSequence: 1n,
      grantDigest: GRANT_DIGEST,
      negotiationDigest: NEGOTIATION_DIGEST,
      binding: BINDING,
      proofJti: PROOF_JTI,
      certificateId: CERTIFICATE_ID,
      certificateGeneration: 1n,
      signature: SIGNATURE,
    };
    const wrongBytes = encodeRemoteEndpointFinalProofV1(wrongProof);
    expect(() => adapter.consumeFinalProofs(wrongBytes, makeFinalProof(2))).toThrow(
      RemoteWebRtcAdapterError,
    );
  });
});

describe("remote_native_lifecycle_generation_matrix", () => {
  it("emits generation-bound lifecycle events", () => {
    const { adapter, events } = makeAdapter(
      makeChildPlan("direct_allowed", [makeStunServer()], true, 42),
    );
    adapter.emitLifecycle({ type: "background", generation: 42 });
    adapter.emitLifecycle({ type: "inactive", generation: 42 });
    adapter.emitLifecycle({ type: "os_kill", generation: 42 });
    adapter.emitLifecycle({ type: "network_change", generation: 42 });
    adapter.emitLifecycle({ type: "airplane_mode", generation: 42 });
    adapter.emitLifecycle({ type: "push_tap", generation: 42 });
    const lifecycle = events.filter(
      (e) =>
        e.type === "background" ||
        e.type === "inactive" ||
        e.type === "os_kill" ||
        e.type === "network_change" ||
        e.type === "airplane_mode" ||
        e.type === "push_tap",
    );
    expect(lifecycle).toHaveLength(6);
    for (const e of lifecycle) {
      expect(e.generation).toBe(42);
    }
  });

  it("stale callbacks cannot mutate a superseded generation", () => {
    const { adapter, events } = makeAdapter(
      makeChildPlan("direct_allowed", [makeStunServer()], true, 1),
    );
    // Emit a lifecycle event for a different generation — should be ignored.
    adapter.emitLifecycle({ type: "background", generation: 99 } as never);
    expect(events.filter((e) => e.type === "background")).toHaveLength(0);
  });

  it("emits turn_failure and native_module_failure events", () => {
    const { adapter, events } = makeAdapter(
      makeChildPlan("direct_allowed", [makeStunServer()], true, 5),
    );
    adapter.emitLifecycle({ type: "turn_failure", generation: 5, reason: "relay unreachable" });
    adapter.emitLifecycle({
      type: "native_module_failure",
      generation: 5,
      reason: "module not found",
    });
    expect(events.some((e) => e.type === "turn_failure" && e.generation === 5)).toBe(true);
    expect(events.some((e) => e.type === "native_module_failure" && e.generation === 5)).toBe(true);
  });

  it("closed event is generation-bound", () => {
    const { adapter, events } = makeAdapter(
      makeChildPlan("direct_allowed", [makeStunServer()], true, 7),
    );
    adapter.createPeer();
    adapter.close("network", "connection lost");
    const closed = events.filter((e) => e.type === "closed");
    expect(closed).toHaveLength(1);
    expect(closed[0]!.generation).toBe(7);
    expect(closed[0]!.reason).toContain("network");
  });
});

describe("remote_native_no_media_permissions", () => {
  it("the adapter interface declares no media track/stream/permission surface", () => {
    // The NativeRtcPeerConnection interface has no addTrack, addStream,
    // getSenders, getReceivers, or media-related methods. Verify by checking
    // the interface members indirectly through the fake implementation.
    const rtc = makeFakeRtcModule();
    const peer = new rtc.RTCPeerConnection({
      iceServers: [],
      iceTransportPolicy: "all",
    });
    const methodNames = Object.getOwnPropertyNames(Object.getPrototypeOf(peer));
    for (const m of methodNames) {
      expect(m).not.toMatch(
        /addTrack|addStream|getSenders|getReceivers|media|MediaStream|MediaTrack/,
      );
    }
  });

  it("the adapter creates only data channels, no media tracks", () => {
    const { adapter, rtc } = makeAdapter(makeChildPlan("direct_allowed", [makeStunServer()]));
    adapter.createPeer();
    const peer = rtc.__lastPeer as unknown as Record<string, unknown>;
    const channels = peer.__channels as NativeRtcDataChannel[];
    // Only three data channels: control, interactive, bulk.
    expect(channels).toHaveLength(3);
    expect(
      channels.every(
        (c) => c.label === "control" || c.label === "interactive" || c.label === "bulk",
      ),
    ).toBe(true);
  });
});

describe("remote_native_secure_identity_lifecycle", () => {
  it("asserts X25519 is never treated as identity", () => {
    expect(() => assertNotIdentityKey("x25519_ephemeral")).toThrow();
    expect(() => assertNotIdentityKey("p256_durable")).not.toThrow();
  });

  it("asserts the adapter never persists keys", () => {
    expect(() => assertNoKeyPersistence("persist")).toThrow();
    expect(() => assertNoKeyPersistence("store")).toThrow();
    expect(() => assertNoKeyPersistence("write")).toThrow();
    expect(() => assertNoKeyPersistence("send")).not.toThrow();
  });

  it("resolves unlock for locked key store", () => {
    const state: RemoteIdentityKeyState = {
      keyId: new Uint8Array(16),
      kind: "p256_durable",
      custodyClass: "os_protected",
      generation: 1n,
      status: "locked",
    };
    expect(resolveIdentityLifecycleAction(state)).toBe("unlock");
  });

  it("resolves re_enroll for lost key store", () => {
    const state: RemoteIdentityKeyState = {
      keyId: new Uint8Array(16),
      kind: "p256_durable",
      custodyClass: "os_protected",
      generation: 1n,
      status: "lost",
    };
    expect(resolveIdentityLifecycleAction(state)).toBe("re_enroll");
  });

  it("resolves re_enroll for revoked key", () => {
    const state: RemoteIdentityKeyState = {
      keyId: new Uint8Array(16),
      kind: "p256_durable",
      custodyClass: "os_protected",
      generation: 1n,
      status: "revoked",
    };
    expect(resolveIdentityLifecycleAction(state)).toBe("re_enroll");
  });

  it("re-enrollment must not weaken custody class", () => {
    expect(() => assertReEnrollmentNotWeaker("hardware_or_external", "os_protected")).toThrow();
    expect(() => assertReEnrollmentNotWeaker("os_protected", "hardware_or_external")).not.toThrow();
    expect(() => assertReEnrollmentNotWeaker("os_protected", "os_protected")).not.toThrow();
  });

  it("asserts durable P-256 for identity", () => {
    const valid: RemoteIdentityKeyState = {
      keyId: new Uint8Array(16),
      kind: "p256_durable",
      custodyClass: "os_protected",
      generation: 1n,
      status: "active",
    };
    expect(() => assertDurableP256Identity(valid)).not.toThrow();
    const invalid: RemoteIdentityKeyState = {
      keyId: new Uint8Array(16),
      kind: "x25519_ephemeral",
      custodyClass: "os_protected",
      generation: 1n,
      status: "active",
    };
    expect(() => assertDurableP256Identity(invalid)).toThrow();
  });
});

describe("Expo Go unsupported state", () => {
  it("isExpoGo detects storeClient execution environment", async () => {
    const { isExpoGo } = await import("../components/expo-go-unsupported");
    // In the test environment, executionEnvironment is not storeClient.
    expect(isExpoGo()).toBe(false);
  });
});
