import { describe, expect, it, vi } from "vitest";
import { encodeRemoteEndpointFinalProofV1 } from "./remote-signaling-payloads";
import { REMOTE_LANES } from "./remote-transport-lanes";
import {
  decodeRemoteWebRtcFragment,
  encodeRemoteWebRtcFragment,
  extractDtlsFingerprint,
  parseCandidateType,
  REMOTE_WEBRTC_BUFFERED_AMOUNT_HIGH_THRESHOLD,
  REMOTE_WEBRTC_CHANNEL_IDS,
  REMOTE_WEBRTC_FRAGMENT_MAX_PAYLOAD_BYTES,
  REMOTE_WEBRTC_MAX_FRAGMENT_COUNT,
  type RemoteWebAttemptInput,
  type RemoteWebCapabilityProbe,
  type RemoteWebEvent,
  RemoteWebRtcAdapter,
  type RemoteWebRtcFragment,
  RemoteWebRtcReassembly,
  remoteWebAllowLocalCandidate,
  remoteWebAllowRemoteCandidate,
  remoteWebCapabilityGate,
  remoteWebIceConfiguration,
  remoteWebNegotiationDigest,
  remoteWebRedactedDiagnostic,
  remoteWebRtcFragmentPayload,
  remoteWebSafeUxState,
  remoteWebVerifyProofs,
  type WebRtcDataChannel,
  type WebRtcPeerConnection,
  type WebRtcPeerFactory,
} from "./remote-webrtc-web-adapter";

const bytes = (length: number, value: number) => new Uint8Array(length).fill(value);
const id16 = (value: number) => bytes(16, value);

// ---------------------------------------------------------------------------
// Deterministic peer/channel fakes
// ---------------------------------------------------------------------------

class FakeDataChannel implements WebRtcDataChannel {
  bufferedAmount = 0;
  readonly bufferedAmountLowThreshold: number = 0;
  readyState: "connecting" | "open" | "closing" | "closed" = "connecting";
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onbufferedamountlow: (() => void) | null = null;
  onmessage: ((event: { readonly data: Uint8Array }) => void) | null = null;
  sent: Uint8Array[] = [];

  constructor(
    readonly label: string,
    readonly id: number | null,
    readonly ordered: boolean,
  ) {}

  send(data: Uint8Array): void {
    this.sent.push(data);
    this.bufferedAmount += data.length;
  }

  close(): void {
    this.readyState = "closed";
    this.onclose?.();
  }

  /** Test helper: simulate the browser opening the channel. */
  open(): void {
    this.readyState = "open";
    this.onopen?.();
  }

  /** Test helper: simulate the remote peer sending a message. */
  receive(data: Uint8Array): void {
    this.onmessage?.({ data });
  }
}

class FakePeerConnection implements WebRtcPeerConnection {
  localDescription: { readonly type: "offer"; readonly sdp: string } | null = null;
  remoteDescription: { readonly type: "answer"; readonly sdp: string } | null = null;
  iceConnectionState: WebRtcPeerConnection["iceConnectionState"] = "new";
  connectionState: WebRtcPeerConnection["connectionState"] = "new";
  onicecandidate:
    | ((event: {
        readonly candidate: {
          readonly candidate: string;
          readonly sdpMid: string | null;
          readonly sdpMLineIndex: number | null;
        } | null;
      }) => void)
    | null = null;
  oniceconnectionstatechange: (() => void) | null = null;
  onconnectionstatechange: (() => void) | null = null;
  ondatachannel: ((event: { readonly channel: WebRtcDataChannel }) => void) | null = null;
  channels: FakeDataChannel[] = [];
  addedCandidates: { readonly candidate: string }[] = [];
  closed = false;
  readonly offerSdp: string;

  constructor(offerSdp?: string) {
    this.offerSdp =
      offerSdp ??
      "v=0\r\no=- 1 1 IN IP4 0\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0\r\na=fingerprint:sha-256 01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20\r\na=setup:actpass\r\na=mid:0\r\n";
  }

  createDataChannel(
    label: string,
    options?: { readonly id?: number; readonly ordered?: boolean; readonly negotiated?: boolean },
  ): WebRtcDataChannel {
    const channel = new FakeDataChannel(label, options?.id ?? null, options?.ordered ?? true);
    this.channels.push(channel);
    // Set local description (offer) with the DTLS fingerprint on first channel creation.
    if (!this.localDescription) {
      this.localDescription = { type: "offer", sdp: this.offerSdp };
    }
    return channel;
  }

  async setLocalDescription(description: {
    readonly type: string;
    readonly sdp: string;
  }): Promise<void> {
    this.localDescription = { type: "offer" as const, sdp: description.sdp };
  }

  async setRemoteDescription(description: {
    readonly type: "answer";
    readonly sdp: string;
  }): Promise<void> {
    this.remoteDescription = { type: "answer", sdp: description.sdp };
  }

  async addIceCandidate(candidate: { readonly candidate: string }): Promise<void> {
    this.addedCandidates.push({ candidate: candidate.candidate });
  }

  close(): void {
    this.closed = true;
    this.iceConnectionState = "closed";
    this.connectionState = "closed";
  }

  /** Test helper: emit a local ICE candidate. */
  emitCandidate(candidate: string, sdpMid = "0", sdpMLineIndex = 0): void {
    this.onicecandidate?.({ candidate: { candidate, sdpMid, sdpMLineIndex } });
  }

  /** Test helper: emit ICE gathering null (end of candidates). */
  emitIceEnd(): void {
    this.onicecandidate?.({ candidate: null });
  }

  /** Test helper: simulate ICE + DTLS connection. */
  connect(): void {
    this.iceConnectionState = "connected";
    this.oniceconnectionstatechange?.();
    this.connectionState = "connected";
    this.onconnectionstatechange?.();
  }
}

class FakePeerFactory implements WebRtcPeerFactory {
  peers: FakePeerConnection[] = [];
  readonly offerSdp: string | undefined;

  constructor(offerSdp?: string) {
    this.offerSdp = offerSdp;
  }

  create(): WebRtcPeerConnection {
    const peer = new FakePeerConnection(this.offerSdp);
    this.peers.push(peer);
    return peer;
  }
}

// ---------------------------------------------------------------------------
// Helpers to build valid final proofs
// ---------------------------------------------------------------------------

function makeFinalProof(
  role: 1 | 2,
  opts: {
    readonly childAttemptId: Uint8Array;
    readonly transportEpoch: Uint8Array;
    readonly grantDigest: Uint8Array;
    readonly admissionSequence: bigint;
    readonly negotiationDigest: Uint8Array;
    readonly certificateId: Uint8Array;
    readonly certificateGeneration: bigint;
  },
): Uint8Array {
  return encodeRemoteEndpointFinalProofV1({
    role,
    transport: 1,
    childAttemptId: opts.childAttemptId,
    transportEpoch: opts.transportEpoch,
    admissionSequence: opts.admissionSequence,
    grantDigest: opts.grantDigest,
    negotiationDigest: opts.negotiationDigest,
    binding: bytes(96, 7), // same binding for both roles — agreement bytes must match
    proofJti: id16(role),
    certificateId: opts.certificateId,
    certificateGeneration: opts.certificateGeneration,
    signature: bytes(64, role),
  });
}

function makeAttemptInput(overrides?: Partial<RemoteWebAttemptInput>): RemoteWebAttemptInput {
  return {
    childAttemptId: id16(1),
    transportEpoch: id16(2),
    admissionSequence: 1n,
    grantDigest: bytes(32, 3),
    icePolicy: {
      turnServers: [
        { urls: ["turn:relay.example.com:3478"], username: "user", credential: "cred" },
      ],
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

function makeProbe(overrides?: Partial<RemoteWebCapabilityProbe>): RemoteWebCapabilityProbe {
  return {
    isSecureContext: () => true,
    hasRtcPeerConnection: () => true,
    hasNegotiatedDataChannels: () => true,
    lookupP256Handle: async () => ({ status: "present" as const, handle: {} }),
    lookupEphemeralX25519: async () => true,
    ...overrides,
  };
}

function makeAdapter(
  factory: WebRtcPeerFactory,
  events: RemoteWebEvent[],
  opts?: { readonly random?: () => Uint8Array },
): RemoteWebRtcAdapter {
  return new RemoteWebRtcAdapter({
    peerFactory: factory,
    emit: (event) => events.push(event),
    random: opts?.random,
  });
}

// ===========================================================================
// remote_web_capability_gate
// ===========================================================================

describe("remote_web_capability_gate", () => {
  it("passes with secure context, RTCPeerConnection, data channels, and durable P-256", async () => {
    const result = await remoteWebCapabilityGate({
      probe: makeProbe(),
      capability: "direct_allowed",
      childAttemptId: id16(1),
    });
    expect(result.status).toBe("ok");
  });

  it("fails with secure_context_required before any resource allocation", async () => {
    const probe = makeProbe({ isSecureContext: () => false });
    const lookupP256 = vi.fn();
    const result = await remoteWebCapabilityGate({
      probe: { ...probe, lookupP256Handle: lookupP256 },
      capability: "direct_allowed",
      childAttemptId: id16(1),
    });
    expect(result.status).toBe("secure_context_required");
    expect(lookupP256).not.toHaveBeenCalled();
  });

  it("fails with browser_upgrade_required when RTCPeerConnection is missing", async () => {
    const probe = makeProbe({ hasRtcPeerConnection: () => false });
    const result = await remoteWebCapabilityGate({
      probe,
      capability: "direct_allowed",
      childAttemptId: id16(1),
    });
    expect(result.status).toBe("browser_upgrade_required");
  });

  it("fails with browser_upgrade_required when negotiated data channels are missing", async () => {
    const probe = makeProbe({ hasNegotiatedDataChannels: () => false });
    const result = await remoteWebCapabilityGate({
      probe,
      capability: "direct_allowed",
      childAttemptId: id16(1),
    });
    expect(result.status).toBe("browser_upgrade_required");
  });

  it("fails with relay_unavailable when capability is unavailable (no peer created)", async () => {
    const lookupP256 = vi.fn(async () => ({ status: "present" as const, handle: {} }));
    const result = await remoteWebCapabilityGate({
      probe: makeProbe({ lookupP256Handle: lookupP256 }),
      capability: "unavailable",
      childAttemptId: id16(1),
    });
    expect(result.status).toBe("relay_unavailable");
  });

  it("fails with reenrollment_required when P-256 handle is missing", async () => {
    const probe = makeProbe({ lookupP256Handle: async () => ({ status: "missing" as const }) });
    const result = await remoteWebCapabilityGate({
      probe,
      capability: "direct_allowed",
      childAttemptId: id16(1),
    });
    expect(result.status).toBe("reenrollment_required");
  });

  it("fails with reenrollment_required when P-256 handle is corrupt", async () => {
    const probe = makeProbe({ lookupP256Handle: async () => ({ status: "corrupt" as const }) });
    const result = await remoteWebCapabilityGate({
      probe,
      capability: "direct_allowed",
      childAttemptId: id16(1),
    });
    expect(result.status).toBe("reenrollment_required");
  });

  it("fails with remote_crypto_unsupported when ephemeral X25519 is missing for the child", async () => {
    const probe = makeProbe({ lookupEphemeralX25519: async () => false });
    const result = await remoteWebCapabilityGate({
      probe,
      capability: "direct_allowed",
      childAttemptId: id16(1),
    });
    expect(result.status).toBe("remote_crypto_unsupported");
  });

  it("never probes or accepts WebCrypto X25519 as durable identity", async () => {
    const lookupP256 = vi.fn(async () => ({ status: "present" as const, handle: {} }));
    const lookupX25519 = vi.fn(async () => true);
    await remoteWebCapabilityGate({
      probe: makeProbe({ lookupP256Handle: lookupP256, lookupEphemeralX25519: lookupX25519 }),
      capability: "direct_allowed",
      childAttemptId: id16(1),
    });
    // P-256 is the durable identity check; X25519 is the per-child ephemeral check.
    expect(lookupP256).toHaveBeenCalledTimes(1);
    expect(lookupX25519).toHaveBeenCalledTimes(1);
  });
});

// ===========================================================================
// remote_web_ice_consent_matrix
// ===========================================================================

describe("remote_web_ice_consent_matrix", () => {
  const relayOnlyPolicy = {
    turnServers: [{ urls: ["turn:relay.example.com:3478"], username: "u", credential: "c" }],
    transportPolicy: "relay" as const,
    policyDigest: bytes(32, 1),
  };
  const directPolicy = {
    turnServers: [{ urls: ["stun:stun.example.com:3478"], username: "u", credential: "c" }],
    transportPolicy: "direct" as const,
    policyDigest: bytes(32, 2),
  };

  it("direct_allowed permits normal signed ICE with policy all", () => {
    const config = remoteWebIceConfiguration("direct_allowed", directPolicy);
    expect(config).not.toBeNull();
    expect(config!.iceTransportPolicy).toBe("all");
    expect(config!.iceServers).toHaveLength(1);
  });

  it("relay_only configures only verified signed TURN URLs and iceTransportPolicy relay", () => {
    const config = remoteWebIceConfiguration("relay_only", relayOnlyPolicy);
    expect(config).not.toBeNull();
    expect(config!.iceTransportPolicy).toBe("relay");
    expect(config!.iceServers[0]!.urls).toEqual(["turn:relay.example.com:3478"]);
  });

  it("relay_only rejects a policy that is not relay", () => {
    const config = remoteWebIceConfiguration("relay_only", directPolicy);
    expect(config).toBeNull();
  });

  it("unavailable creates no peer configuration", () => {
    const config = remoteWebIceConfiguration("unavailable", relayOnlyPolicy);
    expect(config).toBeNull();
  });

  it("never merges browser defaults or public STUN — only signed servers", () => {
    const config = remoteWebIceConfiguration("direct_allowed", directPolicy);
    expect(config!.iceServers).toHaveLength(1);
    expect(config!.iceServers[0]!.urls).toEqual(["stun:stun.example.com:3478"]);
  });

  it("suppresses non-relay local candidates in relay_only", () => {
    expect(remoteWebAllowLocalCandidate("relay_only", "host")).toBe(false);
    expect(remoteWebAllowLocalCandidate("relay_only", "srflx")).toBe(false);
    expect(remoteWebAllowLocalCandidate("relay_only", "prflx")).toBe(false);
    expect(remoteWebAllowLocalCandidate("relay_only", "relay")).toBe(true);
  });

  it("allows all local candidates in direct_allowed", () => {
    for (const typ of ["host", "srflx", "prflx", "relay"] as const) {
      expect(remoteWebAllowLocalCandidate("direct_allowed", typ)).toBe(true);
    }
  });

  it("rejects non-relay remote candidates in relay_only", () => {
    expect(remoteWebAllowRemoteCandidate("relay_only", "host")).toBe(false);
    expect(remoteWebAllowRemoteCandidate("relay_only", "srflx")).toBe(false);
    expect(remoteWebAllowRemoteCandidate("relay_only", "relay")).toBe(true);
  });

  it("parses candidate type from candidate strings", () => {
    expect(parseCandidateType("candidate:1 1 udp 1 1.2.3.4 5 typ host")).toBe("host");
    expect(parseCandidateType("candidate:2 1 udp 1 1.2.3.4 5 typ srflx")).toBe("srflx");
    expect(parseCandidateType("candidate:3 1 udp 1 1.2.3.4 5 typ relay")).toBe("relay");
    expect(parseCandidateType("candidate:4 1 udp 1 1.2.3.4 5 typ prflx")).toBe("prflx");
  });

  it("does not overstate browser-internal guarantee — only that no non-relay candidate leaves/enters/becomes usable", () => {
    // The function controls publication/acceptance/nomination, not internal gathering.
    expect(remoteWebAllowLocalCandidate("relay_only", "host")).toBe(false);
    expect(remoteWebAllowRemoteCandidate("relay_only", "host")).toBe(false);
  });
});

// ===========================================================================
// remote_web_passive_adapter_contract
// ===========================================================================

describe("remote_web_passive_adapter_contract", () => {
  it("accepts explicit establish/send/close commands and emits typed events", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    expect(events.some((e) => e.kind === "capability")).toBe(true);
    expect(events.some((e) => e.kind === "health")).toBe(true);
    expect(events.some((e) => e.kind === "signaling")).toBe(true);
    adapter.dispatch({ kind: "send", lane: "control", bytes: bytes(10, 1) });
    adapter.dispatch({ kind: "close", reason: "cancel" });
    expect(events.some((e) => e.kind === "close")).toBe(true);
  });

  it("owns no retry/fallback/reattach/attachment policy — only passive commands", () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    // The adapter exposes only dispatch/ingestSignaling/close — no retry/fallback methods.
    expect(typeof adapter.dispatch).toBe("function");
    expect(typeof adapter.ingestSignaling).toBe("function");
    expect(typeof adapter.close).toBe("function");
    expect((adapter as unknown as Record<string, unknown>).retry).toBeUndefined();
    expect((adapter as unknown as Record<string, unknown>).fallback).toBeUndefined();
    expect((adapter as unknown as Record<string, unknown>).reattach).toBeUndefined();
  });

  it("emits exact typed events only", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    const validKinds = new Set<RemoteWebEvent["kind"]>([
      "capability",
      "signaling",
      "candidate",
      "ice_complete",
      "health",
      "lane_ready",
      "lane_data",
      "backpressure",
      "close",
    ]);
    for (const event of events) {
      expect(validKinds.has(event.kind)).toBe(true);
    }
  });
});

// ===========================================================================
// remote_web_webrtc_daemon_interop (final-proof gate)
// ===========================================================================

describe("remote_web_webrtc_daemon_interop", () => {
  it("exposes lanes only after both exact stored final-proof events and ready acknowledgements", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events, {
      random: () => id16(9),
    });
    const input = makeAttemptInput();
    await adapter.dispatch({ kind: "establish", input });

    const peer = factory.peers[0]!;
    // Open all channels.
    for (const channel of peer.channels) channel.open();
    // Simulate DTLS connection.
    peer.connect();

    // No lanes yet — proofs not received.
    expect(events.find((e) => e.kind === "lane_ready")).toBeUndefined();

    // Compute the negotiation digest from the offer/answer/fingerprint.
    const offerSdp = new TextEncoder().encode(peer.localDescription!.sdp);
    const answerSdp = new TextEncoder().encode(
      "a=fingerprint:sha-256 01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20\r\n",
    );
    const fingerprint = extractDtlsFingerprint(peer.localDescription!.sdp)!;
    const negotiationDigest = remoteWebNegotiationDigest(offerSdp, answerSdp, fingerprint);

    const clientProof = makeFinalProof(1, {
      childAttemptId: input.childAttemptId,
      transportEpoch: input.transportEpoch,
      grantDigest: input.grantDigest,
      admissionSequence: input.admissionSequence,
      negotiationDigest,
      certificateId: input.identity.certificateId,
      certificateGeneration: input.identity.certificateGeneration,
    });
    const daemonProof = makeFinalProof(2, {
      childAttemptId: input.childAttemptId,
      transportEpoch: input.transportEpoch,
      grantDigest: input.grantDigest,
      admissionSequence: input.admissionSequence,
      negotiationDigest,
      certificateId: input.identity.certificateId,
      certificateGeneration: input.identity.certificateGeneration,
    });

    // Feed answer first so the adapter has the answer SDP for proof verification.
    adapter.ingestSignaling({ type: "answer", sdp: answerSdp, descriptionId: id16(7) });

    // Feed both proofs.
    adapter.ingestSignaling({ type: "client_final_proof", proof: clientProof });
    adapter.ingestSignaling({ type: "daemon_final_proof", proof: daemonProof });

    // Now lanes should be open.
    const laneReady = events.find((e) => e.kind === "lane_ready");
    expect(laneReady).toBeDefined();
    expect(
      laneReady!.kind === "lane_ready" && laneReady!.kind === "lane_ready" && laneReady!.lanes,
    ).toEqual([...REMOTE_LANES]);
  });

  it("does not open lanes on a transcript digest or DTLS-connected callback alone", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    const peer = factory.peers[0]!;
    for (const channel of peer.channels) channel.open();
    peer.connect();
    // No proofs — no lanes.
    expect(events.find((e) => e.kind === "lane_ready")).toBeUndefined();
  });

  it("rejects proof with mismatched child/epoch/sequence", () => {
    const offerSdp = bytes(10, 1);
    const answerSdp = bytes(10, 2);
    const fingerprint = bytes(32, 3);
    const negotiationDigest = remoteWebNegotiationDigest(offerSdp, answerSdp, fingerprint);
    const childAttemptId = id16(1);
    const transportEpoch = id16(2);
    const grantDigest = bytes(32, 3);
    const admissionSequence = 1n;
    const certId = id16(6);
    const certGen = 1n;

    const clientProof = makeFinalProof(1, {
      childAttemptId,
      transportEpoch,
      grantDigest,
      admissionSequence,
      negotiationDigest,
      certificateId: certId,
      certificateGeneration: certGen,
    });
    const daemonProof = makeFinalProof(2, {
      childAttemptId: id16(99), // wrong child
      transportEpoch,
      grantDigest,
      admissionSequence,
      negotiationDigest,
      certificateId: certId,
      certificateGeneration: certGen,
    });

    const result = remoteWebVerifyProofs({
      clientProof,
      daemonProof,
      expectedChildAttemptId: childAttemptId,
      expectedTransportEpoch: transportEpoch,
      expectedOfferSdp: offerSdp,
      expectedAnswerSdp: answerSdp,
      expectedDtlsFingerprint: fingerprint,
      grantDigest,
      admissionSequence,
    });
    expect(result.bothVerified).toBe(false);
  });

  it("rejects proof with mismatched negotiation digest (fingerprint/offer/answer)", () => {
    const offerSdp = bytes(10, 1);
    const answerSdp = bytes(10, 2);
    const fingerprint = bytes(32, 3);
    const wrongDigest = bytes(32, 99);
    const childAttemptId = id16(1);
    const transportEpoch = id16(2);
    const grantDigest = bytes(32, 3);
    const admissionSequence = 1n;
    const certId = id16(6);
    const certGen = 1n;

    const clientProof = makeFinalProof(1, {
      childAttemptId,
      transportEpoch,
      grantDigest,
      admissionSequence,
      negotiationDigest: wrongDigest,
      certificateId: certId,
      certificateGeneration: certGen,
    });
    const daemonProof = makeFinalProof(2, {
      childAttemptId,
      transportEpoch,
      grantDigest,
      admissionSequence,
      negotiationDigest: wrongDigest,
      certificateId: certId,
      certificateGeneration: certGen,
    });

    const result = remoteWebVerifyProofs({
      clientProof,
      daemonProof,
      expectedChildAttemptId: childAttemptId,
      expectedTransportEpoch: transportEpoch,
      expectedOfferSdp: offerSdp,
      expectedAnswerSdp: answerSdp,
      expectedDtlsFingerprint: fingerprint,
      grantDigest,
      admissionSequence,
    });
    expect(result.bothVerified).toBe(false);
  });
});

// ===========================================================================
// remote_web_signaling_replay
// ===========================================================================

describe("remote_web_signaling_replay", () => {
  it("handles candidate reorder and duplicate without error", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    const candidate = {
      candidateId: id16(10),
      sdpMid: "0",
      sdpMLineIndex: 0,
      candidate: "candidate:1 1 udp 1 1.2.3.4 5 typ relay",
    };
    // Reorder: send same candidate twice.
    adapter.ingestSignaling({ type: "remote_candidate", candidate });
    adapter.ingestSignaling({ type: "remote_candidate", candidate });
    const peer = factory.peers[0]!;
    expect(peer.addedCandidates).toHaveLength(1); // duplicate rejected
  });

  it("handles late events gracefully (after close)", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    adapter.close("cancel");
    // Late signaling event should be ignored.
    adapter.ingestSignaling({
      type: "remote_candidate",
      candidate: {
        candidateId: id16(11),
        sdpMid: "0",
        sdpMLineIndex: 0,
        candidate: "candidate:1 1 udp 1 1.2.3.4 5 typ relay",
      },
    });
    const peer = factory.peers[0]!;
    expect(peer.addedCandidates).toHaveLength(0);
  });
});

// ===========================================================================
// remote_web_attempt_generation_cleanup
// ===========================================================================

describe("remote_web_attempt_generation_cleanup", () => {
  it("navigation/unmount closes the peer and channels deterministically", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    const peer = factory.peers[0]!;
    adapter.close("navigation");
    expect(peer.closed).toBe(true);
    for (const channel of peer.channels) {
      expect(channel.readyState).toBe("closed");
    }
    expect(adapter.isActive).toBe(false);
  });

  it("replacement increments generation and invalidates prior attempt", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput({ generation: 1 }) });
    const gen1 = adapter.currentGeneration;
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput({ generation: 2 }) });
    expect(adapter.currentGeneration).toBeGreaterThan(gen1);
    // First peer should be closed.
    expect(factory.peers[0]!.closed).toBe(true);
  });

  it("late promise from a stale generation does not mutate state", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    const peer = factory.peers[0]!;
    // Replace the attempt.
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput({ generation: 2 }) });
    // Simulate a late channel open from the old peer.
    const oldChannel = peer.channels[0]!;
    oldChannel.open();
    // No lane_ready should be emitted from the stale attempt.
    expect(events.find((e) => e.kind === "lane_ready")).toBeUndefined();
  });

  it("cancel deadline closes without stale mutation or leaks", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    adapter.close("deadline");
    expect(events.filter((e) => e.kind === "close")).toHaveLength(1);
    // Double close is a no-op.
    adapter.close("cancel");
    expect(events.filter((e) => e.kind === "close")).toHaveLength(1);
  });
});

// ===========================================================================
// remote_web_channel_backpressure
// ===========================================================================

describe("remote_web_channel_backpressure", () => {
  it("maps three lanes to channel IDs 0/2/4", () => {
    expect(REMOTE_WEBRTC_CHANNEL_IDS.control).toBe(0);
    expect(REMOTE_WEBRTC_CHANNEL_IDS.interactive).toBe(2);
    expect(REMOTE_WEBRTC_CHANNEL_IDS.bulk).toBe(4);
  });

  it("fragments and reassembles payloads across channels", () => {
    const frameId = id16(1);
    const payload = bytes(REMOTE_WEBRTC_FRAGMENT_MAX_PAYLOAD_BYTES * 2 + 100, 7);
    const fragments = remoteWebRtcFragmentPayload("bulk", payload, frameId);
    expect(fragments.length).toBeGreaterThan(1);
    expect(fragments.length).toBeLessThanOrEqual(REMOTE_WEBRTC_MAX_FRAGMENT_COUNT);
    const reassembly = new RemoteWebRtcReassembly();
    let reassembled: Uint8Array | null = null;
    for (const fragment of fragments) {
      const encoded = encodeRemoteWebRtcFragment(fragment);
      const decoded = decodeRemoteWebRtcFragment(encoded);
      reassembled = reassembly.ingest(decoded);
    }
    expect(reassembled).not.toBeNull();
    expect(Buffer.from(reassembled!).equals(Buffer.from(payload))).toBe(true);
  });

  it("round-trips a single-fragment payload", () => {
    const frameId = id16(2);
    const payload = bytes(100, 5);
    const fragments = remoteWebRtcFragmentPayload("control", payload, frameId);
    expect(fragments).toHaveLength(1);
    const encoded = encodeRemoteWebRtcFragment(fragments[0]!);
    const decoded = decodeRemoteWebRtcFragment(encoded);
    expect(decoded.lane).toBe("control");
    expect(decoded.end).toBe(true);
    expect(decoded.fragmentCount).toBe(1);
  });

  it("detects duplicate fragments without error", () => {
    const frameId = id16(3);
    const fragments = remoteWebRtcFragmentPayload("interactive", bytes(200, 9), frameId);
    const reassembly = new RemoteWebRtcReassembly();
    const encoded = encodeRemoteWebRtcFragment(fragments[0]!);
    reassembly.ingest(decodeRemoteWebRtcFragment(encoded));
    // Duplicate — should return null, not throw.
    expect(reassembly.ingest(decodeRemoteWebRtcFragment(encoded))).toBeNull();
  });

  it("detects fragment conflict (mismatched count)", () => {
    const frameId = id16(4);
    // Create a 2-fragment frame so the first fragment doesn't complete immediately.
    const fragments = remoteWebRtcFragmentPayload(
      "control",
      bytes(REMOTE_WEBRTC_FRAGMENT_MAX_PAYLOAD_BYTES + 100, 1),
      frameId,
    );
    expect(fragments.length).toBeGreaterThanOrEqual(2);
    const reassembly = new RemoteWebRtcReassembly();
    reassembly.ingest(fragments[0]!);
    // Feed a second fragment with a different count.
    const conflicting: RemoteWebRtcFragment = {
      lane: "control",
      frameId,
      fragmentIndex: 1,
      fragmentCount: 3,
      end: false,
      bytes: bytes(10, 2),
    };
    expect(() => reassembly.ingest(conflicting)).toThrow("fragment_conflict");
  });

  it("enforces buffered-amount backpressure thresholds", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    const input = makeAttemptInput();
    await adapter.dispatch({ kind: "establish", input });
    const peer = factory.peers[0]!;
    for (const channel of peer.channels) channel.open();
    peer.connect();

    // Open lanes with valid proofs.
    const offerSdp = new TextEncoder().encode(peer.localDescription!.sdp);
    const answerSdp = new TextEncoder().encode(
      "a=fingerprint:sha-256 01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20\r\n",
    );
    const fingerprint = extractDtlsFingerprint(peer.localDescription!.sdp)!;
    const negotiationDigest = remoteWebNegotiationDigest(offerSdp, answerSdp, fingerprint);
    const clientProof = makeFinalProof(1, {
      childAttemptId: input.childAttemptId,
      transportEpoch: input.transportEpoch,
      grantDigest: input.grantDigest,
      admissionSequence: input.admissionSequence,
      negotiationDigest,
      certificateId: input.identity.certificateId,
      certificateGeneration: input.identity.certificateGeneration,
    });
    const daemonProof = makeFinalProof(2, {
      childAttemptId: input.childAttemptId,
      transportEpoch: input.transportEpoch,
      grantDigest: input.grantDigest,
      admissionSequence: input.admissionSequence,
      negotiationDigest,
      certificateId: input.identity.certificateId,
      certificateGeneration: input.identity.certificateGeneration,
    });
    adapter.ingestSignaling({ type: "answer", sdp: answerSdp, descriptionId: id16(7) });
    adapter.ingestSignaling({ type: "client_final_proof", proof: clientProof });
    adapter.ingestSignaling({ type: "daemon_final_proof", proof: daemonProof });

    // Send a large payload on bulk to trigger backpressure.
    const bulkChannel = peer.channels.find((c) => c.id === REMOTE_WEBRTC_CHANNEL_IDS.bulk)!;
    bulkChannel.bufferedAmount = REMOTE_WEBRTC_BUFFERED_AMOUNT_HIGH_THRESHOLD.bulk + 1;
    adapter.dispatch({ kind: "send", lane: "bulk", bytes: bytes(100, 1) });
    expect(events.some((e) => e.kind === "backpressure" && e.lane === "bulk")).toBe(true);
  });

  it("final-proof gate blocks sends before lanes are open", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput() });
    const peer = factory.peers[0]!;
    for (const channel of peer.channels) channel.open();
    // No proofs — send should be a no-op.
    adapter.dispatch({ kind: "send", lane: "control", bytes: bytes(10, 1) });
    const controlChannel = peer.channels.find((c) => c.id === REMOTE_WEBRTC_CHANNEL_IDS.control)!;
    expect(controlChannel.sent).toHaveLength(0);
  });
});

// ===========================================================================
// Safe UX / redaction
// ===========================================================================

describe("remote_web_safe_ux_redaction", () => {
  it("maps capability status to safe UX state without network/identity material", () => {
    expect(remoteWebSafeUxState({ status: "ok", capability: "direct_allowed" })).toBe("active");
    expect(
      remoteWebSafeUxState({ status: "browser_upgrade_required", capability: "direct_allowed" }),
    ).toBe("browser_upgrade_required");
    expect(
      remoteWebSafeUxState({ status: "reenrollment_required", capability: "direct_allowed" }),
    ).toBe("reenrollment_required");
    expect(remoteWebSafeUxState({ status: "relay_unavailable", capability: "unavailable" })).toBe(
      "relay_unavailable",
    );
    expect(remoteWebSafeUxState({ status: "policy_denied", capability: "direct_allowed" })).toBe(
      "policy_denied",
    );
    expect(
      remoteWebSafeUxState({ status: "secure_context_required", capability: "direct_allowed" }),
    ).toBe("secure_context_required");
    expect(
      remoteWebSafeUxState({ status: "remote_crypto_unsupported", capability: "direct_allowed" }),
    ).toBe("remote_crypto_unsupported");
  });

  it("redacted diagnostics contain no candidates, addresses, credentials, or fingerprints", () => {
    for (const state of [
      "active",
      "browser_upgrade_required",
      "reenrollment_required",
      "relay_unavailable",
      "policy_denied",
      "secure_context_required",
      "remote_crypto_unsupported",
      "closed",
    ] as const) {
      const diag = remoteWebRedactedDiagnostic(state);
      expect(diag).not.toMatch(/\d+\.\d+\.\d+\.\d+/); // no addresses
      expect(diag).not.toMatch(/turn:/); // no TURN URLs
      expect(diag).not.toMatch(/sha-256/); // no fingerprints
      expect(diag).not.toMatch(/password|secret|token/i); // no credentials
    }
  });
});

// ===========================================================================
// DTLS fingerprint extraction
// ===========================================================================

describe("extractDtlsFingerprint", () => {
  it("extracts a 32-byte fingerprint from SDP", () => {
    const sdp =
      "a=fingerprint:sha-256 01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20\r\n";
    const fp = extractDtlsFingerprint(sdp);
    expect(fp).not.toBeNull();
    expect(fp).toHaveLength(32);
    expect(fp![0]).toBe(0x01);
    expect(fp![31]).toBe(0x20);
  });

  it("returns null when no fingerprint is present", () => {
    expect(extractDtlsFingerprint("no fingerprint here\r\n")).toBeNull();
  });
});

// ===========================================================================
// Relay-only local candidate suppression in adapter
// ===========================================================================

describe("relay_only adapter candidate suppression", () => {
  it("never publishes a non-relay local candidate to signaling", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({
      kind: "establish",
      input: makeAttemptInput({
        capability: "relay_only",
        icePolicy: {
          turnServers: [{ urls: ["turn:relay.example.com:3478"], username: "u", credential: "c" }],
          transportPolicy: "relay",
          policyDigest: bytes(32, 1),
        },
      }),
    });
    const peer = factory.peers[0]!;
    // Emit a host candidate — should be suppressed.
    peer.emitCandidate("candidate:1 1 udp 1 192.168.1.1 5 typ host");
    expect(events.filter((e) => e.kind === "candidate")).toHaveLength(0);
    // Emit a relay candidate — should be published.
    peer.emitCandidate("candidate:2 1 udp 1 1.2.3.4 5 typ relay");
    expect(events.filter((e) => e.kind === "candidate")).toHaveLength(1);
  });

  it("rejects non-relay remote candidates in relay_only", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({
      kind: "establish",
      input: makeAttemptInput({
        capability: "relay_only",
        icePolicy: {
          turnServers: [{ urls: ["turn:relay.example.com:3478"], username: "u", credential: "c" }],
          transportPolicy: "relay",
          policyDigest: bytes(32, 1),
        },
      }),
    });
    const peer = factory.peers[0]!;
    // Host remote candidate — rejected.
    adapter.ingestSignaling({
      type: "remote_candidate",
      candidate: {
        candidateId: id16(1),
        sdpMid: "0",
        sdpMLineIndex: 0,
        candidate: "candidate:1 1 udp 1 192.168.1.1 5 typ host",
      },
    });
    expect(peer.addedCandidates).toHaveLength(0);
    // Relay remote candidate — accepted.
    adapter.ingestSignaling({
      type: "remote_candidate",
      candidate: {
        candidateId: id16(2),
        sdpMid: "0",
        sdpMLineIndex: 0,
        candidate: "candidate:2 1 udp 1 1.2.3.4 5 typ relay",
      },
    });
    expect(peer.addedCandidates).toHaveLength(1);
  });

  it("unavailable capability creates no peer", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({
      kind: "establish",
      input: makeAttemptInput({ capability: "unavailable" }),
    });
    expect(factory.peers).toHaveLength(0);
    expect(
      events.some((e) => e.kind === "capability" && e.result.status === "relay_unavailable"),
    ).toBe(true);
  });

  it("ipConsent denied blocks establishment with policy_denied", async () => {
    const factory = new FakePeerFactory();
    const events: RemoteWebEvent[] = [];
    const adapter = makeAdapter(factory, events);
    await adapter.dispatch({ kind: "establish", input: makeAttemptInput({ ipConsent: "denied" }) });
    expect(factory.peers).toHaveLength(0);
    expect(events.some((e) => e.kind === "capability" && e.result.status === "policy_denied")).toBe(
      true,
    );
  });
});
