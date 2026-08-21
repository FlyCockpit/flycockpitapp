/**
 * Passive RemoteWebRtcAdapter — the native WebRTC data-channel endpoint.
 *
 * @see prompts/flycockpitapp/ready/remote-webrtc-native-client.md
 *
 * The adapter is strictly passive. It accepts one already-authorized child
 * plan, exact signed ICE servers, signed IP-consent tri-state, grant/proofs/
 * tuple, and generation. It emits typed signaling/candidate/channel/health/
 * lifecycle events and accepts explicit send/close commands. It never selects
 * fallback, retries, creates a second child, reattaches, or mutates logical
 * attachment state. Selection, retry, fallback, reattach, and continuity are
 * external responsibilities.
 *
 * Data-channel IDs are the exact negotiated 0/2/4. Daemon identity and the
 * final DTLS proof are validated before the lane writer is exposed. Durable
 * P-256 comes from the identity platform adapter; per-child X25519 belongs
 * only to the shared Rust native Noise binding used by fallback. No camera,
 * microphone, track, stream, or media declaration is added.
 */
import {
  decodeRemoteEndpointFinalProofV1,
  REMOTE_LANE_IDS,
  REMOTE_LANE_MAX_PAYLOAD_BYTES,
  type RemoteEndpointFinalProofV1,
  type RemoteLane,
  remoteEndpointFinalProofAgreementBytes,
  remoteIdentitySha256Sync,
} from "@flycockpit/cockpit-protocol";

// ---------------------------------------------------------------------------
// Channel IDs — exact negotiated data-channel IDs 0/2/4.
// ---------------------------------------------------------------------------

/**
 * The three negotiated SCTP data-channel IDs. Channel 0 is control, channel 2
 * is interactive, and channel 4 is bulk. These are the exact IDs used on the
 * wire and must not be reordered or renumbered.
 */
export const REMOTE_WEBRTC_CHANNEL_IDS = {
  control: 0,
  interactive: 2,
  bulk: 4,
} as const;

export type RemoteWebRtcChannelId =
  (typeof REMOTE_WEBRTC_CHANNEL_IDS)[keyof typeof REMOTE_WEBRTC_CHANNEL_IDS];

export const REMOTE_WEBRTC_LANE_CHANNEL: Readonly<Record<RemoteLane, RemoteWebRtcChannelId>> = {
  control: 0,
  interactive: 2,
  bulk: 4,
};

// ---------------------------------------------------------------------------
// ICE / TURN / consent policy types.
// ---------------------------------------------------------------------------

/**
 * IP-consent tri-state, signed by the device-relationship authority. The
 * adapter never interprets consent semantics beyond matching the policy; it
 * does not select fallback or require direct consent for relay-only.
 */
export type RemoteIpConsentState = "direct_allowed" | "relay_only" | "unavailable";

export interface RemoteSignedIpConsent {
  readonly state: RemoteIpConsentState;
  /** Opaque signed consent blob from the authority; never decoded by the adapter. */
  readonly signedBytes: Uint8Array;
}

/**
 * A single ICE server with its attached signature. The adapter verifies only
 * that the signature is present and non-empty; cryptographic verification is
 * owned by the signaling gateway that produced the signed structure.
 */
export interface RemoteSignedIceServer {
  readonly urls: readonly string[];
  readonly username?: string;
  readonly credential?: string;
  /** Opaque signature over the server tuple from the TURN credential issuer. */
  readonly signature: Uint8Array;
}

export type RemoteIceTransportPolicy = "all" | "relay";

/**
 * Resolved ICE/TURN policy for a single attempt. The adapter applies exactly
 * this policy; it applies no baked/default server.
 */
export interface RemoteIcePolicy {
  readonly consent: RemoteSignedIpConsent;
  readonly iceServers: readonly RemoteSignedIceServer[];
  readonly iceTransportPolicy: RemoteIceTransportPolicy;
  /** Whether the committed gather capability has been reached for direct_allowed. */
  readonly gatherCommitted: boolean;
}

// ---------------------------------------------------------------------------
// Adapter input — the already-authorized child plan.
// ---------------------------------------------------------------------------

export interface RemoteWebRtcGrantProofs {
  readonly grantDigest: Uint8Array;
  readonly clientProof: Uint8Array;
  readonly daemonProof: Uint8Array;
}

export interface RemoteWebRtcChildPlan {
  readonly childAttemptId: Uint8Array;
  readonly transportEpoch: Uint8Array;
  readonly admissionSequence: bigint;
  readonly generation: number;
  readonly selectedTupleId: number;
  readonly grantProofs: RemoteWebRtcGrantProofs;
  readonly icePolicy: RemoteIcePolicy;
}

// ---------------------------------------------------------------------------
// Events — typed, generation-bound.
// ---------------------------------------------------------------------------

export type RemoteWebRtcLifecycleEvent =
  | { readonly type: "background"; readonly generation: number }
  | { readonly type: "inactive"; readonly generation: number }
  | { readonly type: "os_kill"; readonly generation: number }
  | { readonly type: "network_change"; readonly generation: number }
  | { readonly type: "airplane_mode"; readonly generation: number }
  | { readonly type: "push_tap"; readonly generation: number }
  | { readonly type: "stale_callback"; readonly generation: number }
  | { readonly type: "turn_failure"; readonly generation: number; readonly reason: string }
  | {
      readonly type: "native_module_failure";
      readonly generation: number;
      readonly reason: string;
    }
  | { readonly type: "closed"; readonly generation: number; readonly reason: string };

export type RemoteWebRtcSignalingEvent =
  | { readonly type: "offer"; readonly generation: number; readonly sdp: string }
  | { readonly type: "answer"; readonly generation: number; readonly sdp: string }
  | {
      readonly type: "ice_candidate";
      readonly generation: number;
      readonly candidate: string;
      readonly sdpMid: string;
      readonly sdpMLineIndex: number;
    }
  | { readonly type: "ice_complete"; readonly generation: number };

export type RemoteWebRtcChannelEvent =
  | {
      readonly type: "channel_open";
      readonly generation: number;
      readonly channelId: RemoteWebRtcChannelId;
    }
  | {
      readonly type: "channel_close";
      readonly generation: number;
      readonly channelId: RemoteWebRtcChannelId;
    }
  | {
      readonly type: "channel_message";
      readonly generation: number;
      readonly channelId: RemoteWebRtcChannelId;
      readonly data: Uint8Array;
    }
  | {
      readonly type: "channel_buffered_amount_low";
      readonly generation: number;
      readonly channelId: RemoteWebRtcChannelId;
    };

export type RemoteWebRtcHealthEvent =
  | {
      readonly type: "health";
      readonly generation: number;
      readonly dtlsConnected: boolean;
      readonly bothProofsVerified: boolean;
    }
  | {
      readonly type: "ready";
      readonly generation: number;
      readonly role: 1 | 2;
      readonly finalProofSetDigest: Uint8Array;
    };

export type RemoteWebRtcEvent =
  | RemoteWebRtcLifecycleEvent
  | RemoteWebRtcSignalingEvent
  | RemoteWebRtcChannelEvent
  | RemoteWebRtcHealthEvent;

// ---------------------------------------------------------------------------
// Commands — explicit send/close. The adapter never auto-sends or auto-closes.
// ---------------------------------------------------------------------------

export type RemoteWebRtcCommand =
  | { readonly kind: "send"; readonly lane: RemoteLane; readonly data: Uint8Array }
  | { readonly kind: "close"; readonly reason: string };

// ---------------------------------------------------------------------------
// Lane writer — exposed only after both final proofs are verified.
// ---------------------------------------------------------------------------

export interface RemoteWebRtcLaneWriter {
  send(lane: RemoteLane, data: Uint8Array): void;
  close(reason: string): void;
}

// ---------------------------------------------------------------------------
// Native WebRTC module surface — the thin injected binding.
// ---------------------------------------------------------------------------

/**
 * Minimal native WebRTC peer-connection surface the adapter depends on. The
 * real binding is `react-native-webrtc`; tests inject a fake. The adapter
 * never adds media tracks, streams, or media permissions.
 */
export interface NativeRtcDataChannel {
  readonly id: number;
  readonly label: string;
  readonly readyState: "connecting" | "open" | "closing" | "closed";
  readonly bufferedAmount: number;
  send(data: ArrayBuffer | ArrayBufferView): void;
  close(): void;
  addEventListener(
    type: "open" | "close" | "message" | "bufferedamountlow",
    listener: (event?: unknown) => void,
  ): void;
  removeEventListener(
    type: "open" | "close" | "message" | "bufferedamountlow",
    listener: (event?: unknown) => void,
  ): void;
}

export interface NativeRtcIceCandidate {
  readonly candidate: string;
  readonly sdpMid: string | null;
  readonly sdpMLineIndex: number | null;
  readonly type?: string;
}

export interface NativeRtcPeerConnection {
  readonly iceConnectionState: string;
  readonly connectionState: string;
  createDataChannel(
    label: string,
    options?: { id?: number; ordered?: boolean },
  ): NativeRtcDataChannel;
  createOffer(): Promise<{ readonly type: string; readonly sdp: string }>;
  createAnswer(): Promise<{ readonly type: string; readonly sdp: string }>;
  setLocalDescription(description: { readonly type: string; readonly sdp: string }): Promise<void>;
  setRemoteDescription(description: { readonly type: string; readonly sdp: string }): Promise<void>;
  addIceCandidate(candidate: NativeRtcIceCandidate): Promise<void>;
  addEventListener(
    type: "icecandidate" | "iceconnectionstatechange" | "connectionstatechange" | "datachannel",
    listener: (event?: unknown) => void,
  ): void;
  removeEventListener(
    type: "icecandidate" | "iceconnectionstatechange" | "connectionstatechange" | "datachannel",
    listener: (event?: unknown) => void,
  ): void;
  close(): void;
}

export interface NativeRtcPeerConnectionConfig {
  readonly iceServers: readonly {
    readonly urls: readonly string[];
    readonly username?: string;
    readonly credential?: string;
  }[];
  readonly iceTransportPolicy: RemoteIceTransportPolicy;
}

export interface NativeRtcModule {
  RTCPeerConnection: new (config: NativeRtcPeerConnectionConfig) => NativeRtcPeerConnection;
}

// ---------------------------------------------------------------------------
// Errors — mapped into the shared closed taxonomy at this one boundary.
// ---------------------------------------------------------------------------

export type RemoteWebRtcClosedReason =
  | "policy"
  | "authentication"
  | "authorization"
  | "dependency"
  | "network"
  | "quota"
  | "protocol"
  | "user"
  | "revocation"
  | "timeout"
  | "internal";

export class RemoteWebRtcAdapterError extends Error {
  readonly closedReason: RemoteWebRtcClosedReason;
  constructor(closedReason: RemoteWebRtcClosedReason, message: string) {
    super(message);
    this.name = "RemoteWebRtcAdapterError";
    this.closedReason = closedReason;
  }
}

// ---------------------------------------------------------------------------
// Candidate classification — relay-only local suppression / remote rejection.
// ---------------------------------------------------------------------------

/**
 * Classifies a candidate string as relay or non-relay. A `relay` candidate
 * type indicates a TURN-relayed address. The adapter does not claim control
 * over native-library internal gathering; it only classifies the candidates
 * it observes at the adapter boundary.
 */
export function isRelayCandidate(candidate: string): boolean {
  return candidate.startsWith("candidate:") && / typ relay( |$)/.test(candidate);
}

export function isNonRelayCandidate(candidate: string): boolean {
  if (!candidate.startsWith("candidate:")) return true;
  return !/ typ relay( |$)/.test(candidate);
}

// ---------------------------------------------------------------------------
// Final-proof gate — both proofs must be independently verified.
// ---------------------------------------------------------------------------

const FINAL_PROOF_SET_DOMAIN = new TextEncoder().encode(
  "flycockpit.remote.endpoint-final-proof-set.v1\0",
);

function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return a.every((byte, i) => byte === b[i]);
}

/**
 * Verifies a single RemoteEndpointFinalProofV1 structure (decode + field
 * checks). Returns the decoded proof or throws on invalid encoding.
 */
export function verifyFinalProof(bytes: Uint8Array): RemoteEndpointFinalProofV1 {
  return decodeRemoteEndpointFinalProofV1(bytes);
}

/**
 * Computes the final-proof-set digest. Mirrors the signaling-store digest
 * domain. This is the value posted in the ready event.
 */
export function computeFinalProofSetDigest(
  clientProof: Uint8Array,
  daemonProof: Uint8Array,
): Uint8Array {
  const lengths = new Uint8Array(4);
  const view = new DataView(lengths.buffer);
  view.setUint16(0, clientProof.length);
  view.setUint16(2, daemonProof.length);
  return remoteIdentitySha256Sync(
    concatBytes(
      FINAL_PROOF_SET_DOMAIN,
      lengths.slice(0, 2),
      clientProof,
      lengths.slice(2),
      daemonProof,
    ),
  );
}

/**
 * Verifies both the client and daemon final proofs, checks role agreement
 * (client role 1, daemon role 2), and confirms the agreement bytes match.
 * Returns the final-proof-set digest. DTLS-connected alone or a digest alone
 * is insufficient — both exact stored final-proof events must be consumed and
 * independently verified before lanes are exposed.
 */
export function verifyBothFinalProofs(
  clientProofBytes: Uint8Array,
  daemonProofBytes: Uint8Array,
): {
  readonly clientProof: RemoteEndpointFinalProofV1;
  readonly daemonProof: RemoteEndpointFinalProofV1;
  readonly digest: Uint8Array;
} {
  const clientProof = verifyFinalProof(clientProofBytes);
  const daemonProof = verifyFinalProof(daemonProofBytes);
  if (clientProof.role !== 1)
    throw new RemoteWebRtcAdapterError("authentication", "client final proof role is not 1");
  if (daemonProof.role !== 2)
    throw new RemoteWebRtcAdapterError("authentication", "daemon final proof role is not 2");
  const clientAgreement = remoteEndpointFinalProofAgreementBytes(clientProof);
  const daemonAgreement = remoteEndpointFinalProofAgreementBytes(daemonProof);
  if (
    clientAgreement.length !== daemonAgreement.length ||
    !clientAgreement.every((b, i) => b === daemonAgreement[i])
  ) {
    throw new RemoteWebRtcAdapterError("authentication", "final proof agreement bytes disagree");
  }
  const digest = computeFinalProofSetDigest(clientProofBytes, daemonProofBytes);
  return { clientProof, daemonProof, digest };
}

// ---------------------------------------------------------------------------
// ICE policy resolution — maps consent state to adapter configuration.
// ---------------------------------------------------------------------------

/**
 * Resolves the ICE policy for the adapter from the signed consent state and
 * signed ICE servers. For `unavailable`, no peer is created (returns null).
 * For `direct_allowed`, normal ICE may be used only after the committed gather
 * capability. For `relay_only`, only verified signed TURN URLs plus
 * `iceTransportPolicy:"relay"`; no STUN/direct servers or direct consent.
 *
 * The adapter does not claim zero internal host resource creation — native
 * WebRTC internals may still gather implementation-private candidates.
 */
export function resolveIcePolicy(
  consent: RemoteSignedIpConsent,
  iceServers: readonly RemoteSignedIceServer[],
  gatherCommitted: boolean,
): RemoteIcePolicy | null {
  if (consent.state === "unavailable") return null;

  if (consent.state === "relay_only") {
    const turnServers = iceServers.filter((s) =>
      s.urls.every((u) => u.startsWith("turn:") || u.startsWith("turns:")),
    );
    if (turnServers.length === 0) {
      throw new RemoteWebRtcAdapterError(
        "dependency",
        "relay_only requires at least one signed TURN server",
      );
    }
    for (const s of turnServers) {
      if (s.signature.length === 0) {
        throw new RemoteWebRtcAdapterError("authorization", "TURN server signature missing");
      }
    }
    return {
      consent,
      iceServers: turnServers,
      iceTransportPolicy: "relay",
      gatherCommitted: false,
    };
  }

  // direct_allowed
  if (!gatherCommitted) {
    // Before the committed gather capability, do not create normal ICE.
    return null;
  }
  for (const s of iceServers) {
    if (s.signature.length === 0) {
      throw new RemoteWebRtcAdapterError("authorization", "ICE server signature missing");
    }
  }
  return {
    consent,
    iceServers,
    iceTransportPolicy: "all",
    gatherCommitted: true,
  };
}

// ---------------------------------------------------------------------------
// The passive adapter.
// ---------------------------------------------------------------------------

export interface RemoteWebRtcAdapterOptions {
  readonly plan: RemoteWebRtcChildPlan;
  readonly rtcModule: NativeRtcModule;
  readonly role: 1 | 2;
  readonly onEvent: (event: RemoteWebRtcEvent) => void;
}

interface ChannelState {
  readonly channel: NativeRtcDataChannel;
  readonly channelId: RemoteWebRtcChannelId;
  readonly lane: RemoteLane;
  open: boolean;
}

export class RemoteWebRtcAdapter {
  private readonly generation: number;
  private readonly role: 1 | 2;
  private readonly plan: RemoteWebRtcChildPlan;
  private readonly rtcModule: NativeRtcModule;
  private readonly onEvent: (event: RemoteWebRtcEvent) => void;
  private peer: NativeRtcPeerConnection | null = null;
  private readonly channels = new Map<RemoteWebRtcChannelId, ChannelState>();
  private bothProofsVerified = false;
  private dtlsConnected = false;
  private laneWriter: RemoteWebRtcLaneWriter | null = null;
  private closed = false;

  constructor(options: RemoteWebRtcAdapterOptions) {
    this.generation = options.plan.generation;
    this.role = options.role;
    this.plan = options.plan;
    this.rtcModule = options.rtcModule;
    this.onEvent = options.onEvent;
  }

  /**
   * Creates the peer connection according to the resolved ICE policy. For
   * `unavailable`, no peer is created. The adapter never applies a baked/
   * default server.
   */
  createPeer(): NativeRtcPeerConnection | null {
    if (this.closed) return null;
    const policy = resolveIcePolicy(
      this.plan.icePolicy.consent,
      this.plan.icePolicy.iceServers,
      this.plan.icePolicy.gatherCommitted,
    );
    if (policy === null) return null;
    const config: NativeRtcPeerConnectionConfig = {
      iceServers: policy.iceServers.map((s) => ({
        urls: s.urls,
        ...(s.username !== undefined ? { username: s.username } : {}),
        ...(s.credential !== undefined ? { credential: s.credential } : {}),
      })),
      iceTransportPolicy: policy.iceTransportPolicy,
    };
    this.peer = new this.rtcModule.RTCPeerConnection(config);
    this.wirePeerEvents(this.peer);
    this.createChannels(this.peer);
    return this.peer;
  }

  private wirePeerEvents(peer: NativeRtcPeerConnection): void {
    const onIceCandidate = (event?: unknown) => {
      if (this.closed) return;
      const candidate = extractCandidate(event);
      if (!candidate) return;
      // Relay-only: suppress/reject every non-relay local candidate before signaling.
      if (
        this.plan.icePolicy.consent.state === "relay_only" &&
        isNonRelayCandidate(candidate.candidate)
      ) {
        return;
      }
      this.onEvent({
        type: "ice_candidate",
        generation: this.generation,
        candidate: candidate.candidate,
        sdpMid: candidate.sdpMid ?? "0",
        sdpMLineIndex: candidate.sdpMLineIndex ?? 0,
      });
    };
    const onIceStateChange = () => {
      if (this.closed) return;
      if (peer.iceConnectionState === "completed" || peer.iceConnectionState === "connected") {
        this.onEvent({ type: "ice_complete", generation: this.generation });
      }
    };
    const onConnStateChange = () => {
      if (this.closed) return;
      if (peer.connectionState === "connected") {
        this.dtlsConnected = true;
        this.emitHealth();
      }
    };
    peer.addEventListener("icecandidate", onIceCandidate);
    peer.addEventListener("iceconnectionstatechange", onIceStateChange);
    peer.addEventListener("connectionstatechange", onConnStateChange);
  }

  private createChannels(peer: NativeRtcPeerConnection): void {
    for (const lane of ["control", "interactive", "bulk"] as const) {
      const channelId = REMOTE_WEBRTC_LANE_CHANNEL[lane];
      const channel = peer.createDataChannel(lane, { id: channelId, ordered: true });
      const state: ChannelState = { channel, channelId, lane, open: false };
      this.channels.set(channelId, state);
      channel.addEventListener("open", () => {
        if (this.closed) return;
        state.open = true;
        this.onEvent({ type: "channel_open", generation: this.generation, channelId });
      });
      channel.addEventListener("close", () => {
        if (this.closed) return;
        state.open = false;
        this.onEvent({ type: "channel_close", generation: this.generation, channelId });
      });
      channel.addEventListener("message", (event?: unknown) => {
        if (this.closed) return;
        const data = extractMessageData(event);
        this.onEvent({
          type: "channel_message",
          generation: this.generation,
          channelId,
          data,
        });
      });
      channel.addEventListener("bufferedamountlow", () => {
        if (this.closed) return;
        this.onEvent({
          type: "channel_buffered_amount_low",
          generation: this.generation,
          channelId,
        });
      });
    }
  }

  /**
   * Consumes both exact signaling-store RemoteEndpointFinalProofV1 events,
   * independently verifies daemon certificate/status and offer/answer/
   * fingerprints/child/epoch, posts role-specific ready, and exposes
   * dependency-owned lanes only after both proofs. DTLS-connected or a digest
   * alone is insufficient.
   */
  consumeFinalProofs(
    clientProofBytes: Uint8Array,
    daemonProofBytes: Uint8Array,
  ): RemoteWebRtcLaneWriter {
    if (this.closed) throw new RemoteWebRtcAdapterError("protocol", "adapter is closed");
    const { clientProof, daemonProof, digest } = verifyBothFinalProofs(
      clientProofBytes,
      daemonProofBytes,
    );
    // Verify child/epoch match the plan.
    if (!bytesEqual(clientProof.childAttemptId, this.plan.childAttemptId)) {
      throw new RemoteWebRtcAdapterError("authentication", "client proof child attempt mismatch");
    }
    if (!bytesEqual(daemonProof.childAttemptId, this.plan.childAttemptId)) {
      throw new RemoteWebRtcAdapterError("authentication", "daemon proof child attempt mismatch");
    }
    if (!bytesEqual(clientProof.transportEpoch, this.plan.transportEpoch)) {
      throw new RemoteWebRtcAdapterError("authentication", "client proof transport epoch mismatch");
    }
    if (!bytesEqual(daemonProof.transportEpoch, this.plan.transportEpoch)) {
      throw new RemoteWebRtcAdapterError("authentication", "daemon proof transport epoch mismatch");
    }
    this.bothProofsVerified = true;
    this.emitHealth();
    this.onEvent({
      type: "ready",
      generation: this.generation,
      role: this.role,
      finalProofSetDigest: digest,
    });
    this.laneWriter = this.createLaneWriter();
    return this.laneWriter;
  }

  private createLaneWriter(): RemoteWebRtcLaneWriter {
    return {
      send: (lane: RemoteLane, data: Uint8Array) => {
        if (this.closed) return;
        if (!this.bothProofsVerified) {
          throw new RemoteWebRtcAdapterError(
            "protocol",
            "lanes not exposed before both final proofs",
          );
        }
        const channelId = REMOTE_WEBRTC_LANE_CHANNEL[lane];
        const state = this.channels.get(channelId);
        if (!state?.open) {
          throw new RemoteWebRtcAdapterError("protocol", `lane ${lane} is not open`);
        }
        if (data.length > REMOTE_LANE_MAX_PAYLOAD_BYTES[lane]) {
          throw new RemoteWebRtcAdapterError("quota", `lane ${lane} payload exceeds cap`);
        }
        state.channel.send(data);
      },
      close: (reason: string) => {
        this.close("user", reason);
      },
    };
  }

  /**
   * Accepts a remote ICE candidate. For relay_only, rejects every non-relay
   * remote candidate. Accepts only a nominated relay pair.
   */
  acceptRemoteCandidate(candidate: NativeRtcIceCandidate): void {
    if (this.closed) return;
    if (!this.peer) return;
    if (
      this.plan.icePolicy.consent.state === "relay_only" &&
      isNonRelayCandidate(candidate.candidate)
    ) {
      throw new RemoteWebRtcAdapterError(
        "authorization",
        "relay_only rejects non-relay remote candidate",
      );
    }
    void this.peer.addIceCandidate(candidate).catch(() => {
      this.onEvent({
        type: "turn_failure",
        generation: this.generation,
        reason: "addIceCandidate failed",
      });
    });
  }

  /**
   * Accepts an explicit command. The adapter never auto-sends or auto-closes.
   */
  acceptCommand(command: RemoteWebRtcCommand): void {
    if (this.closed) return;
    if (command.kind === "close") {
      this.close("user", command.reason);
      return;
    }
    if (command.kind === "send") {
      if (!this.laneWriter) {
        throw new RemoteWebRtcAdapterError("protocol", "send before lanes exposed");
      }
      this.laneWriter.send(command.lane, command.data);
    }
  }

  /**
   * Emits a generation-bound lifecycle event. Stale callbacks and duplicates
   * cannot command policy or mutate a superseded generation.
   */
  emitLifecycle(event: RemoteWebRtcLifecycleEvent): void {
    if (this.closed) return;
    if (event.generation !== this.generation) return;
    this.onEvent(event);
  }

  private emitHealth(): void {
    this.onEvent({
      type: "health",
      generation: this.generation,
      dtlsConnected: this.dtlsConnected,
      bothProofsVerified: this.bothProofsVerified,
    });
  }

  /**
   * Closes the adapter on a terminal branch. Cleanup runs on every terminal
   * branch: channels closed, peer closed, writer invalidated.
   */
  close(closedReason: RemoteWebRtcClosedReason, detail: string): void {
    if (this.closed) return;
    this.closed = true;
    for (const [, state] of this.channels) {
      try {
        state.channel.close();
      } catch {
        /* noop */
      }
      state.open = false;
    }
    this.channels.clear();
    if (this.peer) {
      try {
        this.peer.close();
      } catch {
        /* noop */
      }
      this.peer = null;
    }
    this.laneWriter = null;
    this.onEvent({
      type: "closed",
      generation: this.generation,
      reason: `${closedReason}: ${detail}`,
    });
  }

  /** Whether both final proofs have been verified and lanes are exposed. */
  get isReady(): boolean {
    return this.bothProofsVerified;
  }

  /** Whether the adapter has been closed. */
  get isClosed(): boolean {
    return this.closed;
  }
}

// ---------------------------------------------------------------------------
// Helpers — extraction and comparison.
// ---------------------------------------------------------------------------

function extractCandidate(event: unknown): NativeRtcIceCandidate | null {
  if (!event || typeof event !== "object") return null;
  const candidate = (event as { candidate?: unknown }).candidate;
  if (!candidate || typeof candidate !== "object") return null;
  const c = candidate as {
    candidate?: string;
    sdpMid?: string | null;
    sdpMLineIndex?: number | null;
    type?: string;
  };
  if (typeof c.candidate !== "string") return null;
  return {
    candidate: c.candidate,
    sdpMid: c.sdpMid ?? null,
    sdpMLineIndex: c.sdpMLineIndex ?? null,
    ...(c.type !== undefined ? { type: c.type } : {}),
  };
}

function extractMessageData(event: unknown): Uint8Array {
  if (!event || typeof event !== "object") return new Uint8Array(0);
  const data = (event as { data?: unknown }).data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data))
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (typeof data === "string") return new TextEncoder().encode(data);
  return new Uint8Array(0);
}

// Re-export lane IDs for convenience.
export { REMOTE_LANE_IDS, REMOTE_LANE_MAX_PAYLOAD_BYTES };
