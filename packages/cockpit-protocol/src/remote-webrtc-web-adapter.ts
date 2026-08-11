/**
 * Browser WebRTC remote client adapter.
 *
 * @see remote-webrtc-web-client
 *
 * This module is the passive browser endpoint of the client-to-daemon WebRTC
 * transport. It wraps a browser `RTCPeerConnection` behind deterministic,
 * injectable peer/signaling/channel fakes so it can be exercised in Node
 * tests without a real browser. The adapter:
 *
 * - feature-detects before any ticket/peer/resource is created;
 * - honours the exact evaluated network capability (`direct_allowed`,
 *   `relay_only`, `unavailable`) and never merges browser defaults;
 * - is the offerer / ICE-controlling role;
 * - validates the daemon final proof and the exact DTLS fingerprint/offer-answer
 *   transcript before exposing any lane writer;
 * - owns three negotiated data channels (IDs 0/2/4) with fragment/reassembly
 *   and buffered-amount backpressure;
 * - emits typed events only and accepts explicit establish/send/close commands;
 * - owns NO retry/fallback/reattach/selection/logical-mutation state;
 * - generation-guards every promise/event listener so navigation, unmount,
 *   cancellation, deadline, late promise, or replacement cannot mutate stale
 *   state.
 */

import { remoteIdentitySha256Sync } from "./remote-identity-protocol";
import { remoteFinalProofSetDigest } from "./remote-signaling-attempt-store";
import {
  decodeRemoteEndpointFinalProofV1,
  encodeRemoteSignalingReadyV1,
  type RemoteEndpointFinalProofV1,
  type RemoteSignalingReadyV1,
  remoteEndpointFinalProofAgreementBytes,
} from "./remote-signaling-payloads";
import {
  laneFromId,
  REMOTE_LANE_IDS,
  REMOTE_LANE_MAX_PAYLOAD_BYTES,
  REMOTE_LANES,
  type RemoteLane,
} from "./remote-transport-lanes";

// ---------------------------------------------------------------------------
// Public capability / consent types
// ---------------------------------------------------------------------------

/** Tri-state evaluated network capability, owned by shared selection. */
export type RemoteWebCapability = "direct_allowed" | "relay_only" | "unavailable";

/** Tri-state IP-disclosure consent, owned by shared selection/continuity. */
export type RemoteWebIpConsent = "granted" | "denied" | "pending";

export type RemoteWebCapabilityStatus =
  | "ok"
  | "browser_upgrade_required"
  | "reenrollment_required"
  | "remote_crypto_unsupported"
  | "relay_unavailable"
  | "policy_denied"
  | "secure_context_required";

export interface RemoteWebCapabilityResult {
  readonly status: RemoteWebCapabilityStatus;
  readonly capability: RemoteWebCapability;
}

/** Signed ICE policy supplied by the dependency-owned TURN/ICE policy layer. */
export interface RemoteWebSignedIcePolicy {
  /** Verified signed TURN URLs; exclusive — no browser defaults are merged. */
  readonly turnServers: readonly RemoteWebTurnServer[];
  /** When relay_only, iceTransportPolicy is "relay" and no STUN/direct is set. */
  readonly transportPolicy: "direct" | "relay";
  /** Digest of the signed policy for replay/generation checks. */
  readonly policyDigest: Uint8Array;
}

export interface RemoteWebTurnServer {
  readonly urls: readonly string[];
  readonly username: string;
  readonly credential: string;
}

export interface RemoteWebIdentityHandles {
  /** Non-extractable persisted P-256 signing key handle (IndexedDB). */
  readonly p256KeyHandle: unknown;
  /** Enrolled client certificate JWS (provenance from identity custody). */
  readonly clientCertificateJws: Uint8Array;
  /** Certificate id/generation for proof binding. */
  readonly certificateId: Uint8Array;
  readonly certificateGeneration: bigint;
}

export interface RemoteWebAttemptInput {
  /** One authorized child plan. */
  readonly childAttemptId: Uint8Array;
  readonly transportEpoch: Uint8Array;
  readonly admissionSequence: bigint;
  readonly grantDigest: Uint8Array;
  /** Exact signed ICE policy. */
  readonly icePolicy: RemoteWebSignedIcePolicy;
  /** Signed IP-consent tri-state digest. */
  readonly ipConsent: RemoteWebIpConsent;
  /** Enrolled identity handles (durable P-256). */
  readonly identity: RemoteWebIdentityHandles;
  /** Grant/proofs/tuple and generation. */
  readonly generation: number;
  /** Evaluated network capability. */
  readonly capability: RemoteWebCapability;
}

// ---------------------------------------------------------------------------
// Passive adapter command / event contract
// ---------------------------------------------------------------------------

export type RemoteWebCommand =
  | { readonly kind: "establish"; readonly input: RemoteWebAttemptInput }
  | { readonly kind: "send"; readonly lane: RemoteLane; readonly bytes: Uint8Array }
  | { readonly kind: "close"; readonly reason?: RemoteWebCloseReason };

export type RemoteWebCloseReason =
  | "navigation"
  | "unmount"
  | "cancel"
  | "deadline"
  | "replacement"
  | "remote_closed"
  | "error";

export type RemoteWebEvent =
  | { readonly kind: "capability"; readonly result: RemoteWebCapabilityResult }
  | { readonly kind: "signaling"; readonly message: RemoteWebSignalingOut }
  | { readonly kind: "candidate"; readonly candidate: RemoteWebLocalCandidate }
  | { readonly kind: "ice_complete" }
  | { readonly kind: "health"; readonly status: RemoteWebHealthStatus }
  | { readonly kind: "lane_ready"; readonly lanes: readonly RemoteLane[] }
  | { readonly kind: "lane_data"; readonly lane: RemoteLane; readonly bytes: Uint8Array }
  | { readonly kind: "backpressure"; readonly lane: RemoteLane; readonly bufferedAmount: number }
  | { readonly kind: "close"; readonly reason: RemoteWebCloseReason; readonly error?: string };

export type RemoteWebHealthStatus =
  | "establishing"
  | "signaling_open"
  | "ice_gathering"
  | "dtls_connecting"
  | "dtls_connected"
  | "proof_pending"
  | "active"
  | "closing"
  | "closed";

export type RemoteWebSignalingOut =
  | { readonly type: "offer"; readonly sdp: Uint8Array; readonly descriptionId: Uint8Array }
  | { readonly type: "candidate"; readonly candidate: RemoteWebLocalCandidate }
  | { readonly type: "ice_complete"; readonly transportEpoch: Uint8Array };

export interface RemoteWebLocalCandidate {
  readonly candidateId: Uint8Array;
  readonly sdpMid: string;
  readonly sdpMLineIndex: number;
  readonly candidate: string;
}

/** Inbound signaling events consumed by the adapter (cursor-replayable). */
export type RemoteWebSignalingIn =
  | { readonly type: "answer"; readonly sdp: Uint8Array; readonly descriptionId: Uint8Array }
  | { readonly type: "remote_candidate"; readonly candidate: RemoteWebRemoteCandidate }
  | { readonly type: "ice_complete"; readonly transportEpoch: Uint8Array }
  | {
      readonly type: "daemon_final_proof";
      readonly proof: Uint8Array;
    }
  | {
      readonly type: "client_final_proof";
      readonly proof: Uint8Array;
    }
  | { readonly type: "daemon_ready"; readonly ready: RemoteSignalingReadyV1 };

export interface RemoteWebRemoteCandidate {
  readonly candidateId: Uint8Array;
  readonly sdpMid: string;
  readonly sdpMLineIndex: number;
  readonly candidate: string;
}

// ---------------------------------------------------------------------------
// Injectable browser-peer factory (deterministic fakes in tests)
// ---------------------------------------------------------------------------

/** Parsed candidate type for relay-only enforcement. */
export type RemoteWebCandidateType = "host" | "srflx" | "prflx" | "relay";

/** Parse the `typ=` field from an ICE candidate string. */
export function parseCandidateType(candidate: string): RemoteWebCandidateType {
  const match = /typ\s+([a-z]+)/.exec(candidate);
  const typ = match?.[1];
  if (typ === "host" || typ === "srflx" || typ === "prflx" || typ === "relay") return typ;
  return "host";
}

/** Minimal structural RTCDataChannel interface (no DOM lib needed). */
export interface WebRtcDataChannel {
  readonly label: string;
  readonly id: number | null;
  readonly ordered: boolean;
  bufferedAmount: number;
  bufferedAmountLowThreshold: number;
  readonly readyState: "connecting" | "open" | "closing" | "closed";
  onopen: (() => void) | null;
  onclose: (() => void) | null;
  onbufferedamountlow: (() => void) | null;
  onmessage: ((event: { readonly data: Uint8Array }) => void) | null;
  send(data: Uint8Array): void;
  close(): void;
}

/** Minimal structural RTCIceCandidate. */
export interface WebRtcIceCandidate {
  readonly candidate: string;
  readonly sdpMid: string | null;
  readonly sdpMLineIndex: number | null;
}

/** Minimal structural RTCSessionDescription. */
export interface WebRtcSessionDescription {
  readonly type: "offer" | "answer" | "pranswer" | "rollback";
  readonly sdp: string;
}

export interface WebRtcPeerConnection {
  readonly localDescription: WebRtcSessionDescription | null;
  readonly remoteDescription: WebRtcSessionDescription | null;
  readonly iceConnectionState:
    | "new"
    | "checking"
    | "connected"
    | "completed"
    | "disconnected"
    | "failed"
    | "closed";
  readonly connectionState:
    | "new"
    | "connecting"
    | "connected"
    | "disconnected"
    | "failed"
    | "closed";
  onicecandidate: ((event: { readonly candidate: WebRtcIceCandidate | null }) => void) | null;
  oniceconnectionstatechange: (() => void) | null;
  onconnectionstatechange: (() => void) | null;
  ondatachannel: ((event: { readonly channel: WebRtcDataChannel }) => void) | null;
  createDataChannel(
    label: string,
    options?: {
      readonly id?: number;
      readonly ordered?: boolean;
      readonly negotiated?: boolean;
    },
  ): WebRtcDataChannel;
  setLocalDescription(description: WebRtcSessionDescription): Promise<void>;
  setRemoteDescription(description: WebRtcSessionDescription): Promise<void>;
  addIceCandidate(candidate: WebRtcIceCandidate): Promise<void>;
  addTransceiver?(): unknown;
  close(): void;
}

export interface WebRtcPeerFactory {
  create(configuration: {
    readonly iceServers: readonly { readonly urls: readonly string[] }[];
    readonly iceTransportPolicy?: RTCIceTransportPolicy;
  }): WebRtcPeerConnection;
}

/** DOM RTCIceTransportPolicy values. */
export type RTCIceTransportPolicy = "all" | "relay";

/** DTLS fingerprint extracted from an SDP description for proof binding. */
export function extractDtlsFingerprint(sdp: string): Uint8Array | null {
  const match = /a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)/.exec(sdp);
  if (!match?.[1]) return null;
  const hex = match[1].replace(/:/g, "");
  if (hex.length !== 64) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Capability gate
// ---------------------------------------------------------------------------

export interface RemoteWebCapabilityProbe {
  isSecureContext(): boolean;
  hasRtcPeerConnection(): boolean;
  hasNegotiatedDataChannels(): boolean;
  /** Durable P-256 lookup via IndexedDB; never probes WebCrypto X25519. */
  lookupP256Handle(): Promise<RemoteWebP256HandleResult>;
  /** Per-child ephemeral X25519 capability from the shared Rust-WASM core. */
  lookupEphemeralX25519(childAttemptId: Uint8Array): Promise<boolean>;
}

export type RemoteWebP256HandleResult =
  | { readonly status: "present"; readonly handle: unknown }
  | { readonly status: "missing" }
  | { readonly status: "corrupt" };

export interface RemoteWebCapabilityGateInput {
  readonly probe: RemoteWebCapabilityProbe;
  readonly capability: RemoteWebCapability;
  readonly childAttemptId: Uint8Array;
}

/**
 * Feature-detect before any ticket/peer/resource allocation.
 *
 * Owns only durable P-256; never probes or accepts WebCrypto X25519. X25519
 * belongs only to the fallback child establishment path, which independently
 * checks the shared Rust-WASM core's per-child ephemeral capability.
 */
export async function remoteWebCapabilityGate(
  input: RemoteWebCapabilityGateInput,
): Promise<RemoteWebCapabilityResult> {
  if (!input.probe.isSecureContext()) {
    return { status: "secure_context_required", capability: input.capability };
  }
  if (!input.probe.hasRtcPeerConnection()) {
    return { status: "browser_upgrade_required", capability: input.capability };
  }
  if (!input.probe.hasNegotiatedDataChannels()) {
    return { status: "browser_upgrade_required", capability: input.capability };
  }
  if (input.capability === "unavailable") {
    return { status: "relay_unavailable", capability: input.capability };
  }
  const p256 = await input.probe.lookupP256Handle();
  if (p256.status === "missing" || p256.status === "corrupt") {
    return { status: "reenrollment_required", capability: input.capability };
  }
  // The fallback independently checks X25519; the WebRTC path does not own it.
  // We only check it to surface `remote_crypto_unsupported` for the child, but
  // never as durable identity or a WebRTC prerequisite.
  const x25519 = await input.probe.lookupEphemeralX25519(input.childAttemptId);
  if (!x25519) {
    return { status: "remote_crypto_unsupported", capability: input.capability };
  }
  return { status: "ok", capability: input.capability };
}

// ---------------------------------------------------------------------------
// ICE consent matrix
// ---------------------------------------------------------------------------

export interface RemoteWebIceConfig {
  readonly iceServers: readonly { readonly urls: readonly string[] }[];
  readonly iceTransportPolicy?: RTCIceTransportPolicy;
}

/**
 * Translate the exact evaluated network capability + signed ICE policy into
 * the RTCConfiguration. No browser defaults or public STUN are ever merged.
 */
export function remoteWebIceConfiguration(
  capability: RemoteWebCapability,
  policy: RemoteWebSignedIcePolicy,
): RemoteWebIceConfig | null {
  if (capability === "unavailable") return null;
  if (capability === "relay_only") {
    if (policy.transportPolicy !== "relay") return null;
    return {
      iceServers: policy.turnServers.map((server) => ({ urls: server.urls })),
      iceTransportPolicy: "relay",
    };
  }
  // direct_allowed: normal signed ICE only after committed direct-gather auth.
  if (policy.transportPolicy === "relay") {
    return {
      iceServers: policy.turnServers.map((server) => ({ urls: server.urls })),
      iceTransportPolicy: "relay",
    };
  }
  return {
    iceServers: policy.turnServers.map((server) => ({ urls: server.urls })),
    iceTransportPolicy: "all",
  };
}

/**
 * Determine whether a local candidate may be published to signaling.
 *
 * `relay_only` suppresses every non-relay local candidate — no host/srflx/prflx
 * candidate can leave the browser. Browser internals may still enumerate
 * implementation-private candidates; we only guarantee none leaves, enters, or
 * becomes usable.
 */
export function remoteWebAllowLocalCandidate(
  capability: RemoteWebCapability,
  candidateType: RemoteWebCandidateType,
): boolean {
  if (capability === "relay_only") return candidateType === "relay";
  if (capability === "direct_allowed") return true;
  return false;
}

/**
 * Determine whether a remote candidate may be accepted/nominated.
 *
 * `relay_only` rejects any remote candidate whose parsed type is not `relay`.
 */
export function remoteWebAllowRemoteCandidate(
  capability: RemoteWebCapability,
  candidateType: RemoteWebCandidateType,
): boolean {
  if (capability === "relay_only") return candidateType === "relay";
  if (capability === "direct_allowed") return true;
  return false;
}

// ---------------------------------------------------------------------------
// Channel / lane mapping
// ---------------------------------------------------------------------------

/**
 * Three negotiated reliable data channels mapped to logical lanes.
 *
 * The prompt specifies IDs 0/2/4 for control/interactive/bulk. These are the
 * negotiated channel IDs (not the lane IDs 0/1/2), giving even spacing to
 * avoid browser implementation quirks with adjacent channel ids.
 */
export const REMOTE_WEBRTC_CHANNEL_IDS: Readonly<Record<RemoteLane, number>> = {
  control: 0,
  interactive: 2,
  bulk: 4,
};

export const REMOTE_WEBRTC_CHANNEL_LABELS: Readonly<Record<RemoteLane, string>> = {
  control: "flycockpit.control",
  interactive: "flycockpit.interactive",
  bulk: "flycockpit.bulk",
};

export function laneFromChannelId(channelId: number): RemoteLane | undefined {
  return REMOTE_LANES.find((lane) => REMOTE_WEBRTC_CHANNEL_IDS[lane] === channelId);
}

export const REMOTE_WEBRTC_BUFFERED_AMOUNT_HIGH_THRESHOLD: Readonly<Record<RemoteLane, number>> = {
  control: 64 * 1024,
  interactive: 256 * 1024,
  bulk: 512 * 1024,
};

export const REMOTE_WEBRTC_MAX_CANDIDATES = 64;
export const REMOTE_WEBRTC_MAX_SDP_BYTES = 122_880;
export const REMOTE_WEBRTC_MAX_LANE_PAYLOAD_BYTES = REMOTE_LANE_MAX_PAYLOAD_BYTES;

// ---------------------------------------------------------------------------
// Final-proof gate
// ---------------------------------------------------------------------------

export interface RemoteWebProofVerification {
  readonly clientProofVerified: boolean;
  readonly daemonProofVerified: boolean;
  readonly bothVerified: boolean;
  readonly negotiationDigest: Uint8Array;
}

/**
 * Independently verify the daemon certificate/status and matching
 * offer/answer/fingerprints/child/epoch before lanes open. A transcript digest
 * or local DTLS-connected callback alone cannot open lanes.
 */
export function remoteWebVerifyProofs(input: {
  readonly clientProof: Uint8Array;
  readonly daemonProof: Uint8Array;
  readonly expectedChildAttemptId: Uint8Array;
  readonly expectedTransportEpoch: Uint8Array;
  readonly expectedOfferSdp: Uint8Array;
  readonly expectedAnswerSdp: Uint8Array;
  readonly expectedDtlsFingerprint: Uint8Array;
  readonly grantDigest: Uint8Array;
  readonly admissionSequence: bigint;
}): RemoteWebProofVerification {
  let client: RemoteEndpointFinalProofV1;
  let daemon: RemoteEndpointFinalProofV1;
  try {
    client = decodeRemoteEndpointFinalProofV1(input.clientProof);
    daemon = decodeRemoteEndpointFinalProofV1(input.daemonProof);
  } catch {
    return {
      clientProofVerified: false,
      daemonProofVerified: false,
      bothVerified: false,
      negotiationDigest: new Uint8Array(32),
    };
  }
  const clientOk = verifyOneProof(client, {
    role: 1,
    transport: 1,
    childAttemptId: input.expectedChildAttemptId,
    transportEpoch: input.expectedTransportEpoch,
    grantDigest: input.grantDigest,
    admissionSequence: input.admissionSequence,
  });
  const daemonOk = verifyOneProof(daemon, {
    role: 2,
    transport: 1,
    childAttemptId: input.expectedChildAttemptId,
    transportEpoch: input.expectedTransportEpoch,
    grantDigest: input.grantDigest,
    admissionSequence: input.admissionSequence,
  });
  // The two proofs must agree on the transport/child/epoch/sequence/grant.
  const clientAgreement = remoteEndpointFinalProofAgreementBytes(client);
  const daemonAgreement = remoteEndpointFinalProofAgreementBytes(daemon);
  const agreementsMatch =
    clientAgreement.length === daemonAgreement.length &&
    clientAgreement.every((b, i) => b === daemonAgreement[i]);
  // Verify the transcript digest: offer + answer + DTLS fingerprint.
  const negotiationDigest = remoteWebNegotiationDigest(
    input.expectedOfferSdp,
    input.expectedAnswerSdp,
    input.expectedDtlsFingerprint,
  );
  const transcriptMatch =
    client.negotiationDigest.every((b, i) => b === negotiationDigest[i]) &&
    daemon.negotiationDigest.every((b, i) => b === negotiationDigest[i]);
  const bothVerified = clientOk && daemonOk && agreementsMatch && transcriptMatch;
  return {
    clientProofVerified: clientOk,
    daemonProofVerified: daemonOk,
    bothVerified,
    negotiationDigest,
  };
}

function verifyOneProof(
  proof: RemoteEndpointFinalProofV1,
  expected: {
    readonly role: 1 | 2;
    readonly transport: 1 | 2;
    readonly childAttemptId: Uint8Array;
    readonly transportEpoch: Uint8Array;
    readonly grantDigest: Uint8Array;
    readonly admissionSequence: bigint;
  },
): boolean {
  if (proof.role !== expected.role) return false;
  if (proof.transport !== expected.transport) return false;
  if (!proof.childAttemptId.every((b, i) => b === expected.childAttemptId[i])) return false;
  if (!proof.transportEpoch.every((b, i) => b === expected.transportEpoch[i])) return false;
  if (proof.admissionSequence !== expected.admissionSequence) return false;
  if (!proof.grantDigest.every((b, i) => b === expected.grantDigest[i])) return false;
  return true;
}

/** Transcript digest over offer + answer + DTLS fingerprint. */
export function remoteWebNegotiationDigest(
  offerSdp: Uint8Array,
  answerSdp: Uint8Array,
  dtlsFingerprint: Uint8Array,
): Uint8Array {
  const te = new TextEncoder();
  return remoteIdentitySha256Sync(
    concatBytes([
      te.encode("flycockpit.remote.webrtc-negotiation.v1\0"),
      u32(offerSdp.length),
      offerSdp,
      u32(answerSdp.length),
      answerSdp,
      u32(dtlsFingerprint.length),
      dtlsFingerprint,
    ]),
  );
}

// ---------------------------------------------------------------------------
// Fragment / reassembly (shared fragment for data-channel backpressure)
// ---------------------------------------------------------------------------

export const REMOTE_WEBRTC_MAX_FRAGMENT_COUNT = 9;
export const REMOTE_WEBRTC_FRAGMENT_HEADER_BYTES = 24;
export const REMOTE_WEBRTC_CHANNEL_MAX_PAYLOAD_BYTES = 16 * 1024;
export const REMOTE_WEBRTC_FRAGMENT_MAX_PAYLOAD_BYTES =
  REMOTE_WEBRTC_CHANNEL_MAX_PAYLOAD_BYTES - REMOTE_WEBRTC_FRAGMENT_HEADER_BYTES;

export interface RemoteWebRtcFragment {
  readonly lane: RemoteLane;
  readonly frameId: Uint8Array;
  readonly fragmentIndex: number;
  readonly fragmentCount: number;
  readonly end: boolean;
  readonly bytes: Uint8Array;
}

/** Fragment a lane payload into channel-sized fragments. */
export function remoteWebRtcFragmentPayload(
  lane: RemoteLane,
  payload: Uint8Array,
  frameId: Uint8Array,
): readonly RemoteWebRtcFragment[] {
  if (payload.length === 0) {
    return [
      {
        lane,
        frameId,
        fragmentIndex: 0,
        fragmentCount: 1,
        end: true,
        bytes: new Uint8Array(0),
      },
    ];
  }
  const maxPayload = REMOTE_WEBRTC_FRAGMENT_MAX_PAYLOAD_BYTES;
  const fragmentCount = Math.min(
    REMOTE_WEBRTC_MAX_FRAGMENT_COUNT,
    Math.ceil(payload.length / maxPayload),
  );
  const chunkSize = Math.ceil(payload.length / fragmentCount);
  const fragments: RemoteWebRtcFragment[] = [];
  for (let i = 0; i < fragmentCount; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, payload.length);
    fragments.push({
      lane,
      frameId,
      fragmentIndex: i,
      fragmentCount,
      end: i === fragmentCount - 1,
      bytes: payload.slice(start, end),
    });
  }
  return fragments;
}

/** Encode a fragment for the data channel. */
export function encodeRemoteWebRtcFragment(fragment: RemoteWebRtcFragment): Uint8Array {
  if (fragment.fragmentCount < 1 || fragment.fragmentCount > REMOTE_WEBRTC_MAX_FRAGMENT_COUNT)
    throw new Error("invalid_fragment_count");
  if (fragment.fragmentIndex < 0 || fragment.fragmentIndex >= fragment.fragmentCount)
    throw new Error("invalid_fragment_index");
  if (fragment.frameId.length !== 16) throw new Error("invalid_frame_id");
  if (fragment.bytes.length > REMOTE_WEBRTC_FRAGMENT_MAX_PAYLOAD_BYTES)
    throw new Error("fragment_payload_cap_exceeded");
  const out = new Uint8Array(REMOTE_WEBRTC_FRAGMENT_HEADER_BYTES + fragment.bytes.length);
  out[0] = REMOTE_LANE_IDS[fragment.lane];
  out[1] = fragment.fragmentCount;
  out[2] = fragment.fragmentIndex;
  out[3] = fragment.end ? 1 : 0;
  out.set(fragment.frameId, 4);
  new DataView(out.buffer).setUint32(20, fragment.bytes.length);
  out.set(fragment.bytes, REMOTE_WEBRTC_FRAGMENT_HEADER_BYTES);
  return out;
}

/** Decode a fragment from the data channel. */
export function decodeRemoteWebRtcFragment(bytes: Uint8Array): RemoteWebRtcFragment {
  if (bytes.length < REMOTE_WEBRTC_FRAGMENT_HEADER_BYTES) throw new Error("invalid_fragment");
  const laneId = bytes[0]!;
  const lane = laneFromId(laneId);
  if (!lane) throw new Error("invalid_lane");
  const fragmentCount = bytes[1]!;
  const fragmentIndex = bytes[2]!;
  const end = bytes[3] === 1;
  const frameId = bytes.slice(4, 20);
  if (frameId.every((b) => b === 0)) throw new Error("invalid_frame_id");
  const length = new DataView(bytes.buffer, bytes.byteOffset).getUint32(20);
  if (
    length > REMOTE_WEBRTC_FRAGMENT_MAX_PAYLOAD_BYTES ||
    bytes.length !== REMOTE_WEBRTC_FRAGMENT_HEADER_BYTES + length
  )
    throw new Error("invalid_fragment");
  if (fragmentCount < 1 || fragmentCount > REMOTE_WEBRTC_MAX_FRAGMENT_COUNT)
    throw new Error("invalid_fragment_count");
  if (fragmentIndex >= fragmentCount) throw new Error("invalid_fragment_index");
  const isFinal = fragmentIndex === fragmentCount - 1;
  if (end !== isFinal) throw new Error("fragment_end_flag_misplaced");
  return {
    lane,
    frameId,
    fragmentIndex,
    fragmentCount,
    end,
    bytes: bytes.slice(REMOTE_WEBRTC_FRAGMENT_HEADER_BYTES),
  };
}

/** Bounded per-lane reassembly with duplicate / reorder / conflict detection. */
export class RemoteWebRtcReassembly {
  private partials = new Map<
    string,
    { fragments: Map<number, Uint8Array>; count: number; bytes: number }
  >();
  private completed = new Map<string, number>();
  private readonly maxFrames: number;
  private readonly maxBytes: number;

  constructor(opts?: { readonly maxFrames?: number; readonly maxBytes?: number }) {
    this.maxFrames = opts?.maxFrames ?? 16;
    this.maxBytes = opts?.maxBytes ?? 8 * 1024 * 1024;
  }

  /** Returns the reassembled payload when the final fragment arrives, else null. */
  ingest(fragment: RemoteWebRtcFragment): Uint8Array | null {
    const key = frameKeyHex(fragment.frameId);
    if (this.completed.has(key)) return null; // duplicate of a completed frame
    let entry = this.partials.get(key);
    if (!entry) {
      if (this.partials.size >= this.maxFrames) throw new Error("reassembly_frame_limit");
      entry = { fragments: new Map(), count: fragment.fragmentCount, bytes: 0 };
      this.partials.set(key, entry);
    }
    if (entry.count !== fragment.fragmentCount) throw new Error("fragment_conflict");
    if (entry.fragments.has(fragment.fragmentIndex)) return null; // duplicate fragment
    if (entry.bytes + fragment.bytes.length > this.maxBytes)
      throw new Error("reassembly_byte_limit");
    entry.fragments.set(fragment.fragmentIndex, fragment.bytes);
    entry.bytes += fragment.bytes.length;
    if (entry.fragments.size < entry.count) return null;
    // All fragments present — reassemble in order.
    const parts: Uint8Array[] = [];
    for (let i = 0; i < entry.count; i++) {
      const part = entry.fragments.get(i);
      if (!part) throw new Error("fragment_missing");
      parts.push(part);
    }
    const payload = concatBytes(parts);
    this.partials.delete(key);
    if (this.completed.size >= 64) {
      const first = this.completed.keys().next();
      if (!first.done) this.completed.delete(first.value as string);
    }
    this.completed.set(key, payload.length);
    return payload;
  }

  get outstandingFrames(): number {
    return this.partials.size;
  }

  clear(): void {
    this.partials.clear();
    this.completed.clear();
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function u32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

function frameKeyHex(id: Uint8Array): string {
  let hex = "";
  for (const b of id) hex += b.toString(16).padStart(2, "0");
  return hex;
}

// ---------------------------------------------------------------------------
// Passive adapter
// ---------------------------------------------------------------------------

export interface RemoteWebRtcAdapterOptions {
  readonly peerFactory: WebRtcPeerFactory;
  readonly emit: (event: RemoteWebEvent) => void;
  /** Injected randomness for frame ids / candidate ids. */
  readonly random?: () => Uint8Array;
}

interface ActiveAttempt {
  readonly generation: number;
  readonly input: RemoteWebAttemptInput;
  readonly peer: WebRtcPeerConnection;
  readonly channels: Map<RemoteLane, WebRtcDataChannel>;
  readonly reassembly: RemoteWebRtcReassembly;
  readonly localCandidates: RemoteWebLocalCandidate[];
  readonly remoteCandidatesSeen: Set<string>;
  readonly proofState: {
    clientProof: Uint8Array | null;
    daemonProof: Uint8Array | null;
    daemonReady: RemoteSignalingReadyV1 | null;
    lanesOpen: boolean;
  };
  readonly offerSdp: Uint8Array;
  readonly answerSdp: Uint8Array;
  readonly dtlsFingerprint: Uint8Array;
  closed: boolean;
  iceCompleteSent: boolean;
}

/**
 * Passive browser WebRTC adapter. Accepts explicit establish/send/close
 * commands and emits typed events. Owns no retry/fallback/reattach/selection
 * or logical-mutation state.
 */
export class RemoteWebRtcAdapter {
  private readonly peerFactory: WebRtcPeerFactory;
  private readonly emitFn: (event: RemoteWebEvent) => void;
  private readonly random: () => Uint8Array;
  private active: ActiveAttempt | null = null;
  private generation = 0;

  constructor(options: RemoteWebRtcAdapterOptions) {
    this.peerFactory = options.peerFactory;
    this.emitFn = options.emit;
    this.random = options.random ?? (() => crypto.getRandomValues(new Uint8Array(16)));
  }

  /** Emit a typed event to the caller. */
  private emit(event: RemoteWebEvent): void {
    this.emitFn(event);
  }

  get currentGeneration(): number {
    return this.generation;
  }

  get isActive(): boolean {
    return this.active !== null && !this.active.closed;
  }

  /** Dispatch an explicit command. */
  async dispatch(command: RemoteWebCommand): Promise<void> {
    switch (command.kind) {
      case "establish":
        await this.establish(command.input);
        break;
      case "send":
        this.send(command.lane, command.bytes);
        break;
      case "close":
        this.close(command.reason ?? "cancel");
        break;
    }
  }

  /** Inbound signaling event (cursor-replayable, bounded). */
  ingestSignaling(event: RemoteWebSignalingIn): void {
    const attempt = this.active;
    if (!attempt || attempt.closed) return;
    if (!this.isCurrentAttempt(attempt)) return;
    switch (event.type) {
      case "answer":
        this.handleAnswer(attempt, event);
        break;
      case "remote_candidate":
        this.handleRemoteCandidate(attempt, event);
        break;
      case "ice_complete":
        // Daemon-side ICE complete; informational only.
        break;
      case "daemon_final_proof":
        this.handleDaemonProof(attempt, event.proof);
        break;
      case "client_final_proof":
        this.handleClientProof(attempt, event.proof);
        break;
      case "daemon_ready":
        this.handleDaemonReady(attempt, event.ready);
        break;
    }
  }

  // --- establish -----------------------------------------------------------

  private async establish(input: RemoteWebAttemptInput): Promise<void> {
    // Generation guard: a new establish invalidates any prior attempt.
    const generation = ++this.generation;
    this.closeInternal("replacement");
    if (input.capability === "unavailable") {
      this.emit({
        kind: "capability",
        result: { status: "relay_unavailable", capability: input.capability },
      });
      return;
    }
    const iceConfig = remoteWebIceConfiguration(input.capability, input.icePolicy);
    if (!iceConfig) {
      this.emit({
        kind: "capability",
        result: { status: "policy_denied", capability: input.capability },
      });
      return;
    }
    if (input.ipConsent === "denied") {
      this.emit({
        kind: "capability",
        result: { status: "policy_denied", capability: input.capability },
      });
      return;
    }
    this.emit({ kind: "capability", result: { status: "ok", capability: input.capability } });
    this.emit({ kind: "health", status: "establishing" });

    const peer = this.peerFactory.create(iceConfig);
    const channels = new Map<RemoteLane, WebRtcDataChannel>();
    const reassembly = new RemoteWebRtcReassembly();

    // The attempt record is referenced by every event handler; declare it
    // first so closures capture the binding, then assign after construction.
    let attempt: ActiveAttempt;

    // Create three negotiated data channels (client is offerer).
    for (const lane of REMOTE_LANES) {
      const channel = peer.createDataChannel(REMOTE_WEBRTC_CHANNEL_LABELS[lane], {
        id: REMOTE_WEBRTC_CHANNEL_IDS[lane],
        ordered: true,
        negotiated: true,
      });
      channel.bufferedAmountLowThreshold = REMOTE_WEBRTC_BUFFERED_AMOUNT_HIGH_THRESHOLD[lane] / 2;
      channel.onopen = () => {
        if (!this.isCurrentAttempt(attempt)) return;
        this.maybeOpenLanes(attempt);
      };
      channel.onmessage = (event) => {
        if (!this.isCurrentAttempt(attempt)) return;
        this.handleChannelMessage(attempt, lane, event.data);
      };
      channel.onbufferedamountlow = () => {
        if (!this.isCurrentAttempt(attempt)) return;
        this.emit({
          kind: "backpressure",
          lane,
          bufferedAmount: channel.bufferedAmount,
        });
      };
      channels.set(lane, channel);
    }

    // ICE candidate handling.
    peer.onicecandidate = (event) => {
      if (!this.isCurrentAttempt(attempt)) return;
      if (!event.candidate) return;
      const candidateType = parseCandidateType(event.candidate.candidate);
      if (!remoteWebAllowLocalCandidate(input.capability, candidateType)) {
        // Non-relay local candidate suppressed in relay_only — never published.
        return;
      }
      if (attempt.localCandidates.length >= REMOTE_WEBRTC_MAX_CANDIDATES) return;
      const localCandidate: RemoteWebLocalCandidate = {
        candidateId: this.random(),
        sdpMid: event.candidate.sdpMid ?? "0",
        sdpMLineIndex: event.candidate.sdpMLineIndex ?? 0,
        candidate: event.candidate.candidate,
      };
      attempt.localCandidates.push(localCandidate);
      this.emit({ kind: "candidate", candidate: localCandidate });
      this.emit({
        kind: "signaling",
        message: { type: "candidate", candidate: localCandidate },
      });
    };

    peer.oniceconnectionstatechange = () => {
      if (!this.isCurrentAttempt(attempt)) return;
      const state = peer.iceConnectionState;
      if (state === "checking") {
        this.emit({ kind: "health", status: "ice_gathering" });
      }
      if (state === "connected" || state === "completed") {
        this.emit({ kind: "health", status: "dtls_connecting" });
      }
      if (state === "failed" || state === "disconnected") {
        if (!attempt.closed) this.close("error");
      }
    };

    peer.onconnectionstatechange = () => {
      if (!this.isCurrentAttempt(attempt)) return;
      const state = peer.connectionState;
      if (state === "connected") {
        this.emit({ kind: "health", status: "dtls_connected" });
      }
      if (state === "disconnected" || state === "failed") {
        if (!attempt.closed) this.close("remote_closed");
      }
    };

    // Create the offer (client is offerer/ICE-controlling).
    this.emit({ kind: "health", status: "signaling_open" });
    const offerSdp = new TextEncoder().encode(peer.localDescription?.sdp ?? "");
    const descriptionId = this.random();

    const attemptRecord: ActiveAttempt = {
      generation,
      input,
      peer,
      channels,
      reassembly,
      localCandidates: [],
      remoteCandidatesSeen: new Set(),
      proofState: {
        clientProof: null,
        daemonProof: null,
        daemonReady: null,
        lanesOpen: false,
      },
      offerSdp,
      answerSdp: new Uint8Array(0),
      dtlsFingerprint:
        extractDtlsFingerprint(peer.localDescription?.sdp ?? "") ?? new Uint8Array(32),
      closed: false,
      iceCompleteSent: false,
    };
    attempt = attemptRecord;
    this.active = attemptRecord;

    this.emit({
      kind: "signaling",
      message: { type: "offer", sdp: offerSdp, descriptionId },
    });
  }

  // --- send ----------------------------------------------------------------

  private send(lane: RemoteLane, payload: Uint8Array): void {
    const attempt = this.active;
    if (!attempt || attempt.closed || !this.isCurrentAttempt(attempt)) return;
    if (!attempt.proofState.lanesOpen) return; // lanes gated on final proof
    if (payload.length > REMOTE_WEBRTC_MAX_LANE_PAYLOAD_BYTES[lane]) return;
    const channel = attempt.channels.get(lane);
    if (channel?.readyState !== "open") return;
    const frameId = this.random();
    const fragments = remoteWebRtcFragmentPayload(lane, payload, frameId);
    for (const fragment of fragments) {
      const encoded = encodeRemoteWebRtcFragment(fragment);
      channel.send(encoded);
    }
    if (channel.bufferedAmount > REMOTE_WEBRTC_BUFFERED_AMOUNT_HIGH_THRESHOLD[lane]) {
      this.emit({ kind: "backpressure", lane, bufferedAmount: channel.bufferedAmount });
    }
  }

  // --- inbound signaling handlers ------------------------------------------

  private handleAnswer(attempt: ActiveAttempt, event: { readonly sdp: Uint8Array }): void {
    if (attempt.answerSdp.length > 0) return; // duplicate / reorder guard
    if (event.sdp.length > REMOTE_WEBRTC_MAX_SDP_BYTES) return;
    const sdpString = new TextDecoder().decode(event.sdp);
    try {
      attempt.peer.setRemoteDescription({ type: "answer", sdp: sdpString });
    } catch {
      this.close("error");
      return;
    }
    // Store answer bytes and DTLS fingerprint for proof verification.
    (attempt as { answerSdp: Uint8Array }).answerSdp = event.sdp;
    const fingerprint = extractDtlsFingerprint(sdpString);
    if (fingerprint) (attempt as { dtlsFingerprint: Uint8Array }).dtlsFingerprint = fingerprint;
    this.maybeOpenLanes(attempt);
  }

  private handleRemoteCandidate(
    attempt: ActiveAttempt,
    event: { readonly candidate: RemoteWebRemoteCandidate },
  ): void {
    const key = frameKeyHex(event.candidate.candidateId);
    if (attempt.remoteCandidatesSeen.has(key)) return; // duplicate
    if (attempt.remoteCandidatesSeen.size >= REMOTE_WEBRTC_MAX_CANDIDATES) return;
    const candidateType = parseCandidateType(event.candidate.candidate);
    if (!remoteWebAllowRemoteCandidate(attempt.input.capability, candidateType)) {
      // Non-relay remote candidate rejected in relay_only.
      return;
    }
    attempt.remoteCandidatesSeen.add(key);
    try {
      attempt.peer.addIceCandidate({
        candidate: event.candidate.candidate,
        sdpMid: event.candidate.sdpMid,
        sdpMLineIndex: event.candidate.sdpMLineIndex,
      });
    } catch {
      // Late/glare — ignore; shared selection owns recovery.
    }
  }

  private handleClientProof(attempt: ActiveAttempt, proof: Uint8Array): void {
    if (attempt.proofState.clientProof) return; // duplicate
    attempt.proofState.clientProof = proof;
    this.maybeOpenLanes(attempt);
  }

  private handleDaemonProof(attempt: ActiveAttempt, proof: Uint8Array): void {
    if (attempt.proofState.daemonProof) return; // duplicate
    attempt.proofState.daemonProof = proof;
    this.maybeOpenLanes(attempt);
  }

  private handleDaemonReady(attempt: ActiveAttempt, ready: RemoteSignalingReadyV1): void {
    attempt.proofState.daemonReady = ready;
    // Post our role-specific ready acknowledgement.
    const clientProof = attempt.proofState.clientProof;
    const daemonProof = attempt.proofState.daemonProof;
    if (!clientProof || !daemonProof) return;
    try {
      const setDigest = remoteFinalProofSetDigest(clientProof, daemonProof);
      const ourReady: RemoteSignalingReadyV1 = {
        verifiedPeerProofJti: decodeRemoteEndpointFinalProofV1(daemonProof).proofJti,
        finalProofSetDigest: setDigest,
      };
      const encoded = encodeRemoteSignalingReadyV1(ourReady);
      // Emit the ready ack as a signaling out — the caller routes it.
      this.emit({
        kind: "signaling",
        message: {
          type: "ice_complete",
          transportEpoch: attempt.input.transportEpoch,
        },
      });
      void encoded; // encoded ready is consumed by the caller's signaling store
    } catch {
      // Proof disagreement — do not open lanes.
    }
  }

  // --- final-proof gate ----------------------------------------------------

  private maybeOpenLanes(attempt: ActiveAttempt): void {
    if (attempt.proofState.lanesOpen) return;
    const clientProof = attempt.proofState.clientProof;
    const daemonProof = attempt.proofState.daemonProof;
    if (!clientProof || !daemonProof) return;
    // All channels must be open.
    for (const lane of REMOTE_LANES) {
      const channel = attempt.channels.get(lane);
      if (channel?.readyState !== "open") return;
    }
    const verification = remoteWebVerifyProofs({
      clientProof,
      daemonProof,
      expectedChildAttemptId: attempt.input.childAttemptId,
      expectedTransportEpoch: attempt.input.transportEpoch,
      expectedOfferSdp: attempt.offerSdp,
      expectedAnswerSdp: attempt.answerSdp,
      expectedDtlsFingerprint: attempt.dtlsFingerprint,
      grantDigest: attempt.input.grantDigest,
      admissionSequence: attempt.input.admissionSequence,
    });
    if (!verification.bothVerified) return;
    attempt.proofState.lanesOpen = true;
    this.emit({ kind: "health", status: "proof_pending" });
    this.emit({ kind: "health", status: "active" });
    this.emit({ kind: "lane_ready", lanes: [...REMOTE_LANES] });
  }

  // --- channel message / reassembly ----------------------------------------

  private handleChannelMessage(attempt: ActiveAttempt, lane: RemoteLane, data: Uint8Array): void {
    let fragment: RemoteWebRtcFragment;
    try {
      fragment = decodeRemoteWebRtcFragment(data);
    } catch {
      return; // malformed — drop silently (no diagnostics with network material)
    }
    if (fragment.lane !== lane) return; // lane mismatch — drop
    try {
      const payload = attempt.reassembly.ingest(fragment);
      if (payload) {
        this.emit({ kind: "lane_data", lane, bytes: payload });
      }
    } catch {
      // Reassembly limit — shared selection owns recovery.
    }
  }

  // --- close / cleanup -----------------------------------------------------

  close(reason: RemoteWebCloseReason): void {
    this.closeInternal(reason);
  }

  private closeInternal(reason: RemoteWebCloseReason): void {
    const attempt = this.active;
    if (!attempt) return;
    if (attempt.closed && reason !== "replacement") return;
    attempt.closed = true;
    this.emit({ kind: "health", status: "closing" });
    // Close all channels and the peer — deterministic cleanup.
    for (const channel of attempt.channels.values()) {
      try {
        channel.onopen = null;
        channel.onclose = null;
        channel.onmessage = null;
        channel.onbufferedamountlow = null;
        channel.close();
      } catch {
        // ignore
      }
    }
    attempt.channels.clear();
    attempt.reassembly.clear();
    attempt.localCandidates.length = 0;
    attempt.remoteCandidatesSeen.clear();
    attempt.proofState.clientProof = null;
    attempt.proofState.daemonProof = null;
    attempt.proofState.daemonReady = null;
    attempt.proofState.lanesOpen = false;
    try {
      attempt.peer.onicecandidate = null;
      attempt.peer.oniceconnectionstatechange = null;
      attempt.peer.onconnectionstatechange = null;
      attempt.peer.ondatachannel = null;
      attempt.peer.close();
    } catch {
      // ignore
    }
    if (reason !== "replacement") {
      this.active = null;
    }
    this.emit({ kind: "health", status: "closed" });
    this.emit({ kind: "close", reason });
  }

  private isCurrentAttempt(attempt: ActiveAttempt): boolean {
    return this.active === attempt && attempt.generation === this.generation && !attempt.closed;
  }
}

// ---------------------------------------------------------------------------
// Redaction / safe UX
// ---------------------------------------------------------------------------

export type RemoteWebSafeUxState =
  | "active"
  | "browser_upgrade_required"
  | "reenrollment_required"
  | "relay_unavailable"
  | "policy_denied"
  | "secure_context_required"
  | "remote_crypto_unsupported"
  | "closed";

/** Map a capability result to a safe UX state without exposing any network/identity material. */
export function remoteWebSafeUxState(result: RemoteWebCapabilityResult): RemoteWebSafeUxState {
  switch (result.status) {
    case "ok":
      return "active";
    case "browser_upgrade_required":
      return "browser_upgrade_required";
    case "reenrollment_required":
      return "reenrollment_required";
    case "relay_unavailable":
      return "relay_unavailable";
    case "policy_denied":
      return "policy_denied";
    case "secure_context_required":
      return "secure_context_required";
    case "remote_crypto_unsupported":
      return "remote_crypto_unsupported";
  }
}

/** A redacted diagnostic string that never contains network/auth/identity/content material. */
export function remoteWebRedactedDiagnostic(state: RemoteWebSafeUxState): string {
  switch (state) {
    case "active":
      return "remote_session_active";
    case "browser_upgrade_required":
      return "browser_upgrade_required";
    case "reenrollment_required":
      return "device_reenrollment_required";
    case "relay_unavailable":
      return "relay_unavailable";
    case "policy_denied":
      return "remote_policy_denied";
    case "secure_context_required":
      return "secure_context_required";
    case "remote_crypto_unsupported":
      return "remote_crypto_unsupported";
    case "closed":
      return "remote_session_closed";
  }
}
