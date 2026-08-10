import transitionFixture from "../fixtures/remote/signaling-attempt-store-v1.json";
import { remoteIdentitySha256Sync } from "./remote-identity-protocol";
import {
  decodeRemoteEndpointFinalProofV1,
  remoteEndpointFinalProofAgreementBytes,
} from "./remote-signaling-payloads";

export const REMOTE_SIGNALING_REQUEST_MAGIC = "FCSE";
export const REMOTE_SIGNALING_ACK_MAGIC = "FCAK";
export const REMOTE_SIGNALING_VERSION = 1;
export const REMOTE_SIGNALING_HEADER_BYTES = 44;
export const REMOTE_SIGNALING_MAX_REQUEST_BYTES = 131_072;
export const REMOTE_SIGNALING_MAX_PAYLOAD_BYTES = 131_028;
export const REMOTE_SIGNALING_MAX_EVENTS = 256;
export const REMOTE_SIGNALING_MAX_AGGREGATE_BYTES = 2 * 1024 * 1024;
export const REMOTE_SIGNALING_MAX_CANDIDATES_PER_ROLE = 64;
export const REMOTE_SIGNALING_ATTEMPT_TTL_MS = 5 * 60_000;
export const RemoteSignalingTransport = { webrtc: 1, websocket_data: 2 } as const;
export const RemoteSignalingProducerRole = { server: 1, client: 2, daemon: 3 } as const;
export const RemoteSignalingEventKind = {
  attempt_available: 1,
  daemon_admission_offer: 2,
  client_admission_proof: 3,
  offer: 4,
  answer: 5,
  ice_candidate: 6,
  ice_complete: 7,
  fallback_pair_authenticated: 8,
  fallback_noise_complete: 9,
  client_final_proof: 10,
  daemon_final_proof: 11,
  ready: 12,
  attempt_rejected: 13,
  attempt_cancelled: 14,
  attempt_superseded: 15,
} as const;
export interface RemoteSignalingTransitionV1 {
  transport: "common" | "webrtc" | "websocket_data";
  event: keyof typeof RemoteSignalingEventKind;
  role: "server" | "client" | "daemon";
  from: string;
  to: string;
  prerequisites: readonly string[];
  result: string;
  slotCardinality: "repeatable" | "one_per_role" | "one_terminal" | "one_per_attempt";
}
const transitionValues = {
  transport: new Set(["common", "webrtc", "websocket_data"]),
  role: new Set(["server", "client", "daemon"]),
  slot: new Set(["repeatable", "one_per_role", "one_terminal", "one_per_attempt"]),
};
export const REMOTE_SIGNALING_TRANSITION_ROWS: readonly RemoteSignalingTransitionV1[] =
  transitionFixture.transitions.map((row) => {
    if (
      !transitionValues.transport.has(row.transport) ||
      !(row.event in RemoteSignalingEventKind) ||
      !transitionValues.role.has(row.role) ||
      !transitionValues.slot.has(row.slotCardinality)
    )
      throw new Error("invalid generated remote signaling transition row");
    return row as RemoteSignalingTransitionV1;
  });
export const REMOTE_SIGNALING_REQUEST_VECTORS = transitionFixture.requests;
export type RemoteSignalingTransportV1 = 1 | 2;
export type RemoteSignalingProducerRoleV1 = 1 | 2 | 3;
export type RemoteSignalingEventKindV1 =
  | 1
  | 2
  | 3
  | 4
  | 5
  | 6
  | 7
  | 8
  | 9
  | 10
  | 11
  | 12
  | 13
  | 14
  | 15;

export interface RemoteSignalingEventRequestV1 {
  transport: RemoteSignalingTransportV1;
  producerRole: RemoteSignalingProducerRoleV1;
  eventKind: RemoteSignalingEventKindV1;
  childAttemptId: Uint8Array;
  eventId: Uint8Array;
  payload: Uint8Array;
}
export interface RemoteSignalingCommitAckV1 {
  eventId: Uint8Array;
  sequence: bigint;
  eventDigest: Uint8Array;
}
export class RemoteSignalingCodecError extends Error {}
const te = new TextEncoder();
const DIGEST_DOMAIN = te.encode("flycockpit.remote.signaling-event-request.v1\0");
const FINAL_PROOF_DOMAIN = te.encode("flycockpit.remote.endpoint-final-proof-set.v1\0");

function fail(message: string): never {
  throw new RemoteSignalingCodecError(message);
}
function id16(value: Uint8Array, name: string) {
  if (value.length !== 16 || value.every((byte) => byte === 0))
    fail(`${name} must be nonzero 16 bytes`);
}
function enumRange(value: number, max: number, name: string) {
  if (!Number.isInteger(value) || value < 1 || value > max) fail(`unknown ${name}`);
}
function concat(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function preamble(bytes: Uint8Array, magic: string) {
  return bytes.length >= 5 && String.fromCharCode(...bytes.slice(0, 4)) === magic && bytes[4] === 1;
}
function validateCombination(request: RemoteSignalingEventRequestV1) {
  const { transport, producerRole: role, eventKind: kind } = request;
  if (
    (kind === 4 && (transport !== 1 || role !== 2)) ||
    (kind === 5 && (transport !== 1 || role !== 3))
  )
    fail("transport or role disagrees with event kind");
  if ((kind === 8 || kind === 9) && transport !== 2)
    fail("transport disagrees with fallback event");
  if (kind === 8 && role !== 1) fail("fallback pair requires server");
  if (kind === 1 && role !== 1) fail("attempt_available requires server");
  if (kind === 2 && role !== 3) fail("daemon admission offer requires daemon");
  if (kind === 3 && role !== 2) fail("client admission proof requires client");
  if (kind === 10 && role !== 2) fail("client final proof requires client");
  if (kind === 11 && role !== 3) fail("daemon final proof requires daemon");
  if ([6, 7, 9, 12, 14].includes(kind) && role !== 2 && role !== 3)
    fail("event requires client or daemon");
  if (kind === 13 && role !== 1 && role !== 3) fail("attempt rejection requires server or daemon");
  if (kind === 15 && role !== 1) fail("attempt supersession requires server");
  if ((kind === 6 || kind === 7) && transport !== 1) fail("ICE event requires WebRTC");
}

function validateTerminalPayload(request: RemoteSignalingEventRequestV1) {
  const { eventKind: kind, payload } = request;
  if (kind === 13 || kind === 14) {
    if (payload.length !== 2 || payload[0] !== 1 || payload[1]! < 1 || payload[1]! > 11)
      fail("invalid terminal reason");
    const allowed = kind === 13 ? [1, 2, 3, 4, 6, 7, 9, 10, 11] : [4, 5, 7, 8, 9, 10, 11];
    if (!allowed.includes(payload[1]!)) fail("reason illegal for terminal event");
  }
  if (kind === 15) {
    id16(payload, "replacementAttemptId");
    if (payload.every((byte, index) => byte === request.childAttemptId[index]))
      fail("replacement attempt must differ");
  }
}

export function encodeRemoteSignalingEventRequestV1(request: RemoteSignalingEventRequestV1) {
  enumRange(request.transport, 2, "transport");
  enumRange(request.producerRole, 3, "producer role");
  enumRange(request.eventKind, 15, "event kind");
  id16(request.childAttemptId, "childAttemptId");
  id16(request.eventId, "eventId");
  validateCombination(request);
  validateTerminalPayload(request);
  if (request.payload.length > REMOTE_SIGNALING_MAX_PAYLOAD_BYTES) fail("payload exceeds cap");
  const out = new Uint8Array(REMOTE_SIGNALING_HEADER_BYTES + request.payload.length);
  out.set(te.encode(REMOTE_SIGNALING_REQUEST_MAGIC));
  out[4] = 1;
  out[5] = request.transport;
  out[6] = request.producerRole;
  out[7] = request.eventKind;
  out.set(request.childAttemptId, 8);
  out.set(request.eventId, 24);
  new DataView(out.buffer).setUint32(40, request.payload.length);
  out.set(request.payload, REMOTE_SIGNALING_HEADER_BYTES);
  return out;
}
export function decodeRemoteSignalingEventRequestV1(
  bytes: Uint8Array,
): RemoteSignalingEventRequestV1 {
  if (bytes.length < REMOTE_SIGNALING_HEADER_BYTES) fail("truncated request");
  if (bytes.length > REMOTE_SIGNALING_MAX_REQUEST_BYTES) fail("request exceeds cap");
  if (!preamble(bytes, REMOTE_SIGNALING_REQUEST_MAGIC)) fail("wrong magic or version");
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(40);
  if (
    length > REMOTE_SIGNALING_MAX_PAYLOAD_BYTES ||
    length !== bytes.length - REMOTE_SIGNALING_HEADER_BYTES
  )
    fail("payload length mismatch");
  const request: RemoteSignalingEventRequestV1 = {
    transport: bytes[5] as RemoteSignalingTransportV1,
    producerRole: bytes[6] as RemoteSignalingProducerRoleV1,
    eventKind: bytes[7] as RemoteSignalingEventKindV1,
    childAttemptId: bytes.slice(8, 24),
    eventId: bytes.slice(24, 40),
    payload: bytes.slice(44),
  };
  enumRange(request.transport, 2, "transport");
  enumRange(request.producerRole, 3, "producer role");
  enumRange(request.eventKind, 15, "event kind");
  id16(request.childAttemptId, "childAttemptId");
  id16(request.eventId, "eventId");
  validateCombination(request);
  validateTerminalPayload(request);
  return request;
}
export function remoteSignalingEventDigest(bytes: Uint8Array) {
  decodeRemoteSignalingEventRequestV1(bytes);
  return remoteIdentitySha256Sync(concat(DIGEST_DOMAIN, bytes));
}
export function encodeRemoteSignalingCommitAckV1(ack: RemoteSignalingCommitAckV1) {
  id16(ack.eventId, "eventId");
  if (ack.sequence < 1n || ack.sequence > 0xffffffffffffffffn) fail("invalid sequence");
  if (ack.eventDigest.length !== 32) fail("eventDigest must be 32 bytes");
  const out = new Uint8Array(61);
  out.set(te.encode(REMOTE_SIGNALING_ACK_MAGIC));
  out[4] = 1;
  out.set(ack.eventId, 5);
  new DataView(out.buffer).setBigUint64(21, ack.sequence);
  out.set(ack.eventDigest, 29);
  return out;
}
export function decodeRemoteSignalingCommitAckV1(bytes: Uint8Array): RemoteSignalingCommitAckV1 {
  if (bytes.length !== 61 || !preamble(bytes, REMOTE_SIGNALING_ACK_MAGIC))
    fail("invalid commit ACK");
  const ack = {
    eventId: bytes.slice(5, 21),
    sequence: new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(21),
    eventDigest: bytes.slice(29, 61),
  };
  id16(ack.eventId, "eventId");
  if (ack.sequence === 0n || ack.eventDigest.length !== 32) fail("invalid commit ACK");
  return ack;
}
export function remoteFinalProofSetDigest(clientProof: Uint8Array, daemonProof: Uint8Array) {
  if (
    !clientProof.length ||
    clientProof.length > 512 ||
    !daemonProof.length ||
    daemonProof.length > 512
  )
    fail("invalid final proof length");
  const client = decodeRemoteEndpointFinalProofV1(clientProof),
    daemon = decodeRemoteEndpointFinalProofV1(daemonProof);
  const clientAgreement = remoteEndpointFinalProofAgreementBytes(client);
  const daemonAgreement = remoteEndpointFinalProofAgreementBytes(daemon);
  if (
    client.role !== 1 ||
    daemon.role !== 2 ||
    clientAgreement.length !== daemonAgreement.length ||
    !clientAgreement.every((byte, index) => byte === daemonAgreement[index])
  )
    fail("final proofs disagree or have swapped roles");
  const lengths = new Uint8Array(4),
    view = new DataView(lengths.buffer);
  view.setUint16(0, clientProof.length);
  view.setUint16(2, daemonProof.length);
  return remoteIdentitySha256Sync(
    concat(FINAL_PROOF_DOMAIN, lengths.slice(0, 2), clientProof, lengths.slice(2), daemonProof),
  );
}

export interface RemoteWebRtcDescriptionV1 {
  childAttemptId: Uint8Array;
  transportEpoch: Uint8Array;
  descriptionId: Uint8Array;
  sdp: Uint8Array;
}
function canonicalSdp(sdp: Uint8Array) {
  if (sdp.length < 1 || sdp.length > 122_880) fail("SDP length");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(sdp);
  } catch {
    return fail("invalid SDP UTF-8");
  }
  if (
    (sdp[0] === 0xef && sdp[1] === 0xbb && sdp[2] === 0xbf) ||
    text.includes("\0") ||
    !text.endsWith("\r\n") ||
    /(^|[^\r])\n|\r(?!\n)/.test(text)
  )
    fail("noncanonical SDP line endings");
}
function encodeDescription(value: RemoteWebRtcDescriptionV1, answer: boolean) {
  id16(value.childAttemptId, "childAttemptId");
  id16(value.transportEpoch, "transportEpoch");
  id16(value.descriptionId, answer ? "answerId" : "offerId");
  canonicalSdp(value.sdp);
  const out = new Uint8Array(58 + value.sdp.length);
  out.set(te.encode(answer ? "FCWN" : "FCWO"));
  out[4] = 1;
  out[5] = answer ? 2 : 1;
  out.set(value.childAttemptId, 6);
  out.set(value.transportEpoch, 22);
  out.set(value.descriptionId, 38);
  new DataView(out.buffer).setUint32(54, value.sdp.length);
  out.set(value.sdp, 58);
  return out;
}
function decodeDescription(bytes: Uint8Array, answer: boolean): RemoteWebRtcDescriptionV1 {
  if (
    bytes.length < 59 ||
    !preamble(bytes, answer ? "FCWN" : "FCWO") ||
    bytes[5] !== (answer ? 2 : 1)
  )
    fail("invalid WebRTC description");
  const length = new DataView(bytes.buffer, bytes.byteOffset).getUint32(54);
  if (bytes.length !== 58 + length) fail("SDP length mismatch");
  const value = {
    childAttemptId: bytes.slice(6, 22),
    transportEpoch: bytes.slice(22, 38),
    descriptionId: bytes.slice(38, 54),
    sdp: bytes.slice(58),
  };
  id16(value.childAttemptId, "childAttemptId");
  id16(value.transportEpoch, "transportEpoch");
  id16(value.descriptionId, answer ? "answerId" : "offerId");
  canonicalSdp(value.sdp);
  return value;
}
export const encodeRemoteWebRtcOfferV1 = (value: RemoteWebRtcDescriptionV1) =>
  encodeDescription(value, false);
export const decodeRemoteWebRtcOfferV1 = (bytes: Uint8Array) => decodeDescription(bytes, false);
export const encodeRemoteWebRtcAnswerV1 = (value: RemoteWebRtcDescriptionV1) =>
  encodeDescription(value, true);
export const decodeRemoteWebRtcAnswerV1 = (bytes: Uint8Array) => decodeDescription(bytes, true);

export interface RemoteWebRtcCandidateV1 {
  role: 1 | 2;
  childAttemptId: Uint8Array;
  transportEpoch: Uint8Array;
  candidateId: Uint8Array;
  sdpMid: string;
  sdpMLineIndex: number;
  candidate: string;
}
function visibleToken(value: string, name: string) {
  const raw = te.encode(value);
  if (!raw.length || !raw.every((byte) => byte >= 0x21 && byte <= 0x7e)) fail(`invalid ${name}`);
  return raw;
}
function canonicalCandidate(value: string) {
  const raw = te.encode(value);
  if (
    !raw.length ||
    !raw.every((byte) => byte >= 0x20 && byte <= 0x7e) ||
    !value.startsWith("candidate:") ||
    value.startsWith(" ") ||
    value.endsWith(" ") ||
    value.includes("  ")
  )
    fail("invalid candidate");
  return raw;
}
export function encodeRemoteWebRtcCandidateV1(value: RemoteWebRtcCandidateV1) {
  enumRange(value.role, 2, "candidate role");
  id16(value.childAttemptId, "childAttemptId");
  id16(value.transportEpoch, "transportEpoch");
  id16(value.candidateId, "candidateId");
  const mid = visibleToken(value.sdpMid, "sdpMid"),
    candidate = canonicalCandidate(value.candidate);
  if (
    mid.length > 255 ||
    candidate.length > 0xffff ||
    !Number.isInteger(value.sdpMLineIndex) ||
    value.sdpMLineIndex < 0 ||
    value.sdpMLineIndex > 0xffff
  )
    fail("invalid candidate");
  const out = new Uint8Array(59 + mid.length + candidate.length);
  out.set(te.encode("FCWC"));
  out[4] = 1;
  out[5] = value.role;
  out.set(value.childAttemptId, 6);
  out.set(value.transportEpoch, 22);
  out.set(value.candidateId, 38);
  out[54] = mid.length;
  out.set(mid, 55);
  const view = new DataView(out.buffer);
  view.setUint16(55 + mid.length, value.sdpMLineIndex);
  view.setUint16(57 + mid.length, candidate.length);
  out.set(candidate, 59 + mid.length);
  if (out.length > 4096) fail("candidate exceeds cap");
  return out;
}
export function decodeRemoteWebRtcCandidateV1(bytes: Uint8Array): RemoteWebRtcCandidateV1 {
  if (bytes.length < 61 || bytes.length > 4096 || !preamble(bytes, "FCWC"))
    fail("invalid candidate frame");
  const role = bytes[5] as 1 | 2;
  enumRange(role, 2, "candidate role");
  const childAttemptId = bytes.slice(6, 22),
    transportEpoch = bytes.slice(22, 38),
    candidateId = bytes.slice(38, 54);
  id16(childAttemptId, "childAttemptId");
  id16(transportEpoch, "transportEpoch");
  id16(candidateId, "candidateId");
  const midLength = bytes[54]!,
    view = new DataView(bytes.buffer, bytes.byteOffset);
  if (!midLength || 59 + midLength > bytes.length) fail("invalid sdpMid length");
  const sdpMid = new TextDecoder().decode(bytes.slice(55, 55 + midLength));
  const sdpMLineIndex = view.getUint16(55 + midLength),
    length = view.getUint16(57 + midLength);
  if (59 + midLength + length !== bytes.length) fail("candidate length mismatch");
  const candidate = new TextDecoder().decode(bytes.slice(59 + midLength));
  visibleToken(sdpMid, "sdpMid");
  canonicalCandidate(candidate);
  return { role, childAttemptId, transportEpoch, candidateId, sdpMid, sdpMLineIndex, candidate };
}
export interface RemoteWebRtcIceCompleteV1 {
  role: 1 | 2;
  childAttemptId: Uint8Array;
  transportEpoch: Uint8Array;
}
export function encodeRemoteWebRtcIceCompleteV1(value: RemoteWebRtcIceCompleteV1) {
  enumRange(value.role, 2, "ICE role");
  id16(value.childAttemptId, "childAttemptId");
  id16(value.transportEpoch, "transportEpoch");
  const out = new Uint8Array(38);
  out.set(te.encode("FCWE"));
  out[4] = 1;
  out[5] = value.role;
  out.set(value.childAttemptId, 6);
  out.set(value.transportEpoch, 22);
  return out;
}
export function decodeRemoteWebRtcIceCompleteV1(bytes: Uint8Array): RemoteWebRtcIceCompleteV1 {
  if (bytes.length !== 38 || !preamble(bytes, "FCWE")) fail("invalid ICE complete");
  const role = bytes[5] as 1 | 2;
  enumRange(role, 2, "ICE role");
  const childAttemptId = bytes.slice(6, 22),
    transportEpoch = bytes.slice(22, 38);
  id16(childAttemptId, "childAttemptId");
  id16(transportEpoch, "transportEpoch");
  return { role, childAttemptId, transportEpoch };
}
