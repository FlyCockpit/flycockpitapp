/**
 * Exact binary codecs for the remote signaling gateway pre-auth frames and
 * the durable control event header.
 *
 * All frames are network byte order (big-endian) and exact-length.
 * Noncanonical, trailing, or coalesced bytes fail before any state mutation.
 */
import {
  REMOTE_GATEWAY_MAX_ADMISSION_PROOF_BYTES,
  REMOTE_GATEWAY_MAX_CERTIFICATE_JWS_BYTES,
  REMOTE_GATEWAY_MAX_FCDA_BYTES,
  REMOTE_GATEWAY_MAX_FCSA_BYTES,
} from "./close-codes";

export class RemoteGatewayCodecError extends Error {}

const te = new TextEncoder();
const fail = (message: string): never => {
  throw new RemoteGatewayCodecError(message);
};

function id16(value: Uint8Array, name: string) {
  if (value.length !== 16 || value.every((byte) => byte === 0))
    fail(`${name} must be nonzero 16 bytes`);
}

// ---------------------------------------------------------------------------
// FCDC — server daemon challenge (53 bytes)
//   magic="FCDC"[4] | version:u8(1) | challenge:[32] | issuedAt:i64 | expiresAt:i64
// ---------------------------------------------------------------------------
export const FCDC_BYTES = 53;
export const FCDC_MAGIC = "FCDC";

export function encodeFcdcFrame(value: {
  challenge: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
}): Uint8Array {
  if (value.challenge.length !== 32) fail("FCDC challenge must be 32 bytes");
  if (value.issuedAt >= value.expiresAt) fail("FCDC issuedAt must precede expiresAt");
  const out = new Uint8Array(FCDC_BYTES);
  out.set(te.encode(FCDC_MAGIC));
  out[4] = 1;
  out.set(value.challenge, 5);
  const view = new DataView(out.buffer);
  view.setBigInt64(37, value.issuedAt);
  view.setBigInt64(45, value.expiresAt);
  return out;
}

export function decodeFcdcFrame(bytes: Uint8Array): {
  challenge: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
} {
  if (bytes.length !== FCDC_BYTES) fail("FCDC length");
  if (String.fromCharCode(...bytes.slice(0, 4)) !== FCDC_MAGIC || bytes[4] !== 1)
    fail("FCDC magic/version");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const challenge = bytes.slice(5, 37);
  if (challenge.every((b) => b === 0)) fail("FCDC challenge must be nonzero");
  return {
    challenge,
    issuedAt: view.getBigInt64(37),
    expiresAt: view.getBigInt64(45),
  };
}

// ---------------------------------------------------------------------------
// FCDA — daemon auth response (≤4,215 bytes)
//   magic="FCDA"[4] | version:u8(1) | certificateLength:u16 | certificateJws
//   | connectionNonce:[32] | lastDiscoverySeq:u64 | lastControlSeq:u64 | signature:[64]
// ---------------------------------------------------------------------------
export const FCDA_MAGIC = "FCDA";
export const FCDA_MIN_BYTES = 4 + 1 + 2 + 32 + 8 + 8 + 64; // 119 + min cert

export function encodeFcdaFrame(value: {
  certificateJws: Uint8Array;
  connectionNonce: Uint8Array;
  lastDiscoverySeq: bigint;
  lastControlSeq: bigint;
  signature: Uint8Array;
}): Uint8Array {
  if (
    !value.certificateJws.length ||
    value.certificateJws.length > REMOTE_GATEWAY_MAX_CERTIFICATE_JWS_BYTES
  )
    fail("FCDA certificate length");
  if (value.connectionNonce.length !== 32) fail("FCDA connectionNonce must be 32 bytes");
  if (value.signature.length !== 64) fail("FCDA signature must be 64 bytes");
  const out = new Uint8Array(4 + 1 + 2 + value.certificateJws.length + 32 + 8 + 8 + 64);
  out.set(te.encode(FCDA_MAGIC));
  out[4] = 1;
  const view = new DataView(out.buffer);
  view.setUint16(5, value.certificateJws.length);
  out.set(value.certificateJws, 7);
  out.set(value.connectionNonce, 7 + value.certificateJws.length);
  const nonceEnd = 7 + value.certificateJws.length + 32;
  view.setBigUint64(nonceEnd, value.lastDiscoverySeq);
  view.setBigUint64(nonceEnd + 8, value.lastControlSeq);
  out.set(value.signature, nonceEnd + 16);
  if (out.length > REMOTE_GATEWAY_MAX_FCDA_BYTES) fail("FCDA cap");
  return out;
}

export function decodeFcdaFrame(bytes: Uint8Array): {
  certificateJws: Uint8Array;
  connectionNonce: Uint8Array;
  lastDiscoverySeq: bigint;
  lastControlSeq: bigint;
  signature: Uint8Array;
  bytesBeforeSignature: Uint8Array;
} {
  if (bytes.length < FCDA_MIN_BYTES || bytes.length > REMOTE_GATEWAY_MAX_FCDA_BYTES)
    fail("FCDA length");
  if (String.fromCharCode(...bytes.slice(0, 4)) !== FCDA_MAGIC || bytes[4] !== 1)
    fail("FCDA magic/version");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const certLen = view.getUint16(5);
  if (certLen === 0 || certLen > REMOTE_GATEWAY_MAX_CERTIFICATE_JWS_BYTES) fail("FCDA cert length");
  const expected = 7 + certLen + 32 + 8 + 8 + 64;
  if (bytes.length !== expected) fail("FCDA trailing/truncated");
  const certificateJws = bytes.slice(7, 7 + certLen);
  const connectionNonce = bytes.slice(7 + certLen, 7 + certLen + 32);
  if (connectionNonce.every((b) => b === 0)) fail("FCDA nonce must be nonzero");
  const nonceEnd = 7 + certLen + 32;
  const lastDiscoverySeq = view.getBigUint64(nonceEnd);
  const lastControlSeq = view.getBigUint64(nonceEnd + 8);
  const signature = bytes.slice(nonceEnd + 16);
  const bytesBeforeSignature = bytes.slice(0, nonceEnd + 16);
  return {
    certificateJws,
    connectionNonce,
    lastDiscoverySeq,
    lastControlSeq,
    signature,
    bytesBeforeSignature,
  };
}

// ---------------------------------------------------------------------------
// FCSA — client auth response (≤564 bytes)
//   magic="FCSA"[4] | version:u8(1) | ticketId:[16] | ticketSecret:[32]
//   | admissionProofLength:u16 | admissionProof
// ---------------------------------------------------------------------------
export const FCSA_MAGIC = "FCSA";

export function encodeFcsaFrame(value: {
  ticketId: Uint8Array;
  ticketSecret: Uint8Array;
  admissionProof: Uint8Array;
}): Uint8Array {
  id16(value.ticketId, "FCSA ticketId");
  if (value.ticketSecret.length !== 32) fail("FCSA ticketSecret must be 32 bytes");
  if (
    !value.admissionProof.length ||
    value.admissionProof.length > REMOTE_GATEWAY_MAX_ADMISSION_PROOF_BYTES
  )
    fail("FCSA admissionProof length");
  const out = new Uint8Array(4 + 1 + 16 + 32 + 2 + value.admissionProof.length);
  out.set(te.encode(FCSA_MAGIC));
  out[4] = 1;
  out.set(value.ticketId, 5);
  out.set(value.ticketSecret, 21);
  const view = new DataView(out.buffer);
  view.setUint16(53, value.admissionProof.length);
  out.set(value.admissionProof, 55);
  if (out.length > REMOTE_GATEWAY_MAX_FCSA_BYTES) fail("FCSA cap");
  return out;
}

export function decodeFcsaFrame(bytes: Uint8Array): {
  ticketId: Uint8Array;
  ticketSecret: Uint8Array;
  admissionProof: Uint8Array;
} {
  if (bytes.length < 55 || bytes.length > REMOTE_GATEWAY_MAX_FCSA_BYTES) fail("FCSA length");
  if (String.fromCharCode(...bytes.slice(0, 4)) !== FCSA_MAGIC || bytes[4] !== 1)
    fail("FCSA magic/version");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const proofLen = view.getUint16(53);
  if (
    proofLen === 0 ||
    proofLen > REMOTE_GATEWAY_MAX_ADMISSION_PROOF_BYTES ||
    bytes.length !== 55 + proofLen
  )
    fail("FCSA proof length/trailing");
  const ticketId = bytes.slice(5, 21);
  id16(ticketId, "FCSA ticketId");
  const ticketSecret = bytes.slice(21, 53);
  if (ticketSecret.every((b) => b === 0)) fail("FCSA ticketSecret must be nonzero");
  const admissionProof = bytes.slice(55);
  return { ticketId, ticketSecret, admissionProof };
}

// ---------------------------------------------------------------------------
// RemoteControlEventV1 — canonical network-byte-order durable control event
//   magic="FCRC"[4] | version:u8(1) | controlSeq:u64 | eventId:[16] | kind:u8
//   | serviceVersion:u64 | policyEpoch:u64 | authorityEpoch:u64 | issuedAt:i64
//   | payloadLength:u32 | payloadDigest:[32] | payload
//   Header is exactly 98 bytes; payload ≤65,536; whole event ≤65,634.
// ---------------------------------------------------------------------------
export const FCRC_MAGIC = "FCRC";
export const REMOTE_CONTROL_EVENT_HEADER_BYTES = 98;
export const REMOTE_CONTROL_EVENT_MAX_PAYLOAD = 65_536;
export const REMOTE_CONTROL_EVENT_MAX_BYTES = 65_634;
export const REMOTE_CONTROL_EVENT_MAX_COMPACT_JWS = 96 * 1024;

export const RemoteControlEventKind = {
  lease_refresh: 1,
  policy_narrowed: 2,
  device_revoked: 3,
  instance_revoked: 4,
  tenant_authority_changed: 5,
  attachment_revoked: 6,
  drain: 7,
  authority_status: 8,
} as const;
export type RemoteControlEventKindV1 =
  (typeof RemoteControlEventKind)[keyof typeof RemoteControlEventKind];

export interface RemoteControlEventV1 {
  controlSeq: bigint;
  eventId: Uint8Array;
  kind: RemoteControlEventKindV1;
  serviceVersion: bigint;
  policyEpoch: bigint;
  authorityEpoch: bigint;
  issuedAt: bigint;
  payload: Uint8Array;
}

export function encodeRemoteControlEventHeader(value: {
  controlSeq: bigint;
  eventId: Uint8Array;
  kind: RemoteControlEventKindV1;
  serviceVersion: bigint;
  policyEpoch: bigint;
  authorityEpoch: bigint;
  issuedAt: bigint;
  payloadLength: number;
  payloadDigest: Uint8Array;
}): Uint8Array {
  id16(value.eventId, "FCRC eventId");
  if (value.controlSeq < 1n) fail("FCRC controlSeq must be ≥1");
  if (value.payloadDigest.length !== 32) fail("FCRC payloadDigest must be 32 bytes");
  if (value.payloadLength > REMOTE_CONTROL_EVENT_MAX_PAYLOAD) fail("FCRC payload cap");
  const out = new Uint8Array(REMOTE_CONTROL_EVENT_HEADER_BYTES);
  out.set(te.encode(FCRC_MAGIC));
  out[4] = 1;
  const view = new DataView(out.buffer);
  view.setBigUint64(5, value.controlSeq);
  out.set(value.eventId, 13);
  out[29] = value.kind;
  view.setBigUint64(30, value.serviceVersion);
  view.setBigUint64(38, value.policyEpoch);
  view.setBigUint64(46, value.authorityEpoch);
  view.setBigInt64(54, value.issuedAt);
  view.setUint32(62, payloadLengthOrThrow(value.payloadLength));
  out.set(value.payloadDigest, 66);
  return out;
}

function payloadLengthOrThrow(length: number): number {
  if (!Number.isInteger(length) || length < 0 || length > REMOTE_CONTROL_EVENT_MAX_PAYLOAD)
    fail("FCRC payload length");
  return length;
}

export function decodeRemoteControlEventHeader(bytes: Uint8Array): {
  controlSeq: bigint;
  eventId: Uint8Array;
  kind: RemoteControlEventKindV1;
  serviceVersion: bigint;
  policyEpoch: bigint;
  authorityEpoch: bigint;
  issuedAt: bigint;
  payloadLength: number;
  payloadDigest: Uint8Array;
} {
  if (bytes.length !== REMOTE_CONTROL_EVENT_HEADER_BYTES) fail("FCRC header length");
  if (String.fromCharCode(...bytes.slice(0, 4)) !== FCRC_MAGIC || bytes[4] !== 1)
    fail("FCRC magic/version");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const controlSeq = view.getBigUint64(5);
  const eventId = bytes.slice(13, 29);
  id16(eventId, "FCRC eventId");
  const kind = bytes[29] as RemoteControlEventKindV1;
  if (kind < 1 || kind > 8) fail("FCRC unknown kind");
  const serviceVersion = view.getBigUint64(30);
  const policyEpoch = view.getBigUint64(38);
  const authorityEpoch = view.getBigUint64(46);
  const issuedAt = view.getBigInt64(54);
  const payloadLength = view.getUint32(62);
  const payloadDigest = bytes.slice(66, 98);
  if (payloadLength > REMOTE_CONTROL_EVENT_MAX_PAYLOAD) fail("FCRC payload cap");
  return {
    controlSeq,
    eventId,
    kind,
    serviceVersion,
    policyEpoch,
    authorityEpoch,
    issuedAt,
    payloadLength,
    payloadDigest,
  };
}

// ---------------------------------------------------------------------------
// Gateway command ACK — exact 26 bytes
//   version:u8(1) | kind:u8 | commandId:[16] | committedSequence:u64
// ---------------------------------------------------------------------------
export const REMOTE_GATEWAY_ACK_BYTES = 26;

export function encodeGatewayAck(value: {
  kind: number;
  commandId: Uint8Array;
  committedSequence: bigint;
}): Uint8Array {
  id16(value.commandId, "ACK commandId");
  if (value.kind < 1 || value.kind > 255) fail("ACK kind");
  if (value.committedSequence < 0n || value.committedSequence > 0xffffffffffffffffn)
    fail("ACK sequence");
  const out = new Uint8Array(REMOTE_GATEWAY_ACK_BYTES);
  out[0] = 1;
  out[1] = value.kind;
  out.set(value.commandId, 2);
  new DataView(out.buffer).setBigUint64(18, value.committedSequence);
  return out;
}

export function decodeGatewayAck(bytes: Uint8Array): {
  kind: number;
  commandId: Uint8Array;
  committedSequence: bigint;
} {
  if (bytes.length !== REMOTE_GATEWAY_ACK_BYTES) fail("ACK length");
  if (bytes[0] !== 1) fail("ACK version");
  const commandId = bytes.slice(2, 18);
  id16(commandId, "ACK commandId");
  return {
    kind: bytes[1]!,
    commandId,
    committedSequence: new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(18),
  };
}
