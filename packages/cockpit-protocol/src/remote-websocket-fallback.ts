import { remoteIdentitySha256Sync } from "./remote-identity-protocol";

const encoder = new TextEncoder();
export const REMOTE_FALLBACK_SUBPROTOCOL = "flycockpit.remote-data.v1" as const;
export const REMOTE_FALLBACK_TICKET_TTL_MS = 30_000;
export const REMOTE_FALLBACK_CHALLENGE_BYTES = 53;
export const REMOTE_FALLBACK_AUTH_MAX_CERTIFICATE_BYTES = 4096;
export const REMOTE_FALLBACK_AUTH_MAX_BYTES = 4247;
export const REMOTE_FALLBACK_OUTER_HEADER_BYTES = 28;
export const REMOTE_FALLBACK_MAX_CIPHERTEXT_BYTES = 65_535;
export const REMOTE_FALLBACK_MIN_CIPHERTEXT_BYTES = 30;
export const REMOTE_FALLBACK_MAX_MESSAGE_BYTES = 65_563;
export const REMOTE_FALLBACK_ACK_BYTES = 9;
export const REMOTE_FALLBACK_ACK_NONE = 0xffffffffffffffffn;
export const REMOTE_FALLBACK_WINDOW_RECORDS = 64;
export const REMOTE_FALLBACK_WINDOW_BYTES = 4 * 1024 * 1024;
export const REMOTE_FALLBACK_ROUTE_LEASE_TTL_MS = 30_000;
export const REMOTE_FALLBACK_ROUTE_RENEW_MS = 10_000;
export const REMOTE_FALLBACK_ROUTE_RETIRE_GRACE_MS = 60_000;
export const REMOTE_FALLBACK_RETRY_MS = [750, 1500, 3000] as const;

export type RemoteFallbackRole = "client" | "daemon";
export type RemoteFallbackOriginClass = "web" | "native" | "daemon";
export type RemoteFallbackPairState =
  | "waiting_peer"
  | "pair_commit_pending"
  | "noise_handshake"
  | "noise_commit_pending"
  | "proof_pending"
  | "lease_pending"
  | "active"
  | "closing"
  | "closed";

export interface RemoteFallbackTicketV1 {
  ticketId: Uint8Array;
  role: RemoteFallbackRole;
  tenantId: Uint8Array;
  logicalAttachmentId: Uint8Array;
  childAttemptId: Uint8Array;
  transportEpoch: Uint8Array;
  admissionSequence: bigint;
  grantDigest: Uint8Array;
  authBundleDigest: Uint8Array;
  certificateId: Uint8Array;
  certificateGeneration: bigint;
  originClass: RemoteFallbackOriginClass;
  expiresAt: bigint;
  ticketSecretDigest: Uint8Array;
}

export interface RemoteFallbackChallengeV1 {
  challenge: Uint8Array;
  issuedAt: bigint;
  expiresAt: bigint;
}

export interface RemoteFallbackAuthV1 {
  ticketId: Uint8Array;
  ticketSecret: Uint8Array;
  certificateJws: Uint8Array;
  connectionNonce: Uint8Array;
  signature: Uint8Array;
}

export interface RemoteFallbackPairV1 {
  pairId: Uint8Array;
  opaqueRouteId: Uint8Array;
  routeGeneration: bigint;
  pairGeneration: bigint;
  clientSocketGeneration: bigint;
  daemonSocketGeneration: bigint;
  transportEpoch: Uint8Array;
  admissionSequence: bigint;
  grantDigest: Uint8Array;
  authBundleDigest: Uint8Array;
  attachmentBinding: Uint8Array;
  routeBindingKeyGeneration: bigint;
  state: RemoteFallbackPairState;
}

export interface RemoteFallbackRouteLeaseV1 {
  pairId: Uint8Array;
  replicaId: string;
  socketGeneration: bigint;
  transportEpoch: Uint8Array;
  attachmentBinding: Uint8Array;
  pairGeneration: bigint;
  connectionLeaseId: Uint8Array;
  connectionLeaseGeneration: bigint;
  connectionLeaseDigest: Uint8Array;
  routeLeaseGeneration: bigint;
  expiresAt: bigint;
}

export class RemoteFallbackCodecError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "RemoteFallbackCodecError";
  }
}

function fail(code: string): never {
  throw new RemoteFallbackCodecError(code);
}
function exact(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) fail(`invalid_${name}`);
}
function nonzero(bytes: Uint8Array, length: number, name: string): void {
  exact(bytes, length, name);
  if (bytes.every((byte) => byte === 0)) fail(`invalid_${name}`);
}
function signedI64(value: bigint, name: string): void {
  if (value < -(1n << 63n) || value > (1n << 63n) - 1n) fail(`invalid_${name}`);
}
function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function u64(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) fail("invalid_u64");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value);
  return out;
}

export function encodeRemoteFallbackChallengeV1(value: RemoteFallbackChallengeV1): Uint8Array {
  nonzero(value.challenge, 32, "challenge");
  signedI64(value.issuedAt, "issued_at");
  signedI64(value.expiresAt, "expires_at");
  if (value.expiresAt <= value.issuedAt) fail("invalid_challenge_expiry");
  const out = new Uint8Array(REMOTE_FALLBACK_CHALLENGE_BYTES);
  out.set(encoder.encode("FCDF"));
  out[4] = 1;
  out.set(value.challenge, 5);
  const view = new DataView(out.buffer);
  view.setBigInt64(37, value.issuedAt);
  view.setBigInt64(45, value.expiresAt);
  return out;
}

export function decodeRemoteFallbackChallengeV1(bytes: Uint8Array): RemoteFallbackChallengeV1 {
  if (
    bytes.length !== REMOTE_FALLBACK_CHALLENGE_BYTES ||
    new TextDecoder().decode(bytes.subarray(0, 4)) !== "FCDF" ||
    bytes[4] !== 1
  )
    fail("invalid_challenge");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const value = {
    challenge: bytes.slice(5, 37),
    issuedAt: view.getBigInt64(37),
    expiresAt: view.getBigInt64(45),
  };
  if (value.challenge.every((byte) => byte === 0) || value.expiresAt <= value.issuedAt)
    fail("invalid_challenge_expiry");
  return value;
}

export function encodeRemoteFallbackAuthV1(value: RemoteFallbackAuthV1): Uint8Array {
  nonzero(value.ticketId, 16, "ticket_id");
  nonzero(value.ticketSecret, 32, "ticket_secret");
  nonzero(value.connectionNonce, 32, "connection_nonce");
  exact(value.signature, 64, "p1363_signature");
  if (
    value.certificateJws.length === 0 ||
    value.certificateJws.length > REMOTE_FALLBACK_AUTH_MAX_CERTIFICATE_BYTES
  )
    fail("invalid_certificate_length");
  const out = new Uint8Array(151 + value.certificateJws.length);
  out.set(encoder.encode("FCFA"));
  out[4] = 1;
  out.set(value.ticketId, 5);
  out.set(value.ticketSecret, 21);
  new DataView(out.buffer).setUint16(53, value.certificateJws.length);
  out.set(value.certificateJws, 55);
  out.set(value.connectionNonce, 55 + value.certificateJws.length);
  out.set(value.signature, 87 + value.certificateJws.length);
  return out;
}

export function decodeRemoteFallbackAuthV1(bytes: Uint8Array): RemoteFallbackAuthV1 {
  if (
    bytes.length < 152 ||
    bytes.length > REMOTE_FALLBACK_AUTH_MAX_BYTES ||
    new TextDecoder().decode(bytes.subarray(0, 4)) !== "FCFA" ||
    bytes[4] !== 1
  )
    fail("invalid_auth_frame");
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(53);
  if (
    length === 0 ||
    length > REMOTE_FALLBACK_AUTH_MAX_CERTIFICATE_BYTES ||
    bytes.length !== 151 + length
  )
    fail("invalid_certificate_length");
  const value = {
    ticketId: bytes.slice(5, 21),
    ticketSecret: bytes.slice(21, 53),
    certificateJws: bytes.slice(55, 55 + length),
    connectionNonce: bytes.slice(55 + length, 87 + length),
    signature: bytes.slice(87 + length),
  };
  nonzero(value.ticketId, 16, "ticket_id");
  nonzero(value.ticketSecret, 32, "ticket_secret");
  nonzero(value.connectionNonce, 32, "connection_nonce");
  return value;
}

export function remoteFallbackSocketAuthDigest(input: {
  challengeFrame: Uint8Array;
  role: RemoteFallbackRole;
  childAttemptId: Uint8Array;
  transportEpoch: Uint8Array;
  authFrame: Uint8Array;
}): Uint8Array {
  decodeRemoteFallbackChallengeV1(input.challengeFrame);
  nonzero(input.childAttemptId, 16, "child_attempt_id");
  nonzero(input.transportEpoch, 16, "transport_epoch");
  const auth = decodeRemoteFallbackAuthV1(input.authFrame);
  const beforeSignature = input.authFrame.subarray(
    0,
    input.authFrame.length - auth.signature.length,
  );
  const protocol = encoder.encode(REMOTE_FALLBACK_SUBPROTOCOL);
  return remoteIdentitySha256Sync(
    concat([
      encoder.encode("flycockpit.remote.fallback-socket-auth.v1\0"),
      input.challengeFrame,
      Uint8Array.of(protocol.length),
      protocol,
      Uint8Array.of(input.role === "client" ? 1 : 2),
      input.childAttemptId,
      input.transportEpoch,
      beforeSignature,
    ]),
  );
}

export function remoteFallbackTicketSecretDigest(secret: Uint8Array): Uint8Array {
  nonzero(secret, 32, "ticket_secret");
  return remoteIdentitySha256Sync(secret);
}

export interface RemoteFallbackOuterRecordV1 {
  routeGeneration: bigint;
  direction: "client_to_daemon" | "daemon_to_client";
  recordSequence: bigint;
  peerSeenThrough: bigint;
  ciphertext: Uint8Array;
}

export function encodeRemoteFallbackOuterRecordV1(value: RemoteFallbackOuterRecordV1): Uint8Array {
  if (
    value.routeGeneration < 1n ||
    value.routeGeneration > 0xffffffffffffffffn ||
    value.recordSequence < 0n ||
    value.recordSequence >= 1n << 32n ||
    value.peerSeenThrough < 0n ||
    value.peerSeenThrough > 0xffffffffffffffffn ||
    value.ciphertext.length < REMOTE_FALLBACK_MIN_CIPHERTEXT_BYTES ||
    value.ciphertext.length > REMOTE_FALLBACK_MAX_CIPHERTEXT_BYTES
  )
    fail("invalid_outer_record");
  const out = new Uint8Array(REMOTE_FALLBACK_OUTER_HEADER_BYTES + value.ciphertext.length);
  out[0] = 1;
  const view = new DataView(out.buffer);
  view.setBigUint64(1, value.routeGeneration);
  out[9] = value.direction === "client_to_daemon" ? 0 : 1;
  view.setBigUint64(10, value.recordSequence);
  view.setBigUint64(18, value.peerSeenThrough);
  view.setUint16(26, value.ciphertext.length);
  out.set(value.ciphertext, 28);
  return out;
}

export function decodeRemoteFallbackOuterRecordV1(bytes: Uint8Array): RemoteFallbackOuterRecordV1 {
  if (
    bytes.length < REMOTE_FALLBACK_OUTER_HEADER_BYTES ||
    bytes.length > REMOTE_FALLBACK_MAX_MESSAGE_BYTES ||
    bytes[0] !== 1
  )
    fail("invalid_outer_record");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const length = view.getUint16(26);
  const direction = bytes[9];
  if (
    length < REMOTE_FALLBACK_MIN_CIPHERTEXT_BYTES ||
    length > REMOTE_FALLBACK_MAX_CIPHERTEXT_BYTES ||
    bytes.length !== 28 + length ||
    (direction !== 0 && direction !== 1)
  )
    fail("invalid_outer_record");
  const routeGeneration = view.getBigUint64(1);
  const recordSequence = view.getBigUint64(10);
  if (routeGeneration === 0n || recordSequence >= 1n << 32n) fail("invalid_outer_record");
  return {
    routeGeneration,
    direction: direction === 0 ? "client_to_daemon" : "daemon_to_client",
    recordSequence,
    peerSeenThrough: view.getBigUint64(18),
    ciphertext: bytes.slice(28),
  };
}

export function encodeRemoteFallbackAckV1(largestContiguous: bigint): Uint8Array {
  return concat([Uint8Array.of(1), u64(largestContiguous)]);
}
export function decodeRemoteFallbackAckV1(bytes: Uint8Array): bigint {
  if (bytes.length !== REMOTE_FALLBACK_ACK_BYTES || bytes[0] !== 1) fail("invalid_ack");
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(1);
}
