/**
 * Shared test fixtures for the signaling gateway auth/relay suites (NOT a
 * `*.test.ts`, so importing it registers no tests).
 *
 * Two responsibilities:
 *  1. Mint an in-test daemon identity-CA ring and sign real FCDA control-auth
 *     frames (a genuine ES256 identity certificate + a P-256 signature over the
 *     exact domain-separated control-auth preimage). Nothing here fakes the
 *     verifier — `buildRingVerifier` returns the production
 *     `RingDaemonCertificateVerifier`, and a broken cert/signature really fails.
 *  2. Re-export the `remote-signaling-store.test.ts` request/offer/proof
 *     fixture builders verbatim, plus admission + connection helpers the auth
 *     and relay suites share.
 */
import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import {
  type AuthorityRingFile,
  normalizeAuthorityIssuer,
  normalizeEs256Signature,
  parseAuthorityRingFile,
  RingAuthorityVerifier,
} from "@flycockpit/api/lib/remote-authority";
import type { MemoryRemoteSignalingAttemptStore } from "@flycockpit/api/lib/remote-signaling-store";
import {
  canonicalizeRfc8785,
  daemonAdmissionOfferDigest,
  decodeProtocolIdBase64Url,
  encodeClientAdmissionProofV1,
  encodeDaemonAdmissionOfferV1,
  encodeProtocolIdBase64Url,
  encodeRemoteChildAuthenticationBundleV1,
  encodeRemoteEndpointFinalProofV1,
  encodeRemoteFallbackNoiseCompleteV1,
  encodeRemoteFallbackPairAuthenticatedV1,
  encodeRemoteSignalingEventRequestV1,
  encodeRemoteSignalingReadyV1,
  encodeRemoteWebRtcAnswerV1,
  encodeRemoteWebRtcCandidateV1,
  encodeRemoteWebRtcIceCompleteV1,
  encodeRemoteWebRtcOfferV1,
  parseRemoteIdentityCertificateJws,
  remoteFinalProofSetDigest,
} from "@flycockpit/cockpit-protocol";
import WebSocket from "ws";
import { encodeFcdaFrame, encodeFcsaFrame } from "./binary-codecs";
import { REMOTE_GATEWAY_SUBPROTOCOL } from "./close-codes";
import {
  daemonControlAuthPreimage,
  RingDaemonCertificateVerifier,
} from "./daemon-certificate-verifier";
import type { GatewayTestEnv } from "./test-fixtures";

// ---------------------------------------------------------------------------
// The exact configured origin the harness advertises (test-fixtures.ts).
// ---------------------------------------------------------------------------
export const CONFIGURED_ORIGIN = "https://app.example.test";
export const DEFAULT_ISSUER = "https://app.example.test";

const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
const canonicalB64 = (value: unknown): string =>
  Buffer.from(canonicalizeRfc8785(value)).toString("base64url");

export const sha256Bytes = (bytes: Uint8Array): Uint8Array =>
  new Uint8Array(createHash("sha256").update(Buffer.from(bytes)).digest());

// ---------------------------------------------------------------------------
// Deliverable A — in-test daemon identity-CA ring + FCDA signing.
// ---------------------------------------------------------------------------

export interface TestIdentityRing {
  ring: AuthorityRingFile;
  kid: string;
  privateKey: KeyObject;
}

/** Mint a fresh single-key daemon identity-CA ring (validated via `parseAuthorityRingFile`). */
export function makeIdentityRing(): TestIdentityRing {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = privateKey.export({ format: "jwk" }) as {
    x: string;
    y: string;
    d: string;
  };
  const kid = `test-identity-${randomBytes(6).toString("hex")}`;
  const ring = parseAuthorityRingFile({
    schemaVersion: 1,
    revision: "1",
    authorityEpoch: "1",
    currentKid: kid,
    keys: [
      {
        kid,
        alg: "ES256",
        kty: "EC",
        crv: "P-256",
        x: jwk.x,
        y: jwk.y,
        d: jwk.d,
        state: "current",
        activatedAt: "0",
        retireAt: null,
      },
    ],
  });
  return { ring, kid, privateKey };
}

/** Build the production identity-CA verifier over a test ring. */
export function buildRingVerifier(
  ring: AuthorityRingFile,
  issuer: string = DEFAULT_ISSUER,
): RingDaemonCertificateVerifier {
  return new RingDaemonCertificateVerifier(
    new RingAuthorityVerifier(ring, "0"),
    normalizeAuthorityIssuer(issuer),
  );
}

export interface MintedDaemonCertificate {
  certJws: string;
  daemonPrivateKey: KeyObject;
  instanceId: string;
  instanceProtocolId: Uint8Array;
  certificateGeneration: bigint;
}

export interface MintDaemonCertificateInput {
  ring: AuthorityRingFile;
  kid: string;
  ringPrivateKey: KeyObject;
  instanceId?: string;
  generation?: bigint;
  issuer?: string;
  /** 1 = client subject (rejected by the daemon verifier), 2 = daemon subject. */
  subjectKind?: 1 | 2;
  /** Certificate validity window (seconds). */
  iat?: bigint;
  exp?: bigint;
  /** Emit a payload that still parses but is structurally corrupt after minting. */
}

/**
 * Mint a real identity certificate JWS whose signature is produced by the ring
 * private key, embedding a fresh daemon P-256 public key. Parses its own output
 * so a malformed fixture is loud.
 */
export function mintDaemonCertificate(input: MintDaemonCertificateInput): MintedDaemonCertificate {
  const generation = input.generation ?? 1n;
  const issuer = input.issuer ?? DEFAULT_ISSUER;
  const subjectKind = input.subjectKind ?? 2;
  const instanceId = input.instanceId ?? encodeProtocolIdBase64Url(randomBytes(16));

  const { publicKey: daemonPublicKey, privateKey: daemonPrivateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const daemonJwk = daemonPublicKey.export({ format: "jwk" }) as { x: string; y: string };
  const x = daemonJwk.x;
  const y = daemonJwk.y;
  const thumbprint = createHash("sha256")
    .update(`{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`)
    .digest("base64url");

  const payload = {
    schemaVersion: 1,
    iss: issuer,
    aud: "flycockpit-remote-peer-v1",
    sub: encodeProtocolIdBase64Url(randomBytes(16)),
    tenantId: encodeProtocolIdBase64Url(randomBytes(16)),
    accountId: subjectKind === 1 ? encodeProtocolIdBase64Url(randomBytes(16)) : null,
    instanceId,
    subjectKind,
    certificateId: encodeProtocolIdBase64Url(randomBytes(16)),
    generation: String(generation),
    publicKey: { crv: "P-256", kty: "EC", x, y },
    thumbprint,
    custody: 1,
    presenceMode: 1,
    authorityEpoch: "1",
    iat: String(input.iat ?? 0n),
    exp: String(input.exp ?? 9_999_999_999n),
  };
  const header = {
    alg: "ES256",
    kid: input.kid,
    typ: "flycockpit-remote-identity-certificate+jws",
  };
  const signingInput = `${canonicalB64(header)}.${canonicalB64(payload)}`;
  const signature = normalizeEs256Signature({
    encoding: "ieee-p1363",
    bytes: sign("sha256", Buffer.from(signingInput), {
      key: input.ringPrivateKey,
      dsaEncoding: "ieee-p1363",
    }),
  });
  const certJws = `${signingInput}.${b64url(signature)}`;
  // Loud fixture: a certificate that cannot be parsed is a broken test, not a
  // gateway assertion. (subjectKind 1 and unknown-kid variants still parse.)
  parseRemoteIdentityCertificateJws(certJws);
  return {
    certJws,
    daemonPrivateKey,
    instanceId,
    instanceProtocolId: decodeProtocolIdBase64Url(instanceId),
    certificateGeneration: generation,
  };
}

export interface SignFcdaInput {
  fcdcFrame: Uint8Array;
  certJws: string;
  daemonPrivateKey: KeyObject;
  instanceProtocolId: Uint8Array;
  certificateGeneration: bigint;
  configuredOrigin?: string;
  lastDiscoverySeq?: bigint;
}

/** Build and sign a complete FCDA frame answering the FCDC challenge. */
export function signFcda(input: SignFcdaInput): Uint8Array {
  const configuredOrigin = input.configuredOrigin ?? CONFIGURED_ORIGIN;
  const frame = encodeFcdaFrame({
    certificateJws: new TextEncoder().encode(input.certJws),
    connectionNonce: new Uint8Array(32).fill(7),
    lastDiscoverySeq: input.lastDiscoverySeq ?? 0n,
    lastControlSeq: 0n,
    signature: new Uint8Array(64).fill(1),
  });
  const before = frame.slice(0, frame.length - 64);
  const preimage = daemonControlAuthPreimage({
    fcdcFrame: input.fcdcFrame,
    configuredOrigin,
    subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.control,
    instanceProtocolId: input.instanceProtocolId,
    certificateGeneration: input.certificateGeneration,
    fcdaBytesBeforeSignature: before,
  });
  const signature = normalizeEs256Signature({
    encoding: "ieee-p1363",
    bytes: sign("sha256", Buffer.from(preimage), {
      key: input.daemonPrivateKey,
      dsaEncoding: "ieee-p1363",
    }),
  });
  frame.set(signature, frame.length - 64);
  return frame;
}

// ---------------------------------------------------------------------------
// Store fixture builders copied verbatim from
// packages/api/src/lib/remote-signaling-store.test.ts (the exact valid FCSE /
// offer / proof byte builders the store re-validates), so gateway commits go
// through the real store transition machine unchanged.
// ---------------------------------------------------------------------------

export const id = (start: number): Uint8Array =>
  Uint8Array.from({ length: 16 }, (_, index) => start + index);
export const digest = (start: number): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_, index) => start + index);
export const signature = (): Uint8Array => new Uint8Array(64).fill(9);
export const daemonOffer = (childAttemptId: Uint8Array = id(1), transport: 1 | 2 = 1): Uint8Array =>
  encodeDaemonAdmissionOfferV1({
    instanceId: id(20),
    daemonDeviceId: id(40),
    daemonDeviceGeneration: 1n,
    daemonCertificateId: id(60),
    daemonCertificateGeneration: 1n,
    logicalAttachmentId: id(80),
    childAttemptId,
    grantJti: id(100),
    grantDigest: digest(1),
    serverNonce: digest(40),
    serviceVersion: 1n,
    policyEpoch: 1n,
    policyDigest: digest(80),
    authorizedTransportBits: transport,
    daemonTupleIds: [1],
    offerJti: id(120),
    issuedAt: 1n,
    expiresAt: 2n,
    signature: signature(),
  });
export const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g)!.map((byte) => Number.parseInt(byte, 16)));
const finalProof = (
  role: 1 | 2,
  transport: 1 | 2 = 1,
  childAttemptId: Uint8Array = id(1),
): Uint8Array =>
  encodeRemoteEndpointFinalProofV1({
    role,
    transport,
    childAttemptId,
    transportEpoch: id(50),
    admissionSequence: 3n,
    grantDigest: digest(1),
    negotiationDigest: digest(40),
    binding: new Uint8Array(96).fill(8),
    proofJti: id(role === 1 ? 140 : 160),
    certificateId: id(role === 1 ? 180 : 200),
    certificateGeneration: 1n,
    signature: new Uint8Array(64).fill(role),
  });
export const request = (
  kind: number,
  role: 1 | 2 | 3,
  event: number = kind,
  transport: 1 | 2 = kind >= 8 && kind <= 9 ? 2 : 1,
  childAttemptId: Uint8Array = id(1),
): Uint8Array => {
  // Annotate as the general `Uint8Array` (i.e. `Uint8Array<ArrayBufferLike>`) so
  // every encoder result assigns cleanly — `new Uint8Array()` and the `encode*`
  // helpers yield `Uint8Array<ArrayBuffer>`, while `daemonOffer`/`finalProof`
  // return the general `Uint8Array`; all are assignable to this.
  let payload: Uint8Array = new Uint8Array();
  const description = {
    childAttemptId,
    transportEpoch: id(50),
    descriptionId: id(70),
    sdp: new TextEncoder().encode("v=0\r\n"),
  };
  if (kind === 1)
    payload = encodeRemoteChildAuthenticationBundleV1({
      childAttemptId,
      grantJws: Uint8Array.of(1),
      clientCertificateJws: Uint8Array.of(2),
      daemonCertificateJws: Uint8Array.of(3),
      authorityStatusJws: Uint8Array.of(4),
      servicePolicyJws: Uint8Array.of(5),
    });
  if (kind === 2) payload = daemonOffer(childAttemptId, transport);
  if (kind === 3)
    payload = encodeClientAdmissionProofV1({
      tenantId: id(20),
      accountId: id(40),
      clientDeviceId: id(60),
      clientDeviceGeneration: 1n,
      clientCertificateId: id(80),
      clientCertificateGeneration: 1n,
      logicalAttachmentId: id(100),
      childAttemptId,
      grantJti: id(120),
      grantDigest: digest(1),
      daemonOfferDigest: daemonAdmissionOfferDigest(daemonOffer(childAttemptId, transport)),
      daemonOfferJti: id(120),
      chosenTransport: transport,
      clientTupleIds: [1],
      daemonTupleIds: [1],
      selectedTupleId: 1,
      policyDigest: digest(80),
      serverNonce: digest(10),
      clientNonce: digest(50),
      issuedAt: 1n,
      expiresAt: 2n,
      proofJti: id(30),
      signature: signature(),
    });
  if (kind === 4) payload = encodeRemoteWebRtcOfferV1(description);
  if (kind === 5) payload = encodeRemoteWebRtcAnswerV1(description);
  if (kind === 6)
    payload = encodeRemoteWebRtcCandidateV1({
      role: role === 2 ? 1 : 2,
      childAttemptId,
      transportEpoch: id(50),
      candidateId: id(event),
      sdpMid: "0",
      sdpMLineIndex: 0,
      candidate: "candidate:1 1 UDP 1 192.0.2.1 9 typ host",
    });
  if (kind === 7)
    payload = encodeRemoteWebRtcIceCompleteV1({
      role: role === 2 ? 1 : 2,
      childAttemptId,
      transportEpoch: id(50),
    });
  if (kind === 8)
    payload = encodeRemoteFallbackPairAuthenticatedV1({
      pairId: id(90),
      pairGeneration: 1n,
      routeGeneration: 1n,
      clientSocketGeneration: 1n,
      daemonSocketGeneration: 1n,
      admissionSequence: 3n,
      pairAuthorizationDigest: digest(90),
    });
  if (kind === 9)
    payload = encodeRemoteFallbackNoiseCompleteV1({
      role: role === 2 ? 1 : 2,
      pairId: id(90),
      socketGeneration: 1n,
      noiseHandshakeHash: digest(10),
      prologueDigest: digest(50),
      connectionNonce: digest(90),
    });
  if (kind === 10 || kind === 11)
    payload = finalProof(kind === 10 ? 1 : 2, transport, childAttemptId);
  if (kind === 12) {
    const client = finalProof(1, transport, childAttemptId);
    const daemon = finalProof(2, transport, childAttemptId);
    payload = encodeRemoteSignalingReadyV1({
      verifiedPeerProofJti: id(role === 2 ? 160 : 140),
      finalProofSetDigest: remoteFinalProofSetDigest(client, daemon),
    });
  }
  return encodeRemoteSignalingEventRequestV1({
    transport,
    producerRole: role,
    eventKind: kind as 1,
    childAttemptId,
    eventId: id(32 + event),
    payload,
  });
};
export const actor = (role: "server" | "client" | "daemon") => ({
  role,
  actor: `${role}-one`,
  generation: 1n,
});
export const createInput = {
  daemonInstanceId: "abcdefghijklmnopqrstuv",
  childAttemptId: id(1),
  transportKind: "webrtc" as const,
  participantRefs: ["opaque-a", "opaque-b"] as const,
};

/**
 * Build the exact `ClientAdmissionProofV1` payload the store re-validates at
 * admission — byte-identical to `decodeRemoteSignalingEventRequestV1(request(3,2)).payload`
 * for the defaults, with narrow overrides for negative tests.
 */
export function clientAdmissionProofPayload(overrides?: {
  childAttemptId?: Uint8Array;
  transport?: 1 | 2;
  proofJti?: Uint8Array;
  clientNonce?: Uint8Array;
}): Uint8Array {
  const childAttemptId = overrides?.childAttemptId ?? id(1);
  const transport = overrides?.transport ?? 1;
  return encodeClientAdmissionProofV1({
    tenantId: id(20),
    accountId: id(40),
    clientDeviceId: id(60),
    clientDeviceGeneration: 1n,
    clientCertificateId: id(80),
    clientCertificateGeneration: 1n,
    logicalAttachmentId: id(100),
    childAttemptId,
    grantJti: id(120),
    grantDigest: digest(1),
    daemonOfferDigest: daemonAdmissionOfferDigest(daemonOffer(childAttemptId, transport)),
    daemonOfferJti: id(120),
    chosenTransport: transport,
    clientTupleIds: [1],
    daemonTupleIds: [1],
    selectedTupleId: 1,
    policyDigest: digest(80),
    serverNonce: digest(10),
    clientNonce: overrides?.clientNonce ?? digest(50),
    issuedAt: 1n,
    expiresAt: 2n,
    proofJti: overrides?.proofJti ?? id(30),
    signature: signature(),
  });
}

// ---------------------------------------------------------------------------
// Connection helpers with a buffered binary-message queue (never drops a
// message that arrives between awaits, unlike `ws.once`).
// ---------------------------------------------------------------------------

export interface MessageQueue {
  next(): Promise<Buffer>;
  readonly length: number;
}

const toBuffer = (data: Buffer | ArrayBuffer | Buffer[]): Buffer =>
  Buffer.isBuffer(data)
    ? data
    : data instanceof ArrayBuffer
      ? Buffer.from(data)
      : Buffer.concat(data as readonly Buffer[]);

export function messageQueue(ws: WebSocket): MessageQueue {
  const buffer: Buffer[] = [];
  const waiters: ((value: Buffer) => void)[] = [];
  ws.on("message", (data) => {
    const buf = toBuffer(data);
    const waiter = waiters.shift();
    if (waiter) waiter(buf);
    else buffer.push(buf);
  });
  return {
    next(): Promise<Buffer> {
      const buffered = buffer.shift();
      if (buffered) return Promise.resolve(buffered);
      return new Promise<Buffer>((resolve) => waiters.push(resolve));
    },
    get length() {
      return buffer.length;
    },
  };
}

export interface QueuedSocket {
  ws: WebSocket;
  queue: MessageQueue;
}

export function connectWithQueue(
  url: string,
  options?: { subprotocol?: string; headers?: Record<string, string> },
): Promise<QueuedSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, options?.subprotocol, {
      headers: options?.headers,
      perMessageDeflate: false,
    });
    const queue = messageQueue(ws);
    ws.once("open", () => resolve({ ws, queue }));
    ws.once("error", reject);
  });
}

// ---------------------------------------------------------------------------
// Admission helper — seeds a daemon_offered attempt, mints a single-use ticket,
// connects a signal socket, admits it, and drains the two initial peer-event
// deliveries (seq1 server bundle, seq2 daemon offer). The returned socket is
// positioned at cursor=3 (its own admission), ready for relay assertions.
// ---------------------------------------------------------------------------

export interface AdmitSignalOptions {
  child?: Uint8Array;
  deviceAttachmentId?: string;
  transport?: 1 | 2;
  store?: MemoryRemoteSignalingAttemptStore;
  originClass?: "browser_same_origin" | "native_no_origin";
}

export interface AdmittedSignalSocket extends QueuedSocket {
  ticketId: Uint8Array;
  secret: Uint8Array;
  proofBytes: Uint8Array;
  child: Uint8Array;
  deviceAttachmentId: string;
  /** The two peer events delivered right after admission (server bundle, daemon offer). */
  initialDeliveries: [Buffer, Buffer];
}

/** Seed a daemon_offered attempt and its admission ticket without connecting a socket. */
export async function seedDaemonOfferedTicket(
  store: MemoryRemoteSignalingAttemptStore,
  options?: {
    child?: Uint8Array;
    transport?: 1 | 2;
    deviceAttachmentId?: string;
    originClass?: "browser_same_origin" | "native_no_origin";
    admissionProofSha256?: Uint8Array;
  },
): Promise<{
  ticketId: Uint8Array;
  secret: Uint8Array;
  proofBytes: Uint8Array;
  child: Uint8Array;
}> {
  const child = options?.child ?? id(1);
  const transport = options?.transport ?? 1;
  const transportKind = transport === 1 ? ("webrtc" as const) : ("websocket_data" as const);
  await store.create(
    { ...createInput, childAttemptId: child, transportKind },
    request(1, 1, 1, transport, child),
    actor("server"),
  );
  await store.commit(
    createInput.daemonInstanceId,
    child,
    request(2, 3, 2, transport, child),
    actor("daemon"),
  );
  const proofBytes = clientAdmissionProofPayload({ childAttemptId: child, transport });
  const { ticketId, secret } = await store.issueClientAdmissionTicket({
    daemonInstanceId: createInput.daemonInstanceId,
    childAttemptId: child,
    originClass: options?.originClass ?? "browser_same_origin",
    accountId: "acct-1",
    deviceAttachmentId: options?.deviceAttachmentId ?? "attach-1",
    deviceGeneration: 5n,
    admissionProofSha256: options?.admissionProofSha256 ?? sha256Bytes(proofBytes),
  });
  return { ticketId, secret, proofBytes, child };
}

export async function admitSignalSocket(
  env: GatewayTestEnv,
  options?: AdmitSignalOptions,
): Promise<AdmittedSignalSocket> {
  const store = options?.store ?? env.store;
  const deviceAttachmentId = options?.deviceAttachmentId ?? "attach-1";
  const { ticketId, secret, proofBytes, child } = await seedDaemonOfferedTicket(store, {
    child: options?.child,
    transport: options?.transport,
    deviceAttachmentId,
    originClass: options?.originClass,
  });
  const { ws, queue } = await connectWithQueue(env.url, {
    subprotocol: REMOTE_GATEWAY_SUBPROTOCOL.signal,
    headers: { origin: CONFIGURED_ORIGIN },
  });
  ws.send(
    Buffer.from(encodeFcsaFrame({ ticketId, ticketSecret: secret, admissionProof: proofBytes })),
  );
  const initialDeliveries: [Buffer, Buffer] = [await queue.next(), await queue.next()];
  return { ws, queue, ticketId, secret, proofBytes, child, deviceAttachmentId, initialDeliveries };
}
