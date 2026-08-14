import { createHash } from "node:crypto";
import {
  daemonAdmissionOfferDigest,
  decodeClientAdmissionProofV1,
  decodeDaemonAdmissionOfferV1,
  decodeProtocolIdBase64Url,
  decodeRemoteChildAuthenticationBundleV1,
  decodeRemoteEndpointFinalProofV1,
  decodeRemoteFallbackNoiseCompleteV1,
  decodeRemoteFallbackPairAuthenticatedV1,
  decodeRemoteSignalingEventRequestV1,
  decodeRemoteSignalingReadyV1,
  decodeRemoteWebRtcAnswerV1,
  decodeRemoteWebRtcCandidateV1,
  decodeRemoteWebRtcIceCompleteV1,
  decodeRemoteWebRtcOfferV1,
  encodeProtocolIdBase64Url,
  encodeRemoteSignalingCommitAckV1,
  REMOTE_SIGNALING_ATTEMPT_TTL_MS,
  REMOTE_SIGNALING_MAX_AGGREGATE_BYTES,
  REMOTE_SIGNALING_MAX_CANDIDATES_PER_ROLE,
  REMOTE_SIGNALING_MAX_EVENTS,
  REMOTE_SIGNALING_TRANSITION_ROWS,
  type RemoteSignalingCommitAckV1,
  RemoteSignalingEventKind,
  type RemoteSignalingEventRequestV1,
  remoteChildAuthenticationDigests,
  remoteEndpointFinalProofAgreementBytes,
  remoteFinalProofSetDigest,
  remoteSignalingEventDigest,
} from "@flycockpit/cockpit-protocol";
import { createRedisConnection } from "@flycockpit/queue/connection";
import {
  REMOTE_SIGNALING_COMMIT_ADMISSION_LUA,
  REMOTE_SIGNALING_COMMIT_LUA,
  REMOTE_SIGNALING_CREATE_LUA,
  REMOTE_SIGNALING_ISSUE_ADMISSION_TICKET_LUA,
  REMOTE_SIGNALING_SOCKET_LEASE_ACQUIRE_LUA,
} from "./remote-signaling-store.lua";

const sha256Hex = (bytes: Uint8Array) =>
  createHash("sha256").update(Buffer.from(bytes)).digest("hex");

type Redis = ReturnType<typeof createRedisConnection>;

export { REMOTE_SIGNALING_ATTEMPT_TTL_MS };
export const REMOTE_SIGNALING_READ_MAX_EVENTS = 64;
export const REMOTE_SIGNALING_READ_MAX_BYTES = 512 * 1024;
export type RemoteSignalingAttemptState =
  | "created"
  | "daemon_offered"
  | "admitted"
  | "offered"
  | "answered"
  | "fallback_paired"
  | "fallback_noise_complete"
  | "completed"
  | "rejected"
  | "cancelled"
  | "superseded";
export interface RemoteSignalingActorBindingV1 {
  role: "server" | "client" | "daemon";
  actor: string;
  generation: bigint;
}
export interface RemoteSignalingAttemptCreateV1 {
  daemonInstanceId: string;
  childAttemptId: Uint8Array;
  transportKind: "webrtc" | "websocket_data";
  participantRefs: readonly [string, string];
  discovery?: {
    daemonCertificateGeneration: bigint;
    discoveryId: Uint8Array;
    authBundleDigest: Uint8Array;
  };
}
export interface RemoteSignalingCommittedEventV1 {
  sequence: bigint;
  redisCreatedAtMs: number;
  requestBytes: Uint8Array;
  request: RemoteSignalingEventRequestV1;
  actor: RemoteSignalingActorBindingV1;
  ackBytes: Uint8Array;
}
export interface RemoteSignalingCommitResultV1 {
  kind: "committed" | "replay";
  sequence: bigint;
  ackBytes: Uint8Array;
}
export type RemoteSignalingReadResultV1 =
  | { kind: "events"; events: readonly RemoteSignalingCommittedEventV1[]; latestSequence: bigint }
  | { kind: "unavailable" };
export interface RemoteDiscoveryEntryV1 {
  discoverySeq: bigint;
  discoveryId: Uint8Array;
  childAttemptId: Uint8Array;
  attemptWakeRouteId: Uint8Array;
  authBundleDigest: Uint8Array;
  expiresAtMs: number;
}
export type RemoteDiscoveryReadResultV1 =
  | { kind: "entries"; entries: readonly RemoteDiscoveryEntryV1[]; latestDiscoverySeq: bigint }
  | {
      kind: "expired_gap";
      expectedAfterSeq: bigint;
      expiredThroughSeq: bigint;
      latestDiscoverySeq: bigint;
    }
  | { kind: "unavailable" };
export interface RemoteInstanceWakeLeaseV1 {
  instanceWakeRouteId: Uint8Array;
  instanceWakeRouteGeneration: bigint;
  socketGeneration: bigint;
  expiresAtMs: number;
}
export class RemoteSignalingStoreError extends Error {
  constructor(
    readonly code:
      | "unavailable"
      | "conflict"
      | "invalid_transition"
      | "limit"
      | "corrupt"
      | "retry"
      | "auth_failed",
    message = code,
  ) {
    super(message);
  }
}

/** Redis-owned single-use client admission ticket. TTL is 30 s from Redis `TIME` (memory parity via `now`). */
export const REMOTE_SIGNALING_ADMISSION_TICKET_TTL_MS = 30_000;
/** Live signal sockets allowed per device attachment (store-enforced, Redis + memory parity). */
export const REMOTE_SIGNALING_MAX_SIGNALING_SOCKETS_PER_ATTACHMENT = 2;
/**
 * Per-attachment socket-lease TTL. The gateway renews it on a shorter interval
 * for the whole life of an open socket, so this is only the crashed-replica
 * safety net — a dead replica's lease frees a slot within this window.
 */
export const REMOTE_SIGNALING_SOCKET_LEASE_TTL_MS = 60_000;

export type RemoteSignalingAdmissionOriginClass = "browser_same_origin" | "native_no_origin";

export interface RemoteSignalingAdmissionTicketInput {
  daemonInstanceId: string;
  childAttemptId: Uint8Array;
  originClass: RemoteSignalingAdmissionOriginClass;
  accountId: string;
  deviceAttachmentId: string;
  deviceGeneration: bigint;
  /** SHA-256 of the exact `ClientAdmissionProofV1` bytes the client commits at admission time. */
  admissionProofSha256: Uint8Array;
}
export interface RemoteSignalingAdmissionTicketV1 {
  ticketId: Uint8Array;
  secret: Uint8Array;
}
/** The FCSA-side fields the gateway forwards to {@link RemoteSignalingAttemptStore.commitClientAdmission}. */
export interface RemoteSignalingAdmissionTicketProof {
  ticketId: Uint8Array;
  /** Hex SHA-256 of the ticket secret the client presented (gateway-computed, never the raw secret). */
  secretSha256Hex: string;
  /** The socket's verified upgrade-time origin class. */
  originClass: string;
}
export interface RemoteSignalingClientAdmissionResultV1 {
  result: RemoteSignalingCommitResultV1;
  /** Server-derived from the consumed ticket — never from client-declared bytes. */
  actor: RemoteSignalingActorBindingV1;
  childAttemptId: Uint8Array;
  deviceAttachmentId: string;
  deviceGeneration: bigint;
}
/**
 * Non-consuming routing hint for an admission ticket: which daemon instance /
 * child attempt this ticket targets, so the gateway can form the instance-scoped
 * key for the atomic {@link RemoteSignalingAttemptStore.commitClientAdmission}.
 * A forged/incorrect route can never admit — the atomic commit re-validates the
 * secret, origin class, child, and proof digest against the real ticket.
 */
export interface RemoteSignalingAdmissionTicketRoute {
  daemonInstanceId: string;
  childAttemptId: Uint8Array;
}
export interface RemoteSignalingAttemptStore {
  create(
    input: RemoteSignalingAttemptCreateV1,
    requestBytes: Uint8Array,
    actor: RemoteSignalingActorBindingV1,
  ): Promise<RemoteSignalingCommitResultV1>;
  commit(
    daemonInstanceId: string,
    childAttemptId: Uint8Array,
    requestBytes: Uint8Array,
    actor: RemoteSignalingActorBindingV1,
  ): Promise<RemoteSignalingCommitResultV1>;
  read(
    daemonInstanceId: string,
    childAttemptId: Uint8Array,
    afterSequence: bigint,
  ): Promise<RemoteSignalingReadResultV1>;
  metadata(
    daemonInstanceId: string,
    childAttemptId: Uint8Array,
  ): Promise<{ attemptWakeRouteId: Uint8Array; expiresAtMs: number } | { kind: "unavailable" }>;
  authenticateInstanceWake(
    daemonInstanceId: string,
    certificateGeneration: bigint,
    socketGeneration: bigint,
    authoritativeAfterSeq: bigint,
  ): Promise<RemoteInstanceWakeLeaseV1>;
  renewInstanceWake(
    daemonInstanceId: string,
    certificateGeneration: bigint,
    lease: RemoteInstanceWakeLeaseV1,
  ): Promise<RemoteInstanceWakeLeaseV1>;
  readDiscovery(
    daemonInstanceId: string,
    certificateGeneration: bigint,
    socketGeneration: bigint,
    afterSeq: bigint,
  ): Promise<RemoteDiscoveryReadResultV1>;
  ackDiscovery(
    daemonInstanceId: string,
    certificateGeneration: bigint,
    socketGeneration: bigint,
    expectedPriorSeq: bigint,
    newSeq: bigint,
    expiredGap?: boolean,
  ): Promise<void>;
  closeInstanceWake(
    daemonInstanceId: string,
    certificateGeneration: bigint,
    lease: RemoteInstanceWakeLeaseV1,
  ): Promise<void>;
  discoveryHighWater(daemonInstanceId: string, certificateGeneration: bigint): Promise<bigint>;
  /**
   * Mint a single-use admission ticket. Only `SHA-256(secret)` plus bindings are
   * stored (never the raw secret), with a 30 s TTL. The plaintext secret is
   * returned to the caller once and never persisted.
   */
  /**
   * Allocate a cross-replica-monotonic control socket generation for
   * `(daemonInstanceId, certificateGeneration)` (Redis `INCR`; memory parity).
   */
  allocateControlSocketGeneration(
    daemonInstanceId: string,
    certificateGeneration: bigint,
  ): Promise<bigint>;
  issueClientAdmissionTicket(
    input: RemoteSignalingAdmissionTicketInput,
  ): Promise<RemoteSignalingAdmissionTicketV1>;
  /** Non-consuming lookup of a ticket's target instance/child for gateway routing. */
  resolveAdmissionTicket(ticketId: Uint8Array): Promise<RemoteSignalingAdmissionTicketRoute | null>;
  /**
   * Atomically consume the ticket and apply the `client_admission_proof` (kind 3)
   * transition. Ticket expiry, secret digest, origin class, child attempt, and
   * `admissionProofSha256` vs `SHA-256(request payload)` are all checked in the
   * same atomic step; any mismatch throws `auth_failed` WITHOUT consuming the
   * ticket, and a consumed ticket is gone across replicas so a concurrent
   * double-connect admits exactly one socket. The actor is derived from the
   * ticket, never from client-declared bytes.
   */
  commitClientAdmission(
    daemonInstanceId: string,
    childAttemptId: Uint8Array,
    requestBytes: Uint8Array,
    ticket: RemoteSignalingAdmissionTicketProof,
  ): Promise<RemoteSignalingClientAdmissionResultV1>;
  /**
   * Acquire one live signal-socket lease for a device attachment. Throws
   * `conflict` when the attachment already holds
   * `REMOTE_SIGNALING_MAX_SIGNALING_SOCKETS_PER_ATTACHMENT` unexpired leases.
   * Re-acquiring an already-held `leaseId` refreshes it (idempotent).
   */
  acquireSignalingSocketLease(deviceAttachmentId: string, leaseId: string): Promise<void>;
  /** Release a previously acquired signal-socket lease. Idempotent. */
  releaseSignalingSocketLease(deviceAttachmentId: string, leaseId: string): Promise<void>;
  close(): Promise<void>;
}
interface Attempt {
  input: RemoteSignalingAttemptCreateV1 & { createdAtMs: number; expiresAtMs: number };
  wakeRouteId: Uint8Array;
  state: RemoteSignalingAttemptState;
  sequence: bigint;
  totalBytes: number;
  events: RemoteSignalingCommittedEventV1[];
  idempotency: Map<
    string,
    {
      bytes: Uint8Array;
      actor: RemoteSignalingActorBindingV1;
      result: RemoteSignalingCommitResultV1;
    }
  >;
  markers: Set<string>;
  clientCandidates: number;
  daemonCandidates: number;
  proofs: Map<"client" | "daemon", Uint8Array>;
  finalProofSetDigest?: Uint8Array;
  daemonOfferDigest?: Uint8Array;
  daemonOfferJti?: Uint8Array;
}
interface MemoryAdmissionTicket {
  secretSha256Hex: string;
  originClass: string;
  childAttemptId: Uint8Array;
  admissionProofSha256Hex: string;
  daemonInstanceId: string;
  accountId: string;
  deviceAttachmentId: string;
  deviceGeneration: bigint;
  expiresAtMs: number;
}
interface MemoryDiscoveryGeneration {
  latest: bigint;
  expiredThrough: bigint;
  highWater: bigint;
  routeGeneration: bigint;
  entries: Map<bigint, RemoteDiscoveryEntryV1>;
  cursors: Map<bigint, bigint>;
  wake?: RemoteInstanceWakeLeaseV1;
}
const terminal = new Set<RemoteSignalingAttemptState>([
  "completed",
  "rejected",
  "cancelled",
  "superseded",
]);
const equal = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((v, i) => v === b[i]);
const actorEqual = (a: RemoteSignalingActorBindingV1, b: RemoteSignalingActorBindingV1) =>
  a.role === b.role && a.actor === b.actor && a.generation === b.generation;
const key = (instance: string, child: Uint8Array) =>
  `${instance}/${encodeProtocolIdBase64Url(child)}`;
const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
function randomId(random: (bytes: Uint8Array) => void) {
  const id = new Uint8Array(16);
  do random(id);
  while (id.every((x) => x === 0));
  return id;
}
function expectedRole(role: number) {
  return role === 1 ? "server" : role === 2 ? "client" : "daemon";
}
function validateTypedPayloadUnchecked(request: RemoteSignalingEventRequestV1) {
  let child: Uint8Array | undefined;
  if (request.eventKind === 1)
    child = decodeRemoteChildAuthenticationBundleV1(request.payload).childAttemptId;
  if (request.eventKind === 2) child = decodeDaemonAdmissionOfferV1(request.payload).childAttemptId;
  if (request.eventKind === 3) {
    const proof = decodeClientAdmissionProofV1(request.payload);
    if (proof.chosenTransport !== request.transport)
      throw new RemoteSignalingStoreError("unavailable");
    child = proof.childAttemptId;
  }
  if (request.eventKind === 4) child = decodeRemoteWebRtcOfferV1(request.payload).childAttemptId;
  if (request.eventKind === 5) child = decodeRemoteWebRtcAnswerV1(request.payload).childAttemptId;
  if (request.eventKind === 6) {
    const candidate = decodeRemoteWebRtcCandidateV1(request.payload);
    if (candidate.role !== request.producerRole - 1)
      throw new RemoteSignalingStoreError("unavailable");
    child = candidate.childAttemptId;
  }
  if (request.eventKind === 7) {
    const complete = decodeRemoteWebRtcIceCompleteV1(request.payload);
    if (complete.role !== request.producerRole - 1)
      throw new RemoteSignalingStoreError("unavailable");
    child = complete.childAttemptId;
  }
  if (child && !equal(child, request.childAttemptId))
    throw new RemoteSignalingStoreError("unavailable");
  if (request.eventKind === 8) decodeRemoteFallbackPairAuthenticatedV1(request.payload);
  if (request.eventKind === 9) {
    const noise = decodeRemoteFallbackNoiseCompleteV1(request.payload);
    if (noise.role !== request.producerRole - 1) throw new RemoteSignalingStoreError("unavailable");
  }
  if (request.eventKind === 10 || request.eventKind === 11) {
    const proof = decodeRemoteEndpointFinalProofV1(request.payload);
    if (
      proof.role !== request.producerRole - 1 ||
      proof.transport !== request.transport ||
      !equal(proof.childAttemptId, request.childAttemptId)
    )
      throw new RemoteSignalingStoreError("unavailable");
  }
  if (request.eventKind === 12) decodeRemoteSignalingReadyV1(request.payload);
}
function validateTypedPayload(request: RemoteSignalingEventRequestV1) {
  try {
    validateTypedPayloadUnchecked(request);
  } catch (error) {
    if (error instanceof RemoteSignalingStoreError) throw error;
    throw new RemoteSignalingStoreError("unavailable");
  }
}
function validateDiscoveryBinding(
  request: RemoteSignalingEventRequestV1,
  discovery: RemoteSignalingAttemptCreateV1["discovery"],
) {
  if (!discovery) return;
  if (
    discovery.discoveryId.length !== 16 ||
    discovery.discoveryId.every((byte) => byte === 0) ||
    discovery.authBundleDigest.length !== 32 ||
    !equal(
      remoteChildAuthenticationDigests(request.payload).authBundleDigest,
      discovery.authBundleDigest,
    )
  )
    throw new RemoteSignalingStoreError("unavailable");
}
function applyTransition(attempt: Attempt, request: RemoteSignalingEventRequestV1) {
  const kind = request.eventKind,
    role = expectedRole(request.producerRole),
    mark = (name: string) => {
      if (attempt.markers.has(name)) throw new RemoteSignalingStoreError("invalid_transition");
      attempt.markers.add(name);
    };
  if (terminal.has(attempt.state)) throw new RemoteSignalingStoreError("invalid_transition");
  const event = Object.entries(RemoteSignalingEventKind).find(([, value]) => value === kind)?.[0],
    declared = REMOTE_SIGNALING_TRANSITION_ROWS.some(
      (row) =>
        (row.transport === "common" || row.transport === attempt.input.transportKind) &&
        row.event === event &&
        row.role === role &&
        (row.from === "nonterminal" || row.from.split("|").includes(attempt.state)),
    );
  if (!declared) throw new RemoteSignalingStoreError("invalid_transition");
  if (kind === 2 && attempt.state === "created") {
    const offer = decodeDaemonAdmissionOfferV1(request.payload);
    attempt.daemonOfferDigest = daemonAdmissionOfferDigest(request.payload);
    attempt.daemonOfferJti = offer.offerJti.slice();
    mark("daemon_offer");
    attempt.state = "daemon_offered";
    return;
  }
  if (kind === 3 && attempt.state === "daemon_offered") {
    const proof = decodeClientAdmissionProofV1(request.payload);
    if (
      !attempt.daemonOfferDigest ||
      !attempt.daemonOfferJti ||
      !equal(attempt.daemonOfferDigest, proof.daemonOfferDigest) ||
      !equal(attempt.daemonOfferJti, proof.daemonOfferJti)
    )
      throw new RemoteSignalingStoreError("invalid_transition");
    mark("admission");
    attempt.state = "admitted";
    return;
  }
  if (kind === 4 && attempt.state === "admitted") {
    mark("offer");
    attempt.state = "offered";
    return;
  }
  if (kind === 5 && attempt.state === "offered") {
    mark("answer");
    attempt.state = "answered";
    return;
  }
  if (kind === 6 && (attempt.state === "offered" || attempt.state === "answered")) {
    const field = role === "client" ? "clientCandidates" : "daemonCandidates";
    if (
      (role === "daemon" && attempt.state !== "answered") ||
      attempt[field] >= REMOTE_SIGNALING_MAX_CANDIDATES_PER_ROLE ||
      attempt.markers.has(`${role}_ice_complete`)
    )
      throw new RemoteSignalingStoreError("invalid_transition");
    attempt[field]++;
    return;
  }
  if (kind === 7 && (attempt.state === "offered" || attempt.state === "answered")) {
    if (role === "daemon" && attempt.state !== "answered")
      throw new RemoteSignalingStoreError("invalid_transition");
    mark(`${role}_ice_complete`);
    return;
  }
  if (kind === 8 && attempt.state === "admitted" && role === "server") {
    mark("fallback_pair");
    attempt.state = "fallback_paired";
    return;
  }
  if (
    kind === 9 &&
    (attempt.state === "fallback_paired" || attempt.state === "fallback_noise_complete")
  ) {
    mark(`${role}_noise`);
    if (attempt.markers.has("client_noise") && attempt.markers.has("daemon_noise"))
      attempt.state = "fallback_noise_complete";
    return;
  }
  if (
    (kind === 10 || kind === 11) &&
    ((attempt.input.transportKind === "webrtc" && attempt.state === "answered") ||
      (attempt.input.transportKind === "websocket_data" &&
        attempt.state === "fallback_noise_complete"))
  ) {
    const proof = decodeRemoteEndpointFinalProofV1(request.payload);
    if (
      attempt.input.transportKind === "webrtc" &&
      (!attempt.markers.has("client_ice_complete") || !attempt.markers.has("daemon_ice_complete"))
    )
      throw new RemoteSignalingStoreError("invalid_transition");
    const opposite = attempt.proofs.get(role === "client" ? "daemon" : "client");
    if (opposite) {
      const oppositeProof = decodeRemoteEndpointFinalProofV1(opposite);
      if (
        !equal(
          remoteEndpointFinalProofAgreementBytes(proof),
          remoteEndpointFinalProofAgreementBytes(oppositeProof),
        )
      )
        throw new RemoteSignalingStoreError("invalid_transition");
    }
    mark(`${role}_proof`);
    attempt.proofs.set(role as "client" | "daemon", request.payload.slice());
    const client = attempt.proofs.get("client"),
      daemon = attempt.proofs.get("daemon");
    if (client && daemon) attempt.finalProofSetDigest = remoteFinalProofSetDigest(client, daemon);
    return;
  }
  if (
    kind === 12 &&
    (attempt.state === "answered" || attempt.state === "fallback_noise_complete")
  ) {
    const client = attempt.proofs.get("client"),
      daemon = attempt.proofs.get("daemon"),
      opposite = role === "client" ? daemon : client;
    const ready = decodeRemoteSignalingReadyV1(request.payload);
    const oppositeProof = opposite && decodeRemoteEndpointFinalProofV1(opposite);
    if (
      !client ||
      !daemon ||
      !opposite ||
      !attempt.finalProofSetDigest ||
      !oppositeProof ||
      !equal(ready.verifiedPeerProofJti, oppositeProof.proofJti) ||
      !equal(ready.finalProofSetDigest, attempt.finalProofSetDigest)
    )
      throw new RemoteSignalingStoreError("invalid_transition");
    mark(`${role}_ready`);
    if (attempt.markers.has("client_ready") && attempt.markers.has("daemon_ready"))
      attempt.state = "completed";
    return;
  }
  if (kind === 13 && (role === "server" || role === "daemon")) {
    attempt.state = "rejected";
    return;
  }
  if (kind === 14) {
    attempt.state = "cancelled";
    return;
  }
  if (kind === 15 && role === "server") {
    attempt.state = "superseded";
    return;
  }
  throw new RemoteSignalingStoreError("invalid_transition");
}

export class MemoryRemoteSignalingAttemptStore implements RemoteSignalingAttemptStore {
  private readonly attempts = new Map<string, Attempt>();
  private readonly discovery = new Map<string, MemoryDiscoveryGeneration>();
  private readonly tickets = new Map<string, MemoryAdmissionTicket>();
  private readonly ticketRoutes = new Map<
    string,
    { instance: string; child: Uint8Array; expiresAtMs: number }
  >();
  private readonly leases = new Map<string, Map<string, number>>();
  private readonly socketGenerations = new Map<string, bigint>();
  constructor(
    private readonly now = () => Date.now(),
    private readonly random = (out: Uint8Array) =>
      out.set(crypto.getRandomValues(new Uint8Array(out.length))),
    private readonly wake: (route: Uint8Array, latest: bigint) => void = () => {},
  ) {}
  private evictExpired() {
    const now = this.now();
    for (const [storeKey, attempt] of this.attempts)
      if (now >= attempt.input.expiresAtMs) this.attempts.delete(storeKey);
    for (const [ticketKey, ticket] of this.tickets)
      if (now >= ticket.expiresAtMs) this.tickets.delete(ticketKey);
    for (const [routeKey, route] of this.ticketRoutes)
      if (now >= route.expiresAtMs) this.ticketRoutes.delete(routeKey);
    for (const [attachment, held] of this.leases) {
      for (const [leaseId, expiresAtMs] of held) if (now >= expiresAtMs) held.delete(leaseId);
      if (held.size === 0) this.leases.delete(attachment);
    }
    for (const generation of this.discovery.values()) {
      for (const [sequence, entry] of generation.entries)
        if (now >= entry.expiresAtMs) generation.entries.delete(sequence);
      while (
        generation.expiredThrough < generation.latest &&
        !generation.entries.has(generation.expiredThrough + 1n)
      )
        generation.expiredThrough++;
      if (generation.wake && now >= generation.wake.expiresAtMs) {
        generation.wake = undefined;
        generation.cursors.clear();
      }
    }
  }
  private discoveryGeneration(instance: string, certificateGeneration: bigint) {
    const discoveryKey = `${instance}/${certificateGeneration}`;
    let generation = this.discovery.get(discoveryKey);
    if (!generation) {
      generation = {
        latest: 0n,
        expiredThrough: 0n,
        highWater: 0n,
        routeGeneration: 0n,
        entries: new Map(),
        cursors: new Map(),
      };
      this.discovery.set(discoveryKey, generation);
    }
    return generation;
  }
  async create(
    input: RemoteSignalingAttemptCreateV1,
    bytes: Uint8Array,
    actor: RemoteSignalingActorBindingV1,
  ) {
    this.evictExpired();
    const request = decodeRemoteSignalingEventRequestV1(bytes);
    validateTypedPayload(request);
    if (request.eventKind !== 1 || !equal(request.childAttemptId, input.childAttemptId))
      throw new RemoteSignalingStoreError("unavailable");
    validateDiscoveryBinding(request, input.discovery);
    const storeKey = key(input.daemonInstanceId, input.childAttemptId);
    if (this.attempts.has(storeKey))
      return this.commit(input.daemonInstanceId, input.childAttemptId, bytes, actor, true);
    const createdAtMs = this.now();
    const attempt: Attempt = {
      input: {
        ...structuredClone(input),
        createdAtMs,
        expiresAtMs: createdAtMs + REMOTE_SIGNALING_ATTEMPT_TTL_MS,
      },
      wakeRouteId: randomId(this.random),
      state: "created",
      sequence: 0n,
      totalBytes: 0,
      events: [],
      idempotency: new Map(),
      markers: new Set(),
      clientCandidates: 0,
      daemonCandidates: 0,
      proofs: new Map(),
    };
    this.attempts.set(storeKey, attempt);
    try {
      const result = await this.commit(
        input.daemonInstanceId,
        input.childAttemptId,
        bytes,
        actor,
        true,
      );
      if (input.discovery) {
        const generation = this.discoveryGeneration(
          input.daemonInstanceId,
          input.discovery.daemonCertificateGeneration,
        );
        const discoverySeq = ++generation.latest;
        generation.entries.set(discoverySeq, {
          discoverySeq,
          discoveryId: input.discovery.discoveryId.slice(),
          childAttemptId: input.childAttemptId.slice(),
          attemptWakeRouteId: attempt.wakeRouteId.slice(),
          authBundleDigest: input.discovery.authBundleDigest.slice(),
          expiresAtMs: attempt.input.expiresAtMs,
        });
      }
      return result;
    } catch (error) {
      this.attempts.delete(storeKey);
      throw error;
    }
  }
  async commit(
    instance: string,
    child: Uint8Array,
    bytes: Uint8Array,
    actor: RemoteSignalingActorBindingV1,
    creating = false,
  ): Promise<RemoteSignalingCommitResultV1> {
    this.evictExpired();
    const attempt = this.attempts.get(key(instance, child));
    if (!attempt || this.now() >= attempt.input.expiresAtMs) {
      this.attempts.delete(key(instance, child));
      throw new RemoteSignalingStoreError("unavailable");
    }
    const request = decodeRemoteSignalingEventRequestV1(bytes);
    validateTypedPayload(request);
    if (
      !equal(request.childAttemptId, child) ||
      expectedRole(request.producerRole) !== actor.role ||
      (request.transport === 1 ? "webrtc" : "websocket_data") !== attempt.input.transportKind
    )
      throw new RemoteSignalingStoreError("unavailable");
    const eventKey = hex(request.eventId),
      prior = attempt.idempotency.get(eventKey);
    if (prior) {
      if (!equal(prior.bytes, bytes)) throw new RemoteSignalingStoreError("conflict");
      if (!actorEqual(prior.actor, actor)) throw new RemoteSignalingStoreError("unavailable");
      return { ...prior.result, kind: "replay", ackBytes: prior.result.ackBytes.slice() };
    }
    if (creating && attempt.sequence !== 0n) throw new RemoteSignalingStoreError("conflict");
    if (
      attempt.events.length >= REMOTE_SIGNALING_MAX_EVENTS ||
      attempt.totalBytes + bytes.length > REMOTE_SIGNALING_MAX_AGGREGATE_BYTES
    )
      throw new RemoteSignalingStoreError("limit");
    if (!creating) applyTransition(attempt, request);
    const sequence = ++attempt.sequence,
      digest = remoteSignalingEventDigest(bytes);
    const ack: RemoteSignalingCommitAckV1 = {
      eventId: request.eventId,
      sequence,
      eventDigest: digest,
    };
    const result: RemoteSignalingCommitResultV1 = {
      kind: "committed",
      sequence,
      ackBytes: encodeRemoteSignalingCommitAckV1(ack),
    };
    const event = {
      sequence,
      redisCreatedAtMs: this.now(),
      requestBytes: bytes.slice(),
      request,
      actor: { ...actor },
      ackBytes: result.ackBytes.slice(),
    };
    attempt.events.push(event);
    attempt.totalBytes += bytes.length;
    attempt.idempotency.set(eventKey, { bytes: bytes.slice(), actor: { ...actor }, result });
    this.wake(attempt.wakeRouteId.slice(), sequence);
    return { ...result, ackBytes: result.ackBytes.slice() };
  }
  async read(
    instance: string,
    child: Uint8Array,
    after: bigint,
  ): Promise<RemoteSignalingReadResultV1> {
    this.evictExpired();
    const attempt = this.attempts.get(key(instance, child));
    if (!attempt || this.now() >= attempt.input.expiresAtMs) {
      this.attempts.delete(key(instance, child));
      return { kind: "unavailable" };
    }
    const events: RemoteSignalingCommittedEventV1[] = [];
    let bytes = 0;
    for (const event of attempt.events) {
      if (event.sequence <= after) continue;
      if (
        events.length === REMOTE_SIGNALING_READ_MAX_EVENTS ||
        bytes + event.requestBytes.length > REMOTE_SIGNALING_READ_MAX_BYTES
      )
        break;
      events.push(structuredClone(event));
      bytes += event.requestBytes.length;
    }
    return { kind: "events", events, latestSequence: attempt.sequence };
  }
  async metadata(instance: string, child: Uint8Array) {
    this.evictExpired();
    const attempt = this.attempts.get(key(instance, child));
    if (!attempt || this.now() >= attempt.input.expiresAtMs) {
      this.attempts.delete(key(instance, child));
      return { kind: "unavailable" as const };
    }
    return {
      attemptWakeRouteId: attempt.wakeRouteId.slice(),
      expiresAtMs: attempt.input.expiresAtMs,
    };
  }
  async authenticateInstanceWake(
    instance: string,
    certificateGeneration: bigint,
    socketGeneration: bigint,
    authoritativeAfterSeq: bigint,
  ): Promise<RemoteInstanceWakeLeaseV1> {
    this.evictExpired();
    const generation = this.discoveryGeneration(instance, certificateGeneration);
    if (!socketGeneration || authoritativeAfterSeq !== generation.highWater)
      throw new RemoteSignalingStoreError("conflict");
    const existingCursor = generation.cursors.get(socketGeneration);
    if (existingCursor !== undefined && existingCursor !== authoritativeAfterSeq)
      throw new RemoteSignalingStoreError("conflict");
    generation.cursors.set(socketGeneration, authoritativeAfterSeq);
    const lease = {
      instanceWakeRouteId: randomId(this.random),
      instanceWakeRouteGeneration: ++generation.routeGeneration,
      socketGeneration,
      expiresAtMs: this.now() + 45_000,
    };
    generation.wake = lease;
    return structuredClone(lease);
  }
  async renewInstanceWake(
    instance: string,
    certificateGeneration: bigint,
    lease: RemoteInstanceWakeLeaseV1,
  ) {
    this.evictExpired();
    const current = this.discoveryGeneration(instance, certificateGeneration).wake;
    if (
      !current ||
      current.socketGeneration !== lease.socketGeneration ||
      current.instanceWakeRouteGeneration !== lease.instanceWakeRouteGeneration ||
      !equal(current.instanceWakeRouteId, lease.instanceWakeRouteId)
    )
      throw new RemoteSignalingStoreError("unavailable");
    current.expiresAtMs = this.now() + 45_000;
    return structuredClone(current);
  }
  async readDiscovery(
    instance: string,
    certificateGeneration: bigint,
    socketGeneration: bigint,
    afterSeq: bigint,
  ): Promise<RemoteDiscoveryReadResultV1> {
    this.evictExpired();
    const generation = this.discoveryGeneration(instance, certificateGeneration);
    if (
      generation.wake?.socketGeneration !== socketGeneration ||
      generation.cursors.get(socketGeneration) !== afterSeq
    )
      return { kind: "unavailable" };
    if (afterSeq < generation.expiredThrough)
      return {
        kind: "expired_gap",
        expectedAfterSeq: afterSeq,
        expiredThroughSeq: generation.expiredThrough,
        latestDiscoverySeq: generation.latest,
      };
    const entries: RemoteDiscoveryEntryV1[] = [];
    let bytes = 0;
    for (let sequence = afterSeq + 1n; sequence <= generation.latest; sequence++) {
      const entry = generation.entries.get(sequence);
      if (!entry) return { kind: "unavailable" };
      const attempt = this.attempts.get(key(instance, entry.childAttemptId)),
        available = attempt?.events[0];
      if (
        !attempt ||
        !available ||
        !equal(attempt.wakeRouteId, entry.attemptWakeRouteId) ||
        !equal(
          remoteChildAuthenticationDigests(available.request.payload).authBundleDigest,
          entry.authBundleDigest,
        )
      )
        return { kind: "unavailable" };
      const size = 16 + 16 + 16 + 32 + 8;
      if (
        entries.length >= REMOTE_SIGNALING_READ_MAX_EVENTS ||
        bytes + size > REMOTE_SIGNALING_READ_MAX_BYTES
      )
        break;
      entries.push(structuredClone(entry));
      bytes += size;
    }
    return { kind: "entries", entries, latestDiscoverySeq: generation.latest };
  }
  async ackDiscovery(
    instance: string,
    certificateGeneration: bigint,
    socketGeneration: bigint,
    expectedPriorSeq: bigint,
    newSeq: bigint,
    expiredGap = false,
  ) {
    this.evictExpired();
    const generation = this.discoveryGeneration(instance, certificateGeneration);
    if (
      generation.wake?.socketGeneration !== socketGeneration ||
      generation.cursors.get(socketGeneration) !== expectedPriorSeq ||
      newSeq < expectedPriorSeq ||
      newSeq > generation.latest ||
      (expiredGap && newSeq !== generation.expiredThrough) ||
      (!expiredGap && !generation.entries.has(newSeq))
    )
      throw new RemoteSignalingStoreError("conflict");
    generation.cursors.set(socketGeneration, newSeq);
    generation.highWater = newSeq;
  }
  async closeInstanceWake(
    instance: string,
    certificateGeneration: bigint,
    lease: RemoteInstanceWakeLeaseV1,
  ) {
    const generation = this.discoveryGeneration(instance, certificateGeneration),
      current = generation.wake;
    if (
      current?.socketGeneration === lease.socketGeneration &&
      current.instanceWakeRouteGeneration === lease.instanceWakeRouteGeneration &&
      equal(current.instanceWakeRouteId, lease.instanceWakeRouteId)
    )
      generation.wake = undefined;
    generation.cursors.delete(lease.socketGeneration);
  }
  async discoveryHighWater(instance: string, certificateGeneration: bigint) {
    this.evictExpired();
    return this.discoveryGeneration(instance, certificateGeneration).highWater;
  }
  async allocateControlSocketGeneration(instance: string, certificateGeneration: bigint) {
    const generationKey = `${instance}/${certificateGeneration}`;
    const next = (this.socketGenerations.get(generationKey) ?? 0n) + 1n;
    this.socketGenerations.set(generationKey, next);
    return next;
  }
  async issueClientAdmissionTicket(
    input: RemoteSignalingAdmissionTicketInput,
  ): Promise<RemoteSignalingAdmissionTicketV1> {
    this.evictExpired();
    if (input.admissionProofSha256.length !== 32)
      throw new RemoteSignalingStoreError("unavailable");
    const ticketId = randomId(this.random);
    const secret = new Uint8Array(32);
    do this.random(secret);
    while (secret.every((byte) => byte === 0));
    const expiresAtMs = this.now() + REMOTE_SIGNALING_ADMISSION_TICKET_TTL_MS;
    this.tickets.set(`${input.daemonInstanceId}/${hex(ticketId)}`, {
      secretSha256Hex: sha256Hex(secret),
      originClass: input.originClass,
      childAttemptId: input.childAttemptId.slice(),
      admissionProofSha256Hex: hex(input.admissionProofSha256),
      daemonInstanceId: input.daemonInstanceId,
      accountId: input.accountId,
      deviceAttachmentId: input.deviceAttachmentId,
      deviceGeneration: input.deviceGeneration,
      expiresAtMs,
    });
    this.ticketRoutes.set(hex(ticketId), {
      instance: input.daemonInstanceId,
      child: input.childAttemptId.slice(),
      expiresAtMs,
    });
    return { ticketId, secret };
  }
  async resolveAdmissionTicket(
    ticketId: Uint8Array,
  ): Promise<RemoteSignalingAdmissionTicketRoute | null> {
    this.evictExpired();
    const route = this.ticketRoutes.get(hex(ticketId));
    if (!route || this.now() >= route.expiresAtMs) return null;
    return { daemonInstanceId: route.instance, childAttemptId: route.child.slice() };
  }
  async commitClientAdmission(
    instance: string,
    child: Uint8Array,
    requestBytes: Uint8Array,
    ticket: RemoteSignalingAdmissionTicketProof,
  ): Promise<RemoteSignalingClientAdmissionResultV1> {
    this.evictExpired();
    const request = decodeRemoteSignalingEventRequestV1(requestBytes);
    validateTypedPayload(request);
    if (request.eventKind !== 3 || !equal(request.childAttemptId, child))
      throw new RemoteSignalingStoreError("unavailable");
    // Ticket authentication FIRST — a wrong-secret / absent-ticket replay must
    // fail closed, never reach the idempotency/replay path (which would let a
    // second socket admit off one consumed ticket).
    const ticketKey = `${instance}/${hex(ticket.ticketId)}`;
    const stored = this.tickets.get(ticketKey);
    if (
      !stored ||
      this.now() >= stored.expiresAtMs ||
      stored.secretSha256Hex !== ticket.secretSha256Hex ||
      stored.originClass !== ticket.originClass ||
      !equal(stored.childAttemptId, child) ||
      stored.admissionProofSha256Hex !== sha256Hex(request.payload)
    )
      throw new RemoteSignalingStoreError("auth_failed");
    // Idempotent replay (reachable only while the ticket is still valid — a
    // successful admission consumes it, so a genuine cross-call replay hits
    // auth_failed above).
    const attempt = this.attempts.get(key(instance, child));
    const eventKey = hex(request.eventId);
    const prior = attempt?.idempotency.get(eventKey);
    if (prior) {
      if (!equal(prior.bytes, requestBytes)) throw new RemoteSignalingStoreError("conflict");
      return {
        result: { ...prior.result, kind: "replay", ackBytes: prior.result.ackBytes.slice() },
        actor: { ...prior.actor },
        childAttemptId: child.slice(),
        deviceAttachmentId: prior.actor.actor,
        deviceGeneration: prior.actor.generation,
      };
    }
    const actor: RemoteSignalingActorBindingV1 = {
      role: "client",
      actor: stored.deviceAttachmentId,
      generation: stored.deviceGeneration,
    };
    // Apply the transition first; only a successful admission consumes the ticket.
    const result = await this.commit(instance, child, requestBytes, actor);
    this.tickets.delete(ticketKey);
    return {
      result,
      actor,
      childAttemptId: child.slice(),
      deviceAttachmentId: stored.deviceAttachmentId,
      deviceGeneration: stored.deviceGeneration,
    };
  }
  async acquireSignalingSocketLease(deviceAttachmentId: string, leaseId: string): Promise<void> {
    const now = this.now();
    let held = this.leases.get(deviceAttachmentId);
    if (!held) {
      held = new Map();
      this.leases.set(deviceAttachmentId, held);
    }
    for (const [id, expiresAtMs] of held) if (now >= expiresAtMs) held.delete(id);
    if (!held.has(leaseId) && held.size >= REMOTE_SIGNALING_MAX_SIGNALING_SOCKETS_PER_ATTACHMENT)
      throw new RemoteSignalingStoreError("conflict");
    held.set(leaseId, now + REMOTE_SIGNALING_SOCKET_LEASE_TTL_MS);
  }
  async releaseSignalingSocketLease(deviceAttachmentId: string, leaseId: string): Promise<void> {
    const held = this.leases.get(deviceAttachmentId);
    if (!held) return;
    held.delete(leaseId);
    if (held.size === 0) this.leases.delete(deviceAttachmentId);
  }
  async close() {}
}

/** Production ownership wrapper. Mutations fail closed; there is deliberately no memory fallback. */
export class RedisRemoteSignalingAttemptStore implements RemoteSignalingAttemptStore {
  constructor(
    private readonly redis: Redis = createRedisConnection({ maxRetriesPerRequest: 3 }),
    private readonly random = (out: Uint8Array) =>
      out.set(crypto.getRandomValues(new Uint8Array(out.length))),
  ) {}
  private keys(instance: string, child: Uint8Array) {
    if (!/^[A-Za-z0-9_-]{22}$/.test(instance)) throw new RemoteSignalingStoreError("unavailable");
    const base = `flycockpit:remote-signaling:{${instance}}:attempt:${encodeProtocolIdBase64Url(child)}`;
    return [`${base}:metadata`, `${base}:events`, `${base}:idempotency`] as const;
  }
  private discoveryKeys(instance: string, certificateGeneration: bigint, socketGeneration: bigint) {
    if (!/^[A-Za-z0-9_-]{22}$/.test(instance)) throw new RemoteSignalingStoreError("unavailable");
    const base = `flycockpit:remote-signaling:{${instance}}`;
    return {
      index: `${base}:discovery:${certificateGeneration}`,
      expired: `${base}:discovery-expired-through:${certificateGeneration}`,
      cursor: `${base}:discovery-cursor:${certificateGeneration}:${socketGeneration}`,
      wake: `${base}:instance-wake:${certificateGeneration}`,
    };
  }
  private actor(actor: RemoteSignalingActorBindingV1) {
    return JSON.stringify({
      role: actor.role,
      actor: actor.actor,
      generation: actor.generation.toString(),
    });
  }
  private result(
    kind: "committed" | "replay",
    sequence: bigint,
    request: RemoteSignalingEventRequestV1,
    bytes: Uint8Array,
  ) {
    return {
      kind,
      sequence,
      ackBytes: encodeRemoteSignalingCommitAckV1({
        eventId: request.eventId,
        sequence,
        eventDigest: remoteSignalingEventDigest(bytes),
      }),
    } as RemoteSignalingCommitResultV1;
  }
  async create(
    input: RemoteSignalingAttemptCreateV1,
    bytes: Uint8Array,
    actor: RemoteSignalingActorBindingV1,
  ) {
    const request = decodeRemoteSignalingEventRequestV1(bytes);
    validateTypedPayload(request);
    if (
      request.eventKind !== 1 ||
      !equal(request.childAttemptId, input.childAttemptId) ||
      expectedRole(request.producerRole) !== actor.role ||
      (request.transport === 1 ? "webrtc" : "websocket_data") !== input.transportKind
    )
      throw new RemoteSignalingStoreError("unavailable");
    validateDiscoveryBinding(request, input.discovery);
    const wake = randomId(this.random);
    const discovery = input.discovery,
      discoveryKeys = this.discoveryKeys(
        input.daemonInstanceId,
        discovery?.daemonCertificateGeneration ?? 0n,
        0n,
      );
    const reply = (await this.redis.eval(
      REMOTE_SIGNALING_CREATE_LUA,
      6,
      ...this.keys(input.daemonInstanceId, input.childAttemptId),
      discoveryKeys.index,
      discoveryKeys.expired,
      discoveryKeys.wake,
      encodeProtocolIdBase64Url(input.childAttemptId),
      input.transportKind,
      hex(wake),
      input.participantRefs[0],
      input.participantRefs[1],
      bytes.length.toString(),
      Buffer.from(bytes),
      this.actor(actor),
      hex(request.eventId),
      hex(bytes),
      discovery ? "1" : "0",
      discovery ? hex(discovery.discoveryId) : "",
      discovery ? hex(discovery.authBundleDigest) : "",
      hex(input.childAttemptId),
    )) as string[];
    if (reply[0] === "replay") return this.result("replay", BigInt(reply[1]!), request, bytes);
    if (reply[0] === "conflict") throw new RemoteSignalingStoreError("conflict");
    if (reply[0] !== "committed") throw new RemoteSignalingStoreError("unavailable");
    return this.result("committed", 1n, request, bytes);
  }
  async commit(
    instance: string,
    child: Uint8Array,
    bytes: Uint8Array,
    actor: RemoteSignalingActorBindingV1,
  ) {
    const request = decodeRemoteSignalingEventRequestV1(bytes);
    validateTypedPayload(request);
    if (!equal(request.childAttemptId, child) || expectedRole(request.producerRole) !== actor.role)
      throw new RemoteSignalingStoreError("unavailable");
    const keys = this.keys(instance, child);
    let agreement = "",
      proofJti = "",
      peerProofJti = "",
      suppliedProofSetDigest = "",
      expectedProofSetDigest = "",
      daemonOfferDigestHex = "",
      daemonOfferJtiHex = "";
    if (request.eventKind === 2) {
      const offer = decodeDaemonAdmissionOfferV1(request.payload);
      daemonOfferDigestHex = hex(daemonAdmissionOfferDigest(request.payload));
      daemonOfferJtiHex = hex(offer.offerJti);
    } else if (request.eventKind === 3) {
      const proof = decodeClientAdmissionProofV1(request.payload);
      daemonOfferDigestHex = hex(proof.daemonOfferDigest);
      daemonOfferJtiHex = hex(proof.daemonOfferJti);
    }
    if (request.eventKind === 10 || request.eventKind === 11) {
      const proof = decodeRemoteEndpointFinalProofV1(request.payload);
      agreement = hex(remoteEndpointFinalProofAgreementBytes(proof));
      proofJti = hex(proof.proofJti);
      const peerPayload = await this.redis.hget(
        keys[0],
        request.eventKind === 10 ? "daemonProofPayload" : "clientProofPayload",
      );
      if (peerPayload) {
        const peer = Uint8Array.from(
          peerPayload.match(/../g)!.map((byte) => Number.parseInt(byte, 16)),
        );
        try {
          expectedProofSetDigest = hex(
            request.eventKind === 10
              ? remoteFinalProofSetDigest(request.payload, peer)
              : remoteFinalProofSetDigest(peer, request.payload),
          );
        } catch {
          throw new RemoteSignalingStoreError("invalid_transition");
        }
      }
    } else if (request.eventKind === 12) {
      const ready = decodeRemoteSignalingReadyV1(request.payload);
      peerProofJti = hex(ready.verifiedPeerProofJti);
      suppliedProofSetDigest = hex(ready.finalProofSetDigest);
    }
    const reply = (await this.redis.eval(
      REMOTE_SIGNALING_COMMIT_LUA,
      3,
      ...keys,
      hex(request.eventId),
      hex(bytes),
      bytes.length.toString(),
      request.eventKind.toString(),
      request.producerRole.toString(),
      Buffer.from(bytes),
      this.actor(actor),
      request.transport === 1 ? "webrtc" : "websocket_data",
      agreement,
      proofJti,
      peerProofJti,
      suppliedProofSetDigest,
      hex(request.payload),
      expectedProofSetDigest,
      encodeProtocolIdBase64Url(child),
      daemonOfferDigestHex,
      daemonOfferJtiHex,
    )) as string[];
    const status = reply[0];
    if (status === "committed" || status === "replay")
      return this.result(status, BigInt(reply[1]!), request, bytes);
    throw new RemoteSignalingStoreError(
      status === "conflict"
        ? "conflict"
        : status === "limit"
          ? "limit"
          : status === "invalid_transition"
            ? "invalid_transition"
            : status === "retry"
              ? "retry"
              : "unavailable",
    );
  }
  async read(
    instance: string,
    child: Uint8Array,
    after: bigint,
  ): Promise<RemoteSignalingReadResultV1> {
    const keys = this.keys(instance, child),
      [ttl, metadata] = await Promise.all([
        this.redis.pttl(keys[0]),
        this.redis.hmget(keys[0], "expiresAtMs", "sequence"),
      ]);
    if (ttl === -2 || ttl === 0 || !metadata[0] || !metadata[1]) {
      return { kind: "unavailable" };
    }
    if (ttl === -1) return { kind: "unavailable" };
    const rows = await this.redis.xrangeBuffer(
      keys[1],
      `(${after}-0`,
      "+",
      "COUNT",
      REMOTE_SIGNALING_READ_MAX_EVENTS,
    );
    const events: RemoteSignalingCommittedEventV1[] = [];
    let total = 0;
    for (const [id, fields] of rows) {
      const map = new Map<string, Buffer>();
      for (let i = 0; i < fields.length; i += 2)
        map.set(fields[i]!.toString("utf8"), fields[i + 1]!);
      const raw = map.get("request"),
        bytes = new Uint8Array(raw ?? Buffer.alloc(0));
      if (total + bytes.length > REMOTE_SIGNALING_READ_MAX_BYTES) break;
      total += bytes.length;
      const request = decodeRemoteSignalingEventRequestV1(bytes);
      const parsed = JSON.parse(String(map.get("actor"))) as {
        role: RemoteSignalingActorBindingV1["role"];
        actor: string;
        generation: string;
      };
      const sequence = BigInt(id.toString("ascii").split("-")[0]!);
      events.push({
        sequence,
        redisCreatedAtMs: Number(map.get("createdAtMs")),
        requestBytes: bytes,
        request,
        actor: { role: parsed.role, actor: parsed.actor, generation: BigInt(parsed.generation) },
        ackBytes: this.result("committed", sequence, request, bytes).ackBytes,
      });
    }
    return { kind: "events", events, latestSequence: BigInt(metadata[1]!) };
  }
  async metadata(instance: string, child: Uint8Array) {
    const keys = this.keys(instance, child),
      [ttl, route, expires] = await Promise.all([
        this.redis.pttl(keys[0]),
        this.redis.hget(keys[0], "attemptWakeRouteId"),
        this.redis.hget(keys[0], "expiresAtMs"),
      ]);
    if (ttl <= 0 || !route || !expires) return { kind: "unavailable" as const };
    return {
      attemptWakeRouteId: Uint8Array.from(
        route.match(/../g)!.map((byte) => Number.parseInt(byte, 16)),
      ),
      expiresAtMs: Number(expires),
    };
  }
  async authenticateInstanceWake(
    instance: string,
    certificateGeneration: bigint,
    socketGeneration: bigint,
    authoritativeAfterSeq: bigint,
  ): Promise<RemoteInstanceWakeLeaseV1> {
    if (socketGeneration <= 0n) throw new RemoteSignalingStoreError("conflict");
    const keys = this.discoveryKeys(instance, certificateGeneration, socketGeneration),
      highWaterKey = this.discoveryKeys(instance, certificateGeneration, 0n).cursor,
      route = randomId(this.random),
      reply = (await this.redis.eval(
        `local now=redis.call('TIME');local now_ms=tonumber(now[1])*1000+math.floor(tonumber(now[2])/1000);local high=redis.call('HGET',KEYS[3],'highWater') or '0';local cursor=redis.call('GET',KEYS[2]);if high~=ARGV[4] or tonumber(ARGV[2])<=0 or (cursor and cursor~=ARGV[4]) then return {'conflict'} end;local generation=redis.call('HINCRBY',KEYS[3],'routeGeneration',1);local expires=now_ms+45000;redis.call('SET',KEYS[2],ARGV[4]);redis.call('PEXPIREAT',KEYS[2],expires);redis.call('HSET',KEYS[1],'instanceWakeRouteId',ARGV[1],'instanceWakeRouteGeneration',tostring(generation),'socketGeneration',ARGV[2],'expiresAtMs',tostring(expires));redis.call('PEXPIREAT',KEYS[1],expires);return {'ok',tostring(generation),tostring(expires)}`,
        3,
        keys.wake,
        keys.cursor,
        highWaterKey,
        hex(route),
        socketGeneration.toString(),
        certificateGeneration.toString(),
        authoritativeAfterSeq.toString(),
      )) as string[];
    if (reply[0] !== "ok") throw new RemoteSignalingStoreError("conflict");
    return {
      instanceWakeRouteId: route,
      instanceWakeRouteGeneration: BigInt(reply[1]!),
      socketGeneration,
      expiresAtMs: Number(reply[2]),
    };
  }
  async renewInstanceWake(
    instance: string,
    certificateGeneration: bigint,
    lease: RemoteInstanceWakeLeaseV1,
  ) {
    const keys = this.discoveryKeys(instance, certificateGeneration, lease.socketGeneration),
      reply = (await this.redis.eval(
        `local now=redis.call('TIME');local now_ms=tonumber(now[1])*1000+math.floor(tonumber(now[2])/1000);if redis.call('HGET',KEYS[1],'instanceWakeRouteId')~=ARGV[1] or redis.call('HGET',KEYS[1],'instanceWakeRouteGeneration')~=ARGV[2] or redis.call('HGET',KEYS[1],'socketGeneration')~=ARGV[3] then return {'unavailable'} end;local expires=now_ms+45000;redis.call('HSET',KEYS[1],'expiresAtMs',tostring(expires));redis.call('PEXPIREAT',KEYS[1],expires);redis.call('PEXPIREAT',KEYS[2],expires);return {'ok',tostring(expires)}`,
        2,
        keys.wake,
        keys.cursor,
        hex(lease.instanceWakeRouteId),
        lease.instanceWakeRouteGeneration.toString(),
        lease.socketGeneration.toString(),
      )) as string[];
    if (reply[0] !== "ok") throw new RemoteSignalingStoreError("unavailable");
    return { ...lease, expiresAtMs: Number(reply[1]) };
  }
  async readDiscovery(
    instance: string,
    certificateGeneration: bigint,
    socketGeneration: bigint,
    afterSeq: bigint,
  ): Promise<RemoteDiscoveryReadResultV1> {
    const keys = this.discoveryKeys(instance, certificateGeneration, socketGeneration),
      [wakeSocket, cursor] = await Promise.all([
        this.redis.hget(keys.wake, "socketGeneration"),
        this.redis.get(keys.cursor),
      ]);
    if (wakeSocket !== socketGeneration.toString() || cursor !== afterSeq.toString())
      return { kind: "unavailable" };
    const entryPrefix = keys.index.replace(":discovery:", ":discovery-entry:") + ":",
      reconcile = (await this.redis.eval(
        `local now=redis.call('TIME');local now_ms=tonumber(now[1])*1000+math.floor(tonumber(now[2])/1000);local expired=tonumber(redis.call('GET',KEYS[1]) or '0');local last_id='0-0';if redis.call('EXISTS',KEYS[2])==1 then local info=redis.call('XINFO','STREAM',KEYS[2]);for i=1,#info,2 do if info[i]=='last-generated-id' then last_id=info[i+1] end end end;local latest=tonumber(string.match(last_id,'^(%d+)'));local rows=redis.call('XRANGE',KEYS[2],'('..tostring(expired)..'-0','+','COUNT',64);for _,row in ipairs(rows) do local seq=tonumber(string.match(row[1],'^(%d+)'));if seq~=expired+1 then return {'corrupt'} end;local expires=nil;for i=1,#row[2],2 do if row[2][i]=='expiresAt' then expires=tonumber(row[2][i+1]) end end;if not expires then return {'corrupt'} end;if expires>now_ms then break end;redis.call('DEL',ARGV[1]..tostring(seq));expired=seq end;if expired>tonumber(redis.call('GET',KEYS[1]) or '0') then redis.call('SET',KEYS[1],tostring(expired));redis.call('XTRIM',KEYS[2],'MINID',tostring(expired+1)..'-0') end;return {'ok',tostring(expired),tostring(latest)}`,
        2,
        keys.expired,
        keys.index,
        entryPrefix,
      )) as string[];
    if (reconcile[0] !== "ok") return { kind: "unavailable" };
    const expired = BigInt(reconcile[1]!),
      latest = BigInt(reconcile[2]!);
    if (afterSeq < expired)
      return {
        kind: "expired_gap",
        expectedAfterSeq: afterSeq,
        expiredThroughSeq: expired,
        latestDiscoverySeq: latest,
      };
    const rows = await this.redis.xrange(
        keys.index,
        `(${afterSeq}-0`,
        "+",
        "COUNT",
        REMOTE_SIGNALING_READ_MAX_EVENTS,
      ),
      entries: RemoteDiscoveryEntryV1[] = [];
    let total = 0;
    for (const [streamId] of rows) {
      const sequence = BigInt(streamId.split("-")[0]!),
        raw = await this.redis.getBuffer(
          keys.index.replace(":discovery:", ":discovery-entry:") + `:${sequence}`,
        );
      if (!raw) return { kind: "unavailable" };
      if (raw.length !== 88 || total + raw.length > REMOTE_SIGNALING_READ_MAX_BYTES) break;
      const bytes = new Uint8Array(raw),
        view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const entry: RemoteDiscoveryEntryV1 = {
        discoverySeq: sequence,
        discoveryId: bytes.slice(0, 16),
        childAttemptId: bytes.slice(16, 32),
        attemptWakeRouteId: bytes.slice(32, 48),
        authBundleDigest: bytes.slice(48, 80),
        expiresAtMs: Number(view.getBigUint64(80)),
      };
      const attemptKeys = this.keys(instance, entry.childAttemptId),
        [attemptRoute, eventRows] = await Promise.all([
          this.redis.hget(attemptKeys[0], "attemptWakeRouteId"),
          this.redis.xrangeBuffer(attemptKeys[1], "1-0", "1-0"),
        ]);
      if (attemptRoute !== hex(entry.attemptWakeRouteId) || eventRows.length !== 1)
        return { kind: "unavailable" };
      const fields = eventRows[0]![1],
        requestIndex = fields.findIndex((field) => field.toString("utf8") === "request");
      if (requestIndex < 0) return { kind: "unavailable" };
      const requestBytes = new Uint8Array(fields[requestIndex + 1] ?? Buffer.alloc(0)),
        request = decodeRemoteSignalingEventRequestV1(requestBytes);
      if (
        request.eventKind !== 1 ||
        !equal(request.childAttemptId, entry.childAttemptId) ||
        !equal(
          remoteChildAuthenticationDigests(request.payload).authBundleDigest,
          entry.authBundleDigest,
        )
      )
        return { kind: "unavailable" };
      entries.push(entry);
      total += raw.length;
    }
    return { kind: "entries", entries, latestDiscoverySeq: latest };
  }
  async ackDiscovery(
    instance: string,
    certificateGeneration: bigint,
    socketGeneration: bigint,
    expectedPriorSeq: bigint,
    newSeq: bigint,
    expiredGap = false,
  ) {
    if (newSeq < expectedPriorSeq) throw new RemoteSignalingStoreError("conflict");
    const keys = this.discoveryKeys(instance, certificateGeneration, socketGeneration),
      highWaterKey = this.discoveryKeys(instance, certificateGeneration, 0n).cursor,
      reply = await this.redis.eval(
        `if redis.call('HGET',KEYS[1],'socketGeneration')~=ARGV[1] or redis.call('GET',KEYS[2])~=ARGV[2] or (redis.call('HGET',KEYS[5],'highWater') or '0')~=ARGV[2] then return 0 end;local last_id='0-0';if redis.call('EXISTS',KEYS[6])==1 then local info=redis.call('XINFO','STREAM',KEYS[6]);for i=1,#info,2 do if info[i]=='last-generated-id' then last_id=info[i+1] end end end;local high=tonumber(string.match(last_id,'^(%d+)'));if tonumber(ARGV[3])>high then return 0 end;if ARGV[4]=='1' and redis.call('GET',KEYS[3])~=ARGV[3] then return 0 end;if ARGV[4]=='0' and redis.call('EXISTS',KEYS[4])==0 then return 0 end;redis.call('SET',KEYS[2],ARGV[3],'KEEPTTL');redis.call('HSET',KEYS[5],'highWater',ARGV[3]);return 1`,
        6,
        keys.wake,
        keys.cursor,
        keys.expired,
        keys.index.replace(":discovery:", ":discovery-entry:") + `:${newSeq}`,
        highWaterKey,
        keys.index,
        socketGeneration.toString(),
        expectedPriorSeq.toString(),
        newSeq.toString(),
        expiredGap ? "1" : "0",
      );
    if (reply !== 1) throw new RemoteSignalingStoreError("conflict");
  }
  async closeInstanceWake(
    instance: string,
    certificateGeneration: bigint,
    lease: RemoteInstanceWakeLeaseV1,
  ) {
    const keys = this.discoveryKeys(instance, certificateGeneration, lease.socketGeneration);
    await this.redis.eval(
      `if redis.call('HGET',KEYS[1],'instanceWakeRouteId')==ARGV[1] and redis.call('HGET',KEYS[1],'instanceWakeRouteGeneration')==ARGV[2] and redis.call('HGET',KEYS[1],'socketGeneration')==ARGV[3] then redis.call('DEL',KEYS[1],KEYS[2]);return 1 end;return 0`,
      2,
      keys.wake,
      keys.cursor,
      hex(lease.instanceWakeRouteId),
      lease.instanceWakeRouteGeneration.toString(),
      lease.socketGeneration.toString(),
    );
  }
  async discoveryHighWater(instance: string, certificateGeneration: bigint) {
    const key = this.discoveryKeys(instance, certificateGeneration, 0n).cursor;
    return BigInt((await this.redis.hget(key, "highWater")) ?? "0");
  }
  private admissionTicketKey(instance: string, ticketId: Uint8Array) {
    if (!/^[A-Za-z0-9_-]{22}$/.test(instance)) throw new RemoteSignalingStoreError("unavailable");
    return `flycockpit:remote-signaling:{${instance}}:admission-ticket:${hex(ticketId)}`;
  }
  private socketLeaseKey(deviceAttachmentId: string) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(deviceAttachmentId))
      throw new RemoteSignalingStoreError("unavailable");
    return `flycockpit:remote-signaling:socket-lease:{${deviceAttachmentId}}`;
  }
  async allocateControlSocketGeneration(instance: string, certificateGeneration: bigint) {
    if (!/^[A-Za-z0-9_-]{22}$/.test(instance)) throw new RemoteSignalingStoreError("unavailable");
    const generationKey = `flycockpit:remote-signaling:{${instance}}:socket-generation:${certificateGeneration}`;
    return BigInt(await this.redis.incr(generationKey));
  }
  async issueClientAdmissionTicket(
    input: RemoteSignalingAdmissionTicketInput,
  ): Promise<RemoteSignalingAdmissionTicketV1> {
    if (input.admissionProofSha256.length !== 32)
      throw new RemoteSignalingStoreError("unavailable");
    const ticketId = randomId(this.random);
    const secret = new Uint8Array(32);
    do this.random(secret);
    while (secret.every((byte) => byte === 0));
    const expires = Number(
      (await this.redis.eval(
        REMOTE_SIGNALING_ISSUE_ADMISSION_TICKET_LUA,
        1,
        this.admissionTicketKey(input.daemonInstanceId, ticketId),
        sha256Hex(secret),
        input.originClass,
        encodeProtocolIdBase64Url(input.childAttemptId),
        hex(input.admissionProofSha256),
        input.daemonInstanceId,
        input.accountId,
        input.deviceAttachmentId,
        input.deviceGeneration.toString(),
      )) as string,
    );
    await this.redis.set(
      `flycockpit:remote-signaling:admission-ticket-route:${hex(ticketId)}`,
      JSON.stringify({
        daemonInstanceId: input.daemonInstanceId,
        childAttemptId: encodeProtocolIdBase64Url(input.childAttemptId),
      }),
      "PXAT",
      expires,
    );
    return { ticketId, secret };
  }
  async resolveAdmissionTicket(
    ticketId: Uint8Array,
  ): Promise<RemoteSignalingAdmissionTicketRoute | null> {
    const raw = await this.redis.get(
      `flycockpit:remote-signaling:admission-ticket-route:${hex(ticketId)}`,
    );
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { daemonInstanceId: string; childAttemptId: string };
    return {
      daemonInstanceId: parsed.daemonInstanceId,
      childAttemptId: decodeProtocolIdBase64Url(parsed.childAttemptId),
    };
  }
  async commitClientAdmission(
    instance: string,
    child: Uint8Array,
    requestBytes: Uint8Array,
    ticket: RemoteSignalingAdmissionTicketProof,
  ): Promise<RemoteSignalingClientAdmissionResultV1> {
    const request = decodeRemoteSignalingEventRequestV1(requestBytes);
    validateTypedPayload(request);
    if (request.eventKind !== 3 || !equal(request.childAttemptId, child))
      throw new RemoteSignalingStoreError("unavailable");
    const proof = decodeClientAdmissionProofV1(request.payload);
    const keys = this.keys(instance, child);
    const reply = (await this.redis.eval(
      REMOTE_SIGNALING_COMMIT_ADMISSION_LUA,
      4,
      keys[0],
      keys[1],
      keys[2],
      this.admissionTicketKey(instance, ticket.ticketId),
      hex(request.eventId),
      hex(requestBytes),
      requestBytes.length.toString(),
      Buffer.from(requestBytes),
      encodeProtocolIdBase64Url(child),
      hex(proof.daemonOfferDigest),
      hex(proof.daemonOfferJti),
      ticket.secretSha256Hex,
      ticket.originClass,
      sha256Hex(request.payload),
      request.transport === 1 ? "webrtc" : "websocket_data",
    )) as string[];
    const status = reply[0];
    if (status === "committed" || status === "replay") {
      const actorJson = reply[2];
      if (!actorJson) throw new RemoteSignalingStoreError("corrupt");
      const parsed = JSON.parse(actorJson) as { role: "client"; actor: string; generation: string };
      const actor: RemoteSignalingActorBindingV1 = {
        role: parsed.role,
        actor: parsed.actor,
        generation: BigInt(parsed.generation),
      };
      return {
        result: this.result(status, BigInt(reply[1]!), request, requestBytes),
        actor,
        childAttemptId: child.slice(),
        deviceAttachmentId: parsed.actor,
        deviceGeneration: actor.generation,
      };
    }
    throw new RemoteSignalingStoreError(
      status === "auth_failed"
        ? "auth_failed"
        : status === "conflict"
          ? "conflict"
          : status === "limit"
            ? "limit"
            : status === "invalid_transition"
              ? "invalid_transition"
              : "unavailable",
    );
  }
  async acquireSignalingSocketLease(deviceAttachmentId: string, leaseId: string): Promise<void> {
    const reply = (await this.redis.eval(
      REMOTE_SIGNALING_SOCKET_LEASE_ACQUIRE_LUA,
      1,
      this.socketLeaseKey(deviceAttachmentId),
      leaseId,
      REMOTE_SIGNALING_SOCKET_LEASE_TTL_MS.toString(),
      REMOTE_SIGNALING_MAX_SIGNALING_SOCKETS_PER_ATTACHMENT.toString(),
    )) as string[];
    if (reply[0] !== "ok") throw new RemoteSignalingStoreError("conflict");
  }
  async releaseSignalingSocketLease(deviceAttachmentId: string, leaseId: string): Promise<void> {
    await this.redis.zrem(this.socketLeaseKey(deviceAttachmentId), leaseId);
  }
  async close() {
    await this.redis.quit();
  }
}
