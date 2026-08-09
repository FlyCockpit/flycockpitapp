import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  decodeRemoteFallbackAuthV1,
  decodeRemoteFallbackChallengeV1,
  decodeRemoteFallbackOuterRecordV1,
  REMOTE_FALLBACK_ROUTE_LEASE_TTL_MS,
  REMOTE_FALLBACK_TICKET_TTL_MS,
  type RemoteFallbackPairState,
  type RemoteFallbackPairV1,
  type RemoteFallbackRole,
  type RemoteFallbackRouteLeaseV1,
  type RemoteFallbackTicketV1,
  remoteFallbackSocketAuthDigest,
  remoteFallbackTicketSecretDigest,
} from "@flycockpit/cockpit-protocol";

export interface RemoteFallbackRedis {
  time(): Promise<Array<string | number>>;
  set(key: string, value: string, mode: "PX", ttl: number, condition: "NX"): Promise<unknown>;
  get(key: string): Promise<string | null>;
  eval(script: string, keyCount: number, ...args: string[]): Promise<unknown>;
  publish(channel: string, payload: string): Promise<number>;
}

export interface RemoteFallbackSignalingCommitter {
  transitionPairState(
    pair: RemoteFallbackPairV1,
    from: RemoteFallbackPairState,
    to: RemoteFallbackPairState,
  ): Promise<void>;
  commitFallbackPair(
    pair: RemoteFallbackPairV1,
  ): Promise<{ eventId: string; eventDigest: string; sequence: string }>;
  commitNoiseComplete(input: {
    pairId: Uint8Array;
    role: RemoteFallbackRole;
    handshakeHash: Uint8Array;
    prologueDigest: Uint8Array;
  }): Promise<{ eventId: string; eventDigest: string; sequence: string }>;
  readCommittedFinalProofSet(
    pairId: Uint8Array,
  ): Promise<{ finalProofSetDigest: Uint8Array } | null>;
}

export interface RemoteFallbackAdmissionSnapshot {
  state: "admitted";
  tenantId: Uint8Array;
  logicalAttachmentId: Uint8Array;
  childAttemptId: Uint8Array;
  transportEpoch: Uint8Array;
  admissionSequence: bigint;
  grantDigest: Uint8Array;
  authBundleDigest: Uint8Array;
}
export interface RemoteFallbackCertificateVerifier {
  verify(input: {
    certificateJws: Uint8Array;
    signatureP1363: Uint8Array;
    signingDigest: Uint8Array;
    expectedRole: RemoteFallbackRole;
    expectedCertificateId: Uint8Array;
    expectedCertificateGeneration: bigint;
    originClass: string;
  }): Promise<boolean>;
}
export interface RemoteFallbackAdmissionSource {
  loadTicket(ticketId: Uint8Array): Promise<RemoteFallbackTicketV1 | null>;
  loadAdmittedAttempt(childAttemptId: Uint8Array): Promise<RemoteFallbackAdmissionSnapshot | null>;
}

function equalBytes(first: Uint8Array, second: Uint8Array): boolean {
  return first.length === second.length && timingSafeEqual(first, second);
}
function nonzero(bytes: Uint8Array, length: number): boolean {
  return bytes.length === length && bytes.some((byte) => byte !== 0);
}
function validateTicket(ticket: RemoteFallbackTicketV1): void {
  if (
    !nonzero(ticket.ticketId, 16) ||
    !nonzero(ticket.tenantId, 16) ||
    !nonzero(ticket.logicalAttachmentId, 16) ||
    !nonzero(ticket.childAttemptId, 16) ||
    !nonzero(ticket.transportEpoch, 16) ||
    !nonzero(ticket.certificateId, 16) ||
    ticket.ticketSecretDigest.length !== 32 ||
    ticket.grantDigest.length !== 32 ||
    ticket.authBundleDigest.length !== 32 ||
    equalBytes(ticket.grantDigest, ticket.authBundleDigest) ||
    ticket.admissionSequence < 1n ||
    ticket.certificateGeneration < 1n
  )
    throw new Error("fallback_ticket_invalid");
}
function validatePair(pair: RemoteFallbackPairV1): void {
  if (
    !nonzero(pair.pairId, 16) ||
    !nonzero(pair.opaqueRouteId, 16) ||
    !nonzero(pair.transportEpoch, 16) ||
    pair.grantDigest.length !== 32 ||
    pair.authBundleDigest.length !== 32 ||
    equalBytes(pair.grantDigest, pair.authBundleDigest) ||
    pair.attachmentBinding.length !== 32 ||
    pair.routeGeneration < 1n ||
    pair.pairGeneration < 1n ||
    pair.clientSocketGeneration < 1n ||
    pair.daemonSocketGeneration < 1n ||
    pair.admissionSequence < 1n ||
    pair.routeBindingKeyGeneration < 1n
  )
    throw new Error("fallback_pair_invalid");
}

export function createRemoteFallbackPair(input: {
  transportEpoch: Uint8Array;
  admissionSequence: bigint;
  grantDigest: Uint8Array;
  authBundleDigest: Uint8Array;
  attachmentBinding: Uint8Array;
  routeBindingKeyGeneration: bigint;
}): RemoteFallbackPairV1 {
  const pair: RemoteFallbackPairV1 = {
    pairId: randomBytes(16),
    opaqueRouteId: randomBytes(16),
    routeGeneration: 1n,
    pairGeneration: 1n,
    clientSocketGeneration: 1n,
    daemonSocketGeneration: 1n,
    ...input,
    state: "waiting_peer",
  };
  validatePair(pair);
  return pair;
}

export async function verifyRemoteFallbackSocketAdmission(input: {
  challengeFrame: Uint8Array;
  authFrame: Uint8Array;
  subprotocol: string;
  originClass: string;
  nowMillis: bigint;
  source: RemoteFallbackAdmissionSource;
  certificates: RemoteFallbackCertificateVerifier;
}): Promise<RemoteFallbackTicketV1> {
  if (input.subprotocol !== "flycockpit.remote-data.v1")
    throw new Error("fallback_subprotocol_mismatch");
  const challenge = decodeRemoteFallbackChallengeV1(input.challengeFrame);
  if (input.nowMillis < challenge.issuedAt || input.nowMillis >= challenge.expiresAt)
    throw new Error("fallback_challenge_expired");
  const auth = decodeRemoteFallbackAuthV1(input.authFrame);
  const ticket = await input.source.loadTicket(auth.ticketId);
  if (ticket) validateTicket(ticket);
  if (
    !ticket ||
    ticket.expiresAt <= input.nowMillis ||
    ticket.originClass !== input.originClass ||
    !equalBytes(remoteFallbackTicketSecretDigest(auth.ticketSecret), ticket.ticketSecretDigest)
  )
    throw new Error("fallback_ticket_invalid");
  const attempt = await input.source.loadAdmittedAttempt(ticket.childAttemptId);
  if (
    !attempt ||
    !equalBytes(attempt.tenantId, ticket.tenantId) ||
    !equalBytes(attempt.logicalAttachmentId, ticket.logicalAttachmentId) ||
    !equalBytes(attempt.childAttemptId, ticket.childAttemptId) ||
    !equalBytes(attempt.transportEpoch, ticket.transportEpoch) ||
    attempt.admissionSequence !== ticket.admissionSequence ||
    !equalBytes(attempt.grantDigest, ticket.grantDigest) ||
    !equalBytes(attempt.authBundleDigest, ticket.authBundleDigest)
  )
    throw new Error("fallback_admission_changed");
  const signingDigest = remoteFallbackSocketAuthDigest({
    challengeFrame: input.challengeFrame,
    role: ticket.role,
    childAttemptId: ticket.childAttemptId,
    transportEpoch: ticket.transportEpoch,
    authFrame: input.authFrame,
  });
  if (
    !(await input.certificates.verify({
      certificateJws: auth.certificateJws,
      signatureP1363: auth.signature,
      signingDigest,
      expectedRole: ticket.role,
      expectedCertificateId: ticket.certificateId,
      expectedCertificateGeneration: ticket.certificateGeneration,
      originClass: input.originClass,
    }))
  )
    throw new Error("fallback_certificate_invalid");
  return ticket;
}

export const CONSUME_TICKET_AND_PAIR_LUA = `
local existingRole = redis.call('GET', KEYS[2])
if existingRole then
  if existingRole ~= ARGV[2] then return {'error','role_conflict'} end
  local priorPair = redis.call('GET', KEYS[4])
  if priorPair and priorPair ~= ARGV[4] then return {'error','pair_conflict'} end
  return {'duplicate', priorPair or existingRole}
end
local ticket = redis.call('GET', KEYS[1])
if not ticket then return {'error','ticket_missing'} end
if ticket ~= ARGV[1] then return {'error','ticket_conflict'} end
if redis.call('GET', KEYS[5]) ~= ARGV[5] then return {'error','admission_changed'} end
local consumed = redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[3], 'NX')
if not consumed then
  local prior = redis.call('GET', KEYS[2])
  if prior == ARGV[2] then return {'duplicate', prior} end
  return {'error','role_conflict'}
end
redis.call('DEL', KEYS[1])
local peer = redis.call('GET', KEYS[3])
if peer then
  local pair = redis.call('SET', KEYS[4], ARGV[4], 'PX', ARGV[3], 'NX')
  if pair then return {'paired', ARGV[4]} end
  local prior = redis.call('GET', KEYS[4])
  if prior == ARGV[4] then return {'duplicate', prior} end
  return {'error','pair_conflict'}
end
return {'waiting', ARGV[2]}
`;
export const ISSUE_ROLE_TICKET_LUA = `
if redis.call('EXISTS', KEYS[1]) == 1 then return {'error','role_ticket_exists'} end
if redis.call('EXISTS', KEYS[2]) == 1 then return {'error','ticket_collision'} end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[2])
return {'issued', ARGV[1]}
`;

export const RENEW_ROUTE_LEASE_LUA = `
local pair = redis.call('GET', KEYS[1])
local lease = redis.call('GET', KEYS[2])
local connection = redis.call('GET', KEYS[3])
local admission = redis.call('GET', KEYS[4])
if pair ~= ARGV[1] or lease ~= ARGV[2] or connection ~= ARGV[3] or admission ~= ARGV[6] then return {'error','stale'} end
redis.call('SET', KEYS[2], ARGV[4], 'PX', ARGV[5], 'XX')
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return {'renewed', ARGV[4]}
`;

export const INSTALL_ROUTE_LEASE_LUA = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'error','pair_stale'} end
if redis.call('GET', KEYS[2]) ~= ARGV[2] then return {'error','connection_stale'} end
local installed = redis.call('SET', KEYS[3], ARGV[3], 'PX', ARGV[4], 'NX')
if installed then return {'installed', ARGV[3]} end
local prior = redis.call('GET', KEYS[3])
if prior == ARGV[3] then return {'duplicate', prior} end
return {'error','route_conflict'}
`;

export const CLOSE_ROUTE_LEASE_LUA = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
redis.call('DEL', KEYS[2])
return 1
`;
export const TRANSITION_FALLBACK_PAIR_LUA = `
local prior = redis.call('GET', KEYS[1])
if prior == ARGV[2] then return {'duplicate', prior} end
if prior ~= ARGV[1] then return {'error','pair_state_conflict'} end
redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3], 'XX')
return {'transitioned', ARGV[2]}
`;
export const LOOKUP_FALLBACK_ROUTE_LUA = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'error','route_stale'} end
local pair = redis.call('GET', KEYS[2])
if not pair then return {'error','pair_missing'} end
return {'found', pair}
`;

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}
function json(value: unknown): string {
  return JSON.stringify(value, (_key, item) =>
    typeof item === "bigint" ? item.toString() : item instanceof Uint8Array ? hex(item) : item,
  );
}
function redisNowMillis(parts: Array<string | number>): bigint {
  if (parts.length !== 2) throw new Error("redis_time_invalid");
  return BigInt(String(parts[0])) * 1000n + BigInt(String(parts[1])) / 1000n;
}

export class RemoteFallbackTicketStore {
  constructor(
    private readonly redis: RemoteFallbackRedis,
    private readonly prefix = "remote:fallback",
  ) {}

  async issue(
    input: Omit<RemoteFallbackTicketV1, "ticketId" | "ticketSecretDigest" | "expiresAt">,
  ): Promise<{ ticket: RemoteFallbackTicketV1; secret: Uint8Array }> {
    const now = redisNowMillis(await this.redis.time());
    const ticketId = randomBytes(16),
      secret = randomBytes(32);
    const ticket: RemoteFallbackTicketV1 = {
      ...input,
      ticketId,
      ticketSecretDigest: remoteFallbackTicketSecretDigest(secret),
      expiresAt: now + BigInt(REMOTE_FALLBACK_TICKET_TTL_MS),
    };
    validateTicket(ticket);
    const result = await this.redis.eval(
      ISSUE_ROLE_TICKET_LUA,
      2,
      `${this.prefix}:ticket-role:${hex(ticket.childAttemptId)}:${ticket.role}`,
      `${this.prefix}:ticket:${hex(ticketId)}`,
      json(ticket),
      String(REMOTE_FALLBACK_TICKET_TTL_MS),
    );
    if (!Array.isArray(result) || result[0] !== "issued") throw new Error("role_ticket_exists");
    return { ticket, secret };
  }

  verifySecret(ticket: RemoteFallbackTicketV1, secret: Uint8Array): boolean {
    const digest = remoteFallbackTicketSecretDigest(secret);
    return timingSafeEqual(digest, ticket.ticketSecretDigest);
  }

  async consumeRoleAndMaybePair(input: {
    ticket: RemoteFallbackTicketV1;
    authenticatedRoleRecord: string;
    admittedAttemptRecord: string;
    pair: RemoteFallbackPairV1;
  }): Promise<"waiting" | "paired" | "duplicate"> {
    const ticketKey = `${this.prefix}:ticket:${hex(input.ticket.ticketId)}`;
    const roleKey = `${this.prefix}:role:${hex(input.pair.pairId)}:${input.ticket.role}`;
    const peerRole = input.ticket.role === "client" ? "daemon" : "client";
    const peerKey = `${this.prefix}:role:${hex(input.pair.pairId)}:${peerRole}`;
    const pairKey = `${this.prefix}:pair:${hex(input.pair.pairId)}`;
    const result = await this.redis.eval(
      CONSUME_TICKET_AND_PAIR_LUA,
      5,
      ticketKey,
      roleKey,
      peerKey,
      pairKey,
      `${this.prefix}:admission:${hex(input.ticket.childAttemptId)}`,
      json(input.ticket),
      input.authenticatedRoleRecord,
      String(REMOTE_FALLBACK_TICKET_TTL_MS),
      json(input.pair),
      input.admittedAttemptRecord,
    );
    if (!Array.isArray(result) || typeof result[0] !== "string")
      throw new Error("fallback_ticket_reducer_invalid");
    if (result[0] === "waiting" || result[0] === "paired" || result[0] === "duplicate")
      return result[0];
    throw new Error(typeof result[1] === "string" ? result[1] : "fallback_ticket_reducer_conflict");
  }
}

export class RemoteFallbackRouteLeaseStore {
  constructor(
    private readonly redis: RemoteFallbackRedis,
    private readonly prefix = "remote:fallback",
  ) {}

  async transitionPairState(
    pair: RemoteFallbackPairV1,
    from: RemoteFallbackPairState,
    to: RemoteFallbackPairState,
  ): Promise<void> {
    if (pair.state !== from) throw new Error("pair_state_conflict");
    const replacement = { ...pair, state: to };
    const result = await this.redis.eval(
      TRANSITION_FALLBACK_PAIR_LUA,
      1,
      `${this.prefix}:pair:${hex(pair.pairId)}`,
      json(pair),
      json(replacement),
      String(REMOTE_FALLBACK_ROUTE_LEASE_TTL_MS),
    );
    if (!Array.isArray(result) || (result[0] !== "transitioned" && result[0] !== "duplicate"))
      throw new Error("pair_state_conflict");
  }

  async install(input: {
    opaqueRouteId: Uint8Array;
    role: RemoteFallbackRole;
    pair: RemoteFallbackPairV1;
    connectionLease: string;
    lease: RemoteFallbackRouteLeaseV1;
  }): Promise<"installed" | "duplicate"> {
    const now = redisNowMillis(await this.redis.time());
    if (
      input.pair.state !== "lease_pending" ||
      !equalBytes(input.opaqueRouteId, input.pair.opaqueRouteId) ||
      !equalBytes(input.lease.pairId, input.pair.pairId) ||
      !equalBytes(input.lease.transportEpoch, input.pair.transportEpoch) ||
      !equalBytes(input.lease.attachmentBinding, input.pair.attachmentBinding) ||
      input.lease.pairGeneration !== input.pair.pairGeneration ||
      input.lease.socketGeneration !==
        (input.role === "client"
          ? input.pair.clientSocketGeneration
          : input.pair.daemonSocketGeneration) ||
      !nonzero(input.lease.connectionLeaseId, 16) ||
      input.lease.connectionLeaseGeneration < 1n ||
      input.lease.connectionLeaseDigest.length !== 32 ||
      input.lease.replicaId.length < 1 ||
      input.lease.routeLeaseGeneration < 1n ||
      input.lease.expiresAt !== now + BigInt(REMOTE_FALLBACK_ROUTE_LEASE_TTL_MS)
    )
      throw new Error("route_lease_binding_conflict");
    const route = hex(input.opaqueRouteId);
    const result = await this.redis.eval(
      INSTALL_ROUTE_LEASE_LUA,
      3,
      `${this.prefix}:pair:${hex(input.pair.pairId)}`,
      `${this.prefix}:connection:${hex(input.lease.connectionLeaseId)}`,
      `${this.prefix}:route:${route}:${input.role}`,
      json(input.pair),
      input.connectionLease,
      json(input.lease),
      String(REMOTE_FALLBACK_ROUTE_LEASE_TTL_MS),
    );
    if (Array.isArray(result) && (result[0] === "installed" || result[0] === "duplicate"))
      return result[0];
    throw new Error("route_lease_install_conflict");
  }

  async renew(input: {
    opaqueRouteId: Uint8Array;
    role: RemoteFallbackRole;
    expectedPair: RemoteFallbackPairV1;
    expectedLease: RemoteFallbackRouteLeaseV1;
    expectedConnectionLease: string;
    childAttemptId: Uint8Array;
    expectedAdmission: string;
    replacement: RemoteFallbackRouteLeaseV1;
  }): Promise<void> {
    const now = redisNowMillis(await this.redis.time());
    if (
      input.replacement.expiresAt !== now + BigInt(REMOTE_FALLBACK_ROUTE_LEASE_TTL_MS) ||
      input.replacement.routeLeaseGeneration !== input.expectedLease.routeLeaseGeneration + 1n ||
      !equalBytes(input.replacement.pairId, input.expectedLease.pairId) ||
      input.replacement.replicaId !== input.expectedLease.replicaId ||
      input.replacement.socketGeneration !== input.expectedLease.socketGeneration ||
      !equalBytes(input.replacement.transportEpoch, input.expectedLease.transportEpoch) ||
      !equalBytes(input.replacement.attachmentBinding, input.expectedLease.attachmentBinding) ||
      input.replacement.pairGeneration !== input.expectedLease.pairGeneration ||
      !equalBytes(input.replacement.connectionLeaseId, input.expectedLease.connectionLeaseId) ||
      input.replacement.connectionLeaseGeneration !==
        input.expectedLease.connectionLeaseGeneration ||
      !equalBytes(
        input.replacement.connectionLeaseDigest,
        input.expectedLease.connectionLeaseDigest,
      )
    )
      throw new Error("invalid_route_lease_replacement");
    const route = hex(input.opaqueRouteId),
      role = input.role;
    const result = await this.redis.eval(
      RENEW_ROUTE_LEASE_LUA,
      4,
      `${this.prefix}:pair:${hex(input.expectedPair.pairId)}`,
      `${this.prefix}:route:${route}:${role}`,
      `${this.prefix}:connection:${hex(input.expectedLease.connectionLeaseId)}`,
      `${this.prefix}:admission:${hex(input.childAttemptId)}`,
      json(input.expectedPair),
      json(input.expectedLease),
      input.expectedConnectionLease,
      json(input.replacement),
      String(REMOTE_FALLBACK_ROUTE_LEASE_TTL_MS),
      input.expectedAdmission,
    );
    if (!Array.isArray(result) || result[0] !== "renewed") throw new Error("stale_route_lease");
  }

  async close(input: {
    opaqueRouteId: Uint8Array;
    role: RemoteFallbackRole;
    expectedPair: RemoteFallbackPairV1;
    expectedLease: RemoteFallbackRouteLeaseV1;
  }): Promise<boolean> {
    const route = hex(input.opaqueRouteId);
    const result = await this.redis.eval(
      CLOSE_ROUTE_LEASE_LUA,
      2,
      `${this.prefix}:pair:${hex(input.expectedPair.pairId)}`,
      `${this.prefix}:route:${route}:${input.role}`,
      json(input.expectedPair),
      json(input.expectedLease),
    );
    return result === 1;
  }
}

export class RemoteFallbackPairCoordinator {
  private state: RemoteFallbackPairState = "waiting_peer";
  private pairCommit: string | undefined;
  private pairAuthorizationDelivered = false;
  private noiseCommits = new Map<RemoteFallbackRole, string>();
  private noiseInputs = new Map<RemoteFallbackRole, string>();
  private noiseCommitsDelivered = false;
  private finalProofSetDigest: Uint8Array | undefined;
  private activationIdentity: string | undefined;

  constructor(
    readonly pair: RemoteFallbackPairV1,
    private readonly signaling: RemoteFallbackSignalingCommitter,
  ) {
    validatePair(pair);
  }
  private setState(state: RemoteFallbackPairState): void {
    this.state = state;
    this.pair.state = state;
  }
  currentState(): RemoteFallbackPairState {
    return this.state;
  }

  async bothSocketsAuthenticated(): Promise<void> {
    if (this.state === "pair_commit_pending" && this.pairCommit) return;
    if (this.state !== "waiting_peer") throw new Error("pair_state_conflict");
    await this.signaling.transitionPairState(this.pair, "waiting_peer", "pair_commit_pending");
    this.setState("pair_commit_pending");
    const ack = await this.signaling.commitFallbackPair(this.pair);
    this.pairCommit = `${ack.eventId}:${ack.sequence}:${ack.eventDigest}`;
  }

  async confirmPairAuthorizationDelivered(committedEvent: string): Promise<void> {
    if (this.pairAuthorizationDelivered && committedEvent === this.pairCommit) return;
    if (this.state !== "pair_commit_pending" || committedEvent !== this.pairCommit)
      throw new Error("pair_authorization_commit_conflict");
    this.pairAuthorizationDelivered = true;
    await this.signaling.transitionPairState(this.pair, "pair_commit_pending", "noise_handshake");
    this.setState("noise_handshake");
  }

  async noiseComplete(
    role: RemoteFallbackRole,
    handshakeHash: Uint8Array,
    prologueDigest: Uint8Array,
  ): Promise<void> {
    const inputIdentity = `${hex(handshakeHash)}:${hex(prologueDigest)}`;
    const priorInput = this.noiseInputs.get(role);
    if (priorInput) {
      if (priorInput === inputIdentity) return;
      throw new Error("noise_commit_conflict");
    }
    if (this.state !== "noise_handshake" && this.state !== "noise_commit_pending")
      throw new Error("noise_state_conflict");
    if (
      !this.pairCommit ||
      !this.pairAuthorizationDelivered ||
      handshakeHash.length !== 32 ||
      prologueDigest.length !== 32
    )
      throw new Error("noise_commit_prerequisite_missing");
    const ack = await this.signaling.commitNoiseComplete({
      pairId: this.pair.pairId,
      role,
      handshakeHash,
      prologueDigest,
    });
    const identity = `${ack.eventId}:${ack.sequence}:${ack.eventDigest}`;
    const prior = this.noiseCommits.get(role);
    if (prior && prior !== identity) throw new Error("noise_commit_conflict");
    this.noiseCommits.set(role, identity);
    this.noiseInputs.set(role, inputIdentity);
    const next = this.noiseCommits.size === 2 ? "proof_pending" : "noise_commit_pending";
    await this.signaling.transitionPairState(this.pair, this.state, next);
    this.setState(next);
  }

  async proofsCommitted(): Promise<void> {
    if (this.finalProofSetDigest) return;
    if (
      this.state !== "proof_pending" ||
      this.noiseCommits.size !== 2 ||
      !this.noiseCommitsDelivered
    )
      throw new Error("proof_prerequisite_missing");
    const proofSet = await this.signaling.readCommittedFinalProofSet(this.pair.pairId);
    if (proofSet?.finalProofSetDigest.length !== 32) throw new Error("proof_set_not_committed");
    this.finalProofSetDigest = proofSet.finalProofSetDigest;
    await this.signaling.transitionPairState(this.pair, "proof_pending", "lease_pending");
    this.setState("lease_pending");
  }

  confirmNoiseCommitsDelivered(input: { clientCommit: string; daemonCommit: string }): void {
    if (
      this.state !== "proof_pending" ||
      input.clientCommit !== this.noiseCommits.get("client") ||
      input.daemonCommit !== this.noiseCommits.get("daemon")
    )
      throw new Error("noise_commit_delivery_conflict");
    this.noiseCommitsDelivered = true;
  }

  async activate(leases: readonly RemoteFallbackRouteLeaseV1[]): Promise<Uint8Array> {
    const activationIdentity = leases.map(json).join("\n");
    if (this.activationIdentity) {
      if (this.activationIdentity === activationIdentity && this.finalProofSetDigest)
        return this.finalProofSetDigest;
      throw new Error("lease_binding_conflict");
    }
    if (this.state !== "lease_pending" || !this.finalProofSetDigest || leases.length !== 2)
      throw new Error("lease_prerequisite_missing");
    for (const roleLease of leases) {
      if (
        hex(roleLease.pairId) !== hex(this.pair.pairId) ||
        roleLease.pairGeneration !== this.pair.pairGeneration ||
        roleLease.transportEpoch.some((byte, index) => byte !== this.pair.transportEpoch[index]) ||
        roleLease.attachmentBinding.some(
          (byte, index) => byte !== this.pair.attachmentBinding[index],
        )
      )
        throw new Error("lease_binding_conflict");
    }
    await this.signaling.transitionPairState(this.pair, "lease_pending", "active");
    this.activationIdentity = activationIdentity;
    this.setState("active");
    return this.finalProofSetDigest;
  }

  async close(): Promise<void> {
    if (this.state !== "closed")
      await this.signaling.transitionPairState(this.pair, this.state, "closing");
    this.setState(this.state === "closed" ? "closed" : "closing");
  }
  async closed(): Promise<void> {
    if (this.state !== "closed")
      await this.signaling.transitionPairState(this.pair, this.state, "closed");
    this.setState("closed");
  }
}

export interface OpaqueFallbackForwarder {
  forward(input: {
    opaqueRouteId: Uint8Array;
    routeGeneration: bigint;
    direction: 0 | 1;
    opaqueRecord: Uint8Array;
    pairId: Uint8Array;
    pairGeneration: bigint;
    socketGeneration: bigint;
    transportEpoch: Uint8Array;
    attachmentBinding: Uint8Array;
  }): Promise<void>;
}

export class RedisOpaqueFallbackForwarder implements OpaqueFallbackForwarder {
  constructor(
    private readonly redis: RemoteFallbackRedis,
    private readonly replicaId: string,
    private readonly local: OpaqueFallbackForwarder,
  ) {}
  async forward(input: {
    opaqueRouteId: Uint8Array;
    routeGeneration: bigint;
    direction: 0 | 1;
    opaqueRecord: Uint8Array;
    pairId: Uint8Array;
    pairGeneration: bigint;
    socketGeneration: bigint;
    transportEpoch: Uint8Array;
    attachmentBinding: Uint8Array;
  }): Promise<void> {
    if (input.opaqueRecord.length > 65_563) throw new Error("opaque_record_too_large");
    const outer = decodeRemoteFallbackOuterRecordV1(input.opaqueRecord);
    if (
      outer.routeGeneration !== input.routeGeneration ||
      (outer.direction === "client_to_daemon" ? 0 : 1) !== input.direction
    )
      throw new Error("opaque_route_header_conflict");
    const route = hex(input.opaqueRouteId);
    const owner = await this.redis.get(
      `remote:fallback:route:${route}:${input.direction === 0 ? "daemon" : "client"}`,
    );
    if (!owner) throw new Error("route_unavailable");
    const parsed = JSON.parse(owner) as Record<string, unknown>;
    if (
      parsed.pairId !== hex(input.pairId) ||
      parsed.pairGeneration !== input.pairGeneration.toString() ||
      parsed.socketGeneration !== input.socketGeneration.toString() ||
      parsed.transportEpoch !== hex(input.transportEpoch) ||
      parsed.attachmentBinding !== hex(input.attachmentBinding)
    )
      throw new Error("stale_route_generation");
    const lookup = await this.redis.eval(
      LOOKUP_FALLBACK_ROUTE_LUA,
      2,
      `remote:fallback:route:${route}:${input.direction === 0 ? "daemon" : "client"}`,
      `remote:fallback:pair:${hex(input.pairId)}`,
      owner,
    );
    if (!Array.isArray(lookup) || lookup[0] !== "found" || typeof lookup[1] !== "string")
      throw new Error("route_unavailable");
    const pair = JSON.parse(lookup[1]) as Record<string, unknown>;
    if (
      pair.routeGeneration !== input.routeGeneration.toString() ||
      pair.pairGeneration !== input.pairGeneration.toString() ||
      pair.transportEpoch !== hex(input.transportEpoch) ||
      pair.attachmentBinding !== hex(input.attachmentBinding) ||
      pair.state !== "active"
    )
      throw new Error("stale_pair_authorization");
    if (parsed.replicaId === this.replicaId) return this.local.forward(input);
    const envelope = json({
      opaqueRouteId: input.opaqueRouteId,
      routeGeneration: input.routeGeneration,
      direction: input.direction,
      opaqueRecord: input.opaqueRecord,
    });
    await this.redis.publish(`remote:fallback:replica:${String(parsed.replicaId)}`, envelope);
  }
}

export interface RemoteFallbackQuotaPolicy {
  maxSocketsPerChild: number;
  maxSocketsPerAccount: number;
  maxSocketsPerTenant: number;
  maxBytesPerPair: bigint;
  maxDurationMillis: bigint;
  maxQueuedBytesPerSocket: number;
}
export class RemoteFallbackQuotaLedger {
  private readonly children = new Map<string, number>();
  private readonly accounts = new Map<string, number>();
  private readonly tenants = new Map<string, number>();
  private readonly pairs = new Map<string, { bytes: bigint; openedAt: bigint }>();
  constructor(readonly policy: RemoteFallbackQuotaPolicy) {
    for (const value of [
      policy.maxSocketsPerChild,
      policy.maxSocketsPerAccount,
      policy.maxSocketsPerTenant,
      policy.maxQueuedBytesPerSocket,
    ])
      if (!Number.isSafeInteger(value) || value < 1) throw new Error("fallback_quota_unconfigured");
    if (policy.maxBytesPerPair < 1n || policy.maxDurationMillis < 1n)
      throw new Error("fallback_quota_unconfigured");
  }
  open(input: {
    childAttemptId: Uint8Array;
    accountId: Uint8Array;
    tenantId: Uint8Array;
    pairId: Uint8Array;
    nowMillis: bigint;
  }): void {
    if (this.pairs.has(hex(input.pairId))) throw new Error("fallback_pair_already_open");
    const dimensions: Array<[Map<string, number>, string, number]> = [
      [this.children, hex(input.childAttemptId), this.policy.maxSocketsPerChild],
      [this.accounts, hex(input.accountId), this.policy.maxSocketsPerAccount],
      [this.tenants, hex(input.tenantId), this.policy.maxSocketsPerTenant],
    ];
    if (dimensions.some(([map, key, cap]) => (map.get(key) ?? 0) >= cap))
      throw new Error("fallback_socket_quota_exceeded");
    for (const [map, key] of dimensions) map.set(key, (map.get(key) ?? 0) + 1);
    this.pairs.set(hex(input.pairId), { bytes: 0n, openedAt: input.nowMillis });
  }
  charge(pairId: Uint8Array, bytes: number, queuedBytes: number, nowMillis: bigint): void {
    if (
      !Number.isSafeInteger(bytes) ||
      bytes < 0 ||
      queuedBytes > this.policy.maxQueuedBytesPerSocket
    )
      throw new Error("fallback_queue_quota_exceeded");
    const pair = this.pairs.get(hex(pairId));
    if (!pair) throw new Error("fallback_pair_not_open");
    const next = pair.bytes + BigInt(bytes);
    if (
      next > this.policy.maxBytesPerPair ||
      nowMillis - pair.openedAt > this.policy.maxDurationMillis
    )
      throw new Error("fallback_pair_budget_exceeded");
    pair.bytes = next;
  }
  close(input: {
    childAttemptId: Uint8Array;
    accountId: Uint8Array;
    tenantId: Uint8Array;
    pairId: Uint8Array;
  }): void {
    for (const [map, key] of [
      [this.children, hex(input.childAttemptId)],
      [this.accounts, hex(input.accountId)],
      [this.tenants, hex(input.tenantId)],
    ] as Array<[Map<string, number>, string]>) {
      const value = map.get(key) ?? 0;
      if (value <= 1) map.delete(key);
      else map.set(key, value - 1);
    }
    this.pairs.delete(hex(input.pairId));
  }
}

export class RemoteFallbackLeaseHeartbeat {
  private nextRenewAt: bigint;
  private closed = false;
  constructor(
    private expiresAt: bigint,
    nowMillis: bigint,
    private readonly renew: () => Promise<bigint>,
    private readonly closeTransport: () => Promise<void>,
  ) {
    this.nextRenewAt = nowMillis + 10_000n;
  }
  async tick(nowMillis: bigint): Promise<void> {
    if (this.closed) return;
    if (nowMillis >= this.expiresAt) {
      this.closed = true;
      await this.closeTransport();
      return;
    }
    if (nowMillis < this.nextRenewAt) return;
    try {
      const replacementExpiry = await this.renew();
      if (replacementExpiry <= nowMillis || replacementExpiry > nowMillis + 30_000n)
        throw new Error("invalid_renewal_expiry");
      this.expiresAt = replacementExpiry;
      this.nextRenewAt = nowMillis + 10_000n;
    } catch {
      this.closed = true;
      await this.closeTransport();
    }
  }
}

export const ROUTE_LEASE_TTL_MILLIS = REMOTE_FALLBACK_ROUTE_LEASE_TTL_MS;
