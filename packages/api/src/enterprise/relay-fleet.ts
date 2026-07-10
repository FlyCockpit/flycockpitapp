import { randomBytes, verify as verifySignature } from "node:crypto";
import { env } from "@flycockpit/env/server";
import { createRedisConnection } from "@flycockpit/queue/connection";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

export type RelayFleetSession = { relayId: string; expiresAt: number };
export type RelayFleetRelay = {
  relayId: string;
  subdomain: string;
  region: string;
  accepting: boolean;
  connections: number;
};
export type RelayCandidate = { relayId: string; region: string | null; wsUrl: string };

const RELAY_TTL_MS = 45_000;
const SESSION_TTL_MS = 30 * 60_000;
const NONCE_TTL_MS = 120_000;
const REGISTER_SKEW_MS = 60_000;

const caKeySchema = z.object({ kid: z.string().min(1), publicKey: z.string().min(1) });
const certificatePayloadSchema = z.object({
  relayId: z.string().trim().min(1).max(120),
  subdomain: z.string().trim().min(1).max(255),
  region: z.string().trim().min(1).max(120),
  relayPublicKey: z.string().min(1),
  notBefore: z.string().datetime(),
  notAfter: z.string().datetime(),
});
const relayCertificateSchema = z
  .object({
    kid: z.string().min(1),
    payload: certificatePayloadSchema,
    signature: z.string().min(1),
  })
  .strict();

export const relayRegisterInputSchema = z
  .object({
    certificate: relayCertificateSchema,
    challengeSignature: z.string().min(1),
    nonce: z.string().trim().min(16).max(256),
    timestamp: z.string().datetime(),
  })
  .strict();

export const relayHeartbeatInputSchema = z
  .object({
    relayId: z.string().trim().min(1).max(120),
    accepting: z.boolean(),
    connections: z.number().int().nonnegative(),
    leaseDeltas: z
      .object({
        added: z.array(z.string().trim().min(1).max(128)).default([]),
        removed: z.array(z.string().trim().min(1).max(128)).default([]),
      })
      .default({ added: [], removed: [] }),
    userDeltas: z
      .object({
        added: z.array(z.string().trim().min(1).max(128)).default([]),
        removed: z.array(z.string().trim().min(1).max(128)).default([]),
      })
      .default({ added: [], removed: [] }),
    leases: z.array(z.string().trim().min(1).max(128)).optional(),
    users: z.array(z.string().trim().min(1).max(128)).optional(),
    region: z.string().optional(),
  })
  .strict();

export type RelayHeartbeatInput = z.infer<typeof relayHeartbeatInputSchema>;

export interface RelayFleetStore {
  consumeNonce(nonce: string, ttlMs: number, now: number): Promise<boolean>;
  putSession(token: string, session: RelayFleetSession, ttlMs: number, now: number): Promise<void>;
  getSession(token: string, now: number): Promise<RelayFleetSession | null>;
  putRelay(relay: RelayFleetRelay, ttlMs: number, now: number): Promise<void>;
  getRelay(relayId: string, now: number): Promise<RelayFleetRelay | null>;
  listRegions(): Promise<string[]>;
  listRelayIdsForRegion(region: string): Promise<string[]>;
  removeRelayFromRegion(region: string, relayId: string): Promise<void>;
  addRelayLease(relayId: string, instanceId: string): Promise<void>;
  replaceRelayLeases(relayId: string, instanceIds: string[]): Promise<void>;
  listRelayLeases(relayId: string): Promise<string[]>;
  addRelayUser(relayId: string, userId: string): Promise<void>;
  replaceRelayUsers(relayId: string, userIds: string[]): Promise<void>;
  listRelayUsers(relayId: string): Promise<string[]>;
  setLease(instanceId: string, relayId: string, ttlMs: number, now: number): Promise<void>;
  getLease(instanceId: string, now: number): Promise<string | null>;
  refreshLeaseIfOwner(
    instanceId: string,
    relayId: string,
    ttlMs: number,
    now: number,
  ): Promise<boolean>;
  removeLeaseIfOwner(instanceId: string, relayId: string): Promise<void>;
  setUserLease(userId: string, relayId: string, ttlMs: number, now: number): Promise<void>;
  getUserLease(userId: string, now: number): Promise<string | null>;
  refreshUserLeaseIfOwner(
    userId: string,
    relayId: string,
    ttlMs: number,
    now: number,
  ): Promise<boolean>;
  removeUserLeaseIfOwner(userId: string, relayId: string): Promise<void>;
}

type Deps = { store?: RelayFleetStore; now?: () => number; randomInt?: (max: number) => number };

let redisStore: RelayFleetStore | null = null;

export function getRelayFleetStore(): RelayFleetStore {
  redisStore ??= new RedisRelayFleetStore();
  return redisStore;
}

export function resetRelayFleetStoreForTests() {
  redisStore = null;
}

export async function registerRelay(input: unknown, deps: Deps = {}) {
  const result = relayRegisterInputSchema.safeParse(input);
  if (!result.success) unauthorized();
  const parsed = result.data;
  const now = deps.now?.() ?? Date.now();
  const certificate = parsed.certificate;
  const payload = certificate.payload;
  if (Math.abs(now - Date.parse(parsed.timestamp)) > REGISTER_SKEW_MS) unauthorized();
  if (now < Date.parse(payload.notBefore) || now > Date.parse(payload.notAfter)) unauthorized();
  if (revokedRelayIds().has(payload.relayId)) unauthorized();

  const caKey = caPublicKeys().find((key) => key.kid === certificate.kid);
  if (!caKey) unauthorized();
  if (!verifyDetached(caKey.publicKey, canonicalJson(payload), certificate.signature))
    unauthorized();
  const challenge = { relayId: payload.relayId, nonce: parsed.nonce, timestamp: parsed.timestamp };
  if (
    !verifyDetached(payload.relayPublicKey, canonicalJson(challenge), parsed.challengeSignature)
  ) {
    unauthorized();
  }

  const store = deps.store ?? getRelayFleetStore();
  if (!(await store.consumeNonce(parsed.nonce, NONCE_TTL_MS, now))) unauthorized();

  const token = randomBytes(32).toString("base64url");
  const expiresAt = now + SESSION_TTL_MS;
  await store.putSession(token, { relayId: payload.relayId, expiresAt }, SESSION_TTL_MS, now);
  await store.putRelay(
    {
      relayId: payload.relayId,
      subdomain: payload.subdomain,
      region: payload.region,
      accepting: true,
      connections: 0,
    },
    RELAY_TTL_MS,
    now,
  );
  return { sessionToken: token, expiresAt: new Date(expiresAt).toISOString() };
}

export async function verifyFleetSessionToken(token: string, deps: Deps = {}) {
  return (deps.store ?? getRelayFleetStore()).getSession(token, deps.now?.() ?? Date.now());
}

export async function recordRelayHeartbeat(
  identity: { relayId: string },
  input: unknown,
  deps: Deps = {},
) {
  const parsed = relayHeartbeatInputSchema.parse(input);
  if (parsed.relayId !== identity.relayId) unauthorized();
  const store = deps.store ?? getRelayFleetStore();
  const now = deps.now?.() ?? Date.now();
  const current = await store.getRelay(identity.relayId, now);
  if (!current) unauthorized();
  await store.putRelay(
    { ...current, accepting: parsed.accepting, connections: parsed.connections },
    RELAY_TTL_MS,
    now,
  );

  if (parsed.leases) await reconcileRelayLeases(store, identity.relayId, parsed.leases, now);
  else
    await applyLeaseDeltas(
      store,
      identity.relayId,
      parsed.leaseDeltas.added,
      parsed.leaseDeltas.removed,
      now,
    );

  if (parsed.users) await reconcileRelayUsers(store, identity.relayId, parsed.users, now);
  else
    await applyUserDeltas(
      store,
      identity.relayId,
      parsed.userDeltas.added,
      parsed.userDeltas.removed,
      now,
    );

  for (const instanceId of await store.listRelayLeases(identity.relayId)) {
    await store.refreshLeaseIfOwner(instanceId, identity.relayId, RELAY_TTL_MS, now);
  }
  for (const userId of await store.listRelayUsers(identity.relayId)) {
    await store.refreshUserLeaseIfOwner(userId, identity.relayId, RELAY_TTL_MS, now);
  }
  return { ok: true };
}

export async function recordConnectorRelayLease(
  relayId: string,
  instanceId: string,
  deps: Deps = {},
) {
  const store = deps.store ?? getRelayFleetStore();
  const now = deps.now?.() ?? Date.now();
  const relay = await store.getRelay(relayId, now);
  if (!relay?.accepting) throw new ORPCError("NOT_FOUND", { message: "Relay not found." });
  await store.setLease(instanceId, relayId, RELAY_TTL_MS, now);
  await store.addRelayLease(relayId, instanceId);
  return relayToTarget(relay);
}

export async function resolveRelayForInstance(instanceId: string, deps: Deps = {}) {
  const store = deps.store ?? getRelayFleetStore();
  const now = deps.now?.() ?? Date.now();
  const relayId = await store.getLease(instanceId, now);
  if (!relayId) throw new ORPCError("NOT_FOUND", { message: "Instance is not connected." });
  const relay = await store.getRelay(relayId, now);
  if (!relay) throw new ORPCError("NOT_FOUND", { message: "Instance is not connected." });
  return relayToTarget(relay);
}

export async function recordUserRelayLease(userId: string, relayId: string, deps: Deps = {}) {
  const store = deps.store ?? getRelayFleetStore();
  const now = deps.now?.() ?? Date.now();
  const relay = await store.getRelay(relayId, now);
  if (!relay?.accepting) throw new ORPCError("NOT_FOUND", { message: "Relay not found." });
  await store.setUserLease(userId, relayId, RELAY_TTL_MS, now);
  await store.addRelayUser(relayId, userId);
  return relayToTarget(relay);
}

export async function resolveRelayForUser(userId: string, deps: Deps = {}) {
  const store = deps.store ?? getRelayFleetStore();
  const now = deps.now?.() ?? Date.now();
  const relayId = await store.getUserLease(userId, now);
  if (!relayId) return null;
  const relay = await store.getRelay(relayId, now);
  return relay ? { ...relayToTarget(relay), controlUrl: controlUrlFromRelay(relay) } : null;
}

export async function selectUserRelay(userId: string, deps: Deps = {}) {
  const candidates = await listRelayCandidates(deps);
  const selected = candidates[0];
  if (!selected) throw new ORPCError("NOT_FOUND", { message: "Relay not found." });
  return recordUserRelayLease(userId, selected.relayId, deps);
}

export async function listRelayCandidates(deps: Deps = {}): Promise<RelayCandidate[]> {
  const store = deps.store ?? getRelayFleetStore();
  const randomInt = deps.randomInt ?? ((max: number) => Math.floor(Math.random() * max));
  const now = deps.now?.() ?? Date.now();
  const candidates: RelayCandidate[] = [];
  for (const region of await store.listRegions()) {
    const fresh: RelayFleetRelay[] = [];
    for (const relayId of await store.listRelayIdsForRegion(region)) {
      const relay = await store.getRelay(relayId, now);
      if (!relay) {
        await store.removeRelayFromRegion(region, relayId);
      } else if (relay.accepting) {
        fresh.push(relay);
      }
    }
    const selected = pickPowerOfTwo(fresh, randomInt);
    if (selected) candidates.push(relayToTarget(selected));
  }
  return candidates;
}

function pickPowerOfTwo(relays: RelayFleetRelay[], randomInt: (max: number) => number) {
  if (relays.length === 0) return null;
  if (relays.length === 1) return relays[0];
  const first = randomInt(relays.length);
  let second = randomInt(relays.length - 1);
  if (second >= first) second += 1;
  const a = relays[first];
  const b = relays[second];
  if (!a || !b) return relays[0] ?? null;
  return a.connections <= b.connections ? a : b;
}

async function applyLeaseDeltas(
  store: RelayFleetStore,
  relayId: string,
  added: string[],
  removed: string[],
  now: number,
) {
  for (const instanceId of added) {
    const owner = await store.getLease(instanceId, now);
    if (owner === relayId) {
      await store.addRelayLease(relayId, instanceId);
      await store.refreshLeaseIfOwner(instanceId, relayId, RELAY_TTL_MS, now);
    } else if (owner) {
      console.error(
        `[relay-fleet] rejected lease hijack instance=${instanceId} owner=${owner} claimant=${relayId}`,
      );
    }
  }
  for (const instanceId of removed) {
    await store.removeLeaseIfOwner(instanceId, relayId);
  }
}

async function reconcileRelayLeases(
  store: RelayFleetStore,
  relayId: string,
  leases: string[],
  now: number,
) {
  const existing = new Set(await store.listRelayLeases(relayId));
  const next = new Set(leases);
  await store.replaceRelayLeases(relayId, leases);
  for (const instanceId of existing) {
    if (!next.has(instanceId)) await store.removeLeaseIfOwner(instanceId, relayId);
  }
  for (const instanceId of next) {
    if ((await store.getLease(instanceId, now)) === relayId) {
      await store.refreshLeaseIfOwner(instanceId, relayId, RELAY_TTL_MS, now);
    }
  }
}

async function applyUserDeltas(
  store: RelayFleetStore,
  relayId: string,
  added: string[],
  removed: string[],
  now: number,
) {
  for (const userId of added) {
    const owner = await store.getUserLease(userId, now);
    if (owner === relayId) {
      await store.addRelayUser(relayId, userId);
      await store.refreshUserLeaseIfOwner(userId, relayId, RELAY_TTL_MS, now);
    }
  }
  for (const userId of removed) await store.removeUserLeaseIfOwner(userId, relayId);
}

async function reconcileRelayUsers(
  store: RelayFleetStore,
  relayId: string,
  users: string[],
  now: number,
) {
  const existing = new Set(await store.listRelayUsers(relayId));
  const next = new Set(users);
  await store.replaceRelayUsers(relayId, users);
  for (const userId of existing)
    if (!next.has(userId)) await store.removeUserLeaseIfOwner(userId, relayId);
  for (const userId of next)
    if ((await store.getUserLease(userId, now)) === relayId)
      await store.refreshUserLeaseIfOwner(userId, relayId, RELAY_TTL_MS, now);
}

function relayToTarget(relay: RelayFleetRelay): RelayCandidate {
  return { relayId: relay.relayId, region: relay.region, wsUrl: wsUrlFromRelay(relay) };
}

function wsUrlFromRelay(relay: RelayFleetRelay) {
  const scheme = env.NODE_ENV === "production" ? "wss" : "ws";
  return `${scheme}://${relay.subdomain}/ws`;
}

function controlUrlFromRelay(relay: RelayFleetRelay) {
  const scheme = env.NODE_ENV === "production" ? "https" : "http";
  return `${scheme}://${relay.subdomain}/control`;
}

function caPublicKeys() {
  return z.array(caKeySchema).parse(JSON.parse(env.RELAY_CA_PUBLIC_KEYS ?? "[]"));
}

function revokedRelayIds() {
  return new Set(
    (env.RELAY_REVOKED_IDS ?? "")
      .split(",")
      .map((id) => id.trim())
      .filter(Boolean),
  );
}

function verifyDetached(publicKey: string, payload: string, signature: string) {
  try {
    return verifySignature(
      null,
      Buffer.from(payload),
      publicKey,
      Buffer.from(signature, "base64url"),
    );
  } catch {
    return false;
  }
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => [key, sortKeys(child)]),
  );
}

function unauthorized(): never {
  throw new ORPCError("UNAUTHORIZED", { message: "Unauthorized." });
}

type Expiring<T> = { value: T; expiresAt: number };

export class MemoryRelayFleetStore implements RelayFleetStore {
  nonces = new Map<string, number>();
  sessions = new Map<string, Expiring<RelayFleetSession>>();
  relays = new Map<string, Expiring<RelayFleetRelay>>();
  regions = new Map<string, Set<string>>();
  relayLeases = new Map<string, Set<string>>();
  relayUsers = new Map<string, Set<string>>();
  leases = new Map<string, Expiring<string>>();
  users = new Map<string, Expiring<string>>();

  async consumeNonce(nonce: string, ttlMs: number, now: number) {
    const expiresAt = this.nonces.get(nonce);
    if (expiresAt && expiresAt > now) return false;
    this.nonces.set(nonce, now + ttlMs);
    return true;
  }
  async putSession(token: string, session: RelayFleetSession, ttlMs: number, now: number) {
    this.sessions.set(token, { value: session, expiresAt: now + ttlMs });
  }
  async getSession(token: string, now: number) {
    return fresh(this.sessions, token, now);
  }
  async putRelay(relay: RelayFleetRelay, ttlMs: number, now: number) {
    this.relays.set(relay.relayId, { value: relay, expiresAt: now + ttlMs });
    const set = this.regions.get(relay.region) ?? new Set<string>();
    set.add(relay.relayId);
    this.regions.set(relay.region, set);
  }
  async getRelay(relayId: string, now: number) {
    return fresh(this.relays, relayId, now);
  }
  async listRegions() {
    return [...this.regions.keys()].sort();
  }
  async listRelayIdsForRegion(region: string) {
    return [...(this.regions.get(region) ?? [])].sort();
  }
  async removeRelayFromRegion(region: string, relayId: string) {
    this.regions.get(region)?.delete(relayId);
  }
  async addRelayLease(relayId: string, instanceId: string) {
    addToSet(this.relayLeases, relayId, instanceId);
  }
  async replaceRelayLeases(relayId: string, instanceIds: string[]) {
    this.relayLeases.set(relayId, new Set(instanceIds));
  }
  async listRelayLeases(relayId: string) {
    return [...(this.relayLeases.get(relayId) ?? [])].sort();
  }
  async addRelayUser(relayId: string, userId: string) {
    addToSet(this.relayUsers, relayId, userId);
  }
  async replaceRelayUsers(relayId: string, userIds: string[]) {
    this.relayUsers.set(relayId, new Set(userIds));
  }
  async listRelayUsers(relayId: string) {
    return [...(this.relayUsers.get(relayId) ?? [])].sort();
  }
  async setLease(instanceId: string, relayId: string, ttlMs: number, now: number) {
    this.leases.set(instanceId, { value: relayId, expiresAt: now + ttlMs });
  }
  async getLease(instanceId: string, now: number) {
    return fresh(this.leases, instanceId, now);
  }
  async refreshLeaseIfOwner(instanceId: string, relayId: string, ttlMs: number, now: number) {
    if ((await this.getLease(instanceId, now)) !== relayId) return false;
    await this.setLease(instanceId, relayId, ttlMs, now);
    return true;
  }
  async removeLeaseIfOwner(instanceId: string, relayId: string) {
    if (this.leases.get(instanceId)?.value === relayId) this.leases.delete(instanceId);
  }
  async setUserLease(userId: string, relayId: string, ttlMs: number, now: number) {
    this.users.set(userId, { value: relayId, expiresAt: now + ttlMs });
  }
  async getUserLease(userId: string, now: number) {
    return fresh(this.users, userId, now);
  }
  async refreshUserLeaseIfOwner(userId: string, relayId: string, ttlMs: number, now: number) {
    if ((await this.getUserLease(userId, now)) !== relayId) return false;
    await this.setUserLease(userId, relayId, ttlMs, now);
    return true;
  }
  async removeUserLeaseIfOwner(userId: string, relayId: string) {
    if (this.users.get(userId)?.value === relayId) this.users.delete(userId);
  }
}

function fresh<T>(map: Map<string, Expiring<T>>, key: string, now: number) {
  const item = map.get(key);
  if (!item) return null;
  if (item.expiresAt <= now) {
    map.delete(key);
    return null;
  }
  return item.value;
}

function addToSet(map: Map<string, Set<string>>, key: string, value: string) {
  const set = map.get(key) ?? new Set<string>();
  set.add(value);
  map.set(key, set);
}

class RedisRelayFleetStore implements RelayFleetStore {
  private readonly redis = createRedisConnection({ maxRetriesPerRequest: 3, commandTimeout: 5000 });
  async consumeNonce(nonce: string, ttlMs: number) {
    return (await this.redis.set(key("nonce", nonce), "1", "PX", ttlMs, "NX")) === "OK";
  }
  async putSession(token: string, session: RelayFleetSession, ttlMs: number) {
    await this.redis.set(key("session", token), JSON.stringify(session), "PX", ttlMs);
  }
  async getSession(token: string) {
    const raw = await this.redis.get(key("session", token));
    return raw ? (JSON.parse(raw) as RelayFleetSession) : null;
  }
  async putRelay(relay: RelayFleetRelay, ttlMs: number) {
    await this.redis.set(key("relay", relay.relayId), JSON.stringify(relay), "PX", ttlMs);
    await this.redis.sadd(key("region", relay.region), relay.relayId);
    await this.redis.sadd(key("regions"), relay.region);
  }
  async getRelay(relayId: string) {
    const raw = await this.redis.get(key("relay", relayId));
    return raw ? (JSON.parse(raw) as RelayFleetRelay) : null;
  }
  async listRegions() {
    return (await this.redis.smembers(key("regions"))).sort();
  }
  async listRelayIdsForRegion(region: string) {
    return (await this.redis.smembers(key("region", region))).sort();
  }
  async removeRelayFromRegion(region: string, relayId: string) {
    await this.redis.srem(key("region", region), relayId);
  }
  async addRelayLease(relayId: string, instanceId: string) {
    await this.redis.sadd(key("relay-leases", relayId), instanceId);
  }
  async replaceRelayLeases(relayId: string, instanceIds: string[]) {
    await this.redis.del(key("relay-leases", relayId));
    if (instanceIds.length) await this.redis.sadd(key("relay-leases", relayId), ...instanceIds);
  }
  async listRelayLeases(relayId: string) {
    return (await this.redis.smembers(key("relay-leases", relayId))).sort();
  }
  async addRelayUser(relayId: string, userId: string) {
    await this.redis.sadd(key("relay-users", relayId), userId);
  }
  async replaceRelayUsers(relayId: string, userIds: string[]) {
    await this.redis.del(key("relay-users", relayId));
    if (userIds.length) await this.redis.sadd(key("relay-users", relayId), ...userIds);
  }
  async listRelayUsers(relayId: string) {
    return (await this.redis.smembers(key("relay-users", relayId))).sort();
  }
  async setLease(instanceId: string, relayId: string, ttlMs: number) {
    await this.redis.set(key("lease", instanceId), relayId, "PX", ttlMs);
  }
  async getLease(instanceId: string) {
    return this.redis.get(key("lease", instanceId));
  }
  async refreshLeaseIfOwner(instanceId: string, relayId: string, ttlMs: number) {
    if ((await this.getLease(instanceId)) !== relayId) return false;
    await this.redis.pexpire(key("lease", instanceId), ttlMs);
    return true;
  }
  async removeLeaseIfOwner(instanceId: string, relayId: string) {
    if ((await this.getLease(instanceId)) === relayId)
      await this.redis.del(key("lease", instanceId));
  }
  async setUserLease(userId: string, relayId: string, ttlMs: number) {
    await this.redis.set(key("user", userId), relayId, "PX", ttlMs);
  }
  async getUserLease(userId: string) {
    return this.redis.get(key("user", userId));
  }
  async refreshUserLeaseIfOwner(userId: string, relayId: string, ttlMs: number) {
    if ((await this.getUserLease(userId)) !== relayId) return false;
    await this.redis.pexpire(key("user", userId), ttlMs);
    return true;
  }
  async removeUserLeaseIfOwner(userId: string, relayId: string) {
    if ((await this.getUserLease(userId)) === relayId) await this.redis.del(key("user", userId));
  }
}

function key(...parts: string[]) {
  return ["flycockpit:fleet", ...parts].join(":");
}
