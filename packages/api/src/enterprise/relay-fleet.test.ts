import { generateKeyPairSync, sign } from "node:crypto";
import { ORPCError } from "@orpc/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const envState = vi.hoisted(() => ({
  NODE_ENV: "test",
  RELAY_CA_PUBLIC_KEYS: "[]",
  RELAY_REVOKED_IDS: "",
}));

vi.mock("@flycockpit/env/server", () => ({ env: envState }));
vi.mock("@flycockpit/queue/connection", () => ({
  createRedisConnection: vi.fn(() => {
    throw new Error("Redis must not be used by relay fleet unit tests.");
  }),
}));

const {
  MemoryRelayFleetStore,
  listRelayCandidates,
  recordConnectorRelayLease,
  recordRelayHeartbeat,
  recordUserRelayLease,
  registerRelay,
  resolveRelayForInstance,
  resolveRelayForUser,
  verifyFleetSessionToken,
} = await import("./relay-fleet");

type KeyPair = ReturnType<typeof generateKeyPairSync>;

function keyPair(): KeyPair {
  return generateKeyPairSync("ed25519");
}

function publicPem(pair: KeyPair) {
  return pair.publicKey.export({ type: "spki", format: "pem" }).toString();
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

function detachedSign(pair: KeyPair, value: unknown) {
  return sign(null, Buffer.from(canonicalJson(value)), pair.privateKey).toString("base64url");
}

function buildRegistration(overrides: Partial<Record<string, unknown>> = {}) {
  const ca = keyPair();
  const relay = keyPair();
  const now = "2026-07-10T12:00:00.000Z";
  const payload = {
    relayId: "relay-a",
    subdomain: "relay-a.example.test",
    region: "iad",
    relayPublicKey: publicPem(relay),
    notBefore: "2026-07-10T11:00:00.000Z",
    notAfter: "2026-07-10T13:00:00.000Z",
    ...(overrides.payload as object | undefined),
  };
  const challenge = { relayId: payload.relayId, nonce: "nonce-nonce-nonce-1", timestamp: now };
  envState.RELAY_CA_PUBLIC_KEYS = JSON.stringify([{ kid: "ca-1", publicKey: publicPem(ca) }]);
  envState.RELAY_REVOKED_IDS = "";
  return {
    now,
    ca,
    relay,
    input: {
      certificate: {
        kid: "ca-1",
        payload,
        signature: detachedSign(ca, payload),
        ...(overrides.certificate as object | undefined),
      },
      challengeSignature: detachedSign(relay, challenge),
      nonce: challenge.nonce,
      timestamp: now,
      ...(overrides.input as object | undefined),
    },
  };
}

async function expectUnauthorized(action: () => Promise<unknown>) {
  await expect(action()).rejects.toSatisfy((error: ORPCError) => {
    expect(error.code).toBe("UNAUTHORIZED");
    return true;
  });
}

describe("relay fleet", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    envState.NODE_ENV = "test";
    envState.RELAY_CA_PUBLIC_KEYS = "[]";
    envState.RELAY_REVOKED_IDS = "";
  });

  it("registers a relay with a CA certificate, proof-of-possession, and one-time nonce", async () => {
    const store = new MemoryRelayFleetStore();
    const registration = buildRegistration();
    const result = await registerRelay(registration.input, {
      store,
      now: () => Date.parse(registration.now),
    });

    expect(result.sessionToken).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(
      await verifyFleetSessionToken(result.sessionToken, {
        store,
        now: () => Date.parse(registration.now),
      }),
    ).toEqual({
      relayId: "relay-a",
      expiresAt: Date.parse(registration.now) + 30 * 60_000,
    });
    await expectUnauthorized(() =>
      registerRelay(registration.input, { store, now: () => Date.parse(registration.now) }),
    );
  });

  it("rejects unknown CAs, expired certificates, revoked relays, and bad PoP signatures", async () => {
    const store = new MemoryRelayFleetStore();

    const unknownCa = buildRegistration({ certificate: { kid: "missing" } });
    await expectUnauthorized(() =>
      registerRelay(unknownCa.input, { store, now: () => Date.parse(unknownCa.now) }),
    );

    const expired = buildRegistration({ payload: { notAfter: "2026-07-10T11:59:00.000Z" } });
    await expectUnauthorized(() =>
      registerRelay(expired.input, { store, now: () => Date.parse(expired.now) }),
    );

    const revoked = buildRegistration();
    envState.RELAY_REVOKED_IDS = "relay-a";
    await expectUnauthorized(() =>
      registerRelay(revoked.input, { store, now: () => Date.parse(revoked.now) }),
    );

    const badPop = buildRegistration({ input: { challengeSignature: "not-a-valid-signature" } });
    await expectUnauthorized(() =>
      registerRelay(badPop.input, { store, now: () => Date.parse(badPop.now) }),
    );
  });

  it("lists one fresh accepting relay per region using power-of-two load selection", async () => {
    const store = new MemoryRelayFleetStore();
    const now = Date.parse("2026-07-10T12:00:00.000Z");
    await store.putRelay(
      {
        relayId: "relay-eu",
        subdomain: "eu.example.test",
        region: "fra",
        accepting: true,
        connections: 2,
      },
      45_000,
      now,
    );
    await store.putRelay(
      {
        relayId: "relay-busy",
        subdomain: "busy.example.test",
        region: "iad",
        accepting: true,
        connections: 50,
      },
      45_000,
      now,
    );
    await store.putRelay(
      {
        relayId: "relay-idle",
        subdomain: "idle.example.test",
        region: "iad",
        accepting: true,
        connections: 1,
      },
      45_000,
      now,
    );
    await store.putRelay(
      {
        relayId: "relay-draining",
        subdomain: "drain.example.test",
        region: "iad",
        accepting: false,
        connections: 0,
      },
      45_000,
      now,
    );
    await store.putRelay(
      {
        relayId: "relay-stale",
        subdomain: "stale.example.test",
        region: "sfo",
        accepting: true,
        connections: 0,
      },
      10,
      now - 1_000,
    );

    const randoms = [0, 0];
    const result = await listRelayCandidates({
      store,
      now: () => now,
      randomInt: (max) => randoms.shift() ?? max - 1,
    });

    expect(result).toEqual([
      { relayId: "relay-eu", region: "fra", wsUrl: "ws://eu.example.test/ws" },
      { relayId: "relay-idle", region: "iad", wsUrl: "ws://idle.example.test/ws" },
    ]);
    expect(await store.listRelayIdsForRegion("sfo")).toEqual([]);
  });

  it("records connector leases and rejects heartbeat lease hijacks", async () => {
    const store = new MemoryRelayFleetStore();
    const now = Date.parse("2026-07-10T12:00:00.000Z");
    await store.putRelay(
      {
        relayId: "relay-a",
        subdomain: "a.example.test",
        region: "iad",
        accepting: true,
        connections: 0,
      },
      45_000,
      now,
    );
    await store.putRelay(
      {
        relayId: "relay-b",
        subdomain: "b.example.test",
        region: "iad",
        accepting: true,
        connections: 0,
      },
      45_000,
      now,
    );

    await recordConnectorRelayLease("relay-a", "inst-1", { store, now: () => now });
    await expect(
      resolveRelayForInstance("inst-1", { store, now: () => now }),
    ).resolves.toMatchObject({
      relayId: "relay-a",
      wsUrl: "ws://a.example.test/ws",
    });

    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await recordRelayHeartbeat(
      { relayId: "relay-b" },
      {
        relayId: "relay-b",
        accepting: true,
        connections: 1,
        leaseDeltas: { added: ["inst-1"], removed: [] },
      },
      { store, now: () => now + 5_000 },
    );
    expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining("rejected lease hijack"));
    await expect(
      resolveRelayForInstance("inst-1", { store, now: () => now + 5_000 }),
    ).resolves.toMatchObject({
      relayId: "relay-a",
    });

    await recordRelayHeartbeat(
      { relayId: "relay-a" },
      {
        relayId: "relay-a",
        accepting: true,
        connections: 1,
        leaseDeltas: { added: [], removed: ["inst-1"] },
      },
      { store, now: () => now + 10_000 },
    );
    await expect(
      resolveRelayForInstance("inst-1", { store, now: () => now + 10_000 }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("NOT_FOUND");
      return true;
    });
  });

  it("tracks user relay leases for user token and toast routing", async () => {
    const store = new MemoryRelayFleetStore();
    const now = Date.parse("2026-07-10T12:00:00.000Z");
    await store.putRelay(
      {
        relayId: "relay-a",
        subdomain: "a.example.test",
        region: "iad",
        accepting: true,
        connections: 0,
      },
      45_000,
      now,
    );

    await recordUserRelayLease("user-1", "relay-a", { store, now: () => now });
    await expect(resolveRelayForUser("user-1", { store, now: () => now })).resolves.toEqual({
      relayId: "relay-a",
      region: "iad",
      wsUrl: "ws://a.example.test/ws",
      controlUrl: "http://a.example.test/control",
    });

    await recordRelayHeartbeat(
      { relayId: "relay-a" },
      {
        relayId: "relay-a",
        accepting: true,
        connections: 1,
        userDeltas: { added: [], removed: ["user-1"] },
      },
      { store, now: () => now + 1_000 },
    );
    await expect(
      resolveRelayForUser("user-1", { store, now: () => now + 1_000 }),
    ).resolves.toBeNull();
  });

  it("rejects a certificate without a proof-of-possession signature", async () => {
    const store = new MemoryRelayFleetStore();
    const registration = buildRegistration();
    const withoutChallenge = { ...registration.input, challengeSignature: undefined };

    await expectUnauthorized(() =>
      registerRelay(withoutChallenge, { store, now: () => Date.parse(registration.now) }),
    );
  });

  it("draws a fresh power-of-two sample on every candidate request", async () => {
    const store = new MemoryRelayFleetStore();
    const now = Date.parse("2026-07-10T12:00:00.000Z");
    for (const relayId of ["relay-0", "relay-1", "relay-2", "relay-3"]) {
      await store.putRelay(
        {
          relayId,
          subdomain: `${relayId}.example.test`,
          region: "iad",
          accepting: true,
          connections: 10,
        },
        45_000,
        now,
      );
    }

    const chosen = new Set<string>();
    const samples = [0, 0, 1, 0, 2, 0, 3, 0];
    let offset = 0;
    for (let i = 0; i < 200; i += 1) {
      const [candidate] = await listRelayCandidates({
        store,
        now: () => now,
        randomInt: () => samples[offset++ % samples.length] ?? 0,
      });
      if (candidate) chosen.add(candidate.relayId);
    }

    expect([...chosen].sort()).toEqual(["relay-0", "relay-1", "relay-2", "relay-3"]);
  });

  it("keeps existing leases routable while a relay is draining", async () => {
    const store = new MemoryRelayFleetStore();
    const now = Date.parse("2026-07-10T12:00:00.000Z");
    await store.putRelay(
      {
        relayId: "relay-a",
        subdomain: "a.example.test",
        region: "iad",
        accepting: true,
        connections: 0,
      },
      45_000,
      now,
    );
    await recordConnectorRelayLease("relay-a", "inst-1", { store, now: () => now });

    await recordRelayHeartbeat(
      { relayId: "relay-a" },
      { relayId: "relay-a", accepting: false, connections: 1 },
      { store, now: () => now + 1_000 },
    );

    await expect(
      recordConnectorRelayLease("relay-a", "inst-2", { store, now: () => now + 1_000 }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("NOT_FOUND");
      return true;
    });
    await expect(listRelayCandidates({ store, now: () => now + 1_000 })).resolves.toEqual([]);
    await expect(
      resolveRelayForInstance("inst-1", { store, now: () => now + 1_000 }),
    ).resolves.toMatchObject({
      relayId: "relay-a",
      wsUrl: "ws://a.example.test/ws",
    });
  });

  it("ignores heartbeat region drift and refreshes leases across repeated heartbeats", async () => {
    const store = new MemoryRelayFleetStore();
    const start = Date.parse("2026-07-10T12:00:00.000Z");
    await store.putRelay(
      {
        relayId: "relay-a",
        subdomain: "a.example.test",
        region: "iad",
        accepting: true,
        connections: 0,
      },
      45_000,
      start,
    );
    await recordConnectorRelayLease("relay-a", "inst-1", { store, now: () => start });

    for (const seconds of [15, 30, 45, 60, 75, 90]) {
      await recordRelayHeartbeat(
        { relayId: "relay-a" },
        { relayId: "relay-a", accepting: true, connections: 1, region: "sfo" },
        { store, now: () => start + seconds * 1_000 },
      );
    }

    await expect(
      resolveRelayForInstance("inst-1", { store, now: () => start + 90_000 }),
    ).resolves.toMatchObject({
      relayId: "relay-a",
    });
    await expect(store.getRelay("relay-a", start + 90_000)).resolves.toMatchObject({
      region: "iad",
    });
  });

  it("limits full reconcile deletes to leases owned by that relay", async () => {
    const store = new MemoryRelayFleetStore();
    const now = Date.parse("2026-07-10T12:00:00.000Z");
    await store.putRelay(
      {
        relayId: "relay-a",
        subdomain: "a.example.test",
        region: "iad",
        accepting: true,
        connections: 0,
      },
      45_000,
      now,
    );
    await store.putRelay(
      {
        relayId: "relay-b",
        subdomain: "b.example.test",
        region: "iad",
        accepting: true,
        connections: 0,
      },
      45_000,
      now,
    );
    await recordConnectorRelayLease("relay-a", "inst-1", { store, now: () => now });
    await recordConnectorRelayLease("relay-b", "inst-3", { store, now: () => now });

    await recordRelayHeartbeat(
      { relayId: "relay-a" },
      { relayId: "relay-a", accepting: true, connections: 1, leases: ["inst-2"] },
      { store, now: () => now + 1_000 },
    );

    await expect(
      resolveRelayForInstance("inst-1", { store, now: () => now + 1_000 }),
    ).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("NOT_FOUND");
      return true;
    });
    await expect(
      resolveRelayForInstance("inst-3", { store, now: () => now + 1_000 }),
    ).resolves.toMatchObject({
      relayId: "relay-b",
    });
  });
});
