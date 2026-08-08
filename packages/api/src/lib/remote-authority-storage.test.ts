import { describe, expect, it } from "vitest";
import type { ObservationLease } from "./remote-authority";
import {
  PostgresAuthorityRuntimeStore,
  RedisAuthorityObservationStore,
  type RedisClient,
  type SqlClient,
} from "./remote-authority-storage";

const lease = (generation: string): ObservationLease => ({
  issuerDigest: "a".repeat(64),
  deploymentId: "prod_1",
  membershipGeneration: "3",
  replicaId: "replica-a",
  replicaGeneration: "2",
  leaseGeneration: generation,
  revision: "4",
  digest: "b".repeat(64),
  currentKid: "k1",
  publicKids: ["k0", "k1"],
  authorityEpoch: "4",
  observedRedisTime: "100",
  expiresAt: "130",
});

describe("RedisAuthorityObservationStore", () => {
  it("uses an atomic decimal generation CAS and rejects a stale publisher", async () => {
    let stored: string | null = null;
    const evalCalls: string[][] = [];
    const redis = {
      time: async () => ["100", "0"],
      incr: async () => 1,
      set: async () => undefined,
      scan: async () => ["0", []] as [string, string[]],
      get: async () => stored,
      eval: async (_script: string, _keys: number, ...args: string[]) => {
        evalCalls.push(args);
        const incoming = args[1]!;
        if (stored) {
          const current = (JSON.parse(stored) as ObservationLease).leaseGeneration;
          if (
            current.length > incoming.length ||
            (current.length === incoming.length && current > incoming)
          )
            return 0;
        }
        stored = args[0]!;
        return 1;
      },
    } satisfies RedisClient;
    const store = new RedisAuthorityObservationStore(redis);

    await store.publishLease(lease("10"), 30);
    await expect(store.publishLease(lease("9"))).rejects.toThrow(
      "stale observation lease generation",
    );
    await store.publishLease(lease("10"));
    expect(evalCalls[0]).toEqual([
      "remote-authority:lease:prod_1:3:replica-a:2",
      expect.any(String),
      "10",
      "30",
    ]);
  });

  it("filters by membership generation and rejects a key/payload generation mismatch", async () => {
    const value = JSON.stringify(lease("8"));
    const redis = {
      time: async () => ["100", "0"],
      incr: async () => 1,
      set: async () => undefined,
      eval: async () => 1,
      scan: async () =>
        ["0", ["remote-authority:lease:prod_1:3:replica-a:99"]] as [string, string[]],
      get: async () => value,
    } satisfies RedisClient;
    await expect(
      new RedisAuthorityObservationStore(redis).listLeases("prod_1", "3"),
    ).rejects.toThrow("observation lease key mismatch");
  });
});

describe("PostgresAuthorityRuntimeStore raw fence behavior", () => {
  it("selects the newest frozen generation and reads its journal generation", async () => {
    const queries: Array<{ query: string; values: unknown[] }> = [];
    const db = {
      $transaction: async <T>(fn: (tx: SqlClient) => Promise<T>) => fn(db),
      $executeRawUnsafe: async () => 0,
      $queryRawUnsafe: async (query: string, ...values: unknown[]) => {
        queries.push({ query, values });
        if (query.includes("remote_authority_signing_fences"))
          return [
            {
              signingGeneration: "12",
              state: "frozen",
              cutoff: new Date(19_000),
              updatedAt: new Date(21_000),
            },
          ];
        return [{ mintId: "m1", state: "finalized", signedAt: new Date(19_000) }];
      },
    } satisfies SqlClient;

    const proof = await new PostgresAuthorityRuntimeStore(db).loadFrozenSigningJournalProof(
      "prod_1",
      "k0",
    );
    expect(proof.signingGeneration).toBe("12");
    expect(queries[0]?.query).toContain('ORDER BY "signingGeneration" DESC LIMIT 1');
    expect(queries[1]?.query).toContain('"signingGeneration"=$3::numeric');
    expect(queries[1]?.values).toEqual(["prod_1", "k0", "12"]);
  });
});
