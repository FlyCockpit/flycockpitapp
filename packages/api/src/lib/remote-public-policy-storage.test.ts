import { describe, expect, it } from "vitest";
import {
  type ActivatableRow,
  activateDuePolicies,
  type GroupAckResult,
  type PolicyStore,
  PostgresPolicyStore,
  type SqlClient,
} from "./remote-public-policy-storage";

// ---------------------------------------------------------------------------
// Fake SqlClient with INJECTED DB time — the boolean predicate columns
// (dueNow / expired / reapable / convergenceTimedOut) are the values the
// database clock would have produced. No real DB, no sleeps, no env mutation.
// ---------------------------------------------------------------------------

interface Recorder {
  queries: Array<{ q: string; values: unknown[] }>;
  executes: Array<{ q: string; values: unknown[] }>;
}

function makeDb(
  route: (q: string, values: unknown[]) => unknown[],
  exec: (q: string, values: unknown[]) => number = () => 1,
) {
  const rec: Recorder = { queries: [], executes: [] };
  const db = {
    $queryRawUnsafe: async (q: string, ...values: unknown[]) => {
      rec.queries.push({ q, values });
      return route(q, values);
    },
    $executeRawUnsafe: async (q: string, ...values: unknown[]) => {
      rec.executes.push({ q, values });
      return exec(q, values);
    },
    $transaction: async <T>(fn: (tx: SqlClient) => Promise<T>) => fn(db),
  } satisfies SqlClient;
  return { db, rec };
}

const store = (db: SqlClient) => new PostgresPolicyStore(db);

describe("PostgresPolicyStore leases", () => {
  it("renews with a 45s TTL and a replica-generation CAS (late heartbeat is a no-op)", async () => {
    // The fake models the CAS: only the current generation "2" changes a row.
    const { db, rec } = makeDb(
      () => [],
      (_q, values) => (values[1] === "2" ? 1 : 0),
    );
    const s = store(db);
    const fresh = await s.renewReplicaLease({
      replicaId: "r1",
      replicaGeneration: "2",
      evaluatorDigest: "ev",
      serviceVersion: "3",
      policyDigest: "pd",
    });
    const stale = await s.renewReplicaLease({
      replicaId: "r1",
      replicaGeneration: "1",
      evaluatorDigest: "ev",
      serviceVersion: "3",
      policyDigest: "pd",
    });
    expect(fresh).toBe(true);
    expect(stale).toBe(false);
    expect(rec.executes[0]?.q).toContain("INTERVAL '45 seconds'");
    expect(rec.executes[0]?.q).toContain('"replicaGeneration"=$2::numeric');
    expect(rec.executes[0]?.q).toContain("'ready'");
  });

  it("increments replica + membership generation on a replacement register", async () => {
    const { db } = makeDb((q) =>
      q.includes("remote_policy_consumer_groups")
        ? [{ membershipGeneration: "5" }]
        : [{ replicaGeneration: "3" }],
    );
    const result = await store(db).registerReplicaLease({
      consumerId: "attempt_issuer",
      replicaId: "r1",
      evaluatorDigest: "ev",
      serviceVersion: "3",
      policyDigest: "pd",
    });
    expect(result).toEqual({ replicaId: "r1", replicaGeneration: "4", membershipGeneration: "6" });
  });

  it("starts a fresh replica at generation 1 and bumps membership on a join", async () => {
    const { db } = makeDb((q) =>
      q.includes("remote_policy_consumer_groups") ? [{ membershipGeneration: "5" }] : [],
    );
    const result = await store(db).registerReplicaLease({
      consumerId: "attempt_issuer",
      replicaId: "r2",
      evaluatorDigest: "ev",
      serviceVersion: "3",
      policyDigest: "pd",
    });
    expect(result).toEqual({ replicaId: "r2", replicaGeneration: "1", membershipGeneration: "6" });
  });

  it("removes a lease only after drain + expiry and increments membership generation", async () => {
    const drainedExpired = makeDb((q) =>
      q.includes("remote_policy_consumer_groups")
        ? [{ membershipGeneration: "5" }]
        : [{ consumerId: "attempt_issuer", state: "draining", expired: true }],
    );
    expect(
      await store(drainedExpired.db).removeReplicaLease({
        replicaId: "r1",
        replicaGeneration: "1",
      }),
    ).toEqual({ removed: true, membershipGeneration: "6" });

    const drainedFresh = makeDb(() => [
      { consumerId: "attempt_issuer", state: "draining", expired: false },
    ]);
    expect(
      await store(drainedFresh.db).removeReplicaLease({ replicaId: "r1", replicaGeneration: "1" }),
    ).toEqual({ removed: false, membershipGeneration: null });

    const notDraining = makeDb(() => [
      { consumerId: "attempt_issuer", state: "ready", expired: true },
    ]);
    expect(
      await store(notDraining.db).removeReplicaLease({ replicaId: "r1", replicaGeneration: "1" }),
    ).toEqual({ removed: false, membershipGeneration: null });
  });

  it("marks unexplained expiry stale (blocking convergence)", async () => {
    const { db, rec } = makeDb(() => [{ replicaId: "r1" }, { replicaId: "r2" }]);
    const stale = await store(db).markExpiredLeasesStale();
    expect(stale).toEqual(["r1", "r2"]);
    expect(rec.queries[0]?.q).toContain("'stale'");
    expect(rec.queries[0]?.q).toContain('"expiresAt"<=NOW()');
    expect(rec.queries[0]?.q).toContain("'starting'");
  });

  it("reaps a stale lease only ≥90s after expiry and only with recorded evidence", async () => {
    await expect(
      store(makeDb(() => []).db).reapStaleLease({ replicaId: "r1", evidence: "  " }),
    ).rejects.toThrow(/evidence/);

    const reapable = makeDb((q) =>
      q.includes("remote_policy_consumer_groups")
        ? [{ membershipGeneration: "9" }]
        : [{ consumerId: "attempt_issuer", state: "stale", reapable: true }],
    );
    expect(
      await store(reapable.db).reapStaleLease({ replicaId: "r1", evidence: "operator: cordoned" }),
    ).toEqual({ reaped: true, membershipGeneration: "10" });
    expect(reapable.rec.queries[0]?.q).toContain("INTERVAL '90 seconds'");
    // The evidence is durably recorded (audit INSERT) in the same transaction,
    // before the lease delete — an authenticated reap always leaves a record.
    const auditInsert = reapable.rec.executes.find((e) =>
      e.q.includes("remote_policy_lease_reap_audits"),
    );
    expect(auditInsert, "reap must persist an audit row").toBeDefined();
    expect(auditInsert?.values).toContain("operator: cordoned");
    const deleteIdx = reapable.rec.executes.findIndex((e) =>
      e.q.includes("DELETE FROM remote_policy_consumer_replica_leases"),
    );
    const auditIdx = reapable.rec.executes.findIndex((e) =>
      e.q.includes("remote_policy_lease_reap_audits"),
    );
    expect(auditIdx).toBeGreaterThanOrEqual(0);
    expect(auditIdx).toBeLessThan(deleteIdx);

    const tooEarly = makeDb(() => [
      { consumerId: "attempt_issuer", state: "stale", reapable: false },
    ]);
    expect(
      await store(tooEarly.db).reapStaleLease({ replicaId: "r1", evidence: "operator: cordoned" }),
    ).toEqual({ reaped: false, membershipGeneration: null });
  });
});

// Route helper for the recordGroupAck transaction (several queries in order).
function ackRoute(opts: {
  group: Record<string, unknown> | null;
  snapshot: Array<Record<string, unknown>>;
  leases: Array<Record<string, unknown>>;
  policy?: Record<string, unknown>;
}) {
  return (q: string): unknown[] => {
    if (q.includes('FROM remote_public_service_policies WHERE "policyId"')) {
      return [opts.policy ?? { serviceVersion: "2", payloadDigest: "pd" }];
    }
    if (q.includes("remote_policy_consumer_groups")) return opts.group ? [opts.group] : [];
    if (q.includes("FROM remote_policy_activation_snapshots")) return opts.snapshot;
    if (q.includes("\"state\"<>'stale'")) return []; // recapture leases
    if (q.includes("FROM remote_policy_consumer_replica_leases")) return opts.leases;
    return [];
  };
}

describe("PostgresPolicyStore membership-snapshot ACK reducer", () => {
  const required = { state: "required", membershipGeneration: "7", evaluatorDigest: "ev" };

  it("ACKs only when every snapshotted replica is ready with the exact evaluator/policy digest", async () => {
    const { db } = makeDb(
      ackRoute({
        group: required,
        snapshot: [{ membershipGeneration: "7", replicaId: "r1", replicaGeneration: "3" }],
        leases: [
          {
            replicaId: "r1",
            replicaGeneration: "3",
            state: "ready",
            evaluatorDigest: "ev",
            serviceVersion: "2",
            policyDigest: "pd",
          },
        ],
      }),
    );
    expect(
      await store(db).recordGroupAck({ policyId: "p2", consumerId: "attempt_issuer" }),
    ).toEqual({
      acked: true,
      recaptured: false,
      membershipGeneration: "7",
    });
  });

  it("does not ACK while a snapshotted replica is still starting (no recapture)", async () => {
    const { db } = makeDb(
      ackRoute({
        group: required,
        snapshot: [{ membershipGeneration: "7", replicaId: "r1", replicaGeneration: "3" }],
        leases: [
          {
            replicaId: "r1",
            replicaGeneration: "3",
            state: "starting",
            evaluatorDigest: "ev",
            serviceVersion: "2",
            policyDigest: "pd",
          },
        ],
      }),
    );
    const result = await store(db).recordGroupAck({ policyId: "p2", consumerId: "attempt_issuer" });
    expect(result.acked).toBe(false);
    expect(result.recaptured).toBe(false);
  });

  it("invalidates and recaptures when the membership generation changed (scale-out)", async () => {
    const { db, rec } = makeDb(
      ackRoute({
        group: required,
        snapshot: [{ membershipGeneration: "6", replicaId: "r1", replicaGeneration: "3" }],
        leases: [],
      }),
    );
    const result = await store(db).recordGroupAck({ policyId: "p2", consumerId: "attempt_issuer" });
    expect(result).toEqual({ acked: false, recaptured: true, membershipGeneration: "7" });
    expect(
      rec.executes.some((e) => e.q.includes("DELETE FROM remote_policy_activation_snapshots")),
    ).toBe(true);
  });

  it("invalidates a snapshotted replica that went stale (blocks convergence)", async () => {
    const { db } = makeDb(
      ackRoute({
        group: required,
        snapshot: [{ membershipGeneration: "7", replicaId: "r1", replicaGeneration: "3" }],
        leases: [
          { replicaId: "r1", replicaGeneration: "3", state: "stale", evaluatorDigest: "ev" },
        ],
      }),
    );
    const result = await store(db).recordGroupAck({ policyId: "p2", consumerId: "attempt_issuer" });
    expect(result).toEqual({ acked: false, recaptured: true, membershipGeneration: "7" });
  });

  it("invalidates on evaluator digest divergence", async () => {
    const { db } = makeDb(
      ackRoute({
        group: required,
        snapshot: [{ membershipGeneration: "7", replicaId: "r1", replicaGeneration: "3" }],
        leases: [
          {
            replicaId: "r1",
            replicaGeneration: "3",
            state: "ready",
            evaluatorDigest: "different",
            serviceVersion: "2",
            policyDigest: "pd",
          },
        ],
      }),
    );
    expect(
      (await store(db).recordGroupAck({ policyId: "p2", consumerId: "attempt_issuer" })).acked,
    ).toBe(false);
  });

  it("cannot ACK an unknown or non-required consumer group", async () => {
    const { db } = makeDb(
      ackRoute({
        group: { state: "disabled", membershipGeneration: "1", evaluatorDigest: "ev" },
        snapshot: [],
        leases: [],
      }),
    );
    const result = await store(db).recordGroupAck({ policyId: "p2", consumerId: "attempt_issuer" });
    expect(result.acked).toBe(false);
    expect(result.recaptured).toBe(true);
  });
});

describe("PostgresPolicyStore activation transactions", () => {
  it("activates a narrowing row and appends the …_activated outbox in the same transaction", async () => {
    const { db, rec } = makeDb((q) => {
      if (q.includes("'scheduled'"))
        return [
          { serviceVersion: "2", compactJws: "compact.jws.v2", changeClass: "narrowing_or_equal" },
        ];
      if (q.includes('ORDER BY "serviceVersion" DESC')) return [{ policyId: "p1" }]; // prior pointer
      return []; // no leases
    });
    expect(await store(db).activateNarrowingRow("p2")).toBe(true);
    const update = rec.executes.find((e) => e.q.includes('SET "state"=$2::"RemotePolicyRowState"'));
    expect(update?.values).toEqual(["p2", "active_converging", "p1"]);
    expect(rec.executes.some((e) => e.q.includes("'remote_public_service_policy_activated'"))).toBe(
      true,
    );
  });

  it("prepares a widening row without superseding the pointer or emitting activated", async () => {
    const { db, rec } = makeDb((q) =>
      q.includes("'scheduled'")
        ? [{ serviceVersion: "3", compactJws: "compact.jws.v3", changeClass: "widening" }]
        : [],
    );
    expect(await store(db).prepareWideningRow("p3")).toBe(true);
    const update = rec.executes.find((e) => e.q.includes('SET "state"=$2::"RemotePolicyRowState"'));
    expect(update?.values).toEqual(["p3", "preparing", null]);
    expect(rec.executes.some((e) => e.q.includes("'remote_public_service_policy_activated'"))).toBe(
      false,
    );
  });

  it("advances a widening pointer and appends activated in a second transaction", async () => {
    const { db, rec } = makeDb((q) =>
      q.includes("'preparing'")
        ? [{ serviceVersion: "3", compactJws: "compact.jws.v3" }]
        : [{ policyId: "p2" }],
    );
    expect(await store(db).advanceWideningPointer("p3")).toBe(true);
    expect(rec.executes.some((e) => e.q.includes("SET \"state\"='active'"))).toBe(true);
    expect(rec.executes.some((e) => e.q.includes("'remote_public_service_policy_activated'"))).toBe(
      true,
    );
  });

  it("fails convergence without rolling back the pointer, and fails preparing keeping the old policy", async () => {
    const failed = makeDb(() => []);
    expect(await store(failed.db).markConvergenceFailed("p2")).toBe(true);
    expect(failed.rec.executes[0]?.q).toContain("'active_convergence_failed'");
    expect(failed.rec.executes[0]?.q).toContain("\"state\"='active_converging'");
    expect(failed.rec.executes[0]?.q).not.toContain("supersedesPolicyId");

    const scheduledFailed = makeDb(() => []);
    expect(await store(scheduledFailed.db).markScheduledFailed("p3")).toBe(true);
    expect(scheduledFailed.rec.executes[0]?.q).toContain("'scheduled_failed'");
    expect(scheduledFailed.rec.executes[0]?.q).toContain("\"state\"='preparing'");
  });

  it("scans scheduled/preparing/active_converging rows for crash-recovery", async () => {
    const { db, rec } = makeDb(() => [
      {
        policyId: "p2",
        serviceVersion: "2",
        changeClass: "narrowing_or_equal",
        compactJws: "c",
        payloadDigest: "pd",
        previousDigest: null,
        notBefore: "1000",
        state: "scheduled",
        dueNow: true,
        convergenceTimedOut: false,
      },
    ]);
    const rows = await store(db).loadActivatableRows();
    expect(rows[0]?.dueNow).toBe(true);
    expect(rec.queries[0]?.q).toContain("'scheduled'");
    expect(rec.queries[0]?.q).toContain("'preparing'");
    expect(rec.queries[0]?.q).toContain("'active_converging'");
  });
});

// ---------------------------------------------------------------------------
// activateDuePolicies orchestrator — driven by a fake PolicyStore.
// ---------------------------------------------------------------------------

function orchestratorStore(opts: {
  rows: ActivatableRow[];
  required: string[];
  ack: GroupAckResult;
}): { store: PolicyStore; calls: string[] } {
  const calls: string[] = [];
  const record = (name: string) => {
    calls.push(name);
  };
  const store: PolicyStore = {
    async markExpiredLeasesStale() {
      record("markExpiredLeasesStale");
      return [];
    },
    async loadActivatableRows() {
      return opts.rows;
    },
    async loadRequiredConsumerIds() {
      return opts.required;
    },
    async recordGroupAck() {
      return opts.ack;
    },
    async activateNarrowingRow() {
      record("activateNarrowingRow");
      return true;
    },
    async prepareWideningRow() {
      record("prepareWideningRow");
      return true;
    },
    async markPolicyActive() {
      record("markPolicyActive");
      return true;
    },
    async markConvergenceFailed() {
      record("markConvergenceFailed");
      return true;
    },
    async advanceWideningPointer() {
      record("advanceWideningPointer");
      return true;
    },
    async markScheduledFailed() {
      record("markScheduledFailed");
      return true;
    },
    loadPolicyTip: () => Promise.reject(new Error("unused")),
    loadPolicyByServiceVersion: () => Promise.reject(new Error("unused")),
    insertScheduledPolicy: () => Promise.reject(new Error("unused")),
    seedConsumerGroups: () => Promise.reject(new Error("unused")),
    registerReplicaLease: () => Promise.reject(new Error("unused")),
    renewReplicaLease: () => Promise.reject(new Error("unused")),
    drainReplicaLease: () => Promise.reject(new Error("unused")),
    removeReplicaLease: () => Promise.reject(new Error("unused")),
    reapStaleLease: () => Promise.reject(new Error("unused")),
  };
  return { store, calls };
}

function row(over: Partial<ActivatableRow>): ActivatableRow {
  return {
    policyId: "p",
    serviceVersion: "2",
    changeClass: "narrowing_or_equal",
    compactJws: "c",
    payloadDigest: "pd",
    previousDigest: null,
    notBefore: "1000",
    state: "scheduled",
    dueNow: true,
    convergenceTimedOut: false,
    ...over,
  };
}

const acked: GroupAckResult = { acked: true, recaptured: false, membershipGeneration: "1" };
const notAcked: GroupAckResult = { acked: false, recaptured: false, membershipGeneration: "1" };

describe("activateDuePolicies", () => {
  it("activates a due narrowing row", async () => {
    const { store, calls } = orchestratorStore({ rows: [row({})], required: [], ack: acked });
    const outcomes = await activateDuePolicies({ store });
    expect(outcomes).toEqual([{ policyId: "p", action: "activated_narrowing" }]);
    expect(calls).toContain("activateNarrowingRow");
  });

  it("prepares a due widening row", async () => {
    const { store, calls } = orchestratorStore({
      rows: [row({ changeClass: "widening" })],
      required: [],
      ack: acked,
    });
    expect(await activateDuePolicies({ store })).toEqual([
      { policyId: "p", action: "preparing_widening" },
    ]);
    expect(calls).toContain("prepareWideningRow");
  });

  it("marks a fully-ACKed converging row active", async () => {
    const { store, calls } = orchestratorStore({
      rows: [row({ state: "active_converging" })],
      required: ["attempt_issuer"],
      ack: acked,
    });
    expect(await activateDuePolicies({ store })).toEqual([{ policyId: "p", action: "active" }]);
    expect(calls).toContain("markPolicyActive");
  });

  it("fails a converging row after the 300s timeout without rolling back", async () => {
    const { store, calls } = orchestratorStore({
      rows: [row({ state: "active_converging", convergenceTimedOut: true })],
      required: ["attempt_issuer"],
      ack: notAcked,
    });
    expect(await activateDuePolicies({ store })).toEqual([
      { policyId: "p", action: "convergence_failed" },
    ]);
    expect(calls).toContain("markConvergenceFailed");
    expect(calls).not.toContain("markPolicyActive");
    expect(calls).not.toContain("advanceWideningPointer");
  });

  it("advances the widening pointer only after a complete ACK", async () => {
    const { store, calls } = orchestratorStore({
      rows: [row({ state: "preparing", changeClass: "widening" })],
      required: ["attempt_issuer"],
      ack: acked,
    });
    expect(await activateDuePolicies({ store })).toEqual([{ policyId: "p", action: "active" }]);
    expect(calls).toContain("advanceWideningPointer");
  });

  it("fails a preparing widening row on timeout, keeping the old policy authoritative", async () => {
    const { store, calls } = orchestratorStore({
      rows: [row({ state: "preparing", changeClass: "widening", convergenceTimedOut: true })],
      required: ["attempt_issuer"],
      ack: notAcked,
    });
    expect(await activateDuePolicies({ store })).toEqual([
      { policyId: "p", action: "scheduled_failed" },
    ]);
    expect(calls).toContain("markScheduledFailed");
    expect(calls).not.toContain("advanceWideningPointer");
  });
});
