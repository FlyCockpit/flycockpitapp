import {
  type ActivatableRow,
  activateDuePolicies,
  type PolicyStore,
} from "@flycockpit/api/lib/remote-public-policy-storage";
import { describe, expect, it } from "vitest";

// The worker handler wires the production `activateDuePolicies` entry point to a
// Postgres store; this test certifies that same entry point against a fake
// store (no DB), proving the BullMQ wakeup drives the DB-time state machine.

const dueNarrowingRow: ActivatableRow = {
  policyId: "p2",
  serviceVersion: "2",
  changeClass: "narrowing_or_equal",
  compactJws: "compact.jws",
  payloadDigest: "pd",
  previousDigest: null,
  notBefore: "1000",
  state: "scheduled",
  dueNow: true,
  convergenceTimedOut: false,
};

function fakeStore(calls: string[]): PolicyStore {
  const unused = (name: string) => (): never => {
    throw new Error(`unexpected ${name}`);
  };
  const store: PolicyStore = {
    async markExpiredLeasesStale() {
      calls.push("markExpiredLeasesStale");
      return [];
    },
    async loadActivatableRows() {
      return [dueNarrowingRow];
    },
    async loadRequiredConsumerIds() {
      return [];
    },
    async activateNarrowingRow() {
      calls.push("activateNarrowingRow");
      return true;
    },
    recordGroupAck: unused("recordGroupAck"),
    prepareWideningRow: unused("prepareWideningRow"),
    markPolicyActive: unused("markPolicyActive"),
    markConvergenceFailed: unused("markConvergenceFailed"),
    advanceWideningPointer: unused("advanceWideningPointer"),
    markScheduledFailed: unused("markScheduledFailed"),
    loadPolicyTip: unused("loadPolicyTip"),
    loadPolicyByServiceVersion: unused("loadPolicyByServiceVersion"),
    insertScheduledPolicy: unused("insertScheduledPolicy"),
    seedConsumerGroups: unused("seedConsumerGroups"),
    registerReplicaLease: unused("registerReplicaLease"),
    renewReplicaLease: unused("renewReplicaLease"),
    drainReplicaLease: unused("drainReplicaLease"),
    removeReplicaLease: unused("removeReplicaLease"),
    reapStaleLease: unused("reapStaleLease"),
  };
  return store;
}

describe("activate-due-policies worker entry point", () => {
  it("drives activateDuePolicies over the recovered rows", async () => {
    const calls: string[] = [];
    const outcomes = await activateDuePolicies({ store: fakeStore(calls) });
    expect(outcomes).toEqual([{ policyId: "p2", action: "activated_narrowing" }]);
    expect(calls).toContain("markExpiredLeasesStale");
    expect(calls).toContain("activateNarrowingRow");
  });
});
