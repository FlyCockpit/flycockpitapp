import type {
  RemoteFallbackPairV1,
  RemoteFallbackRouteLeaseV1,
} from "@flycockpit/cockpit-protocol";
import { describe, expect, it } from "vitest";
import {
  RemoteFallbackPairCoordinator,
  RemoteFallbackQuotaLedger,
  type RemoteFallbackSignalingCommitter,
} from "./remote-fallback-runtime";

const bytes = (length: number, fill: number) => new Uint8Array(length).fill(fill);
const pair: RemoteFallbackPairV1 = {
  pairId: bytes(16, 1),
  opaqueRouteId: bytes(16, 2),
  routeGeneration: 1n,
  pairGeneration: 1n,
  clientSocketGeneration: 1n,
  daemonSocketGeneration: 1n,
  transportEpoch: bytes(16, 3),
  admissionSequence: 1n,
  grantDigest: bytes(32, 4),
  authBundleDigest: bytes(32, 5),
  attachmentBinding: bytes(32, 6),
  routeBindingKeyGeneration: 1n,
  state: "waiting_peer",
};
const lease = (fill: number): RemoteFallbackRouteLeaseV1 => ({
  pairId: pair.pairId,
  replicaId: `replica-${fill}`,
  socketGeneration: 1n,
  transportEpoch: pair.transportEpoch,
  attachmentBinding: pair.attachmentBinding,
  pairGeneration: pair.pairGeneration,
  connectionLeaseId: bytes(16, fill),
  connectionLeaseGeneration: 1n,
  connectionLeaseDigest: bytes(32, fill),
  routeLeaseGeneration: 1n,
  expiresAt: 30_000n,
});

describe("remote fallback causal admission", () => {
  it("requires pair/noise/proof commit acknowledgements before lease activation", async () => {
    const signaling: RemoteFallbackSignalingCommitter = {
      async transitionPairState() {},
      async commitFallbackPair() {
        return { eventId: "pair", sequence: "1", eventDigest: "a" };
      },
      async commitNoiseComplete({ role }) {
        return { eventId: role, sequence: role === "client" ? "2" : "3", eventDigest: role };
      },
      async readCommittedFinalProofSet() {
        return { finalProofSetDigest: bytes(32, 9) };
      },
    };
    const coordinator = new RemoteFallbackPairCoordinator(pair, signaling);
    await expect(coordinator.activate([lease(1), lease(2)])).rejects.toThrow(
      "lease_prerequisite_missing",
    );
    await coordinator.bothSocketsAuthenticated();
    expect(coordinator.currentState()).toBe("pair_commit_pending");
    await coordinator.confirmPairAuthorizationDelivered("pair:1:a");
    expect(coordinator.currentState()).toBe("noise_handshake");
    await coordinator.noiseComplete("client", bytes(32, 7), bytes(32, 8));
    expect(coordinator.currentState()).toBe("noise_commit_pending");
    await coordinator.noiseComplete("daemon", bytes(32, 7), bytes(32, 8));
    expect(coordinator.currentState()).toBe("proof_pending");
    coordinator.confirmNoiseCommitsDelivered({
      clientCommit: "client:2:client",
      daemonCommit: "daemon:3:daemon",
    });
    await coordinator.proofsCommitted();
    await expect(coordinator.activate([lease(1), lease(2)])).resolves.toEqual(bytes(32, 9));
    expect(coordinator.currentState()).toBe("active");
  });

  it("enforces socket, queue, byte and duration quota dimensions", () => {
    const ledger = new RemoteFallbackQuotaLedger({
      maxSocketsPerChild: 1,
      maxSocketsPerAccount: 1,
      maxSocketsPerTenant: 1,
      maxBytesPerPair: 10n,
      maxDurationMillis: 100n,
      maxQueuedBytesPerSocket: 20,
    });
    const coordinates = {
      childAttemptId: bytes(16, 1),
      accountId: bytes(16, 2),
      tenantId: bytes(16, 3),
      pairId: bytes(16, 4),
      nowMillis: 0n,
    };
    ledger.open(coordinates);
    expect(() => ledger.open({ ...coordinates, pairId: bytes(16, 5) })).toThrow(
      "fallback_socket_quota_exceeded",
    );
    ledger.charge(coordinates.pairId, 10, 20, 100n);
    expect(() => ledger.charge(coordinates.pairId, 1, 0, 100n)).toThrow(
      "fallback_pair_budget_exceeded",
    );
    ledger.close(coordinates);
  });
});
