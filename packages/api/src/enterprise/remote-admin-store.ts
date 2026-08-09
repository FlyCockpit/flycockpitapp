import type { CounterState, RemoteAdminStepUpV1 } from "./remote-admin-state";
import { evaluateAndAdvanceCounter } from "./remote-admin-state";

export type AtomicStepUpStore = {
  updateUnconsumed(input: { id: string; consumedAt: number; now: number }): Promise<number>;
};

/** The store implementation must map this to one conditional UPDATE in a transaction. */
export async function consumeStepUpAtomically(
  store: AtomicStepUpStore,
  row: RemoteAdminStepUpV1,
  now: number,
): Promise<void> {
  if (now < row.issuedAt || now > row.expiresAt) throw new Error("remote_admin_step_up_expired");
  if ((await store.updateUnconsumed({ id: row.id, consumedAt: now, now })) !== 1)
    throw new Error("remote_admin_step_up_consumed");
}

export type AtomicCounterStore = {
  serializable<T>(callback: () => Promise<T>): Promise<T>;
  findStoredDecision(requestId: string, digest: Uint8Array): Promise<{ accepted: boolean } | null>;
  lockActiveCounter(input: {
    tenantId: Uint8Array;
    credentialIdHash: Uint8Array;
    registryGeneration: bigint;
  }): Promise<CounterState>;
  compareAndSetCounter(input: { expectedGeneration: bigint; next: CounterState }): Promise<boolean>;
  storeDecision(input: { requestId: string; digest: Uint8Array; accepted: boolean }): Promise<void>;
  revalidateCredential(input: {
    credentialIdHash: Uint8Array;
    registryGeneration: bigint;
  }): Promise<boolean>;
};

/** Signer-side exact retry and counter transition transaction contract. */
export async function consumeApprovalWithCounter(input: {
  store: AtomicCounterStore;
  requestId: string;
  digest: Uint8Array;
  tenantId: Uint8Array;
  credentialIdHash: Uint8Array;
  registryGeneration: bigint;
  observedSignCount: bigint;
}): Promise<boolean> {
  return input.store.serializable(async () => {
    const prior = await input.store.findStoredDecision(input.requestId, input.digest);
    if (prior) return prior.accepted;
    if (!(await input.store.revalidateCredential(input)))
      throw new Error("remote_admin_registry_stale");
    const current = await input.store.lockActiveCounter(input);
    const decision = evaluateAndAdvanceCounter(current, input.observedSignCount);
    if (
      !(await input.store.compareAndSetCounter({
        expectedGeneration: current.stateGeneration,
        next: decision.next,
      }))
    )
      throw new Error("remote_admin_counter_serialization_conflict");
    await input.store.storeDecision({
      requestId: input.requestId,
      digest: input.digest,
      accepted: decision.accepted,
    });
    return decision.accepted;
  });
}
