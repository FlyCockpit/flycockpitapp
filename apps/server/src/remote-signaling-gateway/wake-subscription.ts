/**
 * Wake-notification seam for the signaling gateway.
 *
 * The store is the single authority for committed events; wake notifications are
 * pure "there may be new events" nudges that trigger a re-read through
 * `store.read` / `store.readDiscovery`. Production uses one lazy Redis
 * subscription connection (built in `remote-signaling-runtime.ts`) over the
 * store's existing Pub/Sub channels; tests use the in-process implementation
 * below, fed by `MemoryRemoteSignalingAttemptStore`'s `wake` callback.
 */
export interface RemoteSignalingWakeSubscription {
  /** Subscribe to an attempt wake route. Returns an unsubscribe function. */
  subscribeAttempt(routeId: Uint8Array, handler: () => void): () => void;
  /** Subscribe to an instance discovery wake route. Returns an unsubscribe function. */
  subscribeInstance(routeId: Uint8Array, handler: () => void): () => void;
  /**
   * Subscribe to the dedicated control-outbox wake channel for one instance
   * generation. The wake is a signal + high-water hint only; the woken handler
   * re-reads every control-event JWS from Postgres. Returns an unsubscribe.
   */
  subscribeControlOutbox(
    daemonInstanceProtocolId: string,
    daemonCertificateGeneration: bigint,
    handler: () => void,
  ): () => void;
  /** Release any underlying resources (e.g. the Redis subscription connection). */
  close(): Promise<void>;
}

/** The per-instance-generation key both wake sides agree on. */
export const controlOutboxWakeKey = (
  daemonInstanceProtocolId: string,
  daemonCertificateGeneration: bigint,
): string => `${daemonInstanceProtocolId}:${daemonCertificateGeneration}`;

const routeHex = (routeId: Uint8Array) => Buffer.from(routeId).toString("hex");

/** In-process wake bus. Importing it opens zero sockets. */
export class InMemoryRemoteSignalingWakeSubscription implements RemoteSignalingWakeSubscription {
  private readonly attemptHandlers = new Map<string, Set<() => void>>();
  private readonly instanceHandlers = new Map<string, Set<() => void>>();
  private readonly controlOutboxHandlers = new Map<string, Set<() => void>>();

  private subscribe(
    map: Map<string, Set<() => void>>,
    key: string,
    handler: () => void,
  ): () => void {
    let set = map.get(key);
    if (!set) {
      set = new Set();
      map.set(key, set);
    }
    set.add(handler);
    return () => {
      const current = map.get(key);
      if (!current) return;
      current.delete(handler);
      if (current.size === 0) map.delete(key);
    };
  }

  subscribeAttempt(routeId: Uint8Array, handler: () => void): () => void {
    return this.subscribe(this.attemptHandlers, routeHex(routeId), handler);
  }
  subscribeInstance(routeId: Uint8Array, handler: () => void): () => void {
    return this.subscribe(this.instanceHandlers, routeHex(routeId), handler);
  }
  subscribeControlOutbox(
    daemonInstanceProtocolId: string,
    daemonCertificateGeneration: bigint,
    handler: () => void,
  ): () => void {
    return this.subscribe(
      this.controlOutboxHandlers,
      controlOutboxWakeKey(daemonInstanceProtocolId, daemonCertificateGeneration),
      handler,
    );
  }

  /** Deliver an attempt wake to all subscribers (call from the memory store's `wake`). */
  publishAttempt(routeId: Uint8Array): void {
    for (const handler of this.attemptHandlers.get(routeHex(routeId)) ?? []) handler();
  }
  /** Deliver an instance discovery wake to all subscribers. */
  publishInstance(routeId: Uint8Array): void {
    for (const handler of this.instanceHandlers.get(routeHex(routeId)) ?? []) handler();
  }
  /** Deliver a control-outbox wake to all subscribers for one instance generation. */
  publishControlOutbox(
    daemonInstanceProtocolId: string,
    daemonCertificateGeneration: bigint,
  ): void {
    const key = controlOutboxWakeKey(daemonInstanceProtocolId, daemonCertificateGeneration);
    for (const handler of this.controlOutboxHandlers.get(key) ?? []) handler();
  }

  async close(): Promise<void> {
    this.attemptHandlers.clear();
    this.instanceHandlers.clear();
    this.controlOutboxHandlers.clear();
  }
}
