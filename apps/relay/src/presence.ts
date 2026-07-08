import { EventEmitter } from "node:events";
import { type RelayControlMessage, relayControlMessageSchema } from "@flycockpit/relay-protocol";
import IORedis from "ioredis";

export type PresenceLease = {
  instanceId: string;
  relayId: string;
  connectionId: string;
  expiresAt: number;
};

export type PresenceStore = {
  setDaemonLease(lease: PresenceLease, ttlMs: number): Promise<void>;
  touchDaemonLease(
    instanceId: string,
    connectionId: string,
    expiresAt: number,
    ttlMs: number,
  ): Promise<void>;
  getDaemonLease(instanceId: string): Promise<PresenceLease | null>;
  deleteDaemonLease(instanceId: string, connectionId: string): Promise<void>;
  publishControl(message: RelayControlMessage): Promise<void>;
  subscribeControl(handler: (message: RelayControlMessage) => void): Promise<() => Promise<void>>;
  close(): Promise<void>;
};

const controlChannel = "flycockpit:relay:control";
const keyPrefix = "flycockpit:relay:presence:";

function isExpired(lease: PresenceLease, now = Date.now()) {
  return lease.expiresAt <= now;
}

export class MemoryPresenceStore implements PresenceStore {
  private leases = new Map<string, PresenceLease>();
  private events = new EventEmitter();

  async setDaemonLease(lease: PresenceLease, _ttlMs?: number): Promise<void> {
    this.leases.set(lease.instanceId, lease);
  }

  async touchDaemonLease(
    instanceId: string,
    connectionId: string,
    expiresAt: number,
    _ttlMs?: number,
  ): Promise<void> {
    const current = this.leases.get(instanceId);
    if (!current || current.connectionId !== connectionId) return;
    this.leases.set(instanceId, { ...current, expiresAt });
  }

  async getDaemonLease(instanceId: string): Promise<PresenceLease | null> {
    const lease = this.leases.get(instanceId);
    if (!lease) return null;
    if (isExpired(lease)) {
      this.leases.delete(instanceId);
      return null;
    }
    return lease;
  }

  async deleteDaemonLease(instanceId: string, connectionId: string): Promise<void> {
    const current = this.leases.get(instanceId);
    if (current?.connectionId === connectionId) this.leases.delete(instanceId);
  }

  async publishControl(message: RelayControlMessage): Promise<void> {
    queueMicrotask(() => this.events.emit("control", message));
  }

  async subscribeControl(
    handler: (message: RelayControlMessage) => void,
  ): Promise<() => Promise<void>> {
    this.events.on("control", handler);
    return async () => {
      this.events.off("control", handler);
    };
  }

  async close(): Promise<void> {
    this.events.removeAllListeners();
    this.leases.clear();
  }
}

class RedisPresenceStore implements PresenceStore {
  private readonly redis: IORedis;
  private readonly subscriber: IORedis;

  constructor(redisUrl: string) {
    this.redis = new IORedis(redisUrl, {
      maxRetriesPerRequest: 3,
      connectTimeout: 5000,
      commandTimeout: 5000,
    });
    this.subscriber = new IORedis(redisUrl, {
      maxRetriesPerRequest: null,
      connectTimeout: 5000,
      commandTimeout: 5000,
    });
  }

  async setDaemonLease(lease: PresenceLease, ttlMs: number): Promise<void> {
    await this.redis.set(keyPrefix + lease.instanceId, JSON.stringify(lease), "PX", ttlMs);
  }

  async touchDaemonLease(
    instanceId: string,
    connectionId: string,
    expiresAt: number,
    ttlMs: number,
  ): Promise<void> {
    const current = await this.getDaemonLease(instanceId);
    if (!current || current.connectionId !== connectionId) return;
    await this.setDaemonLease({ ...current, expiresAt }, ttlMs);
  }

  async getDaemonLease(instanceId: string): Promise<PresenceLease | null> {
    const raw = await this.redis.get(keyPrefix + instanceId);
    if (!raw) return null;
    try {
      const lease = JSON.parse(raw) as PresenceLease;
      if (isExpired(lease)) {
        await this.redis.del(keyPrefix + instanceId);
        return null;
      }
      return lease;
    } catch {
      await this.redis.del(keyPrefix + instanceId);
      return null;
    }
  }

  async deleteDaemonLease(instanceId: string, connectionId: string): Promise<void> {
    const current = await this.getDaemonLease(instanceId);
    if (current?.connectionId === connectionId) await this.redis.del(keyPrefix + instanceId);
  }

  async publishControl(message: RelayControlMessage): Promise<void> {
    await this.redis.publish(controlChannel, JSON.stringify(message));
  }

  async subscribeControl(
    handler: (message: RelayControlMessage) => void,
  ): Promise<() => Promise<void>> {
    const listener = (_channel: string, raw: string) => {
      try {
        handler(relayControlMessageSchema.parse(JSON.parse(raw)));
      } catch {
        // Ignore malformed control messages; they may come from an older relay.
      }
    };
    this.subscriber.on("message", listener);
    await this.subscriber.subscribe(controlChannel);
    return async () => {
      this.subscriber.off("message", listener);
      await this.subscriber.unsubscribe(controlChannel);
    };
  }

  async close(): Promise<void> {
    await Promise.allSettled([this.subscriber.quit(), this.redis.quit()]);
  }
}

export function createPresenceStore(redisUrl?: string): PresenceStore {
  return redisUrl ? new RedisPresenceStore(redisUrl) : new MemoryPresenceStore();
}
