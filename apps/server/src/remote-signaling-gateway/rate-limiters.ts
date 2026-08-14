/**
 * Token-bucket rate limiters for the remote signaling gateway.
 *
 * All limiters use injected monotonic time so tests are deterministic.
 * Tenant/service policy may only lower these limits, never raise them.
 */
import { REMOTE_GATEWAY_LIMITER_MAX_BUCKETS, REMOTE_GATEWAY_RATE } from "./close-codes";

export interface MonotonicClock {
  nowMs(): number;
}

/** Memory bounds for per-key limiter maps (attacker-chosen keys must not grow unbounded). */
export interface LimiterMemoryOptions {
  /** Hard cap on live buckets; the least-recently-used bucket is evicted past it. */
  maxBuckets?: number;
  /** Minimum clock interval between eviction sweeps of fully-refilled buckets. */
  sweepIntervalMs?: number;
}

/**
 * A per-key token-bucket map that (a) evicts fully-refilled (idle) buckets on a
 * clock-driven sweep and (b) enforces a hard size cap with LRU eviction. Both
 * are driven by the injected {@link MonotonicClock} so growth keyed on
 * attacker-chosen input (IP, device id) is bounded.
 */
class BoundedBucketMap {
  private readonly buckets = new Map<string, TokenBucket>();
  private readonly maxBuckets: number;
  private readonly sweepIntervalMs: number;
  private lastSweepMs: number;

  constructor(
    private readonly clock: MonotonicClock,
    private readonly makeBucket: () => TokenBucket,
    options?: LimiterMemoryOptions,
  ) {
    this.maxBuckets = Math.max(1, options?.maxBuckets ?? REMOTE_GATEWAY_LIMITER_MAX_BUCKETS);
    this.sweepIntervalMs = Math.max(1, options?.sweepIntervalMs ?? 60_000);
    this.lastSweepMs = clock.nowMs();
  }

  private sweep() {
    const now = this.clock.nowMs();
    if (now - this.lastSweepMs < this.sweepIntervalMs) return;
    this.lastSweepMs = now;
    for (const [key, bucket] of this.buckets)
      if (bucket.available(this.clock) >= bucket.capacity) this.buckets.delete(key);
  }

  consume(key: string, cost = 1): boolean {
    this.sweep();
    let bucket = this.buckets.get(key);
    if (bucket)
      this.buckets.delete(key); // move to most-recently-used position
    else bucket = this.makeBucket();
    const allowed = bucket.consume(this.clock, cost);
    this.buckets.set(key, bucket);
    while (this.buckets.size > this.maxBuckets) {
      const oldest = this.buckets.keys().next().value;
      if (oldest === undefined) break;
      this.buckets.delete(oldest);
    }
    return allowed;
  }

  get size(): number {
    return this.buckets.size;
  }
}

export class TokenBucket {
  private tokens: number;
  private lastRefillMs: number;
  readonly capacity: number;
  readonly refillPerSecond: number;

  constructor(
    capacity: number,
    refillPerSecond: number,
    clock: MonotonicClock,
    initialTokens?: number,
  ) {
    this.capacity = capacity;
    this.refillPerSecond = refillPerSecond;
    this.tokens = initialTokens ?? capacity;
    this.lastRefillMs = clock.nowMs();
  }

  /** Try to consume `cost` tokens. Returns true if allowed, false if exhausted. */
  consume(clock: MonotonicClock, cost = 1): boolean {
    this.refill(clock);
    if (this.tokens >= cost) {
      this.tokens -= cost;
      return true;
    }
    return false;
  }

  private refill(clock: MonotonicClock) {
    const now = clock.nowMs();
    const elapsedMs = now - this.lastRefillMs;
    if (elapsedMs <= 0) return;
    const refill = (elapsedMs / 1000) * this.refillPerSecond;
    this.tokens = Math.min(this.capacity, this.tokens + refill);
    this.lastRefillMs = now;
  }

  /** Current available tokens (after refill). */
  available(clock: MonotonicClock): number {
    this.refill(clock);
    return this.tokens;
  }
}

/**
 * Per-IP unauthenticated upgrade limiter: 10/minute with burst 5.
 * Keyed by IP address.
 */
export class UnauthUpgradeRateLimiter {
  private readonly buckets: BoundedBucketMap;
  private readonly policyCeiling: { perMinute: number; burst: number };

  constructor(
    clock: MonotonicClock,
    policy?: { perMinute: number; burst: number },
    memory?: LimiterMemoryOptions,
  ) {
    // Policy may only lower the ceiling.
    this.policyCeiling = policy
      ? {
          perMinute: Math.min(policy.perMinute, REMOTE_GATEWAY_RATE.unauthUpgrade.perMinute),
          burst: Math.min(policy.burst, REMOTE_GATEWAY_RATE.unauthUpgrade.burst),
        }
      : REMOTE_GATEWAY_RATE.unauthUpgrade;
    this.buckets = new BoundedBucketMap(
      clock,
      () => new TokenBucket(this.policyCeiling.burst, this.policyCeiling.perMinute / 60, clock),
      memory,
    );
  }

  consume(ip: string): boolean {
    return this.buckets.consume(ip);
  }

  /** Live bucket count (diagnostics / memory-bound tests only). */
  get bucketCount(): number {
    return this.buckets.size;
  }
}

/**
 * Per-socket authenticated signaling limiter: 64 frames/second with burst 128.
 */
export class SignalingFrameRateLimiter {
  private readonly bucket: TokenBucket;
  private readonly policyCeiling: { perSecond: number; burst: number };

  constructor(
    private readonly clock: MonotonicClock,
    policy?: { perSecond: number; burst: number },
  ) {
    this.policyCeiling = policy
      ? {
          perSecond: Math.min(policy.perSecond, REMOTE_GATEWAY_RATE.signaling.perSecond),
          burst: Math.min(policy.burst, REMOTE_GATEWAY_RATE.signaling.burst),
        }
      : REMOTE_GATEWAY_RATE.signaling;
    this.bucket = new TokenBucket(this.policyCeiling.burst, this.policyCeiling.perSecond, clock);
  }

  consume(): boolean {
    return this.bucket.consume(this.clock);
  }
}

/**
 * Per-socket daemon control limiter: 32 frames/second with burst 64.
 */
export class DaemonControlRateLimiter {
  private readonly bucket: TokenBucket;
  private readonly policyCeiling: { perSecond: number; burst: number };

  constructor(
    private readonly clock: MonotonicClock,
    policy?: { perSecond: number; burst: number },
  ) {
    this.policyCeiling = policy
      ? {
          perSecond: Math.min(policy.perSecond, REMOTE_GATEWAY_RATE.daemonControl.perSecond),
          burst: Math.min(policy.burst, REMOTE_GATEWAY_RATE.daemonControl.burst),
        }
      : REMOTE_GATEWAY_RATE.daemonControl;
    this.bucket = new TokenBucket(this.policyCeiling.burst, this.policyCeiling.perSecond, clock);
  }

  consume(): boolean {
    return this.bucket.consume(this.clock);
  }
}

/**
 * Ticket creation limiter: 10/minute per device, 30/minute per account.
 */
export class TicketCreationRateLimiter {
  private readonly deviceBuckets: BoundedBucketMap;
  private readonly accountBuckets: BoundedBucketMap;

  constructor(
    clock: MonotonicClock,
    policy?: { perMinuteDevice: number; perMinuteAccount: number },
    memory?: LimiterMemoryOptions,
  ) {
    const deviceCeiling = policy
      ? Math.min(policy.perMinuteDevice, REMOTE_GATEWAY_RATE.ticketCreationPerMinuteDevice)
      : REMOTE_GATEWAY_RATE.ticketCreationPerMinuteDevice;
    const accountCeiling = policy
      ? Math.min(policy.perMinuteAccount, REMOTE_GATEWAY_RATE.ticketCreationPerMinuteAccount)
      : REMOTE_GATEWAY_RATE.ticketCreationPerMinuteAccount;
    this.deviceBuckets = new BoundedBucketMap(
      clock,
      () => new TokenBucket(deviceCeiling, deviceCeiling / 60, clock),
      memory,
    );
    this.accountBuckets = new BoundedBucketMap(
      clock,
      () => new TokenBucket(accountCeiling, accountCeiling / 60, clock),
      memory,
    );
  }

  consume(deviceId: string, accountId: string): boolean {
    if (!this.deviceBuckets.consume(deviceId)) return false;
    return this.accountBuckets.consume(accountId);
  }

  /** Live bucket counts (diagnostics / memory-bound tests only). */
  get bucketCounts(): { devices: number; accounts: number } {
    return { devices: this.deviceBuckets.size, accounts: this.accountBuckets.size };
  }
}
