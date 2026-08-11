/**
 * Token-bucket rate limiters for the remote signaling gateway.
 *
 * All limiters use injected monotonic time so tests are deterministic.
 * Tenant/service policy may only lower these limits, never raise them.
 */
import { REMOTE_GATEWAY_RATE } from "./close-codes";

export interface MonotonicClock {
  nowMs(): number;
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
  private readonly buckets = new Map<string, TokenBucket>();
  private readonly policyCeiling: { perMinute: number; burst: number };

  constructor(
    private readonly clock: MonotonicClock,
    policy?: { perMinute: number; burst: number },
  ) {
    // Policy may only lower the ceiling.
    this.policyCeiling = policy
      ? {
          perMinute: Math.min(policy.perMinute, REMOTE_GATEWAY_RATE.unauthUpgrade.perMinute),
          burst: Math.min(policy.burst, REMOTE_GATEWAY_RATE.unauthUpgrade.burst),
        }
      : REMOTE_GATEWAY_RATE.unauthUpgrade;
  }

  consume(ip: string): boolean {
    let bucket = this.buckets.get(ip);
    if (!bucket) {
      bucket = new TokenBucket(
        this.policyCeiling.burst,
        this.policyCeiling.perMinute / 60,
        this.clock,
      );
      this.buckets.set(ip, bucket);
    }
    return bucket.consume(this.clock);
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
  private readonly deviceBuckets = new Map<string, TokenBucket>();
  private readonly accountBuckets = new Map<string, TokenBucket>();
  private readonly deviceCeiling: number;
  private readonly accountCeiling: number;

  constructor(
    private readonly clock: MonotonicClock,
    policy?: { perMinuteDevice: number; perMinuteAccount: number },
  ) {
    this.deviceCeiling = policy
      ? Math.min(policy.perMinuteDevice, REMOTE_GATEWAY_RATE.ticketCreationPerMinuteDevice)
      : REMOTE_GATEWAY_RATE.ticketCreationPerMinuteDevice;
    this.accountCeiling = policy
      ? Math.min(policy.perMinuteAccount, REMOTE_GATEWAY_RATE.ticketCreationPerMinuteAccount)
      : REMOTE_GATEWAY_RATE.ticketCreationPerMinuteAccount;
  }

  consume(deviceId: string, accountId: string): boolean {
    let deviceBucket = this.deviceBuckets.get(deviceId);
    if (!deviceBucket) {
      deviceBucket = new TokenBucket(this.deviceCeiling, this.deviceCeiling / 60, this.clock);
      this.deviceBuckets.set(deviceId, deviceBucket);
    }
    if (!deviceBucket.consume(this.clock)) return false;

    let accountBucket = this.accountBuckets.get(accountId);
    if (!accountBucket) {
      accountBucket = new TokenBucket(this.accountCeiling, this.accountCeiling / 60, this.clock);
      this.accountBuckets.set(accountId, accountBucket);
    }
    return accountBucket.consume(this.clock);
  }
}
