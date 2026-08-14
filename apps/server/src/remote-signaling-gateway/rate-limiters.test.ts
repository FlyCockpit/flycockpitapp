import { describe, expect, it } from "vitest";
import { REMOTE_GATEWAY_RATE } from "./close-codes";
import {
  DaemonControlRateLimiter,
  type MonotonicClock,
  SignalingFrameRateLimiter,
  TicketCreationRateLimiter,
  TokenBucket,
  UnauthUpgradeRateLimiter,
} from "./rate-limiters";

class FakeClock implements MonotonicClock {
  private ms: number;
  constructor(initial = 0) {
    this.ms = initial;
  }
  nowMs(): number {
    return this.ms;
  }
  advance(ms: number) {
    this.ms += ms;
  }
}

describe("remote_gateway_rate_limit: token bucket basics", () => {
  it("allows up to capacity then rejects", () => {
    const clock = new FakeClock();
    const bucket = new TokenBucket(5, 10, clock);
    for (let i = 0; i < 5; i++) expect(bucket.consume(clock)).toBe(true);
    expect(bucket.consume(clock)).toBe(false);
  });

  it("refills over time", () => {
    const clock = new FakeClock();
    const bucket = new TokenBucket(5, 10, clock); // 10 per second
    for (let i = 0; i < 5; i++) bucket.consume(clock);
    expect(bucket.consume(clock)).toBe(false);
    clock.advance(500); // 0.5s → 5 tokens refilled
    expect(bucket.consume(clock)).toBe(true);
  });
});

describe("remote_gateway_rate_limit: unauth upgrade limiter", () => {
  it("proves 10/minute with burst 5", () => {
    expect(REMOTE_GATEWAY_RATE.unauthUpgrade.perMinute).toBe(10);
    expect(REMOTE_GATEWAY_RATE.unauthUpgrade.burst).toBe(5);
    const clock = new FakeClock();
    const limiter = new UnauthUpgradeRateLimiter(clock);
    // Burst 5
    for (let i = 0; i < 5; i++) expect(limiter.consume("1.2.3.4")).toBe(true);
    expect(limiter.consume("1.2.3.4")).toBe(false);
    // Different IP has its own bucket
    expect(limiter.consume("5.6.7.8")).toBe(true);
  });

  it("refills at 10/minute rate", () => {
    const clock = new FakeClock();
    const limiter = new UnauthUpgradeRateLimiter(clock);
    for (let i = 0; i < 5; i++) limiter.consume("1.2.3.4");
    expect(limiter.consume("1.2.3.4")).toBe(false);
    // 10/minute = 1/6 seconds per token. 6 seconds → 1 token.
    clock.advance(6_000);
    expect(limiter.consume("1.2.3.4")).toBe(true);
  });

  it("policy may only lower the ceiling", () => {
    const clock = new FakeClock();
    // Try to raise — should be clamped down to the default.
    const limiter = new UnauthUpgradeRateLimiter(clock, {
      perMinute: 100,
      burst: 100,
    });
    // Should still be 5 burst.
    for (let i = 0; i < 5; i++) expect(limiter.consume("1.2.3.4")).toBe(true);
    expect(limiter.consume("1.2.3.4")).toBe(false);
  });

  it("policy may lower the ceiling", () => {
    const clock = new FakeClock();
    const limiter = new UnauthUpgradeRateLimiter(clock, {
      perMinute: 5,
      burst: 2,
    });
    for (let i = 0; i < 2; i++) expect(limiter.consume("1.2.3.4")).toBe(true);
    expect(limiter.consume("1.2.3.4")).toBe(false);
  });
});

describe("remote_gateway_rate_limit: signaling frame limiter", () => {
  it("proves 64/second with burst 128", () => {
    expect(REMOTE_GATEWAY_RATE.signaling.perSecond).toBe(64);
    expect(REMOTE_GATEWAY_RATE.signaling.burst).toBe(128);
    const clock = new FakeClock();
    const limiter = new SignalingFrameRateLimiter(clock);
    for (let i = 0; i < 128; i++) expect(limiter.consume()).toBe(true);
    expect(limiter.consume()).toBe(false);
  });

  it("refills at 64/second", () => {
    const clock = new FakeClock();
    const limiter = new SignalingFrameRateLimiter(clock);
    for (let i = 0; i < 128; i++) limiter.consume();
    expect(limiter.consume()).toBe(false);
    clock.advance(1_000); // 1s → 64 tokens
    for (let i = 0; i < 64; i++) expect(limiter.consume()).toBe(true);
  });
});

describe("remote_gateway_rate_limit: daemon control limiter", () => {
  it("proves 32/second with burst 64", () => {
    expect(REMOTE_GATEWAY_RATE.daemonControl.perSecond).toBe(32);
    expect(REMOTE_GATEWAY_RATE.daemonControl.burst).toBe(64);
    const clock = new FakeClock();
    const limiter = new DaemonControlRateLimiter(clock);
    for (let i = 0; i < 64; i++) expect(limiter.consume()).toBe(true);
    expect(limiter.consume()).toBe(false);
  });
});

describe("remote_gateway_rate_limit: ticket creation limiter", () => {
  it("proves 10/minute per device and 30/minute per account", () => {
    expect(REMOTE_GATEWAY_RATE.ticketCreationPerMinuteDevice).toBe(10);
    expect(REMOTE_GATEWAY_RATE.ticketCreationPerMinuteAccount).toBe(30);
    const clock = new FakeClock();
    const limiter = new TicketCreationRateLimiter(clock);
    // 10 tickets for one device
    for (let i = 0; i < 10; i++) expect(limiter.consume("device-1", "account-1")).toBe(true);
    expect(limiter.consume("device-1", "account-1")).toBe(false);
    // Different device, same account — device bucket is fresh but account has budget
    expect(limiter.consume("device-2", "account-1")).toBe(true);
  });

  it("account limit kicks in after 30 tickets across devices", () => {
    const clock = new FakeClock();
    const limiter = new TicketCreationRateLimiter(clock);
    for (let d = 0; d < 3; d++) {
      for (let i = 0; i < 10; i++) {
        expect(limiter.consume(`device-${d}`, "account-1")).toBe(true);
      }
    }
    // 30 consumed; 31st from a new device should fail on account bucket
    expect(limiter.consume("device-3", "account-1")).toBe(false);
  });
});

describe("remote_gateway_rate_limit: ICE candidate cap", () => {
  it("proves 64 ICE candidates per role/attempt", () => {
    expect(REMOTE_GATEWAY_RATE.maxIceCandidatesPerRoleAttempt).toBe(64);
  });
});

describe("remote_gateway_rate_limit: limiter memory bound", () => {
  it("evicts fully-refilled buckets on a clock-driven sweep", () => {
    const clock = new FakeClock();
    const limiter = new UnauthUpgradeRateLimiter(clock, undefined, {
      maxBuckets: 10_000,
      sweepIntervalMs: 1_000,
    });
    for (let i = 0; i < 100; i++) limiter.consume(`10.0.0.${i}`);
    expect(limiter.bucketCount).toBe(100);
    // Advance long enough for every idle bucket to refill to capacity, then the
    // next consume triggers a sweep that evicts all of them.
    clock.advance(60_000);
    limiter.consume("198.51.100.1");
    expect(limiter.bucketCount).toBe(1);
    // Per-IP limiting still rejects an over-limit burst after the sweep.
    for (let i = 0; i < 5; i++) expect(limiter.consume("203.0.113.7")).toBe(true);
    expect(limiter.consume("203.0.113.7")).toBe(false);
  });

  it("caps the bucket map with oldest-eviction under N >> cap distinct IPs", () => {
    const clock = new FakeClock();
    const limiter = new UnauthUpgradeRateLimiter(clock, undefined, {
      maxBuckets: 4,
      sweepIntervalMs: 10_000,
    });
    for (let i = 0; i < 500; i++) limiter.consume(`8.8.${Math.floor(i / 256)}.${i % 256}`);
    expect(limiter.bucketCount).toBeLessThanOrEqual(4);
  });

  it("bounds the ticket-creation limiter's device and account maps", () => {
    const clock = new FakeClock();
    const limiter = new TicketCreationRateLimiter(clock, undefined, {
      maxBuckets: 4,
      sweepIntervalMs: 10_000,
    });
    for (let i = 0; i < 200; i++) limiter.consume(`device-${i}`, `account-${i}`);
    const counts = limiter.bucketCounts;
    expect(counts.devices).toBeLessThanOrEqual(4);
    expect(counts.accounts).toBeLessThanOrEqual(4);
  });
});

describe("remote_gateway_rate_limit: concurrent socket caps", () => {
  it("proves 2 signaling sockets per device/attachment", () => {
    expect(REMOTE_GATEWAY_RATE.maxConcurrentSignalingSocketsPerDeviceAttachment).toBe(2);
  });

  it("proves 1 control socket per instance generation", () => {
    expect(REMOTE_GATEWAY_RATE.maxControlSocketsPerInstanceGeneration).toBe(1);
  });
});
