import type { Session } from "@flycockpit/auth";
import { env } from "@flycockpit/env/server";
import { redisConnection } from "@flycockpit/queue";
import type { Context, Next } from "hono";
import { RateLimiterMemory, RateLimiterRedis, RateLimiterRes } from "rate-limiter-flexible";
import { resolveClientIp } from "./client-ip.js";

type RateLimiter = Pick<RateLimiterRedis, "consume" | "points">;

// ---------------------------------------------------------------------------
// Rate limiters backed by Redis with in-memory insurance
// ---------------------------------------------------------------------------
// Algorithm: "enhanced fixed window" (rate-limiter-flexible's default).
// This is NOT a true sliding window — it counts hits per fixed-duration bucket
// with partial-overlap weighting. Good enough for abuse prevention; don't
// replace it thinking the name is wrong.
//
// Fail mode: **fail-open**. If Redis is unreachable the middleware lets the
// request through rather than returning 503. The in-memory insurance limiter
// still enforces a generous ceiling so the app stays up (with slightly relaxed
// limits) during a Redis blip.
// ---------------------------------------------------------------------------

/**
 * Auth limiter — strict, applied to /api/auth/* to defend against
 * credential-stuffing and account-enumeration attacks.
 *
 * 10 requests / 60 s per key. Offenders are blocked for 15 minutes.
 */
export const authLimiter = new RateLimiterRedis({
  storeClient: redisConnection,
  keyPrefix: "rl:auth",
  points: env.RATE_LIMIT_AUTH_POINTS,
  duration: env.RATE_LIMIT_AUTH_DURATION,
  blockDuration: env.RATE_LIMIT_AUTH_BLOCK_DURATION,
  inMemoryBlockOnConsumed: env.RATE_LIMIT_AUTH_POINTS + 1, // block in-process once 1 over limit
  inMemoryBlockDuration: env.RATE_LIMIT_AUTH_BLOCK_DURATION,
  insuranceLimiter: new RateLimiterMemory({
    keyPrefix: "rl:auth:ins",
    points: Math.ceil(env.RATE_LIMIT_AUTH_POINTS * 1.5), // slightly more generous while Redis is down
    duration: env.RATE_LIMIT_AUTH_DURATION,
    blockDuration: env.RATE_LIMIT_AUTH_BLOCK_DURATION,
  }),
});

/**
 * Signup limiter — very strict, applied to /api/auth/sign-up/* to prevent
 * account-creation spam. 3 requests / 3600 s per key with a 1-hour block.
 *
 * Must be mounted BEFORE the general authLimiter so signup traffic hits this
 * tighter limit first; the authLimiter still applies as a second layer.
 */
export const signupLimiter = new RateLimiterRedis({
  storeClient: redisConnection,
  keyPrefix: "rl:signup",
  points: env.RATE_LIMIT_SIGNUP_POINTS,
  duration: env.RATE_LIMIT_SIGNUP_DURATION,
  blockDuration: env.RATE_LIMIT_SIGNUP_BLOCK_DURATION,
  inMemoryBlockOnConsumed: env.RATE_LIMIT_SIGNUP_POINTS + 1,
  inMemoryBlockDuration: env.RATE_LIMIT_SIGNUP_BLOCK_DURATION,
  insuranceLimiter: new RateLimiterMemory({
    keyPrefix: "rl:signup:ins",
    points: Math.ceil(env.RATE_LIMIT_SIGNUP_POINTS * 1.5),
    duration: env.RATE_LIMIT_SIGNUP_DURATION,
    blockDuration: env.RATE_LIMIT_SIGNUP_BLOCK_DURATION,
  }),
});

/**
 * RPC limiter — general, applied to /rpc/* for normal API traffic.
 *
 * 100 requests / 60 s per key.
 */
export const rpcLimiter = new RateLimiterRedis({
  storeClient: redisConnection,
  keyPrefix: "rl:rpc",
  points: env.RATE_LIMIT_RPC_POINTS,
  duration: env.RATE_LIMIT_RPC_DURATION,
  inMemoryBlockOnConsumed: env.RATE_LIMIT_RPC_POINTS + 1,
  inMemoryBlockDuration: env.RATE_LIMIT_RPC_DURATION,
  insuranceLimiter: new RateLimiterMemory({
    keyPrefix: "rl:rpc:ins",
    points: Math.ceil(env.RATE_LIMIT_RPC_POINTS * 1.5),
    duration: env.RATE_LIMIT_RPC_DURATION,
  }),
});

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/**
 * Resolve the rate-limit key for a request.
 *
 * Priority:
 * 1. Authenticated user → session.user.id (so limits follow the account, not the IP)
 * 2. Anonymous → the real client IP (`resolveClientIp`, proxy-aware) → "unknown"
 *
 * The session is resolved once per request by `sessionMiddleware` and read
 * here from the Hono context. Routes that don't mount `sessionMiddleware`
 * (or the rate-limit unit test) leave `c.get("session")` undefined; we fall
 * through to IP keying in that case.
 */
function resolveKey(c: Context): string {
  const existing = c.get("session") as Session | null | undefined;
  if (existing?.user?.id) {
    return `uid:${existing.user.id}`;
  }

  return resolveClientIp(c);
}

function setRateLimitHeaders(c: Context, limiter: RateLimiter, res: RateLimiterRes) {
  const limit = limiter.points;
  const remaining = Math.max(0, res.remainingPoints);
  // msBeforeNext is ms until the current window resets
  const resetEpochSeconds = Math.ceil((Date.now() + res.msBeforeNext) / 1000);

  c.header("X-RateLimit-Limit", String(limit));
  c.header("X-RateLimit-Remaining", String(remaining));
  c.header("X-RateLimit-Reset", String(resetEpochSeconds));
}

/**
 * Create a Hono middleware that enforces a `rate-limiter-flexible` limiter.
 *
 * On rejection → 429 JSON with rate-limit + Retry-After headers.
 * On Redis outage → request passes through (fail-open); the insurance
 * in-memory limiter still provides a safety net.
 */
export function createRateLimiterMiddleware(limiter: RateLimiter) {
  return async (c: Context, next: Next) => {
    const key = resolveKey(c);

    try {
      const res = await limiter.consume(key);
      setRateLimitHeaders(c, limiter, res);
      await next();
    } catch (rlResult: unknown) {
      if (rlResult instanceof RateLimiterRes) {
        // Rate limit exceeded — reject with 429
        setRateLimitHeaders(c, limiter, rlResult);
        const retryAfter = Math.ceil(rlResult.msBeforeNext / 1000);
        c.header("Retry-After", String(retryAfter));
        return c.json({ error: "Too many attempts. Please wait a moment and try again." }, 429);
      }

      // Any other error (Redis connectivity, unexpected throw) → fail-open.
      // Log and let the request through so a Redis blip doesn't take down
      // the entire API.
      console.error("[rate-limit] Redis error, failing open:", rlResult);
      await next();
    }
  };
}
