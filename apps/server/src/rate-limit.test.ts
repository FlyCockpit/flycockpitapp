import { Hono } from "hono";
import { RateLimiterMemory } from "rate-limiter-flexible";
import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Mock heavy dependencies so the module loads without Redis / env / auth.
// ---------------------------------------------------------------------------

vi.mock("@flycockpit/auth", () => ({
  auth: {
    api: {
      getSession: vi.fn().mockResolvedValue(null),
    },
  },
}));

vi.mock("@flycockpit/env/server", () => ({
  env: {
    RATE_LIMIT_AUTH_POINTS: 3,
    RATE_LIMIT_AUTH_DURATION: 60,
    RATE_LIMIT_AUTH_BLOCK_DURATION: 120,
    RATE_LIMIT_SIGNUP_POINTS: 3,
    RATE_LIMIT_SIGNUP_DURATION: 3600,
    RATE_LIMIT_SIGNUP_BLOCK_DURATION: 3600,
    RATE_LIMIT_RPC_POINTS: 5,
    RATE_LIMIT_RPC_DURATION: 60,
    RATE_LIMIT_INSTANCE_INVITE_POINTS: 2,
    RATE_LIMIT_INSTANCE_INVITE_DURATION: 3600,
    RATE_LIMIT_INSTANCE_INVITE_BLOCK_DURATION: 3600,
    TRUST_PROXY_HOPS: undefined,
  },
}));

vi.mock("@flycockpit/queue", () => ({
  redisConnection: {},
}));

const mockGetConnInfo = vi.fn(() => ({ remote: { address: "10.0.0.1" } }));

vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: mockGetConnInfo,
}));

// Mock RateLimiterRedis so module-level `authLimiter` and `rpcLimiter`
// instantiate without a real Redis connection. We don't test those instances
// directly — we test `createRateLimiterMiddleware` with a RateLimiterMemory.
vi.mock("rate-limiter-flexible", async (importOriginal) => {
  const original = await importOriginal<typeof import("rate-limiter-flexible")>();
  return {
    ...original,
    // Replace RateLimiterRedis with RateLimiterMemory so module-level
    // constructors don't need a live Redis client.
    RateLimiterRedis: original.RateLimiterMemory,
  };
});

const { createInstanceInviteRateLimiterMiddleware, createRateLimiterMiddleware } = await import(
  "./rate-limit.js"
);

// ---------------------------------------------------------------------------
// Test: rate limiter middleware returns 429 with correct headers
// ---------------------------------------------------------------------------
// Trade-off: We use RateLimiterMemory instead of a real Redis-backed limiter.
// This means the test does NOT verify Redis round-trips, but it does exercise
// the full Hono middleware path including header serialisation, 429 body, and
// the consume → reject flow. For a true integration test against Redis, spin
// up a test container and replace RateLimiterMemory with RateLimiterRedis.
// ---------------------------------------------------------------------------

const LIMIT = 3;

describe("createRateLimiterMiddleware", () => {
  let app: Hono;

  beforeEach(() => {
    mockGetConnInfo.mockReturnValue({ remote: { address: "10.0.0.1" } });

    // Fresh limiter + app per test so counters reset.
    const limiter = new RateLimiterMemory({
      keyPrefix: "test",
      points: LIMIT,
      duration: 60,
    });

    app = new Hono();
    app.use("/*", createRateLimiterMiddleware(limiter));
    app.get("/ping", (c) => c.text("pong"));
  });

  it("allows requests within the limit and returns rate-limit headers", async () => {
    const res = await app.request("/ping");

    expect(res.status).toBe(200);
    expect(res.headers.get("X-RateLimit-Limit")).toBe(String(LIMIT));
    expect(res.headers.get("X-RateLimit-Remaining")).toBeTruthy();
    expect(res.headers.get("X-RateLimit-Reset")).toBeTruthy();
  });

  it("returns 429 with all rate-limit headers on the (limit + 1)th request", async () => {
    mockGetConnInfo.mockReturnValue({ remote: { address: "10.0.0.2" } });

    // Exhaust the allowance
    for (let i = 0; i < LIMIT; i++) {
      const res = await app.request("/ping");
      expect(res.status).toBe(200);
    }

    // The next request should be rejected
    const rejected = await app.request("/ping");

    expect(rejected.status).toBe(429);

    // Verify all four rate-limit headers are present and non-empty
    expect(rejected.headers.get("X-RateLimit-Limit")).toBe(String(LIMIT));
    expect(rejected.headers.get("X-RateLimit-Remaining")).toBe("0");
    expect(rejected.headers.get("X-RateLimit-Reset")).toBeTruthy();
    expect(rejected.headers.get("Retry-After")).toBeTruthy();

    // Verify numeric values are sensible
    const reset = Number(rejected.headers.get("X-RateLimit-Reset"));
    expect(reset).toBeGreaterThan(0);

    const retryAfter = Number(rejected.headers.get("Retry-After"));
    expect(retryAfter).toBeGreaterThan(0);

    // Verify response body
    const body = await rejected.json();
    expect(body).toEqual({ error: "Too many attempts. Please wait a moment and try again." });
  });

  it("tracks limits per IP independently", async () => {
    // Exhaust allowance for IP A
    mockGetConnInfo.mockReturnValue({ remote: { address: "10.0.0.3" } });
    for (let i = 0; i < LIMIT; i++) {
      await app.request("/ping");
    }

    // IP A is blocked
    const blockedA = await app.request("/ping");
    expect(blockedA.status).toBe(429);

    // IP B still has its full allowance
    mockGetConnInfo.mockReturnValue({ remote: { address: "10.0.0.4" } });
    const allowedB = await app.request("/ping");
    expect(allowedB.status).toBe(200);
  });

  it("behind a private-network proxy, keys on the proxy-appended client IP — not the spoofable leftmost X-Forwarded-For", async () => {
    // Socket peer is the proxy (private). A trusted proxy appends the real
    // client IP as the rightmost entry; the client controls only the left.
    mockGetConnInfo.mockReturnValue({ remote: { address: "10.0.0.5" } });

    for (let i = 0; i < LIMIT; i++) {
      const res = await app.request("/ping", {
        // Vary the spoofed leftmost entry every request; the proxy-appended
        // real client (198.51.100.7) stays constant.
        headers: { "x-forwarded-for": `203.0.113.${i}, 198.51.100.7` },
      });
      expect(res.status).toBe(200);
    }

    const rejected = await app.request("/ping", {
      headers: { "x-forwarded-for": "203.0.113.99, 198.51.100.7" },
    });
    // Throttled despite a fresh spoofed leftmost value: the key is the constant
    // proxy-appended client IP, so X-Forwarded-For spoofing can't escape it.
    expect(rejected.status).toBe(429);
  });

  it("on a bare deployment (public socket peer), ignores X-Forwarded-For entirely", async () => {
    // No proxy: the socket peer is the real, public client. A forged
    // X-Forwarded-For must not let it dodge the limit.
    mockGetConnInfo.mockReturnValue({ remote: { address: "198.51.100.50" } });

    for (let i = 0; i < LIMIT; i++) {
      const res = await app.request("/ping", {
        headers: { "x-forwarded-for": `203.0.113.${i}` },
      });
      expect(res.status).toBe(200);
    }

    const rejected = await app.request("/ping", {
      headers: { "x-forwarded-for": "203.0.113.99" },
    });
    expect(rejected.status).toBe(429);
  });
});

describe("createInstanceInviteRateLimiterMiddleware", () => {
  it("limits instance invites by owner and target email", async () => {
    const ownerLimiter = new RateLimiterMemory({
      keyPrefix: "invite-owner",
      points: 1,
      duration: 60,
    });
    const targetLimiter = new RateLimiterMemory({
      keyPrefix: "invite-target",
      points: 1,
      duration: 60,
    });
    const app = new Hono<{ Variables: { session: { user: { id: string } } } }>();
    app.use("/*", async (c, next) => {
      c.set("session", { user: { id: c.req.header("x-user") ?? "owner-1" } });
      await next();
    });
    app.use("/rpc/*", createInstanceInviteRateLimiterMiddleware({ ownerLimiter, targetLimiter }));
    app.post("/rpc/instanceSharing/invite", (c) => c.text("ok"));

    const first = await app.request("/rpc/instanceSharing/invite", {
      method: "POST",
      headers: { "content-type": "application/json", "x-user": "owner-1" },
      body: JSON.stringify({ email: "Target@Example.Test" }),
    });
    expect(first.status).toBe(200);

    const sameOwner = await app.request("/rpc/instanceSharing/invite", {
      method: "POST",
      headers: { "content-type": "application/json", "x-user": "owner-1" },
      body: JSON.stringify({ email: "other@example.test" }),
    });
    expect(sameOwner.status).toBe(429);

    const sameTarget = await app.request("/rpc/instanceSharing/invite", {
      method: "POST",
      headers: { "content-type": "application/json", "x-user": "owner-2" },
      body: JSON.stringify({ email: "target@example.test" }),
    });
    expect(sameTarget.status).toBe(429);
  });
});
