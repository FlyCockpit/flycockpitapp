import type { MiddlewareHandler } from "hono";
import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  ingestAttentionNotification: vi.fn(),
  ingestRemoteInstanceAuditEvents: vi.fn(),
  recordUserPresenceHeartbeat: vi.fn(),
}));

vi.mock("@flycockpit/env/server", () => ({
  env: {
    BETTER_AUTH_URL: "https://app.example.test",
    COCKPIT_RELAY_URL: undefined,
    RELAY_CONTROL_SECRET: undefined,
  },
}));

vi.mock("@flycockpit/api/lib/notifications", () => ({
  ingestAttentionNotification: mocks.ingestAttentionNotification,
  recordUserPresenceHeartbeat: mocks.recordUserPresenceHeartbeat,
  parseRelayAttentionIngest: (body: {
    event?: string;
    userId?: string;
    instanceId?: string;
    payload: { clientId: string; visible: boolean } | unknown;
  }) => {
    if (body.event === "user_presence") {
      return { kind: "presence", userId: body.userId, payload: body.payload };
    }
    return { kind: "attention", instanceId: body.instanceId, payload: body.payload };
  },
}));

vi.mock("@flycockpit/api/lib/instance-sharing", () => ({
  ingestRemoteInstanceAuditEvents: mocks.ingestRemoteInstanceAuditEvents,
}));

const { resetRelayControlConfig, setRelayControlConfig } = await import(
  "@flycockpit/api/lib/relay-config"
);
const { mountRelayRoutes } = await import("./relay-routes");

const secret = "relay-secret-relay-secret-relay-123";

function jsonRequest(headers: Record<string, string> = {}) {
  return {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({
      relayId: "relay-test",
      event: "user_presence",
      userId: "user-1",
      payload: { clientId: "client-1", visible: true },
    }),
  };
}

function budgetLimiter(points: number): MiddlewareHandler {
  let count = 0;
  return async (c, next) => {
    count += 1;
    if (count > points) return c.json({ error: "limited" }, 429);
    await next();
  };
}

function buildApp(options: { configured?: boolean; rateLimiter?: MiddlewareHandler } = {}) {
  if (options.configured ?? true) {
    setRelayControlConfig({
      relayId: "relay-test",
      controlSecret: secret,
      controlUrl: "https://relay.example.test/control",
    });
  } else {
    setRelayControlConfig(null);
  }

  const app = new Hono();
  const warn = vi.fn();
  mountRelayRoutes(app, { rateLimiter: options.rateLimiter, logger: { warn } });
  return { app, warn };
}

describe("relay routes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetRelayControlConfig();
    mocks.ingestAttentionNotification.mockResolvedValue({ eventId: "evt-1", recipients: [] });
    mocks.recordUserPresenceHeartbeat.mockResolvedValue({ present: true });
  });

  it("rejects missing and wrong relay credentials before ingest side effects", async () => {
    const { app } = buildApp();

    const missing = await app.request("/api/relay/control-ingest", jsonRequest());
    expect(missing.status).toBe(401);
    expect(await missing.json()).toEqual({ error: "unauthorized" });

    const wrong = await app.request(
      "/api/relay/control-ingest",
      jsonRequest({ authorization: "Bearer wrong" }),
    );
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toEqual({ error: "unauthorized" });

    expect(mocks.recordUserPresenceHeartbeat).not.toHaveBeenCalled();
    expect(mocks.ingestAttentionNotification).not.toHaveBeenCalled();
  });

  it("records a presence heartbeat with the correct relay credential", async () => {
    const { app } = buildApp();

    const res = await app.request(
      "/api/relay/control-ingest",
      jsonRequest({ authorization: `Bearer ${secret}` }),
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(mocks.recordUserPresenceHeartbeat).toHaveBeenCalledWith({
      userId: "user-1",
      clientId: "client-1",
      visible: true,
    });
  });

  it("returns 503 and emits one boot warning when relay control is not configured", async () => {
    const { app, warn } = buildApp({ configured: false });

    const first = await app.request("/api/relay/control-ingest", jsonRequest());
    const second = await app.request("/api/relay/control-ingest", jsonRequest());

    expect(first.status).toBe(503);
    expect(await first.json()).toEqual({ error: "relay_control_not_configured" });
    expect(second.status).toBe(503);
    expect(warn).toHaveBeenCalledOnce();
    expect(String(warn.mock.calls[0]?.[0])).toContain("RELAY_CONTROL_SECRET");
  });

  it("runs the /api/relay/* rate limiter before control-ingest auth", async () => {
    const { app } = buildApp({ rateLimiter: budgetLimiter(1) });

    const allowed = await app.request("/api/relay/control-ingest", jsonRequest());
    expect(allowed.status).toBe(401);

    const limited = await app.request("/api/relay/control-ingest", jsonRequest());
    expect(limited.status).toBe(429);
  });
});
