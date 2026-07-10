import { ingestRemoteInstanceAuditEvents } from "@flycockpit/api/lib/instance-sharing";
import {
  ingestAttentionNotification,
  parseRelayAttentionIngest,
  recordUserPresenceHeartbeat,
} from "@flycockpit/api/lib/notifications";
import { getMissingRelayControlConfigKeys } from "@flycockpit/api/lib/relay-config";
import {
  RelayControlNotConfiguredError,
  RelayCredentialUnauthorizedError,
  type RelayIdentity,
  verifyRelayCredential,
} from "@flycockpit/api/lib/relay-credentials";
import { env } from "@flycockpit/env/server";
import { ORPCError } from "@orpc/server";
import type { Env, Hono, MiddlewareHandler } from "hono";

type Logger = Pick<typeof console, "warn">;

type RelayRouteOptions<E extends Env> = {
  rateLimiter?: MiddlewareHandler<E>;
  logger?: Logger;
};

function orpcErrorResponse(err: { status: number; code: string; message: string }) {
  const status = err.status >= 400 && err.status <= 599 ? err.status : 400;
  return { body: { error: err.code, message: err.message }, status };
}

export function mountRelayRoutes<E extends Env>(app: Hono<E>, options: RelayRouteOptions<E> = {}) {
  const logger = options.logger ?? console;
  if (options.rateLimiter) app.use("/api/relay/*", options.rateLimiter);

  const missing = getMissingRelayControlConfigKeys();
  if (missing.length > 0) {
    logger.warn(
      `[server] Relay control ingest is disabled; missing ${missing.join(", ")}. ` +
        "Set RELAY_CONTROL_SECRET and COCKPIT_RELAY_URL to accept relay events.",
    );
  }

  app.post("/api/relay/register", async (c) => {
    if (env.DEPLOYMENT_PROFILE === "oss") return c.json({ error: "not_found" }, 404);

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "bad_json" }, 400);
    }

    try {
      const { registerRelay } = await import("@flycockpit/api/enterprise/relay-fleet");
      return c.json(await registerRelay(body));
    } catch (err) {
      if (err instanceof ORPCError && err.code === "UNAUTHORIZED") {
        return c.json({ error: "unauthorized" }, 401);
      }
      if (err instanceof ORPCError) {
        const response = orpcErrorResponse(err);
        return c.json(response.body, response.status as 400);
      }
      return c.json({ error: "bad_request" }, 400);
    }
  });

  app.post("/api/relay/heartbeat", async (c) => {
    if (env.DEPLOYMENT_PROFILE === "oss") return c.json({ error: "not_found" }, 404);

    let identity: RelayIdentity;
    try {
      identity = await verifyRelayCredential(c.req.raw);
      if (identity.mode !== "fleet") return c.json({ error: "unauthorized" }, 401);
    } catch (err) {
      if (
        err instanceof RelayControlNotConfiguredError ||
        err instanceof RelayCredentialUnauthorizedError
      ) {
        return c.json({ error: "unauthorized" }, 401);
      }
      throw err;
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "bad_json" }, 400);
    }

    try {
      const { recordRelayHeartbeat } = await import("@flycockpit/api/enterprise/relay-fleet");
      return c.json(await recordRelayHeartbeat(identity, body));
    } catch (err) {
      if (err instanceof ORPCError && err.code === "UNAUTHORIZED") {
        return c.json({ error: "unauthorized" }, 401);
      }
      if (err instanceof ORPCError) {
        const response = orpcErrorResponse(err);
        return c.json(response.body, response.status as 400);
      }
      return c.json({ error: "bad_request" }, 400);
    }
  });

  app.post("/api/relay/control-ingest", async (c) => {
    try {
      await verifyRelayCredential(c.req.raw);
    } catch (err) {
      if (err instanceof RelayControlNotConfiguredError) {
        return c.json({ error: "relay_control_not_configured" }, 503);
      }
      if (err instanceof RelayCredentialUnauthorizedError) {
        return c.json({ error: "unauthorized" }, 401);
      }
      throw err;
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "bad_json" }, 400);
    }

    try {
      const parsed = parseRelayAttentionIngest(body);
      if (parsed.kind === "presence") {
        await recordUserPresenceHeartbeat({
          userId: parsed.userId,
          clientId: parsed.payload.clientId,
          visible: parsed.payload.visible,
        });
        return c.json({ ok: true });
      }

      const result = await ingestAttentionNotification({
        instanceId: parsed.instanceId,
        payload: parsed.payload,
      });
      return c.json({ ok: true, result });
    } catch (err) {
      if (err instanceof ORPCError) {
        const response = orpcErrorResponse(err);
        return c.json(response.body, response.status as 400);
      }
      return c.json({ error: "bad_request" }, 400);
    }
  });

  app.post("/api/relay/audit-ingest", async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "bad_json" }, 400);
    }

    try {
      const result = await ingestRemoteInstanceAuditEvents(body);
      return c.json({ ok: true, result });
    } catch (err) {
      if (err instanceof ORPCError) {
        const response = orpcErrorResponse(err);
        return c.json(response.body, response.status as 400);
      }
      return c.json({ error: "bad_request" }, 400);
    }
  });
}
