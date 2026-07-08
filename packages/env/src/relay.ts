import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createEnv } from "@t3-oss/env-core";
import { config as loadEnv } from "dotenv";
import { z } from "zod";
import { originUrl } from "./url.js";

loadEnv({ path: path.resolve(import.meta.dirname, "../../../.env") });

const staleEnvPath = path.resolve(import.meta.dirname, "../../../apps/relay/.env");
if (fs.existsSync(staleEnvPath)) {
  console.warn(
    "[env] Found apps/relay/.env — this file is not read. " +
      "The canonical .env location is the repository root.",
  );
}

export const env = createEnv({
  server: {
    NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
    PORT: z.coerce.number().int().min(1).max(65_535).optional(),
    RELAY_PORT: z.coerce.number().int().min(1).max(65_535).optional(),
    RELAY_ID: z.string().trim().min(1).max(120).optional(),
    BETTER_AUTH_URL: originUrl("BETTER_AUTH_URL").optional(),
    RELAY_TOKEN_ISSUER: originUrl("RELAY_TOKEN_ISSUER").optional(),
    RELAY_JWKS_URL: z.url().optional(),
    RELAY_CONTROL_INGEST_URL: z.url().optional(),
    RELAY_CONTROL_SECRET: z.string().min(32).optional(),
    REDIS_URL: z.string().min(1).optional(),
    RELAY_HEARTBEAT_MS: z.coerce.number().int().positive().default(10_000),
    RELAY_LEASE_TTL_MS: z.coerce.number().int().positive().default(30_000),
    RELAY_MAX_FRAME_BYTES: z.coerce
      .number()
      .int()
      .positive()
      .default(8 * 1024 * 1024),
    RELAY_MAX_CHANNELS_PER_CLIENT: z.coerce.number().int().positive().default(16),
    RELAY_MAX_CONNECTIONS_PER_INSTANCE: z.coerce.number().int().positive().default(1),
    RELAY_CLIENT_RATE_LIMIT_PER_SECOND: z.coerce.number().int().positive().default(60),
    RELAY_SHUTDOWN_GRACE_MS: z.coerce.number().int().positive().default(10_000),
  },
  runtimeEnv: process.env,
  emptyStringAsUndefined: true,
});

export const RELAY_ID = env.RELAY_ID ?? os.hostname() + "-" + process.pid;
export const RELAY_PORT = env.RELAY_PORT ?? env.PORT ?? 3010;
function requiredRelayIssuer(): string {
  const issuer = env.RELAY_TOKEN_ISSUER ?? env.BETTER_AUTH_URL;
  if (!issuer) {
    throw new Error("[env] RELAY_TOKEN_ISSUER or BETTER_AUTH_URL is required for the relay.");
  }
  return issuer;
}

export const RELAY_TOKEN_ISSUER: string = requiredRelayIssuer();

export const RELAY_JWKS_URL =
  env.RELAY_JWKS_URL ?? new URL("/api/relay/jwks.json", RELAY_TOKEN_ISSUER).toString();
