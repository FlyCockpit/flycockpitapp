import { createEnv } from "@t3-oss/env-core";
import { z } from "zod";
import {
  S3_FORCE_PATH_STYLE as SHARED_S3_FORCE_PATH_STYLE,
  VIDEO_ENABLE_4K as SHARED_VIDEO_ENABLE_4K,
  env as sharedEnv,
  strictBooleanFlag,
} from "./shared.js";
import { originUrl } from "./url.js";

// ---------------------------------------------------------------------------
// Full server environment.
//
// `extends: [sharedEnv]` merges in everything ./shared.ts already validated
// (database, redis, S3, video, translation) so server-side code keeps seeing a
// single `env` with every field. This module adds only the server-only
// variables and the startup guards that depend on them. The worker never
// imports this file, so a worker-only deployment is not required to set
// BETTER_AUTH_URL, BETTER_AUTH_SECRET, the rate-limit knobs, etc.
//
// Disjointness contract: no key declared here may also appear in
// ./shared.ts — `extends` merges, it does not allow overriding.
// ---------------------------------------------------------------------------

export const env = createEnv({
  extends: [sharedEnv],
  server: {
    // Optional process port override. Portless and production platforms inject
    // `PORT`; `SERVER_PORT` is only for raw local runs or container overrides.
    PORT: z.coerce.number().int().min(1).max(65_535).optional(),
    SERVER_PORT: z.coerce.number().int().min(1).max(65_535).optional(),
    BETTER_AUTH_SECRET: z.string().min(32),
    BETTER_AUTH_URL: originUrl("BETTER_AUTH_URL"),
    CORS_ORIGIN: originUrl("CORS_ORIGIN").optional(),
    SSO_ENABLED: strictBooleanFlag(),
    SSO_CLIENT_ID: z.string().optional(),
    SSO_CLIENT_SECRET: z.string().optional(),
    SSO_ISSUER: z.string().optional(),
    SSO_PROVIDER_NAME: z.string().default("SSO"),
    FORCE_SSO: strictBooleanFlag(),
    SIGNUP_ENABLED: strictBooleanFlag(),
    PRODUCT_NAME: z.string().min(1).max(80).default("Flycockpit"),
    ENTERPRISE_LICENSE_FILE: z.string().optional(),
    ENTERPRISE_LICENSE_PUBLIC_KEY: z.string().optional(),
    VAPID_PUBLIC_KEY: z.string().optional(),
    VAPID_PRIVATE_KEY: z.string().optional(),
    VAPID_SUBJECT: z.string().default("mailto:admin@example.com"),
    RATE_LIMIT_RPC_POINTS: z.coerce.number().int().positive().default(100),
    RATE_LIMIT_RPC_DURATION: z.coerce.number().int().positive().default(60),
    RATE_LIMIT_AUTH_POINTS: z.coerce.number().int().positive().default(10),
    RATE_LIMIT_AUTH_DURATION: z.coerce.number().int().positive().default(60),
    RATE_LIMIT_AUTH_BLOCK_DURATION: z.coerce.number().int().positive().default(900),
    RATE_LIMIT_SIGNUP_POINTS: z.coerce.number().int().positive().default(3),
    RATE_LIMIT_SIGNUP_DURATION: z.coerce.number().int().positive().default(3600),
    RATE_LIMIT_SIGNUP_BLOCK_DURATION: z.coerce.number().int().positive().default(3600),
    RATE_LIMIT_INSTANCE_INVITE_POINTS: z.coerce.number().int().positive().default(10),
    RATE_LIMIT_INSTANCE_INVITE_DURATION: z.coerce.number().int().positive().default(3600),
    RATE_LIMIT_INSTANCE_INVITE_BLOCK_DURATION: z.coerce.number().int().positive().default(3600),
    // Number of reverse-proxy hops in front of the app, for deriving the real
    // client IP used as the anonymous rate-limit key.
    //
    // Leave UNSET (the default) for zero-config behaviour that is correct for
    // every deploy target in our docs (Render, Railway, Dokploy/nginx, Azure
    // Container Apps): the app trusts the client IP that a proxy on a
    // private/loopback network forwarded, and otherwise (bare deployment, local
    // dev) keys on the real socket peer. See apps/server/src/client-ip.ts.
    //
    // Set this only when a proxy in front of the app has a PUBLIC IP (e.g.
    // Cloudflare, a public load balancer) or your topology is fixed: it is the
    // exact number of proxies between the client and the app. 0 disables
    // X-Forwarded-For entirely and always keys on the socket peer.
    TRUST_PROXY_HOPS: z.coerce.number().int().min(0).optional(),
    ADMIN_EMAILS: z.string().optional(),
    // Comma-separated allowlist of hostnames the image endpoint may proxy
    // (SSRF protection). Empty = the image endpoint refuses external URLs and
    // only serves transformations of stored Assets. Example:
    // IMAGE_PROXY_ALLOWED_HOSTS=cdn.example.com,images.partner.com
    IMAGE_PROXY_ALLOWED_HOSTS: z.string().default(""),
    IMAGE_PROXY_TIMEOUT_MS: z.coerce.number().int().positive().default(5000),
    IMAGE_PROXY_MAX_BYTES: z.coerce
      .number()
      .int()
      .positive()
      .default(10 * 1024 * 1024),
    IMAGE_TRANSFORM_MAX_INPUT_PIXELS: z.coerce.number().int().positive().default(50_000_000),
    // Hard cap on a single asset upload, in bytes. The Hono-level 10 MB body
    // limit still applies independently — set this lower if you want to reject
    // large uploads earlier with a clearer error.
    ASSET_UPLOAD_MAX_BYTES: z.coerce
      .number()
      .int()
      .positive()
      .default(10 * 1024 * 1024),
    COCKPIT_INSTANCE_LIMIT: z.coerce.number().int().positive().default(10),
    COCKPIT_INSTANCE_GRANTEE_LIMIT: z.coerce.number().int().positive().default(10),
    COCKPIT_RELAY_ID: z.string().trim().min(1).max(120).optional(),
    COCKPIT_RELAY_URL: z.string().url().optional(),
    RELAY_CONTROL_SECRET: z.string().min(32).optional(),
    RELAY_CA_PUBLIC_KEYS: z.string().optional(),
    RELAY_REVOKED_IDS: z.string().optional(),
  },
  runtimeEnv: process.env,
  emptyStringAsUndefined: true,
});

// ---------------------------------------------------------------------------
// Re-exported worker-safe derived constants. Server-side modules import these
// from `@flycockpit/env/server` (e.g. the videos router uses VIDEO_ENABLE_4K),
// so keep them available here even though their source of truth is ./shared.ts.
// ---------------------------------------------------------------------------
export const S3_FORCE_PATH_STYLE: boolean = SHARED_S3_FORCE_PATH_STYLE;
export const VIDEO_ENABLE_4K: boolean = SHARED_VIDEO_ENABLE_4K;

// ---------------------------------------------------------------------------
// Admin emails — parsed once at startup into a Set for O(1) lookups.
// ---------------------------------------------------------------------------
export const ADMIN_EMAILS: Set<string> = new Set(
  (env.ADMIN_EMAILS ?? "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean),
);

export const SSO_ENABLED: boolean = env.SSO_ENABLED;
export const FORCE_SSO: boolean = env.FORCE_SSO;
export const SIGNUP_ENABLED: boolean = env.SIGNUP_ENABLED;
export const DEPLOYMENT_PROFILE = env.DEPLOYMENT_PROFILE;

// ---------------------------------------------------------------------------
// BETTER_AUTH_SECRET entropy check — catch weak/placeholder secrets early.
// ---------------------------------------------------------------------------
const WEAK_PLACEHOLDERS = [
  "changeme",
  "secret",
  "password",
  "your-secret-here",
  "replace-me",
  "placeholder",
];

function isWeakSecret(secret: string): string | null {
  // All-same-character strings (e.g. "aaaaaaaaaa…")
  if (new Set(secret).size === 1) {
    return "all characters are identical";
  }
  // Repeating hex-like patterns (e.g. "xxxxxxxx…", "00000000…")
  if (/^(.)\1+$/.test(secret) || /^(..)\1+$/.test(secret)) {
    return "repeating pattern detected";
  }
  // Known placeholder words (case-insensitive)
  const lower = secret.toLowerCase();
  for (const placeholder of WEAK_PLACEHOLDERS) {
    if (lower === placeholder || lower.includes(placeholder)) {
      return `contains placeholder word "${placeholder}"`;
    }
  }
  // Fewer than 10 distinct characters → low entropy
  if (new Set(secret).size < 10) {
    return `only ${new Set(secret).size} distinct characters (need at least 10)`;
  }
  return null;
}

const weakReason = isWeakSecret(env.BETTER_AUTH_SECRET);
if (weakReason) {
  const msg =
    `[env] BETTER_AUTH_SECRET is weak: ${weakReason}. ` +
    "Generate a strong secret with: pnpm generate:secret";
  if (env.NODE_ENV === "production") {
    throw new Error(msg);
  }
  console.warn(msg);
}

if (ADMIN_EMAILS.size === 0 && env.NODE_ENV === "production") {
  console.warn(
    "[env] ADMIN_EMAILS is empty — no users will have admin privileges. " +
      "Set ADMIN_EMAILS in your environment to grant admin access.",
  );
}

if (FORCE_SSO && env.NODE_ENV === "production") {
  const missing: string[] = [];
  if (!SSO_ENABLED) missing.push("SSO_ENABLED=true");
  if (!env.SSO_CLIENT_ID) missing.push("SSO_CLIENT_ID");
  if (!env.SSO_CLIENT_SECRET) missing.push("SSO_CLIENT_SECRET");
  if (!env.SSO_ISSUER) missing.push("SSO_ISSUER");
  if (missing.length > 0) {
    throw new Error(
      `[env] FATAL: FORCE_SSO=true in production requires ${missing.join(", ")}. ` +
        "Fix the SSO deployment secrets or unset FORCE_SSO before redeploying.",
    );
  }
}
if (env.DEPLOYMENT_PROFILE === "enterprise") {
  const missing: string[] = [];
  if (!env.ENTERPRISE_LICENSE_FILE) missing.push("ENTERPRISE_LICENSE_FILE");
  if (!env.ENTERPRISE_LICENSE_PUBLIC_KEY) missing.push("ENTERPRISE_LICENSE_PUBLIC_KEY");
  if (missing.length > 0) {
    throw new Error(`[env] FATAL: DEPLOYMENT_PROFILE=enterprise requires ${missing.join(", ")}.`);
  }
}

if (SIGNUP_ENABLED && !env.SMTP_HOST) {
  const msg =
    "[env] SIGNUP_ENABLED=true but SMTP_HOST is not configured. " +
    "Better-Auth enforces email verification on signup, so the first user to " +
    "register will hit a runtime error when the verification email tries to send. " +
    "Set SMTP_HOST/SMTP_PORT/SMTP_FROM (and SMTP_USER/SMTP_PASS if your provider " +
    "requires auth), or set SIGNUP_ENABLED=false until SMTP is wired up.";
  if (env.NODE_ENV === "production") {
    throw new Error(msg);
  }
  console.warn(msg);
}
