import fs from "node:fs";
import path from "node:path";
import { createEnv } from "@t3-oss/env-core";
import { config as loadEnv } from "dotenv";
import { z } from "zod";
import { originUrl } from "./url.js";

// ---------------------------------------------------------------------------
// Worker-safe environment.
//
// This module validates ONLY the variables that the BullMQ worker (and the
// packages it shares with the server: @flycockpit/db, @flycockpit/queue,
// @flycockpit/api/lib/storage, @flycockpit/i18n-translate, @flycockpit/mailer) actually
// read. It is the import target for every worker-reachable module.
//
// The server's full surface lives in ./server.ts, which `extends` this module
// and adds the server-only variables (Better-Auth, CORS, SSO, VAPID,
// rate limits, admin emails, image proxy, …). Importing `@flycockpit/env/server`
// from worker-graph code would force the worker to set BETTER_AUTH_URL,
// BETTER_AUTH_SECRET, etc. — variables the worker never uses. SMTP is included
// here because the worker can send operational-alert emails without needing
// Better-Auth URL/secret validation.
//
// dotenv loading and the strict-boolean helper live here (not in ./server.ts)
// so that exactly one module owns them regardless of which entrypoint loads
// first: ./server.ts imports this file, so this runs before server validation;
// the worker imports only this file.
// ---------------------------------------------------------------------------

export const strictBooleanFlag = (defaultValue: boolean = false) =>
  z
    .enum(["true", "false"])
    .default(defaultValue ? "true" : "false")
    .transform((value) => value === "true");

// Loaded once at module import. Path is resolved relative to this file, not CWD,
// so it works from any working directory and any build output location.
loadEnv({ path: path.resolve(import.meta.dirname, "../../../.env") });

// ---------------------------------------------------------------------------
// Warn if a stale per-app .env exists — the canonical location is repo root.
// ---------------------------------------------------------------------------
const staleEnvPath = path.resolve(import.meta.dirname, "../../../apps/server/.env");
if (fs.existsSync(staleEnvPath)) {
  console.warn(
    "[env] Found apps/server/.env — this file is no longer read. " +
      "The canonical .env location is the repository root. " +
      "Move its contents to the root .env and delete apps/server/.env to silence this warning.",
  );
}

export const env = createEnv({
  server: {
    DATABASE_URL: z.string().min(1),
    REDIS_URL: z.string().min(1),
    NODE_ENV: z.enum(["development", "production", "test"]).default("development"),
    // ---- Deployment profile. Worker-safe because both the server (routers,
    // entitlements) and the worker (enterprise-only queue handlers) gate the
    // commercially licensed packages/api/src/enterprise/ code on it.
    DEPLOYMENT_PROFILE: z.enum(["hosted", "enterprise", "oss"]).default("oss"),
    // ---- Asset hosting (optional). When S3_BUCKET is unset, the asset and
    // image endpoints return 503; the rest of the app boots fine. To enable,
    // configure all four required values below. Works with any S3-compatible
    // provider (AWS S3, Cloudflare R2, Backblaze B2, MinIO, DigitalOcean
    // Spaces, etc.) — set S3_ENDPOINT for non-AWS providers. The worker shares
    // this config to read raw uploads and write HLS segments / analyze assets.
    S3_BUCKET: z.string().optional(),
    S3_REGION: z.string().default("auto"),
    S3_ACCESS_KEY_ID: z.string().optional(),
    S3_SECRET_ACCESS_KEY: z.string().optional(),
    S3_ENDPOINT: z.url().optional(),
    // MinIO and some self-hosted providers require path-style URLs
    // (https://endpoint/bucket/key) instead of virtual-hosted-style
    // (https://bucket.endpoint/key). Default false works for AWS / R2.
    S3_FORCE_PATH_STYLE: strictBooleanFlag(),
    // ---- Translation provider (optional). Used by the BullMQ
    // `translate-content` worker to auto-translate Posts/Pages into target
    // locales. The validator keeps both API keys optional so the rest of the
    // app boots without them; the provider factory throws at first use if the
    // key for the chosen provider is missing.
    //
    // Default provider is `openrouter` because it's the cheapest path to
    // claude-haiku-4-5 + gives a single account multi-model access for A/B
    // experiments. Set TRANSLATION_PROVIDER=anthropic to call the Anthropic
    // API directly with ANTHROPIC_API_KEY.
    OPENROUTER_API_KEY: z.string().min(1).optional(),
    ANTHROPIC_API_KEY: z.string().min(1).optional(),
    TRANSLATION_PROVIDER: z.enum(["openrouter", "anthropic"]).default("openrouter"),
    // Optional public origin metadata for translation providers such as
    // OpenRouter. This is not used for auth and is safe for worker-only env.
    PUBLIC_APP_URL: originUrl("PUBLIC_APP_URL").optional(),
    // ---- Email transport (optional). Shared because both the server and the
    // worker use @flycockpit/mailer. Keeping SMTP here lets worker-only deploys
    // opt into failure-alert emails without setting Better-Auth server vars.
    SMTP_HOST: z.string().optional(),
    SMTP_PORT: z.coerce.number().int().positive().optional(),
    SMTP_USER: z.string().optional(),
    SMTP_PASS: z.string().optional(),
    SMTP_FROM: z.string().optional(),
    // Per-call model override. Falls through to the provider's default
    // (`anthropic/claude-haiku-4-5` for OpenRouter, `claude-haiku-4-5` for
    // direct Anthropic) when unset.
    TRANSLATION_MODEL: z.string().min(1).optional(),
    // ---- Video transcoding (optional). Inherits the S3 config above for
    // storage of raw uploads and HLS segments. Requires the worker (or a
    // worker-equivalent process) plus an ffmpeg binary on PATH.
    //
    // Path to the ffmpeg binary. Defaults to "ffmpeg" — works when the
    // executable is on PATH (true inside the worker container; install it
    // locally with `brew install ffmpeg` / `apt-get install ffmpeg`).
    VIDEO_FFMPEG_PATH: z.string().default("ffmpeg"),
    VIDEO_FFPROBE_PATH: z.string().default("ffprobe"),
    // Include the 2160p (4K) rung in the default ladder. When true, sources
    // ≥ 2160p tall pick up a 4K rendition; sources below 2160p are unaffected
    // (the worker never upscales). Per-video policy lives on
    // Video.ladderPolicy for the case where you want 4K for one specific
    // upload without globally enabling it.
    VIDEO_ENABLE_4K: strictBooleanFlag(),
    // Hard cap on a single raw video upload, in bytes. Default 10 GB — large
    // enough for typical 4K originals but smaller than the S3 5 TB ceiling
    // so a runaway upload doesn't bankrupt you.
    VIDEO_UPLOAD_MAX_BYTES: z.coerce
      .number()
      .int()
      .positive()
      .default(10 * 1024 * 1024 * 1024),
    // Worker concurrency for the transcode-video queue. CPU-bound: bump to 2
    // only on a worker host with enough cores to run two concurrent encodes
    // (8+ cores recommended). The transcode-audio-track queue inherits a
    // separate concurrency limit because audio encoding is much lighter.
    VIDEO_TRANSCODE_CONCURRENCY: z.coerce.number().int().positive().default(1),
    VIDEO_AUDIO_TRANSCODE_CONCURRENCY: z.coerce.number().int().positive().default(2),
    // Reject sources longer than this before encoding. Default 4 hours, which
    // covers long-form VOD while preventing tiny malicious uploads from
    // expanding into unbounded transcode work.
    VIDEO_TRANSCODE_MAX_DURATION_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(4 * 60 * 60),
    // ffmpeg process bounds. `-timelimit` caps CPU seconds; the worker also
    // applies a wall-clock timeout around every ffmpeg child process.
    VIDEO_FFMPEG_THREADS: z.coerce.number().int().positive().default(2),
    VIDEO_FFMPEG_TIMELIMIT_SECONDS: z.coerce
      .number()
      .int()
      .positive()
      .default(6 * 60 * 60),
    // CRF quality for libx264. Lower = higher quality / larger file. 23 is
    // the safe "imperceptible to most viewers" default. 18-22 for
    // higher-quality archives, 24-26 for stricter bandwidth budgets. The
    // worker pairs this with `preset slow` for ~5% better compression at
    // ~2× the encode time vs `medium`.
    VIDEO_X264_CRF: z.coerce.number().int().min(0).max(51).default(23),
    VIDEO_X264_PRESET: z
      .enum([
        "ultrafast",
        "superfast",
        "veryfast",
        "faster",
        "fast",
        "medium",
        "slow",
        "slower",
        "veryslow",
      ])
      .default("slow"),
  },
  runtimeEnv: process.env,
  emptyStringAsUndefined: true,
});

export const DEPLOYMENT_PROFILE = env.DEPLOYMENT_PROFILE;
export const S3_FORCE_PATH_STYLE: boolean = env.S3_FORCE_PATH_STYLE;
export const VIDEO_ENABLE_4K: boolean = env.VIDEO_ENABLE_4K;
