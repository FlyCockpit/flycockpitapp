---
title: Environment Variables
description: All environment variables used by the starter app.
---

Environment variables are validated at startup using [`@t3-oss/env-core`](https://env.t3.gg/) with Zod schemas. The definitions live in `packages/env/src/`, split into three entry points:

- **`@flycockpit/env/shared`** (`src/shared.ts`) — the worker-safe subset. Validates only the variables the BullMQ worker and its shared packages (`@flycockpit/db`, `@flycockpit/queue`, `@flycockpit/api/lib/storage`, `@flycockpit/i18n-translate`, `@flycockpit/mailer`) actually read: `DATABASE_URL`, `REDIS_URL`, `NODE_ENV`, all `S3_*`, all `VIDEO_*`, optional `SMTP_*`, and the translation variables (`OPENROUTER_API_KEY` / `ANTHROPIC_API_KEY` / `TRANSLATION_PROVIDER` / `TRANSLATION_MODEL`).
- **`@flycockpit/env/server`** (`src/server.ts`) — `extends` the shared schema and adds the server-only variables (Better Auth, CORS, SSO, signup, VAPID, rate limits, `ADMIN_EMAILS`, the image-proxy / transform / asset-upload limits). Server-side code keeps importing a single merged `env`.
- **`@flycockpit/env/web`** (`src/web.ts`) — the client (`VITE_*`) variables.

A worker-only deployment imports only `@flycockpit/env/shared`, so it does **not** need to set the server-only variables (`BETTER_AUTH_URL`, `BETTER_AUTH_SECRET`, the rate-limit knobs, etc.). `SMTP_*` is shared and optional on the worker; set it there only if you want operational-alert email.

## Server (`.env` at repo root)

The variables below are validated by `@flycockpit/env/server`. Those marked **Worker-safe** are validated by `@flycockpit/env/shared` and are the only server variables a worker-only deployment must set; the rest are server-only.

| Variable | Required | Default | Worker-safe | Description |
|---|---|---|---|---|
| `DATABASE_URL` | Yes | — | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | — | Yes | Redis connection string (queues, rate limits) |
| `BETTER_AUTH_SECRET` | Yes (min 32 chars) | — | No | Secret key used by Better Auth |
| `BETTER_AUTH_URL` | Yes | — | No | Public app origin used by auth callbacks. Default local dev uses the portless web hostname, e.g. `https://flycockpit.localhost`. Do not include a path, query, hash, or credentials. |
| `CORS_ORIGIN` | No | — | No | Exact browser origin allowed to call the API directly. Do not include a path, query, hash, or credentials. |
| `SERVER_PORT` | No | `3000` | No | Raw local/container API listen override. Leave unset with portless. |
| `PORT` | No | — | No | Injected by portless and production platforms; used when `SERVER_PORT` is unset. |
| `NODE_ENV` | No | `development` | Yes | `development`, `production`, or `test` |

### SSO (optional)

| Variable | Required | Default | Description |
|---|---|---|---|
| `SSO_ENABLED` | No | `false` | Enable SSO authentication |
| `SSO_CLIENT_ID` | No | — | OAuth client ID for your SSO provider |
| `SSO_CLIENT_SECRET` | No | — | OAuth client secret |
| `SSO_ISSUER` | No | — | SSO issuer URL (e.g. `https://your-org.okta.com`) |
| `SSO_PROVIDER_NAME` | No | `SSO` | Display name shown on the login button |
| `FORCE_SSO` | No | `false` | When `true`, only SSO login is available |

### Push notifications (optional)

| Variable | Required | Default | Description |
|---|---|---|---|
| `VAPID_PUBLIC_KEY` | No | — | VAPID public key for web push |
| `VAPID_PRIVATE_KEY` | No | — | VAPID private key for web push |
| `VAPID_SUBJECT` | No | `mailto:admin@example.com` | VAPID subject identifier (should be a `mailto:` or `https:` URL) |

#### Generating VAPID keys

VAPID (Voluntary Application Server Identification) keys are required for sending web push notifications. Generate a key pair using the `web-push` CLI that is already installed as a dependency:

```bash
npx web-push generate-vapid-keys
```

This outputs a public key and a private key. Add them to your environment files:

1. In your root `.env`, set both `VAPID_PUBLIC_KEY` and `VAPID_PRIVATE_KEY`.
2. In `apps/web/.env`, set `VITE_VAPID_PUBLIC_KEY` to the same public key.

The public key must match between server and web so that push subscriptions created in the browser can be validated by the server.

## Web (`apps/web/.env`)

| Variable | Required | Default | Description |
|---|---|---|---|
| `VITE_SERVER_URL` | No | `window.location.origin` | Server API origin. Leave unset for same-origin deployments and the default portless/Vite proxy flow; set it only when the browser should call a separate API origin directly. Do not include a path, query, hash, or credentials. |
| `VITE_DEV_PORT` | No | `3001` | Raw Vite dev-server listen port. Leave unset with portless. |
| `VITE_DEV_SERVER_URL` | No | `http://localhost:3000` or the `apps/server` hostname from `portless.json` under portless | API origin for the Vite dev proxy. Do not include a path, query, hash, or credentials. |
| `VITE_VAPID_PUBLIC_KEY` | No | — | VAPID public key (must match the server's `VAPID_PUBLIC_KEY`) |
| `VITE_APP_NAME` | No | `App` | App-shell name used in the header, document title, PWA manifest, and admin MCP snippet. |
