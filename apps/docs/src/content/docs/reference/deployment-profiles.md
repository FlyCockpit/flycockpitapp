---
title: Deployment Profiles and Entitlements
---

Flycockpit uses one codebase with three runtime profiles selected by `DEPLOYMENT_PROFILE`:

| Profile | Intended use | Native app | Owned hosted connections |
| --- | --- | --- | --- |
| `oss` | Open-source self-hosts | Not eligible; use the PWA | Enabled by default |
| `hosted` | Flycockpit public hosted service | Requires the user entitlement | Requires Pro or an active trial |
| `enterprise` | Licensed self-hosted enterprise deployments | Requires a valid enterprise license | Requires a valid enterprise license |

The public descriptor is available at `/api/meta/profile` and returns `profile`, `productName`, `version`, `nativeAppEligible`, and non-secret enterprise-license status when present. Authenticated clients should also call the entitlements API before enabling paid or licensed features; UI checks are advisory and server procedures remain authoritative.

## Self-host bootstrap

1. Generate secrets:

   ```sh
   openssl rand -hex 32
   pnpm generate:vapid
   ```

2. Create a local `.env` for compose with at least:

   ```env
   POSTGRES_PASSWORD=replace-me
   BETTER_AUTH_SECRET=replace-with-openssl-output
   BETTER_AUTH_URL=http://localhost:3000
   ADMIN_EMAILS=you@example.com
   SIGNUP_ENABLED=false
   ```

3. Start the stack:

   ```sh
   docker compose -f docker-compose.selfhost.yml up -d
   ```

4. After the first successful boot, set `APPLY_SCHEMA=off` for steady-state restarts. Set it back to `safe` only for schema-changing upgrades.

SMTP is optional for local evaluation but required for production email verification. VAPID keys are optional until web push is enabled.

## Enterprise license files

Enterprise deployments set `DEPLOYMENT_PROFILE=enterprise`, `ENTERPRISE_LICENSE_FILE`, and `ENTERPRISE_LICENSE_PUBLIC_KEY`. The license file is signed JSON with org, expiry, and entitlement flags. Invalid or expired licenses degrade enterprise-only capabilities without locking data.
