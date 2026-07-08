# Sitemap

All app routes are prefixed with a locale segment: `/{lang}/...`. Supported locales are defined in `packages/config/src/locales.ts`.

## Public Routes

| Route | Purpose |
| --- | --- |
| `/{lang}` | Flycockpit home page. |
| `/{lang}/about` | Product and operations overview. |
| `/{lang}/cookie-policy` | Cookie policy and consent preferences entrypoint. |
| `/{lang}/sign-in` | Sign in. |
| `/{lang}/sign-up` | Sign up when enabled. |
| `/{lang}/reset-password` | Password reset request. |
| `/{lang}/reset-password/$token` | Password reset completion. |
| `/{lang}/verify-email` | Email verification status. |
| `/{lang}/devices/approve` | Device approval. |
| `/{lang}/videos/$videoId` | Public video watch route with authorization checks for restricted videos. |

## Authenticated Routes

| Route | Purpose |
| --- | --- |
| `/{lang}/dashboard` | Signed-in user dashboard. |
| `/{lang}/settings` | Account settings. |
| `/{lang}/settings/profile` | Profile settings. |
| `/{lang}/settings/security` | Password, sessions, two-factor auth, and passkeys. |
| `/{lang}/settings/privacy` | Consent and privacy controls. |

## Admin Routes

| Route | Purpose |
| --- | --- |
| `/{lang}/admin` | Admin operations overview. |
| `/{lang}/admin/enterprise` | Enterprise instance and billing operations. |
| `/{lang}/admin/users` | User management. |
| `/{lang}/admin/devices` | Device management. |
| `/{lang}/admin/assets` | Asset library. |
| `/{lang}/admin/assets/cleanup` | Asset cleanup tools. |
| `/{lang}/admin/videos` | Video library. |
| `/{lang}/admin/videos/$videoId` | Video details and audio tracks. |
| `/{lang}/admin/api-keys` | Admin API keys. |
| `/{lang}/admin/jobs` | Background job failures. |
| `/{lang}/admin/seed` | On-demand seed job. |
| `/{lang}/admin/settings` | Instance settings. |

## SEO Files

`/robots.txt`, `/sitemap.xml`, and `/llms.txt` are served by `apps/server/src/seo.ts`. Only public, indexable routes belong in the `PUBLIC_PATHS` array.
