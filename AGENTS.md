# AGENTS.md

Rules for coding agents working in Flycockpit.

## Project Shape

Flycockpit is a pnpm/Turborepo monorepo with a React web app, Hono API server, BullMQ worker, Expo native app, relay service, Prisma database package, and shared internal packages under the `@flycockpit/*` scope.

The Rust Cockpit CLI lives in `apps/cli`. It is a standalone Cargo crate, not a pnpm workspace package: pnpm/turbo commands do not build it, and its checks are `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test --locked` run from `apps/cli/`. Its CI is `.github/workflows/cli-ci.yml` and releases go through `.github/workflows/release.yml` (cargo-dist + Homebrew tap).

## Default Workflow

- Read the relevant code before changing it.
- Keep changes scoped to the user request.
- Do not commit unless the user explicitly asks.
- Do not install dependencies without asking first.
- Prefer existing package boundaries and local helper APIs.
- Keep `sitemap.md` and `apps/server/src/seo.ts` in sync when changing public routes.

## Safety

- Never read or print secret values unless the task requires it.
- Never commit `.env` files or real credentials.
- Do not weaken auth, authorization, CSRF, CORS, CSP, or rate limits without explicit approval.
- Do not use `sudo`.
- Do not run destructive database commands such as reset, drop, truncate, or forced Prisma pushes.
- Asset and video URLs are bearer-style access URLs; verify authorization before returning them.

## Code Standards

- Use TypeScript types directly; do not add `any` or `as any` to silence errors.
- Use oRPC query and mutation options for app data access.
- Keep React hooks at the top level and avoid direct `useEffect` in web route/component files unless encapsulated in an approved hook.
- User-facing web strings should go through the locale bundles unless they are accessibility labels or system-failure fallbacks.
- Use Skeletons for content loading states.
- Avoid `transition: all` and Tailwind `transition-all`.

## Checks

Run the narrowest useful checks for the change, and broaden when shared contracts are touched:

```bash
pnpm check:ci
pnpm check-types
pnpm test
pnpm db:validate
```
