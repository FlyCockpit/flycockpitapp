# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Also read `AGENTS.md` — it is the authoritative workspace map and contains the binding rules for coding agents (workflow, safety, and code standards). Key ones: do not commit unless explicitly asked, do not install dependencies without asking, never run destructive database commands, and do not weaken auth/CSRF/CORS/CSP/rate limits without explicit approval.

## Repository shape

Flycockpit is a pnpm + Turborepo monorepo of TypeScript apps and packages, plus a Cargo workspace rooted at `Cargo.toml`. `AGENTS.md` is authoritative for workspace shape; keep this short map in sync with it. Apps under `apps/`: `apps/cli`, `apps/docs`, `apps/native`, `apps/relay`, `apps/relay-rs`, `apps/server`, `apps/web`, and `apps/worker`.

Current Rust members are `apps/cli` (the `cockpit` CLI binary, commands, and terminal host), `apps/relay-rs` (Rust relay), `crates/cockpit-tui` (ratatui terminal interface), `crates/cockpit-core` (UI-free Cockpit application layer), `crates/cockpit-config` (config types/loading), `crates/cockpit-db` (SQLite layer and migrations), `crates/cockpit-proto` (daemon wire protocol), and `crates/relay-protocol` (relay wire protocol). See the Rust crate graph in `AGENTS.md` for the authoritative dependency direction. Rust crates are NOT pnpm workspace packages: pnpm/turbo commands never build or test them — run cargo from the repo root.

### TypeScript side

- `apps/web` — React 19 PWA (TanStack Router, React Query, Tailwind, routes in `src/routes/`).
- `apps/docs` — documentation site.
- `apps/server` — Hono API server: Better Auth, oRPC mount, asset/video routes, MCP admin tools, SEO, security middleware. Most files have a colocated `*.test.ts`.
- `apps/worker` — BullMQ worker (asset analysis, video transcoding, cleanup, seed jobs, enterprise log exports).
- `apps/native` — Expo Router app sharing the same auth and API contracts.
- `apps/relay` — TypeScript remote-session relay service (`@flycockpit/relay-protocol` envelopes); it remains during the replacement transition.
- `packages/api` — oRPC routers (`src/routers/`) and service logic; this is where app business logic lives.
- `packages/db` — Prisma schema in `prisma/schema/`, generated client, seed. Uses `prisma db push`, **not migration files**.
- `packages/auth` (Better Auth config/roles), `packages/env` (runtime env validation for every surface), `packages/queue` (BullMQ queue names/schemas/producers), `packages/ui` (shared shadcn/ui), `packages/config`, `packages/mailer`, `packages/cockpit-protocol` (shared cockpit session/project types).

Data flow: web/native → oRPC client (React Query options) → routers in `packages/api/src/routers/` (mounted by `apps/server`) → Prisma client from `@flycockpit/db`. Background work goes through `@flycockpit/queue` producers and is consumed by `apps/worker`.

**License boundary:** `packages/api/src/enterprise/` is under the FlyCockpit Enterprise License; everything else is Apache-2.0. Keep enterprise-only logic inside that directory.

### Rust (`apps/cli`, `crates/*`)

`apps/cli` is the Rust `cockpit` AI coding harness binary. It owns CLI argument parsing, subcommand wiring, and terminal host integration; `commands/tui.rs` launches `cockpit_tui::tui::app::App`, the one sanctioned binary-to-UI edge. The ratatui terminal interface, panes, overlays, and clipboard helpers live in `crates/cockpit-tui`. Reusable application logic lives in `crates/cockpit-core`, including daemon, engine, providers, auth, tools, agents, skills, session, redaction, packages, and wizard modules. SQLite storage and migrations live in `crates/cockpit-db`; config types/loading live in `crates/cockpit-config`; daemon protocol types live in `crates/cockpit-proto`.

`apps/relay-rs` is the Rust relay that is replacing `apps/relay`; both relay implementations exist during the transition tracked by the `retire-typescript-relay` prompt. Relay wire types live in `crates/relay-protocol`.

CI is `.github/workflows/cli-ci.yml`; releases via cargo-dist (`.github/workflows/release.yml`, Homebrew tap). Requires Rust 1.95+.

## Commands

### TypeScript monorepo (run from repo root)

```bash
pnpm install                 # deps (postinstall installs lefthook hooks)
pnpm dev:services            # start local infra (docker compose: db, redis, ...)
pnpm dev                     # full stack via portless → https://flycockpit.localhost / https://api.flycockpit.localhost
pnpm dev:web|dev:server|dev:worker|dev:relay   # single app

pnpm check:ci                # biome lint+format check (CI mode)
pnpm check                   # biome auto-fix
pnpm check-types             # tsc across the monorepo (turbo)
pnpm test                    # vitest via turbo, all packages
pnpm db:validate             # prisma validate + format check
pnpm db:push                 # sync schema to local db
pnpm db:generate             # regenerate prisma client
```

Tests are Vitest, colocated as `*.test.ts` next to source. Run one package's tests with `pnpm -F server test` (or `-F web`, `-F @flycockpit/api`). Run a single test file:

```bash
pnpm -F @flycockpit/api exec vitest run src/routers/users.test.ts
```

Pre-commit (lefthook) runs biome, `pnpm check-types`, and prisma validation — CI runs the same checks.

### Rust workspace (run from repo root)

```bash
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked           # all tests; single test: cargo test <name>
cargo run                     # launches the cockpit TUI
```

These three checks are what CLI CI enforces.

## Conventions that span files

- App data access from web/native goes through oRPC query/mutation options — don't hand-roll fetches against the server.
- User-facing web strings go through the locale bundles (`apps/web/src/locales/`), except accessibility labels and system-failure fallbacks.
- No `any` / `as any` to silence TypeScript errors.
- Avoid direct `useEffect` in web route/component files unless encapsulated in an approved hook; use Skeletons for loading states; avoid `transition: all` / Tailwind `transition-all`.
- When changing public routes, keep `sitemap.md` and `apps/server/src/seo.ts` in sync.
- Asset and video URLs are bearer-style access URLs — verify authorization before returning one from any API, SSR response, email, or admin tool.
- Environment variables are validated in `@flycockpit/env`; add new ones there (and to `turbo.json` `passThroughEnv` if dev servers need them). Secrets never go in git; `.env.example` holds placeholders only.
