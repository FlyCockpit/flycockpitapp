# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Also read `AGENTS.md` — it is the authoritative workspace map and contains the binding rules for coding agents (workflow, safety, and code standards). Key ones: do not commit unless explicitly asked, do not install dependencies without asking, never run destructive database commands, and do not weaken auth/CSRF/CORS/CSP/rate limits without explicit approval.

## Repository shape

Flycockpit is a pnpm + Turborepo monorepo of TypeScript apps and packages, plus a Cargo workspace rooted at `Cargo.toml`. `AGENTS.md` is authoritative for workspace shape; keep this short map in sync with it. Apps under `apps/`: `apps/cli`, `apps/docs`, `apps/native`, `apps/relay` (temporary TypeScript standalone relay bridge), `apps/server` (destination public WebSocket owner), `apps/tenant-authority` (Rust tenant-authority reference service), `apps/web`, and `apps/worker`. The former Rust relay app has been deleted; there is no replacement Rust WebSocket server.

Current Rust members are `apps/cli` (the `cockpit` CLI binary, commands, and terminal host), `apps/tenant-authority` (customer-operated tenant-authority reference service), `crates/cockpit-tui` (ratatui terminal interface), `crates/cockpit-core` (UI-free Cockpit application layer), `crates/cockpit-client` (dependency-minimal local daemon client transport), `crates/cockpit-host` (dependency-minimal private filesystem, path, process, PID, lifecycle-guard, and named-pipe identity/connect primitives), `crates/cockpit-config` (config types/loading), `crates/cockpit-tokenizer` (strict shared tiktoken contract), `crates/cockpit-db` (SQLite layer and migrations), `crates/cockpit-proto` (daemon wire protocol), `crates/cockpit-noise` (Noise protocol bindings), `crates/cockpit-test-support` (shared test-only helpers), and `crates/relay-protocol` (legacy relay wire types still used by the daemon client). See the Rust crate graph in `AGENTS.md` for the authoritative dependency direction. Rust crates are NOT pnpm workspace packages: pnpm/turbo commands never build or test them — run cargo from the repo root.

### TypeScript side

- `apps/web` — React 19 PWA (TanStack Router, React Query, Tailwind, routes in `src/routes/`).
- `apps/docs` — documentation site.
- `apps/server` — Hono API server: Better Auth, oRPC mount, asset/video routes, MCP admin tools, SEO, security middleware. Most files have a colocated `*.test.ts`.
- `apps/worker` — BullMQ worker (asset analysis, video transcoding, cleanup, seed jobs, enterprise log exports).
- `apps/native` — Expo Router app sharing the same auth and API contracts.
- `apps/relay` — temporary TypeScript remote-session relay bridge (`@flycockpit/relay-protocol` envelopes) still built by `Dockerfile.relay` until WebSocket lifecycle moves into `apps/server`. Not the long-term architecture.
- `packages/api` — oRPC routers (`src/routers/`) and service logic; this is where app business logic lives.
- `packages/db` — Prisma schema in `prisma/schema/`, generated client, seed. Uses `prisma db push`, **not migration files**.
- `packages/auth` (Better Auth config/roles), `packages/env` (runtime env validation for every surface), `packages/queue` (BullMQ queue names/schemas/producers), `packages/ui` (shared shadcn/ui), `packages/config`, `packages/mailer`, `packages/cockpit-protocol` (shared cockpit session/project types).

Data flow: web/native → oRPC client (React Query options) → routers in `packages/api/src/routers/` (mounted by `apps/server`) → Prisma client from `@flycockpit/db`. Background work goes through `@flycockpit/queue` producers and is consumed by `apps/worker`.

**License boundary:** `packages/api/src/enterprise/` is under the FlyCockpit Enterprise License; everything else is Apache-2.0. Keep enterprise-only logic inside that directory.

### Rust (`apps/cli`, `crates/*`)

`apps/cli` is the Rust `cockpit` AI coding harness binary. It owns CLI argument parsing, subcommand wiring, and terminal host integration; `commands/tui.rs` launches `cockpit_tui::tui::app::App`, the one sanctioned binary-to-UI edge. The ratatui terminal interface, panes, overlays, and clipboard helpers live in `crates/cockpit-tui`. Reusable application logic lives in `crates/cockpit-core`, including daemon lifecycle/server, engine, providers, auth, tools, agents, skills, session, redaction, packages, and wizard modules. Typed local daemon client framing, exact handshake, request timeouts, and event delivery live in `crates/cockpit-client`. Dependency-minimal private filesystem, path, process/PID, lifecycle metadata guards, and named-pipe identity/connect primitives live in the `crates/cockpit-host` leaf; the local daemon client uses host directly for Windows pipe connect/identity. SQLite storage and migrations live in `crates/cockpit-db`; config types/loading live in `crates/cockpit-config`; daemon protocol types live in `crates/cockpit-proto`.

Public/server-side WebSockets are TypeScript-owned. `apps/relay` is only a temporary deployed bridge; the destination owner is TypeScript `apps/server`. The Rust daemon remains an outbound WebSocket client (and later WebRTC/Noise endpoint), not a public WebSocket service. Legacy relay wire types still used by the daemon live in `crates/relay-protocol` / `packages/relay-protocol` until transport-neutral successors replace them.

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
cargo clippy --locked --tests -- -D warnings
cargo nextest run --locked --workspace   # all tests; single test: cargo nextest run <name>
cargo nextest run --locked --workspace --profile quick  # inner-loop: skips apps/cli e2e binary; full run required before completion/commit
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
