# AGENTS.md

Rules for coding agents working in Flycockpit.

`AGENTS.md` is the authoritative workspace map for coding agents. When workspace
shape changes, update this file and mirror the short map in `CLAUDE.md`.

## Project Shape

Flycockpit is a pnpm/Turborepo monorepo with a React web app, Hono API server, BullMQ worker, Expo native app, relay service, Prisma database package, and shared internal packages under the `@flycockpit/*` scope.

Apps under `apps/`: `apps/cli` (Rust Cockpit CLI), `apps/docs` (documentation site), `apps/native` (Expo app), `apps/relay` (TypeScript relay), `apps/relay-rs` (Rust relay replacing the TypeScript relay during the transition), `apps/server` (Hono API), `apps/web` (React app), and `apps/worker` (BullMQ worker).

Rust code lives in the Cargo workspace rooted at this repo's `Cargo.toml`. Current members are `apps/cli` (Cockpit CLI binary, commands, and terminal host), `apps/relay-rs` (Rust relay), `crates/cockpit-tui` (ratatui terminal interface), `crates/cockpit-core` (UI-free Cockpit application layer), `crates/cockpit-config` (config types/loading), `crates/cockpit-db` (SQLite layer and migrations), `crates/cockpit-proto` (daemon wire protocol), and `crates/relay-protocol` (relay wire protocol). pnpm/turbo commands do not build or test Rust. Run cargo checks from the repo root: `cargo fmt --check`, `cargo nextest run --locked --workspace`, and `cargo clippy --locked --tests -- -D warnings` (test targets are lint-clean and must stay that way). (`cargo nextest run --locked --workspace --profile quick` may be used for intermediate iterations — it skips only apps/cli's e2e integration binary — but the full default-profile run is required before declaring work complete.) CLI CI is `.github/workflows/cli-ci.yml` and releases go through `.github/workflows/release.yml` (cargo-dist + Homebrew tap).

### Rust crate graph

Dependencies run strictly downward; there are no upward or circular edges. This graph is authoritative — do not duplicate it elsewhere.

```
apps/cli            -> cockpit-tui, cockpit-core, cockpit-proto, cockpit-config,
                       cockpit-db, relay-protocol
crates/cockpit-tui  -> cockpit-core, cockpit-proto, cockpit-config, cockpit-db,
                       relay-protocol
crates/cockpit-core -> cockpit-proto, cockpit-config, cockpit-db, relay-protocol
crates/cockpit-proto-> cockpit-config, cockpit-db
crates/cockpit-config -> cockpit-db
crates/cockpit-db   -> (none)
crates/relay-protocol -> (none)

apps/relay-rs       -> relay-protocol
```

Layered, the chain is `apps/cli -> cockpit-tui -> cockpit-core -> cockpit-proto -> cockpit-config -> cockpit-db`, with upper crates also depending directly on lower ones.

Rules that follow from the graph:

- `apps/cli` is the only crate that may depend on `crates/cockpit-tui`. Nothing else does, and nothing else should.
- `crates/cockpit-core` and everything below it must stay free of ratatui, crossterm, and any terminal-UI dependency.
- `crates/cockpit-db` is the base of the chain and depends on no other workspace crate.
- Fix a discovered inversion by moving the symbol to its correct crate — never with a shim or a circular dev-dependency.

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
