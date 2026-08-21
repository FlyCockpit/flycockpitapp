# AGENTS.md

Rules for coding agents working in Flycockpit.

`AGENTS.md` is the authoritative workspace map for coding agents. When workspace
shape changes, update this file and mirror the short map in `CLAUDE.md`.

## Project Shape

Flycockpit is a pnpm/Turborepo monorepo with a React web app, Hono API server, BullMQ worker, Expo native app, relay service, Prisma database package, and shared internal packages under the `@flycockpit/*` scope.

Apps under `apps/`: `apps/cli` (Rust Cockpit CLI), `apps/docs` (documentation site), `apps/native` (Expo app), `apps/relay` (temporary TypeScript standalone relay bridge still deployed until WebSocket ownership moves into `apps/server`), `apps/server` (Hono API; destination owner of public WebSocket signaling/gateway work), `apps/tenant-authority` (Rust tenant-authority reference service), `apps/web` (React app), and `apps/worker` (BullMQ worker). There is no Rust WebSocket relay app: the former `apps/relay-rs` experiment was deleted.

Rust code lives in the Cargo workspace rooted at this repo's `Cargo.toml`. Current members are `apps/cli` (Cockpit CLI binary, commands, and terminal host), `apps/tenant-authority` (customer-operated tenant-authority reference service), `crates/cockpit-tui` (ratatui terminal interface), `crates/cockpit-core` (UI-free Cockpit application layer), `crates/cockpit-config` (config types/loading), `crates/cockpit-tokenizer` (strict shared tiktoken contract), `crates/cockpit-db` (SQLite layer and migrations), `crates/cockpit-proto` (daemon wire protocol), `crates/cockpit-noise` (Noise protocol bindings), `crates/cockpit-test-support` (shared test-only helpers; not a production API), and `crates/relay-protocol` (legacy relay wire types still used by the daemon client). pnpm/turbo commands do not build or test Rust. Run cargo checks serially from the primary repo root with its singular target: `CARGO_TARGET_DIR=target cargo fmt --check`, `CARGO_TARGET_DIR=target cargo nextest run --locked --workspace`, and `CARGO_TARGET_DIR=target cargo clippy --locked --tests -- -D warnings` (test targets are lint-clean and must stay that way). `cargo nextest run --locked --workspace --profile quick` may be used only while fixing a failure in the final serialized validation loop — it skips only apps/cli's e2e integration binary — and the full default-profile run is required after the last change. Worker worktrees never build or test, and build artifacts or dependency caches never go under `/tmp`. CLI CI is `.github/workflows/cli-ci.yml` and releases go through `.github/workflows/release.yml` (cargo-dist + Homebrew tap).

### Rust crate graph

Dependencies run strictly downward; there are no upward or circular edges. This graph is authoritative — do not duplicate it elsewhere.

```
apps/cli                 -> cockpit-tui, cockpit-core, cockpit-proto, cockpit-config,
                            cockpit-db, relay-protocol
apps/tenant-authority    -> cockpit-proto
crates/cockpit-tui       -> cockpit-core, cockpit-proto, cockpit-config
crates/cockpit-core      -> cockpit-proto, cockpit-config, cockpit-tokenizer,
                            cockpit-db, relay-protocol
crates/cockpit-proto     -> cockpit-config, cockpit-db
crates/cockpit-config    -> cockpit-tokenizer, cockpit-db
crates/cockpit-tokenizer -> (none)
crates/cockpit-db        -> (none)
crates/cockpit-noise     -> (none)
crates/cockpit-test-support -> (none)
crates/relay-protocol    -> (none)
```

Layered, the chain is `apps/cli -> cockpit-tui -> cockpit-core -> cockpit-proto -> cockpit-config -> cockpit-db`, with upper crates also depending directly on lower ones. `apps/tenant-authority` sits beside `apps/cli` and depends only on `cockpit-proto`. `cockpit-noise` is a leaf. `cockpit-test-support` is a test-only leaf: upper crates may take it as a dev-dependency or via an explicit `test-support` feature; that is not a production edge and must not become one.

Rules that follow from the graph:

- `apps/cli` is the only crate that may depend on `crates/cockpit-tui`. Nothing else does, and nothing else should.
- `crates/cockpit-core` and everything below it must stay free of ratatui, crossterm, and any terminal-UI dependency.
- `crates/cockpit-db` is the base of the chain and depends on no other production workspace crate (`cockpit-test-support` may appear only as a dev-dependency).
- `crates/cockpit-core` must not re-export `cockpit_db` (`pub use cockpit_db as db` or equivalent). The storage crate is an implementation detail of the core layer. CLI production paths and daemon-connected TUI paths talk to the ledger only through daemon RPCs. The documented daemonless TUI fallback is the narrow exception; do not use it to add a new production database bypass. Fix a bypass by moving the call onto an RPC, not by widening the re-export.
- `crates/cockpit-test-support` and `cockpit_core::test_env` (behind the `test-support` feature) are test instrumentation only. They must not grow into a general-purpose database API for upper crates.
- There is no Rust public WebSocket server or relay binary in this workspace. Server-side/public WebSockets are TypeScript-owned (`apps/relay` as a temporary deployed bridge; destination is TypeScript `apps/server`). The Rust daemon remains an outbound WebSocket client only.
- Fix a discovered inversion by moving the symbol to its correct crate — never with a shim or a circular dev-dependency.

### Storage and daemon ownership

- `cockpit doctor` is read-only inspection: it must not require workspace trust, must not auto-promote an ephemeral daemon to persistent, and must not open SQLite in the CLI process. The hidden `daemon diagnostic-snapshot` worker is the only permitted SQLite-owning diagnostic path.
- Do not stub diagnostics (`"unavailable"`, `"unresolved"`, empty sections) to keep a target compiling. Inspect, or fail closed with a real error.
- Do not bind or publish the daemon socket until boot (database/config) has completed. Clients that see a socket expect a hello promptly.

### Wire protocol (prerelease)

- Live connections require an exact `PROTOCOL_VERSION` match. `MIN_SUPPORTED_PROTOCOL_VERSION` stays equal to `PROTOCOL_VERSION` until a compacted v1 ships. Historical `daemon_proto/vN/` fixtures are migration archaeology and do not expand compatibility.
- Handshake fails closed: missing, malformed, or timed-out daemon hello is a protocol error (`cockpit daemon restart`), never a silent fallback to the current version.
- Rust wire types that cross the Rust/TypeScript boundary (or already have a `packages/cockpit-protocol` mirror) stay in lockstep with that package. A new or renamed mirrored event, request, or response updates both, plus fixtures.

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

### Test integrity

Never make a failing check pass by weakening its test. Do not convert an
assertion of failure into an assertion of success, delete or conditionally skip
assertions (`if result.is_ok() { continue; }` and the like), add
`#[allow(dead_code)]` to test scaffolding so a parsed-but-unasserted field stops
warning, narrow a broad assertion down to a few whitelisted spellings, or add
`--passWithNoTests`-style escapes. Fix the production defect, or change the
contract explicitly in the owning prompt. Reviewers must flag any diff that does
the above. The `scripts/check-test-assertion-integrity.sh` ratchet enforces the
`#[allow(dead_code)]` half mechanically in the Rust test targets.

Gate production helpers with the narrowest target predicate that matches their
call sites. `#[cfg(any(unix, test))]` is appropriate only when a Unix helper is
also required by a unit-test seam; otherwise prefer `unix` or a tighter
`target_os`. Linux-only desktop or Wayland code uses `target_os = "linux"`, not
`unix` (macOS is unix and does not have that path). Do not add
`#[allow(dead_code)]` to keep a Windows or macOS `--tests` clippy target quiet.

## Checks

Run the narrowest useful checks for the change, and broaden when shared contracts are touched:

```bash
pnpm check:ci
pnpm check-types
pnpm test
pnpm db:validate
```

TypeScript tests that import `@flycockpit/env` or `@flycockpit/queue` need
`DATABASE_URL`, `REDIS_URL`, `BETTER_AUTH_SECRET`, and `BETTER_AUTH_URL` even
when they mock persistence (`turbo.json` `test.env` and the unit-test jobs in
`pr-checks.yml` / `main-checks.yml`). When adding a Node script, vitest config,
or fixture generator that CI invokes, declare it as a knip entry; do not restore
`ignoreExportsUsedInFile`. Generated protocol fixtures and fuzz corpora that
Biome would rewrite belong in `biome.json` `files.includes` as ignore patterns,
not reformatted.
