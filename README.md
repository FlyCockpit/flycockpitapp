<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/header/graph.svg?title=Flycockpit&subtitle=Instance+operations+console+for+remote+AI+workspaces&mode=dark" />
  <img alt="Flycockpit" src="https://shieldcn.dev/header/graph.svg?title=Flycockpit&subtitle=Instance+operations+console+for+remote+AI+workspaces&mode=light" width="100%" />
</picture>

# Flycockpit

Flycockpit is an instance operations console for remote AI workspaces. This monorepo includes a web console, API server, background worker, native app shell, relay service, Prisma data layer, shared UI package, and operational tooling for assets, video, users, devices, jobs, and enterprise instance workflows.

## Applications

| App | Path | Purpose |
| --- | --- | --- |
| Web | `apps/web` | React 19 PWA built with TanStack Router, oRPC, React Query, Tailwind CSS, and shared UI components. |
| Server | `apps/server` | Hono API server for auth, oRPC, assets, videos, MCP admin tools, SEO files, and static delivery. |
| Worker | `apps/worker` | BullMQ worker for asset analysis, cleanup, seed jobs, video transcoding, and enterprise log exports. |
| Native | `apps/native` | Expo Router app wired to the same auth and API contracts. |
| Relay | `apps/relay` | Remote-session relay service. |
| CLI | `apps/cli` | `cockpit`, the Rust AI coding harness with a codex-style TUI, session daemon, and multi-agent execution. |
| Docs | `apps/docs` | Starlight documentation app retained for now. |

## Packages

| Package | Purpose |
| --- | --- |
| `@flycockpit/api` | oRPC routers, service libraries, asset/video helpers, and enterprise logic. |
| `@flycockpit/auth` | Better Auth configuration, roles, and user-creation policy. |
| `@flycockpit/db` | Prisma schema, generated client, and seed entrypoint. |
| `@flycockpit/env` | Runtime environment validation for server, worker, web, and native surfaces. |
| `@flycockpit/queue` | BullMQ queue names, schemas, producers, and Redis connection. |
| `@flycockpit/ui` | Shared shadcn/ui components and Tailwind globals. |
| `@flycockpit/config` | Shared TypeScript, PostCSS, locale, and theme config. |
| `@flycockpit/mailer` | Transactional email rendering and delivery helpers. |
| `@flycockpit/relay-protocol` | Shared relay message envelopes. |
| `@flycockpit/cockpit-protocol` | Shared cockpit session and project protocol types. |

## Install the CLI

Install `cockpit` with the one-line installer (macOS and Linux):

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/FlyCockpit/flycockpitapp/releases/latest/download/cockpit-cli-installer.sh | sh
```

Or with Homebrew:

```sh
brew install flycockpit/tap/cockpit
```

See [`apps/cli/README.md`](apps/cli/README.md) for Windows install, usage, and configuration. The CLI is a standalone Rust crate; the pnpm workspace and turbo tasks do not build it. Its CI and releases run through `.github/workflows/cli-ci.yml` and `.github/workflows/release.yml`.

## Local Development

Install dependencies with pnpm:

```bash
pnpm install
```

Copy the example environment and fill in local-only values:

```bash
cp .env.example .env
```

Start local infrastructure, then run the app stack:

```bash
pnpm dev:services
pnpm dev
```

With `portless` configured, the web app runs at `https://flycockpit.localhost` and the API runs at `https://api.flycockpit.localhost`.

Useful commands:

```bash
pnpm check:ci
pnpm check-types
pnpm test
pnpm --filter web build
pnpm db:validate
pnpm db:push
```

## Database

The Prisma schema lives in `packages/db/prisma/schema/`. This project uses `prisma db push` rather than migration files. Use `pnpm db:push` for normal local schema sync and reserve destructive local pushes for disposable development databases only.

## Operational Notes

Secrets belong in environment variables, never in git. `.env.example` and `.env.docker.defaults` should contain placeholders only.

Asset and video URLs are bearer-style access URLs. Always authorize access before returning one from an API, SSR response, email, or admin tool.

## License

This repository is open core:

- Everything outside `packages/api/src/enterprise/` is licensed under the [Apache License 2.0](LICENSE).
- `packages/api/src/enterprise/` contains hosted/enterprise functionality licensed under the [FlyCockpit Enterprise License](packages/api/src/enterprise/LICENSE); production use requires a valid FlyCockpit commercial license.

The Cockpit CLI in [`apps/cli`](apps/cli) is licensed under Apache-2.0 ([`apps/cli/LICENSE`](apps/cli/LICENSE)).

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution terms and [SECURITY.md](SECURITY.md) for the vulnerability reporting policy.

Copyright © 2026 FlyCockpit LLC.
