# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, not via public issues
or pull requests: open a private advisory on the repository's
[Security tab → "Report a vulnerability"](../../security/advisories/new).

We aim to acknowledge reports within 72 hours.

## Supported versions

FlyCockpit ships from `main`. Only the latest code on `main` receives
security fixes; if you self-host, pull updates regularly.

## Security controls shipped by default

Defaults in this repository:

- pnpm 11 supply-chain hardening — release-age gate (7 d), exotic-subdep
  blocking, build-script allowlist, sha512-pinned package manager
  (`pnpm-workspace.yaml`, `package.json#packageManager`).
- SHA-pinned GitHub Actions kept current by Dependabot
  (`.github/dependabot.yml`).
- Trufflehog verified-secret scanning on every PR (`.github/workflows/pr-checks.yml`).
- Trivy HIGH/CRITICAL image scanning on every container build
  (`.github/workflows/build-image.yml`).
- `pnpm audit` on every PR with `--audit-level=high`.
- Non-root `USER node` in the production server and worker images.
- Tight Content-Security-Policy and `secureHeaders` middleware
  (`apps/server/src/index.ts`).
- Tiered rate limiting — signup (3/hour) stricter than auth (10/minute)
  (`apps/server/src/rate-limit.ts`).
- Hard production-boot guards in `packages/env/src/server.ts`:
  a weak `BETTER_AUTH_SECRET` refuses to start in production.
- Permission-checked asset URLs (authorize before returning asset URLs).

See `AGENTS.md` § "Safety" for the full list of guardrails a coding agent
must respect when working in this repo.

## Notes for self-hosted forks

The controls above work on **any repository**, public or private, with no
GitHub Advanced Security (GHAS) subscription. Two additional scanners are
free on public repositories but require GHAS on private ones, so private
self-hosted forks may want to budget for them:

- CodeQL (generic JS/TS SAST).
- GitHub Dependency Review Action.
