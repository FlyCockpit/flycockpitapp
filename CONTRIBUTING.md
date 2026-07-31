# Contributing to FlyCockpit

Thank you for your interest in contributing. Before you open a pull request,
please read how licensing and sign-off work in this repository.

## Licensing of contributions

This repository is open core (see [LICENSE](LICENSE)):

- Everything **outside** `packages/api/src/enterprise/` is licensed under the
  [Apache License 2.0](LICENSE).
- Everything **inside** `packages/api/src/enterprise/` is licensed under the
  [FlyCockpit Enterprise License](packages/api/src/enterprise/LICENSE).

By submitting a contribution, you agree that:

1. Contributions to code outside `packages/api/src/enterprise/` are provided
   under the Apache License 2.0, the same license that covers that code
   (inbound = outbound).
2. Contributions to code inside `packages/api/src/enterprise/` are provided
   under the FlyCockpit Enterprise License, and you grant FlyCockpit LLC a
   perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to
   use, reproduce, modify, display, distribute, sublicense, and relicense
   those contributions as part of its commercial offerings.
3. You have the right to submit the contribution under these terms.

## Developer Certificate of Origin

Every commit must be signed off, certifying the
[Developer Certificate of Origin v1.1](https://developercertificate.org):

```sh
git commit -s
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer. Pull
requests with unsigned commits will be asked to rebase.

## Development setup

See [README.md](README.md) for local setup. Before opening a pull request, run the checks that apply to the code you changed.

For TypeScript and pnpm-workspace scopes, run:

```sh
pnpm check:ci
pnpm check-types
pnpm test
```

For Rust changes in `apps/cli`, `apps/relay-rs`, or `crates/*`, run the Rust
gate from the repository root:

```sh
cargo fmt --check
cargo nextest run --locked --workspace --test-threads=1
cargo clippy --locked --tests -- -D warnings
```

Keep `--test-threads=1`: the workspace has daemon and filesystem tests that
share process-level state, so parallel execution can produce intermittent
failures unrelated to a contributor's change.

Also read [AGENTS.md](AGENTS.md) — its safety and code-standard rules apply
to human contributors as much as to coding agents. Never include secrets,
credentials, or `.env` files in a contribution.

## Security issues

Do not open public issues or pull requests for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the private reporting channel.
