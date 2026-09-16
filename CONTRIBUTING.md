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

For Rust changes in `apps/cli` or `crates/*`, run the Rust gate from the
repository root:

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

## TUI golden screen dumps

`cockpit-tui` checks full-screen renders at 80×24 and 120×40 against
checked-in dumps under `crates/cockpit-tui/tests/golden/<area>/`. The
harness lives in `crates/cockpit-tui/src/tui/golden.rs` (plus App
helpers in `src/tui/app/golden.rs`); Cargo cannot host both
`tests/golden.rs` and `tests/golden/`, so the dump directory is the
corpus and `cargo test -p cockpit-tui golden` runs the tests. The
harness renders through `ratatui::backend::TestBackend`, compares
byte-for-byte, and writes a `.style.txt` sidecar (fg/bg/modifier per
cell run) so palette changes show up in review. The visual reference
for future UI work is [`reference/example-tui/`](reference/example-tui/README.md).

### Add a dump

1. Render a `ratatui` widget or the whole `App` frame with
   `cockpit_tui::test_support::golden` (`render_widget`, `render_app`,
   or `render_frame`).
2. Call `assert_golden("area", "screen", width, height, &buf)` or
   `assert_golden_sizes("area", "screen", |w, h| …)` so both review
   sizes are captured.
3. Run with `COCKPIT_UPDATE_GOLDEN=1` (below) to write
   `<screen>-<WxH>.txt` and `<screen>-<WxH>.style.txt`.
4. Commit both files. A golden change needs a screenshot-style review
   note in the PR — the unified diff of the text dump is the evidence.

The helper pins the clock (`HH:MM` stamps become `12:00`), the welcome
frame counter, and the cloud RNG seed for `clouds::seed_with(w, h,
entropy)` (#428). Mouse-hover is cleared unless the test calls
`GoldenPins::allow_hover()`.

### Regenerate

From the repository root:

```sh
COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-tui golden
```

Only the dumps whose tests ran are rewritten. The same
`COCKPIT_UPDATE_GOLDEN=1` convention is used by
`crates/cockpit-proto/tests/remote_transport_fixtures.rs`.

## Security issues

Do not open public issues or pull requests for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the private reporting channel.
