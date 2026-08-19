# Generated-SVG fuzzing

`cargo-fuzz` (libFuzzer) harnesses for the closed-policy generated-SVG
sanitizer and its independent structural verifier.

This directory is a **detached workspace** (empty `[workspace]` table in
`Cargo.toml`): it is not a member of the root Cargo workspace, so ordinary
`cargo build` / `cargo check --workspace` / `cargo nextest run --workspace`
never build it and it never touches the root `Cargo.lock`. It is built and run
only through `cargo fuzz`, which requires a nightly toolchain.

An in-crate smoke test (`generated_svg_fuzz_harness_smoke` in
`crates/cockpit-core/src/generated_svg/tests.rs`) replays the seed corpus and a
few structural mutations through the exact entry points these targets drive, so
`cargo nextest run -p cockpit-core` proves the harness bodies link and run
(the `-runs=0`-equivalent smoke) without needing the nightly fuzzer.

## Targets

- `sanitize_generated_svg` — full pipeline: accept -> canonicalize -> svg-hush
  -> independent verifier, via `generated_svg::sanitize_generated_svg`.
- `verify_canonical_svg` — the independent structural verifier alone, via
  `generated_svg::fuzz_verify_canonical_svg`.

## Install

```sh
cargo install cargo-fuzz
```

## Run (with hard caps)

From `crates/cockpit-core/`:

```sh
# Bounded smoke: build + zero-iteration run (CI-friendly).
cargo +nightly fuzz run sanitize_generated_svg -- -runs=0
cargo +nightly fuzz run verify_canonical_svg   -- -runs=0

# Time-boxed campaign with allocation / input-size / per-input time caps.
cargo +nightly fuzz run sanitize_generated_svg -- \
  -max_total_time=60 -max_len=1048576 -rss_limit_mb=2048 -timeout=10
cargo +nightly fuzz run verify_canonical_svg -- \
  -max_total_time=60 -max_len=1048576 -rss_limit_mb=2048 -timeout=10
```

The caps mean:

- `-max_len=1048576` — never hand the target more than 1 MiB (well inside the
  sanitizer's 16 MiB raw ceiling; keeps iterations fast).
- `-rss_limit_mb=2048` — abort if resident memory exceeds 2 GiB.
- `-timeout=10` — abort any single input that runs longer than 10 s.
- `-max_total_time=60` — bound the whole campaign; raise for nightly jobs.

Fuzzing must **not** disable the sanitizer's own internal limits (raw bytes,
depth, element/attribute counts, path and text budgets); the targets call the
unmodified production entry points precisely so those limits stay in force.

## Corpus

Seed inputs live under `corpus/<target>/`, mixing valid documents (including
provider output with a leading XML declaration) with adversarial ones (script
injection, deep nesting, oversized numbers, malformed markup). `cargo fuzz`
grows each corpus in place as it discovers new coverage.
