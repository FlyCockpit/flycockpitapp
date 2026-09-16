# UI reference vendored from excoc (`example-tui`)

This directory holds a **read-only copy** of the excoc reference implementation used as the UI fidelity ground truth for epic #453.

| Field | Value |
|-------|-------|
| Source repository | `example-tui` (crate name: `excoc`) |
| Source path (development checkout) | `~/projects/flycockpit/example-tui` |
| Vendored commit | `55bedc0bd4586f86a8ae2df7cafcfe72bb522cbf` |
| Vendored date | 2026-09-16 |

## Usage

Every UI issue in epic #453 must:

1. Read `reference/example-tui/README.md` end to end before implementation.
2. List the named, observable behaviours being reproduced in the PR.
3. Compare golden screen dumps against excoc at 80×24 and 120×40 (see #424).

This tree is **not** a workspace member. Do not add it to `Cargo.toml` `members`.
