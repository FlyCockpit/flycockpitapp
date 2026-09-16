---
name: UI change (excoc fidelity)
about: UI work that must match the excoc reference implementation
title: ""
labels:
  - ui-change
---

## Reference behaviours to reproduce

> **First task:** read `reference/example-tui/README.md` end to end, then fill this checklist with named, observable behaviours from the README and source (e.g. "‹ Back top-left on every screen", "action bar with Continue/Choose/Save/Retry/Done", "P-51 with clouds", "↓ Latest chip").

- [ ] (behaviour 1)
- [ ] (behaviour 2)

## Product-only features kept

What exists in flycockpitapp but is **not** demoed in excoc, and what "restyle to excoc look" means for each:

| Feature | excoc status | Restyle plan |
|---------|--------------|--------------|
| | | |

## Deletions

Named symbols/paths that must be **gone** (grep must return zero; renames do not count):

```sh
# Example: rg -n SetupWizardDialog crates/cockpit-tui  # → 0 lines
```

## Acceptance evidence

- Golden screen dumps at **80×24** and **120×40** checked into the tree and diffed in review (`COCKPIT_UPDATE_GOLDEN=1` to regenerate).
- Substring asserts and `include_str!` source scans are **not** acceptance evidence.

## Verification before dependents start

Post a criterion→evidence table on this issue **before** any dependent issue begins:

| Acceptance criterion | Evidence (test name + `file:line`) |
|----------------------|-------------------------------------|
| | |

## Human checkpoint (UI batches)

One cold `cockpit` first run shown next to `cargo run -- onboard` in `reference/example-tui` before the first dependent issue starts. **Owner must approve** — do not self-certify.
