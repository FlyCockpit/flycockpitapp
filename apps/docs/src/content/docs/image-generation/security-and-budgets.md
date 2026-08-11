---
title: Security and Budgets
description: Authorization, reference egress grants, spend policy, epoch requirements, and remote admin scope.
---

Image generation is a security boundary. A wrong endpoint, an unbounded spend
default, or a global grant can cause paid duplicates or affect another user's
work. This page documents the exact authorization and budget contracts.

## Authorization model

### Reference egress grants

Reference egress grants have only three scopes. There is **no global/unscoped**
grant:

| Scope | Meaning |
| --- | --- |
| `once` | Single use, not persisted |
| `session` | Current session only |
| `project` | Machine-local project |

A **project** grant still requires current session authorization and per-use
audit. Project use is not a standing authority — each generation re-checks
session authorization.

### Grant tuple

A composite authorization grant tuple binds:

- provider
- model
- endpoint origin
- connected location class
- credential identity
- target/workflow digest
- reference-egress boolean
- maximum fanout
- maximum total outputs
- maximum known cost micros **or** explicit `unknown_cost_allowed`

It never contains a wildcard destination or an unbounded implicit maximum. A
grant that does not cover the requested fanout, total outputs, or cost blocks
the request.

### Discovery never grants authority

The `list_image_generation_targets` tool returns only currently selectable
targets. Calling it grants no generation authority — it is informational only.

## Yolo mode

Yolo opens no human prompt and records disposition `agent_discretion` — never
`allow_once` and never a persisted grant — after every hard gate passes. Yolo
does **not** bypass:

- budgets
- egress/path authority
- health checks
- TLS verification
- resource gates

The user-confirmed known-cost base-tier threshold is USD 0.25 (250,000 micros),
configurable from zero through the documented hard ceiling of USD 10
(10,000,000 micros).

## Unknown maximum cost

Unknown maximum cost may dispatch only when request, session, and project
spend choices are **all** explicitly `Unlimited`. If any scope is finite, an
unknown maximum blocks the request.

## Spend policy

### Three explicit choices

Paid generation cannot dispatch until **each** of the three spend scopes is
explicitly finite or `Unlimited`:

| Scope | Options |
| --- | --- |
| Request | `Unconfigured`, `Finite { usd_micros }`, `Unlimited` |
| Session | `Unconfigured`, `Finite { usd_micros }`, `Unlimited` |
| Project | `Unconfigured`, `Finite { usd_micros }`, `Unlimited` |

`Unconfigured` blocks dispatch. There is **no** implicit dollar, UTC, reset,
Auto, or Yolo default. Absence is deliberately represented as `Unconfigured`.

### Project epoch

A finite project budget requires an explicit **epoch policy**. There is no
default epoch. The two epoch kinds:

| Epoch | Fields |
| --- | --- |
| Calendar month | IANA time zone (e.g. `America/Chicago`) |
| Rolling | Duration in seconds, anchor instant |

A calendar-month epoch derives membership from the configured time zone (e.g.
`2026-03@America/Chicago`). A rolling epoch uses a saved anchor and rejects
clock rollback. Epoch membership is derived from the server-owned reservation
clock, not the client wall clock.

### UI suggestions are not defaults

Editable UI suggestions exist as a presentation aid only:

| Suggestion | Display value |
| --- | --- |
| Request | USD 1 (1,000,000 micros) |
| Session | USD 10 (10,000,000 micros) |
| Project | USD 100 (100,000,000 micros) |

These are **not** a default and must never be merged into spend settings by a
loader. The epoch is `project-month` as a suggestion only — there is no
authoritative UTC or reset default.

## Spend reservation

The spend ledger reserves every finite scope before the external journal moves
to `dispatching`. Reservation derives epoch membership from the server-owned
clock. A reservation that would exceed any finite scope blocks before any paid
byte leaves the process.

## Remote generation management

Remote generation management requires **Owner** or the exact-project
**ImageGenerationAdmin** capability. This scope is:

- **not** terminal/session/file/artifact authority
- **not** a standing generation grant
- **not** transferable to another project

See [Remote Client](../remote-client/) for artifact access scope.

## What is never advised

- Disabling TLS or SSRF checks.
- Using a global grant or wildcard destination.
- Setting an implicit spend or epoch default.
- Bypassing health checks under Yolo.
- Retrying `submission_unknown` (the provider may have already accepted).
