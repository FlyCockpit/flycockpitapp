# Db blocking boundary fixtures

These fixtures exercise the **cockpit-db-local** AST/call-graph gate added by
`db-blocking-api-removal`.

## Resolution boundary

The analyzer only resolves symbols **inside the crate under analysis**
(production `crates/cockpit-db/src` or a single fixture file treated as a mini
crate). It does **not**:

- resolve call graphs in other workspace crates (`cockpit-core`, `cockpit-tui`,
  `apps/cli`, …)
- claim workspace-wide wrapper detection
- expand arbitrary macros or model trait object dispatch beyond fail-closed
  reporting

Workspace callers may only use the exact public entrypoints the gate approves.
Wrappers outside cockpit-db are out of scope for this invariant.

## Supported path forms

- out-of-line and inline modules
- inherent `impl Db` methods
- crate-local free functions
- `pub` / `pub(crate)` reachability
- `self` / `Self` / `Db` / `<Db>` / `crate` / `super` paths
- `use` trees including `as` aliases and local glob imports
- `pub use` re-exports
- calls and function-item references
- calls nested in closures, async blocks, matches, and multiline expressions

## Fail-closed unsupported constructs

Encountering any of the following on a public path is a gate error with a
source location (never a silently skipped edge):

- macro-generated public `Db` methods
- trait implementations that expose an unguarded helper path
- unresolved indirect callable values (function pointers / variables)

## Allowlist (exact)

| Entrypoint | Status | Owner / rationale |
|---|---|---|
| `Db::blocking_for_sync_cli` | permanent | Synchronous CLI one-shots; runtime-guarded |
| `Db::blocking_read_for_sync_ui` | temporary | `db-sync-wrapper-migration` |
| `Db::blocking_write_for_sync_ui` | temporary | `db-sync-wrapper-migration` |
| `Db::blocking_write_for_sync_event` | temporary | `db-sync-wrapper-migration` |
| `Db::blocking_write_for_sync_maintenance` | temporary | `db-sync-wrapper-migration` |

No unnamed or wildcard allowlist entries are accepted. Future additions require
a named owning prompt and concrete synchronous-boundary rationale.
