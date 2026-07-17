# Redaction Scrub Site Classification

This inventory classifies every production `RedactionTable::scrub` boundary and helper entry point. Test-only modules/files are excluded. Keep the machine-checked manifest in sync with the explanations below; `redact::scrub_inventory_tests::scrub_inventory_doc_matches_source_tree` fails when a production scrub file appears, disappears, or is omitted here.

## Machine-checked inventory

<!-- scrub-inventory:start -->
- Dispatch: `apps/cli/src/engine/model/dispatch.rs`, `apps/cli/src/engine/model/redact.rs`, `apps/cli/src/engine/model/outbound_guard.rs`, `apps/cli/src/embeddings.rs`, `apps/cli/src/harness/run.rs`
- Client boundary: `apps/cli/src/daemon/server/mod.rs`, `apps/cli/src/daemon/server/dispatch.rs`, `apps/cli/src/engine/driver/mod.rs`
- Off machine: `apps/cli/src/commands/export/mod.rs`, `apps/cli/src/daemon/org_sync.rs`, `apps/cli/src/daemon/remote_audit_upload.rs`
- Session-worker persist path: `apps/cli/src/daemon/session_worker/run.rs`
- Core scrub entry points: `apps/cli/src/redact/mod.rs`
<!-- scrub-inventory:end -->

## Dispatch

- `apps/cli/src/engine/model/dispatch.rs`: one-shot text completions, tool/injection classifier inputs, chat dispatch, captured completion, and tandem assembly scrub system text, prompts, history messages, assistant tool-call arguments, reasoning text, and JSON string leaves immediately before provider dispatch.
- `apps/cli/src/engine/model/redact.rs`: `scrub_message` and `scrub_json_strings` implement the message/tree scrub used by dispatch.
- `apps/cli/src/engine/model/outbound_guard.rs`: shared model outbound guard for text and batch text scrubbing.
- `apps/cli/src/embeddings.rs`: embedding input text is scrubbed with `OutboundGuard::scrub_many` before the OpenAI-compatible embedding request leaves Cockpit.
- `apps/cli/src/harness/run.rs`: harness prompts leave Cockpit for an external harness process, so this is a dispatch boundary for that provider-style execution path.

## Client Boundary

- `apps/cli/src/daemon/server/mod.rs`: recursively scrubs event JSON strings for non-owner principals at socket forwarding and attach-history egress.
- `apps/cli/src/daemon/server/dispatch.rs`: applies the server scrub helpers when returning attach/list history to non-owner clients.
- `apps/cli/src/engine/driver/mod.rs`: `redacted_bounded_snippet` emits bounded, scrubbed failure diagnostics for client/display payloads while the raw failure remains local.

## Off Machine

- `apps/cli/src/commands/export/mod.rs`: export payloads scrub session/config/MCP/file content regardless of model trust or principal.
- `apps/cli/src/daemon/org_sync.rs`: organization sync JSON is scrubbed before upload.
- `apps/cli/src/daemon/remote_audit_upload.rs`: remote audit metadata paths are scrubbed before upload.

## Session-worker persist path

- `apps/cli/src/daemon/session_worker/run.rs`: persisted worker result data is scrubbed through the current session redaction table before it is stored.

## Core scrub entry points

- `apps/cli/src/redact/mod.rs`: defines the `scrub`, `scrub_cow`, and table behavior every boundary above uses. It is listed so changes to the scrub entry-point file stay visible in this inventory.

## Adjacent but different mechanisms

These are not `RedactionTable::scrub` text boundaries and are intentionally excluded from the machine-checked manifest:

- `apps/cli/src/env_snapshot.rs` and `apps/cli/src/tools/bash.rs` use `env_scrub_patterns` to decide which environment variable names/values should be hidden from snapshots or shell display.
- `apps/cli/src/engine/schedule/background.rs` uses `scrub_env` to remove/sanitize background command environment variables.

## Removed

Capture-time and in-process pre-dispatch scrubs were removed from agent capture paths, child/delegation prompt paths, schedule loop/swarm/docs child prompts, background output capture, skill command output, validation hints, custom-tool diagnostics, and daemon child-steer messages. Those values remain raw locally and are covered by the dispatch or client/off-machine boundaries above.
