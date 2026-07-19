# Redaction Scrub Site Classification

This inventory classifies every production `RedactionTable::scrub` boundary and helper entry point. Test-only modules/files are excluded. Keep the machine-checked manifest in sync with the explanations below; `redact::scrub_inventory_tests::scrub_inventory_doc_matches_source_tree` fails when a production scrub file appears, disappears, or is omitted here.

## Machine-checked inventory

<!-- scrub-inventory:start -->
- Dispatch: `crates/cockpit-core/src/engine/model/dispatch.rs`, `crates/cockpit-core/src/engine/model/redact.rs`, `crates/cockpit-core/src/engine/model/outbound_guard.rs`, `crates/cockpit-core/src/embeddings.rs`, `crates/cockpit-core/src/harness/run.rs`, `crates/cockpit-core/src/knowledge.rs`
- Client boundary: `crates/cockpit-core/src/daemon/server/mod.rs`, `crates/cockpit-core/src/daemon/server/dispatch.rs`, `crates/cockpit-core/src/engine/driver/mod.rs`
- Off machine: `apps/cli/src/commands/export/mod.rs`, `crates/cockpit-core/src/daemon/org_sync.rs`, `crates/cockpit-core/src/daemon/remote_audit_upload.rs`
- Session-worker persist path: `crates/cockpit-core/src/daemon/session_worker/mod.rs`, `crates/cockpit-core/src/daemon/session_worker/run.rs`
- Core scrub entry points: `crates/cockpit-core/src/redact/mod.rs`
<!-- scrub-inventory:end -->

## Dispatch

- `crates/cockpit-core/src/engine/model/dispatch.rs`: one-shot text completions, tool/injection classifier inputs, chat dispatch, captured completion, and tandem assembly scrub system text, prompts, history messages, assistant tool-call arguments, reasoning text, and JSON string leaves immediately before provider dispatch.
- `crates/cockpit-core/src/engine/model/redact.rs`: `scrub_message` and `scrub_json_strings` implement the message/tree scrub used by dispatch.
- `crates/cockpit-core/src/engine/model/outbound_guard.rs`: shared model outbound guard for text and batch text scrubbing.
- `crates/cockpit-core/src/embeddings.rs`: embedding input text is scrubbed with `OutboundGuard::scrub_many` before the OpenAI-compatible embedding request leaves Cockpit.
- `crates/cockpit-core/src/harness/run.rs`: harness prompts leave Cockpit for an external harness process, so this is a dispatch boundary for that provider-style execution path.
- `crates/cockpit-core/src/knowledge.rs`: cited memory injected into model context and memory-search tool output are scrubbed before crossing dispatch/client-display boundaries.

## Client Boundary

- `crates/cockpit-core/src/daemon/server/mod.rs`: recursively scrubs event JSON strings for non-owner principals at socket forwarding and attach-history egress.
- `crates/cockpit-core/src/daemon/server/dispatch.rs`: applies the server scrub helpers when returning attach/list history to non-owner clients.
- `crates/cockpit-core/src/engine/driver/mod.rs`: `redacted_bounded_snippet` emits bounded, scrubbed failure diagnostics for client/display payloads while the raw failure remains local.

## Off Machine

- `apps/cli/src/commands/export/mod.rs`: export payloads scrub session/config/MCP/file content regardless of model trust or principal.
- `crates/cockpit-core/src/daemon/org_sync.rs`: organization sync JSON is scrubbed before upload.
- `crates/cockpit-core/src/daemon/remote_audit_upload.rs`: remote audit metadata paths are scrubbed before upload.

## Session-worker persist path

- `crates/cockpit-core/src/daemon/session_worker/mod.rs`: durable notice events are scrubbed through the current session redaction table before they are stored.
- `crates/cockpit-core/src/daemon/session_worker/run.rs`: persisted worker result data is scrubbed through the current session redaction table before it is stored.

## Core scrub entry points

- `crates/cockpit-core/src/redact/mod.rs`: defines the `scrub`, `scrub_cow`, and table behavior every boundary above uses. It is listed so changes to the scrub entry-point file stay visible in this inventory.

## Adjacent but different mechanisms

These are not `RedactionTable::scrub` text boundaries and are intentionally excluded from the machine-checked manifest:

- `crates/cockpit-core/src/env_snapshot.rs` and `crates/cockpit-core/src/tools/bash.rs` use `env_scrub_patterns` to decide which environment variable names/values should be hidden from snapshots or shell display.
- `crates/cockpit-core/src/engine/schedule/background.rs` uses `scrub_env` to remove/sanitize background command environment variables.

## Removed

Capture-time and in-process pre-dispatch scrubs were removed from agent capture paths, child/delegation prompt paths, schedule loop/swarm/docs child prompts, background output capture, skill command output, validation hints, custom-tool diagnostics, and daemon child-steer messages. Those values remain raw locally and are covered by the dispatch or client/off-machine boundaries above.
