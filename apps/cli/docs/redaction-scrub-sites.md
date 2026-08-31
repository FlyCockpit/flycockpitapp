# Internal: Redaction Scrub Site Classification

This inventory classifies every production `RedactionTable::scrub` boundary and helper entry point. Test-only modules/files are excluded. Keep the machine-checked manifest in sync with the explanations below; `redact::scrub_inventory_tests::scrub_inventory_doc_matches_source_tree` fails when a production scrub file appears, disappears, or is omitted here.

## Machine-checked inventory

<!-- scrub-inventory:start -->
- Dispatch: `crates/cockpit-core/src/engine/model/dispatch.rs`, `crates/cockpit-core/src/engine/model/mod.rs`, `crates/cockpit-core/src/engine/model/redact.rs`, `crates/cockpit-core/src/engine/model/outbound_guard.rs`, `crates/cockpit-core/src/engine/model_roles.rs`, `crates/cockpit-core/src/embeddings.rs`, `crates/cockpit-core/src/harness/run.rs`, `crates/cockpit-core/src/knowledge.rs`, `crates/cockpit-core/src/knowledge/dream.rs`, `crates/cockpit-core/src/mcp/builtin.rs`, `crates/cockpit-core/src/skills/auto_select/mod.rs`, `crates/cockpit-core/src/tools/edit.rs`, `crates/cockpit-core/src/tools/skill.rs`, `crates/cockpit-core/src/tools/read.rs`, `crates/cockpit-core/src/tools/recall.rs`, `crates/cockpit-core/src/tools/session_search.rs`, `crates/cockpit-core/src/tools/write.rs`, `crates/cockpit-core/src/engine/agent/tool_dispatch.rs`, `crates/cockpit-core/src/engine/verification/intercept.rs`
- Client boundary: `apps/cli/src/commands/debug.rs`, `crates/cockpit-core/src/daemon/server/mod.rs`, `crates/cockpit-core/src/daemon/fs_api.rs`
- Off machine: `crates/cockpit-core/src/session/export/mod.rs`, `crates/cockpit-core/src/daemon/org_sync.rs`, `crates/cockpit-core/src/daemon/remote_audit_upload.rs`
- Session-worker persist path: `crates/cockpit-core/src/daemon/session_worker/mod.rs`, `crates/cockpit-core/src/daemon/session_worker/run.rs`, `crates/cockpit-core/src/engine/driver/mod.rs`, `crates/cockpit-core/src/engine/rehydrate.rs`, `crates/cockpit-core/src/session/recording.rs`
- Core scrub entry points: `crates/cockpit-core/src/redact/mod.rs`
<!-- scrub-inventory:end -->

## Dispatch

- `crates/cockpit-core/src/engine/model/dispatch.rs`: one-shot text completions, tool/injection classifier inputs, chat dispatch, captured completion, and tandem assembly scrub system text, prompts, history messages, assistant tool-call arguments, reasoning text, and JSON string leaves immediately before provider dispatch.
- `crates/cockpit-core/src/engine/model/mod.rs`: `SessionRedactionRendering::render_redacted` is the untrusted-custody rendering the model-construction path hands to the typed policy request; it scrubs through the session redaction table, and it is the only rendering an untrusted route can produce (there is no raw variant).
- `crates/cockpit-core/src/engine/model/redact.rs`: `scrub_message` and `scrub_json_strings` implement the message/tree scrub used by dispatch.
- `crates/cockpit-core/src/engine/model/outbound_guard.rs`: shared model outbound guard for text and batch text scrubbing.
- `crates/cockpit-core/src/engine/model_roles.rs`: `SessionTableRedaction::render_redacted` and `DelegationCustody::render_brief` scrub delegated child/subagent briefs through the session redaction table before an untrusted delegation target receives them.
- `crates/cockpit-core/src/embeddings.rs`: embedding input text is scrubbed with `OutboundGuard::scrub_many` before the OpenAI-compatible embedding request leaves Cockpit.
- `crates/cockpit-core/src/harness/run.rs`: harness prompts leave Cockpit for an external harness process, so this is a dispatch boundary for that provider-style execution path.
- `crates/cockpit-core/src/knowledge.rs`: cited memory injected into model context and memory-search tool output are scrubbed before crossing dispatch/client-display boundaries.
- `crates/cockpit-core/src/mcp/builtin.rs`: adapted native tool output is scrubbed before it crosses into the Monty builtin MCP result path.
- `crates/cockpit-core/src/skills/auto_select/mod.rs`: auto-selected skill headers scrub package directories before folded skill bodies enter model context.
- `crates/cockpit-core/src/tools/skill.rs`: manually loaded skill and support-file headers scrub package directories before returning tool output.
- `crates/cockpit-core/src/tools/read.rs`: approved reads that add persisted environment-derived redaction metadata re-scrub the returned tool output with the updated table before it reaches model context.
- `crates/cockpit-core/src/tools/recall.rs`: the `cockpit://` provider re-scrubs transcript, compaction, plan, and artifact content before page or single-pseudofile grep output is returned, so archive-imported artifacts and recall results obey the current session's redaction table.
- `crates/cockpit-core/src/engine/agent/tool_dispatch.rs`: durable text-artifact captures scrub through the session redaction table before admission so persisted/retrievable tool bodies never store pre-safety secret bytes.
- `crates/cockpit-core/src/engine/verification/intercept.rs`: verification intercept projections scrub JSON string leaves through the session redaction table before they are persisted as model-visible ledger envelopes.

## Client Boundary

- `apps/cli/src/commands/debug.rs`: assembled-context diagnostics are scrubbed and bounded before they are printed to the local client.
- `crates/cockpit-core/src/daemon/server/mod.rs`: recursively scrubs event JSON strings for non-owner principals at socket forwarding and attach-history egress, including the attach/list history helpers dispatch invokes.
- `crates/cockpit-core/src/daemon/fs_api.rs`: owner settings projections scrub secret literals to opaque per-occurrence placeholders before typed config leaves the daemon.

## Off Machine

- `crates/cockpit-core/src/session/export/mod.rs`: export payloads scrub session/config/MCP/file content regardless of model trust or principal.
- `crates/cockpit-core/src/daemon/egress.rs`: connector-gated first-party requests recheck remote consent and load each session's persisted redaction table fail-closed.
- `crates/cockpit-core/src/daemon/org_sync.rs`: organization sync JSON is scrubbed before upload.
- `crates/cockpit-core/src/daemon/remote_audit_upload.rs`: remote audit metadata paths are scrubbed before upload.

## Session-worker persist path

- `crates/cockpit-core/src/daemon/session_worker/mod.rs`: durable notice events are scrubbed through the current session redaction table before they are stored.
- `crates/cockpit-core/src/daemon/session_worker/run.rs`: persisted worker result data is scrubbed through the current session redaction table before it is stored.
- `crates/cockpit-core/src/engine/driver/mod.rs`: the recent root-turn transcript captured as goal "worker evidence" is scrubbed through the session redaction table before it is persisted as durable goal-root-turn evidence.
- `crates/cockpit-core/src/engine/rehydrate.rs`: rehydrated text-artifact bodies and durable preview head/tail are scrubbed through the session redaction table before reconstructed history re-enters model context, including archive-imported artifacts that bypassed the live scrub boundary at capture time.
- `crates/cockpit-core/src/session/recording.rs`: the fail-closed JSON scrub (`scrub_matched_literals_in_json`/`scrub_scalar_leaf`) walks parsed event JSON leaves through an enforcing redaction table before a recorded session event is persisted, keeping the scrub JSON-escape-safe and never copying matched secret bytes into its output.

## Core scrub entry points

- `crates/cockpit-core/src/redact/mod.rs`: defines the `scrub`, `scrub_cow`, and table behavior every boundary above uses. It is listed so changes to the scrub entry-point file stay visible in this inventory.

## Adjacent but different mechanisms

These are not `RedactionTable::scrub` text boundaries and are intentionally excluded from the machine-checked manifest:

- `crates/cockpit-core/src/env_snapshot.rs` and `crates/cockpit-core/src/tools/bash.rs` use `env_scrub_patterns` to decide which environment variable names/values should be hidden from snapshots or shell display.
- `crates/cockpit-core/src/engine/schedule/background.rs` uses `scrub_env` to remove/sanitize background command environment variables.

## Removed

Capture-time and in-process pre-dispatch scrubs were removed from agent capture paths, child/delegation prompt paths, schedule loop/swarm/docs child prompts, background output capture, skill command output, validation hints, custom-tool diagnostics, and daemon child-steer messages. Those values remain raw locally and are covered by the dispatch or client/off-machine boundaries above.
