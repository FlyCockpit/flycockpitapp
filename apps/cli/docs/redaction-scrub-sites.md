# Redaction Scrub Site Classification

This inventory classifies every remaining production `.scrub(` call after moving transcript capture to raw storage. Test-only assertions in `src/redact/mod.rs`, `src/db/sessions.rs`, `src/daemon/session_worker.rs`, `src/daemon/server.rs`, `src/config/extended.rs`, `src/engine/model.rs`, `src/engine/driver.rs`, and `src/commands/export.rs` are excluded from the production boundary list.

## Dispatch

- `src/engine/model.rs` text completion paths: outbound one-shot model prompts are scrubbed with the model effective table immediately before provider dispatch.
- `src/engine/model.rs` `complete_captured`, `assemble_dispatch_request`, and tandem assembly: system text, history messages, prompts, assistant tool-call arguments, reasoning text, and JSON string leaves are scrubbed with the dispatching model effective table.
- `src/harness/run.rs`: harness prompts leave Cockpit for an external harness process, so this is a dispatch boundary for that provider-style execution path.

## Client Boundary

- `src/daemon/server.rs`: recursively scrubs event JSON strings for non-owner principals at socket forwarding and attach-history egress.
- `src/engine/driver.rs` `redacted_bounded_snippet`: failure diagnostics are event/display payloads, not model input; the raw failure remains local while the emitted snippet is bounded and scrubbed for client consumption.

## Off Machine

- `src/commands/export.rs`: export payloads scrub session/config/MCP/file content regardless of model trust or principal.
- `src/daemon/org_sync.rs`: organization sync JSON is scrubbed before upload.
- `src/daemon/remote_audit_upload.rs`: remote audit metadata paths are scrubbed before upload.

## Removed

Capture-time and in-process pre-dispatch scrubs were removed from `src/engine/agent.rs`, child/delegation prompt paths in `src/engine/driver.rs`, schedule loop/swarm/docs child prompts, background output capture, skill command output, validation hints, custom-tool diagnostics, and daemon child-steer messages. These values now remain raw locally and are covered by the dispatch or client/off-machine boundaries above.
