# Green4 e2e root-fix pass 3 final evidence

## Result and revision boundary

All four findings carried from pass 2 are closed in the revision containing
this artifact. The parent is committed baseline `be989adc8`; the final commit
contains only the intended Rust/TypeScript source, tests, protocol fixtures,
and this audit. The `.codex-*` prompt files remain untracked and excluded.

The interrupted executing-state transition now has a real mirrored
`interrupt_interrupted { session_id, interrupt_id }` daemon event. A live
transition emits it only after the state commit succeeds. Startup
reconciliation may finish before a client exists, so attach now waits the
worker's startup reconciliation gate, establishes the event subscription, and
then replays exact `interrupted` identities read from SQLite. A replay-read
failure rejects attach instead of silently omitting the promised witness. The
SIGKILL E2E awaits the exact session and interrupt identity before its one-shot
SQLite assertion.

Foreground publication now treats control and reveal as one required pair.
Unix binds reveal before control. Windows prepares an undiscoverable random
control pipe, derives and binds reveal from that immutable name, and publishes
the control identity last. `BoundRevealSocket` owns the listener and discovery
path, so reveal is retracted on every later error and on normal shutdown.

`HermeticCockpit` now owns a `DaemonGeneration` made of an immutable daemon
receipt and production `VerifiedDaemonProcess`. It refreshes that ownership
after product restart and clears it only after successful stop, exact process
exit, and metadata retirement. Failed stop, receipt replacement, or unproved
exit preserves the entire isolated home, including the current receipt and
socket, rather than manufacturing cleanup.

## Final ledger

| ID | Final state | Closing proof |
| --- | --- | --- |
| `E2E-DURABLE-POLL` | Closed | Exact post-commit live event plus attach-time durable replay; exact-identity SIGKILL E2E passes. |
| `E2E-AUDIT-WITNESS` | Closed | `Some(seq)` still requires both timeline and audit commits; forced audit-insert failure regression passes. |
| `E2E-PUBLICATION` | Closed | Platform-specific prepare/bind/publish transaction and reveal RAII; reveal-failure and control-failure regressions pass. |
| `E2E-CONTAINMENT` | Closed | Receipt-verified current-generation ownership, restart refresh, fail-closed cleanup, metadata preservation, and repeated reap regressions pass. |

## Class sweep: E2E-DURABLE-POLL

- Scope searched: `apps/cli/tests/e2e`, the CLI event facade,
  `crates/cockpit-core/src/daemon/{registry,server,session_worker}`,
  `crates/cockpit-db/src/db/needs_attention.rs`, Rust protocol fixtures and
  remote classification, TypeScript protocol schema/fixtures, and native/web
  event consumers.
- Queries: `wait_until|wait_until_with_home`, `next_event_unbounded`,
  `InterruptInterrupted|interrupt_interrupted`, `mark_interrupt_interrupted`,
  `settle_unrecoverable_interrupt`, and `broadcast_*interrupt`.
- Affected sites: the one remaining executing-to-interrupted former poll site,
  the worker settlement edge, attach hydration, the CLI facade, Rust and
  TypeScript wire mirrors, remote transport classification, and terminal-state
  native/web/TUI consumers. The prior 13 generic durable-poll callers and both
  helper definitions remain deleted.
- Enforcement point: `settle_unrecoverable_interrupt` broadcasts only inside
  `if committed`; `Db::list_interrupted_interrupts` selects only committed
  `state = 'interrupted'` rows; registry attach first requires startup
  reconciliation; server attach installs the subscription before the durable
  replay and rejects a replay-read error.
- Verification: DB transition/query regression, committed/empty hydration
  regression, failed-settlement/no-event regression, and the real SIGKILL E2E
  all pass. The E2E matches both UUIDs before reading SQLite.
- Remaining exceptions: four budgeted exact-event waits outside these two
  lifecycle files remain in `daemon_state_freshness.rs` and
  `multi_client_queue.rs`; they do not poll SQLite, PID, or filesystem state.
  PTY readiness/screen waits are UI progress bounds. There is no remaining
  durable-state polling exception in the requested class.

### Interrupted-state coverage

| site / operation | status | evidence |
| --- | --- | --- |
| Worker settlement success / live edge | Holds | State CAS/transaction returns `committed = true` before `InterruptInterrupted` send. |
| Worker settlement failure / bypass | Holds | `committed = false` cannot enter the send branch; forced nonexistent-row regression drains the bus and finds no interrupted event. |
| Startup before subscriber | Holds | Registry requires `park_commit`; attach then installs `event_rx` and queries committed interrupted rows. |
| Attach durable replay success | Holds | Query is session-scoped, terminal-state-only, stably ordered, and emits exact row UUIDs. |
| Attach replay read failure | Holds | Error propagates through `map_err(internal)`; attach cannot claim successful hydration. |
| Empty/default attach | Holds | Open row emits no interrupted event in hydration regression. |
| Re-entry after SIGKILL | Holds | E2E awaits exact `session_id` plus `interrupt_id`, then performs one row read and proves no re-execution. |
| Duplicate attach/re-entry | Holds | Durable terminal rows may be rehydrated again by design; consumers terminalize idempotently by interrupt ID. |
| Disconnect/timeout | Holds | Unbounded event receive fails on stream disconnect; nextest is the outer hang guard, not product/test polling. |
| Rust wire and CLI/TUI consumers | Holds | Event enum/tag fixture, CLI conversion, run routing, server redaction match, and TUI exhaustive matches include the variant. |
| TypeScript mirror/native/web consumers | Holds | Zod schema/discriminant, daemon-wire fixture, remote classification fixture, native reducer, and web store tests include the variant. |

## Class sweep: E2E-AUDIT-WITNESS

- Scope searched: ordinary tool terminal dispatch, tool audit insertion,
  `ToolEnd`/`ToolError` sequence construction, CLI mapping, and lifecycle replay
  consumers.
- Queries: `ordinary_tool_terminal_seq_requires_committed_audit_row`,
  `tool_call_seq`, `audit`, `ToolEnd`, and `ToolError` within the dispatcher and
  replay test.
- Affected sites: one ordinary terminal sequencing funnel, shared by success
  and failure terminal events. This funnel is the full class in goal scope.
- Enforcement point: a terminal event carries `Some(seq)` only when the
  timeline row and the separate tool audit row both committed. Live delivery
  remains possible with `seq: None` when auditing fails.
- Verification: `ordinary_tool_terminal_seq_requires_committed_audit_row`
  forces audit insertion failure and observes an unsequenced terminal event,
  an empty audit table, and the retained timeline row. It passes in the final
  focused selection.
- Remaining exceptions: none in the ordinary tool dispatcher. Specialized
  event producers are distinct contracts and were not broadened.

### Audit-witness coverage

| site / operation | status | evidence |
| --- | --- | --- |
| Timeline plus audit success | Holds | Existing success path emits `Some(seq)` and loaded replay cases pass. |
| Audit failure after timeline success | Holds | Forced SQLite trigger failure yields `seq: None` and no audit row. |
| Timeline failure | Holds | No timeline sequence exists, so `Some(seq)` cannot be emitted. |
| Success/error consumers | Holds | Replay accepts `ToolEnd` or `ToolError` only with non-null sequence before one-shot audit reads. |

## Class sweep: E2E-PUBLICATION

- Scope searched: every `bind_reveal_socket`, `bind_private_socket`,
  `NamedPipeListener::{bind,bind_named,prepare,prepare_named,publish}` call,
  foreground startup, early returns, accept-task ownership, and shutdown.
- Queries: `bind_reveal_socket|BoundRevealSocket`, `prepare_and_publish_socket_pair`,
  `publish_socket_pair_with`, `write_pipe_identity`, and
  `leak_reveal_socket` across `cockpit-core` and `cockpit-host`.
- Affected sites: one foreground control/reveal publication funnel, plus the
  Windows listener primitive it uses. Other one-endpoint `bind` callers retain
  the original prepare-plus-publish behavior.
- Enforcement point: Unix pair helper binds required reveal before calling the
  control publisher. Windows pair helper owns a prepared, undiscoverable
  control listener, binds reveal from its immutable name, and writes control
  identity last. Any `?` after reveal construction drops `BoundRevealSocket`,
  closing the endpoint before unlinking its identity path.
- Verification: `foreground_required_reveal_bind_failure_prevents_control_publication`,
  `control_bind_failure_drops_bound_reveal_owner`, and the structural authority
  order test pass; the complete 396-test server module passes. Windows-specific
  tests compile under their target cfg but were not executable on this Linux
  host.
- Remaining exceptions: none. Reveal is now required rather than warning-only;
  no successful foreground publication can omit it.

### Publication coverage

| site / operation | status | evidence |
| --- | --- | --- |
| Boot/recovery entry | Holds | Authority and journal recovery structurally precede both endpoint binds. |
| Unix success | Holds | Reveal bind succeeds, then control bind is the final startup publication. |
| Windows success | Holds | Random control pipe is prepared without identity, reveal sibling binds, then control identity publishes. |
| Required reveal failure / bypass | Holds | Control closure is never invoked; both paths remain absent in regression. |
| Control bind/publication failure | Holds | Reveal owner drops and path is absent/rebindable; Windows counterpart blocks identity publication and asserts reveal retraction. |
| Accept-loop handoff | Holds | `BoundRevealSocket` moves into the reveal task; there is exactly one owner. |
| Normal shutdown | Holds | Foreground task is aborted/joined; its owned listener drops and removes discovery metadata. |
| Panic/early return | Holds | RAII owns listener plus path; cleanup is not deferred to only the happy-path tail. |
| Re-entry after failed publication | Holds | Unix regression rebinds the same reveal path after cleanup. |

## Class sweep: E2E-CONTAINMENT

- Scope searched: every `HermeticCockpit` process-identity field assignment and
  take, all daemon start/restart/stop calls, `local_offline_acceptance`, drop,
  repeated reap, metadata unlink sites, and production daemon receipt/process
  verification APIs in `cockpit-host`.
- Queries: `daemon_generation|daemon_exit|daemon_pid`, `restart_daemon|daemon restart`,
  `try_reap|assert_reaped`, `acquire_verified_daemon_process|has_exited`, and
  `remove_file.*socket` in the e2e support tree.
- Affected sites: initial Hermetic daemon capture, the sole product-restart
  consumer (`local_offline_acceptance`), explicit cleanup, unwind/drop cleanup,
  repeated reap, and platform implementations of non-consuming exact exit
  observation. The former raw-PID `ExactProcessExit` mechanism is deleted.
- Enforcement point: capture reads a receipt, acquires the production verified
  process handle, rereads the same receipt, validates a daemon hello with the
  receipt PID, and rereads again. Restart retains the predecessor witness until
  exact exit is observed and only then installs the replacement. Cleanup
  verifies the current receipt, requires a successful stop result, requires
  exact process exit, requires PID/socket metadata absence, and only then clears
  ownership. Drop preserves the complete isolated home on any failure.
- Verification: restart-refresh/repeated-reap and launch-failure/nonzero-stop/
  replaced-receipt regressions pass; the loaded `local_offline_acceptance` case
  passes after a real product restart. Same-home SIGTERM/SIGKILL restart tests
  also pass.
- Remaining exceptions: unsupported non-Unix/non-Windows platforms retain the
  prior best-effort fallback under a narrow cfg and cannot claim receipt-bound
  ownership; the supported CI/desktop targets Linux, macOS, FreeBSD, and Windows
  use the verified-generation path. No supported-target exception remains.

### Containment coverage

| site / operation | status | evidence |
| --- | --- | --- |
| Initial capture | Holds | Immutable receipt + verified kernel process identity + exact hello, fenced by two receipt rereads. |
| PID recycling/replacement during capture | Holds | Receipt mismatch or non-daemon identity rejects capture without replacing the prior witness. |
| Product restart exit | Holds | Restart command and status handshake complete; predecessor `has_exited` must succeed before ownership swaps. |
| Restart re-entry consumer | Holds | `local_offline_acceptance` calls `restart_daemon`, which refreshes generation before continuing. |
| Stop launch error | Holds | Error returns with receipt, socket, PID, and witness intact. |
| Stop nonzero result | Holds | Regression uses exit 7 and proves metadata/witness remain intact. |
| Stop reports success but exact exit is unproved | Holds | Cleanup fails closed before clearing ownership or touching metadata. |
| Receipt replaced before stop | Holds | Exact receipt comparison rejects cleanup; current metadata is preserved. |
| Cancellation/unwind | Holds | Drop invokes the same checked cleanup; on failure `TempDir::keep` prevents implicit tree deletion. |
| Repeated reap | Holds | First successful reap clears current ownership; subsequent call is an idempotent no-op. |
| Final assertions | Holds | Exact process is dead and current PID/socket metadata must both be absent; absence cannot be manufactured locally. |

## Ownership and ordering

No serial mutex or timing mechanism was added.

- Interrupted event ordering: the SQLite transition owns durability. The live
  event has no permit to publish until the commit returns true. On restart,
  registry attach waits the shared startup-reconciliation completion, then the
  server installs the per-client subscription, reads terminal rows, publishes
  them, and only then completes hydration. A terminal state is evidence in the
  ledger, not a lock; the registry's existing worker-generation/attach permits
  remain the concurrency authority.
- Socket publication ownership: foreground boot holds the existing lifecycle
  metadata guard. Prepared control listener ownership precedes reveal listener
  ownership; reveal ownership precedes control identity publication. After
  publication, the control listener stays in the foreground accept loop and
  the reveal owner moves into its task. Shutdown joins tasks before metadata
  retirement. `BoundRevealSocket` cleanup is independent of terminal state.
- Hermetic process ownership: `DaemonGeneration` exclusively owns the receipt
  and stable process witness. Receipt verification occurs before any stop or
  cleanup effect. Replacement order is product restart/status, capture current
  receipt/process/hello, prove predecessor exit, then swap. Cleanup order is
  exact-receipt check, product stop, exact exit proof, product metadata absence,
  then clear harness ownership. The harness adds no lock; product lifecycle
  commands retain their established lifecycle-transaction then lifetime-lock
  order.

Crash/restart durable intent is explicit: `needs_attention.state =
'interrupted'` commits before either the live or attach-replay event; reveal is
fully bound before the recoverable external effect of control readiness; the
daemon receipt is durable and reverified before the harness may act on a
process generation.

## Inventory completeness

Final search results:

- `rg "wait_until|wait_until_with_home" apps/cli/tests/e2e apps/cli/src/lib.rs`
  finds only unrelated PTY method names; the deleted generic helpers and all 13
  callers remain absent.
- The lifecycle-specific search over `daemon_lifecycle.rs` and
  `daemon_lifecycle_replay.rs` for
  `sleep|Duration::from|wait_until|wait_until_with_home|next_event\(` finds no
  sleep, fixed work wait, or durable predicate polling. Event reads are the
  unbounded exact-identity helper.
- Repository search for `InterruptInterrupted|interrupt_interrupted` finds the
  Rust event/tag and fixture, live and hydration publishers, CLI/TUI mappings,
  remote classification, TypeScript schema/fixture, and native/web reducers and
  tests. Pre-existing DB settlement calls outside the daemon worker do not own
  a client socket and remain storage-only paths; the requested daemon crash
  reconciliation funnel is fully covered.
- Diff-added forbidden-mechanism search finds no retry, sleep, serial mutex,
  `#[ignore]`, or product `cfg(test)`/environment hook. The two new 200ms reads
  are existing-protocol bounded hello I/O used while receipt identity is held,
  not completion polling or a fixed wait for work.
- Publication search finds one foreground pair funnel. Containment search finds
  one `HermeticCockpit` restart consumer and no remaining raw-PID witness.

## Validation

Every Cargo invocation was immediately preceded by exactly:

```text
git ls-files -z | xargs -0 touch
```

Cargo validation ran one invocation at a time, locked, with the repository
`target`, targeted packages/tests only, and `-j 3`. The exact loaded run used
`TMPDIR=/dev/shm` and `NEXTEST_TEST_THREADS=4`.

### Focused production regressions

Core/database filter result: 7/7 passed, 9,235 skipped, run
`46ef5dca-20d1-4049-9d9b-af1633347ee4`.

| Test | Result |
| --- | --- |
| `daemon::server::tests::authority_recovery_precedes_both_socket_binds` | PASS 0.021s |
| `daemon::tests::control_bind_failure_drops_bound_reveal_owner` | PASS 0.019s |
| `daemon::tests::foreground_required_reveal_bind_failure_prevents_control_publication` | PASS 0.017s |
| `daemon::session_worker::tests::failed_interrupt_settlement_does_not_emit_interrupted_event` | PASS 0.464s |
| `daemon::session_worker::tests::interrupted_interrupt_hydration_requires_and_replays_committed_state` | PASS 0.466s |
| `engine::agent::tool_dispatch::tests::ordinary_tool_terminal_seq_requires_committed_audit_row` | PASS 0.539s |
| `db::needs_attention::tests::executing_interrupt_can_be_marked_interrupted_and_reconciled` | PASS 0.426s |

CLI E2E filter result: 3/3 passed, 80 skipped, run
`ae7ada37-a961-465d-b9cd-640c76963ce6`.

| Test | Result |
| --- | --- |
| `support::hermetic::generation_tests::stop_failure_and_replaced_receipt_preserve_current_metadata` | PASS 1.405s |
| `support::hermetic::generation_tests::product_restart_refreshes_verified_generation_and_reaps_repeatedly` | PASS 2.935s |
| `daemon_lifecycle_replay::lifecycle_sigkill_executing_interrupt_reconciles_to_interrupted_without_reexecute` | PASS 11.389s |

An earlier exact filter omitted the `support::` prefix and selected only the
SIGKILL E2E (which passed); the corrected 3/3 run above is the final evidence.

### Complete core server module

```text
CARGO_TARGET_DIR=target cargo nextest run --locked -p cockpit-core \
  -E 'test(/daemon::server::/)' -j 3 --no-fail-fast \
  --status-level pass --final-status-level fail
```

Result: 396/396 passed, 7,990 skipped, run
`a4b08223-d983-4a3e-8354-4b457d161df2`, 244.555s. Slow cases:

- `dispatch_matrix_mutating_dispatch_cases_traverse_socket_path`: PASS 139.019s.
- `authz_default_profile_owner_traverses_every_controlled_socket_path`: PASS 212.162s.

### Exact 24-name loaded selection

```text
TMPDIR=/dev/shm CARGO_TARGET_DIR=target NEXTEST_TEST_THREADS=4 \
  cargo nextest run --locked -p cockpit-cli -p cockpit-core \
  -E "$FILTER" --no-fail-fast -j 3 \
  --status-level pass --final-status-level fail
```

Result: 24/24 passed, one slow, 8,807 skipped, run
`76ba33a0-f48a-4b95-a4d3-11904727dbd4`, 207.582s.

| Exact test name | Result |
| --- | --- |
| `agent_management::agent_cli_management_socket_hard_capability_refusal_preserves_primary_and_optional_exit_codes` | PASS 1.903s |
| `agent_management::agent_cli_management_socket_default_daemon_create_list_and_collision_render_daemon_state` | PASS 2.278s |
| `agent_management::agent_cli_management_socket_bind_choice_defer_rebind_yes_and_capability_matrix` | PASS 2.899s |
| `agent_management::agent_cli_management_socket_invalid_manifest_is_typed_and_has_zero_mutation` | PASS 1.294s |
| `agent_management::agent_cli_management_socket_submit_choice_transcript_replays_the_same_receipt_once` | PASS 1.886s |
| `agent_management::agent_cli_management_socket_yes_only_accepts_exact_author_choice` | PASS 1.471s |
| `daemon_lifecycle::restart_running_daemon_replaces_pid_and_keeps_socket_usable` | PASS 4.350s |
| `daemon_lifecycle::restart_when_not_running_starts_daemon` | PASS 4.471s |
| `agent_management::agent_cli_management_socket_update_targets_exact_installation_and_never_overwrites_dirty_copy` | PASS 6.479s |
| `daemon_lifecycle::spawned_daemon_start_status_stop_round_trip` | PASS 1.259s |
| `daemon_lifecycle::sigkill_operation_allows_restart_against_same_home` | PASS 2.472s |
| `daemon_lifecycle::spawned_daemons_are_parallel_safe` | PASS 1.357s |
| `daemon_lifecycle::sigterm_operation_allows_restart_against_same_home` | PASS 2.887s |
| `daemon_lifecycle::typed_client_sends_request_and_receives_event` | PASS 1.632s |
| `daemon_state_freshness::daemon_refuses_newer_migration_ledger` | PASS 1.560s |
| `run_noninteractive::run_approval_auto_denied` | PASS 6.214s |
| `daemon_lifecycle_replay::lifecycle_attach_replay_across_restart_delivers_persisted_events_once_in_order` | PASS 12.346s |
| `tui_mouse_gesture_pty::tui_mouse_multiclick_pty` | PASS 7.155s |
| `local_offline_acceptance::isolated_settings_export_and_restart_resume_paths_execute_without_accounts` | PASS 14.484s |
| `daemon_lifecycle_replay::lifecycle_graceful_park_round_trip_replays_once` | PASS 10.453s |
| `tui_pty_fixture::tui_pty_fixture_failure_paths_reap` | PASS 8.136s |
| `daemon::server::tests::message_attachment_exactly_once_local_v2_replay_preserves_durable_reference` | PASS 1.764s |
| `daemon::server::tests::cancel_turn_rpc_retracts_only_reasoning_only_real_worker_turns` | PASS 5.270s |
| `daemon::server::tests::authz_default_profile_owner_traverses_every_controlled_socket_path` | PASS 180.465s |

### Protocol mirrors and consumers

- `packages/cockpit-protocol`: `vitest run src/index.test.ts
  src/remote-transport-lanes.test.ts` — 2 files, 84/84 tests passed.
- `apps/native`: `vitest run utils/session-events.test.ts` — 28/28 passed.
- `apps/web`: `vitest run src/stores/remote-sessions.test.ts` — 55/55
  passed; the runner emitted the pre-existing route-file warning only.
- Rust event fixture and wire-tag tests are gated behind the `remote` feature.
  Two targeted Cargo attempts could not reach them because unrelated existing
  feature-matrix compilation is broken: `remote,extended` reports four
  `ConditionalScheduledJob<()>` versus `ConditionalScheduledJobRow` errors in
  `cockpit-db/src/db/scheduler.rs`; `remote` reports the existing missing
  `CanonicalFcorValueV1`/request-macro errors (37 errors). A default-feature
  exact selection consequently selected zero tests because those tests are
  feature-gated. This is the only validation gap. The changed Rust event enum,
  tag, fixture, CLI/core/TUI consumers compiled in the passing core/CLI runs,
  and the cross-language fixture content/classification passed all 84 mirror
  tests.

### Final integrity

`cargo fmt --all` was run after the last Rust source edit. The final
`cargo fmt --all --check`, `git diff --check`, staged-path inventory, staged
diff check, and prompt-exclusion checks are recorded immediately before the
commit containing this artifact.
