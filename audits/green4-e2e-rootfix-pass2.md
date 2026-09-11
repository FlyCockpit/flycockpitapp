# Green4 e2e root-fix pass 2

## Result

The replay/lifecycle class no longer uses an arbitrary wall-clock budget as a
durable completion oracle. The old async `wait_until` and
`wait_until_with_home` helpers and every caller remain deleted. The replay file
and lifecycle file contain no `sleep`, `Duration::from`, `wait_until`, or
budgeted `next_event` call.

Session transitions now follow one pattern:

1. attach the daemon client (which establishes the event subscription),
2. issue the mutation,
3. await an exact production event matched by session plus interrupt/call id
   and, for durable timeline completion, a non-null sequence,
4. read the relevant SQLite row once and assert it directly.

`DaemonClient::next_event_unbounded` and
`next_caffeinate_state_unbounded` read the socket stream without adding a test
wall-clock budget. A disconnected stream fails immediately. Nextest's per-test
timeout is the sole hang guard.

No wire event was added. The CLI-only integration facade now exposes the
existing `UserMessageRecorded.seq`, `ToolEnd.seq`, and `ToolError.seq` fields.

## Former poll to completion signal

| Former durable observation | Replacement completion proof | One-shot assertion after proof |
| --- | --- | --- |
| initial/open approval interrupt | subscribed exact `InterruptRaised(session_id, interrupt_id, reason=initial)` | exact interrupt row/payload |
| parked state after graceful or SIGKILL re-entry | attach first, then exact `InterruptRaised(session_id, interrupt_id, reason=rehydration)` | state is `parked`; payload and gate memo match |
| successful/failed tool audit completion | exact `ToolEnd` or `ToolError` for the session/call with `seq: Some(_)`, plus exact `InterruptResolved` for the same session/interrupt in either arrival order | audit command/output/count and interrupt `resolved` row |
| automatic gate replay completion | exact sequenced `ToolEnd`/`ToolError` for the session/call; any intervening exact interrupt is answered by id | audit output is not declined and command is exact |
| executing replay claim | exact `ToolStart(session_id, call_id)` after the parked interrupt was claimed | interrupt state is `executing` |
| executing-daemon crash reconciliation | stable child SIGKILL/reap, owned sandbox-descendant exit, daemon lifetime release, replacement boot/status handshake | interrupt state is `interrupted`; audit count remains at most one |
| duplicate resolve fully processed | enqueue a benign user message behind the duplicate on the same session-worker FIFO, then await exact `UserMessageRecorded(session_id, seq > prior high-water)` | tool audit count remains exactly one/at most one |
| restart replacement | command awaits exact predecessor child, pass-23 lifetime-lock release, and replacement status handshake | new PID differs in one read |
| stop cleanup | command awaits exact owned child and lifetime-lock-backed stop completion | PID metadata is absent in one read |
| restart while absent | completed stop witness, then replacement status handshake | command says it started an absent daemon |

The replay event helpers no longer impose the former 20-second receive budget
or the former fixed 32-event scan cap. They filter indefinitely for the exact
identity and fail only on disconnect; nextest owns the outer test deadline.

## Commit and event ordering evidence

### Tool events

For the replayed parked operation, the session worker durably changes the
interrupt to `executing` before resuming the host operation. The ordinary tool
dispatcher then emits `ToolStart` before launch, so matching `ToolStart` is a
valid boundary for the single `executing` row assertion.

Ordinary terminal sequencing needed a production correction. Previously the
dispatcher could successfully persist the `session_events` tool-call row,
fail the separate `tool_call_events` audit insert, and still emit a terminal
event carrying `Some(seq)`. That made the terminal sequence an invalid witness
for the audit table. The dispatcher now remembers the journaled audit result
and emits `ToolEnd.seq` / `ToolError.seq` as `Some` only when both the timeline
row and audit row committed. Live display delivery is retained with `seq: None`
when auditing fails.

The new unit regression
`ordinary_tool_terminal_seq_requires_committed_audit_row` installs a SQLite
`BEFORE INSERT` trigger that rejects the audit insert. It proves the ordering
edge by observing `ToolStart`, then `ToolError { seq: None }`, an empty audit
table, and a present timeline tool-call row. The existing hard-failure test now
also requires `ToolError { seq: Some(_) }` on the successful audit path.

### Interrupt and user-message events

- `InterruptRaised(initial)` is delivered from the interrupt established for
  the attached session.
- `InterruptRaised(rehydration)` is constructed from the recovered durable
  interrupt row, so it is downstream of restart reconciliation.
- `InterruptResolved` is sent after the durable resolve/complete operation.
- `UserMessageRecorded` carries the sequence returned by the committed session
  event. Because the follow-up message is queued behind the duplicate resolve
  on the same worker FIFO, its exact sequence is a deterministic
  happens-before witness rather than a negative timing window.

### Process and publication boundaries

The lifecycle harness owns the exact daemon child and the product lifetime
lock witness; it does not poll PID liveness, PID-file removal, or socket-file
absence for completion. Restart/stop command coordination awaits the command
and exact child directly. Replacement acceptance uses the production status
handshake.

The loaded selection exposed a cleanup race in `HermeticCockpit`: it captured
an `ExactProcessExit` identity only during cleanup, after a short-lived daemon
could already have exited. The harness now pins that exact identity immediately
after the successful hello and PID read, and reuses the pinned handle while
reaping. The formerly failing offline restart/resume case passes under load.

The full `daemon::server` module also exposed a socket-publication ordering
defect. Although authority recovery preceded both binds, the control endpoint
was bound before the reveal sibling. The reveal listener is now bound first;
only then is the control endpoint made observable, and the already-bound reveal
listener is handed to its accept task. This preserves the promise that a
visible control socket can provide a prompt hello.

## Subscription-before-trigger inventory

| Path | Subscription established before trigger |
| --- | --- |
| create initial parked sessions | `attach(...)` returns before `send_user_message(...)` |
| initial gate answer and inner parked interrupt | same attached client remains subscribed before `answer_interrupt_option(...)` |
| graceful/SIGKILL rehydration | replacement client calls `attach(existing_session)` before awaiting rehydration |
| approve/deny parked replay | reattached client is subscribed before `approve_*`, `answer_interrupt_option`, or `deny_interrupt` |
| executing crash path | reattached client is subscribed before approval; exact `ToolStart` is awaited before the launch barrier and SIGKILL |
| duplicate resolve barrier | the same client remains subscribed before duplicate approval and the following FIFO user message |
| history replay | replacement client subscribes through `attach(existing_session, cursor=0)` before awaiting exact `HistoryReplay(session_id)` |
| caffeinate lifecycle event | client subscription exists before `set_caffeinate`; initial snapshot is drained first |

## Failure, disconnect, shutdown, and re-entry coverage

- Failure: sequenced `ToolError` is accepted as durable completion only with
  `Some(seq)`; forced audit failure proves it becomes unsequenced.
- Disconnect: every unbounded receive returns an error immediately if the
  daemon event stream closes. Diagnostic status/log context remains on the
  interrupt wait path.
- Graceful shutdown/restart: exact predecessor retirement plus lifetime release
  and replacement status are exercised.
- SIGTERM and SIGKILL: same-home replacement tests exercise both; the executing
  replay test also proves sandbox descendants exit and replay is not repeated.
- Re-entry: open-to-parked reconciliation, parked approval, parked denial,
  automatic gate replay, duplicate resolve, restart-when-absent, and cursor-zero
  history replay are covered.

## Grep inventory

Commands:

```text
rg -n "wait_until|wait_until_with_home|next_event\\(Duration::from_secs\\(20\\)" apps/cli/tests/e2e apps/cli/src/lib.rs
rg -n "sleep|Duration::from|wait_until|wait_until_with_home|next_event\\(" apps/cli/tests/e2e/daemon_lifecycle.rs apps/cli/tests/e2e/daemon_lifecycle_replay.rs
rg -n "sleep|Duration::from" apps/cli/tests/e2e crates/cockpit-test-support
```

The first query finds unrelated PTY method names (`wait_until_screen`,
`wait_until_ready`, and `wait_until_blocking`) plus four budgeted exact-event
receives in `daemon_state_freshness.rs` / `multi_client_queue.rs`; the deleted
generic helpers and their imports/callers do not exist. The
replay/lifecycle-specific query returns zero lines.

The broad timing query returns 113 lines, reviewed line by line:

| File/group | Count | Classification |
| --- | ---: | --- |
| `support/hermetic.rs` | 22 | PTY screen/readiness/progress bounds and the production daemon hello/status handshake; no durable row/file/process predicate completion |
| `support/mod.rs` | 10 | 90/30-second production boot/restart deadline inputs, 200ms hello I/O bounds, and status-handshake boot probes |
| `support/tui_pty.rs` | 3 | PTY screen predicate backoff |
| `tui_mouse_gesture_pty.rs` | 37 | PTY rendering/input progress and negative screen-state bounds |
| `tui_pty_settings_button.rs` | 21 | PTY rendering/input progress |
| `tui_pty_mouse.rs` | 5 | PTY rendering settle/progress |
| `tui_pty_fixture.rs`, `tui_pty_paste.rs` | 1 each | PTY readiness/output bounds |
| `daemon_state_freshness.rs` | 2 | boot handshake input and exact event receive in a different class |
| `multi_client_queue.rs` | 3 | exact event receives in a different class |
| `run_noninteractive.rs` | 4 | child stdout/exit protocol bounds |
| `local_offline_acceptance.rs` | 2 | fixture mtime identity separation and PTY readiness |
| `crates/cockpit-test-support/src/provider.rs` | 2 | scripted provider delay and negative socket-read bound |

These broad-sweep remnants are outside the replay/lifecycle durable-state
completion class. None was widened or repurposed. The replay/lifecycle class
has no remaining timing-budget gap.

## Validation commands and outcomes

Every Cargo invocation below was preceded immediately by:

```text
git ls-files -z | xargs -0 touch
```

Cargo ran serially with the repository `target`, locked dependencies, and `-j3`.

### Focused regression

```text
CARGO_TARGET_DIR=target cargo nextest run --locked -p cockpit-core ordinary_tool_terminal_seq_requires_committed_audit_row -j3
```

Result: 1/1 passed (run `dd8238a7...`). The first compile attempt found a test
type mismatch (`String` versus an event enum); the test was corrected without
weakening its assertions and then passed.

### Complete replay module

```text
CARGO_TARGET_DIR=target cargo nextest run --locked -p cockpit-cli --test e2e -E 'test(/daemon_lifecycle_replay::/)' -j3
```

Result: 8/8 passed (run `492cd...`, 75.281s):

- PASS `lifecycle_graceful_park_round_trip_replays_once`
- PASS `lifecycle_sigkill_open_interrupt_reconciles_and_replays_once`
- PASS `lifecycle_auto_gate_unavailable_park_replay_runs_approved_command`
- PASS `lifecycle_auto_gate_unavailable_sigkill_park_replay_runs_approved_command`
- PASS `lifecycle_deny_round_trip_resolves_without_broadened_rerun`
- PASS `lifecycle_restart_command_preserves_parked_session_and_starts_when_absent`
- PASS `lifecycle_sigkill_executing_interrupt_reconciles_to_interrupted_without_reexecute`
- PASS `lifecycle_attach_replay_across_restart_delivers_persisted_events_once_in_order`

An earlier invocation omitted nextest's required `-E` expression flag and
selected zero tests (exit 4); the corrected command above is the result used.

### Complete core `daemon::server` module

```text
CARGO_TARGET_DIR=target cargo nextest run --locked -p cockpit-core -E 'test(/daemon::server::/)' -j3
```

The first run reported 395/396 passed and exposed
`authority_recovery_precedes_both_socket_binds`; that production bind-order
defect was fixed as described above. The complete rerun passed 396/396 (run
`15e160f3-5540-4cc8-a8c4-5fe8df01b5cf`, 277.424s; 7,987 skipped). Nextest
reported each of the 396 tests PASS. Notable requested/slow cases:

- PASS `authority_recovery_precedes_both_socket_binds` (0.018s)
- PASS `authz_default_profile_owner_traverses_every_controlled_socket_path` (209.771s)
- PASS `cancel_turn_rpc_retracts_only_reasoning_only_real_worker_turns` (6.886s)
- PASS `message_attachment_exactly_once_local_v2_replay_preserves_durable_reference` (1.623s)

### Exact 24-test loaded containment selection

The exact selection was generated from the coordinator's 24-name verify-set
with `test(=fully-qualified-name)` expressions, then run on tmpfs-backed
isolated homes with `NEXTEST_TEST_THREADS=4`:

```text
CARGO_TARGET_DIR=target NEXTEST_TEST_THREADS=4 cargo nextest run --locked \
  -p cockpit-cli -p cockpit-core -E "$FILTER" --no-fail-fast -j3 \
  --status-level pass --final-status-level fail
```

Final result: 24/24 passed, one slow, 8,802 skipped (run
`a2e2a91e-40d6-4f11-8a28-b2875c65c61e`, 238.051s):

| Test | Result |
| --- | --- |
| `agent_cli_management_socket_bind_choice_defer_rebind_yes_and_capability_matrix` | PASS 2.569s |
| `agent_cli_management_socket_default_daemon_create_list_and_collision_render_daemon_state` | PASS 1.876s |
| `agent_cli_management_socket_hard_capability_refusal_preserves_primary_and_optional_exit_codes` | PASS 1.603s |
| `agent_cli_management_socket_invalid_manifest_is_typed_and_has_zero_mutation` | PASS 2.705s |
| `agent_cli_management_socket_submit_choice_transcript_replays_the_same_receipt_once` | PASS 2.893s |
| `agent_cli_management_socket_update_targets_exact_installation_and_never_overwrites_dirty_copy` | PASS 7.249s |
| `agent_cli_management_socket_yes_only_accepts_exact_author_choice` | PASS 1.363s |
| `lifecycle_attach_replay_across_restart_delivers_persisted_events_once_in_order` | PASS 12.455s |
| `lifecycle_graceful_park_round_trip_replays_once` | PASS 12.956s |
| `restart_running_daemon_replaces_pid_and_keeps_socket_usable` | PASS 4.623s |
| `restart_when_not_running_starts_daemon` | PASS 5.155s |
| `sigkill_operation_allows_restart_against_same_home` | PASS 2.719s |
| `sigterm_operation_allows_restart_against_same_home` | PASS 2.471s |
| `spawned_daemons_are_parallel_safe` | PASS 1.442s |
| `spawned_daemon_start_status_stop_round_trip` | PASS 1.262s |
| `typed_client_sends_request_and_receives_event` | PASS 1.849s |
| `daemon_refuses_newer_migration_ledger` | PASS 1.657s |
| `isolated_settings_export_and_restart_resume_paths_execute_without_accounts` | PASS 12.946s |
| `run_approval_auto_denied` | PASS 6.321s |
| `tui_mouse_multiclick_pty` | PASS 7.092s |
| `tui_pty_fixture_failure_paths_reap` | PASS 6.370s |
| `authz_default_profile_owner_traverses_every_controlled_socket_path` | PASS 209.436s |
| `cancel_turn_rpc_retracts_only_reasoning_only_real_worker_turns` | PASS 5.277s |
| `message_attachment_exactly_once_local_v2_replay_preserves_durable_reference` | PASS 1.560s |

An earlier loaded run reached its external hang guard while the long authz case
was contending with ambient work and produced no valid summary; its two exact
isolated-home daemon children were terminated and reaped. A subsequent 24-name
run passed 23 tests but `local_offline_acceptance` aborted in the late process
identity capture race. That failure led to the stable-handle fix; the complete
24/24 rerun above is the post-fix result.

### Formatting and diff integrity

`cargo fmt --all` was run after the implementation changes. Final
`cargo fmt --all --check` passed. `git diff --check` and the staged diff check
also passed before commit.
