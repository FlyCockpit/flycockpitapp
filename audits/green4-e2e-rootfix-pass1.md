# Green4 e2e root-fix final coverage

Baseline: `0b3ca2a4b`. Review base for the platform-gate inventory:
`origin/green-the-rust-4`. Scope: STEP0-F1 through STEP0-F4 plus independent
review findings R1-R6. Final-review pass 4 baseline: `4ddf6b6be`.

## Final-review pass 4 invariant coverage

| Site / operation | Result | Evidence |
| --- | --- | --- |
| async HermeticCockpit Secret Service entry / shutdown | holds | the sole async consumer awaits `enable_isolated_secret_service_async`, then awaits consuming `finish`; the service owner join acknowledges dbus kill+wait before isolated-home Drop |
| sync fixture consumer / panic bypass | holds | the sync consumer retains the sync starter; MockSecretService Drop sends stop and joins the owner rather than detaching cleanup |
| startup lifetime entry / competing owner / re-entry | holds | both foreground and metadata-guard acquisition use one nonblocking advisory-lock attempt; a typed `Busy` result terminates competing startup, while acquisition succeeds after exact owner Drop |
| foreground publication and bind failures | holds | both fallible operations precede every task spawn; endpoint cleanup is armed only after successful publication, so publication failure retires the PID without claiming a pre-existing path and bind failure retracts the generation's publication |
| foreground normal exit / task failure / panic | holds | every owned task is abort-on-Drop; accept join errors flow through the one epilogue, which aborts and awaits all remaining tasks before metadata retirement |
| Stop connected / unreachable fallback / release | holds | one deadline is created before path resolution; connect, request, platform stop, and release observation each consume only its remaining duration |
| Restart discovery / connected / unreachable fallback / release / re-entry | holds | discovery, connect, request, platform stop, and release observation use the same deadline; replacement spawn happens only after exact release success |

Ownership and order for pass 4: lifetime lock precedes the short lifecycle
metadata transaction. Foreground task guards are declared after the metadata
guard, so unwind aborts every task before metadata/lifetime fields drop; the
ordinary epilogue additionally awaits cancellation acknowledgments before
retirement. Endpoint ownership is attached to the metadata guard only after
durable endpoint publication succeeds. The mock service owner thread alone
owns dbus and its child; async fixture completion consumes and joins that owner
before the isolated home can drop. Stop/restart own one immutable deadline;
downstream operations receive durations derived from it and cannot replenish
the budget.

## Final-review pass 4 class sweeps

### R8 — async fixture startup and teardown

Class sweep: searched `apps/cli/tests/e2e` for
`enable_isolated_secret_service`, `start_mock_secret_service`, `shutdown`, and
HermeticCockpit Drop. Affected sites: one sync local-offline case, one Tokio
local-offline case, the Hermetic fixture, and MockSecretService Drop.
Enforcement point: mode-specific fixture entry plus consuming awaited `finish`;
Drop is a deterministic unwind fallback. Verification: exact mock current-thread
async shutdown and exact requested local-offline test. Remaining exceptions:
none in the HermeticCockpit consumer set.

### R9 — post-spawn foreground failure

Class sweep: searched the complete `run_foreground_inner_with_boot_db` body for
task creation, endpoint publication, control/reveal binds, `?`, return, cleanup,
and every JoinHandle. Affected sites: publication/bind ordering and the accept
join `?`; all nine feature-inclusive task categories share `ForegroundTask`.
Enforcement point: pre-spawn publication barrier, abort-on-unwind task owner,
and one explicit abort-and-await epilogue. Verification: natural endpoint
publication failure and overlong Unix control-bind failure plus existing clean
shutdown coverage. Remaining exception: reveal bind remains intentionally
nonfatal and therefore is not an exit bypass.

### R10 — startup lifetime acquisition

Class sweep: searched the workspace for `acquire_daemon_lifetime`, blocking
`flock`/`LockFileEx`, lifetime capture, and release acquisition. Affected sites:
the host primitive and its two production consumers. Enforcement point: one
`LOCK_NB`/`LOCKFILE_FAIL_IMMEDIATELY` acquisition returning typed `Busy`.
Verification: live competing owner on a current-thread runtime and successful
re-entry after exact owner release. Remaining exception: release observation
retains its specified exact-process-exit then one nonblocking acquisition.

### R11 — one command-level lifecycle deadline

Class sweep: searched CLI Stop/Restart and core Linux, macOS/FreeBSD, and
Windows platform-stop routes for `restart_release_timeout`, connect, discovery,
request, platform wait, and release wait. Affected sites: both CLI commands and
all three stable-handle platform backends. Enforcement point: one entry deadline,
`remaining_command_budget`, and `stop_with_timeout`. Verification: operation
budget consumption/expiry unit coverage plus connected Stop/Restart and
unreachable Stop/Restart e2e. Remaining exceptions: non-command automatic
promotion/skew workflows own distinct lifecycle transactions and are outside
the command-level deadline.

## Invariant coverage

| Site / operation | Result | Evidence |
| --- | --- | --- |
| foreground daemon boot / publication | holds | `lifetime.lock` is acquired before the short `lifecycle.lock` PID reservation; product ownership is immediately transferred to kernel process teardown, while injected in-process ownership remains RAII-scoped |
| foreground shutdown / early return / panic | holds | signal, lifecycle, lock-sweeper, remote, and reveal tasks are abort-and-await joined before exact metadata retirement; cleanup never releases lifetime ownership, and every product return/panic path remains locked until process teardown |
| socket Stop / fallback Stop | holds | both capture the predecessor before requesting shutdown and report success only after exact-process completion, the final lifetime-lock acquisition, and PID/socket retirement; e2e removes the live socket to exercise the SIGTERM fallback |
| socket Restart / fallback Restart / re-entry | holds | both stop paths consume the same release witness before spawning; replacement cannot be mistaken for the predecessor because process identity is pinned before shutdown and the final nonblocking lock acquisition fails closed if a replacement already owns the path |
| release success / failure / timeout / cancellation | holds | Linux pidfd, macOS/FreeBSD kqueue, or Windows process HANDLE is captured before shutdown; the platform deadline is internal to the wait; only after exact exit does one nonblocking `flock`/`LockFileEx` acquisition occur, so timeout/cancellation leaves no indefinitely blocked lifetime-lock worker |
| production restart release deadline | holds | `restart_release_timeout` is exactly 30 seconds for default, zero, ordinary explicit, and maximum accepted drain values; daemon graceful-drain configuration is otherwise unchanged |
| hermetic daemon reap, Linux | holds | pidfd is captured before stop and polled to exact exit |
| hermetic daemon reap, macOS/FreeBSD | holds | kqueue is captured before stop, registers `EVFILT_PROC` + `NOTE_EXIT` + `EV_ONESHOT`, and blocking `kevent` consumes that exact registration |
| hermetic daemon reap, Windows | holds | a `SYNCHRONIZE` process HANDLE is opened before stop and consumed by `WaitForSingleObject` |
| mock Secret Service setup, sync | holds | the caller only receives mode-specific readiness; dbus lookup/spawn/stdout read, zbus build, runtime, child, and cleanup are owned by one dedicated thread |
| mock Secret Service setup, current-thread async | holds | work before the first await is channel creation and thread spawn only; readiness is a Tokio oneshot and no runtime worker blocks |
| mock Secret Service receiver drop / shutdown | holds | required async ownership awaits `shutdown`, whose join runs off the Tokio worker and returns an asserted termination ack after the owner killed/waited for dbus; the sync test asserts the equivalent blocking ack; Drop synchronously joins as the deterministic panic fallback |
| replay launch / durable crash boundary | holds | Unix FIFO and Windows named-pipe barriers remain platform-owned; durable `executing` is asserted before the witness and daemon termination occurs only after the byte |
| replay/validation descendant cleanup | holds | Linux pidfd/cgroup evidence, non-Linux Unix process-group empty evidence, and Windows Job Object empty evidence remain the relevant platform witnesses |

Ownership and ordering: the product daemon owns `lifetime.lock` until kernel
process teardown, including after explicit metadata cleanup. It acquires
lifetime before lifecycle and, on shutdown, takes lifecycle only long enough to
retire metadata without releasing lifetime. Injected in-process daemons retain
RAII ownership and release only after their supervisor/task shutdown boundary.
A restart observer opens the lifetime file and captures the exact process handle
before the stop effect. It awaits exact process completion, performs one final
nonblocking lifetime acquisition, and only then checks metadata. The Secret
Service owner thread exclusively owns its dbus child and runtime; callers own
only stop/readiness endpoints and the join handle, with no shared lock order.
Async callers await the explicit shutdown boundary before fixture teardown.

## Class sweeps

### R1/F1 — lifecycle success before release

Class sweep: searched `apps/cli/src/commands/daemon.rs`, core lifecycle callers,
and e2e support with `rg -n 'capture_restart_release|wait_for_restart_release|daemon::stop'`.
Affected sites were CLI Stop fallback and the already-waiting Stop socket,
Restart socket, and Restart fallback paths. Enforcement is the shared core
release witness. Verification covers socket Stop/Restart and a removed-socket
fallback Stop. Remaining exception: a missing or unverified capture fails
closed rather than claiming success.

### R2/F3 — blocking/racy mock Secret Service

Class sweep: searched all `MockSecretService`, `start_mock_secret_service`,
`block_on`, readiness, child `kill`/`wait`, and `JoinHandle::join` sites under
`apps/cli/tests/e2e`. The two public startup modes and Drop were affected.
Enforcement is single-thread ownership plus mode-specific readiness and an
explicit async `shutdown` boundary. The sole async caller awaits stop and owner
join; exact sync, current-thread async, and local-offline acceptance tests verify
the consumers. There is no product hook; Drop synchronously joins only as the
panic/unwind fallback where an async boundary can no longer be awaited.

### R3 — portable exact completion

Class sweep: searched e2e support for daemon PID waits and raw PID probes.
`HermeticCockpit::reap` was the affected cross-platform consumer. Enforcement is
the `ExactProcessExit` platform type: pidfd on Linux, kqueue process filter on
macOS/FreeBSD, and process HANDLE on Windows. Linux is runtime-tested; macOS and
Windows implementations are source-reviewed but cannot be compiled on this
Linux host. Other Unix targets are outside the repository's implemented exact
process-identity set and receive no success claim here.

### R4/F1 — uncancellable lifetime-lock waiter

Class sweep: searched the workspace for lifetime-lock waiters, `flock`,
`LockFileEx`, `spawn_blocking`, and `cockpit-daemon-lifetime-wait`. The one
blocking lifetime waiter and its core consumer were affected. Enforcement is
exact-process-wait-first followed by one nonblocking lock acquisition; no
try-lock loop exists. Real-child timeout and release test the failure and success
branches. Windows' helper uses a finite `WaitForSingleObject` deadline, so a
cancelled future can retain a worker/handle only until that same bounded deadline,
not indefinitely.

### R5/F1 — release deadline

Class sweep: searched every `restart_release_timeout` caller and the shutdown
drain constants. All lifecycle release observation callers share the function;
graceful drain behavior is separately configured in shutdown. Enforcement is
the 30-second constant. Unit coverage asserts default, zero, ordinary explicit,
and maximum CLI grace behavior; witness tests exercise both timeout and success.

### R6 — lifetime ownership survives metadata cleanup

Class sweep: searched `ForegroundMetadataGuard`, `metadata_guard.cleanup`, and
`run_foreground_inner_with_boot_db` across `crates` and `apps`. The single
foreground product owner and the injected in-process sibling were affected.
Enforcement is immediate product transfer to process teardown; cleanup only
retires receipt-bound metadata, and foreground task joins precede cleanup.
Verification exercises cleanup while a real product-path child remains alive,
failed successor acquisition, exact child exit, eventual acquisition, and the
releasable in-process sibling. Remaining exception: injected in-process owners
release after their fully joined logical daemon lifetime so the host test
process can start another generation.

### R7 — macOS/FreeBSD stop routing

Class sweep: searched `stop`, `stop_exact`,
`stop_unix_without_stable_handle`, `acquire_verified_daemon_process`, and every
stable-process cfg. Both public and receipt-exact stop entries were affected.
Enforcement routes macOS/FreeBSD through a receipt-verified kqueue witness,
delivers SIGTERM while retaining it, consumes `NOTE_EXIT` with one bounded
kernel wait, and only then retires metadata. Unsupported Unix stays fail-closed
only outside Linux/macOS/FreeBSD. Structural coverage proves both entry routes,
exact-exit consumption, and the unsupported-set exclusion; the targets are not
installed on this Linux host.

## Added Linux/not-Linux gate bound

Command:
`git diff --unified=0 origin/green-the-rust-4..HEAD -- '*.rs'`, counting each
added line containing `target_os = "linux"` or `not(target_os = "linux")`.
At the final pass-4 working tree the count is **76 additions across 9 files**:

| File | Added gate lines | Classification |
| --- | ---: | --- |
| `crates/cockpit-host/src/process.rs` | 24 | Linux pidfd, parent-death, `/proc`, cgroup/supervisor mechanics; non-Linux Unix process-group and Windows Job Object siblings are separate branches |
| `crates/cockpit-core/src/worktree_orchestration/validation.rs` | 19 | Linux supervisor/cgroup validation versus non-Linux Unix process-group and Windows Job Object containment |
| `crates/cockpit-host/src/daemon_lifecycle.rs` | 7 | Linux pidfd fields/acquisition/wait/test inside the stable-process abstraction whose siblings are macOS/FreeBSD kqueue and Windows HANDLE |
| `apps/cli/tests/e2e/support/mod.rs` | 7 | Linux pidfd exact-exit and Linux-only Secret Service fixture; portable exact-exit siblings are separately gated |
| `crates/cockpit-core/src/daemon/mod.rs` | 8 | stable predecessor selection; Linux pidfd and macOS/FreeBSD kqueue stop routing; unsupported Unix exclusion |
| `apps/cli/tests/e2e/daemon_lifecycle_replay.rs` | 2 | Linux-only descendant pidfd evidence after shared replay barriers |
| `apps/cli/tests/e2e/support/hermetic.rs` | 5 | supported-platform exact process witness selection plus Linux-only async Secret Service fixture ownership |
| `apps/cli/tests/e2e/run_noninteractive.rs` | 2 | expected Linux sandbox-dependent approval result in shared acceptance cases |
| `crates/cockpit-test-support/src/lib.rs` | 2 | Linux memfd executable fixture versus disk-backed non-Linux fixture |

This is an inventory of added textual gates, not a claim that every platform
branch in the repository is exhaustive. No retry, longer timeout, fixed wait,
serial mutex, ignored test, weakened assertion, or product test hook was added.

## Validation

| Command | Result |
| --- | --- |
| `cargo test --locked -p cockpit-core restart_release --no-fail-fast -- --nocapture` | pass: 5 matched, 0 failed |
| targeted nextest: deadline, mock sync/async, local-offline, socket Stop/Restart, fallback Stop | pass: 7 matched, 0 failed |
| targeted nextest: exact host real-child timeout/release witness | pass: 1 matched, 0 failed |
| `cargo fmt --all --check` | pass |
| `cargo check --locked -p cockpit-host --tests` | pass; existing warnings only |
| `cargo check --locked -p cockpit-core --tests` | pass; existing warnings only |
| focused nextest: product lifetime child + cleanup-retains-lock | pass: 2 matched, 0 failed |
| focused nextest: restart release + macOS/FreeBSD routing structure | pass: 6 matched, 0 failed |
| focused CLI e2e: mock sync/async cleanup, local-offline failure, connected stop/restart, unreachable stop | pass: 6 matched, 0 failed |
| final focused core: kqueue routing + injected shutdown | routing passed; injected case failed at its pre-shutdown 2-second socket startup wait under host load, so the new lock-sweeper join was not reached; no retry or timeout widening |
| post-ack mock-only rerun | not started because the coordinated build lane remained occupied; the earlier six-test run exercised the same async join boundary before its return value became an explicit asserted ack |
| Windows cockpit-host targeted check | changed `SYNCHRONIZE` sites compile; blocked later by pre-existing host-leaf `cockpit_config` references and missing `Read` in `named_pipe.rs` |

All Cargo commands used `CARGO_TARGET_DIR=target`, at most three build jobs, and
the required tracked-file touch immediately before invocation. No full-workspace
test was run. The macOS/FreeBSD targets are not installed. The installed Windows
target verified the changed import sites before encountering the unrelated
errors recorded above; CLI e2e no-run was therefore not feasible.
