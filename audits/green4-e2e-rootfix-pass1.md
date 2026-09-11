# Green4 e2e root-fix final coverage

Baseline: `0b3ca2a4b`. Review base for the platform-gate inventory:
`origin/green-the-rust-4`. Scope: STEP0-F1 through STEP0-F4 plus independent
review findings R1-R6.

## Invariant coverage

| Site / operation | Result | Evidence |
| --- | --- | --- |
| foreground daemon boot / publication | holds | `lifetime.lock` is acquired before the short `lifecycle.lock` PID reservation; boot failure and normal shutdown retire PID, socket, and endpoint before releasing lifetime ownership |
| socket Stop / fallback Stop | holds | both capture the predecessor before requesting shutdown and report success only after exact-process completion, the final lifetime-lock acquisition, and PID/socket retirement; e2e removes the live socket to exercise the SIGTERM fallback |
| socket Restart / fallback Restart / re-entry | holds | both stop paths consume the same release witness before spawning; replacement cannot be mistaken for the predecessor because process identity is pinned before shutdown and the final nonblocking lock acquisition fails closed if a replacement already owns the path |
| release success / failure / timeout / cancellation | holds | Linux pidfd, macOS/FreeBSD kqueue, or Windows process HANDLE is captured before shutdown; the platform deadline is internal to the wait; only after exact exit does one nonblocking `flock`/`LockFileEx` acquisition occur, so timeout/cancellation leaves no indefinitely blocked lifetime-lock worker |
| production restart release deadline | holds | `restart_release_timeout` is exactly 30 seconds for default, zero, ordinary explicit, and maximum accepted drain values; daemon graceful-drain configuration is otherwise unchanged |
| hermetic daemon reap, Linux | holds | pidfd is captured before stop and polled to exact exit |
| hermetic daemon reap, macOS/FreeBSD | holds | kqueue is captured before stop, registers `EVFILT_PROC` + `NOTE_EXIT` + `EV_ONESHOT`, and blocking `kevent` consumes that exact registration |
| hermetic daemon reap, Windows | holds | a `SYNCHRONIZE` process HANDLE is opened before stop and consumed by `WaitForSingleObject` |
| mock Secret Service setup, sync | holds | the caller only receives mode-specific readiness; dbus lookup/spawn/stdout read, zbus build, runtime, child, and cleanup are owned by one dedicated thread |
| mock Secret Service setup, current-thread async | holds | work before the first await is channel creation and thread spawn only; readiness is a Tokio oneshot and no runtime worker blocks |
| mock Secret Service receiver drop / shutdown | holds | readiness send is non-panicking; stop send transfers shutdown to the owner; async-context Drop delegates join to a finite reaper while the owner kills and waits for dbus before exit; synchronous Drop joins directly |
| replay launch / durable crash boundary | holds | Unix FIFO and Windows named-pipe barriers remain platform-owned; durable `executing` is asserted before the witness and daemon termination occurs only after the byte |
| replay/validation descendant cleanup | holds | Linux pidfd/cgroup evidence, non-Linux Unix process-group empty evidence, and Windows Job Object empty evidence remain the relevant platform witnesses |

Ownership and ordering: the daemon owns `lifetime.lock` for its entire published
generation. It acquires lifetime before lifecycle and, on shutdown, takes
lifecycle only long enough to retire metadata before dropping lifetime. A
restart observer opens the lifetime file and captures the exact process handle
before the stop effect. It awaits exact process completion, performs one final
nonblocking lifetime acquisition, and only then checks metadata. The Secret
Service owner thread exclusively owns its dbus child and runtime; callers own
only stop/readiness endpoints and the join handle, with no shared lock order.

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
Enforcement is single-thread ownership plus mode-specific readiness. Exact sync,
current-thread async, and local-offline acceptance tests verify the consumers.
There is no product hook; asynchronous Drop hands finite cleanup to a reaper
because Rust has no async Drop.

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

## Added Linux/not-Linux gate bound

Command:
`git diff --unified=0 origin/green-the-rust-4..HEAD -- '*.rs'`, counting each
added line containing `target_os = "linux"` or `not(target_os = "linux")`.
At the final working tree the count is **70 additions across 9 files**:

| File | Added gate lines | Classification |
| --- | ---: | --- |
| `crates/cockpit-host/src/process.rs` | 24 | Linux pidfd, parent-death, `/proc`, cgroup/supervisor mechanics; non-Linux Unix process-group and Windows Job Object siblings are separate branches |
| `crates/cockpit-core/src/worktree_orchestration/validation.rs` | 19 | Linux supervisor/cgroup validation versus non-Linux Unix process-group and Windows Job Object containment |
| `crates/cockpit-host/src/daemon_lifecycle.rs` | 7 | Linux pidfd fields/acquisition/wait/test inside the stable-process abstraction whose siblings are macOS/FreeBSD kqueue and Windows HANDLE |
| `apps/cli/tests/e2e/support/mod.rs` | 7 | Linux pidfd exact-exit and Linux-only Secret Service fixture; portable exact-exit siblings are separately gated |
| `crates/cockpit-core/src/daemon/mod.rs` | 5 | platform set selecting stable predecessor handles and Linux-specific daemon signaling |
| `apps/cli/tests/e2e/daemon_lifecycle_replay.rs` | 2 | Linux-only descendant pidfd evidence after shared replay barriers |
| `apps/cli/tests/e2e/support/hermetic.rs` | 2 | supported-platform exact process witness selection around daemon reap |
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

All Cargo commands used `CARGO_TARGET_DIR=target`, at most three build jobs, and
the required tracked-file touch immediately before invocation. No full-workspace
test was run. macOS/Windows target compilation was unavailable on this Linux
host.
