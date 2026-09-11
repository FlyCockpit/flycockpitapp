# Green4 e2e root-fix pass 1 coverage

Baseline: `0b3ca2a4b`. Scope: STEP0-F1 through STEP0-F4.

| Site / operation | Result | Evidence |
| --- | --- | --- |
| daemon PID reservation -> lifetime publication | holds | `run_foreground` completes the short `lifecycle.lock` reservation, then `ForegroundMetadataGuard::new` acquires `lifetime.lock`; no nested acquisition |
| daemon normal shutdown / boot failure | holds | guard retires PID, socket, and endpoint under `lifecycle.lock`, then drops lifetime lock; `Drop` retains fail-cleanup behavior |
| daemon crash | holds | Unix `flock` and Windows `LockFileEx` are released by kernel handle teardown |
| restart capture / timeout / release | holds | capture opens the same lifetime file; one blocking kernel acquisition runs under `tokio::time::timeout`; Linux pidfd and lock waits are armed concurrently; exact paths are checked after both |
| stale/missing witness | holds fail-closed | missing expected PID or witness returns false; no numeric-PID polling fallback |
| real child lifetime witness | holds | host unit child acquires lock, expired deadline returns false, stdin close exits child, kernel release lets waiter complete |
| replay operation launch, Unix | holds | POSIX FIFO created with `mkfifo`; `dd` writes witness byte and remains live; no `tail -f` substitute |
| replay operation launch, Windows | holds | always-compiled support module creates unique named pipe; client writes byte then blocks in `ReadByte`; Windows structural test checks command contract |
| executing replay crash boundary | holds | durable `executing` row is asserted before the platform witness; daemon kill occurs only after witness byte |
| replay descendant cleanup | holds | Linux e2e pins owned sandbox descendants with pidfds and asserts exit; other Unix product containment uses process-group empty oracle; Windows uses daemon Job Object containment |
| mock Secret Service sync caller | holds | synchronous local-offline acceptance uses dedicated service thread plus sync-only readiness wrapper |
| mock Secret Service async caller | holds | async API awaits Tokio oneshot; current-thread Tokio regression passes without `blocking_recv` |
| validation spawn on Windows | holds | wrapper is created suspended, assigned to kill-on-close Job Object, membership verified, then resumed |
| validation normal exit / cancellation / Drop | holds | normal wait terminates residual job members and waits for job-handle empty; Drop uses the same kernel wait and aborts before overlay restoration if unproven |
| validation restoration / unlock ordering | holds | `GroupedWrapper` remains inside overlay and exclusion guards; `containment_pending` clears only after proven job/process-group empty and wrapper reap |

## Linux-gate class sweep

Search scope supplied by verifier: 66 sites in `daemon_lifecycle_replay.rs` (8),
`support/hermetic.rs` (3), `support/mod.rs` (7), `daemon/mod.rs` (4),
`validation.rs` (18), `cockpit-host/process.rs` (24), and
`cockpit-test-support/lib.rs` (2). Query:
`rg -n 'target_os = "linux"|not\(target_os = "linux"\)'` over those files,
with baseline/diff inspection around every hit.

* Replay barrier: affected 6 of 8 sites; replaced by shared cfg(unix)/cfg(windows)
  abstraction. Remaining 2 are Linux-only pidfd descendant evidence; portable
  containment fallbacks remain product-owned.
* Hermetic/support: Linux gates cover pidfd exact-exit evidence and the Linux
  Secret Service fixture. Non-Linux Unix uses process identity/wait helpers;
  platforms without Secret Service use the no-op fixture path.
* Daemon: Linux gates are pidfd acquisition/wait and `/proc` helpers. Restart
  correctness now depends on the portable advisory lifetime lock; pidfd is
  only an additional exact-process witness.
* Validation: Linux supervisor/cgroup and `/proc` evidence remain optimized.
  Other Unix uses pinned process-group kill plus empty oracle. Windows now uses
  suspended pre-assignment to a Job Object and job-handle empty wait. Unsupported
  platforms fail closed.
* Host process: Linux gates are pidfd, parent-death signal, `/proc` membership,
  and cgroup/supervisor implementation. Siblings are Unix process-group oracle,
  Windows Job Object oracle, or explicit unsupported/fail-closed results.
* Test support: Linux `memfd` executable fixture has a tempfile-backed
  non-Linux implementation; no correctness claim is lost.

No durable-`executing`-only shortcut, retry, longer timeout, sleep, ignored test,
or weakened assertion was introduced.
