# Local daemon supervisor boundary

Issue #439 defines the stable-wrapper design. The implementation boundary is
`crates/cockpit-core/src/daemon/supervisor.rs`: the supervisor owns the public
endpoint, v2 PID receipt/lifetime lock, rendezvous publication, start clock,
worker generation, readiness wait, crash observation, and `sup.ctl`.

This module may depend on host lifecycle/filesystem/process primitives, the
shared client restart-storm guard, protocol version constants used in endpoint
discovery, the daemon module's endpoint bind helpers, and the database crate's
opaque `SupervisorDatabaseOwner` lock witness. The witness exposes no
connection, migration, query, or writer API; retaining it in the wrapper lets a
ready successor overlap a draining predecessor without creating a second
database owner. The module must never import the engine, model providers,
session workers, registry, or database implementation. Those remain inside
`cockpit daemon worker`. This deliberately small binary boundary is what makes
wrapper re-execution and worker upgrades independent of application behavior.

## Endpoint and readiness ABI

On Unix the supervisor retains the public listener and passes a duplicate as fd
3 with `LISTEN_FDS`/`LISTEN_PID`. A worker writes one byte to fd 4 only after
boot, recovery, and listener construction reach the normal publication
barrier. Cockpit's required sensitive/reveal sibling is also inherited on the
internal fd 5 so a ready successor can overlap a draining predecessor.

On Windows each worker creates a fresh random named pipe using the existing
owner-only DACL, remote-client rejection, finite instance pool, and
`FILE_FLAG_FIRST_PIPE_INSTANCE`. Readiness is the atomic owner-only identity
file replacement; clients re-read it for every reconnect. Pipe handles are not
handed between processes.

## Admin protocol

`sup.ctl` is a second owner-only local socket or named-pipe identity beside the
public endpoint. It is same-user trusted under
[`same-user-boundary.md`](security/same-user-boundary.md), not an additional
authentication boundary, and never carries public NDJSON envelopes.

Its independent protocol version is `1` (`ADMIN_PROTOCOL_VERSION`). Every
request and response carries that version. Version 1 commands are `status`,
`roll`, `upgrade { binary }`, `stop`, and `reexec`. Upgrade currently uses the
plain ready-successor-then-drain-predecessor seam; issue #440 owns
boundary-aware handover timers and issue #441 owns fencing/intent rows.

On Unix, `reexec` preserves the lifetime and published-PID locks plus the
public, reveal, and admin listeners across an in-place `exec`, then restores
close-on-exec before any later child launch. On Windows, which has no
`exec(2)`, it starts a replacement wrapper; the worker-owned random pipe stays
live while the replacement acquires the released named mutex and republishes
the v2 supervisor receipt. Neither path resets the supervisor start clock or
worker generation.

Client process watches are advisory supervision signals, not substitutes for
the live worker stream. If the supervisor is lost while its worker connection
is still serving, the TUI keeps that session attached and does not show the
modal restart decision. A later socket drop is untrusted and presents the
restart decision before lifecycle owner resolution. During a trusted worker
roll or crash recovery, reconnect continues to observe the supervisor watch;
owner exit or a spawn-timeout-sized recovery deadline falls back to that same
restart decision instead of reconnecting forever.

The public protocol's `Reconnect { generation }` event means a supervisor has
made a successor generation available and attached clients should reattach to
the same durable session. It is unrelated to `Reconnecting`, which describes a
model-provider network retry.
